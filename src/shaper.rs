//! 按协议限速：tc/HTB + IFB 在内核队列层对入站端口限速。sing-box 没有原生
//! 按入站限速，端口级整形只能做在内核。每协议 = 每端口（proxy_node）：
//! 下载 = 出口网卡按 sport 匹配（服务器→用户），上传 = ingress 重定向到
//! IFB 后按 dport 匹配（用户→服务器）。v4（flower ip）与 v6（flower ip6）
//! 各一套 filter，tcp/udp 各一条。
//!
//! 全量幂等重建：每次 apply 带该服务器的完整端口表，拆除自己的 handle 后
//! 重建——端口增删改值自动收敛。hub 本机协议（server_id=0）进程内直接执行
//! （服务单元需 AmbientCapabilities=CAP_NET_ADMIN）；远程服务器走
//! `shaper.apply` RPC 由 root agent 执行。启动重放见 `replay_local`。

use anyhow::{bail, Context, Result};
use std::process::Command;

const IFB: &str = "portshaper-ifb0";
/// HTB 父类速率：只需 ≥ 各子类之和，出口物理带宽才是真正的上限。
const PARENT_RATE: &str = "1000mbit";

#[derive(Debug, serde::Serialize, serde::Deserialize)]
pub struct ShapedPort {
    pub port: i64,
    /// 用户→服务器（上传）
    pub up: i64,
    /// 服务器→用户（下载）
    pub down: i64,
}

/// 某服务器上启用且填了限速的协议端口表。
pub fn collect_rates(app: &crate::App, server_id: i64) -> Result<Vec<ShapedPort>> {
    let nodes = app.db.proxy_nodes()?;
    Ok(nodes
        .into_iter()
        .filter(|n| n.enabled && n.server_id == server_id && (n.rate_up > 0 || n.rate_down > 0))
        .map(|n| ShapedPort { port: n.listen_port, up: n.rate_up, down: n.rate_down })
        .collect())
}

/// 对一台服务器应用限速：server_id = 0 在 hub 本机执行，其余走 agent RPC。
/// 返回人读结果；失败带原因（tc 缺失 / 权限不足 / agent 不在线）。
pub async fn apply_for_server(app: &crate::App, server_id: i64) -> Result<String> {
    let ports = collect_rates(app, server_id)?;
    if server_id == 0 {
        apply_ports(&ports)
    } else {
        let payload = serde_json::to_value(&ports).context("序列化端口表")?;
        let reply = crate::agent_ws::call_agent(
            app,
            server_id,
            "shaper.apply",
            serde_json::json!({ "ports": payload }),
            std::time::Duration::from_secs(30),
        )
        .await?;
        Ok(reply.get("message").and_then(|m| m.as_str()).unwrap_or("限速已应用").to_owned())
    }
}

/// hub 启动重放：本机协议的限速期望值存在 DB 里，进程一起来就重建一次。
pub async fn replay_local(app: crate::Shared) {
    match apply_for_server(&app, 0).await {
        Ok(msg) => tracing::info!("[shaper] {msg}"),
        Err(e) => tracing::warn!("[shaper] 本机限速重放失败：{e:#}"),
    }
}

fn tc(args: &[&str]) -> Result<()> {
    let out = Command::new("tc")
        .args(args)
        .output()
        .context("服务器缺少 tc 命令（iproute2），请先安装：apt install -y iproute2")?;
    if out.status.success() {
        Ok(())
    } else {
        let err = String::from_utf8_lossy(&out.stderr).trim().to_owned();
        if err.contains("Operation not permitted") || err.contains("Operation not supported") {
            bail!("tc 权限不足（{err}）：LXC/OpenVZ 容器无法限速，或服务缺少 CAP_NET_ADMIN")
        }
        bail!("tc {err}")
    }
}

fn ip(args: &[&str]) -> Result<String> {
    let out = Command::new("ip").args(args).output().context("服务器缺少 ip 命令（iproute2）")?;
    if out.status.success() {
        Ok(String::from_utf8_lossy(&out.stdout).trim().to_owned())
    } else {
        bail!("ip {} 失败：{}", args.join(" "), String::from_utf8_lossy(&out.stderr).trim())
    }
}

/// 出口网卡：默认路由走的那个。
fn detect_nic() -> Result<String> {
    let out = ip(&["-o", "route", "get", "1.1.1.1"])?;
    out.split_whitespace()
        .skip_while(|w| *w != "dev")
        .nth(1)
        .map(str::to_owned)
        .context("无法从路由表识别出口网卡")
}

fn teardown(nic: &str) -> Result<()> {
    // 只拆自己画的：root 是 handle 1: 的 htb 才动，绝不碰他人 qdisc。
    let qdisc = Command::new("tc").args(["qdisc", "show", "dev", nic]).output();
    if let Ok(out) = qdisc {
        let text = String::from_utf8_lossy(&out.stdout);
        if text.contains("htb 1:") {
            tc(&["qdisc", "del", "dev", nic, "root"])?;
        }
        if text.contains("ingress") {
            let _ = tc(&["qdisc", "del", "dev", nic, "ingress"]);
        }
    }
    let _ = Command::new("ip").args(["link", "del", IFB]).output();
    Ok(())
}

/// 应用（或清除，当 ports 为空）一台机器上的全部限速规则。hub 本机与 agent 共用语义。
pub fn apply_ports(ports: &[ShapedPort]) -> Result<String> {
    let nic = detect_nic()?;
    match build(&nic, ports) {
        Ok(()) => Ok(format!(
            "已在 {nic} 应用限速：{} 个端口（↑{} ↓{} Mbps）",
            ports.len(),
            ports.iter().map(|p| p.up).sum::<i64>(),
            ports.iter().map(|p| p.down).sum::<i64>()
        )),
        // 半成品比没有更糟：任一步失败就整体拆掉，错误带给前端。
        Err(e) => {
            teardown(&nic)?;
            Err(e)
        }
    }
}

fn build(nic: &str, ports: &[ShapedPort]) -> Result<()> {
    if ports.is_empty() {
        return teardown(nic);
    }

    // IFB 虚拟设备承载「用户上传」方向：ingress 重定向到 egress 队列才能分类。
    let exists = Command::new("ip").args(["link", "show", IFB]).output();
    let exists = matches!(&exists, Ok(o) if o.status.success());
    if !exists {
        ip(&["link", "add", IFB, "type", "ifb"])
            .context("创建 IFB 设备失败：内核可能未加载 ifb 模块（modprobe ifb）")?;
    }
    ip(&["link", "set", IFB, "up"])?;

    // 下载方向：出口网卡 root HTB，default 99 让未托管流量不受影响。
    tc(&["qdisc", "replace", "dev", nic, "root", "handle", "1:", "htb", "default", "99"])?;
    tc(&[
        "class",
        "replace",
        "dev",
        nic,
        "parent",
        "1:",
        "classid",
        "1:1",
        "htb",
        "rate",
        PARENT_RATE,
        "ceil",
        PARENT_RATE,
    ])?;
    tc(&[
        "class",
        "replace",
        "dev",
        nic,
        "parent",
        "1:",
        "classid",
        "1:99",
        "htb",
        "rate",
        PARENT_RATE,
        "ceil",
        PARENT_RATE,
    ])?;
    // 上传方向：IFB 上的第二棵 HTB。
    tc(&["qdisc", "replace", "dev", IFB, "root", "handle", "2:", "htb", "default", "99"])?;
    tc(&[
        "class",
        "replace",
        "dev",
        IFB,
        "parent",
        "2:",
        "classid",
        "2:1",
        "htb",
        "rate",
        PARENT_RATE,
        "ceil",
        PARENT_RATE,
    ])?;
    tc(&[
        "class",
        "replace",
        "dev",
        IFB,
        "parent",
        "2:",
        "classid",
        "2:99",
        "htb",
        "rate",
        PARENT_RATE,
        "ceil",
        PARENT_RATE,
    ])?;
    // ingress 全量重定向到 IFB（IFB 的 default 99 原样放行非托管流量）。
    tc(&["qdisc", "replace", "dev", nic, "handle", "ffff:", "ingress"])?;
    tc(&[
        "filter", "replace", "dev", nic, "parent", "ffff:", "matchall", "action", "mirred", "egress",
        "redirect", "dev", IFB,
    ])?;

    for (i, p) in ports.iter().enumerate() {
        let down_id = format!("1:{}", 101 + i);
        let up_id = format!("2:{}", 101 + i);
        if p.down > 0 {
            let rate = format!("{}mbit", p.down);
            tc(&[
                "class", "replace", "dev", nic, "parent", "1:1", "classid", &down_id, "htb", "rate", &rate,
                "ceil", &rate,
            ])?;
            // flower 的 L4 端口键不分 v4/v6（ip6src_port 不存在），v6 靠 protocol ipv6 区分
            for proto in ["ip", "ipv6"] {
                for ip_proto in ["tcp", "udp"] {
                    tc(&[
                        "filter",
                        "replace",
                        "dev",
                        nic,
                        "parent",
                        "1:",
                        "protocol",
                        proto,
                        "flower",
                        "ip_proto",
                        ip_proto,
                        "src_port",
                        &p.port.to_string(),
                        "classid",
                        &down_id,
                    ])?;
                }
            }
        }
        if p.up > 0 {
            let rate = format!("{}mbit", p.up);
            tc(&[
                "class", "replace", "dev", IFB, "parent", "2:1", "classid", &up_id, "htb", "rate", &rate,
                "ceil", &rate,
            ])?;
            for proto in ["ip", "ipv6"] {
                for ip_proto in ["tcp", "udp"] {
                    tc(&[
                        "filter",
                        "replace",
                        "dev",
                        IFB,
                        "parent",
                        "2:",
                        "protocol",
                        proto,
                        "flower",
                        "ip_proto",
                        ip_proto,
                        "dst_port",
                        &p.port.to_string(),
                        "classid",
                        &up_id,
                    ])?;
                }
            }
        }
    }
    Ok(())
}
