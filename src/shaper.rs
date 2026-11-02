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

/// root 挂 HTB：qdisc replace 不是幂等操作——HTB 已在 root 上时再 replace
/// 内核报「Change operation not supported」（生产 one 实锤），所以已挂就
/// 跳过；class/filter 的 replace 才有真幂等语义。default 99 恒定，重挂
/// 没有可变参数。
fn ensure_htb(nic: &str, handle: &str) -> Result<()> {
    // capture 模式恒走 replace 臂，让 golden 锁住 replace 的 argv 形状。
    #[cfg(test)]
    if tc_sink().is_some() {
        return tc(&[
            "qdisc",
            "replace",
            "dev",
            nic,
            "root",
            "handle",
            &format!("{handle}:"),
            "htb",
            "default",
            "99",
        ]);
    }
    let out = Command::new("tc").args(["qdisc", "show", "dev", nic]).output()?;
    let text = String::from_utf8_lossy(&out.stdout);
    let wanted = format!("htb {handle}:");
    if text.contains(&wanted) {
        return Ok(());
    }
    tc(&["qdisc", "replace", "dev", nic, "root", "handle", &format!("{handle}:"), "htb", "default", "99"])
}

fn tc(args: &[&str]) -> Result<()> {
    // 测试 seam：golden 测试锁 argv 形状（handle 必须是 "1:" 单参数这类拼接
    // 错误生产才炸、单测抓不住——argv 装配是唯一可提前锁死的层）。
    #[cfg(test)]
    if let Some(sink) = tc_sink() {
        sink.lock().unwrap().push(args.iter().map(|s| s.to_string()).collect());
        return Ok(());
    }
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

/// golden 测试的 tc argv 收集器（仅测试编译进；生产恒 None 零开销）。
#[cfg(test)]
type TcSink = std::sync::Arc<std::sync::Mutex<Vec<Vec<String>>>>;

#[cfg(test)]
static TC_SINK: std::sync::Mutex<Option<TcSink>> = std::sync::Mutex::new(None);

#[cfg(test)]
fn tc_sink() -> Option<TcSink> {
    TC_SINK.lock().unwrap().clone()
}

#[cfg(test)]
pub(crate) fn tc_capture() -> std::sync::Arc<std::sync::Mutex<Vec<Vec<String>>>> {
    let sink = std::sync::Arc::new(std::sync::Mutex::new(Vec::new()));
    *TC_SINK.lock().unwrap() = Some(sink.clone());
    sink
}

fn ip(args: &[&str]) -> Result<String> {
    // 同 tc：capture 模式记 argv 不执行（link add/set 无输出可期待）。
    #[cfg(test)]
    if let Some(sink) = tc_sink() {
        sink.lock()
            .unwrap()
            .push(std::iter::once("ip".to_owned()).chain(args.iter().map(|s| s.to_string())).collect());
        return Ok(String::new());
    }
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
    // capture 模式恒走 add 臂，让 golden 锁住 ip link add 的 argv 形状。
    #[cfg(test)]
    let exists = tc_sink().is_none();
    #[cfg(not(test))]
    let exists = Command::new("ip").args(["link", "show", IFB]).output();
    #[cfg(not(test))]
    let exists = matches!(&exists, Ok(o) if o.status.success());
    if !exists {
        ip(&["link", "add", IFB, "type", "ifb"])
            .context("创建 IFB 设备失败：内核可能未加载 ifb 模块（modprobe ifb）")?;
    }
    ip(&["link", "set", IFB, "up"])?;

    // 下载方向：出口网卡 root HTB，default 99 让未托管流量不受影响。
    ensure_htb(nic, "1")?;
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
    ensure_htb(IFB, "2")?;
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

#[cfg(test)]
mod tests {
    use super::*;

    /// tc/ip argv golden：限速命令序列的形状在此锁死。这些命令只在生产
    /// agent/hub 里真跑，argv 拼接错误（ensure_htb 首版把 "1:" 拆成 "1"
    /// ":" 两个独立参数，单测全绿生产才炸）测试环境抓不住——唯一可提前
    /// 锁死的层就是 argv 装配本身。改 tc 序列必须同改 golden；两仓同名
    /// 同语义（agent 仓 src/shaper.rs 有同款 golden），改一处必须同步
    /// 另一处。
    #[test]
    fn build_emits_the_expected_tc_argv_sequence() {
        let sink = tc_capture();
        let ports = vec![ShapedPort { port: 46154, up: 20, down: 20 }];
        build("eth1", &ports).expect("capture 模式 build 不触网");

        let got = sink.lock().unwrap().clone();
        let want: Vec<Vec<String>> = vec![
            // IFB 建立（capture 恒走 add 臂）+ 拉起。
            ip_vec(&["link", "add", "portshaper-ifb0", "type", "ifb"]),
            ip_vec(&["link", "set", "portshaper-ifb0", "up"]),
            // 下载方向 root HTB——handle 必须是 "1:" 单参数。
            tc_vec(&["qdisc", "replace", "dev", "eth1", "root", "handle", "1:", "htb", "default", "99"]),
            tc_vec(&[
                "class", "replace", "dev", "eth1", "parent", "1:", "classid", "1:1", "htb", "rate",
                "1000mbit", "ceil", "1000mbit",
            ]),
            tc_vec(&[
                "class", "replace", "dev", "eth1", "parent", "1:", "classid", "1:99", "htb", "rate",
                "1000mbit", "ceil", "1000mbit",
            ]),
            // 上传方向 IFB 上的第二棵 HTB。
            tc_vec(&[
                "qdisc",
                "replace",
                "dev",
                "portshaper-ifb0",
                "root",
                "handle",
                "2:",
                "htb",
                "default",
                "99",
            ]),
            tc_vec(&[
                "class",
                "replace",
                "dev",
                "portshaper-ifb0",
                "parent",
                "2:",
                "classid",
                "2:1",
                "htb",
                "rate",
                "1000mbit",
                "ceil",
                "1000mbit",
            ]),
            tc_vec(&[
                "class",
                "replace",
                "dev",
                "portshaper-ifb0",
                "parent",
                "2:",
                "classid",
                "2:99",
                "htb",
                "rate",
                "1000mbit",
                "ceil",
                "1000mbit",
            ]),
            // ingress 全量重定向到 IFB。
            tc_vec(&["qdisc", "replace", "dev", "eth1", "handle", "ffff:", "ingress"]),
            tc_vec(&[
                "filter",
                "replace",
                "dev",
                "eth1",
                "parent",
                "ffff:",
                "matchall",
                "action",
                "mirred",
                "egress",
                "redirect",
                "dev",
                "portshaper-ifb0",
            ]),
            // 下载腿：类 + v4/v6 × tcp/udp 四条 sport filter。
            tc_vec(&[
                "class", "replace", "dev", "eth1", "parent", "1:1", "classid", "1:101", "htb", "rate",
                "20mbit", "ceil", "20mbit",
            ]),
            tc_vec(&[
                "filter", "replace", "dev", "eth1", "parent", "1:", "protocol", "ip", "flower", "ip_proto",
                "tcp", "src_port", "46154", "classid", "1:101",
            ]),
            tc_vec(&[
                "filter", "replace", "dev", "eth1", "parent", "1:", "protocol", "ip", "flower", "ip_proto",
                "udp", "src_port", "46154", "classid", "1:101",
            ]),
            tc_vec(&[
                "filter", "replace", "dev", "eth1", "parent", "1:", "protocol", "ipv6", "flower", "ip_proto",
                "tcp", "src_port", "46154", "classid", "1:101",
            ]),
            tc_vec(&[
                "filter", "replace", "dev", "eth1", "parent", "1:", "protocol", "ipv6", "flower", "ip_proto",
                "udp", "src_port", "46154", "classid", "1:101",
            ]),
            // 上传腿：类 + 四条 dport filter（挂在 IFB 上）。
            tc_vec(&[
                "class",
                "replace",
                "dev",
                "portshaper-ifb0",
                "parent",
                "2:1",
                "classid",
                "2:101",
                "htb",
                "rate",
                "20mbit",
                "ceil",
                "20mbit",
            ]),
            tc_vec(&[
                "filter",
                "replace",
                "dev",
                "portshaper-ifb0",
                "parent",
                "2:",
                "protocol",
                "ip",
                "flower",
                "ip_proto",
                "tcp",
                "dst_port",
                "46154",
                "classid",
                "2:101",
            ]),
            tc_vec(&[
                "filter",
                "replace",
                "dev",
                "portshaper-ifb0",
                "parent",
                "2:",
                "protocol",
                "ip",
                "flower",
                "ip_proto",
                "udp",
                "dst_port",
                "46154",
                "classid",
                "2:101",
            ]),
            tc_vec(&[
                "filter",
                "replace",
                "dev",
                "portshaper-ifb0",
                "parent",
                "2:",
                "protocol",
                "ipv6",
                "flower",
                "ip_proto",
                "tcp",
                "dst_port",
                "46154",
                "classid",
                "2:101",
            ]),
            tc_vec(&[
                "filter",
                "replace",
                "dev",
                "portshaper-ifb0",
                "parent",
                "2:",
                "protocol",
                "ipv6",
                "flower",
                "ip_proto",
                "udp",
                "dst_port",
                "46154",
                "classid",
                "2:101",
            ]),
        ];
        assert_eq!(
            got, want,
            "tc/ip argv 序列漂移：确认内核语义后同步 golden（handle 形态/参数顺序是生产实跑的契约）"
        );
    }

    fn tc_vec(args: &[&str]) -> Vec<String> {
        args.iter().map(|s| s.to_string()).collect()
    }

    fn ip_vec(args: &[&str]) -> Vec<String> {
        std::iter::once("ip".to_owned()).chain(args.iter().map(|s| s.to_string())).collect()
    }
}
