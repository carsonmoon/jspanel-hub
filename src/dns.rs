//! 通用 DDNS 基座（grilling 一期）：节点绑定 FQDN，公网 IP 变化自动更新
//! DNS A 记录。provider 留接口——v1 只实现 Cloudflare（API 标准、免费、
//! DDNS 事实标准），后续按需加其他家。
//!
//! 触发点三处：agent 握手上报 IP 变化（agent_ws 帧循环钩子）、30 分钟兜底
//! 校时循环（`watch`）、节点编辑处的手动「立即同步」（POST
//! /nodes/{id}/dns-sync）。用户可操作的失败都包成 Shown 走人话通道。

use std::time::Duration;

const CF_API: &str = "https://api.cloudflare.com/client/v4";

fn token(app: &crate::App) -> String {
    app.db.get("cf_api_token").unwrap_or_default()
}

pub fn configured(app: &crate::App) -> bool {
    !token(app).is_empty()
}

fn client() -> anyhow::Result<reqwest::Client> {
    reqwest::Client::builder()
        .timeout(Duration::from_secs(15))
        .build()
        .map_err(|e| shown(format!("构建 HTTP 客户端失败：{e}")))
}

fn shown<S: std::fmt::Display>(msg: S) -> anyhow::Error {
    anyhow::Error::msg(crate::Shown(msg.to_string()))
}

/// Cloudflare upsert：在 token 可见的 zone 里按 FQDN 后缀匹配域名，A 记录
/// 存在则改写、不存在则创建。
async fn cloudflare_upsert_a(token: &str, fqdn: &str, ip: &str) -> anyhow::Result<()> {
    let client = client()?;
    let auth = ("Authorization", format!("Bearer {token}"));
    let zones: serde_json::Value = client
        .get(format!("{CF_API}/zones?per_page=50"))
        .header(auth.0, auth.1.clone())
        .send()
        .await
        .map_err(|e| shown(format!("无法访问 Cloudflare：{e}")))?
        .error_for_status()
        .map_err(|e| shown(format!("Cloudflare 拒绝了请求（Token 无效或权限不足）：{e}")))?
        .json()
        .await
        .map_err(|e| shown(format!("解析 Cloudflare zone 列表失败：{e}")))?;
    let zone_id = zones["result"]
        .as_array()
        .and_then(|zs| {
            zs.iter()
                .filter_map(|z| {
                    let name = z["name"].as_str()?;
                    let id = z["id"].as_str()?.to_owned();
                    (fqdn == name || fqdn.ends_with(&format!(".{name}"))).then_some(id)
                })
                .next()
        })
        .ok_or_else(|| {
            shown(format!("Token 可见的域名里没有能匹配 {fqdn} 的 zone（检查 Token 的 Zone:Read 权限）"))
        })?;

    let url = format!("{CF_API}/zones/{zone_id}/dns_records?type=A&name={fqdn}");
    let records: serde_json::Value = client
        .get(&url)
        .header(auth.0, auth.1.clone())
        .send()
        .await
        .map_err(|e| shown(format!("查询 DNS 记录失败：{e}")))?
        .error_for_status()
        .map_err(|e| shown(format!("查询 DNS 记录失败：{e}")))?
        .json()
        .await
        .map_err(|e| shown(format!("解析 DNS 记录失败：{e}")))?;
    // TTL 60（免费套餐下限）：切换/故障转移后客户端恢复时长由缓存剩余时间
    // 决定，短 TTL 直接压缩断连窗口；查询量在本项目规模下可忽略。
    // proxied=false：reality/vless 是非 HTTP 流量，过不了 CDN 代理。
    let body = serde_json::json!({ "type": "A", "name": fqdn, "content": ip, "ttl": 60, "proxied": false });
    let base = format!("{CF_API}/zones/{zone_id}/dns_records");
    let pending = match records["result"][0]["id"].as_str() {
        Some(id) => client.patch(format!("{base}/{id}")).header(auth.0, auth.1).json(&body),
        None => client.post(base).header(auth.0, auth.1).json(&body),
    };
    let v: serde_json::Value = pending
        .send()
        .await
        .map_err(|e| shown(format!("写入 DNS 记录失败：{e}")))?
        .error_for_status()
        .map_err(|e| shown(format!("Cloudflare 拒绝了 DNS 写入（检查 DNS:Edit 权限）：{e}")))?
        .json()
        .await
        .map_err(|e| shown(format!("解析 DNS 写入应答失败：{e}")))?;
    if v["success"].as_bool() != Some(true) {
        return Err(shown(format!("Cloudflare 返回失败：{}", v["errors"])));
    }
    Ok(())
}

fn set_suppressed_fn(node_id: i64, on: bool) {
    let mut m = suppressed_fn();
    if on {
        m.insert(node_id);
    } else {
        m.remove(&node_id);
    }
}

fn suppressed_fn() -> std::sync::MutexGuard<'static, std::collections::HashSet<i64>> {
    use std::sync::OnceLock;
    static M: OnceLock<std::sync::Mutex<std::collections::HashSet<i64>>> = OnceLock::new();
    M.get_or_init(std::sync::Mutex::default).lock().unwrap()
}

/// upsert 测试桩：设了就不发真实 HTTP（dns.rs 无 mock HTTP 基座，切换
/// 主机/跟随同步的单测靠它断言「翻没翻、翻去了哪」）。
pub type UpsertStub = std::sync::Arc<dyn Fn(&str, &str, &str) -> anyhow::Result<()> + Send + Sync>;

fn upsert_stub() -> std::sync::MutexGuard<'static, Option<UpsertStub>> {
    use std::sync::OnceLock;
    static M: OnceLock<std::sync::Mutex<Option<UpsertStub>>> = OnceLock::new();
    M.get_or_init(|| std::sync::Mutex::new(None)).lock().unwrap()
}

/// 测试注入点（仅测试目标可见；bin 目标无调用方）。
#[cfg(test)]
pub fn set_upsert_stub(stub: Option<UpsertStub>) {
    *upsert_stub() = stub;
}

/// 所有 A 记录写入的统一入口（入口故障转移翻转 / 机器 DDNS 同步 /
/// 代理节点域名翻转与跟随）：测试注入点。
async fn upsert_a(token: &str, fqdn: &str, ip: &str) -> anyhow::Result<()> {
    if let Some(stub) = upsert_stub().as_ref() {
        return stub(token, fqdn, ip);
    }
    cloudflare_upsert_a(token, fqdn, ip).await
}

/// 入口故障转移专用：绕过节点自身的 dns_ip 记账，直接把 FQDN 指到指定 IP。
/// 同时抑制 DDNS 自动同步（主入口恢复回切时解除）。
pub async fn flip_a(app: &crate::App, node_id: i64, target_ip: &str) -> anyhow::Result<()> {
    if !configured(app) {
        anyhow::bail!(anyhow::Error::msg(crate::Shown(
            "未配置 Cloudflare API Token（设置页「域名解析」）".into()
        )));
    }
    let fqdn = {
        let Some(n) = app.db.node(node_id)? else { return Err(shown("节点不存在")) };
        let fqdn = n.dns_name.trim().to_owned();
        if fqdn.is_empty() {
            return Err(shown("主入口节点未绑定域名，无法翻转（先在节点编辑里绑定）".to_string()));
        }
        fqdn
    };
    set_suppressed_fn(node_id, true);
    upsert_a(&token(app), &fqdn, target_ip).await?;
    app.db.update_dns_ip(node_id, target_ip)?;
    Ok(())
}

/// 入口故障转移回切：解除抑制并同步回节点自己的上报 IP。
pub async fn unfollow(app: &crate::App, node_id: i64) {
    set_suppressed_fn(node_id, false);
    let _ = sync_node(app, node_id).await;
}

pub fn is_suppressed(node_id: i64) -> bool {
    suppressed_fn().contains(&node_id)
}

/// 把一个节点当前上报的公网 IP 同步进它绑定的 FQDN。返回同步的 IP。
pub async fn sync_node(app: &crate::App, node_id: i64) -> anyhow::Result<String> {
    if !configured(app) {
        return Err(shown("未配置 Cloudflare API Token（设置页「域名解析」）"));
    }
    let (fqdn, dns_ip, ipv4) = {
        let Some(n) = app.db.node(node_id)? else { return Err(shown("节点不存在")) };
        (n.dns_name.clone(), n.dns_ip.clone(), n.ipv4.clone())
    };
    let fqdn = fqdn.trim();
    if fqdn.is_empty() {
        return Err(shown("该节点未绑定域名（节点编辑里设置）"));
    }
    let ip = ipv4.trim();
    if ip.is_empty() {
        return Err(shown("节点还没有上报公网 IPv4（等 agent 首次上报后再试）"));
    }
    if ip == dns_ip {
        return Ok(ip.to_owned());
    }
    upsert_a(&token(app), fqdn, ip).await?;
    app.db.update_dns_ip(node_id, ip)?;
    Ok(ip.to_owned())
}

/// 切换主机落地：把节点自有域名（proxy_node.dns_name）的 A 记录翻到目标
/// IP。调用方（switch_node）保证 token/fqdn 已校验；指向记账由它一并落库。
pub async fn flip_proxy_node(app: &crate::App, fqdn: &str, ip: &str) -> anyhow::Result<()> {
    upsert_a(&token(app), fqdn, ip).await
}

/// 代理节点域名跟随（切换主机）：把「绑了域名、但 A 记录落后于指向机器
/// 上报 IP」的节点重同步一遍。覆盖机器换 IP（域名自愈）与 Cloudflare 侧
/// 被手改的情况。手动切换后记账已同步，这里自然跳过——不打架。
pub async fn sync_proxy_node_domains(app: &crate::App) {
    if !configured(app) {
        return;
    }
    let nodes = match app.db.proxy_nodes() {
        Ok(n) => n,
        Err(_) => return,
    };
    for n in nodes {
        let fqdn = n.dns_name.trim().to_owned();
        if fqdn.is_empty() {
            continue;
        }
        // 指向的机器已删除/未上报 IP：无从同步，跳过（面板切走后自愈）。
        let Ok(Some(m)) = app.db.node(n.dns_server_id) else { continue };
        let ip = m.ipv4.trim().to_owned();
        if ip.is_empty() || ip == n.dns_ip.trim() {
            continue;
        }
        match upsert_a(&token(app), &fqdn, &ip).await {
            Ok(()) => {
                let _ = app.db.update_proxy_dns_ip(n.id, &ip);
                crate::proxy::notify_throttled(app, "ddns", "节点域名已更新", format!("{} → {}", fqdn, ip));
            }
            Err(e) => {
                crate::proxy::notify_throttled(
                    app,
                    "ddns_err",
                    "节点域名同步失败",
                    format!("{}：{e:#}", fqdn),
                );
            }
        }
    }
}

/// 兜底校时循环：每 30 分钟把「绑了域名但 dns_ip 落后于上报 IP」的节点
/// 重同步一遍，覆盖错过的钩子（hub 停机期间的 IP 变化等）。
pub async fn watch(app: crate::Shared) {
    loop {
        tokio::time::sleep(Duration::from_secs(1800)).await;
        let nodes = match app.db.nodes() {
            Ok(n) => n,
            Err(_) => continue,
        };
        for n in nodes.iter().filter(|n| {
            !n.dns_name.trim().is_empty()
                && !n.ipv4.trim().is_empty()
                && n.ipv4.trim() != n.dns_ip.trim()
                && !is_suppressed(n.id)
        }) {
            match sync_node(&app, n.id).await {
                Ok(ip) => crate::proxy::notify_throttled(
                    &app,
                    "ddns",
                    "DDNS 已更新",
                    format!("{} → {}", n.dns_name, ip),
                ),
                Err(e) => crate::proxy::notify_throttled(
                    &app,
                    "ddns_err",
                    "DDNS 同步失败",
                    format!("{}：{e:#}", n.dns_name),
                ),
            }
        }
        sync_proxy_node_domains(&app).await;
    }
}
