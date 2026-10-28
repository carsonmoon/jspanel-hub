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
async fn cloudflare_upsert_a(token: &str, fqdn: &str, ip: &str, proxied: bool) -> anyhow::Result<()> {
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
    // 灰云（DNS-only）：TTL 60（免费套餐下限）——切换/故障转移后客户端恢复
    // 时长由缓存剩余时间决定，短 TTL 直接压缩断连窗口；查询量在本项目规模
    // 下可忽略。reality 等非 HTTP 流量过不了 CDN 代理，直连域名一律灰云。
    // 小黄云（proxied，vless-ws 的 CDN 中转）：Cloudflare 强制 ttl=1（auto），
    // 写 60 会被拒。
    let body = serde_json::json!({
        "type": "A", "name": fqdn, "content": ip,
        "ttl": if proxied { 1 } else { 60 }, "proxied": proxied
    });
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

/// 签发 Cloudflare Origin CA 证书（vless-ws 的 CDN 中转用）：15 年有效期，
/// 私钥在本地生成（rcgen），CSR 上呈、证书回存 proxy_secret。认证两条路：
/// API Token（需 Origin CA 权限）→ 失败再试设置页的 Origin CA Key
/// （X-Auth-User-Service-Key，仪表盘「我的个人资料 → API 令牌」页可取）。
/// 两条路都不通则报错指引手动粘贴。
pub async fn issue_origin_ca(app: &crate::App, fqdn: &str) -> anyhow::Result<(String, String)> {
    if let Some(stub) = origin_ca_stub().as_ref() {
        return stub(fqdn);
    }
    let key = rcgen::KeyPair::generate().map_err(|e| shown(format!("生成证书密钥失败：{e}")))?;
    let params = rcgen::CertificateParams::new(vec![fqdn.to_owned()])
        .map_err(|e| shown(format!("证书参数无效：{e}")))?;
    let csr = params.serialize_request(&key).map_err(|e| shown(format!("生成 CSR 失败：{e}")))?;
    let csr_pem = csr.pem().map_err(|e| shown(format!("编码 CSR 失败：{e}")))?;
    let body = serde_json::json!({
        "hostnames": [fqdn], "requested_validity": 5475, "request_type": "origin-rsa",
        "csr": csr_pem,
    });
    let client = client()?;
    let token = token(app);
    let post = |header: (&'static str, String)| {
        client.post(format!("{CF_API}/certificates")).header(header.0, header.1).json(&body)
    };
    let mut via = "API Token";
    let resp = post(("Authorization", format!("Bearer {token}")))
        .send()
        .await
        .map_err(|e| shown(format!("请求 Cloudflare 签发证书失败：{e}")))?;
    // Token 无 Origin CA 权限时 Cloudflare 回 400/403；换 Origin CA Key 再试。
    let resp = if matches!(resp.status().as_u16(), 400 | 403) {
        let status = resp.status();
        let text = resp.text().await.unwrap_or_default();
        let origin_key = app.db.get("cf_origin_ca_key").unwrap_or_default();
        if origin_key.is_empty() {
            return Err(shown(format!(
                "API Token 签发 Origin CA 证书被拒（{status}：{text}）。两条路任选其一：\
                 ① 设置页填 Origin CA Key（Cloudflare 仪表盘 → My Profile → API Tokens → Origin Keys）；\
                 ② 在节点对话框手动粘贴证书"
            )));
        }
        via = "Origin CA Key";
        post(("X-Auth-User-Service-Key", origin_key))
            .send()
            .await
            .map_err(|e| shown(format!("请求 Cloudflare 签发证书失败：{e}")))?
    } else {
        resp
    };
    let v: serde_json::Value = resp
        .error_for_status()
        .map_err(|e| shown(format!("Cloudflare 拒绝了证书签发（{via} 认证）：{e}")))?
        .json()
        .await
        .map_err(|e| shown(format!("解析证书签发应答失败：{e}")))?;
    let cert = v["result"]["certificate"]
        .as_str()
        .ok_or_else(|| shown(format!("Cloudflare 未返回证书：{}", v["errors"])))?
        .to_owned();
    Ok((cert, key.serialize_pem()))
}

/// Origin CA 签发测试桩（与 upsert 桩同款思路：无 mock HTTP 基座）。
pub type OriginCaStub = std::sync::Arc<dyn Fn(&str) -> anyhow::Result<(String, String)> + Send + Sync>;

fn origin_ca_stub() -> std::sync::MutexGuard<'static, Option<OriginCaStub>> {
    use std::sync::OnceLock;
    static M: OnceLock<std::sync::Mutex<Option<OriginCaStub>>> = OnceLock::new();
    M.get_or_init(|| std::sync::Mutex::new(None)).lock().unwrap()
}

/// 测试注入点（仅测试目标可见）。
#[cfg(test)]
pub fn set_origin_ca_stub(stub: Option<OriginCaStub>) {
    *origin_ca_stub() = stub;
}

/// token 可见的第一个 zone 名（cdn 域名基础域的取值来源）。查询失败/
/// 无 zone 返回 None，由调用方走下一级回退。
pub async fn zone_name(app: &crate::App) -> Option<String> {
    let client = client().ok()?;
    let token = token(app);
    let zones: serde_json::Value = client
        .get(format!("{CF_API}/zones?per_page=5"))
        .header("Authorization", format!("Bearer {token}"))
        .send()
        .await
        .ok()?
        .error_for_status()
        .ok()?
        .json()
        .await
        .ok()?;
    zones["result"][0]["name"].as_str().map(ToOwned::to_owned)
}

/// 删除一条 A 记录（vless-ws 节点删除时清掉小黄云孤儿记录）。记录不
/// 存在视为成功（幂等）。
pub async fn delete_a(app: &crate::App, fqdn: &str) -> anyhow::Result<()> {
    let client = client()?;
    let auth = ("Authorization", format!("Bearer {}", token(app)));
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
        .ok_or_else(|| shown(format!("Token 可见的域名里没有能匹配 {fqdn} 的 zone")))?;
    let records: serde_json::Value = client
        .get(format!("{CF_API}/zones/{zone_id}/dns_records?type=A&name={fqdn}"))
        .header(auth.0, auth.1.clone())
        .send()
        .await
        .map_err(|e| shown(format!("查询 DNS 记录失败：{e}")))?
        .error_for_status()
        .map_err(|e| shown(format!("查询 DNS 记录失败：{e}")))?
        .json()
        .await
        .map_err(|e| shown(format!("解析 DNS 记录失败：{e}")))?;
    for id in records["result"].as_array().into_iter().flatten().filter_map(|r| r["id"].as_str()) {
        let v: serde_json::Value = client
            .delete(format!("{CF_API}/zones/{zone_id}/dns_records/{id}"))
            .header(auth.0, auth.1.clone())
            .send()
            .await
            .map_err(|e| shown(format!("删除 DNS 记录失败：{e}")))?
            .error_for_status()
            .map_err(|e| shown(format!("Cloudflare 拒绝了 DNS 删除：{e}")))?
            .json()
            .await
            .map_err(|e| shown(format!("解析 DNS 删除应答失败：{e}")))?;
        if v["success"].as_bool() != Some(true) {
            return Err(shown(format!("Cloudflare 返回失败：{}", v["errors"])));
        }
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
/// 主机/跟随同步的单测靠它断言「翻没翻、翻去了哪、开没开小黄云」）。
pub type UpsertStub = std::sync::Arc<dyn Fn(&str, &str, &str, bool) -> anyhow::Result<()> + Send + Sync>;

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
/// 代理节点域名翻转与跟随）：测试注入点。`proxied` = 小黄云（vless-ws 的
/// CDN 中转域名），灰云记录恒传 false。
async fn upsert_a(token: &str, fqdn: &str, ip: &str, proxied: bool) -> anyhow::Result<()> {
    if let Some(stub) = upsert_stub().as_ref() {
        return stub(token, fqdn, ip, proxied);
    }
    cloudflare_upsert_a(token, fqdn, ip, proxied).await
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
    upsert_a(&token(app), &fqdn, target_ip, false).await?;
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
    upsert_a(&token(app), fqdn, ip, false).await?;
    app.db.update_dns_ip(node_id, ip)?;
    Ok(ip.to_owned())
}

/// 切换主机落地：把节点自有域名（proxy_node.dns_name）的 A 记录翻到目标
/// IP。调用方（switch_node）保证 token/fqdn 已校验；指向记账由它一并落库。
/// `proxied`：vless-ws 的 CDN 域名开小黄云，其余灰云。
pub async fn flip_proxy_node(app: &crate::App, fqdn: &str, ip: &str, proxied: bool) -> anyhow::Result<()> {
    upsert_a(&token(app), fqdn, ip, proxied).await
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
        // vless-ws 的域名是小黄云记录，跟随同步必须带着 proxied 语义重写，
        // 否则一次自愈就把 CDN 通道打回灰云。
        let proxied = n.protocol == "vless-ws";
        match upsert_a(&token(app), &fqdn, &ip, proxied).await {
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
