//! 代理协议模块：sing-box 核心管理、入站配置生成、分享链接与客户订阅。
//!
//! M1 管理的是 hub 所在机器上的核心：hub 直接拉起并守护 sing-box 子进程，
//! systemd 托管属于多机（agent）阶段（设计文档 5.7）。节点的启停开关只影响
//! 订阅与链接，不触发核心重启（设计文档 6.3）；所有变更落库后整体重渲染配
//! 置，`sing-box check` 通过才原子替换并重启（设计文档 5.4）。

use std::collections::{HashMap, HashSet};
use std::path::{Path, PathBuf};
use std::sync::Mutex;
use std::time::Duration;

use anyhow::{Context, Result};
use base64::engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD};
use base64::Engine as _;
use sha2::{Digest, Sha256};
use tokio::io::{AsyncBufReadExt, BufReader};
use tokio::process::{Child, Command};
use tracing::{debug, info, warn};
use x25519_dalek::{PublicKey, StaticSecret};

use crate::db::{NodeBundle, ProxyNode, ProxySecret, ProxyUser, SubUser};
use crate::{App, Shared};

/// Where the sing-box releases are published. Forking implies rebuilding this.
pub const SINGBOX_REPO: &str = "SagerNet/sing-box";

/// Protocols this build can render configs for.
const RENDERABLE: [&str; 6] = ["vless-reality", "hysteria2", "shadowsocks", "anytls", "socks", "http"];

/// These borrow a hostname the client sends, so a node cannot exist without
/// one: Reality pretends to it, the self-signed pair is minted for it.
const NEEDS_SNI: [&str; 3] = ["vless-reality", "hysteria2", "anytls"];

/// Shadowsocks' default cipher, applied when a node is created without one.
const SS_DEFAULT_METHOD: &str = "2022-blake3-aes-128-gcm";

/// The locally managed core: its process, the version it reported, and what
/// apply last did. The `proxy_desired_running` setting is the source of truth
/// for whether the operator wants it up.
#[derive(Default)]
pub struct CoreState {
    pub child: Option<Child>,
    pub version: String,
    pub applied_hash: String,
    pub last_error: String,
    pub started_at: i64,
    pub restarts: u64,
    /// 本机 Realm 中转：配置指纹与运行状态（M5）。
    pub relay_hash: String,
    pub realm_running: bool,
    pub realm_started_at: i64,
}

pub fn binary_path(app: &App) -> std::path::PathBuf {
    // systemd 机器上与 install.sh 的安装路径一致（单元 ExecStart 指向它）；
    // 无 systemd 的本机联调走 proxy_dir。
    if systemd() {
        std::path::PathBuf::from("/opt/monitor-proxy/bin/sing-box")
    } else {
        app.proxy_dir.join("bin").join("sing-box")
    }
}

pub fn config_path(app: &App) -> std::path::PathBuf {
    if systemd() {
        std::path::PathBuf::from("/opt/monitor-proxy/instances/main/config.json")
    } else {
        app.proxy_dir.join("config.json")
    }
}

// ---- credentials and keys (设计文档 8.4) ----

/// Reality keypair: X25519, base64url without padding — the exact format
/// `sing-box generate reality-keypair` emits. Generated here rather than by
/// shelling out so a node can be created before the core is installed.
pub fn generate_reality_keypair() -> (String, String) {
    let secret = StaticSecret::from(rand::random::<[u8; 32]>());
    let public = PublicKey::from(&secret);
    (URL_SAFE_NO_PAD.encode(secret.to_bytes()), URL_SAFE_NO_PAD.encode(public.as_bytes()))
}

pub fn new_uuid() -> String {
    let b = rand::random::<[u8; 16]>();
    format!(
        "{:02x}{:02x}{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}",
        b[0], b[1], b[2], b[3], b[4], b[5], b[6], b[7], b[8], b[9], b[10], b[11], b[12], b[13], b[14], b[15]
    )
}

pub fn new_short_id() -> String {
    hex::encode(rand::random::<[u8; 4]>())
}

pub fn new_password() -> String {
    hex::encode(rand::random::<[u8; 16]>())
}

/// A Shadowsocks-2022 key: base64 of 16 or 32 random bytes, the size the
/// cipher demands (设计文档 8.4).
pub fn ss_key(method: &str) -> Result<String> {
    let size = match method {
        "2022-blake3-aes-128-gcm" => 16,
        "2022-blake3-aes-256-gcm" | "2022-blake3-chacha20-poly1305" => 32,
        other => refuse!("不支持的 Shadowsocks 加密：{other}"),
    };
    let key: Vec<u8> = (0..size).map(|_| rand::random::<u8>()).collect();
    Ok(STANDARD.encode(key))
}

/// A self-signed certificate minted for the SNI, ECDSA P-256. Clients dial it
/// with `insecure=1`, which the generated links carry; sing-box takes the pair
/// inline, so no file management exists to ship configs around later.
fn self_signed_cert(sni: &str) -> Result<(String, String)> {
    let key = rcgen::KeyPair::generate().context("生成证书密钥失败")?;
    let params = rcgen::CertificateParams::new(vec![sni.to_owned()]).context("证书参数无效")?;
    let cert = params.self_signed(&key).context("自签证书生成失败")?;
    Ok((cert.pem(), key.serialize_pem()))
}

/// The secret a protocol needs at creation time: a Reality keypair, a
/// self-signed pair, or nothing.
fn node_secret(node: &ProxyNode, private_key: Option<&str>, short_id: Option<&str>) -> Result<ProxySecret> {
    Ok(match node.protocol.as_str() {
        "vless-reality" => {
            let (sk, pk) = match private_key {
                Some(key) => reality_keypair_from_private(key)?,
                None => generate_reality_keypair(),
            };
            ProxySecret {
                tls_mode: "reality".into(),
                private_key: sk,
                public_key: pk,
                short_id: short_id.map_or_else(new_short_id, ToOwned::to_owned),
                ..Default::default()
            }
        }
        "hysteria2" | "anytls" => {
            let (cert, key) = self_signed_cert(&node.sni)?;
            ProxySecret { tls_mode: "selfsign".into(), cert_pem: cert, key_pem: key, ..Default::default() }
        }
        "shadowsocks" => ProxySecret {
            tls_mode: "none".into(),
            // SS2022 多用户：服务器自己还要持有一个 PSK（SIP021）。
            psk: ss_key(&node.method)?,
            ..Default::default()
        },
        _ => ProxySecret { tls_mode: "none".into(), ..Default::default() },
    })
}

fn reality_keypair_from_private(value: &str) -> Result<(String, String)> {
    let bytes = URL_SAFE_NO_PAD.decode(value).map_err(|_| {
        anyhow::anyhow!(crate::Shown("Reality 私钥必须是无 padding 的 URL-safe Base64".into()))
    })?;
    if bytes.len() != 32 || URL_SAFE_NO_PAD.encode(&bytes) != value {
        refuse!("Reality 私钥必须解码为 32 字节且不含 padding");
    }
    let secret = StaticSecret::from(<[u8; 32]>::try_from(bytes).unwrap());
    Ok((value.to_owned(), URL_SAFE_NO_PAD.encode(PublicKey::from(&secret).as_bytes())))
}

fn valid_uuid(value: &str) -> bool {
    let parts: Vec<_> = value.split('-').collect();
    parts.len() == 5
        && [8, 4, 4, 4, 12]
            .iter()
            .zip(parts)
            .all(|(&len, part)| part.len() == len && part.bytes().all(|b| b.is_ascii_hexdigit()))
}

fn validate_short_id(value: &str) -> Result<()> {
    if value.is_empty()
        || value.len() > 16
        || !value.len().is_multiple_of(2)
        || !value.bytes().all(|b| b.is_ascii_hexdigit())
    {
        refuse!("Reality short ID 必须是非空、偶数长度且最多 16 个十六进制字符");
    }
    Ok(())
}

/// The credential a protocol's first user carries: a UUID for VLESS, a
/// Shadowsocks-2022 key, or a plain random password.
fn new_credential(node: &ProxyNode) -> Result<String> {
    Ok(match node.protocol.as_str() {
        "vless-reality" => new_uuid(),
        "shadowsocks" => ss_key(&node.method)?,
        _ => new_password(),
    })
}

/// The cipher a Shadowsocks node renders with, falling back to the default.
fn ss_method(node: &ProxyNode) -> &str {
    if node.method.is_empty() {
        SS_DEFAULT_METHOD
    } else {
        &node.method
    }
}

// ---- node CRUD helpers ----

fn parse_port_pool(pool: &str) -> Result<(i64, i64)> {
    let Some((lo, hi)) = pool.split_once('-') else {
        refuse!("端口池格式应为 起始-结束，例如 20000-50000")
    };
    let (Ok(lo), Ok(hi)) = (lo.trim().parse::<i64>(), hi.trim().parse::<i64>()) else {
        refuse!("端口池起止不是数字：{pool}")
    };
    if lo < 1 || hi > 65535 || lo > hi {
        refuse!("端口池范围无效：{pool}")
    }
    Ok((lo, hi))
}

fn choose_free_port(pool: &str, used: &HashSet<i64>) -> Result<i64> {
    let (lo, hi) = parse_port_pool(pool)?;
    let free: Vec<i64> = (lo..=hi).filter(|p| !used.contains(p)).collect();
    if free.is_empty() {
        refuse!("端口池 {lo}-{hi} 已满，请扩大范围或手动指定端口");
    }
    let index = (rand::random::<u64>() % free.len() as u64) as usize;
    Ok(free[index])
}

/// Picks a random free port in the pool on one server. The pool is the
/// `proxy_port_pool` setting, `20000-50000` unless set otherwise（设计文档 4）.
fn allocate_port(app: &App, server_id: i64) -> Result<i64> {
    let pool = app.db.get("proxy_port_pool").unwrap_or_else(|| "20000-50000".into());
    let mut used: HashSet<i64> = proxy_used_ports_scoped(app, server_id)?.into_iter().collect();
    used.extend(relay_ports_on(app, server_id)?);
    choose_free_port(&pool, &used)
}

/// 一台服务器上被中转侧占用的端口：该机中转的监听端口（单端口或「起-止」段，
/// 段全展开）+ 指向它的隧道出口端口。协议侧与中转侧必须看同一份占用：
/// sing-box 与 realm 是同一台机器上抢绑定的两个进程，先起者得，后起者
/// bind 失败进崩溃循环（二期前协议侧的分配/校验只查协议表，是瞎的）。
pub fn relay_ports_on(app: &App, server_id: i64) -> Result<Vec<i64>> {
    let scopes = port_scopes(app, server_id);
    let mut out = Vec::new();
    for r in app.db.relay_rules()? {
        let backs = entry_backup_ids(&r);
        let on_primary = scopes.contains(&r.server_id);
        let on_backup = backs.iter().any(|b| scopes.contains(b));
        if on_primary || on_backup {
            let ports: Vec<i64> =
                r.listen_port.split('-').filter_map(|p| p.trim().parse::<i64>().ok()).collect();
            match ports.as_slice() {
                [one] => out.push(*one),
                [lo, hi] if lo <= hi => out.extend(*lo..=*hi),
                _ => {}
            }
        }
        if scopes.contains(&r.exit_server_id) {
            if let Ok(p) = r.exit_listen_port.trim().parse::<i64>() {
                out.push(p);
            }
        }
    }
    Ok(out)
}

/// 占了 port 的中转规则名（协议端口冲突报错文案用）：该机监听端口/段覆盖
/// port，或隧道出口半边等于 port。
pub fn relay_rule_on_port(app: &App, server_id: i64, port: i64) -> Result<Option<String>> {
    let scopes = port_scopes(app, server_id);
    for r in app.db.relay_rules()? {
        let on_listen = if !scopes.contains(&r.server_id) {
            false
        } else if let Some((lo, hi)) = r
            .listen_port
            .split_once('-')
            .and_then(|(a, b)| Some((a.trim().parse::<i64>().ok()?, b.trim().parse::<i64>().ok()?)))
        {
            (lo..=hi).contains(&port)
        } else {
            r.listen_port.split('-').next().unwrap_or("").parse::<i64>() == Ok(port)
        };
        if on_listen
            || (scopes.contains(&r.exit_server_id) && r.exit_listen_port.trim().parse::<i64>() == Ok(port))
        {
            return Ok(Some(r.name));
        }
    }
    Ok(None)
}

/// 规则的备用入口机 id 列表（entry_backups JSON）。
pub fn entry_backup_ids(r: &crate::db::RelayRule) -> Vec<i64> {
    serde_json::from_str::<Vec<i64>>(r.entry_backups.trim()).unwrap_or_default()
}

/// 节点渲染到的机器全集（切换主机）：原机 server_id + 镜像机 mirror_servers。
/// 渲染过滤与端口占用都以它为准——镜像机出的是同一套 uuid/密钥/端口。
pub fn node_server_ids(n: &crate::db::ProxyNode) -> Vec<i64> {
    let mut ids = vec![n.server_id];
    ids.extend(serde_json::from_str::<Vec<i64>>(n.mirror_servers.trim()).unwrap_or_default());
    ids
}

/// 端口占用互查的身份范围：server_id=0（本机核心）与 hostname 等于 hub 的
/// 「主」节点行指同一台物理机，两套身份共用一个端口空间——协议/中转谁挂
/// 在哪套身份上，占用检查都必须互通（hub+agent 同机部署形态）。
fn port_scopes(app: &App, server_id: i64) -> Vec<i64> {
    let mut scopes = vec![server_id];
    if let Some(local) = local_node_server_id(app) {
        if server_id == 0 && !scopes.contains(&local) {
            scopes.push(local);
        } else if server_id == local && !scopes.contains(&0) {
            scopes.push(0);
        }
    }
    scopes
}

/// 协议端口的注册表占用：跨身份范围合并（见 port_scopes）。
fn proxy_used_ports_scoped(app: &App, server_id: i64) -> Result<Vec<i64>> {
    let mut out = Vec::new();
    for scope in port_scopes(app, server_id) {
        out.extend(app.db.proxy_used_ports(scope)?);
    }
    Ok(out)
}

/// 某机器上协议侧占用的端口（切换主机的全量口径）：本机直挂节点 ∪ 镜像到
/// 该机的节点 ∪ 身份范围合并。镜像节点的端口在目标机同样独占——同一台机
/// 上 sing-box 只能有一个进程绑同一端口。
fn used_ports_on(app: &App, server_id: i64) -> Result<Vec<i64>> {
    let scopes = port_scopes(app, server_id);
    let mut out = proxy_used_ports_scoped(app, server_id)?;
    for n in app.db.proxy_nodes()? {
        if n.server_id == 0 || scopes.contains(&n.server_id) {
            continue;
        }
        if node_server_ids(&n).iter().any(|sid| scopes.contains(sid)) {
            out.push(n.listen_port);
        }
    }
    Ok(out)
}

fn check_common(node: &ProxyNode) -> Result<()> {
    if node.name.trim().is_empty() {
        refuse!("请填写节点名称");
    }
    if !(0..=10000).contains(&node.rate_up) || !(0..=10000).contains(&node.rate_down) {
        refuse!("限速值无效：0（不限）到 10000 Mbps");
    }
    if !RENDERABLE.contains(&node.protocol.as_str()) {
        refuse!("不支持的协议：{}", node.protocol);
    }
    if NEEDS_SNI.contains(&node.protocol.as_str()) && node.sni.trim().is_empty() {
        refuse!("该协议需要伪装目标 / SNI，例如 www.yahoo.com");
    }
    if node.protocol == "vless-reality" && !node.flow.is_empty() && node.flow != "xtls-rprx-vision" {
        refuse!("流控只能是 xtls-rprx-vision 或空字符串");
    }
    if !node.egress_type.is_empty() {
        if !matches!(node.egress_type.as_str(), "socks5" | "http") {
            refuse!("出口类型只支持 socks5 / http");
        }
        if node.egress_host.trim().is_empty() {
            refuse!("请填写出口代理地址");
        }
        if !(1..=65535).contains(&node.egress_port) {
            refuse!("出口端口无效：{}", node.egress_port);
        }
    }
    Ok(())
}

fn default_sni(protocol: &str) -> &'static str {
    match protocol {
        "vless-reality" => "www.yahoo.com",
        "hysteria2" | "anytls" => "www.bing.com",
        _ => "",
    }
}

/// Creates a node: validates, allocates the port, generates credentials and
/// the Reality keypair, stores everything.
pub async fn create_node(app: &Shared, mut node: ProxyNode) -> Result<i64> {
    if node.sni.trim().is_empty() {
        node.sni = default_sni(&node.protocol).into();
    }
    check_common(&node)?;
    // 身份归一：server_id=0 的「本机」虚拟身份已退役（迁移 47 CHECK 兜底），
    // 协议只能挂在真实节点行上——面板机自己就是「主」节点行。
    if node.server_id <= 0 {
        refuse!("请选择节点：本机身份已并入节点列表");
    }
    if app.db.node(node.server_id)?.is_none() {
        refuse!("节点所属服务器不存在");
    }
    // 远程服务器缺核心就自动补装（install.sh 默认已装，这里只是兜底）。
    if node.server_id != 0 {
        if let Err(e) = ensure_remote_core(app, node.server_id).await {
            warn!("auto core install skipped: {e:#}");
        }
    }
    let auto_port = node.listen_port == 0;
    if auto_port {
        node.listen_port = allocate_port(app, node.server_id)?;
    } else if proxy_used_ports_scoped(app, node.server_id)?.contains(&node.listen_port) {
        refuse!("端口 {} 已被占用", node.listen_port);
    } else if let Some(rule) = relay_rule_on_port(app, node.server_id, node.listen_port)? {
        refuse!(
            "端口 {} 与隧道规则「{}」的端口冲突：同一台机器上 sing-box 与 realm 绑不上同一个端口",
            node.listen_port,
            rule
        );
    }
    node.name = node.name.trim().to_owned();
    node.sni = node.sni.trim().to_owned();
    // vless-reality 默认启用 vision flow（Reality 的推荐配置）。
    if node.protocol == "vless-reality" && node.flow.trim().is_empty() {
        node.flow = "xtls-rprx-vision".to_owned();
    }
    node.flow = node.flow.trim().to_owned();
    if node.protocol == "shadowsocks" && node.method.trim().is_empty() {
        node.method = SS_DEFAULT_METHOD.into();
    }
    let custom_private = node.reality_private_key.as_deref().filter(|v| !v.trim().is_empty()).map(str::trim);
    let custom_short = node.reality_short_id.as_deref().filter(|v| !v.trim().is_empty()).map(str::trim);
    if let Some(short) = custom_short {
        validate_short_id(short)?;
    }
    let secret = node_secret(&node, custom_private, custom_short)?;
    let credential = match node.uuid.as_deref().filter(|v| !v.trim().is_empty()).map(str::trim) {
        Some(uuid) if node.protocol == "vless-reality" => {
            if !valid_uuid(uuid) {
                refuse!("UUID 格式无效");
            }
            uuid.to_owned()
        }
        Some(_) if node.protocol != "vless-reality" => new_credential(&node)?,
        None => new_credential(&node)?,
        Some(_) => new_credential(&node)?,
    };
    let id = loop {
        match app.db.create_proxy_node(&node, &secret, &credential) {
            Ok(id) => break id,
            Err(e) if auto_port && e.to_string().contains("端口") => {
                node.listen_port = allocate_port(app, node.server_id)?;
            }
            Err(e) => return Err(e),
        }
    };
    info!("proxy node {id} created: {} :{}", node.protocol, node.listen_port);
    Ok(id)
}

/// Updates the mutable fields of a node. The port may move; uniqueness is
/// checked here for the friendly wording, the schema enforces it regardless.
pub async fn update_node(app: &Shared, mut node: ProxyNode) -> Result<()> {
    check_common(&node)?;
    if node.server_id <= 0 {
        refuse!("请选择节点：本机身份已并入节点列表");
    }
    // Updates must carry a real port; only creation may ask for allocation.
    if !(1..=65535).contains(&node.listen_port) {
        refuse!("端口无效：{}", node.listen_port);
    }
    let Some(current) = app.db.proxy_node(node.id)? else { refuse!("节点不存在，可能已被删除") };
    if current.listen_port != node.listen_port || current.server_id != node.server_id {
        // 端口冲突按节点机器全集查（原机 + 镜像机，镜像机同样独占端口）。
        // 镜像集取库里的现值——PUT 不接受客户端改写 mirror_servers。
        let mut machines = vec![node.server_id];
        machines.extend(serde_json::from_str::<Vec<i64>>(current.mirror_servers.trim()).unwrap_or_default());
        for sid in machines {
            let used: HashSet<i64> = used_ports_on(app, sid)?.into_iter().collect();
            // 本节点自己的现有端口不算自冲突。
            if used.contains(&node.listen_port) && node.listen_port != current.listen_port {
                refuse!("端口 {} 已被占用", node.listen_port);
            }
            if let Some(rule) = relay_rule_on_port(app, sid, node.listen_port)? {
                refuse!(
                    "端口 {} 与隧道规则「{}」的端口冲突：同一台机器上 sing-box 与 realm 绑不上同一个端口",
                    node.listen_port,
                    rule
                );
            }
        }
    }
    if node.server_id != 0 {
        if let Err(e) = ensure_remote_core(app, node.server_id).await {
            warn!("auto core install skipped: {e:#}");
        }
    }
    node.name = node.name.trim().to_owned();
    node.sni = node.sni.trim().to_owned();
    // vless-reality 默认启用 vision flow（Reality 的推荐配置）。
    if node.protocol == "vless-reality" && node.flow.trim().is_empty() {
        node.flow = "xtls-rprx-vision".to_owned();
    }
    node.flow = node.flow.trim().to_owned();
    if node.protocol == "shadowsocks" && node.method.trim().is_empty() {
        node.method = SS_DEFAULT_METHOD.into();
    }
    // The self-signed pair was minted for the old SNI; re-mint on a move.
    if matches!(node.protocol.as_str(), "hysteria2" | "anytls") && current.sni != node.sni {
        let (cert, key) = self_signed_cert(&node.sni)?;
        app.db.update_proxy_secret_cert(node.id, &cert, &key)?;
    }
    let current_secret = app.db.proxy_secret(node.id)?.unwrap_or_default();
    let custom_private = node.reality_private_key.as_deref().filter(|v| !v.trim().is_empty()).map(str::trim);
    let custom_short = node.reality_short_id.as_deref().filter(|v| !v.trim().is_empty()).map(str::trim);
    if let Some(short) = custom_short {
        validate_short_id(short)?;
    }
    let secret = if node.protocol == "vless-reality" && (custom_private.is_some() || custom_short.is_some()) {
        let private = custom_private.unwrap_or(&current_secret.private_key);
        let (private, public) = reality_keypair_from_private(private)?;
        Some(ProxySecret {
            private_key: private,
            public_key: public,
            short_id: custom_short.unwrap_or(&current_secret.short_id).to_owned(),
            ..current_secret.clone()
        })
    } else {
        None
    };
    let credential = match node.uuid.as_deref().filter(|v| !v.trim().is_empty()).map(str::trim) {
        Some(uuid) if node.protocol == "vless-reality" => {
            if !valid_uuid(uuid) {
                refuse!("UUID 格式无效");
            }
            Some(uuid.to_owned())
        }
        Some(_) if node.protocol != "vless-reality" => None,
        None => None,
        Some(_) => None,
    };
    app.db.update_proxy_node(&node, secret.as_ref(), credential.as_deref())?;
    Ok(())
}

// ---- config rendering (设计文档 8.2 / 8.3) ----

/// The TLS block for a protocol that dials TLS itself (hysteria2 / anytls):
/// the self-signed pair goes inline, so configs stay one JSON document.
fn tls_block(node: &ProxyNode, bundle: &NodeBundle) -> Result<serde_json::Value> {
    match bundle.secret.tls_mode.as_str() {
        "selfsign" if !bundle.secret.cert_pem.is_empty() => Ok(serde_json::json!({
            "enabled": true,
            "server_name": node.sni,
            // sing-box 1.13+：内联证书是 PEM 的行数组，字段名为 certificate / key。
            "certificate": bundle.secret.cert_pem.lines().collect::<Vec<_>>(),
            "key": bundle.secret.key_pem.lines().collect::<Vec<_>>(),
        })),
        _ => refuse!("节点「{}」缺少证书，请删除后重建", node.name),
    }
}

/// 渲染一台服务器的完整配置。`remote` 只影响 clash_api 的端口选择：端口
/// 探测反映的是 hub 本机的占用，对远程配置不成立（M3 的教训），远程固定用
/// 设置值或 9090。
pub fn render_config_for(app: &App, bundles: &[NodeBundle], remote: bool) -> Result<serde_json::Value> {
    let mut inbounds = Vec::new();
    let mut egress_outbounds = Vec::new();
    let mut egress_rules = Vec::new();
    for bundle in bundles {
        let n = &bundle.node;
        if bundle.users.is_empty() {
            refuse!("节点「{}」没有任何凭据", n.name);
        }
        let tag = format!("in-{}", n.listen_port);
        let users_password: Vec<_> = bundle
            .users
            .iter()
            .map(|u| serde_json::json!({ "name": u.name, "password": u.credential }))
            .collect();
        let inbound = match n.protocol.as_str() {
            "vless-reality" => {
                let users: Vec<_> = bundle
                    .users
                    .iter()
                    .map(|u| {
                        let mut user = serde_json::json!({ "name": u.name, "uuid": u.credential });
                        if n.flow == "xtls-rprx-vision" {
                            user["flow"] = serde_json::json!(n.flow);
                        }
                        user
                    })
                    .collect();
                serde_json::json!({
                    "type": "vless",
                    "tag": tag,
                    "listen": "::",
                    "listen_port": n.listen_port,
                    "users": users,
                    "tls": {
                        "enabled": true,
                        "server_name": n.sni,
                        "reality": {
                            "enabled": true,
                            "handshake": { "server": n.sni, "server_port": 443 },
                            "private_key": bundle.secret.private_key,
                            "short_id": [bundle.secret.short_id],
                        }
                    }
                })
            }
            "hysteria2" => serde_json::json!({
                "type": "hysteria2",
                "tag": tag,
                "listen": "::",
                "listen_port": n.listen_port,
                "users": users_password,
                "tls": tls_block(n, bundle)?,
            }),
            "anytls" => serde_json::json!({
                "type": "anytls",
                "tag": tag,
                "listen": "::",
                "listen_port": n.listen_port,
                "users": users_password,
                "tls": tls_block(n, bundle)?,
            }),
            "shadowsocks" => {
                // 单凭据（SS2022 的多用户格式在客户端侧不互通：sing-box 客户端
                // 只收单 PSK，mihomo 拼接式又各有实现）。需要隔离就再开一个节点。
                if bundle.users.len() > 1 {
                    refuse!("Shadowsocks 节点只支持一个凭据");
                }
                serde_json::json!({
                    "type": "shadowsocks",
                    "tag": tag,
                    "listen": "::",
                    "listen_port": n.listen_port,
                    "method": ss_method(n),
                    "password": bundle.users[0].credential,
                    "multiplex": { "enabled": true },
                })
            }
            "socks" | "http" => {
                let users: Vec<_> = bundle
                    .users
                    .iter()
                    .map(|u| serde_json::json!({ "username": u.name, "password": u.credential }))
                    .collect();
                serde_json::json!({
                    "type": n.protocol,
                    "tag": tag,
                    "listen": "::",
                    "listen_port": n.listen_port,
                    "users": users,
                })
            }
            other => refuse!("协议 {other} 的配置生成尚未实现"),
        };
        inbounds.push(inbound);
        // 链式出口（M2.5）：该入站的流量先交给上游 socks5/http 代理。按入站
        // 标签分流，每个节点一个专属出站，凭据即使相同也互不影响。
        if !n.egress_type.is_empty() {
            let egress_tag = format!("egress-{}", n.listen_port);
            let mut outbound = match n.egress_type.as_str() {
                "socks5" => serde_json::json!({ "type": "socks", "version": "5" }),
                "http" => serde_json::json!({ "type": "http" }),
                other => refuse!("不支持的出口类型：{other}"),
            };
            outbound["tag"] = serde_json::Value::String(egress_tag.clone());
            outbound["server"] = serde_json::Value::String(n.egress_host.trim().to_owned());
            outbound["server_port"] = n.egress_port.into();
            if !n.egress_username.trim().is_empty() {
                outbound["username"] = serde_json::Value::String(n.egress_username.trim().to_owned());
            }
            if !n.egress_password.trim().is_empty() {
                outbound["password"] = serde_json::Value::String(n.egress_password.trim().to_owned());
            }
            egress_outbounds.push(outbound);
            egress_rules.push(serde_json::json!({
                "inbound": [format!("in-{}", n.listen_port)],
                "outbound": egress_tag,
            }));
        }
    }
    let clash_secret = match app.db.get("proxy_clash_secret") {
        Some(s) if !s.is_empty() => s,
        _ => {
            let s = crate::auth::random_token();
            app.db.set("proxy_clash_secret", &s)?;
            s
        }
    };
    let mut outbounds = vec![serde_json::json!({ "type": "direct", "tag": "direct" })];
    outbounds.extend(egress_outbounds);
    let mut rules = vec![
        serde_json::json!({ "action": "sniff" }),
        serde_json::json!({ "protocol": "dns", "action": "hijack-dns" }),
    ];
    rules.extend(egress_rules);
    // 远程配置暂不带 clash_api：端口占用只有 agent 自己知道，hub 探测不到；
    // M4 接远程统计时让 agent 自选端口并上报。本机沿用探测逻辑。用户级流量
    // （M12）由 sing-box api service（1.14+ 官方自带）的连接事件流承载，
    // 官方核心即可运行。
    let experimental = if remote {
        serde_json::Value::Null
    } else {
        serde_json::json!({
            "clash_api": { "external_controller": clash_api_addr(app), "secret": clash_secret },
        })
    };
    let mut out = serde_json::json!({
        "log": { "level": "info", "timestamp": true },
        "experimental": experimental,
        "inbounds": inbounds,
        "outbounds": outbounds,
        // sing-box 1.13 起没有 dns outbound：DNS 劫持与协议嗅探都是 route action。
        "route": { "rules": rules, "final": "direct" }
    });
    // sing-box api service（M12）：连接事件流是用户级计量的数据源，1.14+
    // 官方自带。仅本机配置；远程侧由 agent 注入自己的实例。
    if !remote {
        out["services"] = serde_json::json!([{
            "type": "api",
            "listen": "127.0.0.1",
            "listen_port": api_service_port(app),
        }]);
    }
    Ok(out)
}

// ---- share links and subscription (设计文档 9 / 10) ----

/// Percent-encodes a fragment or query value the way every client tolerates.
pub fn pct(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for b in s.as_bytes() {
        match b {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => out.push(*b as char),
            _ => out.push_str(&format!("%{b:02X}")),
        }
    }
    out
}

/// The address clients should dial for a node: remote servers use their own
/// public address (the agent's reported interface IPv4, else the connection
/// origin); 本机 nodes fall back to the public_host chain（设计文档 9）。
pub fn node_dial_host(app: &App, server_id: i64, headers: Option<&axum::http::HeaderMap>) -> String {
    if server_id != 0 {
        if let Ok(Some(n)) = app.db.node(server_id) {
            for candidate in [n.ipv4.as_str(), n.ip.as_str()] {
                let c = candidate.trim();
                if !c.is_empty() {
                    return c.to_owned();
                }
            }
        }
        return public_host(app, headers);
    }
    public_host(app, headers)
}

/// The address clients should dial: the `proxy_public_host` setting wins,
/// then `--site`'s host, then the Host header of the request that asked.
pub fn public_host(app: &App, headers: Option<&axum::http::HeaderMap>) -> String {
    if let Some(h) = app.db.get("proxy_public_host") {
        let h = h.trim().to_owned();
        if !h.is_empty() {
            return h;
        }
    }
    if !app.site.is_empty() {
        return app.site.trim_start_matches("https://").trim_start_matches("http://").to_owned();
    }
    if let Some(h) = headers.and_then(|hs| hs.get("host")).and_then(|v| v.to_str().ok()) {
        // The Host header may carry the panel's port; the node's own port is
        // appended separately.
        let host = h.rsplit_once(':').map_or(h, |(h, _)| h);
        if !host.is_empty() {
            return host.to_owned();
        }
    }
    "127.0.0.1".to_owned()
}

// ---- 订阅入口地址（M8）：域名 / IP / CDN 前置的多地址订阅 ----

/// 一个订阅入口：客户端拨它连到节点。`port` 覆盖节点的监听端口——CDN 或
/// 中转前置时入口端口与落地端口不同；`scheme` 只在面板拼订阅 URL 时用，
/// 拨号本身不区分。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Front {
    pub host: String,
    pub port: Option<u16>,
    pub scheme: String,
}

/// 解析一行入口地址：`example.com`、`example.com:8443`、`https://cdn.example.com`、
/// `http://1.2.3.4:28080`、`[2606:4700::1111]:443`。冒号后不是端口的整个当
/// host（裸 IPv6 不带括号的写法交给设置者自己加括号）。
pub fn parse_front(line: &str) -> Option<Front> {
    let line = line.trim();
    if line.is_empty() {
        return None;
    }
    let (scheme, rest) = match line.split_once("://") {
        Some((s, r)) if s == "http" || s == "https" => (s.to_owned(), r),
        Some(_) => return None,
        None => ("https".to_owned(), line),
    };
    let rest = rest.split('/').next().unwrap_or("");
    if rest.is_empty() {
        return None;
    }
    let (host, port) = if let Some(v6) = rest.strip_prefix('[') {
        let (h, tail) = v6.split_once(']')?;
        (h.to_owned(), tail.strip_prefix(':').and_then(|p| p.parse().ok()))
    } else {
        match rest.rsplit_once(':') {
            Some((h, p)) => match p.parse::<u16>() {
                Ok(port) => (h.to_owned(), Some(port)),
                Err(_) => (rest.to_owned(), None),
            },
            None => (rest.to_owned(), None),
        }
    };
    (!host.is_empty()).then_some(Front { host, port, scheme })
}

/// 入口的短标签，多地址订阅里缀在节点名后：域名取第一段（vip.example.com
/// → vip），IP 原样。
pub fn front_label(front: &Front) -> String {
    if front.host.parse::<std::net::IpAddr>().is_ok() {
        front.host.clone()
    } else {
        front.host.split('.').next().unwrap_or(&front.host).to_owned()
    }
}

/// `sub_hosts` 设置（每行一个入口）解析成拨号用的入口列表；空设置回落
/// public_host 的既有三级链——单一入口、无名称后缀，与历史行为一致。
pub fn sub_fronts(app: &App) -> Vec<Front> {
    let parsed: Vec<Front> =
        app.db.get("sub_hosts").map(|v| v.lines().filter_map(parse_front).collect()).unwrap_or_default();
    if parsed.is_empty() {
        vec![Front { host: public_host(app, None), port: None, scheme: "https".into() }]
    } else {
        parsed
    }
}

/// The share link for one credential on one node (设计文档 9). Self-signed
/// nodes carry `insecure=1`, since there is no chain a client could trust.
/// `label` 缀在节点名后，多入口订阅用来区分同一节点的不同入口。
pub fn share_link(bundle: &NodeBundle, user: &ProxyUser, front: &Front, label: &str) -> Result<String> {
    let n = &bundle.node;
    let host = &front.host;
    let port = front.port.map(|p| p as i64).unwrap_or(n.listen_port);
    let name = pct(&format!("{}{}", n.name, label));
    let insecure = if bundle.secret.tls_mode == "selfsign" { "1" } else { "0" };
    match n.protocol.as_str() {
        "vless-reality" => {
            let flow = if n.flow == "xtls-rprx-vision" { "&flow=xtls-rprx-vision" } else { "" };
            Ok(format!(
                "vless://{}@{}:{}?encryption=none&security=reality&sni={}&fp=chrome&pbk={}&sid={}&type=tcp{}#{}",
                user.credential, host, port, pct(&n.sni), pct(&bundle.secret.public_key),
                pct(&bundle.secret.short_id), flow, name,
            ))
        }
        "hysteria2" => Ok(format!(
            "hysteria2://{}@{}:{}/?sni={}&insecure={}#{}",
            user.credential,
            host,
            port,
            pct(&n.sni),
            insecure,
            name,
        )),
        "shadowsocks" => {
            let userinfo = URL_SAFE_NO_PAD.encode(format!("{}:{}", ss_method(n), user.credential));
            Ok(format!("ss://{userinfo}@{}:{}#{}", host, port, name))
        }
        "anytls" => Ok(format!(
            "anytls://{}@{}:{}/?sni={}&insecure={}#{}",
            user.credential,
            host,
            port,
            pct(&n.sni),
            insecure,
            name,
        )),
        "socks" => {
            let auth = URL_SAFE_NO_PAD.encode(format!("{}:{}", user.name, user.credential));
            Ok(format!("socks://{auth}@{}:{}#{}", host, port, name))
        }
        "http" => {
            Ok(format!("http://{}:{}@{}:{}#{}", pct(&user.name), pct(&user.credential), host, port, name,))
        }
        other => refuse!("协议 {other} 的分享链接尚未实现"),
    }
}

/// The (node, credential) pairs a customer's subscription renders: every
/// enabled node where they hold a claimed credential.
fn subscription_bundles(app: &App, sub: &SubUser) -> Result<Vec<(NodeBundle, ProxyUser)>> {
    let bundles = app.db.proxy_node_bundles()?;
    let mut out = Vec::new();
    for mut bundle in bundles {
        if !bundle.node.enabled {
            continue;
        }
        // 方向 40：凭据级失格（到期/超额）的凭据不进客户订阅
        let users: Vec<ProxyUser> = bundle
            .users
            .iter()
            .filter(|u| u.sub_user_id == Some(sub.id) && credential_live(u, today()))
            .cloned()
            .collect();
        if users.is_empty() {
            continue;
        }
        bundle.users = users;
        for user in bundle.users.clone() {
            out.push((bundle.clone(), user));
        }
    }
    if out.is_empty() {
        refuse!("该客户还没有被分配任何节点凭据");
    }
    Ok(out)
}

/// Renders one customer's subscription in the format their client asked for
/// (设计文档 10.2): Clash(mihomo) YAML, sing-box JSON, or base64 of one share
/// link per line — the default v2rayN / Shadowrocket accept.
pub fn subscription_for(app: &App, sub: &SubUser, ua: &str) -> Result<(String, &'static str)> {
    let bundles = subscription_bundles(app, sub)?;
    // 多入口（M8）：每个节点按每个入口各渲染一条，名称缀上入口短标签；
    // 单入口保持历史形态，不带后缀。
    let fronts = sub_fronts(app);
    let suffix = |f: &Front| if fronts.len() > 1 { format!("·{}", front_label(f)) } else { String::new() };
    let ua = ua.to_ascii_lowercase();
    if ["clash", "mihomo", "verge", "stash"].iter().any(|k| ua.contains(k)) {
        Ok((clash_yaml(&bundles, &fronts)?, "text/yaml; charset=utf-8"))
    } else if ["sing-box", "sfa", "sfi", "sfm", "sft"].iter().any(|k| ua.contains(k)) {
        Ok((singbox_json(&bundles, &fronts)?.to_string(), "application/json"))
    } else {
        let mut lines = Vec::new();
        for (bundle, user) in &bundles {
            for front in &fronts {
                lines.push(share_link(bundle, user, front, &suffix(front))?);
            }
        }
        Ok((STANDARD.encode(lines.join("\n")), "text/plain; charset=utf-8"))
    }
}

/// Names stay unique inside one subscription, the way clients require.
fn unique_name(name: &str, used: &mut HashSet<String>) -> String {
    if used.insert(name.to_owned()) {
        return name.to_owned();
    }
    let mut i = 2;
    while !used.insert(format!("{name}-{i}")) {
        i += 1;
    }
    format!("{name}-{i}")
}

/// Whether a client must skip verifying this node's certificate.
fn skip_verify(bundle: &NodeBundle) -> &'static str {
    if bundle.secret.tls_mode == "selfsign" {
        "true"
    } else {
        "false"
    }
}

/// Hand-rolled Clash(mihomo) proxies entries, escaping values the same way
/// 「节点转化助手.html」does — a YAML library is not worth its weight here.
fn yv(v: &str) -> String {
    if v.is_empty() {
        return "\"\"".into();
    }
    let special = v.chars().any(|c| {
        matches!(
            c,
            ':' | '#'
                | '"'
                | '\''
                | '\\'
                | '{'
                | '}'
                | '['
                | ']'
                | ','
                | '&'
                | '*'
                | '?'
                | '|'
                | '>'
                | '%'
                | '`'
                | '@'
                | '!'
                | '^'
        )
    }) || v.starts_with(['-', ' '])
        || v.ends_with(' ')
        || v.parse::<f64>().is_ok();
    if special {
        format!("\"{}\"", v.replace('\\', "\\\\").replace('"', "\\\""))
    } else {
        v.to_owned()
    }
}

pub fn clash_yaml(bundles: &[(NodeBundle, ProxyUser)], fronts: &[Front]) -> Result<String> {
    let multi = fronts.len() > 1;
    let mut used = HashSet::new();
    let mut proxies = Vec::new();
    for (bundle, user) in bundles {
        let n = &bundle.node;
        for front in fronts {
            let label = if multi { format!("·{}", front_label(front)) } else { String::new() };
            let name = unique_name(&format!("{}{label}", n.name), &mut used);
            let host = &front.host;
            let port = front.port.map(|p| p as i64).unwrap_or(n.listen_port);
            let head = format!("  - name: {}\n    server: {}\n    port: {port}\n", yv(&name), yv(host));
            let body = match n.protocol.as_str() {
            "vless-reality" => format!(
                "    type: vless\n    uuid: {}\n    tls: true\n    servername: {}\n{}    network: tcp\n    udp: true\n    client-fingerprint: chrome\n    reality-opts:\n      public-key: {}\n      short-id: {}\n",
                yv(&user.credential), yv(&n.sni),
                if n.flow == "xtls-rprx-vision" { "    flow: xtls-rprx-vision\n" } else { "" },
                yv(&bundle.secret.public_key), yv(&bundle.secret.short_id),
            ),
            "hysteria2" => format!(
                "    type: hysteria2\n    password: {}\n    sni: {}\n    skip-cert-verify: {}\n    alpn: [h3]\n",
                yv(&user.credential),
                yv(&n.sni),
                skip_verify(bundle),
            ),
            "shadowsocks" => format!(
                "    type: ss\n    cipher: {}\n    password: {}\n    udp: true\n",
                yv(ss_method(n)),
                yv(&user.credential),
            ),
            "anytls" => format!(
                "    type: anytls\n    password: {}\n    sni: {}\n    skip-cert-verify: {}\n",
                yv(&user.credential),
                yv(&n.sni),
                skip_verify(bundle),
            ),
            "socks" => format!(
                "    type: socks5\n    username: {}\n    password: {}\n    udp: true\n",
                yv(&user.name),
                yv(&user.credential),
            ),
            "http" => format!(
                "    type: http\n    username: {}\n    password: {}\n",
                yv(&user.name),
                yv(&user.credential),
            ),
            other => refuse!("协议 {other} 的 Clash 渲染尚未实现"),
        };
            proxies.push(format!("{head}{body}"));
        }
    }
    Ok(format!("proxies:\n{}", proxies.join("")))
}

/// A sing-box client config holding one outbound per node (per front, M8).
pub fn singbox_json(bundles: &[(NodeBundle, ProxyUser)], fronts: &[Front]) -> Result<serde_json::Value> {
    let multi = fronts.len() > 1;
    let mut used = HashSet::new();
    let mut outbounds = Vec::new();
    for (bundle, user) in bundles {
        let n = &bundle.node;
        let insecure = bundle.secret.tls_mode == "selfsign";
        for front in fronts {
            let label = if multi { format!("·{}", front_label(front)) } else { String::new() };
            let name = unique_name(&format!("{}{label}", n.name), &mut used);
            let server = &front.host;
            let port = front.port.map(|p| p as i64).unwrap_or(n.listen_port);
            let outbound = match n.protocol.as_str() {
                "vless-reality" => {
                    let mut outbound = serde_json::json!({
                        "type": "vless", "tag": name, "server": server, "server_port": port,
                        "uuid": user.credential,
                        "tls": {
                            "enabled": true, "server_name": n.sni,
                            "utls": { "enabled": true, "fingerprint": "chrome" },
                            "reality": { "enabled": true, "public_key": bundle.secret.public_key, "short_id": bundle.secret.short_id },
                        }
                    });
                    if n.flow == "xtls-rprx-vision" {
                        outbound["flow"] = serde_json::json!(n.flow);
                    }
                    outbound
                }
                "hysteria2" => serde_json::json!({
                    "type": "hysteria2", "tag": name, "server": server, "server_port": port,
                    "password": user.credential,
                    "tls": { "enabled": true, "server_name": n.sni, "insecure": insecure },
                }),
                "shadowsocks" => serde_json::json!({
                    "type": "shadowsocks", "tag": name, "server": server, "server_port": port,
                    "method": ss_method(n), "password": user.credential,
                }),
                "anytls" => serde_json::json!({
                    "type": "anytls", "tag": name, "server": server, "server_port": port,
                    "password": user.credential,
                    "tls": { "enabled": true, "server_name": n.sni, "insecure": insecure },
                }),
                "socks" => serde_json::json!({
                    "type": "socks", "tag": name, "server": server, "server_port": port, "version": "5",
                    "username": user.name, "password": user.credential,
                }),
                "http" => serde_json::json!({
                    "type": "http", "tag": name, "server": server, "server_port": port,
                    "username": user.name, "password": user.credential,
                }),
                other => refuse!("协议 {other} 的 sing-box 渲染尚未实现"),
            };
            outbounds.push(outbound);
        }
    }
    Ok(serde_json::json!({ "outbounds": outbounds }))
}

// ---- core lifecycle (设计文档 5.4，本机形态) ----

/// The address the running core actually listens on, read from the disk
/// config — the file is the fact source, the same way the agent treats its
/// own. Rendering a hub restart must not drift the ports: a running core
/// holds them for real, so the bind-probe fallback below would pick different
/// addresses, rewrite the config, and restart the core around every hub
/// restart for no reason.
fn existing_experimental_addr(app: &App, section: &str, key: &str) -> Option<String> {
    let body = std::fs::read_to_string(config_path(app)).ok()?;
    let v: serde_json::Value = serde_json::from_str(&body).ok()?;
    let addr = v.get("experimental")?.get(section)?.get(key)?.as_str()?.to_owned();
    (!addr.is_empty()).then_some(addr)
}

/// Picks the clash_api listen address: the `proxy_clash_api` setting wins,
/// then the address the current config already carries, else the first
/// candidate this machine can still bind. A taken port is fatal to the core
/// on start — unlike our listeners — and the common case of a Clash dashboard
/// already living on 9090 is exactly where a hub runs.
fn clash_api_addr(app: &App) -> String {
    if let Some(a) = app.db.get("proxy_clash_api") {
        let a = a.trim().to_owned();
        if !a.is_empty() {
            return a;
        }
    }
    if let Some(a) = existing_experimental_addr(app, "clash_api", "external_controller") {
        return a;
    }
    for port in [9090, 19090, 19091, 19092, 19093] {
        let addr = format!("127.0.0.1:{port}");
        if std::net::TcpListener::bind(&addr).is_ok() {
            return addr;
        }
    }
    "127.0.0.1:9090".to_owned()
}

/// sing-box api service 的监听端口（M12 用户级计量数据源），与 clash_api
/// 同一套确定性来源：设置优先，否则沿用磁盘配置里已有的，否则候选段探测。
/// 确定性是必须的——每次 apply 端口变化会改写配置指纹，核心就要多重启一次。
fn api_service_port(app: &App) -> u16 {
    if let Some(a) = app.db.get("proxy_api_service") {
        if let Ok(port) = a.trim().parse::<u16>() {
            return port;
        }
    }
    if let Some(port) = existing_services_port(app) {
        return port;
    }
    for port in [11980u16, 11981, 11982, 11983, 11984] {
        if std::net::TcpListener::bind(("127.0.0.1", port)).is_ok() {
            return port;
        }
    }
    11980
}

/// 磁盘配置里已注入的 api service 端口——文件是事实源，渲染重启不得漂移。
fn existing_services_port(app: &App) -> Option<u16> {
    let body = std::fs::read_to_string(config_path(app)).ok()?;
    let v: serde_json::Value = serde_json::from_str(&body).ok()?;
    v.get("services")?
        .as_array()?
        .iter()
        .find(|sv| sv.get("type").and_then(|t| t.as_str()) == Some("api"))
        .and_then(|sv| sv.get("listen_port"))
        .and_then(|p| p.as_u64())
        .map(|p| p as u16)
}

pub async fn detect_version(bin: &Path) -> Result<String> {
    let out = Command::new(bin)
        .arg("version")
        .output()
        .await
        .with_context(|| format!("无法运行 {}", bin.display()))?;
    if !out.status.success() {
        refuse!("核心版本探测失败，二进制可能不完整");
    }
    let text = String::from_utf8_lossy(&out.stdout);
    // First line: `sing-box version 1.12.4 ...`
    let v = text.lines().next().unwrap_or("").split_whitespace().nth(2).unwrap_or("").trim();
    if v.is_empty() {
        refuse!("无法从版本输出解析出版本号");
    }
    Ok(v.to_owned())
}

async fn latest_singbox_version(app: &App) -> Result<String> {
    let url = crate::proxied(app, format!("https://api.github.com/repos/{SINGBOX_REPO}/releases/latest"));
    let v: serde_json::Value = app
        .http
        .get(url)
        .header("User-Agent", "monitor-hub")
        .header("Accept", "application/vnd.github+json")
        .send()
        .await
        .context("无法访问 GitHub")?
        .error_for_status()
        .context("GitHub 返回错误")?
        .json()
        .await
        .context("解析 GitHub 响应失败")?;
    let tag = v["tag_name"].as_str().unwrap_or_default().trim_start_matches('v').to_owned();
    if tag.is_empty() {
        refuse!("无法获取 sing-box 最新版本号");
    }
    Ok(tag)
}

/// Resolves `version` (or the latest tag) and installs the matching release
/// into `proxy_dir/bin/sing-box`, going through the panel's `github_proxy`
/// when one is configured.
pub async fn install_core(app: &Shared, version: Option<String>) -> Result<String> {
    let version = match version {
        Some(v) => {
            let v = v.trim().trim_start_matches('v').to_owned();
            if v.is_empty() || !v.chars().all(|c| c.is_ascii_digit() || c == '.') {
                refuse!("版本号格式不对：{v}");
            }
            v
        }
        None => latest_singbox_version(app).await?,
    };
    let os = match std::env::consts::OS {
        "linux" => "linux",
        "macos" => "darwin",
        other => {
            refuse!("暂不支持在 {other} 上自动安装核心，请手动放置二进制到 {}", binary_path(app).display())
        }
    };
    let arch = match std::env::consts::ARCH {
        "x86_64" => "amd64",
        "aarch64" => "arm64",
        other => refuse!("暂不支持架构 {other}"),
    };
    let name = format!("sing-box-{version}-{os}-{arch}.tar.gz");
    let url =
        crate::proxied(app, format!("https://github.com/{SINGBOX_REPO}/releases/download/v{version}/{name}"));
    // app.http 的 15s 总超时对几十 MB 的核心包太短，这里单独建一个长超时客户端。
    let client =
        reqwest::Client::builder().timeout(Duration::from_secs(300)).build().context("构建下载客户端失败")?;
    let bytes = client
        .get(url)
        .header("User-Agent", "monitor-hub")
        .send()
        .await
        .context("下载 sing-box 失败")?
        .error_for_status()
        .context("下载 sing-box 失败：远端返回错误")?
        .bytes()
        .await
        .context("读取下载内容失败")?;
    let bin = binary_path(app);
    tokio::fs::create_dir_all(bin.parent().expect("bin has a parent")).await?;
    // 先解包到临时名再原子替换：直接覆盖运行中的二进制在 Linux 上会 ETXTBSY。
    let staging = bin.with_extension("new");
    let mut archive = tar::Archive::new(flate2::read::GzDecoder::new(&bytes[..]));
    let mut found = false;
    for entry in archive.entries()? {
        let mut entry = entry?;
        let path = entry.path()?.to_path_buf();
        if entry.header().entry_type().is_file() && path.file_name().is_some_and(|n| n == "sing-box") {
            // 解包是阻塞 IO；量级几十 MB，多线程 runtime 可承受。
            entry.unpack(&staging)?;
            found = true;
        }
    }
    if !found {
        let _ = tokio::fs::remove_file(&staging).await;
        refuse!("压缩包中没有找到 sing-box 可执行文件");
    }
    tokio::fs::rename(&staging, &bin).await?;
    // 版本切换：清掉已应用指纹，apply 时才会真正重启到新二进制。
    app.proxy.lock().unwrap_or_else(|e| e.into_inner()).applied_hash.clear();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&bin, std::fs::Permissions::from_mode(0o755))?;
    }
    let v = detect_version(&bin).await?;
    app.db.set("proxy_core_version", &v)?;
    info!("sing-box {v} installed at {}", bin.display());
    Ok(v)
}

async fn spawn_core(app: &Shared) -> Result<()> {
    let bin = binary_path(app);
    let cfg = config_path(app);
    let mut child = Command::new(&bin)
        .arg("run")
        .arg("-c")
        .arg(&cfg)
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .kill_on_drop(true)
        .spawn()
        .context("无法启动 sing-box")?;
    if let Some(err) = child.stderr.take() {
        tokio::spawn(pump(err));
    }
    if let Some(out) = child.stdout.take() {
        tokio::spawn(pump(out));
    }
    let mut st = app.proxy.lock().unwrap();
    st.child = Some(child);
    st.started_at = chrono::Utc::now().timestamp();
    st.last_error.clear();
    info!("sing-box started");
    Ok(())
}

/// Feeds the core's stdout/stderr into the hub log, prefixed so a crashed
/// config is diagnosable from `journalctl -u monitor-hub` alone. The target
/// sits under `monitor_hub` so the default `monitor_hub=info` filter passes
/// it through.
async fn pump<R>(stream: R)
where
    R: tokio::io::AsyncRead + Unpin,
{
    let mut lines = BufReader::new(stream).lines();
    while let Ok(Some(line)) = lines.next_line().await {
        info!(target: "monitor_hub::sing_box", "{line}");
    }
}

/// 应用所有变更（设计文档 5.5）：本机核心走本地 apply；每台有节点的远程
/// 服务器推送期望配置，agent 离线时不推——它上线后的第一条 proxy.hash 会
/// 触发对账补发。幂等：agent 收到相同指纹的配置且服务在跑时不动。
pub async fn apply(app: &Shared) -> Result<()> {
    // `apply_local` uses one fixed temporary path. API mutations, manual
    // apply, core start, and the supervisor can all reach this function at
    // once, so hold the guard across the complete check-and-swap sequence.
    let _guard = app.proxy_apply.lock().await;
    // 本机同时是 agent 节点时跳过 apply_local：它会把本机 0 节点的空配置写进
    // agent 管辖的同一份 config.json（写空↔写满乒乓，远程协议起不来——见
    // supervisor 的守卫注释）。远程服务器照常 reconcile。
    let servers = proxy_render_servers(app)?;
    if local_managed_by_agent(app) {
        for server_id in servers {
            reconcile_push(app, server_id)?;
        }
        return Ok(());
    }
    apply_local(app).await?;
    for server_id in servers {
        reconcile_push(app, server_id)?;
    }
    Ok(())
}

/// 有节点要渲染的远程机器全集（原机 + 镜像机，去重排序）。节点 CRUD 后的
/// 推送按它走——镜像机上加/摘凭据同样要立即生效。
pub fn proxy_render_servers(app: &App) -> Result<Vec<i64>> {
    let set: std::collections::BTreeSet<i64> = app
        .db
        .proxy_node_bundles()?
        .iter()
        .flat_map(|b| node_server_ids(&b.node))
        .filter(|s| *s != 0)
        .collect();
    Ok(set.into_iter().collect())
}

/// 本机（server_id = 0）的 apply。本机没有节点时静默跳过——节点可能都在远程。
async fn apply_local(app: &Shared) -> Result<()> {
    let bundles = gated_bundles(app, 0)?;
    let bin = binary_path(app);
    // 核心没装：本机没有可管理对象（节点可能都在远程服务器上）。
    if !bin.is_file() {
        return Ok(());
    }
    let version = detect_version(&bin).await?;
    // 有启用节点渲染入站；没有则空配置——核心干净地跑着（面板显示运行中，
    // systemd 不会因缺配置崩溃循环），以后新建节点推送即无感生效。
    // 两种状态走同一条 check → 原子替换 → 重启路径，幂等。
    let config = render_config_for(app, &bundles, false)?;
    let body = serde_json::to_string_pretty(&config)?;
    let hash = hex::encode(Sha256::digest(body.as_bytes()));
    let unit_running = if systemd() {
        tokio::process::Command::new("systemctl")
            .args(["is-active", "--quiet", "monitor-singbox@main"])
            .output()
            .await
            .map(|o| o.status.success())
            .unwrap_or(false)
    } else {
        app.proxy.lock().unwrap().child.is_some()
    };
    {
        let st = app.proxy.lock().unwrap();
        if st.applied_hash == hash && unit_running {
            return Ok(());
        }
    }
    tokio::fs::create_dir_all(config_path(app).parent().expect("config has a parent")).await?;
    let new_path = config_path(app).with_extension("json.new");
    tokio::fs::write(&new_path, &body).await?;
    let out = Command::new(&bin)
        .arg("check")
        .arg("-c")
        .arg(&new_path)
        .output()
        .await
        .context("无法运行 sing-box check")?;
    if !out.status.success() {
        let _ = tokio::fs::remove_file(&new_path).await;
        let detail = String::from_utf8_lossy(&out.stderr);
        let detail = detail.trim();
        refuse!("配置校验未通过：{}", if detail.is_empty() { "未知错误" } else { detail });
    }
    let last_good = config_path(app).with_extension("json.last_good");
    if config_path(app).exists() {
        tokio::fs::rename(config_path(app), &last_good).await?;
    }
    tokio::fs::rename(&new_path, config_path(app)).await?;

    let desired = app.db.get("proxy_desired_running").as_deref() == Some("on");
    let old = {
        let mut st = app.proxy.lock().unwrap();
        st.version = version;
        st.applied_hash = hash;
        st.child.take()
    };
    if let Some(mut child) = old {
        let _ = child.kill().await;
        info!("sing-box stopped for config swap");
    }
    // 配置有变即将重启/停止：旧连接的 id 不会再有事件，先定稿并清空。
    // （走到这里必然通过了 1229 行的「hash 未变且在运行」早退，核心此前
    // 一定在运行或刚被杀。）
    reset_conn_state();
    if desired {
        if systemd() {
            let rs = tokio::process::Command::new("systemctl")
                .args(["restart", "monitor-singbox@main"])
                .output()
                .await;
            if let Ok(o) = &rs {
                if !o.status.success() {
                    warn!("systemctl restart failed: {}", String::from_utf8_lossy(&o.stderr));
                }
            }
            app.proxy.lock().unwrap().child = None;
        } else {
            spawn_core(app).await?;
        }
    } else if systemd() {
        let _ =
            tokio::process::Command::new("systemctl").args(["stop", "monitor-singbox@main"]).output().await;
    }
    Ok(())
}
/// Applies only where it can: a hub with no core installed yet must accept
/// node CRUD without it; the config goes live on the first install/start.
pub async fn apply_if_ready(app: &Shared) -> bool {
    match apply(app).await {
        Ok(()) => true,
        Err(e) => {
            warn!("apply after mutation failed: {e:#}");
            app.proxy.lock().unwrap().last_error = format!("配置应用失败：{e:#}");
            notify_throttled(app, "apply_failed", "代理配置应用失败", format!("{e:#}"));
            false
        }
    }
}

fn notify_crash(app: &crate::App, message: String) {
    notify_throttled(app, "core_crash", "核心异常", message);
}

pub async fn start(app: &Shared) -> Result<()> {
    app.db.set("proxy_desired_running", "on")?;
    apply(app).await
}

pub async fn stop(app: &Shared) -> Result<()> {
    let _guard = app.proxy_apply.lock().await;
    app.db.set("proxy_desired_running", "off")?;
    let old = { app.proxy.lock().unwrap().child.take() };
    if let Some(mut child) = old {
        let _ = child.kill().await;
    }
    info!("sing-box stopped by operator");
    Ok(())
}

/// Crash guard: polls the child every 2 s. An unexpected exit is recorded and
/// the core pulled up again on a later tick (the config on disk is the last
/// one that passed check). Also starts the core after a hub restart when the
/// operator left it running — the setting survives, the process does not.
/// 本机是否同时是一台 agent 管理的节点：node 表里有 hostname 与 hub 自身
/// 相同的行（与 api.rs `hub_hostname`/node_view 的 local 同判定）。此时
/// /opt/monitor-proxy/instances/main/config.json 归 agent 的 apply 管辖，
/// hub 的本机核心路径（supervisor / apply_local）必须让位——两边写同一份
/// 文件会形成「写空↔写满」乒乓（2026-10-08 线上事故：首个挂在 server_id=1
/// 的同机协议起不来）。
/// hub 本机在 node 表里的身份：hostname 与 hub 相同的那行。None = 纯 hub
/// 部署（本机不跑 agent）。
pub fn local_node_server_id(app: &App) -> Option<i64> {
    let hub_host = std::fs::read_to_string("/etc/hostname").map(|s| s.trim().to_string()).ok()?;
    if hub_host.is_empty() {
        return None;
    }
    app.db.nodes().ok()?.iter().find(|n| n.hostname == hub_host).map(|n| n.id)
}

pub fn local_managed_by_agent(app: &App) -> bool {
    local_node_server_id(app).is_some()
}

pub async fn supervisor(app: crate::Shared) {
    // 本机就是某台 agent 节点（hostname 相同，node_view 的 local 同判定）时，
    // 该机器的 sing-box 配置文件归 agent 的 apply 管辖（/opt/monitor-proxy/
    // instances/main/config.json 是同一路径）。hub 的 supervisor 每轮
    // apply_local 用本机 0 节点的空配置覆盖它，与 agent 推来的期望配置形成
    // 「写空↔写满」乒乓，远程协议永远起不来——本机核心全权交给 agent，
    // supervisor 退出。
    if local_managed_by_agent(&app) {
        info!("hub 本机同时是 agent 节点：sing-box 配置由 agent 对账管理，本机守护退出");
        return;
    }
    loop {
        tokio::time::sleep(Duration::from_secs(2)).await;
        let desired = app.db.get("proxy_desired_running").as_deref() == Some("on");
        {
            let mut st = app.proxy.lock().unwrap();
            if let Some(child) = st.child.as_mut() {
                match child.try_wait() {
                    Ok(Some(status)) => {
                        st.child = None;
                        st.restarts += 1;
                        st.last_error = format!("核心进程退出：{status}");
                        warn!("sing-box exited unexpectedly: {status}");
                        notify_crash(&app, format!("本机 sing-box 意外退出（{status}），正在自动恢复"));
                    }
                    Ok(None) => {}
                    Err(e) => warn!("could not poll sing-box: {e}"),
                }
            }
        }
        if desired {
            let running = { app.proxy.lock().unwrap().child.is_some() };
            if !running {
                if let Err(e) = apply(&app).await {
                    warn!("could not restart sing-box: {e:#}");
                    app.proxy.lock().unwrap().last_error = format!("核心拉起失败：{e:#}");
                    tokio::time::sleep(Duration::from_secs(5)).await;
                }
            }
        }
        // Realm 子进程守护（无 systemd 路径）：开关开着、有启用规则且进程不在就拉起。
        if !systemd() && realm_desired_running(&app) {
            let wanted = app
                .db
                .relay_rules()
                .map(|rs| rs.iter().any(|r| r.server_id == 0 && r.enabled))
                .unwrap_or(false);
            let slot_empty = realm_child_slot().lock().unwrap().as_ref().is_none();
            if wanted && slot_empty && realm_config_path(&app).exists() {
                let _ = spawn_realm_child(&app).await;
            }
        }
    }
}

/// 崩溃/失败通知：同一内容 10 分钟内只发一次，避免刷屏。
pub(crate) fn notify_throttled(app: &crate::App, key: &str, title: &str, message: String) {
    static LAST: std::sync::OnceLock<Mutex<HashMap<String, i64>>> = std::sync::OnceLock::new();
    let last = LAST.get_or_init(|| Mutex::new(HashMap::new()));
    let now = chrono::Utc::now().timestamp();
    {
        let mut m = last.lock().unwrap_or_else(|e| e.into_inner());
        if m.get(key).is_some_and(|t| now - *t < 600) {
            return;
        }
        m.insert(key.to_owned(), now);
    }
    crate::notify::send(
        app,
        crate::notify::Note {
            event: "proxy_alert",
            node: String::new(),
            title: title.to_owned(),
            message,
            time: now,
        },
    );
}

/// What the core status card renders. With systemd present the running state
/// comes from the unit (the hub restart does not touch it); otherwise from the
/// supervised child.
pub fn status(app: &App) -> serde_json::Value {
    let systemd_present = systemd();
    let unit_running = systemd_present
        && std::process::Command::new("systemctl")
            .args(["is-active", "--quiet", "monitor-singbox@main"])
            .output()
            .map(|o| o.status.success())
            .unwrap_or(false);
    let st = app.proxy.lock().unwrap();
    let running = if systemd_present { unit_running } else { st.child.is_some() };
    serde_json::json!({
        "installed": binary_path(app).is_file(),
        "version": if st.version.is_empty() { serde_json::Value::Null } else { serde_json::json!(st.version) },
        "desired_running": app.db.get("proxy_desired_running").as_deref() == Some("on"),
        "running": running,
        "started_at": st.started_at,
        "restarts": st.restarts,
        "applied_hash": st.applied_hash,
        "last_error": st.last_error,
        "config_path": config_path(app),
    })
}

/// 一台服务器的"空配置"：所有节点被停用/删除时推给 agent 摘除入站。
fn empty_server_config() -> (String, String) {
    let body = serde_json::json!({
        "log": { "level": "info", "timestamp": true },
        "inbounds": [],
        "outbounds": [ { "type": "direct", "tag": "direct" } ],
        "route": { "final": "direct" }
    })
    .to_string();
    (body.clone(), hex::encode(Sha256::digest(body.as_bytes())))
}

// ---- Realm 中转（M5）----

/// 从分享链接提取 (scheme, 目标host, 目标端口, 名称)。支持一切
/// `scheme://[凭据@]host:port[?查询][#名称]` 形态（vless/trojan/hysteria2/
/// anytls/tuic/ss/socks 等）；vmess 的 JSON-base64 形态没有 @host:port，
/// 明确报错让用户走手动模式。
pub fn parse_share_link(link: &str) -> Result<(String, String, i64, String)> {
    let trimmed = link.trim();
    let (scheme, rest) = trimmed.split_once("://").context("不是有效的分享链接（缺少 ://）")?;
    let scheme = scheme.to_ascii_lowercase();
    if !matches!(
        scheme.as_str(),
        "vless" | "trojan" | "hysteria2" | "hy2" | "anytls" | "tuic" | "ss" | "socks" | "socks5"
    ) {
        refuse!("暂不支持导入 {scheme}:// 链接，请用手动填写方式");
    }
    // 去掉 ?查询、路径与 #名称，剩下 [凭据@]host:端口
    let head = rest.split(['?', '#', '/']).next().unwrap_or(rest);
    let authority = match head.rsplit_once('@') {
        Some((_, hp)) => hp,
        None => head,
    };
    let (host, port) = authority.rsplit_once(':').context("链接里没有端口")?;
    let port: i64 = port.parse().with_context(|| format!("端口不是数字：{port}"))?;
    if !(1..=65535).contains(&port) {
        refuse!("链接端口无效：{port}");
    }
    let host = host.trim_start_matches('[').trim_end_matches(']').to_owned();
    let name = trimmed
        .split_once('#')
        .map(|(_, frag)| percent_decode(frag))
        .filter(|n| !n.is_empty())
        .unwrap_or_else(|| format!("{scheme}-{port}"));
    Ok((scheme, host, port, name))
}

/// 把分享链接的拨号地址改成中转机的（host:端口），协议参数与名称原样保留
/// ——Realm 是四层透传，客户端看到的协议参数与直连完全一致。
pub fn rewrite_share_link(link: &str, new_host: &str, new_port: i64) -> Result<String> {
    let trimmed = link.trim();
    let (scheme, rest) = trimmed.split_once("://").context("不是有效的分享链接")?;
    let split = rest.find(['?', '#', '/']).unwrap_or(rest.len());
    let (head, tail) = rest.split_at(split);
    let prefix = match head.rsplit_once('@') {
        Some((userinfo, _)) => format!("{userinfo}@"),
        None => String::new(),
    };
    Ok(format!("{scheme}://{prefix}{new_host}:{new_port}{tail}"))
}

/// %XX 百分号解码（名称字段用；无效序列原样保留）。
pub(crate) fn percent_decode(s: &str) -> String {
    let bytes = s.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'%' && i + 2 < bytes.len() + 1 && i + 2 < bytes.len() + 1 {
            if let Ok(v) = u8::from_str_radix(std::str::from_utf8(&bytes[i + 1..i + 3]).unwrap_or(""), 16) {
                out.push(v);
                i += 3;
                continue;
            }
        }
        out.push(bytes[i]);
        i += 1;
    }
    String::from_utf8_lossy(&out).into_owned()
}

/// 中转监听端口的自动分配：端口池内，排除该服务器上节点与中转已占的端口
/// （监听段全展开——此前只排除段首端口，段内其余端口会被分出去）。
pub fn allocate_relay_port(app: &App, server_id: i64) -> Result<i64> {
    let pool = app.db.get("proxy_port_pool").unwrap_or_else(|| "20000-50000".into());
    let Some((lo, hi)) = pool.split_once('-') else {
        refuse!("端口池格式应为 起始-结束，例如 20000-50000")
    };
    let (Ok(lo), Ok(hi)) = (lo.trim().parse::<i64>(), hi.trim().parse::<i64>()) else {
        refuse!("端口池起止不是数字：{pool}")
    };
    let _ = (lo, hi); // 池边界由 choose_free_port 统一解析与报错
    let mut used: HashSet<i64> = proxy_used_ports_scoped(app, server_id)?.into_iter().collect();
    used.extend(relay_ports_on(app, server_id)?);
    // 与协议侧同款：池内随机取空闲端口（此前是 find 取第一个空闲，顺序可预测）。
    choose_free_port(&pool, &used)
}

/// 端口在一台机器上是否已被占用（节点端口 / 中转监听 / 隧道出口半边），
/// `except_rule` 用于编辑时豁免规则自身。
pub fn relay_port_taken(app: &App, server_id: i64, port: i64, except_rule: i64) -> Result<bool> {
    if port <= 0 {
        return Ok(false);
    }
    let scopes = port_scopes(app, server_id);
    if proxy_used_ports_scoped(app, server_id)?.contains(&port) {
        return Ok(true);
    }
    for r in app.db.relay_rules()? {
        if r.id == except_rule {
            continue;
        }
        if scopes.contains(&r.server_id) {
            // 监听端口可能写成段（20000-20100），落在段内即算冲突。
            if let Some((lo, hi)) = r
                .listen_port
                .split_once('-')
                .and_then(|(a, b)| Some((a.trim().parse::<i64>().ok()?, b.trim().parse::<i64>().ok()?)))
            {
                if (lo..=hi).contains(&port) {
                    return Ok(true);
                }
            } else if r.listen_port.split('-').next().unwrap_or("").parse::<i64>() == Ok(port) {
                return Ok(true);
            }
        }
        if scopes.contains(&r.exit_server_id) && r.exit_listen_port.trim().parse::<i64>() == Ok(port) {
            return Ok(true);
        }
    }
    Ok(false)
}

// ---- Realm 中转（M5）续：导入式规则的分享链接（M6）----

/// 导入式中转规则的中转版分享链接：原始链接的地址改成中转机公网地址与
/// 中转监听端口。手动规则（origin_link 为空）返回 None。
pub fn relay_share_link(app: &App, rule: &crate::db::RelayRule) -> Option<String> {
    if rule.origin_link.is_empty() {
        return None;
    }
    let port: i64 = rule.listen_port.split('-').next()?.parse().ok()?;
    let host = node_dial_host(app, rule.server_id, None);
    rewrite_share_link(&rule.origin_link, &host, port).ok()
}

// ---- 流量统计与延迟测试（M4）----

/// 本机有没有 systemd（Realm/sing-box 的进程守护路径选择）。
fn systemd() -> bool {
    Path::new("/run/systemd/system").exists()
}

pub const REALM_REPO: &str = "zhboner/realm";

pub fn realm_binary_path(_app: &App) -> PathBuf {
    // 与 install.sh / agent 的固定路径一致（不随 --db 位置漂移）。
    PathBuf::from("/opt/monitor-proxy/bin/realm")
}

pub fn realm_config_path(_app: &App) -> PathBuf {
    PathBuf::from("/opt/monitor-proxy/instances/main/realm.toml")
}

fn realm_child_slot() -> &'static Mutex<Option<tokio::process::Child>> {
    static C: std::sync::OnceLock<Mutex<Option<tokio::process::Child>>> = std::sync::OnceLock::new();
    C.get_or_init(|| Mutex::new(None))
}

/// TOML 基本字符串转义（host/备注等用户输入直接进配置，不能让它破坏解析）。
pub(crate) fn toml_str(s: &str) -> String {
    let mut out = String::with_capacity(s.len() + 2);
    out.push('"');
    for c in s.chars() {
        match c {
            '\\' => out.push_str("\\\\"),
            '"' => out.push_str("\\\""),
            c => out.push(c),
        }
    }
    out.push('"');
    out
}

/// 加密传输层渲染在规则的那一侧——两侧的 kaminari 语法不同（实测）：
/// 入口（remote_transport）用 `sni` 且必须 insecure（出口侧 servername 模式
/// 生成自签证书）；出口（listen_transport）用 `servername`；ws/wss 两侧都
/// 必须带 host 和 path，缺一个 realm 启动即 panic。
#[derive(Clone, Copy, PartialEq)]
pub enum TransportSide {
    /// 隧道入口半边：出方向套加密层（remote_transport）。
    Entry,
    /// 隧道出口半边：入方向解密（listen_transport）。
    Exit,
}

/// kaminari transport 选项字符串。`default_host` 是 ws Host 头与 TLS 域名的
/// 兜底值（用户没填 sni 时用落地机拨号地址，两侧必须一致才能对上）。
pub fn transport_str(rule: &crate::db::RelayRule, side: TransportSide, default_host: &str) -> String {
    let host = if rule.tls_sni.trim().is_empty() { default_host } else { rule.tls_sni.trim() };
    let path = if rule.ws_path.trim().is_empty() { "/" } else { rule.ws_path.trim() };
    match (side, rule.transport.as_str()) {
        (TransportSide::Entry, "tls") => format!("tls;sni={host};insecure"),
        (TransportSide::Entry, "ws") => format!("ws;host={host};path={path}"),
        (TransportSide::Entry, "wss") => format!("wss;sni={host};insecure;host={host};path={path}"),
        (TransportSide::Exit, "tls") => format!("tls;servername={host}"),
        (TransportSide::Exit, "ws") => format!("ws;host={host};path={path}"),
        (TransportSide::Exit, "wss") => format!("wss;servername={host};host={host};path={path}"),
        _ => String::new(),
    }
}

/// 一条规则参与渲染的有效目标：启用的目标里剔除 down（仅多目标 + 已选
/// 负载策略时——健康摘除才有意义）；全 down 时保留全量（连总比不连好）。
pub fn effective_targets(targets: &[crate::db::RelayTarget], balance: &str) -> Vec<crate::db::RelayTarget> {
    let enabled: Vec<_> = targets.iter().filter(|t| t.enabled).cloned().collect();
    if enabled.len() > 1 && !balance.is_empty() {
        let alive: Vec<_> = enabled.iter().filter(|t| t.state != "down").cloned().collect();
        if !alive.is_empty() {
            return alive;
        }
    }
    enabled
}

/// 渲染一台机器 realm.toml 的全部端点行。三类：
/// - 入口半边：server_id 归属的启用规则（普通转发或多落地）；
/// - 隧道入口半边：隧道规则在本机的一侧（remote 指向落地机的加密监听）；
/// - 出口半边：落地在本机的隧道规则的落地侧（解密后转给真实目标）。
///
/// 同一规则的两半由 hub 同源渲染，加密参数天然配对。
/// 一台机器的中转渲染（隧道实测 bug #1）：hub+agent 同机时 server 0 与
/// 「主」节点行的规则同住一份 realm.toml，必须合并渲染、单点写入——此前
/// 每身份各渲染各的，后写的把先写的端点整块抹掉。纯远程机器 scopes 只有
/// 自己一个，行为与旧的按身份渲染完全一致。
pub fn render_relay_for_machine(app: &App, server_id: i64) -> Result<Option<(String, String)>> {
    let rules: Vec<_> = app.db.relay_rules()?;
    let all_targets = app.db.relay_targets()?;
    let scopes = port_scopes(app, server_id);
    let mut eps = String::new();

    let entry: Vec<_> = rules
        .iter()
        .filter(|r| {
            r.enabled
                && (scopes.contains(&r.server_id) || entry_backup_ids(r).iter().any(|b| scopes.contains(b)))
        })
        .collect();
    // 出口半边：出口在本机范围内、但不是「自己链到自己」的无意义自环。
    let exits: Vec<_> = rules
        .iter()
        .filter(|r| r.enabled && scopes.contains(&r.exit_server_id) && r.exit_server_id != r.server_id)
        .collect();
    if entry.is_empty() && exits.is_empty() {
        if std::env::var("MONITOR_RELAY_DEBUG").as_deref() == Ok("1") {
            eprintln!(
                "[relay-debug] render({server_id}) scopes={scopes:?} rules={} entry={} exits={}",
                rules.len(),
                entry.len(),
                exits.len()
            );
        }
        return Ok(None);
    }

    let targets_of = |rule_id: i64| -> Vec<crate::db::RelayTarget> {
        all_targets.iter().filter(|t| t.rule_id == rule_id).cloned().collect()
    };
    // ws Host 头与 TLS 域名的兜底值：落地机拨号地址。同一规则两侧用同一
    // 个值渲染，Host 头才对得上。
    let tunnel_host = |exit_server_id: i64| -> String {
        if exit_server_id > 0 {
            node_dial_host(app, exit_server_id, None)
        } else {
            String::new()
        }
    };

    for r in &entry {
        let targets = effective_targets(&targets_of(r.id), &r.balance);
        // 隧道入口：remote 是落地机的加密监听，不是业务目标本身。
        let remote: String = if r.exit_server_id > 0 {
            let port: i64 = r.exit_listen_port.trim().parse().unwrap_or(0);
            if port <= 0 {
                continue;
            }
            format!("{}:{port}", node_dial_host(app, r.exit_server_id, None))
        } else if let Some(t) = targets.first() {
            format!("{}:{}", t.host, t.port)
        } else {
            // 目标表为空（端口段等旧形态）：原样用 target 列，保持段对段兼容。
            if r.target.trim().is_empty() {
                continue;
            }
            r.target.trim().to_owned()
        };
        eps.push_str(&format!(
            "\n[[endpoints]]\nlisten = {}\nremote = {}\n",
            toml_str(&format!("{}:{}", listen_host_of(r), r.listen_port)),
            toml_str(&remote),
        ));
        // 多落地：其余目标 + 负载策略（realm 原生权重语法 "roundrobin: 1, 2, 1"）。
        if r.exit_server_id == 0 && targets.len() > 1 {
            let extra: Vec<String> =
                targets[1..].iter().map(|t| toml_str(&format!("{}:{}", t.host, t.port))).collect();
            eps.push_str(&format!("extra_remotes = [{}]\n", extra.join(", ")));
            if !r.balance.is_empty() {
                let weights: Vec<String> = targets.iter().map(|t| format!("{}", t.weight.max(1))).collect();
                eps.push_str(&format!(
                    "balance = {}\n",
                    toml_str(&format!("{}: {}", r.balance, weights.join(", ")))
                ));
            }
        }
        // 隧道入口半边：出方向套加密层（出口侧 servername 自签，入口必须 insecure）。
        if r.exit_server_id > 0 && !r.transport.is_empty() {
            eps.push_str(&format!(
                "remote_transport = {}\n",
                toml_str(&transport_str(r, TransportSide::Entry, &tunnel_host(r.exit_server_id)))
            ));
            if r.send_proxy {
                eps.push_str("send_proxy = true\n");
            }
        }
        eps.push_str(&network_overrides(r));
    }

    for r in &exits {
        let targets = effective_targets(&targets_of(r.id), &r.balance);
        let dbg = std::env::var("MONITOR_RELAY_DEBUG").as_deref() == Ok("1");
        let Some(first) = targets.first() else {
            if dbg {
                eprintln!("[relay-debug] exit rule {} (id {}) has no targets", r.name, r.id);
            }
            continue;
        };
        let port: i64 = match r.exit_listen_port.trim().parse() {
            Ok(p) => p,
            Err(_) => {
                if dbg {
                    eprintln!("[relay-debug] exit rule {} bad port {:?}", r.name, r.exit_listen_port);
                }
                continue;
            }
        };
        if dbg {
            eprintln!("[relay-debug] exit rule {} (id {}) renders {} -> {}", r.name, r.id, port, first.host);
        }
        eps.push_str(&format!(
            "\n[[endpoints]]\nlisten = {}\nremote = {}\n",
            toml_str(&format!("0.0.0.0:{port}")),
            toml_str(&format!("{}:{}", first.host, first.port))
        ));
        // 隧道出口半边：入方向解密（servername 模式自签证书，无需证书管理）；
        // 入口开了 proxy protocol 就要对端接收。
        if !r.transport.is_empty() {
            eps.push_str(&format!(
                "listen_transport = {}\n",
                toml_str(&transport_str(r, TransportSide::Exit, &tunnel_host(r.exit_server_id)))
            ));
            if r.send_proxy {
                eps.push_str("accept_proxy = true\n");
            }
        }
        eps.push_str(&network_overrides(r));
    }

    if eps.is_empty() {
        if std::env::var("MONITOR_RELAY_DEBUG").as_deref() == Ok("1") {
            eprintln!("[relay-debug] render({server_id}) eps empty after loops");
        }
        return Ok(None);
    }
    let body = format!("[network]\nno_tcp = false\nuse_udp = true\n{eps}");
    Ok(Some((body.clone(), hex::encode(Sha256::digest(body.as_bytes())))))
}

/// 规则的监听绑定地址（空 = 0.0.0.0）。
fn listen_host_of(r: &crate::db::RelayRule) -> String {
    let h = r.listen_host.trim();
    if h.is_empty() {
        "0.0.0.0".into()
    } else {
        h.to_owned()
    }
}

/// 端点级 network 覆盖（冒烟验证语法：`network = { no_tcp = true }`）：
/// 每规则协议选择与 MPTCP。both 且不开 MPTCP 时不输出（吃全局默认）。
fn network_overrides(r: &crate::db::RelayRule) -> String {
    let mut opts: Vec<String> = Vec::new();
    match r.protocol.as_str() {
        // 全局默认 no_tcp=false / use_udp=true；只覆盖需要关掉的那一路。
        "tcp" => opts.push("use_udp = false".into()),
        "udp" => opts.push("no_tcp = true".into()),
        _ => {}
    }
    if r.mptcp {
        opts.push("send_mptcp = true".into());
        opts.push("accept_mptcp = true".into());
    }
    if opts.is_empty() {
        String::new()
    } else {
        format!("network = {{ {} }}\n", opts.join(", "))
    }
}

/// Realm 的启停开关（本机卡片可控；规则删光时始终视为停）。
pub fn realm_desired_running(app: &App) -> bool {
    app.db.get("realm_desired_running").as_deref() != Some("off")
}

pub async fn detect_realm_version(bin: &Path) -> Result<String> {
    let out = tokio::process::Command::new(bin).arg("--version").output().await.context("无法运行 realm")?;
    let text = String::from_utf8_lossy(&out.stdout);
    let v = text.split_whitespace().nth(1).unwrap_or("").trim();
    if v.is_empty() {
        refuse!("无法解析 realm 版本号");
    }
    Ok(v.to_owned())
}

pub async fn install_realm_local(app: &Shared, version: Option<String>) -> Result<String> {
    let version = match version {
        Some(v) => {
            let v = v.trim().trim_start_matches('v').to_owned();
            if v.is_empty() || !v.chars().all(|c| c.is_ascii_digit() || c == '.') {
                refuse!("版本号格式不对：{v}");
            }
            v
        }
        None => {
            let url =
                crate::proxied(app, format!("https://api.github.com/repos/{REALM_REPO}/releases/latest"));
            let v: serde_json::Value = app
                .http
                .get(url)
                .header("User-Agent", "monitor-hub")
                .send()
                .await
                .context("无法访问 GitHub")?
                .error_for_status()
                .context("GitHub 返回错误")?
                .json()
                .await
                .context("解析 GitHub 响应失败")?;
            v["tag_name"].as_str().unwrap_or_default().trim_start_matches('v').to_owned()
        }
    };
    let target = match (std::env::consts::OS, std::env::consts::ARCH) {
        ("linux", "x86_64") => "x86_64-unknown-linux-musl",
        ("linux", "aarch64") => "aarch64-unknown-linux-musl",
        ("macos", "x86_64") => "x86_64-apple-darwin",
        ("macos", "aarch64") => "aarch64-apple-darwin",
        (os, arch) => refuse!("暂不支持 {os}/{arch} 自动安装 Realm"),
    };
    let name = format!("realm-{target}.tar.gz");
    let url =
        crate::proxied(app, format!("https://github.com/{REALM_REPO}/releases/download/v{version}/{name}"));
    let client =
        reqwest::Client::builder().timeout(Duration::from_secs(180)).build().context("构建下载客户端失败")?;
    let bytes = client
        .get(url)
        .header("User-Agent", "monitor-hub")
        .send()
        .await?
        .error_for_status()?
        .bytes()
        .await
        .context("读取下载内容失败")?;
    let bin = realm_binary_path(app);
    tokio::fs::create_dir_all(bin.parent().expect("bin has a parent")).await?;
    let staging = bin.with_extension("new");
    let mut archive = tar::Archive::new(flate2::read::GzDecoder::new(&bytes[..]));
    let mut found = false;
    for entry in archive.entries()? {
        let mut entry = entry?;
        let path = entry.path()?.to_path_buf();
        if entry.header().entry_type().is_file() && path.file_name().is_some_and(|n| n == "realm") {
            entry.unpack(&staging)?;
            found = true;
        }
    }
    if !found {
        let _ = tokio::fs::remove_file(&staging).await;
        refuse!("压缩包中没有找到 realm 可执行文件");
    }
    tokio::fs::rename(&staging, &bin).await?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&bin, std::fs::Permissions::from_mode(0o755))?;
    }
    let v = detect_realm_version(&bin).await?;
    info!("realm {v} installed");
    Ok(v)
}

fn realm_listen_ok(listen: &str) -> Result<()> {
    let body = listen.split('-').next().unwrap_or(listen);
    let port = body.rsplit(':').next().unwrap_or("");
    match port.parse::<u16>() {
        Ok(_) => Ok(()),
        Err(_) => refuse!("监听端口无效：{listen}"),
    }
}

pub fn validate_relay(rule: &crate::db::RelayRule) -> Result<()> {
    if rule.name.trim().is_empty() {
        refuse!("请填写规则名称");
    }
    if rule.listen_port.trim().is_empty() {
        refuse!("请填写监听端口");
    }
    realm_listen_ok(rule.listen_port.trim())?;
    let target = rule.target.trim();
    if !target.contains(':') {
        refuse!("目标格式应为 地址:端口，例如 1.2.3.4:443");
    }
    let port = target.rsplit(':').next().unwrap_or("");
    let port = port.split('-').next().unwrap_or(port);
    if port.parse::<u16>().is_err() {
        refuse!("目标端口无效：{target}");
    }
    if !matches!(rule.protocol.as_str(), "both" | "tcp" | "udp" | "") {
        refuse!("协议只能是 双栈 / 仅TCP / 仅UDP");
    }
    if !matches!(rule.balance.as_str(), "" | "roundrobin" | "iphash") {
        refuse!("负载策略只能是 轮询 / 源IP哈希");
    }
    if !matches!(rule.transport.as_str(), "" | "tls" | "ws" | "wss") {
        refuse!("加密传输只能是 不加密 / TLS / WS / WSS");
    }
    if let Some(p) = Some(rule.ws_path.trim()).filter(|p| !p.is_empty()) {
        if (rule.transport == "ws" || rule.transport == "wss") && !p.starts_with('/') {
            refuse!("WS 路径应以 / 开头，例如 /tun");
        }
    }
    if rule.exit_server_id > 0 {
        let p = rule.exit_listen_port.trim();
        if p.is_empty() {
            refuse!("隧道模式需要出口机监听端口");
        }
        if p.parse::<u16>().is_err() {
            refuse!("出口机监听端口无效：{p}");
        }
        // 隧道两端不能是同一台机器：自己加密转发给自己没有意义还成环。
        if rule.exit_server_id == rule.server_id {
            refuse!("隧道出口机不能与入口机相同");
        }
    } else if !rule.exit_listen_port.trim().is_empty() {
        refuse!("未选择隧道出口机时无需填写出口监听端口");
    }
    Ok(())
}

/// 落地目标列表校验（M24）：至少一个；host:port 合法；多目标必须选负载策略。
pub fn validate_relay_targets(targets: &[crate::db::RelayTarget], balance: &str) -> Result<()> {
    if targets.is_empty() {
        refuse!("至少填写一个出口目标");
    }
    for t in targets {
        if t.host.trim().is_empty() {
            refuse!("出口目标地址不能为空");
        }
        if !(1..=65535).contains(&t.port) {
            refuse!("出口目标端口无效：{}:{}", t.host, t.port);
        }
    }
    if targets.len() > 1 && balance.is_empty() {
        refuse!("多个出口目标需要选择负载策略（轮询或源IP哈希）");
    }
    Ok(())
}

/// 本机 Realm 的应用：有启用规则 → 写配置并重启；规则删光 → 停止并清理。
/// 无启用规则且开关开着时的待命占位（realm 拒绝空配置）：仅本机可达的
/// 高位端口 → discard，无人会连它。「启动」总是成功，建规则后立即热加载。
pub fn placeholder_relay_body() -> String {
    concat!(
        "# monitor 待命占位：无中转规则，仅本机可达，不会收到流量\n",
        "[network]\nno_tcp = false\nuse_udp = true\n\n",
        "[[endpoints]]\nlisten = \"127.0.0.1:19998\"\nremote = \"127.0.0.1:9\"\n",
    )
    .to_owned()
}

pub async fn apply_relay_local(app: &Shared) -> Result<()> {
    // 本机同时是 agent 节点时本机 realm 配置归 agent 单写（隧道实测 #1）：
    // server 0 与「主」节点行的端点已由机器范围渲染合并，从这里改道
    // relay.apply，hub 不再直接写 realm.toml——两边都写就是乒乓。
    if let Some(local) = local_node_server_id(app) {
        // 注意推给本机节点行而不是 0：agents 表以节点 id 为键，0 不在其中；
        // 渲染本身按机器范围（port_scopes）合并两个身份的端点。
        reconcile_relay_push(app, local)?;
        return Ok(());
    }
    let desired = realm_desired_running(app);
    let rendered = render_relay_for_machine(app, 0)?;
    // 无启用规则：realm 拒绝空配置，开关开着时用占位待命；开关关闭才真正停止。
    let (body, hash) = match rendered {
        Some(v) => v,
        None if desired => {
            let body = placeholder_relay_body();
            let hash = hex::encode(Sha256::digest(body.as_bytes()));
            (body, hash)
        }
        None => {
            // 开关关闭且无规则：停掉并清理。
            let old = { realm_child_slot().lock().unwrap_or_else(|e| e.into_inner()).take() };
            if let Some(mut child) = old {
                let _ = child.kill().await;
            }
            if systemd() {
                let _ = tokio::process::Command::new("systemctl")
                    .args(["stop", "monitor-realm@main"])
                    .output()
                    .await;
            }
            app.proxy.lock().unwrap_or_else(|e| e.into_inner()).realm_started_at = 0;
            return Ok(());
        }
    };
    let bin = realm_binary_path(app);
    if !bin.is_file() {
        refuse!("Realm 尚未安装，请先在核心状态卡中安装");
    }
    // 启停开关是关的：配置照写（切回启动时立即生效），但不运行。
    if !realm_desired_running(app) {
        let old = { realm_child_slot().lock().unwrap_or_else(|e| e.into_inner()).take() };
        if let Some(mut child) = old {
            let _ = child.kill().await;
        }
        if systemd() {
            let _ =
                tokio::process::Command::new("systemctl").args(["stop", "monitor-realm@main"]).output().await;
        }
        tokio::fs::write(realm_config_path(app), &body).await?;
        {
            let mut st = app.proxy.lock().unwrap_or_else(|e| e.into_inner());
            st.realm_running = false;
            st.realm_started_at = 0;
        }
        return Ok(());
    }
    // 短路守卫以 systemd 为准（隧道实测 #3）：agent 侧停过服务时 hub 内存
    // 的 realm_running 是陈旧的，只看内存会让「启动核心」变成空操作。
    let actually_running = {
        let st = app.proxy.lock().unwrap_or_else(|e| e.into_inner());
        if systemd() {
            std::process::Command::new("systemctl")
                .args(["is-active", "--quiet", "monitor-realm@main"])
                .output()
                .map(|o| o.status.success())
                .unwrap_or(false)
        } else {
            st.realm_running
        }
    };
    let hash_unchanged = { app.proxy.lock().unwrap_or_else(|e| e.into_inner()).relay_hash == hash };
    if hash_unchanged && actually_running {
        return Ok(());
    }
    tokio::fs::create_dir_all(realm_config_path(app).parent().expect("parent")).await?;
    tokio::fs::write(realm_config_path(app), &body).await?;
    if systemd() {
        write_realm_unit(app)?;
        let _ = tokio::process::Command::new("systemctl").args(["daemon-reload"]).output().await;
        let _ =
            tokio::process::Command::new("systemctl").args(["restart", "monitor-realm@main"]).output().await;
        let mut st = app.proxy.lock().unwrap_or_else(|e| e.into_inner());
        st.realm_running = true;
        st.realm_started_at = chrono::Utc::now().timestamp();
    } else {
        spawn_realm_child(app).await?;
    }
    {
        let mut st = app.proxy.lock().unwrap_or_else(|e| e.into_inner());
        st.relay_hash = hash;
        st.realm_running = true;
    }
    info!("realm relay applied");
    Ok(())
}

fn write_realm_unit(app: &App) -> Result<()> {
    let unit = format!(
        "[Unit]\nDescription=monitor realm relay %i\nAfter=network-online.target\nWants=network-online.target\n\n[Service]\nType=simple\nExecStart={} -c {}\nRestart=always\nRestartSec=3\n\n[Install]\nWantedBy=multi-user.target\n",
        realm_binary_path(app).display(),
        realm_config_path(app).display(),
    );
    let path = Path::new("/etc/systemd/system/monitor-realm@.service");
    if !path.exists() {
        std::fs::write(path, unit)?;
    }
    Ok(())
}

async fn spawn_realm_child(app: &Shared) -> Result<()> {
    stop_realm_child().await;
    let child = tokio::process::Command::new(realm_binary_path(app))
        .arg("-c")
        .arg(realm_config_path(app))
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .kill_on_drop(true)
        .spawn()
        .context("无法启动 realm")?;
    let mut st = app.proxy.lock().unwrap_or_else(|e| e.into_inner());
    st.realm_running = true;
    st.realm_started_at = chrono::Utc::now().timestamp();
    realm_child_slot().lock().unwrap().replace(child);
    Ok(())
}

async fn stop_realm_child() {
    let old = realm_child_slot().lock().unwrap_or_else(|e| e.into_inner()).take();
    if let Some(mut child) = old {
        let _ = child.kill().await;
    }
}

/// 本机有没有 Realm 进程在跑（无 systemd 时的兜底判断：slot 或孤儿 pgrep）。
pub async fn realm_locally_running(app: &App) -> bool {
    let ours = realm_child_slot()
        .lock()
        .unwrap_or_else(|e| e.into_inner())
        .as_mut()
        .map(|c| c.try_wait().map(|w| w.is_none()).unwrap_or(true))
        .unwrap_or(false);
    if ours {
        return true;
    }
    let cfg = realm_config_path(app).to_str().unwrap_or_default().to_owned();
    tokio::process::Command::new("pgrep")
        .args(["-f", &cfg])
        .output()
        .await
        .map(|o| o.status.success())
        .unwrap_or(false)
}

/// 中转规则变更后的应用：本机直接 apply；远程推送 relay.apply（离线时靠
/// agent 上线后的对账补发）。
pub async fn apply_relay_after_change(app: &Shared, server_id: i64) -> bool {
    let mut applied = true;
    if server_id == 0 {
        match apply_relay_local(app).await {
            Ok(()) => {}
            Err(e) => {
                warn!("relay apply failed: {e:#}");
                notify_throttled(app, "relay_apply_failed", "隧道配置应用失败", format!("{e:#}"));
                applied = false;
            }
        }
    }
    if server_id != 0 {
        if let Err(e) = ensure_remote_realm(app, server_id).await {
            warn!("auto realm install skipped: {e:#}");
        }
        if let Err(e) = reconcile_relay_push(app, server_id) {
            warn!("relay push failed: {e:#}");
            applied = false;
        }
    }
    applied
}

/// 远程中转：把 realm.toml 推给 agent（幂等，agent 端比对指纹短路）。
/// 某机器 relay 的期望 (配置体, 指纹)：有规则→渲染结果；无规则但「开关开着+
/// 本机作用域」→占位待命（隧道实测 #3）；其余→空串（期望 agent 停服务清理）。
/// 推送与心跳对账必须共用本函数取同一口径——曾因对账只看规则渲染（占位不在
/// 期望集内）而推送会推占位，agent 忠实落盘后指纹永不相等，每 60s 心跳重推
/// 并重启一次 realm。
fn relay_expected(app: &App, server_id: i64) -> Result<(String, String)> {
    if let Some(v) = render_relay_for_machine(app, server_id)? {
        return Ok(v);
    }
    if realm_desired_running(app) && port_scopes(app, server_id).contains(&0) {
        let body = placeholder_relay_body();
        let hash = hex::encode(Sha256::digest(body.as_bytes()));
        return Ok((body, hash));
    }
    Ok((String::new(), String::new()))
}

pub fn reconcile_relay_push(app: &App, server_id: i64) -> Result<bool> {
    // desired 与期望同源（=want 非空），不取全局开关：远端无腿机器的期望是
    // 「停服务清理」，若带 true，agent 会自造占位写盘、指纹与空期望永不相等，
    // 每 60s 心跳重推并重启 realm（占位语义三处分叉的环，2026-10-27 收口）。
    let (body, hash) = relay_expected(app, server_id)?;
    let desired = !hash.is_empty();
    let pushed = {
        let agents = app.agents.read().unwrap_or_else(|e| e.into_inner());
        let Some(agent) = agents.get(&server_id) else { return Ok(false) };
        let frame = serde_json::json!({
            "jsonrpc": "2.0", "id": crate::auth::random_token(),
            "method": "relay.apply",
            "params": { "config": body, "sha256": hash, "desired_running": desired },
        })
        .to_string();
        agent.tx.try_send(frame).is_ok()
    };
    if pushed {
        let _ = app.db.add_agent_job(server_id, "relay.apply", &hash);
    }
    Ok(pushed)
}

/// 本机 Realm 启动（期望状态落库 + 应用）。
pub async fn start_realm(app: &Shared) -> Result<()> {
    if !realm_binary_path(app).is_file() {
        refuse!("Realm 尚未安装，请先安装");
    }
    // 无启用规则也照常启动：apply 会以占位配置待命，建规则后立即热加载。
    app.db.set("realm_desired_running", "on")?;
    apply_relay_local(app).await
}

/// 本机 Realm 停止。
pub async fn stop_realm(app: &Shared) -> Result<()> {
    app.db.set("realm_desired_running", "off")?;
    let old = { realm_child_slot().lock().unwrap_or_else(|e| e.into_inner()).take() };
    if let Some(mut child) = old {
        let _ = child.kill().await;
    }
    if systemd() {
        let _ = tokio::process::Command::new("systemctl").args(["stop", "monitor-realm@main"]).output().await;
    }
    {
        let mut st = app.proxy.lock().unwrap_or_else(|e| e.into_inner());
        st.realm_running = false;
        st.realm_started_at = 0;
    }
    info!("realm stopped by operator");
    Ok(())
}

/// 远程服务器缺 Realm 时自动补装。
pub async fn ensure_remote_realm(app: &Shared, server_id: i64) -> Result<()> {
    let known = {
        let st = app.proxy_remote.lock().unwrap_or_else(|e| e.into_inner());
        st.get(&server_id).map(|s| s.realm_installed).unwrap_or(false)
    };
    if known {
        return Ok(());
    }
    let v = crate::agent_ws::call_agent(
        app,
        server_id,
        "proxy.core.status",
        serde_json::json!({}),
        Duration::from_secs(10),
    )
    .await?;
    let installed = v["realm_version"].as_str().map(|s| !s.is_empty()).unwrap_or(false);
    app.proxy_remote
        .lock()
        .unwrap_or_else(|e| e.into_inner())
        .entry(server_id)
        .or_default()
        .realm_installed = installed;
    if !installed {
        let job = app.db.add_agent_job(server_id, "relay.install", "")?;
        // 补装版本用全局默认（设置页「代理核心」的 realm 项）：空 = 跟最新。
        let want = app.db.get("realm_default_version").filter(|v| !v.trim().is_empty());
        match crate::agent_ws::call_agent(
            app,
            server_id,
            "relay.install",
            serde_json::json!({ "version": want }),
            Duration::from_secs(300),
        )
        .await
        {
            Ok(r) => {
                let _ = app.db.finish_agent_job(job, "success", r["version"].as_str().unwrap_or(""));
                app.proxy_remote
                    .lock()
                    .unwrap_or_else(|e| e.into_inner())
                    .entry(server_id)
                    .or_default()
                    .realm_installed = true;
            }
            Err(e) => {
                let _ = app.db.finish_agent_job(job, "failed", &format!("{e:#}"));
                return Err(e);
            }
        }
    }
    Ok(())
}

// ---- 流量统计与延迟测试（M4）----

/// 从本机 config.json 读出 api service 的 gRPC 端口——文件是事实源。
fn local_api_port(app: &App) -> Option<u16> {
    existing_services_port(app)
}

/// 本机节点的流量轮询：5s 一次（/connections 只含活跃连接，间隔短才能
/// 覆盖短促流量），直连本机 sing-box 的 clash_api；用户级增量由
/// `api_events_loop` 常驻订阅 sing-box api 连接事件流（M12），这里只做
/// 每 5s 一次的落账。
pub async fn stats_loop(app: crate::Shared) {
    let mut last_snapshot = 0i64;
    loop {
        tokio::time::sleep(Duration::from_secs(5)).await;
        let deltas = drain_api_deltas();
        if !deltas.is_empty() {
            book_sub_usage(&app, 0, &deltas);
        }
        // 长连接快照（M14）：每 60s 把仍活跃的连接明细 upsert 进缓冲，
        // 保证日志页能看到尚未关闭的连接。
        let now = chrono::Utc::now().timestamp();
        if now - last_snapshot >= 60 {
            last_snapshot = now;
            let mut pending = pending_conn_logs().lock().unwrap_or_else(|e| e.into_inner());
            for l in conn_lives().lock().unwrap_or_else(|e| e.into_inner()).values() {
                if now - l.last < 300 {
                    pending.push(l.clone());
                }
            }
        }
        let logs: Vec<ConnLife> =
            std::mem::take(&mut pending_conn_logs().lock().unwrap_or_else(|e| e.into_inner()));
        if !logs.is_empty() && app.db.get("conn_log_enabled").as_deref() != Some("off") {
            let rows: Vec<crate::db::ConnectionLogRow> = logs
                .into_iter()
                .map(|l| {
                    // host 归一：sniff 到的 domain 优先，否则 destination 去端口。
                    let (host, port) = split_destination(&l.destination);
                    let (host, port) =
                        if l.domain.is_empty() { (host, port) } else { (l.domain.clone(), port) };
                    crate::db::ConnectionLogRow {
                        conn_id: l.id,
                        user: l.user,
                        inbound: l.inbound,
                        network: l.network,
                        source: l.source,
                        host,
                        port,
                        first: l.first,
                        last: l.last,
                        up: l.up,
                        down: l.down,
                    }
                })
                .collect();
            if let Err(e) = app.db.upsert_connection_logs(0, &rows) {
                warn!("connection logs 落库失败: {e:#}");
            }
        }
        // 节点级采样（M15 起走事件流 inbound 维度；clash 轮询差分对亚秒级
        // 短连接有系统性盲区，已弃用）。
        let tag_deltas = drain_api_tag_deltas();
        if !tag_deltas.is_empty() {
            let ts = chrono::Utc::now().timestamp();
            let rows: Vec<(i64, &str, i64, i64, i64)> =
                tag_deltas.iter().map(|(tag, (rx, tx))| (0, tag.as_str(), ts, *rx, *tx)).collect();
            if let Err(e) = app.db.add_traffic_samples(&rows) {
                warn!("traffic booking failed: {e:#}");
            }
        }
    }
}

/// agent 推来的远程节点流量（设计文档 10.2 的统计通道）。users 是 agent 从
/// agent 推来的连接日志行（M14）：数组逐行 host/port 归一后 upsert。
/// 记录开关（conn_log_enabled）关闭时丢弃——agent 无需感知设置。
pub fn book_remote_connection_logs(app: &App, server_id: i64, params: &serde_json::Value) {
    let Some(rows) = params.as_array() else { return };
    let parsed: Vec<crate::db::ConnectionLogRow> = rows
        .iter()
        .filter_map(|r| {
            let destination = r.get("destination")?.as_str()?.to_owned();
            let domain = r.get("domain").and_then(|d| d.as_str()).unwrap_or_default().to_owned();
            let (d_host, d_port) = split_destination(&destination);
            let (host, port) = if domain.is_empty() { (d_host, d_port) } else { (domain.clone(), d_port) };
            Some(crate::db::ConnectionLogRow {
                conn_id: r.get("id")?.as_str()?.to_owned(),
                user: r.get("user").and_then(|u| u.as_str()).unwrap_or_default().to_owned(),
                inbound: r.get("inbound").and_then(|i| i.as_str()).unwrap_or_default().to_owned(),
                network: r.get("network").and_then(|n| n.as_str()).unwrap_or_default().to_owned(),
                source: r.get("source").and_then(|s| s.as_str()).unwrap_or_default().to_owned(),
                host,
                port,
                first: r.get("first")?.as_i64()?,
                last: r.get("last")?.as_i64()?,
                up: r.get("up")?.as_i64()?,
                down: r.get("down")?.as_i64()?,
            })
        })
        .collect();
    if parsed.is_empty() || app.db.get("conn_log_enabled").as_deref() == Some("off") {
        return;
    }
    if let Err(e) = app.db.upsert_connection_logs(server_id, &parsed) {
        warn!("connection logs 落库失败: {e:#}");
    }
}

/// api_events_loop 聚合的用户级增量（远程为 agent 上报），同一帧到达。
pub fn book_remote_stats(app: &App, server_id: i64, params: &serde_json::Value) {
    let ts = chrono::Utc::now().timestamp();
    if let Some(tags) = params.get("tags").and_then(|t| t.as_object()) {
        let rows: Vec<(i64, &str, i64, i64, i64)> = tags
            .iter()
            .filter_map(|(tag, v)| {
                let rx = v.get(0).and_then(|x| x.as_i64())?;
                let tx = v.get(1).and_then(|x| x.as_i64())?;
                Some((server_id, tag.as_str(), ts, rx, tx))
            })
            .collect();
        if !rows.is_empty() {
            if let Err(e) = app.db.add_traffic_samples(&rows) {
                warn!("remote traffic booking failed: {e:#}");
            }
        }
    }
    if let Some(users) = params.get("users").and_then(|t| t.as_object()) {
        let per: HashMap<String, (i64, i64)> = users
            .iter()
            .filter_map(|(name, v)| {
                let up = v.get(0).and_then(|x| x.as_i64())?;
                let down = v.get(1).and_then(|x| x.as_i64())?;
                Some((name.clone(), (up, down)))
            })
            .collect();
        book_sub_usage(app, server_id, &per);
    }
}

// ---- 用户级流量（M12）：sing-box api 连接事件流 ----

/// destination（"host:port" / "[v6]:port"）拆成 host 与 port。
fn split_destination(dest: &str) -> (String, i64) {
    if let Some(rest) = dest.strip_prefix('[') {
        return match rest.split_once("]:") {
            Some((h, p)) => (h.to_owned(), p.parse::<i64>().unwrap_or(0)),
            _ => (rest.trim_end_matches(']').to_owned(), 0),
        };
    }
    match dest.rsplit_once(':') {
        Some((h, p)) => (h.to_owned(), p.parse::<i64>().unwrap_or(0)),
        None => (dest.to_owned(), 0),
    }
}

/// 一条连接的生命周期明细（M14 连接日志）：New 建、Update 累加、Closed
/// 定稿推入待落库缓冲。
#[derive(Debug, Clone)]
pub struct ConnLife {
    pub id: String,
    pub user: String,
    pub inbound: String,
    pub network: String,
    pub source: String,
    pub destination: String,
    pub domain: String,
    pub first: i64,
    pub last: i64,
    pub up: i64,
    pub down: i64,
}

fn conn_lives() -> &'static Mutex<HashMap<String, ConnLife>> {
    static C: std::sync::OnceLock<Mutex<HashMap<String, ConnLife>>> = std::sync::OnceLock::new();
    C.get_or_init(|| Mutex::new(HashMap::new()))
}

/// 待落库的连接日志行（定稿与活跃快照混合，落库方按 id upsert）。
fn pending_conn_logs() -> &'static Mutex<Vec<ConnLife>> {
    static P: std::sync::OnceLock<Mutex<Vec<ConnLife>>> = std::sync::OnceLock::new();
    P.get_or_init(|| Mutex::new(Vec::new()))
}

/// 连接 id → 凭据用户名（M12）：NEW 事件建立映射，UPDATE/CLOSED 按 id 查。
fn users_of_conn() -> &'static Mutex<HashMap<String, String>> {
    static U: std::sync::OnceLock<Mutex<HashMap<String, String>>> = std::sync::OnceLock::new();
    U.get_or_init(|| Mutex::new(HashMap::new()))
}

/// 用户级流量增量（按凭据用户名聚合）：订阅任务写入，stats_loop 每 5s
/// drain 一次落账。
fn drain_api_deltas() -> HashMap<String, (i64, i64)> {
    std::mem::take(&mut api_deltas().lock().unwrap_or_else(|e| e.into_inner()))
}

/// 节点级流量增量（按入站 tag 聚合，M15 起替代 clash_api 差分）：事件流
/// UPDATE/CLOSED 把增量按所属连接的 inbound 累在这里，stats_loop 每 5s
/// drain 落采样。clash 轮询做差对亚秒级短连接存在系统性盲区（连接在下一
/// 次轮询前就消失了），事件流每笔增量必达，无此问题。
fn api_tag_deltas() -> &'static Mutex<HashMap<String, (i64, i64)>> {
    static D: std::sync::OnceLock<Mutex<HashMap<String, (i64, i64)>>> = std::sync::OnceLock::new();
    D.get_or_init(|| Mutex::new(HashMap::new()))
}

fn drain_api_tag_deltas() -> HashMap<String, (i64, i64)> {
    std::mem::take(&mut api_tag_deltas().lock().unwrap_or_else(|e| e.into_inner()))
}

/// 本机核心（重）启/停止前清空连接态：连接 id 属于 sing-box 进程生命周期，
/// 重启后旧 id 不会再有任何事件，不清理则 conn_lives 泄漏且永不定稿。
/// 已知总量先移交 pending 落库；api_deltas 按用户名记账、与连接 id 无关，
/// 保留给 stats_loop 正常 drain。订阅意外断开（核心仍在运行）时**不清**：
/// 存量连接的 id 依旧有效，清了反而停掉它们的计量。
fn reset_conn_state() {
    let mut lives = conn_lives().lock().unwrap_or_else(|e| e.into_inner());
    let stale: Vec<ConnLife> = lives.drain().map(|(_, l)| l).collect();
    drop(lives);
    pending_conn_logs().lock().unwrap_or_else(|e| e.into_inner()).extend(stale);
    users_of_conn().lock().unwrap_or_else(|e| e.into_inner()).clear();
}

/// 把一批用户增量记到客户头上（user 字段即凭据用户名 → proxy_user →
/// sub_user）；刚越过配额的客户即时通知并推向摘除后的期望配置。没有客户
/// 的用户名（未认领的独立凭据）没有配额可言，静默跳过。
fn book_sub_usage(app: &App, server_id: i64, per_user: &HashMap<String, (i64, i64)>) {
    if per_user.is_empty() {
        return;
    }
    let names: Vec<String> = per_user.keys().cloned().collect();
    let Ok(mapping) = app.db.proxy_sub_of_names(server_id, &names) else { return };
    let deltas: Vec<(i64, i64, i64)> = mapping
        .iter()
        .filter_map(|(name, sub_id)| {
            sub_id.map(|id| {
                let (up, down) = per_user.get(name).copied().unwrap_or((0, 0));
                (id, up, down)
            })
        })
        .collect();
    if deltas.is_empty() {
        return;
    }
    match app.db.bump_sub_usage(&deltas) {
        Ok(crossed) if !crossed.is_empty() => {
            crate::notify::sub_over_quota(app, &crossed);
            for id in crossed {
                if let Err(e) = reconcile_sub(app, id) {
                    warn!("quota reconcile failed: {e:#}");
                }
            }
        }
        Ok(_) => {}
        Err(e) => warn!("sub usage booking failed: {e:#}"),
    }
    // 凭据级配额（方向 40）：同一批增量同步记到 proxy_user 行上，越过凭据
    // 自身配额的即时推向该凭据所在服务器的摘除后配置。
    let pu_names: Vec<String> = per_user.keys().cloned().collect();
    if let Ok(pu_map) = app.db.proxy_user_ids_of_names(server_id, &pu_names) {
        let pu_deltas: Vec<(i64, i64, i64)> = pu_map
            .iter()
            .map(|(name, pu_id)| {
                let (up, down) = per_user.get(name).copied().unwrap_or((0, 0));
                (*pu_id, up, down)
            })
            .collect();
        match app.db.bump_proxy_user_usage(&pu_deltas) {
            Ok(crossed) if !crossed.is_empty() => {
                for server in
                    crossed.iter().filter_map(|pu_id| app.db.proxy_server_of_user(*pu_id).ok().flatten())
                {
                    if let Err(e) = reconcile_push(app, server) {
                        warn!("credential quota reconcile failed: {e:#}");
                    }
                }
            }
            Ok(_) => {}
            Err(e) => warn!("proxy user usage booking failed: {e:#}"),
        }
    }
}
//
// sing-box 1.14+ 官方自带的 api service（`"type": "api"` gRPC）把每条
// 连接的增量（含连接关闭事件）以流式推送，`Connection.user` 就是入站认证
// 的凭据用户名——短连接零盲区，且官方 release 无需任何编译 tag。

/// 用户级流量增量（按凭据用户名聚合）：订阅任务写入，stats_loop 每 5s
/// drain 一次落账。
fn api_deltas() -> &'static Mutex<HashMap<String, (i64, i64)>> {
    static D: std::sync::OnceLock<Mutex<HashMap<String, (i64, i64)>>> = std::sync::OnceLock::new();
    D.get_or_init(|| Mutex::new(HashMap::new()))
}

/// 常驻任务：订阅本机 sing-box api 的连接事件流，把 uplink/downlink 增量
/// 按用户累加。断开（核心重启/升级）后 3s 重连；核心未运行或未配置 api
/// service 时静默等待。
pub async fn api_events_loop(app: crate::Shared) {
    loop {
        let Some(port) = local_api_port(&app) else {
            tokio::time::sleep(Duration::from_secs(5)).await;
            continue;
        };
        match subscribe_connections(port).await {
            Ok(()) => {}
            Err(e) => debug!("sing-box api 订阅断开: {e:#}"),
        }
        tokio::time::sleep(Duration::from_secs(3)).await;
    }
}

/// 订阅连接事件流直到断开。每个事件帧按 user 把 delta 累加进聚合表；
/// NEW 事件（delta 为零）天然被过滤。
async fn subscribe_connections(port: u16) -> Result<()> {
    use h2::client;

    let tcp = tokio::net::TcpStream::connect(("127.0.0.1", port)).await?;
    let (mut send_request, connection) = client::handshake(tcp).await?;
    tokio::spawn(async move {
        let _ = connection.await;
    });
    let request = http::Request::builder()
        .method(http::Method::POST)
        .uri("http://127.0.0.1/daemon.StartedService/SubscribeConnections")
        .header("content-type", "application/grpc")
        .header("te", "trailers")
        .body(())
        .context("gRPC 请求头")?;
    let (response, mut send_body) = send_request.send_request(request, false).context("gRPC 连接")?;
    // SubscribeConnectionsRequest{ interval: 5000 }：field1 int64，varint
    // 0x88 0x27；gRPC 帧 = 压缩标志 + 4 字节大端长度 + 消息体。
    let mut msg = vec![0x08];
    push_varint(&mut msg, 5000);
    let mut frame = Vec::with_capacity(5 + msg.len());
    frame.push(0);
    frame.extend_from_slice(&(msg.len() as u32).to_be_bytes());
    frame.extend_from_slice(&msg);
    send_body.send_data(frame.into(), true).context("gRPC 请求体")?;
    let response = response.await.context("gRPC 响应")?;
    if !response.status().is_success() {
        refuse!("sing-box api 返回 {}", response.status());
    }
    let mut body = response.into_body();
    let mut buf: Vec<u8> = Vec::new();
    while let Some(chunk) = body.data().await {
        let chunk = chunk.context("gRPC 数据流")?;
        buf.extend_from_slice(chunk.as_ref());
        let _ = body.flow_control().release_capacity(chunk.len());
        // 帧边界解析：chunk 可能携带半帧或多帧。
        while buf.len() >= 5 {
            let len = u32::from_be_bytes([buf[1], buf[2], buf[3], buf[4]]) as usize;
            if buf.len() < 5 + len {
                break;
            }
            let now = chrono::Utc::now().timestamp();
            match decode_connection_event(&buf[5..5 + len]) {
                Some(ConnEvent::New { id, user, inbound, network, source, destination, domain }) => {
                    users_of_conn()
                        .lock()
                        .unwrap_or_else(|e| e.into_inner())
                        .insert(id.clone(), user.clone());
                    conn_lives().lock().unwrap_or_else(|e| e.into_inner()).insert(
                        id.clone(),
                        ConnLife {
                            id,
                            user,
                            inbound,
                            network,
                            source,
                            destination,
                            domain,
                            first: now,
                            last: now,
                            up: 0,
                            down: 0,
                        },
                    );
                }
                Some(ConnEvent::Update { id, up, down }) => {
                    // 用户级配额计量（M12 管道，保持不变）。
                    let user = users_of_conn().lock().unwrap_or_else(|e| e.into_inner()).get(&id).cloned();
                    if let Some(user) = user {
                        let mut d = api_deltas().lock().unwrap_or_else(|e| e.into_inner());
                        let e = d.entry(user).or_insert((0, 0));
                        e.0 += up;
                        e.1 += down;
                    }
                    // 连接日志（M14）明细累加；节点级（M15）按 inbound 同步入账。
                    if let Some(l) = conn_lives().lock().unwrap_or_else(|e| e.into_inner()).get_mut(&id) {
                        l.up += up;
                        l.down += down;
                        l.last = now;
                        let mut td = api_tag_deltas().lock().unwrap_or_else(|e| e.into_inner());
                        // 表按 (rx, tx) 存：事件 up=客户端上传→tx，down=下载→rx。
                        let e = td.entry(l.inbound.clone()).or_insert((0, 0));
                        e.0 += down;
                        e.1 += up;
                    }
                }
                Some(ConnEvent::Closed { id, up, down }) => {
                    // 定稿：CLOSED 若带增量（官方核心当前不带）先补最后一拍，
                    // 再整行推入待落库缓冲；配额映射同步移除。
                    if up > 0 || down > 0 {
                        let user =
                            users_of_conn().lock().unwrap_or_else(|e| e.into_inner()).get(&id).cloned();
                        if let Some(user) = user {
                            let mut d = api_deltas().lock().unwrap_or_else(|e| e.into_inner());
                            let e = d.entry(user).or_insert((0, 0));
                            e.0 += up;
                            e.1 += down;
                        }
                        if let Some(l) = conn_lives().lock().unwrap_or_else(|e| e.into_inner()).get_mut(&id) {
                            l.up += up;
                            l.down += down;
                            l.last = now;
                            let mut td = api_tag_deltas().lock().unwrap_or_else(|e| e.into_inner());
                            // 表按 (rx, tx) 存：事件 up=客户端上传→tx，down=下载→rx。
                            let e = td.entry(l.inbound.clone()).or_insert((0, 0));
                            e.0 += down;
                            e.1 += up;
                        }
                    }
                    users_of_conn().lock().unwrap_or_else(|e| e.into_inner()).remove(&id);
                    if let Some(l) = conn_lives().lock().unwrap_or_else(|e| e.into_inner()).remove(&id) {
                        pending_conn_logs().lock().unwrap_or_else(|e| e.into_inner()).push(l);
                    }
                }
                None => {}
            }
            buf.drain(..5 + len);
        }
    }
    Ok(())
}

/// 一条连接事件（M12）：NEW 带完整连接（含用户），UPDATE 只带 id 与增量，
/// CLOSED 带 id——用户需要调用方按 id 从 NEW 里记的映射查回。
#[derive(Debug, PartialEq)]
enum ConnEvent {
    New {
        id: String,
        user: String,
        inbound: String,
        network: String,
        source: String,
        destination: String,
        domain: String,
    },
    Update {
        id: String,
        up: i64,
        down: i64,
    },
    /// 官方核心（1.14 实测）CLOSED 不带增量，up/down 恒零；字段保留以兼容
    /// 带增量的版本——带了就由聚合分支补最后一拍。
    Closed {
        id: String,
        up: i64,
        down: i64,
    },
}

/// 解码一条连接事件帧（实测线上格式：gRPC 帧之内最外层是一个 wire2 信封，
/// 里面才是 type=1 varint、id=2 bytes、connection=3 bytes、uplinkDelta=4、
/// downlinkDelta=5、closedAt=6；connection 里 user=10 bytes）。
fn decode_connection_event(buf: &[u8]) -> Option<ConnEvent> {
    let mut event: Option<Vec<u8>> = None;
    let mut i = 0;
    while i < buf.len() {
        let (key, n) = read_varint(buf, i).ok()?;
        i = n;
        match (key >> 3, key & 7) {
            (1, 2) => {
                let (len, n) = read_varint(buf, i).ok()?;
                i = n;
                let end = (i + len as usize).min(buf.len());
                event = Some(buf[i..end].to_vec());
                i = end;
            }
            _ => {
                let (_, n) = skip_field(buf, i, key & 7).ok()?;
                i = n;
            }
        }
    }
    let buf: &[u8] = &event?;
    let mut kind = 0u64;
    let mut id = String::new();
    let mut connection: Option<Vec<u8>> = None;
    let mut up = 0i64;
    let mut down = 0i64;
    let mut i = 0;
    while i < buf.len() {
        let (key, n) = read_varint(buf, i).ok()?;
        i = n;
        let (num, wire) = (key >> 3, key & 7);
        match (num, wire) {
            (1, 0) => {
                let (v, n) = read_varint(buf, i).ok()?;
                i = n;
                kind = v;
            }
            (2, 2) => {
                let (len, n) = read_varint(buf, i).ok()?;
                i = n;
                let end = (i + len as usize).min(buf.len());
                id = String::from_utf8_lossy(&buf[i..end]).into_owned();
                i = end;
            }
            (3, 2) => {
                let (len, n) = read_varint(buf, i).ok()?;
                i = n;
                let end = (i + len as usize).min(buf.len());
                connection = Some(buf[i..end].to_vec());
                i = end;
            }
            (4, 0) => {
                let (v, n) = read_varint(buf, i).ok()?;
                i = n;
                up = v as i64;
            }
            (5, 0) => {
                let (v, n) = read_varint(buf, i).ok()?;
                i = n;
                down = v as i64;
            }
            _ => {
                let (_, n) = skip_field(buf, i, wire).ok()?;
                i = n;
            }
        }
    }
    // UPDATE 只带 id 与增量（无 connection）；NEW 才携带完整连接。
    if kind == 2 {
        return Some(ConnEvent::Closed { id, up, down });
    }
    if kind == 1 {
        return Some(ConnEvent::Update { id, up, down });
    }
    let connection = connection?;
    let conn: &[u8] = &connection;
    let mut user = String::new();
    let mut inbound = String::new();
    let mut network = String::new();
    let mut source = String::new();
    let mut destination = String::new();
    let mut domain = String::new();
    let mut i = 0;
    while i < conn.len() {
        let (key, n) = read_varint(conn, i).ok()?;
        i = n;
        let (num, wire) = (key >> 3, key & 7);
        if wire == 2 {
            let (len, n) = read_varint(conn, i).ok()?;
            i = n;
            let end = (i + len as usize).min(conn.len());
            let val = String::from_utf8_lossy(&conn[i..end]).into_owned();
            i = end;
            match num {
                2 => inbound = val,
                6 => source = val,
                7 => destination = val,
                8 => domain = val,
                10 => user = val,
                _ => {}
            }
        } else {
            match (num, wire) {
                (5, 0) => {
                    let (v, n) = read_varint(conn, i).ok()?;
                    i = n;
                    // network 枚举：sing-box adapter.Network，1=tcp 2=udp。
                    network = if v == 2 { "udp".into() } else { "tcp".into() };
                }
                _ => {
                    let (_, n) = skip_field(conn, i, wire).ok()?;
                    i = n;
                }
            }
        }
    }
    Some(ConnEvent::New { id, user, inbound, network, source, destination, domain })
}

fn read_varint(buf: &[u8], mut i: usize) -> Result<(u64, usize)> {
    let mut v = 0u64;
    let mut shift = 0;
    loop {
        let b = *buf.get(i).context("protobuf 截断")?;
        i += 1;
        v |= u64::from(b & 0x7F) << shift;
        if b & 0x80 == 0 {
            return Ok((v, i));
        }
        shift += 7;
        if shift > 63 {
            refuse!("protobuf varint 过长");
        }
    }
}

/// 跳过一个未知 protobuf 字段，返回 (wire type 0 时的值, 新偏移)。
fn skip_field(buf: &[u8], i: usize, wire: u64) -> Result<(Option<u64>, usize)> {
    match wire {
        0 => {
            let (v, n) = read_varint(buf, i)?;
            Ok((Some(v), n))
        }
        1 => Ok((None, i + 8)),
        2 => {
            // 长度前缀在 i 处，值从 i+1 起：新偏移 = (len 前缀之后) + 值长度。
            let (len, n) = read_varint(buf, i)?;
            Ok((None, n + len as usize))
        }
        5 => Ok((None, i + 4)),
        w => refuse!("未知 wire type {w}"),
    }
}

fn push_varint(out: &mut Vec<u8>, mut v: u64) {
    loop {
        let b = (v & 0x7F) as u8;
        v >>= 7;
        if v == 0 {
            out.push(b);
            return;
        }
        out.push(b | 0x80);
    }
}

// ---- 多机（M3）：按服务器渲染、对账与远程操作 ----

/// 一台远程服务器最近的对账状态。内存即可：agent 每 60s 重报，hub 重启后
/// 一分钟内补齐。
#[derive(Default, Clone)]
pub struct RemoteState {
    pub last_hash: String,
    pub last_seen: i64,
    pub last_pushed_hash: String,
    pub last_pushed_at: i64,
    /// agent 是否已装核心（install.sh 默认装；此缓存可被状态查询纠正）。
    pub installed: bool,
    /// agent 是否已装 Realm（M5）。
    pub realm_installed: bool,
    /// 最近一次见到的 sing-box 版本（版本过旧黄条，二期）：hub 只在已有的
    /// 触点（状态查询/安装/补装）缓存，没触点过的机器版本未知=不出黄条。
    pub version: String,
}

/// 连接计量走的 api service 是 sing-box 1.14+ 特性，面板按 1.14.2 实测：
/// 主.次低于 1.14 即过旧。解析失败（自编译 tag 等）不算过旧——黄条不误报。
pub fn version_stale(version: &str) -> bool {
    let v = version.trim().trim_start_matches('v');
    let mut it = v.split('.');
    let (Some(major), Some(minor)) = (it.next(), it.next()) else { return false };
    match (major.parse::<u64>(), minor.parse::<u64>()) {
        (Ok(major), Ok(minor)) => major < 1 || (major == 1 && minor < 14),
        _ => false,
    }
}

// ---- 客户生命周期（M7）----

/// Hub 本地日期：到期判定与配额月界的统一时钟，订阅端点、渲染过滤与面板
/// 状态徽标共用。
pub fn today() -> chrono::NaiveDate {
    chrono::Local::now().date_naive()
}

/// 一个客户的动态存续状态。判定不落库：停用/到期读行内字段，配额比对累积
/// 用量，任何一项失格即从订阅与节点配置两侧同时摘除。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SubStatus {
    Active,
    Disabled,
    Expired,
    OverQuota,
}

impl SubStatus {
    /// 面板徽标与订阅端点共用的短句。
    pub fn label(self) -> &'static str {
        match self {
            SubStatus::Active => "正常",
            SubStatus::Disabled => "已停用",
            SubStatus::Expired => "已到期",
            SubStatus::OverQuota => "流量超额",
        }
    }

    pub fn active(self) -> bool {
        self == SubStatus::Active
    }
}

/// 客户当前状态。`today` 用 hub 本地日期，与订阅端点的到期判定同源。
pub fn sub_status(sub: &SubUser, today: chrono::NaiveDate) -> SubStatus {
    if !sub.enabled {
        return SubStatus::Disabled;
    }
    if let Some(exp) = &sub.expires_at {
        if let Ok(d) = chrono::NaiveDate::parse_from_str(exp, "%Y-%m-%d") {
            if d < today {
                return SubStatus::Expired;
            }
        }
    }
    if sub.quota_bytes > 0 && sub.quota_used_up + sub.quota_used_down >= sub.quota_bytes {
        return SubStatus::OverQuota;
    }
    SubStatus::Active
}

/// 一台服务器上真正进入配置的节点与凭据：节点按 enabled，用户按所属客户的
/// 生命周期状态。订阅层早已拒绝失格客户，这里把节点侧的存量凭据一并摘除——
/// 渲染指纹随之变化，既有对账管道把新配置推下去后客户端断开。未认领
/// （sub_user_id 为空）的独立凭据不归生命周期管，原样保留；客户被摘光后
/// 整个入站随之撤下（渲染器不收空凭据节点，协议上也不再留一个空门）。
/// 凭据级失格（方向 40）：设了 到期/配额 且 已过期/已超额 → 该凭据不再可用
/// （从节点配置摘除、订阅渲染跳过）。未启用的凭据跟随客户级判定。
pub fn credential_live(u: &ProxyUser, today: chrono::NaiveDate) -> bool {
    if let Some(exp) = &u.expires_at {
        if let Ok(d) = chrono::NaiveDate::parse_from_str(exp, "%Y-%m-%d") {
            if today > d {
                return false;
            }
        }
    }
    if u.quota_bytes > 0 && u.quota_used_up + u.quota_used_down >= u.quota_bytes {
        return false;
    }
    true
}

pub fn gated_bundles(app: &App, server_id: i64) -> Result<Vec<NodeBundle>> {
    let today = today();
    let subs: HashMap<i64, SubUser> = app.db.sub_users()?.into_iter().map(|s| (s.id, s)).collect();
    let live = |sub_user_id: Option<i64>| match sub_user_id {
        None => true,
        Some(id) => subs.get(&id).is_some_and(|s| sub_status(s, today).active()),
    };
    Ok(app
        .db
        .proxy_node_bundles()?
        .into_iter()
        .filter(|b| b.node.enabled && node_server_ids(&b.node).contains(&server_id))
        .map(|mut b| {
            b.users.retain(|u| live(u.sub_user_id) && credential_live(u, today));
            b
        })
        .filter(|b| !b.users.is_empty())
        .collect())
}

/// 客户的凭据被摘除后把涉及其凭据的远程服务器推向期望配置。幂等：指纹
/// 相同不推，同一期望五分钟内不重推。本机核心不在其中——systemd 机器的
/// supervisor 两秒一轮自动重渲染，其余路径由调用方的 apply 覆盖。
pub fn reconcile_sub(app: &App, sub_id: i64) -> Result<()> {
    for server_id in app.db.proxy_servers_of_sub(sub_id)? {
        if server_id != 0 {
            reconcile_push(app, server_id)?;
        }
    }
    Ok(())
}

/// housekeeping 每小时跑一遍：到期跨日的客户发一次通知（notify 里按坐标
/// 去重）并把它的服务器推向摘除后的期望配置。停用与超额各有即时触发点
/// （面板保存 / 记账边沿），这里只兜到期这种没有单一事件的失格；对账本身
/// 幂等，重复跑只是去重窗口内的空推。
pub fn sub_expiry_sweep(app: &App) -> Result<()> {
    let today = today();
    for sub in app.db.sub_users()? {
        if sub_status(&sub, today) != SubStatus::Expired {
            continue;
        }
        let kind = format!("expiry:{}", sub.expires_at.clone().unwrap_or_default());
        crate::notify::sub_down(app, &sub, &kind, "订阅已到期");
        reconcile_sub(app, sub.id)?;
    }
    Ok(())
}

/// 渲染一台服务器的期望配置及其指纹。该服务器没有节点时返回 None。
/// 只渲染启用的节点：停用 = 真正从配置中摘除入站（应用后客户端断开）。
pub fn render_for_server(app: &App, server_id: i64) -> Result<Option<(String, String)>> {
    let bundles = gated_bundles(app, server_id)?;
    if bundles.is_empty() {
        return Ok(None);
    }
    let config = render_config_for(app, &bundles, server_id != 0)?;
    let body = serde_json::to_string_pretty(&config)?;
    Ok(Some((body.clone(), hex::encode(Sha256::digest(body.as_bytes())))))
}

/// 一台服务器要不要跑核心。本机沿用原设置键，远程按服务器各存一份。
fn desired_running(app: &App, server_id: i64) -> bool {
    if server_id == 0 {
        return app.db.get("proxy_desired_running").as_deref() == Some("on");
    }
    app.db.get(&format!("proxy_desired_running_{server_id}")).as_deref() != Some("off")
}

/// 切换主机（抗墙）：把节点以同一套身份参数渲染到目标机，确认端口跑起来后
/// 才把域名 A 记录翻过去。DNS 永远最后翻——前面任何一步失败都停在原状，
/// 客户端零感知。失败时镜像保留（节点在目标机照跑无害；60s 心跳对账会继续
/// 补推），重试切换收敛更快。老机器不碰：节点照跑、域名不再指向，随时可
/// 反向操作切回。
pub async fn switch_node(app: &Shared, node_id: i64, target: i64) -> Result<serde_json::Value> {
    let Some(node) = app.db.proxy_node(node_id)? else {
        refuse!("节点不存在，可能已被删除");
    };
    if !node.enabled {
        refuse!("节点已停用，先启用再切换");
    }
    let fqdn = node.dns_name.trim().to_owned();
    if fqdn.is_empty() {
        refuse!("该节点未绑定域名：先在节点编辑里绑定（域名需托管在 Cloudflare）");
    }
    if target == node.dns_server_id && node.dns_server_id != 0 {
        refuse!("域名已指向该主机，无需切换");
    }
    {
        let agents = app.agents.read().unwrap_or_else(|e| e.into_inner());
        if !agents.contains_key(&target) {
            refuse!("目标主机不在线（agent 未连接或不是被管机）");
        }
    }
    let Some(machine) = app.db.node(target)? else {
        refuse!("目标主机不存在");
    };
    let target_ip = machine.ipv4.trim().to_owned();
    if target_ip.is_empty() {
        refuse!("目标主机还没有上报公网 IPv4（等 agent 首次上报后再切换）");
    }
    if !crate::dns::configured(app) {
        refuse!("未配置 Cloudflare API Token（设置页「域名解析」）");
    }
    // 同端口是硬约束：分享链接含端口，端口一变链接作废。节点尚未渲染到
    // 目标机时才查占用（已在其上则是自己的端口）。
    if !node_server_ids(&node).contains(&target) {
        if used_ports_on(app, target)?.contains(&node.listen_port) {
            refuse!("端口 {} 在目标主机已被其他代理占用；切换要求同端口（链接含端口）", node.listen_port);
        }
        if let Some(rule) = relay_rule_on_port(app, target, node.listen_port)? {
            refuse!("端口 {} 与目标主机上隧道规则「{}」冲突", node.listen_port, rule);
        }
    }
    if let Err(e) = ensure_remote_core(app, target).await {
        warn!("auto core install skipped: {e:#}");
    }
    app.db.add_proxy_node_mirror(node_id, target)?;
    let (body, hash) = match render_for_server(app, target)? {
        Some(v) => v,
        None => refuse!("节点当前没有生效的凭据，无可渲染配置"),
    };
    // 同步等 agent 回包（apply 幂等：指纹一致且在跑直接返回），agent 侧
    // 失败（写盘/重启失败）会以错误回包顶出来。
    crate::agent_ws::call_agent(
        app,
        target,
        "proxy.apply_config",
        serde_json::json!({ "config": body, "sha256": hash, "desired_running": desired_running(app, target) }),
        Duration::from_secs(60),
    )
    .await?;
    let _ = app.db.add_agent_job(target, "proxy.apply_config", &hash);
    // 探测端口就绪：agent 回包不等于端口已绑，给 sing-box 启动留余量。
    let addr = format!("{target_ip}:{}", node.listen_port);
    let mut ready = false;
    for attempt in 0..5u32 {
        if attempt > 0 {
            tokio::time::sleep(Duration::from_secs(2)).await;
        }
        if let Ok(Ok(_)) =
            tokio::time::timeout(Duration::from_secs(3), tokio::net::TcpStream::connect(&addr)).await
        {
            ready = true;
            break;
        }
    }
    if !ready {
        refuse!(
            "配置已推送到目标主机，但端口 {} 探测未就绪；确认核心状态后重试切换（域名未动，客户端不受影响）",
            node.listen_port
        );
    }
    crate::dns::flip_proxy_node(app, &fqdn, &target_ip).await?;
    app.db.set_proxy_dns_target(node_id, target, &target_ip)?;
    info!("proxy node {node_id} switched to server {target}: {fqdn} -> {target_ip}");
    Ok(
        serde_json::json!({ "ok": true, "dns_name": fqdn, "ip": target_ip, "server_id": target, "server_name": machine.name }),
    )
}

/// 把一台服务器的期望配置推给它的 agent（fire-and-forget，agent 侧幂等）。
/// agent 离线时不推；同一期望配置五分钟内不重推——apply 失败的 agent 会一直
/// 报旧指纹，没有这个去重就会每 60s 重推一次并刷屏审计表。
pub fn reconcile_push(app: &App, server_id: i64) -> Result<bool> {
    let (body, hash) = match render_for_server(app, server_id)? {
        Some(v) => v,
        None => {
            // 该服务器已无启用节点：若 agent 此前持有配置（上报过非空指纹），
            // 推空配置把入站摘除；agent 从未持有过则无事可做。
            let reported = {
                let st = app.proxy_remote.lock().unwrap_or_else(|e| e.into_inner());
                st.get(&server_id).map(|s| s.last_hash.clone()).unwrap_or_default()
            };
            if reported.is_empty() {
                return Ok(false);
            }
            eprintln!("[push] server {server_id}: no enabled nodes, clearing config");
            empty_server_config()
        }
    };
    {
        let mut st = app.proxy_remote.lock().unwrap_or_else(|e| e.into_inner());
        let st = st.entry(server_id).or_default();
        if st.last_pushed_hash == hash && st.last_pushed_at > chrono::Utc::now().timestamp() - 300 {
            return Ok(false);
        }
        st.last_pushed_hash = hash.clone();
        st.last_pushed_at = chrono::Utc::now().timestamp();
    }
    let pushed = {
        let agents = app.agents.read().unwrap_or_else(|e| e.into_inner());
        let Some(agent) = agents.get(&server_id) else { return Ok(false) };
        let frame = serde_json::json!({
            "jsonrpc": "2.0", "id": crate::auth::random_token(),
            "method": "proxy.apply_config",
            "params": {
                "config": body, "sha256": hash.clone(),
                "desired_running": desired_running(app, server_id),
            },
        })
        .to_string();
        agent.tx.try_send(frame).is_ok()
    };
    if pushed {
        let _ = app.db.add_agent_job(server_id, "proxy.apply_config", &hash);
    }
    Ok(pushed)
}

/// agent 上报了它本地配置的指纹（每 60s 及上线时）：记账并按需补推。
/// M5：relay_hash 由同一心跳携带，hub 一并比对（远程 Realm 的对账驱动）。
/// 二期起 sing-box 版本也随心跳捎带：非空就喂进缓存（版本过旧黄条数据源）。
/// 异步：收敛后的「确保拉起」要走一次 call_agent 往返，dispatch 侧以独立
/// 任务调用本函数。
pub async fn on_agent_hash_ext(
    app: &App,
    server_id: i64,
    reported: &str,
    relay_reported: Option<&str>,
    version: Option<&str>,
) -> Result<()> {
    {
        let mut st = app.proxy_remote.lock().unwrap_or_else(|e| e.into_inner());
        let st = st.entry(server_id).or_default();
        st.last_hash = reported.to_owned();
        st.last_seen = chrono::Utc::now().timestamp();
        if let Some(v) = version.filter(|v| !v.is_empty()) {
            st.version = v.to_owned();
        }
    }
    let rendered = render_for_server(app, server_id)?;
    // sing-box 对账：agent 持有配置但期望为空（节点全停用/删除）→ 推空配置摘除。
    // 不能在这里 return：机器可能只挂 relay 腿（入口备用机等），掉出去 relay
    // 对账就被饿死，备用腿永远推不下去（E2E 实测踩中）。清空推送自带 5 分钟
    // 去重，不会风暴。
    if rendered.is_none() && !reported.is_empty() && reconcile_push(app, server_id)? {
        eprintln!("[push] server {server_id}: desired empty, clearing agent config");
    }
    // Realm 对账：与期望不符（或本地已改）就重推 relay.apply。
    if std::env::var("MONITOR_RELAY_DEBUG").as_deref() == Ok("1") {
        eprintln!("[relay-debug] server {server_id} relay_reported={relay_reported:?}");
    }
    if let Some(relay_hash) = relay_reported {
        // 期望指纹与推送同源（relay_expected）：占位待命也算已收敛态，
        // 否则本机无规则时每 60s 心跳都会重推占位并重启 realm。
        let (_, want) = relay_expected(app, server_id)?;
        let desired_running = !want.is_empty();
        if want != relay_hash {
            let pushed = reconcile_relay_push(app, server_id)?;
            eprintln!("[hash] relay reconcile: want={:?} got={:?} pushed={}", want, relay_hash, pushed);
            let _ = pushed;
        } else if desired_running {
            // 指纹一致但服务没跑（重启后 systemd 未拉起等）：确保拉起。
            // relay_hash 只对盘上指纹、看不到运行态，所以收敛后也每拍 poke
            // 一次，由 agent 侧 is-active 幂等兜着。
            if server_id != 0 {
                // 独立方法（批次1b）：只拉起不碰配置。曾借道 relay.apply 靠
                // __noop__+空sha+ensure_started 三个魔法字段区分——一个 RPC
                // 两个操作，调用者要背检查顺序（__noop__ 字面量曾被旧版当
                // 配置写盘损坏 realm.toml）。
                if let Err(e) = crate::agent_ws::call_agent(
                    app,
                    server_id,
                    "relay.ensure_started",
                    serde_json::json!({}),
                    Duration::from_secs(1),
                )
                .await
                {
                    // warn 而非 debug：这条坏了意味着「拉活」失效而面板一切照常
                    // （is-active 事故的教训：静默的成功/无日志的失败让链路断了
                    // 数周无人知）——坏着时每 60s 一条正是该吵的时候；成功静默。
                    warn!("node {server_id}: relay ensure-started poke failed: {e:#}");
                }
            }
        }
    }
    if let Some((_, desired)) = rendered {
        if desired == reported {
            // 已收敛：清掉推送去重，让下一次变更可以立即推送。
            let mut st = app.proxy_remote.lock().unwrap_or_else(|e| e.into_inner());
            if let Some(st) = st.get_mut(&server_id) {
                st.last_pushed_hash.clear();
            }
        } else {
            reconcile_push(app, server_id)?;
        }
    }
    Ok(())
}

/// 远程服务器核心状态：在线时问 agent（10s 超时），离线时报离线。
pub async fn remote_status(app: &Shared, server_id: i64) -> Result<serde_json::Value> {
    let online = app.agents.read().unwrap_or_else(|e| e.into_inner()).contains_key(&server_id);
    if !online {
        return Ok(serde_json::json!({ "online": false, "running": false, "installed": false }));
    }
    let v = crate::agent_ws::call_agent(
        app,
        server_id,
        "proxy.core.status",
        serde_json::json!({}),
        Duration::from_secs(10),
    )
    .await?;
    let (_, desired_hash) = render_for_server(app, server_id)?.unwrap_or_default();
    {
        // 版本缓存触点之一：协议页版本过旧黄条的数据源（二期）。
        let mut st = app.proxy_remote.lock().unwrap_or_else(|e| e.into_inner());
        if let Some(ver) = v["installed_version"].as_str() {
            st.entry(server_id).or_default().version = ver.to_owned();
        }
    }
    let st = app
        .proxy_remote
        .lock()
        .unwrap_or_else(|e| e.into_inner())
        .get(&server_id)
        .cloned()
        .unwrap_or_default();
    Ok(serde_json::json!({
        "online": true,
        "installed": v["installed_version"].as_str().map(|s| !s.is_empty()).unwrap_or(false),
        "version": v["installed_version"],
        "running": v["running"],
        "desired_running": desired_running(app, server_id),
        "applied_hash": v["hash"],
        "desired_hash": desired_hash,
        "reported_hash": st.last_hash,
        "listen_ports": v["listen_ports"],
    }))
}

/// 远程服务器缺核心时自动补装：先问一次状态，没装才走安装 RPC。
/// 失败不致命——调用方记 warning 继续建节点，推送会在核心就绪后收敛。
pub async fn ensure_remote_core(app: &Shared, server_id: i64) -> Result<()> {
    let known = {
        let st = app.proxy_remote.lock().unwrap_or_else(|e| e.into_inner());
        st.get(&server_id).map(|s| s.installed).unwrap_or(false)
    };
    if known {
        return Ok(());
    }
    let v = crate::agent_ws::call_agent(
        app,
        server_id,
        "proxy.core.status",
        serde_json::json!({}),
        Duration::from_secs(10),
    )
    .await?;
    let installed = v["installed_version"].as_str().map(|s| !s.is_empty()).unwrap_or(false);
    {
        let mut st = app.proxy_remote.lock().unwrap_or_else(|e| e.into_inner());
        let st = st.entry(server_id).or_default();
        st.installed = installed;
        if let Some(ver) = v["installed_version"].as_str() {
            st.version = ver.to_owned();
        }
    }
    if !installed {
        // 补装版本用全局默认（设置页「代理核心」，从未设置=1.14.2；显式清空
        // 才是跟最新）而不是 latest：面板按 1.14.x 的 api service 写，批量
        // 兜底不该悄悄漂移到未测过的版本。
        let pinned = app.db.get("singbox_default_version").unwrap_or_else(|| "1.14.2".into());
        let want = if pinned.is_empty() { None } else { Some(pinned) };
        install_remote(app, server_id, want).await?;
    }
    Ok(())
}

/// 近期稳定版本（缓存 1 小时），供版本切换点选（M4）。
/// `repo` 决定查哪个项目（sing-box / realm）。
pub async fn recent_versions(app: &App, repo: &'static str) -> Vec<String> {
    // 按 repo 分键：sing-box 与 realm 的列表共用一处缓存曾让先打开的弹窗
    // 的版本串进另一个核心的切换列表。
    #[allow(clippy::type_complexity)] // 复合缓存类型是既定形态
    static CACHE: std::sync::OnceLock<Mutex<HashMap<&'static str, (i64, Vec<String>)>>> =
        std::sync::OnceLock::new();
    let cache = CACHE.get_or_init(|| Mutex::new(HashMap::new()));
    let cached = {
        let c = cache.lock().unwrap_or_else(|e| e.into_inner());
        // repo 只来自仓库内的两个常量，作键安全。
        c.get(repo).filter(|(at, _)| *at > chrono::Utc::now().timestamp() - 3600).map(|(_, v)| v.clone())
    };
    if let Some(v) = cached {
        return v;
    }
    let url = crate::proxied(app, format!("https://api.github.com/repos/{repo}/releases?per_page=20"));
    let fetched = match app.http.get(url).header("User-Agent", "monitor-hub").send().await {
        Ok(r) => r.json::<serde_json::Value>().await.ok(),
        Err(_) => None,
    };
    let mut versions: Vec<String> = fetched
        .map(|v| {
            v.as_array()
                .map(|arr| {
                    arr.iter()
                        // 预发布（alpha/rc）与草稿不进点选列表，手动输入仍可用。
                        .filter(|r| !r["prerelease"].as_bool().unwrap_or(true))
                        .filter(|r| !r["draft"].as_bool().unwrap_or(true))
                        .filter_map(|r| r["tag_name"].as_str())
                        .map(|t| t.trim_start_matches('v').to_owned())
                        .collect()
                })
                .unwrap_or_default()
        })
        .unwrap_or_default();
    versions.truncate(8);
    if !versions.is_empty() {
        cache
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .insert(repo, (chrono::Utc::now().timestamp(), versions.clone()));
    }
    versions
}

/// 在远程服务器上安装 sing-box（agent 自己下载，10 分钟总超时）。
pub async fn install_remote(app: &Shared, server_id: i64, version: Option<String>) -> Result<String> {
    let job = app.db.add_agent_job(server_id, "proxy.core.install", "")?;
    match crate::agent_ws::call_agent(
        app,
        server_id,
        "proxy.core.install",
        serde_json::json!({ "version": version }),
        Duration::from_secs(600),
    )
    .await
    {
        Ok(v) => {
            let version = v["version"].as_str().unwrap_or_default().to_owned();
            let _ = app.db.finish_agent_job(job, "success", &version);
            {
                let mut st = app.proxy_remote.lock().unwrap_or_else(|e| e.into_inner());
                let st = st.entry(server_id).or_default();
                st.installed = true;
                st.version = version.clone();
            }
            // 版本切换后强制重推一次配置，agent 重启进新二进制。
            if let Some(st) = app.proxy_remote.lock().unwrap_or_else(|e| e.into_inner()).get_mut(&server_id) {
                st.last_pushed_hash.clear();
            }
            Ok(version)
        }
        Err(e) => {
            let detail = format!("{e:#}");
            let _ = app.db.finish_agent_job(job, "failed", &detail);
            Err(e)
        }
    }
}

/// 远程核心的启停：期望状态落库，再让 agent 落实（设计文档 5.5）。
pub async fn set_desired_remote(app: &Shared, server_id: i64, running: bool) -> Result<()> {
    app.db.set(&format!("proxy_desired_running_{server_id}"), if running { "on" } else { "off" })?;
    if running {
        reconcile_push(app, server_id)?;
    } else {
        crate::agent_ws::call_agent(
            app,
            server_id,
            "proxy.core.set_desired",
            serde_json::json!({ "running": false }),
            Duration::from_secs(15),
        )
        .await?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn vless_bundle(flow: &str) -> (NodeBundle, ProxyUser) {
        let (private_key, public_key) = generate_reality_keypair();
        let node = ProxyNode {
            server_id: 1,
            name: "test".into(),
            protocol: "vless-reality".into(),
            listen_port: 24443,
            sni: "www.yahoo.com".into(),
            flow: flow.into(),
            ..Default::default()
        };
        let user = ProxyUser { name: "default".into(), credential: new_uuid(), ..Default::default() };
        (
            NodeBundle {
                node,
                secret: ProxySecret {
                    tls_mode: "reality".into(),
                    private_key,
                    public_key,
                    short_id: "a1b2c3d4".into(),
                    ..Default::default()
                },
                users: vec![user.clone()],
            },
            user,
        )
    }

    #[test]
    fn reality_private_key_derives_public_key_and_rejects_bad_values() {
        let (private, expected) = generate_reality_keypair();
        let (_, actual) = reality_keypair_from_private(&private).unwrap();
        assert_eq!(actual, expected);
        assert!(reality_keypair_from_private("not-base64").is_err());
        assert!(reality_keypair_from_private(&URL_SAFE_NO_PAD.encode([0u8; 31])).is_err());
        assert!(reality_keypair_from_private(&(private + "=")).is_err());
    }

    #[test]
    fn advanced_identifiers_are_validated() {
        assert!(valid_uuid("00000000-0000-0000-0000-000000000000"));
        assert!(!valid_uuid("00000000000000000000000000000000"));
        assert!(validate_short_id("a1").is_ok());
        assert!(validate_short_id("a").is_err());
        assert!(validate_short_id("g1").is_err());
        assert!(validate_short_id("a1b2c3d4e5f60718").is_ok());
    }

    #[test]
    fn automatic_port_is_randomly_chosen_from_free_pool_ports() {
        let used = HashSet::from([20001, 20003]);
        for _ in 0..100 {
            let port = choose_free_port("20001-20004", &used).unwrap();
            assert!((20001..=20004).contains(&port));
            assert!(!used.contains(&port));
        }
    }

    #[test]
    fn automatic_port_reports_an_exhausted_pool() {
        let used = HashSet::from([23000, 23001, 23002]);
        let error = choose_free_port("23000-23002", &used).unwrap_err().to_string();
        assert!(error.contains("端口池 23000-23002 已满"));
    }

    /// 二期端口统一：协议侧的分配与校验必须看到中转占用（含监听段全展开）。
    /// 此前 allocate_relay_port 只排除段首端口，allocate_port 完全不看中转。
    #[test]
    fn protocol_side_sees_relay_occupancy_with_full_segments() {
        let app = crate::App::for_test(crate::db::Db::open(":memory:").unwrap());
        app.db
            .create_relay_rule(&crate::db::RelayRule {
                server_id: 1,
                name: "段规则".into(),
                listen_port: "20000-20100".into(),
                ..Default::default()
            })
            .unwrap();
        // 协议自动分配跳过整段：分不出段内的任何一个端口。
        for _ in 0..50 {
            let port = allocate_port(&app, 1).unwrap();
            assert!(!(20000..=20100).contains(&port), "自动分配落进中转监听段：{port}");
        }
        // 手动协议端口撞中转段：报出规则名；别的机器不受这台的中转影响。
        assert_eq!(relay_rule_on_port(&app, 1, 20050).unwrap().unwrap(), "段规则");
        assert!(relay_rule_on_port(&app, 2, 20050).unwrap().is_none());
        // 隧道出口半边也算这台的占用。
        app.db
            .create_relay_rule(&crate::db::RelayRule {
                server_id: 3,
                name: "出口规则".into(),
                listen_port: "21000".into(),
                exit_server_id: 1,
                exit_listen_port: "21001".into(),
                ..Default::default()
            })
            .unwrap();
        assert_eq!(relay_rule_on_port(&app, 1, 21001).unwrap().unwrap(), "出口规则");
        let port = allocate_port(&app, 1).unwrap();
        assert!(port != 21001 && !(20000..=20100).contains(&port));
    }

    /// 版本过旧黄条的判定：计量依赖 api service（1.14+），主.次低于 1.14
    /// 即过旧；解析失败不算过旧（黄条不误报）。
    #[test]
    fn version_stale_follows_the_metering_minimum() {
        assert!(version_stale("1.13.5"));
        assert!(version_stale("1.9.0"));
        assert!(version_stale("0.14.0"));
        assert!(!version_stale("1.14.0"));
        assert!(!version_stale("1.14.2"));
        assert!(!version_stale("1.15.1"));
        assert!(!version_stale(""));
        assert!(!version_stale("abc"));
        assert!(!version_stale("1"));
    }

    #[test]
    fn no_flow_is_omitted_from_links_and_subscriptions() {
        let (vision, user) = vless_bundle("xtls-rprx-vision");
        let (plain, plain_user) = vless_bundle("");
        let host_front = Front { host: "example.com".into(), port: None, scheme: "https".into() };
        assert!(share_link(&vision, &user, &host_front, "").unwrap().contains("flow=xtls-rprx-vision"));
        assert!(!share_link(&plain, &plain_user, &host_front, "").unwrap().contains("flow="));
        // singbox/clash 渲染现在按节点所属服务器解析拨号地址：用测试 App 并把
        // 公网地址固定为 example.com。
        let app = crate::App::for_test(crate::db::Db::open(":memory:").unwrap());
        app.db.set("proxy_public_host", "example.com").unwrap();
        let fronts = sub_fronts(&app);
        let vision_json = singbox_json(&[(vision, user)], &fronts).unwrap();
        let plain_json = singbox_json(&[(plain, plain_user)], &fronts).unwrap();
        assert_eq!(vision_json["outbounds"][0]["flow"], "xtls-rprx-vision");
        assert_eq!(vision_json["outbounds"][0]["server"], "example.com");
        assert!(plain_json["outbounds"][0].get("flow").is_none());
        let (vision_yaml_node, vision_yaml_user) = vless_bundle("xtls-rprx-vision");
        let (plain_yaml_node, plain_yaml_user) = vless_bundle("");
        let vision_yaml = clash_yaml(&[(vision_yaml_node, vision_yaml_user)], &fronts).unwrap();
        let plain_yaml = clash_yaml(&[(plain_yaml_node, plain_yaml_user)], &fronts).unwrap();
        assert!(vision_yaml.contains("flow: xtls-rprx-vision"));
        assert!(vision_yaml.contains("server: example.com"));
        assert!(!plain_yaml.contains("flow:"));
    }

    /// 多入口订阅（M8）：入口解析、回落、三种格式的逐入口渲染与端口覆盖。
    #[test]
    fn subscription_renders_one_entry_per_front() {
        let app = crate::App::for_test(crate::db::Db::open(":memory:").unwrap());
        app.db.set("proxy_public_host", "main.example.com").unwrap();
        app.db.set("sub_hosts", "cdn.example.com:8443\n203.0.113.9").unwrap();
        let fronts = sub_fronts(&app);
        assert_eq!(fronts.len(), 2);
        assert_eq!(fronts[0].host, "cdn.example.com");
        assert_eq!(fronts[0].port, Some(8443));
        assert_eq!(fronts[1].host, "203.0.113.9");
        // 空设置回落 public_host 的既有链。
        app.db.set("sub_hosts", "").unwrap();
        let fronts = sub_fronts(&app);
        assert_eq!(fronts.len(), 1);
        assert_eq!(fronts[0].host, "main.example.com");
        assert_eq!(fronts[0].port, None);

        // 多入口：每个节点渲染两条，名称带入口短标签，端口覆盖生效。
        app.db.set("sub_hosts", "cdn.example.com:8443\n203.0.113.9").unwrap();
        let fronts = sub_fronts(&app);
        let (bundle, user) = vless_bundle("xtls-rprx-vision");
        let json = singbox_json(&[(bundle, user)], &fronts).unwrap();
        let outbounds = json["outbounds"].as_array().unwrap();
        assert_eq!(outbounds.len(), 2);
        let names: Vec<&str> = outbounds.iter().map(|o| o["tag"].as_str().unwrap()).collect();
        assert!(names.contains(&"test\u{b7}cdn"), "{names:?}");
        assert!(names.contains(&"test\u{b7}203.0.113.9"), "{names:?}");
        assert_eq!(outbounds[0]["server_port"], 8443);
        let (bundle, user) = vless_bundle("");
        let yaml = clash_yaml(&[(bundle, user)], &fronts).unwrap();
        assert!(yaml.contains("port: 8443"), "{yaml}");
        let (bundle, user) = vless_bundle("");
        let front = parse_front("cdn.example.com:8443").unwrap();
        let link = share_link(&bundle, &user, &front, "\u{b7}cdn").unwrap();
        assert!(link.contains("@cdn.example.com:8443?"), "{link}");
        assert!(link.contains("#test%C2%B7cdn"), "{link}");

        // 入口行的各种写法。
        assert_eq!(parse_front("https://a.com:443/x").unwrap().port, Some(443));
        assert_eq!(parse_front("http://1.2.3.4:28080").unwrap().scheme, "http");
        assert_eq!(parse_front("[2606:4700::1111]:443").unwrap().host, "2606:4700::1111");
        assert!(parse_front("  ").is_none());
        assert!(parse_front("https://").is_none());
    }
    /// M12：连接事件解码——用服务器实捕的两条真实帧：一条 UPDATE（只带
    /// id 与上行增量），一条 NEW（带完整连接与 user）。CLOSED 与 UPDATE
    /// 同构（无 connection）。
    /// 架构巡检批次4：两仓（hub/agent）的连接事件解码测试钉同一份 golden
    /// 字节夹具 src/testdata/singbox-events.golden——NEW 全五元组、真实捕包
    /// UPDATE、带收尾增量的 CLOSED 各一条。sha 常量是跨仓对齐销：改任一侧
    /// 夹具必须同步另一侧并同步换两仓的常量，否则测试红。协议知识（字段号、
    /// wire type、生命周期语义）从此只有一份事实源。
    #[test]
    fn golden_fixture_decodes_identically_across_repos() {
        const GOLDEN_SHA: &str = "94870bb2c541976ad13a9357bf029bbbcb1d1c0c4dbd48a7f82de3a3f7864791";
        let golden = include_bytes!("testdata/singbox-events.golden");
        use sha2::{Digest, Sha256};
        assert_eq!(
            hex::encode(Sha256::digest(golden)),
            GOLDEN_SHA,
            "golden 夹具与两仓共享版本不一致：任何一侧改动都要同步另一侧"
        );

        let mut rest = &golden[..];
        let mut events = Vec::new();
        while !rest.is_empty() {
            let n = rest[0] as usize;
            events.push(decode_connection_event(&rest[1..1 + n]).expect("golden 帧必须可解码"));
            rest = &rest[1 + n..];
        }
        assert_eq!(events.len(), 3);
        match &events[0] {
            ConnEvent::New { id, user, inbound, network, source, destination, domain } => {
                assert_eq!(
                    (id.as_str(), user.as_str(), inbound.as_str(), network.as_str()),
                    ("conn-1", "alice", "in-11990", "udp")
                );
                assert_eq!(
                    (source.as_str(), destination.as_str(), domain.as_str()),
                    ("1.2.3.4:5", "example.com:443", "example.com")
                );
            }
            other => panic!("第一帧应为 NEW：{other:?}"),
        }
        assert_eq!(
            events[1],
            ConnEvent::Update { id: "e0a2d363-617b-47be-9aca-bbcd376e53ad".into(), up: 1570, down: 0 }
        );
        assert_eq!(events[2], ConnEvent::Closed { id: "c1".into(), up: 111, down: 222 });
    }

    #[test]
    fn connection_event_decode_reads_deltas_and_user() {
        let update: Vec<u8> = hex_to_bytes(
            "0a2b0801122465306132643336332d363137622d343762652d396163612d62626364333736653533616420a20c",
        );
        let ev = decode_connection_event(&update).unwrap();
        assert_eq!(
            ev,
            ConnEvent::Update { id: "e0a2d363-617b-47be-9aca-bbcd376e53ad".into(), up: 1570, down: 0 }
        );

        // NEW：connection 里带 inbound 与 user。
        let new_frame: Vec<u8> =
            hex_to_bytes("0a1d08001206636f6e6e2d311a111208696e2d31313939305205616c696365");
        match decode_connection_event(&new_frame).unwrap() {
            ConnEvent::New { user, .. } => assert_eq!(user, "alice"),
            other => panic!("expected NEW, got {other:?}"),
        }
    }

    /// CLOSED 若带收尾增量（官方核心当前不带）原样透传给聚合分支补最后一
    /// 拍——字段要被解析出来而不是丢弃。
    #[test]
    fn a_closed_event_keeps_its_final_deltas() {
        // CLOSED { id: "c1", uplinkDelta: 111, downlinkDelta: 222 }
        let frame: Vec<u8> = hex_to_bytes("0a0b080212026331206f28de01");
        assert_eq!(
            decode_connection_event(&frame),
            Some(ConnEvent::Closed { id: "c1".into(), up: 111, down: 222 })
        );
    }

    /// NEW 事件的五元组字段（inbound/source/destination/domain/user）都要
    /// 解出来；network 枚举映射 tcp/udp。
    #[test]
    fn new_event_decode_reads_the_full_tuple() {
        fn ld(field: u64, payload: &[u8]) -> Vec<u8> {
            let mut out = vec![((field << 3) | 2) as u8];
            push_varint(&mut out, payload.len() as u64);
            out.extend_from_slice(payload);
            out
        }
        fn vfield(field: u64, v: u64) -> Vec<u8> {
            let mut out = vec![(field << 3) as u8];
            push_varint(&mut out, v);
            out
        }
        // connection{ id, inbound, network=2(udp), source, destination, domain, user }。
        let mut conn = ld(1, b"conn-1");
        conn.extend(ld(2, b"in-11990"));
        conn.extend(vfield(5, 2));
        conn.extend(ld(6, b"1.2.3.4:5"));
        conn.extend(ld(7, b"example.com:443"));
        conn.extend(ld(8, b"example.com"));
        conn.extend(ld(10, b"alice"));
        // 事件本体：type=NEW(0)、id、connection；外层信封包一层。
        let mut inner = vec![0x08, 0x00];
        inner.extend(ld(2, b"conn-1"));
        inner.extend(ld(3, &conn));
        let mut frame = vec![0x0A];
        push_varint(&mut frame, inner.len() as u64);
        frame.extend_from_slice(&inner);

        match decode_connection_event(&frame).unwrap() {
            ConnEvent::New { user, inbound, network, source, destination, domain, .. } => {
                assert_eq!((user.as_str(), inbound.as_str(), network.as_str()), ("alice", "in-11990", "udp"));
                assert_eq!(
                    (source.as_str(), destination.as_str(), domain.as_str()),
                    ("1.2.3.4:5", "example.com:443", "example.com")
                );
            }
            other => panic!("expected NEW, got {other:?}"),
        }
    }

    fn hex_to_bytes(hex: &str) -> Vec<u8> {
        (0..hex.len()).step_by(2).map(|i| u8::from_str_radix(&hex[i..i + 2], 16).unwrap()).collect()
    }

    #[test]
    fn sub_status_covers_every_lifecycle_branch() {
        let d = |s: &str| chrono::NaiveDate::parse_from_str(s, "%Y-%m-%d").unwrap();
        let at = d("2026-09-30");
        // Default 只对 serde 生效的 enabled 有默认值，构造体字面量得自己给。
        let base = SubUser { id: 1, name: "c".into(), enabled: true, ..Default::default() };
        assert_eq!(sub_status(&base, at), SubStatus::Active);
        // 停用盖过到期：手动关掉的客户不用再解释第二个原因。
        let disabled = SubUser { enabled: false, expires_at: Some("2026-01-01".into()), ..base.clone() };
        assert_eq!(sub_status(&disabled, at), SubStatus::Disabled);
        // 到期当天仍有效，次日起失格。
        let last_day = SubUser { expires_at: Some("2026-09-30".into()), ..base.clone() };
        assert_eq!(sub_status(&last_day, at), SubStatus::Active);
        let expired = SubUser { expires_at: Some("2026-09-29".into()), ..base.clone() };
        assert_eq!(sub_status(&expired, at), SubStatus::Expired);
        // 配额：到达即超额；差一点仍在限额内；未设配额永不过额。
        let over = SubUser { quota_bytes: 100, quota_used_up: 60, quota_used_down: 40, ..base.clone() };
        assert_eq!(sub_status(&over, at), SubStatus::OverQuota);
        let near = SubUser { quota_bytes: 100, quota_used_up: 99, quota_used_down: 0, ..base.clone() };
        assert_eq!(sub_status(&near, at), SubStatus::Active);
        let unlimited =
            SubUser { quota_bytes: 0, quota_used_up: 0, quota_used_down: 1 << 40, ..base.clone() };
        assert_eq!(sub_status(&unlimited, at), SubStatus::Active);
    }

    /// 生命周期门槛：失格客户的凭据从配置里摘除，独立凭据保留，客户的
    /// 凭据被摘光后整节点退出配置。
    #[test]
    fn gated_bundles_drop_disabled_customers_credentials() {
        let app = crate::App::for_test(crate::db::Db::open(":memory:").unwrap());
        let node_id = app
            .db
            .create_proxy_node(
                &ProxyNode {
                    server_id: 1,
                    name: "n1".into(),
                    protocol: "vless-reality".into(),
                    listen_port: 24443,
                    sni: "www.yahoo.com".into(),
                    enabled: true,
                    ..Default::default()
                },
                &ProxySecret::default(),
                new_uuid().as_str(),
            )
            .unwrap();
        let sub_id = app.db.create_sub_user("客户A", "tok").unwrap();
        let sub = SubUser { id: sub_id, name: "客户A".into(), enabled: true, ..Default::default() };
        let alice = app.db.create_proxy_user(node_id, "alice", &new_uuid()).unwrap();
        let bob = app.db.create_proxy_user(node_id, "bob", &new_uuid()).unwrap();
        app.db.set_proxy_user_sub(alice, Some(sub_id)).unwrap();
        // create_proxy_node 自带的 default 凭据也是客户外的一员，一并认领后
        // 节点上只剩客户凭据可测"摘光即整节点退出"。
        let bundles = gated_bundles(&app, 1).unwrap();
        assert_eq!(bundles[0].users.len(), 3);
        let default_user = bundles[0].users.iter().find(|u| u.name == "default").unwrap().id;
        app.db.set_proxy_user_sub(default_user, Some(sub_id)).unwrap();
        app.db.set_proxy_user_sub(bob, Some(sub_id)).unwrap();
        // 停用：三个凭据都归客户，全摘后整节点退出配置。
        app.db.update_sub_user(sub_id, &SubUser { enabled: false, ..sub.clone() }).unwrap();
        assert!(gated_bundles(&app, 1).unwrap().is_empty());
        // 独立凭据不归生命周期管：释放 bob 出来，节点带着它回来。
        app.db.set_proxy_user_sub(bob, None).unwrap();
        let bundles = gated_bundles(&app, 1).unwrap();
        assert_eq!(bundles[0].users.iter().map(|u| u.name.as_str()).collect::<Vec<_>>(), vec!["bob"]);
        // 恢复客户并设 100 配额：正常时全员回归；记账到超额后客户凭据再摘。
        app.db.update_sub_user(sub_id, &SubUser { enabled: true, quota_bytes: 100, ..sub.clone() }).unwrap();
        assert_eq!(gated_bundles(&app, 1).unwrap()[0].users.len(), 3);
        app.db.bump_sub_usage(&[(sub_id, 60, 40)]).unwrap();
        let bundles = gated_bundles(&app, 1).unwrap();
        assert_eq!(bundles[0].users.iter().map(|u| u.name.as_str()).collect::<Vec<_>>(), vec!["bob"]);
    }
}

#[cfg(test)]
mod relay_import_tests {
    use super::*;

    #[test]
    fn vless_link_parses_and_rewrites_keeping_params() {
        let link = "vless://uuid-123@1.2.3.4:21000?encryption=none&security=reality&sni=www.apple.com&fp=chrome&pbk=PBK&sid=abcd&type=tcp&flow=xtls-rprx-vision#%E9%A6%99%E6%B8%AF01";
        let (scheme, host, port, name) = parse_share_link(link).unwrap();
        assert_eq!(scheme, "vless");
        assert_eq!((host.as_str(), port), ("1.2.3.4", 21000));
        assert_eq!(name, "香港01");
        let rewritten = rewrite_share_link(link, "5.6.7.8", 25500).unwrap();
        assert!(rewritten.starts_with("vless://uuid-123@5.6.7.8:25500?"));
        assert!(rewritten.contains("security=reality"));
        assert!(rewritten.contains("flow=xtls-rprx-vision"));
        assert!(rewritten.contains("#%E9%A6%99%E6%B8%AF01"));
        // 参数一个不能少
        assert_eq!(rewritten.matches('&').count(), link.matches('&').count());
    }

    #[test]
    fn hysteria2_link_with_path_and_query_rewrites() {
        let link = "hysteria2://pass@9.9.9.9:36712/?sni=www.bing.com&insecure=1#hy2node";
        let (scheme, host, port, name) = parse_share_link(link).unwrap();
        assert_eq!(
            (scheme.as_str(), host.as_str(), port, name.as_str()),
            ("hysteria2", "9.9.9.9", 36712, "hy2node")
        );
        let rewritten = rewrite_share_link(link, "10.0.0.1", 25000).unwrap();
        assert!(rewritten.starts_with("hysteria2://pass@10.0.0.1:25000/?sni=www.bing.com"));
        assert!(rewritten.contains("insecure=1"));
    }

    #[test]
    fn ss_link_without_userinfo_at_rewrites() {
        // SIP002：userinfo 是 base64(method:password)，里面可能没有 @
        let link = "ss://YWVzLTI1Ni1nY206cGFzc3dvcmQ=@7.7.7.7:8388#SS%E6%97%A5%E6%9C%AC";
        let (scheme, host, port, _) = parse_share_link(link).unwrap();
        assert_eq!((scheme.as_str(), host.as_str(), port), ("ss", "7.7.7.7", 8388));
        let rewritten = rewrite_share_link(link, "4.4.4.4", 25001).unwrap();
        assert!(rewritten.starts_with("ss://YWVzLTI1Ni1nY206cGFzc3dvcmQ=@4.4.4.4:25001#"));
    }

    #[test]
    fn vmess_and_garbage_are_rejected_with_guidance() {
        let err = parse_share_link("vmess://eyJ2IjoiMiJ9").unwrap_err().to_string();
        assert!(err.contains("手动填写"), "{err}");
        assert!(parse_share_link("随便一串字").is_err());
        assert!(parse_share_link("vless://uuid@host:notaport#x").is_err());
    }
}

#[cfg(test)]
mod relay_render_tests {
    use super::*;
    use crate::db::{RelayRule, RelayTarget};

    /// 测试 App + 公网地址固定；不造节点行——node_dial_host 对无行服务器
    /// 回落到 proxy_public_host，出口地址解析是既有函数不在本模块测。
    fn app_with_rule(rule: RelayRule, targets: &[(&str, i64)]) -> crate::App {
        let app = crate::App::for_test(crate::db::Db::open(":memory:").unwrap());
        app.db.set("proxy_public_host", "exit.example.com").unwrap();
        let id = app.db.create_relay_rule(&rule).unwrap();
        let rows: Vec<RelayTarget> = targets
            .iter()
            .enumerate()
            .map(|(i, (h, p))| RelayTarget {
                rule_id: id,
                seq: i as i64,
                host: h.to_string(),
                port: *p,
                enabled: true,
                ..Default::default()
            })
            .collect();
        app.db.replace_relay_targets(id, &rows).unwrap();
        app
    }

    fn base_rule() -> RelayRule {
        RelayRule {
            server_id: 1,
            name: "测试".into(),
            listen_port: "21580".into(),
            enabled: true,
            protocol: "both".into(),
            ..Default::default()
        }
    }

    /// 备用入口机的腿：规则入口在 1、备用是 2,机器 2 必须渲染出同一条入口
    /// 腿——它是故障转移时真正接流量的机器（曾因渲染漏配备用机,切换落空）。
    #[test]
    fn backup_entry_machine_renders_the_entry_leg() {
        let app =
            app_with_rule(RelayRule { entry_backups: "[2]".into(), ..base_rule() }, &[("1.1.1.1", 443)]);
        let (body, _) = render_relay_for_machine(&app, 2).unwrap().unwrap();
        assert!(body.contains("listen = \"0.0.0.0:21580\""), "{body}");
        assert!(body.contains("remote = \"1.1.1.1:443\""), "{body}");
        // 无关机器不渲染。
        assert!(render_relay_for_machine(&app, 7).unwrap().is_none());
    }

    /// 只有 relay 腿、没有 sing-box 节点的机器（入口备用机的常态）：心跳对账
    /// 不得被「sing-box 清空」路径截胡——曾因提前 return,relay 对账被饿死,
    /// 备用腿永远推不下去。
    #[tokio::test]
    async fn relay_only_machine_heartbeat_still_reconciles_relay() {
        let app = std::sync::Arc::new(crate::App::for_test(crate::db::Db::open(":memory:").unwrap()));
        app.db.set("proxy_public_host", "exit.example.com").unwrap();
        let id = app
            .db
            .create_relay_rule(&RelayRule {
                server_id: 1,
                name: "腿".into(),
                listen_port: "21580".into(),
                enabled: true,
                entry_backups: "[2]".into(),
                ..Default::default()
            })
            .unwrap();
        app.db
            .replace_relay_targets(
                id,
                &[RelayTarget {
                    rule_id: id,
                    seq: 0,
                    host: "1.1.1.1".into(),
                    port: 443,
                    enabled: true,
                    ..Default::default()
                }],
            )
            .unwrap();

        // 机器 2 在线（桩:应答一切 RPC 并记账方法名）,其上无任何 sing-box
        // 节点,但 agent 仍持着旧的 sing-box 配置（reported 非空）——正是触发
        // 被删掉的提前 return 的状态。
        let (tx, mut rx) = tokio::sync::mpsc::channel::<String>(16);
        app.agents.write().unwrap().insert(2, crate::agent_ws::Agent::test_stub(tx));
        let seen: std::sync::Arc<std::sync::Mutex<Vec<String>>> = Default::default();
        let seen2 = seen.clone();
        let responder = app.clone();
        tokio::spawn(async move {
            while let Some(frame) = rx.recv().await {
                let v: serde_json::Value = serde_json::from_str(&frame).unwrap();
                seen2.lock().unwrap().push(v["method"].as_str().unwrap_or("").to_owned());
                // fire-and-forget 帧（relay.apply 等）也带 id，但没人等应答。
                if let Some(id) = v["id"].as_str() {
                    if let Some(slot) = responder.proxy_rpcs.lock().unwrap().remove(id) {
                        slot.send(Ok(serde_json::json!({}))).ok();
                    }
                }
            }
        });

        // 真实心跳形状：relay_hash 恒在（无配置时空串）。
        on_agent_hash_ext(&app, 2, "stale-singbox-hash", Some(""), Some("1.14.2")).await.unwrap();

        // relay.apply 已推给机器 2（fire-and-forget,等桩消费到再断言）。
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(5);
        while std::time::Instant::now() < deadline {
            if seen.lock().unwrap().iter().any(|m| m == "relay.apply") {
                break;
            }
            tokio::time::sleep(std::time::Duration::from_millis(50)).await;
        }
        assert!(
            seen.lock().unwrap().iter().any(|m| m == "relay.apply"),
            "心跳后必须推 relay.apply,实际: {:?}",
            seen.lock().unwrap()
        );
    }

    /// 远端机器（无规则、非本机作用域）+ 全局中转开关开：期望是「停服务清理」，
    /// 推送必须带 desired_running=false。若带 true，agent 会自造占位写盘，指纹
    /// 与期望（空串）永不相等——每 60s 心跳重推一次 realm（占位语义三处分叉
    /// 的重启环）。桩忠实模拟 agent 两种行为：空体+true=自造占位（旧版），
    /// 空体+false=停服务清文件。三拍心跳后必须收敛：恰好推过一次、桩已清干净。
    #[tokio::test]
    async fn empty_relay_expectation_stops_the_service_instead_of_placeholder() {
        let app = std::sync::Arc::new(crate::App::for_test(crate::db::Db::open(":memory:").unwrap()));
        app.db.set("proxy_public_host", "exit.example.com").unwrap();
        app.db.set("realm_desired_running", "on").unwrap();

        // 桩的状态：它当前上报的 relay 指纹。起点是「规则刚删、盘上还有旧配置」。
        let reported: std::sync::Arc<std::sync::Mutex<String>> =
            std::sync::Arc::new(std::sync::Mutex::new("stale-hash-of-deleted-rule".into()));
        let pushes: std::sync::Arc<std::sync::Mutex<Vec<bool>>> = Default::default();

        let (tx, mut rx) = tokio::sync::mpsc::channel::<String>(16);
        app.agents.write().unwrap().insert(2, crate::agent_ws::Agent::test_stub(tx));
        let responder = app.clone();
        let reported_seen = reported.clone();
        let pushed_seen = pushes.clone();
        tokio::spawn(async move {
            while let Some(frame) = rx.recv().await {
                let v: serde_json::Value = serde_json::from_str(&frame).unwrap();
                if v["method"] == "relay.apply" {
                    let desired = v["params"]["desired_running"].as_bool().unwrap();
                    let empty = v["params"]["config"].as_str().unwrap_or("x").is_empty();
                    pushed_seen.lock().unwrap().push(desired);
                    if empty {
                        // 忠实两分：true=自造占位写盘（指纹变为占位哈希），
                        // false=停服务删文件（指纹清空）。
                        *reported_seen.lock().unwrap() =
                            if desired { "fabricated-placeholder-hash".into() } else { String::new() };
                    }
                }
                if let Some(id) = v["id"].as_str() {
                    if let Some(slot) = responder.proxy_rpcs.lock().unwrap().remove(id) {
                        slot.send(Ok(serde_json::json!({}))).ok();
                    }
                }
            }
        });

        // 推送是 fire-and-forget（try_send 不等应答），每拍后让步给 responder
        // 消费帧，桩的状态更新才发生在下一拍之前。
        for _ in 0..3 {
            let hash = reported.lock().unwrap().clone();
            on_agent_hash_ext(&app, 2, "", Some(&hash), None).await.unwrap();
            tokio::time::sleep(std::time::Duration::from_millis(100)).await;
        }

        let pushes = pushes.lock().unwrap();
        assert_eq!(pushes.len(), 1, "三拍心跳只该推一次（首拍清场），实际 {:?} 次", pushes);
        assert!(!pushes[0], "空期望的推送必须带 desired_running=false（停服务清理）");
        assert!(reported.lock().unwrap().is_empty(), "收敛后 agent 指纹应为空（服务已停、文件已清）");
    }

    /// 收敛态（上报指纹==期望、realm 应在跑）的心跳必须真正发出 ensure_started
    /// poke：relay_hash 只反映盘上指纹、看不到运行态，服务停了只能靠每拍拉活
    /// 兜底。曾因 call_agent 的 future 建立即弃而从未发出（冻结复盘发现的真 bug）。
    #[tokio::test]
    async fn converged_relay_heartbeat_sends_ensure_started_poke() {
        let app = std::sync::Arc::new(crate::App::for_test(crate::db::Db::open(":memory:").unwrap()));
        app.db.set("proxy_public_host", "exit.example.com").unwrap();
        let id = app.db.create_relay_rule(&RelayRule { entry_backups: "[2]".into(), ..base_rule() }).unwrap();
        app.db
            .replace_relay_targets(
                id,
                &[RelayTarget {
                    rule_id: id,
                    seq: 0,
                    host: "1.1.1.1".into(),
                    port: 443,
                    enabled: true,
                    ..Default::default()
                }],
            )
            .unwrap();

        let (tx, mut rx) = tokio::sync::mpsc::channel::<String>(16);
        app.agents.write().unwrap().insert(2, crate::agent_ws::Agent::test_stub(tx));
        let pokes: std::sync::Arc<std::sync::Mutex<Vec<serde_json::Value>>> = Default::default();
        let seen = pokes.clone();
        let responder = app.clone();
        tokio::spawn(async move {
            while let Some(frame) = rx.recv().await {
                let v: serde_json::Value = serde_json::from_str(&frame).unwrap();
                if v["method"] == "relay.ensure_started" {
                    seen.lock().unwrap().push(v["params"].clone());
                }
                if let Some(id) = v["id"].as_str() {
                    if let Some(slot) = responder.proxy_rpcs.lock().unwrap().remove(id) {
                        slot.send(Ok(serde_json::json!({}))).ok();
                    }
                }
            }
        });

        // 上报指纹与期望完全一致（收敛）：唯一该发生的动作就是拉活 poke。
        let (_, want) = relay_expected(&app, 2).unwrap();
        assert!(!want.is_empty(), "机器 2 有备用腿，期望指纹非空");
        on_agent_hash_ext(&app, 2, "", Some(&want), None).await.unwrap();

        // poke 走 call_agent 等应答，函数返回时帧必已被桩消费并记账。
        let got = pokes.lock().unwrap();
        assert_eq!(got.len(), 1, "恰好一次拉活 poke：{got:?}");
        assert!(got[0].as_object().map(|m| m.is_empty()).unwrap_or(false), "poke 无参数：{got:?}");
    }

    #[test]
    fn multi_target_renders_extra_remotes_and_weighted_balance() {
        let app = app_with_rule(
            RelayRule { balance: "roundrobin".into(), ..base_rule() },
            &[("1.1.1.1", 443), ("2.2.2.2", 443), ("3.3.3.3", 443)],
        );
        let (body, _) = render_relay_for_machine(&app, 1).unwrap().unwrap();
        assert!(body.contains("listen = \"0.0.0.0:21580\""), "{body}");
        assert!(body.contains("remote = \"1.1.1.1:443\""), "{body}");
        assert!(body.contains("extra_remotes = [\"2.2.2.2:443\", \"3.3.3.3:443\"]"), "{body}");
        // 权重全默认 1，realm 原生权重语法
        assert!(body.contains("balance = \"roundrobin: 1, 1, 1\""), "{body}");
    }

    #[test]
    fn protocol_selection_overrides_the_endpoint_network() {
        let app = app_with_rule(RelayRule { protocol: "udp".into(), ..base_rule() }, &[("1.1.1.1", 443)]);
        let (body, _) = render_relay_for_machine(&app, 1).unwrap().unwrap();
        assert!(body.contains("network = { no_tcp = true }"), "{body}");
        let app = app_with_rule(RelayRule { protocol: "tcp".into(), ..base_rule() }, &[("1.1.1.1", 443)]);
        let (body, _) = render_relay_for_machine(&app, 1).unwrap().unwrap();
        assert!(body.contains("network = { use_udp = false }"), "{body}");
        let app = app_with_rule(base_rule(), &[("1.1.1.1", 443)]);
        let (body, _) = render_relay_for_machine(&app, 1).unwrap().unwrap();
        assert!(!body.contains("network ="), "{body}");
    }

    #[test]
    fn relay_expected_treats_placeholder_as_converged_state() {
        // 有规则：期望=渲染结果。
        let app = app_with_rule(base_rule(), &[("1.1.1.1", 443)]);
        let (body, hash) = relay_expected(&app, 1).unwrap();
        let (rbody, rhash) = render_relay_for_machine(&app, 1).unwrap().unwrap();
        assert_eq!(body, rbody);
        assert_eq!(hash, rhash);

        // 无规则+开关开+本机作用域（server 0）：期望占位待命——agent 落盘后
        // 上报的正是这个指纹，对账必须视为已收敛（曾每 60s 重推重启 realm）。
        let app = crate::App::for_test(crate::db::Db::open(":memory:").unwrap());
        let (body, hash) = relay_expected(&app, 0).unwrap();
        let ph = placeholder_relay_body();
        assert_eq!(body, ph);
        assert_eq!(hash, hex::encode(Sha256::digest(ph.as_bytes())));

        // 无规则的远程机：占位仅限本机作用域，远程期望空清理。
        assert_eq!(relay_expected(&app, 7).unwrap(), (String::new(), String::new()));

        // 无规则+开关关：本机作用域也期望空清理。
        app.db.set("realm_desired_running", "off").unwrap();
        assert_eq!(relay_expected(&app, 0).unwrap(), (String::new(), String::new()));
    }

    #[test]
    fn tunnel_rule_renders_both_halves_with_matched_transport() {
        let app = app_with_rule(
            RelayRule {
                transport: "tls".into(),
                tls_sni: "exit.example.com".into(),
                exit_server_id: 2,
                exit_listen_port: "24443".into(),
                ..base_rule()
            },
            &[("127.0.0.1", 21579)],
        );
        // 入口半边：remote 指向落地机的加密监听（无节点行时回落 proxy_public_host）。
        let (entry, _) = render_relay_for_machine(&app, 1).unwrap().unwrap();
        assert!(entry.contains("remote = \"exit.example.com:24443\""), "{entry}");
        assert!(entry.contains("remote_transport = \"tls;sni=exit.example.com;insecure\""), "{entry}");
        // 出口半边：同款域名收进来（servername 自签模式），转给真实目标。
        let (exit, _) = render_relay_for_machine(&app, 2).unwrap().unwrap();
        assert!(exit.contains("listen = \"0.0.0.0:24443\""), "{exit}");
        assert!(exit.contains("listen_transport = \"tls;servername=exit.example.com\""), "{exit}");
        assert!(exit.contains("remote = \"127.0.0.1:21579\""), "{exit}");
        // 两半指纹不同（同一规则在两台机器渲染出不同配置）。
        let (_, h1) = render_relay_for_machine(&app, 1).unwrap().unwrap();
        let (_, h2) = render_relay_for_machine(&app, 2).unwrap().unwrap();
        assert_ne!(h1, h2);
    }

    #[test]
    fn down_targets_are_dropped_only_while_others_survive() {
        // 三目标：第二个 down。多目标 + balance → 摘除；全 down → 保留全量。
        let mk = |state: &str| RelayTarget {
            host: "1.1.1.1".into(),
            port: 443,
            state: state.into(),
            enabled: true,
            ..Default::default()
        };
        let targets = vec![mk("up"), mk("down"), mk("up")];
        let kept = effective_targets(&targets, "roundrobin");
        assert_eq!(kept.len(), 2);
        assert!(kept.iter().all(|t| t.state != "down"));
        let all_down: Vec<_> = vec![mk("down"), mk("down")];
        assert_eq!(effective_targets(&all_down, "roundrobin").len(), 2, "全 down 时保留全量");
        // 单目标 / 未选策略：只展示，不摘。
        let single = vec![mk("down")];
        assert_eq!(effective_targets(&single, "").len(), 1);
    }

    #[test]
    fn transport_string_follows_the_verified_kaminari_matrix() {
        // 实测矩阵：入口用 sni+insecure，出口用 servername；ws/wss 两侧都
        // 必须 host+path（缺一个 realm 启动即 panic）。
        let r = |transport: &str, sni: &str, path: &str| RelayRule {
            transport: transport.into(),
            tls_sni: sni.into(),
            ws_path: path.into(),
            ..Default::default()
        };
        assert_eq!(
            transport_str(&r("tls", "a.com", ""), TransportSide::Entry, "5.6.7.8"),
            "tls;sni=a.com;insecure"
        );
        assert_eq!(
            transport_str(&r("tls", "", ""), TransportSide::Entry, "5.6.7.8"),
            "tls;sni=5.6.7.8;insecure",
            "sni 缺省用落地拨号地址"
        );
        assert_eq!(
            transport_str(&r("tls", "a.com", ""), TransportSide::Exit, "5.6.7.8"),
            "tls;servername=a.com"
        );
        assert_eq!(
            transport_str(&r("ws", "", "/tun"), TransportSide::Entry, "5.6.7.8"),
            "ws;host=5.6.7.8;path=/tun"
        );
        assert_eq!(
            transport_str(&r("ws", "", ""), TransportSide::Exit, "5.6.7.8"),
            "ws;host=5.6.7.8;path=/",
            "path 缺省 /"
        );
        assert_eq!(
            transport_str(&r("wss", "a.com", "/tun"), TransportSide::Entry, "5.6.7.8"),
            "wss;sni=a.com;insecure;host=a.com;path=/tun"
        );
        assert_eq!(
            transport_str(&r("wss", "", ""), TransportSide::Exit, "5.6.7.8"),
            "wss;servername=5.6.7.8;host=5.6.7.8;path=/"
        );
        assert_eq!(transport_str(&r("", "", ""), TransportSide::Entry, "5.6.7.8"), "");
    }

    #[test]
    fn wss_renders_listen_transport_on_entry_side() {
        let app = app_with_rule(
            RelayRule {
                transport: "ws".into(),
                ws_path: "/tun".into(),
                exit_server_id: 2,
                exit_listen_port: "24443".into(),
                ..base_rule()
            },
            &[("127.0.0.1", 21579)],
        );
        let (entry, _) = render_relay_for_machine(&app, 1).unwrap().unwrap();
        assert!(entry.contains("remote_transport = \"ws;host=exit.example.com;path=/tun\""), "{entry}");
        let (exit, _) = render_relay_for_machine(&app, 2).unwrap().unwrap();
        assert!(exit.contains("listen_transport = \"ws;host=exit.example.com;path=/tun\""), "{exit}");
    }

    #[test]
    fn user_input_is_escaped_for_toml() {
        assert_eq!(toml_str("a\"b\\c"), "\"a\\\"b\\\\c\"");
    }

    #[test]
    fn validate_rejects_bad_tunnel_and_balance_shapes() {
        let mut r = base_rule();
        r.target = "1.1.1.1:443".into();
        assert!(validate_relay(&r).is_ok());
        r.exit_server_id = r.server_id;
        r.exit_listen_port = "24443".into();
        assert!(validate_relay(&r).is_err(), "落地机=中转机 应拒绝");
        r.server_id = 0;
        assert!(validate_relay(&r).is_ok());
        r.exit_listen_port = "".into();
        assert!(validate_relay(&r).is_err(), "隧道必须有出口端口");
        r.exit_server_id = 0;
        r.balance = "random".into();
        assert!(validate_relay(&r).is_err(), "未知负载策略应拒绝");
        r.balance = "".into();
        r.transport = "grpc".into();
        assert!(validate_relay(&r).is_err(), "未知加密层应拒绝");
        r.transport = "ws".into();
        r.ws_path = "tun".into();
        assert!(validate_relay(&r).is_err(), "WS 路径应以 / 开头");
        assert!(validate_relay_targets(&[], "").is_err());
        assert!(
            validate_relay_targets(
                &[
                    RelayTarget { host: "a".into(), port: 1, ..Default::default() },
                    RelayTarget { host: "b".into(), port: 2, ..Default::default() }
                ],
                "",
            )
            .is_err(),
            "多目标必须选负载策略"
        );
    }

    mod switch_tests {
        use super::*;
        use crate::db::{Db, Node, ProxyNode, ProxySecret};
        use std::sync::{Arc, Mutex};

        /// upsert 桩是进程级 OnceLock，并行测试会互相踩：涉桩测试全部串行。
        /// tokio Mutex：测试体内持锁跨 await（await_holding_lock 已 deny），
        /// 跨测试争锁时异步等待而非阻塞线程。
        static STUB_GUARD: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());

        #[allow(clippy::type_complexity)] // 测试助手的双 Mutex 嵌套是桩的形态
        fn stub_upsert() -> (crate::dns::UpsertStub, Arc<Mutex<Vec<(String, String)>>>) {
            let calls: Arc<Mutex<Vec<(String, String)>>> = Arc::new(Mutex::new(Vec::new()));
            let c2 = calls.clone();
            let stub: crate::dns::UpsertStub = Arc::new(move |_tok, fqdn, ip| {
                c2.lock().unwrap().push((fqdn.to_owned(), ip.to_owned()));
                Ok(())
            });
            (stub, calls)
        }

        fn app_pair() -> Shared {
            std::sync::Arc::new(crate::App::for_test(Db::open(":memory:").unwrap()))
        }

        fn mk_machine(shared: &Shared, name: &str, ipv4: &str) -> i64 {
            // token 全局唯一；ipv4 是 agent 上报字段，创建不落库，走 save_facts。
            let id = shared
                .db
                .create_node(&Node { name: name.into(), ..Default::default() }, &format!("tok-{name}"))
                .unwrap();
            shared
                .db
                .save_facts(id, &serde_json::json!({ "ipv4": ipv4, "hostname": name }), ipv4, "")
                .unwrap();
            id
        }

        fn mk_node(shared: &Shared, server_id: i64, port: i64, dns: &str) -> i64 {
            shared
                .db
                .create_proxy_node(
                    &ProxyNode {
                        name: "主线".into(),
                        protocol: "vless-reality".into(),
                        listen_port: port,
                        enabled: true,
                        server_id,
                        dns_name: dns.into(),
                        ..Default::default()
                    },
                    &ProxySecret {
                        tls_mode: "reality".into(),
                        private_key: "priv".into(),
                        public_key: "pub".into(),
                        short_id: "abcd1234".into(),
                        ..Default::default()
                    },
                    "11111111-1111-1111-1111-111111111111",
                )
                .unwrap()
        }

        /// 在线 agent 桩：core.status 报已装 1.14.2；fail_apply=true 时
        /// apply_config 以 JSON-RPC error 应答（call_agent 顶出 Shown）。
        async fn spawn_agent(shared: &Shared, server_id: i64, fail_apply: bool) {
            let (tx, mut rx) = tokio::sync::mpsc::channel::<String>(16);
            shared.agents.write().unwrap().insert(server_id, crate::agent_ws::Agent::test_stub(tx));
            let responder = shared.clone();
            tokio::spawn(async move {
                while let Some(frame) = rx.recv().await {
                    let v: serde_json::Value = serde_json::from_str(&frame).unwrap();
                    let id = v["id"].as_str().unwrap().to_owned();
                    let slot = responder.proxy_rpcs.lock().unwrap().remove(&id).unwrap();
                    if v["method"].as_str() == Some("proxy.core.status") {
                        let _ = slot.send(Ok(serde_json::json!({ "installed_version": "1.14.2" })));
                        continue;
                    }
                    if fail_apply {
                        let _ = slot.send(Err("agent 写盘失败".into()));
                        continue;
                    }
                    let _ = slot.send(Ok(serde_json::json!({ "ok": true })));
                }
            });
        }

        fn take_port() -> i64 {
            let l = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
            l.local_addr().unwrap().port() as i64
        }

        #[test]
        fn mirrored_node_renders_same_identity_on_both_machines() {
            let shared = app_pair();
            let a = mk_machine(&shared, "源机", "127.0.0.1");
            let b = mk_machine(&shared, "备机", "127.0.0.1");
            let nid = mk_node(&shared, a, 24443, "");
            shared.db.add_proxy_node_mirror(nid, b).unwrap();
            let n = shared.db.proxy_node(nid).unwrap().unwrap();
            // 新建即指向原机（不变量：dns_server_id 恒为某台真实机器）。
            assert_eq!(n.dns_server_id, a);
            assert_eq!(node_server_ids(&n), vec![a, b]);
            let (body_a, _) = render_for_server(&shared, a).unwrap().unwrap();
            let (body_b, _) = render_for_server(&shared, b).unwrap().unwrap();
            for body in [&body_a, &body_b] {
                assert!(body.contains("11111111-1111-1111-1111-111111111111"), "uuid 应同源: {body}");
                assert!(body.contains("abcd1234"), "short_id 应同源: {body}");
                assert!(body.contains("24443"), "端口应同源: {body}");
            }
            assert_eq!(body_a, body_b, "镜像机渲染应与原机完全一致");
        }

        #[tokio::test]
        async fn switch_flips_dns_only_after_port_is_up() {
            let _g = STUB_GUARD.lock().await;
            let (stub, calls) = stub_upsert();
            crate::dns::set_upsert_stub(Some(stub));
            // 起一个真监听当「目标机上 sing-box 的端口」，探测要真通过。
            let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
            let port = listener.local_addr().unwrap().port() as i64;
            tokio::spawn(async move { while let Ok((_s, _)) = listener.accept().await {} });

            let shared = app_pair();
            shared.db.set("cf_api_token", "tok").unwrap();
            let a = mk_machine(&shared, "源机", "127.0.0.1");
            let b = mk_machine(&shared, "备机", "127.0.0.1");
            let nid = mk_node(&shared, a, port, "node1.example.com");
            // 两台都在线：切过去、切回来都要能选。
            spawn_agent(&shared, b, false).await;
            spawn_agent(&shared, a, false).await;

            let v = switch_node(&shared, nid, b).await.unwrap();
            assert_eq!(v["ip"], "127.0.0.1");
            assert_eq!(v["server_name"], "备机");
            assert_eq!(
                *calls.lock().unwrap(),
                vec![("node1.example.com".to_owned(), "127.0.0.1".to_owned())]
            );
            let n = shared.db.proxy_node(nid).unwrap().unwrap();
            assert_eq!(n.dns_server_id, b);
            assert_eq!(n.dns_ip, "127.0.0.1");
            assert_eq!(node_server_ids(&n), vec![a, b], "老机器保留（随时切回）");

            // 切回：同接口反向，不再加镜像（已在集合），只翻 DNS。
            switch_node(&shared, nid, a).await.unwrap();
            assert_eq!(calls.lock().unwrap().len(), 2);
            assert_eq!(shared.db.proxy_node(nid).unwrap().unwrap().dns_server_id, a);
            crate::dns::set_upsert_stub(None);
        }

        #[tokio::test]
        async fn switch_refuses_when_target_port_taken_by_another_node() {
            let _g = STUB_GUARD.lock().await;
            let (stub, calls) = stub_upsert();
            crate::dns::set_upsert_stub(Some(stub));
            let shared = app_pair();
            shared.db.set("cf_api_token", "tok").unwrap();
            let a = mk_machine(&shared, "源机", "127.0.0.1");
            let b = mk_machine(&shared, "备机", "127.0.0.1");
            let nid = mk_node(&shared, a, 21580, "node1.example.com");
            mk_node(&shared, b, 21580, ""); // 目标机已有同端口的其他节点
            spawn_agent(&shared, b, false).await;

            let err = switch_node(&shared, nid, b).await.unwrap_err().to_string();
            assert!(err.contains("已被其他代理占用"), "{err}");
            assert!(calls.lock().unwrap().is_empty(), "失败不得翻 DNS");
            assert!(
                !node_server_ids(&shared.db.proxy_node(nid).unwrap().unwrap()).contains(&b),
                "冲突不加镜像"
            );
            crate::dns::set_upsert_stub(None);
        }

        #[tokio::test]
        async fn switch_apply_failure_keeps_dns_untouched() {
            let _g = STUB_GUARD.lock().await;
            let (stub, calls) = stub_upsert();
            crate::dns::set_upsert_stub(Some(stub));
            let shared = app_pair();
            shared.db.set("cf_api_token", "tok").unwrap();
            let a = mk_machine(&shared, "源机", "127.0.0.1");
            let b = mk_machine(&shared, "备机", "127.0.0.1");
            let nid = mk_node(&shared, a, 21581, "node1.example.com");
            spawn_agent(&shared, b, true).await; // apply 回错误包

            let err = switch_node(&shared, nid, b).await.unwrap_err().to_string();
            assert!(err.contains("写盘失败"), "{err}");
            assert!(calls.lock().unwrap().is_empty(), "DNS 永远最后翻");
            assert_eq!(shared.db.proxy_node(nid).unwrap().unwrap().dns_server_id, a, "指向不动");
            // 镜像保留（不回滚）：60s 心跳对账会继续补推，重试切换更快收敛。
            assert!(node_server_ids(&shared.db.proxy_node(nid).unwrap().unwrap()).contains(&b));
            crate::dns::set_upsert_stub(None);
        }

        #[tokio::test]
        async fn switch_probe_failure_keeps_dns_untouched() {
            let _g = STUB_GUARD.lock().await;
            let (stub, calls) = stub_upsert();
            crate::dns::set_upsert_stub(Some(stub));
            let closed = take_port(); // 绑一下拿到空闲端口后立刻弃用 → 探测必失败
            let shared = app_pair();
            shared.db.set("cf_api_token", "tok").unwrap();
            let a = mk_machine(&shared, "源机", "127.0.0.1");
            let b = mk_machine(&shared, "备机", "127.0.0.1");
            let nid = mk_node(&shared, a, closed, "node1.example.com");
            spawn_agent(&shared, b, false).await;

            let err = switch_node(&shared, nid, b).await.unwrap_err().to_string();
            assert!(err.contains("探测未就绪"), "{err}");
            assert!(calls.lock().unwrap().is_empty());
            assert_eq!(shared.db.proxy_node(nid).unwrap().unwrap().dns_server_id, a);
            crate::dns::set_upsert_stub(None);
        }

        #[tokio::test]
        async fn proxy_node_domain_follows_target_machine_ip() {
            let _g = STUB_GUARD.lock().await;
            let (stub, calls) = stub_upsert();
            crate::dns::set_upsert_stub(Some(stub));
            let shared = app_pair();
            shared.db.set("cf_api_token", "tok").unwrap();
            let m = shared
                .db
                .create_node(&Node { name: "主机".into(), ..Default::default() }, "tok-follow")
                .unwrap();
            shared
                .db
                .save_facts(m, &serde_json::json!({ "ipv4": "203.0.113.7" }), "203.0.113.7", "")
                .unwrap();
            let nid = mk_node(&shared, m, 21582, "node2.example.com");
            // 记账陈旧（机器换 IP / Cloudflare 被手改后的等价状态）→ 跟随。
            shared.db.update_proxy_dns_ip(nid, "203.0.113.6").unwrap();

            crate::dns::sync_proxy_node_domains(&shared).await;
            assert_eq!(
                *calls.lock().unwrap(),
                vec![("node2.example.com".to_owned(), "203.0.113.7".to_owned())]
            );
            assert_eq!(shared.db.proxy_node(nid).unwrap().unwrap().dns_ip, "203.0.113.7");

            // 记账已同步 → 再跑不重翻。
            crate::dns::sync_proxy_node_domains(&shared).await;
            assert_eq!(calls.lock().unwrap().len(), 1);
            crate::dns::set_upsert_stub(None);
        }
    }
}
