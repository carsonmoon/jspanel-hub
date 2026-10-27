//! 中转规则诊断：按需的多发 TCP 探测，聚合平均延迟与丢包率并分级。
//!
//! 健康检查（后台周期探测/状态机/自动摘除/告警）已按用户拍板整体移除，
//! 诊断是纯检测——只出报告，不回写任何状态。转发是否真的可用以 realm
//! 运行状态与实际流量为准。
//!
//! 视角原则：普通规则从中转机拨目标；加密隧道规则 = 入口机拨出口监听 +
//! 出口机拨落地目标。纯 UDP 目标不做 TCP 探测（nc -z 同款局限），由调用
//! 方拒绝。

use std::time::{Duration, Instant};

use serde_json::json;

/// 单目标 TCP connect 超时。
const PROBE_TIMEOUT_MS: u64 = 3000;

// ---- 自动故障摘除（对标 xwPF xwFailover 的轻量复刻，grilling Q1）----

const FAILOVER_INTERVAL_SECS: u64 = 30;
/// 连续失败多少轮标记 down（xwPF 同款：2）。
const FAILOVER_THRESHOLD: u32 = 2;
/// 标记 down 后多久允许恢复，防抖动（xwPF 同款：120s）。
const RECOVERY_COOLDOWN_SECS: i64 = 120;

/// 一轮探测后的状态裁决（纯函数）：返回 (新连败数, down 标记时间, 新状态)。
/// 恢复必须在线且离开 down 标记超过冷却期；up 侧连败清零。
fn failover_decide(
    state_now: &str,
    fails: u32,
    ok: bool,
    down_at: i64,
    now: i64,
) -> (u32, i64, Option<&'static str>) {
    match ok {
        true => {
            if state_now == "down" && now - down_at >= RECOVERY_COOLDOWN_SECS {
                (0, down_at, Some("up"))
            } else {
                (0, down_at, None)
            }
        }
        false => {
            let fails = fails + 1;
            if fails >= FAILOVER_THRESHOLD && state_now != "down" {
                (fails, now, Some("down"))
            } else {
                (fails, down_at, None)
            }
        }
    }
}

/// 周期任务：对「多目标 + 已选负载策略」的启用规则探测落地目标，连续失败
/// 标 down（渲染侧 effective_targets 剔除、realm 重推即生效），恢复带冷却。
/// 只覆盖多目标规则——单目标摘了就断服，没有摘除意义。
pub async fn failover_watch(app: crate::Shared) {
    loop {
        tokio::time::sleep(Duration::from_secs(FAILOVER_INTERVAL_SECS)).await;
        if let Err(e) = failover_tick(&app).await {
            eprintln!("[relay-health] failover tick: {e:#}");
        }
    }
}

async fn failover_tick(app: &crate::Shared) -> anyhow::Result<()> {
    let rules = app.db.relay_rules()?;
    let all_targets = app.db.relay_targets()?;
    let now = chrono::Utc::now().timestamp();
    let mut touched: std::collections::BTreeSet<i64> = Default::default();
    let mut transitions: Vec<String> = Vec::new();
    let mut seen: std::collections::HashSet<(i64, String, i64)> = Default::default();

    for r in rules.iter().filter(|r| r.enabled && !r.balance.is_empty()) {
        let targets: Vec<_> =
            all_targets.iter().filter(|t| t.rule_id == r.id && t.enabled).cloned().collect();
        if targets.len() < 2 {
            continue;
        }
        let addrs: Vec<String> = targets.iter().map(|t| format!("{}:{}", t.host, t.port)).collect();
        // 探测机离线：拿不到结果就不动状态（宁可不摘，不误摘）。
        let Some(probes) = probe_addrs_multi(app, r.server_id, &addrs, 1, 0).await else {
            continue;
        };
        for (t, probe) in targets.iter().zip(probes) {
            let Some(p) = probe else { continue };
            let key = (r.id, t.host.clone(), t.port);
            seen.insert(key.clone());
            let (prev_fails, prev_down_at) = failover_fails_map().get(&key).copied().unwrap_or((0, 0));
            let (fails, down_at, decision) = failover_decide(&t.state, prev_fails, p.ok, prev_down_at, now);
            failover_fails_map().insert(key, (fails, down_at));
            if let Some(state) = decision {
                app.db.update_relay_target_state(t.id, state)?;
                touched.insert(r.server_id);
                if r.exit_server_id != r.server_id {
                    touched.insert(r.exit_server_id);
                }
                transitions.push(match state {
                    "down" => format!(
                        "「{}」出口 {}:{} 连续 {fails} 轮探测失败，已从负载组摘除",
                        r.name, t.host, t.port
                    ),
                    _ => format!("「{}」出口 {}:{} 恢复，重新加入负载组", r.name, t.host, t.port),
                });
            }
        }
    }
    // 键清理：本轮没见到的（规则删了/目标下线）不再占内存。
    failover_fails_map().retain(|k, _| seen.contains(k));
    // 状态有变化的机器重推配置（realm 渲染剔除 down 目标）。
    for server_id in &touched {
        crate::proxy::reconcile_relay_push(app, *server_id)?;
    }
    if !transitions.is_empty() {
        crate::proxy::notify_throttled(app, "relay_failover", "出口目标健康切换", transitions.join("；"));
    }
    Ok(())
}

/// 判挂状态表：`(规则 id, 域名, 主入口 node) → (连续失败数, 首败时刻)`。
#[allow(clippy::type_complexity)] // 复合键值是判挂状态的既定形态
fn failover_fails_map(
) -> std::sync::MutexGuard<'static, std::collections::HashMap<(i64, String, i64), (u32, i64)>> {
    use std::sync::OnceLock;
    #[allow(clippy::type_complexity)]
    static M: OnceLock<std::sync::Mutex<std::collections::HashMap<(i64, String, i64), (u32, i64)>>> =
        OnceLock::new();
    M.get_or_init(std::sync::Mutex::default).lock().unwrap()
}

// ---- 入口故障转移（grilling 二期）：双确认判挂 → DNS 翻转到备用入口 ----

const ENTRY_INTERVAL_SECS: u64 = 30;
const ENTRY_THRESHOLD: u32 = 2;
const ENTRY_RECOVERY_COOLDOWN_SECS: i64 = 120;

#[derive(Clone, Default)]
struct EntryState {
    /// 连续双确认失败的轮数。
    fails: u32,
    /// 是否已翻转到备用入口。
    flipped: bool,
    /// 翻转时刻（回切冷却用）。
    flipped_at: i64,
    /// 当前生效的入口机（主 = rule.server_id，或某台备用）。
    current: i64,
}

fn entry_states() -> std::sync::MutexGuard<'static, std::collections::HashMap<i64, EntryState>> {
    use std::sync::OnceLock;
    static M: OnceLock<std::sync::Mutex<std::collections::HashMap<i64, EntryState>>> = OnceLock::new();
    M.get_or_init(std::sync::Mutex::default).lock().unwrap()
}

/// 周期任务：对配了备用入口机的启用规则做双确认判挂（主入口 agent 掉线且
/// hub 直连监听端口失败，两者同时成立才算挂），翻转主入口绑定的域名到
/// 备用机 IP；主入口恢复（agent 在线 + 端口可达）并过冷却期后回切。
pub async fn entry_failover_watch(app: crate::Shared) {
    loop {
        tokio::time::sleep(Duration::from_secs(ENTRY_INTERVAL_SECS)).await;
        if let Err(e) = entry_tick(&app).await {
            eprintln!("[relay-health] entry failover tick: {e:#}");
        }
    }
}

async fn entry_tick(app: &crate::Shared) -> anyhow::Result<()> {
    let rules = app.db.relay_rules()?;
    let now = chrono::Utc::now().timestamp();
    let mut seen: std::collections::HashSet<i64> = Default::default();
    for r in rules.iter().filter(|r| r.enabled && !crate::proxy::entry_backup_ids(r).is_empty()) {
        seen.insert(r.id);
        let backups = crate::proxy::entry_backup_ids(r);
        let (mut st, known) = entry_states().get(&r.id).cloned().map(|s| (s, true)).unwrap_or_default();
        if !known {
            st.current = r.server_id;
        }
        // 主入口健康 = agent 在线 且 监听端口可达（双确认，Q1 拍板）。
        let agent_online = app.agents.read().unwrap_or_else(|e| e.into_inner()).contains_key(&r.server_id);
        let primary_healthy = if agent_online { listen_reachable(app, r).await } else { false };
        // 恢复回切：当前在备用上、主入口恢复、过冷却期。
        if st.flipped && primary_healthy && now - st.flipped_at >= ENTRY_RECOVERY_COOLDOWN_SECS {
            crate::dns::unfollow(app, r.server_id).await;
            st = EntryState { fails: 0, flipped: false, flipped_at: now, current: r.server_id };
            entry_states().insert(r.id, st.clone());
            crate::proxy::notify_throttled(
                app,
                "entry_failover",
                "入口已回切",
                format!("「{}」主入口恢复，{} 已指回", r.name, r.server_id),
            );
            continue;
        }
        // 已翻转且主未恢复：不动作。
        if st.flipped {
            entry_states().insert(r.id, st);
            continue;
        }
        // 判挂：双确认连续 ENTRY_THRESHOLD 轮。
        st.fails = if primary_healthy { 0 } else { st.fails + 1 };
        if st.fails < ENTRY_THRESHOLD {
            entry_states().insert(r.id, st);
            continue;
        }
        // 翻转目标：第一台在线的备用入口机（守卫收在块内，不跨 await）。
        let backup = {
            let agents = app.agents.read().unwrap_or_else(|e| e.into_inner());
            backups.iter().copied().find(|b| agents.contains_key(b))
        };
        let Some(backup) = backup else {
            entry_states().insert(r.id, st);
            crate::proxy::notify_throttled(
                app,
                "entry_failover",
                "入口故障无备可用",
                format!("「{}」主入口挂了，但备用入口机都不在线", r.name),
            );
            continue;
        };
        let ip = node_dial_host(app, backup).await;
        match crate::dns::flip_a(app, r.server_id, &ip).await {
            Ok(()) => {
                st.flipped = true;
                st.flipped_at = now;
                st.current = backup;
                st.fails = 0;
                entry_states().insert(r.id, st.clone());
                crate::proxy::notify_throttled(
                    app,
                    "entry_failover",
                    "已切换备用入口",
                    format!("「{}」主入口双确认失联，域名已翻转到备用入口 {}（IP {ip}）", r.name, backup),
                );
            }
            Err(e) => {
                crate::proxy::notify_throttled(
                    app,
                    "entry_failover",
                    "备用入口切换失败",
                    format!("「{}」：{e:#}", r.name),
                );
            }
        }
    }
    entry_states().retain(|k, _| seen.contains(k));
    Ok(())
}

/// hub 直连「节点拨号地址:监听端口」，3 秒超时，通即为入口活着。
async fn listen_reachable(app: &crate::App, r: &crate::db::RelayRule) -> bool {
    let Some(port) =
        r.listen_port.split('-').next().unwrap_or("").trim().parse::<i64>().ok().filter(|p| *p > 0)
    else {
        return true; // 段/异常端口不做监听探测，按活着处理（不误切）
    };
    let host =
        if r.server_id == 0 { "127.0.0.1".to_string() } else { node_dial_host(app, r.server_id).await };
    if host.is_empty() {
        return false;
    }
    probe_local(&format!("{host}:{port}")).await
}

/// 节点的拨号地址（上报 IPv4 优先，回退连接 IP）；0 号返回空。
pub async fn node_dial_host(app: &crate::App, server_id: i64) -> String {
    if server_id == 0 {
        return String::new();
    }
    let Ok(Some(n)) = app.db.node(server_id) else { return String::new() };
    let host = if !n.ipv4.trim().is_empty() { n.ipv4.trim().to_owned() } else { n.ip.trim().to_owned() };
    host
}

/// 诊断强度（grilling 拍板）：每腿 10 次 TCP connect、间隔 200ms。
pub const DIAG_COUNT: u64 = 10;
pub const DIAG_INTERVAL_MS: u64 = 200;

/// 诊断用的单腿聚合结果：是否至少通一次、成功样本平均毫秒、丢包率、原始样本。
#[derive(Debug, Clone)]
pub struct DiagProbe {
    pub ok: bool,
    pub avg_ms: u64,
    pub loss_pct: f64,
    pub samples: Vec<Option<u64>>,
}

fn diag_from_samples(samples: Vec<Option<u64>>) -> DiagProbe {
    let ok_count = samples.iter().filter(|s| s.is_some()).count();
    DiagProbe {
        ok: ok_count > 0,
        avg_ms: if ok_count == 0 { 0 } else { samples.iter().flatten().sum::<u64>() / ok_count as u64 },
        loss_pct: 100.0 * (samples.len() - ok_count) as f64 / samples.len().max(1) as f64,
        samples,
    }
}

/// 连接质量分级：🚀优秀 <80ms 且零丢包；✅良好 <200ms 且丢包<5%；其余较差。
/// 不通（ok=false）不分级，返回空串。
pub fn grade_of(ok: bool, avg_ms: u64, loss_pct: f64) -> &'static str {
    if !ok {
        return "";
    }
    if avg_ms < 80 && loss_pct <= 0.0 {
        "excellent"
    } else if avg_ms < 200 && loss_pct < 5.0 {
        "good"
    } else {
        "poor"
    }
}

/// 一条诊断腿：从 from_server 拨号 addr。key 对应探测对象
/// （`t{target_id}` 落地目标 / `h{rule_id}` 加密隧道跳）。
pub struct DiagLeg {
    pub key: String,
    pub kind: &'static str,
    pub from_server: i64,
    pub addr: String,
    pub display_target: String,
}

/// 诊断腿组装：普通规则每个启用目标一腿（从中转机拨号）；加密隧道规则加
/// 入口→出口一腿（从入口机拨出口监听），落地目标腿改从出口侧拨号。
/// exit_dial_host 由调用方给（node_dial_host(exit)），空串且加密腿组装不出
/// 时跳过。纯 UDP 规则不进诊断（调用方拒绝），这里不校验。
pub fn diagnose_legs(
    rule: &crate::db::RelayRule,
    targets: &[crate::db::RelayTarget],
    exit_dial_host: &str,
    relay_dial_host: &str,
) -> Vec<DiagLeg> {
    let mut legs = Vec::new();
    // 监听腿（隧道实测 #2）：hub 直连中转监听端口。目标腿只证明「落地活着」，
    // 监听被覆盖/核心没跑时它照样绿灯——入口通不通由这条腿说话。
    let listen_port = rule.listen_port.split('-').next().unwrap_or("").trim();
    if let Ok(port) = listen_port.parse::<i64>() {
        if port > 0 && !relay_dial_host.trim().is_empty() {
            legs.push(DiagLeg {
                key: format!("l{}", rule.id),
                kind: "listen",
                from_server: 0,
                addr: format!("{}:{port}", relay_dial_host.trim()),
                display_target: format!("{}:{port}", relay_dial_host.trim()),
            });
        }
    }
    let encrypted = rule.exit_server_id > 0 && !rule.transport.is_empty();
    if encrypted && !exit_dial_host.trim().is_empty() {
        let port = rule.exit_listen_port.trim();
        if !port.is_empty() {
            legs.push(DiagLeg {
                key: format!("h{}", rule.id),
                kind: "hop",
                from_server: rule.server_id,
                addr: format!("{exit_dial_host}:{port}"),
                display_target: format!("{exit_dial_host}:{port}"),
            });
        }
    }
    let dial_side = if encrypted { rule.exit_server_id } else { rule.server_id };
    for t in targets.iter().filter(|t| t.enabled) {
        legs.push(DiagLeg {
            key: format!("t{}", t.id),
            kind: "target",
            from_server: dial_side,
            addr: format!("{}:{}", t.host, t.port),
            display_target: format!("{}:{}", t.host, t.port),
        });
    }
    legs
}

/// 多发探测（诊断）：本机直接循环 connect；远程一次 `relay.probe` RPC
/// （count/interval_ms，agent 侧聚合，老 agent 无 count 字段时按单发兼容解析）。
/// 返回与 addrs 等长；None = 探测机器离线。
pub async fn probe_addrs_multi(
    app: &crate::App,
    server_id: i64,
    addrs: &[String],
    count: u64,
    interval_ms: u64,
) -> Option<Vec<Option<DiagProbe>>> {
    if server_id == 0 {
        let mut out = Vec::new();
        for a in addrs {
            let mut samples = Vec::with_capacity(count as usize);
            for i in 0..count {
                if i > 0 && interval_ms > 0 {
                    tokio::time::sleep(Duration::from_millis(interval_ms)).await;
                }
                let started = Instant::now();
                let ok = probe_local(a).await;
                samples.push(ok.then(|| started.elapsed().as_millis() as u64));
            }
            out.push(Some(diag_from_samples(samples)));
        }
        return Some(out);
    }
    // 最坏情况兜底：每次探测都可能吃满超时。
    let budget = 15 + count * (interval_ms + PROBE_TIMEOUT_MS) / 1000;
    let v = crate::agent_ws::call_agent(
        app,
        server_id,
        "relay.probe",
        json!({ "targets": addrs, "timeout_ms": PROBE_TIMEOUT_MS, "count": count, "interval_ms": interval_ms }),
        Duration::from_secs(budget),
    )
    .await
    .ok()?;
    let results = v["results"].as_array()?;
    let mut out = Vec::new();
    for (i, addr) in addrs.iter().enumerate() {
        let hit =
            results.iter().find(|r| r["target"].as_str() == Some(addr.as_str())).or_else(|| results.get(i));
        out.push(hit.map(|r| {
            let samples: Vec<Option<u64>> =
                r["samples"].as_array().map(|a| a.iter().map(|s| s.as_u64()).collect()).unwrap_or_else(
                    || vec![r["ok"].as_bool().unwrap_or(false).then(|| r["ms"].as_u64()).flatten()],
                );
            diag_from_samples(samples)
        }));
    }
    Some(out)
}

/// 本机单目标 TCP 探测。
async fn probe_local(addr: &str) -> bool {
    matches!(
        tokio::time::timeout(Duration::from_millis(PROBE_TIMEOUT_MS), tokio::net::TcpStream::connect(addr))
            .await,
        Ok(Ok(_))
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    /// 状态机：连续 2 轮失败标记 down；恢复要在线且过冷却期；up 清零连败。
    #[test]
    fn failover_decide_follows_the_two_strikes_and_cooldown() {
        let now = 1_000_000;
        // 第 1 轮失败：未到阈值，不动。
        assert_eq!(failover_decide("up", 0, false, 0, now), (1, 0, None));
        // 第 2 轮失败：标记 down。
        assert_eq!(failover_decide("up", 1, false, 0, now), (2, now, Some("down")));
        // 已 down：继续失败不再重复标记。
        assert_eq!(failover_decide("down", 2, false, now, now + 30), (3, now, None));
        // 冷却期内恢复：不放行。
        assert_eq!(failover_decide("down", 0, true, now, now + 60), (0, now, None));
        // 冷却期后在线：恢复 up。
        assert_eq!(failover_decide("down", 0, true, now, now + RECOVERY_COOLDOWN_SECS), (0, now, Some("up")));
        // up 侧在线：连败清零、无动作。
        assert_eq!(failover_decide("up", 1, true, 0, now), (0, 0, None));
    }

    use crate::db::{RelayRule, RelayTarget};

    #[test]
    fn grading_follows_latency_and_loss_thresholds() {
        assert_eq!(grade_of(false, 0, 0.0), "", "不通不分级");
        assert_eq!(grade_of(true, 5, 0.0), "excellent", "参考图的 5ms/0% = 优秀");
        assert_eq!(grade_of(true, 79, 0.0), "excellent");
        assert_eq!(grade_of(true, 80, 0.0), "good", "80ms 压线归良好");
        assert_eq!(grade_of(true, 199, 4.9), "good");
        assert_eq!(grade_of(true, 50, 5.0), "poor", "丢包 5% 压线归较差");
        assert_eq!(grade_of(true, 300, 0.0), "poor", "高延迟无丢包也是较差");
    }

    #[test]
    fn diagnose_legs_cover_both_sides_of_a_tunnel_and_each_target() {
        let plain = RelayRule { id: 1, server_id: 2, name: "中转".into(), ..Default::default() };
        let targets = [
            RelayTarget { id: 11, host: "1.1.1.1".into(), port: 53, enabled: true, ..Default::default() },
            RelayTarget { id: 12, host: "8.8.8.8".into(), port: 53, enabled: false, ..Default::default() },
        ];
        let legs = diagnose_legs(&plain, &targets, "", "198.51.100.7");
        assert_eq!(legs.len(), 1, "普通规则只探启用目标，停用行不探");
        assert_eq!((legs[0].kind, legs[0].from_server, legs[0].key.as_str()), ("target", 2, "t11"));

        let tunnel = RelayRule {
            id: 3,
            server_id: 1,
            name: "隧道".into(),
            transport: "tls".into(),
            exit_server_id: 9,
            exit_listen_port: "20004".into(),
            ..Default::default()
        };
        let legs = diagnose_legs(&tunnel, &targets, "203.0.113.9", "198.51.100.7");
        assert_eq!(legs.len(), 2, "加密隧道 = 入口→出口 + 出口→目标");
        assert_eq!(
            (legs[0].kind, legs[0].from_server, legs[0].addr.as_str()),
            ("hop", 1, "203.0.113.9:20004"),
            "入口腿从入口机拨出口监听"
        );
        assert_eq!(
            (legs[1].kind, legs[1].from_server, legs[1].key.as_str()),
            ("target", 9, "t11"),
            "落地腿改从出口机拨"
        );
    }

    #[test]
    fn diag_summary_averages_successes_and_counts_loss() {
        let d = diag_from_samples(vec![Some(5), Some(7), None]);
        assert!(d.ok);
        assert_eq!(d.avg_ms, 6);
        assert!((d.loss_pct - 100.0 / 3.0).abs() < 0.01);
        let d = diag_from_samples(vec![None, None, None]);
        assert!(!d.ok, "全超时 = 不通");
        assert_eq!((d.avg_ms, d.loss_pct), (0, 100.0));
        let d = diag_from_samples(vec![Some(10)]);
        assert_eq!((d.ok, d.avg_ms, d.loss_pct), (true, 10, 0.0), "count=1 与旧版单发语义一致");
    }
}
