//! 延迟探测告警（三期）：丢包率告警 + 延迟异常告警（自适应基线）。
//!
//! 每 60 秒评估全部 (监控节点, 探测任务) 组合的最近样本（样本来自
//! ping_record，丢包是 -1 行——二期起 agent 超时显式上报）：
//!
//! - 丢包：窗口 W（默认 15 分钟）内 -1 行占比 ≥ 阈值（默认 20%），连续
//!   CONFIRM 次评估都如此即告警；低于阈值连续 RECOVER 次即恢复。
//! - 延迟异常：基线 = 基线窗口 B（默认 60 分钟，剔除 -1）样本的中位数，
//!   样本不足 10 个视为学习期不评估；当前窗口 C（默认 5 分钟）中位数
//!   > max(基线 × 系数, 基线 + 底线)（默认 ×150% 且 +100ms）连续 CONFIRM
//!   > 次即告警；回落连续 RECOVER 次即恢复。
//!
//! 状态在 ping_alert 表（key = "节点:任务:类型"），重启不丢；恢复的行保留
//! recovered_at 到次日，供概览卡统计「今日恢复」。告警走通知底座（事件
//! ping_loss / ping_latency，与其它事件一样在路由表里挑渠道）；没有渠道时
//! 状态照常推进、通知自然无处投递——概览卡的「当前告警」不依赖渠道配置。

use std::collections::HashMap;

use anyhow::Result;
use chrono::{Local, Utc};
use serde_json::json;
use tracing::warn;

use crate::App;

/// 评估周期：告警滞后样本变化的上界。
const SWEEP: tokio::time::Duration = tokio::time::Duration::from_secs(60);
/// 当前窗口（延迟异常的「现在」侧）：5 分钟。
const CURRENT_WINDOW: i64 = 300;
/// 基线学习的最少成功样本数：少于此数视为学习期，不评估延迟异常。
const BASELINE_SAMPLES: usize = 10;
/// 当前窗口的最少成功样本数：一两次探测不构成「异常」。
const CURRENT_SAMPLES: usize = 3;
/// 恢复比确认多要求的连续正常次数：阈值附近的抖动不该来回打铃。
const RECOVER_EXTRA: i64 = 1;

/// list_ping_tasks 工具用：公开中位数计算。
pub fn median_pub(samples: &mut [i64]) -> Option<i64> {
    median(samples)
}

pub fn enabled(app: &App) -> bool {
    app.db.get("ping_alert_enabled").as_deref() != Some("off")
}

fn number(app: &App, key: &str, min: i64, max: i64, default: i64) -> i64 {
    app.db.get(key).and_then(|v| v.parse().ok()).filter(|n| (min..=max).contains(n)).unwrap_or(default)
}

struct Config {
    loss_pct: i64,
    loss_window: i64,
    latency_window: i64,
    factor_pct: i64,
    floor_ms: i64,
    confirm: i64,
    recover: i64,
}

fn config(app: &App) -> Config {
    let loss_window_min = number(app, "ping_alert_loss_window_min", 1, 60, 15);
    let latency_window_min = number(app, "ping_alert_latency_window_min", 5, 360, 60);
    let confirm = number(app, "ping_alert_confirm", 1, 10, 2);
    Config {
        loss_pct: number(app, "ping_alert_loss_pct", 1, 100, 20),
        loss_window: loss_window_min * 60,
        latency_window: latency_window_min * 60,
        factor_pct: number(app, "ping_alert_factor_pct", 100, 500, 150),
        floor_ms: number(app, "ping_alert_floor_ms", 0, 1_000, 100),
        confirm,
        recover: confirm + RECOVER_EXTRA,
    }
}

/// 中位数：None 表示窗口里没有可用样本。
fn median(samples: &mut [i64]) -> Option<i64> {
    if samples.is_empty() {
        return None;
    }
    samples.sort_unstable();
    Some(match samples.len() {
        1 => samples[0],
        n if n % 2 == 1 => samples[n / 2],
        n => (samples[n / 2 - 1] + samples[n / 2]) / 2,
    })
}

/// 状态机的一步（纯函数，单测覆盖）：`active` 是当前是否有进行中的告警，
/// `bad` 是本轮评估是否越限，`(confirmed, normal_streak)` 随调用推进。
enum Step {
    Hold,
    Raise(String),
    Recover,
}

fn step(
    active: bool,
    bad: bool,
    detail: &str,
    confirmed: &mut i64,
    normal_streak: &mut i64,
    confirm: i64,
    recover: i64,
) -> Step {
    match (active, bad) {
        (false, true) => {
            *confirmed += 1;
            *normal_streak = 0;
            if *confirmed >= confirm {
                Step::Raise(detail.to_string())
            } else {
                Step::Hold
            }
        }
        (false, false) => {
            *confirmed = 0;
            Step::Hold
        }
        (true, true) => {
            *normal_streak = 0;
            Step::Hold
        }
        (true, false) => {
            *normal_streak += 1;
            if *normal_streak >= recover {
                *confirmed = 0;
                Step::Recover
            } else {
                Step::Hold
            }
        }
    }
}

struct Observation {
    bad: bool,
    detail: String,
}

/// 丢包评估：窗口内有样本才评估；agent 离线不产生样本，也就不评估——离线
/// 告警已覆盖该场景。
fn loss_observation(win: &[(i64, i64)], cfg: &Config) -> Option<Observation> {
    if win.is_empty() {
        return None;
    }
    let lost = win.iter().filter(|(_, l)| *l < 0).count() as i64;
    // 按实际回报数算丢包率：用「窗口 ÷ 间隔」的期望数会把刚建的任务放大成
    // 100%。
    let pct = 100 * lost / win.len() as i64;
    Some(Observation {
        bad: pct >= cfg.loss_pct,
        detail: format!("丢包 {pct}%（{lost}/{}），窗口 {} 分钟", win.len(), cfg.loss_window / 60),
    })
}

/// 延迟异常评估：基线（长窗）与当前（短窗）的成功样本都够数才评估。
fn latency_observation(win: &[(i64, i64)], cfg: &Config, now: i64) -> Option<Observation> {
    let baseline: Vec<i64> =
        win.iter().filter(|(ts, l)| *l >= 0 && *ts >= now - cfg.latency_window).map(|(_, l)| *l).collect();
    if baseline.len() < BASELINE_SAMPLES {
        return None;
    }
    let base = median(&mut baseline.clone())?;
    let current: Vec<i64> =
        win.iter().filter(|(ts, l)| *l >= 0 && *ts >= now - CURRENT_WINDOW).map(|(_, l)| *l).collect();
    if current.len() < CURRENT_SAMPLES {
        return None;
    }
    let cur = median(&mut current.clone())?;
    let threshold = (base * cfg.factor_pct / 100).max(base + cfg.floor_ms);
    Some(Observation {
        bad: cur > threshold,
        detail: format!(
            "当前 {} ms，基线 {} ms（近 {} 分钟中位数，阈值 {} ms）",
            cur,
            base,
            cfg.latency_window / 60,
            threshold
        ),
    })
}

/// 一轮评估：取全部样本，逐 (节点, 任务) 跑丢包与延迟两个状态机，落状态、
/// 发通知。
fn evaluate_round(app: &App, now: i64) -> Result<()> {
    let cfg = config(app);
    let pairs = app.db.ping_pairs()?;
    let since = now - cfg.latency_window.max(cfg.loss_window);
    let mut samples: HashMap<(i64, i64), Vec<(i64, i64)>> = HashMap::new();
    for (node_id, task_id, ts, latency) in app.db.ping_samples_since(since)? {
        samples.entry((node_id, task_id)).or_default().push((ts, latency));
    }
    let node_names: HashMap<i64, String> = app.db.nodes()?.into_iter().map(|n| (n.id, n.name)).collect();
    let task_names: HashMap<i64, String> =
        app.db.ping_tasks_all()?.into_iter().map(|t| (t.id, t.name)).collect();

    for (node_id, task_id, _interval) in pairs.clone() {
        let probe = samples.get(&(node_id, task_id));
        let node = node_names.get(&node_id).map(String::as_str).unwrap_or("未知节点");
        let task = task_names.get(&task_id).map(String::as_str).unwrap_or("探测任务");
        let win: Vec<(i64, i64)> = probe
            .map(|v| v.iter().copied().filter(|(ts, _)| *ts >= now - cfg.loss_window).collect())
            .unwrap_or_default();

        // ---- 丢包 ----
        if let Some(obs) = loss_observation(&win, &cfg) {
            apply(
                app,
                &key(node_id, task_id, "loss"),
                node_id,
                task_id,
                node,
                task,
                "ping_loss",
                "📉",
                "探测丢包",
                "丢包率已回落",
                &obs,
                now,
                &cfg,
            )?;
        }
        // ---- 延迟异常 ----
        if let Some(obs) = latency_observation(&win, &cfg, now) {
            apply(
                app,
                &key(node_id, task_id, "latency"),
                node_id,
                task_id,
                node,
                task,
                "ping_latency",
                "📈",
                "探测延迟异常",
                "探测延迟已回落",
                &obs,
                now,
                &cfg,
            )?;
        }
    }
    // 孤儿清扫：任务或节点被删后，其告警不再有样本可评估——「没有证据继续
    // 异常」即恢复，删除本身就是状态的终点。否则进行中的告警永远挂着。
    for (key, node_id, task_id) in app.db.ping_alert_active_keys()? {
        if !pairs.iter().any(|(n, t, _)| *n == node_id && *t == task_id) {
            app.db.ping_alert_recover(&key, now)?;
        }
    }
    Ok(())
}

fn key(node_id: i64, task_id: i64, kind: &str) -> String {
    format!("{node_id}:{task_id}:{kind}")
}

/// 跑一个告警 key 的一步状态机并落库。起报/恢复各发一条通知（恢复的
/// detail 为空）。
#[allow(clippy::too_many_arguments)]
fn apply(
    app: &App,
    key: &str,
    node_id: i64,
    task_id: i64,
    node: &str,
    task: &str,
    event: &'static str,
    mark: &str,
    what: &str,
    recovered_text: &str,
    obs: &Observation,
    now: i64,
    cfg: &Config,
) -> Result<()> {
    let prev = app.db.ping_alert(key)?;
    // 「进行中」= 起报过且未恢复。Hold 阶段的占位行（raised_at=0）不算——
    // 否则确认计数永远走不到起报。
    let active = prev.as_ref().is_some_and(|r| r.recovered_at.is_none() && r.raised_at > 0);
    let mut confirmed = prev.as_ref().map(|r| r.confirmed).unwrap_or(0);
    let mut normal_streak = prev.as_ref().map(|r| r.normal_streak).unwrap_or(0);
    let outcome =
        step(active, obs.bad, &obs.detail, &mut confirmed, &mut normal_streak, cfg.confirm, cfg.recover);
    match outcome {
        Step::Hold => {
            app.db.ping_alert_touch(
                key,
                node_id,
                task_id,
                event.trim_end_matches("ping_"),
                confirmed,
                normal_streak,
                now,
            )?;
        }
        Step::Raise(detail) => {
            app.db.ping_alert_raise(key, node_id, task_id, event.trim_end_matches("ping_"), &detail, now)?;
            crate::notify::send(
                app,
                crate::notify::Note {
                    event,
                    node: node.to_string(),
                    title: format!("{mark} {node} {what}（{task}）"),
                    message: format!("{node} → {task}：{detail}。"),
                    ..Default::default()
                },
            );
        }
        Step::Recover => {
            app.db.ping_alert_recover(key, now)?;
            crate::notify::send(
                app,
                crate::notify::Note {
                    event,
                    node: node.to_string(),
                    title: format!("🟢 {node} {recovered_text}（{task}）"),
                    message: format!("{node} → {task}：{recovered_text}。"),
                    ..Default::default()
                },
            );
        }
    }
    Ok(())
}

/// 概览的监测告警概览：进行中的丢包/延迟告警明细与今日恢复数。
pub fn overview(app: &App) -> Result<serde_json::Value> {
    let active = app.db.ping_alert_active()?;
    let midnight = Local::now()
        .date_naive()
        .and_hms_opt(0, 0, 0)
        .unwrap()
        .and_local_timezone(Local)
        .single()
        .map(|t| t.timestamp())
        .unwrap_or(0);
    let recovered_today = app.db.ping_alert_recovered_since(midnight)?;
    Ok(json!({ "active": active, "recovered_today": recovered_today }))
}

pub async fn watch(app: crate::Shared) {
    let mut ticker = tokio::time::interval(SWEEP);
    ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    loop {
        ticker.tick().await;
        if !enabled(&app) {
            continue;
        }
        match tokio::task::block_in_place(|| evaluate_round(&app, Utc::now().timestamp())) {
            Ok(()) => {}
            Err(e) => warn!("ping alert sweep failed: {e:#}"),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// 状态机：两次确认起报、恢复要多一次正常、期间抖动清零。
    #[test]
    fn the_state_machine_confirms_then_recovers() {
        let (mut c, mut n) = (0, 0);
        assert!(matches!(step(false, true, "d", &mut c, &mut n, 2, 3), Step::Hold), "一次越限不起报");
        assert_eq!(c, 1);
        assert!(matches!(step(false, true, "d", &mut c, &mut n, 2, 3), Step::Raise(d) if d == "d"));
        // 已起报后继续越限保持，恢复正常一次不打铃。
        assert!(matches!(step(true, true, "d", &mut c, &mut n, 2, 3), Step::Hold));
        assert!(matches!(step(true, false, "", &mut c, &mut n, 2, 3), Step::Hold));
        assert!(matches!(step(true, true, "d", &mut c, &mut n, 2, 3), Step::Hold), "抖动清零恢复计数");
        assert!(matches!(step(true, false, "", &mut c, &mut n, 2, 3), Step::Hold));
        assert!(matches!(step(true, false, "", &mut c, &mut n, 2, 3), Step::Hold));
        assert!(matches!(step(true, false, "", &mut c, &mut n, 2, 3), Step::Recover), "连续三次正常才恢复");
        // 恢复后重新计数。
        assert!(matches!(step(false, true, "d", &mut c, &mut n, 2, 3), Step::Hold));
        assert_eq!(c, 1);
    }

    /// 延迟评估：学习期（基线样本不足）不评估；超阈值才算异常。
    #[test]
    fn latency_observation_needs_enough_samples() {
        let cfg = Config {
            loss_pct: 20,
            loss_window: 900,
            latency_window: 3_600,
            factor_pct: 150,
            floor_ms: 100,
            confirm: 2,
            recover: 3,
        };
        let now = 10_000_000;
        let win = |pairs: Vec<(i64, i64)>| pairs;
        // 基线 50ms × 20 个，当前 60ms：远低于 150% 阈值。
        let mut pairs: Vec<(i64, i64)> = (0..20).map(|i| (now - 600 - i * 60, 50)).collect();
        pairs.extend((0..3).map(|i| (now - 60 - i * 30, 60)));
        let obs = latency_observation(&win(pairs), &cfg, now).unwrap();
        assert!(!obs.bad);
        // 当前 200ms：超过 max(75, 150)。
        let mut pairs: Vec<(i64, i64)> = (0..20).map(|i| (now - 600 - i * 60, 50)).collect();
        pairs.extend((0..3).map(|i| (now - 60 - i * 30, 200)));
        assert!(latency_observation(&win(pairs), &cfg, now).unwrap().bad);
        // 学习期：基线只有 3 个样本 → None。
        let pairs: Vec<(i64, i64)> = (0..3).map(|i| (now - 600 - i * 60, 50)).collect();
        assert!(latency_observation(&win(pairs), &cfg, now).is_none());
    }

    /// 丢包评估：按实际回报数算比例；无样本不评估。
    #[test]
    fn loss_observation_rates_by_reported() {
        let cfg = Config {
            loss_pct: 20,
            loss_window: 900,
            latency_window: 3_600,
            factor_pct: 150,
            floor_ms: 100,
            confirm: 2,
            recover: 3,
        };
        let now = 10_000_000;
        let pairs: Vec<(i64, i64)> =
            (0..10).map(|i| (now - 60 - i * 60, if i % 2 == 0 { -1 } else { 40 })).collect();
        let obs = loss_observation(&pairs, &cfg).unwrap();
        assert!(obs.bad, "50% 丢包 ≥ 20%");
        assert!(obs.detail.contains("50%"));
        assert!(loss_observation(&[], &cfg).is_none(), "无样本不评估");
    }
}
