//! 回程线路探测（四期）：hub 调度 agent 的 ICMP traceroute，识别每跳归属
//! 线路，链路主线路连续两次与基线不同即记「线路变化」事件并通知。
//!
//! 与 Lite 的差异：线路规则内置（知名骨干网段，最保守的清单），不做远端
//! BGP 规则自动更新与被墙检测（后续增强）；调度直接走 call_agent RPC，不
//! 引入独立的事件协议。
//!
//! 链路主线路的判定：命中的大陆骨干 hop 里取多数；一跳都命中不了则链路
//! 线路为空串（未识别——目标或路径全在境外，或规则表没有该骨干段）。
//! 学习期：每条链路前 3 次探测只建基线不告警。

use anyhow::Result;
use axum::extract::{Path, State};
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use axum::Json;
use chrono::Utc;
use serde_json::{json, Value};
use std::collections::HashMap;
use tracing::warn;

use crate::api::{answer, bad, fail, invalidate_snapshot, Admin};
use crate::db::{RouteStatus, RouteTask};
use crate::{agent_ws, App, Shared};

/// 每跳探测的 RPC 超时：traceroute 最坏 25 跳 × 800ms ≈ 20s，放宽到 35s。
const PROBE_RPC_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(35);
/// 调度周期：探测是否到期的判断粒度。
const SCHEDULE_TICK: std::time::Duration = std::time::Duration::from_secs(60);
/// 学习期次数：前 3 次探测只建基线。
const LEARN_PROBES: i64 = 3;
/// 识别滑动窗口大小（次）。
const RECENT_WINDOW: usize = 10;
/// 「未识别」占比达到该百分比（%）即视为 ICMP 被限流，冻结切线判定。
const THROTTLE_PCT: i64 = 60;
/// 切线确认：连续这么多次识别到同一条新线路才记「线路变化」。
const LINE_CONFIRM: i64 = 2;

/// 内置回程线路规则：知名大陆骨干与城域/DNS 网段（保守清单，宁可「未识别」
/// 不错判）。kv `route_rules` 有 JSON（[{name, cidrs:[…]}]）时整体覆盖。
const BUILTIN_RULES: &[(&str, &[&str])] = &[
    ("电信163", &["202.97.0.0/16"]),
    ("电信CN2", &["59.43.0.0/16"]),
    ("电信城域", &["101.95.0.0/16", "202.96.0.0/16", "61.139.0.0/16", "222.66.0.0/16"]),
    ("移动CMI", &["223.120.0.0/15", "221.176.0.0/16"]),
    ("移动城域", &["120.196.0.0/16", "211.136.0.0/16"]),
    ("联通4837", &["219.158.0.0/16"]),
    ("联通城域", &["202.106.0.0/16", "210.21.0.0/16"]),
];

pub fn rules(app: &App) -> Vec<(String, Vec<(u32, u32)>)> {
    let parse = |name: &str, cidrs: &[&str]| -> (String, Vec<(u32, u32)>) {
        let mut ranges = Vec::new();
        for cidr in cidrs {
            if let Some((ip, prefix)) = cidr.split_once('/') {
                if let (Ok(ip), Ok(prefix)) = (ip.parse::<std::net::Ipv4Addr>(), prefix.parse::<u32>()) {
                    let base = u32::from(ip);
                    let width = 32u32.saturating_sub(prefix);
                    ranges.push((
                        base,
                        base.saturating_add(if width >= 32 { u32::MAX } else { (1u32 << width) - 1 }),
                    ));
                }
            }
        }
        (name.to_string(), ranges)
    };
    if let Some(custom) = app.db.get("route_rules").filter(|v| !v.is_empty()) {
        if let Ok(Value::Array(list)) = serde_json::from_str::<Value>(&custom) {
            let mut out = Vec::new();
            for entry in &list {
                let name = entry["name"].as_str().unwrap_or_default();
                let cidrs: Vec<&str> = entry["cidrs"]
                    .as_array()
                    .map(|a| a.iter().filter_map(Value::as_str).collect())
                    .unwrap_or_default();
                let (name, ranges) = parse(name, &cidrs);
                if !ranges.is_empty() {
                    out.push((name, ranges));
                }
            }
            if !out.is_empty() {
                return out;
            }
        }
    }
    BUILTIN_RULES.iter().map(|(n, c)| parse(n, c)).collect()
}

/// hop 的归属线路：命中哪条规则就是哪条，没命中为空。
pub fn line_of_ip(ip: &str, rules: &[(String, Vec<(u32, u32)>)]) -> String {
    let Ok(addr) = ip.parse::<std::net::Ipv4Addr>() else { return String::new() };
    let v = u32::from(addr);
    for (name, ranges) in rules {
        if ranges.iter().any(|(lo, hi)| v >= *lo && v <= *hi) {
            return name.clone();
        }
    }
    String::new()
}

/// 链路主线路：命中规则的 hop 里取多数；全未命中为空串。
pub fn line_of_hops(hops: &[Value], _rules: &[(String, Vec<(u32, u32)>)]) -> String {
    let mut counts: std::collections::HashMap<String, i64> = std::collections::HashMap::new();
    for hop in hops {
        let line = hop["line"].as_str().unwrap_or_default();
        if !line.is_empty() {
            *counts.entry(line.to_string()).or_insert(0) += 1;
        }
    }
    counts.into_iter().max_by_key(|(_, n)| *n).map(|(line, _)| line).unwrap_or_default()
}

/// 一次探测的完整处理：识别 → 落状态 → （学习期外）连续两次同线路 ≠ 基线
/// → 记事件 + 通知 + 基线跟随。
fn process(app: &App, task: &RouteTask, node_id: i64, hops: Vec<Value>, now: i64) -> Result<()> {
    let rules = rules(app);
    let hops: Vec<Value> = hops
        .into_iter()
        .map(|mut h| {
            if let Some(ip) = h["ip"].as_str() {
                let line = line_of_ip(ip, &rules);
                if !line.is_empty() {
                    h["line"] = json!(line);
                }
            }
            h
        })
        .collect();
    let line = line_of_hops(&hops, &rules);
    let prev = app.db.route_status(task.id, node_id)?;
    let probes = prev.as_ref().map(|r| r.probes).unwrap_or(0) + 1;
    let mut baseline = prev.as_ref().map(|r| r.baseline.clone()).unwrap_or_default();
    let mut streak = prev.as_ref().map(|r| r.streak).unwrap_or(0);
    let prev_recent: Vec<String> =
        prev.as_ref().and_then(|r| serde_json::from_str::<Vec<String>>(&r.recent).ok()).unwrap_or_default();

    // 限流判定：最近 10 次识别里「未识别」≥ 60% 视为 ICMP 被限流——识别不
    // 出线路的轮次不参与切线判定（streak 不增不清），防止「电信城域↔未识别」
    // 翻转刷线路变化事件。窗口先推入本次结果再统计。
    let mut recent: Vec<String> = prev_recent;
    recent.push(line.clone());
    if recent.len() > RECENT_WINDOW {
        recent.remove(0);
    }
    let unknown_ratio =
        recent.iter().filter(|l| l.is_empty()).count() as i64 * 100 / recent.len().max(1) as i64;
    let throttled = unknown_ratio >= THROTTLE_PCT;

    // 学习期：前几次只建立基线（首个非空识别）。
    if probes <= LEARN_PROBES {
        if baseline.is_empty() && !line.is_empty() {
            baseline = line.clone();
        }
    } else if throttled {
        // 限流中：识别不可信，streak 冻结（不增不清），line 仍如实记录。
    } else if !line.is_empty() && !baseline.is_empty() && line != baseline {
        streak += 1;
    } else {
        streak = 0;
    }
    app.db.save_route_status(&RouteStatus {
        task_id: task.id,
        node_id,
        hops: json!(hops).to_string(),
        line: line.clone(),
        baseline: baseline.clone(),
        probes,
        streak,
        recent: json!(recent).to_string(),
        probed_at: now,
    })?;

    // 连续 LINE_CONFIRM 次识别到同一条新线路 → 切线：记事件 + 通知 + 基线跟随。
    if streak >= LINE_CONFIRM && line != baseline && !line.is_empty() {
        app.db.add_route_event(task.id, node_id, &baseline, &line, now)?;
        let node =
            app.db.node(node_id).ok().flatten().map(|n| n.name).unwrap_or_else(|| format!("节点 {node_id}"));
        crate::notify::send(
            app,
            crate::notify::Note {
                event: "route_change",
                node: node.clone(),
                title: format!("🔀 {node} 回程线路变化（{}）", task.name),
                message: if baseline.is_empty() {
                    format!("{node} → {}：回程识别为 {line}。", task.target)
                } else {
                    format!("{node} → {}：{baseline} → {line}。", task.target)
                },
                ..Default::default()
            },
        );
        app.db.save_route_status(&RouteStatus {
            task_id: task.id,
            node_id,
            hops: json!(hops).to_string(),
            line: line.clone(),
            baseline: line,
            probes,
            streak: 0,
            recent: json!(recent).to_string(),
            probed_at: now,
        })?;
    }
    Ok(())
}

/// 调度循环：每分钟检查一遍，到期的 (任务, 节点) 逐个探测。探测串行执行：
/// 回程任务个位数，串行最坏几十秒，换来的简单性值得。
pub async fn watch(app: Shared) {
    let mut ticker = tokio::time::interval(SCHEDULE_TICK);
    ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    loop {
        ticker.tick().await;
        if let Err(e) = probe_due(&app, Utc::now().timestamp()).await {
            warn!("route probe sweep failed: {e:#}");
        }
    }
}

async fn probe_due(app: &App, now: i64) -> Result<()> {
    let online: std::collections::HashSet<i64> =
        app.agents.read().unwrap_or_else(|e| e.into_inner()).keys().copied().collect();
    for task in app.db.route_tasks()? {
        if !task.enabled {
            continue;
        }
        for node_id in &task.nodes {
            if !online.contains(node_id) {
                continue;
            }
            let probed_at = app.db.route_status(task.id, *node_id)?.map(|s| s.probed_at).unwrap_or(0);
            if now - probed_at < task.interval {
                continue;
            }
            match agent_ws::call_agent(
                app,
                *node_id,
                "route.probe",
                json!({ "target": task.target }),
                PROBE_RPC_TIMEOUT,
            )
            .await
            {
                Ok(result) => {
                    let hops = result["hops"].as_array().cloned().unwrap_or_default();
                    if let Err(e) = process(app, &task, *node_id, hops, Utc::now().timestamp()) {
                        warn!("route status update failed for node {node_id}: {e:#}");
                    }
                }
                Err(e) => warn!("route probe on node {node_id} failed: {e}"),
            }
        }
    }
    Ok(())
}

/// `GET /api/route/tasks`：任务列表 + 每指派节点的链路状态（节点名解析好）。
pub async fn tasks_list(_: Admin, State(app): State<Shared>) -> Response {
    match (|| -> Result<Value> {
        let nodes: HashMap<i64, String> = app.db.nodes()?.into_iter().map(|n| (n.id, n.name)).collect();
        let tasks: Vec<Value> = app
            .db
            .route_tasks()?
            .into_iter()
            .map(|t| {
                let statuses: Vec<Value> = t
                    .nodes
                    .iter()
                    .map(|node_id| {
                        let status = app.db.route_status(t.id, *node_id).ok().flatten();
                        json!({
                            "node_id": node_id,
                            "node": nodes.get(node_id).cloned().unwrap_or_else(|| format!("节点 {node_id}")),
                            "online": app.agents.read().unwrap_or_else(|e| e.into_inner()).contains_key(node_id),
                            "hops": status.as_ref().map(|s| serde_json::from_str::<Value>(&s.hops).unwrap_or(Value::Array(Vec::new()))).unwrap_or(Value::Array(Vec::new())),
                            "line": status.as_ref().map(|s| s.line.clone()).unwrap_or_default(),
                            "baseline": status.as_ref().map(|s| s.baseline.clone()).unwrap_or_default(),
                            "probes": status.as_ref().map(|s| s.probes).unwrap_or(0),
                            "probed_at": status.as_ref().map(|s| s.probed_at).unwrap_or(0),
                        })
                    })
                    .collect();
                json!({
                    "id": t.id, "name": t.name, "target": t.target,
                    "interval": t.interval, "enabled": t.enabled, "nodes": statuses,
                })
            })
            .collect();
        let events: Vec<Value> = app
            .db
            .route_events(50, 0)?
            .into_iter()
            .map(|(task_id, node_id, from, to, at)| {
                json!({
                    "task_id": task_id, "node_id": node_id,
                    "from": from, "to": to, "at": at,
                })
            })
            .collect();
        Ok(
            json!({ "tasks": tasks, "events": events, "rules": rules(&app).iter().map(|(n, r)| json!({"name": n, "count": r.len()})).collect::<Vec<_>>() }),
        )
    })() {
        Ok(v) => Json(v).into_response(),
        Err(e) => fail(e),
    }
}

/// `POST /api/route/tasks`：新建或更新（body 带 id 为更新）。校验目标为
/// IPv4（traceroute 的 raw ICMP 只支持 v4）。
pub async fn task_save(
    _: Admin,
    State(app): State<Shared>,
    body: Result<Json<Value>, axum::extract::rejection::JsonRejection>,
) -> Response {
    let Json(body) = match body {
        Ok(b) => b,
        Err(_) => return bad("请求格式不对"),
    };
    let name = body["name"].as_str().unwrap_or_default().trim();
    let target = body["target"].as_str().unwrap_or_default().trim();
    if name.is_empty() || target.is_empty() {
        return bad("请填写名称和目标");
    }
    if target.parse::<std::net::Ipv4Addr>().is_err() {
        return bad("目标要是 IPv4 地址，例如 223.5.5.5");
    }
    let interval = body["interval"].as_i64().unwrap_or(600);
    if !(60..=86_400).contains(&interval) {
        return bad("探测间隔要在 60 到 86400 秒之间");
    }
    let task = RouteTask {
        id: body["id"].as_i64().unwrap_or(0),
        name: name.to_string(),
        target: target.to_string(),
        interval,
        enabled: body["enabled"].as_bool().unwrap_or(true),
        sort: 0,
        nodes: body["nodes"]
            .as_array()
            .map(|a| a.iter().filter_map(Value::as_i64).collect())
            .unwrap_or_default(),
    };
    match app.db.save_route_task(&task) {
        Ok(id) => {
            invalidate_snapshot(&app);
            Json(json!({"ok": true, "id": id})).into_response()
        }
        Err(e) => fail(e),
    }
}

/// `DELETE /api/route/tasks/{id}`：任务连同状态与事件一并删除。
pub async fn task_delete(_: Admin, State(app): State<Shared>, Path(id): Path<i64>) -> Response {
    match app.db.delete_route_task(id) {
        Ok(()) => {
            invalidate_snapshot(&app);
            Json(json!({"ok": true})).into_response()
        }
        Err(e) => fail(e),
    }
}

/// `POST /api/route/tasks/{id}/probe`：立即探测一次（忽略间隔），返回各
/// 节点的识别结果。
pub async fn task_probe(_: Admin, State(app): State<Shared>, Path(id): Path<i64>) -> Response {
    let Some(task) = app.db.route_task(id).ok().flatten() else {
        return answer(StatusCode::NOT_FOUND, "任务不存在");
    };
    let online: Vec<i64> = app
        .agents
        .read()
        .unwrap_or_else(|e| e.into_inner())
        .keys()
        .copied()
        .filter(|id| task.nodes.contains(id))
        .collect();
    if online.is_empty() {
        return answer(StatusCode::BAD_REQUEST, "指派的节点都不在线");
    }
    let now = Utc::now().timestamp();
    let mut out = Vec::new();
    for node_id in online {
        let node =
            app.db.node(node_id).ok().flatten().map(|n| n.name).unwrap_or_else(|| format!("节点 {node_id}"));
        match agent_ws::call_agent(
            &app,
            node_id,
            "route.probe",
            json!({ "target": task.target }),
            PROBE_RPC_TIMEOUT,
        )
        .await
        {
            Ok(result) => {
                let hops = result["hops"].as_array().cloned().unwrap_or_default();
                if let Err(e) = process(&app, &task, node_id, hops.clone(), now) {
                    warn!("route status update failed for node {node_id}: {e:#}");
                }
                let status = app.db.route_status(task.id, node_id).ok().flatten();
                out.push(json!({
                    "node": node,
                    "line": status.as_ref().map(|s| s.line.clone()).unwrap_or_default(),
                    "baseline": status.as_ref().map(|s| s.baseline.clone()).unwrap_or_default(),
                }));
            }
            Err(e) => out.push(json!({ "node": node, "error": e.to_string() })),
        }
    }
    Json(json!({ "results": out })).into_response()
}

#[cfg(test)]
mod tests {
    use super::*;

    /// 内置规则：知名骨干段命中，非骨干为空。
    #[test]
    fn builtin_rules_recognize_major_backbones() {
        let app = crate::App::for_test(crate::db::Db::open(":memory:").unwrap());
        let rules = rules(&app);
        assert_eq!(line_of_ip("202.97.51.1", &rules), "电信163");
        assert_eq!(line_of_ip("59.43.100.9", &rules), "电信CN2");
        assert_eq!(line_of_ip("223.120.6.9", &rules), "移动CMI");
        assert_eq!(line_of_ip("221.176.1.1", &rules), "移动CMI");
        assert_eq!(line_of_ip("219.158.9.9", &rules), "联通4837");
        assert_eq!(line_of_ip("8.8.8.8", &rules), "", "境外段不识别");
        assert_eq!(line_of_ip("not-an-ip", &rules), "");
    }

    /// 链路主线路：命中的 hop 取多数；全未命中为空。
    #[test]
    fn line_of_hops_takes_the_majority_of_recognized_hops() {
        let app = crate::App::for_test(crate::db::Db::open(":memory:").unwrap());
        let rules = rules(&app);
        let hops = json!([
            {"ttl": 1, "ip": "8.8.8.8"},
            {"ttl": 2, "ip": "202.97.51.1", "line": "电信163"},
            {"ttl": 3, "ip": "202.97.51.2", "line": "电信163"},
            {"ttl": 4, "ip": "59.43.1.1", "line": "电信CN2"},
        ]);
        assert_eq!(line_of_hops(hops.as_array().unwrap(), &rules), "电信163");
        let empty = json!([{"ttl": 1, "ip": "8.8.8.8"}]);
        assert_eq!(line_of_hops(empty.as_array().unwrap(), &rules), "");
    }

    /// 限流判定：「未识别」占比 ≥60% 时冻结切线判定——即使中间出现一条与
    /// 基线不同的「识别」，也不记事件（限流窗口里识别结果不可信）。
    #[test]
    fn throttle_freezes_line_change_during_high_unknown_ratio() {
        let app = crate::App::for_test(crate::db::Db::open(":memory:").unwrap());
        let task = RouteTask {
            id: 1,
            name: "电信回程".into(),
            target: "222.66.151.1".into(),
            interval: 600,
            enabled: true,
            sort: 0,
            nodes: vec![1],
        };
        let hops = |ip: &str| json!([{"ttl": 1, "ip": ip}, {"ttl": 2, "ip": "202.97.51.1"}]);
        let hops_unknown = json!([{"ttl": 1, "ip": "1.2.3.4"}, {"ttl": 2, "ip": "10.255.255.1"}]);
        let now = 2_000_000;
        // 学习期先建立基线（电信163），随后 8 次全未识别（占比 8/10 ≥ 60%）。
        process(&app, &task, 1, serde_json::from_value(hops("202.97.51.1")).unwrap(), now).unwrap();
        for i in 1..=8 {
            process(
                &app,
                &task,
                1,
                serde_json::from_value(hops_unknown.clone()).unwrap(),
                now + i as i64 * 60,
            )
            .unwrap();
        }
        // 第 10 次识别为移动CMI（223.120.x）：窗口占比 8/10 限流中 → streak 冻结 → 不切线。
        process(&app, &task, 1, serde_json::from_value(hops("223.120.6.9")).unwrap(), now + 600).unwrap();
        process(&app, &task, 1, serde_json::from_value(hops("223.120.6.9")).unwrap(), now + 660).unwrap();
        assert_eq!(app.db.route_events(10, 0).unwrap().len(), 0, "限流窗口里不判切线");
        let status = app.db.route_status(1, 1).unwrap().unwrap();
        assert_eq!(status.baseline, "电信163", "基线不动");
    }

    /// 状态机：学习期（<3 次探测）不判切线；之后连续两次同一条新线路才切，
    /// 基线跟随。
    #[test]
    fn line_changes_need_two_consistent_probes_beyond_the_learning_phase() {
        let app = crate::App::for_test(crate::db::Db::open(":memory:").unwrap());
        let task = RouteTask {
            id: 1,
            name: "电信回程".into(),
            target: "222.66.151.1".into(),
            interval: 600,
            enabled: true,
            sort: 0,
            nodes: vec![1],
        };
        // hop 的线路由 process 按 IP 重新识别（识别以 IP 为准），所以用不同
        // 网段的 hop IP 表达不同线路：202.97.x=电信163、223.120.x=移动CMI。
        let hops = |ip: &str| {
            json!([
                {"ttl": 1, "ip": "1.2.3.4"},
                {"ttl": 2, "ip": ip},
            ])
        };
        let now = 1_000_000;
        // 学习期：线路来回跳也不产生事件。
        for (i, ip) in ["202.97.51.1", "223.120.6.9", "59.43.100.9"].iter().enumerate() {
            process(&app, &task, 1, serde_json::from_value(hops(ip)).unwrap(), now + i as i64 * 60).unwrap();
            assert_eq!(app.db.route_events(10, 0).unwrap().len(), 0, "学习期第 {} 次", i + 1);
        }
        // 第 4 次（probes=4 > 3）：与基线（学习期首个非空=电信163）不同但只有一次 → 未切。
        process(&app, &task, 1, serde_json::from_value(hops("223.120.6.9")).unwrap(), now + 300).unwrap();
        assert_eq!(app.db.route_events(10, 0).unwrap().len(), 0, "单次不一致只累积 streak");
        // 第 5 次仍是移动CMI → 连续两次 → 切线事件 + 基线跟随。
        process(&app, &task, 1, serde_json::from_value(hops("223.120.6.9")).unwrap(), now + 600).unwrap();
        let events = app.db.route_events(10, 0).unwrap();
        assert_eq!(events.len(), 1);
        assert_eq!(events[0].2, "电信163");
        assert_eq!(events[0].3, "移动CMI");
        let status = app.db.route_status(1, 1).unwrap().unwrap();
        assert_eq!(status.baseline, "移动CMI", "基线跟随新线路");
        assert_eq!(status.streak, 0);
    }
}
