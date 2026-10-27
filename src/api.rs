//! The panel and public-status HTTP surface.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::time::Duration;

use axum::extract::rejection::JsonRejection;
use axum::extract::ws::{Message, Utf8Bytes, WebSocket, WebSocketUpgrade};
use axum::extract::{ConnectInfo, FromRequestParts, Path, Query, State};
use axum::http::request::Parts;
use axum::http::{header, HeaderMap, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::Json;
use chrono::{Local, NaiveDate, Utc};
use serde::Deserialize;
use serde_json::{json, Value};
use tracing::{debug, info, warn};

use crate::agent_ws::Agent;
use crate::auth::{
    authed, client_ip, current_session, hash_password, issue_session, issued_at, random_token, with_cookies,
};
use crate::db::{Db, Node, NodePatch, PingTask, ProxyNode, ProxyUser, SubUser, Traffic, TrafficPatch};
use crate::{agent_ws, proxy, App, Shared};

/// Present only on requests carrying a valid session. Handlers taking it cannot
/// be reached unauthenticated, so the check cannot be omitted.
pub struct Admin;

impl FromRequestParts<Shared> for Admin {
    type Rejection = Response;

    async fn from_request_parts(parts: &mut Parts, app: &Shared) -> Result<Self, Self::Rejection> {
        if authed(app, &parts.headers) {
            Ok(Admin)
        } else {
            Err(answer(StatusCode::UNAUTHORIZED, "登录已失效，请重新登录"))
        }
    }
}

/// Marks a response whose text was written for the reader; see [`plain_errors`].
#[derive(Clone)]
struct Written;

/// An error response carrying `text` as written. Every error the hub composes
/// is built here.
pub(crate) fn answer(status: StatusCode, text: impl Into<String>) -> Response {
    let mut response = (status, text.into()).into_response();
    response.extensions_mut().insert(Written);
    response
}

/// What a failure this hub cannot explain to the reader says instead.
pub(crate) const INTERNAL: &str = "hub 内部出错，详细原因见 hub 日志";

/// Answers an error: 400 with the outermost [`crate::Shown`] message in its
/// chain, or, without one, 500 with [`INTERNAL`]. The chain is logged in full
/// either way, the underlying cause of a shown message included.
pub(crate) fn fail(e: impl Into<anyhow::Error>) -> Response {
    let e = e.into();
    match e.downcast_ref::<crate::Shown>() {
        Some(shown) => {
            info!("request refused: {e:#}");
            answer(StatusCode::BAD_REQUEST, shown.0.clone())
        }
        None => {
            warn!("request failed: {e:#}");
            answer(StatusCode::INTERNAL_SERVER_ERROR, INTERNAL)
        }
    }
}

pub(crate) fn bad(message: &str) -> Response {
    answer(StatusCode::BAD_REQUEST, message)
}

fn no_such_node() -> Response {
    answer(StatusCode::NOT_FOUND, "节点不存在，可能已被删除")
}

/// The last step of every response. An error the hub composed passes as it is;
/// any other -- an extractor's rejection, the body limit's 413, a bare status --
/// would carry axum's English wording or nothing, and is given a fixed text for
/// its status instead.
pub async fn plain_errors(response: Response) -> Response {
    let status = response.status();
    if !(status.is_client_error() || status.is_server_error())
        || response.extensions().get::<Written>().is_some()
    {
        return response;
    }
    let text = match status {
        StatusCode::UNAUTHORIZED => "登录已失效，请重新登录",
        StatusCode::NOT_FOUND => "请求的内容不存在",
        StatusCode::PAYLOAD_TOO_LARGE => "提交的内容过大",
        s if s.is_server_error() => INTERNAL,
        _ => "请求格式不对",
    };
    // Only the body is replaced: a 405 keeps its `Allow`, for one.
    let (mut parts, _) = response.into_parts();
    parts.headers.remove(header::CONTENT_LENGTH);
    parts.headers.insert(header::CONTENT_TYPE, header::HeaderValue::from_static("text/plain; charset=utf-8"));
    Response::from_parts(parts, text.into())
}

// ---- read paths, shared between the panel and the public page ----

/// Everything a report may expose under `metrics`: the agent contract minus the
/// raw kernel counters, which are a wire-protocol detail disclosing a machine's
/// entire lifetime traffic, plus the four traffic figures `node_view` fills in.
/// The panel additionally sees `iface`.
pub(crate) const PUBLIC_METRICS: [&str; 18] = [
    "uptime",
    "cpu",
    "load",
    "mem_total",
    "mem_used",
    "swap_total",
    "swap_used",
    "disk_total",
    "disk_used",
    "net_rx",
    "net_tx",
    "tcp",
    "udp",
    "procs",
    "total_rx",
    "total_tx",
    "month_rx",
    "month_tx",
];

/// The addresses the panel shows for a node, each with where it comes from: at
/// most one per family, v4 first, the one the machine is reached by. The agent
/// reports its interfaces; `ip` is where its connection arrived from, in dotted
/// form for IPv4.
///
/// Per family an address set by hand comes first, then a public one on the
/// interface. Failing both, where the interface holds only a private address of
/// the family the connection used -- NAT, or a proxy in front -- the
/// connection's public address, its exit, stands in. An exit in a family the
/// interface does not hold is a translator such as NAT64 or WARP and is left
/// out.
///
/// Private addresses appear only when nothing public is known, as where hub and
/// node share a network and they are all there is. `ip` alone is the fallback
/// for an agent reporting no interface.
fn addresses<'a>(
    ip: &'a str,
    (ipv4, ipv6): (&'a str, &'a str),
    (pin4, pin6): (&'a str, &'a str),
) -> Vec<(&'a str, &'static str)> {
    let public =
        |a: &str, v6: bool| a.parse::<IpAddr>().is_ok_and(|a| a.is_ipv6() == v6 && agent_ws::public(a));
    let family = |pin: &'a str, held: &'a str, v6: bool| {
        if !pin.is_empty() {
            Some((pin, "manual"))
        } else if public(held, v6) {
            Some((held, "interface"))
        } else if !held.is_empty() && public(ip, v6) {
            Some((ip, "exit"))
        } else {
            None
        }
    };
    let shown: Vec<_> = [family(pin4, ipv4, false), family(pin6, ipv6, true)].into_iter().flatten().collect();
    if !shown.is_empty() {
        return shown;
    }
    let held: Vec<_> = [ipv4, ipv6].into_iter().filter(|a| !a.is_empty()).map(|a| (a, "interface")).collect();
    if !held.is_empty() {
        return held;
    }
    [ip].into_iter().filter(|a| !a.is_empty()).map(|a| (a, "connection")).collect()
}

/// The hub machine's own hostname, read once. A monitor node whose reported
/// hostname equals it is the same machine -- the panel box itself -- and gets
/// the `local` mark the protocol server picker renders as 「主」. Empty (file
/// unreadable) marks nothing; the badge then simply never renders.
fn hub_hostname() -> &'static str {
    static HOST: std::sync::OnceLock<String> = std::sync::OnceLock::new();
    HOST.get_or_init(|| {
        std::fs::read_to_string("/etc/hostname").map(|s| s.trim().to_string()).unwrap_or_default()
    })
}

/// One node as the UI consumes it: stored config, live metrics and the hub's
/// accumulated traffic in a single object.
fn node_view(node: &Node, current: Option<&Agent>, traffic: &Traffic, full: bool, today: NaiveDate) -> Value {
    // The three capacities arrive twice: once in `Facts`, sent at the handshake,
    // and again in every `Metrics`. The stored figure follows the reports a
    // minute at a time and as the session ends, so it lags a disk mounted while
    // the agent runs -- the agent re-reads its mount table every sample so that
    // it appears -- by up to a minute. Using the report while a node is connected
    // keeps every consumer of this view on one number: the card reads the live
    // metrics and the detail page reads these, and they previously showed the
    // same machine two different capacities. Offline, the stored figure is the
    // last one reported. No floor is applied: a host whose swap has just been
    // disabled reports zero and means it. A node connected but not yet reporting
    // holds `Null`, where `get` returns nothing and the stored figure stands.
    let live = |key: &str, stored: i64| {
        current.and_then(|a| a.metrics.get(key).and_then(serde_json::Value::as_i64)).unwrap_or(stored)
    };
    let mut view = json!({
        "id": node.id,
        "name": node.name,
        // A country rather than an address: it indicates which region a node sits
        // in, which is what a status page conveys, without locating it. The
        // address it was derived from remains behind the panel.
        "country": if node.country_pin.is_empty() { &node.country } else { &node.country_pin },
        // Named by the operator for the status page to divide the list by, so
        // public like the node's name. Empty is ungrouped.
        "group": node.group,
        "sort": node.sort,
        "public": node.public,
        "online": current.is_some(),
        // The live entry while connected, the stored one afterwards. Zero means
        // connected but not yet reporting, which is not a timestamp, so it falls
        // back to the stored value and "offline since" survives the gap.
        "last_seen": current.map(|a| a.last_seen).filter(|t| *t > 0).unwrap_or(node.last_seen),
        "metrics": current.map(|a| a.metrics.clone()).unwrap_or(Value::Null),
        "os": node.os,
        "kernel": node.kernel,
        "arch": node.arch,
        "virt": node.virt,
        "cpu_name": node.cpu_name,
        "cpu_cores": node.cpu_cores,
        "mem_total": live("mem_total", node.mem_total),
        "swap_total": live("swap_total", node.swap_total),
        "disk_total": live("disk_total", node.disk_total),
        "agent_version": node.agent_version,
        "price": node.price,
        "currency": node.currency,
        "billing_cycle": node.billing_cycle,
        "expires_at": node.expires_at,
        // Counted on the hub's calendar, the one renewal follows. A page counting
        // on the visitor's clock would, with the hub on UTC and the visitor on
        // UTC+8, show every online node expired for eight hours each cycle
        // before the hub rolls its date forward.
        "expires_in": node.expires_at.as_deref().and_then(|d| d.parse::<NaiveDate>().ok()).map(|d| (d - today).num_days()),
        "traffic_limit": node.traffic_limit,
        "traffic_mode": node.traffic_mode,
        "traffic_reset_day": node.traffic_reset_day,
        "total_rx": traffic.total_rx,
        "total_tx": traffic.total_tx,
        "month_rx": traffic.month_rx,
        "month_tx": traffic.month_tx,
        "month_used": traffic.month_used(&node.traffic_mode),
        "month_start": traffic.month_start,
        // Of the same nature as the month and lifetime figures beside it, which
        // the public page already shows, so this one is public as well.
        "day_rx": traffic.day_rx,
        "day_tx": traffic.day_tx,
    });
    // An allowlist rather than a denylist, for the panel as well: the agent ships
    // from its own repository, so a field added there would otherwise reach
    // anonymous visitors the day it is released, and a node token in the wrong
    // hands could fill the panel's frame with whatever it sends. No address,
    // hostname or note may ever reach a visitor.
    if let Some(m) = view["metrics"].as_object_mut() {
        m.retain(|k, _| PUBLIC_METRICS.contains(&k.as_str()) || (full && k == "iface"));
        // The same figures as the top-level ones, from the same row. Both official
        // themes refuse a node's live view without them.
        for (key, value) in agent_ws::INJECTED.into_iter().zip([
            traffic.total_rx,
            traffic.total_tx,
            traffic.month_rx,
            traffic.month_tx,
        ]) {
            m.insert(key.into(), json!(value));
        }
    }
    // Address, private notes and the token never leave the panel. The token is
    // included so the install command can be displayed without reissuing it.
    if full {
        let held = (node.ipv4.as_str(), node.ipv6.as_str());
        let (pin4, pin6) = (node.ipv4_pin.as_str(), node.ipv6_pin.as_str());
        let shown = addresses(&node.ip, held, (pin4, pin6));
        // Which row is the panel machine itself, for the 「主」 badge in the
        // protocol server picker. Admin-only: the public page does not reveal
        // which monitored node hosts the panel.
        view["local"] = json!(!hub_hostname().is_empty() && node.hostname == hub_hostname());
        // What each family shows with its own pin cleared and the other's kept,
        // for the edit form to offer as the fallback.
        let auto = |pins, v6: bool| {
            addresses(&node.ip, held, pins)
                .into_iter()
                .find(|(a, _)| a.contains(':') == v6)
                .map_or("", |(a, _)| a)
        };
        view["hostname"] = json!(node.hostname);
        view["ip"] = json!(node.ip);
        view["ipv4"] = json!(node.ipv4);
        view["ipv6"] = json!(node.ipv6);
        view["ipv4_pin"] = json!(node.ipv4_pin);
        view["ipv6_pin"] = json!(node.ipv6_pin);
        view["addresses"] =
            shown.iter().map(|(address, source)| json!({"address": address, "source": source})).collect();
        view["ipv4_auto"] = json!(auto(("", pin6), false));
        view["ipv6_auto"] = json!(auto((pin4, ""), true));
        view["interval"] = json!(current.and_then(Agent::interval));
        view["country_pin"] = json!(node.country_pin);
        view["country_auto"] = json!(node.country);
        view["token"] = json!(node.token);
        view["notify"] = json!(node.notify);
        // 购买网站：主机名点击跳转的目标。DDNS 绑定一并回显——保存路径早于
        // 本视图，这两列此前从未到达面板，编辑弹窗一直显示为空。
        view["purchase_url"] = json!(node.purchase_url);
        view["dns_name"] = json!(node.dns_name);
        view["dns_ip"] = json!(node.dns_ip);
    }
    view
}

fn visible_nodes(app: &App, full: bool) -> Result<Vec<Value>, anyhow::Error> {
    // One traffic query and one lock for the whole list, since this is what every
    // visitor to the public page loads.
    let nodes = app.db.nodes()?;
    let traffic = app.db.all_traffic();
    let agents = app.agents.read().unwrap_or_else(|e| e.into_inner());
    let none = Traffic::default();
    let today = Local::now().date_naive();
    Ok(nodes
        .iter()
        .filter(|n| full || n.public)
        .map(|n| node_view(n, agents.get(&n.id), traffic.get(&n.id).unwrap_or(&none), full, today))
        .collect())
}

pub async fn nodes(State(app): State<Shared>, headers: HeaderMap) -> Response {
    let full = authed(&app, &headers);
    if !full && !app.public_page() {
        return answer(StatusCode::UNAUTHORIZED, "需要登录后查看");
    }
    // The same rendered frame the browser streams receive, for the same reason:
    // otherwise every visitor would rebuild every node's row against the
    // connection the agents write through.
    ([(axum::http::header::CONTENT_TYPE, "application/json")], live_snapshot(&app, full).as_str().to_owned())
        .into_response()
}

#[derive(Deserialize)]
pub struct Window {
    #[serde(default = "default_hours")]
    hours: i64,
    /// How many points the caller can draw. Absent means the full budget.
    points: Option<i64>,
    /// Which half the caller will draw, `metrics` or `ping`. Each tab draws one,
    /// and the other accounted for a third to two thirds of every response. Absent
    /// means both.
    series: Option<String>,
}

fn default_hours() -> i64 {
    6
}

/// How many history windows are built concurrently.
///
/// `PUBLIC_HOURS` bounds what one request costs; this bounds how many may run,
/// closing the same gap `main::RELAY_GATE` and `auth::PASSWORD_GATE` close on
/// the other two paths an anonymous caller can make expensive. This is the most
/// expensive of the three: every request holds the single connection the agents
/// report through for its entire scan, measured at 118 ms for a week of four
/// probes and growing with `retention_days`. Without a gate, 120 requests from
/// one machine took the panel's own node list from 1 ms to 2.8 s.
///
/// Four, because the requests serialise on that one connection regardless: a
/// fifth in flight buys no throughput and merely places another scan ahead of
/// the next agent report. What the number actually sets is how long that wait
/// can become -- four at roughly 120 ms is half a second -- while leaving room
/// for several people opening charts simultaneously.
///
/// Refused rather than queued, as in `auth`: a queue admits the same flood,
/// merely later.
///
/// **This gate is ineffective without the `spawn_blocking` below.** The body of
/// this handler never awaits, so a permit taken and dropped within it is held
/// only while a worker thread is actually running the handler -- at most one per
/// worker, three on this hub. Measured at eight: 120 concurrent requests, zero
/// refusals, the panel still at 14 s. This is the same constraint
/// `PASSWORD_CHECKS` is sized against, approached from the other side: not a
/// value too high for the machine, but a handler that cannot hold more permits
/// than the machine has threads. Moving the scan off the runtime is what makes
/// "in flight" meaningful, and is what every other heavy query here already
/// does.
const HISTORY_SLOTS: usize = 4;
static HISTORY_GATE: tokio::sync::Semaphore = tokio::sync::Semaphore::const_new(HISTORY_SLOTS);

pub async fn metrics(
    State(app): State<Shared>,
    headers: HeaderMap,
    Path(id): Path<i64>,
    Query(w): Query<Window>,
) -> Response {
    let full = authed(&app, &headers);
    if !readable(&app, full, id) {
        return answer(StatusCode::UNAUTHORIZED, "需要登录后查看");
    }
    // After the two point lookups above, so an unauthorised caller is told so
    // rather than asked to retry later.
    let Ok(_permit) = HISTORY_GATE.try_acquire() else {
        return answer(StatusCode::SERVICE_UNAVAILABLE, "查询历史的请求太多，稍后再试");
    };
    let hours = w.hours.clamp(1, if full { ADMIN_HOURS } else { PUBLIC_HOURS });
    let since = Utc::now().timestamp() - hours * 3_600;
    let step = sample_step(hours, w.points);
    let wants = |name: &str| w.series.as_deref().is_none_or(|s| s == name);
    let (want_metrics, want_ping) = (wants("metrics"), wants("ping"));
    // Off the runtime, for the reason given in `db_stats` below: this reads every
    // probe result the node has retained within the window and holds the
    // connection the agents report through throughout. That route is behind
    // `Admin` and cheaper than this one, which anyone can reach.
    //
    // It is also what makes the gate above effective: the permit is held across
    // an await, so exactly four callers are inside it at once rather than however
    // many worker threads happen to exist.
    let built = tokio::task::spawn_blocking(move || {
        // Probe names accompany the samples they label, so the page needs no
        // second request. Names only: targets and assignments remain behind
        // `Admin`. Skipped when probes were not requested, since the resources tab
        // has nothing to label and this costs a turn at the write connection.
        let probes =
            if want_ping { app.db.ping_task_names(id).unwrap_or_else(|_| json!({})) } else { json!({}) };
        let metrics = if want_metrics { app.db.metrics(id, since, step)? } else { vec![] };
        // `loss` is per probe across the whole window, alongside the per-bucket
        // `loss` on the rows. Both are required and neither replaces the other:
        // the row figure is what a tooltip reads, while the window figure is the
        // only one that can be accurate, since the denominators it divides by are
        // gone by the time the rows are built. Additive, so a theme unaware of it
        // continues to work.
        let (ping, loss) =
            if want_ping { app.db.ping_records(id, since, step)? } else { (vec![], json!({})) };
        anyhow::Ok(json!({"metrics": metrics, "ping": ping, "probes": probes, "loss": loss}))
    })
    .await;
    match built.map_err(|e| anyhow::anyhow!(e)).and_then(|r| r) {
        Ok(body) => Json(body).into_response(),
        Err(e) => fail(e),
    }
}

/// Widest history window each audience may request.
///
/// The thinning below bounds the response, not the scan behind it: `hours=2160`
/// returns 320 rows after reading every probe result the node has retained. At a
/// month of retention that is 224 ms holding the single write connection the
/// agents report through, growing with `retention_days`.
///
/// The public ceiling is a week because that is the widest chart the themes
/// draw, so nothing in use is lost. The panel retains the quarter year, being
/// one signed-in operator rather than an anonymous caller.
const PUBLIC_HOURS: i64 = 24 * 7;
const ADMIN_HOURS: i64 = 24 * 90;

/// Seconds between the samples a window is drawn from.
///
/// Thinning exists for what the screen cannot draw rather than as a convention:
/// where the samples fit, every one is sent. A chart of a hundred points reads
/// as a hundred samples taken, which for a probe is a claim about the network.
/// Whole minutes, matching the grid the metric rows sit on.
///
/// `points` is what the caller reports it can draw, and can only lower the
/// budget: `SAMPLES` is the hub's ceiling rather than the caller's, set at a day
/// of minutes so the widest charted probe window returns intact.
// ponytail: the budget is per series, so a response is SAMPLES × (1 + probes) --
// bounded by how many probes the admin created, not by the caller. Four probes
// at a day is ~90 kB gzipped; if that list ever grows long, scale SAMPLES by
// the probe count.
fn sample_step(hours: i64, points: Option<i64>) -> i64 {
    const SAMPLES: i64 = 1_440;
    let budget = points.unwrap_or(SAMPLES).clamp(60, SAMPLES);
    // Rounded up, or the budget would not be one: a window that does not divide
    // evenly would keep the finer step and exceed it. `i64::div_ceil` is still
    // unstable, and both operands are positive here.
    60 * ((hours * 60 + budget - 1) / budget).max(1)
}

/// Guards a per-node read: the panel sees everything, while the public page sees
/// only nodes explicitly published. `full` is the caller's own `authed`, passed
/// in because the handler also needs it for the window ceiling.
fn readable(app: &App, full: bool, id: i64) -> bool {
    full || (app.public_page() && app.db.node(id).ok().flatten().is_some_and(|n| n.public))
}

/// Per-connection read buffer for both WebSocket surfaces. The 128 KiB default
/// would be tens of megabytes across a few hundred agents, for frames a few
/// hundred bytes long.
pub const SOCKET_BUFFER: usize = 4 * 1024;

/// Largest frame either socket accepts, matching the 64 KiB cap on the HTTP
/// body. That limit is a tower layer and never applies here, where the default
/// ceiling is 64 MiB -- reachable with a node's own token, for content that is
/// stored and then served to every viewer of the public page.
pub const MAX_FRAME: usize = 64 * 1024;

/// How long one rendered snapshot is reused. Just under the push interval, so
/// every tick rebuilds once and no viewer receives a stale frame twice.
const SNAPSHOT_TTL_MS: i64 = 1_900;

/// The payload every browser stream sends, built at most once per tick however
/// many tabs are watching: the public page is anonymous, so a per-connection
/// build would make viewer count a multiplier on database work. Two slots,
/// because the admin view carries fields the public one must never expose.
fn live_snapshot(app: &App, full: bool) -> Utf8Bytes {
    let now = Utc::now().timestamp_millis();
    let slot = usize::from(full);
    // 快取检查只读两个槽位，锁内不做任何数据库工作——这把锁是全网热路径
    // （面板首拉、浏览器流、invalidate）的汇合点，持锁过库曾把整个 runtime
    // 冻结数分钟（单 worker 上一旦有人持锁等库，所有任务都排在它后面）。
    // 未命中时放锁重建，回填前二次确认（另一任务可能刚填过）。
    let cached = {
        let cache = app.snapshot.lock().unwrap_or_else(|e| e.into_inner());
        let (ts, frame) = &cache[slot];
        (0..SNAPSHOT_TTL_MS).contains(&now.saturating_sub(*ts)).then(|| frame.clone())
    };
    if let Some(frame) = cached {
        return frame;
    }
    let nodes = visible_nodes(app, full).unwrap_or_default();
    // `admin` is included so the panel's first fetch and its stream share one
    // cached frame.
    let payload = Utf8Bytes::from(json!({"nodes": nodes, "admin": full}).to_string());
    {
        let mut cache = app.snapshot.lock().unwrap_or_else(|e| e.into_inner());
        if now.saturating_sub(cache[slot].0) >= SNAPSHOT_TTL_MS {
            cache[slot] = (now, payload.clone());
        }
    }
    payload
}

/// Drops the cached frames so the next push rebuilds. Without it a node just
/// added in the panel would disappear from the list until the frame expires.
pub(crate) fn invalidate_snapshot(app: &App) {
    for slot in app.snapshot.lock().unwrap_or_else(|e| e.into_inner()).iter_mut() {
        slot.0 = 0;
    }
}

/// What one tick of a browser stream may send: the admin frame while the session
/// that opened it remains live, the public frame while the status page remains
/// open to anonymous callers, and nothing once either ceases to hold.
///
/// Both are checked every tick rather than at the handshake alone, because a
/// socket outlives both answers. The admin frame carries every node's token in
/// the clear, so one outliving its session would distribute credentials that
/// survive revocation -- the same gap `reset_token` closes on the agent side by
/// dropping its sender. The public frame is what an operator withdraws by
/// switching the status page off, and a socket opened a minute earlier would
/// continue sending it for as long as the tab stayed open: `live_ws` refuses new
/// anonymous connections from that moment and `nodes` answers them 401, leaving
/// this the only remaining route. Whatever the handshake tested must be tested
/// here as well.
fn stream_audience(app: &App, session: Option<&str>) -> Option<bool> {
    match session {
        Some(hash) => app.db.session_valid(hash).then_some(true),
        None => app.public_page().then_some(false),
    }
}

/// Live stream for the browser. Each connection runs its own timer -- simpler to
/// reason about than a fan-out channel -- over a shared snapshot, so a timer
/// costs no more than a send.
pub async fn live_ws(State(app): State<Shared>, headers: HeaderMap, upgrade: WebSocketUpgrade) -> Response {
    // The digest rather than the result: signing out must reach a stream already
    // running, and only the row it names can report whether it has.
    let session = current_session(&headers).filter(|hash| app.db.session_valid(hash));
    if session.is_none() && !app.public_page() {
        return answer(StatusCode::UNAUTHORIZED, "需要登录后查看");
    }
    upgrade
        .read_buffer_size(SOCKET_BUFFER)
        .max_message_size(MAX_FRAME)
        .on_upgrade(move |socket| stream_live(app, socket, session))
}

async fn stream_live(app: Shared, mut socket: WebSocket, session: Option<String>) {
    let mut ticker = tokio::time::interval(std::time::Duration::from_secs(2));
    loop {
        ticker.tick().await;
        // Closed rather than downgraded to the public frame, which would leave the
        // panel rendering a list with every admin field missing. The close allows
        // a client to re-query /api/me and determine its current state.
        let Some(full) = stream_audience(&app, session.as_deref()) else { break };
        if socket.send(Message::Text(live_snapshot(&app, full))).await.is_err() {
            break;
        }
    }
}

// ---- panel write paths ----

/// Names all three causes. `--site` is the one input to this decision that
/// nothing about the request reveals: a hub started with
/// `--site https://198.51.100.7` refuses every provisioning call from an
/// otherwise valid https domain entry, and a tunnelled panel is refused until
/// one is given. `main` warns about the first at startup; this is for whoever
/// reads the panel rather than the journal.
const PROVISIONING_DENIED: &str = "请通过 HTTPS 域名访问面板后添加或安装节点；\
     从隧道或回环地址进面板时，给 hub 加 --site 指定节点可达的域名；\
     --site 必须是 https:// 加域名，不能是 IP、不能带路径";

/// Every browser sends `Origin` with these writes, so its absence points at a
/// proxy clearing it. The panel judges from its own address bar and offers the
/// button, which leaves this as the only account of why the hub refuses.
const ORIGIN_MISSING: &str = "请求没有带 Origin 头。浏览器都会发送它，多半是反向代理清掉了\
     （例如 proxy_set_header Origin \"\"），去掉那一行后再试";

/// Whether this origin is the hub's own machine, which is what a tunnel into the
/// panel leaves in the address bar. Nothing between that browser and the hub is
/// in the clear -- it is the loopback interface, or the tunnel's own encryption
/// -- so the entry is sound; what it lacks is an address a node could use, which
/// is why it counts only alongside `--site`.
fn loopback_origin(origin: &str) -> bool {
    let Ok(url) = reqwest::Url::parse(origin) else { return false };
    let Some(host) = url.host_str() else { return false };
    // host_str keeps the brackets an IPv6 literal is written with.
    let ip = host.trim_start_matches('[').trim_end_matches(']').parse::<IpAddr>();
    matches!(url.scheme(), "http" | "https")
        && (host == "localhost" || host.ends_with(".localhost") || ip.is_ok_and(|ip| ip.is_loopback()))
}

pub(crate) fn https_domain(site: &str) -> Option<reqwest::Url> {
    let url = reqwest::Url::parse(site).ok()?;
    (url.scheme() == "https"
        && url.domain().is_some_and(|d| d != "localhost" && !d.ends_with(".localhost"))
        && url.username().is_empty()
        && url.password().is_none()
        && url.path() == "/"
        && url.query().is_none()
        && url.fragment().is_none())
    .then_some(url)
}

/// Whether the browser sending this request is on an https domain entry, which
/// is the only address the panel may build install commands from.
///
/// The browser's own `Origin` answers it. Reconstructing the entry from `Host`
/// and `X-Forwarded-Proto` instead holds only where every proxy in front
/// forwards both, and the common ones do not: the aapanel and BT templates send
/// no `X-Forwarded-Proto`, a bare `proxy_pass` sends its own upstream address as
/// `Host` (as does Apache under `ProxyPreserveHost Off`), `$host` drops a port
/// that is not 443, and a TLS edge ahead of a plaintext hop leaves
/// `X-Forwarded-Proto: http`. Each of those refuses a panel that is in fact on
/// https, and none can be told apart here from a genuine plaintext entry.
/// `Origin` crosses all of them unchanged, and a page cannot forge its own.
///
/// `--site` is measured by the same rule, because it takes this origin's place
/// in the command: an IP or a path there is refused however the panel is
/// reached. It also answers for the one entry this origin cannot: a panel opened
/// over a tunnel reads `http://127.0.0.1:PORT`, which names no address a node
/// could reach, while `--site` names one and the tunnel carries the session
/// under its own encryption.
///
/// The error is the message the panel shows.
fn provisioning_allowed(app: &App, headers: &HeaderMap) -> Result<(), &'static str> {
    if !app.site.is_empty() && https_domain(&app.site).is_none() {
        debug!("provisioning refused: --site {:?} is not an https domain entry", app.site);
        return Err(PROVISIONING_DENIED);
    }
    let Some(origin) = headers.get(header::ORIGIN).and_then(|v| v.to_str().ok()) else {
        debug!("provisioning refused: the request carries no readable Origin");
        return Err(ORIGIN_MISSING);
    };
    if https_domain(origin).is_none() && !(loopback_origin(origin) && !app.site.is_empty()) {
        debug!("provisioning refused: Origin {origin:?} is not an https domain entry");
        return Err(PROVISIONING_DENIED);
    }
    // States that the request belongs to the page it addresses, which `Origin`
    // alone does not: the panel is the only caller, and a page elsewhere holds no
    // session here anyway, `SameSite=Lax` keeping the cookie from it. Browsers
    // predating the header send none, and the origin above remains the test.
    let fetch_site = headers.get("sec-fetch-site").and_then(|v| v.to_str().ok());
    if fetch_site.is_some_and(|site| site != "same-origin") {
        debug!("provisioning refused: Sec-Fetch-Site {fetch_site:?} is not same-origin");
        return Err(PROVISIONING_DENIED);
    }
    Ok(())
}

/// Range and sign limits every stored node must satisfy, or the reason it does
/// not. Shared because both writers must enforce them: the create path formerly
/// accepted a whole `Node` unchecked, leaving the values the update path refuses
/// reachable by another route, and an out-of-range reset day remained harmless
/// only because `period_start` clamps what it reads.
fn node_limits(reset_day: Option<u32>, price: Option<f64>, limit: Option<i64>) -> Option<&'static str> {
    if reset_day.is_some_and(|d| !(1..=31).contains(&d)) {
        return Some("流量重置日要在 1 到 31 之间");
    }
    if price.is_some_and(|v| !v.is_finite() || v < 0.0) || limit.is_some_and(|v| v < 0) {
        return Some("价格和流量上限不能是负数");
    }
    None
}

/// A theme shows the group as a tab label or a section title, so it is held to a
/// length that fits one line on a 390 px phone.
const MAX_GROUP: usize = 13;

/// Trims a group name, or refuses it. Refused rather than truncated: the panel
/// would otherwise report saved a name that is not the one stored.
fn group_error(group: &mut String) -> Option<&'static str> {
    *group = group.trim().to_owned();
    if group.chars().count() > MAX_GROUP || group.chars().any(char::is_control) {
        return Some("分组名最多 13 个字，不能含控制字符");
    }
    None
}

/// Normalizes the currency and billing cycle, or names the one that cannot be
/// stored. The currency is held to the ISO 4217 form of three letters, the only
/// one `Intl.NumberFormat` accepts, so a theme may pass it on without guarding
/// against a throw. Each cycle length is stored in a single spelling, see
/// `cycle_name`.
fn billing_error(currency: Option<&mut String>, cycle: Option<&mut String>) -> Option<&'static str> {
    if let Some(code) = currency {
        *code = code.trim().to_ascii_uppercase();
        if !(code.len() == 3 && code.bytes().all(|b| b.is_ascii_uppercase())) {
            return Some("货币要填三个字母的代码，如 USD、CNY、HKD");
        }
    }
    if let Some(cycle) = cycle.filter(|c| *c != "once") {
        let Some(months) = crate::cycle_months(cycle) else {
            return Some("付款周期要是整月，在 1 个月到 100 年之间");
        };
        *cycle = crate::cycle_name(months);
    }
    None
}

/// Normalizes a patch, or names the first value that cannot be stored. The one
/// check both the single and the batch write pass through, so the two accept
/// exactly the same values.
fn patch_error(node: &mut NodePatch) -> Option<&'static str> {
    if let Some(name) = &mut node.name {
        *name = name.trim().to_owned();
        if name.is_empty() {
            return Some("请填写节点名称");
        }
    }
    if let Some(group) = &mut node.group {
        if let Some(message) = group_error(group) {
            return Some(message);
        }
    }
    node_limits(node.traffic_reset_day, node.price, node.traffic_limit)
        .or_else(|| billing_error(node.currency.as_mut(), node.billing_cycle.as_mut()))
        .or_else(|| pins(node))
}

/// Normalizes the values set by hand, or names the one that cannot stand. Each
/// takes the place of an automatic value, so it is held to what that value would
/// have to be: the country to the rule a looked-up one passes, as both reach the
/// status page; an address to its own family, stored canonical so the panel's
/// search matches however it was typed.
fn pins(node: &mut NodePatch) -> Option<&'static str> {
    if let Some(cc) = &mut node.country_pin {
        *cc = cc.trim().to_ascii_uppercase();
        if !cc.is_empty() && !(cc.len() == 2 && cc.bytes().all(|b| b.is_ascii_uppercase())) {
            return Some("国家要填两个字母的代码，留空则自动识别");
        }
    }
    for (pin, v6) in [(&mut node.ipv4_pin, false), (&mut node.ipv6_pin, true)] {
        let Some(pin) = pin else { continue };
        let typed = pin.trim();
        let parsed = if v6 {
            typed.parse::<Ipv6Addr>().map(IpAddr::V6)
        } else {
            typed.parse::<Ipv4Addr>().map(IpAddr::V4)
        };
        *pin = match parsed {
            Ok(ip) => ip.to_string(),
            Err(_) if typed.is_empty() => String::new(),
            Err(_) if v6 => return Some("IPv6 要填一个 IPv6 地址，或者留空"),
            Err(_) => return Some("IPv4 要填一个 IPv4 地址，或者留空"),
        };
    }
    None
}

pub async fn me(State(app): State<Shared>, headers: HeaderMap) -> Json<Value> {
    Json(json!({
        "authed": authed(&app, &headers),
        "github": app.db.get("github_client_id").is_some_and(|v| !v.is_empty()),
        "site_name": app.db.get("site_name").unwrap_or_else(|| "Monitor".into()),
        "public_page": app.public_page(),
        // Whether this browser may provision is not answered here: a GET carries
        // no `Origin`, so the panel applies `provisioning_allowed`'s rule itself.
        //
        // The hub's own public URL when one was given, which is what belongs in an
        // install command and in the OAuth callback -- not whichever address this
        // browser used, which behind a proxy may be a loopback port. Empty by
        // default, in which case the browser's address is the only one available
        // and the panel falls back to its own origin.
        "site": app.site,
    }))
}

pub async fn create_node(
    _: Admin,
    State(app): State<Shared>,
    headers: HeaderMap,
    body: Result<Json<Node>, JsonRejection>,
) -> Response {
    if let Err(refusal) = provisioning_allowed(&app, &headers) {
        return answer(StatusCode::FORBIDDEN, refusal);
    }
    let Ok(Json(mut node)) = body else { return bad("节点数据格式不对") };
    if node.name.trim().is_empty() {
        return bad("请填写节点名称");
    }
    if let Some(message) =
        node_limits(Some(node.traffic_reset_day), Some(node.price), Some(node.traffic_limit))
            .or_else(|| group_error(&mut node.group))
            .or_else(|| billing_error(Some(&mut node.currency), Some(&mut node.billing_cycle)))
    {
        return bad(message);
    }
    node.name = node.name.trim().to_owned();
    let token = random_token();
    match app.db.create_node(&node, &token) {
        // Usable immediately: the install command is readable from the node list,
        // so adding and deploying require no reissue in between.
        Ok(id) => {
            invalidate_snapshot(&app);
            Json(json!({"id": id})).into_response()
        }
        Err(e) => fail(e),
    }
}

// ---- automatic registration ----

/// How long a registration window stays open.
///
/// Provisioning a batch of machines takes minutes, and the window expires on its
/// own rather than depending on someone returning to close it.
const REGISTER_WINDOW: i64 = 3600;

/// How many nodes one window may register.
///
/// Without it, whoever holds the key for the hour could fill the node table. A
/// hundred is well beyond a plausible batch and well short of a problem.
const REGISTER_LIMIT: i64 = 100;

/// The header in which `install.sh` sends the token the machine already holds.
const HELD_TOKEN: &str = "x-node-token";

/// Exchanges a registration key for a node token, so a batch of machines can be
/// installed with one command rather than one panel visit each.
///
/// No session stands behind this route: the caller is `install.sh` on a machine
/// that has never contacted the hub. A key issued by the panel, valid only within
/// [`REGISTER_WINDOW`], serves in place of a session.
///
/// `provisioning_allowed` does not guard it, because a shell script sends no
/// `Origin` and the proxy headers that remain cannot state what address the
/// caller used. Which addresses may be registered against is enforced in
/// `install.sh`, where that address is known: it refuses plaintext to anything
/// but loopback unless `--insecure` is given, the same switch under which the
/// binary it is about to run as root was already fetched in the clear. The
/// window this key belongs to is still opened from an https domain entry alone.
///
/// One request costs at most a lookup on the token's unique index, two setting
/// reads, a `COUNT`, and one transaction inserting the `node` and `traffic` rows
/// plus a `ping_node` row per `auto_join` probe, at most 64. It makes no outbound
/// request, and the router's 64 KiB body limit bounds the name. Requests in flight
/// are not gated: each step is a point read or one small transaction under the
/// database lock, as with the token lookup of the agent handshake, and an address
/// locked out below reaches none of them. 120 concurrent callers with the window
/// closed move the panel's median from 1.1 ms to 2.1-2.8 ms, with or without a
/// held token, on three cores.
pub async fn agent_register(
    State(app): State<Shared>,
    ConnectInfo(peer): ConnectInfo<std::net::SocketAddr>,
    headers: HeaderMap,
    // Plain text in, plain text out. The caller is a shell script, as with this
    // route's neighbours: `/install.sh` and `/agent/{arch}` return a script and a
    // binary. A bare token is one `$(curl ...)` away, requiring no JSON parser in
    // a POSIX `sh`.
    name: String,
) -> Response {
    let ip = client_ip(&headers, peer.ip());
    // Counted separately from the sign-in page: a batch install started with a
    // stale key is a misconfigured deploy rather than an attack on the panel, and
    // a shared counter would lock the operator out of their own hub for LOCKOUT.
    if app.registrations.locked(ip) {
        return answer(StatusCode::TOO_MANY_REQUESTS, "too many attempts, try again later");
    }
    // A rerun on a registered machine sends the token it already holds and
    // receives it back while that token still opens a node, so the rerun adds no
    // second node. Ahead of the window and the key: it creates nothing, returns
    // only what the caller already holds -- which the 401 of the agent handshake
    // reveals as well -- and must still succeed once the window has closed. A
    // token whose node was deleted, or which was reissued, falls through.
    if let Some(held) = headers.get(HELD_TOKEN).and_then(|v| v.to_str().ok()).filter(|t| !t.is_empty()) {
        match app.db.node_by_token(held) {
            Ok(Some(_)) => return held.to_owned().into_response(),
            Ok(None) => {}
            // Read as "no node", a failed lookup would register a second node for
            // a machine whose node is intact.
            Err(e) => return script_fail(e),
        }
    }
    // One answer for both "no window is open" and "that key is wrong": the
    // difference is only useful to someone who has neither.
    let closed = || {
        answer(StatusCode::FORBIDDEN, "registration is closed; open a new window from the panel's node list")
    };
    let until = app.db.get("register_until").and_then(|v| v.parse::<i64>().ok()).unwrap_or(0);
    let Some(key) = app.db.get("register_key").filter(|k| !k.is_empty() && Utc::now().timestamp() < until)
    else {
        return closed();
    };
    if agent_ws::bearer(&headers) != Some(key.as_str()) {
        // Only an incorrect key counts against the address. With the window
        // closed there is no secret to guess, and counting then would let anyone
        // lock an address they name in `X-Forwarded-For` out of the sign-in page.
        app.registrations.record_failure(ip);
        return closed();
    }
    match app.db.nodes_created_since(until - REGISTER_WINDOW) {
        Ok(n) if n >= REGISTER_LIMIT => {
            return answer(
                StatusCode::FORBIDDEN,
                "this window has registered enough nodes; open a new window from the panel's node list",
            )
        }
        Err(e) => return script_fail(e),
        Ok(_) => {}
    }

    // The name comes from a machine not yet vouched for: control characters would
    // break the panel's rows, and the length must be bounded. `chars()` rather
    // than bytes, so the cut falls on a character boundary.
    let name: String = name.trim().chars().filter(|c| !c.is_control()).take(64).collect();
    let name = if name.is_empty() { "unnamed".to_owned() } else { name };
    // Field defaults live in `Node`'s serde attributes and nowhere else.
    // `Node::default()` is a different set of values -- private, reset day 0 --
    // and a node registered here must match one added through the panel.
    let node = match serde_json::from_value::<Node>(json!({ "name": name })) {
        Ok(node) => node,
        Err(e) => return script_fail(e),
    };
    let token = random_token();
    match app.db.create_node(&node, &token) {
        Ok(_) => {
            app.registrations.clear(ip);
            invalidate_snapshot(&app);
            token.into_response()
        }
        Err(e) => script_fail(e),
    }
}

/// [`fail`] for `install.sh`, whose own output is English and which prints the
/// reply in one line after its own.
fn script_fail(e: impl Into<anyhow::Error>) -> Response {
    warn!("registration failed: {:#}", e.into());
    answer(StatusCode::INTERNAL_SERVER_ERROR, "the hub hit an internal error; its log has the details")
}

/// Opens a registration window with a fresh key. Any previous key stops working
/// the moment this returns.
pub async fn open_register(_: Admin, State(app): State<Shared>, headers: HeaderMap) -> Response {
    if let Err(refusal) = provisioning_allowed(&app, &headers) {
        return answer(StatusCode::FORBIDDEN, refusal);
    }
    let key = random_token();
    let until = (Utc::now().timestamp() + REGISTER_WINDOW).to_string();
    match app.db.set("register_key", &key).and_then(|()| app.db.set("register_until", &until)) {
        Ok(()) => Json(json!({"register_key": key, "register_until": until})).into_response(),
        Err(e) => fail(e),
    }
}

/// Closes the window early, before the hour elapses.
pub async fn close_register(_: Admin, State(app): State<Shared>) -> Response {
    match app.db.set("register_key", "").and_then(|()| app.db.set("register_until", "0")) {
        Ok(()) => StatusCode::NO_CONTENT.into_response(),
        Err(e) => fail(e),
    }
}

pub async fn update_node(
    _: Admin,
    State(app): State<Shared>,
    Path(id): Path<i64>,
    body: Result<Json<NodePatch>, JsonRejection>,
) -> Response {
    let Ok(Json(mut node)) = body else { return bad("节点数据格式不对") };
    if let Some(message) = patch_error(&mut node) {
        return bad(message);
    }
    match app.db.update_node(id, &node) {
        Ok(true) => {
            invalidate_snapshot(&app);
            Json(json!({"ok": true})).into_response()
        }
        Ok(false) => no_such_node(),
        Err(e) => fail(e),
    }
}

/// What a batch may set: the settings the panel applies across a selection.
/// An allowlist, so a field added to [`NodePatch`] later, possibly one that
/// describes a single machine, is refused here until it is listed.
#[derive(Deserialize, Default)]
#[serde(deny_unknown_fields)]
pub struct BatchPatch {
    group: Option<String>,
    notify: Option<bool>,
}

#[derive(Deserialize)]
pub struct NodeBatch {
    ids: Vec<i64>,
    #[serde(default)]
    patch: BatchPatch,
}

/// Applies one patch to every selected node, all or none.
pub async fn update_nodes(
    _: Admin,
    State(app): State<Shared>,
    body: Result<Json<NodeBatch>, JsonRejection>,
) -> Response {
    let Ok(Json(NodeBatch { mut ids, patch })) = body else {
        return bad("批量修改只支持分组和通知");
    };
    ids.sort_unstable();
    ids.dedup();
    if ids.is_empty() {
        return bad("没有选中节点");
    }
    let mut patch = NodePatch { group: patch.group, notify: patch.notify, ..Default::default() };
    if let Some(message) = patch_error(&mut patch) {
        return bad(message);
    }
    match app.db.update_nodes(&ids, &patch) {
        Ok(true) => {
            invalidate_snapshot(&app);
            Json(json!({"updated": ids.len()})).into_response()
        }
        Ok(false) => answer(StatusCode::NOT_FOUND, "有节点已被删除，没有做任何修改；刷新后重新选择"),
        Err(e) => fail(e),
    }
}

#[derive(Deserialize)]
pub struct Order {
    ids: Vec<i64>,
}

/// The list must name every node exactly once, checked inside the transaction
/// that renumbers rather than here: re-reading the node list first would only
/// race the write it guards.
pub async fn reorder_nodes(_: Admin, State(app): State<Shared>, Json(order): Json<Order>) -> Response {
    match app.db.reorder_nodes(&order.ids) {
        Ok(()) => {
            invalidate_snapshot(&app);
            Json(json!({"ok": true})).into_response()
        }
        Err(e) => fail(e),
    }
}

pub async fn delete_node(_: Admin, State(app): State<Shared>, Path(id): Path<i64>) -> Response {
    match app.db.delete_node(id) {
        Ok(true) => {}
        Ok(false) => return no_such_node(),
        Err(e) => return fail(e),
    }
    // 切换主机：从所有节点的镜像集剔除该机（域名指向不自动改，由管理员
    // 在面板上自行切走）。
    if let Err(e) = app.db.strip_server_from_mirrors(id) {
        tracing::warn!("strip mirrors on node delete: {e:#}");
    }
    // The token is checked only at the handshake, so deleting the row does not
    // end a connection already open on it; dropping the sender does. Without
    // this the agent would keep reporting under an id SQLite reassigns to the
    // next node created, which would then appear online on another node's
    // metrics. Dropped after the delete, so the reconnect that follows finds no
    // token to accept. The same reasoning applies in `reset_token` below.
    app.agents.write().unwrap_or_else(|e| e.into_inner()).remove(&id);
    // Its held reading as well, which would otherwise be booked into the node
    // that inherits the id.
    app.readings.lock().unwrap_or_else(|e| e.into_inner()).remove(&id);
    invalidate_snapshot(&app);
    Json(json!({"ok": true})).into_response()
}

/// Issues a fresh token, invalidating the old one immediately.
///
/// Always an explicit action: rotate a token believed to have leaked, then
/// reinstall the agent. Reading the install command does not pass through here.
pub async fn reset_token(_: Admin, State(app): State<Shared>, Path(id): Path<i64>) -> Response {
    let token = random_token();
    match app.db.reset_token(id, &token) {
        Ok(true) => {}
        Ok(false) => return no_such_node(),
        Err(e) => return fail(e),
    }
    // The token is checked only at the handshake, so a session opened with the
    // old one would continue reporting. Dropping the sender ends that loop; the
    // agent reconnects and is refused. Its own teardown leaves the entry
    // untouched, because the session tag no longer matches.
    app.agents.write().unwrap_or_else(|e| e.into_inner()).remove(&id);
    // The token is part of the admin frame, which would otherwise continue to
    // display an install command for the credential just retired.
    invalidate_snapshot(&app);
    // The token alone: the panel builds the command, and one place needs to know
    // its form.
    Json(json!({"token": token})).into_response()
}

pub async fn patch_traffic(
    _: Admin,
    State(app): State<Shared>,
    Path(id): Path<i64>,
    Json(p): Json<TrafficPatch>,
) -> Response {
    if [p.total_rx, p.total_tx, p.month_rx, p.month_tx].into_iter().flatten().any(|v| v < 0) {
        return bad("流量不能是负数");
    }
    match app.db.set_traffic(id, &p) {
        Ok(true) => {
            invalidate_snapshot(&app);
            Json(json!({"ok": true})).into_response()
        }
        Ok(false) => no_such_node(),
        Err(e) => fail(e),
    }
}

pub async fn ping_tasks(_: Admin, State(app): State<Shared>) -> Response {
    match app.db.ping_tasks() {
        Ok(tasks) => Json(json!({"tasks": tasks})).into_response(),
        Err(e) => fail(e),
    }
}

/// As `reorder_nodes`. Nothing is pushed to the agents: the list they run is in
/// id order, see `ping_tasks_for`.
pub async fn reorder_ping_tasks(_: Admin, State(app): State<Shared>, Json(order): Json<Order>) -> Response {
    match app.db.reorder_ping_tasks(&order.ids) {
        Ok(()) => Json(json!({"ok": true})).into_response(),
        Err(e) => fail(e),
    }
}

/// A probe target the agent can resolve: `host:port`, with an IPv6 literal
/// bracketed as a URL writes one.
///
/// A bare `contains(':')` admitted three forms that never connect: a bare IPv6
/// address, which is all colons; `:443` with no host; and `host:` with no port.
/// The agent's `lookup_host` errors on each, `tcp_ping` returns -1, and the chart
/// draws a probe at 100% loss indefinitely with nothing in any log identifying
/// the target as the cause.
fn valid_target(target: &str) -> bool {
    let (host, port) = match target.strip_prefix('[') {
        Some(rest) => match rest.split_once("]:") {
            Some(pair) => pair,
            None => return false,
        },
        // Unbracketed, so the last colon is the port separator; anything still
        // containing a colon is an IPv6 address that required brackets.
        None => match target.rsplit_once(':') {
            Some((host, port)) if !host.contains(':') => (host, port),
            _ => return false,
        },
    };
    !host.is_empty() && port.parse::<u16>().is_ok_and(|p| p > 0)
}

pub async fn save_ping_task(_: Admin, State(app): State<Shared>, Json(mut task): Json<PingTask>) -> Response {
    // Trimmed into the stored value rather than a discarded copy: what reaches
    // the agent is `task.target`, and a trailing space from a paste passes
    // `valid_target` while `lookup_host` rejects the stored string outright,
    // leaving the probe reporting -1 indefinitely. The name is trimmed for the
    // same reason, as it travels to the public page as a chart label.
    task.name = task.name.trim().to_owned();
    task.target = task.target.trim().to_owned();
    if task.name.is_empty() || task.target.is_empty() {
        return bad("请填写名称和目标");
    }
    // A TCP probe requires an explicit port; a bare host would silently never
    // connect.
    if !valid_target(&task.target) {
        return bad("目标要写成「主机:端口」，例如 1.1.1.1:443 或 [2606:4700:4700::1111]:443");
    }
    // Refused rather than clamped, for the reason `setting_error` gives for
    // `retention_days`: the agent clamps this again on arrival, so an
    // out-of-range value never fails but silently becomes a different number
    // while the panel still displays what was entered. Below the floor that
    // number is 5 seconds, the fastest probe available, run by every node the
    // task is assigned to; the panel reaches 0 simply by having its interval
    // field cleared.
    if !(Db::MIN_PROBE_INTERVAL..=3_600).contains(&task.interval) {
        return bad(&format!("间隔要在 {} 到 3600 秒之间", Db::MIN_PROBE_INTERVAL));
    }
    match app.db.save_ping_task(&task) {
        Ok(id) => {
            agent_ws::push_ping_tasks(&app);
            Json(json!({"id": id})).into_response()
        }
        Err(e) => fail(e),
    }
}

pub async fn delete_ping_task(_: Admin, State(app): State<Shared>, Path(id): Path<i64>) -> Response {
    match app.db.delete_ping_task(id) {
        Ok(()) => {
            agent_ws::push_ping_tasks(&app);
            Json(json!({"ok": true})).into_response()
        }
        Err(e) => fail(e),
    }
}

/// Settings the panel may read. Secrets are deliberately excluded: the client can
/// set the GitHub secret but never read it back.
const READABLE_SETTINGS: &[&str] = &[
    "site_name",
    "public_page",
    "github_client_id",
    "github_allowed_users",
    "retention_days",
    "theme",
    "github_proxy",
    "update_notice",
    // 连接日志（M14）：记录开关与保留期。
    "conn_log_enabled",
    "conn_log_retention",
    // 订阅入口地址（M8）：每行一个 host[:port] 或带 scheme 的完整写法。
    "sub_hosts",
    // 协议测速的出口探测目标（空 = gstatic generate_204 默认值）。
    "exit_probe_url",
    // sing-box 全局默认版本（空 = 最新版）：新机安装命令与缺核心自动补装共用，
    // 计量走的 api service 是 1.14+ 特性，默认钉在实测过的 1.14.2。
    "singbox_default_version",
    // realm 全局默认版本（空 = 最新版）：首次建隧道规则时的自动补装用它。
    "realm_default_version",
];

// ---- the database itself ----

/// The largest single request the two upload routes accept, and the reason they
/// sit outside the router's 64 KiB body limit. It is twice the 4 MiB the panel
/// sends, so the chunk size remains the panel's concern alone and requires no
/// negotiated handshake.
///
/// **This, not the two ceilings below, is what a reverse proxy must pass.** A
/// backup of any size arrives 4 MiB at a time, so `client_max_body_size` no
/// longer tracks the size of the database.
pub const MAX_CHUNK: usize = 8 * 1024 * 1024;

/// Whole-file ceilings, one per route, checked against the declared `total` on
/// the first request rather than by counting bytes as they arrive, so an
/// oversized upload is refused before a byte is sent.
///
/// The backup ceiling is set where it is because restoring holds the connection
/// every read and write passes through: at the measured ~40 MB/s that is roughly
/// 6.5 seconds during which the panel and the public page also wait. Database
/// sizes reachable with a few hundred nodes sit two orders of magnitude below
/// it.
pub const MAX_RESTORE: u64 = 256 * 1024 * 1024;
pub const MAX_THEME: u64 = 32 * 1024 * 1024;

/// One request of an upload: `total` is the whole file, `offset` where this piece
/// belongs within it.
///
/// There is no upload id, session or server-side bookkeeping: the state of an
/// upload is the length of the file on disk. A piece continues an upload only if
/// it begins exactly where the last ended, `offset = 0` truncates whatever an
/// interrupted attempt left behind, and nothing is ever left to collect.
#[derive(Deserialize)]
pub struct Chunk {
    offset: u64,
    total: u64,
}

/// Appends one piece to `path`, returning the file's length afterwards; the
/// caller compares that against `total` to determine completion.
///
/// A piece lands whole or not at all -- a failure truncates back to where it
/// began -- so retrying one always aligns on the same offset.
///
/// ponytail: strictly sequential, one round trip per chunk. Concurrent pieces
/// would require pwrite, a commit step and a hash to prove there are no gaps,
/// and would save about a second on a 6.7 MB backup.
async fn receive(path: &str, chunk: &Chunk, max: u64, body: axum::body::Body) -> Result<u64, anyhow::Error> {
    if chunk.total == 0 || chunk.total > max {
        refuse!("文件必须在 1 字节到 {} MiB 之间", max / 1024 / 1024);
    }
    if chunk.offset > chunk.total {
        refuse!("分片位置越过了文件末尾");
    }

    let mut options = std::fs::OpenOptions::new();
    // Only the first piece may create the file, and it truncates: whatever an
    // interrupted upload left behind is overwritten rather than accumulated.
    if chunk.offset == 0 {
        options.write(true).create(true).truncate(true);
    } else {
        options.append(true);
    }
    #[cfg(unix)]
    std::os::unix::fs::OpenOptionsExt::mode(&mut options, 0o600);
    let mut file = match options.open(path) {
        Ok(file) => file,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            refuse!("这次上传已经不在了，请从头开始")
        }
        Err(e) => return Err(e.into()),
    };

    let already = file.metadata()?.len();
    if already != chunk.offset {
        refuse!("分片接不上：已经收到 {already} 字节，这一片却从 {} 开始", chunk.offset);
    }

    match append(&mut file, chunk, body).await {
        Ok(received) => Ok(chunk.offset + received),
        Err(e) => {
            // Undo a partially written piece so a retry aligns again.
            let _ = file.set_len(chunk.offset);
            Err(e)
        }
    }
}

/// Streams one request body onto the end of `file`. The byte count is checked
/// here as well as by the route's body limit: these are the only paths on the hub
/// that write a caller's bytes to disk, so they do not depend on a layer that
/// could be reordered away.
async fn append(
    file: &mut std::fs::File,
    chunk: &Chunk,
    body: axum::body::Body,
) -> Result<u64, anyhow::Error> {
    use anyhow::Context;
    use std::io::Write;
    use std::pin::Pin;

    let mut stream = body.into_data_stream();
    let mut received = 0u64;
    while let Some(piece) =
        std::future::poll_fn(|cx| futures_core::Stream::poll_next(Pin::new(&mut stream), cx)).await
    {
        // The client went away mid-piece, as a cancelled upload does.
        let piece = piece.context(crate::Shown("上传中断了，请重新上传".into()))?;
        received += piece.len() as u64;
        if chunk.offset + received > chunk.total {
            refuse!("这一片超出了声明的文件大小");
        }
        file.write_all(&piece)?;
    }
    Ok(received)
}

/// A scratch file beside the database, so the copy lands on the same filesystem
/// the database has room on. The random component keeps two concurrent calls
/// apart, since `VACUUM INTO` refuses an existing file.
fn scratch_path(app: &App, kind: &str) -> String {
    format!("{}.{kind}-{}.tmp", app.db.file(), &random_token()[..16])
}

/// The data page's figures.
///
/// Off the runtime, like the three routes below: `stats` counts every row of
/// `metric` and `ping_record` -- both WITHOUT ROWID, so each count is a full
/// index scan -- holding the connection the agents report through throughout. At
/// 2.2M rows that is 127 ms during which the public page and every agent report
/// also wait, growing with `retention_days`.
pub async fn db_stats(_: Admin, State(app): State<Shared>) -> Response {
    match tokio::task::spawn_blocking(move || app.db.stats()).await {
        Ok(Ok(stats)) => Json(stats).into_response(),
        Ok(Err(e)) => fail(e),
        Err(e) => fail(anyhow::anyhow!(e)),
    }
}

/// Returns a compact copy of the whole database.
///
/// The copy is written beside the live file and then unlinked while still open,
/// so it exists only for the duration of this response: a client that
/// disconnects partway through leaves nothing behind, and nothing on disk
/// outlives the download.
pub async fn db_backup(_: Admin, State(app): State<Shared>) -> Response {
    let path = scratch_path(&app, "backup");
    // Off the runtime: this reads the entire database while holding the
    // connection the agents write through.
    let copied = {
        let (app, path) = (app.clone(), path.clone());
        tokio::task::spawn_blocking(move || app.db.backup_into(&path)).await
    };
    if let Err(e) = copied.map_err(|e| anyhow::anyhow!(e)).and_then(|r| r) {
        let _ = std::fs::remove_file(&path);
        return fail(e);
    }
    let opened = tokio::fs::File::open(&path).await;
    let size = std::fs::metadata(&path).map(|m| m.len()).unwrap_or(0);
    let _ = std::fs::remove_file(&path);
    match opened {
        Ok(file) => (
            [
                (header::CONTENT_TYPE, "application/octet-stream".to_owned()),
                (header::CONTENT_LENGTH, size.to_string()),
                // The entire credential store: no shared cache may retain a copy.
                (header::CACHE_CONTROL, "no-store".to_owned()),
                (
                    header::CONTENT_DISPOSITION,
                    format!("attachment; filename=\"monitor-{}.db\"", Local::now().format("%Y%m%d-%H%M%S")),
                ),
            ],
            axum::body::Body::from_stream(tokio_util::io::ReaderStream::new(file)),
        )
            .into_response(),
        Err(e) => fail(e),
    }
}

/// Replaces the live database with an uploaded backup, one chunk per request.
///
/// The upload streams to a file beside the database and is validated in full
/// before a single page is copied; see `Db::check_backup`. Afterwards every
/// session in the restored file is dropped and the caller is issued a new one: a
/// backup carries the session rows it held when taken, and restoring it must not
/// revive logged-out sessions.
pub async fn db_restore(
    _: Admin,
    State(app): State<Shared>,
    Query(chunk): Query<Chunk>,
    ConnectInfo(peer): ConnectInfo<std::net::SocketAddr>,
    headers: HeaderMap,
    body: axum::body::Body,
) -> Response {
    // One fixed path, which is what allows the file's own length to constitute
    // the entire protocol.
    // ponytail: one upload in flight per hub. Two started simultaneously land on
    // this same name, and equal-sized chunks align their offsets, so they splice
    // rather than collide. The cost is a failed upload; distinguishing them would
    // require the upload id the protocol deliberately omits.
    let path = format!("{}.upload", app.db.file());
    let received = match receive(&path, &chunk, MAX_RESTORE, body).await {
        Ok(received) => received,
        Err(e) => return fail(e),
    };
    if received < chunk.total {
        return Json(json!({"received": received})).into_response();
    }

    // Moved off the upload name before a byte is read. Splicing costs an upload;
    // what it must not cost is the live database, which without this it could:
    // the other upload would continue appending through its own handle while
    // `check_backup` reads the file and the page copy follows, and SQLite cannot
    // observe a write it did not make. A file that passed every gate would then
    // be copied over in a different state. Afterwards the other upload's next
    // chunk finds nothing and is told to restart, which is the error it already
    // has for an upload that disappeared.
    //
    // ponytail: the rename itself is not covered by a test. What it changes is
    // which path is open during the read, and reaching that would require a
    // second upload landing inside the copy. What is verified afterwards is that
    // neither name is left behind, in
    // `a_finished_restore_leaves_no_scratch_file_behind`.
    let source = scratch_path(&app, "restoring");
    if let Err(e) = std::fs::rename(&path, &source) {
        let _ = std::fs::remove_file(&path);
        return fail(e);
    }

    let outcome = restore(&app, &source).await;
    // SQLite writes a -wal and a -shm beside any file it opens in WAL mode, and a
    // plain copy of a running hub's database is exactly that. They are removed
    // when the connection closes cleanly; these three lines cover the case where
    // it does not.
    for leftover in [source.clone(), format!("{source}-wal"), format!("{source}-shm")] {
        let _ = std::fs::remove_file(leftover);
    }
    match outcome {
        Ok(()) => {
            // Agents authenticate at the handshake, and the tokens they hold may
            // now belong to different nodes, or to none. Dropping the senders ends
            // those loops; each reconnects against the restored database.
            app.agents.write().unwrap_or_else(|e| e.into_inner()).clear();
            // Held readings belong to the database just replaced.
            app.readings.lock().unwrap_or_else(|e| e.into_inner()).clear();
            invalidate_snapshot(&app);
            let cookie =
                match app.db.drop_all_sessions().and_then(|()| issue_session(&app, &headers, peer.ip())) {
                    Ok(cookie) => cookie,
                    Err(e) => return fail(e),
                };
            with_cookies(Json(json!({"ok": true})), [cookie])
        }
        Err(e) => fail(e),
    }
}

async fn restore(app: &Shared, path: &str) -> Result<(), anyhow::Error> {
    // Both halves read the whole file, off the runtime: `PRAGMA integrity_check`
    // on a 256 MiB upload is not runtime work, and the copy that follows holds
    // the connection the agents write through.
    let (app, source) = (app.clone(), path.to_owned());
    tokio::task::spawn_blocking(move || {
        app.db.check_backup(&source)?;
        app.db.restore_from(&source)
    })
    .await?
}

/// Drops history beyond the retention window and rebuilds the file around what
/// remains, which is the only way SQLite returns the space to the filesystem.
pub async fn db_vacuum(_: Admin, State(app): State<Shared>) -> Response {
    let keep = app.db.retention_days();
    let app = app.clone();
    // A rebuild of the whole file, holding the connection the agents write
    // through, so it belongs on a blocking thread.
    let done = tokio::task::spawn_blocking(move || {
        let pruned = app.db.prune(keep)?;
        app.db.vacuum().map(|freed| json!({"pruned": pruned, "freed": freed}))
    })
    .await;
    match done.map_err(|e| anyhow::anyhow!(e)).and_then(|r| r) {
        Ok(result) => Json(result).into_response(),
        Err(e) => fail(e),
    }
}

/// Installs an uploaded theme archive, one chunk per request.
///
/// The archive lands in the themes directory under a name `valid_short` rejects,
/// so a partial upload is invisible to both the theme list and the public page.
/// Installation is performed by `frontend::install`, which unpacks to a staging
/// directory and publishes with a rename: the switch is atomic, and the page is
/// never served from a partially written directory.
pub async fn upload_theme(
    _: Admin,
    State(app): State<Shared>,
    Query(chunk): Query<Chunk>,
    body: axum::body::Body,
) -> Response {
    let path = app.themes.join(".upload.tar.gz");
    let name = path.to_string_lossy().into_owned();
    let received = match receive(&name, &chunk, MAX_THEME, body).await {
        Ok(received) => received,
        Err(e) => return fail(e),
    };
    if received < chunk.total {
        return Json(json!({"received": received})).into_response();
    }

    // Moved off the shared upload name for the same reason as the restore path: a
    // second upload landing on it could continue writing while this archive is
    // read, leaving the unpacker reading a file changed beneath it. Named so
    // `valid_short` still rejects it, keeping a partial archive out of the theme
    // list.
    let source = app.themes.join(format!(".installing-{}.tar.gz", &random_token()[..16]));
    if let Err(e) = std::fs::rename(&path, &source) {
        let _ = std::fs::remove_file(&path);
        return fail(e);
    }

    // Off the runtime: gunzip plus a few thousand small writes.
    let installed = {
        let (app, path) = (app.clone(), source.clone());
        tokio::task::spawn_blocking(move || {
            crate::frontend::install(&app.themes, std::fs::File::open(&path)?, None)
        })
        .await
    };
    let _ = std::fs::remove_file(&source);
    match installed.map_err(|e| anyhow::anyhow!(e)).and_then(|r| r) {
        Ok(theme) => Json(json!({"theme": theme})).into_response(),
        Err(e) => fail(e),
    }
}

/// The asset a theme repository publishes, and the only name the hub fetches: the
/// same `theme.tar.gz` the upload button accepts.
const ARCHIVE: &str = "theme.tar.gz";

/// How long a release lookup stands before the panel asks GitHub again, and how
/// long a failed one does. The short retry keeps one unreachable moment from
/// hiding an update for the rest of the day; the long one keeps a panel left
/// open on a screen to four lookups a day, well inside the 60 per hour an
/// unauthenticated caller is allowed.
const RELEASES_FRESH: i64 = 6 * 3600;
const RELEASES_RETRY: i64 = 600;

/// What is running here, and what is published. The agent's own version travels
/// in its hello and is already in the node list, so the panel compares the two
/// itself and names the nodes to upgrade.
///
/// Admin-only, and deliberately not part of `/api/me`: that route answers
/// anonymous callers, to whom the running hub version is not disclosed. Nothing
/// is fetched until an administrator opens the panel, so a hub whose panel is
/// never opened makes no outbound request.
pub async fn versions(_: Admin, State(app): State<Shared>) -> Json<Value> {
    let cached = app.releases.lock().unwrap().clone();
    let latest = if fresh_enough(&cached, Utc::now().timestamp()) {
        cached
    } else {
        // Both at once: one round trip of latency rather than two, and neither
        // lookup depends on the other.
        let (hub, agent) =
            tokio::join!(latest_tag(&app, crate::HUB_REPO), latest_tag(&app, crate::AGENT_REPO));
        let read = crate::Releases {
            read_at: Utc::now().timestamp(),
            hub: hub.unwrap_or_default(),
            agent: agent.unwrap_or_default(),
        };
        *app.releases.lock().unwrap() = read.clone();
        read
    };
    Json(json!({
        "hub": env!("CARGO_PKG_VERSION"),
        // Empty where GitHub could not be reached, which the panel renders as no
        // update rather than as an error: a hub on a network that cannot reach
        // github.com is a supported deployment, not a fault to report.
        "hub_latest": latest.hub,
        "agent_latest": latest.agent,
        // Whether the navigation marks an update. It governs the mark alone: the
        // lookup runs either way, so the update page still answers when opened.
        "notice": app.db.get("update_notice").as_deref() != Some("off"),
    }))
}

/// Whether the cached lookup still answers. One that returned nothing is held
/// for [`RELEASES_RETRY`] instead, so a single unreachable moment does not hide
/// an update for the rest of the day.
fn fresh_enough(cached: &crate::Releases, now: i64) -> bool {
    let holds =
        if cached.hub.is_empty() || cached.agent.is_empty() { RELEASES_RETRY } else { RELEASES_FRESH };
    cached.read_at != 0 && now - cached.read_at < holds
}

/// The tag of a repository's latest release, without its leading `v`, or None
/// where GitHub could not be read, which costs only the update notice.
async fn latest_tag(app: &App, repo: &str) -> Option<String> {
    let tag = latest_release(app, repo).await.ok()?.tag_name;
    Some(tag.strip_prefix('v').unwrap_or(&tag).to_owned())
}

/// The latest release of `owner/repo`. Unauthenticated: 60 requests per hour from
/// this address. GitHub returns 403 without a User-Agent. Never through the
/// panel's GitHub proxy, which most mirrors provide for release downloads alone.
async fn latest_release(app: &App, repo: &str) -> reqwest::Result<Release> {
    app.http
        .get(format!("https://api.github.com/repos/{repo}/releases/latest"))
        .header(header::USER_AGENT, "monitor-hub")
        .send()
        .await?
        .error_for_status()?
        .json()
        .await
}

#[derive(Deserialize)]
struct Release {
    tag_name: String,
    #[serde(default)]
    assets: Vec<Asset>,
}

#[derive(Deserialize)]
struct Asset {
    name: String,
}

/// The `<owner>/<repo>` a theme's `url` names, where it names a GitHub repository
/// at all.
///
/// An allowlist rather than a filter. Every address the update path fetches is
/// constructed from these two strings, so nothing in a manifest can direct the
/// hub at a host it did not choose, which is why no private-address check is
/// needed here. The only host that is not github.com is the GitHub proxy in the
/// panel's settings, configured by the operator and already used by the agent
/// relay.
fn github_repo(url: &str) -> Option<(&str, &str)> {
    let (owner, rest) = url.strip_prefix("https://github.com/")?.split_once('/')?;
    // A link to a branch or a file is still a link to the repository.
    let repo = rest.split('/').next()?;
    let repo = repo.strip_suffix(".git").unwrap_or(repo);
    (path_segment(owner) && path_segment(repo)).then_some((owner, repo))
}

/// One URL path segment the hub will build a github.com address from: nothing
/// that opens a new segment, and nothing that escapes the current one.
fn path_segment(segment: &str) -> bool {
    !segment.is_empty()
        && segment != "."
        && segment != ".."
        && segment.bytes().all(|c| c.is_ascii_alphanumeric() || matches!(c, b'-' | b'_' | b'.'))
}

/// Reinstalls one theme from the latest GitHub release of the repository its
/// manifest names.
///
/// The manifest supplies `<owner>/<repo>` and nothing more: the release is read
/// from api.github.com and the archive from github.com, both at addresses the hub
/// constructs itself, so no URL from the theme is ever followed. The installed
/// version is compared against the release tag first, which is all most
/// invocations do, making this also the check-for-updates action.
pub async fn update_theme(_: Admin, State(app): State<Shared>, Path(short): Path<String>) -> Response {
    match update(&app, &short).await {
        Ok((updated, version)) => Json(json!({"updated": updated, "version": version})).into_response(),
        Err(e) => fail(e),
    }
}

async fn update(app: &App, short: &str) -> Result<(bool, String), anyhow::Error> {
    use anyhow::Context;

    let Some(installed) = crate::frontend::themes(app)?.into_iter().find(|theme| theme.short == short) else {
        refuse!("没有这个主题");
    };
    let Some((owner, repo)) = github_repo(&installed.url) else {
        refuse!("这个主题的 url 不是 https://github.com/<owner>/<repo>，只能手动上传新包");
    };

    let release = match latest_release(app, &format!("{owner}/{repo}")).await {
        Ok(release) => release,
        Err(e) => {
            let why = match e.status().map(|s| s.as_u16()) {
                None if e.is_decode() => "GitHub 的回复无法识别，稍后再试",
                Some(404) => "这个仓库还没有正式 release",
                // Unauthenticated callers get 60 requests an hour per address.
                Some(403 | 429) => "GitHub 限制了这台机器的请求次数，过一小时再试",
                Some(_) => "GitHub 接口出错，稍后再试",
                None => "hub 连不上 api.github.com，检查它的网络",
            };
            return Err(e).context(crate::Shown(format!("读不到 {owner}/{repo} 的最新 release：{why}")));
        }
    };

    // Tags read `v1.2.3` while manifests carry `1.2.3`. Equal means up to date;
    // anything else is installed, including a deliberate downgrade, since the
    // release is what the author published.
    let tag = &release.tag_name;
    if tag.strip_prefix('v').unwrap_or(tag) == installed.version {
        return Ok((false, installed.version));
    }
    if !path_segment(tag) {
        refuse!("release 的 tag {tag:?} 不能出现在下载地址里");
    }
    // Checked here rather than by downloading and reading a 404: the asset name is
    // the contract, and stating so is the entire error message.
    if !release.assets.iter().any(|asset| asset.name == ARCHIVE) {
        refuse!("release {tag} 里没有 {ARCHIVE}");
    }

    // Through the panel's GitHub proxy when one is configured, the archive being
    // the part a blocked network cannot reach. The API call above is not proxied:
    // most proxies front only releases, and a hub that cannot read the tag still
    // has the upload path.
    let url =
        crate::proxied(app, format!("https://github.com/{owner}/{repo}/releases/download/{tag}/{ARCHIVE}"));
    let unreachable = || crate::Shown(format!("下载 {ARCHIVE} 失败，检查 hub 的网络或面板里的 GitHub 代理"));
    let response = app
        .http
        .get(url)
        .timeout(std::time::Duration::from_secs(120))
        .send()
        .await
        .and_then(reqwest::Response::error_for_status)
        .with_context(unreachable)?;
    // The transfer stops at Content-Length, so checking it checks the body: a
    // header understating the archive cannot make more arrive. GitHub always
    // sends one; a proxy that omits it is refused rather than read unbounded.
    match response.content_length() {
        Some(size) if size <= MAX_THEME => {}
        Some(size) => {
            refuse!("主题包 {} MiB，超过 {} MiB 的上限", size / 1024 / 1024, MAX_THEME / 1024 / 1024)
        }
        None => refuse!("下载没有给出大小，无法确认它在 {} MiB 以内", MAX_THEME / 1024 / 1024),
    }
    let archive = response.bytes().await.with_context(unreachable)?;

    // The same unpacking, validation and atomic replace an upload undergoes,
    // constrained to the theme it may replace. The built-in theme has no
    // directory until this runs: updating it writes one, which then serves in
    // place of the embedded copy until it is deleted.
    let (themes, short) = (app.themes.clone(), short.to_owned());
    let theme = tokio::task::spawn_blocking(move || {
        crate::frontend::install(&themes, std::io::Cursor::new(archive), Some(&short))
    })
    .await??;
    Ok((true, theme.version))
}

/// The thumbnail the theme list displays, where the theme provides one; the list
/// reports which do.
pub async fn theme_preview(_: Admin, State(app): State<Shared>, Path(short): Path<String>) -> Response {
    match crate::frontend::preview(&app.themes, &short) {
        // Not cached: reinstalling a theme under the same name also replaces the
        // image, and this is a panel-only request for a local file.
        Some(png) => {
            ([(header::CONTENT_TYPE, "image/png"), (header::CACHE_CONTROL, "no-cache")], png).into_response()
        }
        None => StatusCode::NOT_FOUND.into_response(),
    }
}

/// Deletes an installed theme. Deleting the one in use is permitted: the public
/// page falls back to the built-in theme from the next request, the same path a
/// broken theme already takes, and leaving the setting intact means reinstalling
/// the theme restores it.
pub async fn delete_theme(_: Admin, State(app): State<Shared>, Path(short): Path<String>) -> Response {
    match crate::frontend::remove(&app.themes, &short) {
        Ok(()) => StatusCode::NO_CONTENT.into_response(),
        Err(e) => fail(e),
    }
}

/// Where a theme's saved settings live. Keyed by `short` in the database rather
/// than stored beside the theme, so updating, reinstalling or deleting the
/// theme leaves them in place, and a backup carries them.
fn theme_config_key(short: &str) -> String {
    format!("theme_config:{short}")
}

/// The settings saved for one theme in the panel: only the fields changed from
/// the defaults its `theme.json` declares, which the theme fills in itself.
/// Any theme may be named, installed or not, so a theme under development
/// reads its own settings from whichever hub it proxies to.
///
/// Anonymous, under the same condition as `/api/nodes`. One request is one
/// primary-key read answering at most 64 KiB, the router's body limit having
/// bounded the write. That is the cost class of `/api/me`, so there is no gate:
/// on a three-core hub (debug build), 120 concurrent requests for a 60 KiB
/// value held the panel's `/api/nodes` at a 230 ms median, against 160 ms
/// under the same load on `/api/me`.
///
/// A failed read answers 500 rather than `{}`: the panel saves on top of what
/// it reads, so an empty answer would erase every saved override.
pub async fn theme_config(
    State(app): State<Shared>,
    headers: HeaderMap,
    Path(short): Path<String>,
) -> Response {
    if !authed(&app, &headers) && !app.public_page() {
        return answer(StatusCode::UNAUTHORIZED, "需要登录后查看");
    }
    if !crate::frontend::valid_short(&short) {
        return StatusCode::NOT_FOUND.into_response();
    }
    match app.db.lookup(&theme_config_key(&short)) {
        Ok(saved) => {
            let saved = saved.unwrap_or_else(|| "{}".into());
            ([(header::CONTENT_TYPE, "application/json")], saved).into_response()
        }
        Err(e) => fail(e),
    }
}

/// Replaces a theme's saved settings. Values are not checked against the
/// theme's declared fields: the theme must validate what it reads regardless,
/// since a value saved under one version of the theme meets the next.
pub async fn save_theme_config(
    _: Admin,
    State(app): State<Shared>,
    Path(short): Path<String>,
    Json(values): Json<serde_json::Map<String, Value>>,
) -> Response {
    if !crate::frontend::valid_short(&short) || !crate::frontend::selectable(&app, &short) {
        return bad("主题没有安装");
    }
    match app.db.set(&theme_config_key(&short), &Value::Object(values).to_string()) {
        Ok(()) => StatusCode::NO_CONTENT.into_response(),
        Err(e) => fail(e),
    }
}

pub async fn themes(_: Admin, State(app): State<Shared>) -> Response {
    match crate::frontend::themes(&app) {
        Ok(mut themes) => {
            // Reads each image to answer, as serving it would: a handful of
            // themes, each image capped at 8 MiB.
            for theme in &mut themes {
                theme.preview = crate::frontend::preview(&app.themes, &theme.short).is_some();
            }
            Json(json!({"themes": themes})).into_response()
        }
        Err(e) => fail(e),
    }
}

/// Every live session, with the caller's own marked.
///
/// `id` is the stored SHA-256 of the session token rather than the token itself:
/// it identifies a row without being presentable as a cookie.
pub async fn sessions(_: Admin, State(app): State<Shared>, headers: HeaderMap) -> Response {
    let mine = current_session(&headers);
    match app.db.sessions() {
        Ok(rows) => Json(
            rows.into_iter()
                .map(|s| {
                    json!({
                        "current": mine.as_deref() == Some(s.token_hash.as_str()),
                        "created_at": issued_at(s.expires_at),
                        "expires_at": s.expires_at,
                        "ip": s.ip,
                        "user_agent": s.user_agent,
                        "id": s.token_hash,
                    })
                })
                .collect::<Vec<_>>(),
        )
        .into_response(),
        Err(e) => fail(e),
    }
}

/// 「退出所有设备」：踢除当前会话以外的全部登录。当前会话必须保留，
/// 否则按下按钮的人自己当场登出，与按钮语义不符。
pub async fn drop_other_sessions(_: Admin, State(app): State<Shared>, headers: HeaderMap) -> Response {
    let mine = current_session(&headers).unwrap_or_default();
    match app.db.drop_other_sessions(&mine) {
        Ok(n) => Json(json!({ "ok": true, "dropped": n })).into_response(),
        Err(e) => fail(e),
    }
}

/// Deleting a row that no longer exists is not an error: two panels open on the
/// same list both achieve the requested sign-out.
pub async fn delete_session(_: Admin, State(app): State<Shared>, Path(id): Path<String>) -> Response {
    match app.db.drop_session(&id) {
        Ok(()) => StatusCode::NO_CONTENT.into_response(),
        Err(e) => fail(e),
    }
}

pub async fn settings(_: Admin, State(app): State<Shared>) -> Json<Value> {
    let mut out = serde_json::Map::new();
    for key in READABLE_SETTINGS {
        out.insert((*key).to_owned(), json!(app.db.get(key).unwrap_or_default()));
    }
    // The one readable key with a default that also rejects the empty string:
    // `setting_error` below refuses "" and `save_settings` writes nothing when any
    // key fails, so a hub where this was never set returned "" here and then
    // rejected the entire settings form, naming a field that was never edited.
    // `retention_days()` already holds the default `prune` and the data page read,
    // so it answers here as well.
    out.insert("retention_days".into(), json!(app.db.retention_days().to_string()));
    // sing-box 全局默认版本：从未设置时回 1.14.2（计量走的 api service 是
    // 1.14+ 特性，面板按 1.14.2 实测）；显式清空合法 = 跟最新版，所以这里
    // 只对 None 回默认，Some("") 原样回给表单。
    out.insert(
        "singbox_default_version".into(),
        json!(app.db.get("singbox_default_version").unwrap_or_else(|| "1.14.2".into())),
    );
    // realm 全局默认版本：从未设置时回空（= 跟最新版，realm 无面板硬依赖的
    // 版本门槛，不像 sing-box 有 1.14+ 计量约束）。
    out.insert(
        "realm_default_version".into(),
        json!(app.db.get("realm_default_version").unwrap_or_else(|| "2.9.6".into())),
    );
    out.insert(
        "github_secret_set".into(),
        json!(app.db.get("github_client_secret").is_some_and(|v| !v.is_empty())),
    );
    // Cloudflare API Token（DDNS 一期）：同款掩码，值本体只写不读。
    out.insert("cf_api_token_set".into(), json!(app.db.get("cf_api_token").is_some_and(|v| !v.is_empty())));
    // Read-only here. A window is opened and closed through its own route, so the
    // key is always one the hub generated, and `save_settings` continues to refuse
    // both names.
    for key in ["register_key", "register_until"] {
        out.insert(key.into(), json!(app.db.get(key).unwrap_or_default()));
    }
    crate::notify::settings(&app, &mut out);
    Json(Value::Object(out))
}

/// Why one setting cannot be stored, or `None` when it can.
///
/// Separate from the write below because every key is validated before any is
/// written: changing the password drops every session, and a 400 raised
/// afterwards -- on a later key, in whatever order the map iterates -- carries no
/// Set-Cookie, signing the admin out of every device through a password change
/// the UI reported as rejected.
fn setting_error(app: &App, key: &str, value: &Value) -> Option<String> {
    // Settings are stored as text. A caller sending the natural JSON type --
    // `{"public_page": false}`, `{"retention_days": 7}` -- was formerly skipped by
    // a bare `continue`, so nothing was written while the response reported
    // success.
    let Some(value) = value.as_str() else { return Some(format!("设置 {key} 的值格式不对")) };
    match key {
        "theme" if !crate::frontend::selectable(app, value) => Some("主题没有安装".into()),
        // Housekeeping clamps whatever it reads, so an unparsable value would be
        // stored, echoed back, and silently mean 7 days indefinitely.
        "retention_days" if !value.parse::<i64>().is_ok_and(|d| (1..=3_650).contains(&d)) => {
            Some("历史保留天数要在 1 到 3650 之间".into())
        }
        // 安装命令与自动补装都要把它拼进 URL/参数，写歪了只会在某台新机的
        // 下载那一步才暴露；空串合法（= 跟最新版）。install.sh 同款校验。
        "singbox_default_version"
            if !value.is_empty() && !value.chars().all(|c| c.is_ascii_digit() || c == '.') =>
        {
            Some("sing-box 默认版本只能含数字和点（如 1.14.2），留空表示最新版".into())
        }
        "realm_default_version"
            if !value.is_empty() && !value.chars().all(|c| c.is_ascii_digit() || c == '.') =>
        {
            Some("realm 默认版本只能含数字和点（如 2.9.6），留空表示最新版".into())
        }
        // The hub fetches this URL itself, so it must be one: a scheme it cannot
        // speak turns every agent download into a 502 that says nothing about the
        // setting responsible.
        //
        // https only. What returns from this host is the agent binary, which
        // `install.sh` writes to /opt/monitor and starts on every node provisioned
        // here; over http:// anyone on the path between the hub and the mirror
        // chooses that binary, while the node still sees a valid TLS connection to
        // the hub.
        "github_proxy" if !(value.is_empty() || value.starts_with("https://")) => {
            Some("GitHub 代理必须以 https:// 开头：agent 程序经它下载，再安装到每个节点".into())
        }
        // 每行都得是一个可解析的入口，一个写错全部订阅跟着坏，宁可当场拒。
        "sub_hosts"
            if value.lines().any(|l| !l.trim().is_empty() && crate::proxy::parse_front(l).is_none()) =>
        {
            Some("订阅入口地址有误：每行一个 host[:port]，可选 http(s):// 前缀".into())
        }
        // 出口探测目标：hub 与每台节点机的 agent 都要能请求它，必须是 http(s)；
        // 留空走默认（gstatic generate_204）。
        "exit_probe_url"
            if !(value.is_empty() || (value.starts_with("http://") || value.starts_with("https://"))) =>
        {
            Some("探测目标必须是 http:// 或 https:// 开头的 URL，留空用默认".into())
        }
        "conn_log_retention" if !value.parse::<i64>().is_ok_and(|d| (1..=90).contains(&d)) => {
            Some("连接日志保留期要在 1 到 90 天之间".into())
        }
        "admin_password" if value.len() < 12 => Some("密码至少 12 位".into()),
        "admin_password" => None,
        k if k.starts_with("notify_") => crate::notify::setting_error(k, value),
        k if READABLE_SETTINGS.contains(&k) || k == "github_client_secret" || k == "cf_api_token" => None,
        _ => Some(format!("没有这个设置项：{key}")),
    }
}

pub async fn save_settings(
    _: Admin,
    State(app): State<Shared>,
    ConnectInfo(peer): ConnectInfo<std::net::SocketAddr>,
    headers: HeaderMap,
    Json(body): Json<Value>,
) -> Response {
    let Some(map) = body.as_object() else { return bad("设置格式不对") };
    for (key, value) in map {
        if let Some(message) = setting_error(&app, key, value) {
            return bad(&message);
        }
    }
    // Set when the password changed, so the caller receives a fresh session rather
    // than being logged out by their own change.
    let mut reissued = String::new();
    for (key, value) in map {
        let value = value.as_str().unwrap_or_default();
        // Changing the password logs out every existing session; the caller
        // receives a replacement.
        if key == "admin_password" {
            match hash_password(value).and_then(|h| {
                app.db.replace_password(&h)?;
                issue_session(&app, &headers, peer.ip())
            }) {
                Ok(cookie) => reissued = cookie,
                Err(e) => return fail(e),
            }
            continue;
        }
        if let Err(e) = app.db.set(key, value) {
            return fail(e);
        }
    }
    with_cookies(Json(json!({"ok": true})), [reissued])
}

// ---- 代理协议（设计文档 8-10）----

/// One node rendered for the panel: fields, credentials, and each credential's
/// share link. The host comes from `proxy::public_host`, so links copied from
/// the browser carry the address the panel itself was reached on.
fn proxy_node_view(host: &str, bundle: &crate::db::NodeBundle) -> Value {
    let users: Vec<Value> = bundle
        .users
        .iter()
        .map(|u| {
            json!({
                "id": u.id,
                "name": u.name,
                "credential": u.credential,
                "sub_user_id": u.sub_user_id,
                "created_at": u.created_at,
                // 凭据级限额/到期（方向 40）：漏发会让限额弹窗永远回显为空，
                // 看起来像保存失败（库里其实写成功了）。
                "expires_at": u.expires_at,
                "quota_bytes": u.quota_bytes,
                "link": proxy::share_link(
                    bundle,
                    u,
                    &proxy::Front { host: host.to_owned(), port: None, scheme: "https".into() },
                    "",
                )
                .unwrap_or_default(),
            })
        })
        .collect();
    json!({
        "id": bundle.node.id,
        "name": bundle.node.name,
        "protocol": bundle.node.protocol,
        "listen_port": bundle.node.listen_port,
        "sni": bundle.node.sni,
        "flow": bundle.node.flow,
        "method": bundle.node.method,
        "server_id": bundle.node.server_id,
        "remark": bundle.node.remark,
        "egress_type": bundle.node.egress_type,
        "egress_host": bundle.node.egress_host,
        "egress_port": bundle.node.egress_port,
        "egress_username": bundle.node.egress_username,
        "egress_password": bundle.node.egress_password,
        "enabled": bundle.node.enabled,
        "rate_up": bundle.node.rate_up,
        "rate_down": bundle.node.rate_down,
        "dns_name": bundle.node.dns_name,
        "dns_server_id": bundle.node.dns_server_id,
        "dns_ip": bundle.node.dns_ip,
        "public_key": bundle.secret.public_key,
        "short_id": bundle.secret.short_id,
        "reality_private_key": if bundle.node.protocol == "vless-reality" { json!(bundle.secret.private_key) } else { Value::Null },
        "uuid": bundle.users.iter().find(|u| u.name == "default").map(|u| u.credential.clone()).unwrap_or_default(),
        "users": users,
    })
}

#[derive(Deserialize)]
pub struct ProxyCredentialQuery {
    kind: String,
}

/// Generates one Reality advanced credential for the authenticated admin UI.
pub async fn proxy_random_credential(_: Admin, Query(query): Query<ProxyCredentialQuery>) -> Response {
    match query.kind.as_str() {
        "uuid" => Json(json!({ "uuid": proxy::new_uuid() })).into_response(),
        "short_id" => Json(json!({ "short_id": proxy::new_short_id() })).into_response(),
        "reality" => {
            let (private_key, public_key) = proxy::generate_reality_keypair();
            Json(json!({ "private_key": private_key, "public_key": public_key })).into_response()
        }
        _ => bad("不支持的凭据类型"),
    }
}

/// 分享链接的拨号地址（切换主机）：节点绑了域名用域名（换 IP/换主机不换
/// 链接），未绑出机器 IP。
fn node_link_host(
    app: &crate::App,
    bundle: &crate::db::NodeBundle,
    headers: Option<&axum::http::HeaderMap>,
) -> String {
    match bundle.node.dns_name.trim() {
        d if !d.is_empty() => d.to_owned(),
        _ => proxy::node_dial_host(app, bundle.node.server_id, headers),
    }
}

pub async fn proxy_nodes(_: Admin, State(app): State<Shared>, headers: HeaderMap) -> Response {
    match app.db.proxy_node_bundles() {
        Ok(bundles) => {
            let nodes: Vec<Value> = bundles
                .iter()
                .map(|b| {
                    let host = node_link_host(&app, b, Some(&headers));
                    proxy_node_view(&host, b)
                })
                .collect();
            let host = proxy::public_host(&app, Some(&headers));
            // 版本过旧黄条（二期）：每台涉协议服务器的 sing-box 版本。本机读
            // 本地状态（缓存为空时现场探测一次——版本探测原本随已删的
            // /proxy/cores 触发）；远程读缓存（隧道页状态查询/安装/补装时刷
            // 新）——没触点过的远程机器无行，黄条不误报。
            let mut local_version = { app.proxy.lock().unwrap_or_else(|e| e.into_inner()).version.clone() };
            if local_version.is_empty() {
                let bin = proxy::binary_path(&app);
                if bin.is_file() {
                    match proxy::detect_version(&bin).await {
                        Ok(v) => {
                            app.proxy.lock().unwrap_or_else(|e| e.into_inner()).version = v.clone();
                            let _ = app.db.set("proxy_core_version", &v);
                            local_version = v;
                        }
                        Err(e) => tracing::warn!("version detect failed: {e:#}"),
                    }
                }
            }
            let mut cores: Vec<Value> = Vec::new();
            if !local_version.is_empty() {
                let stale = proxy::version_stale(&local_version);
                cores.push(json!({ "server_id": 0, "version": local_version, "stale": stale }));
            }
            let mut seen = std::collections::BTreeSet::new();
            {
                let remote = app.proxy_remote.lock().unwrap_or_else(|e| e.into_inner());
                for b in &bundles {
                    let server_id = b.node.server_id;
                    if server_id != 0 && seen.insert(server_id) {
                        if let Some(st) = remote.get(&server_id) {
                            if !st.version.is_empty() {
                                cores.push(json!({ "server_id": server_id, "version": st.version, "stale": proxy::version_stale(&st.version) }));
                            }
                        }
                    }
                }
            }
            Json(json!({ "host": host, "nodes": nodes, "cores": cores })).into_response()
        }
        Err(e) => fail(e),
    }
}

pub async fn create_proxy_node(
    _: Admin,
    State(app): State<Shared>,
    body: Result<Json<Value>, JsonRejection>,
) -> Response {
    let Json(value) = match body {
        Ok(b) => b,
        Err(_) => return bad("请求格式不对"),
    };
    let mut node: ProxyNode = match serde_json::from_value(value.clone()) {
        Ok(n) => n,
        Err(_) => return bad("请求格式不对"),
    };
    if !value.get("flow").is_some() && node.protocol == "vless-reality" {
        node.flow = "xtls-rprx-vision".into();
    }
    let server_id = node.server_id;
    match proxy::create_node(&app, node).await {
        Ok(id) => {
            let applied = proxy::apply_if_ready(&app).await;
            // 限速下发不阻塞创建响应：远端 agent 慢/离线时这一步可达 30s，
            // 用户会以为「没反应」。后台执行，失败只记日志（tc 期望已在库，
            // 下次该服务器的任何限速操作会重建）。
            let app2 = app.clone();
            tokio::spawn(async move {
                if let Err(e) = crate::shaper::apply_for_server(&app2, server_id).await {
                    tracing::warn!("[shaper] create 后台下发失败: {e:#}");
                }
            });
            Json(json!({ "id": id, "applied": applied })).into_response()
        }
        Err(e) => fail(e),
    }
}

pub async fn update_proxy_node(
    _: Admin,
    State(app): State<Shared>,
    Path(id): Path<i64>,
    body: Result<Json<Value>, JsonRejection>,
) -> Response {
    let Json(value) = match body {
        Ok(b) => b,
        Err(_) => return bad("请求格式不对"),
    };
    let mut node: ProxyNode = match serde_json::from_value(value.clone()) {
        Ok(n) => n,
        Err(_) => return bad("请求格式不对"),
    };
    node.id = id;
    if !value.get("flow").is_some() {
        if let Ok(Some(current)) = app.db.proxy_node(id) {
            node.flow = current.flow;
        }
    }
    // 端口/服务器都可能变更：新旧两台都要收敛限速规则。
    let mut shaper_servers = vec![node.server_id];
    if let Ok(Some(current)) = app.db.proxy_node(id) {
        if !shaper_servers.contains(&current.server_id) {
            shaper_servers.push(current.server_id);
        }
    }
    match proxy::update_node(&app, node).await {
        Ok(()) => {
            let applied = proxy::apply_if_ready(&app).await;
            // 同 create：限速下发后台化，远端慢不拖累保存响应。
            let app2 = app.clone();
            let sids = shaper_servers.clone();
            tokio::spawn(async move {
                for sid in sids {
                    if let Err(e) = crate::shaper::apply_for_server(&app2, sid).await {
                        tracing::warn!("[shaper] update 后台下发失败: {e:#}");
                    }
                }
            });
            Json(json!({ "ok": true, "applied": applied })).into_response()
        }
        Err(e) => fail(e),
    }
}

pub async fn delete_proxy_node(_: Admin, State(app): State<Shared>, Path(id): Path<i64>) -> Response {
    let server_id = app.db.proxy_node(id).ok().flatten().map(|n| n.server_id);
    match app.db.delete_proxy_node(id) {
        Ok(()) => {
            let applied = proxy::apply_if_ready(&app).await;
            let mut shaper_err = None;
            if let Some(sid) = server_id {
                if let Err(e) = crate::shaper::apply_for_server(&app, sid).await {
                    shaper_err = Some(e.to_string());
                }
            }
            Json(json!({ "ok": true, "applied": applied, "shaper": shaper_err })).into_response()
        }
        Err(e) => fail(e),
    }
}

#[derive(Deserialize)]
pub struct ProxySwitchBody {
    pub server_id: i64,
}

/// 切换主机（抗墙）：节点同参数渲染到目标机 + 域名 A 记录翻过去。流程与
/// 失败语义见 proxy::switch_node——DNS 最后翻，失败客户端零感知。
pub async fn switch_proxy_node(
    _: Admin,
    State(app): State<Shared>,
    Path(id): Path<i64>,
    body: Result<Json<ProxySwitchBody>, JsonRejection>,
) -> Response {
    let Json(b) = match body {
        Ok(b) => b,
        Err(_) => return bad("请求格式不对"),
    };
    match proxy::switch_node(&app, id, b.server_id).await {
        Ok(v) => Json(v).into_response(),
        Err(e) => fail(e),
    }
}

/// Adds a credential under a node. An empty credential is generated for the
/// protocol (a UUID for vless-reality, a random password otherwise).
pub async fn create_proxy_node_user(
    _: Admin,
    State(app): State<Shared>,
    Path(id): Path<i64>,
    body: Result<Json<ProxyUser>, JsonRejection>,
) -> Response {
    let Json(user) = match body {
        Ok(b) => b,
        Err(_) => return bad("请求格式不对"),
    };
    let name = user.name.trim().to_owned();
    if name.is_empty() {
        return bad("请填写用户名");
    }
    let protocol = match app.db.proxy_node(id) {
        Ok(Some(n)) => n,
        Ok(None) => return no_such_node(),
        Err(e) => return fail(e),
    };
    if protocol.protocol == "shadowsocks" {
        return bad("Shadowsocks 节点为单凭据，需要更多用户请另建节点");
    }
    // v2ray 计数器按用户名聚合（M7 用户级流量记账的前提），同一台服务器上
    // 重名会把两份用量记到一起，创建时就拒绝。
    match app.db.proxy_user_name_taken(protocol.server_id, &name, id) {
        Ok(true) => return bad("同一台服务器上已有同名用户，请换一个名字"),
        Ok(false) => {}
        Err(e) => return fail(e),
    }
    let credential = if user.credential.trim().is_empty() {
        if protocol.protocol == "vless-reality" {
            proxy::new_uuid()
        } else {
            proxy::new_password()
        }
    } else {
        user.credential.trim().to_owned()
    };
    match app.db.create_proxy_user(id, &name, &credential) {
        Ok(uid) => {
            let applied = proxy::apply_if_ready(&app).await;
            Json(json!({ "id": uid, "applied": applied })).into_response()
        }
        Err(e) => fail(e),
    }
}

pub async fn delete_proxy_node_user(
    _: Admin,
    State(app): State<Shared>,
    Path((id, uid)): Path<(i64, i64)>,
) -> Response {
    // The path carries the node id only to keep the URL honest; the credential
    // must belong to it.
    match app.db.proxy_node(id) {
        Ok(Some(_)) => {}
        Ok(None) => return no_such_node(),
        Err(e) => return fail(e),
    }
    match app.db.delete_proxy_user(uid) {
        Ok(()) => {
            let applied = proxy::apply_if_ready(&app).await;
            Json(json!({ "ok": true, "applied": applied })).into_response()
        }
        Err(e) => fail(e),
    }
}

/// Claims (or releases, with null) a credential for a subscription customer.
/// 单凭据轮换（管理端）：原行原名换新值（vless 系新 UUID/其余新密码，计量
/// 历史连续），配置自动下发。用这条凭据的设备掉线，重新拉订阅即恢复。
pub async fn rotate_proxy_user(
    _: Admin,
    State(app): State<Shared>,
    Path((node_id, uid)): Path<(i64, i64)>,
) -> Response {
    // 凭据必须属于路径上的节点（URL 语义诚实）。
    let bundles = match app.db.proxy_node_bundles() {
        Ok(b) => b,
        Err(e) => return fail(e),
    };
    let Some(bundle) = bundles.iter().find(|b| b.node.id == node_id) else {
        return no_such_node();
    };
    let Some(_user) = bundle.users.iter().find(|u| u.id == uid) else {
        return bad("凭据不存在或不属于该节点");
    };
    let credential = if bundle.node.protocol == "vless-reality" {
        crate::proxy::new_uuid()
    } else {
        crate::proxy::new_password()
    };
    if let Err(e) = app.db.update_proxy_user_credential(uid, &credential) {
        return fail(e);
    }
    let applied = proxy::apply_if_ready(&app).await;
    Json(json!({ "ok": true, "applied": applied })).into_response()
}

pub async fn set_proxy_user_sub(
    _: Admin,
    State(app): State<Shared>,
    Path(uid): Path<i64>,
    body: Result<Json<Value>, JsonRejection>,
) -> Response {
    let Json(body) = match body {
        Ok(b) => b,
        Err(_) => return bad("请求格式不对"),
    };
    let sub_user_id = match body.get("sub_user_id") {
        None | Some(Value::Null) => None,
        Some(Value::Number(n)) => match n.as_i64() {
            Some(id) => Some(id),
            None => return bad("sub_user_id 不是整数"),
        },
        Some(_) => return bad("sub_user_id 格式不对"),
    };
    if let Some(sid) = sub_user_id {
        match app.db.sub_user(sid) {
            Ok(Some(_)) => {}
            Ok(None) => return bad("订阅客户不存在，可能已被删除"),
            Err(e) => return fail(e),
        }
    }
    match app.db.set_proxy_user_sub(uid, sub_user_id) {
        Ok(()) => {
            // 认领/释放都改变渲染出的凭据集合；失格客户的凭据反正进不了
            // 配置，这里照常 apply，由 gated_bundles 统一裁决。
            let applied = proxy::apply_if_ready(&app).await;
            Json(json!({ "ok": true, "applied": applied })).into_response()
        }
        Err(e) => fail(e),
    }
}

#[derive(Deserialize)]
pub struct ProxyCoreQuery {
    server_id: Option<i64>,
}

/// 每台服务器的核心状态卡：本机 + 出现在代理节点里或 agent 在线的服务器。
pub async fn proxy_cores(_: Admin, State(app): State<Shared>) -> Response {
    let mut list: Vec<Value> = Vec::new();
    let mut card = serde_json::Map::new();
    card.insert("server_id".into(), json!(0));
    card.insert("name".into(), json!("本机"));
    let bin = proxy::binary_path(&app);
    if bin.is_file() {
        let unknown = { app.proxy.lock().unwrap().version.is_empty() };
        if unknown {
            match proxy::detect_version(&bin).await {
                Ok(v) => {
                    app.proxy.lock().unwrap().version = v.clone();
                    let _ = app.db.set("proxy_core_version", &v);
                }
                Err(e) => tracing::warn!("version detect failed: {e:#}"),
            }
        }
    }
    if let Value::Object(m) = proxy::status(&app) {
        for (k, v) in m {
            card.insert(k, v);
        }
    }
    list.push(Value::Object(card));
    // 按用户的设计（M3.5）：远程服务器的核心全自动，代理协议页只展示本机卡。
    Json(Value::Array(list)).into_response()
}

pub async fn proxy_core_status(
    _: Admin,
    State(app): State<Shared>,
    Query(q): Query<ProxyCoreQuery>,
) -> Response {
    let server_id = q.server_id.unwrap_or(0);
    if server_id != 0 {
        return match proxy::remote_status(&app, server_id).await {
            Ok(v) => Json(v).into_response(),
            Err(e) => fail(e),
        };
    }
    let bin = proxy::binary_path(&app);
    if bin.is_file() {
        let unknown = { app.proxy.lock().unwrap().version.is_empty() };
        if unknown {
            match proxy::detect_version(&bin).await {
                Ok(v) => {
                    app.proxy.lock().unwrap().version = v.clone();
                    let _ = app.db.set("proxy_core_version", &v);
                }
                Err(e) => tracing::warn!("version detect failed: {e:#}"),
            }
        }
    }
    Json(proxy::status(&app)).into_response()
}

pub async fn proxy_core_install(
    _: Admin,
    State(app): State<Shared>,
    body: Result<Json<Value>, JsonRejection>,
) -> Response {
    let (want, server_id) = match &body {
        Ok(Json(v)) => (v["version"].as_str().map(str::to_owned), v["server_id"].as_i64().unwrap_or(0)),
        Err(_) => (None, 0),
    };
    if server_id != 0 {
        return match proxy::install_remote(&app, server_id, want).await {
            Ok(version) => {
                let applied = proxy::apply_if_ready(&app).await;
                Json(json!({ "version": version, "applied": applied })).into_response()
            }
            Err(e) => fail(e),
        };
    }
    match proxy::install_core(&app, want).await {
        Ok(version) => {
            let applied = proxy::apply_if_ready(&app).await;
            Json(json!({ "version": version, "applied": applied })).into_response()
        }
        Err(e) => fail(e),
    }
}

pub async fn proxy_core_start(
    _: Admin,
    State(app): State<Shared>,
    Query(q): Query<ProxyCoreQuery>,
) -> Response {
    let server_id = q.server_id.unwrap_or(0);
    let result = if server_id == 0 {
        proxy::start(&app).await
    } else {
        proxy::set_desired_remote(&app, server_id, true).await
    };
    match result {
        Ok(()) => Json(json!({ "ok": true })).into_response(),
        Err(e) => fail(e),
    }
}

pub async fn proxy_core_stop(
    _: Admin,
    State(app): State<Shared>,
    Query(q): Query<ProxyCoreQuery>,
) -> Response {
    let server_id = q.server_id.unwrap_or(0);
    let result = if server_id == 0 {
        proxy::stop(&app).await
    } else {
        proxy::set_desired_remote(&app, server_id, false).await
    };
    match result {
        Ok(()) => Json(json!({ "ok": true })).into_response(),
        Err(e) => fail(e),
    }
}

pub async fn proxy_apply(_: Admin, State(app): State<Shared>) -> Response {
    match proxy::apply(&app).await {
        Ok(()) => Json(json!({ "ok": true })).into_response(),
        Err(e) => fail(e),
    }
}

/// 管理端：切换单个客户的用户中心页开关。
pub async fn set_user_page(
    _: Admin,
    State(app): State<Shared>,
    Path(id): Path<i64>,
    body: Result<Json<Value>, JsonRejection>,
) -> Response {
    let Json(body) = match body {
        Ok(b) => b,
        Err(_) => return bad("请求格式不对"),
    };
    let on = body.get("on").and_then(Value::as_bool).unwrap_or(true);
    match app.db.set_sub_user_page(id, on) {
        Ok(()) => Json(json!({ "ok": true })).into_response(),
        Err(e) => fail(e),
    }
}

/// 客户的 agent 分发开关：开启后 agent 分发端口可回源该客户的订阅（/api/sub）。
pub async fn set_sub_user_agent_dist(
    _: Admin,
    State(app): State<Shared>,
    Path(id): Path<i64>,
    body: Result<Json<Value>, JsonRejection>,
) -> Response {
    let Json(body) = match body {
        Ok(b) => b,
        Err(_) => return bad("请求格式不对"),
    };
    let on = body.get("on").and_then(Value::as_bool).unwrap_or(false);
    match app.db.set_sub_user_agent_dist(id, on) {
        Ok(()) => Json(json!({ "ok": true })).into_response(),
        Err(e) => fail(e),
    }
}

/// 客户的 /u/ 视图模式（方向 40）：overview 总览 / per_node 逐节点明细。
pub async fn set_sub_user_view_mode(
    _: Admin,
    State(app): State<Shared>,
    Path(id): Path<i64>,
    body: Result<Json<Value>, JsonRejection>,
) -> Response {
    let Json(body) = match body {
        Ok(b) => b,
        Err(_) => return bad("请求格式不对"),
    };
    let mode = body.get("mode").and_then(Value::as_str).unwrap_or("overview");
    if mode != "overview" && mode != "per_node" {
        return bad("视图模式只支持 overview / per_node");
    }
    match app.db.set_sub_user_view_mode(id, mode) {
        Ok(()) => Json(json!({ "ok": true, "mode": mode })).into_response(),
        Err(e) => fail(e),
    }
}

/// 凭据级限额/到期（方向 40）：保存 分配关系 上的 到期日期与流量配额。
/// expires_at 空串=NULL（跟随客户级到期）；quota_bytes 0=不限。
pub async fn set_proxy_user_limits(
    _: Admin,
    State(app): State<Shared>,
    Path(uid): Path<i64>,
    body: Result<Json<Value>, JsonRejection>,
) -> Response {
    let Json(body) = match body {
        Ok(b) => b,
        Err(_) => return bad("请求格式不对"),
    };
    let expires_at = body["expires_at"].as_str().map(|s| s.trim().to_owned()).filter(|s| !s.is_empty());
    let quota_bytes = body["quota_bytes"].as_i64().unwrap_or(0).max(0);
    let quota_reset = if quota_bytes > 0 { "monthly" } else { "" };
    if let Some(exp) = &expires_at {
        if chrono::NaiveDate::parse_from_str(exp, "%Y-%m-%d").is_err() {
            return bad("到期日期格式应为 YYYY-MM-DD");
        }
    }
    match app.db.set_proxy_user_limits(uid, expires_at, quota_bytes, quota_reset) {
        Ok(()) => Json(json!({ "ok": true })).into_response(),
        Err(e) => fail(e),
    }
}

/// 协议级分配（幂等）：把一条协议整体分配给客户或取消。
///
/// 分配 = 该客户在此协议上没有绑定凭据时自动创建一条（名字 `客户名·协议名`，
/// 同服务器唯一；vless 系生成 UUID、其余生成密码），绑定给客户；已有绑定则原样
/// 返回。Shadowsocks 为单凭据协议，不能创建第二条——有空闲凭据就绑定它，被别
/// 人占用则拒绝。
///
/// 取消 = 删除该客户在此协议上的全部绑定凭据（从端口配置摘除，UUID 立即失效）。
/// Shadowsocks 例外：解绑不删除（删掉唯一凭据会让节点永远无法再分配）。
/// 注意未绑定凭据（如 default）始终在端口配置里保持可连接——这是既有行为。
pub async fn assign_sub_node(
    _: Admin,
    State(app): State<Shared>,
    Path((sub_id, node_id)): Path<(i64, i64)>,
    body: Result<Json<Value>, JsonRejection>,
) -> Response {
    let Json(body) = match body {
        Ok(b) => b,
        Err(_) => return bad("请求格式不对"),
    };
    let Some(on) = body["on"].as_bool() else {
        return bad("缺少 on");
    };
    let Some(sub) = app.db.sub_user(sub_id).ok().flatten() else {
        return bad("客户不存在或已删除");
    };
    let bundles = match app.db.proxy_node_bundles() {
        Ok(b) => b,
        Err(e) => return fail(e),
    };
    let Some(bundle) = bundles.iter().find(|b| b.node.id == node_id) else {
        return no_such_node();
    };
    let bound: Vec<_> = bundle.users.iter().filter(|u| u.sub_user_id == Some(sub_id)).collect();

    if !on {
        if bound.is_empty() {
            return Json(json!({ "ok": true, "removed": 0 })).into_response();
        }
        // Shadowsocks 唯一凭据删不得（单凭据协议无法再创建），解绑保留。
        if bundle.node.protocol == "shadowsocks" {
            for u in &bound {
                if let Err(e) = app.db.set_proxy_user_sub(u.id, None) {
                    return fail(e);
                }
            }
            let applied = proxy::apply_if_ready(&app).await;
            return Json(json!({ "ok": true, "removed": bound.len(), "applied": applied })).into_response();
        }
        for u in &bound {
            if let Err(e) = app.db.delete_proxy_user(u.id) {
                return fail(e);
            }
        }
        let applied = proxy::apply_if_ready(&app).await;
        return Json(json!({ "ok": true, "removed": bound.len(), "applied": applied })).into_response();
    }

    // 已绑定：幂等返回。
    if let Some(u) = bound.first() {
        return Json(json!({ "ok": true, "created": false, "credential": u.name, "applied": true }))
            .into_response();
    }
    // Shadowsocks：不能建第二条凭据——有空闲凭据就绑，被占用则拒绝。
    if bundle.node.protocol == "shadowsocks" {
        if let Some(idle) = bundle.users.iter().find(|u| u.sub_user_id.is_none()) {
            if let Err(e) = app.db.set_proxy_user_sub(idle.id, Some(sub_id)) {
                return fail(e);
            }
            let applied = proxy::apply_if_ready(&app).await;
            return Json(
                json!({ "ok": true, "created": false, "credential": idle.name, "applied": applied }),
            )
            .into_response();
        }
        return bad("Shadowsocks 节点为单凭据，且已分配给其他客户");
    }
    let name = format!("{}·{}", sub.name, bundle.node.name);
    match app.db.proxy_user_name_taken(bundle.node.server_id, &name, node_id) {
        Ok(true) => return bad("同一台服务器上已有同名用户，请换一个客户名"),
        Ok(false) => {}
        Err(e) => return fail(e),
    }
    let credential =
        if bundle.node.protocol == "vless-reality" { proxy::new_uuid() } else { proxy::new_password() };
    let uid = match app.db.create_proxy_user(node_id, &name, &credential) {
        Ok(uid) => uid,
        Err(e) => return fail(e),
    };
    if let Err(e) = app.db.set_proxy_user_sub(uid, Some(sub_id)) {
        return fail(e);
    }
    let applied = proxy::apply_if_ready(&app).await;
    Json(json!({ "ok": true, "created": true, "credential": name, "applied": applied })).into_response()
}

pub async fn proxy_sub_users(_: Admin, State(app): State<Shared>) -> Response {
    match app.db.sub_users() {
        Ok(users) => {
            // 行内字段之外补一个实时状态：停用/到期/超额由行内数据动态判定，
            // 前端不做第二份判定逻辑。
            let today = crate::proxy::today();
            let list: Vec<Value> = users
                .iter()
                .map(|s| {
                    let mut v = serde_json::to_value(s).unwrap_or_default();
                    v["status"] = json!(crate::proxy::sub_status(s, today).label());
                    v
                })
                .collect();
            Json(json!(list)).into_response()
        }
        Err(e) => fail(e),
    }
}

pub async fn create_proxy_sub_user(
    _: Admin,
    State(app): State<Shared>,
    body: Result<Json<Value>, JsonRejection>,
) -> Response {
    let Json(body) = match body {
        Ok(b) => b,
        Err(_) => return bad("请求格式不对"),
    };
    let name = body["name"].as_str().unwrap_or_default().trim().to_owned();
    if name.is_empty() {
        return bad("请填写客户名称");
    }
    // 可选的内容方案：创建时即可绑定（订阅内容=方案渲染+客户凭据）。
    let profile_id = match body["profile_id"].as_i64() {
        Some(pid) => match app.db.sub_profile(pid) {
            Ok(Some(_)) => Some(pid),
            Ok(None) => return bad("内容方案不存在"),
            Err(e) => return fail(e),
        },
        None => None,
    };
    // 可选的默认配额/到期（新建弹窗带默认值：1024GB + 次月今日）；配额>0 时
    // 默认每月重置（与凭据限额端点同口径），日期格式校验同款。
    let expires_at = body["expires_at"].as_str().map(|s| s.trim().to_owned()).filter(|s| !s.is_empty());
    if let Some(exp) = &expires_at {
        if chrono::NaiveDate::parse_from_str(exp, "%Y-%m-%d").is_err() {
            return bad("到期日期格式应为 YYYY-MM-DD");
        }
    }
    let quota_bytes = body["quota_bytes"].as_i64().unwrap_or(0).max(0);
    match app.db.create_sub_user_full(&name, &crate::auth::random_token(), profile_id) {
        Ok(id) => {
            if expires_at.is_some() || quota_bytes > 0 {
                let mut s = match app.db.sub_user(id) {
                    Ok(Some(s)) => s,
                    Ok(None) => return bad("客户创建后读取失败"),
                    Err(e) => return fail(e),
                };
                s.expires_at = expires_at;
                if quota_bytes > 0 {
                    s.quota_bytes = quota_bytes;
                    s.quota_reset = "monthly".into();
                }
                if let Err(e) = app.db.update_sub_user(id, &s) {
                    return fail(e);
                }
            }
            Json(json!({ "id": id })).into_response()
        }
        Err(e) => fail(e),
    }
}

pub async fn update_proxy_sub_user(
    _: Admin,
    State(app): State<Shared>,
    Path(id): Path<i64>,
    body: Result<Json<SubUser>, JsonRejection>,
) -> Response {
    let Json(sub) = match body {
        Ok(b) => b,
        Err(_) => return bad("请求格式不对"),
    };
    let name = sub.name.trim().to_owned();
    if name.is_empty() {
        return bad("请填写客户名称");
    }
    if sub.quota_bytes < 0 {
        return bad("流量配额不能为负，不限额请填 0");
    }
    if !matches!(sub.quota_reset.as_str(), "" | "monthly") {
        return bad("重置方式只支持留空（一次性总量）或 monthly（每月重置）");
    }
    let mut sub = sub;
    sub.name = name;
    match app.db.update_sub_user(id, &sub) {
        Ok(()) => {
            // 恢复一个被摘除的客户（启停、调大额度）与摘除一样都改变渲染
            // 结果，走同一条 apply 路径把所有服务器推向新的期望配置。
            let applied = proxy::apply_if_ready(&app).await;
            Json(json!({ "ok": true, "applied": applied })).into_response()
        }
        Err(e) => fail(e),
    }
}

pub async fn delete_proxy_sub_user(_: Admin, State(app): State<Shared>, Path(id): Path<i64>) -> Response {
    match app.db.delete_sub_user(id) {
        Ok(()) => Json(json!({ "ok": true })).into_response(),
        Err(e) => fail(e),
    }
}

/// 续期：从当前到期时间往后推一个月（按用户拍板，不以今天为基准——长过期
/// 客户续一个月仍可能过期，属预期）。未设置到期时间（不限）的客户无从续起。
pub async fn renew_sub_user(_: Admin, State(app): State<Shared>, Path(id): Path<i64>) -> Response {
    let Some(sub) = app.db.sub_user(id).ok().flatten() else {
        return bad("客户不存在或已删除");
    };
    let Some(exp) = sub.expires_at.as_deref().filter(|s| !s.is_empty()) else {
        return bad("该客户未设置到期时间，无法续期");
    };
    let d = match chrono::NaiveDate::parse_from_str(exp, "%Y-%m-%d") {
        Ok(d) => d,
        Err(_) => return bad("到期日期格式异常"),
    };
    // 月末边界由 chrono 钳制（1/31 + 1月 → 2/28）。
    let Some(next) = d.checked_add_months(chrono::Months::new(1)) else {
        return bad("续期计算失败");
    };
    let next = next.format("%Y-%m-%d").to_string();
    let mut s = sub;
    s.expires_at = Some(next.clone());
    match app.db.update_sub_user(id, &s) {
        Ok(()) => {
            // 过期客户续期后凭据要回到端口配置，走与启停/保存同一条 apply 路径。
            let applied = proxy::apply_if_ready(&app).await;
            Json(json!({ "ok": true, "expires_at": next, "applied": applied })).into_response()
        }
        Err(e) => fail(e),
    }
}

/// 节点续期（概览续费日历的「我已续费」）：从当前到期日顺延一个付款周期
/// （billing_cycle 折月数，无周期按 1 个月；月末边界由 chrono 钳制）。只动
/// 面板侧的日期，无下发副作用。
pub async fn renew_node(_: Admin, State(app): State<Shared>, Path(id): Path<i64>) -> Response {
    let node = match app.db.node(id) {
        Ok(Some(n)) => n,
        Ok(None) => return no_such_node(),
        Err(e) => return fail(e),
    };
    let Some(exp) = node.expires_at.as_deref().filter(|s| !s.is_empty()) else {
        return bad("该节点未设置到期时间，无法续期");
    };
    let d = match NaiveDate::parse_from_str(exp, "%Y-%m-%d") {
        Ok(d) => d,
        Err(_) => return bad("到期日期格式异常"),
    };
    let months = crate::cycle_months(&node.billing_cycle).unwrap_or(1);
    let Some(next) = d.checked_add_months(chrono::Months::new(months)) else {
        return bad("续期计算失败");
    };
    let next = next.format("%Y-%m-%d").to_string();
    let patch = crate::db::NodePatch { expires_at: Some(Some(next.clone())), ..Default::default() };
    match app.db.update_node(id, &patch) {
        Ok(true) => {
            invalidate_snapshot(&app);
            Json(json!({ "ok": true, "expires_at": next })).into_response()
        }
        Ok(false) => no_such_node(),
        Err(e) => fail(e),
    }
}

pub async fn reset_proxy_sub_token(_: Admin, State(app): State<Shared>, Path(id): Path<i64>) -> Response {
    let token = crate::auth::random_token();
    match app.db.reset_sub_token(id, &token) {
        Ok(()) => Json(json!({ "token": token })).into_response(),
        Err(e) => fail(e),
    }
}

/// 自助重置配置（管理端编辑弹窗）：开关 + 次数上限。
pub async fn set_sub_user_self_reset(
    _: Admin,
    State(app): State<Shared>,
    Path(id): Path<i64>,
    body: Result<Json<Value>, JsonRejection>,
) -> Response {
    let Json(body) = match body {
        Ok(b) => b,
        Err(_) => return bad("请求格式不对"),
    };
    let allow = body["allow"].as_bool().unwrap_or(false);
    let limit = body["limit"].as_i64().unwrap_or(3).max(0);
    match app.db.set_sub_user_self_reset(id, allow, limit) {
        Ok(()) => Json(json!({ "ok": true })).into_response(),
        Err(e) => fail(e),
    }
}

/// 轮换一个客户的全部绑定凭据值（原行原名，只换秘密值——计量历史不断），
/// 并换发订阅 token。返回新 token。两种重置入口（自助/管理端）共用。
async fn rotate_sub_identities(app: &Shared, sub_id: i64) -> anyhow::Result<String> {
    let bundles = app.db.proxy_node_bundles()?;
    for b in &bundles {
        for u in &b.users {
            if u.sub_user_id != Some(sub_id) {
                continue;
            }
            let credential = if b.node.protocol == "vless-reality" {
                crate::proxy::new_uuid()
            } else {
                crate::proxy::new_password()
            };
            app.db.update_proxy_user_credential(u.id, &credential)?;
        }
    }
    let token = crate::auth::random_token();
    app.db.reset_sub_token(sub_id, &token)?;
    proxy::apply_if_ready(app).await;
    Ok(token)
}

/// 管理员重置（不占客户自助次数）：凭据 + 订阅链接整体换新。
pub async fn admin_reset_sub_user(_: Admin, State(app): State<Shared>, Path(id): Path<i64>) -> Response {
    match rotate_sub_identities(&app, id).await {
        Ok(token) => Json(json!({ "ok": true, "token": token })).into_response(),
        Err(e) => fail(e),
    }
}

/// 客户自助重置（/u/ 页，token 鉴权）：开关开启且次数未用尽才放行。占一次
/// 次数。成功后旧订阅链接与旧凭据同时失效，客户须用返回的新地址。
pub async fn user_page_self_reset(
    State(app): State<Shared>,
    body: Result<Json<Value>, JsonRejection>,
) -> Response {
    let Json(body) = match body {
        Ok(b) => b,
        Err(_) => return bad("请求格式不对"),
    };
    let token = body["token"].as_str().unwrap_or_default().trim().to_owned();
    if token.is_empty() {
        return bad("缺少 token");
    }
    if !app.public_page() {
        return bad("用户中心页已关闭");
    }
    let Some(sub) = app.db.sub_user_by_token(&token).ok().flatten() else {
        return bad("订阅不存在或已失效");
    };
    if !sub.enabled {
        return bad("订阅已停用");
    }
    if !sub.user_page {
        return bad("用户中心页未开启");
    }
    if !sub.allow_self_reset {
        return bad("未开启自助重置，请联系管理员");
    }
    if sub.reset_count >= sub.reset_limit {
        return bad("重置次数已用完，请联系管理员");
    }
    match rotate_sub_identities(&app, sub.id).await {
        Ok(token) => {
            if let Err(e) = app.db.record_self_reset(sub.id) {
                return fail(e);
            }
            Json(json!({ "ok": true, "token": token })).into_response()
        }
        Err(e) => fail(e),
    }
}

/// The customer-facing subscription: token-guarded, no session, no admin data.
#[derive(Deserialize)]
pub struct SubQuery {
    token: Option<String>,
    /// 客户端类型（?t=，语义同旧 conv-sub）：clash 系→YAML、v2ray 系→链接列表。
    t: Option<String>,
}

// ---- 用户中心页（/u/{客户token}）：链接即凭证，公开页总开关 + 每客户开关 ----

/// 入口地址脱敏：IPv4 打星中间两段，IPv6 打星中段，域名原样。
fn mask_host(host: &str) -> String {
    let parts: Vec<&str> = host.split('.').collect();
    if parts.len() == 4 && parts.iter().all(|p| p.parse::<u8>().is_ok()) {
        return format!("{}.***.***.{}", parts[0], parts[3]);
    }
    if host.contains(':') {
        let groups: Vec<&str> = host.split(':').collect();
        if groups.len() > 4 {
            let head = groups[..2].join(":");
            let tail = groups[groups.len() - 2..].join(":");
            return format!("{head}:****:{tail}");
        }
    }
    host.to_owned()
}

/// 用户中心页地址（--site 配置了才发）。
fn user_page_url(site: &str, token: &str) -> Option<String> {
    let s = site.trim_end_matches('/');
    (!s.is_empty()).then(|| format!("{s}/u/{token}"))
}

#[derive(Deserialize)]
pub struct UserPageQuery {
    token: Option<String>,
}

/// 用户中心页的数据端点：客户信息 + 计费口径流量 + 凭据节点（脱敏）+ 多入口订阅链接。
pub async fn user_page_data(State(app): State<Shared>, Query(q): Query<UserPageQuery>) -> Response {
    let Some(token) = q.token.filter(|t| !t.trim().is_empty()) else {
        return bad("缺少 token");
    };
    if !app.public_page() {
        return bad("用户中心页已关闭");
    }
    let Some(sub) = app.db.sub_user_by_token(token.trim()).ok().flatten() else {
        return bad("订阅不存在或已失效");
    };
    if !sub.enabled {
        return bad("订阅已停用");
    }
    if !sub.user_page {
        return bad("用户中心页未开启");
    }
    let status = match crate::proxy::sub_status(&sub, crate::proxy::today()) {
        crate::proxy::SubStatus::Active => "active",
        crate::proxy::SubStatus::Disabled => "disabled",
        crate::proxy::SubStatus::Expired => "expired",
        crate::proxy::SubStatus::OverQuota => "over_quota",
    };
    // 该客户名下凭据所在的节点（proxy_user.sub_user_id 关联）
    let bundles = app.db.proxy_node_bundles().unwrap_or_default();
    let agents = app.agents.read().unwrap_or_else(|e| e.into_inner());
    let fronts = crate::proxy::sub_fronts(&app);
    let today = crate::proxy::today();
    let nodes: Vec<Value> = bundles
        .iter()
        .filter(|b| b.users.iter().any(|u| u.sub_user_id == Some(sub.id)))
        .map(|b| {
            let (host, port) = fronts
                .first()
                .map(|f| (f.host.clone(), f.port.map(|p| p as i64).unwrap_or(b.node.listen_port)))
                .unwrap_or_else(|| (b.node.name.clone(), b.node.listen_port));
            // server_id 0 = hub 本机（服务本请求即在线）；其余按 agent 在线表。
            let online = b.node.server_id == 0 || agents.contains_key(&b.node.server_id);
            let mut n = json!({
                "name": b.node.name,
                "protocol": b.node.protocol,
                "host": mask_host(&host),
                "port": port,
                "online": online,
            });
            // 每条线路的独立分享链接（客户自有凭据）：/u/ 页生成单线路二维码用。
            // share_link 与 /api/sub 链接渲染同源（订阅入口 host + 节点端口）。
            if let (Some(u), Some(front)) = (
                b.users.iter().find(|u| u.sub_user_id == Some(sub.id)),
                fronts.first(),
            ) {
                if let Ok(link) = crate::proxy::share_link(b, u, front, "") {
                    n["share_url"] = json!(link);
                }
            }
            // 模式二（per_node）：逐节点附 该凭据的 到期/配额/实时状态。
            // 凭据未单独设限时回落客户级，显示与门控语义对齐（到期空=跟随客户、配额 0=受客户总额约束）。
            if sub.view_mode == "per_node" {
                if let Some(u) = b.users.iter().find(|u| u.sub_user_id == Some(sub.id)) {
                    let live = crate::proxy::credential_live(u, today) && u.expires_at.as_deref().is_none_or(|e| {
                        chrono::NaiveDate::parse_from_str(e, "%Y-%m-%d").map(|d| today <= d).unwrap_or(true)
                    });
                    n["expires_at"] = json!(u.expires_at.clone().or_else(|| sub.expires_at.clone()));
                    let total = if u.quota_bytes > 0 { u.quota_bytes.max(0) } else { sub.quota_bytes.max(0) };
                    n["quota"] = json!({ "up": u.quota_used_up.max(0), "down": u.quota_used_down.max(0), "total": total });
                    n["limit_enabled"] = json!(u.quota_bytes > 0 || u.expires_at.is_some());
                    n["live"] = json!(live);
                }
            }
            n
        })
        .collect();
    let subs: Vec<Value> = fronts
        .iter()
        .map(|f| {
            let port = f.port.map(|p| format!(":{p}")).unwrap_or_default();
            let label = format!("{}{port}", f.host);
            // 地址带 #客户名 片段（客户端命名约定）：/u/ 页此前漏了它，扫码导入
            // 只能回落地址名（fragment 是最广支持的取名方式，profile-title 兜底）
            json!({
                "label": label,
                "url": format!("{}://{}{port}/api/sub?token={}#{}", f.scheme, f.host, sub.token, crate::proxy::pct(&sub.name)),
            })
        })
        .collect();
    let expire = sub.expires_at.clone();
    Json(json!({
        "name": sub.name,
        "status": status,
        "view_mode": sub.view_mode,
        "self_reset": {
            "allow": sub.allow_self_reset,
            "count": sub.reset_count,
            "limit": sub.reset_limit,
        },
        "quota": {
            "up": sub.quota_used_up.max(0),
            "down": sub.quota_used_down.max(0),
            "total": sub.quota_bytes.max(0),
            "expires_at": expire,
        },
        "nodes": nodes,
        "subs": subs,
    }))
    .into_response()
}

pub async fn proxy_subscription(
    State(app): State<Shared>,
    headers: HeaderMap,
    Query(q): Query<SubQuery>,
) -> Response {
    let Some(token) = q.token.filter(|t| !t.trim().is_empty()) else {
        return bad("缺少 token");
    };
    let sub = match app.db.sub_user_by_token(token.trim()) {
        Ok(Some(s)) => s,
        Ok(None) => return bad("订阅不存在或已失效"),
        Err(e) => return fail(e),
    };
    // agent 分发门控：分发端口回源带 X-Sub-Dist: agent，要求客户开启分发开关。
    let dist = headers.get("x-sub-dist").and_then(|v| v.to_str().ok()) == Some("agent");
    if dist && !sub.agent_dist {
        return (axum::http::StatusCode::FORBIDDEN, "agent distribution disabled").into_response();
    }
    // 与节点侧渲染共用同一个判定（M7）：停用/到期/超额的客户在订阅与凭据
    // 两侧同时失格，文案区分原因让客户自己能看懂。
    match proxy::sub_status(&sub, proxy::today()) {
        proxy::SubStatus::Active => {}
        proxy::SubStatus::Disabled => return bad("订阅已停用"),
        proxy::SubStatus::Expired => return bad("订阅已过期"),
        proxy::SubStatus::OverQuota => return bad("订阅流量已用尽，请联系管理员"),
    }
    let ua = headers.get(header::USER_AGENT).and_then(|v| v.to_str().ok()).unwrap_or_default();
    // ?t= 显式分流（语义沿用旧 conv-sub）；无 t 时 v2ray 系 UA → 链接列表，
    // 其余（clash 系/浏览器）→ YAML。
    let t = q.t.as_deref().map(str::to_ascii_lowercase);
    let want_links = match t.as_deref() {
        Some("v2ray" | "v2rayng" | "base64") => true,
        Some("clash" | "clash-meta" | "clashmeta" | "stash" | "mihomo") => false,
        Some(other) => return bad(&format!("客户端格式 {other} 即将支持")),
        None => {
            let ua = ua.to_ascii_lowercase();
            ua.contains("v2ray") || ua.contains("v2box") || ua.contains("hiddify")
        }
    };
    // 内容：绑定内容方案 → 方案渲染（面板导入的节点链接按该客户凭据生成，
    // 流量计量照走客户归属）；未绑定 → 旧的裸节点输出。方案被删的竞态回落
    // 旧输出，客户在客户端下次更新前重新选择即可。
    let rendered = if let Some(pid) = sub.profile_id {
        match app.db.sub_profile(pid) {
            Ok(Some(p)) => {
                if want_links {
                    crate::subscription::render_links_for(&app, &p, Some(&sub))
                        .map(|b| (b, "text/plain; charset=utf-8".to_owned()))
                } else {
                    crate::subscription::render_profile_for(&app, &p, Some(&sub))
                        .map(|b| (b, "text/yaml; charset=utf-8".to_owned()))
                }
            }
            Ok(None) => proxy::subscription_for(&app, &sub, ua).map(|(b, c)| (b, c.to_owned())),
            Err(e) => return fail(e),
        }
    } else {
        proxy::subscription_for(&app, &sub, ua).map(|(b, c)| (b, c.to_owned()))
    };
    match rendered {
        Ok((body, content_type)) => {
            let mut response = ([(header::CONTENT_TYPE, content_type.as_str())], body).into_response();
            // 命名头：客户端添加订阅时的取名来源（订阅名 = 客户名）。
            for (k, v) in crate::subscription::naming_headers(&sub.name) {
                if let Ok(value) = header::HeaderValue::from_str(&v) {
                    response.headers_mut().insert(k, value);
                }
            }
            subscription_headers(&mut response, &sub, &app.site);
            response
        }
        Err(e) => fail(e),
    }
}

/// 订阅响应的体验头（M8）。subscription-userinfo 是客户端显示「已用/总额/
/// 到期」的通用约定（v2rayN、Clash 系、Shadowrocket 都认）：upload/download
/// 是客户端视角的上下行，total 0 表示不限，expire 是到期日当地末秒的 epoch
/// （0 = 不限）。profile-update-interval 建议更新周期（小时），
/// profile-web-page-url 让客户端能跳回面板——只在配置了 --site 时发，
/// 浏览器地址栏式的 origin 不是给客户看的。
fn subscription_headers(response: &mut Response, sub: &crate::db::SubUser, site: &str) {
    let expire = sub
        .expires_at
        .as_deref()
        .and_then(|d| chrono::NaiveDate::parse_from_str(d, "%Y-%m-%d").ok())
        .and_then(|d| d.and_hms_opt(23, 59, 59))
        .map(|t| t.and_local_timezone(chrono::Local).single().map(|t| t.timestamp()).unwrap_or(0))
        .unwrap_or(0);
    let info = format!(
        "upload={}; download={}; total={}; expire={expire}",
        sub.quota_used_up.max(0),
        sub.quota_used_down.max(0),
        sub.quota_bytes.max(0),
    );
    if let Ok(value) = header::HeaderValue::from_str(&info) {
        response.headers_mut().insert(header::HeaderName::from_static("subscription-userinfo"), value);
    }
    response.headers_mut().insert(
        header::HeaderName::from_static("profile-update-interval"),
        header::HeaderValue::from_static("6"),
    );
    if let Some(page) = user_page_url(site, &sub.token) {
        if let Ok(value) = header::HeaderValue::from_str(&page) {
            response.headers_mut().insert(header::HeaderName::from_static("profile-web-page-url"), value);
        }
    }
}

/// 近期稳定版本，供版本切换点选（M4）。`?core=realm` 查 Realm。
pub async fn proxy_versions(
    _: Admin,
    State(app): State<Shared>,
    Query(q): Query<std::collections::HashMap<String, String>>,
) -> Response {
    let repo = match q.get("core").map(String::as_str) {
        Some("realm") => proxy::REALM_REPO,
        _ => proxy::SINGBOX_REPO,
    };
    Json(json!({ "versions": proxy::recent_versions(&app, repo).await })).into_response()
}

/// 入站 tag（in-{端口}）→ 协议名：先按 (server_id, 端口) 精确匹配，再按
/// 镜像集匹配（切换主机后节点在镜像机上也有同端口采样），最后按端口单独
/// 匹配但仅限同机历史别名（server_id=0 与挂到 agent 身份前的 hub 本机采样）。
/// 盲兜底不收窄的话，两台机器同端口会把流量记到别人的节点名下。
pub(crate) fn tag_node_name(bundles: &[crate::db::NodeBundle], server_id: i64, tag: &str) -> String {
    tag_bundle(bundles, server_id, tag)
        .map(|b| b.node.name.clone())
        .unwrap_or_else(|| format!("{tag}（节点可能已删除）"))
}

/// tag → 节点行（排行跨机归并按节点 id 求和用），匹配次序同 tag_node_name。
pub(crate) fn tag_bundle<'a>(
    bundles: &'a [crate::db::NodeBundle],
    server_id: i64,
    tag: &str,
) -> Option<&'a crate::db::NodeBundle> {
    let port: i64 = tag.trim_start_matches("in-").parse().unwrap_or(0);
    bundles
        .iter()
        .find(|b| b.node.server_id == server_id && b.node.listen_port == port)
        .or_else(|| {
            bundles.iter().find(|b| {
                crate::proxy::node_server_ids(&b.node).contains(&server_id) && b.node.listen_port == port
            })
        })
        .or_else(|| {
            bundles.iter().find(|b| b.node.listen_port == port && (server_id == 0 || b.node.server_id == 0))
        })
}

/// 代理节点的流量合计：今日与累计（M4）。
pub async fn proxy_traffic(_: Admin, State(app): State<Shared>) -> Response {
    match app.db.proxy_traffic() {
        Ok(rows) => {
            let bundles = app.db.proxy_node_bundles().unwrap_or_default();
            let list: Vec<Value> = rows
                .iter()
                .map(|(server_id, tag, trx, ttx, arx, atx)| {
                    // 入站 tag 即 in-{端口}，按服务器 + 端口找回节点名。
                    let node = tag_node_name(&bundles, *server_id, tag);
                    json!({
                        "node": node,
                        "today_rx": trx, "today_tx": ttx,
                        "total_rx": arx, "total_tx": atx,
                    })
                })
                .collect();
            Json(json!({ "traffic": list })).into_response()
        }
        Err(e) => fail(e),
    }
}

// ---- 连接日志（M14）：逐连接的客户端 IP / 访问目标 / 归属客户 ----

#[derive(Deserialize)]
pub struct ConnLogQuery {
    server: Option<i64>,
    /// 来源：空=全部，"__none__"=未认领（自用），否则凭据用户名。
    user: Option<String>,
    /// 节点筛选：入站 tag（如 "in-24443"）。
    node: Option<String>,
    q: Option<String>,
    since: Option<i64>,
    until: Option<i64>,
    page: Option<u32>,
}

fn conn_log_filter(q: &ConnLogQuery) -> crate::db::ConnLogFilter {
    crate::db::ConnLogFilter {
        server_id: q.server,
        user: q.user.clone().filter(|s| !s.trim().is_empty()),
        node: q.node.clone().filter(|s| !s.trim().is_empty()),
        q: q.q.clone().filter(|s| !s.trim().is_empty()),
        since: q.since,
        until: q.until,
        page: q.page.unwrap_or(1),
    }
}

/// 连接日志分页查询（ts_last 降序，50 条/页）。每行附 geo 归属地
/// （查询时解析，不落库；未配 xdb 库时为空串）。
pub async fn connection_logs_list(
    _: Admin,
    State(app): State<Shared>,
    Query(q): Query<ConnLogQuery>,
) -> Response {
    let f = conn_log_filter(&q);
    match app.db.connection_logs(&f) {
        Ok((rows, total)) => {
            let rows = rows
                .into_iter()
                .map(|mut r| {
                    let geo =
                        r.get("source").and_then(|s| s.as_str()).map(crate::geo::lookup).unwrap_or_default();
                    r["geo"] = json!(geo);
                    r
                })
                .collect::<Vec<_>>();
            Json(json!({ "rows": rows, "page": q.page.unwrap_or(1), "total": total })).into_response()
        }
        Err(e) => fail(e),
    }
}

/// 汇总：请求量最多的地址与消耗最多的客户端（后者附归属地）。
pub async fn connection_logs_summary(
    _: Admin,
    State(app): State<Shared>,
    Query(q): Query<ConnLogQuery>,
) -> Response {
    let f = conn_log_filter(&q);
    match app.db.connection_log_summary(&f) {
        Ok((hosts, clients)) => {
            let clients = clients
                .into_iter()
                .map(|mut c| {
                    let geo =
                        c.get("source").and_then(|s| s.as_str()).map(crate::geo::lookup).unwrap_or_default();
                    c["geo"] = json!(geo);
                    c
                })
                .collect::<Vec<_>>();
            Json(json!({ "top_hosts": hosts, "top_clients": clients })).into_response()
        }
        Err(e) => fail(e),
    }
}

/// CSV 导出（同筛选，最多 5000 行）。
pub async fn connection_logs_export(
    _: Admin,
    State(app): State<Shared>,
    Query(q): Query<ConnLogQuery>,
) -> Response {
    let mut f = conn_log_filter(&q);
    f.page = 1;
    let rows = match app.db.connection_logs_export(&f, 5000) {
        Ok(r) => r,
        Err(e) => return fail(e),
    };
    let esc = |v: &str| {
        if v.contains(',') || v.contains('"') {
            format!("\"{}\"", v.replace('"', "\"\""))
        } else {
            v.to_owned()
        }
    };
    let mut out = String::from("time,user,client_ip,geo,node,protocol,host,port,network,up,down\n");
    for (ts, user, source, inbound, host, port, network, up, down) in rows {
        let node = inbound.trim_start_matches("in-");
        let proto = protocol_label(port, &network);
        out.push_str(&format!(
            "{},{},{},{},{},{},{},{},{},{},{}\n",
            chrono::DateTime::from_timestamp(ts, 0)
                .map(|d| d.with_timezone(&chrono::Local).format("%Y-%m-%d %H:%M:%S").to_string())
                .unwrap_or_default(),
            esc(&user),
            esc(&source),
            esc(&crate::geo::lookup(&source)),
            esc(node),
            proto,
            esc(&host),
            port,
            network,
            up,
            down,
        ));
    }
    (
        [
            (header::CONTENT_TYPE, "text/csv; charset=utf-8"),
            (header::CONTENT_DISPOSITION, "attachment; filename=\"connection-logs.csv\""),
        ],
        out,
    )
        .into_response()
}

/// 协议列：端口推断 + 网络前缀。
fn protocol_label(port: i64, network: &str) -> String {
    let base = match port {
        443 => "HTTPS",
        80 => "HTTP",
        53 => "DNS",
        22 => "SSH",
        _ => {
            return if network == "udp" { "UDP" } else { "TCP" }.to_owned();
        }
    };
    if network == "udp" {
        format!("{base}/UDP")
    } else {
        base.to_owned()
    }
}

/// 概览仪表盘（M13）：全网吞吐走势（?range=24h/7d/30d，桶粒度 1min/10min/1h，
/// 与前端 Overview.tsx 的 RANGES 逐档相等）、节点/客户消耗排行、配额预警、
/// 即将到期与 KPI 汇总，一次请求供齐。走势缺桶（无流量时段）由前端补零。
/// 30d 档的 1h 是精度上限：8 天前的采样已被压缩成小时行，更细的桶会失真。
#[derive(Deserialize)]
pub struct OverviewQuery {
    range: Option<String>,
}

pub async fn proxy_overview(_: Admin, State(app): State<Shared>, Query(q): Query<OverviewQuery>) -> Response {
    let now = Utc::now().timestamp();
    // range → 统计窗口与桶粒度：6h/24h 分钟桶、7d/10 分钟桶、30d/小时桶
    // （窗口长度不变），未知值回退 24h。
    let (since, bucket) = match q.range.as_deref() {
        Some("6h") => (now - 6 * 3_600, 60),
        Some("7d") => (now - 7 * 86_400, 600),
        Some("30d") => (now - 30 * 86_400, 3600),
        _ => (now - 86_400, 60),
    };

    match (|| -> anyhow::Result<serde_json::Value> {
        let series: Vec<Value> = app
            .db
            .traffic_series(since, bucket)?
            .into_iter()
            .map(|(bucket, rx, tx)| json!({ "bucket": bucket, "rx": rx, "tx": tx }))
            .collect();

        // 监控节点表一次取齐：计费口径查找、续费日历、KPI 在线数共用。
        let all_nodes = app.db.nodes()?;
        // 协议节点所在服务器的计费口径（traffic_mode）：落在哪台监控节点行
        // 就用哪台的；server_id=0（面板本机）用面板机的监控节点行（hostname
        // 与 hub 自身一致，与 node_view 的 local 标记同判定）。查不到按 sum。
        let hub_host = hub_hostname();
        let mode_of_server = |server_id: i64| -> String {
            all_nodes
                .iter()
                .find(|n| n.id == server_id)
                .or_else(|| all_nodes.iter().find(|n| !hub_host.is_empty() && n.hostname == hub_host))
                .map(|n| n.traffic_mode.clone())
                .unwrap_or_else(|| "sum".into())
        };
        let billed = |rx: i64, tx: i64, mode: &str| match mode {
            "up" => tx,
            "down" => rx,
            "max" => rx.max(tx),
            _ => rx.saturating_add(tx),
        };

        // 今日实时流量：本地零点起的小时桶（前端累计成增长曲线）。
        let today_start =
            Local::now().date_naive().and_hms_opt(0, 0, 0).unwrap().and_local_timezone(Local).single();
        let midnight = today_start.map(|t| t.timestamp()).unwrap_or(now - 86_400);
        let today_series: Vec<Value> = app
            .db
            .traffic_series(midnight, 3600)?
            .into_iter()
            .map(|(bucket, rx, tx)| json!({ "bucket": bucket, "rx": rx, "tx": tx }))
            .collect();

        // 每日计费流量（近 30 天）：先按 日×节点 聚合，再按各节点的计费口径
        // 折算出当日计费值；上下行原值同时给出（柱状图分层用）。
        let daily_raw = app.db.traffic_daily_node(now - 30 * 86_400)?;
        let mut daily_map: std::collections::BTreeMap<String, (i64, i64, i64)> =
            std::collections::BTreeMap::new();
        for (day, server_id, _tag, rx, tx) in daily_raw {
            let e = daily_map.entry(day).or_insert((0, 0, 0));
            e.0 += rx;
            e.1 += tx;
            e.2 += billed(rx, tx, &mode_of_server(server_id));
        }
        let daily: Vec<Value> = daily_map
            .into_iter()
            .map(|(date, (down, up, billed))| json!({ "date": date, "down": down, "up": up, "billed": billed }))
            .collect();

        // 节点排行：tag → 节点名（与 proxy_traffic 同映射，轻量查询）。
        // 跨机镜像的同节点（切换主机）按节点归并求和，不再同名两行；
        // 计费各行先按所在机的口径折算再累加。
        let nodes = app.db.proxy_node_bundles()?;
        let merge_rank = |rows: Vec<(i64, String, i64, i64)>, with_billed: bool| -> Vec<Value> {
            // key → (节点名, rx, tx, billed, mode)
            let mut map: std::collections::BTreeMap<String, (String, i64, i64, i64, String)> =
                std::collections::BTreeMap::new();
            for (server_id, tag, rx, tx) in rows {
                let (key, name) = match tag_bundle(&nodes, server_id, &tag) {
                    Some(b) => (format!("n{}", b.node.id), b.node.name.clone()),
                    None => (format!("s{server_id}:{tag}"), format!("{tag}（节点可能已删除）")),
                };
                let mode = mode_of_server(server_id);
                let billed = if with_billed { billed(rx, tx, &mode) } else { 0 };
                let e = map.entry(key).or_insert((name, 0, 0, 0, mode));
                e.1 += rx;
                e.2 += tx;
                e.3 += billed;
            }
            map.into_values()
                .map(|(node, rx, tx, billed, mode)| json!({ "node": node, "rx": rx, "tx": tx, "billed": billed, "mode": mode }))
                .collect::<Vec<_>>()
        };

        // 单日（今日）流量消耗排行：按计费口径折算后排序，附上下行原值。
        let mut today_rank: Vec<Value> = merge_rank(app.db.traffic_node_rank(midnight)?, true);
        today_rank.sort_by_key(|v| -(v["billed"].as_i64().unwrap_or(0)));
        today_rank.truncate(10);
        let mut node_rank: Vec<Value> = merge_rank(app.db.traffic_node_rank(since)?, false);
        node_rank.sort_by_key(|v| -((v["rx"].as_i64().unwrap_or(0)) + (v["tx"].as_i64().unwrap_or(0))));
        node_rank.truncate(10);

        // 客户排行（按走势同款窗口，联动 range）：小时汇总表聚合后映射回
        // 客户信息；窗口内无用量的客户自然不出现。配额预警与到期列表保持
        // 计费周期语义（quota_used_*，M7 记账）。
        let subs = app.db.sub_users()?;
        let customer_rank: Vec<Value> = app
            .db
            .sub_usage_rank(since)?
            .into_iter()
            .filter_map(|(sub_id, up, down)| {
                let s = subs.iter().find(|s| s.id == sub_id)?;
                Some(json!({
                    "name": s.name, "up": up, "down": down,
                    "quota_bytes": s.quota_bytes, "status": crate::proxy::sub_status(s, crate::proxy::today()).label(),
                }))
            })
            .collect();
        let quota_warn: Vec<Value> = subs
            .iter()
            .filter(|s| {
                let used = s.quota_used_up + s.quota_used_down;
                s.quota_bytes > 0 && used * 5 >= s.quota_bytes * 4
            })
            .map(|s| {
                json!({
                    "name": s.name,
                    "used": s.quota_used_up + s.quota_used_down,
                    "quota_bytes": s.quota_bytes,
                    "status": crate::proxy::sub_status(s, crate::proxy::today()).label(),
                })
            })
            .collect();
        let expiring: Vec<Value> =
            subs.iter()
                .filter(|s| {
                    s.expires_at.as_deref().and_then(|d| d.parse::<chrono::NaiveDate>().ok()).is_some_and(
                        |d| d >= today_naive() && d <= (today_naive() + chrono::Duration::days(7)),
                    )
                })
                .map(|s| json!({ "name": s.name, "expires_at": s.expires_at }))
                .collect();

        // KPI：今日全网、在线节点（agents map 与监控节点交集）、客户数。
        let traffic = app.db.proxy_traffic()?;
        let today_rx: i64 = traffic.iter().map(|t| t.2).sum();
        let today_tx: i64 = traffic.iter().map(|t| t.3).sum();
        let online = app.agents.read().unwrap_or_else(|e| e.into_inner()).keys().copied().collect::<Vec<_>>();
        let total_nodes = all_nodes.len();
        let online_nodes = all_nodes.iter().filter(|n| online.contains(&n.id)).count();

        // 监测告警概览（三期）：进行中的丢包/延迟告警 + 实时统计的离线/
        // 流量超额/账单异常与今日恢复数。离线=down_since 在记的；流量=月计
        // 费用量达到额度；账单=已过期或 7 天内到期。
        let ping_alerts = crate::ping_alert::overview(&app)?;
        let offline_nodes: Vec<String> =
            all_nodes.iter().filter(|n| n.down_since > 0).map(|n| n.name.clone()).collect();
        let all_traffic = app.db.all_traffic();
        let traffic_over: Vec<String> = all_nodes
            .iter()
            .filter(|n| n.traffic_limit > 0)
            .filter(|n| {
                all_traffic.get(&n.id).is_some_and(|t| t.month_used(&n.traffic_mode) >= n.traffic_limit)
            })
            .map(|n| n.name.clone())
            .collect();
        let today = today_naive();
        let billing_alert: Vec<String> = all_nodes
            .iter()
            .filter_map(|n| {
                let d = n.expires_at.as_deref()?.parse::<NaiveDate>().ok()?;
                (d <= today)
                    .then(|| n.name.clone())
                    .or_else(|| ((d - today).num_days() <= 7).then(|| format!("{}（{} 到期）", n.name, d)))
            })
            .collect();
        let route_changes = app.db.route_events(100, now - 86_400).unwrap_or_default().len();
        let alerts = json!({
            "ping": ping_alerts,
            "offline": offline_nodes,
            "traffic": traffic_over,
            "billing": billing_alert,
            "route_changes_24h": route_changes,
        });

        // 续费日历：设了到期日的监控节点（前端按月分组渲染，量小全量下发）。
        let calendar: Vec<Value> = all_nodes
            .iter()
            .filter_map(|n| {
                let exp = n.expires_at.as_deref().filter(|s| !s.is_empty())?;
                Some(json!({ "id": n.id, "name": n.name, "expires_at": exp, "cycle": n.billing_cycle, "price": n.price, "currency": n.currency }))
            })
            .collect();

        Ok(json!({
            "series": series,
            "node_rank": node_rank,
            "customer_rank": customer_rank,
            "quota_warn": quota_warn,
            "expiring": expiring,
            "today_series": today_series,
            "daily": daily,
            "today_rank": today_rank,
            "calendar": calendar,
            "alerts": alerts,
            "kpi": {
                "today_rx": today_rx, "today_tx": today_tx,
                "online_nodes": online_nodes, "total_nodes": total_nodes,
                "customers": subs.len(),
            },
        }))
    })() {
        Ok(v) => Json(v).into_response(),
        Err(e) => fail(e),
    }
}

/// today 的 NaiveDate 版本（概览到期过滤用，与 proxy::today 同源）。
fn today_naive() -> chrono::NaiveDate {
    chrono::Local::now().date_naive()
}

/// 单协议出口线路测试：与批量测速同一语义（从协议所在服务器请求探测目标测
/// HTTP 耗时），返回 `{avg_ms, loss, error}`。
pub async fn test_proxy_node(_: Admin, State(app): State<Shared>, Path(id): Path<i64>) -> Response {
    let Some(node) = (match app.db.proxy_node(id) {
        Ok(n) => n,
        Err(e) => return fail(e),
    }) else {
        return no_such_node();
    };
    if !node.egress_type.is_empty() {
        let (ms, leg1_ms, error) = chain_probe(&app, &node).await;
        return Json(json!({
            "avg_ms": ms.map(|v| v as f64),
            "loss": if ms.is_some() { 0.0 } else { 1.0 },
            "error": error,
            "leg1_ms": leg1_ms.map(|v| v as f64),
        }))
        .into_response();
    }
    let (ms, error) = exit_probe(&app, node.server_id).await;
    Json(json!({
        "avg_ms": ms.map(|v| v as f64),
        "loss": if ms.is_some() { 0.0 } else { 1.0 },
        "error": error,
    }))
    .into_response()
}

/// 批量测速：全部启用协议的**出口线路**延迟。直连出口协议=从协议所在服务器向
/// 探测目标（客户端同款 gstatic generate_204，可用 kv `exit_probe_url` 覆盖）发
/// HTTP GET；socks5/http 出口协议=真实链路两腿——腿1 TCP 连 socks5（3 连发均
/// 值），全链经 socks5 访问探测目标（延迟列显示的值），分层错误见 chain_probe。
pub async fn test_proxy_nodes_bulk(_: Admin, State(app): State<Shared>) -> Response {
    let nodes: Vec<crate::db::ProxyNode> = match app.db.proxy_nodes() {
        Ok(n) => n.into_iter().filter(|n| n.enabled).collect(),
        Err(e) => return fail(e),
    };
    let probes = futures_util::future::join_all(nodes.iter().map(|n| {
        let app = app.clone();
        async move {
            if !n.egress_type.is_empty() {
                let (ms, leg1_ms, error) = chain_probe(&app, n).await;
                (n.id, ms, error, leg1_ms)
            } else {
                let (ms, error) = exit_probe(&app, n.server_id).await;
                (n.id, ms, error, None)
            }
        }
    }))
    .await;
    let results: Vec<Value> = probes
        .into_iter()
        .map(|(id, ms, error, leg1_ms)| {
            json!({
                "id": id,
                "avg_ms": ms.map(|v| v as f64),
                "loss": if ms.is_some() { 0.0 } else { 1.0 },
                "error": error,
                "leg1_ms": leg1_ms.map(|v| v as f64),
            })
        })
        .collect();
    Json(json!({ "results": results })).into_response()
}

/// 出口探测：返回 (耗时毫秒, 失败原因)。目标 URL 可用 kv `exit_probe_url`
/// 覆盖（测试与特殊网络环境用），默认客户端同款 gstatic generate_204。
const EXIT_PROBE_URL: &str = "https://www.gstatic.com/generate_204";

async fn exit_probe(app: &crate::App, server_id: i64) -> (Option<u64>, Option<String>) {
    let url = app
        .db
        .get("exit_probe_url")
        .filter(|v| !v.trim().is_empty())
        .unwrap_or_else(|| EXIT_PROBE_URL.to_string());
    if server_id == 0 {
        let client = match reqwest::Client::builder()
            .timeout(Duration::from_secs(5))
            .redirect(reqwest::redirect::Policy::none())
            .build()
        {
            Ok(c) => c,
            Err(e) => return (None, Some(e.to_string())),
        };
        let started = std::time::Instant::now();
        return match client.get(&url).send().await {
            Ok(_) => (Some(started.elapsed().as_millis() as u64), None),
            Err(e) => (None, Some(e.to_string())),
        };
    }
    match crate::agent_ws::call_agent(
        app,
        server_id,
        "net.http_probe",
        json!({ "url": url, "timeout_ms": 5000 }),
        Duration::from_secs(8),
    )
    .await
    {
        Ok(v) => {
            if v["ok"].as_bool().unwrap_or(false) {
                (v["ms"].as_u64(), None)
            } else {
                (None, Some(v["error"].as_str().unwrap_or("探测失败").to_string()))
            }
        }
        Err(_) => (None, Some("探测机器不在线".to_string())),
    }
}

/// 出口链探测（socks5/http 出口协议的真实链路）：腿1 = 协议所在服务器 TCP 连
/// socks5 节点（3 连发取均值，隧道诊断同款 probe_addrs_multi）；全链 = 经
/// socks5（认证按节点出口配置，socks5h=目标域名由代理端解析）访问探测目标的
/// HTTP 耗时——延迟列显示的就是这个值。分层错误：腿1 不通 → 「socks5 不可
/// 达」；腿1 通但全链失败 → 「socks5 已连上，访问目标失败：原因」。
/// 返回 (全链ms, 腿1ms, 错误)。
async fn chain_probe(
    app: &crate::App,
    node: &crate::db::ProxyNode,
) -> (Option<u64>, Option<u64>, Option<String>) {
    let url = app
        .db
        .get("exit_probe_url")
        .filter(|v| !v.trim().is_empty())
        .unwrap_or_else(|| EXIT_PROBE_URL.to_string());
    let leg_addr = format!("{}:{}", node.egress_host.trim(), node.egress_port);
    let Some(leg1) =
        crate::relay_health::probe_addrs_multi(app, node.server_id, std::slice::from_ref(&leg_addr), 3, 150)
            .await
            .and_then(|v| v.into_iter().next().flatten())
    else {
        return (None, None, Some("探测机器不在线".into()));
    };
    if !leg1.ok {
        return (None, Some(leg1.avg_ms), Some("socks5 不可达".into()));
    }
    let auth = if !node.egress_username.trim().is_empty() {
        format!("{}:{}@", crate::proxy::pct(&node.egress_username), crate::proxy::pct(&node.egress_password))
    } else {
        String::new()
    };
    let (chain_ms, chain_err) = if node.server_id == 0 {
        // 本机协议：hub 进程内经 socks5 拨号发探测。
        let proxy = match reqwest::Proxy::all(format!("socks5h://{auth}{leg_addr}")) {
            Ok(p) => p,
            Err(e) => return (None, Some(leg1.avg_ms), Some(format!("socks5 配置无效: {e}"))),
        };
        match reqwest::Client::builder()
            .timeout(Duration::from_secs(8))
            .redirect(reqwest::redirect::Policy::none())
            .proxy(proxy)
            .build()
        {
            Ok(c) => {
                let started = std::time::Instant::now();
                match c.get(&url).send().await {
                    Ok(_) => (Some(started.elapsed().as_millis() as u64), None),
                    Err(e) => (None, Some(e.to_string())),
                }
            }
            Err(e) => (None, Some(e.to_string())),
        }
    } else {
        match crate::agent_ws::call_agent(
            app,
            node.server_id,
            "net.http_probe",
            json!({
                "url": url,
                "timeout_ms": 8000,
                "socks5": {
                    "server": node.egress_host.trim(),
                    "port": node.egress_port,
                    "username": node.egress_username,
                    "password": node.egress_password,
                }
            }),
            Duration::from_secs(12),
        )
        .await
        {
            Ok(v) => {
                if v["ok"].as_bool().unwrap_or(false) {
                    (v["ms"].as_u64(), None)
                } else {
                    (None, Some(v["error"].as_str().unwrap_or("访问目标失败").to_string()))
                }
            }
            Err(e) => (None, Some(format!("RPC 失败: {e}"))),
        }
    };
    let error = chain_err.map(|e| format!("socks5 已连上，访问目标失败：{e}"));
    (chain_ms, Some(leg1.avg_ms), error)
}

// ---- Realm 中转（M5；M24 起多落地/协议/加密隧道/导入导出）----

/// 中转规则请求体：规则字段 + 落地目标列表（flatten 保持旧字段平铺兼容）。
#[derive(Deserialize)]
pub struct RelayRuleBody {
    #[serde(flatten)]
    pub rule: crate::db::RelayRule,
    #[serde(default)]
    pub targets: Vec<crate::db::RelayTarget>,
}

/// 规则写入前的规范化与校验：目标表清洗、旧形态兼容、target 镜像派生、
/// 隧道落地机存在性与端口冲突检查（出口端口留空则自动分配）。
async fn normalize_relay_rule(
    app: &Shared,
    body: &mut RelayRuleBody,
    except_rule: i64,
) -> anyhow::Result<()> {
    let rule = &mut body.rule;
    for t in &mut body.targets {
        t.host = t.host.trim().to_owned();
    }
    body.targets.retain(|t| !t.host.is_empty() && t.port > 0);
    // 兼容旧客户端/导入：没有 targets 但有 target → 拆成单目标。
    if body.targets.is_empty() && rule.target.contains(':') {
        if let Some((host, port)) = rule.target.rsplit_once(':') {
            if let Ok(port) = port.split('-').next().unwrap_or(port).parse::<i64>() {
                body.targets.push(crate::db::RelayTarget {
                    host: host.trim().to_owned(),
                    port,
                    enabled: true,
                    ..Default::default()
                });
            }
        }
    }
    rule.name = rule.name.trim().to_owned();
    rule.listen_port = rule.listen_port.trim().to_owned();
    // 监听端口留空：两种模式都允许，端口池内自动分配。
    if rule.listen_port.is_empty() || rule.listen_port == "0" {
        rule.listen_port = proxy::allocate_relay_port(app, rule.server_id)?.to_string();
    }
    if rule.protocol.is_empty() {
        rule.protocol = "both".into();
    }
    // 隧道落地机：存在性检查 + 出口端口（留空自动分配，占用即拒绝）。
    // 必须在 validate_relay 之前——它的出口端口必填检查吃分配的结果。
    if rule.exit_server_id > 0 {
        if app.db.node(rule.exit_server_id).ok().flatten().is_none() {
            anyhow::bail!(crate::Shown("隧道出口机不存在".into()));
        }
        let p = rule.exit_listen_port.trim();
        if p.is_empty() || p == "0" {
            rule.exit_listen_port = proxy::allocate_relay_port(app, rule.exit_server_id)?.to_string();
        } else if proxy::relay_port_taken(app, rule.exit_server_id, p.parse().unwrap_or(0), except_rule)? {
            anyhow::bail!(crate::Shown(format!("出口机端口 {p} 已被占用（节点或其他隧道规则）")));
        }
    }
    proxy::validate_relay_targets(&body.targets, &rule.balance)?;
    // target 镜像先于规则校验派生：validate_relay 的目标格式检查吃这个字段。
    if let Some(t0) = body.targets.first() {
        rule.target = format!("{}:{}", t0.host, t0.port);
    }
    proxy::validate_relay(rule)?;
    if rule.server_id != 0 && app.db.node(rule.server_id).ok().flatten().is_none() {
        anyhow::bail!(crate::Shown("入口机不存在".into()));
    }
    rule.target = format!("{}:{}", body.targets[0].host, body.targets[0].port);
    Ok(())
}

/// 规则落库后的应用：隧道规则同时应用到中转机、落地机与**备用入口机**——
/// 备用机的入口腿不推就要等 60s 心跳对账自愈，期间的故障转移切过去是空转。
async fn apply_relay_rule(app: &Shared, rule: &crate::db::RelayRule) -> bool {
    let mut applied = proxy::apply_relay_after_change(app, rule.server_id).await;
    if rule.exit_server_id > 0 && rule.exit_server_id != rule.server_id {
        applied &= proxy::apply_relay_after_change(app, rule.exit_server_id).await;
    }
    for backup in proxy::entry_backup_ids(rule) {
        if backup != rule.server_id {
            applied &= proxy::apply_relay_after_change(app, backup).await;
        }
    }
    applied
}

/// 加密隧道 transport 选项需要的最低 realm 版本（transport/servername 等
/// kaminari 选项在老版本会让 realm 启动即 panic）。解析不了就放行不告警。
fn supports_transport(version: &str) -> bool {
    let mut nums = [0u64; 3];
    for (i, part) in version.trim().trim_start_matches('v').split('.').take(3).enumerate() {
        nums[i] = part.parse().unwrap_or(0);
    }
    (nums[0], nums[1], nums[2]) >= (2, 7, 0)
}

/// 一台机器的 realm 状态（中转页每机一行）。远程机器现场问 agent
/// （5s 超时），问不到就报离线——列表是页面主数据源，不能等 10s。
async fn server_realm_status(app: &App, server_id: i64, name: String) -> Value {
    if server_id == 0 {
        let bin = proxy::realm_binary_path(app);
        let installed = bin.is_file();
        let version = if installed {
            proxy::detect_realm_version(&bin).await.unwrap_or_default()
        } else {
            String::new()
        };
        let desired = proxy::realm_desired_running(app);
        let running = if installed && !version.is_empty() && desired {
            if std::path::Path::new("/run/systemd/system").exists() {
                matches!(
                    tokio::process::Command::new("systemctl").args(["is-active", "--quiet", "monitor-realm@main"]).output().await,
                    Ok(o) if o.status.success()
                )
            } else {
                proxy::realm_locally_running(app).await
            }
        } else {
            false
        };
        return json!({
            "server_id": 0, "name": name, "online": true, "installed": installed,
            "version": version, "running": running, "desired_running": desired,
            "supports_transport": supports_transport(&version),
            "started_at": app.proxy.lock().unwrap_or_else(|e| e.into_inner()).realm_started_at,
        });
    }
    let online = app.agents.read().unwrap_or_else(|e| e.into_inner()).contains_key(&server_id);
    let cached_installed = app
        .proxy_remote
        .lock()
        .unwrap_or_else(|e| e.into_inner())
        .get(&server_id)
        .map(|s| s.realm_installed)
        .unwrap_or(false);
    if !online {
        return json!({ "server_id": server_id, "name": name, "online": false, "installed": cached_installed, "version": "", "running": false, "supports_transport": true });
    }
    match crate::agent_ws::call_agent(app, server_id, "proxy.core.status", json!({}), Duration::from_secs(5))
        .await
    {
        Ok(v) => {
            let installed = v["realm_version"].as_str().map(|s| !s.is_empty()).unwrap_or(false);
            if installed != cached_installed {
                app.proxy_remote
                    .lock()
                    .unwrap_or_else(|e| e.into_inner())
                    .entry(server_id)
                    .or_default()
                    .realm_installed = installed;
            }
            // 版本缓存触点之一：隧道页每次加载都会走到这里，顺手把 sing-box
            // 版本喂给协议页的版本过旧黄条（二期）。
            if let Some(ver) = v["installed_version"].as_str() {
                app.proxy_remote
                    .lock()
                    .unwrap_or_else(|e| e.into_inner())
                    .entry(server_id)
                    .or_default()
                    .version = ver.to_owned();
            }
            let version = v["realm_version"].as_str().unwrap_or_default().to_owned();
            json!({
                "server_id": server_id, "name": name, "online": true, "installed": installed,
                "version": version, "running": v["realm_running"].as_bool().unwrap_or(false),
                "supports_transport": supports_transport(&version),
            })
        }
        Err(_) => {
            json!({ "server_id": server_id, "name": name, "online": true, "installed": cached_installed, "version": "", "running": false, "supports_transport": true })
        }
    }
}

/// 中转规则列表 + 各台中转机的 realm 状态。
pub async fn relay_list(_: Admin, State(app): State<Shared>) -> Response {
    let rules = match app.db.relay_rules() {
        Ok(r) => r,
        Err(e) => return fail(e),
    };
    let all_targets = app.db.relay_targets().unwrap_or_default();
    // 导入式规则的中转版分享链接（原始链接地址改成中转机地址与监听端口）。
    let rules: Vec<Value> = rules
        .iter()
        .map(|r| {
            let mut v = serde_json::to_value(r).unwrap_or(json!({}));
            v["share"] = match proxy::relay_share_link(&app, r) {
                Some(link) => json!(link),
                None => Value::Null,
            };
            v["targets"] = json!(all_targets.iter().filter(|t| t.rule_id == r.id).collect::<Vec<_>>());
            v
        })
        .collect();
    // 出现为中转机/落地机的服务器各报一行状态；本机永远在列（核心卡）。
    // 展示层身份归一：0 号是本机核心的内部哨兵，与「主」节点行是同一台
    // 物理机——cards 合并成一行（server_realm_status 按 0 号查本机状态，
    // 但卡名与 server_id 用节点行，前端不再出现两张同机卡）。
    let local_id = proxy::local_node_server_id(&app);
    let mut ids: Vec<i64> = app
        .db
        .relay_rules()
        .unwrap_or_default()
        .iter()
        .flat_map(|r| [r.server_id, r.exit_server_id])
        .chain(std::iter::once(0))
        .collect();
    // 0 号并进 local 行：集合里不再有独立的 0。
    if let Some(_local) = local_id {
        ids.retain(|id| *id != 0);
    }
    ids.sort();
    ids.dedup();
    if ids.is_empty() {
        // 没有任何规则：核心卡仍要出现——用 local 行（身份归一）或退回 0 号。
        ids.push(local_id.unwrap_or(0));
    } else if local_id.is_some_and(|l| ids.contains(&l)) {
        // local 行已在集合：它就是本机卡的代表，0 号不再单列（已在前面 retain）。
    }
    let mut servers = Vec::new();
    for id in ids {
        let name = if id == 0 {
            "本机".to_string()
        } else {
            app.db.node(id).ok().flatten().map(|n| n.name).unwrap_or_else(|| format!("服务器 {id}"))
        };
        // 该行是合并后的本机代表：状态仍按 0 号（本机核心）查询，但对外
        // 标成节点行的 id——前端不再看到同机两行。
        let query_id = if id == local_id.unwrap_or(-1) { 0 } else { id };
        let mut card = server_realm_status(&app, query_id, name).await;
        if query_id != id {
            card["server_id"] = json!(id);
        }
        if Some(id) == local_id {
            card["local"] = json!(true);
        }
        servers.push(card);
    }
    // 端口池给前端显示「留空自动从 X-Y 随机分配」。
    let port_pool = app.db.get("proxy_port_pool").unwrap_or_else(|| "20000-50000".into());
    Json(json!({ "rules": rules, "realm": servers.iter().find(|s| s["server_id"] == local_id.unwrap_or(0)).cloned().unwrap_or(servers.first().cloned().unwrap_or(json!(null))), "servers": servers, "port_pool": port_pool }))
        .into_response()
}

/// 备用入口机校验：id 必须存在且不能与主入口同机。
fn validate_entry_backups(app: &App, server_id: i64, entry_backups: &str) -> anyhow::Result<()> {
    let ids: Vec<i64> = serde_json::from_str(entry_backups.trim()).unwrap_or_default();
    for id in &ids {
        if *id == server_id {
            return Err(anyhow::Error::msg(crate::Shown("备用入口机不能与主入口相同".into())));
        }
        if app.db.node(*id)?.is_none() {
            return Err(anyhow::Error::msg(crate::Shown(format!("备用入口机不存在：{id}"))));
        }
    }
    Ok(())
}

pub async fn create_relay_rule(
    _: Admin,
    State(app): State<Shared>,
    body: Result<Json<RelayRuleBody>, JsonRejection>,
) -> Response {
    let Json(mut body) = match body {
        Ok(b) => b,
        Err(_) => return bad("请求格式不对"),
    };
    body.rule.id = 0;
    // 身份归一：0 号「本机」虚拟身份退役（迁移 47 CHECK 兜底），中转只能
    // 挂在真实节点行上——面板机自己就是「主」节点行。
    if body.rule.server_id <= 0 {
        return bad("请选择入口机：本机身份已并入节点列表");
    }
    if let Err(e) = validate_entry_backups(&app, body.rule.server_id, &body.rule.entry_backups) {
        return bad(&e.to_string());
    }
    // 导入式：粘贴节点分享链接，目标/名称自动从链接提取，端口可自动分配。
    if !body.rule.origin_link.trim().is_empty() {
        body.rule.origin_link = body.rule.origin_link.trim().to_owned();
        let (_scheme, host, port, name) = match proxy::parse_share_link(&body.rule.origin_link) {
            Ok(v) => v,
            Err(e) => return fail(e),
        };
        if body.rule.name.trim().is_empty() {
            body.rule.name = name;
        }
        if body.targets.is_empty() {
            // enabled 显式 true：..Default::default() 走 derive（bool→false），
            // 不是 serde 的 default="yes"——默认 false 的目标会被渲染滤掉，
            // 落地机永远收不到配置（线上实锤过）。
            body.targets.push(crate::db::RelayTarget { host, port, enabled: true, ..Default::default() });
        }
    }
    if let Err(e) = normalize_relay_rule(&app, &mut body, 0).await {
        return fail(e);
    }
    if body.rule.server_id != 0 {
        if let Err(e) = proxy::ensure_remote_realm(&app, body.rule.server_id).await {
            return fail(e);
        }
    }
    match app.db.create_relay_rule(&body.rule) {
        Ok(id) => {
            if let Err(e) = app.db.replace_relay_targets(id, &body.targets) {
                return fail(e);
            }
            let applied = apply_relay_rule(&app, &body.rule).await;
            let share = proxy::relay_share_link(&app, &crate::db::RelayRule { id, ..body.rule.clone() });
            Json(json!({ "id": id, "applied": applied, "share": share })).into_response()
        }
        Err(e) => fail(e),
    }
}

pub async fn update_relay_rule(
    _: Admin,
    State(app): State<Shared>,
    Path(id): Path<i64>,
    body: Result<Json<RelayRuleBody>, JsonRejection>,
) -> Response {
    let Json(mut body) = match body {
        Ok(b) => b,
        Err(_) => return bad("请求格式不对"),
    };
    // 身份归一：0 号「本机」退役（同 create_relay_rule）。
    if body.rule.server_id <= 0 {
        return bad("请选择入口机：本机身份已并入节点列表");
    }
    if let Err(e) = validate_entry_backups(&app, body.rule.server_id, &body.rule.entry_backups) {
        return bad(&e.to_string());
    }
    body.rule.id = id;
    if let Err(e) = normalize_relay_rule(&app, &mut body, id).await {
        return fail(e);
    }
    // 隧道两端都要重渲染：改动可能影响落地机侧的旧出口半边。
    let old = app.db.relay_rule(id).ok().flatten();
    match app.db.update_relay_rule(&body.rule) {
        Ok(()) => {
            if let Err(e) = app.db.replace_relay_targets(id, &body.targets) {
                return fail(e);
            }
            let mut applied = apply_relay_rule(&app, &body.rule).await;
            if let Some(old) = old {
                if old.exit_server_id != body.rule.exit_server_id
                    && old.exit_server_id > 0
                    && old.exit_server_id != body.rule.exit_server_id
                {
                    applied &= proxy::apply_relay_after_change(&app, old.exit_server_id).await;
                }
            }
            Json(json!({ "ok": true, "applied": applied })).into_response()
        }
        Err(e) => fail(e),
    }
}

pub async fn delete_relay_rule(_: Admin, State(app): State<Shared>, Path(id): Path<i64>) -> Response {
    let old = app.db.relay_rule(id).ok().flatten();
    let server_id = old.as_ref().map(|r| r.server_id).unwrap_or(0);
    match app.db.delete_relay_rule(id) {
        Ok(()) => {
            let mut applied = proxy::apply_relay_after_change(&app, server_id).await;
            if let Some(old) = old {
                if old.exit_server_id > 0 && old.exit_server_id != old.server_id {
                    applied &= proxy::apply_relay_after_change(&app, old.exit_server_id).await;
                }
            }
            Json(json!({ "ok": true, "applied": applied })).into_response()
        }
        Err(e) => fail(e),
    }
}

/// 隧道诊断（对齐用户参考图）：每腿 10 次 TCP connect（200ms 间隔），聚合平均
/// 延迟与丢包率并分级。纯检测——健康检查已移除，诊断不回写任何状态。
pub async fn diagnose_relay_rule(_: Admin, State(app): State<Shared>, Path(id): Path<i64>) -> Response {
    let Some(rule) = app.db.relay_rule(id).ok().flatten() else { return bad("中转规则不存在") };
    if rule.protocol == "udp" {
        return bad("纯 UDP 目标不支持 TCP 探测");
    }
    let targets: Vec<crate::db::RelayTarget> = match app.db.relay_targets_of(id) {
        Ok(t) => t.into_iter().filter(|t| t.enabled).collect(),
        Err(e) => return fail(e),
    };
    let exit_host = if rule.exit_server_id > 0 {
        proxy::node_dial_host(&app, rule.exit_server_id, None)
    } else {
        String::new()
    };
    // 监听腿的拨号地址：本机规则打 127.0.0.1，远程机打它的拨号地址。
    let relay_host = if rule.server_id == 0 {
        "127.0.0.1".to_string()
    } else {
        proxy::node_dial_host(&app, rule.server_id, None)
    };
    let legs = crate::relay_health::diagnose_legs(&rule, &targets, &exit_host, &relay_host);
    if legs.is_empty() {
        return bad("该规则没有可诊断的链路段");
    }
    // 各段并行：每段一次多发探测（远端=一次 RPC，本机=进程内循环）。
    // 监听腿只测 1 次（grilling 拍板）：它测的是本机/直连回环性质的「听/没
    // 听」，多次采样对均值毫无意义；远程两腿才需要多次采样稳住均值。
    let probes = futures_util::future::join_all(legs.iter().map(|leg| {
        let addrs = vec![leg.addr.clone()];
        let from = leg.from_server;
        let app = app.clone();
        let count = if leg.kind == "listen" { 1 } else { crate::relay_health::DIAG_COUNT };
        async move {
            crate::relay_health::probe_addrs_multi(
                &app,
                from,
                &addrs,
                count,
                crate::relay_health::DIAG_INTERVAL_MS,
            )
            .await
        }
    }))
    .await;
    let server_name = |srv: i64| {
        if srv == 0 {
            "本机".to_string()
        } else {
            app.db.node(srv).ok().flatten().map(|n| n.name).unwrap_or_else(|| format!("服务器 {srv}"))
        }
    };
    let mut out = Vec::new();
    for (leg, res) in legs.iter().zip(probes) {
        let mut entry = json!({
            "key": leg.key,
            "kind": leg.kind,
            "from": server_name(leg.from_server),
            "target": leg.display_target,
        });
        let Some(list) = res else {
            entry["ok"] = json!(false);
            entry["error"] = json!("探测机器不在线，无法诊断");
            out.push(entry);
            continue;
        };
        let Some(sum) = list.into_iter().next().flatten() else {
            entry["ok"] = json!(false);
            entry["error"] = json!("探测结果缺失");
            out.push(entry);
            continue;
        };
        entry["ok"] = json!(sum.ok);
        entry["avg_ms"] = json!(sum.avg_ms);
        entry["loss_pct"] = json!(sum.loss_pct);
        entry["grade"] = json!(crate::relay_health::grade_of(sum.ok, sum.avg_ms, sum.loss_pct));
        entry["probes"] = json!(sum.samples.len());
        out.push(entry);
    }
    Json(json!({ "ok": true, "rule": { "id": rule.id, "name": rule.name, "protocol": rule.protocol, "transport": rule.transport, "exit_server_id": rule.exit_server_id }, "legs": out }))
        .into_response()
}

/// 全量导出（JSON）：规则 + 目标 + 全部新字段，供迁移与备份。
pub async fn export_relays(_: Admin, State(app): State<Shared>) -> Response {
    let rules = app.db.relay_rules().unwrap_or_default();
    let all_targets = app.db.relay_targets().unwrap_or_default();
    let rules: Vec<Value> = rules
        .iter()
        .map(|r| {
            let mut v = serde_json::to_value(r).unwrap_or(json!({}));
            v["targets"] = json!(all_targets.iter().filter(|t| t.rule_id == r.id).collect::<Vec<_>>());
            v
        })
        .collect();
    Json(json!({ "kind": "monitor-relay-rules", "version": 1, "exported_at": chrono::Utc::now().timestamp(), "rules": rules }))
        .into_response()
}

/// 批量导入：逐条校验，(中转机, 监听端口) 重复的跳过；全部处理完按涉及
/// 机器统一应用一次。
pub async fn import_relays(
    _: Admin,
    State(app): State<Shared>,
    body: Result<Json<Value>, JsonRejection>,
) -> Response {
    let Json(v) = match body {
        Ok(b) => b,
        Err(_) => return bad("请求格式不对"),
    };
    let Some(list) = v["rules"].as_array() else { return bad("缺少 rules 数组") };
    let mut created = 0i64;
    let mut skipped: Vec<Value> = Vec::new();
    let mut touched: Vec<i64> = Vec::new();
    for item in list {
        let Ok(mut body) = serde_json::from_value::<RelayRuleBody>(item.clone()) else {
            skipped.push(json!({ "name": item["name"], "reason": "格式不对" }));
            continue;
        };
        body.rule.id = 0;
        let server_id = body.rule.server_id;
        let listen = body.rule.listen_port.clone();
        let dup = app
            .db
            .relay_rules()
            .unwrap_or_default()
            .iter()
            .any(|r| r.server_id == server_id && r.listen_port == listen);
        if dup {
            skipped.push(json!({ "name": body.rule.name, "reason": "同入口机监听端口已存在" }));
            continue;
        }
        if body.rule.server_id <= 0 {
            skipped
                .push(json!({ "name": body.rule.name, "reason": "本机身份已退役：请改挂真实节点行后导入" }));
            continue;
        }
        if let Err(e) = normalize_relay_rule(&app, &mut body, 0).await {
            skipped.push(json!({ "name": body.rule.name, "reason": format!("{e:#}") }));
            continue;
        }
        match app.db.create_relay_rule(&body.rule) {
            Ok(id) => {
                let _ = app.db.replace_relay_targets(id, &body.targets);
                created += 1;
                for s in [body.rule.server_id, body.rule.exit_server_id] {
                    if !touched.contains(&s) {
                        touched.push(s);
                    }
                }
            }
            Err(e) => skipped.push(json!({ "name": body.rule.name, "reason": format!("{e:#}") })),
        }
    }
    let mut applied = true;
    for s in touched {
        applied &= proxy::apply_relay_after_change(&app, s).await;
    }
    Json(json!({ "created": created, "skipped": skipped, "applied": applied })).into_response()
}

/// 手动「立即同步」：把节点当前上报的公网 IP 推进它绑定的 DNS A 记录。
pub async fn dns_sync_node(_: Admin, State(app): State<Shared>, Path(id): Path<i64>) -> Response {
    match crate::dns::sync_node(&app, id).await {
        Ok(ip) => Json(json!({ "ok": true, "ip": ip })).into_response(),
        Err(e) => fail(e),
    }
}

pub async fn realm_start(_: Admin, State(app): State<Shared>) -> Response {
    match proxy::start_realm(&app).await {
        Ok(()) => Json(json!({ "ok": true })).into_response(),
        Err(e) => fail(e),
    }
}

pub async fn realm_stop(_: Admin, State(app): State<Shared>) -> Response {
    match proxy::stop_realm(&app).await {
        Ok(()) => Json(json!({ "ok": true })).into_response(),
        Err(e) => fail(e),
    }
}

pub async fn install_realm(
    _: Admin,
    State(app): State<Shared>,
    body: Result<Json<Value>, JsonRejection>,
) -> Response {
    let (server_id, want) = match &body {
        Ok(Json(v)) => (v["server_id"].as_i64().unwrap_or(0), v["version"].as_str().map(str::to_owned)),
        Err(_) => (0, None),
    };
    if server_id != 0 {
        return match proxy::ensure_remote_realm(&app, server_id).await {
            Ok(()) => Json(json!({ "ok": true })).into_response(),
            Err(e) => fail(e),
        };
    }
    match proxy::install_realm_local(&app, want).await {
        Ok(version) => {
            let applied = proxy::apply_relay_after_change(&app, 0).await;
            Json(json!({ "version": version, "applied": applied })).into_response()
        }
        Err(e) => fail(e),
    }
}

#[cfg(test)]
mod tests {

    #[tokio::test]
    async fn user_page_endpoint_gates_and_masks() {
        let app = app();
        let id = app.db.create_sub_user("客户", "usertok").unwrap();
        // 总开关关闭：403 语义（bad 文案）
        app.db.set("public_page", "off").unwrap();
        let q = Query(UserPageQuery { token: Some("usertok".into()) });
        let shared: Shared = std::sync::Arc::new(app);
        let resp = user_page_data(State(shared.clone()), q).await;
        assert_eq!(resp.status(), StatusCode::BAD_REQUEST, "关着的时候返回 400 携带原因文案");
        shared.db.set("public_page", "on").unwrap();
        // 每客户开关关闭 → bad 文案
        shared.db.set_sub_user_page(id, false).unwrap();
        let resp =
            user_page_data(State(shared.clone()), Query(UserPageQuery { token: Some("usertok".into()) }))
                .await;
        let body = axum::body::to_bytes(resp.into_body(), 1024).await.unwrap();
        assert!(String::from_utf8_lossy(&body).contains("未开启"));
        // 重新开启：数据返回且无脱敏需要（ fronts 回落 public_host 可能是域名/本地）
        shared.db.set_sub_user_page(id, true).unwrap();
        let resp =
            user_page_data(State(shared), Query(UserPageQuery { token: Some("usertok".into()) })).await;
        let body = axum::body::to_bytes(resp.into_body(), 64 * 1024).await.unwrap();
        let v: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(v["name"], "客户");
        assert_eq!(v["status"], "active");
        assert!(!v["subs"].as_array().unwrap().is_empty());
        // 订阅地址带 #客户名 片段（客户端取名回落顺序里 fragment 最广支持）
        let sub_url = v["subs"][0]["url"].as_str().unwrap();
        assert!(sub_url.ends_with("%E5%AE%A2%E6%88%B7"), "片段应是客户名的百分号编码: {sub_url}");
    }

    /// 模式二回落：凭据未单独设限时，节点卡回落到客户级（到期跟随、配额取
    /// 客户总额度），与门控语义一致；凭据自己设了则原样。
    #[tokio::test]
    async fn user_page_per_node_falls_back_to_customer_limits() {
        let app = app();
        let mk = |name: &str, port: i64| crate::db::ProxyNode {
            server_id: 1,
            name: name.into(),
            protocol: "vless-reality".into(),
            listen_port: port,
            enabled: true,
            ..Default::default()
        };
        app.db.create_proxy_node(&mk("香港", 24001), &crate::db::ProxySecret::default(), "hk").unwrap();
        app.db.create_proxy_node(&mk("东京", 24002), &crate::db::ProxySecret::default(), "jp").unwrap();
        let sub_id = app.db.create_sub_user("客户", "usertok").unwrap();
        for bundle in app.db.proxy_node_bundles().unwrap() {
            if let Some(u) = bundle.users.first() {
                app.db.set_proxy_user_sub(u.id, Some(sub_id)).unwrap();
            }
        }
        // 客户级：100GB + 2030 到期；香港凭据不设限（回落客户），东京凭据自设限额。
        let mut s = app.db.sub_user(sub_id).unwrap().unwrap();
        s.quota_bytes = 100 * 1024 * 1024 * 1024;
        s.expires_at = Some("2030-01-01".into());
        app.db.update_sub_user(sub_id, &s).unwrap();
        for b in app.db.proxy_node_bundles().unwrap() {
            if let Some(u) = b.users.iter().find(|u| u.sub_user_id == Some(sub_id)) {
                if b.node.name == "东京" {
                    app.db
                        .set_proxy_user_limits(u.id, Some("2029-06-30".into()), 50 * 1024 * 1024 * 1024, "")
                        .unwrap();
                }
            }
        }
        app.db.set_sub_user_view_mode(sub_id, "per_node").unwrap();
        let shared: Shared = std::sync::Arc::new(app);
        shared.db.set("public_page", "on").unwrap();
        let resp =
            user_page_data(State(shared), Query(UserPageQuery { token: Some("usertok".into()) })).await;
        let body = axum::body::to_bytes(resp.into_body(), 64 * 1024).await.unwrap();
        let v: serde_json::Value = serde_json::from_slice(&body).unwrap();
        let nodes = v["nodes"].as_array().unwrap();
        let hk = nodes.iter().find(|n| n["name"] == "香港").unwrap();
        assert_eq!(hk["expires_at"], "2030-01-01", "凭据未设到期 → 回落客户到期");
        assert_eq!(
            hk["quota"]["total"],
            serde_json::json!(100u64 * 1024 * 1024 * 1024),
            "凭据未设配额 → 回落客户总额度"
        );
        assert!(
            hk["share_url"].as_str().unwrap_or("").starts_with("vless://"),
            "每线路附客户凭据的独立分享链接"
        );
        let jp = nodes.iter().find(|n| n["name"] == "东京").unwrap();
        assert_eq!(jp["expires_at"], "2029-06-30", "凭据自设到期 → 原样");
        assert_eq!(
            jp["quota"]["total"],
            serde_json::json!(50u64 * 1024 * 1024 * 1024),
            "凭据自设配额 → 原样"
        );
    }

    /// 协议级分配：分配自动建「客户名·协议名」凭据并绑定（幂等不重复建）、
    /// 内置 default 保留且未绑定；取消删除绑定凭据、未分配时取消为空操作。
    #[tokio::test]
    async fn assign_node_creates_binds_and_unassign_deletes() {
        let app = app();
        let mk = |name: &str, port: i64| crate::db::ProxyNode {
            server_id: 1,
            name: name.into(),
            protocol: "vless-reality".into(),
            listen_port: port,
            enabled: true,
            ..Default::default()
        };
        let node_id = app
            .db
            .create_proxy_node(&mk("香港-01", 24443), &crate::db::ProxySecret::default(), "hk")
            .unwrap();
        let sub_id = app.db.create_sub_user("客户A", "tok-a").unwrap();
        let shared: Shared = std::sync::Arc::new(app);

        let resp = assign_sub_node(
            Admin,
            State(shared.clone()),
            Path((sub_id, node_id)),
            Ok(Json(json!({ "on": true }))),
        )
        .await;
        assert_eq!(resp.status(), StatusCode::OK);
        let bundle =
            shared.db.proxy_node_bundles().unwrap().into_iter().find(|b| b.node.id == node_id).unwrap();
        let bound: Vec<_> = bundle.users.iter().filter(|u| u.sub_user_id == Some(sub_id)).collect();
        assert_eq!(bound.len(), 1, "分配即建凭据并绑定");
        assert_eq!(bound[0].name, "客户A·香港-01");
        let builtin = bundle.users.iter().find(|u| u.sub_user_id.is_none()).expect("内置凭据保留");
        assert_eq!(builtin.name, "default");

        let resp = assign_sub_node(
            Admin,
            State(shared.clone()),
            Path((sub_id, node_id)),
            Ok(Json(json!({ "on": true }))),
        )
        .await;
        assert_eq!(resp.status(), StatusCode::OK, "幂等");
        let bundle =
            shared.db.proxy_node_bundles().unwrap().into_iter().find(|b| b.node.id == node_id).unwrap();
        assert_eq!(
            bundle.users.iter().filter(|u| u.sub_user_id == Some(sub_id)).count(),
            1,
            "重复分配不重复建"
        );

        let resp = assign_sub_node(
            Admin,
            State(shared.clone()),
            Path((sub_id, node_id)),
            Ok(Json(json!({ "on": false }))),
        )
        .await;
        assert_eq!(resp.status(), StatusCode::OK);
        let bundle =
            shared.db.proxy_node_bundles().unwrap().into_iter().find(|b| b.node.id == node_id).unwrap();
        assert!(bundle.users.iter().all(|u| u.sub_user_id != Some(sub_id)), "取消即删除绑定凭据");
        assert_eq!(bundle.users.len(), 1, "只剩内置凭据");

        let resp = assign_sub_node(
            Admin,
            State(shared.clone()),
            Path((sub_id, node_id)),
            Ok(Json(json!({ "on": false }))),
        )
        .await;
        assert_eq!(resp.status(), StatusCode::OK, "未分配时取消为空操作");
    }

    /// 新建客户带默认配额/到期：落库 + 每月重置口径；不带则不限。
    #[tokio::test]
    async fn create_sub_user_applies_default_quota_and_expiry() {
        let app = app();
        let shared: Shared = std::sync::Arc::new(app);
        let resp = create_proxy_sub_user(
            Admin,
            State(shared.clone()),
            Ok(Json(json!({ "name": "客户C", "expires_at": "2030-03-08", "quota_bytes": 1024i64 * 1024 * 1024 * 1024 }))),
        ).await;
        assert_eq!(resp.status(), StatusCode::OK);
        let id = {
            let bytes = axum::body::to_bytes(resp.into_body(), 1024).await.unwrap();
            let v: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
            v["id"].as_i64().unwrap()
        };
        let s = shared.db.sub_user(id).unwrap().unwrap();
        assert_eq!(s.expires_at.as_deref(), Some("2030-03-08"));
        assert_eq!(s.quota_bytes, 1024i64 * 1024 * 1024 * 1024);
        assert_eq!(s.quota_reset, "monthly", "配额>0 默认每月重置");

        let resp =
            create_proxy_sub_user(Admin, State(shared.clone()), Ok(Json(json!({ "name": "客户D" })))).await;
        assert_eq!(resp.status(), StatusCode::OK);
        let bytes = axum::body::to_bytes(resp.into_body(), 1024).await.unwrap();
        let v: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
        let s = shared.db.sub_user(v["id"].as_i64().unwrap()).unwrap().unwrap();
        assert_eq!(s.expires_at, None);
        assert_eq!(s.quota_bytes, 0);
    }

    /// 续期：从当前到期时间顺延一个月；未设置到期时间（不限）拒绝。
    #[tokio::test]
    async fn renew_extends_expiry_by_one_month() {
        let app = app();
        let id = app.db.create_sub_user("客户", "tok").unwrap();
        let mut s = app.db.sub_user(id).unwrap().unwrap();
        s.expires_at = Some("2026-11-06".into());
        app.db.update_sub_user(id, &s).unwrap();
        let shared: Shared = std::sync::Arc::new(app);

        let resp = renew_sub_user(Admin, State(shared.clone()), Path(id)).await;
        assert_eq!(resp.status(), StatusCode::OK);
        let bytes = axum::body::to_bytes(resp.into_body(), 1024).await.unwrap();
        let v: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(v["expires_at"], "2026-12-06", "从当前到期顺延一个月");
        assert_eq!(shared.db.sub_user(id).unwrap().unwrap().expires_at.as_deref(), Some("2026-12-06"));

        let unlimited = shared.db.create_sub_user("不限", "tok2").unwrap();
        let resp = renew_sub_user(Admin, State(shared.clone()), Path(unlimited)).await;
        assert_eq!(resp.status(), StatusCode::BAD_REQUEST, "未设置到期时间 → 拒绝");
    }

    /// 节点续期（续费日历「我已续费」）：按付款周期折月顺延（月末钳制）；
    /// 未设置到期时间的节点拒绝。
    #[tokio::test]
    async fn renew_node_advances_by_billing_cycle() {
        let app = app();
        let mk = |name: &str, cycle: &str, exp: Option<&str>| crate::db::Node {
            name: name.into(),
            billing_cycle: cycle.into(),
            expires_at: exp.map(|s| s.into()),
            ..Default::default()
        };
        let id = app.db.create_node(&mk("香港机房", "monthly", Some("2026-01-31")), "tok1").unwrap();
        let yearly = app.db.create_node(&mk("年付机", "yearly", Some("2027-02-28")), "tok2").unwrap();
        let none = app.db.create_node(&mk("不限期", "monthly", None), "tok3").unwrap();
        let shared: Shared = std::sync::Arc::new(app);

        let resp = renew_node(Admin, State(shared.clone()), Path(id)).await;
        assert_eq!(resp.status(), StatusCode::OK);
        let bytes = axum::body::to_bytes(resp.into_body(), 1024).await.unwrap();
        let v: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(v["expires_at"], "2026-02-28", "1-31 + 1 个月，2 月无 31 日 → 钳制到 2-28");
        assert_eq!(shared.db.node(id).unwrap().unwrap().expires_at.as_deref(), Some("2026-02-28"));

        // 年付（1y=12 个月）：2027-02-28 → 2028-02-29（2028 闰年）。
        let resp = renew_node(Admin, State(shared.clone()), Path(yearly)).await;
        assert_eq!(resp.status(), StatusCode::OK);
        let bytes = axum::body::to_bytes(resp.into_body(), 1024).await.unwrap();
        let v: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(v["expires_at"], "2028-02-28", "chrono 加月保日号：2-28 + 12 个月 = 2028-02-28");

        let resp = renew_node(Admin, State(shared.clone()), Path(none)).await;
        assert_eq!(resp.status(), StatusCode::BAD_REQUEST, "未设置到期时间 → 拒绝");
    }

    /// 每日计费流量的原始聚合：按本地日 × 节点分组，窗口外的天不出现。
    #[tokio::test]
    async fn traffic_daily_node_groups_by_local_day() {
        let app = app();
        let now = Utc::now().timestamp();
        let ins = |ts: i64, rx: i64, tx: i64| {
            app.db.add_traffic_samples(&[(0, "in-24001", ts, rx, tx)]).unwrap();
        };
        // 今天两行 + 昨天一行 + 31 天前一行（窗口外）。
        let today = Local::now()
            .date_naive()
            .and_hms_opt(12, 0, 0)
            .unwrap()
            .and_local_timezone(Local)
            .single()
            .unwrap()
            .timestamp();
        ins(now - 60, 100, 40);
        ins(now - 120, 50, 10);
        ins(today - 86_400, 7, 3);
        ins(now - 31 * 86_400, 999, 999);
        let rows = app.db.traffic_daily_node(now - 30 * 86_400).unwrap();
        let by_day: std::collections::HashMap<String, (i64, i64)> =
            rows.into_iter().map(|(d, _, _, rx, tx)| (d, (rx, tx))).collect();
        assert_eq!(by_day.len(), 2, "窗口内应只有两个自然日: {by_day:?}");
        let today_key = Local::now().date_naive().format("%Y-%m-%d").to_string();
        let yesterday_key =
            (Local::now().date_naive() - chrono::Duration::days(1)).format("%Y-%m-%d").to_string();
        assert_eq!(by_day[&today_key], (150, 50), "当日两行合并");
        assert_eq!(by_day[&yesterday_key], (7, 3));
    }

    /// 单凭据轮换：值换新、原名不变、其他凭据不动、配置下发。
    #[tokio::test]
    async fn rotate_single_credential_rotates_only_that_row() {
        let app = app();
        let mk = |name: &str, port: i64| crate::db::ProxyNode {
            server_id: 1,
            name: name.into(),
            protocol: "vless-reality".into(),
            listen_port: port,
            enabled: true,
            ..Default::default()
        };
        let node_id =
            app.db.create_proxy_node(&mk("香港", 24443), &crate::db::ProxySecret::default(), "hk").unwrap();
        let sub_id = app.db.create_sub_user("客户", "tok").unwrap();
        let bundles = app.db.proxy_node_bundles().unwrap();
        let builtin_id = bundles.iter().find(|b| b.node.id == node_id).unwrap().users[0].id;
        let bound_id = app.db.create_proxy_user(node_id, "客户·香港", "bound-uuid").unwrap();
        app.db.set_proxy_user_sub(bound_id, Some(sub_id)).unwrap();
        let shared: Shared = std::sync::Arc::new(app);

        let resp = rotate_proxy_user(Admin, State(shared.clone()), Path((node_id, bound_id))).await;
        assert_eq!(resp.status(), StatusCode::OK);
        let bundle =
            shared.db.proxy_node_bundles().unwrap().into_iter().find(|b| b.node.id == node_id).unwrap();
        let builtin = bundle.users.iter().find(|u| u.id == builtin_id).unwrap();
        let bound = bundle.users.iter().find(|u| u.id == bound_id).unwrap();
        assert_ne!(bound.credential, "bound-uuid", "目标凭据换值");
        assert_eq!(bound.name, "客户·香港", "原名不变");
        assert_eq!(builtin.credential, "hk", "其他凭据不动");

        // 凭据不属于该节点：拒绝
        let resp = rotate_proxy_user(Admin, State(shared.clone()), Path((node_id, 99999))).await;
        assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
    }

    /// 客户自助重置：开关关/次数尽拒绝；成功=凭据换值（原名不变）+token 换新
    /// +计数加一。管理端重置不占次数。
    #[tokio::test]
    async fn user_self_reset_gates_and_rotation() {
        let app = app();
        let mk = |name: &str, port: i64| crate::db::ProxyNode {
            server_id: 1,
            name: name.into(),
            protocol: "vless-reality".into(),
            listen_port: port,
            enabled: true,
            ..Default::default()
        };
        let node_id = app
            .db
            .create_proxy_node(&mk("香港", 24443), &crate::db::ProxySecret::default(), "hk-cred")
            .unwrap();
        let sub_id = app.db.create_sub_user("客户", "tok-old").unwrap();
        for b in app.db.proxy_node_bundles().unwrap() {
            for u in b.users.iter().filter(|u| u.node_id == node_id) {
                app.db.set_proxy_user_sub(u.id, Some(sub_id)).unwrap();
            }
        }
        let old_cred = app
            .db
            .proxy_node_bundles()
            .unwrap()
            .into_iter()
            .find(|b| b.node.id == node_id)
            .unwrap()
            .users
            .into_iter()
            .find(|u| u.sub_user_id == Some(sub_id))
            .unwrap()
            .credential;
        let shared: Shared = std::sync::Arc::new(app);
        let call = |token: &'static str| {
            let shared = shared.clone();
            async move { user_page_self_reset(State(shared), Ok(Json(json!({ "token": token })))).await }
        };

        // 开关未开：拒绝
        let resp = call("tok-old").await;
        assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
        // 开启后成功：凭据换值（原名）、token 换新、计数 1
        shared.db.set_sub_user_self_reset(sub_id, true, 2).unwrap();
        let resp = call("tok-old").await;
        assert_eq!(resp.status(), StatusCode::OK);
        let bytes = axum::body::to_bytes(resp.into_body(), 1024).await.unwrap();
        let v: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
        let new_token = v["token"].as_str().unwrap().to_owned();
        assert_ne!(new_token, "tok-old");
        let bundle =
            shared.db.proxy_node_bundles().unwrap().into_iter().find(|b| b.node.id == node_id).unwrap();
        let rotated = bundle.users.iter().find(|u| u.sub_user_id == Some(sub_id)).unwrap();
        assert_ne!(rotated.credential, old_cred, "凭据值已轮换");
        assert_eq!(rotated.name, "default", "凭据原名不变（计量连续）");
        let s = shared.db.sub_user(sub_id).unwrap().unwrap();
        assert_eq!(s.reset_count, 1);
        assert_eq!(s.token, new_token);
        // 旧 token 已失效
        assert!(shared.db.sub_user_by_token("tok-old").unwrap().is_none());
        // 再重置一次到上限
        let tok2: &'static str = Box::leak(new_token.clone().into_boxed_str());
        let resp = call(tok2).await;
        assert_eq!(resp.status(), StatusCode::OK);
        // 次数用尽：拒绝
        let resp = call(tok2).await;
        assert_eq!(resp.status(), StatusCode::BAD_REQUEST);

        // 管理端重置：不占自助次数
        let resp = admin_reset_sub_user(Admin, State(shared.clone()), Path(sub_id)).await;
        assert_eq!(resp.status(), StatusCode::OK);
        let s = shared.db.sub_user(sub_id).unwrap().unwrap();
        assert_eq!(s.reset_count, 2, "管理端重置不占自助次数");
        assert_ne!(s.token, new_token);
    }

    /// Shadowsocks 单凭据：分配=绑定空闲凭据（不新建），取消=解绑保留
    /// （删掉唯一凭据会让节点永远无法再分配）。
    #[tokio::test]
    async fn assign_shadowsocks_binds_idle_and_unassign_keeps_it() {
        let app = app();
        let mk = |name: &str, port: i64| crate::db::ProxyNode {
            server_id: 1,
            name: name.into(),
            protocol: "shadowsocks".into(),
            listen_port: port,
            enabled: true,
            ..Default::default()
        };
        let node_id = app
            .db
            .create_proxy_node(&mk("ss", 24444), &crate::db::ProxySecret::default(), "ss-cred")
            .unwrap();
        let sub_id = app.db.create_sub_user("客户B", "tok-b").unwrap();
        let shared: Shared = std::sync::Arc::new(app);

        let resp = assign_sub_node(
            Admin,
            State(shared.clone()),
            Path((sub_id, node_id)),
            Ok(Json(json!({ "on": true }))),
        )
        .await;
        assert_eq!(resp.status(), StatusCode::OK);
        let bundle =
            shared.db.proxy_node_bundles().unwrap().into_iter().find(|b| b.node.id == node_id).unwrap();
        assert_eq!(bundle.users.len(), 1, "单凭据不新建");
        assert_eq!(bundle.users[0].sub_user_id, Some(sub_id));

        let resp = assign_sub_node(
            Admin,
            State(shared.clone()),
            Path((sub_id, node_id)),
            Ok(Json(json!({ "on": false }))),
        )
        .await;
        assert_eq!(resp.status(), StatusCode::OK);
        let bundle =
            shared.db.proxy_node_bundles().unwrap().into_iter().find(|b| b.node.id == node_id).unwrap();
        assert_eq!(bundle.users.len(), 1, "解绑保留凭据");
        assert_eq!(bundle.users[0].sub_user_id, None);
    }

    /// 同服务器凭据名唯一：目标名已被占用时拒绝分配（防计量串账）。
    #[tokio::test]
    async fn assign_rejects_when_credential_name_taken_on_same_server() {
        let app = app();
        let mk = |name: &str, port: i64| crate::db::ProxyNode {
            server_id: 1,
            name: name.into(),
            protocol: "vless-reality".into(),
            listen_port: port,
            enabled: true,
            ..Default::default()
        };
        let node_id = app
            .db
            .create_proxy_node(&mk("香港-01", 24443), &crate::db::ProxySecret::default(), "hk")
            .unwrap();
        let other_id = app
            .db
            .create_proxy_node(&mk("东京-01", 24444), &crate::db::ProxySecret::default(), "jp")
            .unwrap();
        let sub_id = app.db.create_sub_user("客户A", "tok-a").unwrap();
        app.db.create_proxy_user(other_id, "客户A·香港-01", "taken-uuid").unwrap();
        let shared: Shared = std::sync::Arc::new(app);

        let resp = assign_sub_node(
            Admin,
            State(shared.clone()),
            Path((sub_id, node_id)),
            Ok(Json(json!({ "on": true }))),
        )
        .await;
        assert_eq!(resp.status(), StatusCode::BAD_REQUEST, "同名凭据已存在于同服务器 → 拒绝");
        let bundle =
            shared.db.proxy_node_bundles().unwrap().into_iter().find(|b| b.node.id == node_id).unwrap();
        assert!(bundle.users.len() == 1 && bundle.users[0].name == "default", "拒绝时不产生半成品");
    }

    use super::*;
    // Sessions remain hashed; only node tokens are stored in the clear.
    use crate::auth::sha256;
    use crate::db::Db;

    /// What a browser on `https://monitor.example.com` sends with a panel write.
    fn panel_headers() -> HeaderMap {
        HeaderMap::from_iter([
            (header::ORIGIN, "https://monitor.example.com".parse().unwrap()),
            (header::HeaderName::from_static("sec-fetch-site"), "same-origin".parse().unwrap()),
        ])
    }

    fn app() -> App {
        App::for_test(Db::open(":memory:").unwrap())
    }

    /// 生命周期门槛在订阅端点的出口文案：正常（无节点时报缺凭据而非拒绝
    /// 客户）、停用、到期、超额，各有各的话，客户自己能看懂被拒的原因。
    #[tokio::test]
    async fn subscription_gates_follow_the_customer_lifecycle() {
        let app = std::sync::Arc::new(app());
        let id = app.db.create_sub_user("客户A", "tok").unwrap();
        let today = crate::proxy::today().format("%Y-%m-%d").to_string();
        let yesterday = (crate::proxy::today() - chrono::Duration::days(1)).format("%Y-%m-%d").to_string();
        let ask = |app: &std::sync::Arc<App>| {
            proxy_subscription(
                State(app.clone()),
                HeaderMap::new(),
                Query(SubQuery { token: Some("tok".into()), t: None }),
            )
        };
        let body = |r: Response| async {
            let bytes = axum::body::to_bytes(r.into_body(), 1024).await.unwrap();
            String::from_utf8_lossy(&bytes).into_owned()
        };
        // 正常但没分配凭据：不是拒绝客户，是渲染层的“没凭据”。
        assert!(body(ask(&app).await).await.contains("还没有被分配任何节点"));
        // 停用。
        app.db.update_sub_user(id, &crate::db::SubUser { enabled: false, ..Default::default() }).unwrap();
        assert!(body(ask(&app).await).await.contains("已停用"));
        // 到期（昨天），到期当天仍然可用。
        app.db
            .update_sub_user(
                id,
                &crate::db::SubUser { enabled: true, expires_at: Some(yesterday), ..Default::default() },
            )
            .unwrap();
        assert!(body(ask(&app).await).await.contains("已过期"));
        app.db
            .update_sub_user(
                id,
                &crate::db::SubUser { enabled: true, expires_at: Some(today), ..Default::default() },
            )
            .unwrap();
        assert!(body(ask(&app).await).await.contains("还没有被分配任何节点"));
        // 超额。
        app.db.bump_sub_usage(&[(id, 30, 0)]).unwrap();
        app.db
            .update_sub_user(id, &crate::db::SubUser { enabled: true, quota_bytes: 10, ..Default::default() })
            .unwrap();
        assert!(body(ask(&app).await).await.contains("流量已用尽"));
    }

    /// Taken by every test that calls `metrics`. `HISTORY_GATE` is process-wide,
    /// and a test holding all of its permits would refuse a parallel one with a
    /// 503. Tokio's mutex, since the guard is held across awaits.
    static HISTORY_TESTS: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());

    /// A lookup nobody can refresh must not hide an update all day, and a panel
    /// left open on a screen must not ask GitHub on every load.
    #[test]
    fn a_release_lookup_is_held_for_six_hours_and_a_failed_one_for_ten_minutes() {
        let now = Utc::now().timestamp();
        let read = |read_at, hub: &str, agent: &str| crate::Releases {
            read_at,
            hub: hub.into(),
            agent: agent.into(),
        };
        assert!(!fresh_enough(&crate::Releases::default(), now), "nothing has been read yet");
        assert!(fresh_enough(&read(now - 5 * 3600, "1.2.0", "1.1.0"), now));
        assert!(!fresh_enough(&read(now - 7 * 3600, "1.2.0", "1.1.0"), now));
        assert!(fresh_enough(&read(now - 300, "", ""), now), "a failure is held briefly");
        assert!(!fresh_enough(&read(now - 1200, "1.2.0", ""), now), "half an answer is a failure");
    }

    fn app_with_site(site: &str) -> App {
        let mut state = app();
        state.site = site.into();
        state
    }

    #[tokio::test]
    async fn provisioning_follows_the_browsers_own_origin() {
        let app = std::sync::Arc::new(app_with_site("https://monitor.example.com"));
        let good = panel_headers();
        assert!(provisioning_allowed(&app, &good).is_ok());

        // The four shapes a reverse proxy puts in Host and X-Forwarded-Proto
        // while the browser is on https: no X-Forwarded-Proto at all, the proxy's
        // own upstream address as Host, a plaintext hop behind a TLS edge, and a
        // port dropped by `$host`. Reading them instead of the origin refuses
        // each one.
        let mut proxied = good.clone();
        proxied.insert(header::HOST, "127.0.0.1:28080".parse().unwrap());
        proxied.insert("x-forwarded-proto", "http".parse().unwrap());
        assert!(provisioning_allowed(&app, &proxied).is_ok());

        for origin in [
            "http://monitor.example.com",
            "https://198.51.100.1",
            "null",
            // A registered name resolving wherever its owner points it, which is
            // not the loopback entry below however it is spelled.
            "http://127.0.0.1.example.com",
        ] {
            let mut headers = good.clone();
            headers.insert(header::ORIGIN, origin.parse().unwrap());
            assert_eq!(provisioning_allowed(&app, &headers), Err(PROVISIONING_DENIED), "{origin}");
        }

        // A panel opened over a tunnel reads as loopback. It names no address a
        // node could reach, so it provisions alongside --site and not without it.
        for origin in ["http://127.0.0.1:9911", "http://localhost:9911", "http://[::1]:9911"] {
            let mut headers = good.clone();
            headers.insert(header::ORIGIN, origin.parse().unwrap());
            assert!(provisioning_allowed(&app, &headers).is_ok(), "{origin}");
            assert!(provisioning_allowed(&app_with_site(""), &headers).is_err(), "{origin} without --site");
        }
        // No origin at all: every caller that is not a browser, and a browser
        // behind a proxy that clears the header, which the message names.
        let mut headers = good.clone();
        headers.remove(header::ORIGIN);
        assert_eq!(provisioning_allowed(&app, &headers), Err(ORIGIN_MISSING));
        // A request sent from a page elsewhere.
        headers = good.clone();
        headers.insert("sec-fetch-site", "cross-site".parse().unwrap());
        assert!(provisioning_allowed(&app, &headers).is_err());

        // Both panel paths refuse, and neither leaves anything behind.
        headers = good.clone();
        headers.insert(header::ORIGIN, "http://monitor.example.com".parse().unwrap());
        let node = serde_json::from_value(json!({"name":"blocked"})).unwrap();
        assert_eq!(
            create_node(Admin, State(app.clone()), headers.clone(), Ok(Json(node))).await.status(),
            StatusCode::FORBIDDEN
        );
        assert_eq!(open_register(Admin, State(app.clone()), headers).await.status(), StatusCode::FORBIDDEN);
        assert!(app.db.nodes().unwrap().is_empty());
        assert!(app.db.get("register_key").is_none());

        // --site takes the origin's place in the command, so one that is not an
        // https domain refuses every entry.
        for site in [
            "http://monitor.example.com",
            "https://198.51.100.1",
            "https://user@monitor.example.com",
            "https://monitor.example.com/path",
        ] {
            assert!(https_domain(site).is_none());
            assert_eq!(provisioning_allowed(&app_with_site(site), &good), Err(PROVISIONING_DENIED), "{site}");
        }
    }

    /// Whatever this accepts is pushed to every assigned agent and passed directly
    /// to `lookup_host`. Forms it cannot resolve return -1 indefinitely, which the
    /// chart draws as a probe losing every packet, so the check must match what
    /// the error message claims.
    #[test]
    fn a_probe_target_must_be_something_the_agent_can_resolve() {
        // Each of these causes `lookup_host` to return an error, verified against
        // it: a bare IPv6 address is all colons, and the other two omit the half
        // the message requires.
        for bad in
            ["2606:4700:4700::1111", ":443", "example.com:", "1.1.1.1", "1.1.1.1:0", "[::1]:x", "[::1]"]
        {
            assert!(!valid_target(bad), "{bad}");
        }
        for good in ["1.1.1.1:443", "[2606:4700:4700::1111]:443", "example.com:80", "[::1]:1"] {
            assert!(valid_target(good), "{good}");
        }
    }

    /// The check above is meaningful only if it runs on the stored string: what
    /// reaches the agent is the stored value, and `lookup_host` rejects
    /// `"1.1.1.1:443 "` outright -- the permanent -1 `valid_target` exists to
    /// prevent, reachable through a check that passed.
    #[tokio::test]
    async fn a_probe_target_is_stored_as_the_string_that_was_checked() {
        let app = std::sync::Arc::new(app());
        let save = |name: &str, target: &str| {
            let task = PingTask {
                id: 0,
                name: name.to_owned(),
                target: target.to_owned(),
                interval: 60,
                nodes: vec![],
                ..Default::default()
            };
            save_ping_task(Admin, State(app.clone()), Json(task))
        };
        assert_eq!(save(" 探测 ", "1.1.1.1:443 ").await.status(), StatusCode::OK);
        let stored = &app.db.ping_tasks().unwrap()[0];
        assert_eq!(stored.target, "1.1.1.1:443", "the agent gets this string, not the one that was checked");
        assert_eq!(stored.name, "探测", "and it labels an anonymous chart");
        // Trimming must not turn a blank entry into a saved row.
        assert_eq!(save("   ", "   ").await.status(), StatusCode::BAD_REQUEST);
        assert_eq!(app.db.ping_tasks().unwrap().len(), 1);
    }

    /// The same rule as `retention_days`, applied to the other value this hub
    /// clamps downstream: an out-of-range value must fail, or it silently becomes
    /// a different one. Below the floor that value is 5 seconds, the fastest probe
    /// available, and the panel reaches 0 simply by clearing its interval field,
    /// since `Number("")` is 0.
    #[tokio::test]
    async fn a_probe_interval_out_of_range_is_refused_rather_than_clamped() {
        let app = std::sync::Arc::new(app());
        let save = |interval| {
            let task = PingTask {
                id: 0,
                name: "probe".into(),
                target: "1.1.1.1:443".into(),
                interval,
                nodes: vec![],
                ..Default::default()
            };
            save_ping_task(Admin, State(app.clone()), Json(task))
        };
        for refused in [0, -1, 4, 3_601, i64::MAX] {
            assert_eq!(save(refused).await.status(), StatusCode::BAD_REQUEST, "{refused}");
        }
        assert!(app.db.ping_tasks().unwrap().is_empty(), "a refused interval must not store a probe");

        // Both ends of the range still save, storing exactly what was sent.
        for ok in [5, 60, 3_600] {
            assert_eq!(save(ok).await.status(), StatusCode::OK, "{ok}");
        }
        let stored: Vec<i64> = app.db.ping_tasks().unwrap().iter().map(|t| t.interval).collect();
        assert_eq!(stored, vec![5, 60, 3_600]);
    }

    /// The update path follows a manifest's `url` to build a download address, so
    /// what counts as a GitHub repository constitutes the entire trust boundary:
    /// whatever this accepts, the hub will fetch.
    #[test]
    fn only_a_github_repository_url_can_name_a_release_to_download() {
        assert_eq!(
            github_repo("https://github.com/carsonmoon/jspanel-hub"),
            Some(("carsonmoon", "jspanel-hub"))
        );
        // A link to the repository, in whatever form the author wrote it.
        assert_eq!(github_repo("https://github.com/a/b.git"), Some(("a", "b")));
        assert_eq!(github_repo("https://github.com/a/b/tree/main"), Some(("a", "b")));
        assert_eq!(github_repo("https://github.com/a/b/"), Some(("a", "b")));

        for hostile in [
            "",
            // Not github.com, however much of it appears in the string.
            "http://github.com/a/b",
            "https://github.com.evil.test/a/b",
            "https://github.com@evil.test/a/b",
            "https://evil.test/https://github.com/a/b",
            // On github.com, but naming no repository to fetch from.
            "https://github.com/a",
            "https://github.com//b",
            "https://github.com/../../etc/passwd",
            "https://github.com/a/..",
            // Anything that could open a segment of its own in the URL built from
            // it, whether encoded, queried or fragmented.
            "https://github.com/a/b%2f..%2fc",
            "https://github.com/a/b?x=1",
            "https://github.com/a b",
        ] {
            assert_eq!(github_repo(hostile), None, "{hostile} must not name a download");
        }

        // The release tag also lands in that URL, arriving from the API rather
        // than the manifest.
        assert!(path_segment("v0.1.15") && path_segment("2024.1"));
        assert!(!path_segment("release/1.0") && !path_segment("..") && !path_segment(""));
    }

    /// The entire chunked-upload protocol: an upload is only ever as long as what
    /// has landed, so a piece continues it, restarts it, or is refused.
    #[tokio::test]
    async fn a_chunk_continues_an_upload_only_where_the_last_one_ended() {
        let path = std::env::temp_dir().join(format!("monitor-chunk-{}", std::process::id()));
        let path = path.to_str().unwrap();
        let piece = |offset, total| Chunk { offset, total };
        let body = |bytes: &'static [u8]| axum::body::Body::from(bytes);

        // Two pieces in order, with the length indicating where the next begins.
        assert_eq!(receive(path, &piece(0, 6), 1024, body(b"abc")).await.unwrap(), 3);
        assert_eq!(receive(path, &piece(3, 6), 1024, body(b"def")).await.unwrap(), 6);
        assert_eq!(std::fs::read(path).unwrap(), b"abcdef");

        // A gap, a rewind and an overshoot all produce the same refusal.
        assert!(receive(path, &piece(9, 12), 1024, body(b"xyz")).await.is_err());
        assert!(receive(path, &piece(3, 12), 1024, body(b"xyz")).await.is_err());
        assert!(receive(path, &piece(6, 7), 1024, body(b"toolong")).await.is_err());
        // None of them modified the file, so the upload can continue.
        assert_eq!(std::fs::metadata(path).unwrap().len(), 6);

        // The ceiling is checked against the declared total, before any bytes
        // arrive.
        assert!(receive(path, &piece(0, 4096), 1024, body(b"a")).await.is_err());
        assert!(receive(path, &piece(0, 0), 1024, body(b"")).await.is_err());

        // Starting over truncates whatever an interrupted attempt left behind.
        assert_eq!(receive(path, &piece(0, 2), 1024, body(b"hi")).await.unwrap(), 2);
        assert_eq!(std::fs::read(path).unwrap(), b"hi");
        std::fs::remove_file(path).unwrap();
    }

    /// Both scratch names a restore uses sit beside the live database, and one left
    /// behind is what the next upload fails on: `receive` refuses a first chunk
    /// that does not align with an existing file.
    ///
    /// This does not cover the rename in `db_restore`, which changes which path is
    /// open during the copy and would require a second upload landing inside it.
    /// It covers the part that outlives the request, which is what a later edit
    /// could silently drop.
    #[tokio::test]
    async fn a_finished_restore_leaves_no_scratch_file_behind() {
        let dir = std::env::temp_dir().join(format!("monitor-restore-{}", &random_token()[..16]));
        std::fs::create_dir_all(&dir).unwrap();
        let live = dir.join("live.db").to_string_lossy().into_owned();
        let app = std::sync::Arc::new(App::for_test(Db::open(&live).unwrap()));
        node(&app, "kept", true);

        // What a restore actually receives: a backup of a hub database.
        let copy = format!("{live}.copy");
        app.db.backup_into(&copy).unwrap();
        let bytes = std::fs::read(&copy).unwrap();
        std::fs::remove_file(&copy).unwrap();

        let done = db_restore(
            Admin,
            State(app.clone()),
            Query(Chunk { offset: 0, total: bytes.len() as u64 }),
            ConnectInfo("198.51.100.7:40000".parse().unwrap()),
            HeaderMap::new(),
            axum::body::Body::from(bytes),
        )
        .await;
        assert_eq!(done.status(), StatusCode::OK);
        assert_eq!(app.db.nodes().unwrap().len(), 1, "the backup went in");

        // The database and its journal are the only files that may remain.
        let left: Vec<String> = std::fs::read_dir(&dir)
            .unwrap()
            .filter_map(|e| e.ok().map(|e| e.file_name().to_string_lossy().into_owned()))
            .filter(|name| !matches!(name.as_str(), "live.db" | "live.db-wal" | "live.db-shm"))
            .collect();
        assert!(left.is_empty(), "left beside the database: {left:?}");
        std::fs::remove_dir_all(&dir).unwrap();
    }

    /// A connected agent holding one report. The receiver is returned because
    /// dropping it closes the channel, which is the signal `reset_token` is tested
    /// for.
    fn connect(app: &App, id: i64, metrics: Value) -> tokio::sync::mpsc::Receiver<String> {
        let (tx, rx) = tokio::sync::mpsc::channel(1);
        let mut agent = crate::agent_ws::Agent::new(7, tx, 0);
        agent.metrics = metrics;
        agent.last_seen = Utc::now().timestamp();
        app.agents.write().unwrap().insert(id, agent);
        rx
    }

    /// A probe assigned to `nodes`. The window query draws only a node's current
    /// assignments, so a fixture holding ping records requires one.
    fn task(app: &App, nodes: Vec<i64>) -> i64 {
        app.db
            .save_ping_task(&PingTask {
                id: 0,
                name: "probe".into(),
                target: "1.1.1.1:443".into(),
                interval: 60,
                nodes,
                ..Default::default()
            })
            .unwrap()
    }

    fn node(app: &App, name: &str, public: bool) -> i64 {
        app.db
            .create_node(
                &Node { name: name.into(), public, ..Default::default() },
                &format!("token-of-{name}"),
            )
            .unwrap()
    }

    /// A chart request costs roughly the same whatever it spans. This path
    /// requires no session, so an unbounded window would be megabytes of JSON any
    /// caller could have the hub build on the connection the agents report
    /// through.
    #[test]
    fn a_history_window_costs_the_same_however_wide_it_is() {
        let app = app();
        let id = node(&app, "n", true);
        let now = Utc::now().timestamp();
        // A month of history at the rate the hub writes it. Two probes, because
        // the budget is per series and a single-probe fixture would conceal that.
        const PROBES: i64 = 2;
        for _ in 0..PROBES {
            task(&app, vec![id]);
        }
        for i in 0..30 * 1440 {
            app.db.insert_metric(id, now - i * 60, &json!({"cpu": 1.0})).unwrap();
            for task in 1..=PROBES {
                app.db.insert_pings(id, &[(task, now - i * 20, 42)]).unwrap();
            }
        }

        // Including windows that do not divide evenly, which are where a step
        // rounded the wrong way overruns.
        for hours in [1, 6, 13, 23, 24, 168, 2_160] {
            let step = sample_step(hours, None);
            let since = now - hours * 3_600;
            let metrics = app.db.metrics(id, since, step).unwrap();
            let (ping, _) = app.db.ping_records(id, since, step).unwrap();
            // Against the budget itself rather than whatever the step produced:
            // derived from the step, this would only demonstrate that division
            // works. One bucket of slack, as the window rarely divides evenly.
            let cap = 1_441;
            assert!(metrics.len() <= cap, "{hours}h returned {} metric rows", metrics.len());
            assert!(
                ping.len() <= cap * PROBES as usize,
                "{hours}h returned {} ping rows for {PROBES} probes",
                ping.len()
            );
            // Thinned, but neither empty nor reaching outside the window.
            assert!(!metrics.is_empty() && !ping.is_empty(), "{hours}h returned nothing");
            // A bucket the window opens partway through begins before it.
            assert!(
                metrics.iter().all(|m| m["ts"].as_i64().unwrap() >= since - step),
                "{hours}h reached back too far"
            );
        }
        // The widest window costs no more than a narrow one: unthinned, a month of
        // history is 43,200 rows.
        assert!(app.db.metrics(id, now - 2_160 * 3_600, sample_step(2_160, None)).unwrap().len() <= 1_441);

        // A day returns every minute it holds: thinning exists only for what the
        // screen cannot draw.
        assert_eq!(sample_step(24, Some(2_000)), 60, "a day of minutes fits under the ceiling");
        assert_eq!(sample_step(6, Some(2_000)), 60, "and so does six hours");

        // A caller may request less than the budget, never more: the ceiling
        // belongs to the hub, since this path takes no credentials.
        assert!(sample_step(24, Some(390)) > sample_step(24, None));
        assert_eq!(sample_step(24, Some(100_000)), sample_step(24, None));
        assert_eq!(sample_step(24, Some(0)), sample_step(24, Some(60)));

        // Requesting one half leaves the other empty rather than sending it: on
        // the day window that half was two thirds of the response.
        let series = |q: &str| serde_urlencoded::from_str::<Window>(q).unwrap().series;
        assert_eq!(series("hours=24&series=ping").as_deref(), Some("ping"));
        assert!(series("hours=24").is_none(), "no series means both, which is what curl gets");
    }

    /// What a thinned bucket may return. Keeping one row and discarding the rest
    /// made the seven-day chart integrate to twice the traffic the minutes hold,
    /// and drew a probe losing half its packets as an unbroken line.
    #[test]
    fn a_thinned_bucket_answers_with_its_mean_and_says_what_it_lost() {
        let app = app();
        let id = node(&app, "n", true);
        // Anchored on a bucket boundary, one whole bucket in the past. Anchored on
        // `now`, the rows would straddle the boundary depending on the second the
        // suite runs at.
        let base = Utc::now().timestamp() / 120 * 120 - 120;
        // One bucket: a quiet minute and a busy one, then a probe that answered
        // once and timed out three times.
        // The quiet minute predates the peak column, whose default is 0.
        app.db.insert_metric(id, base + 10, &json!({"cpu": 0.0, "net_rx": 0, "net_tx": 3_000})).unwrap();
        app.db
            .insert_metric(
                id,
                base + 70,
                &json!({"cpu": 40.0, "net_rx": 1_000, "net_rx_max": 4_000, "net_tx": 1_000, "net_tx_max": 2_000}),
            )
            .unwrap();
        for _ in 0..3 {
            task(&app, vec![id]);
        }
        for (i, latency) in [30, -1, -1, -1].into_iter().enumerate() {
            app.db.insert_pings(id, &[(1, base + 10 + i as i64 * 20, latency)]).unwrap();
        }
        // A second probe that never answered, and a third that answered cleanly.
        app.db.insert_pings(id, &[(2, base + 10, -1)]).unwrap();
        app.db.insert_pings(id, &[(3, base + 10, 12)]).unwrap();

        let m = &app.db.metrics(id, base, 120).unwrap()[0];
        assert_eq!(m["cpu"], 20.0, "the bucket is its mean, not one row of it");
        assert_eq!(m["net_rx"], 500);
        assert_eq!(m["net_rx_max"], 4_000, "the bucket peaks where its busiest minute did");
        assert_eq!(m["net_tx_max"], 3_000, "a row without a peak counts as its own mean");
        assert_eq!(m["ts"], base, "stamped with the bucket, so every series shares a grid");

        // Keyed by task rather than index: the order is the panel's, which
        // `a_probe_chart_follows_the_panel_order` covers.
        let (rows, window_loss) = app.db.ping_records(id, base, 120).unwrap();
        let probe = |task: i64| {
            rows.iter().find(|r| r["task_id"] == task).unwrap_or_else(|| panic!("no probe {task}"))
        };
        assert_eq!(probe(1)["latency"], 30, "the median of what answered, not of the timeouts");
        assert_eq!(probe(1)["loss"], 75);
        assert_eq!(probe(2)["latency"], json!(null), "a bucket that was all timeout has no latency");
        assert_eq!(probe(2)["loss"], 100);
        // One answer, so there is nothing for a band to span.
        assert!(probe(1).get("band").is_none(), "{:?}", probe(1));
        // A clean bucket carries no loss key, which is why the percentage rounds
        // up: the key's absence denotes no loss, so no loss must be the only way
        // to produce it.
        assert!(probe(3).get("loss").is_none(), "{:?}", probe(3));
        // Each probe has one bucket here, so the window and bucket figures agree
        // -- precisely the fixture shape that concealed the difference between
        // them. The test below separates the two.
        assert_eq!(window_loss["2"], 100.0);
        assert!(window_loss.get("3").is_none(), "a probe that lost nothing is left out");

        // One timeout in a bucket too large for it to reach a whole percent:
        // truncating would report the same as a clean bucket.
        let wide = node(&app, "wide", true);
        let wide_probe = task(&app, vec![wide]);
        let wide_base = base / 180 * 180;
        for i in 0..180 {
            app.db.insert_pings(wide, &[(wide_probe, wide_base + i, if i == 0 { -1 } else { 20 })]).unwrap();
        }
        let (rows, _) = app.db.ping_records(wide, wide_base, 180).unwrap();
        assert_eq!(rows.len(), 1, "the fixture has to be one bucket for this to mean anything");
        let row = &rows[0];
        assert_eq!(row["loss"], 1, "a bucket that lost one of 180 has not lost none");

        // What the band conveys: the median reading and the two extremes the
        // bucket reached. Drawing 20 alone would render a 40 ms swing as a flat
        // point.
        let jitter = node(&app, "jitter", true);
        let jitter_probe = task(&app, vec![jitter]);
        for (i, latency) in [10, 20, 50, 20, 20].into_iter().enumerate() {
            app.db.insert_pings(jitter, &[(jitter_probe, wide_base + i as i64, latency)]).unwrap();
        }
        let row = &app.db.ping_records(jitter, wide_base, 180).unwrap().0[0];
        assert_eq!(row["latency"], 20, "the middle answer, not the mean of 24");
        assert_eq!(row["band"], json!([10, 50]));

        // An even count has no single middle value, so it is the mean of the two
        // straddling it. Every neighbouring pair differs, so selecting one rank
        // either way would yield 20 or 30 rather than 25.
        let even = node(&app, "even", true);
        let even_probe = task(&app, vec![even]);
        for (i, latency) in [40, 10, 30, 20].into_iter().enumerate() {
            app.db.insert_pings(even, &[(even_probe, wide_base + i as i64, latency)]).unwrap();
        }
        assert_eq!(app.db.ping_records(even, wide_base, 180).unwrap().0[0]["latency"], 25);
    }

    /// What a window lost is the proportion of its samples lost, and only the hub
    /// can determine it: `close_bucket` divides within each bucket and keeps the
    /// quotient, so the denominators are gone by the time a reader sees the rows.
    /// Averaging the bucket percentages would weight a bucket holding one sample
    /// equally with one holding twelve, and unequal buckets are the ordinary case
    /// rather than an edge one. The window's first and last are partial by
    /// construction, and a probe that starts, stops, loses its node or skips a
    /// round on a slow resolver produces more.
    #[test]
    fn a_probe_reports_the_share_of_the_window_it_lost_not_the_mean_of_its_buckets() {
        let app = app();
        let id = node(&app, "n", true);
        let probe = task(&app, vec![id]);
        let base = Utc::now().timestamp() / 60 * 60 - 120;
        // A full minute at five seconds per round with no loss, then a minute
        // holding one sample, which was lost, before the probe stopped.
        for i in 0..12 {
            app.db.insert_pings(id, &[(probe, base + i * 5, 20)]).unwrap();
        }
        app.db.insert_pings(id, &[(probe, base + 60, -1)]).unwrap();

        let (rows, loss) = app.db.ping_records(id, base, 60).unwrap();
        let per_bucket: Vec<i64> = rows.iter().map(|r| r["loss"].as_i64().unwrap_or(0)).collect();
        assert_eq!(per_bucket, vec![0, 100], "the buckets are right about themselves");

        // Their mean is 50%, while one round of thirteen did not answer.
        let window = loss.get(probe.to_string()).and_then(|v| v.as_f64()).expect("this probe lost one");
        assert!((window - 100.0 / 13.0).abs() < 1e-9, "{window}");
        assert!(window < 8.0, "the window lost {window}%, not the 50% its buckets average to");
    }

    #[test]
    fn the_public_view_hides_private_nodes_and_sensitive_fields() {
        let app = app();
        let open = node(&app, "open", true);
        node(&app, "hidden", false);
        app.db.save_facts(open, &json!({"hostname": "vps-1"}), "198.51.100.9", "").unwrap();

        // A live report, so the public view has metrics to strip. `hostname` is
        // what a node token in the wrong hands can insert, and what the agent
        // repository could add to the contract.
        let _held = connect(
            &app,
            open,
            json!({"boot_id": "abc", "net_rx_total": 134_000_000_000i64, "cpu": 1.0, "iface": "eth1",
                   "hostname": "db-prod-01", "ip": "203.0.113.7", "total_rx": 1}),
        );

        let public = visible_nodes(&app, false).unwrap();
        assert_eq!(public.len(), 1, "a node marked private must not be listed");
        assert_eq!(public[0]["name"], "open");
        // Disclosing the token would let any visitor impersonate the node.
        for hidden in ["ip", "addresses", "ipv4_auto", "ipv6_auto", "remark", "hostname", "token", "interval"]
        {
            assert!(public[0].get(hidden).is_none(), "{hidden} must not be public");
        }
        assert!(
            !serde_json::to_string(&public).unwrap().contains("token-of-open"),
            "no node's token may appear anywhere in a public payload"
        );
        // Raw kernel counters would disclose the machine's lifetime traffic, and
        // anything the contract does not name is not published at all, the report
        // coming from a machine holding one node's token.
        for hidden in ["boot_id", "net_rx_total", "net_tx_total", "hostname", "ip"] {
            assert!(public[0]["metrics"].get(hidden).is_none(), "{hidden} must not be public");
        }
        assert_eq!(public[0]["metrics"]["cpu"], 1.0, "the rest of the report still goes out");
        assert!(public[0]["metrics"].get("iface").is_none(), "the interface list is the panel's");

        let admin = visible_nodes(&app, true).unwrap();
        assert_eq!(admin.len(), 2);
        assert_eq!(admin[0]["ip"], "198.51.100.9");
        // The panel reads `iface` and nothing else the contract leaves out.
        assert_eq!(admin[0]["metrics"]["iface"], "eth1");
        for hidden in ["boot_id", "net_rx_total", "hostname", "ip"] {
            assert!(admin[0]["metrics"].get(hidden).is_none(), "{hidden} is not part of the panel's frame");
        }
        // The traffic inside `metrics` is the hub's, whatever the report claimed.
        for view in [&public[0], &admin[0]] {
            assert_eq!(view["metrics"]["total_rx"], view["total_rx"]);
            assert_eq!(view["metrics"]["month_tx"], view["month_tx"]);
        }
    }

    /// One address per family, marked with where it came from.
    #[test]
    fn a_node_shows_the_address_it_is_reached_by() {
        let rows = |ip, held, pins| -> Vec<String> {
            addresses(ip, held, pins).into_iter().map(|(a, source)| format!("{a} {source}")).collect()
        };
        let none = ("", "");
        // A public interface is the machine; a different exit in front of it is a
        // proxy and stays out.
        assert_eq!(
            rows("2001:db8::2", ("203.0.113.7", "2001:db8::2"), none),
            ["203.0.113.7 interface", "2001:db8::2 interface"]
        );
        assert_eq!(rows("198.51.100.1", ("203.0.113.7", ""), none), ["203.0.113.7 interface"]);
        // NAT: the exit replaces the private interface address, which nobody
        // outside can use.
        assert_eq!(rows("203.0.113.7", ("10.10.2.250", ""), none), ["203.0.113.7 exit"]);
        assert_eq!(rows("203.0.113.7", ("100.64.0.9", ""), none), ["203.0.113.7 exit"]);
        // An LXC guest behind NAT with a public /128, reached over v4 by a current
        // agent...
        assert_eq!(
            rows("203.0.113.7", ("10.10.1.5", "2401:b60:1c::5"), none),
            ["203.0.113.7 exit", "2401:b60:1c::5 interface"]
        );
        // ...and over v6 by an older one reporting the ULA ahead of it.
        assert_eq!(rows("2401:b60:1c::5", ("10.10.1.5", "fd42:43af::1"), none), ["2401:b60:1c::5 exit"]);
        // Behind a transparent proxy the exit is the proxy's; the home line can
        // only be set by hand.
        let home = ("192.168.1.5", "2409:8a1e::5");
        assert_eq!(rows("198.51.100.77", home, none), ["198.51.100.77 exit", "2409:8a1e::5 interface"]);
        assert_eq!(
            rows("198.51.100.77", home, ("203.0.113.50", "")),
            ["203.0.113.50 manual", "2409:8a1e::5 interface"]
        );
        // A pin wins over a public interface too, and may name a private address
        // for use on the LAN.
        assert_eq!(
            rows("", ("203.0.113.7", "2001:db8::5"), ("", "2001:db8::9")),
            ["203.0.113.7 interface", "2001:db8::9 manual"]
        );
        assert_eq!(rows("203.0.113.7", ("10.0.0.2", ""), ("10.0.0.2", "")), ["10.0.0.2 manual"]);
        // No interface in the exit's family: a translator (NAT64, WARP) that does
        // not lead to the machine.
        assert_eq!(rows("104.28.1.1", ("", "2001:db8::5"), none), ["2001:db8::5 interface"]);
        // An address reported under the other family's name is not that family's.
        assert_eq!(rows("203.0.113.7", ("2001:db8::5", ""), none), ["203.0.113.7 exit"]);
        // Nothing public anywhere: hub and node share a network, and the private
        // addresses are all there is.
        assert_eq!(rows("192.168.1.2", ("192.168.1.5", ""), none), ["192.168.1.5 interface"]);
        assert_eq!(
            rows("fd00::2", ("10.0.0.2", "fd00::5"), none),
            ["10.0.0.2 interface", "fd00::5 interface"]
        );
        assert_eq!(
            rows("198.18.0.1", ("192.168.1.5", ""), none),
            ["192.168.1.5 interface"],
            "a TUN proxy's fake-IP range is not public"
        );
        // With no interface reported the connection is all there is, and nothing
        // says it is not the machine's own.
        assert_eq!(rows("203.0.113.7", none, none), ["203.0.113.7 connection"]);
        assert_eq!(rows("", ("10.0.0.2", ""), none), ["10.0.0.2 interface"]);
        assert!(rows("", none, none).is_empty());

        // The panel gets the list, and per family what shows with the pin
        // cleared.
        let app = app();
        let id = node(&app, "n", true);
        app.db
            .save_facts(id, &json!({"ipv4": "10.10.1.5", "ipv6": "2401:b60:1c::5"}), "203.0.113.7", "")
            .unwrap();
        let patch: NodePatch = serde_json::from_value(json!({"ipv4_pin": "198.51.100.50"})).unwrap();
        app.db.update_node(id, &patch).unwrap();
        let view = &visible_nodes(&app, true).unwrap()[0];
        assert_eq!(
            view["addresses"],
            json!([{"address": "198.51.100.50", "source": "manual"}, {"address": "2401:b60:1c::5", "source": "interface"}])
        );
        assert_eq!(
            (&view["ipv4_auto"], &view["ipv6_auto"]),
            (&json!("203.0.113.7"), &json!("2401:b60:1c::5"))
        );

        // Private addresses show only when nothing public is known, so the pin
        // the other family keeps decides: v4 falls back to nothing while the v6
        // pin stands.
        let lan = node(&app, "lan", true);
        app.db
            .save_facts(lan, &json!({"ipv4": "192.168.1.5", "ipv6": "fd00::5"}), "192.168.1.2", "")
            .unwrap();
        let patch: NodePatch = serde_json::from_value(json!({"ipv6_pin": "2001:db8::9"})).unwrap();
        app.db.update_node(lan, &patch).unwrap();
        let view = visible_nodes(&app, true).unwrap().into_iter().find(|v| v["id"] == lan).unwrap();
        assert_eq!((&view["ipv4_auto"], &view["ipv6_auto"]), (&json!(""), &json!("fd00::5")));
    }

    #[tokio::test]
    async fn rotating_a_token_closes_the_session_the_old_one_opened() {
        let app = std::sync::Arc::new(app());
        let id = node(&app, "n", true);
        let mut rx = connect(&app, id, Value::Null);

        let response = reset_token(Admin, axum::extract::State(app.clone()), Path(id)).await;
        assert_eq!(response.status(), StatusCode::OK);
        // The agent loop selects on this receiver, so a closed channel is how it
        // learns to stop. `try_recv`, because `recv().await` on a channel
        // incorrectly left open would hang the suite rather than fail it.
        assert!(
            matches!(rx.try_recv(), Err(tokio::sync::mpsc::error::TryRecvError::Disconnected)),
            "the old agent's channel must be closed"
        );
        assert!(app.agents.read().unwrap().is_empty(), "the node must read as offline at once");
    }

    /// A batch writes to every selected node or to none, accepts only what a
    /// selection can share, and a group reaches the status page.
    #[tokio::test]
    async fn a_batch_edit_applies_to_all_selected_nodes_or_none() {
        let app = std::sync::Arc::new(app());
        let state = || axum::extract::State(app.clone());
        let (a, b, c) = (node(&app, "a", true), node(&app, "b", true), node(&app, "c", true));
        let batch = |ids: Vec<i64>, patch: Value| {
            Ok(Json(NodeBatch { ids, patch: serde_json::from_value(patch).unwrap() }))
        };
        let group = |id| app.db.node(id).unwrap().unwrap().group;

        let r =
            update_nodes(Admin, state(), batch(vec![a, b, a], json!({"group": " 香港 ", "notify": true})))
                .await;
        assert_eq!(r.status(), StatusCode::OK);
        assert_eq!((group(a), group(b), group(c)), ("香港".into(), "香港".into(), String::new()));
        assert!(app.db.node(b).unwrap().unwrap().notify);

        // One id gone: nothing is written, not even to the nodes still there.
        let r = update_nodes(Admin, state(), batch(vec![a, 999], json!({"group": "东京"}))).await;
        assert_eq!(r.status(), StatusCode::NOT_FOUND);
        assert_eq!(group(a), "香港", "a refused batch leaves every node as it was");

        // Only the listed fields deserialize, so the extractor refuses the rest.
        for refused in [json!({"name": "x"}), json!({"ipv4_pin": "1.2.3.4"}), json!({"public": false})] {
            assert!(serde_json::from_value::<BatchPatch>(refused.clone()).is_err(), "{refused}");
        }
        // Counted in characters, not bytes: thirteen of them take 39 bytes.
        let r = update_nodes(Admin, state(), batch(vec![a], json!({"group": "港".repeat(MAX_GROUP)}))).await;
        assert_eq!(r.status(), StatusCode::OK);
        let r =
            update_nodes(Admin, state(), batch(vec![a], json!({"group": "港".repeat(MAX_GROUP + 1)}))).await;
        assert_eq!(r.status(), StatusCode::BAD_REQUEST);
        assert_eq!(
            update_nodes(Admin, state(), batch(vec![], json!({"notify": false}))).await.status(),
            StatusCode::BAD_REQUEST
        );

        assert!(live_snapshot(&app, false).as_str().contains(r#""group":"香港""#), "the group is public");
    }

    /// What the panel saves is what an anonymous visitor reads, under the same
    /// condition as the node list, and only an installed theme takes a write.
    #[tokio::test]
    async fn saved_theme_settings_reach_visitors_while_the_status_page_is_open() {
        let app = std::sync::Arc::new(app());
        let state = || axum::extract::State(app.clone());
        let read = |short: &str| theme_config(state(), HeaderMap::new(), Path(short.to_owned()));
        let body = |r: Response| async { axum::body::to_bytes(r.into_body(), usize::MAX).await.unwrap() };

        assert_eq!(&body(read("default").await).await[..], b"{}", "nothing saved reads as no overrides");
        let values = json!({"notice": "维护中", "show_price": false}).as_object().unwrap().clone();
        let saved = save_theme_config(Admin, state(), Path("default".into()), Json(values.clone())).await;
        assert_eq!(saved.status(), StatusCode::NO_CONTENT);
        let read_back: Value = serde_json::from_slice(&body(read("default").await).await).unwrap();
        assert_eq!(read_back, Value::Object(values.clone()));

        let missing = save_theme_config(Admin, state(), Path("aurora".into()), Json(values.clone())).await;
        assert_eq!(missing.status(), StatusCode::BAD_REQUEST, "a theme that is not installed takes no write");
        assert_eq!(read("../etc").await.status(), StatusCode::NOT_FOUND);

        app.db.set("public_page", "off").unwrap();
        assert_eq!(
            read("default").await.status(),
            StatusCode::UNAUTHORIZED,
            "a closed status page hides them too"
        );
    }

    /// Days to expiry are counted on the hub's calendar and are public, like the
    /// date itself; no date counts nothing.
    #[test]
    fn days_to_expiry_follow_the_hubs_calendar() {
        let app = app();
        let id = node(&app, "a", true);
        let expires_in = || visible_nodes(&app, false).unwrap()[0]["expires_in"].clone();
        assert_eq!(expires_in(), Value::Null);
        let today = Local::now().date_naive();
        for days in [3, 0, -1] {
            app.db.set_expiry(id, &(today + chrono::Duration::days(days)).to_string()).unwrap();
            assert_eq!(expires_in(), json!(days));
        }
    }

    /// A write naming a node that no longer exists, such as one deleted from
    /// another tab, is refused rather than reported as saved.
    #[tokio::test]
    async fn writes_to_a_missing_node_are_not_found() {
        let app = std::sync::Arc::new(app());
        let state = || axum::extract::State(app.clone());
        let patch = Ok(Json(NodePatch { notify: Some(true), ..Default::default() }));
        assert_eq!(update_node(Admin, state(), Path(9), patch).await.status(), StatusCode::NOT_FOUND);
        assert_eq!(delete_node(Admin, state(), Path(9)).await.status(), StatusCode::NOT_FOUND);
        assert_eq!(reset_token(Admin, state(), Path(9)).await.status(), StatusCode::NOT_FOUND);
        let traffic = Json(TrafficPatch { total_rx: Some(1), ..Default::default() });
        assert_eq!(patch_traffic(Admin, state(), Path(9), traffic).await.status(), StatusCode::NOT_FOUND);
    }

    /// Deleting a node must reach the connection it opened, for the same reason
    /// rotating its token does, and more urgently: SQLite reassigns the freed id
    /// to the next node created. Left connected, the old machine reports under
    /// that id, so an undeployed node appears online with another machine's
    /// metrics, and its traffic and history are booked to it.
    #[tokio::test]
    async fn deleting_a_node_closes_its_session_so_the_next_id_does_not_inherit_it() {
        let app = std::sync::Arc::new(app());
        let old = node(&app, "old", true);
        let mut rx = connect(&app, old, json!({"cpu": 42.0}));

        assert_eq!(
            delete_node(Admin, axum::extract::State(app.clone()), Path(old)).await.status(),
            StatusCode::OK
        );
        assert!(
            matches!(rx.try_recv(), Err(tokio::sync::mpsc::error::TryRecvError::Disconnected)),
            "the deleted node's agent must be told to go"
        );

        // SQLite reuses the id; nothing of the old machine may accompany it.
        let fresh = node(&app, "fresh", true);
        assert_eq!(fresh, old, "the fixture only means anything if the id is reused");
        let nodes = visible_nodes(&app, true).unwrap();
        assert_eq!(nodes.len(), 1);
        assert_eq!(nodes[0]["online"], json!(false), "a node nobody deployed is not online");
        assert_eq!(nodes[0]["metrics"], Value::Null, "and it has nobody else's metrics");
    }

    /// Values set by hand take the place of automatic ones, so each is held to
    /// what the automatic value would have to be, and of the three only the
    /// country reaches the status page. The create path stores none of them.
    #[tokio::test]
    async fn values_set_by_hand_are_checked_and_only_the_country_goes_public() {
        let app = std::sync::Arc::new(app());
        let id = node(&app, "n", true);
        app.db.save_facts(id, &json!({}), "198.51.100.77", "198.51.100.77").unwrap();
        app.db.set_country(id, "SG", "198.51.100.77").unwrap();
        let put = |patch: Value| {
            update_node(
                Admin,
                axum::extract::State(app.clone()),
                Path(id),
                Ok(Json(serde_json::from_value(patch).unwrap())),
            )
        };
        for bad in [
            json!({"country_pin": "CHN"}),
            json!({"country_pin": "中国"}),
            json!({"country_pin": "C1"}),
            json!({"ipv4_pin": "2409:8a1e::5"}),
            json!({"ipv4_pin": "203.0.113.9:22"}),
            json!({"ipv4_pin": "203.0.113.256"}),
            json!({"ipv6_pin": "203.0.113.9"}),
            json!({"ipv6_pin": "[2409:8a1e::5]:22"}),
        ] {
            assert_eq!(put(bad.clone()).await.status(), StatusCode::BAD_REQUEST, "accepted {bad}");
        }
        let typed =
            json!({"country_pin": " cn ", "ipv4_pin": " 203.0.113.9 ", "ipv6_pin": "2409:8A1E:0::0088"});
        assert_eq!(put(typed).await.status(), StatusCode::OK);
        let stored = app.db.node(id).unwrap().unwrap();
        assert_eq!(
            (stored.country_pin.as_str(), stored.ipv4_pin.as_str(), stored.ipv6_pin.as_str()),
            ("CN", "203.0.113.9", "2409:8a1e::88"),
            "stored canonical"
        );

        let public = visible_nodes(&app, false).unwrap()[0].to_string();
        assert!(public.contains(r#""country":"CN""#), "the pin replaces the looked-up country: {public}");
        assert!(
            !public.contains("203.0.113.9") && !public.contains("2409:8a1e::88") && !public.contains("SG")
        );
        let full = &visible_nodes(&app, true).unwrap()[0];
        assert_eq!(
            (full["country_auto"].as_str(), full["ipv4_pin"].as_str()),
            (Some("SG"), Some("203.0.113.9"))
        );

        // A hello leaves the pins alone; empty returns each to automatic.
        app.db.save_facts(id, &json!({}), "198.51.100.88", "198.51.100.88").unwrap();
        assert_eq!(app.db.node(id).unwrap().unwrap().ipv4_pin, "203.0.113.9");
        assert_eq!(
            put(json!({"country_pin": "", "ipv4_pin": " ", "ipv6_pin": ""})).await.status(),
            StatusCode::OK
        );
        let stored = app.db.node(id).unwrap().unwrap();
        assert!(stored.country_pin.is_empty() && stored.ipv4_pin.is_empty() && stored.ipv6_pin.is_empty());
        assert_eq!(
            visible_nodes(&app, false).unwrap()[0]["country"],
            "",
            "back to the lookup, which the new address left owing"
        );
    }

    /// Both writers enforce the same limits. The create path formerly accepted a
    /// whole `Node` unchecked, leaving everything the update path refuses
    /// reachable by another route.
    #[tokio::test]
    async fn both_write_paths_refuse_the_same_out_of_range_values() {
        let app = std::sync::Arc::new(app());
        let id = node(&app, "n", true);
        for bad in [
            json!({"name": "x", "traffic_reset_day": 99}),
            json!({"name": "x", "price": -5.0}),
            json!({"name": "x", "traffic_limit": -1}),
            json!({"name": "x", "currency": "USDT"}),
            json!({"name": "x", "currency": "港币"}),
            json!({"name": "x", "billing_cycle": "0m"}),
            json!({"name": "x", "billing_cycle": "1201m"}),
            json!({"name": "x", "billing_cycle": "weekly"}),
        ] {
            let created = create_node(
                Admin,
                axum::extract::State(app.clone()),
                panel_headers(),
                Ok(Json(serde_json::from_value(bad.clone()).unwrap())),
            )
            .await;
            assert_eq!(created.status(), StatusCode::BAD_REQUEST, "create accepted {bad}");
            let updated = update_node(
                Admin,
                axum::extract::State(app.clone()),
                Path(id),
                Ok(Json(serde_json::from_value(bad.clone()).unwrap())),
            )
            .await;
            assert_eq!(updated.status(), StatusCode::BAD_REQUEST, "update accepted {bad}");
        }
        assert_eq!(app.db.nodes().unwrap().len(), 1, "nothing was created");
    }

    /// A length with a name is stored under it, so a theme built for hub 1.3.0
    /// still labels it.
    #[tokio::test]
    async fn currency_and_cycle_are_stored_in_one_spelling() {
        let app = std::sync::Arc::new(app());
        let id = node(&app, "n", true);
        for (sent, currency, cycle) in [
            (json!({"currency": " hkd ", "billing_cycle": "60m"}), "HKD", "60m"),
            (json!({"billing_cycle": "12m"}), "HKD", "yearly"),
            (json!({"billing_cycle": "once"}), "HKD", "once"),
        ] {
            let put = update_node(
                Admin,
                State(app.clone()),
                Path(id),
                Ok(Json(serde_json::from_value(sent).unwrap())),
            );
            assert_eq!(put.await.status(), StatusCode::OK);
            let stored = app.db.node(id).unwrap().unwrap();
            assert_eq!((stored.currency.as_str(), stored.billing_cycle.as_str()), (currency, cycle));
        }
    }

    /// A stream outlives the request that opened it, so everything the handshake
    /// tested must be re-read rather than captured -- both answers, not one. The
    /// admin frame carries every node's token in the clear, and the public frame
    /// is what switching the status page off is meant to withdraw; a socket
    /// surviving either decision would continue sending what was withdrawn.
    #[test]
    fn a_stream_re_reads_both_answers_its_handshake_tested() {
        let app = app();
        let hash = sha256("live-token");
        app.db.create_session(&hash, Utc::now().timestamp() + 3_600, "198.51.100.7", "test-agent").unwrap();

        assert_eq!(stream_audience(&app, Some(&hash)), Some(true), "a live session gets the admin frame");
        assert_eq!(stream_audience(&app, None), Some(false), "an anonymous stream gets the public one");

        // Signing out, another device revoking this one, a password change and a
        // restore all manifest as this row disappearing.
        app.db.drop_session(&hash).unwrap();
        assert_eq!(stream_audience(&app, Some(&hash)), None, "a revoked session must end its stream");

        // The other half. `live_ws` refuses a new anonymous connection from here
        // and `nodes` answers 401, so a stream that continued was the only
        // remaining route, for as long as the tab stayed open.
        app.db.create_session(&hash, Utc::now().timestamp() + 3_600, "198.51.100.7", "test-agent").unwrap();
        app.db.set("public_page", "off").unwrap();
        assert_eq!(stream_audience(&app, None), None, "closing the status page must end anonymous streams");
        assert_eq!(stream_audience(&app, Some(&hash)), Some(true), "a signed-in operator still gets theirs");
    }

    #[test]
    fn the_shared_snapshot_keeps_the_two_audiences_apart() {
        let app = app();
        let open = node(&app, "open", true);
        node(&app, "hidden", false);
        app.db.save_facts(open, &json!({"hostname": "vps-1"}), "198.51.100.9", "").unwrap();

        let public = live_snapshot(&app, false);
        let admin = live_snapshot(&app, true);
        // Caching must never let one audience's payload reach the other.
        assert!(!public.as_str().contains("198.51.100.9"), "the public frame must carry no address");
        assert!(!public.as_str().contains("hidden"), "the public frame must carry no private node");
        assert!(admin.as_str().contains("198.51.100.9") && admin.as_str().contains("hidden"));

        // Two reads over unchanged data prove nothing, since a rebuild returns the
        // same bytes, so the data is modified first.
        node(&app, "late", true);
        assert_eq!(live_snapshot(&app, false), public, "the frame is reused, not rebuilt per viewer");
    }

    #[test]
    fn a_clock_stepping_backwards_does_not_pin_a_stale_frame() {
        let app = app();
        node(&app, "first", true);
        live_snapshot(&app, false);

        // NTP correcting a fresh boot leaves the cached stamp in the future, which
        // does not constitute a young frame.
        app.snapshot.lock().unwrap()[0].0 = Utc::now().timestamp_millis() + 60_000;
        node(&app, "added-after", true);
        assert!(live_snapshot(&app, false).as_str().contains("added-after"));
    }

    /// The panel sends only a name, and expects the node just added to appear in
    /// the frame it is already streaming.
    #[tokio::test]
    async fn a_node_added_from_the_panel_needs_only_a_name_and_shows_up_at_once() {
        let app = std::sync::Arc::new(app());
        node(&app, "existing", true);
        assert!(!live_snapshot(&app, true).as_str().contains("added"));

        let added: Node = serde_json::from_value(json!({"name": "added"})).unwrap();
        // The defaults the panel relies on by omitting them, `public` above all:
        // the alternative would publish a node that was never published.
        assert!(added.public);
        assert_eq!(added.billing_cycle, "monthly");
        assert_eq!(added.traffic_reset_day, 1);

        let created = create_node(Admin, State(app.clone()), panel_headers(), Ok(Json(added))).await;
        assert_eq!(created.status(), StatusCode::OK);
        // Frames are cached for nearly two seconds, so without dropping the cache
        // the node just added would disappear from the list.
        assert!(live_snapshot(&app, true).as_str().contains("added"));

        // A name consisting only of spaces is refused and leaves no node behind.
        let blank = Json(serde_json::from_value::<Node>(json!({"name": "   "})).unwrap());
        let refused = create_node(Admin, State(app.clone()), panel_headers(), Ok(blank)).await;
        assert_eq!(refused.status(), StatusCode::BAD_REQUEST);
        assert_eq!(app.db.nodes().unwrap().len(), 2);
    }

    /// Every gate on the anonymous route, in the order a batch install encounters
    /// them: closed, wrong key, open, expired, closed manually.
    #[tokio::test]
    async fn registration_only_works_inside_a_window_the_panel_opened() {
        let app = std::sync::Arc::new(app());
        let register = |key: Option<&str>, name: &str| {
            let mut headers = HeaderMap::new();
            if let Some(key) = key {
                headers.insert("authorization", format!("Bearer {key}").parse().unwrap());
            }
            agent_register(
                State(app.clone()),
                ConnectInfo("198.51.100.7:40000".parse().unwrap()),
                headers,
                name.to_owned(),
            )
        };

        // Nothing was opened, so no key is correct.
        assert_eq!(register(Some("guess"), "a").await.status(), StatusCode::FORBIDDEN);
        assert!(app.db.nodes().unwrap().is_empty());

        assert_eq!(open_register(Admin, State(app.clone()), panel_headers()).await.status(), StatusCode::OK);
        let key = app.db.get("register_key").unwrap();
        assert_eq!(register(Some("guess"), "a").await.status(), StatusCode::FORBIDDEN);
        assert_eq!(register(None, "a").await.status(), StatusCode::FORBIDDEN);
        assert!(app.db.nodes().unwrap().is_empty());

        let issued = register(Some(&key), "  web-01\n").await;
        assert_eq!(issued.status(), StatusCode::OK);
        let token = axum::body::to_bytes(issued.into_body(), usize::MAX).await.unwrap().to_vec();
        let token = String::from_utf8(token).unwrap();
        // The purpose of the route: what returned is a token an agent can connect
        // with, not merely a 200.
        let id = app.db.node_by_token(&token).unwrap().expect("token opens a node");
        let node = app.db.nodes().unwrap().into_iter().find(|n| n.id == id).unwrap();
        assert_eq!(node.name, "web-01");
        // Registered nodes take the panel's defaults rather than `Node::default()`.
        assert!(node.public);
        assert_eq!(node.traffic_reset_day, 1);

        // An hour later the same key is worthless, which is what makes leaving the
        // window open harmless.
        app.db.set("register_until", &(Utc::now().timestamp() - 1).to_string()).unwrap();
        assert_eq!(register(Some(&key), "b").await.status(), StatusCode::FORBIDDEN);

        // Reopened, then closed manually: the key from the open window stops
        // working.
        open_register(Admin, State(app.clone()), panel_headers()).await;
        let key = app.db.get("register_key").unwrap();
        assert_eq!(close_register(Admin, State(app.clone())).await.status(), StatusCode::NO_CONTENT);
        assert_eq!(register(Some(&key), "c").await.status(), StatusCode::FORBIDDEN);
        assert_eq!(app.db.nodes().unwrap().len(), 1);
    }

    /// A rerun of the batch command on a registered machine keeps its node, also
    /// after the window closed, until that node is deleted from the panel.
    #[tokio::test]
    async fn a_rerun_keeps_its_node_until_the_node_is_deleted() {
        let app = std::sync::Arc::new(app());
        let register = |key: &str, held: &str| {
            let mut headers = HeaderMap::new();
            headers.insert("authorization", format!("Bearer {key}").parse().unwrap());
            // curl omits a header whose value is empty, so a machine holding no
            // token sends none.
            if !held.is_empty() {
                headers.insert(HELD_TOKEN, held.parse().unwrap());
            }
            agent_register(
                State(app.clone()),
                ConnectInfo("198.51.100.7:40000".parse().unwrap()),
                headers,
                "web-01".to_owned(),
            )
        };
        let text = |r: Response| async {
            String::from_utf8(axum::body::to_bytes(r.into_body(), usize::MAX).await.unwrap().to_vec())
                .unwrap()
        };

        open_register(Admin, State(app.clone()), panel_headers()).await;
        let key = app.db.get("register_key").unwrap();
        let token = text(register(&key, "").await).await;
        let id = app.db.node_by_token(&token).unwrap().expect("token opens a node");

        assert_eq!(text(register(&key, &token).await).await, token);
        close_register(Admin, State(app.clone())).await;
        assert_eq!(text(register(&key, &token).await).await, token, "the token outlives its window");
        assert_eq!(app.db.nodes().unwrap().len(), 1);

        // Deleted: the held token no longer answers, so a closed window refuses
        // rather than handing back a token the agent would be refused with.
        app.db.delete_node(id).unwrap();
        assert_eq!(register(&key, &token).await.status(), StatusCode::FORBIDDEN);
        open_register(Admin, State(app.clone()), panel_headers()).await;
        let key = app.db.get("register_key").unwrap();
        let fresh = text(register(&key, &token).await).await;
        assert_ne!(fresh, token);
        assert!(app.db.node_by_token(&fresh).unwrap().is_some());
        assert_eq!(app.db.nodes().unwrap().len(), 1);
    }

    /// The ceiling on the anonymous route: a leaked key cannot fill the table.
    #[tokio::test]
    async fn one_window_stops_registering_at_the_limit() {
        let app = std::sync::Arc::new(app());
        open_register(Admin, State(app.clone()), panel_headers()).await;
        let key = app.db.get("register_key").unwrap();
        for i in 0..REGISTER_LIMIT {
            node(&app, &format!("n{i}"), true);
        }
        let mut headers = HeaderMap::new();
        headers.insert("authorization", format!("Bearer {key}").parse().unwrap());
        let refused = agent_register(
            State(app.clone()),
            ConnectInfo("198.51.100.7:40000".parse().unwrap()),
            headers,
            "one-too-many".to_owned(),
        )
        .await;
        assert_eq!(refused.status(), StatusCode::FORBIDDEN);
        assert_eq!(app.db.nodes().unwrap().len() as i64, REGISTER_LIMIT);
    }

    #[test]
    fn a_node_view_carries_traffic_even_while_offline() {
        let app = app();
        let id = node(&app, "n", true);
        app.db.accumulate(id, "b", (100, 100), Local::now()).unwrap();
        app.db.accumulate(id, "b", (900, 500), Local::now()).unwrap();
        app.db.touch_seen(id, 1_700_000_000, &serde_json::Value::Null).unwrap();

        let view = &visible_nodes(&app, true).unwrap()[0];
        assert_eq!(view["online"], false);
        assert_eq!(view["metrics"], Value::Null);
        assert_eq!(view["total_rx"], 800, "traffic is stored, not derived from the live state");
        assert_eq!(view["total_tx"], 400);
        // The live entry went with the connection, so "offline since" must come
        // from the node row.
        assert_eq!(view["last_seen"], 1_700_000_000);
    }

    /// A capacity arrives twice -- once in the facts stored at the handshake, and
    /// again in every report -- and the two diverge as soon as a disk is mounted
    /// on a running machine, which the agent detects by re-reading its mount table
    /// every sample. Drawn from the stored copy, the card and the detail page
    /// showed the same host two different sizes until it reconnected.
    #[test]
    fn a_capacity_that_changed_since_the_handshake_is_the_reported_one() {
        let app = app();
        let id = node(&app, "n", true);
        // What the handshake stored: 30 GB of disk, 1 GB of swap.
        app.db
            .save_facts(
                id,
                &json!({"mem_total": 1_000, "swap_total": 1i64 << 30, "disk_total": 30i64 << 30}),
                "ip",
                "",
            )
            .unwrap();

        let offline = &visible_nodes(&app, true).unwrap()[0];
        assert_eq!(
            offline["disk_total"],
            30i64 << 30,
            "with nobody connected the stored facts are all there is"
        );

        // A 5 GB volume is mounted and swap is disabled. The same session, with no
        // second hello, so the stored facts do not change.
        let _held = connect(
            &app,
            id,
            json!({"mem_total": 1_000, "swap_total": 0, "disk_total": 35i64 << 30, "cpu": 1.0}),
        );
        let live = &visible_nodes(&app, true).unwrap()[0];
        assert_eq!(live["disk_total"], 35i64 << 30, "the report is the truth while the agent is connected");
        assert_eq!(live["swap_total"], 0, "swapoff means zero, not the gigabyte that was there at connect");
        assert_eq!(live["disk_total"], live["metrics"]["disk_total"], "one number, not two");
        assert_eq!(app.db.node(id).unwrap().unwrap().disk_total, 30i64 << 30, "and no extra write to get it");
    }

    /// `PUBLIC_HOURS` bounds one window; this bounds how many are built
    /// concurrently. Each holds the connection the agents report through for its
    /// entire scan, and the path takes no credentials. `PASSWORD_GATE` refuses the
    /// same way; `RELAY_GATE` queues briefly instead, as a batch install is one
    /// burst of legitimate requests.
    #[tokio::test]
    async fn history_queries_past_the_gate_are_refused_rather_than_queued() {
        let _serial = HISTORY_TESTS.lock().await;
        let app = std::sync::Arc::new(app());
        let id = node(&app, "n", true);
        let ask = || {
            metrics(
                State(app.clone()),
                HeaderMap::new(),
                Path(id),
                Query(Window { hours: 1, points: None, series: None }),
            )
        };

        let held: Vec<_> =
            (0..HISTORY_SLOTS).map(|_| HISTORY_GATE.try_acquire().expect("up to the limit")).collect();
        assert_eq!(ask().await.status(), StatusCode::SERVICE_UNAVAILABLE);
        drop(held);
        assert_eq!(ask().await.status(), StatusCode::OK, "a finished query gives its slot back");

        // An unauthorised caller is told so rather than asked to retry later: the
        // gate sits behind the visibility check deliberately.
        app.db.set("public_page", "off").unwrap();
        let held: Vec<_> =
            (0..HISTORY_SLOTS).map(|_| HISTORY_GATE.try_acquire().expect("up to the limit")).collect();
        assert_eq!(ask().await.status(), StatusCode::UNAUTHORIZED);
        drop(held);
    }

    /// A settings write lands whole or not at all. Changing the password drops
    /// every session and places the replacement cookie on the response, so a 400
    /// raised afterwards -- on a later key, in whatever order the map iterates --
    /// would sign the admin out of every device without explanation.
    #[tokio::test]
    async fn a_settings_write_is_all_or_nothing() {
        let app = std::sync::Arc::new(app());
        app.db.set("admin_password_hash", "the-old-hash").unwrap();
        let save = |body: Value| {
            save_settings(
                Admin,
                State(app.clone()),
                ConnectInfo("198.51.100.7:40000".parse().unwrap()),
                HeaderMap::new(),
                Json(body),
            )
        };

        // BTreeMap order places the password first, which is the failing case.
        let refused = save(json!({"admin_password": "a-long-enough-one", "retention_days": "abc"})).await;
        assert_eq!(refused.status(), StatusCode::BAD_REQUEST);
        assert_eq!(app.db.get("admin_password_hash").as_deref(), Some("the-old-hash"));

        // A correctly named key carrying the wrong type is refused rather than
        // discarded while the response reports success.
        let refused = save(json!({"public_page": false})).await;
        assert_eq!(refused.status(), StatusCode::BAD_REQUEST);
        assert_eq!(app.db.get("public_page"), None);

        let saved = save(json!({"public_page": "off", "retention_days": "7"})).await;
        assert_eq!(saved.status(), StatusCode::OK);
        assert_eq!(app.db.get("retention_days").as_deref(), Some("7"));
    }

    /// The install script and the sign-in page keep separate counters: five
    /// machines started with a stale key is a misconfigured deploy, and a shared
    /// counter would lock the operator out of the panel for the lockout window.
    #[tokio::test]
    async fn a_wrong_registration_key_does_not_lock_the_sign_in_page() {
        let app = std::sync::Arc::new(app());
        app.db.set("register_key", "the-key").unwrap();
        app.db.set("register_until", &(Utc::now().timestamp() + 60).to_string()).unwrap();
        let mut headers = HeaderMap::new();
        headers.insert("authorization", "Bearer wrong".parse().unwrap());
        let peer: std::net::SocketAddr = "198.51.100.7:9000".parse().unwrap();

        // The attempt after the last permitted one answers 429 rather than 403.
        for _ in 0..5 {
            let refused =
                agent_register(State(app.clone()), ConnectInfo(peer), headers.clone(), "n".into()).await;
            assert_eq!(refused.status(), StatusCode::FORBIDDEN);
        }
        assert!(app.registrations.locked(peer.ip()), "the register route counts its own failures");
        assert!(!app.throttle.locked(peer.ip()), "and the panel's sign-in page is not one of them");
    }

    #[test]
    fn per_node_reads_follow_the_public_flag_and_the_public_page_switch() {
        let app = app();
        let open = node(&app, "open", true);
        let hidden = node(&app, "hidden", false);

        assert!(readable(&app, false, open), "a published node is readable by anyone");
        assert!(!readable(&app, false, hidden), "a private node is not");
        assert!(!readable(&app, false, 9999), "an unknown id is not");
        assert!(readable(&app, true, hidden), "the panel sees a private node");

        // Switching the public page off closes even a published node.
        app.db.set("public_page", "off").unwrap();
        assert!(!readable(&app, false, open));
        assert!(readable(&app, true, open), "and never closes it for the panel");
    }

    /// The window ceiling is a scan bound rather than a response bound: the
    /// thinning already limits the row count, while a quarter-year still reads
    /// every row behind it holding the write connection.
    #[tokio::test]
    async fn an_anonymous_history_window_stops_at_a_week() {
        let _serial = HISTORY_TESTS.lock().await;
        let app = std::sync::Arc::new(app());
        let id = node(&app, "n", true);
        let now = Utc::now().timestamp();
        // One sample per day for a month, so a row's presence identifies its
        // window. The minute of slack keeps day seven clear of the 168-hour cutoff:
        // exactly on the boundary, a second elapsing between these inserts and the
        // query below would drop it and leave the count one short.
        for day in 0..30 {
            app.db.insert_metric(id, now - day * 86_400 + 60, &json!({"cpu": 1.0})).unwrap();
        }
        let ask = |hours| {
            let query = format!("hours={hours}&series=metrics");
            metrics(
                State(app.clone()),
                HeaderMap::new(),
                Path(id),
                Query(serde_urlencoded::from_str::<Window>(&query).unwrap()),
            )
        };
        let rows =
            |body: &str| serde_json::from_str::<Value>(body).unwrap()["metrics"].as_array().unwrap().len();

        let week = axum::body::to_bytes(ask(168).await.into_body(), usize::MAX).await.unwrap();
        assert_eq!(rows(std::str::from_utf8(&week).unwrap()), 8, "a week reaches back seven days");

        // Requesting the quarter year formerly available to an anonymous caller
        // returns the week: the extra rows exist, and reading them is the cost.
        let quarter = axum::body::to_bytes(ask(2_160).await.into_body(), usize::MAX).await.unwrap();
        assert_eq!(quarter, week, "an anonymous window past a week is clamped to one");
    }

    #[tokio::test]
    async fn changing_the_password_kills_other_sessions_but_not_the_caller() {
        let app = std::sync::Arc::new(app());
        let stale = random_token();
        app.db
            .create_session(&sha256(&stale), Utc::now().timestamp() + 3_600, "198.51.100.7", "test-agent")
            .unwrap();

        let body = Json(json!({"admin_password": "a-long-enough-password"}));
        let response = save_settings(
            Admin,
            axum::extract::State(app.clone()),
            ConnectInfo("198.51.100.7:40000".parse().unwrap()),
            HeaderMap::new(),
            body,
        )
        .await;

        assert!(!app.db.session_valid(&sha256(&stale)), "sessions must not outlive the old password");

        // The caller receives a replacement rather than being logged out by its
        // own password change.
        let cookie = response
            .headers()
            .get(axum::http::header::SET_COOKIE)
            .expect("a replacement session")
            .to_str()
            .unwrap();
        let token = cookie.split(';').next().unwrap().split('=').nth(1).unwrap();
        assert!(app.db.session_valid(&sha256(token)), "the replacement session must work");
    }

    /// The panel hides the delete button on the caller's own row, so the mark is
    /// all that prevents an admin from signing themselves out.
    #[tokio::test]
    async fn the_session_list_marks_the_caller_and_hides_expired_rows() {
        let app = std::sync::Arc::new(app());
        let (mine, theirs, stale) = (random_token(), random_token(), random_token());
        let now = Utc::now().timestamp();
        app.db.create_session(&sha256(&mine), now + 3_600, "198.51.100.7", "test-agent").unwrap();
        app.db.create_session(&sha256(&theirs), now + 7_200, "198.51.100.7", "test-agent").unwrap();
        app.db.create_session(&sha256(&stale), now - 1, "198.51.100.7", "test-agent").unwrap();

        let mut headers = HeaderMap::new();
        headers.insert(header::COOKIE, format!("monitor_session={mine}").parse().unwrap());
        let body = axum::body::to_bytes(
            sessions(Admin, axum::extract::State(app.clone()), headers).await.into_body(),
            usize::MAX,
        )
        .await
        .unwrap();
        let rows: Vec<Value> = serde_json::from_slice(&body).unwrap();

        assert_eq!(rows.len(), 2, "an expired session is not a session");
        assert_eq!(rows[0]["id"], sha256(&theirs), "newest first");
        assert_eq!(rows[0]["current"], false);
        assert_eq!(rows[1]["id"], sha256(&mine));
        assert_eq!(rows[1]["current"], true, "the caller's own row must be marked");
        assert_eq!(rows[1]["created_at"].as_i64().unwrap(), now + 3_600 - 14 * 86_400);

        delete_session(Admin, axum::extract::State(app.clone()), Path(sha256(&theirs))).await;
        assert!(!app.db.session_valid(&sha256(&theirs)), "the deleted device is signed out");
        assert!(app.db.session_valid(&sha256(&mine)), "and nobody else is");
    }

    #[tokio::test]
    async fn a_short_password_is_refused_and_changes_nothing() {
        let app = std::sync::Arc::new(app());
        let live = random_token();
        app.db
            .create_session(&sha256(&live), Utc::now().timestamp() + 3_600, "198.51.100.7", "test-agent")
            .unwrap();

        let body = Json(json!({"admin_password": "short"}));
        let response = save_settings(
            Admin,
            axum::extract::State(app.clone()),
            ConnectInfo("198.51.100.7:40000".parse().unwrap()),
            HeaderMap::new(),
            body,
        )
        .await;

        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
        assert!(app.db.get("admin_password_hash").is_none(), "the password must not have changed");
        assert!(app.db.session_valid(&sha256(&live)), "a rejected change must not log anyone out");
    }

    /// Housekeeping clamps whatever it finds, so an unparsable value is not an
    /// error downstream: it silently means 7 days, in a field still displaying
    /// what was entered.
    #[tokio::test]
    async fn a_retention_window_that_would_never_apply_is_refused() {
        let app = std::sync::Arc::new(app());
        let put = |v: &str| {
            save_settings(
                Admin,
                State(app.clone()),
                ConnectInfo("198.51.100.7:40000".parse().unwrap()),
                HeaderMap::new(),
                Json(json!({"retention_days": v.to_owned()})),
            )
        };
        for junk in ["", "abc", "0", "-1", "9999"] {
            assert_eq!(put(junk).await.status(), StatusCode::BAD_REQUEST, "{junk:?}");
        }
        assert!(app.db.get("retention_days").is_none(), "a refused window must not be stored");
        assert_eq!(put("7").await.status(), StatusCode::OK);
        assert_eq!(app.db.get("retention_days").as_deref(), Some("7"));
    }

    /// What `settings` returns must be what `save_settings` accepts. The panel
    /// echoes the whole form back and the write is all-or-nothing, so one key
    /// returned in a form the write refuses fails the entire page, naming a field
    /// that was never edited.
    #[tokio::test]
    async fn a_fresh_hub_answers_settings_that_it_will_take_back() {
        let app = std::sync::Arc::new(app());
        let Json(read) = settings(Admin, State(app.clone())).await;
        assert_eq!(read["retention_days"], "7", "the default belongs in the answer, not in each caller");

        // Exactly what the panel sends, on a hub where nothing was ever set.
        let echoed = json!({
            "site_name": read["site_name"],
            "retention_days": read["retention_days"],
            "github_proxy": read["github_proxy"],
            "public_page": "on",
            "notify_grace": read["notify_grace"],
            "notify_traffic": read["notify_traffic"],
            "notify_expiry": read["notify_expiry"],
            "notify_login": read["notify_login"],
        });
        assert_eq!(
            save_settings(
                Admin,
                State(app.clone()),
                ConnectInfo("198.51.100.7:40000".parse().unwrap()),
                HeaderMap::new(),
                Json(echoed)
            )
            .await
            .status(),
            StatusCode::OK,
            "a fresh hub's own settings must survive a round trip"
        );
        assert_eq!(app.db.retention_days(), 7, "and the stored window is the one that was shown");
    }

    #[tokio::test]
    async fn settings_never_hand_back_a_secret() {
        let app = app();
        app.db.set("github_client_secret", "super-secret").unwrap();
        app.db.set("github_client_id", "public-id").unwrap();
        // 渠道凭据（二期起）住在 notify_channels 里，任何值都不会进 /api/settings。
        app.db
            .create_notify_channel("Telegram", "telegram", r#"{"token":"123:bot-secret","chat":"42"}"#)
            .unwrap()
            .unwrap();
        app.db
            .create_notify_channel(
                "Webhook",
                "webhook",
                r#"{"url":"https://hooks.example/url-secret","headers":"Authorization: header-secret"}"#,
            )
            .unwrap()
            .unwrap();

        let Json(body) = settings(Admin, axum::extract::State(std::sync::Arc::new(app))).await;
        assert_eq!(body["github_client_id"], "public-id");
        assert_eq!(body["github_secret_set"], true);
        assert!(body.get("github_client_secret").is_none());
        for secret in ["super-secret", "bot-secret", "url-secret", "header-secret"] {
            assert!(!body.to_string().contains(secret), "{secret}");
        }
    }

    /// What every error response is held to: text written for the reader passes
    /// as it is, and nothing else -- a library's error, axum's rejection wording
    /// -- reaches the body.
    #[tokio::test]
    async fn only_written_text_reaches_an_error_response() {
        let read = |r: Response| async move {
            let r = plain_errors(r).await;
            let body = axum::body::to_bytes(r.into_body(), usize::MAX).await.unwrap();
            String::from_utf8(body.to_vec()).unwrap()
        };
        let raw = || std::io::Error::other("/opt/monitor/data/themes/.staging-1: incomplete deflate stream");

        let internal = fail(raw());
        assert_eq!(internal.status(), StatusCode::INTERNAL_SERVER_ERROR);
        assert_eq!(read(internal).await, INTERNAL);

        // The shown message, wherever it sits in the chain, and never its cause.
        let wrapped =
            anyhow::Error::from(raw()).context(crate::Shown("主题包损坏".into())).context("installing");
        let refused = fail(wrapped);
        assert_eq!(refused.status(), StatusCode::BAD_REQUEST);
        assert_eq!(read(refused).await, "主题包损坏");

        let rejection =
            (StatusCode::UNPROCESSABLE_ENTITY, "Failed to deserialize the JSON body").into_response();
        assert_eq!(read(rejection).await, "请求格式不对");
        assert_eq!(read(StatusCode::UNAUTHORIZED.into_response()).await, "登录已失效，请重新登录");
        assert_eq!(read(bad("请填写节点名称")).await, "请填写节点名称");
    }

    /// 批量测速（出口线路语义）：从协议所在服务器向探测目标发 HTTP GET——
    /// 目标可用 kv `exit_probe_url` 覆盖（测试指向本地起的小 HTTP 服务）；
    /// 收到响应即有均值，连不上判不通；停用协议不进结果。
    #[tokio::test]
    async fn bulk_test_probes_exit_line_from_the_nodes_server() {
        let app = app();
        // 本地起一个只答 204 的小 HTTP 服务当探测目标。
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let open_port = listener.local_addr().unwrap().port();
        std::thread::spawn(move || {
            for stream in listener.incoming().flatten() {
                let mut s = stream;
                use std::io::Write;
                let _ = s.write_all(b"HTTP/1.1 204 No Content\r\nContent-Length: 0\r\n\r\n");
            }
        });
        let mk = |name: &str, port: i64, enabled: bool| crate::db::ProxyNode {
            server_id: 1,
            name: name.into(),
            protocol: "socks".into(),
            listen_port: port,
            enabled,
            ..Default::default()
        };
        app.db.create_proxy_node(&mk("开着", 24000, true), &crate::db::ProxySecret::default(), "s1").unwrap();
        app.db
            .create_proxy_node(&mk("停用", 24001, false), &crate::db::ProxySecret::default(), "s3")
            .unwrap();
        let shared: Shared = std::sync::Arc::new(app);
        // 身份归一后探测走节点机 RPC：伪造一台在线 agent，从收到的帧里取
        // rpc id，按 relay.probe 的应答形状回 204 探测样本。
        let (tx, mut rx) = tokio::sync::mpsc::channel::<String>(16);
        shared.agents.write().unwrap().insert(1, crate::agent_ws::Agent::test_stub(tx));
        let responder = shared.clone();
        tokio::spawn(async move {
            while let Some(frame) = rx.recv().await {
                let v: serde_json::Value = serde_json::from_str(&frame).unwrap();
                let id = v["id"].as_str().unwrap().to_owned();
                let reply = if v["method"] == "net.http_probe" {
                    // 忠实一点：真发一次请求，死目标自然回失败。
                    let url = v["params"]["url"].as_str().unwrap_or_default().to_owned();
                    let started = std::time::Instant::now();
                    let outcome = reqwest::Client::builder()
                        .timeout(std::time::Duration::from_secs(3))
                        .redirect(reqwest::redirect::Policy::none())
                        .build()
                        .ok()
                        .map(|c| async move {
                            c.get(&url)
                                .timeout(std::time::Duration::from_secs(3))
                                .send()
                                .await
                                .map(|r| (200..400).contains(&(r.status().as_u16())))
                                .unwrap_or(false)
                        });
                    let ok = match outcome {
                        Some(fut) => fut.await,
                        None => false,
                    };
                    serde_json::json!({ "ok": ok, "ms": started.elapsed().as_millis() as u64 })
                } else {
                    let target = v["params"]["targets"][0].clone();
                    serde_json::json!({ "results": [ { "target": target, "samples": [12] } ] })
                };
                responder.proxy_rpcs.lock().unwrap().remove(&id).unwrap().send(Ok(reply)).unwrap();
            }
        });
        // 目标可达：有均值零丢包。
        shared.db.set("exit_probe_url", &format!("http://127.0.0.1:{open_port}/generate_204")).unwrap();
        let resp = test_proxy_nodes_bulk(Admin, State(shared.clone())).await;
        let v: serde_json::Value =
            serde_json::from_slice(&axum::body::to_bytes(resp.into_body(), 64 * 1024).await.unwrap())
                .unwrap();
        let results = v["results"].as_array().unwrap();
        assert_eq!(results.len(), 1, "停用协议不测");
        assert!(results[0]["avg_ms"].as_f64().is_some(), "204 响应有耗时");
        assert_eq!(results[0]["loss"], 0.0);
        // 目标不可达：无均值、带原因。
        let dead = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let dead_port = dead.local_addr().unwrap().port();
        drop(dead);
        shared.db.set("exit_probe_url", &format!("http://127.0.0.1:{dead_port}/generate_204")).unwrap();
        let resp = test_proxy_nodes_bulk(Admin, State(shared)).await;
        let v: serde_json::Value =
            serde_json::from_slice(&axum::body::to_bytes(resp.into_body(), 64 * 1024).await.unwrap())
                .unwrap();
        let row = &v["results"].as_array().unwrap()[0];
        assert!(row["avg_ms"].is_null(), "连不上无均值");
        assert_eq!(row["loss"], 1.0);
        assert!(row["error"].as_str().is_some_and(|e| !e.is_empty()), "失败带原因");
    }

    /// 方向二核心：客户绑定内容方案后，/api/sub 输出 = 方案渲染 + 该客户自有
    /// 凭据（计量归属不变）；未绑定回落裸节点输出。
    #[tokio::test]
    async fn customer_bound_profile_renders_with_customer_credential() {
        let app = app();
        // 面板节点 + default 凭据 + 客户自有凭据
        let node = crate::db::ProxyNode {
            server_id: 1,
            name: "节点".into(),
            protocol: "vless-reality".into(),
            listen_port: 24000,
            enabled: true,
            ..Default::default()
        };
        let node_id =
            app.db.create_proxy_node(&node, &crate::db::ProxySecret::default(), "default-cred").unwrap();
        let cust_uid = app.db.create_proxy_user(node_id, "客户A", "cust-uuid").unwrap();
        let sub_id = app.db.create_sub_user("客户A", "custok").unwrap();
        app.db.set_proxy_user_sub(cust_uid, Some(sub_id)).unwrap();
        // 内容方案：模板注入 + 勾选这个托管节点（sub_node 记录来源节点）
        let managed = crate::db::SubNode {
            name: "节点".into(),
            raw_link: "vless://default-uuid@1.2.3.4:24000?security=reality&pbk=PBK&sid=SID#节点".into(),
            proxy_node_id: Some(node_id),
            enabled: true,
            ..Default::default()
        };
        app.db.upsert_sub_node(&managed).unwrap();
        let profile_id = app
            .db
            .create_sub_profile(&crate::db::SubProfile {
                name: "方案".into(),
                token: "proftok".into(),
                template_name: "全局代理.yaml".into(),
                selected_nodes: vec![],
                ..Default::default()
            })
            .unwrap();
        // 客户绑定方案
        let mut sub = app.db.sub_user(sub_id).unwrap().unwrap();
        sub.profile_id = Some(profile_id);
        app.db.update_sub_user(sub_id, &sub).unwrap();

        let shared: Shared = std::sync::Arc::new(app);
        let resp = proxy_subscription(
            State(shared.clone()),
            HeaderMap::new(),
            Query(SubQuery { token: Some("custok".into()), t: None }),
        )
        .await;
        let body = axum::body::to_bytes(resp.into_body(), 256 * 1024).await.unwrap();
        let text = String::from_utf8_lossy(&body).into_owned();
        assert!(text.contains("proxy-groups"), "绑定方案后输出完整 Clash 配置");
        assert!(text.contains("cust-uuid"), "节点链接用客户自有凭据");
        assert!(!text.contains("default-uuid"), "不再使用 default 凭据");
        // 未绑定对照：回落裸节点输出（default 凭据的链接列表/原始内容）
        let mut sub2 = sub.clone();
        sub2.profile_id = None;
        shared.db.update_sub_user(sub_id, &sub2).unwrap();
        let resp = proxy_subscription(
            State(shared),
            HeaderMap::new(),
            Query(SubQuery { token: Some("custok".into()), t: None }),
        )
        .await;
        let body = axum::body::to_bytes(resp.into_body(), 256 * 1024).await.unwrap();
        // 未绑定输出 = 分配凭据的链接列表（base64，UA 为空走链接格式）
        let decoded = base64::Engine::decode(&base64::engine::general_purpose::STANDARD, &body).unwrap();
        let text = String::from_utf8(decoded).unwrap();
        assert!(!text.contains("proxy-groups"), "未绑定回落裸节点输出");
        assert!(text.contains("cust-uuid"), "裸节点输出按分配凭据渲染: {text}");
    }

    // ---- 切换主机：链接地址与流量记名口径 ----

    #[test]
    fn link_host_prefers_node_domain_over_machine_ip() {
        let shared = std::sync::Arc::new(app());
        let m = shared.db.create_node(&Node { name: "源机".into(), ..Default::default() }, "t").unwrap();
        // ipv4 是 agent 上报字段，创建不落库，走 save_facts。
        shared.db.save_facts(m, &serde_json::json!({ "ipv4": "198.51.100.9" }), "198.51.100.9", "").unwrap();
        let bundle = |dns: &str| crate::db::NodeBundle {
            node: crate::db::ProxyNode { server_id: m, dns_name: dns.into(), ..Default::default() },
            ..Default::default()
        };
        // 绑了域名 → 域名（换 IP/换主机不换链接）。
        assert_eq!(node_link_host(&shared, &bundle("node1.example.com"), None), "node1.example.com");
        // 未绑 → 机器 IP。
        assert_eq!(node_link_host(&shared, &bundle(""), None), "198.51.100.9");
    }

    #[test]
    fn tag_bundle_matches_mirrors_and_never_cross_machine_blind() {
        let bundle = |server_id: i64, mirrors: &str| crate::db::NodeBundle {
            node: crate::db::ProxyNode {
                server_id,
                listen_port: 21580,
                mirror_servers: mirrors.into(),
                ..Default::default()
            },
            ..Default::default()
        };
        let bundles = vec![bundle(1, "[2]"), bundle(3, "[]")];
        // 原机精确命中。
        assert_eq!(tag_bundle(&bundles, 1, "in-21580").unwrap().node.server_id, 1);
        // 镜像机命中同一节点（切换主机后采样在镜像机名下）。
        assert_eq!(tag_bundle(&bundles, 2, "in-21580").unwrap().node.server_id, 1);
        // 第三台机器同端口：绝不盲匹配（曾有跨机误记坑）。
        assert!(tag_bundle(&bundles, 4, "in-21580").is_none());
        // server_id=0 的同机历史别名兜底保留。
        assert!(tag_bundle(&bundles, 0, "in-21580").is_some());
    }
}
