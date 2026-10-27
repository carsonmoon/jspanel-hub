//! Outbound alerts through channel instances: Telegram, a templated webhook,
//! Bark, Server酱 and SMTP email. Channels live in `notify_channels` (one row
//! per destination, secrets in its config JSON, echoed to the panel only as
//! set-or-not), each event kind routed to a set of channels via
//! `notify_routes` — a kind without a route row goes to every enabled channel.
//! Identical alerts raised within the digest window are merged into one send.
//!
//! Events: a node going offline and returning, a billing period's traffic
//! crossing the threshold and the full allowance, expiry dates approaching or
//! rolled forward, a sign-in to the panel, and a customer losing quota or
//! expiry standing.

use std::collections::{HashMap, HashSet};
use std::net::IpAddr;
use std::sync::OnceLock;
use std::time::Duration;

use anyhow::Result;
use axum::extract::{Path, State};
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use axum::Json;
use chrono::{DateTime, Local, NaiveDate, TimeZone, Timelike, Utc};
use lettre::transport::smtp::client::Tls;
use lettre::transport::smtp::client::TlsParameters;
use lettre::{AsyncSmtpTransport, AsyncTransport, Tokio1Executor};
use reqwest::header::{HeaderMap, HeaderName, HeaderValue, CONTENT_TYPE};
use serde_json::{json, Value};
use tokio::sync::mpsc;
use tracing::{debug, warn};

use crate::api::{answer, bad, fail, invalidate_snapshot, Admin};
use crate::{App, Shared};

/// One alert. `node` lists the node names it concerns, comma-separated, and is
/// empty for a sign-in.
#[derive(Debug, Clone, Default)]
pub struct Note {
    pub event: &'static str,
    pub node: String,
    pub title: String,
    pub message: String,
    /// Unix seconds, stamped when queued: delivery can trail the event by minutes
    /// while a channel is retried.
    pub time: i64,
}

/// Alerts awaiting delivery. A channel that stays down holds each alert for
/// about a minute per channel (`ATTEMPTS` × the 15 s client timeout plus the
/// pauses), so the queue can fill; beyond it alerts are dropped with a warning
/// rather than held in memory without bound.
pub const QUEUE: usize = 64;
const ATTEMPTS: u32 = 3;
const RETRY: Duration = Duration::from_secs(10);

/// Nodes listed in one alert before the rest are only counted. Discord rejects a
/// message over 2000 characters and WeCom one over 2048 bytes, and an outage on
/// the hub's side names every node at once; twenty lines of typical names stay
/// within both.
const LISTED: usize = 20;

/// How often connectivity and traffic are examined. An offline alert therefore
/// trails the grace period by at most this interval.
const SWEEP: Duration = Duration::from_secs(30);

/// A node that returned from an absence longer than the grace period within
/// `FLAP_WINDOW` of going away again is flapping, and that absence is reported
/// only once it lasts `FLAP_GRACE`. Simulated over an hour at the default grace,
/// a node up for one minute and down for four otherwise sends 23 alerts.
const FLAP_WINDOW: i64 = 3_600;
const FLAP_GRACE: i64 = 1_800;

pub const DEFAULT_BODY: &str =
    r#"{"event":"{{event}}","node":"{{node}}","title":"{{title}}","message":"{{message}}"}"#;
pub const DEFAULT_TEXT: &str = "{{title}}\n{{message}}";

/// 渠道类型清单（路由编辑与新增渠道用）：key、展示名。
pub const KINDS: [(&str, &str); 5] = [
    ("telegram", "Telegram"),
    ("webhook", "Webhook"),
    ("bark", "Bark"),
    ("smtp", "邮件 SMTP"),
    ("serverchan", "Server酱"),
];

/// 事件类型清单（路由编辑用）：key、展示名、说明。新增类型默认路由到全部
/// 启用渠道（无路由行即广播），清单更新无需迁移。
pub const EVENTS: [(&str, &str, &str); 10] = [
    ("offline", "节点离线", "掉线超过宽限期"),
    ("online", "节点恢复", "离线后重新上线"),
    ("traffic", "流量提醒", "越过阈值或用尽额度"),
    ("expiry", "到期提醒", "每天 9 点汇总即将到期"),
    ("renew", "自动续期", "到期日被顺延"),
    ("login", "面板登录", "管理员登录提醒"),
    ("sub_alert", "客户生命周期", "配额用尽或到期失格"),
    ("ping_loss", "探测丢包", "丢包率超过阈值"),
    ("ping_latency", "探测延迟异常", "延迟偏离自适应基线"),
    ("route_change", "回程线路变化", "回程探测识别到线路切换"),
];

/// Numeric settings as `(key, min, max, default, the panel's name for it)`.
const NUMBERS: [(&str, i64, i64, i64, &str); 10] = [
    // Minutes a node may stay away before it is reported. Agents reconnect within
    // seconds of a network or hub interruption, which one minute already covers.
    // Capped at FLAP_GRACE: a longer grace would outwait a flapping node too, and
    // the absence clock, kept in memory, restarts with the hub, so every restart
    // during an outage would delay its alert by up to one more grace period.
    // Nodes expected to stay down for hours have their alerts switched off.
    ("notify_grace", 1, FLAP_GRACE / 60, 3, "离线宽限期"),
    // Percent of the allowance that raises the first traffic alert; 0 disables
    // traffic alerts.
    ("notify_traffic", 0, 100, 80, "流量提醒"),
    // Days ahead an expiry is listed; 0 disables both expiry reminders and
    // renewal notices.
    ("notify_expiry", 0, 365, 7, "到期提醒"),
    // Seconds identical alerts are merged within; 0 sends each one as it comes.
    ("notify_digest", 0, 3_600, 0, "汇总推送"),
    // 三期：丢包与延迟异常告警的阈值。窗口以分钟计，系数是百分比。
    ("ping_alert_loss_pct", 1, 100, 20, "丢包告警阈值"),
    ("ping_alert_loss_window_min", 1, 60, 15, "丢包窗口"),
    ("ping_alert_latency_window_min", 5, 360, 60, "延迟基线窗口"),
    ("ping_alert_factor_pct", 100, 500, 150, "延迟偏离系数"),
    ("ping_alert_floor_ms", 0, 1_000, 100, "延迟偏离底线"),
    ("ping_alert_confirm", 1, 10, 2, "连续确认次数"),
];

/// Credentials, reported to the panel only as set or unset. A webhook URL is
/// commonly the credential itself (Discord, Slack, DingTalk, WeCom, Bark).
fn number(app: &App, key: &str) -> i64 {
    let (_, min, max, default, _) =
        NUMBERS.iter().copied().find(|(k, ..)| *k == key).expect("a numeric setting");
    app.db.get(key).and_then(|v| v.parse().ok()).filter(|n| (min..=max).contains(n)).unwrap_or(default)
}

fn setting(app: &App, key: &str) -> Option<String> {
    app.db.get(key).filter(|v| !v.is_empty())
}

/// The notification half of `GET /api/settings`, defaults filled in so that the
/// panel can echo every value back unchanged. Channel credentials live in
/// `notify_channels` now and reach the panel through `/api/notify/config`.
pub fn settings(app: &App, out: &mut serde_json::Map<String, Value>) {
    for (key, ..) in NUMBERS {
        out.insert(key.into(), json!(number(app, key).to_string()));
    }
    let login = if app.db.get("notify_login").as_deref() == Some("off") { "off" } else { "on" };
    out.insert("notify_login".into(), json!(login));
    let ping_enabled = if app.db.get("ping_alert_enabled").as_deref() == Some("off") { "off" } else { "on" };
    out.insert("ping_alert_enabled".into(), json!(ping_enabled));
}

/// Why a notification setting cannot be stored, or `None` when it can. Channel
/// credentials are validated where they are saved (`channel_error`).
pub fn setting_error(key: &str, value: &str) -> Option<String> {
    if let Some((_, min, max, _, label)) = NUMBERS.iter().find(|(k, ..)| *k == key) {
        let fits = value.parse::<i64>().is_ok_and(|n| (*min..=*max).contains(&n));
        return (!fits).then(|| format!("{label}要填 {min} 到 {max} 之间的整数"));
    }
    let problem = match key {
        "notify_login" => (!matches!(value, "on" | "off")).then_some("登录提醒只能是 on 或 off"),
        "ping_alert_enabled" => (!matches!(value, "on" | "off")).then_some("探测告警开关只能是 on 或 off"),
        _ => return Some(format!("没有这个设置项：{key}")),
    };
    problem.map(Into::into)
}

/// Values that exercise every escape the body template must survive.
fn sample() -> Note {
    Note {
        event: "test",
        node: r#"a"b\c"#.into(),
        title: "{{message}}".into(),
        message: "line\nline".into(),
        ..Default::default()
    }
}

/// `Name: value`, one per line. Values are never echoed in an error: they are
/// typically the credential.
fn parse_headers(text: &str) -> Result<Vec<(HeaderName, HeaderValue)>, String> {
    text.lines()
        .map(str::trim)
        .filter(|line| !line.is_empty())
        .map(|line| {
            let (name, value) = line.split_once(':').ok_or("Webhook 请求头每行要写成「名称: 值」")?;
            let name = HeaderName::try_from(name.trim())
                .map_err(|_| format!("Webhook 请求头名称 {:?} 不合法", name.trim()))?;
            let value = HeaderValue::try_from(value.trim())
                .map_err(|_| format!("Webhook 请求头 {name} 的值不合法"))?;
            Ok((name, value))
        })
        .collect()
}

/// Substitutes the placeholders in a single pass, JSON-escaping each value when
/// `json` is set so it is valid inside a string literal. A second pass would also
/// substitute placeholders contained in the inserted values, such as a node name.
fn render(template: &str, note: &Note, site: &str, json: bool) -> String {
    let time = clock(note.time);
    let fields = [
        ("{{event}}", note.event),
        ("{{node}}", note.node.as_str()),
        ("{{title}}", note.title.as_str()),
        ("{{message}}", note.message.as_str()),
        ("{{site}}", site),
        ("{{time}}", time.as_str()),
    ];
    let mut out = String::with_capacity(template.len());
    let mut rest = template;
    while let Some(at) = rest.find("{{") {
        out.push_str(&rest[..at]);
        rest = &rest[at..];
        match fields.iter().find(|(key, _)| rest.starts_with(key)) {
            Some((key, value)) => {
                if json {
                    let quoted = Value::from(*value).to_string();
                    out.push_str(&quoted[1..quoted.len() - 1]);
                } else {
                    out.push_str(value);
                }
                rest = &rest[key.len()..];
            }
            None => {
                out.push_str("{{");
                rest = &rest[2..];
            }
        }
    }
    out.push_str(rest);
    out
}

enum Channel {
    Telegram { token: String, chat: String, text: String },
    Webhook { url: String, headers: String, body: String },
    Bark { server: String, key: String, group: String },
    ServerChan { key: String },
    Smtp { host: String, port: u16, username: String, password: String, from: String, to: String },
}

/// 解析一个渠道实例的 config JSON。解析失败的行在投递时跳过（日志告警），
/// 不拖垮其余渠道。
fn parse_channel(kind: &str, cfg: &Value) -> Option<Channel> {
    let s = |field: &str| cfg.get(field).and_then(Value::as_str).unwrap_or_default().to_string();
    match kind {
        "telegram" if !s("token").is_empty() && !s("chat").is_empty() => Some(Channel::Telegram {
            token: s("token"),
            chat: s("chat"),
            text: if s("text").is_empty() { DEFAULT_TEXT.into() } else { s("text") },
        }),
        "webhook" if !s("url").is_empty() => Some(Channel::Webhook {
            url: s("url"),
            headers: s("headers"),
            body: if s("body").is_empty() { DEFAULT_BODY.into() } else { s("body") },
        }),
        "bark" if !s("key").is_empty() => Some(Channel::Bark {
            server: if s("server").is_empty() { "https://api.day.app".into() } else { s("server") },
            key: s("key"),
            group: s("group"),
        }),
        "serverchan" if !s("key").is_empty() => Some(Channel::ServerChan { key: s("key") }),
        "smtp" if !s("host").is_empty() => Some(Channel::Smtp {
            host: s("host"),
            port: s("port").parse().ok().unwrap_or(587),
            username: s("username"),
            password: s("password"),
            from: s("from"),
            to: s("to"),
        }),
        _ => None,
    }
}

/// 从库里读出全部启用的渠道：`(id, 实例名, 解析后的适配器)`。
fn channels(app: &App) -> Vec<(i64, String, Channel)> {
    let mut out = Vec::new();
    let Ok(rows) = app.db.notify_channels() else { return out };
    for row in rows.into_iter().filter(|c| c.enabled) {
        let Ok(cfg) = serde_json::from_str::<Value>(&row.config) else {
            warn!("notify channel {} ({}) has unreadable config; skipped", row.name, row.kind);
            continue;
        };
        match parse_channel(&row.kind, &cfg) {
            Some(ch) => out.push((row.id, row.name, ch)),
            None => warn!("notify channel {} ({}) is missing required fields; skipped", row.name, row.kind),
        }
    }
    out
}

/// 事件的投递目标：路由行存在用路由（渠道可能已被删，解析时剔除），没有行
/// 广播给全部启用渠道。
fn routed(app: &App, event: &str) -> Vec<(i64, String, Channel)> {
    let all = channels(app);
    let ids = app
        .db
        .notify_routes()
        .ok()
        .and_then(|rows| rows.into_iter().find(|(e, _)| e == event).map(|(_, ids)| ids));
    match ids {
        Some(ids) => all.into_iter().filter(|(id, ..)| ids.contains(id)).collect(),
        None => all,
    }
}

/// 一类渠道里属于凭据、列表只回「配了与否」的字段。
fn secrets_of(kind: &str) -> &'static [&'static str] {
    match kind {
        "telegram" => &["token"],
        "webhook" => &["url", "headers"],
        "bark" | "serverchan" => &["key"],
        "smtp" => &["password"],
        _ => &[],
    }
}

/// 编辑保存时合并凭据：新值留空的凭据字段沿用旧值（面板把旧值显示为占位
/// 点，不回显原文），其余字段以新值为准。
fn merge_secrets(kind: &str, mut new: Value, old: &Value) -> Value {
    let Some(obj) = new.as_object_mut() else { return new };
    for field in secrets_of(kind) {
        let blank = obj.get(*field).and_then(Value::as_str).is_none_or(str::is_empty);
        let had = old.get(*field).and_then(Value::as_str).is_some_and(|v| !v.is_empty());
        if blank && had {
            obj.insert((*field).into(), old[*field].clone());
        }
    }
    new
}

/// 为什么这份渠道配置存不进去。新建时全部字段必检；编辑时凭据字段允许留空
/// （= 沿用旧值，见 `merge_secrets`），其余照检。
fn channel_error(kind: &str, cfg: &Value, editing: bool) -> Option<String> {
    let s = |field: &str| cfg.get(field).and_then(Value::as_str).unwrap_or_default().trim();
    let only = |s: &str, extra: &[u8]| {
        !s.is_empty() && s.bytes().all(|b| b.is_ascii_alphanumeric() || extra.contains(&b))
    };
    let digits = |s: &str| !s.is_empty() && s.bytes().all(|b| b.is_ascii_digit());
    let http_url = |s: &str| reqwest::Url::parse(s).is_ok_and(|u| matches!(u.scheme(), "http" | "https"));
    // 留空且是编辑（旧值沿用）的字段跳过格式检查。
    let ok = |field: &str, check: &dyn Fn(&str) -> bool| -> bool {
        let v = s(field);
        if v.is_empty() && editing && secrets_of(kind).contains(&field) {
            return true;
        }
        check(v)
    };
    match kind {
        "telegram" => {
            if !ok("token", &|v| {
                v.split_once(':').is_some_and(|(id, secret)| digits(id) && only(secret, b"_-"))
            }) {
                return Some("Telegram Bot Token 的格式应为 123456:ABC-DEF".into());
            }
            if !ok("chat", &|v| match v.strip_prefix('@') {
                Some(name) => only(name, b"_"),
                None => digits(v.strip_prefix('-').unwrap_or(v)),
            }) {
                return Some("Telegram Chat ID 要填数字 ID 或 @用户名".into());
            }
        }
        "webhook" => {
            // Plain http is accepted: a relay on the hub's own host or network is
            // a common target, and only an admin can set this.
            if !ok("url", &http_url) {
                return Some("Webhook URL 必须以 http:// 或 https:// 开头".into());
            }
            if !s("headers").is_empty() {
                if let Err(reason) = parse_headers(s("headers")) {
                    return Some(reason);
                }
            }
            if !s("body").is_empty()
                && serde_json::from_str::<Value>(&render(s("body"), &sample(), r#"s"i\te"#, true)).is_err()
            {
                return Some("Webhook 请求体填入内容后必须是合法的 JSON，占位符要放在引号里".into());
            }
        }
        "bark" => {
            if !ok("key", &|v| only(v, b"")) {
                return Some("Bark 的 Key 只能是 App 里显示的那串字母数字".into());
            }
            if !s("server").is_empty() && !http_url(s("server")) {
                return Some("自建 Bark 服务器地址要以 http:// 或 https:// 开头".into());
            }
        }
        "serverchan" => {
            if !ok("key", &|v| only(v, b"")) {
                return Some("Server酱的 SendKey 不能为空".into());
            }
        }
        "smtp" => {
            if s("host").is_empty() {
                return Some("SMTP 服务器地址不能为空".into());
            }
            if !s("port").is_empty() && !s("port").parse::<u16>().is_ok_and(|p| p > 0) {
                return Some("SMTP 端口要填 1 到 65535 之间的整数".into());
            }
            for field in ["from", "to"] {
                if !s(field).contains('@') {
                    return Some(
                        match field {
                            "from" => "发件地址要是一个邮箱（含 @）",
                            _ => "收件地址要是一个邮箱（含 @）",
                        }
                        .into(),
                    );
                }
            }
        }
        other => return Some(format!("没有这个渠道类型：{other}")),
    }
    None
}

/// Why a delivery failed, and whether another attempt could change that. A
/// refused credential or a malformed request fails identically every time, and
/// retrying it would hold the queue for 20 s per alert.
///
/// `reason` is the far end's own answer, for the log; `shown` is what the panel
/// says, composed here from the status rather than quoted from the answer.
struct Failure {
    retry: bool,
    reason: String,
    shown: String,
}

/// The client alerts are sent with, separate from `App::http` because it must not
/// follow redirects. reqwest resends a POST answered with 301 or 302 as a GET
/// without its body, which the far end typically accepts: the panel would report
/// success while nothing arrives. A redirect to another host also withholds only
/// `Authorization` and cookies, so a credential header such as `X-Gotify-Key`
/// would follow it. Built on first use, so a hub without channels never
/// allocates it.
fn client() -> &'static reqwest::Client {
    static CLIENT: OnceLock<reqwest::Client> = OnceLock::new();
    CLIENT.get_or_init(|| {
        reqwest::Client::builder()
            .timeout(Duration::from_secs(15))
            .redirect(reqwest::redirect::Policy::none())
            .build()
            .expect("http client")
    })
}

async fn post(app: &App, channel: &Channel, note: &Note) -> Result<(), Failure> {
    let site = site_name(app);
    // SMTP 走 lettre 的独立协议栈，不走 reqwest 的请求构造。
    if let Channel::Smtp { host, port, username, password, from, to } = channel {
        return smtp_send(host, *port, username, password, from, to, note, &site).await;
    }
    let request = match channel {
        // Plain text: under a parse mode Telegram rejects a message whose node
        // name happens to contain markup.
        Channel::Telegram { token, chat, text } => client()
            .post(format!("https://api.telegram.org/bot{token}/sendMessage"))
            .json(&json!({"chat_id": chat, "text": render(text, note, &site, false)})),
        Channel::Webhook { url, headers, body } => {
            // `insert` into one map: `RequestBuilder::header` and `HeaderMap::extend`
            // both append, which would send a configured Content-Type alongside the
            // default instead of in its place.
            let mut map = HeaderMap::new();
            map.insert(CONTENT_TYPE, HeaderValue::from_static("application/json"));
            let headers = parse_headers(headers).map_err(|reason| Failure {
                retry: false,
                shown: reason.clone(),
                reason,
            })?;
            for (name, value) in headers {
                map.insert(name, value);
            }
            client().post(url).headers(map).body(render(body, note, &site, true))
        }
        // Bark 的 title/body 有长度上限，与面板同款约定：标题短、正文长。
        Channel::Bark { server, key, group } => {
            let payload = json!({
                "title": render("{{title}}", note, &site, false),
                "body": render("{{message}}", note, &site, false),
                "group": if group.is_empty() { "monitor".into() } else { group.clone() },
            });
            client().post(format!("{server}/{key}")).json(&payload)
        }
        // Server酱的标题上限 32 字符左右：超长标题截断，正文（desp）放全量。
        Channel::ServerChan { key } => {
            let title = render("{{title}}", note, &site, false);
            client().post(format!("https://sctapi.ftqq.com/{key}.send")).form(&[
                ("title", title.chars().take(48).collect::<String>()),
                ("desp", render("{{message}}", note, &site, false)),
            ])
        }
        Channel::Smtp { .. } => unreachable!("handled above"),
    };
    // The URL is stripped from the error: Telegram's carries the bot token and a
    // webhook's is often the credential, and the error reaches both the journal
    // and the panel.
    let mut response = request.send().await.map_err(|e| Failure {
        retry: true,
        shown: if e.is_timeout() { "请求超时" } else { "连不上对方服务器" }.into(),
        reason: format!("{:#}", anyhow::Error::from(e.without_url())),
    })?;
    let status = response.status();
    if status.is_success() {
        return Ok(());
    }
    // The first chunk carries the reason (Telegram's `description`, Discord's
    // `message`) without reading an error page of arbitrary length.
    let head = response.chunk().await.ok().flatten().unwrap_or_default();
    let code = status.as_u16();
    let why = match (channel, code) {
        (_, 300..=399) => "地址发生了跳转，请填写跳转后的地址",
        (Channel::Telegram { .. }, 401 | 404) => "Bot Token 不对",
        (Channel::Telegram { .. }, 400) => "Chat ID 不对，或者 bot 还没有加入这个会话",
        (Channel::Telegram { .. }, 403) => "bot 被这个会话移除或屏蔽了",
        (_, 401 | 403) => "对方拒绝了鉴权，检查 URL 或请求头里的凭据",
        (_, 404) => "地址不存在，检查 URL",
        (_, 429) => "发送太频繁，被对方限流",
        (_, 500..) => "对方服务器出错",
        _ => "对方拒收了这条消息，检查请求体格式",
    };
    Err(Failure {
        retry: status.is_server_error() || status == StatusCode::TOO_MANY_REQUESTS,
        shown: format!("{why}（HTTP {code}）"),
        reason: format!(
            "{status}: {}",
            String::from_utf8_lossy(&head).chars().take(300).collect::<String>().trim()
        ),
    })
}

/// Queues an alert without waiting, so that sign-in and housekeeping never
/// stall behind a slow channel.
pub fn send(app: &App, mut note: Note) {
    note.time = Utc::now().timestamp();
    if let Err(mpsc::error::TrySendError::Full(note)) = app.notes.try_send(note) {
        warn!("notification queue is full; dropped {:?}", note.title);
    }
}

/// SMTP delivery: implicit TLS on 465, STARTTLS for any other port (`relay`
/// refuses a server that does not offer TLS), authenticated when a username is
/// configured. The subject carries the title, the body the message.
#[allow(clippy::too_many_arguments)]
async fn smtp_send(
    host: &str,
    port: u16,
    username: &str,
    password: &str,
    from: &str,
    to: &str,
    note: &Note,
    site: &str,
) -> Result<(), Failure> {
    let bad_field = |what: &str, e: lettre::address::AddressError| Failure {
        retry: false,
        shown: format!("{what}不是合法的邮箱地址"),
        reason: e.to_string(),
    };
    let email = lettre::Message::builder()
        .from(from.parse().map_err(|e: lettre::address::AddressError| bad_field("发件地址", e))?)
        .to(to.parse().map_err(|e: lettre::address::AddressError| bad_field("收件地址", e))?)
        .subject(render("{{title}}", note, site, false))
        .body(render("{{message}}", note, site, false))
        .map_err(|e| Failure {
            retry: false, shown: "邮件内容构造失败".into(), reason: e.to_string()
        })?;
    let builder = match port {
        465 => {
            let tls = TlsParameters::new(host.to_string()).map_err(|e| Failure {
                retry: false,
                shown: "TLS 初始化失败".into(),
                reason: e.to_string(),
            })?;
            AsyncSmtpTransport::<Tokio1Executor>::builder_dangerous(host).port(port).tls(Tls::Wrapper(tls))
        }
        _ => AsyncSmtpTransport::<Tokio1Executor>::relay(host)
            .map_err(|e| Failure {
                retry: false,
                shown: "SMTP 服务器不支持 STARTTLS 加密，或地址不对".into(),
                reason: e.to_string(),
            })?
            .port(port),
    };
    let mailer = if username.is_empty() {
        builder
    } else {
        builder.credentials(lettre::transport::smtp::authentication::Credentials::new(
            username.to_string(),
            password.to_string(),
        ))
    };
    match mailer.build().send(email).await {
        Ok(_) => Ok(()),
        Err(e) => Err(Failure { retry: true, shown: format!("SMTP 错误：{e}"), reason: format!("{e:#}") }),
    }
}

/// 汇总缓冲：`(渠道 id, 内容键) → (首条, 合并条数, 冲洗时刻)`。内容键 = 事件、
/// 标题、正文三者拼接：窗口内同渠道的相同内容合成一条，首条的 time（事件时刻）
/// 保留，冲掉的是重复条目而非首条。
type Digest = HashMap<(i64, String), (Note, u32, i64)>;

fn digest_key(note: &Note) -> String {
    format!("{}\u{1}{}\u{1}{}", note.event, note.title, note.message)
}

/// Pure part of the merge, unit-testable: absorb one alert into the buffer.
fn digest_absorb(buffer: &mut Digest, cid: i64, note: &Note, window: i64, now: i64) {
    let entry = buffer.entry((cid, digest_key(note))).or_insert_with(|| (note.clone(), 0, now + window));
    entry.1 += 1;
}

/// Pure part of the flush: entries whose window has elapsed leave the buffer.
fn digest_due(buffer: &mut Digest, now: i64) -> Vec<(i64, Note, u32)> {
    let due: Vec<(i64, String)> =
        buffer.iter().filter(|(_, (_, _, at))| *at <= now).map(|(k, _)| k.clone()).collect();
    due.into_iter()
        .filter_map(|k| buffer.remove(&k.clone()).map(|(note, count, _)| (k.0, note, count)))
        .collect()
}

/// One channel, retried. Channels are re-read per delivery, so a panel edit
/// applies to the next alert.
async fn deliver_one(app: &App, cid: i64, note: &Note) {
    let Some((_, name, channel)) = channels(app).into_iter().find(|(id, ..)| *id == cid) else {
        return;
    };
    for attempt in 1..=ATTEMPTS {
        match post(app, &channel, note).await {
            Ok(()) => break,
            Err(f) if !f.retry || attempt == ATTEMPTS => {
                warn!("{} alert {:?} not delivered: {}", name, note.title, f.reason);
                break;
            }
            Err(f) => {
                debug!("{} alert {:?}, attempt {attempt}: {}", name, note.title, f.reason);
                tokio::time::sleep(RETRY).await;
            }
        }
    }
}

/// Delivers queued alerts to each event's routed channels, each channel retried
/// independently. Identical alerts (same event, title and message) raised
/// within the digest window on a channel are merged into one send whose count
/// is appended to the message; a window of zero sends each as it comes.
///
/// At most once: an alert that exhausts its attempts is dropped, and the state
/// that produced it (`down_since`, the traffic step, the digest date) already
/// records it as sent, so it is not raised again.
pub async fn deliver(app: Shared, mut inbox: mpsc::Receiver<Note>) {
    let mut buffer: Digest = HashMap::new();
    let mut ticker = tokio::time::interval(Duration::from_secs(1));
    ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    loop {
        tokio::select! {
            _ = ticker.tick() => {}
            maybe = inbox.recv() => {
                match maybe {
                    Some(note) => {
                        let window = number(&app, "notify_digest");
                        let now = Utc::now().timestamp();
                        for (cid, _, _) in routed(&app, note.event) {
                            if window > 0 {
                                digest_absorb(&mut buffer, cid, &note, window, now);
                            } else {
                                deliver_one(&app, cid, &note).await;
                            }
                        }
                    }
                    None => break,
                }
            }
        }
        let now = Utc::now().timestamp();
        for (cid, mut note, count) in digest_due(&mut buffer, now) {
            if count > 1 {
                note.message =
                    format!("{}\n（汇总窗口内另有 {} 条相同告警，已合并为一条）", note.message, count - 1);
            }
            deliver_one(&app, cid, &note).await;
        }
    }
}

fn sample_note() -> Note {
    Note {
        event: "test",
        title: "✅ 测试通知".into(),
        message: "收到这条说明通知渠道可用".into(),
        time: Utc::now().timestamp(),
        ..Default::default()
    }
}

/// `POST /api/notify/test`: one alert through every configured channel, past the
/// queue and its retries, so each channel's own error reaches the panel.
pub async fn test(_: Admin, State(app): State<Shared>) -> Response {
    let channels = channels(&app);
    if channels.is_empty() {
        return answer(StatusCode::BAD_REQUEST, "还没有配置通知渠道");
    }
    let note = sample_note();
    let mut failed = Vec::new();
    let mut sent = Vec::new();
    for (_id, name, channel) in &channels {
        if let Err(f) = post(&app, channel, &note).await {
            warn!("{} test alert not delivered: {}", name, f.reason);
            failed.push(format!("{}：{}", name, f.shown));
        } else {
            sent.push(name.clone());
        }
    }
    if failed.is_empty() {
        Json(json!({"sent": sent})).into_response()
    } else {
        answer(StatusCode::BAD_GATEWAY, failed.join("；"))
    }
}

/// `POST /api/notify/channels/{id}/test`: the same alert through one channel.
pub async fn channel_test(_: Admin, State(app): State<Shared>, Path(id): Path<i64>) -> Response {
    let Some((_, name, channel)) = channels(&app).into_iter().find(|(cid, ..)| *cid == id) else {
        return answer(StatusCode::NOT_FOUND, "渠道不存在、未启用或配置不完整");
    };
    match post(&app, &channel, &sample_note()).await {
        Ok(()) => Json(json!({"sent": name})).into_response(),
        Err(f) => {
            warn!("{} test alert not delivered: {}", name, f.reason);
            answer(StatusCode::BAD_GATEWAY, &f.shown)
        }
    }
}

/// `GET /api/notify/config`: everything the notification settings page renders
/// in one response — channels with masked secrets, the kind and event lists,
/// the routing table and the digest window.
pub async fn config(_: Admin, State(app): State<Shared>) -> Response {
    let channels: Vec<Value> = app
        .db
        .notify_channels()
        .unwrap_or_default()
        .into_iter()
        .map(|c| {
            let cfg: Value = serde_json::from_str(&c.config).unwrap_or_default();
            let mut masked = serde_json::Map::new();
            let mut sets = serde_json::Map::new();
            if let Some(obj) = cfg.as_object() {
                for (k, v) in obj {
                    if secrets_of(&c.kind).contains(&k.as_str()) {
                        let present = v.as_str().is_some_and(|s| !s.is_empty());
                        sets.insert(k.clone(), json!(present));
                        masked.insert(k.clone(), json!(""));
                    } else {
                        masked.insert(k.clone(), v.clone());
                    }
                }
            }
            json!({
                "id": c.id, "name": c.name, "kind": c.kind, "enabled": c.enabled,
                "config": masked, "sets": sets,
            })
        })
        .collect();
    let mut route_map = serde_json::Map::new();
    for (event, ids) in app.db.notify_routes().unwrap_or_default() {
        route_map.insert(event, json!(ids));
    }
    let routes: Value = route_map.into();
    Json(json!({
        "channels": channels,
        "kinds": KINDS.iter().map(|(k, l)| json!({"key": k, "label": l})).collect::<Vec<_>>(),
        "events": EVENTS.iter().map(|(k, l, d)| json!({"key": k, "label": l, "desc": d})).collect::<Vec<_>>(),
        "routes": routes,
        "digest": number(&app, "notify_digest"),
    }))
    .into_response()
}

/// `POST /api/notify/channels`: create one. The name is the route editor's
/// label and must be unique; the config is validated per kind before it lands.
pub async fn channel_create(
    _: Admin,
    State(app): State<Shared>,
    body: Result<Json<Value>, axum::extract::rejection::JsonRejection>,
) -> Response {
    let Json(body) = match body {
        Ok(b) => b,
        Err(_) => return bad("请求格式不对"),
    };
    let name = body["name"].as_str().unwrap_or_default().trim();
    if name.is_empty() {
        return bad("渠道名称不能为空");
    }
    let Some(kind) = body["kind"].as_str() else { return bad("缺少渠道类型") };
    if !KINDS.iter().any(|(k, _)| *k == kind) {
        return bad("没有这个渠道类型");
    }
    let cfg = body["config"].clone();
    if let Some(problem) = channel_error(kind, &cfg, false) {
        return bad(&problem);
    }
    match app.db.create_notify_channel(name, kind, &cfg.to_string()) {
        Ok(Some(id)) => {
            invalidate_snapshot(&app);
            Json(json!({"ok": true, "id": id})).into_response()
        }
        Ok(None) => bad("已有同名的渠道，换一个名字"),
        Err(e) => fail(e),
    }
}

/// `PUT /api/notify/channels/{id}`: rename, edit config (blank credential
/// fields keep the stored value) and toggle.
pub async fn channel_update(
    _: Admin,
    State(app): State<Shared>,
    Path(id): Path<i64>,
    body: Result<Json<Value>, axum::extract::rejection::JsonRejection>,
) -> Response {
    let Json(body) = match body {
        Ok(b) => b,
        Err(_) => return bad("请求格式不对"),
    };
    let Some(row) = app.db.notify_channel(id).ok().flatten() else {
        return answer(StatusCode::NOT_FOUND, "渠道不存在");
    };
    let name = body["name"].as_str().unwrap_or(&row.name).trim();
    if name.is_empty() {
        return bad("渠道名称不能为空");
    }
    // 请求不带 config（如只切启停）= 配置原样保留；带了则空凭据沿用旧值。
    let cfg = match body.get("config") {
        None | Some(Value::Null) => serde_json::from_str::<Value>(&row.config).unwrap_or_default(),
        Some(new) => {
            let merged =
                merge_secrets(&row.kind, new.clone(), &serde_json::from_str(&row.config).unwrap_or_default());
            if let Some(problem) = channel_error(&row.kind, &merged, true) {
                return bad(&problem);
            }
            merged
        }
    };
    let enabled = body["enabled"].as_bool().unwrap_or(row.enabled);
    match app.db.update_notify_channel(id, name, &cfg.to_string(), enabled) {
        Ok(true) => {
            invalidate_snapshot(&app);
            Json(json!({"ok": true})).into_response()
        }
        Ok(false) => answer(StatusCode::NOT_FOUND, "渠道不存在"),
        Err(e) => fail(e),
    }
}

/// `DELETE /api/notify/channels/{id}`: drops the channel and prunes it from
/// every route.
pub async fn channel_delete(_: Admin, State(app): State<Shared>, Path(id): Path<i64>) -> Response {
    match app.db.delete_notify_channel(id) {
        Ok(()) => {
            invalidate_snapshot(&app);
            Json(json!({"ok": true})).into_response()
        }
        Err(e) => fail(e),
    }
}

/// `PUT /api/notify/routes`: the routing table, `{event: [channel ids]}`. A
/// kind left out of the body keeps its table; kinds in the body are stored
/// even when empty (explicit silence), unknown events are refused.
pub async fn routes_put(
    _: Admin,
    State(app): State<Shared>,
    body: Result<Json<Value>, axum::extract::rejection::JsonRejection>,
) -> Response {
    let Json(body) = match body {
        Ok(b) => b,
        Err(_) => return bad("请求格式不对"),
    };
    let Some(routes) = body["routes"].as_object() else { return bad("请求缺少 routes") };
    for (event, ids) in routes {
        if !EVENTS.iter().any(|(k, ..)| *k == event) {
            return bad(&format!("没有这个事件类型：{event}"));
        }
        let Some(ids) = ids.as_array() else { return bad("路由要填渠道 id 数组") };
        let known: Vec<i64> = ids.iter().filter_map(Value::as_i64).collect();
        let stored: Vec<i64> = app.db.notify_channels().unwrap_or_default().iter().map(|c| c.id).collect();
        if known.iter().any(|id| !stored.contains(id)) {
            return bad("路由里有不存在的渠道");
        }
        if let Err(e) = app.db.set_notify_route(event, &known) {
            return fail(e);
        }
    }
    Json(json!({"ok": true})).into_response()
}

/// `PUT /api/notify/digest`: the merge window in seconds, 0 = off.
pub async fn digest_put(
    _: Admin,
    State(app): State<Shared>,
    body: Result<Json<Value>, axum::extract::rejection::JsonRejection>,
) -> Response {
    let Json(body) = match body {
        Ok(b) => b,
        Err(_) => return bad("请求格式不对"),
    };
    let Some(seconds) = body["seconds"].as_i64() else { return bad("要填秒数") };
    if let Some(problem) = setting_error("notify_digest", &seconds.to_string()) {
        return bad(&problem);
    }
    match app.db.set("notify_digest", &seconds.to_string()) {
        Ok(()) => Json(json!({"ok": true})).into_response(),
        Err(e) => fail(e),
    }
}

pub fn signed_in(app: &App, how: &str, ip: IpAddr) {
    if app.db.get("notify_login").as_deref() != Some("off") {
        let message = format!("{how} · 来自 {ip}");
        send(app, Note { event: "login", title: "🔑 面板登录".into(), message, ..Default::default() });
    }
}

/// Expiry dates that housekeeping rolled forward, as `(name, "old → new")`.
pub fn renewed(app: &App, items: Vec<(&str, String)>) {
    if number(app, "notify_expiry") > 0 {
        if let Some(note) = batch("renew", "🔁", "已自动续期", items) {
            send(app, note);
        }
    }
}

/// M7：客户生命周期通知。同一客户同一次失格只发一次——kind 携带事件坐标
/// （到期用日期，超额用当期起点），已发过的记在 setting 里，重启不重发；
/// 客户恢复后再次失格是新坐标，照常再发。
pub fn sub_down(app: &App, sub: &crate::db::SubUser, kind: &str, why: &str) {
    let key = format!("notified_sub:{}:{kind}", sub.id);
    if app.db.get(&key).is_some() {
        return;
    }
    if let Err(e) = app.db.set(&key, "1") {
        warn!("could not record sub notification: {e:#}");
        return;
    }
    send(
        app,
        Note {
            event: "sub_alert",
            title: format!("🚫 客户{}：{}", sub.name, why),
            message: format!("客户「{}」{why}，其凭据已从节点配置摘除；恢复后自动生效。", sub.name),
            ..Default::default()
        },
    );
}

/// 记账边沿：这批客户刚刚越过自身配额，即时告知并让调用方摘除。
pub fn sub_over_quota(app: &App, ids: &[i64]) {
    for id in ids {
        if let Ok(Some(sub)) = app.db.sub_user(*id) {
            sub_down(app, &sub, &format!("quota:{}", sub.quota_period_start), "流量配额已用尽");
        }
    }
}

/// Once a day from 09:00 hub time, the nodes expiring within the configured
/// window. The date is stored once sent, so a restart does not repeat it, and
/// not while no channel is configured, so one configured later that day still
/// receives the digest.
pub fn expiry_digest(app: &App, now: DateTime<Local>) -> Result<Option<Note>> {
    let days = number(app, "notify_expiry");
    let today = now.date_naive();
    if days == 0
        || now.hour() < 9
        || app.db.get("notify_expiry_sent") == Some(today.to_string())
        || channels(app).is_empty()
    {
        return Ok(None);
    }
    let mut soon: Vec<(NaiveDate, String)> = app
        .db
        .nodes()?
        .into_iter()
        .filter_map(|n| {
            let date = n.expires_at.as_deref()?.parse::<NaiveDate>().ok()?;
            (0..=days).contains(&(date - today).num_days()).then_some((date, n.name))
        })
        .collect();
    soon.sort();
    app.db.set("notify_expiry_sent", &today.to_string())?;
    let items = soon
        .iter()
        .map(|(date, name)| {
            let left = match (*date - today).num_days() {
                0 => "今天到期".into(),
                d => format!("还剩 {d} 天"),
            };
            (name.as_str(), format!("{date} {left}"))
        })
        .collect();
    Ok(batch("expiry", "⏳", "即将到期", items))
}

/// One alert for any number of nodes: a list in the message, the names in
/// `node`. `None` when there is nothing to say.
fn batch(event: &'static str, mark: &str, what: &str, items: Vec<(&str, String)>) -> Option<Note> {
    let (title, message) = match items.as_slice() {
        [] => return None,
        [(name, detail)] => (format!("{mark} {name} {what}"), detail.clone()),
        _ => {
            let mut lines: Vec<String> =
                items.iter().take(LISTED).map(|(name, detail)| format!("{name} · {detail}")).collect();
            if items.len() > LISTED {
                lines.push(format!("……另外 {} 台", items.len() - LISTED));
            }
            (format!("{mark} {} 台节点{what}", items.len()), lines.join("\n"))
        }
    };
    let node = items.iter().map(|(name, _)| *name).collect::<Vec<_>>().join(", ");
    Some(Note { event, node, title, message, ..Default::default() })
}

/// Sweep state that need not outlive the process.
#[derive(Default)]
pub struct Watch {
    /// Set after the first sweep, which records the traffic steps already reached
    /// without announcing them again after a restart.
    primed: bool,
    /// Per node, the billing period and the traffic step last announced in it.
    traffic: HashMap<i64, (String, i64)>,
    /// Per absent node, when a sweep first found it absent. Absence is measured
    /// from here rather than from `last_seen`, which an agent reporting every few
    /// minutes leaves minutes old: measured from that, a restart of such an agent
    /// caught by a single sweep would already be past the grace period. After a
    /// hub restart the first sweep finds every node absent, which also gives each
    /// agent the whole grace period to reconnect.
    absent: HashMap<i64, i64>,
    /// Per node, when it last returned from an absence longer than the grace
    /// period. Absences shorter than that, such as an agent restart, do not count.
    returned: HashMap<i64, i64>,
}

pub async fn watch(app: Shared) {
    let mut watch = Watch::default();
    let mut ticker = tokio::time::interval(SWEEP);
    loop {
        ticker.tick().await;
        // Synchronous database work, kept off the runtime threads like a report.
        match tokio::task::block_in_place(|| sweep(&app, &mut watch, Utc::now().timestamp())) {
            Ok(notes) => notes.into_iter().for_each(|note| send(&app, note)),
            Err(e) => warn!("notification sweep failed: {e:#}"),
        }
    }
}

/// One pass over every node. Nodes going offline, nodes returning and traffic
/// crossings are each gathered into one alert per pass. An outage on the hub's
/// side, which drops every agent within about 30 s, therefore produces one or
/// two alerts rather than one per node (two for 40 nodes in simulation), and the
/// rate stays below the 20 messages a minute that Telegram groups, DingTalk and
/// WeCom accept.
///
/// A return is announced only after an offline alert, whether or not the node
/// still has alerts enabled: brief disconnections within the grace period stay
/// silent in both directions. Nothing is recorded as announced while no channel
/// is configured, so configuring one afterwards still reports nodes already down
/// and traffic already past a step.
fn sweep(app: &App, watch: &mut Watch, now: i64) -> Result<Vec<Note>> {
    let online: HashSet<i64> = app.agents.read().unwrap_or_else(|e| e.into_inner()).keys().copied().collect();
    let nodes = app.db.nodes()?;
    // Node ids are rowids, which SQLite hands to the next node created once the
    // newest is deleted; state kept under a deleted id would pass that node's
    // absence, return and traffic step to the new one.
    // ponytail: a delete and a create within one SWEEP still inherit; key by
    // creation time if that ever matters.
    let ids: HashSet<i64> = nodes.iter().map(|n| n.id).collect();
    watch.absent.retain(|id, _| ids.contains(id));
    watch.returned.retain(|id, _| ids.contains(id));
    watch.traffic.retain(|id, _| ids.contains(id));
    let grace = number(app, "notify_grace") * 60;
    let armed = !channels(app).is_empty();
    let (mut down, mut up) = (Vec::new(), Vec::new());
    for node in &nodes {
        if online.contains(&node.id) {
            if watch.absent.remove(&node.id).is_some_and(|since| now - since >= grace) {
                watch.returned.insert(node.id, now);
            }
            if node.down_since > 0 {
                app.db.set_down_since(node.id, 0)?;
                up.push((node.name.as_str(), format!("离线 {}", span(now - node.down_since))));
            }
            continue;
        }
        // A node that has never reported cannot be announced, and tracking its
        // absence would count its first connection as a return from an outage.
        if node.last_seen == 0 {
            continue;
        }
        let since = *watch.absent.entry(node.id).or_insert(now);
        let flapping = watch.returned.get(&node.id).is_some_and(|back| since - back < FLAP_WINDOW);
        let wait = if flapping { FLAP_GRACE } else { grace };
        if armed && node.notify && node.down_since == 0 && now - since >= wait {
            app.db.set_down_since(node.id, node.last_seen)?;
            down.push((node.name.as_str(), format!("最后上报 {}", clock(node.last_seen))));
        }
    }
    let mut notes: Vec<Note> = [batch("offline", "🔴", "离线", down), batch("online", "🟢", "恢复在线", up)]
        .into_iter()
        .flatten()
        .collect();

    let percent = number(app, "notify_traffic");
    let mut metered = Vec::new();
    let traffic = if percent > 0 && armed { app.db.all_traffic() } else { HashMap::new() };
    for node in nodes.iter().filter(|n| n.traffic_limit > 0) {
        let Some(t) = traffic.get(&node.id) else { continue };
        let used = t.month_used(&node.traffic_mode);
        // i128: 100 × a limit near i64::MAX would overflow.
        let reached = |p: i64| used as i128 * 100 >= node.traffic_limit as i128 * p as i128;
        let step = if reached(100) {
            100
        } else if reached(percent) {
            percent
        } else {
            0
        };
        // A step below the one recorded is a manual correction; storing it lets the
        // same crossing be announced again.
        let last = watch.traffic.insert(node.id, (t.month_start.clone(), step));
        let told = last.is_some_and(|(period, last)| period == t.month_start && last >= step);
        if step == 0 || told || !watch.primed {
            continue;
        }
        let mode = match node.traffic_mode.as_str() {
            "up" => "仅上行",
            "down" => "仅下行",
            "max" => "取较大值",
            _ => "上下行相加",
        };
        let share = used as i128 * 100 / node.traffic_limit as i128;
        let detail = format!(
            "已用 {share}%，{} / {}（{mode}），本期自 {} 起",
            gib(used),
            gib(node.traffic_limit),
            t.month_start
        );
        metered.push((node.name.as_str(), detail));
    }
    notes.extend(batch("traffic", "⚠️", "流量提醒", metered));
    watch.primed = true;
    Ok(notes)
}

fn span(seconds: i64) -> String {
    let minutes = seconds.max(0) / 60;
    match (minutes / 1_440, minutes / 60 % 24, minutes % 60) {
        (0, 0, m) => format!("{m} 分钟"),
        (0, h, m) => format!("{h} 小时 {m} 分钟"),
        (d, h, _) => format!("{d} 天 {h} 小时"),
    }
}

fn site_name(app: &App) -> String {
    setting(app, "site_name").unwrap_or_else(|| "Monitor".into())
}

/// Hub-local time with its offset: a hub in a container commonly runs on UTC
/// while its operator reads local time.
fn clock(ts: i64) -> String {
    Local.timestamp_opt(ts, 0).single().map(|t| t.format("%m-%d %H:%M %:z").to_string()).unwrap_or_default()
}

/// GiB, labelled GB as in the panel.
fn gib(bytes: i64) -> String {
    format!("{:.2} GB", bytes as f64 / (1u64 << 30) as f64)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::agent_ws::Agent;
    use crate::db::{Db, Node, NodePatch, TrafficPatch};

    fn app() -> App {
        App::for_test(Db::open(":memory:").unwrap())
    }

    fn node(app: &App, name: &str, notify: bool, last_seen: i64) -> i64 {
        let id = app
            .db
            .create_node(&Node { name: name.into(), traffic_reset_day: 1, ..Default::default() }, name)
            .unwrap();
        app.db.update_node(id, &NodePatch { notify: Some(notify), ..Default::default() }).unwrap();
        app.db.touch_seen(id, last_seen, &serde_json::Value::Null).unwrap();
        id
    }

    fn connect(app: &App, id: i64) {
        let (tx, _) = mpsc::channel(1);
        app.agents.write().unwrap().insert(id, Agent::new(1, tx, 0));
    }

    /// Offline alerts are only marked while a channel exists to carry them.
    fn with_channel(app: &App) {
        app.db
            .create_notify_channel("Webhook", "webhook", r#"{"url":"http://127.0.0.1:9/"}"#)
            .unwrap()
            .unwrap();
    }

    #[test]
    fn a_rendered_body_stays_json_whatever_the_values_contain() {
        let body = render(
            r#"{"t":"{{title}}","m":"{{message}}","n":"{{node}}","s":"{{site}}","x":"{{other}}"}"#,
            &sample(),
            r#"my "hub""#,
            true,
        );
        let parsed: Value = serde_json::from_str(&body).unwrap();
        // Single pass: the title's own "{{message}}" is text, not a placeholder.
        assert_eq!(parsed["t"], "{{message}}");
        assert_eq!(parsed["m"], "line\nline");
        assert_eq!(parsed["n"], r#"a"b\c"#);
        assert_eq!(parsed["s"], r#"my "hub""#);
        assert_eq!(parsed["x"], "{{other}}", "an unknown placeholder is left as written");
        // Telegram's text is not JSON: the same values arrive unescaped.
        assert_eq!(
            render("[{{site}}] {{node}}\n{{message}}", &sample(), "hub", false),
            "[hub] a\"b\\c\nline\nline"
        );

        // 渠道配置校验（二期起渠道住自己的表，走 channel_error）。
        let cfg = |json: &str| serde_json::from_str::<Value>(json).unwrap();
        let webhook = |body: &str, _headers: &str| {
            channel_error(
                "webhook",
                &cfg(&format!(r#"{{"url":"https://x.example/h"{{c}},"body":{body:?}}}"#)),
                false,
            )
        };
        let _ = webhook;
        assert_eq!(channel_error("webhook", &cfg(r#"{"url":"https://x.example/h"}"#), false), None);
        assert!(
            channel_error("webhook", &cfg(r#"{"url":"ftp://x"}"#), false).is_some(),
            "webhook url must be http(s)"
        );
        assert_eq!(
            channel_error(
                "webhook",
                &cfg(r#"{"url":"https://x.example/h","headers":"Authorization: Bearer x\n\nX-Id: 1"}"#),
                false
            ),
            None
        );
        assert!(channel_error(
            "webhook",
            &cfg(r#"{"url":"https://x.example/h","headers":"Authorization Bearer x"}"#),
            false
        )
        .is_some());
        assert_eq!(
            channel_error(
                "webhook",
                &cfg(r#"{"url":"https://x.example/h","body":"{\"t\":\"{{title}}\"}"}"#),
                false
            ),
            None
        );
        assert!(
            channel_error(
                "webhook",
                &cfg(r#"{"url":"https://x.example/h","body":"{\"t\": {{title}}}"}"#),
                false
            )
            .is_some(),
            "placeholder must sit inside quotes"
        );
        assert!(
            channel_error("telegram", &cfg(r#"{"token":"123:abc/../x","chat":"42"}"#), false).is_some(),
            "goes into the path"
        );
        assert_eq!(channel_error("telegram", &cfg(r#"{"token":"123456:AA-b_c","chat":"42"}"#), false), None);
        for chat in ["-1001234", "42", "@my_channel"] {
            assert_eq!(
                channel_error(
                    "telegram",
                    &cfg(&format!(r#"{{"token":"123456:AA-b_c","chat":"{chat}"}}"#)),
                    false
                ),
                None,
                "{chat}"
            );
        }
        assert!(channel_error("telegram", &cfg(r#"{"token":"123456:AA-b_c","chat":"-"}"#), false).is_some());
        // 编辑时空凭据沿用旧值：合法；新建时留空：拒绝。
        assert_eq!(channel_error("telegram", &cfg(r#"{"chat":"42"}"#), true), None);
        assert!(channel_error("telegram", &cfg(r#"{"chat":"42"}"#), false).is_some());
        assert_eq!(channel_error("bark", &cfg(r#"{"key":"AbCdEf123456"}"#), false), None);
        assert!(channel_error("bark", &cfg(r#"{"server":"ftp://x","key":"k"}"#), false).is_some());
        assert_eq!(channel_error("serverchan", &cfg(r#"{"key":"SCT123456"}"#), false), None);
        assert_eq!(
            channel_error(
                "smtp",
                &cfg(r#"{"host":"smtp.example.com","port":"465","from":"a@b.c","to":"d@e.f"}"#),
                false
            ),
            None
        );
        assert!(channel_error(
            "smtp",
            &cfg(r#"{"host":"smtp.example.com","from":"bad","to":"d@e.f"}"#),
            false
        )
        .is_some());
        assert!(
            setting_error("notify_expiry_sent", "2026-01-01").is_some(),
            "internal state is not a setting"
        );
        assert!(setting_error("notify_unknown", "").is_some(), "an empty value does not make a key known");

        // A long list is cut to what Discord and WeCom accept; `node` stays whole.
        let names: Vec<String> = (0..60).map(|i| format!("n{i}")).collect();
        let note =
            batch("offline", "🔴", "离线", names.iter().map(|n| (n.as_str(), "d".into())).collect()).unwrap();
        assert_eq!(note.title, "🔴 60 台节点离线");
        assert_eq!(note.message.lines().count(), LISTED + 1);
        assert!(note.message.ends_with("……另外 40 台"));
        assert_eq!(note.node.split(", ").count(), 60);
    }

    #[test]
    fn offline_is_announced_once_after_the_grace_period_and_paired_with_the_return() {
        let app = app();
        let now = 1_000_000;
        let a = node(&app, "a", true, now - 600);
        node(&app, "b", true, now - 600);
        let quiet = node(&app, "quiet", false, now - 600);
        let brief = node(&app, "brief", true, now - 600);
        let mut watch = Watch { primed: true, ..Default::default() };

        // Nothing is marked while no channel could carry the alert, so the nodes
        // are still reported once one is configured.
        assert!(sweep(&app, &mut watch, now).unwrap().is_empty(), "the grace period starts when seen absent");
        assert!(sweep(&app, &mut watch, now + 180).unwrap().is_empty(), "no channel");
        with_channel(&app);
        connect(&app, brief);
        let notes = sweep(&app, &mut watch, now + 210).unwrap();
        assert_eq!(notes.len(), 1, "two nodes down in one sweep are one alert");
        assert_eq!(notes[0].title, "🔴 2 台节点离线");
        assert_eq!(notes[0].node, "a, b", "not the opted-out node, nor one back within the grace period");
        assert!(sweep(&app, &mut watch, now + 240).unwrap().is_empty(), "announced once");

        // A restart forgets nothing that was announced: the state is in the row.
        let mut restarted = Watch::default();
        assert!(sweep(&app, &mut restarted, now + 300).unwrap().is_empty());
        assert!(sweep(&app, &mut restarted, now + 900).unwrap().is_empty());

        connect(&app, a);
        connect(&app, quiet);
        let notes = sweep(&app, &mut restarted, now + 900).unwrap();
        assert_eq!(notes.len(), 1);
        assert_eq!(notes[0].event, "online");
        assert_eq!(notes[0].title, "🟢 a 恢复在线", "only the node whose absence was announced");
        assert_eq!(notes[0].message, "离线 25 分钟");
        assert!(sweep(&app, &mut restarted, now + 930).unwrap().is_empty());
    }

    /// `last_seen` is written once a minute at best, and once per report for an
    /// agent reporting less often. Measured from it, a restart of an agent on a
    /// five-minute interval would be past the grace period the moment a sweep
    /// caught it.
    #[test]
    fn a_restart_is_not_an_outage_however_old_the_last_report_is() {
        let app = app();
        with_channel(&app);
        let now = 1_000_000;
        let id = node(&app, "slow", true, now - 240);
        connect(&app, id);
        let mut watch = Watch { primed: true, ..Default::default() };
        assert!(sweep(&app, &mut watch, now).unwrap().is_empty());
        app.agents.write().unwrap().remove(&id);
        assert!(sweep(&app, &mut watch, now + 30).unwrap().is_empty(), "absent for one sweep");
        connect(&app, id);
        assert!(sweep(&app, &mut watch, now + 60).unwrap().is_empty());
    }

    #[test]
    fn a_flapping_node_is_reported_only_once_an_absence_outlasts_half_an_hour() {
        let app = app();
        let t = 1_000_000;
        with_channel(&app);
        let id = node(&app, "flappy", true, t);
        let mut watch = Watch { primed: true, ..Default::default() };
        let mut at = |now: i64| -> Vec<&'static str> {
            sweep(&app, &mut watch, now).unwrap().into_iter().map(|n| n.event).collect()
        };
        let back = |now| {
            connect(&app, id);
            app.db.touch_seen(id, now, &serde_json::Value::Null).unwrap();
        };
        let gone = |last_seen| {
            app.agents.write().unwrap().remove(&id);
            app.db.touch_seen(id, last_seen, &serde_json::Value::Null).unwrap();
        };

        // A five-minute absence is an ordinary outage.
        assert!(at(t).is_empty());
        assert_eq!(at(t + 300), ["offline"]);
        back(t + 330);
        assert_eq!(at(t + 330), ["online"]);
        // Gone again ten minutes later: flapping, so ten minutes pass in silence,
        // but an absence that reaches half an hour is still reported.
        gone(t + 900);
        assert!(at(t + 900).is_empty());
        assert!(at(t + 1_500).is_empty());
        assert_eq!(at(t + 2_700), ["offline"]);
        back(t + 2_730);
        assert_eq!(at(t + 2_730), ["online"]);

        // An hour online restores the ordinary grace period.
        gone(t + 2_730 + 3_600);
        assert!(at(t + 2_730 + 3_600).is_empty());
        assert_eq!(at(t + 2_730 + 3_600 + 180), ["offline"]);
        back(t + 6_600);
        at(t + 6_600);

        // A 30-second absence, an agent restart, is not a flap.
        gone(t + 10_800);
        at(t + 10_830);
        back(t + 10_860);
        at(t + 10_860);
        gone(t + 11_000);
        assert!(at(t + 11_000).is_empty());
        assert_eq!(at(t + 11_180), ["offline"], "the next absence keeps the ordinary grace period");
    }

    /// A deleted node's id goes to the next node created, and a node's first
    /// connection is not a return from an outage: either would put a new node on
    /// the flapping grace period or suppress its first traffic alert.
    #[test]
    fn a_new_node_starts_with_no_absence_return_or_traffic_step() {
        let app = app();
        with_channel(&app);
        let (t, gb) = (1_000_000, 1i64 << 30);
        let metered = |id: i64| {
            app.db
                .update_node(id, &NodePatch { traffic_limit: Some(100 * gb), ..Default::default() })
                .unwrap();
            let patch = TrafficPatch { month_rx: Some(90 * gb), month_tx: Some(0), ..Default::default() };
            app.db.set_traffic(id, &patch).unwrap();
        };
        let mut watch = Watch { primed: true, ..Default::default() };
        let mut at = |now: i64| -> Vec<&'static str> {
            sweep(&app, &mut watch, now).unwrap().into_iter().map(|n| n.event).collect()
        };

        let old = node(&app, "old", false, t);
        metered(old);
        assert_eq!(at(t), ["traffic"]);
        app.db.delete_node(old).unwrap();
        assert!(at(t + 30).is_empty());

        let new = node(&app, "new", true, 0);
        assert_eq!(new, old, "the id is reused");
        metered(new);
        assert_eq!(at(t + 60), ["traffic"]);
        connect(&app, new);
        app.db.touch_seen(new, t + 600, &serde_json::Value::Null).unwrap();
        assert!(at(t + 600).is_empty());
        app.agents.write().unwrap().remove(&new);
        assert!(at(t + 630).is_empty());
        assert_eq!(at(t + 810), ["offline"], "the ordinary grace period");
    }

    #[test]
    fn traffic_is_announced_at_the_threshold_and_at_the_allowance_once_each() {
        let app = app();
        let id = node(&app, "t", false, 0);
        let gb = 1i64 << 30;
        app.db.update_node(id, &NodePatch { traffic_limit: Some(100 * gb), ..Default::default() }).unwrap();
        let mut watch = Watch::default();
        let used = |month_rx: i64| {
            app.db.set_traffic(
                id,
                &TrafficPatch { month_rx: Some(month_rx), month_tx: Some(0), ..Default::default() },
            )
        };
        let titles = |watch: &mut Watch| -> Vec<String> {
            let notes = sweep(&app, watch, 0).unwrap().into_iter().filter(|n| n.event == "traffic");
            notes.map(|n| format!("{} {}", n.title, n.message.split('，').next().unwrap())).collect()
        };

        used(85 * gb).unwrap();
        assert!(titles(&mut watch).is_empty());
        assert!(titles(&mut watch).is_empty(), "no channel");
        with_channel(&app);
        assert_eq!(
            titles(&mut watch),
            ["⚠️ t 流量提醒 已用 85%"],
            "a crossing made before the channel existed"
        );
        let mut watch = Watch::default();
        assert!(titles(&mut watch).is_empty(), "the first sweep after a start records, it does not repeat");
        used(10 * gb).unwrap();
        assert!(titles(&mut watch).is_empty(), "below the threshold");
        used(81 * gb).unwrap();
        assert_eq!(
            titles(&mut watch),
            ["⚠️ t 流量提醒 已用 81%"],
            "a correction downward re-arms the crossing"
        );
        used(95 * gb).unwrap();
        assert!(titles(&mut watch).is_empty(), "no alert per percent between the two steps");
        used(100 * gb).unwrap();
        assert_eq!(titles(&mut watch), ["⚠️ t 流量提醒 已用 100%"]);
        assert!(titles(&mut watch).is_empty());
    }

    /// 汇总推送：窗口内同渠道相同内容合并为一条并计数；不同内容互不干扰；
    /// 冲洗只取到期条目。
    #[test]
    fn the_digest_merges_identical_alerts_within_the_window() {
        let mut buffer: Digest = HashMap::new();
        let note = |msg: &str| Note {
            event: "offline",
            title: "🔴 a 离线".into(),
            message: msg.into(),
            ..Default::default()
        };
        digest_absorb(&mut buffer, 1, &note("最后上报 12:00"), 300, 1_000);
        digest_absorb(&mut buffer, 1, &note("最后上报 12:00"), 300, 1_020);
        digest_absorb(&mut buffer, 1, &note("最后上报 13:00"), 300, 1_030);
        digest_absorb(&mut buffer, 2, &note("最后上报 12:00"), 300, 1_040);
        assert_eq!(buffer.len(), 3, "两渠道×两内容");

        // 1_200 时：渠道 1 的首条（窗口到 1_300）未到期，渠道 2（到 1_340）未到期。
        assert!(digest_due(&mut buffer, 1_200).is_empty());
        let due = digest_due(&mut buffer, 1_300);
        assert_eq!(due.len(), 1);
        let (cid, flushed, count) = &due[0];
        assert_eq!(*cid, 1);
        assert_eq!(flushed.message, "最后上报 12:00");
        assert_eq!(*count, 2, "窗口内相同内容合并计数");
        assert_eq!(buffer.len(), 2);
    }

    #[test]
    fn the_expiry_digest_is_sent_once_a_day_from_nine() {
        let app = app();
        let at = |h| Local.with_ymd_and_hms(2026, 9, 15, h, 0, 0).unwrap();
        for (name, date) in
            [("later", "2026-09-30"), ("soon", "2026-09-20"), ("today", "2026-09-15"), ("gone", "2026-09-14")]
        {
            let id = node(&app, name, false, 0);
            app.db.set_expiry(id, date).unwrap();
        }
        assert!(expiry_digest(&app, at(8)).unwrap().is_none(), "not before nine");
        assert!(expiry_digest(&app, at(9)).unwrap().is_none(), "no channel, and the day is not spent");
        with_channel(&app);
        let note = expiry_digest(&app, at(9)).unwrap().unwrap();
        assert_eq!(note.title, "⏳ 2 台节点即将到期");
        assert_eq!(note.message, "today · 2026-09-15 今天到期\nsoon · 2026-09-20 还剩 5 天");
        assert!(expiry_digest(&app, at(10)).unwrap().is_none(), "once per day");
    }
}
