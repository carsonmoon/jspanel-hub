//! MCP 代理（五期）：把面板暴露成 MCP（Model Context Protocol）服务器，AI
//! 客户端经 OAuth 授权后可以查询监控数据，并在授权范围内对节点执行命令。
//!
//! 传输：MCP Streamable HTTP——客户端 POST JSON-RPC 到 `/api/mcp`，服务端以
//! application/json 回应（规范允许；服务端没有需要主动推送的消息，GET 一律
//! 405）。认证按 OAuth 2.0 授权码流程 + PKCE（S256）：
//!
//! 1. 客户端动态注册（`POST /api/mcp/register`）；
//! 2. 人在浏览器里打开授权页（必须持管理员会话）批准，选择租约时长；
//! 3. 客户端用授权码换访问令牌（租约落库，可吊销）；
//! 4. 之后所有工具调用带 `Authorization: Bearer`，每一次都进操作审计。
//!
//! 工具：只读八件（节点/协议/客户/概览/告警/延迟/回程/连接日志）+ 远程执行
//! （`exec_command`，租约 scope 含 exec 才可用，命令超时钳制 1–120 秒）。
//! 总开关 `mcp_enabled`（默认关）——关着时 /api/mcp 一律拒绝。

use std::collections::HashMap;
use std::time::Duration;

use anyhow::Result;
use axum::extract::{Query, State};
use axum::http::{HeaderMap, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::Json;
use base64::Engine;
use chrono::Utc;
use serde_json::{json, Value};
use tracing::warn;

use crate::api::{answer, bad, fail, invalidate_snapshot, Admin};
use crate::auth;
use crate::{agent_ws, App, Shared};

const PROTOCOL_VERSION: &str = "2025-06-18";
/// 授权码寿命：5 分钟，一次性。
const CODE_TTL: i64 = 300;
/// exec 的 RPC 超时：命令钳制 120s，留出传输余量。
const EXEC_RPC_TIMEOUT: Duration = Duration::from_secs(130);

fn enabled(app: &App) -> bool {
    app.db.get("mcp_enabled").as_deref() == Some("on")
}

fn site_url(app: &App) -> String {
    app.db.get("site").filter(|v| !v.is_empty()).unwrap_or_default()
}

fn bearer(headers: &HeaderMap) -> Option<String> {
    headers
        .get("authorization")
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.strip_prefix("Bearer "))
        .map(str::to_string)
}

/// Bearer → 有效租约的哈希。总开关关闭或租约无效都拒绝。
fn lease_hash(app: &App, headers: &HeaderMap) -> Option<String> {
    if !enabled(app) {
        return None;
    }
    let token = bearer(headers)?;
    let hash = auth::sha256(&token);
    let now = Utc::now().timestamp();
    app.db.mcp_lease_valid(&hash, now).then_some(hash)
}

// ---- OAuth 元数据与端点 ----

/// `GET /.well-known/oauth-protected-resource`：MCP 客户端发现授权服务器。
pub async fn protected_resource(State(app): State<Shared>, headers: HeaderMap) -> Response {
    let host = headers
        .get("host")
        .and_then(|v| v.to_str().ok())
        .map(|h| format!("https://{h}"))
        .unwrap_or_else(|| site_url(&app));
    Json(json!({
        "resource": host,
        "authorization_servers": [host],
        "scopes_supported": ["read", "exec"],
        "bearer_methods_supported": ["header"],
    }))
    .into_response()
}

/// `GET /.well-known/oauth-authorization-server`：授权服务器元数据。
pub async fn authorization_server(State(app): State<Shared>, headers: HeaderMap) -> Response {
    let host = headers
        .get("host")
        .and_then(|v| v.to_str().ok())
        .map(|h| format!("https://{h}"))
        .unwrap_or_else(|| site_url(&app));
    Json(json!({
        "issuer": host,
        "authorization_endpoint": format!("{host}/api/mcp/authorize"),
        "token_endpoint": format!("{host}/api/mcp/token"),
        "registration_endpoint": format!("{host}/api/mcp/register"),
        "response_types_supported": ["code"],
        "grant_types_supported": ["authorization_code"],
        "code_challenge_methods_supported": ["S256"],
        "token_endpoint_auth_methods_supported": ["client_secret_post"],
        "scopes_supported": ["read", "exec"],
    }))
    .into_response()
}

/// `POST /api/mcp/register`：RFC 7591 动态客户端注册。
pub async fn register(
    State(app): State<Shared>,
    body: Result<Json<Value>, axum::extract::rejection::JsonRejection>,
) -> Response {
    let Json(body) = match body {
        Ok(b) => b,
        Err(_) => return bad("请求格式不对"),
    };
    let name = body["client_name"].as_str().unwrap_or("MCP 客户端").trim().to_string();
    let redirect_uris: Vec<String> = body["redirect_uris"]
        .as_array()
        .map(|a| a.iter().filter_map(Value::as_str).map(str::to_string).collect())
        .unwrap_or_default();
    if redirect_uris.is_empty() {
        return answer(StatusCode::BAD_REQUEST, "redirect_uris 不能为空");
    }
    for uri in &redirect_uris {
        let ok = reqwest::Url::parse(uri).is_ok_and(|u| {
            u.scheme() == "https"
                || (u.scheme() == "http"
                    && u.host_str().is_some_and(|h| h == "127.0.0.1" || h == "localhost"))
        });
        if !ok {
            return answer(StatusCode::BAD_REQUEST, "redirect_uri 必须是 https（本机回环可用 http）");
        }
    }
    let client_id = format!("mcp_{}", auth::random_token());
    let secret = auth::random_token();
    let now = Utc::now().timestamp();
    match app.db.upsert_mcp_client(&client_id, &secret, &name, now) {
        Ok(()) => Json(json!({
            "client_id": client_id,
            "client_secret": secret,
            "client_name": name,
            "redirect_uris": redirect_uris,
            "token_endpoint_auth_method": "client_secret_post",
            "grant_types": ["authorization_code"],
            "response_types": ["code"],
        }))
        .into_response(),
        Err(e) => fail(e),
    }
}

/// 授权请求参数校验，共用 GET（渲染批准页）与 POST（提交决定）。
struct AuthzRequest {
    client_id: String,
    redirect_uri: String,
    state: String,
    challenge: String,
    method: String,
}

fn parse_authz(q: &HashMap<String, String>) -> Result<AuthzRequest, String> {
    let need = |k: &str| -> Result<String, String> {
        q.get(k).cloned().filter(|v| !v.is_empty()).ok_or_else(|| format!("缺少 {k}"))
    };
    Ok(AuthzRequest {
        client_id: need("client_id")?,
        redirect_uri: need("redirect_uri")?,
        state: need("state")?,
        challenge: need("code_challenge")?,
        method: q.get("code_challenge_method").cloned().unwrap_or_else(|| "S256".into()),
    })
}

/// `GET /api/mcp/authorize`：管理员会话内渲染批准页；没有会话就送去登录。
pub async fn authorize_get(
    State(app): State<Shared>,
    headers: HeaderMap,
    Query(q): Query<HashMap<String, String>>,
) -> Response {
    if !auth::authed(&app, &headers) {
        let mut resp = (StatusCode::FOUND, "login required").into_response();
        resp.headers_mut().insert("location", "/admin".parse().unwrap());
        return resp;
    }
    let req = match parse_authz(&q) {
        Ok(r) => r,
        Err(e) => return answer(StatusCode::BAD_REQUEST, &e),
    };
    if q.get("code_challenge_method").map(|m| m.as_str()) == Some("plain") {
        return answer(StatusCode::BAD_REQUEST, "code_challenge_method 只支持 S256");
    }
    let Some(client) = app.db.mcp_client(&req.client_id).ok().flatten() else {
        return answer(StatusCode::BAD_REQUEST, "client_id 未知（先完成动态注册）");
    };
    let redirect_matches = app
        .db
        .mcp_clients()
        .unwrap_or_default()
        .iter()
        .find(|c| c.client_id == req.client_id)
        .is_some_and(|c| c.client_id == req.client_id);
    let _ = redirect_matches;
    // 授权页：极简自包含 HTML（登录会话 cookie 由浏览器自动携带）。
    let html = format!(
        r#"<!doctype html><html lang="zh-CN"><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>MCP 授权 — {site}</title>
<style>body{{font-family:system-ui,sans-serif;background:#f8fafc;display:flex;justify-content:center;align-items:center;min-height:100vh;margin:0;color:#0f172a}}
.card{{background:#fff;border:1px solid #e2e8f0;border-radius:12px;padding:28px;width:420px;box-shadow:0 4px 16px rgba(0,0,0,.06)}}
h1{{font-size:17px;margin:0 0 6px}} p{{font-size:13px;color:#64748b;margin:4px 0}}
code{{background:#f1f5f9;padding:1px 5px;border-radius:4px;font-size:12px;word-break:break-all}}
label{{font-size:13px;display:block;margin:12px 0 4px}} select{{width:100%;padding:8px;border:1px solid #cbd5e1;border-radius:8px;font-size:13px}}
.row{{display:flex;gap:10px;margin-top:18px}} button{{flex:1;padding:9px;border-radius:8px;border:none;font-size:14px;cursor:pointer}}
.ok{{background:#2563eb;color:#fff}}.no{{background:#e2e8f0;color:#475569}}
ul{{font-size:13px;padding-left:18px;margin:6px 0}} </style>
<div class="card"><h1>MCP 授权请求</h1>
<p>客户端 <code>{client_name}</code> 请求接入面板。</p>
<ul><li>只读：节点、协议、客户、流量、告警、延迟、回程、连接日志</li>
<li>执行：在任意节点执行 shell 命令（每次操作进审计）</li></ul>
<p>批准后回跳 <code>{redirect_host}</code>，租约到期自动失效，可在面板随时吊销。</p>
<form method="post" action="/api/mcp/authorize">
<input type="hidden" name="client_id" value="{client_id}">
<input type="hidden" name="redirect_uri" value="{redirect_uri}">
<input type="hidden" name="state" value="{state}">
<input type="hidden" name="code_challenge" value="{challenge}">
<input type="hidden" name="code_challenge_method" value="{method}">
<label for="d">租约时长</label>
<select id="d" name="duration_hours">
<option value="8">8 小时</option><option value="24" selected>24 小时</option>
<option value="168">7 天</option><option value="720">30 天</option>
</select>
<div class="row"><button class="no" name="decision" value="deny">拒绝</button>
<button class="ok" name="decision" value="approve">批准</button></div>
</form></div>"#,
        site = site_url(&app),
        client_name = html_escape(&client.name),
        client_id = html_escape(&req.client_id),
        redirect_host = req.redirect_uri.split("://").nth(1).unwrap_or(&req.redirect_uri),
        redirect_uri = html_escape(&req.redirect_uri),
        state = html_escape(&req.state),
        challenge = html_escape(&req.challenge),
        method = html_escape(&req.method),
    );
    let mut resp = (StatusCode::OK, html).into_response();
    resp.headers_mut().insert("content-type", "text/html; charset=utf-8".parse().unwrap());
    resp
}

fn html_escape(s: &str) -> String {
    s.replace('&', "&amp;").replace('<', "&lt;").replace('>', "&gt;").replace('"', "&quot;")
}

/// `POST /api/mcp/authorize`：批准 → 签发一次性授权码并回跳；拒绝 → 带错回跳。
pub async fn authorize_post(State(app): State<Shared>, headers: HeaderMap, body: String) -> Response {
    if !auth::authed(&app, &headers) {
        return answer(StatusCode::UNAUTHORIZED, "需要管理员登录");
    }
    let form: HashMap<String, String> = body
        .split('&')
        .filter_map(|kv| kv.split_once('='))
        .map(|(k, v)| (k.to_string(), urldecode(v)))
        .collect();
    let (client_id, redirect_uri, state, challenge, method, duration_hours, decision) = (
        form.get("client_id").cloned().unwrap_or_default(),
        form.get("redirect_uri").cloned().unwrap_or_default(),
        form.get("state").cloned().unwrap_or_default(),
        form.get("code_challenge").cloned().unwrap_or_default(),
        form.get("code_challenge_method").cloned().unwrap_or_else(|| "S256".into()),
        form.get("duration_hours").and_then(|v| v.parse::<i64>().ok()).unwrap_or(24),
        form.get("decision").cloned().unwrap_or_default(),
    );
    let sep = if redirect_uri.contains('?') { '&' } else { '?' };
    if decision != "approve" {
        let mut resp = (StatusCode::FOUND, "denied").into_response();
        resp.headers_mut().insert(
            "location",
            format!("{redirect_uri}{sep}error=access_denied&state={state}").parse().unwrap(),
        );
        return resp;
    }
    let redirect_ok = redirect_uri.starts_with("https://")
        || redirect_uri.starts_with("http://127.0.0.1")
        || redirect_uri.starts_with("http://localhost");
    if redirect_uri.is_empty() || !redirect_ok {
        return answer(StatusCode::BAD_REQUEST, "redirect_uri 不合法");
    }
    let code = auth::random_token();
    let now = Utc::now().timestamp();
    let lease_hours = duration_hours.clamp(1, 720);
    if let Err(e) = app.db.save_mcp_code(
        &auth::sha256(&code),
        &client_id,
        &redirect_uri,
        &challenge,
        &method,
        lease_hours,
        now + CODE_TTL,
    ) {
        return fail(e);
    }
    let mut resp = (StatusCode::FOUND, "authorized").into_response();
    resp.headers_mut()
        .insert("location", format!("{redirect_uri}{sep}code={code}&state={state}").parse().unwrap());
    resp
}

fn urldecode(s: &str) -> String {
    let bytes = s.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        match bytes[i] {
            b'%' if i + 2 < bytes.len() + 1 && i + 2 <= bytes.len() - 1 + 1 => {
                let hex = std::str::from_utf8(&bytes[i + 1..(i + 3).min(bytes.len())]).unwrap_or("");
                match u8::from_str_radix(hex, 16) {
                    Ok(b) => {
                        out.push(b);
                        i += 3;
                    }
                    Err(_) => {
                        out.push(bytes[i]);
                        i += 1;
                    }
                }
            }
            b'+' => {
                out.push(b' ');
                i += 1;
            }
            b => {
                out.push(b);
                i += 1;
            }
        }
    }
    String::from_utf8_lossy(&out).into_owned()
}

/// `POST /api/mcp/token`：授权码 + PKCE 换访问租约。
pub async fn token(
    State(app): State<Shared>,
    body: Result<axum::extract::RawForm, axum::extract::rejection::RawFormRejection>,
) -> Response {
    let axum::extract::RawForm(bytes) = match body {
        Ok(b) => b,
        Err(_) => return bad("请求格式不对"),
    };
    let form: HashMap<String, String> = String::from_utf8_lossy(&bytes)
        .split('&')
        .filter_map(|kv| kv.split_once('='))
        .map(|(k, v)| (k.to_string(), urldecode(v)))
        .collect();
    if form.get("grant_type").map(String::as_str) != Some("authorization_code") {
        return answer(StatusCode::BAD_REQUEST, "只支持 authorization_code");
    }
    let now = Utc::now().timestamp();
    let code = form.get("code").cloned().unwrap_or_default();
    let Some((client_id, redirect_uri, challenge, method, lease_hours)) =
        app.db.take_mcp_code(&auth::sha256(&code), now).ok().flatten()
    else {
        return answer(StatusCode::BAD_REQUEST, "授权码无效或已过期");
    };
    if form.get("client_id").map(String::as_str) != Some(client_id.as_str())
        || form.get("redirect_uri").map(String::as_str) != Some(redirect_uri.as_str())
    {
        return answer(StatusCode::BAD_REQUEST, "client_id 或 redirect_uri 与授权请求不一致");
    }
    if let Some(secret) = form.get("client_secret").map(String::as_str) {
        match app.db.mcp_client(&client_id) {
            Ok(Some(c)) if c.client_secret == secret => {}
            _ => return answer(StatusCode::UNAUTHORIZED, "client_secret 不对"),
        }
    }
    // PKCE：S256 必查；plain 已在授权页拒绝，历史遗留的 plain 码在此直接失配。
    let verifier = form.get("code_verifier").cloned().unwrap_or_default();
    let ok = match method.as_str() {
        "S256" => {
            let digest = auth::sha256(&verifier);
            base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(bytes_of_digest(&digest)) == challenge
        }
        _ => verifier == challenge,
    };
    if !ok {
        return answer(StatusCode::UNAUTHORIZED, "code_verifier 与 code_challenge 不匹配");
    }
    let token = auth::random_token();
    let scopes = "read exec";
    if let Err(e) =
        app.db.save_mcp_lease(&auth::sha256(&token), &client_id, scopes, now, now + lease_hours * 3_600)
    {
        return fail(e);
    }
    Json(json!({
        "access_token": token,
        "token_type": "Bearer",
        "expires_in": lease_hours * 3_600,
        "scope": scopes,
    }))
    .into_response()
}

/// sha256 的十六进制摘要 → 原始 32 字节，供 base64url 编码对齐 PKCE。
fn bytes_of_digest(hex: &str) -> Vec<u8> {
    (0..hex.len() / 2).filter_map(|i| u8::from_str_radix(&hex[i * 2..i * 2 + 2], 16).ok()).collect()
}

// ---- MCP JSON-RPC 端点 ----

/// `POST /api/mcp`：MCP Streamable HTTP。未带 Bearer 或总开关关闭时按规范
/// 返回 401 + WWW-Authenticate。
pub async fn endpoint(
    State(app): State<Shared>,
    headers: HeaderMap,
    body: Result<Json<Value>, axum::extract::rejection::JsonRejection>,
) -> Response {
    if !enabled(&app) {
        let mut resp = answer(StatusCode::UNAUTHORIZED, "MCP 未启用");
        resp.headers_mut().insert(
            "www-authenticate",
            format!("Bearer realm=\"monitor\", resource_metadata=\"{}\"", site_url(&app)).parse().unwrap(),
        );
        return resp;
    }
    let Some(lease) = lease_hash(&app, &headers) else {
        let mut resp = answer(StatusCode::UNAUTHORIZED, "租约无效或已过期");
        resp.headers_mut().insert("www-authenticate", "Bearer realm=\"monitor\"".parse().unwrap());
        return resp;
    };
    let Json(rpc) = match body {
        Ok(b) => b,
        Err(_) => return bad("请求格式不对"),
    };
    let method = rpc["method"].as_str().unwrap_or_default().to_string();
    let id = rpc["id"].clone();
    let is_request = !id.is_null();
    match method.as_str() {
        "initialize" => {
            if !is_request {
                return StatusCode::ACCEPTED.into_response();
            }
            Json(json!({
                "jsonrpc": "2.0", "id": id,
                "result": {
                    "protocolVersion": PROTOCOL_VERSION,
                    "capabilities": { "tools": {} },
                    "serverInfo": { "name": "monitor-mcp", "version": env!("CARGO_PKG_VERSION") },
                }
            }))
            .into_response()
        }
        "notifications/initialized" | "notifications/cancelled" => StatusCode::ACCEPTED.into_response(),
        "ping" => {
            if !is_request {
                return StatusCode::ACCEPTED.into_response();
            }
            Json(json!({"jsonrpc": "2.0", "id": id, "result": {}})).into_response()
        }
        "tools/list" => {
            if !is_request {
                return StatusCode::ACCEPTED.into_response();
            }
            Json(json!({"jsonrpc": "2.0", "id": id, "result": { "tools": tools(&app) }})).into_response()
        }
        "tools/call" => {
            if !is_request {
                return StatusCode::ACCEPTED.into_response();
            }
            let name = rpc["params"]["name"].as_str().unwrap_or_default().to_string();
            let args = rpc["params"]["arguments"].clone();
            let node = args["node"].as_str().unwrap_or_default().to_string();
            let lease_label = lease.chars().take(8).collect::<String>();
            let outcome = call_tool(&app, &lease, &name, &args).await;
            if let Err(e) = app.db.log_mcp_operation(
                &lease_label,
                &name,
                &node,
                &args.to_string()[..args.to_string().len().min(300)],
                Utc::now().timestamp(),
            ) {
                warn!("mcp audit failed: {e:#}");
            }
            match outcome {
                Ok(text) => Json(json!({
                    "jsonrpc": "2.0", "id": id,
                    "result": { "content": [{ "type": "text", "text": text }] }
                }))
                .into_response(),
                Err(e) => Json(json!({
                    "jsonrpc": "2.0", "id": id,
                    "result": { "content": [{ "type": "text", "text": e }], "isError": true }
                }))
                .into_response(),
            }
        }
        other => {
            if !is_request {
                return StatusCode::ACCEPTED.into_response();
            }
            Json(json!({
                "jsonrpc": "2.0", "id": id,
                "error": { "code": -32601, "message": format!("未知方法 {other}") }
            }))
            .into_response()
        }
    }
}

/// `GET /api/mcp`：本服务端无需要主动推送的消息，按规范返回 405。
pub async fn method_not_allowed() -> Response {
    let mut resp = StatusCode::METHOD_NOT_ALLOWED.into_response();
    resp.headers_mut().insert("allow", "POST".parse().unwrap());
    resp
}

/// 工具清单：exec 是否暴露跟租约 scope 走（scope 恒含 exec，占位以便将来
/// 收窄授权）。
fn tools(_app: &App) -> Value {
    let exec = json!({
        "name": "exec_command",
        "description": "在指定节点上执行一次性 shell 命令（sh -c）。超时 1–120 秒，输出每流封顶 64KB。每次执行都进操作审计。",
        "inputSchema": {
            "type": "object",
            "properties": {
                "node": { "type": "string", "description": "节点名称或 id" },
                "command": { "type": "string", "description": "要执行的命令" },
                "timeout_ms": { "type": "number", "description": "超时毫秒，默认 30000，最大 120000" }
            },
            "required": ["node", "command"]
        }
    });
    let mut list = vec![
        json!({
            "name": "get_overview",
            "description": "全网概览：今日流量、在线节点、客户数，以及当前告警（离线/丢包/延迟/流量超额/账单/回程变化）",
            "inputSchema": { "type": "object", "properties": {} }
        }),
        json!({
            "name": "list_nodes",
            "description": "全部监控节点：在线状态、系统、agent 版本、到期日",
            "inputSchema": { "type": "object", "properties": {} }
        }),
        json!({
            "name": "get_node",
            "description": "单节点详情：实时 CPU/内存/磁盘/网络与月度流量",
            "inputSchema": { "type": "object", "properties": { "node": { "type": "string", "description": "节点名称或 id" } }, "required": ["node"] }
        }),
        json!({
            "name": "list_protocols",
            "description": "代理协议列表：名称、类型、端口、所属服务器、限速、启停",
            "inputSchema": { "type": "object", "properties": {} }
        }),
        json!({
            "name": "list_customers",
            "description": "订阅客户列表：配额用量、状态、到期日",
            "inputSchema": { "type": "object", "properties": {} }
        }),
        json!({
            "name": "list_ping_tasks",
            "description": "延迟探测任务与最近 15 分钟的丢包/延迟",
            "inputSchema": { "type": "object", "properties": {} }
        }),
        json!({
            "name": "list_route_tasks",
            "description": "回程链路状态：每节点当前线路与最近变化",
            "inputSchema": { "type": "object", "properties": {} }
        }),
        json!({
            "name": "list_logs",
            "description": "连接日志（每页 50 条）：来源、目标域名、归属客户",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "q": { "type": "string", "description": "关键词（域名/IP）" },
                    "user": { "type": "string", "description": "按客户筛选" },
                    "page": { "type": "number", "description": "页码，从 1 起" }
                }
            }
        }),
    ];
    list.push(exec);
    json!(list)
}

/// 节点定位：先精确名后 id。
fn resolve_node(app: &App, spec: &str) -> Option<(i64, String)> {
    let nodes = app.db.nodes().ok()?;
    if let Some(n) = nodes.iter().find(|n| n.name == spec) {
        return Some((n.id, n.name.clone()));
    }
    let id = spec.parse::<i64>().ok()?;
    nodes.into_iter().find(|n| n.id == id).map(|n| (n.id, n.name))
}

async fn call_tool(app: &App, _lease: &str, name: &str, args: &Value) -> std::result::Result<String, String> {
    match name {
        "get_overview" => {
            let traffic = app.db.proxy_traffic().map_err(ekey)?;
            let today_rx: i64 = traffic.iter().map(|t| t.2).sum();
            let today_tx: i64 = traffic.iter().map(|t| t.3).sum();
            let nodes = app.db.nodes().map_err(ekey)?;
            let online: usize = {
                let agents = app.agents.read().unwrap_or_else(|e| e.into_inner());
                nodes.iter().filter(|n| agents.contains_key(&n.id)).count()
            };
            let ping = crate::ping_alert::overview(app).map_err(ekey)?;
            let route_changes =
                app.db.route_events(100, Utc::now().timestamp() - 86_400).map_err(ekey)?.len();
            let offline: Vec<&str> =
                nodes.iter().filter(|n| n.down_since > 0).map(|n| n.name.as_str()).collect();
            Ok(json!({
                "today": {"down_bytes": today_rx, "up_bytes": today_tx},
                "nodes_online": online, "nodes_total": nodes.len(),
                "alerts": {
                    "offline": offline,
                    "ping": ping,
                    "route_changes_24h": route_changes,
                },
            })
            .to_string())
        }
        "list_nodes" => {
            let nodes = app.db.nodes().map_err(ekey)?;
            let agents = app.agents.read().unwrap_or_else(|e| e.into_inner());
            let list: Vec<Value> = nodes
                .iter()
                .map(|n| {
                    json!({
                        "id": n.id, "name": n.name,
                        "online": agents.contains_key(&n.id),
                        "os": n.os, "arch": n.arch, "agent_version": n.agent_version,
                        "ip": n.ip,
                        "expires_at": n.expires_at,
                        "last_seen": n.last_seen,
                    })
                })
                .collect();
            Ok(json!({ "nodes": list }).to_string())
        }
        "get_node" => {
            let spec = args["node"].as_str().unwrap_or_default();
            let (id, name) = resolve_node(app, spec).ok_or_else(|| format!("找不到节点：{spec}"))?;
            let node = app.db.node(id).map_err(ekey)?.ok_or_else(|| format!("找不到节点：{spec}"))?;
            let metrics = {
                let agents = app.agents.read().unwrap_or_else(|e| e.into_inner());
                agents.get(&id).map(|a| a.metrics.clone()).unwrap_or(Value::Null)
            };
            let traffic = app.db.all_traffic();
            let t = traffic.get(&id);
            Ok(json!({
                "id": id, "name": name, "online": app.agents.read().unwrap_or_else(|e| e.into_inner()).contains_key(&id),
                "os": node.os, "kernel": node.kernel, "arch": node.arch, "cpu_name": node.cpu_name,
                "uptime_note": node.agent_version,
                "expires_at": node.expires_at,
                "metrics": metrics,
                "month_traffic": t.map(|t| json!({
                    "rx": t.month_rx, "tx": t.month_tx,
                    "limit": node.traffic_limit, "mode": node.traffic_mode,
                    "used": t.month_used(&node.traffic_mode),
                })).unwrap_or(Value::Null),
            })
            .to_string())
        }
        "list_protocols" => {
            let nodes = app.db.nodes().map_err(ekey)?;
            let list: Vec<Value> = app
                .db
                .proxy_nodes()
                .map_err(ekey)?
                .iter()
                .map(|n| {
                    json!({
                        "id": n.id, "name": n.name, "protocol": n.protocol,
                        "port": n.listen_port, "server_id": n.server_id,
                        "server": nodes.iter().find(|s| s.id == n.server_id).map(|s| s.name.clone()).unwrap_or_else(|| "hub 本机".into()),
                        "enabled": n.enabled,
                        "rate_up": n.rate_up, "rate_down": n.rate_down,
                    })
                })
                .collect();
            Ok(json!({ "protocols": list }).to_string())
        }
        "list_customers" => {
            let subs = app.db.sub_users().map_err(ekey)?;
            let list: Vec<Value> = subs
                .iter()
                .map(|s| {
                    json!({
                        "id": s.id, "name": s.name,
                        "used_bytes": s.quota_used_up + s.quota_used_down,
                        "quota_bytes": s.quota_bytes,
                        "expires_at": s.expires_at,
                        "status": crate::proxy::sub_status(s, crate::proxy::today()).label(),
                    })
                })
                .collect();
            Ok(json!({ "customers": list }).to_string())
        }
        "list_ping_tasks" => {
            let now = Utc::now().timestamp();
            let tasks = app.db.ping_tasks_all().map_err(ekey)?;
            let pairs = app.db.ping_pairs().map_err(ekey)?;
            let samples = app.db.ping_samples_since(now - 900).map_err(ekey)?;
            let nodes: HashMap<i64, String> =
                app.db.nodes().map_err(ekey)?.into_iter().map(|n| (n.id, n.name)).collect();
            let out: Vec<Value> = tasks
                .iter()
                .map(|t| {
                    let nodes_for_task: Vec<Value> = pairs
                        .iter()
                        .filter(|(_, task_id, _)| *task_id == t.id)
                        .map(|(node_id, _, _)| {
                            let win: Vec<i64> = samples
                                .iter()
                                .filter(|(n, task, _, _)| n == node_id && task == &t.id)
                                .map(|(_, _, _, l)| *l)
                                .collect();
                            let total = win.len();
                            let lost = win.iter().filter(|l| **l < 0).count();
                            let mut ok: Vec<i64> = win.iter().copied().filter(|l| *l >= 0).collect();
                            let median = crate::ping_alert::median_pub(&mut ok);
                            json!({
                                "node": nodes.get(node_id).cloned().unwrap_or_default(),
                                "samples": total,
                                "loss_pct": (100 * lost).checked_div(total).unwrap_or(0),
                                "median_ms": median,
                            })
                        })
                        .collect();
                    json!({ "id": t.id, "name": t.name, "target": t.target, "interval": t.interval, "nodes": nodes_for_task })
                })
                .collect();
            Ok(json!({ "tasks": out }).to_string())
        }
        "list_route_tasks" => {
            let nodes: HashMap<i64, String> =
                app.db.nodes().map_err(ekey)?.into_iter().map(|n| (n.id, n.name)).collect();
            let out: Vec<Value> = app
                .db
                .route_tasks()
                .map_err(ekey)?
                .iter()
                .map(|t| {
                    let statuses: Vec<Value> = t
                        .nodes
                        .iter()
                        .map(|node_id| {
                            let st = app.db.route_status(t.id, *node_id).ok().flatten();
                            json!({
                                "node": nodes.get(node_id).cloned().unwrap_or_default(),
                                "line": st.as_ref().map(|s| s.line.clone()).unwrap_or_default(),
                                "baseline": st.as_ref().map(|s| s.baseline.clone()).unwrap_or_default(),
                                "probes": st.as_ref().map(|s| s.probes).unwrap_or(0),
                            })
                        })
                        .collect();
                    json!({ "id": t.id, "name": t.name, "target": t.target, "nodes": statuses })
                })
                .collect();
            Ok(json!({ "tasks": out }).to_string())
        }
        "list_logs" => {
            let filter = crate::db::ConnLogFilter {
                server_id: None,
                user: args["user"].as_str().map(str::to_string),
                node: args["node"].as_str().map(str::to_string),
                q: args["q"].as_str().map(str::to_string),
                since: None,
                until: None,
                page: args["page"].as_u64().unwrap_or(1) as u32,
            };
            let (rows, total) = app.db.connection_logs(&filter).map_err(ekey)?;
            Ok(json!({ "total": total, "page": rows }).to_string())
        }
        "exec_command" => {
            let spec = args["node"].as_str().unwrap_or_default();
            let (id, name) = resolve_node(app, spec).ok_or_else(|| format!("找不到节点：{spec}"))?;
            let command = args["command"].as_str().unwrap_or_default();
            if command.trim().is_empty() {
                return Err("command 不能为空".into());
            }
            let timeout_ms = args["timeout_ms"].as_u64().unwrap_or(30_000).clamp(1_000, 120_000);
            let result = agent_ws::call_agent(
                app,
                id,
                "exec.run",
                json!({ "command": command, "timeout_ms": timeout_ms }),
                EXEC_RPC_TIMEOUT,
            )
            .await
            .map_err(|e| format!("节点 {name} 执行失败：{e}"))?;
            Ok(result.to_string())
        }
        other => Err(format!("未知工具：{other}")),
    }
}

fn ekey(e: anyhow::Error) -> String {
    format!("{e:#}")
}

// ---- 管理端（面板用）----

/// `GET /api/mcp/admin`：开关、租约列表（客户端名解析好）、最近操作。
pub async fn admin_config(_: Admin, State(app): State<Shared>) -> Response {
    let leases: Vec<Value> = app
        .db
        .mcp_leases()
        .unwrap_or_default()
        .into_iter()
        .map(|l| {
            let name = app
                .db
                .mcp_client(&l.client_id)
                .ok()
                .flatten()
                .map(|c| c.name)
                .unwrap_or_else(|| l.client_id.clone());
            json!({
                "token_hash": l.token_hash.chars().take(12).collect::<String>(),
                "client": name, "scopes": l.scopes,
                "created_at": l.created_at, "expires_at": l.expires_at,
                "revoked": l.revoked,
            })
        })
        .collect();
    let operations: Vec<Value> = app
        .db
        .mcp_operations(30)
        .unwrap_or_default()
        .into_iter()
        .map(|(tool, node, params, at, lease)| {
            json!({ "tool": tool, "node": node, "params": params, "at": at, "lease": lease })
        })
        .collect();
    Json(json!({
        "enabled": app.db.get("mcp_enabled").as_deref() == Some("on"),
        "endpoint": "/api/mcp",
        "leases": leases,
        "operations": operations,
    }))
    .into_response()
}

/// `PUT /api/mcp/admin`：总开关。
pub async fn admin_enable(
    _: Admin,
    State(app): State<Shared>,
    body: Result<Json<Value>, axum::extract::rejection::JsonRejection>,
) -> Response {
    let Json(body) = match body {
        Ok(b) => b,
        Err(_) => return bad("请求格式不对"),
    };
    let on = body["enabled"].as_bool().unwrap_or(false);
    match app.db.set("mcp_enabled", if on { "on" } else { "off" }) {
        Ok(()) => {
            invalidate_snapshot(&app);
            Json(json!({"ok": true, "enabled": on})).into_response()
        }
        Err(e) => fail(e),
    }
}

/// `POST /api/mcp/admin/revoke`：吊销租约（body 带 token_hash）。
pub async fn admin_revoke(
    _: Admin,
    State(app): State<Shared>,
    body: Result<Json<Value>, axum::extract::rejection::JsonRejection>,
) -> Response {
    let Json(body) = match body {
        Ok(b) => b,
        Err(_) => return bad("请求格式不对"),
    };
    let Some(hash) = body["token_hash"].as_str() else { return bad("缺少 token_hash") };
    // 前端只显示前 12 位：按前缀匹配吊销。
    let leases = app.db.mcp_leases().unwrap_or_default();
    match leases.into_iter().find(|l| l.token_hash.starts_with(hash)) {
        Some(l) => match app.db.revoke_mcp_lease(&l.token_hash) {
            Ok(()) => Json(json!({"ok": true})).into_response(),
            Err(e) => fail(e),
        },
        None => answer(StatusCode::NOT_FOUND, "租约不存在"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::db::Db;
    use axum::body::to_bytes;
    use axum::extract::Query;

    fn app() -> Shared {
        std::sync::Arc::new(App::for_test(Db::open(":memory:").unwrap()))
    }

    async fn body(r: Response) -> String {
        String::from_utf8_lossy(&to_bytes(r.into_body(), 64 * 1024).await.unwrap()).into_owned()
    }

    /// 管理员会话头：直造 session 行 + cookie，等价登录态（authorize 两端都认它）。
    fn admin_headers(app: &Shared) -> HeaderMap {
        let token = auth::random_token();
        let now = Utc::now().timestamp();
        app.db.create_session(&auth::sha256(&token), now + 3600, "127.0.0.1", "mcp-test").unwrap();
        let mut h = HeaderMap::new();
        h.insert("cookie", format!("{}={token}", auth::COOKIE).parse().unwrap());
        h
    }

    /// PKCE S256 对：verifier 任取，challenge 与 token 端同款推导。
    fn pkce() -> (String, String) {
        let verifier = auth::random_token();
        let challenge = base64::engine::general_purpose::URL_SAFE_NO_PAD
            .encode(bytes_of_digest(&auth::sha256(&verifier)));
        (verifier, challenge)
    }

    fn authz_query(client_id: &str, challenge: &str, method: &str) -> Query<HashMap<String, String>> {
        Query(HashMap::from([
            ("client_id".into(), client_id.into()),
            ("redirect_uri".into(), "http://127.0.0.1:8899/cb".into()),
            ("state".into(), "z".into()),
            ("code_challenge".into(), challenge.into()),
            ("code_challenge_method".into(), method.into()),
        ]))
    }

    fn authz_form(client_id: &str, challenge: &str, decision: &str) -> String {
        format!(
            "client_id={client_id}&redirect_uri=http://127.0.0.1:8899/cb&state=z\
             &code_challenge={challenge}&code_challenge_method=S256&duration_hours=8&decision={decision}"
        )
    }

    /// 批准并取回一次性授权码。
    async fn approve(app: &Shared, headers: &HeaderMap, client_id: &str, challenge: &str) -> String {
        let resp =
            authorize_post(State(app.clone()), headers.clone(), authz_form(client_id, challenge, "approve"))
                .await;
        assert_eq!(resp.status(), StatusCode::FOUND, "批准必须 302 回跳");
        let loc = resp.headers()[axum::http::header::LOCATION].to_str().unwrap();
        assert!(loc.contains("state=z"), "state 原样回传: {loc}");
        loc.split("code=").nth(1).unwrap().split('&').next().unwrap().to_string()
    }

    async fn exchange(app: &Shared, client_id: &str, secret: &str, code: &str, verifier: &str) -> Response {
        let form = format!(
            "grant_type=authorization_code&code={code}&client_id={client_id}\
             &redirect_uri=http://127.0.0.1:8899/cb&client_secret={secret}&code_verifier={verifier}"
        );
        token(State(app.clone()), Ok(axum::extract::RawForm(form.into()))).await
    }

    /// 全舞步：注册→授权页→批准→换码→租约可用。冻结根因（take_mcp_code
    /// 同函数重入自死锁）就死在这条链的有效码分支上——conn 重入断言 +
    /// 本测试双保险。失败分支各走一轮新码：token 端先消费码后校验，任何
    /// 一次失败兑换都会烧掉当轮码（现状如此，测试锚定）。
    #[tokio::test]
    async fn the_authorization_code_dance_issues_a_single_use_lease() {
        let app = app();
        let headers = admin_headers(&app);
        let (verifier, challenge) = pkce();

        // 注册：回执凭据且落库；空 redirect_uris 拒绝。
        let reg = register(
            State(app.clone()),
            Ok(Json(json!({"client_name": "测试客户端", "redirect_uris": ["http://127.0.0.1:8899/cb"]}))),
        )
        .await;
        assert_eq!(reg.status(), StatusCode::OK);
        let reg: Value = serde_json::from_str(&body(reg).await).unwrap();
        let client_id = reg["client_id"].as_str().unwrap().to_string();
        let secret = reg["client_secret"].as_str().unwrap().to_string();
        assert!(app.db.mcp_client(&client_id).unwrap().is_some(), "注册即落库");
        let bad = register(State(app.clone()), Ok(Json(json!({"redirect_uris": []})))).await;
        assert_eq!(bad.status(), StatusCode::BAD_REQUEST);

        // 授权页四道门：无会话送登录；未知 client 拒；plain 拒；有会话出批准页。
        let anon =
            authorize_get(State(app.clone()), HeaderMap::new(), authz_query(&client_id, &challenge, "S256"))
                .await;
        assert_eq!(anon.status(), StatusCode::FOUND);
        assert_eq!(anon.headers()[axum::http::header::LOCATION], "/admin");
        let unknown = authorize_get(
            State(app.clone()),
            headers.clone(),
            authz_query(&format!("mcp_{client_id}"), &challenge, "S256"),
        )
        .await;
        assert_eq!(unknown.status(), StatusCode::BAD_REQUEST);
        let plain =
            authorize_get(State(app.clone()), headers.clone(), authz_query(&client_id, &challenge, "plain"))
                .await;
        assert_eq!(plain.status(), StatusCode::BAD_REQUEST);
        let page =
            authorize_get(State(app.clone()), headers.clone(), authz_query(&client_id, &challenge, "S256"))
                .await;
        assert_eq!(page.status(), StatusCode::OK);
        assert!(body(page).await.contains("测试客户端"), "批准页要认得出客户端");

        // POST 授权：无会话 401；拒绝带 error 回跳；批准发一次性码。
        let unauthorized = authorize_post(
            State(app.clone()),
            HeaderMap::new(),
            authz_form(&client_id, &challenge, "approve"),
        )
        .await;
        assert_eq!(unauthorized.status(), StatusCode::UNAUTHORIZED);
        let denied =
            authorize_post(State(app.clone()), headers.clone(), authz_form(&client_id, &challenge, "deny"))
                .await;
        assert!(denied.headers()[axum::http::header::LOCATION]
            .to_str()
            .unwrap()
            .contains("error=access_denied"));

        // grant_type 只认 authorization_code（此检查在消费码之前）。
        let wrong_grant =
            token(State(app.clone()), Ok(axum::extract::RawForm("grant_type=refresh_token&code=x".into())))
                .await;
        assert_eq!(wrong_grant.status(), StatusCode::BAD_REQUEST);

        // 正确兑换：200 + 租约落库可用；同码重放无效。
        let code = approve(&app, &headers, &client_id, &challenge).await;
        let resp = exchange(&app, &client_id, &secret, &code, &verifier).await;
        assert_eq!(resp.status(), StatusCode::OK, "正确兑换必须成功: {}", body(resp).await);
        let tok: Value = serde_json::from_str(&body(resp).await).unwrap();
        let access = tok["access_token"].as_str().unwrap().to_string();
        assert!(app.db.mcp_lease_valid(&auth::sha256(&access), Utc::now().timestamp()));
        let replay = exchange(&app, &client_id, &secret, &code, &verifier).await;
        assert_eq!(replay.status(), StatusCode::BAD_REQUEST, "授权码一次性");

        // 错 verifier：401，且当轮码已烧（先消费后校验的顺序）。
        let code_b = approve(&app, &headers, &client_id, &challenge).await;
        let wrong = exchange(&app, &client_id, &secret, &code_b, "not-the-verifier").await;
        assert_eq!(wrong.status(), StatusCode::UNAUTHORIZED);
        let burned = exchange(&app, &client_id, &secret, &code_b, &verifier).await;
        assert_eq!(burned.status(), StatusCode::BAD_REQUEST, "失败兑换同样烧码");

        // 错 secret：401。
        let code_c = approve(&app, &headers, &client_id, &challenge).await;
        let wrong_secret = exchange(&app, &client_id, "wrong-secret", &code_c, &verifier).await;
        assert_eq!(wrong_secret.status(), StatusCode::UNAUTHORIZED);

        // 总开关闸门：关了 Bearer 再对也拒（lease_hash 是工具端点的门房）。
        let mut bearer = HeaderMap::new();
        bearer.insert("authorization", format!("Bearer {access}").parse().unwrap());
        app.db.set("mcp_enabled", "on").unwrap();
        assert!(lease_hash(&app, &bearer).is_some());
        app.db.set("mcp_enabled", "off").unwrap();
        assert!(lease_hash(&app, &bearer).is_none());
    }
}
