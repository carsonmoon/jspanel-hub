//! 规则模式来源管理：自定义模板来源与类别集来源、内置项的用户覆盖。
//!
//! 类别集 JSON 兼容妙妙屋 `configs/proxy-groups.json`（数组，元素含
//! name/label/group_label/site_rules[]/ip_rules[]），解析时补默认
//! （path 缺省 ./ruleset/{key}.mrs）。来源是实体：URL 类别源「同步」整体
//! 替换快照、删除来源连带删掉它的类别（订阅里引用的残留 key 渲染时跳过）。
//! 内置 39 预设/24 类保留代码基准，修改存 `conv_builtin_overrides` 覆盖，
//! 删覆盖行即恢复默认。

use anyhow::{bail, Context, Result};
use axum::extract::{Path, State};
use axum::response::{IntoResponse, Response};
use axum::Json;
use serde::Deserialize;
use serde_json::{json, Value};

use crate::api::{bad, fail, Admin};
use crate::db::RuleSource;
use crate::{Shared, Shown};

/// 内置与来源统一的类别视图（build_category_config 的输入）。
#[derive(Clone, Debug, serde::Serialize)]
pub struct CategoryView {
    pub key: String,
    pub label: String,
    /// (provider key, url, path)
    pub site: Vec<(String, String, String)>,
    pub ips: Vec<(String, String, String)>,
    /// true = 来自自定义来源（区别于内置/被覆盖的内置）
    pub custom: bool,
}

/// 统一后的模板预设视图（内置 39 + 自定义来源，key：内置原 key / 自定义 u{id}）。
#[derive(Clone, Debug)]
pub struct PresetView {
    pub key: String,
    pub name: String,
    pub url: String,
    pub kind: String,
    pub builtin: bool,
    /// 内置预设被用户删除（覆盖存 {"deleted":true} 墓碑）；恢复默认即撤销。
    pub deleted: bool,
}

// ---- 类别集 JSON 解析（妙妙屋 proxy-groups.json 兼容）----

#[derive(Deserialize)]
struct RawProvider {
    key: String,
    url: String,
    #[serde(default)]
    path: Option<String>,
}

#[derive(Deserialize)]
struct RawCategory {
    name: String,
    #[serde(default)]
    label: Option<String>,
    #[serde(default)]
    emoji: Option<String>,
    #[serde(default)]
    group_label: Option<String>,
    #[serde(default)]
    site_rules: Vec<RawProvider>,
    #[serde(default)]
    ip_rules: Vec<RawProvider>,
}

fn parse_provider(p: RawProvider, skipped: &mut Vec<String>) -> Option<(String, String, String)> {
    if p.url.is_empty() {
        skipped.push(format!("{}（缺 url）", p.key));
        return None;
    }
    let path = p.path.unwrap_or_else(|| format!("./ruleset/{}.mrs", p.key));
    Some((p.key, p.url, path))
}

/// 类别视图 → 规范 JSON 文本（与解析器同一形态，快照存取用）。
pub(crate) fn categories_to_raw_json(cats: &[CategoryView]) -> String {
    let arr: Vec<Value> = cats
        .iter()
        .map(|c| {
            json!({
                "name": c.key,
                "group_label": c.label,
                "site_rules": c.site.iter().map(|(k, u, p)| json!({"key": k, "url": u, "path": p})).collect::<Vec<_>>(),
                "ip_rules": c.ips.iter().map(|(k, u, p)| json!({"key": k, "url": u, "path": p})).collect::<Vec<_>>(),
            })
        })
        .collect();
    serde_json::to_string(&arr).unwrap_or_else(|_| "[]".into())
}

/// 解析类别集 JSON。宽松：单个坏元素跳过并汇总原因；一个类别都没出才报错。
pub fn parse_categories_json(text: &str) -> Result<Vec<CategoryView>> {
    let raw: Value = serde_json::from_str(text).context("类别集不是有效 JSON")?;
    let arr = raw.as_array().context("类别集 JSON 应为数组（妙妙屋 proxy-groups.json 格式）")?;
    let mut out: Vec<CategoryView> = Vec::new();
    let mut skipped: Vec<String> = Vec::new();
    for el in arr {
        let Ok(rc) = serde_json::from_value::<RawCategory>(el.clone()) else {
            skipped.push("缺 name 的元素".to_string());
            continue;
        };
        let site: Vec<_> =
            rc.site_rules.into_iter().filter_map(|p| parse_provider(p, &mut skipped)).collect();
        let ips: Vec<_> = rc.ip_rules.into_iter().filter_map(|p| parse_provider(p, &mut skipped)).collect();
        if site.is_empty() && ips.is_empty() {
            skipped.push(format!("{}（没有任何规则集）", rc.name));
            continue;
        }
        let label = rc
            .group_label
            .or_else(|| rc.emoji.clone().zip(rc.label.clone()).map(|(e, l)| format!("{e} {l}")))
            .or(rc.label)
            .unwrap_or_else(|| rc.name.clone());
        out.push(CategoryView { key: rc.name, label, site, ips, custom: true });
    }
    if out.is_empty() {
        bail!(
            "没有解析出任何类别：{}",
            if skipped.is_empty() { "空数组".into() } else { skipped.join("；") }
        );
    }
    Ok(out)
}

// ---- 生效集合（内置 + 覆盖 + 来源）----

fn apply_category_override(view: &mut CategoryView, ov: &serde_json::Map<String, Value>) {
    if let Some(Value::String(l)) = ov.get("label") {
        view.label = l.clone();
    }
    let tuples = |arr: Option<&Value>| -> Vec<(String, String, String)> {
        arr.and_then(Value::as_array)
            .map(|list| {
                list.iter()
                    .filter_map(|e| {
                        let a = e.as_array()?;
                        Some((
                            a.first()?.as_str()?.to_string(),
                            a.get(1)?.as_str()?.to_string(),
                            a.get(2)?.as_str()?.to_string(),
                        ))
                    })
                    .collect()
            })
            .unwrap_or_default()
    };
    if let Some(arr) = ov.get("site") {
        view.site = tuples(Some(arr));
    }
    if let Some(arr) = ov.get("ips") {
        view.ips = tuples(Some(arr));
    }
    view.custom = false;
}

/// 内置 24 类（套用用户覆盖）。
pub fn builtin_categories(app: &crate::App) -> Vec<CategoryView> {
    let overrides = app.db.builtin_overrides().unwrap_or_default();
    crate::subscription::RULE_CATEGORIES
        .iter()
        .map(|c| {
            let mut view = c.view();
            if let Some(ov) = overrides
                .iter()
                .find(|(t, _)| t == &format!("cat:{}", c.key))
                .and_then(|(_, v)| v.as_object())
            {
                apply_category_override(&mut view, ov);
            }
            view
        })
        .collect()
}

/// 全部生效类别：内置（含覆盖）+ 各类别源（key 命名空间 `s{id}:{name}`）。
pub fn effective_categories(app: &crate::App) -> Vec<CategoryView> {
    let mut out = builtin_categories(app);
    if let Ok(sources) = app.db.rule_sources("categories") {
        for s in sources {
            if let Ok(cats) = parse_categories_json(&s.data) {
                for mut c in cats {
                    c.key = format!("s{}:{}", s.id, c.key);
                    c.custom = true;
                    out.push(c);
                }
            }
        }
    }
    out
}

/// 按 key 解析生效类别：内置（归一化旧 key + 覆盖）或 `s{id}:name` 来源类别。
/// 来源已删除时返回 None（调用方静默跳过，订阅渲染不炸）。
pub fn resolve_category(app: &crate::App, key: &str) -> Option<CategoryView> {
    let nk = crate::subscription::normalize_category(key);
    if !nk.is_empty() {
        let c = crate::subscription::RULE_CATEGORIES.iter().find(|c| c.key == nk)?;
        let mut view = c.view();
        if let Ok(Some(ov)) = app.db.builtin_override(&format!("cat:{nk}")) {
            if let Some(ov) = ov.as_object() {
                apply_category_override(&mut view, ov);
            }
        }
        return Some(view);
    }
    let rest = key.strip_prefix('s')?;
    let (id, name) = rest.split_once(':')?;
    let id: i64 = id.parse().ok()?;
    let s = app.db.rule_source(id).ok().flatten()?;
    if s.kind != "categories" {
        return None;
    }
    parse_categories_json(&s.data).ok()?.into_iter().find(|c| c.key == name).map(|mut c| {
        c.key = key.to_string();
        c.custom = true;
        c
    })
}

/// 类别 key 是否指向生效类别（内置归一化后命中，或来源命名空间存活）。
pub fn category_key_exists(app: &crate::App, key: &str) -> bool {
    resolve_category(app, key).is_some()
}

/// 内置 39 预设（套用用户覆盖；含已删除墓碑，调用方按需过滤）。
pub fn builtin_presets(app: &crate::App) -> Vec<PresetView> {
    let overrides = app.db.builtin_overrides().unwrap_or_default();
    crate::subscription::TEMPLATE_PRESETS
        .iter()
        .map(|p| {
            let mut v = PresetView {
                key: p.key.to_string(),
                name: p.name.to_string(),
                url: p.url.to_string(),
                kind: p.kind.to_string(),
                builtin: true,
                deleted: false,
            };
            if let Some(ov) = overrides
                .iter()
                .find(|(t, _)| t == &format!("preset:{}", p.key))
                .and_then(|(_, v)| v.as_object())
            {
                if let Some(Value::String(n)) = ov.get("name") {
                    v.name = n.clone();
                }
                if let Some(Value::String(u)) = ov.get("url") {
                    v.url = u.clone();
                }
                if let Some(Value::String(k)) = ov.get("kind") {
                    v.kind = k.clone();
                }
                if let Some(Value::Bool(true)) = ov.get("deleted") {
                    v.deleted = true;
                }
            }
            v
        })
        .collect()
}

/// 全部生效预设：内置（含覆盖，剔除已删除）+ 自定义模板来源（key = `u{id}`）。
pub fn effective_presets(app: &crate::App) -> Vec<PresetView> {
    let mut out: Vec<PresetView> = builtin_presets(app).into_iter().filter(|p| !p.deleted).collect();
    if let Ok(sources) = app.db.rule_sources("template") {
        for s in sources {
            out.push(PresetView {
                key: format!("u{}", s.id),
                name: s.name.clone(),
                url: s.url.clone(),
                kind: "auto".into(),
                builtin: false,
                deleted: false,
            });
        }
    }
    out
}

/// 统一删除预设条目（来源管理 · 预设清单的删除闭环），返回给前端的人读结果描述：
///
/// - `preset:{key}`：内置预设打墓碑覆盖（{"deleted":true}），连带删除已导入的同名模板
///   （否则模板仍作为独立条目留在使用模板下拉，删除不闭环）；
/// - `u{id}`：删除自定义模板来源（kind=template 的 rule_source），下拉同步消失；
/// - `t{id}`：删除上传/导入的模板（内置模板不可删），下拉同步消失。
pub fn delete_preset_source(app: &crate::App, key: &str) -> Result<String> {
    if let Some(preset_key) = key.strip_prefix("preset:") {
        if !crate::subscription::TEMPLATE_PRESETS.iter().any(|p| p.key == preset_key) {
            bail!("未知的内置预设");
        }
        let target = format!("preset:{preset_key}");
        let name = builtin_presets(app)
            .into_iter()
            .find(|p| p.key == preset_key)
            .map(|p| p.name)
            .unwrap_or_default();
        app.db.set_builtin_override(&target, &serde_json::json!({ "deleted": true }))?;
        // 级联：删掉同名已导入模板（导入副本），预设才真正从使用模板下拉消失
        for t in app.db.sub_templates()? {
            if !t.is_builtin && t.name == name {
                app.db.delete_sub_template(t.id)?;
            }
        }
        return Ok(format!("已删除预设「{name}」，可随时在已删除区恢复"));
    }
    if let Some(id) = key.strip_prefix('u').and_then(|s| s.parse::<i64>().ok()) {
        let sources = app.db.rule_sources("template")?;
        let Some(s) = sources.into_iter().find(|s| s.id == id) else {
            bail!("来源不存在");
        };
        app.db.delete_rule_source(id)?;
        return Ok(format!("已删除来源「{}」，使用模板下拉同步移除", s.name));
    }
    if let Some(id) = key.strip_prefix('t').and_then(|s| s.parse::<i64>().ok()) {
        let templates = app.db.sub_templates()?;
        let Some(t) = templates.into_iter().find(|t| t.id == id) else {
            bail!("模板不存在");
        };
        if t.is_builtin {
            bail!("内置模板不可删除");
        }
        app.db.delete_sub_template(id)?;
        return Ok(format!("已删除配置「{}」，使用模板下拉同步移除", t.name));
    }
    bail!("未知的预设条目")
}

/// 按 key 解析生效预设。
pub fn resolve_preset(app: &crate::App, key: &str) -> Option<PresetView> {
    effective_presets(app).into_iter().find(|p| p.key == key)
}

// ---- HTTP 处理器 ----

/// 来源管理 tab 的全部数据：内置类别/预设（含覆盖状态）+ 自定义来源。
pub async fn sources_list(_: Admin, State(app): State<Shared>) -> Response {
    let cats: Vec<Value> = builtin_categories(&app)
        .into_iter()
        .map(|c| {
            json!({
                "key": c.key, "label": c.label, "custom": false,
                "overridden": app.db.builtin_override(&format!("cat:{}", c.key)).ok().flatten().is_some(),
                "site": c.site, "ips": c.ips,
            })
        })
        .collect();
    let templates = app.db.sub_templates().unwrap_or_default();
    let presets: Vec<Value> = builtin_presets(&app)
        .into_iter()
        .map(|p| {
            json!({
                "key": p.key, "name": p.name, "url": p.url, "kind": p.kind,
                "overridden": app.db.builtin_override(&format!("preset:{}", p.key)).ok().flatten().is_some(),
                "deleted": p.deleted,
                "imported": templates.iter().any(|t| !t.is_builtin && t.name == p.name),
            })
        })
        .collect();
    let uploaded: Vec<Value> =
        templates.iter().filter(|t| !t.is_builtin).map(|t| json!({ "id": t.id, "name": t.name })).collect();
    let sources: Vec<Value> = ["categories", "template"]
        .iter()
        .flat_map(|kind| app.db.rule_sources(kind).unwrap_or_default())
        .map(|s| {
            let count = if s.kind == "categories" { parse_categories_json(&s.data).map(|c| c.len()).unwrap_or(0) } else { 0 };
            json!({ "id": s.id, "kind": s.kind, "name": s.name, "url": s.url, "last_sync": s.last_sync, "created_at": s.created_at, "count": count })
        })
        .collect();
    Json(json!({ "builtin_categories": cats, "builtin_presets": presets, "uploaded": uploaded, "sources": sources })).into_response()
}

#[derive(Deserialize)]
pub struct SourceAddBody {
    kind: String,
    name: String,
    #[serde(default)]
    url: String,
    /// 类别源粘贴型：直接给 JSON 文本（与 url 二选一，url 优先）。
    #[serde(default)]
    content: String,
}

/// 添加来源。模板来源：name+url；类别来源：name + url（立即拉取）或 content（粘贴），
/// 解析失败拒绝并给出逐条原因。
pub async fn sources_add(
    _: Admin,
    State(app): State<Shared>,
    body: Result<Json<SourceAddBody>, axum::extract::rejection::JsonRejection>,
) -> Response {
    let Json(body) = match body {
        Ok(b) => b,
        Err(_) => return bad("请求格式不对"),
    };
    let name = body.name.trim();
    if name.is_empty() {
        return bad("来源名称不能为空");
    }
    let kind = body.kind.as_str();
    if !matches!(kind, "template" | "categories") {
        return bad("未知的来源类型");
    }
    let mut s = RuleSource {
        id: 0,
        kind: kind.into(),
        name: name.to_owned(),
        url: body.url.trim().to_owned(),
        data: String::new(),
        last_sync: 0,
        created_at: 0,
    };
    if kind == "template" {
        if s.url.is_empty() {
            return bad("模板来源必须填写 URL");
        }
    } else {
        let (text, source_label) = if !s.url.is_empty() {
            match crate::subscription::fetch_remote(&app, &s.url, "").await {
                Ok((t, _)) => (t, s.url.clone()),
                Err(e) => return fail(e),
            }
        } else if !body.content.trim().is_empty() {
            (body.content.clone(), "粘贴内容".to_string())
        } else {
            return bad("类别来源需要 URL 或粘贴的 JSON");
        };
        let cats = match parse_categories_json(&text) {
            Ok(c) => c,
            Err(e) => return fail(anyhow::Error::msg(Shown(format!("{source_label} 不可用：{e}")))),
        };
        s.data = categories_to_raw_json(&cats);
        s.last_sync = chrono::Utc::now().timestamp();
    }
    match app.db.create_rule_source(&s) {
        Ok(id) => Json(json!({ "id": id })).into_response(),
        Err(e) => fail(e),
    }
}

/// 编辑来源的核心逻辑。模板来源改 name + url（惰性导入不变：下次「加载」按新 URL
/// 拉取）；类别来源只允许改 name——url 与已同步快照 data 耦合，改 URL 请删除重建。
pub fn update_rule_source(app: &crate::App, id: i64, name: &str, url: &str) -> Result<String> {
    let name = name.trim();
    if name.is_empty() {
        bail!("来源名称不能为空");
    }
    let Some(s) = app.db.rule_source(id)? else {
        bail!("来源不存在");
    };
    let url = url.trim();
    if s.kind == "template" {
        if url.is_empty() {
            bail!("模板来源必须填写 URL");
        }
        app.db.update_rule_source(id, name, url)?;
        Ok(format!("已更新来源「{name}」"))
    } else {
        if !url.is_empty() && url != s.url {
            bail!("类别来源不支持修改 URL（与已同步快照耦合），请删除后重新添加");
        }
        app.db.update_rule_source_name(id, name)?;
        Ok(format!("已更新来源「{name}」"))
    }
}

/// 编辑来源（预设清单行内编辑）：模板来源 name+url；类别来源仅 name。
pub async fn source_update(
    _: Admin,
    State(app): State<Shared>,
    Path(id): Path<i64>,
    body: Result<Json<Value>, axum::extract::rejection::JsonRejection>,
) -> Response {
    let Json(body) = match body {
        Ok(b) => b,
        Err(_) => return bad("请求格式不对"),
    };
    let name = body.get("name").and_then(Value::as_str).unwrap_or("");
    let url = body.get("url").and_then(Value::as_str).unwrap_or("");
    match update_rule_source(&app, id, name, url) {
        Ok(msg) => Json(json!({ "ok": true, "message": msg })).into_response(),
        Err(e) => bad(&e.to_string()),
    }
}

/// URL 类别源手动同步：重新拉取并整体替换快照。
pub async fn source_sync(_: Admin, State(app): State<Shared>, Path(id): Path<i64>) -> Response {
    let Some(s) = app.db.rule_source(id).ok().flatten() else { return bad("来源不存在") };
    if s.kind != "categories" {
        return bad("只有类别来源支持同步");
    }
    if s.url.is_empty() {
        return bad("粘贴型来源没有 URL，请删除后重新添加");
    }
    let (text, _) = match crate::subscription::fetch_remote(&app, &s.url, "").await {
        Ok(v) => v,
        Err(e) => return fail(e),
    };
    let cats = match parse_categories_json(&text) {
        Ok(c) => c,
        Err(e) => return fail(anyhow::Error::msg(Shown(format!("同步失败：{e}")))),
    };
    let data = categories_to_raw_json(&cats);
    match app.db.set_rule_source_data(id, &data) {
        Ok(()) => Json(json!({ "ok": true, "count": cats.len() })).into_response(),
        Err(e) => fail(e),
    }
}

/// 模板来源立即导入：拉取 → 按内容分派转换 → 入库（与内置预设同一管线）。
pub async fn source_import(_: Admin, State(app): State<Shared>, Path(id): Path<i64>) -> Response {
    let Some(s) = app.db.rule_source(id).ok().flatten() else { return bad("来源不存在") };
    if s.kind != "template" {
        return bad("只有模板来源支持导入");
    }
    match crate::subscription::import_template_from_url(&app, &s.name, &s.url, "").await {
        Ok((tid, name)) => Json(json!({ "id": tid, "name": name })).into_response(),
        Err(e) => fail(e),
    }
}

/// 删除来源（类别源连带删掉它的全部类别；订阅引用的残留 key 渲染时跳过）。
pub async fn source_delete(_: Admin, State(app): State<Shared>, Path(id): Path<i64>) -> Response {
    match app.db.delete_rule_source(id) {
        Ok(()) => Json(json!({ "ok": true })).into_response(),
        Err(e) => fail(e),
    }
}

/// 保存内置覆盖（target = cat:key | preset:key）。cat 的 value：
/// {label, site: [[key,url,path]..], ips: [[..]]}；preset 的 value：
/// {name, url, kind}。
pub async fn builtin_override_put(
    _: Admin,
    State(app): State<Shared>,
    Path(target): Path<String>,
    body: Result<Json<Value>, axum::extract::rejection::JsonRejection>,
) -> Response {
    let Json(value) = match body {
        Ok(b) => b,
        Err(_) => return bad("请求格式不对"),
    };
    if let Some(key) = target.strip_prefix("cat:") {
        let nk = crate::subscription::normalize_category(key);
        if nk.is_empty() || !crate::subscription::RULE_CATEGORIES.iter().any(|c| c.key == nk) {
            return bad("未知的内置类别");
        }
        let label = value.get("label").and_then(Value::as_str).unwrap_or("").trim().to_owned();
        if label.is_empty() {
            return bad("类别名称不能为空");
        }
        let count = value.get("site").and_then(Value::as_array).map(|a| a.len()).unwrap_or(0)
            + value.get("ips").and_then(Value::as_array).map(|a| a.len()).unwrap_or(0);
        if count == 0 {
            return bad("至少保留一条规则集");
        }
        let target = format!("cat:{nk}");
        return match app.db.set_builtin_override(&target, &value) {
            Ok(()) => Json(json!({ "ok": true })).into_response(),
            Err(e) => fail(e),
        };
    }
    if let Some(key) = target.strip_prefix("preset:") {
        if !crate::subscription::TEMPLATE_PRESETS.iter().any(|p| p.key == key) {
            return bad("未知的内置预设");
        }
        let name = value.get("name").and_then(Value::as_str).unwrap_or("").trim();
        let url = value.get("url").and_then(Value::as_str).unwrap_or("").trim();
        if name.is_empty() || url.is_empty() {
            return bad("预设名称与 URL 不能为空");
        }
        return match app.db.set_builtin_override(&target, &value) {
            Ok(()) => Json(json!({ "ok": true })).into_response(),
            Err(e) => fail(e),
        };
    }
    bad("未知的覆盖目标")
}

/// 删除内置覆盖（恢复代码默认）。对已删除的内置预设，这也是「恢复（撤销删除）」。
pub async fn builtin_override_delete(
    _: Admin,
    State(app): State<Shared>,
    Path(target): Path<String>,
) -> Response {
    match app.db.delete_builtin_override(&target) {
        Ok(removed) => Json(json!({ "ok": true, "removed": removed })).into_response(),
        Err(e) => fail(e),
    }
}

/// 统一删除预设条目（见 [`delete_preset_source`] 的三分支语义）。
pub async fn preset_source_delete(_: Admin, State(app): State<Shared>, Path(key): Path<String>) -> Response {
    match delete_preset_source(&app, &key) {
        Ok(msg) => Json(json!({ "ok": true, "message": msg })).into_response(),
        // 全部分支都是用户输入/资源不存在，400 而非 500
        Err(e) => bad(&e.to_string()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn app() -> crate::App {
        crate::App::for_test(crate::db::Db::open(":memory:").unwrap())
    }

    /// 一条完整、一条坏元素（provider 缺 url）的样例。
    const SAMPLE: &str = r#"[
      {"name":"testcat","label":"🧪 测试类别",
       "site_rules":[{"key":"example","url":"https://example.com/example.mrs"}],
       "ip_rules":[{"key":"example-ip","url":"https://example.com/ip.mrs","path":"./ruleset/ex-ip.mrs"}]},
      {"name":"broken","label":"x","site_rules":[{"key":"no-url"}]}
    ]"#;

    #[test]
    fn categories_json_parses_with_defaults_and_skips() {
        let cats = parse_categories_json(SAMPLE).unwrap();
        assert_eq!(cats.len(), 1, "坏元素应被跳过");
        let c = &cats[0];
        assert_eq!(c.key, "testcat");
        assert_eq!(c.label, "🧪 测试类别");
        // path 缺省按 key 补全；显式 path 保留
        assert_eq!(
            c.site[0],
            (
                "example".to_string(),
                "https://example.com/example.mrs".to_string(),
                "./ruleset/example.mrs".to_string()
            )
        );
        assert_eq!(c.ips[0].2, "./ruleset/ex-ip.mrs");
        assert!(c.custom);
        assert!(parse_categories_json("[]").is_err(), "空数组应报错");
        assert!(parse_categories_json("not json").is_err());
    }

    #[test]
    fn source_crud_effective_merge_and_delete() {
        let app = app();
        let id = app
            .db
            .create_rule_source(&RuleSource {
                id: 0,
                kind: "categories".into(),
                name: "测试源".into(),
                url: String::new(),
                data: categories_to_raw_json(&parse_categories_json(SAMPLE).unwrap()),
                last_sync: 5,
                created_at: 1,
            })
            .unwrap();
        let eff = effective_categories(&app);
        assert_eq!(eff.len(), crate::subscription::RULE_CATEGORIES.len() + 1, "内置 24 + 来源 1");
        let key = format!("s{id}:testcat");
        let c = resolve_category(&app, &key).unwrap();
        assert_eq!(c.label, "🧪 测试类别");
        assert!(category_key_exists(&app, &key));
        assert!(category_key_exists(&app, "ads"));
        // 删除来源后解析消失
        app.db.delete_rule_source(id).unwrap();
        assert!(resolve_category(&app, &key).is_none());
        assert!(!category_key_exists(&app, &key));
    }

    #[test]
    fn builtin_override_changes_and_resets() {
        let app = app();
        app.db
            .set_builtin_override(
                "cat:ads",
                &json!({"label":"🛑 我的广告拦截","site":[["category-ads-all","https://mirror.example/a.mrs","./ruleset/a.mrs"]],"ips":[]}),
            )
            .unwrap();
        let c = resolve_category(&app, "ads").unwrap();
        assert_eq!(c.label, "🛑 我的广告拦截");
        assert_eq!(c.site.len(), 1);
        assert_eq!(c.site[0].1, "https://mirror.example/a.mrs");
        assert!(!c.custom, "覆盖后的内置仍是内置");
        assert!(app.db.delete_builtin_override("cat:ads").unwrap(), "确有覆盖被删");
        let c = resolve_category(&app, "ads").unwrap();
        assert_eq!(c.label, "🛑 广告拦截");
        assert!(c.site[0].1.ends_with("geosite/category-ads-all.mrs"));
    }

    #[test]
    fn presets_effective_with_custom_and_override() {
        let app = app();
        let id = app
            .db
            .create_rule_source(&RuleSource {
                id: 0,
                kind: "template".into(),
                name: "我的来源".into(),
                url: "https://example.com/mine.ini".into(),
                ..Default::default()
            })
            .unwrap();
        let ps = effective_presets(&app);
        assert_eq!(ps.len(), crate::subscription::TEMPLATE_PRESETS.len() + 1);
        let custom = resolve_preset(&app, &format!("u{id}")).unwrap();
        assert_eq!(custom.name, "我的来源");
        assert!(!custom.builtin);
        app.db
            .set_builtin_override(
                "preset:acl4ssr-online-mini",
                &json!({"name":"改名预设","url":"https://example.com/x.ini","kind":"acl4ssr"}),
            )
            .unwrap();
        let p = resolve_preset(&app, "acl4ssr-online-mini").unwrap();
        assert_eq!(p.name, "改名预设");
        assert_eq!(p.url, "https://example.com/x.ini");
    }

    #[test]
    fn preset_delete_tombstone_hides_from_effective_and_restores() {
        let app = app();
        let key = crate::subscription::TEMPLATE_PRESETS[0].key;
        assert!(effective_presets(&app).iter().any(|p| p.key == key), "初始应在生效清单");
        let msg = delete_preset_source(&app, &format!("preset:{key}")).unwrap();
        assert!(msg.contains("已删除"));
        assert!(
            !effective_presets(&app).iter().any(|p| p.key == key),
            "删除后从生效清单（使用模板下拉）消失"
        );
        // 来源管理仍列出（墓碑标记），恢复默认 = 清覆盖 = 撤销删除
        let all = builtin_presets(&app);
        assert!(all.iter().find(|p| p.key == key).unwrap().deleted);
        assert!(app.db.delete_builtin_override(&format!("preset:{key}")).unwrap());
        assert!(effective_presets(&app).iter().any(|p| p.key == key), "恢复后回到生效清单");
        // 覆盖恢复也撤销删除：改名 + 删除 + 清覆盖 → 名字回默认且在清单
        let key2 = crate::subscription::TEMPLATE_PRESETS[1].key;
        app.db
            .set_builtin_override(
                &format!("preset:{key2}"),
                &json!({"name":"改名","url":"https://x/y.ini","kind":"auto"}),
            )
            .unwrap();
        delete_preset_source(&app, &format!("preset:{key2}")).unwrap();
        assert!(!effective_presets(&app).iter().any(|p| p.key == key2));
        app.db.delete_builtin_override(&format!("preset:{key2}")).unwrap();
        let p = resolve_preset(&app, key2).unwrap();
        assert!(effective_presets(&app).iter().any(|q| q.key == key2) && p.name != "改名");
    }

    #[test]
    fn preset_delete_cascades_imported_template_but_keeps_builtin() {
        let app = app();
        let p = &crate::subscription::TEMPLATE_PRESETS[0];
        // 模拟已导入：同名非内置模板 + 一个无关模板 + 内置模板
        let copy = crate::db::SubTemplate {
            name: p.name.to_string(),
            content: "proxies: []".into(),
            ..Default::default()
        };
        let copy_id = app.db.create_sub_template(&copy).unwrap();
        let other_id = app
            .db
            .create_sub_template(&crate::db::SubTemplate {
                name: "别的配置".into(),
                content: "proxies: []".into(),
                ..Default::default()
            })
            .unwrap();
        let builtin_id = app.db.sub_templates().unwrap().iter().find(|t| t.is_builtin).map(|t| t.id).unwrap();
        assert!(app.db.sub_templates().unwrap().iter().any(|t| t.id == copy_id), "前置：同名副本确已建库");
        delete_preset_source(&app, &format!("preset:{}", p.key)).unwrap();
        let left = app.db.sub_templates().unwrap();
        assert!(!left.iter().any(|t| t.id == copy_id), "同名导入副本应被级联删除");
        assert!(left.iter().any(|t| t.id == other_id), "无关模板不受影响");
        assert!(left.iter().any(|t| t.id == builtin_id), "内置模板不受影响");
    }

    #[test]
    fn preset_source_delete_u_and_t_branches_and_guards() {
        let app = app();
        // u{id}：自定义模板来源
        let id = app
            .db
            .create_rule_source(&RuleSource {
                id: 0,
                kind: "template".into(),
                name: "我的来源".into(),
                url: "https://example.com/mine.ini".into(),
                ..Default::default()
            })
            .unwrap();
        assert!(effective_presets(&app).iter().any(|p| p.key == format!("u{id}")));
        let msg = delete_preset_source(&app, &format!("u{id}")).unwrap();
        assert!(msg.contains("我的来源"));
        assert!(!effective_presets(&app).iter().any(|p| p.key == format!("u{id}")));
        // 类别来源不是预设，u{id} 不可删
        let cat_id = app
            .db
            .create_rule_source(&RuleSource {
                id: 0,
                kind: "categories".into(),
                name: "类别源".into(),
                url: String::new(),
                data: "{}".into(),
                ..Default::default()
            })
            .unwrap();
        assert!(delete_preset_source(&app, &format!("u{cat_id}")).is_err(), "类别来源不是预设条目");
        // t{id}：上传模板可删，内置模板不可删
        let tid = app
            .db
            .create_sub_template(&crate::db::SubTemplate {
                name: "上传的配置".into(),
                content: "proxies: []".into(),
                ..Default::default()
            })
            .unwrap();
        let msg = delete_preset_source(&app, &format!("t{tid}")).unwrap();
        assert!(msg.contains("上传的配置"));
        assert!(!app.db.sub_templates().unwrap().iter().any(|t| t.id == tid));
        let builtin_id = app.db.sub_templates().unwrap().iter().find(|t| t.is_builtin).map(|t| t.id).unwrap();
        assert!(delete_preset_source(&app, &format!("t{builtin_id}")).is_err(), "内置模板不可删");
        // 未知 key 一律报错
        assert!(delete_preset_source(&app, "nope").is_err());
        assert!(delete_preset_source(&app, "preset:does-not-exist").is_err());
        assert!(delete_preset_source(&app, "u99999").is_err());
        assert!(delete_preset_source(&app, "t99999").is_err());
    }

    #[test]
    fn source_update_template_edits_flow_into_effective_presets() {
        let app = app();
        let id = app
            .db
            .create_rule_source(&RuleSource {
                id: 0,
                kind: "template".into(),
                name: "旧名".into(),
                url: "https://old/x.ini".into(),
                ..Default::default()
            })
            .unwrap();
        let msg = update_rule_source(&app, id, " 新名 ", "https://new/y.ini").unwrap();
        assert!(msg.contains("新名"));
        let p = resolve_preset(&app, &format!("u{id}")).unwrap();
        assert_eq!(p.name, "新名");
        assert_eq!(p.url, "https://new/y.ini");
        // 守卫：空名 / 空 URL / 来源不存在
        assert!(update_rule_source(&app, id, "", "https://x/y.ini").is_err());
        assert!(update_rule_source(&app, id, "名", "  ").is_err());
        assert!(update_rule_source(&app, 999_999, "名", "https://x/y.ini").is_err());
    }

    #[test]
    fn source_update_categories_rejects_url_change_but_allows_rename() {
        let app = app();
        let id = app
            .db
            .create_rule_source(&RuleSource {
                id: 0,
                kind: "categories".into(),
                name: "类别源".into(),
                url: "https://x/groups.json".into(),
                data: "{}".into(),
                ..Default::default()
            })
            .unwrap();
        assert!(
            update_rule_source(&app, id, "类别源", "https://other/groups.json").is_err(),
            "改 URL 必须拒绝"
        );
        update_rule_source(&app, id, "改名类别源", "").unwrap();
        assert_eq!(app.db.rule_source(id).unwrap().unwrap().name, "改名类别源");
        // url 原样回传（前端编辑框回显现值）时放行，只改名字
        update_rule_source(&app, id, "再改一次", "https://x/groups.json").unwrap();
        let s = app.db.rule_source(id).unwrap().unwrap();
        assert_eq!(s.name, "再改一次");
        assert_eq!(s.url, "https://x/groups.json");
    }
}
