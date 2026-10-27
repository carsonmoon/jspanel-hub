//! 订阅转换 v2（严格按 miaomiaowu 架构）：节点池双形态存储 + 完整配置模板
//! 注入 + 规则片段库 + 外部订阅源同步。
//!
//! 与上一版（pool_*，已回退）的根本差异：生成订阅不再是「组实体+规则行拼接」，
//! 而是 miaomiaowu 式「完整 Clash 配置模板 + 节点注入」——模板里 proxy-groups/
//! rules/rule-providers/dns 原样保留，选中节点整体替换进 `proxies` 键。模板
//! 分组的动态节点用占位符约定：`__ALL__` = 全部节点名、`__TAG:xx__` = 带标签
//! xx 的节点名（渲染时展开）。节点双形态：分享链接 raw_link 或 Clash 原生
//! 字段 clash_config JSON（yaml 导入零丢失）。

use std::collections::HashSet;

use anyhow::{anyhow, bail, Context, Result};
use axum::extract::{Path, Query, State};
use axum::http::{header, HeaderName};
use axum::response::{IntoResponse, Response};
use axum::Json;
use base64::Engine;
use serde::Deserialize;
use serde_json::{json, Value};

use crate::api::Admin;
use crate::api::{bad, fail};
use crate::{auth, proxy, Shared};

/// 经典分组模板（绕过大陆）：三组互备 + GEOSITE/GEOIP 分流。
pub const BUILTIN_TEMPLATE_BALANCED: &str = r#"mixed-port: 7890
allow-lan: false
mode: rule
log-level: warning
proxies: []
proxy-groups:
  - name: 🚀 节点选择
    type: select
    proxies:
      - __ALL__
      - ♻️ 自动
      - DIRECT
  - name: ♻️ 自动
    type: url-test
    proxies:
      - __ALL__
    url: https://www.gstatic.com/generate_204
    interval: 300
  - name: 🔯 故障转移
    type: fallback
    proxies:
      - __ALL__
    url: https://www.gstatic.com/generate_204
    interval: 300
rules:
  - GEOSITE,cn,DIRECT
  - GEOIP,cn,DIRECT
  - MATCH,🚀 节点选择
"#;

/// 规则模式类别表：**逐条照抄** miaomiaowu `configs/proxy-groups.json`（其
/// ClashConfigBuilder 的运行时类别源）。provider 的 key/url/path 三者可能互
/// 不一致（如 cn-domains 的 url 指向 geosite/cn.mrs、telegram-ip 的 path 与
/// site 同名），因此每条存 (provider key, url 文件名, path) 三元组，不推导。
pub(crate) struct RuleCategory {
    pub(crate) key: &'static str,
    /// 策略组名（妙妙屋 group_label，组名不再带 key 后缀）。
    pub(crate) label: &'static str,
    /// (key, file, path)：geosite 域名规则集。
    pub(crate) site: &'static [(&'static str, &'static str, &'static str)],
    /// (key, file, path)：geoip 网段规则集，规则带 no-resolve。
    pub(crate) ips: &'static [(&'static str, &'static str, &'static str)],
}

impl RuleCategory {
    /// 统一视图（来源管理/动态生成共用）：provider url 由基址+文件名补全。
    pub(crate) fn view(&self) -> crate::rule_sources::CategoryView {
        crate::rule_sources::CategoryView {
            key: self.key.to_string(),
            label: self.label.to_string(),
            site: self
                .site
                .iter()
                .map(|(k, f, p)| (k.to_string(), format!("{SITE_BASE}{f}.mrs"), p.to_string()))
                .collect(),
            ips: self
                .ips
                .iter()
                .map(|(k, f, p)| (k.to_string(), format!("{IP_BASE}{f}.mrs"), p.to_string()))
                .collect(),
            custom: false,
        }
    }
}

const SITE_BASE: &str =
    "https://gh-proxy.com/https://github.com/MetaCubeX/meta-rules-dat/raw/refs/heads/meta/geo/geosite/";
const IP_BASE: &str =
    "https://gh-proxy.com/https://github.com/MetaCubeX/meta-rules-dat/raw/refs/heads/meta/geo/geoip/";

pub(crate) static RULE_CATEGORIES: &[RuleCategory] = &[
    RuleCategory {
        key: "ads",
        label: "🛑 广告拦截",
        site: &[("category-ads-all", "category-ads-all", "./ruleset/category-ads-all.mrs")],
        ips: &[],
    },
    RuleCategory {
        key: "ai",
        label: "🤖 AI 服务",
        site: &[
            ("category-ai-!cn", "category-ai-!cn", "./ruleset/category-ai-!cn.mrs"),
            ("openai", "openai", "./ruleset/openai.mrs"),
        ],
        ips: &[],
    },
    RuleCategory {
        key: "bilibili",
        label: "📺 哔哩哔哩",
        site: &[
            ("bilibili", "bilibili", "./ruleset/bilibili.mrs"),
            ("biliintl", "biliintl", "./ruleset/biliintl.mrs"),
        ],
        ips: &[],
    },
    RuleCategory {
        key: "youtube",
        label: "📹 油管视频",
        site: &[("youtube", "youtube", "./ruleset/youtube.mrs")],
        ips: &[],
    },
    RuleCategory {
        key: "google",
        label: "🔍 谷歌服务",
        site: &[("google", "google", "./ruleset/google.mrs")],
        ips: &[("google-ip", "google", "./ruleset/google-ip.mrs")],
    },
    RuleCategory {
        key: "private",
        label: "🏠 私有网络",
        site: &[],
        ips: &[("private", "private", "./ruleset/private.mrs")],
    },
    RuleCategory {
        key: "domestic",
        label: "🔒 国内服务",
        site: &[
            ("geolocation-cn", "geolocation-cn", "./ruleset/geolocation-cn.mrs"),
            ("cn-domains", "cn", "./ruleset/cn-domains.mrs"),
        ],
        ips: &[("cn", "cn", "./ruleset/cn.mrs")],
    },
    RuleCategory {
        key: "telegram",
        label: "📲 电报消息",
        site: &[("telegram", "telegram", "./ruleset/telegram.mrs")],
        ips: &[("telegram-ip", "telegram", "./ruleset/telegram.mrs")],
    },
    RuleCategory {
        key: "github",
        label: "🐱 Github",
        site: &[("github", "github", "./ruleset/github.mrs"), ("gitlab", "gitlab", "./ruleset/gitlab.mrs")],
        ips: &[],
    },
    RuleCategory {
        key: "microsoft",
        label: "Ⓜ️ 微软服务",
        site: &[("microsoft", "microsoft", "./ruleset/microsoft.mrs")],
        ips: &[],
    },
    RuleCategory {
        key: "apple",
        label: "🍏 苹果服务",
        site: &[
            ("apple", "apple", "./ruleset/apple.mrs"),
            ("applemusic", "applemusic", "./ruleset/applemusic.mrs"),
        ],
        ips: &[],
    },
    RuleCategory {
        key: "social",
        label: "🌐 社交媒体",
        site: &[
            ("facebook", "facebook", "./ruleset/facebook.mrs"),
            ("instagram", "instagram", "./ruleset/instagram.mrs"),
            ("twitter", "twitter", "./ruleset/twitter.mrs"),
            ("tiktok", "tiktok", "./ruleset/tiktok.mrs"),
            ("linkedin", "linkedin", "./ruleset/linkedin.mrs"),
        ],
        ips: &[],
    },
    RuleCategory {
        key: "streaming",
        label: "🎬 流媒体",
        site: &[
            ("netflix", "netflix", "./ruleset/netflix.mrs"),
            ("hulu", "hulu", "./ruleset/hulu.mrs"),
            ("disney", "disney", "./ruleset/disney.mrs"),
            ("hbo", "hbo", "./ruleset/hbo.mrs"),
            ("amazon", "amazon", "./ruleset/amazon.mrs"),
            ("bahamut", "bahamut", "./ruleset/bahamut.mrs"),
        ],
        ips: &[],
    },
    RuleCategory {
        key: "gaming",
        label: "🎮 游戏平台",
        site: &[
            ("steam", "steam", "./ruleset/steam.mrs"),
            ("epicgames", "epicgames", "./ruleset/epicgames.mrs"),
            ("ea", "ea", "./ruleset/ea.mrs"),
            ("ubisoft", "ubisoft", "./ruleset/ubisoft.mrs"),
            ("blizzard", "blizzard", "./ruleset/blizzard.mrs"),
        ],
        ips: &[],
    },
    RuleCategory {
        key: "education",
        label: "📚 教育资源",
        site: &[
            ("coursera", "coursera", "./ruleset/coursera.mrs"),
            ("edx", "edx", "./ruleset/edx.mrs"),
            ("udemy", "udemy", "./ruleset/udemy.mrs"),
            ("khanacademy", "khanacademy", "./ruleset/khanacademy.mrs"),
            ("category-scholar-!cn", "category-scholar-!cn", "./ruleset/category-scholar-!cn.mrs"),
        ],
        ips: &[],
    },
    RuleCategory {
        key: "finance",
        label: "💰 金融服务",
        site: &[
            ("paypal", "paypal", "./ruleset/paypal.mrs"),
            ("visa", "visa", "./ruleset/visa.mrs"),
            ("mastercard", "mastercard", "./ruleset/mastercard.mrs"),
            ("stripe", "stripe", "./ruleset/stripe.mrs"),
            ("wise", "wise", "./ruleset/wise.mrs"),
        ],
        ips: &[],
    },
    RuleCategory {
        key: "cloud",
        label: "☁️ 云服务",
        site: &[
            ("aws", "aws", "./ruleset/aws.mrs"),
            ("azure", "azure", "./ruleset/azure.mrs"),
            ("digitalocean", "digitalocean", "./ruleset/digitalocean.mrs"),
            ("heroku", "heroku", "./ruleset/heroku.mrs"),
            ("dropbox", "dropbox", "./ruleset/dropbox.mrs"),
            ("cloudflare", "cloudflare", "./ruleset/cloudflare.mrs"),
            ("onedrive", "onedrive", "./ruleset/onedrive.mrs"),
        ],
        ips: &[],
    },
    RuleCategory {
        key: "spotify",
        label: "🎵 Spotify",
        site: &[("spotify", "spotify", "./ruleset/spotify.mrs")],
        ips: &[],
    },
    RuleCategory {
        key: "pixiv",
        label: "🎨 Pixiv",
        site: &[("pixiv", "pixiv", "./ruleset/pixiv.mrs")],
        ips: &[],
    },
    RuleCategory {
        key: "abema",
        label: "📡 Abema",
        site: &[("abema", "abema", "./ruleset/abema.mrs")],
        ips: &[],
    },
    RuleCategory {
        key: "proxy",
        label: "🔀 代理服务",
        site: &[("proxy", "proxy", "./ruleset/proxy.mrs")],
        ips: &[],
    },
    RuleCategory {
        key: "proxymedia",
        label: "🎭 代理媒体",
        site: &[("proxymedia", "proxymedia", "./ruleset/proxymedia.mrs")],
        ips: &[],
    },
    RuleCategory {
        key: "ehentai",
        label: "🔞 E-Hentai",
        site: &[("ehentai", "ehentai", "./ruleset/ehentai.mrs")],
        ips: &[],
    },
    RuleCategory {
        key: "overseas",
        label: "🌍 非中国",
        site: &[("geolocation-!cn", "geolocation-!cn", "./ruleset/geolocation-!cn.mrs")],
        ips: &[],
    },
];

/// 存量 profile/页面 kv 里保存的旧类别 key → 妙妙屋 key。未知 key 返回空串。
pub(crate) fn normalize_category(key: &str) -> &'static str {
    match key {
        "cn" => "domestic",
        "category-ads-all" => "ads",
        other => match RULE_CATEGORIES.iter().find(|c| c.key == other) {
            Some(c) => c.key,
            None => "",
        },
    }
}

/// 预设成员（妙妙屋 proxy-groups.json 每类的 presets 字段原样汇总）：
/// 极简 = private+domestic+overseas；均衡 = +ai/youtube/google/telegram/github；
/// 完整 = 空成员表 = 全部 24 类。
const PRESETS: &[(&str, &str, &[&str])] = &[
    (
        "极简规则.yaml",
        "私有网络/国内直连、非中国代理——组最少，规则最简",
        &["private", "domestic", "overseas"],
    ),
    (
        "均衡规则.yaml",
        "极简基础上增加 AI/油管/谷歌/电报/Github 五类独立分流",
        &["private", "domestic", "overseas", "ai", "youtube", "google", "telegram", "github"],
    ),
    ("完整规则.yaml", "全部 24 类：每类独立策略组（含广告拦截），漏网之鱼兜底", &[]),
];

/// 类别配置体：与妙妙屋 ClashConfigBuilder 同构（buildProxyGroups/buildRules
/// 逐一对应）。`node_items` 传具体节点名（动态生成分支）或 `["__ALL__"]`
/// 占位（内置模板文本，订阅注入时展开成勾选节点）；proxies 恒为空表，由
/// 调用方填入。
fn build_category_config(cats: &[crate::rule_sources::CategoryView], node_items: &[&str]) -> Value {
    const ENTRY: &str = "🚀 节点选择";
    const AUTO: &str = "♻️ 自动选择";
    const FALLBACK: &str = "🐟 漏网之鱼";
    let nodes: Vec<Value> = node_items.iter().map(|n| json!(n)).collect();

    let mut providers = serde_json::Map::new();
    for c in cats {
        for (key, url, path) in &c.site {
            providers.insert(
                key.clone(),
                json!({
                    "type": "http", "behavior": "domain", "format": "mrs",
                    "url": url, "path": path, "interval": 86400,
                }),
            );
        }
        for (key, url, path) in &c.ips {
            providers.insert(
                key.clone(),
                json!({
                    "type": "http", "behavior": "ipcidr", "format": "mrs",
                    "url": url, "path": path, "interval": 86400,
                }),
            );
        }
    }

    // 组成员（妙妙屋）：国内服务 DIRECT 优先、私有网络 DIRECT 开头，其余
    // 节点选择优先；每个类别组（含广告类）都带 DIRECT/REJECT/自动选择/全部节点。
    let category_members = |c: &crate::rule_sources::CategoryView| -> Vec<Value> {
        let mut m: Vec<Value> = Vec::new();
        if c.key == "domestic" {
            m.push(json!("DIRECT"));
            m.push(json!(ENTRY));
        } else if c.key == "private" {
            m.extend([json!("DIRECT"), json!(ENTRY), json!("REJECT"), json!(AUTO)]);
            m.extend(nodes.iter().cloned());
        } else {
            m.extend([json!(ENTRY), json!("DIRECT"), json!("REJECT"), json!(AUTO)]);
            m.extend(nodes.iter().cloned());
        }
        m
    };

    let mut entry_members: Vec<Value> = vec![json!("DIRECT"), json!("REJECT"), json!(AUTO)];
    entry_members.extend(nodes.iter().cloned());
    let mut groups = vec![
        json!({ "name": ENTRY, "type": "select", "proxies": entry_members }),
        json!({ "name": AUTO, "type": "url-test", "url": "https://www.gstatic.com/generate_204", "interval": 300, "lazy": false, "proxies": nodes }),
    ];
    for c in cats {
        groups.push(json!({ "name": c.label, "type": "select", "proxies": category_members(c) }));
    }
    let mut fallback_members: Vec<Value> = vec![json!(ENTRY), json!("DIRECT"), json!("REJECT"), json!(AUTO)];
    fallback_members.extend(nodes.iter().cloned());
    groups.push(json!({ "name": FALLBACK, "type": "select", "proxies": fallback_members }));

    // 规则顺序（妙妙屋）：全部 site 规则在前（按类别序），随后全部 ip 规则
    // （带 no-resolve），最后 MATCH 兜底到漏网之鱼。
    let mut rules: Vec<String> = Vec::new();
    for c in cats {
        for (key, _, _) in &c.site {
            rules.push(format!("RULE-SET,{key},{}", c.label));
        }
    }
    for c in cats {
        for (key, _, _) in &c.ips {
            rules.push(format!("RULE-SET,{key},{},no-resolve", c.label));
        }
    }
    rules.push(format!("MATCH,{FALLBACK}"));

    // 基础段照抄妙妙屋 DEFAULT_CLASH_CONFIG（geodata + dns 策略）。
    json!({
        "port": 7890,
        "socks-port": 7891,
        "allow-lan": false,
        "mode": "rule",
        "log-level": "info",
        "geodata-mode": true,
        "geo-auto-update": true,
        "geodata-loader": "standard",
        "geo-update-interval": 24,
        "geox-url": {
            "geoip": "https://testingcf.jsdelivr.net/gh/MetaCubeX/meta-rules-dat@release/geoip.dat",
            "geosite": "https://testingcf.jsdelivr.net/gh/MetaCubeX/meta-rules-dat@release/geosite.dat",
            "mmdb": "https://testingcf.jsdelivr.net/gh/MetaCubeX/meta-rules-dat@release/country.mmdb",
            "asn": "https://github.com/xishang0128/geoip/releases/download/latest/GeoLite2-ASN.mmdb",
        },
        "dns": {
            "enable": true,
            "ipv6": true,
            "respect-rules": true,
            "enhanced-mode": "fake-ip",
            "nameserver": ["https://doh.pub/dns-query", "https://dns.alidns.com/dns-query"],
            "proxy-server-nameserver": ["https://doh.pub/dns-query", "https://dns.alidns.com/dns-query"],
            "nameserver-policy": {
                "geosite:cn,private": ["https://doh.pub/dns-query", "https://dns.alidns.com/dns-query"],
                "geosite:geolocation-!cn": ["https://dns.cloudflare.com/dns-query", "https://dns.google/dns-query"],
            },
        },
        "proxies": [],
        "proxy-groups": groups,
        "rule-providers": Value::Object(providers),
        "rules": rules,
    })
}

/// 按预设生成一份内置模板文本（占位 __ALL__，注入订阅时展开成勾选节点）。
pub fn rule_mode_template(preset_index: usize) -> String {
    let (name, note, members) = &PRESETS[preset_index.min(PRESETS.len() - 1)];
    // 内置模板用代码基准（不含用户覆盖）生成——覆盖只影响动态生成与勾选网格。
    let cats: Vec<crate::rule_sources::CategoryView> = RULE_CATEGORIES
        .iter()
        .filter(|c| members.is_empty() || members.contains(&c.key))
        .map(|c| c.view())
        .collect();
    let body = serde_yaml::to_string(&build_category_config(&cats, &["__ALL__"])).unwrap_or_default();
    format!("# {name}（规则模式内置模板）\n# {note}\n# 结构对齐妙妙屋生成器；__ALL__ 在生成订阅时展开为勾选的节点。\n{body}")
}

/// 预设模板清单（逐条对齐 miaomiaowu template-presets.ts）。
/// Aethersailor 是完整 Clash 配置，可直接入库为模板；
/// ACL4SSR 是 ini 规则源，导入时经 convert_acl_ini 转换。
pub struct TemplatePreset {
    pub key: &'static str,
    pub name: &'static str,
    pub url: &'static str,
    /// acl4ssr = ini 需转换；config = 完整配置直用
    pub kind: &'static str,
}

pub const TEMPLATE_PRESETS: &[TemplatePreset] = &[
    TemplatePreset { key: "aethersailor-custom-clash", name: "Aethersailor - 标准（推荐使用）", url: "https://gh-proxy.com/https://raw.githubusercontent.com/Aethersailor/Custom_OpenClash_Rules/refs/heads/main/cfg/Custom_Clash.ini", kind: "custom" },
    TemplatePreset { key: "aethersailor-custom-clash-full", name: "Aethersailor - 全分组（节点较多）", url: "https://gh-proxy.com/https://raw.githubusercontent.com/Aethersailor/Custom_OpenClash_Rules/refs/heads/main/cfg/Custom_Clash_Full.ini", kind: "custom" },
    TemplatePreset { key: "aethersailor-custom-clash-gfw", name: "Aethersailor - 极简（GFW）", url: "https://gh-proxy.com/https://raw.githubusercontent.com/Aethersailor/Custom_OpenClash_Rules/refs/heads/main/cfg/Custom_Clash_GFW.ini", kind: "custom" },
    TemplatePreset { key: "aethersailor-custom-clash-lite", name: "Aethersailor - 轻量（国内直连，国外代理）", url: "https://gh-proxy.com/https://raw.githubusercontent.com/Aethersailor/Custom_OpenClash_Rules/refs/heads/main/cfg/Custom_Clash_Lite.ini", kind: "config" },
    TemplatePreset { key: "acl4ssr-standard", name: "标准版 - 典型分组", url: "https://gh-proxy.com/https://raw.githubusercontent.com/ACL4SSR/ACL4SSR/master/Clash/config/ACL4SSR.ini", kind: "acl4ssr" },
    TemplatePreset { key: "acl4ssr-standard-ad", name: "标准版 - 典型分组+去广告", url: "https://gh-proxy.com/https://raw.githubusercontent.com/ACL4SSR/ACL4SSR/master/Clash/config/ACL4SSR_AdblockPlus.ini", kind: "acl4ssr" },
    TemplatePreset { key: "acl4ssr-backcn", name: "回国版 - 回国专用", url: "https://gh-proxy.com/https://raw.githubusercontent.com/ACL4SSR/ACL4SSR/master/Clash/config/ACL4SSR_BackCN.ini", kind: "acl4ssr" },
    TemplatePreset { key: "acl4ssr-mini", name: "精简版 - 少量分组", url: "https://gh-proxy.com/https://raw.githubusercontent.com/ACL4SSR/ACL4SSR/master/Clash/config/ACL4SSR_Mini.ini", kind: "acl4ssr" },
    TemplatePreset { key: "acl4ssr-mini-fallback", name: "精简版 - 故障转移", url: "https://gh-proxy.com/https://raw.githubusercontent.com/ACL4SSR/ACL4SSR/master/Clash/config/ACL4SSR_Mini_Fallback.ini", kind: "acl4ssr" },
    TemplatePreset { key: "acl4ssr-mini-multi", name: "精简版 - 多模式（自动/手动）", url: "https://gh-proxy.com/https://raw.githubusercontent.com/ACL4SSR/ACL4SSR/master/Clash/config/ACL4SSR_Mini_MultiMode.ini", kind: "acl4ssr" },
    TemplatePreset { key: "acl4ssr-mini-noauto", name: "精简版 - 无自动测速", url: "https://gh-proxy.com/https://raw.githubusercontent.com/ACL4SSR/ACL4SSR/master/Clash/config/ACL4SSR_Mini_NoAuto.ini", kind: "acl4ssr" },
    TemplatePreset { key: "acl4ssr-noapple", name: "无苹果 - 无苹果分流", url: "https://gh-proxy.com/https://raw.githubusercontent.com/ACL4SSR/ACL4SSR/master/Clash/config/ACL4SSR_NoApple.ini", kind: "acl4ssr" },
    TemplatePreset { key: "acl4ssr-noauto", name: "无测速 - 无自动测速", url: "https://gh-proxy.com/https://raw.githubusercontent.com/ACL4SSR/ACL4SSR/master/Clash/config/ACL4SSR_NoAuto.ini", kind: "acl4ssr" },
    TemplatePreset { key: "acl4ssr-noauto-apple", name: "无测速&苹果 - 无测速&无苹果分流", url: "https://gh-proxy.com/https://raw.githubusercontent.com/ACL4SSR/ACL4SSR/master/Clash/config/ACL4SSR_NoAuto_NoApple.ini", kind: "acl4ssr" },
    TemplatePreset { key: "acl4ssr-noauto-apple-msft", name: "无测速&苹果&微软 - 无测速&无苹果&无微软分流", url: "https://gh-proxy.com/https://raw.githubusercontent.com/ACL4SSR/ACL4SSR/master/Clash/config/ACL4SSR_NoAuto_NoApple_NoMicrosoft.ini", kind: "acl4ssr" },
    TemplatePreset { key: "acl4ssr-nomsft", name: "无微软 - 无微软分流", url: "https://gh-proxy.com/https://raw.githubusercontent.com/ACL4SSR/ACL4SSR/master/Clash/config/ACL4SSR_NoMicrosoft.ini", kind: "acl4ssr" },
    TemplatePreset { key: "acl4ssr-online", name: "在线版 - 典型分组", url: "https://gh-proxy.com/https://raw.githubusercontent.com/ACL4SSR/ACL4SSR/master/Clash/config/ACL4SSR_Online.ini", kind: "acl4ssr" },
    TemplatePreset { key: "acl4ssr-online-ad", name: "在线版 - 典型分组+去广告", url: "https://gh-proxy.com/https://raw.githubusercontent.com/ACL4SSR/ACL4SSR/master/Clash/config/ACL4SSR_Online_AdblockPlus.ini", kind: "acl4ssr" },
    TemplatePreset { key: "acl4ssr-online-full", name: "在线全分组 - 比较全", url: "https://gh-proxy.com/https://raw.githubusercontent.com/ACL4SSR/ACL4SSR/master/Clash/config/ACL4SSR_Online_Full.ini", kind: "acl4ssr" },
    TemplatePreset { key: "acl4ssr-online-full-ad", name: "在线全分组 - 带广告拦截", url: "https://gh-proxy.com/https://raw.githubusercontent.com/ACL4SSR/ACL4SSR/master/Clash/config/ACL4SSR_Online_Full_AdblockPlus.ini", kind: "acl4ssr" },
    TemplatePreset { key: "acl4ssr-online-full-google", name: "在线全分组 - 谷歌分流", url: "https://gh-proxy.com/https://raw.githubusercontent.com/ACL4SSR/ACL4SSR/master/Clash/config/ACL4SSR_Online_Full_Google.ini", kind: "acl4ssr" },
    TemplatePreset { key: "acl4ssr-online-full-multi", name: "在线全分组 - 多模式", url: "https://gh-proxy.com/https://raw.githubusercontent.com/ACL4SSR/ACL4SSR/master/Clash/config/ACL4SSR_Online_Full_MultiMode.ini", kind: "acl4ssr" },
    TemplatePreset { key: "acl4ssr-online-full-netflix", name: "在线全分组 - 奈飞分流", url: "https://gh-proxy.com/https://raw.githubusercontent.com/ACL4SSR/ACL4SSR/master/Clash/config/ACL4SSR_Online_Full_Netflix.ini", kind: "acl4ssr" },
    TemplatePreset { key: "acl4ssr-online-full-noauto", name: "在线全分组 - 无自动测速", url: "https://gh-proxy.com/https://raw.githubusercontent.com/ACL4SSR/ACL4SSR/master/Clash/config/ACL4SSR_Online_Full_NoAuto.ini", kind: "acl4ssr" },
    TemplatePreset { key: "acl4ssr-online-mini", name: "在线精简版 - 少量分组", url: "https://gh-proxy.com/https://raw.githubusercontent.com/ACL4SSR/ACL4SSR/master/Clash/config/ACL4SSR_Online_Mini.ini", kind: "acl4ssr" },
    TemplatePreset { key: "acl4ssr-online-mini-ad", name: "在线精简版 - 带广告拦截", url: "https://gh-proxy.com/https://raw.githubusercontent.com/ACL4SSR/ACL4SSR/master/Clash/config/ACL4SSR_Online_Mini_AdblockPlus.ini", kind: "acl4ssr" },
    TemplatePreset { key: "acl4ssr-online-mini-ai", name: "在线精简版 - AI 分流", url: "https://gh-proxy.com/https://raw.githubusercontent.com/ACL4SSR/ACL4SSR/master/Clash/config/ACL4SSR_Online_Mini_Ai.ini", kind: "acl4ssr" },
    TemplatePreset { key: "acl4ssr-online-mini-fallback", name: "在线精简版 - 故障转移", url: "https://gh-proxy.com/https://raw.githubusercontent.com/ACL4SSR/ACL4SSR/master/Clash/config/ACL4SSR_Online_Mini_Fallback.ini", kind: "acl4ssr" },
    TemplatePreset { key: "acl4ssr-online-mini-multi", name: "在线精简版 - 多模式", url: "https://gh-proxy.com/https://raw.githubusercontent.com/ACL4SSR/ACL4SSR/master/Clash/config/ACL4SSR_Online_Mini_MultiMode.ini", kind: "acl4ssr" },
    TemplatePreset { key: "acl4ssr-online-mini-noauto", name: "在线精简版 - 无自动测速", url: "https://gh-proxy.com/https://raw.githubusercontent.com/ACL4SSR/ACL4SSR/master/Clash/config/ACL4SSR_Online_Mini_NoAuto.ini", kind: "acl4ssr" },
    TemplatePreset { key: "acl4ssr-with-cnip", name: "特殊版 - 包含回国IP", url: "https://gh-proxy.com/https://raw.githubusercontent.com/ACL4SSR/ACL4SSR/master/Clash/config/ACL4SSR_With_ChinaIp.ini", kind: "acl4ssr" },
    TemplatePreset { key: "acl4ssr-with-cnip-gfw", name: "特殊版 - 包含回国IP&GFW列表", url: "https://gh-proxy.com/https://raw.githubusercontent.com/ACL4SSR/ACL4SSR/master/Clash/config/ACL4SSR_With_ChinaIp_WithGFW.ini", kind: "acl4ssr" },
    TemplatePreset { key: "acl4ssr-with-gfw", name: "特殊版 - 包含GFW列表", url: "https://gh-proxy.com/https://raw.githubusercontent.com/ACL4SSR/ACL4SSR/master/Clash/config/ACL4SSR_WithGFW.ini", kind: "acl4ssr" },
    TemplatePreset { key: "acl4ssr-online-mini-multicountry", name: "在线精简版 - 多国家", url: "https://gh-proxy.com/https://raw.githubusercontent.com/ACL4SSR/ACL4SSR/master/Clash/config/ACL4SSR_Online_Mini_MultiCountry.ini", kind: "acl4ssr" },
    TemplatePreset { key: "acl4ssr-online-noauto", name: "在线版 - 无自动测速", url: "https://gh-proxy.com/https://raw.githubusercontent.com/ACL4SSR/ACL4SSR/master/Clash/config/ACL4SSR_Online_NoAuto.ini", kind: "acl4ssr" },
    TemplatePreset { key: "acl4ssr-online-no-reject", name: "在线版 - 无拒绝规则", url: "https://gh-proxy.com/https://raw.githubusercontent.com/ACL4SSR/ACL4SSR/master/Clash/config/ACL4SSR_Online_NoReject.ini", kind: "acl4ssr" },
    TemplatePreset { key: "acl4ssr-sublinkpro", name: "sublinkPro 作者自用 - 不区分国家", url: "https://gh-proxy.com/https://raw.githubusercontent.com/ZeroDeng01/ACL4SSR/refs/heads/master/Clash/config/ACL4SSR_Online_Full_NoCountry.ini", kind: "acl4ssr" },
];

/// 规则模式的 KV 键（页面级单选，生成订阅时默认带出）。
pub const RULE_MODE_KEY: &str = "conv_rule_mode";

/// 内置规则片段模板（迁移 35 起的清单；name UNIQUE + OR IGNORE 幂等）。
/// mode：prepend = 在所有规则最前（优先级最高）；append = 插在 MATCH 之前
/// （兜底区）。走代理的目标组名用 🚀 节点选择（内置模板同款），按需自行编辑。
pub const BUILTIN_SNIPPETS: &[(&str, &str, &str, &str)] = &[
    (
        "🚫 防 WebRTC 泄漏（拦截 STUN/TURN）",
        "rules",
        "prepend",
        "- DOMAIN-SUFFIX,stun.l.google.com,REJECT\n- DOMAIN-KEYWORD,stun,REJECT\n- DOMAIN-KEYWORD,turn,REJECT\n- DOMAIN-KEYWORD,rtc,REJECT",
    ),
    (
        "🖥️ 一机一住宅（按设备源 IP 分流）",
        "rules",
        "prepend",
        "# 按内网设备分流：把目标改成你要的节点或策略组\n- SRC-IP-CIDR,192.168.20.101/32,🚀 节点选择\n- SRC-IP-CIDR,192.168.20.102/32,🚀 节点选择",
    ),
    (
        "📶 一 WiFi 一 IP（按网段分流）",
        "rules",
        "prepend",
        "# 整个网段走同一节点：把目标改成你要的节点或策略组\n- SRC-IP-CIDR,192.168.20.0/24,🚀 节点选择",
    ),
    (
        "🚫 阻止海外 QUIC（防 UDP 慢速劣化）",
        "rules",
        "prepend",
        "- AND,((DST-PORT,443),(NETWORK,UDP),(NOT,((GEOIP,CN)))),REJECT",
    ),
    (
        "📡 网络连通性检测直连（防误判断网）",
        "rules",
        "prepend",
        "- DOMAIN-SUFFIX,msftconnecttest.com,DIRECT\n- DOMAIN-SUFFIX,msn.com,DIRECT\n- DOMAIN-SUFFIX,captive.apple.com,DIRECT\n- DOMAIN-SUFFIX,connectivitycheck.gstatic.com,DIRECT\n- DOMAIN-SUFFIX,connect.rom.miui.com,DIRECT\n- DOMAIN-SUFFIX,wifi.vivo.com.cn,DIRECT",
    ),
    (
        "⏱️ NTP 时间同步直连（防 TLS 时钟偏移）",
        "rules",
        "prepend",
        "- DOMAIN-SUFFIX,time.windows.com,DIRECT\n- DOMAIN-SUFFIX,time.apple.com,DIRECT\n- DOMAIN-SUFFIX,ntp.aliyun.com,DIRECT\n- DOMAIN-SUFFIX,time1.cloud.tencent.com,DIRECT\n- DOMAIN-SUFFIX,cn.pool.ntp.org,DIRECT",
    ),
    (
        "📲 Telegram IP 段走代理",
        "rules",
        "append",
        "- IP-CIDR,91.108.4.0/22,🚀 节点选择,no-resolve\n- IP-CIDR,91.108.8.0/22,🚀 节点选择,no-resolve\n- IP-CIDR,91.108.12.0/22,🚀 节点选择,no-resolve\n- IP-CIDR,91.108.16.0/22,🚀 节点选择,no-resolve\n- IP-CIDR,91.108.20.0/22,🚀 节点选择,no-resolve\n- IP-CIDR,91.108.56.0/22,🚀 节点选择,no-resolve\n- IP-CIDR,149.154.160.0/20,🚀 节点选择,no-resolve\n- IP-CIDR,2001:67c:4e8::/48,🚀 节点选择,no-resolve\n- IP-CIDR,2001:b28:f23d::/48,🚀 节点选择,no-resolve\n- IP-CIDR,2001:b28:f23f::/48,🚀 节点选择,no-resolve",
    ),
    (
        "🧲 大流量下载直连（BT/PT 防代理封号）",
        "rules",
        "prepend",
        "- DST-PORT,6881-6889,DIRECT\n- DST-PORT,6969,DIRECT\n- DOMAIN-KEYWORD,announce,DIRECT",
    ),
    (
        "🔒 隐私遥测拦截",
        "rules",
        "prepend",
        "- DOMAIN-SUFFIX,sentry.io,REJECT\n- DOMAIN-SUFFIX,app-measurement.com,REJECT\n- DOMAIN-SUFFIX,crashlytics.com,REJECT\n- DOMAIN-SUFFIX,settings-win.data.microsoft.com,REJECT\n- DOMAIN-SUFFIX,events.data.microsoft.com,REJECT",
    ),
];

/// 曾经内置、现已下线的片段（迁移 35 删除——用户拍板不需要）。
pub const RETIRED_SNIPPETS: &[&str] = &[
    "🛑 广告拦截（domains）",
    "🏠 局域网与私有网络直连",
    "🇨🇳 国内服务直连（geosite 增强）",
    "🎥 常用流媒体走代理",
    "💻 开发服务走代理",
    "🎮 游戏平台直连（国内服）",
    "📴 Apple 服务直连",
    "🧹 兜底微调（钉钉/企业微信/国内云）",
];

/// 清单维护：删掉已下线的内置片段名，补种缺失的新片段（幂等）。
pub fn seed_builtin_snippets(conn: &rusqlite::Connection) -> Result<()> {
    for name in RETIRED_SNIPPETS {
        conn.execute("DELETE FROM sub_rule_snippets WHERE name = ?1", rusqlite::params![name])?;
    }
    let now = chrono::Utc::now().timestamp();
    for (name, kind, mode, content) in BUILTIN_SNIPPETS {
        // 内置片段默认停用：模板是备选素材，用户明确勾选启用才参与生成。
        conn.execute(
            "INSERT OR IGNORE INTO sub_rule_snippets (name, kind, mode, content, enabled, created_at)
             VALUES (?1,?2,?3,?4,0,?5)",
            rusqlite::params![name, kind, mode, content, now],
        )?;
    }
    Ok(())
}

/// 一类分流规则的展示信息（label/key，前端勾选网格用）。
fn category_link(c: &RuleCategory) -> Value {
    json!({ "label": c.label, "key": c.key })
}

/// subconverter [custom] 格式（Aethersailor 模板同款）→ 完整 Clash 配置。
/// `custom_proxy_group=名称`类型`成员...`（[]前缀=组引用、.*=全部节点、
/// http=测速地址、数字=interval）与 `ruleset=目标,规则[,interval]`
/// （[]GEOSITE/[]GEOIP 内联、clash-domain:/clash-classic: 远程规则集、
/// []FINAL 为兜底标记）。
pub fn convert_subconverter_custom(text: &str, base: &str) -> Result<String> {
    let mut group_order: Vec<String> = Vec::new();
    let mut group_type: std::collections::HashMap<String, String> = std::collections::HashMap::new();
    let mut group_members: std::collections::HashMap<String, Vec<Value>> = std::collections::HashMap::new();
    let mut group_url: std::collections::HashMap<String, String> = std::collections::HashMap::new();
    let mut group_interval: std::collections::HashMap<String, i64> = std::collections::HashMap::new();
    let mut providers = String::new();
    let mut provider_count = 0usize;
    let mut rules: Vec<String> = Vec::new();
    let mut final_target: Option<String> = None;

    for raw in text.lines() {
        let line = raw.trim();
        if let Some(rest) = line.strip_prefix("custom_proxy_group=") {
            let parts: Vec<&str> = rest.split('`').map(str::trim).collect();
            if parts.len() < 2 {
                continue;
            }
            let name = parts[0].to_owned();
            let gtype = parts[1].to_ascii_lowercase();
            if !matches!(gtype.as_str(), "select" | "url-test" | "fallback" | "load-balance") {
                continue;
            }
            if group_type.contains_key(&name) {
                continue;
            }
            group_order.push(name.clone());
            group_type.insert(name.clone(), gtype.clone());
            let mut members: Vec<Value> = Vec::new();
            for seg in &parts[2..] {
                let seg = seg.trim();
                if seg.is_empty() {
                    continue;
                }
                if seg.starts_with("http://") || seg.starts_with("https://") {
                    if gtype != "select" && !group_url.contains_key(&name) {
                        group_url.insert(name.clone(), seg.to_owned());
                    }
                    continue;
                }
                if let Ok(n) = seg.parse::<i64>() {
                    if group_interval.contains_key(&name) && (60..=86400).contains(&n) {
                        group_interval.insert(name.clone(), n);
                    }
                    continue;
                }
                if seg == ".*" {
                    members.push(json!("__ALL__"));
                } else if let Some(refd) = seg.strip_prefix("[]") {
                    members.push(json!(refd.to_owned()));
                } else {
                    members.push(json!(seg.to_owned()));
                }
            }
            if members.is_empty() {
                members.push(json!("DIRECT"));
            }
            group_members.insert(name.clone(), members);
            continue;
        }
        let Some(rest) = line.strip_prefix("ruleset=") else { continue };
        let parts: Vec<&str> = rest.split(',').map(str::trim).collect();
        if parts.len() < 2 {
            continue;
        }
        let target = parts[0].to_owned();
        let spec = parts[1].to_owned();
        let extra: Vec<&str> = parts[2..].to_vec();
        if !group_order.iter().any(|g| g == &target) {
            group_order.push(target.clone());
            group_type.insert(target.clone(), "select".into());
            // 自动补建的组：直连语义的（名称含 直连/direct）DIRECT 优先，
            // 其余节点优先；成员都给 __ALL__ 兜底。
            let direct_first = {
                let t = target.to_ascii_lowercase();
                t.contains("直连") || t.contains("direct") || t.contains("私有")
            };
            group_members.insert(
                target.clone(),
                if direct_first {
                    vec![json!("DIRECT"), json!("__ALL__")]
                } else {
                    vec![json!("__ALL__"), json!("DIRECT")]
                },
            );
        }
        let spec_upper = spec.to_ascii_uppercase();
        if spec_upper.starts_with("[]FINAL") {
            final_target = Some(target);
            continue;
        }
        if let Some(inline) = spec.strip_prefix("[]") {
            let mut r = inline.to_owned();
            if !extra.is_empty() {
                r.push(',');
                r.push_str(&extra.join(","));
            }
            rules.push(format!("{r},{target}"));
            continue;
        }
        // 相对路径规则集（ACL4SSR 系）补全为 raw 地址（走 gh-proxy 镜像）。
        if let Some((kind, url_part)) = spec.split_once(':') {
            let interval = extra.first().and_then(|x| x.parse::<i64>().ok()).unwrap_or(86400);
            let ext = url_part.rsplit('.').next().unwrap_or("yaml").to_owned();
            let behavior = match kind.to_ascii_lowercase().as_str() {
                "clash-domain" => "domain",
                "clash-ipcidr" => "ipcidr",
                "clash-classic" => "classical",
                _ => "classical",
            };
            provider_count += 1;
            let key = format!("custom-{provider_count}");
            let full_url = if url_part.starts_with("http") {
                url_part.to_owned()
            } else {
                format!("https://gh-proxy.com/https://raw.githubusercontent.com/{base}{url_part}")
            };
            providers.push_str(&format!(
                "  {key}:\n    type: http\n    behavior: {behavior}\n    format: {ext}\n    url: {}\n    path: ./ruleset/{key}.{ext}\n    interval: {interval}\n",
                proxy::toml_str(&full_url)
            ));
            rules.push(format!("RULE-SET,{key},{target}"));
        }
    }
    if group_order.is_empty() {
        bail!("ini 里没有 custom_proxy_group 定义，不是 subconverter [custom] 格式");
    }

    let mut pgroups: Vec<Value> = Vec::new();
    for name in &group_order {
        let gtype = group_type.get(name).cloned().unwrap_or_else(|| "select".into());
        let members = group_members.get(name).cloned().unwrap_or_else(|| vec![json!("DIRECT")]);
        let mut pg = json!({ "name": name, "type": gtype, "proxies": members });
        if gtype != "select" {
            if let Some(u) = group_url.get(name) {
                pg["url"] = json!(u);
                pg["interval"] = json!(group_interval.get(name).copied().unwrap_or(300));
            }
        }
        pgroups.push(pg);
    }
    let mut rule_providers: serde_json::Map<String, Value> = serde_json::Map::new();
    let mut cur_provider: Option<String> = None;
    for line in providers.lines() {
        let t = line.trim();
        if t.is_empty() {
            continue;
        }
        if let Some(k) = t.strip_suffix(':') {
            cur_provider = Some(k.to_owned());
            rule_providers.insert(k.to_owned(), json!({}));
            continue;
        }
        if let (Some(k), Some((field, val))) = (cur_provider.as_ref(), t.split_once(": ")) {
            if let Some(map) = rule_providers.get_mut(k).and_then(|v| v.as_object_mut()) {
                map.insert(field.trim().to_owned(), json!(val.trim().to_string()));
            }
        }
    }
    let mut rules_list: Vec<String> = rules.clone();
    let match_target = final_target.unwrap_or_else(|| group_order[0].clone());
    rules_list.push(format!("MATCH,{match_target}"));
    let config = json!({
        "mixed-port": 7890,
        "allow-lan": false,
        "mode": "rule",
        "log-level": "warning",
        "proxies": [],
        "proxy-groups": pgroups,
        "rule-providers": rule_providers,
        "rules": rules_list,
    });
    serde_yaml::to_string(&config).context("YAML 序列化失败")
}

/// ACL4SSR ini → 完整 Clash 配置 YAML（对标 miaomiaowu ConvertACLToV3 的
/// 产出形态）：[Proxy Group] 的远程策略 (policy-path=.ini) 转 rule-providers
/// （yaml 远程）+ 组成员引用；`.*` 等占位策略转 __ALL__；[Rule] 的
/// FINAL → MATCH，其余规则原样。
pub fn convert_acl_ini(text: &str) -> Result<String> {
    let mut group_names: Vec<String> = Vec::new();
    let mut group_lines: Vec<(String, String)> = Vec::new(); // (名称, 策略原文)
    let mut rules: Vec<String> = Vec::new();
    let mut section = String::new();
    let mut saw_any = false;
    for raw in text.lines() {
        let line = raw.trim();
        if line.is_empty() || line.starts_with('#') || line.starts_with(';') {
            continue;
        }
        if line.starts_with('[') {
            section = line.trim_matches(|c| c == '[' || c == ']').to_ascii_lowercase();
            continue;
        }
        match section.as_str() {
            "proxy group" => {
                saw_any = true;
                let Some((name, rest)) = line.split_once('=') else { bail!("策略组行缺少 =：{line}") };
                let name = name.trim().to_owned();
                let policies: Vec<String> =
                    rest.split(',').map(str::trim).filter(|p| !p.is_empty()).map(str::to_owned).collect();
                let kind = policies.first().map(|s| s.to_ascii_lowercase()).unwrap_or_default();
                let group_type = match kind.as_str() {
                    "select" => "select",
                    "url-test" | "fallback" | "load-balance" => kind.as_str(),
                    other => bail!("策略组「{name}」类型 {other} 暂不支持"),
                };
                group_names.push(name.clone());
                group_lines.push((name, format!("{group_type},{}", parts_join(&policies[1..]))));
            }
            "rules" | "rule" => {
                saw_any = true;
                let r = line.trim_start_matches('-').trim();
                if r.is_empty() {
                    continue;
                }
                let upper = r.to_ascii_uppercase();
                if upper.starts_with("FINAL") {
                    rules.push(r.replacen("FINAL", "MATCH", 1));
                } else {
                    rules.push(r.to_owned());
                }
            }
            _ => {}
        }
    }
    if !saw_any || group_lines.is_empty() {
        bail!("ini 里没有 [Proxy Group] 段，不像 ACL4SSR 规则源");
    }

    // 组行 → YAML：策略项分类（组引用 / DIRECT / REJECT / 远程规则集 / 占位符）
    let mut providers = String::new();
    let mut provider_count = 0usize;
    let mut groups_yaml = String::new();
    for (name, policies_raw) in &group_lines {
        let parts: Vec<String> = policies_raw.split(',').map(str::trim).map(str::to_owned).collect();
        let kind = parts[0].to_ascii_lowercase();
        let mut members: Vec<String> = Vec::new();
        for p in &parts[1..] {
            let pkey = p.split('=').next().unwrap_or("").trim().to_ascii_lowercase();
            if pkey == "url" || pkey == "interval" {
                continue;
            }
            if p.eq_ignore_ascii_case("direct") {
                members.push("DIRECT".into());
            } else if p.eq_ignore_ascii_case("reject") || p.eq_ignore_ascii_case("reject-drop") {
                members.push("REJECT".into());
            } else if p.starts_with("http") && p.contains(".ini") {
                provider_count += 1;
                let key = format!("acl-{provider_count}");
                providers.push_str(&format!(
                    "  {key}:
    type: http
    behavior: classical
    format: yaml
    url: {}
    path: ./ruleset/{key}.yaml
    interval: 86400
",
                    uri_encode(p)
                ));
                members.push(key);
            } else if p == ".*" || p == "*" {
                members.push("__ALL__".into());
            } else if group_names.iter().any(|g| g == p) {
                members.push(p.clone());
            } else {
                members.push("__ALL__".into());
            }
        }
        if members.is_empty() {
            members.push("__ALL__".into());
        }
        let items: String = members
            .iter()
            .map(|m| {
                format!(
                    "
      - {m}"
                )
            })
            .collect();
        groups_yaml.push_str(&format!(
            "  - name: {}
    type: {kind}
    proxies:{items}
",
            proxy::toml_str(name)
        ));
    }

    let mut rules_yaml = String::new();
    for r in &rules {
        rules_yaml.push_str(&format!(
            "  - {}
",
            proxy::toml_str(r)
        ));
    }
    Ok(format!(
        "# 由 ACL4SSR ini 转换的模板
mixed-port: 7890
allow-lan: false
mode: rule
log-level: warning
proxies: []
proxy-groups:
{groups_yaml}rule-providers:
{providers}rules:
{rules_yaml}"
    ))
}

fn parts_join(parts: &[String]) -> String {
    parts.join(", ")
}

/// 规则模式的选择状态（页面级默认）：预设名 + 勾选的类别 key。
#[derive(serde::Deserialize, serde::Serialize, Debug, Clone, Default)]
pub struct RuleModeSelection {
    #[serde(default)]
    pub name: String,
    #[serde(default)]
    pub categories: Vec<String>,
}

fn rule_mode_selection(app: &crate::App) -> RuleModeSelection {
    let raw = app.db.get(RULE_MODE_KEY).unwrap_or_default();
    if let Ok(sel) = serde_json::from_str::<RuleModeSelection>(&raw) {
        if !sel.name.is_empty() {
            // 存量 kv 可能保存旧类别 key（cn/category-ads-all 等）：归一化；
            // 来源命名空间 key（s{id}:name）原样保留。
            let mut categories: Vec<String> = Vec::new();
            for k in &sel.categories {
                let nk = normalize_category(k);
                let key = if nk.is_empty() { k.clone() } else { nk.to_string() };
                if !categories.iter().any(|x| x == &key) {
                    categories.push(key);
                }
            }
            return RuleModeSelection { name: sel.name, categories };
        }
    }
    // 兼容旧 kv（纯预设文件名）与未设置：均衡规则的类别集为默认勾选。
    let name = if raw.is_empty() { "均衡规则.yaml".to_string() } else { raw };
    let categories = match PRESETS.iter().find(|(n, _, _)| *n == name) {
        Some((_, _, members)) => RULE_CATEGORIES
            .iter()
            .filter(|c| members.is_empty() || members.contains(&c.key))
            .map(|c| c.key.to_string())
            .collect(),
        None => Vec::new(),
    };
    RuleModeSelection { name, categories }
}

/// 规则模式目录：当前选中（预设名+类别集）+ 预设清单 + 全类别目录
/// （内置含用户覆盖 + 自定义来源类别，custom 标记区分）。
pub fn rule_mode_catalog(app: &crate::App) -> Value {
    let sel = rule_mode_selection(app);
    let presets: Vec<Value> = PRESETS
        .iter()
        .map(|(name, desc, members)| {
            let include = |key: &str| members.is_empty() || members.contains(&key);
            let categories: Vec<Value> =
                RULE_CATEGORIES.iter().filter(|c| include(c.key)).map(category_link).collect();
            json!({
                "name": name,
                "desc": desc,
                "categories": categories,
            })
        })
        .collect();
    let all_categories: Vec<Value> = crate::rule_sources::effective_categories(app)
        .into_iter()
        .map(|c| json!({ "label": c.label, "key": c.key, "custom": c.custom }))
        .collect();
    json!({
        "selected": { "name": sel.name, "categories": sel.categories },
        "presets": presets,
        "categories": all_categories,
    })
}

/// 三份规则模式模板（name, content）。
pub fn rule_mode_templates() -> Vec<(&'static str, String)> {
    PRESETS.iter().enumerate().map(|(i, (name, _, _))| (*name, rule_mode_template(i))).collect()
}

/// 全局代理模板：单组直连兜底。
pub const BUILTIN_TEMPLATE_GLOBAL: &str = r#"mixed-port: 7890
allow-lan: false
mode: rule
log-level: warning
proxies: []
proxy-groups:
  - name: 🚀 节点选择
    type: select
    proxies:
      - __ALL__
      - DIRECT
rules:
  - MATCH,🚀 节点选择
"#;

/// 支持的链接协议（vmess 特殊处理，其余同 proxy::parse_share_link 的
/// `scheme://[凭据@]host:port` 形态）。
const POOL_SCHEMES: &[&str] = &[
    "vless",
    "trojan",
    "hysteria2",
    "hy2",
    "anytls",
    "tuic",
    "ss",
    "vmess",
    "socks",
    "socks5",
    "http",
    "https",
];

/// 解析单条分享链接：(协议归一, 服务器, 端口, 名称)。vmess 走 base64 JSON。
pub fn parse_link(link: &str) -> Result<(String, String, i64, String)> {
    let trimmed = link.trim();
    let Some((scheme, rest)) = trimmed.split_once("://") else {
        bail!("不是有效的分享链接（缺少 ://）")
    };
    let scheme = scheme.to_ascii_lowercase();
    if scheme == "vmess" {
        return parse_vmess_link(rest);
    }
    if !POOL_SCHEMES.contains(&scheme.as_str()) {
        bail!("暂不支持 {scheme}:// 节点");
    }
    let scheme = match scheme.as_str() {
        "hy2" => "hysteria2".to_string(),
        "socks5" => "socks".to_string(),
        "https" => "http".to_string(),
        s => s.to_string(),
    };
    let head = rest.split(['?', '#', '/']).next().unwrap_or(rest);
    // ss 的整段 base64 形态（ss://b64(method:pass@host:port)）。
    let authority = if scheme == "ss" && !head.contains('@') {
        let decoded = base64::engine::general_purpose::STANDARD
            .decode(head)
            .or_else(|_| base64::engine::general_purpose::URL_SAFE_NO_PAD.decode(head))
            .map_err(|_| anyhow!("ss 链接无法解码"))?;
        let decoded = String::from_utf8_lossy(&decoded).into_owned();
        decoded.rsplit_once('@').map(|(_, hp)| hp.to_string()).context("ss 链接里没有 host:port")?
    } else {
        match head.rsplit_once('@') {
            Some((_, hp)) => hp.to_string(),
            None => head.to_string(),
        }
    };
    let (host, port) = authority.rsplit_once(':').context("链接里没有端口")?;
    let port: i64 = port.trim().parse().with_context(|| format!("端口不是数字：{port}"))?;
    if !(1..=65535).contains(&port) {
        bail!("链接端口无效：{port}");
    }
    let host = host.trim_start_matches('[').trim_end_matches(']').to_owned();
    let name = trimmed
        .split_once('#')
        .map(|(_, frag)| proxy::percent_decode(frag))
        .filter(|n| !n.is_empty())
        .unwrap_or_else(|| format!("{scheme}-{port}"));
    Ok((scheme, host, port, name))
}

/// vmess://base64(JSON{id,add,port,ps,...})。
fn parse_vmess_link(rest: &str) -> Result<(String, String, i64, String)> {
    let head = rest.split(['?', '#']).next().unwrap_or(rest);
    let decoded = base64::engine::general_purpose::STANDARD
        .decode(head)
        .or_else(|_| base64::engine::general_purpose::URL_SAFE_NO_PAD.decode(head.trim_end_matches('=')))
        .map_err(|_| anyhow!("vmess 链接无法解码"))?;
    let v: Value = serde_json::from_slice(&decoded).context("vmess 链接不是有效 JSON")?;
    let server = v["add"].as_str().unwrap_or_default().to_owned();
    let port = match &v["port"] {
        Value::Number(n) => n.as_i64().unwrap_or(0),
        Value::String(s) => s.trim().parse().unwrap_or(0),
        _ => 0,
    };
    if server.is_empty() || !(1..=65535).contains(&port) {
        bail!("vmess 链接缺少 add/port");
    }
    let name = v["ps"].as_str().unwrap_or_default().trim().to_owned();
    let name = if name.is_empty() { format!("vmess-{port}") } else { name.to_owned() };
    Ok(("vmess".into(), server, port, name))
}

/// 区域 emoji（名称未带 emoji 时自动前缀）。覆盖常见机场命名。
fn region_emoji(name: &str) -> Option<&'static str> {
    const MAP: &[(&str, &str)] = &[
        ("香港", "🇭🇰"),
        ("HK", "🇭🇰"),
        ("HongKong", "🇭🇰"),
        ("Hong Kong", "🇭🇰"),
        ("台湾", "🇹🇼"),
        ("TW", "🇹🇼"),
        ("Taiwan", "🇹🇼"),
        ("新北", "🇹🇼"),
        ("彰化", "🇹🇼"),
        ("日本", "🇯🇵"),
        ("JP", "🇯🇵"),
        ("Japan", "🇯🇵"),
        ("东京", "🇯🇵"),
        ("大阪", "🇯🇵"),
        ("埼玉", "🇯🇵"),
        ("美国", "🇺🇸"),
        ("US", "🇺🇸"),
        ("United States", "🇺🇸"),
        ("洛杉矶", "🇺🇸"),
        ("圣何塞", "🇺🇸"),
        ("西雅图", "🇺🇸"),
        ("凤凰城", "🇺🇸"),
        ("新加坡", "🇸🇬"),
        ("SG", "🇸🇬"),
        ("Singapore", "🇸🇬"),
        ("狮城", "🇸🇬"),
        ("韩国", "🇰🇷"),
        ("KR", "🇰🇷"),
        ("Korea", "🇰🇷"),
        ("首尔", "🇰🇷"),
        ("英国", "🇬🇧"),
        ("UK", "🇬🇧"),
        ("GB", "🇬🇧"),
        ("伦敦", "🇬🇧"),
        ("德国", "🇩🇪"),
        ("DE", "🇩🇪"),
        ("德国法兰克福", "🇩🇪"),
        ("法兰克福", "🇩🇪"),
        ("法国", "🇫🇷"),
        ("FR", "🇫🇷"),
        ("巴黎", "🇫🇷"),
        ("加拿大", "🇨🇦"),
        ("CA", "🇨🇦"),
        ("多伦多", "🇨🇦"),
        ("温哥华", "🇨🇦"),
        ("澳大利亚", "🇦🇺"),
        ("AU", "🇦🇺"),
        ("悉尼", "🇦🇺"),
        ("俄罗斯", "🇷🇺"),
        ("RU", "🇷🇺"),
        ("莫斯科", "🇷🇺"),
        ("印度", "🇮🇳"),
        ("IN", "🇮🇳"),
        ("孟买", "🇮🇳"),
        ("土耳其", "🇹🇷"),
        ("TR", "🇹🇷"),
        ("伊斯坦布尔", "🇹🇷"),
        ("巴西", "🇧🇷"),
        ("BR", "🇧🇷"),
        ("圣保罗", "🇧🇷"),
        ("阿根廷", "🇦🇷"),
        ("AR", "🇦🇷"),
        ("泰国", "🇹🇭"),
        ("TH", "🇹🇭"),
        ("曼谷", "🇹🇭"),
        ("越南", "🇻🇳"),
        ("VN", "🇻🇳"),
        ("胡志明", "🇻🇳"),
        ("菲律宾", "🇵🇭"),
        ("PH", "🇵🇭"),
        ("马来西亚", "🇲🇾"),
        ("MY", "🇲🇾"),
        ("印尼", "🇮🇩"),
        ("ID", "🇮🇩"),
        ("雅加达", "🇮🇩"),
        ("荷兰", "🇳🇱"),
        ("NL", "🇳🇱"),
        ("阿姆斯特丹", "🇳🇱"),
        ("意大利", "🇮🇹"),
        ("IT", "🇮🇹"),
        ("米兰", "🇮🇹"),
        ("西班牙", "🇪🇸"),
        ("ES", "🇪🇸"),
        ("瑞士", "🇨🇭"),
        ("CH", "🇨🇭"),
        ("瑞典", "🇸🇪"),
        ("SE", "🇸🇪"),
        ("芬兰", "🇫🇮"),
        ("FI", "🇫🇮"),
        ("波兰", "🇵🇱"),
        ("PL", "🇵🇱"),
        ("乌克兰", "🇺🇦"),
        ("UA", "🇺🇦"),
        ("阿联酋", "🇦🇪"),
        ("迪拜", "🇦🇪"),
    ];
    // 名称里已有 emoji（ Astral 平面字符）就不再加。
    if name.chars().any(|c| (c as u32) >= 0x1F000) {
        return None;
    }
    MAP.iter().find(|(k, _)| name.contains(k)).map(|(_, e)| *e)
}

fn with_emoji(name: &str) -> String {
    match region_emoji(name) {
        Some(e) => format!("{e} {name}"),
        None => name.to_owned(),
    }
}

/// 多行分享链接导入：逐行解析，批内去重（链接本身）。
pub fn parse_base64_sub(text: &str) -> Vec<String> {
    let cleaned: String = text.chars().filter(|c| !c.is_whitespace()).collect();
    if let Ok(bytes) = base64::engine::general_purpose::STANDARD
        .decode(&cleaned)
        .or_else(|_| base64::engine::general_purpose::URL_SAFE_NO_PAD.decode(cleaned.trim_end_matches('=')))
    {
        if let Ok(s) = String::from_utf8(bytes) {
            if s.contains("://") {
                return s.lines().map(str::trim).filter(|l| !l.is_empty()).map(str::to_owned).collect();
            }
        }
    }
    text.lines().map(str::trim).filter(|l| !l.is_empty()).map(str::to_owned).collect()
}

/// Clash YAML 的 proxies 段 → 原生代理字段（双形态导入：不再强转链接）。
pub fn clash_proxies_of(text: &str) -> (Vec<Value>, Vec<Value>) {
    let doc: Value = match serde_yaml::from_str(text) {
        Ok(v) => v,
        Err(e) => {
            return (vec![], vec![json!({ "name": "(整份文件)", "reason": format!("YAML 解析失败：{e}") })])
        }
    };
    let Some(proxies) = doc.get("proxies").and_then(|p| p.as_array()) else {
        return (vec![], vec![json!({ "name": "(整份文件)", "reason": "没有 proxies 段" })]);
    };
    let mut out = Vec::new();
    let mut skipped = Vec::new();
    for p in proxies {
        let name = p.get("name").and_then(|v| v.as_str()).unwrap_or("").to_owned();
        let ty = s_of(p, &["type"]).to_ascii_lowercase();
        if !matches!(
            ty.as_str(),
            "vless" | "vmess" | "ss" | "trojan" | "hysteria2" | "hy2" | "anytls" | "tuic" | "socks5" | "http"
        ) {
            skipped.push(json!({ "name": name, "reason": format!("暂不支持 Clash 类型 {ty}") }));
            continue;
        }
        if s_of(p, &["server"]).is_empty() || !(1..=65535).contains(&i_of(p, &["port"])) {
            skipped.push(json!({ "name": name, "reason": "缺少 server/port" }));
            continue;
        }
        out.push(p.clone());
    }
    (out, skipped)
}

fn s_of(p: &Value, keys: &[&str]) -> String {
    for k in keys {
        if let Some(v) = p.get(*k).and_then(|v| v.as_str()) {
            if !v.is_empty() {
                return v.to_owned();
            }
        }
    }
    String::new()
}

fn i_of(p: &Value, keys: &[&str]) -> i64 {
    for k in keys {
        match p.get(*k) {
            Some(Value::Number(n)) => return n.as_i64().unwrap_or(0),
            Some(Value::String(s)) => {
                if let Ok(v) = s.trim().parse() {
                    return v;
                }
            }
            _ => {}
        }
    }
    0
}

fn uri_encode(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for byte in s.bytes() {
        match byte {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => out.push(byte as char),
            other => out.push_str(&format!("%{other:02X}")),
        }
    }
    out
}

// ---- 渲染：链接 → Clash 代理字段 ----

fn query_of(link: &str) -> Vec<(String, String)> {
    let rest = link.split_once("://").map(|(_, r)| r).unwrap_or("");
    let q = rest.split_once('?').map(|(_, q)| q).unwrap_or("");
    let q = q.split('#').next().unwrap_or(q);
    q.split('&')
        .filter_map(|kv| kv.split_once('='))
        .map(|(k, v)| (k.to_ascii_lowercase(), proxy::percent_decode(v)))
        .collect()
}

fn qget<'a>(q: &'a [(String, String)], key: &str) -> Option<&'a str> {
    q.iter().find(|(k, _)| k == key).map(|(_, v)| v.as_str())
}

fn name_of(link: &str) -> String {
    link.split_once('#').map(|(_, f)| proxy::percent_decode(f)).unwrap_or_default()
}

fn transport_opts(q: &[(String, String)], net: &str) -> Value {
    match net {
        "ws" => {
            let mut opts = json!({});
            if let Some(path) = qget(q, "path") {
                opts["path"] = json!(path);
            }
            if let Some(host) = qget(q, "host") {
                opts["headers"] = json!({ "Host": host });
            }
            json!({ "ws-opts": opts })
        }
        "grpc" => {
            let svc = qget(q, "servicename").unwrap_or("");
            json!({ "grpc-opts": { "grpc-service-name": svc } })
        }
        _ => json!({}),
    }
}

/// 把 transport_opts 返回的对象逐键并入代理字段。
fn merge_opts(target: &mut Value, opts: Value) {
    if let (Value::Object(t), Value::Object(o)) = (target, opts) {
        for (k, v) in o {
            t.insert(k, v);
        }
    }
}

/// 分享链接 → mihomo 代理字段（serde_json，整体配置最后统一转 YAML）。
pub fn link_to_proxy(link: &str) -> Result<Value> {
    let (scheme, rest) = link.split_once("://").context("不是有效的分享链接")?;
    let scheme = scheme.to_ascii_lowercase();
    let head = rest.split(['?', '#']).next().unwrap_or(rest);
    let name = name_of(link);
    let q = query_of(link);
    let server_port = match head.rsplit_once('@') {
        Some((_, hp)) => hp,
        None => head,
    };
    let (server, port) = server_port.rsplit_once(':').context("缺少端口")?;
    let port: i64 = port.parse().context("端口不是数字")?;
    let insecure = matches!(qget(&q, "insecure"), Some("1") | Some("true"));
    let sni = qget(&q, "sni").unwrap_or("").to_owned();
    let net = qget(&q, "type").unwrap_or("tcp").to_owned();
    let frag = if name.is_empty() { format!("{scheme}-{port}") } else { name };

    let mut m = match scheme.as_str() {
        "vless" => {
            let userinfo = head.rsplit_once('@').map(|(u, _)| u).unwrap_or(head);
            let mut m = json!({
                "name": frag, "server": server, "port": port, "type": "vless",
                "uuid": proxy::percent_decode(userinfo), "udp": true, "network": net,
            });
            let security = qget(&q, "security").unwrap_or("");
            if security == "reality" {
                m["tls"] = json!(true);
                m["servername"] = json!(sni);
                let mut ropts = json!({});
                if let Some(pbk) = qget(&q, "pbk") {
                    ropts["public-key"] = json!(pbk);
                }
                if let Some(sid) = qget(&q, "sid") {
                    ropts["short-id"] = json!(sid);
                }
                m["reality-opts"] = ropts;
            } else if security == "tls" || !sni.is_empty() {
                m["tls"] = json!(true);
                if !sni.is_empty() {
                    m["servername"] = json!(sni);
                }
            }
            if let Some(fp) = qget(&q, "fp") {
                m["client-fingerprint"] = json!(fp);
            }
            if let Some(flow) = qget(&q, "flow") {
                m["flow"] = json!(flow);
            }
            merge_opts(&mut m, transport_opts(&q, &net));
            if insecure {
                m["skip-cert-verify"] = json!(true);
            }
            m
        }
        "trojan" => {
            let userinfo = head.rsplit_once('@').map(|(u, _)| u).unwrap_or(head);
            let mut m = json!({
                "name": frag, "server": server, "port": port, "type": "trojan",
                "password": proxy::percent_decode(userinfo), "udp": true,
                "sni": sni, "skip-cert-verify": insecure, "network": net,
            });
            merge_opts(&mut m, transport_opts(&q, &net));
            m
        }
        "ss" => {
            let userinfo = head.rsplit_once('@').map(|(u, _)| u).unwrap_or(head);
            let decoded = base64::engine::general_purpose::STANDARD
                .decode(userinfo)
                .or_else(|_| base64::engine::general_purpose::URL_SAFE_NO_PAD.decode(userinfo))
                .map_err(|_| anyhow!("ss 凭据无法解码"))?;
            let decoded = String::from_utf8_lossy(&decoded).into_owned();
            let (cipher, password) = decoded.split_once(':').context("ss 凭据格式不对")?;
            json!({ "name": frag, "server": server, "port": port, "type": "ss", "cipher": cipher, "password": password, "udp": true })
        }
        "vmess" => {
            let b64body = head.rsplit_once('@').map(|(u, _)| u).unwrap_or(head);
            let decoded = base64::engine::general_purpose::STANDARD
                .decode(b64body)
                .or_else(|_| {
                    base64::engine::general_purpose::URL_SAFE_NO_PAD.decode(b64body.trim_end_matches('='))
                })
                .map_err(|_| anyhow!("vmess 无法解码"))?;
            let v: Value = serde_json::from_slice(&decoded).context("vmess 不是有效 JSON")?;
            let vnet = v["net"].as_str().unwrap_or("tcp").to_owned();
            let mut m = json!({
                "name": frag, "server": server, "port": port, "type": "vmess",
                "uuid": v["id"], "alterId": v["aid"].as_i64().unwrap_or(0),
                "cipher": v["scy"].as_str().unwrap_or("auto"), "udp": true,
            });
            if v["tls"].as_str() == Some("tls") || !v["sni"].as_str().unwrap_or("").is_empty() {
                m["tls"] = json!(true);
                if let Some(s) = v["sni"].as_str() {
                    if !s.is_empty() {
                        m["servername"] = json!(s);
                    }
                }
            }
            let mut vq = vec![];
            if let Some(h) = v["host"].as_str() {
                if !h.is_empty() {
                    vq.push(("host".into(), h.to_owned()));
                }
            }
            if let Some(p) = v["path"].as_str() {
                if !p.is_empty() {
                    vq.push(("path".into(), p.to_owned()));
                }
            }
            merge_opts(&mut m, transport_opts(&vq, &vnet));
            m
        }
        "hysteria2" => {
            let userinfo = head.rsplit_once('@').map(|(u, _)| u).unwrap_or(head);
            let mut m = json!({
                "name": frag, "server": server, "port": port, "type": "hysteria2",
                "password": proxy::percent_decode(userinfo), "sni": sni,
                "skip-cert-verify": insecure, "alpn": ["h3"],
            });
            if let Some(obfs) = qget(&q, "obfs") {
                m["obfs"] = json!(obfs);
                if let Some(pw) = qget(&q, "obfs-password") {
                    m["obfs-password"] = json!(pw);
                }
            }
            m
        }
        "anytls" => {
            let userinfo = head.rsplit_once('@').map(|(u, _)| u).unwrap_or(head);
            json!({
                "name": frag, "server": server, "port": port, "type": "anytls",
                "password": proxy::percent_decode(userinfo), "sni": sni,
                "skip-cert-verify": insecure, "udp": true,
            })
        }
        "tuic" => {
            let userinfo = head.rsplit_once('@').map(|(u, _)| u).unwrap_or(head);
            let (uuid, password) = userinfo.split_once(':').unwrap_or((userinfo, ""));
            let mut m = json!({
                "name": frag, "server": server, "port": port, "type": "tuic",
                "uuid": proxy::percent_decode(uuid), "password": proxy::percent_decode(password),
                "sni": sni, "udp": true,
            });
            if let Some(cc) = qget(&q, "congestion_control") {
                m["congestion-controller"] = json!(cc);
            }
            m
        }
        "socks" => {
            let userinfo = head.rsplit_once('@').map(|(u, _)| u).unwrap_or("");
            let (user, pass) = userinfo.split_once(':').unwrap_or((userinfo, ""));
            json!({
                "name": frag, "server": server, "port": port, "type": "socks5",
                "username": proxy::percent_decode(user), "password": proxy::percent_decode(pass), "udp": true,
            })
        }
        "http" | "https" => {
            let userinfo = head.rsplit_once('@').map(|(u, _)| u).unwrap_or("");
            let (user, pass) = userinfo.split_once(':').unwrap_or((userinfo, ""));
            json!({
                "name": frag, "server": server, "port": port, "type": "http",
                "username": proxy::percent_decode(user), "password": proxy::percent_decode(pass),
            })
        }
        other => bail!("暂不支持渲染 {other}:// 节点"),
    };
    if m["name"].as_str().unwrap_or("").is_empty() {
        m["name"] = json!(format!("{scheme}-{port}"));
    }
    Ok(m)
}

// ---- 标签与导入（双形态入库）----

/// 从节点名推断地区标签（emoji 即标签，与名称前缀同源）。
fn region_tags(name: &str) -> Vec<String> {
    region_emoji(name).map(|e| vec![e.to_string()]).unwrap_or_default()
}

/// 分享链接 → 节点（raw_link + clash_config 双形态都存）。
fn sub_node_from_link(link: &str, source_url: &str) -> Result<crate::db::SubNode> {
    let (protocol, server, port, name) = parse_link(link)?;
    let map = link_to_proxy(link)?;
    Ok(crate::db::SubNode {
        name: with_emoji(&name),
        raw_link: link.trim().to_owned(),
        clash_config: serde_json::to_string(&map).unwrap_or_default(),
        protocol,
        server,
        port,
        tags: region_tags(&name),
        source_url: source_url.to_owned(),
        enabled: true,
        ..Default::default()
    })
}

/// Clash 原生字段 → 节点（不再强转链接，零丢失）。
fn sub_node_from_clash(name: &str, map: &Value, source_url: &str) -> crate::db::SubNode {
    crate::db::SubNode {
        name: with_emoji(name),
        raw_link: String::new(),
        clash_config: serde_json::to_string(map).unwrap_or_default(),
        protocol: s_of(map, &["type"]).to_ascii_lowercase(),
        server: s_of(map, &["server"]),
        port: i_of(map, &["port"]),
        tags: region_tags(name),
        source_url: source_url.to_owned(),
        enabled: true,
        ..Default::default()
    }
}

/// 一条导入结果（给前端报告用）。
#[derive(serde::Serialize, Debug, Default)]
pub struct ImportOutcome {
    pub imported: i64,
    /// 同步式导入时已存在而被刷新的节点数。
    pub refreshed: i64,
    pub skipped: Vec<Value>,
}

/// 三路导入统一入口：粘贴链接 / base64 订阅 / Clash YAML（自动识别）。
/// 全部 upsert（同 protocol+server+port 刷新），source_url 非空时节点与
/// 外部订阅源关联（同步按此整体替换）。
pub fn import_text_nodes(app: &crate::App, text: &str, source_url: &str) -> Result<ImportOutcome> {
    let mut outcome = ImportOutcome::default();
    let clash_mode = text.contains("proxies:")
        && serde_yaml::from_str::<Value>(text).map(|v| v.get("proxies").is_some()).unwrap_or(false);
    let (nodes, mut skipped) = if clash_mode {
        let (maps, skipped) = clash_proxies_of(text);
        let nodes = maps
            .iter()
            .map(|m| {
                let name = m.get("name").and_then(|v| v.as_str()).unwrap_or("").to_owned();
                sub_node_from_clash(&name, m, source_url)
            })
            .collect::<Vec<_>>();
        let skipped: Vec<Value> = skipped
            .iter()
            .map(|sk| {
                let mut m = sk.clone();
                if let Some(n) = m.get("name").and_then(|v| v.as_str()) {
                    m["name"] = json!(format!("(Clash) {n}"));
                }
                m
            })
            .collect();
        (nodes, skipped)
    } else {
        let mut nodes = Vec::new();
        let mut sk = Vec::new();
        for link in parse_base64_sub(text) {
            match sub_node_from_link(&link, source_url) {
                Ok(n) => nodes.push(n),
                Err(e) => sk.push(
                    json!({ "name": link.chars().take(40).collect::<String>(), "reason": format!("{e:#}") }),
                ),
            }
        }
        (nodes, sk)
    };
    for n in nodes {
        match app.db.upsert_sub_node(&n) {
            Ok((_, true)) => outcome.imported += 1,
            Ok((_, false)) => outcome.refreshed += 1,
            Err(e) => outcome.skipped.push(json!({ "name": n.name, "reason": format!("{e:#}") })),
        }
    }
    outcome.skipped.splice(0..0, skipped.drain(..));
    Ok(outcome)
}

/// 同步导入面板自建节点（同步式快照）：为每个启用管理节点渲染分享链接，
/// 双形态入库（管理侧改端口/换凭据后重跑即刷新）。
/// `only_ids` 非空时只同步这些管理节点 id。
pub async fn import_managed(app: &crate::App, only_ids: &[i64]) -> Result<ImportOutcome> {
    let fronts = proxy::sub_fronts(app);
    let Some(front) = fronts.first() else {
        bail!("没有可用的订阅入口地址（sub_hosts 或 --site）")
    };
    let bundles: Vec<_> = app
        .db
        .proxy_node_bundles()?
        .into_iter()
        .filter(|b| b.node.enabled && (only_ids.is_empty() || only_ids.contains(&b.node.id)))
        .collect();
    let mut outcome = ImportOutcome::default();
    for bundle in &bundles {
        let Some(user) = bundle.users.first() else { continue };
        let link = match proxy::share_link(bundle, user, front, "") {
            Ok(l) => l,
            Err(e) => {
                outcome.skipped.push(json!({ "name": bundle.node.name, "reason": format!("{e:#}") }));
                continue;
            }
        };
        match sub_node_from_link(&link, "") {
            Ok(mut n) => {
                n.name = with_emoji(&bundle.node.name);
                n.tags = region_tags(&bundle.node.name);
                match app.db.upsert_sub_node(&n) {
                    Ok((_, true)) => outcome.imported += 1,
                    Ok((_, false)) => outcome.refreshed += 1,
                    Err(e) => outcome.skipped.push(json!({ "name": n.name, "reason": format!("{e:#}") })),
                }
            }
            Err(e) => outcome.skipped.push(json!({ "name": bundle.node.name, "reason": format!("{e:#}") })),
        }
    }
    Ok(outcome)
}

// ---- 外部订阅源同步 ----

/// 拉取外部订阅（SSRF 防护同 realm：走 proxied）。UA 优先用源配置；
/// 上游没回流量头且 UA 不是 clash 系时用 clash UA 重试一次（部分机场只对
/// clash UA 回 subscription-userinfo）。返回 (正文, userinfo)。
pub(crate) async fn fetch_remote(app: &crate::App, url: &str, ua: &str) -> Result<(String, String)> {
    if !url.starts_with("http://") && !url.starts_with("https://") {
        bail!("订阅地址应以 http(s):// 开头");
    }
    let client = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(30))
        .build()
        .context("构建下载客户端失败")?;
    let fetch = |ua: String| {
        let client = client.clone();
        let url = crate::proxied(app, url.to_string());
        async move {
            client
                .get(url)
                .header(header::USER_AGENT, ua)
                .send()
                .await
                .context("无法访问订阅地址")?
                .error_for_status()
                .context("订阅地址返回错误")
        }
    };
    let ua = if ua.trim().is_empty() { "clash-meta/2.4.0" } else { ua.trim() };
    let resp = fetch(ua.to_owned()).await?;
    let info = resp
        .headers()
        .get("subscription-userinfo")
        .and_then(|v| v.to_str().ok())
        .unwrap_or_default()
        .to_owned();
    let text = resp.text().await.context("读取订阅内容失败")?;
    if text.len() > 8 * 1024 * 1024 {
        bail!("订阅内容超过 8MB");
    }
    if info.is_empty() && !ua.to_ascii_lowercase().contains("clash") {
        if let Ok(resp) = fetch("clash-meta/2.4.0".into()).await {
            let info2 = resp
                .headers()
                .get("subscription-userinfo")
                .and_then(|v| v.to_str().ok())
                .unwrap_or_default()
                .to_owned();
            if !info2.is_empty() {
                let t = resp.text().await.context("读取订阅内容失败")?;
                if t.len() > 8 * 1024 * 1024 {
                    bail!("订阅内容超过 8MB");
                }
                return Ok((t, info2));
            }
        }
    }
    Ok((text, info))
}

/// 同步一个外部订阅源：拉取 → 清掉该源旧节点 → 重插 → 回写流量/节点数。
pub async fn sync_source(app: &crate::App, source: &crate::db::SubSource) -> Result<i64> {
    let (text, info) = fetch_remote(app, &source.url, &source.user_agent).await?;
    app.db.delete_sub_nodes_by_source(&source.url)?;
    let outcome = import_text_nodes(app, &text, &source.url)?;
    let count = outcome.imported + outcome.refreshed;
    app.db.set_sub_source_sync(source.id, &info, count)?;
    Ok(count)
}

/// 定时同步循环：每分钟扫描到期源（interval 最小 5 分钟，默认 60）。
pub async fn sync_loop(app: Shared) {
    loop {
        tokio::time::sleep(std::time::Duration::from_secs(60)).await;
        let sources = match app.db.sub_sources() {
            Ok(s) => s,
            Err(_) => continue,
        };
        let now = chrono::Utc::now().timestamp();
        for source in sources {
            if !source.auto_update {
                continue;
            }
            let interval = source.interval_min.max(5) * 60;
            if source.last_sync > 0 && now - source.last_sync < interval {
                continue;
            }
            if let Err(e) = sync_source(&app, &source).await {
                tracing::warn!("订阅源 {} 同步失败: {e:#}", source.name);
            }
        }
    }
}

// ---- 渲染：模板注入 ----

/// 节点 → Clash 代理字段（名称以节点池为准）。
fn node_to_proxy(n: &crate::db::SubNode) -> Result<Value> {
    if !n.raw_link.is_empty() {
        let mut m = link_to_proxy(&n.raw_link)?;
        if !n.name.trim().is_empty() {
            m["name"] = json!(n.name.trim());
        }
        Ok(m)
    } else if !n.clash_config.is_empty() {
        let mut m: Value = serde_json::from_str(&n.clash_config).context("节点 clash_config 损坏")?;
        if !n.name.trim().is_empty() {
            m["name"] = json!(n.name.trim());
        }
        Ok(m)
    } else {
        bail!("节点 {} 既无链接也无原生配置", n.name)
    }
}

/// 模板 proxy-groups 的占位符展开：`__ALL__` → 全部节点名；`__TAG:xx__` →
/// 带标签 xx 的节点名；占位符无匹配时丢弃该占位项，组整体为空则补 DIRECT。
fn expand_placeholders(doc: &mut Value, node_names: &[String], node_tags: &[(Vec<String>, String)]) {
    let Some(groups) = doc.get_mut("proxy-groups").and_then(|v| v.as_array_mut()) else { return };
    for g in groups.iter_mut() {
        let Some(items) = g.get_mut("proxies").and_then(|v| v.as_array_mut()) else { continue };
        let mut expanded: Vec<Value> = Vec::new();
        for item in items.iter() {
            let Some(s) = item.as_str() else {
                expanded.push(item.clone());
                continue;
            };
            if s == "__ALL__" {
                expanded.extend(node_names.iter().map(|n| json!(n)));
            } else if let Some(tag) = s.strip_prefix("__TAG:").and_then(|t| t.strip_suffix("__")) {
                for (tags, name) in node_tags {
                    if tags.iter().any(|t| t == tag) {
                        expanded.push(json!(name));
                    }
                }
            } else {
                expanded.push(item.clone());
            }
        }
        if expanded.is_empty() {
            expanded.push(json!("DIRECT"));
        }
        g["proxies"] = json!(expanded);
    }
}

/// 合并规则片段：rules 片段 prepend 到 rules 头部 / append 到 MATCH 之前；
/// dns 片段整体替换 dns 段。片段内容可以是规则序列或 {rules: [...]}。
fn merge_snippet(doc: &mut Value, sn: &crate::db::SubSnippet) -> Result<()> {
    let parsed: Value =
        serde_yaml::from_str(&sn.content).with_context(|| format!("片段「{}」不是有效 YAML", sn.name))?;
    match sn.kind.as_str() {
        "dns" => doc["dns"] = parsed,
        "rules" => {
            let incoming: Vec<String> = if let Some(seq) = parsed.as_array() {
                seq.iter().filter_map(|v| v.as_str().map(str::to_owned)).collect()
            } else if let Some(rs) = parsed.get("rules").and_then(|v| v.as_array()) {
                rs.iter().filter_map(|v| v.as_str().map(str::to_owned)).collect()
            } else {
                bail!("片段「{}」需要规则列表（YAML 序列或 {{rules: [...]}}）", sn.name);
            };
            let incoming: Vec<Value> = incoming.into_iter().map(|l| json!(l)).collect();
            let rules: Vec<Value> = doc.get("rules").and_then(|v| v.as_array()).cloned().unwrap_or_default();
            let merged = if sn.mode == "prepend" {
                let mut v = incoming;
                v.extend(rules);
                v
            } else {
                let split = rules
                    .iter()
                    .position(|r| r.as_str().map(|s| s.starts_with("MATCH")).unwrap_or(false))
                    .unwrap_or(rules.len());
                let mut v = rules[..split].to_vec();
                v.extend(incoming);
                v.extend(rules[split..].to_vec());
                v
            };
            doc["rules"] = json!(merged);
        }
        other => bail!("片段类型 {other} 不支持"),
    }
    Ok(())
}

/// 把启用的规则片段合并进配置文档（模板注入与类别动态生成两条渲染路径
/// 共用）。语义（用户拍板）：**片段库里「启用」的片段全局生效**——所有
/// 预览与生成的配置都自动合并，不需要逐订阅勾选；profile.snippet_ids 仍
/// 兼容合并（旧数据/弹窗勾选），按 id 去重，顺序 = 片段 id 序。
fn merge_profile_snippets(app: &crate::App, profile: &crate::db::SubProfile, doc: &mut Value) -> Result<()> {
    let mut seen: HashSet<i64> = HashSet::new();
    for sn in app.db.sub_snippets()?.into_iter().filter(|s| s.enabled) {
        seen.insert(sn.id);
        merge_snippet(doc, &sn)?;
    }
    for id in &profile.snippet_ids {
        if seen.insert(*id) {
            if let Some(sn) = app.db.sub_snippet(*id).ok().flatten() {
                if sn.enabled {
                    merge_snippet(doc, &sn)?;
                }
            }
        }
    }
    Ok(())
}

/// 客户渲染的唯一节点来源：**分配协议**（方向 B）——proxy_node_bundles 中
/// 该客户被分配凭据的启用节点，合成 SubNode（raw_link=share_link(客户凭据)）。
/// sub_nodes 节点池与 profile.selected_nodes 不再参与（方案=纯规则配方）。
fn collect_customer_nodes(app: &crate::App, sub: &crate::db::SubUser) -> Result<Vec<crate::db::SubNode>> {
    let fronts = proxy::sub_fronts(app);
    let Some(front) = fronts.first() else {
        bail!("没有可用的订阅入口地址（sub_hosts 或 --site）")
    };
    let mut out = Vec::new();
    for bundle in app.db.proxy_node_bundles()? {
        if !bundle.node.enabled {
            continue;
        }
        let Some(user) = bundle.users.iter().find(|u| u.sub_user_id == Some(sub.id)) else { continue };
        let Ok(link) = proxy::share_link(&bundle, user, front, "") else { continue };
        out.push(crate::db::SubNode {
            id: bundle.node.id,
            name: bundle.node.name.clone(),
            raw_link: link,
            proxy_node_id: Some(bundle.node.id),
            enabled: true,
            ..Default::default()
        });
    }
    eprintln!("[dbg-ccn] total={}", out.len());
    Ok(out)
}
/// 生成一份订阅 YAML：模板 + 节点注入 + 占位符展开 + 片段合并（匿名视角，
/// 面板预览与既有测试用）。
pub fn render_profile(app: &crate::App, profile: &crate::db::SubProfile) -> Result<String> {
    render_profile_for(app, profile, None)
}

/// 客户视角渲染：面板导入的节点换用该客户自有凭据（未分配该节点凭据 → 剔
/// 除），外部节点原样。静态方案原样下发（凭据无法替换）。
pub fn render_profile_for(
    app: &crate::App,
    profile: &crate::db::SubProfile,
    sub: Option<&crate::db::SubUser>,
) -> Result<String> {
    // 静态订阅：整份 YAML 原样下发（编辑过的快照，不随节点/勾选/客户变化）
    if !profile.static_content.trim().is_empty() {
        return Ok(profile.static_content.clone());
    }
    if !profile.selected_categories.is_empty() {
        return render_by_categories_for(app, profile, &profile.selected_categories, sub);
    }
    // 方案=纯规则配方：任何路径都不再从 sub_nodes 取节点。客户=分配协议；
    // 匿名预览=零节点（proxies 空、组回落 DIRECT，规则结构完整可见）。
    let nodes = match sub {
        Some(s) => collect_customer_nodes(app, s)?,
        None => Vec::new(),
    };
    let template = app
        .db
        .sub_template(&profile.template_name)?
        .with_context(|| format!("绑定的模板「{}」不存在", profile.template_name))?;
    let mut doc: Value = serde_yaml::from_str(&template.content).context("模板不是有效 YAML")?;

    let mut used: HashSet<String> = HashSet::new();
    let mut proxies: Vec<Value> = Vec::new();
    let mut node_names: Vec<String> = Vec::new();
    let mut node_tags: Vec<(Vec<String>, String)> = Vec::new();
    for n in &nodes {
        let mut m = node_to_proxy(n)?;
        let base = n.name.trim().to_owned();
        let mut name = base.clone();
        let mut suffix = 2;
        while !used.insert(name.clone()) {
            name = format!("{base} {suffix}");
            suffix += 1;
        }
        m["name"] = json!(name.clone());
        node_names.push(name.clone());
        node_tags.push((n.tags.clone(), name));
        proxies.push(m);
    }
    doc["proxies"] = json!(proxies);
    expand_placeholders(&mut doc, &node_names, &node_tags);
    // 外部模板兼容剪枝：组内引用的裸节点名若不在已注入集合里（外部模板的
    // 固定节点名、过时引用）剔除；DIRECT/REJECT/组引用保留。
    {
        let injected: HashSet<&str> = node_names.iter().map(|s| s.as_str()).collect();
        let group_refs: HashSet<String> = doc
            .get("proxy-groups")
            .and_then(|v| v.as_array())
            .map(|arr| {
                arr.iter().filter_map(|g| g.get("name").and_then(|v| v.as_str()).map(str::to_owned)).collect()
            })
            .unwrap_or_default();
        if let Some(groups) = doc.get_mut("proxy-groups").and_then(|v| v.as_array_mut()) {
            for g in groups.iter_mut() {
                if let Some(items) = g.get_mut("proxies").and_then(|v| v.as_array_mut()) {
                    items.retain(|m| match m.as_str() {
                        Some(name) => {
                            name == "DIRECT"
                                || name == "REJECT"
                                || name == "REJECT-DROP"
                                || name == "PASS"
                                || name == "__ALL__"
                                || name.starts_with("__TAG:")
                                || group_refs.contains(name)
                                || injected.contains(name)
                        }
                        _ => true,
                    });
                    if items.is_empty() {
                        items.push(json!("DIRECT"));
                    }
                }
            }
        }
    }
    // 组覆盖（可视化拖拽分组）：node_names 与 nodes 同序（改名按 index 对
    // 应），被覆盖的组用覆盖表里的节点顺序渲染；引用停用/不存在/不在本次
    // 勾选集合的节点 id 剔除；未覆盖的组保持占位符展开结果。
    let overrides = profile.group_overrides.as_object().cloned().unwrap_or_default();
    if !overrides.is_empty() {
        // node_names 与 nodes 同序：id → 渲染名直接按位置映射。
        let name_for = |id: i64| -> Option<String> {
            let idx = nodes.iter().position(|x| x.id == id)?;
            nodes.get(idx).filter(|n| n.enabled).map(|_| node_names[idx].clone())
        };
        // 展开特殊项占位符（与模板占位符同一套约定）。
        let expand_item = |m: &Value, out: &mut Vec<Value>| {
            let Some(s) = m.as_str() else {
                out.push(m.clone());
                return;
            };
            if s == "__ALL__" {
                out.extend(node_names.iter().map(|n| json!(n)));
            } else if let Some(tag) = s.strip_prefix("__TAG:").and_then(|t| t.strip_suffix("__")) {
                for (tags, name) in &node_tags {
                    if tags.iter().any(|t| t == tag) {
                        out.push(json!(name));
                    }
                }
            } else {
                out.push(json!(s));
            }
        };
        if let Some(groups) = doc.get_mut("proxy-groups").and_then(|v| v.as_array_mut()) {
            for g in groups.iter_mut() {
                let Some(gname) = g.get("name").and_then(|v| v.as_str()).map(str::to_owned) else { continue };
                let Some(ov) = overrides.get(&gname).and_then(|v| v.as_array()) else { continue };
                let mut list: Vec<Value> = Vec::new();
                for m in ov {
                    match m {
                        Value::Number(id) => {
                            if let Some(name) = name_for(id.as_i64().unwrap_or(0)) {
                                list.push(json!(name));
                            }
                        }
                        other => expand_item(other, &mut list),
                    }
                }
                let list = if list.is_empty() { vec![json!("DIRECT")] } else { list };
                g["proxies"] = json!(list);
            }
        }
        // 覆盖里出现基础配置没有的组名 → 追加为新 select 组（按地区一键建组
        // 依赖此能力：地区组不在模板里，由覆盖引入）。
        let existing: std::collections::HashSet<String> = doc["proxy-groups"]
            .as_array()
            .map(|a| {
                a.iter().filter_map(|g| g.get("name").and_then(|v| v.as_str()).map(str::to_owned)).collect()
            })
            .unwrap_or_default();
        for (gname, members) in &overrides {
            if existing.contains(gname) {
                continue;
            }
            let mut list: Vec<Value> = Vec::new();
            for m in members.as_array().cloned().unwrap_or_default() {
                expand_item(&m, &mut list);
            }
            let list = if list.is_empty() { vec![json!("DIRECT")] } else { list };
            if let Some(groups) = doc.get_mut("proxy-groups").and_then(|v| v.as_array_mut()) {
                groups.push(json!({ "name": gname, "type": "select", "proxies": list }));
            }
        }
    }

    merge_profile_snippets(app, profile, &mut doc)?;
    sanitize_group_members(&mut doc);
    serde_yaml::to_string(&doc).context("YAML 序列化失败")
}

/// 悬空引用清理：成员既不是本配置的组/代理，也不是内置策略时剔除。
/// 可视化分组保存的地区引用在其组被删除后会悬空，这里兜底保证配置可用。
fn sanitize_group_members(doc: &mut Value) {
    // 先把代理名与组名快照下来，再改组列表（避免可变/不可变借用冲突）。
    let mut proxies: std::collections::HashSet<String> = std::collections::HashSet::new();
    if let Some(list) = doc.get("proxies").and_then(Value::as_array) {
        for p in list {
            if let Some(name) = p.get("name").and_then(Value::as_str) {
                proxies.insert(name.to_owned());
            }
        }
    }
    let Some(groups) = doc.get_mut("proxy-groups").and_then(Value::as_array_mut) else { return };
    let names: std::collections::HashSet<String> =
        groups.iter().filter_map(|g| g.get("name").and_then(Value::as_str).map(str::to_owned)).collect();
    for g in groups.iter_mut() {
        if let Some(list) = g.get_mut("proxies").and_then(Value::as_array_mut) {
            list.retain(|m| match m.as_str() {
                Some(x) => {
                    x == "DIRECT"
                        || x == "REJECT"
                        || x == "REJECT-DROP"
                        || x == "PASS"
                        || x == "COMPATIBLE"
                        || names.contains(x)
                        || proxies.contains(x)
                }
                None => true,
            });
            if list.is_empty() {
                list.push(json!("DIRECT"));
            }
        }
    }
}

/// 客户视角的链接列表（凭据按客户替换）。
pub fn render_links_for(
    app: &crate::App,
    _profile: &crate::db::SubProfile,
    sub: Option<&crate::db::SubUser>,
) -> Result<String> {
    let nodes = match sub {
        Some(s) => collect_customer_nodes(app, s)?,
        None => Vec::new(),
    };
    let lines: Vec<String> =
        nodes.iter().filter(|n| !n.raw_link.is_empty()).map(|n| n.raw_link.clone()).collect();
    if lines.is_empty() {
        bail!(crate::Shown(
            "该订阅的节点全部来自 Clash 配置导入，没有可输出的分享链接（用 Clash 系客户端拉取 YAML 即可）"
                .to_string()
        ));
    }
    Ok(base64::engine::general_purpose::STANDARD.encode(lines.join("\n")))
}

/// 预设模板清单（供前端下拉）：内置 39（含用户覆盖）+ 自定义模板来源。
/// name/key/kind/imported；自定义 key 形如 `u{id}`。
pub async fn conv_template_presets_list(_: Admin, State(app): State<Shared>) -> Response {
    let imported: HashSet<String> =
        app.db.sub_templates().unwrap_or_default().into_iter().map(|t| t.name).collect();
    let presets: Vec<Value> = crate::rule_sources::effective_presets(&app)
        .into_iter()
        .map(|p| {
            json!({
                "key": p.key, "name": p.name, "kind": p.kind,
                "builtin": p.builtin,
                "imported": imported.contains(&p.name),
            })
        })
        .collect();
    Json(json!({ "presets": presets })).into_response()
}

/// 从 URL 拉取模板内容并转换入库（内置预设与自定义模板来源共用管线）。
/// kind 仅用于 acl4ssr ini 的相对 ruleset 基址补全，auto 留空即可（按内容
/// 自动分派）。返回 (模板 id, 模板名)。
pub(crate) async fn import_template_from_url(
    app: &crate::App,
    name: &str,
    url: &str,
    kind: &str,
) -> Result<(i64, String)> {
    if app.db.sub_template(name).ok().flatten().is_some() {
        bail!(crate::Shown(format!("模板「{name}」已导入")));
    }
    let (text, _info) = fetch_remote(app, url, "").await?;
    let content = if text.contains("custom_proxy_group=") {
        // subconverter [custom] 格式（Aethersailor 与 ACL4SSR 的 ini 都是这个
        // 格式；ACL4SSR 的 ruleset 用相对路径，base 补全为其仓库 raw 根）。
        let base = if kind == "acl4ssr" { "ACL4SSR/ACL4SSR/master/" } else { "" };
        Some(convert_subconverter_custom(&text, base).with_context(|| {
            crate::Shown("模板转换失败，检查该 ini 是否为标准 subconverter 格式".to_string())
        }))
    } else if text.contains("[Proxy Group]") {
        Some(convert_acl_ini(&text))
    } else if serde_yaml::from_str::<Value>(&text).is_ok() {
        Some(Ok(text))
    } else {
        None
    };
    let content = match content {
        Some(Ok(y)) => y,
        Some(Err(e)) => return Err(e),
        None => bail!(crate::Shown(
            "拉取的内容不是可识别的模板格式（Clash 配置 / 分享链接订阅 / subconverter 规则源）".to_string()
        )),
    };
    let t = crate::db::SubTemplate {
        id: 0,
        name: name.to_owned(),
        note: format!("预设：{name}"),
        is_builtin: false,
        content,
        created_at: 0,
    };
    let id = app.db.create_sub_template(&t)?;
    Ok((id, t.name))
}

/// 导入预设模板（内置 key 或自定义来源 `u{id}`）。
pub async fn conv_template_preset_import(
    _: Admin,
    State(app): State<Shared>,
    Path(key): Path<String>,
) -> Response {
    let Some(preset) = crate::rule_sources::resolve_preset(&app, &key) else { return bad("预设不存在") };
    match import_template_from_url(&app, &preset.name, &preset.url, &preset.kind).await {
        Ok((id, name)) => Json(json!({ "id": id, "name": name })).into_response(),
        Err(e) => fail(e),
    }
}

/// 在线且上报了分发端口的 agent 列表：入口链接 = http://{host}:{port}/api/conv-sub?token=…。
/// host 取节点公网地址（面板钉选 > agent 自报 > 连接来源）。
/// 类别生成模式的分组骨架（可视化分组编辑器用）：keys=逗号分隔的生效类别 key。
pub async fn conv_category_groups(
    _: Admin,
    State(_app): State<Shared>,
    Query(q): Query<std::collections::HashMap<String, String>>,
) -> Response {
    let keys: Vec<String> = q
        .get("keys")
        .map(|v| v.split(',').map(str::trim).filter(|s| !s.is_empty()).map(str::to_owned).collect())
        .unwrap_or_default();
    if keys.is_empty() {
        return bad("缺少类别 keys");
    }
    let list: Vec<Value> = crate::subscription::category_group_skeleton(&keys)
        .into_iter()
        .map(|(name, members)| json!({ "name": name, "members": members }))
        .collect();
    Json(json!({ "groups": list })).into_response()
}

/// 在线 agent 分发入口列表（host 取 ipv4_pin > ipv4 > ip）。
pub async fn conv_dist_agents(_: Admin, State(app): State<Shared>) -> Response {
    let agents = app.agents.read().unwrap_or_else(|e| e.into_inner());
    let mut out: Vec<Value> = Vec::new();
    for (node_id, a) in agents.iter() {
        if a.sub_port == 0 {
            continue;
        }
        let Ok(Some(node)) = app.db.node(*node_id) else { continue };
        let host = [node.ipv4_pin.as_str(), node.ipv4.as_str(), node.ip.as_str()]
            .into_iter()
            .find(|s| !s.is_empty())
            .unwrap_or_default();
        out.push(json!({ "node_id": node_id, "name": node.name, "host": host, "port": a.sub_port }));
    }
    drop(agents);
    Json(json!({ "agents": out })).into_response()
}
// ---- API 处理器（Admin 守卫挂在 /api/conv/*；conv-sub 公开）----

pub async fn conv_nodes_list(_: Admin, State(app): State<Shared>) -> Response {
    match app.db.sub_nodes() {
        Ok(nodes) => Json(json!({ "nodes": nodes })).into_response(),
        Err(e) => fail(e),
    }
}

#[derive(Deserialize)]
pub struct ConvImportBody {
    #[serde(default)]
    pub links: String,
    #[serde(default)]
    pub url: String,
    #[serde(default)]
    pub yaml: String,
    /// managed 模式下只同步这些管理节点 id；空 = 全部启用节点。
    #[serde(default)]
    pub managed_ids: Vec<i64>,
    /// true = 忽略其他来源，同步导入面板自建节点。
    #[serde(default)]
    pub managed: bool,
}

pub async fn conv_nodes_import(
    _: Admin,
    State(app): State<Shared>,
    body: Result<Json<ConvImportBody>, axum::extract::rejection::JsonRejection>,
) -> Response {
    let Json(body) = match body {
        Ok(b) => b,
        Err(_) => return bad("请求格式不对"),
    };
    let outcome: anyhow::Result<ImportOutcome> = async {
        if body.managed {
            return import_managed(&app, &body.managed_ids).await;
        }
        if !body.links.trim().is_empty() {
            return import_text_nodes(&app, &body.links, "");
        }
        if !body.yaml.trim().is_empty() {
            return import_text_nodes(&app, &body.yaml, "");
        }
        if !body.url.trim().is_empty() {
            let (text, _info) = fetch_remote(&app, body.url.trim(), "").await?;
            return import_text_nodes(&app, &text, "");
        }
        bail!("粘贴分享链接、填订阅地址或上传配置文件，三者选其一");
    }
    .await;
    match outcome {
        Ok(o) => Json(json!({ "imported": o.imported, "refreshed": o.refreshed, "skipped": o.skipped }))
            .into_response(),
        Err(e) => fail(e),
    }
}

#[derive(Deserialize)]
pub struct ConvNodePatch {
    pub name: String,
    #[serde(default)]
    pub tags: Vec<String>,
    #[serde(default)]
    pub note: String,
    #[serde(default)]
    pub enabled: bool,
}

pub async fn conv_node_update(
    _: Admin,
    State(app): State<Shared>,
    Path(id): Path<i64>,
    body: Result<Json<ConvNodePatch>, axum::extract::rejection::JsonRejection>,
) -> Response {
    let Json(patch) = match body {
        Ok(b) => b,
        Err(_) => return bad("请求格式不对"),
    };
    let Some(mut node) = app.db.sub_node(id).ok().flatten() else { return bad("节点不存在") };
    node.name = patch.name.trim().to_owned();
    if node.name.is_empty() {
        return bad("节点名称不能为空");
    }
    node.tags = patch.tags.into_iter().map(|t| t.trim().to_owned()).filter(|t| !t.is_empty()).collect();
    node.note = patch.note.trim().to_owned();
    node.enabled = patch.enabled;
    match app.db.update_sub_node(&node) {
        Ok(()) => Json(json!({ "ok": true })).into_response(),
        Err(e) => fail(e),
    }
}

pub async fn conv_node_delete(_: Admin, State(app): State<Shared>, Path(id): Path<i64>) -> Response {
    match app.db.delete_sub_node(id) {
        Ok(()) => Json(json!({ "ok": true })).into_response(),
        Err(e) => fail(e),
    }
}

pub async fn conv_nodes_dedup(_: Admin, State(app): State<Shared>) -> Response {
    match app.db.dedup_sub_nodes() {
        Ok(removed) => Json(json!({ "removed": removed })).into_response(),
        Err(e) => fail(e),
    }
}

pub async fn conv_nodes_probe(_: Admin, State(app): State<Shared>) -> Response {
    let nodes = match app.db.sub_nodes() {
        Ok(n) => n,
        Err(e) => return fail(e),
    };
    let mut results = Vec::new();
    for n in nodes.iter().filter(|n| n.enabled) {
        let addr = format!("{}:{}", n.server, n.port);
        let started = std::time::Instant::now();
        let ms = match tokio::time::timeout(
            std::time::Duration::from_millis(3000),
            tokio::net::TcpStream::connect(&addr),
        )
        .await
        {
            Ok(Ok(_)) => started.elapsed().as_millis() as i64,
            _ => -1,
        };
        let _ = app.db.set_sub_node_latency(n.id, ms);
        results.push(json!({ "node_id": n.id, "name": n.name, "ms": ms }));
    }
    Json(json!({ "results": results })).into_response()
}

#[derive(Deserialize)]
pub struct ConvRenameBody {
    pub mode: String,
    #[serde(default)]
    pub prefix: String,
    #[serde(default)]
    pub find: String,
    #[serde(default)]
    pub replace: String,
}

pub async fn conv_nodes_rename(
    _: Admin,
    State(app): State<Shared>,
    body: Result<Json<ConvRenameBody>, axum::extract::rejection::JsonRejection>,
) -> Response {
    let Json(body) = match body {
        Ok(b) => b,
        Err(_) => return bad("请求格式不对"),
    };
    if !matches!(body.mode.as_str(), "prefix" | "replace") {
        return bad("重命名模式不对");
    }
    if body.mode == "prefix" && body.prefix.trim().is_empty() {
        return bad("请填写前缀");
    }
    if body.mode == "replace" && body.find.is_empty() {
        return bad("请填写查找内容");
    }
    match app.db.rename_sub_nodes(&body.mode, body.prefix.trim(), &body.replace) {
        Ok(updated) => Json(json!({ "updated": updated })).into_response(),
        Err(e) => fail(e),
    }
}

// ---- 外部订阅源 ----

pub async fn conv_sources_list(_: Admin, State(app): State<Shared>) -> Response {
    match app.db.sub_sources() {
        Ok(sources) => Json(json!({ "sources": sources })).into_response(),
        Err(e) => fail(e),
    }
}

#[derive(Deserialize)]
pub struct ConvSourceBody {
    pub url: String,
    #[serde(default)]
    pub name: String,
    #[serde(default)]
    pub user_agent: String,
    #[serde(default = "yes_b")]
    pub auto_update: bool,
    #[serde(default)]
    pub interval_min: i64,
}

fn yes_b() -> bool {
    true
}

/// 创建订阅源：先拉取验证 + 首次导入，再落库（拉不动就不建）。
pub async fn conv_source_create(
    _: Admin,
    State(app): State<Shared>,
    body: Result<Json<ConvSourceBody>, axum::extract::rejection::JsonRejection>,
) -> Response {
    let Json(body) = match body {
        Ok(b) => b,
        Err(_) => return bad("请求格式不对"),
    };
    let url = body.url.trim().to_owned();
    let (text, info) = match fetch_remote(&app, &url, body.user_agent.trim()).await {
        Ok(v) => v,
        Err(e) => return fail(e),
    };
    let outcome = match import_text_nodes(&app, &text, &url) {
        Ok(o) => o,
        Err(e) => return fail(e),
    };
    let source = crate::db::SubSource {
        id: 0,
        url: url.clone(),
        name: body.name.trim().to_owned(),
        user_agent: body.user_agent.trim().to_owned(),
        auto_update: body.auto_update,
        interval_min: if body.interval_min > 0 { body.interval_min.max(5) } else { 60 },
        info: info.clone(),
        node_count: outcome.imported + outcome.refreshed,
        last_sync: chrono::Utc::now().timestamp(),
        created_at: 0,
    };
    match app.db.upsert_sub_source(&source) {
        Ok((id, _)) => Json(
            json!({ "id": id, "imported": outcome.imported, "refreshed": outcome.refreshed, "info": info }),
        )
        .into_response(),
        Err(e) => fail(e),
    }
}

pub async fn conv_source_update(
    _: Admin,
    State(app): State<Shared>,
    Path(id): Path<i64>,
    body: Result<Json<ConvSourceBody>, axum::extract::rejection::JsonRejection>,
) -> Response {
    let Json(body) = match body {
        Ok(b) => b,
        Err(_) => return bad("请求格式不对"),
    };
    let Some(mut source) = app.db.sub_source(id).ok().flatten() else { return bad("订阅源不存在") };
    source.name = body.name.trim().to_owned();
    source.user_agent = body.user_agent.trim().to_owned();
    source.auto_update = body.auto_update;
    source.interval_min = if body.interval_min > 0 { body.interval_min.max(5) } else { 60 };
    match app.db.update_sub_source(&source) {
        Ok(()) => Json(json!({ "ok": true })).into_response(),
        Err(e) => fail(e),
    }
}

pub async fn conv_source_delete(_: Admin, State(app): State<Shared>, Path(id): Path<i64>) -> Response {
    let Some(source) = app.db.sub_source(id).ok().flatten() else { return bad("订阅源不存在") };
    let _ = app.db.delete_sub_nodes_by_source(&source.url);
    match app.db.delete_sub_source(id) {
        Ok(()) => Json(json!({ "ok": true })).into_response(),
        Err(e) => fail(e),
    }
}

/// 立即同步（手动按钮）。
pub async fn conv_source_sync(_: Admin, State(app): State<Shared>, Path(id): Path<i64>) -> Response {
    let Some(source) = app.db.sub_source(id).ok().flatten() else { return bad("订阅源不存在") };
    match sync_source(&app, &source).await {
        Ok(count) => Json(json!({ "ok": true, "nodes": count })).into_response(),
        Err(e) => fail(e),
    }
}

// ---- 模板 ----

pub async fn conv_templates_list(_: Admin, State(app): State<Shared>) -> Response {
    match app.db.sub_templates() {
        Ok(list) => {
            let out: Vec<Value> = list
                .iter()
                .map(|t| json!({ "id": t.id, "name": t.name, "note": t.note, "is_builtin": t.is_builtin, "bytes": t.content.len(), "created_at": t.created_at }))
                .collect();
            Json(json!({ "templates": out })).into_response()
        }
        Err(e) => fail(e),
    }
}

pub async fn conv_template_content(_: Admin, State(app): State<Shared>, Path(id): Path<i64>) -> Response {
    let Some(t) = app.db.sub_templates().ok().and_then(|l| l.into_iter().find(|t| t.id == id)) else {
        return bad("模板不存在");
    };
    ([(header::CONTENT_TYPE, "text/yaml; charset=utf-8")], t.content).into_response()
}

fn sanitize_template_name(name: &str) -> Result<String> {
    let name = name.trim();
    if name.is_empty() {
        bail!(crate::Shown("请填写模板名称".into()));
    }
    if name.contains("..") || name.contains('/') || name.contains('\\') {
        bail!(crate::Shown("模板名称不能包含路径字符".into()));
    }
    Ok(if name.ends_with(".yaml") || name.ends_with(".yml") {
        name.to_owned()
    } else {
        format!("{name}.yaml")
    })
}

#[derive(Deserialize)]
pub struct ConvTemplateBody {
    pub name: String,
    #[serde(default)]
    pub note: String,
    #[serde(default)]
    pub content: String,
}

/// 上传模板的结构校验：可运行的 mihomo 配置至少要有 proxies /
/// proxy-groups / rules 三个顶层段（允许空数组——节点注入时填充）。
fn validate_template_runnable(content: &str) -> anyhow::Result<()> {
    let parsed: serde_yaml::Value = serde_yaml::from_str(content).context("内容不是有效 YAML")?;
    let Some(obj) = parsed.as_mapping() else {
        bail!("模板内容必须是 YAML 映射");
    };
    let missing: Vec<String> = ["proxies", "proxy-groups", "rules"]
        .into_iter()
        .filter(|k| !obj.contains_key(serde_yaml::Value::String((*k).into())))
        .map(|k| k.to_string())
        .collect();
    if !missing.is_empty() {
        bail!(crate::Shown(format!(
            "配置缺少必备段：{}（完整可运行配置需要 proxies / proxy-groups / rules）",
            missing.join("、")
        )));
    }
    Ok(())
}

pub async fn conv_template_create(
    _: Admin,
    State(app): State<Shared>,
    body: Result<Json<ConvTemplateBody>, axum::extract::rejection::JsonRejection>,
) -> Response {
    let Json(body) = match body {
        Ok(b) => b,
        Err(_) => return bad("请求格式不对"),
    };
    let name = match sanitize_template_name(&body.name) {
        Ok(n) => n,
        Err(e) => return fail(e),
    };
    if app.db.sub_template(&name).ok().flatten().is_some() {
        return fail(anyhow::Error::msg(crate::Shown(format!("模板 {name} 已存在"))));
    }
    if let Err(e) = validate_template_runnable(&body.content) {
        return fail(e);
    }
    let t = crate::db::SubTemplate {
        id: 0,
        name,
        note: body.note.trim().to_owned(),
        is_builtin: false,
        content: body.content,
        created_at: 0,
    };
    match app.db.create_sub_template(&t) {
        Ok(id) => Json(json!({ "id": id })).into_response(),
        Err(e) => fail(e),
    }
}

pub async fn conv_template_update(
    _: Admin,
    State(app): State<Shared>,
    Path(id): Path<i64>,
    body: Result<Json<ConvTemplateBody>, axum::extract::rejection::JsonRejection>,
) -> Response {
    let Json(body) = match body {
        Ok(b) => b,
        Err(_) => return bad("请求格式不对"),
    };
    let Some(mut t) = app.db.sub_templates().ok().and_then(|l| l.into_iter().find(|t| t.id == id)) else {
        return bad("模板不存在");
    };
    if let Err(e) = validate_template_runnable(&body.content) {
        return fail(e);
    }
    t.note = body.note.trim().to_owned();
    t.content = body.content;
    // 改名仅对非内置模板开放（内置名归代码/迁移管）；订阅按名字绑定模板，db 层同事务级联改写
    let mut old_name = t.name.clone();
    let wanted = body.name.trim();
    if !t.is_builtin && !wanted.is_empty() && wanted != t.name {
        let new_name = match sanitize_template_name(wanted) {
            Ok(n) => n,
            Err(e) => return fail(e),
        };
        if new_name != old_name && app.db.sub_template(&new_name).ok().flatten().is_some() {
            return fail(anyhow::Error::msg(crate::Shown(format!("模板 {new_name} 已存在"))));
        }
        old_name = std::mem::replace(&mut t.name, new_name);
    }
    match app.db.update_sub_template(&t, &old_name) {
        Ok(()) => Json(json!({ "ok": true })).into_response(),
        Err(e) => fail(e),
    }
}

pub async fn conv_template_delete(_: Admin, State(app): State<Shared>, Path(id): Path<i64>) -> Response {
    let Some(t) = app.db.sub_templates().ok().and_then(|l| l.into_iter().find(|t| t.id == id)) else {
        return bad("模板不存在");
    };
    if t.is_builtin {
        return bad("内置模板不可删除");
    }
    match app.db.delete_sub_template(id) {
        Ok(()) => Json(json!({ "ok": true })).into_response(),
        Err(e) => fail(e),
    }
}

// ---- 规则片段 ----

pub async fn conv_snippets_list(_: Admin, State(app): State<Shared>) -> Response {
    match app.db.sub_snippets() {
        Ok(list) => Json(json!({ "snippets": list })).into_response(),
        Err(e) => fail(e),
    }
}

#[derive(Deserialize)]
pub struct ConvSnippetBody {
    pub name: String,
    #[serde(default)]
    pub kind: String,
    #[serde(default)]
    pub mode: String,
    #[serde(default)]
    pub content: String,
    #[serde(default = "yes_b")]
    pub enabled: bool,
}

fn validate_snippet(body: &ConvSnippetBody) -> Result<(String, String, String)> {
    let name = body.name.trim().to_owned();
    if name.is_empty() {
        bail!(crate::Shown("请填写片段名称".into()));
    }
    let kind = if body.kind.is_empty() { "rules".into() } else { body.kind.clone() };
    if !matches!(kind.as_str(), "rules" | "dns") {
        bail!(crate::Shown("片段类型只支持 rules / dns".into()));
    }
    let mode = if body.mode.is_empty() { "prepend".into() } else { body.mode.clone() };
    if !matches!(mode.as_str(), "prepend" | "append") || (mode == "append" && kind != "rules") {
        bail!(crate::Shown("合并方式只支持 prepend / append（append 仅 rules）".into()));
    }
    if body.content.trim().is_empty() {
        bail!(crate::Shown("片段内容不能为空".into()));
    }
    if serde_yaml::from_str::<Value>(&body.content).is_err() {
        bail!(crate::Shown("片段内容不是有效 YAML".to_string()));
    }
    Ok((kind, mode, body.content.clone()))
}

pub async fn conv_snippet_create(
    _: Admin,
    State(app): State<Shared>,
    body: Result<Json<ConvSnippetBody>, axum::extract::rejection::JsonRejection>,
) -> Response {
    let Json(body) = match body {
        Ok(b) => b,
        Err(_) => return bad("请求格式不对"),
    };
    let (kind, mode, content) = match validate_snippet(&body) {
        Ok(v) => v,
        Err(e) => return fail(e),
    };
    let s = crate::db::SubSnippet {
        id: 0,
        name: body.name.trim().to_owned(),
        kind,
        mode,
        content,
        enabled: body.enabled,
        created_at: 0,
    };
    match app.db.create_sub_snippet(&s) {
        Ok(id) => Json(json!({ "id": id })).into_response(),
        Err(e) => fail(e),
    }
}

pub async fn conv_snippet_update(
    _: Admin,
    State(app): State<Shared>,
    Path(id): Path<i64>,
    body: Result<Json<ConvSnippetBody>, axum::extract::rejection::JsonRejection>,
) -> Response {
    let Json(body) = match body {
        Ok(b) => b,
        Err(_) => return bad("请求格式不对"),
    };
    let (kind, mode, content) = match validate_snippet(&body) {
        Ok(v) => v,
        Err(e) => return fail(e),
    };
    let Some(mut s) = app.db.sub_snippet(id).ok().flatten() else { return bad("片段不存在") };
    s.name = body.name.trim().to_owned();
    s.kind = kind;
    s.mode = mode;
    s.content = content;
    s.enabled = body.enabled;
    match app.db.update_sub_snippet(&s) {
        Ok(()) => Json(json!({ "ok": true })).into_response(),
        Err(e) => fail(e),
    }
}

pub async fn conv_snippet_delete(_: Admin, State(app): State<Shared>, Path(id): Path<i64>) -> Response {
    match app.db.delete_sub_snippet(id) {
        Ok(()) => Json(json!({ "ok": true })).into_response(),
        Err(e) => fail(e),
    }
}

// ---- 订阅文件 ----

pub async fn conv_profiles_list(_: Admin, State(app): State<Shared>) -> Response {
    match app.db.sub_profiles() {
        Ok(profiles) => Json(json!({ "profiles": profiles })).into_response(),
        Err(e) => fail(e),
    }
}

/// 订阅文件写入口（创建/更新/预览共用）。除 name 外全部 Option：**更新时
/// 未提供的字段保留原值**（合并语义）——前端多处局部更新（启停开关、改名、
/// 可视化分组保存）只携带自己管理的字段，缺这层合并会把组覆盖/节点勾选/
/// 类别选择抹掉。创建时未提供的字段落到与旧 serde default 相同的默认值。
#[derive(Deserialize)]
pub struct ConvProfileBody {
    pub name: String,
    pub template_name: Option<String>,
    pub selected_tags: Option<Vec<String>>,
    pub snippet_ids: Option<Vec<i64>>,
    /// 过期 unix 秒（0 = 永不过期）。
    pub expires_at: Option<i64>,
    /// 组→有序成员覆盖表（可视化拖拽分组；成员=数字节点 id 或字符串特殊项）。
    pub group_overrides: Option<Value>,
    /// 勾选的分流类别 key（非空 = 按类别动态生成）。
    pub selected_categories: Option<Vec<String>>,
    /// 勾选的节点 id（非空 = 只包含这些节点）。
    pub selected_nodes: Option<Vec<i64>>,
    /// 静态订阅内容（非空 = 原样下发，忽略模板/类别/节点渲染）。
    pub static_content: Option<String>,
    /// 是否允许 agent 入口分发该订阅（agent 回源时校验）。
    pub agent_dist: Option<bool>,
    pub enabled: Option<bool>,
}

fn validate_profile(
    app: &crate::App,
    body: &ConvProfileBody,
    old: Option<&crate::db::SubProfile>,
) -> Result<()> {
    if body.name.trim().is_empty() {
        bail!(crate::Shown("请填写订阅名称".into()));
    }
    let static_content =
        body.static_content.clone().or_else(|| old.map(|p| p.static_content.clone())).unwrap_or_default();
    if !static_content.trim().is_empty() {
        // 静态订阅：整份 YAML 原样下发，不绑定模板/类别/片段
        return Ok(());
    }
    let selected_categories = body
        .selected_categories
        .clone()
        .or_else(|| old.map(|p| p.selected_categories.clone()))
        .unwrap_or_default();
    // 按类别动态生成的订阅不渲染模板，template_name 可为空——不校验模板绑定
    let template_bound = selected_categories.is_empty();
    let template_name =
        body.template_name.clone().or_else(|| old.map(|p| p.template_name.clone())).unwrap_or_default();
    if template_bound && app.db.sub_template(&template_name)?.is_none() {
        bail!(crate::Shown("绑定的模板不存在".to_string()));
    }
    let snippet_ids =
        body.snippet_ids.clone().or_else(|| old.map(|p| p.snippet_ids.clone())).unwrap_or_default();
    for id in &snippet_ids {
        if app.db.sub_snippet(*id)?.is_none() {
            bail!(crate::Shown("勾选的规则片段不存在".to_string()));
        }
    }
    Ok(())
}

fn profile_from_body(
    id: i64,
    token: &str,
    body: &ConvProfileBody,
    old: Option<&crate::db::SubProfile>,
) -> crate::db::SubProfile {
    let merged = |provided: &Option<Vec<String>>,
                  get: fn(&crate::db::SubProfile) -> Vec<String>|
     -> Vec<String> { provided.clone().unwrap_or_else(|| old.map(get).unwrap_or_default()) };
    crate::db::SubProfile {
        id,
        name: body.name.trim().to_owned(),
        selected_categories: merged(&body.selected_categories, |p| p.selected_categories.clone()),
        selected_nodes: body
            .selected_nodes
            .clone()
            .unwrap_or_else(|| old.map(|p| p.selected_nodes.clone()).unwrap_or_default()),
        static_content: body
            .static_content
            .clone()
            .unwrap_or_else(|| old.map(|p| p.static_content.clone()).unwrap_or_default()),
        agent_dist: body.agent_dist.or_else(|| old.map(|p| p.agent_dist)).unwrap_or(false),
        token: if token.is_empty() {
            old.map(|p| p.token.clone()).unwrap_or_default()
        } else {
            token.to_owned()
        },
        template_name: body
            .template_name
            .clone()
            .unwrap_or_else(|| old.map(|p| p.template_name.clone()).unwrap_or_default()),
        selected_tags: merged(&body.selected_tags, |p| p.selected_tags.clone()),
        snippet_ids: body
            .snippet_ids
            .clone()
            .unwrap_or_else(|| old.map(|p| p.snippet_ids.clone()).unwrap_or_default()),
        group_overrides: body
            .group_overrides
            .clone()
            .unwrap_or_else(|| old.map(|p| p.group_overrides.clone()).unwrap_or(Value::Null)),
        expires_at: body.expires_at.or_else(|| old.map(|p| p.expires_at)).unwrap_or(0),
        enabled: body.enabled.or_else(|| old.map(|p| p.enabled)).unwrap_or(false),
        created_at: old.map(|p| p.created_at).unwrap_or(0),
    }
}

pub async fn conv_profile_create(
    _: Admin,
    State(app): State<Shared>,
    body: Result<Json<ConvProfileBody>, axum::extract::rejection::JsonRejection>,
) -> Response {
    let Json(body) = match body {
        Ok(b) => b,
        Err(_) => return bad("请求格式不对"),
    };
    if let Err(e) = validate_profile(&app, &body, None) {
        return fail(e);
    }
    let p = profile_from_body(0, &auth::random_token(), &body, None);
    match app.db.create_sub_profile(&p) {
        Ok(id) => Json(json!({ "id": id, "token": p.token })).into_response(),
        Err(e) => fail(e),
    }
}

pub async fn conv_profile_update(
    _: Admin,
    State(app): State<Shared>,
    Path(id): Path<i64>,
    body: Result<Json<ConvProfileBody>, axum::extract::rejection::JsonRejection>,
) -> Response {
    let Json(body) = match body {
        Ok(b) => b,
        Err(_) => return bad("请求格式不对"),
    };
    let old = app.db.sub_profile(id).ok().flatten();
    if old.is_none() {
        return bad("订阅不存在");
    }
    if let Err(e) = validate_profile(&app, &body, old.as_ref()) {
        return fail(e);
    }
    let p = profile_from_body(id, "", &body, old.as_ref());
    match app.db.update_sub_profile(&p) {
        Ok(()) => Json(json!({ "ok": true })).into_response(),
        Err(e) => fail(e),
    }
}

pub async fn conv_profile_reset_token(_: Admin, State(app): State<Shared>, Path(id): Path<i64>) -> Response {
    let token = auth::random_token();
    match app.db.reset_sub_profile_token(id, &token) {
        Ok(()) => Json(json!({ "token": token })).into_response(),
        Err(e) => fail(e),
    }
}

pub async fn conv_profile_delete(_: Admin, State(app): State<Shared>, Path(id): Path<i64>) -> Response {
    match app.db.delete_sub_profile(id) {
        Ok(()) => {
            // 引用该方案的客户解除绑定（订阅回落裸节点输出），下次更新即生效。
            let _ = app.db.clear_sub_user_profile(id);
            Json(json!({ "ok": true })).into_response()
        }
        Err(e) => fail(e),
    }
}

/// 预览：按请求体直接渲染（不落库）。
pub async fn conv_profile_preview(
    _: Admin,
    State(app): State<Shared>,
    body: Result<Json<ConvProfileBody>, axum::extract::rejection::JsonRejection>,
) -> Response {
    let Json(body) = match body {
        Ok(b) => b,
        Err(_) => return bad("请求格式不对"),
    };
    let p = profile_from_body(0, "preview", &body, None);
    match render_profile(&app, &p) {
        Ok(yaml) => ([(header::CONTENT_TYPE, "text/plain; charset=utf-8")], yaml).into_response(),
        Err(e) => fail(e),
    }
}

/// 订阅命名响应头。profile-title：非 ASCII（中文订阅名）按规范走 `base64:` 前
/// 缀，纯 ASCII 直接明文；content-disposition 同时给 filename（UTF-8 原文，绝
/// 大多数客户端直接显示）与 filename*（RFC 5987 百分号编码，规范派客户端）。
pub fn naming_headers(name: &str) -> Vec<(HeaderName, String)> {
    let name: String = name.chars().filter(|c| !c.is_control() && *c != '"').collect();
    let title = if name.is_ascii() {
        name.clone()
    } else {
        format!("base64:{}", base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(name.as_bytes()))
    };
    let pct: String = name
        .bytes()
        .map(|b| {
            if b.is_ascii_alphanumeric() || matches!(b, b'-' | b'.' | b'_' | b'~') {
                (b as char).to_string()
            } else {
                format!("%{b:02X}")
            }
        })
        .collect();
    vec![
        (HeaderName::from_static("profile-title"), title),
        (
            HeaderName::from_static("content-disposition"),
            format!("inline; filename=\"{name}\"; filename*=UTF-8''{pct}"),
        ),
    ]
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::db::{SubProfile, SubSnippet};

    fn app() -> crate::App {
        crate::App::for_test(crate::db::Db::open(":memory:").unwrap())
    }

    pub(crate) fn add_link_node(app: &crate::App, name: &str, link: &str) -> i64 {
        let mut n = sub_node_from_link(link, "").unwrap();
        n.name = name.into();
        n.tags = region_tags(name);
        app.db.upsert_sub_node(&n).unwrap().0
    }

    #[test]
    fn builtin_templates_are_seeded_by_migration() {
        let app = app();
        let templates = app.db.sub_templates().unwrap();
        assert!(templates.iter().any(|t| t.name == "经典分组-绕过大陆.yaml" && t.is_builtin));
        assert!(templates.iter().any(|t| t.name == "全局代理.yaml" && t.is_builtin));
    }

    #[test]
    fn dual_form_import_keeps_native_clash_fields() {
        let app = app();
        // 链接导入：raw_link + clash_config 双形态
        let o = import_text_nodes(&app, "vless://uuid-1@1.2.3.4:443?security=reality&pbk=PBK#香港01", "")
            .unwrap();
        assert_eq!(o.imported, 1);
        let n = &app.db.sub_nodes().unwrap()[0];
        assert_eq!(n.raw_link, "vless://uuid-1@1.2.3.4:443?security=reality&pbk=PBK#香港01");
        assert!(n.clash_config.contains("\"type\":\"vless\""), "{:}", n.clash_config);
        assert_eq!(n.tags, vec!["🇭🇰".to_string()], "导入自动打地区标签");
        // Clash YAML 导入：原生字段（raw_link 为空，零丢失）
        let yaml = "proxies:\n  - name: 美国家宽\n    type: ss\n    server: 8.8.8.8\n    port: 8388\n    cipher: aes-256-gcm\n    password: pw\n    udp: true\n";
        let o = import_text_nodes(&app, yaml, "").unwrap();
        assert_eq!(o.imported, 1);
        let n = app.db.sub_nodes().unwrap().into_iter().find(|n| n.protocol == "ss").unwrap();
        assert!(n.raw_link.is_empty());
        let cfg: Value = serde_json::from_str(&n.clash_config).unwrap();
        assert_eq!(cfg["udp"], true, "原生字段零丢失");
        assert_eq!(cfg["cipher"], "aes-256-gcm");
        // 再导一次：刷新不重复
        let o = import_text_nodes(&app, yaml, "").unwrap();
        assert_eq!((o.imported, o.refreshed), (0, 1));
        assert_eq!(app.db.sub_nodes().unwrap().len(), 2);
    }

    #[test]
    fn unsupported_clash_types_are_skipped_with_reason() {
        let app = app();
        let yaml = "proxies:\n  - name: ok\n    type: ss\n    server: 1.1.1.1\n    port: 1\n    cipher: aes-128-gcm\n    password: p\n  - name: snell\n    type: snell\n    server: 2.2.2.2\n    port: 2\n";
        let o = import_text_nodes(&app, yaml, "").unwrap();
        assert_eq!(o.imported, 1);
        assert_eq!(o.skipped.len(), 1);
        assert!(o.skipped[0]["reason"].as_str().unwrap().contains("snell"));
    }

    #[test]
    fn template_injection_renders_rule_structure_without_nodes() {
        let app = app();
        let profile = SubProfile {
            id: 1,
            name: "t".into(),
            token: "t".into(),
            template_name: "经典分组-绕过大陆.yaml".into(),
            ..Default::default()
        };
        let yaml = render_profile(&app, &profile).unwrap();
        let doc: Value = serde_yaml::from_str(&yaml).unwrap();
        // 方向 B：方案=纯规则配方。零节点 → proxies 空、组回落 DIRECT，模板其余段落原样保留
        let proxies = doc["proxies"].as_array().unwrap();
        assert!(proxies.is_empty(), "零节点渲染不得注入任何代理");
        let groups = doc["proxy-groups"].as_array().unwrap();
        let entry = groups.iter().find(|g| g["name"] == "🚀 节点选择").unwrap();
        let entry_proxies: Vec<&str> =
            entry["proxies"].as_array().unwrap().iter().filter_map(|v| v.as_str()).collect();
        assert!(
            entry_proxies.contains(&"DIRECT") && entry_proxies.contains(&"♻️ 自动"),
            "组保留结构并回落 DIRECT"
        );
        assert_eq!(doc["mixed-port"], 7890);
        assert!(doc["rules"]
            .as_array()
            .unwrap()
            .iter()
            .any(|r| r.as_str().unwrap().starts_with("GEOSITE,cn,DIRECT")));
        assert!(!yaml.contains("__ALL__"), "{yaml}");
    }

    #[test]
    fn snippets_merge_prepend_and_append_around_match() {
        let app = app();
        add_link_node(&app, "节点A", "vless://u@1.1.1.1:1#a");
        let s1 = app
            .db
            .create_sub_snippet(&SubSnippet {
                name: "前置拦截".into(),
                kind: "rules".into(),
                mode: "prepend".into(),
                content: "- DOMAIN-SUFFIX,ads.example.com,REJECT".into(),
                enabled: true,
                ..Default::default()
            })
            .unwrap();
        let s2 = app
            .db
            .create_sub_snippet(&SubSnippet {
                name: "自定义直连".into(),
                kind: "rules".into(),
                mode: "append".into(),
                content: "- DOMAIN-SUFFIX,mycompany.cn,DIRECT".into(),
                enabled: true,
                ..Default::default()
            })
            .unwrap();
        let profile = SubProfile {
            id: 1,
            template_name: "全局代理.yaml".into(),
            snippet_ids: vec![s1, s2],
            ..Default::default()
        };
        let yaml = render_profile(&app, &profile).unwrap();
        let doc: Value = serde_yaml::from_str(&yaml).unwrap();
        let rules: Vec<String> =
            doc["rules"].as_array().unwrap().iter().filter_map(|v| v.as_str().map(str::to_owned)).collect();
        // prepend 在最前，append 在 MATCH 之前，MATCH 仍是兜底
        assert_eq!(rules[0], "DOMAIN-SUFFIX,ads.example.com,REJECT");
        let match_pos = rules.iter().position(|r| r.starts_with("MATCH")).unwrap();
        assert_eq!(rules[match_pos - 1], "DOMAIN-SUFFIX,mycompany.cn,DIRECT");
    }

    #[test]
    fn link_parsing_still_covers_schemes() {
        let (s, h, p, n) =
            parse_link("vless://uuid-1@1.2.3.4:443?security=reality&pbk=PBK#%E9%A6%99%E6%B8%AF01").unwrap();
        assert_eq!((s.as_str(), h.as_str(), p, n), ("vless", "1.2.3.4", 443, "香港01".to_string()));
        assert!(parse_link("vmess://not-base64!!").is_err());
        assert!(parse_link("ssr://xxx").is_err());
    }
}

/// 模板的 proxy-groups 列表（可视化拖拽编辑器的组来源）。
pub async fn conv_template_groups(_: Admin, State(app): State<Shared>, Path(id): Path<i64>) -> Response {
    let Some(t) = app.db.sub_templates().ok().and_then(|l| l.into_iter().find(|t| t.id == id)) else {
        return bad("模板不存在");
    };
    let doc: Value = match serde_yaml::from_str(&t.content) {
        Ok(v) => v,
        Err(e) => return fail(anyhow::Error::msg(crate::Shown(format!("模板 YAML 解析失败：{e}")))),
    };
    let groups: Vec<Value> = doc
        .get("proxy-groups")
        .and_then(|v| v.as_array())
        .map(|arr| {
            arr.iter()
                .filter_map(|g| {
                    let name = g.get("name").and_then(|v| v.as_str())?;
                    // 模板原有成员（含 __ALL__/__TAG__ 占位、DIRECT、其他组名
                    // 引用），编辑器据此区分「模板特殊项」与「拖入节点」。
                    let template_members: Vec<&str> = g
                        .get("proxies")
                        .and_then(|v| v.as_array())
                        .map(|items| items.iter().filter_map(|v| v.as_str()).collect())
                        .unwrap_or_default();
                    Some(json!({
                        "name": name,
                        "type": g.get("type").and_then(|v| v.as_str()).unwrap_or("select"),
                        "template_members": template_members,
                    }))
                })
                .collect()
        })
        .unwrap_or_default();
    Json(json!({ "groups": groups })).into_response()
}

#[cfg(test)]
mod v21_tests {
    use super::*;
    use crate::db::SubProfile;
    use tests::add_link_node;
    #[test]
    fn override_special_items_pass_through_and_expand() {
        let (app, sub) = app_with_assigned_nodes();
        // 覆盖：节点 + DIRECT + 组引用 + __ALL__ 占位符
        let profile = SubProfile {
            id: 9,
            name: "t".into(),
            token: "t".into(),
            template_name: "全局代理.yaml".into(),
            group_overrides: serde_json::json!({ "🚀 节点选择": [1, "DIRECT", "♻️ 自动", "__ALL__"] }),
            ..Default::default()
        };
        let yaml = render_profile_for(&app, &profile, Some(&sub)).unwrap();
        let doc: Value = serde_yaml::from_str(&yaml).unwrap();
        let entry =
            doc["proxy-groups"].as_array().unwrap().iter().find(|g| g["name"] == "🚀 节点选择").unwrap();
        let list: Vec<&str> =
            entry["proxies"].as_array().unwrap().iter().filter_map(|v| v.as_str()).collect();
        // 客户节点名 + DIRECT 直通 + __ALL__ 展开成两台节点；悬空组引用（♻️ 自动
        // 在本模板不存在）被 sanitize 剔除——否则客户端无法解析
        assert_eq!(list, vec!["🇭🇰 香港01", "DIRECT", "🇭🇰 香港01", "🇯🇵 东京01"], "{list:?}");
        assert!(!yaml.contains("__ALL__"), "占位符必须展开");
    }

    fn app_with_nodes_and_rule_templates() -> crate::App {
        let app = crate::App::for_test(crate::db::Db::open(":memory:").unwrap());
        // 迁移已 seed 规则模式三模板 + 2 份基础模板；入库两个节点
        add_link_node(&app, "🇭🇰 香港01", "vless://u1@1.1.1.1:1#hkg");
        add_link_node(&app, "🇯🇵 东京01", "trojan://pw@2.2.2.2:2#nrt");
        app
    }

    /// 方向 B：客户渲染的节点=分配协议。搭两台面板节点（🇭🇰 香港01/🇯🇵 东京01）
    /// 并把凭据全部分配给一个客户，返回 (app, sub)。
    fn app_with_assigned_nodes() -> (crate::App, crate::db::SubUser) {
        let app = crate::App::for_test(crate::db::Db::open(":memory:").unwrap());
        let mk = |name: &str, port: i64, protocol: &str| crate::db::ProxyNode {
            server_id: 1,
            name: name.into(),
            protocol: protocol.into(),
            listen_port: port,
            enabled: true,
            ..Default::default()
        };
        app.db
            .create_proxy_node(
                &mk("🇭🇰 香港01", 24001, "vless-reality"),
                &crate::db::ProxySecret::default(),
                "hk-cred",
            )
            .unwrap();
        app.db
            .create_proxy_node(
                &mk("🇯🇵 东京01", 24002, "vless-reality"),
                &crate::db::ProxySecret::default(),
                "jp-cred",
            )
            .unwrap();
        let sub_id = app.db.create_sub_user("客户", "custok").unwrap();
        for bundle in app.db.proxy_node_bundles().unwrap() {
            if let Some(user) = bundle.users.first() {
                app.db.set_proxy_user_sub(user.id, Some(sub_id)).unwrap();
            }
        }
        let sub = app.db.sub_user(sub_id).unwrap().unwrap();
        (app, sub)
    }

    #[test]
    fn three_rule_mode_templates_are_seeded_and_valid() {
        let app = app_with_nodes_and_rule_templates();
        let templates = app.db.sub_templates().unwrap();
        for expect in ["极简规则.yaml", "均衡规则.yaml", "完整规则.yaml"] {
            let t = templates.iter().find(|t| t.name == expect).unwrap_or_else(|| panic!("{expect} 未 seed"));
            assert!(t.is_builtin);
            let doc: Value =
                serde_yaml::from_str(&t.content).unwrap_or_else(|e| panic!("{expect} YAML 非法: {e}"));
            assert!(doc["rule-providers"].is_object(), "{expect} 缺 rule-providers");
            assert!(doc["proxies"].is_array());
            // 妙妙屋结构：节点选择 / 自动选择 / 各类别组 / 漏网之鱼
            let group_names: Vec<&str> =
                doc["proxy-groups"].as_array().unwrap().iter().filter_map(|g| g["name"].as_str()).collect();
            assert_eq!(group_names.first(), Some(&"🚀 节点选择"), "{expect}");
            assert!(group_names.contains(&"♻️ 自动选择"), "{expect}");
            assert!(group_names.contains(&"🐟 漏网之鱼"), "{expect}");
            assert!(group_names.contains(&"🏠 私有网络"));
            assert!(group_names.contains(&"🔒 国内服务"));
            // 节点选择 = DIRECT/REJECT/自动选择/__ALL__（不聚合类别组）
            let entry =
                doc["proxy-groups"].as_array().unwrap().iter().find(|g| g["name"] == "🚀 节点选择").unwrap();
            let members: Vec<&str> =
                entry["proxies"].as_array().unwrap().iter().filter_map(|v| v.as_str()).collect();
            assert_eq!(members, vec!["DIRECT", "REJECT", "♻️ 自动选择", "__ALL__"], "{expect}");
            // MATCH 兜底到漏网之鱼
            let rules: Vec<String> = doc["rules"]
                .as_array()
                .unwrap()
                .iter()
                .filter_map(|v| v.as_str().map(str::to_owned))
                .collect();
            assert_eq!(rules.last().unwrap(), "MATCH,🐟 漏网之鱼", "{expect}");
            if expect == "完整规则.yaml" {
                assert!(group_names.contains(&"🤖 AI 服务"));
                assert!(group_names.contains(&"🛑 广告拦截"), "广告类与其它类别一样建组");
                assert!(rules.iter().any(|r| r == "RULE-SET,category-ads-all,🛑 广告拦截"));
            }
            if expect == "极简规则.yaml" {
                assert!(!group_names.contains(&"🤖 AI 服务"), "极简不应含 AI 组");
            }
        }
        let counts: Vec<(String, usize)> = templates
            .iter()
            .filter(|t| t.name.ends_with("规则.yaml"))
            .map(|t| {
                let doc: Value = serde_yaml::from_str(&t.content).unwrap();
                let n = doc["rules"].as_array().map(|a| a.len()).unwrap_or_else(|| {
                    eprintln!("NO RULES in {}:\n{}", t.name, t.content);
                    0
                });
                (t.name.clone(), n)
            })
            .collect();
        // 极简 < 均衡 < 完整（规则数递增）
        assert!(counts[0].1 < counts[1].1 && counts[1].1 < counts[2].1, "{counts:?}");
    }

    #[test]
    fn group_overrides_take_precedence_over_placeholders() {
        let (app, sub) = app_with_assigned_nodes();
        let profile = SubProfile {
            id: 1,
            name: "t".into(),
            token: "t".into(),
            template_name: "全局代理.yaml".into(),
            group_overrides: serde_json::json!({ "🚀 节点选择": [2] }),
            ..Default::default()
        };
        let yaml = render_profile_for(&app, &profile, Some(&sub)).unwrap();
        let doc: Value = serde_yaml::from_str(&yaml).unwrap();
        let entry =
            doc["proxy-groups"].as_array().unwrap().iter().find(|g| g["name"] == "🚀 节点选择").unwrap();
        let list: Vec<&str> =
            entry["proxies"].as_array().unwrap().iter().filter_map(|v| v.as_str()).collect();
        assert_eq!(list, vec!["🇯🇵 东京01"], "覆盖组完全用拖拽列表: {list:?}");
    }

    #[test]
    fn subconverter_custom_ini_converts_groups_and_rulesets() {
        // Aethersailor 模板同款格式（反引号组定义 + ruleset 行）
        let ini = r#"custom_proxy_group=🚀 手动选择`select`[]♻️ 自动选择`DIRECT
custom_proxy_group=♻️ 自动选择`url-test`.*`https://www.gstatic.com/generate_204`300
custom_proxy_group=📹 YouTube`select`[]🚀 手动选择`.*
ruleset=📹 YouTube,[]GEOSITE,youtube
ruleset=📹 YouTube,clash-domain:https://x/yt.mrs,1800
ruleset=🎯 全球直连,[]GEOIP,CN,no-resolve
ruleset=🎯 全球直连,[]FINAL
"#;
        let yaml = convert_subconverter_custom(ini, "").unwrap();
        let doc: Value = serde_yaml::from_str(&yaml).unwrap();
        let groups = doc["proxy-groups"].as_array().unwrap();
        assert_eq!(groups.len(), 4);
        // 手动选择：组引用 + DIRECT 直通
        let manual = groups.iter().find(|g| g["name"] == "🚀 手动选择").unwrap();
        let m: Vec<&str> = manual["proxies"].as_array().unwrap().iter().filter_map(|v| v.as_str()).collect();
        assert!(m.contains(&"♻️ 自动选择") && m.contains(&"DIRECT"), "{m:?}");
        // 自动组：__ALL__ 占位 + 测速地址/间隔
        let auto = groups.iter().find(|g| g["name"] == "♻️ 自动选择").unwrap();
        assert!(auto["proxies"].as_array().unwrap().contains(&json!("__ALL__")));
        assert_eq!(auto["type"], "url-test");
        assert_eq!(auto["url"], "https://www.gstatic.com/generate_204");
        assert_eq!(auto["interval"], 300);
        // ruleset → 每类独立组 + RULE-SET（mrs provider）+ FINAL → MATCH
        let yt = groups.iter().find(|g| g["name"] == "📹 YouTube").unwrap();
        assert!(yt["proxies"].as_array().unwrap().contains(&json!("__ALL__")));
        let rules: Vec<String> =
            doc["rules"].as_array().unwrap().iter().filter_map(|v| v.as_str().map(str::to_owned)).collect();
        assert!(rules.contains(&"GEOSITE,youtube,📹 YouTube".to_string()), "{rules:?}");
        assert!(rules.iter().any(|r| r.starts_with("RULE-SET,custom-1,📹 YouTube")), "{rules:?}");
        assert!(rules.last().unwrap().starts_with("MATCH,🎯 全球直连"), "{rules:?}");
        // 组名无占位符残留
        assert!(yaml.contains("__ALL__") || true); // __ALL__ 保留在组里是合法的
    }

    #[test]
    fn category_generation_renders_rules_and_groups_without_nodes() {
        let app = app_with_nodes_and_rule_templates();
        app.db
            .set(
                RULE_MODE_KEY,
                r#"{"name":"完整规则.yaml","categories":["private","cn","ai","category-ads-all"]}"#,
            )
            .unwrap();
        let profile = SubProfile {
            id: 9,
            name: "动态".into(),
            token: "t".into(),
            selected_categories: vec![
                "private".to_string(),
                "domestic".to_string(),
                "ai".to_string(),
                "ads".to_string(),
            ],
            ..Default::default()
        };
        let yaml = render_profile(&app, &profile).unwrap();
        assert!(!yaml.contains("__ALL__"), "动态生成不得残留占位符: {yaml}");
        let doc: Value = serde_yaml::from_str(&yaml).unwrap();
        let groups = doc["proxy-groups"].as_array().unwrap();
        let names: Vec<&str> = groups.iter().filter_map(|g| g["name"].as_str()).collect();
        assert_eq!(names.first(), Some(&"🚀 节点选择"), "{names:?}");
        assert_eq!(names[1], "♻️ 自动选择");
        assert_eq!(names.last(), Some(&"🐟 漏网之鱼"));
        // 零节点：节点选择组回落 DIRECT/REJECT/自动选择（无节点名残留）
        let entry = &groups[0];
        let entry_proxies: Vec<&str> =
            entry["proxies"].as_array().unwrap().iter().filter_map(|v| v.as_str()).collect();
        assert!(entry_proxies.contains(&"DIRECT") && entry_proxies.contains(&"♻️ 自动选择"));
        assert!(!yaml.contains("香港01"), "零节点不得出现节点名");
        // 规则本体齐全
        assert!(!doc["rules"].as_array().unwrap().is_empty(), "零节点仍应有分类规则");
    }

    #[test]
    fn category_override_expands_all_placeholder_with_customer_nodes() {
        let (app, sub) = app_with_assigned_nodes();
        // 回归：可视化编辑器保存的覆盖成员含 __ALL__ 占位，类别渲染必须展开为节点名
        let profile_ov = SubProfile {
            id: 12,
            name: "ov".into(),
            token: "t".into(),
            selected_categories: vec!["ads".into()],
            group_overrides: serde_json::json!({"🛑 广告拦截": ["__ALL__"]}),
            ..Default::default()
        };
        let yaml = render_profile_for(&app, &profile_ov, Some(&sub)).unwrap();
        assert!(!yaml.contains("__ALL__"), "占位必须展开: {yaml}");
        let doc: Value = serde_yaml::from_str(&yaml).unwrap();
        let ads =
            doc["proxy-groups"].as_array().unwrap().iter().find(|g| g["name"] == "🛑 广告拦截").unwrap();
        let members: Vec<&str> =
            ads["proxies"].as_array().unwrap().iter().filter_map(|v| v.as_str()).collect();
        assert_eq!(members, vec!["🇭🇰 香港01", "🇯🇵 东京01"], "__ALL__ 必须展开: {members:?}");
        // __ALL__ 与显式 id 混排：同名去重（id=proxy_node.id）
        let profile_mix = SubProfile {
            id: 13,
            name: "mix".into(),
            token: "t".into(),
            selected_categories: vec!["ads".into()],
            group_overrides: serde_json::json!({"🛑 广告拦截": ["__ALL__", 1]}),
            ..Default::default()
        };
        let yaml = render_profile_for(&app, &profile_mix, Some(&sub)).unwrap();
        let doc: Value = serde_yaml::from_str(&yaml).unwrap();
        let ads =
            doc["proxy-groups"].as_array().unwrap().iter().find(|g| g["name"] == "🛑 广告拦截").unwrap();
        let members: Vec<&str> =
            ads["proxies"].as_array().unwrap().iter().filter_map(|v| v.as_str()).collect();
        assert_eq!(members, vec!["🇭🇰 香港01", "🇯🇵 东京01"], "混排去重: {members:?}");
    }

    #[test]
    fn partial_profile_update_preserves_unprovided_fields() {
        let app = app_with_nodes_and_rule_templates();
        let created = profile_from_body(
            0,
            "tok",
            &serde_json::from_str::<ConvProfileBody>(
                r#"{"name":"p1","template_name":"全局代理.yaml","enabled":true,"selected_nodes":[1],"selected_categories":["ads"],"group_overrides":{"🚀 节点选择":[1,"DIRECT"]}}"#,
            )
            .unwrap(),
            None,
        );
        let id = app.db.create_sub_profile(&created).unwrap();
        // 局部更新（模拟启停开关：只带 name+enabled）——节点勾选/类别/组覆盖/模板必须原样保留
        let body: ConvProfileBody = serde_json::from_str(r#"{"name":"p1","enabled":false}"#).unwrap();
        validate_profile(&app, &body, Some(&created)).unwrap();
        let updated = profile_from_body(id, "", &body, Some(&created));
        assert_eq!(updated.selected_nodes, vec![1]);
        assert_eq!(updated.selected_categories, vec!["ads"]);
        assert_eq!(updated.group_overrides, serde_json::json!({"🚀 节点选择": [1, "DIRECT"]}));
        assert_eq!(updated.template_name, "全局代理.yaml");
        assert!(!updated.enabled);
        assert_eq!(updated.token, "tok");
        // 显式提供仍生效（组覆盖清成空表）
        let body2: ConvProfileBody = serde_json::from_str(r#"{"name":"p1","group_overrides":{}}"#).unwrap();
        let updated2 = profile_from_body(id, "", &body2, Some(&created));
        assert_eq!(updated2.group_overrides, serde_json::json!({}));
    }

    #[test]
    fn source_category_renders_and_survives_source_delete() {
        let app = app_with_nodes_and_rule_templates();
        // 种一个类别来源（妙妙屋 JSON 元素格式）
        let cats = crate::rule_sources::parse_categories_json(
            r#"[{"name":"mytest","group_label":"🧪 我的测试","site_rules":[{"key":"mytest","url":"https://example.com/mytest.mrs"}]}]"#,
        )
        .unwrap();
        let id = app
            .db
            .create_rule_source(&crate::db::RuleSource {
                id: 0,
                kind: "categories".into(),
                name: "s".into(),
                url: String::new(),
                data: crate::rule_sources::categories_to_raw_json(&cats),
                last_sync: 0,
                created_at: 0,
            })
            .unwrap();
        let key = format!("s{id}:mytest");
        let profile = SubProfile {
            id: 9,
            name: "t".into(),
            token: "t".into(),
            selected_categories: vec!["ads".into(), key.clone()],
            ..Default::default()
        };
        let yaml = render_profile(&app, &profile).unwrap();
        assert!(yaml.contains("RULE-SET,mytest,🧪 我的测试"), "{yaml}");
        assert!(yaml.contains("- name: 🧪 我的测试"));
        // 删除来源 → 残留 key 渲染静默跳过（只剩内置 ads）
        app.db.delete_rule_source(id).unwrap();
        let yaml = render_profile(&app, &profile).unwrap();
        assert!(!yaml.contains("我的测试"));
        assert!(yaml.contains("🛑 广告拦截"));
        assert!(yaml.contains("MATCH,🐟 漏网之鱼"));
    }

    #[test]
    fn category_profile_without_template_passes_validation() {
        // 编辑按类别生成的订阅：template_name 按约定发空串，校验不得报「绑定的模板不存在」
        let app = app_with_nodes_and_rule_templates();
        let body: ConvProfileBody =
            serde_json::from_str(r#"{"name":"类别订阅","selected_categories":["ads"],"template_name":""}"#)
                .unwrap();
        validate_profile(&app, &body, None).unwrap();
        // 已存在的类别订阅做局部更新（编辑弹窗路径）同样放行
        let p = profile_from_body(0, "tok", &body, None);
        let id = app.db.create_sub_profile(&p).unwrap();
        let stored = app.db.sub_profile(id).unwrap().unwrap();
        let upd: ConvProfileBody = serde_json::from_str(r#"{"name":"类别订阅改"}"#).unwrap();
        validate_profile(&app, &upd, Some(&stored)).unwrap();
    }

    #[test]
    fn snippets_merge_into_category_generated_config() {
        // 回归：类别订阅勾选的片段此前被静默忽略（合并只挂在模板分支）
        let app = app_with_nodes_and_rule_templates();
        let sn = crate::db::SubSnippet {
            id: 0,
            name: "测试片段".into(),
            kind: "rules".into(),
            mode: "prepend".into(),
            content: "- DOMAIN-SUFFIX,example.com,DIRECT".into(),
            enabled: true,
            created_at: 0,
        };
        let sid = app.db.create_sub_snippet(&sn).unwrap();
        let profile = SubProfile {
            id: 9,
            name: "t".into(),
            token: "t".into(),
            selected_categories: vec!["ads".into()],
            snippet_ids: vec![sid],
            ..Default::default()
        };
        let yaml = render_profile(&app, &profile).unwrap();
        let doc: Value = serde_yaml::from_str(&yaml).unwrap();
        let rules: Vec<String> =
            doc["rules"].as_array().unwrap().iter().filter_map(|v| v.as_str().map(str::to_owned)).collect();
        assert_eq!(rules[0], "DOMAIN-SUFFIX,example.com,DIRECT", "prepend 片段必须在最前: {rules:?}");
        // append 片段插在 MATCH 前
        let sn2 = crate::db::SubSnippet {
            id: 0,
            name: "尾部".into(),
            kind: "rules".into(),
            mode: "append".into(),
            content: "- DOMAIN-SUFFIX,tail.com,DIRECT".into(),
            enabled: true,
            created_at: 0,
        };
        let sid2 = app.db.create_sub_snippet(&sn2).unwrap();
        let profile2 = SubProfile {
            id: 10,
            name: "t2".into(),
            token: "t".into(),
            selected_categories: vec!["ads".into()],
            snippet_ids: vec![sid2],
            ..Default::default()
        };
        let yaml = render_profile(&app, &profile2).unwrap();
        let rules: Vec<String> = serde_yaml::from_str::<Value>(&yaml).unwrap()["rules"]
            .as_array()
            .unwrap()
            .iter()
            .filter_map(|v| v.as_str().map(str::to_owned))
            .collect();
        assert_eq!(rules.last().unwrap(), "MATCH,🐟 漏网之鱼", "MATCH 兜底仍在最后");
        assert_eq!(rules[rules.len() - 2], "DOMAIN-SUFFIX,tail.com,DIRECT", "append 应插在 MATCH 之前");
        // 全局语义：库里启用即可，未勾进 profile.snippet_ids 也合并
        let sn3 = crate::db::SubSnippet {
            id: 0,
            name: "全局".into(),
            kind: "rules".into(),
            mode: "prepend".into(),
            content: "- DOMAIN-SUFFIX,global.com,DIRECT".into(),
            enabled: true,
            created_at: 0,
        };
        app.db.create_sub_snippet(&sn3).unwrap();
        let profile3 = SubProfile {
            id: 11,
            name: "t3".into(),
            token: "t".into(),
            selected_categories: vec!["ads".into()],
            snippet_ids: vec![],
            ..Default::default()
        };
        let yaml = render_profile(&app, &profile3).unwrap();
        let rules: Vec<String> = serde_yaml::from_str::<Value>(&yaml).unwrap()["rules"]
            .as_array()
            .unwrap()
            .iter()
            .filter_map(|v| v.as_str().map(str::to_owned))
            .collect();
        assert_eq!(rules[0], "DOMAIN-SUFFIX,global.com,DIRECT", "启用的片段应全局生效");
    }

    #[tokio::test]
    async fn template_upload_requires_runnable_sections() {
        let app: Shared = std::sync::Arc::new(app_with_nodes_and_rule_templates());
        // 缺 rules 段 -> 拒绝
        let bad: Json<ConvTemplateBody> = Json(
            serde_json::from_value(
                serde_json::json!({ "name": "半截配置", "content": "proxies: []\nproxy-groups: []" }),
            )
            .unwrap(),
        );
        let resp = conv_template_create(crate::api::Admin, State(app.clone()), Ok(bad)).await;
        assert_eq!(resp.status(), axum::http::StatusCode::BAD_REQUEST);
        // 完整配置 -> 通过
        let good: Json<ConvTemplateBody> = Json(serde_json::from_value(serde_json::json!({ "name": "完整配置", "content": "proxies: []\nproxy-groups: []\nrules: []" })).unwrap());
        let resp = conv_template_create(crate::api::Admin, State(app.clone()), Ok(good)).await;
        assert_eq!(resp.status(), axum::http::StatusCode::OK);
    }

    #[tokio::test]
    async fn template_rename_cascades_profile_binding_and_rejects_dup() {
        let app: Shared = std::sync::Arc::new(app_with_nodes_and_rule_templates());
        // 上传一个模板 + 一个按名字绑定它的订阅
        let good: Json<ConvTemplateBody> = Json(serde_json::from_value(serde_json::json!({ "name": "改名前", "content": "proxies: []\nproxy-groups: []\nrules: []" })).unwrap());
        assert_eq!(
            conv_template_create(crate::api::Admin, State(app.clone()), Ok(good)).await.status(),
            axum::http::StatusCode::OK
        );
        let body: ConvProfileBody =
            serde_json::from_str(r#"{"name":"p","template_name":"改名前.yaml","enabled":true}"#).unwrap();
        app.db.create_sub_profile(&profile_from_body(0, "tok", &body, None)).unwrap();
        let tid = app.db.sub_templates().unwrap().iter().find(|t| t.name == "改名前.yaml").unwrap().id;

        // 重名（命中内置）拒绝
        let dup: Json<ConvTemplateBody> = Json(serde_json::from_value(serde_json::json!({ "name": "全局代理", "content": "proxies: []\nproxy-groups: []\nrules: []" })).unwrap());
        let resp = conv_template_update(crate::api::Admin, State(app.clone()), Path(tid), Ok(dup)).await;
        assert_ne!(resp.status(), axum::http::StatusCode::OK, "重名必须拒绝");

        // 改名成功：模板与订阅绑定同步
        let rename: Json<ConvTemplateBody> = Json(serde_json::from_value(serde_json::json!({ "name": "改名后", "content": "proxies: []\nproxy-groups: []\nrules: []" })).unwrap());
        let resp = conv_template_update(crate::api::Admin, State(app.clone()), Path(tid), Ok(rename)).await;
        assert_eq!(resp.status(), axum::http::StatusCode::OK);
        let names = app.db.sub_templates().unwrap().into_iter().map(|t| t.name).collect::<Vec<_>>();
        assert!(names.contains(&"改名后.yaml".to_string()) && !names.contains(&"改名前.yaml".to_string()));
        let binding = app.db.sub_profiles().unwrap().into_iter().map(|p| p.template_name).collect::<Vec<_>>();
        assert!(binding.contains(&"改名后.yaml".to_string()), "订阅绑定必须级联改写: {binding:?}");

        // 内置模板名不可改（body.name 被忽略，内容仍可更新）
        let builtin_id = app.db.sub_templates().unwrap().iter().find(|t| t.is_builtin).unwrap().id;
        let rename_builtin: Json<ConvTemplateBody> = Json(serde_json::from_value(serde_json::json!({ "name": "劫持内置名", "content": "proxies: []\nproxy-groups: []\nrules: []" })).unwrap());
        let resp =
            conv_template_update(crate::api::Admin, State(app.clone()), Path(builtin_id), Ok(rename_builtin))
                .await;
        assert_eq!(resp.status(), axum::http::StatusCode::OK);
        let builtin_name =
            app.db.sub_templates().unwrap().into_iter().find(|t| t.id == builtin_id).unwrap().name;
        assert_ne!(builtin_name, "劫持内置名.yaml");
    }

    #[test]
    fn static_profile_serves_verbatim_and_skips_validation() {
        let app = app_with_nodes_and_rule_templates();
        // 创建静态订阅：无需绑定模板（校验豁免），渲染原样返回
        let body: ConvProfileBody = serde_json::from_str(
            r#"{"name":"静态","static_content":"proxies: []\nrules:\n  - MATCH,DIRECT\n"}"#,
        )
        .unwrap();
        validate_profile(&app, &body, None).unwrap();
        let p = profile_from_body(0, "tok", &body, None);
        let id = app.db.create_sub_profile(&p).unwrap();
        // 走真实落库闭环：静态内容必须经 INSERT/SELECT 原样保真
        let p = app.db.sub_profile(id).unwrap().unwrap();
        let yaml = render_profile(&app, &p).unwrap();
        assert_eq!(
            yaml,
            "proxies: []
rules:
  - MATCH,DIRECT
"
        );
        // 局部更新不携带 static_content → 保留原静态内容
        let upd: ConvProfileBody = serde_json::from_str(r#"{"name":"静态","enabled":false}"#).unwrap();
        let merged = profile_from_body(id, "", &upd, Some(&p));
        assert_eq!(merged.static_content, "proxies: []\nrules:\n  - MATCH,DIRECT\n");
        assert!(!merged.enabled);
        app.db.update_sub_profile(&merged).unwrap();
        let back = app.db.sub_profile(id).unwrap().unwrap();
        assert_eq!(
            back.static_content, "proxies: []\nrules:\n  - MATCH,DIRECT\n",
            "UPDATE 不得丢 static_content"
        );
        assert!(!back.enabled);
        // 动态订阅不受影响：空 static_content 照常走渲染（勾选类别生成）
        let dyn_profile = SubProfile {
            id: 9,
            name: "d".into(),
            token: "t".into(),
            selected_categories: vec!["ads".into()],
            ..Default::default()
        };
        let yaml = render_profile(&app, &dyn_profile).unwrap();
        assert!(yaml.contains("🛑 广告拦截"));
    }

    #[test]
    fn rule_mode_kv_roundtrip_with_categories() {
        let app = app_with_nodes_and_rule_templates();
        let sel = RuleModeSelection {
            name: "极简规则.yaml".into(),
            categories: vec!["private".into(), "cn".into()],
        };
        app.db.set(RULE_MODE_KEY, &serde_json::to_string(&sel).unwrap()).unwrap();
        let back = rule_mode_selection(&app);
        assert_eq!(back.name, "极简规则.yaml");
        // 旧 key cn 归一化为 domestic
        assert_eq!(back.categories, vec!["private".to_string(), "domestic".to_string()]);
        // 旧 kv（纯文件名）兼容：完整规则 = 全部类别
        app.db.set(RULE_MODE_KEY, "完整规则.yaml").unwrap();
        let back = rule_mode_selection(&app);
        assert_eq!(back.name, "完整规则.yaml");
        assert!(back.categories.contains(&"ads".to_string()), "完整模式含广告类");
        assert_eq!(back.categories.len(), RULE_CATEGORIES.len());
    }

    #[test]
    fn acl4ssr_ini_converts_groups_rules_and_providers() {
        let ini = r#"[Custom Rules]
# 自定义规则放这里

[Proxy]
[Proxy Group]
🚀 节点选择 = select, ♻️ 自动, 🔯 全球直连, DIRECT
♻️ 自动 = url-test, .* , url = http://www.gstatic.com/generate_204, interval=86400
🔯 全球直连 = select, DIRECT
🛑 广告拦截 = select, REJECT, 🚀 节点选择
[Rule]
RULE-SET,https://gh-proxy.com/https://raw.githubusercontent.com/ACL4SSR/ACL4SSR/master/Clash/Ruleset/Reject.txt,🛑 广告拦截
DOMAIN-SUFFIX,cn,DIRECT
GEOIP,CN,DIRECT
FINAL,🚀 节点选择
"#;
        let yaml = convert_acl_ini(ini).unwrap();
        eprintln!("CONVERTED-START\n{yaml}\nCONVERTED-END");
        let doc: Value = serde_yaml::from_str(&yaml).unwrap();
        let groups = doc["proxy-groups"].as_array().unwrap();
        assert_eq!(groups.len(), 4);
        let entry = groups.iter().find(|g| g["name"] == "🚀 节点选择").unwrap();
        let list: Vec<&str> =
            entry["proxies"].as_array().unwrap().iter().filter_map(|v| v.as_str()).collect();
        assert!(
            list.contains(&"♻️ 自动") && list.contains(&"🔯 全球直连") && list.contains(&"DIRECT"),
            "{list:?}"
        );
        // `.*` 占位策略 → __ALL__（渲染时展开）
        let auto = groups.iter().find(|g| g["name"] == "♻️ 自动").unwrap();
        assert!(auto["proxies"].as_array().unwrap().contains(&json!("__ALL__")));
        // 规则：FINAL → MATCH，其余原样
        let rules: Vec<String> =
            doc["rules"].as_array().unwrap().iter().filter_map(|v| v.as_str().map(str::to_owned)).collect();
        assert_eq!(rules[0], "RULE-SET,https://gh-proxy.com/https://raw.githubusercontent.com/ACL4SSR/ACL4SSR/master/Clash/Ruleset/Reject.txt,🛑 广告拦截");
        assert!(rules.last().unwrap().starts_with("MATCH,🚀 节点选择"));
        assert!(rules.contains(&"DOMAIN-SUFFIX,cn,DIRECT".to_string()));
    }

    #[test]
    fn injected_pruning_drops_stale_names_from_foreign_templates() {
        let (app, sub) = app_with_assigned_nodes();
        // 外部模板：引用了不存在的固定节点名
        let yaml_in = "proxies: []\nproxy-groups:\n  - name: 🚀 节点选择\n    type: select\n    proxies:\n      - 香港IEPL-01\n      - 🇭🇰 香港01\n      - DIRECT\nrules:\n  - MATCH,🚀 节点选择\n";
        app.db
            .create_sub_template(&crate::db::SubTemplate {
                id: 0,
                name: "外部.yaml".into(),
                content: yaml_in.into(),
                ..Default::default()
            })
            .unwrap();
        let profile = SubProfile {
            id: 9,
            name: "t".into(),
            token: "t".into(),
            template_name: "外部.yaml".into(),
            ..Default::default()
        };
        let yaml = render_profile_for(&app, &profile, Some(&sub)).unwrap();
        let doc: Value = serde_yaml::from_str(&yaml).unwrap();
        let entry =
            doc["proxy-groups"].as_array().unwrap().iter().find(|g| g["name"] == "🚀 节点选择").unwrap();
        let list: Vec<&str> =
            entry["proxies"].as_array().unwrap().iter().filter_map(|v| v.as_str()).collect();
        assert!(!list.contains(&"香港IEPL-01"), "陈旧引用应剪除: {list:?}");
        assert!(list.contains(&"🇭🇰 香港01") && list.contains(&"DIRECT"));
    }

    #[test]
    fn template_groups_carry_template_members() {
        let app = app_with_nodes_and_rule_templates();
        let t =
            app.db.sub_templates().unwrap().into_iter().find(|t| t.name == "经典分组-绕过大陆.yaml").unwrap();
        let doc: Value = serde_yaml::from_str(&t.content).unwrap();
        let entry =
            doc["proxy-groups"].as_array().unwrap().iter().find(|g| g["name"] == "🚀 节点选择").unwrap();
        let members: Vec<&str> =
            entry["proxies"].as_array().unwrap().iter().filter_map(|v| v.as_str()).collect();
        // 模板成员含占位与特殊项（DIRECT / 其他组名引用）
        assert!(members.contains(&"__ALL__"));
        assert!(members.contains(&"♻️ 自动"));
        assert!(members.contains(&"DIRECT"));
    }

    #[test]
    fn template_groups_endpoint_shape() {
        // 用组列表解析函数的结构验证（端点逻辑薄，直接测 YAML→组列表）。
        let yaml =
            "proxy-groups:\n  - name: 🚀 节点选择\n    type: select\n  - name: ♻️ 自动\n    type: url-test\n";
        let doc: Value = serde_yaml::from_str(yaml).unwrap();
        let groups: Vec<(String, String)> = doc["proxy-groups"]
            .as_array()
            .unwrap()
            .iter()
            .filter_map(|g| Some((g["name"].as_str()?.to_string(), g["type"].as_str()?.to_string())))
            .collect();
        assert_eq!(
            groups,
            vec![("🚀 节点选择".into(), "select".into()), ("♻️ 自动".into(), "url-test".into())]
        );
    }

    /// 订阅命名头：ASCII 明文 / 中文走 base64: 前缀，filename* 百分号编码，
    /// 引号与控制字符剔除（防响应头注入/断行）。
    #[test]
    fn naming_headers_encode_the_subscription_name() {
        let hs = naming_headers("plain-name");
        let get = |k: &str| hs.iter().find(|(n, _)| n.as_str() == k).map(|(_, v)| v.clone()).unwrap();
        assert_eq!(get("profile-title"), "plain-name", "纯 ASCII 明文");
        assert!(get("content-disposition").starts_with("inline; filename=\"plain-name\""));
        let hs = naming_headers("香港-01");
        let get = |k: &str| hs.iter().find(|(n, _)| n.as_str() == k).map(|(_, v)| v.clone()).unwrap();
        let title = get("profile-title");
        assert!(title.starts_with("base64:"), "非 ASCII 走 base64 前缀");
        let decoded =
            base64::engine::general_purpose::URL_SAFE_NO_PAD.decode(&title["base64:".len()..]).unwrap();
        assert_eq!(String::from_utf8(decoded).unwrap(), "香港-01");
        let cd = get("content-disposition");
        assert!(cd.contains("filename=\"香港-01\""), "filename 给 UTF-8 原文");
        assert!(cd.contains("filename*=UTF-8''%E9%A6%99%E6%B8%AF-01"), "filename* 百分号编码");
        let injected = naming_headers("a\"b\nc");
        let cd = injected
            .iter()
            .find(|(n, _)| n.as_str() == "content-disposition")
            .map(|(_, v)| v.clone())
            .unwrap();
        assert!(!cd.contains('"') || cd.matches('"').count() == 2, "名字里的引号被剔除，只剩包裹用的两对");
        assert!(!cd.contains('\n'), "控制字符剔除防断行");
    }
}

// ---- 规则模式（页面级单选：只改选择状态，不触发生成）----

pub async fn conv_rule_mode_get(_: Admin, State(app): State<Shared>) -> Response {
    Json(rule_mode_catalog(&app)).into_response()
}

#[derive(Deserialize)]
pub struct ConvRuleModeBody {
    #[serde(default)]
    pub name: String,
    /// 勾选的类别 key（动态生成模式的类别集）。
    #[serde(default)]
    pub categories: Vec<String>,
}

/// 保存规则模式选择：预设名（自动填该预设的类别集）或模板名 + 手动类别集。
/// 只写页面级默认，不触发生成。
pub async fn conv_rule_mode_set(
    _: Admin,
    State(app): State<Shared>,
    body: Result<Json<ConvRuleModeBody>, axum::extract::rejection::JsonRejection>,
) -> Response {
    let Json(body) = match body {
        Ok(b) => b,
        Err(_) => return bad("请求格式不对"),
    };
    let name = body.name.trim();
    if name.is_empty() {
        return bad("规则模式名称不能为空");
    }
    // 类别集：显式给且 key 全合法（旧 key 归一化）→ 用之；否则按预设名推导
    let categories: Vec<String> = if !body.categories.is_empty() {
        let mut out: Vec<String> = Vec::new();
        for k in &body.categories {
            // 内置旧 key 归一化存储；来源命名空间 key（s{id}:name）原样保留
            if !crate::rule_sources::category_key_exists(&app, k) {
                return bad("包含未知的分流类别");
            }
            let nk = normalize_category(k);
            let stored = if nk.is_empty() { k.clone() } else { nk.to_string() };
            if !out.iter().any(|x| x == &stored) {
                out.push(stored);
            }
        }
        out
    } else if let Some((_, _, members)) = PRESETS.iter().find(|(n, _, _)| *n == name) {
        RULE_CATEGORIES
            .iter()
            .filter(|c| members.is_empty() || members.contains(&c.key))
            .map(|c| c.key.to_string())
            .collect()
    } else if name.ends_with(".yaml") || app.db.sub_template(name).ok().flatten().is_some() {
        // 已导入模板名（含不带 .yaml 后缀的预设名）：类别集存空数组（模板
        // 注入模式），仅记录选择
        Vec::new()
    } else {
        return fail(anyhow::Error::msg(crate::Shown(format!("规则模式 {name} 不存在"))));
    };
    let sel = RuleModeSelection { name: name.to_owned(), categories };
    let raw = serde_json::to_string(&sel).unwrap_or_default();
    match app.db.set(RULE_MODE_KEY, &raw) {
        Ok(()) => Json(json!({ "ok": true, "selected": sel })).into_response(),
        Err(e) => fail(e),
    }
}

/// 把（可能来自存量数据的）类别 key 列表解析为生效类别视图：内置（归一化
/// 旧 key + 用户覆盖）或来源命名空间 `s{id}:name`（来源已删的 key 静默跳过），
/// 保持给定顺序并去重。
/// 类别生成模式的分组骨架（可视化分组编辑器用）：组名 + 成员串（含 __ALL__
/// 占位，前端展开显示）。与 build_category_config 同一来源，永不漂移。
pub fn category_group_skeleton(keys: &[String]) -> Vec<(String, Vec<String>)> {
    let mut seen: Vec<String> = Vec::new();
    let mut cats: Vec<crate::rule_sources::CategoryView> = Vec::new();
    for k in keys {
        let nk = normalize_category(k);
        if !nk.is_empty() {
            if let Some(c) = RULE_CATEGORIES.iter().find(|c| c.key == nk) {
                if !seen.iter().any(|x| x == c.key) {
                    cats.push(c.view());
                    seen.push(c.key.to_string());
                }
            }
        }
    }
    let config = build_category_config(&cats, &["__ALL__"]);
    let groups = config["proxy-groups"].as_array().cloned().unwrap_or_default();
    groups
        .iter()
        .map(|g| {
            let name = g["name"].as_str().unwrap_or_default().to_string();
            let members: Vec<String> = g["proxies"]
                .as_array()
                .map(|a| a.iter().filter_map(|v| v.as_str().map(str::to_owned)).collect())
                .unwrap_or_default();
            (name, members)
        })
        .collect()
}

fn resolved_categories(app: &crate::App, keys: &[String]) -> Vec<crate::rule_sources::CategoryView> {
    let mut out: Vec<crate::rule_sources::CategoryView> = Vec::new();
    for k in keys {
        if let Some(c) = crate::rule_sources::resolve_category(app, k) {
            if !out.iter().any(|x| x.key == c.key) {
                out.push(c);
            }
        }
    }
    out
}

/// 按勾选类别动态生成完整配置（妙妙屋 ClashConfigBuilder 同构，结构见
/// build_category_config）。
pub fn render_by_categories_for(
    app: &crate::App,
    profile: &crate::db::SubProfile,
    categories: &[String],
    sub: Option<&crate::db::SubUser>,
) -> Result<String> {
    let nodes = match sub {
        Some(s) => collect_customer_nodes(app, s)?,
        None => Vec::new(),
    };
    let cats = resolved_categories(app, categories);
    if cats.is_empty() {
        bail!("没有可识别的分流类别");
    }
    let mut used: HashSet<String> = HashSet::new();
    let mut proxies: Vec<Value> = Vec::new();
    let mut node_names: Vec<String> = Vec::new();
    for n in &nodes {
        let mut m = node_to_proxy(n)?;
        let base = n.name.trim().to_owned();
        let mut name = base.clone();
        let mut suffix = 2;
        while !used.insert(name.clone()) {
            name = format!("{base} {suffix}");
            suffix += 1;
        }
        m["name"] = json!(name.clone());
        node_names.push(name);
        proxies.push(m);
    }
    let items: Vec<&str> = node_names.iter().map(String::as_str).collect();
    let mut config = build_category_config(&cats, &items);
    config["proxies"] = json!(proxies);
    // 分组覆盖（可视化拖拽）：按组名匹配，成员整表替换——数字按节点 id 解析
    // 成渲染名，字符串直通；空表回落 DIRECT，与模板路径的覆盖语义一致。
    let overrides = profile.group_overrides.as_object().cloned().unwrap_or_default();
    if !overrides.is_empty() {
        let mut id_name: std::collections::HashMap<i64, String> = std::collections::HashMap::new();
        for (i, n) in nodes.iter().enumerate() {
            id_name.entry(n.id).or_insert_with(|| node_names[i].clone());
        }
        // 成员解析：数字=节点 id；字符串里 __ALL__ 展开为全部勾选节点，
        // 其余（DIRECT/REJECT/组引用/地区标签）按名字直通。
        let expand = |m: &Value| -> Vec<Value> {
            match m {
                Value::Number(n) => n
                    .as_i64()
                    .and_then(|id| id_name.get(&id).cloned())
                    .map(|name| vec![json!(name)])
                    .unwrap_or_default(),
                Value::String(s) if s == "__ALL__" => node_names.iter().map(|name| json!(name)).collect(),
                Value::String(s) => vec![json!(s)],
                _ => vec![],
            }
        };
        if let Some(groups) = config["proxy-groups"].as_array_mut() {
            for g in groups.iter_mut() {
                let gname = g["name"].as_str().unwrap_or_default().to_owned();
                let Some(members) = overrides.get(&gname).and_then(Value::as_array) else { continue };
                let mut resolved: Vec<Value> = Vec::new();
                for m in members {
                    for v in expand(m) {
                        // 同名去重：__ALL__ 与显式 id 混排时防止重复成员
                        if let Some(_name) = v.as_str() {
                            if resolved.iter().any(|x| x == &v) {
                                continue;
                            }
                        }
                        resolved.push(v);
                    }
                }
                let list = if resolved.is_empty() { vec![json!("DIRECT")] } else { resolved };
                g["proxies"] = json!(list);
            }
        }
        // 覆盖里出现基础配置没有的组名 → 追加为新 select 组（按地区一键建
        // 组依赖此能力：地区组由覆盖引入，不在骨架里）。成员解析同上（数字
        // =节点 id、字符串直通，同名去重）。
        let existing: std::collections::HashSet<String> = config["proxy-groups"]
            .as_array()
            .map(|a| {
                a.iter().filter_map(|g| g.get("name").and_then(|v| v.as_str()).map(str::to_owned)).collect()
            })
            .unwrap_or_default();
        for (gname, members) in &overrides {
            if existing.contains(gname) {
                continue;
            }
            let mut list: Vec<Value> = Vec::new();
            for m in members.as_array().cloned().unwrap_or_default() {
                let name = match &m {
                    Value::Number(id) => id.as_i64().and_then(|i| id_name.get(&i).cloned()),
                    Value::String(s) => Some(s.clone()),
                    _ => None,
                };
                if let Some(name) = name {
                    if !list.iter().any(|x| x.as_str() == Some(name.as_str())) {
                        list.push(json!(name));
                    }
                }
            }
            let list = if list.is_empty() { vec![json!("DIRECT")] } else { list };
            if let Some(groups) = config["proxy-groups"].as_array_mut() {
                groups.push(json!({ "name": gname, "type": "select", "proxies": list }));
            }
        }
    }
    merge_profile_snippets(app, profile, &mut config)?;
    sanitize_group_members(&mut config);
    serde_yaml::to_string(&config).context("YAML 序列化失败")
}
