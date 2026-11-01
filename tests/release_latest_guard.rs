//! 源码防线（retro 2026-11-02）：`releases/latest` 只许对着外部第三方仓。
//!
//! 自有两仓（jspanel-hub/jspanel-agent）混着非构建 tag——agent 仓的
//! `realm-api-v*` release 没有 agent 资产，GitHub 的 releases/latest 会把它
//! 当最新：中转 404、更新页对错版本（2026-11-02 实际发生，install E2E 揪出）。
//! 自有仓的 release 语义一律走 `latest_v_release`（v 前缀过滤）或钉死 tag。
//! 外部仓（SagerNet/sing-box、zhboner/realm、主题仓）tag 约定不可控，
//! releases/latest 是它们的正确用法。
//!
//! 形态与 agent 仓 tests/unit_active_guard.rs 同款：锁的是「这类错误不再
//! 出现」，不是逐行审阅。新合法点出现时本测试不该红——只有自有仓撞上才会。

use std::path::PathBuf;

#[test]
fn releases_latest_never_targets_the_own_repos() {
    let src = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("src");
    let mut offenders = Vec::new();
    let mut stack = vec![src];
    while let Some(dir) = stack.pop() {
        for entry in std::fs::read_dir(&dir).expect("src 目录可读") {
            let path = entry.expect("目录项可读").path();
            if path.is_dir() {
                stack.push(path);
                continue;
            }
            if path.extension().is_none_or(|e| e != "rs") {
                continue;
            }
            let text = std::fs::read_to_string(&path).expect("源码可读");
            for (i, line) in text.lines().enumerate() {
                let trimmed = line.trim_start();
                // 注释里的提法（文档、教训记录）不算使用点。
                if trimmed.starts_with("//") || !line.contains("releases/latest") {
                    continue;
                }
                // 自有仓的引用方式：字面量仓名或仓常量。同 line 命中即违规——
                // 当年出事的写法正是 `format!("…{AGENT_REPO}/releases/latest/…")`。
                if ["jspanel", "AGENT_REPO", "HUB_REPO"].iter().any(|m| line.contains(m)) {
                    offenders.push(format!("{}:{}: {}", path.display(), i + 1, line.trim()));
                }
            }
        }
    }
    assert!(
        offenders.is_empty(),
        "releases/latest 撞上自有仓：混 tag 仓库的 latest 语义不可用（见本文件头注释），\
         改走 latest_v_release 或钉死 tag：\n{}",
        offenders.join("\n")
    );
}
