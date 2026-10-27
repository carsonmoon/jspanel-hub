#!/bin/sh
# 一键构建 + 部署（retro 产物：本流程每次手工 5 步，收拢成一条命令）。
# 用法：MONITOR_DEPLOY_HOST=root@面板机 ./deploy.sh [hub|agent]（默认 hub）
# hub：web-admin npm build（含 tsc）→ docker musl 交叉编译 → scp → systemd 换新重启 → 输出新指纹
# agent：跳过前端构建，其余同（systemd 单元 monitor-agent，路径 /opt/monitor/monitor-agent）
# 部署目标与面板 URL 由环境变量注入（本脚本入公开仓，不含任何具体主机信息）：
#   MONITOR_DEPLOY_HOST  必填，scp/ssh 目标，如 root@10.0.0.1
#   MONITOR_PANEL_URL    选填，如 https://panel.example.com；设置时输出前端指纹
set -e

TARGET="${1:-hub}"
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
HOST="${MONITOR_DEPLOY_HOST:?需设置 MONITOR_DEPLOY_HOST（scp/ssh 目标，如 root@10.0.0.1）}"

case "$TARGET" in
  hub)   DIR="$ROOT/monitor";       UNIT=monitor-hub;   BIN=monitor-hub ;;
  agent) DIR="$ROOT/monitor-agent"; UNIT=monitor-agent; BIN=monitor-agent ;;
  *) echo "usage: ./deploy.sh [hub|agent]" >&2; exit 1 ;;
esac

cd "$DIR"
# 部署前门禁（ci.yml check 作业同款，retro 候选 2）：本地先把 fmt/clippy/
# test 三连跑过，才进昂贵的 docker 构建——CI 从未运行过的纪律接到部署关口。
# 2026-10-27 agent 仓 lint 债清零后同设。collect 的三个环境依赖测试读真实
# hostname/free/df（macOS 沙盒必红，HANDOFF 既有非回归），agent 路径按名跳过。
cargo fmt --all --check
cargo clippy --all-targets -- -D warnings
if [ "$TARGET" = hub ]; then
  cargo test --quiet
else
  cargo test --quiet -- --skip real_host_collection_is_sane \
    --skip memory_and_disk_agree_with_free_and_df_on_this_machine \
    --skip a_black_holed_address_gives_way_to_the_next_within_the_fallback
fi
if [ "$TARGET" = hub ]; then
  if command -v shellcheck >/dev/null 2>&1; then
    shellcheck -S warning install.sh install-hub.sh scripts/*.sh deploy.sh
  else
    echo "提示: 本机无 shellcheck，跳过脚本检查（brew install shellcheck 可启用）"
  fi
  (cd web-admin && npm run build)
fi

docker run --rm --platform linux/amd64 -v "$PWD":/work \
  -v "$HOME/.cargo/registry":/usr/local/cargo/registry -w /work rust:1-slim-bookworm \
  sh -c 'apt-get update -qq >/dev/null && apt-get install -y -qq musl-tools >/dev/null && rustup target add x86_64-unknown-linux-musl && cargo build --release --locked --target x86_64-unknown-linux-musl'

scp "target/x86_64-unknown-linux-musl/release/$BIN" "$HOST:/tmp/$BIN.new"
# 换新前留一个时间戳备份（回滚用），并按本前缀只保留最近 5 个——历史上
# 手工部署留了 97 个 .bak 约 1GB 无清理，从此由本脚本自律。
ssh "$HOST" "systemctl stop $UNIT && { cp -a /opt/monitor/$BIN /opt/monitor/$BIN.bak-\$(date +%Y%m%d-%H%M%S) 2>/dev/null || true; } && mv /tmp/$BIN.new /opt/monitor/$BIN && chmod 755 /opt/monitor/$BIN && systemctl start $UNIT && sleep 2 && systemctl is-active $UNIT && ls -1t /opt/monitor/$BIN.bak-* 2>/dev/null | tail -n +6 | xargs -r rm -f"

if [ "$TARGET" = hub ] && [ -n "${MONITOR_PANEL_URL:-}" ]; then
  MAIN_FP=$(curl -sk "$MONITOR_PANEL_URL/admin/" | grep -o 'main-[^"]*\.js' | head -1)
  USER_FP=$(curl -sk "$MONITOR_PANEL_URL/u/" | grep -o 'user-[^"]*\.js' | head -1)
  echo "admin 指纹:  $MAIN_FP"
  echo "用户中心指纹: $USER_FP"
fi
