#!/bin/sh
# install.sh 全流程容器 E2E（retro 2026-11-02 收编，配方在 /tmp 蒸发前落仓）。
# 本地临时 hub + 特权 systemd 容器，走面板同款路径：/install.sh 下发 → hub
# 中转下载 agent → --with-realm/--with-gost 预装落位 → agent 上线 → --upgrade
# 不触碰核心。CI 不跑本脚本（需要 docker 与 arm64 原生虚拟化）：
#   scripts/install-e2e.sh [monitor-hub 二进制路径]   # 默认 target/debug/monitor-hub
# 依赖：docker、jq、curl；Apple Silicon 上 --platform linux/arm64 原生跑（免 qemu）。
# 镜像配方（5 轮试错的结论，勿走回头路）：官方多架构镜像普遍没有 systemd——
# debian/ubuntu 精简镜像剥了 systemd，jrei/systemd-debian 与 archlinux 官方
# 镜像都没有 arm64 manifest——所以普通容器装齐 systemd 后 commit 成镜像，
# 再以 /sbin/init 重起为特权容器。
# 虚过教训（retro 同批）：upgrade 腿必须带 --insecure——本地 hub 是明文 http，
# 不带会在明文校验处提前退出，而「核心 mtime 未变」的断言照绿，什么也没验到。
# 断言前先看输出走了哪条分支，确认锻炼到目标路径。
set -eu

HUB_BIN=${1:-target/debug/monitor-hub}
PORT=${E2E_PORT:-9977}
PLATFORM=${E2E_PLATFORM:-linux/arm64}
URL=http://127.0.0.1:$PORT
CURL_INNER=http://host.docker.internal:$PORT
DIR=$(mktemp -d /tmp/install-e2e.XXXXXX)
HUB_PID=
CONTAINER=install-e2e

cleanup() {
	[ -n "$HUB_PID" ] && kill "$HUB_PID" 2>/dev/null || true
	docker rm -f "$CONTAINER" >/dev/null 2>&1 || true
	[ "${KEEP_DIR:-}" = 1 ] || rm -rf "$DIR"
}
trap cleanup EXIT

fail() {
	echo "install-e2e: $*" >&2
	exit 1
}

wait_for() {
	what=$1
	shift
	i=0
	until "$@" >/dev/null 2>&1; do
		i=$((i + 1))
		[ "$i" -le 60 ] || fail "timed out waiting for $what"
		sleep 0.5
	done
}

[ -x "$HUB_BIN" ] || fail "hub 二进制不存在或不可执行：$HUB_BIN（先 cargo build）"

# 节点上报在线（wait_for 只收命令名，管道检查包成函数——e2e.sh 的 reported 同款）。
online() {
	curl -fs -H "Cookie: $COOKIE" "$URL/api/nodes" | jq -e '.nodes[0].online' >/dev/null
}

# ---- 1. 本地临时 hub（e2e.sh 同款：应急密码 → 登录 → API 建 node 拿 token）----
echo "== 本地 hub ($URL)"
"$HUB_BIN" --listen "127.0.0.1:$PORT" --db "$DIR/hub.db" --themes "$DIR/themes" >"$DIR/hub.log" 2>&1 &
HUB_PID=$!
wait_for "the hub to listen" curl -fs "$URL/api/me"
PASSWORD=$(sed -n 's/.*Emergency password: //p' "$DIR/hub.log" | head -1)
[ -n "$PASSWORD" ] || fail "hub 日志没有应急密码"
COOKIE=$(curl -fsS -D - -o /dev/null -H 'content-type: application/json' -d "{\"password\":\"$PASSWORD\"}" \
	"$URL/api/auth/login" | tr -d '\r' | sed -n 's/^[Ss]et-[Cc]ookie: \(monitor_session=[^;]*\).*/\1/p')
[ -n "$COOKIE" ] || fail "登录失败"
curl -fsS -o /dev/null -H "Cookie: $COOKIE" -H 'Origin: https://hub.example.com' -H 'Sec-Fetch-Site: same-origin' \
	-H 'content-type: application/json' -d '{"name":"install-e2e","remark":""}' "$URL/api/nodes" || fail "建 node 失败"
TOKEN=$(curl -fsS -H "Cookie: $COOKIE" "$URL/api/nodes" | jq -r '.nodes[0].token // empty')
[ -n "$TOKEN" ] || fail "没拿到 token"

# 装的是新脚本：改 install.sh 忘了重编 hub 时，这里当场红而不是装出旧版。
curl -fsS "$URL/install.sh" | grep -q -- "--with-gost" || fail "hub 服务的 install.sh 不含 --with-gost（include_str! 旧货？重编）"

# ---- 2. systemd 容器（配方法见文件头注释）----
echo "== systemd 容器 ($PLATFORM)"
docker rm -f "$CONTAINER" >/dev/null 2>&1 || true
docker run -d --name "$CONTAINER-prep" --platform "$PLATFORM" ubuntu:24.04 sleep infinity >/dev/null
docker exec "$CONTAINER-prep" bash -c \
	'apt-get update -qq >/dev/null && DEBIAN_FRONTEND=noninteractive apt-get install -y -qq systemd systemd-sysv dbus curl jq ca-certificates >/dev/null' \
	|| fail "备镜像装 systemd 失败"
docker commit "$CONTAINER-prep" "$CONTAINER-img" >/dev/null
docker rm -f "$CONTAINER-prep" >/dev/null
docker run -d --name "$CONTAINER" --privileged --platform "$PLATFORM" "$CONTAINER-img" /sbin/init >/dev/null
sleep 4
docker exec "$CONTAINER" systemctl is-system-running >/dev/null 2>&1 || sleep 4

# ---- 3. 全新安装：--with-realm --with-gost --no-singbox ----
echo "== install.sh --with-realm --with-gost --no-singbox"
docker exec "$CONTAINER" sh -c \
	"curl -fsSL $CURL_INNER/install.sh | sh -s -- --server $CURL_INNER --token $TOKEN --insecure --with-realm --with-gost --no-singbox" 2>&1 | tail -12

echo "== 断言：核心落位与版本"
docker exec "$CONTAINER" /opt/monitor-proxy/bin/realm --version | grep -q "2.9.8-m1" || fail "realm 版本不对"
docker exec "$CONTAINER" sh -c '/opt/monitor-proxy/bin/gost -V 2>&1 || /opt/monitor-proxy/bin/gost --version' | grep -q "3.3.2" || fail "gost 版本不对"
docker exec "$CONTAINER" sh -c 'test ! -e /opt/monitor-proxy/bin/sing-box' || fail "sing-box 不应存在（--no-singbox）"

docker exec "$CONTAINER" systemctl is-active --quiet monitor-agent || fail "monitor-agent 单元没起来"
wait_for "the node to report online" online
echo "== agent 已上线到本地 hub"

# ---- 4. --upgrade：agent 换新，核心 mtime 不动 ----
echo "== --upgrade --insecure（不带 insecure 会提前退出=虚过，见文件头）"
RL_BEFORE=$(docker exec "$CONTAINER" stat -c %Y /opt/monitor-proxy/bin/realm)
GO_BEFORE=$(docker exec "$CONTAINER" stat -c %Y /opt/monitor-proxy/bin/gost)
docker exec "$CONTAINER" sh -c \
	"curl -fsSL $CURL_INNER/install.sh | sh -s -- --upgrade --insecure" 2>&1 | tail -6
RL_AFTER=$(docker exec "$CONTAINER" stat -c %Y /opt/monitor-proxy/bin/realm)
GO_AFTER=$(docker exec "$CONTAINER" stat -c %Y /opt/monitor-proxy/bin/gost)
[ "$RL_BEFORE" = "$RL_AFTER" ] || fail "upgrade 动了 realm 二进制"
[ "$GO_BEFORE" = "$GO_AFTER" ] || fail "upgrade 动了 gost 二进制"
docker exec "$CONTAINER" systemctl is-active --quiet monitor-agent || fail "upgrade 后 agent 没起来"

echo "install-e2e: ✓ 全过"
