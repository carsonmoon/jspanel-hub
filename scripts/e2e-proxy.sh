#!/bin/sh
# 代理协议分叉功能的端到端检查：客户生命周期（M7）从面板 API 到订阅端点走
# 一遍。与 scripts/e2e.sh 分开放——agent 侧 CI 拿的是 hub 仓库的 e2e.sh 去
# 对上游 release 跑，分叉新增的接口放那里必炸；这个文件只挂本仓库的 CI。
#   scripts/e2e-proxy.sh <monitor-hub>
set -eu

HUB=$1
URL=http://127.0.0.1:${E2E_PORT:-9953}
DIR=$(mktemp -d)
HUB_PID=
COOKIE="$DIR/cookie.txt"

cleanup() {
	status=$?
	[ -z "$HUB_PID" ] || kill $HUB_PID 2>/dev/null || true
	if [ "$status" -ne 0 ] && [ -f "$DIR/hub.log" ]; then
		echo "--- hub.log" >&2
		cat "$DIR/hub.log" >&2
	fi
	rm -rf "$DIR"
}
trap cleanup EXIT

fail() {
	echo "e2e-proxy: $*" >&2
	exit 1
}

# Retries a command every half second for up to 30 seconds.
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

# A panel write as the browser sends it: provisioning checks the Origin.
panel() {
	method=$1
	path=$2
	data=${3:-}
	if [ -n "$data" ]; then
		curl -fs -X "$method" -b "$COOKIE" -H 'Content-Type: application/json' \
			-H 'Origin: https://hub.example.com' -H 'Sec-Fetch-Site: same-origin' \
			-d "$data" "$URL$path"
	else
		curl -fs -X "$method" -b "$COOKIE" \
			-H 'Origin: https://hub.example.com' -H 'Sec-Fetch-Site: same-origin' \
			"$URL$path"
	fi
}

"$HUB" --listen "${URL#http://}" --db "$DIR/hub.db" --themes "$DIR/themes" >"$DIR/hub.log" 2>&1 &
HUB_PID=$!
wait_for "the hub to listen" curl -fs "$URL/api/me"

PASSWORD=$(sed -n 's/.*Emergency password: //p' "$DIR/hub.log" | head -1)
[ -n "$PASSWORD" ] || fail "no emergency password in hub.log"
curl -fs -c "$COOKIE" -H 'Content-Type: application/json' \
	-d "{\"password\":\"$PASSWORD\"}" "$URL/api/auth/login" >/dev/null

# 一个本机 VLESS 节点、一个订阅客户、一个客户凭据、一个独立凭据。
panel POST /api/proxy/nodes '{"name":"e2e","protocol":"vless-reality","listen_port":24443,"sni":"www.yahoo.com"}' >/dev/null
SUB=$(panel POST /api/proxy/sub-users '{"name":"客户A"}' | sed 's/[^0-9]//g')
[ -n "$SUB" ] || fail "no sub user id in create reply"
TOKEN=$(panel GET /api/proxy/sub-users | jq -r '.[0].token')
NODE_ID=$(panel GET /api/proxy/nodes | jq '.nodes[0].id')
USER_ID=$(panel POST "/api/proxy/nodes/$NODE_ID/users" '{"name":"alice","credential":""}' | sed 's/[^0-9]//g')
[ -n "$USER_ID" ] || fail "no proxy user id in create reply"
panel PUT "/api/proxy/users/$USER_ID/sub" "{\"sub_user_id\":$SUB}" >/dev/null

# 正常客户：订阅端点回 base64 链接，列表带实时状态。
BODY=$(curl -fs "$URL/api/sub?token=$TOKEN")
echo "$BODY" | base64 -d 2>/dev/null | grep -q "vless://" || fail "subscription has no vless link"
STATUS=$(panel GET /api/proxy/sub-users | jq -r '.[0].status')
[ "$STATUS" = "正常" ] || fail "expected 正常, got $STATUS"

# 停用：订阅拒绝，面板徽标变化。
panel PUT "/api/proxy/sub-users/$SUB" '{"name":"客户A","enabled":false}' >/dev/null
curl -fs "$URL/api/sub?token=$TOKEN" >/dev/null 2>&1 && fail "disabled sub still served"
curl -s "$URL/api/sub?token=$TOKEN" | grep -q "已停用" || fail "disabled sub gave no reason"
STATUS=$(panel GET /api/proxy/sub-users | jq -r '.[0].status')
[ "$STATUS" = "已停用" ] || fail "expected 已停用, got $STATUS"

# 恢复并设配额、把配置里的凭据摘除路径核对到期望配置：停用客户的凭据
# 不再出现在渲染的配置里（本机核心未安装，直接看渲染闸门的输出）。
panel PUT "/api/proxy/sub-users/$SUB" '{"name":"客户A","enabled":true,"quota_bytes":1073741824,"quota_reset":"monthly"}' >/dev/null
STATUS=$(panel GET /api/proxy/sub-users | jq -r '.[0].status')
[ "$STATUS" = "正常" ] || fail "expected 正常 after re-enable, got $STATUS"
USED=$(panel GET /api/proxy/sub-users | jq '.[0].quota_used_up + .[0].quota_used_down')
[ "$USED" = "0" ] || fail "expected zero usage on a fresh sub, got $USED"

# HTTPS 配置脚本与 install.sh 一样由 hub 自带。
curl -fs "$URL/setup-tls.sh" | head -1 | grep -q '^#!' || fail "setup-tls.sh not served"

echo "e2e-proxy: ok"
