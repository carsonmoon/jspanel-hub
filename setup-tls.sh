#!/bin/sh
# monitor hub 的 HTTPS 一键配置：acme.sh 签证书，Caddy 终结 TLS 反代到本机
# 回环的 hub。与 install-hub.sh 分开是刻意的——那份脚本是上游高频修改的文
# 件，注入 TLS 功能块意味着每次同步上游都要解冲突；而它升级 hub 时本就保
# 留单元里已有的 --site，这里写一次、之后每次升级自动沿用。
#
#   sudo sh setup-tls.sh --domain panel.example.com [--email ops@example.com]
#                        [--dns dns_cf] [--port 28080]
#   sudo sh setup-tls.sh --status
#   sudo sh setup-tls.sh --off --domain panel.example.com
#
# 默认 HTTP-01（Caddy 以 webroot 方式回放 80 端口的质询）；--dns 走 acme.sh
# 的 DNS API（如 dns_cf，凭据经环境变量传入，如 CF_Token），支持泛域名，域
# 名挂 CDN 时也能签。
set -eu
PATH="$PATH:/usr/sbin:/sbin"

SERVICE="monitor-hub"
UNIT="/etc/systemd/system/monitor-hub.service"
ROOT="/opt/monitor"
TLS_DIR="$ROOT/tls"
ACME_WEBROOT="$ROOT/acme"
ACME="$HOME/.acme.sh/acme.sh"
CADDYFILE="/etc/caddy/Caddyfile"
MARK_BEGIN="# monitor-hub managed -- begin"
MARK_END="# monitor-hub managed -- end"
DEFAULT_PORT="28080"
PORT=""
DOMAIN=""
EMAIL=""
DNS=""
ACTION=""

# ---- ui ----
if [ -t 1 ] && [ -z "${NO_COLOR-}" ]; then
	B="$(printf '\033[1m')" D="$(printf '\033[2m')" N="$(printf '\033[0m')"
	G="$(printf '\033[32m')" R="$(printf '\033[31m')" Y="$(printf '\033[33m')"
else
	B="" D="" N="" G="" R="" Y=""
fi
rule() { printf '  %s────────────────────────────────────────────%s\n' "$D" "$N"; }
ok() { printf '  %s✓%s  %s    %s%s%s\n' "$G" "$N" "$1" "$D" "${2-}" "$N"; }
field() { printf '  %s%s%s    %s\n' "$D" "$1" "$N" "$2"; }
warn() { printf '  %s!%s  %s\n' "$Y" "$N" "$1"; }
die() { printf '  %s✗%s  %s\n' "$R" "$N" "$1" >&2; exit 1; }
banner() {
	printf '\n  %smonitor hub%s  %s·%s  HTTPS 配置\n' "$B" "$N" "$D" "$N"
	rule
	printf '\n'
}

usage() {
	# 静态文本而不是 sed 抽 $0 注释：curl | sh 时 $0 是 "sh"，没有文件可读。
	cat <<'EOF'
monitor hub 的 HTTPS 一键配置：acme.sh 签证书，Caddy 终结 TLS 反代到本机回环的 hub。

  sudo sh setup-tls.sh --domain panel.example.com [--email ops@example.com]
                       [--dns dns_cf] [--port 28080]
  sudo sh setup-tls.sh --status
  sudo sh setup-tls.sh --off --domain panel.example.com

默认 HTTP-01（Caddy 以 webroot 回放 80 端口质询）；--dns 走 acme.sh 的 DNS
API（如 dns_cf，凭据经环境变量传入，如 CF_Token），支持泛域名，域名挂 CDN
时也能签。幂等，可重复运行；--off 只摘托管站点块与 --site，证书保留。
EOF
	exit 0
}

for arg in "$@"; do
	case "$arg" in
	-h | --help) usage ;;
	esac
done

while [ $# -gt 0 ]; do
	case "$1" in
	--domain) DOMAIN="${2-}"; shift ;;
	--email) EMAIL="${2-}"; shift ;;
	--dns) DNS="${2-}"; shift ;;
	--port) PORT="${2-}"; shift ;;
	--status) ACTION="status" ;;
	--off) ACTION="off" ;;
	*) die "未知参数：$1（--help 看用法）" ;;
	esac
	shift
done

# ---- 前置 ----

[ "$(id -u)" = "0" ] || die "请用 root 运行（sudo sh setup-tls.sh ...）"
[ -f "$UNIT" ] || die "没找到 $UNIT：先用 install-hub.sh 装 hub"

# hub 实际监听的端口：从单元的 ExecStart 里抠 --listen 的尾巴，与本机安
# 装脚本同源，避免两边各记一份。
unit_port() {
	grep -o ' --listen [^ ]*' "$UNIT" | awk 'NR == 1 { print $NF }' | sed 's/.*://'
}
PORT="${PORT:-$(unit_port)}"
PORT="${PORT:-$DEFAULT_PORT}"

# 单元里已有的 --site：更新而不是追加，保持 ExecStart 恰好一个 --site。
site_in_unit() { grep -q ' --site ' "$UNIT"; }

dns_resolve() {
	if command -v dig >/dev/null 2>&1; then
		dig +short "$1" A "$1" AAAA 2>/dev/null | grep -q .
	elif command -v nslookup >/dev/null 2>&1; then
		nslookup "$1" >/dev/null 2>&1
	elif command -v getent >/dev/null 2>&1; then
		getent hosts "$1" >/dev/null 2>&1
	else
		return 0 # 没有解析工具就不挡路，签发时会暴露问题
	fi
}

# 占用 80/443 的进程名，给人看错误提示用。
port_holder() {
	if command -v ss >/dev/null 2>&1; then
		ss -tlnp "sport = :$1" 2>/dev/null | sed -n 's/.*users:((\"\([^\"]*\)\".*/\1/p' | head -1
	fi
}

preflight() {
	[ -n "$DOMAIN" ] || die "缺少 --domain 域名"
	case "$DOMAIN" in
	*.*) ;;
	*) die "$DOMAIN 不像域名：需要一个解析到本机的 FQDN" ;;
	esac
	if [ ! -n "$DNS" ]; then
		dns_resolve "$DOMAIN" || die "$DOMAIN 解析不到地址：等 DNS 生效，或用 --dns 走 DNS API 验证"
		# HTTP-01 的质询由 Caddy 在 80 端口回放。
		holder=$(port_holder 80 || true)
		if [ -n "$holder" ] && [ "$holder" != "caddy" ]; then
			die "80 端口被 $holder 占用：HTTP-01 验证需要它。改用 --dns，或把 $holder 挪走"
		fi
	fi
	holder=$(port_holder 443 || true)
	if [ -n "$holder" ] && [ "$holder" != "caddy" ]; then
		die "443 端口被 $holder 占用：代理节点的端口池若含 443，请在面板里换端口后再启用 HTTPS"
	fi
	ok "前置检查" "$DOMAIN → 127.0.0.1:$PORT"
}

# ---- 组件 ----

install_caddy() {
	if command -v caddy >/dev/null 2>&1; then
		ok "Caddy" "已安装 $(caddy version 2>/dev/null | cut -d' ' -f1)"
		return
	fi
	warn "安装 Caddy（官方源）…"
	if command -v apt-get >/dev/null 2>&1; then
		export DEBIAN_FRONTEND=noninteractive
		apt-get update -qq
		apt-get install -y -qq debian-keyring debian-archive-keyring apt-transport-https curl gnupg >/dev/null
		# cloudsmith 的 key 是 ASCII 甲胄格式，Debian 13 的 apt（sqv）要求
		# 去甲后的 .gpg，且 sources 列表按这个路径引用。
		curl -fsSL "https://dl.cloudsmith.io/public/caddy/stable/gpg.key" | gpg --dearmor -o /usr/share/keyrings/caddy-stable-archive-keyring.gpg
		curl -fsSL "https://dl.cloudsmith.io/public/caddy/stable/debian.deb.txt" >/etc/apt/sources.list.d/caddy-stable.list
		apt-get update -qq
		apt-get install -y -qq caddy >/dev/null
	elif command -v dnf >/dev/null 2>&1; then
		dnf install -y 'dnf-command(copr)' >/dev/null
		dnf copr enable -y @caddy/caddy >/dev/null
		dnf install -y caddy >/dev/null
	elif command -v yum >/dev/null 2>&1; then
		yum install -y yum-plugin-copr >/dev/null
		yum copr enable -y @caddy/caddy >/dev/null
		yum install -y caddy >/dev/null
	else
		die "不认识的包管理器：请手动安装 Caddy 后重跑"
	fi
	ok "Caddy" "$(caddy version 2>/dev/null | cut -d' ' -f1)"
}

install_acme() {
	if [ -x "$ACME" ]; then
		ok "acme.sh" "已安装"
	else
		warn "安装 acme.sh…"
		# acme.sh 没有可用的 crontab 就拒装，而自动续期正靠它。
		if ! command -v crontab >/dev/null 2>&1; then
			if command -v apt-get >/dev/null 2>&1; then
				DEBIAN_FRONTEND=noninteractive apt-get install -y -qq cron >/dev/null
				systemctl enable --now cron >/dev/null 2>&1 || true
			elif command -v dnf >/dev/null 2>&1; then
				dnf install -y cronie >/dev/null
				systemctl enable --now crond >/dev/null 2>&1 || true
			elif command -v yum >/dev/null 2>&1; then
				yum install -y cronie >/dev/null
				systemctl enable --now crond >/dev/null 2>&1 || true
			fi
		fi
		curl -fsSL https://get.acme.sh | sh -s >/dev/null
		[ -x "$ACME" ] || die "acme.sh 安装失败"
	fi
	# 默认 Let's Encrypt：ZeroSSL 的匿名注册经常被拒，LE 只在没邮箱时少一封
	# 到期提醒。
	"$ACME" --set-default-ca --server letsencrypt >/dev/null 2>&1 || true
	if [ -n "$EMAIL" ]; then
		"$ACME" --register-account -m "$EMAIL" >/dev/null 2>&1 || true
	fi
}

# Caddyfile 里属于本脚本的部分：两枚标记之间的托管块。别人的站点原样保留。
strip_managed() {
	awk -v b="$MARK_BEGIN" -v e="$MARK_END" 'index($0, b) {skip = 1; next} index($0, e) {skip = 0; next} !skip'
}

# 先让 Caddy 以纯 HTTP 状态起来，只回放 ACME 质询；签下证书后再切换到完整
# 的 TLS 站点。证书没签下来之前 Caddy 起不来 TLS 块（文件不存在）。已有
# 配置里的非托管内容原样保留。
bootstrap_caddyfile() {
	mkdir -p "$ACME_WEBROOT"
	if [ -f "$CADDYFILE" ]; then
		strip_managed <"$CADDYFILE" >"$CADDYFILE.new"
	else
		: >"$CADDYFILE.new"
	fi
	# redir 在 Caddy 默认指令序里先于 handle_path 执行，质询会被 301 走，
	# 所以跳转必须收进排在其后的 handle 块。
	cat >>"$CADDYFILE.new" <<EOF
$MARK_BEGIN
http://$DOMAIN {
	handle /.well-known/acme-challenge/* {
		root * $ACME_WEBROOT
		file_server
	}
	handle {
		redir https://{host}{uri} permanent
	}
}
$MARK_END
EOF
	caddy validate --config "$CADDYFILE.new" >/dev/null 2>&1 || die "生成的 Caddyfile 校验失败"
	mv "$CADDYFILE.new" "$CADDYFILE"
	systemctl enable --now caddy >/dev/null 2>&1 || true
	systemctl restart caddy
}

issue_cert() {
	warn "签发证书（$DOMAIN，${DNS:+DNS API $DNS}${DNS:-HTTP-01}）…"
	set -- "$ACME" --issue -d "$DOMAIN" --server letsencrypt
	if [ -n "$DNS" ]; then
		set -- "$@" --dns "$DNS"
	else
		set -- "$@" -w "$ACME_WEBROOT"
	fi
	if ! "$@"; then
		[ -n "$DNS" ] && warn "DNS 模式需要提供商凭据在环境变量里（如 dns_cf 的 CF_Token/CF_Account_ID），参考 acme.sh 的 dnsapi 文档"
		die "签发失败；上面的 acme.sh 输出有原因"
	fi
	mkdir -p "$TLS_DIR"
	"$ACME" --install-cert -d "$DOMAIN" \
		--fullchain-file "$TLS_DIR/fullchain.pem" \
		--key-file "$TLS_DIR/key.pem" \
		--reloadcmd "systemctl reload caddy" >/dev/null
	# Caddy 服务用户要能读私钥；目录随 install-hub 是 0755。
	chmod 755 "$TLS_DIR"
	chmod 644 "$TLS_DIR/fullchain.pem"
	if getent group caddy >/dev/null 2>&1; then
		chown root:caddy "$TLS_DIR/key.pem"
		chmod 640 "$TLS_DIR/key.pem"
	else
		chmod 644 "$TLS_DIR/key.pem"
	fi
	ok "证书" "$TLS_DIR（续期由 acme.sh 的 cron 自动完成，reload Caddy）"
}

# 完整站点块：80 回放质询并跳 https，443 终结 TLS 反代回环的 hub。
# WebSocket（agent 上报）对 reverse_proxy 是透明的，无需额外配置。
caddy_block() {
	cat <<EOF
$MARK_BEGIN
http://$DOMAIN {
	handle /.well-known/acme-challenge/* {
		root * $ACME_WEBROOT
		file_server
	}
	redir https://{host}{uri} permanent
}

$DOMAIN {
	tls $TLS_DIR/fullchain.pem $TLS_DIR/key.pem
	reverse_proxy 127.0.0.1:$PORT
}
$MARK_END
EOF
}

write_caddyfile() {
	# 有托管块就只换托管块，不动文件里别人的站点；没有就从现有文件（或空）
	# 起步，把托管块追加在末尾。
	if [ -f "$CADDYFILE" ] && grep -qF "$MARK_BEGIN" "$CADDYFILE"; then
		strip_managed <"$CADDYFILE" >"$CADDYFILE.new"
	elif [ -f "$CADDYFILE" ]; then
		warn "已有 $CADDYFILE：托管站点块追加在文件末尾"
		cp "$CADDYFILE" "$CADDYFILE.new"
	else
		: >"$CADDYFILE.new"
	fi
	caddy_block >>"$CADDYFILE.new"
	caddy validate --config "$CADDYFILE.new" >/dev/null 2>&1 || die "Caddyfile 校验失败，已保留原文件"
	mv "$CADDYFILE.new" "$CADDYFILE"
	systemctl reload caddy 2>/dev/null || systemctl restart caddy
	ok "Caddy" "$DOMAIN → 127.0.0.1:$PORT"
}

# 单元 ExecStart 回填 --site：写一次终身有效——install-hub.sh 升级时保留
# 单元里已有的 --site，之后所有升级自动沿用。
set_site() {
	if site_in_unit; then
		sed -i "s| --site [^ ]*| --site https://$DOMAIN|" "$UNIT"
	else
		sed -i "/^ExecStart=/s|$| --site https://$DOMAIN|" "$UNIT"
	fi
	systemctl daemon-reload
	systemctl restart "$SERVICE"
	ok "hub" "--site https://$DOMAIN 已写入单元并重启"
}

verify() {
	printf '  %s…%s  健康检查\n' "$D" "$N"
	i=0
	until curl -fs "https://$DOMAIN/api/me" >/dev/null 2>&1; do
		i=$((i + 1))
		[ "$i" -le 30 ] || {
			warn "https://$DOMAIN 还没通：看 systemctl status caddy 与 journalctl -u caddy -n 50"
			warn "证书与配置都留在原处，排除后重跑本脚本即可"
			exit 1
		}
		sleep 1
	done
	ok "健康检查" "https://$DOMAIN/api/me"
}

status() {
	banner
	if [ -f "$TLS_DIR/fullchain.pem" ]; then
		field "证书" "$(openssl x509 -in "$TLS_DIR/fullchain.pem" -noout -subject -enddate 2>/dev/null | tr '\n' ' ')"
	else
		field "证书" "未签发"
	fi
	if systemctl is-active --quiet caddy 2>/dev/null; then
		field "Caddy" "运行中"
	else
		field "Caddy" "未运行"
	fi
	if site_in_unit; then
		field "--site" "$(grep -o ' --site [^ ]*' "$UNIT" | head -1 | cut -d' ' -f3)"
	else
		field "--site" "未设置"
	fi
	[ -f "$CADDYFILE" ] && grep -qF "$MARK_BEGIN" "$CADDYFILE" && field "站点块" "已托管于 $CADDYFILE" ||
		field "站点块" "无"
}

off() {
	[ -n "$DOMAIN" ] || die "--off 需要同时给 --domain（确认要撤的站点）"
	printf '  %s?%s  撤下 %s 的 HTTPS（证书保留在 %s）  %s[y/N]%s ' "$Y" "$N" "$DOMAIN" "$TLS_DIR" "$D" "$N"
	if [ -t 0 ]; then
		read -r reply || reply=""
		case "$reply" in y | Y | yes) ;; *) printf '  已取消\n'; exit 0 ;; esac
	fi
	if [ -f "$CADDYFILE" ] && grep -qF "$MARK_BEGIN" "$CADDYFILE"; then
		strip_managed <"$CADDYFILE" >"$CADDYFILE.new"
		mv "$CADDYFILE.new" "$CADDYFILE"
		systemctl reload caddy 2>/dev/null || systemctl restart caddy || true
		ok "Caddy" "托管站点块已移除"
	fi
	if site_in_unit; then
		sed -i 's| --site [^ ]*||' "$UNIT"
		systemctl daemon-reload
		systemctl restart "$SERVICE"
		ok "hub" "--site 已移除并重启"
	fi
}

case "${ACTION:-up}" in
status)
	status
	;;
off)
	off
	;;
up)
	banner
	preflight
	install_caddy
	install_acme
	# HTTP-01 需要一个能回放质询的 80 站点先跑起来；DNS 模式不需要。
	[ -n "$DNS" ] || bootstrap_caddyfile
	issue_cert
	write_caddyfile
	set_site
	verify
	printf '\n'
	ok "完成" "面板 https://$DOMAIN/admin"
	field "订阅" "入口地址面板里填 $DOMAIN（设置 → 站点设置 → 订阅入口地址）"
	field "续期" "acme.sh cron 自动续期并 reload Caddy，无需人工"
	printf '\n'
	;;
esac
