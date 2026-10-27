# jspanel

基于 [monitor-probe/monitor](https://github.com/monitor-probe/monitor) 的二开私用线：监控 + 代理节点管控面板。
上游文档：[monitor-document.pages.dev](https://monitor-document.pages.dev)，安装、配置、反向代理与主题开发都在这里。

## 特性

- 实时监控：秒级实时数据展示
- 轻量高效：Rust 语言构建，低资源占用，极简高效
- 自托管：完全掌控数据隐私，部署简单
- 通知：节点掉线、流量、到期与登录，推送到 Telegram 或自定义 Webhook

## 组成

| 仓库 | 说明 |
|---|---|
| [jspanel-hub](https://github.com/carsonmoon/jspanel-hub) | hub：后台、API、公开页宿主 |
| [jspanel-agent](https://github.com/carsonmoon/jspanel-agent) | Linux agent |
| [monitor-theme-default](https://github.com/monitor-probe/monitor-theme-default) | 内置默认主题 |

```
agent (Linux)  ──WebSocket / JSON-RPC 2.0──▶  hub (axum + SQLite)  ──▶  后台 + 状态页
```

## 部署

```bash
curl -fsSL https://github.com/carsonmoon/jspanel-hub/releases/latest/download/install-hub.sh -o install-hub.sh
sudo sh install-hub.sh
```

一条命令启用 HTTPS（acme.sh 签证书 + Caddy 反代 + 回填 `--site`，续期自动）：

```bash
curl -fsSL https://github.com/carsonmoon/jspanel-hub/releases/latest/download/setup-tls.sh -o setup-tls.sh
sudo sh setup-tls.sh --domain panel.example.com --email ops@example.com
```

已装好的 hub 也能直接从自身取这份脚本：`curl -fsSL https://<hub>/setup-tls.sh`。
`--dns dns_cf` 等走 DNS API，支持泛域名与 CDN 场景；`--status` 查看，`--off` 撤下。

