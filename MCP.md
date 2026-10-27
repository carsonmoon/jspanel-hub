# MCP 接入指南

面板可以把自己暴露成一个 MCP（Model Context Protocol）服务器：Claude Desktop、Cursor 等支持 MCP 的 AI 客户端经 OAuth 授权后，即可查询监控数据，并在授权范围内对被管节点执行命令。所有能力只读为主、每一次调用都进审计，随时可吊销。

## 能力一览

| 工具 | 说明 |
|---|---|
| `get_overview` | 概览：告警（离线/探测/流量）、统计摘要 |
| `list_nodes` / `get_node` | 被管主机列表 / 单机详情（在线状态、指标） |
| `list_protocols` | 代理节点与凭据概况 |
| `list_customers` | 订阅客户与用量 |
| `list_ping_tasks` | 监控（ping）任务及其目标 |
| `list_route_tasks` | 回程线路探测任务与结果 |
| `list_logs` | 连接日志 |
| `exec_command` | 在指定节点执行一次性命令（`sh -c`）。超时 1–120 秒，输出每流封顶 64KB，**每次执行都进审计** |

## 快速接入（标准 MCP 客户端）

前提：管理员在面板 **安全页 → MCP 代理** 打开总开关（默认关闭）。

在客户端的 MCP 服务器设置里把面板注册为远程服务器，URL 填：

```
https://panel.example.com/api/mcp
```

以 Cursor / Claude Desktop 为例（支持远程 MCP + OAuth 自动发现）：

```json
{
  "mcpServers": {
    "jspanel": { "url": "https://panel.example.com/api/mcp" }
  }
}
```

客户端会自动完成动态注册并跳转浏览器：**用管理员账号登录面板**，在批准页选择租约时长后确认，回到客户端即可使用全部工具。租约到期自动失效，也可在安全页随时吊销。

## 手动流程（了解原理或自行开发客户端时）

认证按 OAuth 2.0 授权码 + PKCE（S256），四步：

```sh
PANEL=https://panel.example.com

# 1. 动态注册（拿 client_id / client_secret）
curl -X POST $PANEL/api/mcp/register -H 'Content-Type: application/json' \
  -d '{"client_name":"我的客户端","redirect_uris":["http://localhost:8765/callback"]}'

# 2. 浏览器打开授权页（管理员会话内）批准；或模拟表单提交：
#    POST /api/mcp/authorize  表单字段 client_id / redirect_uri /
#    code_challenge / code_challenge_method=S256 / duration_hours(1-720) /
#    decision=approve
#    → 302 回跳 redirect_uri?code=…

# 3. 授权码换访问令牌（授权码 5 分钟一次性；code_verifier 对应步骤 2 的 challenge）
curl -X POST $PANEL/api/mcp/token -H 'Content-Type: application/x-www-form-urlencoded' \
  -d "grant_type=authorization_code&code=…&client_id=…&client_secret=…&redirect_uri=…&code_verifier=…"

# 4. 调用（JSON-RPC，MCP Streamable HTTP）
curl -X POST $PANEL/api/mcp \
  -H "Authorization: Bearer <access_token>" -H 'Content-Type: application/json' \
  -d '{"jsonrpc":"2.0","id":1,"method":"tools/list"}'
```

说明：

- `redirect_uri` 必须是 https；本机回环（127.0.0.1 / localhost）允许 http
- OAuth 发现端点：`/.well-known/oauth-protected-resource`、`/.well-known/oauth-authorization-server`
- 工具调用方法：`tools/list`、`tools/call`（`exec_command` 的参数为 `node`（主机名或 id）、`command`、可选 `timeout_ms`）

## 安全模型

- **总开关默认关**：关闭时 `/api/mcp` 一律拒绝，已有 Bearer 也无效
- **租约制**：批准时选时长（1–720 小时），到期自动失效；安全页可单条吊销，吊销即时生效
- **授权码一次性**：5 分钟有效，兑换失败（含 verifier 错误）同样作废
- **全程审计**：每次工具调用（含失败）在安全页「最近操作」留一行：工具、目标节点、参数摘要、时间、租约标识
- **exec 的信任边界**：命令经面板 → 节点 agent 以 **root** 执行（agent 通道即 root 信任域，与配置下发同域），面板不做命令白名单——把租约只发给可信的客户端，用完即吊销

## 常见问题

- **工具调用返回「租约无效或已过期」**：租约到期/被吊销/总开关被关，重新走授权即可
- **授权页让我先登录**：正常——批准动作必须由管理员会话完成
- **审计里没有记录**：确认面板版本 ≥ 1.4.1（1.4.0 有审计列表类型错序的显示问题）
