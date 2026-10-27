import { useCallback, useEffect, useRef, useState } from "react"
import { CalendarDays, Download, RefreshCw, Search } from "lucide-react"
import { toast } from "sonner"

import { Notice } from "@/components/ui/notice"
import { Button } from "@/components/ui/button"
import { PageHeader } from "@/components/page-header"
import { Card } from "@/components/ui/card"
import { Input } from "@/components/ui/input"
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select"
import { Switch } from "@/components/ui/switch"
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table"
import { api } from "@/lib/api"

type ConnLogRow = {
  conn_id: string
  first: number
  last: number
  user: string
  sub_user_id: number
  inbound: string
  source: string
  geo: string
  host: string
  port: number
  network: string
  up: number
  down: number
  server_id: number
}

type Summary = {
  top_hosts: { host: string; count: number; bytes: number }[]
  top_clients: { source: string; geo: string; count: number; bytes: number }[]
}

const PAGE_SIZE = 50

function fmtTime(ts: number) {
  return new Date(ts * 1000).toLocaleString("zh-CN", { hour12: false })
}

function protocolLabel(port: number, network: string) {
  // 8080：Ookla/Speedtest 测速服务器惯用端口，日志里高频出现
  const base =
    port === 443 ? "HTTPS"
    : port === 80 ? "HTTP"
    : port === 53 ? "DNS"
    : port === 22 ? "SSH"
    : port === 8080 ? "HTTP"
    : null
  // 未知端口 + network 未知（sing-box 事件解析遗留，库中 network 常为空）→
  // 回退显示端口本身，绝不出空 chip
  if (!base) return network ? network.toUpperCase() : `:${port}`
  return network === "udp" ? `${base}/UDP` : base
}

// 协议 → 彩虹 chip 色类（色值在 index.css 的 .lg-*，与协议页彩虹 chips 同饱和度公式）：
// 443 蓝、80 橙、53 青、22 绿、其他 udp=QUIC 天蓝、其他 tcp=TLS 紫
function logChipClass(label: string): string {
  if (label.startsWith("HTTPS")) return label.endsWith("UDP") ? "lg-quic" : "lg-https"
  if (label === "HTTP") return "lg-http"
  if (label.startsWith("DNS")) return "lg-dns"
  if (label === "SSH") return "lg-ssh"
  if (label.endsWith("UDP")) return "lg-quic"
  if (label === "TLS") return "lg-tls"
  return "lg-other"
}

// 行的入站 tag → 节点名：优先同服务器精确匹配（端口可跨服务器复用），
// 退而按 tag 匹配，都没有（节点已删/旧数据）显示原始 tag。
function nodeLabel(r: ConnLogRow, nodes: { tag: string; name: string; server_id: number }[]) {
  return (
    nodes.find((n) => n.tag === r.inbound && n.server_id === r.server_id)?.name ??
    nodes.find((n) => n.tag === r.inbound)?.name ??
    r.inbound
  )
}

// 日期（YYYY-MM-DD，本地时区）→ unix 秒：开始取当日零点；结束取当日末尾，
// 选同一天即过滤整天。空串返回 undefined。
const fmtSince = (d: string) => (d ? String(Math.floor(new Date(`${d}T00:00:00`).getTime() / 1000)) : undefined)
const fmtUntil = (d: string) => (d ? String(Math.floor(new Date(`${d}T23:59:59`).getTime() / 1000)) : undefined)

export default function Logs() {
  const [rows, setRows] = useState<ConnLogRow[]>([])
  const [total, setTotal] = useState(0)
  const [page, setPage] = useState(1)
  const [recording, setRecording] = useState(true)
  const [source, setSource] = useState("all")
  const [server, setServer] = useState("all")
  const [node, setNode] = useState("all")
  const [q, setQ] = useState("")
  const [query, setQuery] = useState("")
  const [since, setSince] = useState("")
  const [until, setUntil] = useState("")
  const [servers, setServers] = useState<{ id: number; name: string }[]>([])
  const [nodes, setNodes] = useState<{ tag: string; name: string; server_id: number }[]>([])
  const [customers, setCustomers] = useState<string[]>([])
  const [summary, setSummary] = useState<Summary>({ top_hosts: [], top_clients: [] })
  const [busy, setBusy] = useState(false)

  // 记录开关：读设置并在切换时保存。
  useEffect(() => {
    api<Record<string, unknown>>("/settings")
      .then((s) => setRecording(s.conn_log_enabled !== "off"))
      .catch(() => setRecording(true))
  }, [])
  const toggleRecording = async (v: boolean) => {
    setRecording(v)
    try {
      await api("/settings", { method: "PUT", body: JSON.stringify({ conn_log_enabled: v ? "on" : "off" }) })
      toast.success(v ? "已开启记录" : "已关闭记录（已有日志保留到期自动清理）")
    } catch (e) {
      toast.error((e as Error).message)
      setRecording(!v)
    }
  }

  // 筛选下拉的数据：服务器（监控节点）、代理节点、客户名。
  useEffect(() => {
    api<{ nodes: { id: number; name: string; online: boolean }[] }>("/nodes")
      .then((r) => setServers(r.nodes.map((n) => ({ id: n.id, name: n.name }))))
      .catch(() => setServers([]))
    api<{ nodes: { name: string; listen_port: number; server_id: number }[] }>("/proxy/nodes")
      .then((r) =>
        setNodes(
          r.nodes.map((n) => ({ tag: `in-${n.listen_port}`, name: n.name, server_id: n.server_id })),
        ),
      )
      .catch(() => setNodes([]))
    api<{ name: string }[]>("/proxy/sub-users")
      .then((r) => setCustomers(r.map((s) => s.name)))
      .catch(() => setCustomers([]))
  }, [])

  const params = useCallback(() => {
    const p = new URLSearchParams()
    if (server !== "all") p.set("server", server)
    if (source !== "all") p.set("user", source)
    if (node !== "all") p.set("node", node)
    if (query) p.set("q", query)
    const s = fmtSince(since)
    const u = fmtUntil(until)
    if (s) p.set("since", s)
    if (u) p.set("until", u)
    return p
  }, [server, source, node, query, since, until])

  const load = useCallback(async () => {
    setBusy(true)
    try {
      const p = params()
      p.set("page", String(page))
      const r = await api<{ rows: ConnLogRow[]; total: number }>(`/proxy/connection-logs?${p}`)
      setRows(r.rows)
      setTotal(r.total)
      setSummary(await api<Summary>(`/proxy/connection-logs/summary?${p}`))
    } catch (e) {
      toast.error((e as Error).message)
    } finally {
      setBusy(false)
    }
  }, [params, page])

  useEffect(() => {
    load()
  }, [load])

  const exportCsv = () => {
    window.open(`/api/proxy/connection-logs/export.csv?${params()}`, "_blank")
  }

  // 时间范围：快捷下拉选择时自动填开始日期（清空结束日期）；手动改日期
  // 视为自定义。hours=null 表示全部（清空日期）。
  const [quick, setQuickState] = useState("168")
  const setQuick = (v: string) => setQuickState(v)
  const applyRange = (hours: number | null) => {
    if (hours === null) {
      setSince("")
      setUntil("")
    } else {
      const d = new Date(Date.now() - hours * 3600_000)
      const pad = (n: number) => String(n).padStart(2, "0")
      setSince(`${d.getFullYear()}-${pad(d.getMonth() + 1)}-${pad(d.getDate())}`)
      setUntil("")
    }
    setPage(1)
  }
  const applyQuick = (v: string) => {
    setQuickState(v)
    applyRange(v === "all" || v === "custom" ? null : Number(v))
  }

  // 节点下拉跟随服务器过滤。
  const nodeOptions = node === "all" ? nodes : nodes.filter((n) => server === "all" || n.server_id === Number(server))

  const totalPages = Math.max(1, Math.ceil(total / PAGE_SIZE))

  return (
    <div className="flex flex-col gap-6">
      <PageHeader
        title="日志"
        description="逐连接记录客户端 IP、归属地与访问目标；保留期在「设置」页，过期自动清理。"
        actions={
          <>
            <Button variant="outline" size="sm" onClick={exportCsv}>
              <Download className="size-3.5" /> 导出 CSV
            </Button>
            <Button variant="ghost" size="icon" onClick={() => load().catch((e) => toast.error(e.message))}>
              <RefreshCw className="size-4" />
            </Button>
          </>
        }
      />

      <Card className="flex flex-row items-center gap-3 px-4 py-2.5">
        <span className="text-sm text-muted-foreground">记录</span>
        <Switch checked={recording} onCheckedChange={(v) => toggleRecording(v).catch(() => {})} id="rec-sw" />
      </Card>

      <Card className="flex flex-row flex-wrap items-center gap-x-2 gap-y-2 px-4 py-2.5">
        <Select value={source} onValueChange={(v) => (setSource(v), setPage(1))}>
          <SelectTrigger className="w-auto min-w-28">
            <SelectValue placeholder="全部来源" />
          </SelectTrigger>
          <SelectContent>
            <SelectItem value="all">全部来源</SelectItem>
            <SelectItem value="__none__">自用（未认领）</SelectItem>
            {customers.map((c) => (
              <SelectItem key={c} value={c}>
                {c}
              </SelectItem>
            ))}
          </SelectContent>
        </Select>
        <Select value={server} onValueChange={(v) => (setServer(v), setNode("all"), setPage(1))}>
          <SelectTrigger className="w-auto min-w-28">
            <SelectValue placeholder="全部服务器" />
          </SelectTrigger>
          <SelectContent>
            <SelectItem value="all">全部服务器</SelectItem>
            <SelectItem value="0">本机</SelectItem>
            {servers.map((sv) => (
              <SelectItem key={sv.id} value={String(sv.id)}>
                {sv.name}
              </SelectItem>
            ))}
          </SelectContent>
        </Select>
        <Select value={node} onValueChange={(v) => (setNode(v), setPage(1))}>
          <SelectTrigger className="w-auto min-w-28">
            <SelectValue placeholder="全部主机" />
          </SelectTrigger>
          <SelectContent>
            <SelectItem value="all">全部主机</SelectItem>
            {nodeOptions.map((n) => (
              <SelectItem key={n.tag} value={n.tag}>
                {n.name}
              </SelectItem>
            ))}
          </SelectContent>
        </Select>
        <div className="relative min-w-44 flex-1">
          <Search className="absolute left-2.5 top-2.5 size-4 text-muted-foreground" />
          <Input
            value={q}
            onChange={(e) => setQ(e.target.value)}
            onKeyDown={(e) => {
              if (e.key === "Enter") {
                setQuery(q)
                setPage(1)
              }
            }}
            onBlur={() => q !== query && (setQuery(q), setPage(1))}
            placeholder="搜索目标域名 / IP / 客户"
            className="pl-8"
          />
        </div>
        <TimeCapsule value={since} onChange={(v) => (setSince(v), setPage(1), setQuick("custom"))} placeholder="开始时间" />
        <TimeCapsule value={until} onChange={(v) => (setUntil(v), setPage(1), setQuick("custom"))} placeholder="结束时间" />
        <Select value={quick} onValueChange={(v) => applyQuick(v)}>
          <SelectTrigger className="w-28">
            <SelectValue placeholder="时间" />
          </SelectTrigger>
          <SelectContent>
            <SelectItem value="24">24小时</SelectItem>
            <SelectItem value="168">7天</SelectItem>
            <SelectItem value="720">30天</SelectItem>
            <SelectItem value="all">全部</SelectItem>
            {quick === "custom" && <SelectItem value="custom">自定义</SelectItem>}
          </SelectContent>
        </Select>
      </Card>

      <div className="grid gap-4 lg:grid-cols-2">
        <Card className="flex flex-col gap-2 p-4">
          <div className="text-sm font-medium">请求量最多的地址</div>
          {summary.top_hosts.length === 0 ? (
            <div className="py-4 text-center text-sm text-muted-foreground">还没有记录。</div>
          ) : (
            summary.top_hosts.map((h) => (
              <div key={h.host} className="flex items-center justify-between text-sm">
                <span className="truncate font-mono text-xs">{h.host}</span>
                <span className="text-muted-foreground">{h.count}</span>
              </div>
            ))
          )}
        </Card>
        <Card className="flex flex-col gap-2 p-4">
          <div className="text-sm font-medium">请求最多的客户端</div>
          {summary.top_clients.length === 0 ? (
            <div className="py-4 text-center text-sm text-muted-foreground">还没有记录。</div>
          ) : (
            summary.top_clients.map((c) => (
              <div key={c.source} className="flex items-center justify-between gap-3 text-sm">
                <span className="flex min-w-0 flex-col">
                  <span className="truncate font-mono text-xs">{c.source.replace(/:\d+$/, "")}</span>
                  {c.geo && <span className="truncate text-xs text-muted-foreground">{c.geo}</span>}
                </span>
                <span className="shrink-0 text-muted-foreground">{c.count}</span>
              </div>
            ))
          )}
        </Card>
      </div>

      <Card className="p-4">
        <div className="mb-3 flex items-center justify-between text-sm">
          <span className="text-muted-foreground">
            共 {total} 条 · 第 {page}/{totalPages} 页
          </span>
          <div className="flex gap-2">
            <Button variant="outline" size="sm" disabled={page <= 1} onClick={() => setPage(page - 1)}>
              上一页
            </Button>
            <Button variant="outline" size="sm" disabled={page >= totalPages} onClick={() => setPage(page + 1)}>
              下一页
            </Button>
          </div>
        </div>
        {!recording && (
          <div className="mb-3">
            <Notice>记录已关闭：当前不落库新连接；重新开启后恢复记录。</Notice>
          </div>
        )}
        <Table>
          <TableHeader>
            <TableRow>
              <TableHead>时间</TableHead>
              <TableHead>来源</TableHead>
              <TableHead>客户端</TableHead>
              <TableHead>主机</TableHead>
              <TableHead>代理</TableHead>
              <TableHead>请求地址</TableHead>

            </TableRow>
          </TableHeader>
          <TableBody>
            {rows.length === 0 && (
              <TableRow>
                <TableCell colSpan={6} className="py-8 text-center text-muted-foreground">
                  {busy ? "加载中…" : "还没有记录；产生代理流量后这里会出现逐连接的日志。"}
                </TableCell>
              </TableRow>
            )}
            {rows.map((r) => (
              <TableRow key={r.conn_id}>
                <TableCell className="whitespace-nowrap font-mono text-xs">{fmtTime(r.last)}</TableCell>
                <TableCell className="text-xs">
                  {r.sub_user_id > 0
                    ? <span className="pt lg-ssh">{r.user || `客户 #${r.sub_user_id}`}</span>
                    : <span className="pt lg-other">自用</span>}
                </TableCell>
                <TableCell className="text-xs">
                  <span className="flex flex-col">
                    <span className="font-mono">{r.source.replace(/:\d+$/, "")}</span>
                    {r.geo && <span className="text-muted-foreground">{r.geo}</span>}
                  </span>
                </TableCell>
                <TableCell className="text-xs">
                  <span className="pt lg-node">{nodeLabel(r, nodes)}</span>
                </TableCell>
                <TableCell className="text-xs">
                  <span className={`pt ${logChipClass(protocolLabel(r.port, r.network))}`}>{protocolLabel(r.port, r.network)}</span>
                </TableCell>
                <TableCell className="max-w-64 truncate font-mono text-xs">
                  {/* 域名可点击新窗口打开（按 https 假定），端口留在文本里不参与链接 */}
                  <a
                    href={`https://${r.host}`}
                    target="_blank"
                    rel="noreferrer noopener"
                    className="hover:text-primary hover:underline"
                    onClick={(e) => e.stopPropagation()}
                  >
                    {r.host}
                  </a>
                  <span className="text-muted-foreground">:{r.port}</span>
                </TableCell>
              </TableRow>
            ))}
          </TableBody>
        </Table>
      </Card>
    </div>
  )
}


/** 胶囊样式的日期输入（按天粒度，无时分）：日历图标 + 原生日期选择。
 * 聚焦编辑时占位浮层让位（否则键入的分段文字与浮层文字重叠），输入框放宽
 * 到浏览器固有宽度（固定窄宽时分段内容会溢出胶囊、压到相邻控件），失焦且
 * 无值时恢复紧凑占位态。 */
function TimeCapsule({ value, onChange, placeholder }: { value: string; onChange: (v: string) => void; placeholder: string }) {
  const inputRef = useRef<HTMLInputElement>(null)
  const [edit, setEdit] = useState(false)
  return (
    <div className="flex h-9 shrink-0 items-center gap-2 rounded-full bg-muted px-3" title={placeholder}>
      {/* 日历图标即点击入口：showPicker 唤起浏览器日期选择。 */}
      <CalendarDays
        className="size-4 shrink-0 cursor-pointer text-muted-foreground"
        onClick={() => inputRef.current?.showPicker()}
      />
      <div className="relative">
        <input
          ref={inputRef}
          type="date"
          value={value}
          onChange={(e) => onChange(e.target.value)}
          onFocus={() => setEdit(true)}
          onBlur={() => setEdit(false)}
          aria-label={placeholder}
          className={`bg-transparent text-xs outline-none [&::-webkit-calendar-picker-indicator]:hidden ${
            value || edit ? "text-foreground" : "w-24 [&::-webkit-datetime-edit]:text-transparent"
          }`}
        />
        {!value && !edit && (
          <span className="pointer-events-none absolute inset-0 flex items-center text-xs text-muted-foreground">
            {placeholder}
          </span>
        )}
      </div>
    </div>
  )
}
