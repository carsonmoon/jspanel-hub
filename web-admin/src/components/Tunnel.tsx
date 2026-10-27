import { useCallback, useEffect, useRef, useState } from "react"
import { Download, Pencil, Plus, QrCode, RefreshCw, Stethoscope, Trash2, Upload } from "lucide-react"
import { toast } from "sonner"

import { QrDialog } from "@/components/QrDialog"
import { Dialog, DialogContent, DialogFooter, DialogHeader, DialogTitle } from "@/components/ui/dialog"
import { TunnelRuleDialog, type Machine } from "@/components/TunnelRuleDialog"
import { Badge } from "@/components/ui/badge"
import { Button } from "@/components/ui/button"
import { Card } from "@/components/ui/card"
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table"
import { Switch } from "@/components/ui/switch"
import { api, type RelayRule, type RealmStatus } from "@/lib/api"
import { copy } from "@/components/QrDialog"
import { Tooltip, TooltipContent, TooltipTrigger } from "@/components/ui/tooltip"

type TunnelData = {
  port_pool: string
  rules: RelayRule[]
  realm: RealmStatus | null
  servers: RealmStatus[]
}

const protocolBadge = (p: string) =>
  p === "tcp" ? <Badge variant="outline">TCP</Badge> : p === "udp" ? <Badge variant="outline">UDP</Badge> : null

const transportLabel = { tls: "TLS", ws: "WS", wss: "WSS" } as Record<string, string>


// ---- 隧道诊断弹窗（对齐参考图）：每段链路一卡 = 平均延迟/丢包率/连接质量分级 ----

type DiagLeg = {
  key: string
  kind: string
  from: string
  target: string
  ok?: boolean
  state?: string
  avg_ms?: number
  loss_pct?: number
  grade?: string
  probes?: number
  error?: string
}

const GRADE_BADGE: Record<string, { text: string; cls: string }> = {
  excellent: { text: "🚀 优秀", cls: "bg-emerald-500/10 text-emerald-600 dark:text-emerald-400" },
  good: { text: "✅ 良好", cls: "bg-primary/10 text-primary" },
  poor: { text: "⚠️ 较差", cls: "bg-amber-500/10 text-amber-600 dark:text-amber-400" },
}

/** 一张链路段卡：✓/✕ 圆图标 + 段名/机器名 + 平均延迟/丢包率/质量三栏 + 目标地址行。 */
function LegCard({ leg, legName }: { leg: DiagLeg; legName: string }) {
  const ok = leg.ok === true
  return (
    <div className={`flex flex-col gap-2.5 rounded-xl border px-4 py-3.5 ${ok ? "border-emerald-500/40" : "border-red-500/40"}`}>
      <div className="flex items-start gap-2.5">
        <span
          className={`flex size-7 shrink-0 items-center justify-center rounded-full text-sm font-bold text-white ${ok ? "bg-emerald-500" : "bg-red-500"}`}
        >
          {ok ? "✓" : "✕"}
        </span>
        <div className="min-w-0 flex-1">
          <div className="font-medium">{legName}</div>
          <div className="text-sm text-muted-foreground">{leg.from}</div>
        </div>
        {leg.error ? (
          <Badge variant="secondary">{leg.error}</Badge>
        ) : (
          <span className={`rounded-md px-2 py-0.5 text-xs font-medium ${ok ? "bg-emerald-500/10 text-emerald-600 dark:text-emerald-400" : "bg-red-500/10 text-red-600 dark:text-red-400"}`}>
            {ok ? "成功" : "失败"}
          </span>
        )}
      </div>
      {leg.error ? null : (
        <>
          <div className="grid grid-cols-3 items-end gap-2 px-1 pt-1">
            <div className="text-center">
              <div className="text-2xl font-semibold text-primary">{ok ? leg.avg_ms : "—"}</div>
              <div className="text-xs text-muted-foreground">平均延迟(ms)</div>
            </div>
            <div className="text-center">
              <div className="text-2xl font-semibold text-amber-600 dark:text-amber-400">{ok ? (leg.loss_pct ?? 0).toFixed(1) : "—"}</div>
              <div className="text-xs text-muted-foreground">丢包率(%)</div>
            </div>
            <div className="flex flex-col items-center gap-1">
              {leg.grade ? (
                <span className={`rounded-md px-2 py-0.5 text-xs font-medium ${GRADE_BADGE[leg.grade]?.cls ?? ""}`}>
                  {GRADE_BADGE[leg.grade]?.text ?? leg.grade}
                </span>
              ) : (
                <span className="text-muted-foreground">—</span>
              )}
              <div className="text-xs text-muted-foreground">连接质量</div>
            </div>
          </div>
          <div className="truncate font-mono text-xs text-muted-foreground">
            目标地址: {leg.target}
            {leg.probes ? ` · ${leg.probes} 次探测` : ""}
          </div>
        </>
      )}
    </div>
  )
}

/** 诊断弹窗：打开即自动开跑，底部重新诊断；结果同时刷新健康状态。 */
function DiagnoseDialog({ rule, onOpenChange }: {
  rule: RelayRule | null
  onOpenChange: (open: boolean) => void
}) {
  const [legs, setLegs] = useState<DiagLeg[] | null>(null)
  const [running, setRunning] = useState(false)

  const legName = (leg: DiagLeg) => {
    if (leg.kind === "listen") return "面板→入口监听"
    if (leg.kind === "hop") return "入口→出口"
    return "出口→目标"
  }

  const run = async () => {
    if (!rule) return
    setRunning(true)
    setLegs(null)
    try {
      const r = await api<{ legs: DiagLeg[] }>(`/proxy/relays/${rule.id}/diagnose`, { method: "POST" })
      setLegs(r.legs)
    } catch (e) {
      toast.error((e as Error).message)
      setLegs([])
    } finally {
      setRunning(false)
    }
  }

  useEffect(() => {
    if (rule) run()
    else setLegs(null)
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [rule])

  const segCount = rule
    ? rule.targets.filter((t) => t.enabled).length + (rule.transport && rule.exit_server_id > 0 ? 1 : 0)
    : 0

  return (
    <Dialog open={rule !== null} onOpenChange={onOpenChange}>
      <DialogContent className="sm:max-w-lg">
        <DialogHeader>
          <DialogTitle>转发诊断结果</DialogTitle>
        </DialogHeader>
        {rule && (
          <div className="flex flex-col gap-3">
            <div className="flex items-center gap-1.5">
              <span className="font-medium">{rule.name}</span>
              {rule.transport && <Badge variant="secondary">{transportLabel[rule.transport] ?? rule.transport} 转发</Badge>}
              {protocolBadge(rule.protocol)}
              {/* 监听腿结论浓缩成 chip（grilling 拍板）：挂在标题行，地址进
                  hover 黑框——监听中即入口段成功，不再单独占一行。 */}
              {(() => {
                const listen = legs?.find((l) => l.kind === "listen")
                if (!listen) return null
                return (
                  <Tooltip disableHoverableContent>
                    <TooltipTrigger asChild>
                      <Badge
                        variant="secondary"
                        className={listen.ok ? "bg-emerald-500/10 text-emerald-600 dark:text-emerald-400" : "bg-destructive/10 text-destructive"}
                      >
                        {listen.ok ? "监听中" : "未监听"}
                      </Badge>
                    </TooltipTrigger>
                    <TooltipContent side="bottom" sideOffset={4}>
                      <div className="tnum">{listen.target}</div>
                      <div className="opacity-70">面板→入口监听{listen.ok ? "成功" : "失败"}</div>
                    </TooltipContent>
                  </Tooltip>
                )
              })()}
            </div>
            {legs === null ? (
              <div className="flex flex-col items-center gap-2 py-10 text-sm text-muted-foreground">
                <RefreshCw className="size-5 animate-spin" />
                正在逐段探测（共 {segCount || "若干"} 段，每段 10 次），约需 2–4 秒…
              </div>
            ) : legs.length === 0 ? (
              <div className="py-10 text-center text-sm text-muted-foreground">没有可诊断的链路段：该规则没有启用中的出口目标。</div>
            ) : (
              <div className="flex flex-col gap-3">
                {legs
                  .filter((leg) => leg.kind !== "listen")
                  .map((leg) => (
                    <LegCard key={leg.key} leg={leg} legName={legName(leg)} />
                  ))}
              </div>
            )}
          </div>
        )}
        <DialogFooter>
          <Button variant="outline" size="sm" onClick={() => onOpenChange(false)}>
            关闭
          </Button>
          <Button size="sm" disabled={running} onClick={run}>
            <RefreshCw className={`size-3.5 ${running ? "animate-spin" : ""}`} /> 重新诊断
          </Button>
        </DialogFooter>
      </DialogContent>
    </Dialog>
  )
}



/// 一台机器的 realm 状态徽标（grilling 终版）：一颗点+机器名，hover 黑框
/// 一句话——健康报「运行中」，异常只报原因；点开的 popover 已裁撤（启停/
/// 切版本属低频操作，面板重装/agent 面板可达时自然恢复）。
function RealmPill({ status }: { status: RealmStatus }) {
  const local = status.server_id === 0 || !!status.local
  const abnormal = !status.online && !local ? "离线（agent 失联）" : !status.installed ? "未安装 realm" : !status.running ? (status.desired_running === false ? "已停止" : "已停止（等待配置推送）") : status.supports_transport === false ? `版本过旧（${status.version || "未知"}，加密隧道需 ≥ 2.7）` : ""
  const tone = abnormal ? (abnormal.startsWith("离线") || abnormal.startsWith("未安装") ? "bg-red-500" : "bg-amber-500") : "bg-emerald-500"
  return (
    <Tooltip disableHoverableContent>
      <TooltipTrigger asChild>
        <span className="inline-flex cursor-default items-center gap-1 rounded-full px-1 py-0.5 text-xs">
          <span className={`size-2 rounded-full ${tone}`} />
          <span className="max-w-28 truncate font-medium">{status.name}</span>
        </span>
      </TooltipTrigger>
      <TooltipContent side="bottom" sideOffset={4}>
        <div className="tnum">{status.name}</div>
        <div className="opacity-70">{abnormal || "运行中"}</div>
      </TooltipContent>
    </Tooltip>
  )
}

// Two clicks within the window delete: no dialog, no accidental loss.
function useConfirmDelete() {
  const [armed, setArmed] = useState<number | null>(null)
  useEffect(() => {
    if (armed === null) return
    const timer = setTimeout(() => setArmed(null), 3000)
    return () => clearTimeout(timer)
  }, [armed])
  return { armed, arm: setArmed }
}

function RelayCard({ rules, servers, realmServers, portPool, reload }: {
  rules: RelayRule[]
  servers: Machine[]
  realmServers: RealmStatus[]
  portPool: string
  reload: () => Promise<void>
}) {
  const [dialogOpen, setDialogOpen] = useState(false)
  const [editing, setEditing] = useState<RelayRule | null>(null)
  const [qrRule, setQrRule] = useState<RelayRule | null>(null)
  const [diagRule, setDiagRule] = useState<RelayRule | null>(null)
  const fileRef = useRef<HTMLInputElement>(null)
  const { armed, arm } = useConfirmDelete()
  const serverName = (id: number) =>
    id === 0 ? (servers.find((s) => s.local)?.name ?? "本机") : (servers.find((s) => s.id === id)?.name ?? `服务器 ${id}`)
  // 机器的拨号 IP（上报 IPv4 优先，回退连接 IP），复制/hover 用。
  const serverIp = (id: number) => {
    const s = id === 0 ? servers.find((x) => x.local) : servers.find((x) => x.id === id)
    return s?.ip ?? ""
  }

  const toggle = async (rule: RelayRule, enabled: boolean) => {
    try {
      await api(`/proxy/relays/${rule.id}`, { method: "PUT", body: JSON.stringify({ ...rule, enabled }) })
      await reload()
    } catch (e) {
      toast.error((e as Error).message)
    }
  }

  const remove = async (rule: RelayRule) => {
    try {
      await api(`/proxy/relays/${rule.id}`, { method: "DELETE" })
      toast.success("转发规则已删除")
      await reload()
    } catch (e) {
      toast.error((e as Error).message)
    }
  }

  const exportRules = async () => {
    try {
      const data = await api<unknown>("/proxy/relays/export")
      const blob = new Blob([JSON.stringify(data, null, 2)], { type: "application/json" })
      const url = URL.createObjectURL(blob)
      const a = document.createElement("a")
      a.href = url
      a.download = `relay-rules-${new Date().toISOString().slice(0, 10)}.json`
      a.click()
      URL.revokeObjectURL(url)
    } catch (e) {
      toast.error((e as Error).message)
    }
  }

  const importRules = async (file: File) => {
    try {
      const parsed = JSON.parse(await file.text()) as { rules?: unknown[] }
      const r = await api<{ created: number; skipped: { name: unknown; reason: string }[] }>("/proxy/relays/import", {
        method: "POST",
        body: JSON.stringify({ rules: parsed.rules ?? [] }),
      })
      toast.success(`导入完成：新建 ${r.created} 条${r.skipped.length ? `，跳过 ${r.skipped.length} 条` : ""}`)
      await reload()
    } catch (e) {
      toast.error((e as Error).message)
    }
  }

  return (
    <Card className="flex flex-col gap-3 p-5">
      <div className="flex items-center justify-between">
        <div>
          <div className="flex items-center gap-2">
            <div className="font-medium">转发规则</div>
            {/* 每台机器一颗状态徽标：健康=绿点零存在感，点开管理（grilling a/a/a） */}
            <div className="flex items-center gap-1.5">
              {(realmServers.length > 0
                ? realmServers
                : [{ server_id: 0, name: "本机", online: true, installed: false, version: "", running: false, desired_running: true }]
              ).map((s) => (
                <RealmPill key={s.server_id} status={s} />
              ))}
            </div>
          </div>
          <div className="text-sm text-muted-foreground">
            把一台机器的端口转发到其他机器
          </div>
        </div>
        <div className="flex gap-2">
          <input
            ref={fileRef}
            type="file"
            accept="application/json"
            className="hidden"
            onChange={(e) => {
              const f = e.target.files?.[0]
              if (f) importRules(f)
              e.target.value = ""
            }}
          />
          <Button variant="outline" size="sm" onClick={() => fileRef.current?.click()}>
            <Upload className="size-3.5" /> 导入
          </Button>
          <Button variant="outline" size="sm" onClick={exportRules}>
            <Download className="size-3.5" /> 导出
          </Button>
          <Button size="sm" onClick={() => { setEditing(null); setDialogOpen(true) }}>
            <Plus className="size-3.5" /> 新建转发
          </Button>
        </div>
      </div>
      <Table>
        <TableHeader>
          <TableRow>
            <TableHead>名称</TableHead>
            <TableHead>入口机</TableHead>
            <TableHead>监听端口</TableHead>
            <TableHead>出口目标</TableHead>
            <TableHead>启用</TableHead>
            <TableHead className="text-right">操作</TableHead>
          </TableRow>
        </TableHeader>
        <TableBody>
          {rules.length === 0 && (
            <TableRow>
              <TableCell colSpan={6} className="py-8 text-center text-muted-foreground">
                  还没有转发规则，点右上角「新建转发」开始。
              </TableCell>
            </TableRow>
          )}
          {rules.map((rule) => (
            <TableRow key={rule.id}>
              <TableCell>
                <div className="flex items-center gap-1.5 font-medium">
                  {rule.name}
                  {rule.transport && (
                    <Badge variant="secondary" title={`加密隧道 → ${serverName(rule.exit_server_id)}（出口端口 ${rule.exit_listen_port}）`}>
                      {transportLabel[rule.transport] ?? rule.transport}
                    </Badge>
                  )}
                  {protocolBadge(rule.protocol)}
                </div>
                {rule.note && <div className="text-xs text-muted-foreground">{rule.note}</div>}
              </TableCell>
              <TableCell>
                {/* 面板机充当中转机：server_id=0，或（存量规则）恰落在面板机的监控节点行上——同一台物理机 */}
                <span className="inline-flex items-center gap-1">
                  <Tooltip disableHoverableContent>
                    <TooltipTrigger asChild>
                      <button
                        type="button"
                        onClick={() => {
                          const ip = serverIp(rule.server_id)
                          if (ip) copy(ip, "入口机 IP")
                        }}
                        aria-label="复制入口机 IP"
                        className="truncate font-medium hover:text-foreground"
                      >
                        {serverName(rule.server_id)}
                      </button>
                    </TooltipTrigger>
                    <TooltipContent side="right" sideOffset={6}>
                      <div className="tnum">{serverIp(rule.server_id) || "未知"}:{String(rule.listen_port).split("-")[0]}</div>
                      <div className="opacity-70">入口机地址，点击复制 IP</div>
                    </TooltipContent>
                  </Tooltip>
                  {(rule.server_id === 0 || servers.find((s) => s.id === rule.server_id)?.local) && (
                    <span className="rounded bg-primary/15 px-1 text-[10px] font-medium text-primary">主</span>
                  )}
                  {/* 备用入口机数（入口故障转移）：hover 看名单 */}
                  {(() => {
                    const ids: number[] = JSON.parse(rule.entry_backups || "[]")
                    return ids.length > 0 ? (
                      <span
                        className="rounded bg-muted px-1 text-[10px] font-medium text-muted-foreground"
                        title={`备用入口：${ids.map((id) => serverName(id)).join("、")}`}
                      >
                        +{ids.length} 备
                      </span>
                    ) : null
                  })()}
                </span>
              </TableCell>
              <TableCell className="font-mono">{rule.listen_port}</TableCell>
              <TableCell>
                <div className="flex flex-wrap gap-1.5">
                  {rule.targets.length === 0 && <span className="font-mono text-muted-foreground">{rule.target}</span>}
                  {rule.targets.map((t) => (
                    <Tooltip key={t.id} disableHoverableContent>
                      <TooltipTrigger asChild>
                        <button
                          type="button"
                          onClick={() => copy(`${t.host}:${t.port}`, "出口目标")}
                          className="inline-flex items-center gap-1 rounded-md border px-1.5 py-0.5 font-mono text-xs hover:bg-muted"
                        >
                          {/* 自动故障摘除的健康点：红=已被摘出负载组（failover_watch 标记） */}
                          {t.state === "down" && <span className="size-1.5 rounded-full bg-red-500" title="探测失败，已摘除" />}
                          {t.host}:{t.port}
                          {rule.targets.length > 1 && <span className="text-muted-foreground">×{t.weight}</span>}
                        </button>
                      </TooltipTrigger>
                      <TooltipContent side="top" sideOffset={4}>
                        <div className="tnum">{t.host}:{t.port}</div>
                        <div className="opacity-70">出口目标，点击复制{rule.targets.length > 1 ? ` · 权重 ${t.weight}` : ""}</div>
                      </TooltipContent>
                    </Tooltip>
                  ))}
                </div>
              </TableCell>
              <TableCell>
                <Switch checked={rule.enabled} onCheckedChange={(v) => toggle(rule, v)} />
              </TableCell>
              <TableCell className="text-right">
                <div className="flex justify-end gap-1">
                  <Button
                    variant="ghost"
                    size="sm"
                    disabled={rule.protocol === "udp"}
                    title={rule.protocol === "udp" ? "UDP 转发不适用 TCP 诊断" : "诊断：逐段探测每条转发链路的延迟与丢包"}
                    onClick={() => setDiagRule(rule)}
                  >
                    <Stethoscope className="size-3.5" /> 诊断
                  </Button>
                  {rule.share && (
                    <Button variant="ghost" size="sm" onClick={() => setQrRule(rule)}>
                      <QrCode className="size-3.5" />
                    </Button>
                  )}
                  <Button variant="ghost" size="sm" onClick={() => { setEditing(rule); setDialogOpen(true) }}>
                    <Pencil className="size-3.5" /> 编辑
                  </Button>
                  <Button
                    variant={armed === rule.id ? "destructive" : "ghost"}
                    size="sm"
                    title={armed === rule.id ? "再点一次确认删除" : "删除规则"}
                    onClick={() => (armed === rule.id ? remove(rule) : arm(rule.id))}
                  >
                    <Trash2 className="size-3.5" /> {armed === rule.id ? "确认" : "删除"}
                  </Button>
                </div>
              </TableCell>
            </TableRow>
          ))}
        </TableBody>
      </Table>
      <TunnelRuleDialog open={dialogOpen} onOpenChange={setDialogOpen} editing={editing} servers={servers} portPool={portPool} onSaved={reload} />
      {qrRule && qrRule.share && (
        <QrDialog url={qrRule.share} name={qrRule.name} kind="node" onOpenChange={() => setQrRule(null)} />
      )}
      <DiagnoseDialog rule={diagRule} onOpenChange={(o) => !o && setDiagRule(null)} />
    </Card>
  )
}

// ---- 隧道页：各机 realm 状态 + 隧道规则（M5 拆出；M24 对标 xwPF 增强） ----

function useTunnelData() {
  const [data, setData] = useState<TunnelData>({ rules: [], realm: null, servers: [], port_pool: "20000-50000" })
  const [servers, setServers] = useState<Machine[]>([])
  const load = useCallback(async () => {
    const [t, n] = await Promise.all([
      api<TunnelData>("/proxy/relays").catch(() => ({ rules: [], realm: null, servers: [], port_pool: "20000-50000" })),
      api<{ nodes?: { id: number; name: string; online?: boolean; local?: boolean; addresses?: { address: string }[]; ipv4?: string }[] } | { id: number; name: string; online?: boolean; local?: boolean; addresses?: { address: string }[]; ipv4?: string }[]>("/nodes").catch(() => ({ nodes: [] })),
    ])
    setData(t)
    // 机器下拉：监控节点行本身就是服务器（node.id 即 proxy_node 的 server_id），
    // 全部进下拉，本机（server_id=0）由单独的「本机」选项表达。
    // online 供下拉过滤离线，local 标记面板所在机器（其节点行与「本机」同一台物理机）。
    const list = Array.isArray(n) ? n : (n.nodes ?? [])
    const byId = new Map<number, { name: string; online?: boolean; local?: boolean; ip: string }>()
    for (const node of list) {
      if (!byId.has(node.id))
        byId.set(node.id, {
          name: node.name ?? `服务器 ${node.id}`,
          online: !!node.online,
          local: !!node.local,
          ip: String(node.addresses?.[0]?.address ?? node.ipv4 ?? ""),
        })
    }
    setServers([...byId].map(([id, s]) => ({ id, name: s.name, online: s.online, local: s.local, ip: s.ip })))
  }, [])
  useEffect(() => {
    load()
  }, [load])
  return { data, servers, reload: load }
}

export default function Tunnel() {
  const { data, servers, reload } = useTunnelData()
  return (
    <div className="flex flex-col gap-6">
      <RelayCard rules={data.rules} servers={servers} realmServers={data.servers} portPool={data.port_pool} reload={reload} />
    </div>
  )
}
