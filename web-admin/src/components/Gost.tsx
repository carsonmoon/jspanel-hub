import { useCallback, useEffect, useState } from "react"
import { Pencil, Plus, Trash2 } from "lucide-react"
import { toast } from "sonner"

import { GostRuleDialog, type Machine } from "@/components/GostRuleDialog"
import { Badge } from "@/components/ui/badge"
import { Button } from "@/components/ui/button"
import { Card } from "@/components/ui/card"
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table"
import { Switch } from "@/components/ui/switch"
import { Tooltip, TooltipContent, TooltipTrigger } from "@/components/ui/tooltip"
import { api, type GostData, type GostRule } from "@/lib/api"
import { copy } from "@/components/QrDialog"

const transportLabel: Record<string, string> = { tls: "TLS", wss: "WSS", tcp: "TCP" }
const balanceLabel: Record<string, string> = { fifo: "主备", round: "轮询", rand: "随机", hash: "源IP哈希" }

// Two clicks within the window delete: no dialog, no accidental loss.（转发页同款）
function useConfirmDelete() {
  const [armed, setArmed] = useState<number | null>(null)
  useEffect(() => {
    if (armed === null) return
    const timer = setTimeout(() => setArmed(null), 3000)
    return () => clearTimeout(timer)
  }, [armed])
  return { armed, arm: setArmed }
}

function GostCard({ rules, servers, portPool, gostVersion, reload }: {
  rules: GostRule[]
  servers: Machine[]
  portPool: string
  gostVersion: string
  reload: () => Promise<void>
}) {
  const [dialogOpen, setDialogOpen] = useState(false)
  const [editing, setEditing] = useState<GostRule | null>(null)
  const { armed, arm } = useConfirmDelete()
  const serverName = (id: number) => servers.find((s) => s.id === id)?.name ?? `服务器 ${id}`
  const serverIp = (id: number) => servers.find((s) => s.id === id)?.ip ?? ""

  const toggle = async (rule: GostRule, enabled: boolean) => {
    try {
      // PUT 全量语义：必须带全字段（漏带字段=清库级隐患，先例两次）。
      await api(`/gost/${rule.id}`, { method: "PUT", body: JSON.stringify({ ...rule, enabled }) })
      await reload()
    } catch (e) {
      toast.error((e as Error).message)
    }
  }

  const remove = async (rule: GostRule) => {
    try {
      await api(`/gost/${rule.id}`, { method: "DELETE" })
      toast.success("隧道规则已删除")
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
            <div className="font-medium">隧道规则</div>
            {gostVersion && <Badge variant="outline">gost {gostVersion}</Badge>}
          </div>
          <div className="text-sm text-muted-foreground">
            端口转发与加密隧道（gost 内核）· 首次建规则时机器自动安装，增删规则热生效不影响其他规则
          </div>
        </div>
        <Button size="sm" onClick={() => { setEditing(null); setDialogOpen(true) }}>
          <Plus className="size-3.5" /> 新建规则
        </Button>
      </div>
      <Table>
        <TableHeader>
          <TableRow>
            <TableHead>名称</TableHead>
            <TableHead>入口机</TableHead>
            <TableHead>监听端口</TableHead>
            <TableHead>出口 / 落地</TableHead>
            <TableHead>启用</TableHead>
            <TableHead className="text-right">操作</TableHead>
          </TableRow>
        </TableHeader>
        <TableBody>
          {rules.length === 0 && (
            <TableRow>
              <TableCell colSpan={6} className="py-8 text-center text-muted-foreground">
                还没有隧道规则，点右上角「新建规则」开始。
              </TableCell>
            </TableRow>
          )}
          {rules.map((rule) => (
            <TableRow key={rule.id}>
              <TableCell>
                <div className="flex flex-wrap items-center gap-1.5 font-medium">
                  {rule.name}
                  <Badge variant={rule.mode === "tunnel" ? "secondary" : "outline"} title={rule.mode === "tunnel" ? "隧道转发：入口⇄出口加密链" : "端口转发：同机直连落地"}>
                    {rule.mode === "tunnel" ? `隧道 · ${transportLabel[rule.transport] ?? rule.transport}` : "转发"}
                  </Badge>
                  {rule.balance && <Badge variant="outline" title="多目标负载策略">{balanceLabel[rule.balance] ?? rule.balance}</Badge>}
                  {!rule.udp && <Badge variant="outline" title="未开启 UDP 转发">仅TCP</Badge>}
                  {!rule.enabled && <Badge variant="secondary">停用</Badge>}
                </div>
              </TableCell>
              <TableCell>
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
                    <div className="tnum">{serverIp(rule.server_id) || "未知"}:{rule.listen_port}</div>
                    <div className="opacity-70">入口机地址，点击复制 IP</div>
                  </TooltipContent>
                </Tooltip>
              </TableCell>
              <TableCell className="font-mono">{rule.listen_port}</TableCell>
              <TableCell>
                {rule.exit_server_id > 0 ? (
                  <div className="flex flex-col gap-0.5">
                    <span className="text-sm">
                      → {serverName(rule.exit_server_id)}
                      <span className="ml-1 font-mono text-xs text-muted-foreground">:{rule.exit_listen_port}</span>
                    </span>
                    <span className="truncate font-mono text-xs text-muted-foreground">{rule.targets.split("\n")[0]}</span>
                  </div>
                ) : (
                  <div className="flex flex-wrap gap-1">
                    {rule.targets.split("\n").filter(Boolean).map((t) => (
                      <button
                        key={t}
                        type="button"
                        onClick={() => copy(t.trim(), "落地目标")}
                        className="inline-flex items-center rounded-md border px-1.5 py-0.5 font-mono text-xs hover:bg-muted"
                      >
                        {t.trim()}
                      </button>
                    ))}
                  </div>
                )}
              </TableCell>
              <TableCell>
                <Switch checked={rule.enabled} onCheckedChange={(v) => toggle(rule, v)} />
              </TableCell>
              <TableCell className="text-right">
                <div className="flex justify-end gap-1">
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
      <GostRuleDialog open={dialogOpen} onOpenChange={setDialogOpen} editing={editing} servers={servers} portPool={portPool} onSaved={reload} />
    </Card>
  )
}

// ---- 隧道页（gost）：端口转发 + 加密隧道，与转发页（realm）并行独立 ----

function useGostData() {
  const [data, setData] = useState<GostData>({ rules: [], port_pool: "20000-50000", gost_version: "" })
  const [servers, setServers] = useState<Machine[]>([])
  const load = useCallback(async () => {
    const [g, n] = await Promise.all([
      api<GostData>("/gost").catch(() => ({ rules: [], port_pool: "20000-50000", gost_version: "" })),
      api<{ nodes?: { id: number; name: string; online?: boolean; local?: boolean; addresses?: { address: string }[]; ipv4?: string }[] } | { id: number; name: string; online?: boolean; local?: boolean; addresses?: { address: string }[]; ipv4?: string }[]>("/nodes").catch(() => ({ nodes: [] })),
    ])
    setData(g)
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

export default function Gost() {
  const { data, servers, reload } = useGostData()
  return (
    <div className="flex flex-col gap-6">
      <GostCard rules={data.rules} servers={servers} portPool={data.port_pool} gostVersion={data.gost_version} reload={reload} />
    </div>
  )
}
