import { useEffect, useState } from "react"
import { ArrowDown, ArrowUp, Plus, Trash2 } from "lucide-react"

import { Badge } from "@/components/ui/badge"
import { Button } from "@/components/ui/button"
import { Dialog, DialogContent, DialogFooter, DialogHeader, DialogTitle } from "@/components/ui/dialog"
import { Input } from "@/components/ui/input"
import { Label } from "@/components/ui/label"
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select"
import { Switch } from "@/components/ui/switch"
import { api, type GostRule } from "@/lib/api"

export type Machine = { id: number; name: string; online?: boolean; local?: boolean; ip?: string }

type DraftTarget = { host: string; port: string }

type Draft = {
  name: string
  serverId: string
  listenPort: string
  /** 隧道模式（出口机非空）或端口转发 */
  tunnel: boolean
  exitServerId: string
  transport: string
  exitListenPort: string
  targets: DraftTarget[]
  balance: string
  udp: boolean
}

function emptyDraft(): Draft {
  return {
    name: "",
    serverId: "",
    listenPort: "",
    tunnel: false,
    exitServerId: "",
    transport: "tls",
    exitListenPort: "",
    targets: [{ host: "", port: "" }],
    balance: "",
    udp: true,
  }
}

function draftOf(rule: GostRule): Draft {
  const targets = rule.targets
    .split("\n")
    .map((l) => l.trim())
    .filter(Boolean)
    .map((l) => {
      const i = l.lastIndexOf(":")
      return { host: i > 0 ? l.slice(0, i) : l, port: i > 0 ? l.slice(i + 1) : "" }
    })
  return {
    name: rule.name,
    serverId: String(rule.server_id),
    listenPort: rule.listen_port,
    tunnel: rule.exit_server_id > 0,
    exitServerId: String(rule.exit_server_id || ""),
    transport: rule.transport || "tls",
    exitListenPort: rule.exit_listen_port,
    targets: targets.length > 0 ? targets : [{ host: "", port: "" }],
    balance: rule.balance,
    udp: rule.udp,
  }
}

/** gost 规则编辑弹窗（隧道模块批次2）：扁平模型——端口转发/隧道转发一张表单，
 * 开「隧道转发」选出出口机即成套。PUT 全量语义：保存必须带全字段。 */
export function GostRuleDialog({ open, onOpenChange, editing, servers, portPool, onSaved }: {
  open: boolean
  onOpenChange: (open: boolean) => void
  editing: GostRule | null
  servers: Machine[]
  portPool: string
  onSaved: () => Promise<void>
}) {
  const [draft, setDraft] = useState<Draft>(emptyDraft())
  const [busy, setBusy] = useState(false)
  const set = (patch: Partial<Draft>) => setDraft((d) => ({ ...d, ...patch }))

  useEffect(() => {
    if (!open) return
    if (editing) {
      setDraft(draftOf(editing))
    } else {
      const local = servers.find((s) => s.local)
      const fallback = local ?? servers.find((s) => s.online) ?? servers[0]
      setDraft({ ...emptyDraft(), serverId: fallback ? String(fallback.id) : "" })
    }
  }, [open, editing])

  const patchTarget = (i: number, patch: Partial<DraftTarget>) =>
    set({ targets: draft.targets.map((t, j) => (j === i ? { ...t, ...patch } : t)) })
  const moveTarget = (i: number, dir: -1 | 1) => {
    const j = i + dir
    if (j < 0 || j >= draft.targets.length) return
    const next = [...draft.targets]
    ;[next[i], next[j]] = [next[j], next[i]]
    set({ targets: next })
  }

  // 入口/出口机都只列在线机器（离线发不下配置），编辑中的存量值恒保留并标注。
  const entryOptions = servers.filter((sv) => sv.online || String(sv.id) === draft.serverId)
  const exitOptions = servers.filter(
    (sv) => (sv.online || String(sv.id) === draft.exitServerId) && String(sv.id) !== draft.serverId,
  )
  const multi = draft.targets.length > 1

  const save = async () => {
    setBusy(true)
    try {
      const targets = draft.targets
        .map((t) => `${t.host.trim()}:${t.port.trim()}`)
        .filter((l) => !l.startsWith(":") && !l.endsWith(":") && l !== ":")
        .join("\n")
      const base = {
        // PUT 全量语义（漏键=serde default 清掉）：从 editing 展开再覆盖表单
        // 字段——新增后端字段不再可能被手拼字面量漏带（Gost toggle 漏 enabled
        // 是 tsc 侥幸抓住的先例）。
        ...(editing ?? { enabled: true }),
        server_id: Number(draft.serverId),
        name: draft.name.trim(),
        exit_server_id: draft.tunnel ? Number(draft.exitServerId) : 0,
        transport: draft.tunnel ? draft.transport : "",
        listen_port: draft.listenPort.trim(),
        exit_listen_port: draft.tunnel ? draft.exitListenPort.trim() : "",
        targets,
        balance: multi ? draft.balance : "",
        udp: draft.udp,
        enabled: editing?.enabled ?? true,
      }
      if (editing) {
        await api(`/gost/${editing.id}`, { method: "PUT", body: JSON.stringify({ ...base, created_at: editing.created_at }) })
      } else {
        await api("/gost", { method: "POST", body: JSON.stringify(base) })
      }
      await onSaved()
      onOpenChange(false)
    } finally {
      setBusy(false)
    }
  }

  const nameOk = draft.name.trim() !== ""
  const tunnelOk = !draft.tunnel || draft.exitServerId !== ""
  const targetsOk = draft.targets.every((t) => !t.host.trim() || (t.port.trim() !== "" && Number(t.port) > 0))

  return (
    <Dialog open={open} onOpenChange={onOpenChange}>
      <DialogContent className="max-h-[85vh] max-w-lg overflow-y-auto">
        <DialogHeader>
          <DialogTitle>{editing ? "编辑隧道规则" : "新建隧道规则"}</DialogTitle>
        </DialogHeader>
        <div className="flex flex-col gap-3">
          <div className="flex flex-col gap-1.5">
            <Label>规则名称</Label>
            <Input value={draft.name} onChange={(e) => set({ name: e.target.value })} placeholder="例如 落地-中转" />
          </div>
          <div className="flex gap-1 rounded-md bg-muted p-1 text-sm">
            <button
              onClick={() => set({ tunnel: false, exitServerId: "", exitListenPort: "", transport: "" })}
              className={`flex-1 rounded px-2 py-1 transition-colors ${!draft.tunnel ? "bg-background font-medium shadow-sm" : "text-muted-foreground"}`}
            >
              端口转发
            </button>
            <button
              onClick={() => {
                const first = exitOptions[0]
                set({ tunnel: true, exitServerId: first ? String(first.id) : draft.exitServerId, transport: draft.transport || "tls" })
              }}
              disabled={exitOptions.length === 0}
              className={`flex-1 rounded px-2 py-1 transition-colors ${draft.tunnel ? "bg-background font-medium shadow-sm" : "text-muted-foreground"} disabled:cursor-not-allowed disabled:opacity-50`}
            >
              隧道转发
            </button>
          </div>
          <p className="text-xs text-muted-foreground">
            {draft.tunnel
              ? "入口机监听端口，经加密隧道送到出口机，再由出口机转发到落地目标（可过 CDN 场景外的加密中转）。"
              : "入口机直接把端口流量转发到落地目标（TCP + UDP），多目标可选负载/主备策略。"}
          </p>
          <div className="grid grid-cols-2 gap-3">
            <div className="flex flex-col gap-1.5">
              <Label>入口机</Label>
              <Select value={draft.serverId} onValueChange={(v) => set({ serverId: v })}>
                <SelectTrigger><SelectValue /></SelectTrigger>
                <SelectContent>
                  {entryOptions.map((sv) => (
                    <SelectItem key={sv.id} value={String(sv.id)}>
                      {sv.name}
                      {sv.local && <span className="rounded bg-primary/15 px-1 text-[10px] font-medium text-primary">主</span>}
                      {!sv.online && "（离线）"}
                    </SelectItem>
                  ))}
                </SelectContent>
              </Select>
            </div>
            <div className="flex flex-col gap-1.5">
              <Label>监听端口</Label>
              <Input value={draft.listenPort} onChange={(e) => set({ listenPort: e.target.value.replace(/\D/g, "") })} placeholder={`留空自动（${portPool || "20000-50000"}）`} />
            </div>
          </div>

          {draft.tunnel && (
            <div className="flex flex-col gap-3 rounded-md border p-3">
              <div className="grid grid-cols-2 gap-3">
                <div className="flex flex-col gap-1.5">
                  <Label>出口机（加密端另一侧）</Label>
                  <Select value={draft.exitServerId} onValueChange={(v) => set({ exitServerId: v })}>
                    <SelectTrigger><SelectValue /></SelectTrigger>
                    <SelectContent>
                      {exitOptions.map((sv) => (
                        <SelectItem key={sv.id} value={String(sv.id)}>
                          {sv.name}
                          {sv.local && <span className="rounded bg-primary/15 px-1 text-[10px] font-medium text-primary">主</span>}
                          {!sv.online && "（离线）"}
                        </SelectItem>
                      ))}
                    </SelectContent>
                  </Select>
                </div>
                <div className="flex flex-col gap-1.5">
                  <Label>节点间协议</Label>
                  <Select value={draft.transport} onValueChange={(v) => set({ transport: v })}>
                    <SelectTrigger><SelectValue /></SelectTrigger>
                    <SelectContent>
                      <SelectItem value="tls">TLS（加密直连）</SelectItem>
                      <SelectItem value="wss">WSS（WebSocket over TLS）</SelectItem>
                      <SelectItem value="tcp">TCP（明文，调试用）</SelectItem>
                    </SelectContent>
                  </Select>
                </div>
              </div>
              <div className="flex flex-col gap-1.5">
                <Label>出口机监听端口</Label>
                <Input value={draft.exitListenPort} onChange={(e) => set({ exitListenPort: e.target.value.replace(/\D/g, "") })} placeholder="留空自动分配" />
              </div>
              <p className="text-xs text-muted-foreground">
                证书由面板自动生成自签对下发两端，入口侧不校验——改协议或换出口机配置自动跟随。
              </p>
            </div>
          )}

          <div className="flex flex-col gap-1.5">
            <div className="flex items-center justify-between">
              <Label>落地目标（可多个，每行一个 host:port）</Label>
              <Button variant="ghost" size="sm" onClick={() => set({ targets: [...draft.targets, { host: "", port: "" }] })}>
                <Plus className="size-3.5" /> 添加
              </Button>
            </div>
            <div className="flex flex-col gap-1.5">
              {draft.targets.map((t, i) => (
                <div key={i} className="flex items-center gap-1.5">
                  <Input
                    className="flex-1"
                    value={t.host}
                    onChange={(e) => patchTarget(i, { host: e.target.value })}
                    placeholder="目标地址（IP 或域名）"
                  />
                  <Input className="w-24" value={t.port} onChange={(e) => patchTarget(i, { port: e.target.value.replace(/\D/g, "") })} placeholder="端口" />
                  <div className="flex">
                    <Button variant="ghost" size="icon" className="size-7" disabled={i === 0} onClick={() => moveTarget(i, -1)}>
                      <ArrowUp className="size-3.5" />
                    </Button>
                    <Button variant="ghost" size="icon" className="size-7" disabled={i === draft.targets.length - 1} onClick={() => moveTarget(i, 1)}>
                      <ArrowDown className="size-3.5" />
                    </Button>
                    <Button variant="ghost" size="icon" className="size-7" disabled={draft.targets.length === 1} onClick={() => set({ targets: draft.targets.filter((_, j) => j !== i) })}>
                      <Trash2 className="size-3.5" />
                    </Button>
                  </div>
                </div>
              ))}
            </div>
          </div>
          <div className="grid grid-cols-2 gap-3">
            <div className="flex flex-col gap-1.5">
              <Label>负载策略{multi ? "" : "（单目标无需）"}</Label>
              <Select value={draft.balance || "none"} onValueChange={(v) => set({ balance: v === "none" ? "" : v })} disabled={!multi}>
                <SelectTrigger><SelectValue /></SelectTrigger>
                <SelectContent>
                  <SelectItem value="none">不启用</SelectItem>
                  <SelectItem value="fifo">主备（fifo，按顺序优先）</SelectItem>
                  <SelectItem value="round">轮询（round）</SelectItem>
                  <SelectItem value="rand">随机（rand）</SelectItem>
                  <SelectItem value="hash">源IP哈希（hash）</SelectItem>
                </SelectContent>
              </Select>
            </div>
            <div className="flex flex-col gap-1.5">
              <Label>UDP 转发</Label>
              <div className="flex h-9 items-center gap-2">
                <Switch checked={draft.udp} onCheckedChange={(v) => set({ udp: v })} />
                <span className="text-sm text-muted-foreground">{draft.udp ? "转发 UDP（额外监听同端口）" : "仅 TCP"}</span>
              </div>
            </div>
          </div>
        </div>
        <DialogFooter className="items-center">
          {(!nameOk || !tunnelOk || !targetsOk) && <Badge variant="secondary">名称、出口机与目标填全后可保存</Badge>}
          <Button disabled={busy || !nameOk || !tunnelOk || !targetsOk} onClick={save}>
            {editing ? "保存" : "创建"}
          </Button>
        </DialogFooter>
      </DialogContent>
    </Dialog>
  )
}
