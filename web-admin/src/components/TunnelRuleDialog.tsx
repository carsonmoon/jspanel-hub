import { useEffect, useState } from "react"
import { ArrowDown, ArrowUp, Plus, Trash2 } from "lucide-react"

import { Badge } from "@/components/ui/badge"
import { Button } from "@/components/ui/button"
import { Dialog, DialogContent, DialogFooter, DialogHeader, DialogTitle } from "@/components/ui/dialog"
import { Input } from "@/components/ui/input"
import { Label } from "@/components/ui/label"
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select"
import { Switch } from "@/components/ui/switch"
import { api, type RelayRule, type RelayTarget } from "@/lib/api"

export type Machine = { id: number; name: string; online?: boolean; local?: boolean; ip?: string }

type DraftTarget = { host: string; port: string; weight: string }

type Draft = {
  name: string
  serverId: string
  listenPort: string
  targets: DraftTarget[]
  balance: string
  protocol: string
  transport: string
  tlsSni: string
  tlsInsecure: boolean
  wsPath: string
  exitServerId: string
  exitListenPort: string
  listenHost: string
  through: string
  iface: string
  sendProxy: boolean
  mptcp: boolean
  note: string
  originLink: string
  entryBackups: string[]
  /** 最近一次从链接自动提取的名称：区分名称框是自动的还是手敲的。 */
  autoName: string
}

function emptyDraft(): Draft {
  return {
    name: "",
    autoName: "",
    entryBackups: [],
    // 入口机默认值在 open 时按面板机的节点行填（身份归一后没有「本机(0)」）
    serverId: "",
    listenPort: "",
    targets: [{ host: "", port: "", weight: "1" }],
    balance: "",
    protocol: "both",
    transport: "",
    tlsSni: "",
    tlsInsecure: false,
    wsPath: "",
    exitServerId: "0",
    exitListenPort: "",
    listenHost: "",
    through: "",
    iface: "",
    sendProxy: false,
    mptcp: false,
    note: "",
    originLink: "",
  }
}

function draftOf(rule: RelayRule): Draft {
  const targets = rule.targets.length > 0
    ? rule.targets.map((t) => ({ host: t.host, port: String(t.port), weight: String(t.weight) }))
    : [{ host: rule.target.split(":")[0] ?? "", port: rule.target.split(":")[1] ?? "", weight: "1" }]
  return {
    name: rule.name,
    serverId: String(rule.server_id),
    listenPort: rule.listen_port,
    targets,
    balance: rule.balance,
    protocol: rule.protocol || "both",
    transport: rule.transport,
    tlsSni: rule.tls_sni,
    tlsInsecure: rule.tls_insecure,
    wsPath: rule.ws_path,
    exitServerId: String(rule.exit_server_id || 0),
    exitListenPort: rule.exit_listen_port,
    listenHost: rule.listen_host,
    through: rule.through,
    iface: rule.interface,
    sendProxy: rule.send_proxy,
    mptcp: rule.mptcp,
    note: rule.note,
    autoName: "",
    originLink: rule.origin_link,
    entryBackups: JSON.parse(rule.entry_backups || "[]").map(String),
  }
}

/** 隧道规则编辑弹窗：导入链接 / 手动两种模式，手动含多出口、加密隧道与高级选项。 */
export function TunnelRuleDialog({ open, onOpenChange, editing, servers, portPool, onSaved }: {
  open: boolean
  onOpenChange: (open: boolean) => void
  editing: RelayRule | null
  servers: Machine[]
  portPool: string
  onSaved: () => Promise<void>
}) {
  const [mode, setMode] = useState<"import" | "manual">("import")
  const [draft, setDraft] = useState<Draft>(emptyDraft())
  const [advanced, setAdvanced] = useState(false)
  const [busy, setBusy] = useState(false)
  const set = (patch: Partial<Draft>) => setDraft((d) => ({ ...d, ...patch }))

  useEffect(() => {
    if (!open) return
    setMode(editing ? (editing.origin_link ? "import" : "manual") : "import")
    if (editing) {
      setDraft(draftOf(editing))
    } else {
      const local = servers.find((s) => s.local)
      const fallback = local ?? servers.find((s) => s.online) ?? servers[0]
      setDraft({ ...emptyDraft(), serverId: fallback ? String(fallback.id) : "" })
    }
    setAdvanced(false)
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

  // 入口机：在线机器才可选（离线发不下配置），当前编辑值恒保留并标注「（离线）」。
  const relayOptions = servers.filter((sv) => sv.online || String(sv.id) === draft.serverId)
  // 出口机：同样只列在线，且不能与入口机同机（加密隧道必须 ≥2 台物理机）；
  // 存量规则的出口机恒保留。
  const exitOptions = servers.filter(
    (sv) => (sv.online || String(sv.id) === draft.exitServerId) && String(sv.id) !== draft.serverId,
  )

  const save = async () => {
    setBusy(true)
    try {
      const targets: RelayTarget[] = draft.targets
        .map((t, i) => ({
          id: 0, rule_id: 0, seq: i,
          host: t.host.trim(), port: Number(t.port) || 0,
          weight: Math.max(1, Number(t.weight) || 1), enabled: true,
          state: "unknown", fail_streak: 0, ok_streak: 0, down_since: 0, last_checked: 0,
        }))
        .filter((t) => t.host && t.port > 0)
      const base = {
        server_id: Number(draft.serverId),
        name: draft.name.trim(),
        listen_port: draft.listenPort.trim(),
        enabled: editing?.enabled ?? true,
        origin_link: editing?.origin_link ?? draft.originLink.trim(),
        protocol: draft.protocol,
        note: draft.note.trim(),
        balance: targets.length > 1 ? draft.balance : "",
        transport: draft.exitServerId !== "0" ? draft.transport : "",
        tls_sni: draft.tlsSni.trim(),
        tls_insecure: draft.tlsInsecure,
        ws_path: draft.wsPath.trim(),
        exit_server_id: Number(draft.exitServerId),
        exit_listen_port: draft.exitListenPort.trim(),
        listen_host: draft.listenHost.trim(),
        through: draft.through.trim(),
        interface: draft.iface.trim(),
        send_proxy: draft.sendProxy,
        mptcp: draft.mptcp,
        entry_backups: JSON.stringify(draft.entryBackups.map(Number)),
        targets,
      }
      if (editing) {
        await api(`/proxy/relays/${editing.id}`, { method: "PUT", body: JSON.stringify({ ...base, target: editing.target, created_at: editing.created_at }) })
      } else {
        await api("/proxy/relays", { method: "POST", body: JSON.stringify(base) })
      }
      await onSaved()
      onOpenChange(false)
    } finally {
      setBusy(false)
    }
  }

  const tunnel = draft.exitServerId !== "0"
  const multi = draft.targets.length > 1
  const nameOk = mode === "import" && !editing ? draft.originLink.trim() !== "" : draft.name.trim() !== ""
  const targetsOk = mode === "import" && !editing || draft.targets.every((t) => !t.host.trim() || (Number(t.port) > 0 && t.port !== ""))

  return (
    <Dialog open={open} onOpenChange={onOpenChange}>
      <DialogContent className="max-h-[85vh] max-w-lg overflow-y-auto">
        <DialogHeader>
          <DialogTitle>{editing ? "编辑转发规则" : "新建转发规则"}</DialogTitle>
        </DialogHeader>
        <div className="flex flex-col gap-3">
          {!editing && (
            <div className="flex gap-1 rounded-md bg-muted p-1 text-sm">
              <button onClick={() => setMode("import")} className={`flex-1 rounded px-2 py-1 transition-colors ${mode === "import" ? "bg-background font-medium shadow-sm" : "text-muted-foreground"}`}>
                导入链接
              </button>
              <button onClick={() => setMode("manual")} className={`flex-1 rounded px-2 py-1 transition-colors ${mode === "manual" ? "bg-background font-medium shadow-sm" : "text-muted-foreground"}`}>
                手动填写
              </button>
            </div>
          )}
          {mode === "import" && !editing && (
            <div className="flex flex-col gap-1.5">
              <Label>分享链接</Label>
              <Input
                value={draft.originLink}
                onChange={(e) => {
                  const link = e.target.value
                  // 自动提取 # 后的节点名到名称框：名称为空或仍是上次自动
                  // 提取值时才覆盖，用户手敲过的不动。
                  const auto = link.includes("#") ? decodeURIComponent(link.split("#")[1].replace(/\+/g, " ")).trim() : ""
                  if (auto) {
                    const prev = draft.name.trim()
                    if (!prev || prev === draft.autoName) set({ originLink: link, name: auto, autoName: auto })
                    else set({ originLink: link, autoName: auto })
                  } else {
                    set({ originLink: link })
                  }
                }}
                placeholder="vless://…@1.2.3.4:21000?…#代理名"
              />
            </div>
          )}
          <div className="flex flex-col gap-1.5">
            <Label>规则名称</Label>
            <Input value={draft.name} onChange={(e) => set({ name: e.target.value })} placeholder="例如 香港-转发" />
          </div>
          <div className="grid grid-cols-2 gap-3">
            <div className="flex flex-col gap-1.5">
              <Label>入口机</Label>
              <Select value={draft.serverId} onValueChange={(v) => set({ serverId: v, entryBackups: draft.entryBackups.filter((b) => b !== v) })}>
                <SelectTrigger><SelectValue /></SelectTrigger>
                <SelectContent>
                  {relayOptions.map((sv) => (
                    <SelectItem key={sv.id} value={String(sv.id)}>
                      {sv.name}
                      {sv.local && (
                        <span className="rounded bg-primary/15 px-1 text-[10px] font-medium text-primary">主</span>
                      )}
                      {!sv.online && "（离线）"}
                    </SelectItem>
                  ))}
                </SelectContent>
              </Select>
            </div>
            <div className="flex flex-col gap-1.5">
              <Label>监听端口</Label>
              <Input value={draft.listenPort} onChange={(e) => set({ listenPort: e.target.value })} placeholder={portPool || "20000-50000"} />
            </div>
          </div>

          {/* 备用入口机（入口故障转移）：备用机上镜像同一条入口（同端口→同
              目标），主入口双确认判挂后域名翻转到备用机。候选=在线且非主。 */}
          {servers.length > 1 && (
            <div className="flex flex-col gap-1.5">
              <Label>备用入口机（可选）</Label>
              <div className="flex flex-wrap gap-1.5">
                {servers
                  .filter((sv) => String(sv.id) !== draft.serverId)
                  .map((sv) => {
                    const on = draft.entryBackups.includes(String(sv.id))
                    return (
                      <button
                        key={sv.id}
                        type="button"
                        onClick={() =>
                          set({
                            entryBackups: on
                              ? draft.entryBackups.filter((b) => b !== String(sv.id))
                              : [...draft.entryBackups, String(sv.id)],
                          })
                        }
                        className={`rounded-md border px-2 py-1 text-xs transition-colors ${
                          on ? "border-foreground bg-secondary font-medium" : "text-muted-foreground hover:bg-muted"
                        }`}
                      >
                        {sv.name}
                        {sv.local && <span className="ml-1 rounded bg-primary/15 px-1 text-[10px] font-medium text-primary">主</span>}
                        {!sv.online && "（离线）"}
                      </button>
                    )
                  })}
              </div>
              <p className="text-xs text-muted-foreground">
                备用机上会监听同一端口、转发到同一目标；主入口失联（agent 掉线且端口不可达，连续
                2 轮）时主入口绑定的域名自动翻转到备用机，恢复后回切。
              </p>
            </div>
          )}

          {/* 编辑导入式规则也要能改出口目标：链接只是来源，目标建立后就是
              普通可编辑字段（否则目标错了无从修正——线上实锤过 20000）。 */}
          {(mode === "manual" || editing) && (
            <>
              <div className="flex flex-col gap-1.5">
                <div className="flex items-center justify-between">
                  <Label>出口目标（可多个，多出口负载均衡）</Label>
                  <Button variant="ghost" size="sm" onClick={() => set({ targets: [...draft.targets, { host: "", port: "", weight: "1" }] })}>
                    <Plus className="size-3.5" /> 添加目标
                  </Button>
                </div>
                <div className="flex flex-col gap-1.5">
                  {draft.targets.map((t, i) => (
                    <div key={i} className="flex items-center gap-1.5">
                      <Input className="flex-1" value={t.host} onChange={(e) => patchTarget(i, { host: e.target.value })} placeholder="出口地址" />
                      <Input className="w-24" value={t.port} onChange={(e) => patchTarget(i, { port: e.target.value.replace(/\D/g, "") })} placeholder="端口" />
                      <Input className="w-16" title="权重（多目标负载均衡时生效）" value={t.weight} onChange={(e) => patchTarget(i, { weight: e.target.value.replace(/\D/g, "") })} placeholder="权重" />
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
                      <SelectItem value="roundrobin">轮询（roundrobin）</SelectItem>
                      <SelectItem value="iphash">源IP哈希（iphash）</SelectItem>
                    </SelectContent>
                  </Select>
                </div>
                <div className="flex flex-col gap-1.5">
                  <Label>转发协议</Label>
                  <Select value={draft.protocol} onValueChange={(v) => set({ protocol: v })}>
                    <SelectTrigger><SelectValue /></SelectTrigger>
                    <SelectContent>
                      <SelectItem value="both">TCP + UDP</SelectItem>
                      <SelectItem value="tcp">仅 TCP</SelectItem>
                      <SelectItem value="udp">仅 UDP</SelectItem>
                    </SelectContent>
                  </Select>
                </div>
              </div>
            </>
          )}

          <div className="rounded-md border p-3">
            <div className="flex items-center gap-2">
              <Switch
                checked={tunnel}
                disabled={exitOptions.length === 0}
                onCheckedChange={(v) => {
                  if (!v) {
                    set({ exitServerId: "0", transport: "" }) // 0=直连哨兵，非身份
                    return
                  }
                  // 默认选第一台可用出口机；没有就保持关（开关已禁用）。
                  const first = exitOptions[0]
                  if (!first) return
                  set({ exitServerId: String(first.id), transport: draft.transport || "tls" })
                }}
                id="tunnel"
              />
              <Label htmlFor="tunnel" className="font-medium">加密隧道（入口机 ⇄ 出口机间加一层 TLS / WS / WSS）</Label>
            </div>
            <p className="mt-1 text-xs text-muted-foreground">
              {exitOptions.length === 0
                ? "没有可用的出口机：加密隧道需要入口、出口两台不同的在线物理机（都装有面板 agent）。"
                : "开启后出口机也需安装面板 agent，两端配置由面板自动生成并配对。"}
            </p>
            {tunnel && (
              <div className="mt-3 flex flex-col gap-3">
                <div className="grid grid-cols-2 gap-3">
                  <div className="flex flex-col gap-1.5">
                    <Label>加密方式</Label>
                    <Select value={draft.transport || "none"} onValueChange={(v) => set({ transport: v === "none" ? "" : v })}>
                      <SelectTrigger><SelectValue /></SelectTrigger>
                      <SelectContent>
                        <SelectItem value="tls">TLS</SelectItem>
                        <SelectItem value="ws">WS</SelectItem>
                        <SelectItem value="wss">WSS（WS over TLS）</SelectItem>
                      </SelectContent>
                    </Select>
                  </div>
                  <div className="flex flex-col gap-1.5">
                    <Label>出口机（加密层另一端）</Label>
                    <Select value={draft.exitServerId} onValueChange={(v) => set({ exitServerId: v === draft.serverId ? "0" : v })}>
                      <SelectTrigger><SelectValue /></SelectTrigger>
                      <SelectContent>
                        {exitOptions.map((sv) => (
                          <SelectItem key={sv.id} value={String(sv.id)}>
                            {sv.name}
                            {!sv.online && "（离线）"}
                          </SelectItem>
                        ))}
                      </SelectContent>
                    </Select>
                  </div>
                </div>
                <div className="grid grid-cols-2 gap-3">
                  {(draft.transport === "tls" || draft.transport === "wss") && (
                    <div className="flex flex-col gap-1.5">
                    <Label>SNI / 域名</Label>
                    <Input value={draft.tlsSni} onChange={(e) => set({ tlsSni: e.target.value })} placeholder="留空则使用出口机地址" />
                    </div>
                  )}
                  {(draft.transport === "ws" || draft.transport === "wss") && (
                    <div className="flex flex-col gap-1.5">
                      <Label>WS 路径</Label>
                      <Input value={draft.wsPath} onChange={(e) => set({ wsPath: e.target.value })} placeholder="/tun" />
                    </div>
                  )}
                  <div className="flex flex-col gap-1.5">
                    <Label>出口机监听端口</Label>
                    <Input value={draft.exitListenPort} onChange={(e) => set({ exitListenPort: e.target.value.replace(/\D/g, "") })} placeholder="自动分配" />
                  </div>
                </div>
                {(draft.transport === "tls" || draft.transport === "wss") && (
                  <p className="text-xs text-muted-foreground">
                    出口侧用 SNI 域名（未填则为出口机地址）生成自签证书，入口侧固定不校验证书；有真实域名时填 SNI 即可。
                  </p>
                )}
              </div>
            )}
          </div>

          <div className="flex flex-col gap-2">
            <button className="self-start text-sm text-muted-foreground underline-offset-2 hover:underline" onClick={() => setAdvanced(!advanced)}>
              {advanced ? "收起高级选项（绑定地址 / Proxy Protocol / MPTCP）" : "高级选项（绑定地址 / Proxy Protocol / MPTCP）"}
            </button>
            {advanced && (
              <div className="flex flex-col gap-3 rounded-md border p-3">
                <div className="grid grid-cols-3 gap-3">
                  <div className="flex flex-col gap-1.5">
                    <Label>监听地址</Label>
                    <Input value={draft.listenHost} onChange={(e) => set({ listenHost: e.target.value })} placeholder="0.0.0.0" />
                  </div>
                  <div className="flex flex-col gap-1.5">
                    <Label>出站绑定 IP</Label>
                    <Input value={draft.through} onChange={(e) => set({ through: e.target.value })} placeholder="自动" />
                  </div>
                  <div className="flex flex-col gap-1.5">
                    <Label>网卡</Label>
                    <Input value={draft.iface} onChange={(e) => set({ iface: e.target.value })} placeholder="eth0" />
                  </div>
                </div>
                <div className="flex flex-col gap-2">
                  <label className="flex items-center gap-2 text-sm">
                    <Switch checked={draft.sendProxy} onCheckedChange={(v) => set({ sendProxy: v })} />
                    Proxy Protocol v2（把真实客户端 IP 传给出口）
                  </label>
                  <label className="flex items-center gap-2 text-sm">
                    <Switch checked={draft.mptcp} onCheckedChange={(v) => set({ mptcp: v })} />
                    MPTCP（多路径 TCP，需内核开启）
                  </label>
                </div>
              </div>
            )}
          </div>
        </div>
        <DialogFooter className="items-center">
          {!editing && !nameOk && <Badge variant="secondary">填入链接或名称后可保存</Badge>}
          <Button disabled={busy || !nameOk || !targetsOk} onClick={save}>
            {editing ? "保存" : "创建"}
          </Button>
        </DialogFooter>
      </DialogContent>
    </Dialog>
  )
}
