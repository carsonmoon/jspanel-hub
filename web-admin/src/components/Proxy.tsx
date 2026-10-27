import { useCallback, useEffect, useState } from "react"
import { Activity, ArrowLeftRight, Copy, Globe, Pencil, Plus, QrCode, RefreshCw, Trash2 } from "lucide-react"
import { toast } from "sonner"

import { copy } from "@/components/QrDialog"
import { QrDialog } from "@/components/QrDialog"
import { Tooltip, TooltipContent, TooltipTrigger } from "@/components/ui/tooltip"
import { Button } from "@/components/ui/button"
import { Card } from "@/components/ui/card"
import { Dialog, DialogContent, DialogFooter, DialogHeader, DialogTitle } from "@/components/ui/dialog"
import { Input } from "@/components/ui/input"
import { Label } from "@/components/ui/label"
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select"
import { Switch } from "@/components/ui/switch"
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table"
import { api, type Node } from "@/lib/api"
import { protocolChipClass } from "@/lib/protocolChip"

// ---- types mirroring the hub's proxy API (设计文档 8-10) ----

export type ProxyUser = {
  id: number
  name: string
  credential: string
  sub_user_id: number | null
  link: string
  /** 凭据级到期（YYYY-MM-DD），null=跟随客户级。 */
  expires_at?: string | null
  /** 凭据级流量配额（字节），0=不启用。 */
  quota_bytes?: number
  /** 分配给客户的时间（秒级时间戳）；0=未分配或历史分配。 */
  created_at?: number
  quota_used_up?: number
  quota_used_down?: number
  quota_period_start?: number
  quota_reset?: string
}

export type ProxyNode = {
  id: number
  name: string
  protocol: string
  listen_port: number
  sni: string
  flow: string
  uuid: string
  method: string
  enabled: boolean
  server_id: number
  remark: string
  egress_type: string
  egress_host: string
  egress_port: number
  egress_username: string
  egress_password: string
  public_key: string
  short_id: string
  reality_private_key: string | null
  rate_up: number
  rate_down: number
  dns_name: string
  dns_server_id: number
  dns_ip: string
  users: ProxyUser[]
}

export type SubUser = {
  id: number
  name: string
  token: string
  enabled: boolean
  expires_at: string | null
  remark: string
  created_at: number
  quota_bytes: number
  quota_reset: string
  quota_used_up: number
  quota_used_down: number
  quota_period_start: number
  /** /u/{token} 用户中心页开关。 */
  user_page: boolean
  /** 绑定的内容方案（订阅内容 = 该方案渲染 + 客户自有凭据）；null = 裸节点。 */
  profile_id?: number | null
  /** agent 分发开关（分发端口按它门控回源）。 */
  agent_dist?: boolean
  /** /u/ 用户中心页视图：overview 总览 / per_node 逐节点明细。 */
  view_mode?: string
  /** 自助重置订阅（/u/ 页客户自行轮换凭据+链接）：开关/上限/已用/上次时间。 */
  allow_self_reset?: boolean
  reset_limit?: number
  reset_count?: number
  last_reset_at?: number
  status: string
}

export const PROTOCOL_LABEL: Record<string, string> = {
  "vless-reality": "VLESS + Reality",
  hysteria2: "Hysteria 2",
  shadowsocks: "Shadowsocks",
  anytls: "AnyTLS",
  socks: "SOCKS5",
  http: "HTTP",
}

const PROTOCOLS = Object.keys(PROTOCOL_LABEL)
const NEEDS_SNI = new Set(["vless-reality", "hysteria2", "anytls"])
const SS_METHODS = ["2022-blake3-aes-128-gcm", "2022-blake3-aes-256-gcm"]
const DEFAULT_SNI: Record<string, string> = {
  "vless-reality": "www.yahoo.com",
  hysteria2: "www.bing.com",
  anytls: "www.bing.com",
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



function useProxyData() {
  const [servers, setServers] = useState<{ id: number; name: string; online: boolean; local?: boolean; ip: string }[]>([])
  const [nodes, setNodes] = useState<ProxyNode[]>([])
  const [cores, setCores] = useState<{ server_id: number; version: string; stale: boolean }[]>([])
  const load = useCallback(async () => {
    const n = await api<{ host: string; nodes: ProxyNode[]; cores?: { server_id: number; version: string; stale: boolean }[] }>("/proxy/nodes")
    setNodes(n.nodes)
    setCores(n.cores ?? [])
    try {
      // 服务器下拉用：本机之外的所有监控服务器（含离线的，方便预建节点）。
      const all = await api<{ nodes?: { id: number; name: string }[] } | { id: number; name: string }[]>("/nodes")
      const list = Array.isArray(all) ? all : (all.nodes ?? [])
      setServers(
        list.map((x) => {
          const n = x as { id: number; name: string; online?: boolean; local?: boolean; addresses?: { address: string }[]; ipv4?: string }
          return { id: n.id, name: n.name, online: !!n.online, local: !!n.local, ip: String(n.addresses?.[0]?.address ?? n.ipv4 ?? "") }
        }),
      )
    } catch {
      setServers([])
    }
  }, [])
  useEffect(() => {
    load().catch((e) => toast.error(e.message))
  }, [load])
  return { servers, nodes, cores, reload: load }
}

// ---- nodes ----

const EGRESS_LABEL: Record<string, string> = { "": "直接出网", socks5: "SOCKS5 代理", http: "HTTP 代理" }

// 解析住宅代理商常见的粘贴格式：ip:端口:用户名:密码、ip:端口、
// user:pass@ip:端口，可选 socks5:// http:// 前缀（前缀决定出口类型）。
function parseEgress(raw: string): { type: string; host: string; port: number; user: string; pass: string } | null {
  let s = raw.trim()
  if (!s) return null
  let type = ""
  const scheme = s.match(/^(socks5|socks|http):\/\//i)
  if (scheme) {
    type = scheme[1].toLowerCase() === "http" ? "http" : "socks5"
    s = s.slice(scheme[0].length)
  }
  let user = ""
  let pass = ""
  if (s.includes("@")) {
    const at = s.lastIndexOf("@")
    const userinfo = s.slice(0, at)
    s = s.slice(at + 1)
    const c = userinfo.indexOf(":")
    if (c >= 0) {
      user = userinfo.slice(0, c)
      pass = userinfo.slice(c + 1)
    } else {
      user = userinfo
    }
  }
  const parts = s.split(":")
  if (parts.length === 2) {
    return { type: type || "socks5", host: parts[0].trim(), port: Number(parts[1]), user, pass }
  }
  if (parts.length === 4 && !user && !pass) {
    return { type: type || "socks5", host: parts[0].trim(), port: Number(parts[1]), user: parts[2], pass: parts[3] }
  }
  return null
}

function NodeDialog({ open, initial, servers, onOpenChange, reload }: {
  open: boolean
  initial?: ProxyNode | null
  servers: { id: number; name: string; online: boolean; local?: boolean }[]
  onOpenChange: (v: boolean) => void
  reload: () => Promise<void>
}) {
  const editing = !!initial
  const [name, setName] = useState("")
  const [protocol, setProtocol] = useState("vless-reality")
  const [serverId, setServerId] = useState(0)
  const [sni, setSni] = useState(DEFAULT_SNI["vless-reality"])
  const [flow, setFlow] = useState("xtls-rprx-vision")
  const [uuid, setUuid] = useState("")
  const [privateKey, setPrivateKey] = useState("")
  const [shortId, setShortId] = useState("")
  const [publicKey, setPublicKey] = useState("")
  const [method, setMethod] = useState(SS_METHODS[0])
  const [port, setPort] = useState("")
  const [rateUp, setRateUp] = useState("")
  const [rateDown, setRateDown] = useState("")
  const [egressType, setEgressType] = useState("")
  const [egressHost, setEgressHost] = useState("")
  const [egressPort, setEgressPort] = useState("")
  const [egressUser, setEgressUser] = useState("")
  const [egressPass, setEgressPass] = useState("")
  const [egressPaste, setEgressPaste] = useState("")
  const [egressParsed, setEgressParsed] = useState(false)
  const [dnsName, setDnsName] = useState("")
  const [busy, setBusy] = useState(false)
  useEffect(() => {
    if (!open) return
    const n = initial
    setName(n?.name ?? "")
    setProtocol(n?.protocol ?? "vless-reality")
    // 新建默认选第一台在线机器：server_id=0 不在下拉里，留 0 触发器空白、
    // 不改就保存还会创建出 server_id=0 的存量形态协议（255 号提交信息声称
    // 的行为，实际此前未落地）
    // 身份归一：没有「本机(0)」兜底——默认第一台在线节点，列表空则留空由后端报「请选择节点」
    setServerId(n?.server_id ?? servers.find((s) => s.online)?.id ?? servers[0]?.id ?? 0)
    setSni(n?.sni ?? DEFAULT_SNI["vless-reality"])
    setFlow(n ? (n.flow || "none") : "xtls-rprx-vision")
    setUuid(n?.uuid ?? "")
    setPrivateKey(n?.reality_private_key ?? "")
    setShortId(n?.short_id ?? "")
    setPublicKey(n?.public_key ?? "")
    setMethod(n?.method || SS_METHODS[0])
    setPort(n ? String(n.listen_port) : "")
    setRateUp(n?.rate_up ? String(n.rate_up) : "")
    setRateDown(n?.rate_down ? String(n.rate_down) : "")
    setEgressType(n?.egress_type ?? "")
    setEgressHost(n?.egress_host ?? "")
    setEgressPort(n?.egress_port ? String(n.egress_port) : "")
    setEgressUser(n?.egress_username ?? "")
    setEgressPass(n?.egress_password ?? "")
    setEgressPaste("")
    setEgressParsed(false)
    setDnsName(n?.dns_name ?? "")
  }, [open, initial])

  const changeProtocol = (value: string) => {
    setProtocol(value)
    if (!editing) setSni(DEFAULT_SNI[value] ?? "")
  }

  const save = async () => {
    setBusy(true)
    try {
      const body: Record<string, unknown> = {
        name: name.trim(),
        protocol,
        server_id: serverId,
        listen_port: port.trim() ? Number(port.trim()) : 0,
        rate_up: rateUp.trim() ? Number(rateUp.trim()) : 0,
        rate_down: rateDown.trim() ? Number(rateDown.trim()) : 0,
        egress_type: egressType,
        egress_host: egressHost.trim(),
        egress_port: egressPort.trim() ? Number(egressPort.trim()) : 0,
        egress_username: egressUser.trim(),
        egress_password: egressPass,
        dns_name: dnsName.trim(),
      }
      if (NEEDS_SNI.has(protocol)) body.sni = sni.trim()
      if (protocol === "vless-reality") {
        body.flow = flow === "none" ? "" : flow
        if (uuid.trim()) body.uuid = uuid.trim()
        if (privateKey.trim()) body.reality_private_key = privateKey.trim()
        if (shortId.trim()) body.reality_short_id = shortId.trim()
      }
      if (protocol === "shadowsocks") body.method = method
      if (editing) {
        await api(`/proxy/nodes/${initial!.id}`, { method: "PUT", body: JSON.stringify(body) })
        toast.success("代理已更新")
      } else {
        await api("/proxy/nodes", { method: "POST", body: JSON.stringify(body) })
        toast.success("代理已创建")
      }
      onOpenChange(false)
      await reload()
    } catch (e) {
      toast.error((e as Error).message)
    } finally {
      setBusy(false)
    }
  }

  const randomize = async (kind: "uuid" | "reality" | "short_id") => {
    setBusy(true)
    try {
      const result = await api<{ uuid?: string; short_id?: string; private_key?: string; public_key?: string }>(
        `/proxy/credentials/random?kind=${kind}`,
      )
      if (kind === "uuid") setUuid(result.uuid ?? "")
      if (kind === "short_id") setShortId(result.short_id ?? "")
      if (kind === "reality") {
        setPrivateKey(result.private_key ?? "")
        setPublicKey(result.public_key ?? "")
      }
    } catch (e) {
      toast.error((e as Error).message)
    } finally {
      setBusy(false)
    }
  }

  const udpHint =
    egressType === "http" && protocol === "hysteria2"
      ? "HTTP 出站不支持 UDP，Hysteria2 的 UDP 业务将不可用。"
      : egressType === "socks5"
        ? "UDP 是否可用取决于上游 SOCKS5 是否支持 UDP ASSOCIATE。"
        : null

  return (
    <Dialog open={open} onOpenChange={onOpenChange}>
      <DialogContent className="max-h-[85vh] max-w-md overflow-y-auto">
        <DialogHeader>
          <DialogTitle>{editing ? "编辑代理" : "新建代理"}</DialogTitle>
        </DialogHeader>
        <div className="flex flex-col gap-3">
          <div className="flex flex-col gap-1.5">
            <Label>代理名称</Label>
            <Input value={name} onChange={(e) => setName(e.target.value)} placeholder="例如 香港-01" />
          </div>
          <div className="flex flex-col gap-1.5">
            <Label>主机</Label>
            <Select value={String(serverId)} onValueChange={(v) => setServerId(Number(v))}>
              <SelectTrigger>
                <SelectValue />
              </SelectTrigger>
              <SelectContent>
                {/* 离线机器不进下拉（无法下发配置）；编辑已建在离线机器上的协议时保留该项并标注 */}
                {servers
                  .filter((s) => s.online || s.id === serverId)
                  .map((s) => (
                    <SelectItem key={s.id} value={String(s.id)}>
                      {s.name}
                      {/* 面板所在机器的固定标识（后端按 hostname 判定），不随节点名改动 */}
                      {s.local && <span className="rounded bg-primary/15 px-1 text-[10px] font-medium text-primary">主</span>}
                      {!s.online && "（离线）"}
                    </SelectItem>
                  ))}
              </SelectContent>
            </Select>
          </div>
          <div className="flex flex-col gap-1.5">
            <Label>协议</Label>
            <Select value={protocol} onValueChange={changeProtocol} disabled={editing}>
              <SelectTrigger>
                <SelectValue />
              </SelectTrigger>
              <SelectContent>
                {PROTOCOLS.map((p) => (
                  <SelectItem key={p} value={p}>
                    {PROTOCOL_LABEL[p]}
                  </SelectItem>
                ))}
              </SelectContent>
            </Select>
          </div>
          {NEEDS_SNI.has(protocol) && (
            <div className="flex flex-col gap-1.5">
              <Label>伪装目标 / SNI{protocol !== "vless-reality" && "（自签证书按它生成）"}</Label>
              <Input value={sni} onChange={(e) => setSni(e.target.value)} />
            </div>
          )}
          {protocol === "vless-reality" && (
            <>
              <div className="flex flex-col gap-1.5">
                <Label>流控</Label>
                <Select value={flow} onValueChange={setFlow}>
                  <SelectTrigger><SelectValue /></SelectTrigger>
                  <SelectContent>
                    <SelectItem value="xtls-rprx-vision">Vision</SelectItem>
                    <SelectItem value="none">无流控</SelectItem>
                  </SelectContent>
                </Select>
              </div>
              <details className="rounded-md border p-3">
                <summary className="cursor-pointer text-sm font-medium">高级设置</summary>
                <div className="mt-3 flex flex-col gap-2">
                  <div className="flex flex-col gap-1.5">
                    <Label>默认 UUID</Label>
                    <div className="flex gap-2">
                      <Input value={uuid} onChange={(e) => setUuid(e.target.value)} placeholder="留空保持现有值" />
                      <Button type="button" variant="outline" size="icon" title="随机生成 UUID" disabled={busy} onClick={() => randomize("uuid")}>
                        <RefreshCw className="size-4" />
                      </Button>
                    </div>
                  </div>
                  <div className="flex flex-col gap-1.5">
                    <Label>Reality 私钥</Label>
                    <div className="flex gap-2">
                      <Input value={privateKey} onChange={(e) => setPrivateKey(e.target.value)} placeholder="留空保持现有值" />
                      <Button type="button" variant="outline" size="icon" title="随机生成 Reality 密钥" disabled={busy} onClick={() => randomize("reality")}>
                        <RefreshCw className="size-4" />
                      </Button>
                    </div>
                  </div>
                  <div className="flex flex-col gap-1.5">
                    <Label>Reality short ID</Label>
                    <div className="flex gap-2">
                      <Input value={shortId} onChange={(e) => setShortId(e.target.value)} placeholder="留空保持现有值" />
                      <Button type="button" variant="outline" size="icon" title="随机生成 short ID" disabled={busy} onClick={() => randomize("short_id")}>
                        <RefreshCw className="size-4" />
                      </Button>
                    </div>
                  </div>
                  {publicKey && (
                    <div className="flex flex-col gap-1.5">
                      <Label>Public key（自动推导）</Label>
                      <Input value={publicKey} readOnly />
                    </div>
                  )}
                </div>
              </details>
            </>
          )}
          {protocol === "shadowsocks" && (
            <div className="flex flex-col gap-1.5">
              <Label>加密方法</Label>
              <Select value={method} onValueChange={setMethod} disabled={editing}>
                <SelectTrigger>
                  <SelectValue />
                </SelectTrigger>
                <SelectContent>
                  {SS_METHODS.map((m) => (
                    <SelectItem key={m} value={m}>
                      {m}
                    </SelectItem>
                  ))}
                </SelectContent>
              </Select>
            </div>
          )}
          <div className="flex flex-col gap-1.5">
            <Label>端口{!editing && "（留空从端口池自动分配）"}</Label>
            <Input value={port} onChange={(e) => setPort(e.target.value)} placeholder="20000-50000" inputMode="numeric" />
          </div>
          <div className="flex flex-col gap-1.5">
            <Label>绑定域名（可选，需托管在 Cloudflare）</Label>
            <Input value={dnsName} onChange={(e) => setDnsName(e.target.value)} placeholder="例如 node1.example.com" />
            <p className="text-xs text-muted-foreground">
              绑定后分享链接与二维码改用该域名：IP 被墙时「切换主机」换 IP 不换链接，客户无需重新导入。
            </p>
          </div>
          <div className="flex flex-col gap-1.5">
            <Label>限速（Mbps，留空不限）</Label>
            <div className="grid grid-cols-2 gap-2">
              <div className="flex items-center gap-1.5">
                <span className="shrink-0 text-xs text-up">↑ 上行</span>
                <Input value={rateUp} onChange={(e) => setRateUp(e.target.value)} placeholder="不限" inputMode="numeric" />
              </div>
              <div className="flex items-center gap-1.5">
                <span className="shrink-0 text-xs text-primary">↓ 下行</span>
                <Input value={rateDown} onChange={(e) => setRateDown(e.target.value)} placeholder="不限" inputMode="numeric" />
              </div>
            </div>
            <p className="text-xs text-muted-foreground">在该代理端口上做内核级限速（tc），对所有经此端口的流量生效。</p>
          </div>
          <div className="rounded-md border p-3">
            <div className="mb-2 text-sm font-medium">链式出口（流量经上游代理后再出网）</div>
            <div className="flex flex-col gap-2">
              <div className="flex gap-2">
                <Select value={egressType} onValueChange={setEgressType}>
                  <SelectTrigger>
                    <SelectValue />
                  </SelectTrigger>
                  <SelectContent>
                    {Object.entries(EGRESS_LABEL).map(([v, label]) => (
                      <SelectItem key={v} value={v}>
                        {label}
                      </SelectItem>
                    ))}
                  </SelectContent>
                </Select>
                <Input
                  value={egressPaste}
                  onChange={(e) => {
                    setEgressPaste(e.target.value)
                    const parsed = parseEgress(e.target.value)
                    setEgressParsed(!!parsed)
                    if (parsed) {
                      if (!egressType) setEgressType(parsed.type)
                      setEgressHost(parsed.host)
                      setEgressPort(parsed.port ? String(parsed.port) : "")
                      if (parsed.user) setEgressUser(parsed.user)
                      if (parsed.pass) setEgressPass(parsed.pass)
                    }
                  }}
                  placeholder="粘贴 IP:端口:用户名:密码"
                  className={egressParsed ? "border-emerald-500" : undefined}
                />
              </div>
              {egressType && (
                <>
                  <div className="flex gap-2">
                    <Input value={egressHost} onChange={(e) => setEgressHost(e.target.value)} placeholder="上游地址" />
                    <Input value={egressPort} onChange={(e) => setEgressPort(e.target.value)} placeholder="端口" inputMode="numeric" className="w-28" />
                  </div>
                  <div className="flex gap-2">
                    <Input value={egressUser} onChange={(e) => setEgressUser(e.target.value)} placeholder="用户名（可空）" />
                    <Input value={egressPass} onChange={(e) => setEgressPass(e.target.value)} placeholder="密码（可空）" type="password" />
                  </div>
                  {udpHint && <div className="text-xs text-amber-600">{udpHint}</div>}
                </>
              )}
            </div>
          </div>
        </div>
        <DialogFooter>
          <Button disabled={busy || !name.trim()} onClick={save}>
            {editing ? "保存" : "创建"}
          </Button>
        </DialogFooter>
      </DialogContent>
    </Dialog>
  )
}

/// 出口测速的常用预设目标（点选即保存；空 = 默认 gstatic generate_204）。
const PROBE_PRESETS: { label: string; url: string }[] = [
  { label: "默认（gstatic）", url: "" },
  { label: "Apple", url: "http://www.apple.com/library/test/success.html" },
  { label: "高通（国内）", url: "http://www.qualcomm.cn/generate_204" },
  { label: "Cloudflare", url: "http://cp.cloudflare.com" },
  { label: "微软（国内）", url: "http://www.msftconnecttest.com/connecttest.txt" },
]

/// 切换主机（IP 被墙时换机不换链接）：同一套参数先在新主机跑起来、端口
/// 确认可连，最后才改域名解析——中途失败域名不动，客户端无感知。
function SwitchDialog({ open, node, servers, onOpenChange, reload }: {
  open: boolean
  node: ProxyNode | null
  servers: { id: number; name: string; online: boolean; local?: boolean }[]
  onOpenChange: (v: boolean) => void
  reload: () => Promise<void>
}) {
  const [target, setTarget] = useState(0)
  const [busy, setBusy] = useState(false)
  useEffect(() => {
    if (open) setTarget(0)
  }, [open, node])
  if (!node) return null
  const currentName =
    servers.find((s) => s.id === node.dns_server_id)?.name ?? `主机 ${node.dns_server_id}`
  const options = servers.filter((s) => s.online && s.id !== node.dns_server_id)

  const run = async () => {
    if (!target) return
    setBusy(true)
    try {
      const r = await api<{ ip: string; server_name: string }>(`/proxy/nodes/${node.id}/switch`, {
        method: "POST",
        body: JSON.stringify({ server_id: target }),
      })
      toast.success(`已切换：${node.dns_name} → ${r.server_name}（${r.ip}），客户端约 5 分钟内自动恢复`)
      onOpenChange(false)
      await reload()
    } catch (e) {
      toast.error((e as Error).message)
    } finally {
      setBusy(false)
    }
  }

  return (
    <Dialog open={open} onOpenChange={busy ? () => {} : onOpenChange}>
      <DialogContent className="max-w-md">
        <DialogHeader>
          <DialogTitle>切换主机</DialogTitle>
        </DialogHeader>
        <div className="flex flex-col gap-3">
          <div className="rounded-md border p-3 text-sm">
            <div className="font-medium">{node.name}</div>
            <div className="mt-1 text-xs text-muted-foreground">
              域名 <span className="font-mono">{node.dns_name}</span>
            </div>
            <div className="mt-0.5 text-xs text-muted-foreground">
              当前指向：{currentName}
              {node.dns_ip && <span className="font-mono">（{node.dns_ip}）</span>}
            </div>
          </div>
          <div className="flex flex-col gap-1.5">
            <Label>切换到（在线被管主机）</Label>
            <Select value={String(target)} onValueChange={(v) => setTarget(Number(v))}>
              <SelectTrigger>
                <SelectValue placeholder="选择目标主机" />
              </SelectTrigger>
              <SelectContent>
                {options.length === 0 && (
                  <div className="px-3 py-2 text-xs text-muted-foreground">没有其他在线主机可选</div>
                )}
                {options.map((s) => (
                  <SelectItem key={s.id} value={String(s.id)}>
                    {s.name}
                    {s.local && <span className="ml-1 rounded bg-primary/15 px-1 text-[10px] font-medium text-primary">主</span>}
                    {s.id === node.server_id && "（原机）"}
                  </SelectItem>
                ))}
              </SelectContent>
            </Select>
            <p className="text-xs text-muted-foreground">
              同一套参数（UUID/密钥/端口）会先在新主机跑起来并确认端口可连，最后才改域名解析；
              中途任何失败域名都不动，客户端无感知。原主机节点保留，可随时再切回。
            </p>
          </div>
        </div>
        <DialogFooter>
          <Button variant="ghost" disabled={busy} onClick={() => onOpenChange(false)}>
            取消
          </Button>
          <Button disabled={busy || !target} onClick={run}>
            {busy ? "切换中…（最长约 1 分钟）" : "切换"}
          </Button>
        </DialogFooter>
      </DialogContent>
    </Dialog>
  )
}

/// 延迟读数按程度着色（与订阅页/隧道页同款分级）：<150 绿 / <400 黄 / 其余红，不通红。
/// 链式出口协议（leg1_ms 有值）：显示 tcping 风格的 socks5 连接延迟（用户拍板：只
/// 关心节点可用），全链耗时进悬浮提示（300ms 即显，比原生 title 快）；全链失败整
/// 键变红，原因在悬停。
function LatencyText({ r }: { r: { avg_ms: number | null; loss: number; error?: string | null; leg1_ms?: number | null } }) {
  if (r.leg1_ms != null) {
    if (r.avg_ms === null)
      return (
        <span className="text-xs font-medium text-destructive" title={r.error || "链路不可用"}>
          不可用
        </span>
      )
    const cls = r.leg1_ms < 150 ? "text-emerald-600 dark:text-emerald-400" : r.leg1_ms < 400 ? "text-amber-600 dark:text-amber-400" : "text-destructive"
    return (
      <span className="group relative inline-block cursor-help">
        <span className={`text-xs font-medium ${cls}`}>{r.leg1_ms.toFixed(0)} ms</span>
        <span className="pointer-events-none absolute bottom-full left-1/2 z-50 mb-1 -translate-x-1/2 whitespace-nowrap rounded-md border bg-popover px-2 py-1 text-[11px] text-popover-foreground opacity-0 shadow-md transition-opacity duration-100 group-hover:opacity-100 group-hover:delay-300">
          SOCKS5 连接 {r.leg1_ms.toFixed(0)} ms · 访问目标 {r.avg_ms.toFixed(0)} ms
        </span>
      </span>
    )
  }
  if (r.avg_ms === null) return <span className="text-xs font-medium text-destructive" title={r.error || "探测失败"}>不通</span>
  const cls = r.avg_ms < 150 ? "text-emerald-600 dark:text-emerald-400" : r.avg_ms < 400 ? "text-amber-600 dark:text-amber-400" : "text-destructive"
  return (
    <span className={`text-xs font-medium ${cls}`}>
      {r.avg_ms.toFixed(0)} ms{r.loss > 0 ? `（丢包 ${(r.loss * 100).toFixed(0)}%）` : ""}
    </span>
  )
}

function NodesCard({ nodes, servers, reload }: { nodes: ProxyNode[]; servers: { id: number; name: string; online: boolean; local?: boolean; ip: string }[]; reload: () => Promise<void> }) {
  const [dialogOpen, setDialogOpen] = useState(false)
  const [editing, setEditing] = useState<ProxyNode | null>(null)
  const [switching, setSwitching] = useState<ProxyNode | null>(null)
  const [qrNode, setQrNode] = useState<{ name: string; url: string } | null>(null)
  const [testing, setTesting] = useState<number | null>(null)
  const [bulkTesting, setBulkTesting] = useState(false)
  const [probeOpen, setProbeOpen] = useState(false)
  const [probeDraft, setProbeDraft] = useState("")
  const [latency, setLatency] = useState<Record<number, { avg_ms: number | null; loss: number; error?: string | null; leg1_ms?: number | null }>>({})
  const { armed, arm } = useConfirmDelete()

  const test = async (node: ProxyNode) => {
    setTesting(node.id)
    try {
      const r = await api<{ avg_ms: number | null; loss: number; error?: string | null; leg1_ms?: number | null }>(`/proxy/nodes/${node.id}/test`, { method: "POST" })
      if (r.avg_ms === null) toast.error(r.error || "出口线路不可达")
      setLatency((m) => ({ ...m, [node.id]: r }))
    } catch (e) {
      toast.error((e as Error).message)
    } finally {
      setTesting(null)
    }
  }

  useEffect(() => {
    api<{ exit_probe_url?: string }>("/settings").then((s) => setProbeDraft(s.exit_probe_url ?? "")).catch(() => {})
  }, [])

  const saveProbe = async (url: string) => {
    try {
      await api("/settings", { method: "PUT", body: JSON.stringify({ exit_probe_url: url }) })
      setProbeDraft(url)
      setProbeOpen(false)
      toast.success(url ? "测速目标已保存" : "已恢复默认测速目标")
    } catch (e) {
      toast.error((e as Error).message)
    }
  }

  // 批量测速：所有启用协议并行探测（禁用协议没在监听，测了只会显示不通）。
  const testAll = async () => {
    setBulkTesting(true)
    try {
      const r = await api<{ results: { id: number; avg_ms: number | null; loss: number; error?: string | null; leg1_ms?: number | null }[] }>("/proxy/nodes/test", { method: "POST" })
      setLatency((m) => ({ ...m, ...Object.fromEntries(r.results.map((x) => [x.id, x])) }))
      const down = r.results.filter((x) => x.avg_ms === null).length
      if (r.results.length === 0) toast.error("没有启用中的代理")
      else if (down === r.results.length) toast.error("测速完成：全部代理不可达")
      else toast.success(down > 0 ? `测速完成：${r.results.length - down} 通 / ${down} 不通` : `测速完成：${r.results.length} 个代理全部可达`)
    } catch (e) {
      toast.error((e as Error).message)
    } finally {
      setBulkTesting(false)
    }
  }

  const toggle = async (node: ProxyNode, enabled: boolean) => {
    try {
      // 启停只改订阅可见性，不触发核心重启（设计文档 6.3）。
      await api(`/proxy/nodes/${node.id}`, { method: "PUT", body: JSON.stringify({ ...node, enabled }) })
      await reload()
    } catch (e) {
      toast.error((e as Error).message)
    }
  }

  const remove = async (node: ProxyNode) => {
    try {
      await api(`/proxy/nodes/${node.id}`, { method: "DELETE" })
      toast.success("代理已删除")
      await reload()
    } catch (e) {
      toast.error((e as Error).message)
    }
  }

  return (
    <Card className="flex flex-col gap-3 p-5">
      <div className="flex items-center justify-between">
        <div>
          <div className="text-sm font-semibold">配置代理</div>
          <div className="text-sm text-muted-foreground">
            新建代理，复制链接或扫码分享
          </div>
        </div>
        <div className="flex gap-2">
          <Button variant="outline" size="sm" disabled={bulkTesting} title="对所有启用的代理，从其所在主机请求测速目标 测出口延迟。" onClick={testAll}>
            <Activity className={`size-3.5 ${bulkTesting ? "animate-pulse" : ""}`} /> {bulkTesting ? "测速中…" : "测速"}
          </Button>
          <div className="relative">
            <Button variant="ghost" size="icon" title="测速目标" onClick={() => setProbeOpen(!probeOpen)}>
              <Globe className="size-4" />
            </Button>
            {probeOpen && (
              <>
                <div className="fixed inset-0 z-10" onClick={() => setProbeOpen(false)} />
                <div className="absolute right-0 top-9 z-20 w-80 rounded-md border bg-popover p-3 shadow-md">
                  <div className="text-sm font-medium">测速目标 URL</div>
                  <p className="mt-1 text-xs text-muted-foreground">
                    测速时从每台代理所在主机请求这个地址。
                  </p>
                  <Input
                    className="mt-2 font-mono text-xs"
                    placeholder="https://www.gstatic.com/generate_204"
                    value={probeDraft}
                    onChange={(e) => setProbeDraft(e.target.value)}
                  />
                  <div className="mt-2 flex flex-wrap gap-1">
                    {PROBE_PRESETS.map((p) => (
                      <button
                        key={p.label}
                        onClick={() => saveProbe(p.url)}
                        className={`rounded-md border px-1.5 py-0.5 text-[11px] transition-colors ${
                          probeDraft === p.url ? "border-foreground bg-secondary font-medium" : "text-muted-foreground hover:bg-muted"
                        }`}
                      >
                        {p.label}
                      </button>
                    ))}
                  </div>
                  <div className="mt-2.5 flex justify-end">
                    <Button size="sm" onClick={() => saveProbe(probeDraft.trim())}>
                      保存
                    </Button>
                  </div>
                </div>
              </>
            )}
          </div>
          <Button size="sm" onClick={() => { setEditing(null); setDialogOpen(true) }}>
            <Plus className="size-3.5" /> 新建代理
          </Button>
        </div>
      </div>
      <Table>
        <TableHeader>
          <TableRow>
            <TableHead>代理名称</TableHead>
            <TableHead>协议</TableHead>
            <TableHead>主机</TableHead>
            <TableHead>端口</TableHead>
            <TableHead>限速</TableHead>
            <TableHead>延迟</TableHead>
            <TableHead>启用</TableHead>
            <TableHead className="text-right">操作</TableHead>
          </TableRow>
        </TableHeader>
        <TableBody>
          {nodes.length === 0 && (
            <TableRow>
              <TableCell colSpan={8} className="py-8 text-center text-muted-foreground">
                还没有代理，点右上角「新建代理」开始。
              </TableCell>
            </TableRow>
          )}
          {nodes.map((node) => (
            <TableRow key={node.id}>
              <TableCell className="font-medium">{node.name}</TableCell>
              <TableCell>
                <span className={protocolChipClass(node.protocol)}>{PROTOCOL_LABEL[node.protocol] ?? node.protocol}</span>
              </TableCell>
              <TableCell>
                {(() => {
                  // 名字/在线与编辑弹窗「所在服务器」下拉同源（/api/nodes）
                  const srv = servers.find((s) => s.id === node.server_id)
                  const name = srv?.name ?? `服务器 ${node.server_id}`
                  const online = srv?.online ?? false
                  const ip = srv?.ip ?? ""
                  const chained = !!node.egress_type
                  const domain = node.dns_name || ""
                  const shownIp = chained ? node.egress_host : domain || ip
                  // 切换主机：域名指向不在原机时，标注当前承接流量的机器。
                  const pointed = domain && node.dns_server_id !== node.server_id
                    ? servers.find((s) => s.id === node.dns_server_id)?.name ?? `主机 ${node.dns_server_id}`
                    : null
                  return (
                    <div className="flex flex-col gap-0.5 text-xs">
                      <div className="flex items-center gap-1.5">
                        <span
                          className={`inline-block size-2 shrink-0 rounded-full ${online ? "bg-emerald-500" : "bg-zinc-400"}`}
                          title={online ? "在线" : "离线"}
                        />
                        <Tooltip disableHoverableContent>
                          <TooltipTrigger asChild>
                            <button
                              type="button"
                              onClick={() => {
                                if (ip) copy(ip, ` ${ip}`)
                              }}
                              aria-label={`复制主机 IP`}
                              className="truncate font-medium hover:text-foreground"
                            >
                              {node.server_id === 0 ? "hub 本机" : name}
                            </button>
                          </TooltipTrigger>
                          <TooltipContent side="right" sideOffset={6}>
                            <div className="tnum">{ip || "未知"}</div>
                            <div className="opacity-70">主机，点击复制</div>
                          </TooltipContent>
                        </Tooltip>
                        {node.server_id === 0 && (
                          <span className="shrink-0 rounded bg-primary/15 px-1 text-[10px] font-medium text-primary">主</span>
                        )}
                        <span className={`shrink-0 rounded px-1.5 py-px text-[11px] font-medium ${chained ? "bg-primary/15 text-primary" : "bg-emerald-500/15 text-emerald-600 dark:text-emerald-400"}`}>
                          {chained ? "链式" : "直连"}
                        </span>
                        {pointed && (
                          <span className="shrink-0 rounded bg-amber-500/15 px-1.5 py-px text-[11px] font-medium text-amber-600 dark:text-amber-400" title="域名解析当前指向的主机（切换主机）">
                            指向 {pointed}
                          </span>
                        )}
                      </div>
                      {(() => {
                        // 链式:复制 SOCKS5/HTTP 链式代理的 ip:端口:用户名:密码（可
                        // 直接粘进别的面板）；直连:复制首凭据分享链接（与二维码同源）。
                        const chainCopy = `${node.egress_host}:${node.egress_port}${node.egress_username ? `:${node.egress_username}:${node.egress_password}` : ""}`
                        const target = chained ? chainCopy : (node.users[0]?.link ?? "")
                        if (!target) return <div className="font-mono text-muted-foreground">{shownIp}</div>
                        const hint = chained ? "链式代理，点击复制" : "分享链接，点击复制"
                        return (
                          <Tooltip disableHoverableContent>
                            <TooltipTrigger asChild>
                              <button
                                type="button"
                                onClick={() => copy(target, chained ? "链式代理" : "分享链接")}
                                aria-label={`复制 ${hint}`}
                                className="tnum group inline-flex items-center gap-1 whitespace-nowrap font-mono text-muted-foreground hover:text-foreground"
                              >
                                {shownIp}
                                <Copy className="size-3 shrink-0 opacity-0 transition-opacity group-hover:opacity-100" />
                              </button>
                            </TooltipTrigger>
                            <TooltipContent side="right" sideOffset={6} className="max-w-xs">
                              <div className="tnum break-all">{target}</div>
                              <div className="opacity-70">{hint}</div>
                            </TooltipContent>
                          </Tooltip>
                        )
                      })()}
                    </div>
                  )
                })()}
              </TableCell>
              <TableCell className="font-mono">{node.listen_port}</TableCell>
              <TableCell className="text-xs">
                {node.rate_up > 0 || node.rate_down > 0 ? (
                  <span className="font-mono">
                    {node.rate_up > 0 && <span className="text-up">↑{node.rate_up}</span>}
                    {node.rate_up > 0 && node.rate_down > 0 && " / "}
                    {node.rate_down > 0 && <span className="text-primary">↓{node.rate_down}</span>}
                    <span className="ml-1 text-muted-foreground">Mbps</span>
                  </span>
                ) : (
                  <span className="text-muted-foreground">不限</span>
                )}
              </TableCell>
              <TableCell className="text-xs">{latency[node.id] ? <LatencyText r={latency[node.id]} /> : ""}</TableCell>
              <TableCell>
                <Switch checked={node.enabled} onCheckedChange={(v) => toggle(node, v)} />
              </TableCell>
              <TableCell className="text-right">
                <div className="flex justify-end gap-1">
                  {node.users[0] && (
                    <Button variant="ghost" size="sm" onClick={() => setQrNode({ name: node.name, url: node.users[0].link })}>
                      <QrCode className="size-3.5" /> 二维码
                    </Button>
                  )}
                  <Button variant="ghost" size="sm" onClick={() => { setEditing(node); setDialogOpen(true) }}>
                    <Pencil className="size-3.5" /> 编辑
                  </Button>
                  <Button
                    variant="ghost"
                    size="sm"
                    disabled={!node.dns_name}
                    title={node.dns_name ? "IP 被墙时把域名解析切到另一台主机，参数与链接不变" : "先在编辑中绑定域名，才能切换主机"}
                    onClick={() => setSwitching(node)}
                  >
                    <ArrowLeftRight className="size-3.5" /> 切换
                  </Button>
                  <Button variant="ghost" size="sm" disabled={testing === node.id || bulkTesting} onClick={() => test(node)}>
                    <Activity className={`size-3.5 ${testing === node.id ? "animate-pulse" : ""}`} /> {testing === node.id ? "测试中…" : "测试"}
                  </Button>
                  <Button
                    variant={armed === node.id ? "destructive" : "ghost"}
                    size="sm"
                    title={armed === node.id ? "再点一次确认删除" : "删除代理"}
                    onClick={() => (armed === node.id ? remove(node) : arm(node.id))}
                  >
                    <Trash2 className="size-3.5" /> {armed === node.id ? "确认" : "删除"}
                  </Button>
                </div>
              </TableCell>
            </TableRow>
          ))}
        </TableBody>
      </Table>
      <NodeDialog open={dialogOpen} initial={editing} servers={servers} onOpenChange={setDialogOpen} reload={reload} />
      <SwitchDialog open={!!switching} node={switching} servers={servers} onOpenChange={() => setSwitching(null)} reload={reload} />
      {qrNode && <QrDialog url={qrNode.url} name={qrNode.name} kind="node" onOpenChange={() => setQrNode(null)} />}
    </Card>
  )
}

// The 协议 page: nodes（设计文档 12）；realm 核心与中转规则在隧道页。
export default function Proxy(_props: { nodes?: Node[] }) {
  const { servers, nodes: proxyNodes, cores, reload } = useProxyData()
  // 版本过旧黄条（二期）：只列 hub 已见过版本的机器；连接计量依赖
  // api service（sing-box ≥1.14），过旧的机器计量会失效。
  const stale = cores.filter((c) => c.stale)
  const staleNames = stale
    .map((c) =>
      c.server_id === 0
        ? (servers.find((s) => s.local)?.name ?? "hub 本机")
        : (servers.find((s) => s.id === c.server_id)?.name ?? `服务器 ${c.server_id}`),
    )
    .join("、")
  return (
    <div className="flex flex-col gap-6">
      {stale.length > 0 && (
        <div className="rounded-md border border-warn/40 bg-warn/10 px-3 py-2.5 text-sm text-warn">
          {staleNames} 的 sing-box {stale.map((c) => `v${c.version}`).join("、")} 版本过旧（需 ≥ 1.14）：连接计量依赖 api
          service，可能失效，请在对应机器重装或切换核心
        </div>
      )}
      <NodesCard nodes={proxyNodes} servers={servers} reload={reload} />
    </div>
  )
}
