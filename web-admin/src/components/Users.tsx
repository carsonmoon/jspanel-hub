import { useCallback, useEffect, useState } from "react"
import { CalendarCheck, ChevronDown, Clock, Copy, Download, ExternalLink, Pencil, Plus, QrCode, Trash2, UserPlus } from "lucide-react"
import { toast } from "sonner"
import * as XLSX from "xlsx"

import { ConfirmDialog } from "./Admin"
import { copy, QrDialog } from "@/components/QrDialog"
import { Tooltip, TooltipContent, TooltipTrigger } from "@/components/ui/tooltip"
import { copyText } from "@/lib/utils"
import { Button } from "@/components/ui/button"
import { StatusBadge } from "@/components/ui/status-badge"
import { PageHeader } from "@/components/page-header"
import { Card } from "@/components/ui/card"
import { Dialog, DialogContent, DialogFooter, DialogHeader, DialogTitle } from "@/components/ui/dialog"
import { Input } from "@/components/ui/input"
import { Label } from "@/components/ui/label"
import { Switch } from "@/components/ui/switch"
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table"
import { api, type ConvProfile } from "@/lib/api"
import { bytes, FOREVER } from "@/lib/format"
import type { ProxyNode, ProxyUser, SubUser } from "@/components/Proxy"

// 凭据行：名字+UUID 前缀悬停出分享链接气泡点击复制；限额与重置按需显示。
/// 凭据「重置」的原位确认（armed）：3 秒窗口，与全站删除确认同语法。
function CredentialResetButton({ onReset }: { onReset: () => void }) {
  const [armed, setArmed] = useState(false)
  return (
    <Button
      variant={armed ? "destructive" : "ghost"}
      size="sm"
      className="h-7 px-2 text-xs"
      aria-live="polite"
      title={armed ? "再点一次确认重置" : "轮换此凭据的值（使用它的设备需重新拉取订阅）"}
      onClick={() => {
        if (armed) {
          setArmed(false)
          onReset()
        } else {
          setArmed(true)
          setTimeout(() => setArmed(false), 3000)
        }
      }}
    >
      {armed ? "确认重置" : "重置"}
    </Button>
  )
}

function CredentialRow({
  u, onLimit, onReset, actions,
}: {
  u: { id: number; name: string; credential: string; link: string }
  onLimit?: () => void
  onReset?: () => void
  actions?: React.ReactNode
}) {
  // 自动创建的凭据名是「用户名·协议名」，显示时只取用户名段（复制仍是完整凭据）。
  const displayName = u.name.includes("·") ? u.name.split("·")[0] : u.name
  return (
    <div className="flex items-center justify-between gap-2 rounded-md border px-3 py-1.5 text-sm">
      <Tooltip disableHoverableContent>
        <TooltipTrigger asChild>
          <button
            type="button"
            onClick={() => copy(u.link, "分享链接")}
            aria-label={`复制 ${u.name} 的分享链接`}
            className="tnum group inline-flex items-start gap-1 text-left font-mono text-xs text-muted-foreground hover:text-foreground"
          >
            <span className="break-all">{displayName} · {u.credential}</span>
            <Copy className="size-3 shrink-0 opacity-0 transition-opacity group-hover:opacity-100" />
          </button>
        </TooltipTrigger>
        <TooltipContent side="right" sideOffset={6} className="max-w-xs">
          <div className="tnum break-all">{u.link}</div>
          <div className="opacity-70">分享链接，点击复制</div>
        </TooltipContent>
      </Tooltip>
      <div className="flex shrink-0 items-center gap-1">
        {onLimit && (
          <Button variant="ghost" size="sm" className="h-7 px-2 text-xs" title="为此凭据单独设置 到期日期与流量配额" onClick={onLimit}>
            限额
          </Button>
        )}
        {onReset && <CredentialResetButton onReset={onReset} />}
        {actions}
      </div>
    </div>
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

function AssignDialog({ sub, subs, nodes, onOpenChange, reload }: { sub: SubUser; subs: SubUser[]; nodes: ProxyNode[]; onOpenChange: (v: boolean) => void; reload: () => Promise<void> }) {
  const [busy, setBusy] = useState<number | null>(null)
  // 凭据「重置」的原位确认（armed）：key = 凭据 id，3 秒窗口自动解除。
  const [armedReset, setArmedReset] = useState<number | null>(null)
  const [limitsFor, setLimitsFor] = useState<number | null>(null)
  const [query, setQuery] = useState("")
  const subName = (id: number | null) => (id == null ? "" : subs.find((s) => s.id === id)?.name ?? "?")

  // 即时过滤：协议名/端口/任一凭据名命中即整行显示
  const q = query.trim().toLowerCase()
  const filtered = nodes.filter(
    (node) =>
      !q ||
      node.name.toLowerCase().includes(q) ||
      String(node.listen_port).includes(q) ||
      node.users.some((u) => u.name.toLowerCase().includes(q)),
  )

  // 协议级分配：开关即分配/取消，凭据由后端幂等创建与删除（断服语义在取消侧）
  const assign = async (node: ProxyNode, on: boolean) => {
    setBusy(node.id)
    try {
      await api(`/proxy/sub-users/${sub.id}/nodes/${node.id}/assign`, { method: "PUT", body: JSON.stringify({ on }) })
      toast.success(on ? "已分配" : "已取消分配")
      await reload()
    } catch (e) {
      toast.error((e as Error).message)
    } finally {
      setBusy(null)
    }
  }

  // 单凭据轮换（管理端）：原行原名换新值，用它的设备重新拉订阅即恢复
  const rotate = async (nodeId: number, uid: number) => {
    setBusy(uid)
    try {
      await api(`/proxy/nodes/${nodeId}/users/${uid}/rotate`, { method: "PUT" })
      toast.success("凭据已轮换")
      await reload()
    } catch (e) {
      toast.error((e as Error).message)
    } finally {
      setBusy(null)
    }
  }

  // 凭据级限额（方向 40）：到期日期 + 流量配额 GB（留空=不启用）。
  const saveLimits = async (uid: number, expires: string, quotaGb: string) => {
    setBusy(uid)
    try {
      await api(`/proxy/users/${uid}/limits`, {
        method: "PUT",
        body: JSON.stringify({ expires_at: expires || null, quota_bytes: quotaGb ? Math.round(Number(quotaGb) * 1024 ** 3) : 0 }),
      })
      toast.success("凭据限额已保存")
      await reload()
    } catch (e) {
      toast.error((e as Error).message)
    } finally {
      setBusy(null)
    }
  }

  return (
    <Dialog open onOpenChange={onOpenChange}>
      <DialogContent className="max-w-md">
        <DialogHeader>
          <DialogTitle>把代理分配给 {sub.name}</DialogTitle>
        </DialogHeader>
        <Input
          value={query}
          onChange={(e) => setQuery(e.target.value)}
          placeholder="搜索代理名称、端口或凭据…"
          autoFocus
        />
        <div className="flex max-h-80 flex-col gap-3 overflow-y-auto">
          {filtered.map((node) => {
            const bound = node.users.filter((u) => u.sub_user_id === sub.id)
            const others = node.users.filter((u) => u.sub_user_id != null && u.sub_user_id !== sub.id)
            const on = bound.length > 0
            const single = bound.length <= 1
            return (
              <div key={node.id} className="flex flex-col gap-1.5">
                <div className="flex items-center justify-between gap-2">
                  <div className="min-w-0">
                    <div className="text-sm font-medium">
                      {node.name} <span className="font-mono text-xs text-muted-foreground">:{node.listen_port}</span>
                    </div>
                    {others.length > 0 && (
                      <div className="text-xs text-muted-foreground">另有 {others.map((u) => subName(u.sub_user_id)).join("、")}</div>
                    )}
                  </div>
                  <div className="flex shrink-0 items-center gap-2">
                    {on && single && (
                      <>
                        <Button
                          variant="ghost"
                          size="sm"
                          className="h-7 px-2 text-xs"
                          title="为此凭据单独设置 到期日期与流量配额"
                          onClick={() => setLimitsFor(limitsFor === bound[0].id ? null : bound[0].id)}
                        >
                          限额
                        </Button>
                        <Button
                          variant={armedReset === bound[0].id ? "destructive" : "ghost"}
                          size="sm"
                          className="h-7 px-2 text-xs"
                          aria-live="polite"
                          title={armedReset === bound[0].id ? "再点一次确认重置" : "轮换此凭据的值（使用它的设备需重新拉取订阅）"}
                          disabled={busy === node.id}
                          onClick={() => {
                            if (armedReset === bound[0].id) {
                              setArmedReset(null)
                              rotate(node.id, bound[0].id)
                            } else {
                              setArmedReset(bound[0].id)
                              setTimeout(() => setArmedReset((a) => (a === bound[0].id ? null : a)), 3000)
                            }
                          }}
                        >
                          {armedReset === bound[0].id ? "确认重置" : "重置"}
                        </Button>
                      </>
                    )}
                    <Switch checked={on} disabled={busy === node.id} onCheckedChange={(v) => assign(node, v)} aria-label={`把 ${node.name} 的代理分配给该客户`} />
                  </div>
                </div>
                {on && single && limitsFor === bound[0]?.id && bound[0] && (
                  <CredentialLimits uid={bound[0].id} user={bound[0]} onSave={(uid, expires, quotaGb) => saveLimits(uid, expires, quotaGb)} />
                )}
                {on && bound.map((u) => (
                  <CredentialRow
                    key={u.id}
                    u={u}
                    onLimit={single ? undefined : () => setLimitsFor(limitsFor === u.id ? null : u.id)}
                    onReset={
                      single
                        ? undefined
                        : () => {
                            if (confirm(`重置凭据 ${u.name}？正在使用它的设备需重新拉取订阅。`)) rotate(node.id, u.id)
                          }
                    }
                  />
                ))}
              </div>
            )
          })}
          {nodes.length === 0 && <div className="text-sm text-muted-foreground">先创建代理，再来分配。</div>}
          {nodes.length > 0 && filtered.length === 0 && (
            <div className="py-4 text-center text-sm text-muted-foreground">没有匹配的代理或凭据。</div>
          )}
        </div>
      </DialogContent>
    </Dialog>
  )
}

const SUB_STATUS_TONE: Record<string, "ok" | "off" | "danger"> = {
  正常: "ok",
  已停用: "off",
  已到期: "danger",
  流量超额: "danger",
}

function QuotaBar({ sub }: { sub: SubUser }) {
  if (!sub.quota_bytes) return <span className="text-xs text-muted-foreground">不限</span>
  const used = sub.quota_used_up + sub.quota_used_down
  const pct = Math.min(100, Math.round((used / sub.quota_bytes) * 100))
  const over = used >= sub.quota_bytes
  return (
    <div className="flex w-[220px] max-w-full flex-col gap-1">
      <div className="h-1.5 w-full overflow-hidden rounded-full bg-muted">
        <div
          className={`h-full rounded-full ${over ? "bg-destructive" : pct > 80 ? "bg-warn" : "bg-primary"}`}
          style={{ width: `${pct}%` }}
        />
      </div>
      {/* 单行完整显示（不 truncate）：已用量加粗，每月重置缀在行尾 */}
      <div className="whitespace-nowrap text-xs">
        <span className="font-medium">{bytes(used)}</span>
        <span className="text-muted-foreground"> / {bytes(sub.quota_bytes)}</span>
        <span className={over ? "text-destructive" : "text-muted-foreground"}>（{pct}%）</span>
        {sub.quota_reset === "monthly" && <span className="text-muted-foreground"> · 每月重置</span>}
      </div>
    </div>
  )
}


/// 凭据级限额编辑（方向 40）：到期日期 + 流量配额 GB（留空=不启用该凭据级限制）。
/// 输入框始终显示真实已存值（空=跟随客户/不限）；「预设」一键填入常规套路
/// （到期=今天+1 个自然月、流量 500GB），预设只是填表，保存才生效。
function CredentialLimits({ uid, user, onSave }: { uid: number; user: ProxyUser; onSave: (uid: number, expires: string, quotaGb: string) => Promise<void> }) {
  const [expires, setExpires] = useState(user.expires_at ?? "")
  const [quotaGb, setQuotaGb] = useState(user.quota_bytes ? String(Math.round(user.quota_bytes / 1024 ** 3)) : "")
  const [busy, setBusy] = useState(false)
  const d = new Date()
  d.setMonth(d.getMonth() + 1)
  const pad = (n: number) => String(n).padStart(2, "0")
  const presetExpires = `${d.getFullYear()}-${pad(d.getMonth() + 1)}-${pad(d.getDate())}`

  return (
    <div className="flex flex-col gap-1.5 rounded-md bg-muted/40 p-2.5">
      <div className="grid grid-cols-2 gap-2">
        <div className="flex flex-col gap-1">
          <Label className="text-[11px] text-muted-foreground">到期日期（留空跟随客户）</Label>
          <Input type="date" className="h-8 text-xs" value={expires} onChange={(e) => setExpires(e.target.value)} />
        </div>
        <div className="flex flex-col gap-1">
          <Label className="text-[11px] text-muted-foreground">流量配额 GB（0/留空=不限）</Label>
          <Input type="number" min={0} className="h-8 text-xs" value={quotaGb} onChange={(e) => setQuotaGb(e.target.value)} placeholder="例如 50" />
        </div>
      </div>
      <div className="flex items-center justify-between gap-2">
        <span className="text-[11px] text-muted-foreground">预设：{presetExpires} · 500GB</span>
        <Button
          variant="ghost"
          size="sm"
          className="h-6 text-xs"
          onClick={() => {
            setExpires(presetExpires)
            setQuotaGb("500")
          }}
        >
          预设
        </Button>
      </div>
      <div className="flex justify-end">
        <Button
          size="sm"
          className="h-7 text-xs"
          disabled={busy}
          onClick={() => {
            setBusy(true)
            onSave(uid, expires, quotaGb).finally(() => setBusy(false))
          }}
        >
          保存限额
        </Button>
      </div>
    </div>
  )
}

function SubEditDialog({
  sub,
  planOptions,
  onOpenChange,
  reload,
}: {
  sub: SubUser
  planOptions: { label: string; value: string }[]
  onOpenChange: (v: boolean) => void
  reload: () => Promise<void>
}) {
  const [name, setName] = useState(sub.name)
  const [profileId, setProfileId] = useState(sub.profile_id != null ? String(sub.profile_id) : "")
  const [viewMode, setViewMode] = useState(sub.view_mode ?? "overview")
  const [enabled, setEnabled] = useState(sub.enabled)
  // 管理员重置是全站后果最重的操作之一：升格为模态确认（armed 不够醒目）。
  const [confirmAdminReset, setConfirmAdminReset] = useState(false)
  const [expires, setExpires] = useState(sub.expires_at ?? "")
  const [quota, setQuota] = useState(sub.quota_bytes ? String(Math.round(sub.quota_bytes / 1024 ** 3)) : "")
  const [monthly, setMonthly] = useState(sub.quota_reset === "monthly")
  const [allowReset, setAllowReset] = useState(sub.allow_self_reset ?? false)
  const [resetLimit, setResetLimit] = useState(String(sub.reset_limit ?? 3))
  const [busy, setBusy] = useState(false)

  const save = async () => {
    setBusy(true)
    try {
      const gb = Number(quota)
      await api(`/proxy/sub-users/${sub.id}`, {
        method: "PUT",
        body: JSON.stringify({
          name: name.trim(),
          enabled,
          // 备注 UI 已移除（无处展示的伪功能），保存时原样透传既有值，不丢数据
          remark: sub.remark,
          // 后端 PUT 是全量更新：漏带此键会把到期日清成 NULL（ ∞）
          expires_at: expires || null,
          quota_bytes: quota && gb > 0 ? Math.round(gb * 1024 ** 3) : 0,
          quota_reset: monthly ? "monthly" : "",
          profile_id: profileId ? Number(profileId) : null,
          view_mode: viewMode,
        }),
      })
      await api(`/proxy/sub-users/${sub.id}/self-reset`, {
        method: "PUT",
        body: JSON.stringify({ allow: allowReset, limit: Number(resetLimit) || 0 }),
      })
      toast.success("用户已保存")
      onOpenChange(false)
      await reload()
    } catch (e) {
      toast.error((e as Error).message)
    } finally {
      setBusy(false)
    }
  }

  // 管理端重置（不占客户自助次数）：凭据+订阅链接整体换新，新 /u/ 链接复制到剪贴板
  const adminReset = async () => {
    setBusy(true)
    try {
      const r = await api<{ token: string }>(`/proxy/sub-users/${sub.id}/admin-reset`, { method: "POST" })
      copyText(`${location.origin}/u/${r.token}`, "已复制新的用户中心链接")
      toast.success("已重置，新的用户中心链接已复制")
      onOpenChange(false)
      await reload()
    } catch (e) {
      toast.error((e as Error).message)
    } finally {
      setBusy(false)
    }
  }

  return (
    <Dialog open onOpenChange={onOpenChange}>
      <DialogContent className="max-w-sm">
        <DialogHeader>
          <DialogTitle>编辑用户</DialogTitle>
        </DialogHeader>
        <div className="flex flex-col gap-3">
          <div className="flex flex-col gap-1.5">
            <Label>用户名称</Label>
            <Input value={name} onChange={(e) => setName(e.target.value)} />
          </div>
          <div className="flex flex-col gap-1.5">
            <Label>配置选择</Label>
            <select
              className="h-9 w-full rounded-md border bg-transparent px-2 text-sm"
              value={profileId}
              onChange={(e) => setProfileId(e.target.value)}
            >
              {planOptions.map((o) => (
                <option key={o.value} value={o.value}>{o.label}</option>
              ))}
            </select>
          </div>
          <div className="flex items-center justify-between">
            <Label>启用</Label>
            <Switch checked={enabled} onCheckedChange={setEnabled} aria-label="启用该客户" />
          </div>
          <div className="flex flex-col gap-1.5">
            <Label>到期日期（留空不限）</Label>
            <Input type="date" value={expires} onChange={(e) => setExpires(e.target.value)} />
          </div>
          <div className="flex flex-col gap-1.5">
            <Label>流量配额 GB（0 或留空不限）</Label>
            <Input
              type="number"
              min={0}
              value={quota}
              onChange={(e) => setQuota(e.target.value)}
              placeholder="例如 100"
            />
          </div>
          <div className="flex items-center justify-between">
            <div>
              <Label>每月重置</Label>
              <p className="text-xs text-muted-foreground">开：每个自然月清零重计；关：一次性总量。</p>
            </div>
            <Switch checked={monthly} onCheckedChange={setMonthly} disabled={!quota || !Number(quota)} aria-label="每月重置" />
          </div>
          <div className="flex flex-col gap-1.5">
            <Label>用户中心视图</Label>
            <select
              className="h-9 w-full rounded-md border bg-transparent px-2 text-sm"
              value={viewMode}
              onChange={(e) => setViewMode(e.target.value)}
            >
              <option value="overview">订阅配额</option>
              <option value="per_node">代理配额</option>
            </select>
          </div>
          <div className="flex flex-col gap-2 rounded-md border p-3">
            <div className="flex items-center justify-between">
              <div>
                <Label>允许客户自助重置</Label>
                <p className="text-xs text-muted-foreground">
                  /u/ 页显示重置入口：凭据与订阅链接整体换新，所有设备需重新导入。
                </p>
              </div>
              <Switch checked={allowReset} onCheckedChange={setAllowReset} aria-label="允许客户自助重置" />
            </div>
            {allowReset && (
              <div className="flex items-center justify-between">
                <Label className="text-xs text-muted-foreground">次数上限</Label>
                <Input
                  type="number"
                  min={0}
                  className="h-8 w-24 text-xs"
                  value={resetLimit}
                  onChange={(e) => setResetLimit(e.target.value)}
                />
              </div>
            )}
            {(sub.reset_count ?? 0) > 0 && (
              <p className="text-xs text-muted-foreground">
                已自助重置 {sub.reset_count} 次
                {(sub.last_reset_at ?? 0) > 0 &&
                  `，上次 ${new Date((sub.last_reset_at ?? 0) * 1000).toLocaleDateString("zh-CN")}`}
                。
              </p>
            )}
            <Button variant="outline" size="sm" className="w-full" disabled={busy} onClick={() => setConfirmAdminReset(true)}>
              重置订阅与凭据（管理员）
            </Button>
          </div>

        </div>
        {confirmAdminReset && (
          <ConfirmDialog
            title={`重置 ${sub.name} 的订阅与凭据？`}
            description="所有设备需重新导入，旧链接立即失效。重置只换身份，代理 IP 与端口不变；重置后 /u/ 页地址会变，请把新地址发给客户。"
            confirmLabel="确认重置"
            busy={busy}
            onClose={() => setConfirmAdminReset(false)}
            onConfirm={() => {
              setConfirmAdminReset(false)
              adminReset()
            }}
          />
        )}
        <DialogFooter>
          <Button disabled={busy || !name.trim()} onClick={save}>
            保存
          </Button>
        </DialogFooter>
      </DialogContent>
    </Dialog>
  )
}

// 订阅入口（M8）：来自设置页的 sub_hosts，每行一个 host[:port] 或带 scheme。
// 面板据它给每个客户列出多条订阅链接；空设置回落面板自身地址。
function frontUrl(line: string): string {
  const m = /^(https?):\/\/(.*)$/.exec(line)
  return `${m ? m[1] : "https"}://${m ? m[2] : line.trim()}/api/sub`
}

function useSubUrls(): string[] {
  const [urls, setUrls] = useState<string[]>([])
  useEffect(() => {
    api<{ sub_hosts?: string }>("/settings")
      .then((s) => {
        const lines = String(s.sub_hosts ?? "")
          .split("\n")
          .map((l) => l.trim())
          .filter(Boolean)
        setUrls(lines.length ? lines.map(frontUrl) : [`${location.origin}/api/sub`])
      })
      .catch(() => setUrls([`${location.origin}/api/sub`]))
  }, [])
  return urls
}

function SubsCard({ subs, nodes, reload }: { subs: SubUser[]; nodes: ProxyNode[]; reload: () => Promise<void> }) {
  const [createOpen, setCreateOpen] = useState(false)
  const [name, setName] = useState("")
  const [createPlan, setCreatePlan] = useState("")
  const [createExpires, setCreateExpires] = useState("")
  const [createQuota, setCreateQuota] = useState("")
  const [expiryOpen, setExpiryOpen] = useState(false)
  const [renewCred, setRenewCred] = useState<ProxyUser | null>(null)

  // 凭据续期（grilling 五期）：当前到期 +1 个自然月（月末钳制，同客户续期口径）。
  // 走 limits 接口保存，本期限额计数随之归零=新周期开始。
  const renewCredTo = (u: ProxyUser) => {
    const base = u.expires_at ? new Date(`${u.expires_at}T00:00:00`) : new Date()
    const day = base.getDate()
    base.setMonth(base.getMonth() + 1)
    if (base.getDate() !== day) base.setDate(0)
    const pad = (n: number) => String(n).padStart(2, "0")
    return `${base.getFullYear()}-${pad(base.getMonth() + 1)}-${pad(base.getDate())}`
  }
  const doRenewCred = async (u: ProxyUser) => {
    const next = renewCredTo(u)
    try {
      await api(`/proxy/users/${u.id}/limits`, {
        method: "PUT",
        body: JSON.stringify({ expires_at: next, quota_bytes: u.quota_bytes }),
      })
      toast.success(`已续期至 ${next}`)
      setRenewCred(null)
      await reload()
    } catch (e) {
      toast.error((e as Error).message)
    }
  }

  // 打开新建弹窗：到期=今天+1 个月，流量默认 1024GB（用户拍板的默认值）
  const openCreate = () => {
    const d = new Date()
    d.setMonth(d.getMonth() + 1)
    const pad = (n: number) => String(n).padStart(2, "0")
    setCreateExpires(`${d.getFullYear()}-${pad(d.getMonth() + 1)}-${pad(d.getDate())}`)
    setCreateQuota("1024")
    setCreateOpen(true)
  }

  // 到期一览与导出（grilling 四/五期）同源：一行 = 一条分配（客户×代理），按
  // 凭据到期升序（未填压底）。剩余 ≤3 天（含已过期）到期日标红提醒。
  const assignments = subs
    .flatMap((sub) =>
      nodes.flatMap((node) =>
        node.users
          .filter((u) => u.sub_user_id === sub.id)
          .map((u) => ({ sub, node, u })),
      ),
    )
    .sort((a, b) => (a.u.expires_at ?? "9999-12-31").localeCompare(b.u.expires_at ?? "9999-12-31"))
  const gb = (b: number) => Number((b / 1024 ** 3).toFixed(2))
  const in3 = new Date()
  in3.setDate(in3.getDate() + 3)
  const soon = (exp: string | null | undefined) =>
    !!exp && exp <= `${in3.getFullYear()}-${String(in3.getMonth() + 1).padStart(2, "0")}-${String(in3.getDate()).padStart(2, "0")}`
  const assignedAt = (ts?: number) => (ts ? new Date(ts * 1000).toLocaleString("sv-SE") : "未知")

  const exportExcel = () => {
    const rows = assignments.map(({ sub, node, u }) => {
      const dial = u.link.match(/@([^@?/]+):(\d+)/)
      const outlet = node.egress_type
        ? `${node.egress_host}:${node.egress_port}:${node.egress_username}:${node.egress_password}`
        : dial
          ? `${dial[1]}:${dial[2]}`
          : ""
      return [
        sub.name,
        node.name,
        assignedAt(u.created_at),
        u.expires_at ?? "",
        gb((u.quota_used_up ?? 0) + (u.quota_used_down ?? 0)),
        u.quota_bytes ? gb(u.quota_bytes) : "",
        outlet,
        u.link,
      ]
    })
    const ws = XLSX.utils.aoa_to_sheet([
      ["客户", "代理名称", "分配时间", "凭据到期", "本期已用 (GB)", "配额 (GB)", "出口", "分享链接"],
      ...rows,
    ])
    ws["!cols"] = [{ wch: 12 }, { wch: 18 }, { wch: 20 }, { wch: 12 }, { wch: 12 }, { wch: 10 }, { wch: 44 }, { wch: 70 }]
    const wb = XLSX.utils.book_new()
    XLSX.utils.book_append_sheet(wb, ws, "用户记录")
    const d = new Date()
    const pad = (n: number) => String(n).padStart(2, "0")
    XLSX.writeFile(wb, `用户记录-${d.getFullYear()}-${pad(d.getMonth() + 1)}-${pad(d.getDate())}.xlsx`)
  }
  const [busy, setBusy] = useState(false)
  const [qr, setQr] = useState<{ sub: SubUser } | null>(null)
  const [menuOpen, setMenuOpen] = useState(false)
  const [renewFor, setRenewFor] = useState<SubUser | null>(null)
  const [assign, setAssign] = useState<SubUser | null>(null)
  const [edit, setEdit] = useState<SubUser | null>(null)
  const [plans, setPlans] = useState<ConvProfile[]>([])
  const [distAgents, setDistAgents] = useState<{ node_id: number; name: string; host: string; port: number }[]>([])
  const { armed, arm } = useConfirmDelete()
  const fronts = useSubUrls()

  useEffect(() => {
    api<{ profiles: ConvProfile[] }>("/conv/profiles").then((r) => setPlans(r.profiles.filter((p) => !p.static_content))).catch(() => {})
    api<{ agents: { node_id: number; name: string; host: string; port: number }[] }>("/conv/dist-agents").then((r) => setDistAgents(r.agents)).catch(() => {})
  }, [])

  // 客户订阅链接带 #客户名 片段（客户端命名约定）；t 为客户端格式（?t=v2rayng）。
  const custUrl = (sub: SubUser, front: string, t?: "v2rayng") => {
    const base = t ? `${front}?token=${sub.token}&t=${t}` : `${front}?token=${sub.token}`
    return `${base}#${encodeURIComponent(sub.name)}`
  }
  const planOptions = [
    { label: "仅代理", value: "" as const },
    ...plans.map((p) => ({ label: p.name, value: String(p.id) })),
  ]
  const setAgentDist = async (sub: SubUser, on: boolean) => {
    try {
      await api(`/proxy/sub-users/${sub.id}/agent-dist`, { method: "PUT", body: JSON.stringify({ on }) })
      toast.success(on ? "agent 分发已开启" : "agent 分发已关闭")
      await reload()
    } catch (e) {
      toast.error((e as Error).message)
    }
  }
  const toggleUserPage = async (sub: SubUser, on: boolean) => {
    try {
      await api(`/proxy/sub-users/${sub.id}/user-page`, { method: "PUT", body: JSON.stringify({ on }) })
      toast.success(on ? "用户页已开启" : "用户页已关闭")
      await reload()
    } catch (e) {
      toast.error((e as Error).message)
    }
  }
  const copyUserPage = (sub: SubUser) => {
    const url = `${location.origin}/u/${sub.token}`
    copy(url, "用户页链接")
    // 复制的同时新窗口打开，直接看到客户的公开页效果
    window.open(url, "_blank", "noopener")
  }

  // 续期：从当前到期时间往后推一个月（后端同款口径，含月末钳制）
  const nextMonth = (dateStr: string) => {
    const [y, m, d] = dateStr.split("-").map(Number)
    const ny = m === 12 ? y + 1 : y
    const nm = m === 12 ? 1 : m + 1
    const last = new Date(ny, nm, 0).getDate()
    return `${ny}-${String(nm).padStart(2, "0")}-${String(Math.min(d, last)).padStart(2, "0")}`
  }
  const renew = async (sub: SubUser) => {
    try {
      const r = await api<{ expires_at: string }>(`/proxy/sub-users/${sub.id}/renew`, { method: "POST" })
      toast.success(`已续期至 ${r.expires_at}`)
      await reload()
    } catch (e) {
      toast.error((e as Error).message)
    }
  }

  const create = async () => {
    setBusy(true)
    try {
      await api("/proxy/sub-users", {
        method: "POST",
        body: JSON.stringify({
          name: name.trim(),
          profile_id: createPlan ? Number(createPlan) : null,
          expires_at: createExpires || null,
          quota_bytes: createQuota && Number(createQuota) > 0 ? Math.round(Number(createQuota) * 1024 ** 3) : 0,
        }),
      })
      toast.success("用户已创建，分配代理后即可在二维码处扫码交付")
      setName("")
      setCreatePlan("")
      setCreateOpen(false)
      await reload()
    } catch (e) {
      toast.error((e as Error).message)
    } finally {
      setBusy(false)
    }
  }

  const remove = async (sub: SubUser) => {
    try {
      await api(`/proxy/sub-users/${sub.id}`, { method: "DELETE" })
      toast.success("用户已删除")
      await reload()
    } catch (e) {
      toast.error((e as Error).message)
    }
  }

  return (
    <div className="flex flex-col gap-6">
      <PageHeader
        title="用户"
        actions={
          <>
            <Button variant="outline" size="sm" onClick={() => setExpiryOpen(true)}>
              <Clock className="size-3.5" /> 到期一览
            </Button>
            <Button variant="outline" size="sm" onClick={exportExcel} disabled={subs.length === 0}>
              <Download className="size-3.5" /> 导出 Excel
            </Button>
            <Button size="sm" onClick={openCreate}>
              <Plus className="size-3.5" /> 新建用户
            </Button>
          </>
        }
      />
      <Card className="flex flex-col gap-4 p-5">
      <Table>
        <TableHeader>
          <TableRow>
            <TableHead className="w-[16%]">用户</TableHead>
            <TableHead className="w-[12%]">状态</TableHead>
            <TableHead className="w-[34%]">流量</TableHead>
            <TableHead className="w-[16%]">到期</TableHead>
            <TableHead className="text-right">操作</TableHead>
          </TableRow>
        </TableHeader>
        <TableBody>
          {subs.length === 0 && (
            <TableRow>
              <TableCell colSpan={5} className="py-8 text-center text-muted-foreground">
                还没有用户。
              </TableCell>
            </TableRow>
          )}
          {subs.map((sub) => (
            <TableRow key={sub.id}>
              <TableCell className="font-medium">{sub.name}</TableCell>
              <TableCell>
                <StatusBadge tone={SUB_STATUS_TONE[sub.status] ?? "off"}>{sub.status}</StatusBadge>
              </TableCell>
              <TableCell>
                <QuotaBar sub={sub} />
              </TableCell>
              <TableCell className="text-sm text-muted-foreground">{sub.expires_at || FOREVER}</TableCell>

              <TableCell className="text-right">
                <div className="flex items-center justify-end gap-0.5">
                  <Switch checked={sub.user_page} onCheckedChange={(v) => toggleUserPage(sub, v)} aria-label={`开关 ${sub.name} 的用户页`} />
                  <Button variant="ghost" size="sm" title="打开用户中心页" onClick={() => copyUserPage(sub)}>
                    <ExternalLink className="size-3.5" /> 用户页
                  </Button>
                  <Button variant="ghost" size="sm" title="订阅二维码与复制" onClick={() => { setQr({ sub }); setMenuOpen(false) }}>
                    <QrCode className="size-3.5" /> 二维码
                  </Button>
                  <Button
                    variant="ghost"
                    size="sm"
                    disabled={!sub.expires_at}
                    title={sub.expires_at ? "到期时间往后推一个月" : "未设置到期时间，无法续期"}
                    onClick={() => setRenewFor(sub)}
                  >
                    <CalendarCheck className="size-3.5" /> 续期
                  </Button>
                  <Button variant="ghost" size="sm" title="编辑用户" onClick={() => setEdit(sub)}>
                    <Pencil className="size-3.5" /> 编辑
                  </Button>
                  <Button variant="ghost" size="sm" title="分配代理" onClick={() => setAssign(sub)}>
                    <UserPlus className="size-3.5" /> 分配代理
                  </Button>
                  <Button
                    variant={armed === sub.id ? "destructive" : "ghost"}
                    size="sm"
                    title={armed === sub.id ? "再点一次确认删除" : "删除用户"}
                    onClick={() => (armed === sub.id ? remove(sub) : arm(sub.id))}
                  >
                    <Trash2 className="size-3.5" /> {armed === sub.id ? "确认" : "删除"}
                  </Button>
                </div>
              </TableCell>
            </TableRow>
          ))}
        </TableBody>
      </Table>
      <Dialog open={createOpen} onOpenChange={setCreateOpen}>
        <DialogContent className="max-w-sm">
          <DialogHeader>
            <DialogTitle>新建订阅用户</DialogTitle>
          </DialogHeader>
          <div className="flex flex-col gap-1.5">
            <Label>用户名称</Label>
            <Input value={name} onChange={(e) => setName(e.target.value)} placeholder="例如 用户A" />
          </div>
          <div className="flex flex-col gap-1.5">
            <Label>配置选择</Label>
            <select
              className="h-9 w-full rounded-md border bg-transparent px-2 text-sm"
              value={createPlan}
              onChange={(e) => setCreatePlan(e.target.value)}
            >
              {planOptions.map((o) => (
                <option key={o.value} value={o.value}>{o.label}</option>
              ))}
            </select>
          </div>
          <div className="grid grid-cols-2 gap-2">
            <div className="flex flex-col gap-1.5">
              <Label>到期日期（默认次月今日）</Label>
              <Input type="date" value={createExpires} onChange={(e) => setCreateExpires(e.target.value)} />
            </div>
            <div className="flex flex-col gap-1.5">
              <Label>流量配额 GB</Label>
              <Input type="number" min={0} value={createQuota} onChange={(e) => setCreateQuota(e.target.value)} />
            </div>
          </div>
          <DialogFooter>
            <Button disabled={busy || !name.trim()} onClick={create}>
              创建
            </Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>
      {edit && <SubEditDialog sub={edit} planOptions={planOptions} onOpenChange={() => setEdit(null)} reload={reload} />}
      {qr && (
        <QrDialog
          url={custUrl(qr.sub, fronts[0])}
          name={`${qr.sub.name} 的订阅`}
          kind="subscription"
          onOpenChange={() => setQr(null)}
          extra={
            <div className="flex flex-col items-center gap-2 border-t pt-3">
              <div className="text-xs text-muted-foreground">二维码内容：Auto（自动识别）</div>
              <div className="relative">
                {menuOpen && <div className="fixed inset-0 z-10" onClick={() => setMenuOpen(false)} />}
                <Button size="sm" onClick={() => setMenuOpen(!menuOpen)}>
                  <Copy className="size-3.5" /> 复制 <ChevronDown className={`size-3.5 transition-transform ${menuOpen ? "rotate-180" : ""}`} />
                </Button>
                {menuOpen && (
                  <div className="absolute bottom-full left-1/2 z-20 mb-1.5 w-72 -translate-x-1/2 rounded-md border bg-popover p-1.5 shadow-md">
                    {(() => {
                      const main = custUrl(qr.sub, fronts[0])
                      const links = custUrl(qr.sub, fronts[0], "v2rayng")
                      const rows: { key: string; label: string; url: string }[] = [
                        { key: "auto", label: "Auto（自动识别）", url: main },
                        { key: "clash", label: "Clash / mihomo（YAML）", url: main },
                        { key: "links", label: "链接列表（base64，v2rayN 系）", url: links },
                      ]
                      return (
                        <>
                          {rows.map((f) => (
                            <button
                              key={f.key}
                              onClick={() => {
                                copyText(f.url, "已复制订阅地址")
                                setMenuOpen(false)
                              }}
                              className="flex w-full items-center justify-between rounded px-2 py-1.5 text-left text-xs transition-colors hover:bg-muted"
                            >
                              <span className="truncate">{f.label}</span>
                              <Copy className="size-3 shrink-0 text-muted-foreground" />
                            </button>
                          ))}
                          {qr.sub.agent_dist && distAgents.length > 0 && (
                            <>
                              <div className="mt-1 border-t px-2 pb-1 pt-1.5 text-[11px] text-muted-foreground">agent 分发入口</div>
                              {distAgents.map((a) => (
                                <button
                                  key={a.node_id}
                                  className="flex w-full items-center justify-between gap-2 rounded px-2 py-1 text-left text-xs hover:bg-muted"
                                  onClick={() => { copyText(`http://${a.host}:${a.port}/api/sub?token=${qr.sub.token}`, "已复制订阅地址"); setMenuOpen(false) }}
                                >
                                  <span className="truncate">{a.name}（{a.host}:{a.port}）</span>
                                  <Copy className="size-3 shrink-0" />
                                </button>
                              ))}
                            </>
                          )}
                        </>
                      )
                    })()}
                  </div>
                )}
              </div>
              <div className="flex items-center gap-2 text-xs text-muted-foreground">
                agent 分发
                <Switch checked={qr.sub.agent_dist ?? false} onCheckedChange={(v) => setAgentDist(qr.sub, v)} />
              </div>
            </div>
          }
        />
      )}
      {assign && <AssignDialog sub={assign} subs={subs} nodes={nodes} onOpenChange={() => setAssign(null)} reload={reload} />}
      {renewFor && renewFor.expires_at && (
        <Dialog open onOpenChange={() => setRenewFor(null)}>
          <DialogContent className="max-w-sm">
            <DialogHeader>
              <DialogTitle>续期 {renewFor.name}</DialogTitle>
            </DialogHeader>
            <div className="flex flex-col gap-2 text-sm">
              <div className="flex items-center justify-between">
                <span className="text-muted-foreground">当前到期</span>
                <span className="tnum">{renewFor.expires_at}</span>
              </div>
              <div className="flex items-center justify-between">
                <span className="text-muted-foreground">续期后</span>
                <span className="tnum font-medium">{nextMonth(renewFor.expires_at)}</span>
              </div>
              <p className="text-xs text-muted-foreground">从当前到期时间往后推一个月。</p>
            </div>
            <DialogFooter>
              <Button variant="outline" onClick={() => setRenewFor(null)}>取消</Button>
              <Button
                onClick={async () => {
                  await renew(renewFor)
                  setRenewFor(null)
                }}
              >
                确认续期
              </Button>
            </DialogFooter>
          </DialogContent>
        </Dialog>
      )}
      {expiryOpen && (
        <Dialog open onOpenChange={setExpiryOpen}>
          <DialogContent className="max-h-[85dvh] overflow-y-auto sm:max-w-3xl">
            <DialogHeader>
              <DialogTitle>到期一览</DialogTitle>
            </DialogHeader>
            <Table>
              <TableHeader>
                <TableRow>
                  <TableHead>客户</TableHead>
                  <TableHead>代理名称</TableHead>
                  <TableHead>分配时间</TableHead>
                  <TableHead>凭据到期</TableHead>
                  <TableHead className="text-right">本期已用 (GB)</TableHead>
                  <TableHead className="text-right">配额 (GB)</TableHead>
                </TableRow>
              </TableHeader>
              <TableBody>
                {assignments.length === 0 && (
                  <TableRow>
                    <TableCell colSpan={6} className="py-6 text-center text-muted-foreground">还没有已分配的代理</TableCell>
                  </TableRow>
                )}
                {assignments.map(({ sub, node, u }) => (
                  <TableRow key={u.id}>
                    <TableCell>{sub.name}</TableCell>
                    <TableCell>{node.name}</TableCell>
                    <TableCell className="text-xs">{assignedAt(u.created_at)}</TableCell>
                    <TableCell>
                      {u.expires_at ? (
                        <button
                          type="button"
                          onClick={() => setRenewCred(u)}
                          title="续期：往后推一个月"
                          className={"tnum hover:underline decoration-dotted underline-offset-2 " + (soon(u.expires_at) ? "text-red-500" : "")}
                        >
                          {u.expires_at}
                        </button>
                      ) : (
                        ""
                      )}
                    </TableCell>
                    <TableCell className="text-right tnum">{gb((u.quota_used_up ?? 0) + (u.quota_used_down ?? 0))}</TableCell>
                    <TableCell className="text-right tnum">{u.quota_bytes ? gb(u.quota_bytes) : ""}</TableCell>
                  </TableRow>
                ))}
              </TableBody>
            </Table>
            <p className="text-xs text-muted-foreground">按凭据到期升序；剩余 ≤3 天（含已过期）标红，口径与主机页一致。点到期日期可续期。</p>
          </DialogContent>
        </Dialog>
      )}
      {renewCred && (
        <Dialog open onOpenChange={() => setRenewCred(null)}>
          <DialogContent className="max-w-sm">
            <DialogHeader>
              <DialogTitle>续期 {renewCred.name}</DialogTitle>
            </DialogHeader>
            <div className="flex flex-col gap-2 text-sm">
              <div className="flex items-center justify-between">
                <span className="text-muted-foreground">当前到期</span>
                <span className="tnum">{renewCred.expires_at}</span>
              </div>
              <div className="flex items-center justify-between">
                <span className="text-muted-foreground">续期后</span>
                <span className="tnum font-medium">{renewCredTo(renewCred)}</span>
              </div>
              <p className="text-xs text-muted-foreground">从当前到期时间往后推一个月。</p>
            </div>
            <DialogFooter>
              <Button variant="outline" onClick={() => setRenewCred(null)}>取消</Button>
              <Button onClick={() => doRenewCred(renewCred)}>确认续期</Button>
            </DialogFooter>
          </DialogContent>
        </Dialog>
      )}
    </Card>
    </div>
  )
}

// ---- 用户页：订阅客户的独立页面（从协议页拆出） ----

function useUserData() {
  const [subs, setSubs] = useState<SubUser[]>([])
  const [nodes, setNodes] = useState<ProxyNode[]>([])
  const load = useCallback(async () => {
    const [s, n] = await Promise.all([
      api<SubUser[]>("/proxy/sub-users"),
      api<{ host: string; nodes: ProxyNode[] }>("/proxy/nodes"),
    ])
    setSubs(s)
    setNodes(n.nodes)
  }, [])
  useEffect(() => {
    load()
  }, [load])
  return { subs, nodes, reload: load }
}

export default function Users() {
  const { subs, nodes, reload } = useUserData()
  return (
    <div className="flex flex-col gap-6">
      <SubsCard subs={subs} nodes={nodes} reload={reload} />
    </div>
  )
}
