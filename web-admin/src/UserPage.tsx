// 用户中心页（/u/{客户token}）：链接即凭证的独立轻量页。
// 数据端点 GET /api/user-page?token=…（公开，公开页总开关 + 每客户 user_page 开关管控）。
// 视图由管理端按客户设定（sub_user.view_mode）：overview=概览三卡；per_node=逐代理
// 明细卡置顶为主体（到期/流量两栏大数字+全宽进度条），订阅链接保留，客户级配额卡隐藏。
// 设计语言对齐面板：语义色阶（ok/near/over）、上红下蓝（text-up/down）、状态徽标
// （StatusBadge，管理端同款映射）。协议类型与代理地址端口不向客户展示（用户拍板：
// 客户视角只认代理的名称、状态、到期与流量）。
import { useEffect, useState } from "react"
import QRCode from "qrcode"

import { StatusBadge } from "@/components/ui/status-badge"

declare const __USER_BASE__: string

type PageData = {
  name: string
  status: "active" | "expired" | "over_quota" | "disabled"
  view_mode: "overview" | "per_node"
  quota: { up: number; down: number; total: number; expires_at: string | null }
  nodes: {
    name: string
    protocol: string
    host: string
    port: number
    online: boolean
    share_url?: string
    expires_at?: string | null
    limit_enabled?: boolean
    live?: boolean
    quota?: { up: number; down: number; total: number }
  }[]
  subs: { label: string; url: string }[]
  self_reset?: { allow: boolean; count: number; limit: number }
}

const STATUS_TEXT: Record<PageData["status"], string> = {
  active: "正常使用中",
  expired: "已过期",
  over_quota: "流量已用尽",
  disabled: "已停用",
}
// 管理端用户页同款状态→语义色映射（正常绿/停用灰/到期红/超额红）
const STATUS_TONE: Record<PageData["status"], "ok" | "off" | "danger"> = {
  active: "ok",
  expired: "danger",
  over_quota: "danger",
  disabled: "off",
}

function gb(bytes: number) {
  return `${(bytes / 1024 ** 3).toFixed(2)} GB`
}

// 复制到剪贴板：clipboard API 优先（需用户激活），被拒（老内核/App 内置
// webview 常见）退化 execCommand 临时选区方案。返回是否成功。
async function copyText(text: string): Promise<boolean> {
  try {
    await navigator.clipboard.writeText(text)
    return true
  } catch {
    try {
      const ta = document.createElement("textarea")
      ta.value = text
      ta.style.position = "fixed"
      ta.style.opacity = "0"
      document.body.appendChild(ta)
      ta.select()
      const ok = document.execCommand("copy")
      ta.remove()
      return ok
    } catch {
      return false
    }
  }
}

// ① 流量配额（仅概览模式；代理明细模式下逐代理卡已覆盖流量信息）。
// 订阅二维码收编到卡头（概览模式不再单设订阅链接卡；取首个订阅入口）
function QuotaSection({ data, onShowQr }: { data: PageData; onShowQr: (url: string) => void }) {
  const used = data.quota.up + data.quota.down
  const pct = data.quota.total > 0 ? Math.min(100, (used / data.quota.total) * 100) : 0
  return (
    <section className="flex flex-col gap-4 rounded-xl border bg-white p-5 dark:bg-zinc-900">
      {/* 状态徽标统一在页头（两种模式一致），卡内不再重复 */}
      <div className="flex items-center justify-between gap-2">
        <div className="text-lg font-medium">流量配额</div>
        {data.subs.length > 0 && (
          <button
            className="shrink-0 whitespace-nowrap rounded-md border px-2.5 py-1.5 text-xs text-muted-foreground transition-colors hover:bg-muted hover:text-foreground"
            title="订阅二维码（点开可复制链接）"
            onClick={() => onShowQr(data.subs[0].url)}
          >
            二维码
          </button>
        )}
      </div>
      {data.quota.total > 0 ? (
        <>
          <div className="flex items-center justify-between text-sm">
            <span>
              已用：<b className="tnum">{gb(used)}</b>
            </span>
            <span className="text-muted-foreground">
              额度：<span className="tnum">{gb(data.quota.total)}</span>（{pct.toFixed(0)}%）
            </span>
          </div>
          <div className="h-2 w-full overflow-hidden rounded-full bg-zinc-200 dark:bg-zinc-800">
            <div className="h-full rounded-full bg-ok" style={{ width: `${pct}%` }} />
          </div>
          <div className="flex justify-between text-xs text-muted-foreground">
            <span>
              <span className="tnum text-up">上行 {gb(data.quota.up)}</span> ·{" "}
              <span className="tnum text-down">下行 {gb(data.quota.down)}</span>
            </span>
            <span className="tnum">剩余 {gb(Math.max(0, data.quota.total - used))}</span>
          </div>
        </>
      ) : (
        <div className="text-sm text-muted-foreground">该订阅不限流量。</div>
      )}
      {data.quota.expires_at && (
        <div className="text-sm text-muted-foreground">到期时间：{data.quota.expires_at}</div>
      )}
    </section>
  )
}

// 订阅小卡：嵌在代理明细网格里，与代理卡同宽。整体高度必须压在代理卡自然高度
// 之下（提示行收进卡头、二维码 128px）——网格默认等高拉伸，订阅卡一旦更高就会
// 把同行代理卡撑高（第一版踩过：三卡全被拉到 258px）。点击二维码即复制订阅链接
// （/api/sub 全部代理 + 客户凭据 + #客户名 片段；取首个订阅入口）。
function SubQrCard({ url }: { url: string }) {
  const [img, setImg] = useState("")
  const [copied, setCopied] = useState(false)
  useEffect(() => {
    if (url) QRCode.toDataURL(url, { width: 256, margin: 2 }).then(setImg).catch(() => {})
  }, [url])
  useEffect(() => setCopied(false), [url])
  if (!url) return null
  return (
    <div className="flex flex-col gap-2 rounded-xl border bg-white p-4 dark:bg-zinc-900">
      <div className="flex items-center gap-2">
        <span className="truncate text-base font-semibold">订阅链接</span>
        <span className={`ml-auto shrink-0 text-[11px] ${copied ? "font-medium text-ok" : "text-muted-foreground"}`}>
          {copied ? "已复制链接" : "点击复制链接"}
        </span>
      </div>
      <img
        src={img}
        alt="订阅二维码"
        className="mx-auto w-32 cursor-pointer rounded transition-transform active:scale-95"
        title="点击复制链接"
        onClick={async () => {
          if (await copyText(url)) {
            setCopied(true)
            setTimeout(() => setCopied(false), 1500)
          } else {
            prompt(`复制失败，请手动复制：`, url)
          }
        }}
      />
    </div>
  )
}

// ③ 可用代理：概览=紧凑两列网格（名称+在线点+单代理二维码）；代理明细=置顶统计卡
// （名称+在线状态 → 到期/流量两栏大数字 → 全宽进度条 → 上红下蓝分项），
// 订阅小卡作为网格末位卡片（与代理卡同尺寸）
function NodesSection({ data, onShowQr }: { data: PageData; onShowQr: (url: string) => void }) {
  const perNode = data.view_mode === "per_node"
  if (!perNode) {
    return (
      <section className="flex flex-col gap-3 rounded-xl border bg-white p-5 dark:bg-zinc-900">
        <div className="text-lg font-medium">可用代理（{data.nodes.length}）</div>
        <div className="grid grid-cols-1 gap-2 md:grid-cols-2">
          {data.nodes.map((n) => (
            <div key={n.name} className="flex items-center gap-2 rounded-lg border p-3">
              <span
                className={`inline-block size-2 shrink-0 rounded-full ${n.online ? "bg-ok" : "bg-zinc-400"}`}
                title={n.online ? "在线" : "离线"}
              />
              <span className="truncate font-medium">{n.name}</span>
              {n.share_url && (
                <button
                  className="ml-auto shrink-0 whitespace-nowrap rounded-md border px-2.5 py-1.5 text-xs text-muted-foreground transition-colors hover:bg-muted hover:text-foreground"
                  title="本代理的导入二维码（仅该代理，用你自己的凭据）"
                  onClick={() => onShowQr(n.share_url!)}
                >
                  二维码
                </button>
              )}
            </div>
          ))}
          {data.nodes.length === 0 && (
            <div className="py-4 text-center text-sm text-muted-foreground">
              还没有分配给你的代理，请联系管理员。
            </div>
          )}
        </div>
      </section>
    )
  }
  return (
    <div className="flex flex-col gap-3">
      <div className="text-lg font-medium">可用代理（{data.nodes.length}）</div>
      <div className="grid grid-cols-1 gap-3 md:grid-cols-2 xl:grid-cols-3">
      {data.nodes.map((n) => {
        const q = n.quota
        const qUsed = q ? q.up + q.down : 0
        const qPct = q && q.total > 0 ? Math.min(100, Math.round((qUsed / q.total) * 100)) : 0
        const qOver = q && q.total > 0 && qUsed >= q.total
        const expired = n.expires_at ? new Date(n.expires_at + "T23:59:59") < new Date() : false
        return (
          <div key={n.name} className="flex flex-col gap-3 rounded-xl border bg-white p-4 dark:bg-zinc-900">
            {/* 卡头：名称 + 单代理二维码 + 在线状态（点+文字，不只靠颜色）；协议与地址端口不向客户展示 */}
            <div className="flex items-center gap-2">
              <span className="truncate text-base font-semibold">{n.name}</span>
              {n.share_url && (
                <button
                  className="ml-auto shrink-0 whitespace-nowrap rounded-md border px-2.5 py-1.5 text-xs text-muted-foreground transition-colors hover:bg-muted hover:text-foreground"
                  title="本代理的导入二维码（仅该代理，用你自己的凭据）"
                  onClick={() => onShowQr(n.share_url!)}
                >
                  二维码
                </button>
              )}
              <span
                className={`inline-flex shrink-0 items-center gap-1.5 text-xs font-medium ${
                  n.online ? "text-ok" : "text-muted-foreground"
                }`}
              >
                <span className={`size-1.5 rounded-full ${n.online ? "bg-ok" : "bg-zinc-400"}`} aria-hidden />
                {n.online ? "在线" : "离线"}
              </span>
            </div>
            {/* 统计块：到期 / 流量 两栏大数字 */}
            <div className="grid grid-cols-2 gap-3 border-t pt-3">
              <div className="flex flex-col gap-1">
                <span className="text-[11px] text-muted-foreground">到期日期</span>
                {n.expires_at ? (
                  <span className={`tnum text-lg font-semibold leading-tight ${expired ? "text-over" : ""}`}>
                    {n.expires_at}
                  </span>
                ) : (
                  <span className="text-lg font-medium leading-tight text-muted-foreground">不限</span>
                )}
                {expired && <span className="text-xs font-medium text-over">已过期</span>}
              </div>
              <div className="flex flex-col gap-1">
                <span className="text-[11px] text-muted-foreground">流量已用</span>
                <span className="tnum text-lg font-semibold leading-tight">{gb(qUsed)}</span>
                <span className="tnum text-xs text-muted-foreground">
                  {q && q.total > 0 ? `/ ${gb(q.total)} · ${qPct}%` : "不限"}
                </span>
              </div>
            </div>
            {/* 进度条：限额才画（语义色阶 ok→near(>80%)→over），无限额不出假条 */}
            {q && q.total > 0 && (
              <div className="h-2 w-full overflow-hidden rounded-full bg-zinc-200 dark:bg-zinc-800">
                <div
                  className={`h-full rounded-full ${qOver ? "bg-over" : qPct > 80 ? "bg-near" : "bg-ok"}`}
                  style={{ width: `${Math.max(qPct, 2)}%` }}
                />
              </div>
            )}
            {/* 上红下蓝（面板惯例） */}
            {q && (
              <div className="flex items-center justify-between text-xs">
                <span className="tnum text-up">↑ 上行 {gb(q.up)}</span>
                <span className="tnum text-down">↓ 下行 {gb(q.down)}</span>
              </div>
            )}
          </div>
        )
      })}
      {/* 订阅小卡：与代理卡同宽，直接显示二维码（点击复制） */}
      <SubQrCard url={data.subs[0]?.url ?? ""} />
      {data.nodes.length === 0 && (
        <div className="col-span-full py-4 text-center text-sm text-muted-foreground">
          还没有分配给你的代理，请联系管理员。
        </div>
      )}
      </div>
    </div>
  )
}

// 重置订阅卡（自助）：凭据+订阅链接整体换新，所有设备需重新导入。剩余次数
// 显示；成功后用新 token 替换当前 /u/ 地址（旧地址立即失效，客户不被锁在页
// 面外）并刷新数据。
function ResetCard({ data, token, onReset }: { data: PageData; token: string; onReset: (newToken: string) => void }) {
  const [confirming, setConfirming] = useState(false)
  const [busy, setBusy] = useState(false)
  const remain = (data.self_reset?.limit ?? 0) - (data.self_reset?.count ?? 0)
  return (
    <section className="flex flex-col gap-3 rounded-xl border bg-white p-5 dark:bg-zinc-900">
      <div className="text-lg font-medium">重置订阅</div>
      {remain > 0 ? (
        <>
          <p className="text-xs text-muted-foreground">
            员工离职或链接外泄时可整体重置：所有代理凭据与订阅链接换新（代理 IP 与端口不变），剩余 {remain} 次。
          </p>
          {!confirming ? (
            <button
              className="w-fit rounded-md border px-3 py-2 text-sm text-destructive transition-colors hover:bg-destructive/10"
              onClick={() => setConfirming(true)}
            >
              重置订阅
            </button>
          ) : (
            <div className="flex flex-col gap-2 rounded-lg border p-3 text-sm">
              <p>确认重置？<b>所有设备需要重新导入</b>，旧链接立即失效，剩余 {remain - 1} 次。</p>
              <div className="flex gap-2">
                <button
                  className="rounded-md border px-3 py-2 text-sm hover:bg-muted"
                  onClick={() => setConfirming(false)}
                >
                  取消
                </button>
                <button
                  className="rounded-md bg-destructive px-3 py-2 text-sm font-medium text-white disabled:opacity-50"
                  disabled={busy}
                  onClick={async () => {
                    setBusy(true)
                    try {
                      const resp = await fetch("/api/user-page/self-reset", {
                        method: "POST",
                        headers: { "Content-Type": "application/json" },
                        body: JSON.stringify({ token }),
                      })
                      const v = await resp.json()
                      if (!resp.ok || !v.token) throw new Error(v.error || `HTTP ${resp.status}`)
                      onReset(v.token)
                    } catch (e) {
                      alert((e as Error).message || "重置失败")
                    } finally {
                      setBusy(false)
                      setConfirming(false)
                    }
                  }}
                >
                  {busy ? "重置中…" : "确认重置"}
                </button>
              </div>
            </div>
          )}
        </>
      ) : (
        <p className="text-xs text-muted-foreground">重置次数已用完，请联系管理员。</p>
      )}
    </section>
  )
}

// 页面级二维码浮层：订阅卡与代理卡共用（遮罩点击 + 显式关闭双通道退出）。
// 点击二维码本体即复制对应链接（订阅地址或单代理分享链接），复制后浮层保持
// 打开（可能扫码 + 复制交替用），反馈走下方提示行。
function QrOverlay({ qr, onClose }: { qr: { url: string; img: string } | null; onClose: () => void }) {
  const [copied, setCopied] = useState(false)
  useEffect(() => setCopied(false), [qr])
  if (!qr) return null
  const copyQr = async () => {
    if (await copyText(qr.url)) {
      setCopied(true)
      setTimeout(() => setCopied(false), 1500)
    } else {
      prompt(`复制失败，请手动复制：`, qr.url)
    }
  }
  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/60 p-4" onClick={onClose}>
      <div
        className="flex flex-col items-center gap-3 rounded-xl border bg-white p-4 dark:bg-zinc-900"
        onClick={(e) => e.stopPropagation()}
      >
        <img
          src={qr.img}
          alt="二维码"
          className="h-auto max-w-full cursor-pointer rounded transition-transform active:scale-95"
          title="点击复制链接"
          onClick={copyQr}
        />
        <div className={`text-xs ${copied ? "font-medium text-ok" : "text-muted-foreground"}`}>
          {copied ? "已复制链接" : "点击二维码复制链接"}
        </div>
        <button className="rounded-md border px-3 py-2 text-sm hover:bg-muted" onClick={onClose}>
          关闭
        </button>
      </div>
    </div>
  )
}

export default function UserPage() {
  const token = decodeURIComponent(location.pathname.split("/")[2] ?? "")
  const [data, setData] = useState<PageData | null>(null)
  const [error, setError] = useState("")
  const [qr, setQr] = useState<{ url: string; img: string } | null>(null)
  const [migrated, setMigrated] = useState(false)
  const showQr = (url: string) =>
    QRCode.toDataURL(url, { width: 256, margin: 2 }).then((img) => setQr({ url, img }))
  const loadData = (t: string) => {
    fetch(`/api/user-page?token=${encodeURIComponent(t)}`)
      .then(async (r) => {
        const text = await r.text()
        if (!r.ok) throw new Error(text || `HTTP ${r.status}`)
        return JSON.parse(text) as PageData
      })
      .then(setData)
      .catch((e) => setError((e as Error).message))
  }
  // 自助重置成功：页面迁移到新的 /u/ 地址（旧地址立即失效），数据用新 token 重取
  const onSelfReset = (newToken: string) => {
    history.replaceState({}, "", `/u/${newToken}`)
    setMigrated(true)
    loadData(newToken)
  }

  useEffect(() => {
    if (!token) {
      setError("链接缺少凭证（/u/{token}）")
      return
    }
    loadData(token)
  }, [])

  if (error)
    return (
      <div className="flex min-h-screen items-center justify-center p-6">
        <div className="rounded-xl border p-8 text-center text-muted-foreground">{error}</div>
      </div>
    )
  if (!data)
    return (
      <div className="flex min-h-screen items-center justify-center p-6 text-muted-foreground">加载中…</div>
    )

  // 代理明细模式：统计卡置顶为主体、订阅链接随后；概览模式：流量配额（含订阅二维码）→ 代理网格
  const perNode = data.view_mode === "per_node"
  return (
    <div className="min-h-screen bg-zinc-50 p-4 text-zinc-900 dark:bg-zinc-950 dark:text-zinc-100 md:p-8">
      <div className="mx-auto flex max-w-4xl flex-col gap-6">
        <div className="flex items-center justify-between gap-3">
          <h1 className="text-xl font-semibold">用户中心 · {data.name}</h1>
          {/* 账号级状态在两种模式下都可见（此前明细模式下随配额卡一起消失） */}
          <StatusBadge tone={STATUS_TONE[data.status]}>{STATUS_TEXT[data.status]}</StatusBadge>
        </div>
        {migrated && (
          <div className="rounded-xl border border-emerald-500/40 bg-emerald-500/10 p-4 text-sm">
            <b>订阅已重置。</b>新的用户中心地址已生效——请收藏并分发给在职员工：
            <button
              className="ml-1 rounded-md border px-2 py-0.5 text-xs hover:bg-muted"
              onClick={async () => {
                try {
                  await navigator.clipboard.writeText(location.origin + "/u/" + token)
                  alert("已复制新的用户中心地址")
                } catch {
                  prompt("复制失败，请手动复制：", location.origin + "/u/" + token)
                }
              }}
            >
              复制新地址
            </button>
          </div>
        )}
        {perNode ? (
          <NodesSection data={data} onShowQr={showQr} />
        ) : (
          <>
            <QuotaSection data={data} onShowQr={showQr} />
            <NodesSection data={data} onShowQr={showQr} />
          </>
        )}
        {data.self_reset?.allow && (
          <ResetCard data={data} token={token} onReset={onSelfReset} />
        )}
        <QrOverlay qr={qr} onClose={() => setQr(null)} />
        <div className="pb-6 text-center text-[11px] text-muted-foreground">Monitor 用户中心</div>
      </div>
    </div>
  )
}
