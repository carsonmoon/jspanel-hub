import { useCallback, useEffect, useRef, useState, type MouseEvent as ReactMouseEvent } from "react"
import { ChevronDown, RefreshCw, ChevronLeft, ChevronRight } from "lucide-react"
import { toast } from "sonner"

import { Button } from "@/components/ui/button"
import { PageHeader } from "@/components/page-header"
import { Card } from "@/components/ui/card"
import { money, cycleMonths } from "@/lib/format"
import { Popover, PopoverContent, PopoverTrigger } from "@/components/ui/popover"
import { Skeleton } from "@/components/ui/skeleton"
import { api } from "@/lib/api"
import { bytes } from "@/lib/format"

type Overview = {
  series: { bucket: number; rx: number; tx: number }[]
  node_rank: { node: string; rx: number; tx: number }[]
  customer_rank: { name: string; up: number; down: number; quota_bytes: number; status: string }[]
  quota_warn: { name: string; used: number; quota_bytes: number; status: string }[]
  expiring: { name: string; expires_at: string }[]
  today_series: { bucket: number; rx: number; tx: number }[]
  today_rank: { node: string; billed: number; rx: number; tx: number; mode: string }[]
  calendar: { id: number; name: string; expires_at: string; cycle: string; price: number; currency: string }[]
  alerts: {
    ping: { active: { kind: string; node: string; task: string; raised_at: number; detail: string }[]; recovered_today: number }
    offline: string[]
    traffic: string[]
    route_changes_24h: number
  }
  kpi: { today_rx: number; today_tx: number; online_nodes: number; total_nodes: number; customers: number }
}

// 计费口径（traffic_mode）→ 展示名；排行/每日计费流量的「计费」列按它折算。
// 走势范围 → 桶数与桶粒度（与后端 proxy_overview 的 range 映射逐档相等）。
// tickEvery：刻度间隔（桶数），末桶固定加「现在」刻度。30d 档 1h 是精度
// 上限：8 天前的采样已压缩成小时行，更细的桶会失真。
const RANGES = {
  "6h": { label: "6小时", buckets: 360, bucketSecs: 60, tickEvery: 60 },
  "24h": { label: "24小时", buckets: 1440, bucketSecs: 60, tickEvery: 240 },
  "7d": { label: "7天", buckets: 1008, bucketSecs: 10 * 60, tickEvery: 144 },
  "30d": { label: "30天", buckets: 720, bucketSecs: 3600, tickEvery: 120 },
} as const
type RangeKey = keyof typeof RANGES

function useOverview(range: RangeKey) {
  const [data, setData] = useState<Overview | null>(null)
  const [loadedRange, setLoadedRange] = useState<RangeKey>(range)
  const rangeRef = useRef(range)
  useEffect(() => {
    rangeRef.current = range
  }, [range])
  const load = useCallback(async () => {
    try {
      const d = await api<Overview>(`/proxy/overview?range=${range}`)
      // 切换范围后旧请求才返回时丢弃，避免串数据。
      if (rangeRef.current !== range) return
      setData(d)
      setLoadedRange(range)
    } catch (e) {
      toast.error((e as Error).message)
    }
  }, [range])
  useEffect(() => {
    load()
    const t = setInterval(load, 30_000)
    return () => clearInterval(t)
  }, [load])
  return { data, loadedRange, reload: load }
}

function Kpi({ label, value, sub, accent }: { label: string; value: string; sub?: React.ReactNode; accent?: "up" | "ok" | "warn" }) {
  const bar = accent === "up" ? "border-l-up" : accent === "ok" ? "border-l-ok" : accent === "warn" ? "border-l-warn" : "border-l-primary"
  return (
    <Card className={`flex flex-col gap-1 border-l-[3px] p-4 ${bar}`}>
      <div className="text-xs text-muted-foreground">{label}</div>
      <div className="text-lg font-semibold">{value}</div>
      {sub && <div className="text-xs text-muted-foreground">{sub}</div>}
    </Card>
  )
}

/** 流量走势：手绘 SVG 折线双曲线 + 渐变面积（项目无图表库）。缺桶由这里补零。
 * 下行（蓝）与上行（红）在同一坐标系里各自一条连续折线（相邻桶直连，尖峰
 * 锯齿原样呈现），带渐变面积填充区分层次。真实时间刻度轴 + 十字线悬停读数。
 * 时间窗默认 6 小时（每分钟一点），可切 24h/7d/30d。 */
function ThroughputChart({ series, range }: { series: { bucket: number; rx: number; tx: number }[]; range: RangeKey }) {
  const { buckets, bucketSecs, tickEvery } = RANGES[range]
  const [hover, setHover] = useState<number | null>(null)
  const W = 800
  const H = 220
  const PAD = 4
  // buckets 个整桶，缺的补零；最后一桶是"当前桶"。桶对齐 unix 时间的
  // bucketSecs 整数倍（与后端聚合一致）。
  const start = Math.floor(Date.now() / 1000 / bucketSecs) * bucketSecs - (buckets - 1) * bucketSecs
  const byBucket = new Map(series.map((p) => [p.bucket, p]))
  const points = Array.from({ length: buckets }, (_, i) => {
    const b = start + i * bucketSecs
    const p = byBucket.get(b)
    return { hour: i, down: p?.rx ?? 0, up: p?.tx ?? 0 }
  })
  const max = Math.max(...points.map((p) => p.down + p.up), 1)
  const x = (i: number) => PAD + (i * (W - PAD * 2)) / (buckets - 1)
  const y = (v: number) => Math.max(PAD, H - PAD - (v * (H - PAD * 2)) / max)

  // 直连折线：相邻桶直线相连（探针/路由器流量图风格），尖峰锯齿原样呈现。
  const line = (key: "down" | "up") =>
    points.map((p, i) => `${i === 0 ? "M" : "L"}${x(i).toFixed(1)},${y(p[key]).toFixed(1)}`).join(" ")
  const lineDown = line("down")
  const lineUp = line("up")
  const baseline = H - PAD
  const areaDown = `${lineDown} L${x(buckets - 1).toFixed(1)},${baseline} L${x(0).toFixed(1)},${baseline} Z`
  const areaUp = `${lineUp} L${x(buckets - 1).toFixed(1)},${baseline} L${x(0).toFixed(1)},${baseline} Z`

  // 刻度：每 tickEvery 桶一个 + 末桶「现在」。24h 档零点刻度带日期。
  const pad2 = (n: number) => String(n).padStart(2, "0")
  const fmtDate = (b: number) => {
    const d = new Date(b * 1000)
    return `${pad2(d.getMonth() + 1)}-${pad2(d.getDate())}`
  }
  const fmtTick = (i: number) => {
    const b = start + i * bucketSecs
    if (range === "30d") return fmtDate(b)
    if (range === "7d") {
      const d = new Date(b * 1000)
      return `${fmtDate(b)} ${pad2(d.getHours())}:00`
    }
    const d = new Date(b * 1000)
    return d.getHours() === 0 ? fmtDate(b) : `${pad2(d.getHours())}:00`
  }
  const tickIdx: number[] = []
  for (let i = 0; i < buckets; i += tickEvery) tickIdx.push(i)
  if (tickIdx[tickIdx.length - 1] !== buckets - 1) tickIdx.push(buckets - 1)

  // tooltip 直接显示桶时间（不显示区间）。
  const fmtFull = (b: number) =>
    new Date(b * 1000).toLocaleString("zh-CN", { month: "numeric", day: "numeric", hour: "2-digit", minute: "2-digit", hour12: false })
  const hoverTime = (i: number) => fmtFull(start + i * bucketSecs)

  // 鼠标 → 最近桶下标（viewBox 坐标换算）。
  const onMove = (e: ReactMouseEvent<SVGSVGElement>) => {
    const rect = e.currentTarget.getBoundingClientRect()
    const relX = ((e.clientX - rect.left) / rect.width) * W
    const idx = Math.round((relX - PAD) / ((W - PAD * 2) / (buckets - 1)))
    setHover(Math.max(0, Math.min(buckets - 1, idx)))
  }
  // tooltip 水平位置三段翻转，贴边不出界。
  const tipAlign = hover === null ? "" : hover < buckets * 0.15 ? "translateX(0)" : hover > buckets * 0.85 ? "translateX(-100%)" : "translateX(-50%)"
  const hoverPoint = hover === null ? null : points[hover]

  return (
    <div className="flex flex-col gap-2">
      <div className="relative">
        <svg viewBox={`0 0 ${W} ${H}`} className="w-full" role="img" aria-label="流量折线图，悬停查看各时点数值" onMouseMove={onMove} onMouseLeave={() => setHover(null)}>
          {tickIdx.slice(0, -1).map((i) => (
            <line key={i} x1={x(i)} x2={x(i)} y1={PAD} y2={H - PAD} strokeWidth="1" className="stroke-muted-foreground/15" />
          ))}
          {/* 横向虚线刻度（按峰值比例）+ 右侧流量值：给「当前量级」一个参照物 */}
          {/* y 轴自解释：顶部峰值虚线、中线虚线、底部 0 基线实线，左侧标数值 */}
          <line x1={PAD} x2={W - PAD} y1={PAD} y2={PAD} strokeDasharray="3 4" strokeWidth="1" className="stroke-muted-foreground/25" />
          <line x1={PAD} x2={W - PAD} y1={y(max / 2)} y2={y(max / 2)} strokeDasharray="3 4" strokeWidth="1" className="stroke-muted-foreground/25" />
          <line x1={PAD} x2={W - PAD} y1={H - PAD} y2={H - PAD} strokeWidth="1" className="stroke-muted-foreground/30" />
          <text x={PAD + 4} y={PAD + 10} fontSize="9" className="fill-muted-foreground/60">{bytes(max)}</text>
          <text x={PAD + 4} y={y(max / 2) - 4} fontSize="9" className="fill-muted-foreground/60">{bytes(max / 2)}</text>
          <text x={PAD + 4} y={H - PAD - 4} fontSize="9" className="fill-muted-foreground/60">0</text>
          {/* 折线 + 渐变面积（最早的形态）：时间窗收窄后每分钟一点有足够
              横向空间，折线舒展可读 */}
          <defs>
            <linearGradient id="grad-down" x1="0" y1="0" x2="0" y2="1">
              <stop offset="0%" stopColor="currentColor" stopOpacity="0.28" className="text-primary" />
              <stop offset="100%" stopColor="currentColor" stopOpacity="0.02" className="text-primary" />
            </linearGradient>
            <linearGradient id="grad-up" x1="0" y1="0" x2="0" y2="1">
              <stop offset="0%" stopColor="currentColor" stopOpacity="0.24" className="text-up" />
              <stop offset="100%" stopColor="currentColor" stopOpacity="0.02" className="text-up" />
            </linearGradient>
          </defs>
          <path d={areaDown} fill="url(#grad-down)" />
          <path d={areaUp} fill="url(#grad-up)" />
          <path d={lineDown} fill="none" stroke="currentColor" strokeWidth="2" className="text-primary" />
          <path d={lineUp} fill="none" stroke="currentColor" strokeWidth="1.75" className="text-up" />
          {hoverPoint && hover !== null && (
            <>
              <line x1={x(hover)} x2={x(hover)} y1={PAD} y2={H - PAD} strokeWidth="1" className="stroke-muted-foreground/40" />
              <circle cx={x(hover)} cy={y(hoverPoint.down)} r="3.5" className="fill-primary" />
              <circle cx={x(hover)} cy={y(hoverPoint.up)} r="3.5" className="fill-up" />
            </>
          )}
        </svg>
        {hoverPoint && hover !== null && (
          <div
            className="pointer-events-none absolute top-1 z-10 w-max rounded-md border bg-popover px-2.5 py-1.5 text-xs shadow-md"
            style={{ left: `${(x(hover) / W) * 100}%`, transform: tipAlign }}
          >
            <div className="font-medium">{hoverTime(hover)}</div>
            <div className="mt-0.5 flex flex-col gap-0.5 text-muted-foreground">
              <span>下行 {bytes(hoverPoint.down)}</span>
              <span>上行 {bytes(hoverPoint.up)}</span>
              <span className="font-medium text-foreground">合计 {bytes(hoverPoint.down + hoverPoint.up)}</span>
            </div>
          </div>
        )}
      </div>
      {/* 刻度行：百分比定位与网格线对齐；首尾刻度向内对齐防溢出。 */}
      <div className="relative h-4 text-xs text-muted-foreground">
        {/* 只留首尾两个刻度（对齐参考图 22:52 / 23:22 的极简） */}
        {[0, buckets - 1].map((i) => (
          <span
            key={i}
            className="absolute top-0 whitespace-nowrap"
            style={{
              left: `${(x(i) / W) * 100}%`,
              transform: i === 0 ? "translateX(0)" : "translateX(-100%)",
            }}
          >
            {i === buckets - 1 ? "现在" : fmtTick(i)}
          </span>
        ))}
      </div>
    </div>
  )
}

/** 堆叠双色排行条（截图同款）：名称 + 总量大字、下行蓝/上行橙堆叠条、
 * 条下色点小注脚。width 口径沿用 RankBar：第一名占满，其余按比例。 */
function StackedRankBar({ rank, label, down, up, max }: { rank: number; label: string; down: number; up: number; max: number }) {
  const total = down + up
  // 条长口径沿用旧 RankBar：第一名占满，其余按与第一名的比例。
  const width = max > 0 ? Math.max(2, Math.round((total / max) * 100)) : 0
  const downShare = total > 0 ? Math.round((down / total) * 100) : 0
  return (
    <div className="flex flex-col gap-1">
      <div className="flex items-baseline justify-between gap-2">
        <span className="truncate text-xs">
          <span className="mr-1.5 tnum text-muted-foreground">{rank}.</span>
          <span className="font-medium">{label}</span>
        </span>
        <span className="tnum shrink-0 text-xs font-semibold">{bytes(total)}</span>
      </div>
      <div className="flex h-2 w-full overflow-hidden rounded-full bg-muted" role="img" aria-label={`${label}：下行 ${bytes(down)}，上行 ${bytes(up)}`}>
        <div className="flex h-full gap-px" style={{ width: `${width}%` }}>
          {down > 0 && <div className="h-full bg-primary" style={{ width: `${downShare}%` }} />}
          {up > 0 && <div className="h-full bg-up" style={{ width: `${100 - downShare}%` }} />}
        </div>
      </div>
      <div className="flex items-center justify-end gap-4 text-[11px] text-muted-foreground">
        <span className="flex items-center gap-1">
          <span className="inline-block size-1.5 rounded-full bg-up" /> 上行 {bytes(up)}
        </span>
        <span className="flex items-center gap-1">
          <span className="inline-block size-1.5 rounded-full bg-primary" /> 下行 {bytes(down)}
        </span>
      </div>
    </div>
  )
}

export default function Overview({ go }: { go?: (to: string) => void }) {
  const [range, setRange] = useState<RangeKey>("6h")
  const [alertsOpen, setAlertsOpen] = useState(false)
  const { data, loadedRange, reload } = useOverview(range)
  if (!data)
    return (
      <div className="flex flex-col gap-6">
        <PageHeader title="概览" />
        <div className="grid gap-4 sm:grid-cols-3">
          {Array.from({ length: 3 }).map((_, i) => (
            <Card key={i} className="gap-1 border-l-[3px] border-l-primary p-4">
              <Skeleton className="h-4 w-16" />
              <Skeleton className="mt-1 h-6 w-24" />
            </Card>
          ))}
        </div>
        <Card className="gap-3 p-5">
          <Skeleton className="h-5 w-32" />
          <Skeleton className="h-56 w-full" />
        </Card>
      </div>
    )
  const k = data.kpi
  const calendarItems = data.calendar
  // 图例实时值：最近一个非零点（当前桶可能在积累中，取最近有数据的更真实）
  const latest = (() => {
    const pts = [...data.series].reverse()
    const p = pts.find((q) => q.rx + q.tx > 0) ?? pts[0]
    return { down: p?.rx ?? 0, up: p?.tx ?? 0 }
  })()
  const nodeMax = Math.max(...data.node_rank.map((n) => n.rx + n.tx), 1)
  const custMax = Math.max(...data.customer_rank.map((c) => c.up + c.down), 1)

  return (
    <div className="flex flex-col gap-6">
      <PageHeader
        title="概览"
        actions={
          <Button variant="ghost" size="icon" onClick={() => reload().catch((e) => toast.error(e.message))}>
            <RefreshCw className="size-4" />
          </Button>
        }
      />

      <div className="grid gap-4 sm:grid-cols-3">
        <Kpi
          label="今日流量"
          value={bytes(k.today_rx + k.today_tx)}
          sub={
            <span className="inline-flex items-center gap-1.5">
              <span className="inline-flex items-center gap-1">
                <span className="inline-block size-1.5 rounded-full bg-up" /> 上行 {bytes(k.today_tx)}
              </span>
              ·
              <span className="inline-flex items-center gap-1">
                <span className="inline-block size-1.5 rounded-full bg-primary" /> 下行 {bytes(k.today_rx)}
              </span>
            </span>
          }
        />
        <Kpi label="在线主机" value={`${k.online_nodes} / ${k.total_nodes}`} accent="ok" />
        <Kpi label="用户数" value={String(k.customers)} />
      </div>

      {(() => {
        const a = data.alerts
        const lossActive = a.ping.active.filter((x) => x.kind === "loss")
        const latencyActive = a.ping.active.filter((x) => x.kind === "latency")
        // 告警类别 → 后续查看的页面（go 由 Admin 注入；未注入时整行退化为纯文字）。
        // label 单一来源：goTargets 的键与 rows 的 label 都受 AlertLabel 联合类型约束，
        // 改名/删类漏同步直接 tsc 编译红，不再静默退化为不可点行（7e66562 的教训）。
        const ALERT_LABELS = ["服务器离线", "探测丢包", "探测延迟异常", "流量超额", "回程线路变化"] as const
        type AlertLabel = (typeof ALERT_LABELS)[number]
        const goTargets: Record<AlertLabel, string> = {
          服务器离线: "/admin/nodes",
          探测丢包: "/admin/ping",
          探测延迟异常: "/admin/ping",
          流量超额: "/admin/nodes",
          回程线路变化: "/admin/ping",
        }
        const rows: { label: AlertLabel; count: number; items: { node: string; detail: string }[] }[] = [
          { label: "服务器离线", count: a.offline.length, items: a.offline.map((n) => ({ node: n, detail: "" })) },
          {
            label: "探测丢包",
            count: lossActive.length,
            items: lossActive.map((x) => ({ node: x.node, detail: `${x.task} · ${x.detail}` })),
          },
          {
            label: "探测延迟异常",
            count: latencyActive.length,
            items: latencyActive.map((x) => ({ node: x.node, detail: `${x.task} · ${x.detail}` })),
          },
          { label: "流量超额", count: a.traffic.length, items: a.traffic.map((n) => ({ node: n, detail: "已达额度 100%" })) },
          { label: "回程线路变化", count: a.route_changes_24h, items: [] },
        ]
        const alertCount = rows.reduce((sum, r) => sum + r.count, 0)
        const affected = new Set<string>()
        for (const r of rows) for (const it of r.items) affected.add(it.node)
        // 巡检语义：无告警=一行绿条；有告警=汇总条+展开五类明细。
        if (alertCount === 0)
          return (
            <Card className="flex items-center justify-between gap-3 px-5 py-3">
              <div className="flex items-center gap-2 text-sm">
                <span className="inline-block size-2 rounded-full bg-ok" />
                <span className="font-medium">一切正常</span>
                <span className="text-xs text-muted-foreground">主机、网络与流量无异常</span>
              </div>
              <span className="text-xs text-muted-foreground">
                今日恢复 <span className="tnum text-ok">{a.ping.recovered_today}</span>
              </span>
            </Card>
          )
        return (
          <Card className="flex flex-col gap-3 p-5">
            <button type="button" className="flex flex-wrap items-center justify-between gap-2 text-left" onClick={() => setAlertsOpen(!alertsOpen)}>
              <div className="flex items-center gap-2 text-sm">
                <span className="inline-block size-2 animate-pulse rounded-full bg-destructive" />
                <span className="font-semibold">
                  {alertCount} 项告警
                  {affected.size > 0 && <span className="font-normal text-muted-foreground"> · 影响 {affected.size} 个主机</span>}
                </span>
              </div>
              <div className="flex items-center gap-4 text-sm">
                <span className="text-xs text-muted-foreground">
                  今日恢复 <span className="tnum text-ok">{a.ping.recovered_today}</span>
                </span>
                <ChevronDown className={`size-4 text-muted-foreground transition-transform ${alertsOpen ? "rotate-180" : ""}`} />
              </div>
            </button>
            {alertsOpen && (
              <div className="grid gap-x-8 gap-y-1.5 border-t pt-3 sm:grid-cols-2 lg:grid-cols-3">
                {rows.filter((r) => r.count > 0).map((r) => {
                  // 整类行可点击跳到对应页面后续查看；未注入 go（如公开页）退化为纯文字。
                  const target = goTargets[r.label]
                  const clickable = !!(go && target)
                  // 每类严格一行：明细摘要内联在标签后（截断，全量去对应页看）——
                  // 无明细的类别（回程变化只有计数）与有明细的等高，网格不再参差。
                  const first = r.items[0]
                  const inner = (
                    <div className="flex min-w-0 items-center justify-between gap-2 text-xs">
                      <span className="flex min-w-0 items-center gap-1.5">
                        <span className="inline-block size-1.5 shrink-0 rounded-full bg-destructive" />
                        <span className="truncate">
                          {r.label}
                          {first && (
                            <span className="text-muted-foreground">
                              {" · "}
                              {first.node}
                              {first.detail && ` · ${first.detail}`}
                            </span>
                          )}
                        </span>
                      </span>
                      {/* 常显 › 承担「行可点」暗示（用户拍板：替代 hover 文字「点击查看」）；
                          仅 clickable 时出现，公开页退化行不撒谎 */}
                      <span className="flex shrink-0 items-center gap-0.5 tnum font-semibold text-destructive">
                        {r.count}
                        {clickable && (
                          <ChevronRight className="size-3 text-muted-foreground/60 transition-colors group-hover:text-foreground" />
                        )}
                      </span>
                    </div>
                  )
                  if (!clickable) return <div key={r.label}>{inner}</div>
                  return (
                    <button
                      key={r.label}
                      type="button"
                      onClick={() => go!(target)}
                      title={`查看${r.label}详情`}
                      className="group block w-full rounded-md text-left transition-colors hover:bg-muted/60"
                    >
                      {inner}
                    </button>
                  )
                })}
              </div>
            )}
          </Card>
        )
      })()}

      <Card className="flex flex-col gap-3 p-5">
        <div className="flex flex-wrap items-center justify-between gap-2">
          <div className="flex items-center gap-3">
            <div className="text-sm font-semibold">流量走势</div>
            {/* 图例上移（对齐参考图）：色块 + 系列名 + 最近一点实时值 */}
            <div className="flex items-center gap-3 text-xs">
              <span className="flex items-center gap-1.5">
                <span className="inline-block size-2 rounded-[3px] bg-primary" />
                <span className="text-muted-foreground">下行</span>
                <span className="tnum font-medium">{bytes(latest.down)}</span>
              </span>
              <span className="flex items-center gap-1.5">
                <span className="inline-block size-2 rounded-[3px] bg-up" />
                <span className="text-muted-foreground">上行</span>
                <span className="tnum font-medium">{bytes(latest.up)}</span>
              </span>
            </div>
          </div>
          <div className="flex items-center gap-2">
            {/* 窗口标注右上（对齐参考图 all servers · last 30 min） */}
            <span className="hidden text-xs text-muted-foreground sm:inline">
              全部主机 · {range === "6h" ? "近 6 小时" : RANGES[loadedRange].label}
            </span>
            <div className="flex gap-1">
              {(Object.keys(RANGES) as RangeKey[]).map((r) => (
                <Button
                  key={r}
                  variant={range === r ? "secondary" : "ghost"}
                  size="sm"
                  className="h-7 px-2.5 text-xs"
                  onClick={() => setRange(r)}
                >
                  {RANGES[r].label}
                </Button>
              ))}
            </div>
          </div>
        </div>
        <ThroughputChart series={data.series} range={loadedRange} />
      </Card>



      <div className="grid gap-4 lg:grid-cols-2">
        <Card className="flex flex-col p-5">
          <RenewalCalendar items={calendarItems} onRenewed={reload} />
        </Card>
        <div className="grid gap-4">
          <Card className="flex flex-col gap-3 p-5">
            <div className="text-sm font-semibold">代理消耗 TOP（{RANGES[loadedRange].label}）</div>
            {data.node_rank.length === 0 ? (
              <div className="py-6 text-center text-sm text-muted-foreground">还没有流量数据。</div>
            ) : (
              <div className="flex flex-col gap-3.5">
                {data.node_rank.map((n, i) => (
                  <StackedRankBar key={n.node} rank={i + 1} label={n.node} down={n.rx} up={n.tx} max={nodeMax} />
                ))}
              </div>
            )}
          </Card>
          <Card className="flex flex-col gap-3 p-5">
            <div className="text-sm font-semibold">用户消耗 TOP（{RANGES[loadedRange].label}）</div>
            {data.customer_rank.length === 0 ? (
              <div className="py-6 text-center text-sm text-muted-foreground">还没有用户产生流量。</div>
            ) : (
              <div className="flex flex-col gap-3.5">
                {data.customer_rank.map((c, i) => (
                  <StackedRankBar key={c.name} rank={i + 1} label={c.name} down={c.down} up={c.up} max={custMax} />
                ))}
              </div>
            )}
          </Card>
        </div>
      </div>

      {data.quota_warn.length > 0 && (
        <div className="grid gap-4 lg:grid-cols-2">
          <Card className="flex flex-col gap-2 p-4">
            <div className="font-medium text-destructive">配额预警（已用 ≥80%）</div>
            {data.quota_warn.map((w) => (
              <div key={w.name} className="flex items-center justify-between text-sm">
                <span>{w.name}</span>
                <span className="text-muted-foreground">
                  {bytes(w.used)} / {bytes(w.quota_bytes)} · {w.status}
                </span>
              </div>
            ))}
          </Card>
        </div>
      )}
    </div>
  )
}

function RenewalCalendar({ items, onRenewed }: { items: { id: number; name: string; expires_at: string; cycle: string; price: number; currency: string }[]; onRenewed: () => void }) {
  // 周期文案：monthly=月付、12 个月=年付，其余按「N 个月」，一次性=一次性。
  const cycleLabel = (cycle: string) => {
    const m = cycleMonths(cycle)
    if (m === 0) return "一次性"
    if (m === 1) return "月付"
    if (m === 12) return "年付"
    return Number.isNaN(m) ? cycle : `${m} 个月`
  }
  const now = new Date()
  const [view, setView] = useState({ y: now.getFullYear(), m: now.getMonth() })
  const [armed, setArmed] = useState<number | null>(null)
  const [busy, setBusy] = useState(false)

  const byDay = new Map<string, { id: number; name: string; expires_at: string; cycle: string; price: number; currency: string }[]>()
  for (const it of items) {
    const day = (it.expires_at ?? "").slice(0, 10)
    const arr = byDay.get(day) ?? []
    arr.push(it)
    byDay.set(day, arr)
  }
  const daysInMonth = new Date(view.y, view.m + 1, 0).getDate()
  const offset = (new Date(view.y, view.m, 1).getDay() + 6) % 7
  const key = (d: number) => `${view.y}-${String(view.m + 1).padStart(2, "0")}-${String(d).padStart(2, "0")}`
  const todayKey = `${now.getFullYear()}-${String(now.getMonth() + 1).padStart(2, "0")}-${String(now.getDate()).padStart(2, "0")}`
  const move = (delta: number) => {
    const d = new Date(view.y, view.m + delta, 1)
    setView({ y: d.getFullYear(), m: d.getMonth() })
  }
  const renew = async (id: number) => {
    if (armed !== id) {
      setArmed(id)
      setTimeout(() => setArmed((a) => (a === id ? null : a)), 3000)
      return
    }
    setBusy(true)
    try {
      const v = await api<{ expires_at: string }>(`/nodes/${id}/renew`, { method: "POST" })
      toast.success(`已续期到 ${v.expires_at}`)
      setArmed(null)
      onRenewed()
    } catch (e) {
      toast.error((e as Error).message)
    } finally {
      setBusy(false)
    }
  }
  return (
    <div className="flex flex-col gap-3">
      <div className="flex items-center justify-between">
        <div className="text-sm font-semibold">续费日历</div>
        <div className="flex items-center gap-1">
          <Button variant="ghost" size="icon" className="size-7" onClick={() => move(-1)} aria-label="上个月">
            <ChevronLeft className="size-4" />
          </Button>
          <span className="min-w-20 text-center text-xs font-medium">
            {view.y} 年 {view.m + 1} 月
          </span>
          <Button variant="ghost" size="icon" className="size-7" onClick={() => move(1)} aria-label="下个月">
            <ChevronRight className="size-4" />
          </Button>
        </div>
      </div>
      <div className="grid grid-cols-7 gap-1 text-center text-xs text-muted-foreground">
        {["一", "二", "三", "四", "五", "六", "日"].map((w) => (
          <span key={w}>{w}</span>
        ))}
      </div>
      <div className="grid grid-cols-7 gap-1">
        {Array.from({ length: offset }, (_, i) => (
          <span key={`pad-${i}`} />
        ))}
        {Array.from({ length: daysInMonth }, (_, i) => {
          const d = i + 1
          const k = key(d)
          const list = byDay.get(k)
          const isToday = k === todayKey
          // 到期日弹层（对齐参考稿）：点日格浮出当天的机器列表，悬浮在日历
          // 上方——此前内联渲染在网格下方，月份一有到期卡片就被撑长。
          const cell = (interactive: boolean) => (
            <button
              type="button"
              className={`flex h-11 w-full flex-col items-center justify-center gap-0.5 rounded-md text-xs transition-colors ${
                interactive ? "hover:bg-muted data-[state=open]:bg-primary/15" : ""
              } ${isToday ? "font-bold text-primary" : ""}`}
            >
              <span>{d}</span>
              {list?.length ? (
                <span className="text-[10px] leading-none text-primary">{list.length} 台</span>
              ) : (
                <span className="h-2.5" />
              )}
            </button>
          )
          if (!list?.length) {
            return <span key={k} className="contents">{cell(false)}</span>
          }
          return (
            <Popover key={k}>
              <PopoverTrigger asChild>{cell(true)}</PopoverTrigger>
              <PopoverContent className="w-72 p-0" align="center" onOpenAutoFocus={(e) => e.preventDefault()}>
                <div className="flex items-center justify-between border-b px-3 py-2">
                  <span className="text-sm font-semibold">
                    {view.m + 1}月{d}日
                  </span>
                  <span className="text-xs text-muted-foreground">{list.length} 台</span>
                </div>
                <div className="flex flex-col gap-1.5 px-3 py-2.5">
                  {list.map((it) => (
                    <div key={it.id} className="flex items-center justify-between gap-2 text-sm">
                      <span className="truncate font-medium">{it.name}</span>
                      <span className="flex shrink-0 items-center gap-2">
                        {/* 日期与浮层头部重复（byDay 按日分组，行内恒同一天），不重复渲染 */}
                        {it.price > 0 && (
                          <span className="shrink-0 text-xs text-muted-foreground">
                            {money(it.price, it.currency)} / {cycleLabel(it.cycle)}
                          </span>
                        )}
                        <Button
                          variant={armed === it.id ? "destructive" : "outline"}
                          size="sm"
                          className="h-7 px-2 text-xs"
                          disabled={busy}
                          onClick={() => renew(it.id)}
                        >
                          {armed === it.id ? "确认续期" : "续期"}
                        </Button>
                      </span>
                    </div>
                  ))}
                </div>
              </PopoverContent>
            </Popover>
          )
        })}
      </div>
    </div>
  )
}
