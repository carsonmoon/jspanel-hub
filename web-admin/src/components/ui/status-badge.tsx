import { Badge } from "@/components/ui/badge"

// 实底语义徽标的唯一出口（impeccable critique 一致性收敛）：各页手写的
// bg-emerald-600/zinc-500/red-600 徽标全部走这里。tone → 语义色：
// ok=绿（在线/启用/正常/运行中）、off=灰（离线/停用/已停止）、
// danger=红（到期/超额/失败）、warn=琥珀（预警）。hover 类只在交互元素上
// 有意义，这里一律不带。
const TONE: Record<"ok" | "off" | "danger" | "warn", string> = {
  ok: "border-transparent bg-emerald-600 text-white",
  off: "border-transparent bg-zinc-500 text-white",
  danger: "border-transparent bg-red-600 text-white",
  warn: "border-transparent bg-amber-500 text-zinc-950",
}

export function StatusBadge({ tone, children, title }: { tone: keyof typeof TONE; children: React.ReactNode; title?: string }) {
  return (
    <Badge variant="outline" className={TONE[tone]} title={title}>
      {children}
    </Badge>
  )
}
