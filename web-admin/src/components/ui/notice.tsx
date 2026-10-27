import { AlertTriangle } from "lucide-react"

// 警示横幅的唯一出口：此前 4 处 amber 横幅各写一遍（只有 1 处带 dark 变体），
// 收敛到 --warn token，明暗自动适配。
export function Notice({ children }: { children: React.ReactNode }) {
  return (
    <div className="flex items-start gap-2 rounded-md border border-warn/40 bg-warn/10 px-3 py-2 text-xs text-warn">
      <AlertTriangle className="mt-0.5 size-3.5 shrink-0" />
      <div className="min-w-0">{children}</div>
    </div>
  )
}
