// 页头组件（impeccable critique 一致性收敛）：18px semibold 标题 + 一句话
// 描述 + 右侧 actions 槽。Operate 面板靠「我在哪、这页管什么」维持扫读。
export function PageHeader({ title, description, actions }: { title: string; description?: string; actions?: React.ReactNode }) {
  return (
    <div className="flex items-start justify-between gap-4">
      <div className="min-w-0">
        <h1 className="text-lg font-semibold tracking-tight">{title}</h1>
        {description && <p className="text-sm text-muted-foreground">{description}</p>}
      </div>
      {actions && <div className="flex shrink-0 items-center gap-2">{actions}</div>}
    </div>
  )
}
