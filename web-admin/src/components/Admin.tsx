import { memo, useCallback, useEffect, useId, useRef, useState } from "react"
import { flushSync } from "react-dom"
import { ArrowUpCircle, Bell, CalendarClock, Check, ChevronDown, ChevronRight, CircleQuestionMark, Copy, Database, Download, Globe, GripVertical, Layers, LogOut, Monitor, Palette, Pencil, Plus, Radio, RefreshCw, Rss, Search, Send, Server, Settings, Shield, SlidersHorizontal, Trash2, Upload, Users as UsersIcon, Waypoints, ScrollText, LayoutDashboard } from "lucide-react"
import { toast } from "sonner"

import { Badge } from "@/components/ui/badge"
import { Button } from "@/components/ui/button"
import { Card } from "@/components/ui/card"
import { Dialog, DialogContent, DialogDescription, DialogFooter, DialogHeader, DialogTitle } from "@/components/ui/dialog"
import { Input } from "@/components/ui/input"
import { Label } from "@/components/ui/label"
import { Popover, PopoverAnchor, PopoverContent } from "@/components/ui/popover"
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select"
import { Switch } from "@/components/ui/switch"
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table"
import { Tooltip, TooltipContent, TooltipTrigger } from "@/components/ui/tooltip"
import { Skeleton } from "@/components/ui/skeleton"
import { StatusBadge } from "@/components/ui/status-badge"
import { api, badIfaceName, behind, changes, configFields, configForm, configOverrides, configSections, configValues, currentIface, fits, GIB, groupsOf, ifaceChoice, ifaceSpec, inGroup, outdatedAgents, provisioningSite, shortAddress, trafficCorrection, upload, type ConfigField, type IfaceChoice, type Node, type PingTask, type Source } from "@/lib/api"
import { bytes, cycleMonths, FOREVER, money, uptime } from "@/lib/format"

import Proxy from "@/components/Proxy"
import Overview from "@/components/Overview"
import Tunnel from "@/components/Tunnel"
import Logs from "@/components/Logs"
import Subscribe from "@/components/Subscribe"
import Users from "@/components/Users"

// Counters the panel can correct after migration or an accounting error.
const TRAFFIC_FIELDS = [
  ["total_rx", "累计下行"],
  ["total_tx", "累计上行"],
  ["month_rx", "本月下行"],
  ["month_tx", "本月上行"],
] as const
const TRAFFIC_MODES: Record<string, string> = {
  sum: "上下行相加",
  max: "取较大值",
  up: "仅上行",
  down: "仅下行",
}

// Displaced rows slide from where they were drawn to their new place: each is
// offset back by the distance it moved, then released. Transforms leave layout
// and stacking alone, so hit-testing mid-slide reads layout positions and the
// sticky header stays on top. A slide cut short restarts from where it was drawn.
function slide(rows: HTMLTableSectionElement | null, update: () => void) {
  const before = new Map([...(rows?.rows ?? [])].map((row) => [row, row.getBoundingClientRect().top]))
  for (const row of before.keys()) row.getAnimations().forEach((a) => a.id === "slide" && a.cancel())
  flushSync(update)
  if (matchMedia("(prefers-reduced-motion: reduce)").matches) return
  for (const [row, top] of before) {
    const dy = top - row.getBoundingClientRect().top
    if (dy) row.animate({ transform: [`translateY(${dy}px)`, "none"] }, { id: "slide", duration: 150, easing: "ease-out" })
  }
}

// Drag-to-reorder for a table whose order the hub stores at `/${path}/order`.
// Rows are displaced while the pointer is down and the whole order is saved on
// release, so a filtered table must disable its handles: the rows on screen are
// then not `order`.
function useDragOrder<T extends { id: number }>(items: T[], path: string, reload: () => void) {
  const [manualOrder, setManualOrder] = useState<number[]>([])
  const [dragging, setDragging] = useState<number | null>(null)
  const orderBeforeDrag = useRef<number[]>([])
  const body = useRef<HTMLTableSectionElement | null>(null)
  // One save in flight at a time, so two quick reorders reach the hub in order.
  const saving = useRef<Promise<unknown>>(Promise.resolve())
  const byId = new Map(items.map((item) => [item.id, item]))
  const orderedIds = new Set(manualOrder)
  const order = [
    ...manualOrder.map((id) => byId.get(id)).filter((item): item is T => Boolean(item)),
    ...items.filter((item) => !orderedIds.has(item.id)),
  ]
  const ids = () => order.map((item) => item.id)

  // Once the hub lists this order, its list is followed again, so a reorder made
  // in another tab appears here instead of being overwritten by the next drag.
  if (dragging === null && manualOrder.length && manualOrder.join() === items.map((item) => item.id).join()) {
    setManualOrder([])
  }

  // Handled on the document by layout position, not by the row under the
  // pointer: a sliding row is drawn away from its place, and the one under the
  // pointer mid-slide is not the one it would displace. Re-attached on every
  // render, since `order` changes as rows are displaced.
  //
  // Dragenter is accepted as well as dragover: over a new element the browser
  // fires only dragenter until its next update, and a release in between -- as
  // when a reorder brings another row under a still pointer -- would otherwise
  // count as a drop outside and restore the order.
  useEffect(() => {
    const rows = body.current
    if (dragging === null || !rows) return
    const over = (e: DragEvent) => {
      // The header row counts as inside: a drag to the top readily overshoots
      // onto it, and a release there would otherwise discard the drag.
      const table = rows.parentElement!.getBoundingClientRect()
      if (e.clientX < table.left || e.clientX > table.right || e.clientY < table.top || e.clientY > table.bottom) return
      e.preventDefault()
      if (e.type === "drop") return
      if (e.dataTransfer) e.dataTransfer.dropEffect = "move"
      const list = [...rows.rows]
      // Offsets count from the rows' container, which does not slide.
      const y = e.clientY - list[0].offsetParent!.getBoundingClientRect().top
      const from = list.findIndex((row) => row.dataset.id === String(dragging))
      const to = list.findIndex((row) => y >= row.offsetTop && y < row.offsetTop + row.offsetHeight)
      if (from < 0 || to < 0 || from === to) return
      // Moved only where the pointer would then rest on the dragged row. Rows
      // differ in height: a short row moved past a tall one would leave the
      // tall one under the pointer, and the two would swap back and forth.
      const target = list[to]
      const height = list[from].offsetHeight
      if (to > from ? y < target.offsetTop + target.offsetHeight - height : y >= target.offsetTop + height) return
      move(dragging, to)
    }
    const types = ["dragenter", "dragover", "drop"] as const
    for (const type of types) document.addEventListener(type, over)
    return () => {
      for (const type of types) document.removeEventListener(type, over)
    }
  })

  function move(id: number, to: number) {
    const next = [...ids()]
    const from = next.indexOf(id)
    if (from < 0 || to < 0 || to >= next.length || from === to) return
    next.splice(to, 0, ...next.splice(from, 1))
    slide(body.current, () => setManualOrder(next))
    return next
  }

  // Dropped outside the table or cancelled with Escape: the order is restored.
  function cancel() {
    setDragging(null)
    const before = orderBeforeDrag.current
    if (before.length) slide(body.current, () => setManualOrder(before))
  }

  function save(next: number[]) {
    setDragging(null)
    const before = orderBeforeDrag.current
    if (!before.length || next.join() === before.join()) return
    orderBeforeDrag.current = next
    const put = () => api(`/${path}/order`, { method: "PUT", body: JSON.stringify({ ids: next }) })
    // A refusal falls back to whatever the hub holds, which a save queued
    // behind it may still change.
    saving.current = saving.current.then(put).then(reload, (e: Error) => {
      setManualOrder([])
      reload()
      toast.error(e.message)
    })
  }

  return {
    order,
    row: (id: number) => ({
      "data-id": id,
      "data-dragging": dragging === id || undefined,
      // Opaque, with the dragged row beneath the rest: two rows crossing mid-slide
      // would otherwise draw their text over each other. No hover tint during a
      // drag, since the browser keeps it on whichever row reaches the start point.
      className: `relative z-1 bg-card transition-opacity data-[dragging]:z-0 data-[dragging]:opacity-40 ${dragging === null ? "" : "hover:bg-card"}`,
    }),
    handle: (id: number) => ({
      onDragStart: (e: React.DragEvent<HTMLElement>) => {
        orderBeforeDrag.current = ids()
        body.current = e.currentTarget.closest("tbody")
        setDragging(id)
        e.dataTransfer.effectAllowed = "move"
        // Firefox refuses to start a drag without a payload.
        e.dataTransfer.setData("text/plain", String(id))
      },
      onDragEnd: (e: React.DragEvent) => (e.dataTransfer.dropEffect === "none" ? cancel() : save(ids())),
      onKeyDown: (e: React.KeyboardEvent) => {
        const delta = e.key === "ArrowUp" ? -1 : e.key === "ArrowDown" ? 1 : 0
        if (!delta) return
        e.preventDefault()
        orderBeforeDrag.current = ids()
        body.current = e.currentTarget.closest("tbody")
        const next = move(id, ids().indexOf(id) + delta)
        if (next) save(next)
      },
    }),
  }
}

function DragHandle({ name, disabled, title = "拖动排序", ...events }: React.ComponentProps<"button"> & { name: string }) {
  return (
    <button
      type="button"
      draggable={!disabled}
      disabled={disabled}
      className="cursor-grab touch-none rounded p-1 text-muted-foreground hover:bg-muted hover:text-foreground active:cursor-grabbing disabled:cursor-default disabled:opacity-40 disabled:hover:bg-transparent"
      title={title}
      aria-label={`拖动 ${name} 排序`}
      {...events}
    >
      <GripVertical className="size-4" />
    </button>
  )
}

function copy(text: string, done = "已复制") {
  // navigator.clipboard exists only in a secure context. Over plain http the
  // copy command still works from a click, the clipboard filled from its event.
  if (!navigator.clipboard) {
    const put = (e: ClipboardEvent) => { e.clipboardData?.setData("text/plain", text); e.preventDefault() }
    document.addEventListener("copy", put)
    const ok = document.execCommand("copy")
    document.removeEventListener("copy", put)
    return ok ? toast.success(done) : toast.error("复制失败")
  }
  navigator.clipboard.writeText(text).then(
    () => toast.success(done),
    () => toast.error("复制失败"),
  )
}

const SOURCES: Record<Source, string> = {
  manual: "手动填写",
  interface: "网卡地址",
  exit: "hub 看到的出口，不在主机网卡上（NAT 或代理）",
  connection: "hub 看到的连接地址",
}

// The address a node is reached by, one per family, each click-to-copy: pasting
// one into an ssh command is why they are shown. Where each came from is in the
// tooltip, keeping the column to addresses alone.
//
// Drawn again only when the addresses change. The table re-renders on every
// push, and redrawing a tooltip per address would raise the panel's script time
// at a hundred nodes from 66 to 128 ms a second.
const Addresses = memo(
  function Addresses({ list }: { list: NonNullable<Node["addresses"]> }) {
    if (!list.length) return <span className="text-sm text-muted-foreground">—</span>
    return (
      // As wide as the longer address, so both tooltips open from one right
      // edge and the one for a short IPv4 does not cover the IPv6 below it.
      <div className="grid w-fit gap-y-0.5">
        {list.map(({ address, source }) => (
          // Beside the addresses rather than under one, where it would cover
          // the other; and gone once the pointer leaves it.
          <Tooltip key={address} disableHoverableContent>
            <TooltipTrigger asChild>
              <button
                type="button"
                // The toast names what was copied: a tap shows no tooltip, and
                // the cell may show the address shortened.
                onClick={() => copy(address, `已复制 ${address}`)}
                aria-label={`复制 ${address}`}
                className="tnum group inline-flex items-center gap-1 text-sm hover:text-foreground"
              >
                {shortAddress(address)}
                <Copy className="size-3 shrink-0 opacity-0 transition-opacity group-hover:opacity-100" />
              </button>
            </TooltipTrigger>
            <TooltipContent side="right" sideOffset={6} className="max-w-xs">
              <div className="tnum">{address}</div>
              <div className="opacity-70">{SOURCES[source]}，点击复制</div>
            </TooltipContent>
          </Tooltip>
        ))}
      </div>
    )
  },
  // Rows arrive as fresh objects on every push, so the list is compared by value.
  (a, b) => JSON.stringify(a.list) === JSON.stringify(b.list),
)

// Name, address, country and group: what a node is looked up by, in every node list.
function searchNodes(nodes: Node[], query: string) {
  const needle = query.trim().toLowerCase()
  if (!needle) return nodes
  return nodes.filter((n) =>
    [n.name, n.ip, n.ipv4, n.ipv6, n.ipv4_pin, n.ipv6_pin, n.country, n.group].some((v) => v?.toLowerCase().includes(needle)))
}

// A filter naming a group no node carries any more -- renamed, or its last node
// deleted -- falls back to all rather than showing an empty list; so does 未分组
// once no group is left, since the dropdown that would clear it is hidden then.
// Reset rather than masked, so the old filter does not return with a later group
// of the same name.
function useGroupFilter(nodes: Node[]) {
  const [filter, setFilter] = useState("all")
  const valid = filter === "all"
    || (filter === "none" ? nodes.some((n) => n.group) : nodes.some((n) => n.group === filter.slice(1)))
  if (!valid) setFilter("all")
  return [valid ? filter : "all", setFilter] as const
}

// Offered once some node has a group. 未分组 is where a batch of freshly
// registered machines waits to be assigned one.
function GroupFilter({ nodes, value, onChange, className = "" }: {
  nodes: Node[]
  value: string
  onChange: (value: string) => void
  className?: string
}) {
  const groups = groupsOf(nodes)
  if (!groups.length) return null
  return (
    <Select value={value} onValueChange={onChange}>
      <SelectTrigger className={className} aria-label="按分组筛选"><SelectValue /></SelectTrigger>
      <SelectContent position="popper">
        <SelectItem value="all">全部分组</SelectItem>
        {groups.map((g) => <SelectItem key={g} value={`=${g}`}>{g}</SelectItem>)}
        <SelectItem value="none">未分组</SelectItem>
      </SelectContent>
    </Select>
  )
}

function NodeSearch({ value, onChange, className = "" }: { value: string; onChange: (value: string) => void; className?: string }) {
  return (
    <div className={`relative ${className}`}>
      <Search className="pointer-events-none absolute top-1/2 left-2.5 size-4 -translate-y-1/2 text-muted-foreground" />
      <Input
        className="pl-8"
        placeholder="名称/地址/地区/分组"
        aria-label="搜索主机"
        value={value}
        onChange={(e) => onChange(e.target.value)}
        // Inside a dialog's form, Enter would otherwise save the dialog.
        onKeyDown={(e) => e.key === "Enter" && e.preventDefault()}
      />
    </div>
  )
}

// Ticks nodes in a searchable grid. 全选 and 全不选 act on the rows in view, so a
// search or a group narrows what they touch: pick a group, then 全选. Offline
// nodes are dimmed but remain selectable.
function NodePicker({ nodes, chosen, onPick, disabled = false }: {
  nodes: Node[]
  chosen: Set<number>
  onPick: (list: Node[], on: boolean) => void
  disabled?: boolean
}) {
  const [query, setQuery] = useState("")
  const [group, setGroup] = useGroupFilter(nodes)
  // The unfiltered list's height, held as its floor: in a centred dialog a
  // shrinking list would move the search box out from under the cursor.
  const [listHeight, setListHeight] = useState(0)
  const visible = inGroup(searchNodes(nodes, query), group)
  const visibleChosen = visible.filter((n) => chosen.has(n.id)).length
  return (
    <div className="rounded-lg border">
      <div className="flex flex-wrap items-center gap-1 border-b p-2">
        <NodeSearch className="min-w-0 flex-1 basis-40" value={query} onChange={setQuery} />
        <GroupFilter nodes={nodes} value={group} onChange={setGroup} className="w-32" />
        <Button type="button" size="sm" variant="ghost" className="px-2.5" disabled={disabled || visibleChosen === visible.length} onClick={() => onPick(visible, true)}>全选</Button>
        <Button type="button" size="sm" variant="ghost" className="px-2.5" disabled={disabled || visibleChosen === 0} onClick={() => onPick(visible, false)}>全不选</Button>
      </div>
      {/* Three columns keep a few dozen nodes within one scroll. A phone gets
          one: two cut a name to a few characters, and a tap shows no title. */}
      <div
        ref={(el) => { if (el && !listHeight) setListHeight(el.offsetHeight) }}
        // Capped like the height itself, which a min-height would otherwise
        // override once the viewport shrinks.
        style={{ minHeight: listHeight ? `min(${listHeight}px, 16rem, 40dvh)` : undefined }}
        className="grid max-h-[min(16rem,40dvh)] grid-cols-1 content-start gap-0.5 overflow-y-auto p-1.5 min-[480px]:grid-cols-2 sm:grid-cols-3"
      >
        {visible.map((n) => (
          <label key={n.id} title={n.group ? `${n.name} · ${n.group}` : n.name} className="flex min-w-0 cursor-pointer items-center gap-2 rounded-md px-2 py-1.5 text-sm hover:bg-muted">
            <input type="checkbox" checked={chosen.has(n.id)} disabled={disabled} onChange={(e) => onPick([n], e.target.checked)} className="shrink-0 accent-primary" />
            <span className={`truncate ${n.online ? "" : "text-muted-foreground"}`}>{n.name}</span>
            {n.country && <span className="ml-auto shrink-0 text-xs text-muted-foreground">{n.country}</span>}
          </label>
        ))}
        {!visible.length && (
          <p className="col-span-full p-2 text-xs text-muted-foreground">{nodes.length ? "没有匹配的主机" : "先添加主机"}</p>
        )}
      </div>
    </div>
  )
}

// Every command the panel hands out. break-all because a token has no spaces to
// wrap at.
function Command({ className = "", children }: { className?: string; children: React.ReactNode }) {
  return (
    <pre className={`overflow-auto whitespace-pre-wrap break-all rounded-lg border bg-muted/40 p-3 text-xs leading-relaxed select-all ${className}`}>
      {children}
    </pre>
  )
}

function Field({ label, hint, help, className = "", children }: {
  label: string
  hint?: string
  help?: React.ReactNode
  className?: string
  children: React.ReactNode
}) {
  const title = <Label className="text-sm font-medium">{label}</Label>
  return (
    <div className={`space-y-2 ${className}`}>
      {help ? <div className="flex items-center gap-1.5">{title}<Help>{help}</Help></div> : title}
      {children}
      {hint && <p className="text-xs leading-relaxed text-muted-foreground">{hint}</p>}
    </div>
  )
}

// A tap shows no tooltip on its own, so a click opens it as well. The trigger's
// own handlers would close it on press and on click; both are prevented.
function Help({ children }: { children: React.ReactNode }) {
  const [open, setOpen] = useState(false)
  return (
    <Tooltip open={open} onOpenChange={setOpen}>
      <TooltipTrigger asChild>
        <button
          type="button"
          aria-label="说明"
          className="text-muted-foreground hover:text-foreground"
          onPointerDown={(e) => e.preventDefault()}
          onClick={(e) => {
            e.preventDefault()
            setOpen(true)
          }}
        >
          <CircleQuestionMark className="size-3.5" />
        </button>
      </TooltipTrigger>
      <TooltipContent className="max-w-64 space-y-1 text-left">{children}</TooltipContent>
    </Tooltip>
  )
}

// A titled option with its control at the right. `toggle` makes the whole row a
// label, so a click anywhere flips the Switch it holds; `below` opens beneath it
// in the same card.
function OptionRow({ title, hint, toggle = false, below, children }: {
  title: React.ReactNode
  hint?: React.ReactNode
  toggle?: boolean
  below?: React.ReactNode
  children: React.ReactNode
}) {
  const Row = toggle ? "label" : "div"
  return (
    <div className="flex flex-col rounded-lg border bg-muted/30 text-sm">
      {/* flex-1: stretched by a grid, the row fills the card and stays clickable. */}
      <Row className={`flex flex-1 items-center justify-between gap-4 px-3 py-2.5 ${toggle ? "cursor-pointer" : ""}`}>
        <span>
          <span className="block font-medium">{title}</span>
          {hint && <span className="mt-0.5 block text-xs text-muted-foreground">{hint}</span>}
        </span>
        {children}
      </Row>
      {below && <div className="border-t px-3 pt-3 pb-3.5">{below}</div>}
    </div>
  )
}

// Free text, with the groups already in use offered, so a group is picked
// rather than retyped, where a typo would start a second one. A list of its own
// rather than a <datalist>: Chrome draws that as a tooltip and filters it by the
// text already in the box, so a grouped node was offered only its own group.
// The whole list shows on opening; typing narrows it without highlighting, so
// Enter keeps a new name that merely prefixes an existing one.
function GroupInput({ nodes, value, onChange }: {
  nodes: Pick<Node, "group">[]
  value: string
  onChange: (value: string) => void
}) {
  const id = useId()
  const [open, setOpen] = useState(false)
  const [typed, setTyped] = useState(false)
  const [active, setActive] = useState(0)
  const input = useRef<HTMLInputElement>(null)
  const counts = new Map<string, number>()
  for (const n of nodes) if (n.group) counts.set(n.group, (counts.get(n.group) ?? 0) + 1)
  const name = value.trim()
  const query = typed ? name.toLowerCase() : ""
  const matches = [...counts.keys()].filter((g) => g.toLowerCase().includes(query))
  // "" is 未分组, offered last while the list is not being narrowed.
  const items = query ? matches : [...matches, ""]
  const fresh = typed && name !== "" && !counts.has(name)
  const shown = open && (matches.length > 0 || fresh)

  useEffect(() => {
    if (shown) document.getElementById(`${id}-${active}`)?.scrollIntoView({ block: "nearest" })
  }, [id, active, shown])

  const show = () => {
    setTyped(false)
    setActive(Math.max(0, [...counts.keys(), ""].indexOf(name)))
    setOpen(true)
  }
  const pick = (group: string) => {
    onChange(group)
    setTyped(false)
    setOpen(false)
  }
  const onKeyDown = (e: React.KeyboardEvent) => {
    if (e.key === "ArrowDown" || e.key === "ArrowUp") {
      e.preventDefault()
      if (!shown) return show()
      if (!items.length) return
      const down = e.key === "ArrowDown"
      setActive((i) => (i < 0 ? (down ? 0 : items.length - 1) : (i + (down ? 1 : -1) + items.length) % items.length))
    } else if (e.key === "Enter" && shown) {
      e.preventDefault()
      if (items[active] !== undefined) pick(items[active])
      else setOpen(false)
    }
  }

  if (!counts.size) {
    return <Input maxLength={13} value={value} onChange={(e) => onChange(e.target.value)} placeholder="未分组" />
  }
  return (
    <Popover open={shown} onOpenChange={setOpen}>
      <PopoverAnchor asChild>
        <div className="relative">
          <Input
            ref={input}
            role="combobox"
            aria-expanded={shown}
            aria-controls={id}
            aria-autocomplete="list"
            aria-activedescendant={shown && items[active] !== undefined ? `${id}-${active}` : undefined}
            maxLength={13}
            value={value}
            placeholder="未分组"
            className="pr-9"
            onChange={(e) => {
              onChange(e.target.value)
              setTyped(true)
              setActive(-1)
              setOpen(true)
            }}
            onClick={show}
            onKeyDown={onKeyDown}
          />
          {/* Not a tab stop, and keeps the focus in the box it opens a list for. */}
          <button
            type="button"
            tabIndex={-1}
            aria-label="选择分组"
            className="absolute inset-y-0 right-0 flex w-9 items-center justify-center text-muted-foreground"
            onMouseDown={(e) => {
              e.preventDefault()
              if (shown) return setOpen(false)
              input.current?.focus()
              show()
            }}
          >
            <ChevronDown className={`size-4 opacity-50 transition-transform ${shown ? "rotate-180" : ""}`} />
          </button>
        </div>
      </PopoverAnchor>
      <PopoverContent
        align="start"
        className="w-(--radix-popover-trigger-width) p-1"
        onOpenAutoFocus={(e) => e.preventDefault()}
        onCloseAutoFocus={(e) => e.preventDefault()}
        // The box and its button sit outside the list; pressing them is not a dismissal.
        onInteractOutside={(e) => input.current?.parentElement?.contains(e.target as Element) && e.preventDefault()}
        onMouseDown={(e) => e.preventDefault()}
      >
        <div role="listbox" id={id} aria-label="已有分组" className="max-h-60 overflow-y-auto">
          {items.map((group, i) => (
            <div key={group || "\0"}>
              {group === "" && <div className="my-1 h-px bg-border" />}
              <div
                id={`${id}-${i}`}
                role="option"
                aria-selected={group === name}
                onMouseEnter={() => setActive(i)}
                onClick={() => pick(group)}
                className={`relative flex cursor-default items-center gap-2 rounded-sm py-1.5 pr-8 pl-2 text-sm select-none ${i === active ? "bg-accent text-accent-foreground" : ""}`}
              >
                <span className={`truncate ${group ? "" : "text-muted-foreground"}`}>{group || "未分组"}</span>
                {group && <span className="tnum ml-auto shrink-0 text-xs text-muted-foreground">{counts.get(group)} 台</span>}
                {group === name && <Check className="absolute right-2 size-4" />}
              </div>
            </div>
          ))}
          {fresh && <p className="px-2 py-1.5 text-xs text-muted-foreground">新分组「{name}」，保存后生效</p>}
        </div>
      </PopoverContent>
    </Popover>
  )
}

// Puts the nodes ticked here into one group, or, with the name left empty, out
// of any. Renaming or dissolving a group is the same act: filter the picker to
// it, tick all, then type the new name or clear it. One request, applied to all
// of them or none.
function GroupDialog({ nodes, onClose, onSaved }: { nodes: Node[]; onClose: () => void; onSaved: () => void }) {
  const [name, setName] = useState("")
  const [chosen, setChosen] = useState<Set<number>>(new Set())
  const [saving, setSaving] = useState(false)
  const group = name.trim()
  // Counted against the live list, so a node deleted meanwhile is not sent.
  const ids = nodes.filter((n) => chosen.has(n.id)).map((n) => n.id)
  const pick = (list: Node[], on: boolean) =>
    setChosen((old) => {
      const next = new Set(old)
      for (const n of list) {
        if (on) next.add(n.id)
        else next.delete(n.id)
      }
      return next
    })

  async function save() {
    setSaving(true)
    try {
      await api("/nodes/batch", { method: "PUT", body: JSON.stringify({ ids, patch: { group } }) })
      toast.success(group ? `已把 ${ids.length} 台设为「${group}」` : `已把 ${ids.length} 台移出分组`)
      onClose()
      onSaved()
    } catch (e) {
      toast.error((e as Error).message)
    } finally {
      setSaving(false)
    }
  }

  return (
    <Dialog open onOpenChange={(open) => !open && onClose()}>
      <DialogContent onOpenAutoFocus={(e) => e.preventDefault()} className="sm:max-w-2xl">
        <DialogHeader>
          <DialogTitle>设置分组</DialogTitle>
          <DialogDescription className="leading-relaxed">
            勾选主机，设为同一个分组。改名或解散：先筛选出这个分组、全选，再填新名字或清空。
          </DialogDescription>
        </DialogHeader>
        <form noValidate className="contents" onSubmit={(e) => { e.preventDefault(); save() }}>
          <div className="space-y-4">
            <Field label="分组名" hint="公开页可见，最多 13 字；留空为移出分组">
              <GroupInput nodes={nodes} value={name} onChange={setName} />
            </Field>
            <NodePicker nodes={nodes} chosen={chosen} onPick={pick} />
          </div>
          <DialogFooter>
            <Button type="button" variant="ghost" onClick={onClose}>取消</Button>
            <Button type="submit" disabled={saving || !ids.length} className="max-w-full gap-0">
              <span className="truncate">{group ? `设为「${group}」` : "移出分组"}</span>
              {ids.length > 0 && <span className="tnum shrink-0">（{ids.length} 台）</span>}
            </Button>
          </DialogFooter>
        </form>
      </DialogContent>
    </Dialog>
  )
}

export function ConfirmDialog({ title, description, confirmLabel, busy = false, onClose, onConfirm, children }: {
  title: string
  description: string
  confirmLabel: string
  busy?: boolean
  onClose: () => void
  onConfirm: () => void
  children?: React.ReactNode
}) {
  return (
    <Dialog open onOpenChange={(open) => !open && onClose()}>
      <DialogContent className="sm:max-w-md">
        <DialogHeader>
          <DialogTitle>{title}</DialogTitle>
          <DialogDescription className="leading-relaxed">{description}</DialogDescription>
        </DialogHeader>
        {children}
        <DialogFooter className="border-t pt-4">
          <Button variant="ghost" onClick={onClose}>取消</Button>
          <Button variant="destructive" onClick={onConfirm} disabled={busy}>{confirmLabel}</Button>
        </DialogFooter>
      </DialogContent>
    </Dialog>
  )
}

function CreateNode({ onClose, onSaved }: {
  onClose: () => void
  onSaved: (id: number) => void
}) {
  const [name, setName] = useState("")
  const [saving, setSaving] = useState(false)

  async function save(e: React.FormEvent) {
    e.preventDefault()
    if (!name.trim()) return toast.error("请填写主机名称")
    setSaving(true)
    try {
      const { id } = await api<{ id: number }>("/nodes", {
        method: "POST",
        body: JSON.stringify({ name: name.trim() }),
      })
      toast.success("主机已添加")
      onClose()
      onSaved(id)
    } catch (e) {
      toast.error((e as Error).message)
    } finally {
      setSaving(false)
    }
  }

  return (
    <Dialog open onOpenChange={(open) => !open && onClose()}>
      <DialogContent className="sm:max-w-md">
        <DialogHeader>
          <DialogTitle>添加主机</DialogTitle>
        </DialogHeader>
        <form className="space-y-4" onSubmit={save}>
          <Field label="名称">
            <Input autoFocus value={name} onChange={(e) => setName(e.target.value)} placeholder="香港 · 甲商家" />
          </Field>
          <DialogFooter className="border-t pt-4">
            <Button type="button" variant="ghost" onClick={onClose}>取消</Button>
            <Button type="submit" disabled={saving}>添加</Button>
          </DialogFooter>
        </form>
      </DialogContent>
    </Dialog>
  )
}

function NodeForm({ node, nodes, onClose, onSaved }: {
  node: Node
  nodes: Node[]
  onClose: () => void
  onSaved: () => void
}) {
  const [form, setForm] = useState(node)
  const [limitGib, setLimitGib] = useState(String(node.traffic_limit / GIB || ""))
  // Text, as the limit is: a number state turns an emptied box into 0.
  const [resetDay, setResetDay] = useState(String(node.traffic_reset_day))
  const [saving, setSaving] = useState(false)
  const gib = (bytes: number) => String(Number((bytes / GIB).toFixed(3)))
  const [traffic, setTraffic] = useState(() =>
    Object.fromEntries(TRAFFIC_FIELDS.map(([k]) => [k, gib(node[k])])) as Record<string, string>,
  )
  // Compared as entered rather than as bytes: rounding to GB would read as an
  // edit and zero a node that has transferred a few MB.
  const pristine = useRef(traffic)
  const set = <K extends keyof Node>(k: K, v: Node[K]) => setForm((f) => ({ ...f, [k]: v }))
  // What each address box falls back to when left empty.
  const automatic = (v6: boolean) => (v6 ? node.ipv6_auto : node.ipv4_auto) || "无"

  async function save() {
    if (!form.name.trim()) return toast.error("请填写主机名称")
    const resetOn = Number(resetDay)
    if (!Number.isInteger(resetOn) || resetOn < 1 || resetOn > 31) return toast.error("每月重置日要填 1–31 之间的整数")
    const patch = changes(node, {
      name: form.name.trim(),
      public: form.public,
      group: (form.group ?? "").trim(),
      traffic_mode: form.traffic_mode,
      traffic_limit: Math.round(Number(limitGib) * GIB),
      traffic_reset_day: resetOn,
      notify: !!form.notify,
      ipv4_pin: (form.ipv4_pin ?? "").trim(),
      ipv6_pin: (form.ipv6_pin ?? "").trim(),
      country_pin: (form.country_pin ?? "").trim().toUpperCase(),
      dns_name: (form.dns_name ?? "").trim(),
    })
    const correction = trafficCorrection(pristine.current, traffic)
    if ([patch.traffic_limit, ...Object.values(correction)].some((v) => v !== undefined && (!Number.isSafeInteger(v) || v < 0))) {
      return toast.error("流量必须是有效的非负数，且不能超出精确计数范围")
    }
    setSaving(true)
    try {
      // The correction belongs to the new reset period, so its day is saved
      // first.
      if (Object.keys(patch).length) {
        await api(`/nodes/${node.id}`, { method: "PUT", body: JSON.stringify(patch) })
      }
      if (Object.keys(correction).length) {
        await api(`/nodes/${node.id}/traffic`, {
          method: "PUT",
          body: JSON.stringify(correction),
        })
      }
      toast.success("主机设置已保存")
      onClose()
      onSaved()
    } catch (e) {
      toast.error((e as Error).message)
    } finally {
      setSaving(false)
    }
  }

  return (
    <Dialog open onOpenChange={(open) => !open && onClose()}>
      <DialogContent onOpenAutoFocus={(e) => e.preventDefault()} className="sm:max-w-2xl">
        <DialogHeader>
          <DialogTitle>{node.name}</DialogTitle>
        </DialogHeader>
        {/* noValidate here and in the other dialogs: save() checks every field.
            The browser's own check would refuse a fractional GB against the
            default step of 1, and cannot point at a field folded inside
            流量校正, so the save button would do nothing. */}
        <form noValidate className="contents" onSubmit={(e) => { e.preventDefault(); save() }}>
          <div className="space-y-6">
            <section className="space-y-4">
              <div className="grid gap-4 sm:grid-cols-2">
                <Field label="名称">
                  <Input value={form.name} onChange={(e) => set("name", e.target.value)} />
                </Field>
                <Field label="分组" hint="公开页可见，留空为未分组">
                  <GroupInput nodes={nodes} value={form.group ?? ""} onChange={(v) => set("group", v)} />
                </Field>
              </div>
              <div className="grid gap-3 sm:grid-cols-2">
                <OptionRow title="公开显示" hint="关闭后只在管理后台可见" toggle>
                  <Switch checked={form.public} onCheckedChange={(v) => set("public", v)} />
                </OptionRow>
                <OptionRow title="离线通知" hint="掉线超过宽限期、恢复时各推一条" toggle>
                  <Switch checked={!!form.notify} onCheckedChange={(v) => set("notify", v)} />
                </OptionRow>
              </div>
            </section>
            <section className="space-y-3 border-t pt-5">
              <h3 className="text-sm font-semibold">流量</h3>
              {/* On a phone the two short numbers share a row, the mode takes
                  the next; dense packing restores the order from sm up. */}
              <div className="grid grid-flow-row-dense grid-cols-2 gap-4 sm:grid-cols-3">
                <Field label="每月额度 (GB)" hint="留空或 0 不限">
                  <Input type="number" value={limitGib} onChange={(e) => setLimitGib(e.target.value)} placeholder="1024" />
                </Field>
                <Field label="计算方式" className="col-span-2 sm:col-span-1">
                  <Select value={form.traffic_mode} onValueChange={(v) => set("traffic_mode", v)}>
                    <SelectTrigger className="w-full"><SelectValue /></SelectTrigger>
                    <SelectContent position="popper">
                      {Object.entries(TRAFFIC_MODES).map(([k, v]) => (
                        <SelectItem key={k} value={k}>{v}</SelectItem>
                      ))}
                    </SelectContent>
                  </Select>
                </Field>
                <Field label="每月重置日" hint="1–31，改后本月重算，总量不变">
                  <Input type="number" min={1} max={31} value={resetDay} onChange={(e) => setResetDay(e.target.value)} />
                </Field>
              </div>
              <details className="rounded-lg border bg-muted/30 px-3 py-2.5">
                <summary className="cursor-pointer text-sm font-medium">流量校正</summary>
                <p className="mt-2 text-xs leading-relaxed text-muted-foreground">
                  按 GB 填入需要校正的值，未修改的计数器继续正常累计。
                </p>
                <div className="mt-3 grid grid-cols-2 gap-4">
                  {TRAFFIC_FIELDS.map(([key, label]) => (
                    <Field key={key} label={`${label} (GB)`}>
                      <Input
                        type="number"
                        step="0.001"
                        value={traffic[key]}
                        onChange={(e) => setTraffic((t) => ({ ...t, [key]: e.target.value }))}
                      />
                    </Field>
                  ))}
                </div>
              </details>
            </section>
            <section className="space-y-3 border-t pt-5">
              <h3 className="text-sm font-semibold">地址与地区</h3>
              <div className="grid grid-flow-row-dense grid-cols-[1fr_5rem] gap-4 sm:grid-cols-[1fr_1.4fr_6rem]">
                <Field label="IPv4">
                  <Input value={form.ipv4_pin ?? ""} onChange={(e) => set("ipv4_pin", e.target.value)} placeholder={`自动：${automatic(false)}`} />
                </Field>
                <Field label="IPv6" className="col-span-full sm:col-span-1">
                  <Input value={form.ipv6_pin ?? ""} onChange={(e) => set("ipv6_pin", e.target.value)} placeholder={`自动：${automatic(true)}`} />
                </Field>
                <p className="col-span-full text-xs leading-relaxed text-muted-foreground">
                  留空为自动。国家/地区填两位代码，如 CN；手填的值会一直显示，IP 变了要自己改。
                </p>
                <Field
                  label="绑定域名（DDNS）"
                  hint="公网 IP 变化时自动更新这条 A 记录（需在设置页配 Cloudflare Token）；入口故障转移切备用机时翻的也是它。留空不参与"
                  className="col-span-full"
                >
                  <div className="flex items-center gap-1.5">
                    <Input
                      value={form.dns_name ?? ""}
                      onChange={(e) => set("dns_name", e.target.value.replace(/\s/g, ""))}
                      placeholder="如 hk.example.com"
                      spellCheck={false}
                    />
                    <Button
                      variant="outline"
                      size="sm"
                      disabled={!(form.dns_name ?? "").trim()}
                      onClick={async () => {
                        // 先存再同步：域名刚改过也立即生效。
                        try {
                          const patch = changes(node, { dns_name: (form.dns_name ?? "").trim() })
                          if (Object.keys(patch).length) await api(`/nodes/${node.id}`, { method: "PUT", body: JSON.stringify(patch) })
                          const r = await api<{ ok: boolean; ip: string }>(`/nodes/${node.id}/dns-sync`, { method: "POST" })
                          toast.success(`已同步：${r.ip}`)
                          onSaved()
                        } catch (e) {
                          toast.error((e as Error).message)
                        }
                      }}
                    >
                      立即同步
                    </Button>
                  </div>
                  {node.dns_ip && <p className="mt-1 text-xs text-muted-foreground">当前记录：{node.dns_ip}</p>}
                </Field>
                <Field label="国家/地区">
                  <Input
                    value={form.country_pin ?? ""}
                    maxLength={2}
                    onChange={(e) => set("country_pin", e.target.value.toUpperCase())}
                    placeholder={`自动：${node.country_auto || "无"}`}
                  />
                </Field>
              </div>
            </section>
          </div>
          <DialogFooter>
            <Button type="button" variant="ghost" onClick={onClose}>取消</Button>
            <Button type="submit" disabled={saving}>保存</Button>
          </DialogFooter>
        </form>
      </DialogContent>
    </Dialog>
  )
}

const CURRENCY_NAMES = new Intl.DisplayNames(["zh-CN"], { type: "currency" })

// The name confirms a code the hub can only check the shape of. DisplayNames
// echoes back a code outside ISO 4217 and throws on anything but three letters,
// which the hub refuses with its own message.
function currencyHint(code: string) {
  try {
    const name = CURRENCY_NAMES.of(code)
    return name === code ? "未知代码，照原样显示" : name
  } catch {
    return undefined
  }
}

function BillingForm({ node, onClose, onSaved }: {
  node: Node
  onClose: () => void
  onSaved: () => void
}) {
  const [form, setForm] = useState(node)
  // Text rather than a number: a numeric state cannot represent an empty field,
  // so clearing it would snap back to 0 mid-entry. Empty means free.
  const [price, setPrice] = useState(node.price > 0 ? String(node.price) : "")
  // Whole years are entered in years, the way a five-year plan is sold.
  const months = cycleMonths(node.billing_cycle)
  const [unit, setUnit] = useState(months === 0 ? "once" : months % 12 ? "months" : "years")
  const [count, setCount] = useState(String(months % 12 ? months : months / 12 || 1))
  const [saving, setSaving] = useState(false)
  const set = <K extends keyof Node>(k: K, v: Node[K]) => setForm((f) => ({ ...f, [k]: v }))

  async function save() {
    // The hub refuses a length out of range and stores a named one by name, so
    // an unchanged length is compared in months, not in spelling.
    const cycle = unit === "once" ? "once" : `${Number(count) * (unit === "years" ? 12 : 1)}m`
    setSaving(true)
    try {
      await api(`/nodes/${node.id}`, {
        method: "PUT",
        body: JSON.stringify(changes(node, {
          price: Math.max(0, Number(price) || 0),
          currency: form.currency,
          billing_cycle: cycleMonths(cycle) === months ? node.billing_cycle : cycle,
          expires_at: form.expires_at || null,
          purchase_url: (form.purchase_url ?? "").trim(),
        })),
      })
      toast.success("续费设置已保存")
      onClose()
      onSaved()
    } catch (e) {
      toast.error((e as Error).message)
    } finally {
      setSaving(false)
    }
  }

  return (
    <Dialog open onOpenChange={(open) => !open && onClose()}>
      <DialogContent onOpenAutoFocus={(e) => e.preventDefault()} className="sm:max-w-md">
        <DialogHeader>
          <DialogTitle>{node.name}</DialogTitle>
        </DialogHeader>
        <form noValidate className="contents" onSubmit={(e) => { e.preventDefault(); save() }}>
          <div className="space-y-5">
            <div className="grid grid-cols-2 gap-4">
              <Field label="价格" hint="留空或 0 为免费">
                <Input
                  type="number"
                  min="0"
                  step="0.01"
                  value={price}
                  onChange={(e) => setPrice(e.target.value)}
                  placeholder="免费"
                />
              </Field>
              <Field
                label="货币"
                hint={currencyHint(form.currency.toUpperCase())}
                help={
                  <>
                    <p>填三个字母的货币代码，大小写都行。</p>
                    <p>
                      例如：
                      {["美元 USD", "人民币 CNY", "港币 HKD", "新台币 TWD", "欧元 EUR", "日元 JPY"].map((c, i) => (
                        <span key={c}>{i > 0 && "、"}<span className="whitespace-nowrap">{c}</span></span>
                      ))}
                    </p>
                  </>
                }
              >
                {/* Uppercased by CSS: rewriting the value mid-composition would
                    break an input method, and the hub stores it uppercased. */}
                <Input
                  maxLength={3}
                  autoCapitalize="characters"
                  spellCheck={false}
                  className="uppercase"
                  value={form.currency}
                  onChange={(e) => set("currency", e.target.value)}
                  placeholder="USD"
                />
              </Field>
            </div>
            <div className="grid grid-cols-2 gap-4">
              <Field label="付款周期">
                <div className="flex gap-2">
                  {unit !== "once" && (
                    <Input
                      type="number"
                      min="1"
                      step="1"
                      aria-label="周期长度"
                      className="w-16"
                      value={count}
                      onChange={(e) => setCount(e.target.value)}
                    />
                  )}
                  <Select value={unit} onValueChange={setUnit}>
                    <SelectTrigger className="min-w-0 flex-1"><SelectValue /></SelectTrigger>
                    <SelectContent position="popper">
                      <SelectItem value="months">月</SelectItem>
                      <SelectItem value="years">年</SelectItem>
                      <SelectItem value="once">一次性</SelectItem>
                    </SelectContent>
                  </Select>
                </div>
              </Field>
              <Field label="到期时间">
                <Input type="date" value={form.expires_at ?? ""} onChange={(e) => set("expires_at", e.target.value)} />
              </Field>
            </div>
            <Field label="购买网站" hint="保存后主机名可点击，新标签打开">
              <Input
                value={form.purchase_url ?? ""}
                onChange={(e) => set("purchase_url", e.target.value)}
                placeholder="https://example.com"
                spellCheck={false}
              />
            </Field>
          </div>
          <DialogFooter>
            <Button type="button" variant="ghost" onClick={onClose}>取消</Button>
            <Button type="submit" disabled={saving}>保存</Button>
          </DialogFooter>
        </form>
      </DialogContent>
    </Dialog>
  )
}

// Each command runs the hub's own install.sh and is offered only on an https
// domain entry. `args` receives that entry, which the agent is also given as
// --server.
function scriptCommand(site: string, args: (site: string) => string[]) {
  site = provisioningSite(site)
  return site && `curl -fsSL ${site}/install.sh | sh -s -- ${args(site).join(" ")}`
}

// Built here rather than fetched: the node list already carries the token, so
// viewing an install command is a read rather than an action. Reissuing one to
// display it would take the running agent offline.
function installCommand(site: string, token: string, seconds: number | undefined, iface: string | undefined, core: string[]) {
  return scriptCommand(site, (s) => [`--server ${s}`, `--token ${token}`, ...intervalArg(seconds), ...ifaceArg(iface), ...core])
}

// Left out untouched, as an untouched --iface is: a rerun then keeps what the
// machine already has.
function intervalArg(seconds: number | undefined) {
  return seconds === undefined ? [] : [`--interval ${seconds}`]
}

// '' is how install.sh is told to clear a value it would otherwise keep; a
// name needs no quoting, as ifaceSpec admits no shell metacharacter.
function ifaceArg(iface: string | undefined) {
  return iface === undefined ? [] : [`--iface ${iface || "''"}`]
}

// One command for a batch of machines. The key belongs to the hub, is valid only
// within the window it opened, and each machine exchanges it for a token of its
// own, so unlike an install command this text is no one's credential and can be
// sent to every machine as it is.
function registerCommand(site: string, key: string, seconds: number | undefined, iface: string | undefined, core: string[]) {
  return scriptCommand(site, (s) => [`--server ${s}`, `--register ${key}`, ...intervalArg(seconds), ...ifaceArg(iface), ...core])
}

// The two proxy-core flags both install dialogs append. sing-box installs by
// default (its unchecked form is the explicit --no-singbox), pinned to the
// settings' global default unless the field is emptied for latest; realm is
// opt-in — the agent auto-installs it when the first relay rule needs it.
function coreArgs(sb: ReturnType<typeof useSingboxOption>, realm: ReturnType<typeof useRealmOption>) {
  const args: string[] = []
  if (sb.on) {
    if (sb.version) args.push(`--singbox-version ${sb.version}`)
  } else {
    args.push("--no-singbox")
  }
  if (realm.on) {
    args.push("--with-realm")
    if (realm.version) args.push(`--realm-version ${realm.version}`)
  }
  return args
}

// Carries no token, so it is the same for every node and remains valid after the
// node is deleted.
function uninstallCommand(site: string) {
  return scriptCommand(site, () => ["--uninstall"])
}

// Also the same for every node: install.sh reads the token and the hub address
// from the machine's own env file.
function upgradeCommand(site: string) {
  return scriptCommand(site, () => ["--upgrade"])
}

export type Versions = { hub: string; hub_latest: string; agent_latest: string; notice: boolean }

/**
 * What is running and what is published. Read once per panel load: the hub holds
 * the answer for six hours, so this costs a GitHub lookup a few times a day at
 * most, and nothing at all while nobody opens the panel.
 *
 * A hub that cannot reach github.com answers with empty latest fields, which
 * render as no update rather than as an error.
 */
function useVersions() {
  const [versions, setVersions] = useState<Versions | null>(null)
  const load = useCallback(() => api<Versions>("/version").then(setVersions).catch(() => {}), [])
  useEffect(() => { load() }, [load])
  return { versions, reload: load }
}

// The window lives on the hub; this reads it back and counts down, which is also
// what makes an expired one disappear from the panel without interaction.
function useRegisterWindow() {
  const [key, setKey] = useState("")
  const [until, setUntil] = useState(0)
  const [now, setNow] = useState(() => Math.floor(Date.now() / 1000))

  useEffect(() => {
    api<Settings>("/settings")
      .then((s) => { setKey(String(s.register_key ?? "")); setUntil(Number(s.register_until ?? 0)) })
      .catch(() => {})
    const timer = setInterval(() => setNow(Math.floor(Date.now() / 1000)), 1000)
    return () => clearInterval(timer)
  }, [])

  return {
    key,
    left: key === "" ? 0 : Math.max(0, until - now),
    async open() {
      try {
        const w = await api<{ register_key: string; register_until: string }>("/register-window", { method: "POST" })
        setKey(w.register_key)
        setUntil(Number(w.register_until))
      } catch (e) {
        toast.error((e as Error).message)
      }
    },
    async close() {
      try {
        await api("/register-window", { method: "DELETE" })
        setKey("")
        setUntil(0)
        toast.success("注册窗口已关闭")
      } catch (e) {
        toast.error((e as Error).message)
      }
    },
  }
}

function RegisterDialog({ site, reg, onClose }: {
  site: string
  reg: ReturnType<typeof useRegisterWindow>
  onClose: () => void
}) {
  const iface = useIfaceOption(undefined)
  const interval = useIntervalOption()
    const settings = useSettings().s
  const sbDefault = typeof settings?.singbox_default_version === "string" ? settings.singbox_default_version : undefined
  const sb = useSingboxOption(sbDefault)
  const realm = useRealmOption(typeof settings?.realm_default_version === "string" ? settings.realm_default_version : undefined)
  const command = reg.left > 0 && iface.valid && sb.valid ? registerCommand(site, reg.key, interval.flag, iface.flag, coreArgs(sb, realm)) : ""
  const clock = `${Math.floor(reg.left / 60)}:${String(reg.left % 60).padStart(2, "0")}`

  return (
    <Dialog open onOpenChange={(open) => !open && onClose()}>
      <DialogContent onOpenAutoFocus={(e) => e.preventDefault()} className="sm:max-w-xl">
        <DialogHeader>
          <DialogTitle>批量添加</DialogTitle>
        </DialogHeader>
        <div className="space-y-5">
          {/* One string: JSX turns a line break inside CJK text into a visible space. */}
          <p className="text-sm text-muted-foreground">
            {"开一个一小时的注册窗口。期间这条命令在任意机器上跑一次，那台机器就会自己出现在列表里，" +
              "名字默认取它的 hostname。命令里没有任何一台机器的凭证，可以同时发给多台机器。"}
          </p>
          <section className="space-y-3">
            <h3 className="text-sm font-semibold">安装选项</h3>
            <IntervalOption option={interval} batch />
            <IfaceOption option={iface} batch />
            <SingboxOption option={sb} />
            <RealmOption option={realm} />
          </section>
          {reg.left > 0 ? (
            <section className="space-y-2 border-t pt-5">
              <h3 className="text-sm font-semibold">安装命令</h3>
              <Command className={`max-h-40 min-h-24 ${command ? "" : "text-muted-foreground"}`}>
                {command || "网卡名有误，改正后显示命令"}
              </Command>
              {/* Per machine, so it cannot be part of the one command. */}
              <p className="text-xs leading-relaxed text-muted-foreground">
                要给某台单独起名，在它执行的命令末尾加 <code>--name 名字</code>，只对新建的主机生效。
                <a
                  className="ml-1 underline underline-offset-2 hover:text-foreground"
                  href="https://monitor-document.pages.dev/install/batch"
                  target="_blank"
                  rel="noreferrer"
                >
                  批量执行的做法
                </a>
              </p>
              <OptionRow title={`窗口 ${clock} 后自动关闭`} hint="到点自动失效，装完了也可以现在就关">
                <Button variant="outline" size="sm" onClick={reg.close}>立即关闭</Button>
              </OptionRow>
            </section>
          ) : (
            <Button onClick={reg.open}>开启一小时窗口</Button>
          )}
        </div>
        <DialogFooter>
          <Button variant="ghost" onClick={onClose}>关闭</Button>
          <Button onClick={() => copy(command)} disabled={!command}>
            <Copy className="size-4" /> 复制
          </Button>
        </DialogFooter>
      </DialogContent>
    </Dialog>
  )
}

// The reporting interval both install dialogs offer, opening on the node's
// current one where the hub has read it from the reports. `flag` stays
// undefined until the field is changed, including back to what it opened on.
function useIntervalOption(current?: number | null) {
  const [typed, setTyped] = useState<string>()
  const text = typed ?? String(current ?? 1)
  const seconds = Math.min(3600, Math.max(1, Math.round(Number(text) || 1)))
  return { typed: text, setTyped, current, flag: typed === undefined ? undefined : seconds }
}

function IntervalOption({ option, batch = false }: { option: ReturnType<typeof useIntervalOption>; batch?: boolean }) {
  return (
    <OptionRow
      title="上报间隔"
      hint={batch ? "1–3600 秒，默认 1 秒。这一批机器都按这个间隔上报，机器多时可以调大" : (
        <>
          1–3600 秒，默认 1 秒。不改动时沿用机器上原有的间隔
          {option.current && <span className="mt-0.5 block">当前：{option.current} 秒</span>}
        </>
      )}
    >
      <span className="flex shrink-0 items-center gap-2 text-muted-foreground">
        {/* Text rather than number: no spinner arrows, and no wheel changing
            the value under a passing scroll. */}
        <Input
          inputMode="numeric"
          value={option.typed}
          onChange={(e) => option.setTyped(e.target.value.replace(/\D/g, ""))}
          aria-label="上报间隔（秒）"
          className="tnum h-8 w-20 bg-background text-right"
        />
        秒
      </span>
    </OptionRow>
  )
}

// The `--iface` part of an install command. Off leaves the flag out, and
// install.sh then keeps whatever the machine already has; on with both lists
// empty passes '' and restores the default rules. It opens on for a node whose
// agent reports a list, so reinstalling from here repeats that list rather than
// relying on the machine to remember it.
function useIfaceOption(current: string | undefined) {
  const [on, setOn] = useState(!!current)
  const [choice, setChoice] = useState<IfaceChoice>(() => ifaceChoice(current ?? ""))
  const bad = on ? badIfaceName(choice) : undefined
  const spec = ifaceSpec(choice)
  return { on, setOn, choice, setChoice, current, bad, valid: !bad, flag: on && spec !== null ? spec : undefined }
}

// sing-box 安装选项：默认装。版本框默认填设置页的全局默认版本（服务端在
// 从未设置时已回 1.14.2），清空 = 跟最新版；只收数字和点，写歪了不让命令
// 出街（install.sh 同款校验，避免某台新机下载时才发现）。
function useSingboxOption(defaultVersion: string | undefined) {
  const [on, setOn] = useState(true)
  const [typed, setTyped] = useState<string>()
  const value = (typed !== undefined ? typed : (defaultVersion ?? "")).trim()
  const bad = !!value && !/^[0-9.]+$/.test(value)
  return { on, setOn, typed, setTyped, defaultVersion, bad, valid: !bad, version: on ? value || undefined : undefined }
}

function SingboxOption({ option }: { option: ReturnType<typeof useSingboxOption> }) {
  const { on, setOn, typed, setTyped, defaultVersion, bad } = option
  return (
    <OptionRow
      title="安装 sing-box 核心"
      hint={on ? "代理模块的载体，装好不启动，第一条代理推送时拉起" : "不装：首次把代理挂到这台机器时按全局默认版本自动补装"}
      toggle
      below={on && (
        <Field label="sing-box 版本" hint="留空 = 最新版。计量依赖 api service（1.14+），全局默认已在设置页钉住">
          <div className="flex flex-col gap-2">
            <Input
              value={typed ?? defaultVersion ?? ""}
              onChange={(e) => setTyped(e.target.value.replace(/[^0-9.]/g, ""))}
              placeholder="如 1.14.2，留空 = 最新"
              spellCheck={false}
              aria-invalid={bad}
              className="font-mono text-xs"
            />
            <div className="flex flex-wrap gap-1.5">
              <button
                type="button"
                onClick={() => setTyped("")}
                className={`rounded-md border px-2 py-1 text-xs transition-colors ${
                  typed === "" ? "border-foreground bg-secondary font-medium" : "text-muted-foreground hover:bg-muted"
                }`}
              >
                最新版
              </button>
              {defaultVersion && (
                <button
                  type="button"
                  onClick={() => setTyped(undefined)}
                  className={`rounded-md border px-2 py-1 text-xs transition-colors ${
                    typed === undefined ? "border-foreground bg-secondary font-medium" : "text-muted-foreground hover:bg-muted"
                  }`}
                >
                  默认 {defaultVersion}
                </button>
              )}
            </div>
            {bad && <p className="text-xs text-destructive">版本号只能含数字和点</p>}
          </div>
        </Field>
      )}
    >
      <Switch checked={on} onCheckedChange={setOn} />
    </OptionRow>
  )
}

// realm 安装选项：默认不装（装机多下一份二进制，中转机才用得上）；勾上后
// install.sh 只下载二进制，systemd 单元由 agent 在第一份中转配置推送时自写。
function useRealmOption(defaultVersion: string | undefined) {
  const [on, setOn] = useState(false)
  const [typed, setTyped] = useState<string>()
  const value = (typed !== undefined ? typed : (defaultVersion ?? "")).trim()
  return { on, setOn, typed, setTyped, defaultVersion, version: value || undefined }
}

function RealmOption({ option }: { option: ReturnType<typeof useRealmOption> }) {
  const { on, setOn, typed, setTyped, defaultVersion } = option
  return (
    <OptionRow
      title="安装 realm 核心"
      hint="转发出口的载体。不装也能用：首次建转发规则时 agent 自动补装（用设置页的全局默认版本）；勾上适合网络不便访问 GitHub 的机器"
      toggle
      below={on && (
        <Field label="realm 版本" hint="留空 = 最新版；全局默认已在设置页，可在此临时覆盖">
          <div className="flex flex-col gap-2">
            <Input
              value={typed ?? ""}
              onChange={(e) => setTyped(e.target.value.replace(/[^0-9.]/g, ""))}
              placeholder={`默认 ${defaultVersion || "最新版"}，留空 = 最新`}
              spellCheck={false}
              className="font-mono text-xs"
            />
            <div className="flex flex-wrap gap-1.5">
              <button
                type="button"
                onClick={() => setTyped("")}
                className={`rounded-md border px-2 py-1 text-xs transition-colors ${
                  typed === "" ? "border-foreground bg-secondary font-medium" : "text-muted-foreground hover:bg-muted"
                }`}
              >
                最新版
              </button>
              {defaultVersion && (
                <button
                  type="button"
                  onClick={() => setTyped(undefined)}
                  className={`rounded-md border px-2 py-1 text-xs transition-colors ${
                    typed === undefined ? "border-foreground bg-secondary font-medium" : "text-muted-foreground hover:bg-muted"
                  }`}
                >
                  默认 {defaultVersion}
                </button>
              )}
            </div>
          </div>
        </Field>
      )}
    >
      <Switch checked={on} onCheckedChange={setOn} />
    </OptionRow>
  )
}

function describeIface(spec: string) {
  const { only, skip } = ifaceChoice(spec)
  const parts = [only && `只统计 ${only.replaceAll(",", "、")}`, skip && `不统计 ${skip.replaceAll(",", "、")}`]
  return parts.filter(Boolean).join("；") || "默认规则"
}

function IfaceOption({ option, batch = false }: { option: ReturnType<typeof useIfaceOption>; batch?: boolean }) {
  const { on, setOn, choice, setChoice, current, bad } = option
  const field = (list: keyof IfaceChoice, label: string, placeholder: string) => (
    <Field label={label}>
      <Input
        value={choice[list]}
        onChange={(e) => setChoice({ ...choice, [list]: e.target.value })}
        placeholder={placeholder}
        spellCheck={false}
        aria-invalid={bad?.list === list}
        className="bg-background font-mono text-xs"
      />
    </Field>
  )
  const hint = on
    ? batch ? "每台机器都按这里的设置统计" : "覆盖这台机器原有的设置"
    : batch ? "关闭时各台机器沿用原有设置，新机器按默认规则" : "关闭时沿用机器上原有的设置，转发流量的机器才需要指定"
  return (
    <OptionRow
      title="指定统计的网卡"
      hint={<>{hint}{current !== undefined && <span className="mt-0.5 block">当前：{describeIface(current)}</span>}</>}
      toggle
      below={on && (
        <div className="space-y-2.5">
          <div className="grid gap-3 sm:grid-cols-2">
            {field("only", "只统计", "如 WAN 口 eth1 或 pppoe-wan")}
            {field("skip", "不统计", "如 LAN 口 eth0")}
          </div>
          <p className={`text-xs leading-relaxed ${bad ? "text-destructive" : "text-muted-foreground"}`}>
            {bad
              ? `「${bad.name}」不是有效的网卡名：写完整的名字，多个用逗号分隔`
              : "写完整的网卡名，多个用逗号分隔。两项都留空即恢复默认规则。"}
          </p>
        </div>
      )}
    >
      <Switch checked={on} onCheckedChange={setOn} />
    </OptionRow>
  )
}

function InstallDialog({ node, site, onClose, onRotated }: {
  node: Node
  site: string
  onClose: () => void
  onRotated: () => void
}) {
  const [token, setToken] = useState(node.token ?? "")
  const [rotating, setRotating] = useState(false)
  const [confirmRotate, setConfirmRotate] = useState(false)
  const iface = useIfaceOption(currentIface(node))
  const interval = useIntervalOption(node.interval)
    const settings = useSettings().s
  const sbDefault = typeof settings?.singbox_default_version === "string" ? settings.singbox_default_version : undefined
  const sb = useSingboxOption(sbDefault)
  const realm = useRealmOption(typeof settings?.realm_default_version === "string" ? settings.realm_default_version : undefined)

  const command = token && iface.valid && sb.valid ? installCommand(site, token, interval.flag, iface.flag, coreArgs(sb, realm)) : ""

  async function rotate() {
    setRotating(true)
    try {
      const fresh = await api<{ token: string }>(`/nodes/${node.id}/token`, { method: "POST" })
      setToken(fresh.token)
      setConfirmRotate(false)
      toast.success("凭证已换发，需用新命令重装")
      onRotated()
    } catch (e) {
      toast.error((e as Error).message)
    } finally {
      setRotating(false)
    }
  }

  return (
    <Dialog open onOpenChange={(open) => !open && onClose()}>
      <DialogContent onOpenAutoFocus={(e) => e.preventDefault()} className="sm:max-w-xl">
        <DialogHeader>
          <DialogTitle>{node.name}</DialogTitle>
          {/* The one place a single node's agent version is shown, and what an
              issue report asks for. Empty until the node has reported once. */}
          {node.agent_version && <DialogDescription>当前 agent v{node.agent_version}</DialogDescription>}
        </DialogHeader>
        <div className="space-y-5">
          <section className="space-y-3">
            <h3 className="text-sm font-semibold">安装选项</h3>
            <IntervalOption option={interval} />
            <IfaceOption option={iface} />
            <SingboxOption option={sb} />
            <RealmOption option={realm} />
          </section>
          <section className="space-y-2 border-t pt-5">
            <h3 className="text-sm font-semibold">安装命令</h3>
            {/* A node added before the hub kept tokens has nothing to show
                until one is reissued. */}
            <Command className={`max-h-40 min-h-24 ${command ? "" : "text-muted-foreground"}`}>
              {command || (token ? "网卡名有误，改正后显示命令" : "旧版本创建的凭证不可读取，换发后显示")}
            </Command>
          </section>
          <OptionRow title="换发凭证" hint="旧凭证立即作废，agent 掉线，需用新命令重装">
            <Button variant="outline" size="sm" disabled={rotating} onClick={() => setConfirmRotate(true)}>
              换发
            </Button>
          </OptionRow>
        </div>
        <DialogFooter>
          <Button variant="ghost" onClick={onClose}>关闭</Button>
          <Button onClick={() => copy(command)} disabled={!command}>
            <Copy className="size-4" /> 复制
          </Button>
        </DialogFooter>
      </DialogContent>
      {confirmRotate && (
        <ConfirmDialog
          title={`给「${node.name}」换发凭证？`}
          description="旧凭证立即作废，agent 掉线，必须用新命令重装。仅在凭证可能泄露时使用。"
          confirmLabel="换发凭证"
          busy={rotating}
          onClose={() => setConfirmRotate(false)}
          onConfirm={rotate}
        />
      )}
    </Dialog>
  )
}

// Width in ems, near enough: a CJK character is one, anything else about half.
const ems = (word: string) => [...word].reduce((n, c) => n + (c > "\u2e7f" ? 1 : 0.55), 0)

// A node name, broken at its spaces and after the dots of a hostname --
// registered nodes are named after theirs. A word up to eight ems stays whole,
// a city, a label or a hyphenated one such as GIA-E, where the browser would
// leave its last letter to open the next line. A wider word, as a name typed
// without spaces usually is, breaks between its CJK characters, and a run of
// letters only where nothing else fits: kept whole, it would set the column's
// minimum width and push the table past the screen. A separator such as the ·
// in 香港 09 · DMIT, or a dash, is held to the word before it, so no line opens
// with one.
function nameText(name: string) {
  return name
    .replace(/ (?=[·|/｜—–-] )/g, "\u00a0")
    .split(/( )/)
    .map((word, i) => {
      const parts = word.split(".").flatMap((part, j) => (j ? [".", <wbr key={j} />, part] : [part]))
      if (ems(word) > 8) return <span key={i} className="wrap-anywhere [word-break:normal]">{parts}</span>
      return word.includes("-") ? <span key={i} className="whitespace-nowrap">{word}</span> : parts
    })
}

// Traffic turns a subdued orange at the alert threshold and a subdued red once
// the allowance is used up, so the table agrees with the alerts. With alerts
// off, the threshold's default of 80 % still marks a node running short.
function trafficTone(n: Node, warnAt: number) {
  if (n.traffic_limit <= 0) return ""
  if (n.month_used >= n.traffic_limit) return "text-over"
  return n.month_used * 100 >= n.traffic_limit * warnAt ? "text-near" : ""
}

function Nodes({ nodes, refresh, site, refusal }: { nodes: Node[]; refresh: () => void; site: string; refusal: string }) {
  const warnAt = Number(useSettings().s?.notify_traffic) || 80
  const [creating, setCreating] = useState(false)
  const [editing, setEditing] = useState<Node | null>(null)
  const [billing, setBilling] = useState<Node | null>(null)
  const [installing, setInstalling] = useState<Node | null>(null)
  const [registering, setRegistering] = useState(false)
  const reg = useRegisterWindow()
  const [deleting, setDeleting] = useState<Node | null>(null)
  const [removing, setRemoving] = useState(false)
  const [query, setQuery] = useState("")
  const [group, setGroup] = useGroupFilter(nodes)
  const [grouping, setGrouping] = useState(false)
  // A new node lands last, a hundred rows down on a large fleet, so it is
  // brought into view once the list carries it. A filter hiding it cancels the
  // scroll rather than leaving one to fire when the filter is cleared.
  const added = useRef<number | null>(null)
  const drag = useDragOrder(nodes, "nodes", refresh)
  const visible = inGroup(searchNodes(drag.order, query), group)
  useEffect(() => {
    if (added.current === null || !nodes.some((n) => n.id === added.current)) return
    document.querySelector(`tbody tr[data-id="${added.current}"]`)?.scrollIntoView({ block: "center", behavior: "smooth" })
    added.current = null
  })
  const searching = query.trim() !== "" || group !== "all"
  const uninstall = refusal ? "" : uninstallCommand(site)

  async function remove() {
    if (!deleting) return
    setRemoving(true)
    try {
      await api(`/nodes/${deleting.id}`, { method: "DELETE" })
      toast.success("已删除")
      setDeleting(null)
      refresh()
    } catch (e) {
      toast.error((e as Error).message)
    } finally {
      setRemoving(false)
    }
  }

  return (
    <>
    <div className="space-y-4">
      {refusal && <p className="text-sm text-muted-foreground">{refusal}</p>}
      <div className="flex flex-wrap items-center justify-end gap-2">
        <div className="mr-auto flex w-full gap-2 sm:w-auto">
          <NodeSearch className="min-w-0 flex-1 sm:w-64 sm:flex-none" value={query} onChange={setQuery} />
          <GroupFilter nodes={nodes} value={group} onChange={setGroup} className="w-32" />
        </div>
        <Button variant="outline" disabled={!nodes.length} onClick={() => setGrouping(true)}>
          <Layers /> 分组
        </Button>
        {/* An open window is visible from the list itself, so nobody has to
            remember they left one open. */}
        <Button variant="outline" disabled={!!refusal} onClick={() => setRegistering(true)}>
          <Server /> 批量添加{reg.left > 0 && ` · ${Math.ceil(reg.left / 60)} 分`}
        </Button>
        <Button disabled={!!refusal} onClick={() => setCreating(true)}>
          <Plus /> 添加主机
        </Button>
      </div>

      <Card className="overflow-x-auto p-0">
        <Table>
          <TableHeader>
            {/* Percentages, or the address column swallows every spare pixel
                and pushes status across the table. */}
            <TableRow>
              <TableHead className="w-[26%]">名称</TableHead>
              <TableHead className="w-[18%]">IP</TableHead>
              <TableHead className="w-[12%]">状态</TableHead>
              <TableHead className="w-[16%]">流量</TableHead>
              {/* Below xl the expiry date moves under the price: seven
                  columns leave a 1024px window no room for names. */}
              <TableHead className="w-[10%]">价格<span className="xl:hidden"> / 到期</span></TableHead>
              <TableHead className="hidden w-[12%] xl:table-cell">到期</TableHead>
              <TableHead className="text-right">操作</TableHead>
            </TableRow>
          </TableHeader>
          <TableBody>
            {visible.map((n) => (
              <TableRow key={n.id} {...drag.row(n.id)}>
                {/* Wraps: under the cell's default nowrap, one long name would
                    widen the table until the actions left the screen. */}
                <TableCell className="whitespace-normal">
                  <div className="flex items-center gap-2">
                    <DragHandle
                      {...drag.handle(n.id)}
                      name={n.name}
                      disabled={searching}
                      title={searching ? "清空搜索和分组筛选后可拖动排序" : undefined}
                    />
                    <div className="min-w-24">
                      {/* Lines are balanced, so none ends on a character or two. */}
                      <div className="font-medium text-balance break-keep">
                        {/* 购买网站（grilling 三期）：填了就整体可点，新标签打开；
                            无协议前缀自动补 https://，空则保持纯文字。 */}
                        {(() => {
                          const raw = (n.purchase_url ?? "").trim()
                          const url = raw ? (/^https?:\/\//i.test(raw) ? raw : `https://${raw}`) : ""
                          return url ? (
                            <a href={url} target="_blank" rel="noopener noreferrer" className="hover:underline decoration-dotted underline-offset-2">
                              {nameText(n.name)}
                            </a>
                          ) : (
                            nameText(n.name)
                          )
                        })()}
                        {/* In the name's flow, a fixed gap after its last word.
                            Beside the block it would sit at the cell's edge
                            whenever the name or group wraps, since a wrapped
                            block spans the whole width. The gap is a figure
                            space, which does not break: the badge moves down
                            with the last word rather than open a line alone. */}
                        {n.country && "\u2007"}
                        {n.country && (
                          <Badge
                            variant="outline"
                            title={n.country_pin ? "手动指定" : undefined}
                            className="align-middle font-normal text-muted-foreground"
                          >
                            {n.country}
                          </Badge>
                        )}
                      </div>
                      {n.group && <div className="text-xs text-balance text-muted-foreground">{n.group}</div>}
                    </div>
                  </div>
                </TableCell>
                {/* Addresses live only here, never on the public page. */}
                <TableCell>
                  <Addresses list={n.addresses ?? []} />
                </TableCell>
                <TableCell>
                  {/* Stacked and centred on one axis. The slot is as wide as
                      the three-character 不公开, so a lone pill sits where it
                      would above that one and every row lines up. */}
                  <div className="flex w-fit min-w-14 flex-col items-center gap-1">
                    <StatusBadge tone={n.online ? "ok" : "off"}>
                      {n.online ? "在线" : "离线"}
                    </StatusBadge>
                    {!n.public && <Badge variant="outline" className="font-normal">不公开</Badge>}
                    {/* Under the badge, not inside it: the column is a tenth of
                        the table and the three do not share one line. A slot of
                        the pills' width that the text spills out of evenly, so a
                        long duration does not widen the slot and move the
                        pills off the axis the other rows share. */}
                    {!n.online && n.last_seen > 0 && Date.now() / 1000 - n.last_seen >= 60 && (
                      <div className="flex w-14 justify-center">
                        <span className="tnum text-xs whitespace-nowrap text-muted-foreground">
                          {uptime(Date.now() / 1000 - n.last_seen)}
                        </span>
                      </div>
                    )}
                  </div>
                </TableCell>
                {/* Counted by the node's own billing rule, as on the public
                    page. Two unbreakable halves, so a narrow table moves the
                    limit to a second line rather than splitting a figure. */}
                <TableCell className="tnum text-sm whitespace-normal">
                  <span className={`whitespace-nowrap ${trafficTone(n, warnAt)}`}>
                    {bytes(n.month_used)}
                  </span>{" "}
                  <span className="whitespace-nowrap text-muted-foreground">
                    / {n.traffic_limit > 0 ? bytes(n.traffic_limit) : FOREVER}
                  </span>
                </TableCell>
                <TableCell className="tnum text-sm">
                  {n.price > 0 ? money(n.price, n.currency) : "免费"}
                  <div className="text-xs text-muted-foreground xl:hidden">
                    {n.expires_at
                      ? <span className={(n.expires_in ?? Infinity) <= 3 ? "text-red-500" : undefined}>{n.expires_at}</span>
                      : FOREVER}
                  </div>
                </TableCell>
                {/* 快到期（≤3 天，含已过期）日期变红；∞ 为未填到期日。 */}
                <TableCell className="hidden text-sm xl:table-cell">
                  {n.expires_at
                    ? <span className={(n.expires_in ?? Infinity) <= 3 ? "text-red-500" : undefined}>{n.expires_at}</span>
                    : FOREVER}
                </TableCell>
                <TableCell className="text-right whitespace-nowrap">
                  <Button variant="ghost" size="icon" disabled={!!refusal} onClick={() => setInstalling(n)} title="安装 Agent" aria-label="安装 Agent">
                    <Download />
                  </Button>
                  <Button variant="ghost" size="icon" onClick={() => setEditing(n)} title="编辑主机" aria-label="编辑主机">
                    <Pencil />
                  </Button>
                  <Button variant="ghost" size="icon" onClick={() => setBilling(n)} title="续费设置" aria-label="续费设置">
                    <CalendarClock />
                  </Button>
                  <Button variant="ghost" size="icon" onClick={() => setDeleting(n)} title="删除主机" aria-label="删除主机">
                    <Trash2 className="text-destructive" />
                  </Button>
                </TableCell>
              </TableRow>
            ))}
            {nodes.length === 0 && (
              <TableRow>
                <TableCell colSpan={7} className="py-10 text-center text-sm text-muted-foreground">
                  还没有主机，右上角添加
                </TableCell>
              </TableRow>
            )}
            {searching && nodes.length > 0 && !visible.length && (
              <TableRow>
                <TableCell colSpan={7} className="py-10 text-center text-sm text-muted-foreground">
                  没有匹配的主机
                </TableCell>
              </TableRow>
            )}
          </TableBody>
        </Table>
      </Card>

      {creating && (
        <CreateNode
          onClose={() => setCreating(false)}
          onSaved={(id) => { added.current = id; refresh() }}
        />
      )}
      {editing && (
        <NodeForm
          node={editing}
          nodes={nodes}
          onClose={() => setEditing(null)}
          onSaved={refresh}
        />
      )}
      {grouping && <GroupDialog nodes={drag.order} onClose={() => setGrouping(false)} onSaved={refresh} />}
      {billing && (
        <BillingForm node={billing} onClose={() => setBilling(null)} onSaved={refresh} />
      )}
      {registering && <RegisterDialog site={site} reg={reg} onClose={() => { setRegistering(false); refresh() }} />}

      {installing && (
        <InstallDialog
          node={installing}
          site={site}
          onClose={() => setInstalling(null)}
          onRotated={refresh}
        />
      )}
      {deleting && (
        <ConfirmDialog
          title={`删除主机「${deleting.name}」？`}
          description="历史指标、流量记录和凭证一并删除，不可恢复。"
          confirmLabel="删除主机"
          busy={removing}
          onClose={() => setDeleting(null)}
          onConfirm={remove}
        >
          {/* Deleting the node leaves the agent running on the machine, retrying
              with a token the hub no longer accepts. */}
          {uninstall && (
            <div className="space-y-2">
              <div className="flex items-center justify-between gap-2">
                <Label className="text-sm font-medium">卸载 agent</Label>
                <Button variant="ghost" size="sm" onClick={() => copy(uninstall)}>
                  <Copy className="size-4" /> 复制
                </Button>
              </div>
              <Command>{uninstall}</Command>
              <p className="text-xs text-muted-foreground">
                在这台机器上以 root 执行，停止 agent，删除二进制、env 文件和服务文件。
              </p>
            </div>
          )}
        </ConfirmDialog>
      )}
    </div>
    </>
  )
}

function PingForm({ task, nodes, onClose, onSaved }: {
  task: Partial<PingTask>
  nodes: Node[]
  onClose: () => void
  onSaved: () => void
}) {
  const [form, setForm] = useState(task)
  // Text until saved, so the box can be emptied and retyped.
  const [every, setEvery] = useState(String(task.interval ?? 60))
  const [saving, setSaving] = useState(false)
  // The assignments as the hub holds them, as far as this dialog can tell: those
  // loaded, plus any node that registers while it is open, which an auto_join
  // probe takes at once. Shown ticked, so unticking one removes it.
  const base = useRef(task.nodes ?? [])
  const seen = useRef(new Set(nodes.map((n) => n.id)))
  useEffect(() => {
    const fresh = nodes.filter((n) => !seen.current.has(n.id)).map((n) => n.id)
    for (const id of fresh) seen.current.add(id)
    if (!task.auto_join || !fresh.length) return
    base.current = [...base.current, ...fresh]
    setForm((f) => ({ ...f, nodes: [...(f.nodes ?? []), ...fresh] }))
  }, [nodes, task.auto_join])
  const chosen = new Set(form.nodes)
  // Counted against the live list: `form.nodes` can still name a node deleted
  // since the probes were loaded.
  const chosenCount = nodes.filter((n) => chosen.has(n.id)).length

  const pick = (list: Node[], on: boolean) =>
    setForm((f) => {
      const next = new Set(f.nodes)
      for (const n of list) {
        if (on) next.add(n.id)
        else next.delete(n.id)
      }
      return { ...f, nodes: [...next] }
    })

  async function save() {
    if (!form.name?.trim() || !form.target?.trim()) return toast.error("请填写名称和目标")
    const interval = Number(every)
    if (!Number.isInteger(interval) || interval < 5 || interval > 3600) return toast.error("间隔要填 5–3600 之间的整数秒")
    setSaving(true)
    try {
      // `base` limits the save to what was ticked or unticked here; a node that
      // joined through auto_join while the dialog was open keeps its assignment.
      const body = { ...form, interval, ...(task.id ? { base: base.current } : {}) }
      await api("/ping-tasks", { method: "POST", body: JSON.stringify(body) })
      toast.success("已保存，正在下发")
      onClose()
      onSaved()
    } catch (e) {
      toast.error((e as Error).message)
    } finally {
      setSaving(false)
    }
  }

  return (
    <Dialog open onOpenChange={(open) => !open && onClose()}>
      <DialogContent onOpenAutoFocus={(e) => e.preventDefault()} className="sm:max-w-2xl">
        <DialogHeader>
          <DialogTitle>{task.id ? "编辑监控" : "添加监控"}</DialogTitle>
        </DialogHeader>
        <form noValidate className="contents" onSubmit={(e) => { e.preventDefault(); save() }}>
          <div className="space-y-6">
            {/* On a phone the name takes the first row and the target shares the
                second with the interval, so the tab order matches the screen. */}
            <section className="grid grid-cols-[1fr_6rem] gap-4 sm:grid-cols-[1fr_1.4fr_6rem]">
              <Field label="名称" className="col-span-full sm:col-span-1">
                {/* A new monitor starts empty, so the cursor belongs here;
                    editing an existing one starts with nothing selected. */}
                <Input autoFocus={!task.id} value={form.name ?? ""} onChange={(e) => setForm({ ...form, name: e.target.value })} placeholder="Cloudflare" />
              </Field>
              <Field label="目标地址" hint="host:port，每个主机各自 TCP 连接">
                <Input value={form.target ?? ""} onChange={(e) => setForm({ ...form, target: e.target.value })} placeholder="1.1.1.1:443" />
              </Field>
              <Field label="间隔（秒）" hint="5–3600">
                <Input type="number" min="5" max="3600" value={every} onChange={(e) => setEvery(e.target.value)} />
              </Field>
            </section>
            <section className="space-y-3 border-t pt-5">
              <div className="flex items-baseline justify-between gap-2">
                <h3 className="text-sm font-semibold">运行主机</h3>
                <span className="tnum text-xs text-muted-foreground">已选 {chosenCount} / {nodes.length}</span>
              </div>
              <NodePicker nodes={nodes} chosen={chosen} onPick={pick} />
              <OptionRow title="新主机自动加入" hint="以后添加的主机自动开始" toggle>
                <Switch checked={!!form.auto_join} onCheckedChange={(v) => setForm({ ...form, auto_join: v })} />
              </OptionRow>
            </section>
          </div>
          <DialogFooter>
            <Button type="button" variant="ghost" onClick={onClose}>取消</Button>
            <Button type="submit" disabled={saving}>保存</Button>
          </DialogFooter>
        </form>
      </DialogContent>
    </Dialog>
  )
}

function Ping({ nodes }: { nodes: Node[] }) {
  // null until loaded, so the empty state does not flash before the list.
  const [tasks, setTasks] = useState<PingTask[] | null>(null)
  const [editing, setEditing] = useState<Partial<PingTask> | null>(null)
  const [deleting, setDeleting] = useState<PingTask | null>(null)
  const [removing, setRemoving] = useState(false)

  // A failed first load draws the page empty, keeping 添加监控 in reach.
  const load = () =>
    api<{ tasks: PingTask[] }>("/ping-tasks")
      .then((d) => setTasks(d.tasks))
      .catch((e: Error) => {
        toast.error(e.message)
        setTasks((tasks) => tasks ?? [])
      })
  // A node added or removed changes assignments on the hub: auto_join adds, a
  // deletion cascades.
  useEffect(() => { load() }, [nodes.length])
  // Unfiltered, so the handles are never disabled.
  const drag = useDragOrder(tasks ?? [], "ping-tasks", load)

  async function remove() {
    if (!deleting) return
    setRemoving(true)
    try {
      await api(`/ping-tasks/${deleting.id}`, { method: "DELETE" })
      toast.success("监控已删除")
      setDeleting(null)
      load()
    } catch (e) {
      toast.error((e as Error).message)
    } finally {
      setRemoving(false)
    }
  }

  if (!tasks)
    return (
      <div className="space-y-4">
        <Card className="gap-3 p-5">
          <Skeleton className="h-5 w-40" />
          <Skeleton className="h-40 w-full" />
        </Card>
      </div>
    )
  return (
    <>
    <div className="space-y-4">
      <div className="flex justify-end">
        <Button onClick={() => setEditing({ name: "", target: "", interval: 60, nodes: nodes.map((n) => n.id), auto_join: true })}>
          <Plus /> 添加监控
        </Button>
      </div>

      <Card className="overflow-x-auto p-0">
        <Table>
          <TableHeader>
            <TableRow>
              <TableHead className="w-[22%]">名称</TableHead>
              <TableHead className="w-[34%]">目标</TableHead>
              <TableHead className="w-[10%]">间隔</TableHead>
              <TableHead className="w-[22%]">主机</TableHead>
              <TableHead className="text-right">操作</TableHead>
            </TableRow>
          </TableHeader>
          <TableBody>
            {drag.order.map((t) => (
              <TableRow key={t.id} {...drag.row(t.id)}>
                <TableCell className="font-medium">
                  <div className="flex items-center gap-2">
                    <DragHandle {...drag.handle(t.id)} name={t.name} />
                    {t.name}
                  </div>
                </TableCell>
                <TableCell className="tnum text-sm">{t.target}</TableCell>
                <TableCell className="tnum text-sm">{t.interval}s</TableCell>
                <TableCell className="text-sm whitespace-nowrap text-muted-foreground">
                  {t.nodes.length > 0 && t.nodes.length === nodes.length ? "全部" : `${t.nodes.length} 个`}
                  {t.auto_join && <Badge variant="outline" className="ml-2 font-normal">自动加入</Badge>}
                </TableCell>
                <TableCell className="text-right whitespace-nowrap">
                  <Button variant="ghost" size="icon" onClick={() => setEditing(t)} title="编辑监控" aria-label="编辑监控"><Pencil /></Button>
                  <Button variant="ghost" size="icon" onClick={() => setDeleting(t)} title="删除监控" aria-label="删除监控">
                    <Trash2 className="text-destructive" />
                  </Button>
                </TableCell>
              </TableRow>
            ))}
            {tasks.length === 0 && (
              <TableRow>
                <TableCell colSpan={5} className="py-10 text-center text-sm text-muted-foreground">
                  还没有监控任务，点「添加监控」开始。
                </TableCell>
              </TableRow>
            )}
          </TableBody>
        </Table>
      </Card>

      {editing && <PingForm task={editing} nodes={nodes} onClose={() => setEditing(null)} onSaved={load} />}

      <RouteSection nodes={nodes} />
      {deleting && (
        <ConfirmDialog
          title={`删除监控「${deleting.name}」？`}
          description="该监控及其历史延迟记录一并删除，不可恢复。"
          confirmLabel="删除监控"
          busy={removing}
          onClose={() => setDeleting(null)}
          onConfirm={remove}
        />
      )}
    </div>
    </>
  )
}

type Theme = {
  name: string
  short: string
  description: string
  version: string
  author: string
  url: string
  selected: boolean
  // 内置主题在二进制里，没有目录可删。装上一份同名的会顶替它，那一份就是普通
  // 主题，删掉之后内置的重新顶上。
  builtin: boolean
  // theme.json 里声明的设置表单，原样转过来，由 configFields 挑出能画的字段。
  config?: unknown
  // 主题包是否带 preview.png，由 hub 告知，卡片的高度一次排定，不因图片晚到而改变。
  preview: boolean
}

// 主题在 theme.json 里声明的设置。hub 只存与默认值不同的项，其余由主题用自己的默认值补上，
// 所以主题作者日后改了某个默认值，没动过这一项的站点会跟着变。
//
// 字段不多时是一列；多了改成宽对话框：按分组标题分节，左侧切换，右侧两列，
// 否则几十项排成一条细长的列表。有改动的节在导航上带一个点。
function ThemeSettings({ theme, saved, onClose }: {
  theme: Theme
  saved: Record<string, unknown>
  onClose: () => void
}) {
  const form = configForm(theme.config)
  const fields = form.filter((entry): entry is ConfigField => entry.type !== "title")
  const sections = configSections(form)
  const large = fields.length > 6
  const paged = large && sections.length > 1
  const [current, setCurrent] = useState(0)
  const [values, setValues] = useState(() => configValues(fields, saved))
  // What the save builds on. Keys the form does not declare are kept, except
  // after 恢复默认: that also clears them, the only way from the panel to drop
  // a value, publicly readable, left by a field the theme has since removed.
  const [base, setBase] = useState(saved)
  const [saving, setSaving] = useState(false)
  const set = (key: string, value: unknown) => setValues((old) => ({ ...old, [key]: value }))
  const label = (field: ConfigField) => field.label || field.key
  // A number box holds its text while being edited; an empty one holds no
  // number, where Number("") would read as 0.
  const typed = (f: ConfigField) =>
    f.type !== "number" ? values[f.key] : values[f.key] === "" ? NaN : Number(values[f.key])
  const differs = (f: ConfigField) => typed(f) !== f.default

  async function save(e: React.FormEvent) {
    e.preventDefault()
    // The browser checks required/min/max only on the boxes on screen; a
    // section switched away from is no longer rendered, so its numbers are
    // checked here and the offending one brought back into view.
    const invalid = fields.find((f) => f.type === "number" && !fits(f, typed(f)))
    if (invalid) {
      setCurrent(Math.max(0, sections.findIndex((section) => section.fields.includes(invalid))))
      const range =
        invalid.min !== undefined && invalid.max !== undefined ? `${invalid.min}–${invalid.max} 之间的`
        : invalid.min !== undefined ? `不小于 ${invalid.min} 的`
        : invalid.max !== undefined ? `不大于 ${invalid.max} 的` : ""
      return toast.error(`「${label(invalid)}」要填${range}数字`)
    }
    setSaving(true)
    try {
      await api(`/themes/${theme.short}/config`, {
        method: "PUT",
        body: JSON.stringify(configOverrides(fields, base, Object.fromEntries(fields.map((f) => [f.key, typed(f)])))),
      })
      toast.success("主题设置已保存，公开页刷新后生效")
      onClose()
    } catch (e) {
      toast.error((e as Error).message)
    } finally {
      setSaving(false)
    }
  }

  const input = (field: ConfigField) =>
    field.type === "boolean" ? (
      <OptionRow key={field.key} title={label(field)} hint={field.help} toggle>
        <Switch checked={values[field.key] as boolean} onCheckedChange={(v) => set(field.key, v)} />
      </OptionRow>
    ) : (
      <Field key={field.key} label={label(field)} hint={field.help} className={large && field.type === "text" ? "sm:col-span-2" : ""}>
        {field.type === "text" ? (
          <textarea
            rows={4}
            className={`${TEXT_BOX} text-sm`}
            value={values[field.key] as string}
            onChange={(e) => set(field.key, e.target.value)}
          />
        ) : field.type === "select" ? (
          <Select value={values[field.key] as string} onValueChange={(v) => set(field.key, v)}>
            <SelectTrigger className="w-full"><SelectValue /></SelectTrigger>
            <SelectContent position="popper">
              {field.options!.map((o) => (
                <SelectItem key={o.value} value={o.value}>{o.label || o.value}</SelectItem>
              ))}
            </SelectContent>
          </Select>
        ) : field.type === "number" ? (
          <Input
            type="number"
            required
            step="any"
            min={field.min}
            max={field.max}
            value={String(values[field.key])}
            onChange={(e) => set(field.key, e.target.value)}
          />
        ) : (
          <Input value={values[field.key] as string} onChange={(e) => set(field.key, e.target.value)} />
        )}
      </Field>
    )

  return (
    <Dialog open onOpenChange={(open) => !open && onClose()}>
      <DialogContent
        onOpenAutoFocus={(e) => e.preventDefault()}
        className={large ? "flex h-[min(46rem,calc(100dvh-2rem))] flex-col overflow-hidden sm:max-w-4xl" : "sm:max-w-lg"}
      >
        <DialogHeader>
          <DialogTitle>{theme.name} 设置</DialogTitle>
        </DialogHeader>
        <form className="flex min-h-0 flex-1 flex-col gap-4" onSubmit={save}>
          <div className="flex min-h-0 flex-1 flex-col gap-4 sm:flex-row">
            {paged && (
              <nav className="-mx-1 flex shrink-0 gap-1 overflow-x-auto px-1 pb-1 sm:mx-0 sm:w-48 sm:flex-col sm:overflow-y-auto sm:px-0">
                {sections.map((section, index) => (
                  <button
                    key={index}
                    type="button"
                    aria-current={index === current}
                    onClick={() => setCurrent(index)}
                    className={`flex shrink-0 items-center gap-2 rounded-md px-3 py-1.5 text-left text-sm transition-colors ${
                      index === current ? "bg-muted font-medium" : "text-muted-foreground hover:bg-muted/60 hover:text-foreground"
                    }`}
                  >
                    <span className="whitespace-nowrap sm:whitespace-normal">{section.label}</span>
                    {section.fields.some(differs) && (
                      <span className="ml-auto size-1.5 shrink-0 rounded-full bg-primary" title="有改动" />
                    )}
                  </button>
                ))}
              </nav>
            )}
            <div className={`min-h-0 flex-1 ${large ? "overflow-y-auto pr-1" : ""}`}>
              <div className={`grid items-start gap-4 ${large ? "sm:grid-cols-2" : ""}`}>
                {paged
                  ? sections[current].fields.map(input)
                  : form.map((entry, index) =>
                      entry.type === "title" ? (
                        <h3 key={`title-${index}`} className={`pt-2 text-sm font-semibold first:pt-0 ${large ? "sm:col-span-2" : ""}`}>
                          {entry.label}
                        </h3>
                      ) : (
                        input(entry)
                      ),
                    )}
              </div>
            </div>
          </div>
          {/* One row on a phone as well: stacked, the three buttons would take a
              third of the height the fields have. */}
          <DialogFooter className="flex-row items-center border-t pt-4">
            <Button
              type="button"
              variant="ghost"
              className="mr-auto"
              onClick={() => {
                setValues(Object.fromEntries(fields.map((f) => [f.key, f.default])))
                setBase({})
              }}
            >
              {paged ? "全部恢复默认" : "恢复默认"}
            </Button>
            <Button type="button" variant="ghost" onClick={onClose}>取消</Button>
            <Button type="submit" disabled={saving}>保存</Button>
          </DialogFooter>
        </form>
      </DialogContent>
    </Dialog>
  )
}

function Themes() {
  const [themes, setThemes] = useState<Theme[] | null>(null)
  const [busy, setBusy] = useState("")
  const [doomed, setDoomed] = useState<Theme | null>(null)
  const [zoomed, setZoomed] = useState<Theme | null>(null)
  const [configuring, setConfiguring] = useState<{ theme: Theme; saved: Record<string, unknown> } | null>(null)
  const picker = useRef<HTMLInputElement>(null)

  const load = () =>
    api<{ themes: Theme[] }>("/themes").then((data) => setThemes(data.themes)).catch(() => setThemes([]))
  useEffect(() => { load() }, [])

  async function select(short: string) {
    try {
      await api("/settings", { method: "PUT", body: JSON.stringify({ theme: short }) })
      setThemes((old) => old?.map((theme) => ({ ...theme, selected: theme.short === short })) ?? old)
      toast.success("主题已切换")
    } catch (e) {
      toast.error((e as Error).message)
    }
  }

  async function install(file: File) {
    setBusy("upload")
    try {
      const { theme } = await upload<{ theme: Theme }>("/themes", file)
      // The hub reads a theme from disk on every request, so it is already live;
      // reloading the list only brings this page up to date.
      toast.success(`已安装 ${theme.name} ${theme.version}`)
      load()
    } catch (e) {
      toast.error((e as Error).message)
    } finally {
      setBusy("")
    }
  }

  // Only a theme whose manifest names a GitHub repository has a source to update
  // from; the hub refuses anything else, and this merely hides the button.
  const updatable = (theme: Theme) => theme.url.startsWith("https://github.com/")

  async function update(theme: Theme) {
    setBusy(`update:${theme.short}`)
    try {
      const { updated, version } = await api<{ updated: boolean; version: string }>(
        `/themes/${theme.short}/update`,
        { method: "POST" },
      )
      toast.success(updated ? `${theme.name} 已更新到 ${version}` : `${theme.name} 已是最新版本 ${version}`)
      if (updated) load()
    } catch (e) {
      toast.error((e as Error).message)
    } finally {
      setBusy("")
    }
  }

  // Read on opening rather than inside the dialog, so the form starts from what
  // is saved instead of flashing the defaults first.
  async function configure(theme: Theme) {
    try {
      setConfiguring({ theme, saved: await api(`/themes/${theme.short}/config`) })
    } catch (e) {
      toast.error((e as Error).message)
    }
  }

  async function remove(theme: Theme) {
    setBusy("delete")
    try {
      await api(`/themes/${theme.short}`, { method: "DELETE" })
      toast.success(`已删除 ${theme.name}`)
      load()
    } catch (e) {
      toast.error((e as Error).message)
    } finally {
      setBusy("")
      setDoomed(null)
    }
  }

  if (!themes)
    return (
      <div className="space-y-4">
        <Card className="gap-3 p-5">
          <Skeleton className="h-5 w-40" />
          <Skeleton className="h-40 w-full" />
        </Card>
      </div>
    )
  return (
    <>
    <div className="space-y-4">
      <Card className="gap-4 p-5">
        <div>
          <h3 className="text-sm font-semibold">安装主题</h3>
          <p className="mt-1 text-xs leading-relaxed text-muted-foreground">
            上传主题作者发布的 <code>theme.tar.gz</code>，同名主题整体替换。
            <br />
            主题的 <code>url</code> 指向 GitHub 仓库时，卡片上的 <RefreshCw className="inline size-3" /> 从它最新的
            release 取 <code>theme.tar.gz</code>，版本没变就不下载。
            <br />
            主题代码在访客浏览器中执行，请只安装可信来源。
          </p>
        </div>
        <div>
          <Button size="sm" disabled={!!busy} onClick={() => picker.current?.click()}>
            <Upload /> {busy === "upload" ? "安装中…" : "上传主题包"}
          </Button>
          <input
            ref={picker}
            type="file"
            accept=".gz,.tgz,application/gzip"
            className="hidden"
            onChange={(e) => {
              const file = e.target.files?.[0]
              e.target.value = ""
              if (file) install(file)
            }}
          />
        </div>
      </Card>

      {/* items-start：有预览图和没有的卡片不该为了等高而留白 */}
      <div className="grid items-start gap-3 sm:grid-cols-2">
        {themes.map((theme) => (
          <Card key={theme.short} className="gap-4 p-5">
            {/* 缩略图被压到卡片那点宽度，比例不是 16:9 的还会被 object-cover
                裁掉边，所以图本身要能点开看原尺寸——就地开一个对话框，不跳走。 */}
            {theme.preview && (
              <button type="button" title="查看完整预览图" className="cursor-zoom-in" onClick={() => setZoomed(theme)}>
                <img
                  src={`/api/themes/${theme.short}/preview`}
                  alt={`${theme.name} 预览图`}
                  className="aspect-video w-full rounded-md border object-cover object-top"
                />
              </button>
            )}
            <div className="flex items-start gap-3">
              <div className="min-w-0 flex-1">
                <div className="flex items-center gap-2">
                  <h3 className="font-semibold">{theme.name}</h3>
                  {theme.selected && <Badge>当前</Badge>}
                  {theme.builtin && <Badge variant="secondary" className="font-normal">内置</Badge>}
                </div>
                <p className="mt-1 text-sm text-muted-foreground">{theme.description}</p>
              </div>
              <div className="flex shrink-0 items-center gap-1">
                <Button size="sm" variant={theme.selected ? "secondary" : "default"} disabled={theme.selected} onClick={() => select(theme.short)}>
                  {theme.selected ? "使用中" : "使用"}
                </Button>
                {configFields(theme.config).length > 0 && (
                  <Button size="icon" variant="ghost" title="主题设置" aria-label="主题设置" onClick={() => configure(theme)}>
                    <SlidersHorizontal />
                  </Button>
                )}
                {updatable(theme) && (
                  <Button
                    size="icon"
                    variant="ghost"
                    title="从 GitHub 更新"
                    aria-label="从 GitHub 更新"
                    disabled={!!busy}
                    onClick={() => update(theme)}
                  >
                    <RefreshCw className={busy === `update:${theme.short}` ? "animate-spin" : ""} />
                  </Button>
                )}
                {/* The built-in theme is served from the binary and has no
                    directory to delete -- it is also the fallback everything
                    else lands on. */}
                {!theme.builtin && (
                  <Button size="icon" variant="ghost" title="删除主题" aria-label="删除主题" disabled={!!busy} onClick={() => setDoomed(theme)}>
                    <Trash2 />
                  </Button>
                )}
              </div>
            </div>
            <p className="text-xs text-muted-foreground">
              {theme.author} · {theme.version}
              {theme.url && <> · <a className="hover:underline" href={theme.url} target="_blank" rel="noreferrer">源码</a></>}
            </p>
          </Card>
        ))}
      </div>

      {/* 原图，不是卡片上那张裁过的：宽度给到 4xl，高度让 80vh 兜住，
          object-contain 保证整张都在框里而不是被切一刀。 */}
      {zoomed && (
        <Dialog open onOpenChange={(open) => !open && setZoomed(null)}>
          <DialogContent className="sm:max-w-4xl">
            <DialogHeader>
              <DialogTitle>{zoomed.name} 预览图</DialogTitle>
              <DialogDescription>{zoomed.author} · {zoomed.version}</DialogDescription>
            </DialogHeader>
            <img
              src={`/api/themes/${zoomed.short}/preview`}
              alt={`${zoomed.name} 预览图`}
              className="max-h-[80vh] w-full rounded-md border object-contain"
            />
          </DialogContent>
        </Dialog>
      )}

      {configuring && <ThemeSettings {...configuring} onClose={() => setConfiguring(null)} />}

      {doomed && (
        <ConfirmDialog
          title={`删除 ${doomed.name}？`}
          description={
            doomed.short === "default"
              ? "装上的这份会从磁盘上删掉，公开页回到 hub 内置的那份默认主题。"
              : doomed.selected
                ? "这是当前使用的主题，删除后公开页会回到内置的默认主题。"
                : "主题目录会从磁盘上删掉，重新上传主题包可以装回来。"
          }
          confirmLabel="删除"
          busy={!!busy}
          onClose={() => setDoomed(null)}
          onConfirm={() => remove(doomed)}
        />
      )}
    </div>
    </>
  )
}

type Settings = Record<string, string | boolean>

// Two pages write settings, and each loads only what it displays.
function useSettings() {
  const [s, setS] = useState<Settings | null>(null)
  useEffect(() => { api<Settings>("/settings").then(setS).catch(() => {}) }, [])
  return {
    s,
    set: (k: string, v: string) => setS((old) => ({ ...(old ?? {}), [k]: v })),
    // Resolves to whether the hub took the patch; a failure is already toasted.
    save: async (patch: Record<string, string>, done = "已保存") => {
      try {
        await api("/settings", { method: "PUT", body: JSON.stringify(patch) })
      } catch (e) {
        toast.error((e as Error).message)
        return false
      }
      toast.success(done)
      // Only the saved keys and the `*_set` flags are taken from the hub: a
      // credential comes back as a flag, so the typed value must not linger,
      // while another card's unsaved edits on the same page must survive. A
      // failed read leaves the form as typed; the save itself stands.
      try {
        const fresh = await api<Settings>("/settings")
        setS((old) => {
          const next = { ...old }
          for (const key of Object.keys(patch)) next[key] = fresh[key]
          for (const [key, value] of Object.entries(fresh)) if (key.endsWith("_set")) next[key] = value
          return next
        })
      } catch (e) {
        toast.error((e as Error).message)
      }
      return true
    },
  }
}

// `onSaved` refreshes what the header shows, the site name among it.
function SettingsTab({ onSaved }: { onSaved: () => void }) {
  const { s, set, save } = useSettings()
  if (!s)
    return (
      <div className="space-y-4">
        <Card className="gap-3 p-5">
          <Skeleton className="h-5 w-40" />
          <Skeleton className="h-40 w-full" />
        </Card>
      </div>
    )
  return (
    <>
    <div className="space-y-4">
      <Card className="gap-4 p-5">
        <div className="grid gap-4 sm:grid-cols-2">
          <Field label="站点名称">
            <Input value={String(s.site_name ?? "")} onChange={(e) => set("site_name", e.target.value)} placeholder="Monitor" />
          </Field>
          <Field label="数据保留天数" hint="超出的明细自动清理，累计流量不受影响">
            <Input
              type="number"
              value={String(s.retention_days ?? "")}
              onChange={(e) => set("retention_days", e.target.value)}
              placeholder="7"
            />
          </Field>
          <Field
            label="GitHub 代理"
            hint="留空直连。仅在 hub 自己拉不到 GitHub Release 时填。这个地址返回的字节会被安装到每一台主机上，只填信得过的镜像"
          >
            <Input
              value={String(s.github_proxy ?? "")}
              onChange={(e) => set("github_proxy", e.target.value)}
              placeholder="https://ghfast.top"
            />
          </Field>
          {/* 记录开关在「日志」页（连同它的读写），这里只留保留期。 */}
          <Field label="日志保留（天）" hint="逐连接的访问记录保留多久，1–90 天">
            <Input
              type="number"
              value={String(s.conn_log_retention ?? "")}
              onChange={(e) => set("conn_log_retention", e.target.value)}
              placeholder="7"
            />
          </Field>
          <Field
            label="订阅地址"
            hint="代理订阅的备选入口，每行一个，可带端口或 http(s):// 前缀。第一行为主地址；留空用面板地址。域名 / 直连 IP / CDN 前置各占一行，客户的订阅内容会按每个入口各渲染一份"
          >
            <textarea
              className={TEXTAREA}
              rows={3}
              value={String(s.sub_hosts ?? "")}
              onChange={(e) => set("sub_hosts", e.target.value)}
              placeholder={"panel.example.com\ncdn.example.com:8443\n203.0.113.9"}
            />
          </Field>
          <Field label="sing-box 默认版本" hint="安装命令与自动补装共用，留空 = 最新版（计量需 ≥1.14，建议钉住）">
            <Input
              value={String(s.singbox_default_version ?? "")}
              onChange={(e) => set("singbox_default_version", e.target.value.replace(/[^0-9.]/g, ""))}
              placeholder="1.14.2"
              spellCheck={false}
              className="font-mono text-xs"
            />
          </Field>
          <Field label="realm 默认版本" hint="自动补装共用，留空 = 最新版">
            <Input
              value={String(s.realm_default_version ?? "")}
              onChange={(e) => set("realm_default_version", e.target.value.replace(/[^0-9.]/g, ""))}
              placeholder="2.9.6"
              spellCheck={false}
              className="font-mono text-xs"
            />
          </Field>
          <Field
            label="Cloudflare API Token"
            hint={s.cf_api_token_set ? "已设置，留空不变。主机编辑里的「绑定域名」靠它更新 A 记录" : "未设置。主机编辑里的「绑定域名」靠它更新 A 记录"}
          >
            <Input
              type="password"
              autoComplete="off"
              placeholder={s.cf_api_token_set ? "••••••••" : ""}
              value={String(s.cf_api_token ?? "")}
              onChange={(e) => set("cf_api_token", e.target.value)}
              spellCheck={false}
            />
          </Field>
        </div>
        {/* 不是 <label>：点文字不该切换开关，只有开关自己可点。
            aria-labelledby 保住读屏软件那边的关联。 */}
        <div className="flex items-center gap-2 text-sm">
          <Switch
            aria-labelledby="public-page-label"
            checked={s.public_page !== "off"}
            onCheckedChange={(v) => set("public_page", v ? "on" : "off")}
          />
          <span id="public-page-label">开放公开状态页，关闭后所有页面需登录</span>
        </div>
        <div>
          <Button
            size="sm"
            onClick={() =>
              save({
                site_name: String(s.site_name ?? ""),
                // conn_log_enabled 不在这里写：开关归「日志」页管，避免
                // 设置页一次保存把它按本地快照写回去。
                conn_log_retention: String(s.conn_log_retention || "7"),
                // `||` rather than `??`: the hub returns "" for an unset key
                // rather than null, and "" is the one value this key's write path
                // refuses.
                retention_days: String(s.retention_days || "7"),
                github_proxy: String(s.github_proxy ?? ""),
                sub_hosts: String(s.sub_hosts ?? ""),
                public_page: s.public_page === "off" ? "off" : "on",
                singbox_default_version: String(s.singbox_default_version ?? ""),
                realm_default_version: String(s.realm_default_version ?? ""),
                // Cloudflare Token 是掩码写：留空 = 保持不变，填了才提交。
                ...(typeof s.cf_api_token === "string" && s.cf_api_token ? { cf_api_token: s.cf_api_token } : {}),
              }).then((ok) => ok && onSaved())
            }
          >
            保存设置
          </Button>
        </div>
      </Card>

      <McpCard />
    </div>
    </>
  )
}

type McpLeaseRow = { token_hash: string; client: string; scopes: string; created_at: number; expires_at: number; revoked: boolean }
type McpOpRow = { tool: string; node: string; params: string; at: number; lease: string }

/** MCP 代理（五期）：AI 客户端经 OAuth 授权接入面板。开关、租约、审计。 */
function McpCard() {
  const [cfg, setCfg] = useState<{ enabled: boolean; leases: McpLeaseRow[]; operations: McpOpRow[] } | null>(null)
  const [revoking, setRevoking] = useState<string | null>(null)

  const load = useCallback(() => {
    api<{ enabled: boolean; leases: McpLeaseRow[]; operations: McpOpRow[] }>("/mcp/admin")
      .then(setCfg)
      .catch((e: Error) => toast.error(e.message))
  }, [])
  useEffect(() => {
    load()
  }, [load])

  async function toggle(on: boolean) {
    try {
      await api("/mcp/admin", { method: "PUT", body: JSON.stringify({ enabled: on }) })
      load()
    } catch (e) {
      toast.error((e as Error).message)
    }
  }

  async function revoke(hash: string) {
    if (revoking !== hash) {
      setRevoking(hash)
      setTimeout(() => setRevoking((a) => (a === hash ? null : a)), 3000)
      return
    }
    setRevoking(null)
    try {
      await api("/mcp/admin/revoke", { method: "POST", body: JSON.stringify({ token_hash: hash }) })
      toast.success("租约已吊销")
      load()
    } catch (e) {
      toast.error((e as Error).message)
    }
  }

  const fmt = (ts: number) => new Date(ts * 1000).toLocaleString("zh-CN", { month: "numeric", day: "numeric", hour: "2-digit", minute: "2-digit", hour12: false })
  return (
    <Card className="gap-4 p-5">
      <div className="flex flex-wrap items-start justify-between gap-3">
        <div className="min-w-0 flex-1">
          <h3 className="text-sm font-semibold">MCP 代理</h3>
          <p className="mt-1 text-xs leading-relaxed text-muted-foreground">
            AI 客户端经 OAuth 授权接入面板：端点 <code className="rounded bg-muted px-1">/api/mcp</code>，只读工具覆盖主机/流量/客户/告警/日志，另含远程执行（每次操作进审计）。接入方式：注册端点 <code className="rounded bg-muted px-1">/api/mcp/register</code>，批准页走管理员登录。
          </p>
        </div>
        <Switch checked={cfg?.enabled ?? false} onCheckedChange={toggle} aria-label="启用 MCP" />
      </div>
      {cfg && cfg.enabled && (
        <>
          {cfg.leases.length > 0 && (
            <div className="flex flex-col divide-y rounded-md border">
              {cfg.leases.map((l) => {
                const expired = l.expires_at < Date.now() / 1000
                return (
                  <div key={l.token_hash} className="flex flex-wrap items-center gap-2 px-3 py-2 text-sm first:rounded-t-md last:rounded-b-md">
                    <span className="font-medium">{l.client}</span>
                    <span className="text-xs text-muted-foreground">{l.scopes}</span>
                    <span className="ml-auto text-xs text-muted-foreground">
                      {fmt(l.created_at)} → {fmt(l.expires_at)}
                      {expired && "（已过期）"}
                    </span>
                    {!l.revoked && !expired && (
                      <Button size="sm" variant={revoking === l.token_hash ? "destructive" : "ghost"} onClick={() => revoke(l.token_hash)}>
                        {revoking === l.token_hash ? "确认吊销" : "吊销"}
                      </Button>
                    )}
                    {(l.revoked || expired) && <Badge variant="outline" className="font-normal">{l.revoked ? "已吊销" : "已过期"}</Badge>}
                  </div>
                )
              })}
            </div>
          )}
          {cfg.operations.length > 0 && (
            <div className="rounded-md border p-3">
              <div className="text-xs font-medium text-muted-foreground">最近操作（审计）</div>
              <div className="mt-1.5 flex flex-col gap-1">
                {cfg.operations.slice(0, 8).map((op, i) => (
                  <div key={i} className="flex items-center gap-2 text-xs">
                    <span className="text-muted-foreground">{fmt(op.at)}</span>
                    <span className="font-medium">{op.tool}</span>
                    {op.node && <span>{op.node}</span>}
                    <span className="truncate text-muted-foreground">{op.params}</span>
                  </div>
                ))}
              </div>
            </div>
          )}
        </>
      )}
    </Card>
  )
}

const TEXT_BOX =

  "w-full min-w-0 rounded-md border border-input bg-transparent px-3 py-2 shadow-xs outline-none placeholder:text-muted-foreground focus-visible:border-ring focus-visible:ring-[3px] focus-visible:ring-ring/50 dark:bg-input/30"
const TEXTAREA = `${TEXT_BOX} font-mono text-xs`

// One offline alert, filled in the way the hub fills a template: in a single pass,
// JSON-escaped for the webhook body. Previews only; nothing here is sent.
const SAMPLE_NOTE: Record<string, string> = {
  event: "offline",
  node: "香港 · 甲商家",
  title: "🔴 香港 · 甲商家 离线",
  message: "最后上报 09-15 20:13 +08:00",
  time: "09-15 20:16 +08:00",
}

const PLACEHOLDERS = "{{title}} {{message}} {{node}} {{event}} {{site}} {{time}}"

function TemplatePreview({ template, site, json = false }: { template: string; site: string; json?: boolean }) {
  if (!template.trim()) return <p className="text-xs text-muted-foreground">留空保存即恢复默认模板</p>
  const values = { ...SAMPLE_NOTE, site }
  let out = template.replace(/\{\{(event|node|title|message|site|time)\}\}/g, (_, key: keyof typeof values) =>
    json ? JSON.stringify(values[key]).slice(1, -1) : values[key],
  )
  if (json) {
    try {
      out = JSON.stringify(JSON.parse(out), null, 2)
    } catch {
      return (
        <p className="rounded-md bg-destructive/10 px-3 py-2 text-xs text-destructive">
          代入后不是合法 JSON，保存会被拒绝。占位符要写在引号里，例如 "text": "{"{{title}}"}"
        </p>
      )
    }
  }
  return (
    <div className="space-y-1">
      <div className="text-xs text-muted-foreground">预览（以一条离线通知为例）</div>
      <pre className="overflow-x-auto rounded-md bg-muted/50 px-3 py-2 font-mono text-xs whitespace-pre-wrap break-all">{out}</pre>
    </div>
  )
}

// Offline alerts are opt-in per node, so turning them on for a fleet needs one
// place rather than one dialog per node. Ticks are a draft until 保存, like every
// other form in the panel: a request per click would make each tick wait on a
// round trip and a refresh before showing.
function OfflineNodes({ nodes, refresh }: { nodes: Node[]; refresh: () => void }) {
  // Only the ticks changed here, by node id. A snapshot of every node's state
  // would send back a node another session switched meanwhile.
  const [draft, setDraft] = useState<Map<number, boolean>>(new Map())
  const [saving, setSaving] = useState(false)
  const on = (n: Node) => draft.get(n.id) ?? !!n.notify
  const chosen = new Set(nodes.filter(on).map((n) => n.id))
  // Against the live list, so a node deleted meanwhile is neither counted nor sent.
  const turnOn = nodes.filter((n) => on(n) && !n.notify).map((n) => n.id)
  const turnOff = nodes.filter((n) => !on(n) && n.notify).map((n) => n.id)
  const dirty = turnOn.length + turnOff.length > 0

  // Kept after a save until the list reports it, so the ticks do not flash back
  // to the old state for a round trip. Adjusted during render rather than in an
  // effect, as it follows from props alone.
  if (draft.size && !dirty && !saving) setDraft(new Map())

  const pick = (list: Node[], value: boolean) =>
    setDraft((old) => {
      const next = new Map(old)
      for (const n of list) next.set(n.id, value)
      return next
    })

  async function save() {
    setSaving(true)
    try {
      for (const [ids, on] of [[turnOn, true], [turnOff, false]] as const) {
        if (ids.length) await api("/nodes/batch", { method: "PUT", body: JSON.stringify({ ids, patch: { notify: on } }) })
      }
      toast.success("离线通知已保存")
    } catch (e) {
      toast.error((e as Error).message)
    } finally {
      refresh()
      setSaving(false)
    }
  }

  const pending = [turnOn.length && `打开 ${turnOn.length} 台`, turnOff.length && `关闭 ${turnOff.length} 台`].filter(Boolean)
  return (
    <Card className="gap-4 p-5">
      <div>
        <h3 className="text-sm font-semibold">离线通知</h3>
        <p className="mt-1 text-xs text-muted-foreground">
          按主机打开，默认关。已打开 {nodes.filter((n) => n.notify).length} / {nodes.length} 台
          {pending.length > 0 && <span className="text-foreground">，待保存：{pending.join("、")}</span>}
        </p>
      </div>
      <NodePicker nodes={nodes} chosen={chosen} onPick={pick} disabled={saving} />
      <div className="flex justify-end gap-2">
        <Button size="sm" variant="ghost" disabled={!dirty || saving} onClick={() => setDraft(new Map())}>撤销</Button>
        <Button size="sm" disabled={!dirty || saving} onClick={save}>保存</Button>
      </div>
    </Card>
  )
}

type NotifyChannelRow = {
  id: number
  name: string
  kind: string
  enabled: boolean
  config: Record<string, unknown>
  sets: Record<string, boolean>
}
type NotifyConfig = {
  channels: NotifyChannelRow[]
  kinds: { key: string; label: string }[]
  events: { key: string; label: string; desc: string }[]
  routes: Record<string, number[]>
  digest: number
}

// 每类渠道的表单字段：password 型是凭据（编辑留空 = 沿用旧值，面板显示占位点）。
const CHANNEL_FIELDS: Record<string, { key: string; label: string; type?: "password" | "textarea"; placeholder?: string; hint?: string }[]> = {
  telegram: [
    { key: "token", label: "Bot Token", type: "password", placeholder: "123456:ABC-DEF…" },
    { key: "chat", label: "Chat ID", placeholder: "-1001234567890", hint: "数字 ID，群组是负数；公开频道可填 @频道名" },
    { key: "text", label: "消息模板", type: "textarea", hint: `纯文本。占位符 ${PLACEHOLDERS}` },
  ],
  webhook: [
    { key: "url", label: "URL", type: "password", placeholder: "https://…" },
    { key: "headers", label: "请求头", type: "textarea", placeholder: "Authorization: Bearer xxx", hint: "可选，一行一个" },
    { key: "body", label: "请求体", type: "textarea", hint: `以 POST 发送 JSON。占位符 ${PLACEHOLDERS}，须写在引号内` },
  ],
  bark: [
    { key: "server", label: "服务器", placeholder: "https://api.day.app", hint: "留空用官方推送服务器" },
    { key: "key", label: "Bark Key", type: "password", placeholder: "App 里显示的推送 Key" },
    { key: "group", label: "分组", placeholder: "monitor", hint: "可选，通知按组归档" },
  ],
  serverchan: [{ key: "key", label: "SendKey", type: "password", placeholder: "SCT…" }],
  smtp: [
    { key: "host", label: "服务器", placeholder: "smtp.example.com" },
    { key: "port", label: "端口", placeholder: "587", hint: "465 走隐式 TLS，其余端口走 STARTTLS" },
    { key: "username", label: "用户名", placeholder: "留空则不认证" },
    { key: "password", label: "密码", type: "password" },
    { key: "from", label: "发件地址", placeholder: "panel@example.com" },
    { key: "to", label: "收件地址", placeholder: "me@example.com" },
  ],
}

const KIND_DOT: Record<string, string> = {
  telegram: "bg-sky-500",
  webhook: "bg-orange-500",
  bark: "bg-emerald-500",
  smtp: "bg-violet-500",
  serverchan: "bg-cyan-500",
}

/// 事件路由卡（用户拍板折叠）：默认收起只显示摘要（N 类事件 → 已启用渠道
/// 数），展开才是完整路由表；勾选逻辑与原先一致。
function RouteCard({ cfg, setCfg, reload }: { cfg: NotifyConfig; setCfg: (c: NotifyConfig) => void; reload: () => void }) {
  const [open, setOpen] = useState(false)
  const enabled = cfg.channels.filter((c) => c.enabled)
  const fallback = enabled.map((c) => c.id)
  const custom = cfg.events.filter((ev) => {
    const routed = cfg.routes[ev.key]
    return routed !== undefined && (routed.length !== fallback.length || routed.some((id) => !fallback.includes(id)))
  }).length
  async function toggleRoute(event: string, channelId: number) {
    const current = cfg.routes[event] ?? enabled.map((c) => c.id)
    const next = current.includes(channelId) ? current.filter((v) => v !== channelId) : [...current, channelId]
    // 乐观更新，失败回滚由 reload 兜底。
    setCfg({ ...cfg, routes: { ...cfg.routes, [event]: next } })
    try {
      await api("/notify/routes", { method: "PUT", body: JSON.stringify({ routes: { [event]: next } }) })
    } catch (e) {
      toast.error((e as Error).message)
      reload()
    }
  }


  return (
    <Card className="gap-4 p-5">
      <div className="flex items-center justify-between gap-3">
        <div className="min-w-0">
          <div className="flex items-center gap-2">
            <h3 className="text-sm font-semibold">事件路由</h3>
            <span className="rounded bg-muted px-1.5 py-0.5 text-[10px] font-medium text-muted-foreground">
              {custom > 0 ? `${custom} 类已自定义` : "全部默认"}
            </span>
          </div>
          <p className="mt-1 text-xs text-muted-foreground">
            {cfg.events.length} 类事件 → {enabled.length} 个启用渠道
          </p>
        </div>
        <Button variant="ghost" size="sm" className="text-xs text-muted-foreground" onClick={() => setOpen((v) => !v)}>
          {open ? "收起" : "展开"}
        </Button>
      </div>
      {open && (
        <>
          <p className="text-xs leading-relaxed text-muted-foreground">
            每类事件发到勾选的渠道；全不勾 = 该事件静默。没动过的事件默认发到全部启用渠道。
          </p>
          <div className="flex flex-col divide-y">
            {cfg.events.map((ev) => {
              const fallback2 = enabled.map((c) => c.id)
              const routed = cfg.routes[ev.key] ?? fallback2
              return (
                <div key={ev.key} className="flex flex-wrap items-center gap-x-4 gap-y-2 py-2.5 first:pt-0 last:pb-0">
                  <div className="min-w-40">
                    <div className="text-sm font-medium">{ev.label}</div>
                    <div className="text-xs text-muted-foreground">{ev.desc}</div>
                  </div>
                  <div className="flex flex-wrap gap-1.5">
                    {cfg.channels.map((c) => (
                      <button
                        key={c.id}
                        type="button"
                        disabled={!c.enabled}
                        onClick={() => toggleRoute(ev.key, c.id)}
                        className={`rounded-full border px-2.5 py-0.5 text-xs transition-colors ${
                          routed.includes(c.id) ? "border-primary/40 bg-primary/15 text-primary" : "text-muted-foreground"
                        } ${!c.enabled ? "cursor-not-allowed opacity-40" : ""}`}
                      >
                        {c.name}
                      </button>
                    ))}
                  </div>
                </div>
              )
            })}
          </div>
        </>
      )}
    </Card>
  )
}

/** 通知设置（二期底座）：渠道实例、事件路由表、汇总推送窗口。 */
function Notify({ nodes, refresh }: { nodes: Node[]; refresh: () => void }) {
  const { s, set, save } = useSettings()
  const [cfg, setCfg] = useState<NotifyConfig | null>(null)
  const [testing, setTesting] = useState(false)
  // 编辑器状态：id=null 新建。config 的凭据字段从 sets 渲染占位点，提交时留空=沿用。
  const [editing, setEditing] = useState<{ id: number | null; kind: string; name: string; config: Record<string, string>; sets: Record<string, boolean> } | null>(null)
  const [saving, setSaving] = useState(false)
  const [armedDelete, setArmedDelete] = useState<number | null>(null)
  const [digestDraft, setDigestDraft] = useState<string | null>(null)
  // 早退必须在全部 hooks 之后（React #310：条件渲染改变 hook 数量）。
  const text = (k: string) => String(s?.[k] ?? "")

  const load = useCallback(async () => {
    try {
      setCfg(await api<NotifyConfig>("/notify/config"))
    } catch (e) {
      toast.error((e as Error).message)
    }
  }, [])
  useEffect(() => {
    load()
  }, [load])
  if (!s) return null

  const kindLabel = (key: string) => cfg?.kinds.find((k) => k.key === key)?.label ?? key

  function openCreate() {
    setEditing({ id: null, kind: "telegram", name: "", config: {}, sets: {} })
  }
  function openEdit(row: NotifyChannelRow) {
    const config: Record<string, string> = {}
    for (const f of CHANNEL_FIELDS[row.kind] ?? []) {
      config[f.key] = typeof row.config[f.key] === "string" ? (row.config[f.key] as string) : ""
    }
    setEditing({ id: row.id, kind: row.kind, name: row.name, config, sets: row.sets })
  }

  async function saveEditing() {
    if (!editing) return
    setSaving(true)
    try {
      if (editing.id === null) {
        await api("/notify/channels", { method: "POST", body: JSON.stringify({ name: editing.name, kind: editing.kind, config: editing.config }) })
        toast.success("渠道已添加")
      } else {
        await api(`/notify/channels/${editing.id}`, { method: "PUT", body: JSON.stringify({ name: editing.name, enabled: true, config: editing.config }) })
        toast.success("渠道已保存")
      }
      setEditing(null)
      await load()
    } catch (e) {
      toast.error((e as Error).message)
    } finally {
      setSaving(false)
    }
  }

  async function toggleChannel(row: NotifyChannelRow) {
    try {
      // 不带 config = 配置原样保留，只切启停。
      await api(`/notify/channels/${row.id}`, { method: "PUT", body: JSON.stringify({ name: row.name, enabled: !row.enabled }) })
      await load()
    } catch (e) {
      toast.error((e as Error).message)
    }
  }

  async function deleteChannel(row: NotifyChannelRow) {
    if (armedDelete !== row.id) {
      setArmedDelete(row.id)
      setTimeout(() => setArmedDelete((a) => (a === row.id ? null : a)), 3000)
      return
    }
    setArmedDelete(null)
    try {
      await api(`/notify/channels/${row.id}`, { method: "DELETE" })
      toast.success("渠道已删除")
      await load()
    } catch (e) {
      toast.error((e as Error).message)
    }
  }

  async function testChannel(id: number) {
    try {
      const { sent } = await api<{ sent: string }>(`/notify/channels/${id}/test`, { method: "POST" })
      toast.success(`测试通知已发送：${sent}`)
    } catch (e) {
      toast.error((e as Error).message)
    }
  }

  async function testAll() {
    setTesting(true)
    try {
      const { sent } = await api<{ sent: string[] }>("/notify/test", { method: "POST" })
      toast.success(`测试通知已发送：${sent.join("、")}`)
    } catch (e) {
      toast.error((e as Error).message)
    } finally {
      setTesting(false)
    }
  }


  async function saveDigest() {
    try {
      await api("/notify/digest", { method: "PUT", body: JSON.stringify({ seconds: Number(digestDraft ?? cfg?.digest ?? 0) }) })
      toast.success("汇总推送已保存")
      setDigestDraft(null)
      await load()
    } catch (e) {
      toast.error((e as Error).message)
    }
  }

  const editingFields = editing ? (CHANNEL_FIELDS[editing.kind] ?? []) : []
  const digestValue = digestDraft ?? String(cfg?.digest ?? 0)

  return (
    <>
    <div className="space-y-4">
      <Card className="gap-4 p-5">
        <div className="flex flex-wrap items-start justify-between gap-3">
          <div className="min-w-0 flex-1">
            <h3 className="text-sm font-semibold">通知渠道</h3>
            <p className="mt-1 text-xs leading-relaxed text-muted-foreground">
              一个渠道是一处推送目的地，可配多个同类。每类事件发到哪些渠道在「事件路由」里选；离线通知在下方按主机打开，流量和到期提醒对填了额度、到期日的主机生效。
            </p>
          </div>
          <div className="flex gap-2">
            <Button size="sm" variant="secondary" disabled={testing} onClick={testAll}>
              <Send /> {testing ? "发送中…" : "全部测试"}
            </Button>
            <Button size="sm" onClick={openCreate}>
              <Plus /> 新增渠道
            </Button>
          </div>
        </div>
        {!cfg || cfg.channels.length === 0 ? (
          <div className="py-6 text-center text-sm text-muted-foreground">还没有渠道，点「新增渠道」配置第一个推送目的地。</div>
        ) : (
          <div className="flex flex-col divide-y">
            {cfg.channels.map((row) => (
              <div key={row.id} className="flex flex-wrap items-center gap-3 py-2.5 first:pt-0 last:pb-0">
                <span className={`inline-block size-2 shrink-0 rounded-full ${row.enabled ? KIND_DOT[row.kind] ?? "bg-muted-foreground" : "bg-zinc-400"}`} title={row.enabled ? "启用" : "停用"} />
                <span className="min-w-0 flex-1 truncate font-medium">{row.name}</span>
                <span className="text-xs text-muted-foreground">{kindLabel(row.kind)}</span>
                <Switch checked={row.enabled} onCheckedChange={() => toggleChannel(row)} aria-label={`启停 ${row.name}`} />
                <Button size="sm" variant="ghost" onClick={() => testChannel(row.id)}>测试</Button>
                <Button size="sm" variant="ghost" onClick={() => openEdit(row)}>
                  <Pencil className="size-3.5" /> 编辑
                </Button>
                <Button size="sm" variant={armedDelete === row.id ? "destructive" : "ghost"} onClick={() => deleteChannel(row)}>
                  <Trash2 className="size-3.5" /> {armedDelete === row.id ? "确认删除" : "删除"}
                </Button>
              </div>
            ))}
          </div>
        )}
      </Card>

      {cfg && <RouteCard cfg={cfg} setCfg={setCfg} reload={load} />}

      <Card className="gap-4 p-5">
        <div>
          <h3 className="text-sm font-semibold">丢包与延迟告警</h3>
          <p className="mt-1 text-xs leading-relaxed text-muted-foreground">
            按「监控」页的探测任务评估：丢包率超过阈值、或延迟偏离自适应基线，连续确认后告警，回落即恢复。事件在上方「事件路由」里挑渠道（探测丢包/探测延迟异常）。
          </p>
        </div>
        <div className="flex items-center gap-2 text-sm">
          <Switch
            aria-labelledby="ping-alert-enabled-label"
            checked={s.ping_alert_enabled !== "off"}
            onCheckedChange={(v) => {
              set("ping_alert_enabled", v ? "on" : "off")
              save({ ping_alert_enabled: v ? "on" : "off" })
            }}
          />
          <span id="ping-alert-enabled-label">启用探测告警</span>
        </div>
        <div className="grid gap-4 sm:grid-cols-2 lg:grid-cols-3">
          <Field label="丢包告警阈值（%）" hint="窗口内丢包率达到该比例即算越限，1–100">
            <Input type="number" min={1} max={100} value={text("ping_alert_loss_pct")} onChange={(e) => set("ping_alert_loss_pct", e.target.value)} />
          </Field>
          <Field label="丢包窗口（分钟）" hint="按窗口内的实际回报数算丢包率，1–60">
            <Input type="number" min={1} max={60} value={text("ping_alert_loss_window_min")} onChange={(e) => set("ping_alert_loss_window_min", e.target.value)} />
          </Field>
          <Field label="延迟基线窗口（分钟）" hint="窗口内成功样本的中位数为基线，样本不足 10 个是学习期，5–360">
            <Input type="number" min={5} max={360} value={text("ping_alert_latency_window_min")} onChange={(e) => set("ping_alert_latency_window_min", e.target.value)} />
          </Field>
          <Field label="延迟偏离系数（%）" hint="当前中位数超过 基线×系数% 即越限，100–500">
            <Input type="number" min={100} max={500} value={text("ping_alert_factor_pct")} onChange={(e) => set("ping_alert_factor_pct", e.target.value)} />
          </Field>
          <Field label="延迟偏离底线（ms）" hint="系数之外再放宽的绝对值，0–1000；低基线链路靠它避免误报">
            <Input type="number" min={0} max={1000} value={text("ping_alert_floor_ms")} onChange={(e) => set("ping_alert_floor_ms", e.target.value)} />
          </Field>
          <Field label="连续确认（次）" hint="连续这么多次评估都越限才告警，恢复再多要一次，1–10">
            <Input type="number" min={1} max={10} value={text("ping_alert_confirm")} onChange={(e) => set("ping_alert_confirm", e.target.value)} />
          </Field>
        </div>
        <div className="flex justify-end">
          <Button
            size="sm"
            onClick={() =>
              save({
                ping_alert_loss_pct: text("ping_alert_loss_pct"),
                ping_alert_loss_window_min: text("ping_alert_loss_window_min"),
                ping_alert_latency_window_min: text("ping_alert_latency_window_min"),
                ping_alert_factor_pct: text("ping_alert_factor_pct"),
                ping_alert_floor_ms: text("ping_alert_floor_ms"),
                ping_alert_confirm: text("ping_alert_confirm"),
              })
            }
          >
            保存
          </Button>
        </div>
      </Card>

      <OfflineNodes nodes={nodes} refresh={refresh} />

      <Card className="gap-4 p-5">
        <h3 className="text-sm font-semibold">事件</h3>
        <div className="grid gap-4 sm:grid-cols-2 lg:grid-cols-4">
          <Field label="离线宽限期（分钟）" hint="断开超过这么久才算离线，1–30">
            <Input type="number" min={1} max={30} value={text("notify_grace")} onChange={(e) => set("notify_grace", e.target.value)} />
          </Field>
          <Field label="流量提醒（%）" hint="本期用量达到该比例和 100% 时各提醒一次，0 关闭">
            <Input type="number" min={0} max={100} value={text("notify_traffic")} onChange={(e) => set("notify_traffic", e.target.value)} />
          </Field>
          <Field label="到期提醒（天）" hint="每天 9 点汇总这么多天内到期的主机，自动续期时也提醒，0 关闭">
            <Input type="number" min={0} max={365} value={text("notify_expiry")} onChange={(e) => set("notify_expiry", e.target.value)} />
          </Field>
          <Field label="汇总推送（秒）" hint="窗口内相同内容的告警合并成一条，0 关闭">
            <Input
              type="number"
              min={0}
              max={3600}
              value={digestValue}
              onChange={(e) => setDigestDraft(e.target.value)}
              onBlur={() => {
                if (digestDraft !== null && Number(digestDraft) !== (cfg?.digest ?? 0)) saveDigest()
                else setDigestDraft(null)
              }}
            />
          </Field>
        </div>
        <div className="flex flex-wrap items-center justify-between gap-3">
          <div className="flex items-center gap-2 text-sm">
            <Switch aria-labelledby="notify-login-label" checked={s.notify_login !== "off"} onCheckedChange={(v) => set("notify_login", v ? "on" : "off")} />
            <span id="notify-login-label">登录后台时提醒</span>
          </div>
          <Button
            size="sm"
            onClick={() =>
              save({
                notify_grace: text("notify_grace"),
                notify_traffic: text("notify_traffic"),
                notify_expiry: text("notify_expiry"),
                notify_login: s.notify_login === "off" ? "off" : "on",
              })
            }
          >
            保存
          </Button>
        </div>
      </Card>

      <Dialog open={editing !== null} onOpenChange={(v) => !v && setEditing(null)}>
        <DialogContent className="max-h-[85vh] overflow-y-auto sm:max-w-lg">
          <DialogHeader>
            <DialogTitle>{editing?.id === null ? "新增渠道" : "编辑渠道"}</DialogTitle>
            <DialogDescription>
              {editing?.id === null ? "选类型、填凭据；同类渠道可以配多个，各自启停。" : "凭据字段留空 = 沿用已保存的值。"}
            </DialogDescription>
          </DialogHeader>
          {editing && (
            <div className="flex flex-col gap-3">
              <div className="grid grid-cols-2 gap-3">
                <div className="flex flex-col gap-1.5">
                  <Label>渠道名称</Label>
                  <Input value={editing.name} onChange={(e) => setEditing({ ...editing, name: e.target.value })} placeholder="例如 运维群 Telegram" />
                </div>
                <div className="flex flex-col gap-1.5">
                  <Label>类型</Label>
                  <Select
                    value={editing.kind}
                    disabled={editing.id !== null}
                    onValueChange={(v) => setEditing({ ...editing, kind: v, config: {}, sets: {} })}
                  >
                    <SelectTrigger><SelectValue /></SelectTrigger>
                    <SelectContent>
                      {(cfg?.kinds ?? []).map((k) => (
                        <SelectItem key={k.key} value={k.key}>{k.label}</SelectItem>
                      ))}
                    </SelectContent>
                  </Select>
                </div>
              </div>
              {editing.id !== null && editing.sets && Object.keys(editing.sets).length > 0 && (
                <p className="text-xs text-muted-foreground">
                  已配置的凭据：{Object.entries(editing.sets).filter(([, v]) => v).map(([k]) => editingFields.find((f) => f.key === k)?.label ?? k).join("、")}（留空沿用）
                </p>
              )}
              {editingFields.map((f) => (
                <Field key={f.key} label={f.label} hint={f.hint ?? (editing.sets[f.key] ? "已设置，留空不变" : undefined)}>
                  {f.type === "textarea" ? (
                    <textarea
                      rows={f.key === "body" ? 4 : 3}
                      className={TEXTAREA}
                      placeholder={editing.sets[f.key] ? "••••••••" : f.placeholder}
                      value={editing.config[f.key] ?? ""}
                      onChange={(e) => setEditing({ ...editing, config: { ...editing.config, [f.key]: e.target.value } })}
                    />
                  ) : (
                    <Input
                      type={f.type === "password" ? "password" : "text"}
                      autoComplete="off"
                      placeholder={editing.sets[f.key] ? "••••••••" : f.placeholder}
                      value={editing.config[f.key] ?? ""}
                      onChange={(e) => setEditing({ ...editing, config: { ...editing.config, [f.key]: e.target.value } })}
                    />
                  )}
                </Field>
              ))}
              {(editing.kind === "telegram" || editing.kind === "webhook") && (
                <TemplatePreview
                  template={editing.config[editing.kind === "telegram" ? "text" : "body"] ?? ""}
                  site={text("site_name") || "Monitor"}
                  json={editing.kind === "webhook"}
                />
              )}
            </div>
          )}
          <DialogFooter>
            <Button variant="ghost" onClick={() => setEditing(null)}>取消</Button>
            <Button disabled={saving || !editing?.name.trim()} onClick={saveEditing}>
              {saving ? "保存中…" : "保存"}
            </Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>
    </div>
    </>
  )
}

// ---- 回程线路探测（四期）：任务 + 链路状态 + 变化事件 ----

// 常见探测目标（三大运营商公共 DNS）：弹窗里做成一键 chips，自定义仍走输入框。
const COMMON_ROUTE_TARGETS = [
  { label: "电信 DNS", ip: "222.66.151.1" },
  { label: "移动 DNS", ip: "120.196.165.24" },
  { label: "联通 DNS", ip: "210.21.4.130" },
]

type RouteStatusRow = {
  node_id: number
  node: string
  online: boolean
  hops: { ttl: number; ip?: string; line?: string }[]
  line: string
  baseline: string
  probes: number
  probed_at: number
}
type RouteTaskRow = { id: number; name: string; target: string; interval: number; enabled: boolean; nodes: RouteStatusRow[] }
type RouteConfig = {
  tasks: RouteTaskRow[]
  events: { task_id: number; node_id: number; from: string; to: string; at: number }[]
  rules: { name: string; count: number }[]
}

const LINE_CHIP: Record<string, string> = {
  电信163: "bg-sky-500/15 text-sky-600 dark:text-sky-400",
  电信CN2: "bg-primary/15 text-primary",
  电信城域: "bg-sky-500/15 text-sky-600 dark:text-sky-400",
  移动CMI: "bg-violet-500/15 text-violet-600 dark:text-violet-400",
  移动城域: "bg-violet-500/15 text-violet-600 dark:text-violet-400",
  联通4837: "bg-emerald-500/15 text-emerald-600 dark:text-emerald-400",
  联通城域: "bg-emerald-500/15 text-emerald-600 dark:text-emerald-400",
}

function LineChip({ line }: { line: string }) {
  if (!line) return <span className="text-xs text-muted-foreground">未识别</span>
  return <span className={`rounded px-1.5 py-px text-xs font-medium ${LINE_CHIP[line] ?? "bg-muted text-foreground"}`}>{line}</span>
}

function RouteSection({ nodes }: { nodes: Node[] }) {
  const [cfg, setCfg] = useState<RouteConfig | null>(null)
  const [editing, setEditing] = useState<(Partial<Omit<RouteTaskRow, "nodes">> & { nodes?: number[] }) | null>(null)
  const [deleting, setDeleting] = useState<RouteTaskRow | null>(null)
  const [removing, setRemoving] = useState(false)
  const [probing, setProbing] = useState<number | null>(null)
  const [expanded, setExpanded] = useState<string | null>(null)
  // 编辑器里的 nodes 是节点 id（列表行的 nodes 是链路状态，两者不同物）。

  const load = useCallback(() => {
    api<RouteConfig>("/route/tasks")
      .then(setCfg)
      .catch((e: Error) => toast.error(e.message))
  }, [])
  useEffect(() => {
    load()
  }, [load])

  async function probe(id: number) {
    setProbing(id)
    try {
      const { results } = await api<{ results: { node: string; line?: string; baseline?: string; error?: string }[] }>(`/route/tasks/${id}/probe`, { method: "POST" })
      for (const r of results) {
        if (r.error) toast.error(`${r.node}：${r.error}`)
        else toast.success(`${r.node}：${r.line || "未识别"}${r.baseline ? `（基线 ${r.baseline}）` : ""}`)
      }
      load()
    } catch (e) {
      toast.error((e as Error).message)
    } finally {
      setProbing(null)
    }
  }

  async function remove() {
    if (!deleting) return
    setRemoving(true)
    try {
      await api(`/route/tasks/${deleting.id}`, { method: "DELETE" })
      toast.success("回程任务已删除")
      setDeleting(null)
      load()
    } catch (e) {
      toast.error((e as Error).message)
    } finally {
      setRemoving(false)
    }
  }

  return (
    <>
      {/* 页头行在卡片外（用户拍板）：标题 + 添加按钮 + 内置线路规则收纳 */}
      <div className="flex flex-wrap items-center justify-between gap-3">
        <div className="flex min-w-0 items-center gap-2">
          <h3 className="text-sm font-semibold">回程链路状态</h3>
          {cfg && cfg.rules.length > 0 && (
            <Tooltip disableHoverableContent>
              <TooltipTrigger asChild>
                <span className="cursor-help rounded bg-muted px-1.5 py-0.5 text-[10px] font-medium text-muted-foreground">
                  内置线路 {cfg.rules.length} 条
                </span>
              </TooltipTrigger>
              <TooltipContent side="right" sideOffset={6}>
                <div className="text-xs">{cfg.rules.map((r) => `${r.name}(${r.count} 段)`).join("、")}</div>
                <div className="mt-1 opacity-70">按骨干网段识别每跳归属</div>
              </TooltipContent>
            </Tooltip>
          )}
        </div>
        <Button onClick={() => setEditing({ name: "", target: "223.5.5.5", interval: 600, enabled: true, nodes: [] })}>
          <Plus /> 添加回程
        </Button>
      </div>
      <Card className="gap-4 p-5">
        <p className="text-xs leading-relaxed text-muted-foreground">
          从指派的主机对目标做 ICMP traceroute，按骨干网段识别每跳归属（电信/移动/联通）。前三次探测是学习期，只建基线不告警。
        </p>
      {!cfg || cfg.tasks.length === 0 ? (
        <div className="py-6 text-center text-sm text-muted-foreground">还没有回程任务。添加一个目标（如电信 DNS 222.66.151.1），面板会从各主机探测回程链路并识别线路。</div>
      ) : (
        <div className="flex flex-col divide-y">
          {cfg.tasks.map((t) => (
            <div key={t.id} className="flex flex-col gap-2 py-3 first:pt-0 last:pb-0">
              <div className="flex flex-wrap items-center gap-2">
                <span className="font-medium">{t.name}</span>
                <span className="tnum text-xs text-muted-foreground">→ {t.target}</span>
                <span className="tnum text-xs text-muted-foreground">每 {t.interval}s</span>
                {!t.enabled && <Badge variant="outline" className="font-normal">停用</Badge>}
                <span className="flex-1" />
                <Button size="sm" variant="ghost" disabled={probing === t.id} onClick={() => probe(t.id)}>
                  <Radio /> {probing === t.id ? "探测中…" : "立即探测"}
                </Button>
                <Button size="sm" variant="ghost" onClick={() => setEditing({ id: t.id, name: t.name, target: t.target, interval: t.interval, enabled: t.enabled, nodes: t.nodes.map((n) => n.node_id) })}>
                  <Pencil className="size-3.5" /> 编辑
                </Button>
                <Button size="sm" variant={deleting?.id === t.id ? "destructive" : "ghost"} disabled={removing} onClick={() => (deleting?.id === t.id ? remove() : setDeleting(t))}>
                  <Trash2 className="size-3.5" /> {deleting?.id === t.id ? "确认删除" : "删除"}
                </Button>
              </div>
              <div className="flex flex-col gap-1">
                {t.nodes.map((n) => {
                  const ek = `${t.id}:${n.node_id}`
                  return (
                    <div key={n.node_id} className="rounded-md border px-3 py-2">
                      <button type="button" className="flex w-full items-center gap-2 text-left" onClick={() => setExpanded(expanded === ek ? null : ek)}>
                        <span className={`inline-block size-1.5 rounded-full ${n.online ? "bg-ok" : "bg-zinc-400"}`} title={n.online ? "在线" : "离线"} />
                        <span className="text-sm font-medium">{n.node}</span>
                        <LineChip line={n.line} />
                        {n.probes < 3 && n.probes > 0 && <Badge variant="outline" className="font-normal">学习期 {n.probes}/3</Badge>}
                        {n.probes === 0 && <span className="text-xs text-muted-foreground">未探测</span>}
                        <span className="flex-1" />
                        {n.probed_at > 0 && <span className="text-xs text-muted-foreground">{new Date(n.probed_at * 1000).toLocaleTimeString("zh-CN", { hour: "2-digit", minute: "2-digit", hour12: false })} 探测</span>}
                        <ChevronDown className={`size-3.5 text-muted-foreground transition-transform ${expanded === ek ? "rotate-180" : ""}`} />
                      </button>
                      {expanded === ek && (
                        <div className="mt-2 flex flex-col gap-0.5 border-t pt-2">
                          {n.hops.length === 0 && <span className="text-xs text-muted-foreground">还没有链路数据。</span>}
                          {n.hops.map((h) => (
                            <div key={h.ttl} className="flex items-center gap-2 text-xs">
                              <span className="tnum w-8 text-muted-foreground">{h.ttl}</span>
                              {h.ip ? <span className="tnum font-mono">{h.ip}</span> : <span className="text-muted-foreground">* * *</span>}
                              {h.line && <LineChip line={h.line} />}
                            </div>
                          ))}
                        </div>
                      )}
                    </div>
                  )
                })}
              </div>
            </div>
          ))}
        </div>
      )}
      {cfg && cfg.events.length > 0 && (
        <div className="rounded-md border p-3">
          <div className="text-xs font-medium text-muted-foreground">最近线路变化</div>
          <div className="mt-1.5 flex flex-col gap-1">
            {cfg.events.slice(0, 8).map((ev, i) => {
              const task = cfg.tasks.find((t) => t.id === ev.task_id)
              const node = task?.nodes.find((n) => n.node_id === ev.node_id)?.node ?? `主机 ${ev.node_id}`
              return (
                <div key={i} className="flex items-center gap-2 text-xs">
                  <span className="text-muted-foreground">{new Date(ev.at * 1000).toLocaleString("zh-CN", { month: "numeric", day: "numeric", hour: "2-digit", minute: "2-digit", hour12: false })}</span>
                  <span className="font-medium">{node}</span>
                  <span>{ev.from || "未识别"} → {ev.to}</span>
                  <span className="text-muted-foreground">（{task?.name ?? ev.task_id}）</span>
                </div>
              )
            })}
          </div>
        </div>
      )}

      <Dialog open={editing !== null} onOpenChange={(v) => !v && setEditing(null)}>
        <DialogContent className="sm:max-w-md">
          <DialogHeader>
            <DialogTitle>{editing?.id ? "编辑回程" : "添加回程"}</DialogTitle>
            <DialogDescription>从指派的主机对目标做 ICMP traceroute（需要主机上的 agent 以 root 运行，默认满足）。</DialogDescription>
          </DialogHeader>
          {editing && (
            <div className="flex flex-col gap-3">
              <Field label="任务名称">
                <Input value={editing.name ?? ""} onChange={(e) => setEditing({ ...editing, name: e.target.value })} placeholder="例如 电信回程" />
              </Field>
              <Field label="目标（IPv4）">
                <Input value={editing.target ?? ""} onChange={(e) => setEditing({ ...editing, target: e.target.value })} placeholder="223.5.5.5" />
                {/* 常见目标一键填入（用户提议：可选 chips + 自定义输入兜底）；当前值命中即高亮 */}
                <div className="flex flex-wrap gap-1.5">
                  {COMMON_ROUTE_TARGETS.map((t) => {
                    const chosen = editing.target === t.ip
                    return (
                      <button
                        key={t.ip}
                        type="button"
                        className={`rounded-full border px-2.5 py-0.5 text-xs transition-colors ${chosen ? "border-primary/40 bg-primary/15 text-primary" : "border-input text-muted-foreground hover:bg-muted"}`}
                        onClick={() => setEditing({ ...editing, target: t.ip })}
                      >
                        {t.label} <span className="tnum font-mono">{t.ip}</span>
                      </button>
                    )
                  })}
                </div>
              </Field>
              <Field label="探测间隔（秒）" hint="60–86400">
                <Input type="number" min={60} max={86400} value={editing.interval ?? 600} onChange={(e) => setEditing({ ...editing, interval: Number(e.target.value) })} />
              </Field>
              <div className="flex flex-col gap-1.5">
                <Label>指派主机</Label>
                <div className="flex flex-wrap gap-1.5">
                  {nodes.map((n) => {
                    const chosen = (editing.nodes ?? []).includes(n.id)
                    return (
                      <button
                        key={n.id}
                        type="button"
                        className={`rounded-full border px-2.5 py-0.5 text-xs transition-colors ${chosen ? "border-primary/40 bg-primary/15 text-primary" : "border-input text-muted-foreground hover:bg-muted"}`}
                        onClick={() => {
                          const cur = editing.nodes ?? []
                          setEditing({ ...editing, nodes: chosen ? cur.filter((v) => v !== n.id) : [...cur, n.id] })
                        }}
                      >
                        {n.name}
                      </button>
                    )
                  })}
                </div>
              </div>
            </div>
          )}
          <DialogFooter>
            <Button variant="ghost" onClick={() => setEditing(null)}>取消</Button>
            <Button
              disabled={!editing?.name?.trim() || !editing?.target?.trim()}
              onClick={async () => {
                try {
                  await api("/route/tasks", { method: "POST", body: JSON.stringify(editing) })
                  toast.success("回程任务已保存")
                  setEditing(null)
                  load()
                } catch (e) {
                  toast.error((e as Error).message)
                }
              }}
            >
              保存
            </Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>
      </Card>
    </>
  )
}

// The two ways into this panel, on their own page: the GitHub identity it trusts
// and the password that works when GitHub does not.
type Session = { id: string; current: boolean; created_at: number; expires_at: number; ip: string; user_agent: string }

// UA 解析只认常见浏览器/系统（安全页「登录会话」卡展示用），认不出就显示「未知设备」。
function deviceName(ua: string): string {
  const os = /Windows/.test(ua)
    ? "Windows"
    : /Mac OS X|Macintosh/.test(ua)
      ? "macOS"
      : /Android/.test(ua)
        ? "Android"
        : /iPhone|iPad|iOS/.test(ua)
          ? "iOS"
          : /Linux/.test(ua)
            ? "Linux"
            : ""
  const browser = /Edg(e|A|iOS)?\//.test(ua)
    ? "Edge"
    : /OPR\//.test(ua)
      ? "Opera"
      : /Firefox\//.test(ua)
        ? "Firefox"
        : /Chrome\//.test(ua)
          ? "Chrome"
          : /Safari\//.test(ua)
            ? "Safari"
            : ""
  return [browser, os].filter(Boolean).join(" · ") || "未知设备"
}

const fmtTime = (ts: number) => new Date(ts * 1000).toLocaleString("zh-CN", { year: "numeric", month: "long", day: "numeric", hour: "2-digit", minute: "2-digit" })

function useSessions() {
  const [rows, setRows] = useState<Session[] | null>(null)
  // A failed load leaves the list empty rather than absent: the security page
  // waits for it, and the password card must stay reachable.
  const load = useCallback(
    () =>
      api<Session[]>("/sessions")
        .then(setRows)
        .catch((e: Error) => {
          toast.error(e.message)
          setRows((rows) => rows ?? [])
        }),
    [],
  )
  useEffect(() => { load() }, [load])
  return { rows, load }
}

function Sessions({ rows, reload }: { rows: Session[]; reload: () => void }) {
  const [busy, setBusy] = useState(false)
  const [confirmAll, setConfirmAll] = useState(false)

  // 下线一条或退出所有其它设备：id 省略 = 全部（当前会话服务端保留）。
  const drop = async (id?: string) => {
    setBusy(true)
    try {
      await api(id ? `/sessions/${id}` : "/sessions", { method: "DELETE" })
      toast.success(id ? "已下线" : "已退出所有其它设备")
      setConfirmAll(false)
      reload()
    } catch (e) {
      toast.error((e as Error).message)
    } finally {
      setBusy(false)
    }
  }

  return (
    <Card className="gap-4 p-5">
      <div className="flex items-start justify-between gap-3">
        <div>
          <h3 className="text-sm font-semibold">登录会话</h3>
          <p className="mt-1 text-xs text-muted-foreground">这些设备目前已登录你的账号。</p>
        </div>
        {rows.some((s) => !s.current) && (
          <Button variant="outline" size="sm" disabled={busy} onClick={() => setConfirmAll(true)}>
            <LogOut /> 退出所有设备
          </Button>
        )}
      </div>
      <div className="flex flex-col">
        {rows.map((s) => (
          <div key={s.id} className="flex items-center justify-between gap-3 border-b py-2.5 last:border-b-0">
            <div className="flex min-w-0 items-center gap-3">
              <span className="flex size-9 shrink-0 items-center justify-center rounded-md bg-muted">
                <Monitor className="size-4 text-muted-foreground" />
              </span>
              <div className="min-w-0">
                <div className="flex items-center gap-1.5 text-sm font-medium">
                  {deviceName(s.user_agent)}
                  {s.current && <Badge variant="secondary">当前设备</Badge>}
                </div>
                <div className="truncate text-xs text-muted-foreground">
                  IP {s.ip || "未知"} · 登录时间 {fmtTime(s.created_at)} · 过期时间 {fmtTime(s.expires_at)}
                </div>
              </div>
            </div>
            {/* 当前会话没有下线按钮：右上角的退出登录做的就是这件事，而在这里下线
                只会让已经渲染好的面板以为自己还登着。 */}
            {!s.current && (
              <Button variant="ghost" size="sm" className="text-xs" disabled={busy} onClick={() => drop(s.id)}>
                下线
              </Button>
            )}
          </div>
        ))}
      </div>
      {confirmAll && (
        <ConfirmDialog
          onClose={() => setConfirmAll(false)}
          onConfirm={() => drop(undefined)}
          title="退出所有其它设备？"
          description="其它设备将立即被登出，需要重新登录；当前这台不受影响。"
          confirmLabel="退出所有设备"
        />
      )}
    </Card>
  )
}

function Security({ site }: { site: string }) {
  const { s, set, save } = useSettings()
  const sessions = useSessions()
  const [password, setPassword] = useState("")
  // Drawn once both have arrived, so the list does not land late above the
  // cards and push them down.
  if (!s || !sessions.rows)
    return (
      <div className="space-y-4">
        <Card className="gap-3 p-5">
          <Skeleton className="h-5 w-40" />
          <Skeleton className="h-40 w-full" />
        </Card>
      </div>
    )
  const callback = `${site}/api/auth/github/callback`

  return (
    <>
    <div className="space-y-4">
      <Sessions rows={sessions.rows} reload={sessions.load} />

      <Card className="gap-4 p-5">
        <div>
          <h3 className="text-sm font-semibold">GitHub 登录</h3>
          <p className="mt-1 text-xs text-muted-foreground">
            OAuth App 回调地址 <code className="rounded bg-muted px-1 break-all">{callback}</code>
          </p>
        </div>
        <div className="grid gap-4 sm:grid-cols-2">
          <Field label="Client ID">
            <Input value={String(s.github_client_id ?? "")} onChange={(e) => set("github_client_id", e.target.value)} />
          </Field>
          <Field label="Client Secret" hint={s.github_secret_set ? "已设置，留空不变" : "未设置"}>
            <Input
              type="password"
              autoComplete="off"
              placeholder={s.github_secret_set ? "••••••••" : ""}
              value={String(s.github_client_secret ?? "")}
              onChange={(e) => set("github_client_secret", e.target.value)}
            />
          </Field>
        </div>
        {String(s.github_client_id ?? "") !== "" && String(s.github_allowed_users ?? "").trim() === "" && (
          <p className="rounded-md bg-destructive/10 px-3 py-2 text-sm text-destructive">
            白名单为空，GitHub 登录拒绝所有人。填入用户名并保存后生效。
          </p>
        )}
        <Field label="允许登录的 GitHub 用户名" hint="逗号分隔。留空 = 拒绝所有人，不是放行所有人">
          <Input value={String(s.github_allowed_users ?? "")} onChange={(e) => set("github_allowed_users", e.target.value)} placeholder="GitHub 用户名" />
        </Field>
        <div>
          <Button
            size="sm"
            onClick={() => {
              const patch: Record<string, string> = {
                github_client_id: String(s.github_client_id ?? ""),
                github_allowed_users: String(s.github_allowed_users ?? ""),
              }
              if (typeof s.github_client_secret === "string" && s.github_client_secret) {
                patch.github_client_secret = s.github_client_secret
              }
              save(patch)
            }}
          >
            保存 GitHub 设置
          </Button>
        </div>
      </Card>

      <Card className="gap-4 p-5">
        <div>
          <h3 className="text-sm font-semibold">应急密码</h3>
          <p className="mt-1 text-xs text-muted-foreground">
            GitHub 不可用时的备用入口。修改后其它设备登录立即失效，当前设备不受影响。
          </p>
        </div>
        <Field label="新密码" hint="至少 12 位">
          <Input type="password" value={password} onChange={(e) => setPassword(e.target.value)} autoComplete="new-password" />
        </Field>
        <div>
          <Button
            size="sm"
            disabled={password.length < 12}
            // Every other session ends with the change, so the list is read again.
            onClick={() => save({ admin_password: password }, "密码已修改").then((ok) => { if (ok) { setPassword(""); sessions.load() } })}
          >
            修改密码
          </Button>
        </div>
      </Card>
    </div>
    </>
  )
}

type DbInfo = {
  path: string
  size: number
  wal: number
  free: number
  /** Timestamp of the earliest history row, null on a database with none. */
  oldest: number | null
  retention: number
  rows: Record<string, number>
}

// The only two tables whose row count indicates anything about size. Every other
// holds one row per node or per key.
const DB_ROWS: [string, string][] = [
  ["metric", "历史明细"],
  ["ping_record", "延迟记录"],
]

function Data() {
  const [info, setInfo] = useState<DbInfo | null>(null)
  const [busy, setBusy] = useState("")
  const [confirm, setConfirm] = useState<"vacuum" | null>(null)
  const [pending, setPending] = useState<File | null>(null)
  const [sent, setSent] = useState(0)
  // Closing the dialog must stop the upload rather than merely hide it: restore
  // is the one irreversible action here, and it takes minutes on a large
  // backup.
  const abort = useRef<AbortController | null>(null)
  const picker = useRef<HTMLInputElement>(null)

  const load = () => api<DbInfo>("/db").then(setInfo).catch((e: Error) => toast.error(e.message))
  useEffect(() => { load() }, [])

  async function vacuum() {
    setBusy("vacuum")
    try {
      const { pruned, freed } = await api<{ pruned: number; freed: number }>("/db/vacuum", { method: "POST" })
      toast.success(`已清理 ${pruned} 行，回收 ${bytes(freed)}`)
      load()
    } catch (e) {
      toast.error((e as Error).message)
    } finally {
      setBusy("")
      setConfirm(null)
    }
  }

  async function restore(file: File) {
    setBusy("restore")
    setSent(0)
    abort.current = new AbortController()
    try {
      await upload("/db/restore", file, setSent, abort.current.signal)
      toast.success("已恢复，正在重新加载")
      // Every node, setting and session on the page came from the database just
      // replaced.
      setTimeout(() => location.reload(), 800)
    } catch (e) {
      // Aborting partway is not a failure: the hub replaces nothing until the
      // last chunk, so the original database remains.
      const aborted = (e as Error).name === "AbortError"
      if (aborted) toast.info("已取消，数据库没有改动")
      else toast.error((e as Error).message)
      setBusy("")
    }
    setPending(null)
  }

  if (!info) return null
  const stat = (label: string, value: string) => (
    <div key={label}>
      <div className="text-xs text-muted-foreground">{label}</div>
      <div className="tnum mt-0.5 text-sm">{value}</div>
    </div>
  )

  return (
    <>
    <div className="space-y-4">
      <Card className="gap-4 p-5">
        <h3 className="text-sm font-semibold">数据库</h3>
        <div className="grid grid-cols-2 gap-4 sm:grid-cols-4">
          {stat("文件大小", bytes(info.size))}
          {stat("预写日志", bytes(info.wal))}
          {stat("可回收空间", bytes(info.free))}
          {stat("保留天数", `${info.retention} 天`)}
          {/* 和保留天数并排：跨度小于保留期是还没攒够，大于保留期就是每小时
              那次 prune 没在跑。 */}
          {stat("历史跨度", info.oldest ? `${Math.floor((Date.now() / 1000 - info.oldest) / 86400)} 天` : "—")}
          {DB_ROWS.map(([key, label]) => stat(label, (info.rows[key] ?? 0).toLocaleString()))}
        </div>
        <p className="truncate text-xs text-muted-foreground" title={info.path}>
          <code>{info.path}</code>
        </p>
      </Card>

      <Card className="gap-4 p-5">
        <div>
          <h3 className="text-sm font-semibold">回收空间</h3>
          <p className="mt-1 text-xs leading-relaxed text-muted-foreground">
            按保留天数清掉过期明细，再重建数据库文件把空出来的页还给磁盘（SQLite 的 VACUUM）。重建期间需要与数据库等量的空闲磁盘，过程中面板和上报会短暂变慢。
          </p>
        </div>
        <div>
          <Button size="sm" variant="secondary" disabled={!!busy} onClick={() => setConfirm("vacuum")}>
            {busy === "vacuum" ? "回收中…" : "立即回收"}
          </Button>
        </div>
      </Card>

      <Card className="gap-4 p-5">
        <div>
          <h3 className="text-sm font-semibold">备份</h3>
          <p className="mt-1 text-xs leading-relaxed text-muted-foreground">
            导出的是整个数据库，含主机凭证与登录密码哈希，请当作密钥保管。恢复会用备份文件整体覆盖当前数据，当前主机、设置、历史全部作废，所有设备需要重新登录。
            <br />
            请用这里导出的文件恢复：直接复制 <code>monitor.db</code> 会丢掉预写日志里还没落盘的那部分。
          </p>
        </div>
        <div className="flex flex-wrap gap-2">
          {/* The browser's own download: the file is streamed straight from
              the response, never held in the page. */}
          <Button size="sm" asChild>
            <a href="/api/db/backup" download>
              <Download /> 导出备份
            </a>
          </Button>
          <Button size="sm" variant="secondary" disabled={!!busy} onClick={() => picker.current?.click()}>
            <Upload /> 导入备份
          </Button>
          <input
            ref={picker}
            type="file"
            accept=".db,application/octet-stream"
            className="hidden"
            onChange={(e) => {
              setPending(e.target.files?.[0] ?? null)
              e.target.value = ""
            }}
          />
        </div>
      </Card>

      {confirm === "vacuum" && (
        <ConfirmDialog
          title="回收空间？"
          description="超出保留天数的历史明细会被删除，然后重建数据库文件。累计流量不受影响。"
          confirmLabel={busy === "vacuum" ? "回收中…" : "开始回收"}
          busy={!!busy}
          onClose={() => setConfirm(null)}
          onConfirm={vacuum}
        />
      )}
      {pending && (
        <ConfirmDialog
          title="用备份覆盖当前数据？"
          description={`将用 ${pending.name}（${bytes(pending.size)}）整体替换当前数据库。当前的主机、设置和历史全部丢失，且无法撤销。`}
          confirmLabel={busy === "restore" ? `已上传 ${bytes(sent)} / ${bytes(pending.size)}` : "确认恢复"}
          busy={!!busy}
          onClose={() => { abort.current?.abort(); setPending(null) }}
          onConfirm={() => restore(pending)}
        />
      )}
    </div>
    </>
  )
}

const releaseUrl = (repo: string, version: string) => `https://github.com/carsonmoon/${repo}/releases/tag/v${version}`

/** `v1.2.0 → v1.3.0` when something is published, the running version alone otherwise. */
function VersionPair({ current, latest }: { current: string; latest: string }) {
  if (!behind(current, latest)) {
    return <span className="text-xs text-muted-foreground">{latest ? `已是最新 v${current}` : `当前 v${current}`}</span>
  }
  return (
    <span className="text-xs text-muted-foreground">
      v{current} <span className="px-0.5">→</span>
      <span className="ml-0.5 font-medium text-foreground">v{latest}</span>
    </span>
  )
}

/** Outdated nodes grouped by the version they run, oldest first. */
function byVersion(nodes: Node[]): [string, Node[]][] {
  const groups = new Map<string, Node[]>()
  for (const n of nodes) groups.set(n.agent_version, [...(groups.get(n.agent_version) ?? []), n])
  return [...groups].sort(([a], [b]) => a.localeCompare(b, undefined, { numeric: true }))
}

/**
 * What is published for the hub and the agents. Its own route rather than a
 * banner on the node list; the dot in the navigation is what says there is
 * something here.
 *
 * The hub card names the release alone: how to take it depends on how the hub
 * was installed, script or container, which the hub cannot tell.
 */
function Update({ versions, reload, nodes, site, refusal }: {
  versions: Versions | null
  reload: () => void
  nodes: Node[]
  site: string
  refusal: string
}) {
  const [saving, setSaving] = useState(false)
  if (!versions) return null
  const outdated = outdatedAgents(nodes, versions.agent_latest)
  const offline = outdated.filter((n) => !n.online).length
  const upgrade = refusal ? "" : upgradeCommand(site)
  const unreachable = !versions.hub_latest && !versions.agent_latest

  // Applied on the spot: one switch, and the navigation changes with it.
  async function setNotice(on: boolean) {
    setSaving(true)
    try {
      await api("/settings", { method: "PUT", body: JSON.stringify({ update_notice: on ? "on" : "off" }) })
      reload()
    } catch (e) {
      toast.error((e as Error).message)
    } finally {
      setSaving(false)
    }
  }

  return (
    <>
    <div className="space-y-4">
      {unreachable && (
        <Card className="p-5">
          <p className="text-sm text-muted-foreground">
            查不到最新版本：这台 hub 连不上 api.github.com。GitHub 代理不作用于这一项。
          </p>
        </Card>
      )}

      <Card className="gap-4 p-5">
        <div className="flex flex-wrap items-center justify-between gap-2">
          <h3 className="text-sm font-semibold">面板</h3>
          <div className="flex items-center gap-3">
            <VersionPair current={versions.hub} latest={versions.hub_latest} />
            {behind(versions.hub, versions.hub_latest) && (
              <Button size="sm" variant="ghost" asChild>
                <a href={releaseUrl("monitor", versions.hub_latest)} target="_blank" rel="noreferrer">
                  发布说明
                </a>
              </Button>
            )}
          </div>
        </div>
      </Card>

      <Card className="gap-4 p-5">
        <div className="flex flex-wrap items-center justify-between gap-2">
          <h3 className="text-sm font-semibold">节点程序</h3>
          <span className="text-xs text-muted-foreground">
            {versions.agent_latest
              ? outdated.length
                ? <>最新 v{versions.agent_latest} · <span className="font-medium text-foreground">{outdated.length} 台待升级</span></>
                : `已是最新 v${versions.agent_latest}`
              : "查不到版本"}
          </span>
        </div>
        {/* Also where the lookup failed: the command does not depend on it, and a
            hub that fetches agents through the GitHub proxy cannot read tags. */}
        {(outdated.length > 0 || !versions.agent_latest) && (
          <>
            <p className="text-xs leading-relaxed text-muted-foreground">
              以 root 在每台机器上执行一次。不含凭证，沿用机器上已有的设置，不会新建主机。
            </p>
            {upgrade ? (
              <>
                <Command>{upgrade}</Command>
                <div className="flex flex-wrap gap-2">
                  <Button size="sm" variant="secondary" onClick={() => copy(upgrade)}>
                    <Copy className="size-4" /> 复制命令
                  </Button>
                  {versions.agent_latest && (
                    <Button size="sm" variant="ghost" asChild>
                      <a href={releaseUrl("agent", versions.agent_latest)} target="_blank" rel="noreferrer">
                        发布说明
                      </a>
                    </Button>
                  )}
                  <Button size="sm" variant="ghost" asChild>
                    <a href="https://monitor-document.pages.dev/install/batch" target="_blank" rel="noreferrer">
                      批量升级的做法
                    </a>
                  </Button>
                </div>
              </>
            ) : (
              <p className="text-xs text-muted-foreground">{refusal}</p>
            )}
            {/* Collapsed until asked for, grouped by version, and bounded in height
                once open, so any number of nodes stays one line on the page. */}
            {outdated.length > 0 && (
              <details className="group border-t pt-3">
                <summary className="flex cursor-pointer list-none items-center justify-between gap-3 rounded-md text-xs text-muted-foreground outline-none focus-visible:ring-[3px] focus-visible:ring-ring/50 [&::-webkit-details-marker]:hidden">
                  <span className="flex items-center gap-1.5">
                    <ChevronRight className="size-4 transition-transform group-open:rotate-90" />
                    待升级的主机
                  </span>
                  {offline > 0 && <span>其中 {offline} 台离线</span>}
                </summary>
                <div className="mt-3 max-h-60 space-y-3 overflow-auto">
                  {byVersion(outdated).map(([version, group]) => (
                    <div key={version} className="space-y-1.5">
                      <div className="text-xs text-muted-foreground">v{version} · {group.length} 台</div>
                      <div className="flex flex-wrap gap-1.5">
                        {group.map((n) => (
                          <Badge
                            key={n.id}
                            variant="secondary"
                            className={`font-normal ${n.online ? "" : "opacity-50"}`}
                            title={n.online ? undefined : "离线"}
                          >
                            {n.name}
                          </Badge>
                        ))}
                      </div>
                    </div>
                  ))}
                </div>
              </details>
            )}
          </>
        )}
      </Card>

      <Card className="p-5">
        <OptionRow
          title="更新提醒"
          hint="有新版本时在导航的「更新」旁显示小圆点。关闭只是不再显示圆点，这一页照常检查"
          toggle
        >
          <Switch checked={versions.notice} disabled={saving} onCheckedChange={setNotice} />
        </OptionRow>
      </Card>
    </div>
    </>
  )
}

// Each area is its own route rather than a tab, so a page can be linked to and a
// reload returns to the same section.
const ADMIN_SECTIONS = [
  { path: "/admin/overview", label: "概览", icon: LayoutDashboard },
  { path: "/admin/nodes", label: "主机", icon: Server },
  { path: "/admin/proxy", label: "代理", icon: Globe },
  { path: "/admin/tunnel", label: "转发", icon: Waypoints },
  { path: "/admin/users", label: "用户", icon: UsersIcon },
  { path: "/admin/subscribe", label: "订阅", icon: Rss },
  { path: "/admin/logs", label: "日志", icon: ScrollText },
  { path: "/admin/ping", label: "监控", icon: Radio },
  { path: "/admin/notify", label: "通知", icon: Bell },
  { path: "/admin/data", label: "维护", icon: Database },
  { path: "/admin/themes", label: "主题", icon: Palette },
  { path: "/admin/security", label: "安全", icon: Shield },
  { path: "/admin/settings", label: "设置", icon: Settings },
  { path: "/admin/update", label: "更新", icon: ArrowUpCircle },
] as const

export function Admin({
  path,
  go,
  nodes,
  refresh,
  site,
  refusal,
  reloadMe,
}: {
  path: string
  go: (to: string) => void
  nodes: Node[]
  refresh: () => void
  site: string
  refusal: string
  reloadMe: () => void
}) {
  const { versions, reload } = useVersions()
  // One dot for both; the page separates them. Absent when switched off on that
  // page, or when the lookup failed and the page has nothing to say.
  const updates =
    !!versions?.notice
    && (behind(versions.hub, versions.hub_latest) || outdatedAgents(nodes, versions.agent_latest).length > 0)
  return (
    <div className="flex flex-col gap-6 md:flex-row">
      <nav className="flex gap-1 overflow-x-auto md:w-44 md:shrink-0 md:flex-col md:overflow-visible">
        {ADMIN_SECTIONS.map(({ path: to, label, icon: Icon }) => {
          const active = path === to
          return (
            <button
              key={to}
              onClick={() => go(to)}
              aria-current={active ? "page" : undefined}
              className={`flex shrink-0 items-center gap-2 rounded-md px-3 py-2 text-sm transition-colors ${
                active ? "bg-primary text-primary-foreground font-medium" : "text-muted-foreground hover:bg-muted"
              }`}
            >
              <Icon className="size-4" />
              {label}
              {to === "/admin/update" && updates && (
                <span className="ml-1 size-1.5 shrink-0 rounded-full bg-foreground md:ml-auto" title="有新版本" />
              )}
            </button>
          )
        })}
      </nav>

      <div className="min-w-0 flex-1">
        {path === "/admin/overview" ? (
          <Overview go={go} />
        ) : path === "/admin/proxy" ? (
          <Proxy />
        ) : path === "/admin/tunnel" ? (
          <Tunnel />
        ) : path === "/admin/users" ? (
          <Users />
        ) : path === "/admin/subscribe" ? (
          <Subscribe />
        ) : path === "/admin/logs" ? (
          <Logs />
        ) : path === "/admin/ping" ? (
          <Ping nodes={nodes} />
        ) : path === "/admin/notify" ? (
          <Notify nodes={nodes} refresh={refresh} />
        ) : path === "/admin/data" ? (
          <Data />
        ) : path === "/admin/themes" ? (
          <Themes />
        ) : path === "/admin/security" ? (
          <Security site={site} />
        ) : path === "/admin/settings" ? (
          <SettingsTab onSaved={reloadMe} />
        ) : path === "/admin/update" ? (
          <Update versions={versions} reload={reload} nodes={nodes} site={site} refusal={refusal} />
        ) : (
          <Nodes nodes={nodes} refresh={refresh} site={site} refusal={refusal} />
        )}
      </div>
    </div>
  )
}

/** 续费日历：按监控节点到期日汇总的月视图（周一为第一列）。点日期列出当天
 * 到期的机器，「续期」从当前到期日顺延一个付款周期（二次点击确认，3 秒）。 */

