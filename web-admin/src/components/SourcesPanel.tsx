import { useEffect, useState } from "react"
import { toast } from "sonner"
import { Trash2 } from "lucide-react"

import { Badge } from "@/components/ui/badge"
import { Button } from "@/components/ui/button"
import { Dialog, DialogContent, DialogFooter, DialogHeader, DialogTitle } from "@/components/ui/dialog"
import { Input } from "@/components/ui/input"
import { Label } from "@/components/ui/label"
import { ConvTemplateDialog } from "@/components/SubDialogs"
import { api } from "@/lib/api"

type BuiltinCategory = { key: string; label: string; custom: boolean; overridden: boolean; site: [string, string, string][]; ips: [string, string, string][] }
type BuiltinPreset = { key: string; name: string; url: string; kind: string; overridden: boolean; deleted: boolean; imported: boolean }
type RuleSource = { id: number; kind: "template" | "categories"; name: string; url: string; last_sync: number; created_at: number; count: number }
type UploadedTemplate = { id: number; name: string }

// Two clicks within the window delete: no dialog, no accidental loss.
function useConfirmDelete() {
  const [armed, setArmed] = useState<string | null>(null)
  useEffect(() => {
    if (armed === null) return
    const timer = setTimeout(() => setArmed(null), 3000)
    return () => clearTimeout(timer)
  }, [armed])
  return { armed, arm: setArmed }
}

/** 合并后的预设行：内置（代码出厂，覆盖可恢复）/ URL 来源（惰性导入）/ 上传配置。 */
type PresetRow =
  | { src: "builtin"; arm: string; name: string; url: string; overridden: boolean; imported: boolean; presetKey: string }
  | { src: "url"; arm: string; name: string; url: string; sourceId: number }
  | { src: "upload"; arm: string; name: string; templateId: number }

/** 规则模式 · 来源管理 tab：内置类别/预设的查看与修改（存覆盖，可恢复默认），预设模板三源合一（内置 + URL + 上传），自定义类别来源的增删同步。 */
export function SourcesPanel({ onChanged }: { onChanged: () => Promise<void> }) {
  const [cats, setCats] = useState<BuiltinCategory[]>([])
  const [presets, setPresets] = useState<BuiltinPreset[]>([])
  const [uploaded, setUploaded] = useState<UploadedTemplate[]>([])
  const [sources, setSources] = useState<RuleSource[]>([])
  const [loading, setLoading] = useState(false)
  const [catEdit, setCatEdit] = useState<BuiltinCategory | null>(null)
  const [presetEdit, setPresetEdit] = useState<BuiltinPreset | null>(null)
  const [urlEdit, setUrlEdit] = useState<RuleSource | null>(null)
  const [tplEdit, setTplEdit] = useState<{ id: number; name: string } | null>(null)
  const [uploadOpen, setUploadOpen] = useState(false)
  const [urlAddOpen, setUrlAddOpen] = useState(false)
  const { armed, arm } = useConfirmDelete()

  const load = async () => {
    setLoading(true)
    try {
      const r = await api<{ builtin_categories: BuiltinCategory[]; builtin_presets: BuiltinPreset[]; uploaded: UploadedTemplate[]; sources: RuleSource[] }>("/conv/rule-sources")
      setCats(r.builtin_categories)
      setPresets(r.builtin_presets)
      setUploaded(r.uploaded ?? [])
      setSources(r.sources)
    } catch (e) {
      toast.error((e as Error).message)
    } finally {
      setLoading(false)
    }
  }
  useEffect(() => {
    load()
  }, [])

  const run = async (fn: () => Promise<void>) => {
    try {
      await fn()
      await load()
      await onChanged()
    } catch (e) {
      toast.error((e as Error).message)
    }
  }
  const time = (ts: number) => (ts > 0 ? new Date(ts * 1000).toLocaleString("zh-CN", { month: "2-digit", day: "2-digit", hour: "2-digit", minute: "2-digit" }) : "未同步")
  const templates = sources.filter((s) => s.kind === "template")
  const categorySources = sources.filter((s) => s.kind === "categories")

  // 三源合一：内置（原序）→ URL 来源（添加序）→ 上传配置（添加序）。
  // 名称命中预设/URL 来源的上传模板 = 导入副本，不重复成行（由预设行「已导入」徽标表达）。
  const alivePresets = presets.filter((p) => !p.deleted)
  const presetNames = new Set(alivePresets.map((p) => p.name))
  const urlNames = new Set(templates.map((s) => s.name))
  const rows: PresetRow[] = [
    ...alivePresets.map((p) => ({ src: "builtin" as const, arm: `p:${p.key}`, name: p.name, url: p.url, overridden: p.overridden, imported: p.imported, presetKey: p.key })),
    ...templates.map((s) => ({ src: "url" as const, arm: `u${s.id}`, name: s.name, url: s.url, sourceId: s.id })),
    ...uploaded.filter((t) => !presetNames.has(t.name) && !urlNames.has(t.name)).map((t) => ({ src: "upload" as const, arm: `t${t.id}`, name: t.name, templateId: t.id })),
  ]
  const SRC_LABEL: Record<PresetRow["src"], string> = { builtin: "内置", url: "URL", upload: "上传" }

  return (
    <div className="flex flex-col gap-3 text-sm">
      <p className="text-xs text-muted-foreground">
        内置类别/预设来自代码出厂定义，可在此修改（存为覆盖，随时恢复默认）。预设模板清单 = 内置预设 + URL 来源 + 上传的配置，全部进「使用模板」下拉；上传/URL 的删除不可恢复。
      </p>

      {/* ① 内置分流类别 */}
      <div className="flex flex-col gap-1.5">
        <div className="text-xs font-medium text-muted-foreground">内置分流类别（{cats.length}）</div>
        <div className="grid max-h-60 grid-cols-1 gap-1 overflow-y-auto md:grid-cols-2">
          {cats.map((c) => (
            <div key={c.key} className="flex items-center justify-between gap-2 rounded border px-2 py-1">
              <div className="min-w-0">
                <span className="truncate">{c.label}</span>
                {c.overridden && <Badge variant="outline" className="ml-1.5 text-muted-foreground">已修改</Badge>}
                <span className="ml-1.5 text-[11px] text-muted-foreground">{c.site.length + c.ips.length} 条规则集</span>
              </div>
              <div className="flex shrink-0 gap-1">
                <Button variant="ghost" size="sm" className="h-6 px-1.5 text-xs" onClick={() => setCatEdit(c)}>编辑</Button>
                {c.overridden && (
                  <Button variant="ghost" size="sm" className="h-6 px-1.5 text-xs" onClick={() => run(async () => { await api(`/conv/builtin/cat:${c.key}`, { method: "DELETE" }); toast.success(`「${c.label}」已恢复默认`) })}>
                    恢复默认
                  </Button>
                )}
              </div>
            </div>
          ))}
        </div>
      </div>

      {/* ② 预设模板（三源合一）：头部增加入口（上传 / URL），行内三类均可编辑 */}
      <div className="flex flex-col gap-1.5">
        <div className="flex items-center justify-between gap-2">
          <div className="text-xs font-medium text-muted-foreground">预设模板（{rows.length}）</div>
          <div className="flex shrink-0 gap-1">
            <Button variant="outline" size="sm" className="h-6 px-1.5 text-xs" onClick={() => setUploadOpen(true)}>上传配置</Button>
            <Button variant="ghost" size="sm" className="h-6 px-1.5 text-xs" onClick={() => setUrlAddOpen((v) => !v)}>{urlAddOpen ? "收起" : "添加 URL 预设"}</Button>
          </div>
        </div>
        {urlAddOpen && (
          <TemplateAdd
            onAdd={(name, url) => run(async () => {
              await api("/conv/rule-sources", { method: "POST", body: JSON.stringify({ kind: "template", name, url }) })
              setUrlAddOpen(false)
              toast.success("URL 预设已添加，使用模板下拉点「加载」时自动拉取")
            })}
          />
        )}
        <div className="grid max-h-60 grid-cols-1 gap-1 overflow-y-auto md:grid-cols-2">
          {rows.map((r) => (
            <div key={r.arm} className="flex items-center justify-between gap-2 rounded border px-2 py-1">
              <div className="min-w-0">
                <div className="flex min-w-0 items-center">
                  <span className="truncate" title={"url" in r ? r.url : undefined}>{r.name}</span>
                  <Badge variant="outline" className="ml-1.5 shrink-0 text-[11px] text-muted-foreground">{SRC_LABEL[r.src]}</Badge>
                  {r.src === "builtin" && r.overridden && <Badge variant="outline" className="ml-1 shrink-0 text-muted-foreground">已修改</Badge>}
                  {r.src === "builtin" && r.imported && <Badge variant="outline" className="ml-1 shrink-0 text-muted-foreground">已导入</Badge>}
                </div>
                {r.src === "url" && <div className="truncate text-[11px] text-muted-foreground" title={r.url}>{r.url}</div>}
              </div>
              <div className="flex shrink-0 gap-1">
                {r.src === "builtin" && <Button variant="ghost" size="sm" className="h-6 px-1.5 text-xs" onClick={() => { const p = alivePresets.find((x) => x.key === r.presetKey); if (p) setPresetEdit(p) }}>编辑</Button>}
                {r.src === "url" && <Button variant="ghost" size="sm" className="h-6 px-1.5 text-xs" onClick={() => { const s = templates.find((x) => x.id === r.sourceId); if (s) setUrlEdit(s) }}>编辑</Button>}
                {r.src === "upload" && <Button variant="ghost" size="sm" className="h-6 px-1.5 text-xs" onClick={() => setTplEdit({ id: r.templateId, name: r.name })}>编辑</Button>}
                {r.src === "builtin" && alivePresets.find((x) => x.key === r.presetKey)?.overridden && (
                  <Button variant="ghost" size="sm" className="h-6 px-1.5 text-xs" onClick={() => run(async () => { await api(`/conv/builtin/preset:${r.presetKey}`, { method: "DELETE" }); toast.success(`「${r.name}」已恢复默认`) })}>
                    恢复默认
                  </Button>
                )}
                <Button
                  variant={armed === r.arm ? "destructive" : "ghost"}
                  size="sm"
                  className="h-6 px-1.5 text-xs"
                  title={
                    r.src === "builtin"
                      ? (alivePresets.find((x) => x.key === r.presetKey)?.imported ? "删除预设并连带删除已导入的同名模板" : "从预设清单和使用模板下拉移除，可恢复")
                      : r.src === "url"
                        ? "删除来源，使用模板下拉同步移除"
                        : "删除此配置，使用模板下拉同步移除"
                  }
                  onClick={() =>
                    armed === r.arm
                      ? run(async () => {
                          const resp = await api<{ message: string }>(`/conv/preset-sources/${r.arm}`, { method: "DELETE" })
                          toast.success(resp.message || `「${r.name}」已删除`)
                        })
                      : arm(r.arm)
                  }
                >
                  <Trash2 className="size-3" /> {armed === r.arm ? "确认" : ""}
                </Button>
              </div>
            </div>
          ))}
        </div>
        {presets.some((p) => p.deleted) && (
          <div className="flex flex-col gap-1">
            <div className="text-xs text-muted-foreground">已删除（{presets.filter((p) => p.deleted).length}）· 点恢复回到预设清单与使用模板下拉</div>
            <div className="flex flex-wrap gap-1">
              {presets.filter((p) => p.deleted).map((p) => (
                <Button key={p.key} variant="outline" size="sm" className="h-6 px-1.5 text-xs" onClick={() => run(async () => { await api(`/conv/builtin/preset:${p.key}`, { method: "DELETE" }); toast.success(`「${p.name}」已恢复`) })}>
                  ↩ {p.name}
                </Button>
              ))}
            </div>
          </div>
        )}
        <ConvTemplateDialog open={uploadOpen} onOpenChange={setUploadOpen} editing={null} onDone={() => run(async () => {})} />
        <ConvTemplateDialog
          open={!!tplEdit}
          onOpenChange={(v) => { if (!v) setTplEdit(null) }}
          editing={tplEdit ? { id: tplEdit.id, name: tplEdit.name, note: "", is_builtin: false, bytes: 0, created_at: 0 } : null}
          onDone={() => run(async () => {})}
        />
      </div>

      {/* ③ 自定义类别来源 */}
      <div className="flex flex-col gap-2 rounded-md border p-2.5">
        <div className="text-xs font-medium text-muted-foreground">自定义类别来源（妙妙屋 proxy-groups.json 格式，粘贴或 URL 拉取；删除来源会连带删掉它的类别）</div>
        {categorySources.map((s) => (
          <div key={s.id} className="flex items-center justify-between gap-2 rounded border px-2 py-1">
            <div className="min-w-0">
              <span className="truncate font-medium">{s.name}</span>
              <span className="ml-1.5 text-[11px] text-muted-foreground">{s.count} 类 · {time(s.last_sync)}</span>
            </div>
            <div className="flex shrink-0 gap-1">
              {s.url && <Button variant="outline" size="sm" className="h-6 px-1.5 text-xs" onClick={() => run(async () => { const r = await api<{ count: number }>(`/conv/rule-sources/${s.id}/sync`, { method: "POST" }); toast.success(`已同步 ${r.count} 类`) })}>同步</Button>}
              <Button
                variant={armed === `s${s.id}` ? "destructive" : "ghost"}
                size="sm"
                className="h-6 px-1.5 text-xs"
                title="删除来源，连带删掉它提供的类别（订阅里的残留引用渲染时跳过）"
                onClick={() =>
                  armed === `s${s.id}`
                    ? run(async () => { await api(`/conv/rule-sources/${s.id}`, { method: "DELETE" }); toast.success(`来源「${s.name}」已删除`) })
                    : arm(`s${s.id}`)
                }
              >
                <Trash2 className="size-3" /> {armed === `s${s.id}` ? "确认" : ""}
              </Button>
            </div>
          </div>
        ))}
        <CategoryAdd onAdd={(name, url, content) => run(async () => { await api("/conv/rule-sources", { method: "POST", body: JSON.stringify({ kind: "categories", name, url, content }) }); toast.success("类别来源已添加") })} />
      </div>

      {catEdit && <CategoryEditDialog cat={catEdit} onClose={() => setCatEdit(null)} onSaved={() => run(async () => { setCatEdit(null); toast.success("已保存（存为覆盖，可恢复默认）") })} />}
      {presetEdit && <PresetEditDialog preset={presetEdit} onClose={() => setPresetEdit(null)} onSaved={() => run(async () => { setPresetEdit(null); toast.success("已保存（存为覆盖，可恢复默认）") })} />}
      {urlEdit && <SourceEditDialog source={urlEdit} onClose={() => setUrlEdit(null)} onSaved={() => run(async () => { setUrlEdit(null); toast.success("已保存，使用模板下拉同步更新") })} />}
      {loading && <div className="text-center text-xs text-muted-foreground">加载中…</div>}
    </div>
  )
}

function TemplateAdd({ onAdd }: { onAdd: (name: string, url: string) => Promise<void> }) {
  const [name, setName] = useState("")
  const [url, setUrl] = useState("")
  return (
    <div className="flex items-end gap-2">
      <div className="flex flex-col gap-1">
        <Label className="text-[11px] text-muted-foreground">名称</Label>
        <Input className="h-8 w-40" value={name} onChange={(e) => setName(e.target.value)} placeholder="例如 别人的预设" />
      </div>
      <div className="flex min-w-0 flex-1 flex-col gap-1">
        <Label className="text-[11px] text-muted-foreground">配置 URL（ini / Clash YAML）</Label>
        <Input className="h-8" value={url} onChange={(e) => setUrl(e.target.value)} placeholder="https://…/config.ini" />
      </div>
      <Button size="sm" className="h-8 shrink-0" disabled={!name.trim() || !url.trim()} onClick={async () => { await onAdd(name.trim(), url.trim()); setName(""); setUrl("") }}>
        添加
      </Button>
    </div>
  )
}

function CategoryAdd({ onAdd }: { onAdd: (name: string, url: string, content: string) => Promise<void> }) {
  const [name, setName] = useState("")
  const [url, setUrl] = useState("")
  const [content, setContent] = useState("")
  const canAdd = name.trim() && (url.trim() || content.trim())
  return (
    <div className="flex flex-col gap-1.5">
      <div className="flex items-end gap-2">
        <div className="flex flex-col gap-1">
          <Label className="text-[11px] text-muted-foreground">来源名称</Label>
          <Input className="h-8 w-40" value={name} onChange={(e) => setName(e.target.value)} placeholder="例如 我自己的类别集" />
        </div>
        <div className="flex min-w-0 flex-1 flex-col gap-1">
          <Label className="text-[11px] text-muted-foreground">JSON URL（可选，与粘贴二选一）</Label>
          <Input className="h-8" value={url} onChange={(e) => setUrl(e.target.value)} placeholder="https://…/proxy-groups.json" />
        </div>
      </div>
      <textarea
        className="h-24 w-full rounded-md border bg-transparent p-2 font-mono text-xs"
        value={content}
        onChange={(e) => setContent(e.target.value)}
        placeholder='[{"name":"mycat","group_label":"🧪 我的类别","site_rules":[{"key":"mycat","url":"https://…/mycat.mrs"}]}]'
      />
      <Button size="sm" className="self-end" disabled={!canAdd} onClick={async () => { await onAdd(name.trim(), url.trim(), content); setName(""); setUrl(""); setContent("") }}>
        添加类别来源
      </Button>
    </div>
  )
}

function CategoryEditDialog({ cat, onClose, onSaved }: { cat: BuiltinCategory; onClose: () => void; onSaved: () => Promise<void> }) {
  const [text, setText] = useState(() => JSON.stringify({ label: cat.label, site: cat.site, ips: cat.ips }, null, 2))
  const [busy, setBusy] = useState(false)
  const save = async () => {
    let value: unknown
    try {
      value = JSON.parse(text)
    } catch {
      toast.error("JSON 解析失败")
      return
    }
    setBusy(true)
    try {
      await api(`/conv/builtin/cat:${cat.key}`, { method: "PUT", body: JSON.stringify(value) })
      await onSaved()
    } catch (e) {
      toast.error((e as Error).message)
    } finally {
      setBusy(false)
    }
  }
  return (
    <Dialog open onOpenChange={(v) => !v && onClose()}>
      <DialogContent className="max-w-xl">
        <DialogHeader>
          <DialogTitle>编辑内置类别 · {cat.key}</DialogTitle>
        </DialogHeader>
        <div className="flex flex-col gap-2">
          <p className="text-xs text-muted-foreground">
            修改存为覆盖，可随时「恢复默认」。site = geosite 域名规则集，ips = geoip 网段规则集（生成时自动带 no-resolve）。
          </p>
          <textarea className="h-64 w-full rounded-md border bg-transparent p-2 font-mono text-xs" value={text} onChange={(e) => setText(e.target.value)} />
        </div>
        <DialogFooter>
          <Button disabled={busy} onClick={save}>保存覆盖</Button>
        </DialogFooter>
      </DialogContent>
    </Dialog>
  )
}

function PresetEditDialog({ preset, onClose, onSaved }: { preset: BuiltinPreset; onClose: () => void; onSaved: () => Promise<void> }) {  const [name, setName] = useState(preset.name)
  const [url, setUrl] = useState(preset.url)
  const [kind, setKind] = useState(preset.kind)
  const [busy, setBusy] = useState(false)
  const save = async () => {
    setBusy(true)
    try {
      await api(`/conv/builtin/preset:${preset.key}`, { method: "PUT", body: JSON.stringify({ name: name.trim(), url: url.trim(), kind }) })
      await onSaved()
    } catch (e) {
      toast.error((e as Error).message)
    } finally {
      setBusy(false)
    }
  }
  return (
    <Dialog open onOpenChange={(v) => !v && onClose()}>
      <DialogContent className="max-w-md">
        <DialogHeader>
          <DialogTitle>编辑内置预设 · {preset.key}</DialogTitle>
        </DialogHeader>
        <div className="flex flex-col gap-2">
          <div className="flex flex-col gap-1">
            <Label>显示名称</Label>
            <Input value={name} onChange={(e) => setName(e.target.value)} />
          </div>
          <div className="flex flex-col gap-1">
            <Label>配置 URL</Label>
            <Input value={url} onChange={(e) => setUrl(e.target.value)} />
          </div>
          <div className="flex flex-col gap-1">
            <Label>类型（acl4ssr 的 ini 相对路径会补其仓库基址）</Label>
            <Input value={kind} onChange={(e) => setKind(e.target.value)} placeholder="acl4ssr / 留空自动识别" />
          </div>
        </div>
        <DialogFooter>
          <Button disabled={busy || !name.trim() || !url.trim()} onClick={save}>保存覆盖</Button>
        </DialogFooter>
      </DialogContent>
    </Dialog>
  )
}

function SourceEditDialog({ source, onClose, onSaved }: { source: RuleSource; onClose: () => void; onSaved: () => Promise<void> }) {
  const [name, setName] = useState(source.name)
  const [url, setUrl] = useState(source.url)
  const [busy, setBusy] = useState(false)
  const save = async () => {
    setBusy(true)
    try {
      await api(`/conv/rule-sources/${source.id}`, { method: "PUT", body: JSON.stringify({ name: name.trim(), url: url.trim() }) })
      await onSaved()
    } catch (e) {
      toast.error((e as Error).message)
    } finally {
      setBusy(false)
    }
  }
  return (
    <Dialog open onOpenChange={(v) => !v && onClose()}>
      <DialogContent className="max-w-md">
        <DialogHeader>
          <DialogTitle>编辑 URL 预设</DialogTitle>
        </DialogHeader>
        <div className="flex flex-col gap-2">
          <p className="text-xs text-muted-foreground">改名与改 URL 即时生效；使用模板下拉里点「加载」时按新 URL 拉取。</p>
          <div className="flex flex-col gap-1">
            <Label>显示名称</Label>
            <Input value={name} onChange={(e) => setName(e.target.value)} />
          </div>
          <div className="flex flex-col gap-1">
            <Label>配置 URL（ini / Clash YAML）</Label>
            <Input value={url} onChange={(e) => setUrl(e.target.value)} />
          </div>
        </div>
        <DialogFooter>
          <Button disabled={busy || !name.trim() || !url.trim()} onClick={save}>保存</Button>
        </DialogFooter>
      </DialogContent>
    </Dialog>
  )
}
