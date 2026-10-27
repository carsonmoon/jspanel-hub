import { useCallback, useEffect, useState } from "react"
import { ChevronDown, Copy, Download, Layers, Pencil, Plus, Trash2 } from "lucide-react"
import { toast } from "sonner"

import { ConvGroupEditorDialog, ConvSnippetDialog, StaticProfileDialog, TplSaveDialog, downloadText } from "@/components/SubDialogs"
import { Label } from "@/components/ui/label"
import { Button } from "@/components/ui/button"
import { Badge } from "@/components/ui/badge"
import { Card } from "@/components/ui/card"
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select"
import { Switch } from "@/components/ui/switch"
import { api, type ConvProfile, type ConvSnippet, type ConvTemplate } from "@/lib/api"

import { SourcesPanel } from "@/components/SourcesPanel"
import { copyText } from "@/lib/utils"

// 名称按字母 A→Z 排序：英文取首字母，中文按拼音首字母与英文字母混排
// （zh collation 本身把汉字排在英文之后，直接 localeCompare 会让 Aethersailor 沉底）。
const zhColl = new Intl.Collator("zh-Hans-CN")
const PINYIN_INITIALS: [string, string][] = [
  ["a", "阿"], ["b", "八"], ["c", "擦"], ["d", "搭"], ["e", "蛾"], ["f", "发"], ["g", "噶"],
  ["h", "哈"], ["j", "击"], ["k", "喀"], ["l", "垃"], ["m", "妈"], ["n", "拿"], ["o", "哦"],
  ["p", "啪"], ["q", "七"], ["r", "然"], ["s", "撒"], ["t", "塌"], ["w", "挖"], ["x", "希"],
  ["y", "压"], ["z", "匝"],
]
function letterKey(s: string): string {
  const c = [...s.trim()][0] ?? ""
  if (/[a-z]/i.test(c)) return c.toLowerCase()
  for (let i = PINYIN_INITIALS.length - 1; i >= 0; i--) {
    if (zhColl.compare(PINYIN_INITIALS[i][1], c) <= 0) return PINYIN_INITIALS[i][0]
  }
  return "~" // 非字母非汉字（数字/符号）排在 z 之后
}

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

// 预览对应的生成上下文：模板模式存解析后的模板名（preset: 前缀已换成真名），
// 自定义模式存规则模式名 + 勾选的类别；保存订阅时按它组装请求体。
type PreviewCtx = { kind: "template"; templateName: string } | { kind: "custom"; ruleName: string; categories: string[] }

type Data = {
  templates: ConvTemplate[]
  snippets: ConvSnippet[]
  profiles: ConvProfile[]
}

const EMPTY: Data = { templates: [], snippets: [], profiles: [] }

/** 订阅入口（sub_hosts 多入口同款）。 */

/** 有效期时间戳 → 本地日期 YYYY-MM-DD。 */


export default function Subscribe() {
  const [data, setData] = useState<Data>(EMPTY)
  const [snippetEditing, setSnippetEditing] = useState<ConvSnippet | null>(null)
  const [snippetOpen, setSnippetOpen] = useState(false)
  const [editingProfile, setEditingProfile] = useState<ConvProfile | null>(null)
  // 复制菜单切中的格式：null = Auto（主地址）；选中后二维码随之重绘
  const [visualEditing, setVisualEditing] = useState<ConvProfile | null>(null)
  const [visualOpen, setVisualOpen] = useState(false)
  const [modeTab, setModeTab] = useState<"custom" | "template" | "sources">("custom")
  const [selectedTemplate, setSelectedTemplate] = useState("")
  const [tplPreview, setTplPreview] = useState<string | null>(null)
  const [tplGenerated, setTplGenerated] = useState("")
  const [tplEditing, setTplEditing] = useState(false)
  const [staticEditing, setStaticEditing] = useState<ConvProfile | null>(null)
  const [previewCtx, setPreviewCtx] = useState<PreviewCtx | null>(null)
  const [saveOpen, setSaveOpen] = useState(false)
  const [tplDropdownOpen, setTplDropdownOpen] = useState(false)
  const [ruleMode, setRuleMode] = useState<{
    selected: { name: string; categories: string[] }
    presets: { name: string; desc: string; categories: { label: string; key: string }[] }[]
    categories: { label: string; key: string; custom: boolean }[]
  }>({ selected: { name: "", categories: [] }, presets: [], categories: [] })
  const [showCategories, setShowCategories] = useState(true)
  // 片段库列表默认折叠（内置片段默认停用，按需展开逐个开）
  const [snippetsOpen, setSnippetsOpen] = useState(false)
  const [plansOpen, setPlansOpen] = useState(true)
  const [tplPresets, setTplPresets] = useState<{ key: string; name: string; kind: string; imported: boolean }[]>([])
  const { armed, arm } = useConfirmDelete()

  const load = useCallback(async () => {
    const [t, sn, p, ruleModeData, tplPresetsData] = await Promise.all([
      api<{ templates: ConvTemplate[] }>("/conv/templates").catch(() => ({ templates: [] })),
      api<{ snippets: ConvSnippet[] }>("/conv/snippets").catch(() => ({ snippets: [] })),
      api<{ profiles: ConvProfile[] }>("/conv/profiles").catch(() => ({ profiles: [] })),
      api<{ selected: { name: string; categories: string[] }; presets: { name: string; desc: string; categories: { label: string; key: string }[] }[]; categories: { label: string; key: string; custom: boolean }[] }>("/conv/rule-mode").catch(() => ({ selected: { name: "", categories: [] }, presets: [], categories: [] })),
      api<{ presets: { key: string; name: string; kind: string; imported: boolean }[] }>("/conv/template-presets").catch(() => ({ presets: [] })),
    ])
    setData({ templates: t.templates, snippets: sn.snippets, profiles: p.profiles })
    setRuleMode(ruleModeData)
    setTplPresets(tplPresetsData.presets)
  }, [])
  useEffect(() => {
    load()
  }, [load])

  // 使用模板 tab 的下拉选项：已导入模板（内置的 全局代理/极简/均衡/完整 不进此下拉）+ 未导入预设，整体按名称字母序。
  // src 徽标：模板行按名称命中预设名单标「预设」（=导入副本），否则「上传」；未导入预设行标「预设」。
  const tplPresetOptions = (() => {
    const presetNames = new Set(tplPresets.map((p) => p.name))
    const importedNames = new Set(data.templates.map((t) => t.name))
    const options: { value: string; label: string; key: string | null; src: "preset" | "upload" }[] = data.templates
      .filter((t) => !t.is_builtin)
      .map((t) => ({ value: t.name, label: t.name, key: null, src: presetNames.has(t.name) ? ("preset" as const) : ("upload" as const) }))
    for (const p of tplPresets) {
      if (!importedNames.has(p.name)) {
        options.push({ value: `preset:${p.key}`, label: p.name, key: p.key, src: "preset" })
      }
    }
    return options.sort(
      (a, b) => letterKey(a.label).localeCompare(letterKey(b.label)) || zhColl.compare(a.label, b.label),
    )
  })()


  const toggleCategory = (key: string) => {
    setRuleMode((m) => {
      const categories = m.selected.categories.includes(key)
        ? m.selected.categories.filter((k) => k !== key)
        : [...m.selected.categories, key]
      return { ...m, selected: { ...m.selected, categories } }
    })
  }


  const removeSnippet = async (s: ConvSnippet) => {
    try {
      await api(`/conv/snippets/${s.id}`, { method: "DELETE" })
      toast.success("片段已删除")
      await load()
    } catch (e) {
      toast.error((e as Error).message)
    }
  }

  // 编辑订阅 = 把订阅现值预填回规则模式流程（模板/类别/节点勾选），重新加载预览后同名保存即更新
  const startEditProfile = (p: ConvProfile) => {
    setEditingProfile(p)
    if (p.selected_categories.length > 0) {
      setModeTab("custom")
      setRuleMode((m) => ({ ...m, selected: { name: p.template_name || m.selected.name, categories: p.selected_categories } }))
    } else {
      setModeTab("template")
      setSelectedTemplate(p.template_name)
    }
    setTplPreview(null); setTplGenerated(""); setPreviewCtx(null); setTplEditing(false)
    setTimeout(() => document.getElementById("rule-mode-card")?.scrollIntoView({ behavior: "smooth", block: "start" }), 60)
  }
  const selectRuleMode = async (name: string, categories?: string[]) => {
    try {
      const r = await api<{ selected: { name: string; categories: string[] } }>("/conv/rule-mode", {
        method: "POST",
        body: JSON.stringify(categories ? { name, categories } : { name }),
      })
      setRuleMode((m) => ({ ...m, selected: r.selected }))
      toast.success(`规则模式已切换：${name.replace(".yaml", "")}`)
    } catch (e) {
      toast.error((e as Error).message)
    }
  }
  const cancelEdit = async () => {
    setEditingProfile(null)
    setTplPreview(null); setPreviewCtx(null)
    await load()
  }


  const removeProfile = async (p: ConvProfile) => {
    try {
      await api(`/conv/profiles/${p.id}`, { method: "DELETE" })
      toast.success("订阅已删除")
      await load()
    } catch (e) {
      toast.error((e as Error).message)
    }
  }
  const loadTemplatePreview = async () => {
    let tplName = selectedTemplate
    try {
      // 未导入的预设：先拉取转换入库，模板名以导入返回为准
      if (tplName.startsWith("preset:")) {
        const key = tplName.slice("preset:".length)
        const r = await api<{ name: string }>(`/conv/template-presets/${key}/import`, { method: "POST" })
        tplName = r.name
      }
      const resp = await fetch("/api/conv/profiles/preview", {
        method: "POST",
        headers: { "content-type": "application/json" },
        credentials: "include",
        body: JSON.stringify({
          name: "预览",
          template_name: tplName,
          selected_tags: [],
          snippet_ids: [],
          expires_at: 0,
          enabled: true,
        }),
      })
      const text = await resp.text()
      if (!resp.ok) throw new Error(text || `HTTP ${resp.status}`)
      setTplPreview(text)
      setTplGenerated(text)
      setTplEditing(false)
      setPreviewCtx({ kind: "template", templateName: tplName })
    } catch (e) {
      toast.error((e as Error).message)
    }
  }
  // 自定义规则 tab：按当前规则模式的类别集动态生成预览（与使用模板同一保存通道）
  const loadCustomPreview = async () => {
    try {
      const resp = await fetch("/api/conv/profiles/preview", {
        method: "POST",
        headers: { "content-type": "application/json" },
        credentials: "include",
        body: JSON.stringify({
          name: "预览",
          template_name: ruleMode.selected.name,
          selected_tags: [],
          snippet_ids: [],
          expires_at: 0,
          enabled: true,
          selected_categories: ruleMode.selected.categories,
        }),
      })
      const text = await resp.text()
      if (!resp.ok) throw new Error(text || `HTTP ${resp.status}`)
      setTplPreview(text)
      setTplGenerated(text)
      setTplEditing(false)
      setPreviewCtx({ kind: "custom", ruleName: ruleMode.selected.name, categories: ruleMode.selected.categories })
    } catch (e) {
      toast.error((e as Error).message)
    }
  }



  return (
    <div className="flex flex-col gap-6">
      {/* ② 规则模式（页面级默认：自定义类别勾选 / 使用模板两种模式；生成与编辑共用此流程） */}
      <Card id="rule-mode-card" className="flex flex-col gap-3 p-5">
        <div>
          <div className="text-sm font-semibold">规则模式</div>
          <div className="text-sm text-muted-foreground">
            自定义规则：按类别动态生成配置；使用模板：套用完整配置模板自动解析代理组和规则。
          </div>
        </div>
        {editingProfile && (
          <div className="flex items-center justify-between gap-2 rounded-md border border-warn/40 bg-warn/10 px-3 py-2 text-sm">
            <span>正在编辑方案「{editingProfile.name}」——调整后点「加载」预览，「保存方案」同名即更新。</span>
            <Button variant="ghost" size="sm" className="shrink-0" onClick={cancelEdit}>取消编辑</Button>
          </div>
        )}
        <div className="grid gap-2 md:grid-cols-3">
          <button
            onClick={() => { setModeTab("custom"); setTplPreview(null); setPreviewCtx(null) }}
            className={`rounded-md border px-3 py-2 text-sm font-medium transition-colors ${modeTab === "custom" ? "border-foreground bg-secondary" : "text-muted-foreground hover:bg-muted"}`}
          >
            自定义规则
          </button>
          <button
            onClick={() => { setModeTab("template"); setTplPreview(null); setPreviewCtx(null) }}
            className={`rounded-md border px-3 py-2 text-sm font-medium transition-colors ${modeTab === "template" ? "border-foreground bg-secondary" : "text-muted-foreground hover:bg-muted"}`}
          >
            使用模板
          </button>
          <button
            onClick={() => setModeTab("sources")}
            className={`rounded-md border px-3 py-2 text-sm font-medium transition-colors ${modeTab === "sources" ? "border-foreground bg-secondary" : "text-muted-foreground hover:bg-muted"}`}
          >
            来源管理
          </button>
        </div>

        {modeTab === "custom" && (
          <>
            <div className="flex flex-col gap-1.5">
              <Label className="text-xs text-muted-foreground">规则选择（预设自动勾选常用类别，可手动调整）</Label>
              <Select
                value={ruleMode.selected.name}
                onValueChange={(name) => {
                  const preset = ruleMode.presets.find((x) => x.name === name)
                  const cats = preset ? preset.categories.map((c) => c.key) : []
                  selectRuleMode(name, cats)
                }}
              >
                <SelectTrigger><SelectValue placeholder="选择规则模式…" /></SelectTrigger>
                <SelectContent>
                  {ruleMode.presets.map((p) => (
                    <SelectItem key={p.name} value={p.name}>{p.name.replace(".yaml", "")}</SelectItem>
                  ))}
                </SelectContent>
              </Select>
              <div className="text-xs text-muted-foreground">已自动选择常用类别，可以手动调整。</div>
            </div>
            <div className="rounded-md border">
              <button className="flex w-full items-center justify-between px-3 py-2 text-sm" onClick={() => setShowCategories(!showCategories)}>
                <span>已选择 {ruleMode.selected.categories.length} 个类别</span>
                <ChevronDown className={`size-3.5 shrink-0 text-muted-foreground transition-transform ${showCategories ? "rotate-180" : ""}`} />
              </button>
              {showCategories && (
                <div className="grid grid-cols-2 gap-1.5 border-t p-3 md:grid-cols-3">
                  {ruleMode.categories.map((c) => {
                    const checked = ruleMode.selected.categories.includes(c.key)
                    return (
                      <label key={c.key} className="flex cursor-pointer items-center gap-2 rounded px-1.5 py-1 text-sm hover:bg-muted">
                        <input type="checkbox" checked={checked} onChange={() => toggleCategory(c.key)} />
                        <span className="truncate">{c.label}</span>
                        {c.custom && <Badge variant="outline" className="text-[11px] text-muted-foreground">自定义</Badge>}
                      </label>
                    )
                  })}
                  {ruleMode.categories.length === 0 && <span className="text-xs text-muted-foreground">加载中…</span>}
                </div>
              )}
            </div>
          </>
        )}

        {modeTab === "template" && (
          <div className="flex flex-col gap-3">
            <div className="flex flex-col gap-1.5">
              <Label className="text-xs text-muted-foreground">选择模板（使用 ACL4SSR/Aethersailor 规则模板生成配置，自动解析代理组和规则）</Label>
              {/* 长列表用自建面板：radix Select 在 40 条目下有滚动循环问题 */}
              <div className="relative">
                <Button
                  variant="outline"
                  className="w-full justify-between font-normal"
                  onClick={() => setTplDropdownOpen(!tplDropdownOpen)}
                >
                  <span className="truncate">{selectedTemplate || "选择模板…"}</span>
                </Button>
                {tplDropdownOpen && (
                  <div className="absolute z-20 mt-1 max-h-80 w-full overflow-y-auto rounded-md border bg-popover p-1 shadow-md">
                    {tplPresetOptions.map((o) => (
                      <button
                        key={o.value}
                        className={`flex w-full items-center gap-1.5 rounded px-3 py-2 text-left text-sm hover:bg-muted ${selectedTemplate === o.value ? "bg-secondary font-medium" : ""}`}
                        onClick={() => { setSelectedTemplate(o.value); setTplPreview(null); setTplDropdownOpen(false) }}
                      >
                        <span className="truncate">{o.label}</span>
                        <Badge variant="outline" className={`ml-auto shrink-0 text-[11px] font-normal ${o.src === "upload" ? "text-muted-foreground" : "text-primary"}`}>
                          {o.src === "upload" ? "上传" : "预设"}
                        </Badge>
                      </button>
                    ))}
                  </div>
                )}
              </div>
            </div>

          </div>
        )}

        {modeTab === "sources" && <SourcesPanel onChanged={load} />}

        {/* 自定义/使用模板共用：加载预览 → 保存订阅（节点来自上方节点管理的勾选）；来源管理 tab 不显示 */}
        {modeTab !== "sources" && (
          <Button
            className="w-full"
            disabled={modeTab === "template" && !selectedTemplate}
            onClick={() => (modeTab === "template" ? loadTemplatePreview() : loadCustomPreview())}
          >
            加载
          </Button>
        )}

            {tplPreview !== null && previewCtx !== null && (
          <div className="rounded-md border">
            <div className="flex items-center justify-between border-b px-3 py-2">
              <div>
                <div className="text-sm font-medium">生成的 Clash 配置</div>
                <div className="text-xs text-muted-foreground">
                  {tplPreview.split("\n").length} 行 · {new Blob([tplPreview]).size} 字节 · {tplEditing ? "编辑中" : "只读预览"}
                </div>
              </div>
              <div className="flex gap-1">
                <Button variant={tplEditing ? "default" : "outline"} size="sm" onClick={() => setTplEditing(!tplEditing)}>
                  <Pencil className="size-3.5" /> {tplEditing ? "退出编辑" : "编辑"}
                </Button>
                <Button variant="outline" size="sm" onClick={() => copyText(tplPreview, "配置已复制")}>
                  <Copy className="size-3.5" /> 复制
                </Button>
                <Button variant="outline" size="sm" onClick={() => downloadText("config.yaml", tplPreview)}>
                  <Download className="size-3.5" /> 下载
                </Button>
              </div>
            </div>
            {tplEditing ? (
              <textarea
                className="max-h-96 min-h-60 w-full resize-y overflow-auto bg-transparent p-3 font-mono text-xs outline-none"
                value={tplPreview}
                onChange={(e) => setTplPreview(e.target.value)}
                spellCheck={false}
              />
            ) : (
              <pre className="max-h-96 overflow-auto p-3 font-mono text-xs">{tplPreview}</pre>
            )}
            <div className="flex items-center justify-between gap-2 border-t px-3 py-2">
              <span className="text-xs text-muted-foreground">保存为内容方案（配方）；交付给设备统一在用户页按客户进行。</span>
              <Button size="sm" onClick={() => setSaveOpen(true)}>
                保存方案{tplPreview !== tplGenerated && "（已修改）"}
              </Button>
            </div>
          </div>
        )}
      </Card>

      {/* ③ 规则片段库（默认折叠：内置片段默认停用，按需展开逐个启用） */}
      <Card className="flex flex-col gap-3 p-5">
        <div className="flex items-center justify-between gap-4">
          <button className="flex min-w-0 items-center gap-2 text-left" onClick={() => setSnippetsOpen(!snippetsOpen)}>
            <ChevronDown className={`size-3.5 shrink-0 text-muted-foreground transition-transform ${snippetsOpen ? "rotate-180" : ""}`} />
            <span className="min-w-0">
              <span className="flex items-center gap-2">
                <span className="font-medium">规则片段库</span>
                <Badge variant="outline">
                  {data.snippets.filter((x) => x.enabled).length} 已启用 / {data.snippets.length} 总
                </Badge>
              </span>
              <span className="block text-sm text-muted-foreground">启用的片段全局生效：规则模式加载、生成与订阅输出都会自动合并（prepend 在最前 / append 在 MATCH 前）。内置模板默认停用：防 WebRTC 泄漏 / 一机一住宅 / 一 WiFi 一 IP / 阻止海外 QUIC / 连通性检测 / NTP / Telegram IP 段 / 下载直连 / 遥测拦截——展开后按需启用。</span>
            </span>
          </button>
          <Button size="sm" className="shrink-0" onClick={() => { setSnippetEditing(null); setSnippetOpen(true) }}>
            <Plus className="size-3.5" /> 新建片段
          </Button>
        </div>
        {snippetsOpen && (
          <div className="flex flex-col gap-1.5 border-t pt-3">
            {data.snippets.length === 0 ? (
              <div className="py-6 text-center text-sm text-muted-foreground">还没有片段。把网上抄到的规则整段粘进来即可。</div>
            ) : (
            <div className="flex flex-col gap-1.5">
              {data.snippets.map((s) => (
              <div key={s.id} className="flex items-center gap-2 rounded-md border px-2 py-1.5 text-sm">
                <span className="flex-1 truncate font-medium">{s.name}</span>
                <Badge variant="outline">{s.kind}</Badge>
                <Badge variant="secondary">{s.mode}</Badge>
                <Switch checked={s.enabled} onCheckedChange={async (v) => {
                  try {
                    await api(`/conv/snippets/${s.id}`, { method: "PUT", body: JSON.stringify({ name: s.name, kind: s.kind, mode: s.mode, content: s.content, enabled: v }) })
                    await load()
                  } catch (e) {
                    toast.error((e as Error).message)
                  }
                }} />
                <Button variant="ghost" size="sm" onClick={() => { setSnippetEditing(s); setSnippetOpen(true) }}>
                  <Pencil className="size-3.5" />
                </Button>
                <Button variant={armed === `sn${s.id}` ? "destructive" : "ghost"} size="sm" onClick={() => (armed === `sn${s.id}` ? removeSnippet(s) : arm(`sn${s.id}`))}>
                  <Trash2 className="size-3.5" /> {armed === `sn${s.id}` ? "确认" : ""}
                </Button>
                </div>
              ))}
            </div>
            )}
          </div>
        )}
      </Card>

      {/* ④ 内容方案：保存的模板/规则配方（交付统一在用户页按客户进行，方案本身无链接/二维码/启停/到期） */}
      <Card className="flex flex-col gap-3 p-5">
        <div className="flex items-center justify-between gap-4">
          <button className="flex min-w-0 items-center gap-2 text-left" onClick={() => setPlansOpen(!plansOpen)}>
            <ChevronDown className={`size-3.5 shrink-0 text-muted-foreground transition-transform ${plansOpen ? "rotate-180" : ""}`} />
            <span className="min-w-0">
              <span className="flex items-center gap-2">
                <span className="font-medium">内容方案</span>
                <Badge variant="outline">{data.profiles.length}</Badge>
              </span>
              <span className="block text-sm text-muted-foreground">
                保存时快照当前勾选的代理与规则；代理池之后怎么勾选都不影响已保存的方案。交付给设备统一在用户页按客户进行。
              </span>
            </span>
          </button>
        </div>
            <div className="flex flex-col gap-1.5 border-t pt-3">
              {plansOpen && (
                <div className="flex flex-col gap-1.5">
                  {data.profiles.length === 0 ? (
                    <div className="py-2 text-center text-xs text-muted-foreground">还没有方案：上方「加载」预览后点「保存方案」即可创建（保存的是当时勾选的代理与规则快照）。</div>
                  ) : (
                    data.profiles.map((p) => {
                      const overrideCount = Object.keys(p.group_overrides || {}).length
                      return (
                        <div key={p.id} className="flex items-center gap-2 rounded-md border px-3 py-2 text-sm">
                          <div className="flex min-w-0 flex-1 items-center gap-1.5 font-medium">
                            <span className="truncate">{p.name}</span>
                            {p.static_content && <Badge variant="outline" title="整份 YAML 原样下发，不随代理/勾选/客户变化；无法绑定客户">静态</Badge>}
                            {overrideCount > 0 && <Badge variant="secondary" title={`${overrideCount} 个组被自定义`}>自定义 {overrideCount} 组</Badge>}
                          </div>
                          <div className="flex shrink-0 items-center gap-0.5">
                            <Button variant="ghost" size="sm" title={p.static_content ? "编辑静态 YAML" : "在规则模式中编辑（预填后重新生成）"} onClick={() => (p.static_content ? setStaticEditing(p) : startEditProfile(p))}>
                              <Pencil className="size-3.5" /> 编辑
                            </Button>
                            <Button variant="ghost" size="sm" title="拖拽分组" onClick={() => { setVisualEditing(p); setVisualOpen(true) }}>
                              <Layers className="size-3.5" /> 分组
                            </Button>
                            <Button
                              variant={armed === `p${p.id}` ? "destructive" : "ghost"}
                              size="sm"
                              title={armed === `p${p.id}` ? "再点一次确认删除" : "删除方案"}
                              onClick={() => (armed === `p${p.id}` ? removeProfile(p) : arm(`p${p.id}`))}
                            >
                              <Trash2 className="size-3.5" /> {armed === `p${p.id}` ? "确认" : "删除"}
                            </Button>
                          </div>
                        </div>
                      )
                    })
                  )}
                </div>
              )}
            </div>
      </Card>


      <ConvSnippetDialog open={snippetOpen} onOpenChange={setSnippetOpen} editing={snippetEditing} onDone={load} />
      <ConvGroupEditorDialog open={visualOpen} onOpenChange={setVisualOpen} profile={visualEditing} nodes={[]} templates={data.templates} onDone={load} />
      <TplSaveDialog
        open={saveOpen}
        onOpenChange={setSaveOpen}
        defaultName={
          // 默认名回落到模板名/规则模式名
          previewCtx?.kind === "template"
            ? previewCtx.templateName.replace(/\.ya?ml$/, "")
            : previewCtx
              ? previewCtx.ruleName.replace(/\.ya?ml$/, "")
              : ""
        }
        existingNames={data.profiles.map((p) => p.name)}
        notice={tplPreview !== null && tplPreview !== tplGenerated ? "已修改：将保存为静态方案（整份 YAML 原样下发，不再自动更新）" : editingProfile ? `正在编辑方案「${editingProfile.name}」：同名保存即更新该方案。` : undefined}
        onSave={async (name) => {
          const ctx = previewCtx
          if (!ctx) return
          const edited = tplPreview !== null && tplPreview !== tplGenerated
          // 同名覆盖：沿用既有订阅的分组覆盖/片段/启停与令牌，只更新本流程管理的字段
          const existing = data.profiles.find((p) => p.name === name)
          const body = JSON.stringify({
            name,
            template_name: ctx.kind === "template" ? ctx.templateName : ctx.ruleName,
            selected_tags: existing?.selected_tags ?? [],
              snippet_ids: existing?.snippet_ids ?? [],
            group_overrides: existing?.group_overrides ?? {},
            selected_categories: ctx.kind === "custom" ? ctx.categories : [],
            ...(edited ? { static_content: tplPreview } : {}),
          })
          if (existing) await api(`/conv/profiles/${existing.id}`, { method: "PUT", body })
          else await api("/conv/profiles", { method: "POST", body })
          toast.success(existing ? `订阅「${name}」已覆盖更新${edited ? "（静态）" : ""}` : `订阅「${name}」已保存${edited ? "（静态）" : ""}`)
          await load()
        }}
      />
      {staticEditing && <StaticProfileDialog profile={staticEditing} onOpenChange={() => setStaticEditing(null)} onDone={load} />}
    </div>
  )
}
