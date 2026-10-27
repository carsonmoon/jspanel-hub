import { useEffect, useRef, useState } from "react"
import { Copy, Upload } from "lucide-react"
import { toast } from "sonner"

import { Button } from "@/components/ui/button"
import { Dialog, DialogContent, DialogFooter, DialogHeader, DialogTitle } from "@/components/ui/dialog"
import { Input } from "@/components/ui/input"
import { Label } from "@/components/ui/label"
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select"
import { Switch } from "@/components/ui/switch"
import { Badge } from "@/components/ui/badge"
import { api, type ConvNode, type ConvProfile, type ConvSnippet, type ConvTemplate } from "@/lib/api"
import { copyText } from "@/lib/utils"

// ---- 导入弹窗：粘贴链接 / 订阅 URL / 上传配置 / 面板节点同步 ----

type ImportTab = "links" | "url" | "file" | "managed"

type ImportReport = { imported: number; refreshed?: number; skipped: { name: unknown; reason: string }[] }

export function ConvImportDialog({ open, onOpenChange, onDone }: {
  open: boolean
  onOpenChange: (v: boolean) => void
  onDone: () => Promise<void>
}) {
  const [tab, setTab] = useState<ImportTab>("links")
  const [links, setLinks] = useState("")
  const [url, setUrl] = useState("")
  const [yaml, setYaml] = useState("")
  const [managedNodes, setManagedNodes] = useState<{ node: { id: number; name: string; protocol: string; listen_port: number }; checked: boolean }[] | null>(null)
  const [busy, setBusy] = useState(false)
  const [report, setReport] = useState<ImportReport | null>(null)
  const fileRef = useRef<HTMLInputElement>(null)

  useEffect(() => {
    if (open) {
      setReport(null)
      setLinks("")
      setUrl("")
      setYaml("")
      setManagedNodes(null)
    }
  }, [open])

  useEffect(() => {
    if (!open || tab !== "managed" || managedNodes) return
    api<{ nodes: { id: number; name: string; protocol: string; listen_port: number }[] }>("/proxy/nodes")
      .then((r) => setManagedNodes(r.nodes.map((node) => ({ node, checked: true }))))
      .catch((e) => toast.error((e as Error).message))
  }, [open, tab, managedNodes])

  const submit = async () => {
    setBusy(true)
    try {
      const body: Record<string, unknown> = {}
      if (tab === "links") body.links = links
      if (tab === "url") body.url = url.trim()
      if (tab === "file") body.yaml = yaml
      if (tab === "managed") {
        body.managed = true
        body.managed_ids = (managedNodes ?? []).filter((x) => x.checked).map((x) => x.node.id)
      }
      const r = await api<ImportReport>("/conv/nodes/import", { method: "POST", body: JSON.stringify(body) })
      setReport(r)
      await onDone()
    } catch (e) {
      toast.error((e as Error).message)
    } finally {
      setBusy(false)
    }
  }

  return (
    <Dialog open={open} onOpenChange={onOpenChange}>
      <DialogContent className="max-h-[85vh] max-w-lg overflow-y-auto">
        <DialogHeader>
          <DialogTitle>导入代理</DialogTitle>
        </DialogHeader>
        <div className="flex gap-1 rounded-md bg-muted p-1 text-sm">
          {([["links", "粘贴链接"], ["url", "订阅 URL"], ["file", "上传配置"], ["managed", "面板代理"]] as [ImportTab, string][]).map(([k, label]) => (
            <button key={k} onClick={() => setTab(k)} className={`flex-1 rounded px-2 py-1 transition-colors ${tab === k ? "bg-background font-medium shadow-sm" : "text-muted-foreground"}`}>
              {label}
            </button>
          ))}
        </div>
        {tab === "links" && (
          <div className="flex flex-col gap-1.5">
            <Label>分享链接（每行一条，支持 vless/trojan/ss/vmess/hysteria2/anytls/tuic/socks）</Label>
            <textarea className="h-40 w-full rounded-md border bg-transparent p-2 font-mono text-xs" value={links} onChange={(e) => setLinks(e.target.value)} placeholder={"vless://…@1.2.3.4:443?…#香港01\ntrojan://…@5.6.7.8:443#东京02"} />
          </div>
        )}
        {tab === "url" && (
          <div className="flex flex-col gap-1.5">
            <Label>订阅地址（自动识别 base64 链接列表或 Clash 配置；会创建可定时同步的外部订阅源）</Label>
            <Input value={url} onChange={(e) => setUrl(e.target.value)} placeholder="https://airport.example.com/api/v1/client/subscribe?token=…" />
          </div>
        )}
        {tab === "file" && (
          <div className="flex flex-col gap-1.5">
            <Label>上传 Clash/猫咪配置文件（取其中的 proxies 段，原生字段零丢失）</Label>
            <Button variant="outline" size="sm" className="w-fit" onClick={() => fileRef.current?.click()}>选择文件</Button>
            <input ref={fileRef} type="file" accept=".yaml,.yml,.txt,.conf" className="hidden" onChange={(e) => { const f = e.target.files?.[0]; if (f) f.text().then(setYaml); e.target.value = "" }} />
            {yaml && <div className="rounded-md border px-2 py-1 text-xs text-muted-foreground">已读取 {yaml.length} 字符</div>}
          </div>
        )}
        {tab === "managed" && (
          <div className="flex flex-col gap-1.5">
            <Label>面板自建代理（勾选要导入的；同步式快照：重复执行会刷新已有代理的链接与名称）</Label>
            {managedNodes === null ? (
              <div className="py-4 text-center text-xs text-muted-foreground">加载中…</div>
            ) : managedNodes.length === 0 ? (
              <div className="py-4 text-center text-xs text-muted-foreground">代理页还没有条目。</div>
            ) : (
              <div className="flex max-h-48 flex-col gap-1 overflow-y-auto rounded-md border p-2">
                {managedNodes.map(({ node: n, checked }) => (
                  <label key={n.id} className="flex cursor-pointer items-center justify-between gap-2 rounded px-1.5 py-1 text-xs hover:bg-muted">
                    <span className="flex items-center gap-2">
                      <input
                        type="checkbox"
                        checked={checked}
                        onChange={(e) => setManagedNodes(managedNodes.map((x) => (x.node.id === n.id ? { ...x, checked: e.target.checked } : x)))}
                      />
                      <span className="truncate font-medium">{n.name}</span>
                    </span>
                    <span className="font-mono text-muted-foreground">{n.protocol} · {n.listen_port}</span>
                  </label>
                ))}
              </div>
            )}
            <p className="text-xs text-muted-foreground">为勾选的代理用其默认凭据生成分享链接入池；此后管理侧改端口/换凭据，回到这里再点一次即可刷新。</p>
          </div>
        )}
        {report && (
          <div className="flex flex-col gap-1 rounded-md border p-2 text-xs">
            <div className="font-medium text-emerald-600">导入成功 {report.imported} 条{report.refreshed ? `，刷新 ${report.refreshed} 条` : ""}</div>
            {report.skipped.length > 0 && (
              <div className="flex flex-col gap-0.5 text-muted-foreground">
                <div>跳过 {report.skipped.length} 条：</div>
                {report.skipped.map((s, i) => (
                  <div key={i} className="truncate">· {String(s.name)}：{s.reason}</div>
                ))}
              </div>
            )}
          </div>
        )}
        <DialogFooter>
          <Button disabled={busy || (tab === "links" && !links.trim()) || (tab === "url" && !url.trim()) || (tab === "file" && !yaml) || (tab === "managed" && !(managedNodes ?? []).some((x) => x.checked))} onClick={submit}>
            {tab === "managed" ? (report ? "再次同步" : "同步导入") : report ? "继续导入" : "导入"}
          </Button>
        </DialogFooter>
      </DialogContent>
    </Dialog>
  )
}

// ---- 节点编辑弹窗 ----

export function ConvNodeEditDialog({ open, onOpenChange, node, onDone }: {
  open: boolean
  onOpenChange: (v: boolean) => void
  node: ConvNode | null
  onDone: () => Promise<void>
}) {
  const [name, setName] = useState("")
  const [tags, setTags] = useState("")
  const [enabled, setEnabled] = useState(true)
  const [busy, setBusy] = useState(false)

  useEffect(() => {
    if (!open || !node) return
    setName(node.name)
    setTags(node.tags.join(", "))
    setEnabled(node.enabled)
  }, [open, node])

  const save = async () => {
    if (!node) return
    setBusy(true)
    try {
      await api(`/conv/nodes/${node.id}`, { method: "PUT", body: JSON.stringify({ name, tags: tags.split(/[,，]/).map((t) => t.trim()).filter(Boolean), note: node.note, enabled }) })
      await onDone()
      onOpenChange(false)
    } catch (e) {
      toast.error((e as Error).message)
    } finally {
      setBusy(false)
    }
  }

  return (
    <Dialog open={open} onOpenChange={onOpenChange}>
      <DialogContent className="max-w-md">
        <DialogHeader>
          <DialogTitle>编辑代理</DialogTitle>
        </DialogHeader>
        <div className="flex flex-col gap-3">
          <div className="flex flex-col gap-1.5">
            <Label>代理名称</Label>
            <Input value={name} onChange={(e) => setName(e.target.value)} />
          </div>
          <div className="flex flex-col gap-1.5">
            <Label>标签（逗号分隔，生成订阅时按标签勾选）</Label>
            <Input value={tags} onChange={(e) => setTags(e.target.value)} placeholder="🇭🇰, 机场01" />
          </div>
          <div className="grid grid-cols-3 gap-2 text-xs text-muted-foreground">
            <div><div className="font-medium text-foreground">{node?.protocol || "-"}</div>协议</div>
            <div className="col-span-2 truncate"><div className="font-mono font-medium text-foreground">{node ? `${node.server}:${node.port}` : "-"}</div>服务器</div>
          </div>
          {node?.raw_link && (
            <div className="flex flex-col gap-1.5">
              <div className="flex items-center justify-between">
                <Label>原始链接</Label>
                <Button variant="ghost" size="sm" onClick={() => copyText(node.raw_link, "链接已复制")}>
                  <Copy className="size-3.5" /> 复制
                </Button>
              </div>
              <div className="max-h-20 overflow-y-auto rounded-md border bg-muted/40 p-2 font-mono text-xs break-all">{node.raw_link}</div>
            </div>
          )}
          <label className="flex items-center gap-2 text-sm">
            <Switch checked={enabled} onCheckedChange={setEnabled} /> 启用（停用后不进入任何订阅）
          </label>
        </div>
        <DialogFooter>
          <Button disabled={busy || !name.trim()} onClick={save}>保存</Button>
        </DialogFooter>
      </DialogContent>
    </Dialog>
  )
}

// ---- 重命名弹窗 ----

export function ConvRenameDialog({ open, onOpenChange, onDone }: {
  open: boolean
  onOpenChange: (v: boolean) => void
  onDone: () => Promise<void>
}) {
  const [mode, setMode] = useState<"prefix" | "replace">("prefix")
  const [prefix, setPrefix] = useState("")
  const [find, setFind] = useState("")
  const [replace, setReplace] = useState("")
  const [busy, setBusy] = useState(false)

  useEffect(() => {
    if (open) {
      setMode("prefix")
      setPrefix("")
      setFind("")
      setReplace("")
    }
  }, [open])

  const save = async () => {
    setBusy(true)
    try {
      const body = mode === "prefix" ? { mode, prefix: prefix.trim() } : { mode, find, replace }
      const r = await api<{ updated: number }>("/conv/nodes/rename", { method: "POST", body: JSON.stringify(body) })
      toast.success(`已更新 ${r.updated} 个代理名`)
      await onDone()
      onOpenChange(false)
    } catch (e) {
      toast.error((e as Error).message)
    } finally {
      setBusy(false)
    }
  }

  return (
    <Dialog open={open} onOpenChange={onOpenChange}>
      <DialogContent className="max-w-sm">
        <DialogHeader>
          <DialogTitle>批量重命名</DialogTitle>
        </DialogHeader>
        <div className="flex flex-col gap-3">
          <div className="flex gap-1 rounded-md bg-muted p-1 text-sm">
            <button onClick={() => setMode("prefix")} className={`flex-1 rounded px-2 py-1 transition-colors ${mode === "prefix" ? "bg-background font-medium shadow-sm" : "text-muted-foreground"}`}>加前缀</button>
            <button onClick={() => setMode("replace")} className={`flex-1 rounded px-2 py-1 transition-colors ${mode === "replace" ? "bg-background font-medium shadow-sm" : "text-muted-foreground"}`}>查找替换</button>
          </div>
          {mode === "prefix" ? (
            <div className="flex flex-col gap-1.5">
              <Label>统一前缀</Label>
              <Input value={prefix} onChange={(e) => setPrefix(e.target.value)} placeholder="例如 [机场01] " />
            </div>
          ) : (
            <>
              <div className="flex flex-col gap-1.5">
                <Label>查找内容</Label>
                <Input value={find} onChange={(e) => setFind(e.target.value)} />
              </div>
              <div className="flex flex-col gap-1.5">
                <Label>替换为（可留空 = 删除）</Label>
                <Input value={replace} onChange={(e) => setReplace(e.target.value)} />
              </div>
            </>
          )}
        </div>
        <DialogFooter>
          <Button disabled={busy || (mode === "prefix" ? !prefix.trim() : !find)} onClick={save}>执行</Button>
        </DialogFooter>
      </DialogContent>
    </Dialog>
  )
}

// ---- 保存内容方案取名弹窗（规则模式两 tab 的「加载 → 预览 → 保存」共用）----
// 方向二后方案只是配方：无有效期/启停/链接，交付统一在用户页按客户进行。

export function TplSaveDialog({ open, onOpenChange, defaultName, existingNames, notice, onSave }: {
  open: boolean
  onOpenChange: (v: boolean) => void
  defaultName: string
  existingNames: string[]
  /** 非空时在弹窗里额外展示（如「已修改：将保存为静态方案」）。 */
  notice?: string
  onSave: (name: string) => Promise<void>
}) {
  const [name, setName] = useState("")
  const [busy, setBusy] = useState(false)

  useEffect(() => {
    if (open) setName(defaultName)
  }, [open, defaultName])

  const trimmed = name.trim()
  const overwrite = existingNames.includes(trimmed)
  const save = async () => {
    setBusy(true)
    try {
      await onSave(trimmed)
      onOpenChange(false)
    } catch (e) {
      toast.error((e as Error).message)
    } finally {
      setBusy(false)
    }
  }

  return (
    <Dialog open={open} onOpenChange={onOpenChange}>
      <DialogContent className="max-w-sm">
        <DialogHeader>
          <DialogTitle>保存内容方案</DialogTitle>
        </DialogHeader>
        <div className="flex flex-col gap-3">
          <div className="flex flex-col gap-1.5">
            <Label>方案名称</Label>
            <Input
              value={name}
              onChange={(e) => setName(e.target.value)}
              placeholder="例如 我的分流"
              autoFocus
              onKeyDown={(e) => { if (e.key === "Enter" && trimmed && !busy) save() }}
            />
          </div>
          {notice && <div className="rounded-md border border-warn/40 bg-warn/10 px-2 py-1.5 text-xs text-warn">{notice}</div>}
          <div className="text-xs text-muted-foreground">
            {overwrite ? "已存在同名方案，保存将覆盖更新它（绑定它的客户下次更新订阅即生效）。" : "方案保存后到用户页选择它交付给客户。"}
          </div>
        </div>
        <DialogFooter>
          <Button disabled={busy || !trimmed} onClick={save}>保存</Button>
        </DialogFooter>
      </DialogContent>
    </Dialog>
  )
}

// ---- 静态订阅编辑弹窗（整份 YAML 原样存储）----

export function StaticProfileDialog({ profile, onOpenChange, onDone }: {
  profile: ConvProfile | null
  onOpenChange: (v: boolean) => void
  onDone: () => Promise<void>
}) {
  const [content, setContent] = useState("")
  const [busy, setBusy] = useState(false)

  useEffect(() => {
    if (profile) setContent(profile.static_content)
  }, [profile])

  const save = async () => {
    if (!profile) return
    setBusy(true)
    try {
      await api(`/conv/profiles/${profile.id}`, { method: "PUT", body: JSON.stringify({ name: profile.name, static_content: content }) })
      toast.success("静态订阅已更新")
      await onDone()
      onOpenChange(false)
    } catch (e) {
      toast.error((e as Error).message)
    } finally {
      setBusy(false)
    }
  }

  return (
    <Dialog open={!!profile} onOpenChange={onOpenChange}>
      <DialogContent className="max-h-[90vh] sm:max-w-4xl overflow-y-auto">
        <DialogHeader>
          <DialogTitle>编辑静态订阅 · {profile?.name}</DialogTitle>
        </DialogHeader>
        <p className="text-xs text-muted-foreground">静态订阅原样下发这份 YAML，不随代理/勾选变化；想换代理就删掉重新生成。</p>
        <textarea
          className="h-[55vh] w-full rounded-md border bg-transparent p-2 font-mono text-xs"
          value={content}
          onChange={(e) => setContent(e.target.value)}
          spellCheck={false}
        />
        <DialogFooter>
          <Button disabled={busy || !content.trim()} onClick={save}>保存</Button>
        </DialogFooter>
      </DialogContent>
    </Dialog>
  )
}

// ---- 模板上传/编辑弹窗 ----

export function ConvTemplateDialog({ open, onOpenChange, editing, onDone }: {
  open: boolean
  onOpenChange: (v: boolean) => void
  editing: ConvTemplate | null
  onDone: () => Promise<void>
}) {
  const [name, setName] = useState("")
  const [content, setContent] = useState("")
  const [busy, setBusy] = useState(false)
  const fileRef = useRef<HTMLInputElement>(null)

  useEffect(() => {
    if (!open) return
    setName(editing?.name ?? "")
    setContent("")
    if (editing) {
      fetch(`/api/conv/templates/${editing.id}/content`, { credentials: "include" })
        .then((r) => { if (!r.ok) throw new Error(`HTTP ${r.status}`); return r.text() })
        .then(setContent)
        .catch((e) => toast.error((e as Error).message))
    }
  }, [open, editing])

  const loadFile = (file: File) => file.text().then(setContent)

  const save = async () => {
    setBusy(true)
    try {
      // note 已无展示位置，弹窗不再提供输入；编辑时原样保留库内值，避免静默抹掉
      const body = JSON.stringify({ name: name.trim(), note: editing?.note ?? "", content })
      if (editing) await api(`/conv/templates/${editing.id}`, { method: "PUT", body })
      else await api("/conv/templates", { method: "POST", body })
      await onDone()
      onOpenChange(false)
    } catch (e) {
      toast.error((e as Error).message)
    } finally {
      setBusy(false)
    }
  }

  return (
    <Dialog open={open} onOpenChange={onOpenChange}>
      <DialogContent className="max-h-[88vh] max-w-2xl overflow-y-auto">
        <DialogHeader>
          <DialogTitle>{editing ? "编辑模板" : "上传模板"}</DialogTitle>
        </DialogHeader>
        <div className="flex flex-col gap-1.5">
          <Label>模板名称</Label>
          <Input value={name} onChange={(e) => setName(e.target.value)} disabled={!!editing?.is_builtin && editing.name !== ""} placeholder="我的模板" />
        </div>
        <div className="flex flex-col gap-1.5">
          <div className="flex items-center justify-between">
            <Label>mihomo 配置</Label>
            <div className="flex gap-1">
              <input ref={fileRef} type="file" accept=".yaml,.yml,.txt" className="hidden" onChange={(e) => { const f = e.target.files?.[0]; if (f) loadFile(f); e.target.value = "" }} />
              <Button variant="outline" size="sm" onClick={() => fileRef.current?.click()}><Upload className="size-3.5" /> 读入文件</Button>
            </div>
          </div>
          <textarea className="h-72 w-full rounded-md border bg-transparent p-2 font-mono text-xs" value={content} onChange={(e) => setContent(e.target.value)} placeholder="mixed-port: 7890&#10;proxies: []&#10;proxy-groups:&#10;  - name: 🚀 节点选择&#10;    type: select&#10;    proxies: [__ALL__, DIRECT]&#10;rules:&#10;  - GEOSITE,cn,DIRECT&#10;  - MATCH,🚀 节点选择" />
          <p className="text-[11px] text-muted-foreground">使用模板时勾选的代理会替换其中的 proxies 键，其余内容原样保留；分组里可用 __ALL__ / __TAG:地区__ 占位。</p>
        </div>
        <DialogFooter>
          <Button disabled={busy || !name.trim() || !content.trim()} onClick={save}>{editing ? "保存" : "上传"}</Button>
        </DialogFooter>
      </DialogContent>
    </Dialog>
  )
}

// ---- 规则片段库弹窗 ----

export function ConvSnippetDialog({ open, onOpenChange, editing, onDone }: {
  open: boolean
  onOpenChange: (v: boolean) => void
  editing: ConvSnippet | null
  onDone: () => Promise<void>
}) {
  const [name, setName] = useState("")
  const [kind, setKind] = useState("rules")
  const [mode, setMode] = useState("prepend")
  const [content, setContent] = useState("")
  const [enabled, setEnabled] = useState(true)
  const [busy, setBusy] = useState(false)

  useEffect(() => {
    if (!open) return
    setName(editing?.name ?? "")
    setKind(editing?.kind ?? "rules")
    setMode(editing?.mode ?? "prepend")
    setContent(editing?.content ?? "")
    setEnabled(editing?.enabled ?? true)
  }, [open, editing])

  const save = async () => {
    setBusy(true)
    try {
      const body = JSON.stringify({ name: name.trim(), kind, mode, content, enabled })
      if (editing) await api(`/conv/snippets/${editing.id}`, { method: "PUT", body })
      else await api("/conv/snippets", { method: "POST", body })
      await onDone()
      onOpenChange(false)
    } catch (e) {
      toast.error((e as Error).message)
    } finally {
      setBusy(false)
    }
  }

  return (
    <Dialog open={open} onOpenChange={onOpenChange}>
      <DialogContent className="max-w-xl">
        <DialogHeader>
          <DialogTitle>{editing ? "编辑规则片段" : "新建规则片段"}</DialogTitle>
        </DialogHeader>
        <div className="flex flex-col gap-3">
          <div className="flex flex-col gap-1.5">
            <Label>名称</Label>
            <Input value={name} onChange={(e) => setName(e.target.value)} placeholder="自定义直连" />
          </div>
          <div className="grid grid-cols-2 gap-3">
            <div className="flex min-w-0 flex-col gap-1.5">
              <Label>类型</Label>
              <Select value={kind} onValueChange={setKind}>
                <SelectTrigger className="w-full"><SelectValue /></SelectTrigger>
                <SelectContent>
                  <SelectItem value="rules">rules（规则段）</SelectItem>
                  <SelectItem value="dns">dns（替换 dns 段）</SelectItem>
                </SelectContent>
              </Select>
            </div>
            <div className="flex min-w-0 flex-col gap-1.5">
              <Label>合并方式</Label>
              <Select value={mode} onValueChange={setMode} disabled={kind === "dns"}>
                <SelectTrigger className="w-full"><SelectValue /></SelectTrigger>
                <SelectContent>
                  <SelectItem value="prepend">prepend（插到规则最前）</SelectItem>
                  <SelectItem value="append" disabled={kind === "dns"}>append（MATCH 之前）</SelectItem>
                </SelectContent>
              </Select>
            </div>
          </div>
        </div>
        <div className="flex flex-col gap-1.5">
          <Label>片段内容（多行 YAML；rules 类型为规则序列，每行一条）</Label>
          <textarea className="h-44 w-full rounded-md border bg-transparent p-2 font-mono text-xs" value={content} onChange={(e) => setContent(e.target.value)} placeholder={"- DOMAIN-SUFFIX,example.com,DIRECT\n- DOMAIN-KEYWORD,google,🚀 节点选择"} />
        </div>
        <label className="flex items-center gap-2 text-sm">
          <Switch checked={enabled} onCheckedChange={setEnabled} /> 启用
        </label>
        <DialogFooter>
          <Button disabled={busy || !name.trim() || !content.trim()} onClick={save}>{editing ? "保存" : "创建"}</Button>
        </DialogFooter>
      </DialogContent>
    </Dialog>
  )
}

// ---- 生成订阅弹窗（模板 + 标签 + 片段 + 有效期 + 预览） ----

export function ConvProfileDialog({ open, onOpenChange, editing, templates, tags, snippets, categories, presets, initialTemplate, onDone }: {
  open: boolean
  onOpenChange: (v: boolean) => void
  editing: ConvProfile | null
  templates: ConvTemplate[]
  tags: string[]
  snippets: ConvSnippet[]
  /** 生效分流类别目录（内置含覆盖 + 自定义来源），按类别生成模式的勾选来源。 */
  categories: { label: string; key: string; custom: boolean }[]
  /** 全部预设（内置含覆盖 + 自定义来源，imported=已入库）；未导入的选中后自动拉取。 */
  presets: { key: string; name: string; imported: boolean }[]
  /** 新建时的默认：模板名字符串，或规则模式选择 { 模板名, 勾选类别 }。 */
  initialTemplate?: string | { name: string; categories: string[] }
  onDone: () => Promise<void>
}) {
  const [name, setName] = useState("")
  const [templateName, setTemplateName] = useState("")
  const [selectedTags, setSelectedTags] = useState<string[]>([])
  const [snippetIds, setSnippetIds] = useState<number[]>([])
  const [expiresAt, setExpiresAt] = useState("")
  const [enabled, setEnabled] = useState(true)
  const [selectedCategories, setSelectedCategories] = useState<string[]>([])
  const [genMode, setGenMode] = useState<"template" | "categories">("template")
  const [tplOpen, setTplOpen] = useState(false)
  const [preview, setPreview] = useState("")
  const [busy, setBusy] = useState(false)

  useEffect(() => {
    if (!open) return
    setName(editing?.name ?? "")
    // 规则模式默认带出仅限新建：编辑时保留订阅自己的模板与类别，
    // 否则页面级规则模式会悄悄覆盖订阅的 selected_categories。
    const init = !editing && typeof initialTemplate === "object" && initialTemplate !== null ? initialTemplate : undefined
    const wanted = editing?.template_name
      || (init && templates.some((t) => t.name === init.name) ? init.name : "")
      || (typeof initialTemplate === "string" && templates.some((t) => t.name === initialTemplate) ? initialTemplate : "")
    setTemplateName(wanted || templates[0]?.name || "")
    setSelectedCategories(editing?.selected_categories ?? init?.categories ?? [])
    setGenMode(
      editing
        ? editing.selected_categories.length
          ? "categories"
          : "template"
        : (init?.categories?.length ? "categories" : "template"),
    )
    setSelectedTags(editing?.selected_tags ?? [])
    setSnippetIds(editing?.snippet_ids ?? [])
    setExpiresAt(editing?.expires_at ? new Date(editing.expires_at * 1000).toISOString().slice(0, 10) : "")
    setEnabled(editing?.enabled ?? true)
    setPreview("")
  }, [open, editing, templates, initialTemplate])

  // 使用模板下拉：已导入模板 + 未导入预设（value=preset:key，保存/预览前自动导入），名称 zh 字母序
  const templateOptions = (() => {
    const presetNames = new Set(presets.map((p) => p.name))
    const opts: { value: string; label: string }[] = templates
      .filter((t) => !presets.some((p) => p.imported && p.name === t.name))
      .map((t) => ({ value: t.name, label: t.name }))
    for (const p of presets) {
      if (!p.imported && !presetNames.has("") && !templates.some((t) => t.name === p.name)) {
        opts.push({ value: `preset:${p.key}`, label: p.name })
      }
    }
    return opts.sort((a, b) => a.label.localeCompare(b.label, "zh-Hans-CN"))
  })()
  // 选中值若是未导入预设：先导入入库，返回真实模板名
  const resolveTemplate = async (): Promise<string> => {
    if (!templateName.startsWith("preset:")) return templateName
    const key = templateName.slice("preset:".length)
    const r = await api<{ name: string }>(`/conv/template-presets/${key}/import`, { method: "POST" })
    return r.name
  }
  const toggleTag = (t: string) => setSelectedTags(selectedTags.includes(t) ? selectedTags.filter((x) => x !== t) : [...selectedTags, t])
  const toggleSnippet = (id: number) => setSnippetIds(snippetIds.includes(id) ? snippetIds.filter((x) => x !== id) : [...snippetIds, id])
  const expirySecs = () => (expiresAt ? Math.floor(new Date(expiresAt).getTime() / 1000 + 86399) : 0)

  const body = async () =>
    JSON.stringify({
      name: name.trim() || "预览",
      // 按类别生成：模板名仅作空勾选时的回落基底；使用模板：类别恒为空
      template_name: genMode === "categories" ? templateName || "均衡规则.yaml" : await resolveTemplate(),
      selected_categories: genMode === "categories" ? selectedCategories : [],
      selected_tags: selectedTags,
      snippet_ids: snippetIds,
      expires_at: expirySecs(),
      enabled,
    })

  const doPreview = async () => {
    try {
      // 预览端点返回 YAML 纯文本，不能走按 JSON 解析的 api() 辅助。
      const resp = await fetch("/api/conv/profiles/preview", {
        method: "POST",
        headers: { "content-type": "application/json" },
        credentials: "include",
        body: await body(),
      })
      const text = await resp.text()
      if (!resp.ok) throw new Error(text || `HTTP ${resp.status}`)
      setPreview(text)
    } catch (e) {
      toast.error((e as Error).message)
    }
  }

  const save = async () => {
    setBusy(true)
    try {
      if (editing) await api(`/conv/profiles/${editing.id}`, { method: "PUT", body: await body() })
      else await api("/conv/profiles", { method: "POST", body: await body() })
      await onDone()
      onOpenChange(false)
    } catch (e) {
      toast.error((e as Error).message)
    } finally {
      setBusy(false)
    }
  }

  return (
    <Dialog open={open} onOpenChange={onOpenChange}>
      <DialogContent className="max-h-[88vh] max-w-xl overflow-y-auto">
        <DialogHeader>
          <DialogTitle>{editing ? "编辑订阅" : "生成订阅"}</DialogTitle>
        </DialogHeader>
        <div className="grid grid-cols-2 gap-3">
          <div className="flex flex-col gap-1.5">
            <Label>订阅名称</Label>
            <Input value={name} onChange={(e) => setName(e.target.value)} placeholder="我的订阅" />
          </div>
          <div className="flex flex-col gap-1.5">
            <Label>生成方式</Label>
            <div className="flex gap-1 rounded-md bg-muted p-1 text-sm">
              <button onClick={() => setGenMode("template")} className={`flex-1 rounded px-2 py-1 transition-colors ${genMode === "template" ? "bg-background font-medium shadow-sm" : "text-muted-foreground"}`}>使用模板</button>
              <button onClick={() => setGenMode("categories")} className={`flex-1 rounded px-2 py-1 transition-colors ${genMode === "categories" ? "bg-background font-medium shadow-sm" : "text-muted-foreground"}`}>按类别生成</button>
            </div>
            {genMode === "template" ? (
              // 自建滚动面板：radix Select 在 40 条目下有滚动循环/难选中/宽度抖动问题
              <div className="relative">
                <Button variant="outline" className="w-full justify-between font-normal" onClick={() => setTplOpen(!tplOpen)}>
                  <span className="truncate">{templateOptions.find((o) => o.value === templateName)?.label ?? (templateName || "选择模板…")}</span>
                </Button>
                {tplOpen && (
                  <>
                    <div className="fixed inset-0 z-10" onClick={() => setTplOpen(false)} />
                    <div className="absolute z-20 mt-1 max-h-60 w-[24rem] max-w-[85vw] overflow-y-auto rounded-md border bg-popover p-1 shadow-md">
                      {templateOptions.map((o) => (
                        <button
                          key={o.value}
                          title={o.label}
                          className={`flex w-full items-center rounded px-2 py-1.5 text-left text-xs hover:bg-muted ${templateName === o.value ? "bg-secondary font-medium" : ""}`}
                          onClick={() => { setTemplateName(o.value); setTplOpen(false) }}
                        >
                          <span className="truncate">{o.label}</span>
                        </button>
                      ))}
                    </div>
                  </>
                )}
              </div>
            ) : (
              <div className="grid max-h-40 grid-cols-2 gap-1 overflow-y-auto rounded-md border p-1.5 md:grid-cols-3">
                {categories.map((c) => (
                  <label key={c.key} className="flex cursor-pointer items-center gap-1.5 rounded px-1 py-0.5 text-xs hover:bg-muted">
                    <input
                      type="checkbox"
                      checked={selectedCategories.includes(c.key)}
                      onChange={() => setSelectedCategories((prev) => (prev.includes(c.key) ? prev.filter((x) => x !== c.key) : [...prev, c.key]))}
                    />
                    <span className="truncate">{c.label}</span>
                    {c.custom && <span className="text-[11px] text-muted-foreground">自定义</span>}
                  </label>
                ))}
                {categories.length === 0 && <span className="text-xs text-muted-foreground">加载中…</span>}
                <div className="col-span-full text-[11px] text-muted-foreground">一个都不勾 = 回落为上方模板的注入结果。</div>
              </div>
            )}
          </div>
        </div>
        <div className="grid grid-cols-2 gap-3">
          <div className="flex flex-col gap-1.5">
            <Label>代理标签（不勾 = 全部代理）</Label>
            <div className="flex min-h-9 flex-wrap items-center gap-1.5 rounded-md border p-1.5">
              {tags.length === 0 && <span className="text-xs text-muted-foreground">代理还没有标签。</span>}
              {tags.map((t) => (
                <button key={t} onClick={() => toggleTag(t)} className={`rounded-md border px-2 py-0.5 text-xs transition-colors ${selectedTags.includes(t) ? "border-foreground bg-secondary font-medium" : "text-muted-foreground hover:bg-muted"}`}>
                  {t}
                </button>
              ))}
            </div>
          </div>
          <div className="flex flex-col gap-1.5">
            <Label>有效期（留空 = 永不过期）</Label>
            <Input type="date" value={expiresAt} onChange={(e) => setExpiresAt(e.target.value)} />
          </div>
        </div>
        <div className="flex flex-col gap-1.5">
          <Label>规则片段（勾选按顺序合并进生成的配置）</Label>
          <div className="flex flex-wrap gap-1.5">
            {snippets.length === 0 && <span className="text-xs text-muted-foreground">片段库为空，可在下方「规则片段库」新建。</span>}
            {snippets.map((s) => (
              <button key={s.id} onClick={() => toggleSnippet(s.id)} className={`rounded-md border px-2 py-0.5 text-xs transition-colors ${snippetIds.includes(s.id) ? "border-foreground bg-secondary font-medium" : "text-muted-foreground hover:bg-muted"}`}>
                {s.name} · {s.mode}
              </button>
            ))}
          </div>
        </div>
        <label className="flex items-center gap-2 text-sm">
          <Switch checked={enabled} onCheckedChange={setEnabled} /> 启用（停用后订阅地址返回失效占位配置）
        </label>
        {preview && <pre className="max-h-56 overflow-auto rounded-md border bg-muted/40 p-2 text-xs">{preview}</pre>}
        <DialogFooter>
          <Button variant="outline" disabled={busy} onClick={doPreview}>预览 YAML</Button>
          <Button disabled={busy || !name.trim() || (genMode === "template" && !templateName)} onClick={save}>{editing ? "保存" : "创建"}</Button>
        </DialogFooter>
      </DialogContent>
    </Dialog>
  )
}

// 下载辅助（模板下载用）
export function downloadText(filename: string, text: string) {
  const blob = new Blob([text], { type: "application/yaml" })
  const url = URL.createObjectURL(blob)
  const a = document.createElement("a")
  a.href = url
  a.download = filename
  a.click()
  URL.revokeObjectURL(url)
}

// ---- 可视化拖拽分组编辑器：把节点拖进模板代理组 ----

export function ConvGroupEditorDialog({ open, onOpenChange, profile, nodes, templates, onDone }: {
  open: boolean
  onOpenChange: (v: boolean) => void
  profile: ConvProfile | null
  nodes: ConvNode[]
  templates: ConvTemplate[]
  onDone: () => Promise<void>
}) {
  // 每个组一份「完整成员列表」：特殊项（DIRECT/REJECT/组名/占位符）与节点 id
  // 混排。字符串成员 = 模板特殊项（渲染端按名字直通）；数字成员 = 节点 id。
  type Member = string | number
  const [groups, setGroups] = useState<{ name: string; type: string }[]>([])
  const [members, setMembers] = useState<Record<string, Member[]>>({})
  const [isOverride, setIsOverride] = useState<Record<string, boolean>>({})
  const [dirty, setDirty] = useState(false)
  const [busy, setBusy] = useState(false)
  const [loading, setLoading] = useState(false)
  const [templateInit, setTemplateInit] = useState<Record<string, Member[]>>({})
  const [dragId, setDragId] = useState<Member | null>(null)
  const [dragFrom, setDragFrom] = useState<string | null>(null)
  const [zoneHot, setZoneHot] = useState<null | "add" | "remove">(null)
  const [showAll, setShowAll] = useState(false)

  useEffect(() => {
    if (!open || !profile) return
    setLoading(true)
    // 按类别生成的订阅：组列表来自类别生成骨架（/api/conv/category-groups），
    // 与实际渲染的组一致；模板订阅仍读绑定模板的组。
    const isCategory = profile.selected_categories.length > 0
    const groupsFetch: Promise<{ groups: { name: string; type: string; template_members?: string[] }[] }> = isCategory
      ? fetch(`/api/conv/category-groups?keys=${encodeURIComponent(profile.selected_categories.join(","))}`, { credentials: "include" })
          .then((r) => { if (!r.ok) throw new Error(`HTTP ${r.status}`); return r.json() })
          .then((g) => ({ groups: (g.groups as { name: string; members: string[] }[]).map((x) => ({ name: x.name, type: "select", template_members: x.members })) }))
      : Promise.resolve({ groups: [] }).then(() => {
          const template = templates.find((t) => t.name === profile.template_name)
          return template
            ? fetch(`/api/conv/templates/${template.id}/groups`, { credentials: "include" })
                .then((r) => { if (!r.ok) throw new Error(`HTTP ${r.status}`); return r.json() })
            : Promise.resolve({ groups: [] })
        })
    groupsFetch
      .then((g: { groups: { name: string; type: string; template_members?: string[] }[] }) => {
        setGroups(g.groups.map(({ name, type }) => ({ name, type })))
        // 初始成员：有覆盖用覆盖（其中数字=节点 id、字符串=特殊项）；无覆盖
        // 用模板成员原样（占位符仍是合法成员，渲染时展开）。
        const init: Record<string, Member[]> = {}
        const ov = profile.group_overrides ?? {}
        for (const grp of g.groups) {
          init[grp.name] = ov[grp.name]
            ? ov[grp.name].map((x) => (typeof x === "number" ? x : (x as string)))
            : (grp.template_members ?? [])
        }
        setMembers(init)
        setTemplateInit(Object.fromEntries(g.groups.map((grp) => [grp.name, grp.template_members ?? []])))
        setIsOverride(Object.fromEntries(g.groups.map((grp) => [grp.name, !!ov[grp.name]])))
        setDirty(false)
      })
      .catch((e) => toast.error((e as Error).message))
      .finally(() => setLoading(false))
  }, [open, profile, templates])

  const nodeName = (id: number) => nodes.find((n) => n.id === id)?.name ?? `代理 ${id}`
  const assignedIds = new Set(
    Object.values(members).flatMap((list) => list.filter((m): m is number => typeof m === "number")),
  )
  const unassigned = nodes.filter((n) => n.enabled && (showAll || !assignedIds.has(n.id)))

  const setList = (gid: string, list: Member[]) => {
    setMembers((m) => ({ ...m, [gid]: list }))
    setIsOverride((o) => ({ ...o, [gid]: true }))
    setDirty(true)
  }
  const addTo = (gid: string, m: Member, before?: number) => {
    const list = members[gid] ?? []
    if (list.includes(m)) return
    const next = [...list]
    if (before === undefined || before >= next.length) next.push(m)
    else next.splice(Math.max(0, before), 0, m)
    setList(gid, next)
  }
  const removeFrom = (gid: string, idx: number) => {
    setList(gid, (members[gid] ?? []).filter((_, j) => j !== idx))
  }
  const moveIn = (gid: string, idx: number, dir: -1 | 1) => {
    const list = [...(members[gid] ?? [])]
    const j = idx + dir
    if (j < 0 || j >= list.length) return
    ;[list[idx], list[j]] = [list[j], list[idx]]
    setList(gid, list)
  }
  const onDropGroup = (gid: string, before: number) => {
    if (dragId === null || dragFrom === null) return
    if (dragFrom === gid) {
      const list = [...(members[gid] ?? [])]
      const from = list.indexOf(dragId)
      if (from < 0) return
      list.splice(from, 1)
      const target = from < before ? before - 1 : before
      list.splice(Math.max(0, target), 0, dragId)
      setList(gid, list)
    } else {
      addTo(gid, dragId, before)
    }
    setDragId(null)
    setDragFrom(null)
  }

  // 节点是否已被某组成员覆盖（显式 id / __ALL__ / 命中 __TAG 占位）
  const coveredBy = (list: Member[] | undefined, id: number, tags: string[]) => {
    if (!list) return false
    if (list.includes(id)) return true
    return list.some((m) => typeof m === "string" && ((m === "__ALL__") || (m.startsWith("__TAG:") && m.endsWith("__") && tags.includes(m.slice(6, -2)))))
  }
  // 批量加/移所有组：占位组按需展开成显式成员（移除=剔除该节点后冻结），
  // 未覆盖的组不动（保持占位符自动跟随，不无谓冻结）。
  const addNodeToAll = (id: number) => {
    const node = nodes.find((n) => n.id === id)
    const next: Record<string, Member[]> = { ...members }
    const touched: string[] = []
    for (const g of groups) {
      const list = next[g.name] ?? []
      if (coveredBy(list, id, node?.tags ?? [])) continue
      next[g.name] = [...list, id]
      touched.push(g.name)
    }
    setMembers(next)
    setIsOverride((o) => ({ ...o, ...Object.fromEntries(touched.map((g) => [g, true])) }))
    setDirty(true)
  }
  // 冻结某组为显式成员并移除指定节点（占位组先展开；空表回落 DIRECT）
  const freezeWithout = (gid: string, id: number) => {
    const list = members[gid] ?? []
    const expanded: Member[] = []
    const seen = new Set<string>()
    for (const m of list) {
      const items: Member[] = []
      if (typeof m === "number") items.push(m)
      else if (m === "__ALL__") items.push(...nodes.filter((n) => n.enabled).map((n) => n.id))
      else if (typeof m === "string" && m.startsWith("__TAG:") && m.endsWith("__")) {
        const tag = m.slice("__TAG:".length, -"__".length)
        items.push(...nodes.filter((n) => n.enabled && n.tags.includes(tag)).map((n) => n.id))
      } else items.push(m)
      for (const it of items) {
        if (it === id) continue
        const k = typeof it === "number" ? `#${it}` : it
        if (!seen.has(k)) { seen.add(k); expanded.push(it) }
      }
    }
    const list2 = expanded.length ? expanded : (["DIRECT"] as Member[])
    setMembers((prev) => ({ ...prev, [gid]: list2 }))
    setIsOverride((o) => ({ ...o, [gid]: true }))
    setDirty(true)
  }
  const removeNodeFromAll = (id: number) => {
    const node = nodes.find((n) => n.id === id)
    const tags = node?.tags ?? []
    for (const gid of Object.keys(members)) {
      if (coveredBy(members[gid], id, tags)) freezeWithout(gid, id)
    }
  }

  // 按地区一键建组（miaomiaowu handleAutoGroupByRegion 同款语义）：每个标签
  // 建一个组（成员=该地区节点），入口组改为引用各地区组——用户在入口组里
  // 直接选地区。入口组整表替换为地区引用（不再保留全部节点占位）。
  const autoGroupByRegion = () => {
    const next: Record<string, Member[]> = { ...members }
    const allTags: string[] = []
    for (const n of nodes.filter((x) => x.enabled)) {
      for (const t of n.tags) {
        if (!allTags.includes(t)) {
          allTags.push(t)
        }
      }
    }
    if (allTags.length === 0) {
      toast.error("代理没有地区标签，无法按地区建组")
      return
    }
    const entry = groups[0]?.name
    if (entry && next[entry]) {
      next[entry] = ["DIRECT", "REJECT", ...(groups[1] ? [groups[1].name] : []), ...allTags]
      setList(entry, next[entry])
    }
    // 每个地区一张新组卡（已存在则跳过），成员=该地区节点 id
    const added: { name: string; type: string; members: Member[] }[] = []
    for (const tag of allTags) {
      if (groups.some((g) => g.name === tag)) continue
      const ids = nodes.filter((n) => n.enabled && n.tags.includes(tag)).map((n) => n.id)
      next[tag] = ids
      added.push({ name: tag, type: "url-test", members: ids })
    }
    setMembers(next)
    if (added.length) {
      setGroups((g) => [...g, ...added.map((a) => ({ name: a.name, type: a.type }))])
      setIsOverride((o) => ({ ...o, ...Object.fromEntries(added.map((a) => [a.name, true])) }))
    }
    setDirty(true)
    if (added.length) toast.success(`已按地区建 ${added.length} 个组（保存后生效）`)
    toast.success(`已按地区建 ${allTags.length} 个组（保存后生效）`)
  }

  const save = async () => {
    if (!profile) return
    setBusy(true)
    try {
      await api(`/conv/profiles/${profile.id}`, {
        method: "PUT",
        body: JSON.stringify({
          name: profile.name,
          template_name: profile.template_name,
          selected_tags: profile.selected_tags,
          snippet_ids: profile.snippet_ids,
          expires_at: profile.expires_at,
          group_overrides: members,
          enabled: profile.enabled,
        }),
      })
      toast.success("分组已保存")
      await onDone()
      onOpenChange(false)
    } catch (e) {
      toast.error((e as Error).message)
    } finally {
      setBusy(false)
    }
  }
  const clearOverrides = () => {
    setMembers({ ...templateInit })
    setIsOverride(Object.fromEntries(groups.map((g) => [g.name, false])))
    setDirty(true)
  }
  // 占位符显示成语义标签（存的值不变，渲染端语义：__ALL__=勾选的全部节点）
  const enabledCount = nodes.filter((n) => n.enabled).length
  const specialLabel = (m: string) => {
    if (m === "__ALL__") return `全部代理（${enabledCount}）`
    if (m.startsWith("__TAG:") && m.endsWith("__")) return `标签${m.slice("__TAG:".length, -"__".length)}的代理`
    return m
  }
  const specialTitle = (m: string) =>
    m === "__ALL__"
      ? "占位符：渲染时展开为当前勾选的全部代理"
      : m.startsWith("__TAG:")
        ? "占位符：渲染时展开为带该标签的代理"
        : `模板项：${m}`
  // 组内展示列表：__ALL__/__TAG 占位展开成具体节点（仅展示层；保存仍写占位符
  // 原文，未自定义的组保持「随勾选自动变化」）。auto=true 的节点 chip 不可
  // 单独移除/排序，但可拖到其他组（拖入即把目标组转为自定义）。
  const displayOf = (gid: string): { m: Member; auto: boolean; isNode: boolean }[] => {
    const list = members[gid] ?? []
    const out: { m: Member; auto: boolean; isNode: boolean }[] = []
    const seen = new Set<string>()
    const push = (m: Member, auto: boolean, isNode: boolean) => {
      const k = typeof m === "number" ? `#${m}` : m
      if (seen.has(k)) return
      seen.add(k)
      out.push({ m, auto, isNode })
    }
    for (const m of list) {
      if (typeof m === "number") {
        push(m, false, true)
        continue
      }
      if (m === "__ALL__") {
        for (const n of nodes) if (n.enabled) push(n.id, true, true)
        continue
      }
      if (m.startsWith("__TAG:") && m.endsWith("__")) {
        const tag = m.slice("__TAG:".length, -"__".length)
        for (const n of nodes) if (n.enabled && n.tags.includes(tag)) push(n.id, true, true)
        continue
      }
      push(m, true, false)
    }
    return out
  }

  return (
    <Dialog open={open} onOpenChange={onOpenChange}>
      <DialogContent className="max-h-[92vh] sm:max-w-7xl overflow-y-auto">
        <DialogHeader>
          <DialogTitle>可视化分组 — {profile?.name}</DialogTitle>
        </DialogHeader>
        {loading ? (
          <div className="py-8 text-center text-sm text-muted-foreground">加载模板分组…</div>
        ) : (
          <>
            <p className="text-xs text-muted-foreground">
              灰色为模板原有项（渲染时直通或展开），带绿点的是代理：拖入组即自定义、可拖动排序或 × 移除；未自定义的组按占位符自动展开。「全部代理」渲染时展开为当前勾选的全部代理。
            </p>
            <div className="flex flex-wrap items-center gap-2">
              <Button variant="outline" size="sm" onClick={autoGroupByRegion}>按地区一键建组</Button>
              <Button variant="ghost" size="sm" disabled={!dirty} onClick={clearOverrides}>重置全部分组</Button>
              {dirty && <Badge variant="secondary">有未保存修改</Badge>}
              <div className="ml-auto grid grid-cols-2 gap-3">
                <div
                  onDragOver={(e) => { e.preventDefault(); setZoneHot("add") }}
                  onDragLeave={() => setZoneHot(null)}
                  onDrop={(e) => {
                    e.preventDefault()
                    if (typeof dragId === "number") { addNodeToAll(dragId); toast.success("已添加到所有组") }
                    setDragId(null); setDragFrom(null); setZoneHot(null)
                  }}
                  className={`flex min-h-20 flex-col items-center justify-center gap-1 rounded-xl border-2 border-dashed px-6 py-4 text-center transition-colors ${zoneHot === "add" ? "border-foreground bg-secondary text-foreground" : "text-muted-foreground"}`}
                >
                  <span className="text-sm font-medium">添加到所有组</span>
                  <span className="text-[11px]">把左侧代理拖到这里</span>
                </div>
                <div
                  onDragOver={(e) => { e.preventDefault(); setZoneHot("remove") }}
                  onDragLeave={() => setZoneHot(null)}
                  onDrop={(e) => {
                    e.preventDefault()
                    if (typeof dragId === "number") { removeNodeFromAll(dragId); toast.success("已从所有组移除") }
                    setDragId(null); setDragFrom(null); setZoneHot(null)
                  }}
                  className={`flex min-h-20 flex-col items-center justify-center gap-1 rounded-xl border-2 border-dashed px-6 py-4 text-center transition-colors ${zoneHot === "remove" ? "border-destructive bg-destructive/10 text-foreground" : "text-muted-foreground"}`}
                >
                  <span className="text-sm font-medium">从所有组移除</span>
                  <span className="text-[11px]">把左侧代理拖到这里</span>
                </div>
              </div>
            </div>
            <div className="grid grid-cols-1 gap-4 lg:grid-cols-[20rem_1fr]">
              <div className="flex max-h-[60vh] flex-col gap-2 rounded-lg border p-3">
                <div className="flex items-center justify-between">
                  <div className="text-xs font-medium text-muted-foreground">代理池</div>
                  <label className="flex items-center gap-1 text-[11px] text-muted-foreground">
                    <input type="checkbox" checked={showAll} onChange={(e) => setShowAll(e.target.checked)} /> 显示已添加
                  </label>
                </div>
                {unassigned.map((n) => (
                  <div
                    key={n.id}
                    draggable
                    onDragStart={(e) => { e.dataTransfer.setData("text/plain", String(n.id)); setDragId(n.id); setDragFrom("pool") }}
                    onDragEnd={() => { setDragId(null); setDragFrom(null); setZoneHot(null) }}
                    onClick={() => groups[0] && addTo(groups[0].name, n.id)}
                    className={`cursor-grab rounded-lg border px-2.5 py-1.5 text-xs hover:bg-muted ${dragId === n.id ? "border-primary bg-secondary/50" : "bg-background"}`}
                  >
                    <span className="block truncate">{n.name}</span>
                    {n.tags.length > 0 && (
                      <div className="flex gap-1 text-[11px] text-muted-foreground">
                        {n.tags.map((t) => <span key={t}>{t}</span>)}
                      </div>
                    )}
                  </div>
                ))}
                {unassigned.length === 0 && <div className="py-4 text-center text-xs text-muted-foreground">全部代理已分配（勾选「显示已添加」查看）</div>}
              </div>
              <div className="flex max-h-[60vh] flex-col gap-3 overflow-y-auto pr-1">
                {groups.map((g) => {
                  // 展示层展开占位符：所见即渲染结果（节点名而非 __ALL__）
                  const chips = displayOf(g.name)
                  const overridden = isOverride[g.name]
                  return (
                    <div
                      key={g.name}
                      className="flex flex-col gap-2.5 rounded-xl border p-3.5 transition-shadow hover:shadow-sm"
                      onDragOver={(e) => e.preventDefault()}
                      onDrop={(e) => { e.stopPropagation(); onDropGroup(g.name, chips.length) }}
                    >
                      <div className="flex flex-wrap items-center gap-2">
                        <span className="text-sm font-semibold">{g.name}</span>
                        <Badge variant="secondary">{g.type}</Badge>
                        <span className="text-[11px] text-muted-foreground">{chips.length} 成员</span>
                        <span className="ml-auto">{overridden ? <Badge variant="outline">已自定义</Badge> : <Badge variant="outline" className="text-muted-foreground">占位符自动</Badge>}</span>
                      </div>
                      <div className="flex flex-wrap gap-1.5">
                        {chips.map((c, idx) => {
                          const isNode = c.isNode
                          const autoNode = isNode && c.auto
                          return (
                            <span
                              key={`${g.name}-${idx}-${c.m}`}
                              draggable={isNode}
                              onDragStart={isNode ? () => { setDragId(c.m); setDragFrom(g.name) } : undefined}
                              onDragOver={(e) => e.preventDefault()}
                              onDrop={(e) => { e.stopPropagation(); onDropGroup(g.name, idx) }}
                              className={`inline-flex max-w-64 items-center gap-1.5 rounded-full border px-2.5 py-1 text-xs ${autoNode ? "cursor-grab border-dashed bg-muted/30 text-foreground/80" : isNode ? "cursor-grab bg-background" : "border-dashed bg-muted/40 text-muted-foreground"}`}
                              title={isNode ? nodeName(c.m as number) : specialTitle(c.m as string)}
                            >
                              {isNode && <span className={`inline-block size-1.5 shrink-0 rounded-full ${c.auto ? "bg-emerald-500/60" : "bg-emerald-500"}`} />}
                              <span className="max-w-40 truncate">{isNode ? nodeName(c.m as number) : specialLabel(c.m as string)}</span>
                              {isNode && !c.auto && (
                                <>
                                  <button className="text-muted-foreground hover:text-foreground" onClick={(e) => { e.stopPropagation(); moveIn(g.name, idx, -1) }}>↑</button>
                                  <button className="text-muted-foreground hover:text-foreground" onClick={(e) => { e.stopPropagation(); moveIn(g.name, idx, 1) }}>↓</button>
                                </>
                              )}
                              {isNode && c.auto ? (
                                <button
                                  className="text-muted-foreground hover:text-destructive"
                                  title="从该组移除（组转为显式成员）"
                                  onClick={(e) => { e.stopPropagation(); freezeWithout(g.name, c.m as number) }}
                                >
                                  ×
                                </button>
                              ) : (
                                <button className="text-muted-foreground hover:text-destructive" onClick={(e) => { e.stopPropagation(); removeFrom(g.name, idx) }}>×</button>
                              )}
                            </span>
                          )
                        })}
                        {chips.length === 0 && <span className="text-[11px] text-muted-foreground">空组（渲染时补 DIRECT）</span>}
                      </div>
                    </div>
                  )
                })}
              </div>
            </div>
          </>
        )}
        <DialogFooter className="sticky bottom-0 -mx-6 -mb-6 flex items-center justify-between gap-2 border-t bg-background px-6 py-3">
          <span className="text-xs text-muted-foreground">{dirty ? "有未保存的修改" : "全部修改已保存"}</span>
          <Button disabled={busy || loading} onClick={save}>保存分组</Button>
        </DialogFooter>
      </DialogContent>
    </Dialog>
  )
}

