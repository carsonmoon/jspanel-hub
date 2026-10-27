import { useEffect, useState } from "react"
import QRCode from "qrcode"
import { toast } from "sonner"

import { Dialog, DialogContent, DialogHeader, DialogTitle } from "@/components/ui/dialog"

// what 拼在「已复制」之后，调用方传裸名词（如「分享链接」），勿自带前缀；展示具体值时以空格开头（` ${ip}`）。
export async function copy(text: string, what: string) {
  try {
    await navigator.clipboard.writeText(text)
    toast.success(`已复制${what}`)
  } catch {
    toast.error("复制失败，请手动复制")
  }
}

export function QrDialog({ url, name, kind, onOpenChange, extra }: { url: string; name: string; kind: "node" | "subscription"; onOpenChange: (v: boolean) => void; /** 可选扩展区（订阅页：地址栏+客户端格式+分发入口），出现在二维码下方。 */ extra?: React.ReactNode }) {
  const [dataUrl, setDataUrl] = useState("")
  useEffect(() => {
    QRCode.toDataURL(url, { width: 320, margin: 2 })
      .then(setDataUrl)
      .catch(() => toast.error("二维码生成失败"))
  }, [url])
  return (
    <Dialog open onOpenChange={onOpenChange}>
      <DialogContent className={extra ? "sm:max-w-lg" : "max-w-xs"}>
        <DialogHeader>
          <DialogTitle>{kind === "node" ? name : `${name} 的订阅`}</DialogTitle>
        </DialogHeader>
        {dataUrl ? (
          <button onClick={() => copy(url, kind === "node" ? "分享链接" : "订阅地址")} title={kind === "node" ? "点击复制分享链接" : "点击复制订阅地址"} className="mx-auto block">
            <img src={dataUrl} alt={`${kind === "node" ? "代理" : "订阅"}二维码`} className="rounded-md" />
          </button>
        ) : (
          <div className="flex h-64 items-center justify-center text-muted-foreground">生成中…</div>
        )}
        {extra}
      </DialogContent>
    </Dialog>
  )
}
