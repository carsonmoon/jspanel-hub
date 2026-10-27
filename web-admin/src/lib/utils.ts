import { clsx, type ClassValue } from "clsx"
import { toast } from "sonner"
import { twMerge } from "tailwind-merge"

export function cn(...inputs: ClassValue[]) {
  return twMerge(clsx(inputs))
}

/**
 * 写剪贴板并提示。navigator.clipboard 只在安全上下文存在；纯 http 页面里退回
 * execCommand——一次点击事件中剪贴板仍可由其 copy 事件填充。
 */
export function copyText(text: string, done = "已复制") {
  if (!navigator.clipboard) {
    const put = (e: ClipboardEvent) => {
      e.clipboardData?.setData("text/plain", text)
      e.preventDefault()
    }
    document.addEventListener("copy", put)
    const ok = document.execCommand("copy")
    document.removeEventListener("copy", put)
    if (ok) toast.success(done)
    else toast.error("复制失败")
    return
  }
  navigator.clipboard.writeText(text).then(
    () => toast.success(done),
    () => toast.error("复制失败"),
  )
}
