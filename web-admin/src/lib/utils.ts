import { clsx, type ClassValue } from "clsx"
import { toast } from "sonner"
import { twMerge } from "tailwind-merge"

export function cn(...inputs: ClassValue[]) {
  return twMerge(clsx(inputs))
}

/**
 * 写剪贴板原语，返回是否成功。navigator.clipboard 只在安全上下文存在；纯
 * http 页面里退回 execCommand——一次点击事件中剪贴板仍可由其 copy 事件填充。
 * UI 反馈（toast/prompt）由调用方决定；全仓唯一剪贴板实现（候选 8 收敛，
 * 之前 QrDialog 版无 http 回退、Admin/UserPage 各有一份私有拷贝）。
 */
export async function copyToClipboard(text: string): Promise<boolean> {
  if (navigator.clipboard) {
    try {
      await navigator.clipboard.writeText(text)
      return true
    } catch {
      // clipboard 被拒（老内核/App 内置 webview 常见）落回 execCommand。
    }
  }
  try {
    const put = (e: ClipboardEvent) => {
      e.clipboardData?.setData("text/plain", text)
      e.preventDefault()
    }
    document.addEventListener("copy", put)
    const ok = document.execCommand("copy")
    document.removeEventListener("copy", put)
    return ok
  } catch {
    return false
  }
}

/** 写剪贴板并提示。done 是成功 toast 全句。 */
export async function copyText(text: string, done = "已复制") {
  const ok = await copyToClipboard(text)
  if (ok) toast.success(done)
  else toast.error("复制失败")
}
