// RX-78 协议彩虹编码——每协议固定色相的 chip。
// 色值定义在 index.css 的 .pt-* 类（v3 预览审定的 oklch 值，明暗各一套），
// 这里只负责协议名 → 类名的映射；未收录的协议回落中性描边（pt-unknown）。
const CHIP_BY_PROTOCOL: Record<string, string> = {
  vless: "pt-vless",
  "vless-reality": "pt-vless",
  vmess: "pt-vmess",
  trojan: "pt-trojan",
  ss: "pt-ss",
  shadowsocks: "pt-ss",
  hysteria2: "pt-hy2",
  hysteria: "pt-hy2",
  tuic: "pt-tuic",
  anytls: "pt-anytls",
}

export function protocolChipClass(protocol: string): string {
  return `pt ${CHIP_BY_PROTOCOL[protocol] ?? "pt-unknown"}`
}
