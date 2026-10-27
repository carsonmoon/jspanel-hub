import { defineConfig } from "vite"
import react from "@vitejs/plugin-react"
import tailwindcss from "@tailwindcss/vite"

export default defineConfig({
  // Served under /admin/ so its hashed assets cannot collide with a theme's.
  base: "/admin/",
  plugins: [react(), tailwindcss()],
  // import.meta.dirname rather than new URL(...).pathname: the latter is
  // URL-encoded, so a checkout under a path containing a space or a non-ASCII
  // name resolves to %20 and the alias silently points nowhere.
  resolve: { alias: { "@": import.meta.dirname + "/src" } },
  build: {
    chunkSizeWarningLimit: 900,
    // 用户中心页（/u/{token}）是独立入口，与面板共用同一批 chunk。
    rollupOptions: { input: { main: "index.html", user: "user.html" } },
  },
  server: { proxy: { "/api": { target: "http://127.0.0.1:9911", ws: true } } },
})
