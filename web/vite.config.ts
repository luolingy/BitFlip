import { defineConfig } from "vite";
import react from "@vitejs/plugin-react";

// 生产构建：产物进 web/dist，由 rust-embed 编进 bitflip 二进制。
// 不做代码分割：界面是本地单页应用，几十 KB 的资源不值得多几个请求。
export default defineConfig({
  plugins: [react()],
  build: {
    outDir: "dist",
    emptyOutDir: true,
    sourcemap: false,
    target: "es2022",
  },
  server: {
    host: "127.0.0.1",
    port: 5173,
    strictPort: true,
    // 开发时把 /api 代理到本地 bitflip 服务，避免 CORS 与双端口令牌传递。
    // 服务端仍会做 Origin 校验：若被拒，用 `bitflip serve <target> --allow-origin http://127.0.0.1:5173`。
    proxy: {
      "/api": {
        target: "http://127.0.0.1:8790",
        changeOrigin: false,
      },
    },
  },
});
