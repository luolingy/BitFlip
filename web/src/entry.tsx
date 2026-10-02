// 构建期入口：只负责挂载 React 应用。
//
// 为什么单独一个文件：内嵌 SPA 的构建在受限沙箱里无法走 vite
// （vite 的配置加载会 execFile 子进程，沙箱拒绝 → spawn EPERM，
// 见 CLAUDE.md §6 trap 6）。因此用 rolldown 直接打包本文件，
// 而 rolldown 不再支持把 CSS 打进 JS bundle。
// 样式由 scripts/build-web.mjs 单独拷成 dist/assets/app.css，
// 并在 index.html 里用 <link> 引入 —— 结果与 vite 产物等价。
import { StrictMode } from "react";
import { createRoot } from "react-dom/client";

import { App } from "./App";

const container = document.getElementById("root");
if (!container) {
  throw new Error("找不到 #root 容器：index.html 与 SPA 入口不匹配");
}

createRoot(container).render(
  <StrictMode>
    <App />
  </StrictMode>,
);
