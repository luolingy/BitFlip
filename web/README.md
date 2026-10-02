# BitFlip Web 界面

React + TypeScript + Vite。构建产物进 `web/dist/`，由 `rust-embed` 编进 `bitflip` 二进制，
**运行期不需要 Node**（见 `docs/DECISIONS.md` ADR-0001）。

## 构建

```powershell
cd web
npm install --cache .npm-cache
npm run build          # typecheck + vite build -> web/dist
cd ..
cargo build -p bitflip-app     # 重新编译以把 dist 内嵌进去
```

`--cache .npm-cache` 不是可选项：本机 C: 盘只剩几 GB，npm 必须把缓存写在仓库内
（见 `CLAUDE.md` §3）。仓库里保留了 `web/dist/.gitkeep`，所以**没构建过前端也能编译 Rust**，
此时服务会返回一份说明页而不是空白页（`crates/bitflip-server/src/fallback.html`）。

## 开发模式

```powershell
# 终端 1：起服务（不自动开浏览器），目标随便给一个
cargo run -p bitflip-cli -- serve tests/fixtures/generated/sample-x86_64.exe --no-open

# 终端 2：Vite 开发服务器，/api 已代理到 127.0.0.1:8790
cd web
npm run dev            # http://127.0.0.1:5173
```

令牌：开发模式下从终端打印的 URL 里取 `#token=…` 片段，拼到 `http://127.0.0.1:5173/#token=…`。
`resolveToken()` 会把它存进 `sessionStorage` 并立刻从地址栏擦掉。

若服务端因 Origin 校验拒绝（浏览器对同源 GET 一般不发送 `Origin`，代理场景通常不会触发）：

```powershell
cargo run -p bitflip-cli -- serve <目标> --allow-origin http://127.0.0.1:5173
```

## 目录

```
web/
  index.html           SPA 入口（Vite 模板）
  vite.config.ts       构建与 dev 代理配置
  tsconfig.json        严格模式：strict + exactOptionalPropertyTypes + noUncheckedIndexedAccess
  src/
    api.ts             与本地服务通信：令牌解析、接口类型、错误映射
    App.tsx            三栏界面（导航 / 反汇编 / 目标信息）
    styles.css         深色主题（与 Rust 侧占位页同一套配色）
    main.tsx           挂载
  dist/                构建产物（不入库，仅保留 .gitkeep）
```

## 约定

- **不造假入口。** 未实现的区块在界面上明确标注里程碑并置灰，而不是给一个点了没反应的按钮。
- **接口类型与 Rust 侧对齐。** `src/api.ts` 里的 `TargetInfo` / `HealthResponse` 与
  `bitflip-core::TargetInfo`、`bitflip-server` 的 `/api/health` 一一对应；
  改 Rust 侧 DTO 就要同步改这里（`crates/bitflip-server/tests/http.rs` 是权威契约测试）。
- **地址格式。** 跨进程一律定长小写 16 位十六进制，前端只做展示，不自己发明格式。
- 界面文案中文，标识符与注释保持英文（`CLAUDE.md` §1）。
