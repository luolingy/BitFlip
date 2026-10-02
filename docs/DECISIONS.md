# 决策记录（ADR）

> 只记录**已决**与**待决**的架构决策。已决项如需推翻，追加新条目而不是改写旧条目。

## 已决

### ADR-0001 · 技术栈：Rust 全栈 + 内嵌 Web SPA

**状态**：已决（用户确认）
**决策**：分析核心、服务、CLI 全部 Rust；UI 是 TypeScript + React + Vite 的 SPA，
用 `rust-embed` 编进二进制；`bitflip <target>` 起本地 HTTP 服务并打开系统浏览器。

**理由**
- 跨平台交付只需要"为每个平台构建一个 Rust 二进制"，不需要原生 GUI 外壳（用户明确要求 UI 走本地网页服务）。
- 运行期零依赖：不需要 Node、不需要附带 DLL/SO 集合。
- 反汇编/分析是 CPU 与内存密集型，Rust 是唯一能同时满足性能与安全的选择。

**代价**
- 构建期依赖 npm 构建 SPA（CI 里 `npm ci && npm run build`）。
- 浏览器是唯一 UI 载体：布局/渲染能力受 Web 限制，超大数据渲染需要虚拟滚动与游标分页（已纳入设计）。

**被否方案**
- `Rust napi 插件 + Node/Hono 服务`（adi 路线）：可复用 adi 的 TS 代码，但分发依赖 Node 打包
  （adi 的 `build-bundle.mjs` 需要给 pkg 打补丁、内联 yoga.wasm），脆弱且继承 adi 的内存/性能短板。
- `纯 Rust + 服务端直出 HTML`：依赖最少，但大型反汇编列表与 CFG 图视图实现代价过高。

### ADR-0002 · 仓库形态：独立仓库，`bitflip-core` 可嵌入

**状态**：已决（用户确认）
**决策**：BitFlip 是独立 git 仓库；`crates/bitflip-core` 是对外稳定 API，
可被其他项目通过 git submodule / path / crate 依赖嵌入；服务层与 UI 是它的消费者之一。

**理由**：用户要求"作为子模块"；同时避免"能嵌入"沦为口号 —— 只要 API 稳定、分层单向，嵌入成本自然低。

**约束**
- `bitflip-core` 不依赖 `axum`/`tokio`/`rust-embed`，也不暴露 SPA 类型。
- 公开 API 的破坏性变更需要 CHANGELOG + 版本号提升。
- 参考实现 `temp/adi` 的风格：它的 CLI/核心分层是清晰的，可作为 API 分层惯例的参照。

### ADR-0003 · 格式优先级：除 Apple 可执行文件外全覆盖，Mach-O 推迟到 M10

**状态**：已决（用户确认）
**决策**：M1–M9 支持 PE（exe/dll/sys/obj/lib）、ELF（exec/so/o）、ar 归档、raw 固件、COFF 对象；
Mach-O（含 `.app` bundle、dylib、fat/universal）列入 M10 TODO，不在主线里程碑验收范围内。

**理由**：用户明确"除了苹果的可执行文件，其他都要，苹果的文件写进未来 todo"；
同时本机无 macOS 环境，Mach-O 的验证成本高（只能做解析层验证，无法链接真实产物）。

**约束**：`Container`/`Object` 抽象预留 `Fat` 变体，但 M0–M9 不实现其解析，
避免为未实现的需求扭曲主设计（见 ARCHITECTURE §3）。

### ADR-0004 · 构建工具：npm（不用 pnpm）；构建目录固定在 F:

**状态**：已决
**决策**：SPA 用 `npm`；`cargo` 的 `target-dir` 固定为仓库内 `.cargo-target`（F: 盘）；
必要时 `CARGO_HOME` 也指向 F:。

**理由**
- 本机 `pnpm` 在沙箱环境下不可用（`spawn EPERM`），`npm 11.12.1` 可用。
- C: 盘仅剩约 2.8GB，Rust + capstone + axum 的构建产物以 GB 计，不能落在 C:。

### ADR-0005 · `temp/adi` 是只读参照，永不入库

**状态**：已决（用户明确要求，反复强调"记住"）
**决策**：`temp/` 被 `.gitignore` 忽略；`.githooks/pre-commit` 额外拒绝任何 `temp/` 下的暂存内容；
CLAUDE.md §0 写入硬约束。

**理由**：用户要求不要提交 `temp/` 的任何内容；单一来源的规则 + 自动化守卫比"记住"可靠。
**代价**：新克隆仓库需要执行一次 `git config core.hooksPath .githooks`（已写入 CLAUDE.md 与 README）。

### ADR-0006 · 不继承 adi 的四项设计

**状态**：已决
**决策**：明确不采用 adi 的（1）全量物化指令、（2）仅 `.text` 递归下降、
（3）size+mtime 有效性的只读 FlatBuffers 缓存、（4）同步阻塞无进度分析。

**理由**：这四项与"支持大二进制、覆盖率、可增量标注、UI 不假死"的目标直接冲突（详见 PLAN.md §2）。
FlatBuffers 降级为**导出格式**（供外部工具消费），不作为工程库。

### ADR-0007 · 许可证：MIT OR Apache-2.0 双许可

**状态**：已决（用户确认，对应决策门 D6）
**决策**：项目以 `MIT OR Apache-2.0` 双许可发布（`LICENSE-MIT`、`LICENSE-APACHE`，
`Cargo.toml` 的 `license` 字段为 `MIT OR Apache-2.0`）。

**理由**
- 双许可是 Rust 生态的事实标准（Rust 自身、tokio、axum、serde 均为双许可），
  使用方可以按需选择，兼容性摩擦最小。
- 与计划引入的依赖许可兼容：capstone（BSD-3-Clause）、goblin（MIT）、axum/tokio（MIT）、
  iced-x86（MIT）。Apache-2.0 的专利授权条款对企业使用方更友好。

**代价**：贡献者需要接受双许可（`CONTRIBUTING` 后续补充 DCO/CLA 说明，M1 前完成）。

### ADR-0008 · 开发环境网络：仓库内 crates.io 代理 + 仓库内 CARGO_HOME

**状态**：已决（M0 期间的环境适配）
**决策**：本机（受限沙箱）里 `curl`/`Invoke-WebRequest`/cargo 自带的 libcurl 走 Schannel 时
`AcquireCredentialsHandle` 失败（`SEC_E_NO_CREDENTIALS`），而 Node 的 TLS 正常。
因此提供两件事：

1. `scripts/crates-proxy.mjs`：Node 实现的 crates.io 稀疏索引 + 包体代理（默认 `127.0.0.1:8765`，
   磁盘缓存在 `.crates-proxy-cache/`）；
2. `scripts/cargo.ps1`：把 `CARGO_HOME` 指向仓库内 `.cargo-home/`，
   该目录的 `config.toml` 把 `crates-io` 替换为本地代理。

**理由**
- 这是**环境适配**，不是产品设计：BitFlip 本身对网络没有任何要求，CI 与普通开发机照常直连 crates.io。
- 必须落在仓库内有两个原因：沙箱只允许写工作区；C: 盘空间不足。

**代价与限制**
- 本机所有 cargo 命令必须经由 `scripts/cargo.ps1`（或自行设置 `CARGO_HOME`），否则会尝试写 `C:\Users\...\.cargo` 而失败。
- `.cargo-home/config.toml` 里的源替换必须**始终生效**：先用 `--offline` 拉到的包不会出现在
  `crates-io` 源下，混用会报 "no matching package named ... found"。
- `Cargo.lock` 入库，保证后续可离线、可复现构建。

### ADR-0009 · npm 缓存重定向到仓库内

**状态**：已决（M0 期间的环境适配）
**决策**：npm 安装在 `web/` 下执行，并显式带 `--cache .npm-cache`；
`web/.npmrc` 只固定 registry（`registry.npmmirror.com`），不写相对 cache 路径
（npm 对相对路径的解析基准不保证）。

**理由**：与 ADR-0004 同因 —— C: 盘空间不足且沙箱拒绝写 C:；`node_modules` 与 npm 缓存都在仓库内，随工作区一起清理。

## 待决（决策门）

| ID | 决策 | 期限 | 候选与倾向 |
|----|------|------|-----------|
| D1 | 脚本层引擎 | M6 末 | rquickjs（JS 生态、C 依赖编译）/ mlua（易嵌入、Lua 生态弱）/ wasmtime（隔离最好、API 笨重）。倾向：先 rquickjs，若构建负担过重退 mlua |
| D2 | 工程库存储 | **M4 前（阻塞）** | SQLite(rusqlite，成熟/事务/迁移好) vs 自研 append-only log + 索引快照（巨型文件 IO 更可控、无 SQL 依赖）。倾向：先用 SQLite 把功能做对，M6 后按基准决定是否引入自研日志层 |
| D3 | 解码后端 | M2 末 | capstone 单后端（简单、多架构）vs 加 iced-x86（x86 文本与属性精度更高）。倾向：M2 只包 capstone，接口留后端抽象 |
| D4 | PDB/DWARF 范围 | M8 前 | 先函数名 + 行号；类型系统后置 |
| D5 | 反编译器 | M10 评审 | 默认不做 |
| ~~D6~~ | ~~许可证~~ | — | **已决：见 ADR-0007（MIT OR Apache-2.0 双许可）** |

