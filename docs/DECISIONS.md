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

### ADR-0010 · SPA 构建提供不依赖子进程的备用路径

**状态**：已决（M1 期间的环境适配）
**决策**：SPA 有两条等价构建路径，产物一致：

1. `cd web && npm run build`（vite）—— 普通开发机与 CI 使用；
2. `node scripts/build-web.mjs`（rolldown 直出 + 单独复制 CSS）—— 受限沙箱使用，
   脚本内自校验产物大小并确认 React 运行时确实被打进去。

**背景**：M1 需要在浏览器里验证段/节结构视图，而在本机沙箱下 `vite build` 必然失败：

```
spawn EPERM
  at optimizeSafeRealPathSync (vite/dist/node/chunks/node.js)
```

vite 在加载配置时会 `execFile` 解析真实路径，而沙箱禁止 Node 创建子进程
（CLAUDE.md §6 trap 6）。这不是项目缺陷 —— 在普通终端里 `npm run build` 正常。

**理由**
- 段/节视图是 M1 的验收项，不能因为"本机构建不出来"就不验证。
- 备用路径只依赖已安装的 `rolldown`（vite 8 的底层打包器），不引入新依赖、不下载任何东西。
- 产物与 vite 版本**同源同依赖**：同一份 `src/`，只是少了文件名哈希。

**代价与限制**
- 产物文件名不含内容哈希，因此不能依赖长缓存；对内嵌进二进制的场景无影响。
- 样式必须由脚本单独复制（rolldown 已不再支持把 CSS 打进 JS bundle），
  故入口拆成 `src/entry.tsx`（无 CSS import）与 `src/main.tsx`（vite 用的带 CSS 入口）。
- `web/index.html` 入库并被脚本读取，保证标题/lang/meta 只有一处定义；
  资源引用固定为 `/assets/app.js` 与 `/assets/app.css`，脚本会校验这一点。
- **两条路径都必须保持可用**：改前端构建相关配置时要同时验证。

## 待决（决策门）

| ID | 决策 | 期限 | 候选与倾向 |
|----|------|------|-----------|
| D1 | 脚本层引擎 | M6 末 | rquickjs（JS 生态、C 依赖编译）/ mlua（易嵌入、Lua 生态弱）/ wasmtime（隔离最好、API 笨重）。倾向：先 rquickjs，若构建负担过重退 mlua |
| ~~D2~~ | ~~工程库存储~~ | — | **已决：见 ADR-0012（主数据 SQLite + 派生物独立文件，分层）** |
| ~~D3~~ | ~~解码后端~~ | — | **已决：见 ADR-0011（capstone 单后端，接口保持后端抽象）** |

### ADR-0012 · D2 已决：主数据进 SQLite，派生物走独立文件

**状态**：已决（M4 前的阻塞决策门；完整分析见 [`docs/D2-STORAGE-ANALYSIS.md`](./D2-STORAGE-ANALYSIS.md)）

**决策**：工程库按**数据性质**分层，而不是按存储技术偏好二选一。

- **主数据**（用户的名字/注释/类型/书签/补丁/函数边界/代码数据标记）→ **SQLite**
  （`rusqlite`，`bundled` 静态链接），库文件即 `.bfp`。
- **派生物**（反汇编、函数、交叉引用、字符串表、CFG）→ **独立文件** `<target-hash>.bda`，
  自研紧凑格式，写临时文件 + **原子 rename** 发布。整体可删、可无条件重建。
- `bitflip-project` 的公开 API **不暴露 `rusqlite` 类型**：`bitflip-core` 是对外稳定契约，
  嵌入方不该被迫依赖 SQLite。

**理由（三条，按重要性排序）**

1. **两类数据的写入模式相反。** 主数据是"小而频繁的随机写"，派生物是"大而一次性的批量写"。
   任何单一方案都会在一边吃亏：纯 SQLite 让几十万条派生物走 INSERT（慢 + 库膨胀），
   纯自研日志让"按地址查注释"这类高频查询要自己维护二级索引。
2. **同库会把"可以失败"和"绝不能失败"绑在一根绳上。** 派生物写入是可以失败的
   （磁盘满、分析取消），用户注释绝不能失败。更重要的是，重新分析要"先删旧派生物再写新的"——
   同库的大事务一旦中断崩溃，用户会看到**半新半旧的分析结果，而它看起来和完整的没区别**。
   这正是 CLAUDE.md §7 明令禁止的"让界面看起来完整"。分开存则由 rename 的原子性天然保证
   派生物**要么全新、要么全旧**。
3. **`bitflip-project` 已把这条分界写成契约**（"主数据 vs 可再生派生物"），
   D2 只是在落实它，不是在推翻已有设计。

**明确否掉的原倾向**：D2 表格原倾向是"先用 SQLite 把功能做对，M6 后按基准决定是否引入自研日志层"。
**这个倾向在 M4 的语境下是错的** —— 它假设"以后换存储是局部的事"，但 M4 之后派生物的表结构
与读写路径会全面依赖 SQL，而用户已经建了工程库、存了注释。**迁移一个装着用户主数据的库，
比一开始就分开贵得多。** 现在分开的成本只是"两个文件、两个写入路径"，这是便宜的。

**明确不做的事**：不引入 ORM；不做"存储后端抽象层"。目前只有一个后端，
抽象层是纯粹投机成本；等真有第二个后端（如只读导出快照）再抽，那时形态会清楚得多。

**代价**

- 两套写入路径要各自维护与各自测试（但简化版的单一路径代价更大，见 §3.2）。
- `rusqlite` 的 `bundled` 特性要编 C，会拉长冷启动构建（本机 capstone vendored 编译已需 7m38s）。
- 派生物格式的版本演进要自己保证（用 `format_version` + 交叉校验 `target_sha256` 兜住）。

**重新评估的触发条件**（任一满足即重开 D2）

1. 基准显示注解落库 P95 **持续 > 50ms**（即 SQLite 确实撑不住）；
2. 派生物在 M5/M8 演化出**按范围频繁查询**的需求，而 mmap + 二分不够用；
3. 用户提出**多目标联合检索**（"在所有打开的工程里找这个字符串"）——
   那需要真正的数据库，而不是每目标一个文件。
| D4 | PDB/DWARF 范围 | M8 前 | 先函数名 + 行号；类型系统后置 |
| D5 | 反编译器 | M10 评审 | 默认不做 |
| ~~D6~~ | ~~许可证~~ | — | **已决：见 ADR-0007（MIT OR Apache-2.0 双许可）** |

### ADR-0011 · D3 已决：M2 只包 capstone 单后端，接口保持后端抽象

**状态**：已决（M2 末的决策门，依据 M2 的实际使用证据）

**决策**：M2 的 `Decoder` 只实现 capstone 一个后端。**不**在 M2 引入 iced-x86。
`Decoder` trait 保持后端无关（`decode_one` 返回结构化的 `DecodedInsn`，
不暴露任何 capstone 类型），因此将来加后端是纯增量工作。

**依据（M2 实测，不是预设）**

- capstone 的单后端已经覆盖了 M2 的全部需求：x86 / x86-64 / AArch64 / ARM /
  RISC-V / MIPS 的真实解码、`detail(true)` 下的读写寄存器集合与内存操作数、
  以及 CALL/JUMP/RET/INT/PRIVILEGE 的**语义分组**。流程判断走分组而不是
  匹配助记符字符串，这条在实现中被证明是可靠的。
- 引入 iced-x86 的收益（x86 文本格式更贴近微软习惯、单条指令属性更细）
  在当前阶段**还换不来代价**：它是第二个 vendored C 依赖之外的纯 Rust 依赖，
  但真正的问题是**双后端会让"指令长度"出现两个真相来源**。指令长度决定
  稀疏索引的键，两个后端在少数前缀组合上给出不同长度，会让索引出现
  不可复现的漂移 —— 这是本项目最不能接受的一类 bug（CLAUDE.md §7）。
- 分支目标语义已用测试固化：capstone 给的是**已解析的绝对目标地址**
  （`backend::relative_targets_are_resolved_to_absolute`）。将来换后端时，
  这条测试会立刻失败并提醒适配层做转换 —— 这正是"保持后端抽象"的具体价值。

**代价与触发条件**

- 代价：x86 的文本渲染目前用 capstone 的 Intel 语法，个别助记符的写法与
  MSVC 习惯略有差异（例如内存操作数里的 `+` 被省略成 `[rcx rdx]`）。
  这影响的是**可读性**，不影响结构化字段。
- 重新评估的触发条件（任一满足即重开 D3）：
  1. M6 的交叉引用阶段需要比 capstone 更细的 x86 语义（如显式标志位读写）；
  2. 用户反馈明确指出 x86 文本格式妨碍阅读；
  3. 遇到 capstone 无法正确解码、而 iced-x86 可以的真实样本。

