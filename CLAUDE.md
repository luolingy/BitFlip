# BitFlip —— 项目规则

> 面向在本仓库工作的 AI 助手与协作者。规则优先于个人偏好。

## 0. 硬约束（不可协商）

1. **`temp/` 下的任何内容永不入库、永不修改。**
   `temp/adi` 是一个只读的参照项目（ELF 逆向 TUI/web 工具），仅用于借鉴设计。
    - `.gitignore` 已忽略 `temp/`；
    - `.githooks/pre-commit` 会拒绝任何 `temp/` 下的暂存内容与 >8MB 的文件；
    - 需要借鉴其代码时**读取**，不要 `git add`、不要原地重构、不要把它的文件复制进来后继续维护两份。
    - 新克隆仓库后执行一次：`git config core.hooksPath .githooks`
2. **不把二进制样本/构建产物入库。** 样本由 `tests/fixtures` 脚本生成（见 docs/PLAN.md §5.2）。
3. **磁盘预算。** 本机 C: 仅剩约 2.8GB，构建输出必须落在 F:（见 §3）。

## 1. 语言

- 面向用户的文档、提交信息、UI 文案：中文（技术术语保留英文原文）。
- 代码、标识符、注释里的术语：英文。
- 提交信息用祈使句、中文，首行 ≤ 72 字符；正文说明「为什么」而不是「改了什么」。

## 2. 技术栈（已定，见 docs/DECISIONS.md）

- Rust 全栈：分析核心 + axum 本地服务 + `rust-embed` 内嵌 SPA，单文件可执行，**运行期零 Node 依赖**。
- 前端 TypeScript + React + Vite，**构建期**用 `npm`（本机 `pnpm` 在沙箱下不可用，不要引入 pnpm）。
- 参照 `temp/adi` 的选型：`goblin`（格式解析）、`capstone`（解码）、FlatBuffers（只读导出快照）；
  但**不继承**它的同步阻塞分析、全量物化、只读缓存这三处设计（原因见 docs/PLAN.md §2）。

## 3. 环境与构建

- 目标平台：Windows 优先（开发机 Windows 10 x64），Linux 次之，macOS 推迟。
- 所有构建/缓存目录必须在 F: 盘：
  - `.cargo/config.toml` 里固定 `[build] target-dir = ".cargo-target"`；
  - 如 `C:\Users\...\.cargo` 空间吃紧，用 `CARGO_HOME` 指到 F:；
  - 不要把 `node_modules` 或 `target` 建到 C:。
- 可用工具链（已验证）：rustc/cargo 1.96、Node 24 + npm 11、LLVM clang + llvm-readobj、
  mingw gcc/ld/objdump、MSVC dumpbin、cmake 3.x、Python 3.12。
- **WSL 只做轻量验证**（用户硬盘紧张）：不要在 WSL 里装重型工具链或跑全量构建。
  ELF 目标优先用 Windows 侧 `clang --target=... -c` 生成 object；需要链接产物时手动、按需在 WSL 里做一次。

## 4. 工程约定

- 分层依赖方向单向：`cli/app → server → core → {loader, arch, analyze, symbols, project}`。
  下层不得依赖上层；`bitflip-core` 的公开 API 是对外契约，改动需要记入 CHANGELOG 并考虑兼容。
- 地址表示：**内部一律 `u64`**；跨进程 wire 上统一为定长小写 16 位十六进制（`0000000000401000`）；
  用户输入接受 `0x` 前缀与省略前缀。不要引入第二套地址字符串规范。
- 错误：库用 `thiserror` 定义错误枚举，二进制入口用 `anyhow`；作业/FFI 边界用 `catch_unwind` 兜住 panic，
  分析器崩溃必须转成错误而不是进程退出。
- 并发：分析热路径用 `rayon` 同步并行；服务层 `tokio` 只负责 IO 与作业调度；不把 async 传染进解码/分析核心。
- 跨进程/持久化数据都带显式版本号 + 迁移路径（工程库 `schema_version`、导出格式 `format_version`）。
- 数据结构优先列式（SoA）与 interned 字符串池；**禁止**把每条指令物化成带 `String` 字段的对象（adi 的 OOM 教训）。
- 新增能力必须带：单元测试 + fixture（若涉及格式）+ 黄金快照更新说明。

## 5. 提交前自检

一条命令跑完（推荐）：

```powershell
& .\scripts\preflight.ps1
```

等价的手工步骤：

```
cargo fmt --all -- --check
cargo clippy --all-targets -- -D warnings
cargo test --workspace
cargo bench --no-run          # 基准能编译
cd web && npm run typecheck   # SPA 起用后
```

**入库守卫（每次 commit 前必做）**：

```
git diff --cached --name-only | grep -i '^temp/' && echo "禁止提交 temp/" && exit 1
```

PowerShell 等价：

```powershell
git diff --cached --name-only | Select-String '^temp/' # 有输出即中止
```

> 已知限制：`.githooks/pre-commit` 在受限沙箱里无法启动（git 通过 `sh.exe` 跑钩子，
> 沙箱会拒绝其 `CreateFileMapping`，表现为 `sh.exe: fatal error`）。
> 因此钩子只是**第二道**防线，第一道是上面这条手动检查 —— 两者都不可省。

## 6. 本机脚本约定（踩过的坑，别重犯）

这些是 Windows PowerShell 5.1 + 受限沙箱下的硬性约束。改了脚本就必须重新验证，
不要凭"看起来对"就提交。

1. **`.ps1` 一律只写 ASCII。** PS 5.1 把无 BOM 的脚本按 ANSI 读取，中文注释/字符串会
   破坏解析（典型报错 `The string is missing the terminator`）。检查方法：
   `Get-Content x.ps1 -Raw | Select-String '[^\x00-\x7F]'`。
2. **`scripts/cargo.ps1` 不要加 `param()` 块**，用裸 `$args` 转发。两个已验证的坑：
   - 声明第二个参数（哪怕从未使用）会让 `ValueFromRemainingArguments` 错位：
     `test --workspace` 变成 `@('--workspace','','test')`；
   - 有 `param()` 就会启用 common parameters，PS 会把重复的短选项绑到自己的参数上：
     `build -p a -p b` 报 `parameter 'PipelineVariable' is specified more than once`
     （`-p` 是 `-PipelineVariable` 的前缀）。
   改动后必须手工验证四条命令：`build --workspace`、`test --workspace`、
   `clippy --all-targets -- -D warnings`、`build --release -p bitflip-app -p bitflip-cli`。
3. **不要用 `$ErrorActionPreference = 'Stop'`。** 原生命令（cargo、clang、gcc）把进度与
   警告写在 stderr，PS 5.1 会把每一行 stderr 变成终止性错误。用 `'Continue'` +
   检查 `$LASTEXITCODE`。
4. **原生命令的参数用引号数组。** `-Wl,-e,_start` 这类会被 PS 当参数解析器吃掉；
   写成 `@('-Wl,-e,_start')`。
5. **`Get-Content -Raw` 对空文件返回 `$null`**，`[regex]::Match($null, ...)` 会抛
   `ArgumentNullException`。先 `[string]` 转换。
6. **Node 子进程不可用。** 本沙箱里 Node 的 `child_process.spawn` 一律 `EPERM`，
   因此不能从 Node 拉起被测进程；需要"起服务再测"的脚本用 PowerShell 写
   （见 `scripts/smoke-port-fallback.ps1`），Node 脚本只做 HTTP 客户端
   （见 `scripts/smoke-server.mjs`）。
7. **cargo 必须走包装脚本。** 直接 `cargo` 会尝试写 `C:\Users\...\.cargo` 并失败；
   用 `& .\scripts\cargo.ps1 ...`（它设置仓库内的 `CARGO_HOME`）。
8. **npm 必须带 `--cache .npm-cache`**，否则写 C: 盘被拒（见 ADR-0009）。
9. **`try/finally` 里的清理会毁掉测试。** 冒烟测试的 `finally` 若用来杀进程，
   必须在所有断言**之后**执行，否则服务在断言前就死了，测试会对着死端口"通过"。

## 7. 分析准确性的底线

BitFlip 的立身之本是"说的就是真的"。下列做法一律禁止：

- **不用假名冒充识别结果。** 分析不出来的函数就叫"未识别"，不要生成 `func_xxx` 之类的
  占位名让界面看起来完整（这是参照实现的教训，见 `docs/PLAN.md` §2）。
- **拿不到就说拿不到。** 未知字段用 `None` / `null` + `notes` 里的原因说明，
  不要用 `0`、空串或默认值代替。
- **未实现的能力明确报错。** 返回 `BitFlipError::NotYetImplemented { feature }`（要写清
  计划里程碑），而不是返回空集合让 UI 显示"分析完成但什么都没有"。
- **降级要写在界面上。** 例如文件超过 8 MiB 嗅探窗口、归档成员被截断，
  都必须在结论里出现，不能悄悄少给数据。

