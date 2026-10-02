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

```
cargo fmt --all -- --check
cargo clippy --all-targets -- -D warnings
cargo test --workspace
cargo bench --no-run          # 基准能编译
cd web && npm run typecheck   # SPA 起用后
```
