# Changelog

本项目遵循 [Keep a Changelog](https://keepachangelog.com/zh-CN/1.1.0/)，
版本号遵循 [Semantic Versioning](https://semver.org/lang/zh-CN/)。

## [Unreleased]

### 计划中
- M1：PE / ELF 完整解析（段、节、导入、导出、入口、重定位、unwind 表）
- M2：地址空间 + capstone 解码 + 反汇编列表 UI

## [0.0.1-m0] - 2026-10-02

M0 的目标是"骨架跑通、边界定死、不假装能干还没做的事"。凡是尚未实现的入口，
界面上置灰并标注里程碑，API 返回明确的"尚未实现"，而不是空结果集。

### 新增

- **Cargo workspace（9 个 crate）**，依赖方向单向
  `cli/app → server → core → {loader, arch, analyze, symbols, project}`：
  `bitflip-arch`、`bitflip-loader`、`bitflip-analyze`、`bitflip-symbols`、
  `bitflip-project`、`bitflip-core`、`bitflip-server`、`bitflip-cli`、`bitflip-app`。
- **`bitflip-arch`**：架构/模式/端序模型（x86、x86_64、aarch64、arm、riscv32/64、
  mips/mips64、wasm32），ELF `e_machine`、PE `Machine`、Mach-O `cputype` 三张映射表；
  结构化指令模型 `DecodedInsn`（流程、条件、读写寄存器、内存操作数）与 `RegSet` 位集；
  `Decoder` trait 与 `decoder_for`（M2 前返回 `UnsupportedDecoder`，不谎报能力）。
- **`bitflip-loader` 嗅探**：ELF（含 extended shnum 的识别）、PE（MZ/PE 签名、可选头
  PE32/PE32+、入口 RVA + 镜像基址、DLL 标志、CLI header 检出 .NET）、COFF 目标文件、
  ar 归档（GNU `/`、`//` 长名表、`/N` 偏移引用、BSD `#1/len` 内联名、MSVC NUL 长名表，
  并据此区分 `ar` 与 `msvc-lib`）、Mach-O 与 fat 容器（仅识别，解析排期 M10）。
  只读前 8 MiB（`SNIFF_WINDOW`），超限时在结论里显式说明。
- **`bitflip-analyze`**：作业边界 `JobHandle`、协作式取消 `CancelToken`、
  进度事件 `JobEvent`、阶段划分 S1–S9；`run_guarded` 用 `catch_unwind` 把分析器
  panic 转成错误（崩溃不得带走进程），并有单元测试验证。
- **`bitflip-symbols`**：9 级符号来源优先级（用户 > 签名库 > 调试信息 > 导出 >
  符号表 > unwind > 导入桩 > 分析推断 > 启发式）与候选合并（保留全部候选，
  只选一个用于展示）。
- **`bitflip-project`**：工程库契约 —— 用户标注是主数据、分析结果是可重建派生物；
  目标身份用内容哈希而不是 size+mtime；`SCHEMA_VERSION` 与"拒绝以旧读新"的兼容性判定。
- **`bitflip-core`**：唯一对外稳定 API。`Session::open/target_info`、`TargetInfo`
  wire DTO（地址统一定长 16 位小写十六进制）、统一错误 `BitflipError`、
  `CORE_API_VERSION`；不依赖 axum/tokio/rust-embed。
- **`bitflip-server`**：axum 本地服务 —— 只绑回环、32 字节随机令牌
  （`X-BitFlip-Token` 头或 `?token=`）、Origin 白名单（令牌与 Origin 两道门同时生效）、
  端口占用自动顺延、优雅退出、`GET /api/health` 与 `GET /api/target`、
  rust-embed 内嵌 SPA 与前端路由回退。
- **前端 SPA**：TypeScript + React + Vite，中文三栏界面（导航 / 反汇编 / 目标信息），
  深色主题；令牌从 URL 片段读取后立刻从地址栏擦掉；未实现的区块置灰并标注里程碑。
  未构建前端时服务返回一份说明如何构建的占位页（而不是空白页或 404）。
- **CLI**：`bitflip <target>`（起服务 + 开浏览器，`--port`/`--host`/`--token`/
  `--no-open`/`--allow-origin`/`--info-only`）与无头 `bitflip-cli info|serve|version`。
- **开发基础设施**：
  - `scripts/crates-proxy.mjs` + `scripts/cargo.ps1`：绕开本机 Schannel 无法出网的问题，
    `CARGO_HOME` 也落在仓库内（详见 `docs/DECISIONS.md` ADR-0008/0009）；
  - `scripts/gen-fixtures.ps1`：用 clang 交叉编译 / mingw / MSVC / llvm-ar /
    llvm-lib 生成 21 个样本（PE、COFF、ELF 六种架构、静态库、raw、截断、超窗口），
    **样本不入库**，缺失的工具链会逐条报告而不是静默跳过；
  - `scripts/preflight.ps1`：一条命令跑完 `temp/` 守卫 + fmt + clippy + test +
    前端类型检查 + 回环绑定校验；
  - `scripts/smoke-server.mjs`、`scripts/smoke-port-fallback.ps1`、
    `scripts/smoke-bind.ps1`：三个端到端冒烟测试（令牌/Origin、端口回退与令牌隔离、
    **只绑回环地址对着真实监听套接字验证**）；
  - `.github/workflows/ci.yml`：fmt/clippy/test 门禁 + 构建 SPA 后的服务冒烟测试
    （含 403 用例、只绑回环校验、`bitflip <target>` 用户入口可起服务）。
- **许可证**：MIT OR Apache-2.0 双许可（ADR-0007）。
- **文档**：`docs/DECISIONS.md` 增补 ADR-0007（许可证）、ADR-0008（本地 crates 代理）、
  ADR-0009（npm 缓存重定向）；D6 决策门关闭。

### 已知限制

- 解码、函数识别、交叉引用、注释持久化尚未接入（M2 起）；相关 UI 入口置灰并标注里程碑。
- Mach-O / `.app` bundle / fat 容器只识别不解析（M10）。
- 本机 `.githooks/pre-commit` 在受限沙箱里无法启动（git 通过 `sh.exe` 跑钩子被拒），
  因此它是第二道防线；每次提交仍必须手工执行 `git diff --cached --name-only | Select-String '^temp/'`。
- `scripts/*.ps1` 必须保持 ASCII：Windows PowerShell 5.1 会把无 BOM 的非 ASCII 脚本
  按 ANSI 读取，导致解析失败（已在 `scripts/cargo.ps1` 顶部注明）。
- Windows PowerShell 5.1 的 `param()` 只能声明一个参数：声明第二个（哪怕未使用）会让
  `ValueFromRemainingArguments` 错位（`test --workspace` 变成 `--workspace '' test`）。
