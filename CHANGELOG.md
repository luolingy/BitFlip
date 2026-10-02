# Changelog

本项目遵循 [Keep a Changelog](https://keepachangelog.com/zh-CN/1.1.0/)，
版本号遵循 [Semantic Versioning](https://semver.org/lang/zh-CN/)。

## [Unreleased]

### 新增 — M2：反汇编引擎

- **`bitflip-arch::backend`**：capstone 后端的真实接线。结构化提取
  流程语义（`groups` 里的 CALL/JUMP/RET/INT/PRIVILEGE 分组，而不是匹配
  助记符字符串）、读写的寄存器集合、操作数（x86 / AArch64 / ARM 分架构提取，
  RISC-V 与 MIPS 暂不提取细节）。没有后端支持的架构明确返回
  `DecodeError::Unsupported`，**不会**拿别的架构去解码。
- **`bitflip-arch::render`**：把结构化指令渲染成 Intel 语法的文本。
  文本是渲染层的产物，分析层只消费结构化字段。
- **`bitflip-analyze::addrspace`**：分页地址空间。按段或**节**建立
  （可重定位目标文件没有程序头，只有节表且节地址全是 0，只认段就完全
  无法反汇编），稀疏指令索引（`BTreeMap`），读取**不跨段**，
  `containing()` 把落在指令中间的地址吸附到包含它的那条。
- **`bitflip-analyze::scan`**：线性扫描与递归下降**双策略**，
  并分别记录覆盖来源（`ScanCoverage::reachable` / `linear_only`）。
  线性扫描按段并行（`rayon`），递归下降用显式栈而非递归调用。
- **`bitflip-core::Disasm`**：会话级反汇编视图，含分页
  （`InsnPage`，服务端游标）、统计（`DisasmStats`）与降级说明。
- **`/api/insns?from=&count=`**：列式分页接口。服务端把过大的 `count`
  收敛到上限（不信任客户端），非法地址返回 400 而不是悄悄从头开始。
- **反汇编 UI**：虚拟滚动列表（只挂载视口内的行），
  `j`/`k`/`g`/`G`/`Enter` 键盘导航，地址列可点击跟随控制流目标，
  机器码列，以及覆盖率统计条。

### 修复

- **大于嗅探窗口（8 MiB）的文件无法被解析，因此完全无法反汇编。**
  根因是把两件不同的事混成了一件：嗅探只读文件前缀（便宜，文件头都在前面），
  解析必须读整个文件。早先版本以"文件超过读取上限"为由直接拒绝解析，
  后果是任何大于 8 MiB 的目标都拿不到解析结果 —— 而 M2 自己的验收标准
  要求 100MB 级目标能扫描，也就是结构性地达不到。现在解析的上限由**内存**
  决定（`MAX_FULL_PARSE_BYTES = 512 MiB`）而不是由嗅探窗口决定，
  超过内存上限时才明确拒绝并说清原因。
- 稀疏索引在地址空间顶端因饱和加法而漏判覆盖（`InsnIndex::containing`）。
- 线性扫描在解码失败且不重新同步时会把同一次失败统计两遍。

### 性能（M2 验收标准 1，实测）

对自造的 100 MiB ELF（约 105 万条指令，用 `cargo test -p bitflip-core --release
-- --ignored bench_scan` 复现）：

| 指标 | 目标 | 实测 |
|------|------|------|
| 首次扫描耗时 | < 15s | **6.5s** |
| 稀疏索引占用 | < 3× 文件大小 | **0.32×**（33.6 MB） |
| 已索引指令 | — | 1,050,496 |
| 解码失败 | — | 0 |

并用另一条测试钉住"同一输入两次扫描结果完全一致"（确定性是正确性前提，
不是性能指标）。
### 变更

- `AppState` 新增 `with_session()`：整个 `Session` 交给服务层，
  反汇编需要原始字节，而 `ObjectInfo` 是已拍扁的 wire 投影。
- 导航项分真实可用（M1/M2）与未落地（置灰 + 标注里程碑）两类，
  未落地的项不可点击。

### 已知限制

- 反汇编**只覆盖已索引的指令**：间接跳转/调用的目标是运行期才确定的，
  静态分析不跟随，因此跳转表的目标不会出现在结果里（M3 的 CFG 阶段处理）。
- 条件跳转的判定是**保守启发式**（capstone 的 x86 后端不直接暴露条件位），
  宁可多给一个后继也不漏掉一个块。M3 会用真正的条件位替换。
- RISC-V / MIPS 的操作数细节暂不提取：流程语义正确，但操作数为空。
- 归档成员（`.a` / `.lib`）的逐成员反汇编排期 M5。

### 计划中
- M3：CFG 重建、函数边界、交叉引用
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
