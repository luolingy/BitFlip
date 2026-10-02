# Changelog

本项目遵循 [Keep a Changelog](https://keepachangelog.com/zh-CN/1.1.0/)，
版本号遵循 [Semantic Versioning](https://semver.org/lang/zh-CN/)。

## [Unreleased]

### 新增 — M1：格式解析（ELF / PE / COFF）

- **`bitflip-loader::reader`**：全部字节读取的唯一入口。所有解析器必须经过
  `Reader`，越界一律返回 `ParseError` 而不是 panic 或静默截断；
  表项遍历 `for_each_entry` 先按 `checked_mul` 校验整张表的范围再逐项读取，
  并对不可信数量封顶 —— 输入决定不了内存布局。
- **`bitflip-loader::object`**：容器→对象→段/节/符号的统一模型
  （`Object` / `Segment` / `Section` / `Import` / `Export` / `RawSymbol` /
  `Reloc` / `UnwindEntry` / `FormatInfo`）。段是内存视角、节是文件视角，两者都保留。
- **`bitflip-loader::elf`**：ELF32/ELF64 完整解析 —— 节表与程序头表、
  extended `shnum`/`shstrndx`、`ImageBase` 推导、入口点、`.symtab`/`.dynsym`、
  重定位（x86_64 / i386 / aarch64 / arm / riscv / mips）、`DT_NEEDED` 依赖、
  节对齐与 `p_paddr ≠ p_vaddr` 等结构异常检测。
- **`bitflip-loader::pe`**：PE32/PE32+ 完整解析 —— DOS/NT 头、节表、
  数据目录、`ImageBase`、入口 RVA、导入表（含按序号导入与延迟导入）、
  导出表（含转发导出）、基址重定位、`.pdata` RUNTIME_FUNCTION、`.NET` CLI 头检出。
- **`bitflip-loader::coff`**：`.obj` 解析 —— 节表（含 `/NNN` 长节名）、
  COFF 符号表（含辅助记录跳过）、重定位（按机器类型区分编号含义）。
- **`bitflip-core`**：`Session::open` 现在做一次完整解析，并把结果作为
  `ObjectInfo` 暴露给上层。解析失败**不会**导致打开失败：识别结论仍然可用，
  失败原因写进 `notes`，`parsed()` 返回 `None`。
- **稳定 JSON schema**：`TargetInfo` 与 `/api/*` 响应都带 `format_version`
  （当前 `1`），地址一律定长 16 位小写十六进制。
- **`bitflip info <目标> --json`**：输出 `{format_version, target, parsed}`；
  人类可读模式打印段表、节表、各表计数、依赖模块与导出清单。
- **`/api/sections`**：段/节结构视图的数据源；一次返回识别结论 + 解析结果。
- **段/节 UI**：段（内存视角）与节（文件视角）分页签呈现，
  显示虚拟地址、文件偏移、大小、权限、内容类别、是否映射，
  并高亮入口点所在的节。解析失败时明确显示"未能得到结构结果"+原因。

### 新增 — 解析鲁棒性

- **结构化模糊测试**（`bitflip-loader::fuzz`）：确定性 xorshift 变异器 +
  8 类变异算子（位翻转、极值字节、虚报长度、越界偏移、截断、复制、表长虚报），
  偏向头部以命中有意义的字段。断言只有一条：畸形输入下**不 panic、不 OOM**。
  自带"模糊测试确实在跑"的自检（统计接受/拒绝样本数）。
- **跨实现对照校验**（`scripts/verify-elf.ps1`）：把解析结果与
  `llvm-readobj` 的节名集合、节数量、入口点逐项比对。
  当前 9 个真实样本（x86_64 / i386 / aarch64 / armv7 / riscv64 / mips32 的
  `.o`、`.exe`、`.so`）**全部一致**。

### 已知限制

- 归档（`.a` / `.lib`）的**成员级**解析排期 M5；当前对归档只解析容器结构。
- `.eh_frame` 的 CFI/FDE 展开排期 M3（已检出存在并给出说明）。
- Mach-O 解析排期 M10（当前只做识别）。
- PE 的延迟导入目前只列出模块名，符号级解析排期待补。
- `.NET` 托管程序集只做识别，不反编译 CIL。

### 计划中
- M2：地址空间 + capstone 解码 + 反汇编列表 UI

### 备注

- `scripts/build-web.mjs` 提供一条不依赖子进程的 SPA 构建路径（rolldown 直出）。
  受限沙箱里 Node 的 `child_process` 一律 EPERM，`vite build` 在加载配置时会
  `execFile` 因而必然失败（CLAUDE.md §6 trap 6）；普通终端下 `npm run build`
  仍然可用。

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
