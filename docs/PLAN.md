# BitFlip（比特翻转）长期计划

> 版本 v1 · 状态：待评审 · 本文件是唯一的里程碑权威来源，改动需说明理由。

---

## 1. 定位与范围

### 1.1 一句话定位

本地优先、跨平台的**静态**二进制逆向分析平台：一个自包含可执行文件，`bitflip <target>`
在 `127.0.0.1` 起本地 HTTP 服务并打开浏览器 UI，提供 IDA 级别的反汇编、函数/交叉引用、
注释/类型标注与补丁写回能力。UI 走 Web 是为了跨平台交付，而不是为了"云化"。

### 1.2 交付形态（三件套，同一份核心）

| 形态 | 入口 | 用途 |
|------|------|------|
| GUI 应用 | `bitflip <target>` | 启动服务 + 打开浏览器，交互式逆向 |
| 无头 CLI | `bitflip-cli info/disasm/xref/symbols/export/patch` | 脚本化、批处理、CI 中的二进制体检 |
| 库 | `bitflip-core` crate | 被其他项目嵌入（git submodule / path / crate 依赖）—— 这是"作为子模块"的落点 |

### 1.3 支持矩阵

**容器与对象格式**（"除了 Apple 的可执行文件，其他都要"）：

| 类别 | 具体 | 里程碑 | 备注 |
|------|------|--------|------|
| PE32 / PE32+ | exe / dll / sys / ocx | M1, M3 | 段表、导出表、导入表(IAT/ILT)、基址重定位、`.pdata` RUNTIME_FUNCTION |
| COFF | `.obj`（MSVC/clang-cl） | M2 | 与 PE 共用对象层 |
| 静态库 | MLib `.lib`（含第二成员索引）、GNU/BSD `ar` `.a` | M5 | 成员枚举、符号索引、按成员独立分析 |
| ELF32/64 | ET_EXEC / ET_DYN(.so) / ET_REL(.o) | M1, M3 | `.symtab`/`.dynsym`、`PT_DYNAMIC`、PLT/GOT、`init_array`、`.eh_frame` |
| 归档 | ar 长名表 `//`、符号索引 `/` | M5 | 与 `.lib` 同一抽象 |
| Raw / 固件 | 任意二进制 + 手工基址/段定义 | M2 | 等价 IDA 的 "Binary file" 加载，实用且便宜 |
| .NET 程序集 | PE + CLI header | 仅识别（M3） | 识别并提示，不做 CIL 反编译 |
| Mach-O / `.app` / fat | — | **M10 TODO** | 按用户要求推迟；容器层预留 `Object` 抽象不为之变形 |

**架构**：

| 架构 | 里程碑 | 解码后端 |
|------|--------|----------|
| x86 64 / 32 / 16 | M2 / M5 | capstone（后期可选 iced-x86 提升 x86 质量，决策门 D3） |
| ARM64 (AArch64) | M5 | capstone |
| ARM / Thumb | M5 | capstone |
| RISC-V 32/64 | M6+ | capstone |
| MIPS | M6+ | capstone |
| wasm32 | M10 | 自研/第三方（非承诺） |

**多架构能力要求**：同一份分析流程不得出现 `if arch == x86` 分支散落各处——
架构差异必须收敛到 `bitflip-arch` 的 ABI/调用约定/解码描述表里（见 ARCHITECTURE §4）。

### 1.4 非目标（明确不做，避免范围失控）

- 动态调试器、仿真执行、符号执行（M10 之后另议，不进主线）。
- 恶意样本沙箱、云端分析服务、多用户协作后端。
- 原生 GUI 外壳（egui/Qt）——UI 只走本地 Web。
- 与 IDA/Ghidra 数据库格式的双向兼容（只做导出，不做格式互操作）。
- 反编译器（C 伪代码）——M10 决策门，**非承诺**。
- Java/`.NET` 字节码反编译。

---

## 2. 为什么不能直接改 `temp/adi`

`temp/adi` 是参照实现（只读，见 CLAUDE.md §0）。它证明了"Rust 核心 + Web UI"这条路走得通，
但它的四个设计决定与"IDA 级工具"的目标直接冲突：

| adi 现状 | 后果 | BitFlip 的做法 |
|----------|------|----------------|
| 只支持 64 位 x86_64 ELF | 无法处理 PE/静态库/ARM | 容器层与对象层分离，格式矩阵 §1.3 |
| 递归下降只覆盖 `.text`，不跟 PLT / 不跟数据引用 | 真实二进制大面积漏分析，误判为数据 | 全镜像扫描 + 多来源种子（unwind、导入表、引用、跳转表）§6.3 |
| 每条指令物化成带 `String` 的 JS 对象 | 100MB+ 二进制 OOM，上传被硬限 48MB | 分页地址空间 + 紧凑指令 + interned 字符串池 §6.1 |
| FlatBuffers 只读缓存，size+mtime 判有效，改名重写整个文件 | 无法增量、无法承载用户数据规模 | 可写工程库；用户数据是主数据，分析结果是可重建派生物 §6.6 |
| `analyze` 同步阻塞、无进度、不可取消 | 大文件界面假死 | 作业队列 + 进度事件 + 取消 §6.7 |
| 无脚本层 | 无法批量标注/自动化 | M7 脚本层（决策门 D1） |

可以继承的：`goblin` + `capstone` + FlatBuffers 的**选型**思路、列式传输（adi web 的 `a/b/m/o/f/t` 设计是对的）、
worker/进程隔离以避免崩主循环。

---

## 3. 架构总览

分层与依赖方向（详细设计见 [ARCHITECTURE.md](ARCHITECTURE.md)）：

```
bitflip-app / bitflip-cli          ← 进程入口，参数解析，生命周期
        │
   bitflip-server                  ← axum HTTP + WS + rust-embed 内嵌 SPA + token 鉴权
        │
   bitflip-core                    ← 对外稳定门面：open / analyze / query / annotate / patch / export
        │
   ┌────┴────┬──────────┬──────────┬──────────┐
loader     arch      analyze    symbols    project
格式解析   解码/ABI   分析流水线  符号来源    可写工程库
```

单向依赖，下层不得反向依赖上层。`bitflip-core` 的公开 API 是对外契约（供其他项目嵌入），
破坏性变更需要 CHANGELOG 记录与版本号提升。

---

## 4. 里程碑

每个里程碑的定义是"**可交付且可用**"：结束时必须有一个能在真实二进制上跑通的完整链路。
无固定日期，按门禁推进；每个 M 结束打 git tag。

### M0 · 地基（可运行的空壳）

**目标**：证明"单二进制 + 内嵌 Web UI"这条交付链路成立。

交付物：
- Cargo workspace（crates 清单见 §3）、`.cargo/config.toml`（`target-dir` 落在 F:）、
  `cargo fmt` / `clippy -D warnings` / `test` 基线、GitHub Actions 风格 CI 配置（Windows 优先）。
- 统一错误模型（`BitflipError`）、日志（`tracing`）、`catch_unwind` 作业边界。
- `bitflip-core` API 骨架 + `bitflip-server`（`/api/health`）+ 最小 SPA（Vite + React + 中文界面骨架）。
- `bitflip <target>` 启动 → 打印带 token 的本地 URL → 打开默认浏览器；只做端口占用回退与优雅退出。
- 许可证决定（ADR 待补）。

验收标准：
1. `cargo run -p bitflip-app -- tests/fixtures/generated/tiny.exe` 能起服务并打开页面；
2. 页面 `GET /api/health` 显示核心版本与构建信息；
3. 无 token / 错误 Origin 的请求被拒绝（403）；
4. `cargo clippy --all-targets -- -D warnings` 零告警。

风险：SPA 构建产物嵌入二进制（`rust-embed`）在 Windows 上的路径处理；端口与浏览器启动的跨平台差异。

### M1 · 容器/对象层 + 首个真实解析（PE + ELF）

**目标**：打开文件就能给出可信的镜像结构。

交付物：
- `bitflip-loader`：`Container → Object → Segment/Section/Symbol` 抽象；magic 嗅探与格式判定。
- PE32/PE32+ 解析：DOS/NT 头、节表、`ImageBase`、入口、导出表、导入表、重定位、`.pdata` 读取。
- ELF 解析：ELF32/64、段表/节表、`PT_LOAD`/`PT_DYNAMIC`、`.symtab`/`.dynsym`、入口。
- CLI `bitflip info <target>`（人类可读 + `--json`）。
- 段树 UI：段/节列表、标志、虚拟地址范围、入口点。

验收标准：
1. 对一组真实样本（mingw 构建的 exe/dll、MSVC 构建的 exe、clang 交叉的 ELF `.o`）输出正确的节表与入口；
2. `bitflip info` 的 JSON 有稳定 schema + `format_version`，有快照测试；
3. 畸形输入（截断、字段越界、循环引用）只返回错误，不 panic、不 OOM —— 用 fuzz 目标（`cargo-fuzz`）证明。

风险：格式解析的鲁棒性是长期负债 —— 从 M1 就上 fuzz，不要推迟。

### M2 · 反汇编引擎 + 地址空间

**目标**：能看反汇编，且能处理大文件。

交付物：
- `bitflip-loader`：raw binary 加载（手工基址/段定义）、COFF `.obj`、`Object` 归一化。
- `bitflip-arch`：`Decoder` trait + capstone 后端 + 结构化指令（flow kind、条件、寄存器读写集合、内存操作数）。
- `AddrSpace`：按段分页的地址空间，mmap 直映射文件，稀疏指令表（BTreeMap/分页 arena），按需解码。
- 线性扫描 + 递归下降双策略；函数边界初判（符号 + 入口 + 调用目标）。
- 列式分页 API（`GET /api/sessions/:id/insns?from=&count=`），服务端游标。
- UI：反汇编列表（虚拟滚动，键盘导航 j/k/g/G/Enter/b）、字节列、地址列、跳转跟随。

验收标准：
1. 打开 100MB 级 PE 首扫 < 15s、内存 < 3× 文件大小（`tests/bench` 里可复现）；
2. 列表滚动在 1M+ 指令规模下不掉帧（浏览器 Performance 面板实测，非估算）；
3. 分页边界（跨段、段末尾、非法地址）有测试；
4. 解码器 fuzz 10 分钟无 panic。

> 大文件的测试方法、fixture 生成与实测数据见 `docs/BIG-FILE-TESTING.md`。
> 现状：96 MiB fixture 完整分析 2.1 s（release），100MB 级目标达标。

风险：指令表示一旦定型很难改 —— 本阶段必须完成结构化设计评审（见 ARCHITECTURE §4）。
`capstone` 的 `disasm_count` 式分块解码要注意退化路径（adi 曾在此踩到二次复杂度）。

### M3 · 函数、符号与交叉引用（第一个"像 IDA"的版本）

**目标**：可用的交互式分析：找函数、看引用、标名字。

交付物：
- `bitflip-symbols`：PE 导出/导入（含序号、转发导出）、ELF `symtab`/`dynsym`、
  `.eh_frame` FDE 与 `.pdata` unwind 表驱动的**函数边界**（剥离符号场景的关键路径）。
- 函数识别流水线：多来源候选 + 置信度 + 冲突消解（符号 > unwind > 调用目标 > prologue 模式）。
- 交叉引用：代码引用（call/jmp，直接 + 间接来源推断）、数据引用（rip-relative/绝对地址）；xref 面板。
- 二进制视图（hex dump，可跳到反汇编）、字符串表（ASCII/UTF-16，min length 可调）。
- 重命名与注释（首版落库）、导航历史、地址跳转框、书签。
- .NET CLI header 识别（提示"托管程序集，暂不支持 CIL"）。

验收标准：
1. 对无符号的 mingw 静态链接 exe，函数识别覆盖率（vs `objdump`/`dumpbin` 的函数清单）≥ 95%；
2. 每个函数都有来源与置信度，UI 可筛选；
3. xref 双向一致（`to→from` 与 `from→to` 不矛盾），有属性测试（proptest）。

风险：间接引用（`call [rax+0x10]`、跳转表）是覆盖率的瓶颈，需在 M6 强化；M3 先明确"未解析"而不是猜错。

### M4 · 工程库 + 增量分析 + 作业系统

**目标**：可持续工作的工作台 —— 打开快、标注不丢、大文件不假死。

交付物：
- `bitflip-project`：可写工程库（决策门 D2 选型），`schema_version` + 迁移；
  主数据（names/comments/types/bookmarks/patches）与分析派生物（functions/xrefs/insn 索引）分离，
  派生物可整体重建。
- 作业队列：一次分析一个目标（CPU 密集），多会话受并发上限约束；进度/阶段/日志经 WS 推送；可取消。
- 增量：注解落库 < 50ms；改名/注释不触发重新分析；打开已分析目标 < 2s。
- 崩溃恢复：分析中断后重启不损坏工程库（journal/事务验证）。
- 会话持久化（最近打开的二进制列表，等价 adi web 的 `index.json`，但要原子写 + 并发安全）。

验收标准：
1. 100MB 目标：首扫 → 关闭 → 重开 ≤ 2s；
2. 分析中途 kill 进程，重启后工程库可读、可继续（有测试脚本）；
3. 10 万条注解下改名操作 p95 < 50ms（基准测试）。

风险：数据库选型影响全身。D2 必须在本阶段**开始前**定案，不允许中途换。
**状态：D2 已在 M2 结束时定案（ADR-0012）—— 主数据 SQLite、派生物独立 `.bda` 文件。
这样本阶段的写入路径已无待定项，可以按 `docs/D2-STORAGE-ANALYSIS.md` §6 的清单落地。**

### M5 · 静态库 / 动态库 / 归档 + 多架构

**目标**：`exe/app/静态库/动态库` 全覆盖（除 Apple）。

交付物：
- MLib `.lib` 解析（含 linker member / 第二成员链，类型 1 与类型 2）、GNU/BSD `ar`（长名表、符号索引）。
- 归档 UI：成员树、按成员进入分析、成员级符号索引、跨成员 xref（导出间调用）。
- 共享库语义：`.so`/`.dll` 的导出 thunk、导入 stub、PLT/GOT 解析、重定位驱动的指针表识别。
- AArch64 + ARM/Thumb 解码与 ABI（参数寄存器、栈帧、返回约定）；跨架构的指令文本渲染。
- 架构自动识别 + 手动覆盖（raw 二进制必须有）。

验收标准：
1. 对 `.a`/`.lib` 中的每个成员可独立反汇编并统计函数数；成员选择与符号定位在 UI 与 CLI 都可用；
2. ARM64 fixture（clang 交叉生成）的 CFG 正确性抽查通过；
3. 架构差异只在 `bitflip-arch` 内出现（用 `grep` 门禁脚本验证：`analyze` 里不出现架构枚举分支）。

风险：`.lib` 的格式变体（MSVC 版本差异）与 ARM/Thumb 的指令集切换是已知难点；fixture 覆盖要够。

### M6 · 数据/代码判定与高级分析

**目标**：把"看起来对"变成"分析得对"。

交付物：
- 数据 vs 代码判定（引用驱动 + 对齐填充 + 无效指令检测 + 用户覆写）。
- 跳转表/`switch` 识别（PE `jmp [rip+...]` + 表基址推导；ELF `.rodata` 表模式），生成多后继 CFG。
- 常量/结构体初步：字符串引用聚合、立即数常见模式、数组步长推断。
- 调用约定与参数推断（ABI 驱动：x64/win64/sysv、ARM64 AAPCS），函数原型展示。
- 栈帧/局部变量视图（unwind + prologue 分析），最少做到"帧大小 + 保存寄存器"。
- 交叉引用过滤（按类型/来源/范围）、可达性、调用图（call graph）视图。

验收标准：
1. 跳转表 fixture 的目标集合与编译器实际生成的完全一致（黄金快照）；
2. 数据/代码误判率在真实样本集上有量化指标与回归门禁（不许"感觉变好了"）；
3. 调用图在 1 万函数规模下可交互渲染。

风险：这一阶段的复杂度最容易失控 —— 每项能力都必须有"未解析时如何诚实显示"的降级策略。

### M7 · 脚本层与插件（决策门 D1 后启动）

**目标**：可自动化、可扩展，等价 IDA 的 IDC/IDAPython 位置。

交付物：
- 嵌入脚本引擎（rquickjs / mlua / wasmtime 三选一，见 DECISIONS D1）+ 沙箱与超时。
- 脚本 API：读地址空间/指令/函数/xref/符号、写注释与名字、注册分析 pass、生成补丁、
  自定义视图数据源；错误与日志回传到 UI。
- UI：脚本控制台（REPL + 结果表格）、脚本库（保存/复用）、脚本触发的批处理进度。
- 内置脚本示例集：批量重命名、导出函数清单、识别常见库调用模式。

验收标准：
1. 一个"识别所有调用 `memcpy` 并重命名参数注释"的脚本可端到端跑通；
2. 死循环脚本可被中断，不影响主进程；
3. 脚本 API 有版本号与稳定保证（与 `bitflip-core` 语义对齐，但不直接暴露内部类型）。

风险：脚本引擎拖入 C 依赖（QuickJS 需编译）与跨平台构建复杂度；WASM 方案隔离最好但 API 笨重。

### M8 · 高级符号来源与签名识别

**目标**：让剥离二进制的分析质量接近"有符号"。

交付物：
- DWARF（`gimli`）：函数/变量/类型/行号（ELF 与 PE 上的 DWARF）；PE 的 PDB 支持（`pdb` crate）。
- FLIRT 风格签名库：从已知库（静态链接运行库、常见 CRT/OpenSSL/压缩库）生成签名并自动命名。
- 库函数识别：编译器内置函数（`__security_check_cookie`、`memcpy` 展开等）模式库。
- 符号来源优先级与冲突展示（用户 > 签名 > PDB/DWARF > 导出 > 推断）。

验收标准：
1. 静态链接的 mingw exe 上，签名库能识别出 libgcc/CRT 函数并给出可读名字（量化：识别数 + 误报率）；
2. PDB 可用时，函数名/源文件/行号在 UI 全链路贯通（含 xref 与调用图）。

风险：PDB/DWARF 解析是吃时间的大坑；限定范围（先函数名+行号，类型系统后置）。

### M9 · 补丁、导出与差分

**目标**：分析成果能带出工具并作用于二进制。

交付物：
- 字节补丁编辑（单字节/区间/汇编 patch 预览；`nop`/跳转重定向辅助）。
- "Apply patches to input file"/另存：写回可执行文件，含校验（PE checksum、ELF 段/节一致性），
  **默认写到副本**并需要显式确认。
- 导出：反汇编文本（Intel/AT&T）、JSON、函数清单、符号表、CFG（DOT）、差异报告；
  FlatBuffers 只读快照导出（供外部工具消费，格式带版本号）。
- 差分视图：两个同族二进制（DLL 版本升级）的符号/函数/指令级差异。
- CLI 全部等价能力，可用于 CI。

验收标准：
1. 补丁后二进制可正常执行（fixture 上做 monkey patch 并真跑一次）；
2. 写回失败/不一致时文件不被破坏（写临时文件 + 原子替换，有测试）；
3. 导出 JSON schema 有版本号 + 快照测试。

风险：写回是**破坏性操作**，必须默认安全（副本 + 原子替换 + 显式确认）。这一条是硬约束。

### M10 · 未来 TODO 池（不承诺，按需排序）

- **Mach-O / `.app` bundle / fat（universal）容器 + Apple 架构**（用户已明确推迟到这里）。
- 反编译器（C 伪代码）：独立决策门，工作量数倍于前面所有之和，可能永不做。
- 动态分析：调试器集成（attach/断点/内存视图）、指令级 trace 导入。
- 跨二进制知识库：函数指纹库、社区签名共享（本地优先，无云）。
- 协作：工程库的合并/冲突解决（多人标注同一目标）。
- wasm32 / Java 字节码支持。
- 性能极致化：GPU/PGO、分析结果 mmap 预热、超大固件（GB 级）流式分析。

---

## 5. 横向轨道

### 5.1 性能预算（硬门禁，每个里程碑跑基准）

| 指标 | 预算 |
|------|------|
| 打开 100MB PE/ELF（首扫） | < 15s |
| 打开已分析目标（工程库命中） | < 2s |
| 常驻内存 | < 3× 文件大小 |
| 反汇编列表滚动 | 1M+ 指令不掉帧 |
| 单条注解落库 p95 | < 50ms |
| 分页 API 响应（20k 条列式） | < 200ms 局域网本地 |
| 冷启动到 UI 可交互 | < 1.5s |

超预算即为阻塞问题：要么优化，要么修改预算并在本文件记录理由。

### 5.2 测试与样本策略（磁盘紧张下的做法）

- **样本不入库**（C: 仅剩 ~2.8GB）。`tests/fixtures/` 放**生成脚本 + 源文件 + 黄金断言**，产物 gitignore。
- 生成矩阵（全部可在 Windows 上完成，不需要重型 WSL）：
  - PE：mingw `gcc`（exe/dll/静态链接 exe）、MSVC `cl.exe`/`lib.exe`（exe/dll/obj/lib）；
  - ELF：`clang --target=x86_64-unknown-linux-gnu -c` / `--target=aarch64-unknown-linux-gnu -c` → `.o`；
  - 归档：`llvm-ar` / `lib.exe` 打包上面的 object；
  - raw：脚本截取/构造。
  - 需要**链接**的 Linux 产物（可执行 `.so`）用 WSL 手动生成一次并只保留断言，不进自动 CI。
- 三层测试：单元（各 loader/decoder）、黄金快照（分析结构：函数数/段表/CFG 边）、属性测试
  （xref 一致性、编解码往返、分页边界）。
- fuzz：loader 与 decoder 的 `cargo-fuzz` 目标常驻，CI 跑短时 + 本地跑长时。
- 端到端：无头浏览器（Playwright/Chromium）跑一条"打开→跳转→改名→导出"的主链路。

### 5.3 UI/UX 原则

- 键盘优先（IDA 用户的手感）：`j/k/g/G/Enter/b/r/;`/`x/空格`/`n`，所有操作有快捷键且有命令面板。
- 中文界面为准，i18n 结构就位（文案集中管理，不硬编码在组件里）。
- 大列表一律虚拟滚动，分页由服务端游标驱动；**不把全部指令流拉进浏览器**（adi 的做法在 10 万条以上不合理）。
- 长任务一律进"作业面板"：进度、阶段、可取消、错误可复制。
- 三栏式工作台：左侧（段/函数/符号树 + 字符串）、中间（反汇编/图形/hex 多标签）、右侧（详情/xref/注释）。

### 5.4 打包与分发

- 目标产物：单文件可执行（Windows `.exe`、Linux 静态/半静态二进制）；SPA 用 `rust-embed` 内嵌。
- 运行期零依赖（不需要 Node、不需要 DLL 附带，除系统 CRT）。
- 构建期依赖 npm（仅构建 SPA）；CI 里 `npm ci && npm run build` 后 `cargo build --release`。
- 交叉编译：Linux 产物优先在 Linux CI 构建（本机磁盘/WSL 限制不做重型交叉）；macOS 推迟。

### 5.5 文档与协作

- 用户文档：快速上手、快捷键、CLI 参考、脚本 API 参考（M7 起）。
- 架构文档与决策记录（ADR）随代码演进，不允许只在提交信息里。
- 每个里程碑打 tag + CHANGELOG 条目（面向使用者的行为变化）。

---

## 6. 关键设计决策（详细论证见 ARCHITECTURE.md）

1. **地址空间分页 + 稀疏指令表**：避免全量物化；mmap 直映射；按需解码。
2. **结构化指令表示**：解码结果的语义（flow/条件/寄存器读写/内存操作数）比文本重要，
   上层能力（数据流、签名、调用图）都建立在此之上。
3. **多来源函数发现 + 置信度**：符号、unwind 表、调用目标、prologue、签名库各自产出候选并合并，
   冲突可解释（UI 显示"为什么认为这里是函数"）。
4. **列表式传输（列式 + 服务端游标）**：沿用 adi web 的正确选择，但翻页由服务端承担；
   wire 地址统一 16 位定长 hex。
5. **用户数据 vs 分析派生物分离**：用户标注永不因重新分析而丢失；派生物可整体重建。
6. **作业队列 + 事件推送**：分析与 UI 解耦；可取消；进度可观测。
7. **诚实降级**：任何"没分析出来"的地方明确显示"未解析"，而不是猜测填充（adi 用 `func_xxx`/`loc_xxx`
   假名掩盖了这一点）。

---

## 7. 决策门（开工前必须定案）

| ID | 决策 | 影响 | 状态 |
|----|------|------|------|
| D1 | 脚本层：rquickjs（JS） / mlua（Lua） / wasmtime（WASM 插件） | M7 起全部脚本能力与插件生态 | 待定（M6 末） |
| ~~D2~~ | ~~工程库：SQLite / 自研日志~~ | M4 起所有持久化 | **已决：主数据 SQLite + 派生物独立文件（ADR-0012，分析见 `D2-STORAGE-ANALYSIS.md`）** |
| ~~D3~~ | ~~解码后端：capstone / + iced-x86~~ | 指令文本质量与属性精度 | **已决：capstone 单后端，接口保持后端抽象（ADR-0011）** |
| D4 | PDB/DWARF 依赖范围 | M8 工作量与体积 | 待定（M8 前） |
| D5 | 是否做反编译器 | 数倍于全部既有工作量 | 待定（M10 评审） |
| D6 | 许可证 | 依赖兼容性（capstone BSD、goblin MIT），对外分发方式 | **M0 前** |

---

## 8. 风险登记表

| ID | 风险 | 等级 | 缓解 |
|----|------|------|------|
| R1 | 范围爆炸（IDA 是数十年工程） | 高 | 里程碑"每个 M 都可用"；能力矩阵显式声明未支持；非目标写死 |
| R2 | 磁盘紧张（C: ~2.8GB） | 高 | `target-dir` 与 `CARGO_HOME` 落 F:；样本不入库；CI 产物及时清理 |
| R3 | 沙箱下 `pnpm` 不可用 | 中 | 只用 npm（已验证）；不引入 pnpm 工作流 |
| R4 | 本机缺少 Linux/macOS 原生环境 | 中 | clang 交叉 `-c` 造 object；WSL 仅手动轻量验证；macOS 推迟到 M10 |
| R5 | 格式解析鲁棒性（畸形输入导致 panic/OOM） | 高 | 从 M1 起 fuzz + 尺寸/递归上限 + 越界全用 `checked_*` |
| R6 | 性能回归 | 中 | 每个 M 跑基准门禁（§5.1），criterion + 内存基准 |
| R7 | 指令表示/数据库选型反复 | 中 | D2/D3 设门禁，定案后不改；定型前做设计评审 |
| R8 | 单文件分发与 SPA 构建耦合 | 低 | 运行期零依赖；构建脚本把 SPA 产物嵌入前校验哈希 |
| R9 | 参照项目 `temp/adi` 被误入库/误改 | 中 | `.gitignore` + `.githooks/pre-commit` + CLAUDE.md §0 |

---

## 9. 立即行动（M0 开工清单）

1. 定许可证（D6），补 `LICENSE`。
2. 建 workspace 骨架：8 个 crate 的空壳 + `.cargo/config.toml`（`target-dir = ".cargo-target"`）+ `rust-toolchain.toml`。
3. 前端骨架：`web/`（Vite + React + TS + 中文界面 + 虚拟滚动占位），`npm run build` 产物由 `rust-embed` 引入。
4. `bitflip-server`：`/api/health` + Origin/token 校验 + 端口回退 + 静态资源。
5. `bitflip-app`：`bitflip <target>` → 起服务 → 打开浏览器 → `Ctrl+C` 优雅退出。
6. CI（Windows）：fmt / clippy / test / SPA typecheck + build。
7. `tests/fixtures/gen-fixtures.ps1`：生成 M1 需要的最小样本集（PE exe/dll、ELF .o、归档）。
8. 打 tag `v0.0.1-m0`。

> 完成 M0 后，README 的"状态"改为可构建，并补一份 5 分钟上手文档。
