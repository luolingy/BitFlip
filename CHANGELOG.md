# Changelog

本项目遵循 [Keep a Changelog](https://keepachangelog.com/zh-CN/1.1.0/)，
版本号遵循 [Semantic Versioning](https://semver.org/lang/zh-CN/)。

## [Unreleased]

> **缺记声明**：M3 / M4 / M5 / M6 四个阶段的条目在本文件中**缺失** ——
> 本次补记时没有把握据实重建（只能从提交标题反推，那正是本项目禁止的"看起来对"）。
> 这四个阶段各自交付了什么、哪些交付物只做了一部分，**以 `docs/PLAN.md` 里
> 各阶段的"完成情况（据实记录）"为准**，那里有逐条状态表与取舍说明。
> 补齐本文件属于待办，不是"没有发生过"。

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

### 新增 — M7：脚本层（进行中）

引擎选型与实测依据见 [`docs/D1-SCRIPT-ENGINE-ANALYSIS.md`](./docs/D1-SCRIPT-ENGINE-ANALYSIS.md)，
决策记录见 [`docs/DECISIONS.md`](./docs/DECISIONS.md) 的 ADR-0013；
脚本 API 参考与运行模型见 [`docs/M7-SCRIPTING.md`](./docs/M7-SCRIPTING.md)。

- **`bitflip-script`（新 crate）**：嵌入 rquickjs 引擎。`catch_unwind` 把宿主侧
  panic 转成错误；墙钟超时经 QuickJS 中断回调终止死循环，主进程不受影响；
  每次运行新建上下文，脚本之间不共享全局变量。
- **写入暂存与回滚**：`setComment` / `setName` 先入暂存区，脚本**正常结束**时才
  提交；超时、异常、panic 一律整体丢弃，不留半成品结果。
  提交是逐条写入的，中途失败会返回**已写入条数与总条数** ——
  这是唯一可以部分成功的结局，界面必须如实显示这两个数。
- **脚本 API 版本号**：`bitflip.apiVersion`（当前 `1`）。脚本看到的是序列化后的
  wire 形状，与 HTTP `/api/*` 同源，但**不暴露 `bitflip-core` 的内部类型**；
  与 `ANALYSIS_FORMAT_VERSION` / `DISASM_FORMAT_VERSION` 独立演进。
- **读 API**：`target` / `notes()` / `counts()` / `readBytes()`，
  以及 `functions` / `xrefs` / `strings` / `insns` 四组访问器。
  一律提供 `count()` + `page(offset, count)`（必要时补 `at()`），
  **不提供 `all()`** —— ntdll.dll 一个目标就有 66778 条交叉引用，
  一次物化等于给脚本递一颗定时炸弹。页对象同时带 `total` / `requested` /
  `skipped` / `returned` / `truncated`，让"被过滤掉了"与"本来就没有"可区分。
- **`Host::warmup()`**：把分析结论与反汇编提前算好，使其**不计入**脚本超时。
  ntdll.dll 的全量分析要 10.6 秒而脚本默认上限是 5 秒，不预热的话第一个读函数
  列表的脚本会报"脚本超时" —— 而那不是脚本的错。
- **能力缺失一律报错**：没有打开目标时读 API 抛异常而不是返回 `0`；
  没有反汇编结果时 `bitflip.insns.*` 抛异常而不是返回空数组；
  查不到时返回 `null` 而不是 `undefined`。
- **可省略参数**：`page()` / `search()` / `progress(done)` 这类省略写法都真的成立。
  此前可选参数写成 `Option<T>`，而 rquickjs 的 `Option<T>` 走的是**必填**的实参校验，
  于是文档里承诺的默认值一调用就报
  `Error calling function with 0 argument(s) while 2 where expected` ——
  参数类型看起来完全正确，只有在用户照着文档写字时才暴露。
- **外部取消**：`CancelToken` 让控制台的"停止"能掐断死循环脚本，
  报 `ScriptError::Cancelled` 而**不是** `Timeout` —— 用户按的停止与脚本太慢是两回事，
  混成一条会让人去改一段本来没问题的代码。没有脚本在跑时发出的取消会被忽略，
  不会留给下一次运行（否则下一个脚本刚启动就被掐掉，现象是"莫名其妙立刻失败"）。
- **批处理进度**：`bitflip.progress(done, total?, label?)` 由脚本主动上报。
  宿主不替脚本估算百分比；`total` 省略时界面显示"进行中"而不是 `0%`。
- **服务层脚本端点**：`POST /api/script/run`（立刻返回）、`GET /api/script/status`
  （轮询观测日志与进度）、`POST /api/script/cancel`、`GET /api/script/library`
  （内置示例源码）、`GET /api/script/table`（分页取脚本产出的表）。不做成一个同步
  的 POST，是因为那样既看不到进度、也没有一个可被外部引用的运行对象可供取消，
  还会把 tokio 运行时占住（脚本执行是纯 CPU 的，跑在 `spawn_blocking` 里）。
  单槽运行：脚本会改标注，第二个并发请求明确得到 409 而不是排队。
- **填充判定移进 `bitflip-arch`（分层债）**：`is_import_thunk_tail` 原先在
  `bitflip-core` 里直接匹配 x86 填充字节（`0x90`/`0xCC`/`66 0F 1F`）—— 架构知识
  留在了 core 层，而分层门禁按标识符匹配、抓不到操作码字节，所以它一直是绿的。
  现在填充判据是 `bitflip-arch::padding_len`（按架构分派），核心只负责
  "窗口里只允许出现填充或下一条桩"。**这不是洁癖**：实测拿 x86 字节匹配
  `elf-armv7.o` 会凭空多出一个"导入桩"函数（普通代码被认成桩）。不支持的架构
  现在直接不跑这条来源并写进 `notes`，不再按 x86 字节猜。
- **导入桩来源的回归门禁**（`crates/bitflip-core/tests/import_thunks.rs`）：
  这条来源此前**没有任何测试**，而它的失效方式是"认出的桩静默变成 0 个"
  （当年把覆盖率从 92.21% 抬到 95%，掉回去不报错也不 panic）。现有下限断言
  （据实记录：当前 5 个）与跨架构断言（arm/aarch64/riscv 上必须是 0 个），
  并反向验证过：把填充判定归零 → 桩数归零、测试带诊断变红。
- **PLT 桩语义命名（M5 欠下的一项）**：ELF 的 `.plt` 桩按它跳转的 GOT 槽位
  对应的导入符号命名（`sample_add@plt`），名字与 `llvm-objdump` 打印的标签
  逐字相同。依据不需要"符号归属推断"（M5 当时的判断）：`.rela.plt` 里每条
  JUMP_SLOT 重定位都写着那个槽属于谁，桩的职责就是从那个槽取地址跳过去。
  形状识别（哪些字节是桩）放进 `bitflip-arch::plt_stub` —— 架构知识不下沉到
  core；`bitflip-core` 只做"槽 → 符号名"的对照。**对不上就不命名**，按序号
  导入（无名字）也不造 `@序号` 这种"把不知道伪装成知道"的名字；未知架构由
  `supports_plt_stub` 说明并写进 `notes`，不假装扫过了。
- **脚本 API：生成补丁**（`bitflip.setPatch`）：接受十六进制字符串
  （`'9090'` / `'90 90'` / `'0x90 0x90'`，分隔符随意）或字节数组
  （`[0x48, 0x31, 0xc0]`），按**字节**落库为 `patch` 标注。补丁不是注释：
  `text` 必须是 `None`，`patch_hex` 才是内容 —— 存成注释文本的话界面会把它当
  备注渲染，M9 也无从知道该覆写哪些字节。非法输入一律报错并指出问题所在
  （哪一段、什么字符、实际多少位），不做"尽力而为"的猜测。顺带修掉一个缺陷：
  `bitflip.get(addr, 'patch')` 原先永远返回 `null`（`get` 只取 `text`，而补丁的
  正文在 `patch_hex` 里），与"脚本必须能读到自己刚写的东西"直接冲突。
  范围：M7 只管**生成**，把补丁**应用**到文件是 M9。
- **脚本 API：读符号**（`bitflip.symbols.*`）：`count` / `page` / `at(index)` /
  `find(name)` / `atAddress(addr)`。三条不能含糊的地方：
  符号表与函数表是**两份数据**（剥离后函数表还在、符号表空了，必须能分辨
  "没有符号表"与"没有这个名字"）；`at` 按**下标**取，因为同一地址上可以有多条
  符号，按地址取会静默丢数据；`atAddress` **只返回已定义符号** —— 未定义符号的
  `value` 根本不是地址（PE 导入符号、ELF 未定义符号常见取值是 `0` 或节内偏移），
  算进来会让"这个地址上有什么"多出一堆毫不相干的答案且毫无迹象。
  没有目标时整个 `bitflip.symbols.*` 抛异常说明原因，**不返回空表**。
- **脚本 API：自定义视图数据源**（`bitflip.table(name, columns, rows, options?)`）：
  脚本**声明**列名与列类型（`text` / `number` / `address` / `bool`），界面照声明
  渲染 —— 地址列按地址显示、数字列右对齐、空值显示成"——"、多张表标签页切换。
  在它之前，界面只能靠"定长十六进制"猜哪一列是地址，猜错了就是把别的东西当地址
  显示，而用户以为是脚本说的。几条不能含糊的地方：只收标量（对象/数组单元格
  报错，不变成 `[object Object]`）；地址列只收精确值（超过 2^53−1 的数字在 JS 里
  本就不等于自己，静默取整会把这一行指到别的地址，所以报错并让脚本改用十六进制
  字符串）；`bool` 列不把非 0 当真；超限（16 张表 / 64 列 / 合计 20 万格）与形状
  错误一律**报错并指出第几行第几列**，不截断、不替脚本编内容，且被拒绝的调用
  **一张表都不落**。表与标注共享"先暂存、正常结束才提交"的规则（失败/超时/取消
  一张不留、每次运行开始清空），但**不落工程库**：它是分析会话的派生物，寿命与
  `.bda` 一致，持久化需要失效判定与一次 `.bfp` schema 迁移。
  数据走 `GET /api/script/table?name=&offset=&count=` 分页取，`status` 只回表摘要
  （每几百毫秒轮询一次，塞不下整张表）；表名不存在是 `404` 并列出当前有哪些表 ——
  返回空数组在界面上表现为"这张表是空的"，与"没有这张表"完全是两回事。
  **未做**：注册自定义分析 pass（需要 pass 注册表与依赖排序，见 PLAN §M7 取舍 2）。
- **内置示例脚本集**：`memcpy-args`（验收标准 1 的载体）、`rename-by-string`、
  `export-functions`、`library-patterns`，经 `GET /api/script/library` 下发。
  每一份都被 `crates/bitflip-script/tests/builtin.rs` **真的执行过** ——
  文档里的示例没有编译期检查，会静默腐烂，一个跑不起来的示例比没有示例更糟。
  写名字的脚本一律不覆盖已有名字、推断名带 `str_` 前缀、注释写明依据；
  只给候选的脚本明写"不构成识别结论"（CLAUDE.md §7）。
  `export-functions` 与 `library-patterns` 是 `bitflip.table` 的参考实现：
  前者同时打制表符行（"带走"用）与声明式表（"看"用），后者只给表。
- **脚本控制台 UI**（`web/src/ScriptConsole.tsx`）：编辑器 + 运行/停止 + 分级日志 +
  进度条 + 表格 + 脚本库。三件事在界面上明说：每次运行都是**全新上下文**
  （不是能攒状态的 REPL）；预热阶段"停止"置灰并说明原因；脚本层**不是**沙箱。
  表格分两路：**脚本声明的表**（按列类型渲染，列头标出类型，可切换、可继续取
  下一段，没取完时明说还有多少行）与**日志里的制表符行**（无列声明，因此界面
  一个字都不加工 —— 顺带删掉了原先"看着像定长十六进制就当地址渲染"的猜测，
  那句话当时就与"界面不推断列的含义"的注释冲突）。
  用户脚本存在浏览器本地存储里（服务端是一次性进程，存在它旁边等于关掉就没），
  换端口即换存储空间这一条写在界面上。
- **端到端冒烟测试**（`scripts/smoke-script-console.ps1`，已接入 `preflight.ps1`）：
  起真服务、走 HTTP、跑**发布出去的那一份**内置脚本源码，46 项检查。
  其中验收标准 1 走完整链路（HTTP → 脚本 → 读函数/交叉引用 → 暂存 → 提交 →
  经 `/api/annotations` 读回），实测 `memcpy@0000000140009218`、8 个调用点全部
  标注且读得回来；表的链路也走完（发布 → 摘要 → 分页取数据 → 地址是 16 位十六
  进制**字符串**而不是数字 → 空单元格是空 → 表名不存在是 404 → 越界页被拒 →
  下一次运行不再提供上一张表）。
  该脚本用 .NET `HttpClient` 而不是 `Invoke-RestMethod`：
  服务端按 RFC 8259 以 `application/json`（不带 charset）返回，而 Windows
  PowerShell 5.1 会退回 ISO-8859-1 解码，中文全部变成乱码，把乱码再发回去
  就会毁掉脚本源码（浏览器一律按 UTF-8 解码，界面不受影响）。

### 修复

- **PE 映像里同一个二进制出现两套函数地址。** 根因：COFF 符号的 `Value` 是
  **节内偏移**，而加载器把它当地址原样存下来了。于是一个带符号表的 mingw 样本
  上，符号表来源的 `memcpy` 落在 `0x8218`，分析发现的函数落在 `0x1400096c0`，
  函数总数被记成 309（每个函数各记两遍）；界面与脚本都会据此认错地址。
  实测真值：`.text` 的 VA 是 `0x140001000`，`0x140001000 + 0x8218 = 0x140009218`，
  正是 `objdump` 给出的绝对地址。修复后同一目标为 156 个函数，每个都兼具名字与
  正确地址。新增两条不变量测试（符号地址必须落在某个节内；
  未定义符号（无节号）不得凭空加基址）。
  这一路径此前没有任何测试覆盖 —— 剥离符号的样本走的是另一条来源，正好绕开了它。

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
