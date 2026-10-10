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

### 新增 — M8：高级符号来源与签名识别（进行中）

M8 分两半走。**签名库**这一半已落地：剥离目标上唯一剩下的证据是字节，而"这段字节是
哪个库函数"只有从用户自己机器上的库抽出来的指纹能回答。**调试信息**这一半也已落地：
剥掉符号表之后唯一还有名字和行号的地方 —— DWARF 与 PDB（MSVC 系，在旁边的 `.pdb` 里）
两条路都通，且共用同一个出口，所以反汇编、函数表、交叉引用、调用图上都能看到源位置。
交付物 3、4（编译器内置模式库、多来源冲突展示）已在后续提交里落地，见 `docs/PLAN.md` §M8 记录 8、9。

- **`bitflip-signature`（新 crate）**：从可重定位对象（`.o`/`.obj`/静态库成员）抽函数指纹。
  一条签名 = 名字 + 形态（位宽/字节序/编码族）+ 长度上界 + 前缀模式（≤24 字节，
  被重定位改写的字节记成通配）+ 可选尾部 CRC。索引键取前缀开头 4 个确定字节，
  匹配时先比前缀、再验尾部。
  **不预置任何数据库**：签名是本地派生物，由用户从自己的库生成 —— 项目定位是本地优先，
  也不把第三方指纹打包进来（那会变成一份来源不明的"事实"）。
- **`bitflip-cli signature build` / `signature info`**：建库与查看。`--out` 必填、
  默认**拒绝覆盖**（要覆盖得显式写 `--force`）、一条签名都没产出时**报错**而不是
  写个空文件让人以为成功了。账目闭合：对象数、函数符号数 = 产出 + 丢弃，
  且各丢弃原因分项（未定义符号 / 不在可执行节 / 确定字节太少 / 开头即通配 /
  同形无法区分 / 重复）。
- **`--signatures <FILE>`**：每个打开目标的命令都支持（与 `--arch`/`--base` 同级摊平）。
  在分析里它是"来源 7"，排在其它来源**收齐候选之后** —— 因为"这个函数有多长"
  决定"装不装得下这条签名"，而函数范围优先取 `.pdata` 展开信息（PE 上唯一精确的边界）。
  认出的函数来源标成 `signature` / 中文"签名库"，与符号表、导出、展开表并列可筛。
- **降级一律写在界面上**：签名文件读不出 / 版本不符**直接报错**（不静默跳过，
  否则"给了签名库却什么都没认出来"会被理解成库不够全）；形态对不上就明说
  "没有适配本目标形态的签名"且不产生账目（不是"用了 0 个"）；没认出来要分类说明 ——
  库里有同形无法区分 / 可读字节不够（**没有证据**，不是"不匹配"）/ 签名比函数长被排除。
- **量化验收 `scripts/m8-signature-acceptance.ps1`**：本机 mingw 四个静态库
  （2275 个对象 / 2753 个函数符号）→ 749 条签名，对剥离的 `m3-mingw-static.exe`
  （真值 154 个函数，取自 strip **之前**的 objdump）：**认出 63 个、名字全对、错名 0**
  （误报率 0%）；库里含 67 个真值名字，即查全率 94%（占全部真值 41%）。
  错名是硬失败门禁：写错名字比不写名字更糟（CLAUDE.md §7）。缺库或缺样本时如实
  SKIPPED，不报没测过的数字。
- 测试：`bitflip-signature` 13 条（含对齐填充造成的假阳性、短函数被邻居字节"复活"、
  ELF 有确切大小时才做尾部校验）、`bitflip-core/tests/m8_signatures.rs` 3 条
  （端到端命名且认出集合**完全相等** = 没有假阳性、不可用的签名文件必须报错、
  形态不匹配必须明说）、CLI 4 条（落盘往返、拒绝覆盖、空产出报错、输入缺失报名字）。

### 新增 — M8：调试信息（DWARF）

剥离的二进制上还能问出名字和行号的地方只剩调试信息；这一半就是把它读出来并接到用户
看得到的地方。断成三步提交，每步可独立验证：先"读出来"（新 crate），再"行号到反汇编列表"，
最后"名字与源位置进分析结论"。

- **`bitflip-debug`（新 crate）**：`gimli` 读 DWARF，产出"编译单元 + 带地址的子程序 +
  行表"。`DebugInfo::location_at(addr)` 是稀疏查询（落在行与行之间返回 `None`），
  `function_containing(addr)` 只在已知范围内命中。三条不变量：
  **不猜**（读不到就是 `None`；函数没有地址就不算函数；行号缺失的行丢掉）、
  **不失败**（调试信息是"有更好、没有也行"的东西：某个编译单元坏了只影响它自己，
  其余结果保留，异常写成中文说明进 `notes`）、**不依赖符号表**（只看 `.debug_*` 节）。
  刻意不做的两件：内联展开（`DW_TAG_inlined_subroutine`）的行号不并入行表 ——
  那是"被内联进来的函数"的位置，混进来会让函数行号在源码里乱跳 —— 但要**数出来**；
  类型系统一律不读（M8 已明确后置）。
- **分析里的"来源 8"**：调试信息同时给出**名字**和**精确边界**，这个组合别处都没有
  （符号表给名字不给边界，展开表给边界不给名字），所以它排在导出之前、签名之后
  （`SymbolSource::DebugInfo` = 20）。它提供的边界还补进签名匹配用的范围表 ——
  范围越准，"签名比函数长"这类排除就越有效。
- **`FunctionWire` 增 `file`/`line`，`XrefWire` 增 `from_file`/`from_line`，
  `InsnWire` 增 `file`/`line`**。反汇编列表、xref、调用图查的是**同一份**行表
  （挂在 `Disasm` 上）：同一地址在两个视图里显示不同行号是没法向用户解释的。
  声明位置只在**入口与调试信息里的函数起始地址完全一致**时才给 —— 按范围套用邻近
  函数的声明位置，等于把别人的源文件安到这个函数头上（§7）。
  `DISASM_FORMAT_VERSION` 不动：加可选字段是向后兼容的加法，为一个加法改版本号会让
  所有存量消费者被迫跟着动。
- **`DebugUseWire`**：账目要能兑现成数量 —— 多少个编译单元、多少个带地址的子程序、
  其中多少个有名字、多少条行记录、各因何被跳过。只给一个"有调试信息"的布尔值，
  用户看到函数名没出来时无法判断是"本来就没有"还是"我们没读出来"。
- **`Session` 打开时自带调试信息**（不需要用户给路径，也不该让打开失败）：读不到东西时
  里面只有说明，那些说明进 `info.notes` —— "这份文件没有调试信息"与"有但被裁掉了"
  是两个不同的结论，都要看得见。静态库按成员各读一份（成员是独立编译单元）。
- **fixture 与真值都不用自己人**（`scripts/gen-debug-fixture.ps1`）：`llvm-dwarfdump`
  取函数真值、`addr2line` 取地址 → 源位置真值；fixture 用 `-g -O0 -gdwarf-4` 编自己的
  样本，另用 `objcopy --strip-all --keep-section=.debug_*` 做出"**符号表没了、调试信息
  留着**"的变体（脚本自己断言这两半成立）。**不复用 M3 那个 mingw 样本**：它的 DWARF
  只覆盖预编译的 libgcc 对象，自己的函数一个 `DW_TAG_subprogram` 都没有 ——
  解析器完全坏掉也能"找到点东西"。
- **实测（逐条核对，不是"看着对"）**：33 个函数（名字/起止/声明行/源文件）与 392 条
  行记录对齐独立工具；反汇编列表里 **392 条指令**的源位置与 `addr2line` 全一致；
  符号表被剥光的样本上函数名来自调试信息、精确边界用上、声明行/源文件与 `dwarfdump`
  一致；1961 条 xref 里 156 条带上了发起指令的源码行。
- 测试：`bitflip-debug` 5 条（函数与行表对齐独立工具、无调试信息的目标、行与行之间的
  空隙返回 `None`）、`bitflip-core/tests/m8_debug.rs` 6 条（全链路 392 条指令对齐
  `addr2line`、剥离样本靠调试信息命名与给声明位置、xref 带发起位置、没有调试信息时
  字段全空且说明里讲清原因）。

### 新增 — M8：调试信息（PDB）

MSVC 系的调试信息不在镜像里，而在旁边的 `.pdb` 里。这一半把它接上 —— 关键是**界面一行都没改**：
`read_pdb` 产出的 `DebugInfo` 与 DWARF 完全一样，所以分析层、wire 与 SPA 跟着就显示了。

- **`bitflip-debug::read_pdb`**（`pdb` crate）：读编译单元的 `S_GPROC32`/`S_LPROC32` 得名字与精确
  边界，读模块行表得地址 → 源文件:行号；PDB 里存的是节内偏移，经 `AddressMap` 换成 RVA 再加
  镜像基址得到虚拟地址。
- **入口分三个**：`read`（只 DWARF）、`read_pdb`（只 PDB，输入是字节，不碰文件系统，因此可测）、
  `read_target`（读镜像里的 DWARF，再按同名约定找旁边的 PDB，两者都有就 `merge`）。分析层只调
  `read_target`；成员会话传 `None` —— 不知道路径就不去猜一个可能配错的 PDB。
- **只对 PE（exe/dll）找 PDB**：静态库/归档成员的 PDB 地址语义与镜像不同，那部分没做，所以也不去找。
- **与 DWARF 的语义差异都写进 `notes`**：PDB 没有"声明行"字段，所以 `decl_line` 是"该函数第一条行
  记录所在的行"；PDB 没有 DWARF 那种"无地址的声明/被内联"分类，所以 `skipped` 全为 0 是**不适用**
  而不是统计为零；行记录的结尾按 PDB 自己的语义（一条行记录有效到下一跳）算。
- **真值来自第三方工具**（`scripts/gen-pdb-fixture.ps1`）：`llvm-pdbutil dump -symbols/-l` 取函数与行
  记录，`llvm-readobj` 取节表把节内偏移换算成虚拟地址，产出 `m8-pdb.golden.txt`。样本
  `tests/fixtures/m8_pdb_sample.c` 刻意不 include 任何头文件，好让 clang-cl 不需要 Windows SDK
  环境就能编它；链接用 `/NODEFAULTLIB /ENTRY:...`，完全不碰 CRT。
- **脚本里的一条交叉检查**：每个函数的入口必须与它第一条行记录的地址重合，否则直接失败 ——
  它拦住的正是下面那个坑。
- **一个会静默出错的坑**：`llvm-pdbutil dump` 打印的 `addr = 0001:0032` 是**十进制**偏移（真值
  0x20），按十六进制解析会让 6 个函数里 5 个地址错掉，而且不报任何错。这不是猜出来的：行表与
  符号表对同一批函数给的地址对不上才暴露出来 —— 所以现在把这条一致性写成断言。
- 测试：`bitflip-debug` +5 条（函数与 PDB dump 逐条一致、行记录与地址逐条一致、符号表被剥光后靠
  PDB 命名并给出源位置、没有 PDB 的目标说明找过哪里、空 PDB 说明是空的）；`bitflip-core` +1 条
  （PDB 目标端到端：名字、精确边界、声明位置、账目 6 个函数 23 条行记录）。

### 新增 — M8：多来源冲突展示与编译器内置模式库

M8 的四个交付物到这里齐了。这两件是最后两件：一件让"多个来源各说各话"能被用户看见，
一件让**没有签名库**的机器也能认出编译器自己生成的函数。

- **`FunctionWire.aliases`（交付物 4）**：同一个入口上**名字不同**的候选全部列出来
  （名字 / 来源 / 置信度），按来源优先级排序；界面在函数表"来源"格后显示"另有 N 个候选"，
  悬停看到分别是哪个来源说的。两条克制写进了实现与测试：未命名的候选不进别名（那是
  "没认出来"，不是"另一种说法"），与最终名字相同的候选也不进（那是相互印证，不是冲突）。
  实测：`m3-mingw-static.unstripped.exe` + 本机 mingw 签名库 → 156 个函数 / 154 个有名字 /
  **3 个函数有别的说法**（`_fpreset` vs `fpreset` 这类符号表别名），全部来自符号表。
- **新来源 `builtin-pattern`（"编译器模式"，优先级 68）+ `bitflip-analyze/src/builtins.rs`（交付物 3）**：
  判据是公开、可复核的固定字节序列，因此**不需要任何签名库**。当前一条判据：GCC x64 的
  逐页栈探测助手 `___chkstk_ms`（两处 `0x1000` 页步进 + `or [rcx],0` 探测 + 直线代码在第一条
  `ret` 处结束）。实测（剥光符号）两个 mingw 目标各命中 1 个，地址与未剥符号的孪生样本一致，
  **误报 0**；每次分析都在 `notes` 里报账（"1 条判据，命中 N 个"），零命中不会被读成"没有"。
- 新 fixture `tests/fixtures/m8_builtins_sample.c` + `scripts/gen-builtins-fixture.ps1`：
  8 KiB 的栈帧逼出真的探测循环，真值取自 mingw objdump，脚本**先断言那不是桩函数**再写黄金值。
- 测试 +10：`bitflip-analyze` 内置判据 6 条（其中 4 条是"证据不足就不认"）、
  `bitflip-core/tests/m8_builtins.rs` 2 条（含"只准命中这一个地址"与"同名不同来源不算冲突"）、
  `aliases` 单元测试 2 条。

**本次新增部分的已知限制**：

- 内置模式库只有一条判据。`__security_check_cookie`（判据要落在 load config 的 cookie 地址上，
  本机没有能产生它的 MSVC fixture）、MSVC 的 `__chkstk`（与 GCC 的形状相近、名字不同，无法从
  形状区分工具链）、GCC 的 `__do_global_dtors`（形状与"任何遍历回调表的小函数"不可区分）都
  **没做**，理由逐条记在 `docs/PLAN.md` §M8 —— 认错名字比不认更糟。
- **PE 调试目录里的 CodeView 记录（交付物 1 的收尾）**：找 PDB 不再只靠 `foo.exe` → `foo.pdb`
  的同名约定，而是先看链接器写下的 `RSDS` 记录（GUID + age + 当时的路径），再退回目标旁边的
  同名文件，最后才是同名约定；三条都试不到时报出**试过哪些路径**。
  实测：把 `m8-pdb.exe` 拷进一个**没有 PDB** 的目录，6 个函数仍然全部有名字与行号（走记录里的
  绝对路径）；修复前是 0 个。
  踩的坑值得单独记：`IMAGE_DEBUG_DIRECTORY.Type` 在 **+12**（`+0` 是 `Characteristics`），
  第一版读在 `+0`，于是 `find` 恒为 `None`；而单元测试当时**是绿的** —— 因为合成镜像按同一个
  错误假设拼的（自证其说）。现在单测按官方字段顺序拼，并配一条真实 lld-link 样本的测试兜底。
- **候选 PDB 要与记录核对身份**：GUID/age 对不上就不采用（继续试下一个候选），并在 `notes` 里
  说明是哪一条对不上、为什么不采用 —— 同目录放着一个上次构建留下的同名 PDB 太常见了，名字对、
  内容不对，用它就会把旧行号安到新镜像上。真样本上两者一致
  （`8a67143c-d173-1ace-4c4c-44205044422e` / age 1）；"不匹配不许认"与 GUID 文本的字段端序
  另有 3 条测试钉住（不匹配那半边没法用真产物造：fixture 只产一份 PDB）。
- 每个命中背后的判据（`BuiltinHit::why`）只在代码与文档里，界面只显示来源标签；
  "逐条理由上界面"是后续工作。
- 内联展开的 `memcpy`/`memset` 是"函数内部标注"而不是给函数命名，本次不做。
- mingw 的 `___chkstk_ms` 在符号表里是 **NOTYPE** 符号（objdump `(ty 0)`），而我们的符号表
  来源只收函数类型符号 —— 所以即使不剥符号，这个名字也只由内置判据给出。
- 浏览器目视确认仍未做。
### 新增 — MSVC 名字反修饰（M8 遗留项，进行中）

`?bar@Widget@@QEAAHXZ` 这种名字机器能对齐、人读不了。现在函数表里显示的是可读名
（`int __cdecl foo(int)`），而**原始修饰名不丢**：它作为 `aliases` 的一条留在函数上，
签名库、脚本、地址表继续按原始名匹配 —— 改了显示，不改身份。反修饰只认 MSVC 那一套
（`?` 开头）；Itanium（`_Z3fooi`）、Rust 修饰、本来就可读的名字一律原样显示，
不认识就说不认识，不给一个看着像样的名字。

真值取自第三方工具（MSVC 的 `undname.exe`）：`?foo@@YAHH@Z` → `int __cdecl foo(int)`
两个独立实现互相印证。已知风格差异：`undname` 会打印 `__ptr64`，LLVM 风格不打印；本机没有
`llvm-undname`，所以另两条的期望值只有单方来源（写在代码注释里）。依赖 `msvc-demangler 0.11`
（经本地 crates 代理拉取；已进本地缓存，普通构建不需要代理）。

**端到端已验**：新增 C++ 样例与 `scripts/gen-cxx-fixture.ps1`（clang-cl `/Zi` + `lld-link /debug`）。
直接分析 `m8-cxx.obj`（符号表里带修饰名）：显示名 `public: int __cdecl Widget::bar(int)`，
`aliases` 里留存原始修饰名 `?bar@Widget@@QEAAHH@Z` —— "改了显示、不改身份"在真实链路上成立。

三件如实记下的事：
- `undname` 打的是 `…Widget::bar(int) __ptr64`，我们用 LLVM 风格（不带 `__ptr64`）。golden 里存的是
  `undname` 的原话，所以拿它做断言**不能**逐字相等，要按"去掉 `__ptr64` 后相等"或按语义比。
- 走 PDB 那条路时拿到的名字**已经是可读的**（`Widget::bar`），反修饰在那条路上没被真正用到；
  可读名从哪来（链接器写进 PDB，还是读取路径上某处做的）**没查清**，没写进文档当结论。
- 自动化回归测试还没补（现在这次是手工测量）。手工验过又没进测试的东西，下次会悄悄退化。
  → **已补**：`crates/bitflip-core/tests/m8_demangle_e2e.rs` 两条（显示名可读 + 原始名留存为
  `aliases`；普通 C 名不被改动）。

### 新增 — M9：导出（反汇编文本 / JSON / 函数清单 / 符号表 / 交叉引用 / CFG-DOT）

写回与差分**未做**，见 `docs/PLAN.md` §M9 的"完成情况"。这里记已落地的导出。

- **`bitflip-core::export`（新模块）**：六种格式 —— `asm-intel`、`asm-att`、`json-functions`、
  `json-symbols`、`json-xrefs`、`dot-cfg`。每个导出都自述：文本类首行是
  `# bitflip-export v1 format=... target=... arch=... generated_at=...` 注释头，
  JSON 是 `{format_version, producer, meta, totals, 数据...}`，`meta` 含四个层的 wire 版本、
  目标与架构、过滤参数、RFC 3339 时间。`EXPORT_FORMAT_VERSION` 独立演进。
- **单一实现、两个入口**：格式与写出只在核心层写一遍；CLI `export` 子命令与服务端
  `GET /api/export` 都调它。服务端用 `export_with_disasm` 复用 `AppState` 缓存的反汇编，
  一次导出不重扫；因此也不会出现"CLI 与服务端各拼一份文本"的漂移。
- **`bitflip-arch::render::format_insn_with`**：按 `TextStyle` 渲染 Intel / AT&T。
  AT&T 规则：`%reg` / `$imm` / `disp(%base,%index,scale)`、操作数倒序、直接跳转写绝对目标、
  间接跳转加 `*`、仅带内存操作数时给助记符加宽度后缀。`DecodedInsn` 不带段前缀与
  `lock`/`rep` 前缀，因此那几类不渲染（记在注释里，不假装支持）。
  真值来自独立的 `objdump -d -M att`：对拍 6000 条，逐字相同 5859 条，已记录的解码层差异约 140 条，
  **未解释的不一致 0 条**。
- **`Disasm` 新增 `text_style` / `set_text_style` / `with_text_style`**：语法风格是**反汇编视图**
  的属性，只有一条渲染路径。`with_text_style` 共享同一个索引 `Arc`，换风格不重扫。
- **CLI `bitflip-cli export`**：`--format/--out/--from/--to/--function/--no-bytes/--no-source/
  --max-functions/--limit-bytes/--summary/--force`。正文走 stdout，截断与降级说明走 **stderr**
  （混进正文会破坏"导出的文件就是那批字节"）。`--out` 默认拒绝覆盖，父目录不存在即报错。
- **HTTP `GET /api/export`**：正文即导出字节，元信息走响应头
  （`x-bitflip-format`/`-export-format-version`/`-items`/`-truncated`/`-warning-N`）。

**诚实性（CLAUDE.md §7）的具体落点**：

- **截断永远自述。** 每次导出有字节预算（CLI 默认 32 MiB，`--limit-bytes 0` = 不限；
  HTTP 上限 128 MiB）。流式格式撞上预算就在报告里写清"少写了多少条"并给出下一步（按地址段分批）；
  截断位置一定落在**行边界**，撞墙后不再补写后面的短行。
- **不能交半份的格式明确失败。** JSON 是单个文档、DOT 是语法文件 —— 截断它们只会得到
  解析不了的东西，所以超预算时返回 `ExportError::OverBudget` 并带上差额与说明
  （`Display` 里连 `notes` 一起印出来：只存不印等于没存）。
- **能力不匹配报错，不回落。** 对非 x86 目标要 `asm-att` 返回 `NotYetImplemented`
  （HTTP 501），而不是给它 Intel 文本假装成功。
- **不造名字。** DOT 里没有名字的函数标为「未识别」，不生成 `func_xxx`。

**测试与门禁**：

- `crates/bitflip-core/tests/m9_export.rs`：六种格式端到端（自述头、`format_version`、
  `totals` 与数据一致、定长 hex 地址、未知 `iat_slot` 写 `null`、范围过滤生效、
  截断有账目且落在行边界、超预算 JSON 报错、非 x86 的 AT&T 报错）。fixture 缺失时**响亮失败**。
- `crates/bitflip-arch/tests/att_matches_objdump.rs`：与 `objdump -M att` 对拍。
- `scripts/smoke-export-http.ps1`（46 项断言，已接入 `preflight.ps1`）：起真实服务进程打真 HTTP，
  验证元数据穿过 HTTP 层、截断被标记、写错的参数被拒、非 x86 的 AT&T 是 501。
- 全量 `cargo test --workspace`：904 passed / 0 failed / 5 ignored。

### 修复

- **Intel 内存操作数缺 `+`：`[rax rax]`。** `format_mem` 把 base 与 index 各当一个"片段"用空格
  拼起来，于是 `nop DWORD PTR [rax+rax*1+0x0]` 被渲染成 `nop dword ptr [rax rax]` ——
  在任何汇编器里都是**语法错误**，而它"看起来像"一个地址。真实样本（`m3-mingw-static.exe`）
  上 146 行受影响。改为按算术式拼装（组分之间一定有 `+`，比例总是写出来）。
  真值取自 `objdump -M intel` 与 `llvm-objdump` 的实读输出。同处一并修正：
  负位移原来写成 `- 0x12e`（有空格），改为 `-0x12e`；绝对地址不再带前导 `+`（`[+0x402000]`）。

- **AT&T 渲染里负位移按无符号打印**（`0xfffffffffffffed2(%rip)`）。与 `objdump -M att`
  对拍时发现，改为 `-0x12e(%rip)`。这条与上一条都是被"导出"这个新功能照出来的：
  以前没有独立真值去逐条对拍渲染结果。

- **服务端导出查询参数被静默忽略。** 第一版用 `limit-bytes`，而 `serde_urlencoded`
  **默认忽略不认识的字段**，于是 `/api/export?limit-bytes=1000` 返回 200 和一份**没被限制大小**
  的响应 —— 用户完全看不出来。现在参数名一律单词（`limit`/`bytes`/`source`/`max_functions`）
  并加 `deny_unknown_fields`，写错的键返回 400 并列出可用参数。

- **PE 映像的长节名（`/NNN`）从来没解析过。** `.text`/`.data` 这类名字在 8 字节以内、
  直接存在节头里，所以这条路径在普通可执行文件上**永远走不到**；而 `.debug_info` 从第一个
  字符起就超长，名字被存成 `/19` 这种形式。结果：文件里明明有完整的调试节，分析却看不到，
  表现为"这个目标没有调试信息" —— M8 的 DWARF 支持就是被这个卡住的。真名要到 COFF
  字符串表里查（位置 = `PointerToSymbolTable + 18 × NumberOfSymbols`），其中
  **`NumberOfSymbols == 0` 而指针非零是正常形态**（objcopy 剥掉符号表后仍留着字符串表），
  只看符号数就会把整张表当成不存在。COFF 目标文件那条路径一直是对的 —— 同一个格式、
  同一张字符串表写了两遍，只有一份是对的。查不到时保持原样并写进 `notes`（猜一个名字
  比留着看不懂的名字更糟）。新增两条测试，一条正一条反；这两条路径此前都没有覆盖。

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
- **ELF 目标文件里符号的"属于哪个节"一直是空的。** ELF 符号的 `st_shndx` 只是个下标，
  节名要从 `.shstrtab` 查，而解析符号表时没有把节名字符串表传进去：`section_name`
  每次都返回 `<节 N>` 占位、代码再把它判成 `None`。以前只是界面上少显示一列，
  M8 会挡住真功能 —— 签名生成要按"符号 → 节 → 文件偏移"取函数字节，没有节名就取不到
  （实测 `elf-x86_64.o` 里 3 个函数符号全部以"不知道属于哪个节"丢弃，功能看起来像没实现）。
  反向验证：`crates/bitflip-signature/tests/generate_and_match.rs` 的 ELF 测试在修复前是红的。
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
- 签名库按**启动参数**指定（`--signatures`），服务与界面沿用启动时那一份；
  按目标/按工程切换签名库排在后续里程碑（`Session` 已经按目标持有签名库，接口不缺）。
- 同形（字节一样、名字不同）的库函数**整体丢弃并计数**，不在"多个候选"里随便挑一个：
  本机 mingw 四库实测有 542 个函数符号因此没有签名。降级方向是报"N 个候选之一"，
  而不是猜一个名字（CLAUDE.md §7）。
- 编译器内置模式（`__security_check_cookie`、内联展开的 `memcpy` 之类）尚未识别（M8 交付物 3）。
- **PDB 已接入，但有三处收尾未做**（M8 交付物 1）：① 还没读 PE 调试目录里的 CodeView 记录，
  所以 PDB 是按**同名约定**（`foo.exe` → 同目录 `foo.pdb`）找的，别名 PDB 找不到 —— 找不到会
  明说找过哪里；② MSVC 修饰名**不做反修饰**（未实现的能力不假装）；③ 静态库/归档成员的 PDB
  不做（地址语义与镜像不同）。
- **调试信息只在"有"的时候给结论**：行号与声明位置全部来自调试节，没有就是 `null`
  （不用邻近行、不用默认值顶替）。`-O2` 之后内联的行号归因未展开：内联子程序被计数并写进
  说明，但不并入行表。
- **界面上已经显示源位置**（M8 验收标准 2）：反汇编列表每行右侧 `文件名:行号`、函数表
  「源位置」列、交叉引用表显示发起指令的源码行、调用图函数列表显示源位置；没有调试信息时
  不显示占位。**但没做浏览器目视确认** —— 编译、产物内容与 HTTP 数据都核过，"长得对不对"
  要人眼过一遍。
- 调试信息参与命名后，**同一地址的多个来源（符号表/导出/调试信息/签名）仍未在界面上
  摊开**（M8 交付物 4）：优先级与来源字段都有了，缺的是"冲突展示"（`aliases` 已经给出数据，
  界面上的"另有 N 个候选"标记也已加上；缺的是逐来源摊开的视图）。
- **导出（M9）已落地，但写回与差分未做**：
  - 字节补丁编辑、写回（PE checksum / ELF 一致性校验、副本 + 原子替换 + 显式确认）、
    差分视图、FlatBuffers 只读快照 —— **都还没有**。验收标准 1、2 挂在这里。
  - 导出 JSON 只有结构与版本号断言，**schema 快照测试未做**。
  - 导出在 SPA 里**还没有入口**（只有 CLI `export` 与 `GET /api/export`）。
  - **AT&T 文本只对 x86 族目标实现**。非 x86 目标要 `asm-att` 会明确报"尚未实现"
    （HTTP 501），而不是回落成 Intel 文本。
  - 段前缀（`%gs:`）、`lock`/`rep`/`bnd`、多字节 NOP 的 hint 前缀**不渲染**：
    `DecodedInsn`/`MemRef` 不带这些信息。这是"没有数据就说没有"，不是渲染 bug。
  - 导出是**一次性成文**（返回 `String` + 报告），不是流式写出：超大目标要靠字节预算 +
    按地址段分批。真正的流式留给后续（那时也要同时给出报告）。

### 计划中
- M9 剩余：字节补丁与写回、差分视图、FlatBuffers 只读快照、导出 schema 快照测试、
  导出在 SPA 里的入口（见 `docs/PLAN.md` §M9）
- M8 遗留：静态库成员的 PDB、符号表 NOTYPE 符号里的函数名（`objdump -t` 实读：`.text` 里的
  NOTYPE 符号绝大多数是节符号与编译器标签；`m3-mingw-static.unstripped.exe` 上只有
  `__C_specific_handler` 与 `___chkstk_ms` 两个像函数名）、按目标切换签名库
  （逐条见 §M8「未做」）
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
