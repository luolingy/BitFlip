# Changelog

本项目遵循 [Keep a Changelog](https://keepachangelog.com/zh-CN/1.1.0/)，
版本号遵循 [Semantic Versioning](https://semver.org/lang/zh-CN/)。

## [Unreleased]

> **缺记声明**：M3 / M4 / M5 / M6 四个阶段的条目在本文件中**缺失** ——
> 本次补记时没有把握据实重建（只能从提交标题反推，那正是本项目禁止的"看起来对"）。
> 这四个阶段各自交付了什么、哪些交付物只做了一部分，**以 `docs/PLAN.md` 里
> 各阶段的"完成情况（据实记录）"为准**，那里有逐条状态表与取舍说明。
> 补齐本文件属于待办，不是"没有发生过"。

### 新增 — DEX 码元布局校验：指令 ∪ 载荷必须恰好铺满（M11 的 M2a 第一步）

**能力**：`bitflip_loader::check_code_item_layout(bytes, code_off)` —— 对任一方法
走一遍 `[0, insns_size)`，要求每一步**恰好**有一样东西接着（指令或载荷），
并检查终点、长度自相矛盾、载荷与指令撞在同一码元上。

**为什么这条值得单独存在**：它是唯一一条**能独立验证解码器宽度表**的检查 ——
`insns_size` 自己从 `code_off + 12` 读，载荷长度按规范 §F.3 从载荷自己的
`ident` + `size` 字段算，**不读库报的长度字段**，只借库给的地址。宽度表里错一个
码元，后面所有指令的地址就全错位，这里会报洞或越界。反过来，用库的长度去验证
库的长度，库错得多离谱都会"通过"。

**实测（真实 APK，三个 dex）**：**143486 个带字节码的方法、2406 个载荷，
0 处不吻合**；7334 个抽象 / `native` 方法没有字节码，如实计数、不计入检查。
设计文档写的验收门槛是"3000 个真实方法上 0 不吻合"，这次覆盖面是它的 47 倍。

**未做（据实记）**：另两条 M1 验收（`31t` 目标落在 payload 起始、
`try_item.handler_off` 落在 `encoded_catch_handler` 起点）要 CFG 与异常表，
属 M2a 后续；解码投影与渲染函数同样还没做。

### 新增 — DEX（Dalvik Executable）结构模型（M11 的 M1）

**能力**：`.dex` 文件（以及 APK 里的 `classes*.dex`）现在能被**如实列出结构**：
版本、六个池（`string_ids` / `type_ids` / `proto_ids` / `field_ids` / `method_ids` /
`class_defs`）的**头声明数量与实际解析数量**、类/字段/方法三张列式表
（含静态/实例、直接/虚、`code_off`、`SourceFile`、继承关系），以及一份 `notes`。

**边界（明确写在这里，避免被读成"能反编译了"）**：

- **不建 CFG、不解码字节码、不反编译** —— 那是 M2 及其后的里程碑。
- **不是机器码对象模型**：DEX 没有机器架构、没有段权限、没有 `image_base`，
  所以它**不走** `parse_object`，`ObjectKind::Dex` 的 `arch` 恒为 `None`
  （不用占位枚举冒充）。
- **不接依赖库的推断层**：只使用 `droidsaw-dex` 的 `parser` / `ids` / `decode`
  这些事实层模块；`emit*` / `sugar` / `r8_inversion` / `optimize` / `emulator` /
  `xrefs` / `types` 等一律不引用，并有 grep 守卫
  （`crates/bitflip-loader/tests/dex_library_boundary.rs`）防止后来者无意接上。
- **违规但不致命的东西要看得见**：依赖库把"规范不符但 ART 容忍"处记进
  `parse_errors`，我们逐条抄进 `notes`。实测真实 APK 的 3 个 dex 中**有 2 个**
  的 `string_ids` 乱序（违反规范排序要求）—— 既不因此拒绝文件，也不隐瞒。
- **DEX 尚未接进 CLI/UI**：模型与黄金测试先落地，接界面排在 M2 之后。

**测试**：合成样本（按规范逐字段拼出的最小合规 DEX，含 Adler-32 / SHA-1 /
`map_list` / `class_data` / `code_item`，断言"合规样本零 notes"）+
`#[ignore]` 的真实 APK 黄金测试（三个 dex 共 22938 类；`class_defs_size`
与手读值 7643:7643 逐一对齐）。

**性能（实测，含一次被数字否掉的假设）**：`classes.dex`（8.8 MB / 7643 类）
release 下 **1.2 s**，其中依赖库的 `DexFile::parse` 占 1174 ms、我们的
`class_data` 循环只占 **29 ms**；同一条路径在 debug 下约 70 s/dex，
**是 debug 构建的开销，不是算法问题**（先怀疑 O(n²)，release 数字否掉了它）。

**未做（据实记）**：`insns_size` 的"指令 ∪ 载荷恰好铺满"验收推迟到 M2；
解析预算（`Budget`）未接；交叉引用/调用图/反编译未做。

### 修复 — aarch64 反汇编会中止进程（vendored `capstone` + 一处补丁）

**问题**：`capstone` 0.14.0 在 `src/arch/arm64.rs` 里把 capstone C 端给的
**原始**系统寄存器编码 `mem::transmute` 成 `Arm64Sysreg`。那个枚举是稀疏的
`#[repr(u32)]`（只有 `0` 与 49k~62k 段里那些具名编码），而 C 端
（`printMRSSystemRegister`，AArch64InstPrinter.c）**不校验**就写 `op.reg = Val`。
于是任何它没命名的编码都会让 transmute 构造非法枚举值 —— 那是**非展开** panic：
进程直接 abort（退出码 `0xC0000409`），`catch_unwind` **在原理上**接不住。

实测：真实上架 APK 里的 `lib/arm64-v8a/libBugly_Native.so` 跑 `functions` /
`symbol` / `export` **一律中止进程**；同一个库的 x86_64 版本正常出 493 个函数。
差别只在架构。aarch64 是 Android 主 ABI，不修这条，M11 的核心收益对大多数
真实 APK 都拿不到。**上游没有修好的版本可升**（0.14.0 就是 crates.io 最新）。

**修法**：vendored 一份 `capstone` 0.14.0 到 `third-party/capstone/`，
根 `Cargo.toml` 用 `[patch.crates-io]` 指过去。改动只有 3 处、约 20 行：
把"I don't know 的原始编码"**如实保留为 `u32`**，不再伪装成枚举。
理由与升级步骤见 `third-party/capstone/PATCH.md`。

**为什么不用"越界就退化成 `INVALID`"**：那是静默丢数据（§7）；而且合法性判断
需要一张上千条的编码表，只能从 `capstone-sys` 的 bindgen 输出里抄，
正是 §6.11 警告的"照自己的假设拼表"。调查中还查明 **`ARM64_OP_REG_MRS` 只在
capstone 认不出编码时才出现**（认得出时走 `ARM64_OP_SYS`），所以这个变体的语义
本来就是"未映射的编码"，用枚举当载荷才是那个说不通的设计。

**验证**（含反向验证，见 `docs/research/capstone-arm64-abort.md`）：

| 项 | 结果 |
| --- | --- |
| 补丁后：同一个 `.so` | `functions` → 退出码 0，**495 个函数** |
| 补丁后：同一个 `.so` 的 `export` | 退出码 0，42 901 条指令 |
| 补丁后：APK 的 aarch64 成员 | `symbol JNI_OnLoad` → `0xa4f8` |
| x86_64 成员 | 493 个函数，与改动前一致 |
| **撤掉补丁** | 编译期哨兵报 `error[E0308]`；重新构建的 CLI 再跑那个 `.so` → **又回到 `0xC0000409`** |

回归测试：`crates/bitflip-arch/tests/arm64_sysreg_operand.rs`（5 条）。
它钉的是**那 4 个字节**（`ce af 03 d5`）而不是样本文件 —— §0.2 禁止二进制样本
入库，而单条指令的解码不依赖上下文，4 个字节就够复现。

**同一子系统的后续修复**：上面那个 `_ => {}` 兜底（以及内存索引恒为
`None`）是**另一件事**，已在下节修掉。

### 修复 — aarch64 操作数被静默丢掉（系统寄存器 / 屏障 / 预取 / 内存索引）

**问题**：`bitflip-arch` 的 `convert_arm64_operand` 末尾是 `_ => {}`，
把 10 类操作数整个丢掉；同一函数里内存操作数还写死了 `index: None`。
指令文本是按我们自己的操作数表拼的（`render.rs` 刻意不复用 capstone 的
`op_str`），所以丢操作数在输出里**看不出来** —— 不 panic、不报错，只是少给数据：

| llvm-objdump（真值） | 修复前 | 修复后 |
| --- | --- | --- |
| `mrs x19, TPIDR_EL0` | `mrs x19` | `mrs x19, s3_3_c13_c0_2` |
| `msr TPIDR_EL0, x19` | `msr x19` | `msr s3_3_c13_c0_2, x19` |
| `dsb sy` | `dsb` | `dsb sy` |
| `tlbi vmalle1` | `tlbi` | `tlbi <sys_op:153>` |
| `prfm pldl1keep, [x1]` | `prfm [x1]` | `prfm <prefetch:?>, [x1]` |
| `ldr x0, [x1, x2]` | `ldr x0, [x1]` | `ldr x0, [x1+x2*1]` |

第一行是这里最坏的一格：`msr x19` 语法正确、语义是**另一条指令**，
读者没有任何线索能发现少了东西。

**修法**（全在我们自己的代码里，没有再动 vendored 的 capstone）：

1. `convert_arm64_operand` 的 `match` 改成**穷举** capstone 的
   `Arm64OperandType`，只有 `Invalid` 是空分支。以后 capstone 新增操作数
   种类时会直接编译不过（`E0004`），而不是继续静默丢 —— 本次改完确实报了
   两处 `E0004`，那正是想要的效果。
2. `Operand` 增加 8 个变体（`SysReg` / `Pstate` / `Barrier` / `Prefetch` /
   `SysOp` / `FpImm` / `Svcr` / `SmeIndex`），`MemRef` 增加 `index_extend`。
   `ARCH_API_VERSION` 1 → 2。
3. 渲染层补上对应文本；拿不到的用**显式标记**。

**顺带查出的第二个缺陷（同一处代码，独立成因）**：`arm64_modifier` 在
`op.shift` 有值时就 `return`，把同一条指令的 `op.ext` 整个丢掉。capstone 对
`sxtw` 形式的索引与操作数会**同时**填这两个字段（`[x9, w8, sxtw #3]` →
`shift=Lsl(3)` + `ext=SXTW`），于是**有符号扩展被静默渲染成逻辑左移** ——
索引为负时算出的有效地址不同。受影响的有两条路径：带扩展的内存索引，
和 `add x0, x1, w2, sxtw #2` 这类带扩展的寄存器操作数。修法是扩展优先、
移位量照带。

**刻意记下的两处"与 llvm-objdump / IDA 不同"**（是选择，不是缺陷）：

* **系统寄存器用 ARM 的规范编码形式**（`s3_3_c13_c0_2`）而不是名字
  （`TPIDR_EL0`）。名字表上千条、只能从 capstone 的 bindgen 输出里抄，
  正是 §6.11 警告的做法；规范形式信息一点没少，可查、可逆。
* **IC/DC/AT/TLBI 的子操作名未补**，渲染成 `<sys_op:192>` 这类标记（括号里是
  capstone 的判别值）。补名是一张 210 条的表，属后续工作；现在宁可显示
  "我认不出"，也不显示一个**编出来的**名字（§7）。

`prfm` 的预取类型是另一类：**capstone 自己就不给这个操作数**。它的
`ARM64_OP_PREFETCH` 枚举从未被赋值，`AArch64InstPrinter.c` 给 11 种操作数
建了 detail，唯独漏了预取。所以这不是我们丢的，建模成"位置在、值拿不到"，
渲染 `<prefetch:?>`。证据、复核命令、以及可选的"从指令第 `[4:0]` 位取
`prfop`"方案见 `docs/research/capstone-prefetch-operand.md`。

**验证**（真值一律取自 `E:\LLVM\bin\llvm-objdump.exe`，不是我们自己的输出）：

| 项 | 结果 |
| --- | --- |
| 195 KB 的 `libBugly_Native.so`：llvm-objdump 认定的索引内存操作数 | 147 处，**逐个地址**核对我们全部带上了索引（0 处遗漏） |
| 探针 `probe_idx.o`（13 条，覆盖 `sxtw`/`uxtw`/`lsl`/无修饰 + 各类移位） | 逐条与 llvm-objdump 一致 |
| 探针 `probe_ops.o`（系统寄存器 / PState / 屏障 / IC/DC/AT/TLBI / 预取 / `fmov` / C-IMM） | 逐条一致，差异只在我们**刻意标记**的那两处 |
| `ret` 这类无操作数指令 | 不会凭空多出操作数（防"补过头"） |

**没做的**：真实样本上没做**反向**普查（我们给了索引、objdump 没给的情况）。
探针里有对照组，但 147 那个数字只证明了"不漏"，不证明"不多"。

回归测试：`crates/bitflip-arch/tests/arm64_operand_kinds.rs`（6 条）。
字节序列硬编在测试里（§0.2 不许入库样本），真值文本逐条抄自 llvm-objdump。

### 新增 — M11 的 M0：ZIP/APK 容器 + `.so` 直接复用 ELF 通路

M0 的目标是"先把壳打开"，**不做** DEX：识别 ZIP 容器、枚举成员、把
`lib/<abi>/*.so` 交给已有的 ELF 解析与反汇编通路。

**新增依赖**：`zip` 9.0.2（MIT）。刻意**关掉**默认特性 —— 默认会拉进
aes-crypto / bzip2 / deflate64 / lzma / ppmd / zstd / xz / time，而 APK 实测
只用方法 0（stored）与 8（deflate）。用 `deflate-flate2-zlib-rs` 这个纯 Rust 后端，
避免引入 C 工具链、保住单文件可执行。`zip` **没有** `build.rs`，不像 `lief`
那样在构建期联网。

**设计上改动过的两个判断**（都是被实测推翻的，记在这里免得又改回去）：

1. **`MemberStorage` 的分法从"压缩了没有"改成"怎么取内容"**。
   `Plain` / `Compressed` 这个分法逼出一个说不通的格子：ZIP 里方法 0 的成员
   按它算"可直接切片"，可它的数据起点**不在中央目录里**（中央目录只记本地头
   的位置），要另外解析本地头才算得出来。一格语义依赖另一处解析的结果，
   就是分法错了。改成 `Inline` / `Container` 后 ar / `.lib` 恒为 `Inline`、
   ZIP 恒为 `Container`（无论方法号），每个格子都自洽。

2. **`ArchiveMember::offset` 从 `u64` 改成 `Option<u64>`**。
   实测（读 `zip` 源码确认）：`ZipFileEntry::data_start()` 只是一个由
   reader 填的 `OnceCell`，走纯元数据枚举时**恒为 `None`** —— 也就是说
   ZIP 的数据偏移在元数据这条路上根本拿不到。既然拿不到，就用 `None` 报出来，
   不能用 `0`（§7：拿不到就说拿不到）。

**自己写的只有两处，且都不参与解析**（解析全部交给 `zip` crate）：

* `find_eocd`：从文件末尾往前找中央目录结束记录。它存在的唯一目的是把
  ["我只看了文件的一部分"] 与 ["文件坏了"] 分开报。`zip` crate 对这两种情形
  都会返回一个"无效归档"类的错误，不先分这一刀，用户会去修一个没坏的文件。
* `count_central_records`：走一遍中央目录数**实际**条数。非 ZIP64 的结束记录里
  成员数字段是 16 位，一个真有 65538 个成员的文件会**回绕**成 2 ——
  照单全收就会"只列出 2 个成员且不报截断"，界面完全看不出少了东西。

**新增错误变体**：`ParseError::DirectoryNotInRange`（"没读到容器目录"，
与 `Truncated` / `OutOfBounds` 刻意分开）与 `ParseError::NotSupported`
（"这个用法还没支持"；不能复用 `Unsupported`，那要一个真实的 `value`，
凑一个 `0` 进去就是 §7 禁止的）。

**签名只报存在性**。v1 看 `META-INF/*.SF`，v2/v3 看中央目录之前那块。
类型名与字段名一律避开 `valid` / `verified`，只有 `present` ——
"存在签名块"与"签名有效"是两件事。v2/v3 的判据是**结构自洽**而不是只比 16 字节
魔数：最初只比魔数，结果"最后一个成员的数据正好以这 16 字节结尾"的文件会被误判，
单测随手构造一个就复现了。

**真实 APK 实测**（`ah-app-release.apk`，31.5 MB，`com.weavi.ahh` 1.6.3）：

| 项 | 结果 |
| --- | --- |
| 成员枚举 | 1867 个，与独立基准一致 |
| 存储 | 全部方法 8（deflate），`offset` 全部算出（本地头解析成功） |
| 签名存在性 | v1 与 v2/v3 **都存在**（未校验有效性） |
| `functions --member lib/x86_64/libBugly_Native.so` | 解压 → ELF → 反汇编，**493 个函数**、1 个导入桩 |
| `symbol ... --member lib/x86_64/...` | `JNI_OnLoad` 定位到成员内 `0xa330` |

**同一轮发现、但属于既有问题（不是本次引入）**：`capstone` 0.14.0 在
`src/arch/arm64.rs:70` 用 `mem::transmute::<Arm64Reg, Arm64Sysreg>` 转换
MRS/MSR 操作数，遇到超出 `Arm64Sysreg` 取值范围的寄存器号会触发 Rust 的枚举
有效性检查，**非展开 panic → 直接 abort**。对裸 `.so` 与 APK 成员**同样复现**，
即与本次改动无关；且 0.14.0（2026-01-04 发布）已是 crates.io 最新版本，
没有可升级的修好版本。影响面很大：aarch64 是 Android 的主 ABI，
ARM64 的 `.so` 目前**任何**反汇编都会中止进程。这条同时违反 CLAUDE.md §4
"分析器崩溃必须转成错误而不是进程退出"（abort 连 `catch_unwind` 都兜不住）。
细节与处置建议见 `docs/research/capstone-arm64-abort.md`。


### 更正 — M11 改为复用现成库（推翻上一条的"DEX 必须自研"）

上一条记录说"DEX 解析器与 Dalvik 解码器都自己写"。**那个结论错了**，
本次实测后改写。新增 `docs/research/apk-dex-library-survey.md` 记录证据。

**错在方法**：当时的依据是**点名试了几个猜到的 crate 名**
（`dex`/`dalvik`/`smali`），而不是**搜索** crates.io。
改用 crates.io 搜索 API 枚举后立刻找到可用项。教训：候选名要来自枚举，
不是来自"我能想到的名字"。

**实测结论**（样本：真实上架 APK，1867 条目、3 个 dex、37 个 `.so`）：

| crate | 许可 | 实测 |
| --- | --- | --- |
| `droidsaw-dex` 2.0.0 | BSD-3-Clause | 类数 **7643 与手读 header 一致**；指令解码在 **3000/3000** 个真实方法上"恰好铺满 `[0,insns_size)`"；CFG 直接给出 `SwitchCase`/`ExceptionHandler` 等边类型 |
| `apk-info` 1.0.13 | Apache-2.0 | 条目数 / ABI 名单 / multidex **逐项与独立基准一致**；二进制清单还原为 29 392 字节 XML |
| `zip` 9.0.2 | MIT | 解出的 `.so` 是 ELF64 `EM_AARCH64` |

两棵依赖树实跑许可闸门：强著佐权 **0**。

**仍然成立的否决**（别以为一起翻了）：`smali` 是 GPL-3.0-only；
`dex` 冻结在 2021；`dalvik` 不建结构模型；`lief` 构建期下载。
错的只是"因此没有可用轮子"这一步推论。

**划清的一条线**：`droidsaw-dex` 的**反编译层**
（`emit`/`emit_dex`/`sugar`/`r8_inversion`）**不接入** ——
ADR-0018 已判定"类型推断 + Java 源码生成"按定义就是推断，展示即违反 §7。
只用 `parser`/`decode`/`cfg`/`xrefs`/`mutf8`/`opcodes` 这些事实抽取层。

**顺带纠正一处参考文档**：规范写 `string_ids` 必须升序，
但实测**真实上架 APK 就是乱序的**（`OutOfOrder { pool: StringIds }`）。
所以这类检查只进 `notes`，既不拒绝文件也不静默丢掉。

**这次也纠正了我自己的一个错误**：第一版覆盖率检查把
`fill-array-data` 的长度算成 `4 + data.len()*element_width/2`，
得到 9/3000 不吻合，一度像是库的 bug。停查后确认是**我重复计了
`element_width`**（`data` 存的就是原始字节）。改对后归零。
过程记在调查报告 §2.2，因为"差点把自己的 bug 报成别人的"值得留痕。

### 新增 — APK / DEX 自研逆向核心的设计与格式参考

- `docs/APK-DEX-DESIGN.md`（新）：M11 的分层、里程碑拆分与验收标准。
- `docs/research/dex-apk-format-reference.md`（新）：字节级实现参考
  （header/`map_list`/id 表/`class_data` diff/`code_item`/try-catch/指令表/
  payload/AXML/arsc/签名块），含 13 项显式 `UNVERIFIED` 与实现陷阱。
- ADR-0019（新）：DEX 解析器与 Dalvik 解码器**自研**（`smali` 是 GPL-3.0，
  `dex` 2021 年冻结，`dalvik` 只是反汇编器 —— 没有可用的轮子）；
  APK 容器用 `zip`（MIT）；**里程碑按价值/成本排，APK 容器先做**。

**用真实样本纠正了三处范围假设**（样本：本机两个 APK，1867 / 1624 条目）：

| 原以为 | 实测 | 影响 |
| --- | --- | --- |
| 现代 APK 用 v041 容器 DEX | **6 个 dex 全是 `dex\n035\0`、`header_size = 112`** | 砍掉 v041 分支（格式里最容易全错的一处） |
| `.so` 可能未压缩、需对齐 | **全部 DEFLATE（37/37、20/20），STORED 为 0** | 必须解压；不做"直接 mmap `.so`"与 zipalign 校验 |
| ABI 是 Soong 那 5 个 | 还有 legacy **`armeabi`** | ABI 名单要补 |

同时确认 `.so` 是 `EM_AARCH64` 的 ELF64（**可直接复用既有 ELF 路径**）、
`AndroidManifest.xml` 是二进制 XML（type `0x0003`）、`resources.arsc` 头与文档一致。

**硬约束（实测而非推断）**：capstone 0.18 只有 18 个架构，**没有 Dalvik/ART** ——
Dalvik 解码器必须自写（`Decoder` trait 只有 `spec()` + `decode_one()`，边界很窄）。

### 修复 — `info` 在大目标上慢一个数量级（10.8s → 0.65s）

> 定位与实测数据见 `docs/PERFORMANCE.md`。

- **展开信息改为推迟解码。** PE 的 `.pdata` 每个函数一条，
  `owo-terminal.exe` 有 **417,629** 条，而 `parse_pdata` 原本对**每一条**都调用
  `parse_unwind_info` —— 1.2 秒。`info` 一个字段都用不到它（`info` 甚至不反汇编）。
  现在建表时只读三个 RVA（函数边界要用的），解码推迟到 `Session::analysis_cached`
  里真正需要帧大小时。`parse_object` 实测 **1.247s → 155ms**。
  - `UnwindEntry` 新增 `deferred: bool`，与 `decoded: None` **必须分开**：
    前者是"还没问"，后者是"问了但解不出来"。合成一个 `None` 就是用"未知"
    冒充"没有"（§7）。
  - ELF 的 `.eh_frame` 填 `deferred: false` —— 它的 CFI 解码是"M3 还没做"
    （待实现的特性），不是"推迟到需要时做"（性能手段），混起来会掩盖事实。
- **同一个文件读两遍改为读一遍。** `parse_target` 读一遍用于解析，之后判断
  "要留字节"时再读一遍存进 session —— 201 MiB 的目标就是 402 MiB 的 I/O。
  现在读一次共用，且读之前先检查大小上限（避免"读 600 MiB 再拒绝"）。
  `parse_target` 里"没有字节"的两种原因也分开说：超上限是一种结论，
  读盘失败是另一种。
- **防回归**：`unwind_golden.rs` 新增 `parse_defers_unwind_decoding_until_asked`。
  必须有人守着这个特性 —— 把解码挪回 `parse` 会让性能悄悄退化，
  而**所有功能测试仍然是绿的**（结果一样，只是慢）。

release 实测（201 MB / 425,448 函数）：

| | 改前 | 改后 |
| --- | --- | --- |
| `info` | 10.8s | **0.65s** |

尚未解决（据实记录）：`Session::open` 仍要读整个文件，而这个目标的解析器
实测**最多只需要读到偏移 `0x3b0`（944 字节）**。要改需要动 `Arc<[u8]>`
的所有读点或引入 mmap，属于独立的架构决策，见 `docs/PERFORMANCE.md` §5。

### 新增 — 依赖选型调研与许可证闸门

> 回答"有没有现成的轮子补上架构/格式/反编译器的缺口，许可能不能接受"。
> 完整结论见 `docs/DEPENDENCY-DECISIONS.md`，原始实测输出见
> `docs/research/dependency-probe-evidence.md`。

- **`scripts/check-licenses.py` + `scripts/test-check-licenses.py`（新）**：
  依赖许可闸门，已接入 `scripts/preflight.ps1`。对 `cargo metadata` 的**已解析依赖树**
  做 DENY 检查（GPL/LGPL/AGPL/SSPL）。用 DENY 而不是 ALLOW 列表是有意的：
  ALLOW 列表会在第一次遇到写法差异（`MIT/Apache-2.0` 与 `MIT OR Apache-2.0`）时误报，
  而**会误报的闸门会被关掉**，那比没有闸门更糟。
  逻辑本身有 21 条测试锁住，因为"永远说干净"的闸门和"什么都没做"的闸门无法区分 ——
  写这条闸门时确实踩了两个 bug：OR/AND 切分把 `LGPL-2.1-or-later` 误判为干净
  （`\bOR\b` 会把 `-or-later` 切开），以及对 `r-efi` 的
  `MIT OR Apache-2.0 OR LGPL-2.1-or-later` 误报（那一支可以选 MIT，不是违规）。
- **当前依赖树 191 个 crate，零个受限许可。**
- **`CLAUDE.md` §5** 补上许可检查步骤与此前三个"很对口但许可不可用"的轮子
  （`exe` GPL-3.0、`dotnetdll` GPL-3.0+、`smali` GPL-3.0-only）。

### 调研结论要点（供后续里程碑取用）

- **架构扩展有现成轮子**：`wazabin-sleigh` + `-precompile` 已在**本机实测**
  解出 x86_64 指令（MIT / MIT AND Apache-2.0）。Ghidra 的 SLEIGH 规范覆盖
  **39 个语言**（含 Dalvik 与 JVM），远超 capstone 的 9 种。
  保留意见：上游仓库极新（2026-08 创建、0 star），spec 在 `build.rs` 现场编译，
  本机实测编译超过 10 分钟 —— 先做 spike，不要直接变成主路径。
- **Mach-O 有现成轮子**：`object` 0.40（Apache-2.0 OR MIT）实测能解 fat/universal 头
  （按规格合成 FAT_MAGIC，正确识别 x86_64 与 arm64 两个切片），
  另有代码签名与 dyld cache 支持 —— 后两者 `goblin` 没有。
  ⚠️ 但它的 README 明确写了**不适用于恶意样本分析**，与我们的用途冲突，
  必须配套资源限额（理由与方案见 `docs/DEPENDENCY-DECISIONS.md` §2.3）。
- **反编译器有轮子但会违反 §7**：`ghidra-decompiler`（Apache-2.0、纯 Rust，
  本机实测可编译可运行、常量折叠正确）会输出 `func_0x00000000` 这种占位名，
  且在带分支的输入上**静默丢掉整段逻辑**而不提示 —— 正是 §7 最怕的静默错误输出。
  结论：先做隔离验证，不直接接入。
- **`lief` 不是因为许可被否**：它的许可是干净的 Apache-2.0，
  真正的问题是**构建期联网下载预编译二进制** + C++ FFI。这条理由必须记录，
  否则将来会有人只看许可证再提一次。
- **DEX 是唯一没有可用轮子的缺口**：`dex`（MIT）冻结于 2021，
  `smali` 是 GPL 且是这一带最活跃的。建议 M11 先做"APK 解包 + 复用 ELF 路径"
  （APK 就是 ZIP，`zip` 9.0.1 是 MIT 纯 Rust），DEX 单独排后。

### 新增 — 伪代码导出（`pseudo-c`）：反编译器的**有界子集**

> 决策与理由见 `docs/DECISIONS.md` ADR-0018 与 `docs/DECOMPILER-SCOPE.md`。
> 一句话：**这不是反编译器**，它只做单基本块内的表达式还原，不做控制流结构化。

- **`bitflip-analyze::pseudo`（新模块）**：把单个基本块内的指令翻成 C 风格语句。
  产出的硬约束（都有测试锁住）：
  - 每条语句带来源指令地址，可逐句回查机器码；
  - `structured` 字段恒为 `false`，且输出里**必定**带 `FlatGoto` 说明 ——
    条件跳转以 `if (cond) goto` 出现，不是还原出的 `if/while/for`；
  - 没有名字的函数输出入口地址，**不编造** `func_xxx`（测试断言输出不含 `func_`）；
  - 间接跳转写明"目标未知（需要数据流分析）"，不编地址；
  - 翻不出来的指令写成注释并**计数**（`PseudocodeFunction::untranslated`），
    不填默认值、不静默丢弃；
  - 内存访问宽度取自 `MemRef::size`（是事实，不是猜）；宽度不是 1/2/4/8 时
    如实标注字节数，不硬塞一个 C 类型。
- **寄存器名改为注入**（`bitflip_analyze::RegisterNamer`）。原因是实测踩到的一个真 bug：
  本模块最初硬编码 `0 => rax, 1 => rcx, …`，假定 `RegId` 是从 0 连续编号的序号，
  但它是 **capstone 的原始编号**，于是真实目标上 `RegId(44)`、`RegId(231)` 全判成未知，
  绝大多数指令退化成"无法翻译"。权威来源是
  `bitflip_arch::backend::CapstoneDecoder::register_name`，本模块**不维护名字表**。
  回归测试：`namer_is_asked_with_raw_capstone_ids_not_a_compact_index`。
- **`ExportFormat::PseudoC`**（`--format pseudo-c`）：CLI / HTTP 导出自动可用。
  头部说明区明确写出"这是有界子集，不是反编译器"与"请对着反汇编核对"。
- **`Disasm::decode_range`**：取一段地址区间内已解码的指令，复用与
  `Disasm::render` 相同的解码路径（不另开一条解码，避免"伪代码与反汇编列表不是同一条指令"）。
- **`bitflip-analyze` 新增 12 个测试**。

### 文档 — 与 IDA Pro 的格式/架构覆盖对照

- **`docs/FORMAT-COVERAGE-VS-IDA.md`（新）**：BitFlip 与 IDA Pro 在**文件格式**与
  **处理器架构**两个维度上的逐项对照，数据取自 Hex-Rays 官方文档。结论按"是否缺"
  分三类列出（文件格式缺口、架构缺口、以及**反编译器**覆盖缺口 —— IDA 的
  反汇编器覆盖面远大于其反编译器），并标注每一项的排期归属。
- **`docs/DECOMPILER-SCOPE.md`（新）**：D5（是否做反编译器）的拆解决策。
  关键论据：源码→二进制是**多对一**映射，其逆不唯一，结构化选择"在最终意义上
  是不可判定的"；SAILR 实测 7 355 个函数，DREAM 做到零 goto 但结构相似度从
  22.5 恶化到 45.99 —— **"消除 goto"不是变好而是变差**。
- **`docs/research/decompiler-architecture-survey.md`（新）**：反编译器架构综述，
  逐条附来源 URL。
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

写回**未做**，见 `docs/PLAN.md` §M9 的"完成情况"。这里记已落地的导出。

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
  真值来自独立的 `objdump -d -M att`：对拍 6000 条，逐字相同 5859 条，已记录的解码层差异 **141** 条，
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

### 新增 — M9：差分视图（两个同族二进制的函数 / 节表 / 符号差异）

指令级**逐条对齐**未做（现在按函数粒度判定内容是否相同），见 `docs/PLAN.md` §M9 的"未做"。

- **`bitflip-core::diff`（新模块）**：`DIFF_FORMAT_VERSION = 1`。范围 `functions`（默认）/
  `sections` / `symbols` / `all`；类别 `added` / `removed` / `changed` / `moved` / `unchanged`；
  可按类别过滤、可设条目上限（超限截断并记账）。
- **地址归一化是中心问题，不是实现细节。** 两版镜像基址几乎总不相同（fixture 里差 `0x40000000`），
  裸比虚拟地址会得到"每个函数都变了"——条理清楚、字段齐全、**全错**。默认按 RVA 比，
  并把**归一化方式连同两侧实测基址写进输出头部**（文本注释头 / JSON `normalization` +
  `v1_image_base` + `v2_image_base`）。没有基址时（`.o` 这类）归一化判为**不可用**，
  只用名字匹配，并在 `notes` 里写明"地址维度未参与比对"。
- **两档指纹**，因为"没变"/"搬了家"/"搬了家又改了"是三件不同的事：
  **强指纹**把落在镜像地址范围内的字面量换成"它指向的 RVA"（位置无关）；**弱指纹**把所有
  十六进制字面量抹成占位符（只留指令形状）。函数体里嵌着被调用者的地址，被调用者挪了位置时
  调用处的绝对地址也会变 —— 只有忽略地址那一维，"搬家"才认得出来。
- **普通立即数原样保留**（不进归一化）：早期把每个字面量都减掉函数起点，于是 `sub rsp, 0x28`
  变成 base-dependent 的值，两版基址不同就让每个带小立即数的函数被判成"改动"。
  保留也是必需的 —— 抹平会让 `add eax, 0x5eed` 与 `add eax, 0x1234` 指纹相同（漏报）。
- **匹配顺序本身是判据**：①同名（先看归一化地址是否也相同）→ ②未命名且归一化地址与内容都相同
  → ③剩下的是新增与删除。第一版**先按地址配对**，把"被删的函数"与"恰好补在那个 RVA 上的新函数"
  配成一条含糊的"改动"。合并阶段还有一条守则：配对不一对一（同一侧多个不同函数对上另一侧同一个）
  说明是巧合，**拆成明确的删 + 增**并记进 `notes`。
- **每个条目交代配对判据** `match_basis`（`name+address` / `content+size` / `name-only` /
  `address-only`）；内容维度是**三态**（Same / Different / Unknown）—— `None == None`
  曾被当成"内容相同"，于是凭空宣称"内容逐条相同"并把不相关函数配成一对"移动"。
- **账目闭合且可自检**：每个条目恰好落进一个桶，`len(entries) == totals.total()` 且逐条重数一致；
  按类别过滤发生在**记账之后**（否则"比了多少条"这个分母会被污染成 1）。
- **CLI `bitflip-cli diff OLD NEW`**：`--scope/--only/--max-entries/--format text|json/--out/
  --force/--summary`。`--out` 默认拒绝覆盖，父目录不存在即报错。**刻意不提供**
  `--arch`/`--base`：一次开两个文件，一份覆盖参数套到哪个上都没有正当答案。
- **HTTP `GET /api/diff?against=<path>&scope=&only=&entries=`**：返回 `DiffReport` JSON。
  **这是新增的一条"读另一个文件"的能力**，边界写在端点文档里：挂在同一条 `require_token` 下；
  只接受**已存在的常规文件**（目录/特殊文件拒绝，并明确说"不是常规文件"，不让它伪装成格式问题）；
  路径原样使用**不做**规范化重写（规范化会把符号链接的目标藏起来）；只读，从不写回。
  条目默认 2048、硬上限 20000（HTTP 响应要先过内存与网络）。

**测试与门禁**：

- `scripts/gen-diff-fixture.py`：编译两个源文件版本（`--image-base` 不同），真值由
  `llvm-nm --print-size` 对两个符号表做集合运算得到 —— **差异是编译器与链接器实际产出的**。
  受控差异四类俱全（新增 / 删除 / 同 RVA 不同内容 / 未变对照组）。生成器自带自检：
  符号在文件里 ≠ 分析器看得见一个函数（早期 `df_removed` 被 `-O1` 内联，`llvm-nm` 照样列出它，
  端到端测试因此红在**差分实现**上，方向完全错误），现在用 `llvm-objdump -d` 的函数标签核对。
  fixture 已接入 `scripts/gen-fixtures.ps1` —— 否则差分冒烟会 SKIP，而 SKIP 会读成通过。
- `crates/bitflip-core/tests/m9_diff.rs`：12 条端到端，**逐条断言真值文件**（不抄数字，
  抄进来的数字会随 fixture 重新生成而失效，失效方式是"测试还在绿"）。
- `crates/bitflip-core/src/diff.rs` 单测：直接钉两个归一化函数（bug 都出在这一层）。
- `scripts/smoke-diff-http.ps1`（45 项断言，已接入 `preflight.ps1`）：起真实服务进程打真 HTTP。
- 全量 `cargo test --workspace`：937 passed / 0 failed / 5 ignored。

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
### 修正 — 性能预算的表述：按"函数数"而非"文件大小"

用 `D:\owo-terminal\owo-terminal.exe`（Electron 应用，201 MB）做真实大文件实测，
**推翻了 `docs/BIG-FILE-TESTING.md` 里"按文件大小线性外推"这个模型**：

| 目标 | 大小 | 函数数 | `info` | `functions` | 每千函数 |
| --- | --- | --- | --- | --- | --- |
| `MRT.exe` | 220 MB | 1 751 | 1.9 s | 23.8 s | 13.6 ms |
| `owo-terminal.exe` | 201 MB | **425 448** | 10.8 s | **301.1 s** | **0.71 ms** |

文件更小却慢 12.6 倍。按"每千函数"归一，owo-terminal 的单位成本反而**低 19 倍** ——
所以这不是实现退化，而是这类文件把 Chromium + V8 + Node 全静态链了进来，函数数比
普通原生程序高两个数量级（243 倍）。

原预算写"打开 100MB PE 首扫 < 15s"，会让人以为 201 MB 该在 15 s 上下，实测 301 s。
**真正决定耗时的量是函数数与指令数**，文件大小只是它们的间接代理，而 Electron 这类
目标上这个代理关系已经失效。`PLAN.md` §5.1 与 `BIG-FILE-TESTING.md` 已改为按函数数
表述（约 0.7 ms/千函数）。

本次只动文档，未改代码。另记一条待查项：`info` 在 201 MB 上是 10.8 s，明显高于
既有的 1–2 s —— 它只嗅探前 8 MiB，所以这 10.8 s 花在建地址空间/列节表上，
与函数数无关，值得单独定位。
### 变更 — `format/elf` 内部拆分（承接上一节的模块化）

- **`elf.rs`（2114 行）拆成五个文件**：`mod`（磁盘上的布局：常量、`sh_type`/`p_type`
  等取值、三个头部结构体及取值方法）、`parse`（编排：唯一入口，按"段 → 节 → 符号 →
  重定位 → 动态 → 展开"顺序调用）、`sym`（符号表 / 重定位表 / 重定位分类）、
  `dynamic`（`.eh_frame` FDE、`PT_DYNAMIC` 依赖、导出推导）、`tests`。
  与 PE 同法，同样是**纯搬移**：20 项导出逐字节相同，测试数守恒（938 passed）。
- **拆分暴露出一处原本隐式的依赖**：`use super::*` **不跨模块边界**，所以测试与
  兄弟模块必须逐个点名它们依赖的内部函数。`tests.rs` 里因此新增了一段显式 `use`。
  这不是拆分的副作用，而是把"测试能用哪些内部函数"从"碰巧都在同一个文件里"
  变成了写下来的事实。
- **子模块命名避开 Rust 关键字**：`dyn` 是关键字，最初的 `dyn.rs` 直接编译失败
  （`expected identifier, found keyword`），改名为 `dynamic.rs`。
- **可见性不是一刀切**：`mod.rs` 里的项对**兄弟模块**可见需要 `pub(crate)`
  （`pub(super)` 只能让父模块看见），而入口要供集成测试调用则是 `pub`。
  这条在 `mod.rs` 的注释里写清楚了，免得后来者"统一成 pub(super)"再踩一次。
- `format/coff`（约 600 行）**不拆**：拆分带来一层跳转，只有文件大到需要导航时才
  划算。PE（2770 行）与 ELF（2114 行）到了那个体量，COFF 没有。

### 新增 — macOS 沙箱策略、SBPL 静态检查、清理脚本

- **`docs/macos-macho-fixture.sb.in`**：在 macOS 上生成 Mach-O / `.app` / IPA
  测试 fixture 与跑测试所需的 Seatbelt 策略（SBPL）。
  写入策略而不是"直接跑"，是因为默认沙箱要么什么都不给（工具报的权限错指向
  完全无关的地方），要么给成 `(allow default)`（等于没有沙箱）。
  文件里每条权限都写了用途，末尾还列了**故意没给**的能力及原因
  （不跑被分析目标、不做真签名、不碰真机、不写 `/Library`）。
  路径用 `__REPO__` / `__TMP__` / `__HOME__` 占位而不是写死：`subpath` 匹配不到
  任何东西时**不会报错**，只会"什么都不授权"，写死路径在换机器时会静默失效。
  另记录了现状：`scripts/` 里的 fixture 生成脚本目前是 Windows 专项的
  （硬编码 `E:\LLVM\bin` 等），跨平台改造是使用这份策略的前置条件。
- **`scripts/check-sandbox-profile.py`**：SBPL 的静态检查。捕两类错：括号不配对
  （macOS 会拒绝加载**整个**沙箱）与残留占位符（策略静默失效）。
  它**明确列出自己查不了的东西**——谓词是否真的匹配、策略是否真的在拦，
  都需要 macOS 实跑；不会让人把"静态检查通过"误读成"策略正确"。
  已接入 preflight，以 SKIP 而非静默通过的方式处理"还没有策略文件"的情况。
- **`scripts/clean.ps1`**：按 CLAUDE.md §3 的顺序回收磁盘（先 `deps/*.pdb`、
  再 `incremental/`、最后旧冒烟日志），带 `-WhatIf` 预演与写入探针自检。
  **不删 `deps/` 本体**（20 GB，删了要全量重编）。本次实跑回收 7.3 GB
  （`.cargo-target` 20.4 GB → 13.1 GB），清理后 `cargo build --workspace --tests` 仍为 0。
- `.gitignore` 补了临时提交信息文件的模式：此前只忽略 `/.commit-msg.txt`，
  而实际写法五花八门（`temp-commit-msg.txt` 等），**任何一个没被忽略的名字都会被
  `git add -A` 顺手提交进去**。

### 新增 — 里程碑：M11（Android：APK/DEX）与 M12（Apple：Mach-O/`.app`/IPA）

面向计划的变更，还没有代码。记在这里是因为它改变了"哪些能力会被做、按什么顺序做"。

- **M11 · Android：APK / DEX**（用户要求"完全逆向"）。先把 APK 当 ZIP 打开、
  枚举成员（`classes*.dex` / `AndroidManifest.xml` / `resources.arsc` / `lib/<abi>/*.so`），
  其中 `lib/*.so` **就是 ELF，走既有路径即可分析** —— 这一条几乎零成本，先做，
  让第一版就有真实价值。随后是 DEX 解析与 Dalvik 字节码解码。
- **M12 · Apple：Mach-O / `.app` / IPA**（用户要求"完全逆向"）。
  **IPA 依赖 Mach-O，必须先做完 Mach-O**：`.ipa` 只是 ZIP，里面是 `.app` 目录，
  目录里是可执行文件 —— 没有 Mach-O 解析，IPA 支持就只是一个会列出文件名的解压器。
- **M10 保持"未来 TODO 池"不变**，其中"Mach-O / `.app` / fat"一条移入 M12。
- **M11 与 M12 互不依赖，可并行。**

**为什么单列里程碑而不是塞进 M10**：这两项是**用户明确要求的交付**，而 M10 是
"不承诺、按需排序"的池子；混在一起会让"没排期"和"不承诺"变成同一个状态，用户无从
知道它到底做不做。更重要的是它们**都不是"再加一种容器"**：M11 引入**基于寄存器的
字节码**（无栈帧、无机器码、无重定位），要动 `bitflip-arch` / `bitflip-analyze` 的
执行模型假设；M12 引入**目录作为可打开目标**（本项目第一次），要动 `Session` 的
打开路径。把它们写成一条 TODO 是用格式的相似性掩盖工作量的不相似性。

**非目标写死了**（避免"完全逆向"被理解成无限范围）：不做 Smali ↔ DEX 双向转换、
不做 APK/IPA 重打包与重签名、不做 Java 源码级反编译、不做 `objc_msgSend` 目标的
静态臆测（运行期决定就如实标注为运行期决定）。

**接口预算**：`docs/ARCHITECTURE.md` §3.2 列出了新增格式要动的地方 —— 预期的四处
扩展全在**容器与执行模型**层面（那是通用层的正当职责），没有一处是"为某个格式的结构
打特判"。实施中若出现第五处且只服务一种格式，说明该格式的东西漏进了通用层。
新增风险 R10–R12（硬套既有流水线、容器层攻击面、fixture 生成不了时静默跳过）。

### 变更 — 逆向核心模块化：通用层与格式层的边界

改动的**行为变更量为零**，这一点有硬证据（见末尾）。这一节记的是"边界"本身，
因为它决定了以后加一种格式要动哪些文件。

- **`bitflip-loader` 新增 `format/`**：PE / COFF / ELF 各占一个子模块。
  在这之前 `pe.rs`（2770 行）、`elf.rs`（1951 行）、`coff.rs`（584 行）与通用文件
  平摊在 `src/` 下，"哪个是通用的、哪个是某个格式的"只能靠文件名猜。
- **`format/pe` 按关注点拆成五个文件**（`mod`：映像骨架；`import`：导入/延迟导入/导出；
  `reloc`：基址重定位；`unwind`：`.pdata` + `UNWIND_INFO`；`inspect`：.NET CLI 头与
  COFF 符号表）。这是**纯搬移**，逐字节校验过。
- **格式派发收敛到唯一入口 `bitflip_loader::parse_object`**。`match kind` 曾在
  `bitflip-core::session`（打开目标、打开归档成员）与 `bitflip-signature::generate`
  三处各写一遍 —— 漏改一处的后果是**静默的**：新格式会走进兜底分支，被报成
  "不是可分析对象（识别为 X）"，看起来像识别出了问题。配套加了 `has_parser(kind)`：
  调用方现在只回答两件事 —— 这个类别有没有解析器、失败怎么表述。
- **`UnwindEntry` 新增四个格式无关访问器**（`frame_size` / `saved_registers` /
  `frame_register` / `notes`）。此前 `bitflip-analyze::frames` 直接 `use PeUnwindInfo`，
  于是通用分析层知道 PE 的 opcode 怎么编码；现在它一个格式类型名都不出现。
  新增了 `ParseError::NoParser`，替掉"没有解析器"与"某个字段的取值不支持"混用
  （后者要指向具体字段与数值，硬凑一个 `value = 0` 正是 §7 禁止的）。
- **`format/elf` 与 `format/coff` 尚未内部拆分**。这不是遗漏而是取舍：拆分带来一层
  跳转，只有文件大到需要导航时才划算；而且一次只搬一个文件，出问题能立刻定位。
  ELF 的拆分与 PE 是同一类工作，单独一轮做。

**"零行为变更"的证据**：把改动 stash 掉、用 HEAD 版本与改动版本对
`m3-mingw-static.exe` / `elf-aarch64.exe` / 两个 diff fixture 各导出
`asm-intel` / `asm-att` / `json-functions` / `json-symbols` / `dot-cfg` 共 20 项，
去掉自述头里必然变化的时间戳后**逐字节相同**。这一条必须做：拆前拆后测试都绿是正常的，
"测试没红"提供不了"只动了位置"的证据。

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
  并据此区分 `ar` 与 `msvc-lib`）、Mach-O 与 fat 容器（仅识别，解析排期见 M12）。
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
- Mach-O / `.app` bundle / fat 容器只识别不解析（排期 M12，见 ADR-0017）。
- APK / DEX 尚不支持（排期 M11）。APK 里 `lib/<abi>/*.so` 是普通 ELF，
  但这些字节目前不会被从 APK 里取出来 —— 容器层还不认识 ZIP。
- 本机 `.githooks/pre-commit` 在受限沙箱里无法启动（git 通过 `sh.exe` 跑钩子被拒），
  因此它是第二道防线；每次提交仍必须手工执行 `git diff --cached --name-only | Select-String '^temp/'`。
- `scripts/*.ps1` 必须保持 ASCII：Windows PowerShell 5.1 会把无 BOM 的非 ASCII 脚本
  按 ANSI 读取，导致解析失败（已在 `scripts/cargo.ps1` 顶部注明）。
- Windows PowerShell 5.1 的 `param()` 只能声明一个参数：声明第二个（哪怕未使用）会让
  `ValueFromRemainingArguments` 错位（`test --workspace` 变成 `--workspace '' test`）。
