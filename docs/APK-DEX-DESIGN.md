# APK / DEX 逆向核心 —— 设计

> 状态：**设计**（未实现）。字节约束见
> [`docs/research/dex-apk-format-reference.md`](./research/dex-apk-format-reference.md)；
> 现成库实测证据见
> [`docs/research/apk-dex-library-survey.md`](./research/apk-dex-library-survey.md)。
> 相关：ADR-0019（含更正）、`docs/DEPENDENCY-DECISIONS.md` §2.4。
>
> **更正**：本文初版标题是"**自研** APK / DEX 逆向核心"，§1 论证的是
> "必须自研"。那个前提**错了**（见下），已改写。

## 1. 用现成库，只自研缺口

初版的论证是"没有可用的轮子"，依据是**点名试了几个猜到的 crate 名**。
改成**搜索 crates.io 枚举**之后，可用的宽松许可库是有，而且实测能跑：

| 层 | 用什么 | 许可 | 实测结论 |
| --- | --- | --- | --- |
| APK 容器 | `zip`（或 `apk-info-zip` 抗畸形包） | MIT / Apache-2.0 | 解出的 `.so` 是 ELF64 `EM_AARCH64` |
| 清单 / 资源 | `apk-info` / `apk-info-axml` | Apache-2.0 | 二进制清单还原成 29 392 字节 XML |
| DEX 结构 + 解码 + CFG | `droidsaw-dex`（**只用事实层**） | BSD-3-Clause | 类数 7643 与手读 header 一致；解码 3000/3000 "恰好铺满" |
| **native 库** | **既有 ELF 路径** | —— | APK 里的 `.so` 就是普通 ELF，零新代码 |

**仍然成立的否决**（这几条不变，别因为"改了结论"就以为它们也翻了）：
`smali` 是 GPL-3.0-only；`dex` 冻结在 2021；`dalvik` 不建结构模型；
`lief` 构建期下载。错的是"所以没有轮子"这一步推论，不是这几条本身。

**必须划清的一条线**：`droidsaw-dex` 的**反编译层不接入**。
它的 `emit`/`emit_dex`/`sugar`/`r8_inversion` 做类型推断与 Java 源码生成，
ADR-0018 已判定这类输出按定义就是推断，展示即违反 §7。
好在这些是并列的公开模块，**只用 `parser`/`decode`/`cfg`/`xrefs`/`mutf8`/`opcodes`**。

**引用现成库的条件**（都来自实测，不是形式条款）：

1. 这两个库**极新**（首发 2026-04，下载 945/611），发布的 crate **不含测试**
   （`exclude = ["/tests"]`）。所以**必须配项目自己的黄金测试** ——
   对着真实 APK 断言类数/方法数/覆盖率等不变量，不能只信库的自述。
2. 几个 crate 声明了许可但**没随包发 LICENSE 文件**；
   Apache-2.0 的分发义务要求附原文。
3. 新依赖必须过 `scripts/check-licenses.py`（两棵树已实跑：强著佐权 0）。

## 2. 真实样本实测（先看现实，再定范围）

样本：`C:\Users\Administrator\Downloads\ah-app-release.apk`（1867 条目）与
`base.apk`（1624 条目）。**这些数据推翻了三个我原本会写进设计的假设：**

| 实测 | 数据 | 对设计的影响 |
| --- | --- | --- |
| **DEX 是 035，不是 041** | 6 个 dex 全是 `dex\n035\0`、`header_size = 112` | **v041 容器 DEX 不做**（省掉整个 §1.3 的"偏移相对容器"改写，那是设计里最容易全错的一处） |
| **native 库全是 DEFLATE** | 压缩方法 `{8: 37}`、`{8: 20}`，STORED **0 个** | 必须解压才能拿到 ELF；**不做**"从 APK 直接 mmap `.so`"这条路 |
| 因此对齐/16KB 页要求不适用 | 压缩条目的 `header_offset % 4096` 无意义 | 不实现 zipalign 相关的对齐校验 |
| **`armeabi` 仍存在** | 有 `arm64-v8a / armeabi / armeabi-v7a / x86 / x86_64` | 文档里 Soong 的 ABI 列表**不完整** |
| `.so` 就是普通 ELF64 | `EM_AARCH64 (183)` | **可直接复用现有 ELF 路径** |

## 3. 分层：把"能复用"的先做掉

APK 里有两类东西，成本差一个数量级：

```text
AndroidManifest.xml   二进制 XML（AXML）      → 新解析器（中）
resources.arsc        资源表                  → 新解析器（中）
classes*.dex          Dalvik 字节码           → 新解析器 + 新解码器（大）
lib/<abi>/*.so        ELF 共享库              → 已有 ELF 路径，零新代码
```

**`lib/<abi>/*.so` 是纯赚的**：APK 里的 native 库就是 ELF，而 ELF 路径已经能解析
（PE/ELF 已支持）。只要能把成员解压出来，原生库的逆向能力**立刻可用**，
不需要等 DEX 那一大块。

所以里程碑按"价值/成本"排序，而不是按格式复杂度排序。

## 4. 架构接入

### 4.1 已有的抽象够用（不需要改分层）

`ContainerKind` 早就为"一个文件多个对象"留了位（`Ar` / `MsvcLib` / `Fat`），
`ObjectKind` 是"单个对象是什么格式"。APK 正好是这两者的组合：

```text
ContainerKind::Zip        ← 新增（APK 就是 ZIP）
ObjectKind::Dex           ← 新增
ObjectKind::Elf           ← 已有，APK 里的 .so 直接命中
```

`Fat` 当时的注释就说"抽象要提前留出来"。这里**不需要**发明新的分层概念 ——
APK 的成员是**有名字、格式各异**的，与 `Ar` 同构（只是成员格式不单一），
所以复用 `members` + `member_kind` 那套即可，只是 `member_kind` 变成"逐个成员判"。

### 4.2 需要新增的概念

1. **`Arch::Dalvik`**。`Arch` 现在 9 个变体，都是原生 ISA。Dalvik 是寄存器机，
   不是 ISA —— 但它占的是"用什么解码器"这个位置，所以进 `Arch` 是对的位置。
   `Mode`/`Endian`/`ptr_size` 对 DEX 没有意义，`ArchSpec` 要能表达"这些字段不适用"
   （或在 `Arch::Dalvik` 分支里固定成有意义的值，并在 UI 上不显示）。

2. **新的解码后端 `DexDecoder`**。这是**硬约束**，不是偏好 ——
   实测 capstone 0.18 只支持 18 个架构（ARM/ARM64/MIPS/X86/PPC/SPARC/SYSZ/XCORE/
   M68K/TMS320C64X/M680X/EVM/MOS65XX/WASM/BPF/RISCV/SH/TRICORE），**没有 Dalvik**。
   好在这条边界很窄：`Decoder` trait 只有 `spec()` + `decode_one()`，
   `decode_many` 有默认实现。

3. **合成地址空间**。这是唯一需要认真想的一点。DEX 里没有虚拟地址：
   - 数据用**文件偏移**；
   - 代码用 **code unit 索引**（相对 `insns` 起点，2 字节一个单位）。

   项目约定"内部一律 `u64`"，所以仍用 `u64`，但必须是**明确的合成地址**，
   例如 `addr = (dex_index << 48) | code_item_off << 16 | code_unit_pc`。
   要求：
   - 合成规则写进文档，并且**反解函数有单测** —— 否则用户看到
     `0001000000001234` 会以为是个真实地址；
   - UI 上显示时反解成"`classes2.dex` 内第 N 条指令"这种可读形式。

4. **要接进来的 CFG 边类型**。现有 CFG 只有 fallthrough / 条件 / 无条件。
   DEX 还需要：
   - `SwitchCase` / `SwitchDefault`（来自 `packed-switch-payload` / `sparse-switch-payload`）；
   - 异常边（来自 `try_item` + `encoded_catch_handler`，**一个 try 块可有多个 handler**）；
   - handler 入口是一种特殊的块入口（`move-exception` 只能在那里出现）。

   **更正：这些不必自己造。** `droidsaw-dex` 的 `EdgeKind` 已经是
   `FallThrough | Branch | SwitchCase(i32) | SwitchDefault |
   ExceptionHandler(TypeIdx) | ExceptionCatchAll`，并带
   `ExceptionRegion { start_addr, end_addr, handler_blocks }`。
   要做的是**投影到项目的 CFG 表示**，不是新增语义。

5. **多 dex 的符号键**。multidex 下同一个类名可能出现在不同 dex。
   符号 id 必须是 `(dex_index, index)` 复合键，不能只用 index。

### 4.3 不复用的东西（重要）

DEX **不是**"另一种可执行格式"，不要硬塞进现有分析层：

- **没有栈帧**：寄存器机，不需要栈平衡分析，也就**不能**跑现有的 `frames` 路径。
  现有 `scan_frames` 依赖 `UnwindEntry` 与 `push/pop` 前导扫描 —— 对 DEX 全部不适用。
- **没有 cross-function 的段权限概念**（`.text`/`.rdata` 之类）。
- **`SizeOfImage`/`image_base` 不存在**。因此 `analyze` 层里凡是"按 RVA 落在哪个节"
  的逻辑都要对 DEX 短路。

## 5. 里程碑

排期理由变了：**现在每一层都有现成库，所以不是"挑最便宜的做"，而是
"按依赖顺序做"**。M0 仍排第一，因为它零新解析代码且立刻有用；
但 M1/M2 的成本已经从"写一个解析器 + 一个解码器 + 一个 CFG 构造器"
降到"**写适配层 + 验证**"。

### M0 — APK 容器 + native 库复用 ELF

1. `ContainerKind::Zip`：ZIP 解析。用 `zip`；若要抗畸形包（BadPack）
   再加 `apk-info-zip`。
2. 成员枚举：`members` 列出所有条目，标出 `classes*.dex`、`lib/<abi>/*.so`、
   `AndroidManifest.xml`、`resources.arsc`。
3. **解压 `.so` 成员 → 走现有 ELF 路径**。这是本里程碑的核心收益。
4. 记录每个成员的诊断信息（都不需要解压就能从文件读出）：
   `compress_type`、`localHeaderOffset % 4`、`.so` 的 `offset % 4096 / % 16384`、
   ELF 头的 `p_align`。
5. 签名**检测**（不校验）：v1（`META-INF/` 条目名）、v2/v3（APK Signing Block）。
   结论必须区分"**存在** v2 块"与"**已验证** v2 签名" —— 后者未实现，
   按 §7 报 `NotYetImplemented`。

**验收**（本节已在探测工程里**预演通过**，见调查报告 §3）：
对 `ah-app-release.apk` 列出 1867 个成员、37 个 `.so` 解出普通 ELF64
（`EM_AARCH64`），并能对其中一个成员出函数清单。

#### M0 完成情况（据实记录，2026-10-14）

逐条对上面 5 项，**做到哪就说哪**（§7：跳过与通过必须分得开）：

| # | 项 | 状态 | 说明 |
| --- | --- | --- | --- |
| 1 | `ContainerKind::Zip` | **完成** | 只用 `zip` 9.0.2。**没有**加 `apk-info-zip` —— 实测这个真实 APK 的全部 1867 个条目 `zip` 都读得下来，抗畸形包的需求尚未出现，**等遇到再说**（先加库不符合"最小改动"）。 |
| 2 | 成员枚举 + 标出 APK 的那些位置 | **完成** | 枚举 1867 个与独立基准一致；`ApkRole` 按**成员名**标出 `classes*.dex` / `lib/<abi>/*.so` / 清单 / 资源表 / v1 签名文件。注意它的适用前提（见 `ApkRole` 文档）：只说明"名字符合约定"，既不说明"这是 APK"，也不说明"内容是那个格式"。 |
| 3 | **解压 `.so` → 走现有 ELF 通路** | **完成（x86_64 已验证）** | `functions --member lib/x86_64/libBugly_Native.so` → **493 个函数** + 1 个导入桩；`symbol ... --member` 把 `JNI_OnLoad` 定位到成员内 `0xa330`。**但 aarch64 目前不可用**：`capstone` 0.14.0 自身缺陷会让进程 abort（`docs/research/capstone-arm64-abort.md`），对裸 `.so` 同样复现，属既有问题、与本次改动无关。aarch64 是 Android 主 ABI，所以这条障碍很实际。 |
| 4 | 逐成员诊断信息 | **部分完成** | 已做：`compress_type`（如实给**原始方法号**）、`offset`（本地头解析得出，算不出时 `null` 而非 0）、`uncompressed_size`。**未做**：`localHeaderOffset % 4`、`.so` 的 `offset % 4096 / % 16384`、ELF 头的 `p_align`。后三项是"对齐诊断"，价值在于解释某些 `.so` 为什么加载失败，属于 M0 的次要目标，**没有冒充完成**。 |
| 5 | 签名**检测**（不校验） | **完成（存在性）** | v1 看 `META-INF/*.SF`，v2/v3 看中央目录前那块。v2/v3 的判据是**结构自洽**（块首 size == 魔数前的 size，且 `size+8` 正好回退到块首），不是只比 16 字节魔数 —— 只比魔数会被"最后一个成员的数据正好以它结尾"骗过去，单测随手构造就复现了。类型名只有 `present`、没有 `valid`/`verified`。 |

**关于第 5 项里"校验未实现"怎么表达**：当前**没有**校验入口，所以结论以
`notes` 里的显式说明给出（"仅检测存在性，**未校验签名有效性**"），
而不是返回 `NotYetImplemented` —— 后者要有被调用的动作才谈得上"未实现"。
等真的加上"校验签名"这个动作时，它必须报 `NotYetImplemented`。

**本轮暴露出的两个"想当然"**（都写进代码注释了，免得改回去）：
成员内容**不能**直接用 `offset..offset+size` 切片（ZIP 成员要解压，而且
数据起点在本地头里）；`read_member` **确实**会校验本地头（原以为"走中央目录
就不看本地头"，两个用例当场失败）。


### M1 — DEX 结构模型（不建 CFG）

> **完成情况（据实记录，2026-10-14）**：已落地，代码在
> `crates/bitflip-loader/src/format/dex/`，入口 `bitflip_loader::parse_dex_structure`；
> 测试在 `crates/bitflip-loader/tests/dex_structure.rs`（合成样本，永远跑）
> 与 `dex_library_boundary.rs`（grep 守卫）。
>
> * **实现路径与本节的设想有一处不同（说明理由）**：不是投影 `api::ClassSummary` /
>   `MethodSummary`，而是直接用 `parser` + `ids` + `decode::parse_class_data`。
>   原因是本节引用的那条约束本身：`api` 层返回的是**已经物化成 `String` 的**
>   摘要，投影时必然先付一次 `String` 分配、再去重；而 `class_defs` /
>   `class_data` 本来就是**索引**，直接用它们才真正满足"列式 + 不物化字符串"。
>   连带的收益是"字段清单"也拿得到 —— `api::list_methods` 只给方法。
> * **验收项：已完成** —— 类数 == **手读**的 `class_defs_size`（真实样本
>   7643:7643）、六个池"声明 == 实际"、符号数 == `class_data` 四个 size 之和、
>   库的 `parse_errors` 逐条进 `notes`、grep 守卫（比本节要求更严：还断言
>   "库只能被适配层引用"与"适配层确实用了库的事实层"）。
> * **验收项：第一条已补上，另两条待补** —— 本节列的"指令 ∪ payload 恰好铺满
>   `[0, insns_size)`"、"`31t` 目标落在 payload 起始 unit"、"`try_item` 的
>   `handler_off` 落在 `encoded_catch_handler` 起点"三条**都要解码指令与 payload
>   宽度**，而解码是 M2 的交付物。M1 当时不做，也不假装做了；
>   **第一条已于 2026-10-14 补上**（`format/dex/layout.rs`，只借库的地址、
>   长度按规范从原始字节重算；真实样本上 **143486 个方法 0 处不吻合**）。
>   另两条要 CFG 与异常表，属 M2a 后续。
> * **实测修正一处本节的说法**：`parse_errors` 在真实样本上不是"一条"而是
>   **3 个 dex 里有 2 个**各有 `OutOfOrder { pool: StringIds }`
>   （`classes.dex` @ `0x10589`、`classes2.dex` @ `0xffd0`）。
> * **性能**：`classes.dex`（8.8 MB / 7643 类）release 下 1.2 s，其中库的
>   `DexFile::parse` 占 1174 ms、我们的 `class_data` 循环 29 ms；
>   debug 下约 70 s/dex（**是 debug 开销，不是 O(n²)** —— 这一点先被怀疑过，
>   被 release 数字否掉了）。
> * **仍未做**：解析预算（`Budget`）未接；DEX 还没接进 CLI/UI；
>   交叉引用/调用图/反编译未做。逐条状态另见 `docs/PLAN.md` 的 M11 · M1 段。

后端用 `droidsaw-dex` 的 `parser` 层 + `ids`/`mutf8`，**不自己写解析器**。
真正要做的是**适配**：把它返回的带 `String` 的
`ClassSummary`/`MethodSummary` 投影到项目的**列式 SoA 表示**与 interned
字符串池（CLAUDE.md §4 禁止把每条指令物化成带 `String` 的对象）。
**这个适配层才是本里程碑的主要工作量。**

**不做**：CFG、数据流、注解、`debug_info`（各自的后续里程碑）。

**验收 —— 关键变化：验收对象是"库 + 我们的适配"**。
因为库极新且发布包不含测试（§1 条件 1），**必须有自己的黄金测试**：

- 断言"类数 == 手读 `header.class_defs_size`"（实测 7643:7643，可复现）；
- 断言"**指令 ∪ payload 恰好铺满 `[0, insns_size)`**"，
  `insns_size` 与 payload 长度都**按规范手算**，不读库的长度字段。
  这条能抓出绝大多数宽度表 / payload / 对齐错误 ——
  实测在 3000 个真实方法上 0 不吻合；
- 断言"每条 `31t` 的分支目标正好指向一个合法 payload 起始 unit"；
- 断言"每个 `try_item` 的 `handler_off` 正好落在某个 `encoded_catch_handler` 起点"；
- 断言"符号数量 == `class_data` 四个 size 之和"；
- **记录库报出的 `parse_errors`**：实测真实 APK 上就有一条
  `OutOfOrder { pool: StringIds }`。这类"规范不符但 ART 容忍"的情形
  只能写进 `notes`，**不能据此拒绝文件**，也不能静默丢掉；
- grep 守卫：代码里**不出现** `droidsaw_dex::emit*` / `sugar` /
  `r8_inversion` 的引用（§1 划的那条线）。

**验证集**：`ah-app-release.apk` 的 3 个 dex 现成可用
（8.8 / 10.4 / 6.0 MB，分别 7643 / 8833 / 6462 个类）。

### M2 — Dalvik 解码 + CFG

> **本节要求"动手前定"的那件事已定：ADR-0020。** 结论：**DEX 的视图自成一类**，
> 不把 `Disasm` 泛化成 trait。理由是 `Disasm` 的五格里有四格
> （`AddrSpace` / `InsnIndex` / 扫描种子 / 覆盖率统计）对 DEX 根本不成立：
> 只把最后一格（`renderer`）换成 trait，会造出一个"看起来能装 DEX、
> 实际静默产出无意义结论"的类型 —— 与 M1 拒绝把 DEX 塞进 `parse_object`
> 是同一条理由。下面那条"渲染要单独解决"因此有了答案：**渲染不需要走进
> `Disasm`**，DEX 侧自己有一个视图类型 + 自己的 `render_insn`。
>
> **拆成两段推进（据实记录，免得"看起来完成了"）**：
>
> * **M2a（事实层，先做）**：解码投影 + CFG 投影 + 渲染函数 + 黄金测试，
>   全部落在 DEX 侧，**不碰 `bitflip-core`**。并补齐 M1 推迟的三条验收
>   （"指令 ∪ 载荷恰好铺满 `[0, insns_size)`"、"`31t` 目标落在 payload 起始"、
>   "`try_item` 的 `handler_off` 落在 `encoded_catch_handler` 起点"）——
>   它们本来就要解码宽度，属于这一段。
> * **M2b（接产品，后做）**：CLI/导出怎么呈现 DEX 视图（新子命令，还是
>   `--member classes.dex` 自动切视图）。ADR-0020 明确把这一条留到 M2a 之后，
>   依据是"用户在命令行上想表达什么"。

用 `droidsaw-dex` 的 `decode` + `cfg`，**要写的是适配层**：

- 把 `decode::parse_code_item` 的 `Instruction`
  （`addr`/`Opcode`/`size`/`dst`/`src`/`literal`/`target`/`pool_idx`）
  投影成项目的列式指令表示；
- 把 `cfg::Cfg`（`EdgeKind` 已是 `FallThrough | Branch | SwitchCase(i32) |
  SwitchDefault | ExceptionHandler(TypeIdx) | ExceptionCatchAll`，外加
  `ExceptionRegion { start_addr, end_addr, handler_blocks }`）
  投影成项目的 CFG 表示；
- **指令文本渲染要单独解决**：`droidsaw-dex` 有 `Opcode::mnemonic()`，
  但项目的 `Disasm.renderer` 类型是 `Option<Arc<CapstoneDecoder>>`，
  DEX 走不进去。**这一点要在动手前定**（新增 DEX 渲染路径，或把 renderer
  抽象成 trait）。这是本方案里唯一一处"现成库帮不上"的**结构**问题。

### M3 — AXML + resources.arsc

用 `apk-info-axml`（或 `rusty-axml` / `resand`）。
**实测已经能还原出 29 392 字节可读 XML**，含 package / versionCode /
versionName / minSdk / targetSdk / permissions / activities / services /
主 activity / 签名条目数。价值中等（元信息与字符串为主，不是代码逻辑）。

### 暂不排期

- **v041 容器 DEX**：本机两个真实样本都是 035。等遇到真实 v041 样本再做
  （参考文档 §1.3 已把算法与陷阱写好，届时照着做）。
- **ODEX / VDEX / CompactDex**：明确拒绝并说明。`0xE3–0xF9` 一律报
  `UnknownOpcode` + "可能是已废弃的 ODEX quick 指令"。**不要**抄网上的 magic 字符串。
- **重打包 APK 的修复**：只报告（checksum/signature 不一致写 `notes`），不修。

## 6. 已知陷阱（详见参考文档 §9，这里只列最容易全错的）

现在这些陷阱主要**由 `droidsaw-dex` 处理**了，但**我们的黄金测试仍要盯着它们** ——
理由就是 §1 条件 1：库极新，且发布的 crate 把 `tests/` 排除了，
我们无法从制品验证它对这些边角的处理。**"库应该处理了"不是证据。**

1. **`tries_size != 0` 隐含 4 字节对齐**（`insns_size` 为奇数时跳 2 字节 padding；
   `tries_size` 为奇数时 handler 列表末尾再补 1 字节）。这是"整体错位 2 字节"的头号来源。
2. **MUTF-8 ≠ UTF-8**：`U+0000` 是 `0xC0 0x80`，裸 `0x00` 是终止符，
   增补平面用 **CESU-8 风格的两个 3 字节代理对**。所以 `strcmp` 排序不可靠。
3. **`uleb128p1`**：磁盘值 = 索引 + 1，**原始 0 表示"无"**。写错会让所有
   `DBG_SET_FILE` 与局部变量名**偏移一位**。
4. **ULEB128 必须限 5 字节**。绝不能写成 `while (b & 0x80)` ——
   构造的全 `0x80` 流会越界读。
5. **所有 `off` 字段：0 = 不存在**（`Option<T>`），不要解析出"偏移 0 的对象"
   （会把 header 当 `code_item` 读）。
6. **diff 编码只在 `class_data_item` 里**（每个列表第一个元素直接给索引）。
   `annotation_element.name_idx` **不是** diff。
7. **`0xE3–0xF9` 不是多字节 odex 指令**，是 `10x` 的 unused 槽位；
   **"`0xff` = expanded opcode" 在 ART 里不存在**（`0xff` 是 `const-method-type`）。
   这两条流传很广，都别信。
8. **不要信 `insns_size`**：用它之前先与实际字节数比对。
9. **规范要求 ≠ 现网事实。** 实测一个真实上架 APK 的 `string_ids` **就是乱序的**
   （`OutOfOrder { pool: StringIds }`）。所以排序性自检的结论只能进 `notes`，
   **既不能据此拒绝文件，也不能静默丢掉**。

## 7. 本设计里仍未验证的（不许用默认值糊过去）

**第一类：格式本身的未知。** 参考文档 §10 有完整清单（13 项），
其中最影响**本设计**的三项：

1. **payload 必须 4 字节对齐**的规范原文未取得。实现上：期待对齐，
   未对齐记 `notes` 而**不拒绝文件**。
2. **AXML 的 UTF-8 字符串池是否就是 MUTF-8**（只验证了长度编码）。
   按"UTF-8 + 保留代理对"处理最稳。
3. **`.cdex`/`.vdex`/`.oat` 的 magic 原文未取得** → 只能按"magic 不匹配任一已知
   DEX 版本"报错，**不要**写死网上抄来的 magic 字符串。

**第二类：新引入的依赖本身的未知**（这一类是本次改方案后**新增**的，
必须写明，否则会被"库能跑"这件事掩盖）：

4. **本次只验证了有限几条不变量**（类数一致、指令恰好铺满、CFG 边类型、
   目录/清单字段），**没有逐字段核对全部输出**。例如
   `access_flags` 语义、注解、`debug_info`、xrefs 都**没验**。
5. **037–041 各版本的实际行为未验**（本次样本全是 035）。
6. **`resand` / `rusty-axml` / `dex-parser-rust` / `apk-info-zip` / `droidsaw-apk`
   本次没有实跑**，只有许可与 API 面调研。
7. 这两个库**极新、产量异常**（见调查报告 §4 第 1 条）。这不构成"不能用"，
   但构成"**必须自己验**"。

另外：**本机两个 APK 都是 035 不等于"现网没有 041"**。样本量为 2，
而且两个都可能来自同一时期的同一构建链。M0/M1 的实现要能在遇到 041 时
**明确报"版本 041 尚未支持"**，而不是按 035 的规则错误解析。
