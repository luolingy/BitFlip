# 自研 APK / DEX 逆向核心 —— 设计

> 状态：**设计**（未实现）。字节约束见
> [`docs/research/dex-apk-format-reference.md`](./research/dex-apk-format-reference.md)。
> 相关：ADR-0019（本文）、`docs/DEPENDENCY-DECISIONS.md` §2.4。

## 1. 为什么必须自研

不是"选择自研"，是**没有可用的轮子**。三条路都堵着（结论已记录在
`docs/DEPENDENCY-DECISIONS.md`，由 `scripts/check-licenses.py` 守着）：

| 候选 | 许可 | 为什么不能用 |
| --- | --- | --- |
| `smali` / `baksmali` | **GPL-3.0-only** | 传染整个产品。已进 `DENY` 清单 |
| `dex` crate | MIT | **2021-05-31 起冻结**，不支持 038+ 的 `call_site_ids`/`method_handles`，也不支持 v041 |
| `dalvik` crate | MIT OR Apache-2.0 | 只是**反汇编器**，不建结构模型（没有 class/field/method 表） |
| `lief` | Apache-2.0（许可没问题） | 构建期下载预编译二进制 + C++ FFI，且 docs.rs 每个版本都构建失败 |
| `exe` / `dotnetdll` | GPL-3.0 / GPL-3.0+ | deny-list |

**结论：DEX 解析器与 Dalvik 解码器都自己写。** APK 容器那层可以用 `zip`
（9.0.1，MIT，纯 Rust，已过许可闸门）。

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

4. **新的 CFG 边类型**。现有 CFG 只有 fallthrough / 条件 / 无条件。
   DEX 还需要：
   - `SwitchCase { targets, keys }`（来自 `packed-switch-payload` / `sparse-switch-payload`）；
   - `ExceptionEdge`（来自 `try_item` + `encoded_catch_handler`，**一个 try 块可有多个 handler**）；
   - handler 入口是一种特殊的块入口（`move-exception` 只能在那里出现）。

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

按"价值/成本"排序。**M0/M1 加起来就能覆盖 APK 逆向里很大一部分实际需求**
（很多 app 的核心逻辑在 native 库里），而成本远低于 M2/M3。

### M0 — APK 容器 + native 库复用 ELF（成本最低，价值最高）

1. `ContainerKind::Zip`：ZIP 解析（EOCD / central directory / local header）。
   用 `zip` crate，不自己写 ZIP。
2. 成员枚举：`members` 列出所有条目，标出 `classes*.dex`、`lib/<abi>/*.so`、
   `AndroidManifest.xml`、`resources.arsc`。
3. **解压 `.so` 成员 → 走现有 ELF 路径**。这是本里程碑的核心收益。
4. 记录每个成员的诊断信息（都不需要解压就能从文件读出）：
   `compress_type`、`localHeaderOffset % 4`、`.so` 的 `offset % 4096 / % 16384`、
   ELF 头的 `p_align`。
5. 签名**检测**（不校验）：v1（`META-INF/` 条目名）、v2/v3（APK Signing Block）。
   结论必须区分"**存在** v2 块"与"**已验证** v2 签名" —— 后者未实现，
   按 §7 报 `NotYetImplemented`。

**验收**：对 `ah-app-release.apk` 能列出 1867 个成员、37 个 `.so` 全部解析成
ELF 对象（`EM_AARCH64`），并能对其中一个成员出函数清单。

### M1 — DEX 结构模型（不建 CFG）

按参考文档 §1–§5 的顺序：`dex_header` → `map_list` → id 表（含 MUTF-8）
→ `class_def`/`class_data` → `code_item` + 指令遍历。

**不做**：CFG、数据流、注解、`debug_info`（各自的后续里程碑）。

**验收**（不能只看绿灯，CLAUDE.md §7）：
- fixture 按**规范字节**手工拼（**不要按解析器假设拼** —— §6.11 的教训），
  另配真实样本；
- 断言"所有 `code_item` 的指令遍历消耗的 code unit 数 **== `insns_size`**"
  —— 这一条能抓出绝大多数宽度表 / payload / 对齐错误；
- 断言"每条 `31t` 的分支目标正好指向一个合法 payload 起始 unit"；
- 断言"每个 `try_item` 的 `handler_off` 正好落在某个 `encoded_catch_handler` 起点"；
- 断言"符号数量 == `class_data` 四个 size 之和"。

**先用真实样本反推 fixture**：`ah-app-release.apk` 的 3 个 dex 是现成的实现验证集
（8.8 MB / 10.4 MB / 6.0 MB）。

### M2 — Dalvik 解码器 + CFG

`DexDecoder`（`Decoder` trait 实现）+ 指令文本渲染 + 新 CFG 边类型。
渲染不能走 capstone 的助记符表（那是 `CapstoneDecoder` 独有的），
所以 DEX 的 `Disasm.renderer` 必须是 `None` 或新增一个 DEX 渲染路径 ——
**这一点要在动手前定**，因为 `Disasm.renderer` 的类型是
`Option<Arc<CapstoneDecoder>>`，DEX 需要新的表达。

### M3 — AXML + resources.arsc

`AndroidManifest.xml`（package/versionCode/versionName/minSdkVersion/debuggable
/permissions/activities）+ 资源表。价值中等（元信息与字符串为主，不是代码逻辑）。

### 暂不排期

- **v041 容器 DEX**：本机两个真实样本都是 035。等遇到真实 v041 样本再做
  （参考文档 §1.3 已把算法与陷阱写好，届时照着做）。
- **ODEX / VDEX / CompactDex**：明确拒绝并说明。`0xE3–0xF9` 一律报
  `UnknownOpcode` + "可能是已废弃的 ODEX quick 指令"。**不要**抄网上的 magic 字符串。
- **重打包 APK 的修复**：只报告（checksum/signature 不一致写 `notes`），不修。

## 6. 已知陷阱（详见参考文档 §9，这里只列最容易全错的）

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

## 7. 本设计里仍未验证的（不许用默认值糊过去）

参考文档 §10 有完整清单（13 项）。其中最影响**本设计**的三项：

1. **payload 必须 4 字节对齐**的规范原文未取得。实现上：期待对齐，
   未对齐记 `notes` 而**不拒绝文件**。
2. **AXML 的 UTF-8 字符串池是否就是 MUTF-8**（只验证了长度编码）。
   按"UTF-8 + 保留代理对"处理最稳。
3. **`.cdex`/`.vdex`/`.oat` 的 magic 原文未取得** → 只能按"magic 不匹配任一已知
   DEX 版本"报错，**不要**写死网上抄来的 magic 字符串。

另外：**本机两个 APK 都是 035 不等于"现网没有 041"**。样本量为 2，
而且两个都可能来自同一时期的同一构建链。M0/M1 的实现要能在遇到 041 时
**明确报"版本 041 尚未支持"**，而不是按 035 的规则错误解析。
