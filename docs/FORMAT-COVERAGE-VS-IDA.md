# 格式覆盖对比：BitFlip vs IDA Pro

> 回答的问题：**"跟 IDA Pro 比，我们还差哪些格式？"**
>
> 数据来源是 Hex-Rays 官方文档（逐条读了原文，不是凭印象列的），日期见文末。
> 本页只做**事实对比**，不做"我们也能做到"的宣传；差距就是差距。

## 1. 先说结论

差距不在"能不能拆 PE/ELF"，而在三个维度上，按重要性排序：

1. **处理器架构**：IDA 支持 **150+ 种**处理器模块，我们 **9 种**（且其中 wasm 未落地）。
   这是最大的、也最不值得追的差距 —— 见 §4 的解释。
2. **非原生格式**：固件/ROM/历史平台（N64、SNES、GameBoy、PSX、Palm、EPOC、QNX…）。
   这些是 IDA 靠几十年积累攒出来的长尾，对"分析现代桌面/移动二进制"的目标几乎没有价值。
3. **反编译器覆盖**：IDA 官方有 12 种架构的反编译器，我们 **0 种**（本轮刚开始）。

**真正该追的只有三件事**（见 §5）：Mach-O 落地（M12 已排期）、DEX（M11 已排期）、
以及反编译器的**有界子集**。

## 2. 文件格式：官方原文逐条对照

IDA 官方文档明确说这个列表**不完整**（"The list contains some, but not all"），
所以下表是"至少这些"，不是"仅这些"。

| IDA Pro 支持的格式（官方原文） | BitFlip 现状 |
| --- | --- |
| MS DOS / EXE File | ✗ |
| MS DOS COM File | ✗ |
| MS DOS Driver | ✗ |
| New Executable (NE) | ✗ |
| Linear Executable (LX) | ✗ |
| Linear Executable (LE) | ✗ |
| **Portable Executable (PE)** (x86, x64, ARM, etc) | **✓ 已解析** |
| Windows CE PE (ARM, SH-3, SH-4, MIPS) | ✗ |
| **Mach-O for OS X and iOS** (x86, x64, ARM, PPC) | **△ 仅识别**（M12 排期） |
| Apple Dyld Shared Cache (DSC) | ✗ |
| **Dalvik Executable (DEX)** | ✗（M11 排期） |
| EPOC (Symbian OS executable) | ✗ |
| Windows Crash Dump (DMP) | ✗ |
| XBOX Executable (XBE) | ✗ |
| Intel Hex Object File | ✗ |
| MOS Technology Hex Object File | ✗ |
| Netware Loadable Module (NLM) | ✗ |
| **Common Object File Format (COFF)** | **✓ 已解析** |
| Binary File（裸二进制兜底） | **✓ 已支持**（`ObjectKind::Raw`） |
| Object Module Format (OMF) | ✗ |
| OMF library | ✗ |
| S-record format | ✗ |
| ZIP archive | ✗ |
| JAR archive | ✗ |
| **Executable and Linkable Format (ELF)** | **✓ 已解析**（`.o`/`.so`/可执行） |
| Watcom DOS32 Extender (W32RUN) | ✗ |
| Linux a.out (AOUT) | ✗ |
| PalmPilot program file | ✗ |
| AIX ar library (AIAFF) | ✗ |
| PEF (Mac OS or Be OS executable) | ✗ |
| QNX 16 and 32-bits | ✗ |
| Nintendo (N64) | ✗ |
| SNES ROM file (SMC) | ✗ |
| Motorola DSP56000 .LOD | ✗ |
| Sony Playstation PSX executable/object/library | ✗ |

### 归档/容器（IDA 官方单独列了一节）

| IDA | BitFlip |
| --- | --- |
| 静态库 `.a` / `.lib`（选成员） | **✓ 已支持**（`Ar` / `MsvcLib`，可列成员） |
| ZIP archive（选包内文件） | ✗ |
| Fat/universal Mach-O（选架构切片） | **△ 仅识别**（`ContainerKind::Fat`，M12） |

**格式层面的结论**：现代主流三件套（PE / ELF / COFF）+ 归档已经齐了。
差的是 Mach-O（已排期 M12）、DEX（已排期 M11）、以及一大片历史/嵌入式格式。

## 3. 处理器架构：这是数量级的差距

IDA 官方处理器列表（原文，此处归类压缩，原文共约 150 个条目）：

| 类别 | IDA | BitFlip |
| --- | --- | --- |
| x86 / x64 | ✓（含 AVX-512 等全部扩展） | ✓（x86 / x86_64） |
| ARM32 / ARM64 | ✓（ARMv3–v8、Thumb、NEON、SVE2/SME） | ✓（Arm/Thumb、Aarch64） |
| MIPS / MIPS64 | ✓（含 microMIPS、MIPS16、Allegrex…） | ✓（Mips / Mips64） |
| RISC-V 32/64 | ✓ | ✓ |
| PowerPC / POWER | ✓（极完整，含 Xenon/Cell/VLE） | ✗ |
| SPARC | ✓ | ✗ |
| SuperH | ✓ | ✗ |
| m68k / 6800 / 6805 / 6809 / HCS08 / HCS12 | ✓ | ✗ |
| Z80 / Z180 / Z380 / Z8 | ✓ | ✗ |
| 6502 / 65C02 / 65816 | ✓ | ✗ |
| AVR | ✓ | ✗ |
| PIC 12/14/18/24/dsPIC | ✓ | ✗ |
| MSP430 / MSP430X | ✓ | ✗ |
| 8051 / 80196 / 8080 / 8085 | ✓ | ✗ |
| Intel 860 / 960 / IA-64 (Itanium) | ✓ | ✗ |
| DEC PDP-11 / Alpha | ✓ | ✗ |
| IBM z/Architecture (S390x) | ✓ | ✗ |
| HP-PA (PA-RISC) | ✓ | ✗ |
| H8/300 / H8/500 / H8S / H8SX | ✓ | ✗ |
| V850 / RH850 | ✓ | ✗ |
| Tricore (TC1xxx–TC4x) | ✓ | ✗ |
| Xtensa | ✓ | ✗ |
| ARC / ARCompact / ARCv2 | ✓ | ✗ |
| NEC 78K0 / 78K0S | ✓ | ✗ |
| C166 | ✓ | ✗ |
| M32R / M7700 / M7900 / M16C | ✓ | ✗ |
| CR16 / ST-7 / ST-9 / ST-10 / TLCS900 / MN102 | ✓ | ✗ |
| unSP (SunPlus) / SPC700 / Rockwell C39 / KR1878 | ✓ | ✗ |
| Samsung SAM8 / Philips XA / xScale | ✓ | ✗ |
| DSP：TI C2x/C5x/C6x/C54x/C55x/C28x、DSP56K、DSP563xx、ADSP-218x | ✓ | ✗ |
| Java Virtual Machine (bytecode) | ✓ | ✗ |
| **Microsoft .NET (CLI bytecode)** | ✓ | ✗ |
| **Dalvik (Android DEX)** | ✓ | ✗（M11） |
| **WebAssembly (WASM)** | ✓ | **△ `Arch::Wasm32` 已定义但未实现** |
| Qualcomm Hexagon QDSP6 | ✓ | ✗ |
| EFI Byte Code (EBC) | ✓ | ✗ |
| SPU (Cell BE) | ✓ | ✗ |
| MCore / CSky V1 / Renesas RL78 / RX | ✓ | ✗ |

**IDA Home 处理器列表**（官方原文，用于说明"连免费版都覆盖 5 族"）：
x86/x64、ARM/ARM64、MIPS/MIPS64、PowerPC/PPC64、RISC-V/RV64。

**我们 `Arch` 的完整定义**（源码枚举，9 项）：
`X86`、`X86_64`、`Aarch64`、`Arm`、`Riscv32`、`Riscv64`、`Mips`、`Mips64`、`Wasm32`。

## 4. 这个差距要不要追？——不要

**150:9 看着刺眼，但直接对比是错的。** 理由：

1. IDA 那 150 个模块里，**绝大多数是几十年积累的嵌入式/历史平台长尾**。
   一个分析 Electron 桌面应用或 Android APK 的用户，永远用不到 H8/300 或 Rockwell C39。
2. 我们的目标在 `docs/PLAN.md` §1 写得很清楚：现代桌面/移动二进制。
   **在这种目标下，架构覆盖根本不是瓶颈 —— 反编译器质量和分析深度才是。**
3. 每加一个架构，成本不只是"写个解码表"：要配 ABI（调用约定/寄存器约定）、
   unwind 语义、跳转表识别、参数推断。capstone 能解码 ≠ 我们能分析。
   **这正是 `docs/PLAN.md` 里把反编译器标为"数倍于全部既有工作量"的同一个原因。**

结论：**架构表应当按"目标场景"补，而不是按"对标 IDA"补。**
现实优先级：ARM64（已做，移动端必需）> DEX/Dalvik（M11）> PowerPC（如果要做主机/固件）
> 其余不排期。

## 5. 该追的三件事

| 优先级 | 事项 | 状态 | 理由 |
| --- | --- | --- | --- |
| P0 | **Mach-O 解析落地** | M12 已排期 | iOS/macOS 目标的前提；`.app`/IPA 都压在它上面 |
| P0 | **DEX/Dalvik** | M11 已排期 | Android 主线；且 DEX 是**字节码**，不需要"反汇编到指令"这一步 |
| P1 | **反编译器的有界子集** | 本轮评估 | 见 `docs/DECOMPILER-SCOPE.md` |
| P2 | APK/IPA 容器解包 | M11/M12 从属 | 本质是 ZIP + 清单，成本远低于上面的分析工作 |
| — | 其余格式/架构 | 不排期 | 与目标场景无关，明确记为**非目标** |

## 6. 反编译器：IDA 12 种，我们 0 种

IDA 官方文档明确列出 **12 种**反编译器 flavor：

x86、x64、ARM、ARM64、PowerPC、PowerPC64、MIPS、MIPS64、RISC-V 32、RISC-V 64、
ARC 32、V850 32。

IDA Home 9.5 起包含其中 11 种（在线反编译器）+ Android DEX/ODEX。
另有 **Android DEX/ODEX 反编译器**（9.5 新增，产出可读 Java 代码）。

**我们：0 种。** 这是最实质的差距，也是本轮要评估的唯一一件事 ——
见 `docs/DECOMPILER-SCOPE.md`。

注意一个容易忽略的事实：**IDA 的反汇编器覆盖面远大于反编译器**。
官方原话大意是"其他处理器模块没有官方 Hex-Rays flavor"（举例 6502、8051、AVR、
SPARC、TriCore、Xtensa）。也就是说，**连 IDA 自己都只给主流架构做反编译**。
这对我们的取舍是重要参考：不必等架构齐了再做反编译。

## 7. 数据来源

- [Supported file formats](https://docs.hex-rays.com/core/disassembler/specification/supported-file-formats.md)（Hex-Rays 官方）
- [Supported processors](https://docs.hex-rays.com/core/disassembler/specification/supported-processors.md)（Hex-Rays 官方）
- [Loaders](https://docs.hex-rays.com/core/disassembler/concepts/loaders.md)（Hex-Rays 官方）
- [Decompiler 架构覆盖查询结果](https://docs.hex-rays.com/core/decompiler/overview.md)（Hex-Rays 官方文档问答）
- [IDA 9.5 发布说明（含 DEX 反编译器与 IDA MCP）](https://www.cnblogs.com/sysin/p/23226188)

**可信度标注**：
- 格式与处理器列表：**来自官方文档原文**，可信度高。但官方自称列表不完整，
  所以实际覆盖**只会比上表更多**（即我们的差距**不小于**表中所示）。
- 12 种反编译器：来自官方文档的问答接口，可信度中高（未逐一核对每个 flavor 页面）。
- 我方覆盖：来自**源码枚举**（`ObjectKind` / `Arch` / `has_parser`），
  可信度最高 —— 这是实际代码，不是文档承诺。

**下一步**：上表每一处缺口对应哪个现成轮子、许可能不能用、代价多少，
见 `docs/DEPENDENCY-DECISIONS.md`（含本机实测证据）。一句话概括：
格式与架构的缺口基本都有可用的宽松许可轮子，
**唯一没有可用轮子的是 DEX**；反编译器有轮子但**会违反 §7**。

