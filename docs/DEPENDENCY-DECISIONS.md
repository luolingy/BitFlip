# 轮子选型结论：架构、格式、反编译器

> 回答的问题：**"有没有现成的轮子能补上架构/格式/反编译器的缺口？许可能不能接受？"**
>
> 结论分三类：**拿来用**、**有保留地用**、**不用（并写明为什么）**。
> 所有判断都基于本机**实测编译并运行**过的证据（见
> `docs/research/dependency-probe-evidence.md`）或官方一手文档，
> 不是凭印象。**没有实测过的项一律标注**。

## 0. 先说三个最重要的结论

1. **许可不是问题，架构和格式的轮子基本都能用。**
   调研了 30+ 个候选，**零个 GPL/LGPL/AGPL/SSPL**。
   但踩到 3 个 GPL 地雷（`exe`、`dotnetdll`、`smali`），见 §4。
2. **`ghidra-decompiler`（koute）是真的能用，但它的输出直接违反我们的 §7。**
   这是本次调研最关键的发现，见 §3。它能力很强（常量折叠正确），
   但**会静默丢掉函数体而不提示** —— 那正是我们最怕的失败模式。
3. **`object` crate 的 README 明确写了"不适用于恶意样本分析"。**
   这是它自己的安全声明，与我们"分析任意不可信二进制"的用途正面冲突，
   见 §2.3。许可是干净的（Apache-2.0 OR MIT），问题在威胁模型。

## 1. 结论总表

| 缺口 | 轮子 | 许可 | 实测 | 结论 |
| --- | --- | --- | --- | --- |
| **Mach-O（含 fat）** | `object` 0.40 | Apache-2.0 OR MIT | **实测通过** | **用**，但要加资源限额（§2.3） |
| Mach-O 代码签名 / dyld cache | `object` 0.40 | 同上 | 未实测（API 存在） | 用 |
| Mach-O 深度签名（CMS） | `apple-codesign` | MPL-2.0 | 未实测 | **需你拍板**（MPL 是文件级 copyleft） |
| APK（ZIP 容器） | `zip` 9.0.1 | MIT | 未实测 | 用 |
| JVM class | `cafebabe` | 0BSD | 未实测 | 用 |
| **DEX（M11 核心）** | —— | —— | —— | **没有可用的轮子，见 §2.4** |
| **架构扩展（9 → 40+）** | `wazabin-sleigh` + `-precompile` | MIT / MIT AND Apache-2.0 | **实测通过** | 用（有保留，见 §2.5） |
| **反编译器** | `ghidra-decompiler` 2.1 | Apache-2.0 | **实测通过但违反 §7** | **先做隔离验证，不直接接**（§3） |
| .NET / CIL | `dotscope` | Apache-2.0 | 未实测 | 有需要时用 |
| DWARF | `gimli`（已在用） | MIT OR Apache-2.0 | —— | 保持 |
| WASM | `wasmparser` | Apache-2.0 WITH LLVM-exception | 未实测 | 有需要时用 |

**没有任何一个缺口是"必须自己从零写"的**，唯一接近的是 DEX。

## 2. 逐项说明

### 2.1 架构：SLEIGH 路线可以把 9 种扩到 40+ 种

**实测证据**（`dependency-probe-evidence.md` §1）：
`wazabin-sleigh` 成功解出 x86_64 `mov eax, 1` → `MOV EAX,1`。

**它为什么重要**：我们现在用 capstone，覆盖 9 种架构。IDA 有 150+。
`ghidra-decompiler` 内嵌了 **39 个语言目录**（实测列出）：
6502、68000、8048、8051、8085、AARCH64、ARM、Atmel、BPF、CP1600、CR16、
Dalvik、DATA、eBPF、HCS08、HCS12、Hexagon、**JVM**、Loongarch、M16C、M8C、
MC6800、MCS96、MIPS、NDS32、PA-RISC、PIC、PowerPC、RISCV、Sparc、SuperH、
SuperH4、TI_MSP430、Toy、tricore、V850、x86、Xtensa、Z80。

注意 **Dalvik 和 JVM 也在里面** —— 这对 M11（APK/DEX）是意外收获。

**保留意见（必须写下来）**：
- `wazabin-*` 是**全新项目**（仓库 2026-08-24 创建，0 star）。
- 它的 spec 数据来自**第三方** `Garfield1002/open_sleigh`（git submodule）。
- spec 在 `build.rs` 里现场编译，**构建很慢**（本机实测超过 10 分钟）。
- 所以：**先做 spike，不要直接变成主路径**。

### 2.2 文件格式：Mach-O 有现成轮子，DEX 没有

**Mach-O（M12）—— `object` 0.40 实测通过。**
按规格合成 FAT_MAGIC 头（大端 0xCAFEBABE + nfat_arch=2），实测输出：
```
OK, 2 slice(s): cputype=U32(01000007) offset=0x1000 size=0x400
              | cputype=U32(0100000c) offset=0x2000 size=0x400
```
`0x01000007` = x86_64，`0x0100000c` = arm64，解析正确。
这正是 `goblin` **做不到**的部分（goblin 的 fat 支持是 `Mach::Fat(MultiArch)`，
且**不解析代码签名、不支持 dyld cache**）。

**版本要求**：`MachOFatFile` 是 **0.32.0 才加入**的（旧 fat API 被移除）。
必须 ≥0.32，当前 0.40.0。本机 `.cargo-home` 里已缓存 0.40.0。

### 2.3 ⚠️ `object` 的威胁模型与我们的用途冲突（**需要你决策**）

它的 README 原文（本人亲自抓取核对，非二手转述）：

> This crate is intended to be used with trusted inputs. For example, it is
> suitable for use as part of a compiler toolchain, **but not for malware
> analysis or a service exposed to arbitrary inputs.**
>
> There is little effort to mitigate denial of service attacks (such as
> algorithmic complexity attacks due to overlapping structures).
>
> The crate does not aim to replicate the behaviour of platform loaders...
> Data returned by the parser may not match the data used by a loader.

**BitFlip 恰恰就是"分析任意不可信二进制"** —— 这是它声明的非适用场景。
而且第三条与 §7 直接相关：它自己承认"解析结果可能与加载器实际用的数据不一致"，
所以任何 on-disk vs loaded 的差异**必须作为结论标出来**，不能默认一致。

**两个可选方案（我倾向 A+B 组合）**：
- **A. 加资源限额**：每次解析包一层墙钟超时 + 分配上限 + 有界迭代，
  触顶时作为**显式降级结果**上报（不是静默返回空）。
- **B. goblin 走主路径，`object` 只补 goblin 的盲区**
  （fat Mach-O、代码签名、dyld cache）。

无论选哪个，这条"为什么不用默认姿态"的**理由必须写进代码注释**，
否则下一个人会以为是漏配了。

### 2.4 DEX：没有可用的轮子（M11 的真实风险）

- `dex`（MIT）是唯一像样的纯 Rust DEX 解析器（3,051 行），
  但**冻结在 2021-05-31**。
- `smali` 是这一带维护最活跃的（2026-08），但**每一个版本都是 GPL-3.0-only**，
  直接出局。
- `dalvik`（MIT OR Apache-2.0）还活着，但它是**反汇编器，不是容器解析器**。
- `dex-parser` / `dexlib` / `dex-parser-rs` 等**不存在**（crates.io 404）。

**结论**：DEX 要么自己写，要么接手维护 `dex`。
**APK 本身是好消息**：它就是个 ZIP，`zip` 9.0.1 是 MIT 且纯 Rust。
**建议**：M11 先做"APK 解包 + 复用已有 ELF 路径处理 `lib/*.so`"，
这一段**完全不需要新轮子**；DEX 单独作为高风险子项排后。

### 2.5 不要用的（含**理由**，因为许可是干净的）

| 轮子 | 许可 | 不用它的**真实**理由 |
| --- | --- | --- |
| `lief` | **Apache-2.0（干净）** | 构建期**从网络下载预编译二进制**；C++ FFI；docs.rs 对**所有版本**都构建失败 |
| `jingle_sleigh` | MIT | 编译 13034 行 C++，破坏单文件可执行 |
| `sleigh-compiler` | Apache-2.0 | **111232 行 C++ 对 149 行 Rust**，最差的 FFI 比例 |
| `libsla` | Apache-2.0 | FFI，且 2025-11 后无更新 |
| `sleigh-rs` | MIT | 2023-07 后停更，只是一个 parser |

**特别说明 `lief`**：如果只看许可会误判为"可以用"（它的许可以及它 vendored 的
mbedtls/nlohmann/spdlog/Catch2 全是宽松许可）。**但它的构建要联网下预编译产物**，
这对"可复现构建 + 单文件可执行"是硬伤。这条理由必须记录，
否则将来有人会重新提它。

## 3. ⚠️ 反编译器：`ghidra-decompiler` 能跑，但输出违反 §7

**这是本次调研最重要的发现。** 我实测编译并运行了它（不是读文档）。

### 它能做对的事
输入 `mov eax,1; add eax,2; ret`（9 字节），输出：
```c
xunknown8 func_0x00000000(void)
{
  return 3;
}
```
**常量折叠是对的**（1+2=3）。这是真本事，不是花架子。

### 但它同时暴露了两个 §7 硬伤
1. **函数名是 `func_0x00000000`** —— 正是 CLAUDE.md §7 第一句
   明文禁止的占位名（"不要生成 `func_xxx` 之类的占位名"）。
2. **类型是 `xunknown8`** —— 一个我们无法核对的类型名。

### 第二组测试才是决定性的
输入一段带分支的完整函数：
`test edi,edi; je +5; mov eax,1; ret; xor eax,eax; ret`

输出：
```c
void func_0x00000000(void)
{
  return;
}
```

**整段逻辑消失了**：没有 `test edi,edi` 的判断，没有两个 `ret` 返回不同值
（1 / 0）的事实。而它**没有任何提示说明自己丢掉了东西** ——
输出看起来完全像一次成功。

**这正是 §7 最担心的失败模式：静默的错误输出。**
不是"它算错了"，而是"它不说自己没做出来"。

### 另外两个量化代价（本机实测，非文档）
- **体积**：`ghidra-decompiler` 的 rlib 是 **212 MB**；
  对比 capstone 的 8.2 MB（**26 倍**）。`wazabin-sleigh` 是 54.4 MB。
  我们目前 `bitflip-cli.exe` 是单文件可执行，这个量级必须正视。
- **构建时间**：首次编译约 8 分钟；`wazabin-sleigh-precompile` 因在
  `build.rs` 里现场编译 SLEIGH spec，单独就要 10 分钟以上。

### 建议（不直接接）
**先做隔离 spike，不接入主路径**。spike 的验收标准是"它能不能满足 §7"：
1. 强制它**不得**输出 `func_*` 占位名 —— 要么拿到真名，要么我们改写输出。
2. **必须能判断它是否丢掉了代码**：给它已知函数体，检查输出是否覆盖全部指令；
   覆盖不全时我们要能**知道**并标出来。
3. 明确失败的边界：哪些输入它会静默给错答案。

如果 1/2 做不到，那它对我们就是**负资产** —— 一个会说谎的分析结果
比没有分析结果更糟，因为它会被用户相信。

## 4. 必须 deny-list 的 GPL 地雷

| crate | 许可 | 它本来能干什么 |
| --- | --- | --- |
| `exe` | **GPL-3.0** | PE 解析 |
| `dotnetdll` | **GPL-3.0+** | .NET metadata 解析 |
| `smali` | **GPL-3.0-only** | DEX（这一带最活跃的） |

三个都"本来很对口"，缺陷只在许可。**建议把 `cargo-deny` 的许可证检查
加进 `scripts/preflight.ps1`** —— 它正好符合 CLAUDE.md §5 的自检位置，
而且能自动拦住这类问题。.NET 的替代品是 `dotscope`（Apache-2.0）。

## 5. 我没能验证的（不要当成事实）

- **没有任何一件**做过 fuzz 或恶意输入测试。全部实测都是"良性小样本能不能跑通"。
  `object` 的 DoS 抗性、`ghidra-decompiler` 在畸形输入下的行为，**都未验证**。
- `apple-codesign`（MPL-2.0）的实际解析覆盖面未验证；
  `fdt` 的许可（报告为 MPL-2.0）我没有亲自复核。
- 所有"维护活跃度"都是从**发版时间**推断的，不是提交频率 ——
  这是代理指标，不等价。
- 子 agent 报告的 404 列表、`pdb` 的仓库归属等，我**未逐条复核**。
- `dotscope`、`clsmta`、`cildec` 等 .NET 轮子只看过元数据，**源码未读**。