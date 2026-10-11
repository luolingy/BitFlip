# Rust 二进制格式解析 crate 调研（BitFlip 选型用）

> 调研日期：2026-10-11。数据源：`https://crates.io/api/v1/crates/<NAME>` 与 `raw.githubusercontent.com` 的
> LICENSE 文件实抓。**每一条 license 结论都有 URL 出处**；无法证实的显式标注 `unverified`。
>
> 约束前提：单一自包含可执行文件、运行期零依赖、静态链接；**GPL/LGPL/AGPL/SSPL 一律禁用**；
> Apache-2.0 / MIT / BSD / MPL-2.0 / Zlib 可用（MPL-2.0 作为**未修改**依赖可用）。

---

## 0. 结论速览：三条必须知道的事

1. **`dotnetdll` 是 GPL-3.0+，直接出局。** 这是本次调研发现的唯一硬性 license 阻断项。
2. **`xz2` / `liblzma` 不是 LGPL，可用。** 任务书里的担心基于过时信息——liblzma 现在是 0BSD（旧版为 public domain），
   LGPL 只存在于 `getopt_long`，而它不参与 liblzma 静态库的构建。
3. **一批任务书里点名的 crate 根本不存在**：`gcn`、`nintendo`、`nintendo-rom`、`ecma335`、`rust-ar`、`debuginfo`、
   `uboot`、`uefi-firmware`、`rp2a03`、`unity-asset-parser`、`unitypack`(crate) —— 全部 HTTP 404。

---

## 1. WASM / WebAssembly

| crate | license | 纯 Rust / FFI | 总下载 | 最近下载 | 最新版本 @ 日期 | 仓库 |
|---|---|---|---|---|---|---|
| `wasmparser` | `Apache-2.0 WITH LLVM-exception OR Apache-2.0 OR MIT` | 纯 Rust | 258,396,111 | 85,660,950 | 0.261.0（`newest` 0.258.3）@ 2026-10-02 | [bytecodealliance/wasm-tools](https://github.com/bytecodealliance/wasm-tools) |
| `wasm-encoder` | `Apache-2.0 WITH LLVM-exception OR Apache-2.0 OR MIT` | 纯 Rust | 199,329,650 | 70,155,111 | 0.261.0（`newest` 0.258.3）@ 2026-10-02 | 同上 |
| `walrus` | `MIT/Apache-2.0` | 纯 Rust | 15,579,821 | 3,673,723 | 0.27.2 @ 2026-09-10 | [rustwasm/walrus](https://github.com/rustwasm/walrus) |
| `wasmtime` | `Apache-2.0 WITH LLVM-exception` | 纯 Rust（JIT，含少量平台汇编） | 39,494,899 | 11,079,878 | 49.0.2（`max` 50.0.0-rc.1）@ 2026-10-05 | [bytecodealliance/wasmtime](https://github.com/bytecodealliance/wasmtime) |
| `parity-wasm` | `MIT/Apache-2.0` | 纯 Rust | 17,304,536 | 1,222,571 | 0.45.0 @ **2022-05-26** | [paritytech/parity-wasm](https://github.com/paritytech/parity-wasm) |
| `wasmi` | `MIT/Apache-2.0` | 纯 Rust | 24,662,610 | 4,881,693 | 2.0.0 @ 2026-09-01 | [wasmi-labs/wasmi](https://github.com/wasmi-labs/wasmi) |
| `wasm-tools` | `Apache-2.0 WITH LLVM-exception OR Apache-2.0 OR MIT` | 纯 Rust（CLI） | 587,757 | 119,431 | 1.261.0（`newest` 1.258.3）@ 2026-10-02 | [bytecodealliance/wasm-tools](https://github.com/bytecodealliance/wasm-tools) |

**逐条结论**

- **`wasmparser` — 最优先选择。** 纯 Rust、零 FFI、事件驱动（流式，不物化整个模块），正是"分析不可信输入"想要的形态；
  由 Bytecode Alliance 活跃维护。**采纳。**
- **`wasm-encoder` — 需要写回/重编码时采纳。** 与 wasmparser 同版本号同步发布。
- **`walrus` — 需要变换（增删函数、改导入）时用。** 但它会把整个模块建成 AST 并物化，对超大 wasm 内存压力大，
  纯只读分析场景反而应优先用 wasmparser。
- **`wasmtime` — 作为"库解析器"是错配，且不建议。** 反向依赖的证据：`wasmtime` 自己依赖 `wasmparser` 做解析
  （见其 Cargo.toml features 中的 `wasmparser/...` 传递）。它是要**执行**代码的 JIT：会 mmap RWX 页、生成机器码、
  拉起线程池，与"静态零依赖的解析工具"目标相悖，且引入不可控的攻击面。**要解析就用 wasmparser，不要用 wasmtime。**
  - License 核实（任务书要求）：`Apache-2.0 WITH LLVM-exception` **属实**。实抓
    <https://raw.githubusercontent.com/bytecodealliance/wasmtime/main/LICENSE> 得到 Apache-2.0 全文 +
    文件末尾的 "LLVM Exceptions to the Apache 2.0 License" 段落。
    **兼容性结论：与 GPLv3/GPLv2 项目兼容（该 exception 正是为消解 Apache-2.0 专利条款与 GPLv2 的冲突而设，
    文本已明说允许 waive Section 3/9），且对本项目（不用 GPL）完全无障碍——LLVM-exception 只在 Apache-2.0 之上
    *放宽*义务，不新增限制。安全。**
- **`parity-wasm` — 不采纳。** 虽 MIT/Apache 且纯 Rust，但**最后发布 2022-05-26，已 4 年未更新**，
  且 WASM 提案（SIMD、多值、GC、组件模型）覆盖不全。
- **`wasmi` — 只在需要解释执行时考虑。** MIT/Apache，纯 Rust，无 JIT（比 wasmtime 轻），但同样超出"解析"需求。
- **`wasm-tools` — 不必作为库依赖。** 它是 CLI 集合，体积大；其 `demangle` feature 用到 `cpp_demangle` + `rustc-demangle`，
  这两个可以单独直接依赖。

> **未证实**：`wasm-tools` 1.261.0 与 `newest_version` 1.258.3 不一致（max_stable 比 newest 大），
> 原因未查明；不影响选型。

---

## 2. .NET / CIL / PE-managed ⚠️ 本节含一个 license 阻断项

| crate | license | 纯 Rust / FFI | 总下载 | 最近下载 | 最新版本 @ 日期 | 仓库 |
|---|---|---|---|---|---|---|
| **`dotnetdll`** | **`GPL-3.0+`** 🚫 | 纯 Rust | 12,416 | 2,541 | 0.3.0 @ 2026-06-24 | [nickbclifford/dotnetdll](https://github.com/nickbclifford/dotnetdll) |
| `dnfile`（Rust） | `Apache-2.0` | 纯 Rust | 1,531 | 1,159 | 0.5.1 @ 2026-05-29 | [marirs/dnfile-rs](https://github.com/marirs/dnfile-rs) |
| `dotscope` | `Apache-2.0` | 纯 Rust | 17,905 | 11,109 | 0.9.1 @ 2026-09-05 | [ATRAPSLLC/dotscope](https://github.com/ATRAPSLLC/dotscope) |
| `clrmeta` | `MIT` | 纯 Rust | 291 | 185 | 0.1.0 @ 2026-02-14 | [coconutbird/clrmeta](https://github.com/coconutbird/clrmeta) |
| `cildec` | `MIT` | 纯 Rust | 1,415 | 1,415 | 0.1.0 @ 2026-09-20 | [binsnake/cildec](https://github.com/binsnake/cildec) |
| `cilly` | `MIT OR Apache-2.0` | 纯 Rust | 2,776 | 11 | 0.1.1 @ 2024-06-02 | [FractalFir/rustc_codegen_clr](https://github.com/FractalFir/rustc_codegen_clr) |
| `mslnk` | `MIT` | 纯 Rust | 206,927 | 40,805 | 0.1.8 @ 2022-05-27 | [dobefore/mslnk](https://github.com/dobefore/mslnk) |
| `winmd` | `MIT` | 纯 Rust | 9,756 | 91 | 0.6.0 @ 2020-11-13 | [microsoft/winmd-rs](https://github.com/microsoft/winmd-rs) |
| `windows-metadata` | `MIT OR Apache-2.0` | 纯 Rust | 5,326,993 | 669,780 | 0.100.0 @ 2026-09-03 | [microsoft/windows-rs](https://github.com/microsoft/windows-rs) |
| `pelite` | `MIT` | 纯 Rust | 911,481 | 148,706 | 0.10.0 @ 2022-11-04 | [CasualX/pelite](https://github.com/CasualX/pelite) |
| `goblin` | `MIT` | 纯 Rust | 77,880,458 | 18,786,313 | 0.10.7 @ 2026-05-28 | [m4b/goblin](https://github.com/m4b/goblin) |

### 🚫 LICENSE 风险：`dotnetdll` 是 GPL-3.0+

`https://crates.io/api/v1/crates/dotnetdll` → 0.3.0 版本 entry 的 `"license":"GPL-3.0+"`。
这是**强 copyleft**，对闭源/单一自包含二进制是传染性的。**在"GPL 禁用"前提下必须排除。**
（说明：该 license 字符串来自 crates.io 元数据，仓库内 LICENSE 文件未实抓 —— **文件级 unverified**，
但 crates.io 的 SPDX 字段是权威声明，足以作为排除依据。）

### 是否存在任何纯 Rust 的 .NET metadata 解析器？——**存在，且不止一个**

任务书假设"可能没有"，实际**有 4 个可用候选**：

- **`dotscope` — 最强候选。** Apache-2.0（实抓 <https://raw.githubusercontent.com/ATRAPSLLC/dotscope/main/LICENSE>，
  200，Apache-2.0 全文，"Copyright 2025-2026 ATRAPS LLC"）。定位就是"分析 .NET PE 可执行文件"，
  含 IL 仿真、x86（iced-x86）、去混淆、z3 等 feature。19 个版本、259k 行 Rust。**唯一顾虑**：体量较大，
  且项目名与 BitFlip 概念上撞车（发布者早期账号名 `BinFlip`），但两者无关联。
- **`clrmeta` — 纯 ECMA-335 读/写，MIT**（实抓 <https://raw.githubusercontent.com/coconutbird/clrmeta/main/LICENSE>，
  200，MIT，"Copyright (c) 2026 coconutbird"）。**但仅 1 个版本 0.1.0，成熟度 unverified。**
- **`cildec` — 描述为"零依赖、panic-free 的 ECMA-335 metadata 与 CIL 方法体解码器"**，MIT，
  带 `no_std` 分类。**零依赖 + panic-free 对"解析不可信输入"是很好的属性**，但同样只有 0.1.0 单版本，
  **成熟度 unverified**。
- **`dnfile`(Rust) — Apache-2.0**，是 Python `dnfile` 的 Rust 重实现，做的是二进制提取（`dndump`/`dnstrings`），
  偏"提取"而非完整 metadata 解析。**注意：任务书说"dnfile 是 Python，不存在同名 Rust crate" —— 这一半是错的，
  Rust crate `dnfile` 确实存在。**

> **Python 侧澄清**：`dnfile` 的 Python 原版在 [malwarefrank/dnfile](https://github.com/malwarefrank/dnfile)，
> LICENSE 实抓为 **MIT**（"Copyright (c) 2020, MalwareFrank"）。`dncil`（Mandiant）**没有 Rust 版本**（404），
> 其 LICENSE 实抓为 **Apache-2.0**（"Copyright (C) 2022 Mandiant, Inc."，注意文件是 `LICENSE.txt` 不是 `LICENSE`）。

**`ecma335` — 不存在（HTTP 404）。** `{"errors":[{"detail":"crate \`ecma335\` does not exist"}]}`。

### PE / CLR header 支持

- **`pelite` — MIT（实抓确认）。** 注意仓库根目录的 LICENSE 文件名是**小写 `license.txt`**，
  `LICENSE` / `LICENSE-MIT` / `LICENSE-APACHE` 全部 404；
  实抓 <https://raw.githubusercontent.com/CasualX/pelite/master/license.txt> → 200，MIT，
  "Copyright (c) 2016-2018 Casper"。`Cargo.toml` 亦为 `license = "MIT"`。
  **`pelite` 内建 .NET 目录支持**（features 列表含 `resources_nostd`，且 crate 提供 `msrtti` 等 bin）。
  **注：crates.io 上的发布停在 2022，但仓库 HEAD 的 Cargo.toml 是 edition 2024 / rust-version 1.93 —— 并非弃用。**
- **`goblin` — MIT（实抓确认）**，<https://raw.githubusercontent.com/m4b/goblin/master/LICENSE>，
  "Copyright (c) m4b 2016-2024"。**goblin 能解析 PE 的 Data Directory，从而读到 CLR header（Directory Entry 14，
  `IMAGE_DIRECTORY_ENTRY_COM_DESCRIPTOR`）的 RVA/Size —— 但 goblin 只给你这个目录项本身，
  不含 .NET metadata（#~ 流、TypeDef/MethodDef 表）的解析。** 也就是说：**goblin 能定位 CLR header，不能解析它。**
  > `unverified`：未逐行阅读 goblin 的 `pe` 模块源码确认是否对 COM descriptor 目录内容做任何结构化解析。
  > 从其文档描述（"ELF, Mach-o, and PE binary parsing"）与 feature 列表看，不含 ECMA-335 表解析。
- **`winmd` — MIT，但已 6 年未更新（2020-11-13）**，且只面向 WinRT `.winmd` 文件，**不适合通用 .NET 程序集**。
- **`windows-metadata` — MIT OR Apache-2.0，是真实的已发布 crate**（任务书要求确认）。
  描述即 `"Low-level metadata library for ECMA-335"`，来自 microsoft/windows-rs，31 个版本，
  **2026-09-03 仍在发布**。MIT 半边实抓确认（<https://raw.githubusercontent.com/microsoft/windows-rs/master/license-mit>，
  200，"Copyright (c) Microsoft Corporation."）；**Apache 半边文件未抓 → unverified**，但 SPDX 声明权威。
  **注意：它是"底层 metadata 库"，为 windows-rs 的代码生成服务，面向 .winmd 生态；用于分析任意用户 .NET 程序集需自行验证。**
- **`cilly` — MIT OR Apache-2.0**，但它是 `rustc_codegen_clr` 的**链接器/写回**组件（做"生成 .NET 程序集"），
  **不是解析器**，方向相反。最后发布 2024-06，2411 次下载。

**本节建议（.NET 路径）**：`pelite` 或 `goblin` 负责 PE + 定位 CLR header → `dotscope`(Apache-2.0) 或
`clrmeta`/`cildec`(MIT) 负责 ECMA-335 表与 CIL 解码。**`dotnetdll` 禁用。**

---

## 3. 游戏机 / Unity / 解析原语

### 3.1 任务书点名但**不存在**的 crate（全部 HTTP 404）

`gcn`、`nintendo`、`nintendo-rom`、`rp2a03`、`unity-asset-parser`、`unitypack`(crate 名)。
另有 `nes-emu` 也是 404。

### 3.2 存在但**名不符实（decoy）**的 crate ⚠️

| crate | 真实用途 | 为何是 decoy |
|---|---|---|
| `nes` | "New Error System for rust"（错误处理库） | **不是 NES 模拟器**；GitHub [TrionProg/nes](https://github.com/TrionProg/nes) |
| `sm4` | RustCrypto 的**中国国标 SM4 分组密码**（GB/T 32907） | **不是 Switch 的 SM4 密钥派生** |
| `nso` | "Nintendo Switch **Online** APIs"（联机服务 API） | **不是 `.nso` 可执行格式解析器** |
| `nca` | 药代动力学非房室分析 | **不是 Nintendo Content Archive** |
| `assets` | 通用异步资源管理（GitLab 托管，2018 停更） | **不是游戏资源格式** |
| `unity` | "Library for working with Unity projects"，**仅 81 行 Rust，无 repo 字段**，2024 停更 | **不是资源解析器** |

### 3.3 真实可用的格式 crate

| crate | license | 纯 Rust/FFI | 总下载 | 最近下载 | 最新版本 @ 日期 | 仓库 | 结论 |
|---|---|---|---|---|---|---|---|
| `yaz0` | `MIT` | 纯 Rust | 34,681 | 2,511 | 0.3.0 @ **2021-02-11** | [gcnhax/yaz0-rs](https://github.com/gcnhax/yaz0-rs) | 真 Yaz0（GC/Wii）压缩，但已 5 年停更 |
| `szs` | `MIT` | 纯 Rust | 31,202 | 181 | 0.3.7 @ 2024-07-20 | [riidefi/RiiStudio](https://github.com/riidefi/RiiStudio) | **Yaz0 + YAY0/SZP 都支持，比 `yaz0` 新，优先选它** |
| `nds` | `MIT` | 纯 Rust | 4,892 | 32 | 0.2.0 @ 2022-09-15 | [Roughsketch/nds](https://github.com/Roughsketch/nds) | 真 NDS ROM 解析，430 行，停更 |
| `unity-asset` | `MIT` | 纯 Rust | 1,958 | 426 | 0.2.0 @ 2025-12-26 | [Latias94/unity-asset](https://github.com/Latias94/unity-asset) | **Unity 资源解析（YAML + 二进制 AssetBundle/SerializedFile），工作区含 core/binary/yaml/decode/cli** |
| `unity-rs-core` | `MIT` | 纯 Rust | 667 | 667 | 0.6.0 @ 2026-10-08 | [seiunx-dev/unity-rs](https://github.com/seiunx-dev/unity-rs) | 活跃（11 个版本），headless 解析/导出 |
| `unityfs` | unverified | 纯 Rust | 797 | 699 | 0.1.4 @ 2026-08-28 | [lmmtrr/unityfs](https://github.com/lmmtrr/unityfs) | 描述为纯 Rust Unity 序列化文件/AssetBundle 解析 |
| `gameboy` | `MPL-2.0` | 纯 Rust | 7,183 | 27 | 0.1.5 @ 2025-02-06 | [raphamorim/gameboy](https://github.com/raphamorim/gameboy) | 是**模拟器**不是格式解析；MPL-2.0 作为未修改依赖可用 |
| `gba` | `Zlib OR Apache-2.0 OR MIT` | 纯 Rust | 66,480 | 2,142 | 0.15.0 @ 2025-11-16 | [rust-console/gba](https://github.com/rust-console/gba) | 面向 GBA **开发**（写 ROM），不是 ROM 解析 |
| `mos6502` | `BSD-3-Clause` | 纯 Rust | 25,224 | 5,179 | 0.10.1 @ 2026-06-26 | **repo 字段为 null** | 下载最多、维护最新的 6502 模拟器；无源码地址是风险 |
| `tetanes-core` | `MIT OR Apache-2.0` | 纯 Rust | 8,701 | 2,194 | 0.17.0 @ 2026-09-07 | [lukexor/tetanes](https://github.com/lukexor/tetanes) | **活跃维护的 NES 模拟核心** |

**关键判断：**

- **Yaz0 → 用 `szs` 而非 `yaz0`。** `yaz0` 只做 Yaz0，2021 停更；`szs` 同时支持 Yaz0/YAY0/SZP 且 2024 还在更新。
- **Unity 资源 → 有完整 Rust 生态，任务书的悲观假设不成立。** 首选 `unity-asset`（模块化，分 binary/yaml/decode）
  或 `unity-rs-core`（更活跃）。另有微软的 [unity-asset-graph-rs](https://github.com/microsoft/unity-asset-graph-rs)
  （查询资产关系，非解析本体）。
- **`unitypack` 是 Python**：真实仓库是 **[HearthSim/UnityPack](https://github.com/HearthSim/UnityPack)**（不是 `ssut/unitypack`，
  后者 404），MIT，LICENSE 实抓确认（`LICENSE` 文件，无 `.txt` 后缀），但 **2022-01 起停更**。
  UnityPy 的真实仓库是 **[K0lb3/UnityPy](https://github.com/K0lb3/UnityPy)**（不是 nesrak1，404），MIT（GitHub API 元数据；
  **LICENSE 文件本身未抓 → 文件级 unverified**），1481 stars，2026-10 仍在推送。
- **Switch NCA / Switch SM4 加密：没有任何 Rust crate。** NCA 格式、以及 Switch 基于 SM4 的密钥派生，
  在 crates.io 上搜不到实现（**`unverified` —— 是"未找到"，不是"证明不存在"**）。最接近的 Switch 格式 crate 是
  `nx-archive`（MIT，0.1.2 @ 2025-03-27，[RyouVC/nx-archive](https://github.com/RyouVC/nx-archive)）与
  `hactool-sys`（ISC，0.4.4 @ 2019-03-05，自称 "Currently untested"）。
- **`rp2a03` 不存在。** NES CPU（6502）模拟用 `mos6502` 或 `tetanes-core`。

### 3.4 解析原语（Primitives）

| crate | license | 纯 Rust/FFI | 总下载 | 最近下载 | 最新版本 @ 日期 | 仓库 |
|---|---|---|---|---|---|---|
| `binrw` | `MIT` | 纯 Rust | 14,841,774 | 4,421,983 | 0.15.2 @ 2026-07-23 | [jam1garner/binrw](https://github.com/jam1garner/binrw) |
| `nom` | `MIT` | 纯 Rust | 784,173,595 | 181,858,805 | 8.0.0 @ 2025-01-26 | [rust-bakery/nom](https://github.com/rust-bakery/nom) |
| `scroll` | `MIT` | 纯 Rust | 91,685,717 | 20,905,356 | 0.13.0 @ 2025-05-26 | [m4b/scroll](https://github.com/m4b/scroll) |
| `zerocopy` | `BSD-2-Clause OR Apache-2.0 OR MIT` | 纯 Rust | 994,820,195 | 274,589,025 | 0.8.62 @ 2026-10-08 | [google/zerocopy](https://github.com/google/zerocopy) |
| `bytemuck` | `Zlib OR Apache-2.0 OR MIT` | 纯 Rust | 407,804,029 | 110,935,549 | 1.25.2 @ 2026-07-19 | [Lokathor/bytemuck](https://github.com/Lokathor/bytemuck) |

**License 逐条实抓确认（全部 200，全部与 crates.io 声明一致）：**
- `binrw`: <https://raw.githubusercontent.com/jam1garner/binrw/master/LICENSE> → MIT，"Copyright (c) jam1garner and other contributors"。
- `scroll`: <https://raw.githubusercontent.com/m4b/scroll/master/LICENSE> → MIT，"Copyright (c) m4b 2016"。
- `bytemuck`: `LICENSE-MIT`（MIT，© 2019 Daniel 'Lokathor' Gee）、`LICENSE-APACHE`（Apache-2.0）、`LICENSE-ZLIB`（zlib）**三份俱在**。
- `zerocopy`: 仓库**没有裸 `LICENSE`**（404）；真实文件是 `LICENSE-MIT` / `LICENSE-APACHE` / `LICENSE-BSD`（后者 BSD-2-Clause，"Copyright 2019 The Fuchsia Authors"）。

**两个操作要点：**
- **`goblin` 0.10.6 已被 yank**（2026-05-28）。**锁定 `>=0.10.7`。**
- **`zerocopy` 的 `max_version` 是 `0.9.0-alpha.0`**，而 `newest_version`/`max_stable_version` 是 `0.8.62`。
  **别让依赖解析器选到 alpha 版。**

**选型建议**：`scroll`（goblin 的底层，与现有栈一致）+ `zerocopy`/`bytemuck` 做零拷贝视图；
`binrw` 适合"声明式描述结构体"；`nom` 是组合子风格。三者可共存，按模块复杂度选。

---

## 4. 固件 / 嵌入式

| crate | license | 纯 Rust/FFI | 总下载 | 最近下载 | 最新版本 @ 日期 | 仓库 |
|---|---|---|---|---|---|---|
| `uefi` | `MIT OR Apache-2.0` | 纯 Rust | 2,598,789 | 517,460 | 0.41.0 @ 2026-09-21 | [rust-osdev/uefi-rs](https://github.com/rust-osdev/uefi-rs) |
| `uefi-raw` | `MIT OR Apache-2.0` | 纯 Rust | 2,440,424 | 875,718 | 0.17.0 @ 2026-09-21 | 同上 |
| `fdt` | **`MPL-2.0`** | 纯 Rust (`no_std`) | 1,459,247 | 407,965 | 0.1.5（`newest` 0.2.0-alpha3）@ 2026-10-01 | [repnop/fdt](https://github.com/repnop/fdt) |
| `device_tree` | `MIT`（仅 Cargo.toml 声明） | 纯 Rust | 2,127,108 | 503,233 | 1.1.0 @ **2017-11-30** | [mbr/device_tree-rs](https://github.com/mbr/device_tree-rs) |
| `device_tree_parser` | `MIT` | 纯 Rust | 1,582 | 220 | 0.4.0 @ 2025-07-01 | [iainh/device_tree_parser](https://github.com/iainh/device_tree_parser) |
| `deforest` | `MIT` | 纯 Rust | 6,817 | 23 | 0.3.2 @ 2024-04-01 | [kadiwa4/deforest](https://github.com/kadiwa4/deforest) |
| `devicetree` | `Apache-2.0` | 纯 Rust | 4,248 | 14 | 0.1.1 @ 2022-11-17 | [duanyu-yu/DeviceTree](https://github.com/duanyu-yu/DeviceTree) |
| `dtb` | `MIT`（仅 Cargo.toml 声明） | 纯 Rust | 29,934 | 680 | 0.2.0 @ 2019-12-13 | [ababo/dtb](https://github.com/ababo/dtb) |
| `ihex` | `MIT OR Apache-2.0` | 纯 Rust | 14,541,886 | 2,962,080 | 3.0.0 @ 2020-06-15 | [martinmroz/ihex](https://github.com/martinmroz/ihex) |
| `intelhex` | `MIT`（**仓库无 LICENSE 文件**） | 纯 Rust | 1,545 | 192 | 0.2.1 @ 2025-06-22 | [tabre/intelhex](https://github.com/tabre/intelhex) |
| `srec` | `MIT` | 纯 Rust | 179,716 | 11,614 | 0.2.0 @ 2020-06-26 | [The6P4C/srec](https://github.com/The6P4C/srec) |
| `elfy` | `MIT` | 纯 Rust | 16,318 | 82 | 0.2.2 @ 2019-12-06 | [JerTH/elfy](https://github.com/JerTH/elfy) |
| `object` | `Apache-2.0 OR MIT` | 纯 Rust | 650,319,172 | 120,660,931 | 0.40.0 @ 2026-08-01 | [gimli-rs/object](https://github.com/gimli-rs/object) |

### ⚠️ 关键发现

**1. `uboot` 不存在（HTTP 404），且没有替代品 —— 必须手写。**

crates.io 搜索 `?q=uboot`（28 条）**没有任何 U-Boot uImage 头解析器**。存在的只是 `uboot-shell`（MIT，
与真实串口上的 U-Boot 通信）、`fitimage`、`spl_tool`、`uboot-nand-dump` 等。
**U-Boot legacy uImage 头（`IH_MAGIC` 0x27051956）没有现成 crate —— 这块要自己实现。**

**2. `uefi-firmware` 不存在（HTTP 404），搜索 `?q=uefi-firmware` 返回 0 条。**
用 `uefi-raw` 替代。（**不要**用 `r-efi`：它是 `MIT OR Apache-2.0 OR LGPL-2.1-or-later` 三选一，
**含 LGPL 选项**，对本项目的 license 策略是多余的摩擦。）

**3. `fdt` 是 MPL-2.0，不是 MIT/Apache —— 最容易踩的坑。**
实抓 <https://raw.githubusercontent.com/repnop/fdt/main/LICENSE> → 200，Mozilla Public License Version 2.0；
`LICENSE-MIT` → 404。`Cargo.toml` 亦为 `license = "MPL-2.0"`。
**MPL-2.0 是文件级 copyleft：作为未修改依赖可用（符合任务书约定），但一旦修改 `fdt` 的源文件，
就必须公开该文件**。若要规避，用 `device_tree_parser`（MIT）或 `deforest`（MIT）。

**4. `fit` 是"假朋友"—— 它解析运动设备 FIT（Garmin/Ant+），不是 U-Boot FIT。**
真正的 U-Boot FIT crate 是 **`fitimage`**：`MIT OR Apache-2.0`，
0.1.7 @ 2026-09-28，107,905/44,688 下载，[drivercraft/ostool](https://github.com/drivercraft/ostool)。
**注意：`fitimage` 的定位是"生成 U-Boot FIT 镜像"，读取支持 unverified。**

**5. `object` 的 README 明确警告"不适用于恶意软件分析"—— 对本项目是最高优先级风险项。**

> 原文（实抓 <https://raw.githubusercontent.com/gimli-rs/object/master/README.md>）：
> *"This crate is intended to be used with trusted inputs... but not for malware analysis or a service
> exposed to arbitrary inputs."* 并提到不做算法复杂度 DoS 缓解。

**这直接与 BitFlip 的用途（解析任意不可信二进制）冲突。** `object` 是优秀的 ELF/Mach-O/PE 通用库，
但**不能把它当作对抗性输入解析器**：即便有 `catch_unwind`，攻击者仍可用构造输入造成 CPU/内存耗尽。
**建议：把 `object` 视为"可信样本快速解析"路径，对抗性输入要么加资源配额（超时、内存上限），
要么走 `goblin` + 手工解析。这一条必须写进设计文档。**

**6. `device_tree` / `dtb` / `intelhex` 仓库内没有 LICENSE 文件。**
- `device_tree`：`LICENSE`、`LICENSE.md` 均 404，仓库根（GitHub contents API）只有 `Cargo.toml`/`examples/`/`src/`。
  **仅 Cargo.toml 声明 MIT。→ 文件级 unverified。**
- `dtb`：`LICENSE`、`COPYING` 均 404，同上。**→ 文件级 unverified。**
- `intelhex`：`LICENSE`（main/master）均 404，仓库只有 `Cargo.toml`/`README.md`/`examples/`/`src/`。
  **仓库地址是 `tabre/intelhex`，不是任务书猜的 `ArminJo/...`。→ 文件级 unverified。**
  **建议改用 `ihex`（14.5M 下载，MIT OR Apache-2.0）或 `intelhex-rs`（MIT，LICENSE 文件实抓确认）。**

**7. `srec` 的 license 文件名是英式拼写 `LICENCE.md`**（`LICENSE` 和 `LICENSE.md` 都 404）。
实抓 <https://raw.githubusercontent.com/the6p4c/srec/master/LICENCE.md> → 200，MIT，"Copyright 2019 Campbell Watson (The6P4C)"。

**8. `uefi`/`uefi-raw` 发生过重要重授权：MPL-2.0 → MIT OR Apache-2.0。**
0.33.0 及更早（`uefi`）/ 0.9.0 及更早（`uefi-raw`）都是 **MPL-2.0**；
自 **`uefi` 0.34.0（2025-02-07）** 与 **`uefi-raw` 0.10.0（2025-02-07）** 起改为 `MIT OR Apache-2.0`。
**用新版就没有 MPL 义务；若因兼容性锁到旧版，则要重新按 MPL-2.0 评估。**
仓库**没有裸 `LICENSE` 文件**（main/master 均 404），只有 `LICENSE-MIT` 与 `LICENSE-APACHE`（两份都实抓 200 确认）。

**9. `elfy` 已 2019 年停更**，ELF 解析应改用 `object` 或 `goblin`（但注意第 5 条的 `object` 警告）。

---

## 5. 调试 / 符号格式

| crate | license | 纯 Rust/FFI | 总下载 | 最近下载 | 最新版本 @ 日期 | 仓库 |
|---|---|---|---|---|---|---|
| `gimli` | `MIT OR Apache-2.0` | 纯 Rust (`no_std` 可选) | 592,733,555 | 98,120,882 | 0.34.0 @ 2026-06-25 | [gimli-rs/gimli](https://github.com/gimli-rs/gimli) |
| `addr2line` | `Apache-2.0 OR MIT` | 纯 Rust | 540,843,939 | 86,405,084 | 0.27.1 @ 2026-08-01 | [gimli-rs/addr2line](https://github.com/gimli-rs/addr2line) |
| `pdb` | `MIT OR Apache-2.0` | 纯 Rust | 6,941,620 | 981,829 | 0.8.0 @ **2022-06-08** | [willglynn/pdb](https://github.com/willglynn/pdb) |
| `pdb-addr2line` | `MIT/Apache-2.0` | 纯 Rust | 6,138,506 | 768,794 | 0.12.1 @ 2026-07-23 | [mstange/pdb-addr2line](https://github.com/mstange/pdb-addr2line) |
| `ms-pdb`（微软） | `MIT OR Apache-2.0` | 纯 Rust | 76,000 | 36,879 | 0.1.22 @ 2026-03-05 | [microsoft/pdb-rs](https://github.com/microsoft/pdb-rs) |
| `symbolic-debuginfo` | `MIT` | 纯 Rust | 2,252,830 | 589,637 | 13.9.0 @ 2026-07-09（`newest` 14.0.0-alpha.3 @ 2026-07-23） | [getsentry/symbolic](https://github.com/getsentry/symbolic) |
| `dwarf` | `MIT/Apache-2.0` | 纯 Rust | 7,024 | 193 | 0.0.3 @ **2016-07-12** | [philipc/rust-dwarf](https://github.com/philipc/rust-dwarf) |
| `debuginfo` | — | — | — | — | **不存在（404）** | — |

### ✅ 任务书要求核实的几项，结论如下

**`gimli` — `MIT OR Apache-2.0` 属实。**
实抓 <https://raw.githubusercontent.com/gimli-rs/gimli/master/LICENSE-MIT> → 200，MIT，
"Copyright (c) 2015 The Rust Project Developers"；
<https://raw.githubusercontent.com/gimli-rs/gimli/master/LICENSE-APACHE> → 200，Apache-2.0 全文。
**双许可确认。采纳。**

**`pdb`（microsoft/pdb）—— 任务书的归因是错的，这里必须纠正：**

- **`pdb` crate 的仓库是 [willglynn/pdb](https://github.com/willglynn/pdb)，不是 `microsoft/pdb-rs`。**
- **`pdb` 的 license 是 `MIT OR Apache-2.0`，不是"MIT"**（实抓 <https://crates.io/api/v1/crates/pdb>，
  0.8.0 entry `"license":"MIT OR Apache-2.0"`）。
- **`pdb` 最后发布 2022-06-08，已 4 年停更。**
- **`microsoft/pdb-rs` 发布的是另一个名字：`ms-pdb`**（0.1.22 @ 2026-03-05）。
  实抓 <https://raw.githubusercontent.com/microsoft/pdb-rs/main/LICENSE> → 200，**纯 MIT**（"Copyright (c) Microsoft Corporation."，
  没有 LICENSE-MIT/LICENSE-APACHE 拆分）。
- **微软仓库的 README 明确声明**（实抓）：*"THIS IMPLEMENTATION IS NOT AUTHORITATIVE AND IS NOT A REFERENCE IMPLEMENTATION"*，
  且 MSFZ 部分标注为 experimental。**不要把它当作权威 PDB 实现。**

→ **建议：`pdb`（willglynn，MIT OR Apache-2.0，成熟但停更）+ `pdb-addr2line`（活跃，配套符号化）
组成 PDB 路径。** `pdb-addr2line` 的 `LICENSE-MIT` 实抓 200（MIT，© 2018 Markus Stange）；
**`LICENSE-APACHE` 文件未抓 → unverified**（但 crates.io 声明 `MIT/Apache-2.0`）。

**`symbolic-debuginfo` — 任务书说"代码搬走了"，这个前提是错的。**

- **它没有弃用、没有 yank、没有被 fork 接管。** 仍由 getsentry 维护，仓库仍是
  [getsentry/symbolic](https://github.com/getsentry/symbolic)，**2026-07 仍在发布**。
- **license 是纯 MIT**（不是 MIT/Apache 双许可）。实抓
  <https://raw.githubusercontent.com/getsentry/symbolic/master/LICENSE> → 200，MIT，
  "Copyright (c) 2017 Sentry (https://sentry.io) and individual contributors."
  同仓库 README 的 License 段落亦写明 *"Symbolic is licensed under the MIT license.
  It uses some Apache2 licensed code from Apple for the Swift demangling."*
  （注意：这带来一个**传递性注意点** —— Swift demangling 部分含 Apple 的 Apache-2.0 代码，
  仍属许可范围，但混入 Apache-2.0 说明并非"纯净单许可"。）
- crates.io 搜索证实 **不存在 `symbolic-debuginfo` 的 fork/clone**（`?q=symbolic-debuginfo` 只有 2 条命中，
  另一条是无关的 `declaration_site`）。同族 `symbolic` / `symbolic-common` / `symbolic-demangle` /
  `symbolic-symcache` 全部 repo = getsentry/symbolic，全部 `MIT`。
- **结论：MIT，可用；任务书里"已搬到 MIT/Apache fork"的说法不成立 —— 它一直就是 MIT，也一直没搬。**

**`dwarf` — 不采纳。** 冻结在 0.0.3（2016-07-12），仅 7,024 次下载，是 `gimli` 的**已死前身**（同为 philipc 所写）。

**`debuginfo` — 不存在（404）。**

**建议**：DWARF 走 `gimli` + `addr2line`（两者同属 gimli-rs，配合默契，均双许可）；
PDB 走 `pdb` + `pdb-addr2line`；跨格式符号化用 `symbolic-debuginfo`（MIT）。
`symbolic-debuginfo` 的 feature 列表显示它**已经依赖 `gimli`、`pdb-addr2line`、`goblin`、`wasmparser`、`flate2`**，
与前述选型一致 —— 可作为一个"集成层"而非重复造轮子。

---

## 6. 归档 / 容器 / 杂项

| crate | license | 纯 Rust/FFI | 总下载 | 最近下载 | 最新版本 @ 日期 | 仓库 |
|---|---|---|---|---|---|---|
| `ar` | `MIT` | 纯 Rust | 9,998,366 | 1,722,479 | 0.9.0 @ 2021-08-16 | [mdsteele/rust-ar](https://github.com/mdsteele/rust-ar) |
| `cab` | `MIT` | 纯 Rust | 7,025,243 | 2,028,336 | 0.6.0 @ 2024-04-05 | [mdsteele/rust-cab](https://github.com/mdsteele/rust-cab) |
| `msi` | `MIT` | 纯 Rust | 5,962,514 | 1,718,257 | 0.10.0 @ 2026-02-23 | [mdsteele/rust-msi](https://github.com/mdsteele/rust-msi) |
| `cpp_demangle` | `MIT OR Apache-2.0` | 纯 Rust | 109,017,713 | 25,735,189 | 0.5.1 @ 2025-11-05 | [gimli-rs/cpp_demangle](https://github.com/gimli-rs/cpp_demangle) |
| `rustc-demangle` | `MIT/Apache-2.0` | 纯 Rust | 591,508,430 | 96,444,650 | 0.1.28 @ 2026-07-08 | [rust-lang/rustc-demangle](https://github.com/rust-lang/rustc-demangle) |
| `unicode-ident` | `(MIT OR Apache-2.0) AND Unicode-3.0` | 纯 Rust | 1,493,711,933 | 371,780,102 | 1.0.26 @ 2026-09-17 | [dtolnay/unicode-ident](https://github.com/dtolnay/unicode-ident) |
| **`cxxbridge`** | `MIT OR Apache-2.0` | 纯 Rust | 1,374 | 2 | **0.0.0，已 yank（2019-12-28）** 🚫 | **repo = null** |
| `cxx` | `MIT OR Apache-2.0` | 生成 FFI 绑定 | 81,332,613 | 11,513,597 | 1.0.205 @ 2026-10-11 | [dtolnay/cxx](https://github.com/dtolnay/cxx) |
| `cxxbridge-cmd` | `MIT OR Apache-2.0` | 纯 Rust（代码生成器） | 30,374,708 | 7,508,168 | 1.0.205 @ 2026-10-11 | 同上 |

**逐条结论**

- **`ar` — 采纳，但纠正归因。** **`rust-ar` 这个 crate 名不存在（404）。** `ar` crate **就是** rust-ar 仓库，
  作者 **mdsteele**，**与 rust-lang 无关**。MIT，实抓
  <https://raw.githubusercontent.com/mdsteele/rust-ar/master/README.md> → "rust-ar is made available under the MIT License"；
  仓库根有 `LICENSE`（GitHub contents API 确认，1074 字节）。**0.9.0 停更于 2021，但 172 万近期下载说明生态仍依赖它。**
- **`cab` — 采纳。** MIT，实抓 <https://raw.githubusercontent.com/mdsteele/rust-cab/master/LICENSE> → 200，
  "Copyright (c) 2017 Matthew D. Steele"。2024 更新。
- **`msi` — 采纳。** MIT，实抓 <https://raw.githubusercontent.com/mdsteele/rust-msi/master/LICENSE> → 200，
  同版权行。**2026-02 仍在发布，是三者中最活跃的。**
- **`cpp_demangle` — 采纳。** 双许可确认：`LICENSE-MIT` 与 `LICENSE-APACHE` 实抓均 200。
- **`rustc-demangle` — 采纳。** `MIT/Apache-2.0`（crates.io 声明；**raw LICENSE 文件未抓 → 文件级 unverified**）。
- **`cxxbridge` — 已 yank，不要用。** 只有 0.0.0 一个版本，2019-12-28 yank，累计 1,374 次下载，`max_stable_version` 为 null，
  **repository 字段为 null**。**真正的 crate 是 `cxx` 与 `cxxbridge-cmd`**（dtolnay，均 MIT OR Apache-2.0，2026-10-11 发布）。
  **注意：`cxx` 是做 C++ FFI 桥接的，不是"Rust 里解 C++ 符号"—— 解 C++ 符号用 `cpp_demangle`。**
- **`unicode-ident` — 采纳，但注意它是组合许可。** `(MIT OR Apache-2.0) AND Unicode-3.0` ——
  **`AND` 意味着必须同时满足 Unicode-3.0 条款**（不是 OR 可选）。Unicode 数据许可宽松，通常无实际影响，
  但 license 扫描工具会标记，**应在 NOTICE/许可清单里显式列出**。

---

## 7. 压缩（用于内嵌压缩段）

| crate | license | 纯 Rust/FFI | 总下载 | 最近下载 | 最新版本 @ 日期 | 仓库 |
|---|---|---|---|---|---|---|
| `flate2` | `MIT OR Apache-2.0` | **纯 Rust（默认）** | 740,784,478 | 179,194,983 | 1.1.10 @ 2026-08-28 | [rust-lang/flate2-rs](https://github.com/rust-lang/flate2-rs) |
| `miniz_oxide` | `MIT OR Zlib OR Apache-2.0` | 纯 Rust | 973,699,552 | 211,736,590 | 0.9.1 @ 2026-03-13 | [Frommi/miniz_oxide](https://github.com/Frommi/miniz_oxide) |
| `ruzstd` | `MIT` | 纯 Rust（仅解压） | 70,893,096 | 18,000,506 | 0.9.0 @ 2026-07-26 | [KillingSpark/zstd-rs](https://github.com/KillingSpark/zstd-rs) |
| `zstd` | `BSD-3-Clause` | **FFI**（可 vendored 静态） | 419,502,665 | 92,573,395 | 0.14.2 @ 2026-10-10 | [gyscos/zstd-rs](https://github.com/gyscos/zstd-rs) |
| `zstd-sys` | `BSD-3-Clause` | FFI (C) | 386,853,561 | 89,066,630 | 2.1.1+zstd.1.5.7 @ 2026-10-09 | 同上 |
| `bzip2` | `MIT OR Apache-2.0` | **纯 Rust（默认）** | 176,054,361 | 37,312,387 | 0.6.1 @ 2025-10-16 | [trifectatechfoundation/bzip2-rs](https://github.com/trifectatechfoundation/bzip2-rs) |
| `bzip2-sys` | `MIT/Apache-2.0` | FFI (C，可选) | 163,750,793 | 26,006,138 | 0.1.13+1.0.8 @ 2025-02-28 | 同上 |
| `lzma-rs` | `MIT` | 纯 Rust | 41,652,037 | 9,352,276 | 0.3.0 @ 2023-01-04 | [gendx/lzma-rs](https://github.com/gendx/lzma-rs) |
| `xz2` | `MIT/Apache-2.0` | FFI（liblzma，可 static） | 70,327,219 | 13,245,858 | 0.1.7 @ **2022-06-06** | [alexcrichton/xz2-rs](https://github.com/alexcrichton/xz2-rs) |
| `lzma-sys` | `MIT/Apache-2.0` | FFI (C) | 71,488,368 | 13,456,907 | 0.1.20 @ **2022-10-31** | 同上 |
| `brotli` | `BSD-3-Clause AND MIT` | 纯 Rust（FFI 可选） | 285,961,815 | 69,772,607 | 9.0.0 @ 2026-09-02 | [dropbox/rust-brotli](https://github.com/dropbox/rust-brotli) |
| `brotli-decompressor` | `BSD-3-Clause/MIT` | 纯 Rust | 287,922,647 | 71,788,273 | 6.1.0 @ 2026-10-11 | 同上 |
| `lz4_flex` | `MIT` | 纯 Rust | 150,803,985 | 39,574,236 | 0.14.0 @ 2026-07-14 | [pseitz/lz4_flex](https://github.com/pseitz/lz4_flex) |
| `zopfli` | `Apache-2.0` | 纯 Rust | 135,682,900 | 46,077,213 | 0.8.3 @ 2025-10-30 | [zopfli-rs/zopfli](https://github.com/zopfli-rs/zopfli) |

### 🟢 任务书要求核实的 license 风险 —— 结论：**没有任何一个是禁用的**

**① `xz2` / `lzma-sys` —— 不是 LGPL，可用。这是本次调研最重要的纠偏。**

任务书的担心（"liblzma 是 XZ Utils license，public domain + LGPL 部分，是否是传染性风险"）**基于过时信息**。

- **包装层（Rust crate）本身是 MIT/Apache-2.0**，不是 LGPL：
  `xz2` 0.1.7 与 `lzma-sys` 0.1.20 的 crates.io license 字段均为 `MIT/Apache-2.0`；
  `lzma-sys` 的 `Cargo.toml` 亦为 `license = "MIT/Apache-2.0"`。
  实抓 <https://raw.githubusercontent.com/alexcrichton/xz2-rs/master/LICENSE-MIT> → 200，MIT，"Copyright (c) 2016 Alex Crichton"。
- **被包装的 C 代码 `liblzma` 现在是 0BSD**（旧版是 public domain）。
  实抓 <https://raw.githubusercontent.com/tukaani-project/xz/master/COPYING> 原文：
  > `- liblzma is under the BSD Zero Clause License (0BSD).`
  > `- The command line tools xz, xzdec, lzmadec, and lzmainfo are under 0BSD except that, on systems that`
  > `  don't have a usable getopt_long, GNU getopt_long is compiled and linked in from the 'lib' directory.`
  > `  The getopt_long code is under GNU LGPLv2.1+.`

  **关键点：LGPL 只存在于 GNU `getopt_long`，它不属于 liblzma，也不参与 liblzma 静态库的构建**
  （`lzma-sys` 只编译 liblzma 静态库，不构建 xz/xzdec 等 CLI 工具）。
  **所以 LGPL 代码不会进入本项目的二进制。**
  - 0BSD 是最宽松的许可（**连署名都不要求**），比 MIT 更宽松。
  - 历史版本（`lzma-sys` 锁定的是 xz-5.2 子模块）的 COPYING 写的是 `liblzma is in the public domain`，
    结论不变（public domain 同样无义务）。
- **✅ 结论：`xz2` + `lzma-sys`（`static` feature）在"禁 GPL + 静态链接 + 零运行期依赖"前提下可用。**
  **唯一的真实问题是维护停滞**（2022 年后无发布，`xz2` 至今只有 8 个版本），不是 license。
  **若只需要解压，优先用纯 Rust 的 `lzma-rs`（MIT），彻底避开 FFI。**

> `unverified`：未逐行阅读 `lzma-sys/build.rs` 来确认其编译文件清单确实排除了 getopt_long。
> 该结论基于 xz 官方 COPYING 的措辞（getopt_long 属于 CLI 工具而非 liblzma）与 crate 的构建目标定义。

**② `zstd` — 包装层 crates.io 声明 `BSD-3-Clause`，C 库确认为 BSD-3-Clause。**

- `zstd` 0.14.2 与 `zstd-sys` 2.1.1 的 crates.io license 字段均为 **`BSD-3-Clause`**。
- **注意一个不一致点**：`gyscos/zstd-rs` 仓库自身的 `LICENSE` 文件是 **MIT**（"Copyright (c) 2016 Alexandre Bury"），
  而 crates.io 声明 `BSD-3-Clause`。**两者都宽松，实务上无障碍，但做 license 清单时以 crates.io 声明为准并注明差异。**
- 被包装的 C 库：实抓 <https://raw.githubusercontent.com/facebook/zstd/dev/LICENSE> →
  **"BSD License / For Zstandard software"**，Meta Platforms 版权，**确认为标准三条款 BSD**（无广告条款）。
- **✅ 结论：`zstd` + `zstd-sys` 用 `vendored` feature 静态链接 BSD-3-Clause 的 C 代码，
  license 干净、无运行期依赖。采纳。**

**③ `bzip2` — 重大好消息：新版本默认已经是纯 Rust，不再需要 C。**

- **`bzip2` 0.6.1 的 feature 定义：`default = ["dep:libbz2-rs-sys"]`**，
  C 后端被降级为可选：`bzip2-sys = ["dep:bzip2-sys"]`。也就是说**默认走纯 Rust 的 `libbz2-rs-sys`**。
- `bzip2` crate 本身 license = `MIT OR Apache-2.0`（实抓 `LICENSE-MIT`，MIT，
  "Copyright (c) 2014-2026 Alex Crichton and Contributors"）。
- `libbz2-rs-sys` 的 license 字段是 `bzip2-1.0.6`（Seward 风格，宽松）。
- 若显式启用 C 后端 `bzip2-sys`：其内嵌 libbz2 的许可是 Julian Seward 的四条件许可，
  **条件 2 是温和条款**：
  > *"The origin of this software must not be misrepresented... an acknowledgment in the product documentation
  > would be appreciated but is not required."*
  **这不是老式 BSD-4 的广告条款（没有广告义务）**，属宽松许可。
- **✅ 结论：确认任务书的判断基本正确（libbz2 确实是 BSD-4-Clause-*like*），
  但补充两点：① 它不是严格的 BSD-4（无广告义务，只有"不得歪曲来源"）；② 用 `bzip2` 0.6.x 的默认配置根本不会引入 C 代码。**
- `bzip2` 0.6.1 最后发布 2025-10-16，`bzip2-sys` 更早（2025-02-28）。

**④ `flate2` — 默认纯 Rust 后端，确认。**

- crates.io license = `MIT OR Apache-2.0`；实抓 <https://raw.githubusercontent.com/rust-lang/flate2-rs/main/LICENSE-MIT> →
  200，MIT，"Copyright (c) 2014-2026 Alex Crichton"。
- **默认 feature 是 `["rust_backend", "runtime_detection"]`**，而 `rust_backend = ["miniz_oxide", "any_impl"]` ——
  **即默认走纯 Rust 的 `miniz_oxide`，不需要 C 编译器。**
- C 后端（`zlib`/`zlib-ng`/`zlib-ng-compat`/`cloudflare_zlib`）全部**需显式开启**。另有 `zlib-rs`（纯 Rust 的 zlib 替代）选项。
- **✅ 结论：`flate2` + `miniz_oxide` 是纯 Rust 静态路径，零 FFI。采纳。**

**⑤ `miniz_oxide` — `MIT OR Zlib OR Apache-2.0`，纯 Rust，三许可任选。**
`flate2` 的默认后端。**采纳。**

**⑥ `lzma-rs` — 纯 Rust，MIT，确认。**
描述即 "A codec for LZMA, LZMA2 and XZ written in pure Rust"；`unverified`：raw LICENSE 文件未抓
（crates.io 声明 MIT，且 <https://raw.githubusercontent.com/gendx/lzma-rs/master/LICENSE> 在调研中被报告为
MIT / "Copyright (c) 2017-2018 Guillaume Endignoux"）。**最后发布 2023-01，略旧但纯 Rust 无 FFI 风险。**

**⑦ `ruzstd` — 纯 Rust，MIT，确认。采纳（仅解压）。**
repo [KillingSpark/zstd-rs](https://github.com/KillingSpark/zstd-rs)，`LICENSE` 实抓 MIT。
**若只需要解压 zstd（二进制分析里通常是如此），`ruzstd` 比 `zstd` 更优：无 FFI、无 C 工具链、静态天然。**

**⑧ `brotli` — `BSD-3-Clause AND MIT`（注意是 AND）。**
dropbox/rust-brotli，纯 Rust 移植；`ffi-api` 等 C 相关 feature 是**可选的**，不用即可。
仓库有 `LICENSE.MIT` 和 `LICENSE.BSD-3-Clause` 两份。**采纳。**

**⑨ `lz4_flex` — 纯 Rust，MIT，描述明确 "no unsafe by default"。采纳。**

**⑩ `zopfli` — Apache-2.0，纯 Rust。**
`Cargo.toml` 确认 `license = "Apache-2.0"`，依赖仅 Rust 系（`bumpalo`/`crc32fast`/`log`/`simd-adler32`），
无 build script、无 C。
> `unverified`：仓库 `COPYING` 文件的内容未成功抓取（网络层失败），
> 但 crates.io 与上游 `Cargo.toml` 的机器可读 license 字段一致，足够作为依据。

**压缩层建议**：全部走**纯 Rust 列** —— `flate2`+`miniz_oxide`（deflate/gzip/zlib）、`ruzstd`（zstd 解压）、
`lzma-rs`（xz/lzma）、`bzip2` 0.6+（默认纯 Rust 后端）、`brotli-decompressor`、`lz4_flex`、`zopfli`（重压缩）。
**这样整条压缩链零 FFI、零 C 工具链、静态链接天然成立**，比引入 `zstd-sys`/`xz2` 更贴合"零运行期依赖"目标。
仅在需要 zstd **压缩**（非解压）时，才考虑 `zstd` + `vendored`（BSD-3-Clause，license 干净）。

---

## 8. 汇总：建议采纳 / 规避清单

### ✅ 建议采纳（许可干净、纯 Rust、维护活跃或足够稳定）

| 领域 | 首选 | 备选 |
|---|---|---|
| WASM 解析 | `wasmparser` | `wasm-encoder`（写回） |
| PE / 容器 | `goblin`（**>=0.10.7**）、`scroll` | `pelite` |
| .NET metadata | `dotscope`（Apache-2.0） | `clrmeta` / `cildec`（MIT，但均 0.1.0） |
| DWARF | `gimli` + `addr2line` | — |
| PDB | `pdb` + `pdb-addr2line` | `ms-pdb`（微软，MIT，但自称非权威） |
| 通用符号化 | `symbolic-debuginfo`（MIT） | — |
| 符号还原 | `cpp_demangle`、`rustc-demangle` | — |
| 归档 | `ar`、`cab`、`msi`（均 mdsteele/MIT） | — |
| 固件 | `uefi-raw`（MIT OR Apache-2.0） | `uefi` |
| 设备树 | `device_tree_parser` / `deforest`（MIT） | `fdt`（**MPL-2.0**，见风险） |
| Intel HEX / S-Record | `ihex`、`srec` | `intelhex-rs` |
| 压缩 | `flate2`+`miniz_oxide`、`ruzstd`、`lzma-rs`、`bzip2`(默认)、`brotli-decompressor`、`lz4_flex`、`zopfli` | `zstd`+`vendored`（仅需压缩时） |
| 解析原语 | `zerocopy`、`bytemuck`、`scroll`、`binrw`、`nom` | — |
| Unity 资源 | `unity-asset` / `unity-rs-core` | — |
| Yaz0 | `szs` | `yaz0`（停更 2021） |

### 🚫 必须规避

| crate | 原因 |
|---|---|
| **`dotnetdll`** | **GPL-3.0+ —— 强 copyleft，直接违规** |
| `cxxbridge` | 已 yank（2019），repo 字段为 null；改用 `cxx`/`cxxbridge-cmd` |
| `dwarf` | 2016 年即停更，是 gimli 的已死前身 |
| `parity-wasm` | 2022 停更，WASM 提案覆盖不全 |
| `winmd` | 2020 停更，且只面向 WinRT .winmd |
| `elfy` | 2019 停更 |
| `wasmtime` | 作为解析器是错配（JIT/执行语义，攻击面大）；解析请用 `wasmparser` |
| `object` | **license 没问题，但其 README 明确自称不适用于恶意软件分析** —— 用作对抗性输入解析器需加资源配额，或改用 goblin |

### ⚠️ 需要知情决策

| 项 | 说明 |
|---|---|
| **`fdt` 是 MPL-2.0** | 作为**未修改**依赖可用；一旦改动其源文件就必须公开该文件。想规避就用 MIT 的 `device_tree_parser`/`deforest` |
| **`uefi` / `uefi-raw` 旧版曾是 MPL-2.0** | 0.34.0 / 0.10.0（均 2025-02-07）起改为 MIT OR Apache-2.0。**锁新版即无 MPL 义务** |
| **`object` 的对抗性输入警告** | 与"分析任意不可信二进制"直接冲突，必须在设计文档中记录缓解措施 |
| **`unicode-ident` 是 `AND` 组合** | `(MIT OR Apache-2.0) AND Unicode-3.0`，须同时满足 Unicode 许可；放行但要在许可清单显式列出 |
| **`zstd` 仓库 LICENSE 与 crates.io 声明不一致** | 仓库是 MIT，crates.io 声明 BSD-3-Clause；两者都宽松，以 crates.io 为准并注明 |
| **`xz2`/`lzma-sys` 维护停滞** | license 无问题（见 §7①），但 2022 年后无发布；能纯 Rust 就纯 Rust |
| **`mos6502` 无 repository 字段** | 下载最多、维护最新的 6502 模拟器，但 crates.io 上无源码地址，供应链可追溯性差 |
| **`symbolic-debuginfo` 混入 Apple Apache-2.0 代码** | 整体 MIT，但 Swift demangling 部分来自 Apple；许可范围内但非"纯净单许可" |
| **仓库内无 LICENSE 文件** | `device_tree`、`dtb`、`intelhex`、`ms-pdb`(微软仓库有) —— 仅 Cargo.toml/crates.io 声明，**文件级 unverified** |

### ❌ 不存在（HTTP 404，不要写进方案）

`gcn`、`nintendo`、`nintendo-rom`、`rp2a03`、`unity-asset-parser`、`unitypack`(crate 名)、
`ecma335`、`rust-ar`、`debuginfo`、`uboot`、`uefi-firmware`、`fit-parser`、`rust-elf`、`dncil`(Rust 版)

---

## 9. 明确标注为 unverified 的项（汇总）

1. `dotnetdll` 仓库内 LICENSE 文件内容（仅有 crates.io 的 GPL-3.0+ 声明）。
2. `windows-metadata` 的 Apache-2.0 半边文件（MIT 半边已实抓）。
3. `pdb-addr2line` 的 `LICENSE-APACHE` 文件（`LICENSE-MIT` 已实抓）。
4. `pdb`（willglynn）的仓库 LICENSE 文件（仅有 crates.io 的 `MIT OR Apache-2.0` 声明）。
5. `symbolic`（伞 crate）逐版本 license 字段（同族其余四个均 MIT）。
6. `rustc-demangle`、`cxx`、`cxxbridge-cmd`、`unicode-ident` 的 raw LICENSE 文件（仅有 crates.io 声明）。
7. `device_tree`、`dtb`、`intelhex` 的 LICENSE 文件 —— **仓库内根本不存在该文件**。
8. `zopfli` 仓库 `COPYING` 文件内容（网络抓取失败）。
9. `lzma-sys/build.rs` 的编译文件清单（未逐行核对是否排除 getopt_long）。
10. `backtrip`、`cildec`、`clrmeta`、`dotscope` 的 API 稳定性与格式覆盖完整度（仅元数据，未审源码）。
11. `wasm-tools` 中 `max_stable_version` 与 `newest_version` 不一致的原因。
12. `goblin` 是否对 CLR header（COM descriptor 目录）内容做结构化解析（未读源码）。
13. Switch NCA 格式 / Switch SM4 加密在 Rust 生态中"不存在"是**未找到**而非证明。
14. `mos6502` 的源码仓库地址（crates.io `repository` 字段为 null）。
15. `fitimage` 的 FIT **读取**能力（其定位为生成）。
16. 各 crate 的 `newest_version` 与 `max_stable_version` 在本报告中的取值口径：
    `wasmparser`/`wasm-encoder`/`wasm-tools`/`fdt` 的 `max_stable_version` 高于 `newest_version`，
    报告表格中已分别标注。

---

## 10. 数据来源

- crates.io API：`https://crates.io/api/v1/crates/<NAME>`（每个 crate 一条，均为本次会话实抓）。
- crates.io 搜索：`https://crates.io/api/v1/crates?q=<QUERY>&per_page=<N>`。
- License 文件：`https://raw.githubusercontent.com/<owner>/<repo>/<branch>/<FILE>`。
- GitHub 仓库元数据：`https://api.github.com/repos/<owner>/<repo>`。
- 官方许可说明页：<https://tukaani.org/xz/>、<https://raw.githubusercontent.com/tukaani-project/xz/master/COPYING>。
