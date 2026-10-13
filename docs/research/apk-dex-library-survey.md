# APK / DEX 现成库实测调查报告

> 结论驱动：本文只记录**实测**结果。凡是没跑过的，一律标"未验证"。
> 日期：2026-10。样本：`C:\Users\Administrator\Downloads\ah-app-release.apk`
> （1867 条目、3 个 dex、37 个 `.so`、`com.weavi.ahh` 1.6.3）。

## 0. 这份报告推翻了我自己的一个结论

`ADR-0019` 写的是"**DEX 解析器与 Dalvik 解码器必须自研**，因为没有可用的轮子"。
那个结论**错了**，而且错的方式值得记下来：

- 之前的调研（提交 `fa97e18`）只**点名检查了三个已知 crate**（`dex` 冻结、
  `dalvik` 只是反汇编器、`smali` 是 GPL-3.0），然后就归纳为"没有可用的"。
- 这次改用 **crates.io 搜索 API**（`/api/v1/crates?q=...`）按关键词枚举，
  立刻浮出 `droidsaw-dex`（BSD-3-Clause，45k LoC）与 `apk-info`（Apache-2.0）。
- 教训：**"我查过几个候选"不等于"没有候选"。** 归纳结论必须写明搜索方式，
  否则一个基于三次点采样的判断会被当成普查结论沿用下去。

## 1. 候选清单（许可先过闸）

| crate | 版本 | 许可 | 说明 | LoC |
| --- | --- | --- | --- | --- |
| `droidsaw-dex` | 2.0.0 | **BSD-3-Clause** | DEX 解析 + 解码 + CFG + xrefs（另有反编译器部分） | 45 536 |
| `droidsaw-apk` | 2.0.0 | **BSD-3-Clause** | APK 容器/清单/签名 v1–v4/native 库/DEX 头 | 31 020 |
| `apk-info` | 1.0.13 | **Apache-2.0** | 面向对抗样本的 APK/XAPK/APKM 解析 | 832 |
| `apk-info-zip` | 1.0.13 | **Apache-2.0** | 自研 ZIP（处理 BadPack 畸形包） | 1 794 |
| `apk-info-axml` | 1.0.13 | **Apache-2.0** | AXML + ARSC | 3 724 |
| `rusty-axml` | 0.2.1 | **Apache-2.0** | AXML 解析 | 2 636 |
| `resand` | 0.3.0 | **Apache-2.0** | ARSC/AXML **读写** | 7 688 |
| `dex-parser-rust` | 1.3.0 | **MIT OR Apache-2.0** | DEX/APK 并行解析 | 3 489 |

**依赖树许可闸门（实跑 `cargo metadata` 全量枚举）**：

- `droidsaw-dex` 树：91 个包，强著佐权 **0**。
- `apk-info` 树：118 个包，强著佐权 **0**。
- 唯一被朴素正则命中的是 `r-efi`（`MIT OR Apache-2.0 OR LGPL-2.1-or-later`）——
  这是**析取式**许可，我们按 MIT/Apache 使用即可，**不构成著佐权**。

## 2. `droidsaw-dex` 实测（真实 `classes.dex`，8 800 484 字节）

### 2.1 结构模型正确

```
我手读 header.class_defs_size @0x60 = 7643
dex.list_classes().len()            = 7643     一致 OK
类 7643，方法 53 906，其中有代码 50 934（可反汇编）
```

类描述符是真的，且语义自洽，例如 Kotlin 协程调试类
（`L_COROUTINE/ArtificialStackFrames;`，源码 `CoroutineDebugging.kt`）——
`_COROUTINE` 正是 Kotlin 协程的真实包名，不是编造的占位名。

### 2.2 指令解码：独立验证"恰好铺满"

**这是本次最有价值的一条验证。** 我不用库自己的长度字段，而是照规范手算
每个 payload 占多少 code unit，然后要求
`instructions ∪ payloads` **恰好**铺满 `[0, insns_size)`，无空洞无重叠：

```
检查 3000 个 code_item  ->  不吻合 = 0
```

`insns_size` 也是我从原始字节 `code_off + 0x0C` 手读的，不是库给的值。

**过程中我自己错了一次，记在这里**：第一版我把 `fill-array-data` 的长度写成
`4 + data.len() * element_width / 2`，得到 9/3000 不吻合（全在 `R$styleable`
这类塞满 int 数组的类）。停查后发现是**我重复计了 `element_width`** ——
`data` 存的就是原始字节，`data.len()` 已经等于 `element_count * element_width`。
改成 `4 + ceil(data.len()/2)` 后归零。
**差点把自己的 bug 报成库的 bug** —— 所以"异常"出现时先怀疑自己的度量。

### 2.3 CFG：我设计文档里要"新增"的边类型它已经有了

`droidsaw-dex` 的 `EdgeKind`：

```rust
pub enum EdgeKind {
    FallThrough, Branch,
    SwitchCase(i32), SwitchDefault,
    ExceptionHandler(TypeIdx), ExceptionCatchAll,
}
pub struct ExceptionRegion { start_addr, end_addr, handler_blocks: Vec<(EdgeKind, BlockIdx)> }
```

对照 `docs/APK-DEX-DESIGN.md` §4.2 我写下的"必须新增"清单：
`SwitchCase{targets,keys}`、`ExceptionEdge`（一个 try 多 handler）、
handler 特殊入口 —— **全部已存在**。实跑也印证：

```
MediaBrowserCompat$CallbackHandler::handleMessage  块=15 异常区=2
   边种类=["Branch","ExceptionHandler(TypeIdx(373))","FallThrough"]
RatingCompat::fromRating   -> packed-switch(6 个目标)
MessageHandler::handleMessage -> packed-switch(13 个目标)
```

### 2.4 它对"拿不到就别说拿不到"的处理与 §7 同向

两处值得记下，因为它们正是本项目 `CLAUDE.md` §7 的要求：

1. `DetectorVerdict::{Yes, No, Indeterminate}` 的文档逐字写着：
   解析失败**不得**塌缩成 `No` —— "This enum closes the silent-skip evasion
   primitive"（把畸形内容洗成"不存在"）。这就是"跳过与通过必须分得开"。
2. `CodeItem` 遇到 `try_item` 越界会**夹取到合法范围并同时把原值记进
   `invariant_violations`**，注释明说"parser does NOT hard-error"。
   即"降级可见"，不是静默修好。

### 2.5 实测到的真实世界违规（对我参考文档的直接修正）

```
ParseFailure { kind: OutOfOrder { pool: StringIds }, offset: 66953 }
```

**一个真实上架 APK 的 `string_ids` 就是乱序的。** 我参考文档里把
`string_ids` 升序列为规范要求（并建议做自检）—— 现在有了实证：这类不符
**在真实样本里存在**，因此自检结论只能写进 `notes`，**不能据此拒绝文件**。
`droidsaw-dex` 的行为（容忍 + 记录）正是对的。

### 2.6 工程质量信号（不是结论，只是旁证）

- `#![forbid(unsafe_code)]`；非测试构建 `deny` 了 `unwrap_used`、
  `expect_used`、`panic`、`indexing_slicing`、`arithmetic_side_effects`。
- 带 **Kani 形式化验证**harness，覆盖的恰好是我参考文档列出的坑：
  `header_size` 校验、`0x78563412` 反端序围栏、空 try 区、`class_def` 四个
  偏移字段的边界、MUTF-8 解码一致性、`encoded_value` 的 `value_arg` 上界。
- `build.rs` 是编译期一致性闸门（CFG 谓词名 vs 独立 oracle、解码格式表 vs
  文档矩阵），**不联网、不起外部命令** —— 这点单独确认过，因为本项目曾因
  `lief` 的构建期下载而否掉它。

## 3. `apk-info` 实测（同一个真实 APK）

所有独立对照项**全部一致**：

| 项 | 我的独立基准（手写字节/`zip`） | `apk-info` |
| --- | --- | --- |
| 条目总数 | 1867 | 1867 |
| `.dex` | 3 个 | `is_multidex() = true` |
| ABI 目录 | `arm64-v8a, armeabi, armeabi-v7a, x86, x86_64` | 同（逐项一致） |
| `classes.dex` 类数 | 7643（手读 `@0x60`） | 与 `droidsaw-dex` 互相印证 |

它还能给出（这些是**新**数据，不是我给它的）：包名 `com.weavi.ahh`、
versionCode 72 / versionName 1.6.3、minSdk 21 / targetSdk 29、
26 个权限、107 个 activity、11 个 service、主 activity
`com.weavi.ahh.SplashActivity`、2 条签名、以及把二进制清单**还原成
29 392 字节可读 XML**（命名空间正确）。

**M0 的核心收益已验证**：`lib/arm64-v8a/libBugly_Native.so` 解压得
195 200 字节、`Deflated`、`ELF` class=2（ELF64）、etype=3（ET_DYN）、
machine=183（EM_AARCH64）⇒ **既有 ELF 路径可直接吃**。

## 4. 必须一起说清楚的风险

1. **这两个库极新，且产量异常。** `droidsaw-*` 首发 2026-04，总下载 945 / 611；
   从 0.1.0（源码行数为 0）到 1.0.0 的 43 333 LoC 只隔 6 周。
   这个速度不像常规人工开发。**因此不能靠"读起来很专业"采信它** ——
   本次只验证了上面列出的那几条不变量，**没有**逐字段核对全部输出。
2. **发布的 crate 里没有测试**：`Cargo.toml` 写了 `exclude = ["/tests", ...]`，
   所以"179 个测试覆盖 DEX 035–041"这个说法**无法从制品验证**。
3. **有几个 crate 声明了许可但没随包发 LICENSE 文件**：
   `apk-info*`、`rusty-axml`、`dex-parser-rust` 都是。
   `Cargo.toml` 的 SPDX 字段是声明，但 Apache-2.0 的分发义务要求附许可原文 ——
   真要依赖，得从各自仓库取回 LICENSE 并随产品分发。
4. **反编译器部分不能用来出"分析结论"。** `droidsaw-dex` 的
   `emit` / `emit_dex` / `sugar` / `r8_inversion`（约占其体积一半）做的是
   **类型推断与 Java 源码生成** —— `ADR-0018` 已判定这类输出按定义就是推断，
   直接展示会违反 §7。**只用 `parser` / `decode` / `cfg` / `xrefs` / `mutf8`
   这些"事实抽取"层；反编译层不用。** 好在它们是并列的公开模块，切得开。
5. `droidsaw-apk` 为做 v1–v4 签名验证引入了 `rsa`/`p256`/`ecdsa`/`cms`
   等密码学依赖（体积与维护面都变大）。若我们只需要"检测签名块存在"，
   应当优先考虑 `apk-info-zip::signature`，避免背这套依赖。
6. **未验证**：`droidsaw-dex` 对 037–041 各版本的实际行为（本次样本全是 035）；
   `resand`、`rusty-axml`、`dex-parser-rust`、`apk-info-zip`、`droidsaw-apk`
   本次**没有实跑**。
7. **许可闸门的覆盖范围要说准**：§1 里"强著佐权 0"那句对应的是
   **两个探测工程各自的实际依赖树**（`droidsaw-dex`+`zip` = 91 个包；
   `apk-info`+`rusty-axml`+`zip` = 118 个包）。
   **`droidsaw-apk` 自己的依赖树本次没有单独过闸** ——
   只在首次 `cargo fetch` 时观察到它引入了 `rsa`/`p256`/`ecdsa`/`cms`
   等密码学依赖（这些通常也是 Apache-2.0/MIT，但**那是推测，不是实测**）。
   真要用 `droidsaw-apk`，必须先补跑一次闸门。

## 5. 复现方式

探测工程在 `.smoke-logs/apk-probe`（DEX）与 `.smoke-logs/apk-probe2`（容器），
已被 git 忽略，不入库。跑法：

```powershell
& .\scripts\cargo.ps1 run --manifest-path .smoke-logs\apk-probe\Cargo.toml  --example dex
& .\scripts\cargo.ps1 run --manifest-path .smoke-logs\apk-probe\Cargo.toml  --example dex2
& .\scripts\cargo.ps1 run --manifest-path .smoke-logs\apk-probe2\Cargo.toml --example container
```

`dex2` 就是 §2.2 那条"恰好铺满"的严格检验（含对我自己那处错误的注释）。
