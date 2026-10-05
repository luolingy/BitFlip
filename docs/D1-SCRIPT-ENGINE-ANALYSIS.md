# D1 决策分析：脚本层引擎

> **状态：已决（2026-10）—— 选方案 A（rquickjs），wasmtime 推迟到 M8+。
> 定案见 [`docs/DECISIONS.md`](./DECISIONS.md) ADR-0013。**
> 本文保留为决策依据与实测记录，不再是待选清单；§5 的推荐与 §6 的落地清单
> 就是 M7 的执行依据。
>
> 决策门 D1（见 `docs/DECISIONS.md`），计划要求 **M6 末**闭环。
>
> 编写时点：M6 全部交付物已完成、M7 尚未开工。此时 `bitflip-core` 的对外
> 契约（19 个 `*Wire` 类型、21 个 HTTP 端点、3 个 `format_version` 常量）
> 已经稳定，**这正是重开这个决策的最佳时机** —— 脚本 API 要镜像的就是这套
> 契约，契约没定型之前选引擎等于在流沙上浇地基。

## 1. 这个决策要解决什么

PLAN §M7 要的不是"嵌入一个解释器"，而是**把分析能力开放给用户脚本**：

| 交付物要求 | 对引擎的实际约束 |
|---|---|
| 读地址空间/指令/函数/xref/符号 | 脚本要**高频回调宿主**并拿到结构化数据 |
| 写注释与名字 | 脚本要能把数据**写回**宿主 |
| 注册分析 pass | 宿主要把脚本函数当回调**反复调用** |
| 生成补丁 | 脚本产出结构化结果，宿主执行 |
| 错误与日志回传 UI | 引擎的错误/输出要能被捕获并带上位置信息 |
| 沙箱与超时 | 引擎必须提供**可中断**的执行，且中断后进程完好 |

### 具体指标（来自 PLAN §M7 验收）

| 指标 | 目标 | 来源 |
|---|---|---|
| "识别所有 `memcpy` 调用并重命名参数注释"脚本端到端跑通 | 必须 | PLAN §M7 验收 1 |
| 死循环脚本可被中断，**不影响主进程** | 必须 | PLAN §M7 验收 2 |
| 脚本 API 有版本号与稳定保证，且**不直接暴露内部类型** | 必须 | PLAN §M7 验收 3 |

再加三条本项目自己的硬约束：

- **CLAUDE.md §0.3 / §3**：C: 仅剩约 1.9GB，F: 剩约 7.5GB，所有构建落在 F:。
  引擎的构建时间与 target 体积是**真实的日常成本**，不是纸面数字。
- **CLAUDE.md §2**：单文件可执行、运行期零 Node 依赖。引擎不得破坏这一条。
- **CLAUDE.md §7**：拿不到就说拿不到。超时/崩溃必须是**可读的错误**，
  不能变成静默失败或宿主进程退出。

### 验收 1 为什么是这次决策的关键

"识别所有 `memcpy` 调用"意味着脚本要遍历**几千个函数**、每次调用穿过
脚本↔宿主边界。ntdll 上有 13930 条 `call` 类型 xref、5488 个函数。
**这是一份"话很多"的负载**，不是"跑一次算个哈希"的负载。
它把"宿主 API 调用有多贵"从理论问题变成了每天都会撞到的问题 ——
这一点直接决定了下面四个方案的排序。

## 2. 候选方案

### 方案 A：rquickjs（JavaScript / QuickJS）

`rquickjs 0.14.0`（2026-09），MIT，MSRV **1.87**，edition 2021。

- 静态编译 QuickJS 的 C 源码（`quickjs.c` / `libregexp.c` / `libunicode.c` / `dtoa.c`），
  经 `cc` crate 走本机 MSVC。
- **不需要 libclang**：`bindgen` 是**可选**特性，默认走预生成绑定。
  只有预生成绑定不覆盖的平台才需要打开它。
- 中断：`Runtime::set_interrupt_handler`，回调返回 `true` 即中止执行。
- 与项目最大的契合点：**前端已经是 TypeScript**。脚本语言与 UI 语言同为
  JS，且脚本 API 的类型声明可以由前端已有的 `web/src/api.ts` 生成 ——
  一套契约、两处消费。

### 方案 B：mlua（Lua 5.4 / 5.5 / LuaJIT / Luau）

`mlua 0.12.2`（2026-10），MIT，MSRV **1.88**，edition 2024。

- `vendored` 特性静态编译 Lua 5.4 的 C 源码（约 30 个 .c 文件），同样走本机 MSVC。
- 中断：debug hook（`HookTriggers::every_nth_instruction`），回调返回 `Err` 即中止。
- Rust 生态里**最成熟的嵌入式脚本绑定**：`UserData` / `create_function` /
  多值返回 / 协程 / async 支持都齐备，绑定宿主类型的摩擦最小。
- 代价：Lua 生态对"逆向分析"几乎没有现成积累，用户得从零写。

### 方案 C：wasmtime（WASM 插件）

`wasmtime 49.0.2`（2026-10），Apache-2.0 WITH LLVM-exception，
**MSRV 1.96.0**、edition 2024。

- 主体是 Rust（Cranelift JIT）。**但"不需要 C 编译器"是错的**：
  它的 `build.rs` 会经 `cc` crate 编译 `src/runtime/vm/helpers.c`（实测确认，
  见 §3）。C 的部分比 A/B 小得多，但"零 C 依赖"这个常见印象不成立。
- 中断：fuel（确定性计数）或 epoch 中断（墙钟超时，另一线程推进）。
- 隔离最好：wasm 模块**在构造上无法**破坏宿主内存，不给文件系统就没有文件系统。
- 代价最重：脚本必须是**编译好的 .wasm**，宿主 API 要先定义成一套 ABI
  （导入函数 + 线性内存里的数据编解码）。每加一个 API 就要动 ABI。
- 注意：**MSRV 1.96.0 正好等于本机工具链版本**，零余量 ——
  意味着工具链只能升不能降，且 wasmtime 一升 MSRV 我们就得跟着升。

### 方案 D（衍生）：两段式 —— 先 A 或 B，WASM 推迟到 M8+

理由不是"和稀泥"，而是这两个需求**时间上不重合**：

- M7 要的是**用户脚本**（可读、可改、随手跑）—— 这是 A/B 的强项；
- "插件生态"要的是**可分发、可信任的第三方扩展** —— 那才是 C 的强项，
  而 PLAN 里它排在 M8（签名库匹配）之后。

如果 M7 阶段强行上 WASM，代价是"每个 API 都要过一遍 ABI"在**最需要快速
迭代 API 的阶段**全部付清。反过来，先 A/B 并不堵死 WASM：脚本层是
`bitflip-script` 一个 crate，引擎在它内部，宿主 API 的**语义契约**
（wire 形状）两边可以共用。

## 3. 真机测量（本机实测，不是引用别人的数字）

方法：每个方案一个最小 crate，独立 target 目录，`cargo build --release`
冷构建，同一台机器、同一工具链（rustc 1.96）。每个 crate 都同时验证
"死循环能否被中断 + 中断后运行时是否仍可用"。

| 方案 | 冷构建 | 二进制 | target 占用 | 中断机制 | 实测中断 |
|---|---|---|---|---|---|
| A · rquickjs 0.14（`full`） | **221.9 s** | **1.14 MB** | 158 MB | 中断回调 | 499 ms 后返回错误，运行时仍可用 |
| B · mlua 0.12（`lua54`+`vendored`） | **280.3 s** | **0.52 MB** | 56 MB | debug hook | 556 ms 后返回错误，运行时仍可用 |
| C · wasmtime 49（最小特性） | **997.7 s** | **11.67 MB** | 710 MB | fuel | 24 ms 后 trap，实例仍可用 |
| C′ · wasmtime 49（默认特性） | **1980.5 s** | **14.63 MB** | 1061 MB | fuel | 同上 |

C′ 是"照默认配置 `wasmtime = "49"` 加进来"的代价 —— 很多嵌入方就是这么
开始的，所以这个数字比 C 更能代表**实际会发生的成本**。默认特性会拉进
component-model、async、gc、profiling、coredump、addr2line、cache、
debug-builtins 等；即使只用一个 `f() -> 7` 的函数，也要付 33 分钟构建和
14.63 MB 体积。

补充观察（同样来自实测）：

- **三个引擎都能满足验收 2**（死循环可中断且进程完好），且中断后运行时/
  实例都还能继续用。**所以"能不能中断"不构成区分度** —— 区分度在别处。
- C 的中断错误是一条 **wasm backtrace**（`error while executing at wasm
  backtrace: 0: 0x2d - <unknown>!<wasm function 0>`）。要变成用户能看懂的
  "脚本执行超时（第 N 行）"，需要自己再做一层映射。A/B 直接给出
  `interrupted` / 带位置信息的错误。
- C 的**最小特性**构建就已经是 A 的 4.5 倍、B 的 3.6 倍耗时；二进制是
  A 的 10 倍、B 的 22 倍。11.67 MB 是**空壳**体积，不含任何脚本逻辑。
  按默认特性则分别是 **9 倍耗时、13 倍体积**（1980.5 s / 14.63 MB）。
- **三个引擎都需要 C 编译器**（本机 MSVC 实测都编过）。这条纠正了一个常见
  印象：WASM 方案并不"零 C 依赖" —— wasmtime 的 `build.rs` 会经 `cc` crate
  编译 `src/runtime/vm/helpers.c`。区别只在于 **C 的分量**：A/B 编译的是引擎
  本体（QuickJS 4 个 .c 文件 / Lua 约 30 个 .c 文件），C 只编译一份运行时辅助。
  三者都**不需要 libclang**（rquickjs 的 `bindgen` 是可选特性，默认走预生成绑定）。
  也就是说 PLAN §M7 风险栏点名的"C 依赖"顾虑对**三个方案都成立**，
  它不构成区分度。

> 测量脚本与源码在 `.cargo-tmp/d1-spike/`（gitignored，不入库）。
> 复现方式见本文 §7。

## 4. 方案对比

按对本项目的实际影响排序，而不是按引擎的绝对优劣：

| 维度 | A · rquickjs | B · mlua | C · wasmtime |
|---|---|---|---|
| 满足验收 2（可中断） | ✅ | ✅ | ✅ |
| 满足验收 3（不暴露内部类型） | 自然（显式绑定函数） | 自然 | 天然（ABI 强制解耦） |
| **验收 1 的宿主调用成本** | 低 | **最低** | **高**（每次调用过 ABI + 内存编解码） |
| 用户脚本可读可改 | ✅ 源码分发 | ✅ 源码分发 | ❌ 需编译产物 |
| 宿主 API 迭代成本 | 低 | 低 | **高**（改 ABI） |
| 单文件体积 | +1.14 MB | **+0.52 MB** | +11.67 MB（默认 14.63 MB） |
| 冷构建代价 | 3m42s | 4m40s | **16m38s（默认 33m0s）** |
| 构建依赖 | MSVC，无 libclang | MSVC，无 libclang | MSVC（`helpers.c` 经 cc） |
| MSRV 余量（本机 1.96） | 1.87（宽） | 1.88（宽） | **1.96（零）** |
| 隔离强度 | 进程内 | 进程内 | **强** |
| 许可证兼容 | MIT ✅ | MIT ✅ | Apache-2.0+LLVM ✅ |
| 与前端语言统一 | **✅ 同为 JS/TS** | ❌ | ❌ |
| RE 领域生态 | 中（JS 通用生态大） | 中（Lua 在嵌入式/游戏） | 低（WASM 插件偏新） |

**一句话概括这张表**：三个方案在"能不能做到"上打平，在"每次调用有多贵"
和"改一次 API 有多贵"上分出胜负 —— 而 M7 阶段这两件事正好是最高频的。

## 5. 结论与触发条件

### 推荐：方案 A（rquickjs），并把方案 D 的两段式作为路线图

理由按重要性排序：

1. **验收 1 是话很多的负载，A/B 的主场。** 遍历 5488 个函数、13930 条
   call xref 并写回注释，在 A/B 里就是普通函数调用；在 C 里每次都要
   过 ABI、把地址/字符串在线性内存里编解码。这不是"稍微慢一点"，
   而是**脚本 API 的每个形状都要为 ABI 让路**。
2. **M7 会反复改 API，C 的迭代税最贵。** 交付物清单里"自定义视图数据源"
   这类需求天然会不断长出新的宿主函数。A/B 里加一个函数是加一个绑定；
   C 里是改 ABI + 重新编译所有脚本 + 处理版本兼容。
3. **前端已经是 TypeScript。** 同一门语言意味着 `web/src/api.ts` 已有的
   wire 类型定义可以**生成**脚本 API 的类型声明，用户写脚本时有补全、
   有类型检查；宿主侧也少维护一套心智模型。这是 B/C 拿不到的。
4. **体积与构建代价差一个数量级。** 0.52–1.14 MB vs 11.67–14.63 MB；
   3m42s vs 16m38s（默认特性 33m0s）。本项目明确要求单文件可执行，
   且磁盘紧张。
5. **MSRV 零余量是长期负债。** wasmtime 的 MSRV 1.96.0 正好卡在本机
   工具链上 —— 我们会被它牵着升级，且它一旦再抬 MSRV，M7 之后的
   构建就会在某次 `cargo update` 后突然失败。

**A 优于 B 的唯一理由是第 3 条（语言统一）**。如果第 3 条对你没有价值，
B 在其余每一项上都不差，且在"宿主调用成本"和"体积"上更好 —— 这是我
把 B 列为同等可行的原因，不是陪跑。

### 明确不推荐：M7 阶段直接用方案 C（wasmtime）

不是因为它不好，而是**它的强项（隔离、可分发）在 M7 阶段用不上，
它的弱项（ABI 税、体积、构建时间）在 M7 阶段全额支付**。
等 M8 之后真有第三方插件分发需求时再引入，那时 ABI 的形态也会清楚得多
（这正是 D2 里"不做过早抽象"的同一条推理）。

### 什么情况下应该改选

| 如果 | 那就选 |
|---|---|
| 你打算让用户**分发二进制插件**给不可信第三方 | C（现在就上，别推迟） |
| 你认为脚本 API 会**极其稳定**、几乎不再新增宿主函数 | C 的 ABI 税被摊薄，可考虑 |
| 你更看重"用户脚本能被大量非专业用户写出来" | A（JS 生态 + 类型提示） |
| 你更看重"嵌入摩擦最小、体积最小、绑定最成熟" | B |
| 你不想现在决定"脚本语言"，希望语言中立 | C 或 D（先只做 CLI/HTTP，M7 推迟） |

### 我不替你决定的部分

**A 与 B 的取舍本质上是"脚本语言选型"，不是技术可行性问题** ——
两者都过验收、都能量产。选 A 意味着用户写 JS，选 B 意味着用户写 Lua。
这一条取决于你想要什么样的用户，取决于你的判断，我不替你拍。

## 6. 可执行方案（若选 A，M7 落地清单）

### 6.1 分层与新增 crate

```
bitflip-script（新）      引擎封装：Runtime 生命周期、超时、日志、错误映射
  └─ 依赖 bitflip-core    只读 wire 契约 + 写入 API（注释/名字/补丁）
bitflip-server            加 /api/script/*（控制台、脚本库、批处理进度）
web/                      脚本控制台视图（REPL + 结果表格）
```

`bitflip-script` 放在 `core` **之上**（它要用 core 的契约），
`server` 之下。不得反向依赖，否则触发分层门禁。

### 6.2 API 版本与稳定保证（验收 3）

- 脚本 API 复用 **wire 形状**（定长 16 位小写十六进制地址、`format_version`），
  不直接暴露 `bitflip-core` 的 Rust 类型 —— 满足"不直接暴露内部类型"。
- 新增 `SCRIPT_API_VERSION: u32`，与 `ANALYSIS_FORMAT_VERSION` 独立演进：
  脚本 API 加函数 = 次版本；改语义 = 主版本 + 迁移说明进 CHANGELOG。
- 全局对象命名 `bitflip`，脚本以 `bitflip.functions.all()` 这类形状访问。

### 6.3 沙箱与超时（验收 2）

- 每个脚本执行有**墙钟上限**（默认 5s，可配置），由
  `set_interrupt_handler` 的截止时间实现。
- 中断后**运行时保留**（实测可用），但**丢弃该脚本的所有未提交写入** ——
  半途的写入必须回滚，否则用户会看到"跑了一半的批处理结果"，
  这正是 CLAUDE.md §7 禁止的"看起来完整"。
- 日志与错误带脚本行号回传 UI；引擎自身的 panic 由 `catch_unwind` 兜住。

### 6.4 验收测试（M7 必须有的）

1. `identify_memcpy_and_annotate` —— 端到端跑验收 1 的脚本，断言注释真的落库；
2. `infinite_loop_is_interrupted_and_host_survives` —— 死循环脚本被中断，
   断言进程存活、且**部分写入被回滚**；
3. `script_api_version_is_reported` —— 断言 `bitflip.apiVersion` 存在且
   与 `SCRIPT_API_VERSION` 一致；
4. `script_error_carries_line_number` —— 语法/运行时错误必须带行号；
5. 中断后**再跑一个正常脚本**必须成功（防"中断把引擎弄坏"）。

### 6.5 待你决定后我立刻做的事

按 M6 的节奏：先写 ADR-0013 定案 → 建 `bitflip-script` 骨架与 5 个验收
测试（先红）→ 实现 → 真机在 ntdll.dll 上跑验收 1 的脚本 → 单独提交。

## 7. 复现测量

本次测量用的尖刺是**临时目录、随时可删**（`.cargo-tmp/d1-spike/`，gitignored）。
下面是完整配方，照做即可复现上表 —— 每个尖刺只有一个 `Cargo.toml`
加一个 `main.rs`。

依赖（各自加空 `[workspace]` 表，避免被仓库根的 workspace 吸收）：

```toml
# a-rquickjs
rquickjs = { version = "0.14", features = ["full"] }
# b-mlua
mlua = { version = "0.12", features = ["lua54", "vendored"] }
# c-wasmtime（现实可用的最小面）
wasmtime = { version = "49", default-features = false, features = ["cranelift", "runtime", "std", "wat"] }
# d-wasmtime-default（对照组）
wasmtime = "49"
```

四个 `main.rs` 做同一件事：起一个**死循环脚本**，约 500 ms 后中断，
断言 (1) 返回错误而不是正常返回，(2) **中断之后运行时/实例仍能正常执行**。

| 尖刺 | 死循环脚本 | 中断方式 |
|---|---|---|
| a-rquickjs | `while (true) {}` | `Runtime::set_interrupt_handler` 里比较墙钟截止时间 |
| b-mlua | `while true do end` | `HookTriggers::every_nth_instruction(10_000)` + 回调返回 `Err` |
| c/d-wasmtime | `(loop $l (br $l))` | `Config::consume_fuel(true)` + `Store::set_fuel(20_000_000)` |

```powershell
$env:PATH = "F:\cache\cargo\bin;$env:PATH"
$env:CARGO_HOME = "F:\exeliang\BitFlip\.cargo-home"
$env:TMP = "F:\exeliang\BitFlip\.cargo-tmp"; $env:TEMP = $env:TMP
cargo build --release --target-dir target     # 冷构建计时
.\target\release\spike-<name>.exe             # 中断行为
```

> 计时口径：独立 target 目录的**全冷**构建（含所有依赖），同一台机器、
> 同一工具链。这量的是"从零拉起来要多久"，不是"加进已有 workspace 的
> 增量"—— 后者会小一些，但方案之间的**倍数关系**不变。
