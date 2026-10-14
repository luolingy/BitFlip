# `capstone` 0.14.0 的 aarch64 反汇编会**中止进程**（既有问题）

> **状态：已修（2026-10-14）。** 修法是 vendored 一份本地副本 + 一处补丁：
> `third-party/capstone/`，`[patch.crates-io]` 指过去，
> 详见 `third-party/capstone/PATCH.md`。
>
> 本文保留原始调查记录（现象、机理、复现、影响面）作为**为什么要有那个 fork**
> 的依据。文末的"处置选项"与"待办"按实际情况更新过。
>
> **仍未修的是相邻问题**（同一子系统，但另一件事）：`bitflip-arch` 的
> `convert_arm64_operand` 有个 `_ => {}` 兜底，把系统寄存器 / PState / 屏障 /
> 预取这几类操作数整个丢掉，导致渲染出的指令文本**缺操作数**，
> 而且缺得**看不出来**（`msr x19` 读起来像一条合法的另一条指令）。
> 这属于 §7「降级要写在界面上」，见文末。

> 发现于 M11 的 M0 验证过程（用真实 APK 的 `lib/arm64-v8a/*.so` 试反汇编）。
> 记录在这里是因为它**与 ZIP/APK 改动无关**，但对"APK 里的 `.so` 能不能分析"
> 是硬阻断 —— aarch64 是 Android 的主 ABI。

## 现象

对任何含 `MRS` / `MSR` 指令的 aarch64 目标跑反汇编，进程直接死：

```text
thread 'main' panicked at .cargo-home\...\capstone-0.14.0\src\arch\arm64.rs:70:17:
trying to construct an enum from an invalid value 0x1d7e
thread caused non-unwinding panic. aborting.
[exit code: 1]
```

注意最后两行：**non-unwinding panic → abort**。这不是普通的 `panic!`，
栈不会被展开。

## 位置与机理

`capstone-0.14.0/src/arch/arm64.rs`，同一处模式出现两次：

```rust
// 第 69-71 行
ARM64_OP_REG_MRS => RegMrs(unsafe {
    mem::transmute::<Arm64Reg::Type, Arm64Sysreg>(value.reg as Arm64Reg::Type)
}),
// 第 72-74 行
ARM64_OP_REG_MSR => RegMsr(unsafe {
    mem::transmute::<Arm64Reg::Type, Arm64Sysreg>(value.reg as Arm64Reg::Type)
}),
```

`MRS` / `MSR` 的操作数是**通用寄存器**，取值范围与 `Arm64Reg` 一样宽；
而 `Arm64Sysreg` 只覆盖系统寄存器，取值域**窄得多**。于是这个 `transmute`
把宽取值域的值硬当成窄枚举的判别式用。本例里的 `0x1d7e`（7550）就是某个
通用寄存器号，落到 `Arm64Sysreg` 的合法取值之外。

Rust 对枚举做有效性检查，遇到非法判别式就调 `panic!`，而且是
**non-unwinding**（因为"值不合法"意味着程序状态已经不可信）——
所以 `catch_unwind` 也接不住。

**这是 `capstone` crate 自身的健全性缺陷**，不是用法问题：`transmute` 到枚举
本就是 UB 面，正确写法是**可失败转换**（越界时退化成 `Invalid` 或保留原始号码）。

## 复现（与 ZIP 代码无关）

关键证据：**裸 `.so` 与 APK 成员表现完全一致**，所以与 M0 改动无关。

```powershell
# 1) 裸 .so（完全不经过 ZIP 代码路径）
& .\.cargo-target\debug\bitflip-cli.exe functions .smoke-logs\extract\libBugly_Native.so --count 5
#    → 同一个 arm64.rs:70 abort

# 2) 同一个文件经 APK 成员进去
& .\.cargo-target\debug\bitflip-cli.exe functions <apk> --member "lib/arm64-v8a/libBugly_Native.so" --count 5
#    → 同一个 arm64.rs:70 abort
```

样本：`.so` 是真实上架 APK 里的 `lib/arm64-v8a/libBugly_Native.so`，
解压后 195 200 字节，ELF64 `EM_AARCH64` `ET_DYN`，26 个节。
`info` 层（不认识 `MRS`/`MSR`，不反汇编）**正常**：

```text
单对象文件 / ELF / aarch64/64/le，入口 0x8520，节 26
```

也就是说：**解析层没问题，是反汇编层的 crate 崩的。**

旁证：同一 APK 里的 `lib/x86_64/libBugly_Native.so` 走**完全相同的代码路径**
（同一个 `--member`、同一条反汇编通路），正常产出 493 个函数。
差别只在架构 —— 这把问题定位在 aarch64 分支上。

## 影响面

1. **ARM64 的 `.so` 目前任何反汇编都会中止进程。** 不是"结果不对"，是"进程没了"。
2. 对 CLI 而言是退出码 1；对 `serve` 而言是**服务进程死亡**，
   前端只会看到连接断开，看不出原因。
3. 违反 CLAUDE.md §4："作业/FFI 边界用 `catch_unwind` 兜住 panic，
   分析器崩溃必须转成错误而不是进程退出"。这里 `catch_unwind` **在原理上**
   接不住 —— non-unwinding panic 直接 abort。也就是说现有兜底机制在这条路径上
   是失效的，不是"忘了加"。

## 为什么没有"升级到修好的版本"这条选项

- crates.io 上 `capstone` 最新版是 **0.14.0**（发布 2026-01-04），
  也就是我们正在用的版本；`0.13.0`（2025-02-04）、`0.12.0`（2024-02-25）
  更旧。**没有更新的可用版本。**
- 该 crate 的 `capstone-sys` 是绑定层，`arch/arm64.rs` 属于纯 Rust 封装，
  问题在这一层，换 `capstone-sys` 版本解决不了。

## 处置选项（已按实际选择更新）

| 方案 | 结果 |
| --- | --- |
| **A. `[patch.crates-io]` 本地补一份** | ✅ **选了这条**，2026-10-14 落地。改动 3 处、约 20 行，见 `third-party/capstone/PATCH.md` |
| B. 不用 capstone 反汇编 aarch64 | ❌ 否掉：要另找解码器并重做选型链，代价与收益不成比例 |
| C. 把 aarch64 反汇编放进子进程 | ❌ 否掉：跨进程边界与"单文件可执行、零外部依赖"直接冲突，而且只是把 abort 挪个地方 |
| D. 禁用 aarch64 反汇编并报 `NotYetImplemented` | ❌ 否掉：A 的代价比 D 还小，没必要先降级 |

**方案 A 的一个设计选择**（当时留作待办的那条）：越界编码**原样保留为 `u32`**，
而不是退化成 `ARM64_SYSREG_INVALID`。两个理由：

1. 退化成 `INVALID` 是**静默丢数据**（§7）。原始编码能反查 capstone 的表、
   能对上 ARM 手册的编码字段；变成 `INVALID` 就查无可查。
2. 合法性判断需要一张上千条的编码表，而那张表只能从 `capstone-sys` 的
   bindgen 输出里抄 —— §6.11 的教训正是"照自己的假设拼表，错了会静悄悄错"。

调查过程中还查明了一件事，它让这个选择更站得住：**`ARM64_OP_REG_MRS` 只在
capstone 认不出编码时才出现**（认得出时走 `ARM64_OP_SYS`）。也就是说这个变体
的语义本来就是"未映射的系统寄存器编码"，用 `Arm64Sysreg` 当载荷才是那个
说不通的设计。

## 已做的验证（含反向验证）

| 验证 | 结果 |
| --- | --- |
| 打补丁前：真实 `lib/arm64-v8a/libBugly_Native.so` | `functions` → 退出码 `0xC0000409`，`arm64.rs:70`，`invalid value 0x1d7e`，`non-unwinding panic. aborting.` |
| 打补丁后：同一个 `.so` | `functions` → 退出码 0，**495 个函数** |
| 打补丁后：同一个 `.so` 的 `export` | 退出码 0，42 901 条指令 |
| 打补丁后：APK 里的 aarch64 成员 | `symbol JNI_OnLoad --member lib/arm64-v8a/...` → `0xa4f8` |
| x86_64 成员未被影响 | 493 个函数，与改动前一致 |
| **反向验证**：把补丁撤掉后重新构建 | 编译期哨兵报 `error[E0308]`；构建出的 CLI 再跑那个 `.so` → 又回到 `0xC0000409`。**证明测试与补丁都在真的起作用**，不是绿灯说谎 |

回归测试在 `crates/bitflip-arch/tests/arm64_sysreg_operand.rs`（5 条）。
它钉的是**那 4 个字节**（`ce af 03 d5`）而不是样本文件 —— §0.2 禁止二进制样本入库，
而单条指令的解码不依赖上下文，4 个字节就够复现。

## 待办

- [x] 方案 A 的补丁写法 —— 见上面的设计选择。
- [x] 回归测试 —— `crates/bitflip-arch/tests/arm64_sysreg_operand.rs`，
      并用"撤掉补丁必须变红"反向验证过。
- [x] 检查 `bitflip-arch` 的 aarch64 调用点 —— 顺带查出**相邻问题**，见下。

## 仍未做：相邻问题（`bitflip-arch` 把操作数丢了）

`crates/bitflip-arch/src/backend.rs` 的 `convert_arm64_operand` 有个 `_ => {}`
兜底，`RegMrs` / `RegMsr` / `Pstate` / `Sys` / `Prefetch` / `Barrier` 全落在里面。
而指令文本是**按我们自己的操作数表拼的**（`render.rs` 刻意不复用 capstone 的
`op_str`），所以这些操作数在输出里直接消失：

| 地址 | llvm-objdump | BitFlip |
| --- | --- | --- |
| 0 | `mrs x19, TPIDR_EL0` | `mrs x19` |
| 4 | `msr TPIDR_EL0, x19` | `msr x19` |
| 0x10 | `msr DAIFSet, #0x2` | `msr 0x2` |
| 0x18 | `dsb sy` | `dsb` |
| 0x20 | `dc civac, x0` | `dc x0` |
| 0x24 | `tlbi vmalle1` | `tlbi` |
| 0x28 | `prfm pldl1keep, [x1]` | `prfm [x1]` |

`msr x19` 不只是"不全"——它读起来像一条**合法的另一条指令**。用户照这个读会
把语义搞错，而且没有任何标记提示"这里少了东西"。这属于 §7「降级要写在界面上」，
与 capstone 的 abort 是两件事。

（另有一条上游行为，不打算碰：capstone 的 C 端把**未知**的 MSR 也标成
`ARM64_OP_REG_MRS`（`AArch64InstPrinter.c:2297`），而已知的 MSR 目标走
`ARM64_OP_SYS`，Rust 端读成 `Sys(Arm64SysOp)` —— 字段被一物两用，
值对类型错。详见 `third-party/capstone/PATCH.md`。）

修复这条要在 `bitflip-arch` 里给这几类操作数补上渲染，并**给系统寄存器起名**
（capstone 的 C 表是唯一权威，`cs_reg_name` 对系统寄存器编码不适用）。
那是一个独立改动，需要单独定做法。

