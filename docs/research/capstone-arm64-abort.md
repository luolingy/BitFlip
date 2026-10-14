# `capstone` 0.14.0 的 aarch64 反汇编会**中止进程**（既有问题，非本次引入）

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

## 处置选项

| 方案 | 代价 | 说明 |
| --- | --- | --- |
| **A. `[patch.crates-io]` 本地补一份** | 低（改动约 20 行），但要维护 fork | 把那两处 `transmute` 换成可失败转换；越界时给出**原始号码**而不是猜。缺点：以后每次升级 `capstone` 都要重新套一次 |
| **B. 不用 capstone 反汇编 aarch64** | 高 | 得另找解码器，且 `docs/DEPENDENCY-DECISIONS.md` 的选型链要重做 |
| **C. 先在调用层把 abort 变成可报错** | 中 | 把 aarch64 反汇编放到子进程里，父进程看退出码 —— 代价是跨进程边界，与"单文件可执行、零外部依赖"的目标有摩擦 |
| **D. 暂时禁用 aarch64 反汇编并明确报错** | 低 | 至少不再 abort：`info` 仍然工作，`functions` 返回 `NotYetImplemented`。诚实但没有产出 |

**建议 A + D 一起做**：A 解决根因（本地补一份，改动很小），
D 作为 A 落地前的过渡（把"进程死掉"换成"明确说这个架构的反汇编暂不可用"）。
在任何情况下**不要**让 abort 留在里面 —— 它对 `serve` 是致命的。

## 待办

- [ ] 评估方案 A 的具体补丁写法（越界时退化成 `Invalid` 还是保留原始号码？
      前者会让 `MRS` 操作数静默丢失，后者要改 `Arm64OperandType` 的形状 ——
      倾向保留原始号码，因为 §7 要求"拿不到就说拿不到"而不是悄悄少给）。
- [ ] 补一条**真实样本**回归测试：拿一个含 `MRS`/`MSR` 的 aarch64 `.so`
      跑反汇编，断言"不中止"。样本按 CLAUDE.md §0.2 由 `tests/fixtures` 脚本生成。
- [ ] 检查 `bitflip-arch` 里对 aarch64 的调用点，确认没有别的地方绕开这道坎。
