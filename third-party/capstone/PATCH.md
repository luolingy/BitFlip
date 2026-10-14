# `third-party/capstone` —— vendored 并打过补丁的 `capstone` 0.14.0

## 这个目录是什么

`capstone` 0.14.0 的**完整源码副本**（上游：<https://github.com/capstone-rust/capstone-rs>，
MIT，见同目录 `LICENSE`），加**一处修改**。仓库根 `Cargo.toml` 用
`[patch.crates-io]` 把依赖指到这里。

只改了一个文件：`src/arch/arm64.rs`。所有改动都在
`// === BitFlip fork begin ===` / `// === BitFlip fork end ===` 之间，
用这两行标记一搜就能看到全部差异。

## 为什么改：aarch64 反汇编会**中止进程**

上游 `Arm64OperandType::new` 里：

```rust
// 上游 0.14.0
ARM64_OP_REG_MRS => RegMrs(unsafe {
    mem::transmute::<Arm64Reg::Type, Arm64Sysreg>(value.reg as Arm64Reg::Type)
}),
```

`Arm64Sysreg`（= `capstone_sys::arm64_sysreg`）是一个**稀疏**的
`#[repr(u32)]` 枚举：合法值只有 `0`，以及 49k~62k 段里那些具名编码
（例如 `ARM64_SYSREG_TPIDR_EL0 = 56962`）。而 capstone 的 C 端在
`arch/AArch64/AArch64InstPrinter.c` 的 `printMRSSystemRegister` /
`printMSRSystemRegister` 里，**不校验**就把指令里的原始编码写进操作数：

```c
MI->flat_insn->detail->arm64.operands[...].reg = Val;   /* 原样透传 */
```

`Val` 是 capstone 自己那张名字表**查不到**时也会照样透传的原始编码。
于是：

- 遇到它命名的编码（如 `TPIDR_EL0` = 56962）→ 恰好是合法枚举值 → 正常；
- 遇到它**没**命名的编码 → `transmute` 构造非法枚举值 →
  Rust 的有效性检查报
  `trying to construct an enum from an invalid value 0x1d7e`。

关键在于这个 panic 是**非展开**的（`thread caused non-unwinding panic.
aborting.`）：栈不会回退，`catch_unwind` **接不住**，进程直接 abort。
实测退出码 `0xC0000409`。

这条直接违反 CLAUDE.md §4「作业/FFI 边界用 `catch_unwind` 兜住 panic，
分析器崩溃必须转成错误而不是进程退出」—— 而且不是"忘了加兜底"，
是**兜底机制在这条路径上原理性失效**。

### 实测影响

| 目标 | 结果 |
| --- | --- |
| 真实上架 APK 里的 `lib/arm64-v8a/libBugly_Native.so` | `functions` / `symbol` / `export` **一律 abort** |
| 同一个 `.so` 的 x86_64 版本（`lib/x86_64/…`） | 正常，493 个函数 |

aarch64 是 Android 的主 ABI，所以不修这一条，M11「APK 里的 `.so` 直接复用
ELF 通路」这个核心收益对大多数真实 APK 都拿不到。

**上游没有修好的版本可升**：0.14.0（2026-01-04 发布）就是 crates.io 最新，
`0.13.0` / `0.12.0` 更旧。

## 补丁做了什么

把"原样透传的原始编码"**如实保留为 `u32`**，不再伪装成枚举：

```rust
// BitFlip fork
ARM64_OP_REG_MRS => RegMrs(unsafe { value.reg }),
ARM64_OP_REG_MSR => RegMsr(unsafe { value.reg }),
```

```rust
// BitFlip fork
RegMrs(u32),   // 原始系统寄存器编码，不要假定它是合法 Arm64Sysreg
RegMsr(u32),
```

三处改动：操作数转换（2 处 transmute）、枚举载荷类型（2 个变体）、
以及 crate 自带测试里对应的 3 个用例（含一条针对 `0x1d7e` 的回归用例）。

### 为什么是"保留原始值"而不是"越界就退化成 INVALID"

考虑过的另一条路是：查表判断合法性，合法才给枚举，越界用
`Arm64Sysreg::ARM64_SYSREG_INVALID`。**否掉了**，两个理由：

1. **会静默丢数据**（§7）。原始编码是有信息量的（能反查 capstone 的表、
   能对上 ARM 手册的编码字段），退化成 `INVALID` 就查无可查了。
2. **合法性判断需要一张上千条的编码表**。这张表只能从 `capstone-sys` 的
   bindgen 输出里抄出来，抄完还要在每次 `capstone-sys` 升级时重新核对
   —— 一个维护负担，换来的却是"更少的信息"。而 §6.11 的教训正是：
   照自己的假设拼表，错了会静悄悄地错。

保留 `u32` 还有一个附带好处：类型不再宣称一个它保证不了的承诺
（"这一定是有效的 `Arm64Sysreg`"）。

## 这个补丁**没有**解决的相邻问题（不要误以为顺手修了）

1. **capstone 的 C 端把未知的 MSR 也标成 `ARM64_OP_REG_MRS`。**
   `printMSRSystemRegister` 的 else 分支（`AArch64InstPrinter.c:2297`）
   写的是 `ARM64_OP_REG_MRS`。所以 `RegMsr` 实际上**几乎不会**出现，
   未知的 MSR 会被当成 MRS。这是上游 C 端的行为，本补丁没动它。
2. **已知的 MSR 目标走的是 `ARM64_OP_SYS`，而 Rust 端把它读成
   `Arm64SysOp`。** 但 `ARM64_OP_SYS` 的 `sys` 字段被 C 端同时用于
   两件事：真正的 SYS 指令操作（IC/DC/AT/TLBI）与 MSR 的系统寄存器编码
   （`AArch64InstPrinter.c:2281` 写的也是原始编码）。Rust 端只有一个
   `Sys(Arm64SysOp)`，读非 SYS 指令时会得到一个**语义不对**的枚举值。
   `Arm64SysOp` 的读取没有 transmute，所以**不崩**，但值是错的。
3. **`bitflip-arch` 把这类操作数整个丢掉了。** `convert_arm64_operand`
   的 `match` 有个 `_ => {}` 兜底，`RegMrs` / `RegMsr` / `Pstate` / `Sys` /
   `Prefetch` / `Barrier` 全落在里面。实测后果是**渲染出的指令文本缺操作数**，
   而文本是按我们自己的操作数表拼的（`render.rs` 刻意不复用 capstone 的
   `op_str`）：

   | 地址 | llvm-objdump | BitFlip |
   | --- | --- | --- |
   | 0 | `mrs x19, TPIDR_EL0` | `mrs x19` |
   | 4 | `msr TPIDR_EL0, x19` | `msr x19` |
   | 0x10 | `msr DAIFSet, #0x2` | `msr 0x2` |
   | 0x18 | `dsb sy` | `dsb` |
   | 0x20 | `dc civac, x0` | `dc x0` |
   | 0x24 | `tlbi vmalle1` | `tlbi` |
   | 0x28 | `prfm pldl1keep, [x1]` | `prfm [x1]` |

   `msr x19` 不只是"不全"——它读起来像一条**合法的另一条指令**。
   这属于 §7「降级要写在界面上」的范畴，与本补丁是两件事，另行处理。

## 目录里保留了什么、删了什么

**改了一个文件**（`src/arch/arm64.rs`），**删了一个目录**（`test-inputs/`）。

删 `test-inputs/` 的理由是遵守 CLAUDE.md §0.2（"不把二进制样本入库"）——
它只有一个文件 `x86_64.bin_ls.bin`（68.6 KiB），引用它的地方只有两处，
都在我们不会跑的范围里：

- `benches/my_benchmark.rs` 的 `include_bytes!`；
- `ci/test.sh` 的命令行。

所以删掉它**不影响构建**，也不影响任何声明的 cargo target（`[[bench]]` 指向的
`benches/my_benchmark.rs` 仍在）。唯一的代价是：真去跑 `cargo bench` 时那个
bench 会编不过 —— 我们不会跑它（这个 crate 不是 workspace 成员）。

`src/` 一个文件都没删、没改（除 `arch/arm64.rs`）。`src/test.rs` 用了
`pretty_assertions`（上游的 dev-dependency），所以 `Cargo.toml` 里保留着
dev-dependencies 声明 —— 这样那份测试源码仍然自洽。

其余都原样保留：`Cargo.toml`、`LICENSE`（MIT 原文）、`THIRD_PARTY.txt`、
`README.md`、`CHANGELOG.md`、`Cargo.toml.orig`、`examples/`、`benches/`、
`ci/`、`scripts/`。**尽量少动**是有意的：差异越小，将来升级时越好套。

## 怎么升级到新的上游版本

```powershell
# 1) 拉新版本源码，替换本目录（保留 PATCH.md 与 LICENSE 的说明作用）
#    新版本号要同步改根 Cargo.toml 的 capstone 版本要求
# 2) 在 src/arch/arm64.rs 里搜 "transmute" 与 "Arm64Sysreg"
#    - 若上游已改成可失败转换、或已把载荷改成 u32 → 补丁可以整个删掉，
#      连 [patch.crates-io] 一起删；
#    - 若还是 transmute → 按上面的三处改动重新套一遍。
# 3) 按下面的验证步骤跑一遍。
```

判断补丁能不能删的最快办法：看上游 `Arm64OperandType::RegMrs` 的载荷类型。
只要它还是 `Arm64Sysreg`，这个 bug 就还在。

## 验证

```powershell
# 单测：不崩 + 如实保留编码（回归用例钉住了 0x1d7e）
& .\scripts\cargo.ps1 test -p capstone        # 需要该 crate 被当作成员时；
                                              # 通常靠下面两条端到端验证

# 端到端 1：真实 aarch64 .so 不再 abort
& .\.cargo-target\debug\bitflip-cli.exe functions <某个 arm64 .so> --count 5

# 端到端 2：指令文本与 llvm-objdump 对得上
& .\scripts\cargo.ps1 build -p bitflip-cli
& .\.cargo-target\debug\bitflip-cli.exe export <某个 arm64 .so> --format asm-intel
```

`bitflip-arch` 侧的回归测试在 `crates/bitflip-arch/tests/arm64_sysreg.rs`。
