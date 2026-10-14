//! aarch64 系统寄存器操作数：钉住 `capstone` 的那处补丁。
//!
//! ## 为什么要有这条测试
//!
//! `capstone` 0.14.0 在 `src/arch/arm64.rs` 里把 capstone C 端给的原始系统
//! 寄存器编码 `mem::transmute` 成 `Arm64Sysreg`。那个枚举是**稀疏**的
//! `#[repr(u32)]`（只有 `0` 与 49k~62k 段里那些具名编码），而 C 端
//! （`printMRSSystemRegister` / `printMSRSystemRegister`）**不校验**就写
//! `op.reg = Val`。于是任何它没命名的编码都会让 transmute 构造非法枚举值
//! —— 那是**非展开** panic：进程直接 abort，`catch_unwind` 接不住。
//!
//! 仓库用 `third-party/capstone` 的本地副本替掉了这一处（见该目录的
//! `PATCH.md`）。**这条测试是那个补丁的哨兵**：补丁一旦丢失（比如升级
//! `capstone` 时把 `[patch.crates-io]` 一起删了），这里会立刻红。
//!
//! ## 为什么不用真实样本文件
//!
//! 触发它的原始样本是真实上架 APK 里的 `lib/arm64-v8a/libBugly_Native.so`。
//! 但 CLAUDE.md §0.2 禁止把二进制样本入库，所以这里只钉**那 4 个字节**——
//! 单条指令的解码不依赖上下文，4 个字节就够复现。
//!
//! ## 真值从哪来
//!
//! 不照自己的实现写期望值（§6.11 的教训）。每个常量都有出处：
//!
//! - 字节 `ce af 03 d5` 与地址 `0x12ce`：从 BitFlip 自己的导出结果
//!   （`export --format asm-intel`）里定位到的那一行，它是本次实测中
//!   **唯一**产生 `0x1d7e` 的行；
//! - `0x1d7e`：上游 panic 报文里那个值，也由下面的编码规则从字节算出；
//! - `TPIDR_EL0 = 56962`：`capstone-sys` 的 `ARM64_SYSREG_TPIDR_EL0` 常量，
//!   并与 `llvm-objdump` 打出的 `mrs x19, TPIDR_EL0` 对得上。
//!
//! ## 一个反直觉但重要的事实
//!
//! `ARM64_OP_REG_MRS` **只在 capstone 认不出这个编码时**才出现。它认得出时
//! 走的是 `ARM64_OP_SYS`（`AArch64InstPrinter.c` 的 MRS 打印函数里，
//! 命中具名分支写 `type = ARM64_OP_SYS; sys = Val`，只有落到 else 分支才写
//! `type = ARM64_OP_REG_MRS`）。
//!
//! 也就是说：这个变体的语义本来就是"**未映射**的系统寄存器编码"。
//! 补丁把它改成携带原始 `u32`，不是权宜之计，而是与它的实际含义一致 ——
//! 原来的 `Arm64Sysreg` 载荷才是那个说不通的设计。
//!
//! 顺带解释了为什么这个 bug 一直没被发现：常见指令（`TPIDR_EL0` 之类）
//! 全走具名分支，一次也不碰 `RegMrs`。
//!
//! ## 本测试**不**覆盖的（别以为顺手修好了）
//!
//! 具名编码走 `ARM64_OP_SYS`，而 Rust 绑定把它读成 `Sys(Arm64SysOp)` ——
//! `Arm64SysOp` 是 `SYS` 指令（IC/DC/AT/TLBI）的操作枚举，**不是**系统寄存器
//! 编码。这个字段被 C 端一物两用，绑定只建模了其中一种，于是系统寄存器编码
//! 落进了一个语义不同的类型里：**值是对的，类型是错的**。
//! 它没有 transmute，所以不崩；本补丁也没动它。
//! 下面的 `ViaSysField` 把当前行为钉住，将来真去修时这里会红，
//! 提醒"这是一次有意的行为变更，不是回归"。

use bitflip_arch::{ArchSpec, CapstoneDecoder, Decoder};

/// 触发上游 abort 的真实字节，按**文件顺序**（即小端）。
///
/// 反汇编出来是 `msr x14` 那一族；对应的 32 位字是 `0xd503afce`。
const ABORTING_BYTES: [u8; 4] = [0xce, 0xaf, 0x03, 0xd5];
/// 该字节在样本里的偏移。地址只影响 PC 相对渲染，不影响这里断言的东西。
const ABORTING_ADDR: u64 = 0x12ce;
/// 编码里解出的系统寄存器字段 —— 正是上游 panic 报文里的那个非法值。
const ABORTING_SYSREG: u32 = 0x1d7e;

/// 一条**正常**的 `mrs`：`mrs x19, TPIDR_EL0`。
///
/// 它给出的编码恰好是合法枚举值，所以在没打补丁的版本上也**不会**崩 ——
/// 这正是这个 bug 容易被漏掉的原因：常见指令都走得通。
const TPIDR_EL0_BYTES: [u8; 4] = [0x53, 0xd0, 0x3b, 0xd5];
const TPIDR_EL0_SYSREG: u32 = 56962;

/// 一个 MRS/MSR 类操作数**落在哪个变体**、带的原始编码是多少。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum SysregOperand {
    /// capstone 认不出这个编码：`RegMrs` / `RegMsr`，载荷是原始编码。
    ///
    /// 打到补丁前，构造这个变体就是那次 abort 的来源。
    Unmapped(u32),
    /// capstone 认得出，于是走了它的一物两用字段 `ARM64_OP_SYS`，
    /// Rust 绑定读成 `Sys(Arm64SysOp)`。**类型是错的，值是原始编码。**
    ViaSysField(u32),
}

/// 按 ARM 的编码规则从机器码里取出系统寄存器字段。
///
/// `MRS`/`MSR` 的编码是
/// `1101 0101 00 L op0[1:0] op1 CRn CRm op2 Rt`，
/// 系统寄存器字段占 bit[20:5]。
///
/// 这条函数**独立于解码器**：只用字节做算术。两个常量都由它校验，所以
/// 常量写错（或字节抄错）会在这里被抓住，而不是变成"测试和实现一起错"。
fn sysreg_field(bytes: [u8; 4]) -> u32 {
    let word = u32::from_le_bytes(bytes);
    (word >> 5) & 0xFFFF
}

fn arm64_decoder() -> capstone::Capstone {
    use capstone::arch::arm64::ArchMode;
    use capstone::prelude::*;

    capstone::Capstone::new()
        .arm64()
        .mode(ArchMode::Arm)
        .detail(true)
        .build()
        .expect("构造 aarch64 解码器失败")
}

/// 取出第一条指令里所有 MRS/MSR 操作数。
fn mrs_msr_operands(bytes: [u8; 4], addr: u64) -> Vec<SysregOperand> {
    use capstone::arch::arm64::Arm64OperandType;
    use capstone::arch::ArchOperand;

    let cs = arm64_decoder();
    let insns = cs.disasm_all(&bytes, addr).expect("单条指令解码不该失败");
    let insn = insns.iter().next().expect("这 4 个字节应当能解出一条指令");
    // `Insn::detail()` 在 capstone 0.14 里是 crate 私有的，公开入口是句柄上的
    // `insn_detail`（`bitflip-arch` 的 `decode_one` 走的也是这条）。
    let detail = cs.insn_detail(insn).expect("构造时已开 detail");

    let mut found = Vec::new();
    for operand in detail.arch_detail().operands() {
        if let ArchOperand::Arm64Operand(op) = operand {
            match op.op_type {
                // 载荷是 `u32` —— **这就是补丁的编译期哨兵**：没打补丁时载荷是
                // `Arm64Sysreg`，下面两行绑到 `u32` 会直接编译不过，
                // 而不是等到运行时才崩。
                Arm64OperandType::RegMrs(raw) => found.push(SysregOperand::Unmapped(raw)),
                Arm64OperandType::RegMsr(raw) => found.push(SysregOperand::Unmapped(raw)),
                // `Arm64SysOp` 是字段较少的枚举，直接 `as u32` 取回原始数值。
                Arm64OperandType::Sys(sys_op) => {
                    found.push(SysregOperand::ViaSysField(sys_op as u32));
                }
                _ => {}
            }
        }
    }
    found
}

/// 编码规则本身的自检：两个常量都必须与字节算出来的一致。
///
/// 没有这一条，常量就只是"我抄下来的数字"，抄错了没人知道。
#[test]
fn the_encoding_field_matches_the_bytes_we_pinned() {
    assert_eq!(
        sysreg_field(ABORTING_BYTES),
        ABORTING_SYSREG,
        "0x1d7e 必须能从 ce af 03 d5 里按编码规则算出来"
    );
    assert_eq!(
        sysreg_field(TPIDR_EL0_BYTES),
        TPIDR_EL0_SYSREG,
        "TPIDR_EL0 的编码必须能从 53 d0 3b d5 里算出来"
    );
}

/// 上游崩掉的那个编码，现在必须**如实保留**、不崩。
///
/// 这是本文件的核心用例。断言两件事：
/// 1. 解码不中止进程（没打补丁时，这一行会让整个测试进程 abort）；
/// 2. 原始编码 `0x1d7e` 被原样带出来 —— 不许悄悄退化成 `INVALID`/`0`
///    （CLAUDE.md §7：拿不到就说拿不到，不许用 0 顶替）。
#[test]
fn an_unmapped_system_register_encoding_does_not_abort() {
    let found = mrs_msr_operands(ABORTING_BYTES, ABORTING_ADDR);
    assert_eq!(
        found,
        vec![SysregOperand::Unmapped(ABORTING_SYSREG)],
        "原始编码要原样带出来，且恰好一个操作数"
    );
}

/// 认不出的编码不许被退化成 0。
///
/// 单列一条是为了让"用 0 冒充未知"这个具体退化方式有对应用例，
/// 而不是只靠上面那条 `assert_eq` 顺带压住。
#[test]
fn an_unmapped_encoding_is_never_flattened_to_zero() {
    let found = mrs_msr_operands(ABORTING_BYTES, ABORTING_ADDR);
    assert!(
        found.iter().all(|op| *op != SysregOperand::Unmapped(0)),
        "0 是 ARM64_SYSREG_INVALID，用它顶替未知值正是 §7 禁止的"
    );
}

/// 具名编码这条路径的当前行为（含已知的类型错位）。
///
/// 钉住它有两个作用：
/// * 证明补丁只影响"认不出的值"，没动常见指令的行为；
/// * 将来真去修 `ARM64_OP_SYS` 一物两用的问题时，这里会红，
///   提醒那是一次**有意的行为变更**，而不是悄悄发生的回归。
#[test]
fn a_well_known_system_register_currently_arrives_via_the_sys_field() {
    let found = mrs_msr_operands(TPIDR_EL0_BYTES, 0x8638);
    assert_eq!(
        found,
        vec![SysregOperand::ViaSysField(TPIDR_EL0_SYSREG)],
        "TPIDR_EL0 的编码要原样保留；注意它落在 Sys 字段里（见文件头\"不覆盖的\"）"
    );
}

/// 走 BitFlip 自己的解码入口，确认这条通路也不崩、且能给出助记符。
///
/// 上面几条用的是 capstone 的直接 API；这一条证明 `bitflip-arch` 接进来之后
/// 同样没事（`convert_arm64_operand` 目前会把系统寄存器操作数整个丢掉，
/// 那是另一个问题，不影响"不崩"这个结论）。
#[test]
fn bitflip_decoder_survives_the_encoding_too() {
    let decoder = CapstoneDecoder::new(ArchSpec::aarch64()).expect("aarch64 解码器");
    let insn = decoder
        .decode_one(&ABORTING_BYTES, ABORTING_ADDR)
        .expect("这条指令应当解得出，而不是报错或中止进程");

    let mnemonic = decoder
        .mnemonic_name(&insn)
        .expect("capstone 应当给得出助记符");
    assert!(
        mnemonic == "mrs" || mnemonic == "msr",
        "这 4 个字节是 MRS/MSR 族，实际解出 {mnemonic:?}"
    );
}
