//! capstone 解码后端。
//!
//! ## 这一层的唯一职责
//!
//! 把 capstone 的 `InsnDetail` 翻译成 [`DecodedInsn`]。**绝不**让上层看到
//! capstone 的类型，也绝不让上层去 `parse()` 指令文本 —— 文本是渲染层的事。
//!
//! ## 线程安全
//!
//! capstone 的 `Capstone` 句柄不是 `Sync`。扫描是 `rayon` 并行的，因此这里
//! 用**线程局部句柄池**：每个线程持有自己的句柄，避免加锁也避免每解一条指令
//! 就建一个引擎（那是 adi 踩过的二次复杂度坑）。
//!
//! ## 退化路径
//!
//! capstone 的 `disasm_count` 在一次调用里解码多条指令，但它内部会重新
//! 校验边界；对**每条指令单独调用 `disasm_count(.., 1)`** 是更稳的做法：
//! 出错时能精确定位到哪条指令失败，而不是整块失败。批量接口因此建立在
//! 单条接口之上，由调用方按窗口循环。

use std::cell::RefCell;
use std::fmt;

use capstone::{Capstone, InsnDetail};

use crate::decode::{DecodeError, Decoder};
use crate::insn::{DecodedInsn, Flow, MnemonicId, RegId, RegSet};
use crate::types::{Arch, ArchSpec, Mode};

/// 解码后端的选择。
///
/// M2 只有 capstone；保留这个枚举是为了 D3 决策（是否加 iced-x86）有落点，
/// 而不是把"将来可能换后端"写进注释里然后忘掉。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum DecoderBackend {
    /// capstone（默认）。
    #[default]
    Capstone,
}

/// 创建解码后端失败的原因。
#[derive(Debug, Clone)]
pub enum BackendError {
    /// 该架构/模式组合不在支持范围内。
    Unsupported {
        /// 架构。
        arch: Arch,
        /// 模式。
        mode: Mode,
    },
    /// capstone 拒绝构造该架构的引擎。
    Build {
        /// 架构。
        arch: Arch,
        /// 模式。
        mode: Mode,
        /// capstone 的报错文本。
        detail: String,
    },
}

impl fmt::Display for BackendError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Unsupported { arch, mode } => write!(f, "没有可用的解码后端: {arch}/{mode}"),
            Self::Build { arch, mode, detail } => {
                write!(f, "构造 {arch}/{mode} 解码引擎失败: {detail}")
            }
        }
    }
}

impl std::error::Error for BackendError {}

/// capstone 的架构/模式组合。
///
/// capstone 的 builder 是**每个架构一个方法**（`.x86()` / `.arm64()` / …），
/// 每个方法接受自己那套 `ArchMode`。因此这里不能给出统一的 `(Arch, Mode)` 元组，
/// 只能把"每种组合怎么建"写成一个函数。
enum CsTarget {
    X86(capstone::arch::x86::ArchMode),
    Arm64,
    Arm(capstone::arch::arm::ArchMode),
    Riscv(capstone::arch::riscv::ArchMode),
    Mips(capstone::arch::mips::ArchMode),
}

/// 把 [`ArchSpec`] 映射成 capstone 的架构/模式。
///
/// 返回 `None` 表示 capstone 没有对应后端 —— 调用方据此返回
/// [`DecodeError::Unsupported`]，而不是猜一个近似架构去解码
/// （用 x86 解码 ARM 字节会得到"看起来成功"的垃圾）。
fn cs_target_for(spec: ArchSpec) -> Option<CsTarget> {
    Some(match (spec.arch, spec.mode) {
        (Arch::X86, Mode::M16) => CsTarget::X86(capstone::arch::x86::ArchMode::Mode16),
        (Arch::X86, Mode::M32) | (Arch::X86, Mode::Thumb) => {
            CsTarget::X86(capstone::arch::x86::ArchMode::Mode32)
        }
        (Arch::X86_64, _) => CsTarget::X86(capstone::arch::x86::ArchMode::Mode64),
        (Arch::Aarch64, _) => CsTarget::Arm64,
        // ARM 状态是 32 位；Thumb 是同一架构的另一套编码
        (Arch::Arm, Mode::Thumb) => CsTarget::Arm(capstone::arch::arm::ArchMode::Thumb),
        (Arch::Arm, _) => CsTarget::Arm(capstone::arch::arm::ArchMode::Arm),
        (Arch::Riscv32, _) => CsTarget::Riscv(capstone::arch::riscv::ArchMode::RiscV32),
        (Arch::Riscv64, _) => CsTarget::Riscv(capstone::arch::riscv::ArchMode::RiscV64),
        (Arch::Mips, _) => CsTarget::Mips(capstone::arch::mips::ArchMode::Mips32),
        (Arch::Mips64, _) => CsTarget::Mips(capstone::arch::mips::ArchMode::Mips64),
        _ => return None,
    })
}

/// 构造一个 capstone 引擎。
///
/// 每个架构走自己的 builder 链（capstone 的类型系统要求如此）。
/// 共同点是都开 `detail(true)` —— 没有它就拿不到"读了哪些寄存器"
/// "内存操作数是什么"，而这些正是结构化指令模型必须有的字段。
fn build_engine(spec: ArchSpec) -> Result<Capstone, BackendError> {
    use capstone::arch::{BuildsCapstone, BuildsCapstoneSyntax};

    let target = cs_target_for(spec).ok_or(BackendError::Unsupported {
        arch: spec.arch,
        mode: spec.mode,
    })?;

    let result = match target {
        // x86 家族额外指定 Intel 语法：面向 Windows/x86 逆向的主流习惯，
        // 且与 llvm-objdump --x86-asm-syntax=intel 可直接对照。
        CsTarget::X86(mode) => Capstone::new()
            .x86()
            .mode(mode)
            .syntax(capstone::arch::x86::ArchSyntax::Intel)
            .detail(true)
            .build(),
        // arm64 的 builder 也要求显式 `.mode()`（capstone 的约束），
        // 尽管 AArch64 只有一个模式 `Arm`。不传会得到
        // "Must specify mode for arm64::ArchCapstoneBuilder"。
        CsTarget::Arm64 => Capstone::new()
            .arm64()
            .mode(capstone::arch::arm64::ArchMode::Arm)
            .detail(true)
            .build(),
        CsTarget::Arm(mode) => Capstone::new().arm().mode(mode).detail(true).build(),
        CsTarget::Riscv(mode) => Capstone::new().riscv().mode(mode).detail(true).build(),
        CsTarget::Mips(mode) => Capstone::new().mips().mode(mode).detail(true).build(),
    };

    result.map_err(|error| BackendError::Build {
        arch: spec.arch,
        mode: spec.mode,
        detail: error.to_string(),
    })
}

/// capstone 解码器。
///
/// 每个线程持有一个引擎实例（见模块文档）。`spec` 只读，因此 `Send + Sync`。
pub struct CapstoneDecoder {
    spec: ArchSpec,
    /// 线程局部引擎池。
    ///
    /// 放进 `Arc` 是为了让 `CapstoneDecoder` 能被多个线程共享：`Arc<T>`
    /// 在 `T: Send + Sync` 时自动 `Send + Sync`，而 `thread_local!` 本身
    /// 恰好满足这两条 —— 不需要任何 `unsafe impl`（工作区 lint
    /// `unsafe_code = "deny"` 也不允许）。
    engines: std::sync::Arc<ThreadEngines>,
}

/// 线程局部的 capstone 引擎池。
///
/// 用 `thread_local!` 而不是「`RefCell` + 手动 `unsafe impl Send`」：
/// 后者要靠人保证"这个 `RefCell` 只被本线程访问"，一旦有人在别处
/// 克隆了它就会静默变成数据竞争。`thread_local!` 把这条保证交给编译器。
///
/// 只携带 `ArchSpec`（纯数据）—— 槽位本身由 [`slot_for`] 按架构查表得到，
/// 因此这个类型是 `Send + Sync` 的，无需任何 `unsafe`。
struct ThreadEngines {
    spec: ArchSpec,
}

/// 每个架构规格一个线程局部槽位。
///
/// `thread_local!` 的 key 必须是 `'static`，所以这里用宏按架构展开，
/// 而不是把 `ArchSpec` 塞进一个动态 key。
macro_rules! engine_slot {
    ($name:ident) => {
        thread_local! {
            static $name: RefCell<Option<Capstone>> = const { RefCell::new(None) };
        }
    };
}

engine_slot!(ENGINE_X86);
engine_slot!(ENGINE_X86_64);
engine_slot!(ENGINE_AARCH64);
engine_slot!(ENGINE_ARM);
engine_slot!(ENGINE_RISCV32);
engine_slot!(ENGINE_RISCV64);
engine_slot!(ENGINE_MIPS);
engine_slot!(ENGINE_MIPS64);

/// 选定架构对应的线程局部槽位。
///
/// 未知架构落到 x86_64 槽位只是为了避免 `Option`；真正的拒绝发生在
/// [`build_engine`]，那里会返回 `Unsupported`。
fn slot_for(arch: Arch) -> &'static std::thread::LocalKey<RefCell<Option<Capstone>>> {
    match arch {
        Arch::X86 => &ENGINE_X86,
        Arch::Aarch64 => &ENGINE_AARCH64,
        Arch::Arm => &ENGINE_ARM,
        Arch::Riscv32 => &ENGINE_RISCV32,
        Arch::Riscv64 => &ENGINE_RISCV64,
        Arch::Mips => &ENGINE_MIPS,
        Arch::Mips64 => &ENGINE_MIPS64,
        // X86_64 与未知架构共用槽位；未知架构会在构建时被拒绝
        _ => &ENGINE_X86_64,
    }
}

impl ThreadEngines {
    fn with<R>(&self, f: impl FnOnce(&Capstone) -> R) -> Result<R, DecodeError> {
        let key = slot_for(self.spec.arch);
        key.with(|slot| {
            let mut slot = slot.borrow_mut();
            if slot.is_none() {
                let engine = build_engine(self.spec).map_err(|_| DecodeError::Unsupported {
                    arch: self.spec.arch,
                    mode: self.spec.mode,
                })?;
                *slot = Some(engine);
            }
            // 上面刚保证非 None
            let engine = slot.as_ref().expect("引擎已初始化");
            Ok(f(engine))
        })
    }
}

impl CapstoneDecoder {
    /// 为指定架构规格构造解码器。
    pub fn new(spec: ArchSpec) -> Result<Self, BackendError> {
        // 先构造一次，把"这个架构不支持"在**创建解码器时**就暴露出来，
        // 而不是等到解码第一条指令才发现。构造出来的句柄顺手丢弃 ——
        // 真正使用的是各线程自己的实例。
        let probe = build_engine(spec)?;
        drop(probe);

        Ok(Self {
            spec,
            engines: std::sync::Arc::new(ThreadEngines { spec }),
        })
    }

    /// 把架构规定的寄存器**名**解析成 capstone 的 [`RegId`]。
    ///
    /// # 为什么需要它
    ///
    /// ABI 表里存的是名字（`"rdi"`、`"rcx"`、`"x0"`）—— 那是给人看的
    /// 契约，界面要显示它。而 `DecodedInsn::reads`/`writes` 里放的是
    /// `RegId`，也就是 capstone 的编号。两套表示之间需要一个映射，
    /// 否则"这个函数读了第 1 个参数寄存器吗"这个问题根本无从问起
    /// （`AbiSpec::arg_regs()` 因此长期返回空表）。
    ///
    /// # 为什么不写死一张编号表
    ///
    /// `RegId` 由 capstone 决定，跨架构没有统一规律。写死编号在换
    /// 后端或 capstone 版本变更时会**静默错位**：参数标注整体偏一两个
    /// 寄存器，不报错，只是结论全错。
    ///
    /// 所以这里向真实后端要：遍历该架构的全部寄存器名，找同名的那一个。
    /// 找不到返回 `None` —— 调用方据此说"这个架构不支持参数推断"，
    /// 而不是拿一个猜的编号去比。
    ///
    /// 一次调用是 O(寄存器数)；参数推断按函数做，但每个架构的 ABI 表
    /// 很小（几个到十几个名字），且调用方会在分析开始时解析一次。
    #[must_use]
    pub fn register_id(spec: ArchSpec, name: &str) -> Option<RegId> {
        let decoder = CapstoneDecoder::new(spec).ok()?;
        decoder.with_engine(|cs| {
            // capstone 的寄存器编号不保证连续，按下标逐个问名字，
            // 直到越界返回 None。
            let mut index = 1u16;
            loop {
                let reg = capstone::RegId(index);
                match cs.reg_name(reg) {
                    Some(found) => {
                        if found.eq_ignore_ascii_case(name) {
                            return Some(RegId(index));
                        }
                        index = index.saturating_add(1);
                    }
                    // 编号超出该架构的寄存器表：到头了。
                    // 这里**不是**"出错"，只是枚举结束。
                    None => return None,
                }
            }
        })
    }

    /// 在该解码器**本线程**的 capstone 引擎上执行一段操作。
    ///
    /// 暴露这个是为了渲染层（`render` 模块）能查助记符与寄存器名 ——
    /// 那些表是 capstone 的内部数据，复制一份到本项目会随版本漂移。
    ///
    /// 回调拿到的是本线程的引擎实例，闭包内不得跨线程传递。
    pub(crate) fn with_engine<R>(&self, f: impl FnOnce(&Capstone) -> R) -> R {
        // 渲染期引擎构造失败没有合理语义（查不到名字应显示占位符，而不是崩溃），
        // 因此这里退化为一个"不可能发生"的分支：`new()` 已经用同一个 spec
        // 成功构造过引擎，同一线程再构造一次不会失败。
        match self.engines.with(f) {
            Ok(value) => value,
            Err(error) => {
                debug_assert!(false, "解码器在渲染期初始化失败: {error}");
                unreachable!("new() 已验证同 spec 引擎可构造: {error}")
            }
        }
    }
}

impl fmt::Debug for CapstoneDecoder {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("CapstoneDecoder")
            .field("spec", &self.spec)
            .finish()
    }
}

// 线程安全说明：`ThreadEngines` 只携带 `ArchSpec`（纯数据）与一个
// `&'static LocalKey<RefCell<Option<Capstone>>>`，两者都是 `Send + Sync`；
// 真正的 capstone 句柄存在线程局部存储里，**永远不会跨线程共享**。
// 因此 `CapstoneDecoder: Send + Sync` 由编译器自动推导，不需要 `unsafe impl`。

impl Decoder for CapstoneDecoder {
    fn spec(&self) -> ArchSpec {
        self.spec
    }

    fn decode_one(&self, code: &[u8], addr: u64) -> Result<DecodedInsn, DecodeError> {
        if code.is_empty() {
            return Err(DecodeError::Truncated);
        }

        self.engines.with(|cs| {
            // 单条解码：出错时能精确对应到这条指令
            let insns = cs
                .disasm_count(code, addr, 1)
                .map_err(|_| DecodeError::Invalid)?;
            let insn = insns.iter().next().ok_or(DecodeError::Truncated)?;

            let len = u8::try_from(insn.bytes().len()).map_err(|_| DecodeError::Invalid)?;
            if len == 0 {
                return Err(DecodeError::Invalid);
            }

            let detail = cs.insn_detail(insn).map_err(|_| DecodeError::Invalid)?;

            Ok(convert(insn, &detail, self.spec.arch, addr, len))
        })?
    }
}

/// 把 capstone 的指令映射成结构化表示。
fn convert(
    insn: &capstone::Insn<'_>,
    detail: &InsnDetail<'_>,
    arch: Arch,
    addr: u64,
    len: u8,
) -> DecodedInsn {
    let mut reads = RegSet::new();
    let mut writes = RegSet::new();
    for reg in detail.regs_read() {
        reads.insert(RegId(reg.0));
    }
    for reg in detail.regs_write() {
        writes.insert(RegId(reg.0));
    }

    // capstone 的 groups 里带有跳转/调用/返回的语义分组 —— 从这里判断流程，
    // 而不是匹配助记符字符串。
    use capstone::InsnGroupType::{
        CS_GRP_CALL, CS_GRP_INT, CS_GRP_IRET, CS_GRP_JUMP, CS_GRP_PRIVILEGE, CS_GRP_RET,
    };
    let mut is_jump = false;
    let mut is_call = false;
    let mut is_ret = false;
    let mut is_trap = false;
    let mut privileged = false;
    for group in detail.groups() {
        match group.0 as u32 {
            CS_GRP_JUMP => is_jump = true,
            CS_GRP_CALL => is_call = true,
            CS_GRP_RET | CS_GRP_IRET => is_ret = true,
            CS_GRP_INT => is_trap = true,
            CS_GRP_PRIVILEGE => privileged = true,
            _ => {}
        }
    }

    // 操作数与直接目标。间接跳转/调用没有静态目标（`target` 保持 `None`）——
    // 这里**不猜**目标，跳转表解析是 M3 的工作。
    let mut target = None;
    let mut operands = Vec::new();
    for operand in detail.arch_detail().operands() {
        use capstone::arch::ArchOperand;
        match operand {
            ArchOperand::X86Operand(op) => {
                convert_x86_operand(&op, is_jump || is_call, &mut operands, &mut target);
            }
            ArchOperand::Arm64Operand(op) => {
                convert_arm64_operand(&op, is_jump || is_call, &mut operands, &mut target);
            }
            ArchOperand::ArmOperand(op) => {
                convert_arm_operand(&op, is_jump || is_call, &mut operands, &mut target);
            }
            // 其余架构（RISC-V / MIPS）在 M2 先不提取操作数细节：
            // 宁可少给字段，也不要给错的字段。流程语义仍然是对的。
            _ => {}
        }
    }

    let flow = if is_ret {
        Flow::Return
    } else if is_call {
        Flow::Call
    } else if is_jump {
        // `conditional` 表示"这条跳转是否有两个后继"，它**只**由助记符决定：
        // `jmp *rax` 是间接跳转，但它仍然是无条件跳转 —— 没有顺序后继。
        //
        // 曾经的写法是 `target.is_none() || is_conditional_jump(...)`，把
        // "目标未知"和"有条件"混成了一个标志。后果是 `jmp *__imp_x(%rip)`
        // 被标成条件跳转，于是 who-knows 的地方多出一个"顺序后继"，并且
        // 导入桩识别（要判 `conditional: false` 的间接跳转）一个都匹配不到。
        // "目标未知"已经由 `target: None` 如实表达，不需要借用 conditional。
        Flow::Branch {
            conditional: is_conditional_jump(insn.mnemonic().unwrap_or("")),
        }
    } else if is_trap {
        Flow::Trap
    } else {
        Flow::Fallthrough
    };

    // capstone 的 id 用作助记符标识的来源 —— 渲染层用它反查名字。
    let mnemonic = MnemonicId(insn.id().0);

    // 条件码。**必须**单独取：它不在 `InsnId` 里，`b.lt` 与 `b` 的 id 相同。
    // 不取的话渲染层只能拿到裸 `b`，把条件跳转显示成无条件跳转。
    let condition = convert_condition(detail, arch);

    DecodedInsn {
        addr,
        len,
        arch,
        mnemonic,
        flow,
        target,
        condition,
        operands,
        reads,
        writes,
        privileged,
    }
}

/// 从 capstone 的 detail 里取条件码。
///
/// x86 不从这里取：x86 的条件分支有**各自独立的助记符**（`je`/`jne`/`jl`…），
/// 名字里已经带了条件，`InsnId` 就能区分。AArch64/AArch32 则是同一个 `b`
/// 配一个 cc 字段，名字里看不出来。所以只有 ARM 系需要这条路径。
fn convert_condition(detail: &InsnDetail<'_>, arch: Arch) -> Option<crate::insn::ConditionCode> {
    use crate::insn::ConditionCode;

    match arch {
        Arch::Aarch64 => {
            let cc = detail.arch_detail().arm64()?.cc();
            use capstone::arch::arm64::Arm64CC;
            Some(match cc {
                Arm64CC::ARM64_CC_EQ => ConditionCode::Equal,
                Arm64CC::ARM64_CC_NE => ConditionCode::NotEqual,
                Arm64CC::ARM64_CC_HS => ConditionCode::CarrySet,
                Arm64CC::ARM64_CC_LO => ConditionCode::CarryClear,
                Arm64CC::ARM64_CC_MI => ConditionCode::Minus,
                Arm64CC::ARM64_CC_PL => ConditionCode::Plus,
                Arm64CC::ARM64_CC_VS => ConditionCode::Overflow,
                Arm64CC::ARM64_CC_VC => ConditionCode::NoOverflow,
                Arm64CC::ARM64_CC_HI => ConditionCode::UnsignedHigher,
                Arm64CC::ARM64_CC_LS => ConditionCode::UnsignedLowerOrSame,
                Arm64CC::ARM64_CC_GE => ConditionCode::SignedGreaterEqual,
                Arm64CC::ARM64_CC_LT => ConditionCode::SignedLessThan,
                Arm64CC::ARM64_CC_GT => ConditionCode::SignedGreaterThan,
                Arm64CC::ARM64_CC_LE => ConditionCode::SignedLessOrEqual,
                Arm64CC::ARM64_CC_AL => ConditionCode::Always,
                Arm64CC::ARM64_CC_NV => ConditionCode::Never,
                // `ARM64_CC_INVALID` 表示"这条指令不设条件码"，是正常情形。
                _ => return None,
            })
        }
        // AArch32 的条件码在指令编码的高 4 位里，capstone 目前没有通过
        // 统一接口暴露。**如实返回 `None`**（不猜），CFG 仍然是对的
        // （靠 `Flow::Branch { conditional }`），只是文本上会显示成裸 `b`。
        // 这一条写在这里是为了让它可被找到，而不是悄悄漏掉。
        _ => None,
    }
}

/// 把 capstone 的寄存器 id 转成本项目的 [`RegId`]；无效哨兵值转成 `None`。
fn opt_reg(reg: capstone::RegId) -> Option<RegId> {
    if reg.0 == 0 {
        None // capstone 的 INVALID_REG
    } else {
        Some(RegId(reg.0))
    }
}

/// x86 上 RIP 在 capstone 里的寄存器编号。
///
/// 这是个外部约定值，不是我们编的：capstone 的 `X86_REG_RIP = 41`。
/// 单独起个名字是为了让引用点能说清"这个 41 是什么"，否则读代码的人
/// 只会看到一个魔法数字。
const RIP_REG_ID: u16 = 41;

/// x86 操作数。
fn convert_x86_operand(
    op: &capstone::arch::x86::X86Operand,
    is_control_flow: bool,
    operands: &mut Vec<crate::insn::Operand>,
    target: &mut Option<u64>,
) {
    use capstone::arch::x86::X86OperandType;

    match op.op_type {
        X86OperandType::Reg(reg) => {
            if let Some(reg) = opt_reg(reg) {
                operands.push(crate::insn::Operand::Reg(reg));
            }
        }
        X86OperandType::Imm(value) => {
            operands.push(crate::insn::Operand::Imm(value));
            // 直接跳转/调用的目标就在立即数里
            if is_control_flow {
                *target = Some(value as u64);
            }
        }
        X86OperandType::Mem(mem) => {
            let base = opt_reg(mem.base());

            // RIP 相对操作数（`mov rax, [rip+0x10]`、`lea rcx, [rip+...]`）
            // 必须转成 `PcRelative` 而不是普通 `Mem`。
            //
            // 这个分支长期缺失，后果是一整条链路静默失效：x86 上
            // `Operand::PcRelative` 从来没被产出过，于是
            // `xrefs_of` 的数据引用分支永远命中不了 —— 交叉引用里
            // 看不到任何全局变量访问，字符串引用聚合也一条都匹配不到
            // （ntdll 上有 6487 条字符串，却"没有一条被引用"）。
            //
            // 它不报错、不 panic，只是安静地少给数据，
            // 所以只能靠"用真实目标验证结论是否合理"来发现。
            //
            // RIP 在 capstone 里的编号是 41；`disp` 是**相对位移**
            // （不是解析后的地址），与 `PcRelative` 的语义一致。
            if base == Some(crate::insn::RegId(RIP_REG_ID)) {
                operands.push(crate::insn::Operand::PcRelative(mem.disp()));
                return;
            }

            operands.push(crate::insn::Operand::Mem(crate::insn::MemRef {
                base,
                index: opt_reg(mem.index()),
                scale: mem.scale() as u8,
                disp: mem.disp(),
                size: op.size,
                write: false,
            }));
        }
        _ => {}
    }
}

/// arm64 操作数。
fn convert_arm64_operand(
    op: &capstone::arch::arm64::Arm64Operand,
    is_control_flow: bool,
    operands: &mut Vec<crate::insn::Operand>,
    target: &mut Option<u64>,
) {
    use capstone::arch::arm64::Arm64OperandType;

    match op.op_type {
        Arm64OperandType::Reg(reg) => {
            let Some(reg) = opt_reg(reg) else { return };

            // 移位/扩展修饰必须一起带出来 —— 见 `Operand::Shifted` 的说明。
            //
            // capstone 把修饰拆成**两个独立字段**：`shift`（LSL/LSR/ASR/ROR）
            // 与 `ext`（UXTB…SXTX）。两者互斥，但都要检查。
            if let Some((kind, amount)) = arm64_modifier(op) {
                operands.push(crate::insn::Operand::Shifted { reg, kind, amount });
                return;
            }

            operands.push(crate::insn::Operand::Reg(reg));
        }
        Arm64OperandType::Imm(value) => {
            operands.push(crate::insn::Operand::Imm(value));
            if is_control_flow {
                *target = Some(value as u64);
            }
        }
        Arm64OperandType::Mem(mem) => {
            operands.push(crate::insn::Operand::Mem(crate::insn::MemRef {
                base: opt_reg(mem.base()),
                index: None,
                scale: 1,
                disp: i64::from(mem.disp()),
                size: 0,
                write: false,
            }));
        }
        _ => {}
    }
}

/// 取 AArch64 操作数的移位/扩展修饰，返回（类型, 移位量）。
///
/// capstone 把它们放在两个字段里：`shift` 管逻辑/算术移位，
/// `ext` 管符号/零扩展。二者各自用 `*_INVALID` 表示"没有修饰"。
fn arm64_modifier(
    op: &capstone::arch::arm64::Arm64Operand,
) -> Option<(crate::insn::ShiftKind, u32)> {
    use crate::insn::ShiftKind;
    use capstone::arch::arm64::{Arm64Extender, Arm64Shift};

    // 先看移位字段。`Lsl(3)` 表示 `lsl #3`。
    match op.shift {
        Arm64Shift::Lsl(n) => return Some((ShiftKind::Lsl, n)),
        Arm64Shift::Lsr(n) => return Some((ShiftKind::Lsr, n)),
        Arm64Shift::Asr(n) => return Some((ShiftKind::Asr, n)),
        Arm64Shift::Ror(n) => return Some((ShiftKind::Ror, n)),
        // MSL（masking shift left）在 AArch64 汇编里写作 `lsl`；保留原样会让
        // 用户对着外部工具对不上，所以按 LLVM 的显示走 Lsl。
        Arm64Shift::Msl(n) => return Some((ShiftKind::Lsl, n)),
        // `Invalid` 不是错误，是"这条指令没有移位修饰"，继续看扩展字段。
        Arm64Shift::Invalid => {}
    }

    // 再看扩展字段。
    let kind = match op.ext {
        Arm64Extender::ARM64_EXT_UXTB => ShiftKind::Uxtb,
        Arm64Extender::ARM64_EXT_UXTH => ShiftKind::Uxth,
        Arm64Extender::ARM64_EXT_UXTW => ShiftKind::Uxtw,
        Arm64Extender::ARM64_EXT_UXTX => ShiftKind::Uxtx,
        Arm64Extender::ARM64_EXT_SXTB => ShiftKind::Sxtb,
        Arm64Extender::ARM64_EXT_SXTH => ShiftKind::Sxth,
        Arm64Extender::ARM64_EXT_SXTW => ShiftKind::Sxtw,
        Arm64Extender::ARM64_EXT_SXTX => ShiftKind::Sxtx,
        // `ARM64_EXT_INVALID` 与 `ARM64_EXT_*` 里将来的新值都落到这里。
        // 返回 `None` 就是**如实表示"没有可渲染的修饰"**；
        // 而不是硬编一个默认值假装认识。
        _ => return None,
    };
    Some((kind, 0))
}

/// arm（AArch32）操作数。
fn convert_arm_operand(
    op: &capstone::arch::arm::ArmOperand,
    is_control_flow: bool,
    operands: &mut Vec<crate::insn::Operand>,
    target: &mut Option<u64>,
) {
    use capstone::arch::arm::ArmOperandType;

    match op.op_type {
        ArmOperandType::Reg(reg) => {
            if let Some(reg) = opt_reg(reg) {
                operands.push(crate::insn::Operand::Reg(reg));
            }
        }
        ArmOperandType::Imm(value) => {
            // capstone 的 ARM 立即数是 i32；本项目内部一律用 i64
            operands.push(crate::insn::Operand::Imm(i64::from(value)));
            if is_control_flow {
                *target = Some(value as u64);
            }
        }
        _ => {}
    }
}

/// 粗略判断是否条件跳转。
///
/// **这是有意为之的近似**，不是最终实现：capstone 的 x86 后端不直接暴露
/// "这个 jmp 是否条件"。M3 构建 CFG 时会用更严格的方式（检查操作数个数与
/// 助记符前缀）替代。这里保守地倾向于"有条件"，因为**多给一个后继**比
/// **漏掉一个后继**安全得多 —— 后者会让 CFG 丢块。
fn is_conditional_jump(mnemonic: &str) -> bool {
    // 无条件跳转的助记符（x86: jmp；ARM64: b；ARM: b）
    !matches!(mnemonic, "jmp" | "b" | "b.w" | "j" | "br" | "bx")
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::insn::Operand;
    use crate::types::Endian;

    fn x64() -> ArchSpec {
        ArchSpec::from_arch(Arch::X86_64, Mode::M64, Endian::Little)
    }

    fn decoder() -> CapstoneDecoder {
        CapstoneDecoder::new(x64()).expect("x86_64 解码器")
    }

    #[test]
    fn rip_relative_memory_becomes_pc_relative_operand() {
        // lea rcx, [rip+0x1234] = 48 8d 0d 34 12 00 00，指令在 0x1000
        //
        // 这条路径曾经缺失：RIP 相对被当成普通 `Mem`，于是
        // x86 上 `Operand::PcRelative` 从未被产出，`xrefs_of` 的数据
        // 引用分支永远命中不了。xref 面板看不到任何全局变量访问，
        // 字符串引用聚合一条都匹配不到 —— 全部静默为空，不报错。
        let dec = decoder();
        let insn = dec
            .decode_one(&[0x48, 0x8d, 0x0d, 0x34, 0x12, 0x00, 0x00], 0x1000)
            .expect("解码 lea");
        let Some(Operand::PcRelative(disp)) = insn.operands.last() else {
            panic!("rip 相对应当产出 PcRelative，实际 {:?}", insn.operands);
        };
        assert_eq!(*disp, 0x1234, "PcRelative 存的是相对位移，不是绝对地址");
    }

    /// 普通内存操作数**不能**被误判成 PC 相对。
    #[test]
    fn ordinary_memory_stays_a_plain_mem_operand() {
        let dec = decoder();
        // 48 8B 43 10 = mov rax, [rbx+0x10]
        let insn = dec
            .decode_one(&[0x48, 0x8b, 0x43, 0x10], 0x1000)
            .expect("解码 mov");
        let Some(Operand::Mem(m)) = insn.operands.last() else {
            panic!("普通内存操作数应当仍是 Mem，实际 {:?}", insn.operands);
        };
        assert_eq!(m.disp, 0x10);
        assert_ne!(m.base.map(|r| r.0), Some(RIP_REG_ID), "rbx 不是 rip");
    }

    #[test]
    fn decodes_simple_nop() {
        let dec = decoder();
        let insn = dec.decode_one(&[0x90], 0x1000).expect("nop");
        assert_eq!(insn.addr, 0x1000);
        assert_eq!(insn.len, 1);
        assert_eq!(insn.flow, Flow::Fallthrough);
        assert!(insn.target.is_none());
    }

    #[test]
    fn decodes_call_with_direct_target() {
        // E8 00 00 00 00 = call +0，位于 0x1000，下一条是 0x1005 => 目标 0x1005。
        //
        // 注意：capstone 已经把相对位移解析成了**绝对目标地址**，
        // 我们不需要（也绝不能）再加一次 "下一条指令地址"。
        // 这一点由 `relative_targets_are_resolved_to_absolute` 固化。
        let dec = decoder();
        let insn = dec
            .decode_one(&[0xE8, 0x00, 0x00, 0x00, 0x00], 0x1000)
            .expect("call");
        assert_eq!(insn.len, 5);
        assert_eq!(insn.flow, Flow::Call);
        assert_eq!(insn.target, Some(0x1005));
        // call 有顺序后继（调用会返回）
        assert!(insn.flow.has_fallthrough());
    }

    #[test]
    fn decodes_unconditional_jump() {
        // E9 00 00 00 00 = jmp +0 -> 0x1005
        let dec = decoder();
        let insn = dec
            .decode_one(&[0xE9, 0x00, 0x00, 0x00, 0x00], 0x1000)
            .expect("jmp");
        assert_eq!(insn.flow, Flow::Branch { conditional: false });
        assert_eq!(insn.target, Some(0x1005));
        assert!(!insn.flow.has_fallthrough(), "无条件跳转没有顺序后继");
    }

    #[test]
    fn decodes_conditional_jump_with_two_successors() {
        // 74 05 = je +5 (0x1002 + 5 = 0x1007)
        let dec = decoder();
        let insn = dec.decode_one(&[0x74, 0x05], 0x1000).expect("je");
        assert_eq!(insn.len, 2);
        match insn.flow {
            Flow::Branch { conditional } => assert!(conditional, "je 应是条件跳转"),
            other => panic!("期望条件跳转，得到 {other:?}"),
        }
        assert_eq!(insn.target, Some(0x1007));
        assert!(insn.flow.has_fallthrough(), "条件跳转必须有顺序后继");
    }

    #[test]
    fn decodes_return() {
        let dec = decoder();
        let insn = dec.decode_one(&[0xC3], 0x1000).expect("ret");
        assert_eq!(insn.flow, Flow::Return);
        assert!(!insn.flow.has_fallthrough());
        assert!(insn.flow.ends_block());
    }

    #[test]
    fn rejects_invalid_bytes() {
        let dec = decoder();
        // 0x06 在 64 位模式下是无效编码（push es 只在 32 位有效）
        assert!(dec.decode_one(&[0x06], 0x1000).is_err());
    }

    #[test]
    fn empty_input_is_truncated() {
        let dec = decoder();
        assert_eq!(
            dec.decode_one(&[], 0x1000).unwrap_err(),
            DecodeError::Truncated
        );
    }

    #[test]
    fn truncated_instruction_is_an_error_not_a_guess() {
        let dec = decoder();
        // call rel32 缺一个字节
        let err = dec.decode_one(&[0xE8, 0x00, 0x00, 0x00], 0x1000);
        assert!(err.is_err(), "不完整的指令必须报错，不能猜长度");
    }

    #[test]
    fn reads_and_writes_registers() {
        // 48 89 d8 = mov rax, rbx  -> 读 rbx，写 rax
        let dec = decoder();
        let insn = dec.decode_one(&[0x48, 0x89, 0xD8], 0x1000).expect("mov");
        assert!(!insn.reads.is_empty(), "mov 应读取源寄存器");
        assert!(!insn.writes.is_empty(), "mov 应写入目标寄存器");
    }

    #[test]
    fn detects_indirect_jump_as_having_no_target() {
        // FF E0 = jmp rax（间接）
        let dec = decoder();
        let insn = dec.decode_one(&[0xFF, 0xE0], 0x1000).expect("jmp rax");
        assert!(matches!(insn.flow, Flow::Branch { .. }));
        assert!(insn.target.is_none(), "间接跳转没有静态目标");
    }

    /// 间接跳转**仍然是无条件跳转**，不能因为"目标未知"就标成条件跳转。
    ///
    /// 回归测试：这里曾经写成 `conditional: target.is_none() || is_conditional_jump(...)`，
    /// 把"目标未知"和"有条件"混成一个标志。后果有两层：
    ///   * `has_fallthrough()` 对一个根本不会往下走的 `jmp *rax` 返回 true，
    ///     等于凭空多给后继，CFG 会多出块；
    ///   * 导入桩识别（判据是 `conditional: false` 的间接跳转）一个都匹配不上，
    ///     实测让 mingw 静态 exe 的函数覆盖率卡在 92.21%。
    #[test]
    fn indirect_jump_is_unconditional_and_has_no_fallthrough() {
        let dec = decoder();
        for (bytes, what) in [
            (vec![0xFF, 0xE0], "jmp rax"),
            (vec![0xFF, 0x25, 0x00, 0x00, 0x00, 0x00], "jmp *(%rip)"),
        ] {
            let insn = dec.decode_one(&bytes, 0x1000).expect(what);
            assert_eq!(
                insn.flow,
                Flow::Branch { conditional: false },
                "{what} 是无条件跳转"
            );
            assert!(
                !insn.flow.has_fallthrough(),
                "{what} 没有顺序后继，不该多出一个后继"
            );
        }
    }

    #[test]
    fn decode_many_stops_at_first_error() {
        let dec = decoder();
        // nop, nop, 非法, nop
        let insns = dec.decode_many(&[0x90, 0x90, 0x06, 0x90], 0x1000, 10);
        assert_eq!(insns.len(), 2, "应在非法字节处停止，不跳过");
    }

    #[test]
    fn decode_many_respects_max() {
        let dec = decoder();
        let insns = dec.decode_many(&[0x90; 16], 0x1000, 5);
        assert_eq!(insns.len(), 5);
    }

    #[test]
    fn unsupported_arch_reports_clearly() {
        let spec = ArchSpec::from_arch(Arch::Wasm32, Mode::M32, Endian::Little);
        let err = CapstoneDecoder::new(spec).unwrap_err();
        assert!(matches!(err, BackendError::Unsupported { .. }));
        assert!(err.to_string().contains("没有可用的解码后端"));
    }

    #[test]
    fn arm64_decodes_aarch64_bytes() {
        // aarch64: ret = D65F03C0
        let spec = ArchSpec::from_arch(Arch::Aarch64, Mode::M64, Endian::Little);
        let dec = CapstoneDecoder::new(spec).expect("aarch64 解码器");
        let insn = dec
            .decode_one(&[0xC0, 0x03, 0x5F, 0xD6], 0x1000)
            .expect("ret");
        assert_eq!(insn.len, 4);
        assert_eq!(insn.flow, Flow::Return);
    }

    #[test]
    fn aarch64_branch_has_target() {
        // aarch64: b .+8  = 14000002
        let spec = ArchSpec::from_arch(Arch::Aarch64, Mode::M64, Endian::Little);
        let dec = CapstoneDecoder::new(spec).expect("aarch64 解码器");
        let insn = dec
            .decode_one(&[0x02, 0x00, 0x00, 0x14], 0x1000)
            .expect("b");
        assert!(matches!(insn.flow, Flow::Branch { .. }));
        assert_eq!(insn.target, Some(0x1008));
    }

    /// AArch64 的移位修饰必须被保留 —— 这是从真实样本里抓到的 bug。
    ///
    /// 样本 `elf-aarch64.exe` 的 `bf_loop` 里有一条
    /// `add w10, w8, w10, lsl #1`（= w8 + 2*w10）。曾经的转换只取
    /// `op.shift` 之外的部分，把它渲染成 `add w10, w8, w10`（= w8 + w10）。
    ///
    /// 这类 bug 的可怕之处在于**它不会让任何测试变红**：
    /// 输出语法完全正确、看起来像一条正常指令，语义却错了。
    /// 只有把真实样本的输出与 `llvm-objdump` 逐条对照才会暴露。
    ///
    /// 字节 `0b0a050a` = `add w10, w8, w10, lsl #1`（小端存放）。
    #[test]
    fn aarch64_shift_modifier_is_preserved() {
        let spec = ArchSpec::from_arch(Arch::Aarch64, Mode::M64, Endian::Little);
        let dec = CapstoneDecoder::new(spec).expect("aarch64 解码器");
        let insn = dec
            .decode_one(&[0x0a, 0x05, 0x0a, 0x0b], 0x210278)
            .expect("add 带 lsl");

        let shifted = insn
            .operands
            .iter()
            .find_map(|op| match op {
                crate::insn::Operand::Shifted { kind, amount, .. } => Some((*kind, *amount)),
                _ => None,
            })
            .expect(
                "add w10, w8, w10, lsl #1 必须解析出 Shifted 操作数；\
                 拿不到就说明移位在解码期被丢掉了（会渲染成语义错误的指令）",
            );

        assert_eq!(shifted.0, crate::insn::ShiftKind::Lsl);
        assert_eq!(shifted.1, 1, "移位量应是 1（lsl #1）");
    }

    /// 没有移位修饰的普通寄存器指令**不应**被误标成 `Shifted`。
    ///
    /// 反向确认：上一条测试证明"有修饰时能拿到"，这条证明"没修饰时不硬造"。
    /// 少了这条，一个"把所有寄存器都当 Shifted"的实现也能过。
    #[test]
    fn aarch64_plain_register_is_not_marked_shifted() {
        let spec = ArchSpec::from_arch(Arch::Aarch64, Mode::M64, Endian::Little);
        let dec = CapstoneDecoder::new(spec).expect("aarch64 解码器");
        // 0b000020 = add w0, w1, w0（无移位）
        let insn = dec
            .decode_one(&[0x20, 0x00, 0x00, 0x0b], 0x21025c)
            .expect("add 无移位");

        assert!(
            insn.operands
                .iter()
                .any(|op| matches!(op, crate::insn::Operand::Reg(_))),
            "无修饰的寄存器应保持 Reg：{:?}",
            insn.operands
        );
        assert!(
            !insn
                .operands
                .iter()
                .any(|op| matches!(op, crate::insn::Operand::Shifted { .. })),
            "没有移位就不该出现 Shifted（不能硬造修饰）：{:?}",
            insn.operands
        );
    }

    /// AArch64 的移位修饰必须渲染出来（端到端：解码 → 文本）。
    ///
    /// 这条盯的是渲染层：即使解码层保住了修饰，渲染若不认识 `Shifted`
    /// 也会把它吞掉，输出照样是错的。
    #[test]
    fn aarch64_shift_modifier_is_rendered() {
        let spec = ArchSpec::from_arch(Arch::Aarch64, Mode::M64, Endian::Little);
        let dec = CapstoneDecoder::new(spec).expect("aarch64 解码器");
        let insn = dec
            .decode_one(&[0x0a, 0x05, 0x0a, 0x0b], 0x210278)
            .expect("add 带 lsl");
        let text = crate::render::format_insn(&dec, &insn);

        // 与 llvm-objdump 的输出对齐：`add w10, w8, w10, lsl #1`
        assert!(
            text.contains("lsl #1"),
            "渲染结果必须带 `lsl #1`，实际：{text:?}\n\
             （丢掉移位会让这条指令看起来对、算得不对）"
        );
    }

    /// AArch64 条件分支必须带条件码 —— 第二个从真实样本里抓到的 bug。
    ///
    /// `b.lt` 与 `b` 的 capstone `InsnId` **相同**，条件在编码的 cc 字段里。
    /// 只用 id 查助记符会得到裸 `b`，于是条件跳转被显示成无条件跳转：
    /// 读者会以为执行流一定跳走，实际是"条件为假就往下走"。
    ///
    /// 字节 `6b010054` = `b.lt 0x210294`（小端存放）。
    #[test]
    fn aarch64_conditional_branch_carries_condition() {
        let spec = ArchSpec::from_arch(Arch::Aarch64, Mode::M64, Endian::Little);
        let dec = CapstoneDecoder::new(spec).expect("aarch64 解码器");
        let insn = dec
            .decode_one(&[0x6b, 0x01, 0x00, 0x54], 0x210268)
            .expect("b.lt");

        assert_eq!(
            insn.condition,
            Some(crate::insn::ConditionCode::SignedLessThan),
            "b.lt 必须解析出 LT 条件码；拿到 None 说明条件在解码期被丢了"
        );
        assert!(
            matches!(insn.flow, Flow::Branch { conditional: true }),
            "条件分支必须同时有两个后继：{:?}",
            insn.flow
        );

        let text = crate::render::format_insn(&dec, &insn);
        assert!(
            text.starts_with("b.lt"),
            "渲染必须写成 `b.lt`（与 llvm-objdump 一致），实际：{text:?}"
        );
    }

    /// 无条件分支**不该**被加上条件后缀。
    ///
    /// 反向确认：上一条证明"有条件时能写出来"，这条证明"没条件时不硬造"。
    /// 少了它，一个"给所有分支都追加 .al"的实现也能过。
    #[test]
    fn aarch64_unconditional_branch_has_no_condition_suffix() {
        let spec = ArchSpec::from_arch(Arch::Aarch64, Mode::M64, Endian::Little);
        let dec = CapstoneDecoder::new(spec).expect("aarch64 解码器");
        // 14000011 = b 0x21029c（无条件）
        let insn = dec
            .decode_one(&[0x11, 0x00, 0x00, 0x14], 0x210258)
            .expect("b");

        // AL 可能来自编码，但它是"无条件"的意思，渲染时必须省略
        if let Some(cc) = insn.condition {
            assert!(
                !cc.is_meaningful(),
                "无条件 b 不该带出有意义的条件码：{cc:?}"
            );
        }
        let text = crate::render::format_insn(&dec, &insn);
        assert_eq!(
            text, "b 0x21029c",
            "无条件跳转必须渲染成裸 `b`，不能有 `.al` 之类后缀"
        );
    }

    /// x86 的条件跳转不依赖 cc 字段：条件在助记符里（`je`/`jl`…）。
    /// 这条确认我们没有把 ARM 的处理方式错误地套到 x86 上。
    #[test]
    fn x86_conditional_jump_keeps_its_own_mnemonic() {
        let dec = decoder();
        // 74 05 = je +5
        let insn = dec.decode_one(&[0x74, 0x05], 0x1000).expect("je");
        let text = crate::render::format_insn(&dec, &insn);
        assert!(
            text.starts_with("je"),
            "x86 条件跳转的条件在助记符里，不应被改写：{text:?}"
        );
        assert!(
            !text.contains("jmp."),
            "不该给 x86 助记符加 ARM 风格的 `.cc` 后缀：{text:?}"
        );
    }

    #[test]
    fn relative_targets_are_resolved_to_absolute() {
        // 固化"capstone 给的是绝对目标"这一事实：如果将来换了后端
        // （D3 决策），这里会立刻失败，提醒适配层做转换。
        let dec = decoder();
        // call rel32=0x10 at 0x1000 => 0x1000 + 5 + 0x10 = 0x1015
        let call = dec
            .decode_one(&[0xE8, 0x10, 0x00, 0x00, 0x00], 0x1000)
            .expect("call");
        assert_eq!(call.target, Some(0x1015), "相对目标应已解析为绝对地址");
        // je rel8=5 at 0x1000 => 0x1000 + 2 + 5 = 0x1007
        let je = dec.decode_one(&[0x74, 0x05], 0x1000).expect("je");
        assert_eq!(je.target, Some(0x1007));
    }

    #[test]
    fn decoder_is_usable_across_threads() {
        // 扫描是 rayon 并行的：同一个解码器必须能被多线程同时使用。
        // 这里用 std::thread 而不是 rayon —— bitflip-arch 不依赖 rayon，
        // 而本测试要验证的正是"跨线程共享同一个解码器"这件事本身。
        let dec = std::sync::Arc::new(decoder());
        let handles: Vec<_> = (0..8)
            .map(|_| {
                let dec = std::sync::Arc::clone(&dec);
                std::thread::spawn(move || dec.decode_many(&[0x90; 8], 0x1000, 8).len())
            })
            .collect();
        let results: Vec<usize> = handles
            .into_iter()
            .map(|h| h.join().expect("线程应正常结束"))
            .collect();
        assert!(
            results.iter().all(|c| *c == 8),
            "并行解码结果不一致: {results:?}"
        );
    }

    #[test]
    fn conditional_jump_detection_is_conservative() {
        // 宁可多给后继，也不要漏
        assert!(!is_conditional_jump("jmp"));
        assert!(is_conditional_jump("je"));
        assert!(is_conditional_jump("jne"));
        assert!(is_conditional_jump("jl"));
    }
}
