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
    Ppc(capstone::arch::ppc::ArchMode),
}

/// 把 [`ArchSpec`] 映射成 capstone 的架构/模式。
///
/// 返回 `None` 表示 capstone 没有对应后端 —— 调用方据此返回
/// [`DecodeError::Unsupported`]，而不是猜一个近似架构去解码
/// （用 x86 解码 ARM 字节会得到"看起来成功"的垃圾）。
///
/// ppc 的三种 capstone 模式是 `Mode32` / `Mode64` / `Qpx`（QPX 是 POWER
/// 浮点扩展，不是位宽）。本仓库只按 32/64 位映射；QPX **不**自动开启：
/// 它会把部分浮点指令解释成另一套语义，而对象头里没有任何字段说"这段代码
/// 用 QPX"。要它应当是用户的显式选择，不是解析器的猜测。
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
        // ppc 只有一种"32 位"和一种"64 位"模式；Thumb 这类跨架构模式对 ppc
        // 没有意义，落下去就是"用错模式解"——所以不兜底，让它变成 Unsupported。
        (Arch::PowerPc, Mode::M32) => CsTarget::Ppc(capstone::arch::ppc::ArchMode::Mode32),
        (Arch::PowerPc64, Mode::M64) => CsTarget::Ppc(capstone::arch::ppc::ArchMode::Mode64),
        _ => return None,
    })
}

/// 本项目的端序 → capstone 的端序。
///
/// 这个转换必须存在，而不是在 `build_engine` 里两处各写一次 `match`：
/// 后者正是"哪个架构要显式传端序"这件事散落的地方。端序知识属于 arch 层
/// （见 `Arch::preferred_endian` 与 `scripts/check-arch-layering.ps1`）。
const fn cs_endian(endian: crate::types::Endian) -> capstone::Endian {
    match endian {
        crate::types::Endian::Little => capstone::Endian::Little,
        crate::types::Endian::Big => capstone::Endian::Big,
    }
}

/// 该架构在 capstone 里的寄存器编号**上界（不含）**。
///
/// 数值来自 capstone 绑定的 `*_REG_ENDING` 哨兵常量（`capstone-sys` 的
/// bindgen 输出，`pre_generated/capstone.rs`），不是本项目自己数出来的：
/// 数少了会让后面的寄存器名静默解析失败，而那种失败**不报错**，
/// 只表现为"参数推断没有结论"（ppc 上就踩过，见
/// [`CapstoneDecoder::register_id`] 的说明）。
///
/// 未映射的架构返回 0 —— 扫描范围 `1..0` 是空区间，于是解析失败而不是猜。
fn reg_id_limit(arch: Arch) -> u16 {
    let limit: u32 = match arch {
        Arch::X86 | Arch::X86_64 => capstone::arch::x86::X86Reg::X86_REG_ENDING,
        Arch::Aarch64 => capstone::arch::arm64::Arm64Reg::ARM64_REG_ENDING,
        Arch::Arm => capstone::arch::arm::ArmReg::ARM_REG_ENDING,
        Arch::Riscv32 | Arch::Riscv64 => capstone::arch::riscv::RiscVReg::RISCV_REG_ENDING,
        Arch::Mips | Arch::Mips64 => capstone::arch::mips::MipsReg::MIPS_REG_ENDING,
        Arch::PowerPc | Arch::PowerPc64 => capstone::arch::ppc::PpcReg::PPC_REG_ENDING,
        _ => 0,
    };
    u16::try_from(limit).unwrap_or(u16::MAX)
}

/// 构造一个 capstone 引擎。
///
/// 每个架构走自己的 builder 链（capstone 的类型系统要求如此）。
/// 共同点是都开 `detail(true)` —— 没有它就拿不到"读了哪些寄存器"
/// "内存操作数是什么"，而这些正是结构化指令模型必须有的字段。
///
/// # 端序
///
/// capstone 的 builder 只给**同时支持两种端序**的架构提供 `.endian()` 方法
/// （`third-party/capstone/src/arch/mod.rs` 的 `both_endian` 标志：arm /
/// arm64 / mips / ppc / riscv 有，x86 没有 —— x86 的端序是固定的）。
/// 所以这里**按架构把这个值传下去**，而不是永远吃 capstone 的默认小端。
///
/// 早先这里从不传端序：对小端架构没有区别，对 ppc 就是致命的 —— ppc 的
/// 指令编码是大端，按小端解出来的不是"解不出来"，而是**另一条合法指令**，
/// 属于最难发现的错误（输出看起来完全正常）。这也是 `Arch::preferred_endian`
/// 对 ppc 返回大端的原因。
fn build_engine(spec: ArchSpec) -> Result<Capstone, BackendError> {
    use capstone::arch::{BuildsCapstone, BuildsCapstoneEndian, BuildsCapstoneSyntax};

    let target = cs_target_for(spec).ok_or(BackendError::Unsupported {
        arch: spec.arch,
        mode: spec.mode,
    })?;
    let endian = cs_endian(spec.endian);

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
            .endian(endian)
            .detail(true)
            .build(),
        CsTarget::Arm(mode) => Capstone::new()
            .arm()
            .mode(mode)
            .endian(endian)
            .detail(true)
            .build(),
        CsTarget::Riscv(mode) => Capstone::new()
            .riscv()
            .mode(mode)
            .endian(endian)
            .detail(true)
            .build(),
        CsTarget::Mips(mode) => Capstone::new()
            .mips()
            .mode(mode)
            .endian(endian)
            .detail(true)
            .build(),
        CsTarget::Ppc(mode) => Capstone::new()
            .ppc()
            .mode(mode)
            .endian(endian)
            .detail(true)
            .build(),
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
engine_slot!(ENGINE_PPC);
engine_slot!(ENGINE_PPC64);

/// 选定架构对应的线程局部槽位。
///
/// 未知架构落到 x86_64 槽位只是为了避免 `Option`；真正的拒绝发生在
/// [`build_engine`]，那里会返回 `Unsupported`。
///
/// 槽位按**架构**而不是按"架构 + 模式/端序"分：同一架构的不同模式共用
/// 一个槽位，而槽位里缓存的是**第一次**构造的引擎（`ThreadEngines::with`
/// 只在 `None` 时构造）。所以一个线程不可以交替用两个 spec 解码 ——
/// 现状是安全的，因为 `CapstoneDecoder` 的 `spec` 在构造时就固定了，
/// 而槽位只被该解码器按自己的 spec 填充。
fn slot_for(arch: Arch) -> &'static std::thread::LocalKey<RefCell<Option<Capstone>>> {
    match arch {
        Arch::X86 => &ENGINE_X86,
        Arch::Aarch64 => &ENGINE_AARCH64,
        Arch::Arm => &ENGINE_ARM,
        Arch::Riscv32 => &ENGINE_RISCV32,
        Arch::Riscv64 => &ENGINE_RISCV64,
        Arch::Mips => &ENGINE_MIPS,
        Arch::Mips64 => &ENGINE_MIPS64,
        // ppc 与 ppc64 各占一个槽位：两者的 capstone 引擎是**不同的后台**
        // （32/64 位寄存器与指令表），共用一个槽位会让先构造的那个把
        // 另一个解错。
        Arch::PowerPc => &ENGINE_PPC,
        Arch::PowerPc64 => &ENGINE_PPC64,
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
    ///
    /// # 编号是**稀疏**的（ppc 上踩到）
    ///
    /// 早先这里的循环把"第一个查不到名字的编号"当成表尾直接返回 `None`。
    /// 这对 x86/arm/arm64/mips/riscv 是成立的（它们的编号确实从 1 连续），
    /// 但 capstone 的 ppc 寄存器表有**空洞**：编号 1、4、7、11、53、119
    /// 是空的（实测，见 `ppc_register_ids_are_sparse`）。于是 ppc 上
    /// 第 1 个编号就返回 `None`，**所有** ppc 寄存器名都解析不出来 ——
    /// 后果是 ppc 的参数标注静默失效（ABI 表在、名字查不到 → 空结论）。
    ///
    /// 现在改成扫到该架构的**真实上界**（capstone 绑定的 `*_REG_ENDING`）
    /// 而不是撞到第一个空洞就收工：上界是精确值，不是猜的魔法数字。
    #[must_use]
    pub fn register_id(spec: ArchSpec, name: &str) -> Option<RegId> {
        let decoder = CapstoneDecoder::new(spec).ok()?;
        let limit = reg_id_limit(spec.arch);
        decoder.with_engine(|cs| {
            // 扫到上界为止，**不**在第一个空洞处收工（见上面的说明）。
            (1..limit).find_map(|index| {
                let found = cs.reg_name(capstone::RegId(index))?;
                found.eq_ignore_ascii_case(name).then_some(RegId(index))
            })
        })
    }

    /// 取一条指令的助记符**名字**（`"push"`、`"sub"`、`"stp"`…）。
    ///
    /// # 为什么分析层需要名字而不是编号
    ///
    /// `DecodedInsn::mnemonic` 是 capstone 的 `MnemonicId`，它的数值
    /// 跨 capstone 版本会变，且不构成稳定契约。分析层要判断"这条指令
    /// 是不是 `sub`"时，只能靠名字。
    ///
    /// 反过来，把 `MnemonicId` 硬编码成常量表是**更糟**的做法：版本一升，
    /// 判断会静默错位 —— 帧大小算错却不报错。所以这里向真实后端要名字，
    /// 由分析层做字符串比较。名字查不到返回 `None`，调用方据此停下并
    /// 记一条降级说明，而不是猜。
    ///
    /// 一次调用是 O(1) 的哈希查找，但涉及 FFI；前导扫描只在函数开头
    /// 的少数几条指令上调用，开销可忽略。
    #[must_use]
    pub fn mnemonic_name(&self, insn: &DecodedInsn) -> Option<String> {
        self.with_engine(|cs| cs.insn_name(capstone::InsnId(insn.mnemonic.0)))
    }

    /// 取一个寄存器编号的**名字**（`RegId(37)` → `"rbx"`）。
    ///
    /// # 为什么不能只靠 ABI 表
    ///
    /// [`crate::AbiSpec`] 里只有参数寄存器、返回寄存器、栈指针、帧指针和
    /// 被调用者保存寄存器这几组**名字**，而且它是"给人看的契约"。
    /// 但前导扫描会遇到表外的寄存器 —— 典型例子是 AArch64 的
    /// `stp x29, x30, [sp, #-16]!`：`x30` 是链接寄存器，不在
    /// `callee_saved_names` 里（按 AAPCS64，x19–x28 才是被调用者保存）。
    ///
    /// 遇到表外寄存器时，要么报一个 `reg#30` 这样的假名（CLAUDE.md §7
    /// 禁止），要么向真实后端问。这里选后者。
    ///
    /// 查不到返回 `None`，调用方如实显示"未识别寄存器"。
    #[must_use]
    pub fn register_name(&self, reg: RegId) -> Option<String> {
        self.with_engine(|cs| cs.reg_name(capstone::RegId(reg.0)))
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

    // 助记符字符串下面要用两处：判断"这条跳转是否有两个后继"，以及区分
    // aarch64 的 `ARM64_OP_SYS` 那个**一物两用**的字段（见下）。
    // 只取一次，避免两处各判一遍不一致。
    let mnemonic_str = insn.mnemonic().unwrap_or("");

    // ppc 的**返回/间接调用**只能靠助记符补：capstone 的 ppc 后端不产出
    // `CS_GRP_RET`（`grep -r CS_GRP_RET arch/PowerPC/` 在 capstone 的 C 源码里
    // 是空的），`blr` / `bctrl` / `bctr` 一律只带 `CS_GRP_JUMP`。照组的结论：
    // `blr`（返回）会被当成"条件分支"多出一个顺序后继，`bctrl`（间接调用）
    // 会被当成跳转而丢掉调用关系 —— ppc 的 CFG 与调用图会整体错。
    //
    // 这是本文件里**唯一**按助记符改流程的地方，理由是后端缺组信息（有
    // 上面那条 grep 证据），而不是"懒得查组"。其余架构仍然只认组。
    if matches!(arch, Arch::PowerPc | Arch::PowerPc64) {
        match mnemonic_str {
            "blr" => {
                is_ret = true;
                is_jump = false;
            }
            // `bctrl` = 经 CTR 的调用（`bctrl` 会写 LR），所以是 Call 而不是 Jump。
            "bctrl" => {
                is_call = true;
                is_jump = false;
            }
            _ => {}
        }
    }

    // MRS/MSR 的**系统寄存器编码**与 IC/DC/AT/TLBI 的**子操作**共用 capstone
    // 的 `ARM64_OP_SYS` 一个字段（C 端一物两用：`printMRSSystemRegister` 与
    // `printMSRSystemRegister` 都往上写原始编码，见 third-party/capstone/PATCH.md）。
    // 两种载荷的取值范围不重叠，但**不靠取值范围猜** —— 靠指令本身区分：
    // 只有 `mrs` / `msr` 的 `Sys` 载荷是系统寄存器编码。
    let sys_holds_sysreg = matches!(mnemonic_str, "mrs" | "msr");

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
                convert_arm64_operand(
                    &op,
                    is_jump || is_call,
                    sys_holds_sysreg,
                    &mut operands,
                    &mut target,
                );
            }
            ArchOperand::ArmOperand(op) => {
                convert_arm_operand(&op, is_jump || is_call, &mut operands, &mut target);
            }
            ArchOperand::PpcOperand(op) => {
                convert_ppc_operand(&op, is_jump || is_call, &mut operands, &mut target);
            }
            // 其余架构（RISC-V / MIPS）在 M2 先不提取操作数细节：
            // 宁可少给字段，也不要给错的字段。流程语义仍然是对的。
            _ => {}
        }
    }

    // capstone 的 AArch64 detail 不给 `prfm` / `prfum` 的预取操作数
    // （证据见 `Operand::Prefetch` 与 docs/research/capstone-prefetch-operand.md），
    // 但那个操作数位置确实存在，而且是**第一个**（`prfm <prfop>, <地址>`）。
    // 这里如实补一个"位置在、值拿不到"的占位 —— 不补的话输出是 `prfm [x1]`，
    // 少了一个操作数却读起来像一条完整指令（CLAUDE.md §7）。
    //
    // 只在 capstone 没给值时才补，所以将来它补上这个字段时这里不会重复。
    if matches!(mnemonic_str, "prfm" | "prfum")
        && !operands
            .iter()
            .any(|op| matches!(op, crate::insn::Operand::Prefetch(_)))
    {
        operands.insert(0, crate::insn::Operand::Prefetch(None));
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
            conditional: is_conditional_jump(mnemonic_str),
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
    let condition = convert_condition(detail, arch, mnemonic_str);

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
fn convert_condition(
    detail: &InsnDetail<'_>,
    arch: Arch,
    mnemonic_str: &str,
) -> Option<crate::insn::ConditionCode> {
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
        // x86 不靠 detail 取条件码：capstone 0.14 的 x86 detail 没有对通用 `jcc` 暴露条件码
        // （只有 SSE/AVX/XOP 的 cc 访问器）。x86 的条件跳转有**各自独立的助记符**
        // （`je`/`jne`/`jl`…），名字本身已经带了条件 —— 从助记符如实映射，不猜。
        // 奇偶条件（`jp`/`jnp` 等）在 [`ConditionCode`] 里没有对应项，返回 `None`（如实保守）。
        Arch::X86 | Arch::X86_64 => x86_condition_from_mnemonic(mnemonic_str),
        // AArch32 的条件码在指令编码的高 4 位里，capstone 目前没有通过
        // 统一接口暴露。**如实返回 `None`**（不猜），CFG 仍然是对的
        // （靠 `Flow::Branch { conditional }`），只是文本上会显示成裸 `b`。
        // 这一条写在这里是为了让它可被找到，而不是悄悄漏掉。
        _ => None,
    }
}

/// 从 x86 条件跳转助记符映射到 [`ConditionCode`]。
///
/// 只认标准 `jcc` 助记符；同义写法（`jz`/`jne`/`jnz`…）归一到同一条件。
/// 奇偶类（`jp`/`jpe`/`jnp`/`jpo`）在 [`ConditionCode`] 里没有对应项 —— 返回 `None`，
/// 由上层如实显示"条件未知"，而不是硬凑一个近似条件（§7：不猜）。
fn x86_condition_from_mnemonic(mnemonic: &str) -> Option<crate::insn::ConditionCode> {
    use crate::insn::ConditionCode;
    Some(match mnemonic {
        "je" | "jz" => ConditionCode::Equal,
        "jne" | "jnz" => ConditionCode::NotEqual,
        // CF=1：无符号"低于"（比借位/进位清除）。
        "jb" | "jnae" | "jc" => ConditionCode::CarryClear,
        // CF=0：无符号"不低于"（高于或相等）。
        "jae" | "jnb" | "jnc" => ConditionCode::CarrySet,
        "jbe" | "jna" => ConditionCode::UnsignedLowerOrSame,
        "ja" | "jnbe" => ConditionCode::UnsignedHigher,
        "jl" | "jnge" => ConditionCode::SignedLessThan,
        "jge" | "jnl" => ConditionCode::SignedGreaterEqual,
        "jle" | "jng" => ConditionCode::SignedLessOrEqual,
        "jg" | "jnle" => ConditionCode::SignedGreaterThan,
        "js" => ConditionCode::Minus,
        "jns" => ConditionCode::Plus,
        "jo" => ConditionCode::Overflow,
        "jno" => ConditionCode::NoOverflow,
        // 奇偶条件：无对应 ConditionCode → 不猜。
        _ => return None,
    })
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

/// ppc 操作数。
///
/// # 这个 `match` 是**穷尽**的（没有 `_` 兜底）
///
/// 与 arm64 的理由相同：`_ => {}` 会让"capstone 新增了操作数类型"变成
/// 静默丢字段，而丢字段的反汇编**看起来是一条完整的指令**（CLAUDE.md §7）。
///
/// # ppc 的 detail 只给三种类型
///
/// `third-party/capstone` 的 C 端（`capstone/arch/PowerPC/PPCInstPrinter.c`）
/// 只写 `PPC_OP_REG` / `PPC_OP_IMM` / `PPC_OP_MEM`，`PPC_OP_CRX` 一次都没有
/// （`PPC_OP_CRX` 只出现在 `ppc.h` 的枚举与 `cstool` 里）。所以 `Crx`
/// 这条分支现实中走不到 —— 但它仍然显式写出来而不是靠 `_` 兜住，理由见上。
///
/// # 为什么 `MemRef::size` 恒为 0
///
/// capstone 的 ppc 内存操作数（`ppc_op_mem`）只有 `base` 与 `disp` 两个字段，
/// **没有**宽度信息（x86 的 `X86Operand` 有 `size`）。宽度要靠助记符
/// （`lwz` = 4 字节、`ld` = 8 字节）推断，而"按助记符前缀猜宽度"是那种
/// 猜错了也不报错的推断。所以这里如实给 0（未知），由渲染层与消费方
/// 自己判断要不要用它。
fn convert_ppc_operand(
    op: &capstone::arch::ppc::PpcOperand,
    is_control_flow: bool,
    operands: &mut Vec<crate::insn::Operand>,
    target: &mut Option<u64>,
) {
    use capstone::arch::ppc::PpcOperand;

    match op {
        PpcOperand::Reg(reg) => {
            if let Some(reg) = opt_reg(*reg) {
                operands.push(crate::insn::Operand::Reg(reg));
            }
        }
        PpcOperand::Imm(value) => {
            operands.push(crate::insn::Operand::Imm(*value));
            // 直接分支/调用的目标就在立即数里（capstone 已经算成**绝对地址**，
            // 与 arm64 的 `bl #0x…` 一致；不是相对位移，所以不做换算）。
            if is_control_flow {
                *target = Some(*value as u64);
            }
        }
        PpcOperand::Mem(mem) => {
            // ppc 的内存操作数没有 index/scale（`lwzx r3, r4, r5` 的索引寄存器
            // 是**独立的通用寄存器操作数**，不是一个带 scale 的寻址模式），
            // 所以这里给 `index: None` 是事实，不是漏了。
            operands.push(crate::insn::Operand::Mem(crate::insn::MemRef {
                base: opt_reg(mem.base()),
                index: None,
                scale: 0,
                disp: i64::from(mem.disp()),
                size: 0,
                write: false,
                index_extend: None,
            }));
        }
        // 见函数文档：本版本 capstone 的 ppc 打印器从不产出 `CRX`。
        // 真出现时**不猜**：`4*cr0+eq` 这种条件寄存器字段没有对应的
        // `Operand` 变体，塞成寄存器会显示成 `bt cr0` —— 语法正确、语义
        // 不同的另一种指令。留下一条告警让它可被发现，而不是静默丢。
        PpcOperand::Crx(_) => {
            tracing::warn!("capstone 产出了 PPC_OP_CRX 操作数，本版本没有建模，该操作数未显示");
        }
        PpcOperand::Invalid => {}
    }
}

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
                // x86 的 SIB 只给索引一个比例，没有"扩展"这个概念。
                index_extend: None,
            }));
        }
        _ => {}
    }
}

/// arm64 操作数。
///
/// ## 这个 `match` 是**穷尽**的（没有 `_` 兜底），这是有意的
///
/// 之前这里是 `_ => {}`，把 10 类操作数**静默丢掉**：系统寄存器、PState、
/// 屏障选项、预取操作、IC/DC/AT/TLBI 子操作、浮点立即数、C-IMM、SVCR、
/// SME 索引。后果不是"少了个字段"，而是**输出一条不存在的指令**：
/// `mrs x19, TPIDR_EL0` 显示成 `mrs x19`，`msr TPIDR_EL0, x19` 显示成
/// `msr x19` —— 后者语法正确、语义完全不同，读者完全看不出少了东西
/// （CLAUDE.md §7：降级要写在界面上）。
///
/// 去掉兜底之后，capstone 将来新增操作数类型会变成**编译错误**，而不是
/// 又一次静默丢失。这比"记得回来补"可靠。
///
/// `sys_holds_sysreg` 用来解开 `ARM64_OP_SYS` 的一物两用，见 `convert`。
fn convert_arm64_operand(
    op: &capstone::arch::arm64::Arm64Operand,
    is_control_flow: bool,
    sys_holds_sysreg: bool,
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
            // 索引寄存器必须带出来。
            //
            // 这里长期写着 `index: None`，把索引**整个丢掉**。真实目标里
            // 76% 的内存操作数带索引（195 KB 的 `libBugly_Native.so` 上，
            // llvm-objdump 报的 7467 个内存操作数里 5664 个带索引），
            // 于是 `ldr x0, [x1, x2]` 显示成 `ldr x0, [x1]` ——
            // 少一个寄存器，读起来却完全像一条正常指令（CLAUDE.md §7）。
            //
            // 修饰（`lsl #3` / `sxtw #2`）在 capstone 里挂在**操作数**上
            // （`op.shift` / `op.ext`），不在 `mem` 里，所以从 `op` 取。
            let (index, scale, index_extend) = arm64_index(&mem, op);

            operands.push(crate::insn::Operand::Mem(crate::insn::MemRef {
                base: opt_reg(mem.base()),
                index,
                scale,
                disp: i64::from(mem.disp()),
                size: 0,
                write: false,
                index_extend,
            }));
        }
        Arm64OperandType::Fp(value) => {
            // 浮点立即数。存**原始位**而不是 `f64`：`Operand` 要能 `Eq`，
            // 而 `f64` 不是（见 `Operand::FpImm` 的文档）。
            operands.push(crate::insn::Operand::FpImm(value.to_bits()));
        }
        Arm64OperandType::Cimm(value) => {
            // C-IMM 是"复杂立即数"（逻辑立即数等）。渲染上与普通立即数
            // 没有区别（都是 `#0x...`），所以归到同一个变体，不另立门户。
            operands.push(crate::insn::Operand::Imm(value));
            if is_control_flow {
                *target = Some(value as u64);
            }
        }
        // `RegMrs` / `RegMsr` 只在 capstone **没能**给这个编码命名时出现
        // （给得出名字时它走 `ARM64_OP_SYS`，见 third-party/capstone/PATCH.md）。
        // 两种情况载荷都是原始编码，所以合并处理。
        Arm64OperandType::RegMrs(raw) | Arm64OperandType::RegMsr(raw) => {
            operands.push(crate::insn::Operand::SysReg(crate::insn::SysRegRef { raw }));
        }
        Arm64OperandType::Pstate(field) => {
            if let Some(field) = pstate_field(field) {
                operands.push(crate::insn::Operand::Pstate(field));
            }
        }
        Arm64OperandType::Sys(value) => {
            let raw = value as u32;
            if sys_holds_sysreg {
                // `mrs` / `msr`：这个字段装的是**系统寄存器编码**。
                operands.push(crate::insn::Operand::SysReg(crate::insn::SysRegRef { raw }));
            } else {
                // `sys` / `dc` / `ic` / `at` / `tlbi`：装的是**子操作**。
                // 名字还没补，渲染层会如实打出未识别标记（不丢）。
                operands.push(crate::insn::Operand::SysOp(crate::insn::SysOpRef { raw }));
            }
        }
        Arm64OperandType::Prefetch(value) => {
            // 走到这里说明 capstone **确实**给了值（见 `Operand::Prefetch` 的
            // 说明：当前版本它从不给）。`None` 表示它报的是 `INVALID`，
            // 那也照样把位置留下 —— "这里有个操作数"本身就是信息。
            operands.push(crate::insn::Operand::Prefetch(prefetch_op(value)));
        }
        Arm64OperandType::Barrier(value) => {
            if let Some(option) = barrier_option(value) {
                operands.push(crate::insn::Operand::Barrier(option));
            }
        }
        Arm64OperandType::SVCR(value) => {
            if let Some(mode) = svcr_mode(value) {
                operands.push(crate::insn::Operand::Svcr(mode));
            }
        }
        // SME 的索引操作数：我们**不知道**它的 ARM 写法，所以如实标记，
        // 不去猜一个格式（§6.11）。ARMv9 SME 目前不会出现在 Android 目标里。
        Arm64OperandType::SMEIndex(_) => {
            operands.push(crate::insn::Operand::SmeIndex);
        }
        // capstone 明确说这个位置没有操作数 —— 没有东西可渲染。
        // 这不是丢数据，所以这里可以（也应该）什么都不做。
        Arm64OperandType::Invalid => {}
    }
}

/// PState 字段：capstone 的枚举 → 我们的。
///
/// 取值与拼写来自 capstone 的 `arm64_pstate`（`arm64.h` 里带显式数值），
/// 不是我们自己编号的。`match` 穷尽、无 `_` 兜底：capstone 加成员会编译报错。
///
/// 返回 `None` 表示 capstone 报的是 `INVALID` —— 那是"这里没有值"，
/// 不是"我们有值但丢了"。
fn pstate_field(field: capstone::arch::arm64::Arm64Pstate) -> Option<crate::insn::PstateField> {
    use crate::insn::PstateField as Ours;
    use capstone::arch::arm64::Arm64Pstate as Cs;

    Some(match field {
        Cs::ARM64_PSTATE_SPSEL => Ours::Spsel,
        Cs::ARM64_PSTATE_DAIFSET => Ours::DaifSet,
        Cs::ARM64_PSTATE_DAIFCLR => Ours::DaifClr,
        Cs::ARM64_PSTATE_PAN => Ours::Pan,
        Cs::ARM64_PSTATE_UAO => Ours::Uao,
        Cs::ARM64_PSTATE_DIT => Ours::Dit,
        Cs::ARM64_PSTATE_INVALID => return None,
    })
}

/// 内存屏障选项：capstone 的枚举 → 我们的。取值来自 `arm64_barrier_op`。
fn barrier_option(
    value: capstone::arch::arm64::Arm64BarrierOp,
) -> Option<crate::insn::BarrierOption> {
    use crate::insn::BarrierOption as Ours;
    use capstone::arch::arm64::Arm64BarrierOp as Cs;

    Some(match value {
        Cs::ARM64_BARRIER_OSHLD => Ours::Oshld,
        Cs::ARM64_BARRIER_OSHST => Ours::Oshst,
        Cs::ARM64_BARRIER_OSH => Ours::Osh,
        Cs::ARM64_BARRIER_NSHLD => Ours::Nshld,
        Cs::ARM64_BARRIER_NSHST => Ours::Nshst,
        Cs::ARM64_BARRIER_NSH => Ours::Nsh,
        Cs::ARM64_BARRIER_ISHLD => Ours::Ishld,
        Cs::ARM64_BARRIER_ISHST => Ours::Ishst,
        Cs::ARM64_BARRIER_ISH => Ours::Ish,
        Cs::ARM64_BARRIER_LD => Ours::Ld,
        Cs::ARM64_BARRIER_ST => Ours::St,
        Cs::ARM64_BARRIER_SY => Ours::Sy,
        Cs::ARM64_BARRIER_INVALID => return None,
    })
}

/// 预取操作：capstone 的枚举 → 我们的。取值来自 `arm64_prefetch_op`。
fn prefetch_op(value: capstone::arch::arm64::ArmPrefetchOp) -> Option<crate::insn::PrefetchOp> {
    use crate::insn::PrefetchOp as Ours;
    use capstone::arch::arm64::ArmPrefetchOp as Cs;

    Some(match value {
        Cs::ARM64_PRFM_PLDL1KEEP => Ours::Pldl1Keep,
        Cs::ARM64_PRFM_PLDL1STRM => Ours::Pldl1Strm,
        Cs::ARM64_PRFM_PLDL2KEEP => Ours::Pldl2Keep,
        Cs::ARM64_PRFM_PLDL2STRM => Ours::Pldl2Strm,
        Cs::ARM64_PRFM_PLDL3KEEP => Ours::Pldl3Keep,
        Cs::ARM64_PRFM_PLDL3STRM => Ours::Pldl3Strm,
        Cs::ARM64_PRFM_PLIL1KEEP => Ours::Plil1Keep,
        Cs::ARM64_PRFM_PLIL1STRM => Ours::Plil1Strm,
        Cs::ARM64_PRFM_PLIL2KEEP => Ours::Plil2Keep,
        Cs::ARM64_PRFM_PLIL2STRM => Ours::Plil2Strm,
        Cs::ARM64_PRFM_PLIL3KEEP => Ours::Plil3Keep,
        Cs::ARM64_PRFM_PLIL3STRM => Ours::Plil3Strm,
        Cs::ARM64_PRFM_PSTL1KEEP => Ours::Pstl1Keep,
        Cs::ARM64_PRFM_PSTL1STRM => Ours::Pstl1Strm,
        Cs::ARM64_PRFM_PSTL2KEEP => Ours::Pstl2Keep,
        Cs::ARM64_PRFM_PSTL2STRM => Ours::Pstl2Strm,
        Cs::ARM64_PRFM_PSTL3KEEP => Ours::Pstl3Keep,
        Cs::ARM64_PRFM_PSTL3STRM => Ours::Pstl3Strm,
        Cs::ARM64_PRFM_INVALID => return None,
    })
}

/// `SMSTART` / `SMSTOP` 的模式：capstone 的枚举 → 我们的。
fn svcr_mode(value: capstone::arch::arm64::Arm64SvcrOp) -> Option<crate::insn::SvcrMode> {
    use crate::insn::SvcrMode as Ours;
    use capstone::arch::arm64::Arm64SvcrOp as Cs;

    Some(match value {
        Cs::ARM64_SVCR_SVCRSM => Ours::Sm,
        Cs::ARM64_SVCR_SVCRZA => Ours::Za,
        Cs::ARM64_SVCR_SVCRSMZA => Ours::SmZa,
        Cs::ARM64_SVCR_INVALID => return None,
    })
}

/// 取 AArch64 操作数的移位/扩展修饰，返回（类型, 移位量）。
///
/// capstone 把它们放在两个字段里：`shift` 管逻辑/算术移位，
/// `ext` 管符号/零扩展。二者各自用 `*_INVALID` 表示"没有修饰"。
fn arm64_modifier(
    op: &capstone::arch::arm64::Arm64Operand,
) -> Option<(crate::insn::ShiftKind, u32)> {
    use crate::insn::ShiftKind;
    use capstone::arch::arm64::Arm64Shift;

    // 移位字段。`Lsl(3)` 表示 `lsl #3`。
    let shift = match op.shift {
        Arm64Shift::Lsl(n) => Some((ShiftKind::Lsl, n)),
        Arm64Shift::Lsr(n) => Some((ShiftKind::Lsr, n)),
        Arm64Shift::Asr(n) => Some((ShiftKind::Asr, n)),
        Arm64Shift::Ror(n) => Some((ShiftKind::Ror, n)),
        // MSL（masking shift left）在 AArch64 汇编里写作 `lsl`；保留原样会让
        // 用户对着外部工具对不上，所以按 LLVM 的显示走 Lsl。
        Arm64Shift::Msl(n) => Some((ShiftKind::Lsl, n)),
        // `Invalid` 不是错误，是"这条指令没有移位修饰"。
        Arm64Shift::Invalid => None,
    };

    // **扩展优先**：`shift` 与 `ext` 是两个独立字段，但同一条指令上可能
    // 同时有值 —— `add x0, x1, w2, sxtw #2` 就是 `ext=SXTW` + `shift=Lsl(2)`。
    // 那时正确的文本是 `w2, sxtw #2`（扩展 + 移位量），而不是 `w2, lsl #2`：
    // 后者把**符号扩展悄悄换成了逻辑左移**，结果完全不同。
    //
    // 早先的版本在 `shift` 分支上直接 `return`，正是丢掉了这种情况下的扩展。
    if let Some(kind) = arm64_extender(op.ext) {
        return Some((kind, shift.map_or(0, |(_, n)| n)));
    }

    shift
}

/// AArch64 的 `ext` 字段 → 扩展类型。`Invalid`（及将来新增的未知值）返回 `None`。
fn arm64_extender(ext: capstone::arch::arm64::Arm64Extender) -> Option<crate::insn::ShiftKind> {
    use crate::insn::ShiftKind;
    use capstone::arch::arm64::Arm64Extender;

    Some(match ext {
        Arm64Extender::ARM64_EXT_UXTB => ShiftKind::Uxtb,
        Arm64Extender::ARM64_EXT_UXTH => ShiftKind::Uxth,
        Arm64Extender::ARM64_EXT_UXTW => ShiftKind::Uxtw,
        Arm64Extender::ARM64_EXT_UXTX => ShiftKind::Uxtx,
        Arm64Extender::ARM64_EXT_SXTB => ShiftKind::Sxtb,
        Arm64Extender::ARM64_EXT_SXTH => ShiftKind::Sxth,
        Arm64Extender::ARM64_EXT_SXTW => ShiftKind::Sxtw,
        Arm64Extender::ARM64_EXT_SXTX => ShiftKind::Sxtx,
        // `ARM64_EXT_INVALID` 与将来新增的未知值：如实表示"没有可渲染的修饰"，
        // 而不是硬编一个默认值假装认识。
        Arm64Extender::ARM64_EXT_INVALID => return None,
    })
}

/// 取 AArch64 内存操作数的（索引寄存器, 有效比例, 索引修饰）。
///
/// AArch64 的索引形式是 `[Xn, Wm, <extend> #s]` 或 `[Xn, Xm, lsl #s]`：
/// **扩展**与**移位量**是两件不同的事，`scale` 只承载后者（有效比例），
/// 扩展另由 `MemRef::index_extend` 承载 —— 因为 `sxtw #2` 与 `lsl #2`
/// 在索引为负时算出的有效地址不同。
fn arm64_index(
    mem: &capstone::arch::arm64::Arm64OpMem,
    op: &capstone::arch::arm64::Arm64Operand,
) -> (
    Option<crate::insn::RegId>,
    u8,
    Option<crate::insn::ShiftKind>,
) {
    // 没有索引寄存器时，修饰字段即使有值也无处可挂（`mem.index()` 用
    // `RegId(0)` = `ARM64_REG_INVALID` 表示"没有索引"，由 `opt_reg` 过滤）。
    let Some(index) = opt_reg(mem.index()) else {
        return (None, 1, None);
    };

    let Some((kind, amount)) = arm64_modifier(op) else {
        return (Some(index), 1, None);
    };

    // 比例是 `1 << 移位量`。AArch64 索引的移位量只可能是 0..4；
    // 越界说明我们理解错了这个字段，那就**不编**一个比例出来 ——
    // 比例保持 1，修饰仍原样带在 `index_extend` 里，信息不丢。
    let scale = if amount < 8 { 1u8 << amount } else { 1 };

    if kind == crate::insn::ShiftKind::Lsl {
        // 纯左移：比例已经表达了它，不需要再记修饰。
        (Some(index), scale, None)
    } else {
        // 扩展（正常情况），或者索引位置上不该出现的移位类型。
        // 两种都原样带出来 —— 宁可渲染层多打一个词，也不静默丢掉修饰。
        (Some(index), scale, Some(kind))
    }
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
    // 无条件跳转的助记符（x86: jmp；ARM64: b；ARM: b；ppc: b / ba / bctr）
    //
    // ppc 的两条要单独列：`ba` 是"绝对地址的无条件分支"，`bctr` 是
    // "跳到 CTR 里那个地址"，两者都**没有**顺序后继。漏掉它们会让 CFG 多出
    // 一条不存在的边（`conditional: true` 的语义就是"有两个后继"）。
    !matches!(
        mnemonic,
        "jmp" | "b" | "b.w" | "j" | "br" | "bx" | "ba" | "bctr"
    )
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
    fn x86_conditional_jump_carries_semantic_condition() {
        // x86 的条件码不在 detail 里，从助记符如实映射到语义 ConditionCode，
        // 供伪代码的 if 条件使用（文本后缀仍不加，见上一条测试）。
        let dec = decoder();
        let cases: &[(u8, crate::insn::ConditionCode)] = &[
            (0x74, crate::insn::ConditionCode::Equal),          // je
            (0x75, crate::insn::ConditionCode::NotEqual),       // jne
            (0x7C, crate::insn::ConditionCode::SignedLessThan), // jl
            (0x7D, crate::insn::ConditionCode::SignedGreaterEqual), // jge
            (0x72, crate::insn::ConditionCode::CarryClear),     // jb
            (0x73, crate::insn::ConditionCode::CarrySet),       // jae
            (0x77, crate::insn::ConditionCode::UnsignedHigher), // ja
            (0x78, crate::insn::ConditionCode::Minus),          // js
        ];
        for &(opcode, expect) in cases {
            let insn = dec
                .decode_one(&[opcode, 0x05], 0x1000)
                .expect("conditional jump");
            assert_eq!(
                insn.condition,
                Some(expect),
                "opcode {opcode:#x} 的条件码应为 {expect:?}"
            );
        }
        // 奇偶条件没有对应 ConditionCode → 如实 None（不猜）。
        let jp = dec.decode_one(&[0x7A, 0x05], 0x1000).expect("jp");
        assert_eq!(jp.condition, None);
    }

    #[test]
    fn x86_cmp_write_register_is_not_an_operand() {
        // 结构化把 `cmp`/`test` + 条件跳转还原成真实比较，靠的是"只设标志"的形状判据：
        // "被写的寄存器不在操作数寄存器里"（标志寄存器不是操作数；mov/add 会写目标操作数）。
        // 这条测试钉死前提：capstone 对 cmp 报告的写寄存器**不是**它的操作数。
        // 若将来变了，判据会失效、结构化退回 flags —— 这里先失败提醒。
        let dec = decoder();
        let operand_regs = |insn: &crate::insn::DecodedInsn| -> Vec<u16> {
            insn.operands
                .iter()
                .filter_map(|op| match op {
                    crate::insn::Operand::Reg(r) => Some(r.0),
                    _ => None,
                })
                .collect()
        };
        // 83 f8 00 = cmp eax, 0
        let cmp = dec.decode_one(&[0x83, 0xF8, 0x00], 0x1000).expect("cmp");
        assert!(!cmp.reads.is_empty(), "cmp 应读操作数");
        let regs = operand_regs(&cmp);
        for r in cmp.writes.iter() {
            assert!(
                !regs.contains(&r.0),
                "cmp 的写寄存器 {r:?} 竟然出现在操作数里，判据会失效"
            );
        }
        // 85 c0 = test eax, eax
        let test = dec.decode_one(&[0x85, 0xC0], 0x1000).expect("test");
        let regs = operand_regs(&test);
        for r in test.writes.iter() {
            assert!(
                !regs.contains(&r.0),
                "test 的写寄存器 {r:?} 竟然出现在操作数里，判据会失效"
            );
        }
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
        // ppc 的无条件分支：`ba`（绝对地址）与 `bctr`（跳 CTR）都没有顺序后继
        assert!(!is_conditional_jump("ba"));
        assert!(!is_conditional_jump("bctr"));
        assert!(is_conditional_jump("bne"));
        assert!(is_conditional_jump("bdnz"));
    }

    // ── PowerPC（M12 第二片） ────────────────────────────────────────────

    /// ppc 的**大端**解码：`addc r2, r3, r4`。
    ///
    /// # 这条黄金值是从编码推出来的，不是抄反汇编输出
    ///
    /// PowerPC 的整数指令都是 4 字节、**大端**存放。`addc` 在 PowerPC ISA
    /// （Book I，"Integer Arithmetic Instructions"）里的编码是：
    ///
    /// ```text
    /// 31 | rD | rA | rB | OE(1) | XO(9) | Rc(1)
    ///  0..5  6..10 11..15 16..20  21  22..30  31
    /// ```
    /// 其中 `XO = 10`（`addc` 的扩展操作码）、`OE = 0`（不更新 OV）。
    ///
    /// 取 `rD = 2, rA = 3, rB = 4`：
    ///
    /// ```text
    /// 011111 00010 00011 00100 0 000001010 0 = 0x7C432014
    /// ```
    ///
    /// 所以文件里的字节是 `7C 43 20 14`。capstone 自己的 ppc 用例
    /// （`third-party/capstone/src/test.rs::test_arch_ppc`）里也有一条
    /// `("addc", b"\x7c\x43\x20\x14")` —— 助记符对得上，操作数是按上面的
    /// 字段切分独立推出来的（两处一致才敢当黄金值）。
    #[test]
    fn ppc32_big_endian_addc_decodes_registers_and_operands() {
        let spec = ArchSpec::from_arch(Arch::PowerPc, Mode::M32, Endian::Big);
        let dec = CapstoneDecoder::new(spec).expect("ppc 解码器必须能构造");
        let insn = dec
            .decode_one(&[0x7c, 0x43, 0x20, 0x14], 0x1000)
            .expect("addc 应当能解");

        assert_eq!(insn.len, 4, "ppc 指令恒为 4 字节");
        assert_eq!(dec.mnemonic_name(&insn).as_deref(), Some("addc"));
        assert_eq!(insn.flow, Flow::Fallthrough);
        assert_eq!(insn.operands.len(), 3, "rD / rA / rB 三个操作数");

        let names: Vec<Option<String>> = insn
            .operands
            .iter()
            .map(|op| match op {
                Operand::Reg(reg) => dec.register_name(*reg),
                _ => None,
            })
            .collect();
        assert_eq!(
            names,
            vec![
                Some("r2".to_string()),
                Some("r3".to_string()),
                Some("r4".to_string())
            ],
            "rD=2 / rA=3 / rB=4（编码里三段各 5 位）"
        );
    }

    /// 端序**必须**传到 capstone：同样的字节按小端解，得到的是另一条指令。
    ///
    /// 这条是"为什么 `build_engine` 要显式传端序"的证据。不传端序时 capstone
    /// 一律按小端解 ppc —— 而 ppc 的编码是大端，于是每条指令都解成**另一条
    /// 合法指令**（或者干脆解不出来）：不报错、看起来正常，只是全错。
    ///
    /// # 为什么小端那一半必须换线程
    ///
    /// 解码器的 capstone 句柄是**线程局部**的，槽位按架构分（见 `slot_for`）。
    /// 同一个线程里先后建两个 ppc 解码器（一个大端、一个小端），第二个会
    /// 复用第一个构造的引擎 —— 于是这条测试会"证明"端序没传下去，其实是
    /// 测法错了。换线程就让槽位是空的，按自己的 spec 真构造一次。
    #[test]
    fn ppc_decoding_depends_on_the_requested_endianness() {
        let bytes = [0x7c, 0x43, 0x20, 0x14];
        let big = CapstoneDecoder::new(ArchSpec::from_arch(Arch::PowerPc, Mode::M32, Endian::Big))
            .expect("ppc 大端解码器");
        let big_insn = big.decode_one(&bytes, 0).expect("大端解 addc");
        assert_eq!(big.mnemonic_name(&big_insn).as_deref(), Some("addc"));

        let wrong = std::thread::spawn(move || {
            let little = CapstoneDecoder::new(ArchSpec::from_arch(
                Arch::PowerPc,
                Mode::M32,
                Endian::Little,
            ))
            .expect("ppc 小端解码器");
            let decoded = little.decode_one(&bytes, 0);
            decoded
                .as_ref()
                .ok()
                .and_then(|insn| little.mnemonic_name(insn))
        })
        .join()
        .expect("线程应正常结束");

        // 实测（本机 capstone 0.14 + arch_powerpc）：小端模式下这四个字节
        // **一条指令都解不出来**（`decode_one` 报 Truncated），所以这里的
        // 结果是 `None`。断言只要求"不是同一条指令" —— 将来 capstone 改了
        // 小端的行为（解成另一条合法指令）时，这条测试仍然是对的。
        assert_ne!(
            wrong.as_deref(),
            Some("addc"),
            "小端下绝不该解出同一条指令 —— 解出了说明端序根本没传下去"
        );
    }

    /// ppc64 的 `blr`（`0x4E800020`）：函数返回。
    ///
    /// `blr` = "branch to link register"。编码 `0x4E800020` 是 PowerPC 里
    /// 最广为人知的常量之一（每个 ppc 函数都以它结尾），primary opcode 19
    /// （XL 型）、`XO = 16`。
    ///
    /// # 这条流程不是从 capstone 的 group 来的
    ///
    /// capstone 的 ppc 后端**不产出 `CS_GRP_RET`**（`grep -r CS_GRP_RET`
    /// 在 `arch/PowerPC/` 下为空），`blr` 只带 `CS_GRP_JUMP`。所以 `convert`
    /// 里对 ppc 的 `blr` / `bctrl` 做了一次按助记符的修正（那里写了完整理由）。
    /// 若哪天 capstone 补上组信息，这条仍然是 Return —— 结论不变。
    #[test]
    fn ppc64_big_endian_blr_is_a_return() {
        let spec = ArchSpec::from_arch(Arch::PowerPc64, Mode::M64, Endian::Big);
        let dec = CapstoneDecoder::new(spec).expect("ppc64 解码器必须能构造");
        let insn = dec
            .decode_one(&[0x4e, 0x80, 0x00, 0x20], 0x1000)
            .expect("blr 应当能解");
        assert_eq!(dec.mnemonic_name(&insn).as_deref(), Some("blr"));
        assert_eq!(insn.flow, Flow::Return, "blr 是返回，不是普通分支");
    }

    /// ppc 的条件分支：目标地址从立即数来，且必须标成"有两个后继"。
    ///
    /// 字节 `40 82 00 14` 在 capstone 的 ppc 用例里是 `bne`；位移字段
    /// `0x0014` 是 16 位有符号数，从地址 0 起算就是 `0x14`。
    #[test]
    fn ppc_conditional_branch_targets_an_absolute_address() {
        let spec = ArchSpec::from_arch(Arch::PowerPc, Mode::M32, Endian::Big);
        let dec = CapstoneDecoder::new(spec).expect("ppc 解码器");
        let insn = dec
            .decode_one(&[0x40, 0x82, 0x00, 0x14], 0)
            .expect("bne 应当能解");
        assert_eq!(dec.mnemonic_name(&insn).as_deref(), Some("bne"));
        assert_eq!(
            insn.flow,
            Flow::Branch { conditional: true },
            "bne 有顺序后继：{:?}",
            insn.flow
        );
        assert_eq!(insn.target, Some(0x14), "分支目标应当已解析成绝对地址");
    }

    /// ppc 的寄存器编号是**稀疏**的：不能拿"第一个空洞"当表尾。
    ///
    /// 实测（本机 capstone 0.14 + `arch_powerpc`）：编号 1、4、7、11、53、119
    /// 返回 `None`，而 `r3` 在 90、`r31` 在 118、`PPC_REG_ENDING = 344`。
    /// 早先的 `register_id` 在第 1 个 `None` 处就放弃了，于是**所有** ppc
    /// 寄存器名都解析不出来 —— 参数标注会静默变成空结论（不报错）。
    #[test]
    fn ppc_register_ids_are_sparse() {
        let spec = ArchSpec::from_arch(Arch::PowerPc, Mode::M32, Endian::Big);
        let dec = CapstoneDecoder::new(spec).expect("ppc 解码器");

        // 编号 1 是空洞：这正是旧实现踩的那一处。
        assert_eq!(dec.register_name(RegId(1)), None, "编号 1 是空洞");
        assert_eq!(
            dec.register_name(RegId(90)).as_deref(),
            Some("r3"),
            "r3 的编号是 90（实测）"
        );
        assert_eq!(
            CapstoneDecoder::register_id(spec, "r3"),
            Some(RegId(90)),
            "名字解析不能因为第一个空洞就放弃"
        );
        assert_eq!(CapstoneDecoder::register_id(spec, "r31"), Some(RegId(118)));
        // 上界来自 capstone 的 PPC_REG_ENDING，不是猜的
        assert_eq!(reg_id_limit(Arch::PowerPc), 344);
        assert_eq!(reg_id_limit(Arch::PowerPc64), 344);
    }

    /// ppc 的 `lwz`（内存操作数）：`lwz r1, 0(0)`。
    ///
    /// 编码 `0x80200000`：primary opcode 32（`lwz`）、`rD = 1`、`rA = 0`、
    /// `d = 0`。`rA = 0` 在 ppc 里表示"基址寄存器是 0"，capstone 把它报成
    /// 无效寄存器（编号 0），因此这里 `base` 必须是 `None` —— 不是"基址是 r0"。
    ///
    /// `size` 恒为 0：capstone 的 ppc 内存操作数不带宽度（见
    /// `convert_ppc_operand` 的说明），所以这里断言的是"如实未知"。
    #[test]
    fn ppc_memory_operand_keeps_displacement_and_reports_unknown_width() {
        let spec = ArchSpec::from_arch(Arch::PowerPc, Mode::M32, Endian::Big);
        let dec = CapstoneDecoder::new(spec).expect("ppc 解码器");
        let insn = dec
            .decode_one(&[0x80, 0x20, 0x00, 0x00], 0)
            .expect("lwz 应当能解");
        assert_eq!(dec.mnemonic_name(&insn).as_deref(), Some("lwz"));
        let Some(Operand::Mem(mem)) = insn.operands.last() else {
            panic!("lwz 的第二个操作数应当是内存引用：{:?}", insn.operands);
        };
        assert_eq!(mem.disp, 0, "位移字段 d = 0");
        assert_eq!(mem.base, None, "rA = 0 表示没有基址寄存器，不是 r0");
        assert_eq!(mem.size, 0, "ppc detail 不给宽度：如实记 0（未知）");
    }
}
