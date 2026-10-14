//! Contains arm64-specific types

pub use crate::arch::arch_builder::arm64::*;
use crate::arch::DetailsArchInsn;
use crate::instruction::{AccessType, RegId, RegIdInt};
use capstone_sys::{arm64_op_mem, arm64_op_sme_index, arm64_op_type, cs_ac_type, cs_arm64, cs_arm64_op};
use core::convert::{From, TryInto};
use core::{cmp, fmt, slice};
use core::ffi::c_uint;

// Re-exports
pub use capstone_sys::arm64_barrier_op as ArmBarrierOp;
pub use capstone_sys::arm64_barrier_op as Arm64BarrierOp;
pub use capstone_sys::arm64_cc as Arm64CC;
pub use capstone_sys::arm64_extender as Arm64Extender;
pub use capstone_sys::arm64_insn as Arm64Insn;
pub use capstone_sys::arm64_insn_group as Arm64InsnGroup;
pub use capstone_sys::arm64_prefetch_op as ArmPrefetchOp;
pub use capstone_sys::arm64_pstate as Arm64Pstate;
pub use capstone_sys::arm64_reg as Arm64Reg;
pub use capstone_sys::arm64_svcr_op as Arm64SvcrOp;
pub use capstone_sys::arm64_sys_op as Arm64SysOp;
pub use capstone_sys::arm64_sysreg as Arm64Sysreg;
pub use capstone_sys::arm64_vas as Arm64Vas;

use capstone_sys::arm64_shifter;
use capstone_sys::cs_arm64_op__bindgen_ty_2;

/// Contains ARM64-specific details for an instruction
pub struct Arm64InsnDetail<'a>(pub(crate) &'a cs_arm64);

/// ARM64 shift amount
#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash)]
pub enum Arm64Shift {
    Invalid,

    /// Logical shift left
    Lsl(u32),

    /// Masking shift left
    Msl(u32),

    /// Logical shift right
    Lsr(u32),

    /// Arithmetic shift right
    Asr(u32),

    /// Rotate right
    Ror(u32),
}

impl Arm64OperandType {
    fn new(
        op_type: arm64_op_type,
        value: cs_arm64_op__bindgen_ty_2,
        svcr: Arm64SvcrOp,
    ) -> Arm64OperandType {
        use self::arm64_op_type::*;
        use self::Arm64OperandType::*;

        match op_type {
            ARM64_OP_INVALID => Invalid,
            ARM64_OP_REG => Reg(RegId(unsafe { value.reg } as RegIdInt)),
            ARM64_OP_IMM => Imm(unsafe { value.imm }),
            ARM64_OP_MEM => Mem(Arm64OpMem(unsafe { value.mem })),
            ARM64_OP_FP => Fp(unsafe { value.fp }),
            ARM64_OP_CIMM => Cimm(unsafe { value.imm }),
            // === BitFlip fork begin ===
            // 上游 0.14.0 在这里 `mem::transmute` 原始编码到 `Arm64Sysreg`。
            // capstone 的 C 端（`printMRSSystemRegister` / `printMSRSystemRegister`，
            // 见 AArch64InstPrinter.c）**不校验**就写 `op.reg = Val`，而
            // `arm64_sysreg` 是稀疏的 `#[repr(u32)]` 枚举（只有 0 与 49k~62k 段里
            // 那些具名编码），所以任何 capstone 没命名的编码都会让 transmute
            // 构造出非法枚举值 —— 那是**非展开** panic：进程直接 abort，
            // `catch_unwind` 接不住。
            //
            // 这里如实保留原始编码。调用方若要名字，得自己查表；不查也比
            // 崩掉、或谎报一个系统寄存器强。详见 third-party/capstone/PATCH.md。
            ARM64_OP_REG_MRS => RegMrs(unsafe { value.reg }),
            ARM64_OP_REG_MSR => RegMsr(unsafe { value.reg }),
            // === BitFlip fork end ===
            ARM64_OP_PSTATE => Pstate(unsafe { value.pstate }),
            ARM64_OP_SYS => Sys(unsafe { value.sys }),
            ARM64_OP_PREFETCH => Prefetch(unsafe { value.prefetch }),
            ARM64_OP_BARRIER => Barrier(unsafe { value.barrier }),
            ARM64_OP_SVCR => SVCR(svcr),
            ARM64_OP_SME_INDEX => SMEIndex(Arm64OpSmeIndex(unsafe { value.sme_index })),
        }
    }
}

/// ARM64 operand
#[derive(Clone, Debug, PartialEq)]
pub struct Arm64Operand {
    /// How is this operand accessed?
    ///
    /// NOTE: this field is always `None` if the "full" feataure is not enabled.
    pub access: Option<AccessType>,

    /// Vector Index for some vector operands
    pub vector_index: Option<u32>,

    /// Vector arrangement specifier (for FloatingPoint/Advanced SIMD insn)
    pub vas: Arm64Vas,

    /// Shifter of this operand
    pub shift: Arm64Shift,

    /// Extender type of this operand
    pub ext: Arm64Extender,

    /// Operand type
    pub op_type: Arm64OperandType,
}

/// ARM64 operand
#[derive(Clone, Debug, PartialEq)]
pub enum Arm64OperandType {
    /// Register
    Reg(RegId),

    /// Immediate
    Imm(i64),

    /// Memory
    Mem(Arm64OpMem),

    /// Floating point
    Fp(f64),

    /// C-IMM
    Cimm(i64),

    // === BitFlip fork begin ===
    // 上游是 `RegMrs(Arm64Sysreg)` / `RegMsr(Arm64Sysreg)`。改成裸编码的原因见
    // `Arm64OperandType::new` 里的说明与 third-party/capstone/PATCH.md：
    // capstone 会原样透传它自己没命名的编码，而那不是一个合法的 `Arm64Sysreg`。
    // 这里用 `u32` 是因为它就是这个码本身，**不是**"暂时用 u32 顶一下"。
    /// System register MRS (move the contents of a PSR to a general-purpose register).
    ///
    /// 载荷是**原始系统寄存器编码**（capstone C 端的 `op.reg`）。
    /// 要与 [`Arm64Sysreg`] 的具名常量比较，直接用数值比即可；
    /// 但**不要**假定它是合法枚举值。
    RegMrs(u32),

    /// System register MSR (move to system coprocessor register from ARM register).
    ///
    /// 载荷语义同 [`Self::RegMrs`]。
    RegMsr(u32),
    // === BitFlip fork end ===

    /// System PState Field (MSR instruction)
    Pstate(Arm64Pstate),

    /// System operation (IC/DC/AT/TLBI)
    Sys(Arm64SysOp),

    /// PRFM operation
    Prefetch(ArmPrefetchOp),

    /// Memory barrier operation (ISB/DMB/DSB instructions)
    Barrier(Arm64BarrierOp),

    /// SMSTART/SMSTOP mode (Streaming SVE & ZA storage)
    SVCR(Arm64SvcrOp),

    /// SME index
    SMEIndex(Arm64OpSmeIndex),

    /// Invalid
    Invalid,
}

/// ARM64 memory operand
#[derive(Debug, Copy, Clone)]
pub struct Arm64OpMem(pub(crate) arm64_op_mem);

impl Arm64InsnDetail<'_> {
    /// Condition codes
    pub fn cc(&self) -> Arm64CC {
        self.0.cc
    }

    /// Whether this insn updates flags
    pub fn update_flags(&self) -> bool {
        self.0.update_flags
    }

    /// Whether writeback is required
    pub fn writeback(&self) -> bool {
        self.0.writeback
    }
}

impl_PartialEq_repr_fields!(Arm64InsnDetail<'a> [ 'a ];
    cc, update_flags, writeback, operands
);

impl Arm64OpMem {
    /// Base register
    pub fn base(&self) -> RegId {
        RegId(self.0.base as RegIdInt)
    }

    /// Index register
    pub fn index(&self) -> RegId {
        RegId(self.0.index as RegIdInt)
    }

    /// Disp value
    pub fn disp(&self) -> i32 {
        self.0.disp as i32
    }
}

impl_PartialEq_repr_fields!(Arm64OpMem;
    base, index, disp
);

impl cmp::Eq for Arm64OpMem {}

/// ARM64 sme index operand
#[derive(Debug, Copy, Clone)]
pub struct Arm64OpSmeIndex(pub(crate) arm64_op_sme_index);

impl Arm64OpSmeIndex {
    /// Register being indexed
    pub fn reg(&self) -> RegId {
        RegId(self.0.reg as RegIdInt)
    }

    /// Base register
    pub fn base(&self) -> RegId {
        RegId(self.0.base as RegIdInt)
    }

    /// Disp value
    pub fn disp(&self) -> i32 {
        self.0.disp as i32
    }
}

impl_PartialEq_repr_fields!(Arm64OpSmeIndex;
    reg, base, disp
);

impl Default for Arm64Operand {
    fn default() -> Self {
        Arm64Operand {
            access: None,
            vector_index: None,
            vas: Arm64Vas::ARM64_VAS_INVALID,
            shift: Arm64Shift::Invalid,
            ext: Arm64Extender::ARM64_EXT_INVALID,
            op_type: Arm64OperandType::Invalid,
        }
    }
}

impl Arm64Shift {
    fn new(type_: arm64_shifter, value: c_uint) -> Arm64Shift {
        use self::arm64_shifter::*;
        use self::Arm64Shift::*;

        macro_rules! arm64_shift_match {
            (
                $( $imm_r_enum:ident = $imm_c_enum:ident, )*
            ) => {
                match type_ {
                    ARM64_SFT_INVALID => Invalid,

                    $(
                        $imm_c_enum => $imm_r_enum(value as u32) ,
                    )*
                }
            }
        }

        arm64_shift_match!(
            Lsl = ARM64_SFT_LSL,
            Msl = ARM64_SFT_MSL,
            Lsr = ARM64_SFT_LSR,
            Asr = ARM64_SFT_ASR,
            Ror = ARM64_SFT_ROR,
        )
    }
}

impl From<&cs_arm64_op> for Arm64Operand {
    fn from(op: &cs_arm64_op) -> Arm64Operand {
        let shift = Arm64Shift::new(op.shift.type_, op.shift.value);
        let op_type = Arm64OperandType::new(op.type_, op.__bindgen_anon_1, op.svcr);
        let vector_index = if op.vector_index >= 0 {
            Some(op.vector_index as u32)
        } else {
            None
        };
        Arm64Operand {
            access: cs_ac_type(op.access as _).try_into().ok(),
            vector_index,
            vas: op.vas,
            shift,
            ext: op.ext,
            op_type,
        }
    }
}

def_arch_details_struct!(
    InsnDetail = Arm64InsnDetail;
    Operand = Arm64Operand;
    OperandIterator = Arm64OperandIterator;
    OperandIteratorLife = Arm64OperandIterator<'a>;
    [ pub struct Arm64OperandIterator<'a>(slice::Iter<'a, cs_arm64_op>); ]
    cs_arch_op = cs_arm64_op;
    cs_arch = cs_arm64;
);

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn test_arm64shift() {
        use super::arm64_shifter::*;
        use super::Arm64Shift::*;
        use core::ffi::c_uint;

        fn t(shift_type_value: (arm64_shifter, c_uint), arm64_shift: Arm64Shift) {
            let (shift_type, value) = shift_type_value;
            assert_eq!(arm64_shift, Arm64Shift::new(shift_type, value));
        }

        t((ARM64_SFT_INVALID, 0), Invalid);
        t((ARM64_SFT_ASR, 0), Asr(0));
    }

    #[test]
    fn test_arm64_op_type() {
        use super::arm64_op_type::*;
        use super::Arm64OperandType::*;
        use super::Arm64Sysreg::*;
        use capstone_sys::arm64_prefetch_op::*;
        use capstone_sys::arm64_pstate::*;
        use capstone_sys::arm64_svcr_op::*;
        use capstone_sys::*;

        fn t(
            op_type_value: (arm64_op_type, cs_arm64_op__bindgen_ty_2, arm64_svcr_op),
            expected_op_type: Arm64OperandType,
        ) {
            let (op_type, op_value, op_svcr) = op_type_value;
            let op_type = Arm64OperandType::new(op_type, op_value, op_svcr);
            assert_eq!(expected_op_type, op_type);
        }

        t(
            (
                ARM64_OP_INVALID,
                cs_arm64_op__bindgen_ty_2 { reg: 0 },
                ARM64_SVCR_INVALID,
            ),
            Invalid,
        );
        t(
            (
                ARM64_OP_REG,
                cs_arm64_op__bindgen_ty_2 { reg: 0 },
                ARM64_SVCR_INVALID,
            ),
            Reg(RegId(0)),
        );
        t(
            (
                ARM64_OP_IMM,
                cs_arm64_op__bindgen_ty_2 { imm: 42 },
                ARM64_SVCR_INVALID,
            ),
            Imm(42),
        );
        t(
            (
                ARM64_OP_REG_MRS,
                cs_arm64_op__bindgen_ty_2 {
                    reg: ARM64_SYSREG_MDRAR_EL1 as arm64_reg::Type,
                },
                ARM64_SVCR_INVALID,
            ),
            RegMrs(ARM64_SYSREG_MDRAR_EL1 as u32),
        );
        t(
            (
                ARM64_OP_PSTATE,
                cs_arm64_op__bindgen_ty_2 {
                    pstate: ARM64_PSTATE_SPSEL,
                },
                ARM64_SVCR_INVALID,
            ),
            Pstate(Arm64Pstate::ARM64_PSTATE_SPSEL),
        );
        t(
            (
                ARM64_OP_FP,
                cs_arm64_op__bindgen_ty_2 { fp: 0.0 },
                ARM64_SVCR_INVALID,
            ),
            Fp(0.0),
        );
        t(
            (
                ARM64_OP_CIMM,
                cs_arm64_op__bindgen_ty_2 { imm: 42 },
                ARM64_SVCR_INVALID,
            ),
            Cimm(42),
        );
        t(
            (
                ARM64_OP_REG_MSR,
                cs_arm64_op__bindgen_ty_2 {
                    reg: arm64_sysreg::ARM64_SYSREG_ICC_EOIR1_EL1 as arm64_reg::Type,
                },
                ARM64_SVCR_INVALID,
            ),
            RegMsr(arm64_sysreg::ARM64_SYSREG_ICC_EOIR1_EL1 as u32),
        );
        // === BitFlip fork begin ===
        // 回归测试：capstone 会透传它自己没命名的系统寄存器编码，而上游在这里
        // 做的是 `transmute` —— 0x1d7e 这种不在 `arm64_sysreg` 取值域里的编码
        // 会让它构造非法枚举值，**非展开** panic 直接 abort 进程。
        // 实测样本：真实上架 APK 里的 `lib/arm64-v8a/libBugly_Native.so`。
        //
        // 这个用例只能测"不崩且如实保留编码"；名字查询是调用方的事。
        t(
            (
                ARM64_OP_REG_MRS,
                cs_arm64_op__bindgen_ty_2 { reg: 0x1d7e },
                ARM64_SVCR_INVALID,
            ),
            RegMrs(0x1d7e),
        );
        // === BitFlip fork end ===
        t(
            (
                ARM64_OP_SYS,
                cs_arm64_op__bindgen_ty_2 {
                    sys: arm64_sys_op::ARM64_AT_S1E0R,
                },
                ARM64_SVCR_INVALID,
            ),
            Sys(arm64_sys_op::ARM64_AT_S1E0R),
        );
        t(
            (
                ARM64_OP_PREFETCH,
                cs_arm64_op__bindgen_ty_2 {
                    prefetch: ARM64_PRFM_PLDL2KEEP,
                },
                ARM64_SVCR_INVALID,
            ),
            Prefetch(ARM64_PRFM_PLDL2KEEP),
        );
        t(
            (
                ARM64_OP_SVCR,
                cs_arm64_op__bindgen_ty_2 { reg: 0 },
                ARM64_SVCR_SVCRSM,
            ),
            SVCR(ARM64_SVCR_SVCRSM),
        );
        t(
            (
                ARM64_OP_SME_INDEX,
                cs_arm64_op__bindgen_ty_2 {
                    sme_index: arm64_op_sme_index {
                        reg: 1,
                        base: 2,
                        disp: 3,
                    },
                },
                ARM64_SVCR_INVALID,
            ),
            SMEIndex(Arm64OpSmeIndex(arm64_op_sme_index {
                reg: 1,
                base: 2,
                disp: 3,
            })),
        );
    }
}
