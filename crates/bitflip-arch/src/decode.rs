//! 解码器与 ABI 契约。

use core::fmt;

use crate::insn::{DecodedInsn, RegId};
use crate::types::{Arch, ArchSpec, Mode};

/// 解码失败原因。
///
/// 解码失败**不是**致命错误：地址空间里可能存在数据或非法字节，
/// 调用方据此把该地址标记为"未解析"，而不是丢弃。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DecodeError {
    /// 字节不足以构成一条完整指令。
    Truncated,
    /// 字节序列不是该架构的合法指令。
    Invalid,
    /// 该架构/模式尚未接入解码后端。
    Unsupported {
        /// 架构。
        arch: Arch,
        /// 模式。
        mode: Mode,
    },
}

impl fmt::Display for DecodeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Truncated => f.write_str("字节不足，无法构成完整指令"),
            Self::Invalid => f.write_str("非法指令编码"),
            Self::Unsupported { arch, mode } => {
                write!(f, "尚未支持解码: {arch}/{mode}")
            }
        }
    }
}

impl std::error::Error for DecodeError {}

/// 指令解码器。实现必须线程安全（同一实例会被 `rayon` 并行使用）。
pub trait Decoder: Send + Sync {
    /// 本解码器对应的架构规格。
    fn spec(&self) -> ArchSpec;

    /// 解码一条指令。`addr` 用于计算 PC 相关目标。
    fn decode_one(&self, code: &[u8], addr: u64) -> Result<DecodedInsn, DecodeError>;

    /// 批量解码，遇到第一个失败即停止并返回已解出的前缀。
    ///
    /// 默认实现基于 [`Decoder::decode_one`]；后端有更高效的成块解码 API 时应覆盖，
    /// 但必须保持"出错即停、不跳过字节"的语义。
    fn decode_many(&self, code: &[u8], addr: u64, max: usize) -> Vec<DecodedInsn> {
        let mut out = Vec::new();
        let mut cursor = 0usize;
        while out.len() < max && cursor < code.len() {
            let Ok(insn) = self.decode_one(&code[cursor..], addr + cursor as u64) else {
                break;
            };
            if insn.len == 0 {
                break;
            }
            cursor += usize::from(insn.len);
            out.push(insn);
        }
        out
    }
}

/// 调用约定与寄存器角色的架构描述。
///
/// 上层做参数推断、栈帧分析时只依赖这里，不写架构分支。
pub trait Abi: Send + Sync {
    /// 架构规格。
    fn spec(&self) -> ArchSpec;

    /// 整型/指针参数寄存器（按调用顺序）。
    fn arg_regs(&self) -> &'static [RegId];

    /// 返回值寄存器。
    fn return_reg(&self) -> RegId;

    /// 栈指针。
    fn stack_pointer(&self) -> RegId;

    /// 帧指针（可能为 `None`，如 AArch64 上的可选 x29）。
    fn frame_pointer(&self) -> Option<RegId>;

    /// 是否被调用者保存（callee-saved）。
    fn is_callee_saved(&self, reg: RegId) -> bool;
}

/// M0–M1 的占位解码器：明确返回"尚未支持"，而不是猜一个结果。
///
/// capstone 后端在 M2 接入（见 `docs/PLAN.md` M2），届时 [`decoder_for`] 返回真实实现。
pub struct UnsupportedDecoder {
    spec: ArchSpec,
}

impl UnsupportedDecoder {
    /// 为指定架构规格创建占位解码器。
    #[must_use]
    pub const fn new(spec: ArchSpec) -> Self {
        Self { spec }
    }
}

impl Decoder for UnsupportedDecoder {
    fn spec(&self) -> ArchSpec {
        self.spec
    }

    fn decode_one(&self, _code: &[u8], _addr: u64) -> Result<DecodedInsn, DecodeError> {
        Err(DecodeError::Unsupported {
            arch: self.spec.arch,
            mode: self.spec.mode,
        })
    }

    fn decode_many(&self, _code: &[u8], _addr: u64, _max: usize) -> Vec<DecodedInsn> {
        Vec::new()
    }
}

/// 按架构规格取解码器。
///
/// M2 起返回真实的 capstone 后端；capstone 没有对应后端（如 wasm32）时
/// 退回 [`UnsupportedDecoder`]，调用方拿到的是明确的
/// [`DecodeError::Unsupported`]，而不是编造的反汇编。
///
/// 这样调用方不需要处理"有没有解码器"这个分支 —— 拿到的永远是
/// 一个可用的 [`Decoder`]，只是能力不同。
#[must_use]
pub fn decoder_for(spec: ArchSpec) -> Box<dyn Decoder> {
    match crate::backend::CapstoneDecoder::new(spec) {
        Ok(decoder) => Box::new(decoder),
        Err(error) => {
            tracing::debug!(
                arch = %spec.arch,
                mode = %spec.mode,
                %error,
                "没有可用的解码后端，退回 UnsupportedDecoder"
            );
            Box::new(UnsupportedDecoder::new(spec))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::Endian;

    #[test]
    fn unsupported_decoder_reports_clearly() {
        let spec = ArchSpec::from_arch(Arch::X86_64, Mode::M64, Endian::Little);
        // 直接构造占位解码器（M0–M1 的行为）：它必须明确报"尚未支持"，
        // 而不是猜一个结果。
        let dec = UnsupportedDecoder::new(spec);
        assert_eq!(dec.spec(), spec);
        let err = dec.decode_one(&[0x90], 0x1000).unwrap_err();
        assert_eq!(
            err,
            DecodeError::Unsupported {
                arch: Arch::X86_64,
                mode: Mode::M64
            }
        );
        assert!(err.to_string().contains("尚未支持解码"));
        assert!(dec.decode_many(&[0x90; 16], 0x1000, 8).is_empty());
    }

    #[test]
    fn decoder_for_returns_real_backend_for_supported_arch() {
        // M2 起 x86_64 必须拿到真实解码器，而不是占位实现
        let spec = ArchSpec::from_arch(Arch::X86_64, Mode::M64, Endian::Little);
        let dec = decoder_for(spec);
        assert_eq!(dec.spec(), spec);
        let insn = dec.decode_one(&[0x90], 0x1000).expect("nop 应能解码");
        assert_eq!(insn.len, 1);
    }

    #[test]
    fn decoder_for_falls_back_to_unsupported_for_unknown_arch() {
        // wasm32 没有 capstone 后端：必须退回占位解码器并明确报错，
        // 而不是 panic，也不是拿别的架构去解 wasm 字节。
        let spec = ArchSpec::from_arch(Arch::Wasm32, Mode::M32, Endian::Little);
        let dec = decoder_for(spec);
        let err = dec.decode_one(&[0x00; 8], 0x1000).unwrap_err();
        assert_eq!(
            err,
            DecodeError::Unsupported {
                arch: Arch::Wasm32,
                mode: Mode::M32
            }
        );
    }
}
