//! BitFlip 的架构、ABI 与指令解码抽象层。
//!
//! 设计约定（见 `docs/ARCHITECTURE.md` §4）：
//!
//! - **架构差异只在本 crate 内出现**。上层（analyze/loader/core）不得出现
//!   `if arch == X86` 之类的分支散落各处，架构知识一律收敛到类型表与 trait 实现里。
//! - **解码结果是结构化的语义**（控制流、寄存器读写、内存操作数），不是文本。
//!   指令文本只是渲染层的一种输出；上层能力（数据流、跳转表、调用约定、签名匹配）
//!   必须消费结构化字段，禁止回头去 `parse(op_str)`。
//! - 解码后端是 capstone（M2 接入）；换后端不应影响上层 —— 上层只依赖
//!   [`Decoder`] trait 与 [`DecodedInsn`]。

mod abi;
mod backend;
mod decode;
mod insn;
mod padding;
mod plt;
mod render;
mod types;

pub use abi::{abi_for_spec, AbiSpec, ReturnAddress};
pub use backend::{BackendError, CapstoneDecoder, DecoderBackend};
pub use decode::{decoder_for, Abi, DecodeError, Decoder, UnsupportedDecoder};
pub use insn::{
    ConditionCode, DecodedInsn, Flow, MemRef, MnemonicId, Operand, RegId, RegSet, ShiftKind,
};
pub use padding::{padding_len, supports_padding};
pub use plt::{plt_stub, supports_plt_stub, PltStub};
pub use render::{flow_label, format_insn, format_insn_with, text_style, TextStyle};
pub use types::{Arch, ArchSpec, Endian, Mode};

/// 本 crate 的公共 API 版本。跨 crate 契约变化时提升。
pub const ARCH_API_VERSION: u32 = 1;
