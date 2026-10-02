//! BitFlip 的架构、ABI 与指令解码抽象层。
//!
//! 设计约定（见 `docs/ARCHITECTURE.md` §4）：
//!
//! - **架构差异只在本 crate 内出现**。上层（analyze/loader/core）不得出现
//!   `if arch == X86` 之类的分支散落各处，架构知识一律收敛到类型表与 trait 实现里。
//! - **解码结果是结构化的语义**（控制流、寄存器读写、内存操作数），不是文本。
//!   指令文本只是渲染层的一种输出；上层能力（数据流、跳转表、调用约定、签名匹配）
//!   必须消费结构化字段，禁止回头去 `parse(op_str)`。
//! - 解码后端（capstone）在 M2 接入，本 crate 现在只定义契约与数据类型。

mod decode;
mod insn;
mod types;

pub use decode::{decoder_for, Abi, DecodeError, Decoder, UnsupportedDecoder};
pub use insn::{DecodedInsn, Flow, MemRef, MnemonicId, Operand, RegId, RegSet};
pub use types::{Arch, ArchSpec, Endian, Mode};

/// 本 crate 的公共 API 版本。跨 crate 契约变化时提升。
pub const ARCH_API_VERSION: u32 = 1;
