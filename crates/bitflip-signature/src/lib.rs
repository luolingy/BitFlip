//! BitFlip 的签名库（FLIRT 风格）。
//!
//! # 解决什么问题
//!
//! 目标是**剥离过的**二进制时，符号表、调试信息、导出表全都不在，只剩下代码本身。
//! 唯一还能把"这是 `memcpy`"说出来的证据，是**代码的形状** —— 而这个形状在编译器
//! 之间存在大量完全相同的结果：同一个 `libgcc.a` / CRT 函数被链接进上千个程序里，
//! 字节几乎逐位相同（差别只在链接器改写的那几个位置）。
//!
//! 本层就是从"已知库"里把这种形状抽出来（[`generate`]），再去目标里找回来
//! （[`matcher`]）。名字的来源是用户自己机器上的静态库，不需要任何云服务或预置
//! 数据库。
//!
//! # 三条不肯让步的规矩
//!
//! 1. **不猜。** 确定字节不够、开头就被重定位糊住、两条不同名字的签名同形 ——
//!    一律丢弃，并记进 [`signature::GenerationStats`]。宁可少给名字。
//! 2. **不静默。** 生成与匹配每个环节的"拿不到"都有计数：丢弃原因、被跳过的截断
//!    成员、因重定位类型不认识而加宽的屏蔽、匹配时因字节不够无法验证的次数。
//! 3. **不越层。** 本层只认"字节 + 重定位 + 名字"，不认识架构枚举，也不解析指令：
//!    架构差异由调用方折算成 [`signature::SignatureArch`] 传进来。
//!
//! # 签名文件是派生物
//!
//! 签名文件带 [`SIGNATURE_FORMAT_VERSION`]，版本不符时**不迁移**、直接报错要求重新
//! 生成（从本机静态库重生成只要几秒）。它记录生成时的形态与账目，可读可 diff。

pub mod generate;
pub mod matcher;
pub mod pattern;
pub mod signature;

pub use generate::{
    generate, signature_arch, ArchiveInput, Generated, SourceReport, INDEX_BYTES, MIN_EXACT_BYTES,
    MIN_EXACT_NO_TAIL, MIN_FUNCTION_BYTES, PREFIX_BYTES, TAIL_MIN_BYTES, TAIL_WINDOW,
};
pub use matcher::{AmbiguousMatch, Hit, Match, MatchReport, Matcher, TargetFunction};
pub use pattern::{crc16_ccitt, Pattern, PatternByte, PatternError};
pub use signature::{
    DropReason, FunctionSignature, GenerationStats, SignatureArch, SignatureError, SignatureSet,
    TailCheck, SIGNATURE_FORMAT_VERSION, SIGNATURE_TOOL,
};
