//! `bitflip-core` —— BitFlip 的引擎门面。
//!
//! 这是**唯一对外稳定 API**：`bitflip-server`、`bitflip-cli` 以及其他想嵌入 BitFlip 的
//! 项目都只依赖它。因此：
//!
//! - 不依赖 `axum` / `tokio` / `rust-embed`，也不暴露任何 UI 类型；
//! - 公开类型的破坏性变更需要提升 [`CORE_API_VERSION`] 并记入 CHANGELOG；
//! - 地址一律 `u64`，字符串化只发生在边界（wire 用定长 16 位十六进制）。
//!
//! 分层依赖方向：`cli/app → server → core → {loader, arch, analyze, symbols, project}`，
//! 下层永不反向依赖（CLAUDE.md §4）。

mod analysis;
mod disasm;
mod error;
mod session;

pub use analysis::{
    xref_source, ArgInferenceWire, ArgScanWire, BlockWire, CallEdgeWire, CallGraphSummaryWire,
    CallGraphWire, CfgWire, CodeMap, CodeMapSample, CodeMapStats, ConstScanWire, DebugUseWire,
    FrameInferenceWire, FrameScanWire, FunctionWire, ImmediateWire, ReachabilityWire,
    ReachableFunctionWire, StrideWire, StringUsageWire, StringWire, TargetAnalysis,
    UnresolvedCallWire, XrefFilter, XrefPage, XrefWire, ANALYSIS_FORMAT_VERSION,
};
pub use disasm::{
    hex16, parse_address, Disasm, DisasmStats, InsnPage, InsnWire, DEFAULT_PAGE_SIZE,
    DISASM_FORMAT_VERSION, MAX_PAGE_SIZE,
};
pub use error::BitflipError;

/// 重新导出归档成员描述：它是 [`Session::members`] / [`Session::member_session`]
/// 的返回类型，嵌入方（如 CLI）要用它做成员选择而不必直接依赖 `bitflip-loader`。
pub use bitflip_loader::ArchiveMember;
pub use session::{
    AnalysisSummary, ExportInfo, ImportInfo, ObjectInfo, OpenOptions, RelocInfo, SectionInfo,
    SegmentInfo, Session, SymbolInfo, TargetInfo, INFO_FORMAT_VERSION, MAX_FULL_PARSE_BYTES,
};

/// 重新导出作业/进度契约，方便嵌入方只依赖 `bitflip-core`。
pub use bitflip_analyze::{
    CancelToken, EventSink, JobError, JobEvent, JobHandle, JobId, JobState, NullSink, Progress,
    StageId,
};

/// 重新导出扫描选项：它是 [`Session::disassemble`] 的参数类型，
/// 嵌入方需要构造它而不必直接依赖 `bitflip-analyze`。
pub use bitflip_analyze::ScanOptions as DisasmScanOptions;

/// 重新导出架构规格（嵌入方做架构相关判断时使用，不需要直接依赖 `bitflip-arch`）。
pub use bitflip_arch::{Arch, ArchSpec, Endian, Mode};

/// 重新导出用户标注类型与工程库句柄：它们是 [`Session::open_project`] 的
/// 读写单位，嵌入方不该被迫直接依赖 `bitflip-project` 才能存一条注释。
///
/// 注意这是**刻意的例外说明**：ADR-0012 的硬约束是"`rusqlite` 类型不得出现在
/// `bitflip-core` 的公开 API 里"，而不是"core 不得转发工程库类型"。
/// `ProjectStore` 的公开方法签名里没有任何 `rusqlite` 类型
/// （`put`/`get`/`range`/`meta` 只出现 `u64`/`&str`/自有类型），
/// 所以转发它不违反该约束，却能让嵌入方只依赖 core 一个 crate。
pub use bitflip_project::{Annotation, AnnotationKind, ProjectStore};

/// `bitflip-core` 公共 API 版本。
pub const CORE_API_VERSION: u32 = 1;

/// BitFlip 引擎版本（来自 Cargo 包版本）。
#[must_use]
pub const fn version() -> &'static str {
    env!("CARGO_PKG_VERSION")
}
