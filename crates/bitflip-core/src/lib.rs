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

mod error;
mod session;

pub use error::BitflipError;
pub use session::{
    AnalysisSummary, ExportInfo, ImportInfo, ObjectInfo, OpenOptions, RelocInfo, SectionInfo,
    SegmentInfo, Session, SymbolInfo, TargetInfo, INFO_FORMAT_VERSION,
};

/// 重新导出作业/进度契约，方便嵌入方只依赖 `bitflip-core`。
pub use bitflip_analyze::{
    CancelToken, EventSink, JobError, JobEvent, JobHandle, JobId, JobState, NullSink, Progress,
    StageId,
};

/// 重新导出架构规格（嵌入方做架构相关判断时使用，不需要直接依赖 `bitflip-arch`）。
pub use bitflip_arch::{Arch, ArchSpec, Endian, Mode};

/// `bitflip-core` 公共 API 版本。
pub const CORE_API_VERSION: u32 = 1;

/// BitFlip 引擎版本（来自 Cargo 包版本）。
#[must_use]
pub const fn version() -> &'static str {
    env!("CARGO_PKG_VERSION")
}
