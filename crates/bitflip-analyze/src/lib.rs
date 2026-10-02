//! 分析流水线：作业边界、进度事件、协作式取消与阶段划分。
//!
//! 本 crate 不知道 HTTP / WebSocket / UI 的存在：服务层订阅 [`EventSink`] 再转发。
//! 这样 `bitflip-core` 与 UI 之间没有反向依赖，`bitflip-core` 也就能被其他项目直接嵌入。
//!
//! 阶段划分（`docs/ARCHITECTURE.md` §5）在 M2 起逐个落地；M0 先固定契约与边界语义。

mod addrspace;
mod job;
mod scan;

pub use addrspace::{
    index_insn, AddrSpace, AddrSpaceError, ByteSource, InsnIndex, MappedSegment, PAGE_MASK,
    PAGE_SIZE, SYNTHETIC_BASE,
};
pub use job::{
    run_guarded, CancelToken, EventSink, JobError, JobEvent, JobHandle, JobId, JobState, NullSink,
    Progress, StageId,
};
pub use scan::{
    combine, control_flow_targets, scan_linear, scan_recursive, ScanCoverage, ScanOptions,
    ScanStats,
};

/// 本 crate 的公共 API 版本。
pub const ANALYZE_API_VERSION: u32 = 1;
