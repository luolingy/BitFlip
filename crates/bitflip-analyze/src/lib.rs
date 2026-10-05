//! 分析流水线：作业边界、进度事件、协作式取消与阶段划分。
//!
//! 本 crate 不知道 HTTP / WebSocket / UI 的存在：服务层订阅 [`EventSink`] 再转发。
//! 这样 `bitflip-core` 与 UI 之间没有反向依赖，`bitflip-core` 也就能被其他项目直接嵌入。
//!
//! 阶段划分（`docs/ARCHITECTURE.md` §5）在 M2 起逐个落地；M0 先固定契约与边界语义。

mod addrspace;
mod args;
mod callgraph;
mod cfg;
mod codemap;
mod consts;
mod frames;
mod functions;
mod job;
mod jumptable;
mod scan;
mod strings;
mod xref;

pub use addrspace::{
    index_insn, AddrSpace, AddrSpaceError, ByteSource, InsnIndex, MappedSegment, PAGE_MASK,
    PAGE_SIZE, SYNTHETIC_BASE,
};
pub use args::{
    infer_args, infer_args_all, summarize_args, ArgInference, ArgScan, InsnRange as ArgInsnRange,
};
pub use callgraph::{
    build_call_graph, find_function, CallEdge, CallGraph, CalleeResolution, FunctionRange,
    GraphSummary,
};
pub use cfg::{build_functions, BasicBlock, Cfg};
pub use codemap::{
    compare_with_truth, judge_code, judge_code_many, AnalysisFacts, CodeEvidence, CodeFacts,
    CodeJudgement, ErrorRate, EvidenceKind, JudgementStats, RegionKind, MIN_DECODE_RUN,
};
pub use consts::{
    aggregate_string_refs, infer_strides, profile_immediates, scan_constants, Access, AccessStride,
    ConstScan, ImmediateProfile, StringUsage,
};
pub use frames::{
    scan_frames, summarize_frames, FrameInference, FrameScan, FrameSource, MAX_PROLOGUE_BYTES,
    MAX_PROLOGUE_INSNS,
};
pub use functions::{merge_candidates, unwind_candidates, ConflictKind, Function};
pub use job::{
    run_guarded, CancelToken, EventSink, JobError, JobEvent, JobHandle, JobId, JobState, NullSink,
    Progress, StageId,
};
pub use jumptable::{
    preferred_width, scan_jump_tables, EntryKind, EntryWidth, JumpTable, JumpTableScan,
    LOOKBACK_WINDOW, MAX_ENTRIES,
};
pub use scan::{
    combine, control_flow_targets, scan_linear, scan_recursive, ScanCoverage, ScanOptions,
    ScanStats,
};
pub use strings::{extract_strings, StringEncoding, StringEntry, StringOptions};
pub use xref::{xrefs_of, xrefs_of_all, Xref, XrefKind};

/// 本 crate 的公共 API 版本。
pub const ANALYZE_API_VERSION: u32 = 1;
