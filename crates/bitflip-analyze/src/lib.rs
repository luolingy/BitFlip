//! 分析流水线：作业边界、进度事件、协作式取消与阶段划分。
//!
//! 本 crate 不知道 HTTP / WebSocket / UI 的存在：服务层订阅 [`EventSink`] 再转发。
//! 这样 `bitflip-core` 与 UI 之间没有反向依赖，`bitflip-core` 也就能被其他项目直接嵌入。
//!
//! 阶段划分（`docs/ARCHITECTURE.md` §5）在 M2 起逐个落地；M0 先固定契约与边界语义。

mod addrspace;
mod args;
pub mod builtins;
mod callgraph;
mod cfg;
mod codemap;
mod consts;
mod frames;
mod functions;
mod job;
mod jumptable;
mod pseudo;
mod scan;
mod strings;
mod structs;
mod structurize;
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
pub use functions::{
    derive_function_start_bounds, derive_function_starts, function_start_candidates,
    merge_candidates, section_end_of, unwind_candidates, ConflictKind, DerivedEnd, Function,
    FunctionStartBound,
};
pub use job::{
    run_guarded, CancelToken, EventSink, JobError, JobEvent, JobHandle, JobId, JobState, NullSink,
    Progress, StageId,
};
pub use jumptable::{
    preferred_width, scan_jump_tables, EntryKind, EntryWidth, JumpTable, JumpTableScan,
    LOOKBACK_WINDOW, MAX_ENTRIES,
};
pub use pseudo::{
    decompile_function, no_register_names, render_function_text, ImportNamer, Pseudocode,
    PseudocodeBlock, PseudocodeFunction, PseudocodeNote, PseudocodeStatement, RegisterNamer,
    Resolvers, StringReader, TableReader, MAX_STATEMENTS, PSEUDO_FORMAT_VERSION,
};
pub use scan::{
    combine, control_flow_targets, scan_linear, scan_linear_with_ledger, scan_recursive,
    scan_recursive_with_ledger, DecodeLedger, DecodedSummary, RecursiveSelection, ScanCoverage,
    ScanOptions, ScanStats,
};
pub use strings::{extract_strings, StringEncoding, StringEntry, StringOptions};
pub use structs::{infer_struct_fields, StructCandidate, StructField, StructReport};
pub use structurize::decompile_structured;
pub use xref::{xrefs_of, xrefs_of_all, Xref, XrefKind};

/// 本 crate 的公共 API 版本。
///
/// v2（M12 第四片）：`SymbolSource` 多出 `FunctionStart` 变体（Mach-O 的
/// `LC_FUNCTION_STARTS`）。这个类型通过 [`Function::name_source`] 出现在本 crate 的
/// 公开 API 里，加变体会让下游的 `match` 编不过 —— 所以它不是"纯增量"，版本号 +1。
/// 新增的 [`derive_function_starts`] 等函数本身是纯增量，不需要单独记。
pub const ANALYZE_API_VERSION: u32 = 2;
