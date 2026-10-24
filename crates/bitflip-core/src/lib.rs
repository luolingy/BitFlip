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
pub mod axml;
pub mod dex;
mod diff;
mod disasm;
mod error;
mod export;
mod import_edges;
mod session;
mod timing;

pub use analysis::{
    xref_source, AliasWire, ArgInferenceWire, ArgScanWire, BlockWire, CallEdgeWire,
    CallGraphSummaryWire, CallGraphWire, CfgWire, CodeMap, CodeMapSample, CodeMapStats,
    ConstScanWire, DebugUseWire, FrameInferenceWire, FrameScanWire, FunctionWire, ImmediateWire,
    ReachabilityWire, ReachableFunctionWire, StrideWire, StringUsageWire, StringWire,
    TargetAnalysis, UnresolvedCallWire, XrefFilter, XrefPage, XrefWire, ANALYSIS_FORMAT_VERSION,
};
pub use diff::{
    diff, diff_with_disasm, render_text as render_diff_text, DiffEntry, DiffKind, DiffOptions,
    DiffReport, DiffScope, DiffTotals, MatchBasis, Normalization, DIFF_FORMAT_VERSION,
};
pub use disasm::{
    hex16, parse_address, Cursor, Disasm, DisasmStats, InsnPage, InsnWire, DEFAULT_PAGE_SIZE,
    DISASM_FORMAT_VERSION, MAX_PAGE_SIZE,
};
pub use error::BitflipError;
pub use export::{
    check_options, export, export_with_disasm, ExportError, ExportFormat, ExportMeta,
    ExportOptions, ExportReport, FormatVersions, Truncation, DEFAULT_EXPORT_BYTE_LIMIT,
    EXPORT_FORMAT_VERSION,
};

/// 一并重新导出 APK 成员角色：它由**成员名**判定（纯字符串，不读字节），
/// 嵌入方要在成员列表里标出 `classes*.dex` / `lib/<abi>/*.so` 就得用它。
///
/// 与上面两条同理：不给嵌入方一个"被迫依赖 `bitflip-loader`"的理由。
/// 但要注意它的**适用前提**（见 `ApkRole` 的文档）：它只表示"名字符合 APK 的
/// 命名约定"，既不表示"这就是 APK"，也不表示"内容是那个格式"。
pub use bitflip_loader::ApkRole;
/// 重新导出归档成员描述：它是 [`Session::members`] / [`Session::member_session`]
/// 的返回类型，嵌入方（如 CLI）要用它做成员选择而不必直接依赖 `bitflip-loader`。
pub use bitflip_loader::ArchiveMember;
/// 一并重新导出成员存储方式：它是 [`ArchiveMember::storage`] 的类型，
/// 嵌入方要判断"这个成员是内联还是得向容器要"就得能看到它。
/// 不导出的话，消费方只能被迫去依赖 `bitflip-loader` —— 那正是上面那条
/// 重新导出想避免的事（核心层的公开 API 是对外契约，载体在这里）。
pub use bitflip_loader::MemberStorage;
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
///
/// v2（M12 第二片）：`bitflip_loader::Object` 新增 `uuid` / `dylibs`，
/// 因此 `ObjectInfo` 也多了这两个字段。字段本身是**增量**的（旧字段一个没动），
/// 但公开结构体的形状变了（字面量构造会编译失败），所以版本号 +1。
/// `bitflip-server` 的 `SERVER_API_VERSION` 保持与之同步（它转发的就是这套类型）。
///
/// v3（M12 第三片）：`Object` 新增 `function_starts: Vec<u64>`（Mach-O 的
/// `LC_FUNCTION_STARTS`），`ObjectInfo` 同步多出这个字段；另外 Mach-O 解析器
/// 开始**真的填** `symbols`（字段本身早就有，形状没变，但"空表"的含义变了：
/// 以前恒为空是因为没解析，现在空是"文件里没有可引用的符号"）。
/// 同样是增量字段，但形状变了 ⇒ 版本号 +1。
///
/// v4（M12 第五片）：[`CallEdgeWire`] 新增 `external` / `import_name` /
/// `import_module`（调用图开始有条边指向**本镜像之外**的导入符号）。
/// 又是增量字段，但公开结构体的形状变了（字面量构造会编译失败），
/// 而且 `callee` 的含义多了一种：`external = true` 时它是桩/槽地址，
/// **不是**函数入口 —— 消费方必须能分辨 ⇒ 版本号 +1。
///
/// v5（objc 名字这一片）：[`CallEdgeWire`] 新增 `objc_selector`（消息边的
/// 选择器名）；[`ObjectInfo`] 新增 `objc` 字段（计数 + 样例 + 说明）；
/// [(`bitflip_loader`)`Object`] 新增 `objc: ObjcMetadata`（选择器/方法/桩）。
/// 三个都是增量字段，但公开结构体的形状都变了（字面量构造会编译失败）⇒ +1。
///
/// v6（间接调用前驱恢复这一片）：[`CallEdgeWire`] 新增 `recovered_indirect`
/// （目标是推理出来的而不是编码里写的）；[`bitflip_analyze::CalleeResolution`]
/// 新增 `IndirectRecovered` 变体。同样是增量 + 形状变化 ⇒ +1。
///
/// v7：`SERVER_API_VERSION` 与 core 同步到 7（之前一版）。
///
/// v8（Swift 元数据这一片）：[`crate::session::ObjectInfo`] 新增 `swift:
/// SwiftInfoWire`（`__swift5_*` 的类型/协议名与计数）。公开结构体的形状变了
/// （字面量构造会编译失败）⇒ +1；`SERVER_API_VERSION` 同步 +1。
///
/// v9（代码签名有界校验这一片）：[`crate::session::ObjectInfo`] 新增 `signature:
/// SignatureInfoWire`（完整性结论/算法/identifier/slot 计数）。同样是公开结构体的
/// 形状变化 ⇒ +1；`SERVER_API_VERSION` 同步 +1。
///
/// v10（entitlements/requirements 事实这一片）：[`crate::session::SignatureInfoWire`]
/// 新增 `entitlements` / `entitlements_has_der_form` / `has_requirements` /
/// `requirements_size`。公开结构体形状变化 ⇒ +1；`SERVER_API_VERSION` 同步 +1。
///
/// v11（CDHash 这一片）：[`crate::session::SignatureInfoWire`] 新增 `cd_hash`
/// （CodeDirectory 自身哈希，签名结构指纹）。公开结构体形状变化 ⇒ +1；
/// `SERVER_API_VERSION` 同步 +1。
pub const CORE_API_VERSION: u32 = 11;

/// BitFlip 引擎版本（来自 Cargo 包版本）。
#[must_use]
pub const fn version() -> &'static str {
    env!("CARGO_PKG_VERSION")
}
