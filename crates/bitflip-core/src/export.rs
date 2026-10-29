//! 导出（M9）：把分析结论带出工具。
//!
//! ## 为什么导出要放在 `bitflip-core`
//!
//! 导出有三种消费方式 —— 命令行、HTTP 端点、脚本 API —— 而它们必须给出
//! **同一份**字节。如果各自拼一遍文本，早晚会漂移，而漂移的表现是
//! "CLI 导出的和界面看到的不一样"，用户没法判断哪个可信。
//! 所以格式与写出逻辑只在这里实现一次，上层只做参数解析与 IO。
//!
//! ## 诚实性规则（CLAUDE.md §7）
//!
//! 1. **截断必须自述。** 每次导出都有字节预算，撞上预算就在结果里写明
//!    截断了多少、接下来该怎么办（分地址段导出）。静默截断会让用户
//!    以为"目标就这么大"。
//! 2. **降级必须写出来。** 反汇编里解不出来的字节在文本里是
//!    `<无法解码>`，条数进 `notes`；非 x86 目标选 AT&T 直接报错，
//!    不拿 Intel 文本充数。
//! 3. **不编造。** 没有调试信息就不写源位置列；符号表为空就是空，
//!    不用"未命名"之类的占位填满。
//!
//! ## 输出契约
//!
//! 每个导出都自带版本与来源，可以脱离本工具被解析：
//!
//! - **文本类**（`asm-*` / `dot-cfg`）：首行是 `# bitflip-export ...`
//!   注释头（不是 JSON，免得它被当成 JSON 解析）；DOT 的头部是 `//` 注释。
//! - **JSON 类**：顶层是对象，含 `format_version` / `producer` / `meta` /
//!   `totals` 与数据字段。`format_version` 变化表示**字段含义**变过。

use serde_json::json;

use crate::analysis::{FunctionWire, TargetAnalysis, XrefWire, ANALYSIS_FORMAT_VERSION};
use crate::disasm::{hex16, DISASM_FORMAT_VERSION};
use crate::error::BitflipError;
use crate::session::{ObjectInfo, Session, INFO_FORMAT_VERSION};
use bitflip_analyze::StructCandidate;

/// 导出格式版本号。
///
/// 消费者（外部工具、CI）靠它判断字段含义是否变过。任何字段增删改都要递增，
/// 并在 `docs/PLAN.md` 的 M9 记录里说明。
pub const EXPORT_FORMAT_VERSION: u32 = 1;

/// 单次导出的默认字节预算（32 MiB）。
///
/// 取值理由：目标文件本身最大 512 MiB（`MAX_FULL_PARSE_BYTES`），
/// 反汇编文本一般是文件大小的数倍 —— 32 MiB 能覆盖几百 KB 到数 MB 的
/// 真实目标（本项目的 fixture 全都在 1 MiB 以内，`ntdll.dll` 约 2 MB），
/// 又不至于让一次误操作把内存吃光。需要全量时显式指定更大的值，
/// 或按地址段分批。
pub const DEFAULT_EXPORT_BYTE_LIMIT: u64 = 32 * 1024 * 1024;

/// 导出格式。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ExportFormat {
    /// 反汇编文本，Intel 语法。
    AsmIntel,
    /// 反汇编文本，AT&T 语法（**只对 x86 族有效**）。
    AsmAtt,
    /// 函数清单（JSON）。
    JsonFunctions,
    /// 符号表 + 导入 + 导出（JSON）。
    JsonSymbols,
    /// 交叉引用全表（JSON）。
    JsonXrefs,
    /// 疑似结构体字段布局（JSON）。**启发式、非真实 C 类型**：见 `bitflip_analyze::structs`。
    JsonStructs,
    /// 依赖库识别（JSON）：按库聚合导入符号，回答"这个二进制依赖哪些库、每库贡献多少导入"。
    /// 数据来自导入表/依赖库列表（**客观**，不猜）。
    JsonLibraries,
    /// 调用图（JSON）：已解析的调用边 + 汇总 + 未解析间接调用。**只列已解析的边**，
    /// 未解析的间接调用单独计数（`summary.unresolved_indirect`），可达集是**下界**。
    JsonCallGraph,
    /// 控制流图（Graphviz DOT）。
    DotCfg,
    /// C 风格伪代码（**有界子集**：单基本块表达式视图，不做控制流结构化）。
    ///
    /// 见 `docs/DECOMPILER-SCOPE.md`：这不是反编译器，条件跳转以 `goto` 出现，
    /// 不还原 if/while/for，不做类型推断。用户必须知道这一点才能正确理解输出。
    PseudoC,
    /// C 风格伪代码，**做了控制流结构化**：可归约 CFG 上的 `if`/`else`/`while`/`do-while`
    /// 从控制流图还原；形态拿不准的地方仍退回 `if (cond) goto`（如实标注部分结构化）。
    /// 有界子集，不做类型推断。
    PseudoCStructured,
    /// DEX 结构快照（JSON）。见 `docs/APK-DEX-DESIGN.md` §M2c 与 ADR-0021。
    DexJson,
    /// DEX 的 smali 风格文本（**我们自己的渲染路径**，不是可回汇编的源文件）。
    DexSmali,
    /// DEX 一个方法的 CFG（Graphviz DOT），与 [`Self::DotCfg`] 同形。
    DexDotCfg,
}

impl ExportFormat {
    /// 稳定短名（CLI 选项、HTTP 参数、JSON `meta.format` 都用它）。
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::AsmIntel => "asm-intel",
            Self::AsmAtt => "asm-att",
            Self::JsonFunctions => "json-functions",
            Self::JsonSymbols => "json-symbols",
            Self::JsonXrefs => "json-xrefs",
            Self::JsonStructs => "json-structs",
            Self::JsonLibraries => "json-libraries",
            Self::JsonCallGraph => "json-callgraph",
            Self::DotCfg => "dot-cfg",
            Self::PseudoC => "pseudo-c",
            Self::PseudoCStructured => "pseudo-c-structured",
            Self::DexJson => "dex-json",
            Self::DexSmali => "dex-smali",
            Self::DexDotCfg => "dex-dot-cfg",
        }
    }

    /// 全部格式（CLI 的 `--help`、错误提示里列出可用值）。
    #[must_use]
    pub const fn all() -> &'static [ExportFormat] {
        &[
            Self::AsmIntel,
            Self::AsmAtt,
            Self::JsonFunctions,
            Self::JsonSymbols,
            Self::JsonXrefs,
            Self::JsonStructs,
            Self::JsonLibraries,
            Self::JsonCallGraph,
            Self::DotCfg,
            Self::PseudoC,
            Self::PseudoCStructured,
            Self::DexJson,
            Self::DexSmali,
            Self::DexDotCfg,
        ]
    }

    /// 解析短名。null 表示不认识（调用方负责报错并列出可用值）。
    #[must_use]
    pub fn parse(text: &str) -> Option<Self> {
        let normalized = text.trim().to_ascii_lowercase();
        Self::all()
            .iter()
            .copied()
            .find(|format| format.as_str() == normalized)
    }

    /// 是否是文本（相对 JSON）格式。CLI 用它决定要不要给一个文件名默认值。
    #[must_use]
    pub const fn is_text(self) -> bool {
        matches!(
            self,
            Self::AsmIntel
                | Self::AsmAtt
                | Self::DotCfg
                | Self::PseudoC
                | Self::DexSmali
                | Self::DexDotCfg
        )
    }

    /// 是不是 DEX 视图的格式（决定入口走哪条路、哪些选项有意义）。
    #[must_use]
    pub const fn is_dex(self) -> bool {
        matches!(self, Self::DexJson | Self::DexSmali | Self::DexDotCfg)
    }
}

/// 导出参数。
///
/// `Default` 的取值是"能导出、但不无限"：半开区间 `[0, u64::MAX)` 表示不过滤，
/// 字节预算取 [`DEFAULT_EXPORT_BYTE_LIMIT`]。
#[derive(Debug, Clone)]
pub struct ExportOptions {
    /// 地址范围（半开区间），`None` 表示不过滤。
    ///
    /// 对 `asm-*` 与 `dot-cfg` 是"只导出这个范围内的内容"；对
    /// `json-functions` 是"只导出入口落在这个范围内的函数"。
    pub range: Option<(u64, u64)>,
    /// 只导出这一个函数（入口地址）。与 `range` 同时给出时**报错**，
    /// 因为"哪个更具体"没有合理答案。
    pub function: Option<u64>,
    /// 反汇编文本是否带机器码列。
    pub include_bytes: bool,
    /// 反汇编文本是否带源位置（有调试信息时）。
    pub include_source: bool,
    /// DOT 最多画多少个函数。
    pub max_functions: usize,
    /// 字节预算；`None` 表示不设上限（调用方自担内存）。
    pub byte_limit: Option<u64>,
    /// 内容截断后是否把**已写出的那部分**保留。
    ///
    /// 恒为 `true` —— 保留半份仍然有用的数据比丢掉整份好，前提是
    /// 报告里写清楚了。这个字段存在只是为了让上面的取舍显式可见。
    pub keep_partial: bool,

    /// 导出哪个 DEX 输入（成员名，或单文件目标的文件名）。见 ADR-0021。
    ///
    /// `None` 的挑选规则由 [`crate::dex::read_input`] 定义：只有一个 DEX 就用它，
    /// 多于一个则**报错**并列出可选名字。
    pub member: Option<String>,
    /// 只导出这个类（smali 描述符，**精确**匹配）。
    pub class: Option<String>,
    /// 只导出描述符含该子串（大小写不敏感）的类。
    pub search: Option<String>,
    /// 只导出这个方法（smali 标识，**精确**匹配）。
    pub method: Option<String>,
    /// `dex-json` 里是否带指令数组（默认带）。
    pub include_instructions: bool,
    /// 是否带 CFG（`dex-json` 里是块 / 边计数，`dex-dot-cfg` 里是图）。
    pub include_cfg: bool,
    /// 指令文本**不解析符号**，输出原始池索引（`string@12` 这类）。
    ///
    /// 与 CLI 的 `--no-symbols` 同义。关掉时不会产出 `unsupported_operands` /
    /// `unavailable_operands` 两个计数 —— **那两个数在关闭时没有意义**，
    /// 交回 0 会被读成"解析过、全都没问题"（§7）。
    pub no_symbols: bool,
}

impl Default for ExportOptions {
    fn default() -> Self {
        Self {
            range: None,
            function: None,
            include_bytes: true,
            include_source: true,
            max_functions: 512,
            byte_limit: Some(DEFAULT_EXPORT_BYTE_LIMIT),
            keep_partial: true,
            member: None,
            class: None,
            search: None,
            method: None,
            include_instructions: true,
            include_cfg: true,
            no_symbols: false,
        }
    }
}

/// 截断账目。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Truncation {
    /// 被截断的是哪一类内容（中文，面向用户）。
    pub what: &'static str,
    /// 因预算不足而没写出的条数（下界：写出过程就此停止）。
    pub dropped: u64,
    /// 已经写出的条数。
    pub written: u64,
    /// 建议的下一步（中文）。
    pub hint: String,
}

/// 导出失败的具体原因。
///
/// 单独成一个枚举而不是复用 [`BitflipError::InvalidInput`]：这些失败**有账目**
/// （写出了多少、还差多少、要不要分批），一句话的字符串装不下，而丢掉这些
/// 数字正是 CLAUDE.md §7 禁止的"降级不写在界面上"。
///
/// `Display` 手工实现（不走 `thiserror` 的格式串），就是为了把 `notes` 一起
/// 印出来：CLI 的 `main` 只 `{}` 一次 `anyhow::Error`，如果 `notes` 不在
/// `Display` 里，那些数字到不了用户眼前 —— 存了等于没存。
#[derive(Debug, Clone)]
pub enum ExportError {
    /// 内容超过字节预算，且该格式**不能**只交一半（JSON 文档、DOT 图）。
    OverBudget {
        /// 被拒绝的内容类别（中文）。
        what: &'static str,
        /// 实际大小。
        bytes: u64,
        /// 预算。
        limit: u64,
        /// 主消息。
        message: String,
        /// 附加说明（中文），必须能显示给用户。
        notes: Vec<String>,
    },
    /// 选项与所选格式不是一回事（给 DEX 格式传地址段、给机器码格式传 DEX 选择器）。
    ///
    /// 单独一个变体而不是 `InvalidInput`：两件事对用户要做的事不一样 ——
    /// "参数写错了"是改参数，"选错了视图"是换 `--format`（ADR-0021）。
    /// **不静默忽略**：忽略一个明确给出的选择器，等于把"我按你说的做了"变成假话。
    MismatchedOptions {
        /// 主消息。
        message: String,
        /// 附加说明（中文），例如"可用值：…"。
        notes: Vec<String>,
    },
}

impl std::fmt::Display for ExportError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::OverBudget { message, notes, .. }
            | Self::MismatchedOptions { message, notes } => {
                write!(formatter, "{message}")?;
                for note in notes {
                    write!(formatter, "\n  · {note}")?;
                }
                Ok(())
            }
        }
    }
}

impl std::error::Error for ExportError {}

/// 导出结果。
#[derive(Debug, Clone)]
pub struct ExportReport {
    /// 本次导出用的格式。
    pub format: ExportFormat,
    /// 写出的字节数。
    pub bytes: u64,
    /// 写出的条目数：asm/dot 是**指令**条数，dot 另见 `items`；json 是记录数。
    pub items: u64,
    /// 截断信息；`None` = 完整导出。
    pub truncated: Option<Truncation>,
    /// 导出来源与参数。
    pub meta: ExportMeta,
    /// 降级与说明（中文）。**必须能浮到 CLI/界面**，不能只留在返回值里。
    pub notes: Vec<String>,
}

impl ExportReport {
    /// 一行中文摘要（CLI 的标准输出用）。
    #[must_use]
    pub fn summary(&self) -> String {
        let mut text = format!(
            "导出 {} · {} 字节 · {} 条{}",
            self.format.as_str(),
            self.bytes,
            self.items,
            if self.format == ExportFormat::DotCfg {
                "（指令；函数数见说明）"
            } else {
                ""
            }
        );
        if let Some(truncation) = &self.truncated {
            text.push_str(&format!(
                " · 已截断（{} 未写出：{}，已写出 {}）",
                truncation.what, truncation.dropped, truncation.written
            ));
        }
        text
    }
}

/// 导出的来源与参数（自述）。
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize)]
pub struct ExportMeta {
    /// 导出格式短名。
    pub format: String,
    /// 产出工具与版本（`bitflip 0.0.1`）。
    pub producer: String,
    /// 各层的 wire 版本，方便排查"哪个环节的语义变了"。
    pub format_versions: FormatVersions,
    /// 目标路径。
    pub target: String,
    /// 目标文件大小。
    pub file_size: u64,
    /// 架构规格（`x86_64/64/le`）；未知为 `null`。
    pub arch: Option<String>,
    /// 地址范围（半开区间）的两个端点；不过滤时为 `null`。
    pub range_from: Option<String>,
    pub range_to: Option<String>,
    /// 只导出单个函数时的入口地址；未指定为 `null`。
    pub function: Option<String>,
    /// 实际导出的 DEX 成员名；非 DEX 导出为 `null`（**不写空串**）。
    pub member: Option<String>,
    /// 导出发生的时间（RFC 3339，UTC）。
    pub generated_at: String,
}

/// 各层 wire 版本集合。
///
/// 每个**用到的**视图各占一列；**没用到的**是 `None` 而不是 `0` —— `0` 会被
/// 读成"这个文件是版本 0 的那个视图"，而事实是我们根本没碰它（§7）。
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize)]
pub struct FormatVersions {
    /// 本模块的导出格式版本。
    pub export: u32,
    /// 识别结论（`TargetInfo`）版本。
    pub info: u32,
    /// 反汇编版本。
    pub disasm: u32,
    /// 分析结论版本。
    pub analysis: u32,
    /// DEX 视图版本（[`crate::dex::DEX_FORMAT_VERSION`]）；非 DEX 导出为 `null`。
    pub dex: Option<u32>,
}

/// 执行一次导出，返回文本。
///
/// `format` 与目标能力不匹配时**报错**（例如对 AArch64 目标导出 AT&T），
/// 而不是退化成别的格式 —— 用户要的是 AT&T，给他 Intel 是欺骗。
///
/// ## 反汇编复用
///
/// 需要反汇编的格式会用 `session.disassemble(...)`**重新扫一遍**。服务端
/// 已经把反汇编缓存在 `AppState` 里，为一次导出再扫一遍纯属浪费，所以
/// 那里应当走 [`export_with_disasm`] 并把手上的那份传进来。两条路共用
/// 同一个 `write_asm`，不存在"CLI 与服务端各拼一份文本"的漂移风险。
pub fn export(
    session: &Session,
    format: ExportFormat,
    options: &ExportOptions,
) -> Result<(String, ExportReport), BitflipError> {
    // **先**查选项与视图是否匹配，再建反汇编：反过来的话，给一个 DEX 目标传
    // `--member` 会先撞上"这个目标不能反汇编"，把"选择器给错了"这条真正
    // 有用的信息盖掉。`export_with_disasm_prebuilt` 里还会再查一次（纯函数，无害）。
    check_options(format, options)?;
    match format {
        ExportFormat::AsmIntel | ExportFormat::AsmAtt => {
            let disasm = session.disassemble(crate::DisasmScanOptions::default())?;
            export_with_disasm(session, &disasm, format, options)
        }
        _ => export_with_disasm_prebuilt(session, None, format, options),
    }
}

/// 用调用方**已经建好的**反汇编做导出（服务端复用缓存的那份）。
///
/// `disasm` 只会被 `asm-*` 用到；其余格式忽略它。若要导出的格式与
/// `disasm` 的语法风格不一致，这里会按 `format` 覆盖风格 —— 这一层
/// 自己的块级克隆，所以调用方的 `Arc<Disasm>` 不受影响。
///
/// # Errors
///
/// 与 [`export`] 相同。
pub fn export_with_disasm(
    session: &Session,
    disasm: &crate::Disasm,
    format: ExportFormat,
    options: &ExportOptions,
) -> Result<(String, ExportReport), BitflipError> {
    export_with_disasm_prebuilt(session, Some(disasm), format, options)
}

/// 两种入口的公共实现。`disasm` 为 `None` 时由 `session` 现建一份。
fn export_with_disasm_prebuilt(
    session: &Session,
    disasm: Option<&crate::Disasm>,
    format: ExportFormat,
    options: &ExportOptions,
) -> Result<(String, ExportReport), BitflipError> {
    // 先查选项与视图是否匹配：不匹配时**一个字节都不该写出**（ADR-0021）。
    // 放在最前面还有个实际好处：`--function` 打错时不必先跑一遍分析。
    check_options(format, options)?;

    let job = session.detached_job();
    let mut meta = build_meta(session, format, options);

    // 截断账目里"少的是什么"随格式而定：反汇编是"指令"，DOT 是"基本块"。
    let item_kind: &'static str = match format {
        ExportFormat::DotCfg | ExportFormat::DexDotCfg => "基本块",
        _ => "指令",
    };
    // 截断的"下一步怎么办"也必须随视图而定：给 DEX 的用户推荐 `--from/--to`
    // 是在推荐一个我们自己会**报错**的选项（DEX 没有线性地址空间）。
    let truncation_hint: &'static str = if format.is_dex() {
        "用 --class / --search 缩小范围，或调大 --limit-bytes"
    } else {
        "用 --from/--to 按地址段分批导出，或调大 --limit-bytes"
    };
    let mut writer = ExportWriter::new(options.byte_limit, item_kind);
    let mut notes: Vec<String> = Vec::new();

    let items: u64 = match format {
        ExportFormat::DexJson | ExportFormat::DexSmali | ExportFormat::DexDotCfg => {
            write_dex(session, &mut writer, format, options, &mut meta, &mut notes)?
        }
        ExportFormat::AsmIntel | ExportFormat::AsmAtt => {
            // 语法风格设在**反汇编视图**上，而不是在导出层另渲染一遍 ——
            // 只有一条渲染路径，导出的文本与界面走的是同一份代码。
            //
            // 换风格时 clone 一份视图（索引仍是同一个 `Arc`）：调用方交进来的
            // 那份（服务端缓存共享的）不该被我们的风格选择影响。
            let style = match format {
                ExportFormat::AsmAtt => bitflip_arch::TextStyle::Att,
                _ => bitflip_arch::TextStyle::Intel,
            };
            let mut owned;
            let styled;
            let disasm: &crate::Disasm = match disasm {
                Some(existing) if existing.text_style == style => existing,
                Some(existing) => {
                    styled = existing.with_text_style(style);
                    &styled
                }
                None => {
                    owned = session.disassemble(crate::DisasmScanOptions::default())?;
                    owned.set_text_style(style);
                    &owned
                }
            };
            write_asm(&mut writer, disasm, format, options, &meta, &mut notes)?
        }
        ExportFormat::JsonFunctions => {
            let analysis = session.analysis(&job)?;
            write_json_functions(&mut writer, &analysis, options, &meta, &mut notes)?
        }
        ExportFormat::JsonSymbols => {
            write_json_symbols(&mut writer, session.parsed(), options, &meta, &mut notes)?
        }
        ExportFormat::JsonXrefs => {
            let analysis = session.analysis(&job)?;
            write_json_xrefs(&mut writer, &analysis, options, &meta, &mut notes)?
        }
        ExportFormat::JsonStructs => {
            write_json_structs(&mut writer, session, options, &meta, &mut notes)?
        }
        ExportFormat::JsonLibraries => {
            write_json_libraries(&mut writer, session.parsed(), options, &meta, &mut notes)?
        }
        ExportFormat::JsonCallGraph => {
            let analysis = session.analysis(&job)?;
            write_json_callgraph(&mut writer, &analysis, options, &meta, &mut notes)?
        }
        ExportFormat::DotCfg => {
            let analysis = session.analysis(&job)?;
            write_dot_cfg(&mut writer, &analysis, options, &meta, &mut notes)?
        }
        ExportFormat::PseudoC => {
            let analysis = session.analysis(&job)?;
            write_pseudo_c(
                session,
                &mut writer,
                &analysis,
                options,
                &meta,
                &mut notes,
                false,
            )?
        }
        ExportFormat::PseudoCStructured => {
            let analysis = session.analysis(&job)?;
            write_pseudo_c(
                session,
                &mut writer,
                &analysis,
                options,
                &meta,
                &mut notes,
                true,
            )?
        }
    };

    let truncated = truncation_of(&writer, truncation_hint);
    let text = writer.finish();
    let report = ExportReport {
        format,
        bytes: text.len() as u64,
        items,
        truncated,
        meta,
        notes,
    };
    Ok((text, report))
}

/// 组装来源信息。
///
/// `member` 由调用方在**真的挑定了**之后填进来（`write_dex` 会覆盖它）：
/// 这里先给 `options.member`，导出的内容里则是实际读到的那个名字 ——
/// 两者在"没给 member、目标只有一个 DEX"时必须一致，不一致就是我们在骗人。
fn build_meta(session: &Session, format: ExportFormat, options: &ExportOptions) -> ExportMeta {
    let info = session.info();
    ExportMeta {
        format: format.as_str().to_string(),
        producer: format!("bitflip {}", crate::version()),
        format_versions: FormatVersions {
            export: EXPORT_FORMAT_VERSION,
            info: INFO_FORMAT_VERSION,
            disasm: DISASM_FORMAT_VERSION,
            analysis: ANALYSIS_FORMAT_VERSION,
            // 只有 DEX 视图的导出才带上这一列；别的格式给 `null` 而不是 0。
            dex: format.is_dex().then_some(crate::dex::DEX_FORMAT_VERSION),
        },
        target: info.path.clone(),
        file_size: info.file_size,
        arch: info.arch.clone(),
        range_from: options.range.map(|(from, _)| hex16(from)),
        range_to: options.range.map(|(_, to)| hex16(to)),
        function: options.function.map(hex16),
        member: options.member.clone(),
        generated_at: now_rfc3339(),
    }
}

/// 选项与所选视图是否匹配。**不匹配就报错**（ADR-0021）。
///
/// # 为什么不能"忽略用不上的选项"
///
/// 用户敲了 `--function 0x401000` 又选了 `dex-json`，只有三种做法：报错、
/// 忽略、或者拿去当别的东西用。后两种都会让用户按自己的意图读一份**不是**
/// 那个意图的输出。CLAUDE.md §7 的"拿不到就说拿不到"在这里的形态是
/// "这个选项在这个视图上不成立，就说不成立"。
///
/// # 为什么是公开的
///
/// 导出路径自己会先调它一遍，但**调用方可能在这之前先做别的事**：服务端
/// 为了复用缓存的反汇编，会在 `export_with_disasm` 之前先取一份 `Disasm`，
/// 而归档目标上那一步会先失败（"成员清单在文件末尾"）——
/// 于是"选择器给错了"这条真正有用的信息被盖掉，实测在真实 APK 上就是这样
/// 漏出来的。所以这个检查必须能**在别的动作之前**单独调一次。
pub fn check_options(format: ExportFormat, options: &ExportOptions) -> Result<(), BitflipError> {
    let dex_selectors: Vec<&str> = [
        options.member.is_some().then_some("member"),
        options.class.is_some().then_some("class"),
        options.search.is_some().then_some("search"),
        options.method.is_some().then_some("method"),
    ]
    .into_iter()
    .flatten()
    .collect();

    if format.is_dex() {
        let wrong: Vec<&str> = [
            options.range.is_some().then_some("--from/--to"),
            options.function.is_some().then_some("--function"),
        ]
        .into_iter()
        .flatten()
        .collect();
        if !wrong.is_empty() {
            return Err(ExportError::MismatchedOptions {
                message: format!(
                    "{} 对 DEX 视图没有意义（本次格式 {}）：DEX 没有线性地址空间，也没有函数入口",
                    wrong.join(" / "),
                    format.as_str()
                ),
                notes: vec![
                    "DEX 里找代码用类与方法：--class 'Lcom/Foo;' / --search 子串 / --method 'Lcom/Foo;->bar(I)V'"
                        .to_string(),
                    "地址段与单个函数是机器码视图（PE / ELF / …）的概念，请改用 asm-intel / json-functions / dot-cfg"
                        .to_string(),
                ],
            }
            .into());
        }
        return Ok(());
    }

    if !dex_selectors.is_empty() {
        return Err(ExportError::MismatchedOptions {
            message: format!(
                "{} 是 DEX 视图的选择器，但本次格式是 {}：一套选择器只对一个视图有意义",
                dex_selectors.join(" / "),
                format.as_str()
            ),
            notes: vec![
                "要看 DEX 就用 --format dex-json / dex-smali / dex-dot-cfg（把 --member 指向 classes*.dex）"
                    .to_string(),
                "机器码目标按地址选：--from/--to / --function".to_string(),
            ],
        }
        .into());
    }
    Ok(())
}

/// 当前时间（RFC 3339，UTC）。
///
/// 不引入 `chrono`/`time`：只要一个时间戳而已，为一个字段拖进一个日期库
/// 不划算。用 `SystemTime` 自己换算 —— 闰年规则在民用日期上很简单，
/// 而且这里的用途是"这次导出是什么时候做的"，不是精密的日历计算。
fn now_rfc3339() -> String {
    let seconds = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| d.as_secs());

    let days = seconds / 86_400;
    let seconds_of_day = seconds % 86_400;
    let (hour, minute, second) = (
        seconds_of_day / 3600,
        (seconds_of_day % 3600) / 60,
        seconds_of_day % 60,
    );
    let (year, month, day) = civil_from_days(days as i64);
    format!("{year:04}-{month:02}-{day:02}T{hour:02}:{minute:02}:{second:02}Z")
}

/// 自 1970-01-01 起的天数 → 民用日期（Howard Hinnant 的算法）。
fn civil_from_days(days: i64) -> (i64, u32, u32) {
    let z = days + 719_468;
    let era = if z >= 0 { z } else { z - 146_096 } / 146_097;
    let doe = z - era * 146_097;
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let year = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let day = (doy - (153 * mp + 2) / 5 + 1) as u32;
    let month = if mp < 10 { mp + 3 } else { mp - 9 } as u32;
    (if month <= 2 { year + 1 } else { year }, month, day)
}

/// 带字节预算的写出器。
///
/// **在写出处**做判断，而不是先拼好整串再截断：后者要先把全部内容物化，
/// 大目标上等于把"限制内存"这件事做反了。
///
/// 只有**流式**格式（反汇编文本、DOT）用它；JSON 是单个文档，截断它只会
/// 得到解析不了的半份，所以走 [`write_document`] 的"超了就报错"路径。
struct ExportWriter {
    buffer: String,
    limit: Option<u64>,
    /// 上一次写出是否因为预算被拒。
    blocked: bool,
    /// 被拒次数（条数）。
    blocked_items: u64,
    /// 成功写出的条数。
    written_items: u64,
    /// 被截断的是哪一类内容（中文）。
    what: &'static str,
}

impl ExportWriter {
    fn new(limit: Option<u64>, what: &'static str) -> Self {
        Self {
            buffer: String::new(),
            limit,
            blocked: false,
            blocked_items: 0,
            written_items: 0,
            what,
        }
    }

    /// 试着写一条。返回是否写出去了。
    ///
    /// 一旦被拒就**不再尝试**（`blocked`），否则后面的短行会零散地补进来，
    /// 输出会变成"缺中间一段"，比明确的截断更糟。
    fn push_line(&mut self, line: &str) -> bool {
        if self.blocked {
            self.blocked_items += 1;
            return false;
        }
        let needed = line.len() as u64;
        if let Some(limit) = self.limit {
            if self.buffer.len() as u64 + needed > limit {
                self.blocked = true;
                self.blocked_items += 1;
                return false;
            }
        }
        self.buffer.push_str(line);
        self.written_items += 1;
        true
    }

    /// 注释头不计入条目数，但仍然受预算约束（否则头部本身可能撑爆）。
    fn push_raw(&mut self, text: &str) {
        if self.blocked {
            return;
        }
        if let Some(limit) = self.limit {
            if self.buffer.len() as u64 + text.len() as u64 > limit {
                self.blocked = true;
                return;
            }
        }
        self.buffer.push_str(text);
    }

    /// 已写出的字节数（供错误报告与测试断言用）。
    fn len(&self) -> u64 {
        self.buffer.len() as u64
    }

    fn finish(self) -> String {
        self.buffer
    }
}

/// 构造截断账目（统一口径，免得各处写法不一致）。
fn truncation_of(writer: &ExportWriter, hint: &str) -> Option<Truncation> {
    writer.blocked.then(|| Truncation {
        what: writer.what,
        dropped: writer.blocked_items,
        written: writer.written_items,
        hint: hint.to_string(),
    })
}

/// 反汇编文本。
fn write_asm(
    writer: &mut ExportWriter,
    disasm: &crate::Disasm,
    format: ExportFormat,
    options: &ExportOptions,
    meta: &ExportMeta,
    notes: &mut Vec<String>,
) -> Result<u64, BitflipError> {
    let style = match format {
        ExportFormat::AsmAtt => bitflip_arch::TextStyle::Att,
        _ => bitflip_arch::TextStyle::Intel,
    };

    // AT&T 是 x86 族的写法。对别的架构套用会产出**谁也不认识的文本**，
    // 所以直接拒绝（CLAUDE.md §7：未实现的能力明确报错，不给替代品）。
    //
    // 用 `NotYetImplemented` 而不是 `InvalidInput`：用户的参数没写错，
    // 是这项能力还没做。混成"输入无效"会让用户去改格式名，而正确的
    // 反应是换 `asm-intel` 或等这个里程碑。
    if style == bitflip_arch::TextStyle::Att && !is_x86_family(meta.arch.as_deref()) {
        return Err(BitflipError::not_implemented(
            "AT&T 反汇编文本目前只对 x86 族目标实现（M9）：非 x86 目标请改用 --format asm-intel",
        ));
    }

    writer.push_raw(&format!(
        "# bitflip-export v{} format={} target={} arch={} generated_at={}\n",
        EXPORT_FORMAT_VERSION,
        format.as_str(),
        meta.target,
        meta.arch.as_deref().unwrap_or("unknown"),
        meta.generated_at
    ));
    writer.push_raw(&format!(
        "# disasm v{} analysis v{} info v{}\n",
        meta.format_versions.disasm, meta.format_versions.analysis, meta.format_versions.info
    ));
    if let Some((from, to)) = options.range {
        writer.push_raw(&format!("# range {} .. {}\n", hex16(from), hex16(to)));
    }
    if let Some(func) = options.function {
        writer.push_raw(&format!("# function {}\n", hex16(func)));
    }
    writer.push_raw(&format!("# producer {}\n", meta.producer));
    writer.push_raw("# 地址 机器码 指令；<无法解码> 表示该位置解不出指令（不是数据结论）\n");

    let mut cursor = disasm.cursor(0);
    let mut decoded_failures: u64 = 0;
    let mut written: u64 = 0;

    while let Some(insn) = cursor.render_next() {
        let address = u64::from_str_radix(&insn.address, 16).unwrap_or(0);
        if let Some((from, to)) = options.range {
            if address < from || address >= to {
                continue;
            }
        }
        if let Some(func) = options.function {
            if address < func {
                continue;
            }
            // 单函数导出：越过函数末尾就停。边界的权威来源是函数区间，
            // 这里只做"至少不要导出别的函数"的粗截断 —— 精确边界由
            // 函数清单提供（`json-functions`），两者不混用。
            if address > func {
                break;
            }
        }

        if insn.text == "<无法解码>" {
            decoded_failures += 1;
        }
        let mut line = String::with_capacity(64);
        line.push_str(&insn.address);
        if options.include_bytes {
            line.push_str("  ");
            line.push_str(&insn.bytes);
        }
        line.push_str("  ");
        line.push_str(&insn.text);
        if options.include_source {
            if let (Some(file), Some(row)) = (&insn.file, insn.line) {
                line.push_str(&format!("  # {file}:{row}"));
            }
        }
        if !insn.reachable {
            // 只线性扫到、没被证明可达 —— 如实标注，别让它看起来同等可信。
            line.push_str("  # 仅线性扫描");
        }
        line.push('\n');

        if !writer.push_line(&line) {
            break;
        }
        written += 1;
    }

    if decoded_failures > 0 {
        notes.push(format!(
            "有 {decoded_failures} 个位置解不出指令（文本为 <无法解码>）：那说明不了它们是数据，只说明这些字节不构成一条合法指令"
        ));
    }
    let stats = disasm.wire_stats();
    notes.push(format!(
        "地址空间共索引 {} 条指令（可达 {} / 仅线性 {}），本次写出 {written} 条",
        stats.indexed, stats.reachable, stats.linear_only
    ));
    for note in &disasm.notes {
        notes.push(format!("反汇编说明：{note}"));
    }
    Ok(written)
}

/// 头两行：格式版本与来源。伪代码与其他文本格式共用同一套溯源头，
/// 这样"这份输出是谁生成的、针对哪个文件"在任何格式里都是同一处答案。
fn pseudo_header(meta: &ExportMeta, options: &ExportOptions) -> String {
    let mut out = String::new();
    out.push_str(&format!(
        "# bitflip-export v{} format={} target={} arch={} generated_at={}\n",
        EXPORT_FORMAT_VERSION,
        ExportFormat::PseudoC.as_str(),
        meta.target,
        meta.arch.as_deref().unwrap_or("unknown"),
        meta.generated_at
    ));
    if let Some((from, to)) = options.range {
        out.push_str(&format!("# range {} .. {}\n", hex16(from), hex16(to)));
    }
    if let Some(func) = options.function {
        out.push_str(&format!("# function {}\n", hex16(func)));
    }
    out.push_str(&format!("# producer {}\n", meta.producer));
    out
}

/// C 风格伪代码（有界子集）。
///
/// **这不是反编译器**，见 `docs/DECOMPILER-SCOPE.md`。输出遵守三条硬约束：
///
/// 1. **每条语句带来源指令地址** —— 用户能逐句回查机器码；
/// 2. **不结构化** —— 条件跳转是 `goto`，不是 `if/while/for`；
/// 3. **不猜** —— 编不出来的东西写注释并计数，不填默认值。
///
/// 关于架构：伪代码的表达式翻译目前只在 **x86_64** 上做过寄存器命名核对。
/// 其他架构上寄存器名拿不到，模块会如实报告 `RegistersUnnamed` 并以编号显示 ——
/// 那种输出仍然忠实（编号是真的），只是不好读。**我们不会为此编一套没核对过的
/// 寄存器名**（错的寄存器名比编号更糟，CLAUDE.md §7）。
fn write_pseudo_c(
    session: &Session,
    writer: &mut ExportWriter,
    analysis: &TargetAnalysis,
    options: &ExportOptions,
    meta: &ExportMeta,
    notes: &mut Vec<String>,
    structured: bool,
) -> Result<u64, BitflipError> {
    let disasm = session.disassemble(crate::DisasmScanOptions::default())?;

    // 寄存器名来自 capstone 后端，**不是**本层自己维护的表。
    //
    // `RegId` 是 capstone 的原始寄存器编号（不是从 0 连续排的序号）。
    // 实测踩过：按"0=rax, 1=rcx…"写一张表，真实目标上 `RegId(44)`、
    // `RegId(231)` 全判成未知，绝大多数指令退化成"无法翻译"。
    // 权威来源是后端的 `register_name`，它的文档也明确了
    // "查不到返回 None，调用方如实显示未识别寄存器"。
    //
    // 没有后端时解析器恒给 `None`，输出会如实标注"寄存器名未覆盖" —— **不猜**（§7）。
    let renderer = disasm.renderer.clone();
    let namer = |id: u16| -> Option<String> {
        renderer
            .as_ref()
            .and_then(|r| r.register_name(bitflip_arch::RegId(id)))
    };
    // 助记符解析器：把 MnemonicId 翻成可读文本，让算术/逻辑指令按真实运算符还原
    // （否则 `add`/`xor r,r` 会被错写成赋值）。后端提供，与寄存器名同源。
    let mnemonic = |m: bitflip_arch::MnemonicId| -> Option<String> {
        renderer.as_ref().and_then(|r| r.mnemonic_name_by_id(m))
    };
    // 跳表读取器：用已构建的地址空间，按虚拟地址读只读数据（switch 跳表用）。
    // 不补零冒充：`read_window` 只返回真实读到的字节（可能到段尾截断）。
    let space = &disasm.space;
    let table_reader = |addr: u64, len: usize| -> Option<Vec<u8>> {
        space.read_window(addr, len).map(|(bytes, _span)| bytes)
    };
    // 读字节闭包（供导入边建表用），独立于 `table_reader` 以便有独立的生命周期，
    // 让 `ImportEdges` 能借用它。
    let read_bytes = |addr: u64, len: usize| space.read(addr, len);

    // 导入名解析：把间接调用/跳板里那个 IAT 槽地址翻成可读的 `模块!函数名`。
    //
    // 这里直接用 `ImportEdges::from_parts`（而不是 `build`）——`build` 只对 Mach-O 建表
    // （PE/ELF 的**调用图边**行为被验收冻结，见 import_edges 模块文档），但本处只需
    // "槽地址 → 导入条目" 这条查询，对所有带 `iat_slot` 的格式都成立，且不改动任何
    // 冻结的调用图行为。桩节范围传空：本处只走规则 1（目标本身就是槽），不需要桩识别。
    let import_edges = session.object().map(|object| {
        crate::import_edges::ImportEdges::from_parts(
            &object.imports,
            object.arch,
            Vec::new(),
            &read_bytes,
        )
    });
    let import_namer = |slot: u64| -> Option<String> {
        let edges = import_edges.as_ref()?;
        let index = edges.lookup_index(slot)?;
        let import = edges.import_at(index)?;
        Some(match (&import.name, import.ordinal) {
            (Some(name), _) => format!("{}!{name}", import.module),
            // 按序号导入：没有名字就如实写序号，**不编**一个像名字的字符串（§7）。
            (None, Some(ordinal)) => format!("{}!#{ordinal}", import.module),
            (None, None) => return None,
        })
    };

    // 异常处理器表：函数入口 → 处理器绝对地址。来自 PE `.pdata` 的 `RUNTIME_FUNCTION`
    // + `UNWIND_INFO`（EHANDLER/UHANDLER）。这是"该函数有异常处理"的权威依据。
    //
    // 需要在**克隆出的对象**上 `resolve_unwind`（解码推迟到真正要问的时刻），
    // 再按 `begin` 建索引。非 PE 格式没有 `.pdata`，这张表为空 —— 如实为空，不猜。
    let exception_handlers: std::collections::BTreeMap<u64, u64> = match session.object() {
        Some(object) => {
            let mut resolved = (**object).clone();
            resolved.resolve_unwind(session.raw_bytes(), object.image_base);
            let base = object.image_base;
            resolved
                .unwind
                .iter()
                .filter_map(|entry| {
                    entry
                        .exception_handler_rva()
                        .map(|rva| (entry.begin, base.saturating_add(u64::from(rva))))
                })
                .collect()
        }
        None => std::collections::BTreeMap::new(),
    };

    // 字符串解析：地址落在**可读、非写、非执行**的段（.rdata / __const 之类）里、且是一段
    // 以 NUL 结尾的干净可打印字节时返回它。保守判定：段权限来自 loader（事实），字节可打印性
    // 直接判（事实），不假设 UTF-8/UTF-16 编码（只收 ASCII 可打印 + 常见空白），给错会误导。
    let string_reader = |addr: u64| -> Option<String> {
        let in_rodata = disasm.space.segments().iter().any(|seg| {
            let end = seg.vaddr.saturating_add(seg.vsize);
            addr >= seg.vaddr
                && addr < end
                && seg.perms.read
                && !seg.perms.write
                && !seg.perms.execute
        });
        if !in_rodata {
            return None;
        }
        // 用 `read_window`（读可用字节，段尾会截断）而不是 `read`（读不满就整段 None）：
        // 段尾附近的字符串也能读到，不会因为"后面 512 字节不满"就整条放弃。
        let (bytes, _span) = disasm.space.read_window(addr, 512)?;
        let mut out = String::new();
        let mut terminated = false;
        for &byte in &bytes {
            if byte == 0 {
                terminated = true;
                break;
            }
            let printable = (0x20..=0x7e).contains(&byte) || matches!(byte, b'\t' | b'\r' | b'\n');
            if !printable {
                return None;
            }
            out.push(byte as char);
            if out.len() >= 400 {
                return None;
            }
        }
        // 至少几个字符、且确实以 NUL 结尾，才认为是一段字符串（避免把短数据片段当串）。
        if terminated && out.len() >= 4 {
            Some(out)
        } else {
            None
        }
    };

    writer.push_raw(&pseudo_header(meta, options));
    if structured {
        writer.push_raw(
            "# 说明：这是**有界子集**，不是反编译器。已做控制流结构化：可归约 CFG 上的 \
             if/else/while/do-while 从控制流图还原，形态拿不准处仍保留 if (cond) goto；\
             未做类型推断。\n",
        );
    } else {
        writer.push_raw(
            "# 说明：这是**有界子集**，不是反编译器。条件跳转以 goto 出现，\
             未还原 if/while/for；未做类型推断。\n",
        );
    }
    writer.push_raw("# 每条语句前的地址是它来自哪条指令 —— 请对着反汇编核对，不要直接相信。\n");

    let mut selected: Vec<&crate::CfgWire> = analysis
        .cfgs()
        .filter(|cfg| {
            let entry = u64::from_str_radix(&cfg.entry, 16).unwrap_or(0);
            if let Some(func) = options.function {
                return entry == func;
            }
            match options.range {
                None => true,
                Some((from, to)) => entry >= from && entry < to,
            }
        })
        .collect();
    selected.sort_by_key(|cfg| u64::from_str_radix(&cfg.entry, 16).unwrap_or(0));

    let limit = options.max_functions;
    let skipped = selected.len().saturating_sub(limit);
    selected.truncate(limit);

    let mut statements: u64 = 0;
    let mut untranslated: u64 = 0;
    let mut unnamed: u64 = 0;

    for cfg in &selected {
        let entry = u64::from_str_radix(&cfg.entry, 16).unwrap_or(0);

        // 名字：只在 `named` 为真时采用。**不编造** `func_xxx`（§7）。
        let name = analysis
            .functions()
            .iter()
            .find(|f| u64::from_str_radix(&f.start, 16) == Ok(entry))
            .filter(|f| f.named)
            .map(|f| f.name.clone());
        if name.is_none() {
            unnamed += 1;
        }

        // 该函数的指令区间：取所有块的最小 start 与最大 end。
        let Some(first) = cfg.blocks.first() else {
            continue;
        };
        let from = cfg
            .blocks
            .iter()
            .filter_map(|b| u64::from_str_radix(&b.start, 16).ok())
            .min()
            .unwrap_or(0);
        let to = cfg
            .blocks
            .iter()
            .filter_map(|b| u64::from_str_radix(&b.end, 16).ok())
            .max()
            .unwrap_or(0);
        let _ = first;

        let insns = disasm.decode_range(from, to);
        let inner = bitflip_analyze::Cfg::build(&insns);
        let code = if structured {
            bitflip_analyze::decompile_structured(
                entry,
                name.as_deref(),
                &insns,
                &inner,
                &namer,
                bitflip_analyze::Resolvers {
                    table: Some(&table_reader),
                    import: Some(&import_namer),
                    string: Some(&string_reader),
                    mnemonic: Some(&mnemonic),
                    exception_handler: exception_handlers.get(&entry).copied(),
                },
            )
        } else {
            bitflip_analyze::decompile_function(
                entry,
                name.as_deref(),
                &insns,
                &inner,
                &namer,
                bitflip_analyze::Resolvers {
                    table: None,
                    import: Some(&import_namer),
                    string: Some(&string_reader),
                    mnemonic: Some(&mnemonic),
                    exception_handler: None,
                },
            )
        };

        statements += code.statement_count as u64;
        for note in &code.notes {
            if let bitflip_analyze::PseudocodeNote::Untranslated { count, .. } = note {
                untranslated += *count as u64;
            }
        }

        // 逐行推入而不是整块 `push_raw`：只有逐行才拿得到返回值，
        // 而"是否被字节预算截断"必须让用户知道（§7），不能悄悄少给。
        let text = bitflip_analyze::render_function_text(&code);
        let mut blocked = false;
        for line in text.lines() {
            if !writer.push_line(line) {
                blocked = true;
                break;
            }
        }
        if blocked {
            notes.push(
                "输出达到字节预算后停止：用 --from/--to 缩小地址范围，或调大 --limit-bytes"
                    .to_string(),
            );
            break;
        }
    }

    if skipped > 0 {
        notes.push(format!(
            "还有 {skipped} 个函数未导出（超过 --max-functions {limit}）：这是截断，不是「没有更多函数」"
        ));
    }
    if unnamed > 0 {
        notes.push(format!(
            "有 {unnamed} 个函数在符号表里没有名字，输出里用入口地址代替 —— 未编造名称"
        ));
    }
    if untranslated > 0 {
        notes.push(format!(
            "共 {untranslated} 条指令无法翻译成 C 语句（输出里是注释）：这些位置**没有**被猜成某个表达式"
        ));
    }
    if structured {
        notes.push(
            "伪代码是有界子集：已做控制流结构化（if/else/while/do-while 从 CFG 还原，\
             形态拿不准处仍保留 if (cond) goto）、未做类型推断。\
             不要把它当作可编译的源码，也不要当作「已还原的逻辑」"
                .to_string(),
        );
    } else {
        notes.push(
            "伪代码是有界子集：条件跳转以 goto 出现、未做类型推断、未做控制流结构化。\
             不要把它当作可编译的源码，也不要当作「已还原的逻辑」"
                .to_string(),
        );
    }
    Ok(statements)
}

/// 判定架构是否属于 x86 族（用 `TargetInfo::arch` 的规格字符串）。
fn is_x86_family(arch: Option<&str>) -> bool {
    match arch {
        Some(spec) => {
            spec.starts_with("x86") || spec.starts_with("i386") || spec.starts_with("i686")
        }
        None => false,
    }
}

/// DEX 视图的导出（`dex-json` / `dex-smali` / `dex-dot-cfg`）。见 `docs/APK-DEX-DESIGN.md` §M2c。
///
/// # 三条路共用什么
///
/// 1. **挑输入**：`crate::dex::read_input`（只有一个 DEX 就用它，多于一个必须指名）。
/// 2. **挑类与方法**：一份逻辑、一个顺序（`class_defs` 顺序、类内 `method_idx` 顺序）。
/// 3. **渲染指令**：`render_instruction_with_symbols` / `project_code_item` ——
///    导出文件里的指令文本与界面上看到的是**同一份代码**产出的。在这里另写一个
///    渲染器，就等于允许"导出文件与界面不一样"，而那种不一致没人会去比对。
///
/// # 确定性（§M2c 的第 3 条硬要求）
///
/// 全程按下标顺序遍历，不碰 `HashMap`：同一个输入连导两次必须逐字节相同，
/// 否则 CI 的差分会把"顺序变了"报成"内容变了"。
fn write_dex(
    session: &Session,
    writer: &mut ExportWriter,
    format: ExportFormat,
    options: &ExportOptions,
    meta: &mut ExportMeta,
    notes: &mut Vec<String>,
) -> Result<u64, BitflipError> {
    let input = crate::dex::read_input(session, options.member.as_deref())?;
    // 信封里写**实际读到**的那个成员名：没给 `member` 时也不能留空 ——
    // 读的人要靠它知道自己手里这份文件是哪个 dex。
    meta.member = Some(input.name.clone());
    notes.extend(input.structure.notes.iter().cloned());

    let selected = select_dex_classes(&input.name, &input.structure, options, notes)?;
    // M9 的这两个选项在 DEX 视图上没有对应物：DEX 的文本导出没有"字节"列
    // （原始码元还没接到导出层），也没有源码行（debug_info 还没解析）。
    // **关掉一个本来就没有的东西不会让输出少东西**，所以这不是"静默忽略选择器"；
    // 但也不能让它看起来生效了 —— 写进说明，用户才知道这个开关没起作用。
    if !options.include_bytes {
        notes.push("--no-bytes 对 DEX 视图没有影响：文本导出里没有字节列".to_string());
    }
    if !options.include_source {
        notes.push(
            "--no-source 对 DEX 视图没有影响：DEX 视图还没有源码行（debug_info 未解析）"
                .to_string(),
        );
    }
    match format {
        ExportFormat::DexJson => write_dex_json(&input, &selected, writer, options, meta, notes),
        ExportFormat::DexSmali => write_dex_smali(&input, &selected, writer, options, meta, notes),
        _ => write_dex_dot_cfg(&input, &selected, writer, options, meta, notes),
    }
}

/// 选中的类（下标 + 描述符），顺序 = `class_defs` 顺序。
///
/// **筛空是错误，不是"导出了 0 个类"**：一份空文件与"筛错了 / 类写错了"在结果上
/// 长得一模一样，而写文件这个动作会让人以为"就是这样"。CLI 的 `--search`（一条
/// **列表**命令）搜不到是合法答案 —— 那里输出里写着"扫描 N 个、匹配 0 个"；
/// 导出没有那行输出，所以只能报错。
fn select_dex_classes(
    member: &str,
    structure: &crate::dex::DexStructure,
    options: &ExportOptions,
    notes: &mut Vec<String>,
) -> Result<Vec<(usize, String)>, BitflipError> {
    let needle = options
        .search
        .as_deref()
        .map(str::to_lowercase)
        .filter(|text| !text.is_empty());

    let mut skipped = 0usize;
    let mut selected: Vec<(usize, String)> = Vec::new();
    for class in 0..structure.class_count() {
        let Some(descriptor) = structure.class_descriptor(class) else {
            skipped += 1;
            continue;
        };
        if let Some(wanted) = options.class.as_deref() {
            if descriptor != wanted {
                continue;
            }
        }
        if let Some(needle) = needle.as_deref() {
            if !descriptor.to_lowercase().contains(needle) {
                continue;
            }
        }
        // `--method` 也在这里筛类：不然只导一个方法时，输出里会带上**所有**
        // 类的头部（实测一个真实 APK 上是 7643 个 `.class` 段落陪 1 个方法），
        // 那份文件看起来像"整个 dex 的清单"，而用户只问了一个方法。
        if let Some(wanted) = options.method.as_deref() {
            if !structure
                .class_methods(class)
                .into_iter()
                .any(|index| structure.method_signature(index).as_deref() == Some(wanted))
            {
                continue;
            }
        }
        selected.push((class, descriptor.to_string()));
    }

    if selected.is_empty() {
        if let Some(wanted) = options.class.as_deref() {
            let hint = if wanted.starts_with('L') && wanted.ends_with(';') {
                ""
            } else {
                "（本命令只做精确匹配：类要写成 smali 描述符，如 `Lcom/Foo;`）"
            };
            return Err(BitflipError::InvalidInput(format!(
                "{member} 里没有类 {wanted}{hint}",
            )));
        }
        if let Some(wanted) = options.method.as_deref() {
            let hint = if wanted.contains("->") && wanted.contains('(') {
                ""
            } else {
                "（方法要写成 smali 标识，如 `Lcom/Foo;->bar(I)V`）"
            };
            return Err(BitflipError::InvalidInput(format!(
                "{member} 里找不到方法 {wanted}{hint}"
            )));
        }
        let needle = needle.unwrap_or_default();
        return Err(BitflipError::InvalidInput(format!(
            "{member} 里没有描述符含「{needle}」的类（这个 DEX 有 {} 个类）：\
             导出一个空文件与'筛错了'分辨不出来，所以这里报错",
            structure.class_count()
        )));
    }

    if skipped > 0 {
        notes.push(format!(
            "有 {skipped} 个类的描述符解析不出来（类定义指向越界的 type_id），已如实跳过"
        ));
    }
    Ok(selected)
}

/// 一个类里要导出的方法下标（类内 `method_idx` 顺序）。
///
/// `options.method` 给了就只留标识完全相等的那个 —— 与 CLI / 服务端同一立场：
/// 短名、子串、参数通配混在一个结果里，"命中哪个"就说不清了。
fn selected_methods(
    structure: &crate::dex::DexStructure,
    class: usize,
    options: &ExportOptions,
) -> Vec<usize> {
    let all = structure.class_methods(class);
    match options.method.as_deref() {
        None => all,
        Some(wanted) => all
            .into_iter()
            .filter(|index| structure.method_signature(*index).as_deref() == Some(wanted))
            .collect(),
    }
}

/// 渲染一条 DEX 指令，并把"账"记进 `rendered`。返回渲染失败数。
///
/// `resolver` 为 `None` 时输出原始池索引（`--no-symbols`）：那时**不记账** ——
/// 交回 0 会被读成"解析过、全都没问题"（§7）。关掉符号这件事由 `symbols.enabled`
/// 与 note 说清楚。
fn render_dex_instruction(
    instructions: &crate::dex::DexInstructions,
    index: usize,
    resolver: Option<&dyn crate::dex::DexSymbolResolver>,
    text: &mut String,
    rendered: &mut crate::dex::DexRenderReport,
) -> u64 {
    match instructions.render_instruction_with_symbols(index, resolver, text) {
        Ok(Some(crate::dex::DexSymbolOutcome::NotSupported)) => {
            rendered.unsupported_operands += 1;
            0
        }
        Ok(Some(crate::dex::DexSymbolOutcome::Unavailable)) => {
            rendered.unavailable_operands += 1;
            0
        }
        Ok(_) => {
            rendered.instructions += 1;
            0
        }
        Err(error) => {
            text.clear();
            text.push_str(&format!("<渲染失败：{error}>"));
            1
        }
    }
}

/// DEX 结构快照（JSON）。
///
/// 一次成文（`write_document`）：JSON 是单个文档，截断它只会得到解析不了的半份，
/// 所以超预算时**报错**并给出缩小范围的办法 —— 与 `json-functions` 同一条规矩。
fn write_dex_json(
    input: &crate::dex::DexInput,
    selected: &[(usize, String)],
    writer: &mut ExportWriter,
    options: &ExportOptions,
    meta: &ExportMeta,
    notes: &mut Vec<String>,
) -> Result<u64, BitflipError> {
    let structure = &input.structure;
    let symbols = structure.symbols();
    let resolver: Option<&dyn crate::dex::DexSymbolResolver> = if options.no_symbols {
        None
    } else {
        Some(&symbols)
    };

    // `max_functions` 对 DEX 是"最多多少个**方法**"的口径（不新增 `max_methods`）。
    let method_budget = options.max_functions;
    let mut methods_written = 0usize;
    let mut methods_over_limit = 0u64;
    let mut methods_without_code = 0u64;
    let mut methods_parse_failed = 0u64;
    let mut instructions_rendered = 0u64;
    let mut render_failures = 0u64;
    let mut rendered = crate::dex::DexRenderReport::default();

    let mut classes = Vec::with_capacity(selected.len());
    for (class, descriptor) in selected {
        let methods: Vec<serde_json::Value> = selected_methods(structure, *class, options)
            .into_iter()
            .filter_map(|method| {
                let facts = structure.methods.get(method);
                let code_off = facts.map_or(0, |f| f.code_off);
                let base = json!({
                    "index": method,
                    "signature": structure.method_signature(method),
                    "name": structure.method_name(method),
                    "access_flags": facts.map_or(0, |f| f.access_flags),
                    "is_direct": facts.is_some_and(|f| f.is_direct),
                    "code_off": (code_off != 0).then(|| hex16(u64::from(code_off))),
                    "has_code": code_off != 0,
                });

                if code_off == 0 {
                    // 抽象 / native 方法是**合法结论**，不是错误，也不算"没导出来"。
                    methods_without_code += 1;
                    return Some(base);
                }
                if methods_written >= method_budget {
                    methods_over_limit += 1;
                    return None;
                }
                methods_written += 1;

                let view = match crate::dex::project_method(&input.bytes, code_off) {
                    Ok(view) => view,
                    Err(error) => {
                        // 单个方法解析失败**不放弃整次导出**：这是"这一段拿不到"，
                        // 报成整份失败会连带丢掉已经能读的几万个类。理由写进 note。
                        methods_parse_failed += 1;
                        return Some(json!({
                            "index": method,
                            "signature": structure.method_signature(method),
                            "code_off": hex16(u64::from(code_off)),
                            "has_code": true,
                            "error": error.to_string(),
                        }));
                    }
                };

                let mut instructions = Vec::new();
                if options.include_instructions {
                    for index in 0..view.instructions.len() {
                        let mut text = String::new();
                        // 渲染不出来就**不留半行**：写下去会被当成"就是这样"。
                        render_failures += render_dex_instruction(
                            &view.instructions,
                            index,
                            resolver,
                            &mut text,
                            &mut rendered,
                        );
                        instructions_rendered += 1;
                        instructions.push(json!({
                            "code_unit": hex16(u64::from(view.instructions.addresses.get(index).copied().unwrap_or(0))),
                            "text": text,
                        }));
                    }
                }

                let mut entry = base;
                let object = entry.as_object_mut().expect("json! 产出的是对象");
                object.insert("registers_size".to_string(), json!(view.registers_size));
                object.insert("ins_size".to_string(), json!(view.ins_size));
                object.insert("outs_size".to_string(), json!(view.outs_size));
                if options.include_instructions {
                    object.insert("instructions".to_string(), json!(instructions));
                }
                if options.include_cfg {
                    object.insert(
                        "cfg".to_string(),
                        json!({
                            "blocks": view.cfg.block_ids.len(),
                            "edges": view.cfg.edge_kinds.len(),
                            "unresolved_edge_targets": view.cfg.unresolved_edge_targets.len(),
                        }),
                    );
                }
                Some(entry)
            })
            .collect();

        classes.push(json!({
            "descriptor": descriptor,
            "short_name": structure.class_short_name(*class),
            "superclass": structure.superclass_descriptor(*class),
            "source_file": structure.source_file(*class),
            "access_flags": structure.classes.get(*class).map_or(0, |c| c.access_flags),
            "fields": structure.class_fields(*class).into_iter().map(|field| {
                let facts = structure.fields.get(field);
                json!({
                    "index": field,
                    "name": structure.field_name(field),
                    "type_descriptor": structure.field_type_descriptor(field),
                    "access_flags": facts.map_or(0, |f| f.access_flags),
                    "is_static": facts.is_some_and(|f| f.is_static),
                })
            }).collect::<Vec<_>>(),
            "methods": methods,
        }));
    }

    if methods_over_limit > 0 {
        notes.push(format!(
            "方法数上限为 {method_budget}（--max-functions），还有 {methods_over_limit} 个方法未导出"
        ));
    }
    if methods_without_code > 0 {
        notes.push(format!(
            "有 {methods_without_code} 个方法没有字节码（抽象 / native）：它们仍在文件里，`has_code: false` —— 这是合法结论，不是解析失败"
        ));
    }
    if methods_parse_failed > 0 {
        notes.push(format!(
            "有 {methods_parse_failed} 个方法的 code_item 解析失败：文件里给了 `error` 字段，没有假装它们没有字节码"
        ));
    }
    if render_failures > 0 {
        notes.push(format!(
            "有 {render_failures} 条指令渲染失败：位置上写了 `<渲染失败：…>`，没有留半行冒充指令"
        ));
    }

    let accounting = options.include_instructions && !options.no_symbols;
    if options.no_symbols && options.include_instructions {
        notes.push(
            "`--no-symbols`：指令文本里的池引用是原始索引，`symbols.unsupported_operands` / \
             `unavailable_operands` 为 null —— 那是'没解析'，不是'解析全通过'"
                .to_string(),
        );
    }

    let document = json!({
        "format_version": crate::dex::DEX_FORMAT_VERSION,
        "producer": meta.producer,
        "meta": meta,
        "member": input.name,
        "role": input.role,
        "size": input.bytes.len(),
        "header": {
            "class_count": structure.class_count(),
            "method_count": structure.method_count(),
            "method_count_with_code": structure.method_count_with_code(),
        },
        "totals": {
            "classes_written": classes.len(),
            "methods_written": methods_written,
            "instructions_written": instructions_rendered,
            "filtered_by_class": options.class.is_some(),
            "filtered_by_search": options.search.is_some(),
            "filtered_by_method": options.method.is_some(),
        },
        "classes": classes,
        // 降级四样：解析期说明、跳过、符号账目、截断（本格式没有流式截断，见 note）。
        "notes": notes,
        "skipped": {
            "methods_without_code": methods_without_code,
            "methods_over_limit": methods_over_limit,
            "methods_parse_failed": methods_parse_failed,
        },
        "symbols": {
            "enabled": options.include_instructions.then_some(!options.no_symbols),
            "instructions": options.include_instructions.then_some(rendered.instructions),
            // 关掉符号解析时**这两个数是 null**：给 0 会被读成"解析过、全都没问题"。
            "unsupported_operands": accounting.then_some(rendered.unsupported_operands),
            "unavailable_operands": accounting.then_some(rendered.unavailable_operands),
            "render_failures": options.include_instructions.then_some(render_failures),
        },
    });

    let text = serde_json::to_string_pretty(&document)
        .map_err(|error| BitflipError::Internal(format!("序列化 DEX 结构快照失败：{error}")))?;
    write_document(writer, &text, options, "DEX 结构快照")?;

    if render_failures > 0 {
        notes.push("（渲染失败的条数见 `symbols.render_failures`）".to_string());
    }
    Ok(classes.len() as u64)
}

/// DEX 的 smali 风格文本。
///
/// **不是可回汇编的 smali 源文件**：注解、`.line`、调试信息、泛型签名等属性没有
/// 保留，指令文本来自我们自己的渲染路径。头一行就把这件事写清楚 ——
/// 让人以为拿到的文件能喂给 `smali` 重新打包，那是彻底误导。
fn write_dex_smali(
    input: &crate::dex::DexInput,
    selected: &[(usize, String)],
    writer: &mut ExportWriter,
    options: &ExportOptions,
    meta: &ExportMeta,
    notes: &mut Vec<String>,
) -> Result<u64, BitflipError> {
    let structure = &input.structure;
    let symbols = structure.symbols();
    let resolver: Option<&dyn crate::dex::DexSymbolResolver> = if options.no_symbols {
        None
    } else {
        Some(&symbols)
    };

    writer.push_raw(&format!(
        "# bitflip-export v{} format=dex-smali target={} member={} dex v{} generated_at={}\n",
        EXPORT_FORMAT_VERSION,
        meta.target,
        input.name,
        crate::dex::DEX_FORMAT_VERSION,
        meta.generated_at
    ));
    writer.push_raw(
        "# 这是 smali **风格**的清单，不是可回汇编的 smali 源文件：\n\
         #   - 没有注解、`.line`、调试信息、泛型签名等属性；\n\
         #   - 指令文本来自 BitFlip 自己的渲染路径，解析不出符号时保留可数的池索引\n\
         #     （`string@12` 这类），不会写成 `?` / `<invalid>` 冒充结果。\n",
    );

    let method_budget = options.max_functions;
    let mut methods_written = 0usize;
    let mut methods_over_limit = 0u64;
    let mut methods_without_code = 0u64;
    let mut instructions: u64 = 0;
    let mut render_failures = 0u64;
    let mut rendered = crate::dex::DexRenderReport::default();

    'classes: for (class, descriptor) in selected {
        writer.push_line(&format!(
            "\n.class {descriptor}   super={}   source_file={}\n",
            structure.superclass_descriptor(*class).unwrap_or("（无）"),
            structure.source_file(*class).unwrap_or("（无）")
        ));
        for field in structure.class_fields(*class) {
            writer.push_line(&format!(
                ".field {} {} {}   # access_flags={:#x}\n",
                if structure.fields.get(field).is_some_and(|f| f.is_static) {
                    "static"
                } else {
                    "instance"
                },
                structure.field_type_descriptor(field).unwrap_or("?"),
                structure.field_name(field).unwrap_or("（无名）"),
                structure.fields.get(field).map_or(0, |f| f.access_flags),
            ));
        }

        for method in selected_methods(structure, *class, options) {
            let facts = structure.methods.get(method);
            let code_off = facts.map_or(0, |f| f.code_off);
            let signature = structure
                .method_signature(method)
                .unwrap_or_else(|| format!("<方法 {method} 的标识取不到>"));
            let mut header = format!(".method {signature}");
            if code_off == 0 {
                methods_without_code += 1;
                header.push_str("   # 无字节码：抽象或 native 方法\n");
                writer.push_line(&header);
                writer.push_line(".end method\n");
                continue;
            }
            if methods_written >= method_budget {
                methods_over_limit += 1;
                continue;
            }
            methods_written += 1;

            let view = match crate::dex::project_method(&input.bytes, code_off) {
                Ok(view) => view,
                Err(error) => {
                    // 解析不了就说解析不了，并把它计入截断账目 —— 不能安静跳过，
                    // 否则读者会以为这个方法本来就没有指令。
                    writer.push_line(&format!("{header}   # code_item 解析失败：{error}\n"));
                    writer.push_line(".end method\n");
                    continue;
                }
            };
            header.push_str(&format!(
                "   # code_off={} registers={} ins={} outs={}\n",
                hex16(u64::from(code_off)),
                view.registers_size,
                view.ins_size,
                view.outs_size
            ));
            if !writer.push_line(&header) {
                // 预算耗尽：后面的都不再写了，账目由 `truncation_of` 给出。
                break 'classes;
            }

            for index in 0..view.instructions.len() {
                let mut text = String::new();
                render_failures += render_dex_instruction(
                    &view.instructions,
                    index,
                    resolver,
                    &mut text,
                    &mut rendered,
                );
                // 地址前缀**已经**在 `text` 里（`render_instruction*` 的约定，
                // 与 CFG 文本一致），这里只加缩进 —— 再加一次会变成
                // `0000: 0000: new-instance …`。
                if !writer.push_line(&format!("    {text}\n")) {
                    break 'classes;
                }
                instructions += 1;
            }

            if options.include_cfg {
                let mut cfg = String::new();
                crate::dex::render_cfg_text(&view, &mut cfg);
                // CFG 文本**逐行加 `#`**：这段不是 smali 语法，标成注释一眼可见。
                for line in cfg.lines() {
                    if !writer.push_line(&format!("# {line}\n")) {
                        break 'classes;
                    }
                }
            }
            if !writer.push_line(".end method\n") {
                break 'classes;
            }
        }
    }

    notes.push(format!(
        "smali 风格清单：写出 {methods_written} 个方法 / {instructions} 条指令；\
         符号解析的账目是已知缺口 {} 处、解析异常 {} 处",
        rendered.unsupported_operands, rendered.unavailable_operands
    ));
    if options.no_symbols {
        notes.push(
            "（`--no-symbols`：指令文本里的池引用保持原始索引，所以上面那两个计数是 0 —— \
             这是'没解析'，不是'解析全通过'）"
                .to_string(),
        );
    }
    if render_failures > 0 {
        notes.push(format!(
            "有 {render_failures} 条指令渲染失败：位置上写了 `<渲染失败：…>`，没有留半行冒充指令"
        ));
    }
    if methods_without_code > 0 {
        notes.push(format!(
            "有 {methods_without_code} 个方法没有字节码（抽象 / native）：清单里写明了原因，不是漏了"
        ));
    }
    if methods_over_limit > 0 {
        notes.push(format!(
            "方法数上限为 {method_budget}（--max-functions），还有 {methods_over_limit} 个方法未导出"
        ));
    }
    Ok(methods_written as u64)
}

/// DEX 的 CFG（Graphviz DOT）：一个方法一个 `subgraph`。
fn write_dex_dot_cfg(
    input: &crate::dex::DexInput,
    selected: &[(usize, String)],
    writer: &mut ExportWriter,
    options: &ExportOptions,
    meta: &ExportMeta,
    notes: &mut Vec<String>,
) -> Result<u64, BitflipError> {
    let structure = &input.structure;

    writer.push_raw(&format!(
        "// bitflip-export v{} format=dex-dot-cfg target={} member={} dex v{} generated_at={}\n\
         // 每个 cluster 是一个方法，节点是基本块（标签是码元偏移，DEX 没有线性地址）。\n",
        EXPORT_FORMAT_VERSION,
        meta.target,
        input.name,
        crate::dex::DEX_FORMAT_VERSION,
        meta.generated_at
    ));
    writer
        .push_raw("digraph bitflip {\n  rankdir=TB;\n  node [shape=box, fontname=\"Consolas\"];\n");

    let method_budget = options.max_functions;
    let mut methods_written = 0usize;
    let mut methods_over_limit = 0u64;
    let mut blocks: u64 = 0;
    let mut unresolved_total: u64 = 0;

    for (class, _) in selected {
        for method in selected_methods(structure, *class, options) {
            let code_off = structure.methods.get(method).map_or(0, |f| f.code_off);
            if code_off == 0 {
                continue;
            }
            if methods_written >= method_budget {
                methods_over_limit += 1;
                continue;
            }
            let signature = structure
                .method_signature(method)
                .unwrap_or_else(|| format!("<方法 {method} 的标识取不到>"));
            let view = match crate::dex::project_method(&input.bytes, code_off) {
                Ok(view) => view,
                Err(error) => {
                    // 解析不了的方法在这里也**留一个节点**：不然读图的人会以为
                    // 这个方法没有控制流，而我们其实只是没解析出来。
                    writer.push_raw(&format!(
                        "  // 方法 {signature}（code_off={:#x}）解析失败：{error}\n",
                        code_off
                    ));
                    continue;
                }
            };
            methods_written += 1;

            let cfg = &view.cfg;
            let cluster = format!("cluster_m{method}");
            writer.push_raw(&format!(
                "  subgraph {cluster} {{\n    label={};\n    style=solid;\n",
                dot_quote(&format!("{signature} @{}", hex16(u64::from(code_off))))
            ));
            // 入口块用双线框：图里能一眼看出从哪进。
            for index in 0..cfg.block_ids.len() {
                let id = cfg.block_ids.get(index).copied().unwrap_or(u32::MAX);
                let start = cfg.block_starts.get(index).copied().unwrap_or(0);
                // 段长的约定与 CFG 文本共用一处定义（`dex_column_range`）。
                let count = crate::dex::dex_column_range(
                    &cfg.block_instruction_offsets,
                    index,
                    cfg.block_instruction_addresses.len(),
                )
                .map_or(0, |range| range.len());
                // 入口块用双线框（`peripheries=2` 是**独立**属性，不能塞进
                // `shape` 的值里 —— Graphviz 会把整串当成一个不认识的形状）。
                let border = if Some(id) == cfg.entry_block {
                    ", peripheries=2"
                } else {
                    ""
                };
                blocks += 1;
                writer.push_raw(&format!(
                    "    b{method}_{id} [label={}, shape=box{border}];\n",
                    dot_quote(&format!("块{id} @{start:04x}（{count} 条）"))
                ));
            }
            for index in 0..cfg.block_ids.len() {
                let id = cfg.block_ids.get(index).copied().unwrap_or(u32::MAX);
                let Some(range) =
                    crate::dex::dex_column_range(&cfg.edge_offsets, index, cfg.edge_kinds.len())
                else {
                    continue;
                };
                for edge in range {
                    let target = cfg.edge_targets.get(edge).copied().unwrap_or(u32::MAX);
                    let label = crate::dex::dex_edge_label(
                        cfg.edge_kinds
                            .get(edge)
                            .copied()
                            .unwrap_or(crate::dex::DexEdgeKind::FallThrough),
                        cfg.edge_switch_keys.get(edge).copied().flatten(),
                        cfg.edge_exception_type_indices.get(edge).copied().flatten(),
                    );
                    // 异常边画虚线：它是"可能跳"，不是"一定跳"。
                    let style = if matches!(
                        cfg.edge_kinds.get(edge).copied(),
                        Some(crate::dex::DexEdgeKind::ExceptionHandler)
                            | Some(crate::dex::DexEdgeKind::ExceptionCatchAll)
                    ) {
                        "dashed"
                    } else {
                        "solid"
                    };
                    writer.push_raw(&format!(
                        "    b{method}_{id} -> b{method}_{target} [label={}, style={style}];\n",
                        dot_quote(&label)
                    ));
                }
            }
            // 没连上的目标画成**不可达的方框**：它们不是任何指令的起点，
            // 所以不能放进块里，但也不能不画（§7：降级要看得见）。
            for entry in &cfg.unresolved_edge_targets {
                unresolved_total += 1;
                let target = entry.target;
                writer.push_raw(&format!(
                    "    u{method}_{target:x} [label={}, shape=\"box\", style=\"dashed\", color=orange];\n",
                    dot_quote(&format!("未连上的目标 {target:#06x}"))
                ));
                writer.push_raw(&format!(
                    "    b{method}_{} -> u{method}_{target:x} [label={}, style=dashed, color=orange];\n",
                    entry.from_block,
                    dot_quote(&crate::dex::dex_edge_label(entry.kind, None, None))
                ));
            }
            writer.push_raw("  }\n");
        }
    }
    writer.push_raw("}\n");

    notes.push(format!(
        "画了 {methods_written} 个方法 / {blocks} 个基本块；未连上的目标 {unresolved_total} 个（画成橙色虚线框）"
    ));
    if methods_over_limit > 0 {
        notes.push(format!(
            "方法数上限为 {method_budget}（--max-functions），还有 {methods_over_limit} 个方法未画"
        ));
    }
    Ok(blocks)
}

/// 函数清单（JSON）。
///
/// 一次成文（不做流式截断）：JSON 是**单个文档**，截断它只会得到解析不了的
/// 半份。超预算时明确报错并给出缩小范围的办法。
fn write_json_functions(
    writer: &mut ExportWriter,
    analysis: &TargetAnalysis,
    options: &ExportOptions,
    meta: &ExportMeta,
    notes: &mut Vec<String>,
) -> Result<u64, BitflipError> {
    let selected: Vec<&FunctionWire> = analysis
        .functions()
        .iter()
        .filter(|func| matches_function(func, options))
        .collect();

    let named = selected.iter().filter(|func| func.named).count();
    let with_alias = selected
        .iter()
        .filter(|func| !func.aliases.is_empty())
        .count();
    let with_source = selected.iter().filter(|func| func.file.is_some()).count();

    let document = json!({
        "format_version": EXPORT_FORMAT_VERSION,
        "producer": meta.producer,
        "meta": meta,
        "totals": {
            "functions": analysis.function_count(),
            "written": selected.len(),
            "named": named,
            "with_aliases": with_alias,
            "with_source_location": with_source,
            "filtered_by_range": options.range.is_some(),
            "filtered_by_function": options.function.is_some(),
        },
        "functions": selected,
        "analysis_notes": analysis.notes(),
    });

    let text = serde_json::to_string_pretty(&document)
        .map_err(|error| BitflipError::Internal(format!("序列化函数清单失败：{error}")))?;
    write_document(writer, &text, options, "函数清单")?;

    if named < selected.len() {
        notes.push(format!(
            "导出的 {} 个函数里有 {} 个没有名字（未识别）。它们仍是函数 —— 边界来自展开表/调用目标等证据，只是还没有可信的名字",
            selected.len(),
            selected.len() - named
        ));
    }
    Ok(selected.len() as u64)
}

/// 函数是否落在导出范围内。
fn matches_function(func: &FunctionWire, options: &ExportOptions) -> bool {
    let entry = u64::from_str_radix(&func.start, 16).unwrap_or(0);
    if let Some(wanted) = options.function {
        if entry != wanted {
            return false;
        }
    }
    if let Some((from, to)) = options.range {
        if entry < from || entry >= to {
            return false;
        }
    }
    true
}

/// 符号表 + 导入 + 导出（JSON）。
fn write_json_symbols(
    writer: &mut ExportWriter,
    parsed: Option<&ObjectInfo>,
    options: &ExportOptions,
    meta: &ExportMeta,
    notes: &mut Vec<String>,
) -> Result<u64, BitflipError> {
    let Some(parsed) = parsed else {
        return Err(BitflipError::unavailable(
            "目标尚未成功解析，没有符号表可导出（原因见 info 的说明）",
        ));
    };

    let in_range = |address: &str| -> bool {
        match options.range {
            None => true,
            Some((from, to)) => {
                let value = u64::from_str_radix(address, 16).unwrap_or(0);
                value >= from && value < to
            }
        }
    };

    let symbols: Vec<&crate::SymbolInfo> = parsed
        .symbols
        .iter()
        .filter(|symbol| in_range(&symbol.value))
        .collect();
    let imports: Vec<&crate::ImportInfo> = parsed
        .imports
        .iter()
        .filter(|import| import.iat_slot.as_deref().is_none_or(in_range))
        .collect();
    let exports: Vec<&crate::ExportInfo> = parsed
        .exports
        .iter()
        .filter(|export| in_range(&export.address))
        .collect();

    let document = json!({
        "format_version": EXPORT_FORMAT_VERSION,
        "producer": meta.producer,
        "meta": meta,
        "totals": {
            "symbols": symbols.len(),
            "imports": imports.len(),
            "exports": exports.len(),
            "defined_symbols": symbols.iter().filter(|s| s.defined).count(),
            "function_symbols": symbols.iter().filter(|s| s.is_function).count(),
        },
        "symbols": symbols,
        "imports": imports,
        "exports": exports,
        "object_notes": parsed.notes,
    });

    let text = serde_json::to_string_pretty(&document)
        .map_err(|error| BitflipError::Internal(format!("序列化符号表失败：{error}")))?;
    write_document(writer, &text, options, "符号表")?;

    if parsed.symbols.is_empty() {
        notes.push(
            "目标没有符号表（可能已剥离）。这不是导出失败 —— 函数边界仍可由展开表与调试信息给出"
                .to_string(),
        );
    }
    for note in &parsed.notes {
        notes.push(format!("解析说明：{note}"));
    }
    Ok((symbols.len() + imports.len() + exports.len()) as u64)
}

/// 交叉引用全表（JSON）。
fn write_json_xrefs(
    writer: &mut ExportWriter,
    analysis: &TargetAnalysis,
    options: &ExportOptions,
    meta: &ExportMeta,
    notes: &mut Vec<String>,
) -> Result<u64, BitflipError> {
    let all: &[XrefWire] = analysis.xrefs();
    let selected: Vec<&XrefWire> = all
        .iter()
        .filter(|xref| match options.range {
            None => true,
            Some((from, to)) => {
                let source = u64::from_str_radix(&xref.from, 16).unwrap_or(0);
                let target = u64::from_str_radix(&xref.to, 16).unwrap_or(0);
                (source >= from && source < to) || (target >= from && target < to)
            }
        })
        .collect();

    let mut counts = std::collections::BTreeMap::<&str, usize>::new();
    let mut sources = std::collections::BTreeMap::<&str, usize>::new();
    for xref in &selected {
        *counts.entry(xref.kind.as_str()).or_default() += 1;
        *sources.entry(xref.source.as_str()).or_default() += 1;
    }

    let document = json!({
        "format_version": EXPORT_FORMAT_VERSION,
        "producer": meta.producer,
        "meta": meta,
        "totals": {
            "xrefs": selected.len(),
            "all_xrefs": all.len(),
            "by_kind": counts,
            "by_source": sources,
        },
        "xrefs": selected,
        "analysis_notes": analysis.notes(),
    });

    let text = serde_json::to_string_pretty(&document)
        .map_err(|error| BitflipError::Internal(format!("序列化交叉引用失败：{error}")))?;
    write_document(writer, &text, options, "交叉引用表")?;
    if selected.len() != all.len() {
        notes.push(format!(
            "地址范围过滤掉了 {} 条交叉引用（全表 {} 条，导出 {} 条）",
            all.len() - selected.len(),
            all.len(),
            selected.len()
        ));
    }
    Ok(selected.len() as u64)
}

/// 导出疑似结构体字段布局（JSON）。
///
/// **启发式、非真实 C 类型**：调用 [`Session::structs_report`]，把候选按访问次数排序后输出。
/// 支持地址范围过滤（按归属函数入口落点）、以及 `--class`/`--method` 等 DEX 选项越界检查由
/// 上层统一处理（此处只用 range / function 选择器，与其他机器码视图一致）。
fn write_json_structs(
    writer: &mut ExportWriter,
    session: &Session,
    options: &ExportOptions,
    meta: &ExportMeta,
    notes: &mut Vec<String>,
) -> Result<u64, BitflipError> {
    let outcome = session.structs_report()?;
    let report = &outcome.report;

    // 地址范围过滤：候选归属函数的入口落在范围内才保留（与 json-functions 的"入口落点"语义一致）。
    let selected: Vec<&StructCandidate> = report
        .candidates
        .iter()
        .filter(|c| match (options.range, c.function) {
            (None, _) => true,
            (Some((from, to)), Some(func)) => func >= from && func < to,
            // 有 range 但候选无函数归属：保守起见丢弃（无法判定落点）。
            (Some(_), None) => false,
        })
        .collect();

    let candidates_json: Vec<_> = selected
        .iter()
        .map(|c| {
            json!({
                "base_reg": c.base.0,
                "function": c.function.map(hex16),
                "size": c.size,
                "field_count": c.fields.len(),
                "access_count": c.access_count(),
                "fields": c.fields.iter().map(|f| json!({
                    "offset": f.offset,
                    "widths": f.widths,
                    "reads": f.reads,
                    "writes": f.writes,
                })).collect::<Vec<_>>(),
            })
        })
        .collect();

    let document = json!({
        "format_version": EXPORT_FORMAT_VERSION,
        "producer": meta.producer,
        "meta": meta,
        "totals": {
            "candidates": selected.len(),
            "all_candidates": report.candidates.len(),
            "instructions": outcome.instructions,
            "function_ranges": outcome.function_ranges,
        },
        "candidates": candidates_json,
        "notes": report.notes,
        "disclaimer": "疑似结构体：启发式证据，非真实 C 类型（无类型/数据流/跨块指针跟踪）",
    });

    let text = serde_json::to_string_pretty(&document)
        .map_err(|error| BitflipError::Internal(format!("序列化结构体推断失败：{error}")))?;
    write_document(writer, &text, options, "结构体推断表")?;
    if selected.len() != report.candidates.len() {
        notes.push(format!(
            "地址范围过滤掉了 {} 个结构体候选（全量 {} 个，导出 {} 个）",
            report.candidates.len() - selected.len(),
            report.candidates.len(),
            selected.len()
        ));
    }
    Ok(selected.len() as u64)
}

/// 一条按库聚合的记录（[`group_imports`] 产出）。
struct LibraryGroup {
    module: String,
    import_count: usize,
    named_count: usize,
    ordinal_only_count: usize,
    sample_names: Vec<String>,
    has_iat_slots: bool,
}

/// 把一个导入列表按 `module` 聚合成库分组（纯函数，便于单测）。
///
/// 空 `module` 归到 `"<未命名模块>"`（不假装它没有库）；样本名字去重、保序、截断到
/// `SAMPLE_LIMIT`；分组按 `module` 升序。
fn group_imports(imports: &[crate::ImportInfo]) -> Vec<LibraryGroup> {
    const UNNAMED: &str = "<未命名模块>";
    const SAMPLE_LIMIT: usize = 12;

    let mut by_module: std::collections::BTreeMap<String, Vec<&crate::ImportInfo>> =
        std::collections::BTreeMap::new();
    for import in imports {
        let key = if import.module.is_empty() {
            UNNAMED.to_string()
        } else {
            import.module.clone()
        };
        by_module.entry(key).or_default().push(import);
    }

    by_module
        .into_iter()
        .map(|(module, imports)| {
            let mut seen = std::collections::BTreeSet::new();
            let mut sample_names = Vec::new();
            let mut named_count = 0usize;
            for i in &imports {
                if let Some(name) = &i.name {
                    named_count += 1;
                    if seen.insert(name.clone()) && sample_names.len() < SAMPLE_LIMIT {
                        sample_names.push(name.clone());
                    }
                }
            }
            LibraryGroup {
                import_count: imports.len(),
                named_count,
                ordinal_only_count: imports.len() - named_count,
                sample_names,
                has_iat_slots: imports.iter().any(|i| i.iat_slot.is_some()),
                module,
            }
        })
        .collect()
}

/// 依赖库识别（JSON）：按库聚合导入符号。
///
/// 数据**客观**：来自导入表（`ImportInfo.module`）与依赖库列表（Mach-O `dylibs`），不做猜测。
/// 回答"这个二进制依赖哪些库、每个库贡献了多少导入、哪些名字/序号"。
/// 不是 FLIRT 那类"识别静态链接的库函数"——那是签名库的职责，需要用户提供静态库生成。
fn write_json_libraries(
    writer: &mut ExportWriter,
    parsed: Option<&ObjectInfo>,
    options: &ExportOptions,
    meta: &ExportMeta,
    notes: &mut Vec<String>,
) -> Result<u64, BitflipError> {
    let Some(parsed) = parsed else {
        return Err(BitflipError::unavailable(
            "目标尚未成功解析，没有导入表可做库识别（原因见 info 的说明）",
        ));
    };

    let in_range = |address: &str| -> bool {
        match options.range {
            None => true,
            Some((from, to)) => {
                let value = u64::from_str_radix(address, 16).unwrap_or(0);
                value >= from && value < to
            }
        }
    };
    let import_in_range =
        |import: &crate::ImportInfo| -> bool { import.iat_slot.as_deref().is_none_or(in_range) };

    // 先按范围过滤导入，再按库聚合（分组只认过滤后的集合）。
    let filtered: Vec<crate::ImportInfo> = parsed
        .imports
        .iter()
        .filter(|import| import_in_range(import))
        .cloned()
        .collect();
    let groups = group_imports(&filtered);

    const UNNAMED: &str = "<未命名模块>";
    let libraries: Vec<_> = groups
        .iter()
        .map(|g| {
            json!({
                "module": g.module,
                "import_count": g.import_count,
                "named_count": g.named_count,
                "ordinal_only_count": g.ordinal_only_count,
                "sample_names": g.sample_names,
                "has_iat_slots": g.has_iat_slots,
            })
        })
        .collect();

    // 声明的依赖库（Mach-O dylibs）与实际导入模块的差异——如实说明，不掩盖。
    // 但只有**存在**声明的 dylib 列表时才做这个对比：PE/ELF 没有 dylib 概念，
    // 拿空列表去比会把每个导入模块都列成"未声明"，那是噪声而不是事实。
    let declared: std::collections::BTreeSet<&str> =
        parsed.dylibs.iter().map(String::as_str).collect();
    let seen: std::collections::BTreeSet<&str> = groups.iter().map(|g| g.module.as_str()).collect();
    let (declared_without_imports, imported_but_not_declared): (Vec<&str>, Vec<&str>) =
        if declared.is_empty() {
            (Vec::new(), Vec::new())
        } else {
            let missing = declared.difference(&seen).copied().collect();
            let extra = seen
                .difference(&declared)
                .copied()
                .filter(|m| *m != UNNAMED)
                .collect();
            (missing, extra)
        };

    let document = json!({
        "format_version": EXPORT_FORMAT_VERSION,
        "producer": meta.producer,
        "meta": meta,
        "totals": {
            "libraries": libraries.len(),
            "imports": filtered.len(),
            "declared_dylibs": parsed.dylibs.len(),
        },
        "declared_dylibs": parsed.dylibs,
        "libraries": libraries,
        "declared_without_imports": declared_without_imports,
        "imported_but_not_declared": imported_but_not_declared,
        "object_notes": parsed.notes,
    });

    let text = serde_json::to_string_pretty(&document)
        .map_err(|error| BitflipError::Internal(format!("序列化依赖库识别失败：{error}")))?;
    write_document(writer, &text, options, "依赖库识别表")?;

    if parsed.imports.is_empty() {
        notes.push(
            "目标没有导入表（可能是静态链接、已剥离，或本身不依赖外部符号）：库识别只能给出空的依赖列表"
                .to_string(),
        );
    }
    for note in &parsed.notes {
        notes.push(format!("解析说明：{note}"));
    }
    Ok(filtered.len() as u64)
}

/// 调用图（JSON）。
///
/// 数据来自 `analysis.call_graph()` —— 它**只列已解析的调用边**，未解析的间接调用
/// 单独计数（`summary.unresolved_indirect`）。可达集/边集都是**下界**：有间接调用
/// 没有目标，真实调用图只会更大。这一点写进 `notes`，不让导出看起来比实际更完整。
///
/// `--function` 时只保留与该函数相关的边（它作调用方或被调用方）；`--from/--to`
/// 时只保留调用方落在区间内的边。过滤只影响 `edges`，`summary` 仍是全图统计（它是
/// 全图事实，按子集重算会产生自相矛盾的数字）。
fn write_json_callgraph(
    writer: &mut ExportWriter,
    analysis: &TargetAnalysis,
    options: &ExportOptions,
    meta: &ExportMeta,
    notes: &mut Vec<String>,
) -> Result<u64, BitflipError> {
    let graph = analysis.call_graph();

    // `--function` 归一化成 16 位十六进制串（与 wire 里的 caller/callee 形式一致）。
    let function = options.function.map(|f| format!("{f:016x}"));
    let in_range = |address: &str| -> bool {
        match options.range {
            None => true,
            Some((from, to)) => {
                let value = u64::from_str_radix(address, 16).unwrap_or(0);
                value >= from && value < to
            }
        }
    };
    let keep = |edge: &crate::analysis::CallEdgeWire| -> bool {
        if let Some(func) = function.as_deref() {
            if edge.caller != func && edge.callee != func {
                return false;
            }
        }
        in_range(&edge.caller)
    };

    let edges: Vec<&crate::analysis::CallEdgeWire> =
        graph.edges.iter().filter(|e| keep(e)).collect();
    let filtered = options.function.is_some() || options.range.is_some();

    let document = json!({
        "format_version": EXPORT_FORMAT_VERSION,
        "producer": meta.producer,
        "meta": meta,
        "filtered": filtered,
        "summary": graph.summary,
        "edges": edges,
        "unresolved": graph.unresolved,
        "graph_notes": graph.notes,
    });

    let text = serde_json::to_string_pretty(&document)
        .map_err(|error| BitflipError::Internal(format!("序列化调用图失败：{error}")))?;
    write_document(writer, &text, options, "调用图")?;

    if graph.summary.unresolved_indirect > 0 {
        notes.push(format!(
            "调用图有 {} 处未解析的间接调用：这些边没有目标，此图与基于它的可达集都只是**下界**（真实调用更多）",
            graph.summary.unresolved_indirect
        ));
    }
    for note in &graph.notes {
        notes.push(format!("调用图说明：{note}"));
    }
    Ok(edges.len() as u64)
}

/// 把一个已构造好的 JSON 文档写出去。
///
/// JSON 是**单个文档**：截断它只会得到解析不了的半份，所以超预算时
/// 明确失败并把差额报出来，而不是交出半个文件。
fn write_document(
    writer: &mut ExportWriter,
    text: &str,
    options: &ExportOptions,
    what: &'static str,
) -> Result<(), BitflipError> {
    if let Some(limit) = options.byte_limit {
        if text.len() as u64 > limit {
            return Err(ExportError::OverBudget {
                what,
                bytes: text.len() as u64,
                limit,
                message: format!(
                    "{what}有 {} 字节，超过预算 {limit}；请调大 --limit-bytes 或用 --from/--to 缩小范围",
                    text.len()
                ),
                notes: vec![
                    "JSON 是单个文档，截断它只会得到解析不了的半份，因此没有写出任何内容"
                        .to_string(),
                    "用 --from/--to 缩小地址范围，或调大 --limit-bytes".to_string(),
                ],
            }
            .into());
        }
    }
    writer.push_raw(text);
    Ok(())
}

/// 控制流图（Graphviz DOT）。
///
/// 形态：整个导出是一张 `digraph`，每个函数一个 `subgraph cluster_<入口>`
/// （标签是函数名，没有名字就写"未识别"—— **不**造 `func_xxx` 假名）。
/// 节点是基本块，标签里带块内首条与末条指令的地址范围。
/// 边是后继；没有对应块的后继用**虚线**画，说明"目标不在已识别块里"。
fn write_dot_cfg(
    writer: &mut ExportWriter,
    analysis: &TargetAnalysis,
    options: &ExportOptions,
    meta: &ExportMeta,
    notes: &mut Vec<String>,
) -> Result<u64, BitflipError> {
    writer.push_raw(&dot_header(meta, options));

    // 函数名映射：入口 → 显示名。没名字就如实写"未识别"。
    let name_of = |entry: u64| -> String {
        analysis
            .functions()
            .iter()
            .find(|func| u64::from_str_radix(&func.start, 16) == Ok(entry))
            .map_or_else(
                || "未识别".to_string(),
                |func| {
                    if func.named {
                        func.name.clone()
                    } else {
                        "未识别".to_string()
                    }
                },
            )
    };

    let mut selected: Vec<&crate::CfgWire> = analysis
        .cfgs()
        .filter(|cfg| {
            let entry = u64::from_str_radix(&cfg.entry, 16).unwrap_or(0);
            if let Some(func) = options.function {
                return entry == func;
            }
            match options.range {
                None => true,
                Some((from, to)) => entry >= from && entry < to,
            }
        })
        .collect();
    selected.sort_by_key(|cfg| u64::from_str_radix(&cfg.entry, 16).unwrap_or(0));

    let total_functions = analysis.cfg_count();
    let limit = options.max_functions;
    let skipped_functions = selected.len().saturating_sub(limit);
    selected.truncate(limit);

    let mut instructions: u64 = 0;
    for cfg in &selected {
        let entry = u64::from_str_radix(&cfg.entry, 16).unwrap_or(0);
        let label = format!("{} ({})", name_of(entry), hex16(entry));
        writer.push_raw(&format!(
            "  subgraph cluster_{entry:x} {{\n    label={};\n    style=solid;\n",
            dot_quote(&label)
        ));

        for block in &cfg.blocks {
            instructions += 1;
            let node_label = format!("{}..{}", block.start, block.end);
            let mut suffix = String::new();
            if block.terminal {
                suffix.push_str(" [不返回]");
            }
            if block.successors.is_empty() {
                suffix.push_str(" [无已知后继]");
            }
            let line = format!(
                "    n{} [label={}];\n",
                block.start,
                dot_quote(&format!("{node_label}{suffix}"))
            );
            if !writer.push_line(&line) {
                break;
            }
        }

        let known: std::collections::BTreeSet<&str> = cfg
            .blocks
            .iter()
            .map(|block| block.start.as_str())
            .collect();
        for block in &cfg.blocks {
            for successor in &block.successors {
                let line = if known.contains(successor.as_str()) {
                    format!("    n{} -> n{};\n", block.start, successor)
                } else {
                    // 目标没有对应的块：虚线画过去并标注，别把它藏起来。
                    format!(
                        "    n{} -> n{} [style=dashed, label=\"块外\"];\n",
                        block.start, successor
                    )
                };
                if !writer.push_line(&line) {
                    break;
                }
            }
        }

        writer.push_raw("  }\n");
    }
    writer.push_raw("}\n");

    if skipped_functions > 0 {
        notes.push(format!(
            "只画了前 {limit} 个函数的 CFG，另有 {skipped_functions} 个没画（共 {total_functions} 个）。\
             用 --from/--to 缩小范围，或调大 --max-functions"
        ));
    }
    // DOT 的文件头/尾没写完就是**语法错误**的文件，解析器会直接报错，
    // 比缺几个块更糟。所以这里**明确失败**，而不是交回半份。
    //
    // 附带说明走错误类型自己的字段（[`ExportError::notes`]），因为失败时
    // 没有 `ExportReport` 可放 —— 光靠一句"超预算了"会丢掉"画了多少"。
    if let Some(truncation) = truncation_of(writer, "用 --from/--to 缩小范围") {
        let mut reasons = vec![
            format!(
                "字节预算用尽：{} 未写出（已写出 {}）",
                truncation.dropped, truncation.written
            ),
            "DOT 在预算用尽处停止写出，文件不完整（Graphviz 会报语法错误），因此未作为结果返回"
                .to_string(),
        ];
        if skipped_functions > 0 {
            reasons.push(format!(
                "另有 {skipped_functions} 个函数未画（共 {total_functions} 个）"
            ));
        }
        return Err(BitflipError::Export(ExportError::OverBudget {
            what: "DOT 控制流图",
            bytes: writer.len(),
            limit: options.byte_limit.unwrap_or(u64::MAX),
            message: format!(
                "DOT 控制流图超过字节预算（{} 字节），为避免交出语法错误的文件而中止",
                writer.len()
            ),
            notes: reasons,
        }));
    }

    Ok(instructions)
}

/// DOT 的注释头。
fn dot_header(meta: &ExportMeta, options: &ExportOptions) -> String {
    let mut header = format!(
        "// bitflip-export v{} format=dot-cfg target={} arch={} generated_at={}\n\
         // 每个 cluster 是一个函数，节点是基本块。未识别名字的函数标为「未识别」。\n",
        EXPORT_FORMAT_VERSION,
        meta.target,
        meta.arch.as_deref().unwrap_or("unknown"),
        meta.generated_at
    );
    if let Some((from, to)) = options.range {
        header.push_str(&format!("// range {} .. {}\n", hex16(from), hex16(to)));
    }
    if let Some(func) = options.function {
        header.push_str(&format!("// function {}\n", hex16(func)));
    }
    header
        .push_str("digraph bitflip {\n  rankdir=TB;\n  node [shape=box, fontname=\"Consolas\"];\n");
    header
}

/// DOT 字符串字面量：转义反斜杠与引号，换行折成 `\n`。
fn dot_quote(text: &str) -> String {
    let mut out = String::with_capacity(text.len() + 2);
    out.push('"');
    for ch in text.chars() {
        match ch {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => {}
            other => out.push(other),
        }
    }
    out.push('"');
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn import(module: &str, name: Option<&str>, iat: Option<&str>) -> crate::ImportInfo {
        crate::ImportInfo {
            module: module.to_string(),
            name: name.map(str::to_string),
            ordinal: None,
            iat_slot: iat.map(str::to_string),
        }
    }

    #[test]
    fn group_imports_buckets_by_module_and_counts() {
        let imports = vec![
            import(
                "KERNEL32.dll",
                Some("CreateFileW"),
                Some("0000000140001000"),
            ),
            import(
                "KERNEL32.dll",
                Some("CreateFileW"),
                Some("0000000140001008"),
            ),
            import(
                "KERNEL32.dll",
                Some("CloseHandle"),
                Some("0000000140001010"),
            ),
            import("ntdll.dll", None, Some("0000000140001018")), // 序号导入，无名
            import("", Some("orphan"), Some("0000000140001020")), // 空 module
        ];
        let groups = group_imports(&imports);
        assert_eq!(groups.len(), 3, "KERNEL32 / ntdll / 未命名");
        let k = groups.iter().find(|g| g.module == "KERNEL32.dll").unwrap();
        assert_eq!(k.import_count, 3);
        assert_eq!(k.named_count, 3);
        assert_eq!(k.ordinal_only_count, 0);
        // 样本名字去重保序：CreateFileW 只出现一次。
        assert_eq!(k.sample_names, vec!["CreateFileW", "CloseHandle"]);
        assert!(k.has_iat_slots);

        let n = groups.iter().find(|g| g.module == "ntdll.dll").unwrap();
        assert_eq!(n.import_count, 1);
        assert_eq!(n.named_count, 0);
        assert_eq!(n.ordinal_only_count, 1);
        assert!(n.sample_names.is_empty());

        let u = groups.iter().find(|g| g.module == "<未命名模块>").unwrap();
        assert_eq!(u.named_count, 1);
    }

    #[test]
    fn group_imports_sample_names_capped() {
        let imports: Vec<crate::ImportInfo> = (0..20)
            .map(|i| import("lib", Some(&format!("sym{i}")), None))
            .collect();
        let groups = group_imports(&imports);
        let g = &groups[0];
        assert_eq!(g.import_count, 20);
        assert_eq!(g.sample_names.len(), 12, "样本上限 12");
        assert!(!g.has_iat_slots);
    }

    #[test]
    fn export_format_names_round_trip() {
        for format in ExportFormat::all() {
            assert_eq!(ExportFormat::parse(format.as_str()), Some(*format));
        }
        assert_eq!(
            ExportFormat::parse("ASM-INTEL"),
            Some(ExportFormat::AsmIntel)
        );
        assert_eq!(
            ExportFormat::parse("  json-functions "),
            Some(ExportFormat::JsonFunctions)
        );
        assert_eq!(ExportFormat::parse("nope"), None);
    }

    #[test]
    fn default_options_are_bounded_not_unlimited() {
        let options = ExportOptions::default();
        assert_eq!(options.byte_limit, Some(DEFAULT_EXPORT_BYTE_LIMIT));
        assert!(options.include_bytes);
        assert!(options.keep_partial);
    }

    #[test]
    fn writer_marks_truncation_instead_of_silently_dropping() {
        let mut writer = ExportWriter::new(Some(20), "指令");
        assert!(writer.push_line("0123456789\n"));
        assert!(!writer.push_line("0123456789\n"));
        assert!(!writer.push_line("0123456789\n"));
        assert!(writer.blocked);
        // 被拒的条数为 2（含第一次撞墙那条）—— 报告里的"少了几条"靠它。
        assert_eq!(writer.blocked_items, 2);
        assert_eq!(writer.written_items, 1);
        assert_eq!(writer.len(), 11);
        let truncation = truncation_of(&writer, "缩小范围").expect("应当报截断");
        assert_eq!(truncation.what, "指令");
        assert_eq!(truncation.written, 1);
    }

    #[test]
    fn civil_dates_are_right_for_known_timestamps() {
        // 1970-01-01 / 2000-03-01（闰年边界）/ 2024-02-29（闰日）/
        // 1969-12-31（负天数不应 panic）。
        assert_eq!(civil_from_days(0), (1970, 1, 1));
        assert_eq!(civil_from_days(11_017), (2000, 3, 1));
        assert_eq!(civil_from_days(19_782), (2024, 2, 29));
        assert_eq!(civil_from_days(-1), (1969, 12, 31));
    }

    #[test]
    fn x86_family_detection_uses_spec_prefix() {
        assert!(is_x86_family(Some("x86_64/64/le")));
        assert!(is_x86_family(Some("x86/32/le")));
        assert!(!is_x86_family(Some("aarch64/64/le")));
        assert!(!is_x86_family(None));
    }
}
