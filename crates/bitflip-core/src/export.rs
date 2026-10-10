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
    /// 控制流图（Graphviz DOT）。
    DotCfg,
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
            Self::DotCfg => "dot-cfg",
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
            Self::DotCfg,
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
        matches!(self, Self::AsmIntel | Self::AsmAtt | Self::DotCfg)
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
}

impl std::fmt::Display for ExportError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::OverBudget { message, notes, .. } => {
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
    /// 导出发生的时间（RFC 3339，UTC）。
    pub generated_at: String,
}

/// 各层 wire 版本集合。
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
    let job = session.detached_job();
    let meta = build_meta(session, format, options);

    // 截断账目里"少的是什么"随格式而定：反汇编是"指令"，DOT 是"基本块"。
    let item_kind: &'static str = match format {
        ExportFormat::DotCfg => "基本块",
        _ => "指令",
    };
    let mut writer = ExportWriter::new(options.byte_limit, item_kind);
    let mut notes: Vec<String> = Vec::new();

    let items: u64 = match format {
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
        ExportFormat::DotCfg => {
            let analysis = session.analysis(&job)?;
            write_dot_cfg(&mut writer, &analysis, options, &meta, &mut notes)?
        }
    };

    let truncated = truncation_of(
        &writer,
        "用 --from/--to 按地址段分批导出，或调大 --limit-bytes",
    );
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
        },
        target: info.path.clone(),
        file_size: info.file_size,
        arch: info.arch.clone(),
        range_from: options.range.map(|(from, _)| hex16(from)),
        range_to: options.range.map(|(_, to)| hex16(to)),
        function: options.function.map(hex16),
        generated_at: now_rfc3339(),
    }
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

/// 判定架构是否属于 x86 族（用 `TargetInfo::arch` 的规格字符串）。
fn is_x86_family(arch: Option<&str>) -> bool {
    match arch {
        Some(spec) => {
            spec.starts_with("x86") || spec.starts_with("i386") || spec.starts_with("i686")
        }
        None => false,
    }
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
        .filter(|import| import.iat_slot.as_deref().is_none_or(&in_range))
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
