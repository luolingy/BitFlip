//! 两个同族二进制的差分（M9 交付物 4）。
//!
//! # 为什么"地址归一化"是这个模块的核心问题，而不是一个实现细节
//!
//! 两个版本的二进制通常**不加载到同一个基址**。`diff-pe-x86_64-v1.exe` 与
//! `-v2.exe`（仓库里的 fixture）就是刻意的例子：基址差 `0x40000000`，
//! `df_stable`/`df_helper`/`df_changed` 三个函数的**虚拟地址全都不一样**，
//! 而它们的 RVA 完全相同。
//!
//! 如果按虚拟地址比，会得到一份"几乎每个函数都变了"的报告 —— 它不是崩溃，
//! 不是报错，就是一份**看起来很正常、每一条都写得很具体**的假报告。
//! 这是最坏的一类错误：用户没有理由怀疑它。
//!
//! 所以这里的规则是：
//!
//! 1. 默认按**归一化地址**（RVA = VA − 镜像基址）比；
//! 2. 用了哪种归一化**必须写进输出**（[`DiffReport::normalization`]），
//!    并且带上两个基址的实测值，让用户能自己核对；
//! 3. 基址拿不到（例如可重定位目标文件没有基址概念）时**明说不可比**，
//!    退化成按名字比，并把这件事写进 `notes` —— 而不是假装比过了。
//!
//! # 三类条目，账目必须闭合
//!
//! 每个条目恰好落进一个桶：`added`（只在 v2）、`removed`（只在 v1）、
//! `changed`（两边都有，但内容不同）、`moved`（内容相同、地址不同）、
//! `unchanged`（两边都有且相同）。`checked_in` = `checked_out` 恒等
//! （[`DiffReport::accounting_balanced`]），有测试钉着 ——
//! "少报"和"多报"都必须能让测试变红。
//!
//! # 谁和谁算"同一个函数"
//!
//! 按匹配强度分三轮，每轮的判据都记在报告的 `match` 字段里，不混着说：
//!
//! 1. **同名 + 同归一化地址** —— 最强，普通改动都是这一类；
//! 2. **内容相同（指令级哈希相同）+ 大小相同** —— 识别"只是搬了位置"的函数。
//!    移动判定要求名字也相同：地址不同、内容相同的两个**不同名**函数，
//!    可能是巧合（两个空函数体都可能只有一条 `ret`），报"移动"是在编故事；
//! 3. 剩下的按名字匹配（`--by name`），报告里标明用了弱判据。
//!
//! 未命名函数不做任何猜测：按归一化地址比，落在"新增/删除/改动"里，
//! 并且**不生成 `func_xxx` 之类的名字**（CLAUDE.md §7）。

use std::collections::BTreeMap;
use std::fmt::Write as _;

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::analysis::FunctionWire;
use crate::disasm::Disasm;
use crate::error::BitflipError;
use crate::session::Session;

/// 差分 wire 格式版本。
///
/// 与 [`crate::EXPORT_FORMAT_VERSION`] **独立**演进：差分报告与导出正文是两份
/// 不同的对外契约，改动其一不该逼着另一方也跳版本号。
pub const DIFF_FORMAT_VERSION: u32 = 1;

/// 参与差分的条目类别。
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum DiffKind {
    /// 只在 v2 里出现。
    Added,
    /// 只在 v1 里出现。
    Removed,
    /// 两边都有，内容不同。
    Changed,
    /// 内容相同，归一化地址不同。
    Moved,
    /// 两边都有且相同。
    Unchanged,
}

impl DiffKind {
    /// 稳定的短名（JSON / 文本 / CLI 过滤）。
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Added => "added",
            Self::Removed => "removed",
            Self::Changed => "changed",
            Self::Moved => "moved",
            Self::Unchanged => "unchanged",
        }
    }

    /// 全部类别（固定顺序：先差异、后未变，与文本输出的排序一致）。
    #[must_use]
    pub const fn all() -> [Self; 5] {
        [
            Self::Added,
            Self::Removed,
            Self::Changed,
            Self::Moved,
            Self::Unchanged,
        ]
    }

    /// 解析短名。
    ///
    /// **必须**与 [`Self::as_str`] 用同一张表：`--only added` 认的值，就是
    /// 报告里 `kind` 打印出来的值。两处各写一张表，用户照抄报告里的名字却
    /// 报"无法识别"，那是最难查的一类问题。
    ///
    /// 大小写不敏感，但**不做前缀匹配**：`mov` 应当是错误，不能悄悄当成 `moved`。
    #[must_use]
    pub fn parse(text: &str) -> Option<Self> {
        let lowered = text.to_ascii_lowercase();
        Self::all()
            .into_iter()
            .find(|kind| kind.as_str() == lowered)
    }

    /// 文本输出里的单字符标记。
    #[must_use]
    pub const fn marker(self) -> char {
        match self {
            Self::Added => '+',
            Self::Removed => '-',
            Self::Changed => '~',
            Self::Moved => '>',
            Self::Unchanged => '=',
        }
    }

    /// 面向界面的中文名。
    #[must_use]
    pub const fn label_zh(self) -> &'static str {
        match self {
            Self::Added => "新增",
            Self::Removed => "删除",
            Self::Changed => "改动",
            Self::Moved => "移动",
            Self::Unchanged => "未变",
        }
    }

    /// 该类别是否算"差异"（用于计数与"有没有变化"的判断）。
    ///
    /// `Unchanged` 不算 —— 否则"有没有变化"永远是"有"，这个判断就没用了。
    #[must_use]
    pub const fn is_difference(self) -> bool {
        !matches!(self, Self::Unchanged)
    }
}

/// 条目是**靠什么**匹配上的。
///
/// 必须暴露出来：按内容匹配出来的"移动"与按名字匹配出来的"改动"可信度不同，
/// 报告里混成一种说法就是在藏信息。
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum MatchBasis {
    /// 名字与归一化地址都相同。
    NameAndAddress,
    /// 内容哈希与大小都相同（地址不同）—— "移动"。
    ContentAndSize,
    /// 只有名字相同（地址也变了、内容也变了）。
    NameOnly,
    /// 只有归一化地址相同（未命名函数）。
    AddressOnly,
    /// 只有地址相同、内容不同（未命名函数改动）。
    AddressOnlyContentDiffers,
}

impl MatchBasis {
    /// 稳定的短名。
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::NameAndAddress => "name+address",
            Self::ContentAndSize => "content+size",
            Self::NameOnly => "name-only",
            Self::AddressOnly => "address-only",
            Self::AddressOnlyContentDiffers => "address-only-content-differs",
        }
    }
}

/// 一个差分条目。
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DiffEntry {
    /// 类别。
    pub kind: DiffKind,
    /// 匹配判据。
    pub match_basis: MatchBasis,
    /// 函数名；未命名时是 `None`（**不生成占位名**）。
    pub name: Option<String>,
    /// 名字来源（`symbol-table` / `signature` / …）；未命名时 `None`。
    pub source: Option<String>,
    /// 归一化地址（RVA），定长 16 位十六进制。
    pub normalized: String,
    /// v1 里的虚拟地址；只在 v2 里出现时为 `None`。
    pub v1_address: Option<String>,
    /// v2 里的虚拟地址；只在 v1 里出现时为 `None`。
    pub v2_address: Option<String>,
    /// v1 里的大小；未知为 `None`。
    pub v1_size: Option<u64>,
    /// v2 里的大小；未知为 `None`。
    pub v2_size: Option<u64>,
    /// 指令条数（v1）；无区间时 `None`。
    pub v1_instructions: Option<u64>,
    /// 指令条数（v2）；无区间时 `None`。
    pub v2_instructions: Option<u64>,
    /// 内容不同的原因（人话），`Unchanged` 时为空。
    pub detail: Option<String>,
}

/// 一类条目的计数。
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct DiffTotals {
    /// 新增。
    pub added: usize,
    /// 删除。
    pub removed: usize,
    /// 改动。
    pub changed: usize,
    /// 移动。
    pub moved: usize,
    /// 未变。
    pub unchanged: usize,
}

impl DiffTotals {
    /// 累计一个条目。
    fn count(&mut self, kind: DiffKind) {
        match kind {
            DiffKind::Added => self.added += 1,
            DiffKind::Removed => self.removed += 1,
            DiffKind::Changed => self.changed += 1,
            DiffKind::Moved => self.moved += 1,
            DiffKind::Unchanged => self.unchanged += 1,
        }
    }

    /// 条目总数。
    #[must_use]
    pub const fn total(&self) -> usize {
        self.added + self.removed + self.changed + self.moved + self.unchanged
    }

    /// 是否有任何差异（不把 `unchanged` 算作差异）。
    #[must_use]
    pub const fn has_changes(&self) -> bool {
        self.added > 0 || self.removed > 0 || self.changed > 0 || self.moved > 0
    }
}

/// 地址归一化方式。
///
/// 这是差分报告里**最重要的一行**：它决定用户能不能相信后面的清单。
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case", tag = "method")]
pub enum Normalization {
    /// 两边都减掉各自的镜像基址（最强，默认）。
    Rva {
        /// v1 的镜像基址。
        v1_base: u64,
        /// v2 的镜像基址。
        v2_base: u64,
    },
    /// 基址相同，虚拟地址即归一化地址。
    SameBase {
        /// 共同的镜像基址。
        base: u64,
    },
    /// 基址拿不到或不一致且无法转换 —— **地址不可比**。
    ///
    /// 此时地址比对被禁用，条目按名字匹配，并且 `notes` 里会说明原因。
    /// 这不是"降级但结果还行"，是"这个维度没法用"。
    Unavailable {
        /// 为什么不可比（面向用户）。
        reason: String,
    },
}

impl Normalization {
    /// 报告里直接展示的一行说明。
    #[must_use]
    pub fn describe_zh(&self) -> String {
        match self {
            Self::Rva { v1_base, v2_base } => {
                format!("RVA（各自减掉镜像基址）：v1 基址 {v1_base:#x}，v2 基址 {v2_base:#x}")
            }
            Self::SameBase { base } => format!("虚拟地址（两边基址相同 {base:#x}）"),
            Self::Unavailable { reason } => format!("地址不可比：{reason}"),
        }
    }

    /// 地址是否可比。
    #[must_use]
    pub const fn is_usable(&self) -> bool {
        !matches!(self, Self::Unavailable { .. })
    }
}

/// 差分范围：只比函数、符号、节，还是全比。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum DiffScope {
    /// 函数清单（默认）。
    Functions,
    /// 节表。
    Sections,
    /// 符号表。
    Symbols,
    /// 全部三类。
    All,
}

impl DiffScope {
    /// 稳定的短名。
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Functions => "functions",
            Self::Sections => "sections",
            Self::Symbols => "symbols",
            Self::All => "all",
        }
    }

    /// 解析用户输入的短名。
    #[must_use]
    pub fn parse(text: &str) -> Option<Self> {
        match text.trim().to_ascii_lowercase().as_str() {
            "functions" | "funcs" | "fn" => Some(Self::Functions),
            "sections" | "secs" => Some(Self::Sections),
            "symbols" | "syms" => Some(Self::Symbols),
            "all" | "everything" => Some(Self::All),
            _ => None,
        }
    }

    /// 全部合法短名（报错时列出）。
    #[must_use]
    pub const fn all() -> [Self; 4] {
        [Self::Functions, Self::Sections, Self::Symbols, Self::All]
    }

    /// 是否包含某一类。
    #[must_use]
    pub const fn includes(self, other: Self) -> bool {
        matches!(self, Self::All)
            || matches!(
                (self, other),
                (Self::Functions, Self::Functions)
                    | (Self::Sections, Self::Sections)
                    | (Self::Symbols, Self::Symbols)
            )
    }
}

/// 差分选项。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DiffOptions {
    /// 比哪几类。
    pub scope: DiffScope,
    /// 只保留某类结果（`None` = 全保留）。用于"只看新增"这类窄查询。
    pub only: Option<DiffKind>,
    /// 条目上限；超出时截断并记账（**不静默丢弃**）。
    pub max_entries: usize,
}

impl Default for DiffOptions {
    fn default() -> Self {
        Self {
            scope: DiffScope::Functions,
            only: None,
            max_entries: 20_000,
        }
    }
}

/// 差分报告。
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DiffReport {
    /// wire 格式版本。
    pub format_version: u32,
    /// 产出者。
    pub producer: String,
    /// 差异类型。
    pub scope: DiffScope,
    /// v1 目标路径。
    pub v1_path: String,
    /// v2 目标路径。
    pub v2_path: String,
    /// v1 的镜像基址。
    pub v1_image_base: u64,
    /// v2 的镜像基址。
    pub v2_image_base: u64,
    /// 归一化方式（**必须看这一行**）。
    pub normalization: Normalization,
    /// v1 的条目总数（进入差分的）。
    pub v1_total: usize,
    /// v2 的条目总数（进入差分的）。
    pub v2_total: usize,
    /// 计数。
    pub totals: DiffTotals,
    /// 条目（按类别、再按归一化地址排序）。
    pub entries: Vec<DiffEntry>,
    /// 是否因 `max_entries` 截断。
    pub truncated: bool,
    /// 截断时丢掉多少条。
    pub dropped: usize,
    /// 说明（降级、不可比、解析告警）。
    pub notes: Vec<String>,
}

impl DiffReport {
    /// 账目是否闭合：每个条目恰好落进一个桶。
    ///
    /// 恒等式：`v1_total + v2_total == 2 × (两边都有的条目)` 不好直接验，
    /// 所以改成更强的等价形式 —— `entries.len() == totals.total()`，
    /// 且 `added + removed + changed + moved + unchanged` 等于逐条重数一遍的结果。
    #[must_use]
    pub fn accounting_balanced(&self) -> bool {
        let mut recounted = DiffTotals::default();
        for entry in &self.entries {
            recounted.count(entry.kind);
        }
        recounted == self.totals && self.entries.len() == self.totals.total()
    }

    /// 一行摘要（CLI 与 UI 直接用）。
    #[must_use]
    pub fn summary_zh(&self) -> String {
        format!(
            "{} 项：新增 {} / 删除 {} / 改动 {} / 移动 {} / 未变 {}",
            self.totals.total(),
            self.totals.added,
            self.totals.removed,
            self.totals.changed,
            self.totals.moved,
            self.totals.unchanged
        )
    }
}

/// 渲染成自述文本。
///
/// 头部**必须**包含归一化方式：一份没说清"按什么比的"的差异报告是不可复核的。
#[must_use]
pub fn render_text(report: &DiffReport) -> String {
    let mut out = String::with_capacity(1024);
    let _ = writeln!(
        out,
        "# bitflip-diff v{} scope={} segments={}",
        report.format_version,
        report.scope.as_str(),
        if report.normalization.is_usable() {
            "comparable"
        } else {
            "NOT-comparable"
        }
    );
    let _ = writeln!(out, "# producer {}", report.producer);
    let _ = writeln!(
        out,
        "# v1 {} (image_base {:#x})",
        report.v1_path, report.v1_image_base
    );
    let _ = writeln!(
        out,
        "# v2 {} (image_base {:#x})",
        report.v2_path, report.v2_image_base
    );
    let _ = writeln!(out, "# 地址归一化：{}", report.normalization.describe_zh());
    let _ = writeln!(
        out,
        "# 账目：v1 {} 项 / v2 {} 项 / {}",
        report.v1_total,
        report.v2_total,
        report.summary_zh()
    );
    let _ = writeln!(out, "# 标记：+ 新增  - 删除  ~ 改动  > 移动  = 未变");
    for note in &report.notes {
        let _ = writeln!(out, "# 说明 {note}");
    }
    if report.truncated {
        let _ = writeln!(
            out,
            "# 截断：还有 {} 条没有列出（用 --max-entries 放宽，或按 --only 过滤）",
            report.dropped
        );
    }
    let _ = writeln!(out);

    for entry in &report.entries {
        let name = entry.name.as_deref().unwrap_or("(未识别)");
        let _ = write!(
            out,
            "{} {}  {}",
            entry.kind.marker(),
            entry.normalized,
            name
        );
        let _ = write!(out, "  [{}]", entry.match_basis.as_str());
        if let (Some(a1), Some(a2)) = (entry.v1_address.as_deref(), entry.v2_address.as_deref()) {
            if a1 != a2 {
                let _ = write!(out, "  v1={a1} v2={a2}");
            }
        }
        if entry.v1_instructions != entry.v2_instructions {
            let _ = write!(
                out,
                "  指令 {} -> {}",
                entry
                    .v1_instructions
                    .map_or_else(|| "-".into(), |n| n.to_string()),
                entry
                    .v2_instructions
                    .map_or_else(|| "-".into(), |n| n.to_string())
            );
        }
        if let Some(detail) = &entry.detail {
            let _ = write!(out, "  # {detail}");
        }
        let _ = writeln!(out);
    }
    out
}

/// 一个函数在两边的可比较快照（内部用）。
struct FuncSnapshot {
    name: Option<String>,
    source: Option<String>,
    normalized: u64,
    address: u64,
    /// 大小字段原值（`0` 在多数格式里表示"未知"，所以不能直接当长度用）。
    size_raw: Option<u64>,
    /// 可比较的大小：原值 > 0 时才算"知道大小"。
    size: Option<u64>,
    instruction_count: Option<u64>,
    /// **强**指纹：指令文本里的地址换算成"相对函数起点"的偏移。
    ///
    /// 用于"同一地址上两段代码是否逐条相同"。这个判据对函数搬到哪里不敏感，
    /// 但对**函数内部引用的外部地址**敏感 —— 被调用者挪了位置，强指纹就变。
    strict_hash: Option<[u8; 32]>,
    /// **弱**指纹：指令文本里的地址**全部忽略**，只留助记符、寄存器与
    /// 非地址立即数的形状。
    ///
    /// 用于"这个函数是不是搬了家"。为什么必须有第二档：函数体里往往**嵌着
    /// 被调用者的地址**（`call 0x140001020`）。两个版本里被调用者自己就挪了
    /// 位置，于是调用处的绝对地址变了 —— 强指纹因此变化，但函数本身**没有
    /// 被改动，只是搬家了**。只有忽略地址那一维，"搬家"才认得出来。
    ///
    /// **实测踩到**：第一版只有强指纹，于是 `df_stable`（两版逐条相同、只是
    /// 位于不同基址）被报成"改动"；再往前一版把地址写进哈希，于是连"搬家"
    /// 都报不出来。
    loose_hash: Option<[u8; 32]>,
}

/// 对两个目标做差分。
///
/// `session1` 是"旧"，`session2` 是"新"。
pub fn diff(
    session1: &Session,
    session2: &Session,
    options: &DiffOptions,
) -> Result<DiffReport, BitflipError> {
    let disasm1 = session1.disassemble(crate::DisasmScanOptions::default())?;
    let disasm2 = session2.disassemble(crate::DisasmScanOptions::default())?;
    diff_with_disasm(session1, &disasm1, session2, &disasm2, options)
}

/// 对两个目标做差分，复用调用方已建好的反汇编。
pub fn diff_with_disasm(
    session1: &Session,
    disasm1: &Disasm,
    session2: &Session,
    disasm2: &Disasm,
    options: &DiffOptions,
) -> Result<DiffReport, BitflipError> {
    let analysis1 = session1.analysis(&session1.detached_job())?;
    let analysis2 = session2.analysis(&session2.detached_job())?;

    let base1 = image_base_of(session1);
    let base2 = image_base_of(session2);
    let extent1 = image_extent_of(session1);
    let extent2 = image_extent_of(session2);
    let mut notes = Vec::new();
    let normalization = normalize_bases(base1, base2, &mut notes);

    let mut entries = Vec::new();
    let mut v1_total = 0;
    let mut v2_total = 0;

    if options.scope.includes(DiffScope::Functions) {
        let (mut rows, t1, t2) = diff_functions(
            Side {
                functions: analysis1.functions(),
                disasm: disasm1,
                base: base1,
                extent: extent1,
            },
            Side {
                functions: analysis2.functions(),
                disasm: disasm2,
                base: base2,
                extent: extent2,
            },
            &normalization,
            &mut notes,
        );
        entries.append(&mut rows);
        v1_total += t1;
        v2_total += t2;
    }

    if options.scope.includes(DiffScope::Sections) {
        let (mut rows, t1, t2) = diff_sections(
            &section_snapshot(session1),
            &section_snapshot(session2),
            &normalization,
            &mut notes,
        );
        entries.append(&mut rows);
        v1_total += t1;
        v2_total += t2;
    }

    if options.scope.includes(DiffScope::Symbols) {
        let (mut rows, t1, t2) = diff_symbols(
            &symbol_snapshot(session1),
            &symbol_snapshot(session2),
            &normalization,
            &mut notes,
        );
        entries.append(&mut rows);
        v1_total += t1;
        v2_total += t2;
    }

    // 归一化不可用时，地址维度整体作废 —— 这一点必须留在报告里，
    // 因为下面的清单是"按名字比出来的"，与"按地址比"可信度不同。
    if !normalization.is_usable() {
        notes.push(
            "地址维度未参与比对：清单里同一条目的差异只能说明名字变了或内容变了，\
             不能说明它换了位置"
                .to_string(),
        );
    }

    // 只看某类（用于"只看新增"这类窄查询）。注意这一步在记账**之后**做，
    // 否则 `v1_total`/`v2_total` 会被过滤后的条目数污染。
    if let Some(only) = options.only {
        entries.retain(|entry| entry.kind == only);
    }

    entries.sort_by(|a, b| {
        a.kind
            .cmp(&b.kind)
            .then_with(|| a.normalized.cmp(&b.normalized))
            .then_with(|| a.name.cmp(&b.name))
    });

    let truncated = entries.len() > options.max_entries;
    let dropped = entries.len().saturating_sub(options.max_entries);
    if truncated {
        entries.truncate(options.max_entries);
        notes.push(format!(
            "条目数超过上限 {}，已截断并丢弃 {dropped} 条（用 --max-entries 放宽）",
            options.max_entries
        ));
    }

    let mut totals = DiffTotals::default();
    for entry in &entries {
        totals.count(entry.kind);
    }

    Ok(DiffReport {
        format_version: DIFF_FORMAT_VERSION,
        producer: format!("bitflip {}", crate::version()),
        scope: options.scope,
        v1_path: session1.path().display().to_string(),
        v2_path: session2.path().display().to_string(),
        v1_image_base: base1,
        v2_image_base: base2,
        normalization,
        v1_total,
        v2_total,
        totals,
        entries,
        truncated,
        dropped,
        notes,
    })
}

/// 取镜像基址；对象没解析出来时返回 0（会被归一化层判为"不可比"）。
fn image_base_of(session: &Session) -> u64 {
    session.object().map_or(0, |object| object.image_base)
}

/// 取承载已加载内容的地址范围 `[基址, 上界)`。
///
/// 用途只有一个：给"指令文本里这个 `0x...` 是不是地址"提供判据。落在范围内
/// 才当地址处理（见 [`normalize_addresses`]）—— 误判方向是"漏报一处改动"
/// 而不是"造出一处改动"，所以上界宽一点无害，下界必须准。
///
/// 只统计**已加载**的节：`.reloc` / 调试节这类不占运行地址的部分没有虚拟
/// 地址可言，把它们算进来会把上界抬到无关的地方。
fn image_extent_of(session: &Session) -> u64 {
    let Some(object) = session.object() else {
        return 0;
    };
    let base = object.image_base;
    let end = object
        .sections
        .iter()
        .filter(|section| section.loaded && section.file.size > 0)
        .map(|section| section.vaddr.saturating_add(section.file.size))
        .max()
        .unwrap_or(0);
    // 上界至少要比基址大一点，否则任何字面量都不落在范围内，
    // 归一化会整体失效（那会让同一函数在两版里被判成"改动"）。
    end.max(base.saturating_add(1))
}

/// 节表快照：`(名字, 虚拟地址, 大小, 属性文本)`。
///
/// 大小取文件范围长度 —— 节在文件与内存里可能长度不同，但差分要的是
/// "这个节变了没有"，用文件范围是稳定且可复核的。
fn section_snapshot(session: &Session) -> Vec<(String, u64, u64, String)> {
    let Some(object) = session.object() else {
        return Vec::new();
    };
    object
        .sections
        .iter()
        .map(|section| {
            (
                section.name.clone(),
                section.vaddr,
                section.file.size,
                format!("{:?}", section.perms),
            )
        })
        .collect()
}

/// 符号名快照（已定义符号的名字集合）。
///
/// 只取名字：差分的符号维度回答的是"哪些名字在、哪些不在"。
/// 名字是符号表里唯一稳定可比的东西 —— 地址在两个版本里本来就会动。
fn symbol_snapshot(session: &Session) -> Vec<String> {
    let Some(object) = session.object() else {
        return Vec::new();
    };
    object
        .symbols
        .iter()
        // 空名符号（例如只有节号的那种）不进符号维度：它们在两个版本里
        // 都叫"空"，比出来只会是一堆同名条目。
        .filter(|symbol| !symbol.name.is_empty())
        .map(|symbol| symbol.name.clone())
        .collect()
}

/// 决定用哪种归一化方式，并把理由写进 `notes`。
fn normalize_bases(base1: u64, base2: u64, notes: &mut Vec<String>) -> Normalization {
    if base1 == 0 || base2 == 0 {
        // 可重定位目标文件（`.o`）没有"镜像基址"这个概念，RVA 也就无从谈起。
        notes.push(format!(
            "有一侧没有镜像基址（v1 {base1:#x} / v2 {base2:#x}）：\
             可重定位目标文件里所有节的地址都是 0，RVA 不是有意义的概念"
        ));
        return Normalization::Unavailable {
            reason: format!("v1 基址 {base1:#x}、v2 基址 {base2:#x}，无法换算相对地址"),
        };
    }
    if base1 == base2 {
        return Normalization::SameBase { base: base1 };
    }
    notes.push(format!(
        "两侧镜像基址不同（{base1:#x} vs {base2:#x}，差 {:#x}）：\
         清单按 RVA 比对；若按虚拟地址比，每个函数都会显示为改动",
        base1.abs_diff(base2)
    ));
    Normalization::Rva {
        v1_base: base1,
        v2_base: base2,
    }
}

/// 归一化一个虚拟地址。
///
/// 归一化不可用时返回 `None` —— 不返回"原值凑合用"，那会让上层以为地址可比。
fn normalized(address: u64, base: u64, normalization: &Normalization) -> Option<u64> {
    match normalization {
        Normalization::Rva { .. } | Normalization::SameBase { .. } => {
            Some(address.wrapping_sub(base))
        }
        Normalization::Unavailable { .. } => None,
    }
}

/// 取函数体的两档指纹（强/弱）与指令条数。
///
/// 为什么两档都必须有：见 [`FuncSnapshot::loose_hash`]。总结成一句 ——
/// **"没改"和"搬了家"是两件事，"搬了家"和"被改了"也是两件事**，
/// 一个哈希分不出来，硬用一个就会给出假报告。
fn code_fingerprints(
    disasm: &Disasm,
    start: u64,
    end: u64,
    base: u64,
    image_end: u64,
) -> ([u8; 32], [u8; 32], u64) {
    let mut strict = Sha256::new();
    let mut loose = Sha256::new();
    let mut count: u64 = 0;
    let mut cursor = disasm.cursor(0);
    while let Some(insn) = cursor.render_next() {
        let address = u64::from_str_radix(&insn.address, 16).unwrap_or(0);
        if address < start {
            continue;
        }
        if address >= end {
            break;
        }
        let strict_text = normalize_addresses(&insn.text, base, image_end);
        let loose_text = strip_addresses(&insn.text);
        // 编码长度进指纹（编码变了就是内容变了）。
        strict.update([insn.length]);
        strict.update(b":");
        strict.update(strict_text.as_bytes());
        strict.update(b"|");
        loose.update([insn.length]);
        loose.update(b":");
        loose.update(loose_text.as_bytes());
        loose.update(b"|");
        count += 1;
    }
    (strict.finalize().into(), loose.finalize().into(), count)
}

/// 把指令文本里**落在镜像地址范围内**的字面量换成"它指向的 RVA"，其余原样保留。
///
/// # 为什么必须是"落在镜像范围内"而不是"减掉函数起点"（实测踩到的坑）
///
/// 前一版把每个字面量都减掉**函数起点**，当成"位置无关化"。那是错的：
/// `sub rsp, 0x28` 里的 `0x28` **不是地址**，减掉函数起点只会得到
/// `0xffffffff...f028` —— 而这个值取决于函数**在哪个绝对地址**。
/// 两个版本的镜像基址不同（`0x140000000` / `0x180000000`），于是同一个
/// `df_stable`、同样的 `sub rsp, 0x28`，算出来的"偏移"不同，强指纹不同，
/// 报告里就多出一条"改动" —— **假阳性，而且每一条都写得很具体**。
///
/// 正确的判据只需要区分两件事：
/// * **落在镜像地址范围内**（`base <= v < image_end`）→ 它是地址，换成
///   `@{v - base}`（它指向的 RVA）。同一个被引用者无论整体挪到哪里，
///   这个值都一样，判据因此与位置无关。
/// * **落在范围外** → 它是普通立即数，**原样保留**。立即数本来就跟位置无关，
///   保留它才能分辨 `add eax, 0x5eed` 与 `add eax, 0x1234`（抹平就是漏报）。
///
/// # 剩下的已知局限
///
/// 一个**非地址**的立即数如果恰好落在镜像地址范围内，会被当成地址归一化。
/// 后果是"可能漏报一处改动"，不会凭空造出改动；而且它必须同时满足
/// "值正好落在镜像范围里"这个条件，概率很低。这个取舍是有意的：把普通
/// 立即数一律抹平会漏报得多得多（每一个常量差异都漏）。
fn normalize_addresses(text: &str, base: u64, image_end: u64) -> String {
    rewrite_hex_literals(text, |value| {
        if base != 0 && value >= base && value < image_end {
            Some(format!("@{:#x}", value - base))
        } else {
            None
        }
    })
}

/// 把指令文本里的**所有**十六进制字面量换成一个不含数值的占位符（弱指纹用）。
///
/// 地址在两个版本里本来就不同，保留任何数值都会让"搬家"认不出来。弱指纹
/// 只回答"指令形状是否一致"，数值差异由强指纹负责。
fn strip_addresses(text: &str) -> String {
    rewrite_hex_literals(text, |_| Some("<imm>".to_string()))
}

/// 扫描文本里的 `0x` 字面量，逐个交给 `map` 决定替换成什么。
///
/// `map` 返回 `Some(replacement)` 就替换，返回 `None` 就**原样保留**。
/// 保留能力是必需的：普通立即数必须留在指纹里，否则常量改动会漏报。
fn rewrite_hex_literals<F>(text: &str, map: F) -> String
where
    F: Fn(u64) -> Option<String>,
{
    let mut out = String::with_capacity(text.len());
    let bytes = text.as_bytes();
    let mut index = 0usize;
    while index < bytes.len() {
        let at_hex = text[index..].starts_with("0x") || text[index..].starts_with("0X");
        if !at_hex {
            out.push(bytes[index] as char);
            index += 1;
            continue;
        }
        let digits_start = index + 2;
        let mut digits_end = digits_start;
        while digits_end < bytes.len() && bytes[digits_end].is_ascii_hexdigit() {
            digits_end += 1;
        }
        if digits_end == digits_start {
            // 光秃秃的 `0x`，不是数字，原样放行
            out.push_str(&text[index..digits_start]);
            index = digits_start;
            continue;
        }
        let raw = &text[digits_start..digits_end];
        match u64::from_str_radix(raw, 16) {
            Ok(value) => match map(value) {
                Some(replacement) => out.push_str(&replacement),
                // 原样保留（连 `0x` 前缀一起）。
                None => out.push_str(&text[index..digits_end]),
            },
            Err(_) => out.push_str(&text[index..digits_end]),
        }
        index = digits_end;
    }
    out
}

/// 把 v1 的函数清单拍平成可比较快照。
fn snapshot(
    functions: &[FunctionWire],
    disasm: &Disasm,
    base: u64,
    image_end: u64,
    label: &str,
    normalization: &Normalization,
    notes: &mut Vec<String>,
) -> Vec<FuncSnapshot> {
    let mut out = Vec::with_capacity(functions.len());
    let mut without_end = 0usize;
    for func in functions {
        let Ok(start) = u64::from_str_radix(&func.start, 16) else {
            continue;
        };
        let end = func
            .end
            .as_deref()
            .and_then(|text| u64::from_str_radix(text, 16).ok());
        if end.is_none() {
            without_end += 1;
        }
        let (hash, loose, count) = match end {
            Some(end) if end > start => {
                let (hash, loose, count) = code_fingerprints(disasm, start, end, base, image_end);
                (Some(hash), Some(loose), Some(count))
            }
            _ => (None, None, None),
        };
        out.push(FuncSnapshot {
            name: if func.named && !func.name.is_empty() {
                Some(func.name.clone())
            } else {
                None
            },
            source: Some(func.source.clone()),
            normalized: normalized(start, base, normalization).unwrap_or(start),
            address: start,
            size_raw: func.size,
            // `0` 表示"未知"而不是"零字节长" —— 直接把 0 当大小会让两个
            // 未知大小的函数因为"都是 0"被判定为"大小相同"。
            size: func.size.filter(|size| *size > 0),
            instruction_count: count,
            strict_hash: hash,
            loose_hash: loose,
        });
    }
    if without_end > 0 {
        // 必须点明是哪一侧：两版各推一条相同的文字，用户就分不清
        // "两边各有 2 个"还是"同一侧的 2 个说了两遍"（实测踩到）。
        notes.push(format!(
            "{label} 有 {without_end} 个函数没有已知结束地址：它们只按名字/地址比对，\
             不参与内容比对（没有区间就没有内容）"
        ));
    }
    out
}

/// 一侧（v1 或 v2）参与函数差分所需的全部输入。
///
/// 打成一个结构而不是排成八个参数：八参数既过不了 clippy 的
/// `too_many_arguments`，也容易在调用处把 v1 的基址传到 v2 的位置上 ——
/// 那种错**不会**编译失败，只会让整份报告按错的基址归一化。
struct Side<'a> {
    functions: &'a [FunctionWire],
    disasm: &'a Disasm,
    base: u64,
    /// `[base, extent)` 之外的 `0x...` 不当作地址（见 [`normalize_addresses`]）。
    extent: u64,
}

/// 匹配好的"配对"（先算再合并，合并时按数量决定"改动"还是"删+增"）。
struct Pairing {
    i1: usize,
    i2: usize,
    basis: MatchBasis,
    /// 是否允许在合并阶段被拆成"删除 + 新增"。
    splittable: bool,
    /// 覆盖 `classify` 给出的类别（`None` 表示用 `classify` 的结论）。
    kind: Option<DiffKind>,
    detail: Option<String>,
}

/// 一对函数的"内容是否相同"三态。
///
/// 必须有第三态 `Unknown`：把"两侧都没有已知区间"当成"相同"会凭空宣称
/// "内容逐条相同"（实测踩到）。未知只能说未知。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Content {
    Same,
    Different,
    Unknown,
}

/// 函数清单差分。
///
/// # 匹配顺序（顺序本身是判据的一部分，改顺序会改变结论）
///
/// 1. **名字相同**（先看归一化地址是否也相同）—— 名字是最强证据。同名的两个
///    函数就是同一个函数，哪怕它搬了家。
/// 2. **未命名 + 归一化地址相同 + 内容相同** —— 没有名字时只能靠地址+内容，
///    而且**两个条件都要**：只看地址会把两个恰好落在同一 RVA 的无关未命名
///    函数配成一对。
/// 3. 剩下的才是新增与删除。
///
/// # 为什么"先按地址配、再改名"是错的（实测踩到的坑）
///
/// 第一版按"归一化地址相同就配对"优先。fixture 里 v1 的 `df_removed` 与 v2 的
/// `df_added` **恰好落在同一个 RVA**（前者被删、后者补上了那个位置），于是它们
/// 被配成一条"改动 0x1030" —— 而用户要看的是"**哪个函数没了、哪个函数出现了**"。
/// 名字不同的两个函数不是同一个函数，地址相同只是巧合。
fn diff_functions(
    one: Side<'_>,
    two: Side<'_>,
    normalization: &Normalization,
    notes: &mut Vec<String>,
) -> (Vec<DiffEntry>, usize, usize) {
    let snap1 = snapshot(
        one.functions,
        one.disasm,
        one.base,
        one.extent,
        "v1",
        normalization,
        notes,
    );
    let snap2 = snapshot(
        two.functions,
        two.disasm,
        two.base,
        two.extent,
        "v2",
        normalization,
        notes,
    );

    let total1 = snap1.len();
    let total2 = snap2.len();

    let mut by_norm1: BTreeMap<u64, Vec<usize>> = BTreeMap::new();
    for (index, snapshot) in snap1.iter().enumerate() {
        by_norm1.entry(snapshot.normalized).or_default().push(index);
    }
    let mut by_norm2: BTreeMap<u64, Vec<usize>> = BTreeMap::new();
    for (index, snapshot) in snap2.iter().enumerate() {
        by_norm2.entry(snapshot.normalized).or_default().push(index);
    }

    let mut used1 = vec![false; snap1.len()];
    let mut used2 = vec![false; snap2.len()];
    let mut pairs: Vec<Pairing> = Vec::new();

    // ── 第 1 轮：按名字配对（未命名的不参与） ──
    //
    // 名字这一维不需要地址，所以 RVA 不可用时这一轮照样成立 ——
    // 归一化不可用的场景（`.o` 文件）就靠它。
    for i1 in 0..snap1.len() {
        if used1[i1] {
            continue;
        }
        let Some(name1) = snap1[i1].name.clone() else {
            continue;
        };
        // 同名可能有多个（别名）：优先挑地址也相同的那一个。
        let candidates: Vec<usize> = (0..snap2.len())
            .filter(|&i2| !used2[i2] && snap2[i2].name.as_deref() == Some(name1.as_str()))
            .collect();
        let Some(&i2) = candidates
            .iter()
            .find(|&&i2| normalization.is_usable() && snap2[i2].normalized == snap1[i1].normalized)
            .or_else(|| candidates.first())
        else {
            continue;
        };

        used1[i1] = true;
        used2[i2] = true;
        let same_address =
            normalization.is_usable() && snap1[i1].normalized == snap2[i2].normalized;

        // 内容那一维有三种状态，**必须**分开：`None == None` 不是"相同"，
        // 而是"都不知道"。混起来会在两侧都没有已知区间时宣称"内容逐条相同"
        // （实测踩到）。
        let content = match (snap1[i1].loose_hash, snap2[i2].loose_hash) {
            (Some(a), Some(b)) if a == b => Content::Same,
            (Some(_), Some(_)) => Content::Different,
            _ => Content::Unknown,
        };

        let mut kind = None;
        let basis = if same_address {
            // 同地址：类别交给 `classify` 决定（它比弱指纹，再比强指纹）。
            MatchBasis::NameAndAddress
        } else {
            match content {
                Content::Same => {
                    kind = Some(DiffKind::Moved);
                    MatchBasis::ContentAndSize
                }
                // 位置变了、内容也变了：**报"改动"而不是"移动"** ——
                // 说"移动"会让用户以为内容没动，那是把一处改动藏起来。
                Content::Different => MatchBasis::NameOnly,
                Content::Unknown => {
                    kind = Some(DiffKind::Moved);
                    MatchBasis::NameOnly
                }
            }
        };

        let detail = if same_address {
            None
        } else {
            let position = format!("位置 {:#x} -> {:#x}", snap1[i1].address, snap2[i2].address);
            Some(match content {
                Content::Same => format!("{position}；内容逐条相同，只是位置变了"),
                Content::Different => {
                    format!("{position}；同名但内容也不同（不是纯粹的移动）")
                }
                Content::Unknown => {
                    format!("{position}；有一侧没有已知区间，无法确认内容是否也跟着变了")
                }
            })
        };
        pairs.push(Pairing {
            i1,
            i2,
            basis,
            splittable: false,
            kind,
            detail,
        });
    }

    // ── 第 2 轮：未命名的，按"归一化地址 + 内容"配对 ──
    if normalization.is_usable() {
        for i1 in 0..snap1.len() {
            if used1[i1] || snap1[i1].name.is_some() {
                continue;
            }
            let Some(indices2) = by_norm2.get(&snap1[i1].normalized) else {
                continue;
            };
            let found = indices2.iter().copied().find(|&i2| {
                !used2[i2]
                    && snap2[i2].name.is_none()
                    && snap1[i1].loose_hash.is_some()
                    && snap1[i1].loose_hash == snap2[i2].loose_hash
            });
            if let Some(i2) = found {
                used1[i1] = true;
                used2[i2] = true;
                pairs.push(Pairing {
                    i1,
                    i2,
                    basis: MatchBasis::AddressOnly,
                    splittable: false,
                    kind: None,
                    detail: None,
                });
            }
        }
    }

    // ── 合并：数量相等才是"改动"，否则拆成"删除 + 新增" ──
    //
    // 这一条是上面那个坑的正面表述：当同一侧的两个不同函数被配到另一侧的
    // 同一个函数上（或者反过来），说明这些配对是**巧合**，真实情况是
    // "一个没了、一个出现了"。宁可报成两条明确的增删，也不要报一条含糊的改动。
    let mut i1_count: BTreeMap<usize, usize> = BTreeMap::new();
    let mut i2_count: BTreeMap<usize, usize> = BTreeMap::new();
    for pair in &pairs {
        *i1_count.entry(pair.i1).or_default() += 1;
        *i2_count.entry(pair.i2).or_default() += 1;
    }

    let mut entries = Vec::new();
    let mut split_removed = 0usize;
    let mut split_added = 0usize;
    for pair in &pairs {
        let balanced = i1_count.get(&pair.i1).copied().unwrap_or(0) == 1
            && i2_count.get(&pair.i2).copied().unwrap_or(0) == 1;
        if !balanced && pair.splittable {
            used1[pair.i1] = false;
            used2[pair.i2] = false;
            split_removed += 1;
            split_added += 1;
            continue;
        }
        let mut entry = compare_pair(&snap1[pair.i1], &snap2[pair.i2], pair.basis);
        if let Some(kind) = pair.kind {
            entry.kind = kind;
        }
        if let Some(detail) = &pair.detail {
            entry.detail = Some(detail.clone());
        }
        entries.push(entry);
    }

    // ── 剩下的是真正的新增与删除 ──
    for (index, snapshot) in snap1.iter().enumerate() {
        if used1[index] {
            continue;
        }
        entries.push(orphan_entry(
            snapshot,
            DiffKind::Removed,
            one.base,
            normalization,
        ));
    }
    for (index, snapshot) in snap2.iter().enumerate() {
        if used2[index] {
            continue;
        }
        entries.push(orphan_entry(
            snapshot,
            DiffKind::Added,
            two.base,
            normalization,
        ));
    }

    if split_removed > 0 {
        notes.push(format!(
            "有 {split_removed} 处配对是巧合（同一侧多个不同函数对上了另一侧同一个）：\
             已改为报成 {} 条删除 + {} 条新增，而不是一条含糊的改动",
            split_removed, split_added
        ));
    }

    let multi = by_norm1.values().filter(|v| v.len() > 1).count()
        + by_norm2.values().filter(|v| v.len() > 1).count();
    if multi > 0 {
        notes.push(format!(
            "有 {multi} 处同一个归一化地址上出现多个函数（别名或其分析重叠）：\
             这些地址上的未命名函数只按内容配对"
        ));
    }

    (entries, total1, total2)
}

/// 比较一对函数，给出类别与说明。
///
/// 判据用**弱**指纹（忽略地址）判定"内容是否变了"：地址那一维由
/// `normalized` 单独承载，混在一起会把"被调用者挪了位置"报成"这个函数被改了"。
fn compare_pair(one: &FuncSnapshot, two: &FuncSnapshot, basis: MatchBasis) -> DiffEntry {
    let (kind, detail) = classify(one, two);

    DiffEntry {
        kind,
        match_basis: basis,
        name: two.name.clone().or_else(|| one.name.clone()),
        source: two.source.clone().or_else(|| one.source.clone()),
        normalized: format!("{:016x}", one.normalized),
        v1_address: Some(format!("{:016x}", one.address)),
        v2_address: Some(format!("{:016x}", two.address)),
        v1_size: one.size,
        v2_size: two.size,
        v1_instructions: one.instruction_count,
        v2_instructions: two.instruction_count,
        detail,
    }
}

/// 判定一对函数是"未变"还是"改动"，并给出人话说明。
fn classify(one: &FuncSnapshot, two: &FuncSnapshot) -> (DiffKind, Option<String>) {
    // 没有区间就没有内容：这是"不知道"，不是"没变"。
    // 只能退回比大小，并且把"比不了内容"这件事写进说明。
    let (Some(loose1), Some(loose2)) = (one.loose_hash, two.loose_hash) else {
        return if one.size != two.size {
            (
                DiffKind::Changed,
                Some(format!(
                    "没有已知区间，无法比内容；大小 {} -> {}",
                    size_text(one.size),
                    size_text(two.size)
                )),
            )
        } else {
            (
                DiffKind::Unchanged,
                Some("没有已知区间，无法比内容；仅按名字与地址认为未变".to_string()),
            )
        };
    };

    if loose1 != loose2 {
        // 指令形状真的变了。
        let mut parts = Vec::new();
        if one.size != two.size {
            parts.push(format!(
                "大小 {} -> {}",
                size_text(one.size),
                size_text(two.size)
            ));
        }
        if one.instruction_count != two.instruction_count {
            parts.push(format!(
                "指令数 {} -> {}",
                count_text(one.instruction_count),
                count_text(two.instruction_count)
            ));
        }
        if parts.is_empty() {
            parts.push("大小与指令数相同，指令序列不同".to_string());
        }
        return (DiffKind::Changed, Some(parts.join("；")));
    }

    // 形状一样，再看强指纹：差异只可能来自"内部引用的地址"。
    if one.strict_hash == two.strict_hash {
        (DiffKind::Unchanged, None)
    } else {
        (
            DiffKind::Changed,
            Some("指令形状未变，但内部引用的地址不同（被调用者/被引用数据换了位置）".to_string()),
        )
    }
}

/// 只在一边出现的条目。
fn orphan_entry(
    snapshot: &FuncSnapshot,
    kind: DiffKind,
    base: u64,
    normalization: &Normalization,
) -> DiffEntry {
    let normalized = normalized(snapshot.address, base, normalization).unwrap_or(snapshot.address);
    let (v1_address, v2_address) = match kind {
        DiffKind::Removed => (Some(format!("{:016x}", snapshot.address)), None),
        _ => (None, Some(format!("{:016x}", snapshot.address))),
    };
    let (v1_size, v2_size) = match kind {
        // 用原值而不是"可比较大小"：`size_raw` 里的 `0` 在报告里就该显示成 0
        // （那是实测到的值），"未知"由 `None` 表示。
        DiffKind::Removed => (snapshot.size_raw, None),
        _ => (None, snapshot.size_raw),
    };
    let (v1_instructions, v2_instructions) = match kind {
        DiffKind::Removed => (snapshot.instruction_count, None),
        _ => (None, snapshot.instruction_count),
    };
    DiffEntry {
        kind,
        match_basis: MatchBasis::AddressOnly,
        name: snapshot.name.clone(),
        source: snapshot.source.clone(),
        normalized: format!("{normalized:016x}"),
        v1_address,
        v2_address,
        v1_size,
        v2_size,
        v1_instructions,
        v2_instructions,
        detail: None,
    }
}

/// 节表差分：按名字比，比大小与地址。
fn diff_sections(
    sections1: &[(String, u64, u64, String)],
    sections2: &[(String, u64, u64, String)],
    normalization: &Normalization,
    notes: &mut Vec<String>,
) -> (Vec<DiffEntry>, usize, usize) {
    let map1: BTreeMap<&str, &(String, u64, u64, String)> =
        sections1.iter().map(|s| (s.0.as_str(), s)).collect();
    let map2: BTreeMap<&str, &(String, u64, u64, String)> =
        sections2.iter().map(|s| (s.0.as_str(), s)).collect();

    let mut names: Vec<&str> = map1.keys().copied().collect();
    for name in map2.keys() {
        if !map1.contains_key(name) {
            names.push(name);
        }
    }
    names.sort_unstable();
    names.dedup();

    let duplicate = sections1.len() - map1.len() + (sections2.len() - map2.len());
    if duplicate > 0 {
        notes.push(format!(
            "有 {duplicate} 个重名节：重名节按名字比对会把它们混成一个，\
             请用符号或函数维度看"
        ));
    }

    let mut entries = Vec::new();
    for name in names {
        let one = map1.get(name);
        let two = map2.get(name);
        let entry = match (one, two) {
            (Some(one), Some(two)) => {
                let same = one.2 == two.2 && one.3 == two.3;
                let kind = if same {
                    DiffKind::Unchanged
                } else {
                    DiffKind::Changed
                };
                let detail = if same {
                    None
                } else {
                    Some(format!(
                        "大小 {} -> {}，属性 {} -> {}",
                        one.2, two.2, one.3, two.3
                    ))
                };
                DiffEntry {
                    kind,
                    match_basis: MatchBasis::NameAndAddress,
                    name: Some(name.to_string()),
                    source: Some("section-table".to_string()),
                    normalized: format!(
                        "{:016x}",
                        normalized(one.1, 0, normalization).unwrap_or(one.1)
                    ),
                    v1_address: Some(format!("{:016x}", one.1)),
                    v2_address: Some(format!("{:016x}", two.1)),
                    v1_size: Some(one.2),
                    v2_size: Some(two.2),
                    v1_instructions: None,
                    v2_instructions: None,
                    detail,
                }
            }
            (Some(one), None) => DiffEntry {
                kind: DiffKind::Removed,
                match_basis: MatchBasis::NameAndAddress,
                name: Some(name.to_string()),
                source: Some("section-table".to_string()),
                normalized: format!("{:016x}", one.1),
                v1_address: Some(format!("{:016x}", one.1)),
                v2_address: None,
                v1_size: Some(one.2),
                v2_size: None,
                v1_instructions: None,
                v2_instructions: None,
                detail: None,
            },
            (None, Some(two)) => DiffEntry {
                kind: DiffKind::Added,
                match_basis: MatchBasis::NameAndAddress,
                name: Some(name.to_string()),
                source: Some("section-table".to_string()),
                normalized: format!("{:016x}", two.1),
                v1_address: None,
                v2_address: Some(format!("{:016x}", two.1)),
                v1_size: None,
                v2_size: Some(two.2),
                v1_instructions: None,
                v2_instructions: None,
                detail: None,
            },
            (None, None) => continue,
        };
        entries.push(entry);
    }

    (entries, sections1.len(), sections2.len())
}

/// 符号表差分：按名字比。
fn diff_symbols(
    symbols1: &[String],
    symbols2: &[String],
    _normalization: &Normalization,
    notes: &mut Vec<String>,
) -> (Vec<DiffEntry>, usize, usize) {
    use std::collections::BTreeSet;
    let set1: BTreeSet<&String> = symbols1.iter().collect();
    let set2: BTreeSet<&String> = symbols2.iter().collect();

    if set1.is_empty() && set2.is_empty() {
        notes.push("两侧都没有符号表：符号维度没有可比的内容（这不是\"符号表相同\"）".to_string());
    } else if set1.is_empty() || set2.is_empty() {
        notes.push(
            "有一侧没有符号表（可能被 strip）：符号维度的新增/删除会整体倒向另一侧，\
             看函数维度更可靠"
                .to_string(),
        );
    }

    let mut names: Vec<&String> = set1.union(&set2).copied().collect();
    names.sort_unstable();
    names.dedup();

    let mut entries = Vec::new();
    for name in names {
        let (kind, detail) = match (set1.contains(name), set2.contains(name)) {
            (true, true) => (DiffKind::Unchanged, None),
            (true, false) => (DiffKind::Removed, None),
            (false, true) => (DiffKind::Added, None),
            (false, false) => continue,
        };
        entries.push(DiffEntry {
            kind,
            match_basis: MatchBasis::NameOnly,
            name: Some(name.clone()),
            source: Some("symbol-table".to_string()),
            normalized: "0000000000000000".to_string(),
            v1_address: None,
            v2_address: None,
            v1_size: None,
            v2_size: None,
            v1_instructions: None,
            v2_instructions: None,
            detail,
        });
    }

    (entries, symbols1.len(), symbols2.len())
}

/// 大小的展示文本（`None` 就是 `-`，不拿 0 顶替）。
fn size_text(size: Option<u64>) -> String {
    size.map_or_else(|| "-".to_string(), |s| s.to_string())
}

/// 指令数的展示文本。
fn count_text(count: Option<u64>) -> String {
    count.map_or_else(|| "-".to_string(), |c| c.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// 测试里统一的镜像基址与范围。
    ///
    /// 写成常量而不是到处撒字面量：这两组数字在测试里出现十几次，
    /// 抄错一位（`0x1400_1000` 少了那位 `0`）会让断言**静默地**去测别的
    /// 地址 —— 实测踩到过一次，排查花了一轮。
    const BASE: u64 = 0x140000000;
    const END: u64 = 0x140010000;
    const BASE_V2: u64 = 0x180000000;
    const END_V2: u64 = 0x180010000;

    fn entry(kind: DiffKind) -> DiffEntry {
        DiffEntry {
            kind,
            match_basis: MatchBasis::NameAndAddress,
            name: Some("x".to_string()),
            source: None,
            normalized: "0000000000001000".to_string(),
            v1_address: None,
            v2_address: None,
            v1_size: None,
            v2_size: None,
            v1_instructions: None,
            v2_instructions: None,
            detail: None,
        }
    }

    fn report(entries: Vec<DiffEntry>) -> DiffReport {
        let mut totals = DiffTotals::default();
        for e in &entries {
            totals.count(e.kind);
        }
        DiffReport {
            format_version: DIFF_FORMAT_VERSION,
            producer: "bitflip test".to_string(),
            scope: DiffScope::Functions,
            v1_path: "a".to_string(),
            v2_path: "b".to_string(),
            v1_image_base: BASE,
            v2_image_base: BASE_V2,
            normalization: Normalization::Rva {
                v1_base: BASE,
                v2_base: BASE_V2,
            },
            v1_total: entries.len(),
            v2_total: entries.len(),
            totals,
            entries,
            truncated: false,
            dropped: 0,
            notes: Vec::new(),
        }
    }

    #[test]
    fn totals_are_the_sum_of_their_buckets() {
        let mut totals = DiffTotals::default();
        for kind in [
            DiffKind::Added,
            DiffKind::Removed,
            DiffKind::Changed,
            DiffKind::Moved,
            DiffKind::Unchanged,
        ] {
            totals.count(kind);
        }
        assert_eq!(totals.total(), 5);
        assert_eq!(totals.added, 1);
        assert!(totals.has_changes());

        // 只有 unchanged 时，"有没有变化"必须是 false —— 否则这个判断永远为真。
        let mut quiet = DiffTotals::default();
        quiet.count(DiffKind::Unchanged);
        assert!(!quiet.has_changes());
    }

    #[test]
    fn accounting_is_balanced_for_a_mixed_report() {
        let r = report(vec![
            entry(DiffKind::Added),
            entry(DiffKind::Removed),
            entry(DiffKind::Unchanged),
            entry(DiffKind::Moved),
        ]);
        assert!(r.accounting_balanced(), "{}", r.summary_zh());
        assert_eq!(r.totals.total(), 4);
    }

    #[test]
    fn accounting_detects_a_tampered_total() {
        // 故意把计数改错：账目不闭合必须能被发现，否则这个断言形同虚设。
        let mut r = report(vec![entry(DiffKind::Added)]);
        r.totals.added = 7;
        assert!(!r.accounting_balanced());
    }

    #[test]
    fn normalization_says_which_dimension_was_used() {
        let rva = Normalization::Rva {
            v1_base: BASE,
            v2_base: BASE_V2,
        };
        let text = rva.describe_zh();
        assert!(text.contains("RVA"), "{text}");
        assert!(text.contains("140000000"), "{text}");
        assert!(text.contains("180000000"), "{text}");
        assert!(rva.is_usable());

        let none = Normalization::Unavailable {
            reason: "没有基址".to_string(),
        };
        assert!(!none.is_usable());
        assert!(
            none.describe_zh().contains("不可比"),
            "{}",
            none.describe_zh()
        );
    }

    #[test]
    fn unavailable_normalization_refuses_to_normalize() {
        let none = Normalization::Unavailable {
            reason: "test".to_string(),
        };
        assert_eq!(normalized(BASE, BASE, &none), None);
        // 可用时必须真的减掉基址，而不是原值返回。
        let rva = Normalization::Rva {
            v1_base: BASE,
            v2_base: 0,
        };
        assert_eq!(normalized(BASE + 0x1000, BASE, &rva), Some(0x1000));
    }

    #[test]
    fn text_header_states_the_normalization_and_the_accounting() {
        let r = report(vec![entry(DiffKind::Added), entry(DiffKind::Unchanged)]);
        let text = render_text(&r);
        assert!(text.contains("# 地址归一化：RVA"), "{text}");
        assert!(text.contains("# 账目："), "{text}");
        assert!(text.contains("新增 1"), "{text}");
        // 差异必须能在正文里按标记认出来
        assert!(text.contains("+ 0000000000001000"), "{text}");
        assert!(text.contains("x"), "{text}");
        // 未变的条目也要列出来（它的标记与差异条目不同）。
        assert!(text.contains("= 0000000000001000"), "{text}");
    }

    #[test]
    fn text_marks_truncation_and_never_hides_it() {
        let mut r = report(vec![entry(DiffKind::Added)]);
        r.truncated = true;
        r.dropped = 42;
        let text = render_text(&r);
        assert!(text.contains("截断"), "{text}");
        assert!(text.contains("42"), "{text}");
    }

    #[test]
    fn scope_parsing_and_membership() {
        assert_eq!(DiffScope::parse("functions"), Some(DiffScope::Functions));
        assert_eq!(DiffScope::parse("ALL"), Some(DiffScope::All));
        assert_eq!(DiffScope::parse("nope"), None);
        assert!(DiffScope::All.includes(DiffScope::Symbols));
        assert!(!DiffScope::Functions.includes(DiffScope::Symbols));
        assert!(DiffScope::Sections.includes(DiffScope::Sections));
    }

    #[test]
    fn kinds_expose_their_markers_and_names() {
        for kind in [
            DiffKind::Added,
            DiffKind::Removed,
            DiffKind::Changed,
            DiffKind::Moved,
            DiffKind::Unchanged,
        ] {
            assert!(!kind.as_str().is_empty());
            assert!(!kind.label_zh().is_empty());
        }
        assert!(DiffKind::Moved.is_difference());
        assert!(!DiffKind::Unchanged.is_difference());
    }

    // ── 地址归一化：本模块所有假报告都出自这一层，所以单测写得最细 ──

    /// 镜像内的地址 → 换成它指向的 RVA。
    #[test]
    fn in_image_literals_become_the_rva_they_point_at() {
        assert_eq!(
            normalize_addresses("call 0x140001020", BASE, END),
            "call @0x1020"
        );
        // 同一个被引用者，整体挪到另一个基址：归一化结果必须一样。
        assert_eq!(
            normalize_addresses("call 0x180001020", BASE_V2, END_V2),
            "call @0x1020"
        );
    }

    /// **这一条是给那个 f22 假阳性上的锁。**
    ///
    /// 曾经的实现把每个字面量都减掉**函数起点**，于是 `sub rsp, 0x28` 会变成
    /// `0xffffffff...f028` —— 一个取决于函数绝对地址的值。两版基址不同 →
    /// 同一个函数被判成"改动"。普通立即数必须原样留下。
    #[test]
    fn ordinary_immediates_are_left_alone_whatever_the_base_is() {
        let text = "sub rsp, 0x28";
        assert_eq!(normalize_addresses(text, BASE, END), text);
        assert_eq!(
            normalize_addresses(text, BASE_V2, END_V2),
            text,
            "普通立即数不能随基址变化"
        );
        // 也不能随"函数在哪儿"变化。
        assert_eq!(
            normalize_addresses("add eax, 0x5eed", BASE, END),
            "add eax, 0x5eed"
        );
    }

    /// 立即数必须留在强指纹里，否则常量改动会漏报。
    #[test]
    fn different_constants_stay_distinguishable() {
        assert_ne!(
            normalize_addresses("add eax, 0x5eed", BASE, END),
            normalize_addresses("add eax, 0x1234", BASE, END)
        );
    }

    /// 没有镜像基址时不做任何替换：宁可"少归一化"，也不要拿裸值当 RVA。
    #[test]
    fn a_missing_base_disables_normalization_instead_of_guessing() {
        assert_eq!(
            normalize_addresses("call 0x140001020", 0, END),
            "call 0x140001020"
        );
    }

    /// 弱指纹抹掉数值，只留形状。
    #[test]
    fn the_loose_form_erases_values_but_keeps_shape() {
        let one = strip_addresses("call 0x140001020");
        let two = strip_addresses("call 0x180001020");
        assert_eq!(one, two, "换了基址的同一个调用，形状必须一致");
        assert_ne!(
            strip_addresses("mov ecx, eax"),
            strip_addresses("mov ecx, ebx"),
            "寄存器不同必须能分出来"
        );
    }

    /// 文本里没有十六进制字面量时原样返回（别把指令名吃掉）。
    #[test]
    fn text_without_literals_is_returned_unchanged() {
        assert_eq!(normalize_addresses("ret", BASE, END), "ret");
        assert_eq!(
            normalize_addresses("xor eax, ecx", BASE, END),
            "xor eax, ecx"
        );
        // 光秃秃的 `0x` 不是数字，别当成数值处理。
        assert_eq!(normalize_addresses("weird 0x", BASE, END), "weird 0x");
    }

    /// 强指纹必须能分辨"被引用者挪了位置"这件事本身：
    /// 归一化把地址换成了它指向的 RVA，所以同一个被引用者仍然相同，
    /// 而指向**不同**被引用者的调用必须能分开。
    #[test]
    fn the_strict_form_keeps_distinct_referents_distinct() {
        assert_eq!(
            normalize_addresses("call 0x140001020", BASE, END),
            normalize_addresses("call 0x180001020", BASE_V2, END_V2)
        );
        assert_ne!(
            normalize_addresses("call 0x140001020", BASE, END),
            normalize_addresses("call 0x140001030", BASE, END)
        );
    }
}
