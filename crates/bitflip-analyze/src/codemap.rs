//! 数据 / 代码判定（M6）。
//!
//! # 为什么需要单独一个判定层
//!
//! "这段字节是代码还是数据"是后续一切分析的前提。函数边界、CFG、
//! 交叉引用都建立在它之上 —— 判错的代价是**在下游放大**的：
//!
//! * 把数据判成代码 → 造出不存在的函数，用户点进去看到乱码；
//! * 把代码判成数据 → 跳转目标凭空消失，CFG 上出现断掉的边。
//!
//! 两种错误都**不会报错**，只会让结论看起来"少了点东西"或者
//! "多了点东西"。所以这里的原则是：
//!
//! 1. **每个结论都带证据**，而不是布尔值。见 [`CodeEvidence`]。
//! 2. **不确定就说不确定**：`Unknown` 是一等公民，不是"默认当代码"。
//! 3. **判定依据必须可复现**，以便量化误判率（M6 验收标准 2）。
//!
//! # 判定的证据来源
//!
//! 按可信度从高到低：
//!
//! | 证据 | 说明 | 可信度 |
//! |---|---|---|
//! | 展开表边界 | `.pdata`/FDE，编译器写死的函数范围 | 最高 |
//! | 符号表类型 | ELF `STT_FUNC` / `STT_OBJECT` | 高 |
//! | 节权限 | `.text` vs `.data` | 高（但 PE 常把只读数据放 `.text`） |
//! | 控制流可达 | 从入口/导出递归下降走到过 | 高 |
//! | 解码一致性 | 从该地址起能连续解出合理指令 | 中 |
//! | 启发式 | 常见函数序言/尾声 | 低 |
//!
//! # 为什么不信"能解码"这一条
//!
//! 从任意字节开始解码几乎总能解出**某些**指令（x86 是变长编码，
//! 任何字节序列都是合法指令的可能性很高）。单靠它会让约 90% 的
//! 随机数据被误判成代码。所以它只作为**辅助**证据，且必须与
//! "控制流可达"或"节权限"联合使用才足以定论。

/// 一段字节的判定结论。
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum RegionKind {
    /// 确认为代码。
    Code,
    /// 确认为数据。
    Data,
    /// 判定不了。
    ///
    /// 这是一等公民：**不要**把"不知道"归到 `Code` 或 `Data` 里。
    /// 归进去会让下游以为有了结论，而那个结论是编的。
    Unknown,
}

impl RegionKind {
    /// 稳定短名（wire 用）。
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Code => "code",
            Self::Data => "data",
            Self::Unknown => "unknown",
        }
    }

    /// 中文标签（UI 用）。
    #[must_use]
    pub const fn label_zh(self) -> &'static str {
        match self {
            Self::Code => "代码",
            Self::Data => "数据",
            Self::Unknown => "未判定",
        }
    }
}

/// 一条判定证据。
///
/// 记的是"凭什么这么判"，而不是"判成了什么"。UI 要能回答用户
/// "你凭什么说这里是数据" —— 只给结论的话，用户无法判断该不该信。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CodeEvidence {
    /// 证据种类。
    pub kind: EvidenceKind,
    /// 这条证据支持哪一边。
    pub supports: RegionKind,
    /// 证据强度（0–100）。0 表示"只是没有反证"，不等于支持。
    pub weight: u8,
    /// 人类可读的说明（中文）。
    pub detail: String,
}

/// 证据种类。
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum EvidenceKind {
    /// 展开表给出的函数边界（编译器写死，最强）。
    UnwindBoundary,
    /// 符号表类型（`STT_FUNC` / `STT_OBJECT`）。
    SymbolType,
    /// 所在节的权限（可执行 / 不可执行）。
    SectionPerm,
    /// 递归下降可达（从入口或导出出发走到过）。
    ControlFlowReachable,
    /// 从该地址起能连续解出合理指令。
    Decodes,
    /// 该地址位于某个已知函数的范围内。
    InsideKnownFunction,
    /// 该地址是某个已知跳转/调用的目标。
    IsBranchTarget,
}

impl EvidenceKind {
    /// 稳定短名（wire 用）。
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::UnwindBoundary => "unwind",
            Self::SymbolType => "symbol",
            Self::SectionPerm => "section",
            Self::ControlFlowReachable => "reachable",
            Self::Decodes => "decodes",
            Self::InsideKnownFunction => "in-function",
            Self::IsBranchTarget => "branch-target",
        }
    }
}

/// 一个地址上的完整判定。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CodeJudgement {
    /// 被判定的地址。
    pub addr: u64,
    /// 结论。
    pub kind: RegionKind,
    /// 综合置信度（0–100）。
    pub confidence: u8,
    /// 支持结论的全部证据（含反向证据）。
    pub evidence: Vec<CodeEvidence>,
}

impl CodeJudgement {
    /// 是否有任何**高可信**证据支持这个结论。
    ///
    /// "高可信"是**分方向**判定的 —— 支持代码与支持数据的强证据不是
    /// 同一批：
    ///
    /// * **代码**：展开表边界、符号类型、控制流可达、在已知函数内。
    ///   "能解码"不算 —— 随机字节也能解码。
    /// * **数据**：节权限**明确**说不可执行。这是声明性的事实，和
    ///   "从字节内容猜出来"完全不同。仅凭"解不出指令"不算 ——
    ///   地址未映射时也是解不出来，那说明不了是数据。
    ///
    /// 只给结论不给方向性判断的话，调用方会以为"有证据"就等于
    /// "结论可靠"，而两者的强度差别很大。
    #[must_use]
    pub fn is_well_supported(&self) -> bool {
        match self.kind {
            RegionKind::Code => self.evidence.iter().any(|e| {
                e.supports == RegionKind::Code
                    && matches!(
                        e.kind,
                        EvidenceKind::UnwindBoundary
                            | EvidenceKind::SymbolType
                            | EvidenceKind::ControlFlowReachable
                            | EvidenceKind::InsideKnownFunction
                    )
            }),
            RegionKind::Data => self.evidence.iter().any(|e| {
                e.supports == RegionKind::Data && matches!(e.kind, EvidenceKind::SectionPerm)
            }),
            // `Unknown` 本来就**不该**有强证据 —— 有的话就该改结论了。
            // 这里返回 false 是在断言"没有"，而不是"没检查"。
            RegionKind::Unknown => false,
        }
    }

    /// 结论的简短理由（给 UI 的一行说明）。
    #[must_use]
    pub fn reason_zh(&self) -> String {
        if self.evidence.is_empty() {
            return "没有任何证据".to_string();
        }
        let mut parts: Vec<String> = self
            .evidence
            .iter()
            .filter(|e| e.supports == self.kind)
            .map(|e| e.detail.clone())
            .collect();
        if parts.is_empty() {
            // 有证据但都不支持这个结论 —— 如实说明，不要编一个理由。
            parts.push(format!("{} 条证据都不支持该结论", self.evidence.len()));
        }
        parts.join("；")
    }
}

/// 判定一个地址需要的外部事实。
///
/// 用 trait 而不是直接传一堆参数：判定逻辑的输入会随证据种类增加而
/// 变化，而测试需要能精确构造"只有某种证据"的场景。
pub trait CodeFacts {
    /// 该地址是否落在可执行节/段里。
    fn in_executable_section(&self, addr: u64) -> Option<bool>;
    /// 该地址是否落在某个展开表给出的函数范围内。
    fn in_unwind_range(&self, addr: u64) -> bool;
    /// 该地址是否是某个已知函数的入口。
    fn is_function_entry(&self, addr: u64) -> bool;
    /// 该地址是否在某个已知函数的范围内。
    fn inside_known_function(&self, addr: u64) -> bool;
    /// 该地址是否被递归下降扫到过（可达）。
    fn is_reachable(&self, addr: u64) -> bool;
    /// 该地址是否是某个已知跳转/调用的目标。
    fn is_branch_target(&self, addr: u64) -> bool;
    /// 从该地址起最多能连续数出多少条**已认定**的指令。
    ///
    /// 返回连续长度，而不是布尔值：`1` 条和 `20` 条的意义完全不同。
    ///
    /// **重要**：这是"被扫描认定为指令起点"的连续数，不是"从这些字节
    /// 能不能解出指令"。两者差别很大且实际存在 —— 数据里完全可以出现
    /// 看起来像指令的字节序列（x86 是变长编码）。调用方若把"能解码"
    /// 当成"是代码"，就会把常量池误判成函数。
    fn decode_run(&self, addr: u64) -> u32;
}

/// 判定一个地址是代码还是数据。
///
/// # 判定规则
///
/// 按证据强度累积，最后看哪一边的加权分高。**关键约束**：
///
/// * 只有"能解码"这一类弱证据时，结论是 `Unknown` 而不是 `Code` ——
///   随机字节也能解码，把它当代码是 M6 要量化的主要误判来源。
/// * 展开表说"这里是函数范围"是压倒性证据，直接定 `Code`。
/// * 不可执行节 + 不在函数的范围里 → `Data`。
#[must_use]
pub fn judge_code(facts: &impl CodeFacts, addr: u64) -> CodeJudgement {
    let mut evidence = Vec::new();
    let mut code_score: i32 = 0;
    let mut data_score: i32 = 0;

    // ── 证据 1：展开表边界（最强）──
    if facts.in_unwind_range(addr) {
        evidence.push(CodeEvidence {
            kind: EvidenceKind::UnwindBoundary,
            supports: RegionKind::Code,
            weight: 100,
            detail: "落在展开表（.pdata/FDE）给出的函数范围内".to_string(),
        });
        code_score += 100;
    }

    // ── 证据 2：节权限 ──
    //
    // 只作为**辅助**：PE 常把只读数据（跳转表、字符串）放在 `.text` 里，
    // 所以"在可执行节里"**不**足以断定是代码。
    match facts.in_executable_section(addr) {
        Some(true) => {
            evidence.push(CodeEvidence {
                kind: EvidenceKind::SectionPerm,
                supports: RegionKind::Code,
                weight: 30,
                detail: "位于可执行节".to_string(),
            });
            code_score += 30;
        }
        Some(false) => {
            evidence.push(CodeEvidence {
                kind: EvidenceKind::SectionPerm,
                supports: RegionKind::Data,
                weight: 60,
                detail: "不在可执行节（数据节里的字节不是指令）".to_string(),
            });
            data_score += 60;
        }
        None => {
            // 拿不到权限信息：不编造，也不加分。
            evidence.push(CodeEvidence {
                kind: EvidenceKind::SectionPerm,
                supports: RegionKind::Unknown,
                weight: 0,
                detail: "拿不到节权限信息，此项不参与判定".to_string(),
            });
        }
    }

    // ── 证据 3：控制流可达（强）──
    if facts.is_reachable(addr) {
        evidence.push(CodeEvidence {
            kind: EvidenceKind::ControlFlowReachable,
            supports: RegionKind::Code,
            weight: 80,
            detail: "从入口或导出出发的递归下降走到过这里".to_string(),
        });
        code_score += 80;
    }

    // ── 证据 4：在已知函数范围内 ──
    if facts.inside_known_function(addr) {
        evidence.push(CodeEvidence {
            kind: EvidenceKind::InsideKnownFunction,
            supports: RegionKind::Code,
            weight: 70,
            detail: "落在某个已知函数的地址范围内".to_string(),
        });
        code_score += 70;
    } else if facts.is_function_entry(addr) {
        evidence.push(CodeEvidence {
            kind: EvidenceKind::InsideKnownFunction,
            supports: RegionKind::Code,
            weight: 90,
            detail: "是某个已知函数的入口".to_string(),
        });
        code_score += 90;
    }

    // ── 证据 5：是跳转/调用目标 ──
    if facts.is_branch_target(addr) {
        evidence.push(CodeEvidence {
            kind: EvidenceKind::IsBranchTarget,
            supports: RegionKind::Code,
            weight: 65,
            detail: "是某个已知跳转或调用的目标".to_string(),
        });
        code_score += 65;
    }

    // ── 证据 6：解码连续性（弱，且要够长才算数）──
    let run = facts.decode_run(addr);
    if run >= MIN_DECODE_RUN {
        // 连续 N 条全部解码成功，随机数据的概率极低。
        let w = (20 + run.min(20)) as u8;
        evidence.push(CodeEvidence {
            kind: EvidenceKind::Decodes,
            supports: RegionKind::Code,
            weight: w,
            detail: format!("从该地址起连续解出 {run} 条指令"),
        });
        code_score += i32::from(w);
    } else if run > 0 {
        // 只解出一两条：**不足以**支持"这是代码"，如实记录但不加分。
        evidence.push(CodeEvidence {
            kind: EvidenceKind::Decodes,
            supports: RegionKind::Unknown,
            weight: 0,
            detail: format!(
                "只连续解出 {run} 条指令（不足 {MIN_DECODE_RUN} 条，随机字节也能做到，不作为代码证据）"
            ),
        });
    } else {
        // 没有任何**已索引**的指令从这里开始。
        //
        // 注意这与"从这些字节解不出指令"**不是一回事**：数据里完全可能
        // 出现看起来像指令的字节序列（本项目的 fixture 就刻意构造了
        // 这种数据）。说"解不出指令"会误导用户以为这里是随机的垃圾字节。
        evidence.push(CodeEvidence {
            kind: EvidenceKind::Decodes,
            supports: RegionKind::Data,
            weight: 50,
            detail: "该地址没有被扫描认定为指令起点".to_string(),
        });
        data_score += 50;
    }

    // ── 汇总裁决 ──
    //
    // `Unknown` 的判据：两边都没有**强**证据。特别地，只有弱证据
    // （节权限 + 能解码）时不给 `Code` —— 这正是误判的主要来源。
    let has_strong_code = facts.in_unwind_range(addr)
        || facts.is_reachable(addr)
        || facts.inside_known_function(addr)
        || facts.is_function_entry(addr);

    // 判 `Data` 需要一个**独立于"解码失败"**的依据。
    //
    // 只凭"解不出指令"就断言是数据，会把两种完全不同的情况混为一谈：
    // ①"这里确实是数据"；②"这里根本没读到字节"。段权限未知时读不到
    // 字节（地址未映射、文件被截断）就会落到 ②，此时说"这是数据"
    // 是编造结论。
    //
    // 所以要求两者之一：节权限**明确**说不可执行，或者解码能力
    // **明确**被判过（`Some(true)` 说明读到了字节但解不出来）。
    let decode_evidence_is_real = match facts.in_executable_section(addr) {
        Some(false) => true,    // 明确在数据节
        Some(true) => run == 0, // 明确在可执行节却解不出来 → 真是数据
        None => false,          // 拿不到权限，解码失败说明不了任何事
    };
    let data_is_supported = data_score > 0 && decode_evidence_is_real;

    let (kind, confidence) = if has_strong_code {
        (RegionKind::Code, clamp_score(code_score))
    } else if data_score > code_score && data_is_supported {
        (RegionKind::Data, clamp_score(data_score))
    } else if code_score >= STRONG_ENOUGH {
        // 没有强证据，但弱证据累积到了相当程度。仍然**不叫代码** ——
        // 只给 Unknown，把"我猜它可能是代码"这件事如实说出来。
        (RegionKind::Unknown, clamp_score(code_score))
    } else {
        // 其余情况一律 `Unknown`：既没有强代码证据，也没有可信的
        // 数据证据。**不把不确定性倒向任何一边** —— 那等于替用户
        // 做了他没授权我们做的判断。
        (RegionKind::Unknown, 0)
    };

    CodeJudgement {
        addr,
        kind,
        confidence,
        evidence,
    }
}

/// 连续解码多少条才足以作为"代码"的弱证据。
///
/// 取 4：单条指令解码成功在随机数据上很常见（x86 是变长编码），
/// 连续 4 条全部成功的概率已经很低，但仍不足以单独定论 ——
/// 它只是把一个地址从"完全没证据"抬到"有点像代码"。
pub const MIN_DECODE_RUN: u32 = 4;

/// 只有弱证据时，需要累积到多少分才给 `Unknown`（而非直接 0 分）。
const STRONG_ENOUGH: i32 = 50;

/// 把分数压到 0–100。
fn clamp_score(score: i32) -> u8 {
    u8::try_from(score.clamp(0, 100)).unwrap_or(100)
}

/// 分类统计：量化误判率用。
///
/// 这不是"好看的数字"，而是 M6 验收标准 2 要求的**门禁输入**：
/// 误判率超过阈值时测试必须失败。
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct JudgementStats {
    /// 判为代码的地址数。
    pub code: usize,
    /// 判为数据的地址数。
    pub data: usize,
    /// 未判定的地址数。
    pub unknown: usize,
}

impl JudgementStats {
    /// 从一批判定汇总。
    #[must_use]
    pub fn from_judgements(judgements: &[CodeJudgement]) -> Self {
        let mut s = Self::default();
        for j in judgements {
            match j.kind {
                RegionKind::Code => s.code += 1,
                RegionKind::Data => s.data += 1,
                RegionKind::Unknown => s.unknown += 1,
            }
        }
        s
    }

    /// 总数。
    #[must_use]
    pub const fn total(&self) -> usize {
        self.code + self.data + self.unknown
    }

    /// 给出了明确结论的比例（0.0–1.0）。
    ///
    /// 这个数字**低不是坏事**：`Unknown` 多说明系统在不确定时没有
    /// 硬凑结论。真正要盯的是下面的误判率。
    #[must_use]
    pub fn decided_ratio(&self) -> f64 {
        let total = self.total();
        if total == 0 {
            return 0.0;
        }
        (self.code + self.data) as f64 / total as f64
    }
}

/// 与黄金标准比对后的误判统计。
///
/// 用于 M6 验收标准 2 的**量化门禁**。
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct ErrorRate {
    /// 黄金标准里是代码、却被判成数据的数量（漏报）
    pub false_negative: usize,
    /// 黄金标准里是数据、却被判成代码的数量（误报）
    pub false_positive: usize,
    /// 判对了的数量。
    pub correct: usize,
    /// 未判定而未计入对错的数量。
    pub unknown: usize,
}

impl ErrorRate {
    /// 参与比较的总数（不含 unknown）。
    #[must_use]
    pub const fn decided(&self) -> usize {
        self.correct + self.false_negative + self.false_positive
    }

    /// 误判率：判错的占**已判定**的比例。
    ///
    /// 分母用"已判定"而不是"总数"：`Unknown` 不是错误，把它算进分母
    /// 会让"多说话"看起来比"少说话"更安全 —— 而事实相反，
    /// 一个编造的结论比没有结论有害得多。
    #[must_use]
    pub fn rate(&self) -> f64 {
        let d = self.decided();
        if d == 0 {
            return 0.0;
        }
        (self.false_negative + self.false_positive) as f64 / d as f64
    }

    /// 漏报率：真代码里被判错的。
    ///
    /// 单独算是因为**两种错的危害不对称**：把代码判成数据会让
    /// 分析凭空少一块；把数据判成代码会造出不存在的函数。
    #[must_use]
    pub fn false_negative_rate(&self) -> f64 {
        let truth = self.correct + self.false_negative;
        if truth == 0 {
            return 0.0;
        }
        self.false_negative as f64 / truth as f64
    }

    /// 误报率：真数据里被判错的。
    #[must_use]
    pub fn false_positive_rate(&self) -> f64 {
        let truth = self.correct + self.false_positive;
        if truth == 0 {
            return 0.0;
        }
        self.false_positive as f64 / truth as f64
    }
}

/// 把判定结果与黄金标准比对。
///
/// `truth` 是"地址 → 真正是代码吗"。只有出现在 `truth` 里的地址参与
/// 统计 —— 黄金标准没覆盖的地址不拿来算分（否则"没标注"会被当错）。
#[must_use]
pub fn compare_with_truth(judgements: &[CodeJudgement], truth: &[(u64, bool)]) -> ErrorRate {
    let truth_map: std::collections::HashMap<u64, bool> = truth.iter().copied().collect();
    let mut rate = ErrorRate::default();

    for j in judgements {
        let Some(&is_code) = truth_map.get(&j.addr) else {
            continue;
        };
        match j.kind {
            RegionKind::Unknown => rate.unknown += 1,
            RegionKind::Code => {
                if is_code {
                    rate.correct += 1;
                } else {
                    rate.false_positive += 1;
                }
            }
            RegionKind::Data => {
                if is_code {
                    rate.false_negative += 1;
                } else {
                    rate.correct += 1;
                }
            }
        }
    }
    rate
}

/// 判定所需事实的**实际**数据源：地址空间 + 已有分析结果。
///
/// 存在的理由：判定逻辑本身要能脱离文件格式测试（见上面的 `Facts`），
/// 而真实调用需要一个把"节权限/函数范围/可达性"接起来的实现。
/// 把这个实现单独放，判定规则的变化就不会牵动数据来源的代码。
pub struct AnalysisFacts<'a> {
    /// 地址空间（判节权限用）。
    pub space: &'a crate::addrspace::AddrSpace,
    /// 已知函数的 `(入口, 上界)`；上界为 `None` 表示只知道入口。
    pub functions: &'a [(u64, Option<u64>)],
    /// 递归下降可达的地址。
    pub reachable: &'a std::collections::HashSet<u64>,
    /// 跳转/调用的目标地址。
    pub branch_targets: &'a std::collections::HashSet<u64>,
    /// 从某地址起连续解码的函数（由上层注入解码器）。
    pub decode_run: &'a dyn Fn(u64) -> u32,
}

impl CodeFacts for AnalysisFacts<'_> {
    fn in_executable_section(&self, addr: u64) -> Option<bool> {
        // 用**段**回答，取不到就说取不到（返回 None 而不是 false）。
        //
        // 不能默认 `false`：那会把"没找到这个地址"变成"它在数据节里"，
        // 于是未映射的地址被判成数据 —— 一个编造的结论。
        let seg = self.space.segment_at(addr)?;
        Some(seg.perms.execute)
    }

    fn in_unwind_range(&self, addr: u64) -> bool {
        // 展开表来源的函数**带边界**，落在 [start, end) 内即强证据。
        self.functions
            .iter()
            .any(|&(start, end)| end.is_some_and(|e| addr >= start && addr < e))
    }

    fn is_function_entry(&self, addr: u64) -> bool {
        self.functions.iter().any(|&(start, _)| start == addr)
    }

    fn inside_known_function(&self, addr: u64) -> bool {
        self.functions
            .iter()
            .any(|&(start, end)| end.is_some_and(|e| addr >= start && addr < e))
    }

    fn is_reachable(&self, addr: u64) -> bool {
        self.reachable.contains(&addr)
    }

    fn is_branch_target(&self, addr: u64) -> bool {
        self.branch_targets.contains(&addr)
    }

    fn decode_run(&self, addr: u64) -> u32 {
        (self.decode_run)(addr)
    }
}

/// 对一个地址集合批量判定。
///
/// 保持输入顺序、不排序：调用方（测试与 UI）通常按地址升序遍历，
/// 重排会让"哪一行对应哪个地址"变得难以核对。
#[must_use]
pub fn judge_code_many(facts: &impl CodeFacts, addrs: &[u64]) -> Vec<CodeJudgement> {
    addrs.iter().map(|&a| judge_code(facts, a)).collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    /// 测试用的可控事实源。
    #[derive(Default)]
    struct Facts {
        exec: Option<bool>,
        unwind: bool,
        entry: bool,
        inside_fn: bool,
        reachable: bool,
        branch_target: bool,
        decode_run: u32,
    }

    impl CodeFacts for Facts {
        fn in_executable_section(&self, _addr: u64) -> Option<bool> {
            self.exec
        }
        fn in_unwind_range(&self, _addr: u64) -> bool {
            self.unwind
        }
        fn is_function_entry(&self, _addr: u64) -> bool {
            self.entry
        }
        fn inside_known_function(&self, _addr: u64) -> bool {
            self.inside_fn
        }
        fn is_reachable(&self, _addr: u64) -> bool {
            self.reachable
        }
        fn is_branch_target(&self, _addr: u64) -> bool {
            self.branch_target
        }
        fn decode_run(&self, _addr: u64) -> u32 {
            self.decode_run
        }
    }

    #[test]
    fn unwind_range_is_decisive_evidence_for_code() {
        let f = Facts {
            unwind: true,
            ..Default::default()
        };
        let j = judge_code(&f, 0x1000);
        assert_eq!(j.kind, RegionKind::Code);
        assert!(j.is_well_supported(), "展开表是强证据");
        assert!(j.reason_zh().contains("展开表"));
    }

    /// **这条是 M6 误判率的守门人**：随机数据也能解码，所以
    /// "能解码"单独**不能**作为代码结论。
    #[test]
    fn decodable_bytes_alone_are_not_enough_to_call_it_code() {
        let f = Facts {
            exec: Some(true),
            decode_run: 100, // 解得出很多条
            ..Default::default()
        };
        let j = judge_code(&f, 0x2000);
        assert_eq!(
            j.kind,
            RegionKind::Unknown,
            "只有节权限与解码能力时不能断言是代码 —— 这正是误判的主要来源"
        );
        assert!(!j.is_well_supported(), "没有强证据的结论不能被当成确定事实");
    }

    #[test]
    fn non_executable_section_without_function_range_is_data() {
        let f = Facts {
            exec: Some(false),
            decode_run: 0,
            ..Default::default()
        };
        let j = judge_code(&f, 0x3000);
        assert_eq!(j.kind, RegionKind::Data);
        assert!(
            j.is_well_supported(),
            "节权限明确说不可执行，这是声明性事实，足以支撑数据结论"
        );
    }

    /// 两种结论的"强证据"是**不同**的一批 —— 这条守住这个不对称。
    ///
    /// 判 `Code` 需要展开表/可达性这类观察；判 `Data` 需要节权限这类
    /// 声明。把两者混为一谈会让某一侧出现"看着有证据其实没有"。
    #[test]
    fn strong_evidence_differs_by_direction() {
        // 只有节权限（可执行）+ 解码能力 → 不足以判代码
        let code_ish = Facts {
            exec: Some(true),
            decode_run: 50,
            ..Default::default()
        };
        let j = judge_code(&code_ish, 0x1000);
        assert_eq!(j.kind, RegionKind::Unknown);
        assert!(!j.is_well_supported());

        // 只有节权限（不可执行）→ 足以判数据
        let data_ish = Facts {
            exec: Some(false),
            ..Default::default()
        };
        let j = judge_code(&data_ish, 0x2000);
        assert_eq!(j.kind, RegionKind::Data);
        assert!(j.is_well_supported());

        // `Unknown` 永远不该被当成"有强证据支撑"
        let unknown = Facts::default();
        let j = judge_code(&unknown, 0x3000);
        assert_eq!(j.kind, RegionKind::Unknown);
        assert!(!j.is_well_supported());
    }

    /// 数据节里的字节即使"恰好能解码"也不该翻案：
    /// 节权限 + 不在任何函数范围 = 数据。
    #[test]
    fn data_section_wins_over_incidental_decodability() {
        let f = Facts {
            exec: Some(false),
            decode_run: 7, // 碰巧能解出几条
            ..Default::default()
        };
        let j = judge_code(&f, 0x3100);
        assert_eq!(
            j.kind,
            RegionKind::Data,
            "数据节里的字节不应因为'能解码'就变成代码"
        );
    }

    #[test]
    fn reachable_address_is_code_even_in_a_non_exec_section() {
        // 罕见但真实：某些打包器把代码放进可写节再执行。
        // 控制流可达是**观察到的事实**，强于节权限这个"声明"。
        let f = Facts {
            exec: Some(false),
            reachable: true,
            ..Default::default()
        };
        let j = judge_code(&f, 0x4000);
        assert_eq!(j.kind, RegionKind::Code);
        assert!(j.reason_zh().contains("递归下降"));
    }

    #[test]
    fn missing_section_permission_does_not_invent_a_conclusion() {
        let f = Facts::default(); // exec = None，什么都不知道
        let j = judge_code(&f, 0x5000);
        assert_eq!(j.kind, RegionKind::Unknown);
        // 必须如实说"拿不到"，而不是编一个默认值。
        assert!(
            j.evidence.iter().any(|e| e.detail.contains("拿不到节权限")),
            "拿不到信息时要在证据里说明，不能静默略过"
        );
    }

    #[test]
    fn short_decode_run_is_recorded_but_not_counted_as_code_evidence() {
        let f = Facts {
            exec: Some(true),
            decode_run: 2, // 少于 MIN_DECODE_RUN
            ..Default::default()
        };
        let j = judge_code(&f, 0x6000);
        assert_eq!(j.kind, RegionKind::Unknown);
        let d = j
            .evidence
            .iter()
            .find(|e| e.kind == EvidenceKind::Decodes)
            .expect("应当记录解码情况");
        assert_eq!(
            d.supports,
            RegionKind::Unknown,
            "短解码串不支持任何一边，必须如实标注"
        );
        assert!(d.detail.contains("随机字节也能做到"));
    }

    #[test]
    fn region_kind_short_names_and_labels_are_stable() {
        assert_eq!(RegionKind::Code.as_str(), "code");
        assert_eq!(RegionKind::Data.as_str(), "data");
        assert_eq!(RegionKind::Unknown.as_str(), "unknown");
        assert_eq!(RegionKind::Unknown.label_zh(), "未判定");
        // 短名必须互不相同（wire 靠它区分）
        let names: std::collections::BTreeSet<&str> =
            [RegionKind::Code, RegionKind::Data, RegionKind::Unknown]
                .iter()
                .map(|k| k.as_str())
                .collect();
        assert_eq!(names.len(), 3);
    }

    #[test]
    fn error_rate_ignores_unknown_in_the_denominator() {
        let judgements = vec![
            CodeJudgement {
                addr: 1,
                kind: RegionKind::Code,
                confidence: 90,
                evidence: vec![],
            },
            CodeJudgement {
                addr: 2,
                kind: RegionKind::Unknown,
                confidence: 0,
                evidence: vec![],
            },
        ];
        let truth = vec![(1u64, true), (2u64, true)];
        let r = compare_with_truth(&judgements, &truth);
        assert_eq!(r.correct, 1);
        assert_eq!(r.unknown, 1);
        assert_eq!(r.decided(), 1);
        assert_eq!(
            r.rate(),
            0.0,
            "没结论不算错 —— 分母只算已判定，否则'少说话'会被惩罚"
        );
    }

    #[test]
    fn error_rate_separates_false_positives_from_false_negatives() {
        let judgements = vec![
            // 真数据判成代码 → 误报
            CodeJudgement {
                addr: 1,
                kind: RegionKind::Code,
                confidence: 90,
                evidence: vec![],
            },
            // 真代码判成数据 → 漏报
            CodeJudgement {
                addr: 2,
                kind: RegionKind::Data,
                confidence: 60,
                evidence: vec![],
            },
        ];
        let truth = vec![(1u64, false), (2u64, true)];
        let r = compare_with_truth(&judgements, &truth);
        assert_eq!(r.false_positive, 1);
        assert_eq!(r.false_negative, 1);
        assert_eq!(r.correct, 0);
        assert_eq!(r.rate(), 1.0);
        // 两种错的危害不对称，所以要能分开看
        assert_eq!(r.false_positive_rate(), 1.0);
        assert_eq!(r.false_negative_rate(), 1.0);
    }

    #[test]
    fn truth_entries_not_judged_are_not_counted() {
        // 黄金标准覆盖了 3 个地址，但只判定了 1 个。
        // "没判定"不能算错，也不能算对。
        let judgements = vec![CodeJudgement {
            addr: 1,
            kind: RegionKind::Code,
            confidence: 90,
            evidence: vec![],
        }];
        let truth = vec![(1u64, true), (2u64, true), (3u64, false)];
        let r = compare_with_truth(&judgements, &truth);
        assert_eq!(r.correct, 1);
        assert_eq!(r.decided(), 1);
        assert_eq!(r.unknown, 0, "未判定的地址根本不在 judgements 里");
    }

    #[test]
    fn judgement_stats_reports_decided_ratio_honestly() {
        let js = vec![
            CodeJudgement {
                addr: 1,
                kind: RegionKind::Code,
                confidence: 90,
                evidence: vec![],
            },
            CodeJudgement {
                addr: 2,
                kind: RegionKind::Data,
                confidence: 60,
                evidence: vec![],
            },
            CodeJudgement {
                addr: 3,
                kind: RegionKind::Unknown,
                confidence: 0,
                evidence: vec![],
            },
            CodeJudgement {
                addr: 4,
                kind: RegionKind::Unknown,
                confidence: 0,
                evidence: vec![],
            },
        ];
        let s = JudgementStats::from_judgements(&js);
        assert_eq!(s.total(), 4);
        assert_eq!(s.code, 1);
        assert_eq!(s.data, 1);
        assert_eq!(s.unknown, 2);
        assert!((s.decided_ratio() - 0.5).abs() < 1e-9);
    }
}
