//! 函数识别：多来源候选 + 置信度 + 冲突消解。
//!
//! 一个地址"是不是函数、从哪到哪"可能同时有多个来源给出答案：
//! 符号表说是、`.pdata`/`.eh_frame` 展开表说是、调用目标说是、prologue 模式说是。
//! 这些来源的可信度不同，冲突时的取舍必须**可解释** —— UI 要能回答
//! "为什么这里被当成函数"（PLAN §M3 交付物）。
//!
//! 优先级沿用 `bitflip-symbols::SymbolSource`（符号 > 展开 > 调用目标 > prologue）。
//! 冲突不静默吞掉：边界不一致的候选全部保留，合并结果附 `notes`。
//!
//! # 边界可能不是"读出来的"
//!
//! 有一种来源只给起点不给终点：Mach-O 的 `LC_FUNCTION_STARTS`。它的结束地址是按
//! "下一个起点"推出来的（见 [`derive_function_starts`]）。这条推导**不许**跟
//! "文件里写着"混为一谈（CLAUDE.md §7），所以：
//!
//! * 它有自己的来源名 [`SymbolSource::FunctionStart`]（"函数起点表"），界面能如实显示；
//! * 推出的结束地址仍然走既有的 `<name>\t<end-hex>` 编码，与展开表/调试信息同一条
//!   通道 —— 不新开一套；
//! * 推不出来时（起点落不进任何节）宁可留 `None`，不拿"到节尾"或"下一个节"凑数。

use bitflip_loader::object::Object;
use bitflip_symbols::{preferred, validate, SymbolCandidate, SymbolSource};

/// 一个函数的最终识别结论。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Function {
    /// 入口地址。
    pub start: u64,
    /// 结束地址（不含）。`None` 表示边界未知 —— 只知道入口。
    /// **不许猜**：猜一个边界然后在上面做 CFG 会把错误固化成"看起来完整"。
    pub end: Option<u64>,
    /// 展示名（已按来源优先级选出；用户命名永远最高）。
    pub name: String,
    /// 名字来源。
    pub name_source: SymbolSource,
    /// 识别置信度（0–100）。
    pub confidence: u8,
    /// 全部候选（含落选的），供 UI 解释"为什么"。
    pub candidates: Vec<SymbolCandidate>,
}

/// 合并冲突的类型。
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ConflictKind {
    /// 两个来源给出的入口一致，但边界不一致。
    BoundaryMismatch {
        /// 各来源给的结束地址。
        ends: Vec<(SymbolSource, u64)>,
    },
    /// 同一地址有多个名字（罕见：符号表重复定义）。
    NameClash {
        /// 冲突的名字列表。
        names: Vec<String>,
    },
}

impl ConflictKind {
    /// 稳定短名（wire 用）。
    #[must_use]
    pub const fn as_str(&self) -> &'static str {
        match self {
            Self::BoundaryMismatch { .. } => "boundary-mismatch",
            Self::NameClash { .. } => "name-clash",
        }
    }
}

/// 合并某入口地址上的全部候选，产出函数结论。
///
/// 规则：
/// 1. 名字按 `preferred()`（来源优先级 → 置信度）选出；
/// 2. 边界取**可信来源给出的最小上界**：展开表（`.pdata`/FDE）的边界是编译器
///    写死的，可信度高于推断；有多个边界时取最小的那个 —— 宁可少要，不要多占
///    （多占会把下一个函数的开头并进来，污染 CFG）；
/// 3. 冲突记录在返回值里，不静默丢弃。
#[must_use]
pub fn merge_candidates(addr: u64, candidates: Vec<SymbolCandidate>) -> Function {
    // 先选出名字。名字必须非空（`validate` 拒空名）：一个空名候选不该
    // 赢下"这个函数叫什么"这个问题。
    //
    // 但**只有边界标记**的名字（`"\t<end>"`）不算名字 —— 那是把结束地址编码进
    // `name` 字段的既有约定（展开表、调试信息、函数起点表都用它）。只做 `validate`
    // 不够：`"\t1010".trim()` 不是空串，于是这种候选会挤掉真正无名的候选、赢下
    // "名字来源"这个位置。实测后果是 Mach-O 的入口点函数显示"来源 = 函数起点表"、
    // PE 上显示"来源 = 展开表"，而它真正的证据是"对象头里写着程序从这里进入"。
    // 所以这里按"剥掉边界标记之后还有没有名字"来判断。
    let named: Vec<SymbolCandidate> = candidates
        .iter()
        .filter(|c| validate(c).is_ok() && has_display_name(&c.name))
        .cloned()
        .collect();
    let chosen = preferred(&named).cloned();

    let (mut name, name_source) = match chosen {
        Some(c) => (c.name, c.source),
        None => {
            // 没有**带名字**的候选，但可能仍有候选 —— 它们只是诚实地
            // 没给出名字（入口点、调用目标推断、导入桩都是这样）。
            //
            // 这里必须保留最可信的那个候选的**来源**，不能一律写成
            // `Discovery`：那会把"因为它是程序入口"和"因为它被调用过"
            // 这两条完全不同的证据链混成一句谎话。
            let best = preferred(&candidates).map(|c| c.source);
            (String::new(), best.unwrap_or(SymbolSource::Discovery))
        }
    };

    // 边界与冲突判定用**全部**候选（含无名的）：入口点候选虽然没名字，
    // 它作为"这里有个函数"的证据一样有效。
    let candidates: Vec<SymbolCandidate> = candidates;

    // 把边界编码在 name 里的候选（约定 `<name>\t<end>`）在名字里带着编码，
    // **标记必须在这里去掉** —— 否则 UI 会把 "\t140001050" 当成函数名显示出来，
    // 那是拿编码细节冒充识别结果（CLAUDE.md §7）。
    //
    // 判断依据是**名字里有没有那个标记**，不是候选来自哪个来源：这条约定最早只有
    // 展开表用（它不提供名字，剥掉标记后名字自然为空，UI 显示"未命名"），
    // 现在调试信息也用（它同时给名字和精确边界）。按来源判断会让调试信息的边界标记
    // 漏在函数名里。
    if let Some((real, _end)) = name.rsplit_once('\t') {
        name = real.to_string();
    }

    // 边界候选：来源带 end 的才参与（调用目标/prologue 只知道入口）
    let mut bounds: Vec<(SymbolSource, u64)> = Vec::new();
    for c in &candidates {
        if c.addr != addr {
            continue;
        }
        // 带边界的候选把 end 编码进 name（约定 `<name>\t<end>`），来源照抄候选自己的：
        // 展开表和调试信息都给精确边界，冲突时用户要能看出来是谁跟谁不一致。
        if let Some((_, end)) = c.name.rsplit_once('\t') {
            if let Ok(end) = u64::from_str_radix(end.trim_start_matches("0x"), 16) {
                bounds.push((c.source, end));
            }
        }
    }

    let mut conflicts = Vec::new();
    let end = if bounds.is_empty() {
        None
    } else {
        let min = bounds.iter().map(|(_, e)| *e).min().expect("非空");
        let mut distinct: Vec<u64> = bounds.iter().map(|(_, e)| *e).collect::<Vec<_>>();
        distinct.sort_unstable();
        distinct.dedup();
        if distinct.len() > 1 {
            conflicts.push(ConflictKind::BoundaryMismatch {
                ends: bounds.clone(),
            });
        }
        Some(min)
    };

    // 置信度：取候选里的最高值；没有候选（空名全被滤掉）时为 0 ——
    // 这时函数其实不该存在，由调用方负责不把它放进结果集。
    let confidence = candidates.iter().map(|c| c.confidence).max().unwrap_or(0);

    Function {
        start: addr,
        end,
        name,
        name_source,
        confidence,
        candidates,
    }
}

/// 这个名字里有没有**真的名字**（不只是 `<name>\t<end>` 里的边界编码）。
///
/// 展开表、调试信息、函数起点表都把结束地址编码在 `name` 后面。剥掉那一段之后
/// 什么都不剩的候选，是"只提供边界、不提供名字"——它不该被当成"这个函数有名字"。
fn has_display_name(name: &str) -> bool {
    let real = name.rsplit_once('\t').map_or(name, |(real, _end)| real);
    !real.trim().is_empty()
}

/// 从展开表条目直接构造函数候选（`.pdata` RUNTIME_FUNCTION / ELF FDE）。
///
/// 展开表的边界是编译器/链接器写死的，置信度高（85）；
/// 名字未知时用空串 —— 由符号层给名字，这里只负责边界。
#[must_use]
pub fn unwind_candidates(entries: &[bitflip_loader::object::UnwindEntry]) -> Vec<SymbolCandidate> {
    entries
        .iter()
        .map(|e| SymbolCandidate {
            addr: e.begin,
            // 约定：`<name>\t<end-hex>`；名字部分为空，由符号来源补。
            // 注意：`merge_candidates` 会在解析出 end 之后把 `\t<end>` 从名字里剥掉，
            // 别让这个编码格式漏到界面上。
            name: format!("\t{:x}", e.end),
            source: SymbolSource::Unwind,
            confidence: 85,
        })
        .collect()
}

/// 由相邻起点推出的一个函数边界。
///
/// # 只有 `start` 是文件里的字节
///
/// `LC_FUNCTION_STARTS` 写的全是**起点**。结束地址是这样定的：第 i 个函数到
/// 第 i+1 个起点为止；最后一个到它所在节的末尾为止；落不进任何节的那个连末尾
/// 都没有 —— 那是 [`DerivedEnd::Unknown`]。把这条推导当成"文件里写着的大小"
/// 就是在说谎（CLAUDE.md §7），所以结束地址必须带着它的来处一起走。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FunctionStartBound {
    /// 起点（文件里写着的）。
    pub start: u64,
    /// 结束地址是怎么来的。
    pub end: DerivedEnd,
}

/// 推导出的结束地址的来源。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DerivedEnd {
    /// 同一张表里的下一个起点 —— 两个数都是文件里的，最硬的一种。
    NextStart(u64),
    /// 表里没有下一个起点了，取所在节的末尾。
    SectionEnd(u64),
    /// 这个起点落不进任何节，表里也没有下一个起点：边界**未知**，不猜。
    Unknown,
}

impl DerivedEnd {
    /// 推出的结束地址（不含）；推不出来时 `None`。
    #[must_use]
    pub const fn value(self) -> Option<u64> {
        match self {
            Self::NextStart(end) | Self::SectionEnd(end) => Some(end),
            Self::Unknown => None,
        }
    }

    /// 结束地址是不是取自相邻起点（而不是节末尾）。
    #[must_use]
    pub const fn is_next_start(self) -> bool {
        matches!(self, Self::NextStart(_))
    }
}

/// 从起点序列推出函数边界。
///
/// `section_end` 回答"这个地址所在节的末尾（不含）在哪"；不在任何节里返回 `None`。
///
/// 起点序列**按输入顺序**处理，不排序也不去重：`Object::function_starts` 的契约
/// 就是升序，这里再排一次会把"表没按规范装出来"这种问题悄悄盖住。序列不升时也
/// 不猜 —— 一个不比自己大的数不能当上界（会长出长度为 0 甚至为负的函数），
/// 那种情况退回节的末尾规则。
#[must_use]
pub fn derive_function_starts(
    starts: &[u64],
    section_end: impl Fn(u64) -> Option<u64>,
) -> Vec<FunctionStartBound> {
    let mut bounds = Vec::with_capacity(starts.len());
    for (index, &start) in starts.iter().enumerate() {
        // 下一个起点必须**严格更大**才配当上界。
        let next = starts.get(index + 1).copied().filter(|&next| next > start);
        let end = match next {
            Some(next) => DerivedEnd::NextStart(next),
            None => match section_end(start).filter(|&end| end > start) {
                Some(end) => DerivedEnd::SectionEnd(end),
                None => DerivedEnd::Unknown,
            },
        };
        bounds.push(FunctionStartBound { start, end });
    }
    bounds
}

/// 某个地址所在节的末尾（虚拟地址，不含）；不在任何节里返回 `None`。
///
/// 用节的**文件大小**：那才是加载后真正有字节的那一段（`Section` 只有 `file.size`，
/// 没有虚拟大小；对 Mach-O 的 `__text` 两者相等）。
#[must_use]
pub fn section_end_of(object: &Object, addr: u64) -> Option<u64> {
    let section = object.section_at(addr)?;
    section.vaddr.checked_add(section.file.size)
}

/// 从对象的函数起点表推出边界。
///
/// 非 Mach-O（PE / ELF / DEX / raw）与剥光的 Mach-O 上 `function_starts` 是空表，
/// 这里返回空 —— 调用方据此**什么都不做**（不加候选、不加 notes）。
#[must_use]
pub fn derive_function_start_bounds(object: &Object) -> Vec<FunctionStartBound> {
    derive_function_starts(&object.function_starts, |addr| section_end_of(object, addr))
}

/// 把推导出的边界变成函数候选。
///
/// 名字恒为空：起点表里根本没有名字。一个没有名字的函数就是"未识别"，
/// 不生成 `func_xxx` 之类的占位名（CLAUDE.md §7）。
///
/// 边界走既有的编码约定 `<name>\t<end-hex>`（与展开表、调试信息同一条），
/// [`merge_candidates`] 解析出 end 后会把它从名字里剥掉；推不出边界时名称为空串，
/// 那个函数就如实"只知道起点"。
#[must_use]
pub fn function_start_candidates(bounds: &[FunctionStartBound]) -> Vec<SymbolCandidate> {
    bounds
        .iter()
        .map(|bound| SymbolCandidate {
            addr: bound.start,
            name: match bound.end.value() {
                Some(end) => format!("\t{end:x}"),
                None => String::new(),
            },
            source: SymbolSource::FunctionStart,
            // 置信度与展开表同档（85）：两者都是工具链在文件里写下的边界事实。
            // "结束地址是推导的"这件事已经由**来源**（rank 52，比展开表低一档）
            // 表达，不在这里再打一次折 —— 否则同一个信息被记两笔账。
            confidence: 85,
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn cand(addr: u64, name: &str, source: SymbolSource, conf: u8) -> SymbolCandidate {
        SymbolCandidate {
            addr,
            name: name.to_string(),
            source,
            confidence: conf,
        }
    }

    #[test]
    fn unwind_boundary_wins_and_sets_end() {
        // 符号表给了名字但没有边界；展开表给了边界。合并后：名字来自符号表，
        // 边界来自展开表 —— 各取所长，而不是"一个来源赢者通吃"。
        let cands = vec![
            cand(0x1000, "sub_1000", SymbolSource::SymbolTable, 70),
            SymbolCandidate {
                addr: 0x1000,
                name: "\t1040".to_string(),
                source: SymbolSource::Unwind,
                confidence: 85,
            },
        ];
        let f = merge_candidates(0x1000, cands);
        assert_eq!(f.name, "sub_1000", "名字应来自符号表");
        assert_eq!(f.end, Some(0x1040), "边界应来自展开表");
        assert_eq!(f.name_source, SymbolSource::SymbolTable);
    }

    #[test]
    fn multiple_unwind_bounds_take_minimum_and_report_conflict() {
        let cands = vec![
            SymbolCandidate {
                addr: 0x2000,
                name: "\t2100".to_string(),
                source: SymbolSource::Unwind,
                confidence: 85,
            },
            SymbolCandidate {
                addr: 0x2000,
                name: "\t2080".to_string(),
                source: SymbolSource::Unwind,
                confidence: 85,
            },
        ];
        let f = merge_candidates(0x2000, cands);
        // 取最小边界：宁可少要，不要把下一个函数的开头并进来
        assert_eq!(f.end, Some(0x2080));
        assert!(f.candidates.len() == 2, "落选候选必须保留，UI 要能解释冲突");
    }

    #[test]
    fn discovery_only_has_no_end() {
        let f = merge_candidates(
            0x3000,
            vec![cand(0x3000, "sub_3000", SymbolSource::Discovery, 50)],
        );
        assert_eq!(f.end, None, "只有调用目标时不知道边界，不许猜");
        assert_eq!(f.name_source, SymbolSource::Discovery);
    }

    #[test]
    fn user_name_beats_everything() {
        let f = merge_candidates(
            0x4000,
            vec![
                cand(0x4000, "from_symtab", SymbolSource::SymbolTable, 90),
                cand(0x4000, "my_read", SymbolSource::User, 10),
            ],
        );
        assert_eq!(f.name, "my_read");
        assert_eq!(f.name_source, SymbolSource::User);
    }

    /// 纯空白的名字**不能**被当成一个名字显示出来。
    ///
    /// 原来的断言是"空名候选被整个丢弃"（`candidates.is_empty()`）。
    /// 那个断言在加入入口点来源之后不再成立，而且**本来就不该成立**：
    /// 一个只有空白名字的候选仍然带着有效信息（来源 + 置信度），
    /// 把它整个丢掉等于把证据一起丢了。
    ///
    /// 真正要守的是"别把空白当名字显示"，所以断言改成盯 `name`。
    #[test]
    fn blank_names_are_not_treated_as_names() {
        let f = merge_candidates(0x5000, vec![cand(0x5000, "   ", SymbolSource::Export, 100)]);
        assert!(
            f.name.is_empty(),
            "纯空白名字必须被规范化成空名字（不能显示成三个空格），实际 {:?}",
            f.name
        );
        assert_eq!(
            f.confidence, 100,
            "空白名候选仍带着它的置信度（100）—— 覆盖度统计不该因为名字空白就归零"
        );
        // 来源仍然保留：这是"这里有个东西"的证据，不该被抹掉
        assert_eq!(f.name_source, SymbolSource::Export);
    }

    /// 无名字的候选仍然要贡献它的**来源**。
    ///
    /// 这条盯的是一个具体的谎话：入口点候选（`EntryPoint`）诚实地不带名字，
    /// 但如果合并时把"没有名字"顺手写成 `Discovery`，界面上就会显示
    /// "分析推断" —— 而真实的证据是"对象头里写着程序从这里进入"。
    /// 两条证据链的可靠性完全不同，不能互相冒充（CLAUDE.md §7）。
    #[test]
    fn unnamed_candidate_keeps_its_own_source() {
        let f = merge_candidates(0x6000, vec![cand(0x6000, "", SymbolSource::EntryPoint, 75)]);
        assert!(f.name.is_empty(), "没有名字就该是空的");
        assert_eq!(
            f.name_source,
            SymbolSource::EntryPoint,
            "来源必须是入口点，不能被写成发现/推断"
        );
        assert!(
            !f.candidates.is_empty(),
            "无名但有来源的候选不该被丢弃 —— 它是「这里有函数」的有效证据"
        );
    }

    /// 有名字的候选赢；无名的只影响来源。
    #[test]
    fn named_candidate_wins_over_unnamed_one() {
        let f = merge_candidates(
            0x7000,
            vec![
                cand(0x7000, "", SymbolSource::EntryPoint, 75),
                cand(0x7000, "real_name", SymbolSource::SymbolTable, 70),
            ],
        );
        assert_eq!(f.name, "real_name");
        assert_eq!(f.name_source, SymbolSource::SymbolTable);
    }

    #[test]
    fn unwind_candidate_encoding_roundtrips() {
        let entries = vec![bitflip_loader::object::UnwindEntry {
            begin: 0x1400,
            end: 0x1440,
            unwind_info: 0,
            decoded: None,
            // 边界来自 begin/end，与 `decoded` 无关：即使这条还没解码，
            // 它依然是一个有效的函数边界候选（`unwind_candidates` 正是这么用的）。
            deferred: false,
        }];
        let cands = unwind_candidates(&entries);
        assert_eq!(cands.len(), 1);
        assert_eq!(cands[0].addr, 0x1400);
        assert_eq!(cands[0].source, SymbolSource::Unwind);
        // 名字部分为空，边界部分能被 merge 还原
        let f = merge_candidates(0x1400, cands);
        assert_eq!(f.end, Some(0x1440));
    }

    // ─────────────────────────────────────────────────────────────
    // 函数起点表（`LC_FUNCTION_STARTS`）
    // ─────────────────────────────────────────────────────────────

    /// 合成一个只带一个 `__text` 节的对象（节的虚拟范围 `0x1000..0x1060`）。
    ///
    /// 按**规格**拼而不是照解析代码拼：这里填的是对象模型（分析层看到的视图），
    /// 字段含义见 `bitflip_loader::object::Section`。Mach-O 的 `__text` 文件大小与
    /// 虚拟大小相等，所以节的末尾就是 `vaddr + file.size`。
    fn synthetic_object(function_starts: &[u64], entry: Option<u64>) -> Object {
        use bitflip_arch::{Arch, ArchSpec, Endian, Mode};
        use bitflip_loader::object::{ContentKind, FileRange, ObjectId, Perms, Section};

        let mut object = Object::new(
            ObjectId::Plain,
            bitflip_loader::ObjectKind::MachO,
            ArchSpec::from_arch(Arch::X86_64, Mode::M64, Endian::Little),
            Endian::Little,
        );
        object.entry = entry;
        object.sections.push(Section {
            name: "__text".into(),
            vaddr: 0x1000,
            file: FileRange::new(0x4000, 0x60),
            perms: Perms {
                read: true,
                write: false,
                execute: true,
            },
            kind: ContentKind::Code,
            loaded: true,
        });
        object.function_starts = function_starts.to_vec();
        object
    }

    /// 与 `bitflip-core` 的 `TargetAnalysis::build` 同一套分组：地址 → 候选列表。
    /// 分组是去重的唯一机制，所以测试必须走同一条路。
    fn merge_by_addr(candidates: Vec<SymbolCandidate>) -> Vec<Function> {
        let mut by_addr: std::collections::BTreeMap<u64, Vec<SymbolCandidate>> =
            std::collections::BTreeMap::new();
        for candidate in candidates {
            by_addr.entry(candidate.addr).or_default().push(candidate);
        }
        by_addr
            .into_iter()
            .map(|(addr, candidates)| merge_candidates(addr, candidates))
            .collect()
    }

    /// 三个起点 → 三个函数，大小由**相邻起点**推出，最后一个用节的末尾。
    #[test]
    fn function_starts_yield_one_function_per_start_with_derived_sizes() {
        let object = synthetic_object(&[0x1000, 0x1010, 0x1030], None);
        let bounds = derive_function_start_bounds(&object);

        // 推导本身：前两个的上界是下一个起点，最后一个取节末尾（0x1000+0x60）。
        assert_eq!(
            bounds.iter().map(|b| (b.start, b.end)).collect::<Vec<_>>(),
            vec![
                (0x1000, DerivedEnd::NextStart(0x1010)),
                (0x1010, DerivedEnd::NextStart(0x1030)),
                (0x1030, DerivedEnd::SectionEnd(0x1060)),
            ],
            "结束地址的来源必须逐条记清楚，不能只剩一个数字"
        );

        let candidates = function_start_candidates(&bounds);
        assert_eq!(candidates.len(), 3);
        assert!(
            candidates.iter().all(|c| c.name.starts_with('\t')),
            "边界编码在名字里（与展开表同一条通道）"
        );

        let functions = merge_by_addr(candidates);
        assert_eq!(functions.len(), 3, "三个起点就是三个函数");
        assert_eq!(functions[0].start, 0x1000);
        assert_eq!(functions[0].end, Some(0x1010));
        assert_eq!(functions[0].end.map(|e| e - 0x1000), Some(0x10));
        assert_eq!(functions[1].end, Some(0x1030));
        assert_eq!(functions[1].end.map(|e| e - 0x1010), Some(0x20));
        assert_eq!(functions[2].end, Some(0x1060));
        assert_eq!(functions[2].end.map(|e| e - 0x1030), Some(0x30));

        // 来源：权威的"函数起点表"，不是"分析推断"。
        for f in &functions {
            assert_eq!(
                f.name_source,
                SymbolSource::FunctionStart,
                "{:#x} 的来源必须是函数起点表",
                f.start
            );
            assert!(
                f.name.is_empty(),
                "起点表里没有名字 —— 不许编（CLAUDE.md §7），实际 {:?}",
                f.name
            );
            assert_eq!(
                f.candidates
                    .iter()
                    .filter(|c| c.source == SymbolSource::FunctionStart)
                    .count(),
                1,
                "落选候选保留，且只有一个函数起点候选"
            );
        }
    }

    /// 起点落不进任何节、表里又没有下一个 → 边界未知，**不猜**。
    #[test]
    fn last_start_outside_every_section_keeps_unknown_end() {
        let object = synthetic_object(&[0x1000, 0x1020, 0x9000], None);
        let bounds = derive_function_start_bounds(&object);
        assert_eq!(bounds[1].end, DerivedEnd::NextStart(0x9000));
        assert_eq!(
            bounds[2].end,
            DerivedEnd::Unknown,
            "0x9000 不在 __text 里，推不出末尾 —— 不许拿一个附近的值凑"
        );
        assert_eq!(bounds[2].end.value(), None);

        let functions = merge_by_addr(function_start_candidates(&bounds));
        assert_eq!(functions.len(), 3);
        assert_eq!(
            functions[2].end, None,
            "推不出边界就留 None（只知道起点），不填 0 也不填下一个节"
        );
    }

    /// 起点正好是入口点：**不能**多出一个函数，入口函数要拿到权威边界。
    #[test]
    fn a_start_equal_to_the_entry_point_does_not_duplicate_it() {
        let object = synthetic_object(&[0x1000, 0x1010], Some(0x1000));
        let mut candidates = function_start_candidates(&derive_function_start_bounds(&object));
        // 入口点来源（与 `bitflip-core` 的"来源 3.5"同样：无名、置信度 75）
        candidates.push(SymbolCandidate {
            addr: 0x1000,
            name: String::new(),
            source: SymbolSource::EntryPoint,
            confidence: 75,
        });

        let functions = merge_by_addr(candidates);
        assert_eq!(
            functions.len(),
            2,
            "入口点已经是函数起点表里的一条，不该多出第三个函数"
        );
        assert_eq!(functions[0].start, 0x1000);
        assert_eq!(
            functions[0].end,
            Some(0x1010),
            "入口函数也要拿到函数起点表给的边界"
        );
        assert_eq!(
            functions[0].candidates.len(),
            2,
            "两个来源在同一地址上合并成一个函数，候选都留着"
        );
        // 来源按既有优先级：入口点(45) 比函数起点表(52) 硬，所以显示"入口点"。
        // 这里还依赖另一条规则：只有边界编码（`"\t<end>"`）的候选**不算有名字**，
        // 否则它会挤掉诚实的无名候选、赢下"名字来源"（见 `has_display_name`）。
        assert_eq!(functions[0].name_source, SymbolSource::EntryPoint);
        assert!(
            functions[0].name.is_empty(),
            "入口点不提供名字，名字仍是空的"
        );
    }

    /// 空表 = 没有这样一张表：不产生候选、不产生函数。
    ///
    /// 与"字段从未被填过"的对象逐字段比对 —— 两者必须**完全一样**，
    /// 否则 PE/ELF/DEX 会凭空多出一条"函数起点表为空"的噪声。
    #[test]
    fn empty_function_starts_change_nothing() {
        let empty = synthetic_object(&[], None);
        let untouched = synthetic_object(&[], None);
        assert_eq!(empty.function_starts, untouched.function_starts);

        let bounds = derive_function_start_bounds(&empty);
        assert!(bounds.is_empty());
        assert!(function_start_candidates(&bounds).is_empty());
        assert!(
            merge_by_addr(function_start_candidates(&bounds)).is_empty(),
            "没有候选就不该有函数"
        );
    }

    /// **冲突**：符号落在推导出的范围里。
    ///
    /// 文档化的结果是"边界不动、矛盾上报"，不是"把边界截到符号那里"：
    ///
    /// * `LC_FUNCTION_STARTS` 说的是"这些是**函数起点**"。被夹在中间的那个地址
    ///   不在这张表里，它只是符号表里的一个地址；截断到它等于让一个没有边界
    ///   主张的来源（`nlist` 里根本没有 size）去改写一个文件里写着的起点序列，
    ///   而截出来的那个数字**没有任何来源断言过**。
    /// * 两个函数因此在地址上重叠 —— 这件事必须让用户看见（由上层写进 notes），
    ///   不能靠"悄悄截断"抹平。
    #[test]
    fn a_symbol_strictly_inside_a_derived_range_does_not_truncate_the_boundary() {
        let object = synthetic_object(&[0x1000, 0x1040], None);
        let mut candidates = function_start_candidates(&derive_function_start_bounds(&object));
        candidates.push(SymbolCandidate {
            addr: 0x1020,
            name: "inner_label".to_string(),
            source: SymbolSource::SymbolTable,
            confidence: 70,
        });

        let functions = merge_by_addr(candidates);
        assert_eq!(
            functions.len(),
            3,
            "0x1000、0x1020（符号）、0x1040（表里第二个起点）各是一个函数 —— \
             符号是**新增**的一个候选地址，不是替换掉某个起点"
        );

        let outer = &functions[0];
        assert_eq!(outer.start, 0x1000);
        assert_eq!(
            outer.end,
            Some(0x1040),
            "推导出的边界不许被夹在中间的符号截断"
        );

        let inner = &functions[1];
        assert_eq!(inner.start, 0x1020);
        assert_eq!(
            inner.end, None,
            "符号表不提供边界（nlist 没有 size 字段），所以这个函数只知道起点"
        );
        assert_eq!(inner.name, "inner_label", "有符号就用符号名，照旧");
    }
}
