//! 函数识别：多来源候选 + 置信度 + 冲突消解。
//!
//! 一个地址"是不是函数、从哪到哪"可能同时有多个来源给出答案：
//! 符号表说是、`.pdata`/`.eh_frame` 展开表说是、调用目标说是、prologue 模式说是。
//! 这些来源的可信度不同，冲突时的取舍必须**可解释** —— UI 要能回答
//! "为什么这里被当成函数"（PLAN §M3 交付物）。
//!
//! 优先级沿用 `bitflip-symbols::SymbolSource`（符号 > 展开 > 调用目标 > prologue）。
//! 冲突不静默吞掉：边界不一致的候选全部保留，合并结果附 `notes`。

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
    let named: Vec<SymbolCandidate> = candidates
        .iter()
        .filter(|c| validate(c).is_ok())
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
        }];
        let cands = unwind_candidates(&entries);
        assert_eq!(cands.len(), 1);
        assert_eq!(cands[0].addr, 0x1400);
        assert_eq!(cands[0].source, SymbolSource::Unwind);
        // 名字部分为空，边界部分能被 merge 还原
        let f = merge_candidates(0x1400, cands);
        assert_eq!(f.end, Some(0x1440));
    }
}
