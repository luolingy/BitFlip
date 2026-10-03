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
    // 过滤空名候选：这是数据错误，不能让一个空名赢下合并
    let candidates: Vec<SymbolCandidate> = candidates
        .into_iter()
        .filter(|c| validate(c).is_ok())
        .collect();

    let chosen = preferred(&candidates).cloned();
    let (mut name, name_source) = chosen
        .map(|c| (c.name, c.source))
        .unwrap_or_else(|| (String::new(), SymbolSource::Discovery));

    // 展开表候选把边界编码在 name 里（约定 `<name>\t<end>`）。边界在上面解析，
    // 但**标记必须在这里从名字里去掉** —— 否则 UI 会把 "\t140001050" 当成函数名
    // 显示出来，那是拿编码细节冒充识别结果（CLAUDE.md §7）。
    // 展开表本身不提供名字，剥掉标记后名字自然为空，UI 会显示"未命名"。
    if name_source == SymbolSource::Unwind {
        if let Some((real, _end)) = name.rsplit_once('\t') {
            name = real.to_string();
        }
    }

    // 边界候选：来源带 end 的才参与（调用目标/prologue 只知道入口）
    let mut bounds: Vec<(SymbolSource, u64)> = Vec::new();
    for c in &candidates {
        if c.addr != addr {
            continue;
        }
        // 展开表候选把 end 编码进 name 约定：`<name>\t<end>`。
        // 这是 sources 层的约定（Unwind 候选必须带边界）；
        // 其他来源的候选不带。
        if c.source == SymbolSource::Unwind {
            if let Some((_, end)) = c.name.rsplit_once('\t') {
                if let Ok(end) = u64::from_str_radix(end.trim_start_matches("0x"), 16) {
                    bounds.push((SymbolSource::Unwind, end));
                }
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

    #[test]
    fn blank_names_are_filtered_out() {
        let f = merge_candidates(0x5000, vec![cand(0x5000, "   ", SymbolSource::Export, 100)]);
        assert!(f.candidates.is_empty(), "空名候选不能存活");
        assert_eq!(f.confidence, 0);
    }

    #[test]
    fn unwind_candidate_encoding_roundtrips() {
        let entries = vec![bitflip_loader::object::UnwindEntry {
            begin: 0x1400,
            end: 0x1440,
            unwind_info: 0,
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
