//! 指令级差分（M9 交付物 4 的最后一块：函数内的"逐条怎么变"）。
//!
//! # 形状（拍板记录，2026-10-19）
//!
//! 外层**锚点块匹配**、内层小段 LCS，输出两级操作序列：
//!
//! 1. **锚点**：归一化后文本相同、且在各自序列里**只出现一次**的指令。
//!    锚点键用"形状"（助记符+寄存器+立即数，绝对地址抹平——与 [`super::diff`]
//!    的弱指纹同一套归一化，理由也相同：绝对地址随基址/被调用者位置变，形状不变）。
//!    锚点还必须**两侧同序**（最长递增锚点链，LIS），乱序锚点只代表巧合同名，
//!    不是同一个位置。
//! 2. 锚点把两侧序列切成一段一段；**段内**走标准 LCS（把两条不同指令的代价
//!    设为 2、插入/删除为 1 —— 这样一条"替换"才会在回溯里被选成"一条 replace"
//!    而不是"一条删 + 一条插"，报告因此能说出"第 3 条 `mov` 变 `add`"）。
//! 3. 段太大（> [`MAX_BLOCK`]）不逐条展开，只给一个 `block` 占位操作 ——
//!    大函数整段重写时报告不该有几千行，**诚实降级**而不是假装逐条对过。
//!
//! # 为什么"每条指令都有归属"不是目标（与纯 LCS 的取舍）
//!
//! 编译器重排两个基本块时，纯 LCS 会报一串删+插；锚点法把它们中间唯一的
//! 稳定指令当界碑，重排块整体落进"块间未展开"或段内 LCS，报告保持可读。
//! 代价是重排块内部不逐条归属——这是有意的取舍，已写入块占位的说明。

use serde::{Deserialize, Serialize};

/// 单个函数内指令级差分的 wire 格式版本。
pub const INSTR_DIFF_FORMAT_VERSION: u32 = 1;

/// 段内逐条细对齐的最大长度；超过就给 `block` 占位（诚实降级）。
pub const MAX_BLOCK: usize = 64;

/// 一个操作。序列按 v1 位置单调；`insert` 没有 v1 侧，`delete` 没有 v2 侧。
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "op", rename_all = "kebab-case")]
pub enum InstrOpWire {
    /// 两边都有、形状一致（数值差异已抹平；真实字节可能仍不同，看 `note`）。
    Equal {
        /// v1 的行号（0 起，在该函数的指令序列里）。
        v1: usize,
        /// v2 的行号。
        v2: usize,
        /// 归一化后的文本（两侧一致）。
        text: String,
    },
    /// 一条换另一条（块内 LCS 以替换优先于删+插）。
    Replace {
        /// v1 的行号。
        v1: usize,
        /// v2 的行号。
        v2: usize,
        /// v1 的归一化文本。
        v1_text: String,
        /// v2 的归一化文本。
        v2_text: String,
    },
    /// v2 多出来的。
    Insert {
        /// v2 的行号。
        v2: usize,
        /// v2 的归一化文本。
        text: String,
    },
    /// v1 有、v2 没有的。
    Delete {
        /// v1 的行号。
        v1: usize,
        /// v1 的归一化文本。
        text: String,
    },
    /// 整段未展开（超过 [`MAX_BLOCK`]）。两端位置锚定这段的范围。
    Block {
        /// v1 区间 `[start, end)`（行号）；一侧为空时对应端为 `None`。
        v1_range: Option<(usize, usize)>,
        /// v2 区间。
        v2_range: Option<(usize, usize)>,
        /// 为什么不展开（固定文案，便于测试与消费方依赖）。
        reason: String,
    },
}

/// 一侧的输入：已按地址排序的指令序列（归一化前）。
pub struct InstrSide<'a> {
    /// `(行内文本, 编码长度)`，文本是反汇编渲染原文（含绝对地址）。
    pub instructions: &'a [(String, u8)],
    /// 归一化用镜像基址（[`super::diff::normalize_addresses`] 同款语义）。
    pub base: u64,
    /// 镜像结束地址（范围外字面量不当地址抹平）。
    pub image_end: u64,
}

/// 两段指令序列的指令级差分。
///
/// 返回操作序列（v1 单调）与统计。**不**知道函数是谁的——那是上层的职责；
/// 这里只回答"这 m 条和那 n 条怎么对应"。
#[must_use]
pub fn diff_instructions(one: &InstrSide<'_>, two: &InstrSide<'_>) -> Vec<InstrOpWire> {
    // 归一化：与弱指纹同一套（地址抹平）。长度编不进文本键——等长替换时
    // 编码长度变了但形状没变的情况（罕见）会被当成 equal；这是有意的：
    // 形状级报告本来就不承诺编码一致，编码差异由函数级强指纹负责。
    let norm = |side: &InstrSide<'_>| -> Vec<String> {
        side.instructions
            .iter()
            .map(|(text, _)| super::diff::normalize_addresses(text, side.base, side.image_end))
            .collect()
    };
    let a = norm(one);
    let b = norm(two);

    // ── 外层：找两侧同序的唯一锚点 ──
    let anchors = anchor_chain(&a, &b);

    // 锚点把两侧各切成 (段起点, 段终点) 对。
    let mut ops = Vec::new();
    let mut a_prev = 0usize;
    let mut b_prev = 0usize;
    for &(ai, bi) in &anchors {
        lcs_block(&a[a_prev..ai], &b[b_prev..bi], a_prev, b_prev, &mut ops);
        ops.push(InstrOpWire::Equal {
            v1: ai,
            v2: bi,
            text: a[ai].clone(),
        });
        a_prev = ai + 1;
        b_prev = bi + 1;
    }
    lcs_block(&a[a_prev..], &b[b_prev..], a_prev, b_prev, &mut ops);
    ops
}

/// 选锚点：文本在各自序列里唯一、且两侧同序的最长链（LIS）。
fn anchor_chain(a: &[String], b: &[String]) -> Vec<(usize, usize)> {
    // 出现次数 >1 的文本不是锚点（同名可能只是巧合同形状）。
    let mut counts_a: std::collections::HashMap<&str, usize> = std::collections::HashMap::new();
    for text in a.iter() {
        *counts_a.entry(text.as_str()).or_default() += 1;
    }
    let mut counts_b: std::collections::HashMap<&str, usize> = std::collections::HashMap::new();
    for text in b.iter() {
        *counts_b.entry(text.as_str()).or_default() += 1;
    }

    // 候选锚点：两侧都唯一。按 a 的顺序天然递增；对 b 序列求 LIS 即"两侧同序"。
    let candidates: Vec<(usize, usize)> = {
        let mut index_b: std::collections::HashMap<&str, usize> = std::collections::HashMap::new();
        for (index, text) in b.iter().enumerate() {
            if counts_b.get(text.as_str()).copied() == Some(1) {
                index_b.insert(text.as_str(), index);
            }
        }
        let mut out = Vec::new();
        for (index, text) in a.iter().enumerate() {
            if counts_a.get(text.as_str()).copied() != Some(1) {
                continue;
            }
            if let Some(&bi) = index_b.get(text.as_str()) {
                out.push((index, bi));
            }
        }
        out
    };

    // 对 b 下标求最长严格递增子序列（a 下标已有序）。 patience 风格：
    // tails 里存 (b下标, 候选序号)；用二分。
    let mut tails: Vec<(usize, usize)> = Vec::new();
    let mut prev: Vec<Option<usize>> = vec![None; candidates.len()];
    for (ci, &(_, bi)) in candidates.iter().enumerate() {
        // 找 tails 里第一个 b 下标 >= bi 的位置（严格递增 → 替换它）。
        let pos = tails.partition_point(|&(tb, _)| tb < bi);
        if pos == tails.len() {
            tails.push((bi, ci));
        } else {
            tails[pos] = (bi, ci);
        }
        if pos > 0 {
            prev[ci] = Some(tails[pos - 1].1);
        }
    }
    // 回溯链条。
    let mut chain = Vec::new();
    if let Some(&(_, mut ci)) = tails.last() {
        loop {
            chain.push(candidates[ci]);
            match prev[ci] {
                Some(p) => ci = p,
                None => break,
            }
        }
    }
    chain.reverse();
    chain
}

/// 段内细对齐（LCS，替换代价 2 = 删1+插1，回溯时优先选替换）。
///
/// 段长超过 [`MAX_BLOCK`]（**任意一侧**超过就算——一侧为 0 时它只是纯插入/
/// 纯删除，不展开也不亏：那本来就是逐条 insert/delete）时输出一个 `block`
/// 占位；一侧为空的段不受限（纯插/删逐条列出反而是用户要的）。
fn lcs_block(a: &[String], b: &[String], a_base: usize, b_base: usize, ops: &mut Vec<InstrOpWire>) {
    if a.is_empty() && b.is_empty() {
        return;
    }
    let too_big = a.len() > MAX_BLOCK || b.len() > MAX_BLOCK;
    if too_big && !a.is_empty() && !b.is_empty() {
        ops.push(InstrOpWire::Block {
            v1_range: Some((a_base, a_base + a.len())),
            v2_range: Some((b_base, b_base + b.len())),
            reason: format!(
                "连续 {} / {} 条指令的段超过逐条展开上限（{}），不假装逐条对过",
                a.len(),
                b.len(),
                MAX_BLOCK
            ),
        });
        return;
    }

    // 标准 DP。段被 MAX_BLOCK 框住，m*n ≤ 64*64 = 4096 格，内存无需优化。
    let (m, n) = (a.len(), b.len());
    let mut dp = vec![0u32; (m + 1) * (n + 1)];
    let at = |i: usize, j: usize| i * (n + 1) + j;
    for i in (0..m).rev() {
        for j in (0..n).rev() {
            let diag = if a[i] == b[j] {
                dp[at(i + 1, j + 1)] + 2
            } else {
                // 替换 = 删+插的代价 2；可行才走替换（否则取删/插的最大值）。
                if dp[at(i + 1, j + 1)] >= dp[at(i + 1, j)].max(dp[at(i, j + 1)]) {
                    dp[at(i + 1, j + 1)]
                } else {
                    dp[at(i + 1, j)].max(dp[at(i, j + 1)])
                }
            };
            dp[at(i, j)] = diag.max(dp[at(i + 1, j)]).max(dp[at(i, j + 1)]);
        }
    }
    // 回溯。
    let (mut i, mut j) = (0usize, 0usize);
    while i < m || j < n {
        if i < m && j < n && a[i] == b[j] {
            ops.push(InstrOpWire::Equal {
                v1: a_base + i,
                v2: b_base + j,
                text: a[i].clone(),
            });
            i += 1;
            j += 1;
        } else if i < m && j < n {
            // 替换优先：只要 DP 值允许（替换不劣于删+插），报一条 replace。
            let take_replace = dp[at(i + 1, j + 1)] >= dp[at(i + 1, j)]
                && dp[at(i + 1, j + 1)] >= dp[at(i, j + 1)];
            if take_replace {
                ops.push(InstrOpWire::Replace {
                    v1: a_base + i,
                    v2: b_base + j,
                    v1_text: a[i].clone(),
                    v2_text: b[j].clone(),
                });
                i += 1;
                j += 1;
            } else if dp[at(i + 1, j)] >= dp[at(i, j + 1)] {
                ops.push(InstrOpWire::Delete {
                    v1: a_base + i,
                    text: a[i].clone(),
                });
                i += 1;
            } else {
                ops.push(InstrOpWire::Insert {
                    v2: b_base + j,
                    text: b[j].clone(),
                });
                j += 1;
            }
        } else if i < m {
            ops.push(InstrOpWire::Delete {
                v1: a_base + i,
                text: a[i].clone(),
            });
            i += 1;
        } else {
            ops.push(InstrOpWire::Insert {
                v2: b_base + j,
                text: b[j].clone(),
            });
            j += 1;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn side(texts: &[&str]) -> (InstrSide<'static>, Vec<(String, u8)>) {
        // 泄漏以获得 'static —— 测试里可接受（数量小、进程生命周期）。
        let owned: Vec<(String, u8)> = texts.iter().map(|t| ((*t).to_string(), 1)).collect();
        let leaked: &'static [(String, u8)] = Box::leak(owned.into_boxed_slice());
        (
            InstrSide {
                instructions: leaked,
                base: 0x140000000,
                image_end: 0x140010000,
            },
            leaked.to_vec(),
        )
    }

    fn op_summary(ops: &[InstrOpWire]) -> Vec<String> {
        ops.iter()
            .map(|op| match op {
                InstrOpWire::Equal { v1, v2, .. } => format!("=({v1},{v2})"),
                InstrOpWire::Replace { v1, v2, .. } => format!("~({v1},{v2})"),
                InstrOpWire::Insert { v2, .. } => format!("+({v2})"),
                InstrOpWire::Delete { v1, .. } => format!("-({v1})"),
                InstrOpWire::Block { .. } => "##".to_string(),
            })
            .collect()
    }

    #[test]
    fn identical_sequences_are_all_equal() {
        let (one, _) = side(&["mov eax, 1", "add eax, 2", "ret"]);
        let (two, _) = side(&["mov eax, 1", "add eax, 2", "ret"]);
        let ops = diff_instructions(&one, &two);
        assert_eq!(
            op_summary(&ops),
            vec!["=(0,0)", "=(1,1)", "=(2,2)"],
            "逐条相同就是全等"
        );
    }

    #[test]
    fn one_replacement_is_reported_as_replace_not_delete_plus_insert() {
        // "第 3 条 mov 变 add"：替换必须是一条 replace，不是 -x +y 两条。
        let (one, _) = side(&["push rbp", "mov rbp, rsp", "mov eax, 1", "pop rbp", "ret"]);
        let (two, _) = side(&["push rbp", "mov rbp, rsp", "add eax, 1", "pop rbp", "ret"]);
        let ops = diff_instructions(&one, &two);
        assert_eq!(
            op_summary(&ops),
            vec!["=(0,0)", "=(1,1)", "~(2,2)", "=(3,3)", "=(4,4)"],
            "一条替换就是一条 replace（形状：mov→add）"
        );
        match &ops[2] {
            InstrOpWire::Replace {
                v1_text, v2_text, ..
            } => {
                assert!(v1_text.contains("mov"), "v1 是 mov，实为 {v1_text}");
                assert!(v2_text.contains("add"), "v2 是 add，实为 {v2_text}");
            }
            other => panic!("期望 Replace，实为 {other:?}"),
        }
    }

    #[test]
    fn absolute_addresses_are_normalized_so_moved_callers_do_not_count_as_changes() {
        // call 的目标换了位置（被调用者搬家，两版基址不同）：形状相同 → equal。
        let one: Vec<(String, u8)> =
            vec![("call 0x140001020".to_string(), 1), ("ret".to_string(), 1)];
        let two: Vec<(String, u8)> =
            vec![("call 0x180001020".to_string(), 1), ("ret".to_string(), 1)];
        let one = InstrSide {
            instructions: &one,
            base: 0x140000000,
            image_end: 0x140010000,
        };
        let two = InstrSide {
            instructions: &two,
            base: 0x180000000,
            image_end: 0x180010000,
        };
        let ops = diff_instructions(&one, &two);
        assert_eq!(
            op_summary(&ops),
            vec!["=(0,0)", "=(1,1)"],
            "仅绝对地址不同不算改动（归一化抹平）"
        );
    }

    #[test]
    fn reordered_blocks_stay_minimal_through_anchors() {
        // 中间两块整体重排 + 首尾唯一锚点。块里每条指令的形状在两侧都唯一，
        // 全是锚点候选；LIS 选出两侧同序的最长链（首、块B两条、尾），
        // 重排的净效果 = 块A的 2 删 + 2 插，**没有假替换**，也不是
        // 纯 LCS 那种把整段打碎的 6+ 操作风暴。
        let (one, _) = side(&[
            "mov eax, 1",   // 0  锚
            "xor ebx, ebx", // 1  ┐ 块A
            "cmp ebx, 5",   // 2  ┘
            "xor ecx, ecx", // 3  ┐ 块B
            "cmp ecx, 7",   // 4  ┘
            "ret",          // 5  锚
        ]);
        let (two, _) = side(&[
            "mov eax, 1",   // 0 锚
            "xor ecx, ecx", // 1 ┐ 块B（挪到前面）
            "cmp ecx, 7",   // 2 ┘
            "xor ebx, ebx", // 3 ┐ 块A（挪到后面）
            "cmp ebx, 5",   // 4 ┘
            "ret",          // 5 锚
        ]);
        let ops = diff_instructions(&one, &two);
        let summary = op_summary(&ops);
        assert_eq!(summary[0], "=(0,0)", "首锚对齐");
        assert_eq!(summary.last().unwrap(), "=(5,5)", "尾锚对齐");
        let deletes = summary.iter().filter(|s| s.starts_with('-')).count();
        let inserts = summary.iter().filter(|s| s.starts_with('+')).count();
        let replaces = summary.iter().filter(|s| s.starts_with('~')).count();
        assert_eq!((deletes, inserts, replaces), (2, 2, 0), "实际 {summary:?}");
    }

    #[test]
    fn oversized_block_degrades_honestly_to_block_placeholder() {
        // 200 条 vs 200 条互不相同的指令 + 中缝一个唯一锚点。锚把序列切成
        // 锚前/锚后两段，两段都超限 → 各占一个 block 占位。
        let v1: Vec<String> = (0..200)
            .map(|i| {
                if i == 100 {
                    "ret".to_string() // 中缝唯一锚点
                } else {
                    format!("mov r{}, {i}", i % 15)
                }
            })
            .collect();
        let v2: Vec<String> = (0..200)
            .map(|i| {
                if i == 100 {
                    "ret".to_string()
                } else {
                    format!("add r{}, {i}", i % 15)
                }
            })
            .collect();
        let one: Vec<(String, u8)> = v1.iter().map(|t| (t.clone(), 1)).collect();
        let two: Vec<(String, u8)> = v2.iter().map(|t| (t.clone(), 1)).collect();
        let one = InstrSide {
            instructions: &one,
            base: 0x140000000,
            image_end: 0x140010000,
        };
        let two = InstrSide {
            instructions: &two,
            base: 0x140000000,
            image_end: 0x140010000,
        };
        let ops = diff_instructions(&one, &two);
        let blocks = ops
            .iter()
            .filter(|op| matches!(op, InstrOpWire::Block { .. }))
            .count();
        assert_eq!(blocks, 2, "锚前/锚后各一个超限段，各占一个 block 占位");
    }

    #[test]
    fn pure_insertion_in_the_middle_keeps_everything_else_aligned() {
        let (one, _) = side(&["push rax", "pop rax", "ret"]);
        let (two, _) = side(&["push rax", "xor ecx, ecx", "pop rax", "ret"]);
        let ops = diff_instructions(&one, &two);
        assert_eq!(
            op_summary(&ops),
            vec!["=(0,0)", "+(1)", "=(1,2)", "=(2,3)"],
            "中间插一条：前后照常对齐，插入单列"
        );
    }
}
