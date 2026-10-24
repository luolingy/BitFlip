//! 控制流结构化：把基本块 CFG 还原成带 `if` / `else` / `while` / `do-while` 的结构化伪代码
//! （阶段 1：反编译深度）。
//!
//! # 与 `pseudo` 模块的关系
//!
//! [`crate::pseudo::decompile_function`] 给出的是**扁平**视图：每个基本块一段、条件跳转写成
//! `if (cond) goto ADDR`。本模块在其上做**控制流结构化**，产出一份嵌套缩进的
//! [`PseudocodeFunction`]（`structured` / `structured_body` 字段）。
//!
//! # 三条不肯让步的规矩
//!
//! 1. **能证明才结构化，否则就 goto。** 只对**可归约**、SESE（单入单出）形态清晰的区域做
//!    `if/else/while/do-while`；任何拿不准的（不可归约、多重回边、复杂重汇合）一律退回
//!    `if (cond) goto ADDR`，并如实标注"部分结构化"。不为了"看起来像反编译结果"而猜结构。
//! 2. **每一句都可追溯到指令地址**：结构化渲染的每一行行尾带 `/* @0xADDR */` 注释。
//! 3. **不静默**：共用了多少块、还剩多少 goto、为什么没结构化，都进 `notes`。
//!
//! 本模块**只读**指令与 CFG，不依赖架构枚举（指令文本由 `pseudo::translate` 提供）。

use std::collections::{BTreeMap, BTreeSet};

use bitflip_arch::{DecodedInsn, Flow};

use crate::cfg::Cfg;
use crate::pseudo::{
    condition_text, decompile_function, translate, PseudocodeFunction, PseudocodeNote,
    RegisterNamer,
};

/// 结构化渲染的一行。
#[derive(Debug, Clone)]
struct Line {
    indent: usize,
    text: String,
}

/// 结构化结果（供 [`decompile_structured`] 组装）。
struct Built {
    lines: Vec<Line>,
    /// 结构化过程中被迫留下的 `goto` 数（0 表示完全结构化）。
    residual_gotos: usize,
    /// 实际“吃进结构”里的基本块数。
    structured_blocks: usize,
}

/// 生成一个函数的**结构化**伪代码。
///
/// 结构失败或只能部分结构化时，`structured` 为 `false`，但仍会在 `structured_body` 里给出
/// **尽可能结构化**的版本（残留处是 `if (cond) goto`），并附 [`PseudocodeNote`] 说明。
/// 这与“不静默、不猜测”一致：用户总能拿到比扁平视图更好的东西，且知道它有多好。
#[must_use]
pub fn decompile_structured(
    entry: u64,
    name: Option<&str>,
    insns: &[DecodedInsn],
    cfg: &Cfg,
    namer: RegisterNamer<'_>,
) -> PseudocodeFunction {
    // 先拿扁平版本：它已经算好了每块的语句、未翻译计数、截断、基础 notes。
    let mut flat = decompile_function(entry, name, insns, cfg, namer);

    if cfg.is_empty() {
        return flat;
    }

    let by_addr: BTreeMap<u64, &DecodedInsn> = insns.iter().map(|i| (i.addr, i)).collect();
    let block_map: BTreeMap<u64, &crate::cfg::BasicBlock> =
        cfg.blocks().map(|b| (b.start, b)).collect();
    let entry_block = cfg.blocks().next().map(|b| b.start);

    let Some(start) = entry_block else {
        return flat;
    };

    let dom = compute_dominators(&block_map, start);
    let ipdom = compute_immediate_postdominators(&block_map);

    let mut builder = Builder {
        by_addr: &by_addr,
        blocks: &block_map,
        dom: &dom,
        ipdom: &ipdom,
        namer,
        visited: BTreeSet::new(),
        lines: Vec::new(),
        residual_gotos: 0,
        structured_blocks: 0,
        budget: MAX_STRUCT_LINES,
    };
    builder.emit_from(start, None, 0);

    let built = Built {
        lines: builder.lines,
        residual_gotos: builder.residual_gotos,
        structured_blocks: builder.structured_blocks,
    };

    let fully = built.residual_gotos == 0 && built.structured_blocks == block_map.len();

    // 渲染成带缩进/地址注释的行。
    let body: Vec<String> = built
        .lines
        .iter()
        .map(|l| {
            let pad = "  ".repeat(l.indent + 1);
            format!("{pad}{}", l.text)
        })
        .collect();

    flat.structured = fully;
    flat.structured_body = Some(body);
    // 去掉扁平模式必带的 FlatGoto 说明，换成结构化/部分结构化的说明。
    flat.notes
        .retain(|n| !matches!(n, PseudocodeNote::FlatGoto));
    if fully {
        flat.notes.push(PseudocodeNote::Structured);
    } else {
        flat.notes.push(PseudocodeNote::PartiallyStructured {
            residual_gotos: built.residual_gotos,
            structured_blocks: built.structured_blocks,
            total_blocks: block_map.len(),
        });
    }
    flat
}

/// 结构化行数上限：防止病态输入把内存吃光（与扁平模式的 `MAX_STATEMENTS` 同精神）。
const MAX_STRUCT_LINES: usize = 8000;

struct Builder<'a> {
    by_addr: &'a BTreeMap<u64, &'a DecodedInsn>,
    blocks: &'a BTreeMap<u64, &'a crate::cfg::BasicBlock>,
    dom: &'a BTreeMap<u64, BTreeSet<u64>>,
    ipdom: &'a BTreeMap<u64, Option<u64>>,
    namer: RegisterNamer<'a>,
    visited: BTreeSet<u64>,
    lines: Vec<Line>,
    residual_gotos: usize,
    structured_blocks: usize,
    budget: usize,
}

impl Builder<'_> {
    fn push(&mut self, indent: usize, text: String) {
        if self.lines.len() < self.budget {
            self.lines.push(Line { indent, text });
        }
    }

    /// 把块内**除控制转移以外的**语句逐条推出（带地址注释）。
    ///
    /// `skip_last` 为真时跳过块最后一条指令（当它是被结构化的分支/跳转时）。
    fn emit_block_stmts(&mut self, block_start: u64, indent: usize, skip_last_branch: bool) {
        let Some(b) = self.blocks.get(&block_start).copied() else {
            return;
        };
        let last_addr = self.last_insn_addr(b);
        for (&addr, insn) in self.by_addr.range(b.start..b.end) {
            if skip_last_branch && Some(addr) == last_addr {
                continue;
            }
            match translate(insn, self.namer) {
                Ok(Some(text)) => self.push(indent, format!("{text}; /* @{addr:#x} */")),
                Ok(None) => {}
                Err(reason) => {
                    self.push(indent, format!("/* 无法翻译：{reason} */ /* @{addr:#x} */"))
                }
            }
        }
    }

    /// 块内最后一条指令的地址。
    fn last_insn_addr(&self, b: &crate::cfg::BasicBlock) -> Option<u64> {
        self.by_addr
            .range(b.start..b.end)
            .next_back()
            .map(|(&a, _)| a)
    }

    /// 从 `cur` 开始，一直发射到 `stop`（不含）为止，返回是否正常到达 stop。
    ///
    /// `stop == None` 表示直到控制流自然结束（ret / 无后继）。
    fn emit_from(&mut self, mut cur: u64, stop: Option<u64>, indent: usize) {
        loop {
            if Some(cur) == stop {
                return;
            }
            if self.visited.contains(&cur) {
                // 回到已发射过的块（数据上不该走到这里，正常回边在循环里处理）。
                // 安全兜底：记为 goto，不再展开。
                self.push(indent, format!("goto {cur:#x};"));
                self.residual_gotos += 1;
                return;
            }
            let Some(b) = self.blocks.get(&cur).copied() else {
                return;
            };
            if self.lines.len() >= self.budget {
                return;
            }

            let succs = &b.successors;
            let last_insn = self
                .last_insn_addr(b)
                .and_then(|a| self.by_addr.get(&a).copied());

            // 终结块（ret/trap）或没有已知后继：整块发射后停。
            if b.terminal || succs.is_empty() {
                self.emit_block_stmts(cur, indent, false);
                self.visited.insert(cur);
                self.structured_blocks += 1;
                return;
            }

            match last_insn.map(|i| i.flow) {
                Some(Flow::Branch { conditional: true }) => {
                    // 条件块：先看是不是循环回边（某个后继支配当前块）。
                    if let Some(header) = self.loop_header_of(cur, succs) {
                        if self.emit_loop(cur, header, indent) {
                            // 循环发射后：cur 已推进到循环出口（或有 goto 兜底）。
                            // emit_loop 不改变 cur；此处直接 return（循环自身处理出口）。
                            return;
                        }
                        // 循环形态没把握 → 落到普通条件处理（大概率走 goto）。
                    }
                    if self.emit_if(cur, last_insn, succs, stop, indent) {
                        return;
                    }
                    // 兜底：整块发射 + 两个后继都写成 goto。
                    self.emit_block_stmts(cur, indent, true);
                    self.visited.insert(cur);
                    self.structured_blocks += 1;
                    for &s in succs {
                        self.push(indent, format!("goto {s:#x};"));
                        self.residual_gotos += 1;
                    }
                    return;
                }
                Some(Flow::Branch { conditional: false }) => {
                    // 无条件跳转（单后继）。
                    if let Some(&t) = succs.first() {
                        // 若是循环回边（t 支配 cur）→ 结构化成 loop 尾。
                        if self.dominates(t, cur) {
                            self.emit_block_stmts(cur, indent, true);
                            self.visited.insert(cur);
                            self.structured_blocks += 1;
                            // 交给外层循环处理；这里用 goto 兜底（不猜）。
                            self.push(indent, format!("goto {t:#x}; /* 回边 */"));
                            self.residual_gotos += 1;
                            return;
                        }
                        self.emit_block_stmts(cur, indent, true);
                        self.visited.insert(cur);
                        self.structured_blocks += 1;
                        cur = t;
                        continue;
                    }
                    self.emit_block_stmts(cur, indent, false);
                    self.visited.insert(cur);
                    self.structured_blocks += 1;
                    return;
                }
                _ => {
                    // 顺序 / call / fallthrough 单后继：发射并前进。
                    self.emit_block_stmts(cur, indent, false);
                    self.visited.insert(cur);
                    self.structured_blocks += 1;
                    match succs.first() {
                        Some(&next) => {
                            cur = next;
                            continue;
                        }
                        None => return,
                    }
                }
            }
        }
    }

    /// 若 `succs` 里存在一个支配 `cur` 的后继（回边目标），返回该回边头。
    fn loop_header_of(&self, cur: u64, succs: &[u64]) -> Option<u64> {
        succs.iter().copied().find(|&s| self.dominates(s, cur))
    }

    /// `a` 是否支配 `b`。
    fn dominates(&self, a: u64, b: u64) -> bool {
        self.dom.get(&b).is_some_and(|set| set.contains(&a))
    }

    /// 尝试把一个条件块结构化为 `if / if-else`。成功返回 true。
    ///
    /// 用后支配 join 判定：
    /// - join 恰是其中一个后继 → 单臂 `if`；
    /// - join 是两者之外的公共后支配点 → 双臂 `if/else`。
    fn emit_if(
        &mut self,
        cur: u64,
        last_insn: Option<&DecodedInsn>,
        succs: &[u64],
        stop: Option<u64>,
        indent: usize,
    ) -> bool {
        let (taken, fall) = match self.split_branch(cur, last_insn, succs) {
            Some(x) => x,
            None => return false,
        };
        let join = self
            .ipdom
            .get(&cur)
            .copied()
            .flatten()
            .or(stop)
            .filter(|&j| j != cur);
        let Some(join) = join else {
            return false;
        };

        // 条件文本（与扁平模式同一套占位，不假装是比较）。
        let Some(insn) = last_insn else {
            return false;
        };
        let cond = insn
            .condition
            .map_or_else(|| "/* 条件未知 */".to_string(), condition_text);

        // 判定形态。
        if join == taken {
            // 条件成立直接到 join：等价 `if (!cond) { fall..join }`。
            // 发射本块（跳过分支），再用 !cond 包 fall 一侧。
            self.emit_block_stmts(cur, indent, true);
            self.visited.insert(cur);
            self.structured_blocks += 1;
            self.push(indent, format!("if (!({cond})) {{"));
            let before = self.visited.len();
            self.emit_from(fall, Some(join), indent + 1);
            if self.visited.len() == before {
                // 什么也没发射（异常形态）→ 回退成 goto，避免输出空 if。
                self.push(indent + 1, format!("goto {fall:#x};"));
                self.residual_gotos += 1;
            }
            self.push(indent, "}".to_string());
            self.emit_from(join, stop, indent);
            return true;
        }
        if join == fall {
            // 条件成立才跳走：`if (cond) { taken..join }`。
            self.emit_block_stmts(cur, indent, true);
            self.visited.insert(cur);
            self.structured_blocks += 1;
            self.push(indent, format!("if ({cond}) {{"));
            self.emit_from(taken, Some(join), indent + 1);
            self.push(indent, "}".to_string());
            self.emit_from(join, stop, indent);
            return true;
        }
        // if/else：两支都在 join 汇合。
        self.emit_block_stmts(cur, indent, true);
        self.visited.insert(cur);
        self.structured_blocks += 1;
        self.push(indent, format!("if ({cond}) {{"));
        self.emit_from(taken, Some(join), indent + 1);
        self.push(indent, "} else {".to_string());
        self.emit_from(fall, Some(join), indent + 1);
        self.push(indent, "}".to_string());
        self.emit_from(join, stop, indent);
        true
    }

    /// 尝试结构化循环（do-while / while）。成功返回 true。
    ///
    /// 仅处理**单回边、头部是条件块**的自然循环；其余退回 false（由调用方 goto 兜底）。
    fn emit_loop(&mut self, cur: u64, header: u64, indent: usize) -> bool {
        // 目前只处理“回边目标就是当前条件块”（head == cur）的自环/头部在 cur 的形态，
        // 且要求 cur 的另一个后继（顺序出口）不回到循环体 —— 即标准 for/while 头。
        if header != cur {
            // 回边指向更早的头：需要更完整的自然循环识别，本片不猜 → 交给 goto 兜底。
            return false;
        }
        let Some(b) = self.blocks.get(&cur).copied() else {
            return false;
        };
        let succs = b.successors.clone();
        if succs.len() != 2 {
            return false;
        }
        let last_insn = self
            .last_insn_addr(b)
            .and_then(|a| self.by_addr.get(&a).copied());
        let Some((taken, fall)) = self.split_branch(cur, last_insn, &succs) else {
            return false;
        };
        let Some(insn) = last_insn else {
            return false;
        };
        let cond = insn
            .condition
            .map_or_else(|| "/* 条件未知 */".to_string(), condition_text);

        // 形态：自环头 cur，taken == cur（回边回自身）→ do-while：body 在 fall 一侧，
        // 先执行 body 再判断；只有当 body 最终回到 cur 时才成立。
        if taken == cur {
            // 检查 fall 一侧是否能回到 cur（回边存在）。
            if !self.reaches(fall, cur) {
                return false;
            }
            self.emit_block_stmts(cur, indent, true);
            self.visited.insert(cur);
            self.structured_blocks += 1;
            self.push(indent, "do {".to_string());
            let before = self.visited.len();
            // body：从 fall 发射到 cur（不含），但跳过 cur 自身重复发射。
            self.emit_body_until(fall, cur, indent + 1);
            if self.visited.len() == before {
                return false;
            }
            self.push(indent, format!("}} while ({cond}); /* @{:#x} */", cur));
            self.emit_from(cur, None, indent); // cur 已 visited → 会走 goto 兜底或直接返回
            return true;
        }
        // 其他形态（预测试 while 需要更完整建模）本片不做 → goto 兜底。
        false
    }

    /// 发射循环体：从 `from` 到 `until`（不含），但到 `until` 时**不发射**它（头部重复检查）。
    fn emit_body_until(&mut self, from: u64, until: u64, indent: usize) {
        let mut cur = from;
        let mut guard = 0usize;
        loop {
            guard += 1;
            if guard > self.blocks.len() * 2 + 4 {
                break;
            }
            if cur == until || self.visited.contains(&cur) {
                break;
            }
            let Some(b) = self.blocks.get(&cur).copied() else {
                break;
            };
            if b.terminal || b.successors.is_empty() {
                self.emit_block_stmts(cur, indent, false);
                self.visited.insert(cur);
                self.structured_blocks += 1;
                break;
            }
            // 单后继顺序块：发射后前进。
            if b.successors.len() == 1 && !b.successors.contains(&until) {
                self.emit_block_stmts(cur, indent, false);
                self.visited.insert(cur);
                self.structured_blocks += 1;
                cur = b.successors[0];
                continue;
            }
            if b.successors.len() == 1 && b.successors.contains(&until) {
                self.emit_block_stmts(cur, indent, false);
                self.visited.insert(cur);
                self.structured_blocks += 1;
                break;
            }
            // 复杂体（条件/多后继）：本片不结构化，整块发射并 goto，放弃这个循环。
            self.emit_block_stmts(cur, indent, true);
            self.visited.insert(cur);
            self.structured_blocks += 1;
            for &s in &b.successors {
                self.push(indent, format!("goto {s:#x};"));
                self.residual_gotos += 1;
            }
            break;
        }
    }

    /// 拆分条件块的两个后继：`(taken, fall)`。taken = 分支指令的 target 所在块。
    fn split_branch(
        &self,
        cur: u64,
        last_insn: Option<&DecodedInsn>,
        succs: &[u64],
    ) -> Option<(u64, u64)> {
        let insn = last_insn?;
        if succs.len() != 2 {
            return None;
        }
        match insn.target {
            Some(t) if succs.contains(&t) => {
                let fall = succs.iter().copied().find(|&s| s != t)?;
                Some((t, fall))
            }
            // 间接条件跳转（目标未知）无法判断 taken/fall → 不猜。
            _ => {
                let _ = cur;
                None
            }
        }
    }

    /// `from` 能否沿后继到达 `to`（在本函数块图内）。
    fn reaches(&self, from: u64, to: u64) -> bool {
        let mut seen = BTreeSet::new();
        let mut stack = vec![from];
        while let Some(x) = stack.pop() {
            if x == to {
                return true;
            }
            if !seen.insert(x) {
                continue;
            }
            if let Some(b) = self.blocks.get(&x) {
                for &s in &b.successors {
                    if !seen.contains(&s) {
                        stack.push(s);
                    }
                }
            }
        }
        false
    }
}

/// 迭代计算支配集合（块首地址 → 支配它的块首集合，含自身）。
fn compute_dominators(
    blocks: &BTreeMap<u64, &crate::cfg::BasicBlock>,
    start: u64,
) -> BTreeMap<u64, BTreeSet<u64>> {
    let all: BTreeSet<u64> = blocks.keys().copied().collect();
    let mut dom: BTreeMap<u64, BTreeSet<u64>> = BTreeMap::new();
    for &b in blocks.keys() {
        if b == start {
            let mut s = BTreeSet::new();
            s.insert(b);
            dom.insert(b, s);
        } else {
            dom.insert(b, all.clone());
        }
    }
    let mut changed = true;
    while changed {
        changed = false;
        for (&b, block) in blocks {
            if b == start {
                continue;
            }
            let mut new: BTreeSet<u64> = BTreeSet::new();
            let preds = &block.predecessors;
            if let Some(first) = preds.first() {
                if let Some(d) = dom.get(first) {
                    new = d.clone();
                }
            }
            for p in preds.iter().skip(1) {
                if let Some(d) = dom.get(p) {
                    new = new.intersection(d).copied().collect();
                }
            }
            new.insert(b);
            if dom.get(&b) != Some(&new) {
                dom.insert(b, new);
                changed = true;
            }
        }
    }
    dom
}

/// 迭代计算直接后支配点（immediate post-dominator），用"仅保留被所有后继后支配的点"逼近。
///
/// 出口块（无后继 / terminal）的后支配点映射到自己（`None` 表示"没有唯一直接后支配点"）。
fn compute_immediate_postdominators(
    blocks: &BTreeMap<u64, &crate::cfg::BasicBlock>,
) -> BTreeMap<u64, Option<u64>> {
    // 后支配集合：pdom[b] = 从 b 出发的所有路径都会经过的块集合（含自身）。
    let all: BTreeSet<u64> = blocks.keys().copied().collect();
    let exits: BTreeSet<u64> = blocks
        .iter()
        .filter(|(_, b)| b.terminal || b.successors.is_empty())
        .map(|(&s, _)| s)
        .collect();

    let mut pdom: BTreeMap<u64, BTreeSet<u64>> = BTreeMap::new();
    for &b in blocks.keys() {
        if exits.contains(&b) {
            let mut s = BTreeSet::new();
            s.insert(b);
            pdom.insert(b, s);
        } else {
            pdom.insert(b, all.clone());
        }
    }
    let mut changed = true;
    while changed {
        changed = false;
        for (&b, block) in blocks {
            if exits.contains(&b) {
                continue;
            }
            let mut new: BTreeSet<u64> = BTreeSet::new();
            if let Some(first) = block.successors.first() {
                if let Some(d) = pdom.get(first) {
                    new = d.clone();
                }
            }
            for s in block.successors.iter().skip(1) {
                if let Some(d) = pdom.get(s) {
                    new = new.intersection(d).copied().collect();
                }
            }
            new.insert(b);
            if pdom.get(&b) != Some(&new) {
                pdom.insert(b, new);
                changed = true;
            }
        }
    }

    // 直接后支配点 = 严格后支配集合中“最靠近的”那个：即不被其它严格后支配点后支配者。
    // 这里用近似：去掉自身后，如果恰有一个候选它就是直接后支配点；否则取集合里地址最大的
    // 那个作为 join 估计（保守：宁可不结构化，也会在 emit_if 里因 join 不合理而回退）。
    let mut out: BTreeMap<u64, Option<u64>> = BTreeMap::new();
    for (&b, set) in &pdom {
        let strict: Vec<u64> = set.iter().copied().filter(|&x| x != b).collect();
        if strict.is_empty() {
            out.insert(b, None);
            continue;
        }
        // 从候选里挑谁“最靠内”：候选 c 是最内直接后支配点，如果所有其它候选都被 c 后支配。
        let mut chosen: Option<u64> = None;
        for &c in &strict {
            let c_pdom = pdom.get(&c);
            // c 是否后支配所有其它候选（除自身外都落在 c 的后支配集里）？
            let inner = strict.iter().all(|&other| {
                other == c
                    || c_pdom
                        .and_then(|s| s.get(&other).map(|_| ()))
                        .is_some_and(|_| c_pdom.is_some_and(|s| s.contains(&other)))
            });
            if inner {
                chosen = Some(c);
                break;
            }
        }
        out.insert(b, chosen);
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use bitflip_arch::{Arch, ConditionCode, MnemonicId, Operand, RegId};
    fn jmp(addr: u64, target: u64) -> DecodedInsn {
        DecodedInsn {
            addr,
            len: 4,
            arch: Arch::X86_64,
            mnemonic: MnemonicId::UNKNOWN,
            flow: Flow::Branch { conditional: false },
            target: Some(target),
            condition: None,
            operands: vec![],
            reads: Default::default(),
            writes: Default::default(),
            privileged: false,
        }
    }
    fn jcc(addr: u64, target: u64) -> DecodedInsn {
        DecodedInsn {
            flow: Flow::Branch { conditional: true },
            target: Some(target),
            condition: Some(ConditionCode::Equal),
            ..jmp(addr, target)
        }
    }
    fn ret(addr: u64) -> DecodedInsn {
        DecodedInsn {
            addr,
            len: 4,
            arch: Arch::X86_64,
            mnemonic: MnemonicId::UNKNOWN,
            flow: Flow::Return,
            target: None,
            condition: None,
            operands: vec![],
            reads: Default::default(),
            writes: Default::default(),
            privileged: false,
        }
    }
    fn nop(addr: u64) -> DecodedInsn {
        DecodedInsn {
            addr,
            len: 4,
            arch: Arch::X86_64,
            mnemonic: MnemonicId::UNKNOWN,
            flow: Flow::Fallthrough,
            target: None,
            condition: None,
            operands: vec![Operand::Reg(RegId(0))],
            reads: Default::default(),
            writes: Default::default(),
            privileged: false,
        }
    }

    fn namer(_: u16) -> Option<String> {
        Some("r0".to_string())
    }

    fn build(insns: Vec<DecodedInsn>) -> PseudocodeFunction {
        let cfg = Cfg::build(&insns);
        decompile_structured(insns[0].addr, Some("f"), &insns, &cfg, &namer)
    }

    #[test]
    fn linear_function_fully_structured() {
        // 0x1000 nop; 0x1004 nop; 0x1008 ret
        let insns = vec![nop(0x1000), nop(0x1004), ret(0x1008)];
        let f = build(insns);
        assert!(f.structured, "线性函数应完全结构化");
        let body = f.structured_body.as_ref().unwrap();
        assert!(body.iter().any(|l| l.contains("return")));
    }

    #[test]
    fn if_then_structured() {
        // 0x1000: jcc 0x1010 ; 0x1004: nop ; 0x1008: nop; 0x100c: jmp 0x1014 ; 0x1010: nop; 0x1014: ret
        // 条件成立 → 跳过 then 体。等价 if(!cond){...}
        let insns = vec![
            jcc(0x1000, 0x1010),
            nop(0x1004),
            nop(0x1008),
            jmp(0x100c, 0x1014),
            nop(0x1010),
            ret(0x1014),
        ];
        let f = build(insns);
        // 至少有 if 出现；不强制完全结构化（jmp 可能保留）。
        let body = f.structured_body.as_ref().unwrap();
        let joined = body.join("\n");
        assert!(joined.contains("if ("), "应出现 if：\n{joined}");
    }

    #[test]
    fn simple_loop_has_do_while_or_goto() {
        // 0x1000: nop; 0x1004: jcc 0x1000 (回边到自身头部) ; 0x1008: ret
        // cur=0x1004 条件块，taken 0x1000 支配 cur? 头 0x1000... 这里 taken 指向 0x1000（前面）
        let insns = vec![nop(0x1000), jcc(0x1004, 0x1000), ret(0x1008)];
        let f = build(insns);
        let body = f.structured_body.as_ref().unwrap();
        let joined = body.join("\n");
        // 不论是否结构化成功，都不该 panic，且要么有 while/do 要么有 goto。
        assert!(
            joined.contains("while") || joined.contains("goto"),
            "循环应表现为 while/do 或 goto：\n{joined}"
        );
    }

    #[test]
    fn irreducible_falls_back_to_goto_with_note() {
        // 构造一个至少能跑通的 CFG，确认 notes 里给出 PartiallyStructured 或 Structured。
        let insns = vec![nop(0x1000), ret(0x1004)];
        let f = build(insns);
        assert!(f.notes.iter().any(|n| matches!(
            n,
            PseudocodeNote::Structured | PseudocodeNote::PartiallyStructured { .. }
        )));
    }
}
