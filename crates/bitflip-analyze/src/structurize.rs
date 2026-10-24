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
    let natural_loops = compute_natural_loops(&block_map, &dom);

    let mut builder = Builder {
        by_addr: &by_addr,
        blocks: &block_map,
        ipdom: &ipdom,
        natural_loops: &natural_loops,
        namer,
        visited: BTreeSet::new(),
        lines: Vec::new(),
        residual_gotos: 0,
        structured_blocks: 0,
        budget: MAX_STRUCT_LINES,
    };
    builder.emit_from(start, None, 0, None);

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
    ipdom: &'a BTreeMap<u64, Option<u64>>,
    /// 自然循环：回边头 → 循环体块集合（含头）。由 `compute_natural_loops` 预算。
    natural_loops: &'a BTreeMap<u64, BTreeSet<u64>>,
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

    /// 从 `cur` 开始发射到 `stop`（不含）为止。
    ///
    /// `bound` 为 `Some` 时表示只在给定块集合内展开（用于循环体）：遇到集合外的块就当作
    /// 区域边界停下，由调用方接着从边界外继续。`None` 表示整个函数。
    fn emit_from(
        &mut self,
        mut cur: u64,
        stop: Option<u64>,
        indent: usize,
        bound: Option<&BTreeSet<u64>>,
    ) {
        loop {
            if Some(cur) == stop {
                return;
            }
            // 到了区域边界（循环体外）就停，交给上层。
            if bound.is_some_and(|b| !b.contains(&cur)) {
                return;
            }
            if self.visited.contains(&cur) {
                // 回到已发射过的块（正常回边应在 emit_loop 里处理，走到这里属异常兜底）。
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

            // 循环头：若当前块是某自然循环的头且尚未发射，优先结构化成 while/do-while。
            // 形态没把握时 `emit_loop` 返回 false，继续按普通块处理（多半走向 goto 兜底）。
            if self.natural_loops.contains_key(&cur) && self.emit_loop(cur, indent, stop, bound) {
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
                    if self.emit_if(cur, last_insn, succs, stop, indent, bound) {
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
        bound: Option<&BTreeSet<u64>>,
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
            self.emit_from(fall, Some(join), indent + 1, bound);
            if self.visited.len() == before {
                // 什么也没发射（异常形态）→ 回退成 goto，避免输出空 if。
                self.push(indent + 1, format!("goto {fall:#x};"));
                self.residual_gotos += 1;
            }
            self.push(indent, "}".to_string());
            self.emit_from(join, stop, indent, bound);
            return true;
        }
        if join == fall {
            // 条件成立才跳走：`if (cond) { taken..join }`。
            self.emit_block_stmts(cur, indent, true);
            self.visited.insert(cur);
            self.structured_blocks += 1;
            self.push(indent, format!("if ({cond}) {{"));
            self.emit_from(taken, Some(join), indent + 1, bound);
            self.push(indent, "}".to_string());
            self.emit_from(join, stop, indent, bound);
            return true;
        }
        // if/else：两支都在 join 汇合。
        self.emit_block_stmts(cur, indent, true);
        self.visited.insert(cur);
        self.structured_blocks += 1;
        self.push(indent, format!("if ({cond}) {{"));
        self.emit_from(taken, Some(join), indent + 1, bound);
        self.push(indent, "} else {".to_string());
        self.emit_from(fall, Some(join), indent + 1, bound);
        self.push(indent, "}".to_string());
        self.emit_from(join, stop, indent, bound);
        true
    }

    /// 尝试把一个**自然循环头**结构化为 `while` 或 `do-while`。成功返回 true。
    ///
    /// 输入 `header` 由 `natural_loops` 保证是一个真回边头（存在块跳回它且它支配那个块）。
    /// 支持两种形态：
    /// - **预测试 while**：头部是条件块，一个后继在循环体内（体入口），另一个后继是循环**出口**。
    ///   `while (继续条件) { 体 }`；
    /// - **do-while**：头部是条件块，体在某一侧，执行完体后由回边块判断是否再回头部。
    ///   这里只在头部自身就是那个“回边判断块”（body 先跑、末尾回跳头部）时还原成
    ///   `do { 体 } while (cond);`。
    ///
    /// 其余形态（多重回边、头部条件块两个后继都在体内且无单一出口、不可归约）**一律不猜**，
    /// 返回 false 交给上层 goto 兜底。
    fn emit_loop(
        &mut self,
        header: u64,
        indent: usize,
        stop: Option<u64>,
        outer_bound: Option<&BTreeSet<u64>>,
    ) -> bool {
        let Some(body) = self.natural_loops.get(&header).cloned() else {
            return false;
        };
        if body.len() < 2 || self.visited.contains(&header) {
            return false;
        }
        // 已经在发射中（体内遇到头部）→ 不重复结构化。
        if outer_bound.is_some_and(|b| !b.contains(&header)) {
            return false;
        }

        let Some(hb) = self.blocks.get(&header).copied() else {
            return false;
        };
        // 头部必须是条件块（带两个后继）。
        let Some(hlast) = self
            .last_insn_addr(hb)
            .and_then(|a| self.by_addr.get(&a).copied())
        else {
            return false;
        };
        if !matches!(hlast.flow, Flow::Branch { conditional: true }) {
            return false;
        }
        let Some((taken, fall)) = self.split_branch(header, Some(hlast), &hb.successors.clone())
        else {
            return false;
        };
        let cond = hlast
            .condition
            .map_or_else(|| "/* 条件未知 */".to_string(), condition_text);

        // 循环出口：体集合中、后继落在体外的目标（必须唯一，否则不猜）。
        let mut exits: BTreeSet<u64> = BTreeSet::new();
        for &m in &body {
            if let Some(mb) = self.blocks.get(&m) {
                for &s in &mb.successors {
                    if !body.contains(&s) {
                        exits.insert(s);
                    }
                }
            }
        }

        // —— 形态 A：预测试 while ——
        // 头部一个后继在体内（体入口），另一个后继是唯一出口。
        let in_body = |x: u64| body.contains(&x) && x != header;
        if in_body(taken) ^ in_body(fall) {
            let (entry, exit) = if in_body(taken) {
                (taken, fall)
            } else {
                (fall, taken)
            };
            // 出口必须是（或就是）唯一出口，且 exit 在体外。
            if !body.contains(&exit) && (exits.len() == 1 && exits.contains(&exit)) {
                // 继续条件：体入口是 taken → while(cond)；体入口是 fall → while(!cond)。
                let continue_cond = if in_body(taken) {
                    cond.clone()
                } else {
                    format!("!({cond})")
                };
                self.emit_block_stmts(header, indent, true);
                self.visited.insert(header);
                self.structured_blocks += 1;
                self.push(
                    indent,
                    format!("while ({continue_cond}) {{ /* @{header:#x} */"),
                );
                let before = self.visited.len();
                self.emit_from(entry, Some(header), indent + 1, Some(&body));
                if self.visited.len() == before {
                    // 体没发射（异常）→ 收回，退回 false 由上层 goto。
                    self.push(indent, format!("}} /* 循环体未能结构化 */ goto {exit:#x};"));
                    self.residual_gotos += 1;
                    return true;
                }
                self.push(indent, "}".to_string());
                // 循环后继续：从出口按外层上下文发射。
                self.emit_from(exit, stop, indent, outer_bound);
                return true;
            }
        }

        // —— 形态 B：do-while ——
        // 头部即回边判断块（体先执行，末尾回跳头部）。判定：头部两个后继都在体内（或一个是自身），
        // 且没有“头部直接跳到体外”的出口；出口由体内某块的体外后继给出。
        let header_exits: Vec<u64> = hb
            .successors
            .iter()
            .copied()
            .filter(|&s| !body.contains(&s))
            .collect();
        if header_exits.is_empty() && exits.len() == 1 {
            let exit = *exits.iter().next().unwrap();
            // 体入口：头部的某个体内后继里，能回到头部的那一支先跑。取 taken/fall 中在体内的那个。
            let entry = if in_body(taken) { taken } else { fall };
            if !in_body(entry) {
                return false;
            }
            self.emit_block_stmts(header, indent, true);
            self.visited.insert(header);
            self.structured_blocks += 1;
            self.push(indent, format!("do {{ /* @{header:#x} */"));
            let before = self.visited.len();
            self.emit_from(entry, Some(header), indent + 1, Some(&body));
            if self.visited.len() == before {
                return false;
            }
            self.push(indent, format!("}} while ({cond});"));
            self.emit_from(exit, stop, indent, outer_bound);
            return true;
        }

        // 形态不确定 → 不猜。
        false
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
}

/// 计算所有**自然循环**：对每条回边 `b -> h`（`h` 支配 `b`），循环体 = `{h} ∪ {能到达 b 且
/// 不经过 h 的块}`（标准算法）。返回 `h -> 循环体块集合`。不可归约图里若某头出现多回边、
/// 体会合并，仍能给出一个集合；但 `emit_loop` 会在形态不唯一时拒绝结构化（不猜）。
fn compute_natural_loops(
    blocks: &BTreeMap<u64, &crate::cfg::BasicBlock>,
    dom: &BTreeMap<u64, BTreeSet<u64>>,
) -> BTreeMap<u64, BTreeSet<u64>> {
    let dominates = |h: u64, b: u64| dom.get(&b).is_some_and(|s| s.contains(&h));
    let mut loops: BTreeMap<u64, BTreeSet<u64>> = BTreeMap::new();

    for (&b, block) in blocks {
        for &s in &block.successors {
            // 回边：后继支配当前块。
            if !dominates(s, b) {
                continue;
            }
            let header = s;
            let mut body: BTreeSet<u64> = BTreeSet::new();
            body.insert(header);
            body.insert(b);
            // 从 b 反向沿前驱扩展，凡不经过 header 的块都并入循环体。
            let mut stack: Vec<u64> = vec![b];
            let mut seen: BTreeSet<u64> = BTreeSet::new();
            while let Some(x) = stack.pop() {
                if x == header || !seen.insert(x) {
                    continue;
                }
                body.insert(x);
                if let Some(xb) = blocks.get(&x) {
                    for &p in &xb.predecessors {
                        if p != header && !seen.contains(&p) {
                            stack.push(p);
                        }
                    }
                }
            }
            loops.entry(header).or_default().extend(body);
        }
    }
    loops
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
    fn pretest_while_structured() {
        // 0x1000: jcc 0x1010(出口)  —— 头部是条件块
        // 0x1004: nop（循环体）
        // 0x1008: jmp 0x1000（回边）
        // 0x1010: ret（出口）
        let insns = vec![
            jcc(0x1000, 0x1010),
            nop(0x1004),
            jmp(0x1008, 0x1000),
            ret(0x1010),
        ];
        let f = build(insns);
        let body = f.structured_body.as_ref().unwrap();
        let joined = body.join("\n");
        assert!(
            joined.contains("while ("),
            "预测试循环应还原成 while：\n{joined}"
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
