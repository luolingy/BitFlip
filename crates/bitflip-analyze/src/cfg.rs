//! 基本块与控制流图（M5）。
//!
//! # 为什么这个模块单独存在
//!
//! CFG 是"函数内控制流"的唯一结构化表示，函数级信息（可达性、循环、
//! 分支复杂度）都从它派生。它同时是**最容易被做对一半**的东西：
//! 只按顺序切块的实现能跑、能显示、看起来正常，只是每条跳转都少了边。
//!
//! # 三条容易做错的规则
//!
//! 1. **块的划分点是"跳转目标"和"跳转的下一条"，不只是"跳转本身"。**
//!    被跳到的地址必须自己开一个块，否则跳转边会指向块的中间，
//!    后继关系就失真了。
//! 2. **`call` 不结束基本块。** 调用会返回，控制继续往下走。
//!    把 call 当终结符会把一个块切成两个，块数虚高、循环判断跟着错。
//! 3. **条件跳转有两个后继**（目标 + 顺序），无条件跳转只有一个。
//!    这里**不**用助记符文本判断，用 [`bitflip_arch::Flow`] 的结构化语义 ——
//!    架构差异（x86 的 `je` vs AArch64 的 `b.eq`）由 `bitflip-arch` 吸收，
//!    本模块对所有架构走同一条代码路径（M5 验收标准 3）。
//!
//! # 边界未知时怎么办
//!
//! 函数的 `end` 可能是 `None`（只知道入口）。此时**不猜**边界：
//! 只用落在该函数已知指令集合里的指令建图，并在 `truncated` 里如实标出。
//! 猜一个边界会把下一个函数的指令并进来，产出一张"看起来完整"的假图。

use std::collections::{BTreeMap, BTreeSet};

use bitflip_arch::{DecodedInsn, Flow};

/// 一个基本块：一段**连续**的、单入口单出口的指令序列。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BasicBlock {
    /// 块首地址（含）。
    pub start: u64,
    /// 块尾地址（不含）—— 即"最后一条指令的下一条"。
    pub end: u64,
    /// 块内最后一条指令的地址。
    ///
    /// 与 `end` 分开是因为两者语义不同：`end` 是区间边界，
    /// `last_insn` 才是"从哪条指令跳出去的"。对长度为 0 的空块二者不同。
    pub last_insn: u64,
    /// 后继块首地址（去重、升序）。
    pub successors: Vec<u64>,
    /// 前驱块首地址（去重、升序）。
    pub predecessors: Vec<u64>,
    /// 块是否以"不返回"结束（`ret` / 陷阱 / 无目标的间接跳转）。
    ///
    /// 为真时块没有顺序后继。这是**结论**不是猜测：`ret` 一定不往下走。
    pub terminal: bool,
}

impl BasicBlock {
    /// 块内字节数。
    #[must_use]
    pub const fn size(&self) -> u64 {
        self.end.saturating_sub(self.start)
    }

    /// 块是否包含该地址。
    #[must_use]
    pub const fn contains(&self, addr: u64) -> bool {
        addr >= self.start && addr < self.end
    }
}

/// 一张函数内的控制流图。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Cfg {
    /// 块首地址 → 块。`BTreeMap` 保证遍历顺序稳定（快照可复现）。
    blocks: BTreeMap<u64, BasicBlock>,
    /// 建图时是否有信息缺失（如函数边界未知）。
    truncated: bool,
    /// 缺失原因（面向用户，中文）。
    notes: Vec<String>,
}

impl Cfg {
    /// 建图：从已解码指令序列构造基本块与边。
    ///
    /// `insns` 必须是**同一函数内**、按地址升序、互不重叠的指令。
    /// 调用方负责按函数切分（本模块不猜函数边界）。
    #[must_use]
    pub fn build(insns: &[DecodedInsn]) -> Self {
        let mut notes = Vec::new();

        if insns.is_empty() {
            return Self {
                blocks: BTreeMap::new(),
                truncated: false,
                notes,
            };
        }

        // 指令地址集合：用于判断"跳转目标是否落在本函数的指令上"。
        let insn_addrs: BTreeSet<u64> = insns.iter().map(|i| i.addr).collect();

        // 第一步：找所有块首。
        //
        // 入口指令必然是块首；此外每个跳转的目标、跳转的下一条、
        // 以及**任何控制转移指令之后的那条**也是块首。
        // 漏掉"跳转目标"会让边指向块的内部；漏掉"跳转的下一条"
        // 会让不可达的指令混进前一个块，于是那个块的出口边
        // 由错误的指令决定。
        let mut leaders: BTreeSet<u64> = BTreeSet::new();
        leaders.insert(insns[0].addr);

        for insn in insns {
            let next = insn.addr + u64::from(insn.len);
            match insn.flow {
                Flow::Branch { .. } => {
                    // 目标若落在本函数指令上，是块首。
                    // 落在函数外（尾调用/跨函数跳转）时**不**建块首 ——
                    // 那个块不属于本函数，建出来会凭空多一个孤立块。
                    if let Some(target) = insn.target {
                        if insn_addrs.contains(&target) {
                            leaders.insert(target);
                        } else if target != next {
                            // 目标既不在本函数内、又不是顺序后继：
                            // 这是一次跳出去的控制转移，如实记一笔。
                            notes.push(format!(
                                "跳转目标 {target:#x} 不在本函数的已知指令内，未建块（可能是尾调用或跨函数跳转）"
                            ));
                        }
                    }
                    // 条件跳转有顺序后继，它也是块首。
                    if matches!(insn.flow, Flow::Branch { conditional: true })
                        && insn_addrs.contains(&next)
                    {
                        leaders.insert(next);
                    }
                    // 无条件跳转之后的指令不可达（除非别处跳过来，那条路径
                    // 会通过"目标"把它标成块首）。**不能在它前面切掉这一刀
                    // 就完事** —— 若不切，它会并进本块，使本块的"最后一条
                    // 指令"变成它，本块真正的出口边（那条 jmp）就丢了。
                    //
                    // 这正是本模块最容易写错的地方：`jmp A; jmp B` 这种
                    // 布局下，块的出口是**第一条** jmp，不是第二条。
                    if !matches!(insn.flow, Flow::Branch { conditional: true })
                        && insn_addrs.contains(&next)
                    {
                        leaders.insert(next);
                    }
                }
                // ret / trap 之后的指令同样不可达，也切一刀。
                Flow::Return | Flow::Trap if insn_addrs.contains(&next) => {
                    leaders.insert(next);
                }
                // call **不**产生块首：调用会返回，控制继续往下。
                _ => {}
            }
        }

        // 第二步：按块首切段，每段是一个块。
        let addrs: Vec<u64> = insns.iter().map(|i| i.addr).collect();
        let mut blocks: BTreeMap<u64, BasicBlock> = BTreeMap::new();

        for (idx, &addr) in addrs.iter().enumerate() {
            if !leaders.contains(&addr) {
                continue;
            }
            // 块在本函数指令序列里的结束位置：下一个块首（或序列末尾）。
            let mut last = idx;
            for (j, &probe) in addrs.iter().enumerate().skip(idx + 1) {
                if leaders.contains(&probe) {
                    break;
                }
                last = j;
            }
            let insn = &insns[last];
            let end = insn.addr + u64::from(insn.len);
            blocks.insert(
                addr,
                BasicBlock {
                    start: addr,
                    end,
                    last_insn: insn.addr,
                    successors: Vec::new(),
                    predecessors: Vec::new(),
                    terminal: false,
                },
            );
        }

        // 第三步：连边。**只看块的最后一条指令** —— 块中间不可能有控制转移，
        // 因为任何跳转都会成为块首（第一步保证了这一点）。
        let mut edges: Vec<(u64, u64)> = Vec::new();
        let starts: Vec<u64> = blocks.keys().copied().collect();

        // 先收集 (块首, 块尾指令) —— 遍历 `blocks` 的同时要写 `blocks`
        // （标记 terminal），所以先把需要的信息拷出来。
        let tails: Vec<(u64, u64)> = blocks.iter().map(|(&s, b)| (s, b.last_insn)).collect();

        for (start, last_insn) in tails {
            let Some(idx) = addrs.iter().position(|&a| a == last_insn) else {
                continue;
            };
            let insn = &insns[idx];
            let next = insn.addr + u64::from(insn.len);

            match insn.flow {
                Flow::Branch { conditional } => {
                    let mut succ: Vec<u64> = Vec::new();
                    if let Some(target) = insn.target {
                        if blocks.contains_key(&target) {
                            succ.push(target);
                        }
                    }
                    if conditional && blocks.contains_key(&next) {
                        succ.push(next);
                    }
                    if succ.is_empty() {
                        // 所有后继都在本函数之外：这个块是图的出口，
                        // 但它不是 `ret`（是跳出去），所以不标 terminal。
                        notes.push(format!(
                            "{last_insn:#x} 的跳转目标不在本函数内，该块没有已知后继"
                        ));
                    }
                    for to in succ {
                        edges.push((start, to));
                    }
                }
                Flow::Call => {
                    // 调用不结束块，顺序后继就是下一条。
                    // 走到这里说明块尾恰好是 call —— 只有在"call 后面
                    // 没有任何指令"（函数末尾的调用且无 ret）时才会发生。
                    if blocks.contains_key(&next) {
                        edges.push((start, next));
                    }
                }
                Flow::Fallthrough => {
                    if blocks.contains_key(&next) {
                        edges.push((start, next));
                    }
                }
                Flow::Return | Flow::Trap => {
                    // 没有后继。标记为终结块。
                    if let Some(b) = blocks.get_mut(&start) {
                        b.terminal = true;
                    }
                }
                Flow::Unknown => {
                    // 语义未知：**不猜**有没有后继。如实记一笔。
                    notes.push(format!("{last_insn:#x} 的控制流语义未知，未连边"));
                }
            }
        }

        // 第四步：写回后继/前驱（去重升序）。
        for (from, to) in edges {
            if let Some(b) = blocks.get_mut(&from) {
                if !b.successors.contains(&to) {
                    b.successors.push(to);
                }
            }
            if let Some(b) = blocks.get_mut(&to) {
                if !b.predecessors.contains(&from) {
                    b.predecessors.push(from);
                }
            }
        }
        for b in blocks.values_mut() {
            b.successors.sort_unstable();
            b.predecessors.sort_unstable();
        }

        // 落到序列末尾的块，若最后一条不是终结指令且没有后继，
        // 说明函数边界未知，块被截断了。如实标注（不猜它的后继）。
        let truncated = if let Some(&last_start) = starts.last() {
            blocks
                .get(&last_start)
                .is_some_and(|b| !b.terminal && b.successors.is_empty())
        } else {
            false
        };
        if truncated {
            notes.push(
                "函数末尾的控制流未闭合（边界未知或末尾是跳转），最后一个块的后继不完整"
                    .to_string(),
            );
        }

        Self {
            blocks,
            truncated,
            notes,
        }
    }

    /// 块数量。
    #[must_use]
    pub fn block_count(&self) -> usize {
        self.blocks.len()
    }

    /// 按地址顺序遍历块。
    pub fn blocks(&self) -> impl Iterator<Item = &BasicBlock> {
        self.blocks.values()
    }

    /// 取某个地址所在的块。
    #[must_use]
    pub fn block_containing(&self, addr: u64) -> Option<&BasicBlock> {
        self.blocks.values().find(|b| b.contains(addr))
    }

    /// 块首地址列表（升序）。
    #[must_use]
    pub fn block_starts(&self) -> Vec<u64> {
        self.blocks.keys().copied().collect()
    }

    /// 是否为空图。
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.blocks.is_empty()
    }

    /// 建图时是否有信息缺失。
    #[must_use]
    pub const fn truncated(&self) -> bool {
        self.truncated
    }

    /// 缺失说明（面向用户）。
    #[must_use]
    pub fn notes(&self) -> &[String] {
        &self.notes
    }

    /// 边数量（含重复的多重边合并后的计数）。
    #[must_use]
    pub fn edge_count(&self) -> usize {
        self.blocks.values().map(|b| b.successors.len()).sum()
    }

    /// 从入口出发可达的块首集合（含入口本身）。
    ///
    /// 图里可能有不可达块（例如块首来自一个已被覆盖的跳转目标），
    /// 它们**不代表死代码** —— 只是当前这张图里没有路径到达，
    /// 因此本方法只用于可达性判断，不用于"死代码"结论。
    #[must_use]
    pub fn reachable_from(&self, entry: u64) -> BTreeSet<u64> {
        let mut seen = BTreeSet::new();
        let Some(entry_block) = self.block_containing(entry) else {
            return seen;
        };
        let mut stack = vec![entry_block.start];
        while let Some(cur) = stack.pop() {
            if !seen.insert(cur) {
                continue;
            }
            if let Some(b) = self.blocks.get(&cur) {
                for &succ in &b.successors {
                    if !seen.contains(&succ) {
                        stack.push(succ);
                    }
                }
            }
        }
        seen
    }

    /// 图里是否存在环（回边）。循环识别的最小判据。
    #[must_use]
    pub fn has_cycle(&self) -> bool {
        // DFS 三色标记：灰色遇到灰色即成环。
        #[derive(Clone, Copy, PartialEq)]
        enum Color {
            White,
            Gray,
            Black,
        }
        let mut color: BTreeMap<u64, Color> =
            self.blocks.keys().map(|&k| (k, Color::White)).collect();

        // 迭代式 DFS，避免深图把栈打爆（大函数很常见）。
        for &root in self.blocks.keys() {
            if color[&root] != Color::White {
                continue;
            }
            let mut stack: Vec<(u64, usize)> = vec![(root, 0)];
            color.insert(root, Color::Gray);
            while let Some(&mut (node, ref mut idx)) = stack.last_mut() {
                let succs = self
                    .blocks
                    .get(&node)
                    .map(|b| b.successors.clone())
                    .unwrap_or_default();
                if *idx < succs.len() {
                    let nxt = succs[*idx];
                    *idx += 1;
                    match color.get(&nxt).copied().unwrap_or(Color::Black) {
                        Color::Gray => return true,
                        Color::White => {
                            color.insert(nxt, Color::Gray);
                            stack.push((nxt, 0));
                        }
                        Color::Black => {}
                    }
                } else {
                    color.insert(node, Color::Black);
                    stack.pop();
                }
            }
        }
        false
    }
}

/// 为一批函数入口分组建图。
///
/// `insns` 为全体指令（升序），`bounds` 为 `(entry, end)` 列表
/// （`end` 为 `None` 表示边界未知）。返回 `entry → Cfg`。
///
/// 边界未知时**不猜**：只用从 `entry` 起、到全局指令序列末尾的指令，
/// 并把 `truncated` 置真。
#[must_use]
pub fn build_functions(insns: &[DecodedInsn], bounds: &[(u64, Option<u64>)]) -> BTreeMap<u64, Cfg> {
    let mut out = BTreeMap::new();
    for &(entry, end) in bounds {
        let slice: Vec<DecodedInsn> = insns
            .iter()
            .filter(|i| {
                i.addr >= entry
                    && match end {
                        Some(e) => i.addr < e,
                        // 边界未知：只取到"下一个已知函数入口之前"由调用方
                        // 保证；这里退化为不设上界，靠 truncated 标注。
                        None => true,
                    }
            })
            .cloned()
            .collect();
        out.insert(entry, Cfg::build(&slice));
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use bitflip_arch::{Arch, ConditionCode, MnemonicId, Operand, RegSet};

    /// 造一条测试指令。真实解码器的输出字段太多，测试里逐字段构造能让
    /// "这次测的是 CFG 不是解码"这件事保持清楚。
    fn insn(addr: u64, len: u8, flow: Flow, target: Option<u64>) -> DecodedInsn {
        DecodedInsn {
            addr,
            len,
            arch: Arch::X86_64,
            mnemonic: MnemonicId(1),
            flow,
            target,
            condition: None,
            operands: Vec::<Operand>::new(),
            reads: RegSet::new(),
            writes: RegSet::new(),
            privileged: false,
        }
    }

    fn jmp(addr: u64, target: u64) -> DecodedInsn {
        insn(addr, 5, Flow::Branch { conditional: false }, Some(target))
    }

    fn jcc(addr: u64, target: u64) -> DecodedInsn {
        insn(addr, 2, Flow::Branch { conditional: true }, Some(target))
    }

    fn call(addr: u64, target: u64) -> DecodedInsn {
        insn(addr, 5, Flow::Call, Some(target))
    }

    fn ret(addr: u64) -> DecodedInsn {
        insn(addr, 1, Flow::Return, None)
    }

    fn plain(addr: u64, len: u8) -> DecodedInsn {
        insn(addr, len, Flow::Fallthrough, None)
    }

    #[test]
    fn straight_line_is_one_block() {
        let insns = vec![plain(0x1000, 4), plain(0x1004, 4), ret(0x1008)];
        let cfg = Cfg::build(&insns);
        assert_eq!(cfg.block_count(), 1, "无分支函数应只有 1 个块");
        let b = cfg.blocks().next().unwrap();
        assert_eq!(b.start, 0x1000);
        assert_eq!(b.end, 0x1009);
        assert!(b.terminal, "以 ret 结束的块应标记终结");
        assert!(b.successors.is_empty());
        assert_eq!(cfg.edge_count(), 0);
    }

    #[test]
    fn conditional_jump_splits_block_and_has_two_successors() {
        // 1000: plain
        // 1004: jcc 1010   -> 两个后继：1010（目标）与 1006（顺序）
        // 1006: plain
        // 100a: ret        <- 是 1006 那个块的**最后一条指令**，不是块首：
        //                     没有任何跳转指向它，所以它不成为 leader
        // 1010: ret
        let insns = vec![
            plain(0x1000, 4),
            jcc(0x1004, 0x1010),
            plain(0x1006, 4),
            ret(0x100a),
            ret(0x1010),
        ];
        let cfg = Cfg::build(&insns);
        assert_eq!(
            cfg.block_starts(),
            vec![0x1000, 0x1006, 0x1010],
            "块首 = 入口 + 跳转目标 + 条件跳转的下一条；ret 本身不产生新块"
        );

        let entry = cfg.block_containing(0x1000).unwrap();
        assert_eq!(
            entry.successors,
            vec![0x1006, 0x1010],
            "条件跳转必须有两个后继（升序）"
        );
        assert!(!entry.terminal, "条件跳转不是终结指令");

        // 落在跳转目标上的块，边界要盖住整段直到下一个块首
        let fallthrough = cfg.block_containing(0x1006).unwrap();
        assert_eq!(fallthrough.end, 0x100b, "块应覆盖到 ret 之后");
        assert!(fallthrough.terminal, "以 ret 结束的块应标记终结");

        // 跳转目标自己必须是块首 —— 否则边会指向块的中间
        let target = cfg.block_containing(0x1010).unwrap();
        assert_eq!(target.start, 0x1010, "跳转目标必须是块首");
        assert_eq!(
            target.predecessors,
            vec![0x1000],
            "1010 的前驱应是发起跳转的块"
        );
    }

    #[test]
    fn unconditional_jump_has_no_fallthrough() {
        // 1000: jmp 1010
        // 1005: ret        <- 没有跳转指向这里，会被并进 1000 那个块，
        //                     所以下面用 1000 单条指令构成的块来断言。
        // 1010: ret
        //
        // 关键：给无条件跳转加上"顺序后继"会让每个 jmp 都多一条假边，
        // CFG 的块数与循环判断会跟着一起错。
        let insns = vec![jmp(0x1000, 0x1010), ret(0x1010)];
        let cfg = Cfg::build(&insns);
        let entry = cfg.block_containing(0x1000).unwrap();
        assert_eq!(entry.successors, vec![0x1010], "无条件跳转**没有**顺序后继");
        assert!(!entry.terminal, "跳出去的块不是 ret，不该标终结");

        // 反向确认：条件跳转**有**两个后继，说明上面不是"所有跳转都只连一条边"
        let cond = Cfg::build(&[jcc(0x1000, 0x1010), ret(0x1002), ret(0x1010)]);
        let cond_entry = cond.block_containing(0x1000).unwrap();
        assert_eq!(
            cond_entry.successors.len(),
            2,
            "条件跳转应有两条出边，作为上面那条断言的反向对照"
        );
    }

    #[test]
    fn call_does_not_split_block() {
        // 调用会返回：call 之后的指令仍与它在同一个块里。
        // 把 call 当终结符的实现会在这里得到 2 个块。
        let insns = vec![
            plain(0x1000, 4),
            call(0x1004, 0x2000),
            plain(0x1009, 4),
            ret(0x100d),
        ];
        let cfg = Cfg::build(&insns);
        assert_eq!(
            cfg.block_count(),
            1,
            "call 不结束基本块：控制会从被调用者返回，继续往下执行"
        );
    }

    #[test]
    fn back_edge_creates_cycle() {
        // 循环：
        // 1000: jcc 1008   -> 进循环条件
        // 1002: ret
        // 1008: plain
        // 100c: jmp 1008   -> 回边
        let insns = vec![
            jcc(0x1000, 0x1008),
            ret(0x1002),
            plain(0x1008, 4),
            jmp(0x100c, 0x1008),
        ];
        let cfg = Cfg::build(&insns);
        assert!(cfg.has_cycle(), "回边必须被识别成环");
        let head = cfg.block_containing(0x1008).unwrap();
        assert_eq!(head.successors, vec![0x1008], "回边的后继是它自己");
        assert_eq!(
            head.predecessors,
            vec![0x1000, 0x1008],
            "循环头有两条入边：来自入口块的分支，和来自自身的回边"
        );
    }

    #[test]
    fn no_cycle_for_straight_line() {
        let insns = vec![plain(0x1000, 4), ret(0x1004)];
        assert!(!Cfg::build(&insns).has_cycle(), "顺序代码不该有环");
    }

    #[test]
    fn reachable_from_entry_excludes_unreachable_block() {
        // 构造一个真实存在的"有块首但对入口不可达"的块。
        //
        // 要点：块首必须由**某个跳转**产生，否则它会被并进前一个块。
        // 所以这里让 0x100a 被 0x1005 处的跳转指向 —— 但 0x1005 自己
        // 只能从 0x1000 顺序到达，而 0x1000 是无条件 jmp 走了，
        // 于是 0x1005 及其下游都从入口不可达。
        //
        // 1000: jmp 1020     <- 入口直接跳走，不落到 1005
        // 1005: jmp 100a     <- 指向 100a，使它成为块首；但本块不可达
        // 100a: ret          <- 有前驱（1005），但从入口到不了
        // 1020: ret          <- 入口的目标
        let insns = vec![
            jmp(0x1000, 0x1020),
            jmp(0x1005, 0x100a),
            ret(0x100a),
            ret(0x1020),
        ];
        let cfg = Cfg::build(&insns);
        assert_eq!(
            cfg.block_starts(),
            vec![0x1000, 0x1005, 0x100a, 0x1020],
            "0x100a 由 0x1005 的跳转产生；0x1005 紧随无条件 jmp，\
             它之后的指令不可达，因此也必须单独成块"
        );

        // 关键：入口块必须**只有一条**出边到 0x1020。
        // 若把 0x1005 并进入口块，出口边会由 0x1005 决定，
        // 入口到 0x1020 的那条边就丢了 —— 这是本模块最隐蔽的错法。
        let entry = cfg.block_containing(0x1000).unwrap();
        assert_eq!(
            entry.successors,
            vec![0x1020],
            "入口块的出口是它自己那条 jmp，不该被后面的指令顶掉"
        );
        assert_eq!(entry.last_insn, 0x1000, "入口块的最后一条指令是那条 jmp");

        let reach = cfg.reachable_from(0x1000);
        assert!(reach.contains(&0x1000), "入口必然可达");
        assert!(reach.contains(&0x1020), "跳转目标必然可达");
        assert!(
            !reach.contains(&0x1005),
            "0x1005 紧跟在无条件 jmp 之后，从入口不可达"
        );
        assert!(
            !reach.contains(&0x100a),
            "0x100a 唯一的前驱 0x1005 不可达，所以它也到不了"
        );

        // 语义提醒：这不是"死代码"结论 —— 可能有别的函数跳进来，
        // 也可能有本图没解析出的间接引用指向它。本方法只回答可达性。
        assert!(!cfg.has_cycle(), "本图无环");
    }

    #[test]
    fn jump_outside_function_does_not_create_phantom_block() {
        // 目标 0x9000 不在本函数指令里：不能为它建一个空块。
        let insns = vec![plain(0x1000, 4), jmp(0x1004, 0x9000)];
        let cfg = Cfg::build(&insns);
        assert_eq!(cfg.block_count(), 1, "函数外的目标不该凭空多出一个块");
        assert!(
            !cfg.notes().is_empty(),
            "跳转到函数外必须留下说明（不是静默）"
        );
    }

    #[test]
    fn truncated_is_reported_for_unclosed_function() {
        // 末尾是一个跳转、且目标在函数外：图没有闭合，必须如实标注。
        let insns = vec![plain(0x1000, 4), jmp(0x1004, 0x9000)];
        let cfg = Cfg::build(&insns);
        assert!(cfg.truncated(), "未闭合的函数必须标 truncated");
    }

    #[test]
    fn empty_input_yields_empty_cfg() {
        let cfg = Cfg::build(&[]);
        assert!(cfg.is_empty());
        assert_eq!(cfg.block_count(), 0);
        assert!(!cfg.truncated());
        assert!(!cfg.has_cycle());
    }

    /// M5 验收标准 3 的一条针对性回归：CFG 不能按架构分支。
    ///
    /// 这里用两条语义相同、架构不同的指令序列建图，结果必须**结构一致**：
    /// x86 的 `je` 与 AArch64 的 `b.eq` 都表达
    /// `Flow::Branch { conditional: true }`，CFG 只认这个。
    #[test]
    fn cfg_is_architecture_agnostic() {
        let x86 = vec![
            plain(0x1000, 4),
            jcc(0x1004, 0x1010),
            plain(0x1006, 4),
            ret(0x100a),
            ret(0x1010),
        ];
        let arm = vec![
            plain(0x1000, 4),
            {
                let mut i = jcc(0x1004, 0x1010);
                i.arch = Arch::Aarch64;
                i.condition = Some(ConditionCode::Equal);
                i
            },
            plain(0x1006, 4),
            ret(0x100a),
            ret(0x1010),
        ];

        let a = Cfg::build(&x86);
        let b = Cfg::build(&arm);
        assert_eq!(
            a.block_count(),
            b.block_count(),
            "同一控制流结构在不同架构上必须产出相同的块数"
        );
        assert_eq!(a.edge_count(), b.edge_count());
        for (ba, bb) in a.blocks().zip(b.blocks()) {
            assert_eq!(ba.start, bb.start);
            assert_eq!(ba.successors, bb.successors);
        }
    }
}
