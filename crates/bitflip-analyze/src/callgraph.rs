//! 调用图构建（M6）。
//!
//! # 这个模块要解决什么
//!
//! 调用图是"谁调用了谁"。听起来简单，但在这个项目里有三个具体难点，
//! 每一个都会让图变得**看起来完整但其实错的**：
//!
//! 1. **间接调用没有目标**。`call [rax+0x18]`（虚函数）、`call rax`
//!    （函数指针）在指令里没有目标地址。真解出来需要数据流分析
//!    （值从哪来、经过哪些算术）。M6 不做那个，所以这类边**如实标为
//!    未解析**，不猜。硬猜一个目标会让用户以为看懂了调用关系。
//! 2. **目标不是函数入口**。跳转表的目标、`thunk`（桩代码）、
//!    编译器插进去的辅助块都可能是 call 的目标，但它们不是"函数"。
//!    把它们当函数会让函数数量虚高。
//! 3. **调用可能落在函数中间**（尾调用合并、共享尾声）。这时要归到
//!    **包含它的那个函数**，而不是当成新函数。
//!
//! # 与 CFG 的分工
//!
//! CFG 是**函数内**的控制流（基本块与边）；调用图是**函数间**的图。
//! 两者都在 `bitflip-core` 里组装，但边从不同的地方来：CFG 的边来自
//! 指令的 `flow`，调用图的边来自 `call` 指令的目标。
//!
//! # 规模约束
//!
//! 验收标准 3 要求"1 万函数规模下可交互渲染"。1 万个节点画不下也没有
//! 意义 —— 所以本模块只负责**建图并把事实算准**（入度/出度/可达性/
//! 强连通分量），抽稀与布局交给上层。`GraphSummary` 就是给上层做
//! 渲染决策用的：先看总体形状，再决定画哪一片。

use std::collections::{BTreeMap, BTreeSet, HashMap, HashSet, VecDeque};

/// 调用边的目标解析状态。
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum CalleeResolution {
    /// 直接调用，目标落在某个已知函数的范围（或入口）内。
    Resolved,
    /// 直接调用，但目标不在任何已知函数里。
    ///
    /// 常见于：thunk/桩代码、编译器辅助块、分析没覆盖到的函数。
    /// **不合并到某个函数** —— 那会编造从属关系。
    OutsideKnownFunctions,
    /// 间接调用（寄存器或内存），指令里没有目标地址。
    ///
    /// 这是 M6 明确不做数据流分析的后果，如实标记而不是留空 ——
    /// 留空会让用户以为"这里没有调用"。
    IndirectUnresolved,
}

impl CalleeResolution {
    /// 稳定短名（wire 用）。
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Resolved => "resolved",
            Self::OutsideKnownFunctions => "outside",
            Self::IndirectUnresolved => "indirect",
        }
    }

    /// 中文标签（UI 用）。
    #[must_use]
    pub const fn label_zh(self) -> &'static str {
        match self {
            Self::Resolved => "已解析",
            Self::OutsideKnownFunctions => "落在已知函数之外",
            Self::IndirectUnresolved => "间接调用，未解析",
        }
    }
}

/// 一条调用边。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CallEdge {
    /// 调用方函数入口。
    pub caller: u64,
    /// 发起调用的指令地址。
    pub from_insn: u64,
    /// 被调用方函数入口；未解析时 `None`（**不填 0，不猜**）。
    pub callee: Option<u64>,
    /// 解析状态。
    pub resolution: CalleeResolution,
    /// 是否为尾调用（`jmp` 到另一个函数，而不是 `call`）。
    ///
    /// 单独标记是因为它影响**可达性分析**：尾调用之后不再回到原函数，
    /// 而普通 call 会返回。把它当普通 call 会让"调用方还在等待"这种
    /// 错误结论传播出去。
    pub tail: bool,
}

/// 调用图。
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct CallGraph {
    /// 全部边（按调用方、再按指令地址排序）。
    pub edges: Vec<CallEdge>,
    /// 函数入口 → 出边下标。
    pub out_edges: BTreeMap<u64, Vec<usize>>,
    /// 函数入口 → 入边下标。
    pub in_edges: BTreeMap<u64, Vec<usize>>,
    /// 间接调用（有调用点但没有目标）的总数。
    ///
    /// 单独计数是为了让"图不完整"这件事**能被量化**，而不是淹没在
    /// 一堆边里。用户看到 10609 个节点、313 处未解析间接调用，
    /// 就知道这张图的边界在哪。
    pub unresolved_indirect: usize,
    /// 降级说明（中文）。
    pub notes: Vec<String>,
}

impl CallGraph {
    /// 函数数量（出现在图中的节点数）。
    #[must_use]
    pub fn node_count(&self) -> usize {
        let mut set: BTreeSet<u64> = BTreeSet::new();
        set.extend(self.out_edges.keys().copied());
        set.extend(self.in_edges.keys().copied());
        set.len()
    }

    /// 边数量。
    #[must_use]
    pub fn edge_count(&self) -> usize {
        self.edges.len()
    }

    /// 某个函数的出边。
    #[must_use]
    pub fn callees_of(&self, entry: u64) -> Vec<&CallEdge> {
        self.out_edges
            .get(&entry)
            .map(|v| v.iter().filter_map(|&i| self.edges.get(i)).collect())
            .unwrap_or_default()
    }

    /// 某个函数的入边（谁调用了它）。
    #[must_use]
    pub fn callers_of(&self, entry: u64) -> Vec<&CallEdge> {
        self.in_edges
            .get(&entry)
            .map(|v| v.iter().filter_map(|&i| self.edges.get(i)).collect())
            .unwrap_or_default()
    }

    /// 直接可达的函数集合（从若干入口出发，沿已解析的边）。
    ///
    /// 只走 `Resolved` 的边：`OutsideKnownFunctions` 没有目标可走，
    /// `IndirectUnresolved` 更是没有目标。所以这个集合是**下界** ——
    /// 真实可达集只会更大。
    #[must_use]
    pub fn reachable_from(&self, roots: &[u64]) -> HashSet<u64> {
        let mut seen: HashSet<u64> = HashSet::new();
        let mut queue: VecDeque<u64> = VecDeque::new();
        for &r in roots {
            if seen.insert(r) {
                queue.push_back(r);
            }
        }
        while let Some(f) = queue.pop_front() {
            for e in self.callees_of(f) {
                if let Some(c) = e.callee {
                    if seen.insert(c) {
                        queue.push_back(c);
                    }
                }
            }
        }
        seen
    }

    /// 从若干入口做 BFS，返回每个可达函数到**最近入口**的跳数。
    ///
    /// 与 [`Self::reachable_from`] 的区别是带深度：可达性回答"能不能到"，
    /// 深度回答"隔着几层调用"。界面要按层展开，就得有这个数。
    ///
    /// 与 `reachable_from` 一样只走已解析的边，所以结果是**下界**。
    #[must_use]
    pub fn reachable_with_depth(&self, roots: &[u64]) -> BTreeMap<u64, u32> {
        let mut depth: BTreeMap<u64, u32> = BTreeMap::new();
        let mut queue: VecDeque<(u64, u32)> = VecDeque::new();
        for &r in roots {
            if depth.insert(r, 0).is_none() {
                queue.push_back((r, 0));
            }
        }
        while let Some((f, d)) = queue.pop_front() {
            for e in self.callees_of(f) {
                let Some(c) = e.callee else {
                    continue;
                };
                // 只记录首次到达：BFS 保证首次即最短
                if let std::collections::btree_map::Entry::Vacant(slot) = depth.entry(c) {
                    slot.insert(d.saturating_add(1));
                    queue.push_back((c, d.saturating_add(1)));
                }
            }
        }
        depth
    }

    /// 没有被任何函数调用的函数（"根"的候选）。
    ///
    /// **不是**"死代码"：间接调用解析不了，被间接调用的函数在这里
    /// 也会显示成没人调用。所以这个列表要配合
    /// `unresolved_indirect` 一起看 —— 只看它会把大量活代码判成死代码。
    #[must_use]
    pub fn entries_candidates(&self, all_functions: &[u64]) -> Vec<u64> {
        let mut out: Vec<u64> = all_functions
            .iter()
            .copied()
            .filter(|f| {
                self.in_edges.get(f).is_none_or(|v| {
                    // 只有解析不了的入边也算"没人调用"
                    !v.iter().any(|&i| {
                        self.edges
                            .get(i)
                            .is_some_and(|e| e.resolution == CalleeResolution::Resolved)
                    })
                })
            })
            .collect();
        out.sort_unstable();
        out
    }

    /// 强连通分量（Tarjan，迭代实现）。
    ///
    /// 用途：递归调用（自环或环）会让朴素的 DFS 爆栈或死循环，
    /// 而递归在真实二进制里很常见。分量本身也是有用信息 ——
    /// 一个巨大的分量通常意味着这里有一堆互相调用的分发器。
    ///
    /// 用迭代而不是递归：3 万节点的深链在递归实现下会真的爆栈，
    /// 而"分析器崩溃"是不可接受的（CLAUDE.md §4）。
    #[must_use]
    pub fn strongly_connected_components(&self) -> Vec<Vec<u64>> {
        // 先算一遍邻接表。若在遍历中对每个节点现算 `resolved_children`，
        // 每次都要重建一个 `BTreeSet` 去重 —— 3 万节点上这是数百毫秒的
        // 主要来源。预计算一次即可。
        let mut adjacency: HashMap<u64, Vec<u64>> = HashMap::with_capacity(self.out_edges.len());
        for &n in self.out_edges.keys() {
            adjacency.insert(n, self.resolved_children(n));
        }

        let mut index_counter = 0usize;
        let mut index: HashMap<u64, usize> = HashMap::new();
        let mut lowlink: HashMap<u64, usize> = HashMap::new();
        let mut on_stack: HashSet<u64> = HashSet::new();
        let mut stack: Vec<u64> = Vec::new();
        let mut components: Vec<Vec<u64>> = Vec::new();

        // 节点集合确定（用 BTreeMap 保证遍历顺序稳定，结果可复现）
        let nodes: Vec<u64> = self.out_edges.keys().copied().collect();

        // 显式栈上的一个框架。
        struct Frame {
            node: u64,
            next_child: usize,
            children: Vec<u64>,
        }

        for &root in &nodes {
            if index.contains_key(&root) {
                continue;
            }
            let mut work: Vec<Frame> = vec![Frame {
                node: root,
                next_child: 0,
                children: adjacency.get(&root).cloned().unwrap_or_default(),
            }];
            index.insert(root, index_counter);
            lowlink.insert(root, index_counter);
            index_counter += 1;
            stack.push(root);
            on_stack.insert(root);

            while let Some(frame) = work.last_mut() {
                if frame.next_child < frame.children.len() {
                    let child = frame.children[frame.next_child];
                    frame.next_child += 1;
                    // `entry` 的"是否已访问"就是 `index` 里有没有它。
                    // 用 `entry` API 一次查找代替 contains_key + insert。
                    if let std::collections::hash_map::Entry::Vacant(slot) = index.entry(child) {
                        slot.insert(index_counter);
                        lowlink.insert(child, index_counter);
                        index_counter += 1;
                        stack.push(child);
                        on_stack.insert(child);
                        work.push(Frame {
                            node: child,
                            next_child: 0,
                            children: adjacency.get(&child).cloned().unwrap_or_default(),
                        });
                    } else if on_stack.contains(&child) {
                        let child_idx = index[&child];
                        let cur = frame.node;
                        let entry = lowlink.entry(cur).or_insert(usize::MAX);
                        if child_idx < *entry {
                            *entry = child_idx;
                        }
                    }
                    continue;
                }

                // 这个节点处理完了：弹栈并回填 lowlink
                let frame = work.pop().expect("刚刚还在");
                let node = frame.node;
                let node_low = lowlink[&node];
                if node_low == index[&node] {
                    let mut comp = Vec::new();
                    while let Some(top) = stack.pop() {
                        on_stack.remove(&top);
                        comp.push(top);
                        if top == node {
                            break;
                        }
                    }
                    comp.sort_unstable();
                    components.push(comp);
                }
                if let Some(parent) = work.last() {
                    let parent_low = lowlink[&parent.node];
                    if node_low < parent_low {
                        lowlink.insert(parent.node, node_low);
                    }
                }
            }
        }

        components.sort_by_key(|c| std::cmp::Reverse(c.len()));
        components
    }

    /// 已解析的直接后继（去重）。
    fn resolved_children(&self, node: u64) -> Vec<u64> {
        let mut seen: BTreeSet<u64> = BTreeSet::new();
        for e in self.callees_of(node) {
            if let Some(c) = e.callee {
                seen.insert(c);
            }
        }
        seen.into_iter().collect()
    }
}

/// 调用图的汇总统计（给上层做渲染决策用）。
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct GraphSummary {
    /// 节点数。
    pub nodes: usize,
    /// 边数。
    pub edges: usize,
    /// 未解析的间接调用数。
    pub unresolved_indirect: usize,
    /// 落在已知函数之外的目标数（去重后）。
    pub outside_targets: usize,
    /// 入度为 0 的节点数（可能是入口，也可能是被间接调用的函数）。
    pub roots: usize,
    /// 强连通分量数量。
    pub components: usize,
    /// 最大分量的大小（>1 说明有递归环）。
    pub largest_component: usize,
    /// 出度最大的前几个函数（`入口 → 出度`），供 UI 展示"枢纽"。
    pub hubs: Vec<(u64, usize)>,
}

impl GraphSummary {
    /// 是否有递归（存在大小 >1 的分量或自环）。
    #[must_use]
    pub fn has_recursion(&self) -> bool {
        self.largest_component > 1
    }
}

impl CallGraph {
    /// 汇总统计。
    ///
    /// `hub_limit` 控制 `hubs` 的长度 —— 1 万个函数全列出来对 UI
    /// 没有意义，用户想看的是"哪几个函数是枢纽"。
    #[must_use]
    pub fn summarize(&self, all_functions: &[u64], hub_limit: usize) -> GraphSummary {
        let outside: BTreeSet<u64> = self
            .edges
            .iter()
            .filter(|e| e.resolution == CalleeResolution::OutsideKnownFunctions)
            .filter_map(|e| e.callee)
            .collect();

        let components = self.strongly_connected_components();

        let mut hubs: Vec<(u64, usize)> =
            self.out_edges.iter().map(|(&f, v)| (f, v.len())).collect();
        // 按出度降序；出度相同按地址升序，保证结果可复现
        hubs.sort_by(|a, b| b.1.cmp(&a.1).then(a.0.cmp(&b.0)));
        hubs.truncate(hub_limit);

        GraphSummary {
            nodes: self.node_count(),
            edges: self.edge_count(),
            unresolved_indirect: self.unresolved_indirect,
            outside_targets: outside.len(),
            roots: self.entries_candidates(all_functions).len(),
            components: components.len(),
            largest_component: components.first().map_or(0, Vec::len),
            hubs,
        }
    }
}

/// 一个已知函数的范围。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FunctionRange {
    /// 入口。
    pub start: u64,
    /// 结束（不含）；`None` 表示只知道入口。
    pub end: Option<u64>,
}

/// 边界未知的函数往后"吸收"地址的最大跨度。
///
/// 取 1 MiB：足够覆盖"主体 + 紧跟的 thunk 群"，又不至于把一个远在
/// 别处（另一个段）的地址误算进来。边界未知时我们**本来就不该**声称
/// 知道它有多大，这里的窗口只是个防御性上限。
const MAX_BOUNDLESS_SPAN: u64 = 0x10_0000;

/// 找到包含 `addr` 的函数。
///
/// # 规则
///
/// 1. `addr` 落在某个有边界的函数的 `[start, end)` 内 → 就是它。
/// 2. `addr` 落在某个**边界未知**的函数的 start 之后（且没超出
///    [`MAX_BOUNDLESS_SPAN`]）→ 归给这个未知边界的函数。
///    这是"紧接着的辅助块"的情形（编译器常把 thunk 紧跟主体放）。
/// 3. 其余情况返回 `None`。
///
/// **不**做"距离最近的前一个函数"这种兜底。一开始写了那个兜底，
/// 结果 `call 0x5000`（远在所有函数之外）被 0x2000 那个函数吸收，
/// 于是"目标不在已知函数里"这件事被掩盖成了"调用了一个已知函数"。
/// 那是编造从属关系 —— 宁可返回 `None`，让上层如实标记
/// `OutsideKnownFunctions`。
#[must_use]
pub fn find_function(functions: &[FunctionRange], addr: u64) -> Option<FunctionRange> {
    // 二分找到最后一个 start <= addr
    let idx = functions.partition_point(|f| f.start <= addr);
    if idx == 0 {
        return None;
    }

    let f = functions[idx - 1];
    match f.end {
        Some(end) => {
            if addr < end {
                Some(f)
            } else {
                // 有边界且 addr 超出：**不能**归给它，也不再往回找
                // ——更早的函数边界只会更小。
                None
            }
        }
        None => {
            // 边界未知：用窗口限制，避免吞掉不相关的地址
            if addr.saturating_sub(f.start) < MAX_BOUNDLESS_SPAN {
                Some(f)
            } else {
                None
            }
        }
    }
}

/// 构建调用图。
///
/// `insns` 是全部已解码指令；`functions` 是已知函数范围。
///
/// # 归属规则
///
/// 一条调用指令属于哪个函数，由 [`find_function`] 决定。落在两个函数
/// 之间的空隙里的调用**没有归属**，跳过并在 `notes` 里计数 ——
/// 不编造一个函数来安置它。
#[must_use]
pub fn build_call_graph(
    insns: &[bitflip_arch::DecodedInsn],
    functions: &[FunctionRange],
) -> CallGraph {
    let mut sorted: Vec<FunctionRange> = functions.to_vec();
    sorted.sort_by_key(|f| f.start);

    let mut edges: Vec<CallEdge> = Vec::new();
    let mut unresolved_indirect = 0usize;
    let mut orphan_calls = 0usize;

    for insn in insns {
        let is_call = insn.flow == bitflip_arch::Flow::Call;
        // 尾调用：`jmp` 到一个**属于别的函数**的目标。
        //
        // 编译器把 `call f; ret` 优化成 `jmp f`，语义上等价于调用。
        // 判断标准是这个目标确实属于另一个已知函数 —— 否则函数内的
        // 跳转（循环、分支）会被误当成尾调用，调用图会被 CFG 的边污染。
        let is_tail = !is_call
            && matches!(insn.flow, bitflip_arch::Flow::Branch { .. })
            && insn.target.is_some_and(|t| {
                let caller_owner = find_function(&sorted, insn.addr).map(|f| f.start);
                let target_owner = find_function(&sorted, t).map(|f| f.start);
                target_owner.is_some() && target_owner != caller_owner
            });

        if !is_call && !is_tail {
            continue;
        }

        let Some(caller) = find_function(&sorted, insn.addr) else {
            orphan_calls += 1;
            continue;
        };

        // 间接调用：有 target 的就是直接调用，没有的就是间接。
        let Some(target) = insn.target else {
            if is_call {
                unresolved_indirect += 1;
                edges.push(CallEdge {
                    caller: caller.start,
                    from_insn: insn.addr,
                    callee: None,
                    resolution: CalleeResolution::IndirectUnresolved,
                    tail: false,
                });
            }
            continue;
        };

        // 尾调用到同一个函数不算调用边（那是循环，由 CFG 表达）
        if is_tail && find_function(&sorted, target).map(|f| f.start) == Some(caller.start) {
            continue;
        }

        let resolution = match find_function(&sorted, target) {
            Some(_) => CalleeResolution::Resolved,
            None => CalleeResolution::OutsideKnownFunctions,
        };

        edges.push(CallEdge {
            caller: caller.start,
            from_insn: insn.addr,
            callee: Some(target),
            resolution,
            tail: is_tail,
        });
    }

    // 稳定排序：让输出可复现（否则测试会随机失败）
    edges.sort_by(|a, b| {
        a.caller
            .cmp(&b.caller)
            .then(a.from_insn.cmp(&b.from_insn))
            .then(a.callee.cmp(&b.callee))
    });
    edges.dedup();

    let mut out_edges: BTreeMap<u64, Vec<usize>> = BTreeMap::new();
    let mut in_edges: BTreeMap<u64, Vec<usize>> = BTreeMap::new();
    for (i, e) in edges.iter().enumerate() {
        out_edges.entry(e.caller).or_default().push(i);
        // 未解析的边没有目标，不进 in_edges（否则等于给一个不存在的
        // 节点建入边）
        if let Some(c) = e.callee {
            in_edges.entry(c).or_default().push(i);
        }
    }

    let mut notes: Vec<String> = Vec::new();
    if unresolved_indirect > 0 {
        notes.push(format!(
            "{unresolved_indirect} 处间接调用（寄存器/内存）未解析 —— \
             解析它们需要数据流分析，M6 未实现；这些调用点在图上是断开的"
        ));
    }
    if orphan_calls > 0 {
        notes.push(format!(
            "{orphan_calls} 条调用指令不在任何已知函数范围内，已跳过（不编造归属）"
        ));
    }

    CallGraph {
        edges,
        out_edges,
        in_edges,
        unresolved_indirect,
        notes,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use bitflip_arch::{Arch, DecodedInsn, Flow, RegSet};

    fn call(addr: u64, target: Option<u64>) -> DecodedInsn {
        DecodedInsn {
            addr,
            len: 5,
            arch: Arch::X86_64,
            mnemonic: bitflip_arch::MnemonicId(1),
            flow: Flow::Call,
            target,
            condition: None,
            operands: vec![],
            reads: RegSet::default(),
            writes: RegSet::default(),
            privileged: false,
        }
    }

    fn tail_jmp(addr: u64, target: u64) -> DecodedInsn {
        DecodedInsn {
            flow: Flow::Branch { conditional: false },
            ..call(addr, Some(target))
        }
    }

    fn plain(addr: u64) -> DecodedInsn {
        DecodedInsn {
            flow: Flow::Fallthrough,
            target: None,
            ..call(addr, None)
        }
    }

    fn funcs(ranges: &[(u64, Option<u64>)]) -> Vec<FunctionRange> {
        ranges
            .iter()
            .map(|&(start, end)| FunctionRange { start, end })
            .collect()
    }

    #[test]
    fn direct_call_becomes_a_resolved_edge() {
        let f = funcs(&[(0x1000, Some(0x1100)), (0x2000, Some(0x2100))]);
        let insns = vec![plain(0x1000), call(0x1020, Some(0x2000))];
        let g = build_call_graph(&insns, &f);

        assert_eq!(g.edge_count(), 1);
        let e = &g.edges[0];
        assert_eq!(e.caller, 0x1000);
        assert_eq!(e.callee, Some(0x2000));
        assert_eq!(e.resolution, CalleeResolution::Resolved);
        assert!(!e.tail);
        assert_eq!(g.unresolved_indirect, 0);
    }

    #[test]
    fn indirect_call_is_marked_unresolved_and_counted_not_dropped() {
        let f = funcs(&[(0x1000, Some(0x1100))]);
        let insns = vec![call(0x1020, None)];
        let g = build_call_graph(&insns, &f);

        assert_eq!(g.edge_count(), 1, "间接调用也要留一条边");
        let e = &g.edges[0];
        assert_eq!(e.callee, None, "没有目标就填 None，不猜一个地址");
        assert_eq!(e.resolution, CalleeResolution::IndirectUnresolved);
        assert_eq!(g.unresolved_indirect, 1);
        // 关键：这件事必须出现在 notes 里，让"图不完整"可见
        assert!(
            g.notes.iter().any(|n| n.contains("间接调用")),
            "未解析的间接调用必须如实说明，不能静默"
        );
    }

    #[test]
    fn call_target_outside_known_functions_is_not_folded_into_a_neighbour() {
        let f = funcs(&[(0x1000, Some(0x1100)), (0x2000, Some(0x2100))]);
        // 0x5000 不在任何函数里
        let insns = vec![call(0x1020, Some(0x5000))];
        let g = build_call_graph(&insns, &f);

        assert_eq!(g.edge_count(), 1);
        assert_eq!(g.edges[0].callee, Some(0x5000), "目标地址要原样保留");
        assert_eq!(
            g.edges[0].resolution,
            CalleeResolution::OutsideKnownFunctions,
            "落在已知函数之外的目标不能硬塞给某个函数"
        );
    }

    #[test]
    fn tail_call_to_another_function_is_an_edge_and_marked_as_tail() {
        let f = funcs(&[(0x1000, Some(0x1100)), (0x2000, Some(0x2100))]);
        let insns = vec![tail_jmp(0x10f0, 0x2000)];
        let g = build_call_graph(&insns, &f);

        assert_eq!(g.edge_count(), 1);
        assert!(g.edges[0].tail, "尾调用要标记出来（它不返回）");
        assert_eq!(g.edges[0].callee, Some(0x2000));
    }

    #[test]
    fn jump_within_the_same_function_is_not_a_call_edge() {
        let f = funcs(&[(0x1000, Some(0x1100))]);
        // 函数内部的条件跳转：循环
        let insns = vec![tail_jmp(0x1040, 0x1010)];
        let g = build_call_graph(&insns, &f);

        assert_eq!(g.edge_count(), 0, "函数内的跳转是 CFG 的边，不是调用图的边");
    }

    #[test]
    fn call_instruction_outside_every_function_is_skipped_and_reported() {
        // 函数从 0x1000 开始，调用点在它前面
        let f = funcs(&[(0x1000, Some(0x1100))]);
        let insns = vec![call(0x0800, Some(0x1000))];
        let g = build_call_graph(&insns, &f);

        assert_eq!(g.edge_count(), 0);
        assert!(
            g.notes.iter().any(|n| n.contains("不在任何已知函数范围内")),
            "没有归属的调用要如实报告，不能静默丢掉"
        );
    }

    /// 边界未知的函数吸收紧接着的地址，但**不能**吸收远在天边的。
    ///
    /// 这个上界是必要的：没有它，"最近的前一个函数"会把任何地址都
    /// 算进去，包括别的段里的地址 —— 于是"目标不在已知函数里"这条
    /// 重要信息被掩盖。
    #[test]
    fn boundless_function_absorbs_nearby_addresses_but_not_distant_ones() {
        let f = funcs(&[(0x1000, None)]);
        // 紧邻：归给它，否则调用会凭空消失
        let near = vec![call(0x1100, Some(0x1000))];
        let g = build_call_graph(&near, &f);
        assert_eq!(g.edges[0].caller, 0x1000);

        // 远在天边（超过 MAX_BOUNDLESS_SPAN）：没有归属，如实丢弃并报告
        let far_addr = 0x1000 + MAX_BOUNDLESS_SPAN + 0x1000;
        let far = vec![call(far_addr, Some(0x1000))];
        let g = build_call_graph(&far, &f);
        assert_eq!(g.edge_count(), 0);
        assert!(g.notes.iter().any(|n| n.contains("不在任何已知函数范围内")));
    }

    /// 有边界的函数不吸收边界之外的地址。
    #[test]
    fn bounded_function_does_not_absorb_addresses_past_its_end() {
        let f = funcs(&[(0x1000, Some(0x1100)), (0x8000, Some(0x8100))]);
        // 0x5000 落在 0x1100 之后、0x8000 之前：不属于任何函数
        assert_eq!(find_function(&f, 0x5000), None);
        // 边界外一点点也不行
        assert_eq!(find_function(&f, 0x1100), None);
        // 边界内可以
        assert_eq!(find_function(&f, 0x10ff).map(|f| f.start), Some(0x1000));
    }

    #[test]
    fn caller_and_callee_indexes_are_consistent() {
        let f = funcs(&[(0x1000, Some(0x1100)), (0x2000, Some(0x2100))]);
        let insns = vec![call(0x1020, Some(0x2000)), call(0x2020, Some(0x1000))];
        let g = build_call_graph(&insns, &f);

        assert_eq!(g.callees_of(0x1000).len(), 1);
        assert_eq!(g.callees_of(0x2000).len(), 1);
        assert_eq!(g.callers_of(0x1000).len(), 1);
        assert_eq!(g.callers_of(0x2000).len(), 1);
        assert_eq!(g.node_count(), 2);
    }

    #[test]
    fn reachable_from_follows_only_resolved_edges() {
        let f = funcs(&[
            (0x1000, Some(0x1100)),
            (0x2000, Some(0x2100)),
            (0x3000, Some(0x3100)),
        ]);
        let insns = vec![
            call(0x1020, Some(0x2000)), // 1000 → 2000
            call(0x2020, None),         // 2000 → 未知（间接）
            call(0x3020, Some(0x1000)), // 3000 → 1000
        ];
        let g = build_call_graph(&insns, &f);

        let r = g.reachable_from(&[0x1000]);
        assert!(r.contains(&0x1000));
        assert!(r.contains(&0x2000));
        assert!(
            !r.contains(&0x3000),
            "0x2000 之后的边是间接的，走不过去 —— 可达集只能是下界"
        );
    }

    #[test]
    fn recursion_is_detected_as_a_component_larger_than_one() {
        let f = funcs(&[(0x1000, Some(0x1100)), (0x2000, Some(0x2100))]);
        let insns = vec![
            call(0x1020, Some(0x2000)),
            call(0x2020, Some(0x1000)), // 互相调用 = 递归环
        ];
        let g = build_call_graph(&insns, &f);

        let comps = g.strongly_connected_components();
        assert_eq!(comps.len(), 1, "两个节点互调构成一个分量");
        assert_eq!(comps[0].len(), 2);

        let s = g.summarize(&[0x1000, 0x2000], 5);
        assert!(s.has_recursion());
        assert_eq!(s.largest_component, 2);
    }

    #[test]
    fn a_long_chain_does_not_blow_the_stack() {
        // 递归实现会在这种深链上爆栈。迭代实现不会。
        let n = 20_000u64;
        let f: Vec<FunctionRange> = (0..n)
            .map(|i| FunctionRange {
                start: 0x1000 + i * 0x100,
                end: Some(0x1000 + i * 0x100 + 0x80),
            })
            .collect();
        let insns: Vec<DecodedInsn> = (0..n - 1)
            .map(|i| call(0x1000 + i * 0x100 + 0x10, Some(0x1000 + (i + 1) * 0x100)))
            .collect();
        let g = build_call_graph(&insns, &f);

        assert_eq!(g.edge_count(), (n - 1) as usize);
        let comps = g.strongly_connected_components();
        assert_eq!(comps.len(), n as usize, "一条链上每个节点自成一分量");
    }

    #[test]
    fn summary_reports_hubs_by_out_degree() {
        let f = funcs(&[
            (0x1000, Some(0x1100)),
            (0x2000, Some(0x2100)),
            (0x3000, Some(0x3100)),
        ]);
        let insns = vec![
            call(0x1020, Some(0x2000)),
            call(0x1030, Some(0x3000)),
            call(0x2020, Some(0x3000)),
        ];
        let g = build_call_graph(&insns, &f);
        let s = g.summarize(&[0x1000, 0x2000, 0x3000], 10);

        assert_eq!(s.nodes, 3);
        assert_eq!(s.edges, 3);
        assert_eq!(s.hubs[0], (0x1000, 2), "出度最大的应当是 0x1000");
    }

    #[test]
    fn edges_are_sorted_and_deduplicated_for_reproducible_output() {
        let f = funcs(&[(0x1000, Some(0x1100)), (0x2000, Some(0x2100))]);
        // 故意乱序，并且有重复
        let insns = vec![
            call(0x1030, Some(0x2000)),
            call(0x1020, Some(0x2000)),
            call(0x1030, Some(0x2000)),
        ];
        let g = build_call_graph(&insns, &f);

        assert_eq!(g.edges.len(), 2, "完全相同的边要去重");
        assert_eq!(g.edges[0].from_insn, 0x1020, "按指令地址升序");
        assert_eq!(g.edges[1].from_insn, 0x1030);
    }

    #[test]
    fn resolution_kinds_have_distinct_short_names_and_chinese_labels() {
        let all = [
            CalleeResolution::Resolved,
            CalleeResolution::OutsideKnownFunctions,
            CalleeResolution::IndirectUnresolved,
        ];
        let names: BTreeSet<&str> = all.iter().map(|r| r.as_str()).collect();
        assert_eq!(names.len(), 3, "wire 短名必须互不相同");
        for r in all {
            assert!(!r.label_zh().is_empty());
        }
    }

    // ── 可达性（M6 交付物 7）──

    #[test]
    fn reachable_depth_is_the_shortest_call_distance() {
        // 链：0x1000 → 0x2000 → 0x3000，外加一条 0x1000 → 0x3000 的近路。
        // 0x3000 的深度必须是 1（最短），不是 2（先走链）。
        let f = funcs(&[
            (0x1000, Some(0x1100)),
            (0x2000, Some(0x2100)),
            (0x3000, Some(0x3100)),
        ]);
        let insns = vec![
            call(0x1020, Some(0x2000)),
            call(0x1030, Some(0x3000)),
            call(0x2020, Some(0x3000)),
        ];
        let g = build_call_graph(&insns, &f);
        let d = g.reachable_with_depth(&[0x1000]);

        assert_eq!(d.get(&0x1000), Some(&0), "入口自己深度 0");
        assert_eq!(d.get(&0x2000), Some(&1));
        assert_eq!(d.get(&0x3000), Some(&1), "BFS 首次到达即最短");
    }

    #[test]
    fn reachable_depth_handles_recursion_without_looping_forever() {
        // 互递归：A → B → A。朴素 DFS 会死循环；BFS + 首次记录必须收敛。
        let f = funcs(&[(0x1000, Some(0x1100)), (0x2000, Some(0x2100))]);
        let insns = vec![call(0x1020, Some(0x2000)), call(0x2020, Some(0x1000))];
        let g = build_call_graph(&insns, &f);
        let d = g.reachable_with_depth(&[0x1000]);

        assert_eq!(d.len(), 2, "两个函数都可达，且各自只记一次");
        assert_eq!(d.get(&0x1000), Some(&0));
        assert_eq!(d.get(&0x2000), Some(&1));
    }

    #[test]
    fn unreachable_functions_are_absent_from_the_depth_map() {
        // 孤立函数（没人调用、也不调用别人）必须**不在**可达集里 ——
        // 这正是"可达性"要回答的问题。
        let f = funcs(&[
            (0x1000, Some(0x1100)),
            (0x2000, Some(0x2100)),
            (0x9000, Some(0x9100)),
        ]);
        let insns = vec![call(0x1020, Some(0x2000))];
        let g = build_call_graph(&insns, &f);
        let d = g.reachable_with_depth(&[0x1000]);

        assert!(d.contains_key(&0x2000));
        assert!(
            !d.contains_key(&0x9000),
            "孤立函数不该出现在从 0x1000 出发的可达集里"
        );
    }

    #[test]
    fn indirect_calls_do_not_extend_reachability() {
        // 未解析的间接调用没有目标可走，所以可达集是**下界**。
        // 这条钉住"下界"这个语义：不许因为存在未解析调用就猜测可达。
        let f = funcs(&[(0x1000, Some(0x1100)), (0x2000, Some(0x2100))]);
        let insns = vec![call(0x1020, None)];
        let g = build_call_graph(&insns, &f);
        let d = g.reachable_with_depth(&[0x1000]);

        assert_eq!(d.len(), 1, "只有入口自己");
        assert!(!d.contains_key(&0x2000));
        assert_eq!(g.unresolved_indirect, 1);
    }
}
