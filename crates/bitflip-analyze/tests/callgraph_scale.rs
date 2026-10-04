//! M6 验收标准 3：调用图在 1 万函数规模下**可交互**。
//!
//! # "可交互"怎么定义成可测的东西
//!
//! "可交互"是个模糊的形容词，必须落成数字才能当门禁。这里拆成三条：
//!
//! 1. **建图本身不炸**：1 万节点的图能在有限时间内建出来，
//!    且不爆栈（递归实现在深链上会真的爆）。
//! 2. **邻域查询是快的**：这是用户实际的交互路径 —— 点开一个函数看
//!    它调用谁、谁调用它。要求 **< 100ms**，否则"点一下卡一下"。
//! 3. **全图是有界的**：边数不能无限膨胀，响应必须有明确上限，
//!    且截断要**如实说明**（不能静默少给数据）。
//!
//! 注意：验收标准说的是"可交互**渲染**"，渲染在前端。后端能做到
//! 的就是上面三条 —— 保证前端要什么能在 100ms 内给到。这一点在
//! 文档里如实写明，不假装后端能替前端背书。

use std::collections::HashSet;
use std::time::Instant;

use bitflip_analyze::{build_call_graph, CallGraph, CalleeResolution, FunctionRange};

/// 造一个 `n` 个函数的合成调用图，用来测规模。
///
/// 形状刻意做成真实二进制里常见的样子而不是纯粹的树：
///
/// * 主体是一条长链（模拟顺序调用）；
/// * 每个函数额外调用几个"后面的"函数（模拟跳转表分发）；
/// * 若干个函数互相调用形成环（模拟递归与分发器）。
///
/// 纯链状图会低估强连通分量算法的成本，纯随机图又会高估。
fn synthetic_graph(n: usize) -> (Vec<bitflip_arch::DecodedInsn>, Vec<FunctionRange>) {
    const BASE: u64 = 0x1_0000_0000;
    const STRIDE: u64 = 0x40;

    let funcs: Vec<FunctionRange> = (0..n)
        .map(|i| FunctionRange {
            start: BASE + i as u64 * STRIDE,
            end: Some(BASE + i as u64 * STRIDE + STRIDE - 4),
        })
        .collect();

    let mut insns: Vec<bitflip_arch::DecodedInsn> = Vec::with_capacity(n * 3);

    let mk_call = |addr: u64, target: u64| bitflip_arch::DecodedInsn {
        addr,
        len: 5,
        arch: bitflip_arch::Arch::X86_64,
        mnemonic: bitflip_arch::MnemonicId(1),
        flow: bitflip_arch::Flow::Call,
        target: Some(target),
        condition: None,
        operands: vec![],
        reads: bitflip_arch::RegSet::default(),
        writes: bitflip_arch::RegSet::default(),
        privileged: false,
    };

    for i in 0..n {
        let here = BASE + i as u64 * STRIDE;

        // 链：调用下一个
        if i + 1 < n {
            insns.push(mk_call(here + 4, BASE + (i + 1) as u64 * STRIDE));
        }
        // 分发：调用几个"远一点"的函数
        for k in [7usize, 31, 97] {
            let t = (i + k) % n;
            if t != i {
                insns.push(mk_call(here + 8, BASE + t as u64 * STRIDE));
            }
        }
        // 环：每 50 个函数里前两个互相调用
        if i % 50 == 0 && i + 2 <= n {
            insns.push(mk_call(here + 12, BASE + (i + 1) as u64 * STRIDE));
        }
    }

    (insns, funcs)
}

/// **门禁 1**：1 万函数的图能建出来，且不爆栈。
#[test]
fn ten_thousand_function_graph_builds_without_blowing_the_stack() {
    let (insns, funcs) = synthetic_graph(10_000);
    let t = Instant::now();
    let g = build_call_graph(&insns, &funcs);
    let build = t.elapsed();

    eprintln!(
        "1 万函数：建图 {} ms，节点 {}，边 {}",
        build.as_millis(),
        g.node_count(),
        g.edge_count()
    );

    assert_eq!(g.node_count(), 10_000, "每个函数都该出现在图里");
    assert!(g.edge_count() > 10_000, "边数应当明显多于节点数");

    // 建图本身不该慢到不可接受。注意这不含反汇编 —— 调用图建立在
    // 已有指令之上，所以这里的预算是纯图构建。
    assert!(
        build.as_millis() < 3_000,
        "1 万函数建图用了 {} ms，太慢",
        build.as_millis()
    );
}

/// **门禁 2**：强连通分量分析在 1 万节点 + 环的图上不爆栈、且够快。
///
/// 这条单独测是因为 Tarjan 的**递归**实现在深链上会真的爆栈 ——
/// 而"分析器崩溃"是这个项目明确不能接受的（CLAUDE.md §4）。
#[test]
fn strongly_connected_components_survives_a_deep_chain() {
    // 一条 3 万节点的纯链：递归实现必爆栈
    let n = 30_000usize;
    const BASE: u64 = 0x2_0000_0000;
    const STRIDE: u64 = 0x40;
    let funcs: Vec<FunctionRange> = (0..n)
        .map(|i| FunctionRange {
            start: BASE + i as u64 * STRIDE,
            end: Some(BASE + i as u64 * STRIDE + STRIDE - 4),
        })
        .collect();
    let insns: Vec<bitflip_arch::DecodedInsn> = (0..n - 1)
        .map(|i| bitflip_arch::DecodedInsn {
            addr: BASE + i as u64 * STRIDE + 4,
            len: 5,
            arch: bitflip_arch::Arch::X86_64,
            mnemonic: bitflip_arch::MnemonicId(1),
            flow: bitflip_arch::Flow::Call,
            target: Some(BASE + (i + 1) as u64 * STRIDE),
            condition: None,
            operands: vec![],
            reads: bitflip_arch::RegSet::default(),
            writes: bitflip_arch::RegSet::default(),
            privileged: false,
        })
        .collect();

    let g = build_call_graph(&insns, &funcs);
    let t = Instant::now();
    let comps = g.strongly_connected_components();
    let elapsed = t.elapsed();

    eprintln!(
        "3 万节点深链：SCC {} ms，得到 {} 个分量",
        elapsed.as_millis(),
        comps.len()
    );
    assert_eq!(comps.len(), n, "纯链上每个节点自成一分量");
    assert!(elapsed.as_millis() < 3_000, "SCC 太慢");
}

/// **门禁 3**：邻域查询在 1 万函数的图上是毫秒级的。
///
/// 这是"可交互"的真实含义：用户点开一个函数，要立刻看到它调用谁、
/// 谁调用它。全图 13 秒可以接受（一次性的），点一下 13 秒不行。
#[test]
fn neighbourhood_lookup_is_interactive_on_a_ten_thousand_function_graph() {
    let (insns, funcs) = synthetic_graph(10_000);
    let g = build_call_graph(&insns, &funcs);

    // 找一个出度最大的函数（最坏情况）
    let hub = g
        .out_edges
        .iter()
        .max_by_key(|(_, v)| v.len())
        .map(|(&k, _)| k)
        .expect("图非空");

    let t = Instant::now();
    let callees = g.callees_of(hub);
    let callers = g.callers_of(hub);
    let elapsed = t.elapsed();

    eprintln!(
        "枢纽函数 {hub:#x}：出边 {} / 入边 {}，查询 {} µs",
        callees.len(),
        callers.len(),
        elapsed.as_micros()
    );

    assert!(!callees.is_empty());
    assert!(
        elapsed.as_millis() < 100,
        "邻域查询用了 {} ms，交互会卡",
        elapsed.as_millis()
    );

    // 深度 2 的邻域展开也要快（前端"再展开一层"是常见操作）
    let t = Instant::now();
    let mut seen: HashSet<u64> = HashSet::from([hub]);
    let mut frontier = vec![hub];
    for _ in 0..2 {
        let mut next = Vec::new();
        for f in &frontier {
            for e in g.callees_of(*f) {
                if let Some(c) = e.callee {
                    if seen.insert(c) {
                        next.push(c);
                    }
                }
            }
        }
        frontier = next;
    }
    let elapsed2 = t.elapsed();
    eprintln!(
        "深度 2 邻域：{} 个节点，{} ms",
        seen.len(),
        elapsed2.as_millis()
    );
    assert!(
        elapsed2.as_millis() < 500,
        "深度 2 邻域用了 {} ms",
        elapsed2.as_millis()
    );
}

/// 未解析的间接调用在图上必须是**可见的缺口**，不是静默的空。
///
/// 大目标上这条尤其重要：ntdll.dll 有 313 处间接调用解析不了。
/// 如果这些调用点悄悄消失，用户会以为"这个函数什么都没调用" ——
/// 一个看起来完整但实际错误的结论。
#[test]
fn unresolved_indirect_calls_stay_visible_on_a_large_graph() {
    let (mut insns, funcs) = synthetic_graph(5_000);
    // 塞一批间接调用进去
    const INDIRECT: usize = 500;
    for i in 0..INDIRECT {
        let addr = 0x1_0000_0000u64 + (i as u64 * 7) * 0x40 + 20;
        insns.push(bitflip_arch::DecodedInsn {
            addr,
            len: 3,
            arch: bitflip_arch::Arch::X86_64,
            mnemonic: bitflip_arch::MnemonicId(2),
            flow: bitflip_arch::Flow::Call,
            target: None,
            condition: None,
            operands: vec![],
            reads: bitflip_arch::RegSet::default(),
            writes: bitflip_arch::RegSet::default(),
            privileged: false,
        });
    }

    let g = build_call_graph(&insns, &funcs);
    let indirect: usize = g
        .edges
        .iter()
        .filter(|e| e.resolution == CalleeResolution::IndirectUnresolved)
        .count();

    eprintln!("{} 处间接调用被记录为未解析", indirect);
    assert!(indirect > 0, "间接调用必须留下痕迹");
    assert_eq!(g.unresolved_indirect, indirect, "计数要与边一致");
    assert!(
        g.notes.iter().any(|n| n.contains("间接调用")),
        "未解析必须在 notes 里说明，否则 UI 无法告诉用户'图不完整'"
    );

    // 未解析的边不能有目标地址（否则就是把猜测当事实）
    for e in &g.edges {
        if e.resolution == CalleeResolution::IndirectUnresolved {
            assert!(e.callee.is_none(), "未解析的边不许编造目标");
        }
    }
}

/// 图的构建结果必须**可复现**：同样的输入两次建图，边序列完全一样。
///
/// 用 `HashMap` 迭代顺序驱动输出会让测试随机失败，也会让"黄金快照"
/// 这类校验失效。
#[test]
fn graph_construction_is_deterministic() {
    let (insns, funcs) = synthetic_graph(2_000);
    let a: CallGraph = build_call_graph(&insns, &funcs);
    let b: CallGraph = build_call_graph(&insns, &funcs);

    assert_eq!(a.edges, b.edges, "两次建图必须得到完全相同的边序列");
    assert_eq!(
        a.strongly_connected_components(),
        b.strongly_connected_components(),
        "分量结果也要稳定"
    );
}
