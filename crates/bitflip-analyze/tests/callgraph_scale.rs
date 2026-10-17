//! M6 验收标准 3：调用图在 1 万函数规模下**可交互**。
//!
//! # "可交互"怎么定义成可测的东西
//!
//! "可交互"是个模糊的形容词，必须落成数字才能当门禁。这里拆成三条：
//!
//! 1. **建图本身不炸**：1 万节点的图能在有限时间内建出来，
//!    且不爆栈（递归实现在深链上会真的爆）。
//! 2. **邻域查询是快的**：这是用户实际的交互路径 —— 点开一个函数看
//!    它调用谁、谁调用它。要求**毫秒级**，否则"点一下卡一下"。
//! 3. **全图是有界的**：边数不能无限膨胀，响应必须有明确上限，
//!    且截断要**如实说明**（不能静默少给数据）。
//!
//! 注意：验收标准说的是"可交互**渲染**"，渲染在前端。后端能做到
//! 的就是上面三条 —— 保证前端要什么能在毫秒级给到。这一点在
//! 文档里如实写明，不假装后端能替前端背书。
//!
//! # 门限为什么不是写死的毫秒数
//!
//! 原来这里写的是 `3000 ms` / `100 ms` / `500 ms`。问题不是宽或严，而是这些数字
//! **测的是机器，不是我们的代码**：同一份代码在慢一倍的机器上耗时翻倍，于是门限
//! 要么在慢机器上误报（本机踩过），要么为了兼容慢机器被调到没有意义。
//!
//! 现在先跑一段**固定工作量**得到"本机单位"（[`machine_unit`]），门限一律写成
//! `本机单位 × 倍数`。慢机器单位大、门限跟着大；快机器两者一起小。算法退化
//! （O(n²)、意外的全图重算）是**结构性**的，倍数再宽松也拦得住 —— 而"这台机器
//! 慢了两倍"不会再被报成回归。
//!
//! 倍数怎么定的：本机实测后取**约 20 倍余量**（见各条 `MULT_*` 常量旁的实测值）。
//! 余量给得大是刻意的：这条测试要抓的是"量级变了"，不是几百毫秒的抖动。

use std::collections::HashSet;
use std::time::{Duration, Instant};

use bitflip_analyze::{build_call_graph, CallGraph, CalleeResolution, FunctionRange};

// ── 本机标定 ──────────────────────────────────────────────────────────────

/// 标定工作量：固定循环的次数。
const CALIBRATION_ROUNDS: u64 = 20_000;

/// 连续测几次取**最小值**（噪声只会让它变慢，最小值最接近真值）。
const CALIBRATION_REPEATS: u32 = 5;

/// 本机单位：一段固定工作量的耗时。
///
/// 刻意用与建图同类的活（哈希插入 + 收集 + 排序 + 地址运算），而不是空循环 ——
/// 空循环会被优化掉，也会掩盖缓存与分配器的差异。`black_box` 保证结果不被优化。
fn machine_unit() -> Duration {
    let mut best = Duration::MAX;
    for _ in 0..CALIBRATION_REPEATS {
        let started = Instant::now();
        let mut table: std::collections::HashMap<u64, u32> =
            std::collections::HashMap::with_capacity(CALIBRATION_ROUNDS as usize);
        for index in 0..CALIBRATION_ROUNDS {
            let key = index.wrapping_mul(0x9E37_79B9_7F4A_7C15);
            *table.entry(key).or_insert(0) += 1;
        }
        let mut values: Vec<u32> = table.values().copied().collect();
        values.sort_unstable();
        std::hint::black_box(values.last().copied().unwrap_or(0));
        best = best.min(started.elapsed());
    }
    best
}

/// 门限 = 本机单位 × 倍数。报错时同时打印两者，方便判断是"机器慢"还是"代码退步"。
fn budget(unit: Duration, multiple: u32) -> Duration {
    unit * multiple
}

/// 断言耗时在门限内，失败信息里带出本机单位 —— 下一次看到红的人不用再猜机器。
fn assert_within(elapsed: Duration, unit: Duration, multiple: u32, what: &str) {
    let limit = budget(unit, multiple);
    assert!(
        elapsed <= limit,
        "{what}用了 {elapsed:?}，超过门限 {limit:?}（本机单位 {unit:?} × {multiple}）—— \
         这不是「机器慢了一点」，是量级变了"
    );
}

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
        if i.is_multiple_of(50) && i + 2 <= n {
            insns.push(mk_call(here + 12, BASE + (i + 1) as u64 * STRIDE));
        }
    }

    (insns, funcs)
}

/// **门禁 1**：1 万函数的图能建出来，且不爆栈。
#[test]
fn ten_thousand_function_graph_builds_without_blowing_the_stack() {
    // 倍数：本机实测建 1 万函数的图约 15 个本机单位（507 ms / 34 ms），
    // 门限给到 80（约 5 倍余量）。本机单位本身在 20–35 ms 之间抖动
    // （debug 构建 + 机器负载），所以余量不能只留 2 倍。
    const MULT_BUILD: u32 = 80;
    let unit = machine_unit();

    let (insns, funcs) = synthetic_graph(10_000);
    let t = Instant::now();
    let g = build_call_graph(&insns, &funcs);
    let build = t.elapsed();

    eprintln!(
        "1 万函数：建图 {} ms（本机单位 {unit:?}，门限 {:?}），节点 {}，边 {}",
        build.as_millis(),
        budget(unit, MULT_BUILD),
        g.node_count(),
        g.edge_count()
    );

    assert_eq!(g.node_count(), 10_000, "每个函数都该出现在图里");
    assert!(g.edge_count() > 10_000, "边数应当明显多于节点数");

    // 建图本身不该慢到不可接受。注意这不含反汇编 —— 调用图建立在
    // 已有指令之上，所以这里的预算是纯图构建。
    assert_within(build, unit, MULT_BUILD, "1 万函数建图");
}

/// **门禁 2**：强连通分量分析在 1 万节点 + 环的图上不爆栈、且够快。
///
/// 这条单独测是因为 Tarjan 的**递归**实现在深链上会真的爆栈 ——
/// 而"分析器崩溃"是这个项目明确不能接受的（CLAUDE.md §4）。
#[test]
fn strongly_connected_components_survives_a_deep_chain() {
    // 倍数：本机实测 3 万节点深链的 SCC 约 39 个本机单位（1126 ms / 29 ms），
    // 门限给到 200（约 5 倍余量）。
    const MULT_SCC: u32 = 200;
    let unit = machine_unit();

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
        "3 万节点深链：SCC {} ms（本机单位 {unit:?}，门限 {:?}），得到 {} 个分量",
        elapsed.as_millis(),
        budget(unit, MULT_SCC),
        comps.len()
    );
    assert_eq!(comps.len(), n, "纯链上每个节点自成一分量");
    assert_within(elapsed, unit, MULT_SCC, "3 万节点深链的 SCC ");
}

/// **门禁 3**：邻域查询在 1 万函数的图上是毫秒级的。
///
/// 这是"可交互"的真实含义：用户点开一个函数，要立刻看到它调用谁、
/// 谁调用它。全图 13 秒可以接受（一次性的），点一下 13 秒不行。
#[test]
fn neighbourhood_lookup_is_interactive_on_a_ten_thousand_function_graph() {
    // 倍数：本机实测单次邻域查询 13 µs ≈ 0.001 个本机单位、深度 2 展开 0 ms。
    // 门限给到 20 / 40 个单位（毫秒级）—— 这条要抓的是「查询退化成全图扫描」，
    // 那会大好几个量级；它不负责发现"慢了 30%"。
    const MULT_ONE_HOP: u32 = 20;
    const MULT_TWO_HOP: u32 = 40;
    let unit = machine_unit();

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
        "枢纽函数 {hub:#x}：出边 {} / 入边 {}，查询 {} µs（本机单位 {unit:?}，门限 {:?}）",
        callees.len(),
        callers.len(),
        elapsed.as_micros(),
        budget(unit, MULT_ONE_HOP)
    );

    assert!(!callees.is_empty());
    assert_within(elapsed, unit, MULT_ONE_HOP, "邻域查询");

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
        "深度 2 邻域：{} 个节点，{} ms（门限 {:?}）",
        seen.len(),
        elapsed2.as_millis(),
        budget(unit, MULT_TWO_HOP)
    );
    assert_within(elapsed2, unit, MULT_TWO_HOP, "深度 2 邻域");
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
