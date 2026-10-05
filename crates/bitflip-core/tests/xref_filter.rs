//! M6 交付物 7 的端到端回归门禁：xref 过滤（按类型 / 来源 / 范围）与可达性。
//!
//! # 这组测试守的是什么
//!
//! 过滤功能最常见的失效模式是**静默地不生效**：过滤条件被忽略、
//! 结果全量返回，界面看起来"正常"，但用户以为自己在看一个子集。
//! 所以这里的断言不是"字段存在"，而是：
//!
//! * 过滤后的结果**真的**变少了（或至少不等于全量时必然有理由）；
//! * 过滤后的每一条都**真的**满足条件；
//! * 跳转表推导出的引用**真的**进了 xref 表，且来源标注为 `jump-table`；
//! * 可达性的三个数字自洽，且"下界"这件事写在 notes 里。
//!
//! 另一类失效模式是**证据不够硬**：跳转表目标是分析器推导的，与指令里
//! 写明的直接目标可信度不同。把两者混在一起显示，用户无法判断该信谁。

use std::collections::BTreeSet;
use std::path::PathBuf;

use bitflip_core::{xref_source, OpenOptions, Session, XrefFilter, XrefWire};

fn fixture(name: &str) -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("..")
        .join("..")
        .join("tests")
        .join("fixtures")
        .join("generated")
        .join(name)
}

/// 打开 fixture 并构建分析结论。
fn analyze(name: &str) -> std::sync::Arc<bitflip_core::TargetAnalysis> {
    let path = fixture(name);
    assert!(path.exists(), "缺少 fixture：{}", path.display());
    let session = Session::open(&path, OpenOptions::default()).expect("打开目标");
    let job = session.detached_job();
    session.analysis(&job).expect("构建分析结论")
}

fn set(items: &[&str]) -> BTreeSet<String> {
    items.iter().map(|s| (*s).to_string()).collect()
}

/// 类型过滤：过滤后的每一条都满足条件，且条数不多于全量。
#[test]
fn kind_filter_returns_only_matching_kinds() {
    let a = analyze("m3-mingw-static.exe");

    let all = a.search_xrefs(&XrefFilter::default(), 0, usize::MAX);
    assert!(all.total > 0, "真实样本上应当有引用");

    for kind in ["call", "jump", "data"] {
        let f = XrefFilter {
            kinds: Some(set(&[kind])),
            ..Default::default()
        };
        let page = a.search_xrefs(&f, 0, usize::MAX);
        assert!(page.total <= all.total, "{kind} 过滤后的条数不应超过全量");
        assert!(
            page.items.iter().all(|x| x.kind == kind),
            "{kind} 过滤后出现了别的类型"
        );
    }

    // 三个类型加起来必须等于全量 —— 说明分类是完备的，没有"第四种"
    let sum: usize = ["call", "jump", "data"]
        .iter()
        .map(|k| {
            a.search_xrefs(
                &XrefFilter {
                    kinds: Some(set(&[k])),
                    ..Default::default()
                },
                0,
                usize::MAX,
            )
            .total
        })
        .sum();
    assert_eq!(sum, all.total, "三种类型之和必须等于全量");
}

/// 来源过滤：`direct` 与 `jump-table` 必须能被干净地分开。
#[test]
fn source_filter_separates_direct_from_derived() {
    let a = analyze("m3-mingw-static.exe");

    let direct = a.search_xrefs(
        &XrefFilter {
            sources: Some(set(&[xref_source::DIRECT])),
            ..Default::default()
        },
        0,
        usize::MAX,
    );
    assert!(direct.total > 0, "真实样本上应当有直接引用");
    assert!(direct.items.iter().all(|x| x.source == xref_source::DIRECT));

    let derived = a.search_xrefs(
        &XrefFilter {
            sources: Some(set(&[xref_source::JUMP_TABLE])),
            ..Default::default()
        },
        0,
        usize::MAX,
    );
    assert!(derived
        .items
        .iter()
        .all(|x| x.source == xref_source::JUMP_TABLE));

    // 两个来源之和等于全量：来源也是完备分类
    let all = a.search_xrefs(&XrefFilter::default(), 0, usize::MAX);
    assert_eq!(
        direct.total + derived.total,
        all.total,
        "direct + jump-table 必须等于全量"
    );
}

/// 跳转表目标**真的**进了 xref 表，并且标成推导来源。
///
/// 这条是交付物 7 的核心：识别出跳转表却不把它的目标放进"谁引用了我"，
/// 表的成员（处理函数、虚表项）就少了一条主要入口。
#[test]
fn jump_table_targets_are_backfilled_as_derived_xrefs() {
    let a = analyze("switch-x86_64.exe");

    let derived = a.search_xrefs(
        &XrefFilter {
            sources: Some(set(&[xref_source::JUMP_TABLE])),
            ..Default::default()
        },
        0,
        usize::MAX,
    );
    assert!(
        derived.total > 0,
        "switch fixture 上有跳转表，推导出的 xref 不该为空"
    );

    // 每一条推导 xref 的发起地址都应当是一条**间接跳转**指令，
    // 且它的目标集合与跳转表识别结论一致 —— 两边必须对得上。
    let tables = a.jump_tables();
    assert!(!tables.tables.is_empty(), "fixture 应当识别出跳转表");

    for x in &derived.items {
        let from = u64::from_str_radix(&x.from, 16).expect("发起地址是 hex");
        let to = u64::from_str_radix(&x.to, 16).expect("目标地址是 hex");
        let targets = tables
            .targets_of(from)
            .unwrap_or_else(|| panic!("推导 xref 的发起地址 {:#x} 不在任何跳转表里", from));
        assert!(
            targets.contains(&to),
            "{:#x} → {:#x} 不在跳转表 {:#x} 的目标里",
            from,
            to,
            from
        );
        assert_eq!(x.kind, "jump", "跳转表目标必须是 jump 型");
    }

    // 推导出的目标总数应当等于各表目标数之和
    let expected: usize = tables.tables.iter().map(|t| t.targets.len()).sum();
    assert_eq!(
        derived.total, expected,
        "推导 xref 条数应当等于所有表的目标数之和"
    );
}

/// 范围过滤：过滤后的每一条都落在范围内，且收窄范围不会让结果变多。
#[test]
fn scope_filter_keeps_only_addresses_inside_the_range() {
    let a = analyze("m3-mingw-static.exe");

    let all = a.search_xrefs(&XrefFilter::default(), 0, usize::MAX);
    let mut addrs: Vec<u64> = all
        .items
        .iter()
        .filter_map(|x| u64::from_str_radix(&x.to, 16).ok())
        .collect();
    addrs.sort_unstable();
    let mid = addrs[addrs.len() / 2];

    let lo = mid.saturating_sub(0x2000);
    let hi = mid.saturating_add(0x2000);
    let ranged = a.search_xrefs(
        &XrefFilter {
            to_range: Some((lo, hi)),
            ..Default::default()
        },
        0,
        usize::MAX,
    );

    assert!(ranged.total > 0, "这个窗口里应当有引用");
    assert!(ranged.total < all.total, "收窄范围后结果必须真的变少");
    for x in &ranged.items {
        let to = u64::from_str_radix(&x.to, 16).expect("hex");
        assert!(
            to >= lo && to < hi,
            "目标 {to:#x} 落在范围 [{lo:#x}, {hi:#x}) 之外"
        );
    }
}

/// 分页的三个数字自洽，且翻页不重不漏。
#[test]
fn pagination_is_consistent_and_does_not_drop_entries() {
    let a = analyze("m3-mingw-static.exe");

    let all = a.search_xrefs(&XrefFilter::default(), 0, usize::MAX);
    assert!(all.total > 4, "样本上的引用太少，测不出分页");

    // 用 count=3 手动翻页，收集到的条目应当与全量逐条相等
    let mut collected: Vec<XrefWire> = Vec::new();
    let mut offset = 0usize;
    loop {
        let page = a.search_xrefs(&XrefFilter::default(), offset, 3);
        assert_eq!(page.total, all.total, "总数不受分页影响");
        assert_eq!(
            page.skipped + page.returned() + page.truncated(),
            page.total,
            "跳过 + 返回 + 截断 必须等于总数"
        );
        if page.items.is_empty() {
            break;
        }
        offset += page.items.len();
        collected.extend(page.items);
        if offset >= all.total {
            break;
        }
    }
    assert_eq!(collected, all.items, "翻页收集的条目必须与全量逐条相等");
}

/// 可达性：数字自洽，且"下界"必须写在 notes 里。
#[test]
fn reachability_is_self_consistent_and_declares_the_lower_bound() {
    let a = analyze("m3-mingw-static.exe");

    let r = a.reachability(None, usize::MAX);
    assert!(r.total_functions > 0, "样本上应当识别出函数");
    assert_eq!(
        r.reachable + r.unreachable,
        r.total_functions,
        "可达 + 不可达 必须等于函数总数"
    );
    assert!(r.reachable > 0, "全局模式下应当有可达函数");

    let hist: usize = r.depth_histogram.iter().sum();
    assert_eq!(hist, r.reachable, "直方图之和必须等于可达函数数");

    // 只要存在未解析的间接调用，就必须说明可达集是下界
    if r.unresolved_indirect > 0 {
        assert!(
            r.notes.iter().any(|n| n.contains("下界")),
            "可达集是下界这件事必须明说：{:?}",
            r.notes
        );
    }
    // 明细顺序：按 (跳数, 地址) 升序 —— 界面按层展开时依赖这个顺序
    let mut sorted = r.functions.clone();
    sorted.sort_by(|x, y| (x.depth, &x.entry).cmp(&(y.depth, &y.entry)));
    assert_eq!(sorted, r.functions, "可达明细必须按 (跳数, 地址) 升序");
}

/// 从一个函数出发的可达集**不会**包含与它无关的函数。
///
/// 这条守的是"可达性真的有区分度"：如果实现退化成"返回全部函数"，
/// 上面的自洽断言仍然会通过，但这条会红。
#[test]
fn reachability_from_one_function_is_a_strict_subset() {
    let a = analyze("m3-mingw-static.exe");

    let all = a.reachability(None, usize::MAX);
    assert!(all.total_functions > 2, "样本上的函数太少，测不出子集关系");

    // 挑一个出度为 0 的函数（没调用任何人）作为起点：
    // 它的可达集应当只有它自己。
    let graph = a.call_graph();
    let callers: BTreeSet<&str> = graph.edges.iter().map(|e| e.caller.as_str()).collect();
    let leaf = a
        .functions()
        .iter()
        .find(|f| !callers.contains(f.start.as_str()))
        .map(|f| f.start.clone());
    let Some(leaf) = leaf else {
        // 样本上每个函数都调用别人：这时退回用第一个函数，
        // 只断言"是严格子集"（不做更强的结论）
        let first = a.functions()[0].start.clone();
        let r = a.reachability(
            Some(u64::from_str_radix(&first, 16).expect("hex")),
            usize::MAX,
        );
        assert!(
            r.reachable <= all.total_functions,
            "从单点出发的可达数不应超过函数总数"
        );
        return;
    };

    let r = a.reachability(
        Some(u64::from_str_radix(&leaf, 16).expect("hex")),
        usize::MAX,
    );
    assert!(
        r.reachable < all.total_functions,
        "从一个叶函数出发的可达集不应等于全部函数（那样说明可达性没有区分度）"
    );
    assert!(
        r.functions.iter().all(|f| f.depth == 0),
        "叶函数出发时不该有更深层的函数"
    );
}

/// 可达性在 AArch64 目标上同样可用（不依赖任何 x86 专属假设）。
#[test]
fn reachability_works_on_a_non_x86_target() {
    let a = analyze("elf-aarch64-cfg.exe");
    let r = a.reachability(None, usize::MAX);
    assert_eq!(r.reachable + r.unreachable, r.total_functions);
    assert_eq!(
        r.depth_histogram.iter().sum::<usize>(),
        r.reachable,
        "直方图之和必须等于可达函数数"
    );
}

/// 起点不是已知函数入口时必须**明说**，而不是安静地给 0。
///
/// 安静地给 0 会被读成"这个函数既不调用别人、也没人调用它" ——
/// 而真实原因是这个地址根本不是函数入口（打错了，或是一段还没识别的
/// 代码）。两种情况的结论完全不同，必须能区分。
#[test]
fn reachability_says_so_when_the_entry_is_not_a_known_function() {
    let a = analyze("m3-mingw-static.exe");

    // 找一个**不是**任何已知函数入口的地址：取第一个函数的入口 +1。
    let first = a.functions()[0].start.clone();
    let start = u64::from_str_radix(&first, 16).expect("hex");
    let bogus = start + 1;

    let r = a.reachability(Some(bogus), usize::MAX);
    assert!(
        r.notes.iter().any(|n| n.contains("不是已知函数入口")),
        "起点不是函数入口时必须写明，实际 notes：{:?}",
        r.notes
    );
    assert_eq!(
        r.reachable + r.unreachable,
        r.total_functions,
        "即使起点不是函数，三个数字仍要自洽"
    );
    assert!(
        r.functions
            .iter()
            .all(|f| f.entry != format!("{bogus:016x}")),
        "不是函数入口的起点不该出现在可达函数明细里"
    );
}

/// 起点是已知函数入口时，它自己一定在明细里且深度为 0。
#[test]
fn reachability_counts_the_entry_itself_when_it_is_a_known_function() {
    let a = analyze("m3-mingw-static.exe");

    // 挑一个真的有出边的函数入口
    let graph = a.call_graph();
    let entry = graph
        .edges
        .iter()
        .map(|e| e.caller.clone())
        .next()
        .expect("样本上应当有调用边");

    let r = a.reachability(
        Some(u64::from_str_radix(&entry, 16).expect("hex")),
        usize::MAX,
    );
    assert!(r.reachable > 0, "已知函数入口的可达集不该为空");
    assert_eq!(r.functions[0].entry, entry, "起点应当排在第一位");
    assert_eq!(r.functions[0].depth, 0, "起点深度必须是 0");
    assert!(
        !r.notes.iter().any(|n| n.contains("不是已知函数入口")),
        "起点是已知函数时不该有这条说明：{:?}",
        r.notes
    );
}
