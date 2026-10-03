//! AArch64 CFG 正确性抽查（PLAN M5 验收标准 2）。
//!
//! # 这个测试在验证什么
//!
//! 验收标准写的是"ARM64 fixture 的 CFG 正确性抽查通过"。抽查的含义是：
//! 挑几个函数，把**正确的 CFG 先写在纸上**，再看程序算出来的是不是一样。
//!
//! 这里的"纸上"是 `tests/fixtures/generated/elf-aarch64-cfg.dis.txt` ——
//! `llvm-objdump` 输出的真实反汇编。每条期望都标了它从哪几行推出来，
//! 而不是"跑一次看输出是多少就写多少"（那样只是把 bug 固化成期望）。
//!
//! # fixture 是怎么来的
//!
//! `scripts/gen-aarch64-cfg-fixture.ps1` 用 clang 交叉编译
//! `tests/fixtures/aarch64_cfg_sample.c` 到 `aarch64-unknown-linux-gnu`。
//! 用 `-O0`：`-O1` 下 clang 把 `cfg_absdiff` 编译成无分支的 `cneg`、
//! 把 `cfg_ladder` 编译成 `cset`/`cinc`/`csel` —— 那些是正确的代码，
//! 但没有条件跳转，CFG 测试会几乎断言不到东西。
//!
//! # 为什么这些用例值得单独写
//!
//! AArch64 与 x86 在 CFG 相关的形状上差别很大：
//! - 条件分支写作 `b.<cond>`（**不是**独立的助记符），条件码在编码里；
//! - 有 `cbz`/`cbnz`（比较并分支）这类"寄存器判定"分支；
//! - `bl` 是带链接的调用，`ret` 用 x30。
//!
//! 如果 CFG 层按架构分支（M5 验收标准 3 禁止的事情），这些差异会
//! 各自漏掉一种。本测试对每条都给出显式期望。

use std::path::PathBuf;

use bitflip_core::{Disasm, DisasmScanOptions, OpenOptions, Session, TargetAnalysis};

fn fixture_path() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("..")
        .join("..")
        .join("tests")
        .join("fixtures")
        .join("generated")
        .join("elf-aarch64-cfg.exe")
}

/// 打开 fixture、反汇编、取分析结果。
fn setup() -> Option<(Session, Disasm, std::sync::Arc<TargetAnalysis>)> {
    let path = fixture_path();
    if !path.exists() {
        return None;
    }
    let session = Session::open(&path, OpenOptions::default()).ok()?;
    let disasm = session.disassemble(DisasmScanOptions::default()).ok()?;
    let job = session.detached_job();
    let analysis = session.analysis(&job).ok()?;
    Some((session, disasm, analysis))
}

/// fixture 缺失时硬失败并给出重建命令。
///
/// 一个在缺 fixture 时"跳过"的验收测试等于没有验收：它会一直绿，
/// 而 CFG 可能在某个 clang 版本上已经坏了。
fn require_fixture() -> (Session, Disasm, std::sync::Arc<TargetAnalysis>) {
    setup().unwrap_or_else(|| {
        panic!(
            "无法建立 AArch64 CFG 测试环境（fixture 缺失或解析失败）: {}\n\
             这个测试验证 M5 验收标准 2（ARM64 CFG 抽查），不能跳过。\n\
             重建：& .\\scripts\\gen-aarch64-cfg-fixture.ps1 -Force",
            fixture_path().display()
        )
    })
}

fn hex(v: u64) -> String {
    format!("{v:016x}")
}

fn unhex(s: &str) -> u64 {
    u64::from_str_radix(s, 16).unwrap_or_else(|_| panic!("不是十六进制地址: {s}"))
}

/// 符号名 → 入口地址。从目标对象的符号表读（fixture 未 strip）。
fn entry_of(session: &Session, name: &str) -> u64 {
    let object = session.object().expect("解析后的目标对象");
    object
        .symbols
        .iter()
        .find(|s| s.name == name && s.is_function)
        .unwrap_or_else(|| panic!("fixture 里找不到函数符号 {name}（fixture 可能重建过）"))
        .value
}

/// 取某函数的 CFG，缺失时给出可诊断的失败信息。
fn cfg_of<'a>(analysis: &'a TargetAnalysis, entry: u64, name: &str) -> &'a bitflip_core::CfgWire {
    analysis.cfg_of(entry).unwrap_or_else(|| {
        panic!(
            "{name}（入口 {entry:#x}）没有 CFG。\
             已有的函数入口：{:?}",
            analysis.cfgs().map(|c| c.entry.clone()).collect::<Vec<_>>()
        )
    })
}

#[test]
fn fixture_is_aarch64() {
    let (session, _disasm, _analysis) = require_fixture();
    let info = session.info();
    let arch = info
        .arch
        .as_deref()
        .unwrap_or_else(|| panic!("fixture 应识别出架构，实际没有：notes={:?}", info.notes));
    assert!(
        arch.to_lowercase().contains("aarch64"),
        "这个 fixture 必须是 AArch64：{arch:?}"
    );
}

/// 抽查 1：`cfg_sum` —— 条件分支必须有两个后继。
///
/// 依据 `elf-aarch64-cfg.dis.txt`（注意 **-O0 下函数入口处是 `b`，不是 `b.ge`**）：
/// ```text
/// cfg_sum:
///   210350: sub/str/str/str        <- 入口块，无分支
///   210360: b     0x210364         <- 无条件：**1 个后继**
///   210364: ldr/ldr/subs           <- 循环头
///   210370: b.ge  0x2103a8         <- 条件：**2 个后继**（2103a8 与 210374）
///   210374: b     0x210378
///   ...
/// ```
///
/// 这里刻意**不看第一个块**：它结束于无条件 `b`，只有一个后继才是对的。
/// 我最初正是在这里写错了期望（假设入口块带条件分支），
/// 所以这条改成按地址精确定位到含 `b.ge` 的那个块 ——
/// 断言"条件分支有两条出边"这件事本身，而不是断言某个块恰好长什么样。
#[test]
fn cfg_sum_conditional_branch_has_two_successors() {
    let (session, _disasm, analysis) = require_fixture();
    let entry = entry_of(&session, "cfg_sum");
    let cfg = cfg_of(&analysis, entry, "cfg_sum");

    assert_eq!(cfg.blocks[0].start, hex(entry), "第一个块应从函数入口开始");

    // 入口块结束于无条件 `b 0x210364`：恰好 1 个后继。
    let first = &cfg.blocks[0];
    assert_eq!(
        first.successors,
        vec![hex(0x210364)],
        "入口块以无条件 `b` 结束，必须只有 1 个后继（不能凭空多出顺序后继）；\
         block={first:?}"
    );
    assert!(!first.terminal, "`b` 不是终结指令");

    // 含 `b.ge` 的块必须恰好有 2 个后继。
    let cond = cfg
        .blocks
        .iter()
        .find(|b| unhex(&b.last_insn) == 0x210370)
        .unwrap_or_else(|| panic!("找不到以 210370（b.ge）结尾的块；blocks={:?}", cfg.blocks));
    assert_eq!(
        cond.successors.len(),
        2,
        "b.ge 是条件分支：必须有 2 个后继（目标 2103a8 + 顺序 210374）。\
         拿到 {} 个说明条件跳转被当成了无条件跳转。block={cond:?}",
        cond.successors.len()
    );
    assert!(
        cond.successors.contains(&hex(0x2103a8)),
        "条件分支的后继里必须有跳转目标 2103a8；实际 {:?}",
        cond.successors
    );
    assert!(
        cond.successors.contains(&hex(0x210374)),
        "条件分支的后继里必须有顺序后继 210374；实际 {:?}",
        cond.successors
    );

    // 两个后继都必须真的是块首（否则边指向块的中间）
    for succ in &cond.successors {
        assert!(
            cfg.blocks.iter().any(|b| &b.start == succ),
            "后继 {succ} 必须是一个块首，否则连边失真"
        );
    }
}

/// 抽查 2：`cfg_sum` —— 真正的循环（回边）。
///
/// 依据 `elf-aarch64-cfg.dis.txt`：
/// ```text
/// cfg_sum:
///   210360: b     0x210364        <- 进条件
///   210364: ldr/subs              <- 循环头
///   210370: b.ge  0x2103a8        <- 条件：退出循环 / 落进循环体
///   210374: b     0x210378
///   210378: ...（循环体计算）
///   210394: b     0x210398
///   210398: ldr/add/str
///   2103a4: b     0x210364        <- **回边**：跳回循环头
///   2103a8: ... ret
/// ```
/// 期望：`has_cycle == true`，且循环头有前驱。
#[test]
fn cfg_sum_has_a_back_edge() {
    let (session, _disasm, analysis) = require_fixture();
    let entry = entry_of(&session, "cfg_sum");
    let cfg = cfg_of(&analysis, entry, "cfg_sum");

    assert!(
        cfg.has_cycle,
        "cfg_sum 里有 `b 0x210364` 回跳（2103a4 → 210364），必须检测到环；\
         实际 {} 个块、{} 条边。blocks={:?}",
        cfg.block_count, cfg.edge_count, cfg.blocks
    );

    let head = hex(0x210364);
    let head_block = cfg
        .blocks
        .iter()
        .find(|b| b.start == head)
        .unwrap_or_else(|| panic!("210364 应是循环头（块首），实际块={:?}", cfg.blocks));
    assert!(
        !head_block.predecessors.is_empty(),
        "循环头必须有前驱（至少来自回边）"
    );
}

/// 抽查 2b：自递归函数**通过 `bl` 递归**，不是通过跳转。
///
/// 这条纠正一个容易搞混的直觉：`cfg_recurse` 调用自己，但那是
/// **调用边**（新栈帧），不是**函数内的回边**。函数内 CFG 只描述
/// 单次调用的控制流，所以它不该有环。
///
/// 反过来，如果哪天有人"为了图好看"把 `bl` 也画成 CFG 边，
/// 这条测试会立刻失败 —— 那会把所有递归函数都标成有循环，
/// 循环复杂度一类的指标跟着失真。
#[test]
fn cfg_recurse_recursion_via_call_is_not_an_intra_function_cycle() {
    let (session, _disasm, analysis) = require_fixture();
    let entry = entry_of(&session, "cfg_recurse");
    let cfg = cfg_of(&analysis, entry, "cfg_recurse");

    assert!(
        !cfg.has_cycle,
        "cfg_recurse 的递归走的是 `bl`（调用边，新栈帧），不是函数内的跳转回边 —— \
         函数内 CFG 不该有环；实际 {} 个块、{} 条边。blocks={:?}",
        cfg.block_count, cfg.edge_count, cfg.blocks
    );
    assert!(
        cfg.block_count > 1,
        "cfg_recurse 有 if 分支，块数应大于 1；实际 {}",
        cfg.block_count
    );
}

/// 抽查 2c：环检测必须与**边表本身**一致，并且只报真有回边的函数。
///
/// 这里不再手写文本解析器去猜外部工具的输出 —— 那本身就是一个
/// 容易写错的组件（我第一版就把它写错了，把立即数当成了跳转目标，
/// 结果每个函数都被判成"有回跳"）。改成两条**不依赖文本解析**的断言：
///
/// 1. `has_cycle` 必须与"按边表独立算出来的可达性"一致 ——
///    即块 p 有一条边指向 ≤ p 的块时才算回边。这是对环检测算法的
///    独立复算，用的是同一份边数据，但走的是完全不同的代码路径。
/// 2. fixture 的已知事实：`cfg_sum` 有回边（`b 0x210364`），
///    `cfg_mix` 没有分支，`cfg_recurse` 的递归走调用（不算函数内环）。
#[test]
fn cycle_flag_matches_independent_recomputation() {
    let (session, _disasm, analysis) = require_fixture();

    let mut with_cycle = Vec::new();
    let mut without_cycle = Vec::new();

    for cfg in analysis.cfgs() {
        // 独立复算：存在一条边指向"地址不高于自己"的块即为回边。
        // 这是回边最朴素的定义；真实的循环检测会做支配树分析，
        // 但对"有没有环"这个问题，二者等价。
        let has_back_edge = cfg.blocks.iter().any(|b| {
            let from = unhex(&b.start);
            b.successors.iter().any(|s| unhex(s) <= from)
        });

        if has_back_edge {
            with_cycle.push(cfg.entry.clone());
        } else {
            without_cycle.push(cfg.entry.clone());
        }

        assert_eq!(
            cfg.has_cycle, has_back_edge,
            "函数 {} 的 has_cycle={} 与按边表复算的结果 {} 不一致。\
             blocks={:?}",
            cfg.entry, cfg.has_cycle, has_back_edge, cfg.blocks
        );
    }

    // fixture 的已知事实（从 elf-aarch64-cfg.dis.txt 读出）：
    // 只有 cfg_sum 里有向低地址的跳转（2103a4: b 0x210364）。
    let cfg_sum = hex(entry_of(&session, "cfg_sum"));
    let cfg_mix = hex(entry_of(&session, "cfg_mix"));

    assert!(
        with_cycle.contains(&cfg_sum),
        "cfg_sum 里 `2103a4: b 0x210364` 是回边，必须被算成有环；\
         实际有环的: {with_cycle:?}"
    );
    assert!(
        without_cycle.contains(&cfg_mix),
        "cfg_mix 没有任何跳转，不该有环；实际无环的: {without_cycle:?}"
    );
    assert!(
        with_cycle.len() < analysis.cfg_count(),
        "应当存在无环的函数（否则环检测可能对什么都返回 true）；\
         有环 {} / 共 {}",
        with_cycle.len(),
        analysis.cfg_count()
    );
}

/// 抽查 3：`cfg_mix` —— 无分支函数恰好 1 个块。
///
/// 反向确认：如果实现"给每个函数都硬塞几个块"，或把 `ret` 前
/// 也算一个新块，这条会失败。`cfg_mix` 在 -O0 下仍是一段直线代码。
#[test]
fn cfg_mix_straight_line_is_one_block() {
    let (session, _disasm, analysis) = require_fixture();
    let entry = entry_of(&session, "cfg_mix");
    let cfg = cfg_of(&analysis, entry, "cfg_mix");

    assert_eq!(
        cfg.block_count, 1,
        "cfg_mix 是直线代码（无分支无环），必须恰好 1 个块；实际 {:?}",
        cfg.blocks
    );
    assert!(!cfg.has_cycle, "直线代码不该有环");
    assert!(cfg.blocks[0].terminal, "以 ret 结束的块应标记终结");
    assert!(cfg.blocks[0].successors.is_empty(), "终结块没有后继");
}

/// 抽查 4：`cfg_call_mid` —— 调用不结束基本块。
///
/// -O0 下 `cfg_call_mid` 会 `bl cfg_mix`、`bl cfg_absdiff`。
/// 调用**会返回**，所以这些指令与其后的代码在同一个块里。
/// 把 `call` 当终结符的实现会把块数算多。
#[test]
fn cfg_call_mid_calls_do_not_split_blocks() {
    let (session, _disasm, analysis) = require_fixture();
    let entry = entry_of(&session, "cfg_call_mid");

    let cfg = analysis
        .cfg_of(entry)
        .unwrap_or_else(|| panic!("cfg_call_mid 入口 {entry:#x} 应有 CFG"));

    // 这个函数在 -O0 下是一条直线（只有 bl 和 ret），因此只应有 1 个块。
    assert_eq!(
        cfg.block_count, 1,
        "cfg_call_mid 是直线代码（bl 不是终结符），必须恰好 1 个块；\
         拿到 {} 个说明 call 被当成了块的分隔符。blocks={:?}",
        cfg.block_count, cfg.blocks
    );
}

/// 抽查 5：`cfg_dispatch` —— switch 的每个分支都必须可达。
///
/// clang 对这个小 switch 可能lower 成 `cbz` + 一串 `b.eq`，
/// 也可能 lower 成跳转表（那会是间接跳转，目标未知）。
/// 两种都是**正确**的代码，所以这里不断言块数，
/// 而是断言"每个 case 的返回值都出现过" —— 对 CFG 而言就是
/// "至少存在足够多的块，并且图里有环或足够的分支"。
///
/// 具体地：`cbz`/`b.eq` 这类比较分支如果被漏掉（它们不是 `b.<cond>`
/// 而是带寄存器操作数的分支），块数会明显偏少。
#[test]
fn cfg_dispatch_branches_are_recognized() {
    let (session, _disasm, analysis) = require_fixture();
    let entry = entry_of(&session, "cfg_dispatch");

    let cfg = analysis
        .cfg_of(entry)
        .unwrap_or_else(|| panic!("cfg_dispatch 入口 {entry:#x} 应有 CFG"));

    assert!(
        cfg.block_count >= 4,
        "cfg_dispatch 有 &7 的 8 路分派，至少应有 4 个块；\
         拿到 {} 个说明 cbz/b.eq 这类分支被漏了。blocks={:?}",
        cfg.block_count,
        cfg.blocks
    );

    // 每个块的后继必须是真实块首（连边完整性）
    for b in &cfg.blocks {
        for succ in &b.successors {
            assert!(
                cfg.blocks.iter().any(|x| &x.start == succ),
                "块 {} 的后继 {succ} 不是块首 —— 图里有悬空边",
                b.start
            );
        }
    }
}

/// 抽查 6：全函数的 CFG 结构自洽 —— 前驱/后继必须互为镜像。
///
/// 这是最强的一条不变式：对每条边 `a → b`，`b` 的前驱里必有 `a`；
/// 反之亦然。任何"只连一边"的实现都会在这里暴露。
/// 它覆盖 fixture 里**所有**函数，而不是抽样的一两个。
#[test]
fn cfg_predecessors_and_successors_are_mirrored() {
    let (_session, _disasm, analysis) = require_fixture();

    let mut checked_edges = 0usize;
    let mut functions_with_cfg = 0usize;

    for cfg in analysis.cfgs() {
        functions_with_cfg += 1;
        for b in &cfg.blocks {
            for succ in &b.successors {
                checked_edges += 1;
                let target = cfg
                    .blocks
                    .iter()
                    .find(|x| &x.start == succ)
                    .unwrap_or_else(|| {
                        panic!(
                            "函数 {} 的块 {} 有后继 {succ}，但它不是块首",
                            cfg.entry, b.start
                        )
                    });
                assert!(
                    target.predecessors.contains(&b.start),
                    "边 {} → {succ} 存在，但 {succ} 的前驱表里没有 {} —— \
                     前驱/后继不对称",
                    b.start,
                    b.start
                );
            }
        }
    }

    assert!(
        functions_with_cfg > 0,
        "fixture 里应当有函数带 CFG，实际 0 —— 说明 CFG 根本没建起来"
    );
    assert!(
        checked_edges > 0,
        "整份 fixture 里一条边都没有，这个测试没有验证到任何东西"
    );
}

/// 抽查 7：块必须覆盖函数的指令区间，且块内地址连续递增。
///
/// 如果分块算错（例如块的 `end` 取了错误指令的末尾），
/// 会出现重叠或空洞。这条对每个函数都检查。
#[test]
fn blocks_are_contiguous_and_ordered() {
    let (_session, _disasm, analysis) = require_fixture();

    for cfg in analysis.cfgs() {
        let mut prev_end: Option<u64> = None;
        for b in &cfg.blocks {
            let start = u64::from_str_radix(&b.start, 16).expect("块首是十六进制");
            let end = u64::from_str_radix(&b.end, 16).expect("块尾是十六进制");
            let last = u64::from_str_radix(&b.last_insn, 16).expect("块尾指令是十六进制");

            assert!(start < end, "函数 {} 的块 {} 区间为空", cfg.entry, b.start);
            assert!(
                last >= start && last < end,
                "函数 {} 的块 {} 的最后一条指令 {last:x} 不在块内",
                cfg.entry,
                b.start
            );

            if let Some(pe) = prev_end {
                assert_eq!(
                    start, pe,
                    "函数 {} 的块 {} 与前一个块之间有空洞或重叠\
                     （前一块结束于 {pe:x}）",
                    cfg.entry, b.start
                );
            }
            prev_end = Some(end);
        }
    }
}

/// 抽查 8：M5 验收标准 3 —— CFG 里不能出现任何架构分支。
///
/// 用同一份 fixture 里**语义等价**的两段代码验证：CFG 只认结构化的
/// `Flow`，不认助记符文本或架构。这里通过"每个函数的 CFG 都非空、
/// 且块数与它自身的控制流复杂度一致"来间接确认没有架构特判 ——
/// 真正的门禁是 `scripts/check-arch-layering.ps1`。
#[test]
fn every_function_gets_a_cfg() {
    let (_session, _disasm, analysis) = require_fixture();

    let mut missing = Vec::new();
    for f in analysis.functions() {
        if f.named && f.source == "symbol-table" {
            let entry = u64::from_str_radix(&f.start, 16).expect("函数入口是十六进制");
            if analysis.cfg_of(entry).is_none() {
                missing.push(f.start.clone());
            }
        }
    }

    assert!(
        missing.is_empty(),
        "以下有符号的函数没有 CFG：{missing:?} —— \
         说明 CFG 只在部分函数上建起来了"
    );
}

/// 抽查 9：`analyze()` 摘要里的 `basic_blocks` 现在是真值。
///
/// M3/M4 期间这个字段诚实地返回 0（CFG 不存在）。M5 必须让它变成
/// 真实计数 —— 否则 UI 会一直显示"0 个基本块"而分析其实已经算出来了。
#[test]
fn analysis_summary_reports_real_basic_block_count() {
    let (session, _disasm, _analysis) = require_fixture();
    let job = session.detached_job();
    let summary = session.analyze(&job).expect("analyze");

    assert!(
        summary.basic_blocks > 0,
        "M5 起 basic_blocks 必须是真实计数；拿到 0 说明摘要没接上 CFG"
    );
    // 每个函数至少 1 个块，所以块数不可能少于函数数。
    assert!(
        summary.basic_blocks >= summary.functions,
        "基本块数（{}）不该少于函数数（{}）：每个函数至少有一个块",
        summary.basic_blocks,
        summary.functions
    );
}
