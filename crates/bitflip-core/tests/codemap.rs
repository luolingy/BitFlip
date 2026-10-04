//! M6 验收标准 2：数据/代码误判率有量化指标与**回归门禁**。
//!
//! # 黄金标准从哪来
//!
//! `tests/fixtures/generated/codemap-x86_64.exe.truth.txt`，由
//! `scripts/gen-codemap-fixture.py` 生成：
//!
//! * **代码**范围来自 PE 的 `.pdata` 展开表（`llvm-readobj --unwind`）——
//!   这是**编译器写死的**函数起止，不是我们推断的。
//! * **数据**地址来自 COFF 符号表里 `R`/`D` 类型的 `cm_*` 符号。
//! * 数据的内容**刻意做成 x86_64 函数序言的字节**（`55 48 89 e5 …`）。
//!   如果数据是随机的零，任何判定器都能轻易说"这不是代码"，
//!   测不出真问题 —— 而"看起来像指令的数据"正是真实样本里的陷阱
//!   （跳转表、常量池、字符串常量区）。
//!
//! # 门禁怎么设
//!
//! 误判率超过阈值**测试失败**。阈值取 0（不许有误判）：
//! fixture 是精心构造的小样本，任何误判都说明规则有缺陷。
//! 真实大样本上的表现另用 `#[ignore]` 的统计测试观察，不作为门禁
//! （大样本没有黄金标准，只能看趋势）。

use std::collections::HashSet;
use std::path::PathBuf;

use bitflip_analyze::{compare_with_truth, judge_code_many, CodeFacts, RegionKind};
use bitflip_core::{OpenOptions, Session};

/// 黄金标准里的一条标注。
#[derive(Debug, Clone)]
struct TruthEntry {
    addr: u64,
    is_code: bool,
    name: String,
}

fn fixture(name: &str) -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("..")
        .join("..")
        .join("tests")
        .join("fixtures")
        .join("generated")
        .join(name)
}

/// 读黄金标准；缺失时**响亮失败**而不是静默跳过。
fn load_truth() -> Vec<TruthEntry> {
    let path = fixture("codemap-x86_64.exe.truth.txt");
    assert!(
        path.exists(),
        "缺少黄金标准 {}：\n\
         生成方式：python scripts/gen-codemap-fixture.py \
         --out tests/fixtures/generated/codemap-x86_64.exe",
        path.display()
    );
    let text = std::fs::read_to_string(&path).expect("读黄金标准");
    let mut out = Vec::new();
    for line in text.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let mut parts = line.split_whitespace();
        let (Some(addr), Some(kind)) = (parts.next(), parts.next()) else {
            continue;
        };
        let name = parts.next().unwrap_or("").to_string();
        let Ok(addr) = u64::from_str_radix(addr, 16) else {
            continue;
        };
        out.push(TruthEntry {
            addr,
            is_code: kind == "code",
            name,
        });
    }
    assert!(!out.is_empty(), "黄金标准为空 —— 生成脚本可能坏了");
    out
}

fn open_fixture() -> Session {
    let path = fixture("codemap-x86_64.exe");
    assert!(
        path.exists(),
        "缺少 fixture {}：见 scripts/gen-codemap-fixture.py",
        path.display()
    );
    Session::open(&path, OpenOptions::default()).expect("打开 codemap fixture")
}

/// 构建判定所需的真实事实源。
struct RealFacts {
    functions: Vec<(u64, Option<u64>)>,
    reachable: HashSet<u64>,
    branch_targets: HashSet<u64>,
    decode_runs: std::collections::HashMap<u64, u32>,
    /// `(起始, 结束, 是否可执行)` —— 来自地址空间的段。
    exec_ranges: Vec<(u64, u64, bool)>,
}

impl RealFacts {
    fn build(session: &Session) -> Self {
        let job = session.detached_job();
        let analysis = session.analysis(&job).expect("分析");

        let functions: Vec<(u64, Option<u64>)> = analysis
            .functions()
            .iter()
            .filter_map(|f| {
                let start = bitflip_core::parse_address(&f.start)?;
                let end = f.end.as_deref().and_then(bitflip_core::parse_address);
                Some((start, end))
            })
            .collect();

        let mut reachable = HashSet::new();
        let mut decode_runs = std::collections::HashMap::new();
        let disasm = session
            .disassemble(bitflip_core::DisasmScanOptions::default())
            .expect("反汇编");

        for (addr, _len) in disasm.space.index().range(0, u64::MAX) {
            reachable.insert(addr);
            decode_runs.insert(addr, count_run(&disasm, addr));
        }

        // 跳转/调用目标直接从反汇编里取：`DecodedInsn::target` 就是
        // "这条跳转去哪"。比从 xref 表反推更直接，也不依赖 xref 的
        // 收录规则（那条规则本身还在演进）。
        let mut branch_targets = HashSet::new();
        for (addr, len) in disasm.space.index().range(0, u64::MAX) {
            let Some(bytes) = disasm.space.read(addr, usize::from(len)) else {
                continue;
            };
            let Ok(insn) = disasm.decoder.decode_one(&bytes, addr) else {
                continue;
            };
            if let Some(t) = insn.target {
                if matches!(
                    insn.flow,
                    bitflip_arch::Flow::Branch { .. } | bitflip_arch::Flow::Call
                ) {
                    branch_targets.insert(t);
                }
            }
        }

        let exec_ranges = disasm
            .space
            .segments()
            .iter()
            .map(|s| (s.vaddr, s.vaddr + s.vsize, s.perms.execute))
            .collect();

        Self {
            functions,
            reachable,
            branch_targets,
            decode_runs,
            exec_ranges,
        }
    }
}

/// 从某地址起连续能解出多少条指令（最多 32 条）。
fn count_run(disasm: &bitflip_core::Disasm, start: u64) -> u32 {
    let mut addr = start;
    let mut n = 0u32;
    while n < 32 {
        // 必须正好是一条已索引指令的起点，否则连续性断了。
        let Some((insn_start, len)) = disasm.space.index().containing(addr) else {
            break;
        };
        if insn_start != addr {
            break;
        }
        let Some(bytes) = disasm.space.read(addr, usize::from(len)) else {
            break;
        };
        if disasm.decoder.decode_one(&bytes, addr).is_err() {
            break;
        }
        addr = addr.saturating_add(u64::from(len));
        n += 1;
    }
    n
}

/// 把 `RealFacts` 适配成判定器要的 `CodeFacts`。
struct Facts<'a> {
    inner: &'a RealFacts,
}

impl CodeFacts for Facts<'_> {
    fn in_executable_section(&self, addr: u64) -> Option<bool> {
        // 用地址空间的**段**权限回答（有类型化的 `perms.execute`）。
        // 取不到就返回 `None` —— 判定器会据此拒绝下"数据"结论，
        // 而不是把"没找到"当成"不在可执行段"。
        self.inner
            .exec_ranges
            .iter()
            .find(|(lo, hi, _)| addr >= *lo && addr < *hi)
            .map(|&(_, _, exec)| exec)
    }

    fn in_unwind_range(&self, addr: u64) -> bool {
        // 用展开表来源的函数范围（`FunctionWire` 里带 `end` 的那些）。
        // 这是最强的代码证据，必须真的接上 —— 早先这里直接返回 false
        // 等于把最强证据旁路了，测试就测不到它。
        self.inner
            .functions
            .iter()
            .any(|&(start, end)| end.is_some_and(|e| addr >= start && addr < e))
    }

    fn is_function_entry(&self, addr: u64) -> bool {
        self.inner.functions.iter().any(|&(start, _)| start == addr)
    }

    fn inside_known_function(&self, addr: u64) -> bool {
        self.inner
            .functions
            .iter()
            .any(|&(start, end)| end.is_some_and(|e| addr >= start && addr < e))
    }

    fn is_reachable(&self, addr: u64) -> bool {
        self.inner.reachable.contains(&addr)
    }

    fn is_branch_target(&self, addr: u64) -> bool {
        self.inner.branch_targets.contains(&addr)
    }

    fn decode_run(&self, addr: u64) -> u32 {
        self.inner.decode_runs.get(&addr).copied().unwrap_or(0)
    }
}

/// **验收标准 2**：误判率为 0。
///
/// 门禁阈值取 0，因为 fixture 是精心构造的小样本 —— 任何误判都说明
/// 规则有缺陷，而不是"样本太难"。真实大样本上没有黄金标准，
/// 只看趋势（见下面的 `#[ignore]` 统计测试）。
#[test]
fn code_data_error_rate_is_zero_on_the_golden_fixture() {
    let truth = load_truth();
    let session = open_fixture();
    let real = RealFacts::build(&session);
    let facts = Facts { inner: &real };

    let addrs: Vec<u64> = truth.iter().map(|t| t.addr).collect();
    let judgements = judge_code_many(&facts, &addrs);
    let pairs: Vec<(u64, bool)> = truth.iter().map(|t| (t.addr, t.is_code)).collect();
    let rate = compare_with_truth(&judgements, &pairs);

    // 打印每条判定，失败时能直接看出是哪一条错了。
    for (j, t) in judgements.iter().zip(truth.iter()) {
        let want = if t.is_code { "code" } else { "data" };
        eprintln!(
            "{:#x} {}  期望={} {}  conf={}  理由={}",
            j.addr,
            j.kind.as_str(),
            want,
            t.name,
            j.confidence,
            j.reason_zh()
        );
    }

    assert!(
        rate.decided() >= 10,
        "只有 {} 条被明确判定，样本太小不足以说明问题（总数 {}）",
        rate.decided(),
        truth.len()
    );

    assert_eq!(
        rate.false_positive,
        0,
        "有 {} 个数据地址被判成代码（误报）。这是最有害的错误：\
         会造出不存在的函数。误报率 = {:.3}",
        rate.false_positive,
        rate.false_positive_rate()
    );
    assert_eq!(
        rate.false_negative,
        0,
        "有 {} 个代码地址被判成数据（漏报）。误判率 = {:.3}",
        rate.false_negative,
        rate.rate()
    );
}

/// 判定结果必须带**可核对的理由**。
///
/// 只给结论的判定器用户无法质疑，也就无法信任。这条要求每个非
/// `Unknown` 的结论都能说出"凭什么"。
#[test]
fn every_conclusion_carries_a_checkable_reason() {
    let truth = load_truth();
    let session = open_fixture();
    let real = RealFacts::build(&session);
    let facts = Facts { inner: &real };

    let addrs: Vec<u64> = truth.iter().map(|t| t.addr).collect();
    for j in judge_code_many(&facts, &addrs) {
        if j.kind == RegionKind::Unknown {
            continue;
        }
        assert!(
            !j.evidence.is_empty(),
            "{:#x} 判为 {} 却没有任何证据",
            j.addr,
            j.kind.as_str()
        );
        assert!(
            j.is_well_supported(),
            "{:#x} 判为 {} 但缺少高可信证据（只有弱证据不该下结论）：{:?}",
            j.addr,
            j.kind.as_str(),
            j.evidence
        );
        let reason = j.reason_zh();
        assert!(
            !reason.is_empty() && !reason.contains("没有任何证据"),
            "{:#x} 的理由为空或自相矛盾：{reason}",
            j.addr
        );
    }
}

/// "像指令的数据"不能被判成代码 —— 这是本 fixture 的核心检验。
///
/// 单独拎出来测，因为它是**最容易被放松**的一条：`cm_looks_like_code_*`
/// 的内容是 `55 48 89 e5 48 83 ec 20 …`，从这些地址开始解码完全能
/// 解出一长串合法指令。只要有谁把"能解码"当成充分条件，这条就会红。
#[test]
fn data_that_decodes_cleanly_is_still_data() {
    let truth = load_truth();
    let session = open_fixture();
    let real = RealFacts::build(&session);
    let facts = Facts { inner: &real };

    let fake_code: Vec<&TruthEntry> = truth
        .iter()
        .filter(|t| !t.is_code && t.name.contains("looks_like_code"))
        .collect();
    assert!(
        !fake_code.is_empty(),
        "fixture 里应当有刻意做成指令样子的数据数组"
    );

    let addrs: Vec<u64> = fake_code.iter().map(|t| t.addr).collect();
    for j in judge_code_many(&facts, &addrs) {
        assert_ne!(
            j.kind,
            RegionKind::Code,
            "{:#x} 是数据（数组 {} 内），尽管它看起来像指令序言 —— \
             不能因为'能解码'就判成代码。证据：{:?}",
            j.addr,
            fake_code
                .iter()
                .find(|t| t.addr == j.addr)
                .map(|t| t.name.as_str())
                .unwrap_or("?"),
            j.evidence
        );
    }
}

/// **反证**：朴素的"能解码就是代码"规则在这个 fixture 上会失败。
///
/// 这条测试不检验我们的判定器，而是检验**测试本身有没有意义**：
/// 如果 fixture 里的数据根本解不出指令，那
/// `data_that_decodes_cleanly_is_still_data` 就是空测试 ——
/// 它在验证一件不可能发生的事。
///
/// 实测 `cm_looks_like_code_0` 的字节是
/// `55 48 89 e5 48 83 ec 20 48 8d 3d 00 00 00 00`，能连续解出
/// `push rbp` / `mov rbp,rsp` / `sub rsp,0x20` / `lea rdi,[rip+0]`。
/// 所以"能解码"确实**不能**作为代码的充分条件。
#[test]
fn the_trap_data_really_does_decode_as_instructions() {
    let session = open_fixture();
    let disasm = session
        .disassemble(bitflip_core::DisasmScanOptions::default())
        .expect("反汇编");

    // 取一个 data 标注里的"像代码"地址
    let truth = load_truth();
    let trap = truth
        .iter()
        .find(|t| !t.is_code && t.name.contains("looks_like_code"))
        .expect("fixture 里应当有像代码的数据");

    let mut addr = trap.addr;
    let mut decoded = 0;
    while decoded < 8 {
        let Some(bytes) = disasm.space.read(addr, 16) else {
            break;
        };
        let Ok(insn) = disasm.decoder.decode_one(&bytes, addr) else {
            break;
        };
        addr += u64::from(insn.len);
        decoded += 1;
    }

    assert!(
        decoded >= 8,
        "{:#x} 处的数据只解出 {decoded} 条指令。\
         这个 fixture 的意义在于'像指令的数据'，若它解不出来，\
         `data_that_decodes_cleanly_is_still_data` 就成了空测试。\
         请检查 scripts/gen-codemap-fixture.py 的 DATA_PREAMBLE。",
        trap.addr
    );

    // 同时确认它**不在**指令索引里 —— 这正是判定器据以区分两者的依据。
    assert!(
        disasm
            .space
            .index()
            .containing(trap.addr)
            .is_none_or(|(start, _)| start != trap.addr),
        "{:#x} 不该被扫描认定为指令起点（它是数据）",
        trap.addr
    );
}
/// 真实大样本上的判定分布。
///
/// **不作为门禁**（没有黄金标准可对），只用来观察比例是否合理。
///
/// 采样必须同时覆盖代码侧与数据侧 —— 只取函数入口的话结果必然是
/// "200/200 全是代码"，什么也说明不了（第一版就是这样）。
///
/// 跑法：`cargo test -p bitflip-core --test codemap -- --ignored --nocapture`
#[test]
#[ignore = "需要真实系统文件，且没有黄金标准，只作观察"]
fn real_target_judgement_distribution() {
    let candidates = [
        r"C:\Windows\System32\ntdll.dll",
        r"C:\Windows\System32\kernel32.dll",
    ];
    for path in candidates {
        let p = PathBuf::from(path);
        if !p.exists() {
            eprintln!("跳过（不存在）：{path}");
            continue;
        }
        let Ok(session) = Session::open(&p, OpenOptions::default()) else {
            eprintln!("跳过（打不开）：{path}");
            continue;
        };
        let real = RealFacts::build(&session);
        let facts = Facts { inner: &real };
        let disasm = session
            .disassemble(bitflip_core::DisasmScanOptions::default())
            .expect("反汇编");

        // 代码侧：函数入口
        let mut addrs: Vec<u64> = real.functions.iter().take(100).map(|&(a, _)| a).collect();
        // 数据侧：非可执行段的地址
        for (lo, hi, exec) in &real.exec_ranges {
            if *exec {
                continue;
            }
            for off in [0u64, 1, 16, 64] {
                let a = lo.saturating_add(off);
                if a < *hi {
                    addrs.push(a);
                }
            }
        }
        // 代码中间地址（扫到过但不一定是函数入口）
        let indexed: Vec<u64> = disasm
            .space
            .index()
            .range(0, u64::MAX)
            .map(|(a, _)| a)
            .take(3000)
            .collect();
        for a in indexed.into_iter().step_by(50).take(60) {
            addrs.push(a);
        }

        let js = judge_code_many(&facts, &addrs);
        let (mut code, mut data, mut unknown, mut unsupported) = (0, 0, 0, 0);
        for j in &js {
            match j.kind {
                RegionKind::Code => code += 1,
                RegionKind::Data => data += 1,
                RegionKind::Unknown => unknown += 1,
            }
            if j.kind != RegionKind::Unknown && !j.is_well_supported() {
                unsupported += 1;
            }
        }
        eprintln!(
            "{path}: 判定 {} 个地址 → 代码 {code} / 数据 {data} / 未判定 {unknown}；\
             下了结论但缺高可信证据的：{unsupported}",
            js.len()
        );
    }
}
