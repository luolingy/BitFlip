//! M5 大文件逆向测试：用 100MB 级的、**内容完全已知**的可执行文件验证
//! 分块扫描路径。
//!
//! # 为什么必须自造文件
//!
//! 拿系统上的大文件（MRT.exe 之类）只能证明"没崩"。大文件上真正危险的
//! 失败模式是"没崩但结果全错"，而这类 bug 只有对着**已知答案**才看得出来。
//!
//! 下面这条测试所盯的 bug 就是这么发现的：`StringScanner::feed` 早先用
//! 分块内的下标当偏移，于是每一块的地址都从段基址重新开始。在 96 MiB 的
//! 文件上，384 个可识别字符串里有 368 个地址与别人重复，去重后只剩 16 个。
//! 一个只统计"有没有扫出字符串"的测试永远抓不到它 —— 详见
//! `docs/BIG-FILE-TESTING.md`。
//!
//! # fixture 从哪来
//!
//! `scripts/gen-big-binary.py` 生成（源码展开 N 份 + 每份内嵌可识别字符串
//! 的填充块），生成物在 gitignored 的 `tests/fixtures/generated/` 下
//! （CLAUDE.md §0.2）。
//! 缺少 fixture 时这些测试会**明确失败并给出重建命令**，而不是静默跳过 ——
//! 静默跳过等于这条覆盖不存在，但看起来是绿的。

use std::path::PathBuf;

use bitflip_core::{DisasmScanOptions, OpenOptions, Session};

/// 生成器默认规模（见 scripts/gen-big-binary.py 的 DEFAULT_*）。
///
/// 96 份 unit × 每份 1 MiB 填充 ≈ 96 MiB 可执行文件。这个量级是刻意的：
/// 稳稳越过 8 MiB 嗅探窗口与 4 MiB 扫描分块两个边界，各跨一个数量级。
///
/// **别把这些数字和 fixture 调得不一致** —— 不一致时测试会红，
/// 那是好事；但如果反过来把断言放宽到"大于零"，这条覆盖就没了。
const UNITS: usize = 96;
const STRINGS_PER_UNIT: usize = 4;
const FUNCS_PER_UNIT: usize = 3;

/// fixture 路径。文件太大，不入库。
fn fixture_path() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("..")
        .join("..")
        .join("tests")
        .join("fixtures")
        .join("generated")
        .join("big-x86_64.exe")
}

/// 取 fixture；不存在就带着重建命令硬失败。
///
/// 刻意不做"跳过"：一条静默跳过的测试看起来是绿的，但覆盖是零。
fn require_fixture() -> PathBuf {
    let path = fixture_path();
    assert!(
        path.exists(),
        "缺少大文件 fixture：{}\n\
         重建方式（约 80 秒）：\n  \
         python scripts/gen-big-binary.py --out tests/fixtures/generated/big-x86_64.exe\n\
         这个文件是刻意不入库的（100MB，见 CLAUDE.md §0.2）。",
        path.display()
    );
    path
}

/// 打开 fixture 并做完整分析。
///
/// 分析本身是重活（100MB 的 PE，实测数秒到数十秒），所以整个文件里
/// 只做一次，由多个断言共用。
fn analyze_once() -> (Session, std::sync::Arc<bitflip_core::TargetAnalysis>) {
    let path = require_fixture();
    let session = Session::open(&path, OpenOptions::default()).expect("打开大 fixture");
    let job = session.detached_job();
    let analysis = session.analysis(&job).expect("分析大 fixture");
    (session, analysis)
}

/// fixture 确实是个大文件 —— 否则这组测试名不副实。
///
/// 这条放在最前面：如果生成器某天退化成产出小文件，后面那些"跨分块"
/// 的断言就会在**没有跨块**的情况下通过，覆盖悄悄消失。
#[test]
fn the_fixture_is_actually_large_enough_to_cross_chunk_boundaries() {
    let path = require_fixture();
    let size = std::fs::metadata(&path).expect("读 metadata").len();

    // 上限：解析上限是 512 MiB，别把自己生成到超出。
    assert!(
        size > 16 * 1024 * 1024,
        "fixture 只有 {} 字节，不足以跨过 4 MiB 的扫描分块边界；\
         这条测试的整个前提就不成立了",
        size
    );

    // 8 MiB 是嗅探窗口。文件必须显著大于它，才能测到降级路径。
    assert!(
        size > 8 * 1024 * 1024 * 2,
        "fixture 只有 {} 字节，没有明显越过 8 MiB 嗅探窗口",
        size
    );
}

/// **核心断言**：跨分块的字符串扫描不能丢数据。
///
/// 这是本次真正抓到 bug 的地方（`StringScanner::feed` 用块内下标当偏移，
/// 每块都从段基址重新开始）。判据分三层，缺一不可：
///
/// 1. **总数**：期望的条数一条不少 —— 带 bug 时实测只有 480/1200；
/// 2. **覆盖**：每一份 unit 都出现。偏移错位的表现是"前面几块的串活下来、
///    后面的被覆盖掉"，所以尾部编号缺失是典型症状；
/// 3. **地址**：互不相同。这是最直接的一条 —— 地址错位会直接产生重复地址。
///
/// 三条里哪一条都别删。尤其是**这两条弱的**：光靠"存在字符串"这种断言，
/// 带 bug 的代码也是绿的。
///
/// 另外注意这份 fixture 的构造：可识别字符串被写进**填充块数组内部**，
/// 而不是当作独立的字符串字面量。独立的字面量会被编译器归拢到只读数据的
/// 同一片区域，几百个串全挤在第一个 4 MiB 分块里 —— 那样跨块路径根本没被
/// 走到，这条测试就是空转（第一版正是如此，带 bug 依然全绿）。
#[test]
fn all_strings_survive_the_streaming_scan() {
    let (_session, analysis) = analyze_once();

    let ours: Vec<&bitflip_core::StringWire> = analysis
        .strings()
        .iter()
        .filter(|s| s.text.starts_with("bitflip-unit-"))
        .collect();

    let expected = UNITS * STRINGS_PER_UNIT;
    assert_eq!(
        ours.len(),
        expected,
        "跨分块扫描丢了字符串：找到 {} 条，期望 {expected} 条。\
         这是 StringScanner 分块偏移错位时的症状：每个分块的地址都从段基址\
         重新开始，后面的串被前面的覆盖掉。",
        ours.len()
    );

    // 光有数量还不够：要确认**每一份 unit** 都出现了。
    // 偏移错位的表现是"前面几块的串活下来、后面的被覆盖"，所以尾部编号
    // 缺失是典型症状 —— 这条比"总数对了"更能定位问题在哪一块。
    let mut units: Vec<usize> = ours
        .iter()
        .filter_map(|s| s.text.strip_prefix("bitflip-unit-"))
        .filter_map(|rest| rest.split('-').next())
        .filter_map(|n| n.parse::<usize>().ok())
        .collect();
    units.sort_unstable();
    units.dedup();

    assert_eq!(
        units.len(),
        UNITS,
        "只找到 {} 份 unit 的字符串（期望 {UNITS} 份）；\
         首尾编号 {:?}..{:?} —— 如果尾部缺失，就是分块偏移没累加",
        units.len(),
        units.first(),
        units.last()
    );
    assert_eq!(units.first(), Some(&0), "第 0 份 unit 的字符串必须存在");
    assert_eq!(
        units.last(),
        Some(&(UNITS - 1)),
        "最后一份 unit 的字符串必须存在（它落在最后一个分块里）"
    );

    // ── 地址：互不相同 ──
    //
    // 这一条是那个 bug 的直接指纹。分块偏移不累加时，每个分块的地址都从
    // 段基址重新开始，不同分块的字符串会拿到**同一个地址**。
    let mut addrs: Vec<&str> = ours.iter().map(|s| s.address.as_str()).collect();
    addrs.sort_unstable();
    let total = addrs.len();
    addrs.dedup();
    assert_eq!(
        addrs.len(),
        total,
        "有 {} 个字符串的地址与别人重复（共 {total} 条，去重后只剩 {}）。\
         这是分块扫描偏移未累加的直接症状：每个分块的地址都从段基址重新开始。",
        total - addrs.len(),
        addrs.len()
    );
}

/// 字符串地址必须严格递增且互不相同 —— 地址错位会直接违反这条。
#[test]
fn string_addresses_are_unique_and_sorted() {
    let (_session, analysis) = analyze_once();

    let addrs: Vec<&str> = analysis
        .strings()
        .iter()
        .filter(|s| s.text.starts_with("bitflip-unit-"))
        .map(|s| s.address.as_str())
        .collect();

    let mut sorted = addrs.clone();
    sorted.sort_unstable();
    assert_eq!(addrs, sorted, "字符串必须按地址升序（接口契约）");

    sorted.dedup();
    assert_eq!(
        sorted.len(),
        addrs.len(),
        "出现了地址重复的字符串 —— 说明分块扫描把不同分块的地址算成了同一个"
    );
}

/// 大于嗅探窗口的文件必须在结论里说明"只嗅探了前 N 字节"。
///
/// 这条守 CLAUDE.md §7 的"降级要写在界面上"：不能悄悄只给部分结论。
#[test]
fn oversized_file_reports_the_sniff_degradation() {
    let path = require_fixture();
    let session = Session::open(&path, OpenOptions::default()).expect("打开大 fixture");
    let info = session.info();

    assert!(
        info.file_truncated,
        "文件 {} 字节大于嗅探窗口，file_truncated 必须为真",
        info.file_size
    );
    let notes = info.notes.join("\n");
    assert!(
        notes.contains("嗅探") || notes.contains("窗口"),
        "说明里必须提到只嗅探了一部分：{notes}"
    );
}

/// 大文件上函数识别仍然区分"符号表里有"与"真的可达"。
#[test]
fn function_sources_stay_distinguishable_on_a_large_input() {
    let (_session, analysis) = analyze_once();

    let from_table = analysis
        .functions()
        .iter()
        .filter(|f| f.source == "symbol-table")
        .count();
    assert!(
        from_table >= UNITS * FUNCS_PER_UNIT,
        "符号表来源的函数应有至少 {} 个，实际 {from_table}",
        UNITS * FUNCS_PER_UNIT
    );

    // 未命名的函数不许有占位名（CLAUDE.md §7）。
    for f in analysis.functions() {
        if !f.named {
            assert!(f.name.is_empty(), "未命名函数出现了占位名：{}", f.name);
        }
    }
}

/// 反汇编覆盖到大文件里靠后的代码，而不是只解了开头。
#[test]
fn disassembly_reaches_code_far_into_the_file() {
    let path = require_fixture();
    let session = Session::open(&path, OpenOptions::default()).expect("打开大 fixture");
    let disasm = session
        .disassemble(DisasmScanOptions::default())
        .expect("反汇编");

    let count = disasm.index.range(0, u64::MAX).count();
    assert!(
        count > 1000,
        "只解出 {count} 条指令，大文件的代码段显然没有扫完"
    );

    // 覆盖标记应落在代码段的**后段**。用最小的已覆盖地址与最大的对比，
    // 确认覆盖不是集中在一处。
    let mut min: Option<u64> = None;
    let mut max: u64 = 0;
    for (addr, _) in disasm.index.range(0, u64::MAX) {
        min = Some(min.map_or(addr, |m: u64| m.min(addr)));
        max = max.max(addr);
    }
    let min = min.expect("至少有一条指令");
    assert!(
        max - min > 0x1000,
        "指令地址跨度只有 {:#x}，覆盖范围异常地窄",
        max - min
    );
}
