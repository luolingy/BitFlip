//! M6 跳转表识别验收：目标集合与编译器实际生成的**完全一致**。
//!
//! # 黄金数据怎么来的（重要）
//!
//! PLAN M6 验收标准 1 要求"跳转表 fixture 的目标集合与编译器实际生成的
//! 完全一致（黄金快照）"。为了让这条标准真的有意义，黄金数据**不是**
//! 用我们自己的分析器导出的 —— 那样只是"自己跟自己对答案"。
//!
//! 获取方式（可复现）：
//!
//! ```text
//! python scripts/gen-jump-table-fixture.py --out tests/fixtures/generated/switch-x86_64.exe --keep-source
//! llvm-objdump -d --no-show-raw-insn tests/fixtures/generated/switch-x86_64.exe
//! llvm-objdump -s --section=.rdata tests/fixtures/generated/switch-x86_64.exe
//! ```
//!
//! 从反汇编读出表基址与跳转序列：
//!
//! ```text
//!   14000104f:  leaq 0xfaa(%rip), %rcx   # 0x140002000   <- 表基址
//!   140001056:  movslq (%rcx,%rax,4), %rax               <- 4 字节有符号项
//!   14000105a:  addq %rcx, %rax                          <- 项加到基址上
//!   14000105d:  jmpq *%rax                               <- 间接跳转
//! ```
//!
//! 从 `.rdata` 读出 0x140002000 处的 16 个 32 位小端值，每个值按
//! **有符号**解释后加到表基址，得到下面这组目标地址。
//!
//! 这组数字**写死在测试里**（而不是运行时再算一遍），这样分析器改了
//! 之后必须显式地改这份期望值 —— 黄金快照的意义就在这里。

use std::collections::BTreeSet;
use std::path::PathBuf;

use bitflip_core::{OpenOptions, Session};

/// 跳转表在 fixture 里的基址（`leaq 0xfaa(%rip)` 算出来的）。
const TABLE_BASE: u64 = 0x140002000;

/// 间接跳转指令的地址。
const JUMP_INSN: u64 = 0x14000105d;

/// **编译器实际生成的**目标集合，由 `.rdata` 原始字节换算而来。
///
/// 顺序即表序（索引 0..15），测试会与识别结果做集合比较。
///
/// 来源（可复核）：`llvm-objdump -s --section=.rdata` 输出
/// ```text
///   140002000 5ff0ffff 24f1ffff d7f0ffff fff0ffff
///   140002010 9bf0ffff 35f1ffff 57f1ffff 13f1ffff
///   140002020 79f1ffff c3f0ffff 68f1ffff 87f0ffff
///   140002030 aff0ffff 46f1ffff 73f0ffff ebf0ffff
/// ```
/// 每个 4 字节组按**小端有符号**读，再加上表基址 0x140002000。
const EXPECTED_TARGETS: [u64; 16] = [
    0x14000105f,
    0x140001124,
    0x1400010d7,
    0x1400010ff,
    0x14000109b,
    0x140001135,
    0x140001157,
    0x140001113,
    0x140001179,
    0x1400010c3,
    0x140001168,
    0x140001087,
    0x1400010af,
    0x140001146,
    0x140001073,
    0x1400010eb,
];

fn fixture(name: &str) -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("..")
        .join("..")
        .join("tests")
        .join("fixtures")
        .join("generated")
        .join(name)
}

/// 打开 fixture；缺失时**响亮失败**而不是静默跳过。
///
/// 静默跳过会让这条验收测试在实现坏掉时依然"通过"。
fn open_switch_fixture() -> Session {
    let path = fixture("switch-x86_64.exe");
    assert!(
        path.exists(),
        "缺少 fixture {}：\n\
         生成方式：python scripts/gen-jump-table-fixture.py \
         --out tests/fixtures/generated/switch-x86_64.exe",
        path.display()
    );
    Session::open(&path, OpenOptions::default()).expect("打开跳转表 fixture")
}

/// 识别出的目标集合必须与编译器生成的一致 —— 这是 M6 验收标准 1。
#[test]
fn recognized_targets_match_the_compilers_table_exactly() {
    let session = open_switch_fixture();
    let job = session.detached_job();
    let analysis = session.analysis(&job).expect("分析");

    let scan = analysis.jump_tables();
    assert!(
        !scan.tables.is_empty(),
        "没有识别出任何跳转表；说明 = {:?}",
        scan.notes
    );

    // 找到 0x14000105d 处那条跳转对应的表。
    let table = scan
        .tables
        .iter()
        .find(|t| t.insn_addr == JUMP_INSN)
        .unwrap_or_else(|| {
            let found: Vec<String> = scan
                .tables
                .iter()
                .map(|t| format!("{:#x}", t.insn_addr))
                .collect();
            panic!("在 {JUMP_INSN:#x} 处没有识别出跳转表；已识别的跳转点：{found:?}")
        });

    assert_eq!(
        table.base, TABLE_BASE,
        "表基址不对：期望 {TABLE_BASE:#x}，实际 {:#x}",
        table.base
    );

    let got: BTreeSet<u64> = table.targets.iter().copied().collect();
    let want: BTreeSet<u64> = EXPECTED_TARGETS.iter().copied().collect();

    assert_eq!(
        got,
        want,
        "\n跳转表目标集合与编译器生成的不一致\n\
         多出来的：{:?}\n\
         少掉的：  {:?}\n\
         识别到的：{:?}\n",
        got.difference(&want)
            .map(|a| format!("{a:#x}"))
            .collect::<Vec<_>>(),
        want.difference(&got)
            .map(|a| format!("{a:#x}"))
            .collect::<Vec<_>>(),
        table
            .targets
            .iter()
            .map(|a| format!("{a:#x}"))
            .collect::<Vec<_>>(),
    );

    // 表项数也必须一致 —— 多读一项说明验证没挡住"表尾之后的内容"。
    assert_eq!(
        table.count,
        EXPECTED_TARGETS.len(),
        "表项数不对：期望 {}，实际 {}",
        EXPECTED_TARGETS.len(),
        table.count
    );
}

/// 表项语义必须是"相对表基址"。
///
/// 这不是实现细节：搞错语义会得到一整套**错位但看起来合理**的地址
/// （每个都能落在代码段里、都能解出指令），验证也能通过。因此必须
/// 显式断言语义，而不是只比较目标集合 —— 目标集合恰好对得上时，
/// 语义可能仍然是错的。
#[test]
fn entry_kind_is_relative_to_base() {
    let session = open_switch_fixture();
    let job = session.detached_job();
    let analysis = session.analysis(&job).expect("分析");

    let table = analysis
        .jump_tables()
        .tables
        .iter()
        .find(|t| t.insn_addr == JUMP_INSN)
        .expect("跳转表");

    assert_eq!(
        table.kind,
        bitflip_analyze::EntryKind::RelativeToBase,
        "x86_64 的 PIC 跳转表是相对表基址的偏移；绝对地址语义会在真实样本上给出错位地址"
    );
    assert_eq!(
        table.width,
        bitflip_analyze::EntryWidth::U32,
        "clang 生成的是 4 字节表项（`movslq (%rcx,%rax,4)`）"
    );
}

/// 识别出的跳转表目标必须都真的能解出指令。
///
/// 这是"验证阶段"的兜底检查：即使目标集合与黄金数据一致，也要确认
/// 每个目标确实是代码而不是碰巧落在可执行段里的填充字节。
#[test]
fn all_table_targets_are_real_instruction_boundaries() {
    let session = open_switch_fixture();
    let job = session.detached_job();
    let analysis = session.analysis(&job).expect("分析");

    let Some(table) = analysis
        .jump_tables()
        .tables
        .iter()
        .find(|t| t.insn_addr == JUMP_INSN)
    else {
        panic!("跳转表未识别");
    };

    let disasm = session
        .disassemble(bitflip_core::DisasmScanOptions::default())
        .expect("反汇编");

    for &target in &table.targets {
        // 该地址必须确实是某条指令的起点。
        //
        // 用 `index.containing` 而不是 `range(..).next()`：后者会
        // 返回"大于等于该地址的第一条指令"，即使目标落在某条指令的
        // **中间**也会返回它 —— 那样就检查不出"目标是半个指令"。
        let containing = disasm.space.index().containing(target);
        assert_eq!(
            containing.map(|(addr, _)| addr),
            Some(target),
            "{target:#x} 不是指令起点（落在 {containing:?} 处）—— \
             跳转表指向了指令中间，说明表项语义或基址算错了"
        );
    }
}

/// 数据表不能被当成跳转表。
///
/// fixture 里 `jt_switch` 有一个**数据表**（0x140002040，直接 `movl`
/// 读值，没有间接跳转）。它与跳转表在同一节里、格式相同，唯一区别是
/// 没有 `jmp` 到表项。这条测试守住"只有间接跳转才触发表识别"。
#[test]
fn data_table_without_indirect_jump_is_not_a_jump_table() {
    let session = open_switch_fixture();
    let job = session.detached_job();
    let analysis = session.analysis(&job).expect("分析");

    assert!(
        !analysis
            .jump_tables()
            .tables
            .iter()
            .any(|t| t.base == 0x140002040),
        "0x140002040 是纯数据表（`movl (%rcx,%rax,4), %eax`，无间接跳转），\
         不该被当成跳转表"
    );
    assert!(
        !analysis
            .jump_tables()
            .tables
            .iter()
            .any(|t| t.base == 0x140002080),
        "0x140002080 同样是被直接读取的数据表，不该被当成跳转表"
    );
}

/// `Disasm` 自己的索引与地址空间里的索引必须是**同一份**。
///
/// 这条守的是一个踩过的真实缺陷：`Disasm` 持有的 `index` 是正确的，
/// 但构造时没有同步回 `space`，两者的 `Arc` 也不同。任何经
/// `space.index()` 取指令的代码（跳转表识别正是）都读到"这里没有
/// 指令"，于是静默什么都不做 —— 不报错、不降级，只是结论为空。
///
/// `Arc::ptr_eq` 是唯一能立刻看出两份数据分叉的判据，所以这里断言
/// 指针相等，而不只是"长度一样"。
#[test]
fn address_space_index_is_the_same_data_as_the_disassembly_index() {
    let session = open_switch_fixture();
    let disasm = session
        .disassemble(bitflip_core::DisasmScanOptions::default())
        .expect("反汇编");

    assert!(
        !disasm.index.is_empty(),
        "fixture 里应当有指令；索引为空说明扫描本身坏了"
    );
    assert!(
        std::sync::Arc::ptr_eq(&disasm.index, &disasm.space.index_arc()),
        "Disasm::index 与 space.index() 必须指向同一份数据，\
         否则经 space 取指令的代码会静默读到空表（长度 {} vs {}）",
        disasm.index.len(),
        disasm.space.index_arc().len()
    );

    // 内容也要一致：随便取一条指令，两边应当看到同一个地址。
    let from_space: Vec<u64> = disasm
        .space
        .index()
        .range(0, u64::MAX)
        .take(4)
        .map(|(a, _)| a)
        .collect();
    let from_disasm: Vec<u64> = disasm
        .index
        .range(0, u64::MAX)
        .take(4)
        .map(|(a, _)| a)
        .collect();
    assert_eq!(from_space, from_disasm, "两份索引的内容必须一致");
    assert!(!from_space.is_empty(), "两边都不该是空的");
}

/// 未解析的间接跳转必须出现在说明里（降级要可见，CLAUDE.md §7）。
#[test]
fn unresolved_indirect_jumps_are_reported() {
    // 用一个**不含**跳转表的大可执行文件：里面若有间接跳转，就该被报告。
    let path = fixture("big-x86_64.exe");
    assert!(
        path.exists(),
        "缺少 fixture {}；见 docs/BIG-FILE-TESTING.md",
        path.display()
    );
    let session = Session::open(&path, OpenOptions::default()).expect("打开");
    let job = session.detached_job();
    let analysis = session.analysis(&job).expect("分析");

    let scan = analysis.jump_tables();
    let notes = scan.notes.join("\n");

    // 三种诚实结果都可以：识别出表、说明有多少条没解析、或明说没有
    // 间接跳转。不可以的是"有间接跳转但什么也不说"。
    let has_tables = !scan.tables.is_empty();
    let mentions_unresolved = notes.contains("未能解析");
    assert!(
        has_tables || mentions_unresolved || notes.contains("没有间接跳转"),
        "既没识别出跳转表，也没说明未解析的间接跳转数量 —— \
         用户会以为 CFG 是完整的。实际说明：{notes}"
    );
}
