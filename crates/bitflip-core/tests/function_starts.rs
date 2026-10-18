//! `LC_FUNCTION_STARTS` 接进分析层的端到端测试（M12 第四片）。
//!
//! # 为什么要一条端到端测试，而不是只有 `bitflip-analyze` 的单测
//!
//! 单测证明"推导 + 合并"这两块积木是对的，证明不了**它们被接上了**：
//! 加载器早就把 `Object.function_starts` 填好了（M12 第三片），可分析层完全可以
//! 继续无视它 —— 那种缺陷不会编译失败、也不会让单测变红，只会让"权威边界"
//! 静静地躺在 `Object` 里没人用。所以这里从 `Disasm::build` + `TargetAnalysis::build`
//! 两个公开入口跑一遍完整流水线，断言函数清单里有那些起点。
//!
//! 合成对象的字节是清一色的 `ret`（`0xc3`）：每条指令 1 字节，地址与字节一一对应，
//! 断言时不必再算指令长度。分析层不关心 `ObjectKind`，但对象按**真实 Mach-O 的
//! 形态**填（`__TEXT` 段 + `__text` 节 + `LC_FUNCTION_STARTS` 的语义），
//! 这样断言的对象形状与生产路径一致。

use std::sync::Arc;

use bitflip_analyze::StringOptions;
use bitflip_arch::{Arch, ArchSpec, Endian, Mode};
use bitflip_core::{Disasm, DisasmScanOptions, TargetAnalysis};
use bitflip_loader::object::{
    ContentKind, FileRange, Object, ObjectId, Perms, RawSymbol, Section, Segment, SymbolTableSource,
};
use bitflip_loader::ObjectKind;

const TEXT_VADDR: u64 = 0x1000;

/// 合成对象：`__TEXT` 段 + `__text` 节，节里全是 `ret`。
///
/// `bytes_len` 同时是节的长度，所以节的末尾 = `TEXT_VADDR + bytes_len`。
fn synthetic_macho(
    bytes_len: usize,
    function_starts: &[u64],
    entry: Option<u64>,
) -> (Object, Arc<[u8]>) {
    let perms = Perms {
        read: true,
        write: false,
        execute: true,
    };
    let file = FileRange::new(0, bytes_len as u64);

    let mut object = Object::new(
        ObjectId::Plain,
        ObjectKind::MachO,
        ArchSpec::from_arch(Arch::X86_64, Mode::M64, Endian::Little),
        Endian::Little,
    );
    object.image_base = TEXT_VADDR;
    object.entry = entry;
    object.function_starts = function_starts.to_vec();
    object.segments.push(Segment {
        name: "__TEXT".into(),
        vaddr: TEXT_VADDR,
        vsize: bytes_len as u64,
        file: Some(file),
        perms,
        kind: ContentKind::Code,
        align: 0x1000,
    });
    object.sections.push(Section {
        name: "__text".into(),
        vaddr: TEXT_VADDR,
        file,
        perms,
        kind: ContentKind::Code,
        loaded: true,
    });

    let bytes: Arc<[u8]> = vec![0xc3_u8; bytes_len].into();
    (object, bytes)
}

fn analyze(object: &Object, bytes: Arc<[u8]>) -> TargetAnalysis {
    let disasm = Disasm::build(object, bytes, DisasmScanOptions::default());
    TargetAnalysis::build(&disasm, object, &StringOptions::default(), None, None)
}

/// 把一个十六进制 wire 地址读回 `u64`。
fn addr(text: &str) -> u64 {
    u64::from_str_radix(text, 16)
        .unwrap_or_else(|error| panic!("地址 {text:?} 不是十六进制：{error}"))
}

fn function_at(analysis: &TargetAnalysis, start: u64) -> Vec<&bitflip_core::FunctionWire> {
    analysis
        .functions()
        .iter()
        .filter(|function| addr(&function.start) == start)
        .collect()
}

/// 三个起点 → 三个函数；大小由相邻起点推出，最后一个取所在节的末尾。
#[test]
fn three_function_starts_become_three_functions_with_derived_sizes() {
    let (object, bytes) = synthetic_macho(0x60, &[0x1000, 0x1010, 0x1030], None);
    let analysis = analyze(&object, bytes);

    assert_eq!(
        analysis.functions().len(),
        3,
        "三个函数起点就该是三个函数：{:?}",
        analysis
            .functions()
            .iter()
            .map(|f| (f.start.as_str(), f.end.as_deref()))
            .collect::<Vec<_>>()
    );

    let expected = [
        (0x1000_u64, 0x1010_u64, 0x10_u64),
        (0x1010, 0x1030, 0x20),
        (0x1030, 0x1060, 0x30), // 节的末尾 = 0x1030 + 0x30
    ];
    for (start, end, size) in expected {
        let found = function_at(&analysis, start);
        assert_eq!(found.len(), 1, "{start:#x} 应当恰好有一个函数");
        let function = found[0];
        assert_eq!(
            function.end.as_deref().map(addr),
            Some(end),
            "{start:#x} 的上界应当是 {end:#x}"
        );
        assert_eq!(
            function.size,
            Some(size),
            "{start:#x} 的大小应当是 {size:#x}"
        );
        assert_eq!(
            function.source, "function-start",
            "{start:#x} 的来源必须是函数起点表（不是分析推断）"
        );
        assert_eq!(function.source_label, "函数起点表");
        assert!(
            !function.named,
            "起点表里没有名字 —— 必须如实'未识别'（CLAUDE.md §7）"
        );
        assert_eq!(function.name, "", "不许编 func_xxx 之类的占位名");
    }

    let notes = analysis.notes().join("\n");
    assert!(
        notes.contains("LC_FUNCTION_STARTS"),
        "用了这张表就要在 notes 里说，实际 notes：{notes}"
    );
    assert!(
        notes.contains("推导"),
        "结束地址是推导出来的，必须这么标：{notes}"
    );
}

/// 起点正好是入口点：不许多出一个函数，入口函数要拿到权威边界。
#[test]
fn a_start_equal_to_the_entry_point_does_not_duplicate_it() {
    let (object, bytes) = synthetic_macho(0x60, &[0x1000, 0x1010, 0x1030], Some(0x1010));
    let analysis = analyze(&object, bytes);

    assert_eq!(
        analysis.functions().len(),
        3,
        "入口点已经在那张表里，不该多出第四个函数"
    );
    let found = function_at(&analysis, 0x1010);
    assert_eq!(found.len(), 1, "0x1010 上只能有一个函数");
    assert_eq!(
        found[0].end.as_deref().map(addr),
        Some(0x1030),
        "入口函数也要拿到函数起点表给的边界"
    );
    // 名字/来源仍按既有优先级：入口点(45) 比函数起点表(52) 硬。
    // 这不是"新来源抢了入口"，而是既有排序的自然结果。
    assert_eq!(found[0].source, "entry-point");
}

/// 空表 = 没有这样一张表：结果与"这个字段从未被填过"**逐字段一致**。
#[test]
fn an_empty_function_starts_field_changes_nothing() {
    // 一个显式置空表，一个连碰都不碰（`Object::new` 里本来就是空表）。
    let (mut explicit, bytes_a) = synthetic_macho(0x60, &[], None);
    explicit.function_starts = Vec::new();
    let (untouched, bytes_b) = synthetic_macho(0x60, &[], None);
    assert!(untouched.function_starts.is_empty());

    let with_empty = analyze(&explicit, bytes_a);
    let without_field = analyze(&untouched, bytes_b);

    assert_eq!(
        with_empty.function_count(),
        without_field.function_count(),
        "空表不许改变函数数"
    );
    assert_eq!(
        with_empty.function_count(),
        0,
        "没有任何来源时就是 0 个函数"
    );
    assert_eq!(
        with_empty.notes(),
        without_field.notes(),
        "空表不许往 notes 里加任何东西（否则 PE/ELF/DEX 会凭空多一条噪声）"
    );
    assert!(
        !with_empty.notes().iter().any(|n| n.contains("函数起点")),
        "没有这张表就不该提到它：{:?}",
        with_empty.notes()
    );
}

/// **冲突**：符号落在推导出的范围里。
///
/// 文档化的结果是"边界不动、矛盾上报"（理由写在 `bitflip-analyze` 的同名单测
/// 与 `TargetAnalysis::build` 的注释里）：`LC_FUNCTION_STARTS` 断言的是**起点**，
/// 被夹在中间的那个地址不在这张表里、也没有任何边界主张，截断到它等于凭空造一个
/// 结束地址。所以这里断言的是**保留 + 报出来**，不是"悄悄截断"。
#[test]
fn a_symbol_strictly_inside_a_derived_range_is_reported_not_truncated() {
    let (mut object, bytes) = synthetic_macho(0x60, &[0x1000, 0x1040], None);
    object.symbols.push(RawSymbol {
        name: "inner_label".into(),
        value: 0x1020,
        // `nlist` 里没有 size 字段，所以符号**不提供**边界 —— 这一条本身也是事实
        size: 0,
        defined: true,
        is_function: true,
        is_weak: false,
        // 绑定类型只有 ELF 有；Mach-O 的 `nlist` 里没有同义字段，分析层也不看它。
        bind: 0,
        section: Some("__text".into()),
        source: SymbolTableSource::Static,
    });

    let analysis = analyze(&object, bytes);
    assert_eq!(
        analysis.function_count(),
        3,
        "0x1000（外层）、0x1020（符号）、0x1040（表里第二个起点）各是一个函数：{:?}",
        analysis
            .functions()
            .iter()
            .map(|f| (f.start.as_str(), f.end.as_deref(), f.name.as_str()))
            .collect::<Vec<_>>()
    );

    let outer = function_at(&analysis, 0x1000);
    assert_eq!(outer.len(), 1);
    assert_eq!(
        outer[0].end.as_deref().map(addr),
        Some(0x1040),
        "推导出的上界不许被夹在中间的符号截断"
    );

    let inner = function_at(&analysis, 0x1020);
    assert_eq!(inner.len(), 1);
    assert_eq!(inner[0].name, "inner_label", "有符号就用符号名，照旧");
    assert_eq!(
        inner[0].end, None,
        "符号不提供边界，所以这个函数只知道起点 —— 不拿外层的上界凑"
    );

    let conflict = analysis
        .notes()
        .iter()
        .find(|note| note.contains("落在上一个函数由 LC_FUNCTION_STARTS 推出的范围里"))
        .unwrap_or_else(|| panic!("重叠必须报出来，实际 notes：{:#?}", analysis.notes()));
    assert!(
        conflict.contains("0x1020") && conflict.contains("0x1040"),
        "冲突说明要指名道姓：{conflict}"
    );
    assert!(
        conflict.contains("没有截断"),
        "结论要写清（边界不动），而不是只报个数字：{conflict}"
    );
}

/// 最后一个起点落不进任何节：边界未知（`None`），不猜，并在 notes 里计数。
#[test]
fn the_last_start_outside_every_section_keeps_an_unknown_size() {
    let (mut object, bytes) = synthetic_macho(0x60, &[0x1000, 0x1010, 0x8000], None);
    // 第二段没有任何节：起点被映射了（读得到字节），但"所在节的末尾"答不上来。
    object.segments.push(Segment {
        name: "__DATA".into(),
        vaddr: 0x8000,
        vsize: 0x10,
        file: None, // 零填充段：仍然可读（读作 0），只是不占文件空间
        perms: Perms {
            read: true,
            write: true,
            execute: false,
        },
        kind: ContentKind::Data,
        align: 0x10,
    });

    let analysis = analyze(&object, bytes);
    let last = function_at(&analysis, 0x8000);
    assert_eq!(last.len(), 1, "0x8000 在已映射的地址空间里，应当有函数");
    assert_eq!(
        last[0].end, None,
        "落不进任何节、表里又没有下一个起点 —— 边界未知，不拿节尾或 0 凑"
    );
    assert_eq!(last[0].size, None);

    let notes = analysis.notes().join("\n");
    assert!(
        notes.contains("1 个推不出边界"),
        "推不出边界的个数要在 notes 里说出来：{notes}"
    );
}

/// 起点不在已映射地址空间里：不建函数，但要报出来。
#[test]
fn an_unmapped_start_is_skipped_and_reported() {
    let (object, bytes) = synthetic_macho(0x60, &[0x1000, 0x9000], None);
    let analysis = analyze(&object, bytes);

    assert!(
        function_at(&analysis, 0x9000).is_empty(),
        "0x9000 没有任何字节，在那里建函数等于造一个点不开的空壳"
    );
    assert_eq!(analysis.function_count(), 1, "只剩 0x1000 那一个函数");
    // 边界仍然是文件里那张表说的：下一个起点是 0x9000。
    let first = function_at(&analysis, 0x1000);
    assert_eq!(first.len(), 1);
    assert_eq!(first[0].end.as_deref().map(addr), Some(0x9000));

    let notes = analysis.notes().join("\n");
    assert!(
        notes.contains("0x9000"),
        "被跳过的起点要说出第一个是谁：{notes}"
    );
}

/// 零填充段不该按 `vsize` 扫描（真实 Mach-O 的 `__PAGEZERO` 会因此把分析卡死）。
///
/// 这是接 `LC_FUNCTION_STARTS` 时在真实样本上踩到的：`__PAGEZERO` 是一个
/// vsize = 4 GiB 的零填充段，字符串扫描原先按 `vsize` 逐块读它 —— 一个 151 KB 的
/// 二进制几分钟都不出结果（`tests/macho_real_analysis.rs` 就是这么撞上去的）。
/// 现在只扫"文件里真有字节"的那一段（见 `TargetAnalysis::build`）。
///
/// 这条测试**断言的是能跑完**：回归时它会去处理 64 MiB 的零填充（debug 构建下几十秒，
/// CI 会明显变慢甚至超时），而不是某个能直接比对的数值 —— 零填充本来也产不出字符串，
/// 结果面上没有别的痕迹。注释留在这里，免得下一个人以为"慢一点无所谓"。
#[test]
fn a_huge_zero_fill_segment_is_not_scanned_for_strings() {
    let (mut object, bytes) = synthetic_macho(0x60, &[], None);
    object.segments.push(Segment {
        name: "__PAGEZERO".into(),
        vaddr: 0x00,
        vsize: 64 * 1024 * 1024,
        file: None, // 零填充：文件里没有对应字节
        perms: Perms::none(),
        kind: ContentKind::Data,
        align: 0x1000,
    });

    let started = std::time::Instant::now();
    let analysis = analyze(&object, bytes);
    let elapsed = started.elapsed();
    eprintln!("含 64 MiB 零填充段的合成目标，分析耗时 {elapsed:?}");

    assert_eq!(analysis.function_count(), 0, "没有来源就不该有函数");
    assert!(
        analysis
            .notes()
            .iter()
            .all(|note| !note.contains("读取失败")),
        "零填充段不该被读：{:?}",
        analysis.notes()
    );
}
