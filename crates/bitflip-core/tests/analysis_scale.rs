//! 规模门禁：真实形状的 Mach-O 上，整份分析必须在本机单位 × 倍数以内跑完。
//!
//! # 这条测试要拦的是什么
//!
//! 151 648 字节的 `LiveContainer` 主二进制一度要 6.4 秒（debug 构建，修掉
//! `__PAGEZERO` 的 4 GiB 空扫之后仍是这个量级），19.6 MB 的样本估计十分钟
//! 以上。根因不是"哪一行慢"，而是**结构**：
//!
//! 1. 九个阶段各自把整个指令索引重解一遍（同样的输入，解八遍）；
//! 2. 每查一个寄存器编号就新建一个 capstone 引擎（每次约 300 µs）；
//! 3. 任何按 `vsize` 走字节的循环都会在空段（`__PAGEZERO`，4 GiB）上白跑。
//!
//! 这三种退化都是**量级**问题，不是抖动。所以门禁不能写死毫秒数（那测的是机器），
//! 要用本机标定的单位乘倍数 —— 与 `callgraph_scale.rs` 同一套做法。
//!
//! # 为什么样本是合成的
//!
//! 真实 IPA 在 `temp/`（只读、永不入库），CI 里没有。所以这里直接在内存里构造
//! 一份**形状真实**的对象：5 000 个函数起点、2 000 个符号、200 KB 的 `__TEXT`、
//! 一个 4 GiB 的 `__PAGEZERO` 空段（专门让"按 vsize 扫字节"的回归当场超时）。
//! 指令是真实可解码的 AArch64 编码（`stp` / `bl` / `cbz` / `nop` / `ret`），不是
//! 随机字节 —— 随机字节解码失败就什么也没测到。
//!
//! 门禁不测"结果对不对"（那是各格式单元测试的事），只测两件：
//! 结构没退化（耗时）与规模真的走通了（函数数、已知边界数）。

use std::sync::Arc;
use std::time::{Duration, Instant};

use bitflip_analyze::StringOptions;
use bitflip_arch::{Arch, ArchSpec, Endian, Mode};
use bitflip_core::{Disasm, DisasmScanOptions, TargetAnalysis};
use bitflip_loader::object::{
    ContentKind, FileRange, Object, ObjectId, Perms, RawSymbol, Section, Segment, SymbolTableSource,
};
use bitflip_loader::ObjectKind;

// ── 本机标定 ──────────────────────────────────────────────────────────────
//
// 与 `crates/bitflip-analyze/tests/callgraph_scale.rs` 同一套做法（同一段代码），
// 但**没有**抽成公共模块：那两处测试在**不同的 crate** 里，集成测试的模块路径
// 不跨包共享，而为此新建一个 dev-dependency crate 要动 workspace 依赖（本任务
// 明确不许新增依赖）。30 行里带注释的重复是可接受的代价；两处都写明了对方的存在。

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

/// 断言耗时在门限内，失败信息里带出本机单位 —— 下一次看到红的人不用再猜机器。
fn assert_within(elapsed: Duration, unit: Duration, multiple: u32, what: &str) {
    let limit = unit * multiple;
    assert!(
        elapsed <= limit,
        "{what}用了 {elapsed:?}，超过门限 {limit:?}（本机单位 {unit:?} × {multiple}）—— \
         这不是「机器慢了一点」，是量级变了（重解码 / 逐函数重解 / 按 vsize 白扫）"
    );
}

// ── 合成样本 ──────────────────────────────────────────────────────────────

/// 函数个数（真实样本 311 / 1 016，这里刻意放大一个量级去摊开每次调用的常数成本）。
const FUNCTION_COUNT: usize = 5_000;
/// 有名字的函数个数（符号表里的函数符号）。
const SYMBOL_COUNT: usize = 2_000;
/// 每个函数的指令条数（10 条 × 4 字节 = 40 字节）。
const INSNS_PER_FUNCTION: usize = 10;
/// `__TEXT` 的基址：与真实 iOS 可执行文件一致（`LC_MAIN` 前的占用由 `__PAGEZERO` 表示）。
const TEXT_BASE: u64 = 0x1_0000_0000;
/// `__PAGEZERO` 的虚拟大小：**4 GiB 空段**，不占文件字节。
///
/// 这条是刻意留的：早先的字符串扫描按 `vsize` 走字节，于是在这个空段上白扫
/// 4 GiB（实测把 151 KB 的样本拖成"几分钟不出结果"）。有了这一段，任何重新
/// 引入"按 vsize 而不是按文件字节"的循环都会让本测试当场超时。
const PAGEZERO_VSIZE: u64 = 0x1_0000_0000;

/// 一条函数的指令编码（AArch64，全部是真实可解码的指令）。
///
/// 形状取真实函数的常见样子：建帧 → 调一个公共枢纽 → 一个条件分支（两个后继，
/// CFG 会因此切块）→ 若干填充 → 返回。
fn function_body(entry: u64, hub: u64) -> [u32; INSNS_PER_FUNCTION] {
    // `bl <hub>`：0x94000000 | imm26，imm26 = (target - pc) / 4。
    let bl = 0x9400_0000u32 | (((hub as i64 - (entry as i64 + 8)) / 4) as u32 & 0x03FF_FFFF);
    // `cbz x0, +12`：0xB4000000 | imm19 << 5 | rt，落在本函数第 6 条（entry + 24）。
    let cbz = 0xB400_0000u32 | ((12 / 4) << 5);
    [
        0xA9BF_7BFD, // stp x29, x30, [sp, #-16]!
        0x9100_03FD, // mov x29, sp
        bl,          // bl <hub>
        cbz,         // cbz x0, entry+24
        0xD503_201F, // nop
        0xD503_201F, // nop
        0xD503_201F, // nop（cbz 的目标）
        0xD503_201F, // nop
        0xD503_201F, // nop
        0xD65F_03C0, // ret
    ]
}

fn perm(read: bool, write: bool, execute: bool) -> Perms {
    Perms {
        read,
        write,
        execute,
    }
}

/// 造一份合成对象：5 000 个起点、2 000 个符号、200 KB `__TEXT`、4 GiB `__PAGEZERO`。
fn synthetic_object() -> (Object, Arc<[u8]>) {
    let text_size = (FUNCTION_COUNT * INSNS_PER_FUNCTION * 4) as u64;
    let data_size: u64 = 0x4000;
    let linkedit_size: u64 = 0x4000;

    // ── 字节布局：__TEXT | __DATA | __LINKEDIT ──
    let mut bytes: Vec<u8> = Vec::with_capacity((text_size + data_size + linkedit_size) as usize);
    let hub = TEXT_BASE;
    for index in 0..FUNCTION_COUNT {
        let entry = TEXT_BASE + index as u64 * (INSNS_PER_FUNCTION as u64 * 4);
        for word in function_body(entry, hub) {
            bytes.extend_from_slice(&word.to_le_bytes());
        }
    }
    // __DATA：放一段可打印的字符串，让字符串扫描有真活可干（不是必须，但更接近真实）。
    let data_offset = bytes.len() as u64;
    bytes.extend_from_slice(b"BitFlip synthetic analysis scale fixture\0");
    bytes.resize((data_offset + data_size) as usize, 0);
    let linkedit_offset = bytes.len() as u64;
    bytes.resize((linkedit_offset + linkedit_size) as usize, 0);

    // ── 段表 ──
    let data_vaddr = TEXT_BASE + text_size;
    let linkedit_vaddr = data_vaddr + data_size;
    let mut object = Object::new(
        ObjectId::Plain,
        ObjectKind::MachO,
        ArchSpec::from_arch(Arch::Aarch64, Mode::M64, Endian::Little),
        Endian::Little,
    );
    object.image_base = TEXT_BASE;
    object.entry = Some(TEXT_BASE);
    object.segments.push(Segment {
        name: "__PAGEZERO".to_string(),
        vaddr: 0,
        vsize: PAGEZERO_VSIZE,
        file: None,
        perms: perm(false, false, false),
        kind: ContentKind::Data,
        align: 0x1000,
    });
    object.segments.push(Segment {
        name: "__TEXT".to_string(),
        vaddr: TEXT_BASE,
        vsize: text_size,
        file: Some(FileRange {
            offset: 0,
            size: text_size,
        }),
        perms: perm(true, false, true),
        kind: ContentKind::Code,
        align: 0x4000,
    });
    object.segments.push(Segment {
        name: "__DATA".to_string(),
        vaddr: data_vaddr,
        vsize: data_size,
        file: Some(FileRange {
            offset: data_offset,
            size: data_size,
        }),
        perms: perm(true, true, false),
        kind: ContentKind::Data,
        align: 0x4000,
    });
    object.segments.push(Segment {
        name: "__LINKEDIT".to_string(),
        vaddr: linkedit_vaddr,
        vsize: linkedit_size,
        file: Some(FileRange {
            offset: linkedit_offset,
            size: linkedit_size,
        }),
        perms: perm(true, false, false),
        kind: ContentKind::SymbolTable,
        align: 0x4000,
    });

    // ── 节表（`__text` 是分析的主战场）──
    object.sections.push(Section {
        name: "__text".to_string(),
        vaddr: TEXT_BASE,
        file: FileRange {
            offset: 0,
            size: text_size,
        },
        perms: perm(true, false, true),
        kind: ContentKind::Code,
        loaded: true,
    });
    object.sections.push(Section {
        name: "__data".to_string(),
        vaddr: data_vaddr,
        file: FileRange {
            offset: data_offset,
            size: data_size,
        },
        perms: perm(true, true, false),
        kind: ContentKind::Data,
        loaded: true,
    });

    // ── 符号表：前 2 000 个函数有名字 ──
    for index in 0..SYMBOL_COUNT {
        let addr = TEXT_BASE + index as u64 * (INSNS_PER_FUNCTION as u64 * 4);
        object.symbols.push(RawSymbol {
            name: format!("_bitflip_synthetic_{index}"),
            value: addr,
            size: 0,
            defined: true,
            is_function: true,
            is_weak: false,
            bind: 0,
            section: Some("__text".to_string()),
            source: SymbolTableSource::Static,
        });
    }

    // ── 函数起点表（Mach-O 的 LC_FUNCTION_STARTS 形状）──
    object.function_starts = (0..FUNCTION_COUNT)
        .map(|index| TEXT_BASE + index as u64 * (INSNS_PER_FUNCTION as u64 * 4))
        .collect();

    (object, bytes.into())
}

/// 整份分析必须在本机单位 × 倍数内完成，且规模真的走通了。
///
/// # 为什么用"本机单位 × 倍数"而不是秒数
///
/// 写死"10 秒内跑完"测的是机器，不是代码：同一份代码在 CI 上可能是本机的
/// 三分之一。所以先在本机测一段固定工作量得到 `unit`，再把预算表达成
/// `unit × N`（与 `callgraph_scale.rs` 同一套做法）。
///
/// 实测两个量：本机 `unit ≈ 20–24 ms`，这条样本整份分析 `≈ 10–11 s ≈ 408–486 个单位`
/// （连跑四次：426 / 424 / 486 / 408 —— 单个量本身抖 10%，所以倍数必须按**最坏**
/// 观测取，不能按中位数）。
///
/// # 这条门禁能抓什么、抓不到什么
///
/// 抓：量级退化（`__PAGEZERO` 的 4 GiB 空扫、某阶段又重解一遍索引、逐函数
/// 重建 capstone 引擎）。这三种在修之前分别对应"几分钟不出结果"、"8 倍解码"、
/// "每函数两次 × 300 µs"，都会把 4xx 推到 1 000 以上。
///
/// 抓不到：小于 2 倍的渐进变慢（1 000 / 486）。故意留这么松是因为本机是低配
/// 机器、CI 也是共享跑者 —— 收紧到 1.2 倍会先红在噪声上，红几次之后大家就会
/// 开始无视这条门禁，那比没有门禁更糟。
#[test]
fn synthetic_macho_analysis_finishes_within_calibrated_budget() {
    /// 整份分析 / 本机单位 的上限。
    ///
    /// 本机实测 408–486 个单位（最坏 486），取 1 000 ≈ 最坏值的 2.06 倍余量。
    const TIME_MULTIPLE: u32 = 1_000;

    let (object, bytes) = synthetic_object();
    let unit = machine_unit();

    let started = Instant::now();
    let disasm = Disasm::build(&object, Arc::clone(&bytes), DisasmScanOptions::default());
    let disasm_elapsed = started.elapsed();

    let started = Instant::now();
    let analysis = TargetAnalysis::build(&disasm, &object, &StringOptions::default(), None, None);
    let analysis_elapsed = started.elapsed();

    // 规模真的走通了：不是"很快就什么也没做"。
    assert!(
        disasm.index.len() >= FUNCTION_COUNT * INSNS_PER_FUNCTION,
        "索引里应当有至少 {} 条指令，实际 {} 条 —— 合成样本没有被解码（门禁会假绿）",
        FUNCTION_COUNT * INSNS_PER_FUNCTION,
        disasm.index.len()
    );
    let known_ends = analysis
        .functions()
        .iter()
        .filter(|function| function.end.is_some())
        .count();
    assert!(
        analysis.function_count() >= FUNCTION_COUNT,
        "函数数应当至少 {FUNCTION_COUNT} 个（函数起点表全覆盖），实际 {} 个",
        analysis.function_count()
    );
    assert!(
        known_ends >= FUNCTION_COUNT,
        "已知上界的函数应当至少 {FUNCTION_COUNT} 个（起点表的结束地址由下一个起点推出），\
         实际 {known_ends} 个"
    );

    let total = disasm_elapsed + analysis_elapsed;
    eprintln!(
        "合成样本：{} 个函数 / {} 个符号 / {} 字节 __TEXT / 索引 {} 条指令；\
         反汇编 {disasm_elapsed:?}、分析 {analysis_elapsed:?}；\
         本机单位 {unit:?}，整份 {total:?} = {:.0} 个单位（上限 {TIME_MULTIPLE}）",
        FUNCTION_COUNT,
        SYMBOL_COUNT,
        FUNCTION_COUNT * INSNS_PER_FUNCTION * 4,
        disasm.index.len(),
        total.as_secs_f64() / unit.as_secs_f64()
    );

    assert_within(total, unit, TIME_MULTIPLE, "合成 Mach-O 的整份分析");
}
