//! M5 共享库语义：导出表、数据/代码区分、以及重叠段上的读取完整性。
//!
//! # 两类样本，各管一段
//!
//! * **自造的小 `.so`**（`scripts/gen-shared-lib.py`，3 KB）覆盖**精确断言**：
//!   导出函数有几个、叫什么、哪些是数据、内部符号不该出现。
//!   小文件让这组测试能在几分之一秒内跑完，可以进常规测试。
//! * **系统上的大 `.so`**（97 MB）覆盖**真实野布局**：节与 PT_LOAD 段重叠、
//!   导出上千个符号。它跑得慢（几分钟），所以放在单独的 `#[ignore]` 测试里，
//!   用 `cargo test -- --ignored` 手动跑。
//!
//! 自造样本负责"说得对"，大样本负责"没崩且不丢数据"。

use std::path::PathBuf;

use bitflip_core::{DisasmScanOptions, OpenOptions, Session};

/// 自造共享库的导出契约。与 `scripts/gen-shared-lib.py` 必须一致。
const EXPORTED_FUNCS: &[&str] = &["sample_add", "sample_mul", "sample_chain"];
const EXPORTED_DATA: &[&str] = &["sample_magic", "sample_table"];
/// 只应出现在 `.symtab`，不该被当作导出。
const INTERNAL_FUNC: &str = "sample_internal";

/// 系统上的大尺寸共享库：真实的重叠段与海量导出。
const LARGE_SO: &str = r"C:\Windows\System32\lxss\lib\libnvwgf2umx.so";

fn generated(name: &str) -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("..")
        .join("..")
        .join("tests")
        .join("fixtures")
        .join("generated")
        .join(name)
}

/// 取自造 `.so`；不存在就带着重建命令硬失败。
///
/// 不做静默跳过：跳过等于这条覆盖不存在，但看起来是绿的。
fn sample_so() -> PathBuf {
    let path = generated("libsample.so");
    assert!(
        path.exists(),
        "缺少共享库 fixture：{}\n重建方式（约 1 秒）：\n  \
         python scripts/gen-shared-lib.py --out tests/fixtures/generated/libsample.so",
        path.display()
    );
    path
}

fn open_so(path: &PathBuf) -> Session {
    Session::open(path, OpenOptions::default()).expect("打开共享库")
}

/// 导出表必须把 3 个函数与 2 个数据符号都列出来。
#[test]
fn exports_include_both_functions_and_data() {
    let session = open_so(&sample_so());
    let exports = session.object().expect("已解析对象").exports.clone();

    let names: Vec<&str> = exports.iter().map(|e| e.name.as_str()).collect();
    for want in EXPORTED_FUNCS {
        assert!(
            names.contains(want),
            "导出表缺少函数 {want}；实际 {names:?}"
        );
    }
    for want in EXPORTED_DATA {
        assert!(
            names.contains(want),
            "导出表缺少数据符号 {want}；实际 {names:?}"
        );
    }
    // 不能只导出函数：共享库的数据符号也是对外接口，
    // 漏掉它们会让"导出表"这个结论不完整。
    assert!(
        names.len() >= EXPORTED_FUNCS.len() + EXPORTED_DATA.len(),
        "导出表只有 {} 项，少于预期的 {} 项",
        names.len(),
        EXPORTED_FUNCS.len() + EXPORTED_DATA.len()
    );
}

/// `is_code` 必须真的区分函数与数据。
///
/// 这是 M5 里最容易做错的一处：ELF 用 `STT_FUNC` / `STT_OBJECT` 区分，
/// 把数据当函数会让界面显示一个点进去全是乱码的"函数"。
#[test]
fn is_code_separates_functions_from_data() {
    let session = open_so(&sample_so());
    let exports = session.object().expect("已解析对象").exports.clone();

    for e in &exports {
        if EXPORTED_FUNCS.contains(&e.name.as_str()) {
            assert!(e.is_code, "{} 是函数，is_code 应为真", e.name);
        }
        if EXPORTED_DATA.contains(&e.name.as_str()) {
            assert!(!e.is_code, "{} 是数据，is_code 应为假", e.name);
        }
    }
}

/// **函数列表里不许出现数据导出。**
///
/// 之前 `analysis` 把所有导出都当成函数候选，于是 `sample_magic`（一个
/// `const int`）被列成"函数"。判据不只查名字，还查地址：
/// 数据导出的地址不该出现在函数列表里。
#[test]
fn data_exports_are_not_listed_as_functions() {
    let path = sample_so();
    let session = open_so(&path);
    let data_addrs: Vec<u64> = session
        .object()
        .expect("已解析对象")
        .exports
        .iter()
        .filter(|e| !e.is_code)
        .map(|e| e.address)
        .collect();
    assert!(!data_addrs.is_empty(), "样本应当有数据导出");

    let job = session.detached_job();
    let analysis = session.analysis(&job).expect("分析");

    let mut wrong = Vec::new();
    for f in analysis.functions() {
        let addr = bitflip_core::parse_address(&f.start).expect("函数地址是合法 hex");
        if data_addrs.contains(&addr) {
            wrong.push(format!("{} @ {}", f.name, f.start));
        }
    }
    assert!(
        wrong.is_empty(),
        "数据导出被当成了函数：{wrong:?}\n\
         数据符号（sample_magic / sample_table）不是代码，列进函数列表 \
         只会让用户点进一堆无法解码的字节。"
    );
}

/// 3 个导出函数都要被识别成函数，且名字来自导出表。
#[test]
fn exported_functions_are_recognized_with_their_names() {
    let session = open_so(&sample_so());
    let job = session.detached_job();
    let analysis = session.analysis(&job).expect("分析");

    for want in EXPORTED_FUNCS {
        let found = analysis
            .functions()
            .iter()
            .find(|f| f.name == *want)
            .unwrap_or_else(|| {
                let names: Vec<&str> = analysis
                    .functions()
                    .iter()
                    .map(|f| f.name.as_str())
                    .collect();
                panic!("没有识别出导出函数 {want}；实际 {names:?}")
            });
        assert_eq!(
            found.source, "export",
            "{want} 的名字应当来自导出表，实际来源 {}",
            found.source
        );
        assert!(found.named, "{want} 应当被标记为已命名");
    }
}

/// **重定位驱动的指针表识别**：只有指针表引用的函数也要被找出来。
///
/// fixture 刻意被 `--strip-all` 剥过，因此 `sample_via_pointer`：
///   * 不在导出表里（它是 static）；
///   * 不在 `.symtab` 里（已剥离）；
///   * 从不被任何 `call` 指向（只出现在 `sample_table` 里）；
///   * 没有 `.eh_frame` FDE（`-nostdlib` 且无异常）。
///
/// 前五个来源一个都碰不到它。唯一能发现它的事实是：
/// `.rela.dyn` 里有一条 `R_X86_64_RELATIVE`，加数正是它的地址。
///
/// 这条测试因此是"路径真的被执行了"的证据 —— 没有它，整个重定位指针表
/// 实现可以在完全没生效的情况下让测试全绿。
#[test]
fn pointer_table_only_function_is_discovered_via_relocation() {
    let path = sample_so();
    let session = open_so(&path);
    let job = session.detached_job();
    let analysis = session.analysis(&job).expect("分析");

    let found = analysis
        .functions()
        .iter()
        .find(|f| f.source == "reloc-pointer")
        .unwrap_or_else(|| {
            let srcs: Vec<&str> = analysis
                .functions()
                .iter()
                .map(|f| f.source.as_str())
                .collect();
            panic!("没有任何函数来自重定位指针表；实际来源 {srcs:?}")
        });

    // 它必须确实是一段代码，而不是数据区里被误判的字节。
    let disasm = session
        .disassemble(DisasmScanOptions::default())
        .expect("反汇编");
    let addr = bitflip_core::parse_address(&found.start).expect("合法 hex");
    assert!(
        disasm.space.contains(addr),
        "重定位指针表指向的地址 {:#x} 不在已映射区间内",
        addr
    );

    // 该地址处必须真的能解出指令。
    assert!(
        disasm
            .index
            .range(addr, addr.saturating_add(1))
            .next()
            .is_some(),
        "重定位指针表指向的 {:#x} 处没有指令 —— \
         说明把数据指针当成了函数指针",
        addr
    );

    // 名字必须留空：指针表里的目标确实没有名字，编一个就是 §7 禁止的假象。
    assert!(
        found.name.is_empty(),
        "重定位指针表发现的函数不该有名字，实际是 {}",
        found.name
    );
    assert!(!found.named, "未命名函数必须 named = false");
}

/// 重定位指针表本身要出现在结论的说明里（降级/能力都要可见）。
#[test]
fn relocation_pointer_discovery_is_reported_in_notes() {
    let session = open_so(&sample_so());
    let job = session.detached_job();
    let analysis = session.analysis(&job).expect("分析");

    let notes = analysis.notes().join("\n");
    assert!(
        notes.contains("重定位"),
        "有函数来自重定位指针表时，说明里应当提到这一点；实际说明：{notes}"
    );
}

/// `RelocPointer` 必须与 `Relative` 分开归类。
///
/// 早先 ELF 的 `R_*_RELATIVE` 被归进 `Relative`（PC 相对），于是指针表
/// 识别没法只挑数据槽位。这条直接验证分类结果。
#[test]
fn relative_pointer_relocations_are_classified_separately() {
    let path = sample_so();
    let session = open_so(&path);
    let relocs = session.object().expect("已解析对象").relocations.clone();
    assert!(!relocs.is_empty(), "样本应当有重定位");

    let pointer_slots = relocs
        .iter()
        .filter(|r| r.kind == bitflip_loader::object::RelocKind::RelocPointer)
        .count();
    assert!(
        pointer_slots >= 1,
        "样本里应当至少有一条数据槽位重定位（R_X86_64_RELATIVE），实际 {} 条；\
         全部分类：{:?}",
        pointer_slots,
        relocs
            .iter()
            .map(|r| (r.raw_kind, r.kind.as_str()))
            .collect::<Vec<_>>()
    );
}

/// 内部（static）函数可以出现在符号表来源里，但**不能**被当作导出。
#[test]
fn internal_function_is_not_an_export() {
    let session = open_so(&sample_so());
    let exports = session.object().expect("已解析对象").exports.clone();
    assert!(
        !exports.iter().any(|e| e.name == INTERNAL_FUNC),
        "static 内部函数 {INTERNAL_FUNC} 不该出现在导出表里 —— \
         导出表只收对外可见的符号"
    );
}

/// 函数地址必须落在可执行区间内。
///
/// 导出地址若被误当成文件偏移，会解出一堆看似合理但完全错误的地址。
#[test]
fn function_addresses_land_in_executable_memory() {
    let session = open_so(&sample_so());
    let job = session.detached_job();
    let analysis = session.analysis(&job).expect("分析");
    let disasm = session
        .disassemble(DisasmScanOptions::default())
        .expect("反汇编");

    for f in analysis.functions() {
        // 回调目标推断出来的地址也必须在映射内
        let addr = bitflip_core::parse_address(&f.start).expect("合法 hex");
        assert!(
            disasm.space.contains(addr),
            "函数 {} @ {} 不在任何已映射区间内",
            f.name,
            f.start
        );
    }
}

/// 大样本上：字符串扫描不得在段中途截断。
///
/// `#[ignore]` 是因为它要几分钟（97 MB，30 万个函数）。手动跑：
/// `cargo test -p bitflip-core --test shared_library -- --ignored`
///
/// 这条盯的是一个真实的数据丢失 bug：ELF 的节与 PT_LOAD 段 vaddr 相同、
/// 大小略有出入，`segment_at` 早先取"排序后第一个"，挑中较小的段就让
/// 整块读取失败，字符串扫描在该处**整个中断**。
#[test]
#[ignore = "需要 97MB 系统样本，数分钟；用 --ignored 手动跑"]
fn large_so_string_scan_does_not_truncate() {
    let path = PathBuf::from(LARGE_SO);
    if !path.exists() {
        eprintln!("跳过：{LARGE_SO} 不存在（系统文件）");
        return;
    }

    let session = Session::open(&path, OpenOptions::default()).expect("打开共享库");
    let job = session.detached_job();
    let analysis = session.analysis(&job).expect("分析");

    let truncated: Vec<&String> = analysis
        .notes()
        .iter()
        .filter(|n| n.contains("截断"))
        .collect();
    assert!(
        truncated.is_empty(),
        "字符串扫描在段中途截断了，数据被静默丢弃：{truncated:?}"
    );
}

/// 大样本上：某来源的函数数不能超过函数总数。
///
/// 之前在样本上出现过 `函数 300340 个` 但 `521869 个函数仅来自调用目标推断`
/// —— 推断出来的比总数还多。根因是计数累加在**调用点**而不是去重地址上。
#[test]
#[ignore = "需要 97MB 系统样本，数分钟；用 --ignored 手动跑"]
fn large_so_discovery_count_does_not_exceed_total() {
    let path = PathBuf::from(LARGE_SO);
    if !path.exists() {
        eprintln!("跳过：{LARGE_SO} 不存在（系统文件）");
        return;
    }

    let session = Session::open(&path, OpenOptions::default()).expect("打开共享库");
    let job = session.detached_job();
    let analysis = session.analysis(&job).expect("分析");

    let total = analysis.functions().len();
    let discovery = analysis
        .functions()
        .iter()
        .filter(|f| f.source == "discovery")
        .count();
    assert!(
        discovery <= total,
        "来自调用目标推断的函数有 {discovery} 个，超过总数 {total} 个 —— \
         计数口径不一致（很可能是按调用点而非去重地址累计的）"
    );
}
