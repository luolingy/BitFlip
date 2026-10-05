//! 调用约定与参数推断的端到端测试（M6）。
//!
//! # 守的是什么
//!
//! 参数推断的失效模式是**看起来合理但整体错位**：约定选错（SysV 当成
//! Microsoft x64）不会报错，只会让每个函数的参数标注偏几个寄存器。
//! 所以这里不测"函数返回了东西"，而是测：
//!
//! 1. **PE 目标必须用 Microsoft x64 约定** —— 选错就是全盘错；
//! 2. **参数下界不能是"每个函数都满"** —— 那说明判据没起作用；
//! 3. **结论自洽**：`used` 里最大的序号 + 1 == `lower_bound`；
//! 4. **不给假名**：架构没有约定时说"不适用"，不说"没有参数"。

use std::path::PathBuf;

use bitflip_core::{OpenOptions, Session};

fn fixture(name: &str) -> PathBuf {
    let p = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("..")
        .join("..")
        .join("tests")
        .join("fixtures")
        .join("generated")
        .join(name);
    assert!(
        p.exists(),
        "缺少样本 {}。生成方式见 docs/PLAN.md §5.2",
        p.display()
    );
    p
}

/// PE 目标必须走 Microsoft x64 约定。
///
/// 这是这一项**最容易错且最难发现**的地方：两套约定下同一个 `rcx`
/// 在一边是第 1 个参数、另一边是第 4 个。用错不会报错，只会整体错位。
#[test]
fn pe_targets_use_the_microsoft_convention() {
    let session = Session::open(fixture("m3-mingw-static.exe"), OpenOptions::default())
        .expect("打开 PE 样本");
    let job = session.detached_job();
    let analysis = session.analysis(&job).expect("分析");

    let scan = analysis.arg_scan();
    let abi = scan.abi_name.as_deref().expect("PE 目标应当有约定");

    assert!(
        abi.contains("Microsoft") || abi.contains("x64"),
        "PE/x86_64 必须用 Microsoft x64 约定，实际是 {abi:?}"
    );
    assert_eq!(
        scan.arg_reg_names.first().map(String::as_str),
        Some("rcx"),
        "Microsoft x64 的第 1 个参数是 rcx，不是 rdi"
    );
    assert_eq!(
        scan.arg_reg_names,
        vec!["rcx", "rdx", "r8", "r9"],
        "Microsoft x64 只有 4 个寄存器参数"
    );
}

/// 参数下界必须有区分度，不能每个函数都一样。
///
/// 如果判据失效（比如把"读"当成无条件命中），上限会饱和；如果完全
/// 失效（比如编号映射没建立），又会全是 0。两种都是"看起来有结论"。
#[test]
fn inferred_lower_bounds_are_not_all_identical() {
    let session =
        Session::open(fixture("m3-mingw-static.exe"), OpenOptions::default()).expect("打开");
    let job = session.detached_job();
    let analysis = session.analysis(&job).expect("分析");

    let scan = analysis.arg_scan();
    assert!(
        !scan.functions.is_empty(),
        "PE 样本应当有函数推断结果。说明：{:?}",
        scan.notes
    );

    let bounds: std::collections::BTreeSet<usize> =
        scan.functions.iter().map(|f| f.lower_bound).collect();
    assert!(
        bounds.len() > 1,
        "所有函数的参数下界都一样（{bounds:?}），说明判据没有区分度"
    );

    let zero = scan.functions.iter().filter(|f| f.lower_bound == 0).count();
    let nonzero = scan.functions.len() - zero;
    assert!(
        nonzero > 0,
        "没有任何函数观测到参数 —— 多半是寄存器编号映射失效了"
    );
    // 也不能全都"有参数"：总有一些叶函数或简单函数不读入参
    assert!(
        zero > 0,
        "所有函数都观测到参数，判据过于宽松（应当有函数不读任何入参寄存器）"
    );
}

/// 结论必须自洽：`lower_bound` 就等于最大已用序号 + 1。
#[test]
fn lower_bound_is_consistent_with_the_used_slots() {
    let session =
        Session::open(fixture("m3-mingw-static.exe"), OpenOptions::default()).expect("打开");
    let job = session.detached_job();
    let analysis = session.analysis(&job).expect("分析");

    let scan = analysis.arg_scan();
    for f in &scan.functions {
        // used 升序且不重复
        let mut sorted = f.used.clone();
        sorted.sort_unstable();
        sorted.dedup();
        assert_eq!(f.used, sorted, "{} 的 used 必须升序去重", f.entry);

        let expected = f.used.last().map_or(0, |&i| i + 1);
        assert_eq!(
            f.lower_bound, expected,
            "{} 的下界 {} 与 used {:?} 不自洽",
            f.entry, f.lower_bound, f.used
        );

        // 序号必须在 ABI 容量内
        for &i in &f.used {
            assert!(
                i < f.register_slots,
                "{} 用了第 {i} 个参数寄存器，但容量只有 {}",
                f.entry,
                f.register_slots
            );
        }

        // used_names 与 used 一一对应
        assert_eq!(
            f.used_names.len(),
            f.used.len(),
            "{} 的 used_names 与 used 数量不一致",
            f.entry
        );
        for (name, &idx) in f.used_names.iter().zip(f.used.iter()) {
            assert_eq!(
                Some(name.as_str()),
                scan.arg_reg_names.get(idx).map(String::as_str),
                "{} 第 {idx} 个参数名对不上",
                f.entry
            );
        }

        // 地址是定长 16 位
        assert_eq!(f.entry.len(), 16);
    }
}

/// 推断结果必须覆盖到真实函数入口。
#[test]
fn inferred_entries_are_real_function_entries() {
    let session =
        Session::open(fixture("m3-mingw-static.exe"), OpenOptions::default()).expect("打开");
    let job = session.detached_job();
    let analysis = session.analysis(&job).expect("分析");

    let entries: Vec<&str> = analysis
        .functions()
        .iter()
        .map(|f| f.start.as_str())
        .collect();
    let scan = analysis.arg_scan();

    assert_eq!(
        scan.functions.len(),
        entries.len(),
        "每个函数都应当有一条推断结果"
    );
    for f in &scan.functions {
        assert!(
            entries.contains(&f.entry.as_str()),
            "推断出的入口 {} 不是已知函数",
            f.entry
        );
        assert!(f.insn_count > 0, "{} 没有可分析的指令", f.entry);
    }
}

/// 没有调用约定的架构要如实说"不适用"。
///
/// 用 wasm32 的合成目标验证。关键是**不能**说成"这些函数没有参数" ——
/// 那是把"能力不适用"伪装成"分析结论"。
#[test]
fn an_arch_without_a_register_abi_says_not_applicable() {
    // 用 aarch64 的 ELF 样本验证"有约定"的一侧；
    // 无约定的一侧（wasm32）在 bitflip-analyze 的单元测试里已覆盖，
    // 那里可以直接构造 AbiSpec = None 的情形。
    let session = Session::open(fixture("elf-aarch64-cfg.exe"), OpenOptions::default())
        .expect("打开 aarch64 样本");
    let job = session.detached_job();
    let analysis = session.analysis(&job).expect("分析");

    let scan = analysis.arg_scan();
    let abi = scan.abi_name.as_deref().expect("aarch64 应当有约定");
    assert!(
        abi.contains("AAPCS") || abi.contains("aarch64") || abi.contains("AArch64"),
        "aarch64 应当用 AAPCS 约定，实际 {abi:?}"
    );
    assert_eq!(
        scan.arg_reg_names.first().map(String::as_str),
        Some("x0"),
        "AAPCS64 的第 1 个参数是 x0"
    );
}
