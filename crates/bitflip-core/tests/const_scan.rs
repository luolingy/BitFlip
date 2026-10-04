//! 常量/结构体初步推断的端到端回归测试（M6）。
//!
//! # 这组测试守的是什么
//!
//! 这一项的三个结论（字符串引用、访问步长、立即数画像）有个共同的
//! 失效模式：**它们会静默地返回空**。不 panic、不报错，只是少给数据 ——
//! 用户看到"0 条字符串被引用"，会以为"这个目标确实没有字符串引用"，
//! 而真实原因可能是整条链路根本没能产出输入。
//!
//! 这不是假设。开发过程中就是如此：`bitflip-arch` 在 x86 上不产出
//! `Operand::PcRelative`（RIP 相对被当成普通 `Mem`），于是
//! `xrefs_of` 的数据引用分支永远命中不了。ntdll.dll 上提取到 6487 条
//! 字符串，聚合结果是 **0 条被引用**。修复后同一目标是 **806 条**。
//!
//! 所以测试的重点不是"函数返回了东西"，而是：
//!
//! 1. **在真实目标上，结论必须非空且量级合理** —— 空结果要能说明理由；
//! 2. **地址要能对得上**：聚合出的字符串地址必须真的是一条字符串；
//! 3. **不做假**：推不出步长时是 `null` 而不是 0；引用者为空时是真的空。

use std::path::PathBuf;

use bitflip_core::{OpenOptions, Session};

/// 指向仓库根下的生成样本目录。
fn generated_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("..")
        .join("..")
        .join("tests")
        .join("fixtures")
        .join("generated")
}

/// 打开常量分析 fixture（`m3-mingw-static.exe`）。
///
/// 选它而不是 `switch-x86_64.exe`：后者是极小的跳转表 fixture
/// （3.5 KB），里面**一条字符串都没有**，用它测字符串引用聚合会
/// 一直失败在"前置条件不成立"上。`m3-mingw-static.exe` 是真实
/// 静态链接的 MinGW 程序（45 KB，155 函数 / 71 字符串 / 1972 xref），
/// 才足够验证这条链路确实工作。
fn open_fixture(name: &str) -> Session {
    let path = generated_dir().join(name);
    assert!(
        path.exists(),
        "缺少样本 {}。生成方式见 docs/PLAN.md §5.2（scripts/gen-*.py）",
        path.display()
    );
    Session::open(&path, OpenOptions::default()).expect("打开样本")
}

/// fixture 里必须真的能聚合出字符串引用。
///
/// 这条是上面那个静默失效的**直接回归门禁**：如果哪天解码层又不再
/// 产出 `PcRelative`（或改动让它失效），这里会立刻变红，而不是等到
/// 有人在真实目标上偶然发现"怎么全是 0"。
#[test]
fn fixture_reports_string_references_rather_than_silently_nothing() {
    let session = open_fixture("m3-mingw-static.exe");
    let job = session.detached_job();
    let analysis = session.analysis(&job).expect("分析");

    let scan = analysis.const_scan();

    assert!(
        !scan.strings.is_empty(),
        "没有聚合出任何字符串引用。这几乎总是**链路断了**而不是目标真的没有引用：\
         检查解码层是否为 RIP 相对寻址产出 Operand::PcRelative。说明：{:?}",
        scan.notes
    );

    // 每条记录都要能被核对：地址可解析、引用点非空
    for usage in &scan.strings {
        assert_eq!(usage.address.len(), 16, "地址必须定长 16 位");
        assert!(!usage.sites.is_empty(), "有记录就必须有引用点");
        for f in &usage.functions {
            assert_eq!(f.len(), 16);
        }
    }
}

/// 聚合出的字符串地址必须**真的**落在字符串表里。
///
/// 防止"聚合出了一堆地址，但它们指向的不是字符串"这种看起来成功的
/// 错误 —— 那比返回空更糟，因为用户会信。
#[test]
fn aggregated_string_addresses_correspond_to_real_strings() {
    let session = open_fixture("m3-mingw-static.exe");
    let job = session.detached_job();
    let analysis = session.analysis(&job).expect("分析");

    // 字符串表里每条字符串覆盖 [address, address+size)
    let strings: Vec<(String, u64)> = analysis
        .strings()
        .iter()
        .map(|s| (s.address.clone(), s.size))
        .collect();
    assert!(!strings.is_empty(), "fixture 应当有字符串");

    let scan = analysis.const_scan();
    assert!(!scan.strings.is_empty(), "前置条件：有聚合结果");

    let starts: Vec<&str> = strings.iter().map(|(a, _)| a.as_str()).collect();
    for usage in &scan.strings {
        assert!(
            starts.contains(&usage.address.as_str()),
            "聚合出的地址 {} 不是任何字符串的起点（字符串起点：{:?}）",
            usage.address,
            &starts[..starts.len().min(8)]
        );
    }
}

/// 引用者归属必须落在真实函数上。
///
/// **允许为空**（引用点可能在所有已知函数之外），但非空时必须真的是
/// 一个函数入口 —— 不能出现"归给了某个不存在的函数"。
#[test]
fn string_reference_owners_are_real_function_entries() {
    let session = open_fixture("m3-mingw-static.exe");
    let job = session.detached_job();
    let analysis = session.analysis(&job).expect("分析");

    let entries: Vec<&str> = analysis
        .functions()
        .iter()
        .map(|f| f.start.as_str())
        .collect();
    assert!(!entries.is_empty(), "fixture 应当有函数");

    let scan = analysis.const_scan();
    for usage in &scan.strings {
        for owner in &usage.functions {
            assert!(
                entries.contains(&owner.as_str()),
                "字符串 {} 的引用者 {} 不是任何已知函数入口",
                usage.address,
                owner
            );
        }
    }
}

/// 推不出步长时必须是 `null`，**不是 0**。
///
/// 0 是个看起来合理的值，填进去 UI 会显示"步长 0"，而真实含义是
/// "不知道"。CLAUDE.md §7 明确禁止拿默认值冒充结论。
#[test]
fn unknown_stride_is_null_not_zero() {
    let session = open_fixture("m3-mingw-static.exe");
    let job = session.detached_job();
    let analysis = session.analysis(&job).expect("分析");

    let scan = analysis.const_scan();
    // 无论有没有步长结论，都不允许出现 stride == Some(0)
    for s in &scan.strides {
        assert_ne!(
            s.stride,
            Some(0),
            "步长 0 不可能：推不出来应当是 null。位置 base={} width={}",
            s.base,
            s.width
        );
    }
}

/// 立即数统计必须自洽：top 的条数不超过 distinct，计数之和不超过 total。
#[test]
fn immediate_profile_is_internally_consistent() {
    let session = open_fixture("m3-mingw-static.exe");
    let job = session.detached_job();
    let analysis = session.analysis(&job).expect("分析");

    let scan = analysis.const_scan();

    assert!(
        scan.immediates.len() <= scan.immediate_distinct,
        "top 条数 {} 不能超过去重总数 {}",
        scan.immediates.len(),
        scan.immediate_distinct
    );

    let sum: usize = scan.immediates.iter().map(|i| i.count).sum();
    assert!(
        sum <= scan.immediate_total,
        "top 的计数之和 {sum} 不能超过总数 {}",
        scan.immediate_total
    );

    // 降序排列：否则 UI 上"高频立即数"会名不副实
    for w in scan.immediates.windows(2) {
        assert!(
            w[0].count >= w[1].count,
            "立即数画像必须按出现次数降序：{} 次出现在 {} 次之前",
            w[0].count,
            w[1].count
        );
    }

    // 值必须是可解析的十进制（前端直接显示，也用来做大整数比较）
    for i in &scan.immediates {
        assert!(
            i.value.parse::<i64>().is_ok(),
            "立即数值必须是十进制字符串，实际 {:?}",
            i.value
        );
    }
}

/// 空结论必须带解释。
///
/// 如果某个目标真的推不出任何东西，`notes` 里要有话说 ——
/// 否则用户看到的是一片空白，分不清"没有"和"没做"。
#[test]
fn empty_results_come_with_an_explanation() {
    let session = open_fixture("m3-mingw-static.exe");
    let job = session.detached_job();
    let analysis = session.analysis(&job).expect("分析");

    let scan = analysis.const_scan();

    // 这条 fixture 应当有立即数（任何真实代码都有），所以只检查：
    // 若某项为空，notes 里必须有对应说明
    if scan.immediates.is_empty() {
        assert!(
            scan.notes.iter().any(|n| n.contains("立即数")),
            "立即数为空但没有说明"
        );
    }
    if scan.strings.is_empty() {
        assert!(
            scan.notes.iter().any(|n| n.contains("字符串")),
            "字符串引用为空但没有说明"
        );
    }
}
