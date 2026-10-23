//! `patch` 子命令背后的端到端行为（真实 Mach-O）。
//!
//! 这里直接打 **`bitflip_patch` 的 API**，而不是去解析 CLI 的 stdout —— 因为这一片
//! 真正要钉住的是：**节级标签**（`__TEXT,__text` 而不是只给段名）、**只写副本**、
//! **原文件不变**。这三件事是 patch 的契约，stdout 只是它的展示。
//!
//! 真实样本是本机产物，不在仓库里，所以测试是 `#[ignore]` 的；**样本缺失时直接失败**
//! （CLAUDE.md §7：跳过与通过必须在报告里分得开），不静默通过。
//!
//! 跑法：
//! ```text
//! BITFLIP_PATCH_TEST_BINARY=<解出来的 Mach-O 主二进制> \
//!   cargo test -p bitflip-cli --test patch_cli -- --ignored --nocapture
//! ```

use std::path::PathBuf;

use bitflip_patch::PatchTarget;

/// 找到用于测试的真实 Mach-O 主二进制。
///
/// 优先 `BITFLIP_PATCH_TEST_BINARY`；否则用会话里解出来的 LiveContainer 主二进制
/// （`.smoke-logs/scratch-app/` 下那个奇怪长名字）。都找不到就**失败**，不跳过。
fn test_binary() -> PathBuf {
    if let Ok(path) = std::env::var("BITFLIP_PATCH_TEST_BINARY") {
        let path = PathBuf::from(path);
        assert!(
            path.is_file(),
            "BITFLIP_PATCH_TEST_BINARY={} 不是文件",
            path.display()
        );
        return path;
    }
    let candidate = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join(
        "../../.smoke-logs/scratch-app/\
         LiveContainer_PleaseDoNotShortenTheExecutableNameBecauseItIsUsedToReserveSpaceForOverwritingThankYou",
    );
    if candidate.is_file() {
        return candidate;
    }
    panic!(
        "找不到真实 Mach-O 样本：请设 BITFLIP_PATCH_TEST_BINARY=<主二进制>，\
         或把它放到 {}。真实样本测试不允许静默跳过（§7）",
        candidate.display()
    );
}

/// 这个二进制里 `__TEXT,__text` 的起始虚拟地址（用样例实测值；读不到就失败）。
const TEXT_VADDR: u64 = 0x1_0000_4000;

#[test]
#[ignore = "需要真实 Mach-O 主二进制；用 --ignored 手动跑"]
fn plan_reports_section_label_for_a_text_address() {
    let path = test_binary();
    let target = PatchTarget::open(&path).expect("应能打开真实 Mach-O");
    // 在 __TEXT,__text 起始处放一条 NOP，读回原字节做对照。
    let plan = target
        .plan(&[(TEXT_VADDR, vec![0x90, 0x90])])
        .expect("落在 __text 内应当允许");
    assert_eq!(plan.sites.len(), 1);
    let site = &plan.sites[0];
    assert_eq!(
        site.section.as_deref(),
        Some("__TEXT,__text"),
        "节级标签要精确到 __text"
    );
    assert_eq!(site.segment.as_deref(), Some("__TEXT"), "段名仍是 __TEXT");
    assert_eq!(plan.touched_sections(), vec!["__TEXT,__text".to_string()]);
    assert_eq!(site.original.len(), 2, "原字节是读回来的 2 字节");
    eprintln!(
        "计划：vaddr={:#x} file_offset={:#x} original={:02x?} section={:?}",
        site.vaddr, site.file_offset, site.original, site.section
    );
}

#[test]
#[ignore = "需要真实 Mach-O 主二进制；用 --ignored 手动跑"]
fn apply_writes_a_copy_and_leaves_the_original_untouched() {
    let path = test_binary();
    let original_bytes = std::fs::read(&path).expect("读原文件");

    let mut target = PatchTarget::open(&path).expect("应能打开真实 Mach-O");
    // 只读预览阶段：不写盘。
    let plan = target
        .plan(&[(TEXT_VADDR, vec![0x90, 0x90])])
        .expect("计划应当被接受");
    target.unlock();
    let report = target.apply(&plan).expect("解锁后应当能写出副本");

    // 副本存在、大小不变（等长替换）、该处字节确实变了。
    assert!(
        report.copy_path.is_file(),
        "副本应当写出：{}",
        report.copy_path.display()
    );
    assert_eq!(report.size_before, report.size_after, "等长替换，大小不变");
    assert_eq!(report.sections, vec!["__TEXT,__text".to_string()]);

    let copy_bytes = std::fs::read(&report.copy_path).expect("读副本");
    let offset = plan.sites[0].file_offset as usize;
    assert_eq!(
        &copy_bytes[offset..offset + 2],
        &[0x90, 0x90],
        "副本该处应已改成新字节"
    );
    assert_eq!(
        &copy_bytes[offset..offset + 2],
        &plan.sites[0].new[..],
        "副本该处应等于 plan.new"
    );

    // 原文件必须一字节不变。
    let after_bytes = std::fs::read(&path).expect("再读原文件");
    assert_eq!(after_bytes, original_bytes, "原文件必须未被改动");

    let _ = std::fs::remove_file(&report.copy_path);
}
