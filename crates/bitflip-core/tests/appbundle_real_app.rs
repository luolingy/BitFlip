//! `.app` 批量重签的**真实样本**端到端回归（默认 `#[ignore]`）。
//!
//! ## 这条测试要守什么
//!
//! `appbundle` 的单测只覆盖管道（Mach-O 识别、in-place 防护、无 Mach-O 报告）。真正的
//! 端到端契约要**真实 `.app`** 才测得出：枚举数正确、`--apply` 后每个二进制**重新 parse
//! 仍 Intact/AdHoc**、`CodeResources` 能读能重算。CI 里没有 Mach-O 样本（gen-fixtures 不产），
//! 所以默认忽略；用 `BITFLIP_APPBUNDLE_SAMPLE=<X.app 路径>` 指向一个真实 `.app` 后加
//! `--ignored` 运行（§0.2：不假装通过，缺样本就明说跳过）。
//!
//! 绝不原地改：验证输出到 `tempfile` 目录里的副本，原 `.app` 不动。

use std::path::Path;

use bitflip_core::appbundle::{apply_resign_app, plan_resign_app, CodeResourcesStatus};
use bitflip_core::{OpenOptions, Session};

#[test]
#[ignore = "需要真实 .app 样本：设 BITFLIP_APPBUNDLE_SAMPLE 后加 --ignored"]
fn real_app_bundle_resign_roundtrip() {
    let Ok(app) = std::env::var("BITFLIP_APPBUNDLE_SAMPLE") else {
        eprintln!("跳过：未设 BITFLIP_APPBUNDLE_SAMPLE");
        return;
    };
    let root = Path::new(&app);

    // 1) 只读计划：枚举数、可重签数、CodeResources 状态。
    let plan = plan_resign_app(root).expect("能规划");
    let cr_desc = match &plan.coderes {
        CodeResourcesStatus::Parsed { entries, .. } => format!("parsed({entries})"),
        CodeResourcesStatus::NotXml => "not-xml".to_string(),
        CodeResourcesStatus::Absent => "absent".to_string(),
    };
    eprintln!(
        "Mach-O={} 可重签={} 失败={} coderes={cr_desc}",
        plan.machos.len(),
        plan.resignable.len(),
        plan.failed.len(),
    );
    assert!(!plan.machos.is_empty(), "真实 .app 里应有 Mach-O");
    assert_eq!(
        plan.failed.len(),
        0,
        "真实样本上不应有重签失败：{:?}",
        plan.failed
    );

    // 2) 应用到临时副本（绝不原地改）。
    let tmp = tempfile::tempdir().expect("临时目录");
    let out = tmp.path().join("resigned.app");
    let report = apply_resign_app(&plan, &out).expect("能应用");
    assert_eq!(
        report.resigned,
        plan.resignable.len(),
        "写出数应等于可重签数"
    );
    assert!(out.is_dir(), "应写出新目录");

    // 3) 每个**原本可解析**的二进制，重签后重新 parse 且签名自洽（Intact 或 AdHoc）。
    //    原本就无法解析的（如导出 trie 畸形的真实 framework），重签不改变"解析不了"这一事实，
    //    如实跳过并计数——不假装它变好了，也不因它失败而否定重签（§7）。
    let mut checked = 0usize;
    let mut skipped_unparseable = 0usize;
    for probe in &plan.machos {
        // 先看原始文件能不能解析：不能的话，重签也不该被要求解析。
        let original = Session::open(&probe.path, OpenOptions::default());
        let originally_parseable = original
            .as_ref()
            .map(|s| s.parsed().is_some())
            .unwrap_or(false);
        if !originally_parseable {
            skipped_unparseable += 1;
            eprintln!("跳过（原本就解析不了）：{}", probe.rel);
            continue;
        }

        let dst = out.join(&probe.rel);
        let session = Session::open(&dst, OpenOptions::default())
            .unwrap_or_else(|e| panic!("重签后打不开 {}：{e}", probe.rel));
        let obj = session
            .parsed()
            .unwrap_or_else(|| panic!("{} 原本可解析，重签后却解析结果为空", probe.rel));
        assert!(obj.signature.applicable, "{} 应是 Mach-O", probe.rel);
        let verdict = obj.signature.verdict.as_str();
        assert!(
            matches!(verdict, "Intact" | "AdHoc"),
            "{} 重签后签名结论应自洽（Intact/AdHoc），实为 {verdict}：{}",
            probe.rel,
            obj.signature.notes.join("; ")
        );
        checked += 1;
    }
    eprintln!(
        "已核对 {checked} 个二进制签名自洽；{skipped_unparseable} 个原本就解析不了（已如实跳过）"
    );
    assert!(checked > 0, "至少应核对到一个可解析二进制");

    // 4) CodeResources 能读能重算，条目数不丢。
    if let CodeResourcesStatus::Parsed { entries, .. } = &plan.coderes {
        let cr = out.join("_CodeSignature/CodeResources");
        let cr_bytes = std::fs::read(&cr).expect("读重算后的 CodeResources");
        let after = bitflip_core::extract_code_resource_hashes(&cr_bytes)
            .expect("重算后仍应是可解析 XML plist");
        assert_eq!(
            after.len(),
            *entries,
            "重算后条目数必须与旧清单一致（数量自洽）"
        );
        eprintln!("CodeResources 条目数 {entries} 保持（重算后仍可解析）");
        assert!(report.coderes_rewritten, "XML plist 应被重写");

        // 抽查：受影响的条目，其清单哈希应已等于磁盘上新文件的真实哈希（自洽）。
        use sha1::Digest as _;
        let mut verified = 0usize;
        for rel in plan.affected.iter().take(5) {
            let disk = std::fs::read(out.join(rel)).expect("读磁盘新文件");
            let want_sha1 = sha1::Sha1::digest(&disk).to_vec();
            let want_sha256 = sha2::Sha256::digest(&disk).to_vec();
            let entry = after
                .iter()
                .find(|h| &h.path == rel)
                .unwrap_or_else(|| panic!("清单里应仍有 {rel}"));
            assert_eq!(
                entry.sha1.as_deref(),
                Some(want_sha1.as_slice()),
                "{rel} 的清单 SHA-1 应等于新文件哈希"
            );
            if let Some(sha256) = &entry.sha256 {
                assert_eq!(
                    sha256.as_slice(),
                    want_sha256.as_slice(),
                    "{rel} SHA-256 应一致"
                );
            }
            verified += 1;
        }
        assert!(verified >= 1, "至少应核对到一个受影响条目");
        eprintln!("已核对 {verified} 个受影响条目的清单哈希与新文件一致");
    }
}
