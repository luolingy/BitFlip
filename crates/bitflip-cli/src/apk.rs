//! `bitflip-cli apk`：看 APK 清单（M11 · M3 的第一片）。
//!
//! 三个出口共用**同一次解析**：摘要（默认）、还原出的 XML（`--xml`）、稳定的 wire
//! JSON（`--json`）。这样"界面上看到的"和"脚本里拿到的"不会各算一遍而分叉。

use anyhow::{bail, Result};

use crate::cli::ApkArgs;

/// 跑 `apk` 子命令：解析一次，按开关打印摘要 / XML / JSON。
///
/// # Errors
///
/// 打开目标失败、目标里没有清单、或清单不是能解析的 AXML —— 都会带着**具体原因**
/// 返回（清单视图的价值就在于原因，压成一句"解析失败"等于没有）。
pub fn run_apk(args: &ApkArgs) -> Result<()> {
    if args.xml && args.json {
        bail!("`--xml` 与 `--json` 只能给一个：前者要还原出的 XML 文本，后者要结构化的摘要");
    }

    let session = bitflip_core::Session::open(&args.target, args.raw.to_open_options()?)?;
    let report = bitflip_core::axml::read_manifest(&session, args.member.as_deref())?;

    let text = if args.json {
        json(&report)
    } else if args.xml {
        report.xml.clone()
    } else {
        summary(&report)
    };
    print!("{text}");
    if !text.ends_with('\n') {
        println!();
    }
    Ok(())
}

/// 给人看的摘要。
fn summary(report: &bitflip_core::axml::ManifestReport) -> String {
    let facts = &report.facts;
    let mut out = String::new();
    out.push_str(&format!(
        "清单：{}（{} 字节 AXML，还原出 {} 字节 XML）\n",
        report.member.as_deref().unwrap_or("（单文件目标）"),
        report.size,
        report.xml.len()
    ));
    out.push_str(&report.headline());
    out.push('\n');
    out.push_str(&format!(
        "minSdk {} · targetSdk {}\n",
        facts.min_sdk.as_deref().unwrap_or("未声明"),
        facts.target_sdk.as_deref().unwrap_or("未声明")
    ));
    if facts.main_activities.is_empty() {
        out.push_str("入口 activity：未声明\n");
    } else {
        out.push_str(&format!(
            "入口 activity：{}\n",
            facts.main_activities.join(", ")
        ));
    }
    for note in &facts.notes {
        out.push_str(&format!("注意：{note}\n"));
    }
    out
}

/// 稳定的 wire JSON（键名与字段顺序固定，前端与脚本按它写）。
fn json(report: &bitflip_core::axml::ManifestReport) -> String {
    let facts = &report.facts;
    let payload = serde_json::json!({
        "format_version": 1,
        "member": report.member,
        "size": report.size,
        "facts": {
            "root": facts.root,
            "package": facts.package,
            "version_code": facts.version_code,
            "version_name": facts.version_name,
            "min_sdk": facts.min_sdk,
            "target_sdk": facts.target_sdk,
            "main_activities": facts.main_activities,
            "activities": facts.activities,
            "services": facts.services,
            "receivers": facts.receivers,
            "providers": facts.providers,
            "permissions": facts.permissions,
            "unresolved_references": facts.unresolved_references,
            "notes": facts.notes,
        },
    });
    serde_json::to_string_pretty(&payload).unwrap_or_else(|_| "{}".to_string())
}
