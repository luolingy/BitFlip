//! `resign-app`：批量重签一个 `.app` 包里的所有 Mach-O，并让 `CodeResources` 清单自洽。
//!
//! 薄封装：所有逻辑（枚举 Mach-O、读/重算 `CodeResources`、计划与落盘）都在
//! [`bitflip_core::appbundle`]，这里只负责把结果打印/序列化、接 CLI 参数。
//!
//! 安全语义同 `resign`：**默认只读预览**，`--apply` 才写出 `xxx.resigned.app` 目录；原包不动。
//! 只走 ad-hoc（不接证书、不产 CMS）。`CodeResources` 只是"哈希自洽"，**不是可信封印**——
//! 真机仍需 `codesign` 复核，输出里会明确提示。

use bitflip_core::appbundle::{
    apply_resign_app, default_output, plan_resign_app, plan_summary_line, CodeResourcesStatus,
};

use crate::cli::ResignAppArgs;

pub fn run_resign_app(args: &ResignAppArgs) -> anyhow::Result<()> {
    let root = &args.target;
    let plan = plan_resign_app(root).map_err(|e| anyhow::anyhow!("{e}"))?;

    println!("扫描 .app：{}", root.display());
    println!("  {}", plan_summary_line(&plan));
    for (rel, err) in &plan.failed {
        println!("  ✗ 跳过 {rel}：{err}");
    }

    if args.json {
        let coderes_entries = match &plan.coderes {
            CodeResourcesStatus::Parsed { entries, .. } => Some(*entries),
            _ => None,
        };
        let payload = serde_json::json!({
            "target": root.display().to_string(),
            "machos": plan.machos.len(),
            "resignable": plan.resignable.len(),
            "failed": plan.failed.iter()
                .map(|(r, e)| serde_json::json!({"path": r, "error": e}))
                .collect::<Vec<_>>(),
            "coderes_entries": coderes_entries,
            "coderes_status": match &plan.coderes {
                CodeResourcesStatus::Absent => "absent",
                CodeResourcesStatus::NotXml => "not-xml",
                CodeResourcesStatus::Parsed { .. } => "parsed",
            },
            "coderes_affected": plan.affected,
            "apply": args.apply,
        });
        println!("{}", serde_json::to_string_pretty(&payload)?);
    }

    if !args.apply {
        println!();
        println!("（只读预览：未写盘。确认无误后加 `--apply` 写出 `xxx.resigned.app`。）");
        return Ok(());
    }

    let out_dir = args.output.clone().unwrap_or_else(|| default_output(root));
    let report = apply_resign_app(&plan, &out_dir).map_err(|e| anyhow::anyhow!("{e}"))?;

    println!();
    println!("已写出副本  {}", report.out_dir.display());
    println!("  重签二进制 {} 个", report.resigned);
    if report.coderes_rewritten {
        println!(
            "  CodeResources 已按新哈希重算 {} 条（尽力自洽；**不是可信封印**，真机仍需 codesign 复核）",
            report.coderes_updated
        );
    } else if matches!(plan.coderes, CodeResourcesStatus::Parsed { .. }) {
        println!("  CodeResources 已解析但重写失败：未改动，需真机 codesign 重建");
    } else if matches!(plan.coderes, CodeResourcesStatus::NotXml) {
        println!(
            "  CodeResources 无法重算（二进制 plist 或不可解析）：未改动，需真机 codesign 重建"
        );
    }
    println!("  提醒：ad-hoc 签名不带证书/CMS；本工具不产可信签名，仅让完整性/清单一类自洽");
    Ok(())
}
