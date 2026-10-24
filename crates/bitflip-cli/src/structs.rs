//! `structs`：从指令流推断"疑似结构体字段布局"（阶段 2 第一片）。
//!
//! 只读、启发式：把形如 `[base + disp]` 的内存访问按基址寄存器聚合成字段
//! （偏移 / 宽度 / 读写次数），推断结构体大小。**不是真实 C 类型**，边界见
//! `bitflip_analyze::structs`。默认人类可读，`--json` 给稳定契约。

use bitflip_core::Session;

use crate::cli::StructsArgs;

pub fn run_structs(args: &StructsArgs) -> anyhow::Result<()> {
    let session = Session::open(&args.target, args.raw.to_open_options()?)?;

    if session.info().is_archive() {
        anyhow::bail!(
            "{} 是归档（{} 个成员）：结构体推断需要具体成员的反汇编。\
             先用 `members` 看成员，再对具体成员跑 `structs`。",
            session.info().path,
            session.members().len()
        );
    }

    let outcome = session
        .structs_report()
        .map_err(|e| anyhow::anyhow!("{e}"))?;
    let report = &outcome.report;

    if args.json {
        let payload = serde_json::json!({
            "target": session.info().path,
            "instructions": outcome.instructions,
            "function_ranges": outcome.function_ranges,
            "candidates": report.candidates.iter().map(|c| serde_json::json!({
                "base_reg": c.base.0,
                "function": c.function.map(|f| format!("{f:016x}")),
                "size": c.size,
                "field_count": c.fields.len(),
                "access_count": c.access_count(),
                "fields": c.fields.iter().map(|f| serde_json::json!({
                    "offset": f.offset,
                    "widths": f.widths,
                    "reads": f.reads,
                    "writes": f.writes,
                })).collect::<Vec<_>>(),
            })).collect::<Vec<_>>(),
            "notes": report.notes,
            "disclaimer": "疑似结构体：启发式证据，非真实 C 类型",
        });
        println!("{}", serde_json::to_string_pretty(&payload)?);
        return Ok(());
    }

    // 人类可读。
    println!("目标：{}", session.info().path);
    println!(
        "解码指令 {} 条 · 函数区间 {} 个 · 疑似结构体 {} 个",
        outcome.instructions,
        outcome.function_ranges,
        report.candidates.len()
    );
    println!();
    let show = if args.limit == 0 {
        report.candidates.len()
    } else {
        args.limit.min(report.candidates.len())
    };
    for (i, c) in report.candidates.iter().take(show).enumerate() {
        let func = c
            .function
            .map(|f| format!("sub_{f:016x}"))
            .unwrap_or_else(|| "(未知函数)".to_string());
        println!(
            "[{i}] {func} base=reg{} 大小≈{} 字段 {} 访问 {}",
            c.base.0,
            c.size,
            c.fields.len(),
            c.access_count()
        );
        for f in &c.fields {
            let widths: Vec<String> = f.widths.iter().map(|w| format!("{w}B")).collect();
            let wtext = if widths.is_empty() {
                "宽度未知".to_string()
            } else {
                widths.join("/")
            };
            println!(
                "    +{:#06x} 宽度[{wtext}]  读 {} 写 {}",
                f.offset, f.reads, f.writes
            );
        }
    }
    if show < report.candidates.len() {
        println!(
            "…… 其余 {} 个未显示（--limit 0 显示全部）",
            report.candidates.len() - show
        );
    }
    println!();
    for n in &report.notes {
        println!("· {n}");
    }
    println!();
    println!("注意：这些是**疑似结构体字段**（启发式推断），不是真实的 C 类型；请结合反汇编判断。");
    Ok(())
}
