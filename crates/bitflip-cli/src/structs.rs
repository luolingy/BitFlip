//! `structs`：从指令流推断"疑似结构体字段布局"（阶段 2 第一片）。
//!
//! 只读、启发式：把形如 `[base + disp]` 的内存访问按基址寄存器聚合成字段
//! （偏移 / 宽度 / 读写次数），推断结构体大小。**不是真实 C 类型**，边界见
//! `bitflip_analyze::structs`。默认人类可读，`--json` 给稳定契约。

use anyhow::Context;
use bitflip_core::{
    derive_function_start_bounds, infer_struct_fields, DecodedInsn, DisasmScanOptions, Flow,
    Session,
};

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

    // 反汇编整个目标，再取回所有解码指令（结构化操作数）。
    let disasm = session
        .disassemble(DisasmScanOptions::default())
        .context("反汇编失败")?;
    let insns = disasm.decode_range(0, u64::MAX);

    // 取函数区间（结构体推断必须按函数分组，否则同号寄存器跨函数混成假结构体）。
    let functions = collect_function_ranges(&session, &insns);
    let report = infer_struct_fields(&insns, &functions);

    if args.json {
        let payload = serde_json::json!({
            "target": session.info().path,
            "instructions": insns.len(),
            "candidates": report.candidates.iter().map(|c| serde_json::json!({
                "base_reg": c.base.0,
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
        "解码指令 {} 条 · 疑似结构体 {} 个",
        insns.len(),
        report.candidates.len()
    );
    println!();
    let show = if args.limit == 0 {
        report.candidates.len()
    } else {
        args.limit.min(report.candidates.len())
    };
    for (i, c) in report.candidates.iter().take(show).enumerate() {
        println!(
            "[{i}] base=reg{} 大小≈{} 字段 {} 访问 {}",
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

/// 从会话分析结果里取 `(函数入口, 结束)` 区间。地址字段是 16 位十六进制串。
///
/// 不调用完整 `analysis()`（那会做全 CFG，对 kernel32.dll 这类大文件要几分钟）：
/// 优先用文件自带的函数起点（Mach-O `LC_FUNCTION_STARTS` 等），**再用直接调用目标补足**
/// （这是廉价且标准的函数发现启发式），最后把起点排序、以"下一个起点"作为上一个的结束。
/// 没有起点信息时退回"整段代码一个区域"——此时不会跨函数混（本来也没函数边界），
/// 但仍可能把不同函数的同号寄存器算到一起，报告里会说明。
fn collect_function_ranges(session: &Session, insns: &[DecodedInsn]) -> Vec<(u64, Option<u64>)> {
    use std::collections::BTreeSet;

    let mut starts: BTreeSet<u64> = BTreeSet::new();

    // 1) 文件自带的函数起点。
    if let Some(object) = session.object() {
        for b in derive_function_start_bounds(object) {
            starts.insert(b.start);
        }
    }

    // 2) 直接调用目标（廉价函数发现）：落在已解码代码里的 target 视作函数入口。
    let mut code: BTreeSet<u64> = BTreeSet::new();
    for insn in insns {
        code.insert(insn.addr);
    }
    if let Some(&first) = insns.iter().map(|i| i.addr).min().as_ref() {
        starts.insert(first);
    }
    for insn in insns {
        if matches!(insn.flow, Flow::Call) {
            if let Some(t) = insn.target {
                if code.contains(&t) {
                    starts.insert(t);
                }
            }
        }
    }

    // 3) 起点排序 → 结束 = 下一个起点（最后一个无结束）。
    let sorted: Vec<u64> = starts.into_iter().collect();
    let mut out: Vec<(u64, Option<u64>)> = Vec::with_capacity(sorted.len());
    for (i, &s) in sorted.iter().enumerate() {
        let end = sorted.get(i + 1).copied();
        out.push((s, end));
    }
    out
}
