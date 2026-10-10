//! `diff`：比较同一个目标的两个版本。
//!
//! ## 这一层只做三件事
//!
//! 1. 解析参数（比哪几类、只看哪类、条目上限、输出格式）；
//! 2. 调 `bitflip_core::diff`；
//! 3. 把结果写到 `--out` 或标准输出，把**降级与截断**打到 stderr。
//!
//! 比对逻辑一概不在这一层实现。服务端 `GET /api/diff` 走同一个核心函数 ——
//! 两份各写一遍，早晚会漂移，而用户没法判断哪个可信（同 `export` 的理由）。
//!
//! ## 为什么可以不看 `--format` 就把结论说清
//!
//! 文本格式的头部就写着"地址归一化：RVA（各自减掉镜像基址）：v1 基址 …"，
//! 两个基址都是实测值。用户**不需要**先理解归一化再做判断 —— 报告自己
//! 交代了它按什么比。JSON 里同一份信息在 `normalization` 字段。
//!
//! ## 关于原始二进制覆盖
//!
//! `export` / `info` 有 `--arch` / `--base` 这类覆盖，`diff` **刻意没有**：
//! 这里同时开两个文件，一份覆盖参数该套到哪个上？套两个可能是错的（两个
//! 版本可以有不同的架构），套一个又没法表达"哪个"。与其猜，不如让用户
//! 先各自确认能正常打开（`info`）再来比。

use std::io::Write as _;
use std::path::Path;

use anyhow::Context;
use bitflip_core::{DiffKind, DiffOptions, DiffScope, Session};

use crate::cli::DiffArgs;

/// `diff` 入口。
pub fn run_diff(args: &DiffArgs) -> anyhow::Result<()> {
    crate::tracing_setup::init(args.verbose);

    let scope = DiffScope::parse(&args.scope).ok_or_else(|| {
        let available: Vec<&str> = DiffScope::all().iter().map(|s| s.as_str()).collect();
        anyhow::anyhow!(
            "比对类型无法识别：{:?}。可用值：{}",
            args.scope,
            available.join("、")
        )
    })?;

    let only = match args.only.as_deref() {
        None => None,
        Some(text) => Some(DiffKind::parse(text).ok_or_else(|| {
            let available: Vec<&str> = DiffKind::all().iter().map(|k| k.as_str()).collect();
            anyhow::anyhow!(
                "差异类别无法识别：{text:?}。可用值：{}",
                available.join("、")
            )
        })?),
    };

    // 两个路径相同是合法的（比一个文件和它自己），但用户几乎总是想给两个
    // 不同的文件。这是**提示**不是错误：拒绝会挡掉"验证实现自洽"这种正当用法。
    if args.old == args.new {
        eprintln!(
            "提示：两个目标路径相同（{}）—— 这次比对的结果应当全是「未变」；\
             如果不然，说明比对逻辑有问题，值得看一眼",
            args.old.display()
        );
    }

    let old = Session::open(&args.old, bitflip_core::OpenOptions::default())
        .with_context(|| format!("打开 v1 目标 {}", args.old.display()))?;
    let new = Session::open(&args.new, bitflip_core::OpenOptions::default())
        .with_context(|| format!("打开 v2 目标 {}", args.new.display()))?;

    let options = DiffOptions {
        scope,
        only,
        max_entries: args.max_entries,
    };

    let report = bitflip_core::diff(&old, &new, &options)?;

    let text = match args.format.as_str() {
        "text" => bitflip_core::render_diff_text(&report),
        "json" => serde_json::to_string_pretty(&report)
            .context("差分报告序列化失败（这属于实现缺陷，请报 issue）")?,
        other => anyhow::bail!("输出格式无法识别：{other:?}。可用值：text（人读）、json（机器读）"),
    };

    // 先落盘再报告：写失败时用户需要看到原因，而不是先看到"比对完成"。
    if let Some(path) = &args.out {
        write_output(path, &text, args.force)?;
    }

    report_to_stderr(&report, args.summary);

    if args.summary {
        return Ok(());
    }
    if args.out.is_some() {
        // 正文已经进文件了，不在终端里再刷一遍。
        println!("{}", report.summary_zh());
        return Ok(());
    }

    print!("{text}");
    Ok(())
}

/// 写输出文件。
///
/// 默认**拒绝覆盖**：比对报告常被拿去交给别人或存档，手滑一次就没地方恢复。
fn write_output(path: &Path, text: &str, force: bool) -> anyhow::Result<()> {
    if path.exists() && !force {
        anyhow::bail!(
            "输出文件已存在：{}。比对结果不默认覆盖；确实要覆盖就加 --force",
            path.display()
        );
    }
    if let Some(parent) = path.parent() {
        if !parent.as_os_str().is_empty() && !parent.exists() {
            anyhow::bail!(
                "输出目录不存在：{}。请先创建它（不自动建目录，避免把文件写到意料之外的地方）",
                parent.display()
            );
        }
    }

    let mut file =
        std::fs::File::create(path).with_context(|| format!("创建输出文件 {}", path.display()))?;
    file.write_all(text.as_bytes())
        .with_context(|| format!("写入输出文件 {}", path.display()))?;
    file.flush()
        .with_context(|| format!("刷新输出文件 {}", path.display()))?;
    Ok(())
}

/// 把账目（截断、降级、说明）打到 stderr。
fn report_to_stderr(report: &bitflip_core::DiffReport, quiet_summary: bool) {
    let mut stderr = std::io::stderr();
    let _ = writeln!(stderr, "{}", report.summary_zh());

    // 账目不闭合是**实现缺陷**的信号：条目数和对不上计数。这种话必须响亮 ——
    // 它意味着报告里某处的数字不可信，用户不该继续拿它做判断。
    if !report.accounting_balanced() {
        let _ = writeln!(
            stderr,
            "警告：账目不闭合（列出 {} 条，计数合计 {}）—— 报告的数字不可全信，请报 issue",
            report.entries.len(),
            report.totals.total()
        );
    }

    // 截断那一行**始终**打印，哪怕用户要的是简洁摘要：
    // 那是"数据不完整"的告警，不能因为要求简洁就吞掉。
    if report.truncated {
        let _ = writeln!(
            stderr,
            "已截断：还有 {} 条没有列出（用 --max-entries 放宽，或按 --only 过滤）",
            report.dropped
        );
    }

    if quiet_summary {
        return;
    }
    for note in &report.notes {
        let _ = writeln!(stderr, "说明：{note}");
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn output_refuses_to_overwrite_without_force() {
        let dir = std::env::temp_dir().join(format!("bitflip-diff-test-{}", std::process::id()));
        std::fs::create_dir_all(&dir).expect("建临时目录");
        let file = dir.join("report.txt");

        write_output(&file, "first\n", false).expect("首次写应当成功");
        let error = write_output(&file, "second\n", false).expect_err("已存在时应当拒绝");
        assert!(
            error.to_string().contains("--force"),
            "拒绝覆盖必须告诉用户怎么覆盖：{error}"
        );
        assert_eq!(std::fs::read_to_string(&file).expect("读回"), "first\n");

        write_output(&file, "second\n", true).expect("--force 应当覆盖");
        assert_eq!(std::fs::read_to_string(&file).expect("读回"), "second\n");

        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn output_reports_missing_parent_directory_instead_of_creating_it() {
        let dir = std::env::temp_dir().join(format!("bitflip-diff-missing-{}", std::process::id()));
        let file = dir.join("nested").join("report.txt");
        let error = write_output(&file, "x", false).expect_err("父目录不存在应当报错");
        assert!(
            error.to_string().contains("输出目录不存在"),
            "必须说清是目录问题：{error}"
        );
        assert!(!dir.exists(), "不得顺手把目录建出来");
    }
}
