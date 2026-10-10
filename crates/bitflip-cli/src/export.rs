//! `export`：把分析结论写成可被别的工具消费的文件。
//!
//! ## 这一层只做三件事
//!
//! 1. 解析参数（格式名、地址范围、字节上限）；
//! 2. 调 `bitflip_core::export`；
//! 3. 把结果写到 `--out` 或标准输出，并把**降级与截断**打到 stderr。
//!
//! 格式与内容一概不在这一层实现。服务端 `GET /api/export` 走同一个核心函数 ——
//! 如果 CLI 自己拼一份文本，两份输出早晚会不一样，而用户没法判断哪个可信。
//!
//! ## 为什么截断信息走 stderr
//!
//! 正文可能被重定向进文件或管道（`bitflip-cli export ... > foo.asm`）。
//! 截断说明如果混进正文，就破坏了"导出的文件是纯文本/纯 JSON"这件事；
//! 如果只写进正文注释，重定向后用户根本看不到。所以：正文去 stdout，
//! 账目去 stderr，两者都不丢。

use std::io::Write as _;
use std::path::Path;

use anyhow::Context;
use bitflip_core::{ExportFormat, ExportOptions, Session};

use crate::cli::ExportArgs;

/// `export` 入口。
pub fn run_export(args: &ExportArgs) -> anyhow::Result<()> {
    crate::tracing_setup::init(args.verbose);

    let format = ExportFormat::parse(&args.format).ok_or_else(|| {
        let available: Vec<&str> = ExportFormat::all()
            .iter()
            .map(|format| format.as_str())
            .collect();
        anyhow::anyhow!(
            "导出格式无法识别：{:?}。可用值：{}",
            args.format,
            available.join("、")
        )
    })?;

    // 单个函数与地址范围互斥 —— 同时给就没有"哪个更具体"的合理答案，
    // 而随便挑一个会让用户拿到不是自己要的东西还看不出来。
    if args.function.is_some() && (args.from.is_some() || args.to.is_some()) {
        anyhow::bail!(
            "--function 与 --from/--to 不能同时使用：请只给其中一个\
             （要单个函数就给入口地址，要一段就给地址范围）"
        );
    }

    let range = match (args.from.as_deref(), args.to.as_deref()) {
        (None, None) => None,
        (from, to) => {
            let from = match from {
                Some(text) => parse_address(text, "--from")?,
                None => 0,
            };
            let to = match to {
                Some(text) => parse_address(text, "--to")?,
                None => u64::MAX,
            };
            if to < from {
                anyhow::bail!(
                    "地址范围为空：--from {from:#x} 大于 --to {to:#x}；\
                     范围是半开区间 [from, to)"
                );
            }
            Some((from, to))
        }
    };

    let function = args
        .function
        .as_deref()
        .map(|text| parse_address(text, "--function"))
        .transpose()?;

    // `--limit-bytes 0` 是"不限制"：0 作为上限没有意义（什么都导不出来），
    // 所以把它定义成显式的"不限"，而不是让用户猜。
    let byte_limit = match args.limit_bytes {
        None => Some(bitflip_core::DEFAULT_EXPORT_BYTE_LIMIT),
        Some(0) => None,
        Some(value) => Some(value),
    };

    let options = ExportOptions {
        range,
        function,
        include_bytes: !args.no_bytes,
        include_source: !args.no_source,
        max_functions: args.max_functions,
        byte_limit,
        keep_partial: true,
    };

    let session = Session::open(&args.target, args.raw.to_open_options()?)?;

    if session.info().is_archive() {
        // 归档没有函数、没有反汇编：直接说清并给替代做法，而不是导出
        // 一个空文件让用户以为"分析完成但什么都没有"（CLAUDE.md §7）。
        anyhow::bail!(
            "{} 是归档（{} 个成员）：容器本身没有可导出的内容。\
             先用 `members` 子命令看有哪些成员，然后导出具体的成员文件。",
            session.info().path,
            session.members().len()
        );
    }

    let (text, report) = bitflip_core::export(&session, format, &options)?;

    // 先落盘再报告：写失败时用户需要看到失败原因，而不是先看到"导出成功"。
    if let Some(path) = &args.out {
        write_output(path, &text, args.force)?;
    }

    report_to_stderr(&report, args.summary);

    if args.summary || args.out.is_some() {
        if args.out.is_none() {
            // `--summary` 且没给文件：正文不打印，但摘要已经在 stderr 了。
            return Ok(());
        }
        println!("{}", report.summary());
        return Ok(());
    }

    print!("{text}");
    Ok(())
}

/// 解析地址（十六进制，可带 `0x`）。
fn parse_address(text: &str, option: &str) -> anyhow::Result<u64> {
    bitflip_core::parse_address(text).ok_or_else(|| {
        anyhow::anyhow!("{option} 的地址无法解析：{text:?}（十六进制，可带 0x 前缀）")
    })
}

/// 写输出文件。
///
/// 默认**拒绝覆盖**：导出文件常被人拿去继续加工，手滑一次就没地方恢复。
/// `--force` 才覆盖，且覆盖前不落临时文件 —— 导出内容是内存里已经成型的
/// 完整字符串，一次 `write_all` 就够，不需要"先写临时再改名"的复杂度。
fn write_output(path: &Path, text: &str, force: bool) -> anyhow::Result<()> {
    if path.exists() && !force {
        anyhow::bail!(
            "输出文件已存在：{}。导出内容可能是别人的输入，不默认覆盖；确实要覆盖就加 --force",
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
fn report_to_stderr(report: &bitflip_core::ExportReport, quiet_summary: bool) {
    let mut stderr = std::io::stderr();
    let _ = writeln!(stderr, "{}", report.summary());

    if let Some(truncation) = &report.truncated {
        let _ = writeln!(
            stderr,
            "已截断：{} 未写出（已写出 {}）。{}",
            truncation.dropped, truncation.written, truncation.hint
        );
    }

    // `--summary` 时摘要已经足够，不再刷一屏说明；但截断那一行**始终**打印 ——
    // 那是"数据不完整"的告警，不能因为要求简洁就吞掉。
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
    fn address_parsing_accepts_hex_with_and_without_prefix() {
        assert_eq!(
            parse_address("140001000", "--from").expect("裸 hex"),
            0x1_4000_1000
        );
        assert_eq!(
            parse_address("0x401000", "--from").expect("带前缀"),
            0x40_1000
        );
        assert!(parse_address("zzz", "--from").is_err(), "非法地址必须报错");
        let message = parse_address("zzz", "--from")
            .expect_err("报错")
            .to_string();
        assert!(
            message.contains("--from"),
            "报错要点明是哪个选项：{message}"
        );
    }

    #[test]
    fn output_refuses_to_overwrite_without_force() {
        let dir = std::env::temp_dir().join(format!("bitflip-export-test-{}", std::process::id()));
        std::fs::create_dir_all(&dir).expect("建临时目录");
        let file = dir.join("out.asm");

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
        let dir =
            std::env::temp_dir().join(format!("bitflip-export-missing-{}", std::process::id()));
        let file = dir.join("nested").join("out.asm");
        let error = write_output(&file, "x", false).expect_err("父目录不存在应当报错");
        assert!(
            error.to_string().contains("输出目录不存在"),
            "必须说清是目录问题：{error}"
        );
        assert!(!dir.exists(), "不得顺手把目录建出来");
    }
}
