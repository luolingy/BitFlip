//! `signature` 子命令：生成与查看签名文件。
//!
//! 签名文件是从**用户自己机器上的静态库**生成出来的派生物：它记录的是
//! "这些函数的字节长什么样"，名字来自库的符号表。因此这里不做任何联网、
//! 不带任何预置数据库 —— 生成结果完全由输入的库决定，可复现、可审计。
//!
//! 两个命令都把"拿不到"说清楚：解析失败的对象、被丢弃的函数各有计数，
//! 产不出任何签名时直接报错而不是写一个空文件。

use anyhow::{bail, Context};
use bitflip_signature::{generate, ArchiveInput, Generated, SignatureSet};
use serde::Serialize;

use crate::cli::{SignatureArgs, SignatureBuildArgs, SignatureCommand, SignatureInfoArgs};

/// 签名文件报告与 CLI 输出的 wire 版本。
const SIGNATURE_REPORT_VERSION: u32 = 1;

/// `signature` 的入口。
pub fn run_signature(args: &SignatureArgs) -> anyhow::Result<()> {
    match &args.command {
        SignatureCommand::Build(build) => run_build(build),
        SignatureCommand::Info(info) => run_info(info),
    }
}

/// `signature build`。
fn run_build(args: &SignatureBuildArgs) -> anyhow::Result<()> {
    // 先读全部输入：读失败要一次性说清是哪一个，而不是"零条签名"这种结论 ——
    // 后者会让用户以为库本身有问题。
    let mut blobs = Vec::with_capacity(args.inputs.len());
    for path in &args.inputs {
        if !path.exists() {
            bail!("输入不存在：{}", path.display());
        }
        let bytes = std::fs::read(path).with_context(|| format!("读取输入 {}", path.display()))?;
        blobs.push((path.display().to_string(), bytes));
    }
    let inputs: Vec<ArchiveInput<'_>> = blobs
        .iter()
        .map(|(name, bytes)| ArchiveInput {
            name: name.clone(),
            bytes,
        })
        .collect();
    let result = generate(&inputs);

    if result.set.is_empty() {
        bail!(
            "所有输入都没有产出签名：{}（可重定位对象才有符号位置可依据；\
             已链接映像与原始字节都不适合做签名来源）",
            result.set.stats.summary_zh()
        );
    }

    if args.out.exists() && !args.force {
        bail!("输出已存在：{}（要覆盖就加 --force）", args.out.display());
    }
    let existed = args.out.exists();
    let json = result
        .set
        .to_json(true)
        .map_err(|error| anyhow::anyhow!("序列化签名文件失败：{error}"))?;
    std::fs::write(&args.out, json)
        .with_context(|| format!("写出签名文件 {}", args.out.display()))?;
    let size = std::fs::metadata(&args.out)
        .map(|meta| meta.len())
        .unwrap_or(0);

    if args.json {
        let report = BuildReport::from(&result, &args.out.display().to_string(), size, existed);
        println!(
            "{}",
            serde_json::to_string_pretty(&report).context("序列化报告")?
        );
        return Ok(());
    }

    println!(
        "签名文件  {}{}",
        args.out.display(),
        if existed { "（覆盖）" } else { "" }
    );
    println!("字节      {size} 字节");
    println!(
        "形态      {}",
        result
            .set
            .arches()
            .iter()
            .map(|arch| arch.to_string())
            .collect::<Vec<_>>()
            .join("、")
    );
    println!("签名      {} 条", result.set.len());
    for source in &result.sources {
        println!(
            "来源      {}（{}）：对象 {} 个 → 签名 {} 条",
            source.name, source.container, source.objects, source.signatures
        );
    }
    println!("账目      {}", result.set.stats.summary_zh());
    Ok(())
}

/// `signature info`。
fn run_info(args: &SignatureInfoArgs) -> anyhow::Result<()> {
    let text = std::fs::read_to_string(&args.file)
        .with_context(|| format!("读取签名文件 {}", args.file.display()))?;
    let set = SignatureSet::from_json(&text).map_err(|error| anyhow::anyhow!("{error}"))?;

    if args.json {
        let report = InfoReport {
            format_version: SIGNATURE_REPORT_VERSION,
            tool: set.tool.clone(),
            signature_format_version: set.format_version,
            signatures: set.len(),
            arches: set.arches().iter().map(|arch| arch.to_string()).collect(),
            stats: set.stats.clone(),
            names: sample_names(&set, args.count),
        };
        println!(
            "{}",
            serde_json::to_string_pretty(&report).context("序列化报告")?
        );
        return Ok(());
    }

    println!("文件      {}", args.file.display());
    println!("生成者    {}", set.tool);
    println!("格式版本  {}", set.format_version);
    println!(
        "形态      {}",
        set.arches()
            .iter()
            .map(|arch| arch.to_string())
            .collect::<Vec<_>>()
            .join("、")
    );
    println!("签名      {} 条", set.len());
    println!("账目      {}", set.stats.summary_zh());
    let names = sample_names(&set, args.count);
    if !names.is_empty() {
        println!("名字示例  {}", names.join("、"));
        if set.len() > names.len() {
            println!(
                "          …（共 {} 条，用 --count 调整示例数量）",
                set.len()
            );
        }
    }
    Ok(())
}

/// 取前 `count` 个名字（已排序，稳定可复现）。
fn sample_names(set: &SignatureSet, count: usize) -> Vec<String> {
    set.signatures
        .iter()
        .take(count)
        .map(|signature| signature.name.clone())
        .collect()
}

/// `signature build --json` 的报告。
#[derive(Debug, Serialize)]
struct BuildReport {
    format_version: u32,
    out: String,
    bytes: u64,
    overwritten: bool,
    signatures: usize,
    arches: Vec<String>,
    stats: bitflip_signature::GenerationStats,
    sources: Vec<SourceWire>,
}

/// 单个输入的产出。
#[derive(Debug, Serialize)]
struct SourceWire {
    name: String,
    container: &'static str,
    objects: u64,
    signatures: u64,
}

impl BuildReport {
    fn from(result: &Generated, out: &str, bytes: u64, overwritten: bool) -> Self {
        Self {
            format_version: SIGNATURE_REPORT_VERSION,
            out: out.to_string(),
            bytes,
            overwritten,
            signatures: result.set.len(),
            arches: result
                .set
                .arches()
                .iter()
                .map(|arch| arch.to_string())
                .collect(),
            stats: result.set.stats.clone(),
            sources: result
                .sources
                .iter()
                .map(|source| SourceWire {
                    name: source.name.clone(),
                    container: source.container,
                    objects: source.objects,
                    signatures: source.signatures,
                })
                .collect(),
        }
    }
}

/// `signature info --json` 的报告。
#[derive(Debug, Serialize)]
struct InfoReport {
    format_version: u32,
    tool: String,
    signature_format_version: u32,
    signatures: usize,
    arches: Vec<String>,
    stats: bitflip_signature::GenerationStats,
    names: Vec<String>,
}
