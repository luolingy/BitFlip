//! `resign`：给一个薄 Mach-O 副本重签（ad-hoc）。
//!
//! 安全语义与 `patch` 一致：**默认只读预览**，`--apply` 才写出 `xxx.resigned` 副本；
//! 原文件在磁盘上始终不动。当前只支持"原地容纳"路径（新签名 ≤ 旧 `datasize`）；
//! 需移动签名区 / 放不下 / 非 Mach-O / 无签名 → 明确报错，不写坏、不接证书、不产 CMS。

use std::path::{Path, PathBuf};

use anyhow::{bail, Context};
use bitflip_core::{resign_macho_file, ResignWriteError};

use crate::cli::ResignArgs;

/// 默认副本路径：在目标旁加 `.resigned`（不是原地改名，也不写 `temp/`）。
fn default_output(target: &Path) -> PathBuf {
    let mut name = target
        .file_name()
        .map(|n| n.to_os_string())
        .unwrap_or_default();
    name.push(".resigned");
    target.with_file_name(name)
}

pub fn run_resign(args: &ResignArgs) -> anyhow::Result<()> {
    let file = std::fs::read(&args.target)
        .with_context(|| format!("读取目标失败：{}", args.target.display()))?;

    // 先做一次重签（纯函数，零副作用）。失败就按类型给人话建议。
    match resign_macho_file(&file) {
        Ok(new_bytes) => {
            if args.json {
                print_json(&args.target, &new_bytes, args.apply)?;
            } else {
                println!("可重签（ad-hoc，原地容纳路径）");
                println!("  目标     {}", args.target.display());
                println!(
                    "  新文件   {} 字节（原 {} 字节）",
                    new_bytes.len(),
                    file.len()
                );
                println!("  说明     只校完整性、不校信任链；不接证书、不产 CMS（ad-hoc）");
            }

            if !args.apply {
                println!();
                println!("（只读预览：未写盘。确认无误后加 `--apply` 写出副本。）");
                return Ok(());
            }

            let out = args
                .output
                .clone()
                .unwrap_or_else(|| default_output(&args.target));
            // 安全：绝不原地覆写 —— 输出路径不得与目标相同。
            if out == args.target {
                bail!(
                    "输出路径与目标相同（{}）：resign 绝不原地覆写，请用 `--output` 指定别的路径",
                    out.display()
                );
            }
            std::fs::write(&out, &new_bytes)
                .with_context(|| format!("写出副本失败：{}", out.display()))?;
            println!();
            println!("已写出副本  {}", out.display());
        }
        Err(error) => {
            // 明确报错：哪一种"不能重签"，都带可操作建议，不写坏。
            bail!("{}", explain(&error, &args.target));
        }
    }
    Ok(())
}

/// 把写盘层错误翻成给人看的建议。
fn explain(error: &ResignWriteError, target: &Path) -> String {
    let base = format!("不能重签 {}：{error}", target.display());
    match error {
        ResignWriteError::DoesNotFit { .. } => format!(
            "{base}\n提示：本版只支持「签名区原地容纳」。签名变大（换算法/页数变多）需要移动\
             签名区或追加到文件末尾，尚未实现。"
        ),
        ResignWriteError::SignatureNotAdjacent { .. } => {
            format!("{base}\n提示：签名区不紧贴被签内容，需要移动签名区，本版不支持。")
        }
        ResignWriteError::NoCodeSignature => {
            format!("{base}\n提示：这个文件本来就没签名，本版不新建签名区。")
        }
        ResignWriteError::NotMachO => {
            format!("{base}\n提示：只支持薄 Mach-O（fat / 容器请先取出具体 slice）。")
        }
        _ => base,
    }
}

fn print_json(target: &Path, new_bytes: &[u8], apply: bool) -> anyhow::Result<()> {
    let payload = serde_json::json!({
        "target": target.display().to_string(),
        "resignable": true,
        "apply": apply,
        "original_bytes": std::fs::metadata(target).map(|m| m.len()).unwrap_or(0),
        "resigned_bytes": new_bytes.len(),
        "mode": "ad-hoc",
    });
    println!(
        "{}",
        serde_json::to_string_pretty(&payload).context("序列化失败")?
    );
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_output_appends_suffix() {
        let out = default_output(Path::new("/tmp/Foo.dylib"));
        assert_eq!(out, PathBuf::from("/tmp/Foo.dylib.resigned"));
    }
}
