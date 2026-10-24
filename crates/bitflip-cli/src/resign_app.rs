//! `resign-app`：批量重签一个 `.app` 包里的所有 Mach-O 二进制，并让 `CodeResources` 清单自洽。
//!
//! 安全语义同 `resign`：**默认只读预览**，`--apply` 才写出 `xxx.resigned.app` 目录；原包不动。
//! 只走 ad-hoc（不接证书、不产 CMS）。`CodeResources` 只做"哈希自洽"（按新文件重算对应条目），
//! **不是可信封印**——真机仍需 `codesign` 复核，输出里会明确提示。

use std::path::{Path, PathBuf};

use anyhow::{bail, Context};
use bitflip_core::{
    extract_code_resource_hashes, resign_macho_file, rewrite_code_resource_hashes, CodeResourceHash,
};

use crate::cli::ResignAppArgs;

/// 判断一段文件头是不是 Mach-O（薄或 fat）。
fn macho_kind(bytes: &[u8]) -> Option<&'static str> {
    let magic = bytes.get(0..4)?;
    match magic {
        [0xfe, 0xed, 0xfa, 0xcf] | [0xcf, 0xfa, 0xed, 0xfe] => Some("macho64"),
        [0xfe, 0xed, 0xfa, 0xce] | [0xce, 0xfa, 0xed, 0xfe] => Some("macho32"),
        [0xca, 0xfe, 0xba, 0xbe] => Some("fat32"),
        [0xca, 0xfe, 0xba, 0xbf] => Some("fat64"),
        _ => None,
    }
}

/// 递归收集 `.app` 里所有 Mach-O 文件（相对路径 + 绝对路径）。
fn collect_machos(root: &Path) -> anyhow::Result<Vec<(String, PathBuf)>> {
    let mut out = Vec::new();
    let mut stack = vec![root.to_path_buf()];
    while let Some(dir) = stack.pop() {
        for entry in std::fs::read_dir(&dir).with_context(|| format!("读目录 {}", dir.display()))?
        {
            let entry = entry?;
            let path = entry.path();
            let ft = entry.file_type()?;
            if ft.is_dir() {
                stack.push(path);
            } else if ft.is_file() {
                // 读前 4 字节判 Mach-O（大文件也只读头）。
                use std::io::Read;
                let mut head = [0u8; 4];
                if let Ok(mut f) = std::fs::File::open(&path) {
                    if f.read_exact(&mut head).is_ok() && macho_kind(&head).is_some() {
                        let rel = path
                            .strip_prefix(root)
                            .unwrap_or(&path)
                            .to_string_lossy()
                            .replace('\\', "/");
                        out.push((rel, path));
                    }
                }
            }
        }
    }
    out.sort();
    Ok(out)
}

fn sha1_bytes(data: &[u8]) -> Vec<u8> {
    use sha1::{Digest, Sha1};
    Sha1::digest(data).to_vec()
}
fn sha256_bytes(data: &[u8]) -> Vec<u8> {
    use sha2::{Digest, Sha256};
    Sha256::digest(data).to_vec()
}

pub fn run_resign_app(args: &ResignAppArgs) -> anyhow::Result<()> {
    let root = &args.target;
    if !root.is_dir() {
        bail!("目标不是目录：{}（需要一个 .app 包）", root.display());
    }

    let machos = collect_machos(root)?;
    if machos.is_empty() {
        bail!("{} 里没找到任何 Mach-O 二进制", root.display());
    }

    // 读 CodeResources（可能不存在）。
    let coderes_rel = "_CodeSignature/CodeResources";
    let coderes_path = root.join(coderes_rel);
    let coderes_bytes = std::fs::read(&coderes_path).ok();
    let old_hashes = coderes_bytes
        .as_deref()
        .and_then(extract_code_resource_hashes);

    // 对每个二进制试重签，收集结果（不写盘）。
    let mut resignable: Vec<(String, PathBuf, Vec<u8>)> = Vec::new();
    let mut failed: Vec<(String, String)> = Vec::new();
    for (rel, path) in &machos {
        let bytes = std::fs::read(path).with_context(|| format!("读 {}", path.display()))?;
        match resign_macho_file(&bytes) {
            Ok(newb) => resignable.push((rel.clone(), path.clone(), newb)),
            Err(e) => failed.push((rel.clone(), format!("{e}"))),
        }
    }

    // 哪些 CodeResources 条目会因为重签而失配（尽力报告）。
    let mut affected: Vec<String> = Vec::new();
    if let Some(old) = &old_hashes {
        for (rel, _, newb) in &resignable {
            if let Some(entry) = old.iter().find(|h| &h.path == rel) {
                let new_sha1 = sha1_bytes(newb);
                let new_sha256 = sha256_bytes(newb);
                let sha1_changed = entry.sha1.as_ref().is_some_and(|s| s != &new_sha1);
                let sha256_changed = entry.sha256.as_ref().is_some_and(|s| s != &new_sha256);
                if sha1_changed || sha256_changed {
                    affected.push(rel.clone());
                }
            }
        }
    }

    println!("扫描 .app：{}", root.display());
    println!(
        "  Mach-O 二进制 {} 个（可重签 {}，失败 {}）",
        machos.len(),
        resignable.len(),
        failed.len()
    );
    if let Some(old) = &old_hashes {
        println!(
            "  CodeResources 封印条目 {} 条；重签会使其中 {} 条哈希失配",
            old.len(),
            affected.len()
        );
    } else if coderes_bytes.is_some() {
        println!("  CodeResources 存在但不是可解析的 XML plist（不解二进制 plist，不重算）");
    } else {
        println!("  没有 _CodeSignature/CodeResources");
    }
    for (rel, err) in &failed {
        println!("  ✗ 跳过 {rel}：{err}");
    }

    if args.json {
        let payload = serde_json::json!({
            "target": root.display().to_string(),
            "machos": machos.len(),
            "resignable": resignable.len(),
            "failed": failed.iter().map(|(r,e)| serde_json::json!({"path": r, "error": e})).collect::<Vec<_>>(),
            "coderes_entries": old_hashes.as_ref().map(|h| h.len()),
            "coderes_affected": affected,
            "apply": args.apply,
        });
        println!("{}", serde_json::to_string_pretty(&payload)?);
    }

    if !args.apply {
        println!();
        println!("（只读预览：未写盘。确认无误后加 `--apply` 写出 `xxx.resigned.app`。）");
        return Ok(());
    }

    // --apply：把整棵树复制到 xxx.resigned.app，替换 Mach-O，重写 CodeResources。
    let out_dir = args.output.clone().unwrap_or_else(|| default_output(root));
    if out_dir == *root {
        bail!("输出目录与目标相同：resign-app 绝不原地覆写，请用 `--output`");
    }
    if out_dir.exists() {
        bail!(
            "输出目录已存在：{}（先删掉或换 --output）",
            out_dir.display()
        );
    }

    // 复制整棵树。
    copy_tree(root, &out_dir)?;

    // 替换 Mach-O。
    let mut updates: Vec<CodeResourceHash> = Vec::new();
    for (rel, _orig, newb) in &resignable {
        let dst = out_dir.join(rel);
        std::fs::write(&dst, newb).with_context(|| format!("写 {}", dst.display()))?;
        updates.push(CodeResourceHash {
            path: rel.clone(),
            sha1: Some(sha1_bytes(newb)),
            sha256: Some(sha256_bytes(newb)),
        });
    }

    // 重写 CodeResources（仅在能解析、且有条目受影响时）。
    let mut rewritten = false;
    if let Some(coderes) = &coderes_bytes {
        if let Some(new_cr) = rewrite_code_resource_hashes(coderes, &updates) {
            let dst = out_dir.join(coderes_rel);
            if let Some(parent) = dst.parent() {
                std::fs::create_dir_all(parent).ok();
            }
            std::fs::write(&dst, &new_cr).with_context(|| format!("写 {}", dst.display()))?;
            rewritten = true;
        }
    }

    println!();
    println!("已写出副本  {}", out_dir.display());
    println!("  重签二进制 {} 个", resignable.len());
    if rewritten {
        println!(
            "  CodeResources 已按新哈希重算（尽力自洽；**不是可信封印**，真机仍需 codesign 复核）"
        );
    } else if coderes_bytes.is_some() {
        println!(
            "  CodeResources 无法重算（二进制 plist 或不可解析）：未改动，需真机 codesign 重建"
        );
    }
    println!("  提醒：ad-hoc 签名不带证书/CMS；本工具不产可信签名，仅让完整性/清单一类自洽");
    Ok(())
}

fn default_output(root: &Path) -> PathBuf {
    let mut name = root
        .file_name()
        .map(|n| n.to_os_string())
        .unwrap_or_default();
    name.push(".resigned");
    // foo.app -> foo.app.resigned
    root.with_file_name(name)
}

fn copy_tree(src: &Path, dst: &Path) -> anyhow::Result<()> {
    std::fs::create_dir_all(dst)?;
    for entry in std::fs::read_dir(src)? {
        let entry = entry?;
        let from = entry.path();
        let to = dst.join(entry.file_name());
        if entry.file_type()?.is_dir() {
            copy_tree(&from, &to)?;
        } else {
            std::fs::copy(&from, &to)?;
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn detects_macho_magics() {
        assert_eq!(macho_kind(&[0xcf, 0xfa, 0xed, 0xfe]), Some("macho64"));
        assert_eq!(macho_kind(&[0xce, 0xfa, 0xed, 0xfe]), Some("macho32"));
        assert_eq!(macho_kind(&[0xca, 0xfe, 0xba, 0xbe]), Some("fat32"));
        assert_eq!(macho_kind(&[0xca, 0xfe, 0xba, 0xbf]), Some("fat64"));
        assert_eq!(macho_kind(&[0x7f, b'E', b'L', b'F']), None);
    }

    #[test]
    fn default_output_is_sibling_with_suffix() {
        let out = default_output(Path::new("/x/Payload/Foo.app"));
        assert_eq!(out, PathBuf::from("/x/Payload/Foo.app.resigned"));
    }
}
