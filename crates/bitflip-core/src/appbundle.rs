//! `.app` 包**批量重签**的可测核心逻辑（F 阶段）。
//!
//! # 这是什么
//!
//! 一个 iOS/macOS `.app` 目录里通常有**很多** Mach-O 二进制：主可执行、`Frameworks/*.framework/`、
//! `PlugIns/`、`Helpers`、`Watch/`、`*.dylib` 等。逐个用现有 [`resign_macho_file`]（ad-hoc、
//! 不接证书、不产 CMS）重签，并让 `_CodeSignature/CodeResources` 清单**数量/哈希自洽**。
//!
//! # 边界（§7，非常重要）
//!
//! - **绝不原地改**：`apply` 只写到一个**新目录**（`xxx.resigned.app`），原包一个字节都不动。
//! - **不可信**：真实封印要 Apple 私钥，官方 `codesign` 会用新哈希重写 `CodeResources`。
//!   本工具没有证书，只能"按新文件重算清单里对应条目的哈希"，让**数量/哈希自洽**——
//!   这**不是可信封印**，真机仍需 `codesign` 复核。输出里必须明确标注。
//! - **不碰证书、不产 CMS**：ad-hoc 签名即可，不做信任链。
//!
//! # 阶段划分
//!
//! 1. [`plan_resign_app`]：只读。枚举包里所有 Mach-O、试重签（算新字节但不落盘）、读旧
//!    `CodeResources`、算出"哪些条目因重签而哈希失配"。
//! 2. [`apply_resign_app`]：把整棵树复制到 `out_dir`，替换每个重签过的二进制，重写
//!    `CodeResources` 里受影响条目的哈希（仅 XML plist；二进制 plist 如实跳过）。
//!
//! CLI 的 `resign-app` 只是这两步的薄封装。

use std::path::{Path, PathBuf};

use crate::{
    extract_code_resource_hashes, resign_macho_file, rewrite_code_resource_hashes, CodeResourceHash,
};
use bitflip_loader::format::macho::code_resources::hash_blob_for;

/// 相对 `.app` 根的资源路径（统一用 `/` 分隔，跨平台稳定）。
pub type RelPath = String;

/// 一个 Mach-O 二进制的探测结果（是否 Mach-O、可否重签）。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MachoProbe {
    /// 相对 `.app` 根的路径（`/` 分隔）。
    pub rel: RelPath,
    /// 绝对路径（用于读文件）。
    pub path: PathBuf,
    /// 文件头识别的 Mach-O 形态（"macho64"/"macho32"/"fat32"/"fat64"）。
    pub kind: &'static str,
}

/// 批量重签的只读计划（frozen，不含落盘副作用）。
#[derive(Debug, Clone)]
pub struct ResignAppPlan {
    /// `.app` 根目录。
    pub root: PathBuf,
    /// 枚举到的所有 Mach-O 二进制（探测层，不保证能重签）。
    pub machos: Vec<MachoProbe>,
    /// 能成功重签的：`(rel, 新字节)`。这些才是 `apply` 时要替换的。
    pub resignable: Vec<(RelPath, Vec<u8>)>,
    /// 重签失败的：`(rel, 原因)`。如实列出，不静默丢弃。
    pub failed: Vec<(RelPath, String)>,
    /// 旧 `CodeResources` 的封印条目哈希（`None` = 没有/不可解析/二进制 plist）。
    pub coderes: CodeResourcesStatus,
    /// 因重签而哈希失配的条目路径（尽力报告；`coderes` 非 XML plist 时为空）。
    pub affected: Vec<RelPath>,
}

/// 旧 `CodeResources` 的读取状态。
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CodeResourcesStatus {
    /// 没有 `_CodeSignature/CodeResources`。
    Absent,
    /// 有文件，但不是可解析的 XML plist（二进制 plist 或形态未识别）。
    NotXml,
    /// 能解析：带条目数 + 每条目旧哈希。
    Parsed {
        /// 条目数（= `old.len()`）。
        entries: usize,
        /// 每条目的旧哈希。
        old: Vec<CodeResourceHash>,
    },
}

/// `apply` 的结果（实际写成什么样）。
#[derive(Debug, Clone)]
pub struct ApplyReport {
    /// 写出的新目录。
    pub out_dir: PathBuf,
    /// 替换（重签）了多少个二进制。
    pub resigned: usize,
    /// `CodeResources` 是否被重写（false = 没有/不可解析）。
    pub coderes_rewritten: bool,
    /// 重写时更新了多少条目的哈希。
    pub coderes_updated: usize,
}

/// `.app` 批量重签的错误。
#[derive(Debug, thiserror::Error)]
pub enum AppBundleError {
    /// 目标不是目录。
    #[error("目标不是目录：{0}（需要一个 .app 包）")]
    NotADirectory(String),
    /// 包里没有任何 Mach-O。
    #[error("{0} 里没找到任何 Mach-O 二进制")]
    NoMachO(String),
    /// 输出目录与目标相同（拒绝原地改）。
    #[error("输出目录与目标相同：resign-app 绝不原地覆写，请用 --output")]
    InPlace,
    /// 输出目录已存在。
    #[error("输出目录已存在：{0}（先删掉或换 --output）")]
    OutputExists(String),
    /// 文件系统读写失败。
    #[error("读/写 {path} 失败：{source}")]
    Io {
        /// 出错的路径。
        path: String,
        /// 底层错误。
        source: std::io::Error,
    },
}

fn io_err(path: &Path, source: std::io::Error) -> AppBundleError {
    AppBundleError::Io {
        path: path.display().to_string(),
        source,
    }
}

/// 识别一段文件头是不是 Mach-O（薄或 fat），返回形态名。
#[must_use]
pub fn macho_kind(head: &[u8]) -> Option<&'static str> {
    match head.get(0..4)? {
        [0xfe, 0xed, 0xfa, 0xcf] | [0xcf, 0xfa, 0xed, 0xfe] => Some("macho64"),
        [0xfe, 0xed, 0xfa, 0xce] | [0xce, 0xfa, 0xed, 0xfe] => Some("macho32"),
        [0xca, 0xfe, 0xba, 0xbe] => Some("fat32"),
        [0xca, 0xfe, 0xba, 0xbf] => Some("fat64"),
        _ => None,
    }
}

/// 递归枚举 `.app` 里所有 Mach-O 二进制（相对路径 + 绝对路径 + 形态）。按相对路径排序。
///
/// 只读文件头 4 字节判形态，不把整文件读进内存。目录不存在时返回 `Io`。
pub fn enumerate_machos(root: &Path) -> Result<Vec<MachoProbe>, AppBundleError> {
    if !root.is_dir() {
        return Err(AppBundleError::NotADirectory(root.display().to_string()));
    }
    let mut out = Vec::new();
    let mut stack = vec![root.to_path_buf()];
    while let Some(dir) = stack.pop() {
        let entries = std::fs::read_dir(&dir).map_err(|e| io_err(&dir, e))?;
        for entry in entries {
            let entry = entry.map_err(|e| io_err(&dir, e))?;
            let path = entry.path();
            let ft = entry.file_type().map_err(|e| io_err(&path, e))?;
            if ft.is_dir() {
                stack.push(path);
            } else if ft.is_file() {
                use std::io::Read;
                let mut head = [0u8; 4];
                if let Ok(mut f) = std::fs::File::open(&path) {
                    if f.read_exact(&mut head).is_ok() {
                        if let Some(kind) = macho_kind(&head) {
                            let rel = path
                                .strip_prefix(root)
                                .unwrap_or(&path)
                                .to_string_lossy()
                                .replace('\\', "/");
                            out.push(MachoProbe { rel, path, kind });
                        }
                    }
                }
            }
        }
    }
    out.sort_by(|a, b| a.rel.cmp(&b.rel));
    Ok(out)
}

const CODERES_REL: &str = "_CodeSignature/CodeResources";

/// 读旧 `CodeResources`：不存在 → [`CodeResourcesStatus::Absent`]；不能解 XML → `NotXml`；
/// 否则 → `Parsed`（带条目旧哈希）。
fn read_coderes(root: &Path) -> CodeResourcesStatus {
    let path = root.join(CODERES_REL);
    let Ok(bytes) = std::fs::read(&path) else {
        return CodeResourcesStatus::Absent;
    };
    match extract_code_resource_hashes(&bytes) {
        Some(old) => CodeResourcesStatus::Parsed {
            entries: old.len(),
            old,
        },
        None => CodeResourcesStatus::NotXml,
    }
}

/// 只读计划：枚举 + 试重签（算新字节不落盘）+ 读 `CodeResources` + 算受影响条目。
///
/// 不写任何文件。`--json`/预览都走它。
pub fn plan_resign_app(root: &Path) -> Result<ResignAppPlan, AppBundleError> {
    let machos = enumerate_machos(root)?;
    if machos.is_empty() {
        return Err(AppBundleError::NoMachO(root.display().to_string()));
    }

    let mut resignable: Vec<(RelPath, Vec<u8>)> = Vec::new();
    let mut failed: Vec<(RelPath, String)> = Vec::new();
    for probe in &machos {
        let bytes = std::fs::read(&probe.path).map_err(|e| io_err(&probe.path, e))?;
        match resign_macho_file(&bytes) {
            Ok(newb) => resignable.push((probe.rel.clone(), newb)),
            Err(e) => failed.push((probe.rel.clone(), format!("{e}"))),
        }
    }

    let coderes = read_coderes(root);

    // 哪些 CodeResources 条目因重签而哈希失配（新文件哈希 vs 清单旧哈希）。
    let mut affected: Vec<RelPath> = Vec::new();
    if let CodeResourcesStatus::Parsed { old, .. } = &coderes {
        for (rel, newb) in &resignable {
            if let Some(entry) = old.iter().find(|h| &h.path == rel) {
                let fresh = hash_blob_for(rel, newb);
                let sha1_changed = match (&entry.sha1, &fresh.sha1) {
                    (Some(a), Some(b)) => a != b,
                    _ => false,
                };
                let sha256_changed = match (&entry.sha256, &fresh.sha256) {
                    (Some(a), Some(b)) => a != b,
                    _ => false,
                };
                if sha1_changed || sha256_changed {
                    affected.push(rel.clone());
                }
            }
        }
    }

    Ok(ResignAppPlan {
        root: root.to_path_buf(),
        machos,
        resignable,
        failed,
        coderes,
        affected,
    })
}

/// 默认输出目录：`Foo.app` → 同级的 `Foo.app.resigned`。
#[must_use]
pub fn default_output(root: &Path) -> PathBuf {
    let mut name = root
        .file_name()
        .map(|n| n.to_os_string())
        .unwrap_or_default();
    name.push(".resigned");
    root.with_file_name(name)
}

/// 应用计划：把整棵树复制到 `out_dir`、替换重签过的二进制、重写 `CodeResources`。
///
/// **绝不原地改**：`out_dir == root` 或 `out_dir` 已存在都直接报错，不偷偷覆盖。
pub fn apply_resign_app(
    plan: &ResignAppPlan,
    out_dir: &Path,
) -> Result<ApplyReport, AppBundleError> {
    let root = &plan.root;
    if out_dir == root {
        return Err(AppBundleError::InPlace);
    }
    if out_dir.exists() {
        return Err(AppBundleError::OutputExists(out_dir.display().to_string()));
    }

    copy_tree(root, out_dir)?;

    // 替换重签过的二进制，并算好 CodeResources 的新哈希。
    let mut updates: Vec<CodeResourceHash> = Vec::new();
    for (rel, newb) in &plan.resignable {
        let dst = out_dir.join(rel);
        std::fs::write(&dst, newb).map_err(|e| io_err(&dst, e))?;
        updates.push(hash_blob_for(rel, newb));
    }

    // 重写 CodeResources（仅当旧文件能解析成 XML plist；二进制 plist 如实跳过）。
    let mut coderes_rewritten = false;
    let mut coderes_updated = 0usize;
    if let CodeResourcesStatus::Parsed { .. } = &plan.coderes {
        let coderes_path = root.join(CODERES_REL);
        if let Ok(old_bytes) = std::fs::read(&coderes_path) {
            if let Some(new_cr) = rewrite_code_resource_hashes(&old_bytes, &updates) {
                let dst = out_dir.join(CODERES_REL);
                if let Some(parent) = dst.parent() {
                    std::fs::create_dir_all(parent).map_err(|e| io_err(parent, e))?;
                }
                std::fs::write(&dst, &new_cr).map_err(|e| io_err(&dst, e))?;
                coderes_rewritten = true;
                coderes_updated = updates.len();
            }
        }
    }

    Ok(ApplyReport {
        out_dir: out_dir.to_path_buf(),
        resigned: plan.resignable.len(),
        coderes_rewritten,
        coderes_updated,
    })
}

fn copy_tree(src: &Path, dst: &Path) -> Result<(), AppBundleError> {
    std::fs::create_dir_all(dst).map_err(|e| io_err(dst, e))?;
    let entries = std::fs::read_dir(src).map_err(|e| io_err(src, e))?;
    for entry in entries {
        let entry = entry.map_err(|e| io_err(src, e))?;
        let from = entry.path();
        let to = dst.join(entry.file_name());
        let ft = entry.file_type().map_err(|e| io_err(&from, e))?;
        if ft.is_dir() {
            copy_tree(&from, &to)?;
        } else {
            std::fs::copy(&from, &to).map_err(|e| io_err(&from, e))?;
        }
    }
    Ok(())
}

/// 供 UI 用：计划里"哪些条目会失配"的数量（已算好）。
#[must_use]
pub fn affected_count(plan: &ResignAppPlan) -> usize {
    plan.affected.len()
}

/// 供 UI 用：一个紧凑的一行摘要（不含落盘）。
#[must_use]
pub fn plan_summary_line(plan: &ResignAppPlan) -> String {
    let cr = match &plan.coderes {
        CodeResourcesStatus::Absent => "无 CodeResources".to_string(),
        CodeResourcesStatus::NotXml => "CodeResources 非 XML plist（不重算）".to_string(),
        CodeResourcesStatus::Parsed { entries, .. } => {
            format!(
                "CodeResources {entries} 条，重签会使 {} 条失配",
                plan.affected.len()
            )
        }
    };
    format!(
        "Mach-O {} 个（可重签 {}，失败 {}）；{cr}",
        plan.machos.len(),
        plan.resignable.len(),
        plan.failed.len()
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn macho_kind_detects_all_magics() {
        assert_eq!(macho_kind(&[0xcf, 0xfa, 0xed, 0xfe]), Some("macho64"));
        assert_eq!(macho_kind(&[0xfe, 0xed, 0xfa, 0xcf]), Some("macho64"));
        assert_eq!(macho_kind(&[0xce, 0xfa, 0xed, 0xfe]), Some("macho32"));
        assert_eq!(macho_kind(&[0xca, 0xfe, 0xba, 0xbe]), Some("fat32"));
        assert_eq!(macho_kind(&[0xca, 0xfe, 0xba, 0xbf]), Some("fat64"));
        assert_eq!(macho_kind(b"\x7fELF"), None);
        assert_eq!(macho_kind(b"\x00"), None);
    }

    #[test]
    fn default_output_is_sibling_with_suffix() {
        assert_eq!(
            default_output(Path::new("/x/Payload/Foo.app")),
            PathBuf::from("/x/Payload/Foo.app.resigned")
        );
    }

    #[test]
    fn not_a_directory_is_reported() {
        let err = enumerate_machos(Path::new("/nonexistent/xyz.app")).unwrap_err();
        assert!(matches!(err, AppBundleError::NotADirectory(_)));
    }

    #[test]
    fn empty_dir_has_no_machos_and_plan_errors() {
        let dir = tempfile::tempdir().unwrap();
        assert!(enumerate_machos(dir.path()).unwrap().is_empty());
        let err = plan_resign_app(dir.path()).unwrap_err();
        assert!(matches!(err, AppBundleError::NoMachO(_)));
    }

    #[test]
    fn plan_does_not_write_and_apply_refuses_existing_or_inplace() {
        // 造一个含"非 Mach-O"文件的目录：枚举为空 → NoMachO（不落盘验证的一部分）。
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("readme.txt"), b"hi").unwrap();
        assert!(plan_resign_app(dir.path()).is_err());

        // in-place / existing 的两道闸在 apply 上，先用手工的 plan 造一个。
        let plan = ResignAppPlan {
            root: dir.path().to_path_buf(),
            machos: vec![],
            resignable: vec![],
            failed: vec![],
            coderes: CodeResourcesStatus::Absent,
            affected: vec![],
        };
        assert!(matches!(
            apply_resign_app(&plan, dir.path()),
            Err(AppBundleError::InPlace)
        ));
        let existing = dir.path().join("out.resigned");
        std::fs::create_dir_all(&existing).unwrap();
        assert!(matches!(
            apply_resign_app(&plan, &existing),
            Err(AppBundleError::OutputExists(_))
        ));
    }
}
