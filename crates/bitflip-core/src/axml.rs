//! APK 清单（M11 · M3）：把 `AndroidManifest.xml` 解成**字段摘要 + 可读 XML**。
//!
//! 这一层只做三件事：**找到**那份二进制 XML、**解析**它、把结果组织成调用方
//! （命令行 / HTTP / 网页）能用的一份结构。解析细节在
//! [`bitflip_loader::format::axml`]；这里负责"从会话里取字节"和"把库的错误
//! 翻译成用户能看懂的输入错误"。
//!
//! # 不读 `resources.arsc` 的后果
//!
//! 引用类属性（`@7f0d0001` 这种）**原样保留**，并列进
//! [`ManifestFacts::unresolved_references`]，同时在 `notes` 里说明一句。
//! 这不是"没做完的部分"被藏起来了 —— 摘要里每个字段都要么是真值，要么是
//! `None`/空 + 原因（CLAUDE.md §7）。资源表是 M3 的第二片。

use std::sync::Arc;

use crate::{BitflipError, Session};

/// APK 里清单的固定成员名（`aapt2` 的产出约定）。
pub const MANIFEST_MEMBER: &str = "AndroidManifest.xml";

pub use bitflip_loader::format::axml::{AxmlError, ManifestFacts, MAX_AXML_BYTES};

/// 一次清单解析的结果。
#[derive(Debug, Clone)]
pub struct ManifestReport {
    /// 归档成员名；**单文件目标时是 `None`**（它不是"某个成员"，就是那个文件）。
    pub member: Option<String>,
    /// AXML 的字节数（不是还原后 XML 的长度 —— 那个是 `xml.len()`）。
    pub size: usize,
    /// 字段摘要。
    pub facts: ManifestFacts,
    /// 还原出的可读 XML。
    pub xml: String,
}

impl ManifestReport {
    /// 摘要与其"降级说明"合并后的一句结论，给命令行与网页共用。
    ///
    /// 放在 core 而不是各自实现：同一条信息会同时出现在两个界面上，两处各写
    /// 一份迟早会不一致（`read_member` 那里踩过同类的坑）。
    #[must_use]
    pub fn headline(&self) -> String {
        let package = self.facts.package.as_deref().unwrap_or("（无包名）");
        let version = match (&self.facts.version_name, &self.facts.version_code) {
            (Some(name), Some(code)) => format!("{name} ({code})"),
            (Some(name), None) => name.clone(),
            (None, Some(code)) => format!("versionCode {code}"),
            (None, None) => "版本未声明".to_string(),
        };
        format!(
            "{package} · {version} · {} activity / {} service / {} receiver / {} provider · {} 条权限",
            self.facts.activities.len(),
            self.facts.services.len(),
            self.facts.receivers.len(),
            self.facts.providers.len(),
            self.facts.permissions.len()
        )
    }
}

/// 读出并解析会话目标的清单。
///
/// `member` 为 `None` 时用 APK 的固定成员名 [`MANIFEST_MEMBER`]；单文件目标忽略它。
///
/// # Errors
///
/// 目标里没有这个成员、成员/文件的字节不是 AXML、或者解析器拒绝它
/// （都归到 [`BitflipError::InvalidInput`]，因为对用户来说都是"这份输入用不了"，
/// 而原始错误文本会带上库的具体分类）。
pub fn read_manifest(
    session: &Session,
    member: Option<&str>,
) -> Result<ManifestReport, BitflipError> {
    let (bytes, member_name) = input_bytes(session, member)?;
    if !bitflip_loader::format::axml::looks_like_axml(&bytes) {
        return Err(BitflipError::InvalidInput(format!(
            "{} 不是二进制 XML（AXML）：清单视图需要 APK 里的 AndroidManifest.xml，\
             或一个独立的 AXML 文件。纯文本 XML 在这里**解不了** —— 它不在 AXML 的格式里",
            member_name
                .clone()
                .unwrap_or_else(|| session.info().path.clone())
        )));
    }

    let document = bitflip_loader::format::axml::parse(&bytes).map_err(|error| {
        BitflipError::InvalidInput(format!(
            "把 {member_name} 当 AXML 解析失败：{error}",
            member_name = member_name
                .clone()
                .unwrap_or_else(|| session.info().path.clone())
        ))
    })?;

    let facts = document.manifest();
    let xml = document.xml();
    Ok(ManifestReport {
        member: member_name,
        size: bytes.len(),
        facts,
        xml,
    })
}

/// 取清单的原始字节：归档走成员取出，单文件从磁盘读（带**读之前**的上限判断）。
fn input_bytes(
    session: &Session,
    member: Option<&str>,
) -> Result<(Arc<[u8]>, Option<String>), BitflipError> {
    let wanted = member.unwrap_or(MANIFEST_MEMBER);
    if session.info().is_archive() {
        let (bytes, found) = session.member_bytes(wanted)?;
        return Ok((bytes, Some(found.name)));
    }

    let path = session.info().path.clone();
    // 与 DEX 那条读取路径同一手法：先看**文件大小**，超限就不读。
    // 上限也取同一个数（`MAX_AXML_BYTES`），理由同 loader 里那个常量的说明。
    let declared = std::fs::metadata(&path)
        .map_err(|error| BitflipError::InvalidInput(format!("读 {path} 的文件大小失败：{error}")))?
        .len();
    if declared > MAX_AXML_BYTES as u64 {
        return Err(BitflipError::InvalidInput(format!(
            "{path} 有 {declared} 字节，超过单份 AXML 的上限 {MAX_AXML_BYTES} 字节：没有读它"
        )));
    }
    let bytes: Arc<[u8]> = std::fs::read(&path)
        .map_err(|error| BitflipError::InvalidInput(format!("读 {path} 失败：{error}")))?
        .into();
    Ok((bytes, None))
}
