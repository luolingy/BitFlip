//! APK 资源表（M3 第二片 · A 方案）：把 `resources.arsc` 解成**结构快照**。
//!
//! 与 [`crate::axml`]（清单）同一条组织方式：解析细节在
//! [`bitflip_loader::format::arsc`]；这里负责"从会话里取字节"和"把库的错误
//! 翻译成用户能看懂的输入错误"。
//!
//! # A 方案的边界（用户已拍板）
//!
//! 只报**结构**：包 / 类型 / 配置 / 条目计数与层级，配置报原始判定字段。
//! **值不解**——`@7f0d0001` 对应的具体字符串/颜色/布局属于下一片
//! （届时 `ARSC::get_resource_value` 是现成的，但这层的 wire 形状先定住，
//! 后面加字段是加法，不是改形）。

use crate::{BitflipError, Session};

pub use bitflip_loader::format::arsc::{ArscError, ArscStructure, MAX_ARSC_BYTES};

/// 资源表结构快照 + 出处信息。
#[derive(Debug, Clone)]
pub struct ResourcesReport {
    /// 归档成员名；**单文件目标时是 `None`**（它就是那个文件）。
    pub member: Option<String>,
    /// 资源表的字节数。
    pub size: usize,
    /// 结构快照。
    pub structure: ArscStructure,
}

impl ResourcesReport {
    /// 一句结论，给命令行与网页共用（与 [`crate::axml::ManifestReport::headline`]
    /// 同一条理由：两个界面各写一份迟早分叉）。
    #[must_use]
    pub fn headline(&self) -> String {
        let packages = self.structure.packages.len();
        let configs: u64 = self
            .structure
            .packages
            .iter()
            .map(|package| package.config_count)
            .sum();
        let types: usize = self
            .structure
            .packages
            .iter()
            .map(|package| {
                // 不同 type_id 的个数（同一种类型会出现在多种配置里，去重）。
                let mut ids: Vec<u8> = package
                    .configs
                    .iter()
                    .flat_map(|config| config.types.iter().map(|t| t.type_id))
                    .collect();
                ids.sort_unstable();
                ids.dedup();
                ids.len()
            })
            .sum();
        format!(
            "{packages} 个资源包 · {} 条资源项（含 {} 个空位）· {types} 种资源类型 · {configs} 个配置切面",
            self.structure.entry_count, self.structure.no_entry_count
        )
    }
}

/// 读出资源表字节：APK 里取固定成员，单文件目标整个文件就是表。
///
/// 与 [`crate::axml`] 的读取路径同一手法：单文件先看**文件大小**，超限就不读
/// （上限与 loader 里那个常量同一个数，理由同它的说明）。
fn input_bytes(
    session: &Session,
    member: Option<&str>,
) -> Result<(std::sync::Arc<[u8]>, Option<String>), BitflipError> {
    let wanted = member.unwrap_or(crate::axml::RESOURCES_MEMBER);
    if session.info().is_archive() {
        let (bytes, found) = session.member_bytes(wanted)?;
        return Ok((bytes, Some(found.name)));
    }

    let path = session.info().path.clone();
    let declared = std::fs::metadata(&path)
        .map_err(|error| BitflipError::InvalidInput(format!("读 {path} 的文件大小失败：{error}")))?
        .len();
    if declared > MAX_ARSC_BYTES as u64 {
        return Err(BitflipError::InvalidInput(format!(
            "{path} 有 {declared} 字节，超过单份资源表的上限 {MAX_ARSC_BYTES} 字节：没有读它"
        )));
    }
    let bytes: std::sync::Arc<[u8]> = std::fs::read(&path)
        .map_err(|error| BitflipError::InvalidInput(format!("读 {path} 失败：{error}")))?
        .into();
    Ok((bytes, None))
}

/// 读出并解析会话目标的资源表。
///
/// `member` 为 `None` 时用 APK 的固定成员名 `resources.arsc`；单文件目标
/// （直接打开一个 `.arsc`）忽略它。
///
/// # Errors
///
/// 目标里没有这个成员、或字节不是能解析的资源表 —— 都归
/// [`BitflipError::InvalidInput`]（对用户来说都是"这份输入用不了"），原始
/// 错误文本带着库的具体分类。
pub fn read_resources(
    session: &Session,
    member: Option<&str>,
) -> Result<ResourcesReport, BitflipError> {
    let (bytes, member_name) = input_bytes(session, member)?;
    let size = bytes.len();
    let structure = ArscStructure::parse(&bytes)
        .map_err(|error| BitflipError::InvalidInput(error.to_string()))?;
    Ok(ResourcesReport {
        member: member_name,
        size,
        structure,
    })
}
