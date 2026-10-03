//! 可写工程库：**用户标注是主数据，分析结果是可重建的派生物**。
//!
//! 这一条是全项目最重要的数据设计决定，直接针对参照实现的缺陷：它的缓存是只读的
//! FlatBuffers 快照，用"文件大小 + mtime"判断有效性，改一个符号名要把整个文件重写一遍。
//! 结果就是用户标注和分析产物纠缠在一起 —— 重新分析会丢标注，标注又会污染缓存。
//!
//! BitFlip 的切分：
//!
//! | 类别 | 内容 | 丢失后果 |
//! |------|------|----------|
//! | 主数据 | `names` / `comments` / `types` / `bookmarks` / `patches` / 手工函数边界 | **不可接受**，必须能完整迁移 |
//! | 派生物 | 函数、基本块、xref、指令索引、字符串、签名匹配 | 可接受，重新分析即可重建 |
//! | 元数据 | `schema_version`、目标内容哈希、工具版本、分析批次 | 用于迁移与失效判定 |
//!
//! 目标的身份用**内容哈希**（不是 size+mtime）：同名不同内容的文件必须被当作不同目标，
//! 否则会出现"拿到别人缓存"这种静默错误。
//!
//! 存储引擎选型见 `docs/DECISIONS.md` D2（M4 前定案）；本 crate 在 M0 只固定契约。

use serde::{Deserialize, Serialize};
use thiserror::Error;

/// 工程库格式版本。任何使旧文件被误读的改动都必须提升它并提供迁移。
pub const SCHEMA_VERSION: u32 = 1;

/// 工程库扩展名。
pub const PROJECT_EXTENSION: &str = "bfp";

/// 用户标注类别（主数据）。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum AnnotationKind {
    /// 符号名。
    Name,
    /// 注释（可区分行内/函数头，M3 细化）。
    Comment,
    /// 类型/结构体定义（M6）。
    Type,
    /// 书签。
    Bookmark,
    /// 字节补丁（M9）。
    Patch,
    /// 手工指定的函数边界（用户覆盖自动分析）。
    FunctionBoundary,
    /// 代码/数据覆写。
    CodeData,
}

impl AnnotationKind {
    /// 稳定的短名。
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Name => "name",
            Self::Comment => "comment",
            Self::Type => "type",
            Self::Bookmark => "bookmark",
            Self::Patch => "patch",
            Self::FunctionBoundary => "function-boundary",
            Self::CodeData => "code-data",
        }
    }

    /// 该类别是否属于主数据（必须迁移、不可因重新分析丢失）。
    #[must_use]
    pub const fn is_primary(self) -> bool {
        // 目前全部标注类别都是主数据；保留该方法是为了把"派生物要不要落库"这类
        // 讨论集中在类型上，而不是散落在存储实现里。
        true
    }

    /// 从短名解析（`as_str` 的逆）。
    ///
    /// 大小写不敏感、允许用 `_` 代替 `-`：这是从 HTTP 查询串/JSON 体来的
    /// 用户输入，纠结连字符会变成无谓的摩擦。
    ///
    /// 无法识别时返回 `None`，由调用方报出**可用的取值列表** ——
    /// 而不是静默回退到某个默认类别（那会把用户的名字当成注释存进去）。
    #[must_use]
    pub fn parse(text: &str) -> Option<Self> {
        let normalized = text.trim().to_ascii_lowercase().replace('_', "-");
        Some(match normalized.as_str() {
            "name" => Self::Name,
            "comment" => Self::Comment,
            "type" => Self::Type,
            "bookmark" => Self::Bookmark,
            "patch" => Self::Patch,
            "function-boundary" => Self::FunctionBoundary,
            "code-data" => Self::CodeData,
            _ => return None,
        })
    }
}

/// 工程库元数据。
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProjectMeta {
    /// 工程库格式版本。
    pub schema_version: u32,
    /// 写入工具版本。
    pub tool_version: String,
    /// 目标内容哈希（sha256，十六进制小写）。
    pub target_sha256: String,
    /// 目标文件大小。
    pub target_size: u64,
    /// 创建时间（Unix 秒）。
    pub created_at_unix: u64,
    /// 最近一次分析时间（Unix 秒）。
    pub analyzed_at_unix: Option<u64>,
}

impl ProjectMeta {
    /// 判定当前工具能否直接读这个工程库。
    #[must_use]
    pub fn compatibility(&self) -> Compatibility {
        if self.schema_version == SCHEMA_VERSION {
            Compatibility::Current
        } else if self.schema_version < SCHEMA_VERSION {
            Compatibility::NeedsMigration {
                from: self.schema_version,
            }
        } else {
            Compatibility::TooNew {
                found: self.schema_version,
            }
        }
    }
}

/// 工程库兼容性判定结果。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Compatibility {
    /// 版本一致，可直接读取。
    Current,
    /// 旧版本，可迁移（主数据必须能迁走）。
    NeedsMigration {
        /// 文件里的版本号。
        from: u32,
    },
    /// 文件由更新的工具写入：明确拒绝，不尝试解析。
    TooNew {
        /// 文件里的版本号。
        found: u32,
    },
}

/// 工程库错误。
#[derive(Debug, Error)]
pub enum ProjectError {
    /// 版本过新。
    #[error("工程库版本 {found} 高于当前支持的 {supported}，请升级 BitFlip（拒绝以旧读新）")]
    TooNew {
        /// 文件版本。
        found: u32,
        /// 支持的版本。
        supported: u32,
    },
    /// 目标内容哈希不匹配：工程库与当前目标不是同一个文件。
    #[error("工程库属于另一个目标（记录 {expected}，当前 {actual}）")]
    TargetMismatch {
        /// 工程库里记录的哈希。
        expected: String,
        /// 当前目标的哈希。
        actual: String,
    },
    /// 一般 IO 错误。
    #[error("工程库 IO 错误: {0}")]
    Io(String),
    /// SQLite 层错误（存储引擎细节，不向上层暴露 `rusqlite` 类型）。
    #[error("工程库存储错误: {0}")]
    Sqlite(String),
    /// 旧版本工程库：需要迁移，且迁移路径尚未实现。
    ///
    /// 与 `TooNew` 相对 —— 那个是"拒绝以旧读新"，这个是"旧库要升级"。
    /// 两者都**明确报错**，绝不静默按新格式解析。
    #[error("工程库版本 {from} 低于当前 {SCHEMA_VERSION}，需要迁移（迁移逻辑见 docs/PLAN.md M4）")]
    MigrationRequired {
        /// 文件里的版本。
        from: u32,
    },
    /// 工程库内容损坏或自相矛盾。
    #[error("工程库内容异常: {0}")]
    Corrupt(String),
}

pub mod derived;
pub mod recent;
pub mod store;

pub use derived::{
    clean_stale_tmp, derived_path, primary_path, read as read_derived, write_atomic, FunctionEntry,
    Snapshot, StringEntry, TableKind, XrefEntry, BDA_FORMAT_VERSION, BDA_MAGIC,
};
pub use recent::{RecentIndex, RecentStore, RecentTarget, INDEX_FORMAT_VERSION, MAX_RECENT};
pub use store::{addr_to_i64, i64_to_addr, Annotation, ProjectStore};

/// 计算目标文件的内容哈希（sha256，小写十六进制）。
///
/// 目标的身份用**内容哈希**而不是 size+mtime：同名不同内容的文件必须被当作
/// 不同目标，否则会出现"拿到别人缓存"这种静默错误。size+mtime 还会在
/// 复制/还原文件之后误判为未变。
///
/// 大文件按块读，避免为了算哈希把整个文件再读进内存一遍。
pub fn target_hash(path: &std::path::Path) -> Result<String, ProjectError> {
    use sha2::{Digest, Sha256};
    use std::io::Read;

    let mut file = std::fs::File::open(path).map_err(derived::io_err)?;
    let mut hasher = Sha256::new();
    let mut buf = vec![0u8; 1 << 20]; // 1 MiB
    loop {
        let n = file.read(&mut buf).map_err(derived::io_err)?;
        if n == 0 {
            break;
        }
        hasher.update(&buf[..n]);
    }
    Ok(hex_lower(&hasher.finalize()))
}

/// 对内存中的字节算哈希（测试与已知内容用）。
#[must_use]
pub fn target_hash_bytes(data: &[u8]) -> String {
    use sha2::{Digest, Sha256};
    hex_lower(&Sha256::digest(data))
}

/// 字节转小写十六进制。
///
/// 不用 `{:x}` 直接格式化摘要：`sha2` 0.11 的摘要类型不实现 `LowerHex`，
/// 而且手写能保证**定长小写**这一 wire 契约（与地址表示同一条约定）。
fn hex_lower(bytes: &[u8]) -> String {
    use std::fmt::Write as _;
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        // 写入 String 不会失败；忽略返回值不丢信息
        let _ = write!(s, "{b:02x}");
    }
    s
}

#[cfg(test)]
mod tests {
    use super::*;

    fn meta(version: u32) -> ProjectMeta {
        ProjectMeta {
            schema_version: version,
            tool_version: "0.0.1".to_string(),
            target_sha256: "00".repeat(32),
            target_size: 1024,
            created_at_unix: 0,
            analyzed_at_unix: None,
        }
    }

    #[test]
    fn compatibility_matrix() {
        assert_eq!(meta(SCHEMA_VERSION).compatibility(), Compatibility::Current);
        assert_eq!(
            meta(SCHEMA_VERSION - 1).compatibility(),
            Compatibility::NeedsMigration {
                from: SCHEMA_VERSION - 1
            }
        );
        assert_eq!(
            meta(SCHEMA_VERSION + 1).compatibility(),
            Compatibility::TooNew {
                found: SCHEMA_VERSION + 1
            }
        );
    }

    #[test]
    fn annotation_kinds_are_primary_data() {
        for kind in [
            AnnotationKind::Name,
            AnnotationKind::Comment,
            AnnotationKind::Type,
            AnnotationKind::Bookmark,
            AnnotationKind::Patch,
            AnnotationKind::FunctionBoundary,
            AnnotationKind::CodeData,
        ] {
            assert!(kind.is_primary(), "{kind:?} 必须属于主数据");
        }
        assert_eq!(AnnotationKind::Name.as_str(), "name");
    }

    #[test]
    fn meta_roundtrips_through_json() {
        let json = serde_json::to_string(&meta(SCHEMA_VERSION)).expect("序列化");
        let back: ProjectMeta = serde_json::from_str(&json).expect("反序列化");
        assert_eq!(back, meta(SCHEMA_VERSION));
    }
}
