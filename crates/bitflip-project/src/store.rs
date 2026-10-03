//! `.bfp` 主数据库（SQLite）：用户标注的权威存储。
//!
//! 设计依据 `docs/D2-STORAGE-ANALYSIS.md` §6.2（表结构）与 ADR-0012。
//!
//! **硬约束**：本模块的公开 API 不得暴露 `rusqlite` 类型。
//! `bitflip-core` 是对外的稳定契约，嵌入方不该被迫依赖 SQLite；
//! 存储引擎是**实现细节**，换掉它不应波及上层（D2 §5 第 3 条）。
//!
//! 只装**主数据**（标注）。派生物（函数/xref/字符串）走独立 `.bda` 文件，
//! 可以整体删除重建 —— 这条分界是本项目最重要的数据设计决定。

use std::path::{Path, PathBuf};

use rusqlite::{params, Connection, OptionalExtension};

use crate::{AnnotationKind, ProjectError, ProjectMeta, SCHEMA_VERSION};

/// 地址 → SQLite INTEGER 的**保序**映射。
///
/// SQLite 的 INTEGER 是有符号 64 位，而我们的地址是 `u64`（CLAUDE.md §4）。
/// 直接 `as i64` 会让 `≥ 2^63` 的地址变成负数，破坏范围查询与排序 ——
/// 用户态地址几乎到不了那里，但"几乎"不是正确性依据。
///
/// 翻转符号位得到保序双射：小地址仍映射到小整数，全序不变。
#[must_use]
pub const fn addr_to_i64(addr: u64) -> i64 {
    (addr ^ 0x8000_0000_0000_0000) as i64
}

/// [`addr_to_i64`] 的逆映射。
#[must_use]
pub const fn i64_to_addr(value: i64) -> u64 {
    (value as u64) ^ 0x8000_0000_0000_0000
}

/// 一条标注（主数据行）。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Annotation {
    /// 地址。
    pub address: u64,
    /// 类别。
    pub kind: AnnotationKind,
    /// 文本内容（名字/注释/类型文本）；补丁行为 `None`。
    pub text: Option<String>,
    /// 补丁的原始字节（十六进制字符串）；非补丁为 `None`。
    pub patch_hex: Option<String>,
}

impl serde::Serialize for Annotation {
    /// 手写序列化而不是 `derive`，为的是守住两条 wire 契约：
    ///
    /// 1. **地址是定长小写 16 位十六进制字符串**（CLAUDE.md §4）。
    ///    直接 derive 会把内部的 `u64` 序列化成 JSON 数字，前端拿到的
    ///    就是 `4198400` 而不是 `"0000000000401000"` —— 一旦有第二个
    ///    端点这么干，"只有一种地址表示"的约定就破了。
    /// 2. 类别用稳定短名（`name` / `comment` / …），不用 Rust 的
    ///    `VariantName` —— 后者随重构改名就会破坏 wire 兼容。
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        use serde::ser::SerializeStruct;
        let mut s = serializer.serialize_struct("Annotation", 4)?;
        s.serialize_field("address", &format!("{:016x}", self.address))?;
        s.serialize_field("kind", self.kind.as_str())?;
        s.serialize_field("text", &self.text)?;
        s.serialize_field("patch_hex", &self.patch_hex)?;
        s.end()
    }
}

impl Annotation {
    /// 构造一条纯文本标注（名字、注释、书签…）。
    #[must_use]
    pub fn text(address: u64, kind: AnnotationKind, text: impl Into<String>) -> Self {
        Self {
            address,
            kind,
            text: Some(text.into()),
            patch_hex: None,
        }
    }

    /// 构造一条字节补丁标注。
    #[must_use]
    pub fn patch(address: u64, bytes: &[u8]) -> Self {
        let mut hex = String::with_capacity(bytes.len() * 2);
        for b in bytes {
            hex.push_str(&format!("{b:02x}"));
        }
        Self {
            address,
            kind: AnnotationKind::Patch,
            text: None,
            patch_hex: Some(hex),
        }
    }

    /// 补丁字节（解码失败或非补丁时为 `None`）。
    #[must_use]
    pub fn patch_bytes(&self) -> Option<Vec<u8>> {
        let hex = self.patch_hex.as_deref()?;
        if hex.len() % 2 != 0 {
            return None;
        }
        let mut out = Vec::with_capacity(hex.len() / 2);
        for i in (0..hex.len()).step_by(2) {
            out.push(u8::from_str_radix(&hex[i..i + 2], 16).ok()?);
        }
        Some(out)
    }
}

/// `.bfp` 主数据库句柄。
pub struct ProjectStore {
    conn: Connection,
    path: PathBuf,
}

impl std::fmt::Debug for ProjectStore {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // 连接不可 Debug；只暴露路径，够用于诊断
        f.debug_struct("ProjectStore")
            .field("path", &self.path)
            .finish_non_exhaustive()
    }
}

impl ProjectStore {
    /// 打开工程库：建表、校验版本与目标哈希。
    ///
    /// 校验顺序是**刻意的**：先版本（`TooNew` 直接拒绝，绝不尝试解析新格式），
    /// 再目标哈希（不匹配就大声失败，而不是把别人的注释套到当前目标上）。
    pub fn open(path: &Path, target_sha256: &str) -> Result<Self, ProjectError> {
        if let Some(parent) = path.parent() {
            let _ = std::fs::create_dir_all(parent);
        }
        let conn = Connection::open(path).map_err(sqlite_err)?;
        // WAL：崩溃安全 + 并发读；NORMAL 在 WAL 下是性能/安全的平衡点
        conn.pragma_update(None, "journal_mode", "WAL")
            .map_err(sqlite_err)?;
        conn.pragma_update(None, "synchronous", "NORMAL")
            .map_err(sqlite_err)?;
        conn.pragma_update(None, "foreign_keys", "ON")
            .map_err(sqlite_err)?;
        Self::init_schema(&conn)?;

        let recorded_version: Option<String> = conn
            .query_row(
                "SELECT value FROM meta WHERE key = 'schema_version'",
                [],
                |row| row.get(0),
            )
            .optional()
            .map_err(sqlite_err)?;

        if let Some(raw) = recorded_version {
            let found: u32 = raw
                .parse()
                .map_err(|_| ProjectError::Corrupt("schema_version 不是数字".into()))?;
            if found > SCHEMA_VERSION {
                return Err(ProjectError::TooNew {
                    found,
                    supported: SCHEMA_VERSION,
                });
            }
            if found < SCHEMA_VERSION {
                return Err(ProjectError::MigrationRequired { from: found });
            }
            let recorded_hash: String = conn
                .query_row(
                    "SELECT value FROM meta WHERE key = 'target_sha256'",
                    [],
                    |row| row.get(0),
                )
                .map_err(sqlite_err)?;
            if recorded_hash != target_sha256 {
                return Err(ProjectError::TargetMismatch {
                    expected: recorded_hash,
                    actual: target_sha256.to_string(),
                });
            }
        }

        Ok(Self {
            conn,
            path: path.to_path_buf(),
        })
    }

    /// 创建（或打开已存在的）工程库并写入元数据。
    pub fn create(
        path: &Path,
        target_sha256: &str,
        target_size: u64,
        tool_version: &str,
        now_unix: u64,
    ) -> Result<Self, ProjectError> {
        let store = Self::open(path, target_sha256)?;
        let exists: Option<String> = store
            .conn
            .query_row(
                "SELECT value FROM meta WHERE key = 'schema_version'",
                [],
                |row| row.get(0),
            )
            .optional()
            .map_err(sqlite_err)?;
        if exists.is_none() {
            store
                .conn
                .execute(
                    "INSERT INTO meta (key, value) VALUES
                    ('schema_version',    ?1),
                    ('tool_version',      ?2),
                    ('target_sha256',     ?3),
                    ('target_size',       ?4),
                    ('created_at_unix',   ?5),
                    ('analyzed_at_unix',  '')",
                    params![
                        SCHEMA_VERSION.to_string(),
                        tool_version,
                        target_sha256,
                        target_size.to_string(),
                        now_unix.to_string()
                    ],
                )
                .map_err(sqlite_err)?;
        }
        Ok(store)
    }

    fn init_schema(conn: &Connection) -> Result<(), ProjectError> {
        conn.execute_batch(
            "CREATE TABLE IF NOT EXISTS meta (
                key   TEXT PRIMARY KEY,
                value TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS annotations (
                id          INTEGER PRIMARY KEY,
                address     INTEGER NOT NULL,
                kind        TEXT    NOT NULL,
                text        TEXT,
                patch_hex   TEXT,
                created_at  INTEGER NOT NULL,
                updated_at  INTEGER NOT NULL,
                UNIQUE(address, kind)
            );
            CREATE INDEX IF NOT EXISTS idx_annotations_address
                ON annotations(address);",
        )
        .map_err(sqlite_err)
    }

    /// 文件路径。
    #[must_use]
    pub fn path(&self) -> &Path {
        &self.path
    }

    /// 读取元数据。
    pub fn meta(&self) -> Result<ProjectMeta, ProjectError> {
        let mut stmt = self
            .conn
            .prepare("SELECT key, value FROM meta")
            .map_err(sqlite_err)?;
        let mut map = std::collections::HashMap::new();
        let rows = stmt
            .query_map([], |row| {
                Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?))
            })
            .map_err(sqlite_err)?;
        for row in rows {
            let (k, v) = row.map_err(sqlite_err)?;
            map.insert(k, v);
        }
        let get = |k: &str| map.get(k).cloned().unwrap_or_default();
        Ok(ProjectMeta {
            schema_version: get("schema_version").parse().unwrap_or(0),
            tool_version: get("tool_version"),
            target_sha256: get("target_sha256"),
            target_size: get("target_size").parse().unwrap_or(0),
            created_at_unix: get("created_at_unix").parse().unwrap_or(0),
            analyzed_at_unix: get("analyzed_at_unix").parse().ok(),
        })
    }

    /// 记录一次分析完成时间（派生物写入成功后调用）。
    pub fn set_analyzed_at(&self, now_unix: u64) -> Result<(), ProjectError> {
        self.conn
            .execute(
                "INSERT INTO meta (key, value) VALUES ('analyzed_at_unix', ?1)
                 ON CONFLICT(key) DO UPDATE SET value = ?1",
                params![now_unix.to_string()],
            )
            .map_err(sqlite_err)?;
        Ok(())
    }

    /// 写入（或覆盖）一条标注。
    ///
    /// 同地址同类只有一条：重复写是**更新**（`UNIQUE(address, kind)` +
    /// upsert）。`updated_at` 由本层维护 —— 时钟是基础设施，不是业务参数。
    pub fn put(&self, annotation: &Annotation, now_unix: u64) -> Result<(), ProjectError> {
        if annotation.text.is_none() && annotation.patch_hex.is_none() {
            return Err(ProjectError::Corrupt("标注既没有文本也没有补丁内容".into()));
        }
        self.conn
            .execute(
                "INSERT INTO annotations
                    (address, kind, text, patch_hex, created_at, updated_at)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?5)
                 ON CONFLICT(address, kind) DO UPDATE SET
                    text       = ?3,
                    patch_hex  = ?4,
                    updated_at = ?5",
                params![
                    addr_to_i64(annotation.address),
                    annotation.kind.as_str(),
                    annotation.text,
                    annotation.patch_hex,
                    now_unix as i64,
                ],
            )
            .map_err(sqlite_err)?;
        Ok(())
    }

    /// 删除一条标注。不存在时静默成功（幂等）。
    pub fn delete(&self, address: u64, kind: AnnotationKind) -> Result<(), ProjectError> {
        self.conn
            .execute(
                "DELETE FROM annotations WHERE address = ?1 AND kind = ?2",
                params![addr_to_i64(address), kind.as_str()],
            )
            .map_err(sqlite_err)?;
        Ok(())
    }

    /// 读一条标注。
    #[must_use]
    pub fn get(&self, address: u64, kind: AnnotationKind) -> Option<Annotation> {
        self.conn
            .query_row(
                "SELECT address, kind, text, patch_hex FROM annotations
                 WHERE address = ?1 AND kind = ?2",
                params![addr_to_i64(address), kind.as_str()],
                row_to_annotation,
            )
            .optional()
            .ok()?
    }

    /// 某地址的全部标注（按类别排序）。
    #[must_use]
    pub fn at(&self, address: u64) -> Vec<Annotation> {
        let mut stmt = match self.conn.prepare(
            "SELECT address, kind, text, patch_hex FROM annotations
             WHERE address = ?1 ORDER BY kind",
        ) {
            Ok(s) => s,
            Err(_) => return Vec::new(),
        };
        stmt.query_map(params![addr_to_i64(address)], row_to_annotation)
            .map(|rows| rows.filter_map(Result::ok).collect())
            .unwrap_or_default()
    }

    /// 按地址范围查（`[from, to)`，左闭右开）。
    ///
    /// 这是最高频的查询：反汇编窗口一屏要批量取标注。
    #[must_use]
    pub fn range(&self, from: u64, to: u64) -> Vec<Annotation> {
        let mut stmt = match self.conn.prepare(
            "SELECT address, kind, text, patch_hex FROM annotations
             WHERE address >= ?1 AND address < ?2 ORDER BY address, kind",
        ) {
            Ok(s) => s,
            Err(_) => return Vec::new(),
        };
        stmt.query_map(
            params![addr_to_i64(from), addr_to_i64(to)],
            row_to_annotation,
        )
        .map(|rows| rows.filter_map(Result::ok).collect())
        .unwrap_or_default()
    }

    /// 标注总数。
    #[must_use]
    pub fn len(&self) -> usize {
        self.conn
            .query_row("SELECT COUNT(*) FROM annotations", [], |row| {
                row.get::<_, i64>(0)
            })
            .map(|n| n as usize)
            .unwrap_or(0)
    }

    /// 是否没有任何标注。
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

fn row_to_annotation(row: &rusqlite::Row<'_>) -> rusqlite::Result<Annotation> {
    Ok(Annotation {
        address: i64_to_addr(row.get::<_, i64>(0)?),
        kind: kind_from_str(&row.get::<_, String>(1)?),
        text: row.get(2)?,
        patch_hex: row.get(3)?,
    })
}

/// 从库里存的短名还原 [`AnnotationKind`]。
///
/// 未知值（手工改库、或将来降级打开更高的库）退回 `Comment`：
/// 丢一条标注的类别，好过整个工程库打不开。
fn kind_from_str(s: &str) -> AnnotationKind {
    match s {
        "name" => AnnotationKind::Name,
        "comment" => AnnotationKind::Comment,
        "type" => AnnotationKind::Type,
        "bookmark" => AnnotationKind::Bookmark,
        "patch" => AnnotationKind::Patch,
        "function-boundary" => AnnotationKind::FunctionBoundary,
        "code-data" => AnnotationKind::CodeData,
        _ => AnnotationKind::Comment,
    }
}

fn sqlite_err(error: rusqlite::Error) -> ProjectError {
    ProjectError::Sqlite(error.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    struct TempDb {
        path: PathBuf,
    }

    impl TempDb {
        fn new(tag: &str) -> Self {
            let mut path = std::env::temp_dir();
            path.push(format!(
                "bf-store-{}-{}-{tag}.bfp",
                std::process::id(),
                std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .map(|d| d.subsec_nanos())
                    .unwrap_or(0)
            ));
            // 上一轮可能残留（WAL 模式会另建 -wal / -shm）
            for suffix in ["", "-wal", "-shm"] {
                let _ = std::fs::remove_file(format!("{}{suffix}", path.display()));
            }
            Self { path }
        }
    }

    impl Drop for TempDb {
        fn drop(&mut self) {
            for suffix in ["", "-wal", "-shm"] {
                let _ = std::fs::remove_file(format!("{}{suffix}", self.path.display()));
            }
        }
    }

    fn open(db: &TempDb, hash: &str) -> ProjectStore {
        ProjectStore::create(&db.path, hash, 4096, "0.0.1-test", 1000).expect("创建工程库")
    }

    #[test]
    fn address_mapping_is_order_preserving_bijection() {
        // 全序必须保持：这是范围查询正确性的根基
        for addr in [
            0u64,
            1,
            0x7fff_ffff_ffff_ffff,
            0x8000_0000_0000_0000,
            u64::MAX,
        ] {
            assert_eq!(i64_to_addr(addr_to_i64(addr)), addr, "{addr:#x} 往返失败");
        }
        assert!(addr_to_i64(0) < addr_to_i64(0x1000));
        assert!(
            addr_to_i64(0x7fff_ffff_ffff_ffff) < addr_to_i64(0x8000_0000_0000_0000),
            "跨过 i64 边界后顺序必须仍然单调"
        );
        assert!(addr_to_i64(0x8000_0000_0000_0000) < addr_to_i64(u64::MAX));
    }

    #[test]
    fn put_get_roundtrip() {
        let db = TempDb::new("rt");
        let store = open(&db, "aa");
        store
            .put(
                &Annotation::text(0x1000, AnnotationKind::Name, "my_func"),
                1,
            )
            .expect("写入");
        let got = store.get(0x1000, AnnotationKind::Name).expect("应存在");
        assert_eq!(got.text.as_deref(), Some("my_func"));
        assert_eq!(store.len(), 1);
    }

    #[test]
    fn put_is_upsert_not_duplicate() {
        let db = TempDb::new("upsert");
        let store = open(&db, "aa");
        for name in ["first", "second"] {
            store
                .put(&Annotation::text(0x1000, AnnotationKind::Name, name), 1)
                .expect("写入");
        }
        assert_eq!(store.len(), 1, "同地址同类必须覆盖，不该出现两条");
        assert_eq!(
            store
                .get(0x1000, AnnotationKind::Name)
                .expect("存在")
                .text
                .as_deref(),
            Some("second")
        );
    }

    #[test]
    fn distinct_kinds_at_same_address_coexist() {
        let db = TempDb::new("kinds");
        let store = open(&db, "aa");
        store
            .put(&Annotation::text(0x1000, AnnotationKind::Name, "f"), 1)
            .expect("写入");
        store
            .put(&Annotation::text(0x1000, AnnotationKind::Comment, "hi"), 1)
            .expect("写入");
        assert_eq!(store.len(), 2, "不同类别是不同行");
        assert_eq!(store.at(0x1000).len(), 2);
    }

    #[test]
    fn target_hash_mismatch_is_loud() {
        let db = TempDb::new("mismatch");
        {
            let _store = open(&db, "aabb");
        }
        let err = ProjectStore::open(&db.path, "ccdd").expect_err("哈希不匹配必须报错");
        assert!(matches!(err, ProjectError::TargetMismatch { .. }));
    }

    #[test]
    fn too_new_schema_is_rejected_not_parsed() {
        let db = TempDb::new("toonew");
        {
            let store = open(&db, "aa");
            store
                .conn
                .execute(
                    "UPDATE meta SET value = '999' WHERE key = 'schema_version'",
                    [],
                )
                .expect("改版本");
        }
        let err = ProjectStore::open(&db.path, "aa").expect_err("以旧读新必须被拒");
        assert!(matches!(err, ProjectError::TooNew { .. }));
    }

    #[test]
    fn old_schema_reports_migration_required() {
        let db = TempDb::new("old");
        {
            let store = open(&db, "aa");
            store
                .conn
                .execute(
                    "UPDATE meta SET value = '0' WHERE key = 'schema_version'",
                    [],
                )
                .expect("改版本");
        }
        let err = ProjectStore::open(&db.path, "aa").expect_err("旧库要明确报迁移");
        assert!(
            matches!(err, ProjectError::MigrationRequired { from: 0 }),
            "实际 {err:?}"
        );
    }

    #[test]
    fn range_query_is_ordered_and_half_open() {
        let db = TempDb::new("range");
        let store = open(&db, "aa");
        for addr in [0x1000u64, 0x1010, 0x1020] {
            store
                .put(
                    &Annotation::text(addr, AnnotationKind::Comment, format!("c{addr:x}")),
                    1,
                )
                .expect("写入");
        }
        let got = store.range(0x1000, 0x1020);
        assert_eq!(got.len(), 2, "区间 [from, to) 是半开区间");
        assert_eq!(got[0].address, 0x1000);
        assert_eq!(got[1].address, 0x1010);
    }

    #[test]
    fn range_query_works_across_i64_boundary() {
        // 保序映射的实际意义：高地址与大范围查询不能出错
        let db = TempDb::new("highbit");
        let store = open(&db, "aa");
        let low = 0x0000_0000_0010_0000u64;
        let high = 0xffff_0000_0000_0000u64;
        store
            .put(&Annotation::text(low, AnnotationKind::Name, "low"), 1)
            .expect("写入");
        store
            .put(&Annotation::text(high, AnnotationKind::Name, "high"), 1)
            .expect("写入");
        let all = store.range(0, u64::MAX);
        assert_eq!(all.len(), 2);
        assert_eq!(all[0].address, low, "排序必须按真实地址升序");
        assert_eq!(all[1].address, high);
    }

    #[test]
    fn patch_annotation_roundtrips_bytes() {
        let db = TempDb::new("patch");
        let store = open(&db, "aa");
        let bytes = [0x90u8, 0x00, 0xEB, 0xFF];
        store
            .put(&Annotation::patch(0x2000, &bytes), 1)
            .expect("写入");
        let got = store.get(0x2000, AnnotationKind::Patch).expect("存在");
        assert_eq!(got.patch_bytes().as_deref(), Some(&bytes[..]));
        assert!(got.text.is_none(), "补丁没有文本内容");
    }

    #[test]
    fn delete_is_idempotent() {
        let db = TempDb::new("del");
        let store = open(&db, "aa");
        store
            .put(&Annotation::text(5, AnnotationKind::Bookmark, "x"), 1)
            .expect("写入");
        store
            .delete(5, AnnotationKind::Bookmark)
            .expect("第一次删除");
        store
            .delete(5, AnnotationKind::Bookmark)
            .expect("第二次删除不该报错");
        assert!(store.is_empty());
    }

    #[test]
    fn empty_annotation_is_rejected() {
        let db = TempDb::new("empty");
        let store = open(&db, "aa");
        let err = store
            .put(
                &Annotation {
                    address: 1,
                    kind: AnnotationKind::Name,
                    text: None,
                    patch_hex: None,
                },
                1,
            )
            .expect_err("空标注必须被拒");
        assert!(matches!(err, ProjectError::Corrupt(_)));
    }

    #[test]
    fn reopen_preserves_annotations() {
        let db = TempDb::new("reopen");
        {
            let store = open(&db, "aa");
            store
                .put(
                    &Annotation::text(0x9000, AnnotationKind::Name, "persist"),
                    1,
                )
                .expect("写入");
        }
        // 关掉再开：主数据必须还在 —— 这是整个存储设计的底线
        let store = ProjectStore::open(&db.path, "aa").expect("重开");
        assert_eq!(
            store
                .get(0x9000, AnnotationKind::Name)
                .expect("存在")
                .text
                .as_deref(),
            Some("persist")
        );
    }

    #[test]
    fn meta_roundtrips_through_the_store() {
        let db = TempDb::new("meta");
        let store = ProjectStore::create(&db.path, "beef", 12345, "9.9.9", 777).expect("创建");
        let meta = store.meta().expect("读 meta");
        assert_eq!(meta.schema_version, SCHEMA_VERSION);
        assert_eq!(meta.target_sha256, "beef");
        assert_eq!(meta.target_size, 12345);
        assert_eq!(meta.tool_version, "9.9.9");
        assert_eq!(meta.created_at_unix, 777);
        assert_eq!(meta.analyzed_at_unix, None, "尚未分析过");

        store.set_analyzed_at(888).expect("记录分析时间");
        assert_eq!(store.meta().expect("再读").analyzed_at_unix, Some(888));
        assert_eq!(
            store.meta().expect("再读").compatibility(),
            crate::Compatibility::Current
        );
    }
}
