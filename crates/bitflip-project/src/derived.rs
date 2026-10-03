//! `.bda` 派生物文件：分析结果的紧凑快照，**可整体删除重建**。
//!
//! 设计依据 `docs/D2-STORAGE-ANALYSIS.md` §6.3（格式）与 §6.4（原子写入）。
//!
//! 与 `.bfp` 的分工是本项目的核心数据决定：
//! - `.bfp` 装**主数据**（用户标注），丢了不可接受，所以用 SQLite 的 WAL 保命；
//! - `.bda` 装**派生物**（函数/xref/字符串），丢了重新分析就行，所以要的是
//!   **写得快、读得快、能整体替换**，而不是事务。
//!
//! 因此这里刻意**不引入数据库**：按地址排序 + 二分查找就能满足
//! "这个地址属于哪个函数"这类全部查询（D2 §6.3）。用 SQLite 装派生产物会让
//! 重新分析变成一次数据库批量写，反而更慢更脆。
//!
//! 索引全部**基址相对**存储：同一个索引能直接套用到 PE 的 image base 变化上。

use std::io::Write;
use std::path::{Path, PathBuf};

use crate::{ProjectError, SCHEMA_VERSION};

/// magic：`BFLPDA\0\0`。
pub const BDA_MAGIC: [u8; 8] = *b"BFLPDA\0\0";
/// 派生物格式版本。
pub const BDA_FORMAT_VERSION: u32 = 1;
/// 文件头长度（magic 8 + version 4 + flags 4 + hash 32 + table_count 4）。
pub const HEADER_LEN: usize = 52;
/// 每个目录项长度（kind 4 + offset 8 + length 8）。
pub const DIRENT_LEN: usize = 20;

/// 表类别。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(u32)]
pub enum TableKind {
    /// 函数（起点 + 可选终点 + 名字 id）。
    Functions = 1,
    /// 交叉引用。
    Xrefs = 2,
    /// 字符串。
    Strings = 3,
    /// 指令索引（地址 + 长度）。
    Instructions = 4,
    /// 符号名字池（interned，供前几张表引用）。
    Names = 5,
}

impl TableKind {
    /// 从 u32 还原；未知值返回 `None`（前向兼容：新表类别要能被旧代码忽略，
    /// 而不是让整个文件读不出来）。
    #[must_use]
    pub const fn from_u32(value: u32) -> Option<Self> {
        match value {
            1 => Some(Self::Functions),
            2 => Some(Self::Xrefs),
            3 => Some(Self::Strings),
            4 => Some(Self::Instructions),
            5 => Some(Self::Names),
            _ => None,
        }
    }
}

/// 函数条目（定长 24 字节）。
///
/// `end` 为 0 表示**边界未知** —— 它必须是明确的"未知"而不是"等于 start"，
/// 这两种情况在 UI 上含义完全不同（前者不该画大小，后者是 0 字节函数）。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FunctionEntry {
    /// 入口地址。
    pub start: u64,
    /// 结束地址（不含）；`0` 表示未知。
    pub end: u64,
    /// 名字池下标（`u32::MAX` 表示没有名字）。
    pub name_ref: u32,
    /// 置信度。
    pub confidence: u8,
    /// 名字来源的空洞占位（保持定长对齐）。
    _pad: [u8; 3],
}

impl FunctionEntry {
    /// 构造一条函数条目。
    #[must_use]
    pub const fn new(start: u64, end: Option<u64>, name_ref: Option<u32>, confidence: u8) -> Self {
        Self {
            start,
            end: match end {
                Some(v) => v,
                None => 0,
            },
            name_ref: match name_ref {
                Some(v) => v,
                None => u32::MAX,
            },
            confidence,
            _pad: [0; 3],
        }
    }

    /// 结束地址（未知时为 `None`）。
    #[must_use]
    pub const fn end(&self) -> Option<u64> {
        if self.end == 0 {
            None
        } else {
            Some(self.end)
        }
    }

    /// 名字池下标。
    #[must_use]
    pub const fn name_ref(&self) -> Option<u32> {
        if self.name_ref == u32::MAX {
            None
        } else {
            Some(self.name_ref)
        }
    }

    fn encode(&self, out: &mut Vec<u8>) {
        out.extend_from_slice(&self.start.to_le_bytes());
        out.extend_from_slice(&self.end.to_le_bytes());
        out.extend_from_slice(&self.name_ref.to_le_bytes());
        out.push(self.confidence);
        out.extend_from_slice(&self._pad);
    }

    fn decode(data: &[u8]) -> Option<Self> {
        if data.len() < 24 {
            return None;
        }
        Some(Self {
            start: u64::from_le_bytes(data[0..8].try_into().ok()?),
            end: u64::from_le_bytes(data[8..16].try_into().ok()?),
            name_ref: u32::from_le_bytes(data[16..20].try_into().ok()?),
            confidence: data[20],
            _pad: [0; 3],
        })
    }
}

/// 交叉引用条目（定长 17 字节）。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct XrefEntry {
    /// 发起地址。
    pub from: u64,
    /// 目标地址。
    pub to: u64,
    /// 类型（1=call，2=jump，3=data）。
    pub kind: u8,
}

impl XrefEntry {
    const ENCODED_LEN: usize = 17;

    /// 类型编码。
    #[must_use]
    pub const fn kind_code(name: &str) -> u8 {
        match name.as_bytes() {
            b"call" => 1,
            b"jump" => 2,
            _ => 3,
        }
    }

    fn encode(&self, out: &mut Vec<u8>) {
        out.extend_from_slice(&self.from.to_le_bytes());
        out.extend_from_slice(&self.to.to_le_bytes());
        out.push(self.kind);
    }

    fn decode(data: &[u8]) -> Option<Self> {
        if data.len() < Self::ENCODED_LEN {
            return None;
        }
        Some(Self {
            from: u64::from_le_bytes(data[0..8].try_into().ok()?),
            to: u64::from_le_bytes(data[8..16].try_into().ok()?),
            kind: data[16],
        })
    }
}

/// 字符串条目（变长：address 8 + size 4 + encoding 1 + utf8 长度 4 + 字节）。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StringEntry {
    /// 起始地址。
    pub address: u64,
    /// 字节长度（原始编码下的字节数）。
    pub size: u32,
    /// 编码代码（1=ascii，2=utf-16le）。
    pub encoding: u8,
    /// 内容。
    pub text: String,
}

/// 派生物快照：内存中的表集合，写盘前先构造好。
#[derive(Debug, Default)]
pub struct Snapshot {
    /// 目标内容哈希（与 `.bfp` 交叉校验）。
    pub target_sha256: String,
    /// 函数表。
    pub functions: Vec<FunctionEntry>,
    /// xref 表。
    pub xrefs: Vec<XrefEntry>,
    /// 字符串表。
    pub strings: Vec<StringEntry>,
    /// 名字池。
    pub names: Vec<String>,
}

impl Snapshot {
    /// 名字池下标；不存在则插入。
    ///
    /// 名字池按**首次出现顺序**增长，不做排序：排序会让"池里第 n 个"
    /// 这个引用变得依赖内容，跨次分析不稳定。
    pub fn intern(&mut self, name: &str) -> u32 {
        if let Some(pos) = self.names.iter().position(|n| n == name) {
            return pos as u32;
        }
        self.names.push(name.to_string());
        (self.names.len() - 1) as u32
    }

    /// 序列化为 `.bda` 字节。
    ///
    /// 表按地址升序写出 —— 读侧的二分查找依赖这个不变量，所以这里**排序是
    /// 格式的一部分**，不是优化。
    #[must_use]
    pub fn to_bytes(&self) -> Vec<u8> {
        let hash = parse_sha256(&self.target_sha256);

        let mut functions = self.functions.clone();
        functions.sort_by_key(|f| f.start);
        let mut xrefs = self.xrefs.clone();
        xrefs.sort_by_key(|x| (x.from, x.to));
        let mut strings = self.strings.clone();
        strings.sort_by_key(|s| s.address);

        let mut tables: Vec<(TableKind, Vec<u8>)> = Vec::new();
        if !functions.is_empty() {
            let mut buf = Vec::with_capacity(functions.len() * 24);
            for f in &functions {
                f.encode(&mut buf);
            }
            tables.push((TableKind::Functions, buf));
        }
        if !xrefs.is_empty() {
            let mut buf = Vec::with_capacity(xrefs.len() * XrefEntry::ENCODED_LEN);
            for x in &xrefs {
                x.encode(&mut buf);
            }
            tables.push((TableKind::Xrefs, buf));
        }
        if !strings.is_empty() {
            let mut buf = Vec::new();
            for s in &strings {
                buf.extend_from_slice(&s.address.to_le_bytes());
                buf.extend_from_slice(&s.size.to_le_bytes());
                buf.push(s.encoding);
                let bytes = s.text.as_bytes();
                buf.extend_from_slice(&(bytes.len() as u32).to_le_bytes());
                buf.extend_from_slice(bytes);
            }
            tables.push((TableKind::Strings, buf));
        }
        if !self.names.is_empty() {
            let mut buf = Vec::new();
            for n in &self.names {
                let bytes = n.as_bytes();
                buf.extend_from_slice(&(bytes.len() as u32).to_le_bytes());
                buf.extend_from_slice(bytes);
            }
            tables.push((TableKind::Names, buf));
        }

        let dir_len = tables.len() * DIRENT_LEN;
        let mut out = Vec::with_capacity(HEADER_LEN + dir_len + 1024);
        out.extend_from_slice(&BDA_MAGIC);
        out.extend_from_slice(&BDA_FORMAT_VERSION.to_le_bytes());
        out.extend_from_slice(&0u32.to_le_bytes()); // flags 保留
        out.extend_from_slice(&hash);
        out.extend_from_slice(&(tables.len() as u32).to_le_bytes());

        // 表数据从目录之后开始
        let mut offset = (HEADER_LEN + dir_len) as u64;
        for (kind, data) in &tables {
            out.extend_from_slice(&(*kind as u32).to_le_bytes());
            out.extend_from_slice(&offset.to_le_bytes());
            out.extend_from_slice(&(data.len() as u64).to_le_bytes());
            offset += data.len() as u64;
        }
        for (_, data) in &tables {
            out.extend_from_slice(data);
        }
        out
    }

    /// 从 `.bda` 字节解析。
    ///
    /// `expected_sha256` 不为空时校验哈希：**目标变了就报错**，
    /// 绝不返回"看起来能用"的旧结果（D2 §6.3）。
    pub fn from_bytes(data: &[u8], expected_sha256: &str) -> Result<Self, ProjectError> {
        if data.len() < HEADER_LEN {
            return Err(ProjectError::Corrupt("派生物文件短于文件头".into()));
        }
        if data[0..8] != BDA_MAGIC {
            return Err(ProjectError::Corrupt("派生物文件 magic 不匹配".into()));
        }
        let version = u32::from_le_bytes(data[8..12].try_into().expect("已校验长度"));
        if version > BDA_FORMAT_VERSION {
            return Err(ProjectError::TooNew {
                found: version,
                supported: BDA_FORMAT_VERSION,
            });
        }
        let hash_bytes = &data[16..48];
        let stored_hash = hex_encode(hash_bytes);
        if !expected_sha256.is_empty() && stored_hash != expected_sha256 {
            return Err(ProjectError::TargetMismatch {
                expected: stored_hash,
                actual: expected_sha256.to_string(),
            });
        }
        let table_count = u32::from_le_bytes(data[48..52].try_into().expect("已校验长度")) as usize;
        let dir_end = HEADER_LEN + table_count * DIRENT_LEN;
        if data.len() < dir_end {
            return Err(ProjectError::Corrupt("派生物目录被截断".into()));
        }

        let mut snapshot = Self {
            target_sha256: stored_hash,
            ..Self::default()
        };

        for i in 0..table_count {
            let base = HEADER_LEN + i * DIRENT_LEN;
            let kind_raw = u32::from_le_bytes(data[base..base + 4].try_into().expect("已校验长度"));
            let offset =
                u64::from_le_bytes(data[base + 4..base + 12].try_into().expect("已校验长度"))
                    as usize;
            let length =
                u64::from_le_bytes(data[base + 12..base + 20].try_into().expect("已校验长度"))
                    as usize;
            // 未知表类别：跳过而不是报错。前向兼容要求旧代码能读新文件里
            // 它认识的那部分。
            let Some(kind) = TableKind::from_u32(kind_raw) else {
                continue;
            };
            let end = offset.saturating_add(length);
            if end > data.len() {
                return Err(ProjectError::Corrupt(format!(
                    "派生物表 {kind:?} 越界（{offset}+{length} > {}）",
                    data.len()
                )));
            }
            let section = &data[offset..end];
            match kind {
                TableKind::Functions => {
                    for chunk in section.chunks_exact(24) {
                        snapshot
                            .functions
                            .push(FunctionEntry::decode(chunk).expect("固定长度"));
                    }
                }
                TableKind::Xrefs => {
                    for chunk in section.chunks_exact(XrefEntry::ENCODED_LEN) {
                        snapshot
                            .xrefs
                            .push(XrefEntry::decode(chunk).expect("固定长度"));
                    }
                }
                TableKind::Strings => {
                    let mut cursor = 0usize;
                    while cursor + 17 <= section.len() {
                        let address = u64::from_le_bytes(
                            section[cursor..cursor + 8].try_into().expect("校验"),
                        );
                        let size = u32::from_le_bytes(
                            section[cursor + 8..cursor + 12].try_into().expect("校验"),
                        );
                        let encoding = section[cursor + 12];
                        let text_len = u32::from_le_bytes(
                            section[cursor + 13..cursor + 17].try_into().expect("校验"),
                        ) as usize;
                        let text_start = cursor + 17;
                        let text_end = text_start + text_len;
                        if text_end > section.len() {
                            return Err(ProjectError::Corrupt("派生物字符串表被截断".into()));
                        }
                        snapshot.strings.push(StringEntry {
                            address,
                            size,
                            encoding,
                            text: String::from_utf8_lossy(&section[text_start..text_end])
                                .into_owned(),
                        });
                        cursor = text_end;
                    }
                }
                TableKind::Names => {
                    let mut cursor = 0usize;
                    while cursor + 4 <= section.len() {
                        let len = u32::from_le_bytes(
                            section[cursor..cursor + 4].try_into().expect("校验"),
                        ) as usize;
                        let start = cursor + 4;
                        let end = start + len;
                        if end > section.len() {
                            return Err(ProjectError::Corrupt("派生物名字池被截断".into()));
                        }
                        snapshot
                            .names
                            .push(String::from_utf8_lossy(&section[start..end]).into_owned());
                        cursor = end;
                    }
                }
                TableKind::Instructions => {
                    // 指令索引目前不落盘（可由扫描重建），保留类别码以便将来使用
                }
            }
        }
        Ok(snapshot)
    }
}

/// 原子写入：建父目录 → 临时文件 → fsync → rename。
///
/// 崩溃在任何一步都不产生半成品：`.bda` 要么是旧版本、要么是新版本（D2 §6.4）。
///
/// 父目录由本函数创建：路径是按哈希前两位分片的（`projects/ef/ef….bda`），
/// 首次写入时该目录必然不存在。把这个责任留给调用方，等于让每个调用方
/// 都重复一遍 `create_dir_all` —— 漏一个就是一个"找不到路径"的 bug。
pub fn write_atomic(path: &Path, bytes: &[u8]) -> Result<(), ProjectError> {
    if let Some(parent) = path.parent() {
        if !parent.as_os_str().is_empty() {
            std::fs::create_dir_all(parent).map_err(io_err)?;
        }
    }
    let tmp = tmp_path(path);
    {
        let mut file = std::fs::File::create(&tmp).map_err(io_err)?;
        file.write_all(bytes).map_err(io_err)?;
        // fsync 之后 rename 才有意义：否则崩溃可能留下"文件在、内容是空的"
        file.sync_all().map_err(io_err)?;
    }
    std::fs::rename(&tmp, path).map_err(io_err)?;
    Ok(())
}

/// 读取并校验 `.bda`。
pub fn read(path: &Path, expected_sha256: &str) -> Result<Snapshot, ProjectError> {
    let data = std::fs::read(path).map_err(io_err)?;
    Snapshot::from_bytes(&data, expected_sha256)
}

/// 清理残留的 `.tmp`（上次崩溃留下的半成品）。
///
/// 返回是否真的删了文件。`.tmp` 不是有效文件，永远不会被误读，
/// 所以清理失败不是错误。
pub fn clean_stale_tmp(path: &Path) -> bool {
    std::fs::remove_file(tmp_path(path)).is_ok()
}

/// 派生物文件路径（`<hash>.bda`）。
#[must_use]
pub fn derived_path(workspace: &Path, target_sha256: &str) -> PathBuf {
    // 前 2 位做分片目录，避免单目录塞满几万个文件
    let prefix = &target_sha256[..target_sha256.len().min(2)];
    workspace
        .join("projects")
        .join(prefix)
        .join(format!("{target_sha256}.bda"))
}

/// 主数据文件路径（`<hash>.bfp`）。
#[must_use]
pub fn primary_path(workspace: &Path, target_sha256: &str) -> PathBuf {
    let prefix = &target_sha256[..target_sha256.len().min(2)];
    workspace
        .join("projects")
        .join(prefix)
        .join(format!("{target_sha256}.bfp"))
}

fn tmp_path(path: &Path) -> PathBuf {
    let mut s = path.as_os_str().to_os_string();
    s.push(".tmp");
    PathBuf::from(s)
}

/// 把 `io::Error` 转成工程库错误。
///
/// `ProjectError::Io` 携带的是字符串而不是 `io::Error`：存储层错误不该把
/// 底层类型泄漏到上层（与 `rusqlite` 类型不外泄同一条原则）。
pub fn io_err(error: std::io::Error) -> ProjectError {
    ProjectError::Io(error.to_string())
}

fn parse_sha256(hex: &str) -> [u8; 32] {
    let mut out = [0u8; 32];
    let bytes = hex.as_bytes();
    for (i, slot) in out.iter_mut().enumerate() {
        let hi = bytes.get(i * 2).copied().unwrap_or(b'0');
        let lo = bytes.get(i * 2 + 1).copied().unwrap_or(b'0');
        *slot = (hex_val(hi) << 4) | hex_val(lo);
    }
    out
}

fn hex_val(c: u8) -> u8 {
    match c {
        b'0'..=b'9' => c - b'0',
        b'a'..=b'f' => c - b'a' + 10,
        b'A'..=b'F' => c - b'A' + 10,
        _ => 0,
    }
}

fn hex_encode(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        out.push_str(&format!("{b:02x}"));
    }
    out
}

/// `.bda` 与 `.bfp` 的格式版本一致性哨兵（测试与文档用）。
#[must_use]
pub const fn bda_schema_alignment() -> (u32, u32) {
    (SCHEMA_VERSION, BDA_FORMAT_VERSION)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn snapshot() -> Snapshot {
        let mut s = Snapshot {
            target_sha256: "ab".repeat(32),
            functions: vec![
                FunctionEntry::new(0x2000, None, None, 40),
                FunctionEntry::new(0x1000, Some(0x1040), Some(0), 85),
            ],
            xrefs: vec![
                XrefEntry {
                    from: 0x1000,
                    to: 0x2000,
                    kind: 1,
                },
                XrefEntry {
                    from: 0x1004,
                    to: 0x3000,
                    kind: 3,
                },
            ],
            strings: vec![StringEntry {
                address: 0x3000,
                size: 6,
                encoding: 1,
                text: "hello".into(),
            }],
            names: Vec::new(),
        };
        s.intern("main");
        s
    }

    #[test]
    fn magic_and_layout_are_stable() {
        let bytes = snapshot().to_bytes();
        assert_eq!(&bytes[0..8], &BDA_MAGIC);
        assert_eq!(
            u32::from_le_bytes(bytes[8..12].try_into().unwrap()),
            BDA_FORMAT_VERSION
        );
        assert_eq!(&bytes[16..48], &parse_sha256(&"ab".repeat(32)));
    }

    #[test]
    fn roundtrip_preserves_everything() {
        let original = snapshot();
        let bytes = original.to_bytes();
        let back = Snapshot::from_bytes(&bytes, &original.target_sha256).expect("解析");

        assert_eq!(back.functions.len(), 2);
        assert_eq!(back.xrefs.len(), 2);
        assert_eq!(back.strings.len(), 1);
        assert_eq!(back.names, vec!["main".to_string()]);
        assert_eq!(back.strings[0].text, "hello");
    }

    #[test]
    fn unknown_end_stays_unknown_across_roundtrip() {
        // 未知边界必须是 None，不能退化成 0 —— 这是诚实性底线
        let original = snapshot();
        let back = Snapshot::from_bytes(&original.to_bytes(), "").expect("解析");
        let unknown = back.functions.iter().find(|f| f.start == 0x2000).unwrap();
        assert_eq!(unknown.end(), None, "未知边界不许变成 0");
        assert_eq!(unknown.name_ref(), None, "没有名字不许变成第 0 个名字");
        let known = back.functions.iter().find(|f| f.start == 0x1000).unwrap();
        assert_eq!(known.end(), Some(0x1040));
    }

    #[test]
    fn tables_are_address_sorted_on_disk() {
        // 读侧二分依赖它，所以这是格式不变量
        let bytes = snapshot().to_bytes();
        let back = Snapshot::from_bytes(&bytes, "").expect("解析");
        let starts: Vec<u64> = back.functions.iter().map(|f| f.start).collect();
        assert_eq!(starts, vec![0x1000, 0x2000], "函数表必须按地址升序落盘");
        let froms: Vec<u64> = back.xrefs.iter().map(|x| x.from).collect();
        assert!(froms.windows(2).all(|w| w[0] <= w[1]), "xref 表必须有序");
    }

    #[test]
    fn hash_mismatch_is_rejected() {
        let bytes = snapshot().to_bytes();
        let err = Snapshot::from_bytes(&bytes, &"cd".repeat(32)).expect_err("哈希不符必须报错");
        assert!(matches!(err, ProjectError::TargetMismatch { .. }));
    }

    #[test]
    fn truncated_file_is_corrupt_not_panic() {
        let bytes = snapshot().to_bytes();
        for cut in [0usize, 8, 20, 51, 60, bytes.len() - 1] {
            let result = Snapshot::from_bytes(&bytes[..cut], "");
            assert!(result.is_err(), "截断到 {cut} 字节应报错而不是 panic");
        }
    }

    #[test]
    fn bad_magic_is_corrupt() {
        let mut bytes = snapshot().to_bytes();
        bytes[0] = b'X';
        assert!(Snapshot::from_bytes(&bytes, "").is_err());
    }

    #[test]
    fn future_version_is_rejected() {
        let mut bytes = snapshot().to_bytes();
        bytes[8..12].copy_from_slice(&(BDA_FORMAT_VERSION + 1).to_le_bytes());
        let err = Snapshot::from_bytes(&bytes, "").expect_err("未来版本必须拒绝");
        assert!(matches!(err, ProjectError::TooNew { .. }));
    }

    #[test]
    fn unknown_table_kind_is_skipped_not_fatal() {
        // 前向兼容：新版本加了表类别，旧代码要能读认识的部分
        let mut bytes = snapshot().to_bytes();
        let table_count = u32::from_le_bytes(bytes[48..52].try_into().unwrap());
        if table_count > 0 {
            bytes[HEADER_LEN..HEADER_LEN + 4].copy_from_slice(&999u32.to_le_bytes());
            let back = Snapshot::from_bytes(&bytes, "").expect("未知表类别应被跳过");
            assert!(back.xrefs.len() + back.functions.len() + back.strings.len() < 5);
        }
    }

    #[test]
    fn empty_snapshot_roundtrips() {
        let empty = Snapshot {
            target_sha256: "00".repeat(32),
            ..Snapshot::default()
        };
        let back = Snapshot::from_bytes(&empty.to_bytes(), "").expect("解析空快照");
        assert!(back.functions.is_empty());
        assert!(back.xrefs.is_empty());
        assert!(back.strings.is_empty());
    }

    #[test]
    fn write_atomic_publishes_and_leaves_no_tmp() {
        let dir = std::env::temp_dir().join(format!("bf-bda-{}", std::process::id()));
        std::fs::create_dir_all(&dir).expect("建目录");
        let path = dir.join("test.bda");
        let data = snapshot().to_bytes();
        write_atomic(&path, &data).expect("原子写");
        assert!(path.exists());
        assert!(
            !tmp_path(&path).exists(),
            "成功后不许留下 .tmp：rename 是原子的"
        );
        let back = read(&path, &"ab".repeat(32)).expect("读回");
        assert_eq!(back.functions.len(), 2);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn write_atomic_replaces_previous_version() {
        let dir = std::env::temp_dir().join(format!("bf-bda-rep-{}", std::process::id()));
        std::fs::create_dir_all(&dir).expect("建目录");
        let path = dir.join("v.bda");
        // 先写一个"旧版本"，确认能被整体替换（用户看到的永远不会是拼接结果）
        write_atomic(&path, &Snapshot::default().to_bytes()).expect("首次写");
        write_atomic(&path, &snapshot().to_bytes()).expect("覆盖");
        let back = read(&path, "").expect("读回");
        assert_eq!(back.functions.len(), 2, "必须是新版本，不是两者的拼接");
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn stale_tmp_is_cleaned() {
        let dir = std::env::temp_dir().join(format!("bf-bda-tmp-{}", std::process::id()));
        std::fs::create_dir_all(&dir).expect("建目录");
        let path = dir.join("x.bda");
        let tmp = tmp_path(&path);
        std::fs::write(&tmp, b"half-written garbage").expect("伪造残留");
        assert!(clean_stale_tmp(&path), "应检测到并删除残留");
        assert!(!tmp.exists());
        assert!(!clean_stale_tmp(&path), "没有残留时返回 false");
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn derived_and_primary_paths_are_sharded_by_hash() {
        let ws = Path::new("F:/ws");
        let hash = "abcdef".to_string() + &"0".repeat(58);
        let bda = derived_path(ws, &hash);
        let bfp = primary_path(ws, &hash);
        assert!(bda.to_string_lossy().contains("projects"));
        assert!(bda.to_string_lossy().ends_with(".bda"));
        assert!(bfp.to_string_lossy().ends_with(".bfp"));
        assert!(
            bda.parent() == bfp.parent(),
            "同一目标的两个文件必须同目录，方便整体搬迁"
        );
        assert!(
            bda.parent().unwrap().to_string_lossy().ends_with("ab"),
            "分片目录取哈希前两位"
        );
    }

    #[test]
    fn xref_kind_codes_are_stable() {
        assert_eq!(XrefEntry::kind_code("call"), 1);
        assert_eq!(XrefEntry::kind_code("jump"), 2);
        assert_eq!(XrefEntry::kind_code("data"), 3);
        assert_eq!(
            XrefEntry::kind_code("未知"),
            3,
            "未知类型退化为 data 而不是 panic"
        );
    }
}
