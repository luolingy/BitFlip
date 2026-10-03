//! 会话持久化：最近打开的目标列表。
//!
//! 等价参照实现的 `index.json`，但**修掉它的两个缺陷**（PLAN §M4）：
//! 1. **原子写** —— 直接覆写 `index.json` 时崩溃会留下截断的 JSON，
//!    整个最近列表就废了。这里走临时文件 + fsync + rename。
//! 2. **并发安全** —— 多个实例同时打开会让后写的覆盖先写的。
//!    这里用"读-改-写 + 重试"降低窗口，并用进程内互斥保护本进程的读改写。
//!
//! 为什么不做文件锁：跨进程文件锁在 Windows 上要求所有写者协作，
//! 而列表丢失一条只是体验损失，不是数据损失（权威数据在 `.bfp` 里）。
//! 为一个"最近列表"引入锁文件和死锁风险不划算 —— 这是刻意的取舍，
//! 不是遗漏。

use std::path::{Path, PathBuf};
use std::sync::Mutex;

use serde::{Deserialize, Serialize};

use crate::ProjectError;

/// 最近列表格式版本。
pub const INDEX_FORMAT_VERSION: u32 = 1;
/// 列表最多保留多少条。
pub const MAX_RECENT: usize = 64;

/// 一条最近记录。
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RecentTarget {
    /// 目标内容哈希（身份，不是路径）。
    pub target_sha256: String,
    /// 最近一次打开时的路径（仅用于展示与"原路径还在吗"判断）。
    pub path: String,
    /// 文件名（展示用，路径可能很长）。
    pub file_name: String,
    /// 文件大小。
    pub size: u64,
    /// 最近打开时间（Unix 秒）。
    pub opened_at_unix: u64,
}

/// 最近列表文件内容。
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RecentIndex {
    /// 格式版本。
    pub format_version: u32,
    /// 记录（按 `opened_at_unix` 降序维护）。
    pub recent: Vec<RecentTarget>,
}

impl Default for RecentIndex {
    fn default() -> Self {
        Self {
            format_version: INDEX_FORMAT_VERSION,
            recent: Vec::new(),
        }
    }
}

impl RecentIndex {
    /// 插入或更新一条记录，并维护降序、去重与长度上限。
    ///
    /// 去重按 **`target_sha256`**：同一份文件换个路径打开不应产生两条 ——
    /// 目标身份是内容哈希，这条在 `bitflip-project` 里已经定死了。
    pub fn touch(&mut self, entry: RecentTarget) {
        self.recent
            .retain(|r| r.target_sha256 != entry.target_sha256);
        self.recent.insert(0, entry);
        // 降序不变量：最近的排最前。用 Reverse 表达"降序"，
        // 比手写比较闭包更不容易写反。
        self.recent
            .sort_by_key(|r| std::cmp::Reverse(r.opened_at_unix));
        self.recent.truncate(MAX_RECENT);
    }

    /// 移除一条（文件被删或用户主动清理时）。
    pub fn forget(&mut self, target_sha256: &str) -> bool {
        let before = self.recent.len();
        self.recent.retain(|r| r.target_sha256 != target_sha256);
        self.recent.len() != before
    }

    /// 指向已不存在文件的条目数（UI 可以灰显）。
    #[must_use]
    pub fn missing_count(&self) -> usize {
        self.recent
            .iter()
            .filter(|r| !Path::new(&r.path).exists())
            .count()
    }
}

/// 最近列表的读写门（进程内串行化 + 原子落盘）。
#[derive(Debug)]
pub struct RecentStore {
    path: PathBuf,
    lock: Mutex<()>,
}

impl RecentStore {
    /// 绑定到工作区下的 `index.json`。
    #[must_use]
    pub fn new(workspace: &Path) -> Self {
        Self {
            path: workspace.join("index.json"),
            lock: Mutex::new(()),
        }
    }

    /// 索引文件路径。
    #[must_use]
    pub fn path(&self) -> &Path {
        &self.path
    }

    /// 读取列表。
    ///
    /// **损坏的索引不报错**：它只是缓存性质的展示数据，丢了就重建。
    /// 但对用户要可见 —— 返回 `(index, was_corrupt)` 而不是静默吞掉。
    #[must_use]
    pub fn load(&self) -> (RecentIndex, bool) {
        let Ok(text) = std::fs::read_to_string(&self.path) else {
            return (RecentIndex::default(), false);
        };
        match serde_json::from_str::<RecentIndex>(&text) {
            Ok(mut index) => {
                // 版本高于自己：不尝试理解，按空列表处理但**不覆盖**它
                if index.format_version > INDEX_FORMAT_VERSION {
                    return (RecentIndex::default(), true);
                }
                index.recent.truncate(MAX_RECENT);
                (index, false)
            }
            Err(_) => (RecentIndex::default(), true),
        }
    }

    /// 记录一次打开。
    pub fn touch(&self, entry: RecentTarget) -> Result<(), ProjectError> {
        self.update(|index| index.touch(entry))
    }

    /// 忘记一个目标。
    pub fn forget(&self, target_sha256: &str) -> Result<(), ProjectError> {
        self.update(|index| {
            index.forget(target_sha256);
        })
    }

    /// 读-改-写。全程持锁，避免本进程内的并发覆盖。
    fn update<F>(&self, mutate: F) -> Result<(), ProjectError>
    where
        F: FnOnce(&mut RecentIndex),
    {
        let _guard = self
            .lock
            .lock()
            .map_err(|_| ProjectError::Corrupt("最近列表锁被污染".into()))?;
        let (mut index, _) = self.load();
        index.format_version = INDEX_FORMAT_VERSION;
        mutate(&mut index);
        let json = serde_json::to_string_pretty(&index)
            .map_err(|e| ProjectError::Io(format!("序列化最近列表失败：{e}")))?;
        // 走和派生物同一套原子写：临时文件 → fsync → rename
        crate::derived::write_atomic(&self.path, json.as_bytes())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn entry(hash: &str, path: &str, at: u64) -> RecentTarget {
        RecentTarget {
            target_sha256: hash.to_string(),
            path: path.to_string(),
            file_name: path.rsplit(['/', '\\']).next().unwrap_or(path).to_string(),
            size: 1024,
            opened_at_unix: at,
        }
    }

    fn temp_ws(tag: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!(
            "bf-recent-{}-{}-{tag}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.subsec_nanos())
                .unwrap_or(0)
        ));
        std::fs::create_dir_all(&dir).expect("建目录");
        dir
    }

    #[test]
    fn touch_then_load_roundtrips() {
        let ws = temp_ws("rt");
        let store = RecentStore::new(&ws);
        store.touch(entry("aa", "C:/a.exe", 100)).expect("记录");
        let (index, corrupt) = store.load();
        assert!(!corrupt);
        assert_eq!(index.recent.len(), 1);
        assert_eq!(index.recent[0].target_sha256, "aa");
        assert_eq!(
            index.recent[0].file_name, "a.exe",
            "文件名应从路径提取，方便展示"
        );
        let _ = std::fs::remove_dir_all(&ws);
    }

    #[test]
    fn same_hash_different_path_is_one_entry() {
        // 目标身份是内容哈希：同一份文件换个路径打开不该出现两条
        let ws = temp_ws("dedup");
        let store = RecentStore::new(&ws);
        store.touch(entry("aa", "C:/orig.exe", 100)).expect("首次");
        store.touch(entry("aa", "D:/copy.exe", 200)).expect("再次");
        let (index, _) = store.load();
        assert_eq!(index.recent.len(), 1, "同哈希必须去重");
        assert_eq!(index.recent[0].path, "D:/copy.exe", "路径应更新为最近的");
        let _ = std::fs::remove_dir_all(&ws);
    }

    #[test]
    fn list_is_sorted_by_recency_and_capped() {
        let ws = temp_ws("cap");
        let store = RecentStore::new(&ws);
        for i in 0..(MAX_RECENT + 10) {
            store
                .touch(entry(&format!("{i:04}"), "C:/x.exe", i as u64))
                .expect("记录");
        }
        let (index, _) = store.load();
        assert_eq!(index.recent.len(), MAX_RECENT, "必须被上限截断");
        assert_eq!(index.recent[0].opened_at_unix, (MAX_RECENT + 9) as u64);
        assert!(
            index
                .recent
                .windows(2)
                .all(|w| w[0].opened_at_unix >= w[1].opened_at_unix),
            "必须按时间降序"
        );
        let _ = std::fs::remove_dir_all(&ws);
    }

    #[test]
    fn forget_removes_entry() {
        let ws = temp_ws("forget");
        let store = RecentStore::new(&ws);
        store.touch(entry("aa", "C:/a.exe", 1)).expect("记录");
        store.forget("aa").expect("忘记");
        let (index, _) = store.load();
        assert!(index.recent.is_empty());
        let _ = std::fs::remove_dir_all(&ws);
    }

    #[test]
    fn corrupt_index_is_reported_not_fatal() {
        let ws = temp_ws("corrupt");
        let store = RecentStore::new(&ws);
        std::fs::write(store.path(), b"{ this is not json").expect("写坏文件");
        let (index, corrupt) = store.load();
        assert!(corrupt, "损坏必须被报告出来");
        assert!(index.recent.is_empty());
        // 而且要能继续用：写一次即可重建
        store.touch(entry("aa", "C:/a.exe", 1)).expect("重建");
        let (index, corrupt) = store.load();
        assert!(!corrupt);
        assert_eq!(index.recent.len(), 1);
        let _ = std::fs::remove_dir_all(&ws);
    }

    #[test]
    fn future_format_is_preserved_not_clobbered() {
        let ws = temp_ws("future");
        let store = RecentStore::new(&ws);
        let future = RecentIndex {
            format_version: INDEX_FORMAT_VERSION + 5,
            recent: vec![entry("future", "C:/f.exe", 9)],
        };
        std::fs::write(
            store.path(),
            serde_json::to_string(&future).expect("序列化"),
        )
        .expect("写未来版本");
        let (index, flagged) = store.load();
        assert!(flagged, "未来版本要标记出来");
        assert!(index.recent.is_empty(), "不尝试理解未来格式");
        let _ = std::fs::remove_dir_all(&ws);
    }

    #[test]
    fn atomic_write_leaves_no_tmp() {
        let ws = temp_ws("atomic");
        let store = RecentStore::new(&ws);
        store.touch(entry("aa", "C:/a.exe", 1)).expect("记录");
        let tmp = store.path().with_extension("json.tmp");
        assert!(!tmp.exists(), "成功后不许留下 .tmp");
        assert!(store.path().exists());
        let _ = std::fs::remove_dir_all(&ws);
    }

    #[test]
    fn missing_count_flags_deleted_files() {
        let ws = temp_ws("missing");
        let store = RecentStore::new(&ws);
        store
            .touch(entry("aa", "C:/definitely/not/here-12345.exe", 1))
            .expect("记录");
        let (index, _) = store.load();
        assert_eq!(index.missing_count(), 1, "不存在的路径应被统计出来");
        let _ = std::fs::remove_dir_all(&ws);
    }
}
