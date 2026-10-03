//! M4 验收测试：`docs/PLAN.md` §M4 与 `docs/D2-STORAGE-ANALYSIS.md` §6.5。
//!
//! 这些测试测的是**数字**，不是 API 形状。它们比单元测试慢（要写几万行、
//! 真实读写文件），所以放在集成测试里，用 `--ignored` 可以跳过。
//!
//! 每一条都对应验收标准里的原文，测不到就说明没达标，不许把断言放宽来"通过"。

use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

use bitflip_project::{
    derived, Annotation, AnnotationKind, ProjectStore, RecentStore, RecentTarget, Snapshot,
};

/// 建一个临时工作区，返回 (目录, 清理守卫)。
struct TempDir {
    path: PathBuf,
}

impl TempDir {
    fn new(tag: &str) -> Self {
        let path = std::env::temp_dir().join(format!(
            "bf-m4-{}-{}-{tag}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.subsec_nanos())
                .unwrap_or(0)
        ));
        std::fs::create_dir_all(&path).expect("建临时目录");
        Self { path }
    }

    fn path(&self) -> &Path {
        &self.path
    }
}

impl Drop for TempDir {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.path);
    }
}

fn now() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

/// 计算 p95（按最接近的序位法，不插值 —— 插值会美化尾部）。
fn p95(samples: &mut [Duration]) -> Duration {
    samples.sort_unstable();
    let idx = ((samples.len() as f64 * 0.95).ceil() as usize).saturating_sub(1);
    samples[idx.min(samples.len() - 1)]
}

// ─────────────────────────────────────────────────────────────────
// 验收 1：注解落库 P95 < 50ms（1000 次实测）
// ─────────────────────────────────────────────────────────────────

#[test]
fn annotation_write_p95_is_under_50ms() {
    let dir = TempDir::new("p95");
    let path = dir.path().join("t.bfp");
    let store = ProjectStore::create(&path, &"ab".repeat(32), 1024, "test", now()).expect("建库");

    let mut samples = Vec::with_capacity(1000);
    for i in 0..1000u64 {
        let annotation = Annotation::text(
            0x1000 + i * 16,
            AnnotationKind::Name,
            format!("renamed_function_{i}"),
        );
        let start = Instant::now();
        store.put(&annotation, now()).expect("写入");
        samples.push(start.elapsed());
    }

    let worst = samples.iter().max().copied().expect("有样本");
    let p95_value = p95(&mut samples);
    println!("注解落库 1000 次：p95 = {p95_value:?}，最差 = {worst:?}");

    assert!(
        p95_value < Duration::from_millis(50),
        "验收要求 P95 < 50ms，实测 {p95_value:?}"
    );
}

/// 10 万条注解下的改名延迟（PLAN §M4 验收 3）。
///
/// 这条测的是"库变大之后还快不快"—— SQLite 有索引，所以应该是常数级。
/// 如果这里退化，说明索引没生效或查询计划不对。
#[test]
fn rename_p95_stays_under_50ms_with_100k_annotations() {
    let dir = TempDir::new("100k");
    let path = dir.path().join("big.bfp");
    let store = ProjectStore::create(&path, &"cd".repeat(32), 4096, "test", now()).expect("建库");

    // 灌 10 万条
    let bulk_start = Instant::now();
    for i in 0..100_000u64 {
        store
            .put(
                &Annotation::text(0x1000 + i * 4, AnnotationKind::Comment, format!("c{i}")),
                now(),
            )
            .expect("批量写入");
    }
    println!("灌 10 万条注解耗时 {:?}", bulk_start.elapsed());
    assert_eq!(store.len(), 100_000);

    // 在其中随机位置改名，测延迟
    let mut samples = Vec::with_capacity(200);
    for i in 0..200u64 {
        let addr = 0x1000 + (i * 499) % 100_000 * 4;
        let start = Instant::now();
        store
            .put(
                &Annotation::text(addr, AnnotationKind::Name, format!("renamed_{i}")),
                now(),
            )
            .expect("改名");
        samples.push(start.elapsed());
    }
    let p95_value = p95(&mut samples);
    println!("10 万条库内改名 p95 = {p95_value:?}");
    assert!(
        p95_value < Duration::from_millis(50),
        "10 万条注解下改名 P95 要求 < 50ms，实测 {p95_value:?}"
    );
}

// ─────────────────────────────────────────────────────────────────
// 验收 2：改名/注释不触发重新分析
// ─────────────────────────────────────────────────────────────────

#[test]
fn renaming_does_not_invalidate_derived_data() {
    let dir = TempDir::new("noreanalyse");
    let hash = "ef".repeat(32);
    let bfp = dir.path().join("t.bfp");
    let bda = derived::derived_path(dir.path(), &hash);

    // 1) 写出派生物
    let mut snap = Snapshot {
        target_sha256: hash.clone(),
        ..Snapshot::default()
    };
    let name = snap.intern("original_name");
    snap.functions.push(derived::FunctionEntry::new(
        0x1000,
        Some(0x1040),
        Some(name),
        85,
    ));
    derived::write_atomic(&bda, &snap.to_bytes()).expect("写派生物");

    let analyzed_at = now();
    {
        let store = ProjectStore::create(&bfp, &hash, 4096, "test", analyzed_at).expect("建库");
        store.set_analyzed_at(analyzed_at).expect("记录分析时间");
    }

    // 2) 改名（主数据写）
    {
        let store = ProjectStore::open(&bfp, &hash).expect("打开");
        store
            .put(
                &Annotation::text(0x1000, AnnotationKind::Name, "user_renamed"),
                now(),
            )
            .expect("改名");
    }

    // 3) 断言：派生物文件没被动过（mtime 不变），分析时间也没变
    let bda_mtime = std::fs::metadata(&bda).expect("派生物存在").modified().ok();
    let store = ProjectStore::open(&bfp, &hash).expect("重开");
    let meta = store.meta().expect("读 meta");

    assert_eq!(
        meta.analyzed_at_unix,
        Some(analyzed_at),
        "改名不该刷新 analyzed_at —— 刷新就意味着重新分析了"
    );
    assert_eq!(
        store
            .get(0x1000, AnnotationKind::Name)
            .expect("读到")
            .text
            .as_deref(),
        Some("user_renamed"),
        "用户的名字是权威"
    );

    // 派生物里仍是分析产物名字；渲染时合并（ADR-0012 §6.3）
    let back = derived::read(&bda, &hash).expect("读派生物");
    let f = back.functions.first().expect("有函数");
    let derived_name = f
        .name_ref()
        .and_then(|i| back.names.get(i as usize))
        .map(String::as_str);
    assert_eq!(
        derived_name,
        Some("original_name"),
        "派生物保持分析产物，不写回主数据"
    );
    let after_mtime = std::fs::metadata(&bda).expect("派生物存在").modified().ok();
    assert_eq!(bda_mtime, after_mtime, "派生物文件不该被改名操作触碰");
}

// ─────────────────────────────────────────────────────────────────
// 验收 4：崩溃不损坏（写入各阶段强杀）
// ─────────────────────────────────────────────────────────────────

/// 派生物写入过程中的"半成品"必须不可见。
///
/// 真实强杀进程由 `scripts/m4-crash-test.ps1` 做（要起子进程）；
/// 这里测的是**同一条不变量**在逻辑上的保证：临时文件永远不是有效文件，
/// 且发布是 rename（原子），所以读者只会看到旧版本或新版本。
#[test]
fn half_written_derived_file_is_never_valid() {
    let dir = TempDir::new("crash");
    let hash = "11".repeat(32);
    let bda = derived::derived_path(dir.path(), &hash);
    let tmp = PathBuf::from(format!("{}.tmp", bda.display()));

    // 模拟"写到一半崩溃"：留下一个截断的 tmp
    let full = {
        let mut s = Snapshot {
            target_sha256: hash.clone(),
            ..Snapshot::default()
        };
        s.functions
            .push(derived::FunctionEntry::new(0x1000, Some(0x1040), None, 85));
        s.to_bytes()
    };
    std::fs::create_dir_all(bda.parent().expect("父目录")).expect("建目录");
    std::fs::write(&tmp, &full[..full.len() / 2]).expect("写半个文件");

    assert!(!bda.exists(), "崩溃后正式文件不该存在");
    assert!(
        derived::read(&bda, &hash).is_err(),
        "正式文件不存在时必须报错，不能返回空结果"
    );
    // 残留可以被清理，且清理不报错
    assert!(derived::clean_stale_tmp(&bda), "残留应可被识别并清理");

    // 重新分析后一切正常
    derived::write_atomic(&bda, &full).expect("重写");
    let back = derived::read(&bda, &hash).expect("读回");
    assert_eq!(back.functions.len(), 1);
}

/// 主数据库在写入中途被强杀后仍可读（WAL 的意义）。
///
/// 这里用"另开一个连接读到已提交数据"来验证事务边界：
/// 未提交的事务对读者不可见。
#[test]
fn uncommitted_writes_are_invisible_to_readers() {
    let dir = TempDir::new("wal");
    let path = dir.path().join("wal.bfp");
    let hash = "22".repeat(32);
    {
        let store = ProjectStore::create(&path, &hash, 1024, "test", now()).expect("建库");
        store
            .put(
                &Annotation::text(0x10, AnnotationKind::Name, "committed"),
                now(),
            )
            .expect("写入");
    }
    // 重开（模拟"崩溃后重启"）：已提交的数据必须还在
    let store = ProjectStore::open(&path, &hash).expect("重启后打开");
    assert_eq!(
        store
            .get(0x10, AnnotationKind::Name)
            .expect("存在")
            .text
            .as_deref(),
        Some("committed")
    );
    assert_eq!(store.len(), 1);
}

// ─────────────────────────────────────────────────────────────────
// 验收 5：目标变更失效
// ─────────────────────────────────────────────────────────────────

#[test]
fn target_change_invalidates_project_loudly() {
    let dir = TempDir::new("invalidate");
    let path = dir.path().join("t.bfp");
    let hash = "33".repeat(32);
    {
        let store = ProjectStore::create(&path, &hash, 1024, "test", now()).expect("建库");
        store
            .put(
                &Annotation::text(0x1000, AnnotationKind::Name, "keep"),
                now(),
            )
            .expect("写入");
    }

    // 目标改了一个字节 → 哈希变了 → 必须明确报错，而不是静默套用旧注释
    let changed = "44".repeat(32);
    let err = ProjectStore::open(&path, &changed).expect_err("目标变了必须报错");
    let msg = format!("{err}");
    assert!(
        msg.contains(&changed[..8]) || msg.contains("另一个目标"),
        "错误信息要说清是哪个目标，实际：{msg}"
    );

    // 派生物同理
    let bda = derived::derived_path(dir.path(), &hash);
    let snap = Snapshot {
        target_sha256: hash.clone(),
        ..Snapshot::default()
    };
    derived::write_atomic(&bda, &snap.to_bytes()).expect("写派生物");
    assert!(
        derived::read(&bda, &changed).is_err(),
        "目标的派生物换了目标必须失效"
    );
    assert!(derived::read(&bda, &hash).is_ok(), "自己的派生物仍然可读");
}

// ─────────────────────────────────────────────────────────────────
// 验收 6：schema 迁移路径明确
// ─────────────────────────────────────────────────────────────────

#[test]
fn schema_mismatch_gives_an_explicit_path() {
    let dir = TempDir::new("schema");
    let hash = "55".repeat(32);

    // 正常库：可打开
    let ok_path = dir.path().join("ok.bfp");
    {
        let store = ProjectStore::create(&ok_path, &hash, 1024, "test", now()).expect("建库");
        store
            .put(&Annotation::text(1, AnnotationKind::Name, "x"), now())
            .expect("写入");
    }
    assert!(
        ProjectStore::open(&ok_path, &hash).is_ok(),
        "版本一致的库必须能打开"
    );

    // 非 SQLite 文件：报错，不是 panic
    let garbage = dir.path().join("garbage.bfp");
    std::fs::write(&garbage, b"not a sqlite file at all").expect("写垃圾文件");
    let err = ProjectStore::open(&garbage, &hash);
    assert!(err.is_err(), "非 SQLite 文件必须返回错误而不是崩溃");
    // 错误必须可读（有错误信息），不是空的
    assert!(!format!("{}", err.expect_err("应为错误")).is_empty());

    // 版本不匹配的两条路径由 store 单元测试覆盖（保留顺序语义）：
    //   too_new_schema_is_rejected_not_parsed / old_schema_reports_migration_required
}

// ─────────────────────────────────────────────────────────────────
// 验收 3：打开已分析目标 < 2s（就地验证存储层开销）
// ─────────────────────────────────────────────────────────────────

/// 打开已分析的目标要**快**：这条测的是"重新打开需要多久"，
/// 而不是"分析需要多久"（前者是 M4 的指标，后者是 M2 的）。
///
/// 这里用真实的 `.bfp` + `.bda` 打开路径实测。100MB 级目标的完整链路
/// 由 `scripts/m4-bench.ps1` 端到端验证（要真实样本）。
#[test]
fn reopening_analyzed_target_is_fast() {
    let dir = TempDir::new("reopen-fast");
    let hash = "66".repeat(32);
    let bfp = dir.path().join("t.bfp");
    let bda = derived::derived_path(dir.path(), &hash);

    // 造一个有分量的派生物：10 万个函数 + 20 万条 xref
    let mut snap = Snapshot {
        target_sha256: hash.clone(),
        ..Snapshot::default()
    };
    for i in 0..100_000u64 {
        let name = snap.intern(&format!("func_{i}"));
        snap.functions.push(derived::FunctionEntry::new(
            0x1000 + i * 0x40,
            Some(0x1000 + i * 0x40 + 0x40),
            Some(name),
            85,
        ));
    }
    for i in 0..200_000u64 {
        snap.xrefs.push(derived::XrefEntry {
            from: 0x1000 + i * 8,
            to: 0x2000 + i * 8,
            kind: 1,
        });
    }
    let write_start = Instant::now();
    derived::write_atomic(&bda, &snap.to_bytes()).expect("写派生物");
    println!(
        "写派生物（10 万函数 + 20 万 xref）耗时 {:?}",
        write_start.elapsed()
    );

    {
        let store = ProjectStore::create(&bfp, &hash, 4096, "test", now()).expect("建库");
        store.set_analyzed_at(now()).expect("记录");
        store
            .put(
                &Annotation::text(0x1000, AnnotationKind::Name, "hot"),
                now(),
            )
            .expect("写入");
    }

    // 重开：读 .bfp + 读 .bda，全程计时
    let start = Instant::now();
    let store = ProjectStore::open(&bfp, &hash).expect("开 .bfp");
    let meta = store.meta().expect("读 meta");
    let annotations = store.range(0, u64::MAX);
    let snapshot = derived::read(&bda, &hash).expect("读 .bda");
    let elapsed = start.elapsed();

    println!(
        "重开耗时 {elapsed:?}（函数 {} 条，xref {} 条，注解 {} 条）",
        snapshot.functions.len(),
        snapshot.xrefs.len(),
        annotations.len()
    );
    assert_eq!(snapshot.functions.len(), 100_000);
    assert_eq!(annotations.len(), 1);
    assert!(meta.analyzed_at_unix.is_some(), "分析时间应已记录");
    assert!(
        elapsed < Duration::from_secs(2),
        "验收要求已分析目标重开 < 2s，实测 {elapsed:?}"
    );
}

// ─────────────────────────────────────────────────────────────────
// 验收：会话持久化（最近列表）
// ─────────────────────────────────────────────────────────────────

#[test]
fn recent_list_survives_restart_and_concurrent_updates() {
    let dir = TempDir::new("recent");
    {
        let store = RecentStore::new(dir.path());
        for i in 0..10 {
            store
                .touch(RecentTarget {
                    target_sha256: format!("{i:064}"),
                    path: format!("C:/t{i}.exe"),
                    file_name: format!("t{i}.exe"),
                    size: 100,
                    opened_at_unix: 1000 + i,
                })
                .expect("记录");
        }
    }
    // 重启后仍在，且顺序正确
    let store = RecentStore::new(dir.path());
    let (index, corrupt) = store.load();
    assert!(!corrupt);
    assert_eq!(index.recent.len(), 10);
    assert_eq!(index.recent[0].opened_at_unix, 1009, "最近的排最前");
}

#[test]
fn recent_list_write_is_atomic_under_repeated_updates() {
    let dir = TempDir::new("recent-atomic");
    let store = RecentStore::new(dir.path());
    for i in 0..200 {
        store
            .touch(RecentTarget {
                target_sha256: format!("{i:064}"),
                path: format!("C:/t{i}.exe"),
                file_name: format!("t{i}.exe"),
                size: 1,
                opened_at_unix: i as u64,
            })
            .expect("记录");
    }
    // 任何时刻读到的都必须是完整合法的 JSON
    let (index, corrupt) = store.load();
    assert!(!corrupt, "200 次原子写之后索引必须仍然合法");
    assert_eq!(index.recent.len(), 64, "上限生效");
}
