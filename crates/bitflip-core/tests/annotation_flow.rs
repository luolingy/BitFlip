//! M3 标注写入路径的验收测试。
//!
//! 这一组测试盯的是 M4 数据设计的核心承诺（docs/DECISIONS.md D2）：
//! **用户标注是主数据，分析结果是可重建的派生物**。承诺只有在下面三件事
//! 同时成立时才算兑现，少一条就等于退回到参照实现的老毛病：
//!
//! 1. 改名/加注释**不触发重新分析**（否则大目标上改个名要等几秒到几十秒）；
//! 2. 重新分析**不丢标注**（否则用户不敢重新分析）；
//! 3. 换一个同名但内容不同的文件，**标注不能被复用**（否则张冠李戴）。
//!
//! 第 3 条是最容易被忽略、后果最严重的一条：用 size+mtime 做目标身份时，
//! 复制/覆盖文件容易撞上，用户会看到别人的函数名。

use bitflip_core::{OpenOptions, Session};
use bitflip_project::{Annotation, AnnotationKind, ProjectStore};

/// 拿一个真实存在的可分析目标（cargo 测试进程自身）。
fn target_exe() -> std::path::PathBuf {
    std::env::current_exe().expect("当前测试可执行文件路径")
}

/// 固定时间戳：测试不该依赖真实时钟（否则结果不可复现）。
const T0: u64 = 1_700_000_000;

fn annotation(addr: u64, kind: AnnotationKind, text: &str) -> Annotation {
    Annotation {
        address: addr,
        kind,
        text: Some(text.to_string()),
        patch_hex: None,
    }
}

#[test]
fn rename_persists_without_reanalysis() {
    let exe = target_exe();
    let ws = tempfile::tempdir().expect("临时工作区");

    let session = Session::open(&exe, OpenOptions::default()).expect("打开目标");
    let hash = session.target_hash().expect("算哈希").to_string();

    {
        let store = session.open_project(ws.path()).expect("打开工程库");
        let a = annotation(0x401000, AnnotationKind::Name, "my_rename");
        store.put(&a, T0).expect("写入标注");
        assert_eq!(store.get(0x401000, AnnotationKind::Name), Some(a));
    }

    // "不触发重新分析"的可观测判据：工程库的 analyzed_at 从未被写入。
    let store = ProjectStore::open(&bitflip_project::primary_path(ws.path(), &hash), &hash)
        .expect("重开工程库");
    let meta = store.meta().expect("元数据");
    assert!(
        meta.analyzed_at_unix.is_none(),
        "只改标注不该写 analyzed_at —— 那意味着重新分析被触发了"
    );

    // 而且标注确实落盘了（不是在内存里）
    assert_eq!(
        store.get(0x401000, AnnotationKind::Name),
        Some(annotation(0x401000, AnnotationKind::Name, "my_rename"))
    );
}

#[test]
fn reanalysis_does_not_lose_annotations() {
    let exe = target_exe();
    let ws = tempfile::tempdir().expect("临时工作区");

    let session = Session::open(&exe, OpenOptions::default()).expect("打开");
    let hash = session.target_hash().expect("哈希").to_string();

    let annotations = vec![
        annotation(0x401000, AnnotationKind::Name, "renamed_fn"),
        annotation(0x401000, AnnotationKind::Comment, "这里有个奇怪的分支"),
        annotation(0x401100, AnnotationKind::Bookmark, "todo"),
        annotation(0x402000, AnnotationKind::FunctionBoundary, "手工边界"),
    ];
    {
        let store = session.open_project(ws.path()).expect("工程库");
        for a in &annotations {
            store.put(a, T0).expect("写入");
        }
    }

    // 模拟"重新分析完成"：写入 analyzed_at，并写一份派生物快照。
    // 标注必须一条不少 —— 这正是把两者分库的意义。
    {
        let store = session.open_project(ws.path()).expect("工程库");
        store.set_analyzed_at(12345).expect("标记分析时间");
        let snapshot = bitflip_project::Snapshot {
            target_sha256: hash.clone(),
            functions: vec![],
            xrefs: vec![],
            strings: vec![],
            names: vec![],
        };
        let bytes = snapshot.to_bytes();
        bitflip_project::write_atomic(&bitflip_project::derived_path(ws.path(), &hash), &bytes)
            .expect("写派生物");
    }

    let store = session.open_project(ws.path()).expect("工程库");
    for a in &annotations {
        assert_eq!(
            store.get(a.address, a.kind),
            Some(a.clone()),
            "重新分析后标注 {:?}@{:#x} 丢了",
            a.kind,
            a.address
        );
    }
    assert_eq!(store.meta().expect("meta").analyzed_at_unix, Some(12345));
}

/// 同名但内容不同的文件必须是**不同目标**，不能复用标注。
///
/// 这是"用内容哈希而不是 size+mtime"的直接理由。构造方式：把当前 exe
/// 复制一份，改掉中间一个字节（大小完全不变）—— size+mtime 方案在
/// 某些时序下会判成同一个文件，内容哈希不会。
#[test]
fn same_size_different_content_is_a_different_target() {
    let exe = target_exe();
    let ws = tempfile::tempdir().expect("临时工作区");

    let dir = tempfile::tempdir().expect("样本目录");
    let copy = dir.path().join("copy.exe");
    let mut data = std::fs::read(&exe).expect("读 exe");
    assert!(data.len() > 1024, "exe 太小，改一个字节不足以构成测试");
    let original_len = data.len();
    // 改中间一个字节：文件长度不变，内容变了
    let mid = data.len() / 2;
    data[mid] = data[mid].wrapping_add(1);
    std::fs::write(&copy, &data).expect("写副本");
    assert_eq!(
        std::fs::metadata(&copy).expect("stat").len(),
        original_len as u64,
        "副本必须与原文件等长，否则这个测试不成立"
    );

    let h1 = Session::open(&exe, OpenOptions::default())
        .expect("打开原文件")
        .target_hash()
        .expect("哈希1")
        .to_string();
    let h2 = Session::open(&copy, OpenOptions::default())
        .expect("打开副本")
        .target_hash()
        .expect("哈希2")
        .to_string();

    assert_ne!(
        h1, h2,
        "大小相同、内容不同，哈希必须不同 —— 否则会拿到别人的标注"
    );

    // 写进原文件对应的工程库，然后确认副本读不到它
    {
        let session = Session::open(&exe, OpenOptions::default()).expect("打开");
        session
            .open_project(ws.path())
            .expect("工程库")
            .put(
                &annotation(0x401000, AnnotationKind::Name, "original_only"),
                T0,
            )
            .expect("写入");
    }

    let copy_session = Session::open(&copy, OpenOptions::default()).expect("打开副本");
    let copy_store = copy_session.open_project(ws.path()).expect("副本工程库");
    assert_eq!(
        copy_store.get(0x401000, AnnotationKind::Name),
        None,
        "内容不同的文件读到了原文件的标注 —— 目标身份判定错了"
    );
}

/// 哈希必须是定长小写十六进制，且确实是 64 个字符（sha256）。
///
/// 定长小写是 wire 契约（CLAUDE.md §4）；`.bda`/`.bfp` 的文件名与
/// 元数据都依赖它，格式一旦漂移会让已有工程库全部失配。
#[test]
fn hash_is_lowercase_hex_and_fixed_length() {
    let exe = target_exe();
    let session = Session::open(&exe, OpenOptions::default()).expect("打开");
    let hash = session.target_hash().expect("哈希");

    assert_eq!(hash.len(), 64, "sha256 的十六进制应是 64 字符：{hash}");
    assert!(
        hash.chars()
            .all(|c| c.is_ascii_hexdigit() && !c.is_ascii_uppercase()),
        "哈希必须是小写十六进制：{hash}"
    );
}

/// 哈希在同一目标上必须稳定（缓存不能改变结果语义）。
#[test]
fn hash_is_stable_across_calls_and_sessions() {
    let exe = target_exe();
    let s1 = Session::open(&exe, OpenOptions::default()).expect("打开");
    let a = s1.target_hash().expect("哈希").to_string();
    let b = s1.target_hash().expect("哈希").to_string();
    assert_eq!(a, b, "同一会话内两次哈希必须一致");

    let s2 = Session::open(&exe, OpenOptions::default()).expect("重开");
    assert_eq!(
        a,
        s2.target_hash().expect("哈希"),
        "跨会话哈希必须一致，否则工程库每次都会失配"
    );
}

/// 已知输入的哈希必须是确定值（锁住实现，防止换算法悄悄失配）。
#[test]
fn known_vector_matches_sha256() {
    // sha256("") = e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855
    assert_eq!(
        bitflip_project::target_hash_bytes(b""),
        "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
    );
    // sha256("abc") = ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad
    assert_eq!(
        bitflip_project::target_hash_bytes(b"abc"),
        "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
    );
}

/// 大文件的哈希要分块读，不能一次性读进内存。
///
/// 这里不做精密的峰值内存测量（那种测试在不同平台上不稳定），
/// 而是验证**行为正确性**：跨越 1 MiB 分块边界的文件哈希必须与
/// 一次性计算的结果一致 —— 分块读的典型 bug 就是漏掉最后一块。
#[test]
fn large_file_hash_handles_chunk_boundary() {
    let dir = tempfile::tempdir().expect("临时目录");
    // 故意取 1 MiB 的整数倍 +1：覆盖"最后一块不足"与"正好整块"两种边界
    let size = (1 << 20) + 1;
    let data: Vec<u8> = (0..size).map(|i| (i % 251) as u8).collect();
    let path = dir.path().join("large.bin");
    std::fs::write(&path, &data).expect("写入");

    let streamed = bitflip_project::target_hash(&path).expect("分块哈希");
    let oneshot = bitflip_project::target_hash_bytes(&data);
    assert_eq!(
        streamed, oneshot,
        "分块读的哈希与一次性计算不一致 —— 多半是漏了最后一块"
    );
}
