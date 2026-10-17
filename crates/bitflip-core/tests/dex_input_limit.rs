//! 单文件 `.dex` 的大小上限：**读之前**按文件大小拒绝，而不是读完再报。
//!
//! 为什么单独一条测试：这个上限的全部价值在于"不要先把 3 GB 读进内存再说话"。
//! 写成"读完再判"也能让功能测试通过，但那时内存已经吃掉了 —— 那种实现只能靠
//! 计时/内存观测才看得出一半，所以这里同时断言**报错内容**与**耗时**。
//!
//! APK 里那条路本来就有上限（先看中央目录里声明的解压后大小，256 MiB）。
//! 单文件这条路此前没有，于是"同一份内容、两种容器、两种行为"。这里对齐。

use std::path::PathBuf;
use std::time::{Duration, Instant};

use bitflip_core::{dex, BitflipError, OpenOptions, Session};

// 与 loader / CLI / server 测试共用的合成样本（这里只用得到 `build()`）。
#[path = "../../bitflip-loader/tests/common/dex_fixture.rs"]
#[allow(dead_code)]
mod fixture;

const LIMIT: usize = bitflip_loader::MAX_DEX_BYTES;

/// 造一个"头是真的、长度超限"的**稀疏**文件：写满 256 MiB 只会让这条测试比它
/// 验证的东西还贵，而且磁盘上真会占那么多。
fn huge_dex(dir: &tempfile::TempDir) -> PathBuf {
    use std::io::Write;

    let path = dir.path().join("huge.dex");
    let mut file = std::fs::File::create(&path).expect("建临时文件");
    file.write_all(&fixture::build()).expect("写 DEX 头");
    file.set_len((LIMIT + 1) as u64)
        .expect("把长度拉到上限 + 1");
    file.flush().expect("落盘");
    path
}

#[test]
fn a_single_file_dex_over_the_ceiling_is_refused_without_being_read() {
    let dir = tempfile::tempdir().expect("临时目录");
    let path = huge_dex(&dir);
    // 先确认它**确实是**一个能被认出来的 DEX：否则这条测试会退化成
    // "不是 DEX 所以报错"，看着绿、其实没测到上限。
    let session = Session::open(&path, OpenOptions::default()).expect("按内容应当识别为 DEX");

    let started = Instant::now();
    let error = match dex::read_input(&session, None) {
        Ok(_) => panic!("{} 超过上限，却被读进来了", path.display()),
        Err(error) => error,
    };
    let elapsed = started.elapsed();

    let text = error.to_string();
    assert!(
        text.contains("超过单份 DEX 的上限"),
        "报错要说清是哪条上限，而不是笼统的读取失败：{text}"
    );
    assert!(
        text.contains(&LIMIT.to_string()),
        "报错要带出上限本身（{LIMIT}），否则用户无从判断该不该切开：{text}"
    );
    assert!(
        matches!(error, BitflipError::InvalidInput(_)),
        "这是输入问题，不是我们的 bug：{error:?}"
    );
    assert!(
        elapsed < Duration::from_secs(5),
        "拒绝用了 {elapsed:?}：看起来是先读了再判"
    );
}

#[test]
fn a_dex_under_the_ceiling_is_read_normally() {
    // 反向对照：上限不能把正常文件也挡了。样本只有几百字节。
    let dir = tempfile::tempdir().expect("临时目录");
    let path = dir.path().join("classes.dex");
    std::fs::write(&path, fixture::build()).expect("写合成样本");
    let session = Session::open(&path, OpenOptions::default()).expect("打开合成样本");

    let input = dex::read_input(&session, None).expect("上限以内必须能读");
    assert_eq!(input.structure.classes.len(), 1);
    assert_eq!(input.bytes.len(), fixture::build().len());
}
