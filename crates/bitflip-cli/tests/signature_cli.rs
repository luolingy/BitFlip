//! `signature` 子命令的端到端测试：真的写文件、真的读回来。
//!
//! 这里断言的重点不是"打印得好看"，而是三件会影响用户资产的事：
//!
//! 1. 生成出来的签名文件能被**原样读回**（格式版本、形态、条数都对得上）；
//! 2. 已经存在的签名文件**不会**被悄悄覆盖；
//! 3. 产不出任何签名时**报错**，而不是写一个空文件让人以为成功了。

use std::path::PathBuf;

use bitflip_cli::{
    run_signature, SignatureArgs, SignatureBuildArgs, SignatureCommand, SignatureInfoArgs,
};
use bitflip_signature::{SignatureSet, SIGNATURE_FORMAT_VERSION};

fn fixture(name: &str) -> PathBuf {
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../tests/fixtures/generated")
        .join(name);
    assert!(path.exists(), "缺少 fixture：{}", path.display());
    path
}

fn build(inputs: Vec<PathBuf>, out: PathBuf, force: bool) -> anyhow::Result<()> {
    run_signature(&SignatureArgs {
        command: SignatureCommand::Build(SignatureBuildArgs {
            inputs,
            out,
            force,
            json: false,
        }),
    })
}

#[test]
fn building_a_signature_file_from_a_fixture_archive_round_trips() {
    let dir = tempfile::tempdir().expect("临时目录");
    let out = dir.path().join("fixture.sig.json");

    build(vec![fixture("libpe-x86_64.a")], out.clone(), false).expect("生成签名");

    let text = std::fs::read_to_string(&out).expect("读回签名文件");
    let set = SignatureSet::from_json(&text).expect("签名文件应当能被本程序读回");
    assert_eq!(set.format_version, SIGNATURE_FORMAT_VERSION);
    assert_eq!(set.len(), 2, "fixture 归档实测产出 2 条签名");
    assert_eq!(set.stats.objects, 1, "归档里只有 1 个对象成员");
    assert_eq!(set.stats.metadata_members, 1, "另有 1 个符号索引成员");
    let names: Vec<&str> = set
        .signatures
        .iter()
        .map(|signature| signature.name.as_str())
        .collect();
    assert_eq!(names, vec!["bf_entry", "bf_loop"]);
    assert_eq!(set.arches().len(), 1, "fixture 只有一种形态");
    assert_eq!(set.arches()[0].bits, 64);

    // `info` 也要能读回来（它走的是同一条加载路径，失败会返回 Err）。
    run_signature(&SignatureArgs {
        command: SignatureCommand::Info(SignatureInfoArgs {
            file: out.clone(),
            count: 5,
            json: false,
        }),
    })
    .expect("查看签名文件");
}

#[test]
fn an_existing_signature_file_is_not_overwritten_without_force() {
    let dir = tempfile::tempdir().expect("临时目录");
    let out = dir.path().join("keep.sig.json");
    std::fs::write(&out, "已有的内容，不许被清掉").expect("写占位文件");

    let error = build(vec![fixture("libpe-x86_64.a")], out.clone(), false)
        .expect_err("不加 --force 不该覆盖已有文件");
    let text = format!("{error:#}");
    assert!(text.contains("--force"), "错误里要给出做法：{text}");
    assert_eq!(
        std::fs::read_to_string(&out).expect("原有文件"),
        "已有的内容，不许被清掉",
        "被拒绝之后文件必须原样不动"
    );

    build(vec![fixture("libpe-x86_64.a")], out.clone(), true).expect("加 --force 才允许覆盖");
    let set = SignatureSet::from_json(&std::fs::read_to_string(&out).expect("读回")).expect("解析");
    assert_eq!(set.len(), 2);
}

#[test]
fn an_input_that_yields_nothing_is_an_error_not_an_empty_file() {
    let dir = tempfile::tempdir().expect("临时目录");
    let out = dir.path().join("empty.sig.json");

    // 已链接映像上的符号位置约定无法可靠区分，生成期会整体拒绝（并记账）。
    let error = build(
        vec![fixture("m3-mingw-static.unstripped.exe")],
        out.clone(),
        false,
    )
    .expect_err("产不出签名时应当报错");
    let text = format!("{error:#}");
    assert!(
        text.contains("没有产出签名"),
        "错误要说清是「一条都没有」，而不是写个空文件：{text}"
    );
    assert!(!out.exists(), "报错时不该留下文件");
}

#[test]
fn a_missing_input_is_reported_by_name() {
    let dir = tempfile::tempdir().expect("临时目录");
    let missing = dir.path().join("不存在.a");
    let error = build(vec![missing.clone()], dir.path().join("x.sig.json"), false)
        .expect_err("输入不存在应当报错");
    let text = format!("{error:#}");
    assert!(text.contains("不存在.a"), "错误里要指出是哪个输入：{text}");
}
