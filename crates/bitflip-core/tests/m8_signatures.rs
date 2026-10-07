//! M8 验收测试：签名库把**剥离**目标上的函数名找回来。
//!
//! 这份测试不依赖本机装了什么 mingw：签名由 fixture 目标**自己的字节**现场合成
//! （名与地址取自 strip 之前的 `objdump` 真值文件）。验的是这条通路：
//!
//! ```text
//! 签名文件 → Session::open（加载 + 形态匹配）→ 分析（字节比对 → 候选）→ wire 来源
//! ```
//!
//! 库指纹**质量**（真实静态库 → 真实剥离 exe 的召回/误报）不是这里能负责的：
//! 那要跑 `scripts/m8-signature-acceptance.ps1`（需要本机 mingw），结论记在
//! `docs/PLAN.md` §M8。这里管的是"名字从哪来、说不清的时候说不清"。
//!
//! 样本不在时**跳过并说明原因**，不假装通过（与 `m3_acceptance.rs` 同一约定）。

use std::path::{Path, PathBuf};

use bitflip_core::{OpenOptions, Session};
use bitflip_signature::{
    signature_arch, FunctionSignature, GenerationStats, Pattern, SignatureArch, SignatureSet,
    SIGNATURE_FORMAT_VERSION,
};

fn fixture(name: &str) -> PathBuf {
    let mut path = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    path.pop(); // crates/bitflip-core -> crates
    path.pop(); // crates -> 仓库根
    path.push("tests/fixtures/generated");
    path.push(name);
    path
}

/// 剥离目标 + 它的真值函数表（`<地址>:<名字>`，地址是绝对 VA）。
fn sample() -> Option<(PathBuf, Vec<(u64, String)>)> {
    let exe = fixture("m3-mingw-static.exe");
    let truth = fixture("m3-mingw-static.funcs.txt");
    if !exe.exists() || !truth.exists() {
        eprintln!(
            "跳过：样本 {} 或真值 {} 不存在，请先跑 scripts/gen-m3-coverage-sample.ps1",
            exe.display(),
            truth.display()
        );
        return None;
    }
    let text = std::fs::read_to_string(&truth).expect("读真值文件");
    let mut functions = Vec::new();
    for line in text.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let Some((addr, name)) = line.split_once(':') else {
            continue;
        };
        if let Ok(value) = u64::from_str_radix(addr.trim_start_matches("0x"), 16) {
            functions.push((value, name.trim().to_string()));
        }
    }
    functions.sort_by_key(|(addr, _)| *addr);
    if functions.is_empty() {
        eprintln!("跳过：真值文件里没有函数");
        return None;
    }
    Some((exe, functions))
}

/// 合成一条签名：名与地址取自真值，字节取自目标镜像。
///
/// `length` 用目标自己给出的函数大小（`.pdata` 的展开范围是精确边界），
/// 前缀取该大小的前 24 字节 —— 与生成器在"有确切大小"时的行为一致。
fn signature_from(session: &Session, addr: u64, name: &str, length: u32) -> FunctionSignature {
    let size = usize::try_from(length).expect("长度");
    let want = size.min(24);
    let bytes = session.read_virtual(addr, want).expect("读目标字节");
    assert_eq!(bytes.len(), want, "函数 {name} 的字节读不全");
    let prefix = Pattern::exact(&bytes);
    assert!(prefix.exact_count() >= 8, "前缀太短，本就该被生成器丢掉");
    FunctionSignature {
        name: name.to_string(),
        arch: signature_arch(&session.object().expect("对象").arch),
        length,
        length_exact: true,
        prefix,
        tail: None,
        exact_bytes: u16::try_from(want).expect("字节数"),
    }
}

/// 把签名写成一个签名库文件，返回文件路径。
fn write_library(dir: &Path, signatures: Vec<FunctionSignature>) -> PathBuf {
    let set = SignatureSet {
        format_version: SIGNATURE_FORMAT_VERSION,
        tool: "bitflip-core 测试".to_string(),
        stats: GenerationStats::default(),
        signatures,
    };
    let path = dir.join("test.sig.json");
    std::fs::write(&path, set.to_json(true).expect("序列化签名库")).expect("写签名库");
    path
}

/// 打开目标并建立分析。
fn analyze(path: &Path, signatures: Option<PathBuf>) -> Session {
    let session = Session::open(
        path,
        OpenOptions {
            signatures,
            ..OpenOptions::default()
        },
    )
    .expect("打开目标");
    let _ = session.analysis(&session.detached_job()).expect("建立分析");
    session
}

/// 取某个地址的函数结论（`start` 是定长 hex，比一遍地址）。
fn function_at(session: &Session, addr: u64) -> Option<(String, String, String, bool)> {
    let analysis = session.analysis(&session.detached_job()).expect("分析");
    analysis
        .functions()
        .iter()
        .find(|f| bitflip_core::parse_address(&f.start) == Some(addr))
        .map(|f| {
            (
                f.name.clone(),
                f.source.clone(),
                f.source_label.clone(),
                f.named,
            )
        })
}

#[test]
fn signature_library_names_functions_on_a_stripped_target() {
    let Some((exe, truth)) = sample() else {
        return;
    };

    // 没有签名库时：目标彻底剥离，这些地址必须是"未识别"（不许有占位名）。
    let bare = analyze(&exe, None);
    let bare_notes: Vec<String> = bare.info().notes.clone();
    assert!(
        !bare_notes.iter().any(|note| note.contains("签名库")),
        "没给签名库就不该提签名库：{bare_notes:?}"
    );

    // 挑三个函数：目标**自己说**足够大的那些（`.pdata` 的展开范围是精确的函数边界）。
    // 1 字节的桩函数里塞不下 16 字节的指纹 —— 匹配器的"装不下就排除"本来就该在
    // 那样的函数上生效（那一条由 `bitflip-signature` 的单元测试管）。
    let bare_analysis = bare.analysis(&bare.detached_job()).expect("分析");
    let sizes: std::collections::BTreeMap<u64, u64> = bare_analysis
        .functions()
        .iter()
        .filter_map(|f| Some((bitflip_core::parse_address(&f.start)?, f.size?)))
        .collect();
    let picked: Vec<(u64, String, u32)> = truth
        .iter()
        .filter_map(|(addr, name)| {
            let size = sizes.get(addr).copied()?;
            (size >= 16).then(|| (*addr, name.clone(), u32::try_from(size).expect("大小")))
        })
        .take(3)
        .collect();
    assert_eq!(picked.len(), 3, "真值里应当能找到三个足够大的函数");

    for (addr, _name, _) in &picked {
        let found = function_at(&bare, *addr);
        let found = found.expect("剥离目标里该地址应当是已识别函数（来自 .pdata）");
        assert!(
            !found.3 && found.0.is_empty(),
            "没有签名库时不许出现假名：{addr:#x} → {found:?}"
        );
    }

    // 加上签名库：同样的地址必须拿到真值里的名字，来源是"签名库"。
    let dir = tempfile::tempdir().expect("临时目录");
    let signatures = picked
        .iter()
        .map(|(addr, name, size)| signature_from(&bare, *addr, name, *size))
        .collect();
    let library = write_library(dir.path(), signatures);

    let named = analyze(&exe, Some(library));
    let notes: Vec<String> = named.info().notes.clone();
    assert!(
        notes.iter().any(|note| note.contains("签名库")),
        "用了签名库就要在说明里写清楚：{notes:?}"
    );

    for (addr, name, _) in &picked {
        let found = function_at(&named, *addr).expect("函数结论");
        assert_eq!(found.0, *name, "{addr:#x} 的名字应当来自签名库");
        assert_eq!(found.1, "signature", "{addr:#x} 的来源记号");
        assert_eq!(found.2, "签名库", "{addr:#x} 的来源中文名");
        assert!(found.3, "{addr:#x} 应当算「有名字」");
    }

    // 账目要对得上，而且**集合要完全相等**：这三个地址该被认出来，
    // 其它地址一个都不该被签名的名字沾上（多出来就是假阳性）。
    let analysis = named.analysis(&named.detached_job()).expect("分析");
    let report = analysis.signatures().expect("用了签名库就该有账目");
    let mut named_by_signature: Vec<u64> = analysis
        .functions()
        .iter()
        .filter(|f| f.source == "signature")
        .filter_map(|f| bitflip_core::parse_address(&f.start))
        .collect();
    named_by_signature.sort_unstable();
    let mut expected: Vec<u64> = picked.iter().map(|(addr, _, _)| *addr).collect();
    expected.sort_unstable();
    assert_eq!(
        named_by_signature, expected,
        "签名库认出的地址集合必须与预期完全一致（多一个就是假阳性）"
    );
    assert_eq!(report.matched, expected.len());
    assert!(
        report.checked >= u64::try_from(expected.len()).expect("个数"),
        "比对过的候选数不该少于认出的个数：{report:?}"
    );
}

#[test]
fn unusable_signature_files_are_reported_not_silently_skipped() {
    let Some((exe, _)) = sample() else {
        return;
    };
    let dir = tempfile::tempdir().expect("临时目录");

    // 1) 文件不存在：报错里要指名道姓，否则用户只能猜。
    let missing = dir.path().join("没有这个文件.json");
    let error = Session::open(
        &exe,
        OpenOptions {
            signatures: Some(missing.clone()),
            ..OpenOptions::default()
        },
    )
    .expect_err("签名库不存在时应当报错");
    let text = error.to_string();
    assert!(
        text.contains("没有这个文件.json"),
        "报错要指出是哪个文件：{text}"
    );

    // 2) 内容不是签名库：报"解析失败"，不能当成"没有可用签名"。
    let broken = dir.path().join("broken.json");
    std::fs::write(&broken, "{\"format_version\": 1, \"不是\": \"签名库\"}").expect("写坏文件");
    let error = Session::open(
        &exe,
        OpenOptions {
            signatures: Some(broken),
            ..OpenOptions::default()
        },
    )
    .expect_err("坏签名库应当报错");
    assert!(
        error.to_string().contains("签名库解析失败"),
        "报错要说清是解析失败：{error}"
    );

    // 3) 版本不符：签名是本地生成的派生物，没有迁移路径 —— 要让人去重新生成。
    let old = dir.path().join("old.json");
    let mut set = SignatureSet {
        format_version: SIGNATURE_FORMAT_VERSION,
        tool: "旧版本".to_string(),
        stats: GenerationStats::default(),
        signatures: Vec::new(),
    };
    set.format_version = SIGNATURE_FORMAT_VERSION - 1;
    std::fs::write(&old, set.to_json(false).expect("序列化")).expect("写旧版本文件");
    let error = Session::open(
        &exe,
        OpenOptions {
            signatures: Some(old),
            ..OpenOptions::default()
        },
    )
    .expect_err("版本不符应当报错");
    assert!(
        error.to_string().contains("重新生成"),
        "版本不符要给出修复动作：{error}"
    );
}

#[test]
fn a_library_for_another_arch_is_reported_and_names_nothing() {
    let Some((exe, truth)) = sample() else {
        return;
    };
    let dir = tempfile::tempdir().expect("临时目录");

    // 拿 fixture 的字节，但把形态标成一份 **32 位大端 ARM** 的签名：
    // 字节一模一样，只是"不是这个目标那一路货"。
    let bare = analyze(&exe, None);
    let (addr, name) = truth
        .iter()
        .find(|(addr, _)| bare.read_virtual(*addr, 16).is_ok())
        .cloned()
        .expect("真值里该有函数");
    let mut signature = signature_from(&bare, addr, &name, 16);
    signature.arch = SignatureArch::new(32, "be", "arm");
    let library = write_library(dir.path(), vec![signature]);

    let session = analyze(&exe, Some(library));
    let notes = session.info().notes.clone();
    assert!(
        notes
            .iter()
            .any(|note| note.contains("没有适配本目标形态的签名")),
        "形态对不上必须明说，不能装作用过：{notes:?}"
    );
    let found = function_at(&session, addr).expect("函数结论");
    assert!(found.0.is_empty(), "形态对不上时不该命名任何一个函数");
    let analysis = session.analysis(&session.detached_job()).expect("分析");
    assert!(
        analysis.signatures().is_none(),
        "根本没跑签名比对时不该有账目（否则界面会显示「用了 0 个」）"
    );
}
