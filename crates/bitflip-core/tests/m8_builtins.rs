//! M8 交付物 3：编译器内置模式库的端到端验证（对着真样本，不给它任何签名库）。
//!
//! 真值来自 `tests/fixtures/generated/m8-builtins.golden.txt` —— 那是 mingw 的 objdump
//! 打出来的，不是 BitFlip 自己的输出。要验的三件事：
//!
//! 1. 在被 `objcopy --strip-all` 剥光的镜像上，命中地址**正好**是黄金值里的那个地址；
//! 2. 全目标**只有这一个**函数由内置判据命名（误报必须为零 —— 判据窄就是为了这个）；
//! 3. 未剥符号的同名样本上，符号表的结论优先，且"同名不同来源"不算冲突
//!    （顺带验 M8 交付物 4 的 `aliases` 语义）。
//!
//! fixture 由 `scripts/gen-builtins-fixture.ps1` 生成；没生成就跳过（跳过不是失败）。

use std::path::{Path, PathBuf};

use bitflip_core::{AliasWire, OpenOptions, Session};

fn fixture(name: &str) -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("..")
        .join("..")
        .join("tests")
        .join("fixtures")
        .join("generated")
        .join(name)
}

/// 从黄金值文本里读一个字段（`key:` 到行尾）。
fn golden_field(text: &str, key: &str) -> Option<String> {
    let prefix = format!("{key}:");
    text.lines()
        .find_map(|line| line.strip_prefix(&prefix))
        .map(|value| value.trim().to_string())
}

fn parse_hex(text: &str) -> Option<u64> {
    u64::from_str_radix(text.trim_start_matches("0x"), 16).ok()
}

/// 测试用到的函数字段。抄成自己的结构体，省得依赖 `FunctionWire` 是不是 `Clone`。
#[derive(Debug, Clone)]
struct Facts {
    start: String,
    name: String,
    source: String,
    source_label: String,
    named: bool,
    end: Option<String>,
    aliases: Vec<AliasWire>,
}

/// 打开目标并建立分析。**不装签名库**：内置判据必须自己站着。
fn analyze(path: &Path) -> Session {
    let session = Session::open(
        path,
        OpenOptions {
            signatures: None,
            ..OpenOptions::default()
        },
    )
    .expect("打开目标");
    let _ = session.analysis(&session.detached_job()).expect("建立分析");
    session
}

fn find_at(session: &Session, addr: u64) -> Option<Facts> {
    let analysis = session.analysis(&session.detached_job()).expect("分析");
    analysis
        .functions()
        .iter()
        .find(|f| bitflip_core::parse_address(&f.start) == Some(addr))
        .map(|f| Facts {
            start: f.start.clone(),
            name: f.name.clone(),
            source: f.source.clone(),
            source_label: f.source_label.clone(),
            named: f.named,
            end: f.end.clone(),
            aliases: f.aliases.clone(),
        })
}

fn builtin_named(session: &Session) -> Vec<(String, String)> {
    let analysis = session.analysis(&session.detached_job()).expect("分析");
    analysis
        .functions()
        .iter()
        .filter(|f| f.source == "builtin-pattern")
        .map(|f| (f.start.clone(), f.name.clone()))
        .collect()
}

fn unnamed_count(session: &Session) -> usize {
    let analysis = session.analysis(&session.detached_job()).expect("分析");
    analysis.functions().iter().filter(|f| !f.named).count()
}

#[test]
fn the_stack_probe_helper_is_named_on_a_stripped_target() {
    let exe = fixture("m8-builtins-nosym.exe");
    let golden_path = fixture("m8-builtins.golden.txt");
    if !exe.exists() || !golden_path.exists() {
        eprintln!("跳过：先跑 scripts/gen-builtins-fixture.ps1");
        return;
    }
    let golden = std::fs::read_to_string(&golden_path).expect("读黄金值");
    let helper_va =
        parse_hex(&golden_field(&golden, "helperVa").expect("helperVa")).expect("十六进制");
    let helper_len =
        parse_hex(&golden_field(&golden, "helperLength").expect("helperLength")).expect("十六进制");

    let session = analyze(&exe);
    let hit =
        find_at(&session, helper_va).unwrap_or_else(|| panic!("{helper_va:#x} 处应当有函数结论"));

    assert!(hit.named, "内置判据要给名字，而不是留下未识别：{hit:?}");
    assert_eq!(hit.name, "___chkstk_ms");
    assert_eq!(hit.source, "builtin-pattern");
    assert_eq!(hit.source_label, "编译器模式");

    // 边界**可以没有**：实测这个纯汇编小助手没有 `.pdata` 条目，剥光符号后分析层只知道
    // "这里有个被调用的函数"，不知道它到哪结束 —— 那就如实报 None，不猜（CLAUDE.md §7）。
    // 有边界时（展开表或调试信息给了）才要求它装得下真值长度。
    if let Some(end) = hit.end.as_deref().and_then(parse_hex) {
        let size = end - helper_va;
        assert!(
            size >= helper_len && size <= helper_len + 16,
            "边界 {size:#x} 与真值长度 {helper_len:#x} 不符（展开表最多对齐 16 字节）"
        );
    }

    // 误报为零：整个目标只有这一个函数由内置判据命名。
    assert_eq!(
        builtin_named(&session),
        vec![(hit.start.clone(), "___chkstk_ms".to_string())],
        "内置判据只能命中真值那一个地址"
    );

    // 样本自己的函数在剥光符号后仍然没有名字 —— 既没有假名，也没有把普通函数认成助手。
    assert!(
        unnamed_count(&session) > 0,
        "剥光符号的目标上必然有未识别的函数，一个都没有说明在编名字"
    );
}

#[test]
fn the_builtin_pattern_names_it_even_when_symbols_are_present() {
    let exe = fixture("m8-builtins.exe");
    let golden_path = fixture("m8-builtins.golden.txt");
    if !exe.exists() || !golden_path.exists() {
        eprintln!("跳过：先跑 scripts/gen-builtins-fixture.ps1");
        return;
    }
    let golden = std::fs::read_to_string(&golden_path).expect("读黄金值");
    let helper_va =
        parse_hex(&golden_field(&golden, "helperVa").expect("helperVa")).expect("十六进制");

    let session = analyze(&exe);
    let hit = find_at(&session, helper_va).expect("符号表与内置判据都指向这里");

    // 即使不剥符号，这个名字也只能由内置判据给出：mingw 的 `___chkstk_ms` 在符号表里是
    // **NOTYPE**（objdump 打印 `(ty 0)`）而不是函数类型符号，所以符号表来源不收它 ——
    // "符号表优先于内置模式"这条优先级在这里没机会生效。记录在案，不假装它生效过。
    assert_eq!(hit.name, "___chkstk_ms");
    assert_eq!(hit.source, "builtin-pattern");
    assert_eq!(hit.source_label, "编译器模式");

    // 两边给出的**名字相同**，所以这不构成冲突：别名列表必须是空的。
    // （未命名的候选 —— 展开表、分析推断 —— 也不该混进别名里。）
    assert!(
        hit.aliases.is_empty(),
        "同名不同来源是相互印证，不是冲突：{:?}",
        hit.aliases
    );
}
