//! 内置示例脚本的**可执行性**测试。
//!
//! # 这组测试要挡的是什么
//!
//! 示例脚本冻结在源码里，最容易出的问题是"文档/示例与实现脱节"：
//! API 改了名、参数从必填变成了可选、某个字段不叫这个名字了 ——
//! 而示例没有编译期检查，所以它会**静默腐烂**，直到用户照着跑一遍才发现。
//!
//! 所以这里的做法是：把 `bitflip_script::builtin_scripts()` 里的每一份源码
//! **真的在真实样本上跑一次**，断言它没有报错、并且真的产出了它承诺的东西。
//!
//! 特别地，PLAN §M7 验收标准 1 用的就是 [`builtin_script("memcpy-args")`] 这
//! 一份源码，不在测试里另抄 —— 否则"测试通过"与"发出去的示例能跑"是两件事。

use std::path::PathBuf;

use bitflip_core::{AnnotationKind, DisasmScanOptions, ProjectStore, Session};
use bitflip_script::{
    builtin_script, builtin_scripts, ColumnKind, Host, Limits, ScriptEngine, TableCell,
};

/// 未经剥离的样本：`memcpy` 只存在于符号表里。
const SYMBOLS_FIXTURE: &str = "m3-mingw-static.unstripped.exe";
/// 剥离过的样本。
const STRIPPED_FIXTURE: &str = "m3-mingw-static.exe";

fn fixture(name: &str) -> PathBuf {
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../tests/fixtures/generated")
        .join(name);
    // 硬断言而不是静默跳过：fixture 缺失时"通过"是最坏的结果。
    assert!(
        path.exists(),
        "缺少 fixture：{}（由 tests/fixtures 脚本生成，见 docs/PLAN.md §5.2）",
        path.display()
    );
    path
}

fn session(name: &str) -> Session {
    Session::open(fixture(name), bitflip_core::OpenOptions::default()).expect("打开样本")
}

fn engine() -> ScriptEngine {
    ScriptEngine::new(Limits {
        timeout: std::time::Duration::from_secs(120),
    })
    .expect("创建引擎")
}

fn host(name: &str) -> Host {
    let session = session(name);
    let disasm = std::sync::Arc::new(
        session
            .disassemble(DisasmScanOptions::default())
            .expect("反汇编样本"),
    );
    let provider: bitflip_script::DisasmProvider =
        std::sync::Arc::new(move || Ok(std::sync::Arc::clone(&disasm)));
    Host::new(None)
        .with_session(std::sync::Arc::new(session))
        .with_disasm(provider)
}

/// 在真实样本上跑一份内置脚本，**并给它一个工程库**。
///
/// 工程库不是可选的：内置脚本里有三份会写标注，没有库时提交会明确失败
/// （"写入无处可存"）。让通用测试也带上库，才是真的把"暂存 → 提交"这条路
/// 走完了 —— 否则这类脚本永远只在"读"的那一半被测过。
///
/// 返回重新打开的工程库与宿主：前者用来核对落盘的内容，后者用来核对脚本
/// 产出的表（表不落库，只活在宿主上）。
fn run_script(name: &str, source: &str) -> (bitflip_script::ScriptOutcome, ProjectStore, Host) {
    let dir = tempfile::tempdir().expect("tempdir");
    let path = dir.path().join("builtin.bfp");
    let hash = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
    ProjectStore::create(&path, hash, 4096, "test", 1_700_000_000).expect("创建工程库");

    let engine = engine();
    let host = host(name).with_project_store(ProjectStore::open(&path, hash).expect("打开工程库"));
    host.warmup().expect("预热");
    let outcome = engine
        .run(&host, source)
        .unwrap_or_else(|error| panic!("内置脚本 {name} 没有跑通：{error}"));

    // 先重开再让临时目录析构：库里的内容要能在"脚本结束之后"被读到。
    let reopened = ProjectStore::open(&path, hash).expect("重新打开工程库");
    (outcome, reopened, host)
}

fn logs(outcome: &bitflip_script::ScriptOutcome) -> String {
    outcome
        .logs
        .iter()
        .map(|log| log.message.as_str())
        .collect::<Vec<_>>()
        .join("\n")
}

#[test]
fn every_builtin_script_runs_on_a_real_target() {
    // 剥离过的样本：更能代表"什么都没识别出来"的处境，
    // 也正好让"找不到 memcpy 要明确报错"这条路径真的被执行到。
    for script in builtin_scripts() {
        if script.id == "memcpy-args" {
            // 剥离样本上它**应当**报错，由下面那条测试单独管。
            continue;
        }
        let (outcome, _store, _host) = run_script(STRIPPED_FIXTURE, script.source);
        let text = logs(&outcome);
        assert!(
            !text.is_empty(),
            "内置脚本 `{}`（{}）跑完了却什么都没说 —— 一个不说话的示例没有教学价值",
            script.id,
            script.name
        );
    }
}

#[test]
fn every_builtin_script_declares_the_current_api_version() {
    // 示例声明的版本落后于引擎时，用户会以为自己环境不对。
    for script in builtin_scripts() {
        assert_eq!(
            script.api_version,
            bitflip_script::SCRIPT_API_VERSION,
            "内置脚本 `{}` 声明的 API 版本与引擎不一致",
            script.id
        );
        assert!(!script.id.is_empty(), "每份脚本都要有稳定标识");
        assert!(!script.name.is_empty(), "每份脚本都要有显示名");
        assert!(
            !script.description.is_empty(),
            "脚本 `{}` 缺少说明：UI 上只有名字的脚本没人敢按",
            script.id
        );
    }
}

#[test]
fn builtin_script_lookup_by_id_finds_every_script() {
    for script in builtin_scripts() {
        let found = builtin_script(script.id).expect("按标识应能找到");
        assert_eq!(found.id, script.id);
    }
    assert!(
        builtin_script("no-such-script").is_none(),
        "找不到时应当是 None，而不是随便给一份"
    );
}

// ---------------------------------------------------------------------------
// 验收标准 1：跑的就是发布出去的那一份源码
// ---------------------------------------------------------------------------

#[test]
fn acceptance_1_the_shipped_memcpy_script_annotates_every_call_site() {
    let dir = tempfile::tempdir().expect("tempdir");
    let path = dir.path().join("m7-builtin-memcpy.bfp");
    let hash = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
    ProjectStore::create(&path, hash, 4096, "test", 1_700_000_000).expect("创建工程库");

    let script = builtin_script("memcpy-args").expect("内置脚本必须在库里");
    let engine = engine();
    let host = host(SYMBOLS_FIXTURE)
        .with_project_store(ProjectStore::open(&path, hash).expect("打开工程库"));
    host.warmup().expect("预热");

    let outcome = engine
        .run(&host, script.source)
        .expect("验收标准 1：内置脚本应当端到端跑通");

    // 脚本对外承诺的前两条日志
    assert_eq!(
        outcome.logs[0].message, "memcpy@0000000140009218",
        "真值文件记的就是这个地址；对不上说明符号解析或函数识别出了问题"
    );
    let annotated: usize = outcome.logs[1]
        .message
        .strip_prefix("annotated=")
        .expect("第二条日志必须是标注条数")
        .parse()
        .expect("标注条数应为整数");
    assert!(annotated > 0, "memcpy 在真实样本上必须被调用过");
    assert_eq!(outcome.committed, annotated, "提交条数必须与脚本报告的一致");

    // 落到库里的必须真的是"调用 memcpy 的那些点"
    let session = session(SYMBOLS_FIXTURE);
    let analysis = session
        .analysis(&session.detached_job())
        .expect("构建分析结论");
    let reopened = ProjectStore::open(&path, hash).expect("重新打开工程库");
    assert_eq!(reopened.len(), annotated);
    for annotation in reopened.range(0, u64::MAX) {
        assert_eq!(
            annotation.text.as_deref(),
            Some("memcpy(dst, src, n)"),
            "注释内容必须是脚本写的那一条"
        );
        let calls_in = analysis
            .xrefs_from(annotation.address)
            .into_iter()
            .any(|x| x.kind == "call" && x.to == "0000000140009218");
        assert!(
            calls_in,
            "注释落到 {:016x} 上了，但那里并没有调用 memcpy",
            annotation.address
        );
    }
}

#[test]
fn acceptance_1_degrades_honestly_when_memcpy_is_not_identified() {
    // 剥离过的样本上没有 memcpy 这个名字。此时正确的行为是**明确报错**并
    // 说明这属于签名识别（M8）的课题，而不是"跑完了但是什么都没发生"。
    let engine = engine();
    let host = host(STRIPPED_FIXTURE);
    host.warmup().expect("预热");
    let script = builtin_script("memcpy-args").expect("内置脚本");

    let error = engine
        .run(&host, script.source)
        .expect_err("剥离样本上应当报错，而不是静默过关");
    let message = error.to_string();
    assert!(
        message.contains("memcpy"),
        "错误里要提到找的是什么：{message}"
    );
    assert!(
        message.contains("M8") || message.contains("签名"),
        "要把\"这不是脚本能补的\"说清楚，否则用户会去改脚本：{message}"
    );
}

// ---------------------------------------------------------------------------
// 逐份脚本的产出断言
// ---------------------------------------------------------------------------

#[test]
fn rename_by_string_only_names_functions_and_says_why() {
    let (outcome, store, _host) = run_script(
        STRIPPED_FIXTURE,
        builtin_script("rename-by-string").unwrap().source,
    );

    let text = logs(&outcome);
    assert!(text.contains("重命名="), "要报告做了什么：{text}");
    assert!(
        text.contains("跳过（已有名字）=") && text.contains("跳过（引用不唯一"),
        "被跳过的东西必须如实统计出来，否则用户会以为脚本漏跑了：{text}"
    );

    // 写进去的每一个名字都必须带 str_ 前缀，并且注释里写明依据 ——
    // 推断出来的名字不许看起来像符号表里的真名（CLAUDE.md §7）。
    //
    // 标注表里名字与注释是**两种 kind**（同一个 `text` 字段装内容），
    // 没有单独的 `name` 字段：这里必须按 kind 分开看。
    let mut names = 0;
    for annotation in store.range(0, u64::MAX) {
        match annotation.kind {
            AnnotationKind::Name => {
                let name = annotation.text.as_deref().expect("名字标注必须有文本");
                assert!(
                    name.starts_with("str_"),
                    "推断名必须带 str_ 前缀以便一眼区分，实际：{name}"
                );
                names += 1;
            }
            AnnotationKind::Comment => {
                let comment = annotation.text.as_deref().unwrap_or_default();
                assert!(
                    comment.contains("按字符串引用推断"),
                    "注释必须写明依据，实际：{comment}"
                );
            }
            other => panic!("这个脚本只该写名字与注释，却出现了 {other:?}"),
        }
    }
    assert!(
        names > 0,
        "剥离样本上有大量字符串引用，应当至少命名一个函数"
    );
}

#[test]
fn export_functions_includes_unnamed_ones_and_the_degradation_notes() {
    let (outcome, _store, _host) = run_script(
        STRIPPED_FIXTURE,
        builtin_script("export-functions").unwrap().source,
    );
    let text = logs(&outcome);

    assert!(
        text.contains("(未命名)"),
        "剥离样本上函数全都是未命名的；导出清单必须如实写 (未命名) 而不是编占位名：{text}"
    );
    assert!(
        text.contains("函数总数=") && text.contains("已导出="),
        "导出必须给出总计，否则用户无法判断是不是被截断了：{text}"
    );
    assert!(
        text.contains('\t'),
        "导出应当是制表符分隔的，实际没有制表符"
    );
}

// ---------------------------------------------------------------------------
// 内置脚本是"声明式表"的参考实现
// ---------------------------------------------------------------------------

#[test]
fn the_example_scripts_show_how_to_publish_a_table() {
    // 示例脚本是用户抄的第一个模板。`bitflip.table` 是新加的（自定义视图
    // 数据源），如果连内置示例都不用，用户就没有可抄的用法 —— 而界面上
    // "结果表格"会继续显示从日志里猜出来的那张表。
    let (outcome, _store, _host) = run_script(
        STRIPPED_FIXTURE,
        builtin_script("export-functions").unwrap().source,
    );
    assert!(
        outcome.tables > 0,
        "导出脚本应当产出一张声明的表，实际 {} 张",
        outcome.tables
    );
}

#[test]
fn the_exported_table_declares_its_column_types() {
    let (outcome, _store, host) = run_script(
        STRIPPED_FIXTURE,
        builtin_script("export-functions").unwrap().source,
    );
    assert_eq!(outcome.tables, 1, "这份脚本只产出一张表");

    let table = &host.tables()[0];
    assert_eq!(table.name, "函数清单");
    assert!(
        table.description.is_some(),
        "表要说清它是什么，否则用户在界面上只看到一个表名"
    );
    let kinds: Vec<ColumnKind> = table.columns.iter().map(|column| column.kind).collect();
    assert_eq!(
        kinds,
        vec![
            ColumnKind::Address,
            ColumnKind::Text,
            ColumnKind::Text,
            ColumnKind::Number,
            ColumnKind::Text
        ],
        "列类型的声明就是这个脚本要教的东西：地址列必须是 address 而不是文本"
    );

    // 声明了 address，宿主就必须按地址收：每一格的地址都要真的解析成了 u64。
    for (index, row) in table.rows.iter().enumerate() {
        assert!(
            matches!(row[0], TableCell::Address(_)),
            "第 {} 行的第一列不是地址单元格：{:?}",
            index + 1,
            row[0]
        );
    }
    // 置信度声明成 number，因此不会有"看起来像数字的字符串"混进来。
    for row in &table.rows {
        assert!(
            matches!(row[3], TableCell::Number(_)),
            "置信度列必须是数字单元格：{:?}",
            row[3]
        );
    }
}

#[test]
fn library_patterns_lists_candidates_and_refuses_to_conclude() {
    let (outcome, _store, _host) = run_script(
        STRIPPED_FIXTURE,
        builtin_script("library-patterns").unwrap().source,
    );
    let text = logs(&outcome);

    assert!(text.contains("调用引用总数="), "要给出统计口径：{text}");
    assert!(text.contains("候选总数="), "要给出候选总数：{text}");
    // 这一条是 CLAUDE.md §7 在这个脚本上的具体落点：
    // 没有签名库时"这个小函数是 memcpy"只是假设，不许写成结论。
    assert!(
        text.contains("不构成识别结论"),
        "必须明确说自己只是候选，实际：{text}"
    );
    assert!(
        outcome.tables > 0,
        "候选清单应当是声明的表（列类型：地址/次数/大小/置信度），实际 {} 张",
        outcome.tables
    );
}
