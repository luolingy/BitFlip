//! M2c：DEX 进 `export`（ADR-0021、`docs/APK-DEX-DESIGN.md` §M2c）。
//!
//! ## 这条测试要守什么
//!
//! DEX 导出最容易出的三种问题都不是编译错误：
//!
//! 1. **顺序不稳定**：导出是给外部工具做差分用的，同一份输入两次导出只要
//!    `meta.generated_at` 之外的字节不同，差分就会把"顺序变了"报成"内容变了"。
//!    这里连导两次并逐行比对。
//! 2. **静默忽略选择器**：把 `--member` 给 `asm-intel`、把 `--function` 给
//!    `dex-json`，如果只当没看见，用户会按自己的意图去读一份不是那个意图的输出。
//!    这里逐条断言**报错**。
//! 3. **降级不出现在文件里**：没有字节码、超出方法数上限、解析失败必须写进
//!    `skipped` / `notes`，而不是让文件看起来"完整"。
//!
//! 样本用 loader / CLI / server 测试共用的那份合成 DEX（`#[path]` 引入）：
//! 只有一份样本，才不会出现"四个 crate 各养一份、然后慢慢分叉"。
//! fixture 缺失不可能发生（它是源码），所以这里没有"跳过"这条歧路。

use std::path::{Path, PathBuf};

use bitflip_core::{
    export, BitflipError, ExportError, ExportFormat, ExportOptions, OpenOptions, Session,
};

// 与 loader / CLI / server 测试共用的合成样本（`allow(dead_code)`：这里只用得到 `build()`）。
#[path = "../../bitflip-loader/tests/common/dex_fixture.rs"]
#[allow(dead_code)]
mod fixture;

/// 合成样本里那唯一的类。
const CLASS: &str = "Lcom/example/Foo;";

/// 把合成样本写成一个临时 `.dex` 文件，并保持临时目录存活。
fn dex_target() -> (tempfile::TempDir, PathBuf) {
    let dir = tempfile::tempdir().expect("临时目录");
    let path = dir.path().join("classes.dex");
    std::fs::write(&path, fixture::build()).expect("写入合成样本");
    (dir, path)
}

fn dex_session() -> (tempfile::TempDir, Session) {
    let (dir, path) = dex_target();
    let session = Session::open(&path, OpenOptions::default()).expect("打开单文件 DEX 目标");
    (dir, session)
}

/// 机器码样本（M9 的那批生成物）。
fn machine_code_session(name: &str) -> Session {
    let path = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("..")
        .join("..")
        .join("tests")
        .join("fixtures")
        .join("generated")
        .join(name);
    assert!(
        path.exists(),
        "缺少 fixture {}；先跑 tests/fixtures/gen-fixtures.ps1 生成样本",
        path.display()
    );
    Session::open(&path, OpenOptions::default()).expect("打开样本")
}

fn parse(text: &str) -> serde_json::Value {
    serde_json::from_str(text).expect("导出必须是合法 JSON（外部工具要能解析）")
}

/// 只导出那一个类（DEX 格式的常用起点）。
fn one_class() -> ExportOptions {
    ExportOptions {
        class: Some(CLASS.to_string()),
        ..ExportOptions::default()
    }
}

#[test]
fn dex_json_snapshot_covers_the_synthetic_fixture() {
    let (_dir, session) = dex_session();
    let (text, report) =
        export(&session, ExportFormat::DexJson, &one_class()).expect("导出 DEX 快照");
    let document = parse(&text);

    assert_eq!(document["format_version"], 1, "DEX 报告格式版本");
    assert_eq!(
        document["meta"]["format_versions"]["dex"], 1,
        "用了 DEX 视图就要在版本表里点名 DEX 视图的版本"
    );
    assert_eq!(document["meta"]["format"], "dex-json");
    assert_eq!(
        document["member"], "classes.dex",
        "单文件目标用文件名当成员名"
    );
    assert_eq!(document["meta"]["member"], "classes.dex");
    assert!(
        document["role"].is_null(),
        "单文件目标不属于 APK 的那几个固定位置：写 null，不要编一个角色"
    );

    // 结构计数：合成样本 1 个类、2 个方法，两个都有字节码。
    assert_eq!(document["header"]["class_count"], 1);
    assert_eq!(document["header"]["method_count"], 2);
    assert_eq!(document["header"]["method_count_with_code"], 2);

    let classes = document["classes"].as_array().expect("classes 数组");
    assert_eq!(classes.len(), 1);
    assert_eq!(report.items, 1, "报告里的条数是导出的类数");
    let class = &classes[0];
    assert_eq!(class["descriptor"], CLASS);
    assert_eq!(class["short_name"], "Foo");
    assert_eq!(class["superclass"], "Ljava/lang/Object;");
    assert_eq!(class["source_file"], "Foo.java");
    assert_eq!(class["access_flags"], fixture::ACC_PUBLIC);

    // 字段：`class_data` 先静态后实例（规范 §4.5.11 的分区），下标与类型都要对得上。
    let fields = class["fields"].as_array().expect("fields 数组");
    assert_eq!(fields.len(), 2);
    assert_eq!(fields[0]["name"], "x");
    assert_eq!(fields[0]["type_descriptor"], "I");
    assert_eq!(fields[0]["is_static"], true);
    assert_eq!(fields[1]["name"], "s");
    assert_eq!(fields[1]["type_descriptor"], "Ljava/lang/String;");
    assert_eq!(fields[1]["is_static"], false);

    // 方法：直接方法在前、虚方法在后（同一节的分区），标识是 smali 写法。
    let methods = class["methods"].as_array().expect("methods 数组");
    assert_eq!(methods.len(), 2);
    assert_eq!(methods[0]["signature"], "Lcom/example/Foo;-><init>()V");
    assert_eq!(methods[0]["is_direct"], true);
    assert_eq!(methods[1]["signature"], "Lcom/example/Foo;->bar(I)V");
    assert_eq!(methods[1]["is_direct"], false);

    for method in methods {
        assert_eq!(method["has_code"], true, "合成样本的两个方法都有字节码");
        let code_off = method["code_off"].as_str().expect("code_off");
        assert_eq!(code_off.len(), 16, "偏移也是定长 hex：{code_off:?}");
        let instructions = method["instructions"]
            .as_array()
            .expect("instructions 数组");
        assert_eq!(instructions.len(), 1, "code_item 里只有一条 return-void");
        let unit = instructions[0]["code_unit"].as_str().expect("code_unit");
        assert_eq!(unit.len(), 16, "码元偏移也是定长 hex：{unit:?}");
        assert!(
            instructions[0]["text"]
                .as_str()
                .is_some_and(|text| text.contains("return-void")),
            "指令文本要来自我们自己的渲染路径：{:?}",
            instructions[0]["text"]
        );
        assert_eq!(method["cfg"]["blocks"], 1);
    }

    // 符号账目：合成样本里的引用都能解析，所以计数是 0 而不是 null。
    assert_eq!(document["symbols"]["enabled"], true);
    assert_eq!(document["symbols"]["unsupported_operands"], 0);
    assert_eq!(document["symbols"]["unavailable_operands"], 0);
}

#[test]
fn dex_json_is_deterministic_apart_from_the_timestamp() {
    let (_dir, session) = dex_session();
    let options = one_class();
    let (first, _) = export(&session, ExportFormat::DexJson, &options).expect("第一次导出");
    let (second, _) = export(&session, ExportFormat::DexJson, &options).expect("第二次导出");

    let first_lines: Vec<&str> = first.lines().collect();
    let second_lines: Vec<&str> = second.lines().collect();
    assert_eq!(
        first_lines.len(),
        second_lines.len(),
        "同一输入两次导出的行数必须一致"
    );
    let differing: Vec<&str> = first_lines
        .iter()
        .zip(second_lines.iter())
        .filter(|(left, right)| left != right)
        .map(|(left, _)| *left)
        .collect();
    assert!(
        differing.iter().all(|line| line.contains("generated_at")),
        "两次导出只允许时间戳那一行不同（其余差异说明顺序不稳定）：{differing:?}"
    );
}

#[test]
fn dex_and_machine_code_selectors_reject_each_other() {
    let (_dir, session) = dex_session();
    let cases: [(ExportFormat, ExportOptions, &str); 6] = [
        (
            ExportFormat::DexJson,
            ExportOptions {
                range: Some((0, 0x100)),
                ..ExportOptions::default()
            },
            "--from/--to",
        ),
        (
            ExportFormat::DexSmali,
            ExportOptions {
                function: Some(0x100),
                ..ExportOptions::default()
            },
            "--function",
        ),
        (
            ExportFormat::DexDotCfg,
            ExportOptions {
                range: Some((0, 0x100)),
                function: Some(0x100),
                ..ExportOptions::default()
            },
            "--from/--to",
        ),
        (
            ExportFormat::JsonFunctions,
            ExportOptions {
                member: Some("classes.dex".to_string()),
                ..ExportOptions::default()
            },
            "member",
        ),
        (
            ExportFormat::DotCfg,
            ExportOptions {
                class: Some(CLASS.to_string()),
                ..ExportOptions::default()
            },
            "class",
        ),
        (
            ExportFormat::JsonSymbols,
            ExportOptions {
                method: Some("Lcom/example/Foo;->bar(I)V".to_string()),
                search: Some("Foo".to_string()),
                ..ExportOptions::default()
            },
            "search",
        ),
    ];

    for (format, options, expected) in cases {
        let error = export(&session, format, &options)
            .expect_err("必须报错而不是忽略选择器（格式与选择器不匹配）");
        match error {
            BitflipError::Export(ExportError::MismatchedOptions { message, notes }) => {
                assert!(
                    message.contains(expected),
                    "{} 的错误要点名是哪个选项：{message}",
                    format.as_str()
                );
                assert!(!notes.is_empty(), "报错必须说清怎么办：{message}");
            }
            other => panic!("期望 MismatchedOptions，得到 {other:?}"),
        }
    }
}

#[test]
fn dex_smali_text_is_labelled_and_does_not_repeat_the_offset() {
    let (_dir, session) = dex_session();
    let options = ExportOptions {
        class: Some(CLASS.to_string()),
        method: Some("Lcom/example/Foo;->bar(I)V".to_string()),
        ..ExportOptions::default()
    };
    let (text, report) =
        export(&session, ExportFormat::DexSmali, &options).expect("导出 smali 风格文本");

    assert!(
        text.starts_with("# bitflip-export v1 format=dex-smali"),
        "文本格式也要自述头：{}",
        text.lines().next().unwrap_or_default()
    );
    assert!(
        text.contains("不是可回汇编的 smali 源文件"),
        "必须写清这份文件喂不了 smali 汇编器"
    );
    assert!(text.contains(&format!(".class {CLASS}")), "要写出类头");
    assert!(
        text.contains(".method Lcom/example/Foo;->bar(I)V"),
        "要写出被选中的方法"
    );
    assert!(text.contains(".end method"), "每个方法要有收尾");
    assert_eq!(
        text.matches(".class ").count(),
        1,
        "给了 --method 就只该有一段类头（`--method` 也要筛类）"
    );
    assert_eq!(report.items, 1, "只导出一个方法");

    // 指令行：`render_instruction*` 已经带地址前缀，这里不能再加一次。
    let instruction_lines: Vec<&str> = text
        .lines()
        .filter(|line| line.starts_with("    ") && !line.trim_start().starts_with('#'))
        .collect();
    assert!(!instruction_lines.is_empty(), "至少要写出一行指令");
    for line in &instruction_lines {
        let trimmed = line.trim_start();
        let (prefix, rest) = trimmed.split_at(4);
        assert!(
            prefix.chars().all(|ch| ch.is_ascii_hexdigit()),
            "指令行以 4 位码元偏移开头：{line:?}"
        );
        assert_eq!(&trimmed[4..6], ": ", "偏移后面是冒号：{line:?}");
        // 前缀只允许出现一次：前 4 位 hex 之后如果又是 "<4 位 hex>: "，说明加了两遍。
        assert!(
            trimmed.get(6..12).is_none_or(|next| !next.ends_with(": ")),
            "地址前缀只能出现一次（这里是：{line:?}）"
        );
        assert!(
            rest.contains("return-void"),
            "指令文本要来自渲染路径：{line:?}"
        );
    }
}

#[test]
fn dex_dot_cfg_is_balanced_dot_keyed_by_method() {
    let (_dir, session) = dex_session();
    let options = ExportOptions {
        class: Some(CLASS.to_string()),
        ..ExportOptions::default()
    };
    let (text, report) = export(&session, ExportFormat::DexDotCfg, &options).expect("导出 DEX CFG");

    assert!(text.starts_with("// bitflip-export v1 format=dex-dot-cfg"));
    assert!(text.contains("digraph bitflip {"));
    assert!(
        text.matches('{').count() == text.matches('}').count(),
        "DOT 的大括号必须配对（否则 Graphviz 解析失败）"
    );
    assert_eq!(
        text.matches("subgraph cluster_").count(),
        2,
        "两个方法两个 cluster"
    );
    assert!(text.contains("shape=box"), "块是方框");
    assert!(
        text.contains("peripheries=2"),
        "入口块用双线框标出来（`peripheries` 必须是独立属性）"
    );
    assert!(
        !text.contains("shape=\"box,"),
        "`peripheries` 不能塞进 `shape` 的值里（Graphviz 会当成不认识的形状）"
    );
    assert!(report.items > 0, "至少要画出一个基本块");
}

#[test]
fn dex_method_limit_and_empty_filters_are_reported_not_silent() {
    let (_dir, session) = dex_session();

    // 方法数上限（对 DEX 复用 `max_functions`，口径是"多少个方法"）。
    let limited = ExportOptions {
        max_functions: 1,
        ..ExportOptions::default()
    };
    let (text, report) = export(&session, ExportFormat::DexJson, &limited).expect("导出 DEX 快照");
    let document = parse(&text);
    assert_eq!(document["totals"]["methods_written"], 1);
    assert_eq!(document["skipped"]["methods_over_limit"], 1);
    assert!(
        report
            .notes
            .iter()
            .any(|note| note.contains("--max-functions")),
        "被上限挡掉多少必须写进说明：{:?}",
        report.notes
    );

    // 筛空**报错**：一份空文件与"筛错了"在结果上长得一模一样。
    let missing_class = ExportFormat::DexJson;
    let error = export(
        &session,
        missing_class,
        &ExportOptions {
            class: Some("Lcom/example/Bar;".to_string()),
            ..ExportOptions::default()
        },
    )
    .expect_err("类不存在必须报错");
    assert!(
        matches!(&error, BitflipError::InvalidInput(message) if message.contains("没有类")),
        "要点名是类没找到：{error}"
    );

    let error = export(
        &session,
        ExportFormat::DexJson,
        &ExportOptions {
            search: Some("NoSuchClass".to_string()),
            ..ExportOptions::default()
        },
    )
    .expect_err("子串没命中必须报错");
    assert!(
        matches!(&error, BitflipError::InvalidInput(message) if message.contains("没有描述符含")),
        "要点名是子串没命中：{error}"
    );

    let error = export(
        &session,
        ExportFormat::DexJson,
        &ExportOptions {
            method: Some("Lcom/example/Foo;->baz()V".to_string()),
            ..ExportOptions::default()
        },
    )
    .expect_err("方法不存在必须报错");
    assert!(
        matches!(&error, BitflipError::InvalidInput(message) if message.contains("找不到方法")),
        "要点名是方法没找到：{error}"
    );
}

#[test]
fn dex_json_over_budget_is_an_error_not_half_a_document() {
    let (_dir, session) = dex_session();
    let options = ExportOptions {
        byte_limit: Some(64),
        class: Some(CLASS.to_string()),
        ..ExportOptions::default()
    };
    let error =
        export(&session, ExportFormat::DexJson, &options).expect_err("64 字节装不下任何快照");
    match error {
        BitflipError::Export(ExportError::OverBudget {
            bytes,
            limit,
            notes,
            ..
        }) => {
            assert!(bytes > limit, "报出的实际大小必须大于预算");
            assert_eq!(limit, 64);
            assert!(!notes.is_empty(), "必须给出怎么办");
        }
        other => panic!("期望 OverBudget，得到 {other:?}"),
    }
}

#[test]
fn dex_smali_truncation_keeps_a_usable_prefix_and_advises_a_real_option() {
    let (_dir, session) = dex_session();
    let options = ExportOptions {
        // 够写下文件头与一部分方法，写不完整个类。
        byte_limit: Some(512),
        class: Some(CLASS.to_string()),
        ..ExportOptions::default()
    };
    let (text, report) = export(&session, ExportFormat::DexSmali, &options).expect("导出");

    assert!(
        report.truncated.is_some(),
        "512 字节一定写不完一个类：这条测试若没截断就什么都没验证"
    );
    let truncation = report.truncated.as_ref().expect("截断账目");
    assert!(truncation.dropped > 0, "必须说明少写了多少条");
    assert!(
        text.len() as u64 <= 512,
        "写出内容不得超过预算：{}",
        text.len()
    );
    assert!(
        text.ends_with('\n'),
        "截断位置必须在行边界：切在行中间会让文本工具读出半个 token"
    );
    assert!(
        truncation.hint.contains("--class") || truncation.hint.contains("--search"),
        "DEX 的截断建议必须给一个 DEX 上真能用的选项：{}",
        truncation.hint
    );
    assert!(
        !truncation.hint.contains("--from"),
        "不能推荐 `--from/--to`：DEX 视图用它会直接报错（没有线性地址空间）：{}",
        truncation.hint
    );
}

#[test]
fn options_without_a_dex_counterpart_are_reported_as_ineffective() {
    let (_dir, session) = dex_session();
    let options = ExportOptions {
        class: Some(CLASS.to_string()),
        include_bytes: false,
        include_source: false,
        ..ExportOptions::default()
    };
    let (_, report) = export(&session, ExportFormat::DexJson, &options).expect("导出");
    assert!(
        report.notes.iter().any(|note| note.contains("--no-bytes")),
        "`--no-bytes` 在 DEX 上不起作用，就必须说出来：{:?}",
        report.notes
    );
    assert!(
        report.notes.iter().any(|note| note.contains("--no-source")),
        "`--no-source` 在 DEX 上不起作用，就必须说出来：{:?}",
        report.notes
    );

    // 默认（两个都给）时不许出现这两句：说明里的每一句都该对应真实情况，
    // 常驻的"没有影响"会变成噪音，用户就不再读了。
    let (_, defaults) = export(&session, ExportFormat::DexJson, &one_class()).expect("导出");
    assert!(
        !defaults
            .notes
            .iter()
            .any(|note| note.contains("--no-bytes") || note.contains("--no-source")),
        "没用这两个开关时不该提它们：{:?}",
        defaults.notes
    );
}

#[test]
fn machine_code_export_reports_a_null_dex_version() {
    let session = machine_code_session("pe-x86_64.dll");
    let (text, _) = export(
        &session,
        ExportFormat::JsonFunctions,
        &ExportOptions::default(),
    )
    .expect("导出函数清单");
    let document = parse(&text);
    assert!(
        document["meta"]["format_versions"]["dex"].is_null(),
        "没用 DEX 视图就写 null，不要写 0（0 会被读成'版本 0 的 DEX 视图'）"
    );
    assert!(
        document["meta"]["member"].is_null(),
        "非 DEX 导出没有成员名，写 null"
    );
}
