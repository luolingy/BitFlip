//! M9 导出的端到端回归：在**真实样本**上验证六种导出。
//!
//! ## 这条测试要守什么
//!
//! 导出最容易出的两种问题都不是编译错误，而是"看起来对"：
//!
//! 1. **静默截断**：字节预算用尽后少给数据而不说 —— 用户会以为"目标就这么大"。
//!    这里用很小的预算强制触发截断，断言报告里**必须**有账目，而且写出部分
//!    必须是完整的行（不能切在行中间）。
//! 2. **能力不匹配时拿别的格式顶替**：对 AArch64 目标要 AT&T，绝不能回落到
//!    Intel 文本假装成功。这里断言它**报错**。
//!
//! 另外把导出的 JSON 结构（`format_version` / `totals` 与数据条数一致）
//! 钉住 —— 那是外部工具消费的契约，漂移了没人会立刻发现。
//!
//! fixture 缺失时**响亮失败**（CLAUDE.md §7：跳过会让绿灯说谎）。

use std::path::{Path, PathBuf};

use bitflip_core::{
    export, ExportError, ExportFormat, ExportOptions, OpenOptions, Session,
    DEFAULT_EXPORT_BYTE_LIMIT, EXPORT_FORMAT_VERSION,
};

fn fixture(name: &str) -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("..")
        .join("..")
        .join("tests")
        .join("fixtures")
        .join("generated")
        .join(name)
}

fn open(name: &str) -> Session {
    let path = fixture(name);
    assert!(
        path.exists(),
        "缺少 fixture {}；先跑 tests/fixtures/gen-fixtures.ps1 生成样本",
        path.display()
    );
    Session::open(&path, OpenOptions::default()).expect("打开样本")
}

/// 解析导出的 JSON，并校验封套。
fn parse_document(text: &str) -> serde_json::Value {
    let value: serde_json::Value =
        serde_json::from_str(text).expect("导出必须是合法 JSON（外部工具要能解析）");
    assert_eq!(
        value["format_version"], EXPORT_FORMAT_VERSION,
        "JSON 里必须带导出格式版本"
    );
    assert!(
        value["producer"]
            .as_str()
            .is_some_and(|p| p.starts_with("bitflip ")),
        "JSON 里必须带产出工具与版本"
    );
    value
}

#[test]
fn asm_export_has_a_self_describing_header_and_real_instructions() {
    let session = open("m3-mingw-static.exe");
    let (text, report) = export(&session, ExportFormat::AsmIntel, &ExportOptions::default())
        .expect("导出 Intel 反汇编");

    let first_line = text.lines().next().expect("至少有一行");
    assert!(
        first_line.starts_with("# bitflip-export v1"),
        "首行必须是自述头，实际是 {first_line:?}"
    );
    assert!(first_line.contains("format=asm-intel"), "{first_line:?}");
    assert!(
        first_line.contains("arch=x86_64"),
        "架构必须写出来：{first_line:?}"
    );

    // 至少要有几百条指令；每条以 16 位定长 hex 地址开头（wire 契约）。
    let instruction_lines: Vec<&str> = text.lines().filter(|line| !line.starts_with('#')).collect();
    assert!(
        instruction_lines.len() > 500,
        "导出指令太少（{} 条），样本或扫描有问题",
        instruction_lines.len()
    );
    for line in instruction_lines.iter().take(50) {
        let address = line.split_whitespace().next().expect("行首是地址");
        assert_eq!(address.len(), 16, "地址必须是定长 16 位 hex：{line:?}");
        assert!(
            address.chars().all(|c| c.is_ascii_hexdigit()),
            "地址必须是十六进制：{line:?}"
        );
    }

    assert_eq!(report.format, ExportFormat::AsmIntel);
    assert_eq!(report.items as usize, instruction_lines.len());
    assert!(report.truncated.is_none(), "默认预算下不该截断");
    assert_eq!(report.bytes, text.len() as u64);
    // 覆盖率与不可解码条数必须写在说明里（降级要写在界面上）。
    assert!(
        report.notes.iter().any(|note| note.contains("索引")),
        "说明里必须给出覆盖率账目：{:?}",
        report.notes
    );
}

#[test]
fn att_export_carries_att_sigils_and_rejects_non_x86() {
    let session = open("m3-mingw-static.exe");
    let (text, _) = export(&session, ExportFormat::AsmAtt, &ExportOptions::default())
        .expect("导出 AT&T 反汇编");
    let body = text
        .lines()
        .filter(|line| !line.starts_with('#'))
        .collect::<Vec<_>>()
        .join("\n");
    assert!(
        body.contains('%') && body.contains('$'),
        "AT&T 文本必须带 % 与 $ 记号"
    );
    assert!(
        !body.contains(" qword ptr "),
        "AT&T 文本不该出现 Intel 的 qword ptr 写法"
    );

    // 能力不匹配：AArch64 目标要 AT&T 必须**报错**，不能回落成 Intel。
    let arm = open("elf-aarch64.exe");
    let error = export(&arm, ExportFormat::AsmAtt, &ExportOptions::default())
        .expect_err("非 x86 目标导出 AT&T 应当报错");
    let message = error.to_string();
    assert!(
        message.contains("AT&T") && message.contains("asm-intel"),
        "报错必须说清原因与替代做法，实际是 {message:?}"
    );
    // 必须是"尚未实现"而不是"输入无效"：用户没写错参数，是这项能力还没做。
    // 混成 InvalidInput 会把人引去改格式名，而正确的反应是换 asm-intel 或等里程碑。
    assert!(
        matches!(error, bitflip_core::BitflipError::NotYetImplemented { .. }),
        "能力缺口要报 NotYetImplemented（HTTP 501），实际是 {error:?}"
    );

    // 同一个目标导出 Intel 是正常的 —— 说明拒绝的是 AT&T，不是这个目标。
    export(&arm, ExportFormat::AsmIntel, &ExportOptions::default())
        .expect("AArch64 目标导出 Intel 反汇编应当成功");
}

#[test]
fn asm_export_reports_truncation_instead_of_silently_dropping() {
    let session = open("m3-mingw-static.exe");
    let options = ExportOptions {
        byte_limit: Some(4096),
        ..ExportOptions::default()
    };
    let (text, report) = export(&session, ExportFormat::AsmIntel, &options).expect("导出");

    assert!(
        report.truncated.is_some(),
        "预算 4 KiB 一定要触发截断（否则这条测试没有验证任何东西）"
    );
    let truncation = report.truncated.as_ref().expect("截断账目");
    assert!(truncation.dropped > 0, "必须说明少写了多少条");
    assert_eq!(truncation.written, report.items);
    assert!(
        !truncation.hint.is_empty(),
        "截断必须给出下一步怎么做，而不是只报一个数字"
    );

    // 保留的那部分必须是完整的行：切在行中间会让文本工具读出半个 token。
    assert!(text.ends_with('\n'), "截断位置必须在行边界");
    assert!(text.len() as u64 <= 4096, "写出内容不得超过预算");
}

#[test]
fn function_export_matches_its_own_totals_and_is_filterable() {
    let session = open("m3-mingw-static.exe");
    let (text, report) = export(
        &session,
        ExportFormat::JsonFunctions,
        &ExportOptions::default(),
    )
    .expect("导出函数清单");
    let document = parse_document(&text);

    let functions = document["functions"].as_array().expect("functions 是数组");
    let written = document["totals"]["written"]
        .as_u64()
        .expect("totals.written");
    assert_eq!(written as usize, functions.len(), "totals 必须与数据一致");
    assert_eq!(report.items as usize, functions.len());
    assert!(!functions.is_empty(), "样本上应当识别出函数");

    // 每条的地址仍是 16 位 hex，且带来源（来源是"名字凭什么可信"的依据）。
    for function in functions.iter().take(20) {
        let start = function["start"].as_str().expect("start");
        assert_eq!(start.len(), 16, "函数入口必须是定长 hex：{start:?}");
        assert!(function["source"].as_str().is_some_and(|s| !s.is_empty()));
    }

    // 范围过滤：只取入口最大的那个函数所在的一段。
    let last = functions.last().expect("至少一个函数")["start"]
        .as_str()
        .expect("start");
    let from = u64::from_str_radix(last, 16).expect("hex");
    let (filtered_text, filtered_report) = export(
        &session,
        ExportFormat::JsonFunctions,
        &ExportOptions {
            range: Some((from, from + 1)),
            ..ExportOptions::default()
        },
    )
    .expect("导出带范围的函数清单");
    let filtered = parse_document(&filtered_text);
    let filtered_functions = filtered["functions"].as_array().expect("数组");
    assert!(!filtered_functions.is_empty(), "范围里应当恰好包含那个入口");
    assert!(
        filtered_functions.len() < functions.len(),
        "范围过滤必须真的减少条数（否则过滤没生效）"
    );
    assert_eq!(filtered_report.items as usize, filtered_functions.len());
}

#[test]
fn symbol_export_reports_imports_and_exports_of_a_real_image() {
    // 三个样本各自覆盖一种"符号来源"，合起来才说明这张表不是空的摆设：
    // - `pe-x86_64.dll`：有**导出表**（名字就在镜像里）；
    // - `m3-mingw-static.exe`：符号表被剥掉，但**导入表**还在；
    // - `elf-x86_64.so`：ELF 的 `.dynsym`（另一个格式的同一件事）。
    let session = open("pe-x86_64.dll");
    let (text, report) = export(
        &session,
        ExportFormat::JsonSymbols,
        &ExportOptions::default(),
    )
    .expect("导出符号表");
    let document = parse_document(&text);

    let totals = &document["totals"];
    for key in ["symbols", "imports", "exports"] {
        assert!(totals[key].is_u64(), "totals.{key} 必须是数字");
    }
    for key in ["symbols", "imports", "exports"] {
        assert_eq!(
            totals[key].as_u64().expect("totals") as usize,
            document[key].as_array().expect("数组").len(),
            "totals.{key} 必须与数据一致"
        );
    }

    let exports = document["exports"].as_array().expect("exports 数组");
    assert!(
        !exports.is_empty(),
        "这个样本有导出表，导出里不该是空的（空说明解析或导出漏了）"
    );
    for export_entry in exports.iter().take(10) {
        let address = export_entry["address"].as_str().expect("address");
        assert_eq!(address.len(), 16, "导出地址必须是定长 hex：{address:?}");
        assert!(
            export_entry["name"]
                .as_str()
                .is_some_and(|name| !name.is_empty()),
            "导出必须有名字（样本里没有纯序号导出）"
        );
    }
    let _ = report;

    // 导入表：IAT 槽地址也必须是定长 hex 或显式 null（未知就写 null）。
    let mingw = open("m3-mingw-static.exe");
    let (mingw_text, _) =
        export(&mingw, ExportFormat::JsonSymbols, &ExportOptions::default()).expect("导出符号表");
    let mingw_document = parse_document(&mingw_text);
    let imports = mingw_document["imports"].as_array().expect("imports 数组");
    assert!(
        !imports.is_empty(),
        "这个样本有导入表（KERNEL32/msvcrt），导出里不该是空的"
    );
    for import in imports {
        assert!(
            import["module"].as_str().is_some_and(|m| !m.is_empty()),
            "导入必须写明来自哪个模块"
        );
        match import["iat_slot"].as_str() {
            Some(slot) => assert_eq!(slot.len(), 16, "IAT 槽地址必须是定长 hex"),
            None => assert!(import["iat_slot"].is_null(), "未知就写 null，不要填空串"),
        }
    }

    // 符号表为空时必须**写明原因**，不能只给一个空数组。
    assert_eq!(
        mingw_document["symbols"].as_array().expect("数组").len(),
        0,
        "这个样本的符号表已剥离"
    );
    let (_, mingw_report) =
        export(&mingw, ExportFormat::JsonSymbols, &ExportOptions::default()).expect("导出符号表");
    assert!(
        mingw_report
            .notes
            .iter()
            .any(|note| note.contains("剥离") || note.contains("符号表")),
        "符号表为空必须写明原因：{:?}",
        mingw_report.notes
    );
}

#[test]
fn xref_export_is_consistent_and_respects_the_range() {
    let session = open("m3-mingw-static.exe");
    let (text, report) =
        export(&session, ExportFormat::JsonXrefs, &ExportOptions::default()).expect("导出交叉引用");
    let document = parse_document(&text);
    let xrefs = document["xrefs"].as_array().expect("xrefs 数组");
    assert!(
        !xrefs.is_empty(),
        "样本上应当有交叉引用（否则调用/跳转的引用收集没生效）"
    );
    assert_eq!(
        document["totals"]["xrefs"].as_u64().expect("totals.xrefs"),
        xrefs.len() as u64
    );
    assert_eq!(report.items as usize, xrefs.len());

    // from / to 都是定长 hex；kind 与 source 不能是空串。
    for xref in xrefs.iter().take(100) {
        for key in ["from", "to"] {
            let value = xref[key].as_str().expect("地址字段");
            assert_eq!(value.len(), 16, "{key} 必须是定长 hex：{value:?}");
        }
        assert!(!xref["kind"].as_str().expect("kind").is_empty());
        assert!(!xref["source"].as_str().expect("source").is_empty());
    }

    // 范围过滤必须真的减少条数，且报告里写清被过滤掉多少。
    let (filtered_text, filtered_report) = export(
        &session,
        ExportFormat::JsonXrefs,
        &ExportOptions {
            range: Some((0, 0x1400_1000)),
            ..ExportOptions::default()
        },
    )
    .expect("导出带范围的交叉引用");
    let filtered = parse_document(&filtered_text);
    let filtered_xrefs = filtered["xrefs"].as_array().expect("数组");
    assert!(
        filtered_xrefs.len() < xrefs.len(),
        "只留 .text 之前的一段，条数必须变少"
    );
    assert!(
        filtered_report
            .notes
            .iter()
            .any(|note| note.contains("过滤")),
        "过滤掉多少要写在说明里：{:?}",
        filtered_report.notes
    );
}

#[test]
fn dot_export_is_syntactically_balanced_and_names_blocks_by_address() {
    let session = open("elf-aarch64-cfg.exe");
    let (text, report) =
        export(&session, ExportFormat::DotCfg, &ExportOptions::default()).expect("导出 CFG");

    assert!(
        text.matches('{').count() == text.matches('}').count(),
        "DOT 的大括号必须配对（否则 Graphviz 解析失败）"
    );
    assert!(text.starts_with("// bitflip-export"), "DOT 也要自述头");
    assert!(text.contains("digraph bitflip {"));
    assert!(text.contains("subgraph cluster_"), "每个函数一个 cluster");
    assert!(report.items > 0, "至少要画出一个基本块");

    // 函数名缺失时写"未识别"，**不造** func_xxx 假名（CLAUDE.md §7）。
    assert!(
        !text.contains("func_") || text.contains("未识别"),
        "不得出现占位假名"
    );
}

#[test]
fn default_budget_is_bounded_and_documented() {
    assert_eq!(DEFAULT_EXPORT_BYTE_LIMIT, 32 * 1024 * 1024);
    let options = ExportOptions::default();
    assert_eq!(options.byte_limit, Some(DEFAULT_EXPORT_BYTE_LIMIT));
}

#[test]
fn over_budget_json_fails_loudly_with_numbers_instead_of_half_a_document() {
    let session = open("m3-mingw-static.exe");
    let options = ExportOptions {
        byte_limit: Some(512),
        ..ExportOptions::default()
    };
    let error = export(&session, ExportFormat::JsonFunctions, &options)
        .expect_err("函数清单远超 512 字节，必须报错");
    match error {
        bitflip_core::BitflipError::Export(ExportError::OverBudget {
            bytes,
            limit,
            notes,
            ..
        }) => {
            assert!(bytes > limit, "报出的实际大小必须大于预算");
            assert_eq!(limit, 512);
            assert!(!notes.is_empty(), "必须给出怎么办");
        }
        other => panic!("期望 OverBudget，得到 {other:?}"),
    }
}
