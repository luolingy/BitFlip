//! `dex` 子命令的测试（M2b）。
//!
//! 两条路，与 loader 侧同样的分工：
//!
//! 1. **合成样本**：与 `bitflip-loader/tests/dex_structure.rs` **共用同一份**
//!    照规范拼出来的最小 DEX（`#[path]` 引入那个文件）。默认就跑，
//!    逐行钉住 CLI 的文本报告 —— 包括"符号解析已关闭"与"没有 CFG"这两条降级说明。
//! 2. **真实 APK**：需要本机样本，所以是 `#[ignore]` 的独立测试；样本不在时
//!    **直接失败**，不静默跳过（CLAUDE.md §7：跳过与通过必须在报告里分得开）。
//!
//! 这里断言的是**输出文本**，不是"函数没报错"：CLI 的价值就在那几行字里。

use std::path::{Path, PathBuf};

use bitflip_cli::{build_dex_json, build_dex_text, DexArgs};

// 与 loader 的结构黄金测试共用的合成样本。`allow(dead_code)`：CLI 测试只用其中的
// `build()`，其余常量与辅助函数是 loader 侧要用的，不该为了这里再删一遍。
#[path = "../../bitflip-loader/tests/common/dex_fixture.rs"]
#[allow(dead_code)]
mod fixture;

/// 一个只填了本测试会用到字段的参数集。
fn args(target: &Path) -> DexArgs {
    DexArgs {
        target: target.to_path_buf(),
        member: None,
        class: None,
        method: None,
        no_symbols: false,
        no_cfg: false,
        limit: 200,
        json: false,
        verbose: false,
    }
}

/// 把合成样本写成一个临时 `.dex` 文件（单文件目标这条路）。
fn write_minimal_dex(dir: &tempfile::TempDir) -> PathBuf {
    let path = dir.path().join("minimal.dex");
    std::fs::write(&path, fixture::build()).expect("写入合成样本");
    path
}

#[test]
fn the_dex_command_renders_a_class_and_a_method_with_its_text_cfg() {
    let dir = tempfile::tempdir().expect("临时目录");
    let target = write_minimal_dex(&dir);

    // ── 概览：有哪几个 DEX、各有多少类与方法
    let summary = build_dex_text(&args(&target)).expect("概览");
    assert!(
        summary.contains("DEX 输入：1 个（minimal.dex）"),
        "概览要列出输入：{summary}"
    );
    assert!(
        summary.contains("1 类 / 2 方法（2 有字节码）"),
        "概览要给出类/方法计数：{summary}"
    );

    // ── 列一个类的方法：两条 smali 标识都要出来
    let mut list = args(&target);
    list.class = Some("Lcom/example/Foo;".to_owned());
    let listing = build_dex_text(&list).expect("列类");
    assert!(
        listing.contains("方法 2 个（2 有字节码 / 0 没有）"),
        "类的方法统计：{listing}"
    );
    assert!(
        listing.contains("Lcom/example/Foo;-><init>()V"),
        "无参方法要出空括号：{listing}"
    );
    assert!(
        listing.contains("Lcom/example/Foo;->bar(I)V"),
        "带参方法要带参数表：{listing}"
    );

    // ── 一个方法的指令与文本 CFG：逐行钉住
    let mut one = args(&target);
    one.method = Some("Lcom/example/Foo;->bar(I)V".to_owned());
    let report = build_dex_text(&one).expect("方法报告");
    let lines: Vec<&str> = report.lines().collect();
    assert_eq!(lines[0], format!("目标：{}", target.display()));
    assert_eq!(lines[1], "方法：Lcom/example/Foo;->bar(I)V");
    assert!(
        lines[2].starts_with("来源：minimal.dex  code_off=0x"),
        "来源行要带成员名与 code_off：{}",
        lines[2]
    );
    assert_eq!(lines[3], "寄存器 1 / 入参 0 / 出参 0");
    assert_eq!(
        lines[4], "符号解析：开启（1 条指令的操作数都解析成了符号文本）",
        "符号解析没缺口时也要说明白"
    );
    assert_eq!(lines[5], "指令（1 条）：");
    assert_eq!(lines[6], "  0000: return-void");
    assert_eq!(
        lines[7],
        "CFG：1 个块、0 条边、0 个未连上的目标（入口块 0）"
    );
    assert_eq!(lines[8], "块 0 @0000（1 条指令）  前驱：无");
    assert_eq!(lines[9], "    没有出边");
    assert_eq!(lines.len(), 10, "报告不该多出别的行：{report}");
}

/// `--no-symbols` 必须**说出来**关掉了符号解析，而不是悄悄换成另一种格式。
#[test]
fn no_symbols_says_the_resolution_is_off() {
    let dir = tempfile::tempdir().expect("临时目录");
    let target = write_minimal_dex(&dir);

    let mut one = args(&target);
    one.method = Some("Lcom/example/Foo;->bar(I)V".to_owned());
    one.no_symbols = true;
    let report = build_dex_text(&one).expect("方法报告");

    assert!(
        report.contains("符号解析：已关闭（--no-symbols）"),
        "关掉符号解析要写在报告里：{report}"
    );
    assert!(
        !report.contains("符号解析：开启"),
        "不能同时说开启与关闭：{report}"
    );
    // 指令本体照常输出（这条指令没有池引用，所以两种模式的文本一样）。
    assert!(
        report.contains("  0000: return-void"),
        "指令仍要输出：{report}"
    );
}

/// `--no-cfg` 时不能还有 CFG 段；`--cfg` 默认是开的（用户 2026-10-16 的决定：先出文本）。
#[test]
fn no_cfg_omits_the_cfg_section() {
    let dir = tempfile::tempdir().expect("临时目录");
    let target = write_minimal_dex(&dir);

    let mut one = args(&target);
    one.method = Some("Lcom/example/Foo;->bar(I)V".to_owned());
    one.no_cfg = true;
    let report = build_dex_text(&one).expect("方法报告");
    assert!(
        !report.contains("CFG："),
        "--no-cfg 时不该有 CFG 段：{report}"
    );
    assert!(report.contains("指令（1 条）："), "指令仍要输出：{report}");
}

/// 类名不像 smali 描述符时要给格式提示，而不是只说"找不到"。
#[test]
fn a_class_that_is_not_a_smali_descriptor_gets_a_format_hint() {
    let dir = tempfile::tempdir().expect("临时目录");
    let target = write_minimal_dex(&dir);

    let mut by_bare_name = args(&target);
    by_bare_name.class = Some("Foo".to_owned());
    let error = build_dex_text(&by_bare_name).expect_err("光写 Foo 不该命中");
    let message = format!("{error:#}");
    assert!(
        message.contains("只做精确匹配") && message.contains("Lcom/Foo;"),
        "要提示 smali 描述符写法：{message}"
    );

    // 写成描述符但不存在：报"找不到"，不再提示格式。
    let mut absent = args(&target);
    absent.class = Some("Lcom/example/Nope;".to_owned());
    let error = build_dex_text(&absent).expect_err("不存在的类");
    let message = format!("{error:#}");
    assert!(message.contains("都找不到类"), "要说清找不到：{message}");
    assert!(
        !message.contains("只做精确匹配"),
        "格式对的时候不该再提示格式：{message}"
    );
}

#[test]
fn a_method_that_does_not_exist_is_an_error_not_an_empty_report() {
    let dir = tempfile::tempdir().expect("临时目录");
    let target = write_minimal_dex(&dir);

    let mut absent = args(&target);
    absent.method = Some("Lcom/example/Foo;->nope()V".to_owned());
    let error = build_dex_text(&absent).expect_err("不存在的方法");
    let message = format!("{error:#}");
    assert!(message.contains("都找不到方法"), "要说清找不到：{message}");
}

/// 目标不是 DEX 时**报错**，不是打印一份空报告。
#[test]
fn a_target_that_is_not_dex_is_an_error() {
    let not_dex = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("Cargo.toml");
    let error = build_dex_text(&args(&not_dex)).expect_err("Cargo.toml 不是 DEX");
    let message = format!("{error:#}");
    assert!(
        message.contains("Cargo.toml"),
        "错误信息要点出是哪个文件：{message}"
    );
}

/// JSON 是稳定的 wire 契约：带 `format_version`、定长 16 位十六进制码元偏移、CFG 文本。
#[test]
fn the_json_report_carries_a_version_and_hex_code_units() {
    let dir = tempfile::tempdir().expect("临时目录");
    let target = write_minimal_dex(&dir);

    let mut one = args(&target);
    one.method = Some("Lcom/example/Foo;->bar(I)V".to_owned());
    one.json = true;
    let text = build_dex_json(&one).expect("JSON 报告");
    let value: serde_json::Value = serde_json::from_str(&text).expect("必须是合法 JSON");

    assert_eq!(value["format_version"], 1, "每份 JSON 都要带格式版本");
    assert_eq!(value["method"]["signature"], "Lcom/example/Foo;->bar(I)V");
    assert_eq!(value["method"]["has_code"], true);
    assert_eq!(value["method"]["registers_size"], 1);
    assert_eq!(value["method"]["instruction_count"], 1);
    assert_eq!(value["method"]["unsupported_operands"], 0);
    assert_eq!(value["method"]["unavailable_operands"], 0);
    assert_eq!(
        value["method"]["instructions"][0]["text"],
        "0000: return-void"
    );
    let code_unit = value["method"]["instructions"][0]["code_unit"]
        .as_str()
        .expect("code_unit 是字符串");
    assert_eq!(code_unit.len(), 16, "定长 16 位：{code_unit}");
    assert!(
        code_unit
            .chars()
            .all(|c| c.is_ascii_digit() || ('a'..='f').contains(&c)),
        "小写十六进制：{code_unit}"
    );
    let cfg = value["method"]["cfg_text"].as_str().expect("cfg_text");
    assert!(cfg.contains("CFG：1 个块"), "CFG 以文本给出：{cfg}");
    assert_eq!(value["method"]["unresolved_edge_targets"], 0);

    // 概览里每个 DEX 的计数与降级说明都在。
    assert_eq!(value["dex_inputs"][0]["name"], "minimal.dex");
    assert_eq!(value["dex_inputs"][0]["class_count"], 1);
    assert_eq!(value["dex_inputs"][0]["method_count"], 2);
    assert_eq!(value["dex_inputs"][0]["method_count_with_code"], 2);
    assert_eq!(
        value["dex_inputs"][0]["notes"].as_array().map(Vec::len),
        Some(0)
    );
}

/// `--class --json`：一个类在每个 DEX 里的出现各一条记录。
#[test]
fn class_json_lists_every_occurrence() {
    let dir = tempfile::tempdir().expect("临时目录");
    let target = write_minimal_dex(&dir);

    let mut one = args(&target);
    one.class = Some("Lcom/example/Foo;".to_owned());
    one.json = true;
    let value: serde_json::Value =
        serde_json::from_str(&build_dex_json(&one).expect("JSON")).expect("合法 JSON");

    assert_eq!(value["class"]["descriptor"], "Lcom/example/Foo;");
    assert_eq!(value["class"]["occurrences"][0]["member"], "minimal.dex");
    assert_eq!(
        value["class"]["occurrences"][0]["superclass"],
        "Ljava/lang/Object;"
    );
    assert_eq!(value["class"]["occurrences"][0]["source_file"], "Foo.java");
    let methods = value["class"]["occurrences"][0]["methods"]
        .as_array()
        .expect("方法列表");
    assert_eq!(methods.len(), 2);
    assert_eq!(methods[0]["signature"], "Lcom/example/Foo;-><init>()V");
    assert_eq!(methods[1]["signature"], "Lcom/example/Foo;->bar(I)V");
    assert_eq!(methods[1]["has_code"], true);
}

/// 真实 APK（M2b 的端到端验证）。
///
/// 样本路径取 `BITFLIP_TEST_APK`，默认是开发机上的那份；**样本不在就直接失败**，
/// 不静默跳过 —— 跳过会让 `cargo test` 看起来全绿，而这条测试一条真实数据都没看过。
#[test]
#[ignore = "需要本机真实 APK（32MB）；用 --ignored 手动跑"]
fn the_real_apk_renders_a_method_from_a_real_dex_member() {
    let path = std::env::var("BITFLIP_TEST_APK")
        .unwrap_or_else(|_| "C:\\Users\\Administrator\\Downloads\\ah-app-release.apk".to_owned());
    let apk = PathBuf::from(&path);
    assert!(
        apk.exists(),
        "找不到真实 APK：{}（用 BITFLIP_TEST_APK 指定）",
        apk.display()
    );

    // 用 core 的出口先挑一个**真有字节码**的方法（CLI 只做精确匹配，得先知道标识）。
    let session =
        bitflip_core::Session::open(&apk, bitflip_core::OpenOptions::default()).expect("打开 APK");
    let bytes = bitflip_core::dex::read_member(&session, "classes.dex").expect("读 classes.dex");
    let structure = bitflip_core::dex::parse(&bytes).expect("解析 classes.dex");
    let method = (0..structure.method_count())
        .find(|index| structure.methods.get(*index).is_some_and(|m| m.has_code()))
        .expect("classes.dex 里应当有带字节码的方法");
    let signature = structure.method_signature(method).expect("方法标识");

    let mut one = args(&apk);
    one.member = Some("classes.dex".to_owned());
    one.method = Some(signature.clone());
    let report = build_dex_text(&one).expect("方法报告");

    assert!(report.contains(&format!("方法：{signature}")), "{report}");
    assert!(
        report.contains("符号解析："),
        "真实数据也必须交代符号解析情况：{report}"
    );
    let instructions = report
        .lines()
        .position(|line| line.starts_with("指令（"))
        .expect("要有指令段");
    // 指令段之后至少一行指令，再之后是 CFG 段。
    assert!(
        report.lines().nth(instructions + 1).is_some_and(|line| line
            .trim_start()
            .starts_with(|c: char| c.is_ascii_hexdigit())),
        "指令段后面应当跟指令行：{report}"
    );
    assert!(report.contains("CFG："), "默认要打印文本 CFG：{report}");

    // 同一个方法走 JSON：计数必须与文本一致。
    let mut json_args = args(&apk);
    json_args.member = Some("classes.dex".to_owned());
    json_args.method = Some(signature.clone());
    json_args.json = true;
    let value: serde_json::Value =
        serde_json::from_str(&build_dex_json(&json_args).expect("JSON")).expect("合法 JSON");
    assert_eq!(value["format_version"], 1);
    assert!(
        value["method"]["instruction_count"].as_u64().unwrap_or(0) > 0,
        "真实方法应当有指令：{value}"
    );

    // 真实数据的输出要看得见（`--nocapture`）：CLAUDE.md §7 要求验证时看数据层输出，
    // 不能只看测试是不是绿的。整份指令可能上千行，所以只印头部与 CFG 汇总行。
    println!("---- 真实 APK：选中方法 {signature}（classes.dex）----");
    for line in report.lines().take(6) {
        println!("{line}");
    }
    for line in report.lines().filter(|line| line.starts_with("CFG：")) {
        println!("{line}");
    }
    println!(
        "---- JSON：指令 {} 条、unsupported {}、unavailable {}、未连上目标 {} ----",
        value["method"]["instruction_count"],
        value["method"]["unsupported_operands"],
        value["method"]["unavailable_operands"],
        value["method"]["unresolved_edge_targets"],
    );
}
