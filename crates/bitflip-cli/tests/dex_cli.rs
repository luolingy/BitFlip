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

use bitflip_cli::{
    build_dex_json, build_dex_text, run_export, DexArgs, ExportArgs, RawOverrideArgs,
};

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
        list_classes: false,
        search: None,
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

/// 一个只填了本测试会用到字段的 `export` 参数集（M2c）。
///
/// `format` 缺省是 `asm-intel`（与 CLI 的缺省一致）：要测 DEX 那条路时显式改它，
/// 这样才能顺带断言"机器码格式 + DEX 选择器"会被拒绝。
fn export_args(target: &Path) -> ExportArgs {
    ExportArgs {
        target: target.to_path_buf(),
        format: "asm-intel".to_owned(),
        out: None,
        from: None,
        to: None,
        function: None,
        member: None,
        class: None,
        search: None,
        method: None,
        no_instructions: false,
        no_cfg: false,
        no_symbols: false,
        no_bytes: false,
        no_source: false,
        max_functions: 512,
        limit_bytes: None,
        force: false,
        summary: true,
        verbose: false,
        raw: RawOverrideArgs::default(),
    }
}

/// M2c：`export` 的 DEX 选择器（合成样本，默认就跑）。
///
/// 这里盯的是**这一层**的责任：开关 → `ExportOptions` 的映射、把结果写到文件、
/// 以及"选择器用错格式就报错"。快照本身的字段由 core 的测试逐项钉住。
#[test]
fn the_export_command_writes_a_dex_snapshot_and_refuses_mixed_selectors() {
    let dir = tempfile::tempdir().expect("临时目录");
    let target = write_minimal_dex(&dir);

    let json_out = dir.path().join("foo.json");
    let mut json_args = export_args(&target);
    json_args.format = "dex-json".to_owned();
    json_args.class = Some("Lcom/example/Foo;".to_owned());
    json_args.out = Some(json_out.clone());
    run_export(&json_args).expect("导出 DEX 快照");
    let document: serde_json::Value =
        serde_json::from_str(&std::fs::read_to_string(&json_out).expect("读回导出"))
            .expect("合法 JSON");
    assert_eq!(document["member"], "minimal.dex");
    assert_eq!(document["classes"][0]["descriptor"], "Lcom/example/Foo;");
    assert_eq!(document["meta"]["format_versions"]["dex"], 1);
    assert_eq!(document["totals"]["methods_written"], 2);

    let smali_out = dir.path().join("foo.smali");
    let mut smali_args = export_args(&target);
    smali_args.format = "dex-smali".to_owned();
    smali_args.class = Some("Lcom/example/Foo;".to_owned());
    smali_args.out = Some(smali_out.clone());
    run_export(&smali_args).expect("导出 smali 风格文本");
    let text = std::fs::read_to_string(&smali_out).expect("读回 smali");
    assert!(
        text.starts_with("# bitflip-export v1 format=dex-smali"),
        "文本格式也要自述头：{text}"
    );
    assert!(text.contains(".class Lcom/example/Foo;"));

    // 机器码格式 + DEX 选择器：**报错**，不静默忽略。
    // （这条同时钉住"选项检查要在建反汇编之前"：`.dex` 目标建不出反汇编，
    //   若顺序反了，用户看到的会是"这个目标不能反汇编"。）
    let mut wrong = export_args(&target);
    wrong.member = Some("minimal.dex".to_owned());
    let error = run_export(&wrong).expect_err("--member 给 asm-intel 必须报错");
    assert!(
        error.to_string().contains("member"),
        "要点名是哪个选择器：{error}"
    );

    // DEX 格式 + 机器码选择器：同样报错。
    let mut wrong = export_args(&target);
    wrong.format = "dex-json".to_owned();
    wrong.function = Some("0x100".to_owned());
    let error = run_export(&wrong).expect_err("--function 给 dex-json 必须报错");
    assert!(
        error.to_string().contains("--function"),
        "要点名是哪个选项：{error}"
    );
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

/// `--list-classes`：把所有类列出来，并交代"扫了多少、匹配多少、列出多少"。
///
/// 为什么要有这条路：`--class` 是精确匹配，而混淆过的 APK 里类名是
/// `L_COROUTINE/ArtificialStackFrames;` 这种东西 —— 没有列表，命令行用户
/// 实际上找不到类，只能先用别的工具查出全名。
#[test]
fn listing_classes_reports_totals_and_method_counts() {
    let dir = tempfile::tempdir().expect("临时目录");
    let target = write_minimal_dex(&dir);

    let mut list = args(&target);
    list.list_classes = true;
    let text = build_dex_text(&list).expect("列类");

    assert!(
        text.contains("类列表（全部；精确匹配用 `--class`）"),
        "要说清这里是列表、不是精确匹配：{text}"
    );
    assert!(
        text.contains("minimal.dex：扫描 1 个类，匹配 1 个"),
        "要给出每个文件的扫描与匹配数：{text}"
    );
    assert!(
        text.contains("Lcom/example/Foo;  方法 2 个（2 有字节码 / 0 无）"),
        "每个类要带方法数与有没有字节码：{text}"
    );
    assert!(
        text.contains("合计：扫描 1 个类，匹配 1 个，列出 1 个。"),
        "合计行是「这个列表可不可信」的唯一依据：{text}"
    );
    assert!(
        !text.contains("未列出"),
        "只有一个类且没截断时不该出现截断说明：{text}"
    );
}

/// `--search`：**子串**、大小写不敏感；搜不到是合法答案，但必须说清扫了多少个。
#[test]
fn search_matches_a_case_insensitive_substring() {
    let dir = tempfile::tempdir().expect("临时目录");
    let target = write_minimal_dex(&dir);

    // `--search` 隐含列表模式（用户不必再敲一遍 `--list-classes`）。
    let mut hit = args(&target);
    hit.search = Some("foo".to_owned());
    let text = build_dex_text(&hit).expect("搜索");
    assert!(
        text.contains("描述符里含「foo」的类"),
        "要说明匹配口径与关键词：{text}"
    );
    assert!(text.contains("匹配 1 个"), "小写子串要命中 Foo：{text}");
    assert!(
        !text.contains("没有类匹配"),
        "命中时不该出现「没找到」的说明：{text}"
    );

    // 搜不到：退出码 0（合法答案），但要说清扫了多少、匹配多少，并给下一步提示。
    let mut miss = args(&target);
    miss.search = Some("Activity".to_owned());
    let text = build_dex_text(&miss).expect("搜不到不是错误");
    assert!(text.contains("扫描 1 个类，匹配 0 个"), "{text}");
    assert!(
        text.contains("合计：扫描 1 个类，匹配 0 个，列出 0 个。"),
        "{text}"
    );
    assert!(
        text.contains("没有类匹配这个子串"),
        "搜不到要给人下一步：{text}"
    );
}

/// 选择器互斥：两条路（文本与 JSON）都必须报错，不能静默只看其中一个。
///
/// 这条测试盯的是一个真实存在过的缺陷：JSON 分支早先是 `if method … else if class …`，
/// 同时给 `--class` 与 `--method` 时静默只输出方法 —— 命令行给了两个互斥选择器，
/// 输出里一个字都不提。
#[test]
fn conflicting_selectors_are_rejected_on_both_paths() {
    let dir = tempfile::tempdir().expect("临时目录");
    let target = write_minimal_dex(&dir);

    let mut both = args(&target);
    both.class = Some("Lcom/example/Foo;".to_owned());
    both.method = Some("Lcom/example/Foo;->bar(I)V".to_owned());
    let error = build_dex_text(&both).expect_err("文本路径要拒绝");
    assert!(format!("{error:#}").contains("只能给一个"), "{error:#}");

    both.json = true;
    let error = build_dex_json(&both).expect_err("JSON 路径也要拒绝");
    assert!(format!("{error:#}").contains("只能给一个"), "{error:#}");

    // 列表与精确选择器也不能同时给。
    let mut mixed = args(&target);
    mixed.search = Some("foo".to_owned());
    mixed.class = Some("Lcom/example/Foo;".to_owned());
    let error = build_dex_text(&mixed).expect_err("列表与 --class 要拒绝");
    let message = format!("{error:#}");
    assert!(message.contains("--search"), "{message}");
    assert!(message.contains("不能同时给"), "{message}");
}

/// `--list-classes --json`：稳定的字段形状（`total` 说共几个，`listed` 说给了几个）。
#[test]
fn class_list_json_has_a_stable_shape() {
    let dir = tempfile::tempdir().expect("临时目录");
    let target = write_minimal_dex(&dir);

    let mut search = args(&target);
    search.search = Some("foo".to_owned());
    search.json = true;
    search.limit = 1;
    let value: serde_json::Value =
        serde_json::from_str(&build_dex_json(&search).expect("JSON")).expect("合法 JSON");

    assert_eq!(value["format_version"], 1);
    assert_eq!(value["class_list"]["search"], "foo");
    assert_eq!(value["class_list"]["total"], 1);
    assert_eq!(value["class_list"]["listed"], 1);
    assert_eq!(value["class_list"]["limit"], 1);
    assert_eq!(value["class_list"]["skipped_without_descriptor"], 0);
    assert_eq!(
        value["class_list"]["classes"][0]["descriptor"],
        "Lcom/example/Foo;"
    );
    assert_eq!(value["class_list"]["classes"][0]["member"], "minimal.dex");
    assert_eq!(value["class_list"]["classes"][0]["short_name"], "Foo");
    assert_eq!(value["class_list"]["classes"][0]["method_count"], 2);
    assert_eq!(value["class_list"]["classes"][0]["methods_with_code"], 2);
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

    // ── 列表 / 搜索：混淆过的 APK 里 `--class` 没法手打，这条路是找类的实际入口
    let mut list_args = args(&apk);
    list_args.list_classes = true;
    list_args.limit = 3;
    let listed = build_dex_text(&list_args).expect("列前几个类");
    assert!(
        listed.contains("合计：扫描 "),
        "列表要交代扫了多少、匹配了多少：{listed}"
    );
    assert!(
        listed.contains("有 ") && listed.contains("未列出（`--limit 0` 可全部列出）"),
        "截断必须写在输出里：{listed}"
    );
    for line in listed.lines().take(10) {
        println!("{line}");
    }

    // 拿一个真实的类描述符去搜它自己：至少命中 1 个，并且列出该描述符。
    let descriptor = structure.class_descriptor(0).expect("第一个类应当有描述符");
    let mut search_args = args(&apk);
    search_args.member = Some("classes.dex".to_owned());
    search_args.search = Some(descriptor.to_owned());
    search_args.limit = 5;
    let found = build_dex_text(&search_args).expect("按描述符搜索");
    assert!(found.contains(descriptor), "搜它自己应当命中：{found}");

    // 混乱的 APK 上搜一个真实存在的短子串（取描述符的最后一段类名）。
    let short = descriptor
        .trim_end_matches(';')
        .rsplit('/')
        .next()
        .unwrap_or(descriptor)
        .to_owned();
    let mut fuzzy = args(&apk);
    fuzzy.member = Some("classes.dex".to_owned());
    fuzzy.search = Some(short.clone());
    let hits = build_dex_text(&fuzzy).expect("按短子串搜索");
    let total_line = hits
        .lines()
        .find(|line| line.starts_with("合计："))
        .expect("合计行");
    println!("---- 真实 APK：搜索子串「{short}」 -> {total_line} ----");
    assert!(
        !total_line.contains("匹配 0 个"),
        "搜一个刚刚见过存在的子串，不该是 0 个匹配：{hits}"
    );

    // 搜一个绝不可能出现的子串：必须是合法答案（不报错），且说清扫了多少个类。
    let mut miss = args(&apk);
    miss.member = Some("classes.dex".to_owned());
    miss.search = Some("zzz_no_such_class_zzz".to_owned());
    let empty = build_dex_text(&miss).expect("搜不到不是错误");
    assert!(empty.contains("匹配 0 个"), "搜不到要如实说 0 个：{empty}");
    assert!(
        empty.contains("扫描 "),
        "搜不到时也要说扫了多少个类，否则分不清'没匹配'与'没扫'：{empty}"
    );
    println!(
        "---- 真实 APK：搜不存在的子串 -> {} ----",
        empty
            .lines()
            .find(|line| line.starts_with("合计："))
            .unwrap_or("")
    );

    // 搜索走 JSON：`total`/`listed`/`limit` 三者要能对上。
    let mut json_search = args(&apk);
    json_search.member = Some("classes.dex".to_owned());
    json_search.search = Some(short);
    json_search.limit = 5;
    json_search.json = true;
    let value: serde_json::Value =
        serde_json::from_str(&build_dex_json(&json_search).expect("JSON")).expect("合法 JSON");
    let total = value["class_list"]["total"].as_u64().unwrap_or(0);
    let listed = value["class_list"]["listed"].as_u64().unwrap_or(0);
    assert!(total > 0, "JSON 也要有匹配：{value}");
    assert_eq!(listed, total.min(5), "{value}");
    assert_eq!(value["class_list"]["limit"], 5);
    assert_eq!(value["class_list"]["classes"][0]["member"], "classes.dex");
    assert!(
        value["class_list"]["classes"][0]["descriptor"]
            .as_str()
            .is_some_and(|d| d.starts_with('L')),
        "{value}"
    );

    // ── M2c：`export` 的 DEX 这条路在**真实 APK**上也要走通
    //    （单文件目标由合成样本那条测试覆盖，这里专门验归档容器）。
    let dir = tempfile::tempdir().expect("临时目录");
    let out = dir.path().join("real.dex.json");
    let mut dex_export = export_args(&apk);
    dex_export.format = "dex-json".to_owned();
    dex_export.member = Some("classes.dex".to_owned());
    dex_export.class = Some(descriptor.to_owned());
    dex_export.limit_bytes = Some(4 * 1024 * 1024);
    dex_export.out = Some(out.clone());
    run_export(&dex_export).expect("从真实 APK 导出 DEX 快照");
    let document: serde_json::Value =
        serde_json::from_str(&std::fs::read_to_string(&out).expect("读回导出")).expect("合法 JSON");
    assert_eq!(document["member"], "classes.dex");
    assert_eq!(document["role"], "主 dex");
    assert_eq!(document["meta"]["format_versions"]["dex"], 1);
    assert_eq!(document["classes"][0]["descriptor"], descriptor);
    assert!(
        document["classes"][0]["methods"]
            .as_array()
            .is_some_and(|methods| !methods.is_empty()),
        "真实类应当有方法：{document}"
    );
    println!(
        "---- 真实 APK：dex-json 导出 {} 个类 / {} 个方法（{} 字节）----",
        document["totals"]["classes_written"],
        document["totals"]["methods_written"],
        std::fs::metadata(&out).map(|meta| meta.len()).unwrap_or(0)
    );

    // 归档里有多个 DEX 时不给 `--member` 必须**报错并列出名字**：
    // 猜一个（通常猜 classes.dex）会让用户拿到一份别的文件的内容，
    // 而文件名还写着目标名。
    let mut ambiguous = export_args(&apk);
    ambiguous.format = "dex-json".to_owned();
    let error = run_export(&ambiguous).expect_err("多 DEX 不给 --member 必须报错");
    let message = error.to_string();
    assert!(message.contains("缺少 member 参数"), "{message}");
    assert!(
        message.contains("classes.dex") && message.contains("classes2.dex"),
        "报错要把可选名字列出来：{message}"
    );
    println!("---- 真实 APK：不给 --member -> {message} ----");
}
