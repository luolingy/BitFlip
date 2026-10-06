//! M7 脚本层验收测试（PLAN §M7）。
//!
//! 这些测试守的是**失效模式**，不是"功能跑通了"：
//!
//! - 死循环必须能被掐断，**且掐断之后引擎还能用**（只测"能中断"是不够的，
//!   一个"中断即报废"的引擎在控制台里等于每超时一次就要重启服务）；
//! - 被中断的脚本**一条写入都不许留下**（半成品是最危险的结局）；
//! - 错误必须带行号（用户报"第 3 行错了"要能核对）；
//! - 超出 JS 精度上限的地址**必须报错**，不许悄悄截断。

use std::time::Duration;

use bitflip_core::{AnnotationKind, ProjectStore};
use bitflip_script::{Host, Limits, ScriptEngine, ScriptError, SCRIPT_API_VERSION};

/// 临时工程库的三个把手：路径、目标哈希（重开时要一致）。
struct TempStore {
    _dir: tempfile::TempDir,
    path: std::path::PathBuf,
    hash: String,
}

impl TempStore {
    fn new() -> Self {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("script-test.bfp");
        let hash = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
        ProjectStore::create(&path, hash, 4096, "test", 1_700_000_000).expect("创建工程库");
        Self {
            _dir: dir,
            path,
            hash: hash.to_string(),
        }
    }

    /// 重新打开工程库 —— 断言走的是**真正落盘**的数据，而不是内存里的对象。
    fn reopen(&self) -> ProjectStore {
        ProjectStore::open(&self.path, &self.hash).expect("重新打开工程库")
    }

    fn take(&self) -> ProjectStore {
        ProjectStore::open(&self.path, &self.hash).expect("打开工程库")
    }
}

/// 短超时的引擎：让超时测试跑得快，又不至于因为 1ms 太苛刻而闪烁。
fn engine_with_timeout_ms(ms: u64) -> ScriptEngine {
    ScriptEngine::new(Limits {
        timeout: Duration::from_millis(ms),
    })
    .expect("创建脚本引擎")
}

// ---------------------------------------------------------------------------
// 验收 3：脚本 API 有版本号
// ---------------------------------------------------------------------------

#[test]
fn script_api_version_is_reported_to_the_script() {
    let engine = engine_with_timeout_ms(2_000);
    let host = Host::new(None);

    let source = format!(
        "bitflip.log(bitflip.apiVersion);\n\
         if (bitflip.apiVersion !== {SCRIPT_API_VERSION}) {{ throw new Error('版本不一致'); }}"
    );
    let outcome = engine.run(&host, &source).expect("版本查询应当成功");

    assert_eq!(outcome.logs.len(), 1, "应当收到一条日志");
    assert_eq!(outcome.logs[0].message, SCRIPT_API_VERSION.to_string());
}

#[test]
fn the_backtick_global_name_is_the_one_scripts_actually_see() {
    let engine = engine_with_timeout_ms(2_000);
    let host = Host::new(None);

    // 用 typeof 而不是直接访问：直接访问会抛 ReferenceError，
    // 那样测出来的是"报错了"，不是"这个名字存在"。
    let outcome = engine
        .run(&host, "bitflip.log(typeof bitflip);")
        .expect("typeof 不应当抛异常");
    assert_eq!(outcome.logs[0].message, "object");
}

// ---------------------------------------------------------------------------
// 验收 2：死循环可被中断，不影响主进程
// ---------------------------------------------------------------------------

#[test]
fn an_infinite_loop_is_interrupted_and_the_engine_still_works_afterwards() {
    let engine = engine_with_timeout_ms(200);
    let host = Host::new(None);

    let err = engine
        .run(&host, "while (true) {}")
        .expect_err("死循环必须被中断，而不是跑到底");
    assert!(
        matches!(err, ScriptError::Timeout { .. }),
        "必须报成超时而不是'脚本运行错误'（用户要做的事完全不同）：{err:?}"
    );

    // 关键的一半：中断之后引擎还能用吗？只能中断一次的实现等于每超时一次
    // 就要重启服务，控制台里完全没法用。
    let outcome = engine
        .run(&host, "bitflip.log('alive');")
        .expect("中断之后引擎必须仍然可用");
    assert_eq!(outcome.logs.len(), 1);
    assert_eq!(outcome.logs[0].message, "alive");
}

#[test]
fn a_long_running_computation_is_interrupted_too() {
    let engine = engine_with_timeout_ms(200);
    let host = Host::new(None);

    // 不是"肉眼可见的死循环"，而是正常写法但算不完 —— 更接近真实事故
    let err = engine
        .run(
            &host,
            "let s = 0; for (let i = 0; i < 1e18; i++) { s += i; }",
        )
        .expect_err("算不完的循环也必须被掐断");
    assert!(matches!(err, ScriptError::Timeout { .. }), "{err:?}");
}

// ---------------------------------------------------------------------------
// 中断 / 失败必须不留半成品
// ---------------------------------------------------------------------------

#[test]
fn writes_from_an_interrupted_script_are_rolled_back_entirely() {
    let store = TempStore::new();
    let engine = engine_with_timeout_ms(200);
    let host = Host::new(Some(store.take()));

    let source = r#"
        bitflip.setName("0000000000401000", "第一个");
        bitflip.setName("0000000000401010", "第二个");
        bitflip.setComment("0000000000401020", "第三个");
        while (true) {}
    "#;
    let err = engine.run(&host, source).expect_err("应当超时");
    assert!(matches!(err, ScriptError::Timeout { .. }), "{err:?}");

    let reopened = store.reopen();
    assert_eq!(
        reopened.len(),
        0,
        "被中断的脚本不许留下任何写入 —— 半成品会被误认为'跑完了'"
    );
}

#[test]
fn writes_from_a_failed_script_are_rolled_back_entirely() {
    let store = TempStore::new();
    let engine = engine_with_timeout_ms(2_000);
    let host = Host::new(Some(store.take()));

    let source = r#"
        bitflip.setName("0000000000401000", "第一个");
        bitflip.setComment("0000000000401000", "注释");
        throw new Error("我故意失败的");
    "#;
    let err = engine.run(&host, source).expect_err("应当失败");
    assert!(matches!(err, ScriptError::Runtime { .. }), "{err:?}");

    assert_eq!(store.reopen().len(), 0, "抛异常的脚本同样不许留下半成品");
}

#[test]
fn a_script_that_finishes_normally_commits_every_staged_write() {
    let store = TempStore::new();
    let engine = engine_with_timeout_ms(2_000);
    let host = Host::new(Some(store.take()));

    let source = r#"
        bitflip.setName("0000000000401000", "第一个");
        bitflip.setComment("0000000000401000", "同一个地址的注释");
        bitflip.setName("0000000000401010", "第二个");
    "#;
    let outcome = engine.run(&host, source).expect("正常脚本应当成功");
    assert_eq!(outcome.committed, 3, "提交条数要与暂存条数一致");

    let reopened = store.reopen();
    assert_eq!(reopened.len(), 3);
    assert_eq!(
        reopened
            .get(0x401000, AnnotationKind::Name)
            .and_then(|a| a.text),
        Some("第一个".to_string())
    );
    assert_eq!(
        reopened
            .get(0x401000, AnnotationKind::Comment)
            .and_then(|a| a.text),
        Some("同一个地址的注释".to_string()),
        "同一地址的不同类别必须各占一行"
    );
}

#[test]
fn a_script_reads_back_its_own_pending_writes() {
    let store = TempStore::new();
    let engine = engine_with_timeout_ms(2_000);
    let host = Host::new(Some(store.take()));

    // "没有名字才命名"是批处理脚本最常见的写法。如果读不到自己的暂存，
    // 这类脚本会对同一个地址重复劳动，或者对着已有名字再改一遍。
    let source = r#"
        bitflip.setComment("0000000000401000", "刚写的");
        bitflip.log(bitflip.get("0000000000401000", "comment"));
        bitflip.log(String(bitflip.get("0000000000402000", "comment")));
        bitflip.log(bitflip.stagedCount());
    "#;
    let outcome = engine.run(&host, source).expect("应当成功");
    assert_eq!(outcome.logs[0].message, "刚写的");
    assert_eq!(outcome.logs[1].message, "null", "没写过的地址应当读回 null");
    assert_eq!(outcome.logs[2].message, "1");
}

#[test]
fn a_script_generates_a_patch_and_reads_it_back_as_hex() {
    let store = TempStore::new();
    let engine = engine_with_timeout_ms(2_000);
    let host = Host::new(Some(store.take()));

    // 补丁以**字节**落库，不是文本。两种输入形式各用一次：
    // 字符串是逆向工程里的通用写法，数组是脚本算出来的字节最自然的落点。
    let source = r#"
        bitflip.setPatch("0000000000401000", "90 90");
        bitflip.setPatch("0000000000401010", [0x48, 0x31, 0xc0]);
        bitflip.log(bitflip.get("0000000000401000", "patch"));
        bitflip.log(bitflip.get("0000000000401010", "patch"));
        bitflip.log(bitflip.stagedCount());
    "#;
    let outcome = engine.run(&host, source).expect("应当成功");
    assert_eq!(outcome.committed, 2);
    // 读回来的是十六进制字符串：`get` 只取 `text` 的话这里会拿到 null，
    // 而"脚本必须能读到自己刚写的东西"没有例外。
    assert_eq!(outcome.logs[0].message, "9090");
    assert_eq!(outcome.logs[1].message, "4831c0");
    assert_eq!(outcome.logs[2].message, "2");

    let reopened = store.reopen();
    let patch = reopened
        .get(0x401000, AnnotationKind::Patch)
        .expect("补丁应当落库");
    assert_eq!(
        patch.patch_bytes(),
        Some(vec![0x90, 0x90]),
        "补丁必须按字节存，而不是把 \"90 90\" 当注释文本存下来"
    );
    assert_eq!(
        patch.text, None,
        "补丁不是注释：`text` 必须是 None，否则界面会把它按文本渲染"
    );
    assert_eq!(
        reopened
            .get(0x401010, AnnotationKind::Patch)
            .and_then(|a| a.patch_bytes()),
        Some(vec![0x48, 0x31, 0xc0])
    );
}

#[test]
fn every_hex_spelling_of_the_same_patch_is_the_same_patch() {
    let store = TempStore::new();
    let engine = engine_with_timeout_ms(2_000);
    let host = Host::new(Some(store.take()));

    let source = r#"
        bitflip.setPatch("0000000000401000", "9090");
        bitflip.setPatch("0000000000401001", "90,90");
        bitflip.setPatch("0000000000401002", "0x90 0x90");
        bitflip.setPatch("0000000000401003", "0X90:0x90");
        bitflip.setPatch("0000000000401004", [144, 144]);
        for (const a of ["0000000000401000", "0000000000401001", "0000000000401002", "0000000000401003", "0000000000401004"]) {
            bitflip.log(a.slice(-1) + "=" + bitflip.get(a, "patch"));
        }
    "#;
    let outcome = engine.run(&host, source).expect("应当成功");
    for (index, log) in outcome.logs.iter().enumerate() {
        assert!(
            log.message.ends_with("=9090"),
            "第 {index} 种写法没解析成同一个补丁：{}",
            log.message
        );
    }
}

#[test]
fn a_malformed_patch_is_rejected_by_naming_the_problem_and_stages_nothing() {
    // 补丁写错了会改坏用户的目标文件。这里逐条钉住"拒绝执行"而不是"尽力而为"。
    let cases: &[(&str, &str)] = &[
        (r#"bitflip.setPatch("0000000000401000", "9");"#, "偶数"),
        (
            r#"bitflip.setPatch("0000000000401000", "zz");"#,
            "非十六进制",
        ),
        (r#"bitflip.setPatch("0000000000401000", "");"#, "不能为空"),
        (
            r#"bitflip.setPatch("0000000000401000", "   ");"#,
            "不能为空",
        ),
        (r#"bitflip.setPatch("0000000000401000", [256]);"#, "0..255"),
        (r#"bitflip.setPatch("0000000000401000", [1.5]);"#, "0..255"),
        (
            r#"bitflip.setPatch("0000000000401000", ["90"]);"#,
            "不是数字",
        ),
        (
            r#"bitflip.setPatch("0000000000401000", 5);"#,
            "十六进制字符串",
        ),
    ];

    for (source, expected) in cases {
        let store = TempStore::new();
        let engine = engine_with_timeout_ms(2_000);
        let host = Host::new(Some(store.take()));

        let error = engine.run(&host, source).expect_err("非法补丁必须报错");
        let message = error.to_string();
        assert!(
            message.contains(expected),
            "错误里必须出现 {expected:?}，实际：{message}"
        );
        assert_eq!(
            store.reopen().len(),
            0,
            "被拒绝的补丁不得留下任何写入（{source}）"
        );
    }
}

#[test]
fn a_patch_larger_than_the_limit_is_refused_with_the_actual_size() {
    let engine = engine_with_timeout_ms(2_000);
    let host = Host::new(None);

    let error = engine
        .run(
            &host,
            r#"bitflip.setPatch("0000000000401000", new Array(65537).fill(0));"#,
        )
        .expect_err("超长补丁必须被拒绝");
    let message = error.to_string();
    assert!(
        message.contains("65537") && message.contains("65536"),
        "错误里要同时给出实际长度与上限，实际：{message}"
    );
}

#[test]
fn log_accepts_any_value_the_way_a_console_does() {
    let engine = engine_with_timeout_ms(2_000);
    let host = Host::new(None);

    // 控制台里 `bitflip.log(count)` 是最自然的写法。如果日志函数只接受字符串，
    // 用户会撞上一句莫名其妙的类型错误 —— 这不是用户的问题，是 API 的问题。
    let source = r#"
        bitflip.log(1 + 1);
        bitflip.log([1, 'a']);
        bitflip.log({});
        bitflip.log(null);
        bitflip.log(bitflip.apiVersion);
    "#;
    let outcome = engine.run(&host, source).expect("日志应当接受任何值");
    let messages: Vec<&str> = outcome.logs.iter().map(|l| l.message.as_str()).collect();
    assert_eq!(
        messages,
        vec!["2", "1,a", "[object Object]", "null", "1"],
        "日志按 JS 的 String() 语义转换"
    );
}

#[test]
fn warn_and_error_are_recorded_at_their_own_levels() {
    let engine = engine_with_timeout_ms(2_000);
    let host = Host::new(None);

    let outcome = engine
        .run(
            &host,
            "bitflip.log('普通');\nbitflip.warn('警告');\nbitflip.error('错误');",
        )
        .expect("应当成功");

    let levels: Vec<&str> = outcome.logs.iter().map(|l| l.level.as_str()).collect();
    assert_eq!(levels, vec!["info", "warn", "error"]);
}

// ---------------------------------------------------------------------------
// 验收：错误必须带行号
// ---------------------------------------------------------------------------

#[test]
fn a_syntax_error_carries_its_line_number() {
    let engine = engine_with_timeout_ms(2_000);
    let host = Host::new(None);

    let err = engine
        .run(&host, "bitflip.log('ok');\nlet broken = ;\n")
        .expect_err("语法错误必须报错");

    match err {
        ScriptError::Syntax { line, .. } => {
            assert_eq!(line, Some(2), "语法错误必须指出第 2 行");
        }
        other => panic!("应当报成语法错误，实际：{other:?}"),
    }
}

#[test]
fn a_runtime_error_carries_its_line_number() {
    let engine = engine_with_timeout_ms(2_000);
    let host = Host::new(None);

    let err = engine
        .run(&host, "bitflip.log('ok');\nnoSuchFunction();\n")
        .expect_err("运行时错误必须报错");

    match err {
        ScriptError::Runtime { line, message, .. } => {
            assert_eq!(
                line,
                Some(2),
                "运行时错误必须指出第 2 行（实际消息：{message}）"
            );
        }
        other => panic!("应当报成运行时错误，实际：{other:?}"),
    }
}

// ---------------------------------------------------------------------------
// 地址与类别的诚实性
// ---------------------------------------------------------------------------

#[test]
fn a_number_address_beyond_the_safe_integer_range_is_rejected_not_truncated() {
    let engine = engine_with_timeout_ms(2_000);
    let host = Host::new(None);

    // 2^53-1 之上 JS 已经无法精确表示。静默截断会把注释写到**另一个函数**上，
    // 而结果看起来完全正常 —— 这是本 crate 最不能接受的一类失效。
    let err = engine
        .run(&host, "bitflip.setName(9007199254740993, 'x');")
        .expect_err("超范围地址必须报错");

    match err {
        ScriptError::Runtime { message, .. } => {
            assert!(
                message.contains("安全整数") || message.contains("2^53"),
                "错误消息要说明为什么，实际：{message}"
            );
        }
        other => panic!("应当报成运行时错误，实际：{other:?}"),
    }
}

#[test]
fn an_unparseable_address_is_rejected() {
    let engine = engine_with_timeout_ms(2_000);
    let host = Host::new(None);

    let err = engine
        .run(&host, "bitflip.setName('not-an-address', 'x');")
        .expect_err("非法地址必须报错");
    assert!(matches!(err, ScriptError::Runtime { .. }), "{err:?}");
}

#[test]
fn an_unknown_annotation_kind_is_rejected_with_the_available_values() {
    let engine = engine_with_timeout_ms(2_000);
    let host = Host::new(None);

    let err = engine
        .run(&host, "bitflip.get('0000000000401000', 'not-a-kind');")
        .expect_err("未知类别必须报错");
    match err {
        ScriptError::Runtime { message, .. } => {
            assert!(
                message.contains("comment") && message.contains("name"),
                "错误消息要列出可用取值，实际：{message}"
            );
        }
        other => panic!("应当报成运行时错误，实际：{other:?}"),
    }
}

#[test]
fn both_hex_string_forms_and_plain_numbers_name_the_same_address() {
    let store = TempStore::new();
    let engine = engine_with_timeout_ms(2_000);
    let host = Host::new(Some(store.take()));

    // 三种写法都指向 0x401000：定长十六进制（规范形式）、0x 前缀、JS 数字。
    // 它们必须落到同一行，否则"只有一个地址规范"的约定就破了。
    let source = r#"
        bitflip.setName("0000000000401000", "定长");
        bitflip.setComment("0x401000", "带前缀");
        bitflip.setName(4198400, "数字");
    "#;
    engine.run(&host, source).expect("应当成功");

    let reopened = store.reopen();
    assert_eq!(reopened.len(), 2, "写的是同一个地址的两个类别");
    assert_eq!(
        reopened
            .get(0x401000, AnnotationKind::Name)
            .and_then(|a| a.text),
        Some("数字".to_string()),
        "后写的应当胜出"
    );
}

#[test]
fn writing_without_a_project_store_fails_loudly_instead_of_pretending() {
    let engine = engine_with_timeout_ms(2_000);
    let host = Host::new(None);

    // 没有打开工程库时脚本的写入无处可存。绝不能当作成功 ——
    // 用户会以为注释已经保存了。
    let err = engine
        .run(&host, "bitflip.setName('0000000000401000', 'x');")
        .expect_err("没有工程库时写入必须失败");
    match err {
        ScriptError::Commit {
            committed, total, ..
        } => {
            assert_eq!((committed, total), (0, 1));
        }
        other => panic!("应当报成提交失败，实际：{other:?}"),
    }
}

#[test]
fn logs_are_per_run_not_accumulated() {
    let engine = engine_with_timeout_ms(2_000);
    let host = Host::new(None);

    let first = engine.run(&host, "bitflip.log('第一次');").expect("第一次");
    assert_eq!(first.logs.len(), 1);

    let second = engine.run(&host, "bitflip.log('第二次');").expect("第二次");
    assert_eq!(
        second.logs.len(),
        1,
        "第二次运行不该带上第一次的日志，否则控制台会越看越乱"
    );
    assert_eq!(second.logs[0].message, "第二次");
}

// ---------------------------------------------------------------------------
// 外部取消（服务层的"停止"按钮）
// ---------------------------------------------------------------------------

/// 死循环 + 很长的超时，只能靠外部取消结束。
const FOREVER: &str = "while (true) { }";

#[test]
fn an_external_cancel_stops_the_script_and_is_reported_as_cancelled() {
    let engine = engine_with_timeout_ms(60_000);
    let token = engine.cancel_token();
    let host = Host::new(None);

    // 必须在另一条线程上取消：脚本跑起来之后本线程就被占住了。
    let canceller = std::thread::spawn(move || {
        // 等到脚本真的开始跑再取消，否则取消请求会因为"没有脚本在运行"被忽略
        // （那正是 CancelToken 的语义，见下一个用例）。
        while !token.is_running() {
            std::thread::sleep(Duration::from_millis(5));
        }
        token.cancel()
    });

    let err = engine
        .run(&host, FOREVER)
        .expect_err("死循环脚本只能以错误结束");
    assert!(
        matches!(err, ScriptError::Cancelled),
        "用户按的停止必须报成\"已取消\"，不能报成超时 —— \
         否则用户会去优化一段本来没问题的脚本。实际：{err:?}"
    );
    assert!(
        canceller.join().expect("取消线程"),
        "取消请求应当被接受（返回 true）"
    );

    // 取消之后引擎必须还能用：不能每次点停止就得重启服务。
    let outcome = engine
        .run(&host, "bitflip.log('取消后仍可用');")
        .expect("取消之后引擎应当仍然可用");
    assert_eq!(outcome.logs[0].message, "取消后仍可用");
}

#[test]
fn a_cancelled_script_leaves_no_writes_behind() {
    let store = TempStore::new();
    let engine = engine_with_timeout_ms(60_000);
    let token = engine.cancel_token();
    let host = Host::new(Some(store.take()));

    let canceller = std::thread::spawn(move || {
        while !token.is_running() {
            std::thread::sleep(Duration::from_millis(5));
        }
        token.cancel()
    });

    // 先写 3 条、再死循环：这 3 条绝不能落盘。
    let source = "\
        bitflip.setComment('0000000000401000', 'a');\n\
        bitflip.setComment('0000000000401004', 'b');\n\
        bitflip.setComment('0000000000401008', 'c');\n\
        while (true) { }";
    let err = engine.run(&host, source).expect_err("应当被取消");
    assert!(matches!(err, ScriptError::Cancelled), "{err:?}");
    canceller.join().expect("取消线程");

    assert_eq!(
        store.reopen().len(),
        0,
        "被取消的脚本不许留下写了一半的标注"
    );
}

#[test]
fn a_cancel_with_no_running_script_is_ignored_rather_than_poisoning_the_next_run() {
    let engine = engine_with_timeout_ms(60_000);
    let token = engine.cancel_token();

    // 没有任何脚本在跑时点停止 —— 这是用户手快，不是错误。
    assert!(
        !token.cancel(),
        "没有在跑的脚本时取消应当返回 false，好让界面如实说\"没有可取消的运行\""
    );

    // 关键：这个落空的取消不能把下一次运行掐掉。
    // 若把取消实现成一个只在开始时重置的全局标志，这里就会挂。
    let host = Host::new(None);
    let outcome = engine
        .run(&host, "bitflip.log('照常跑完');")
        .expect("落空的取消请求不该影响下一次运行");
    assert_eq!(outcome.logs[0].message, "照常跑完");
}

// ---------------------------------------------------------------------------
// 进度上报
// ---------------------------------------------------------------------------

#[test]
fn a_script_can_report_batch_progress() {
    let engine = engine_with_timeout_ms(5_000);
    let host = Host::new(None);

    engine
        .run(&host, "bitflip.progress(3, 10, '正在处理函数');")
        .expect("上报进度应当成功");

    let progress = host.progress().expect("应当能读到进度");
    assert_eq!(progress.done, 3);
    assert_eq!(progress.total, Some(10));
    assert_eq!(progress.label.as_deref(), Some("正在处理函数"));
}

#[test]
fn progress_without_a_total_is_reported_as_unknown_rather_than_zero() {
    let engine = engine_with_timeout_ms(5_000);
    let host = Host::new(None);

    engine
        .run(&host, "bitflip.progress(7);")
        .expect("不带总数的上报应当成功");

    let progress = host.progress().expect("应当能读到进度");
    assert_eq!(progress.done, 7);
    assert_eq!(
        progress.total, None,
        "总数未知时必须报 null，不能填 0 —— 界面会显示成 0% 而看起来像卡住"
    );
}

#[test]
fn progress_is_cleared_between_runs() {
    let engine = engine_with_timeout_ms(5_000);
    let host = Host::new(None);

    engine
        .run(&host, "bitflip.progress(9, 10);")
        .expect("第一次");
    assert!(host.progress().is_some());

    // 第二次没有上报任何进度：不能把上一次的 90% 留在那里，
    // 否则用户看到进度条停在 90% 会以为这一次卡住了。
    engine
        .run(&host, "bitflip.log('不给进度');")
        .expect("第二次");
    assert!(
        host.progress().is_none(),
        "上一次的进度必须清掉，否则进度条会停在一个与本次无关的位置"
    );
}
