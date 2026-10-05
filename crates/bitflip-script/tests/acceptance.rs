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
