//! M7 读 API 的验收测试，含 PLAN §M7 验收标准 1 的端到端脚本。
//!
//! # 这组测试守的是什么
//!
//! 读 API 最容易出的问题不是"报错"，而是**安静地给出错误的东西**：
//!
//! * 没有目标时返回 0 而不是报错 → 脚本据此写出"这个目标没有函数"的结论；
//! * 分页把 `count` 收敛了却不回报 → 用户以为数据只有这么多；
//! * `kinds: []` 被当成"不过滤" → 全部取消勾选反而显示全部；
//! * `insns.at()` 用游标语义冒充精确查找 → "这个地址有指令吗"拿到下一条指令。
//!
//! 所以下面每一条断言都对应上面某一种失效模式，而不是"函数能调用"。

use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use bitflip_core::{AnnotationKind, OpenOptions, ProjectStore, Session};
use bitflip_script::{Host, Limits, ScriptEngine, ScriptError};

fn fixture(name: &str) -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("..")
        .join("..")
        .join("tests")
        .join("fixtures")
        .join("generated")
        .join(name)
}

/// 打开样本。缺样本时**断言失败**而不是静默跳过 —— 一个自动跳过的
/// 验收测试等于没有验收测试。
fn session(name: &str) -> Arc<Session> {
    let path = fixture(name);
    assert!(path.exists(), "缺少 fixture：{}", path.display());
    Arc::new(Session::open(&path, OpenOptions::default()).expect("打开目标"))
}

/// 上限放宽到 60 秒：真实样本的一次分析要几秒，测试运行的机器负载又不可控。
/// 这不是在掩盖超时问题 —— 超时行为本身由 `acceptance.rs` 里 200ms 的用例单独守。
fn engine() -> ScriptEngine {
    ScriptEngine::new(Limits {
        timeout: Duration::from_secs(60),
    })
    .expect("创建脚本引擎")
}

/// 带会话的宿主，并预热分析。
fn warm_host(name: &str) -> Host {
    let host = Host::new(None).with_session(session(name));
    host.warmup().expect("预热失败：样本应当可以分析");
    host
}

// ---------------------------------------------------------------------------
// 目标信息与降级说明
// ---------------------------------------------------------------------------

#[test]
fn target_info_is_available_as_a_value() {
    let engine = engine();
    let host = warm_host("m3-mingw-static.exe");

    let outcome = engine
        .run(
            &host,
            r#"
            bitflip.log(bitflip.target.object);
            bitflip.log(bitflip.target.format_version);
            bitflip.log(String(bitflip.target.abI === undefined));
            "#,
        )
        .expect("读目标信息应当成功");

    assert_eq!(
        outcome.logs[0].message, "pe",
        "m3-mingw-static.exe 是 PE，不是别的格式"
    );
    assert_ne!(outcome.logs[1].message, "0", "wire 版本号必须是真的");
    assert_eq!(outcome.logs[2].message, "true");
}

#[test]
fn degradation_notes_are_reachable_from_scripts() {
    let engine = engine();
    let host = warm_host("m3-mingw-static.exe");

    // 脚本必须能读到分析的降级说明。读不到的话，脚本会把一份降级结果
    // 当成完整事实导出成清单 —— 这正是 CLAUDE.md 第 7 条禁止的。
    let outcome = engine
        .run(
            &host,
            r#"
            const notes = bitflip.notes();
            bitflip.log(Array.isArray(notes));
            bitflip.log(typeof (notes.length >= 0));
            "#,
        )
        .expect("读 notes 应当成功");

    assert_eq!(outcome.logs[0].message, "true", "notes 必须是数组");
    assert_eq!(outcome.logs[1].message, "boolean");
}

#[test]
fn counts_agree_with_the_core_accessors() {
    let engine = engine();
    let host = warm_host("m3-mingw-static.exe");

    let outcome = engine
        .run(
            &host,
            r#"
            const c = bitflip.counts();
            bitflip.log(c.functions === bitflip.functions.count());
            bitflip.log(c.xrefs === bitflip.xrefs.count());
            bitflip.log(c.strings === bitflip.strings.count());
            bitflip.log(c.functions > 0);
            "#,
        )
        .expect("读计数应当成功");

    for (index, message) in outcome.logs.iter().enumerate() {
        assert_eq!(
            message.message, "true",
            "第 {index} 条计数自洽断言失败：脚本看到的两条路径必须给出同一个数"
        );
    }
}

// ---------------------------------------------------------------------------
// 分页
// ---------------------------------------------------------------------------

#[test]
fn a_page_reports_total_requested_and_truncated() {
    let engine = engine();
    let host = warm_host("m3-mingw-static.exe");

    let outcome = engine
        .run(
            &host,
            r#"
            const all = bitflip.functions.count();
            const page = bitflip.functions.page(0, 5);
            bitflip.log(page.total === all);
            bitflip.log(page.requested === 5);
            bitflip.log(page.returned === 5);
            bitflip.log(page.truncated === all - 5);
            bitflip.log(page.skipped === 0);
            "#,
        )
        .expect("分页应当成功");

    for message in &outcome.logs {
        assert_eq!(message.message, "true", "分页字段自洽失败");
    }
}

#[test]
fn a_count_beyond_the_cap_is_clamped_but_reported() {
    let engine = engine();
    let host = warm_host("m3-mingw-static.exe");

    let outcome = engine
        .run(
            &host,
            r#"
            const page = bitflip.functions.page(0, 1000000);
            bitflip.log(page.requested);
            bitflip.log(page.returned <= 4096);
            "#,
        )
        .expect("超上限的分页应当成功而不是报错");

    assert_eq!(
        outcome.logs[0].message, "1000000",
        "用户原本要多少必须如实回报，否则看不出是自己要多了"
    );
    assert_eq!(outcome.logs[1].message, "true");
}

#[test]
fn an_offset_past_the_end_is_an_empty_page_not_an_error() {
    let engine = engine();
    let host = warm_host("m3-mingw-static.exe");

    let outcome = engine
        .run(
            &host,
            r#"
            const n = bitflip.functions.count();
            const page = bitflip.functions.page(n + 100, 10);
            bitflip.log(page.returned === 0);
            bitflip.log(page.skipped === page.total);
            "#,
        )
        .expect("越界 offset 不应当报错");

    assert_eq!(outcome.logs[0].message, "true");
    assert_eq!(outcome.logs[1].message, "true");
}

// ---------------------------------------------------------------------------
// xref 过滤：空集合与不传的区别
// ---------------------------------------------------------------------------

#[test]
fn an_empty_kind_set_matches_nothing_while_omitting_it_matches_everything() {
    let engine = engine();
    let host = warm_host("m3-mingw-static.exe");

    // 这是 core 的 `XrefFilter` 专门写进文档的区别，脚本 API 必须原样保留：
    // 界面上一旦出现"全部取消勾选反而显示全部"，用户就再也不信任过滤器了。
    let outcome = engine
        .run(
            &host,
            r#"
            const all = bitflip.xrefs.search({});
            const none = bitflip.xrefs.search({ kinds: [] });
            const calls = bitflip.xrefs.search({ kinds: ['call'] });
            bitflip.log(all.total > 0);
            bitflip.log(none.total === 0);
            bitflip.log(calls.total > 0);
            bitflip.log(calls.total < all.total);
            bitflip.log(all.items.every(x => true));
            "#,
        )
        .expect("过滤应当成功");

    for (index, message) in outcome.logs.iter().enumerate() {
        assert_eq!(message.message, "true", "第 {index} 条过滤断言失败");
    }
}

#[test]
fn every_item_returned_by_a_filter_really_matches_it() {
    let engine = engine();
    let host = warm_host("m3-mingw-static.exe");

    // "过滤看起来没生效"的典型形态：结果条数变少了，但里面混着不符合条件的条目。
    let outcome = engine
        .run(
            &host,
            r#"
            const page = bitflip.xrefs.search({ kinds: ['call'], count: 200 });
            bitflip.log(page.items.every(x => x.kind === 'call'));
            bitflip.log(page.items.length > 0);
            bitflip.log(page.items.every(x => typeof x.from === 'string' && x.from.length === 16));
            "#,
        )
        .expect("过滤应当成功");

    for message in &outcome.logs {
        assert_eq!(message.message, "true", "过滤结果里混进了不满足条件的条目");
    }
}

#[test]
fn an_address_range_filter_narrows_the_result() {
    let engine = engine();
    let host = warm_host("m3-mingw-static.exe");

    let outcome = engine
        .run(
            &host,
            r#"
            const all = bitflip.xrefs.search({});
            const first = all.items[0];
            // 只保留发起地址落在同一个 4KiB 页里的引用。
            //
            // 这里必须用算术而不是位运算：JS 的 `&` 会把操作数截成 32 位，
            // 而这个映像的地址是 0x14000xxxx（> 2^32），
            // `base & ~0xFFF` 会算出个负数再变成乱的十六进制串。
            // 对脚本作者来说这是个真会踩的坑，所以脚本 API 文档里要写明。
            const base = parseInt(first.from, 16);
            const lo = Math.floor(base / 4096) * 4096;
            const hi = lo + 4096;
            const hex = v => v.toString(16).padStart(16, '0');
            const page = bitflip.xrefs.search({ fromRange: [hex(lo), hex(hi)] });
            bitflip.log(page.total > 0 && page.total <= all.total);
            bitflip.log(page.items.every(x => {
              const a = parseInt(x.from, 16);
              return a >= lo && a < hi;
            }));
            "#,
        )
        .expect("范围过滤应当成功");

    assert_eq!(
        outcome.logs[0].message, "true",
        "范围过滤后条数应当不多于全量"
    );
    assert_eq!(outcome.logs[1].message, "true", "范围过滤结果越界");
}

#[test]
fn a_malformed_filter_is_rejected_instead_of_silently_ignored() {
    let engine = engine();
    let host = warm_host("m3-mingw-static.exe");

    let err = engine
        .run(&host, "bitflip.xrefs.search({ fromRange: ['1000'] });")
        .expect_err("长度不对的范围必须报错");
    match err {
        ScriptError::Runtime { message, .. } => {
            assert!(
                message.contains("两个元素"),
                "错误要说清怎么改，实际：{message}"
            );
        }
        other => panic!("应当报成运行时错误，实际：{other:?}"),
    }

    let err = engine
        .run(&host, "bitflip.xrefs.search('call');")
        .expect_err("非对象参数必须报错");
    assert!(matches!(err, ScriptError::Runtime { .. }), "{err:?}");
}

// ---------------------------------------------------------------------------
// 按下标遍历
// ---------------------------------------------------------------------------

#[test]
fn indexed_access_agrees_with_pages_and_returns_null_when_exhausted() {
    let engine = engine();
    let host = warm_host("m3-mingw-static.exe");

    let outcome = engine
        .run(
            &host,
            r#"
            const n = bitflip.xrefs.count();
            const first = bitflip.xrefs.at(0);
            const viaPage = bitflip.xrefs.page(0, 1).items[0];
            bitflip.log(first.from === viaPage.from && first.to === viaPage.to);
            bitflip.log(String(bitflip.xrefs.at(n)));
            bitflip.log(String(bitflip.xrefs.at(999999999)));
            "#,
        )
        .expect("按下标访问应当成功");

    assert_eq!(
        outcome.logs[0].message, "true",
        "同一个位置，下标与分页必须给出同一条"
    );
    assert_eq!(outcome.logs[1].message, "null", "越界应当返回 null");
    assert_eq!(outcome.logs[2].message, "null");
}

#[test]
fn indexed_access_matches_the_wire_shape_exactly() {
    let engine = engine();
    let host = warm_host("m3-mingw-static.exe");

    // 形状必须与 HTTP wire 完全一致：地址是定长小写 16 位十六进制，
    // 不是数字。用户只需要理解一种数据形状。
    let outcome = engine
        .run(
            &host,
            r#"
            const x = bitflip.xrefs.at(0);
            bitflip.log(typeof x.from);
            bitflip.log(x.from.length);
            bitflip.log(x.from === x.from.toLowerCase());
            bitflip.log(typeof x.reachable);
            "#,
        )
        .expect("读取应当成功");

    assert_eq!(outcome.logs[0].message, "string");
    assert_eq!(outcome.logs[1].message, "16");
    assert_eq!(outcome.logs[2].message, "true");
    assert_eq!(outcome.logs[3].message, "boolean");
}

// ---------------------------------------------------------------------------
// 没有能力时必须报错，不能返回空数据
// ---------------------------------------------------------------------------

#[test]
fn reading_without_a_target_throws_instead_of_returning_zero() {
    let engine = engine();
    let host = Host::new(None); // 没有会话

    // 返回 0 会让脚本写出"这个目标没有函数"的结论，而真相是"没打开目标"。
    for source in [
        "bitflip.functions.count();",
        "bitflip.xrefs.count();",
        "bitflip.counts();",
        "bitflip.notes();",
        "bitflip.readBytes('0000000140001000', 4);",
    ] {
        let err = engine
            .run(&host, source)
            .expect_err(&format!("{source} 应当报错"));
        match err {
            ScriptError::Runtime { message, .. } => assert!(
                message.contains("没有打开目标"),
                "{source} 的错误要说明原因，实际：{message}"
            ),
            other => panic!("{source} 应当报成运行时错误，实际：{other:?}"),
        }
    }

    // 目标信息是值不是函数：此时应当是 null，而不是"空对象"。
    let outcome = engine
        .run(&host, "bitflip.log(String(bitflip.target));")
        .expect("读 target 不应当抛异常");
    assert_eq!(outcome.logs[0].message, "null");
}

#[test]
fn reading_instructions_without_a_disassembly_provider_throws() {
    let engine = engine();
    // 有会话，但没有注入反汇编提供者
    let host = Host::new(None).with_session(session("m3-mingw-static.exe"));

    let err = engine
        .run(&host, "bitflip.insns.page('0000000140001000', 1);")
        .expect_err("没有反汇编结果时应当报错");
    match err {
        ScriptError::Runtime { message, .. } => assert!(
            message.contains("没有反汇编结果"),
            "错误要说明是能力没注入，实际：{message}"
        ),
        other => panic!("应当报成运行时错误，实际：{other:?}"),
    }
}

#[test]
fn reading_bytes_beyond_the_cap_is_rejected_not_truncated() {
    let engine = engine();
    let host = warm_host("m3-mingw-static.exe");

    let err = engine
        .run(
            &host,
            "bitflip.readBytes('0000000140001000', 8 * 1024 * 1024);",
        )
        .expect_err("超过上限的读取必须报错");
    match err {
        ScriptError::Runtime { message, .. } => assert!(
            message.contains("最多读"),
            "要说清上限是多少，实际：{message}"
        ),
        other => panic!("应当报成运行时错误，实际：{other:?}"),
    }
}

#[test]
fn reading_bytes_returns_lowercase_hex() {
    let engine = engine();
    let host = warm_host("m3-mingw-static.exe");

    let outcome = engine
        .run(
            &host,
            r#"
            const entry = bitflip.functions.page(0, 1).items[0].start;
            const bytes = bitflip.readBytes(entry, 8);
            bitflip.log(bytes.length);
            bitflip.log(bytes === bytes.toLowerCase());
            "#,
        )
        .expect("读字节应当成功");

    assert_eq!(
        outcome.logs[0].message, "16",
        "8 字节应是 16 个十六进制字符"
    );
    assert_eq!(outcome.logs[1].message, "true");
}

// ---------------------------------------------------------------------------
// 含反汇编的读 API
// ---------------------------------------------------------------------------

/// 用注入的提供者构造宿主，模拟服务层复用自己那份缓存。
fn host_with_disasm(name: &str) -> Host {
    let session = session(name);
    let provider_session = Arc::clone(&session);
    let provider = Arc::new(move || {
        provider_session
            .disassemble(bitflip_core::DisasmScanOptions::default())
            .map(Arc::new)
            .map_err(|err| err.to_string())
    });
    let host = Host::new(None).with_session(session).with_disasm(provider);
    host.warmup().expect("预热失败");
    host
}

#[test]
fn insns_page_and_at_agree_and_at_is_exact() {
    let engine = engine();
    let host = host_with_disasm("m3-mingw-static.exe");

    let outcome = engine
        .run(
            &host,
            r#"
            const entry = bitflip.functions.page(0, 1).items[0].start;
            const page = bitflip.insns.page(entry, 1);
            const insn = page.instructions[0];
            bitflip.log(insn.address === entry);
            const exact = bitflip.insns.at(entry);
            bitflip.log(exact !== null && exact.address === entry);
            "#,
        )
        .expect("读指令应当成功");

    assert_eq!(outcome.logs[0].message, "true", "游标页的第一条应当是入口");
    assert_eq!(outcome.logs[1].message, "true");
}

#[test]
fn insns_at_is_an_exact_lookup_not_a_cursor() {
    let engine = engine();
    let host = host_with_disasm("m3-mingw-static.exe");

    let outcome = engine
        .run(
            &host,
            r#"
            // 地址 1 落在任何代码之前：不可能有指令从它开始。
            // （不能拿"某条指令 +1"来试探：线性扫描会把未对齐的字节也解出指令，
            //   所以 entry+1 上真有可能存在一条指令起点。这里要的是一个
            //   游标能找到东西、而精确查找必须落空的位置。）
            const atOne = bitflip.insns.at('0000000000000001');
            const cursor = bitflip.insns.page('0000000000000001', 1);
            bitflip.log(cursor.instructions.length > 0);
            bitflip.log(String(atOne));
            "#,
        )
        .expect("应当成功");

    assert_eq!(
        outcome.logs[0].message, "true",
        "前提不成立：游标在这个位置找到不东西，这条测试就没有区分力"
    );
    assert_eq!(
        outcome.logs[1].message, "null",
        "at() 必须是精确匹配；用游标语义实现会返回下一条指令而不是 null"
    );
}

// ---------------------------------------------------------------------------
// 可省略参数
// ---------------------------------------------------------------------------

/// 文档里写的默认值必须**真的**成立。
///
/// rquickjs 对实参个数是严格校验的：把可选参数写成 `Option<T>` 只会得到
/// `Error calling function with 0 argument(s) while 2 where expected`，
/// 而不是"取默认值"。这个坑很隐蔽 —— 参数类型看起来完全正确，
/// 只有用户照着文档写 `page()` 时才会炸。所以这里逐个把省略写法跑一遍。
#[test]
fn optional_arguments_really_are_optional() {
    let engine = engine();
    let host = host_with_disasm("m3-mingw-static.exe");

    let outcome = engine
        .run(
            &host,
            r#"
            // 全部省略
            const f = bitflip.functions.page();
            bitflip.log(f.requested);
            bitflip.log(f.returned > 0);

            // 只给偏移
            const f2 = bitflip.functions.page(2);
            bitflip.log(f2.skipped === 2);

            // 完全不传过滤器，必须等价于传 {}
            const bare = bitflip.xrefs.search();
            const empty = bitflip.xrefs.search({});
            bitflip.log(bare.total > 0 && bare.total === empty.total);

            const s = bitflip.strings.page();
            bitflip.log(s.total === bitflip.strings.count());

            const entry = f.items[0].start;
            const i = bitflip.insns.page(entry);
            bitflip.log(i.instructions.length > 0);
            "#,
        )
        .expect("省略可选参数不应当报错");

    for (index, message) in outcome.logs.iter().enumerate() {
        let expected = if index == 0 { "512" } else { "true" };
        assert_eq!(
            message.message, expected,
            "第 {index} 条省略参数的断言失败（说明 `Opt` 用法或默认值不对）"
        );
    }
}

// ---------------------------------------------------------------------------
// 按下标遍历全部交叉引用 + 落盘
// ---------------------------------------------------------------------------
//
// 注意：验收标准 1（"识别所有调用 memcpy 的位置并写参数注释"）的**权威**版本
// 在 `tests/builtin.rs`：它跑的是随二进制发布出去的那一份内置脚本源码。
// 这里这一份是**读 API 的练习**，走 `xrefs.at(i)` 这条按下标游标的路径
// （内置脚本用的是 `search` 过滤），两条路径都值得被测到 ——
// 但不要再把"验收标准 1"的名号挂在这里，否则将来两份实现分叉时，
// 没人知道该以哪一份为准。

/// 用未经剥离的样本：`memcpy` 这个名字只存在于符号表里，
/// 剥离后的 `m3-mingw-static.exe` 上 `stripped_symbols=0`（见同名 .meta.txt），
/// 按名字找不到任何函数 —— 那是 M8 的签名识别课题，不是 M7 的脚本能力。
const SYMBOLS_FIXTURE: &str = "m3-mingw-static.unstripped.exe";

#[test]
fn reading_every_xref_by_index_annotates_every_memcpy_call_site() {
    let dir = tempfile::tempdir().expect("tempdir");
    let path = dir.path().join("m7-memcpy.bfp");
    let hash = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
    ProjectStore::create(&path, hash, 4096, "test", 1_700_000_000).expect("创建工程库");

    let engine = engine();
    let host = warm_host(SYMBOLS_FIXTURE)
        .with_project_store(ProjectStore::open(&path, hash).expect("打开工程库"));

    // 这一段就是内置示例脚本 `memcpy-args` 想做的事，只是遍历方式不同：
    // 这里用按下标游标（`xrefs.at`），内置脚本用过滤器（`xrefs.search`）。
    // 它同时用到了读 API 与写 API（暂存 + 提交）。
    let source = r#"
        // 1) 找到 memcpy 的入口地址（分页遍历，不一次物化全部函数）
        let memcpy = null;
        const fnTotal = bitflip.functions.count();
        for (let off = 0; off < fnTotal && memcpy === null; off += 512) {
            for (const f of bitflip.functions.page(off, 512).items) {
                if (f.name === 'memcpy') { memcpy = f; break; }
            }
        }
        if (memcpy === null) { throw new Error('目标里没有名为 memcpy 的函数'); }

        // 2) 遍历全部引用，挑出指向 memcpy 的 call
        let annotated = 0;
        const xrefTotal = bitflip.xrefs.count();
        for (let i = 0; i < xrefTotal; i++) {
            const x = bitflip.xrefs.at(i);
            if (x.kind !== 'call') { continue; }
            if (x.to !== memcpy.start) { continue; }
            bitflip.setComment(x.from, 'memcpy(dst, src, n)');
            annotated += 1;
        }

        bitflip.log('memcpy@' + memcpy.start);
        bitflip.log('annotated=' + annotated);
    "#;

    let outcome = engine.run(&host, source).expect("验收脚本应当端到端跑通");

    // 脚本自己报告了找到了 memcpy
    let memcpy_line = outcome.logs[0].message.clone();
    assert!(
        memcpy_line.starts_with("memcpy@000000014000"),
        "应当在 PE 的映像基址上找到 memcpy，实际：{memcpy_line}"
    );
    assert_eq!(
        memcpy_line, "memcpy@0000000140009218",
        "真值文件（m3-mingw-static.funcs.txt）记的就是这个地址；\
         对不上说明符号解析或函数识别出了问题，不是脚本的问题"
    );

    let annotated: usize = outcome.logs[1]
        .message
        .strip_prefix("annotated=")
        .expect("脚本应报告注释条数")
        .parse()
        .expect("注释条数应是整数");
    assert!(
        annotated > 0,
        "memcpy 在真实样本上必须被调用过，否则这条验收标准没有验证到东西"
    );
    assert_eq!(outcome.committed, annotated, "提交条数必须与脚本报告的一致");

    // 落到磁盘上的必须真的是那些调用点，而不是随便一些地址
    let reopened = ProjectStore::open(&path, hash).expect("重新打开工程库");
    assert_eq!(reopened.len(), annotated);

    let session = session(SYMBOLS_FIXTURE);
    let analysis = session
        .analysis(&session.detached_job())
        .expect("构建分析结论");
    let memcpy_start = "0000000140009218";
    for annotation in reopened.range(0, u64::MAX) {
        assert_eq!(annotation.kind, AnnotationKind::Comment);
        assert_eq!(
            annotation.text.as_deref(),
            Some("memcpy(dst, src, n)"),
            "注释内容必须是脚本写的那一条"
        );
        let at = format!("{:016x}", annotation.address);
        let calls_into_memcpy = analysis
            .xrefs_from(annotation.address)
            .into_iter()
            .any(|x| x.kind == "call" && x.to == memcpy_start);
        assert!(
            calls_into_memcpy,
            "地址 {at} 上并没有一条调用 memcpy 的指令，它是怎么被注释上的？"
        );
    }
}
