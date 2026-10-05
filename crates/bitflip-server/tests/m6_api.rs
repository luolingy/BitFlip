//! M6 服务层端点契约测试：调用图 / 数据代码判定 / 跳转表。
//!
//! 这组测试的重点是**字段名与形状**，而不是"路由存在"。
//!
//! # 为什么专门测字段名
//!
//! SPA 用 TypeScript 的 `interface` 描述这些响应，但 `fetch` 拿到的
//! JSON 在类型上是 `any` —— **字段名写错了 TypeScript 不会报错**，
//! 只会让某个表格列静默显示 `undefined`。
//!
//! 这个坑真实发生过：`CodeMapSample` 服务端叫 `addr`，前端一度写成
//! `address`，`npm run typecheck` 全绿，但那一列在界面上是空的。
//! 类型检查抓不到这类错误，所以要在**契约层**用真实响应钉住字段名。
//!
//! 另一类要守的性质是"不许编造"：
//!
//! * 未解析的间接调用必须有 `callee: null` 且被计数 —— 丢掉它会让
//!   用户以为"这个函数什么都没调用"；
//! * 数据/代码判定的三个数字必须自洽（加起来等于抽样总数）；
//! * 跳转表的目标必须都在可执行段里。

use std::sync::atomic::{AtomicU64, Ordering};

use axum::body::{to_bytes, Body};
use axum::http::{Request, StatusCode};
use bitflip_server::{router, AppState, TOKEN_HEADER};
use serde_json::Value;
use tower::ServiceExt;

const TOKEN: &str = "00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff";
const PORT: u16 = 8793;

/// 临时目标目录：`Drop` 时连目录一起清掉（连带工程库）。
///
/// 只留 `dir` 是因为 `Session` 已经打开目标了，测试不再需要路径 ——
/// 多留一个从不读取的 `path` 字段会被 clippy 判为 dead code。
struct TempTarget {
    dir: std::path::PathBuf,
}

impl Drop for TempTarget {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.dir);
    }
}

/// 构造带**多个函数**的 ELF：入口 + 几个互相调用的函数，外加一个间接调用。
///
/// 仅有一个 `call` 的目标测不出调用图的形状（入度/出度/未解析计数），
/// 所以这里刻意排布成 `entry → f1 → f2`，中间夹一处 `call rax`。
fn build_elf_with_call_graph() -> Vec<u8> {
    let mut code: Vec<u8> = Vec::new();
    // 每个函数 16 字节：nop 填充 + 末尾 ret
    // 0x401000 entry: call f1 (0x401010)
    //   相对位移 = 0x401010 - (0x401000+5) = 0x0B
    code.extend_from_slice(&[0x90, 0x90, 0xE8, 0x0B, 0x00, 0x00, 0x00, 0xC3]);
    code.extend_from_slice(&[0x90; 8]); // 填充到 0x401010

    // 0x401010 f1: call f2 (0x401020)；位移 = 0x401020 - (0x401010+5) = 0x0B
    code.extend_from_slice(&[0x90, 0x90, 0xE8, 0x0B, 0x00, 0x00, 0x00, 0xC3]);
    code.extend_from_slice(&[0x90; 8]); // 填充到 0x401020

    // 0x401020 f2: call rax（间接，无目标）+ ret
    code.extend_from_slice(&[0x90, 0x90, 0xFF, 0xD0, 0xC3]);
    code.extend_from_slice(&[0x90; 11]); // 填充到 0x401030
    code.extend_from_slice(&[0xC3]); // 0x401030 末尾

    let text_off = 0x1000usize;
    let text_vaddr = 0x401000u64;
    let mut bytes = vec![0u8; 0x2000];

    bytes[0..4].copy_from_slice(b"\x7fELF");
    bytes[4] = 2;
    bytes[5] = 1;
    bytes[6] = 1;
    bytes[16..18].copy_from_slice(&2u16.to_le_bytes()); // ET_EXEC
    bytes[18..20].copy_from_slice(&62u16.to_le_bytes()); // EM_X86_64
    bytes[20..24].copy_from_slice(&1u32.to_le_bytes());
    bytes[24..32].copy_from_slice(&text_vaddr.to_le_bytes());
    bytes[32..40].copy_from_slice(&64u64.to_le_bytes());
    bytes[52..54].copy_from_slice(&64u16.to_le_bytes());
    bytes[54..56].copy_from_slice(&56u16.to_le_bytes());
    bytes[56..58].copy_from_slice(&1u16.to_le_bytes());

    let ph = 64usize;
    bytes[ph..ph + 4].copy_from_slice(&1u32.to_le_bytes()); // PT_LOAD
    bytes[ph + 4..ph + 8].copy_from_slice(&5u32.to_le_bytes()); // R|X
    bytes[ph + 8..ph + 16].copy_from_slice(&(text_off as u64).to_le_bytes());
    bytes[ph + 16..ph + 24].copy_from_slice(&text_vaddr.to_le_bytes());
    bytes[ph + 24..ph + 32].copy_from_slice(&text_vaddr.to_le_bytes());
    bytes[ph + 32..ph + 40].copy_from_slice(&(code.len() as u64).to_le_bytes());
    bytes[ph + 40..ph + 48].copy_from_slice(&(code.len() as u64).to_le_bytes());
    bytes[ph + 48..ph + 56].copy_from_slice(&0x1000u64.to_le_bytes());

    bytes[text_off..text_off + code.len()].copy_from_slice(&code);
    bytes
}

fn state_with_target(data: &[u8]) -> (AppState, TempTarget) {
    static COUNTER: AtomicU64 = AtomicU64::new(0);
    let mut dir = std::env::temp_dir();
    dir.push(format!(
        "bitflip-m6-{}-{}",
        std::process::id(),
        COUNTER.fetch_add(1, Ordering::Relaxed)
    ));
    std::fs::create_dir_all(&dir).expect("建临时目录");
    let path = dir.join("m6.elf");
    std::fs::write(&path, data).expect("写入临时目标");
    let session =
        bitflip_core::Session::open(&path, bitflip_core::OpenOptions::default()).expect("打开目标");
    let state = AppState::new(TOKEN, None)
        .with_session(std::sync::Arc::new(session))
        .with_allowed_origins(bitflip_server::default_allowed_origins(PORT, &[]));
    (state, TempTarget { dir })
}

async fn get(state: AppState, uri: &str) -> (StatusCode, Value) {
    let request = Request::builder()
        .uri(uri)
        .header(TOKEN_HEADER, TOKEN)
        .body(Body::empty())
        .expect("构造请求");
    let response = router(state).oneshot(request).await.expect("发请求");
    let status = response.status();
    let bytes = to_bytes(response.into_body(), 8 * 1024 * 1024)
        .await
        .expect("读响应体");
    let value = serde_json::from_slice(&bytes)
        .unwrap_or_else(|_| Value::String(String::from_utf8_lossy(&bytes).to_string()));
    (status, value)
}

/// 断言一个对象**恰好**有这些键（多一个少一个都算契约漂移）。
fn assert_keys(value: &Value, expected: &[&str], what: &str) {
    let obj = value
        .as_object()
        .unwrap_or_else(|| panic!("{what} 不是对象"));
    let mut actual: Vec<&str> = obj.keys().map(String::as_str).collect();
    actual.sort_unstable();
    let mut want: Vec<&str> = expected.to_vec();
    want.sort_unstable();
    assert_eq!(
        actual, want,
        "{what} 的字段集合与前端契约不一致 —— 多一个或少一个都会让 UI 某列静默变空"
    );
}

#[tokio::test]
async fn call_graph_response_matches_the_frontend_contract() {
    let (state, _t) = state_with_target(&build_elf_with_call_graph());
    let (status, body) = get(state, "/api/call-graph").await;
    assert_eq!(status, StatusCode::OK, "响应：{body}");

    assert_keys(
        &body,
        &[
            "format_version",
            "summary",
            "edges",
            "unresolved",
            "nodes",
            "focus",
            "depth",
            "returned_edges",
            "truncated_edges",
            "notes",
        ],
        "call-graph 响应",
    );
    assert_keys(
        &body["summary"],
        &[
            "nodes",
            "edges",
            "unresolved_indirect",
            "outside_targets",
            "roots",
            "components",
            "largest_component",
        ],
        "call-graph.summary",
    );

    // 全图模式下没有聚焦对象，depth 为 0（而不是 null 或 1）
    assert!(body["focus"].is_null(), "全图模式 focus 应为 null");
    assert_eq!(body["depth"], 0);

    let summary = &body["summary"];
    assert_eq!(summary["edges"], body["edges"].as_array().unwrap().len());

    // 返回的边数与截断数必须自洽：两者之和 == 图上的总边数。
    // 这条守的是"大目标上界面不许自相矛盾" —— 曾经 summary.edges
    // 报 23660 而 edges 数组只有 20000，且没有任何字段说明少了。
    let returned = body["returned_edges"].as_u64().unwrap();
    let truncated = body["truncated_edges"].as_u64().unwrap();
    assert_eq!(
        returned,
        body["edges"].as_array().unwrap().len() as u64,
        "returned_edges 必须等于 edges 数组长度"
    );
    assert_eq!(
        returned + truncated,
        summary["edges"].as_u64().unwrap(),
        "已返回 + 已截断 必须等于总边数，否则 UI 上的数字对不上"
    );
}

/// 截断必须**自报**：`limit` 卡到 1 时，界面能算出"还有多少条没拿到"。
///
/// 这条用一个真实会触发截断的 `limit` 来测，而不是靠断言"字段存在"。
/// 曾经的实现把截断只写进 `notes` 文案里，`summary.edges` 仍是全量 ——
/// 前端于是显示"共 23660 条边"却只列出 20000 行，看起来像丢了数据。
#[tokio::test]
async fn call_graph_reports_truncation_instead_of_silently_dropping_edges() {
    let (state, _t) = state_with_target(&build_elf_with_call_graph());

    // 先拿到不截断时的真实边数
    let (status, full) = get(state.clone(), "/api/call-graph").await;
    assert_eq!(status, StatusCode::OK);
    let total = full["summary"]["edges"].as_u64().unwrap();
    assert!(
        total >= 2,
        "fixture 应当至少有两条已解析调用边，实际 {total}"
    );

    // 再请求只返回 1 条
    let (status, cut) = get(state, "/api/call-graph?limit=1").await;
    assert_eq!(status, StatusCode::OK, "响应：{cut}");

    assert_eq!(
        cut["edges"].as_array().unwrap().len(),
        1,
        "limit=1 只给一条"
    );
    assert_eq!(cut["returned_edges"], 1);
    assert_eq!(
        cut["truncated_edges"].as_u64().unwrap(),
        total - 1,
        "被截断的条数必须如实报出"
    );
    // 汇总里的总边数**不变** —— 它是图的事实，不是本次响应的长度
    assert_eq!(cut["summary"]["edges"].as_u64().unwrap(), total);

    // 截断这件事必须在 notes 里有一句人话
    let notes = cut["notes"].as_array().unwrap();
    assert!(
        notes.iter().any(|n| n.as_str().unwrap().contains("截断")),
        "截断要有明确的文字说明，不能只在数字上体现"
    );
}

/// 邻域模式的字段形状，以及 `entry` 非法时必须报错。
#[tokio::test]
async fn call_graph_neighbourhood_mode_and_bad_entry() {
    let (state, _t) = state_with_target(&build_elf_with_call_graph());

    let (status, body) = get(
        state.clone(),
        "/api/call-graph?entry=0000000000401000&depth=1",
    )
    .await;
    assert_eq!(status, StatusCode::OK, "响应：{body}");
    assert_eq!(body["focus"], "0000000000401000");
    assert_eq!(body["depth"], 1);

    // 地址格式不对要报错，不能悄悄回退到 0（那会伪装成"跳转成功"）
    let (status, _) = get(state, "/api/call-graph?entry=zzzz").await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
}

/// 未解析的间接调用必须**留在**图里并且被计数。
///
/// 这是"不许编造"的核心：丢掉这些调用点会让一个调用了函数指针的
/// 函数看起来"什么都没调用"。
#[tokio::test]
async fn unresolved_indirect_calls_are_kept_and_counted() {
    let (state, _t) = state_with_target(&build_elf_with_call_graph());
    let (status, body) = get(state, "/api/call-graph").await;
    assert_eq!(status, StatusCode::OK);

    let unresolved = body["unresolved"].as_array().expect("unresolved 是数组");
    let summary_count = body["summary"]["unresolved_indirect"]
        .as_u64()
        .expect("计数是数字");

    // fixture 里有一个 `call rax`（0x401022）
    assert!(
        summary_count >= 1,
        "fixture 里有间接调用，计数应当 >= 1，实际 {summary_count}"
    );
    assert_eq!(
        unresolved.len() as u64,
        summary_count,
        "unresolved 数组长度必须与 summary 计数一致"
    );

    // 每条未解析记录要能定位到调用点
    for u in unresolved {
        assert_keys(u, &["caller", "insn"], "unresolved 条目");
        let insn = u["insn"].as_str().unwrap();
        assert_eq!(insn.len(), 16, "地址必须是定长 16 位：{insn}");
    }

    // 已解析的边必须都有非空 callee —— 空字符串会让前端画出悬空节点
    for e in body["edges"].as_array().expect("edges 是数组") {
        assert_keys(e, &["caller", "callee", "tail"], "edges 条目");
        assert_eq!(e["callee"].as_str().unwrap().len(), 16);
        assert_eq!(e["caller"].as_str().unwrap().len(), 16);
    }
}

#[tokio::test]
async fn code_map_response_matches_the_frontend_contract() {
    let (state, _t) = state_with_target(&build_elf_with_call_graph());
    let (status, body) = get(state, "/api/code-map").await;
    assert_eq!(status, StatusCode::OK, "响应：{body}");

    assert_keys(
        &body,
        &["format_version", "stats", "samples", "notes"],
        "code-map 响应",
    );
    assert_keys(
        &body["stats"],
        &["code", "data", "unknown", "decided_ratio"],
        "code-map.stats",
    );

    // 样本字段名必须是 `addr`（前端一度写成 `address`，typecheck 抓不到）
    let samples = body["samples"].as_array().expect("samples 是数组");
    assert!(!samples.is_empty(), "合成目标应当至少有一个抽样地址");
    for s in samples {
        assert_keys(
            s,
            &[
                "addr",
                "kind",
                "kind_label",
                "confidence",
                "well_supported",
                "reason",
            ],
            "code-map.samples 条目",
        );
        assert_eq!(s["addr"].as_str().unwrap().len(), 16);
        // 结论短名必须是三态之一，不能有第三种拼法
        let kind = s["kind"].as_str().unwrap();
        assert!(
            matches!(kind, "code" | "data" | "unknown"),
            "未知的结论短名：{kind}"
        );
        assert!(
            !s["kind_label"].as_str().unwrap().is_empty(),
            "中文标签不能为空 —— UI 直接显示它"
        );
    }
}

/// 判定的三个数字必须自洽，且 `decided_ratio` 与它们一致。
///
/// 这条守的是"统计不许编"：如果比例与计数对不上，UI 上会显示
/// 一个自相矛盾的画面。
#[tokio::test]
async fn code_map_stats_are_self_consistent() {
    let (state, _t) = state_with_target(&build_elf_with_call_graph());
    let (_, body) = get(state, "/api/code-map").await;

    let stats = &body["stats"];
    let code = stats["code"].as_u64().unwrap();
    let data = stats["data"].as_u64().unwrap();
    let unknown = stats["unknown"].as_u64().unwrap();
    let total = code + data + unknown;

    assert!(total > 0, "应当至少判定了一个地址");

    let samples = body["samples"].as_array().unwrap().len() as u64;
    assert_eq!(
        samples, total,
        "样本数必须等于三个计数之和（每个抽样地址恰好一个结论）"
    );

    let ratio = stats["decided_ratio"].as_f64().unwrap();
    let expected = (code + data) as f64 / total as f64;
    assert!(
        (ratio - expected).abs() < 1e-9,
        "decided_ratio {ratio} 与计数算出的 {expected} 不一致"
    );
}

#[tokio::test]
async fn jump_tables_response_matches_the_frontend_contract() {
    let (state, _t) = state_with_target(&build_elf_with_call_graph());
    let (status, body) = get(state, "/api/jump-tables").await;
    assert_eq!(status, StatusCode::OK, "响应：{body}");

    assert_keys(
        &body,
        &["format_version", "tables", "notes"],
        "jump-tables 响应",
    );

    // 这个 fixture 没有跳转表（没有 switch 分派），所以只验证"空也是
    // 合法结论"以及表项的字段形状（有表时）。空数组不是错误 ——
    // 但绝不能因此返回 500 或编一张表出来。
    for t in body["tables"].as_array().expect("tables 是数组") {
        assert_keys(
            t,
            &[
                "insn_addr",
                "base",
                "width",
                "kind",
                "kind_zh",
                "count",
                "targets",
            ],
            "jump-tables 条目",
        );
        let targets = t["targets"].as_array().unwrap();
        assert_eq!(
            targets.len() as u64,
            t["count"].as_u64().unwrap(),
            "count 必须等于 targets 长度"
        );
        for target in targets {
            assert_eq!(target.as_str().unwrap().len(), 16, "目标地址要定长 16 位");
        }
        let width = t["width"].as_u64().unwrap();
        assert!(
            matches!(width, 1 | 2 | 4 | 8),
            "表项宽度只能是 1/2/4/8，实际 {width}"
        );
    }
}

/// 常量/结构体初步推断的字段形状。
///
/// # 为什么这个端点尤其要测字段名
///
/// 它的三个结论（字符串引用 / 步长 / 立即数）都可能**静默为空**：
/// 不报错，只是列表是空的。字段名一旦写错，前端那几块会一起变成
/// 空白，而 typecheck 抓不到 —— 和 `CodeMapSample.addr` 是同一类坑。
#[tokio::test]
async fn const_scan_response_matches_the_frontend_contract() {
    let (state, _t) = state_with_target(&build_elf_with_call_graph());
    let (status, body) = get(state, "/api/const-scan").await;
    assert_eq!(status, StatusCode::OK, "响应：{body}");

    assert_keys(
        &body,
        &[
            "format_version",
            "strings",
            "strides",
            "immediates",
            "immediate_total",
            "immediate_distinct",
            "notes",
        ],
        "const-scan 响应",
    );

    for s in body["strings"].as_array().expect("strings 是数组") {
        assert_keys(
            s,
            &["address", "functions", "sites"],
            "const-scan.strings 条目",
        );
        assert_eq!(s["address"].as_str().unwrap().len(), 16);
        assert!(
            !s["sites"].as_array().unwrap().is_empty(),
            "有记录就必须有引用点"
        );
    }

    for s in body["strides"].as_array().expect("strides 是数组") {
        assert_keys(
            s,
            &["base", "width", "stride", "offsets"],
            "const-scan.strides 条目",
        );
        // 推不出步长时必须是 null，**不能是 0** —— 0 是编的
        assert_ne!(
            s["stride"],
            serde_json::json!(0),
            "步长 0 不合法：推不出来应当是 null"
        );
    }

    for i in body["immediates"].as_array().expect("immediates 是数组") {
        assert_keys(i, &["value", "count"], "const-scan.immediates 条目");
        // 值是十进制字符串（避免 JSON 精度问题），必须是可解析的整数
        let v = i["value"].as_str().expect("立即数值是字符串");
        assert!(v.parse::<i64>().is_ok(), "立即数值应为十进制，实际 {v:?}");
    }
}

/// 调用约定与参数推断的字段形状。
///
/// 重点在 **`lower_bound` 这个名字**：它是下界不是个数。字段名一旦
/// 被改成 `arg_count`，前端和用户都会把它读成"参数个数"，而那是
/// 没有调试信息时**推不出来**的东西。
#[tokio::test]
async fn arg_scan_response_matches_the_frontend_contract() {
    let (state, _t) = state_with_target(&build_elf_with_call_graph());
    let (status, body) = get(state, "/api/arg-scan").await;
    assert_eq!(status, StatusCode::OK, "响应：{body}");

    assert_keys(
        &body,
        &[
            "format_version",
            "abi_name",
            "arg_reg_names",
            "functions",
            "notes",
        ],
        "arg-scan 响应",
    );

    let regs = body["arg_reg_names"]
        .as_array()
        .expect("arg_reg_names 是数组");

    for f in body["functions"].as_array().expect("functions 是数组") {
        assert_keys(
            f,
            &[
                "entry",
                "insn_count",
                "used",
                "used_names",
                "lower_bound",
                "unobserved_from",
                "register_slots",
                "reads_stack_args",
            ],
            "arg-scan.functions 条目",
        );

        // **不能有 arg_count 字段** —— 那是没有证据的声称
        assert!(
            f.get("arg_count").is_none(),
            "不允许出现 arg_count：没有调试信息时参数个数推不出来，只能给下界"
        );

        assert_eq!(f["entry"].as_str().unwrap().len(), 16, "地址定长 16 位");

        let used: Vec<usize> = f["used"]
            .as_array()
            .unwrap()
            .iter()
            .map(|v| v.as_u64().unwrap() as usize)
            .collect();
        let expected = used.last().map_or(0, |&i| i + 1);
        assert_eq!(
            f["lower_bound"].as_u64().unwrap() as usize,
            expected,
            "下界必须等于最大已用序号 + 1"
        );

        // 参数名与序号必须一一对应（前端按下标取名字）
        assert_eq!(
            f["used_names"].as_array().unwrap().len(),
            used.len(),
            "used_names 与 used 数量不一致"
        );
        for (name, &idx) in f["used_names"].as_array().unwrap().iter().zip(used.iter()) {
            assert_eq!(
                name.as_str().unwrap(),
                regs[idx].as_str().unwrap(),
                "第 {idx} 个参数名对不上"
            );
        }
    }
}

/// 五个端点在没有目标时都必须给出明确的 400，而不是 500 或空数组。
#[tokio::test]
async fn m6_endpoints_require_a_target() {
    let state = AppState::new(TOKEN, None)
        .with_allowed_origins(bitflip_server::default_allowed_origins(PORT, &[]));

    for uri in [
        "/api/call-graph",
        "/api/code-map",
        "/api/const-scan",
        "/api/arg-scan",
        "/api/jump-tables",
    ] {
        let (status, _) = get(state.clone(), uri).await;
        assert_eq!(
            status,
            StatusCode::BAD_REQUEST,
            "{uri} 在没有目标时应当明确拒绝，而不是返回空数据"
        );
    }
}
