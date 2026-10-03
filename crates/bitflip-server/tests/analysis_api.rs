//! M3 服务层端点测试：函数 / 交叉引用 / 字符串 / 十六进制 / 标注。
//!
//! 这组测试的重点不是"路由存在"，而是**契约与诚实性**：
//!
//! * 地址必须是定长小写 16 位十六进制 —— 前端直接拿它当 key，
//!   格式一旦漂移，跳转与高亮会静默错位；
//! * 地址解析失败必须报错，不能悄悄回退到 0（那会伪装成"跳转成功"）；
//! * 标注写入**不触发**重新分析；
//! * 读不到的字节要如实报短，不能补零冒充文件内容。

use std::sync::atomic::{AtomicU64, Ordering};

use axum::body::{to_bytes, Body};
use axum::http::{Request, StatusCode};
use bitflip_server::{router, AppState, TOKEN_HEADER};
use serde_json::Value;
use tower::ServiceExt;

const TOKEN: &str = "fedcba9876543210fedcba9876543210fedcba9876543210fedcba9876543210";
const PORT: u16 = 8791;

/// 一个测试独占的临时目录 + 目标路径。
struct TempTarget {
    dir: std::path::PathBuf,
    path: std::path::PathBuf,
}

impl Drop for TempTarget {
    fn drop(&mut self) {
        // 用 Drop 而不是在每个测试末尾手写清理：测试 panic 时也要收干净，
        // 否则临时目录会在 %TEMP% 里越堆越多（连带工程库）。
        let _ = std::fs::remove_dir_all(&self.dir);
    }
}

/// 写入一个**独占目录**下的临时目标。
///
/// 每个测试必须有自己的目录，理由不是洁癖：工程库 `.bfp` 的路径由
/// **目标内容哈希**派生。测试用的合成 ELF 字节完全相同，于是所有测试
/// 指向同一个工程库 —— 标注测试之间会互相看见对方的行。
/// （这个坑真实发生过：删除测试断言"读不到"时，读到的是上一个测试
/// 留下的 `name` 标注，看起来像删除失效，其实是测试之间共享了库。）
fn write_temp_dir(data: &[u8]) -> TempTarget {
    static COUNTER: AtomicU64 = AtomicU64::new(0);
    let mut dir = std::env::temp_dir();
    dir.push(format!(
        "bitflip-m3-{}-{}",
        std::process::id(),
        COUNTER.fetch_add(1, Ordering::Relaxed)
    ));
    std::fs::create_dir_all(&dir).expect("建临时目录");
    let path = dir.join("m3.elf");
    std::fs::write(&path, data).expect("写入临时目标");
    TempTarget { dir, path }
}

fn state_with_target(data: &[u8]) -> (AppState, TempTarget) {
    let target = write_temp_dir(data);
    let session = bitflip_core::Session::open(&target.path, bitflip_core::OpenOptions::default())
        .expect("打开目标");
    let state = AppState::new(TOKEN, None)
        .with_session(std::sync::Arc::new(session))
        .with_allowed_origins(bitflip_server::default_allowed_origins(PORT, &[]));
    (state, target)
}

fn get_with_token(path: &str) -> Request<Body> {
    Request::builder()
        .uri(path)
        .header(TOKEN_HEADER, TOKEN)
        .body(Body::empty())
        .expect("构造请求")
}

fn json_request(method: &str, path: &str, body: Value) -> Request<Body> {
    Request::builder()
        .method(method)
        .uri(path)
        .header(TOKEN_HEADER, TOKEN)
        .header("content-type", "application/json")
        .body(Body::from(body.to_string()))
        .expect("构造请求")
}

async fn send(state: AppState, request: Request<Body>) -> (StatusCode, Value) {
    let response = router(state).oneshot(request).await.expect("路由响应");
    let status = response.status();
    let bytes = to_bytes(response.into_body(), 8 * 1024 * 1024)
        .await
        .expect("读响应体");
    let body = if bytes.is_empty() {
        Value::Null
    } else {
        serde_json::from_slice(&bytes)
            .unwrap_or_else(|_| Value::String(String::from_utf8_lossy(&bytes).to_string()))
    };
    (status, body)
}

/// 构造带真实可解码机器码的 ELF（ET_EXEC，有程序头，可用虚拟地址读字节）。
///
/// 与 http.rs 的 `build_elf_with_code` 不同：这里用 **ET_EXEC + PT_LOAD**，
/// 因为十六进制视图与交叉引用需要真实的虚拟地址映射；
/// ET_REL 那种"没有程序头、走合成地址空间"的目标覆盖不到这条路径。
fn build_elf_with_code() -> Vec<u8> {
    // nop; nop; call +0; nop; ret …
    // call rel32 = E8 00000000 → 目标 = 下一条指令地址（自身后 5 字节处）
    let code: Vec<u8> = vec![
        0x90, 0x90, 0xE8, 0x00, 0x00, 0x00, 0x00, 0x90, 0xC3, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90,
        0x90,
    ];

    let text_off = 0x1000usize;
    let text_vaddr = 0x401000u64;
    let mut bytes = vec![0u8; 0x2000];

    // ── ELF64 头 ──
    bytes[0..4].copy_from_slice(b"\x7fELF");
    bytes[4] = 2; // 64 位
    bytes[5] = 1; // 小端
    bytes[6] = 1; // 版本
    bytes[16..18].copy_from_slice(&2u16.to_le_bytes()); // ET_EXEC
    bytes[18..20].copy_from_slice(&62u16.to_le_bytes()); // EM_X86_64
    bytes[20..24].copy_from_slice(&1u32.to_le_bytes());
    bytes[24..32].copy_from_slice(&text_vaddr.to_le_bytes()); // e_entry
    bytes[32..40].copy_from_slice(&64u64.to_le_bytes()); // e_phoff
    bytes[52..54].copy_from_slice(&64u16.to_le_bytes()); // e_ehsize
    bytes[54..56].copy_from_slice(&56u16.to_le_bytes()); // e_phentsize
    bytes[56..58].copy_from_slice(&1u16.to_le_bytes()); // e_phnum

    // ── 程序头：PT_LOAD，可读可执行 ──
    let ph = 64usize;
    bytes[ph..ph + 4].copy_from_slice(&1u32.to_le_bytes()); // PT_LOAD
    bytes[ph + 4..ph + 8].copy_from_slice(&5u32.to_le_bytes()); // R|X
    bytes[ph + 8..ph + 16].copy_from_slice(&(text_off as u64).to_le_bytes()); // p_offset
    bytes[ph + 16..ph + 24].copy_from_slice(&text_vaddr.to_le_bytes()); // p_vaddr
    bytes[ph + 24..ph + 32].copy_from_slice(&text_vaddr.to_le_bytes()); // p_paddr
    bytes[ph + 32..ph + 40].copy_from_slice(&(code.len() as u64).to_le_bytes()); // p_filesz
    bytes[ph + 40..ph + 48].copy_from_slice(&(code.len() as u64).to_le_bytes()); // p_memsz
    bytes[ph + 48..ph + 56].copy_from_slice(&0x1000u64.to_le_bytes()); // p_align

    // ── 代码 ──
    bytes[text_off..text_off + code.len()].copy_from_slice(&code);
    bytes
}

/// 空目标：所有分析端点都应给出明确的"不可分析"，而不是 500 或空数组。
#[tokio::test]
async fn analysis_endpoints_require_a_target() {
    let state = AppState::new(TOKEN, None)
        .with_allowed_origins(bitflip_server::default_allowed_origins(PORT, &[]));

    for path in ["/api/functions", "/api/xrefs?address=0", "/api/strings"] {
        let (status, body) = send(state.clone(), get_with_token(path)).await;
        assert_eq!(status, StatusCode::BAD_REQUEST, "{path} 响应: {body}");
        assert!(
            body["error"]
                .as_str()
                .unwrap_or("")
                .contains("没有打开目标"),
            "{path} 的错误信息应说清原因：{body}"
        );
    }
}

/// 函数列表：字段必须是稳定的 wire 形状。
#[tokio::test]
async fn functions_endpoint_returns_wire_shaped_functions() {
    let (state, _target) = state_with_target(&build_elf_with_code());
    let (status, body) = send(state, get_with_token("/api/functions")).await;

    assert_eq!(status, StatusCode::OK, "响应: {body}");
    assert_eq!(
        body["format_version"],
        bitflip_core::ANALYSIS_FORMAT_VERSION
    );
    assert!(body["total"].as_u64().is_some(), "应有 total");

    for f in body["functions"].as_array().expect("functions 应是数组") {
        // 地址必须是定长小写 16 位十六进制
        let start = f["start"].as_str().expect("start");
        assert_eq!(start.len(), 16, "地址不是定长 16 位：{start}");
        assert!(
            start
                .chars()
                .all(|c| c.is_ascii_hexdigit() && !c.is_ascii_uppercase()),
            "地址必须是小写十六进制：{start}"
        );

        // 未命名函数必须 named=false 且名字为空 —— 绝不出现 func_xxx 占位名
        if f["named"] == Value::Bool(false) {
            assert_eq!(
                f["name"].as_str().unwrap_or(""),
                "",
                "未命名函数必须 name 为空，不能有占位名：{f}"
            );
        }
        // 每个函数都要能解释"为什么这里是函数"
        assert!(
            !f["source"].as_str().unwrap_or("").is_empty(),
            "缺 source：{f}"
        );
        assert!(
            !f["source_label"].as_str().unwrap_or("").is_empty(),
            "缺 source_label：{f}"
        );
        assert!(
            f["confidence"].as_u64().unwrap_or(0) <= 100,
            "置信度越界：{f}"
        );
    }
}

/// 交叉引用端点必须双向一致，并说明地址是否落在某个函数里。
#[tokio::test]
async fn xrefs_endpoint_is_bidirectionally_consistent() {
    let (state, _target) = state_with_target(&build_elf_with_code());
    // call 指令在 0x401002
    let (status, body) = send(state, get_with_token("/api/xrefs?address=0000000000401002")).await;

    assert_eq!(status, StatusCode::OK, "响应: {body}");
    assert_eq!(body["address"], "0000000000401002");
    assert!(body["from"].is_array(), "应有 from 数组");
    assert!(body["to"].is_array(), "应有 to 数组");
    // function 为 null 是**真实**结论（地址不在已知函数里），不是错误
    assert!(
        body["function"].is_null() || body["function"]["start"].is_string(),
        "function 要么是 null，要么是函数对象：{body}"
    );

    // 反向查同一条边：从 call 目标往回看，应当能看到来向引用
    let outgoing = body["from"].as_array().expect("from");
    if let Some(first) = outgoing.first() {
        let target = first["to"].as_str().expect("to 字段").to_string();
        let (state2, _target2) = state_with_target(&build_elf_with_code());
        let (status2, body2) = send(
            state2,
            get_with_token(&format!("/api/xrefs?address={target}")),
        )
        .await;
        assert_eq!(status2, StatusCode::OK, "反向查询响应: {body2}");
        let incoming = body2["to"].as_array().expect("to");
        assert!(
            !incoming.is_empty(),
            "A→B 存在时，B 的 to 里必须能查到 A（双向索引不一致）：{body2}"
        );
    }
}

/// 地址解析失败必须报错 —— 不能悄悄回退到 0 假装成功。
#[tokio::test]
async fn xrefs_endpoint_rejects_garbage_address() {
    let (state, _target) = state_with_target(&build_elf_with_code());
    let (status, body) = send(state, get_with_token("/api/xrefs?address=not-an-address")).await;

    assert_eq!(status, StatusCode::BAD_REQUEST, "响应: {body}");
    assert!(
        body["error"].as_str().unwrap_or("").contains("无法解析"),
        "应说清地址解析失败：{body}"
    );
}

/// 字符串端点：总数与分页要自洽。
#[tokio::test]
async fn strings_endpoint_pages_consistently() {
    let (state, _target) = state_with_target(&build_elf_with_code());
    let (status, body) = send(state, get_with_token("/api/strings")).await;

    assert_eq!(status, StatusCode::OK, "响应: {body}");
    let total = body["total"].as_u64().expect("total");
    let strings = body["strings"].as_array().expect("strings");
    assert!(
        strings.len() as u64 <= total,
        "本页条数不能超过总数：{} > {total}",
        strings.len()
    );

    // 地址字段同样必须是定长小写十六进制
    for s in strings {
        let addr = s["address"].as_str().expect("address");
        assert_eq!(addr.len(), 16, "字符串地址不是定长：{addr}");
    }
}

/// 十六进制视图：读到的字节数与行内容必须自洽。
///
/// 这里请求 32 字节而段只有 16 字节：服务端必须**如实报短**
/// （`bytes_read = 16`），而不是失败或用零填充凑满 32。
#[tokio::test]
async fn hex_endpoint_reports_actual_bytes_read() {
    let (state, _target) = state_with_target(&build_elf_with_code());
    let (status, body) = send(
        state,
        get_with_token("/api/hex?address=0000000000401000&length=32"),
    )
    .await;

    assert_eq!(status, StatusCode::OK, "响应: {body}");
    assert_eq!(body["row_bytes"], 16);
    assert_eq!(body["address"], "0000000000401000");

    let read = body["bytes_read"].as_u64().expect("bytes_read") as usize;
    assert_eq!(read, 16, "段只有 16 字节，必须如实报 16：{body}");

    let rows = body["rows"].as_array().expect("rows");
    // 每行的 hex 字段按空格分隔的字节数之和应等于 bytes_read
    let total_from_rows: usize = rows
        .iter()
        .map(|r| r["hex"].as_str().expect("hex").split(' ').count())
        .sum();
    assert_eq!(
        total_from_rows, read,
        "rows 里的字节数应等于 bytes_read（{total_from_rows} != {read}）"
    );

    // 首行必须是我们写进去的机器码：90 90 e8 00 00 00 00 90 c3
    let first = rows[0]["hex"].as_str().expect("hex");
    assert!(
        first.starts_with("90 90 e8 00 00 00 00 90 c3"),
        "首行应是写入的机器码，实际：{first}"
    );
}

/// 十六进制视图越过映射区间时必须报错，而不是返回零填充。
#[tokio::test]
async fn hex_endpoint_rejects_unmapped_address() {
    let (state, _target) = state_with_target(&build_elf_with_code());
    // 0xdeadbeef 远在任何已映射区间之外
    let (status, body) = send(
        state,
        get_with_token("/api/hex?address=00000000deadbeef&length=16"),
    )
    .await;

    assert_eq!(status, StatusCode::BAD_REQUEST, "响应: {body}");
    assert!(
        body["error"]
            .as_str()
            .unwrap_or("")
            .contains("不在任何已映射区间"),
        "应说清地址没有映射，而不是返回零填充：{body}"
    );
}

/// 标注往返：写入 → 读回，且地址是定长十六进制字符串。
#[tokio::test]
async fn annotation_roundtrip_through_http() {
    let (state, _target) = state_with_target(&build_elf_with_code());
    let address = "0000000000401000";

    let (status, body) = send(
        state.clone(),
        json_request(
            "PUT",
            "/api/annotations",
            serde_json::json!({
                "address": address,
                "kind": "name",
                "text": "my_renamed_function"
            }),
        ),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "写入响应: {body}");
    assert_eq!(body["ok"], true);
    assert_eq!(body["address"], address);
    // 关键：写入标注**不触发**重新分析
    assert_eq!(
        body["reanalyzed"], false,
        "写标注不该触发重新分析 —— 那会让大目标上改个名要等几十秒"
    );

    let (status, body) = send(
        state.clone(),
        get_with_token("/api/annotations?from=0000000000401000&to=0000000000402000"),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "读取响应: {body}");

    let list = body["annotations"].as_array().expect("annotations");
    assert_eq!(list.len(), 1, "应读到 1 条标注：{body}");
    assert_eq!(
        list[0]["address"], address,
        "标注地址必须是定长十六进制字符串"
    );
    assert_eq!(list[0]["kind"], "name", "类别用稳定短名");
    assert_eq!(list[0]["text"], "my_renamed_function");
}

/// 空标注必须被拒绝：没有内容的标注行没有意义。
#[tokio::test]
async fn empty_annotation_is_rejected() {
    let (state, _target) = state_with_target(&build_elf_with_code());
    let (status, body) = send(
        state,
        json_request(
            "PUT",
            "/api/annotations",
            serde_json::json!({
                "address": "0000000000401000",
                "kind": "comment"
            }),
        ),
    )
    .await;

    assert_eq!(status, StatusCode::BAD_REQUEST, "响应: {body}");
    assert!(
        body["error"].as_str().unwrap_or("").contains("空标注"),
        "应拒绝空标注：{body}"
    );
}

/// 未知标注类别必须报错并列出可用取值，不能猜一个默认类别。
#[tokio::test]
async fn unknown_annotation_kind_is_rejected_with_options() {
    let (state, _target) = state_with_target(&build_elf_with_code());
    let (status, body) = send(
        state,
        json_request(
            "PUT",
            "/api/annotations",
            serde_json::json!({
                "address": "0000000000401000",
                "kind": "not-a-real-kind",
                "text": "x"
            }),
        ),
    )
    .await;

    assert_eq!(status, StatusCode::BAD_REQUEST, "响应: {body}");
    let error = body["error"].as_str().unwrap_or("");
    assert!(error.contains("无法识别"), "应说明类别无法识别：{body}");
    assert!(error.contains("name"), "应列出可用取值：{body}");
}

/// 删除标注后必须读不到；重复删除保持幂等。
///
/// 这条测试曾经"失败"，但失败原因是测试自身：两个标注测试共用同一个
/// 目标内容哈希 → 共用同一个工程库 → 这里读到了上一个测试留下的行。
/// 现在每个测试有独占目录（见 `write_temp_dir`）。
#[tokio::test]
async fn annotation_delete_is_idempotent() {
    let (state, _target) = state_with_target(&build_elf_with_code());
    let address = "0000000000401000";

    let (status, body) = send(
        state.clone(),
        json_request(
            "PUT",
            "/api/annotations",
            serde_json::json!({"address": address, "kind": "bookmark", "text": "todo"}),
        ),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "写入响应: {body}");

    for attempt in 0..2 {
        let (status, body) = send(
            state.clone(),
            Request::builder()
                .method("DELETE")
                .uri(format!("/api/annotations?address={address}&kind=bookmark"))
                .header(TOKEN_HEADER, TOKEN)
                .body(Body::empty())
                .expect("构造请求"),
        )
        .await;
        assert_eq!(
            status,
            StatusCode::OK,
            "第 {attempt} 次删除应成功（幂等）：{body}"
        );
    }

    let (status, body) = send(
        state,
        get_with_token("/api/annotations?from=0000000000401000&to=0000000000402000"),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "读取响应: {body}");
    assert!(
        body["annotations"]
            .as_array()
            .expect("annotations")
            .is_empty(),
        "删除后应读不到：{body}"
    );
}

/// 标注端点也要令牌：主数据可写意味着它比只读端点更需要防护。
#[tokio::test]
async fn annotation_write_requires_token() {
    let (state, _target) = state_with_target(&build_elf_with_code());
    let request = Request::builder()
        .method("PUT")
        .uri("/api/annotations")
        .header("content-type", "application/json")
        .body(Body::from(
            serde_json::json!({
                "address": "0000000000401000",
                "kind": "name",
                "text": "x"
            })
            .to_string(),
        ))
        .expect("构造请求");
    let (status, body) = send(state, request).await;

    assert_eq!(status, StatusCode::FORBIDDEN, "响应: {body}");
}
