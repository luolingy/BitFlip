//! M2b 服务层：DEX 端点（`/api/dex/*`）。
//!
//! 合成的合规 DEX 与 loader / CLI 的测试共用同一份
//! （`crates/bitflip-loader/tests/common/dex_fixture.rs`，用 `#[path]` 引入）：
//! 样本只有一份，才不会出现"三个 crate 各自养一份样本、然后慢慢分叉"。
//!
//! 真实 APK 的那条（`BITFLIP_TEST_APK`）是 `#[ignore]`，样本缺失时**硬失败** ——
//! 一条会静默跳过的端到端测试等于没有端到端测试。

use std::path::PathBuf;

use axum::body::{to_bytes, Body};
use axum::http::{Request, StatusCode};
use bitflip_server::{router, AppState, TOKEN_HEADER};
use serde_json::Value;
use tower::ServiceExt;

// 与 loader / CLI 测试共用的合成样本（`allow(dead_code)`：这里只用得到 `build()`）。
#[path = "../../bitflip-loader/tests/common/dex_fixture.rs"]
#[allow(dead_code)]
mod fixture;

const TOKEN: &str = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
const PORT: u16 = 8794;

/// 把合成样本写成一个临时 `.dex` 文件，并返回它所在的临时目录（保持存活）。
fn minimal_dex_target() -> (tempfile::TempDir, PathBuf) {
    let dir = tempfile::tempdir().expect("临时目录");
    let path = dir.path().join("minimal.dex");
    std::fs::write(&path, fixture::build()).expect("写入合成样本");
    (dir, path)
}

/// 单文件 DEX 目标的状态。
fn state_with_minimal_dex(path: &std::path::Path) -> AppState {
    let session = bitflip_core::Session::open(path, bitflip_core::OpenOptions::default())
        .expect("打开单文件 DEX 目标");
    AppState::new(TOKEN, None)
        .with_session(std::sync::Arc::new(session))
        .with_allowed_origins(bitflip_server::default_allowed_origins(PORT, &[]))
}

fn get_with_token(path: &str) -> Request<Body> {
    Request::builder()
        .uri(path)
        .header(TOKEN_HEADER, TOKEN)
        .body(Body::empty())
        .expect("构造请求")
}

/// 查询串里的值要按 RFC 3986 转义。
///
/// smali 标识里 `>`、`[`、`]` 都是**不允许**直接出现在 URI 里的字符
/// （`Lcom/Foo;->bar([I)V` 一条就占了三个）。一开始手写 URL 时漏了这一个，
/// 结果是 `Request::builder()` 直接报错 —— 这类错误在"测试绿了"之前就会暴露，
/// 但如果当时顺手把签名简化掉，被测的就不再是真实形状了。
fn encode(value: &str) -> String {
    let mut out = String::with_capacity(value.len());
    for byte in value.bytes() {
        if byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'.' | b'_' | b'~') {
            out.push(byte as char);
        } else {
            out.push('%');
            out.push_str(&format!("{byte:02X}"));
        }
    }
    out
}

/// 拼一条带参数的方法详情 URL。
fn method_url(member: &str, signature: &str, tail: &str) -> String {
    format!(
        "/api/dex/method?member={}&signature={}{tail}",
        encode(member),
        encode(signature)
    )
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

/// `/api/dex/inputs` 是标签页的数据源：每个 DEX 单独一条，**各自的降级说明跟着自己**。
#[tokio::test]
async fn dex_inputs_lists_the_single_file_target() {
    let (_dir, path) = minimal_dex_target();
    let (status, body) = send(
        state_with_minimal_dex(&path),
        get_with_token("/api/dex/inputs"),
    )
    .await;

    assert_eq!(status, StatusCode::OK, "响应: {body}");
    // 比常量而不是写死数字：这条断言问的是"服务把版本带出来了吗"，
    // 不是"版本永远是 1"（`CORE_API_VERSION` 形状变更时这里不该红）。
    assert_eq!(
        body["server_api_version"].as_u64(),
        Some(u64::from(bitflip_server::SERVER_API_VERSION)),
        "服务层版本要带上：{body}"
    );
    assert_eq!(body["format_version"], 1, "DEX 报告版本要带上：{body}");

    let inputs = body["inputs"].as_array().expect("inputs");
    assert_eq!(inputs.len(), 1, "单文件目标只有一个 DEX：{body}");
    assert_eq!(inputs[0]["name"], "minimal.dex");
    assert_eq!(
        inputs[0]["role"],
        Value::Null,
        "裸 .dex 文件不是 APK 的命名位置，角色必须是 null 而不是编一个"
    );
    assert_eq!(inputs[0]["class_count"], 1);
    assert_eq!(inputs[0]["method_count"], 2);
    assert_eq!(inputs[0]["method_count_with_code"], 2);
}

/// 类列表：分页 + 过滤，并且 `total` 是**过滤后**的总数（前端才说得出"共 N 个"）。
#[tokio::test]
async fn dex_classes_pages_and_filters() {
    let (_dir, path) = minimal_dex_target();

    let (status, body) = send(
        state_with_minimal_dex(&path.clone()),
        get_with_token("/api/dex/classes?member=minimal.dex"),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "响应: {body}");
    assert_eq!(body["member"], "minimal.dex");
    assert_eq!(body["total"], 1);
    assert_eq!(body["classes"][0]["descriptor"], "Lcom/example/Foo;");
    assert_eq!(body["classes"][0]["short_name"], "Foo");
    assert_eq!(body["classes"][0]["method_count"], 2);
    assert_eq!(body["classes"][0]["methods_with_code"], 2);

    // 过滤命中 0 条：`total` 也要跟着变成 0（而不是仍然报总数）。
    let (status, body) = send(
        state_with_minimal_dex(&path.clone()),
        get_with_token("/api/dex/classes?member=minimal.dex&search=Activity"),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body["total"], 0, "过滤后总数为 0：{body}");
    assert_eq!(body["classes"].as_array().map(Vec::len), Some(0));

    // 大小写不敏感：`foo` 要能命中 `Lcom/example/Foo;`。
    let (status, body) = send(
        state_with_minimal_dex(&path.clone()),
        get_with_token("/api/dex/classes?member=minimal.dex&search=foo"),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body["total"], 1, "过滤应当大小写不敏感：{body}");

    // 分页越界：offset 超过总数时返回空页，不报错（前端翻到头了就停）。
    let (status, body) = send(
        state_with_minimal_dex(&path),
        get_with_token("/api/dex/classes?member=minimal.dex&offset=99"),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body["offset"], 1, "offset 被夹到 total：{body}");
    assert_eq!(body["classes"].as_array().map(Vec::len), Some(0));
    assert!(
        body["notes"].as_array().is_some_and(|notes| notes
            .iter()
            .any(|n| n.as_str().is_some_and(|n| n.contains("越过末尾")))),
        "空页要说清是翻过头了：{body}"
    );
}

/// 类详情：方法列表要区分"有字节码"与"没有"，并把 `code_off` 给成定长十六进制。
#[tokio::test]
async fn dex_class_lists_methods_with_code_offsets() {
    let (_dir, path) = minimal_dex_target();
    let (status, body) = send(
        state_with_minimal_dex(&path),
        get_with_token("/api/dex/class?member=minimal.dex&descriptor=Lcom/example/Foo;"),
    )
    .await;

    assert_eq!(status, StatusCode::OK, "响应: {body}");
    assert_eq!(body["descriptor"], "Lcom/example/Foo;");
    assert_eq!(body["short_name"], "Foo");
    assert_eq!(body["superclass"], "Ljava/lang/Object;");
    assert_eq!(body["source_file"], "Foo.java");

    let fields = body["fields"].as_array().expect("fields");
    assert_eq!(fields.len(), 2, "样本有静态 x 与实例 s：{body}");
    let static_field = fields
        .iter()
        .find(|f| f["name"] == "x")
        .expect("静态字段 x");
    assert_eq!(
        static_field["is_static"], true,
        "静态与否来自 class_data：{body}"
    );
    let instance_field = fields
        .iter()
        .find(|f| f["name"] == "s")
        .expect("实例字段 s");
    assert_eq!(instance_field["is_static"], false);

    let methods = body["methods"].as_array().expect("methods");
    assert_eq!(methods.len(), 2);
    let bar = methods
        .iter()
        .find(|m| m["name"] == "bar")
        .expect("方法 bar");
    assert_eq!(bar["signature"], "Lcom/example/Foo;->bar(I)V");
    assert_eq!(bar["has_code"], true);
    let code_off = bar["code_off"].as_str().expect("code_off 是字符串");
    assert_eq!(code_off.len(), 16, "定长 16 位十六进制：{code_off}");
    assert!(
        code_off
            .chars()
            .all(|c| c.is_ascii_hexdigit() && !c.is_ascii_uppercase()),
        "小写十六进制：{code_off}"
    );
    assert_eq!(bar["is_direct"], false, "bar 是虚方法：{body}");
}

/// 类名写法不对时给格式提示；写法对但不存在时只说找不到（不再重复提示格式）。
#[tokio::test]
async fn dex_class_separates_a_format_hint_from_a_missing_class() {
    let (_dir, path) = minimal_dex_target();

    let (status, body) = send(
        state_with_minimal_dex(&path.clone()),
        get_with_token("/api/dex/class?member=minimal.dex&descriptor=Foo"),
    )
    .await;
    assert_eq!(status, StatusCode::NOT_FOUND, "响应: {body}");
    let message = body["error"].as_str().expect("error");
    assert!(message.contains("只做精确匹配"), "{message}");
    assert!(message.contains("Lcom/Foo;"), "{message}");

    let (status, body) = send(
        state_with_minimal_dex(&path),
        get_with_token("/api/dex/class?member=minimal.dex&descriptor=Lcom/example/Nope;"),
    )
    .await;
    assert_eq!(status, StatusCode::NOT_FOUND);
    let message = body["error"].as_str().expect("error");
    assert!(message.contains("没有类"), "{message}");
    assert!(
        !message.contains("只做精确匹配"),
        "格式对时不该再提示格式：{message}"
    );
}

/// 方法详情：指令 + 文本 CFG + 符号解析账。
#[tokio::test]
async fn dex_method_returns_instructions_and_a_text_cfg() {
    let (_dir, path) = minimal_dex_target();
    let (status, body) = send(
        state_with_minimal_dex(&path),
        get_with_token(&method_url("minimal.dex", "Lcom/example/Foo;->bar(I)V", "")),
    )
    .await;

    assert_eq!(status, StatusCode::OK, "响应: {body}");
    assert_eq!(body["signature"], "Lcom/example/Foo;->bar(I)V");
    assert_eq!(body["has_code"], true);
    assert_eq!(body["registers_size"], 1);
    assert_eq!(body["ins_size"], 0);
    assert_eq!(body["outs_size"], 0);
    assert_eq!(body["instruction_count"], 1);
    assert_eq!(body["symbols"], true);
    assert_eq!(body["unsupported_operands"], 0);
    assert_eq!(body["unavailable_operands"], 0);

    let instructions = body["instructions"].as_array().expect("instructions");
    assert_eq!(instructions.len(), 1);
    assert_eq!(instructions[0]["text"], "0000: return-void");
    assert_eq!(instructions[0]["address"], "0000000000000000");
    assert_eq!(
        instructions[0]["opcode"], 0x0e,
        "return-void 的 opcode 是 0x0e"
    );

    assert_eq!(body["block_count"], 1);
    assert_eq!(body["edge_count"], 0);
    assert_eq!(body["unresolved_edge_targets"], 0);
    let cfg = body["cfg_text"].as_str().expect("cfg_text");
    assert!(cfg.contains("CFG：1 个块、0 条边"), "CFG 文本：{cfg}");
    assert!(cfg.contains("块 0 @0000（1 条指令）"), "CFG 文本：{cfg}");
}

/// 指令分页：`instruction_count` 始终是**整个方法**的数，只有 `instructions` 分页。
#[tokio::test]
async fn dex_method_pages_instructions_but_still_reports_the_full_count() {
    let (_dir, path) = minimal_dex_target();
    let (status, body) = send(
        state_with_minimal_dex(&path),
        get_with_token(&method_url(
            "minimal.dex",
            "Lcom/example/Foo;->bar(I)V",
            "&offset=0&limit=1",
        )),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "响应: {body}");
    assert_eq!(body["instruction_count"], 1, "总数不受分页影响：{body}");
    assert_eq!(body["limit"], 1);
    assert_eq!(body["instructions"].as_array().map(Vec::len), Some(1));

    // 偏移超出末尾：给出空页并说明，不是错误。
    let (status, body) = send(
        state_with_minimal_dex(&path),
        get_with_token(&method_url(
            "minimal.dex",
            "Lcom/example/Foo;->bar(I)V",
            "&offset=5",
        )),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body["instruction_count"], 1);
    assert_eq!(body["instructions"].as_array().map(Vec::len), Some(0));
    let notes = body["notes"].as_array().expect("notes");
    assert!(
        notes
            .iter()
            .any(|n| n.as_str().is_some_and(|n| n.contains("越过末尾"))),
        "空页必须说明是翻过头了，否则看起来像这个方法没有指令：{body}"
    );
}

/// 缺少必填参数、成员名不存在、参数名写错——三者都必须是 400，且提示不同。
#[tokio::test]
async fn dex_endpoints_reject_bad_requests_with_actionable_messages() {
    let (_dir, path) = minimal_dex_target();

    // 没给 member：提示本次有哪些可选。
    let (status, body) = send(
        state_with_minimal_dex(&path.clone()),
        get_with_token("/api/dex/classes"),
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST, "响应: {body}");
    let message = body["error"].as_str().expect("error");
    assert!(message.contains("缺少 member 参数"), "{message}");
    assert!(
        message.contains("minimal.dex"),
        "要列出可用的名字：{message}"
    );

    // member 给了但不存在：与"没给"要能区分。
    let (status, body) = send(
        state_with_minimal_dex(&path.clone()),
        get_with_token("/api/dex/classes?member=classes9.dex"),
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    let message = body["error"].as_str().expect("error");
    assert!(message.contains("没有名为"), "{message}");

    // 没给 signature：提示 smali 标识的写法。
    let (status, body) = send(
        state_with_minimal_dex(&path.clone()),
        get_with_token("/api/dex/method?member=minimal.dex"),
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    let message = body["error"].as_str().expect("error");
    assert!(message.contains("缺少 signature 参数"), "{message}");

    // 方法标识写法不对：给格式提示，而不是只说找不到。
    let (status, body) = send(
        state_with_minimal_dex(&path.clone()),
        get_with_token(&method_url("minimal.dex", "bar", "")),
    )
    .await;
    assert_eq!(status, StatusCode::NOT_FOUND);
    let message = body["error"].as_str().expect("error");
    assert!(message.contains("只做精确匹配"), "{message}");

    // 参数名写错：`deny_unknown_fields` 让它报错，而不是被静默忽略。
    let (status, body) = send(
        state_with_minimal_dex(&path),
        get_with_token("/api/dex/classes?member=minimal.dex&limt=5"),
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST, "响应: {body}");
    let message = body.to_string();
    assert!(message.contains("limt"), "要指出不认识哪个参数：{message}");
}

/// 没有会话、以及目标里没有 DEX 时，都不能返回"空列表"。
#[tokio::test]
async fn dex_inputs_explains_why_there_is_nothing_to_show() {
    // 没有目标。
    let (status, body) = send(
        AppState::new(TOKEN, None)
            .with_allowed_origins(bitflip_server::default_allowed_origins(PORT, &[])),
        get_with_token("/api/dex/inputs"),
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST, "响应: {body}");
    assert!(
        body["error"]
            .as_str()
            .is_some_and(|m| m.contains("没有打开目标")),
        "要说清是没目标：{body}"
    );

    // 有目标但没有 DEX 成员（ar 归档）。
    let archive = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("..")
        .join("..")
        .join("tests")
        .join("fixtures")
        .join("generated")
        .join("libelf-multi.a");
    assert!(
        archive.exists(),
        "缺少 fixture {}。先跑 `pwsh -File scripts/gen-fixtures.ps1`。",
        archive.display()
    );
    let session = bitflip_core::Session::open(&archive, bitflip_core::OpenOptions::default())
        .expect("打开归档");
    let state = AppState::new(TOKEN, None)
        .with_session(std::sync::Arc::new(session))
        .with_allowed_origins(bitflip_server::default_allowed_origins(PORT, &[]));
    let (status, body) = send(state, get_with_token("/api/dex/inputs")).await;
    assert_eq!(status, StatusCode::BAD_REQUEST, "响应: {body}");
    assert!(
        body["error"]
            .as_str()
            .is_some_and(|m| m.contains("没有以 .dex 结尾的成员")),
        "要说清是目标里没有 DEX：{body}"
    );
}

/// 真实 APK：三个 DEX、类浏览、方法指令与 CFG、以及"没有字节码"这条合法结论。
///
/// 样本路径取 `BITFLIP_TEST_APK`，默认是开发机上的那份；**样本不在就直接失败**。
#[tokio::test]
#[ignore = "需要本机真实 APK（32MB）；用 --ignored 手动跑"]
async fn the_real_apk_lists_three_dex_files_and_renders_a_method() {
    let path = std::env::var("BITFLIP_TEST_APK")
        .unwrap_or_else(|_| "C:\\Users\\Administrator\\Downloads\\ah-app-release.apk".to_owned());
    let apk = PathBuf::from(&path);
    assert!(
        apk.exists(),
        "找不到真实 APK：{}（用 BITFLIP_TEST_APK 指定）",
        apk.display()
    );
    let session =
        bitflip_core::Session::open(&apk, bitflip_core::OpenOptions::default()).expect("打开 APK");
    let state = AppState::new(TOKEN, None)
        .with_session(std::sync::Arc::new(session))
        .with_allowed_origins(bitflip_server::default_allowed_origins(PORT, &[]));

    // ── 标签页：三个 DEX，各自的计数与容错说明
    let (status, body) = send(state.clone(), get_with_token("/api/dex/inputs")).await;
    assert_eq!(status, StatusCode::OK, "响应: {body}");
    let inputs = body["inputs"].as_array().expect("inputs");
    assert_eq!(inputs.len(), 3, "样本 APK 有三个 DEX：{body}");
    let names: Vec<&str> = inputs
        .iter()
        .map(|input| input["name"].as_str().unwrap_or_default())
        .collect();
    assert_eq!(names, ["classes.dex", "classes2.dex", "classes3.dex"]);
    assert_eq!(inputs[0]["role"], "主 dex", "第一个是主 dex：{body}");
    assert_eq!(inputs[1]["role"], "dex 序号 2");
    assert!(
        inputs[0]["class_count"].as_u64().unwrap_or(0) > 1000,
        "真实 DEX 的类数应当是几千：{body}"
    );
    // 降级说明跟着**那一个**文件走（样本上 classes.dex / classes2.dex 各有一处）。
    let first_notes = inputs[0]["notes"].as_array().expect("notes");
    assert!(
        first_notes
            .iter()
            .any(|n| n.as_str().is_some_and(|n| n.contains("OutOfOrder"))),
        "真实样本上解析器的容错记录必须出现在输入列表里：{body}"
    );
    println!(
        "---- 真实 APK 的 DEX 输入：{} / {} / {} 类 ----",
        inputs[0]["class_count"], inputs[1]["class_count"], inputs[2]["class_count"]
    );

    // ── 类浏览：取第一页，再从第一个类跳到详情
    let (status, body) = send(
        state.clone(),
        get_with_token("/api/dex/classes?member=classes.dex&limit=3"),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "响应: {body}");
    assert_eq!(body["limit"], 3);
    let classes = body["classes"].as_array().expect("classes");
    assert_eq!(classes.len(), 3);
    assert!(
        body["total"].as_u64().unwrap_or(0) > 1000,
        "过滤前总数是全部类：{body}"
    );
    let descriptor = classes[0]["descriptor"]
        .as_str()
        .expect("descriptor")
        .to_string();
    println!("---- 第一个类：{descriptor} ----");

    let (status, body) = send(
        state.clone(),
        get_with_token(&format!(
            "/api/dex/class?member=classes.dex&descriptor={}",
            encode(&descriptor)
        )),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "响应: {body}");
    let methods = body["methods"].as_array().expect("methods");
    assert!(!methods.is_empty(), "第一个类应当有方法：{body}");

    // 找一个有字节码的方法（真实 DEX 上绝大多数都有）。
    let with_code = methods
        .iter()
        .find(|method| method["has_code"] == true)
        .expect("应有一个带字节码的方法");
    let signature = with_code["signature"]
        .as_str()
        .expect("signature")
        .to_string();
    let (status, body) = send(
        state.clone(),
        get_with_token(&method_url("classes.dex", &signature, "")),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "响应: {body}");
    assert_eq!(body["has_code"], true);
    assert!(
        body["instruction_count"].as_u64().unwrap_or(0) > 0,
        "真实方法应当有指令：{body}"
    );
    assert!(
        body["cfg_text"]
            .as_str()
            .is_some_and(|cfg| cfg.contains("CFG：")),
        "要给出文本 CFG：{body}"
    );
    assert_eq!(body["symbols"], true);
    assert_eq!(
        body["unavailable_operands"], 0,
        "异常操作数必须为 0：{body}"
    );
    println!(
        "---- {signature}：{} 条指令、{} 个块、unsupported {} / unavailable {} ----",
        body["instruction_count"],
        body["block_count"],
        body["unsupported_operands"],
        body["unavailable_operands"]
    );

    // ── "没有字节码"是合法结论：抽象 / native 方法要给出说明而不是错误
    //
    // 用户提到的这个类里恰好每个方法都有字节码，所以不能只看它：只在第一个类里
    // 找就等于"没找到就跳过"，而跳过会让这条分支永远没人验证。
    // 类列表带 `methods_with_code`，先挑一个**确实有无字节码方法**的类。
    let (status, class_page) = send(
        state.clone(),
        get_with_token("/api/dex/classes?member=classes.dex&limit=200"),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "响应: {class_page}");
    let candidate = class_page["classes"]
        .as_array()
        .expect("classes")
        .iter()
        .find(|class| {
            class["method_count"].as_u64().unwrap_or(0)
                > class["methods_with_code"].as_u64().unwrap_or(0)
        })
        .cloned();
    let Some(candidate) = candidate else {
        panic!("前 200 个类里没有'含无字节码方法'的类，这条分支没被验证到：{class_page}");
    };
    let candidate_descriptor = candidate["descriptor"].as_str().expect("descriptor");
    let (status, body) = send(
        state.clone(),
        get_with_token(&format!(
            "/api/dex/class?member=classes.dex&descriptor={}",
            encode(candidate_descriptor)
        )),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "响应: {body}");
    let method = body["methods"]
        .as_array()
        .expect("methods")
        .iter()
        .find(|method| method["has_code"] == false)
        .cloned()
        .expect("这个类应当有无字节码的方法");
    let signature = method["signature"].as_str().expect("signature");
    let (status, body) = send(
        state.clone(),
        get_with_token(&method_url("classes.dex", signature, "")),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "没有字节码不是错误：{body}");
    assert_eq!(body["has_code"], false);
    assert_eq!(body["code_off"], Value::Null);
    assert_eq!(body["instructions"].as_array().map(Vec::len), Some(0));
    assert!(
        body["notes"].as_array().is_some_and(|notes| notes
            .iter()
            .any(|n| n.as_str().is_some_and(|n| n.contains("没有字节码")))),
        "要说清为什么没有指令：{body}"
    );
    println!("---- 无字节码方法（合法结论）：{candidate_descriptor} {signature} ----");
}
