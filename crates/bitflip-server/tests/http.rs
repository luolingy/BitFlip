//! 服务层 HTTP 契约测试。
//!
//! 这里覆盖的是 M0 的验收标准：健康检查可用、缺令牌/错令牌 403、跨站 Origin 403、
//! 静态资源与 SPA 回退可访问。用 `tower::ServiceExt::oneshot` 直接打路由，
//! 不真正监听端口 —— 端口绑定单独由 `bind` 的单元测试覆盖。

use axum::body::{to_bytes, Body};
use axum::http::{header, Request, StatusCode};
use bitflip_core::{OpenOptions, Session};
use bitflip_server::{router, AppState, TOKEN_HEADER};
use serde_json::Value;
use tower::ServiceExt;

const TOKEN: &str = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
const PORT: u16 = 8790;

fn test_state(target: Option<bitflip_core::TargetInfo>) -> AppState {
    AppState::new(TOKEN, target)
        .with_allowed_origins(bitflip_server::default_allowed_origins(PORT, &[]))
}

fn get(path: &str) -> Request<Body> {
    Request::builder()
        .uri(path)
        .body(Body::empty())
        .expect("构造请求")
}

fn get_with_token(path: &str) -> Request<Body> {
    Request::builder()
        .uri(path)
        .header(TOKEN_HEADER, TOKEN)
        .body(Body::empty())
        .expect("构造请求")
}

async fn send(state: AppState, request: Request<Body>) -> (StatusCode, Value) {
    let response = router(state).oneshot(request).await.expect("路由响应");
    let status = response.status();
    let bytes = to_bytes(response.into_body(), 4 * 1024 * 1024)
        .await
        .expect("读取响应体");
    let body = if bytes.is_empty() {
        Value::Null
    } else {
        serde_json::from_slice(&bytes)
            .unwrap_or_else(|_| Value::String(String::from_utf8_lossy(&bytes).to_string()))
    };
    (status, body)
}

async fn send_raw(state: AppState, request: Request<Body>) -> (StatusCode, String, String) {
    let response = router(state).oneshot(request).await.expect("路由响应");
    let status = response.status();
    let content_type = response
        .headers()
        .get(header::CONTENT_TYPE)
        .and_then(|v| v.to_str().ok())
        .unwrap_or_default()
        .to_string();
    let bytes = to_bytes(response.into_body(), 4 * 1024 * 1024)
        .await
        .expect("读取响应体");
    (
        status,
        content_type,
        String::from_utf8_lossy(&bytes).to_string(),
    )
}

#[tokio::test]
async fn health_requires_token() {
    let (status, body) = send(test_state(None), get("/api/health")).await;
    assert_eq!(status, StatusCode::FORBIDDEN);
    assert!(body["error"]
        .as_str()
        .expect("错误信息")
        .contains("缺少访问令牌"));
}

#[tokio::test]
async fn health_rejects_wrong_token() {
    let request = Request::builder()
        .uri("/api/health")
        .header(TOKEN_HEADER, "wrong-token")
        .body(Body::empty())
        .expect("构造请求");
    let (status, body) = send(test_state(None), request).await;
    assert_eq!(status, StatusCode::FORBIDDEN);
    assert!(body["error"].as_str().expect("错误信息").contains("不正确"));
}

#[tokio::test]
async fn health_accepts_header_and_query_token() {
    let (status, body) = send(test_state(None), get_with_token("/api/health")).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body["ok"], Value::Bool(true));
    assert_eq!(body["name"], "bitflip");
    assert_eq!(body["name_zh"], "比特翻转");
    assert_eq!(body["server_api_version"], 1);
    assert_eq!(body["core_api_version"], 1);
    assert_eq!(body["target"], Value::Null);
    assert!(body["version"].is_string());
    assert!(body["uptime_ms"].is_number());
    assert!(body["ui_embedded"].is_boolean());

    let (status, body) = send(test_state(None), get(&format!("/api/health?token={TOKEN}"))).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body["ok"], Value::Bool(true));
}

#[tokio::test]
async fn cross_site_origin_is_rejected_even_with_valid_token() {
    let request = Request::builder()
        .uri("/api/health")
        .header(TOKEN_HEADER, TOKEN)
        .header(header::ORIGIN, "http://evil.example")
        .body(Body::empty())
        .expect("构造请求");
    let (status, body) = send(test_state(None), request).await;
    assert_eq!(status, StatusCode::FORBIDDEN);
    assert!(body["error"]
        .as_str()
        .expect("错误信息")
        .contains("跨站请求被拒绝"));
}

#[tokio::test]
async fn allowed_origin_passes() {
    let request = Request::builder()
        .uri("/api/health")
        .header(TOKEN_HEADER, TOKEN)
        .header(header::ORIGIN, format!("http://127.0.0.1:{PORT}"))
        .body(Body::empty())
        .expect("构造请求");
    let (status, _body) = send(test_state(None), request).await;
    assert_eq!(status, StatusCode::OK);
}

#[tokio::test]
async fn target_endpoint_returns_opened_target() {
    let dir = tempfile::tempdir().expect("tempdir");
    let path = dir.path().join("sample.exe");
    let mut bytes = vec![0u8; 0x220];
    bytes[0] = b'M';
    bytes[1] = b'Z';
    bytes[0x3c..0x40].copy_from_slice(&0x80u32.to_le_bytes());
    bytes[0x80..0x84].copy_from_slice(b"PE\0\0");
    bytes[0x84..0x86].copy_from_slice(&0x8664u16.to_le_bytes());
    bytes[0x86..0x88].copy_from_slice(&3u16.to_le_bytes());
    let opt = 0x80 + 24;
    bytes[opt..opt + 2].copy_from_slice(&0x20bu16.to_le_bytes());
    bytes[opt + 16..opt + 20].copy_from_slice(&0x1000u32.to_le_bytes());
    bytes[opt + 24..opt + 32].copy_from_slice(&0x1_4000_0000u64.to_le_bytes());
    std::fs::write(&path, &bytes).expect("写入样本");

    let session = Session::open(&path, OpenOptions::default()).expect("打开样本");
    let info = session.target_info();

    let (status, body) = send(test_state(Some(info)), get_with_token("/api/target")).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body["object"], "pe");
    assert_eq!(body["arch"], "x86_64/64/le");
    assert_eq!(body["entry"], "0000000140001000");
    assert_eq!(body["bits"], 64);

    // 没有目标时必须明确 404，而不是返回空对象
    let (status, body) = send(test_state(None), get_with_token("/api/target")).await;
    assert_eq!(status, StatusCode::NOT_FOUND);
    assert!(body["error"]
        .as_str()
        .expect("错误信息")
        .contains("没有打开目标"));
}

#[tokio::test]
async fn sections_endpoint_returns_parsed_structure() {
    let dir = tempfile::tempdir().expect("tempdir");
    let path = dir.path().join("sample.elf");
    // 一个含 .text 与 .data 两个真实节的 ELF64，用来验证"结构"页的数据源。
    let bytes = build_elf_with_two_sections();
    std::fs::write(&path, &bytes).expect("写入样本");

    let session = Session::open(&path, OpenOptions::default()).expect("打开样本");
    let state = test_state(Some(session.target_info())).with_parsed(session.parsed().cloned());

    let (status, body) = send(state, get_with_token("/api/sections")).await;
    assert_eq!(status, StatusCode::OK);

    // 顶层必须带版本号，UI 靠它判断字段含义
    assert_eq!(body["format_version"], 1);

    let parsed = &body["parsed"];
    assert!(!parsed.is_null(), "应有解析结果: {body}");

    let sections = parsed["sections"].as_array().expect("节数组");
    assert_eq!(
        sections.len(),
        3,
        "应有 .text/.data/.shstrtab 三个节: {sections:?}"
    );

    let names: Vec<&str> = sections
        .iter()
        .map(|s| s["name"].as_str().expect("节名"))
        .collect();
    // SHT_NULL 占位节被有意排除，因此这里只出现三个真实节
    assert_eq!(names, vec![".text", ".data", ".shstrtab"]);

    // 地址必须是定长 16 位小写十六进制（wire 契约）
    let addr = sections[0]["vaddr"].as_str().expect("虚拟地址");
    assert_eq!(addr.len(), 16, "地址应为定长 16 位: {addr}");
    assert_eq!(addr, "0000000000401000");

    // 权限与类别要能直接渲染
    assert_eq!(sections[0]["perms"], "r-x");
    assert_eq!(sections[0]["kind"], "code");
    assert_eq!(sections[0]["kind_label"], "代码");
    assert_eq!(sections[1]["perms"], "rw-");
    assert_eq!(sections[1]["kind"], "data");
    assert_eq!(sections[2]["kind"], "strtab");
    // 不参与映射的节不应声称有读权限
    assert_eq!(sections[2]["perms"], "---");
    assert_eq!(sections[2]["loaded"], false);
}

#[tokio::test]
async fn sections_endpoint_reports_malformed_file_without_failing() {
    // 畸形文件必须仍然返回 200 + 识别结论，parsed 为 null，
    // 失败原因出现在 notes 里 —— 而不是 500 或空响应（CLAUDE.md §7）。
    let dir = tempfile::tempdir().expect("tempdir");
    let path = dir.path().join("broken.elf");
    let mut bytes = build_elf_with_two_sections();
    bytes.truncate(20); // 截断成读不出节表的长度
    std::fs::write(&path, &bytes).expect("写入样本");

    let session = Session::open(&path, OpenOptions::default()).expect("打开样本");
    assert!(session.parsed().is_none(), "截断文件不应产生解析结果");

    let notes = &session.info().notes;
    assert!(
        notes.iter().any(|n| n.contains("解析失败")),
        "应在 notes 里说明失败原因: {notes:?}"
    );

    let state = test_state(Some(session.target_info())).with_parsed(session.parsed().cloned());
    let (status, body) = send(state, get_with_token("/api/sections")).await;

    assert_eq!(status, StatusCode::OK, "畸形文件不应导致 5xx");
    assert!(body["parsed"].is_null(), "解析失败时 parsed 应为 null");
    assert_eq!(body["target"]["object"], "elf", "识别结论仍应可用");
}

#[tokio::test]
async fn sections_endpoint_requires_token() {
    let (status, _) = send(test_state(None), get("/api/sections")).await;
    assert_eq!(status, StatusCode::FORBIDDEN);
}

/// 构造一个含 `.text` 与 `.data` 两个节的 ELF64 样本。
fn build_elf_with_two_sections() -> Vec<u8> {
    // 布局：[ELF 头 64][.text 数据 16][.data 数据 16][shstrtab][节表 3*64]
    let mut bytes = vec![0u8; 0x400];
    bytes[..4].copy_from_slice(b"\x7fELF");
    bytes[4] = 2; // 64 位
    bytes[5] = 1; // 小端
    bytes[6] = 1;
    bytes[16..18].copy_from_slice(&2u16.to_le_bytes()); // ET_EXEC
    bytes[18..20].copy_from_slice(&62u16.to_le_bytes()); // x86_64
    bytes[20..24].copy_from_slice(&1u32.to_le_bytes());
    bytes[24..32].copy_from_slice(&0x401000u64.to_le_bytes()); // e_entry
    bytes[40..48].copy_from_slice(&0x300u64.to_le_bytes()); // e_shoff
    bytes[52..54].copy_from_slice(&64u16.to_le_bytes()); // e_ehsize
    bytes[58..60].copy_from_slice(&64u16.to_le_bytes()); // e_shentsize
    bytes[60..62].copy_from_slice(&4u16.to_le_bytes()); // e_shnum（NULL + .text + .data + .shstrtab）
    bytes[62..64].copy_from_slice(&3u16.to_le_bytes()); // e_shstrndx（第 3 个节 = shstrtab）

    // .text 数据 @ 0x100，.data 数据 @ 0x120
    bytes[0x100..0x110].copy_from_slice(&[0x90u8; 16]);
    bytes[0x120..0x130].copy_from_slice(&[0x11u8; 16]);

    // .shstrtab @ 0x200
    let names = b"\0.text\0.data\0.shstrtab\0";
    bytes[0x200..0x200 + names.len()].copy_from_slice(names);

    let shoff = 0x300usize;

    // 节 0：SHT_NULL（全 0）
    // 节 1：.text —— 名字偏移 1，PROGBITS，ALLOC|EXECINSTR
    let s1 = shoff + 64;
    bytes[s1..s1 + 4].copy_from_slice(&1u32.to_le_bytes());
    bytes[s1 + 4..s1 + 8].copy_from_slice(&1u32.to_le_bytes()); // SHT_PROGBITS
    bytes[s1 + 8..s1 + 16].copy_from_slice(&0x6u64.to_le_bytes()); // ALLOC|EXEC
    bytes[s1 + 24..s1 + 32].copy_from_slice(&0x100u64.to_le_bytes()); // sh_offset
    bytes[s1 + 32..s1 + 40].copy_from_slice(&16u64.to_le_bytes()); // sh_size
    bytes[s1 + 48..s1 + 56].copy_from_slice(&16u64.to_le_bytes()); // sh_addralign

    // 节 2：.data —— 名字偏移 7，PROGBITS，ALLOC|WRITE
    let s2 = shoff + 128;
    bytes[s2..s2 + 4].copy_from_slice(&7u32.to_le_bytes());
    bytes[s2 + 4..s2 + 8].copy_from_slice(&1u32.to_le_bytes());
    bytes[s2 + 8..s2 + 16].copy_from_slice(&0x3u64.to_le_bytes()); // ALLOC|WRITE
    bytes[s2 + 24..s2 + 32].copy_from_slice(&0x120u64.to_le_bytes());
    bytes[s2 + 32..s2 + 40].copy_from_slice(&16u64.to_le_bytes());
    bytes[s2 + 48..s2 + 56].copy_from_slice(&16u64.to_le_bytes());

    // 节 2 的 sh_addr 需要是 0x402000 才能验证 vaddr 映射；这里补上。
    bytes[s1 + 16..s1 + 24].copy_from_slice(&0x401000u64.to_le_bytes());
    bytes[s2 + 16..s2 + 24].copy_from_slice(&0x402000u64.to_le_bytes());

    // 节 3：.shstrtab —— 名字偏移 13，SHT_STRTAB，指向放名字的那段
    let s3 = shoff + 192;
    bytes[s3..s3 + 4].copy_from_slice(&13u32.to_le_bytes());
    bytes[s3 + 4..s3 + 8].copy_from_slice(&3u32.to_le_bytes()); // SHT_STRTAB
    bytes[s3 + 24..s3 + 32].copy_from_slice(&0x200u64.to_le_bytes()); // sh_offset
    bytes[s3 + 32..s3 + 40].copy_from_slice(&(names.len() as u64).to_le_bytes());
    bytes[s3 + 48..s3 + 56].copy_from_slice(&1u64.to_le_bytes());

    bytes
}

#[tokio::test]
async fn static_assets_are_served_without_token_and_spa_falls_back() {
    // 根路径：无论 SPA 是否已构建都必须给出可渲染的 HTML
    let (status, content_type, body) = send_raw(test_state(None), get("/")).await;
    assert_eq!(status, StatusCode::OK);
    assert!(content_type.starts_with("text/html"), "{content_type}");
    assert!(!body.is_empty());

    // 前端路由回退：未知路径同样返回入口文档，而不是 404 JSON
    let (status, content_type, body) = send_raw(test_state(None), get("/browse/401000")).await;
    assert_eq!(status, StatusCode::OK);
    assert!(content_type.starts_with("text/html"), "{content_type}");
    assert!(body.contains("<html"), "回退页必须是 HTML");

    // 静态资源不需要令牌，但 API 仍然需要
    let (status, _) = send(test_state(None), get("/api/health")).await;
    assert_eq!(status, StatusCode::FORBIDDEN);
}

// ── 反汇编端点（M2） ────────────────────────────────────────────────────────

/// 构造一个带可执行节、能被真实解码的最小 ELF64。
///
/// 与 `build_elf_with_two_sections` 的区别：这个的 `.text` 里放的是
/// **真实可解码的 x86-64 机器码**（`nop` 与 `ret`），因此可以验证
/// "扫描 → 解码 → 渲染"整条链路，而不只是看节表。
fn build_elf_with_code() -> Vec<u8> {
    let names = b"\0.text\0.shstrtab\0";
    // 节表从 0x80 开始，3 个 64 字节的节头占到 0x140。
    // 代码与字符串表必须放在**节表之后** —— 曾把 text_off 定在 0x100，
    // 结果节头把代码覆盖成 [07,00,00,00]，测试才发现（这正是它该做的）。
    let text_off = 0x180usize;
    // nop; nop; nop; ret
    let code: [u8; 4] = [0x90, 0x90, 0x90, 0xC3];

    let mut bytes = vec![0u8; 0x220];
    // ── ELF64 头 ──
    bytes[0..4].copy_from_slice(b"\x7fELF");
    bytes[4] = 2; // ELFCLASS64
    bytes[5] = 1; // ELFDATA2LSB
    bytes[6] = 1; // EV_CURRENT
                  // e_type = ET_REL(1)：可重定位目标文件，正好覆盖"无程序头"这条路径
    bytes[16..18].copy_from_slice(&1u16.to_le_bytes());
    // e_machine = EM_X86_64(62)
    bytes[18..20].copy_from_slice(&62u16.to_le_bytes());
    bytes[20..24].copy_from_slice(&1u32.to_le_bytes()); // e_version

    let shoff = 0x80usize;
    let shnum = 3u16;
    let shstrndx = 2u16;
    bytes[40..48].copy_from_slice(&(shoff as u64).to_le_bytes());
    bytes[52..54].copy_from_slice(&64u16.to_le_bytes()); // e_ehsize
    bytes[58..60].copy_from_slice(&64u16.to_le_bytes()); // e_shentsize
    bytes[60..62].copy_from_slice(&shnum.to_le_bytes());
    bytes[62..64].copy_from_slice(&shstrndx.to_le_bytes());

    // ── 机器码 ──
    bytes[text_off..text_off + 4].copy_from_slice(&code);
    // ── 节名字符串表 ──
    let names_off = 0x1a0usize;
    bytes[names_off..names_off + names.len()].copy_from_slice(names);

    // 节 0：SHT_NULL（全零，保持不动）
    // 节 1：.text —— ALLOC|EXEC，size=4
    let s1 = shoff + 64;
    bytes[s1..s1 + 4].copy_from_slice(&1u32.to_le_bytes()); // sh_name -> ".text"
    bytes[s1 + 4..s1 + 8].copy_from_slice(&1u32.to_le_bytes()); // SHT_PROGBITS
    bytes[s1 + 8..s1 + 16].copy_from_slice(&0x6u64.to_le_bytes()); // ALLOC|EXEC
    bytes[s1 + 24..s1 + 32].copy_from_slice(&(text_off as u64).to_le_bytes());
    bytes[s1 + 32..s1 + 40].copy_from_slice(&4u64.to_le_bytes());
    bytes[s1 + 48..s1 + 56].copy_from_slice(&16u64.to_le_bytes());
    // 节 2：.shstrtab
    let s2 = shoff + 128;
    bytes[s2..s2 + 4].copy_from_slice(&7u32.to_le_bytes()); // sh_name -> ".shstrtab"
    bytes[s2 + 4..s2 + 8].copy_from_slice(&3u32.to_le_bytes()); // SHT_STRTAB
    bytes[s2 + 24..s2 + 32].copy_from_slice(&(names_off as u64).to_le_bytes());
    bytes[s2 + 32..s2 + 40].copy_from_slice(&(names.len() as u64).to_le_bytes());
    bytes[s2 + 48..s2 + 56].copy_from_slice(&1u64.to_le_bytes());

    bytes
}

fn write_temp(name: &str, data: &[u8]) -> std::path::PathBuf {
    use std::sync::atomic::{AtomicU64, Ordering};
    static COUNTER: AtomicU64 = AtomicU64::new(0);

    let mut path = std::env::temp_dir();
    // 进程 id + 单调计数：并行测试共享同一个进程，只用 pid 会互相覆盖
    // （这曾让三个测试同时读写同一个文件而随机失败）。
    path.push(format!(
        "bitflip-test-{}-{}-{name}",
        std::process::id(),
        COUNTER.fetch_add(1, Ordering::Relaxed)
    ));
    std::fs::write(&path, data).expect("写入临时目标");
    path
}

fn state_with_target(data: &[u8]) -> (AppState, std::path::PathBuf) {
    let path = write_temp("code.elf", data);
    let session = bitflip_core::Session::open(&path, bitflip_core::OpenOptions::default())
        .expect("打开临时目标");
    let state = AppState::new(TOKEN, None).with_session(std::sync::Arc::new(session));
    (state, path)
}

#[tokio::test]
async fn insns_endpoint_returns_decoded_instructions() {
    let (state, path) = state_with_target(&build_elf_with_code());
    let (status, body) = send(state, get_with_token("/api/insns?from=0&count=16")).await;
    let _ = std::fs::remove_file(&path);

    assert_eq!(status, StatusCode::OK, "响应: {body}");
    assert_eq!(body["format_version"], 1);
    assert_eq!(
        body["page"]["format_version"],
        bitflip_core::DISASM_FORMAT_VERSION
    );

    let instructions = body["page"]["instructions"]
        .as_array()
        .expect("instructions 应是数组");
    assert!(!instructions.is_empty(), "应当解出指令，完整响应: {body}");

    let first = &instructions[0];
    assert_eq!(first["address"].as_str().expect("address").len(), 16);
    assert_eq!(first["bytes"], "90");
    assert_eq!(first["text"], "nop");
    assert_eq!(first["flow"], "flow");

    // 统计必须存在，且能说明覆盖率而不是笼统的"完成"
    assert!(body["stats"]["indexed"].as_u64().expect("indexed") >= 4);
    assert!(body["stats"]["mapped_bytes"].as_u64().expect("mapped") >= 4);
}

#[tokio::test]
async fn insns_endpoint_clamps_oversized_count() {
    let (state, path) = state_with_target(&build_elf_with_code());
    let (status, body) = send(state, get_with_token("/api/insns?count=999999")).await;
    let _ = std::fs::remove_file(&path);

    assert_eq!(status, StatusCode::OK);
    assert_eq!(
        body["page"]["requested"].as_u64().expect("requested"),
        bitflip_core::MAX_PAGE_SIZE as u64,
        "服务端必须把过大的 count 收敛到上限，不信任客户端"
    );
}

#[tokio::test]
async fn insns_endpoint_rejects_garbage_address() {
    let (state, path) = state_with_target(&build_elf_with_code());
    let (status, body) = send(state, get_with_token("/api/insns?from=zzz")).await;
    let _ = std::fs::remove_file(&path);

    assert_eq!(
        status,
        StatusCode::BAD_REQUEST,
        "非法地址必须报错而不是悄悄从头开始: {body}"
    );
    let message = body["error"].as_str().unwrap_or_default();
    assert!(message.contains("地址无法解析"), "错误信息: {message}");
}

#[tokio::test]
async fn insns_endpoint_beyond_end_returns_empty_page() {
    let (state, path) = state_with_target(&build_elf_with_code());
    // 注意：可重定位目标文件的地址是**合成的**（基址 0x1_0000_0000），
    // 所以"超出末尾"要用远高于合成基址的地址。用一个低于基址的地址会
    // 反向吸附到第一条指令 —— 那是 containing() 的正确语义，不是 bug。
    let (status, body) = send(
        state,
        get_with_token("/api/insns?from=000000010000ffff&count=8"),
    )
    .await;
    let _ = std::fs::remove_file(&path);

    assert_eq!(status, StatusCode::OK);
    assert_eq!(body["page"]["returned"], 0);
    assert_eq!(body["page"]["next"], Value::Null);
    assert!(body["page"]["instructions"]
        .as_array()
        .expect("数组")
        .is_empty());
}

#[tokio::test]
async fn insns_endpoint_requires_token() {
    let (state, path) = state_with_target(&build_elf_with_code());
    let (status, _) = send(state, get("/api/insns")).await;
    let _ = std::fs::remove_file(&path);
    assert_eq!(status, StatusCode::FORBIDDEN);
}

#[tokio::test]
async fn insns_endpoint_reports_unavailable_target_clearly() {
    // 没有打开目标：必须明确说"没有目标"，而不是 500 或空页
    let (status, body) = send(test_state(None), get_with_token("/api/insns")).await;
    assert_eq!(status, StatusCode::BAD_REQUEST, "响应: {body}");
    assert!(
        body["error"]
            .as_str()
            .unwrap_or_default()
            .contains("没有打开目标"),
        "错误信息应说明原因: {body}"
    );
}

#[tokio::test]
async fn insns_scan_happens_once_and_is_cached() {
    // 同一个 state 连续请求两次：结果必须一致，且第二次不应重扫。
    // 这里能验证的是"结果一致 + 统计稳定"；真正的性能由 bench 覆盖。
    let (state, path) = state_with_target(&build_elf_with_code());

    let (_, first) = send(state.clone(), get_with_token("/api/insns?count=8")).await;
    let (_, second) = send(state, get_with_token("/api/insns?count=8")).await;
    let _ = std::fs::remove_file(&path);

    assert_eq!(
        first["page"]["instructions"], second["page"]["instructions"],
        "缓存后两次请求必须给出相同结果"
    );
    assert_eq!(first["stats"], second["stats"]);
}
