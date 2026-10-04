//! M5 服务层：归档成员端点。
//!
//! M5 验收标准 1 要求"成员选择与符号定位在 UI 与 CLI 里都能用"。
//! `archive_members.rs` 覆盖核心层，这里覆盖**服务层**与 CLI 那两条路径。
//!
//! fixture 是 `tests/fixtures/generated/libelf-multi.a`（三架构 GNU 归档），
//! 由 `scripts/gen-fixtures.ps1` 生成。缺 fixture 时硬失败 —— 一条会静默
//! 跳过的验收测试等于没有验收。

use std::path::PathBuf;

use axum::body::{to_bytes, Body};
use axum::http::{Request, StatusCode};
use bitflip_server::{router, AppState, TOKEN_HEADER};
use serde_json::Value;
use tower::ServiceExt;

const TOKEN: &str = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
const PORT: u16 = 8793;

/// 多架构 GNU 归档 fixture 的路径。
fn archive_fixture() -> PathBuf {
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("..")
        .join("..")
        .join("tests")
        .join("fixtures")
        .join("generated")
        .join("libelf-multi.a");
    assert!(
        path.exists(),
        "缺少 fixture {}。先跑 `pwsh -File scripts/gen-fixtures.ps1`。",
        path.display()
    );
    path
}

fn state_with_archive() -> AppState {
    let session =
        bitflip_core::Session::open(archive_fixture(), bitflip_core::OpenOptions::default())
            .expect("打开归档");
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

/// `/api/members` 必须列出全部成员，并标记哪些可分析。
///
/// `analyzable` 不是装饰性的：GNU 的符号索引成员 `/ (符号索引)` 确实在
/// 列表里，但它不是对象文件。前端靠这个字段决定"能不能点进去"。
/// 如果它恒为 true，用户点进去只会收到一个错误。
#[tokio::test]
async fn members_endpoint_lists_members_and_marks_analyzable_ones() {
    let (status, body) = send(state_with_archive(), get_with_token("/api/members")).await;

    assert_eq!(status, StatusCode::OK, "响应: {body}");
    assert_eq!(body["is_archive"], true, "应是归档：{body}");
    assert_eq!(body["container"], "ar", "容器应是 ar：{body}");

    let members = body["members"].as_array().expect("members");
    assert_eq!(members.len(), 4, "fixture 有 4 个成员：{body}");

    // 三个架构成员必须可分析
    let mut analyzable = Vec::new();
    let mut not_analyzable = Vec::new();
    for m in members {
        let name = m["name"].as_str().expect("name");
        // 每个成员都要有可用的偏移与大小（0 大小说明解析错了）
        let size = m["size"].as_u64().expect("size");
        assert!(size > 0, "成员 {name} 的大小不该是 0");
        m["offset"].as_u64().expect("offset");

        if m["analyzable"].as_bool().expect("analyzable") {
            analyzable.push(name.to_string());
        } else {
            not_analyzable.push(name.to_string());
        }
    }

    for expected in ["elf-x86_64.o", "elf-aarch64.o", "elf-i386.o"] {
        assert!(
            analyzable.contains(&expected.to_string()),
            "成员 {expected} 应可分析；实际可分析：{analyzable:?}"
        );
    }
    assert!(
        !not_analyzable.is_empty(),
        "符号索引成员 `/` 不该被标为可分析；实际全部可分析：{analyzable:?}"
    );
}

/// `/api/members` 对非归档目标：`is_archive=false` + 空成员列表。
///
/// 不能把这个情况做成错误：目标本身是好的，只是没有成员。
/// 也不返回 404 —— 那不是"请求失败"，是"答案是没有"。
#[tokio::test]
async fn members_endpoint_reports_non_archive_honestly() {
    // 用合成 ELF 起一个非归档会话
    let mut dir = std::env::temp_dir();
    dir.push(format!("bitflip-m5-members-{}", std::process::id()));
    std::fs::create_dir_all(&dir).expect("建临时目录");
    let path = dir.join("plain.elf");
    // 一个最小的 ELF 头就够了：我们只关心"不是归档"
    let mut bytes = vec![0u8; 0x40];
    bytes[0..4].copy_from_slice(b"\x7fELF");
    bytes[4] = 2;
    bytes[5] = 1;
    bytes[6] = 1;
    bytes[16..18].copy_from_slice(&2u16.to_le_bytes()); // ET_EXEC
    bytes[18..20].copy_from_slice(&62u16.to_le_bytes()); // x86_64
    std::fs::write(&path, &bytes).expect("写入目标");

    let session =
        bitflip_core::Session::open(&path, bitflip_core::OpenOptions::default()).expect("打开目标");
    let state = AppState::new(TOKEN, None)
        .with_session(std::sync::Arc::new(session))
        .with_allowed_origins(bitflip_server::default_allowed_origins(PORT, &[]));

    let (status, body) = send(state, get_with_token("/api/members")).await;
    let _ = std::fs::remove_dir_all(&dir);

    assert_eq!(status, StatusCode::OK, "响应: {body}");
    assert_eq!(
        body["is_archive"], false,
        "非归档目标应报 is_archive=false（而不是错误）：{body}"
    );
    assert!(
        body["members"].as_array().expect("members").is_empty(),
        "非归档目标没有成员：{body}"
    );
}

/// `/api/members/functions` 必须要求 `member` 参数。
#[tokio::test]
async fn member_functions_requires_member_parameter() {
    let (status, body) = send(
        state_with_archive(),
        get_with_token("/api/members/functions"),
    )
    .await;

    assert_eq!(status, StatusCode::BAD_REQUEST, "响应: {body}");
    let text = body["error"].as_str().unwrap_or_default();
    assert!(text.contains("member"), "错误信息应提到 member：{body}");
}

/// 每个架构成员的函数列表必须**各自独立**且正确。
///
/// 这条是 M5 验收标准的直接检查：三个成员名相同、机器码不同。
/// 断言地址布局确实不同，才能证明后端的成员切换真的生效了。
#[tokio::test]
async fn member_functions_are_scoped_to_the_requested_member() {
    let mut layouts = Vec::new();

    for member in ["elf-x86_64.o", "elf-aarch64.o", "elf-i386.o"] {
        let (status, body) = send(
            state_with_archive(),
            get_with_token(&format!("/api/members/functions?member={member}")),
        )
        .await;
        assert_eq!(status, StatusCode::OK, "member={member} 响应: {body}");
        assert_eq!(body["member"], member, "member 应原样回显：{body}");

        let functions = body["functions"].as_array().expect("functions");
        assert!(
            !functions.is_empty(),
            "成员 {member} 应有函数；响应：{body}"
        );

        // 每个函数都必须是定长十六进制地址 + 有名字
        let mut addrs = Vec::new();
        for f in functions {
            let start = f["start"].as_str().expect("start");
            assert_eq!(
                start.len(),
                16,
                "成员 {member} 里函数地址应是定长 16 位十六进制：{start}"
            );
            assert_eq!(f["named"], true, "fixture 里的函数都该有符号名：{f}");
            addrs.push(start.to_string());
        }
        addrs.sort();
        layouts.push((member.to_string(), addrs));
    }

    // 三个架构的布局不能完全相同 —— 那意味着成员切换没生效
    let distinct: std::collections::BTreeSet<_> = layouts.iter().map(|(_, a)| a.clone()).collect();
    assert!(
        distinct.len() > 1,
        "三个架构成员返回了完全相同的函数地址表（{layouts:?}）——\
         成员切换可能没有真正生效"
    );
}

/// 不存在的成员 → 400，且错误信息里带成员名。
#[tokio::test]
async fn member_functions_reports_unknown_member() {
    let (status, body) = send(
        state_with_archive(),
        get_with_token("/api/members/functions?member=nope.o"),
    )
    .await;

    assert_eq!(status, StatusCode::BAD_REQUEST, "响应: {body}");
    let text = body["error"].as_str().unwrap_or_default();
    assert!(text.contains("nope.o"), "错误信息应含查的名字：{body}");
}

/// 成员端点也要令牌：它能触发真实分析，不是纯元数据。
#[tokio::test]
async fn member_endpoints_require_token() {
    for path in ["/api/members", "/api/members/functions?member=elf-x86_64.o"] {
        let request = Request::builder()
            .uri(path)
            .body(Body::empty())
            .expect("构造请求");
        let (status, body) = send(state_with_archive(), request).await;
        assert_eq!(status, StatusCode::FORBIDDEN, "{path} 响应: {body}");
    }
}
