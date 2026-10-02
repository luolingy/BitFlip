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
    let mut bytes = vec![0u8; 0x200];
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
