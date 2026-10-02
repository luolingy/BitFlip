//! 内嵌的 SPA 资源与静态资源处理。
//!
//! 前端产物通过 `rust-embed` 编进二进制，因此分发物是**单文件、运行期零依赖**
//! （见 `docs/DECISIONS.md` ADR-0001）。
//!
//! 仓库里保留了 `web/dist/.gitkeep` 以便新克隆也能编译（资源目录必须存在）；
//! 真正的 `index.html` 缺失时，返回一份能指导操作的占位页，而不是 404 或空白 ——
//! 这比"服务起来了但页面空白"更容易排查。

use axum::body::Body;
use axum::http::{header, HeaderValue, StatusCode, Uri};
use axum::response::{IntoResponse, Response};
use rust_embed::RustEmbed;

// 路径相对于本 crate 的 CARGO_MANIFEST_DIR（rust-embed 的解析规则）。
// 目录不存在会直接编译失败，因此仓库里保留了 web/dist/.gitkeep。
#[derive(RustEmbed)]
#[folder = "../../web/dist/"]
struct Assets;

const FALLBACK_HTML: &str = include_str!("fallback.html");

/// 内嵌资源里是否有真正的 SPA 入口（供 `/api/health` 如实汇报）。
#[must_use]
pub fn ui_embedded() -> bool {
    Assets::get("index.html").is_some()
}

/// 已内嵌资源数（测试与诊断用）。
#[must_use]
pub fn asset_count() -> usize {
    Assets::iter().count()
}

/// 静态资源处理器：命中就用内嵌资源，否则回退到 SPA 入口（前端路由需要）。
pub async fn static_handler(uri: Uri) -> Response {
    let path = uri.path().trim_start_matches('/');
    let path = if path.is_empty() { "index.html" } else { path };

    if let Some(content) = Assets::get(path) {
        return serve_bytes(path, content.data.into_owned());
    }

    if let Some(index) = Assets::get("index.html") {
        // 前端路由（例如 /browse）由 SPA 自己处理，服务端统一返回入口页。
        return serve_bytes("index.html", index.data.into_owned());
    }

    (
        StatusCode::OK,
        [(header::CONTENT_TYPE, "text/html; charset=utf-8")],
        FALLBACK_HTML,
    )
        .into_response()
}

fn serve_bytes(path: &str, bytes: Vec<u8>) -> Response {
    let content_type = content_type_for(path);
    let mut response = Response::new(Body::from(bytes));
    response.headers_mut().insert(
        header::CONTENT_TYPE,
        HeaderValue::from_str(&content_type)
            .unwrap_or_else(|_| HeaderValue::from_static("application/octet-stream")),
    );
    response
}

/// 文本类资源统一带上 `charset=utf-8`（SPA 是 UTF-8 源码，中文界面依赖它）。
fn content_type_for(path: &str) -> String {
    let mime = mime_guess::from_path(path).first_or_octet_stream();
    let essence = mime.essence_str();
    let needs_charset = essence.starts_with("text/")
        || essence == "application/javascript"
        || essence == "application/json"
        || essence == "application/manifest+json"
        || essence == "image/svg+xml";
    if needs_charset {
        format!("{essence}; charset=utf-8")
    } else {
        essence.to_string()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn content_types_are_explicit_for_text_assets() {
        assert_eq!(content_type_for("index.html"), "text/html; charset=utf-8");
        assert_eq!(
            content_type_for("assets/app.css"),
            "text/css; charset=utf-8"
        );
        // .js 的 MIME 在 mime_guess 版本间有过 text/javascript → application/javascript 的漂移，
        // 因此只断言"是 JS 且带 charset"，避免锁死上游选择。
        let js = content_type_for("assets/app.js");
        assert!(js.contains("javascript"), "{js}");
        assert!(js.ends_with("charset=utf-8"), "{js}");
        assert_eq!(content_type_for("logo.png"), "image/png");
        assert_eq!(
            content_type_for("x.unknown-ext"),
            "application/octet-stream"
        );
    }
}
