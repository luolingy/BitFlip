//! BitFlip 的本地服务层。
//!
//! 安全模型（本工具是**本地**分析器，不是网络服务）：
//!
//! 1. **只绑回环地址**。默认 `127.0.0.1`，不接受外部连接。
//! 2. **访问令牌**。启动时生成 32 字节随机令牌，请求必须带
//!    `X-BitFlip-Token` 头或 `?token=` 查询参数，否则 403。
//! 3. **Origin 校验**。带了 `Origin` 头但不在白名单里的一律拒绝 —— 这条挡住的是
//!    "用户在自己浏览器里打开了一个恶意页面，该页面偷偷请求本机的 BitFlip API"。
//!
//! 令牌与 Origin 是**同时**生效的两道门，不是二选一。

mod assets;

use std::future::Future;
use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use std::time::{Duration, Instant};

use axum::extract::{Request, State};
use axum::http::{header, StatusCode};
use axum::middleware::{self, Next};
use axum::response::{IntoResponse, Response};
use axum::routing::get;
use axum::{Json, Router};
use bitflip_core::TargetInfo;
use serde::Serialize;
use thiserror::Error;
use tokio::net::TcpListener;

pub use assets::{asset_count, ui_embedded};

/// 访问令牌的请求头名（小写，HTTP 头不区分大小写）。
pub const TOKEN_HEADER: &str = "x-bitflip-token";

/// 令牌的查询参数名（供 `EventSource`/WebSocket/首屏 URL 使用）。
pub const TOKEN_QUERY: &str = "token";

/// 服务层 API 版本（wire 契约）。
pub const SERVER_API_VERSION: u32 = 1;

/// 程序名。
pub const APP_NAME: &str = "bitflip";

/// 程序中文名。
pub const APP_NAME_ZH: &str = "比特翻转";

/// 服务运行期状态。
#[derive(Clone)]
pub struct AppState {
    token: Arc<str>,
    allowed_origins: Arc<[String]>,
    target: Option<Arc<TargetInfo>>,
    /// 目标的完整解析结果。
    ///
    /// 与 `target` 分开：`target` 是无条件的嗅探结论，`parsed` 可能因为
    /// 文件畸形而不存在。UI 需要在"识别出来了但解析失败"时仍然能显示
    /// 识别结论与失败原因，而不是一片空白（CLAUDE.md §7）。
    parsed: Option<Arc<bitflip_core::ObjectInfo>>,
    started: Instant,
}

impl AppState {
    /// 创建状态。`target` 是本次会话打开的目标（无目标时为 `None`）。
    #[must_use]
    pub fn new(token: impl Into<Arc<str>>, target: Option<TargetInfo>) -> Self {
        Self {
            token: token.into(),
            allowed_origins: Arc::from(Vec::new()),
            target: target.map(Arc::new),
            parsed: None,
            started: Instant::now(),
        }
    }

    /// 附带解析结果。
    #[must_use]
    pub fn with_parsed(mut self, parsed: Option<bitflip_core::ObjectInfo>) -> Self {
        self.parsed = parsed.map(Arc::new);
        self
    }

    /// 追加允许的 `Origin` 白名单。
    #[must_use]
    pub fn with_allowed_origins(mut self, origins: impl IntoIterator<Item = String>) -> Self {
        self.allowed_origins = origins.into_iter().collect::<Vec<_>>().into();
        self
    }

    /// 访问令牌。
    #[must_use]
    pub fn token(&self) -> &str {
        &self.token
    }

    /// 本次会话的目标识别结论。
    #[must_use]
    pub fn target(&self) -> Option<&TargetInfo> {
        self.target.as_deref()
    }

    /// 本次会话的解析结果（可能因文件畸形而不存在）。
    #[must_use]
    pub fn parsed(&self) -> Option<&bitflip_core::ObjectInfo> {
        self.parsed.as_deref()
    }

    /// 已运行时长。
    #[must_use]
    pub fn uptime(&self) -> Duration {
        self.started.elapsed()
    }
}

/// 生成访问令牌：32 字节随机数的十六进制表示（64 字符）。
#[must_use]
pub fn generate_token() -> String {
    use rand::RngCore;

    let mut bytes = [0u8; 32];
    rand::thread_rng().fill_bytes(&mut bytes);
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

/// 本机默认允许的 `Origin` 白名单。
///
/// `localhost` 与 `127.0.0.1` 都要列上：两者在浏览器里是不同的源，
/// 而 Vite 开发服务器默认绑定前者。
#[must_use]
pub fn default_allowed_origins(port: u16, extra: &[String]) -> Vec<String> {
    let mut origins = vec![
        format!("http://127.0.0.1:{port}"),
        format!("http://localhost:{port}"),
        format!("http://[::1]:{port}"),
    ];
    origins.extend(extra.iter().cloned());
    origins
}

// ── 路由 ────────────────────────────────────────────────────────────────────

/// 构造完整的 axum 路由。
pub fn router(state: AppState) -> Router {
    let api = Router::new()
        .route("/api/health", get(health))
        .route("/api/target", get(target))
        .route("/api/sections", get(sections))
        .route_layer(middleware::from_fn_with_state(state.clone(), require_token));

    Router::new()
        .merge(api)
        // 其余路径交给内嵌 SPA（含前端路由回退）。
        .fallback(assets::static_handler)
        .with_state(state)
}

#[derive(Serialize)]
struct HealthResponse {
    ok: bool,
    name: &'static str,
    name_zh: &'static str,
    version: &'static str,
    server_api_version: u32,
    core_api_version: u32,
    uptime_ms: u64,
    /// 前端资源是否已构建并内嵌（未构建时返回占位页）。
    ui_embedded: bool,
    /// 本次会话目标（无目标为 `null`）。
    target: Option<TargetInfo>,
}

async fn health(State(state): State<AppState>) -> Json<HealthResponse> {
    Json(HealthResponse {
        ok: true,
        name: APP_NAME,
        name_zh: APP_NAME_ZH,
        version: bitflip_core::version(),
        server_api_version: SERVER_API_VERSION,
        core_api_version: bitflip_core::CORE_API_VERSION,
        uptime_ms: state.uptime().as_millis() as u64,
        ui_embedded: assets::ui_embedded(),
        target: state.target().cloned(),
    })
}

async fn target(State(state): State<AppState>) -> Response {
    match state.target() {
        Some(info) => Json(info.clone()).into_response(),
        None => error_response(StatusCode::NOT_FOUND, "本次会话没有打开目标"),
    }
}

/// 段/节视图响应。
#[derive(Serialize)]
struct SectionsResponse {
    /// wire 版本号（与 `TargetInfo::format_version` 同源）。
    format_version: u32,
    /// 目标识别结论（总是存在）。
    target: TargetInfo,
    /// 完整解析结果；`null` 表示解析失败，原因在 `target.notes` 里。
    parsed: Option<bitflip_core::ObjectInfo>,
}

/// 段/节视图：一次返回识别结论 + 解析结果。
///
/// 合并成一个请求而不是两个，是为了让 UI 的"结构"页只有一次往返 ——
/// 两部分数据必须同时呈现才有意义（只显示节表而没有格式/架构不完整）。
async fn sections(State(state): State<AppState>) -> Response {
    let Some(info) = state.target() else {
        return error_response(StatusCode::NOT_FOUND, "本次会话没有打开目标");
    };

    Json(SectionsResponse {
        format_version: info.format_version,
        target: info.clone(),
        parsed: state.parsed().cloned(),
    })
    .into_response()
}

// ── 鉴权 ────────────────────────────────────────────────────────────────────

/// 令牌 + Origin 双重校验中间件。
async fn require_token(State(state): State<AppState>, request: Request, next: Next) -> Response {
    if let Some(origin) = request.headers().get(header::ORIGIN) {
        let origin = origin.to_str().unwrap_or_default();
        if !state
            .allowed_origins
            .iter()
            .any(|allowed| allowed == origin)
        {
            tracing::warn!(origin, "拒绝跨站请求");
            return error_response(
                StatusCode::FORBIDDEN,
                &format!("跨站请求被拒绝（Origin: {origin}）"),
            );
        }
    }

    match request_token(&request) {
        Some(token) if token.as_str() == &*state.token => next.run(request).await,
        Some(_) => {
            tracing::warn!("访问令牌不正确");
            error_response(StatusCode::FORBIDDEN, "访问令牌不正确")
        }
        None => error_response(
            StatusCode::FORBIDDEN,
            "缺少访问令牌：请用带 `?token=` 的 URL，或设置 X-BitFlip-Token 头",
        ),
    }
}

/// 从请求头或查询串里取令牌。
fn request_token(request: &Request) -> Option<String> {
    if let Some(value) = request.headers().get(TOKEN_HEADER) {
        return value.to_str().ok().map(str::to_string);
    }
    let query = request.uri().query()?;
    for pair in query.split('&') {
        if let Some((key, value)) = pair.split_once('=') {
            if key == TOKEN_QUERY && !value.is_empty() {
                return Some(value.to_string());
            }
        }
    }
    None
}

fn error_response(status: StatusCode, message: &str) -> Response {
    (
        status,
        Json(serde_json::json!({
            "error": message,
            "status": status.as_u16(),
        })),
    )
        .into_response()
}

// ── 绑定与运行 ──────────────────────────────────────────────────────────────

/// 绑定失败。
#[derive(Debug, Error)]
pub enum ServerError {
    /// 所有候选端口都绑定失败。
    #[error("端口绑定失败：从 {start} 起尝试了 {attempts} 个端口，最后一次错误：{source}")]
    Bind {
        /// 起始端口。
        start: u16,
        /// 尝试次数。
        attempts: u16,
        /// 最后一次错误。
        #[source]
        source: std::io::Error,
    },
    /// 服务运行期错误。
    #[error("服务运行失败: {0}")]
    Serve(#[source] std::io::Error),
}

/// 已绑定的监听器。
pub struct BoundListener {
    /// 监听器。
    pub listener: TcpListener,
    /// 实际地址（端口回退后的真实端口）。
    pub addr: SocketAddr,
}

/// 绑定回环地址，端口被占用时顺延。
///
/// `port == 0` 表示让操作系统分配临时端口（只尝试一次）。
pub async fn bind(host: IpAddr, port: u16, attempts: u16) -> Result<BoundListener, ServerError> {
    let attempts = if port == 0 { 1 } else { attempts.max(1) };
    let mut last_error = None;

    for offset in 0..attempts {
        let candidate = port.saturating_add(offset);
        let addr = SocketAddr::new(host, candidate);
        match TcpListener::bind(addr).await {
            Ok(listener) => {
                let addr = listener.local_addr().unwrap_or(addr);
                return Ok(BoundListener { listener, addr });
            }
            Err(error) => {
                tracing::debug!(port = candidate, %error, "端口被占用，尝试下一个");
                last_error = Some(error);
            }
        }
    }

    Err(ServerError::Bind {
        start: port,
        attempts,
        source: last_error.unwrap_or_else(|| {
            std::io::Error::new(std::io::ErrorKind::AddrNotAvailable, "没有可用端口")
        }),
    })
}

/// 运行服务，直到 `shutdown` 完成。
pub async fn serve<F>(
    listener: TcpListener,
    state: AppState,
    shutdown: F,
) -> Result<(), ServerError>
where
    F: Future<Output = ()> + Send + 'static,
{
    let app = router(state);
    axum::serve(listener, app)
        .with_graceful_shutdown(shutdown)
        .await
        .map_err(ServerError::Serve)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tokens_are_unique_and_hex() {
        let a = generate_token();
        let b = generate_token();
        assert_eq!(a.len(), 64);
        assert_ne!(a, b);
        assert!(a.chars().all(|c| c.is_ascii_hexdigit()));
    }

    #[test]
    fn default_origins_cover_localhost_spellings() {
        let extra = vec!["http://127.0.0.1:5173".to_string()];
        let origins = default_allowed_origins(8790, &extra);
        assert!(origins.contains(&"http://127.0.0.1:8790".to_string()));
        assert!(origins.contains(&"http://localhost:8790".to_string()));
        assert!(origins.contains(&"http://127.0.0.1:5173".to_string()));
        assert_eq!(origins.len(), 4);
    }

    #[test]
    fn state_exposes_target_and_uptime() {
        let state = AppState::new("tok", None);
        assert!(state.target().is_none());
        assert_eq!(state.token(), "tok");
        assert!(state.uptime().as_secs() < 60);
    }
}
