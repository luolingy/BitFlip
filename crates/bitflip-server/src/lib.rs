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
    /// 本次会话打开的目标（反汇编需要它）。
    ///
    /// 保留整个 `Session` 而不是只保留 `ObjectInfo`：反汇编需要在原始字节上
    /// 建地址空间，而 `ObjectInfo` 是已经"拍扁"成 wire 类型的投影，
    /// 丢了段/节与文件偏移的对应关系。
    session: Option<Arc<bitflip_core::Session>>,
    /// 反汇编结果（惰性建立并缓存的）。
    ///
    /// ## 为什么要缓存，而不是每个请求重扫
    ///
    /// 一次扫描要建立地址空间、跑线性 + 递归下降解码。对 100MB 目标，
    /// 这是秒级到十几秒的工作量。UI 每滚动一屏就发一个请求，
    /// 如果不缓存，滚动会退化成"每次重扫 100MB" —— 这是参照实现里
    /// "同步阻塞分析"那类设计的具体后果。
    ///
    /// ## 为什么用 `OnceLock` 而不是 `Mutex<Option<..>>`
    ///
    /// 我们要的是"只算一次"而不是"互斥更新"。`OnceLock` 让并发的
    /// 首个请求里只有一个真正去扫，其余阻塞等待同一份结果 ——
    /// 而 `Mutex<Option>` 会退化成"每个请求都重算一遍并互相覆盖"。
    ///
    /// 惰性而不是在 `serve` 时预先算：用户可能只想看段表，
    /// 不该为此付出一次 100MB 扫描的代价。
    disasm: Arc<std::sync::OnceLock<Result<Arc<bitflip_core::Disasm>, String>>>,
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
            session: None,
            disasm: Arc::new(std::sync::OnceLock::new()),
            started: Instant::now(),
        }
    }

    /// 附带整个会话（同时带上识别结论与解析结果）。
    ///
    /// 这是 `serve` 的推荐用法：一次给全，避免状态之间不一致
    /// （比如 `target` 有而 `parsed` 没有，但实际会话是解析成功的）。
    #[must_use]
    pub fn with_session(mut self, session: Arc<bitflip_core::Session>) -> Self {
        self.target = Some(Arc::new(session.info().clone()));
        self.parsed = session.parsed().cloned().map(Arc::new);
        self.session = Some(session);
        self
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

    /// 归档成员列表（M5）；非归档时为空。
    ///
    /// # Errors
    ///
    /// 本次会话没有打开目标。
    pub fn members(&self) -> Result<Vec<bitflip_core::ArchiveMember>, String> {
        let Some(session) = self.session.as_ref() else {
            return Err("本次会话没有打开目标".to_string());
        };
        Ok(session.members().to_vec())
    }

    /// 目标的识别结论（容器类别、是否归档等）。
    ///
    /// # Errors
    ///
    /// 本次会话没有打开目标。
    pub fn target_info(&self) -> Result<bitflip_core::TargetInfo, String> {
        let Some(session) = self.session.as_ref() else {
            return Err("本次会话没有打开目标".to_string());
        };
        Ok(session.info().clone())
    }

    /// 取一个归档成员的会话（M5）。
    ///
    /// 成员分析**不走缓存**，每次请求都重新打开成员。这是刻意的取舍：
    /// 缓存要按成员名分桶，而用户一次只看一个成员，省下的那点时间
    /// 换不来"缓存可能过期/串味"的风险。代价是切成员时有几十毫秒的停顿。
    ///
    /// # Errors
    ///
    /// 目标不是归档、成员不存在、成员不是可分析对象。
    pub fn member_session(&self, name: &str) -> Result<bitflip_core::Session, String> {
        let Some(session) = self.session.as_ref() else {
            return Err("本次会话没有打开目标".to_string());
        };
        session
            .member_session(name)
            .map(|(member, _)| member)
            .map_err(|error| error.to_string())
    }

    /// 已运行时长。
    #[must_use]
    pub fn uptime(&self) -> Duration {
        self.started.elapsed()
    }

    /// 取反汇编（惰性建立，只成功建立一次）。
    ///
    /// 返回 `Arc` 以便跨请求共享，避免每次响应都克隆整个指令索引。
    ///
    /// 失败会被缓存 —— 一个"没有可执行段"的目标不会因为用户多刷新几次
    /// 就变得可以反汇编，重试只是浪费 CPU。
    ///
    /// # Errors
    ///
    /// 返回该目标无法反汇编的原因（未解析成功 / 没有可执行区域）。
    pub fn disasm(&self) -> Result<Arc<bitflip_core::Disasm>, String> {
        // 先取已算好的结果（快速路径，不持锁）
        if let Some(ready) = self.disasm.get() {
            return match ready {
                Ok(disasm) => Ok(Arc::clone(disasm)),
                Err(reason) => Err(reason.clone()),
            };
        }

        // 没有会话就没有目标：这是"sections 也没得看"的情形
        let Some(session) = self.session.as_ref() else {
            return Err("本次会话没有打开目标".to_string());
        };

        // get_or_init 保证并发首请求里只有一个真正执行扫描
        let result = self.disasm.get_or_init(|| {
            match session.disassemble(bitflip_core::DisasmScanOptions::default()) {
                Ok(disasm) => Ok(Arc::new(disasm)),
                Err(error) => Err(error.to_string()),
            }
        });

        match result {
            Ok(disasm) => Ok(Arc::clone(disasm)),
            Err(reason) => Err(reason.clone()),
        }
    }

    /// 取目标级分析（函数 / 交叉引用 / 字符串），惰性建立并缓存。
    ///
    /// 与 [`AppState::disasm`] 同样的理由：一次分析要建地址空间、做两遍解码、
    /// 合并函数候选、扫字符串。UI 每个请求都重算等于把滚动变成重扫。
    ///
    /// # Errors
    ///
    /// 返回该目标无法分析的原因（未解析成功 / 没有可分析内容）。
    pub fn analysis(&self) -> Result<Arc<bitflip_core::TargetAnalysis>, String> {
        let Some(session) = self.session.as_ref() else {
            return Err("本次会话没有打开目标".to_string());
        };
        session
            .analysis(&session.detached_job())
            .map_err(|error| error.to_string())
    }

    /// 分析摘要（计数汇总）。
    ///
    /// 与 [`AppState::analysis`] 共用缓存：`Session` 内部把 `TargetAnalysis`
    /// 放在 `OnceLock` 里，所以这里再取一次不会重算。
    ///
    /// # Errors
    ///
    /// 返回该目标无法分析的原因。
    pub fn summary(&self) -> Result<bitflip_core::AnalysisSummary, String> {
        let Some(session) = self.session.as_ref() else {
            return Err("本次会话没有打开目标".to_string());
        };
        session
            .analyze(&session.detached_job())
            .map_err(|error| error.to_string())
    }

    /// 打开（或创建）本次会话的工程库，用于读写标注。
    ///
    /// 工作区取目标文件所在目录下的 `.bitflip`。这样"打开一个 exe"
    /// 就自动在它旁边建立工程，不需要用户先选一个工作区 —— 本地工具
    /// 不该为一件显而易见的事要求配置。
    ///
    /// # Errors
    ///
    /// 目标未解析成功、或工程库读写失败。
    pub fn project(&self) -> Result<bitflip_core::ProjectStore, String> {
        let Some(session) = self.session.as_ref() else {
            return Err("本次会话没有打开目标".to_string());
        };
        let workspace = session
            .path()
            .parent()
            .map(|p| p.join(".bitflip"))
            .ok_or_else(|| "目标路径没有父目录，无法定位工程工作区".to_string())?;
        session
            .open_project(&workspace)
            .map_err(|error| error.to_string())
    }

    /// 按虚拟地址读原始字节（十六进制视图用）。
    ///
    /// 读不到就返回**实际读到的部分**，由调用方如实报告长度 ——
    /// 不用零填充冒充文件内容（CLAUDE.md §7）。
    ///
    /// # Errors
    ///
    /// 目标未解析成功。
    pub fn read_bytes(&self, address: u64, length: usize) -> Result<Vec<u8>, String> {
        let Some(session) = self.session.as_ref() else {
            return Err("本次会话没有打开目标".to_string());
        };
        session
            .read_virtual(address, length)
            .map_err(|error| error.to_string())
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
        .route("/api/insns", get(insns))
        // ── M3：目标级分析 ──
        // 各自独立成一个端点，而不是塞进 `/api/target` 一次返回全部：
        // 函数/xref/字符串三张表在 100MB 目标上都可能上万条，
        // 合并返回会让"只想看字符串"的请求也付出序列化函数表的代价。
        .route("/api/functions", get(functions))
        .route("/api/analyze", get(analyze))
        .route("/api/jump-tables", get(jump_tables))
        .route("/api/code-map", get(code_map))
        .route("/api/cfg", get(cfg))
        .route("/api/members", get(members))
        .route("/api/members/functions", get(member_functions))
        .route("/api/xrefs", get(xrefs))
        .route("/api/strings", get(strings))
        .route("/api/hex", get(hex))
        // 标注是**主数据**，可读可写可删；写路径不触发重新分析。
        .route(
            "/api/annotations",
            get(annotations)
                .put(put_annotation)
                .delete(delete_annotation),
        )
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

/// 反汇编分页响应。
#[derive(Serialize)]
struct InsnsResponse {
    /// wire 格式版本。
    format_version: u32,
    /// 本页内容。
    page: bitflip_core::InsnPage,
    /// 扫描统计（UI 用来说明覆盖率，而不是笼统的"分析完成"）。
    stats: bitflip_core::DisasmStats,
    /// 本目标的降级说明（合成地址、截断、无法解码的字节数…）。
    ///
    /// 单列一个字段而不是塞进 `target.notes`：这些是**分析期**产生的说明，
    /// 而 `target.notes` 是解析期的。混在一起会让用户分不清
    /// "文件有问题"和"分析有取舍"。
    notes: Vec<String>,
}

/// 查询参数：反汇编分页。
#[derive(serde::Deserialize)]
struct InsnsQuery {
    /// 起始地址。接受 `0x` 前缀或裸十六进制；省略则从地址空间开头开始。
    from: Option<String>,
    /// 请求条数；服务端会 clamp 到 `MAX_PAGE_SIZE`。
    count: Option<usize>,
}

/// 反汇编分页：`GET /api/insns?from=<hex>&count=<n>`。
///
/// 列式分页而不是一次返回全部：100 万条指令序列化成 JSON 是几百 MB，
/// 浏览器和内存都撑不住。服务端只渲染请求的那一页。
async fn insns(
    State(state): State<AppState>,
    axum::extract::Query(query): axum::extract::Query<InsnsQuery>,
) -> Response {
    let disasm = match state.disasm() {
        Ok(disasm) => disasm,
        Err(reason) => {
            // 400 而不是 404：目标是存在的，只是它没有可反汇编的内容。
            // 404 会让客户端以为"目标不存在"而去重新打开文件。
            return error_response(StatusCode::BAD_REQUEST, &reason);
        }
    };

    // 地址解析失败要明确报错，而不是悄悄从头开始 ——
    // 那会让用户以为自己跳转成功了，其实只是回到了开头。
    let from = match query.from.as_deref() {
        None | Some("") => 0,
        Some(text) => match bitflip_core::parse_address(text) {
            Some(addr) => addr,
            None => {
                return error_response(
                    StatusCode::BAD_REQUEST,
                    &format!("地址无法解析：{text:?}（需要 16 进制，可带 0x 前缀）"),
                );
            }
        },
    };

    let count = query.count.unwrap_or(bitflip_core::DEFAULT_PAGE_SIZE);

    Json(InsnsResponse {
        format_version: bitflip_core::DISASM_FORMAT_VERSION,
        page: disasm.page(from, count),
        stats: disasm.wire_stats(),
        notes: disasm.notes.clone(),
    })
    .into_response()
}

// ── M3：目标级分析（函数 / 交叉引用 / 字符串）与标注 ───────────────────────

/// 归档成员列表响应：`GET /api/members`。
#[derive(Serialize)]
struct MembersResponse {
    /// wire 格式版本。
    format_version: u32,
    /// 目标是不是归档。
    ///
    /// 显式给出而不是靠"成员数组为空"判断：**"不是归档"与"归档没有成员"
    /// 是两件事**，前端要据此显示不同的界面文案。
    is_archive: bool,
    /// 容器类别（`ar` / `msvc-lib` / 其他）。
    container: String,
    /// 成员列表是否被截断（嗅探窗口或上限）。
    truncated: bool,
    /// 成员。
    members: Vec<MemberWire>,
    /// 识别/解析期的说明。
    notes: Vec<String>,
}

/// 单个归档成员的 wire 表示。
#[derive(Serialize)]
struct MemberWire {
    /// 成员名（已尽量解析长名表）。
    name: String,
    /// 成员数据在容器里的文件偏移。
    offset: u64,
    /// 成员数据长度。
    size: u64,
    /// 成员数据是否超出嗅探窗口。
    truncated: bool,
    /// 成员是否**可以**被当作独立对象分析。
    ///
    /// 这是给前端的提示：`/ (符号索引)` 这类元数据成员在列表里看得见，
    /// 但点进去分析只会得到"不是可分析对象"。先在这里说清楚，
    /// 比让用户点了再吃一个错误好。
    analyzable: bool,
}

/// 归档成员列表：`GET /api/members`。
///
/// `analyzable` 的判定方式与 `Session::member_session` 完全一致：
/// **真的去建一次成员会话**。看起来有点重，但这是唯一诚实的做法 ——
/// 靠名字猜（"以 `/` 开头的就是元数据"）会在别的归档格式上出错，
/// 而这里的代价只是对每个成员做一次头部嗅探。
async fn members(State(state): State<AppState>) -> Response {
    let info = match state.target_info() {
        Ok(i) => i,
        Err(reason) => return error_response(StatusCode::BAD_REQUEST, &reason),
    };
    let all = match state.members() {
        Ok(m) => m,
        Err(reason) => return error_response(StatusCode::BAD_REQUEST, &reason),
    };

    let members: Vec<MemberWire> = all
        .iter()
        .map(|m| MemberWire {
            name: m.name.clone(),
            offset: m.offset,
            size: m.size,
            truncated: m.truncated,
            analyzable: state.member_session(&m.name).is_ok(),
        })
        .collect();

    Json(MembersResponse {
        format_version: info.format_version,
        is_archive: info.is_archive(),
        container: info.container.clone(),
        truncated: info.members_truncated,
        members,
        notes: info.notes.clone(),
    })
    .into_response()
}

/// 函数列表响应。
#[derive(Serialize)]
struct FunctionsResponse {
    /// wire 格式版本。
    format_version: u32,
    /// 总数（分页前）。
    total: usize,
    /// 本页函数。
    functions: Vec<bitflip_core::FunctionWire>,
    /// 分析期的降级说明。
    notes: Vec<String>,
}

/// 分析摘要响应：`GET /api/analyze`。
///
/// 这个端点存在的理由是**让"基本块数"这类汇总值有个真实的出口**。
/// M3/M4 期间 `AnalysisSummary::basic_blocks` 一直诚实地返回 0
/// （CFG 尚未实现），但没有任何接口能把它读出来 —— 于是"诚实的 0"
/// 和"没接上"在外部看起来一模一样。M5 让它是真值，并在此暴露。
#[derive(Serialize)]
struct AnalyzeResponse {
    /// wire 格式版本。
    format_version: u32,
    /// 已索引的指令数。
    instructions: usize,
    /// 识别出的函数数。
    functions: usize,
    /// 基本块总数（全部函数之和）。
    basic_blocks: usize,
    /// 交叉引用数。
    xrefs: usize,
    /// 有 CFG 的函数数。
    functions_with_cfg: usize,
    /// 识别出的跳转表数量（`switch` 分支）。
    ///
    /// 单独暴露的理由：验证过的规则是"间接跳转要么解析成表，要么在
    /// notes 里说明为什么没有"。没有这个计数时，用户只能从 CFG 里
    /// "某个块没有后继"去**推测**表没识别出来 —— 而那条 CFG 看起来
    /// 和"这个函数真的不返回"完全一样。
    jump_tables: usize,
    /// 跳转表覆盖的目标地址总数（已回填进 CFG 的后继边）。
    jump_table_targets: usize,
    /// 数据/代码判定的抽样统计。明细见 `/api/code-map`。
    code_map: bitflip_core::CodeMapStats,
    /// 分析期的降级说明。
    notes: Vec<String>,
}

/// 分析摘要：`GET /api/analyze`。
async fn analyze(State(state): State<AppState>) -> Response {
    let summary = match state.summary() {
        Ok(s) => s,
        Err(reason) => return error_response(StatusCode::BAD_REQUEST, &reason),
    };
    let analysis = match state.analysis() {
        Ok(a) => a,
        Err(reason) => return error_response(StatusCode::BAD_REQUEST, &reason),
    };

    Json(AnalyzeResponse {
        format_version: bitflip_core::ANALYSIS_FORMAT_VERSION,
        instructions: summary.instructions,
        functions: summary.functions,
        basic_blocks: summary.basic_blocks,
        xrefs: summary.xrefs,
        functions_with_cfg: analysis.cfg_count(),
        jump_tables: analysis.jump_tables().tables.len(),
        jump_table_targets: analysis.jump_tables().all_targets().len(),
        code_map: analysis.code_map().stats,
        notes: analysis.notes().to_vec(),
    })
    .into_response()
}

/// 跳转表列表响应：`GET /api/jump-tables`。
#[derive(Serialize)]
struct JumpTablesResponse {
    /// wire 格式版本。
    format_version: u32,
    /// 识别出的跳转表。
    tables: Vec<JumpTableWire>,
    /// 降级说明（未解析的间接跳转等）。
    notes: Vec<String>,
}

/// 一张跳转表的 wire 形式。
#[derive(Serialize)]
struct JumpTableWire {
    /// 间接跳转指令的地址（定长十六进制）。
    insn_addr: String,
    /// 表基址（定长十六进制）。
    base: String,
    /// 表项宽度：`u8` / `u16` / `u32` / `u64`。
    width: &'static str,
    /// 表项语义：`absolute` / `base-relative` / `insn-relative`。
    kind: &'static str,
    /// 表项语义的中文说明。
    kind_zh: &'static str,
    /// 表项数。
    count: usize,
    /// 目标地址（定长十六进制）。
    targets: Vec<String>,
}

/// 跳转表列表：`GET /api/jump-tables`。
///
/// 与 `/api/analyze` 的计数分开暴露的理由：用户需要看到**每张表**
/// 的基址、宽度与语义，才能判断识别得对不对。只给个总数的话，
/// "识别错了但数量对了"和"识别对了"在界面上无法区分 —— 而这两种
/// 情况对下游 CFG 的影响完全不同。
async fn jump_tables(State(state): State<AppState>) -> Response {
    let analysis = match state.analysis() {
        Ok(a) => a,
        Err(reason) => return error_response(StatusCode::BAD_REQUEST, &reason),
    };

    let scan = analysis.jump_tables();
    Json(JumpTablesResponse {
        format_version: bitflip_core::ANALYSIS_FORMAT_VERSION,
        tables: scan
            .tables
            .iter()
            .map(|t| JumpTableWire {
                insn_addr: bitflip_core::hex16(t.insn_addr),
                base: bitflip_core::hex16(t.base),
                width: t.width.as_str(),
                kind: t.kind.as_str(),
                kind_zh: t.kind.label_zh(),
                count: t.count,
                targets: t.targets.iter().map(|a| bitflip_core::hex16(*a)).collect(),
            })
            .collect(),
        notes: scan.notes.clone(),
    })
    .into_response()
}

/// 数据/代码判定响应：`GET /api/code-map`。
#[derive(Serialize)]
struct CodeMapResponse {
    /// wire 格式版本。
    format_version: u32,
    /// 判定统计（基于抽样）。
    stats: bitflip_core::CodeMapStats,
    /// 代表性判定（含证据），供 UI 展示"凭什么这么判"。
    samples: Vec<bitflip_core::CodeMapSample>,
    /// 说明（抽样范围、降级等）。
    notes: Vec<String>,
}

/// 数据/代码判定：`GET /api/code-map`。
///
/// 单独一个端点的理由：判定结论的**依据**（哪条证据、强度多少）是
/// 用户判断"该不该信"的关键，而 `/api/analyze` 是个汇总，塞不下
/// 这些细节。CLAUDE.md §7 要求降级与不确定性可见 —— 只给个比例
/// 数字不算可见。
async fn code_map(State(state): State<AppState>) -> Response {
    let analysis = match state.analysis() {
        Ok(a) => a,
        Err(reason) => return error_response(StatusCode::BAD_REQUEST, &reason),
    };

    let m = analysis.code_map();
    Json(CodeMapResponse {
        format_version: bitflip_core::ANALYSIS_FORMAT_VERSION,
        stats: m.stats,
        samples: m.samples.clone(),
        notes: m.notes.clone(),
    })
    .into_response()
}

/// 单个函数的 CFG 响应：`GET /api/cfg?entry=<hex>`。
#[derive(Serialize)]
struct CfgResponse {
    /// wire 格式版本。
    format_version: u32,
    /// 请求的函数入口（定长十六进制）。
    entry: String,
    /// 该函数的 CFG；入口不存在时为 `null`。
    ///
    /// 用 `null` 而不是空图：**"这个入口没有 CFG"与"这个函数没有基本块"
    /// 是两件不同的事**，前者要如实说"没有"，后者是数据。
    cfg: Option<bitflip_core::CfgWire>,
    /// 一并返回该函数的信息，省一次往返；找不到时为 `null`。
    function: Option<bitflip_core::FunctionWire>,
}

/// CFG 查询参数。
#[derive(serde::Deserialize)]
struct CfgQuery {
    /// 函数入口地址（十六进制）。
    entry: Option<String>,
}

/// 单个函数的控制流图：`GET /api/cfg?entry=<hex>`。
///
/// `entry` 必填：CFG 是**按函数**定义的，没有一个"整个目标的 CFG" ——
/// 那会是一堆互不相连的图，没有任何分析价值。
/// 因此缺少 entry 时返回 400 并说明原因，而不是返回空对象。
async fn cfg(
    State(state): State<AppState>,
    axum::extract::Query(query): axum::extract::Query<CfgQuery>,
) -> Response {
    let analysis = match state.analysis() {
        Ok(a) => a,
        Err(reason) => return error_response(StatusCode::BAD_REQUEST, &reason),
    };

    let Some(raw) = query.entry.as_deref() else {
        return error_response(
            StatusCode::BAD_REQUEST,
            "缺少 entry 参数：CFG 是按函数定义的，请指定函数入口地址（十六进制）",
        );
    };
    let entry = match parse_optional_address(Some(raw)) {
        Ok(v) => v,
        Err(message) => return error_response(StatusCode::BAD_REQUEST, &message),
    };

    let cfg = analysis.cfg_of(entry).cloned();
    let function = analysis
        .functions()
        .iter()
        .find(|f| bitflip_core::parse_address(&f.start) == Some(entry))
        .cloned();

    Json(CfgResponse {
        format_version: bitflip_core::ANALYSIS_FORMAT_VERSION,
        entry: bitflip_core::hex16(entry),
        cfg,
        function,
    })
    .into_response()
}

/// 归档成员里的函数列表：`GET /api/members/functions?member=<name>`。
///
/// 为什么不能复用 `/api/functions?member=`：容器级分析对归档**根本不成立**
/// （`state.analysis()` 会失败），所以那条路径永远走不到成员。
/// 单独一个端点能让"这里是成员的函数"这件事在 URL 层面就清楚，
/// 前端也不会误以为可以拿容器级分页参数来翻成员。
///
/// 返回体复用 [`FunctionsResponse`] 的形状（外加 `member` 字段），
/// 这样前端的函数列表组件不需要为成员写第二套解析。
#[derive(Serialize)]
struct MemberFunctionsResponse {
    /// wire 格式版本。
    format_version: u32,
    /// 成员名（原样回显，让前端确认自己看的是哪个成员）。
    member: String,
    /// 总数（分页前）。
    total: usize,
    /// 本页函数。
    functions: Vec<bitflip_core::FunctionWire>,
    /// 分析期的降级说明。
    notes: Vec<String>,
}

/// 成员函数列表查询参数。
#[derive(serde::Deserialize)]
struct MemberFunctionsQuery {
    /// 成员名（必填）。
    member: Option<String>,
    /// 只看地址 >= 该值的函数。
    from: Option<String>,
    /// 请求条数；服务端 clamp。
    count: Option<usize>,
}

/// 成员函数列表：`GET /api/members/functions?member=<name>`。
async fn member_functions(
    State(state): State<AppState>,
    axum::extract::Query(query): axum::extract::Query<MemberFunctionsQuery>,
) -> Response {
    let Some(name) = query.member.as_deref().filter(|s| !s.is_empty()) else {
        return error_response(
            StatusCode::BAD_REQUEST,
            "缺少 member 参数：请先用 /api/members 查看可用的成员名",
        );
    };

    let session = match state.member_session(name) {
        Ok(s) => s,
        Err(reason) => return error_response(StatusCode::BAD_REQUEST, &reason),
    };

    let job = session.detached_job();
    let analysis = match session.analysis(&job) {
        Ok(a) => a,
        Err(error) => return error_response(StatusCode::BAD_REQUEST, &error.to_string()),
    };

    let from = match parse_optional_address(query.from.as_deref()) {
        Ok(v) => v,
        Err(message) => return error_response(StatusCode::BAD_REQUEST, &message),
    };
    let count = query
        .count
        .unwrap_or(bitflip_core::DEFAULT_PAGE_SIZE)
        .min(bitflip_core::DEFAULT_PAGE_SIZE);

    let all = analysis.functions();
    let total = all.len();
    let functions: Vec<_> = all
        .iter()
        .filter(|f| bitflip_core::parse_address(&f.start).is_some_and(|addr| addr >= from))
        .take(count)
        .cloned()
        .collect();

    Json(MemberFunctionsResponse {
        format_version: bitflip_core::ANALYSIS_FORMAT_VERSION,
        member: name.to_string(),
        total,
        functions,
        notes: analysis.notes().to_vec(),
    })
    .into_response()
}

/// 函数列表查询参数。
#[derive(serde::Deserialize)]
struct FunctionsQuery {
    /// 起始地址（只看 >= 该地址的函数）。
    from: Option<String>,
    /// 请求条数；服务端 clamp。
    count: Option<usize>,
}

/// 函数列表：`GET /api/functions?from=<hex>&count=<n>`。
///
/// 分页的理由与反汇编相同：几万个函数一次序列化会让浏览器卡死。
async fn functions(
    State(state): State<AppState>,
    axum::extract::Query(query): axum::extract::Query<FunctionsQuery>,
) -> Response {
    let analysis = match state.analysis() {
        Ok(a) => a,
        Err(reason) => return error_response(StatusCode::BAD_REQUEST, &reason),
    };

    let from = match parse_optional_address(query.from.as_deref()) {
        Ok(v) => v,
        Err(message) => return error_response(StatusCode::BAD_REQUEST, &message),
    };

    let all = analysis.functions();
    let total = all.len();
    let count = query
        .count
        .unwrap_or(bitflip_core::DEFAULT_PAGE_SIZE)
        .min(bitflip_core::DEFAULT_PAGE_SIZE);

    // `FunctionWire::start` 是定长十六进制字符串（wire 契约），
    // 过滤前要先解析回 u64。解析不出来的条目**跳过但不隐藏**：
    // 正常情况下不可能出现，真出现说明 wire 层有 bug，用 note 提示。
    let functions: Vec<_> = all
        .iter()
        .filter(|f| bitflip_core::parse_address(&f.start).is_some_and(|addr| addr >= from))
        .take(count)
        .cloned()
        .collect();

    Json(FunctionsResponse {
        format_version: bitflip_core::ANALYSIS_FORMAT_VERSION,
        total,
        functions,
        notes: analysis.notes().to_vec(),
    })
    .into_response()
}

/// 交叉引用响应。
#[derive(Serialize)]
struct XrefsResponse {
    /// wire 格式版本。
    format_version: u32,
    /// 查询的地址。
    address: String,
    /// 从该地址发出的引用。
    from: Vec<bitflip_core::XrefWire>,
    /// 指向该地址的引用。
    to: Vec<bitflip_core::XrefWire>,
    /// 包含该地址的函数（`null` 表示没有已知函数覆盖它）。
    ///
    /// `null` 而不是一个占位函数：地址不在任何已知函数里是**真实**情形
    /// （数据段、填充区、还没识别的代码），用假函数掩盖会让用户误判。
    function: Option<bitflip_core::FunctionWire>,
}

/// 交叉引用查询参数。
#[derive(serde::Deserialize)]
struct AddressQuery {
    /// 目标地址（`0x` 前缀可省）。
    address: Option<String>,
    /// `address` 的别名，便于前端直接复用反汇编页的跳转参数名。
    at: Option<String>,
}

/// 交叉引用：`GET /api/xrefs?address=<hex>`。
async fn xrefs(
    State(state): State<AppState>,
    axum::extract::Query(query): axum::extract::Query<AddressQuery>,
) -> Response {
    let analysis = match state.analysis() {
        Ok(a) => a,
        Err(reason) => return error_response(StatusCode::BAD_REQUEST, &reason),
    };

    let raw = query.address.or(query.at);
    let Some(raw) = raw else {
        return error_response(StatusCode::BAD_REQUEST, "缺少 address 参数");
    };
    let Some(address) = bitflip_core::parse_address(&raw) else {
        return error_response(
            StatusCode::BAD_REQUEST,
            &format!("地址无法解析：{raw:?}（需要 16 进制，可带 0x 前缀）"),
        );
    };

    Json(XrefsResponse {
        format_version: bitflip_core::ANALYSIS_FORMAT_VERSION,
        address: bitflip_core::hex16(address),
        from: analysis.xrefs_from(address).into_iter().cloned().collect(),
        to: analysis.xrefs_to(address).into_iter().cloned().collect(),
        function: analysis.function_containing(address).cloned(),
    })
    .into_response()
}

/// 字符串列表响应。
#[derive(Serialize)]
struct StringsResponse {
    /// wire 格式版本。
    format_version: u32,
    /// 总数。
    total: usize,
    /// 本页字符串。
    strings: Vec<bitflip_core::StringWire>,
}

/// 字符串查询参数。
#[derive(serde::Deserialize)]
struct StringsQuery {
    /// 子串过滤（大小写敏感，按需再加）。
    contains: Option<String>,
    /// 请求条数。
    count: Option<usize>,
    /// 跳过条数（分页）。
    offset: Option<usize>,
}

/// 字符串：`GET /api/strings?contains=<s>&count=<n>&offset=<n>`。
async fn strings(
    State(state): State<AppState>,
    axum::extract::Query(query): axum::extract::Query<StringsQuery>,
) -> Response {
    let analysis = match state.analysis() {
        Ok(a) => a,
        Err(reason) => return error_response(StatusCode::BAD_REQUEST, &reason),
    };

    let needle = query.contains.unwrap_or_default();
    let filtered: Vec<_> = analysis
        .strings()
        .iter()
        .filter(|s| needle.is_empty() || s.text.contains(&needle))
        .collect();
    let total = filtered.len();

    let offset = query.offset.unwrap_or(0);
    let count = query
        .count
        .unwrap_or(bitflip_core::DEFAULT_PAGE_SIZE)
        .min(bitflip_core::DEFAULT_PAGE_SIZE);

    Json(StringsResponse {
        format_version: bitflip_core::ANALYSIS_FORMAT_VERSION,
        total,
        strings: filtered
            .into_iter()
            .skip(offset)
            .take(count)
            .cloned()
            .collect(),
    })
    .into_response()
}

/// 十六进制视图响应。
#[derive(Serialize)]
struct HexResponse {
    /// 起始地址（回显规范化后的值）。
    address: String,
    /// 每行的字节数。
    row_bytes: usize,
    /// 行列表。
    rows: Vec<HexRow>,
    /// 实际读到的字节数（可能少于请求，到段尾或文件尾）。
    bytes_read: usize,
}

/// 十六进制视图的一行。
#[derive(Serialize)]
struct HexRow {
    /// 行首地址。
    address: String,
    /// 十六进制字节（每字节两位，小写）。
    hex: String,
    /// ASCII 投影（不可打印字符为 `.`）。
    ascii: String,
}

/// 十六进制视图查询参数。
#[derive(serde::Deserialize)]
struct HexQuery {
    /// 起始地址。
    address: Option<String>,
    /// 请求字节数；服务端 clamp。
    length: Option<usize>,
}

/// 每行显示的字节数。
const HEX_ROW_BYTES: usize = 16;
/// 单次十六进制视图的字节上限（64 KiB：够看几屏，又不会被拿来下载整个文件）。
const MAX_HEX_BYTES: usize = 64 * 1024;

/// 十六进制视图：`GET /api/hex?address=<hex>&length=<n>`。
///
/// 读不到就如实说读不到：`bytes_read` 会小于请求值，UI 据此显示"到段尾"，
/// 而不是拿零填充冒充文件内容（§7）。
async fn hex(
    State(state): State<AppState>,
    axum::extract::Query(query): axum::extract::Query<HexQuery>,
) -> Response {
    let raw = query.address.unwrap_or_else(|| "0".to_string());
    let Some(address) = bitflip_core::parse_address(&raw) else {
        return error_response(
            StatusCode::BAD_REQUEST,
            &format!("地址无法解析：{raw:?}（需要 16 进制，可带 0x 前缀）"),
        );
    };

    let length = query.length.unwrap_or(512).min(MAX_HEX_BYTES);

    let data = match state.read_bytes(address, length) {
        Ok(d) => d,
        Err(reason) => return error_response(StatusCode::BAD_REQUEST, &reason),
    };

    let rows: Vec<HexRow> = data
        .chunks(HEX_ROW_BYTES)
        .enumerate()
        .map(|(index, chunk)| {
            let mut hex = String::with_capacity(chunk.len() * 3);
            let mut ascii = String::with_capacity(chunk.len());
            for (i, byte) in chunk.iter().enumerate() {
                if i > 0 {
                    hex.push(' ');
                }
                hex.push_str(&format!("{byte:02x}"));
                // 只把可打印 ASCII 投影出来；其余用 `.`，
                // 否则中文/控制字节会把 JSON 和终端搞乱。
                ascii.push(if (0x20..0x7f).contains(byte) {
                    *byte as char
                } else {
                    '.'
                });
            }
            HexRow {
                address: bitflip_core::hex16(address + (index * HEX_ROW_BYTES) as u64),
                hex,
                ascii,
            }
        })
        .collect();

    Json(HexResponse {
        address: bitflip_core::hex16(address),
        row_bytes: HEX_ROW_BYTES,
        bytes_read: data.len(),
        rows,
    })
    .into_response()
}

/// 注解（标注）列表响应。
#[derive(Serialize)]
struct AnnotationsResponse {
    /// 格式版本。
    format_version: u32,
    /// 目标内容哈希（工程库的身份）。
    target_sha256: String,
    /// 本页标注。
    annotations: Vec<bitflip_core::Annotation>,
    /// 分析是否已经跑过（UI 据此提示"标注不会被重新分析覆盖"）。
    analyzed_at_unix: Option<u64>,
}

/// 标注查询参数。
#[derive(serde::Deserialize)]
struct AnnotationsQuery {
    /// 起始地址（含）。
    from: Option<String>,
    /// 结束地址（不含）；省略则取 `from + MAX`。
    to: Option<String>,
}

/// 范围查询的默认跨度：一个窗口取 1 MiB 的地址空间内的标注。
const ANNOTATION_WINDOW: u64 = 1 << 20;

/// 读取标注：`GET /api/annotations?from=<hex>&to=<hex>`。
async fn annotations(
    State(state): State<AppState>,
    axum::extract::Query(query): axum::extract::Query<AnnotationsQuery>,
) -> Response {
    let store = match state.project() {
        Ok(s) => s,
        Err(reason) => return error_response(StatusCode::BAD_REQUEST, &reason),
    };
    let meta = match store.meta() {
        Ok(m) => m,
        Err(error) => return error_response(StatusCode::INTERNAL_SERVER_ERROR, &error.to_string()),
    };

    let from = match parse_optional_address(query.from.as_deref()) {
        Ok(v) => v,
        Err(message) => return error_response(StatusCode::BAD_REQUEST, &message),
    };
    let to = match query.to.as_deref() {
        None => from.saturating_add(ANNOTATION_WINDOW),
        Some(text) => match bitflip_core::parse_address(text) {
            Some(v) => v,
            None => {
                return error_response(
                    StatusCode::BAD_REQUEST,
                    &format!("地址无法解析：{text:?}（需要 16 进制，可带 0x 前缀）"),
                );
            }
        },
    };

    Json(AnnotationsResponse {
        format_version: bitflip_core::CORE_API_VERSION,
        target_sha256: meta.target_sha256,
        annotations: store.range(from, to),
        analyzed_at_unix: meta.analyzed_at_unix,
    })
    .into_response()
}

/// 写入标注的请求体。
#[derive(serde::Deserialize)]
struct AnnotationBody {
    /// 地址（字符串，接受 `0x` 前缀）。
    address: String,
    /// 类别：`name` / `comment` / `bookmark` / …
    kind: String,
    /// 文本内容。
    text: Option<String>,
    /// 补丁字节（十六进制字符串）。
    patch_hex: Option<String>,
}

/// 写入标注：`PUT /api/annotations`。
///
/// **这是主数据写入，不触发重新分析** —— UI 改名之后不该等一次全量扫描。
/// 分析结果（函数/xref/字符串）是派生物，存在独立文件里，与标注互不干扰。
async fn put_annotation(
    State(state): State<AppState>,
    Json(body): Json<AnnotationBody>,
) -> Response {
    let store = match state.project() {
        Ok(s) => s,
        Err(reason) => return error_response(StatusCode::BAD_REQUEST, &reason),
    };

    let Some(address) = bitflip_core::parse_address(&body.address) else {
        return error_response(
            StatusCode::BAD_REQUEST,
            &format!("地址无法解析：{:?}", body.address),
        );
    };
    let Some(kind) = bitflip_core::AnnotationKind::parse(&body.kind) else {
        return error_response(
            StatusCode::BAD_REQUEST,
            &format!(
                "标注类别无法识别：{:?}（可用：name/comment/type/bookmark/patch/function-boundary/code-data）",
                body.kind
            ),
        );
    };

    if body.text.is_none() && body.patch_hex.is_none() {
        return error_response(
            StatusCode::BAD_REQUEST,
            "标注既没有 text 也没有 patch_hex：空标注没有意义，已拒绝",
        );
    }

    let annotation = bitflip_core::Annotation {
        address,
        kind,
        text: body.text,
        patch_hex: body.patch_hex,
    };

    let now = now_unix();
    match store.put(&annotation, now) {
        Ok(()) => Json(serde_json::json!({
            "ok": true,
            "address": bitflip_core::hex16(address),
            "kind": kind.as_str(),
            "updated_at_unix": now,
            "reanalyzed": false,
        }))
        .into_response(),
        Err(error) => error_response(StatusCode::INTERNAL_SERVER_ERROR, &error.to_string()),
    }
}

/// 删除标注：`DELETE /api/annotations?address=<hex>&kind=<kind>`。
async fn delete_annotation(
    State(state): State<AppState>,
    axum::extract::Query(query): axum::extract::Query<DeleteAnnotationQuery>,
) -> Response {
    let store = match state.project() {
        Ok(s) => s,
        Err(reason) => return error_response(StatusCode::BAD_REQUEST, &reason),
    };

    let Some(address) = query
        .address
        .as_deref()
        .and_then(bitflip_core::parse_address)
    else {
        return error_response(
            StatusCode::BAD_REQUEST,
            "缺少或无法解析 address 参数（需要 16 进制）",
        );
    };
    let Some(kind) = query
        .kind
        .as_deref()
        .and_then(bitflip_core::AnnotationKind::parse)
    else {
        return error_response(
            StatusCode::BAD_REQUEST,
            "缺少或无法识别 kind 参数（可用：name/comment/type/bookmark/patch/function-boundary/code-data）",
        );
    };

    match store.delete(address, kind) {
        Ok(()) => Json(serde_json::json!({
            "ok": true,
            "address": bitflip_core::hex16(address),
            "kind": kind.as_str(),
        }))
        .into_response(),
        Err(error) => error_response(StatusCode::INTERNAL_SERVER_ERROR, &error.to_string()),
    }
}

/// 删除标注的查询参数。
#[derive(serde::Deserialize)]
struct DeleteAnnotationQuery {
    /// 地址。
    address: Option<String>,
    /// 类别。
    kind: Option<String>,
}

/// 当前 Unix 时间（秒）。时钟是基础设施，不从这里往上层传业务语义。
fn now_unix() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

/// 解析可选地址参数：缺省为 0。
///
/// 与 `insns` 的处理保持一致：解析失败要**报错**，不能悄悄回退到 0 ——
/// 那会让用户以为自己跳转成功了，其实只是回到了开头。
fn parse_optional_address(text: Option<&str>) -> Result<u64, String> {
    match text {
        None | Some("") => Ok(0),
        Some(text) => bitflip_core::parse_address(text)
            .ok_or_else(|| format!("地址无法解析：{text:?}（需要 16 进制，可带 0x 前缀）")),
    }
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
