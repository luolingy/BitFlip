//! 脚本执行端点（M7）：运行、观察、取消。
//!
//! # 为什么是"单槽 + 轮询"而不是一个同步的 POST
//!
//! 一个同步的 `POST /api/script/run` 要等脚本跑完才返回，于是：
//!
//! 1. **看不到进度**。批处理进度与逐条日志都在运行**期间**才有意义，
//!    等结果回来时它们已经全是历史了。
//! 2. **停不下来**。取消端点得先知道"在跑什么"才能取消；同步模型里
//!    服务端根本没有一个可被外部引用的运行对象。
//! 3. **占住 async 线程**。脚本执行是纯 CPU 的，必须落到 `spawn_blocking`，
//!    否则一次 10 秒的批处理会把整个 tokio 运行时卡住 —— 连健康检查都不响应。
//!
//! 所以拆成三个端点：`run` 立刻返回"已开始"，`status` 轮询观测点，
//! `cancel` 发取消请求。
//!
//! # 为什么只有一个槽位
//!
//! 脚本会写标注、会读同一份缓存的分析结论。两个脚本并行跑会让日志与写入
//! 交错，用户没有任何办法分辨"这条注释是哪个脚本写的"。项目的既有约定也是
//! 一次只做一个 CPU 密集的作业（大目标分析独占）。第二个请求明确得到 409，
//! 而不是排队 —— 排队会让用户以为点了没反应。

use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use axum::extract::State;
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use axum::Json;
use serde::{Deserialize, Serialize};

use bitflip_script::{
    CancelToken, Host, Limits, ScriptEngine, ScriptError, ScriptLog, ScriptOutcome, ScriptProgress,
    TableCell, TableColumn, TableSummary,
};

use crate::AppState;

/// 运行阶段。
///
/// 把"预热"单独标出来不是洁癖：预热期间要构建分析结论（ntdll 上 10.6 秒），
/// 而**分析是不可取消的** —— 它不在 QuickJS 里跑，中断回调管不着。界面必须
/// 能如实说"正在分析，暂时不能取消"，而不是让用户对着一个无效的停止按钮猛点。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Phase {
    /// 预热：构建分析与反汇编，不计入脚本超时，不可取消。
    Warming,
    /// 脚本正在执行，可取消。
    Executing,
}

/// 一次运行的观测点。`status` 读它，脚本运行时也在这里更新。
struct Active {
    id: u64,
    started: Instant,
    phase: Phase,
    /// 与阻塞线程里那份共享同一个状态：这就是能实时看到日志与进度的原因。
    host: Host,
    /// 取消令牌的**投递槽**。
    ///
    /// 为什么是 `Option` 而不是直接放一个令牌：`ScriptEngine` 不是 `Send`
    /// （QuickJS 的 `Runtime` 内部是 `Rc`），所以引擎只能在阻塞线程里创建，
    /// 令牌也就只能由那条线程回填。引擎建好之前槽里是 `None`，
    /// 此时取消请求如实报"还在预热"。
    token: Arc<Mutex<Option<CancelToken>>>,
    outcome: Option<Result<ScriptOutcome, ScriptError>>,
}

/// 运行器内部状态。
#[derive(Default)]
struct Runner {
    active: Option<Active>,
}

/// 单槽脚本运行器。
///
/// `Default` 用不了（`Limits` 有默认值但 `Mutex` 需要构造），所以显式写 `new`。
pub struct ScriptRunner {
    inner: Mutex<Runner>,
    next_id: AtomicU64,
    limits: Limits,
}

impl ScriptRunner {
    /// 新建运行器。
    #[must_use]
    pub fn new(limits: Limits) -> Self {
        Self {
            inner: Mutex::new(Runner::default()),
            next_id: AtomicU64::new(1),
            limits,
        }
    }

    fn lock(&self) -> std::sync::MutexGuard<'_, Runner> {
        self.inner
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }

    /// 是否有脚本正在运行（含预热阶段）。
    #[must_use]
    pub fn is_busy(&self) -> bool {
        self.lock()
            .active
            .as_ref()
            .is_some_and(|active| active.outcome.is_none())
    }

    /// 单次运行的墙钟上限。
    #[must_use]
    pub fn limits(&self) -> Limits {
        self.limits.clone()
    }

    /// 当前（或最近一次）运行的宿主句柄。
    ///
    /// 取表数据要用它：表数据不在 `StatusResponse` 里（那是轮询用的摘要），
    /// 而在脚本宿主上。没有运行过就是 `None` —— 调用方据此报"还没有表"，
    /// 而不是返回一张空表。
    #[must_use]
    pub fn host(&self) -> Option<Host> {
        self.lock()
            .active
            .as_ref()
            .map(|active| active.host.clone())
    }
}

/// 取消请求的结果。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CancelOutcome {
    /// 取消请求已送达，脚本会在下一次中断检查时停下。
    Requested,
    /// 没有脚本在运行。
    NothingRunning,
    /// 正在预热（构建分析结论），此阶段不可取消。
    Warming,
    /// 脚本已经结束（结果就在 status 里），没有可取消的对象。
    AlreadyFinished,
}

impl ScriptRunner {
    /// 请求取消当前运行。
    #[must_use]
    pub fn cancel(&self) -> CancelOutcome {
        let runner = self.lock();
        let Some(active) = runner.active.as_ref() else {
            return CancelOutcome::NothingRunning;
        };
        if active.outcome.is_some() {
            return CancelOutcome::AlreadyFinished;
        }
        if active.phase == Phase::Warming {
            return CancelOutcome::Warming;
        }
        let token = active
            .token
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .clone();
        let Some(token) = token else {
            // 引擎还没建好。理论上 `phase` 已经是执行中却拿不到令牌不该发生，
            // 但宁可如实说"还没开始"也不要假装取消成功。
            return CancelOutcome::Warming;
        };
        // `cancel()` 自带"没有脚本在跑就返回 false"的语义（见 bitflip-script）。
        // 这里再判一次是为了把"预热中"与"已开始执行"分开 —— 两者对用户的
        // 意思完全不同。
        if token.cancel() {
            CancelOutcome::Requested
        } else {
            CancelOutcome::AlreadyFinished
        }
    }
}

// ---------------------------------------------------------------------------
// 请求 / 响应
// ---------------------------------------------------------------------------

/// 运行脚本的请求体。
#[derive(Debug, Deserialize)]
pub struct RunRequest {
    /// 脚本源码。
    pub source: String,
}

/// 一行脚本日志的 wire 形状。
#[derive(Debug, Serialize)]
pub struct LogWire {
    /// `info` / `warn` / `error`。
    pub level: &'static str,
    /// 内容。
    pub message: String,
}

impl From<&ScriptLog> for LogWire {
    fn from(log: &ScriptLog) -> Self {
        Self {
            level: log.level.as_str(),
            message: log.message.clone(),
        }
    }
}

/// 进度的 wire 形状。
#[derive(Debug, Serialize)]
pub struct ProgressWire {
    /// 已完成。
    pub done: u64,
    /// 总数（脚本没说时为 `null`，界面应显示"进行中"而不是 0%）。
    pub total: Option<u64>,
    /// 当前在做什么。
    pub label: Option<String>,
}

impl From<&ScriptProgress> for ProgressWire {
    fn from(progress: &ScriptProgress) -> Self {
        Self {
            done: progress.done,
            total: progress.total,
            label: progress.label.clone(),
        }
    }
}

/// 脚本失败的 wire 形状。
///
/// 用带标签的枚举而不是一个 `{ message }` 字符串：界面对"已取消"、"超时"、
/// "提交写了一半"要给完全不同的呈现，把分类丢掉等于逼前端去解析中文文案。
#[derive(Debug, Serialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum ErrorWire {
    /// 被用户取消。
    Cancelled,
    /// 超过墙钟上限。
    Timeout {
        /// 上限毫秒数。
        limit_ms: u64,
    },
    /// 语法错误。
    Syntax {
        /// 说明。
        message: String,
        /// 行号。
        line: Option<u32>,
    },
    /// 运行期异常。
    Runtime {
        /// 说明。
        message: String,
        /// 行号。
        line: Option<u32>,
        /// 调用栈。
        stack: Option<String>,
    },
    /// 调用宿主 API 的方式不对。
    Host {
        /// 说明。
        message: String,
    },
    /// 宿主内部 panic（防御性分支）。
    Panic {
        /// 说明。
        message: String,
    },
    /// 提交写入时部分失败 —— 界面**必须**把两个数都显示出来。
    Commit {
        /// 已写入条数。
        committed: usize,
        /// 总条数。
        total: usize,
        /// 原因。
        reason: String,
    },
    /// 引擎故障。
    Engine {
        /// 说明。
        message: String,
    },
}

impl From<&ScriptError> for ErrorWire {
    fn from(error: &ScriptError) -> Self {
        match error {
            ScriptError::Cancelled => Self::Cancelled,
            ScriptError::Timeout { limit } => Self::Timeout {
                limit_ms: u64::try_from(limit.as_millis()).unwrap_or(u64::MAX),
            },
            ScriptError::Syntax { message, line } => Self::Syntax {
                message: message.clone(),
                line: *line,
            },
            ScriptError::Runtime {
                message,
                line,
                stack,
            } => Self::Runtime {
                message: message.clone(),
                line: *line,
                stack: stack.clone(),
            },
            ScriptError::Host { message } => Self::Host {
                message: message.clone(),
            },
            ScriptError::Panic { message } => Self::Panic {
                message: message.clone(),
            },
            ScriptError::Commit {
                committed,
                total,
                reason,
            } => Self::Commit {
                committed: *committed,
                total: *total,
                reason: reason.clone(),
            },
            ScriptError::Engine { message } => Self::Engine {
                message: message.clone(),
            },
        }
    }
}

/// 运行状态的响应。
#[derive(Debug, Serialize)]
pub struct StatusResponse {
    /// `idle` | `warming` | `running` | `done`。
    pub state: &'static str,
    /// 运行编号（`idle` 时为 `null`）。
    pub run_id: Option<u64>,
    /// 已耗时毫秒。
    pub elapsed_ms: u64,
    /// 目前为止的日志（运行中也在增长）。
    pub logs: Vec<LogWire>,
    /// 脚本上报的进度。
    pub progress: Option<ProgressWire>,
    /// 目前暂存的写入条数。
    pub staged: usize,
    /// 已提交条数（未结束时为 `null`）。
    pub committed: Option<usize>,
    /// 本次运行尝试提交的条数（未结束时为 `null`）。
    pub staged_total: Option<usize>,
    /// 本次运行产出的表（只给形状与行数，数据走 `/api/script/table`）。
    ///
    /// 单独给一个端点取数据行不是洁癖：界面每几百毫秒轮询一次状态，
    /// 把整张表的每一格都塞进轮询响应，光序列化就够把界面拖慢。
    pub tables: Vec<TableSummary>,
    /// 失败信息（成功或未结束时为 `null`）。
    pub error: Option<ErrorWire>,
    /// 现在点取消是否有用。
    ///
    /// 单独给一个字段而不是让前端从 `state` 推断：预热阶段看起来也是"在跑"，
    /// 但取消是无效的，界面必须能据此把按钮置灰并说明原因。
    pub can_cancel: bool,
    /// 脚本 API 版本，供控制台显示。
    pub api_version: u32,
}

/// 状态快照的组装（运行中与已结束共用）。
fn snapshot(
    active: Option<&Active>,
    logs: Vec<ScriptLog>,
    progress: Option<ScriptProgress>,
    staged: usize,
    tables: Vec<TableSummary>,
) -> StatusResponse {
    let Some(active) = active else {
        return StatusResponse {
            state: "idle",
            run_id: None,
            elapsed_ms: 0,
            logs: Vec::new(),
            progress: None,
            staged: 0,
            committed: None,
            staged_total: None,
            tables: Vec::new(),
            error: None,
            can_cancel: false,
            api_version: bitflip_script::SCRIPT_API_VERSION,
        };
    };

    let logs: Vec<LogWire> = logs.iter().map(LogWire::from).collect();
    let progress = progress.as_ref().map(ProgressWire::from);
    let elapsed_ms = u64::try_from(active.started.elapsed().as_millis()).unwrap_or(u64::MAX);

    match active.outcome.as_ref() {
        None => StatusResponse {
            state: match active.phase {
                Phase::Warming => "warming",
                Phase::Executing => "running",
            },
            run_id: Some(active.id),
            elapsed_ms,
            logs,
            progress,
            staged,
            committed: None,
            staged_total: None,
            tables,
            error: None,
            can_cancel: active.phase == Phase::Executing,
            api_version: bitflip_script::SCRIPT_API_VERSION,
        },
        Some(Ok(outcome)) => StatusResponse {
            state: "done",
            run_id: Some(active.id),
            elapsed_ms,
            logs,
            progress,
            staged,
            committed: Some(outcome.committed),
            staged_total: Some(outcome.staged),
            tables,
            error: None,
            can_cancel: false,
            api_version: bitflip_script::SCRIPT_API_VERSION,
        },
        Some(Err(error)) => StatusResponse {
            state: "done",
            run_id: Some(active.id),
            elapsed_ms,
            logs,
            progress,
            staged,
            committed: None,
            staged_total: None,
            tables,
            error: Some(ErrorWire::from(error)),
            can_cancel: false,
            api_version: bitflip_script::SCRIPT_API_VERSION,
        },
    }
}

// ---------------------------------------------------------------------------
// 端点
// ---------------------------------------------------------------------------

/// 错误响应体。
#[derive(Debug, Serialize)]
pub struct MessageResponse {
    /// 面向用户的说明。
    pub error: String,
}

fn conflict(message: &str) -> (StatusCode, Json<MessageResponse>) {
    (
        StatusCode::CONFLICT,
        Json(MessageResponse {
            error: message.to_string(),
        }),
    )
}

/// `POST /api/script/run`：开始一次运行。
///
/// 立刻返回，不等脚本跑完（理由见模块文档）。第二个并发请求得到 409。
pub async fn run(
    State(state): State<AppState>,
    Json(request): Json<RunRequest>,
) -> Result<(StatusCode, Json<StatusResponse>), (StatusCode, Json<MessageResponse>)> {
    // 先做一次便宜的预检，好让"明显在忙"的请求快速得到 409；
    // 真正的判定在 `begin()` 里（它以同一把锁为准，避免两次检查之间被插队）。
    if state.script.is_busy() {
        return Err(conflict(
            "已有脚本正在运行；脚本会改动标注，同一时刻只允许一个",
        ));
    }

    let host = state
        .script_host()
        .map_err(|error| (StatusCode::BAD_REQUEST, Json(MessageResponse { error })))?;

    let limits = state.script.limits();
    let token_slot = Arc::new(Mutex::new(None));
    let run_id = state.script.begin(host.clone(), Arc::clone(&token_slot))?;

    let source = request.source;
    let runner = Arc::clone(&state.script);
    // 纯 CPU 的工作必须离开 async 线程：一次 10 秒的批处理会把 tokio 运行时
    // 卡住，连健康检查都不响应。
    //
    // 引擎**在闭包内部**创建：`ScriptEngine` 不是 `Send`（QuickJS 的 `Runtime`
    // 内部是 `Rc`），移不进来。令牌因此在闭包里回填到 `token_slot`，
    // 取消端点在此之前如实报"还在预热"。
    tokio::task::spawn_blocking(move || {
        let engine = match ScriptEngine::new(limits) {
            Ok(engine) => engine,
            Err(error) => {
                runner.finish(run_id, Err(error));
                return;
            }
        };
        *token_slot
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner) = Some(engine.cancel_token());

        // 预热要花的时间**不该算在脚本头上**（ntdll 上分析要 10.6 秒，
        // 而脚本默认上限远小于此）。预热失败不致命：读 API 会在脚本真正用到
        // 那个能力时报出准确原因。
        let _ = host.warmup();
        runner.mark_executing(run_id);
        let outcome = engine.run(&host, &source);
        runner.finish(run_id, outcome);
    });

    // 返回刚登记的那个观测点：此刻是"预热中"，界面据此显示"正在分析"。
    Ok((StatusCode::ACCEPTED, Json(observe(&state.script))))
}

/// 读一次当前观测点并组装响应。
fn observe(runner: &ScriptRunner) -> StatusResponse {
    let runner = runner.lock();
    let active = runner.active.as_ref();
    let logs = active.map_or_else(Vec::new, |active| active.host.logs());
    let progress = active.and_then(|active| active.host.progress());
    let staged = active.map_or(0, |active| active.host.staged_len());
    let tables = active.map_or_else(Vec::new, |active| active.host.table_summaries());
    snapshot(active, logs, progress, staged, tables)
}

/// `GET /api/script/status`：观测当前（或最近一次）运行。
pub async fn status(State(state): State<AppState>) -> Json<StatusResponse> {
    Json(observe(&state.script))
}

/// 一份内置脚本的 wire 形状。
#[derive(Debug, Serialize)]
pub struct BuiltinScriptWire {
    /// 稳定标识。
    pub id: &'static str,
    /// 显示名。
    pub name: &'static str,
    /// 说明。
    pub description: &'static str,
    /// 写就时依据的脚本 API 版本。
    pub api_version: u32,
    /// 源码。
    pub source: &'static str,
}

/// 脚本库的响应。
#[derive(Debug, Serialize)]
pub struct LibraryResponse {
    /// 当前脚本 API 版本（UI 据此判断示例是否适用于本引擎）。
    pub api_version: u32,
    /// 内置脚本。
    pub scripts: Vec<BuiltinScriptWire>,
}

/// `GET /api/script/library`：内置示例脚本集。
///
/// 源码随响应一起给出（而不是只给标识让前端自己拼）：脚本库要能"看一眼源码
/// 再决定跑不跑"，而且进二进制的这份源码是被测试真的执行过的 ——
/// 前端若自己维护一份副本，那份恰好就是没被跑过的那一份。
pub async fn library() -> Json<LibraryResponse> {
    Json(LibraryResponse {
        api_version: bitflip_script::SCRIPT_API_VERSION,
        scripts: bitflip_script::builtin_scripts()
            .iter()
            .map(|script| BuiltinScriptWire {
                id: script.id,
                name: script.name,
                description: script.description,
                api_version: script.api_version,
                source: script.source,
            })
            .collect(),
    })
}

/// 分页取表的查询参数。
#[derive(Debug, Deserialize)]
pub struct TableQuery {
    /// 表名（必填）。
    pub name: Option<String>,
    /// 起始行（默认 0）。
    pub offset: Option<usize>,
    /// 取多少行（默认 [`DEFAULT_TABLE_PAGE`]，上限 [`MAX_TABLE_PAGE`]）。
    pub count: Option<usize>,
}

/// 默认每页行数与上限。
///
/// 与界面上的"结果表格"同一量级：一张要给人看的表不会只有十行，
/// 但一次几千行也远超一屏。上限存在的意义是**挡住一个数字**——
/// `count=99999999` 会把整张表序列化进一次响应。
pub const DEFAULT_TABLE_PAGE: usize = 2_000;
/// 见 [`DEFAULT_TABLE_PAGE`]。
pub const MAX_TABLE_PAGE: usize = 5_000;

/// 一页表数据的响应。
#[derive(Debug, Serialize)]
pub struct TableResponse<'a> {
    /// 表名。
    pub name: &'a str,
    /// 说明。
    pub description: Option<&'a str>,
    /// 列定义（含类型：界面按它渲染，不猜）。
    pub columns: &'a [TableColumn],
    /// 总行数。
    pub total: usize,
    /// 本页起始行。
    pub offset: usize,
    /// 数据行；每一格是 `null` / 布尔 / 数字 / 字符串（地址是十六进制字符串）。
    pub rows: &'a [Vec<TableCell>],
}

/// `GET /api/script/table?name=<表名>&offset=<n>&count=<n>`：取表数据。
///
/// 表是**本次会话**的派生物（脚本产出，不落工程库），所以这里只认当前
/// [`Host`] 上的那几张表；没有就叫 404 并列出有哪些表，而不是返回空数组 ——
/// 空数组在界面上表现为"这张表是空的"，与"没有这张表"完全是两回事。
pub async fn table(
    State(state): State<AppState>,
    axum::extract::Query(query): axum::extract::Query<TableQuery>,
) -> Response {
    let Some(name) = query
        .name
        .as_deref()
        .map(str::trim)
        .filter(|n| !n.is_empty())
    else {
        return failure(
            StatusCode::BAD_REQUEST,
            "需要 name 参数：/api/script/table?name=<表名>",
        );
    };

    let Some(host) = state.script.host() else {
        return failure(
            StatusCode::NOT_FOUND,
            "本次会话还没有运行过脚本，因此没有表",
        );
    };

    let Some(table) = host.table(name) else {
        let available: Vec<String> = host
            .table_summaries()
            .into_iter()
            .map(|summary| summary.name)
            .collect();
        let hint = if available.is_empty() {
            "本次运行的脚本没有产出表（脚本里要用 bitflip.table(...) 显式产出）".to_string()
        } else {
            format!("当前有：{}", available.join("、"))
        };
        return failure(
            StatusCode::NOT_FOUND,
            &format!("没有名为 {name:?} 的表；{hint}"),
        );
    };

    let offset = query.offset.unwrap_or(0);
    let count = query.count.unwrap_or(DEFAULT_TABLE_PAGE);
    if count == 0 {
        return failure(StatusCode::BAD_REQUEST, "count 必须大于 0");
    }
    if count > MAX_TABLE_PAGE {
        return failure(
            StatusCode::BAD_REQUEST,
            &format!("count 最多 {MAX_TABLE_PAGE}（收到 {count}）；要全部数据请分页取"),
        );
    }

    let end = offset.saturating_add(count).min(table.row_count());
    let rows = if offset >= table.row_count() {
        &[][..]
    } else {
        &table.rows[offset..end]
    };

    Json(TableResponse {
        name: &table.name,
        description: table.description.as_deref(),
        columns: &table.columns,
        total: table.row_count(),
        offset,
        rows,
    })
    .into_response()
}

/// 出错时的响应（与状态码一起给出一句能照做的说明）。
fn failure(status: StatusCode, message: &str) -> Response {
    (
        status,
        Json(MessageResponse {
            error: message.to_string(),
        }),
    )
        .into_response()
}

/// 取消请求的响应。
#[derive(Debug, Serialize)]
pub struct CancelResponse {
    /// 取消请求是否已被接受。
    pub ok: bool,
    /// 面向用户的说明（被拒时解释原因）。
    pub message: String,
}
/// `POST /api/script/cancel`：请求取消。
pub async fn cancel(State(state): State<AppState>) -> (StatusCode, Json<CancelResponse>) {
    let (status, ok, message) = match state.script.cancel() {
        CancelOutcome::Requested => (
            StatusCode::OK,
            true,
            "已请求取消，脚本会在下一次中断检查时停下".to_string(),
        ),
        CancelOutcome::NothingRunning => (
            StatusCode::CONFLICT,
            false,
            "当前没有脚本在运行".to_string(),
        ),
        CancelOutcome::Warming => (
            StatusCode::CONFLICT,
            false,
            "脚本尚未开始执行：正在构建分析结论，这一步不可取消\
             （分析结果会被缓存，下次运行直接复用）"
                .to_string(),
        ),
        CancelOutcome::AlreadyFinished => (
            StatusCode::CONFLICT,
            false,
            "脚本已经结束，没有可取消的运行".to_string(),
        ),
    };
    (status, Json(CancelResponse { ok, message }))
}

/// 默认的脚本上限。
///
/// 比库里的 5 秒宽松：控制台里的脚本常常要遍历上万个函数并逐条写注释，
/// 5 秒会让"能跑完的脚本"频繁被掐断，用户只好无脑调大上限。
/// 真正的死循环由取消按钮兜住，不必全靠超时。
pub const DEFAULT_TIMEOUT: Duration = Duration::from_secs(30);

impl ScriptRunner {
    /// 落一次运行：登记观测点并返回运行编号。
    fn begin(
        &self,
        host: Host,
        token: Arc<Mutex<Option<CancelToken>>>,
    ) -> Result<u64, (StatusCode, Json<MessageResponse>)> {
        let id = self.next_id.fetch_add(1, Ordering::Relaxed);
        let mut runner = self.lock();
        if runner
            .active
            .as_ref()
            .is_some_and(|active| active.outcome.is_none())
        {
            return Err(conflict("已有脚本正在运行"));
        }
        runner.active = Some(Active {
            id,
            started: Instant::now(),
            phase: Phase::Warming,
            host,
            token,
            outcome: None,
        });
        Ok(id)
    }

    /// 标记进入执行阶段（预热结束）。
    fn mark_executing(&self, id: u64) {
        let mut runner = self.lock();
        if let Some(active) = runner.active.as_mut() {
            if active.id == id {
                active.phase = Phase::Executing;
            }
        }
    }

    /// 落结果。
    fn finish(&self, id: u64, outcome: Result<ScriptOutcome, ScriptError>) {
        let mut runner = self.lock();
        if let Some(active) = runner.active.as_mut() {
            if active.id == id {
                active.outcome = Some(outcome);
            }
        }
    }
}
