//! 脚本的宿主侧：`bitflip` 全局对象、写入暂存与能力注入。
//!
//! # 能力是**注入**的，不是自己找的
//!
//! `Host` 不负责打开目标、构建分析结论或反汇编 —— 这些由调用方（服务层）
//! 传入。理由不是洁癖，是**避免两份**：服务层已经把这些结果缓存在
//! `OnceLock` 里，脚本层自己再算一遍不只是慢，还会在同一进程里同时存在
//! 两份指令索引与分析结论。大目标上这是可观的内存。
//!
//! # 地址在脚本里也是字符串
//!
//! CLAUDE.md §4 要求"内部一律 `u64`，跨进程 wire 上统一定长小写 16 位十六进制"。
//! 脚本边界是同类边界，所以**规范形式是字符串**。这里额外接受 JS 数字，
//! 是因为写 `bitflip.setComment(0x401000, "…")` 太自然了；但数字有 2^53 的
//! 精度上限，超出范围**必须报错**而不是悄悄截断 —— 一个被截断的地址会把注释
//! 写到另一个函数上，而且看起来完全正常。

use std::sync::{Arc, Mutex, MutexGuard};

use bitflip_core::{Annotation, AnnotationKind, Disasm, ProjectStore, Session};
use rquickjs::prelude::Opt;
use rquickjs::{Coerced, Ctx, Exception, Function, IntoJs, Object, Value};

use crate::error::ScriptError;
use crate::stage::StagedWrites;

/// 脚本 API 版本。
///
/// 与 `bitflip_core::CORE_API_VERSION`、`ANALYSIS_FORMAT_VERSION` **各管各的**：
/// 它们演进的节奏不同（wire 格式变一次，脚本 API 可能已经加了五个函数）。
/// 脚本通过 `bitflip.apiVersion` 读到它，用来判断自己能不能在新旧宿主上跑。
pub const SCRIPT_API_VERSION: u32 = 1;

/// JS 安全整数上限（2^53 - 1）。超过它的整数在 JS 里已经无法精确表示。
const JS_MAX_SAFE_INTEGER: f64 = 9_007_199_254_740_991.0;

/// 反汇编结果的提供者。
///
/// 用闭包而不是直接传 `Arc<Disasm>`：传值意味着"构造 `Host` 时必须先反汇编"，
/// 于是只写 `bitflip.log(1)` 的脚本也要等一次全量扫描。闭包让第一次真正需要
/// 指令的脚本才付这个代价。
pub type DisasmProvider = Arc<dyn Fn() -> Result<Arc<Disasm>, String> + Send + Sync>;

/// 日志级别。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LogLevel {
    /// `bitflip.log`
    Info,
    /// `bitflip.warn`
    Warn,
    /// `bitflip.error`
    Error,
}

impl LogLevel {
    /// 稳定的短名（wire 与 UI 共用）。
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Info => "info",
            Self::Warn => "warn",
            Self::Error => "error",
        }
    }
}

/// 脚本输出的一行日志。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ScriptLog {
    /// 级别。
    pub level: LogLevel,
    /// 内容。
    pub message: String,
}

/// 脚本上报的进度。
///
/// 只有脚本自己知道要做多少件事（遍历 5000 个函数、处理 12 个归档成员……），
/// 所以进度由脚本主动上报 —— 这与 IDA 的 `replace_wait_box` 是同一个设计：
/// 宿主无法凭空推断批处理进行到哪儿了。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ScriptProgress {
    /// 已完成的数量。
    pub done: u64,
    /// 总数；脚本也不知道时为 `None`（此时界面只能显示"进行中"）。
    pub total: Option<u64>,
    /// 当前在做什么（可空）。
    pub label: Option<String>,
}

/// 宿主内部状态。
pub(crate) struct HostState {
    pub(crate) store: Option<ProjectStore>,
    pub(crate) session: Option<Arc<Session>>,
    pub(crate) disasm: Option<DisasmProvider>,
    pub(crate) staged: StagedWrites,
    pub(crate) logs: Vec<ScriptLog>,
    pub(crate) progress: Option<ScriptProgress>,
}

/// 共享状态句柄。
///
/// `Arc<Mutex<_>>` 而不是 `Rc<RefCell<_>>`：脚本引擎本身是单线程的，但让
/// `Host` 保持 `Send` 能让服务层把它直接构造在 `spawn_blocking` 的闭包里，
/// 而"`Rc` 不能跨线程"这个限制会在增量 3 变成一个很难懂的编译错误。
/// 锁永远不会有竞争（同一个运行时只在一条线程上跑），代价可以忽略。
#[derive(Clone)]
pub(crate) struct Shared(Arc<Mutex<HostState>>);

impl Shared {
    /// 取状态。
    ///
    /// 中毒的锁直接取出里面的值：唯一会中毒的情形是宿主绑定 panic，而那种
    /// 情况下我们要的是"报告这个 panic"，不是让后续所有调用都跟着失败。
    pub(crate) fn lock(&self) -> MutexGuard<'_, HostState> {
        self.0
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }
}

/// 脚本宿主：读分析结论、暂存写入、收集日志。
///
/// `Clone` 是**共享**语义（内部 `Arc`），不是复制：脚本侧持有的句柄与调用方
/// 看到的是同一份暂存区。这一点必须成立，否则"脚本写了 N 条"与"提交了 N 条"
/// 会对不上。
#[derive(Clone)]
pub struct Host {
    state: Shared,
}

impl Host {
    /// 新建宿主。
    ///
    /// `store` 为 `None` 表示当前没有打开工程库 —— 此时**读**仍然可用（脚本能跑），
    /// 但一旦脚本尝试写入，提交阶段会明确报错，而不是假装成功。
    #[must_use]
    pub fn new(store: Option<ProjectStore>) -> Self {
        Self {
            state: Shared(Arc::new(Mutex::new(HostState {
                store,
                session: None,
                disasm: None,
                staged: StagedWrites::new(),
                logs: Vec::new(),
                progress: None,
            }))),
        }
    }

    /// 注入会话（读目标信息、读字节、构建分析结论）。
    #[must_use]
    pub fn with_session(self, session: Arc<Session>) -> Self {
        self.state.lock().session = Some(session);
        self
    }

    /// 注入反汇编结果的提供者。
    ///
    /// 不注入时 `bitflip.insns.*` 会明确报"本次会话没有反汇编结果"，
    /// 而不是返回空数组让脚本以为"这个目标没有指令"。
    #[must_use]
    pub fn with_disasm(self, provider: DisasmProvider) -> Self {
        self.state.lock().disasm = Some(provider);
        self
    }

    /// 注入工程库（覆盖 [`Host::new`] 时传入的那个）。
    ///
    /// 存在的意义是让构造顺序自由：调用方往往先拿会话再开工程库，
    /// 而 [`Host`] 是共享句柄（`Clone` 即同一份状态），后注入才能保证
    /// 脚本侧与调用方看到的是同一个库。
    #[must_use]
    pub fn with_project_store(self, store: ProjectStore) -> Self {
        self.state.lock().store = Some(store);
        self
    }

    /// 预热：把分析结论与反汇编提前算好，让它们**不计入**脚本的墙钟上限。
    ///
    /// # 为什么必须有这个入口
    ///
    /// ntdll.dll 的全量分析要 10.6 秒，而脚本默认上限是 5 秒。不预热的话，
    /// 第一个碰到 `bitflip.functions` 的脚本会报"脚本执行超时" —— 可这**不是
    /// 脚本的错**，用户会因此去改一段本来没问题的代码。调用方（服务层）应当
    /// 在跑脚本之前调用它，并在此期间显示"分析中"而不是"脚本超时"。
    ///
    /// 失败不致命：拿不到分析结论时读 API 会各自报出准确原因，脚本仍然可以跑
    /// （比如只做 `bitflip.log` 的脚本）。
    ///
    /// # Errors
    ///
    /// 返回第一次失败的原因（分析或反汇编）。调用方可以忽略它 —— 真正的错误
    /// 会在脚本真正用到那个能力时以异常形式浮出来。
    pub fn warmup(&self) -> Result<(), String> {
        let session = self.state.lock().session.clone();
        if let Some(session) = session {
            session
                .analysis(&session.detached_job())
                .map_err(|err| err.to_string())?;
        }

        let provider = self.state.lock().disasm.clone();
        if let Some(provider) = provider {
            provider()?;
        }
        Ok(())
    }

    /// 本次运行收集到的日志。
    #[must_use]
    pub fn logs(&self) -> Vec<ScriptLog> {
        self.state.lock().logs.clone()
    }

    /// 脚本上报的进度（脚本没上报过时为 `None`）。
    ///
    /// 服务层在脚本运行时轮询它，用来显示批处理进度；返回 `None` 时应当显示
    /// "进行中"而不是编一个百分比 —— 脚本没说过的事，宿主不该替它说。
    #[must_use]
    pub fn progress(&self) -> Option<ScriptProgress> {
        self.state.lock().progress.clone()
    }

    /// 暂存条数。
    #[must_use]
    pub fn staged_len(&self) -> usize {
        self.state.lock().staged.len()
    }

    /// 开始一次新的运行：清空日志、暂存与进度。
    ///
    /// 同一个 [`Host`] 会被反复用于多次运行（控制台里连着重放几次脚本），
    /// 所以每次运行必须从干净状态开始 —— 否则上一次的日志会混进这一次的结果，
    /// 上一次被丢弃的暂存也会莫名其妙地跟着这一次一起提交，
    /// 上一次的进度条会停在"80%"让用户以为这一次卡住了。
    pub fn begin_run(&self) {
        let mut state = self.state.lock();
        state.logs.clear();
        state.staged.clear();
        state.progress = None;
    }

    /// 丢弃全部暂存写入（中断或失败时调用）。
    pub fn discard(&self) {
        self.state.lock().staged.clear();
    }

    /// 把暂存写入提交到工程库，返回提交条数。
    ///
    /// 部分失败时返回 [`ScriptError::Commit`]，并如实报出"已写入多少"——
    /// 这是本操作唯一真正危险的结局，含糊其辞会让用户以为要么全成要么全不成。
    pub fn commit(&self, now_unix: u64) -> Result<usize, ScriptError> {
        let mut state = self.state.lock();
        let items = state.staged.take_all();
        let total = items.len();
        if total == 0 {
            return Ok(0);
        }

        let Some(store) = state.store.as_ref() else {
            return Err(ScriptError::Commit {
                committed: 0,
                total,
                reason: "当前没有打开工程库，脚本的写入无处可存".to_string(),
            });
        };

        // 失败时 `committed` 就是失败项的下标，也就是**已经写进去的条数** ——
        // 直接把索引当计数用，不必再手工维护一个计数器。
        for (committed, annotation) in items.iter().enumerate() {
            if let Err(err) = store.put(annotation, now_unix) {
                return Err(ScriptError::Commit {
                    committed,
                    total,
                    reason: err.to_string(),
                });
            }
        }
        Ok(total)
    }

    /// 把 `bitflip` 全局对象装进上下文。
    pub(crate) fn install(&self, ctx: &Ctx<'_>) -> rquickjs::Result<()> {
        let state = self.state.clone();
        let globals = ctx.globals();
        let bitflip = Object::new(ctx.clone())?;

        bitflip.set("apiVersion", SCRIPT_API_VERSION)?;

        {
            // 用 `Coerced<String>` 而不是 `String`：后者会**拒绝**非字符串参数，
            // 于是控制台里最自然的写法 `bitflip.log(count)` 会报
            // "Error converting from js 'int' into type 'string'"。
            // 日志函数应当像 `console.log` 一样接受任何值。
            let state = state.clone();
            bitflip.set(
                "log",
                Function::new(ctx.clone(), move |message: Coerced<String>| {
                    state.lock().logs.push(ScriptLog {
                        level: LogLevel::Info,
                        message: message.0,
                    });
                })?,
            )?;
        }
        {
            let state = state.clone();
            bitflip.set(
                "warn",
                Function::new(ctx.clone(), move |message: Coerced<String>| {
                    state.lock().logs.push(ScriptLog {
                        level: LogLevel::Warn,
                        message: message.0,
                    });
                })?,
            )?;
        }
        {
            let state = state.clone();
            bitflip.set(
                "error",
                Function::new(ctx.clone(), move |message: Coerced<String>| {
                    state.lock().logs.push(ScriptLog {
                        level: LogLevel::Error,
                        message: message.0,
                    });
                })?,
            )?;
        }

        {
            let state = state.clone();
            bitflip.set(
                "setName",
                Function::new(
                    ctx.clone(),
                    move |ctx: Ctx<'_>, address: Value<'_>, text: String| -> rquickjs::Result<()> {
                        let address = parse_address(&ctx, &address)?;
                        state.lock().staged.stage(Annotation::text(
                            address,
                            AnnotationKind::Name,
                            text,
                        ));
                        Ok(())
                    },
                )?,
            )?;
        }
        {
            let state = state.clone();
            bitflip.set(
                "setComment",
                Function::new(
                    ctx.clone(),
                    move |ctx: Ctx<'_>, address: Value<'_>, text: String| -> rquickjs::Result<()> {
                        let address = parse_address(&ctx, &address)?;
                        state.lock().staged.stage(Annotation::text(
                            address,
                            AnnotationKind::Comment,
                            text,
                        ));
                        Ok(())
                    },
                )?,
            )?;
        }

        {
            let state = state.clone();
            bitflip.set(
                "get",
                Function::new(
                    ctx.clone(),
                    move |ctx: Ctx<'_>,
                          address: Value<'_>,
                          kind: String|
                          -> rquickjs::Result<AnnotationText> {
                        let address = parse_address(&ctx, &address)?;
                        let kind = parse_kind(&ctx, &kind)?;
                        let state = state.lock();
                        // 先看暂存，再看工程库：脚本必须能读到自己刚写的东西，
                        // 否则"没有名字才命名"这类脚本会重复劳动。
                        if let Some(a) = state.staged.get(address, kind) {
                            return Ok(AnnotationText(a.text.clone()));
                        }
                        Ok(AnnotationText(
                            state
                                .store
                                .as_ref()
                                .and_then(|s| s.get(address, kind))
                                .and_then(|a| a.text),
                        ))
                    },
                )?,
            )?;
        }

        {
            let state = state.clone();
            bitflip.set(
                "stagedCount",
                Function::new(ctx.clone(), move || -> usize { state.lock().staged.len() })?,
            )?;
        }

        {
            // 进度必须是脚本**主动**上报的：只有脚本知道总共要做多少件事。
            // 宿主凭空推断（比如按已暂存条数估）会在"这一轮不写任何东西"的
            // 阶段停住不动，看起来像卡死。
            let state = state.clone();
            bitflip.set(
                "progress",
                Function::new(
                    ctx.clone(),
                    move |done: u64, total: Opt<u64>, label: Opt<String>| {
                        state.lock().progress = Some(ScriptProgress {
                            done,
                            total: total.0,
                            label: label.0,
                        });
                    },
                )?,
            )?;
        }

        crate::read::install(ctx, &state, &bitflip)?;

        globals.set("bitflip", bitflip)?;
        Ok(())
    }
}

/// 一次标注查询的结果，映射到 JS 时：有值 → 字符串，无值 → `null`。
///
/// 为什么不直接用 `Option<String>`：`Option::into_js` 把 `None` 映射成
/// `undefined`。在 JS 里 `undefined` 通常意味着"你取错了键"，而"这个地址还没有
/// 标注"是**合法的预期结果**，两者不该长得一样。
///
/// 为什么不直接让闭包返回 `Value<'js>`：`Value<'js>` 对 `'js` 是**不变量**，
/// 而 `Function::new` 的闭包无法把入参 `Ctx<'js>` 与返回值绑定到同一个 `'js`
/// 上（会报 `lifetime may not live long enough`）。用一个具体的 Rust 类型
/// 走 `IntoJs` 就没有这个问题，顺带把语义写在了类型名上。
struct AnnotationText(Option<String>);

impl<'js> IntoJs<'js> for AnnotationText {
    fn into_js(self, ctx: &Ctx<'js>) -> rquickjs::Result<Value<'js>> {
        match self.0 {
            Some(text) => text.into_js(ctx),
            None => Ok(Value::new_null(ctx.clone())),
        }
    }
}

/// 解析脚本传来的地址：定长十六进制字符串（规范）或 JS 安全整数。
pub(crate) fn parse_address(ctx: &Ctx<'_>, value: &Value<'_>) -> rquickjs::Result<u64> {
    if value.is_string() {
        let raw: String = value.get()?;
        return bitflip_core::parse_address(&raw).ok_or_else(|| {
            Exception::throw_message(
                ctx,
                &format!(
                    "地址无法解析：{raw:?}；需要 16 进制字符串（如 \"0000000000401000\" 或 \"0x401000\"）"
                ),
            )
        });
    }

    if value.is_number() {
        let number: f64 = value.get()?;
        if !number.is_finite() || number < 0.0 || number.fract() != 0.0 {
            return Err(Exception::throw_message(
                ctx,
                &format!("地址必须是整数，收到 {number}"),
            ));
        }
        if number > JS_MAX_SAFE_INTEGER {
            // 到了这里精度已经丢了，但**必须报错**：静默截断会把注释写到
            // 另一个函数上，而结果是"看起来完全正常"的。
            return Err(Exception::throw_message(
                ctx,
                "地址超过 JavaScript 安全整数范围（2^53-1）；请改用 16 进制字符串",
            ));
        }
        return Ok(number as u64);
    }

    Err(Exception::throw_message(
        ctx,
        "地址必须是 16 进制字符串或整数",
    ))
}

/// 解析标注类别。
///
/// 未知取值**报错并列出可用值**，不静默回退到某个默认类别 ——
/// 那会把用户的名字当成注释存进去（与 `AnnotationKind::parse` 的约定一致）。
pub(crate) fn parse_kind(ctx: &Ctx<'_>, raw: &str) -> rquickjs::Result<AnnotationKind> {
    AnnotationKind::parse(raw).ok_or_else(|| {
        Exception::throw_message(
            ctx,
            &format!(
                "未知的标注类别：{raw:?}；可用：name / comment / type / bookmark / function-boundary / code-data"
            ),
        )
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn log_levels_have_stable_short_names() {
        assert_eq!(LogLevel::Info.as_str(), "info");
        assert_eq!(LogLevel::Warn.as_str(), "warn");
        assert_eq!(LogLevel::Error.as_str(), "error");
    }

    #[test]
    fn a_host_without_a_project_store_says_so_instead_of_pretending() {
        let host = Host::new(None);
        // 没有暂存时没什么可提交，不算错
        assert_eq!(host.commit(0).expect("空提交应当成功"), 0);

        // 有暂存但没有工程库：必须报错，而且要报出"0/total"
        host.state
            .lock()
            .staged
            .stage(Annotation::text(0x1000, AnnotationKind::Name, "x"));
        let err = host.commit(0).unwrap_err();
        assert_eq!(err.committed_writes(), Some((0, 1)));
    }

    #[test]
    fn discarding_leaves_nothing_to_commit() {
        let host = Host::new(None);
        host.state
            .lock()
            .staged
            .stage(Annotation::text(0x1000, AnnotationKind::Name, "x"));
        host.discard();
        assert_eq!(host.staged_len(), 0);
        assert_eq!(host.commit(0).expect("丢弃后提交应当无事可做"), 0);
    }
}
