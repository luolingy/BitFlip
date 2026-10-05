//! 脚本的宿主侧：`bitflip` 全局对象与写入暂存。
//!
//! # 地址在脚本里也是字符串
//!
//! CLAUDE.md §4 要求"内部一律 `u64`，跨进程 wire 上统一定长小写 16 位十六进制"。
//! 脚本边界是同类边界，所以**规范形式是字符串**。这里额外接受 JS 数字，
//! 是因为写 `bitflip.setComment(0x401000, "…")` 太自然了；但数字有 2^53 的
//! 精度上限，超出范围**必须报错**而不是悄悄截断 —— 一个被截断的地址会把注释
//! 写到另一个函数上，而且看起来完全正常。

use std::cell::RefCell;
use std::rc::Rc;

use bitflip_core::{Annotation, AnnotationKind, ProjectStore};
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

/// 宿主内部状态（被 JS 闭包与调用方共享）。
pub(crate) struct HostState {
    pub(crate) store: Option<ProjectStore>,
    pub(crate) staged: StagedWrites,
    pub(crate) logs: Vec<ScriptLog>,
}

/// 脚本宿主：读工程库、暂存写入、收集日志。
///
/// `Clone` 是**共享**语义（内部 `Rc`），不是复制：脚本侧持有的句柄与调用方
/// 看到的是同一份暂存区。这一点必须成立，否则"脚本写了 N 条"与"提交了 N 条"
/// 会对不上。
#[derive(Clone)]
pub struct Host {
    state: Rc<RefCell<HostState>>,
}

impl Host {
    /// 新建宿主。
    ///
    /// `store` 为 `None` 表示当前没有打开工程库 —— 此时**读**仍然可用（脚本能跑），
    /// 但一旦脚本尝试写入，提交阶段会明确报错，而不是假装成功。
    #[must_use]
    pub fn new(store: Option<ProjectStore>) -> Self {
        Self {
            state: Rc::new(RefCell::new(HostState {
                store,
                staged: StagedWrites::new(),
                logs: Vec::new(),
            })),
        }
    }

    /// 本次运行收集到的日志。
    #[must_use]
    pub fn logs(&self) -> Vec<ScriptLog> {
        self.state.borrow().logs.clone()
    }

    /// 开始一次新的运行：清空日志与暂存。
    ///
    /// 同一个 [`Host`] 会被反复用于多次运行（控制台里连着重放几次脚本），
    /// 所以每次运行必须从干净状态开始 —— 否则上一次的日志会混进这一次的结果，
    /// 上一次被丢弃的暂存也会莫名其妙地跟着这一次一起提交。
    pub fn begin_run(&self) {
        let mut state = self.state.borrow_mut();
        state.logs.clear();
        state.staged.clear();
    }

    /// 暂存条数。
    #[must_use]
    pub fn staged_len(&self) -> usize {
        self.state.borrow().staged.len()
    }

    /// 丢弃全部暂存写入（中断或失败时调用）。
    pub fn discard(&self) {
        self.state.borrow_mut().staged.clear();
    }

    /// 把暂存写入提交到工程库，返回提交条数。
    ///
    /// 部分失败时返回 [`ScriptError::Commit`]，并如实报出"已写入多少"——
    /// 这是本操作唯一真正危险的结局，含糊其辞会让用户以为要么全成要么全不成。
    pub fn commit(&self, now_unix: u64) -> Result<usize, ScriptError> {
        let mut state = self.state.borrow_mut();
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
        let state = Rc::clone(&self.state);
        let globals = ctx.globals();
        let bitflip = Object::new(ctx.clone())?;

        bitflip.set("apiVersion", SCRIPT_API_VERSION)?;

        {
            // 用 `Coerced<String>` 而不是 `String`：后者会**拒绝**非字符串参数，
            // 于是控制台里最自然的写法 `bitflip.log(count)` 会报
            // "Error converting from js 'int' into type 'string'"。
            // 日志函数应当像 `console.log` 一样接受任何值。
            let state = Rc::clone(&state);
            bitflip.set(
                "log",
                Function::new(ctx.clone(), move |message: Coerced<String>| {
                    state.borrow_mut().logs.push(ScriptLog {
                        level: LogLevel::Info,
                        message: message.0,
                    });
                })?,
            )?;
        }
        {
            let state = Rc::clone(&state);
            bitflip.set(
                "warn",
                Function::new(ctx.clone(), move |message: Coerced<String>| {
                    state.borrow_mut().logs.push(ScriptLog {
                        level: LogLevel::Warn,
                        message: message.0,
                    });
                })?,
            )?;
        }
        {
            let state = Rc::clone(&state);
            bitflip.set(
                "error",
                Function::new(ctx.clone(), move |message: Coerced<String>| {
                    state.borrow_mut().logs.push(ScriptLog {
                        level: LogLevel::Error,
                        message: message.0,
                    });
                })?,
            )?;
        }

        {
            let state = Rc::clone(&state);
            bitflip.set(
                "setName",
                Function::new(
                    ctx.clone(),
                    move |ctx: Ctx<'_>, address: Value<'_>, text: String| -> rquickjs::Result<()> {
                        let address = parse_address(&ctx, &address)?;
                        state.borrow_mut().staged.stage(Annotation::text(
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
            let state = Rc::clone(&state);
            bitflip.set(
                "setComment",
                Function::new(
                    ctx.clone(),
                    move |ctx: Ctx<'_>, address: Value<'_>, text: String| -> rquickjs::Result<()> {
                        let address = parse_address(&ctx, &address)?;
                        state.borrow_mut().staged.stage(Annotation::text(
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
            let state = Rc::clone(&state);
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
                        let state = state.borrow();
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
            let state = Rc::clone(&state);
            bitflip.set(
                "stagedCount",
                Function::new(ctx.clone(), move || -> usize {
                    state.borrow().staged.len()
                })?,
            )?;
        }

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
fn parse_address(ctx: &Ctx<'_>, value: &Value<'_>) -> rquickjs::Result<u64> {
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
fn parse_kind(ctx: &Ctx<'_>, raw: &str) -> rquickjs::Result<AnnotationKind> {
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
            .borrow_mut()
            .staged
            .stage(Annotation::text(0x1000, AnnotationKind::Name, "x"));
        let err = host.commit(0).unwrap_err();
        assert_eq!(err.committed_writes(), Some((0, 1)));
    }

    #[test]
    fn discarding_leaves_nothing_to_commit() {
        let host = Host::new(None);
        host.state
            .borrow_mut()
            .staged
            .stage(Annotation::text(0x1000, AnnotationKind::Name, "x"));
        host.discard();
        assert_eq!(host.staged_len(), 0);
        assert_eq!(host.commit(0).expect("丢弃后提交应当无事可做"), 0);
    }
}
