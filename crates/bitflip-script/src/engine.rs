//! 脚本引擎：运行时生命周期、墙钟超时、错误映射。
//!
//! # 中断是怎么做到的
//!
//! QuickJS 支持注册一个"中断回调"，解释器每隔若干条指令问它一次
//! "要不要停"。回调返回 `true` 即中止执行并抛出异常。这里把回调实现成
//! **墙钟截止时间比较**，于是"用户点了停止"和"脚本跑太久"变成同一件事。
//!
//! 三个候选引擎实测都能中断死循环，所以这不是选型的区分点（见
//! `docs/D1-SCRIPT-ENGINE-ANALYSIS.md` §3）；真正的区别是中断后**留下什么** ——
//! 这里保证一条都不留（见 [`crate::stage`]）。

use std::panic::{catch_unwind, AssertUnwindSafe};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use rquickjs::{Context, Ctx, Error, Exception, Runtime};

use crate::error::ScriptError;
use crate::host::{Host, ScriptLog};

/// 求值时使用的文件名。
///
/// 必须给一个名字：不给的话 stack 里只有 `<eval>` 没有位置，
/// 用户报"第 3 行错了"就无从核对。给了名字，stack 里就是 `script.js:3:5`。
const SCRIPT_FILENAME: &str = "script.js";

/// 沙箱限制。
#[derive(Debug, Clone)]
pub struct Limits {
    /// 单次脚本执行的墙钟上限。
    ///
    /// 默认 5 秒：足够跑完一次几千个函数的批处理，又不至于让用户对着
    /// 卡住的界面猜是不是死了。
    pub timeout: Duration,
}

impl Default for Limits {
    fn default() -> Self {
        Self {
            timeout: Duration::from_secs(5),
        }
    }
}

/// 一次成功运行的结果。
#[derive(Debug, Clone)]
pub struct ScriptOutcome {
    /// 脚本输出的日志。
    pub logs: Vec<ScriptLog>,
    /// 真正提交到工程库的写入条数。
    pub committed: usize,
}

/// 脚本引擎。
///
/// 一个实例可以反复运行脚本：每次运行都用**全新的 Context**，脚本之间不共享
/// 全局变量。这一点是有意的 —— 上一个脚本留下的全局状态污染下一个脚本，
/// 会让"为什么单独跑没事、连着跑就错"变成一场噩梦。
pub struct ScriptEngine {
    runtime: Runtime,
    limits: Limits,
    deadline: Arc<Mutex<Instant>>,
    timed_out: Arc<AtomicBool>,
}

impl ScriptEngine {
    /// 新建引擎。
    pub fn new(limits: Limits) -> Result<Self, ScriptError> {
        let runtime = Runtime::new().map_err(|err| ScriptError::Engine {
            message: format!("无法创建 QuickJS 运行时：{err}"),
        })?;

        let deadline = Arc::new(Mutex::new(Instant::now()));
        let timed_out = Arc::new(AtomicBool::new(false));

        {
            let deadline = Arc::clone(&deadline);
            let timed_out = Arc::clone(&timed_out);
            runtime.set_interrupt_handler(Some(Box::new(move || {
                if timed_out.load(Ordering::Relaxed) {
                    return true;
                }
                let expired = Instant::now()
                    >= *deadline
                        .lock()
                        .unwrap_or_else(std::sync::PoisonError::into_inner);
                if expired {
                    // 记下来，好在事后区分"超时"与"脚本自己抛异常" ——
                    // 两者给用户的建议完全不同。
                    timed_out.store(true, Ordering::Relaxed);
                }
                expired
            })));
        }

        Ok(Self {
            runtime,
            limits,
            deadline,
            timed_out,
        })
    }

    /// 上限配置。
    #[must_use]
    pub const fn limits(&self) -> &Limits {
        &self.limits
    }

    /// 运行一段脚本。
    ///
    /// 语义（按 PLAN §M7 验收 2）：
    ///
    /// - 正常结束 → 提交全部暂存写入，返回 [`ScriptOutcome`]；
    /// - 超时 / 抛异常 / panic → **丢弃全部暂存写入**并返回错误。
    ///
    /// 不存在"写了一半"的结局（除了提交阶段本身失败，那时会如实报出
    /// [`ScriptError::Commit`] 的已写条数）。
    pub fn run(&self, host: &Host, source: &str) -> Result<ScriptOutcome, ScriptError> {
        let started = Instant::now();
        *self
            .deadline
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner) = started + self.limits.timeout;
        self.timed_out.store(false, Ordering::Relaxed);
        host.begin_run();

        let context = Context::full(&self.runtime).map_err(|err| ScriptError::Engine {
            message: format!("无法创建脚本上下文：{err}"),
        })?;

        // panic 会被兜住：脚本层位于 FFI 边界上，一个宿主绑定的 bug 不该
        // 让整个进程退出（CLAUDE.md §4）。这是防御性分支，正常脚本走不到。
        let outcome = catch_unwind(AssertUnwindSafe(|| {
            context.with(|ctx| self.eval(&ctx, host, source))
        }));

        match outcome {
            Ok(Ok(())) => {
                let logs = host.logs();
                let committed = host.commit(now_unix())?;
                Ok(ScriptOutcome { logs, committed })
            }
            Ok(Err(err)) => {
                host.discard();
                Err(err)
            }
            Err(panic) => {
                host.discard();
                Err(ScriptError::Panic {
                    message: panic_message(&panic),
                })
            }
        }
    }

    /// 在给定上下文里求值，并把引擎错误就地翻译成 [`ScriptError`]。
    ///
    /// 必须在 `with` 闭包**内部**翻译：`Error::Exception` 的实际异常值要通过
    /// `Ctx::catch()` 取，而 `Ctx` 出了闭包就没了。
    fn eval(&self, ctx: &Ctx<'_>, host: &Host, source: &str) -> Result<(), ScriptError> {
        if let Err(err) = host.install(ctx) {
            return Err(self.map_error(ctx, err));
        }

        // `EvalOptions` 是 `#[non_exhaustive]`，不能整体构造，只能先取默认再改。
        // 默认值本身是 global + strict，正好是想要的：严格模式能让脚本里的
        // 拼写错误尽早暴露，而不是悄悄创建一个全局变量。
        let mut options = rquickjs::context::EvalOptions::default();
        options.filename = Some(SCRIPT_FILENAME.to_string());

        match ctx.eval_with_options::<(), _>(source, options) {
            Ok(()) => Ok(()),
            Err(err) => Err(self.map_error(ctx, err)),
        }
    }

    /// 把引擎错误翻译成面向人的 [`ScriptError`]。
    fn map_error(&self, ctx: &Ctx<'_>, err: Error) -> ScriptError {
        // 超时优先判定：中断回调抛出的也是异常，但它的成因是宿主掐断的，
        // 不该被报成"脚本运行错误"让用户去改脚本。
        if self.timed_out.load(Ordering::Relaxed) {
            return ScriptError::Timeout {
                limit: self.limits.timeout,
            };
        }

        if matches!(err, Error::Exception) {
            if let Some(described) = describe_exception(ctx) {
                return described;
            }
        }

        ScriptError::Engine {
            message: err.to_string(),
        }
    }
}

/// 读取当前异常的细节。
fn describe_exception(ctx: &Ctx<'_>) -> Option<ScriptError> {
    let value = ctx.catch();
    let object = value.as_object()?;
    let exception = Exception::from_object(object.clone())?;

    let message = exception
        .message()
        .unwrap_or_else(|| "<异常无消息>".to_string());
    let stack = exception.stack();
    // 先看 stack 再退回 message：QuickJS 不在错误对象上放 lineNumber
    // （实测确认，`lineNumber` 只是 Function.prototype 的遗留 getter），
    // 位置只能从 stack 的 `文件名:行:列` 里取。
    let line = stack
        .as_deref()
        .and_then(extract_line)
        .or_else(|| extract_line(&message));

    let name: Option<String> = object.get("name").ok();
    let is_syntax = name.as_deref() == Some("SyntaxError");

    Some(if is_syntax {
        ScriptError::Syntax { message, line }
    } else {
        ScriptError::Runtime {
            message,
            line,
            stack,
        }
    })
}

/// 从 `…/script.js:行:列` 这类文本里取出**最靠前**的行号。
///
/// 取第一个而不是最后一个：stack 里靠前的是最内层帧，也就是真正出错的位置；
/// 靠后的是求值入口。取最后一个会把行号报成"调用发生的那一行"。
fn extract_line(text: &str) -> Option<u32> {
    let bytes = text.as_bytes();
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] != b':' {
            i += 1;
            continue;
        }
        let start = i + 1;
        let mut end = start;
        while end < bytes.len() && bytes[end].is_ascii_digit() {
            end += 1;
        }
        // 形态必须是 `:<数字>:`，避免把 "12:30" 这类无关文本当成行号
        if end > start && end < bytes.len() && bytes[end] == b':' {
            if let Ok(n) = text[start..end].parse::<u32>() {
                return Some(n);
            }
        }
        i = end.max(i + 1);
    }
    None
}

/// 提取 panic 的说明文本。
fn panic_message(panic: &Box<dyn std::any::Any + Send>) -> String {
    if let Some(s) = panic.downcast_ref::<&str>() {
        (*s).to_string()
    } else if let Some(s) = panic.downcast_ref::<String>() {
        s.clone()
    } else {
        "未知 panic 载荷".to_string()
    }
}

/// 当前 Unix 时间（秒）。
fn now_unix() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn line_numbers_are_taken_from_the_innermost_frame() {
        let stack = "    at boom (script.js:10:3)\n    at <eval> (script.js:3:5)";
        assert_eq!(
            extract_line(stack),
            Some(10),
            "最内层帧才是出错位置；取最后一个会把行号报成调用点"
        );
    }

    #[test]
    fn a_single_frame_still_yields_its_line() {
        assert_eq!(extract_line("    at <eval> (script.js:7:1)"), Some(7));
    }

    #[test]
    fn text_without_a_position_yields_nothing_rather_than_a_made_up_line() {
        assert_eq!(extract_line("ReferenceError: x is not defined"), None);
        // "12:30" 不是位置，不能被当成行号
        assert_eq!(extract_line("meeting at 12:30"), None);
        assert_eq!(extract_line(""), None);
    }
}
