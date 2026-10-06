//! 脚本引擎：运行时生命周期、墙钟超时、外部取消、错误映射。
//!
//! # 中断是怎么做到的
//!
//! QuickJS 支持注册一个"中断回调"，解释器每隔若干条指令问它一次
//! "要不要停"。回调返回 `true` 即中止执行并抛出异常。这里把回调实现成
//! **墙钟截止时间比较 + 一个取消标志**，于是"用户点了停止"和"脚本跑太久"
//! 在中断这一层是同一件事，只在**报错**那一层分开成
//! [`ScriptError::Cancelled`] 与 [`ScriptError::Timeout`] ——
//! 两者的成因与建议完全不同。
//!
//! 三个候选引擎实测都能中断死循环，所以这不是选型的区分点（见
//! `docs/D1-SCRIPT-ENGINE-ANALYSIS.md` §3）；真正的区别是中断后**留下什么** ——
//! 这里保证一条都不留（见 [`crate::stage`]）。

use std::panic::{catch_unwind, AssertUnwindSafe};
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
    /// 本次运行**尝试**提交的条数（去重后）。
    ///
    /// 正常路径下等于 `committed`；带上它是因为没有打开工程库时
    /// `committed` 会是 0 —— 只报 0 会让界面显示"什么都没做"，
    /// 而真相是"脚本写了 N 条，但没地方存"。
    pub staged: usize,
}

/// 一次运行的共享状态。
///
/// 超时、取消、运行中标志放在**同一把锁**里，是为了让"外部请求取消"与
/// "开始新一次运行时的重置"不可能交错：两者都必须先拿到这把锁。否则会出现
/// 用户点了停止、而那个请求恰好落进下一次运行的窗口里，把刚启动的脚本掐掉。
#[derive(Debug)]
struct RunControl {
    /// 本次运行的墙钟截止时间。
    deadline: Instant,
    /// 是否已有脚本在跑（决定取消请求是否被接受）。
    running: bool,
    /// 是否因为超时被掐断（用于事后区分超时与脚本自身的异常）。
    timed_out: bool,
    /// 是否收到了外部取消请求。
    cancelled: bool,
}

/// 外部取消令牌。
///
/// 由 [`ScriptEngine::cancel_token`] 取得，可以交给另一个线程（服务层的取消
/// 端点）持有。取消请求只对**正在运行的那一次**有效：没有脚本在跑时
/// [`CancelToken::cancel`] 返回 `false` 并忽略请求，不会影响下一次运行。
#[derive(Debug, Clone)]
pub struct CancelToken {
    control: Arc<Mutex<RunControl>>,
}

impl CancelToken {
    /// 请求中断当前正在运行的脚本。
    ///
    /// 返回 `false` 表示当前没有脚本在运行，请求被忽略。调用方应当据此告知
    /// 用户"没有可取消的运行"，而不是显示"已取消"却什么也没发生。
    pub fn cancel(&self) -> bool {
        let mut control = lock(&self.control);
        if !control.running {
            return false;
        }
        control.cancelled = true;
        true
    }

    /// 是否已有脚本在跑。
    #[must_use]
    pub fn is_running(&self) -> bool {
        lock(&self.control).running
    }
}

/// 脚本引擎。
///
/// 一个实例可以反复运行脚本：每次运行都用**全新的 Context**，脚本之间不共享
/// 全局变量。这一点是有意的 —— 上一个脚本留下的全局状态污染下一个脚本，
/// 会让"为什么单独跑没事、连着跑就错"变成一场噩梦。
pub struct ScriptEngine {
    runtime: Runtime,
    limits: Limits,
    control: Arc<Mutex<RunControl>>,
}

/// 取锁，忽略中毒。
///
/// 中毒发生在"持锁线程 panic"之后，而脚本层的 panic 已经被 `catch_unwind`
/// 兜住并转成错误 —— 此时让后续调用继续工作，比连锁失败更有用；状态本身也
/// 只是几个标量，不会处于半更新的不一致形态。
fn lock<T>(mutex: &Mutex<T>) -> std::sync::MutexGuard<'_, T> {
    mutex
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
}

impl ScriptEngine {
    /// 新建引擎。
    pub fn new(limits: Limits) -> Result<Self, ScriptError> {
        let runtime = Runtime::new().map_err(|err| ScriptError::Engine {
            message: format!("无法创建 QuickJS 运行时：{err}"),
        })?;

        let control = Arc::new(Mutex::new(RunControl {
            deadline: Instant::now(),
            running: false,
            timed_out: false,
            cancelled: false,
        }));

        {
            let control = Arc::clone(&control);
            runtime.set_interrupt_handler(Some(Box::new(move || {
                let mut control = lock(&control);
                if control.cancelled || control.timed_out {
                    return true;
                }
                let expired = Instant::now() >= control.deadline;
                if expired {
                    // 记下来，好在事后区分"超时"与"脚本自己抛异常" ——
                    // 两者给用户的建议完全不同。
                    control.timed_out = true;
                }
                expired
            })));
        }

        Ok(Self {
            runtime,
            limits,
            control,
        })
    }

    /// 取一个取消令牌。
    ///
    /// 同一个引擎可以取多个令牌（都指向同一份运行状态），交给关心取消的
    /// 那个线程即可。
    #[must_use]
    pub fn cancel_token(&self) -> CancelToken {
        CancelToken {
            control: Arc::clone(&self.control),
        }
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
    /// - 超时 / 被取消 / 抛异常 / panic → **丢弃全部暂存写入**并返回错误。
    ///
    /// 不存在"写了一半"的结局（除了提交阶段本身失败，那时会如实报出
    /// [`ScriptError::Commit`] 的已写条数）。
    pub fn run(&self, host: &Host, source: &str) -> Result<ScriptOutcome, ScriptError> {
        let context = {
            // 重置与"标记运行中"在同一把锁内完成，取消请求不可能挤进两者之间。
            let mut control = lock(&self.control);
            control.deadline = Instant::now() + self.limits.timeout;
            control.timed_out = false;
            control.cancelled = false;
            control.running = true;

            Context::full(&self.runtime).map_err(|err| ScriptError::Engine {
                message: format!("无法创建脚本上下文：{err}"),
            })?
        };

        host.begin_run();

        // panic 会被兜住：脚本层位于 FFI 边界上，一个宿主绑定的 bug 不该
        // 让整个进程退出（CLAUDE.md §4）。这是防御性分支，正常脚本走不到。
        let outcome = catch_unwind(AssertUnwindSafe(|| {
            context.with(|ctx| self.eval(&ctx, host, source))
        }));

        // 运行期间在闭包内求值，所以这里释放"运行中"标志要放在**所有**
        // 出口上（含 panic 分支）—— 否则一次 panic 会让取消端点永远认为
        // 还有脚本在跑，用户再也点不动停止。
        let verdict = match outcome {
            Ok(Ok(())) => {
                let logs = host.logs();
                let staged = host.staged_len();
                let commit = host.commit(now_unix());
                commit.map(|committed| ScriptOutcome {
                    logs,
                    committed,
                    staged,
                })
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
        };

        lock(&self.control).running = false;
        verdict
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
        let (cancelled, timed_out) = {
            let control = lock(&self.control);
            (control.cancelled, control.timed_out)
        };

        // 取消优先于超时：两者都由中断回调触发，但用户按了停止的时候报"超时"
        // 会让人以为自己需要去优化脚本。用户自己按的，就得如实说是被取消的。
        if cancelled {
            return ScriptError::Cancelled;
        }
        // 中断回调抛出的也是异常，但成因是宿主掐断的，不该被报成"脚本运行错误"
        // 让用户去改脚本。
        if timed_out {
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
