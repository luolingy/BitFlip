//! `bitflip-script` —— BitFlip 的脚本层。
//!
//! 引擎选型见 `docs/DECISIONS.md` ADR-0013（rquickjs / QuickJS），
//! 实测依据见 `docs/D1-SCRIPT-ENGINE-ANALYSIS.md`。
//!
//! # 分层
//!
//! ```text
//! cli/app → server → bitflip-script → core → {loader, arch, analyze, symbols, project}
//! ```
//!
//! 脚本层在 `core` **之上**（它要用 core 的公开契约），在 `server` **之下**
//! （HTTP 层只负责把它接到端点上）。不得反向依赖。
//!
//! # 安全边界：这里**不是**沙箱
//!
//! ADR-0013 明确要求这句话不能被含糊掉：脚本在**宿主进程内**执行，
//! QuickJS 的缺陷就是宿主进程的内存安全问题。本 crate 能承诺的是：
//!
//! - 死循环脚本会被**墙钟超时**掐断（[`Limits::timeout`]），
//!   或被外部通过 [`CancelToken`] 主动中断；
//! - 脚本抛异常或触发 panic 不会让宿主进程退出；
//! - 被中断的脚本**不会留下写了一半的标注**（[`Host`] 的暂存区语义）。
//!
//! 本 crate **不能**承诺的是：安全地执行不可信的第三方脚本。M7 不具备这个
//! 能力，界面与文档都不许暗示具备。
//!
//! # 两种版本号，各管各的
//!
//! - [`SCRIPT_API_VERSION`]：脚本看到的 `bitflip.*` 接口版本；
//! - `bitflip_core::CORE_API_VERSION` / `ANALYSIS_FORMAT_VERSION`：Rust 嵌入方
//!   与 wire 格式的版本。
//!
//! 它们演进节奏不同，所以**不合并**。脚本要判断自己能不能跑，看前者；
//! 嵌入方要判断数据格式，看后者。

mod builtin;
mod engine;
mod error;
mod host;
mod js;
mod read;
mod stage;
pub use builtin::{builtin_script, builtin_scripts, BuiltinScript};
pub use engine::{CancelToken, Limits, ScriptEngine, ScriptOutcome};
pub use error::ScriptError;
pub use host::{DisasmProvider, Host, LogLevel, ScriptLog, ScriptProgress, SCRIPT_API_VERSION};
pub use stage::StagedWrites;

/// 脚本 API 中 `bitflip` 全局对象的名字。
///
/// 单独导出是为了让文档、UI 提示与测试引用同一个常量，而不是各写一遍字符串。
pub const GLOBAL_NAME: &str = "bitflip";
