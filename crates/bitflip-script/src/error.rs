//! 脚本层的错误类型。
//!
//! 设计原则（CLAUDE.md §7）：**每一种失败都要能被人读懂，并且说清楚它属于哪一类**。
//! 尤其是"超时"与"脚本自己抛异常"必须区分 —— 前者是宿主掐断的，后者是脚本的 bug，
//! 用户要做的处理完全不同。

use std::time::Duration;

/// 脚本执行的失败。
#[derive(Debug, thiserror::Error)]
pub enum ScriptError {
    /// 脚本超过墙钟上限，被宿主中断。
    ///
    /// 注意文案里要说明暂存写入已被丢弃：用户看到"超时"之后第一个问题就是
    /// "那我脚本前半段写的注释还在吗"。
    #[error("脚本执行超过 {limit:?} 上限，已被中断；本次运行暂存的写入已全部丢弃")]
    Timeout {
        /// 配置的上限。
        limit: Duration,
    },

    /// 脚本被**外部请求**中断（用户点了停止）。
    ///
    /// 与 [`Self::Timeout`] 分开是刻意的：两者都由中断回调触发，但成因和建议
    /// 完全不同 —— 超时意味着"把脚本写得更省一点或者提高上限"，取消意味着
    /// "你自己按的，脚本没问题"。合并成一个分支会让用户对着一条超时提示去改
    /// 一段本来没问题的代码。
    #[error("脚本已被取消；本次运行暂存的写入已全部丢弃")]
    Cancelled,

    /// 语法错误（脚本还没开始跑就被拒了）。
    #[error("脚本语法错误{}：{message}", .line.map(|l| format!("（第 {l} 行）")).unwrap_or_default())]
    Syntax {
        /// 引擎给出的说明。
        message: String,
        /// 行号（拿不到时为 `None` —— 不编一个 1 出来）。
        line: Option<u32>,
    },

    /// 运行期异常，包括脚本自己 `throw`。
    #[error("脚本运行错误{}：{message}", .line.map(|l| format!("（第 {l} 行）")).unwrap_or_default())]
    Runtime {
        /// 异常消息。
        message: String,
        /// 行号（拿不到时为 `None`）。
        line: Option<u32>,
        /// 原始 stack（拿不到时为 `None`）。
        stack: Option<String>,
    },

    /// 脚本调用宿主 API 的方式不对（地址无法解析、类别拼错……）。
    #[error("脚本调用宿主 API 出错：{message}")]
    Host {
        /// 面向用户的说明。
        message: String,
    },

    /// 脚本执行过程中触发了 Rust panic，被 `catch_unwind` 兜住。
    ///
    /// 这是**防御性**分支：正常脚本不该走到这里。一旦出现，说明宿主绑定有 bug，
    /// 而不是用户脚本写错了 —— 文案必须把这一点说清楚，否则用户会去改自己的脚本。
    #[error("宿主内部错误（脚本触发了 Rust panic，已被兜住，进程未受影响）：{message}")]
    Panic {
        /// panic 的说明。
        message: String,
    },

    /// 提交暂存写入时失败。
    ///
    /// 必须报出**写了多少、剩多少**：部分成功是这个操作唯一真正危险的结局，
    /// 含糊其辞会让用户以为要么全成要么全不成。
    #[error("提交脚本写入时失败：已写入 {committed}/{total} 条，其余未写入；原因：{reason}")]
    Commit {
        /// 已经写进去的条数。
        committed: usize,
        /// 本应写入的总条数。
        total: usize,
        /// 失败原因。
        reason: String,
    },

    /// 引擎自身故障（运行时创建失败等）。
    #[error("脚本引擎故障：{message}")]
    Engine {
        /// 说明。
        message: String,
    },
}

impl ScriptError {
    /// 这次失败是否留下了已提交的写入。
    ///
    /// 调用方（HTTP 层）要靠它决定怎么向用户交代：除了 [`ScriptError::Commit`]，
    /// 其余分支都保证**一条都没写**。
    #[must_use]
    pub const fn committed_writes(&self) -> Option<(usize, usize)> {
        match self {
            Self::Commit {
                committed, total, ..
            } => Some((*committed, *total)),
            _ => None,
        }
    }
}
