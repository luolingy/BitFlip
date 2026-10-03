//! `bitflip-core` 的统一错误类型。
//!
//! 约定（CLAUDE.md §4）：库用 `thiserror` 定义错误枚举，二进制入口用 `anyhow`；
//! 任何跨越作业边界的 panic 都必须先被转成 [`BitflipError`]，不得穿透到进程顶层。

use thiserror::Error;

/// BitFlip 引擎错误。
#[derive(Debug, Error)]
pub enum BitflipError {
    /// 目标装载/嗅探失败。
    #[error(transparent)]
    Loader(#[from] bitflip_loader::LoaderError),

    /// 功能尚未实现（明确告知排期，而不是返回空结果）。
    #[error("尚未实现: {feature}")]
    NotYetImplemented {
        /// 功能说明（含计划里程碑）。
        feature: &'static str,
    },

    /// 输入非法（路径、地址、参数组合）。
    #[error("输入无效: {0}")]
    InvalidInput(String),

    /// 该目标上做不了这项分析（格式没解析成功、没有可执行段等）。
    ///
    /// 与 [`BitflipError::NotYetImplemented`] 的区别很重要：
    /// 那是"我们还没写"，这是"这个目标本身没有可分析的东西"。
    /// 前者会随版本消失，后者不会 —— 混在一起会让用户以为等版本就够了。
    #[error("该目标无法分析: {0}")]
    AnalysisUnavailable(String),

    /// 作业执行失败。
    #[error("作业失败: {0}")]
    Job(#[from] bitflip_analyze::JobError),

    /// 工程库（用户标注主数据）读写失败。
    #[error("工程库错误: {0}")]
    Project(String),

    /// 内部一致性错误（bug）。
    #[error("内部错误: {0}")]
    Internal(String),
}

impl From<bitflip_project::ProjectError> for BitflipError {
    fn from(error: bitflip_project::ProjectError) -> Self {
        Self::Project(error.to_string())
    }
}

impl BitflipError {
    /// 便捷构造"尚未实现"错误。
    #[must_use]
    pub const fn not_implemented(feature: &'static str) -> Self {
        Self::NotYetImplemented { feature }
    }

    /// 便捷构造"该目标无法分析"错误。
    #[must_use]
    pub fn unavailable(reason: impl Into<String>) -> Self {
        Self::AnalysisUnavailable(reason.into())
    }
}
