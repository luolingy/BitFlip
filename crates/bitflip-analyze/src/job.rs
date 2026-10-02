//! 作业边界：进度、取消、panic 隔离。
//!
//! 两条硬性约定：
//!
//! 1. **panic 不得穿透进程边界**。分析器面对的是畸形输入，解码/解析代码里任何
//!    遗漏的越界都会 panic；[`run_guarded`] 把它转成 [`JobError::Panicked`]，
//!    服务进程继续活着，UI 得到一条可展示的错误。
//! 2. **取消是协作式的**。作业不会被打断在任意指令上，而是在调用方检查
//!    [`CancelToken::is_cancelled`] 的检查点退出，因此不会留下半写状态。

use std::panic::{catch_unwind, AssertUnwindSafe, UnwindSafe};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex, MutexGuard};

use thiserror::Error;

/// 作业标识。
pub type JobId = u64;

/// 分析阶段。顺序即执行顺序，允许从中间阶段单独重跑（改名/注释绝不触发重跑）。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum StageId {
    /// S1 段与映射：把 loader 结果归一化为地址空间。
    Segments,
    /// S2 种子收集：入口、导出、符号、unwind 表、导入 thunk、用户指定。
    Seeds,
    /// S3 解码扫描：递归下降 + 线性扫描。
    Decode,
    /// S4 函数识别：候选合并 + 置信度 + 边界扩展。
    Functions,
    /// S5 CFG 构建：基本块切分与后继（含跳转表）。
    Cfg,
    /// S6 引用解析：控制流目标与数据引用。
    Xrefs,
    /// S7 数据/代码判定：引用驱动 + 非法指令检测 + 用户覆写。
    CodeData,
    /// S8 语义增强：调用约定、参数、字符串、常量与数组、栈帧。
    Semantics,
    /// S9 符号增强：签名库匹配与名称优选。
    Symbols,
}

impl StageId {
    /// 全部阶段，按执行顺序。
    pub const ALL: [Self; 9] = [
        Self::Segments,
        Self::Seeds,
        Self::Decode,
        Self::Functions,
        Self::Cfg,
        Self::Xrefs,
        Self::CodeData,
        Self::Semantics,
        Self::Symbols,
    ];

    /// 阶段代号（S1…S9），用于日志与事件。
    #[must_use]
    pub const fn code(self) -> &'static str {
        match self {
            Self::Segments => "S1",
            Self::Seeds => "S2",
            Self::Decode => "S3",
            Self::Functions => "S4",
            Self::Cfg => "S5",
            Self::Xrefs => "S6",
            Self::CodeData => "S7",
            Self::Semantics => "S8",
            Self::Symbols => "S9",
        }
    }

    /// 面向界面的中文名。
    #[must_use]
    pub const fn label_zh(self) -> &'static str {
        match self {
            Self::Segments => "装载段与地址空间",
            Self::Seeds => "收集分析种子",
            Self::Decode => "解码扫描",
            Self::Functions => "函数识别",
            Self::Cfg => "构建控制流图",
            Self::Xrefs => "解析交叉引用",
            Self::CodeData => "数据/代码判定",
            Self::Semantics => "调用约定与语义",
            Self::Symbols => "符号与签名匹配",
        }
    }
}

/// 作业状态。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum JobState {
    /// 已创建，未开始。
    Pending,
    /// 正在执行。
    Running,
    /// 正常完成。
    Completed,
    /// 被取消（协作式退出）。
    Cancelled,
    /// 失败（含 panic 被捕获）。
    Failed,
}

impl JobState {
    /// 是否为终态。
    #[must_use]
    pub const fn is_terminal(self) -> bool {
        matches!(self, Self::Completed | Self::Cancelled | Self::Failed)
    }
}

/// 进度快照。
#[derive(Debug, Clone, PartialEq)]
pub struct Progress {
    /// 当前阶段。
    pub stage: StageId,
    /// 当前阶段的完成比例（0.0–1.0）。
    pub fraction: f32,
    /// 面向用户的一句话说明。
    pub message: String,
}

impl Default for Progress {
    fn default() -> Self {
        Self {
            stage: StageId::Segments,
            fraction: 0.0,
            message: String::new(),
        }
    }
}

/// 作业事件。服务层把它转成 WebSocket 消息，UI 据此渲染进度面板。
#[derive(Debug, Clone, PartialEq)]
pub enum JobEvent {
    /// 作业开始。
    Started {
        /// 作业 id。
        id: JobId,
    },
    /// 阶段进度更新。
    Stage {
        /// 作业 id。
        id: JobId,
        /// 进度快照。
        progress: Progress,
    },
    /// 自由文本消息（日志、降级说明）。
    Message {
        /// 作业 id。
        id: JobId,
        /// 消息内容。
        text: String,
    },
    /// 作业结束。
    Finished {
        /// 作业 id。
        id: JobId,
        /// 终态。
        state: JobState,
    },
}

/// 事件接收端。实现必须是线程安全的（分析线程会并发发事件）。
pub trait EventSink: Send + Sync {
    /// 投递一个事件。实现内部不得阻塞分析线程。
    fn emit(&self, event: JobEvent);
}

/// 丢弃所有事件的接收端。
#[derive(Debug, Default)]
pub struct NullSink;

impl EventSink for NullSink {
    fn emit(&self, _event: JobEvent) {}
}

/// 作业错误。
#[derive(Debug, Error)]
pub enum JobError {
    /// 作业在检查点观察到取消请求。
    #[error("作业已取消")]
    Cancelled,
    /// 闭包 panic 被捕获（分析器崩溃不得带走进程）。
    #[error("分析器 panic: {0}")]
    Panicked(String),
    /// 某个阶段失败。
    #[error("阶段 {stage} 失败: {message}")]
    StageFailed {
        /// 阶段代号。
        stage: &'static str,
        /// 失败原因。
        message: String,
    },
    /// 内部一致性错误。
    #[error("内部错误: {0}")]
    Internal(String),
}

/// 协作式取消令牌。克隆共享同一状态。
#[derive(Debug, Clone, Default)]
pub struct CancelToken {
    flag: Arc<AtomicBool>,
}

impl CancelToken {
    /// 新建未取消的令牌。
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// 请求取消。
    pub fn cancel(&self) {
        self.flag.store(true, Ordering::SeqCst);
    }

    /// 是否已请求取消。
    #[must_use]
    pub fn is_cancelled(&self) -> bool {
        self.flag.load(Ordering::SeqCst)
    }
}

/// 作业句柄：id + 状态 + 进度 + 取消令牌 + 事件出口。
#[derive(Clone)]
pub struct JobHandle {
    id: JobId,
    state: Arc<Mutex<JobState>>,
    progress: Arc<Mutex<Progress>>,
    cancel: CancelToken,
    sink: Arc<dyn EventSink>,
}

static NEXT_JOB_ID: AtomicU64 = AtomicU64::new(1);

/// 取互斥量，毒化时取回内部数据而不是 panic：进度状态不值得让整个进程崩掉。
fn lock<T>(mutex: &Mutex<T>) -> MutexGuard<'_, T> {
    mutex
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
}

impl JobHandle {
    /// 新建作业（id 自增）。
    #[must_use]
    pub fn new(sink: Arc<dyn EventSink>) -> Self {
        let id = NEXT_JOB_ID.fetch_add(1, Ordering::Relaxed);
        Self {
            id,
            state: Arc::new(Mutex::new(JobState::Pending)),
            progress: Arc::new(Mutex::new(Progress::default())),
            cancel: CancelToken::new(),
            sink,
        }
    }

    /// 使用指定 id 新建作业（服务层用会话内 id 时使用）。
    #[must_use]
    pub fn with_id(id: JobId, sink: Arc<dyn EventSink>) -> Self {
        Self {
            id,
            state: Arc::new(Mutex::new(JobState::Pending)),
            progress: Arc::new(Mutex::new(Progress::default())),
            cancel: CancelToken::new(),
            sink,
        }
    }

    /// 作业 id。
    #[must_use]
    pub fn id(&self) -> JobId {
        self.id
    }

    /// 取消令牌（传给并行分片）。
    #[must_use]
    pub fn cancel_token(&self) -> CancelToken {
        self.cancel.clone()
    }

    /// 请求取消（幂等）。
    pub fn cancel(&self) {
        self.cancel.cancel();
    }

    /// 是否已请求取消。
    #[must_use]
    pub fn is_cancelled(&self) -> bool {
        self.cancel.is_cancelled()
    }

    /// 当前状态。
    #[must_use]
    pub fn state(&self) -> JobState {
        *lock(&self.state)
    }

    /// 当前进度。
    #[must_use]
    pub fn progress(&self) -> Progress {
        lock(&self.progress).clone()
    }

    /// 更新阶段进度并投递事件。
    pub fn set_stage(&self, stage: StageId, fraction: f32, message: impl Into<String>) {
        let progress = Progress {
            stage,
            fraction: fraction.clamp(0.0, 1.0),
            message: message.into(),
        };
        *lock(&self.progress) = progress.clone();
        self.sink.emit(JobEvent::Stage {
            id: self.id,
            progress,
        });
    }

    /// 投递一条自由文本消息。
    pub fn emit_message(&self, text: impl Into<String>) {
        self.sink.emit(JobEvent::Message {
            id: self.id,
            text: text.into(),
        });
    }

    /// 设置终态并投递结束事件。
    pub fn finish(&self, state: JobState) {
        *lock(&self.state) = state;
        self.sink.emit(JobEvent::Finished { id: self.id, state });
    }
}

/// 把闭包包在 panic 边界里执行，并维护作业状态机。
///
/// 闭包应自行检查取消（`job.is_cancelled()`）并返回 [`JobError::Cancelled`]；
/// 只要返回 `Ok`，作业就被记为 `Completed` —— 不做"事后补偿式"的取消判定，
/// 免得把正常完成的工作标成取消。
pub fn run_guarded<T, F>(job: &JobHandle, f: F) -> Result<T, JobError>
where
    F: FnOnce(&JobHandle) -> Result<T, JobError> + UnwindSafe,
{
    *lock(&job.state) = JobState::Running;
    job.sink.emit(JobEvent::Started { id: job.id });
    tracing::debug!(job = job.id, "作业开始");

    let outcome = match catch_unwind(AssertUnwindSafe(|| f(job))) {
        Ok(Ok(value)) => Ok(value),
        Ok(Err(err)) => Err(err),
        Err(payload) => Err(JobError::Panicked(panic_message(payload.as_ref()))),
    };

    let final_state = match &outcome {
        Ok(_) => JobState::Completed,
        Err(JobError::Cancelled) => JobState::Cancelled,
        Err(_) => JobState::Failed,
    };
    tracing::debug!(job = job.id, state = ?final_state, "作业结束");
    job.finish(final_state);

    outcome
}

/// 提取 panic 载荷里的可读文本。
fn panic_message(payload: &(dyn std::any::Any + Send)) -> String {
    if let Some(s) = payload.downcast_ref::<&'static str>() {
        (*s).to_string()
    } else if let Some(s) = payload.downcast_ref::<String>() {
        s.clone()
    } else {
        "未知 panic 载荷".to_string()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[derive(Default)]
    struct RecordingSink {
        events: Mutex<Vec<JobEvent>>,
    }

    impl EventSink for RecordingSink {
        fn emit(&self, event: JobEvent) {
            lock(&self.events).push(event);
        }
    }

    fn sink() -> (Arc<RecordingSink>, Arc<dyn EventSink>) {
        let rec = Arc::new(RecordingSink::default());
        let dyn_sink: Arc<dyn EventSink> = rec.clone();
        (rec, dyn_sink)
    }

    #[test]
    fn successful_job_runs_to_completion() {
        let (rec, s) = sink();
        let job = JobHandle::new(s);

        let value = run_guarded(&job, |job| {
            job.set_stage(StageId::Decode, 0.5, "解码中");
            assert!(!job.is_cancelled());
            Ok(7u32)
        })
        .expect("应当成功");

        assert_eq!(value, 7);
        assert_eq!(job.state(), JobState::Completed);
        assert_eq!(job.progress().stage, StageId::Decode);
        assert!((job.progress().fraction - 0.5).abs() < f32::EPSILON);

        let events = lock(&rec.events);
        assert!(matches!(events.first(), Some(JobEvent::Started { .. })));
        assert!(matches!(
            events.last(),
            Some(JobEvent::Finished {
                state: JobState::Completed,
                ..
            })
        ));
        assert_eq!(events.len(), 3); // Started + Stage + Finished
    }

    #[test]
    fn panicking_job_is_contained_and_reported() {
        let (_rec, s) = sink();
        let job = JobHandle::new(s);

        let err = run_guarded(&job, |_job| -> Result<(), JobError> {
            panic!("模拟解码器越界")
        })
        .expect_err("panic 必须转成错误");

        assert!(matches!(err, JobError::Panicked(ref m) if m.contains("模拟解码器越界")));
        assert_eq!(job.state(), JobState::Failed);
        assert!(err.to_string().contains("panic"));
    }

    #[test]
    fn cancel_is_cooperative_and_reported() {
        let (_rec, s) = sink();
        let job = JobHandle::new(s);
        let token = job.cancel_token();
        token.cancel();

        let err = run_guarded(&job, |job| -> Result<(), JobError> {
            if job.is_cancelled() {
                return Err(JobError::Cancelled);
            }
            Err(JobError::Internal("不该走到这里".to_string()))
        })
        .expect_err("应返回取消");

        assert!(matches!(err, JobError::Cancelled));
        assert_eq!(job.state(), JobState::Cancelled);
        assert!(job.is_cancelled());
    }

    #[test]
    fn progress_fraction_is_clamped() {
        let (_rec, s) = sink();
        let job = JobHandle::new(s);
        let _ = run_guarded(&job, |job| {
            job.set_stage(StageId::Functions, 5.0, "超范围");
            assert!((job.progress().fraction - 1.0).abs() < f32::EPSILON);
            job.set_stage(StageId::Functions, -1.0, "负值");
            assert!(job.progress().fraction.abs() < f32::EPSILON);
            Ok(())
        });
    }

    #[test]
    fn stage_metadata_is_stable() {
        assert_eq!(StageId::ALL.len(), 9);
        assert_eq!(StageId::ALL[0].code(), "S1");
        assert_eq!(StageId::ALL[8].code(), "S9");
        assert_eq!(StageId::Decode.label_zh(), "解码扫描");
        assert!(JobState::Completed.is_terminal());
        assert!(!JobState::Running.is_terminal());
    }
}
