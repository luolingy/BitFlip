//! 分阶段计时（`BITFLIP_TIMING=1` 时才开）。
//!
//! # 为什么留在代码里而不是测完删掉
//!
//! "这次分析为什么慢"是个会反复出现的问题：151 KB 的 LiveContainer 在本机实测要
//! 6.4 秒（任务书里提到的 49 秒没能在本机复现 —— 构建配置/机器不同，能确认的是同一类
//! 成本结构）。临时打点一旦删掉，下一个人就得从头再测一遍，而结论没法复核。所以它常驻，
//! 默认关闭、只写 stderr、**不进任何 wire 结构**（不影响响应与黄金快照），release 构建
//! 里是一个空结构体（零成本）。
//!
//! # 为什么在 crate 根而不是放在 `analysis` 里
//!
//! 打点最初只覆盖 `TargetAnalysis::build`。现在 `Disasm::build` 也要分阶段
//! （地址空间 / 线性扫描 / 递归下降 / 合并）—— 那是同一次"为什么慢"调查的另一半，
//! 两处必须用**同一种输出格式**才能拼在一起看，所以抽到 crate 内部共享。
//! 它不是公开 API：`pub(crate)`，不进 `lib.rs` 的 `pub use`。

#[cfg(debug_assertions)]
pub(crate) mod stages {
    use std::time::Instant;

    /// 一个阶段（标签 + 距上一阶段的微秒数）。
    pub(crate) struct Stages {
        enabled: bool,
        origin: Instant,
        last: Instant,
        marks: Vec<(&'static str, u128)>,
    }

    impl Stages {
        pub(crate) fn new() -> Self {
            let enabled = std::env::var_os("BITFLIP_TIMING").is_some();
            let now = Instant::now();
            Self {
                enabled,
                origin: now,
                last: now,
                marks: Vec::new(),
            }
        }

        /// 记一个阶段边界。关闭时只是一次分支预测，不留开销。
        #[inline]
        pub(crate) fn mark(&mut self, label: &'static str) {
            if !self.enabled {
                return;
            }
            let now = Instant::now();
            self.marks.push((label, (now - self.last).as_micros()));
            self.last = now;
        }

        /// 打表。合计分两行：打点覆盖到的与 `build` 全程（差额是打点之间的事务）。
        pub(crate) fn report(&self, title: &str) {
            if !self.enabled {
                return;
            }
            eprintln!("[BITFLIP_TIMING] {title} 分阶段（µs）:");
            let mut covered = 0u128;
            for (label, micros) in &self.marks {
                covered += *micros;
                eprintln!("  {label:<34} {micros:>10}");
            }
            eprintln!("  {:<34} {covered:>10}", "合计（打点覆盖）");
            eprintln!(
                "  {:<34} {:>10}",
                "合计（build 全程）",
                self.origin.elapsed().as_micros()
            );
        }
    }
}

/// 未开 `debug_assertions` 时的空实现（发布构建里连环境变量都不读）。
#[cfg(not(debug_assertions))]
pub(crate) mod stages {
    pub(crate) struct Stages;

    impl Stages {
        pub(crate) fn new() -> Self {
            Self
        }

        #[inline]
        pub(crate) fn mark(&mut self, _label: &'static str) {}

        pub(crate) fn report(&self, _title: &str) {}
    }
}

pub(crate) use stages::Stages;
