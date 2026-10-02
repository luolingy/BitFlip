//! 日志初始化。用 `BITFLIP_LOG` 或 `RUST_LOG` 覆盖级别。

use tracing_subscriber::EnvFilter;

/// 初始化日志（幂等：重复调用只生效一次）。
pub fn init(verbose: bool) {
    let default_level = if verbose { "debug" } else { "info" };
    let filter = EnvFilter::try_from_default_env()
        .unwrap_or_else(|_| EnvFilter::new(format!("bitflip={default_level},warn")));
    let _ = tracing_subscriber::fmt()
        .with_env_filter(filter)
        .with_target(false)
        .with_writer(std::io::stderr)
        .try_init();
}
