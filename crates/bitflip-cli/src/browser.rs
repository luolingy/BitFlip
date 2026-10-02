//! 打开系统浏览器。
//!
//! 用系统命令而不是引入额外依赖：这三行代码不值得一个 crate。

use std::process::Command;

/// 用默认浏览器打开 URL。
///
/// 在受限沙箱里 `spawn` 可能被拒绝，调用方应当把失败降级为"打印 URL 让用户自己点"，
/// 而不是让整个服务起不来。
pub fn open_url(url: &str) -> std::io::Result<()> {
    #[cfg(target_os = "windows")]
    {
        // `start` 是 cmd 内建命令；第一个引号参数会被当作窗口标题，故传空串占位。
        Command::new("cmd").args(["/C", "start", "", url]).spawn()?;
        Ok(())
    }

    #[cfg(target_os = "macos")]
    {
        Command::new("open").arg(url).spawn()?;
        Ok(())
    }

    #[cfg(all(unix, not(target_os = "macos")))]
    {
        Command::new("xdg-open").arg(url).spawn()?;
        Ok(())
    }
}
