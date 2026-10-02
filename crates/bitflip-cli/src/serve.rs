//! `serve`：打开目标、起本地服务、可选打开浏览器。

use std::net::IpAddr;
use std::path::PathBuf;

use anyhow::Context;
use bitflip_core::{OpenOptions, Session, TargetInfo};
use bitflip_server::{default_allowed_origins, generate_token, AppState};

use crate::browser;

/// 启动本地服务的请求（GUI 入口与 `bitflip-cli serve` 共用）。
#[derive(Debug, Clone)]
pub struct ServeRequest {
    /// 目标文件。
    pub target: PathBuf,
    /// 监听地址（字符串，便于直接来自命令行）。
    pub host: String,
    /// 监听端口（0 = 系统分配）。
    pub port: u16,
    /// 是否自动打开浏览器。
    pub open_browser: bool,
    /// 固定令牌（`None` = 随机生成）。
    pub token: Option<String>,
    /// 追加的允许 Origin。
    pub allow_origins: Vec<String>,
    /// 调试日志。
    pub verbose: bool,
}

/// 同步入口：建立 tokio 运行时并阻塞到服务退出。
pub fn serve_blocking(request: ServeRequest) -> anyhow::Result<()> {
    crate::tracing_setup::init(request.verbose);
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .context("创建 tokio 运行时失败")?;
    runtime.block_on(serve_async(request))
}

async fn serve_async(request: ServeRequest) -> anyhow::Result<()> {
    // 先打开目标：路径不对要立刻失败，而不是先起服务再报错。
    let session = Session::open(&request.target, OpenOptions::default())?;
    let info = session.target_info();
    print_target(&info);

    let host: IpAddr = request
        .host
        .parse()
        .with_context(|| format!("监听地址无法解析: {}", request.host))?;
    if !host.is_loopback() {
        eprintln!(
            "\n⚠ 警告：服务绑定在非回环地址 {host}。\n  \
             BitFlip 是本地分析工具：暴露到网络上意味着别人可以读取（后续还可写回）你的分析结果。\n  \
             访问令牌仍然生效，但请确认这是有意为之。\n"
        );
    }

    let token = request.token.unwrap_or_else(generate_token);
    let bound = bitflip_server::bind(host, request.port, 10).await?;
    let origins = default_allowed_origins(bound.addr.port(), &request.allow_origins);
    // 解析结果随会话一起交给服务层：UI 的"结构"页需要它。
    // 解析失败时传 None，前端会显示识别结论 + 失败原因。
    let state = AppState::new(token.clone(), Some(info))
        .with_parsed(session.parsed().cloned())
        .with_allowed_origins(origins);

    let url = format!("http://{}/#token={}", display_addr(bound.addr), token);
    print_banner(&url);

    if request.open_browser {
        if let Err(error) = browser::open_url(&url) {
            eprintln!("打开浏览器失败（{error}），请手动访问上面的地址。");
        }
    }

    let shutdown = async {
        let _ = tokio::signal::ctrl_c().await;
        println!("\n收到中断信号，正在退出…");
    };

    bitflip_server::serve(bound.listener, state, shutdown).await?;
    println!("BitFlip 已退出。");
    Ok(())
}

/// 把地址渲染成可直接放进 URL 的形式（IPv6 需要方括号）。
fn display_addr(addr: std::net::SocketAddr) -> String {
    if addr.is_ipv6() {
        format!("[{}]:{}", addr.ip(), addr.port())
    } else {
        format!("{}:{}", addr.ip(), addr.port())
    }
}

fn print_target(info: &TargetInfo) {
    println!();
    println!("目标  {}", info.path);
    println!("体积  {} 字节", info.file_size);
    println!("识别  {}", info.summary);
    if let Some(entry) = &info.entry {
        println!("入口  {entry}");
    }
    if let Some(base) = &info.image_base {
        println!("基址  {base}");
    }
    if info.file_truncated {
        println!(
            "注意  文件大于嗅探窗口，以上结论只覆盖前 {} 字节",
            info.sniffed_bytes
        );
    }
    for note in &info.notes {
        println!("说明  {note}");
    }
}

fn print_banner(url: &str) {
    println!();
    println!("BitFlip 已启动（仅本机可访问）：");
    println!("  {url}");
    println!();
    println!("  · 访问令牌在 URL 的片段里，浏览器不会把它发给第三方；丢了这个 URL 就重启一次。");
    println!("  · 按 Ctrl+C 退出。");
    println!();
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::SocketAddr;

    #[test]
    fn ipv6_addresses_are_bracketed() {
        let v4: SocketAddr = "127.0.0.1:8790".parse().expect("v4");
        assert_eq!(display_addr(v4), "127.0.0.1:8790");
        let v6: SocketAddr = "[::1]:8790".parse().expect("v6");
        assert_eq!(display_addr(v6), "[::1]:8790");
    }

    #[test]
    fn serve_fails_fast_on_missing_target() {
        let request = ServeRequest {
            target: PathBuf::from("definitely-missing-binary.exe"),
            host: "127.0.0.1".to_string(),
            port: 0,
            open_browser: false,
            token: Some("t".to_string()),
            allow_origins: Vec::new(),
            verbose: false,
        };
        let error = serve_blocking(request).expect_err("目标不存在必须失败");
        assert!(error.to_string().contains("读取目标失败"));
    }
}
