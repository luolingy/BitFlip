//! BitFlip 命令行实现（`bitflip` 与 `bitflip-cli` 共用）。

mod browser;
mod cli;
mod dex;
mod diff;
mod export;
mod info;
mod manifest;
mod members;
mod patch;
mod serve;
mod signature;
mod tracing_setup;

use std::process::ExitCode;

use clap::Parser;

pub use cli::{
    Cli, Command, DexArgs, DiffArgs, ExportArgs, FunctionsArgs, InfoArgs, MembersArgs, OpenCli,
    PatchArgs, RawOverrideArgs, ServeArgs, SignatureArgs, SignatureBuildArgs, SignatureCommand,
    SignatureInfoArgs, SymbolArgs,
};
pub use dex::{build_json as build_dex_json, build_text as build_dex_text, run_dex};
pub use diff::run_diff;
pub use export::run_export;
pub use info::run_info;
pub use manifest::run_manifest;
pub use members::{run_functions, run_members, run_symbol};
pub use patch::run_patch;
pub use serve::{serve_blocking, ServeRequest};
pub use signature::run_signature;

/// `bitflip <target>` 的入口。
#[must_use]
pub fn gui_main() -> ExitCode {
    let parsed = OpenCli::parse();
    if parsed.info_only {
        return report(run_info(&parsed.target, false, parsed.verbose, &parsed.raw));
    }
    let open_options = match parsed.raw.to_open_options() {
        Ok(o) => o,
        Err(error) => return report(Err(error)),
    };
    report(serve_blocking(ServeRequest {
        target: parsed.target,
        host: parsed.host,
        port: parsed.port,
        open_browser: !parsed.no_open,
        token: parsed.token,
        allow_origins: parsed.allow_origin,
        verbose: parsed.verbose,
        open_options,
    }))
}

/// `bitflip-cli <subcommand>` 的入口。
#[must_use]
pub fn cli_main() -> ExitCode {
    match Cli::parse().command {
        Command::Info(args) => report(run_info(&args.target, args.json, args.verbose, &args.raw)),
        Command::Members(args) => report(run_members(&args)),
        Command::Dex(args) => report(run_dex(&args)),
        Command::Manifest(args) => report(run_manifest(&args)),
        Command::Functions(args) => report(run_functions(&args)),
        Command::Symbol(args) => report(run_symbol(&args)),
        Command::Signature(args) => report(run_signature(&args)),
        Command::Export(args) => report(run_export(&args)),
        Command::Diff(args) => report(run_diff(&args)),
        Command::Patch(args) => report(run_patch(&args)),
        Command::Serve(args) => {
            let open_options = match args.raw.to_open_options() {
                Ok(o) => o,
                Err(error) => return report(Err(error)),
            };
            report(serve_blocking(ServeRequest {
                target: args.target,
                host: args.host,
                port: args.port,
                open_browser: !args.no_open,
                token: args.token,
                allow_origins: args.allow_origin,
                verbose: args.verbose,
                open_options,
            }))
        }
        Command::Version => {
            print_version();
            ExitCode::SUCCESS
        }
    }
}

/// 打印版本与 API 版本（脚本可用 `bitflip-cli version` 做能力探测）。
pub fn print_version() {
    println!("BitFlip {} · 比特翻转", bitflip_core::version());
    println!("core API v{}", bitflip_core::CORE_API_VERSION);
    println!("server API v{}", bitflip_server::SERVER_API_VERSION);
    println!(
        "前端资源  {}",
        if bitflip_server::ui_embedded() {
            "已内嵌"
        } else {
            "未构建（运行 `cd web && npm install && npm run build`）"
        }
    );
}

/// 统一的"错误 → stderr + 退出码"处置。
fn report(result: anyhow::Result<()>) -> ExitCode {
    match result {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            // `{:#}` 打印 anyhow 的完整上下文链，方便定位是哪一层失败的。
            eprintln!("错误：{error:#}");
            ExitCode::FAILURE
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn version_output_is_available() {
        print_version();
        // 这两个号必须**同步**：服务转发的是 core 的公开类型，形状一变就得一起变。
        // 断言写在 CLI 里是因为它同时依赖两个 crate —— 让分叉在编译期之后第一次
        // 跑测试时就被抓住，而不是等某个消费者按旧版本解析出一堆 null。
        assert_eq!(bitflip_core::CORE_API_VERSION, 10);
        assert_eq!(bitflip_server::SERVER_API_VERSION, 10);
        assert_eq!(
            bitflip_core::CORE_API_VERSION,
            bitflip_server::SERVER_API_VERSION
        );
    }
}
