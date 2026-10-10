//! BitFlip 命令行实现（`bitflip` 与 `bitflip-cli` 共用）。

mod browser;
mod cli;
mod export;
mod info;
mod members;
mod serve;
mod signature;
mod tracing_setup;

use std::process::ExitCode;

use clap::Parser;

pub use cli::{
    Cli, Command, ExportArgs, FunctionsArgs, InfoArgs, MembersArgs, OpenCli, RawOverrideArgs,
    ServeArgs, SignatureArgs, SignatureBuildArgs, SignatureCommand, SignatureInfoArgs, SymbolArgs,
};
pub use export::run_export;
pub use info::run_info;
pub use members::{run_functions, run_members, run_symbol};
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
        Command::Functions(args) => report(run_functions(&args)),
        Command::Symbol(args) => report(run_symbol(&args)),
        Command::Signature(args) => report(run_signature(&args)),
        Command::Export(args) => report(run_export(&args)),
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
        assert_eq!(bitflip_core::CORE_API_VERSION, 1);
        assert_eq!(bitflip_server::SERVER_API_VERSION, 1);
    }
}
