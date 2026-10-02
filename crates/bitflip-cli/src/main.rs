//! `bitflip-cli` 可执行入口（无头用法）。

use std::process::ExitCode;

fn main() -> ExitCode {
    bitflip_cli::cli_main()
}
