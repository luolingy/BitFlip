//! `bitflip` 可执行入口。
//!
//! 只有一件事：把参数交给 `bitflip-cli` 的 GUI 入口，返回它的退出码。
//! 真正的逻辑在库里，因此这个文件永远不需要被测。

use std::process::ExitCode;

fn main() -> ExitCode {
    bitflip_cli::gui_main()
}
