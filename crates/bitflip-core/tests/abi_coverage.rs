//! M5 调用约定（ABI）覆盖：寄存器级约定的端到端验证。
//!
//! 单元测试在 `bitflip-arch/src/abi.rs` 里，这里验证**经过 loader 与
//! 会话层之后**结论仍然正确 —— 尤其是 x86_64 的两套约定（System V 与
//! Microsoft x64）必须按目标格式区分：它们的前四个参数寄存器完全不同，
//! 判错会让界面上所有函数的参数标注整体偏移。

use std::path::PathBuf;

use bitflip_core::{OpenOptions, Session};

fn fixture(name: &str) -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("..")
        .join("..")
        .join("tests")
        .join("fixtures")
        .join("generated")
        .join(name)
}

/// PE 目标必须用 Windows x64 约定。
#[test]
fn pe_uses_windows_x64_convention() {
    let path = fixture("big-x86_64.exe");
    // fixture 缺失时**响亮失败**，不静默跳过：静默跳过会让这条测试在
    // 实现坏掉的情况下依然"通过"，那样它就没有守住任何东西。
    assert!(
        path.exists(),
        "缺少 fixture {}；生成方式见 docs/BIG-FILE-TESTING.md",
        path.display()
    );
    let session = Session::open(&path, OpenOptions::default()).expect("打开 PE");
    let abi = session.info().abi.clone().expect("PE 应当有调用约定");

    assert_eq!(abi.name, "Windows x64");
    assert_eq!(
        abi.arg_regs,
        vec!["rcx", "rdx", "r8", "r9"],
        "Windows x64 的前四个参数走 rcx/rdx/r8/r9"
    );
    assert_eq!(abi.return_reg, "rax");
    // PE 上不可能出现 System V 的 rdi/rsi
    assert!(
        !abi.arg_regs.contains(&"rdi".to_string()),
        "Windows x64 不该用 rdi 传参"
    );
}

/// ELF 目标必须用 System V AMD64 约定。
#[test]
fn elf_uses_system_v_convention() {
    let path = fixture("libsample.so");
    assert!(
        path.exists(),
        "缺少 libsample.so；重建见 scripts/gen-shared-lib.py"
    );
    let session = Session::open(&path, OpenOptions::default()).expect("打开 ELF");
    let abi = session.info().abi.clone().expect("ELF 应当有调用约定");

    assert_eq!(abi.name, "System V AMD64");
    assert_eq!(abi.arg_regs[0], "rdi");
    assert_eq!(abi.arg_regs.len(), 6, "System V 有 6 个整型参数寄存器");
    assert_eq!(abi.return_reg, "rax");
}

/// AArch64 必须用 AAPCS64，且返回地址在链接寄存器里。
#[test]
fn aarch64_uses_aapcs64_with_link_register_return() {
    let path = fixture("elf-aarch64-cfg.exe");
    // 同 PE 那条：缺 fixture 就响亮失败，不静默通过。
    assert!(
        path.exists(),
        "缺少 fixture {}；它是 clang 交叉生成的 AArch64 ELF（见 docs/PLAN.md §5.2）",
        path.display()
    );
    let session = Session::open(&path, OpenOptions::default()).expect("打开 AArch64 ELF");
    let abi = session.info().abi.clone().expect("AArch64 应当有调用约定");

    assert_eq!(abi.name, "AAPCS64");
    assert_eq!(abi.arg_regs[0], "x0");
    assert_eq!(abi.arg_regs.len(), 8);
    assert_eq!(abi.return_reg, "x0");
    assert_eq!(abi.stack_pointer, "sp");
    assert!(
        abi.return_address.contains("链接寄存器"),
        "AArch64 的返回地址在 x30：{}",
        abi.return_address
    );
    assert_eq!(abi.stack_align, 16);
}

/// 架构未知时不做猜测：`abi` 必须是 `None`，而不是填一套默认寄存器。
#[test]
fn unknown_architecture_reports_no_abi() {
    // 构造一个真正无法识别的东西：全零文件不会被当成任何已知格式。
    let path = fixture("unknown-no-abi.bin");
    let bytes = vec![0u8; 64];
    std::fs::write(&path, &bytes).expect("写测试文件");

    let session = Session::open(&path, OpenOptions::default()).expect("打开");
    let info = session.info();

    if info.arch.is_none() {
        assert!(
            info.abi.is_none(),
            "架构未知时不该给出调用约定 —— 那等于凭空编一套寄存器名（§7）"
        );
    }

    let _ = std::fs::remove_file(&path);
}
