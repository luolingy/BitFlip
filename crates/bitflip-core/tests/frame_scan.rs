//! 栈帧视图的端到端测试（M6）。
//!
//! # 守的是什么
//!
//! 栈帧结论有两个来源（PE 展开信息 / 前导扫描），失效模式是**两边飘**
//! 而不报错：展开信息版本判错 → 整体退化成"没有数据"；展开码顺序判错
//! → 保存寄存器顺序反过来、栈槽位置全错。所以本文件不测"返回了东西"
//! 这种空泛结论，而是把期望值**钉死在独立工具的核对结果**上：
//!
//! ```text
//! llvm-objdump -d m3-mingw-static.exe
//!   140001010: pushq %r15 / %r14 / %r13 / %r12 / %rbp / %rdi / %rsi / %rbx
//!             subq  $0x58, %rsp            # 前导 16 字节，帧 0x98
//!   1400013d0: subq  $0x28, %rsp            # 前导 4 字节，帧 0x28
//! ```
//!
//! 两边（展开信息 vs 前导扫描）对**同一个函数**必须给出同一个数，这是
//! `Agreed` 状态存在的意义 —— 也是本文件最硬的一条断言。

use std::path::PathBuf;

use bitflip_core::{OpenOptions, Session};

fn fixture(name: &str) -> PathBuf {
    let p = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("..")
        .join("..")
        .join("tests")
        .join("fixtures")
        .join("generated")
        .join(name);
    assert!(
        p.exists(),
        "缺少样本 {}。生成方式见 docs/PLAN.md §5.2",
        p.display()
    );
    p
}

fn scan() -> bitflip_core::FrameScanWire {
    let session = Session::open(fixture("m3-mingw-static.exe"), OpenOptions::default())
        .expect("打开 PE 样本");
    let job = session.detached_job();
    let analysis = session.analysis(&job).expect("分析");
    analysis.frame_scan().clone()
}

/// 大函数 0x140001010：8 个 push + sub 0x58 —— 期望值与 objdump 逐条
/// 对上，而且**两个来源必须一致**（frame_size 0x98）。
#[test]
fn the_big_function_frame_is_cross_checked() {
    let scan = scan();
    let f = scan
        .functions
        .iter()
        .find(|f| f.entry == "0000000140001010")
        .expect("应当有 0x140001010 的帧推断");

    assert_eq!(f.frame_size, Some(0x98), "8×8 + 0x58 = 0x98");
    assert_eq!(f.unwind_frame_size, Some(0x98), "展开信息给出 0x98");
    assert_eq!(f.prologue_frame_size, Some(0x98), "前导扫描也给出 0x98");
    assert_eq!(f.prologue_len, Some(16), "前导 16 字节");
    assert_eq!(
        f.saved_registers,
        vec!["r15", "r14", "r13", "r12", "rbp", "rdi", "rsi", "rbx"],
        "保存寄存器必须按前导顺序，不能是展开码数组顺序（那是反的）"
    );
    // 两个来源对上了，source 必须是 Agreed —— 这是交叉核对的意义
    assert_eq!(f.source, "展开信息与前导扫描一致", "notes={:?}", f.notes);
    assert!(f.frame_pointer.is_none(), "这个函数没有帧指针");
}

/// 短函数 0x1400013d0：`subq $0x28, %rsp` 的叶式函数。
#[test]
fn the_minimal_prologue_frame_is_cross_checked() {
    let scan = scan();
    let f = scan
        .functions
        .iter()
        .find(|f| f.entry == "00000001400013d0")
        .expect("应当有 0x1400013d0 的帧推断");

    assert_eq!(f.frame_size, Some(0x28));
    assert_eq!(f.unwind_frame_size, Some(0x28));
    assert_eq!(f.prologue_frame_size, Some(0x28));
    assert_eq!(f.prologue_len, Some(4), "subq 是 4 字节");
    assert!(
        f.saved_registers.is_empty(),
        "这个函数没有保存寄存器，实际 {:?}",
        f.saved_registers
    );
    assert_eq!(f.source, "展开信息与前导扫描一致");
}

/// 交叉核对要真的起作用：在**两个来源都能给出帧大小**的函数里，
/// 绝大多数必须一致。
///
/// 叶函数常见的合法情况是：展开信息给出帧大小 0，而前导扫描没有识别
/// 建帧指令。这些函数不能算进"两个来源的重叠集合"，否则会把正常的
/// `Unwind`-only 误报成核对失败。
#[test]
fn the_two_sources_agree_on_most_functions() {
    let scan = scan();
    assert!(!scan.functions.is_empty(), "PE 样本应当有函数");

    let agreed = scan
        .functions
        .iter()
        .filter(|f| f.source == "展开信息与前导扫描一致")
        .count();
    let disagreed = scan
        .functions
        .iter()
        .filter(|f| f.source.contains("不一致"))
        .count();
    let overlap = agreed + disagreed;
    assert!(overlap > 0, "样本必须有两个来源都给出帧大小的函数");
    assert!(
        agreed * 4 >= overlap * 3,
        "两个来源在重叠集合里只在 {agreed}/{overlap} 的函数上一致，分歧数 {disagreed}"
    );

    // 有相当一部分函数应当有非零帧
    let with_frame = scan
        .functions
        .iter()
        .filter(|f| f.frame_size.is_some())
        .count();
    assert!(
        with_frame > scan.functions.len() / 4,
        "只有 {with_frame}/{} 个函数拿到帧大小",
        scan.functions.len()
    );
}

/// 两个来源不一致时，两个值都必须出现，不能只给一个。
#[test]
fn disagreements_surface_both_values() {
    let scan = scan();
    for f in scan
        .functions
        .iter()
        .filter(|f| f.source.contains("不一致"))
    {
        let (u, p) = (
            f.unwind_frame_size.expect("不一致时必须有两边的值"),
            f.prologue_frame_size.expect("不一致时必须有两边的值"),
        );
        assert_ne!(u, p, "source 说不一致但两个值相同：{f:?}");
        let joined = f.notes.join("；");
        assert!(
            joined.contains(&format!("{u}")) && joined.contains(&format!("{p}")),
            "分歧说明必须写明两个值：{joined}"
        );
    }
}

/// 没有展开信息的 ELF：帧大小只能靠前导扫描，且要如实说明。
///
/// `elf-aarch64-cfg.exe` 的 .eh_frame 目前只解出函数边界，`decoded`
/// 全是 None —— 这正是"拿不到就说拿不到"的分支。
#[test]
fn elf_frames_degrade_honestly_to_prologue_only() {
    let session = Session::open(fixture("elf-aarch64-cfg.exe"), OpenOptions::default())
        .expect("打开 ELF 样本");
    let job = session.detached_job();
    let analysis = session.analysis(&job).expect("分析");
    let scan = analysis.frame_scan();

    // 整体说明必须讲清楚：有展开信息但没解码出帧细节
    let joined = scan.notes.join("；");
    assert!(
        joined.contains("前导扫描") || joined.contains("没有展开表"),
        "ELF 的降级说明必须讲清数据来源：{joined}"
    );

    // 没有展开信息支撑时，source 不能是"展开信息…"
    for f in scan.functions.iter().take(20) {
        assert!(
            !f.source.starts_with("展开信息"),
            "ELF 没有解码出的展开信息，source 不能声称来自展开信息：{f:?}"
        );
        if f.frame_size.is_some() {
            assert_eq!(
                f.unwind_frame_size, None,
                "ELF 的 unwind_frame_size 必须是 null：{f:?}"
            );
        }
    }
}
