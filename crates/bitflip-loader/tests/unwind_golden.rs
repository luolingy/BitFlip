//! PE `UNWIND_INFO` 解码的黄金测试（M6 栈帧视图的数据来源）。
//!
//! # 为什么用真实样本而不是纯构造的字节
//!
//! 构造字节能测"我的解析器符合我以为的规范"，测不出"我以为的规范是对的"。
//! 这块就栽过两次，而且**两次都只有真实样本能发现**：
//!
//! 1. **版本号搞反**：最初写"版本 0 才是 x64"，在 MinGW PE 上 127 条
//!    展开信息**全部**报版本 1，于是全部退化成"只记录头字段"，一条
//!    操作码都没解出来。规范里 x64 的现行版本就是 **1**。
//! 2. **展开码顺序搞反**：PE/COFF 规定展开码按**前导偏移递减**排列
//!    （最后一条前导指令排在最前）。按数组顺序处理时，8 个 push 解出来
//!    的顺序恰好与反汇编相反，而且每个 push 的栈槽位置全错。
//!
//! # 期望值的来源
//!
//! 下面断言里的数字**不是**从我的解码器抄的，而是用独立工具核对的：
//!
//! ```text
//! llvm-objdump -d --start-address=0x140001010 --stop-address=0x140001030 m3-mingw-static.exe
//!   140001010: pushq %r15
//!   140001012: pushq %r14
//!   140001014: pushq %r13
//!   140001016: pushq %r12
//!   140001018: pushq %rbp
//!   140001019: pushq %rdi
//!   14000101a: pushq %rsi
//!   14000101b: pushq %rbx
//!   14000101c: subq $0x58, %rsp
//! ```
//!
//! 8 × 8 + 0x58 = 152 = 0x98（帧大小）；前导从 0x140001010 到 0x140001020
//! 是 16 字节。两边必须一致 —— 这正是栈帧视图"交叉核对"的意义。

use std::path::PathBuf;

use bitflip_loader::object::{ObjectId, PeUnwindOp};
use bitflip_loader::pe::parse;

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

fn load(name: &str) -> bitflip_loader::object::Object {
    let bytes = std::fs::read(fixture(name)).expect("读样本");
    parse(&bytes, 0, ObjectId::Plain).expect("解析 PE")
}

/// 大函数的前导：8 个 push + sub 0x58。期望值与反汇编逐条对上。
#[test]
fn decodes_the_big_function_frame_exactly() {
    let obj = load("m3-mingw-static.exe");
    let entry = obj
        .unwind
        .iter()
        .find(|e| e.begin == 0x140001010)
        .expect("应当有 0x140001010 的展开条目");
    let info = entry.decoded.as_ref().expect("应当解码成功");

    assert_eq!(info.version, 1, "x64 的现行展开信息版本是 1");
    assert_eq!(
        info.prologue_size, 16,
        "前导 16 字节（0x140001010→0x140001020）"
    );
    assert_eq!(
        info.frame_size(),
        Some(0x98),
        "8×8 + 0x58 = 0x98：帧大小必须与反汇编一致"
    );

    // 保存顺序必须与**前导顺序**一致（r15 先压），不能是数组顺序
    assert_eq!(
        info.saved_registers(),
        vec!["r15", "r14", "r13", "r12", "rbp", "rdi", "rsi", "rbx"],
        "保存寄存器要按前导顺序报告；反了说明没处理'展开码递减排列'"
    );

    // 每个 push 的栈槽：r15 压得最早 → 离最终 RSP 最远（0x90），
    // rbx 压得最晚 → 最近（0x58）
    let pushes: Vec<(&str, u64)> = info
        .ops
        .iter()
        .filter_map(|op| match op {
            PeUnwindOp::PushNonVolatile { reg, slot_from_top } => {
                Some((reg.as_str(), *slot_from_top))
            }
            _ => None,
        })
        .collect();
    assert_eq!(
        pushes,
        vec![
            ("r15", 0x90),
            ("r14", 0x88),
            ("r13", 0x80),
            ("r12", 0x78),
            ("rbp", 0x70),
            ("rdi", 0x68),
            ("rsi", 0x60),
            ("rbx", 0x58),
        ],
        "push 的槽位要逐条对上（槽位算错会让界面显示错误的保存位置）"
    );

    // 最后一条是栈分配
    assert!(
        matches!(info.ops.last(), Some(PeUnwindOp::Alloc { size: 0x58 })),
        "最后一条前导操作应是 sub rsp, 0x58，实际 {:?}",
        info.ops.last()
    );
    assert!(
        info.notes.is_empty(),
        "正常解码不该有降级说明：{:?}",
        info.notes
    );
}

/// 叶函数式的短前导：`subq $0x28, %rsp`，无保存寄存器。
#[test]
fn decodes_a_minimal_prologue_exactly() {
    let obj = load("m3-mingw-static.exe");
    let entry = obj
        .unwind
        .iter()
        .find(|e| e.begin == 0x1400013d0)
        .expect("应当有 0x1400013d0 的展开条目");
    let info = entry.decoded.as_ref().expect("应当解码成功");

    assert_eq!(info.prologue_size, 4, "subq $0x28,%rsp 是 4 字节");
    assert_eq!(info.frame_size(), Some(0x28));
    assert!(
        info.saved_registers().is_empty(),
        "这个函数没保存任何非易失寄存器，实际 {:?}",
        info.saved_registers()
    );
    assert_eq!(info.ops.len(), 1, "只有一条栈分配操作");
    assert!(info.frame_register.is_none(), "没有帧指针");
}

/// 大部分条目都要能解码出东西 —— 防止"静默全空"。
///
/// 如果哪天解码器又整体失效（像版本号那次），这条会立刻变红。
#[test]
fn most_entries_decode_with_real_content() {
    let obj = load("m3-mingw-static.exe");
    assert!(!obj.unwind.is_empty(), "MinGW PE 应当有 .pdata");

    let decoded = obj.unwind.iter().filter(|e| e.decoded.is_some()).count();
    assert_eq!(
        decoded,
        obj.unwind.len(),
        "所有 .pdata 条目都应当能定位到展开信息"
    );

    // 有相当一部分函数应当有非零帧（叶函数为 0 是正常的）
    let with_frame = obj
        .unwind
        .iter()
        .filter(|e| e.decoded.as_ref().and_then(|d| d.frame_size()).unwrap_or(0) > 0)
        .count();
    assert!(
        with_frame > obj.unwind.len() / 4,
        "只有 {with_frame}/{} 个函数解出非零帧大小，解码很可能整体失效了",
        obj.unwind.len()
    );

    // 也不能全部都有帧：叶函数本来就该是 0
    assert!(
        with_frame < obj.unwind.len(),
        "所有函数都有非零帧大小不合常理（叶函数应当为 0）"
    );
}
