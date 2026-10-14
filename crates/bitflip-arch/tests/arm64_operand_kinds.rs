//! AArch64 操作数提取的回归测试：我方的操作数模型 vs **外部**反汇编器的文本。
//!
//! ## 真值从哪来
//!
//! `tests/fixtures` 里没有 aarch64 目标，所以这里的字节序列是现场汇编、
//! 再用 llvm-objdump 反汇编得到的，真值文本逐条抄进下面的表：
//!
//! ```text
//! clang --target=aarch64-linux-gnu -march=armv8.5-a -c probe.s -o probe.o
//! llvm-objdump -d --no-show-raw-insn probe.o
//! ```
//!
//! 抄 llvm-objdump 而不是抄我们自己的输出：期望值若来自实现，实现错了
//! 期望值就跟着错，测试照样全绿 —— 那正是 CLAUDE.md §6.11 记的自证其说。
//!
//! ## 这条测试防的是什么
//!
//! 曾经 `convert_arm64_operand` 末尾是 `_ => {}`，把 10 类操作数**静默丢掉**：
//! `mrs x19, TPIDR_EL0` 显示成 `mrs x19`、`msr TPIDR_EL0, x19` 显示成
//! `msr x19` —— 后者语法正确、语义完全不同，读者看不出少了东西。
//! 同一函数里的内存操作数还写死了 `index: None`，于是真实目标里
//! **所有**带索引的内存操作数只剩基址（195 KB 的 `libBugly_Native.so` 上
//! 147 处，逐地址与 llvm-objdump 对拍已全部修好）。
//!
//! 两者都不报错、不 panic，只是安静地少给数据，所以断言分两类：
//!
//! 1. **操作数个数**：与外部反汇编器文本里的项数一致 —— 少一个就红。
//! 2. **不可得也要可见**：capstone 确实没给的东西（`prfm` 的预取操作数、
//!    IC/DC/AT/TLBI 的子操作名）必须打出**显式标记**，不能消失（§7）。

use bitflip_arch::{format_insn, ArchSpec, CapstoneDecoder, Decoder, MemRef, Operand, ShiftKind};

/// （文件序字节, 地址, 操作数个数, llvm-objdump 真值文本）
///
/// 字节是**文件里的顺序**（小端序），与导出文本中间那列一致。
const TRUTH: &[(&[u8], u64, usize, &str)] = &[
    // ── 系统寄存器 / PState（以前全被丢掉） ──────────────────────────
    (&[0x53, 0xd0, 0x3b, 0xd5], 0x00, 2, "mrs x19, TPIDR_EL0"),
    (&[0x53, 0xd0, 0x1b, 0xd5], 0x04, 2, "msr TPIDR_EL0, x19"),
    (&[0x34, 0x42, 0x3b, 0xd5], 0x08, 2, "mrs x20, DAIF"),
    (&[0xdf, 0x42, 0x03, 0xd5], 0x0c, 2, "msr DAIFSet, #0x2"),
    (&[0xff, 0x42, 0x03, 0xd5], 0x10, 2, "msr DAIFClr, #0x2"),
    (&[0xbf, 0x41, 0x00, 0xd5], 0x14, 2, "msr SPSel, #0x1"),
    // ── 屏障（丢掉操作数会把 `dsb ish` 显示成 `dsb`，语义完全不同） ──
    (&[0x9f, 0x3f, 0x03, 0xd5], 0x24, 1, "dsb sy"),
    (&[0x9f, 0x3b, 0x03, 0xd5], 0x28, 1, "dsb ish"),
    (&[0x9f, 0x36, 0x03, 0xd5], 0x2c, 1, "dsb nshst"),
    (&[0xbf, 0x33, 0x03, 0xd5], 0x30, 1, "dmb osh"),
    (&[0xbf, 0x39, 0x03, 0xd5], 0x34, 1, "dmb ishld"),
    // `isb` 的规范写法**不带操作数**（选项字段被架构忽略），真值就是 0 个。
    // 这里不是"我们把操作数丢了"：capstone 对**认不出**的屏障选项走的是
    // `AArch64InstPrinter.c` 的 else 分支，写的是 `ARM64_OP_IMM`（会渲染成
    // 数字，看得见），所以 `Barrier` 走不到"有值却被丢"的路径。
    (&[0xdf, 0x3f, 0x03, 0xd5], 0x38, 0, "isb"),
    // ── IC/DC/AT/TLBI 的子操作（名字未补，但要可见） ─────────────────
    (&[0x20, 0x7e, 0x0b, 0xd5], 0x3c, 2, "dc civac, x0"),
    (&[0x22, 0x74, 0x0b, 0xd5], 0x44, 2, "dc zva, x2"),
    (&[0x1f, 0x71, 0x08, 0xd5], 0x48, 1, "ic ialluis"),
    (&[0x1f, 0x87, 0x08, 0xd5], 0x50, 1, "tlbi vmalle1"),
    (&[0x05, 0x78, 0x08, 0xd5], 0x58, 2, "at s1e1r, x5"),
    // ── 预取（capstone 的 detail 里**没有**这个操作数，见测试 D） ────
    (&[0x20, 0x00, 0x80, 0xf9], 0x5c, 2, "prfm pldl1keep, [x1]"),
    (
        &[0x53, 0x20, 0x80, 0xf9],
        0x60,
        2,
        "prfm pstl2strm, [x2, #0x40]",
    ),
    (
        &[0x64, 0x80, 0x80, 0xf8],
        0x64,
        2,
        "prfum pldl3keep, [x3, #0x8]",
    ),
    // ── 带索引的内存（以前 index 恒为 None） ────────────────────────
    (&[0x20, 0x68, 0x62, 0xf8], 0x6c, 2, "ldr x0, [x1, x2]"),
    (
        &[0x07, 0x79, 0x69, 0xf8],
        0x70,
        2,
        "ldr x7, [x8, x9, lsl #3]",
    ),
    // ── 浮点立即数 / C-IMM ─────────────────────────────────────────
    (&[0x00, 0x10, 0x2e, 0x1e], 0x74, 2, "fmov s0, #1.00000000"),
    (&[0x01, 0x90, 0x60, 0x1e], 0x78, 2, "fmov d1, #2.50000000"),
    (&[0x6a, 0x1d, 0x40, 0x92], 0x80, 3, "and x10, x11, #0xff"),
    (&[0x8c, 0x46, 0x82, 0xd2], 0x84, 2, "mov x12, #0x1234"),
    // ── 对照：没有操作数的指令不该凭空多出操作数 ───────────────────
    (&[0xc0, 0x03, 0x5f, 0xd6], 0x88, 0, "ret"),
];

/// 带索引的内存操作数用例：`(文件序字节, 地址, 比例, 索引扩展, 真值)`。
type IndexCase = (&'static [u8], u64, u8, Option<ShiftKind>, &'static str);

/// 比例来自 ARM 的 `#s`（`scale == 1 << s`）；扩展是 `sxtw`/`uxtw` 这一维，
/// 它和移位**不是一回事**：索引为负时两者算出的有效地址不同。
const INDEX_TRUTH: &[IndexCase] = &[
    (
        &[0x20, 0xd9, 0x68, 0xf8],
        0x00,
        8,
        Some(ShiftKind::Sxtw),
        "ldr x0, [x9, w8, sxtw #3]",
    ),
    (
        &[0x0b, 0x49, 0x6a, 0x38],
        0x04,
        1,
        Some(ShiftKind::Uxtw),
        "ldrb w11, [x8, w10, uxtw]",
    ),
    (
        &[0x3c, 0xd9, 0x2a, 0xb8],
        0x08,
        4,
        Some(ShiftKind::Sxtw),
        "str w28, [x9, w10, sxtw #2]",
    ),
    (
        &[0x20, 0x79, 0x6a, 0xf8],
        0x0c,
        8,
        None,
        "ldr x0, [x9, x10, lsl #3]",
    ),
    (
        &[0x20, 0x69, 0x6a, 0xf8],
        0x10,
        1,
        None,
        "ldr x0, [x9, x10]",
    ),
    (
        &[0x41, 0x58, 0x63, 0x78],
        0x14,
        2,
        Some(ShiftKind::Uxtw),
        "ldrh w1, [x2, w3, uxtw #1]",
    ),
];

fn decoder() -> CapstoneDecoder {
    CapstoneDecoder::new(ArchSpec::aarch64()).expect("aarch64 解码器")
}

fn decode(bytes: &[u8], addr: u64) -> (CapstoneDecoder, bitflip_arch::DecodedInsn) {
    let decoder = decoder();
    let insn = decoder.decode_one(bytes, addr).expect("解码失败");
    (decoder, insn)
}

/// 取第一个内存操作数。
fn mem_of(insn: &bitflip_arch::DecodedInsn) -> &MemRef {
    insn.operands
        .iter()
        .find_map(|op| match op {
            Operand::Mem(mem) => Some(mem),
            _ => None,
        })
        .expect("这条指令应当有内存操作数")
}

/// 操作数个数必须与外部反汇编器给出的文本一致。
///
/// 「个数」是这一族 bug 唯一能自动抓住的共性：丢操作数不改别的字段，
/// 也不报错，只让列表变短。
#[test]
fn operand_counts_match_the_reference_disassembler() {
    for (bytes, addr, expected, truth) in TRUTH {
        let (_, insn) = decode(bytes, *addr);

        assert_eq!(
            insn.operands.len(),
            *expected,
            "{addr:#x} `{truth}`：操作数个数对不上（我们的操作数：{:?}）",
            insn.operands
        );
    }
}

/// 带索引的内存操作数必须保住索引寄存器、比例、以及扩展。
#[test]
fn indexed_memory_operands_keep_index_scale_and_extend() {
    for (bytes, addr, scale, extend, truth) in INDEX_TRUTH {
        let (_, insn) = decode(bytes, *addr);
        let mem = mem_of(&insn);

        assert!(
            mem.base.is_some(),
            "{addr:#x} `{truth}`：基址丢了（我们的内存操作数：{mem:?}）"
        );
        assert!(
            mem.index.is_some(),
            "{addr:#x} `{truth}`：索引寄存器被丢掉（我们的内存操作数：{mem:?}）"
        );
        assert_eq!(
            mem.scale, *scale,
            "{addr:#x} `{truth}`：比例不对（我们的内存操作数：{mem:?}）"
        );
        assert_eq!(
            mem.index_extend, *extend,
            "{addr:#x} `{truth}`：索引扩展不对（我们的内存操作数：{mem:?}）"
        );
    }
}

/// 渲染出来的索引必须写出来 —— 结构对了但没渲染，用户仍然看不到。
#[test]
fn indexed_memory_operands_are_rendered() {
    let cases: &[(&[u8], u64, &str)] = &[
        (&[0x20, 0xd9, 0x68, 0xf8], 0x00, "[x9+w8*8, sxtw]"),
        (&[0x0b, 0x49, 0x6a, 0x38], 0x04, "[x8+w10*1, uxtw]"),
        (&[0x20, 0x69, 0x6a, 0xf8], 0x10, "[x9+x10*1]"),
        (&[0x20, 0x79, 0x6a, 0xf8], 0x0c, "[x9+x10*8]"),
        // probe_ops.o 的 `ldr x0, [x1, x2]` / `ldr x7, [x8, x9, lsl #3]`
        (&[0x20, 0x68, 0x62, 0xf8], 0x6c, "[x1+x2*1]"),
        (&[0x07, 0x79, 0x69, 0xf8], 0x70, "[x8+x9*8]"),
    ];

    for (bytes, addr, expected) in cases {
        let (decoder, insn) = decode(bytes, *addr);
        let text = format_insn(&decoder, &insn);
        assert!(
            text.contains(expected),
            "{addr:#x}：渲染少了索引（期望含 `{expected}`，实际 `{text}`）"
        );
    }
}

/// 扩展**不能**被当成移位。
///
/// capstone 对 `[x9, w8, sxtw #3]` / `add x0, x1, w2, sxtw #2` 这类编码会
/// **同时**填 `shift=Lsl(3)` 与 `ext=SXTW`。早先的 `arm64_modifier` 在 `shift`
/// 上直接 `return`，于是 `sxtw` 被静默换成了 `lsl` —— 有符号扩展变成逻辑左移，
/// 结果完全不同，而文本看着完全正常。
#[test]
fn an_extend_is_never_flattened_to_a_shift() {
    // （字节, 地址, 必须出现, 必须不出现, llvm-objdump 真值）
    let cases: &[(&[u8], u64, &str, &str, &str)] = &[
        (
            &[0x20, 0xc8, 0x22, 0x8b],
            0x18,
            "w2, sxtw #2",
            "lsl",
            "add x0, x1, w2, sxtw #2",
        ),
        (
            &[0x49, 0x45, 0x2b, 0x8b],
            0x24,
            "w11, uxtw #1",
            "lsl",
            "add x9, x10, w11, uxtw #1",
        ),
        // 对照组：真的是逻辑左移时照旧写 `lsl`。
        (
            &[0x83, 0x0c, 0x05, 0x8b],
            0x1c,
            "x5, lsl #3",
            "sxtw",
            "add x3, x4, x5, lsl #3",
        ),
    ];

    for (bytes, addr, must, must_not, truth) in cases {
        let (decoder, insn) = decode(bytes, *addr);
        let text = format_insn(&decoder, &insn);

        assert!(
            text.contains(must),
            "{addr:#x} `{truth}`：渲染里没有 `{must}`（实际 `{text}`）"
        );
        assert!(
            !text.contains(must_not),
            "{addr:#x} `{truth}`：渲染里不该出现 `{must_not}`（实际 `{text}`）"
        );
    }
}

/// capstone 拿不到的东西必须**看得见**，不能消失。
///
/// 这条测的是 CLAUDE.md §7 的"拿不到就说拿不到"：`prfm` 的预取操作数在
/// capstone 的 detail 里根本不存在（它只出现在 C 头文件和 cstool 里），
/// IC/DC/AT/TLBI 的子操作名我们还没补。两者都渲染成显式标记，
/// 而不是输出一条看着完整、其实少东西的指令。
#[test]
fn unavailable_operands_are_marked_rather_than_dropped() {
    // 预取操作数：位置在（第一个），值拿不到。
    let (decoder, insn) = decode(&[0x20, 0x00, 0x80, 0xf9], 0x5c);
    assert!(
        matches!(insn.operands.first(), Some(Operand::Prefetch(None))),
        "`prfm` 的第一个操作数应当是「位置在、值拿不到」，实际：{:?}",
        insn.operands
    );
    let text = format_insn(&decoder, &insn);
    assert!(
        text.contains("<prefetch:?>"),
        "`prfm` 的预取操作数必须打出显式标记，实际 `{text}`"
    );

    // 系统操作的子操作名：未补，但不能丢。
    let (decoder, insn) = decode(&[0x20, 0x7e, 0x0b, 0xd5], 0x3c);
    let text = format_insn(&decoder, &insn);
    assert!(
        text.contains("<sys_op:192>"),
        "`dc civac, x0` 的子操作必须打出显式标记（含 capstone 的判别值 192），实际 `{text}`"
    );

    // 系统寄存器：不查名字表，但用 ARM 的规范编码形式如实表示，
    // 信息一点没少（`TPIDR_EL0` 就是 `s3_3_c13_c0_2`）。
    let (decoder, insn) = decode(&[0x53, 0xd0, 0x3b, 0xd5], 0x00);
    let text = format_insn(&decoder, &insn);
    assert!(
        text.contains("s3_3_c13_c0_2"),
        "系统寄存器应渲染成规范编码形式，实际 `{text}`"
    );
}

/// 屏障选项必须**按名**渲染：`dsb` / `dsb sy` / `dsb ish` 是三条不同的屏障。
#[test]
fn barrier_options_are_rendered_by_name() {
    let cases: &[(&[u8], u64, &str)] = &[
        (&[0x9f, 0x3f, 0x03, 0xd5], 0x24, "dsb sy"),
        (&[0x9f, 0x3b, 0x03, 0xd5], 0x28, "dsb ish"),
        (&[0xbf, 0x33, 0x03, 0xd5], 0x30, "dmb osh"),
        (&[0xdf, 0x3f, 0x03, 0xd5], 0x38, "isb"),
    ];

    for (bytes, addr, expected) in cases {
        let (decoder, insn) = decode(bytes, *addr);
        let text = format_insn(&decoder, &insn);
        assert_eq!(text, *expected, "{addr:#x}：屏障选项渲染不对");
    }
}
