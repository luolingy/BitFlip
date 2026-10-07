//! 对齐填充的识别：哪些字节是**编译器/链接器用来对齐的填充**，而不是真实指令。
//!
//! # 为什么在 `bitflip-arch` 里
//!
//! "填充长什么样"是纯粹的指令集知识：x86 用 `90`（nop）、`CC`（int3）、
//! `66 66 ... 0F 1F /0`（多字节 nop），AArch64 用 `1F 20 03 D5`（`nop`）或
//! `00 00 00 00`，RISC-V 用 `13 00 00 00`。字节形状与指令集绑定，与
//! "拿这个判断来干什么"无关。
//!
//! # 它曾经住在 `bitflip-core/src/analysis.rs` 里
//!
//! 那里有一份按字节匹配 x86 填充的实现（`is_import_thunk_tail`），用来判断
//! "一个间接跳转桩后面是不是只剩填充"。分层门禁按**标识符**匹配
//! （`Arch::X86_64`、`x86_64` 之类的记号），抓不到操作码字节，所以它一直是绿的。
//!
//! 后果不是理论上的：拿 x86 的字节去匹配 arm 目标，会把普通代码认成桩。
//! 实测 `elf-armv7.o` 上就凭空多出一个"导入桩"函数。现在判据按架构分派，
//! 非 x86 目标如实返回"不是填充"。
//!
//! # 判据宁可窄，不可宽
//!
//! 认错的代价不对称：把一个填充字节当成真实指令，最多是少认一个桩；
//! 把一个真实指令当成填充，会让一段**有代码**的位置被说成"什么都没有"，
//! 于是真正的函数被漏掉。所以这里只认编译器实际会生成的填充序列，
//! 不把"解不出指令的字节"一律算成填充 —— 后者是另一种形式的编造。

use crate::types::{Arch, ArchSpec, Endian};

/// `bytes` 开头有多少字节是**对齐填充**。
///
/// 返回 `0` 表示第一个字节不是填充（不是错误，是正常结果）。
///
/// 两种边界行为是刻意的，调用方依赖它们：
///
/// * **填充序列被缓冲区截断**（例如前缀一直顶到末尾）时，按"填充到末尾"处理。
///   调用方拿的是一个固定窗口，窗口切在填充中间不代表那段不是填充；
/// * 不认识的架构返回 `0`，而不是退回按某个架构的字节猜。
#[must_use]
pub fn padding_len(spec: ArchSpec, bytes: &[u8]) -> usize {
    match (spec.arch, spec.mode, spec.endian) {
        (Arch::X86_64, _, Endian::Little) | (Arch::X86, _, Endian::Little) => x86_padding(bytes),
        // 其余架构如实返回 0：**不做**"通用启发式"。AArch64 的 `nop` 是
        // `1F 20 03 D5`、RISC-V 的是 `13 00 00 00`，各有各的形状；
        // 在没有真实样本验证过的前提下写一张表，只会让"这是填充"变成猜测。
        _ => 0,
    }
}

/// x86/x86_64 的填充序列长度。
fn x86_padding(bytes: &[u8]) -> usize {
    // `66` 是 operand-size 前缀，**它本身不是填充**：`66 90` 才是两字节 nop，
    // `66 66 2E 0F 1F 84 00 00 00 00 00` 是补齐到指定长度的长 nop。
    // 所以先跳过前缀，再看后面那条指令是不是无副作用的填充指令 ——
    // 把前缀本身当成填充会让 `66 41 89 ...`（真实的带前缀指令）被误判。
    let mut i = 0usize;
    while bytes.get(i) == Some(&0x66) {
        i += 1;
    }

    match bytes.get(i) {
        // nop
        Some(&0x90) => i + 1,
        // int3：MSVC 的填充字节
        Some(&0xCC) => i + 1,
        // 多字节 nop：`0F 1F /0`，长度由 ModRM 决定（无内存操作数时按 0 算）。
        //
        // 这是 Intel 在 2006 年之后推荐的 nop；`0F 1F` 带 ModRM 的编码长度
        // 是 3 + disp，所以 `0F 1F 00` = 3 字节、`0F 1F 40 00` = 4 字节、
        // `0F 1F 80 00 00 00 00` = 7 字节。
        Some(&0x0F) if bytes.get(i + 1) == Some(&0x1F) => {
            let modrm = bytes.get(i + 2).copied().unwrap_or(0);
            let extra = match (modrm >> 6) & 3 {
                0 => 0, // 无位移
                1 => 1, // disp8
                2 => 4, // disp32
                _ => 0, // `_` 是寄存器模式，不带位移
            };
            // 截断时只算到缓冲区末尾（见函数文档的边界行为）。
            (i + 3 + extra).min(bytes.len())
        }
        // 前缀后面接的不是填充指令：整段都不算填充。
        Some(_) => 0,
        // 全是前缀、顶到缓冲区末尾：按填充到末尾处理。
        None => i,
    }
}

/// 该架构是否实现了填充识别。
///
/// 与 [`crate::supports_plt_stub`] 同样的用意：让上层能区分
/// "扫过了，没有填充"与"这个架构根本不判填充"，并把后者写进 notes ——
/// 否则"没找到桩"会被读成"这里没有桩"，而真实原因是没人实现这个架构的判据。
#[must_use]
pub const fn supports_padding(spec: ArchSpec) -> bool {
    matches!(
        (spec.arch, spec.mode, spec.endian),
        (Arch::X86_64, _, Endian::Little) | (Arch::X86, _, Endian::Little)
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn single_byte_padding_is_recognised() {
        assert_eq!(padding_len(ArchSpec::x86_64(), &[0x90]), 1, "nop");
        assert_eq!(padding_len(ArchSpec::x86_64(), &[0xCC]), 1, "int3");
        // 连续的填充要一次只报一条指令的量：调用方循环调用它。
        assert_eq!(padding_len(ArchSpec::x86_64(), &[0x90, 0x90]), 1);
    }

    #[test]
    fn the_operand_size_prefix_is_transparent_not_padding() {
        // `66 90` 是两字节 nop，整体算填充（2 字节）。
        assert_eq!(padding_len(ArchSpec::x86_64(), &[0x66, 0x90]), 2);
        // `66 66 0F 1F 00` 是长短 nop，整体 5 字节。
        assert_eq!(
            padding_len(ArchSpec::x86_64(), &[0x66, 0x66, 0x0F, 0x1F, 0x00]),
            5
        );
        // 关键的反例：`66 41 89 e5`（带前缀的真实指令 `mov r13d, esp`）
        // 必须**不**被当成填充。把前缀本身当填充就会在这里出错。
        assert_eq!(
            padding_len(ArchSpec::x86_64(), &[0x66, 0x41, 0x89, 0xE5]),
            0
        );
    }

    #[test]
    fn multi_byte_nops_count_their_displacement() {
        // `0F 1F 00` = 3 字节；`0F 1F 40 00` = 4；`0F 1F 80 00 00 00 00` = 7。
        assert_eq!(padding_len(ArchSpec::x86_64(), &[0x0F, 0x1F, 0x00]), 3);
        assert_eq!(
            padding_len(ArchSpec::x86_64(), &[0x0F, 0x1F, 0x40, 0x00]),
            4
        );
        assert_eq!(
            padding_len(
                ArchSpec::x86_64(),
                &[0x0F, 0x1F, 0x80, 0x00, 0x00, 0x00, 0x00]
            ),
            7
        );
        // `0F 1F` 后接**寄存器模式** ModRM（`C0` = mod 3）没有位移。
        assert_eq!(padding_len(ArchSpec::x86_64(), &[0x0F, 0x1F, 0xC0]), 3);
    }

    #[test]
    fn real_instructions_are_not_padding() {
        let spec = ArchSpec::x86_64();
        assert_eq!(padding_len(spec, &[0x55]), 0, "push rbp");
        assert_eq!(padding_len(spec, &[0x48, 0x89, 0xE5]), 0, "mov rbp, rsp");
        // 零字节**不是**填充：`00 00` 解出来是 `add [rax], al`，
        // 是一条真实指令。把它们当填充会让一段有代码的区间被说成空的。
        assert_eq!(padding_len(spec, &[0x00, 0x00]), 0);
        // `0F` 后面不是 `1F`：是别的指令（`0F 05` = syscall）。
        assert_eq!(padding_len(spec, &[0x0F, 0x05]), 0);
        assert_eq!(
            padding_len(spec, &[0x0F]),
            0,
            "单独一个 0F 解不出指令，不算填充"
        );
    }

    #[test]
    fn a_sequence_cut_off_by_the_buffer_edge_counts_as_padding() {
        let spec = ArchSpec::x86_64();
        // 前缀顶到末尾：调用方给的是固定窗口，窗口切在填充中间不代表不是填充。
        assert_eq!(padding_len(spec, &[0x66]), 1);
        assert_eq!(padding_len(spec, &[0x66, 0x66]), 2);
        // 多字节 nop 的 ModRM 缺失：算到缓冲区末尾。
        assert_eq!(padding_len(spec, &[0x0F, 0x1F]), 2);
        assert_eq!(padding_len(spec, &[0x0F, 0x1F, 0x40]), 3);
        // 空缓冲区。
        assert_eq!(padding_len(spec, &[]), 0);
    }

    #[test]
    fn other_architectures_report_no_padding_instead_of_reading_x86_bytes() {
        // 同样的字节在 AArch64 上是别的指令。拿 x86 的判据去匹配 arm 目标，
        // 会把普通代码认成"填充"，进而把有代码的位置说成空的 ——
        // 实测这曾在 elf-armv7.o 上凭空多出一个"导入桩"函数。
        let aarch64 = ArchSpec::aarch64();
        for bytes in [
            &[0x90u8][..],
            &[0xCC][..],
            &[0x0F, 0x1F, 0x00][..],
            &[0x66, 0x90][..],
        ] {
            assert_eq!(
                padding_len(aarch64, bytes),
                0,
                "AArch64 上不得按 x86 字节判填充：{bytes:02x?}"
            );
        }
        assert!(!supports_padding(aarch64));
        assert!(supports_padding(ArchSpec::x86_64()));
    }

    #[test]
    fn some_implies_progress() {
        // 调用方的循环是 `i += padding_len(...)`，所以只要返回值非 0，
        // 就必须真的前进 —— 否则会死循环。这条测试把这个约定钉住。
        let spec = ArchSpec::x86_64();
        for bytes in [
            &[0x90u8][..],
            &[0x66][..],
            &[0x0F, 0x1F][..],
            &[0x0F, 0x1F, 0x80, 0x00, 0x00, 0x00, 0x00][..],
        ] {
            let n = padding_len(spec, bytes);
            assert!(n >= 1, "非 0 的返回值必须至少前进 1 字节：{bytes:02x?}");
            assert!(n <= bytes.len(), "返回值不得超过缓冲区长度：{bytes:02x?}");
        }
    }
}
