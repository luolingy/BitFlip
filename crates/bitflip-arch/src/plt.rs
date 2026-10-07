//! PLT 桩（procedure linkage table stub）的**形状**识别。
//!
//! # 为什么这件事必须在 `bitflip-arch` 里
//!
//! "哪些字节是一条 PLT 桩"是纯粹的架构知识：x86_64 是
//! `jmp *[rip+disp32]`（`ff 25`），i386 是 `jmp *[imm32]`（`ff 25` + 绝对地址），
//! AArch64 是 `adrp` + `ldr` + `br` 三连。把它写进 `bitflip-analyze` 或
//! `bitflip-core`，分层门禁会（正确地）拦下来 —— 那一层的职责是
//! "桩跳的是哪个 GOT 槽、那个槽对应哪个导入符号"，与"桩长什么样"无关。
//!
//! # 这里只回答一个问题：这个位置跳的是哪个槽
//!
//! `plt_stub` **不**判断"这是不是一个导入"、"该叫什么名字"。
//! 那些要拿重定位表对照，属于上层。这样切分的好处是每一层都能单独被验证：
//! 本模块的测试是一串写死的字节（来自真实 `.so` 的反汇编），
//! 上层的测试则是"槽地址对上重定位后名字对不对"。
//!
//! # 识别不出来是正常结果
//!
//! 返回 `None` 涵盖三种情况：这里的字节不是桩、这个架构还没有实现桩识别、
//! 字节不够长。调用方一律**不命名**（保留"未识别"），而不是退回启发式猜一个 ——
//! 见 CLAUDE.md §7。因此本模块的覆盖是不对称的：漏认一个桩只是少一个名字，
//! 误认一个桩会让一个普通函数被叫成 `foo@plt`。

use crate::types::{Arch, ArchSpec, Endian, Mode};

/// 识别出来的一条 PLT 桩。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PltStub {
    /// 桩跳转时读取的内存槽地址（ELF 的 GOT 槽 / PE 的 IAT 槽）。
    ///
    /// 上层拿它去重定位表里找"这个槽位对应哪个导入符号"。
    pub slot: u64,
}

/// 识别 `addr` 处的一条 PLT 桩。
///
/// `bytes` 是 `addr` 起的原始字节，长度足够时才能给出结论；不足时返回 `None`
/// 而不是"用剩下的字节凑一个"。
#[must_use]
pub fn plt_stub(spec: ArchSpec, bytes: &[u8], addr: u64) -> Option<PltStub> {
    match (spec.arch, spec.mode, spec.endian) {
        // x86_64：`jmp qword ptr [rip + disp32]`
        //
        // 这是 PIC 共享库的 .plt 每条桩的第一条指令。RIP 相对是 64 位 ELF 的
        // 强制性要求，所以位移是**相对下一条指令**的有符号 32 位。
        (Arch::X86_64, Mode::M64, Endian::Little) => {
            let bytes = bytes.get(..6)?;
            if bytes[0] != 0xff || bytes[1] != 0x25 {
                return None;
            }
            let disp = i32::from_le_bytes([bytes[2], bytes[3], bytes[4], bytes[5]]);
            // 下一条指令的地址 + 位移。用 wrapping 是有意的：畸形输入下
            // 溢出只会得到一个对不上任何重定位的槽地址，上层于是不命名 ——
            // 这比 panic 好，也与"分析器崩溃必须转成错误"的约定一致。
            let slot = addr.wrapping_add(6).wrapping_add_signed(i64::from(disp));
            Some(PltStub { slot })
        }

        // i386：`jmp *imm32` —— 32 位没有 RIP 相对，槽地址是绝对地址，
        // 而且是**小端直接写在指令里**的，不是位移。
        (Arch::X86, Mode::M32, Endian::Little) => {
            let bytes = bytes.get(..6)?;
            if bytes[0] != 0xff || bytes[1] != 0x25 {
                return None;
            }
            let slot = u64::from(u32::from_le_bytes([bytes[2], bytes[3], bytes[4], bytes[5]]));
            Some(PltStub { slot })
        }

        // 其余架构目前**如实不识别**：AArch64 的桩是 `adrp`/`ldr`/`br` 三连、
        // 需要解出两条指令的立即数才能算出槽地址。在拿到一个真实的 AArch64
        // 共享库用作对照之前不写 —— 没有对照的架构代码只能靠"看起来对"通过，
        // 而那正是 M6 在展开信息操作码表上栽过的坑。
        _ => None,
    }
}

/// 该架构是否实现了 PLT 桩识别。
///
/// 存在的意义是让上层能区分"扫过了，一条都没找到"与"这个架构根本不扫"，
/// 并把后者写进 `notes` —— 否则在 AArch64 上"没有导入符号名"会被读成
/// "这个目标没有导入"，而真实原因是没人实现。
#[must_use]
pub const fn supports_plt_stub(spec: ArchSpec) -> bool {
    matches!(
        (spec.arch, spec.mode, spec.endian),
        (Arch::X86_64, Mode::M64, Endian::Little) | (Arch::X86, Mode::M32, Endian::Little)
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    /// 字节取自 `tests/fixtures/generated/libsample.so` 的真实反汇编：
    ///
    /// ```text
    /// 0000000000001570 <sample_add@plt>:
    ///     1570: ff 25 2a 21 00 00   jmpq  *0x212a(%rip)   # 0x36a0
    /// ```
    ///
    /// 0x1570 + 6 + 0x212a = 0x36a0，而 `.rela.plt` 里正是
    /// `0x36A0 R_X86_64_JUMP_SLOT sample_add`。
    const X86_64_STUB: &[u8] = &[0xff, 0x25, 0x2a, 0x21, 0x00, 0x00];

    #[test]
    fn an_x86_64_stub_reports_the_slot_it_jumps_through() {
        let stub = plt_stub(ArchSpec::x86_64(), X86_64_STUB, 0x1570).expect("应当识别出桩");
        assert_eq!(stub.slot, 0x36a0);
    }

    #[test]
    fn a_negative_displacement_is_sign_extended() {
        // `jmp *[rip-0x10]`：位移按**有符号**读。当成无符号读会算出
        // 0x1000 + 6 + 0xfffffff0 这种不存在的地址，于是所有桩都对不上
        // 重定位 —— 整个功能静默失效。这与 M6 在跳转表表项上栽的是同一个坑。
        let bytes = [0xffu8, 0x25, 0xf0, 0xff, 0xff, 0xff];
        let stub = plt_stub(ArchSpec::x86_64(), &bytes, 0x1000).expect("应当识别出桩");
        assert_eq!(stub.slot, 0x1000 + 6 - 0x10);
    }

    #[test]
    fn an_i386_stub_reads_an_absolute_slot_address() {
        // i386 没有 RIP 相对：立即数就是槽地址本身（0x0804a000）。
        let bytes = [0xffu8, 0x25, 0x00, 0xa0, 0x04, 0x08];
        let spec = ArchSpec::from_arch(Arch::X86, Mode::M32, Endian::Little);
        let stub = plt_stub(spec, &bytes, 0x8049000).expect("应当识别出桩");
        assert_eq!(stub.slot, 0x0804a000);
    }

    #[test]
    fn unrelated_bytes_are_not_a_stub() {
        let spec = ArchSpec::x86_64();
        // 普通的 `mov eax, [rip+disp]`（8b 05）不是跳转
        assert_eq!(
            plt_stub(spec, &[0x8b, 0x05, 0x00, 0x00, 0x00, 0x00], 0x1000),
            None
        );
        // 直接跳转 `jmp rel32`（e9）不是间接跳转
        assert_eq!(
            plt_stub(spec, &[0xe9, 0x00, 0x00, 0x00, 0x00, 0x00], 0x1000),
            None
        );
        // 字节不够：不许用短读到的部分凑结论
        assert_eq!(plt_stub(spec, &[0xff, 0x25, 0x00], 0x1000), None);
        assert_eq!(plt_stub(spec, &[], 0x1000), None);
    }

    #[test]
    fn architectures_without_a_stub_spec_say_so_instead_of_guessing() {
        // 同样的字节在 AArch64 上必须**不**被认成桩：那段字节在 AArch64 里
        // 是别的指令。如果 plt_stub 忽略了架构，就会在 ARM 目标上把随机代码
        // 当成 PLT 桩并给它起个错名字。
        assert_eq!(plt_stub(ArchSpec::aarch64(), X86_64_STUB, 0x1570), None);
        assert!(!supports_plt_stub(ArchSpec::aarch64()));
        assert!(supports_plt_stub(ArchSpec::x86_64()));
    }

    #[test]
    fn a_malformed_stub_wraps_instead_of_panicking() {
        // 位移大到足以让"下一条指令地址"回绕：允许回绕成一个对不上任何重定位的
        // 槽地址，但**不许 panic** —— 分析器崩溃必须转成错误而不是进程退出。
        //
        // 这里把回绕结果写死，是为了让"输入畸形时会发生什么"成为一条**被固定的
        // 事实**而不是"大概不会出事"：addr 取 u64::MAX - 4，+6 回绕到 1，
        // 加 0x7fffffff 得 0x80000000。
        let spec = ArchSpec::x86_64();
        let bytes = [0xffu8, 0x25, 0xff, 0xff, 0xff, 0x7f];
        let stub = plt_stub(spec, &bytes, u64::MAX - 4).expect("应当识别出桩");
        assert_eq!(stub.slot, 0x8000_0000);
    }
}
