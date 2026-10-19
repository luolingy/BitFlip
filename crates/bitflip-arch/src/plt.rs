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

/// 识别一条**导入跳板桩**（Mach-O `__stubs` 那种"只为跳进导入槽而生"的桩），
/// 返回它读取的槽地址。
///
/// # 为什么和 [`plt_stub`] 分成两个函数
///
/// 覆盖面不同，而且**不能合并**：
///
/// * [`plt_stub`] 的覆盖面同时被 ELF 的 `.plt` 命名路径使用（`bitflip-core` 的
///   `TargetAnalysis::build`）。给它加 AArch64，ELF/AArch64 目标就会多出
///   `名字@plt` 与相应 notes —— 那是另一件事的行为变更，不该由"调用图要认导入
///   边"顺手带出来。
/// * 本函数只被"目标落在桩节里的调用边"这条路径使用。桩节由调用方按格式判定
///   （Mach-O 的 `__stubs`），因此这里的覆盖面按**实际见到的 Mach-O 桩形态**定义：
///   x86_64 / i386 与 [`plt_stub`] 相同，外加 AArch64 的 `adrp` + `ldr` + `br` 三连。
///
/// # AArch64 的判据与出处
///
/// ```text
/// adrp xN, page          ; 1xx10000 ...                (ARM ARM C6.2.10 ADRP)
/// ldr  xN, [xN, #off]    ; 1111 1001 01 imm12 Rn Rt    (LDR 无符号偏移, 64 位)
/// br   xN                ; 1101 0110 0001 1111 0000 00 Rn 11111 (C6.2.44 BR)
/// ```
///
/// 三条必须**同寄存器**串起来（`adrp` 的目标 = `ldr` 的基址、`ldr` 的目标 =
/// `br` 的寄存器），槽地址 = `align(addr, 4096) + 符号扩展的 imm21 << 12 + imm12 * 8`。
/// 这套判据在 `temp/LiveContainer.ipa` 的主二进制上被两个独立来源对上过：
/// `__TEXT,__stubs` 的 78 条桩全部识别，且 78 条算出的槽地址与链式修复
/// （`LC_DYLD_CHAINED_FIXUPS` 的 bind ordinal）给出的 `iat_slot` **逐一相同**。
///
/// 明确**不**识别（返回 `None`，不猜）：
///
/// * `ldur` / `ldr` 变体（有符号偏移、字面量池形式）与 `ldr w` 形式；
/// * arm64e 的 `braa xN, xM`（认证跳转）—— 真实样本里没见过，没有对照就不写；
/// * 任何中间隔着别的指令的形态（那需要数据流分析，不属于"形状识别"）。
#[must_use]
pub fn import_stub_slot(spec: ArchSpec, bytes: &[u8], addr: u64) -> Option<PltStub> {
    if let Some(stub) = plt_stub(spec, bytes, addr) {
        return Some(stub);
    }
    match (spec.arch, spec.mode, spec.endian) {
        (Arch::Aarch64, Mode::M64, Endian::Little) => aarch64_stub_slot(bytes, addr),
        _ => None,
    }
}

/// 该架构是否实现了 [`import_stub_slot`] 的跳板桩识别。
///
/// 与 [`supports_plt_stub`] 分开的理由同上：两个覆盖面**不相等**。
#[must_use]
pub const fn supports_import_stub(spec: ArchSpec) -> bool {
    matches!(
        (spec.arch, spec.mode, spec.endian),
        (Arch::X86_64, Mode::M64, Endian::Little)
            | (Arch::X86, Mode::M32, Endian::Little)
            | (Arch::Aarch64, Mode::M64, Endian::Little)
    )
}

/// AArch64 三连桩（`adrp` + `ldr` + `br`）。见 [`import_stub_slot`] 的文档。
fn aarch64_stub_slot(bytes: &[u8], addr: u64) -> Option<PltStub> {
    let bytes = bytes.get(..12)?;
    let word = |index: usize| {
        let start = index * 4;
        u32::from_le_bytes([
            bytes[start],
            bytes[start + 1],
            bytes[start + 2],
            bytes[start + 3],
        ])
    };
    let (adrp, ldr, br) = (word(0), word(1), word(2));

    // adrp xD, imm  /  ldr xT, [xN, #imm12]  /  br xR
    if adrp & 0x9F00_0000 != 0x9000_0000
        || ldr & 0xFFC0_0000 != 0xF940_0000
        || br & 0xFFFF_FC1F != 0xD61F_0000
    {
        return None;
    }

    let rd_adrp = adrp & 0x1F;
    let rn_ldr = (ldr >> 5) & 0x1F;
    let rt_ldr = ldr & 0x1F;
    let rn_br = (br >> 5) & 0x1F;
    if rd_adrp != rn_ldr || rt_ldr != rn_br {
        return None;
    }

    // ADRP 的立即数：immlo 在 [30:29]，immhi 在 [23:5]，拼起来是 21 位有符号数，
    // 左移 12 位后加到**本指令所在的页**上（不是指令地址）。
    let immlo = i64::from((adrp >> 29) & 0x3);
    let immhi = i64::from((adrp >> 5) & 0x7_FFFF);
    let imm = ((immhi << 2) | immlo) << 43 >> 43;
    let page = (addr & !0xFFF).wrapping_add_signed(imm << 12);

    // LDR 无符号偏移：imm12 在 [21:10]，按访问宽度（8 字节）缩放。
    let imm12 = u64::from((ldr >> 10) & 0xFFF);
    Some(PltStub {
        slot: page.wrapping_add(imm12.wrapping_mul(8)),
    })
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

    // ── 导入跳板桩（Mach-O `__stubs`）──

    /// 真实字节，取自 `temp/LiveContainer.ipa` 的主二进制
    /// （151 648 字节、aarch64、`__TEXT,__stubs` @ 0x10000b588，节大小 0x3a8）。
    ///
    /// | 桩地址 | 三条指令（小端字） | 槽地址 | 导入 |
    /// | --- | --- | --- | --- |
    /// | 0x10000b588 | `b0000030` `f9400210` `d61f0200` | 0x100010000 | `_CFBundleCreate` |
    /// | 0x10000b594 | `b0000030` `f9400a10` `d61f0200` | 0x100010010 | `_NSClassFromString` |
    /// | 0x10000b5a0 | `b0000030` `f9401e10` `d61f0200` | 0x100010038 | `_NSLog` |
    ///
    /// 槽地址来自**另一个**来源：`LC_DYLD_CHAINED_FIXUPS` 的 bind 链算出的
    /// `ChainedImport::iat_slot`（`chained::walk_chains`），与本函数的算法无关。
    /// 两个独立来源对上才算证据（CLAUDE.md §6.11）；自己按自己的假设拼 fixture
    /// 是自证其说。整条桩节 78 条桩算出的槽地址与导入表**逐一相同**。
    const LIVE_CONTAINER_STUB_CF: [u8; 12] = [
        0x30, 0x00, 0x00, 0xb0, // adrp x16, #0x100010000
        0x10, 0x02, 0x40, 0xf9, // ldr  x16, [x16, #0x0]
        0x00, 0x02, 0x1f, 0xd6, // br   x16
    ];

    /// 按 ARM ARM 的字段位置拼三条指令（用来做"改一处就该不认"的负例）。
    fn stub_bytes(adrp: u32, ldr: u32, br: u32) -> [u8; 12] {
        let mut out = [0u8; 12];
        out[0..4].copy_from_slice(&adrp.to_le_bytes());
        out[4..8].copy_from_slice(&ldr.to_le_bytes());
        out[8..12].copy_from_slice(&br.to_le_bytes());
        out
    }

    fn adrp_word(rd: u32, page_delta: i64) -> u32 {
        let imm = ((page_delta >> 12) as u32) & 0x1F_FFFF;
        let immlo = (imm & 0x3) << 29;
        let immhi = ((imm >> 2) & 0x7_FFFF) << 5;
        0x9000_0000 | immlo | immhi | (rd & 0x1F)
    }

    fn ldr_x_word(rt: u32, rn: u32, offset: u64) -> u32 {
        assert_eq!(offset % 8, 0, "LDR 无符号偏移按 8 字节缩放");
        let imm12 = ((offset / 8) & 0xFFF) as u32;
        0xF940_0000 | (imm12 << 10) | ((rn & 0x1F) << 5) | (rt & 0x1F)
    }

    fn br_word(rn: u32) -> u32 {
        0xD61F_0000 | ((rn & 0x1F) << 5)
    }

    #[test]
    fn the_encoder_helpers_reproduce_the_real_livecontainer_stub() {
        // 拼出来的字必须与真实字节逐字节相同 —— 否则后面那些"改一处就该不认"
        // 的负例测的是一段根本不存在的编码，绿得没有意义。
        assert_eq!(adrp_word(16, 0x1_0001_0000 - 0x1_0000_b000), 0xB000_0030);
        assert_eq!(ldr_x_word(16, 16, 0), 0xF940_0210);
        assert_eq!(br_word(16), 0xD61F_0200);
        assert_eq!(
            stub_bytes(
                adrp_word(16, 0x1_0001_0000 - 0x1_0000_b000),
                ldr_x_word(16, 16, 0),
                br_word(16)
            ),
            LIVE_CONTAINER_STUB_CF
        );
    }

    #[test]
    fn a_macho_aarch64_stub_reports_the_slot_it_jumps_through() {
        let spec = ArchSpec::aarch64();
        let stub = import_stub_slot(spec, &LIVE_CONTAINER_STUB_CF, 0x1_0000_b588)
            .expect("应当识别出 AArch64 三连桩");
        assert_eq!(stub.slot, 0x1_0001_0000, "_CFBundleCreate 的槽位");

        // 第二、三条桩：同一个 adrp，不同的 ldr 立即数（0x10 / 0x38）。
        let second = stub_bytes(
            adrp_word(16, 0x1_0001_0000 - 0x1_0000_b000),
            ldr_x_word(16, 16, 0x10),
            br_word(16),
        );
        assert_eq!(
            import_stub_slot(spec, &second, 0x1_0000_b594).map(|s| s.slot),
            Some(0x1_0001_0010),
            "_NSClassFromString 的槽位"
        );
        let third = stub_bytes(
            adrp_word(16, 0x1_0001_0000 - 0x1_0000_b000),
            ldr_x_word(16, 16, 0x38),
            br_word(16),
        );
        assert_eq!(
            import_stub_slot(spec, &third, 0x1_0000_b5a0).map(|s| s.slot),
            Some(0x1_0001_0038),
            "_NSLog 的槽位"
        );
    }

    #[test]
    fn aarch64_stub_requires_the_three_instructions_to_chain_the_same_register() {
        let spec = ArchSpec::aarch64();
        let page = 0x1_0001_0000 - 0x1_0000_b000;
        let base = 0x1_0000_b588;

        // `br x17` 而 adrp/ldr 用的是 x16：跳的是另一个来源的寄存器，不是一条桩
        let br_wrong = stub_bytes(adrp_word(16, page), ldr_x_word(16, 16, 0), br_word(17));
        assert_eq!(import_stub_slot(spec, &br_wrong, base), None);

        // `ldr` 的基址换成 x17（adrp 写的是 x16）
        let ldr_base_wrong = stub_bytes(adrp_word(16, page), ldr_x_word(16, 17, 0), br_word(16));
        assert_eq!(import_stub_slot(spec, &ldr_base_wrong, base), None);

        // 32 位形式的 `ldr w16, [x16]`（0xB9400000）：槽里放的不是指针，不认
        let ldr_w = stub_bytes(adrp_word(16, page), 0xB940_0210, br_word(16));
        assert_eq!(import_stub_slot(spec, &ldr_w, base), None);
    }

    #[test]
    fn arch_shapes_are_not_mixed_between_plt_and_macho_stubs() {
        // x86_64 的桩字节在 AArch64 上不许被认成桩（否则会算出一个不存在的槽）
        assert_eq!(
            import_stub_slot(ArchSpec::aarch64(), X86_64_STUB, 0x1570),
            None
        );
        // 反过来：AArch64 的三连桩在 x86_64 上也不认
        assert_eq!(
            import_stub_slot(ArchSpec::x86_64(), &LIVE_CONTAINER_STUB_CF, 0x1000),
            None
        );
        // x86_64 的导入跳板桩与 PLT 桩是同一个形状（jmp *[rip+disp32]）
        let stub = import_stub_slot(ArchSpec::x86_64(), X86_64_STUB, 0x1570).expect("x86_64 桩");
        assert_eq!(stub.slot, 0x36a0);
    }

    #[test]
    fn aarch64_stub_decodes_a_negative_adrp_immediate() {
        // adrp 的立即数往**低地址**跳：页 = align(addr) - 0x1000。
        // 按无符号读会算出一个高得离谱的槽地址，于是所有桩都对不上导入 ——
        // 静默失效，和 `jmp *[rip-0x10]` 那个坑同源。
        let spec = ArchSpec::aarch64();
        let bytes = stub_bytes(
            adrp_word(16, -0x1000),
            ldr_x_word(16, 16, 0x10),
            br_word(16),
        );
        let stub = import_stub_slot(spec, &bytes, 0x2000).expect("应当识别出桩");
        assert_eq!(stub.slot, 0x1010);
    }

    #[test]
    fn short_or_unrelated_bytes_are_not_an_aarch64_stub() {
        let spec = ArchSpec::aarch64();
        assert_eq!(import_stub_slot(spec, &[], 0x1000), None);
        assert_eq!(import_stub_slot(spec, &[0u8; 11], 0x1000), None);
        assert_eq!(import_stub_slot(spec, &[0u8; 12], 0x1000), None);
        // `nop; nop; nop`
        assert_eq!(
            import_stub_slot(
                spec,
                &stub_bytes(0xD503_201F, 0xD503_201F, 0xD503_201F),
                0x1000
            ),
            None
        );
    }

    #[test]
    fn import_stub_support_is_wider_than_plt_support_and_says_which() {
        // 这两个覆盖面**故意不相等**：ELF 的 .plt 命名路径仍按 supports_plt_stub
        // 判断，AArch64 的 Mach-O 桩只走 supports_import_stub。钉住这条差异，
        // 免得日后有人"顺手"把两个函数合并、连带改掉 ELF/AArch64 的行为。
        assert!(!supports_plt_stub(ArchSpec::aarch64()));
        assert!(supports_import_stub(ArchSpec::aarch64()));
        assert!(supports_plt_stub(ArchSpec::x86_64()));
        assert!(supports_import_stub(ArchSpec::x86_64()));
        // 没实现的架构一律如实回答 false（上层据此写 notes）
        let armv7 = ArchSpec::from_arch(Arch::Arm, Mode::Thumb, Endian::Little);
        assert!(!supports_plt_stub(armv7));
        assert!(!supports_import_stub(armv7));
    }
}
