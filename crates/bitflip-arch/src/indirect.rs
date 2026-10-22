//! 间接调用目标的**前驱恢复**（AArch64）。
//!
//! ## 问题
//!
//! `blr x8` 的目标不在指令编码里 —— 它在一个**寄存器**里。M6 的立场是
//! "不做数据流分析，未解析就如实标未解析"，于是真实二进制上那十几处
//! `blr x8` 全都断开在图外。但其中一部分并不需要数据流分析：那条寄存器
//! 的定义就写在**同一条直线上的前一条或前几条**指令里。
//!
//! ```text
//! adrp x8, 0x100014000        ; 页面基址
//! ldr  x8, [x8, #0x7c0]       ; 从这个槽里读一个指针
//! blr  x8                     ; 调它
//! ```
//!
//! 这是**可证明的**：只要中间没有任何指令改写 `x8`、也没有调用（调用会
//! 改写 caller-saved 寄存器），`blr` 的目标就是那个槽里的值。本模块只做
//! 这种"目视可查"的恢复，不做任何猜测 —— 证明不了就返回 `None`，让调用
//! 方继续如实报"未解析"（CLAUDE.md §7）。
//!
//! ## 两种结论，形状不同
//!
//! * [`RecoveredTarget::Slot`]：`adrp` + `ldr` 取到一个**内存槽**。槽里的
//!   值在静态文件里读不出来（可能是导入槽、可能是运行时才填的缓存）。
//!   所以这里只交出**槽的地址** —— 它是不是某个导入，由上层拿导入表去比
//!   （`bitflip-core::import_edges` 的规则 1 正是"目标等于某个导入槽"）。
//! * [`RecoveredTarget::Address`]：`adrp` + `add` 算出一个**镜像内绝对地址**。
//!   这是"这个函数的地址"，能直接交给函数归属去判定。
//!
//! ## 为什么不做得更宽
//!
//! * **追踪任意寄存器传递**（`mov x9, x8` 链、跨基本块、栈槽）就是数据流
//!   分析，不在本层承诺范围内。
//! * **带索引寻址的 `ldr`**（`[x8, x9, lsl #3]`）当"证明不了"：索引意味着
//!   值依赖另一个寄存器。
//! * **`ldur` / 成对加载**（`ldp`）不认：它们的语义不同，认错会让一条边
//!   指向错误的地址，比留空更糟。
//! * **arm64e 的 `braa`/`blraa`**：capstone 把 `blraa` 报成 `Flow::Call`、
//!   目标寄存器是第一个操作数，所以本模块对它们**自动生效** —— 但手里没有
//!   真实 arm64e 样本，这条路径只有合成编码的单测，没有真实样本验收。
//! * **x86_64 / 其他架构**一律 `None`：`call [rip+disp]` 是另一套形态，本
//!   模块不认（如实不识别，而不是猜）。

use crate::insn::{DecodedInsn, Flow, Operand, RegId};
use crate::types::Arch;

/// 往前最多看多少条指令。
///
/// 真实形态里 `adrp` + `ldr` + `blr` 是连续的（LiveContainer 的两处在
/// `blr` 前 2 条），8 条足够覆盖"中间夹了几个 mov 参数"的情况；再多就没有
/// "直线可查"的把握了（中间大概率有分支）。
pub const MAX_SCAN: usize = 8;

/// 恢复出的间接调用目标。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RecoveredTarget {
    /// 通过一个内存槽间接调用：`adrp xN, #page` + `ldr xN, [xN, #off]`。
    ///
    /// `slot = page + off`。槽里装什么，本层不知道 —— 上层拿去比导入表，
    /// 或者如实告诉用户"值在这个槽里"。
    Slot {
        /// 槽的虚拟地址。
        slot: u64,
    },
    /// 算出来的是镜像内绝对地址：`adrp xN, #page` + `add xN, xN, #off`
    /// （或单条 `adrp`）。
    Address {
        /// 目标地址。
        addr: u64,
    },
}

/// capstone 的 AArch64 助记符编号（`DecodedInsn::mnemonic` 就是它）。
///
/// 为什么要比编号而不是比渲染出来的文本：渲染是**输出层**的事
/// （`render` 模块的文档写明"绝不让上层去 parse 指令文本"），文本还会随
/// 显示风格变化；编号是解码阶段的稳定事实。
mod ids {
    use capstone::arch::arm64::Arm64Insn;

    pub const ADRP: u32 = Arm64Insn::ARM64_INS_ADRP as u32;
    pub const LDR: u32 = Arm64Insn::ARM64_INS_LDR as u32;
    pub const ADD: u32 = Arm64Insn::ARM64_INS_ADD as u32;
}

/// 试着恢复 `insns[index]` 这条间接调用的目标。
///
/// 只在**确实能证明**时返回 `Some`；调用方拿到 `None` 时必须继续如实报
/// "未解析"，不得用零地址或占位名代替。
#[must_use]
pub fn recover_indirect_call_target(
    insns: &[DecodedInsn],
    index: usize,
) -> Option<RecoveredTarget> {
    let call = insns.get(index)?;
    if call.arch != Arch::Aarch64 {
        return None;
    }
    // 只处理"编码里没有目标"的调用（直接调用轮不到这里）。
    if call.flow != Flow::Call || call.target.is_some() {
        return None;
    }
    // `blr xN` / `blraa xN, xM`：目标寄存器是**第一个**操作数。
    let Operand::Reg(target_reg) = *call.operands.first()? else {
        return None;
    };

    // 往前找"谁定义了 target_reg"。找到的必须是一条能算出地址的指令，
    // 否则整条链作废（不跳过它继续往前找 —— 跳过就等于假设它不影响值）。
    let mut j = index;
    let mut steps = 0;
    while j > 0 && steps < MAX_SCAN {
        j -= 1;
        steps += 1;
        let prev = &insns[j];
        if prev.arch != Arch::Aarch64 {
            return None;
        }
        // 调用会改写 caller-saved 寄存器（x0–x18），证明链断在这里。
        if prev.flow == Flow::Call {
            return None;
        }
        // 块边界（返回、无条件跳转、条件跳转）之后没有"直线前驱"可言。
        if prev.flow.ends_block() {
            return None;
        }
        if !prev.writes.contains(target_reg) {
            continue;
        }
        return classify_definition(insns, j);
    }
    None
}

/// 定义寄存器的那条指令能不能算出地址。
fn classify_definition(insns: &[DecodedInsn], index: usize) -> Option<RecoveredTarget> {
    let insn = &insns[index];
    let mnemonic = insn.mnemonic.0;

    // `adrp xN, #page`：单条就给出页基址。
    if mnemonic == ids::ADRP {
        let page = imm_of(insn)?;
        return Some(RecoveredTarget::Address { addr: page as u64 });
    }

    // `ldr xN, [xB, #off]`：槽加载。带索引寻址的一律不认（值依赖另一个寄存器）。
    if mnemonic == ids::LDR {
        let Operand::Mem(mem) = *insn.operands.get(1)? else {
            return None;
        };
        if mem.index.is_some() {
            return None;
        }
        let base = mem.base?;
        let page = find_adrp_page(insns, index, base)?;
        let slot = page.checked_add_signed(mem.disp)?;
        return Some(RecoveredTarget::Slot { slot });
    }

    // `add xN, xB, #off`：镜像内地址。
    if mnemonic == ids::ADD {
        let off = imm_of_at(insn, 2)?;
        let Operand::Reg(base) = *insn.operands.get(1)? else {
            return None;
        };
        // `add xN, xN, #off`（自增）与 `add xN, xB, #off` 都要求 xB 来自 adrp。
        let page = find_adrp_page(insns, index, base)?;
        let addr = page.checked_add_signed(off)?;
        return Some(RecoveredTarget::Address { addr });
    }

    // 其余形态（`mov` / `ldur` / `ldp` / 算术链）一律证明不了。
    None
}

/// 从 `before` 往前找"定义了 `reg` 的 `adrp`"，返回它的页基址。
///
/// 中间出现调用、块边界、或对 `reg` 的另一次写，就说明这条 `adrp` 不再
/// 支配那个用途 —— 返回 `None` 而不是硬凑。
fn find_adrp_page(insns: &[DecodedInsn], before: usize, reg: RegId) -> Option<u64> {
    let mut j = before;
    let mut steps = 0;
    while j > 0 && steps < MAX_SCAN {
        j -= 1;
        steps += 1;
        let prev = &insns[j];
        if prev.arch != Arch::Aarch64 {
            return None;
        }
        if prev.flow == Flow::Call || prev.flow.ends_block() {
            return None;
        }
        if !prev.writes.contains(reg) {
            continue;
        }
        if prev.mnemonic.0 != ids::ADRP {
            return None;
        }
        return imm_of(prev).map(|page| page as u64);
    }
    None
}

/// 第 `at` 个操作数是立即数时返回它。
fn imm_of_at(insn: &DecodedInsn, at: usize) -> Option<i64> {
    match insn.operands.get(at)? {
        Operand::Imm(value) => Some(*value),
        _ => None,
    }
}

/// `adrp xN, #imm` 的立即数（第二个操作数）。
fn imm_of(insn: &DecodedInsn) -> Option<i64> {
    imm_of_at(insn, 1)
}

#[cfg(test)]
#[allow(clippy::unusual_byte_groupings)] // 测试里的地址字面量按节偏移紧凑书写
mod tests {
    use super::*;
    use crate::decode::decoder_for;

    /// 真实字节：`temp/LiveContainer.ipa` 主二进制 `_hook_dyld_image_count`
    /// （0x100006558），三条指令原样抄自 `llvm-objdump -d`：
    ///
    /// ```text
    /// 100006560: d0000068   adrp x8, 0x100014000
    /// 100006564: f943e108   ldr  x8, [x8, #0x7c0]
    /// 100006568: d63f0100   blr  x8
    /// ```
    ///
    /// 期望值是 objdump 自己的注解算出来的：`0x100014000 + 0x7c0 = 0x1000147c0`。
    fn real_got_load_bytes() -> Vec<u8> {
        let words: [u32; 3] = [0xd000_0068, 0xf943_e108, 0xd63f_0100];
        words.iter().flat_map(|w| w.to_le_bytes()).collect()
    }

    fn decode(bytes: &[u8], addr: u64) -> Vec<DecodedInsn> {
        decoder_for(crate::ArchSpec::aarch64()).decode_many(bytes, addr, 64)
    }

    #[test]
    fn real_got_load_call_recovers_the_slot_address() {
        let insns = decode(&real_got_load_bytes(), 0x1_0000_6560);
        assert_eq!(insns.len(), 3, "三条指令都要解出来：{insns:#?}");
        assert_eq!(insns[2].flow, Flow::Call);
        assert_eq!(insns[2].target, None, "`blr` 编码里没有目标");

        let target = recover_indirect_call_target(&insns, 2)
            .expect("真实形态必须能恢复（adrp + ldr + blr）");
        assert_eq!(
            target,
            RecoveredTarget::Slot {
                slot: 0x1_0001_47c0
            }
        );
    }

    /// `adrp x8` + `add x8, x8, #0x30` + `blr x8`：算出镜像内地址。
    ///
    /// 编码照 ARM ARM 的 ADRP / ADD (immediate) 字段拼：
    /// `0x90000008 = adrp x8, #<PC 页>`（immlo = immhi = 0，Rd = 8）、
    /// `0x9100c108 = add x8, x8, #0x30`（imm12 = 0x30，shift 0，Rn = Rd = 8）。
    #[test]
    fn adrp_plus_add_recovers_an_in_image_address() {
        let words: [u32; 3] = [0x9000_0008, 0x9100_c108, 0xd63f_0100];
        let bytes: Vec<u8> = words.iter().flat_map(|w| w.to_le_bytes()).collect();
        // 地址取 0x100000000：adrp 的页 = PC 页 + imm<<12，这里 imm = 0 → 页 0x100000000。
        let insns = decode(&bytes, 0x1_0000_0000);
        assert_eq!(insns.len(), 3, "{insns:#?}");

        let Some(RecoveredTarget::Address { addr }) = recover_indirect_call_target(&insns, 2)
        else {
            panic!("adrp + add 必须恢复成地址：{insns:#?}");
        };
        assert_eq!(addr, 0x1_0000_0030);
    }

    /// 中间有对寄存器的另一次写：证明链断了，不许硬凑。
    #[test]
    fn a_redefinition_breaks_the_proof() {
        // adrp x8 / ldr x8,[x8,#8] / mov x8, x0 / blr x8
        let words: [u32; 4] = [0xb000_0008, 0xf940_0508, 0xaa00_03e8, 0xd63f_0100];
        let bytes: Vec<u8> = words.iter().flat_map(|w| w.to_le_bytes()).collect();
        let insns = decode(&bytes, 0x1_0000_0000);
        assert!(
            recover_indirect_call_target(&insns, 3).is_none(),
            "{insns:#?}"
        );
    }

    /// 中间夹一次调用：caller-saved 可能被改写，证明链断。
    #[test]
    fn a_call_clobbers_the_proof() {
        // adrp x8 / bl somewhere / blr x8
        let words: [u32; 3] = [0xb000_0008, 0x9400_0002, 0xd63f_0100];
        let bytes: Vec<u8> = words.iter().flat_map(|w| w.to_le_bytes()).collect();
        let insns = decode(&bytes, 0x1_0000_0000);
        assert!(
            recover_indirect_call_target(&insns, 2).is_none(),
            "{insns:#?}"
        );
    }

    /// 直接调用（`bl`）不归本模块管：编码里有目标，恢复逻辑不该插嘴。
    #[test]
    fn direct_calls_are_not_touched() {
        let words: [u32; 1] = [0x9400_0002];
        let bytes: Vec<u8> = words.iter().flat_map(|w| w.to_le_bytes()).collect();
        let insns = decode(&bytes, 0x1_0000_0000);
        assert!(insns[0].target.is_some());
        assert!(recover_indirect_call_target(&insns, 0).is_none());
    }

    /// 带索引寻址的 `ldr x8, [x8, x9]` 不认：值依赖另一个寄存器。
    #[test]
    fn indexed_loads_are_not_recovered() {
        // adrp x8 / ldr x8, [x8, x9] / blr x8
        let words: [u32; 3] = [0xb000_0008, 0xf869_6908, 0xd63f_0100];
        let bytes: Vec<u8> = words.iter().flat_map(|w| w.to_le_bytes()).collect();
        let insns = decode(&bytes, 0x1_0000_0000);
        assert!(
            recover_indirect_call_target(&insns, 2).is_none(),
            "{insns:#?}"
        );
    }
}
