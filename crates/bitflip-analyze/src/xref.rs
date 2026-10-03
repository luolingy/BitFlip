//! 交叉引用提取：代码引用与数据引用。
//!
//! xref 的来源有两类，处理方式完全不同：
//!
//! - **代码引用**（call/jmp）：目标就在指令里（直接寻址），
//!   从 [`bitflip_arch::DecodedInsn::target`] 直接读。
//! - **数据引用**（rip-relative / 绝对地址）：藏在内存操作数里。
//!   x64 上访问全局变量是 `mov eax, [rip+0x1234]`，
//!   目标地址 = 下一条指令地址 + disp，必须用**下一条指令的地址**算，
//!   不是本条 —— 这是 x64 编码的规则，也是最容易做错的地方。
//!
//! 间接引用（`call [rax+0x10]`、跳转表）**明确标记为未解析**，
//! 不猜目标（PLAN §M3 风险：间接引用是覆盖率瓶颈，M6 强化）。

use bitflip_arch::{DecodedInsn, Flow, Operand};

/// 一条交叉引用。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Xref {
    /// 引用的发起地址（指令地址）。
    pub from: u64,
    /// 被引用的地址。
    pub to: u64,
    /// 引用类型。
    pub kind: XrefKind,
}

/// 引用类型。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum XrefKind {
    /// 调用（直接）。
    Call,
    /// 跳转（直接，含条件）。
    Jump,
    /// 数据访问（rip-relative / 绝对地址读写）。
    Data,
}

impl XrefKind {
    /// 稳定短名（wire 用）。
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Call => "call",
            Self::Jump => "jump",
            Self::Data => "data",
        }
    }
}

/// 从单条指令提取 xref。
///
/// 返回 0–2 条：直接调用/跳转 1 条；rip-relative 数据访问 1 条；
/// 两者都有（罕见）时 2 条。
#[must_use]
pub fn xrefs_of(insn: &DecodedInsn) -> Vec<Xref> {
    let mut out = Vec::with_capacity(2);

    // 代码引用：只要 target 存在且不是本条指令自身（自循环也算 xref，
    // 但 target == addr 时是死循环标记，保留它 —— 跳转表识别要靠它）
    match insn.flow {
        Flow::Call => {
            if let Some(to) = insn.target {
                out.push(Xref {
                    from: insn.addr,
                    to,
                    kind: XrefKind::Call,
                });
            }
        }
        Flow::Branch { .. } => {
            if let Some(to) = insn.target {
                out.push(Xref {
                    from: insn.addr,
                    to,
                    kind: XrefKind::Jump,
                });
            }
        }
        // Fallthrough / Return / Trap / Unknown：无代码目标
        _ => {}
    }

    // 数据引用：rip-relative 内存操作数。
    // 目标 = 下一条指令地址 + 位移。`operands` 里 PcRelative 存的是相对位移。
    for op in &insn.operands {
        if let Operand::PcRelative(disp) = op {
            let next = insn.addr + u64::from(insn.len);
            // disp 是 i64：负位移（向前引用）是常态；饱和转换防止溢出
            let to = if *disp >= 0 {
                next.checked_add(*disp as u64)
            } else {
                next.checked_sub(disp.unsigned_abs())
            };
            if let Some(to) = to {
                out.push(Xref {
                    from: insn.addr,
                    to,
                    kind: XrefKind::Data,
                });
            }
            // 溢出（理论上不可能：地址空间顶端附近的代码）时静默跳过这条引用，
            // 因为它是解码层的伪影而不是真实引用
        }
    }

    out
}

/// 批量提取：保持 `(from 升序, kind)` 稳定顺序。
///
/// 输入 `insns` 必须已按地址升序 —— 线性/递归扫描的产出都满足。
#[must_use]
pub fn xrefs_of_all(insns: &[DecodedInsn]) -> Vec<Xref> {
    let mut out = Vec::new();
    for insn in insns {
        out.extend(xrefs_of(insn));
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use bitflip_arch::MnemonicId;

    fn insn(addr: u64, len: u8, flow: Flow, target: Option<u64>, ops: Vec<Operand>) -> DecodedInsn {
        DecodedInsn {
            addr,
            len,
            arch: bitflip_arch::Arch::X86_64,
            mnemonic: MnemonicId(1),
            flow,
            target,
            condition: None,
            operands: ops,
            reads: bitflip_arch::RegSet::new(),
            writes: bitflip_arch::RegSet::new(),
            privileged: false,
        }
    }

    #[test]
    fn direct_call_produces_call_xref() {
        let i = insn(0x1000, 5, Flow::Call, Some(0x1040), vec![]);
        let x = xrefs_of(&i);
        assert_eq!(
            x,
            vec![Xref {
                from: 0x1000,
                to: 0x1040,
                kind: XrefKind::Call
            }]
        );
    }

    #[test]
    fn indirect_call_produces_nothing() {
        // 间接调用 target == None：明确不猜
        let i = insn(0x1000, 3, Flow::Call, None, vec![]);
        assert!(xrefs_of(&i).is_empty(), "间接调用不许猜目标");
    }

    #[test]
    fn rip_relative_data_ref_uses_next_insn_address() {
        // mov eax, [rip+0x100] 在 0x2000，长 6 字节：
        // 目标 = 0x2006 + 0x100 = 0x2106，不是 0x2000 + 0x100
        let i = insn(
            0x2000,
            6,
            Flow::Fallthrough,
            None,
            vec![Operand::PcRelative(0x100)],
        );
        let x = xrefs_of(&i);
        assert_eq!(
            x,
            vec![Xref {
                from: 0x2000,
                to: 0x2106,
                kind: XrefKind::Data
            }]
        );
    }

    #[test]
    fn negative_rip_displ_travels_backwards() {
        let i = insn(
            0x2000,
            6,
            Flow::Fallthrough,
            None,
            vec![Operand::PcRelative(-0x20)],
        );
        assert_eq!(xrefs_of(&i)[0].to, 0x2006 - 0x20);
    }

    #[test]
    fn conditional_branch_is_jump_kind() {
        let i = insn(
            0x3000,
            2,
            Flow::Branch { conditional: true },
            Some(0x3100),
            vec![],
        );
        assert_eq!(xrefs_of(&i)[0].kind, XrefKind::Jump);
    }

    #[test]
    fn call_with_data_ref_yields_both() {
        let i = insn(
            0x4000,
            5,
            Flow::Call,
            Some(0x5000),
            vec![Operand::PcRelative(8)],
        );
        let x = xrefs_of(&i);
        assert_eq!(x.len(), 2);
        assert_eq!(x[0].kind, XrefKind::Call);
        assert_eq!(x[1].kind, XrefKind::Data);
    }

    #[test]
    fn batch_preserves_address_order() {
        let insns = vec![
            insn(0x1000, 5, Flow::Call, Some(0x2000), vec![]),
            insn(
                0x1005,
                6,
                Flow::Fallthrough,
                None,
                vec![Operand::PcRelative(0x10)],
            ),
        ];
        let x = xrefs_of_all(&insns);
        assert_eq!(x.len(), 2);
        assert!(x[0].from < x[1].from);
    }
}
