//! 指令文本渲染。
//!
//! ## 为什么渲染单独一层
//!
//! `DecodedInsn` 存的是语义（控制流、寄存器集合、内存操作数），不是文本。
//! 文本是**视图**：同一份结构化指令在 UI 上要显示成 Intel 或 AT&T、
//! 要带不带地址前缀、要不要显示机器码 —— 这些都是渲染选项。
//!
//! 把渲染放进本模块（而不是让 UI 拼字符串）有两个理由：
//!
//! 1. 反汇编文本的格式在多个消费方之间必须一致（CLI、Web UI、导出）；
//! 2. 上层能力**禁止**反向解析文本。如果 UI 自己拼文本，早晚有人会去
//!    `parse()` 它来做分析 —— 那就退化成了参照实现的做法。
//!
//! ## 寄存器命名
//!
//! 本层只拿到 `RegId`（capstone 的编号）。编号到名字的映射依赖架构，
//! 因此这里通过 capstone 的 `reg_name` 获取 —— 这也保证了名字与
//! 解码器认为的编号一致，而不是我们自己维护一张容易漂移的表。

use capstone::Capstone;

use crate::backend::CapstoneDecoder;
use crate::insn::{DecodedInsn, Flow, MemRef, Operand};

/// 指令文本风格。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum TextStyle {
    /// Intel 语法（x86 默认）：`mov rax, rbx`。
    #[default]
    Intel,
    /// AT&T 语法：`movq %rbx, %rax`。
    Att,
}

impl TextStyle {
    /// 稳定短名（用于 JSON / CLI 选项）。
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Intel => "intel",
            Self::Att => "att",
        }
    }
}

/// 全局文本风格（当前只支持 Intel；AT&T 需要 capstone 的语法切换，
/// 留给 M3 的渲染层统一处理）。
#[must_use]
pub const fn text_style() -> TextStyle {
    TextStyle::Intel
}

/// 把一条结构化指令渲染成文本。
///
/// 助记符来自 capstone 的 id 映射；操作数从结构化字段拼装，
/// **不**复用 capstone 返回的 `mnemonic()`（那样等于把文本又当成了数据源）。
///
/// 注意：本函数需要一个 capstone 句柄来查助记符与寄存器名。
/// 这是刻意的取舍 —— 助记符表是 capstone 的内部数据，自己复制一份
/// 会随 capstone 版本漂移，且要维护几千个条目。
pub fn format_insn(decoder: &CapstoneDecoder, insn: &DecodedInsn) -> String {
    decoder.with_engine(|cs| {
        let mnemonic = cs
            .insn_name(capstone::InsnId(insn.mnemonic.0))
            .unwrap_or_else(|| "?".to_string());

        // 条件码是助记符的**后缀**，不是操作数。
        //
        // `b.lt` 与 `b` 的 `InsnId` 相同，差别只在 cc 字段；不追加后缀就会
        // 把条件跳转显示成无条件跳转 —— 读者会以为执行流一定跳走，
        // 而实际上是"条件为假就往下走"。
        let mnemonic = match insn.condition {
            Some(cc) if cc.is_meaningful() => format!("{mnemonic}.{cc}"),
            _ => mnemonic,
        };

        if insn.operands.is_empty() {
            return mnemonic;
        }

        let rendered: Vec<String> = insn
            .operands
            .iter()
            .map(|op| format_operand(cs, op))
            .collect();

        // 直接跳转/调用把目标地址附上，比裸立即数有用得多
        if let Some(target) = insn.target {
            if matches!(insn.flow, Flow::Branch { .. } | Flow::Call) {
                return format!("{mnemonic} {target:#x}");
            }
        }

        format!("{mnemonic} {}", rendered.join(", "))
    })
}

/// 渲染单个操作数。
fn format_operand(cs: &Capstone, op: &Operand) -> String {
    match op {
        Operand::Reg(reg) => cs
            .reg_name(capstone::RegId(reg.0))
            .unwrap_or_else(|| format!("r{}", reg.0)),
        Operand::Imm(value) => {
            if *value < 0 {
                format!("-{:#x}", value.unsigned_abs())
            } else {
                format!("{value:#x}")
            }
        }
        // PC 相对：显示成"相对偏移"，因为绝对地址要等加上指令地址才知道，
        // 而这里是纯渲染层，不该做地址计算。
        Operand::PcRelative(offset) => format!("{offset:+#x}"),
        Operand::Mem(mem) => format_mem(cs, mem),
        // `reg, lsl #n` / `reg, uxtw #n`。
        //
        // 扩展类且量为 0 时按 AArch64 汇编惯例省略 `#0`
        // （`uxtw` 而不是 `uxtw #0`）—— 与 LLVM/GNU as 输出一致，
        // 便于和外部反汇编器逐条对拍。
        Operand::Shifted { reg, kind, amount } => {
            let name = cs
                .reg_name(capstone::RegId(reg.0))
                .unwrap_or_else(|| format!("r{}", reg.0));
            if kind.is_extend() && *amount == 0 {
                format!("{name}, {}", kind.as_str())
            } else {
                format!("{name}, {} #{amount}", kind.as_str())
            }
        }
    }
}

/// 渲染内存操作数：`[base + index*scale + disp]`。
fn format_mem(cs: &Capstone, mem: &MemRef) -> String {
    let mut parts: Vec<String> = Vec::new();

    if let Some(base) = mem.base {
        parts.push(
            cs.reg_name(capstone::RegId(base.0))
                .unwrap_or_else(|| format!("r{}", base.0)),
        );
    }
    if let Some(index) = mem.index {
        let name = cs
            .reg_name(capstone::RegId(index.0))
            .unwrap_or_else(|| format!("r{}", index.0));
        if mem.scale > 1 {
            parts.push(format!("{name}*{}", mem.scale));
        } else {
            parts.push(name);
        }
    }

    if mem.disp != 0 || parts.is_empty() {
        if mem.disp < 0 {
            let abs = mem.disp.unsigned_abs();
            if parts.is_empty() {
                parts.push(format!("-{abs:#x}"));
            } else {
                parts.push(format!("- {abs:#x}"));
            }
        } else if parts.is_empty() {
            parts.push(format!("{:#x}", mem.disp));
        } else {
            parts.push(format!("+ {:#x}", mem.disp));
        }
    }

    let size_prefix = match mem.size {
        1 => "byte ptr ",
        2 => "word ptr ",
        4 => "dword ptr ",
        8 => "qword ptr ",
        _ => "",
    };

    format!("{size_prefix}[{}]", parts.join(" "))
}

/// 流程语义的中文标签（UI 直接显示）。
#[must_use]
pub const fn flow_label(flow: Flow) -> &'static str {
    match flow {
        Flow::Fallthrough => "顺序",
        Flow::Branch { conditional: true } => "条件跳转",
        Flow::Branch { conditional: false } => "跳转",
        Flow::Call => "调用",
        Flow::Return => "返回",
        Flow::Trap => "陷入",
        Flow::Unknown => "未识别",
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::decode::Decoder;
    use crate::types::{Arch, ArchSpec, Endian, Mode};

    fn x64_decoder() -> CapstoneDecoder {
        CapstoneDecoder::new(ArchSpec::from_arch(Arch::X86_64, Mode::M64, Endian::Little))
            .expect("x86_64")
    }

    #[test]
    fn renders_mnemonic_only_for_no_operand_insn() {
        let dec = x64_decoder();
        let insn = dec.decode_one(&[0x90], 0x1000).expect("nop");
        assert_eq!(format_insn(&dec, &insn), "nop");
        let ret = dec.decode_one(&[0xC3], 0x1000).expect("ret");
        assert_eq!(format_insn(&dec, &ret), "ret");
    }

    #[test]
    fn renders_direct_branch_with_target_address() {
        let dec = x64_decoder();
        // E9 00 00 00 00 -> jmp 0x1005
        let insn = dec
            .decode_one(&[0xE9, 0x00, 0x00, 0x00, 0x00], 0x1000)
            .expect("jmp");
        let text = format_insn(&dec, &insn);
        assert!(text.starts_with("jmp"), "应渲染成跳转: {text}");
        assert!(text.contains("0x1005"), "应包含目标地址: {text}");
    }

    #[test]
    fn renders_call_with_target_address() {
        let dec = x64_decoder();
        let insn = dec
            .decode_one(&[0xE8, 0x00, 0x00, 0x00, 0x00], 0x1000)
            .expect("call");
        let text = format_insn(&dec, &insn);
        assert!(text.starts_with("call"), "应渲染成调用: {text}");
        // capstone 已把相对位移解析成绝对目标（见 backend::relative_targets_are_resolved_to_absolute）
        assert!(text.contains("0x1005"), "应包含目标地址: {text}");
    }

    #[test]
    fn renders_register_operands_with_real_names() {
        let dec = x64_decoder();
        // 48 89 D8 = mov rax, rbx
        let insn = dec.decode_one(&[0x48, 0x89, 0xD8], 0x1000).expect("mov");
        let text = format_insn(&dec, &insn);
        assert!(text.starts_with("mov"), "应渲染成 mov: {text}");
        assert!(text.contains("rax"), "应包含 rax: {text}");
        assert!(text.contains("rbx"), "应包含 rbx: {text}");
        assert!(text.contains(", "), "操作数应以逗号分隔: {text}");
    }

    #[test]
    fn unknown_mnemonic_renders_question_mark_not_garbage() {
        let dec = x64_decoder();
        let mut insn = dec.decode_one(&[0x90], 0x1000).expect("nop");
        insn.mnemonic = crate::insn::MnemonicId(0xffff);
        let text = format_insn(&dec, &insn);
        // 查不到名字应给 "?"，不能 panic 也不能给出别的指令名
        assert!(text.starts_with('?'), "未知助记符应渲染成 ?: {text}");
    }

    #[test]
    fn memory_operand_renders_brackets() {
        let dec = x64_decoder();
        // 48 8B 03 = mov rax, [rbx]
        let insn = dec.decode_one(&[0x48, 0x8B, 0x03], 0x1000).expect("mov");
        let text = format_insn(&dec, &insn);
        assert!(text.contains('['), "内存操作数应有方括号: {text}");
        assert!(text.contains(']'), "内存操作数应有方括号: {text}");
    }

    #[test]
    fn rip_relative_memory_renders_with_disp() {
        let dec = x64_decoder();
        // 48 8B 05 10 00 00 00 = mov rax, [rip+0x10]
        let insn = dec
            .decode_one(&[0x48, 0x8B, 0x05, 0x10, 0, 0, 0], 0x1000)
            .expect("mov");
        let text = format_insn(&dec, &insn);
        assert!(text.contains("rip"), "rip 相对应有 rip: {text}");
    }

    #[test]
    fn flow_labels_cover_all_variants() {
        assert_eq!(flow_label(Flow::Fallthrough), "顺序");
        assert_eq!(flow_label(Flow::Branch { conditional: true }), "条件跳转");
        assert_eq!(flow_label(Flow::Branch { conditional: false }), "跳转");
        assert_eq!(flow_label(Flow::Call), "调用");
        assert_eq!(flow_label(Flow::Return), "返回");
        assert_eq!(flow_label(Flow::Trap), "陷入");
        assert_eq!(flow_label(Flow::Unknown), "未识别");
    }

    #[test]
    fn text_style_has_stable_name() {
        assert_eq!(text_style().as_str(), "intel");
        assert_eq!(TextStyle::Att.as_str(), "att");
    }
}
