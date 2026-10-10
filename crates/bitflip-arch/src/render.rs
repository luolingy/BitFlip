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

/// 全局文本风格（Intel）。
///
/// 保留这个常量是为了不动既有调用点：需要别的风格时用
/// [`format_insn_with`]。**不要**再往这里加"当前风格"之类的全局状态 ——
/// 一个进程里同时导出 Intel 与 AT&T 时必须互不影响。
#[must_use]
pub const fn text_style() -> TextStyle {
    TextStyle::Intel
}

/// 按 Intel 语法渲染一条指令。
///
/// 等价于 `format_insn_with(decoder, insn, TextStyle::Intel)`。
pub fn format_insn(decoder: &CapstoneDecoder, insn: &DecodedInsn) -> String {
    format_insn_with(decoder, insn, TextStyle::Intel)
}

/// 按指定语法渲染一条指令。
///
/// 助记符来自 capstone 的 id 映射；操作数从结构化字段拼装，
/// **不**复用 capstone 返回的 `mnemonic()`/`op_str()`（那样等于把文本
/// 又当成了数据源，而两套语法之间就没法共用同一份结构化指令了）。
///
/// 注意：本函数需要一个 capstone 句柄来查助记符与寄存器名。
/// 这是刻意的取舍 —— 助记符表是 capstone 的内部数据，自己复制一份
/// 会随 capstone 版本漂移，且要维护几千个条目。
pub fn format_insn_with(decoder: &CapstoneDecoder, insn: &DecodedInsn, style: TextStyle) -> String {
    decoder.with_engine(|cs| {
        let base = cs
            .insn_name(capstone::InsnId(insn.mnemonic.0))
            .unwrap_or_else(|| "?".to_string());

        // 条件码是助记符的**后缀**，不是操作数。
        //
        // `b.lt` 与 `b` 的 `InsnId` 相同，差别只在 cc 字段；不追加后缀就会
        // 把条件跳转显示成无条件跳转 —— 读者会以为执行流一定跳走，
        // 而实际上是"条件为假就往下走"。
        let base = match insn.condition {
            Some(cc) if cc.is_meaningful() => format!("{base}.{cc}"),
            _ => base,
        };

        match style {
            TextStyle::Intel => render_intel(cs, insn, &base),
            TextStyle::Att => render_att(cs, insn, &base),
        }
    })
}

/// Intel 语法：`mov rax, rbx` / `mov qword ptr [rbx+0x8], rax`。
fn render_intel(cs: &Capstone, insn: &DecodedInsn, mnemonic: &str) -> String {
    if insn.operands.is_empty() {
        return mnemonic.to_string();
    }

    // 直接跳转/调用把目标地址附上，比裸立即数有用得多
    if let Some(target) = insn.target {
        if matches!(insn.flow, Flow::Branch { .. } | Flow::Call) {
            return format!("{mnemonic} {target:#x}");
        }
    }

    let rendered: Vec<String> = insn
        .operands
        .iter()
        .map(|op| format_operand(cs, op))
        .collect();

    format!("{mnemonic} {}", rendered.join(", "))
}

/// AT&T 语法（GNU as 风格，x86 族）。
///
/// 与 Intel 的差异**只有三条**，但三条都必须对，否则输出既不能喂给
/// 汇编器当参照，也没法和 `objdump -M att` 逐条对拍：
///
/// 1. 寄存器加 `%`、立即数加 `$`、内存用 `disp(%base,%index,scale)`；
/// 2. 操作数顺序**反过来**（AT&T 是"源, 目的"）；
/// 3. 直接跳转/调用仍带绝对目标（`objdump -M att` 也这么打），
///    寄存器/内存形式的间接跳转加 `*`（星号 = "跳的是那个位置里的内容"）。
///
/// 已知与 GNU as 的差异（都是**如实**的取舍，不是遗漏）：
/// - 助记符宽度后缀只在**内存操作数**存在时按它的宽度加（`movl $0x1,(%rax)`）：
///   没有内存操作数时宽度由寄存器名本身说明（`mov $0x1,%eax`），
///   而内存操作数宽度拿不到时**不加**后缀，不猜。
/// - 段寄存器前缀（`%gs:`）与 `lock` 前缀**不渲染**：capstone 的细节结构
///   有这两项，但 `DecodedInsn` 目前不承载它们（见 `insn.rs`）。
///   这是解码层的缺口，不是渲染层的选择 —— 渲染层不会去猜。
///   多字节 NOP（`nopw 0x0(%rax,%rax,1)`）同理：capstone 只给 `nop`。
/// - 本函数只对 x86 族有意义。**非 x86 目标不要选 AT&T**：
///   AArch64/ARM 的 AT&T 写法是 GAS 的另一套规则（`b.eq`、`[x0, #8]`），
///   套用 x86 规则会产出一份谁也不认识的文本。调用方（`bitflip-core`
///   的导出层）负责在架构不支持时**明确拒绝**，而不是拿这份文本充数。
fn render_att(cs: &Capstone, insn: &DecodedInsn, mnemonic: &str) -> String {
    // 直接跳转/调用：AT&T 同样打绝对目标。
    if let Some(target) = insn.target {
        if matches!(insn.flow, Flow::Branch { .. } | Flow::Call) {
            return format!("{mnemonic} {target:#x}");
        }
    }

    if insn.operands.is_empty() {
        return mnemonic.to_string();
    }

    let mut rendered: Vec<String> = insn
        .operands
        .iter()
        .map(|op| format_operand_att(cs, op))
        .collect();

    // 操作数顺序：AT&T 把目的放最后。
    rendered.reverse();

    // 间接跳转/调用：目标不在编码里（`insn.target` 为 `None`），
    // 打上 `*` 说明"跳的是寄存器/内存里的地址"。
    let indirect = insn.target.is_none() && matches!(insn.flow, Flow::Branch { .. } | Flow::Call);
    if indirect {
        // AT&T 的目的操作数是最后那个（已 reverse 过）。
        if let Some(last) = rendered.last_mut() {
            if last.starts_with('%') || last.contains('(') {
                last.insert(0, '*');
            }
        }
    }

    // 助记符宽度后缀：只有内存操作数才需要它来说清宽度。
    // 定不出宽度就不加后缀（不猜）。
    let mnemonic = match memory_width(insn).and_then(att_suffix) {
        Some(suffix) => format!("{mnemonic}{suffix}"),
        None => mnemonic.to_string(),
    };

    format!("{mnemonic} {}", rendered.join(","))
}

/// 渲染单个操作数（AT&T 语法）。
fn format_operand_att(cs: &Capstone, op: &Operand) -> String {
    match op {
        Operand::Reg(reg) => format!("%{}", reg_name(cs, reg.0)),
        Operand::Imm(value) => {
            if *value < 0 {
                format!("$-{:#x}", value.unsigned_abs())
            } else {
                format!("${value:#x}")
            }
        }
        // `disp(%rip)`：位移留在括号外，与 objdump 一致。
        Operand::PcRelative(offset) => format!("{}(%rip)", format_disp(*offset)),
        Operand::Mem(mem) => format_mem_att(cs, mem),
        // 移位/扩展操作数（AArch64 语法家族）。AT&T 是 x86 的写法，
        // 非 x86 目标不适合套用；这里保持结构不变，由调用方决定要不要
        // 对非 x86 目标用 AT&T（见 `render_att` 的文档）。
        Operand::Shifted { reg, kind, amount } => {
            let name = format!("%{}", reg_name(cs, reg.0));
            if kind.is_extend() && *amount == 0 {
                format!("{name},{}", kind.as_str())
            } else {
                format!("{name},{} ${amount}", kind.as_str())
            }
        }
    }
}

/// 位移的 AT&T 写法：正数 `0x8`，负数 `-0x8`。
///
/// 这里**必须**按有符号处理。第一版把位移当无符号打，`lea -0x12e(%rip),%rcx`
/// 变成了 `lea 0xfffffffffffffed2(%rip),%rcx` —— 数值上等价，但没人会那样写，
/// 而且长度差了一截，读起来像另一个地址。是 objdump 对拍抓出来的。
fn format_disp(disp: i64) -> String {
    if disp < 0 {
        format!("-{:#x}", disp.unsigned_abs())
    } else {
        format!("{disp:#x}")
    }
}

/// 按操作数宽度给出 AT&T 助记符后缀（`b`/`w`/`l`/`q`）。
///
/// 只在**内存操作数**存在时才有意义：`movl $0x1,(%rsi)` 里的 `l` 说明
/// "写 4 字节"，没有它读者无从判断宽度。宽度未知（`size == 0`）时返回
/// `None` —— **不猜**一个后缀（CLAUDE.md §7）。
fn att_suffix(width: u8) -> Option<&'static str> {
    match width {
        1 => Some("b"),
        2 => Some("w"),
        4 => Some("l"),
        8 => Some("q"),
        _ => None,
    }
}

/// 取本条指令里第一个能定宽度的内存操作数宽度。
fn memory_width(insn: &DecodedInsn) -> Option<u8> {
    insn.operands.iter().find_map(|op| match op {
        Operand::Mem(mem) if mem.size > 0 => Some(mem.size),
        _ => None,
    })
}

/// 渲染内存操作数：`disp(%base,%index,scale)`。
fn format_mem_att(cs: &Capstone, mem: &MemRef) -> String {
    let base = mem
        .base
        .map(|reg| format!("%{}", reg_name(cs, reg.0)))
        .unwrap_or_default();
    let index = mem
        .index
        .map(|reg| format!("%{}", reg_name(cs, reg.0)))
        .unwrap_or_default();

    // 只有 base 时 `0x8(%rax)`；只有 index 时 `0x0(,%rax,4)`；
    // 都没有就是绝对地址，直接用位移，不带括号。
    if base.is_empty() && index.is_empty() {
        return format_disp(mem.disp);
    }

    let disp = if mem.disp == 0 {
        String::new()
    } else {
        format_disp(mem.disp)
    };

    let mut inner = base;
    if !index.is_empty() {
        inner.push(',');
        inner.push_str(&index);
        inner.push(',');
        inner.push_str(&mem.scale.to_string());
    }

    format!("{disp}({inner})")
}

/// 寄存器名。查不到时**编一个可识别的名字**（`r<编号>`），而不是留空 ——
/// 空名字在输出里会变成 `%` 这种看起来像排版错误的东西。
fn reg_name(cs: &Capstone, reg: u16) -> String {
    cs.reg_name(capstone::RegId(reg))
        .unwrap_or_else(|| format!("r{reg}"))
}

/// 渲染单个操作数（Intel 语法）。
fn format_operand(cs: &Capstone, op: &Operand) -> String {
    match op {
        Operand::Reg(reg) => reg_name(cs, reg.0),
        Operand::Imm(value) => {
            if *value < 0 {
                format!("-{:#x}", value.unsigned_abs())
            } else {
                format!("{value:#x}")
            }
        }
        // PC 相对：渲染成 `rip+0x10` 形式。
        //
        // 不在这里算绝对地址 —— 那要加上**下一条指令**的地址，是分析层
        // 的事（见 `bitflip_analyze::xref`）。渲染层只如实呈现指令里
        // 写着的位移。
        //
        // 用 `rip` 这个名字是因为 x86 上这几乎总是 RIP 相对；AArch64
        // 的 PC 相对寻址也归到这里，显示成 `pc+...` 更准，但那需要在
        // 这里拿到架构信息，而 `format_operand` 只看得到操作数。
        // 折中：统一用 `rip`，与外部反汇编器（LLVM/GNU as）在 x86 上的
        // 输出一致，便于逐条对拍。
        Operand::PcRelative(offset) => format!("[rip{offset:+#x}]"),
        Operand::Mem(mem) => format_mem(cs, mem),
        // `reg, lsl #n` / `reg, uxtw #n`。
        //
        // 扩展类且量为 0 时按 AArch64 汇编惯例省略 `#0`
        // （`uxtw` 而不是 `uxtw #0`）—— 与 LLVM/GNU as 输出一致，
        // 便于和外部反汇编器逐条对拍。
        Operand::Shifted { reg, kind, amount } => {
            let name = reg_name(cs, reg.0);
            if kind.is_extend() && *amount == 0 {
                format!("{name}, {}", kind.as_str())
            } else {
                format!("{name}, {} #{amount}", kind.as_str())
            }
        }
    }
}

/// 渲染内存操作数（Intel 语法）：`[base+index*scale+disp]`。
///
/// 组分之间的 `+` 不是可选的排版偏好。真值来自 objdump `-M intel`：
/// `0f 1f 44 00 00` 是 `nop DWORD PTR [rax+rax*1+0x0]`。
fn format_mem(cs: &Capstone, mem: &MemRef) -> String {
    // Intel 风格的内存操作数是一个**算术式**，不是若干片段拼起来的词表：
    // 组分之间必须有 `+` 运算符。这里曾经把 base 与 index 各 push 一个片段、
    // 最后用空格 join，于是 `nop word ptr [rax rax]` 被当成正常输出 ——
    // 而 `[rax rax]` 在任何汇编器里都是语法错误，它只是"看起来像"地址。
    // 真值来自 objdump -M intel：`nop DWORD PTR [rax+rax*1+0x0]`。
    let mut expr = String::new();

    if let Some(base) = mem.base {
        expr.push_str(&reg_name(cs, base.0));
    }
    if let Some(index) = mem.index {
        if !expr.is_empty() {
            expr.push('+');
        }
        expr.push_str(&reg_name(cs, index.0));
        // 比例**总是**写出来（`*1` 也写），与 objdump/capstone 的 Intel 渲染
        // 一致：这样"有没有比例"这件事在文本里一眼可见，不用去数寄存器位置。
        expr.push('*');
        expr.push_str(&mem.scale.to_string());
    }

    // disp == 0 且已有组分时省略（也不写 `+0x0`）—— 保留既有的、更短的
    // 表现形式，避免把每一行都改成 objdump 那种冗长写法而破坏已有快照。
    if expr.is_empty() {
        // 没有 base/index：这是一个绝对地址，直接写数值，**不带前导 `+`**
        //（`[+0x402000]` 没有任何汇编器接受）。绝对值用无符号渲染，
        // 负值只可能出现在有 base/index 的算术式里。
        expr.push_str(&format!("{:#x}", mem.disp.unsigned_abs()));
    } else if mem.disp != 0 {
        if mem.disp < 0 {
            expr.push_str(&format!("-{:#x}", mem.disp.unsigned_abs()));
        } else {
            expr.push_str(&format!("+{:#x}", mem.disp));
        }
    }

    let size_prefix = match mem.size {
        1 => "byte ptr ",
        2 => "word ptr ",
        4 => "dword ptr ",
        8 => "qword ptr ",
        _ => "",
    };

    format!("{size_prefix}[{expr}]")
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

    /// 内存操作数的 Intel 形式必须是**算术式**：组分之间要有 `+`。
    ///
    /// 真值来源（objdump `-M intel` 与 llvm-objdump 的实读输出，取
    /// `tests/fixtures/generated/m3-mingw-static.exe` 的 .text 开头）：
    ///
    /// ```text
    /// 0f 1f 44 00 00        nop    DWORD PTR [rax+rax*1+0x0]
    /// 48 8b 45 f8           mov    rax,QWORD PTR [rbp-0x8]
    /// ```
    ///
    /// 曾经输出 `nop word ptr [rax rax]` —— 用空格拼片段的结果，在任何
    /// 汇编器里都是语法错误。这条测试就是为了钉住那个 `+`。
    #[test]
    fn memory_operands_join_base_and_index_with_a_plus() {
        let dec = x64_decoder();

        // base + index，比例 1，无位移：objdump 写 `[rax+rax*1+0x0]`。
        // 本项目省略 `+0x0`（更短，且位移为 0 时省略是 Intel 汇编的通行写法）。
        let insn = dec
            .decode_one(&[0x0f, 0x1f, 0x44, 0x00, 0x00], 0x1000)
            .expect("nop dword ptr [rax+rax*1]");
        let text = format_insn(&dec, &insn);
        assert!(
            text.contains("[rax+rax*1]"),
            "base 与 index 之间必须有 `+`：{text}"
        );
        assert!(
            !text.contains("rax rax"),
            "空格拼接的内存操作数是语法错误：{text}"
        );

        // base + 负位移：`[rbp-0x8]`。
        let insn = dec
            .decode_one(&[0x48, 0x8b, 0x45, 0xf8], 0x1000)
            .expect("mov rax, [rbp-8]");
        let text = format_insn(&dec, &insn);
        assert!(text.contains("[rbp-0x8]"), "负位移应写成 -0x8：{text}");

        // 比例 4 的 index：`[rcx+rdx*4]`。
        let insn = dec
            .decode_one(&[0x8b, 0x04, 0x91], 0x1000)
            .expect("mov eax, [rcx+rdx*4]");
        let text = format_insn(&dec, &insn);
        assert!(text.contains("[rcx+rdx*4]"), "带比例的形式：{text}");

        // 只有位移（无 base/index）：绝对地址，不带 `+`。
        let insn = dec
            .decode_one(&[0x8b, 0x04, 0x25, 0x00, 0x20, 0x40, 0x00], 0x1000)
            .expect("mov eax, [0x402000]");
        let text = format_insn(&dec, &insn);
        assert!(
            text.contains("[0x402000]") && !text.contains("[+"),
            "绝对地址不该有前导 +：{text}"
        );
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

    /// Intel 渲染与"不传风格"的旧入口必须**逐字**一致。
    ///
    /// 这条钉住的是"加了 AT&T 之后 Intel 没有被动到"：把 `format_insn`
    /// 改成 Att 会立刻变红。
    #[test]
    fn plain_format_insn_is_intel() {
        let dec = x64_decoder();
        for bytes in [
            &[0x90u8][..],
            &[0xC3][..],
            &[0x48, 0x89, 0xD8][..],
            &[0x48, 0x8B, 0x05, 0x10, 0x00, 0x00, 0x00][..],
        ] {
            let insn = dec.decode_one(bytes, 0x1000).expect("解码");
            assert_eq!(
                format_insn(&dec, &insn),
                format_insn_with(&dec, &insn, TextStyle::Intel)
            );
        }
    }

    /// AT&T：寄存器带 `%`、立即数带 `$`、目的操作数在最后。
    #[test]
    fn att_renders_reversed_operands_with_sigils() {
        let dec = x64_decoder();
        // 48 89 D8 = mov rax, rbx（Intel）→ mov %rbx,%rax（AT&T）
        let insn = dec.decode_one(&[0x48, 0x89, 0xD8], 0x1000).expect("mov");
        assert_eq!(
            format_insn_with(&dec, &insn, TextStyle::Att),
            "mov %rbx,%rax"
        );

        // 48 83 EC 58 = sub rsp, 0x58 → sub $0x58,%rsp
        let insn = dec
            .decode_one(&[0x48, 0x83, 0xEC, 0x58], 0x1000)
            .expect("sub");
        assert_eq!(
            format_insn_with(&dec, &insn, TextStyle::Att),
            "sub $0x58,%rsp"
        );
    }

    /// AT&T 内存操作数：`disp(%base)`；带索引时 `disp(%base,%index,scale)`。
    #[test]
    fn att_renders_memory_operands() {
        let dec = x64_decoder();
        // 48 8B 70 08 = mov rsi, [rax+0x8]
        let insn = dec
            .decode_one(&[0x48, 0x8B, 0x70, 0x08], 0x1000)
            .expect("mov");
        assert_eq!(
            format_insn_with(&dec, &insn, TextStyle::Att),
            "movq 0x8(%rax),%rsi"
        );

        // 8B 04 88 = mov eax, [rax+rcx*4]
        let insn = dec.decode_one(&[0x8B, 0x04, 0x88], 0x1000).expect("mov");
        let text = format_insn_with(&dec, &insn, TextStyle::Att);
        assert_eq!(text, "movl (%rax,%rcx,4),%eax");
    }

    /// AT&T 的 RIP 相对用 `disp(%rip)`，位移留在括号**外**。
    #[test]
    fn att_renders_rip_relative_outside_parentheses() {
        let dec = x64_decoder();
        // 48 8B 05 10 00 00 00 = mov rax, [rip+0x10]
        let insn = dec
            .decode_one(&[0x48, 0x8B, 0x05, 0x10, 0, 0, 0], 0x1000)
            .expect("mov");
        assert_eq!(
            format_insn_with(&dec, &insn, TextStyle::Att),
            "mov 0x10(%rip),%rax"
        );
    }

    /// 间接跳转在 AT&T 里要带 `*`；直接跳转带绝对目标、不带 `*`。
    #[test]
    fn att_marks_indirect_jumps_with_star() {
        let dec = x64_decoder();
        // FF E0 = jmp rax → jmp *%rax
        let insn = dec.decode_one(&[0xFF, 0xE0], 0x1000).expect("jmp rax");
        assert_eq!(format_insn_with(&dec, &insn, TextStyle::Att), "jmp *%rax");

        // E9 00 00 00 00 = jmp 0x1005 → jmp 0x1005（不带 *）
        let insn = dec
            .decode_one(&[0xE9, 0x00, 0x00, 0x00, 0x00], 0x1000)
            .expect("jmp rel");
        assert_eq!(format_insn_with(&dec, &insn, TextStyle::Att), "jmp 0x1005");
    }

    /// 无操作数指令两种风格一致（不能被 AT&T 分支弄丢助记符）。
    #[test]
    fn att_keeps_operandless_mnemonics() {
        let dec = x64_decoder();
        let ret = dec.decode_one(&[0xC3], 0x1000).expect("ret");
        assert_eq!(format_insn_with(&dec, &ret, TextStyle::Att), "ret");
        let nop = dec.decode_one(&[0x90], 0x1000).expect("nop");
        assert_eq!(format_insn_with(&dec, &nop, TextStyle::Att), "nop");
    }
}
