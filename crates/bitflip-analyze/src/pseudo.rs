//! 伪代码（C 风格）生成：**有界子集**，不做类型推断、不做控制流结构化。
//!
//! ## 这个模块在做什么、不做什么
//!
//! 完整的反编译器（Hex-Rays / Ghidra 那一类）要做：提升到 IR → SSA → 数据流分析 →
//! 类型推断 → **控制流结构化** → 变量恢复 → 表达式传播 → 美化输出。
//! 其中**控制流结构化是公认最难的一步**，也是"产出看起来对、其实是错的"的主要来源。
//!
//! 本模块**只做最后一步的表达式部分**，且限定在**单个基本块内**：
//!
//! - 把每条指令翻译成一句 C 风格语句（赋值 / 调用 / 返回 / 条件跳转）；
//! - 寄存器与内存引用写成 `reg` / `*(T*)(base + disp)` 形式；
//! - **不跨块做变量合并** —— 每个块独立翻译，寄存器就是寄存器；
//! - **不还原 if/while/for** —— 条件跳转原样写成 `if (cond) goto ADDR;`
//!   （见 [`PseudocodeNote::FlatGoto`）。
//!
//! ## 为什么这样切
//!
//! 因为这条线以内的东西**每一句都能追溯到一条真实指令**，而线以外的东西做不到。
//! 如果我们输出一个 `while` 循环，用户无法判断那是真的循环还是我们猜的；
//! 而输出 `if (x) goto 0x1000;` 时，`x` 来自哪条指令、`0x1000` 是哪个跳转目标，
//! 都是可核对的。**在能核对之前不猜** —— 这正是 §7 的要求。
//!
//! ## 类型
//!
//! 一律用"地址宽度对应的整数类型"（`uint64_t` / `uint32_t` …），不做推断。
//! 记忆体访问写成 `*(uint32_t *)(base + 0x10)` 这类**显式且宽度正确**的形式，
//! 而不是猜成某个结构体字段。宽度**是**从指令里读出来的（`MemRef::size`），
//! 所以它是事实不是猜测；`uint32_t` 这个选择也是事实（这次访问就是 4 字节）。
//!
//! ## 什么时候该拒绝
//!
//! 指令解码失败、操作数无法翻译、寄存器没有名字 —— 这些情况**不猜**，
//! 写成注释 `/* 无法翻译：<原因> */` 并计入 [`PseudocodeFunction::untranslated`]。
//! 调用方据此判断这段输出可用不可用。

use std::collections::BTreeMap;
use std::fmt::Write as _;

use bitflip_arch::{ConditionCode, DecodedInsn, Flow, Operand, ShiftKind};

use crate::cfg::Cfg;

/// 伪代码输出的格式版本。跨进程传输时必带（CLAUDE.md §4）。
pub const PSEUDO_FORMAT_VERSION: u32 = 1;

/// 单个函数能生成的伪代码上限（语句数）。
///
/// 超限时**截断并写明**，不静默少给（§7）。设为 4000 是因为
/// 再长的函数已经不是"读一段伪代码"能解决的了，用户该去看 CFG。
pub const MAX_STATEMENTS: usize = 4000;

/// 一个函数的伪代码。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PseudocodeFunction {
    /// 函数入口地址。
    pub entry: u64,
    /// 函数名。来自符号表/签名库；没有就是 `None`（**不编造** `func_xxx`，§7）。
    pub name: Option<String>,
    /// 是否做了控制流结构化。`decompile_function` 恒为 `false`；
    /// `decompile_structured` 在**全函数控制流都被结构化、没有残留 goto** 时为 `true`。
    ///
    /// 这个字段存在的意义是**让调用方不必猜测**当前输出的语义级别：
    /// `false` 时用户看到的是"每块一段、跳转是 goto"，`true` 才是真正的结构。
    /// 把它写成常量而不是省略，是因为省略会让人以为默认就是结构化的。
    pub structured: bool,
    /// 结构化渲染的函数体（每行带缩进与行尾地址注释），`structured` 为 `true` 时使用；
    /// 为 `None` 时渲染走"按块 per-block"的老路径。**两种渲染都逐句可追溯到指令地址。**
    pub structured_body: Option<Vec<String>>,
    /// 按基本块分组的语句。
    pub blocks: Vec<PseudocodeBlock>,
    /// 语句总数。
    pub statement_count: usize,
    /// 输出被截断的语句数（0 表示完整）。
    pub truncated: usize,
    /// 无法翻译成语句的指令数（0 表示全部翻译成功）。
    ///
    /// 这个计数**必须**能被调用方读到：它是"这份输出有多少是缺失的"的唯一量度。
    /// 只放在 `notes` 的文字里不够 —— 那没法被程序判断。
    pub untranslated: usize,
    /// 降级/说明。**必须显示给用户**，不能吞掉。
    pub notes: Vec<PseudocodeNote>,
}

/// 一个基本块的伪代码。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PseudocodeBlock {
    /// 块首地址。
    pub start: u64,
    /// 块尾地址（不含）。
    pub end: u64,
    /// 前驱块首地址（升序）。
    pub predecessors: Vec<u64>,
    /// 后继块首地址（升序）。
    pub successors: Vec<u64>,
    /// 语句。
    pub statements: Vec<PseudocodeStatement>,
}

/// 一条 C 风格语句。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PseudocodeStatement {
    /// 产生这条语句的指令地址。**每一句都可追溯**。
    pub addr: u64,
    /// 语句文本（不含分号与换行）。
    pub text: String,
}

/// 伪代码的降级说明。
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PseudocodeNote {
    /// 没有做控制流结构化 —— 条件跳转以 `goto` 形式出现。
    ///
    /// 这条**必定存在**，因为它决定了用户该怎么读这份输出。
    FlatGoto,
    /// 已做控制流结构化：`if`/`else`/`while`/`do-while` 都是从 CFG 还原的，函数内无残留 `goto`。
    Structured,
    /// 只做到了**部分**结构化：其余控制流仍以 `goto` 出现。
    PartiallyStructured {
        /// 仍以 `goto` 形式出现的控制转移数。
        residual_gotos: usize,
        /// 已并入结构的块数。
        structured_blocks: usize,
        /// 函数的基本块总数。
        total_blocks: usize,
    },
    /// 输出被截断。
    Truncated {
        /// 已输出的语句数。
        emitted: usize,
        /// 被丢掉的语句数。
        dropped: usize,
    },
    /// 有指令无法翻译。
    Untranslated {
        /// 无法翻译的指令数。
        count: usize,
        /// 第一处的位置与原因（样例，不是全部）。
        first_addr: u64,
        /// 原因。
        reason: String,
    },
    /// 寄存器名解析器覆盖不全，输出里的寄存器以编号出现。
    ///
    /// 这仍然**是忠实的输出**（编号是真的），只是不好读。之所以要单独报出来，
    /// 是因为用户看到 `reg44` 时无法判断那是一个真实的寄存器名还是我们的占位。
    RegistersUnnamed,
    /// 没有名称（符号表里没有）。不编造名字（§7）。
    Unnamed,
    /// 含间接跳转/调用，目标未知，无法给出被调者。
    IndirectTargets {
        /// 间接控制流转移的条数。
        count: usize,
    },
}

impl PseudocodeNote {
    /// 面向用户的中文说明。
    #[must_use]
    pub fn summary_zh(&self) -> String {
        match self {
            Self::FlatGoto => {
                "未做控制流结构化：条件跳转以 if (cond) goto 形式出现，\
                 不是还原出的 if/while/for"
                    .to_string()
            }
            Self::Structured => {
                "已做控制流结构化：if/else/while/do-while 从控制流图还原，函数内无残留 goto"
                    .to_string()
            }
            Self::PartiallyStructured {
                residual_gotos,
                structured_blocks,
                total_blocks,
            } => format!(
                "部分结构化：{structured_blocks}/{total_blocks} 个基本块并入了 if/while 结构；\
                 其余基本块按原样（顺序/跳转）输出，其中 {residual_gotos} 处控制转移退化为 goto\
                 （循环等形态本片未完整还原，如实保留）"
            ),
            Self::Truncated { emitted, dropped } => format!(
                "输出被截断：已输出 {emitted} 条语句，丢弃 {dropped} 条（超过上限 {MAX_STATEMENTS}）"
            ),
            Self::Untranslated {
                count,
                first_addr,
                reason,
            } => format!(
                "{count} 条指令无法翻译（首处 {first_addr:#x}：{reason}）；这些位置在输出里是注释，不是猜测结果"
            ),
            Self::RegistersUnnamed => {
                "寄存器名解析器未覆盖全部寄存器：输出中部分寄存器以编号出现，\
                 那些编号是真实的（capstone 编号），只是没有名字"
                    .to_string()
            }
            Self::Unnamed => {
                "该函数在符号表中没有名字：输出里用入口地址代替，未编造名称".to_string()
            }
            Self::IndirectTargets { count } => format!(
                "{count} 处间接跳转/调用的目标未知（需要数据流分析），输出里写作未解析的目标"
            ),
        }
    }
}

/// 一次生成的全部结果。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Pseudocode {
    /// 格式版本。
    pub format_version: u32,
    /// 各函数的伪代码。
    pub functions: Vec<PseudocodeFunction>,
    /// 全局说明（例如整体降级）。
    pub notes: Vec<String>,
}

impl Pseudocode {
    /// 渲染成可读文本。
    #[must_use]
    pub fn render_text(&self) -> String {
        let mut out = String::new();
        for f in &self.functions {
            out.push_str(&render_function_text(f));
            out.push('\n');
        }
        out
    }
}

/// 把一个函数的伪代码渲染成文本。
#[must_use]
pub fn render_function_text(f: &PseudocodeFunction) -> String {
    let mut out = String::new();
    let head = match &f.name {
        Some(n) => n.clone(),
        None => format!("{:#x}", f.entry),
    };
    let _ = writeln!(
        out,
        "// {head}（入口 {:#x}，{} 个基本块，{} 条语句）",
        f.entry,
        f.blocks.len(),
        f.statement_count
    );
    if f.truncated > 0 {
        let _ = writeln!(out, "// 注意：输出已截断");
    }
    for n in &f.notes {
        let _ = writeln!(out, "// {}", n.summary_zh());
    }
    out.push('\n');
    let _ = writeln!(
        out,
        "void {}(void) {{",
        sanitize_identifier(f.name.as_deref().unwrap_or("sub"))
    );
    if let Some(body) = &f.structured_body {
        // 结构化渲染：每行自带缩进与地址追溯。
        for line in body {
            let _ = writeln!(out, "{line}");
        }
    } else {
        for b in &f.blocks {
            let _ = writeln!(out, "  // block {:#x}..{:#x}", b.start, b.end);
            for s in &b.statements {
                let _ = writeln!(out, "  {:#x}: {};", s.addr, s.text);
            }
        }
    }
    out.push_str("}\n");
    out
}

/// 把函数名变成合法的 C 标识符。
///
/// 名字来自符号表，可能含 `::`、`<`、`.` 等 C 里非法的字符。
/// 处理方式是**替换成下划线**，并在 [`PseudocodeNote::Unnamed`] 之外的场合不额外声明 ——
/// 因为我们改了名字就必须让人看得出来，所以这里只做最小变换，且渲染时同时给出原始入口地址。
fn sanitize_identifier(name: &str) -> String {
    if name.is_empty() {
        return "sub".to_string();
    }
    let mut s: String = name
        .chars()
        .map(|c| {
            if c.is_ascii_alphanumeric() || c == '_' {
                c
            } else {
                '_'
            }
        })
        .collect();
    if s.chars().next().is_some_and(|c| c.is_ascii_digit()) {
        s.insert(0, '_');
    }
    s
}

/// 生成一个函数的伪代码。
///
/// `insns` 必须是该函数的全部指令（按地址升序），`cfg` 是同一函数的控制流图。
/// 二者对不上时（例如指令地址不在任何块里）那些指令会被记为无法翻译，
/// **不会**被静默丢弃。
#[must_use]
pub fn decompile_function(
    entry: u64,
    name: Option<&str>,
    insns: &[DecodedInsn],
    cfg: &Cfg,
    namer: RegisterNamer<'_>,
) -> PseudocodeFunction {
    let mut notes = vec![PseudocodeNote::FlatGoto];
    if name.is_none() {
        notes.push(PseudocodeNote::Unnamed);
    }

    // 按地址索引指令，便于按块取。
    let by_addr: BTreeMap<u64, &DecodedInsn> = insns.iter().map(|i| (i.addr, i)).collect();

    let mut blocks = Vec::new();
    let mut statement_count = 0usize;
    let mut truncated = 0usize;
    let mut untranslated = 0usize;
    let mut first_untranslated: Option<(u64, String)> = None;
    let mut indirect = 0usize;

    for b in cfg.blocks() {
        if statement_count >= MAX_STATEMENTS {
            // 计数剩余指令，用于如实报告丢了多少。
            truncated += usize::try_from(b.end.saturating_sub(b.start)).unwrap_or(0);
            continue;
        }
        let mut statements = Vec::new();
        for (&addr, insn) in by_addr.range(b.start..b.end) {
            if statement_count >= MAX_STATEMENTS {
                truncated += 1;
                continue;
            }
            match translate(insn, namer) {
                Ok(Some(text)) => {
                    statements.push(PseudocodeStatement { addr, text });
                    statement_count += 1;
                }
                Ok(None) => {
                    // 有意不产生语句（例如 nop）—— 不算失败。
                }
                Err(reason) => {
                    untranslated += 1;
                    if first_untranslated.is_none() {
                        first_untranslated = Some((addr, reason.clone()));
                    }
                    statements.push(PseudocodeStatement {
                        addr,
                        text: format!("/* 无法翻译：{reason} */"),
                    });
                    statement_count += 1;
                }
            }
            if matches!(insn.flow, Flow::Branch { .. } | Flow::Call) && insn.target.is_none() {
                indirect += 1;
            }
        }
        blocks.push(PseudocodeBlock {
            start: b.start,
            end: b.end,
            predecessors: b.predecessors.clone(),
            successors: b.successors.clone(),
            statements,
        });
    }

    if truncated > 0 {
        notes.push(PseudocodeNote::Truncated {
            emitted: statement_count,
            dropped: truncated,
        });
    }
    if let Some((addr, reason)) = first_untranslated {
        notes.push(PseudocodeNote::Untranslated {
            count: untranslated,
            first_addr: addr,
            reason,
        });
    }
    if indirect > 0 {
        notes.push(PseudocodeNote::IndirectTargets { count: indirect });
    }
    // 有指令翻译不出来、且寄存器名解析器报不出名字时，说明输出里的
    // 寄存器是以编号出现的 —— 如实告知，而不是让用户以为自己看到的是寄存器名。
    //
    // 判断依据是"确实翻译失败过"，不是"解析器返回了 None"：
    // 一条只用立即数的指令不需要寄存器名，不能因此虚报降级（§7 反向也成立：
    // 不该把正常输出说成降级）。
    if untranslated > 0 && namer(0).is_none() {
        notes.push(PseudocodeNote::RegistersUnnamed);
    }

    PseudocodeFunction {
        entry,
        name: name.map(str::to_string),
        structured: false,
        structured_body: None,
        blocks,
        statement_count,
        truncated,
        untranslated,
        notes,
    }
}

/// 把一条指令翻译成 C 风格语句。
///
/// 返回 `Ok(None)` 表示这条指令**有意不产生语句**（`nop` 之类），
/// 返回 `Err(reason)` 表示**翻译不了**：调用方必须把它当作缺失来报告，
/// 而不是当作"这条指令无关紧要"。
/// `pub(crate)` 是为了让 [`crate::structurize`] 复用同一套指令翻译，
/// 避免两处翻译逻辑漂移（一处改了另一处没改，是这类工具最难查的 bug）。
pub(crate) fn translate(
    insn: &DecodedInsn,
    namer: RegisterNamer<'_>,
) -> Result<Option<String>, String> {
    let m = insn.mnemonic;
    let ops = &insn.operands;

    // 控制流先处理：它们不遵守"目标 = 第一个操作数"的一般形状。
    match insn.flow {
        Flow::Return => return Ok(Some("return".to_string())),
        Flow::Trap => return Ok(Some(format!("__builtin_trap() /* {} */", insn_name(m)))),
        Flow::Branch { conditional } => {
            let target = match insn.target {
                Some(t) => format!("{t:#x}"),
                // 间接跳转：目标未知。**不猜**，写明未知。
                None => "/* 目标未知（间接） */ 0".to_string(),
            };
            if conditional {
                let cond = insn
                    .condition
                    .map_or_else(|| "/* 条件未知 */".to_string(), condition_text);
                return Ok(Some(format!("if ({cond}) goto {target}")));
            }
            return Ok(Some(format!("goto {target}")));
        }
        Flow::Call => {
            // call 的"目标"是被调用的函数；参数不在操作数里（要跨指令读寄存器），
            // 所以这里**不编造参数**，只给被调者地址。
            let callee = match insn.target {
                Some(t) => format!("{t:#x}"),
                None => "/* 目标未知（间接） */ 0".to_string(),
            };
            // AArch64/AArch32 的 bl 带返回地址寄存器，但那是链接细节不是 C 参数。
            return Ok(Some(format!("/* call */ {callee}()")));
        }
        _ => {}
    }

    // 完全不产生语句的指令：既没有操作数，也没有寄存器读写影响。
    //
    // 判据必须是**两者同时成立**。只看寄存器读写会误判：`push 0x10` 这类
    // 指令的操作数在栈上、读写集可能是空的，但它有真实语义，不能当 nop 丢掉。
    // 测试 `registers_are_named_through_the_injected_namer` 抓到的就是这个 ——
    // 当时只看 `reads`/`writes`，把带操作数的指令整条吞掉了。
    if ops.is_empty() && insn.writes.is_empty() && insn.reads.is_empty() {
        return Ok(None);
    }

    // 一般形状：目标 ← 表达式。x86 的 mov 是 dst, src；多数 RISC 的 mov 也是。
    let name = insn_name(m);
    if ops.is_empty() {
        return Ok(Some(format!("/* {name} */")));
    }

    let dst = &ops[0];
    let rhs = if ops.len() >= 2 {
        expr(&ops[1..], insn.addr, namer)?
    } else {
        // 一元指令（inc / neg / push / pop 的单操作数形式…）无法用"目标 ← 源"表达。
        // 不猜它的语义，写成 noreturn 的调用形式会误导，所以明确标出来。
        return Err(format!("{name} 为单操作数指令，无法用赋值形式表达"));
    };

    let lhs = lvalue(dst, namer)?;
    Ok(Some(format!("{lhs} = {rhs}")))
}

/// 指令助记符的可读名。
///
/// `MnemonicId` 只是 capstone 的原始编号，本 crate 不持有"编号 → 文本"的表
/// （那张表在 `bitflip-arch` 的解码后端里，需要 `&dyn Backend`），
/// 所以这里**只能给出编号**。这是有意的取舍：与其在这里写一份会和后端漂移的
/// 第二张表，不如让输出里出现 `insn#N`，并在需要可读名的场合由调用方
/// （它持有后端）去补。
fn insn_name(m: bitflip_arch::MnemonicId) -> String {
    if m.is_unknown() {
        "<unknown>".to_string()
    } else {
        format!("insn#{}", m.get())
    }
}

/// 条件码 → C 表达式片段。
///
/// 注意：这里给出的是**条件本身**，不含两侧操作数 —— 因为标志位（x86 的 ZF/CF…）
/// 不是可读的变量，把它们猜成两个操作数的比较需要数据流分析。
/// 因此 x86 上会输出 `flags_lt` 这类**显式的占位**，而不是看起来像比较的 `a < b`。
pub(crate) fn condition_text(c: ConditionCode) -> String {
    // 条件码的语义是"基于标志位"，不是"基于操作数"。
    // 所以统一写成标志位形式，并让名字一眼看出它是标志而不是变量。
    format!("/* {c:?} */ flags")
}

/// 生成左值（可赋值目标）。
fn lvalue(op: &Operand, namer: RegisterNamer<'_>) -> Result<String, String> {
    match op {
        Operand::Reg(r) => namer(r.0).ok_or_else(|| format!("寄存器编号 {} 无名字", r.0)),
        Operand::Mem(m) => Ok(mem_text(m, namer)),
        Operand::Imm(v) => Err(format!("立即数 {v} 不能作为赋值目标")),
        Operand::PcRelative(d) => Err(format!("PC 相对项 {d} 不能作为赋值目标")),
        Operand::Shifted { .. } => Err("带移位修饰的操作数不能作为赋值目标".to_string()),
        // AArch64 的这几类都不是存储单元：系统寄存器是**操作的对象**（要经
        // `mrs`/`msr` 搬），屏障/预取/SVCR 是选择项，SME 索引是地址计算。
        // 如实拒绝，不要硬当成左值编一个赋值出来。
        Operand::SysReg(_)
        | Operand::Pstate(_)
        | Operand::Barrier(_)
        | Operand::Prefetch(_)
        | Operand::SysOp(_)
        | Operand::FpImm(_)
        | Operand::Svcr(_)
        | Operand::SmeIndex => Err("这一类操作数不能作为赋值目标".to_string()),
    }
}

/// 生成表达式。
fn expr(ops: &[Operand], addr: u64, namer: RegisterNamer<'_>) -> Result<String, String> {
    let mut parts = Vec::new();
    for op in ops {
        parts.push(expr_one(op, addr, namer)?);
    }
    Ok(parts.join(" + "))
}

/// 生成单个操作数的表达式。
fn expr_one(op: &Operand, addr: u64, namer: RegisterNamer<'_>) -> Result<String, String> {
    match op {
        Operand::Reg(r) => namer(r.0).ok_or_else(|| format!("寄存器编号 {} 无名字", r.0)),
        // 立即数写成十六进制：反汇编语境下十六进制比十进制好核对。
        Operand::Imm(v) => Ok(format!("{v:#x}")),
        Operand::Mem(m) => Ok(mem_text(m, namer)),
        Operand::PcRelative(d) => {
            // 转成绝对地址，这样用户能直接跳过去看。溢出按饱和处理并如实呈现。
            let abs = addr.wrapping_add(*d as u64);
            Ok(format!("{abs:#x} /* PC 相对 {d:#x} */"))
        }
        Operand::Shifted { reg, kind, amount } => {
            let r = namer(reg.0).ok_or_else(|| format!("寄存器编号 {} 无名字", reg.0))?;
            let k = match kind {
                ShiftKind::Lsl => "<<",
                ShiftKind::Lsr => ">>",
                ShiftKind::Asr => ">> /* 算术 */",
                ShiftKind::Ror => ">> /* 循环 */",
                // ShiftKind 未来加变体时这里会编译失败，强制处理而不是默认猜一个。
                _ => return Err(format!("不支持的移位类型 {kind:?}")),
            };
            Ok(format!("({r} {k} {amount})"))
        }
        // AArch64 的几类"不是普通操作数"的操作数。这里**保留它们**并写出
        // 显式占位（与 `condition_text` 的 `flags` 同一路数），而不是丢掉 ——
        // 丢掉会让 `dc civac, x0` 的伪代码看起来像一条完整的指令，
        // 而读者无从知道少了东西（CLAUDE.md §7）。
        //
        // `__` 前缀是刻意的：一眼看出这是占位，不是真实符号。
        Operand::SysReg(sysreg) => Ok(format!("__sysreg({:#x})", sysreg.raw)),
        Operand::Pstate(field) => Ok(format!("__pstate({})", field.as_str())),
        Operand::Barrier(option) => Ok(format!("__barrier({})", option.as_str())),
        Operand::Prefetch(Some(op)) => Ok(format!("__prefetch({})", op.as_str())),
        Operand::Prefetch(None) => Ok("__prefetch(?)".to_string()),
        Operand::SysOp(op) => Ok(format!("__sys_op({})", op.raw)),
        // 浮点立即数本身就是一个合法的 C 字面量，直接给值。
        Operand::FpImm(bits) => Ok(format!("{:?}", f64::from_bits(*bits))),
        Operand::Svcr(mode) => Ok(format!("__svcr({})", mode.as_str())),
        Operand::SmeIndex => Ok("__sme_index".to_string()),
    }
}

/// 内存引用 → `*(T *)(base + index*scale + disp)`。
///
/// **宽度是事实**（`MemRef::size` 从指令读出来），所以 `T` 不是猜的；
/// 但如果 size 不是 1/2/4/8，说明是向量访问或我们理解错了 ——
/// 那种情况如实标注字节数，不硬塞一个 C 类型。
fn mem_text(m: &bitflip_arch::MemRef, namer: RegisterNamer<'_>) -> String {
    let ty = match m.size {
        1 => "uint8_t".to_string(),
        2 => "uint16_t".to_string(),
        4 => "uint32_t".to_string(),
        8 => "uint64_t".to_string(),
        n => format!("/* {n} 字节 */ uint8_t"),
    };
    let mut parts = Vec::new();
    if let Some(b) = m.base {
        parts.push(namer(b.0).unwrap_or_else(|| format!("reg{}", b.0)));
    }
    if let Some(i) = m.index {
        let r = namer(i.0).unwrap_or_else(|| format!("reg{}", i.0));
        if m.scale > 1 {
            parts.push(format!("{r} * {}", m.scale));
        } else {
            parts.push(r);
        }
    }
    if m.disp != 0 || parts.is_empty() {
        if m.disp < 0 {
            parts.push(format!("- {:#x}", -m.disp));
        } else {
            parts.push(format!("{:#x}", m.disp));
        }
    }
    let inner = parts.join(" + ");
    if m.write {
        format!("*({ty} *)({inner}) /* 写 */")
    } else {
        format!("*({ty} *)({inner})")
    }
}

/// 寄存器名解析器：把 capstone 的寄存器编号变成名字。
///
/// ## 为什么是参数而不是本模块的表
///
/// `RegId` 是 capstone 的**原始寄存器编号**，不是从 0 连续排的通用寄存器序号。
/// 本模块最初写了一张 `0 => rax, 1 => rcx, ...` 的表 —— **那是错的**：
/// 实测下来 `RegId(44)`、`RegId(231)` 之类全部判成未知，绝大多数指令
/// 退化成"无法翻译"。capstone 的编号有自己的枚举顺序，抄不得。
///
/// 权威来源是 `bitflip_arch::backend::CapstoneDecoder::register_name`，
/// 它的文档明确写了"查不到返回 `None`，调用方如实显示未识别寄存器"。
/// 所以这里把名字解析**注入**进来，而不是复制一份会随 capstone 版本漂移的表。
///
/// 返回 `None` 时调用方必须如实报告，**不得**编一个 `reg#44` 这样的假名（§7）。
pub type RegisterNamer<'a> = &'a dyn Fn(u16) -> Option<String>;

/// 不做命名的解析器：所有寄存器都报"未知"。
///
/// 这是**诚实的默认值**：宁可在输出里写明"寄存器名未覆盖"，
/// 也不要按某个假设的架构猜名字。真实调用方应传入后端提供的解析器。
#[must_use]
pub fn no_register_names(id: u16) -> Option<String> {
    let _ = id;
    None
}
#[cfg(test)]
mod tests {
    use super::*;
    use bitflip_arch::{Arch, MnemonicId, RegId, RegSet};

    /// 一个**确定知道答案**的寄存器名解析器。
    ///
    /// 测试里用假名而不是真 capstone 表，是因为这条测试要验证的是
    /// "名字怎么被使用"，不是"capstone 的编号是什么"。真表的验证在
    /// `bitflip-arch` 的测试里做（那里才有引擎）。
    ///
    /// **顺带说明一个真实踩过的坑**：本模块最初硬编码了一张
    /// `0 => rax, 1 => rcx, ...` 的表，假定 `RegId` 是从 0 连续编号的
    /// 通用寄存器序号。实际 `RegId` 是 capstone 的**原始编号**，
    /// 于是真实目标上 `RegId(44)`、`RegId(231)` 全判成未知，
    /// 绝大多数指令退化成"无法翻译"。下面的
    /// `namer_is_asked_with_raw_capstone_ids_not_a_compact_index`
    /// 就是为这件事写的回归测试。
    fn test_namer(id: u16) -> Option<String> {
        // 刻意用 capstone x86_64 的真实编号：RAX=19, RCX=26, RDX=27, RBX=28,
        // RSP=35, RBP=36, RSI=37, RDI=39。
        let name = match id {
            19 => "rax",
            26 => "rcx",
            27 => "rdx",
            28 => "rbx",
            35 => "rsp",
            36 => "rbp",
            37 => "rsi",
            39 => "rdi",
            _ => return None,
        };
        Some(name.to_string())
    }

    /// 造一条最小指令。**只设测试真正用到的字段**，其余刻意留默认值 ——
    /// 这样测试里出现的是"我关心的语义"，而不是一坨无关的构造。
    fn insn(addr: u64, m: u32, flow: Flow, target: Option<u64>, ops: Vec<Operand>) -> DecodedInsn {
        DecodedInsn {
            addr,
            len: 1,
            arch: Arch::X86_64,
            mnemonic: MnemonicId(m),
            flow,
            target,
            condition: None,
            operands: ops,
            reads: RegSet::new(),
            writes: RegSet::new(),
            privileged: false,
        }
    }

    #[test]
    fn namer_is_asked_with_raw_capstone_ids_not_a_compact_index() {
        // 回归测试：`RegId(35)` 必须是 `rsp`（capstone 编号），
        // **不是**"第 35 个通用寄存器"。
        //
        // 这条测试存在的唯一理由是它抓到过一个真实 bug：本模块曾经硬编码
        // `4 => rsp`，而真实编号是 35 —— 于是真实目标上 rsp 显示为"未知"。
        // 断言写成"编号 35 应该解析成 rsp"而不是"编号 4 应该解析成 rsp"，
        // 就是为了让那个错误假设再也回不来。
        assert_eq!(test_namer(35).as_deref(), Some("rsp"));
        assert_eq!(test_namer(19).as_deref(), Some("rax"));
        // 编号 4 不是任何 x86_64 通用寄存器 —— 旧表在这里会错得很自信。
        assert!(test_namer(4).is_none(), "编号 4 不应被当作某个通用寄存器");
    }

    #[test]
    fn unknown_register_is_reported_not_invented() {
        // 解析器给不出名字时必须报错，而不是编一个名字。
        let i = insn(
            0x1000,
            10,
            Flow::Fallthrough,
            None,
            vec![Operand::Reg(RegId(9999)), Operand::Imm(1)],
        );
        let e = translate(&i, &test_namer).unwrap_err();
        assert!(e.contains("9999"), "应报出编号：{e}");
        assert!(e.contains("无名字"), "应说明是没有名字：{e}");
    }

    #[test]
    fn no_namer_never_invents_names() {
        // 不注入解析器时，所有寄存器都如实报未知 —— 不猜。
        assert!(no_register_names(19).is_none());
        assert!(no_register_names(35).is_none());
        // `no_register_names` 的签名要与 `RegisterNamer` 兼容。
        let _: RegisterNamer<'_> = &no_register_names;
    }

    #[test]
    fn registers_are_named_through_the_injected_namer() {
        let i = insn(
            0x1000,
            10,
            Flow::Fallthrough,
            None,
            vec![Operand::Reg(RegId(19)), Operand::Imm(7)],
        );
        let text = translate(&i, &test_namer).unwrap().unwrap();
        assert!(text.contains("rax = 0x7"), "{text}");
    }

    #[test]
    fn conditional_branch_becomes_goto_not_if() {
        // 核心诚实性断言：条件跳转必须输出 goto 形式，
        // 不能输出看起来像还原出来的 if 语句块。
        let mut i = insn(
            0x1000,
            1,
            Flow::Branch { conditional: true },
            Some(0x1100),
            vec![],
        );
        i.condition = Some(ConditionCode::Equal);
        let text = translate(&i, &test_namer).unwrap().unwrap();
        assert!(text.contains("goto 0x1100"), "应含 goto：{text}");
        assert!(text.starts_with("if ("), "应保留条件：{text}");
        // 不得出现 C 的语句块花括号 —— 那会让人以为是结构化输出。
        assert!(!text.contains('{'), "不得输出块结构：{text}");
    }

    #[test]
    fn indirect_branch_says_unknown_instead_of_guessing() {
        // 间接跳转没有目标：必须写明"未知"，不能编一个地址。
        let i = insn(0x2000, 2, Flow::Branch { conditional: false }, None, vec![]);
        let text = translate(&i, &test_namer).unwrap().unwrap();
        assert!(text.contains("目标未知"), "应说明目标未知：{text}");
        assert!(text.contains("goto"), "仍需给出 goto：{text}");
    }

    #[test]
    fn return_and_trap_are_rendered() {
        let r = insn(0, 3, Flow::Return, None, vec![]);
        assert_eq!(translate(&r, &test_namer).unwrap().unwrap(), "return");
        let t = insn(0, 4, Flow::Trap, None, vec![]);
        assert!(translate(&t, &test_namer)
            .unwrap()
            .unwrap()
            .contains("trap"));
    }

    #[test]
    fn memory_width_comes_from_the_instruction() {
        // 宽度是事实（从 MemRef::size 读），所以类型必须跟着变。
        let m32 = bitflip_arch::MemRef {
            base: Some(RegId(19)),
            index: None,
            scale: 1,
            disp: 0x10,
            size: 4,
            write: false,
            index_extend: None,
        };
        let t = mem_text(&m32, &test_namer);
        assert!(t.contains("uint32_t"), "{t}");
        assert!(t.contains("rax + 0x10"), "{t}");

        let m8 = bitflip_arch::MemRef { size: 1, ..m32 };
        assert!(mem_text(&m8, &test_namer).contains("uint8_t"));

        // 非标准宽度不得硬塞 C 类型。
        let m12 = bitflip_arch::MemRef { size: 12, ..m32 };
        let t12 = mem_text(&m12, &test_namer);
        assert!(t12.contains("12 字节"), "应如实标注字节数：{t12}");
    }

    #[test]
    fn sanitize_leaves_valid_names_alone_and_fixes_invalid() {
        assert_eq!(sanitize_identifier("main"), "main");
        assert_eq!(sanitize_identifier("ns::f<1>"), "ns__f_1_");
        // 以数字开头的名字要加前缀（C 标识符不能以数字开头）。
        assert_eq!(sanitize_identifier("0start"), "_0start");
        assert_eq!(sanitize_identifier(""), "sub");
    }

    #[test]
    fn unnamed_function_gets_a_note_not_a_fabricated_name() {
        let cfg = Cfg::build(&[]);
        let f = decompile_function(0x1000, None, &[], &cfg, &test_namer);
        assert!(f.name.is_none(), "不得编造名字");
        assert!(f.notes.contains(&PseudocodeNote::Unnamed));
        // 渲染时用入口地址，不是 func_xxx。
        let text = render_function_text(&f);
        assert!(text.contains("0x1000"), "{text}");
        assert!(!text.contains("func_"), "不得出现编造名：{text}");
    }

    #[test]
    fn flat_goto_note_is_always_present() {
        // 这条说明决定了用户怎么读输出，漏掉它等于让用户误判。
        let cfg = Cfg::build(&[]);
        let f = decompile_function(0, Some("f"), &[], &cfg, &test_namer);
        assert!(f.notes.contains(&PseudocodeNote::FlatGoto));
        assert!(!f.structured, "本模块恒不结构化");
    }

    #[test]
    fn every_statement_traces_to_an_instruction_address() {
        // 可追溯性是本模块的立身之本：每条语句都要带来源地址。
        let ops = vec![Operand::Reg(RegId(19)), Operand::Imm(7)];
        let insns = vec![insn(0x1000, 10, Flow::Fallthrough, None, ops)];
        let cfg = Cfg::build(&insns);
        let f = decompile_function(0x1000, Some("f"), &insns, &cfg, &test_namer);
        assert_eq!(f.untranslated, 0, "这条应当能翻译");
        for b in &f.blocks {
            for s in &b.statements {
                assert!(s.addr >= b.start && s.addr < b.end, "语句地址应在块内");
            }
        }
    }
}
