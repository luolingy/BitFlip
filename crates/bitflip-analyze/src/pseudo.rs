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
    resolvers: Resolvers<'_>,
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
        let mut prev: Option<&DecodedInsn> = None;
        for (&addr, insn) in by_addr.range(b.start..b.end) {
            if statement_count >= MAX_STATEMENTS {
                truncated += 1;
                continue;
            }
            match translate(
                insn,
                namer,
                resolvers.import,
                resolvers.string,
                resolvers.mnemonic,
                prev,
            ) {
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
            prev = Some(insn);
        }
        // 返回值归纳：`ret` 前紧邻一条对 `eax`/`rax` 的赋值时，融合成 `return <expr>;`。
        fuse_return_value(&mut statements);
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
    import_namer: Option<ImportNamer<'_>>,
    string_reader: Option<StringReader<'_>>,
    mnemonic: Option<MnemonicResolver<'_>>,
    prev: Option<&DecodedInsn>,
) -> Result<Option<String>, String> {
    let m = insn.mnemonic;
    let ops = &insn.operands;

    // 控制流先处理：它们不遵守"目标 = 第一个操作数"的一般形状。
    match insn.flow {
        Flow::Return => return Ok(Some("return".to_string())),
        Flow::Trap => return Ok(Some(format!("__builtin_trap() /* {} */", insn_name(m)))),
        Flow::Branch { conditional } => {
            // 目标表达式：常量地址直接写；间接时把**真实来源**（槽地址/寄存器/表寻址）写出来，
            // 只有确实无法表达才说未知 —— 用一个裸 `0` 冒充目标地址是误导（§7）。
            let target = match insn.target {
                Some(t) => format!("{t:#x}"),
                None => indirect_goto_target(insn, namer, import_namer, false)
                    .unwrap_or_else(|| "/* 目标未知（间接） */ 0".to_string()),
            };
            if conditional {
                // 能从前一条 `cmp`/`test` 还原成真实比较时就还，否则退回标志位占位。
                let cond = branch_condition_text(insn, prev, namer);
                return Ok(Some(format!("if ({cond}) goto {target}")));
            }
            return Ok(Some(format!("goto {target}")));
        }
        Flow::Call => {
            // call 的"目标"是被调用的函数；参数不在操作数里（要跨指令读寄存器），
            // 所以这里**不编造参数**，只给被调者地址。
            let callee = match insn.target {
                Some(t) => format!("{t:#x}"),
                // call 通过槽间接调用时，若有导入名就直接用名字（可读性最高）。
                None => indirect_goto_target(insn, namer, import_namer, true)
                    .unwrap_or_else(|| "/* 目标未知（间接） */ 0".to_string()),
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

    // 一般形状：目标 ← 表达式。但**不是所有两操作数指令都是 mov** —— `add`/`xor`/`shl`
    // 等必须按真实运算符还原，否则会把加法写成赋值、把 `xor r,r`（清零）写成无意义的自赋值。
    // 助记符文本来自注入的 `MnemonicResolver`（本 crate 无编号→文本表）。
    let name = insn_name(m);
    if ops.is_empty() {
        return Ok(Some(format!("/* {name} */")));
    }
    let mn = mnemonic.and_then(|f| f(m)).map(|s| s.to_ascii_lowercase());

    match classify_mnemonic(mn.as_deref()) {
        // 空操作/对齐填充/控制流保护标记 → 有意不产生语句。
        MnemonicClass::Nop => Ok(None),
        // 只设标志、没有可赋值的"目标 ← "形态：`test`/`cmp` 的结果由紧随的分支消费，
        // 输出成一行 `a = b` 是错误的（会误导成赋值）。这里**有意不产生语句**。
        MnemonicClass::FlagsOnly => Ok(None),
        MnemonicClass::Lea => {
            let dst = lvalue(&ops[0], namer)?;
            // lea 计算地址，**不解引用**。`lea r, [mem]` = `r = &mem`（表达式即地址）。
            if let Some(Operand::Mem(mem)) = ops.get(1) {
                Ok(Some(format!("{dst} = {}", mem_addr(mem, namer))))
            } else {
                // 非常规 lea（第二操作数不是内存）→ 落回保守赋值。
                let rhs = expr(&ops[1..], insn.addr, insn.len, namer, string_reader)?;
                Ok(Some(format!("{dst} = {rhs}")))
            }
        }
        MnemonicClass::Binary { op, self_zero } => {
            let dst = lvalue(&ops[0], namer)?;
            let src = expr(&ops[1..], insn.addr, insn.len, namer, string_reader)?;
            // `xor r,r` / `sub r,r` 的同寄存器形状 = 清零（x64 常见零寄存器 idiom）。
            if self_zero && same_register(&ops[0], ops.get(1)) {
                Ok(Some(format!("{dst} = 0")))
            } else {
                Ok(Some(format!("{dst} = {dst} {op} {src}")))
            }
        }
        MnemonicClass::Unary { op, post } => {
            let dst = lvalue(&ops[0], namer)?;
            Ok(Some(match post {
                Some(one) => format!("{dst} = {dst} {one}"),
                None => format!("{dst} = {op}{dst}"),
            }))
        }
        MnemonicClass::Push => {
            // `push x` 语义即把 x 压栈；用 `push(x)` 表达，不改写 rsp 表达式、不编造栈模型。
            let arg = expr(ops, insn.addr, insn.len, namer, string_reader)?;
            Ok(Some(format!("push({arg})")))
        }
        MnemonicClass::Pop => {
            // `pop dst` 语义即从栈弹出到 dst；用 `pop(dst)` 表达。
            let dst = lvalue(&ops[0], namer)?;
            Ok(Some(format!("pop({dst})")))
        }
        MnemonicClass::SetCc => {
            // `setcc dst` 按标志位把 dst 置 0/1。条件来自 `insn.condition`（架构层已按
            // 助记符映射好）。条件不确定时如实显示 `/* 条件未知 */`，仍给 0/1 的形状。
            let dst = lvalue(&ops[0], namer)?;
            let cond = insn
                .condition
                .map_or_else(|| "/* 条件未知 */ flags".to_string(), condition_text);
            Ok(Some(format!("{dst} = ({cond}) ? 1 : 0")))
        }
        MnemonicClass::Div { signed } => {
            // `div`/`idiv <op>`：x86 隐式寄存器除法，被除数是 `rdx:rax`（跨两个寄存器，
            // 无法在 C 里用单表达式精确表达），商→rax、余数→rdx。这里如实渲染成一条**标注
            // 语义的注释语句**：既不是瞎猜的赋值，也比"无法翻译"有信息量（§7：宁写清楚不猜）。
            let op = expr(ops, insn.addr, insn.len, namer, string_reader)?;
            let kind = if signed { "idiv" } else { "div" };
            Ok(Some(format!(
                "/* {kind} {op}：被除数 rdx:rax，商→rax，余数→rdx */"
            )))
        }
        MnemonicClass::Extend { signed } => {
            // `movzx/movsx/movsxd dst, src`：**扩宽搬运**，不是普通 `dst = src`——高位置 0
            // （零扩展）或按符号填满（符号扩展）。源宽度取源寄存器名/内存大小（事实）；
            // 宽度拿不到时退回普通赋值（不猜），但会尽力标注。渲染成带类型转换的形式：
            //   movzx eax, cl  →  eax = (uint8_t)cl
            //   movsx eax, cl  →  eax = (int8_t)cl
            if ops.len() < 2 {
                return Err(format!("{name} 为单操作数指令，无法用赋值形式表达"));
            }
            let dst = lvalue(&ops[0], namer)?;
            let rhs = expr(&ops[1..], insn.addr, insn.len, namer, string_reader)?;
            // 只有**寄存器源**需要补宽度转换：内存源的 `mem_text` 已经带了 `*(uintN_t*)` 类型，
            // 再套一层 `(uintN_t)` 是冗余噪声。寄存器的名字本身没体现出扩展宽度，故补上。
            let ty = match &ops[1] {
                Operand::Reg(r) => {
                    let nm = namer(r.0).ok_or_else(|| format!("寄存器编号 {} 无名字", r.0))?;
                    reg_width_from_name(&nm).map(|w| {
                        if signed {
                            signed_int_type(w)
                        } else {
                            int_type(w)
                        }
                    })
                }
                _ => None,
            };
            match ty {
                Some(ty) => Ok(Some(format!("{dst} = ({ty}){rhs}"))),
                // 源类型已由 mem_text 表达 / 宽度无证据：退回普通赋值，不编造宽度。
                None => Ok(Some(format!("{dst} = {rhs}"))),
            }
        }
        MnemonicClass::Move => {
            if ops.len() < 2 {
                return Err(format!("{name} 为单操作数指令，无法用赋值形式表达"));
            }
            // `mov [rip+rel], reg`：写到 RIP 相对的全局地址。宽度从源寄存器名如实推断
            // （`rcx`→8、`eax`→4…），渲染成 `*(uintN *)(0xABS) = reg`。
            if let Some(text) = store_to_pc_relative(insn, ops, namer, string_reader)? {
                Ok(Some(text))
            } else {
                let dst = lvalue(&ops[0], namer)?;
                let rhs = expr(&ops[1..], insn.addr, insn.len, namer, string_reader)?;
                Ok(Some(format!("{dst} = {rhs}")))
            }
        }
        MnemonicClass::Unknown => {
            // 助记符不认识（或没提供）：退回最保守的"目标 ← 源"。对 mov 正确；对别的指令
            // 可能不准确，但至少在没 mnemonic 解析器时保持既有行为，不引入新回归。
            if ops.len() < 2 {
                return Err(format!("{name} 为单操作数指令，无法用赋值形式表达"));
            }
            if let Some(text) = store_to_pc_relative(insn, ops, namer, string_reader)? {
                Ok(Some(text))
            } else {
                let dst = lvalue(&ops[0], namer)?;
                let rhs = expr(&ops[1..], insn.addr, insn.len, namer, string_reader)?;
                Ok(Some(format!("{dst} = {rhs}")))
            }
        }
    }
}

/// 若目标是 RIP 相对地址（`[rip+rel]`）且**源是寄存器**，渲染成对全局变量的存储：
/// `*(uintN *)(0xABS) = src`。宽度由源寄存器名推断（`rcx`→8、`eax`→4…）。
///
/// 源不是寄存器（立即数/内存）时返回 `Ok(None)` 而**不猜**宽度 —— 让上层照常处理或如实报错。
/// 这解决的是"`mov [rip+rel], rcx` 这类全局变量写入渲染不出来"的真实缺口。
fn store_to_pc_relative(
    insn: &DecodedInsn,
    ops: &[Operand],
    namer: RegisterNamer<'_>,
    string_reader: Option<StringReader<'_>>,
) -> Result<Option<String>, String> {
    let Some(Operand::PcRelative(rel)) = ops.first() else {
        return Ok(None);
    };
    // 源必须是寄存器，才能从名字推宽度。
    let Some(Operand::Reg(src_reg)) = ops.get(1) else {
        return Ok(None);
    };
    let Some(src_name) = namer(src_reg.0) else {
        return Ok(None);
    };
    let Some(width) = reg_width_from_name(&src_name) else {
        return Ok(None);
    };
    // RIP 相对：绝对地址 = 指令末 + 位移（与 expr 的口径一致）。
    let abs = insn
        .addr
        .wrapping_add(u64::from(insn.len))
        .wrapping_add(*rel as u64);
    let ty = int_type(width);
    let value = expr(&ops[1..], insn.addr, insn.len, namer, string_reader)?;
    let store = format!("*({ty} *)({abs:#x}) = {value}");
    Ok(Some(annotate_string(store, abs, string_reader)))
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

/// 若 `text` 是形如 `eax = <expr>` / `rax = <expr>` 的赋值，返回 `<expr>`（返回值表达式）。
///
/// 只认 x86 返回寄存器 `eax`（32 位）/`rax`（64 位）。`eaxjunk = ...` 之类不会被误认
/// （要求前缀后**恰好**是 ` = `）。这两个寄存器是 SysV/MS x64 的返回值寄存器（事实）。
fn return_value_expr(text: &str) -> Option<&str> {
    for reg in ["rax", "eax"] {
        if let Some(rest) = text.strip_prefix(reg) {
            if let Some(value) = rest.strip_prefix(" = ") {
                // 排除把 `rax` 用作更长的名字前缀（含 `[`/`(`/字母/数字）的情形。
                let next = text[reg.len()..].chars().next();
                if matches!(next, Some(' ')) && !value.is_empty() {
                    return Some(value);
                }
            }
        }
    }
    None
}

/// 返回值归纳：`ret` 前先跳过**纯尾声指令**（`pop`、`rsp` 调整、恢复被调用者保存寄存器），
/// 再遇到 `eax = <expr>` / `rax = <expr>` 时融合成 `return <expr>;`。
///
/// 判据保守但不失覆盖：仅当从 `return` 回溯、沿途全是"**不写返回值寄存器、不调用**"的
/// 尾声语句时才融合；一旦遇到未知语句或 `call`（可能改写 rax）就**停止、不融合**。这既覆盖
/// 常见的 `eax = v; rsp += N; pop...; ret` 形态，又绝不误吞可能改写返回值的语句（不猜数据流）。
pub(crate) fn fuse_return_value(statements: &mut Vec<PseudocodeStatement>) {
    let n = statements.len();
    if n < 2 {
        return;
    }
    if statements[n - 1].text.trim() != "return" {
        return;
    }
    // 从 return 前一条开始回溯。
    let mut i = n - 2;
    // 收集可跳过的尾声语句（不写 rax/eax、不 call）。
    while i > 0 && is_epilogue_statement(&statements[i].text) {
        i -= 1;
    }
    let Some(value) = return_value_expr(&statements[i].text) else {
        return;
    };
    // 融合：把 return 之前、从 i 到末尾的尾部语句都删掉（它们是尾声），返回 i 处的值。
    let value = value.trim().to_string();
    statements[i].addr = statements[n - 1].addr;
    statements[i].text = format!("return {value}");
    statements.truncate(i + 1);
}

/// 判断一条语句是否是"纯尾声"语句（跳过它去寻找返回值赋值是安全的）。
///
/// 安全前提：**不写 `eax`/`rax`、不是 `call`**。只认几类确定形态：
/// `pop(...)`、`rsp = ...`（栈指针复位/调整）、恢复被调用者保存寄存器（`rbx/rsi/rdi/rbp/r12..15`
/// 及其 32 位形式）。其余一律视为"停下"（返回 false）。
fn is_epilogue_statement(text: &str) -> bool {
    let t = text.trim();
    if t.starts_with("pop(") {
        return true;
    }
    if t.starts_with("/* call */") {
        return false; // 调用可能改写 rax —— 必须停。
    }
    // `rsp = ...`（栈指针复位）。
    if t.starts_with("rsp = ") {
        return true;
    }
    // 恢复被调用者保存寄存器：<callee-saved reg> = ...
    const CALLEE_SAVED: &[&str] = &[
        "rbx", "ebx", "rsi", "esi", "rdi", "edi", "rbp", "ebp", "r12", "r12d", "r13", "r13d",
        "r14", "r14d", "r15", "r15d",
    ];
    for reg in CALLEE_SAVED {
        if let Some(rest) = t.strip_prefix(reg) {
            if rest.starts_with(" = ") {
                return true;
            }
        }
    }
    false
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

/// 条件分支的 C 表达式：能从前一条 `cmp`/`test` 还原成**真实比较**时就还，
/// 否则退回标志位形式 `/* Cond */ flags`。
///
/// # 依据（为什么这不是猜）
///
/// x86 的条件跳转（`jl`/`jae`…）本身只读标志位；要给出 `a < b` 这样的比较，
/// 必须结合**紧邻其前**那条设置标志的指令。这里的做法是结构化的、限定严格的：
/// - 只认**同一条基本块内、紧挨在分支之前**的那条指令（`prev`）；
/// - 它必须**不写任何通用寄存器**（`writes` 空）却读寄存器 —— 这正是 `cmp`/`test`
///   这类"只设标志"指令的形状（普通算术会写目标寄存器，因此被排除）；
/// - 两个操作数都是**同一寄存器**（`test a,a` 的自测形状）→ 还原成与 0 比较；
///   否则按 `cmp a,b` 还原成有序比较。
///
/// 关系符按条件码的无/有符号语义选择（`jb` 是无符号"低于"→ `(unsigned)a < b`）。
/// 拿不准的条件（`js`/`jo` 之类在 `cmp` 后很罕见）**退回标志位**，不硬套比较 —— §7 不猜。
pub(crate) fn branch_condition_text(
    branch: &DecodedInsn,
    prev: Option<&DecodedInsn>,
    namer: RegisterNamer<'_>,
) -> String {
    let Some(cc) = branch.condition else {
        return "/* 条件未知 */ flags".to_string();
    };
    if let Some(text) = try_comparison(cc, prev, namer) {
        return text;
    }
    condition_text(cc)
}

/// 收集一条指令所有操作数里出现的寄存器编号（基址/索引/移位寄存器都算）。
///
/// 用于判断"被写的寄存器是否就是某个操作数"——这是区分 `cmp/test`（只写标志）与
/// `mov/add`（写目标操作数）的**与架构无关**的结构判据。
fn operand_reg_ids(ops: &[Operand]) -> std::collections::BTreeSet<u16> {
    let mut set = std::collections::BTreeSet::new();
    for op in ops {
        match op {
            Operand::Reg(r) => {
                set.insert(r.0);
            }
            Operand::Mem(m) => {
                if let Some(b) = m.base {
                    set.insert(b.0);
                }
                if let Some(i) = m.index {
                    set.insert(i.0);
                }
            }
            Operand::Shifted { reg, .. } => {
                set.insert(reg.0);
            }
            _ => {}
        }
    }
    set
}

/// 尝试把 `prev`(cmp/test) + `cc` 还原成比较表达式；不成立返回 `None`。
fn try_comparison(
    cc: ConditionCode,
    prev: Option<&DecodedInsn>,
    namer: RegisterNamer<'_>,
) -> Option<String> {
    let p = prev?;
    // 形状门槛：只设标志、有两个操作数、顺序流、读寄存器。
    //
    // "只设标志"的判据**纯结构化、不硬编码架构寄存器名/编号**（硬编码会破坏分层，
    // 按名字（"rflags"/"nzcv"）匹配同样会引入架构词汇）。用的是这样一条与架构无关的事实：
    // `cmp`/`test` 的写集合是**标志寄存器**，它**不是**这条指令的操作数之一；
    // 而 `mov`/`add`/`sub` 等会写**目标操作数**（写集合里含某个操作数寄存器）。
    // 于是判据是："被写的寄存器**都不在操作数寄存器集合里**"。
    if p.reads.is_empty() || p.operands.len() < 2 {
        return None;
    }
    if !matches!(p.flow, Flow::Fallthrough) {
        return None;
    }
    let operand_regs = operand_reg_ids(&p.operands);
    let writes_only_flags = p.writes.iter().all(|r| !operand_regs.contains(&r.0));
    if !writes_only_flags {
        return None;
    }
    let lhs = expr_one(&p.operands[0], p.addr, p.len, namer, None).ok()?;
    let rhs = expr_one(&p.operands[1], p.addr, p.len, namer, None).ok()?;

    // `test a, a` 的自测形状：两操作数是同一寄存器 → 与 0 比较。
    let same_reg = match (&p.operands[0], &p.operands[1]) {
        (Operand::Reg(a), Operand::Reg(b)) => a.0 == b.0,
        _ => false,
    };
    if same_reg {
        return Some(match cc {
            ConditionCode::Equal => format!("{lhs} == 0"),
            ConditionCode::NotEqual => format!("{lhs} != 0"),
            ConditionCode::Minus => format!("(int64_t){lhs} < 0"),
            ConditionCode::Plus => format!("(int64_t){lhs} >= 0"),
            // 其它条件对"自测"没有简洁语义 → 不猜。
            _ => return None,
        });
    }

    // 有序比较：按 cc 的语义选运算符。
    let op = match cc {
        ConditionCode::Equal => format!("{lhs} == {rhs}"),
        ConditionCode::NotEqual => format!("{lhs} != {rhs}"),
        // 有符号关系。
        ConditionCode::SignedLessThan => format!("{lhs} < {rhs}"),
        ConditionCode::SignedGreaterEqual => format!("{lhs} >= {rhs}"),
        ConditionCode::SignedGreaterThan => format!("{lhs} > {rhs}"),
        ConditionCode::SignedLessOrEqual => format!("{lhs} <= {rhs}"),
        // 无符号关系（cast 出来才诚实：同一标志位在有/无符号下含义不同）。
        ConditionCode::CarryClear => format!("(uint64_t){lhs} < (uint64_t){rhs}"),
        ConditionCode::CarrySet => format!("(uint64_t){lhs} >= (uint64_t){rhs}"),
        ConditionCode::UnsignedHigher => format!("(uint64_t){lhs} > (uint64_t){rhs}"),
        ConditionCode::UnsignedLowerOrSame => format!("(uint64_t){lhs} <= (uint64_t){rhs}"),
        // Minus/Plus/Overflow/NoOverflow/Always/Never 在 cmp 之后没有简洁比较语义 → 不猜。
        _ => return None,
    };
    Some(op)
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
/// 若 `value` 对应的绝对地址指向一段可打印 C 字符串，就在值后面加 ` /* "..." */`。
///
/// 字符串来自注入的 [`StringReader`]；它为 `None` 或那里不是干净字符串时不加任何注释
/// —— 绝不把碰巧可打印的字节谎称字符串（§7）。注释里对内容做转义，避免截断/串行。
fn annotate_string(value: String, abs: u64, string_reader: Option<StringReader<'_>>) -> String {
    let Some(text) = string_reader.and_then(|f| f(abs)) else {
        return value;
    };
    format!("{value} /* {} */", escape_comment_string(&text))
}

/// 把字符串转义成能安全放进 `/* ... */` 注释的形式：不可打印字节转 `\xNN`，
/// 引号转义，过长截断（保留可读前缀并注明截断）。
fn escape_comment_string(text: &str) -> String {
    const MAX: usize = 64;
    let mut out = String::with_capacity(text.len() + 2);
    out.push('"');
    let mut truncated = false;
    for (index, ch) in text.chars().enumerate() {
        if index >= MAX {
            truncated = true;
            break;
        }
        match ch {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\t' => out.push_str("\\t"),
            '\r' => out.push_str("\\r"),
            c if c.is_control() => out.push_str(&format!("\\x{:02x}", c as u32)),
            c => out.push(c),
        }
    }
    out.push('"');
    if truncated {
        out.push('…');
    }
    out
}

fn expr(
    ops: &[Operand],
    addr: u64,
    len: u8,
    namer: RegisterNamer<'_>,
    string_reader: Option<StringReader<'_>>,
) -> Result<String, String> {
    let mut parts = Vec::new();
    for op in ops {
        parts.push(expr_one(op, addr, len, namer, string_reader)?);
    }
    Ok(parts.join(" + "))
}

/// 生成单个操作数的表达式。
fn expr_one(
    op: &Operand,
    addr: u64,
    len: u8,
    namer: RegisterNamer<'_>,
    string_reader: Option<StringReader<'_>>,
) -> Result<String, String> {
    match op {
        Operand::Reg(r) => namer(r.0).ok_or_else(|| format!("寄存器编号 {} 无名字", r.0)),
        // 立即数写成十六进制：反汇编语境下十六进制比十进制好核对。
        // 若这个立即数其实是个指向只读数据的字符串地址，附注出来（对逆向核对极有用）。
        Operand::Imm(v) => Ok(annotate_string(format!("{v:#x}"), *v as u64, string_reader)),
        Operand::Mem(m) => Ok(mem_text(m, namer)),
        Operand::PcRelative(d) => {
            // 转成绝对地址，这样用户能直接跳过去看。PC 相对是从**指令末**算起的，
            // 所以要加 `len`（不是只加 `addr`，否则每条都偏一个指令长度）。
            let abs = addr.wrapping_add(u64::from(len)).wrapping_add(*d as u64);
            let value = format!("{abs:#x} /* PC 相对 {d:#x} */");
            Ok(annotate_string(value, abs, string_reader))
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

/// 间接跳转/调用的**目标表达式**（`goto ` / `call ` 后面那一段）。
///
/// 不是"猜目标"，而是把**真实来源**写出来（§7）：`target` 为 `None` 的间接转移，其目标
/// 必然是上一步算出来的，而操作数里通常留着线索：
/// - `Operand::PcRelative(rel)`：`jmp [rip+rel]`（典型**导入跳板**）→ 槽地址 = 本指令末 + rel，
///   目标是**槽里存的那个地址**，所以写成 `*(void **)0xSLOT`（解引用槽）。
/// - `Operand::Mem(m)`：`jmp [base+idx*scale+disp]` → `*(void **)(<寻址>)`（解引用算出地址）。
/// - `Operand::Reg(r)`：`jmp reg` → 直接是寄存器里的地址，写成寄存器名。
///
/// 这些都不是"编出来的常量"，而是指令本身表达的事实；比一个裸 `0` 诚实得多。
fn indirect_goto_target(
    insn: &DecodedInsn,
    namer: RegisterNamer<'_>,
    import_namer: Option<ImportNamer<'_>>,
    is_call: bool,
) -> Option<String> {
    match insn.operands.as_slice() {
        // `jmp/call [rip+rel]` —— 导入跳板与 IAT 槽调用。
        [Operand::PcRelative(rel)] => {
            let slot = insn
                .addr
                .wrapping_add(u64::from(insn.len))
                .wrapping_add(*rel as u64);
            // 能解析出导入名时：call 直接用名字（最好读），goto 用解引用+名字注释
            // （因为 goto 的目标必须是"槽里的值"，把名字放在注释里，语义不含糊）。
            let import = import_namer.and_then(|f| f(slot));
            if let Some(name) = import {
                if is_call {
                    // 形如 `KERNEL32.dll!RtlAllocateHeap /* *(void **)0xSLOT */`
                    return Some(format!("{name} /* *(void **){slot:#x} */"));
                }
                return Some(format!("*(void **){slot:#x} /* = {name} */"));
            }
            Some(format!("*(void **){slot:#x}"))
        }
        // `jmp [base+idx*scale+disp]` —— 跳表或槽表寻址。
        [Operand::Mem(m)] => Some(format!("*(void **)({})", mem_text(m, namer))),
        // `jmp reg` —— 地址在寄存器里。
        [Operand::Reg(r)] => Some(namer(r.0).unwrap_or_else(|| format!("reg#{}", r.0))),
        _ => None,
    }
}

/// 内存引用 → `*(T *)(base + index*scale + disp)`。
///
/// **宽度是事实**（`MemRef::size` 从指令读出来），所以 `T` 不是猜的；
/// 但如果 size 不是 1/2/4/8，说明是向量访问或我们理解错了 ——
/// 那种情况如实标注字节数，不硬塞一个 C 类型。
/// 两个操作数是否是同一个寄存器（用于识别 `xor r,r` / `sub r,r` 清零 idiom）。
fn same_register(a: &Operand, b: Option<&Operand>) -> bool {
    matches!((a, b), (Operand::Reg(x), Some(Operand::Reg(y))) if x.0 == y.0)
}

/// 指令按语义分成的形状类别（决定 `translate` 怎么拼语句）。
enum MnemonicClass {
    /// 空操作 / 对齐填充 / 控制流保护标记（`nop`、多字节 `nop [mem]`、`endbr64`…）——
    /// **不产生任何语句**。多字节 `nop` 带一个内存操作数（如 `nop dword ptr [rax+rax*1]`），
    /// 若走"一般形状"会被误报成"单操作数无法翻译"，其实它语义上就是空操作。
    Nop,
    /// 只设标志、无可赋值结果（`test`/`cmp`）。
    FlagsOnly,
    /// `lea`：算地址不解引用。
    Lea,
    /// 二元运算：`dst = dst <op> src`；`self_zero` 时同寄存器形状 → `dst = 0`。
    Binary { op: &'static str, self_zero: bool },
    /// 一元运算：`dst = <op>dst`（neg/not）或 `dst = dst <one>`（inc/dec）。
    Unary {
        op: &'static str,
        post: Option<&'static str>,
    },
    /// `mov` 家族：`dst = src`。
    Move,
    /// `push <op>`：压栈（语义即 `push(x)`，不改写 rsp 表达式、不编造栈模型）。
    Push,
    /// `pop <dst>`：出栈（语义即 `pop(dst)`）。
    Pop,
    /// `setcc <dst>`：按标志位把 dst 置 0/1（渲染成 `dst = (cond) ? 1 : 0`）。
    SetCc,
    /// `div`/`idiv <op>`：单操作数的隐式寄存器除法（被除数 `rdx:rax`，商→`rax`、余数→`rdx`）。
    /// 因为双寄存器被除数无法在 C 里精确表达，渲染成一条**如实标注语义**的注释语句。
    Div { signed: bool },
    /// `movzx`/`movsx`/`movsxd`：零/符号扩展搬运。与普通 `mov` 的差别是**扩宽**语义
    /// （源窄于目标，高位置 0 或按符号扩展），普通 `dst = src` 会丢掉这一步（宽度 bug）。
    /// 源宽度由源寄存器名（或内存操作数大小）确定；渲染成 `dst = (uintN_t)src` / `(intN_t)src`。
    Extend { signed: bool },
    /// 不认识：退回保守赋值。
    Unknown,
}

/// 判断 `set` 之后的后缀是否是合法 x86 条件码（用于把 `setcc` 与 `set...` 其它指令区分开）。
/// 只认 x86 条件码（与 `x86_condition_from_mnemonic` 对齐），不猜未知后缀。
fn x86_cc_suffix(mn: &str) -> bool {
    let Some(rest) = mn.strip_prefix("set") else {
        return false;
    };
    matches!(
        rest,
        "e" | "z"
            | "ne"
            | "nz"
            | "b"
            | "nae"
            | "c"
            | "ae"
            | "nb"
            | "nc"
            | "be"
            | "na"
            | "a"
            | "nbe"
            | "l"
            | "nge"
            | "ge"
            | "nl"
            | "le"
            | "ng"
            | "g"
            | "nle"
            | "s"
            | "ns"
            | "o"
            | "no"
    )
}

/// 从寄存器名推断**访问宽度**（字节）。名字是 capstone 给的事实，宽度映射是固定表，不是猜。
///
/// 只认 x86 通用寄存器命名（`rax`→8 / `eax`→4 / `ax`→2 / `al`→1，`r8`…`r15` 同理，
/// `r8d`→4，`r8w`→2，`r8b`→1）。推不出（如 `xmm`/`st`/未知名）返回 `None`，调用方据此保守处理。
fn reg_width_from_name(name: &str) -> Option<u8> {
    let base = name.trim_start_matches('<').trim_end_matches('>');
    if let Some(rest) = base.strip_prefix('r') {
        if !rest.is_empty() && rest.chars().all(|c| c.is_ascii_digit()) {
            return Some(8); // r8..r15
        }
        let digits: String = rest.chars().take_while(char::is_ascii_digit).collect();
        if !digits.is_empty() {
            return match rest.trim_start_matches(|c: char| c.is_ascii_digit()) {
                "" => Some(8),
                "d" => Some(4),
                "w" => Some(2),
                "b" => Some(1),
                _ => None,
            };
        }
    }
    const EIGHT: &[&str] = &["rax", "rbx", "rcx", "rdx", "rsi", "rdi", "rbp", "rsp"];
    const FOUR: &[&str] = &["eax", "ebx", "ecx", "edx", "esi", "edi", "ebp", "esp"];
    const TWO: &[&str] = &["ax", "bx", "cx", "dx", "si", "di", "bp", "sp"];
    const ONE: &[&str] = &[
        "al", "bl", "cl", "dl", "sil", "dil", "bpl", "spl", "ah", "bh", "ch", "dh",
    ];
    if EIGHT.contains(&base) {
        Some(8)
    } else if FOUR.contains(&base) {
        Some(4)
    } else if TWO.contains(&base) {
        Some(2)
    } else if ONE.contains(&base) {
        Some(1)
    } else {
        None
    }
}

/// 按宽度给 C 整数类型名（用于 PC 相对存储的解引用类型）。
fn int_type(width: u8) -> String {
    match width {
        1 => "uint8_t".to_string(),
        2 => "uint16_t".to_string(),
        4 => "uint32_t".to_string(),
        8 => "uint64_t".to_string(),
        n => format!("/* {n} 字节 */ uint8_t"),
    }
}

/// 按宽度给 C **有符号**整数类型名（用于 `movsx` 符号扩展的源类型转换）。
fn signed_int_type(width: u8) -> String {
    match width {
        1 => "int8_t".to_string(),
        2 => "int16_t".to_string(),
        4 => "int32_t".to_string(),
        8 => "int64_t".to_string(),
        n => format!("/* {n} 字节 */ int8_t"),
    }
}

/// 把可读助记符文本归类。只处理常见 x86/ARM 算术逻辑；未知返回 `Unknown`（走保守路径）。
///
/// 依据是**指令语义**（事实），不是猜：`add` 就是加法、`xor r,r` 就是清零。给出正确运算
/// 比一句占位更有用，也比把加法错写成赋值诚实得多（§7）。
fn classify_mnemonic(mn: Option<&str>) -> MnemonicClass {
    let Some(mn) = mn else {
        return MnemonicClass::Unknown;
    };
    // `setcc`（setne/setb/setns…）是一大类条件置位指令：后缀与 jcc 同构。
    if mn.starts_with("set") && x86_cc_suffix(mn) {
        return MnemonicClass::SetCc;
    }
    match mn {
        // 空操作/对齐填充/控制流保护标记：无论是否带操作数，都不产生语句。
        "nop" | "endbr64" | "endbr32" | "hint" | "bti" => MnemonicClass::Nop,
        "mov" | "movabs" | "movz" | "movs" => MnemonicClass::Move,
        "movzx" | "movsx" | "movsxd" => MnemonicClass::Extend {
            signed: mn != "movzx",
        },
        "push" | "pushf" | "pushfq" => MnemonicClass::Push,
        "pop" | "popf" | "popfq" => MnemonicClass::Pop,
        "lea" | "adr" | "adrp" => MnemonicClass::Lea,
        "test" | "cmp" | "cmn" | "tst" => MnemonicClass::FlagsOnly,
        "add" | "adds" => MnemonicClass::Binary {
            op: "+",
            self_zero: false,
        },
        "sub" | "subs" => MnemonicClass::Binary {
            op: "-",
            self_zero: true,
        },
        "and" | "ands" => MnemonicClass::Binary {
            op: "&",
            self_zero: false,
        },
        "or" | "orr" | "orrs" => MnemonicClass::Binary {
            op: "|",
            self_zero: false,
        },
        "xor" | "eor" | "xors" => MnemonicClass::Binary {
            op: "^",
            self_zero: true,
        },
        "imul" | "mul" | "madd" => MnemonicClass::Binary {
            op: "*",
            self_zero: false,
        },
        "idiv" => MnemonicClass::Div { signed: true },
        "div" => MnemonicClass::Div { signed: false },
        "shl" | "sal" | "lsl" | "slli" => MnemonicClass::Binary {
            op: "<<",
            self_zero: false,
        },
        "shr" | "lsr" | "srli" => MnemonicClass::Binary {
            op: ">>",
            self_zero: false,
        },
        "sar" | "asr" | "srai" => MnemonicClass::Binary {
            op: ">>",
            self_zero: false,
        },
        "inc" => MnemonicClass::Unary {
            op: "",
            post: Some("+ 1"),
        },
        "dec" => MnemonicClass::Unary {
            op: "",
            post: Some("- 1"),
        },
        "neg" => MnemonicClass::Unary {
            op: "-",
            post: None,
        },
        "not" | "mvn" => MnemonicClass::Unary {
            op: "~",
            post: None,
        },
        _ => MnemonicClass::Unknown,
    }
}

fn mem_text(m: &bitflip_arch::MemRef, namer: RegisterNamer<'_>) -> String {
    let ty = match m.size {
        1 => "uint8_t".to_string(),
        2 => "uint16_t".to_string(),
        4 => "uint32_t".to_string(),
        8 => "uint64_t".to_string(),
        n => format!("/* {n} 字节 */ uint8_t"),
    };
    let inner = frame_slot_ref(m, namer).unwrap_or_else(|| mem_addr(m, namer));
    if m.write {
        format!("*({ty} *)({inner}) /* 写 */")
    } else {
        format!("*({ty} *)({inner})")
    }
}

/// 若这是一次**固定栈槽**访存（`rsp + 常量`，无 index），返回一个符号化引用 `&v<偏移>`，
/// 让 `*(uint64_t *)(rsp + 0x88)` 读成 `*(uint64_t *)(&v88)`——一眼看出是同一栈槽。
///
/// 只认 `rsp`（栈指针）+ 常量位移 + 无 index 的形状（2017/2566 的帧访问是这一形状）；
/// `rbp`/带 index/寄存器位移一律不符号化（可能是动态寻址，不是固定槽）。**仅改名、不改语义**：
/// 外层 `*(ty *)` 的宽度保留，`&v<偏移>` 就是该栈槽地址。`lea` 走 [`mem_addr`]，不受影响
/// （它要真实地址算术，不能变成符号名）。
fn frame_slot_ref(m: &bitflip_arch::MemRef, namer: RegisterNamer<'_>) -> Option<String> {
    if m.index.is_some() || m.disp == 0 {
        return None;
    }
    let base = m.base?;
    let name = namer(base.0)?;
    if name != "rsp" {
        return None;
    }
    // 位移按无符号栈偏移命名（`rsp + 0x88` → `v88`）；负位移极少见，用 `m<偏移>` 区分。
    let slot = if m.disp >= 0 {
        format!("v{:x}", m.disp as u64)
    } else {
        format!("m{:x}", (-m.disp) as u64)
    };
    Some(format!("&{slot}"))
}

/// 内存引用的**地址表达式**（`base + index*scale + disp`），不含解引用/宽度。
/// `lea` 要的正是这个（它算地址、不加载）。
fn mem_addr(m: &bitflip_arch::MemRef, namer: RegisterNamer<'_>) -> String {
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
    parts.join(" + ")
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

/// 只读数据读取器：按虚拟地址读 `len` 字节（用于读 switch 跳表）。
///
/// 返回 `Some(bytes)` 表示读到了（可能短于 `len`，到段尾），`None` 表示该地址
/// 不在任何已映射区间。**不补零冒充**（§7）：读不到就是读不到，调用方据此放弃还原。
///
/// 与 [`RegisterNamer`] 同样的注入方式：本 crate 不持有"目标内存"，由调用方
/// （core 的 `Session::read_virtual`）提供。
pub type TableReader<'a> = &'a dyn Fn(u64, usize) -> Option<Vec<u8>>;

/// 导入名解析器：给一个**槽地址/IAT 地址**，返回该导入的可读名（例如
/// `KERNEL32.dll!RtlAllocateHeap`），解不出来就 `None`。
///
/// 与 [`RegisterNamer`]/[`TableReader`] 同一种注入方式：本 crate 不持有导入表，
/// 由 core 用 `ImportEdges` 提供。**解不出来就返回 None**，渲染层据此退回显示槽地址，
/// 绝不编一个像模像样的函数名（§7）。
pub type ImportNamer<'a> = &'a dyn Fn(u64) -> Option<String>;

/// 字符串解析器：给一个**绝对虚拟地址**，若那里是一段可打印的 C 字符串（只读数据），
/// 返回它（不含结尾 NUL）；否则 `None`。
///
/// 与 [`RegisterNamer`]/[`TableReader`]/[`ImportNamer`] 同一种注入：本 crate 不做
/// "哪段是可读只读数据、这段字节算不算字符串" 的判定（那是 loader/地址空间的活），
/// 由 core 提供。返回 `None` 时渲染层**不加**任何注释 —— 绝不把碰巧可打印的数据谎称字符串。
pub type StringReader<'a> = &'a dyn Fn(u64) -> Option<String>;

/// 助记符解析器：`MnemonicId`（capstone 原始编号）→ 可读助记符文本（小写，如 `"mov"`/`"xor"`）。
///
/// 本 crate 不持有"编号 → 文本"的表（那张表在 `bitflip-arch` 解码后端里），所以算术/逻辑
/// 指令的**真实语义**（`add` 是加法不是赋值、`xor r,r` 是清零）必须靠它来判——注入失败时
/// 只能退回最保守的"目标 ← 源"，那对 `add`/`xor` 是**不准确**的，故 real 运行务必提供。
pub type MnemonicResolver<'a> = &'a dyn Fn(bitflip_arch::MnemonicId) -> Option<String>;

/// 可选的外部事实解析器集合（跳表 / 导入名 / 字符串）。
///
/// 打包成一个结构而不是三个独立参数：它们都是"本 crate 不持有、由 core 注入"的查询，
/// 一起传既避免参数列表膨胀，也让调用点一眼看清"这个渲染拿到了哪些外部事实"。
/// 全部为 `None` 时渲染层只写自己确知的东西（不猜）。
#[derive(Clone, Copy, Default)]
pub struct Resolvers<'a> {
    /// switch 跳表读取器。
    pub table: Option<TableReader<'a>>,
    /// 导入名解析器（槽 → `模块!函数`）。
    pub import: Option<ImportNamer<'a>>,
    /// 只读数据里的 C 字符串解析器。
    pub string: Option<StringReader<'a>>,
    /// 助记符解析器（编号 → 文本），用于还原算术/逻辑指令的真实语义。
    pub mnemonic: Option<MnemonicResolver<'a>>,
}

impl<'a> Resolvers<'a> {
    /// 全都没有：只做纯指令级翻译。
    #[must_use]
    pub const fn none() -> Self {
        Self {
            table: None,
            import: None,
            string: None,
            mnemonic: None,
        }
    }
}

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
    use bitflip_arch::{Arch, ConditionCode, MnemonicId, RegId, RegSet};

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

    /// 造一条伪代码语句（用于直接测 `fuse_return_value`）。
    fn stmt(addr: u64, text: &str) -> PseudocodeStatement {
        PseudocodeStatement {
            addr,
            text: text.to_string(),
        }
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
        let e = translate(&i, &test_namer, None, None, None, None).unwrap_err();
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
        let text = translate(&i, &test_namer, None, None, None, None)
            .unwrap()
            .unwrap();
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
        let text = translate(&i, &test_namer, None, None, None, None)
            .unwrap()
            .unwrap();
        assert!(text.contains("goto 0x1100"), "应含 goto：{text}");
        assert!(text.starts_with("if ("), "应保留条件：{text}");
        // 不得出现 C 的语句块花括号 —— 那会让人以为是结构化输出。
        assert!(!text.contains('{'), "不得输出块结构：{text}");
    }

    #[test]
    fn indirect_branch_says_unknown_instead_of_guessing() {
        // 间接跳转没有目标：必须写明"未知"，不能编一个地址。
        let i = insn(0x2000, 2, Flow::Branch { conditional: false }, None, vec![]);
        let text = translate(&i, &test_namer, None, None, None, None)
            .unwrap()
            .unwrap();
        assert!(text.contains("目标未知"), "应说明目标未知：{text}");
        assert!(text.contains("goto"), "仍需给出 goto：{text}");
    }

    #[test]
    fn return_and_trap_are_rendered() {
        let r = insn(0, 3, Flow::Return, None, vec![]);
        assert_eq!(
            translate(&r, &test_namer, None, None, None, None)
                .unwrap()
                .unwrap(),
            "return"
        );
        let t = insn(0, 4, Flow::Trap, None, vec![]);
        assert!(translate(&t, &test_namer, None, None, None, None)
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
        let f = decompile_function(0x1000, None, &[], &cfg, &test_namer, Resolvers::none());
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
        let f = decompile_function(0, Some("f"), &[], &cfg, &test_namer, Resolvers::none());
        assert!(f.notes.contains(&PseudocodeNote::FlatGoto));
        assert!(!f.structured, "本模块恒不结构化");
    }

    #[test]
    fn every_statement_traces_to_an_instruction_address() {
        // 可追溯性是本模块的立身之本：每条语句都要带来源地址。
        let ops = vec![Operand::Reg(RegId(19)), Operand::Imm(7)];
        let insns = vec![insn(0x1000, 10, Flow::Fallthrough, None, ops)];
        let cfg = Cfg::build(&insns);
        let f = decompile_function(
            0x1000,
            Some("f"),
            &insns,
            &cfg,
            &test_namer,
            Resolvers::none(),
        );
        assert_eq!(f.untranslated, 0, "这条应当能翻译");
        for b in &f.blocks {
            for s in &b.statements {
                assert!(s.addr >= b.start && s.addr < b.end, "语句地址应在块内");
            }
        }
    }

    /// 造一条"只设标志"的 `cmp`/`test`：reads 有、writes 空、顺序流、两操作数。
    fn cmp(addr: u64, a: Operand, b: Operand) -> DecodedInsn {
        let mut i = insn(addr, 7, Flow::Fallthrough, None, vec![a, b]);
        // 读到寄存器（capstone 对 cmp 的常见表现），但不写通用寄存器。
        if let Operand::Reg(r) = &i.operands[0] {
            i.reads.insert(*r);
        }
        i
    }

    /// 造一条条件跳转（设置 condition）。
    fn jcc(addr: u64, cc: ConditionCode) -> DecodedInsn {
        let mut i = insn(
            addr,
            7,
            Flow::Branch { conditional: true },
            Some(0x2000),
            vec![],
        );
        i.condition = Some(cc);
        i
    }

    #[test]
    fn cmp_plus_jcc_becomes_real_comparison() {
        // cmp rax, 0x7 ; jl → if (rax < 0x7)
        let c = cmp(0x1000, Operand::Reg(RegId(19)), Operand::Imm(7));
        let j = jcc(0x1003, ConditionCode::SignedLessThan);
        assert_eq!(
            branch_condition_text(&j, Some(&c), &test_namer),
            "rax < 0x7"
        );
    }

    #[test]
    fn cmp_equality_uses_double_equals() {
        let c = cmp(0x1000, Operand::Reg(RegId(19)), Operand::Reg(RegId(26)));
        let j = jcc(0x1003, ConditionCode::Equal);
        assert_eq!(
            branch_condition_text(&j, Some(&c), &test_namer),
            "rax == rcx"
        );
    }

    #[test]
    fn unsigned_condition_casts_both_sides() {
        // jb（无符号低于）→ (uint64_t)rax < (uint64_t)rdx
        let c = cmp(0x1000, Operand::Reg(RegId(19)), Operand::Reg(RegId(27)));
        let j = jcc(0x1003, ConditionCode::CarryClear);
        assert_eq!(
            branch_condition_text(&j, Some(&c), &test_namer),
            "(uint64_t)rax < (uint64_t)rdx"
        );
    }

    #[test]
    fn test_self_shape_becomes_zero_compare() {
        // test rax, rax ; jz → rax == 0
        let c = cmp(0x1000, Operand::Reg(RegId(19)), Operand::Reg(RegId(19)));
        let j = jcc(0x1003, ConditionCode::Equal);
        assert_eq!(branch_condition_text(&j, Some(&c), &test_namer), "rax == 0");
        let jnz = jcc(0x1003, ConditionCode::NotEqual);
        assert_eq!(
            branch_condition_text(&jnz, Some(&c), &test_namer),
            "rax != 0"
        );
    }

    #[test]
    fn no_prev_or_non_flags_insn_falls_back_to_flags() {
        // 没有前驱 → 标志位占位。
        let j = jcc(0x1000, ConditionCode::SignedLessThan);
        assert_eq!(
            branch_condition_text(&j, None, &test_namer),
            "/* SignedLessThan */ flags"
        );
        // 前驱会写通用寄存器（不是 cmp/test 形状）→ 不还原比较，退回标志位。
        let mut arith = insn(
            0x1000,
            7,
            Flow::Fallthrough,
            None,
            vec![Operand::Reg(RegId(19)), Operand::Reg(RegId(26))],
        );
        arith.writes.insert(RegId(19)); // 写了目标 → 不是纯标志设置
        let j2 = jcc(0x1003, ConditionCode::Equal);
        assert_eq!(
            branch_condition_text(&j2, Some(&arith), &test_namer),
            "/* Equal */ flags"
        );
    }

    #[test]
    fn relational_after_self_test_is_not_forced() {
        // test rax,rax + jl（有符号小于）在自测形状里无简洁语义 → 退回标志位，不猜。
        let c = cmp(0x1000, Operand::Reg(RegId(19)), Operand::Reg(RegId(19)));
        let j = jcc(0x1003, ConditionCode::SignedLessThan);
        assert_eq!(
            branch_condition_text(&j, Some(&c), &test_namer),
            "/* SignedLessThan */ flags"
        );
    }

    #[test]
    fn indirect_jump_through_a_slot_shows_the_slot_not_a_fake_zero() {
        // `jmp [rip+rel]`（导入跳板）解码成 PcRelative；目标表达式应**解引用槽地址**，
        // 而不是那个会让人误以为是真地址的裸 `0`。
        let mut i = insn(0x1000, 7, Flow::Branch { conditional: false }, None, vec![]);
        i.len = 6;
        i.operands = vec![Operand::PcRelative(0x1234)];
        let text = translate(&i, &test_namer, None, None, None, None)
            .unwrap()
            .unwrap();
        // 槽 = 0x1000 + 6 + 0x1234 = 0x223a
        assert_eq!(text, "goto *(void **)0x223a");
        assert!(!text.contains("目标未知"), "不该再退回未知占位：{text}");
    }

    #[test]
    fn indirect_jump_through_a_register_shows_the_register() {
        // `jmp rax`（35 是 capstone 的 rsp；这里用 19 = rax）→ 目标就是寄存器里的地址。
        let mut i = insn(0x1000, 7, Flow::Branch { conditional: false }, None, vec![]);
        i.operands = vec![Operand::Reg(RegId(19))];
        let text = translate(&i, &test_namer, None, None, None, None)
            .unwrap()
            .unwrap();
        assert_eq!(text, "goto rax");
    }

    #[test]
    fn indirect_jump_through_a_table_shows_the_addressing() {
        // `jmp [rdx*8 + disp]` → 解引用算出来的地址。
        let mut i = insn(0x1000, 7, Flow::Branch { conditional: false }, None, vec![]);
        i.operands = vec![Operand::Mem(bitflip_arch::MemRef {
            base: None,
            index: Some(RegId(27)), // rdx
            scale: 8,
            index_extend: None,
            disp: 0x401000,
            size: 8,
            write: false,
        })];
        let text = translate(&i, &test_namer, None, None, None, None)
            .unwrap()
            .unwrap();
        assert!(
            text.starts_with("goto *(void **)("),
            "应解引用表寻址：{text}"
        );
        assert!(text.contains("rdx"), "应保留索引寄存器名：{text}");
        assert!(text.contains("0x401000"), "应保留表基址：{text}");
    }

    #[test]
    fn indirect_jump_without_usable_operand_still_says_unknown() {
        // 操作数里没有任何可用线索时，仍如实说未知（不退化成假地址，也不编目标）。
        let i = insn(0x1000, 7, Flow::Branch { conditional: false }, None, vec![]);
        let text = translate(&i, &test_namer, None, None, None, None)
            .unwrap()
            .unwrap();
        assert_eq!(text, "goto /* 目标未知（间接） */ 0");
    }

    #[test]
    fn indirect_call_through_a_known_import_slot_uses_the_import_name() {
        // call [rip+rel]，槽 0x223a；导入名解析器认得这个槽 → 直接用名字，槽地址退到注释。
        let mut i = insn(0x1000, 7, Flow::Call, None, vec![]);
        i.len = 6;
        i.operands = vec![Operand::PcRelative(0x1234)];
        let imp = |slot: u64| -> Option<String> {
            (slot == 0x223a).then(|| "KERNEL32.dll!RtlAllocateHeap".to_string())
        };
        let text = translate(&i, &test_namer, Some(&imp), None, None, None)
            .unwrap()
            .unwrap();
        assert_eq!(
            text,
            "/* call */ KERNEL32.dll!RtlAllocateHeap /* *(void **)0x223a */()"
        );
    }

    #[test]
    fn indirect_jump_through_a_known_import_slot_keeps_deref_and_notes_the_name() {
        // goto 的目标必须是"槽里的值"，所以保留解引用，把导入名放注释里，语义不含糊。
        let mut i = insn(0x1000, 7, Flow::Branch { conditional: false }, None, vec![]);
        i.len = 6;
        i.operands = vec![Operand::PcRelative(0x1234)];
        let imp = |slot: u64| -> Option<String> { (slot == 0x223a).then(|| "K!Func".to_string()) };
        let text = translate(&i, &test_namer, Some(&imp), None, None, None)
            .unwrap()
            .unwrap();
        assert_eq!(text, "goto *(void **)0x223a /* = K!Func */");
    }

    #[test]
    fn unknown_slot_falls_back_to_the_plain_slot_address() {
        // 解析器不认识这个槽 → 不编名字，只写槽地址（与无解析器时一致）。
        let mut i = insn(0x1000, 7, Flow::Call, None, vec![]);
        i.len = 6;
        i.operands = vec![Operand::PcRelative(0x1234)];
        let imp = |_slot: u64| -> Option<String> { None };
        let text = translate(&i, &test_namer, Some(&imp), None, None, None)
            .unwrap()
            .unwrap();
        assert_eq!(text, "/* call */ *(void **)0x223a()");
    }

    #[test]
    fn immediate_string_pointer_is_annotated_with_the_text() {
        // mov rax, 0x401000 —— 该地址是一段字符串时，值后面附注出来。
        let i = insn(
            0x1000,
            10,
            Flow::Fallthrough,
            None,
            vec![Operand::Reg(RegId(19)), Operand::Imm(0x401000)],
        );
        let sr = |addr: u64| -> Option<String> {
            (addr == 0x401000).then(|| "Hello, world".to_string())
        };
        let text = translate(&i, &test_namer, None, Some(&sr), None, None)
            .unwrap()
            .unwrap();
        assert_eq!(text, "rax = 0x401000 /* \"Hello, world\" */");
    }

    #[test]
    fn string_annotation_escapes_control_and_quotes() {
        // 字符串里的引号/换行要转义，且过长要在 64 字符处截断加省略号。
        let i = insn(
            0x1000,
            10,
            Flow::Fallthrough,
            None,
            vec![Operand::Reg(RegId(19)), Operand::Imm(0x401000)],
        );
        let sr = |_a: u64| -> Option<String> { Some("a\"b\nc".to_string()) };
        let text = translate(&i, &test_namer, None, Some(&sr), None, None)
            .unwrap()
            .unwrap();
        assert!(text.contains("\\\""), "引号应转义：{text}");
        assert!(text.contains("\\n"), "换行应转义：{text}");
    }

    #[test]
    fn no_string_reader_never_fabricates_a_string() {
        // 没有字符串解析器：立即数就是立即数，不加任何注释（不猜）。
        let i = insn(
            0x1000,
            10,
            Flow::Fallthrough,
            None,
            vec![Operand::Reg(RegId(19)), Operand::Imm(0x401000)],
        );
        let text = translate(&i, &test_namer, None, None, None, None)
            .unwrap()
            .unwrap();
        assert_eq!(text, "rax = 0x401000");
    }

    #[test]
    fn pc_relative_absolute_uses_instruction_end_not_start() {
        // PC 相对从**指令末**算起：lea rax,[rip+0x10] 在 0x1000、长 7 字节 → 绝对 0x1017。
        // 早先按 addr+disp 算会偏一个指令长度（错）；此处锁定正确行为。
        let mut i = insn(
            0x1000,
            7,
            Flow::Fallthrough,
            None,
            vec![Operand::Reg(RegId(19)), Operand::PcRelative(0x10)],
        );
        i.len = 7;
        let text = translate(&i, &test_namer, None, None, None, None)
            .unwrap()
            .unwrap();
        assert!(
            text.contains("0x1017"),
            "PC 相对绝对地址应为指令末+disp：{text}"
        );
        assert!(!text.contains("0x1010"), "不得用指令首算：{text}");
    }

    /// 造一条两操作数指令，附带一个固定的助记符解析器（模拟后端返回 `mn`）。
    fn translate_with_mnemonic(mn: &'static str, ops: Vec<Operand>) -> Option<String> {
        let i = insn(0x1000, 7, Flow::Fallthrough, None, ops);
        let resolver =
            move |_m: bitflip_arch::MnemonicId| -> Option<String> { Some(mn.to_string()) };
        translate(&i, &test_namer, None, None, Some(&resolver), None).unwrap()
    }

    #[test]
    fn frame_slot_access_is_symbolized_on_rsp_base() {
        // `*(uint64_t *)(rsp + 0x88)` → `*(uint64_t *)(&v88)`（固定栈槽符号化）。
        let m = bitflip_arch::MemRef {
            size: 8,
            base: Some(RegId(35)), // rsp
            index: None,
            scale: 1,
            disp: 0x88,
            write: false,
            index_extend: None,
        };
        assert_eq!(mem_text(&m, &test_namer), "*(uint64_t *)(&v88)");
        // 写访问保留 `/* 写 */`。
        let w = bitflip_arch::MemRef { write: true, ..m };
        assert_eq!(mem_text(&w, &test_namer), "*(uint64_t *)(&v88) /* 写 */");
    }

    #[test]
    fn frame_slot_not_symbolized_for_indexed_or_non_rsp_base() {
        // 带 index 的动态寻址：不符号化（真实地址算术）。
        let idx = bitflip_arch::MemRef {
            size: 8,
            base: Some(RegId(35)),
            index: Some(RegId(26)),
            scale: 4,
            disp: 0x10,
            write: false,
            index_extend: None,
        };
        assert!(
            mem_text(&idx, &test_namer).contains("rsp + "),
            "带 index 应保留原址"
        );
        // 非 rsp 基址（如 rax）不符号化。
        let rax = bitflip_arch::MemRef {
            size: 8,
            base: Some(RegId(19)), // rax
            index: None,
            scale: 1,
            disp: 0x20,
            write: false,
            index_extend: None,
        };
        assert!(
            mem_text(&rax, &test_namer).contains("rax + "),
            "非 rsp 基址应保留原址"
        );
    }

    #[test]
    fn branch_uses_previous_cmp_for_real_comparison() {
        let c = cmp(0x1000, Operand::Reg(RegId(19)), Operand::Imm(7));
        let j = jcc(0x1004, ConditionCode::Equal);
        let text = translate(&j, &test_namer, None, None, None, Some(&c))
            .unwrap()
            .unwrap();
        assert_eq!(text, "if (rax == 0x7) goto 0x2000");
        // 不传 prev 时退回标志位形式（保持向后兼容）。
        let fallback = translate(&j, &test_namer, None, None, None, None)
            .unwrap()
            .unwrap();
        assert!(
            fallback.contains("flags"),
            "无 prev 应退回 flags：{fallback}"
        );
    }

    #[test]
    fn xor_same_register_becomes_zero_not_self_assign() {
        // `xor r8d, r8d`（x64 零寄存器 idiom）必须写成清零，而不是无意义的 `r8d = r8d`。
        let text = translate_with_mnemonic(
            "xor",
            vec![Operand::Reg(RegId(19)), Operand::Reg(RegId(19))],
        );
        assert_eq!(text.as_deref(), Some("rax = 0"));
    }

    #[test]
    fn xor_different_registers_is_a_real_xor() {
        let text = translate_with_mnemonic(
            "xor",
            vec![Operand::Reg(RegId(19)), Operand::Reg(RegId(26))],
        );
        assert_eq!(text.as_deref(), Some("rax = rax ^ rcx"));
    }

    #[test]
    fn add_is_rendered_as_addition_not_assignment() {
        // `add rax, rcx` 是加法，早先会错写成 `rax = rcx`（严重误导）。
        let text = translate_with_mnemonic(
            "add",
            vec![Operand::Reg(RegId(19)), Operand::Reg(RegId(26))],
        );
        assert_eq!(text.as_deref(), Some("rax = rax + rcx"));
    }

    #[test]
    fn cmp_and_test_produce_no_statement() {
        // cmp/test 只设标志，被紧随的分支消费；输出成一行赋值是错的 → 有意不产生语句。
        assert!(
            translate_with_mnemonic("cmp", vec![Operand::Reg(RegId(19)), Operand::Imm(0)])
                .is_none()
        );
        assert!(translate_with_mnemonic(
            "test",
            vec![Operand::Reg(RegId(19)), Operand::Reg(RegId(19))]
        )
        .is_none());
    }

    #[test]
    fn lea_computes_address_and_does_not_dereference() {
        // `lea rax, [rcx+0x10]` 算地址，不是解引用：绝不能写成 `rax = *(uint64_t*)(...)`。
        let text = translate_with_mnemonic(
            "lea",
            vec![
                Operand::Reg(RegId(19)),
                Operand::Mem(bitflip_arch::MemRef {
                    base: Some(RegId(26)),
                    index: None,
                    scale: 1,
                    index_extend: None,
                    disp: 0x10,
                    size: 8,
                    write: false,
                }),
            ],
        )
        .unwrap();
        assert_eq!(text, "rax = rcx + 0x10");
        assert!(!text.contains("*("), "lea 不得解引用：{text}");
    }

    #[test]
    fn unknown_mnemonic_keeps_conservative_move() {
        // 不认识的助记符（或没解析器）→ 退回保守赋值，不引入新回归。
        let text = translate_with_mnemonic(
            "frobnicate",
            vec![Operand::Reg(RegId(19)), Operand::Reg(RegId(26))],
        );
        assert_eq!(text.as_deref(), Some("rax = rcx"));
    }

    #[test]
    fn multibyte_nop_with_operand_emits_no_statement() {
        // `nop dword ptr [rax+rax*1]`（多字节 nop）带一个内存操作数，但它语义上是空操作：
        // 必须不产生语句，而不是被误报成"单操作数无法翻译"。
        let text = translate_with_mnemonic(
            "nop",
            vec![Operand::Mem(bitflip_arch::MemRef {
                base: Some(RegId(19)),
                index: Some(RegId(19)),
                scale: 1,
                index_extend: None,
                disp: 0,
                size: 4,
                write: false,
            })],
        );
        assert!(text.is_none(), "多字节 nop 不应产生语句，得到 {text:?}");
    }

    #[test]
    fn endbr64_emits_no_statement() {
        // `endbr64`（CET 控制流保护标记）也只是标记，不产生语句。
        assert!(translate_with_mnemonic("endbr64", vec![]).is_none());
    }

    #[test]
    fn setcc_renders_as_conditional_zero_or_one() {
        // `setne r8b`：按标志位把 r8b 置 0/1。带语义条件时应写成 `(cond) ? 1 : 0`，
        // 而不是"单操作数无法翻译"。
        let mut i = insn(
            0x1000,
            7,
            Flow::Fallthrough,
            None,
            vec![Operand::Reg(RegId(19))],
        );
        i.condition = Some(ConditionCode::NotEqual);
        let resolver =
            |_m: bitflip_arch::MnemonicId| -> Option<String> { Some("setne".to_string()) };
        let text = translate(&i, &test_namer, None, None, Some(&resolver), None)
            .unwrap()
            .unwrap();
        assert_eq!(text, "rax = (/* NotEqual */ flags) ? 1 : 0");
        assert!(!text.contains("无法翻译"));
    }

    #[test]
    fn reg_width_from_name_table_is_factual() {
        assert_eq!(reg_width_from_name("rax"), Some(8));
        assert_eq!(reg_width_from_name("eax"), Some(4));
        assert_eq!(reg_width_from_name("ax"), Some(2));
        assert_eq!(reg_width_from_name("al"), Some(1));
        assert_eq!(reg_width_from_name("rcx"), Some(8));
        assert_eq!(reg_width_from_name("r8"), Some(8));
        assert_eq!(reg_width_from_name("r8d"), Some(4));
        assert_eq!(reg_width_from_name("r8w"), Some(2));
        assert_eq!(reg_width_from_name("r8b"), Some(1));
        // 推不出宽度的一律 None（不猜）。
        assert_eq!(reg_width_from_name("xmm0"), None);
        assert_eq!(reg_width_from_name("st"), None);
    }

    #[test]
    fn pc_relative_store_renders_as_global_write() {
        // `mov [rip+0x10], rcx` 在 0x1000、长 7 → 绝对 = 0x1000+7+0x10 = 0x1017。
        // 源是 64 位寄存器 → 渲染成 `*(uint64_t *)(0x1017) = rcx`，而不是"PC 相对不能作赋值目标"。
        let mut i = insn(
            0x1000,
            7,
            Flow::Fallthrough,
            None,
            vec![Operand::PcRelative(0x10), Operand::Reg(RegId(26))],
        );
        i.len = 7;
        let mn = |_m: bitflip_arch::MnemonicId| -> Option<String> { Some("mov".to_string()) };
        let text = translate(&i, &test_namer, None, None, Some(&mn), None).unwrap();
        assert_eq!(text.as_deref(), Some("*(uint64_t *)(0x1017) = rcx"));
    }

    #[test]
    fn pc_relative_store_imm_source_is_refused_not_guessed() {
        // 源是立即数时无法推宽度 → 不猜，仍如实报错（不能假装知道 4/8 字节）。
        let mut i = insn(
            0x1000,
            7,
            Flow::Fallthrough,
            None,
            vec![Operand::PcRelative(0x10), Operand::Imm(0)],
        );
        i.len = 7;
        let mn = |_m: bitflip_arch::MnemonicId| -> Option<String> { Some("mov".to_string()) };
        let r = translate(&i, &test_namer, None, None, Some(&mn), None);
        assert!(r.is_err(), "立即数源推不出宽度，应如实报错而不是猜：{r:?}");
    }

    #[test]
    fn movzx_and_movsx_render_with_widening_cast() {
        // 用能区分宽度的寄存器名（eax=32b, cl=8b, rcx=64b）验证扩宽转换。
        let namer = |id: u16| -> Option<String> {
            Some(
                match id {
                    19 => "eax", // dst 32 位
                    26 => "rcx",
                    40 => "cl", // src 8 位
                    41 => "cx", // src 16 位
                    _ => return None,
                }
                .to_string(),
            )
        };
        let mk = |mn: &'static str, dst: u16, src: u16| -> Option<String> {
            let i = insn(
                0x1000,
                3,
                Flow::Fallthrough,
                None,
                vec![Operand::Reg(RegId(dst)), Operand::Reg(RegId(src))],
            );
            let resolver =
                move |_m: bitflip_arch::MnemonicId| -> Option<String> { Some(mn.to_string()) };
            translate(&i, &namer, None, None, Some(&resolver), None).unwrap()
        };
        // movzx eax, cl → 零扩展到 32 位（uint8_t 转换，再赋给 eax）。
        assert_eq!(mk("movzx", 19, 40).as_deref(), Some("eax = (uint8_t)cl"));
        // movsx eax, cx → 符号扩展（int16_t）。
        assert_eq!(mk("movsx", 19, 41).as_deref(), Some("eax = (int16_t)cx"));
        // movsxd eax, cl（实际是 32←32 的典型用法的简化）：仍走符号扩展渲染。
        assert_eq!(mk("movsxd", 19, 40).as_deref(), Some("eax = (int8_t)cl"));
        // 普通 mov 不带转换（不受影响）。
        assert_eq!(mk("mov", 19, 26).as_deref(), Some("eax = rcx"));
    }

    #[test]
    fn div_and_idiv_render_with_semantic_annotation() {
        // idiv/div 是隐式寄存器除法（被除数 rdx:rax），无法单表达式精确表达 → 渲染成
        // 带语义标注的语句，而不是"无法翻译"。
        assert_eq!(
            translate_with_mnemonic("idiv", vec![Operand::Reg(RegId(26))]).as_deref(),
            Some("/* idiv rcx：被除数 rdx:rax，商→rax，余数→rdx */")
        );
        assert_eq!(
            translate_with_mnemonic("div", vec![Operand::Reg(RegId(19))]).as_deref(),
            Some("/* div rax：被除数 rdx:rax，商→rax，余数→rdx */")
        );
    }

    #[test]
    fn push_and_pop_render_as_stack_ops() {
        // `push rbx` / `pop rbx` 是简单可判的栈操作，应表达出来而不是"无法翻译"。
        assert_eq!(
            translate_with_mnemonic("push", vec![Operand::Reg(RegId(28))]).as_deref(),
            Some("push(rbx)")
        );
        assert_eq!(
            translate_with_mnemonic("pop", vec![Operand::Reg(RegId(28))]).as_deref(),
            Some("pop(rbx)")
        );
        // `push 0x10` 立即数形式。
        assert_eq!(
            translate_with_mnemonic("push", vec![Operand::Imm(0x10)]).as_deref(),
            Some("push(0x10)")
        );
    }

    #[test]
    fn return_value_expr_recognizes_eax_and_rax() {
        assert_eq!(return_value_expr("eax = 0x1"), Some("0x1"));
        assert_eq!(return_value_expr("rax = rcx + 0x8"), Some("rcx + 0x8"));
        // 非返回值寄存器、或被用作更长名字前缀的，都不认。
        assert_eq!(return_value_expr("ebx = 0x1"), None);
        assert_eq!(return_value_expr("rax_flag = 0x1"), None);
        assert_eq!(return_value_expr("*(uint64_t *)(0x0) = rax"), None);
    }

    #[test]
    fn return_value_is_fused_when_adjacent_to_return() {
        // `eax = 0x1; return` → `return 0x1`。
        let mut stmts = vec![
            stmt(0x1000, "rsp = rsp - 0x20"),
            stmt(0x1004, "eax = 0x1"),
            stmt(0x1008, "return"),
        ];
        fuse_return_value(&mut stmts);
        assert_eq!(
            stmts.iter().map(|s| s.text.as_str()).collect::<Vec<_>>(),
            vec!["rsp = rsp - 0x20", "return 0x1"]
        );
    }

    #[test]
    fn return_value_is_fused_across_epilogue_statements() {
        // `eax = x; rsp = rsp + N; pop(rbx); return` —— 越过尾声指令仍找到返回值并融合。
        let mut stmts = vec![
            stmt(0x1000, "eax = 0x1"),
            stmt(0x1004, "rsp = rsp + 0x20"),
            stmt(0x1008, "pop(rbx)"),
            stmt(0x100c, "return"),
        ];
        fuse_return_value(&mut stmts);
        assert_eq!(
            stmts.iter().map(|s| s.text.as_str()).collect::<Vec<_>>(),
            vec!["return 0x1"]
        );
    }

    #[test]
    fn return_value_is_not_fused_when_call_intervenes() {
        // 中间有 call（可能改写 rax）→ 停止、不融合，保留 `eax = x; ...; return`。
        let mut stmts = vec![
            stmt(0x1000, "eax = 0x1"),
            stmt(0x1004, "/* call */ foo()"),
            stmt(0x1008, "rsp = rsp + 0x20"),
            stmt(0x100c, "return"),
        ];
        fuse_return_value(&mut stmts);
        assert_eq!(stmts.len(), 4);
        assert_eq!(stmts[3].text, "return");
    }

    #[test]
    fn return_value_is_not_fused_when_unknown_statement_intervenes() {
        // 中间有无法归类的普通语句 → 停止、不融合（不猜它是否改写返回值）。
        let mut stmts = vec![
            stmt(0x1000, "eax = 0x1"),
            stmt(0x1004, "*(uint64_t *)(0x40) = rcx"),
            stmt(0x1008, "return"),
        ];
        fuse_return_value(&mut stmts);
        assert_eq!(stmts.len(), 3);
        assert_eq!(stmts[2].text, "return");
    }
}
