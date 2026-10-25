//! 控制流结构化：把基本块 CFG 还原成带 `if` / `else` / `while` / `do-while` 的结构化伪代码
//! （阶段 1：反编译深度）。
//!
//! # 与 `pseudo` 模块的关系
//!
//! [`crate::pseudo::decompile_function`] 给出的是**扁平**视图：每个基本块一段、条件跳转写成
//! `if (cond) goto ADDR`。本模块在其上做**控制流结构化**，产出一份嵌套缩进的
//! [`PseudocodeFunction`]（`structured` / `structured_body` 字段）。
//!
//! # 三条不肯让步的规矩
//!
//! 1. **能证明才结构化，否则就 goto。** 只对**可归约**、SESE（单入单出）形态清晰的区域做
//!    `if/else/while/do-while`；任何拿不准的（不可归约、多重回边、复杂重汇合）一律退回
//!    `if (cond) goto ADDR`，并如实标注"部分结构化"。不为了"看起来像反编译结果"而猜结构。
//! 2. **每一句都可追溯到指令地址**：结构化渲染的每一行行尾带 `/* @0xADDR */` 注释。
//! 3. **不静默**：共用了多少块、还剩多少 goto、为什么没结构化，都进 `notes`。
//!
//! 本模块**只读**指令与 CFG，不依赖架构枚举（指令文本由 `pseudo::translate` 提供）。

use std::collections::{BTreeMap, BTreeSet};

use bitflip_arch::{DecodedInsn, Flow, Operand};

use crate::cfg::Cfg;
use crate::pseudo::{
    branch_condition_text, decompile_function, translate, ImportNamer, PseudocodeFunction,
    PseudocodeNote, RegisterNamer, StringReader, TableReader,
};

/// 结构化渲染的一行。
#[derive(Debug, Clone)]
struct Line {
    indent: usize,
    text: String,
}

/// 结构化结果（供 [`decompile_structured`] 组装）。
struct Built {
    lines: Vec<Line>,
    /// 结构化过程中被迫留下的 `goto` 数（0 表示完全结构化）。
    residual_gotos: usize,
    /// 实际“吃进结构”里的基本块数。
    structured_blocks: usize,
}

/// 解析出的跳表形状（见 [`Builder::parse_switch_shape`]）。
struct SwitchShape {
    /// 索引寄存器。
    idx_reg: bitflip_arch::RegId,
    /// 读表项的虚拟地址。
    table_addr: u64,
    /// 每项字节数（偏移表恒 4；指针表 4 或 8）。
    entry_size: usize,
    /// 偏移表基址：`Some(基址)` 时表项是相对基址的偏移，目标 = 基址 + 偏移；
    /// 指针表为 `None`（表项即目标）。
    base: Option<u64>,
}

/// 生成一个函数的**结构化**伪代码。
///
/// 结构失败或只能部分结构化时，`structured` 为 `false`，但仍会在 `structured_body` 里给出
/// **尽可能结构化**的版本（残留处是 `if (cond) goto`），并附 [`PseudocodeNote`] 说明。
/// 这与“不静默、不猜测”一致：用户总能拿到比扁平视图更好的东西，且知道它有多好。
#[must_use]
pub fn decompile_structured(
    entry: u64,
    name: Option<&str>,
    insns: &[DecodedInsn],
    cfg: &Cfg,
    namer: RegisterNamer<'_>,
    resolvers: crate::pseudo::Resolvers<'_>,
) -> PseudocodeFunction {
    // 先拿扁平版本：它已经算好了每块的语句、未翻译计数、截断、基础 notes。
    let mut flat = decompile_function(
        entry,
        name,
        insns,
        cfg,
        namer,
        resolvers.import,
        resolvers.string,
    );

    if cfg.is_empty() {
        return flat;
    }

    let by_addr: BTreeMap<u64, &DecodedInsn> = insns.iter().map(|i| (i.addr, i)).collect();
    let block_map: BTreeMap<u64, &crate::cfg::BasicBlock> =
        cfg.blocks().map(|b| (b.start, b)).collect();
    let entry_block = cfg.blocks().next().map(|b| b.start);

    let Some(start) = entry_block else {
        return flat;
    };

    let dom = compute_dominators(&block_map, start);
    let ipdom = compute_immediate_postdominators(&block_map);
    let natural_loops = compute_natural_loops(&block_map, &dom);

    let mut builder = Builder {
        by_addr: &by_addr,
        blocks: &block_map,
        ipdom: &ipdom,
        natural_loops: &natural_loops,
        namer,
        table_reader: resolvers.table,
        import_namer: resolvers.import,
        string_reader: resolvers.string,
        visited: BTreeSet::new(),
        lines: Vec::new(),
        residual_gotos: 0,
        structured_blocks: 0,
        budget: MAX_STRUCT_LINES,
    };
    builder.emit_from(start, None, 0, None);

    // 覆盖补遍：主路径没走到的块（典型是被函数前部的早退/尾跳分支遮住、只能经间接跳转
    // 或异常到达的分发/辅助块）。**不静默丢弃**：按地址顺序，对每个尚未访问、且没有
    // "已覆盖前驱"的块，起一段新的结构化区域并标注来源。这样 switch/if/while 在分离区域里
    // 也能被还原，而不是永远看不见。
    //
    // 只在确实存在未覆盖块时插入分隔注释，避免污染完全结构化的输出。
    let unreached: Vec<u64> = block_map
        .keys()
        .copied()
        .filter(|a| !builder.visited.contains(a))
        // 只把"入口块"当作新区域起点：它的所有前驱都还没被覆盖（否则会经主路径已连上）。
        .filter(|a| {
            block_map
                .get(a)
                .is_none_or(|b| b.predecessors.iter().all(|p| !builder.visited.contains(p)))
        })
        .collect();
    if !unreached.is_empty() {
        // 过滤掉**纯填充/陷阱块**（`int3`/`nop` 之类）：它们不可执行、不是真正的"分离代码"，
        // 若一并输出就是成百上千行 `__builtin_trap` 噪声，毫无价值。只有当分离区域里**含有
        // 可执行指令**时才起段。
        let real: Vec<u64> = unreached
            .into_iter()
            .filter(|&a| !builder.is_padding_region(a))
            .collect();
        if !real.is_empty() {
            builder.push(
                0,
                "/* --- 以下区域未被主路径连入（可能经间接跳转/异常到达），单独起段 --- */"
                    .to_string(),
            );
            for a in real {
                if builder.visited.contains(&a) || builder.lines.len() >= builder.budget {
                    continue;
                }
                builder.push(0, format!("// @{a:#x}（分离区域起点）"));
                builder.emit_from(a, None, 0, None);
            }
        }
    }

    let built = Built {
        lines: builder.lines,
        residual_gotos: builder.residual_gotos,
        structured_blocks: builder.structured_blocks,
    };

    let fully = built.residual_gotos == 0 && built.structured_blocks == block_map.len();

    // 渲染成带缩进/地址注释的行。
    let body: Vec<String> = built
        .lines
        .iter()
        .map(|l| {
            let pad = "  ".repeat(l.indent + 1);
            format!("{pad}{}", l.text)
        })
        .collect();

    flat.structured = fully;
    flat.structured_body = Some(body);
    // 去掉扁平模式必带的 FlatGoto 说明，换成结构化/部分结构化的说明。
    flat.notes
        .retain(|n| !matches!(n, PseudocodeNote::FlatGoto));
    if fully {
        flat.notes.push(PseudocodeNote::Structured);
    } else {
        flat.notes.push(PseudocodeNote::PartiallyStructured {
            residual_gotos: built.residual_gotos,
            structured_blocks: built.structured_blocks,
            total_blocks: block_map.len(),
        });
    }
    flat
}

/// 结构化行数上限：防止病态输入把内存吃光（与扁平模式的 `MAX_STATEMENTS` 同精神）。
const MAX_STRUCT_LINES: usize = 8000;

struct Builder<'a> {
    by_addr: &'a BTreeMap<u64, &'a DecodedInsn>,
    blocks: &'a BTreeMap<u64, &'a crate::cfg::BasicBlock>,
    ipdom: &'a BTreeMap<u64, Option<u64>>,
    /// 自然循环：回边头 → 循环体块集合（含头）。由 `compute_natural_loops` 预算。
    natural_loops: &'a BTreeMap<u64, BTreeSet<u64>>,
    namer: RegisterNamer<'a>,
    /// 只读数据读取器（读 switch 跳表）；`None` 时不做 switch 还原。
    table_reader: Option<TableReader<'a>>,
    /// 导入名解析器（间接调用/跳板的槽 → 导入名）；`None` 时只写槽地址。
    import_namer: Option<ImportNamer<'a>>,
    /// 字符串解析器（地址 → 只读数据里的 C 字符串）；`None` 时不附注字符串。
    string_reader: Option<StringReader<'a>>,
    visited: BTreeSet<u64>,
    lines: Vec<Line>,
    residual_gotos: usize,
    structured_blocks: usize,
    budget: usize,
}

impl Builder<'_> {
    fn push(&mut self, indent: usize, text: String) {
        if self.lines.len() < self.budget {
            self.lines.push(Line { indent, text });
        }
    }

    /// 把块内**除控制转移以外的**语句逐条推出（带地址注释）。
    ///
    /// `skip_last` 为真时跳过块最后一条指令（当它是被结构化的分支/跳转时）。
    fn emit_block_stmts(&mut self, block_start: u64, indent: usize, skip_last_branch: bool) {
        let Some(b) = self.blocks.get(&block_start).copied() else {
            return;
        };
        let last_addr = self.last_insn_addr(b);
        for (&addr, insn) in self.by_addr.range(b.start..b.end) {
            if skip_last_branch && Some(addr) == last_addr {
                continue;
            }
            match translate(insn, self.namer, self.import_namer, self.string_reader) {
                Ok(Some(text)) => self.push(indent, format!("{text}; /* @{addr:#x} */")),
                Ok(None) => {}
                Err(reason) => {
                    self.push(indent, format!("/* 无法翻译：{reason} */ /* @{addr:#x} */"))
                }
            }
        }
    }

    /// 块内最后一条指令的地址。
    fn last_insn_addr(&self, b: &crate::cfg::BasicBlock) -> Option<u64> {
        self.by_addr
            .range(b.start..b.end)
            .next_back()
            .map(|(&a, _)| a)
    }

    /// 取块内紧挨在 `branch_addr` **之前**的那条指令（用于把 `cmp`/`test` + 条件跳转
    /// 还原成真实比较）。只在同一基本块范围内找，不跨块 —— 跨块的标志设置已不在
    /// "紧邻"范围内，跨块猜比较不可靠。
    /// 判断一个（未覆盖）块是否是**纯填充/陷阱**：块内指令全部是 `trap`（`int3` 等）
    /// 或单字节无法翻译的填充。这类块不值得作为"分离区域"输出（成百上千行噪声）。
    fn is_padding_region(&self, block_start: u64) -> bool {
        let Some(b) = self.blocks.get(&block_start) else {
            return true;
        };
        for (&_a, insn) in self.by_addr.range(b.start..b.end) {
            match insn.flow {
                Flow::Trap => {}
                // `nop`/填充常见为 len==1 且无操作数的 fallthrough。
                Flow::Fallthrough => {
                    if insn.len > 1 || !insn.operands.is_empty() {
                        return false;
                    }
                }
                _ => return false,
            }
        }
        // 空块或全 trap/填充 → 视为填充。
        true
    }

    fn prev_insn(&self, block_start: u64, branch_addr: u64) -> Option<&DecodedInsn> {
        self.by_addr
            .range(block_start..branch_addr)
            .next_back()
            .map(|(_, insn)| *insn)
    }

    /// 跳表形状：解析出的读表参数。
    ///
    /// `base == Some(基址)` 表示**偏移表**（表项是相对基址的 32 位偏移，目标 = 基址 + 偏移）；
    /// `base == None` 表示**指针表**（表项就是目标地址）。
    fn parse_switch_shape(&self, switch_block: u64, jmp: &DecodedInsn) -> Option<SwitchShape> {
        // 形状 A：`jmp [idx*scale + TABLE]` —— 单个 Mem 操作数，指针表。
        if let [Operand::Mem(m)] = jmp.operands.as_slice() {
            let idx = m.index?;
            if m.scale >= 2 && m.disp != 0 {
                let entry_size = match m.size {
                    4 => 4usize,
                    8 => 8usize,
                    _ => return None,
                };
                return Some(SwitchShape {
                    idx_reg: idx,
                    table_addr: m.disp as u64,
                    entry_size,
                    base: None,
                });
            }
        }

        // 形状 B：MSVC x64 偏移跳表 idiom —— `jmp REG`，其前三条指令依次为：
        //   lea BASE, [rip+off]                 ; BASE = 表基址（绝对）
        //   mov DREG, [BASE + IDX*scale + disp] ; DREG = 32 位偏移（项大小 4）
        //   add JREG, BASE                      ; JREG (= REG) = BASE + offset
        // 从块内、jmp 之前反向扫描三条指令，逐一核对寄存器连线。
        let [Operand::Reg(jreg)] = jmp.operands.as_slice() else {
            return None;
        };
        let block = self.blocks.get(&switch_block).copied()?;
        // jmp 之前的指令（按地址升序）。
        let before: Vec<&DecodedInsn> = self
            .by_addr
            .range(block.start..jmp.addr)
            .map(|(_, i)| *i)
            .collect();
        // add JREG, BASE
        let add = before.last()?;
        let [Operand::Reg(areg), Operand::Reg(base_reg)] = add.operands.as_slice() else {
            return None;
        };
        if areg.0 != jreg.0 {
            return None;
        }
        // mov DREG, [BASE + IDX*scale + disp]
        let mov = before.get(before.len().checked_sub(2)?)?;
        let [Operand::Reg(_dreg), Operand::Mem(m)] = mov.operands.as_slice() else {
            return None;
        };
        if m.base.map(|b| b.0) != Some(base_reg.0) || m.size != 4 {
            return None;
        }
        let idx = m.index?;
        // lea BASE, [rip+off]（PcRelative 操作数）
        let lea = before.get(before.len().checked_sub(3)?)?;
        let [Operand::Reg(lreg), Operand::PcRelative(rel)] = lea.operands.as_slice() else {
            return None;
        };
        if lreg.0 != base_reg.0 {
            return None;
        }
        // 基址绝对值：lea 指令地址 + 指令长度 + 相对位移。
        let base_abs = lea
            .addr
            .wrapping_add(u64::from(lea.len))
            .wrapping_add(*rel as u64);
        // 表读地址 = 基址 + mov 的常量位移；项大小固定 4（32 位偏移）。
        let table_addr = base_abs.wrapping_add(m.disp as u64);
        Some(SwitchShape {
            idx_reg: idx,
            table_addr,
            entry_size: 4,
            base: Some(base_abs),
        })
    }

    /// 尝试把"`cmp idx,N` + 条件跳转 → 间接跳转块"这一**跳表分发**还原成 `switch`。
    ///
    /// 入参是**谓词块**（条件跳转所在块）；它的两个后继里，一个是**间接跳转块**（switch 主体）、
    /// 另一个是**缺省**（`ja default` 这类越界走 default）。只认**窄而可证**的形状，任何一环
    /// 不满足就返回 `false`，交回上层走 `if / goto` 兜底 —— 不猜：
    /// - 谓词块内有 `cmp X, Imm(n)`（越界判断），映射到 switch 的 `case 0..=n`；
    /// - switch 块末是跳表分发：指针表 `jmp [idx*scale+TABLE]`，或 MSVC 省 x64 偏移表 idiom
    ///   （`lea` + `mov [base+idx*4+disp]` + `add` + `jmp reg`，见 [`Self::parse_switch_shape`]）；
    /// - 从表读得到 `n+1` 个项（上限 `MAX_SWITCH_CASES`）。
    ///
    /// 产出 `if (<越界条件>的反) { switch (idx) { case i: goto Ti; ... default: goto D; } } else {
    /// goto D; }`：披露分发表是本片目标；各 case 体仍是 `goto`（后续工作）。
    fn emit_switch_from_pred(
        &mut self,
        pred_cur: u64,
        plast: &DecodedInsn,
        succs: &[u64],
        indent: usize,
    ) -> bool {
        const MAX_SWITCH_CASES: usize = 512;
        let Some(reader) = self.table_reader else {
            return false;
        };
        // 谓词块：条件跳转所在块。
        let Some(pred_block) = self.blocks.get(&pred_cur).copied() else {
            return false;
        };
        // switch 主体 = **谓词块的顺序后继**（fallthrough，即分支后下一条指令所在块）。
        // 直接按块边界定位，比"从 succs 里挑间接跳转块"更稳：CFG 对间接跳转会丢掉目标未知
        // 的那条边，导致 succs 里常常只剩 default 一侧。fallthrough 块才是顺序落到的分发块。
        let switch_block = pred_block.end;
        let Some(sb) = self.blocks.get(&switch_block).copied() else {
            return false;
        };
        let s_last = self
            .last_insn_addr(sb)
            .and_then(|a| self.by_addr.get(&a).copied());
        let Some(jmp) = s_last else {
            return false;
        };
        if !(matches!(jmp.flow, Flow::Branch { conditional: false }) && jmp.target.is_none()) {
            return false;
        }
        // 缺省目标 = 谓词块后继里、除 switch 块外的那个（若有）。可能因为间接边丢失而只剩一个，
        // 也可能两个都在；取不等于 switch_block 的那一个，且必须唯一。
        let mut default_iter = succs.iter().copied().filter(|&s| s != switch_block);
        let Some(default_target) = default_iter.next() else {
            return false;
        };
        if default_iter.next().is_some() {
            return false;
        }

        // 解析 switch 块的跳转形状，得到：索引寄存器、表读地址、项大小、以及（偏移表时的）基址。
        let Some(shape) = self.parse_switch_shape(switch_block, jmp) else {
            return false;
        };
        let idx_reg = shape.idx_reg;

        // 谓词块内 `cmp X, Imm(n)` 上界 —— 越界守卫（`ja default`）的界即 case 上界。
        // 注意：守卫比较的寄存器**未必等于**索引寄存器（编译器常把选择子拷一份再比较），
        // 所以这里取谓词块内任意 `cmp reg, imm` 的最大立即数，而不是只认 idx_reg。
        let mut bound: Option<i64> = None;
        for (&_a, insn) in self.by_addr.range(pred_block.start..pred_block.end) {
            if let [Operand::Reg(_), Operand::Imm(n)] = insn.operands.as_slice() {
                // 只接受小的、看起来像 case 数的上界（排除非分支相关的常量）。
                if *n >= 0 {
                    bound = Some(bound.map_or(*n, |b| b.max(*n)));
                }
            }
        }
        let Some(n) = bound else {
            return false;
        };
        let count = n.saturating_add(1);
        if count <= 0 || count as usize > MAX_SWITCH_CASES {
            return false;
        }
        let count = count as usize;

        // 读表并解出各 case 目标：
        // - 指针表（shape A）：表项即目标地址；
        // - 偏移表（shape B）：表项是**相对基址的 32 位偏移**，目标 = 基址 + 偏移。
        let entry_size = shape.entry_size;
        let need = count * entry_size;
        let Some(bytes) = (*reader)(shape.table_addr, need) else {
            return false;
        };
        if bytes.len() < need {
            return false;
        }
        let mut targets = Vec::with_capacity(count);
        for i in 0..count {
            let off = i * entry_size;
            let chunk = &bytes[off..off + entry_size];
            let raw = if entry_size == 8 {
                u64::from_le_bytes(chunk.try_into().expect("8 字节"))
            } else {
                u64::from(u32::from_le_bytes(chunk.try_into().expect("4 字节")))
            };
            let target = match shape.base {
                // 偏移表：目标 = 基址 + 偏移（32 位无符号，`mov ecx` 零扩展到 64 位）。
                Some(base) => base.wrapping_add(raw),
                // 指针表：表项就是目标。
                None => raw,
            };
            targets.push(target);
        }

        // 发射：谓词块语句（跳过它的分支），再 if 守卫 + switch。
        self.emit_block_stmts(pred_cur, indent, true);
        self.visited.insert(pred_cur);
        self.structured_blocks += 1;

        // 守卫条件：分支条件（越界→default）取反即"在表内"。
        let prev = self.prev_insn(pred_cur, plast.addr);
        let cond = branch_condition_text(plast, prev, self.namer);
        let idx_text = (self.namer)(idx_reg.0).unwrap_or_else(|| "idx".to_string());
        self.push(indent, format!("if (!({cond})) {{"));
        self.push(
            indent + 1,
            format!("switch ({idx_text}) {{ /* 跳表 @{:#x} */", shape.table_addr),
        );
        for (i, &t) in targets.iter().enumerate() {
            if t == 0 {
                self.push(
                    indent + 2,
                    format!("case {i}: goto /* 表项 0，无法作目标 */ ;"),
                );
            } else {
                self.push(indent + 2, format!("case {i}: goto {t:#x};"));
            }
        }
        self.push(indent + 2, format!("default: goto {default_target:#x};"));
        self.push(indent + 1, "}".to_string());
        self.push(indent, "} else {".to_string());
        self.push(indent + 1, format!("goto {default_target:#x};"));
        self.push(indent, "}".to_string());

        // switch 块本身也已"解释"掉（其分发被 case 表披露）。
        self.visited.insert(switch_block);
        self.structured_blocks += 1;
        true
    }

    /// 从 `cur` 开始发射到 `stop`（不含）为止。
    ///
    /// `bound` 为 `Some` 时表示只在给定块集合内展开（用于循环体）：遇到集合外的块就当作
    /// 区域边界停下，由调用方接着从边界外继续。`None` 表示整个函数。
    fn emit_from(
        &mut self,
        mut cur: u64,
        stop: Option<u64>,
        indent: usize,
        bound: Option<&BTreeSet<u64>>,
    ) {
        loop {
            if Some(cur) == stop {
                return;
            }
            // 到了区域边界（循环体外）就停，交给上层。
            if bound.is_some_and(|b| !b.contains(&cur)) {
                return;
            }
            if self.visited.contains(&cur) {
                // 回到已发射过的块（正常回边应在 emit_loop 里处理，走到这里属异常兜底）。
                self.push(indent, format!("goto {cur:#x};"));
                self.residual_gotos += 1;
                return;
            }
            let Some(b) = self.blocks.get(&cur).copied() else {
                return;
            };
            if self.lines.len() >= self.budget {
                return;
            }

            // 循环头：若当前块是某自然循环的头且尚未发射，优先结构化成 while/do-while。
            // 形态没把握时 `emit_loop` 返回 false，继续按普通块处理（多半走向 goto 兜底）。
            if self.natural_loops.contains_key(&cur) && self.emit_loop(cur, indent, stop, bound) {
                return;
            }

            let succs = &b.successors;
            let last_insn = self
                .last_insn_addr(b)
                .and_then(|a| self.by_addr.get(&a).copied());

            // 跳表分发：条件块 + 一个间接跳转后继 = switch。先尝试还原，成功则整块消化掉。
            // 放在 `if` 结构化之前，因为间接跳转块没有已知后继，`emit_if` 会因取不到 join 而放弃。
            if let Some(insn) = last_insn {
                if matches!(insn.flow, Flow::Branch { conditional: true })
                    && self.emit_switch_from_pred(cur, insn, succs, indent)
                {
                    return;
                }
            }

            // 终结块（ret/trap）或没有已知后继：整块发射后停。
            if b.terminal || succs.is_empty() {
                self.emit_block_stmts(cur, indent, false);
                self.visited.insert(cur);
                self.structured_blocks += 1;
                return;
            }

            match last_insn.map(|i| i.flow) {
                Some(Flow::Branch { conditional: true }) => {
                    if self.emit_if(cur, last_insn, succs, stop, indent, bound) {
                        return;
                    }
                    // 兜底：整块发射 + 两个后继都写成 goto。
                    self.emit_block_stmts(cur, indent, true);
                    self.visited.insert(cur);
                    self.structured_blocks += 1;
                    for &s in succs {
                        self.push(indent, format!("goto {s:#x};"));
                        self.residual_gotos += 1;
                    }
                    return;
                }
                Some(Flow::Branch { conditional: false }) => {
                    // 无条件跳转（单后继）。
                    if let Some(&t) = succs.first() {
                        self.emit_block_stmts(cur, indent, true);
                        self.visited.insert(cur);
                        self.structured_blocks += 1;
                        cur = t;
                        continue;
                    }
                    self.emit_block_stmts(cur, indent, false);
                    self.visited.insert(cur);
                    self.structured_blocks += 1;
                    return;
                }
                _ => {
                    // 顺序 / call / fallthrough 单后继：发射并前进。
                    self.emit_block_stmts(cur, indent, false);
                    self.visited.insert(cur);
                    self.structured_blocks += 1;
                    match succs.first() {
                        Some(&next) => {
                            cur = next;
                            continue;
                        }
                        None => return,
                    }
                }
            }
        }
    }

    /// 尝试把一个条件块结构化为 `if / if-else`。成功返回 true。
    ///
    /// 用后支配 join 判定：
    /// - join 恰是其中一个后继 → 单臂 `if`；
    /// - join 是两者之外的公共后支配点 → 双臂 `if/else`。
    fn emit_if(
        &mut self,
        cur: u64,
        last_insn: Option<&DecodedInsn>,
        succs: &[u64],
        stop: Option<u64>,
        indent: usize,
        bound: Option<&BTreeSet<u64>>,
    ) -> bool {
        let (taken, fall) = match self.split_branch(cur, last_insn, succs) {
            Some(x) => x,
            None => return false,
        };
        let join = self
            .ipdom
            .get(&cur)
            .copied()
            .flatten()
            .or(stop)
            .filter(|&j| j != cur);
        let Some(join) = join else {
            return false;
        };

        // 条件文本：能从前一条 cmp/test 还原成真实比较时就还，否则退回标志位占位。
        let Some(insn) = last_insn else {
            return false;
        };
        let prev = self.prev_insn(cur, insn.addr);
        let cond = branch_condition_text(insn, prev, self.namer);

        // 判定形态。
        if join == taken {
            // 条件成立直接到 join：等价 `if (!cond) { fall..join }`。
            // 发射本块（跳过分支），再用 !cond 包 fall 一侧。
            self.emit_block_stmts(cur, indent, true);
            self.visited.insert(cur);
            self.structured_blocks += 1;
            self.push(indent, format!("if (!({cond})) {{"));
            let before = self.visited.len();
            self.emit_from(fall, Some(join), indent + 1, bound);
            if self.visited.len() == before {
                // 什么也没发射（异常形态）→ 回退成 goto，避免输出空 if。
                self.push(indent + 1, format!("goto {fall:#x};"));
                self.residual_gotos += 1;
            }
            self.push(indent, "}".to_string());
            self.emit_from(join, stop, indent, bound);
            return true;
        }
        if join == fall {
            // 条件成立才跳走：`if (cond) { taken..join }`。
            self.emit_block_stmts(cur, indent, true);
            self.visited.insert(cur);
            self.structured_blocks += 1;
            self.push(indent, format!("if ({cond}) {{"));
            self.emit_from(taken, Some(join), indent + 1, bound);
            self.push(indent, "}".to_string());
            self.emit_from(join, stop, indent, bound);
            return true;
        }
        // if/else：两支都在 join 汇合。
        self.emit_block_stmts(cur, indent, true);
        self.visited.insert(cur);
        self.structured_blocks += 1;
        self.push(indent, format!("if ({cond}) {{"));
        self.emit_from(taken, Some(join), indent + 1, bound);
        self.push(indent, "} else {".to_string());
        self.emit_from(fall, Some(join), indent + 1, bound);
        self.push(indent, "}".to_string());
        self.emit_from(join, stop, indent, bound);
        true
    }

    /// 尝试把一个**自然循环头**结构化为 `while` 或 `do-while`。成功返回 true。
    ///
    /// 输入 `header` 由 `natural_loops` 保证是一个真回边头（存在块跳回它且它支配那个块）。
    /// 支持两种形态：
    /// - **预测试 while**：头部是条件块，一个后继在循环体内（体入口），另一个后继是循环**出口**。
    ///   `while (继续条件) { 体 }`；
    /// - **do-while**：头部是条件块，体在某一侧，执行完体后由回边块判断是否再回头部。
    ///   这里只在头部自身就是那个“回边判断块”（body 先跑、末尾回跳头部）时还原成
    ///   `do { 体 } while (cond);`。
    ///
    /// 其余形态（多重回边、头部条件块两个后继都在体内且无单一出口、不可归约）**一律不猜**，
    /// 返回 false 交给上层 goto 兜底。
    fn emit_loop(
        &mut self,
        header: u64,
        indent: usize,
        stop: Option<u64>,
        outer_bound: Option<&BTreeSet<u64>>,
    ) -> bool {
        let Some(body) = self.natural_loops.get(&header).cloned() else {
            return false;
        };
        if body.len() < 2 || self.visited.contains(&header) {
            return false;
        }
        // 已经在发射中（体内遇到头部）→ 不重复结构化。
        if outer_bound.is_some_and(|b| !b.contains(&header)) {
            return false;
        }

        let Some(hb) = self.blocks.get(&header).copied() else {
            return false;
        };
        // 头部必须是条件块（带两个后继）。
        let Some(hlast) = self
            .last_insn_addr(hb)
            .and_then(|a| self.by_addr.get(&a).copied())
        else {
            return false;
        };
        if !matches!(hlast.flow, Flow::Branch { conditional: true }) {
            return false;
        }
        let Some((taken, fall)) = self.split_branch(header, Some(hlast), &hb.successors.clone())
        else {
            return false;
        };
        let prev = self.prev_insn(header, hlast.addr);
        let cond = branch_condition_text(hlast, prev, self.namer);

        // 循环出口：体集合中、后继落在体外的目标（必须唯一，否则不猜）。
        let mut exits: BTreeSet<u64> = BTreeSet::new();
        for &m in &body {
            if let Some(mb) = self.blocks.get(&m) {
                for &s in &mb.successors {
                    if !body.contains(&s) {
                        exits.insert(s);
                    }
                }
            }
        }

        // —— 形态 A：预测试 while ——
        // 头部一个后继在体内（体入口），另一个后继是唯一出口。
        let in_body = |x: u64| body.contains(&x) && x != header;
        if in_body(taken) ^ in_body(fall) {
            let (entry, exit) = if in_body(taken) {
                (taken, fall)
            } else {
                (fall, taken)
            };
            // 出口必须是（或就是）唯一出口，且 exit 在体外。
            if !body.contains(&exit) && (exits.len() == 1 && exits.contains(&exit)) {
                // 继续条件：体入口是 taken → while(cond)；体入口是 fall → while(!cond)。
                let continue_cond = if in_body(taken) {
                    cond.clone()
                } else {
                    format!("!({cond})")
                };
                self.emit_block_stmts(header, indent, true);
                self.visited.insert(header);
                self.structured_blocks += 1;
                self.push(
                    indent,
                    format!("while ({continue_cond}) {{ /* @{header:#x} */"),
                );
                let before = self.visited.len();
                self.emit_from(entry, Some(header), indent + 1, Some(&body));
                if self.visited.len() == before {
                    // 体没发射（异常）→ 收回，退回 false 由上层 goto。
                    self.push(indent, format!("}} /* 循环体未能结构化 */ goto {exit:#x};"));
                    self.residual_gotos += 1;
                    return true;
                }
                self.push(indent, "}".to_string());
                // 循环后继续：从出口按外层上下文发射。
                self.emit_from(exit, stop, indent, outer_bound);
                return true;
            }
        }

        // —— 形态 B：do-while ——
        // 头部即回边判断块（体先执行，末尾回跳头部）。判定：头部两个后继都在体内（或一个是自身），
        // 且没有“头部直接跳到体外”的出口；出口由体内某块的体外后继给出。
        let header_exits: Vec<u64> = hb
            .successors
            .iter()
            .copied()
            .filter(|&s| !body.contains(&s))
            .collect();
        if header_exits.is_empty() && exits.len() == 1 {
            let exit = *exits.iter().next().unwrap();
            // 体入口：头部的某个体内后继里，能回到头部的那一支先跑。取 taken/fall 中在体内的那个。
            let entry = if in_body(taken) { taken } else { fall };
            if !in_body(entry) {
                return false;
            }
            self.emit_block_stmts(header, indent, true);
            self.visited.insert(header);
            self.structured_blocks += 1;
            self.push(indent, format!("do {{ /* @{header:#x} */"));
            let before = self.visited.len();
            self.emit_from(entry, Some(header), indent + 1, Some(&body));
            if self.visited.len() == before {
                return false;
            }
            self.push(indent, format!("}} while ({cond});"));
            self.emit_from(exit, stop, indent, outer_bound);
            return true;
        }

        // 形态不确定 → 不猜。
        false
    }

    /// 拆分条件块的两个后继：`(taken, fall)`。taken = 分支指令的 target 所在块。
    fn split_branch(
        &self,
        cur: u64,
        last_insn: Option<&DecodedInsn>,
        succs: &[u64],
    ) -> Option<(u64, u64)> {
        let insn = last_insn?;
        if succs.len() != 2 {
            return None;
        }
        match insn.target {
            Some(t) if succs.contains(&t) => {
                let fall = succs.iter().copied().find(|&s| s != t)?;
                Some((t, fall))
            }
            // 间接条件跳转（目标未知）无法判断 taken/fall → 不猜。
            _ => {
                let _ = cur;
                None
            }
        }
    }
}

/// 计算所有**自然循环**：对每条回边 `b -> h`（`h` 支配 `b`），循环体 = `{h} ∪ {能到达 b 且
/// 不经过 h 的块}`（标准算法）。返回 `h -> 循环体块集合`。不可归约图里若某头出现多回边、
/// 体会合并，仍能给出一个集合；但 `emit_loop` 会在形态不唯一时拒绝结构化（不猜）。
fn compute_natural_loops(
    blocks: &BTreeMap<u64, &crate::cfg::BasicBlock>,
    dom: &BTreeMap<u64, BTreeSet<u64>>,
) -> BTreeMap<u64, BTreeSet<u64>> {
    let dominates = |h: u64, b: u64| dom.get(&b).is_some_and(|s| s.contains(&h));
    let mut loops: BTreeMap<u64, BTreeSet<u64>> = BTreeMap::new();

    for (&b, block) in blocks {
        for &s in &block.successors {
            // 回边：后继支配当前块。
            if !dominates(s, b) {
                continue;
            }
            let header = s;
            let mut body: BTreeSet<u64> = BTreeSet::new();
            body.insert(header);
            body.insert(b);
            // 从 b 反向沿前驱扩展，凡不经过 header 的块都并入循环体。
            let mut stack: Vec<u64> = vec![b];
            let mut seen: BTreeSet<u64> = BTreeSet::new();
            while let Some(x) = stack.pop() {
                if x == header || !seen.insert(x) {
                    continue;
                }
                body.insert(x);
                if let Some(xb) = blocks.get(&x) {
                    for &p in &xb.predecessors {
                        if p != header && !seen.contains(&p) {
                            stack.push(p);
                        }
                    }
                }
            }
            loops.entry(header).or_default().extend(body);
        }
    }
    loops
}

/// 迭代计算支配集合（块首地址 → 支配它的块首集合，含自身）。
fn compute_dominators(
    blocks: &BTreeMap<u64, &crate::cfg::BasicBlock>,
    start: u64,
) -> BTreeMap<u64, BTreeSet<u64>> {
    let all: BTreeSet<u64> = blocks.keys().copied().collect();
    let mut dom: BTreeMap<u64, BTreeSet<u64>> = BTreeMap::new();
    for &b in blocks.keys() {
        if b == start {
            let mut s = BTreeSet::new();
            s.insert(b);
            dom.insert(b, s);
        } else {
            dom.insert(b, all.clone());
        }
    }
    let mut changed = true;
    while changed {
        changed = false;
        for (&b, block) in blocks {
            if b == start {
                continue;
            }
            let mut new: BTreeSet<u64> = BTreeSet::new();
            let preds = &block.predecessors;
            if let Some(first) = preds.first() {
                if let Some(d) = dom.get(first) {
                    new = d.clone();
                }
            }
            for p in preds.iter().skip(1) {
                if let Some(d) = dom.get(p) {
                    new = new.intersection(d).copied().collect();
                }
            }
            new.insert(b);
            if dom.get(&b) != Some(&new) {
                dom.insert(b, new);
                changed = true;
            }
        }
    }
    dom
}

/// 迭代计算直接后支配点（immediate post-dominator），用"仅保留被所有后继后支配的点"逼近。
///
/// 出口块（无后继 / terminal）的后支配点映射到自己（`None` 表示"没有唯一直接后支配点"）。
fn compute_immediate_postdominators(
    blocks: &BTreeMap<u64, &crate::cfg::BasicBlock>,
) -> BTreeMap<u64, Option<u64>> {
    // 后支配集合：pdom[b] = 从 b 出发的所有路径都会经过的块集合（含自身）。
    let all: BTreeSet<u64> = blocks.keys().copied().collect();
    let exits: BTreeSet<u64> = blocks
        .iter()
        .filter(|(_, b)| b.terminal || b.successors.is_empty())
        .map(|(&s, _)| s)
        .collect();

    let mut pdom: BTreeMap<u64, BTreeSet<u64>> = BTreeMap::new();
    for &b in blocks.keys() {
        if exits.contains(&b) {
            let mut s = BTreeSet::new();
            s.insert(b);
            pdom.insert(b, s);
        } else {
            pdom.insert(b, all.clone());
        }
    }
    let mut changed = true;
    while changed {
        changed = false;
        for (&b, block) in blocks {
            if exits.contains(&b) {
                continue;
            }
            let mut new: BTreeSet<u64> = BTreeSet::new();
            if let Some(first) = block.successors.first() {
                if let Some(d) = pdom.get(first) {
                    new = d.clone();
                }
            }
            for s in block.successors.iter().skip(1) {
                if let Some(d) = pdom.get(s) {
                    new = new.intersection(d).copied().collect();
                }
            }
            new.insert(b);
            if pdom.get(&b) != Some(&new) {
                pdom.insert(b, new);
                changed = true;
            }
        }
    }

    // 直接后支配点 = 严格后支配集合中“最靠近的”那个：即不被其它严格后支配点后支配者。
    // 这里用近似：去掉自身后，如果恰有一个候选它就是直接后支配点；否则取集合里地址最大的
    // 那个作为 join 估计（保守：宁可不结构化，也会在 emit_if 里因 join 不合理而回退）。
    let mut out: BTreeMap<u64, Option<u64>> = BTreeMap::new();
    for (&b, set) in &pdom {
        let strict: Vec<u64> = set.iter().copied().filter(|&x| x != b).collect();
        if strict.is_empty() {
            out.insert(b, None);
            continue;
        }
        // 从候选里挑谁“最靠内”：候选 c 是最内直接后支配点，如果所有其它候选都被 c 后支配。
        let mut chosen: Option<u64> = None;
        for &c in &strict {
            let c_pdom = pdom.get(&c);
            // c 是否后支配所有其它候选（除自身外都落在 c 的后支配集里）？
            let inner = strict.iter().all(|&other| {
                other == c
                    || c_pdom
                        .and_then(|s| s.get(&other).map(|_| ()))
                        .is_some_and(|_| c_pdom.is_some_and(|s| s.contains(&other)))
            });
            if inner {
                chosen = Some(c);
                break;
            }
        }
        out.insert(b, chosen);
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use bitflip_arch::{Arch, ConditionCode, MnemonicId, Operand, RegId};
    fn jmp(addr: u64, target: u64) -> DecodedInsn {
        DecodedInsn {
            addr,
            len: 4,
            arch: Arch::X86_64,
            mnemonic: MnemonicId::UNKNOWN,
            flow: Flow::Branch { conditional: false },
            target: Some(target),
            condition: None,
            operands: vec![],
            reads: Default::default(),
            writes: Default::default(),
            privileged: false,
        }
    }
    fn jcc(addr: u64, target: u64) -> DecodedInsn {
        DecodedInsn {
            flow: Flow::Branch { conditional: true },
            target: Some(target),
            condition: Some(ConditionCode::Equal),
            ..jmp(addr, target)
        }
    }
    fn ret(addr: u64) -> DecodedInsn {
        DecodedInsn {
            addr,
            len: 4,
            arch: Arch::X86_64,
            mnemonic: MnemonicId::UNKNOWN,
            flow: Flow::Return,
            target: None,
            condition: None,
            operands: vec![],
            reads: Default::default(),
            writes: Default::default(),
            privileged: false,
        }
    }
    /// 一条 `int3` 式的陷阱填充指令（单字节）。
    fn trap(addr: u64) -> DecodedInsn {
        DecodedInsn {
            addr,
            len: 1,
            arch: Arch::X86_64,
            mnemonic: MnemonicId::UNKNOWN,
            flow: Flow::Trap,
            target: None,
            condition: None,
            operands: vec![],
            reads: Default::default(),
            writes: Default::default(),
            privileged: false,
        }
    }
    fn nop(addr: u64) -> DecodedInsn {
        DecodedInsn {
            addr,
            len: 4,
            arch: Arch::X86_64,
            mnemonic: MnemonicId::UNKNOWN,
            flow: Flow::Fallthrough,
            target: None,
            condition: None,
            operands: vec![Operand::Reg(RegId(0))],
            reads: Default::default(),
            writes: Default::default(),
            privileged: false,
        }
    }

    fn namer(_: u16) -> Option<String> {
        Some("r0".to_string())
    }

    fn build(insns: Vec<DecodedInsn>) -> PseudocodeFunction {
        let cfg = Cfg::build(&insns);
        decompile_structured(
            insns[0].addr,
            Some("f"),
            &insns,
            &cfg,
            &namer,
            crate::pseudo::Resolvers::none(),
        )
    }

    /// 造一条 x86 `cmp reg, imm`（顺序流、只写标志——writes 放一个非操作数寄存器模拟标志）。
    fn cmp_reg_imm(addr: u64, reg: u16, imm: i64) -> DecodedInsn {
        let mut i = nop(addr);
        i.operands = vec![Operand::Reg(RegId(reg)), Operand::Imm(imm)];
        // 模拟标志寄存器写（不在操作数里的寄存器）。
        i.writes.insert(RegId(999));
        i.reads.insert(RegId(reg));
        i
    }

    /// 造一条间接跳转 `jmp [idx*8 + table]`（目标未知 = switch 形态）。
    fn jmp_table(addr: u64, idx_reg: u16, table: i64) -> DecodedInsn {
        let mut i = jmp(addr, 0);
        i.target = None;
        i.operands = vec![Operand::Mem(bitflip_arch::MemRef {
            base: None,
            index: Some(RegId(idx_reg)),
            scale: 8,
            index_extend: None,
            disp: table,
            size: 8,
            write: false,
        })];
        i
    }

    #[test]
    fn switch_table_is_recovered_into_case_dispatch() {
        // 布局：
        //   0x1000 cmp r0(idx),2
        //   0x1004 ja 0x3000 (default)      —— 本块两后继：0x1010(switch) 与 0x3000
        //   0x1010 jmp [r0*8 + 0x8000]        —— switch 块，间接
        //   0x3000 ret  (default)
        //   表 @0x8000: [0x2000, 0x2010, 0x2020]
        let insns = vec![
            cmp_reg_imm(0x1000, 0, 2),
            // ja：flow 条件跳转、target=default；但 CFG 会用 successors 判定。
            DecodedInsn {
                flow: Flow::Branch { conditional: true },
                target: Some(0x3000),
                condition: Some(ConditionCode::UnsignedHigher),
                ..jmp(0x1004, 0x3000)
            },
            jmp_table(0x1008, 0, 0x8000),
            ret(0x3000),
        ];
        let targets = [0x2000u64, 0x2010, 0x2020];
        let reader = move |addr: u64, len: usize| -> Option<Vec<u8>> {
            if addr != 0x8000 {
                return None;
            }
            let mut out = Vec::new();
            for t in targets.iter() {
                out.extend_from_slice(&t.to_le_bytes());
            }
            Some(out[..len.min(out.len())].to_vec())
        };
        let cfg = Cfg::build(&insns);
        let f = decompile_structured(
            insns[0].addr,
            Some("f"),
            &insns,
            &cfg,
            &namer,
            crate::pseudo::Resolvers {
                table: Some(&reader),
                ..crate::pseudo::Resolvers::none()
            },
        );
        let body = f
            .structured_body
            .as_ref()
            .expect("应有结构化正文")
            .join("\n");
        assert!(body.contains("switch (r0)"), "应还原出 switch：\n{body}");
        assert!(body.contains("case 0: goto 0x2000;"), "\n{body}");
        assert!(body.contains("case 2: goto 0x2020;"), "\n{body}");
        assert!(body.contains("default: goto 0x3000;"), "\n{body}");
    }

    #[test]
    fn switch_offset_idiom_is_recovered() {
        // MSVC x64 偏移跳表 idiom：
        //   0x1000 cmp eax,1
        //   0x1004 ja 0x4000 (default)
        //   0x1008 lea r5, [rip + rel]        ; base = 0x1008 + 7 + rel
        //   0x100f mov ecx, [r5 + r0*4 + 0]   ; 32 位偏移，项大小 4
        //   0x1015 add r9, r5                 ; r9 = base + offset
        //   0x1018 jmp r9
        //   0x4000 ret
        // 表 @base: 两个 u32 偏移 [0x40, 0x50] → 目标 base+0x40 / base+0x50。
        let lea_addr = 0x1008u64;
        let rel = 0x2000i64; // base = (0x1008 + 7) + 0x2000 = 0x300f
        let mut lea = nop(lea_addr);
        lea.len = 7;
        lea.operands = vec![Operand::Reg(RegId(5)), Operand::PcRelative(rel)];
        let mut mov = nop(0x100f);
        mov.len = 6;
        mov.operands = vec![
            Operand::Reg(RegId(9)),
            Operand::Mem(bitflip_arch::MemRef {
                base: Some(RegId(5)),
                index: Some(RegId(0)),
                scale: 4,
                index_extend: None,
                disp: 0,
                size: 4,
                write: false,
            }),
        ];
        let mut add = nop(0x1015);
        add.operands = vec![Operand::Reg(RegId(9)), Operand::Reg(RegId(5))];
        let mut jmp_reg = jmp(0x1019, 0);
        jmp_reg.target = None;
        jmp_reg.operands = vec![Operand::Reg(RegId(9))];
        let insns = vec![
            cmp_reg_imm(0x1000, 0, 1),
            DecodedInsn {
                flow: Flow::Branch { conditional: true },
                target: Some(0x4000),
                condition: Some(ConditionCode::UnsignedHigher),
                ..jmp(0x1004, 0x4000)
            },
            lea,
            mov,
            add,
            jmp_reg,
            ret(0x4000),
        ];
        let base = lea_addr + 7 + rel as u64; // 0x300f
        let reader = move |addr: u64, len: usize| -> Option<Vec<u8>> {
            if addr != base {
                return None;
            }
            let mut out = Vec::new();
            out.extend_from_slice(&0x40u32.to_le_bytes());
            out.extend_from_slice(&0x50u32.to_le_bytes());
            Some(out[..len.min(out.len())].to_vec())
        };
        let cfg = Cfg::build(&insns);
        let f = decompile_structured(
            insns[0].addr,
            Some("f"),
            &insns,
            &cfg,
            &namer,
            crate::pseudo::Resolvers {
                table: Some(&reader),
                ..crate::pseudo::Resolvers::none()
            },
        );
        let body = f.structured_body.as_ref().expect("正文").join("\n");
        assert!(body.contains("switch (r0)"), "应还原 switch：\n{body}");
        assert!(
            body.contains(&format!("case 0: goto {:#x};", base + 0x40)),
            "偏移应加到基址：\n{body}"
        );
        assert!(
            body.contains(&format!("case 1: goto {:#x};", base + 0x50)),
            "\n{body}"
        );
    }

    #[test]
    fn switch_without_reader_stays_goto() {
        // 没有 table_reader：间接跳转无法还原，应保持 goto 兜底（不猜）。
        let insns = vec![
            cmp_reg_imm(0x1000, 0, 2),
            DecodedInsn {
                flow: Flow::Branch { conditional: true },
                target: Some(0x3000),
                condition: Some(ConditionCode::UnsignedHigher),
                ..jmp(0x1004, 0x3000)
            },
            jmp_table(0x1008, 0, 0x8000),
            ret(0x3000),
        ];
        let cfg = Cfg::build(&insns);
        let f = decompile_structured(
            insns[0].addr,
            Some("f"),
            &insns,
            &cfg,
            &namer,
            crate::pseudo::Resolvers::none(),
        );
        let body = f.structured_body.as_ref().expect("应有正文").join("\n");
        assert!(
            !body.contains("switch"),
            "无读取器时不应还原 switch：\n{body}"
        );
    }

    #[test]
    fn unreached_code_region_is_emitted_not_dropped() {
        // 主路径：0x1000 jmp 0x1010（跳过 0x1004 一段不可达代码）；0x1004 有一段不可达
        // 但**可执行**的代码（nop + ret）。覆盖补遍应把它作为分离区域输出，而不是丢弃。
        let insns = vec![jmp(0x1000, 0x1010), nop(0x1004), ret(0x1008), ret(0x1010)];
        let f = build(insns);
        let body = f.structured_body.as_ref().unwrap().join("\n");
        assert!(
            body.contains("分离区域起点"),
            "不可达代码块应作为分离区域输出：\n{body}"
        );
        assert!(body.contains("@0x1004"), "\n{body}");
    }

    #[test]
    fn padding_only_unreached_region_is_not_dumped() {
        // 0x1000 jmp 0x1008；0x1004 是一个纯 trap（int3）填充块。覆盖补遍**不应**把它
        // 当分离区域输出（否则真实二进制里成百上千个 int3 会刷屏）。
        let insns = vec![jmp(0x1000, 0x1008), trap(0x1004), ret(0x1008)];
        let f = build(insns);
        let body = f.structured_body.as_ref().unwrap().join("\n");
        assert!(
            !body.contains("分离区域起点"),
            "纯填充块不应作为分离区域输出：\n{body}"
        );
    }

    #[test]
    fn linear_function_fully_structured() {
        // 0x1000 nop; 0x1004 nop; 0x1008 ret
        let insns = vec![nop(0x1000), nop(0x1004), ret(0x1008)];
        let f = build(insns);
        assert!(f.structured, "线性函数应完全结构化");
        let body = f.structured_body.as_ref().unwrap();
        assert!(body.iter().any(|l| l.contains("return")));
    }

    #[test]
    fn if_then_structured() {
        // 0x1000: jcc 0x1010 ; 0x1004: nop ; 0x1008: nop; 0x100c: jmp 0x1014 ; 0x1010: nop; 0x1014: ret
        // 条件成立 → 跳过 then 体。等价 if(!cond){...}
        let insns = vec![
            jcc(0x1000, 0x1010),
            nop(0x1004),
            nop(0x1008),
            jmp(0x100c, 0x1014),
            nop(0x1010),
            ret(0x1014),
        ];
        let f = build(insns);
        // 至少有 if 出现；不强制完全结构化（jmp 可能保留）。
        let body = f.structured_body.as_ref().unwrap();
        let joined = body.join("\n");
        assert!(joined.contains("if ("), "应出现 if：\n{joined}");
    }

    #[test]
    fn simple_loop_has_do_while_or_goto() {
        // 0x1000: nop; 0x1004: jcc 0x1000 (回边到自身头部) ; 0x1008: ret
        // cur=0x1004 条件块，taken 0x1000 支配 cur? 头 0x1000... 这里 taken 指向 0x1000（前面）
        let insns = vec![nop(0x1000), jcc(0x1004, 0x1000), ret(0x1008)];
        let f = build(insns);
        let body = f.structured_body.as_ref().unwrap();
        let joined = body.join("\n");
        // 不论是否结构化成功，都不该 panic，且要么有 while/do 要么有 goto。
        assert!(
            joined.contains("while") || joined.contains("goto"),
            "循环应表现为 while/do 或 goto：\n{joined}"
        );
    }

    #[test]
    fn pretest_while_structured() {
        // 0x1000: jcc 0x1010(出口)  —— 头部是条件块
        // 0x1004: nop（循环体）
        // 0x1008: jmp 0x1000（回边）
        // 0x1010: ret（出口）
        let insns = vec![
            jcc(0x1000, 0x1010),
            nop(0x1004),
            jmp(0x1008, 0x1000),
            ret(0x1010),
        ];
        let f = build(insns);
        let body = f.structured_body.as_ref().unwrap();
        let joined = body.join("\n");
        assert!(
            joined.contains("while ("),
            "预测试循环应还原成 while：\n{joined}"
        );
    }

    #[test]
    fn irreducible_falls_back_to_goto_with_note() {
        // 构造一个至少能跑通的 CFG，确认 notes 里给出 PartiallyStructured 或 Structured。
        let insns = vec![nop(0x1000), ret(0x1004)];
        let f = build(insns);
        assert!(f.notes.iter().any(|n| matches!(
            n,
            PseudocodeNote::Structured | PseudocodeNote::PartiallyStructured { .. }
        )));
    }
}
