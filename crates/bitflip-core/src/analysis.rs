//! M3 分析能力：函数识别、交叉引用、字符串表。
//!
//! 边界划分：
//! - [`Disasm`](crate::Disasm) 管单页反汇编（M2 交付）；
//! - 本模块管**目标级**的函数/xref/字符串结论 —— 从扫描结果构建一次，多端查询。
//!
//! 诚实性规则（CLAUDE.md §7）：
//! - 函数边界未知就写 `None`，不猜；
//! - 没有名字的函数 `named = false`、`name` 为空 —— 不生成 `sub_xxx` 占位名；
//! - 间接引用不猜目标（跳转表是 M6 的工作）；
//! - 每个函数带来源与置信度，UI 能解释"为什么这里被当成函数"。
//!
//! 内存纪律（PLAN §2，参照实现的 OOM 教训）：构建过程**流式**处理指令 ——
//! 一次解码一条、立刻归约成 xref/候选，绝不持有整份 `Vec<DecodedInsn>`。

use std::collections::{BTreeMap, HashMap};

use bitflip_analyze::{merge_candidates, unwind_candidates, Cfg, StringOptions};
use bitflip_arch::Flow;
use bitflip_symbols::{SymbolCandidate, SymbolSource};
use serde::{Deserialize, Serialize};

use crate::disasm::{hex16, Disasm};

/// wire 格式版本。
pub const ANALYSIS_FORMAT_VERSION: u32 = 1;

/// 函数的 wire 表示。
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FunctionWire {
    /// 入口地址（定长 16 位十六进制）。
    pub start: String,
    /// 结束地址（不含）；未知时 `null` —— 不猜边界。
    pub end: Option<String>,
    /// 函数名；未命名时为空串（`named = false`），**不生成占位名**。
    pub name: String,
    /// 是否有名字（来自符号/导出/用户）。
    pub named: bool,
    /// 名字来源（`symbol-table` / `unwind` / `discovery` / …）。
    pub source: String,
    /// 来源的中文名。
    pub source_label: String,
    /// 置信度（0–100）。
    pub confidence: u8,
    /// 大小（`end` 未知时 `null`）。
    pub size: Option<u64>,
}

/// xref 的 wire 表示。
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct XrefWire {
    /// 发起地址（指令地址）。
    pub from: String,
    /// 目标地址。
    pub to: String,
    /// 类型（`call` / `jump` / `data`）。
    pub kind: String,
}

/// 字符串条目的 wire 表示。
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct StringWire {
    /// 起始地址。
    pub address: String,
    /// 字节长度。
    pub size: u64,
    /// 编码（`ascii` / `utf-16le`）。
    pub encoding: String,
    /// 内容。
    pub text: String,
}

/// 目标级分析结论（构建一次，多端查询）。
///
/// 构建**不**物化指令流：逐条解码、逐条归约（见 [`TargetAnalysis::build`]）。
/// 产出的三张表（函数/xref/字符串）都是派生物，可整体重建 ——
/// 这是 ADR-0012 里 `.bda` 文件的内容。
#[derive(Debug)]
pub struct TargetAnalysis {
    functions: Vec<FunctionWire>,
    xrefs: Vec<XrefWire>,
    xref_by_from: HashMap<u64, Vec<usize>>,
    xref_by_to: HashMap<u64, Vec<usize>>,
    strings: Vec<StringWire>,
    /// 每个函数的基本块（按函数入口索引）。M5 引入。
    cfg_by_function: BTreeMap<u64, CfgWire>,
    notes: Vec<String>,
}

/// 一个函数的基本块摘要（wire 用）。
///
/// 只带"块边界 + 后继/前驱 + 是否终结"，**不带**块内指令列表 ——
/// 指令由 `/api/insns` 按地址范围查询。这样 CFG 响应的大小与函数长度无关，
/// 大函数（几万个块）也不会把响应撑爆。
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize)]
pub struct CfgWire {
    /// 函数入口（定长 16 位小写十六进制）。
    pub entry: String,
    /// 基本块数量。
    pub block_count: usize,
    /// 边数量。
    pub edge_count: usize,
    /// 是否存在环（回边）。
    pub has_cycle: bool,
    /// 是否因函数边界未知而截断。
    pub truncated: bool,
    /// 缺失说明（中文，面向用户）。
    pub notes: Vec<String>,
    /// 各基本块。
    pub blocks: Vec<BlockWire>,
}

/// 一个基本块（wire 用）。
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize)]
pub struct BlockWire {
    /// 块首地址。
    pub start: String,
    /// 块尾地址（不含）。
    pub end: String,
    /// 块内最后一条指令的地址。
    pub last_insn: String,
    /// 后继块首地址。
    pub successors: Vec<String>,
    /// 前驱块首地址。
    pub predecessors: Vec<String>,
    /// 是否以不返回的指令结束。
    pub terminal: bool,
}

/// 字符串扫描的单次读取上限：超过则分块流式扫描（跨块边界由状态机衔接）。
const SCAN_CHUNK: usize = 4 * 1024 * 1024;
/// 单个未终止可打印运行的上限：超过即判定为数据伪影并丢弃。
const MAX_RUN: usize = 4096;

impl TargetAnalysis {
    /// 从反汇编结果 + 目标对象构建目标级分析。
    ///
    /// `disasm` 提供地址空间、指令索引、覆盖标记与解码器；
    /// `object` 提供符号/导出/展开表（识别函数的多来源候选）。
    #[must_use]
    pub fn build(
        disasm: &Disasm,
        object: &bitflip_loader::object::Object,
        opts: &StringOptions,
    ) -> Self {
        let mut notes = Vec::new();

        // ── 函数候选收集（多来源）──
        let mut by_addr: HashMap<u64, Vec<SymbolCandidate>> = HashMap::new();

        // 来源 1：符号表中的函数符号
        for sym in &object.symbols {
            if sym.is_function && sym.defined && !sym.name.trim().is_empty() {
                by_addr.entry(sym.value).or_default().push(SymbolCandidate {
                    addr: sym.value,
                    name: sym.name.clone(),
                    source: SymbolSource::SymbolTable,
                    confidence: 70,
                });
            }
        }
        // 来源 2：导出表
        for exp in &object.exports {
            if exp.forwarder.is_some() {
                continue; // 转发导出没有本地代码，不是函数
            }
            by_addr
                .entry(exp.address)
                .or_default()
                .push(SymbolCandidate {
                    addr: exp.address,
                    name: exp.name.clone(),
                    source: SymbolSource::Export,
                    confidence: 80,
                });
        }
        // 来源 3：展开表（PE .pdata / ELF FDE）—— 唯一带边界的来源
        for c in unwind_candidates(&object.unwind) {
            by_addr.entry(c.addr).or_default().push(c);
        }

        // 来源 3.5：入口点。
        //
        // 入口是**唯一一个工具无论如何都知道的地址**，而且它一定是一段代码的
        // 起点。少了这一条，原始二进制（没有符号表、没有导出、没有展开表）
        // 会得到"0 个函数" —— 而用户明明指定了基址，就是想从那里开始看。
        //
        // 置信度给 75：比符号表（70）高、比导出（80）低。入口是个强证据，
        // 但它是"程序从这里开始执行"，不保证"这里是一个函数边界" ——
        // 某些手写汇编的 `_start` 之后就直接是别的函数。
        if let Some(entry) = object.entry {
            // 只在该地址确实有解出来的指令时才作为候选，
            // 否则会在数据区造出一个假函数。
            if disasm
                .index
                .range(entry, entry.saturating_add(1))
                .next()
                .is_some()
            {
                by_addr.entry(entry).or_default().push(SymbolCandidate {
                    addr: entry,
                    name: String::new(), // 入口不等于"函数名叫 entry" —— 诚实留空
                    source: SymbolSource::EntryPoint,
                    confidence: 75,
                });
            }
        }

        // 来源 4：递归下降证明可达的 call 直接目标。
        // 流式：一次解码一条，立刻归约。linear_only 的 call 不算种子 ——
        // 线性扫描会把数据当指令，它的"调用目标"是伪影。
        let mut call_target_count = 0usize;
        for (addr, len) in disasm.index.range(0, u64::MAX) {
            let Some(bytes) = disasm.space.read(addr, usize::from(len)) else {
                continue;
            };
            let Ok(insn) = disasm.decoder.decode_one(&bytes, addr) else {
                continue;
            };
            if insn.flow == Flow::Call && disasm.coverage.is_reachable(addr) {
                let Some(target) = insn.target else {
                    continue;
                };
                by_addr.entry(target).or_default().push(SymbolCandidate {
                    addr: target,
                    name: String::new(), // 调用目标没有名字 —— 诚实留空
                    source: SymbolSource::Discovery,
                    confidence: 40,
                });
                call_target_count += 1;
            }
        }

        // 来源 5：导入桩（import thunk）。
        //
        // 静态链接的 mingw 程序在 `.text` 里留着一批一指令函数：
        // `jmp *__imp_xxx(%rip)` + `nop` 对齐。它们**既没有符号**（已 strip），
        // **也不会被 call**（调用点直接走 IAT），所以前四个来源一个都碰不到它们 ——
        // 实测这让覆盖率停在 92.21%，正好卡在 95% 门槛下面。
        //
        // 判据严格：从某个指令边界起，必须是无条件间接跳转，且后续指令全是填充，
        // 且总长不超过一个桩的尺寸。宁可漏，不要误报（§7）。
        let mut thunk_count = 0usize;
        for (addr, len) in disasm.index.range(0, u64::MAX) {
            // 只对"未识别"的位置找桩：已经认出来的函数不用改来源
            if by_addr.contains_key(&addr) {
                continue;
            }
            let Some(bytes) = disasm.space.read(addr, usize::from(len)) else {
                continue;
            };
            let Ok(insn) = disasm.decoder.decode_one(&bytes, addr) else {
                continue;
            };
            // 桩的第一条：无条件跳转，且目标未知（间接 —— 走 IAT）
            if !matches!(insn.flow, Flow::Branch { conditional: false }) {
                continue;
            }
            if insn.target.is_some() {
                continue; // 直接跳转是普通尾调用/跳转，不是桩
            }
            if !is_import_thunk_tail(&disasm.space, addr, insn.len) {
                continue;
            }
            by_addr.entry(addr).or_default().push(SymbolCandidate {
                addr,
                name: String::new(), // 桩也没有名字 —— 不许编
                source: SymbolSource::ImportThunk,
                confidence: 60,
            });
            thunk_count += 1;
        }
        if thunk_count > 0 {
            notes.push(format!(
                "识别出 {thunk_count} 个导入桩（`jmp *__imp_xxx` 形式的间接跳转桩）"
            ));
        }

        // ── xref 提取（与候选收集同一遍流式解码）──
        let mut xrefs: Vec<XrefWire> = Vec::new();
        let mut xref_by_from: HashMap<u64, Vec<usize>> = HashMap::new();
        let mut xref_by_to: HashMap<u64, Vec<usize>> = HashMap::new();
        for (addr, len) in disasm.index.range(0, u64::MAX) {
            let Some(bytes) = disasm.space.read(addr, usize::from(len)) else {
                continue;
            };
            let Ok(insn) = disasm.decoder.decode_one(&bytes, addr) else {
                continue;
            };
            for x in bitflip_analyze::xrefs_of(&insn) {
                let idx = xrefs.len();
                xref_by_from.entry(x.from).or_default().push(idx);
                xref_by_to.entry(x.to).or_default().push(idx);
                xrefs.push(XrefWire {
                    from: hex16(x.from),
                    to: hex16(x.to),
                    kind: x.kind.as_str().to_string(),
                });
            }
        }

        // ── 合并候选 → 函数结论 ──
        let mut addrs: Vec<u64> = by_addr.keys().copied().collect();
        addrs.sort_unstable();
        let mut functions: Vec<FunctionWire> = Vec::with_capacity(addrs.len());
        for addr in addrs {
            let Some(cands) = by_addr.remove(&addr) else {
                continue;
            };
            let f = merge_candidates(addr, cands);
            // 只有调用目标推断的地址也保留：它确实被调用过，是有信息量的位置。
            // 但名字留空、named=false —— UI 显示"未命名"，而不是编一个 sub_xxx。
            functions.push(FunctionWire {
                start: hex16(addr),
                end: f.end.map(hex16),
                name: f.name.clone(),
                named: !f.name.is_empty(),
                source: f.name_source.as_str().to_string(),
                source_label: f.name_source.label_zh().to_string(),
                confidence: f.confidence,
                size: f.end.map(|e| e.saturating_sub(addr)),
            });
        }
        if call_target_count > 0 {
            notes.push(format!(
                "有 {call_target_count} 个函数仅来自调用目标推断（无符号/展开表佐证），没有边界与名字"
            ));
        }

        // ── 字符串提取（流式，分块）──
        let mut strings: Vec<StringWire> = Vec::new();
        let mut oversized_runs = 0usize;
        for seg in disasm.space.segments() {
            // 代码段不进字符串表：内联常量在反汇编里可见；
            // 把代码字节当字符串扫描只会产出伪影
            if seg.perms.execute || seg.vsize == 0 {
                continue;
            }
            let mut scanner = StringScanner::new(seg.vaddr, opts);
            let mut offset = 0u64;
            while offset < seg.vsize {
                let len = SCAN_CHUNK.min((seg.vsize - offset) as usize);
                let Some(data) = disasm.space.read(seg.vaddr + offset, len) else {
                    notes.push(format!(
                        "段 {}（{:#x}+{:#x}）读取失败，字符串扫描在该处截断",
                        seg.name,
                        seg.vaddr + offset,
                        len
                    ));
                    break;
                };
                scanner.feed(&data);
                offset += len as u64;
            }
            let (entries, oversized) = scanner.finish();
            oversized_runs += oversized;
            for e in entries {
                strings.push(StringWire {
                    address: hex16(e.address),
                    size: e.size,
                    encoding: e.encoding.as_str().to_string(),
                    text: e.text,
                });
            }
        }
        if oversized_runs > 0 {
            notes.push(format!(
                "有 {oversized_runs} 处超过 {MAX_RUN} 字节的连续可打印数据（无终止符）：判定为数据伪影，未计入字符串表"
            ));
        }
        strings.sort_by_key(|s| u64::from_str_radix(&s.address, 16).unwrap_or(0));

        // ── 基本块 / CFG（M5）──
        //
        // 逐函数建图。函数的 `end` 可能未知（只有入口）：此时**不猜边界**，
        // 只取该入口到下一个已知识别入口之前的指令，并把 truncated 置真。
        let cfg_by_function = build_cfgs(disasm, &functions, &mut notes);

        Self {
            functions,
            xrefs,
            xref_by_from,
            xref_by_to,
            strings,
            cfg_by_function,
            notes,
        }
    }

    /// 函数列表（按入口地址升序）。
    #[must_use]
    pub fn functions(&self) -> &[FunctionWire] {
        &self.functions
    }

    /// 函数总数。
    #[must_use]
    pub fn function_count(&self) -> usize {
        self.functions.len()
    }

    /// 基本块总数（全部函数的 CFG 之和）。
    ///
    /// 这是 `/api/analyze` 里 `basic_blocks` 的真实来源 ——
    /// M5 之前它诚实地报 0（CFG 还没实现），现在有真值了。
    #[must_use]
    pub fn basic_block_count(&self) -> usize {
        self.cfg_by_function.values().map(|c| c.block_count).sum()
    }

    /// 某个函数入口的 CFG。
    #[must_use]
    pub fn cfg_of(&self, entry: u64) -> Option<&CfgWire> {
        self.cfg_by_function.get(&entry)
    }

    /// 全部函数的 CFG（按入口地址升序）。
    pub fn cfgs(&self) -> impl Iterator<Item = &CfgWire> {
        self.cfg_by_function.values()
    }

    /// CFG 总数（有 CFG 的函数个数）。
    #[must_use]
    pub fn cfg_count(&self) -> usize {
        self.cfg_by_function.len()
    }

    /// 包含某地址的基本块所在的函数。
    ///
    /// 返回 `(函数入口, 块)`。用于 UI 从任意指令地址跳到它所属的块。
    #[must_use]
    pub fn block_containing(&self, addr: u64) -> Option<(u64, &BlockWire)> {
        let entry = parse_hex(self.function_containing(addr)?.start.as_str())?;
        let cfg = self.cfg_by_function.get(&entry)?;
        let block = cfg.blocks.iter().find(|b| {
            let s = parse_hex(&b.start);
            let e = parse_hex(&b.end);
            matches!((s, e), (Some(s), Some(e)) if addr >= s && addr < e)
        })?;
        Some((entry, block))
    }

    /// 包含某地址的函数。
    ///
    /// 边界已知的函数做范围判断；边界未知的只匹配入口本身 ——
    /// 不用"下一个函数的起点"当上界，那是猜。
    #[must_use]
    pub fn function_containing(&self, addr: u64) -> Option<&FunctionWire> {
        let pos = self
            .functions
            .partition_point(|f| parse_hex(&f.start).is_some_and(|s| s <= addr));
        if pos == 0 {
            return None;
        }
        let f = &self.functions[pos - 1];
        let start = parse_hex(&f.start)?;
        match f.end.as_deref().and_then(parse_hex) {
            Some(end) => (addr >= start && addr < end).then_some(f),
            None => (addr == start).then_some(f),
        }
    }

    /// xref 总数。
    #[must_use]
    pub fn xref_count(&self) -> usize {
        self.xrefs.len()
    }

    /// 从某地址发出的引用（按在指令流中出现的顺序）。
    #[must_use]
    pub fn xrefs_from(&self, addr: u64) -> Vec<&XrefWire> {
        self.xref_by_from
            .get(&addr)
            .map(|idxs| idxs.iter().map(|&i| &self.xrefs[i]).collect())
            .unwrap_or_default()
    }

    /// 指向某地址的引用。
    #[must_use]
    pub fn xrefs_to(&self, addr: u64) -> Vec<&XrefWire> {
        self.xref_by_to
            .get(&addr)
            .map(|idxs| idxs.iter().map(|&i| &self.xrefs[i]).collect())
            .unwrap_or_default()
    }

    /// 字符串列表（按地址升序）。
    #[must_use]
    pub fn strings(&self) -> &[StringWire] {
        &self.strings
    }

    /// 分析 notes（诚实降级说明，浮到 UI）。
    #[must_use]
    pub fn notes(&self) -> &[String] {
        &self.notes
    }
}

fn parse_hex(s: &str) -> Option<u64> {
    u64::from_str_radix(s, 16).ok()
}

/// 逐函数构建 CFG（M5）。
///
/// # 边界处理（这是本函数唯一需要判断的事情）
///
/// `FunctionWire::end` 可能是 `None` —— 只知道入口，不知道到哪结束。
/// 此时**不猜**边界，而是取从入口起、到**下一个已知识别入口**之前的指令。
///
/// 为什么这是安全的近似：下一个已知函数入口一定**不属于**本函数
/// （它是另一个函数的起点），所以切在那里不会把别的函数的指令并进来。
/// 它可能少取（本函数更长）—— 那就 `truncated` 置真如实说明。
/// 宁可少画几个块，不可多画一个假的。
///
/// 边界已知（`Some(end)`）时直接按区间切，不存在这个不确定性。
fn build_cfgs(
    disasm: &Disasm,
    functions: &[FunctionWire],
    notes: &mut Vec<String>,
) -> BTreeMap<u64, CfgWire> {
    let mut out = BTreeMap::new();
    if functions.is_empty() {
        return out;
    }

    // 已知识别入口（升序，`functions` 已按地址升序）——用于给未知边界兜底。
    let entries: Vec<u64> = functions
        .iter()
        .filter_map(|f| parse_hex(&f.start))
        .collect();

    let mut truncated_functions = 0usize;

    for f in functions {
        let Some(entry) = parse_hex(&f.start) else {
            continue;
        };
        let declared_end = f.end.as_deref().and_then(parse_hex);

        // 未知边界时的兜底上界：下一个更大的识别入口。
        // `partition_point` 找到第一个 > entry 的位置。
        let fallback_end = entries
            .partition_point(|&e| e <= entry)
            .checked_sub(0)
            .and_then(|p| entries.get(p).copied());

        let (upper, boundary_unknown) = match declared_end {
            Some(end) => (end, false),
            None => match fallback_end {
                Some(next) => (next, true),
                // 最后一个函数且边界未知：只能扫到它自己的指令用完为止。
                // `u64::MAX` 表示"不设上界"，由 AddrSpace 的区间决定实际范围。
                None => (u64::MAX, true),
            },
        };
        if boundary_unknown {
            truncated_functions += 1;
        }

        // 收集该范围内的指令。`disasm.index` 是地址→长度的有序索引，
        // 直接按区间取，不做全表扫描。
        let mut insns: Vec<bitflip_arch::DecodedInsn> = Vec::new();
        for (addr, len) in disasm.index.range(entry, upper) {
            let Some(bytes) = disasm.space.read(addr, usize::from(len)) else {
                continue;
            };
            if let Ok(insn) = disasm.decoder.decode_one(&bytes, addr) {
                insns.push(insn);
            }
        }
        if insns.is_empty() {
            continue;
        }

        let cfg = Cfg::build(&insns);
        out.insert(
            entry,
            CfgWire {
                entry: f.start.clone(),
                block_count: cfg.block_count(),
                edge_count: cfg.edge_count(),
                has_cycle: cfg.has_cycle(),
                truncated: cfg.truncated() || boundary_unknown,
                notes: cfg.notes().to_vec(),
                blocks: cfg
                    .blocks()
                    .map(|b| BlockWire {
                        start: hex16(b.start),
                        end: hex16(b.end),
                        last_insn: hex16(b.last_insn),
                        successors: b.successors.iter().copied().map(hex16).collect(),
                        predecessors: b.predecessors.iter().copied().map(hex16).collect(),
                        terminal: b.terminal,
                    })
                    .collect(),
            },
        );
    }

    if truncated_functions > 0 {
        notes.push(format!(
            "有 {truncated_functions} 个函数的边界未知，其 CFG 按“到下一个已知函数入口之前”构建\
             （可能少画块，不会多画）"
        ));
    }

    out
}

/// 桩的最大字节数。
///
/// 典型桩是 `jmp *disp32(%rip)`（6 字节）+ 若干 `nop` 对齐，实测都 <= 16 字节。
/// 上限刻意取小：宁可漏掉一个畸形桩，也不要把"一段以 jmp 开头的小代码"
/// 误判成桩（那会凭空造出一个函数，违反 §7）。
const MAX_THUNK_BYTES: u64 = 16;

/// 桩的判据：`jmp *disp(%rip)` 之后必须是**填充或另一个桩**，不能是真实代码体。
///
/// 实测布局（mingw 静态链接 PE）：每个桩恰好 8 字节 ——
/// `ff 25 <disp32>`（间接跳转，6 字节）+ `90 90`（2 字节 nop 对齐），
/// 然后**下一个桩紧接着开始**，中间没有空隙。
///
/// 所以不能要求"后面全是填充直到段尾/大段空白"：那样第一个桩后面的字节
/// 立刻就是下一个桩的 `ff 25`，检查必然失败（这正是最初 12 个桩一个都没认出来的原因）。
///
/// 正确判据是：**这段小窗口里只允许出现"填充"和"另一个桩的开头"**，
/// 出现任何别的指令字节就否决。这样既能认出紧密排列的桩，又不会把
/// `jmp` 开头的普通函数（后面接真实代码）误判成桩。
fn is_import_thunk_tail(space: &bitflip_analyze::AddrSpace, addr: u64, first_len: u8) -> bool {
    let rest_start = addr.saturating_add(u64::from(first_len));
    let window = MAX_THUNK_BYTES.saturating_sub(u64::from(first_len));
    let Some(tail) = space.read(rest_start, window as usize) else {
        // 读到段尾：桩贴着段尾结束也算合法
        return true;
    };

    let mut i = 0usize;
    while i < tail.len() {
        match tail[i] {
            0x90 => i += 1, // nop 填充
            0xCC => i += 1, // int3 填充
            0x66 | 0x0F => {
                // 多字节 nop（`66 66 ... 0F 1F /0`）
                if tail[i] == 0x66 {
                    i += 1;
                    continue;
                }
                if tail.get(i + 1) == Some(&0x1F) {
                    let modrm = tail.get(i + 2).copied().unwrap_or(0);
                    let extra = match (modrm >> 6) & 3 {
                        0 => 0,
                        1 => 1,
                        2 => 4,
                        _ => 0,
                    };
                    i += 3 + extra;
                    continue;
                }
                return false;
            }
            0xff => {
                // 下一个桩的开头：`ff 25 <disp32>`。只接受这一种形式；
                // `ff 15` 之类的间接 call、`ff e0` 的 jmp reg 都不算。
                if tail.get(i + 1) == Some(&0x25) {
                    // 这个桩的长度也要在合理范围内，否则就是长函数
                    let remaining = tail.len() - i;
                    if remaining < 6 {
                        return true; // 窗口到头了，视为合法
                    }
                    i += 6;
                    continue;
                }
                return false;
            }
            0x00 => {
                // 零填充结尾：后面必须全是零
                return tail[i..].iter().all(|&b| b == 0x00);
            }
            _ => return false,
        }
    }
    true
}

/// 流式字符串扫描状态机。
///
/// 分块喂字节（块大小 [`SCAN_CHUNK`]），跨块的可打印运行由内部状态衔接，
/// 因此**长字符串不会因分块被截断或重复计**。段结束时未终止的运行被丢弃
/// （真字符串有 NUL 终止符；悬空运行是代码/表数据的伪影）。
struct StringScanner {
    base: u64,
    opts: StringOptions,
    out: Vec<bitflip_analyze::StringEntry>,
    /// 进行中的 ASCII 运行（字节 + 起始地址）。
    ascii_run: Option<(Vec<u8>, u64)>,
    /// 进行中的 UTF-16LE 运行（低位字节 + 起始地址）。
    utf16_run: Option<(Vec<u8>, u64)>,
    /// 供 UTF-16 配对的"半对"低位字节（奇数位置悬空时跨块衔接）。
    utf16_pending_lo: Option<(u8, u64)>,
    oversized: usize,
}

impl StringScanner {
    fn new(base: u64, opts: &StringOptions) -> Self {
        Self {
            base,
            opts: StringOptions {
                min_length: opts.min_length,
                max_entries: opts.max_entries,
            },
            out: Vec::new(),
            ascii_run: None,
            utf16_run: None,
            utf16_pending_lo: None,
            oversized: 0,
        }
    }

    fn feed(&mut self, data: &[u8]) {
        // 已收集够数就不再扫描：上限存在的意义就是防止畸形输入撑爆内存
        if self.out.len() >= self.opts.max_entries {
            return;
        }
        for (i, &b) in data.iter().enumerate() {
            let addr = self.base + i as u64;
            // ── ASCII 状态机 ──
            if printable_local(b) {
                let run = self.ascii_run.get_or_insert_with(|| (Vec::new(), addr));
                run.0.push(b);
                if run.0.len() > MAX_RUN {
                    // 过长的未终止运行：数据伪影，丢弃重开
                    self.oversized += 1;
                    self.ascii_run = None;
                }
            } else if let Some((bytes, start)) = self.ascii_run.take() {
                if b == 0 && bytes.len() >= self.opts.min_length {
                    self.out.push(bitflip_analyze::StringEntry {
                        address: start,
                        size: bytes.len() as u64,
                        encoding: bitflip_analyze::StringEncoding::Ascii,
                        text: String::from_utf8_lossy(&bytes).into_owned(),
                    });
                }
            }
            // ── UTF-16LE 状态机（按绝对地址偶对齐配对）──
            if addr % 2 == 0 {
                self.utf16_pending_lo = Some((b, addr));
            } else if let Some((lo, run_addr)) = self.utf16_pending_lo.take() {
                // (lo, b) 构成一对，lo 在偶地址 run_addr
                if b == 0 && printable_local(lo) {
                    let run = self.utf16_run.get_or_insert_with(|| (Vec::new(), run_addr));
                    run.0.push(lo);
                    if run.0.len() > MAX_RUN {
                        self.oversized += 1;
                        self.utf16_run = None;
                    }
                } else if lo == 0 && b == 0 {
                    // NUL 终止对：收串
                    if let Some((bytes, start)) = self.utf16_run.take() {
                        if bytes.len() >= self.opts.min_length {
                            self.out.push(bitflip_analyze::StringEntry {
                                address: start,
                                size: (bytes.len() * 2) as u64,
                                encoding: bitflip_analyze::StringEncoding::Utf16Le,
                                text: String::from_utf8_lossy(&bytes).into_owned(),
                            });
                        }
                    }
                } else {
                    // 运行中断（无终止符）：丢弃
                    self.utf16_run = None;
                }
            }
        }
    }

    /// 结束扫描。段尾未终止的运行一律丢弃 —— 没有 NUL 终止符就不算字符串。
    fn finish(self) -> (Vec<bitflip_analyze::StringEntry>, usize) {
        (self.out, self.oversized)
    }
}

/// 与 `bitflip_analyze` 内部一致的可打印判定（那边是模块私有，故本地复制）。
/// 两处必须保持一致：判定不同会让"分块扫描"与"整段提取"给出不同结果。
fn printable_local(b: u8) -> bool {
    (0x20..0x7f).contains(&b) || b == b'\t' || b == b'\r' || b == b'\n'
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{DisasmScanOptions, OpenOptions, Session};
    use std::path::PathBuf;

    /// 构造一个带 .text（真实 x86-64 字节）与 .data（一个字符串）的最小 ELF64。
    fn elf_with_text(code: &[u8]) -> Vec<u8> {
        let names = b"\0.text\0.data\0.shstrtab\0";
        let text_off = 0x180usize;
        let msg = b"hello from data\0";
        let data_off = 0x200usize;
        let names_off = 0x240usize;
        let mut bytes = vec![0u8; 0x280];

        bytes[0..4].copy_from_slice(b"\x7fELF");
        bytes[4] = 2; // ELFCLASS64
        bytes[5] = 1; // LE
        bytes[16..18].copy_from_slice(&1u16.to_le_bytes()); // ET_REL
        bytes[18..20].copy_from_slice(&62u16.to_le_bytes()); // x86_64
        bytes[20..24].copy_from_slice(&1u32.to_le_bytes());

        let shoff = 0x80usize;
        bytes[40..48].copy_from_slice(&(shoff as u64).to_le_bytes());
        bytes[52..54].copy_from_slice(&64u16.to_le_bytes());
        bytes[58..60].copy_from_slice(&64u16.to_le_bytes());
        bytes[60..62].copy_from_slice(&4u16.to_le_bytes()); // shnum
        bytes[62..64].copy_from_slice(&3u16.to_le_bytes()); // shstrndx

        bytes[text_off..text_off + code.len()].copy_from_slice(code);
        bytes[data_off..data_off + msg.len()].copy_from_slice(msg);
        bytes[names_off..names_off + names.len()].copy_from_slice(names);

        // 节 1：.text（ALLOC|EXEC，sh_addr=0 → 合成地址）
        let s1 = shoff + 64;
        bytes[s1..s1 + 4].copy_from_slice(&1u32.to_le_bytes());
        bytes[s1 + 4..s1 + 8].copy_from_slice(&1u32.to_le_bytes());
        bytes[s1 + 8..s1 + 16].copy_from_slice(&0x6u64.to_le_bytes());
        bytes[s1 + 24..s1 + 32].copy_from_slice(&(text_off as u64).to_le_bytes());
        bytes[s1 + 32..s1 + 40].copy_from_slice(&(code.len() as u64).to_le_bytes());
        bytes[s1 + 48..s1 + 56].copy_from_slice(&16u64.to_le_bytes());
        // 节 2：.data（ALLOC|WRITE）
        let s2 = shoff + 128;
        bytes[s2..s2 + 4].copy_from_slice(&7u32.to_le_bytes()); // ".data"
        bytes[s2 + 4..s2 + 8].copy_from_slice(&1u32.to_le_bytes());
        bytes[s2 + 8..s2 + 16].copy_from_slice(&0x3u64.to_le_bytes());
        bytes[s2 + 24..s2 + 32].copy_from_slice(&(data_off as u64).to_le_bytes());
        bytes[s2 + 32..s2 + 40].copy_from_slice(&(msg.len() as u64).to_le_bytes());
        bytes[s2 + 48..s2 + 56].copy_from_slice(&1u64.to_le_bytes());
        // 节 3：.shstrtab
        let s3 = shoff + 192;
        bytes[s3..s3 + 4].copy_from_slice(&13u32.to_le_bytes()); // ".shstrtab"
        bytes[s3 + 4..s3 + 8].copy_from_slice(&3u32.to_le_bytes());
        bytes[s3 + 24..s3 + 32].copy_from_slice(&(names_off as u64).to_le_bytes());
        bytes[s3 + 32..s3 + 40].copy_from_slice(&(names.len() as u64).to_le_bytes());
        bytes[s3 + 48..s3 + 56].copy_from_slice(&1u64.to_le_bytes());
        bytes
    }

    fn open_temp(data: &[u8], tag: &str) -> (PathBuf, Session) {
        let mut p = std::env::temp_dir();
        p.push(format!(
            "bf-m3-{}-{}-{tag}.elf",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.subsec_nanos())
                .unwrap_or(0)
        ));
        std::fs::write(&p, data).expect("写临时文件");
        let s = Session::open(&p, OpenOptions::default()).expect("打开");
        (p, s)
    }

    /// `nop; call +0; nop; ret` —— call 目标指向紧随其后的字节。
    const CALL_CODE: [u8; 8] = [0x90, 0xE8, 0x00, 0x00, 0x00, 0x00, 0x90, 0xC3];

    fn build_for(code: &[u8], tag: &str) -> (PathBuf, TargetAnalysis) {
        let data = elf_with_text(code);
        let (path, session) = open_temp(&data, tag);
        let disasm = session
            .disassemble(DisasmScanOptions::default())
            .expect("反汇编");
        let object = session.object().expect("object").clone();
        let analysis = TargetAnalysis::build(&disasm, &object, &StringOptions::default());
        (path, analysis)
    }

    #[test]
    fn xrefs_and_strings_are_extracted() {
        let (path, analysis) = build_for(&CALL_CODE, "fx");
        assert!(
            analysis.xref_count() >= 1,
            "call 应产出 xref，实际 {}",
            analysis.xref_count()
        );
        assert!(
            analysis
                .strings()
                .iter()
                .any(|s| s.text.contains("hello from data")),
            ".data 里的字符串应被提取，实际 {:?}",
            analysis.strings()
        );
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn unnamed_functions_never_get_fake_names() {
        // 调用目标推断出来的函数没有名字：必须 named=false 且 name 为空。
        // 生成 sub_xxx 之类的占位名是 CLAUDE.md §7 明令禁止的。
        let (path, analysis) = build_for(&CALL_CODE, "unnamed");
        for f in analysis.functions() {
            if !f.named {
                assert!(f.name.is_empty(), "未命名函数不许有占位名：{}", f.name);
            }
        }
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn function_containing_respects_known_bounds_only() {
        // 直接构造 wire 列表验证查询语义：边界已知 → 范围命中；未知 → 只命中入口
        let mk = |start: u64, end: Option<u64>| FunctionWire {
            start: hex16(start),
            end: end.map(hex16),
            name: String::new(),
            named: false,
            source: "discovery".into(),
            source_label: "分析推断".into(),
            confidence: 40,
            size: end.map(|e| e - start),
        };
        let analysis = TargetAnalysis {
            functions: vec![mk(0x1000, Some(0x1040)), mk(0x2000, None)],
            xrefs: Vec::new(),
            xref_by_from: HashMap::new(),
            xref_by_to: HashMap::new(),
            strings: Vec::new(),
            // 本测试只关心 function_containing，不建 CFG。
            cfg_by_function: BTreeMap::new(),
            notes: Vec::new(),
        };
        assert!(analysis.function_containing(0x1000).is_some());
        assert!(analysis.function_containing(0x103f).is_some());
        assert!(analysis.function_containing(0x1040).is_none(), "上界不含");
        assert!(analysis.function_containing(0x2000).is_some());
        assert!(
            analysis.function_containing(0x2010).is_none(),
            "边界未知时不许用下一个函数起点当上界"
        );
    }

    #[test]
    fn xref_lookup_is_bidirectionally_consistent() {
        let (path, analysis) = build_for(&CALL_CODE, "bidi");
        // 对每条 xref，from/to 两侧查询都必须能找到它
        assert!(analysis.xref_count() >= 1, "夹具应至少有一条 xref");
        for x in analysis.xrefs.iter() {
            let from = u64::from_str_radix(&x.from, 16).unwrap();
            let to = u64::from_str_radix(&x.to, 16).unwrap();
            let out = analysis.xrefs_from(from);
            let into = analysis.xrefs_to(to);
            assert!(
                out.iter().any(|y| y.to == x.to && y.kind == x.kind),
                "from 侧查询找不到 {x:?}"
            );
            assert!(
                into.iter().any(|y| y.from == x.from && y.kind == x.kind),
                "to 侧查询找不到 {x:?}"
            );
        }
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn long_string_across_chunk_boundary_is_not_truncated() {
        // 状态机必须跨块衔接：一个正好跨越 4MiB 块边界的字符串要完整取出。
        // 填充必须用**不可打印**字节：用 'A' 填充会让整个块成为一个长的
        // 可打印运行，测不到"跨边界"这件事本身。
        let opts = StringOptions::default();
        let mut scanner = StringScanner::new(0x1000_0000, &opts);
        let mut chunk1 = vec![0x00u8; SCAN_CHUNK - 5];
        chunk1.extend_from_slice(b"START");
        scanner.feed(&chunk1);
        let mut chunk2 = b"END\0tail-data-here\0".to_vec();
        chunk2.extend_from_slice(&[0u8; 16]);
        scanner.feed(&chunk2);
        let (entries, _) = scanner.finish();
        let texts: Vec<&str> = entries.iter().map(|e| e.text.as_str()).collect();
        assert!(
            entries.iter().any(|e| e.text == "STARTEND"),
            "跨块字符串必须完整，实际 {texts:?}"
        );
        assert!(entries.iter().any(|e| e.text == "tail-data-here"));
    }

    #[test]
    fn unterminated_runs_are_dropped_not_reported() {
        // 没有 NUL 终止的可打印数据是伪影：不许进字符串表
        let opts = StringOptions::default();
        let mut scanner = StringScanner::new(0x2000_0000, &opts);
        scanner.feed(b"no-terminator-here");
        let (entries, _) = scanner.finish();
        assert!(entries.is_empty(), "未终止运行不许计入，实际 {entries:?}");
    }
}
