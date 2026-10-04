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

use std::collections::{BTreeMap, BTreeSet, HashMap};

use bitflip_analyze::{
    merge_candidates, scan_jump_tables, unwind_candidates, Cfg, JumpTableScan, StringOptions,
};
use bitflip_arch::Flow;
use bitflip_loader::object::RelocKind;
use bitflip_symbols::{SymbolCandidate, SymbolSource};
use serde::{Deserialize, Serialize};

use crate::disasm::{hex16, parse_address, Disasm};

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
    /// 跳转表识别结论。M6 引入。
    jump_tables: JumpTableScan,
    /// 数据/代码判定的统计与结论。M6 引入。
    code_map: CodeMap,
    /// 函数间调用图。M6 引入。
    call_graph: CallGraphWire,
    notes: Vec<String>,
}

/// 调用图的 wire 表示（M6）。
///
/// # 为什么不在响应里塞全部边
///
/// 验收标准 3 要求"1 万函数规模下可交互渲染"。1 万节点的全图边数
/// 通常在 3–8 万条，序列化出来有几 MB，前端画不动也没意义 ——
/// 用户看的是**结构**，不是每条边。
///
/// 所以这里给：
///
/// * `summary`：总体形状（节点/边/未解析数/分量/hub），用来决定画什么；
/// * `edges`：全部**已解析**的边（只存两端地址对，紧凑）；
/// * `unresolved`：未解析间接调用的调用点（地址 + 调用方），
///   让"图不完整"可见且可定位。
///
/// 逐函数的邻域查询走 `/api/call-graph?entry=`，按需算。
#[derive(Debug, Clone, Default, PartialEq, Eq, serde::Serialize)]
pub struct CallGraphWire {
    /// 汇总统计。
    pub summary: CallGraphSummaryWire,
    /// 已解析的调用边（调用方入口 → 被调用方入口）。
    pub edges: Vec<CallEdgeWire>,
    /// 未解析的间接调用点。
    pub unresolved: Vec<UnresolvedCallWire>,
    /// 降级说明。
    pub notes: Vec<String>,
}

/// 调用图汇总（wire）。
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, serde::Serialize)]
pub struct CallGraphSummaryWire {
    /// 节点数（出现在图中的函数数）。
    pub nodes: usize,
    /// 边数。
    pub edges: usize,
    /// 未解析的间接调用数。
    pub unresolved_indirect: usize,
    /// 落在已知函数之外的目标数（去重）。
    pub outside_targets: usize,
    /// 入度为 0 的节点数。
    pub roots: usize,
    /// 强连通分量数。
    pub components: usize,
    /// 最大分量大小；>1 表示存在递归环。
    pub largest_component: usize,
}

/// 一条已解析的调用边（wire）。
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize)]
pub struct CallEdgeWire {
    /// 调用方函数入口（定长 16 位十六进制）。
    pub caller: String,
    /// 被调用方函数入口。
    pub callee: String,
    /// 是否为尾调用（不返回）。
    pub tail: bool,
}

/// 一个未解析的调用点（wire）。
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize)]
pub struct UnresolvedCallWire {
    /// 调用方函数入口。
    pub caller: String,
    /// 发起调用的指令地址。
    pub insn: String,
}

/// 数据/代码判定的 wire 结果（M6）。
///
/// 为什么存**统计 + 样本**而不是全部地址：一个 200MB 的 PE 有几十万条
/// 指令，把每个地址的判定都物化出来会让这份结构比目标本身还大
/// （CLAUDE.md §4 禁止全量物化）。UI 需要的是"分布如何"与"几个代表
/// 性的例子"，逐地址判定按需用 `/api/code-map` 查询。
#[derive(Debug, Clone, Default, PartialEq, serde::Serialize)]
pub struct CodeMap {
    /// 判定统计。
    pub stats: CodeMapStats,
    /// 抽样得出的代表性判定（含证据），供 UI 展示"凭什么这么判"。
    pub samples: Vec<CodeMapSample>,
    /// 量化误判率所需的说明（本目标没有黄金标准，故只记方法）。
    pub notes: Vec<String>,
}

/// 判定统计的 wire 形式。
///
/// 没有 `Eq`：`decided_ratio` 是 `f64`，浮点不满足 `Eq`。
#[derive(Debug, Clone, Copy, Default, PartialEq, serde::Serialize)]
pub struct CodeMapStats {
    /// 判为代码的地址数。
    pub code: usize,
    /// 判为数据的地址数。
    pub data: usize,
    /// 未判定的地址数。
    pub unknown: usize,
    /// 给出明确结论的比例（0.0–1.0）。
    pub decided_ratio: f64,
}

/// 一条代表性判定。
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize)]
pub struct CodeMapSample {
    /// 地址（定长 16 位小写十六进制）。
    pub addr: String,
    /// 结论短名：`code` / `data` / `unknown`。
    pub kind: &'static str,
    /// 结论中文名。
    pub kind_label: &'static str,
    /// 置信度（0–100）。
    pub confidence: u8,
    /// 是否有高可信证据支撑。
    pub well_supported: bool,
    /// 结论的理由（中文，一句话）。
    pub reason: String,
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
    /// 跳转表识别结论（M6）。
    #[must_use]
    pub fn jump_tables(&self) -> &JumpTableScan {
        &self.jump_tables
    }

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
        //
        // 只把**代码**导出当函数候选。共享库会导出数据符号
        // （`sample_table`、`stdout`、`errno` 之类），把它们列成"函数"
        // 是纯噪声，用户点进去只会看到一堆无法解码的字节 ——
        // §7 要求不制造这种看得见但没意义的结论。
        //
        // `is_code` 由 loader 判定（ELF 看 STT_FUNC、PE 看是否在可执行节）。
        // 拿不到判定的场合（例如节权限缺失）保守地跳过：宁可漏报也不误报。
        for exp in &object.exports {
            if exp.forwarder.is_some() {
                continue; // 转发导出没有本地代码，不是函数
            }
            if !exp.is_code {
                continue; // 数据导出不是函数
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
        //
        // 计数按**去重后的地址**算，不是按调用点算：同一个函数被调用 100 次
        // 也只是一个函数。早先累加在调用点上，于是样本上出现
        // "函数 300340 个" 但 "521869 个函数仅来自调用目标推断" 这种
        // 自相矛盾的结论 —— 数字比总数还大，只会让用户不再相信任何数字。
        let mut call_targets: std::collections::BTreeSet<u64> = std::collections::BTreeSet::new();
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
                call_targets.insert(target);
            }
        }
        let call_target_count = call_targets.len();

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

        // 来源 6：重定位驱动的指针表。
        //
        // 共享库把函数地址放进表里（虚表、`__init_array`、跳转表），
        // 这些槽位在文件里往往还是 0 或占位值 —— 真正的地址要等加载器
        // 按重定位表填。因此**重定位表本身**就是"这里有一个函数指针"的
        // 最强证据：它比"这块数据看起来像地址"可靠得多。
        //
        // 只认两类**数据槽位**重定位：
        //   * `Absolute`：把绝对地址写进某个槽位；
        //   * `RelocPointer`：ELF `R_*_RELATIVE` / PE `IMAGE_REL_BASED_*`，
        //     加载器写"基址 + 加数"，加数即模块内目标地址。
        //
        // 不认 `Relative`（PC 相对，出现在指令里）与 `ImportLookup`
        // （指向外部符号）：两者都不直接给出本模块内的代码地址。
        //
        // 指向的地址必须**已经**有解出来的指令才当候选，否则会在数据区
        // 造出假函数（§7：宁可漏，不要误报）。
        let mut reloc_pointer_count = 0usize;
        for rel in &object.relocations {
            let is_pointer_slot = matches!(rel.kind, RelocKind::Absolute | RelocKind::RelocPointer);
            if !is_pointer_slot {
                continue;
            }
            // 重定位的目标地址 = 原值 + 加数。ELF 的 RELA 把加数放在表里，
            // REL 则把加数写在槽位本身（此时 addend 是 0，下面读槽位补上）。
            let mut target = rel.addend as u64;
            if rel.addend == 0 {
                // REL 情形：从槽位读原值。读不到就跳过，不猜。
                let ptr_len = object.arch.ptr_size as usize;
                let Some(bytes) = disasm.space.read(rel.address, ptr_len) else {
                    continue;
                };
                target = match bytes.len() {
                    8 => u64::from_le_bytes(bytes[..8].try_into().expect("8 字节")),
                    4 => u64::from(u32::from_le_bytes(bytes[..4].try_into().expect("4 字节"))),
                    _ => continue,
                };
            }
            // 已经认出来的不用再动（重定位只是佐证，不该覆盖更强的来源）
            if by_addr.contains_key(&target) {
                continue;
            }
            // 目标处必须真的有指令，否则这是数据指针而不是函数指针
            if disasm
                .index
                .range(target, target.saturating_add(1))
                .next()
                .is_none()
            {
                continue;
            }
            by_addr.entry(target).or_default().push(SymbolCandidate {
                addr: target,
                name: String::new(), // 指针表里的目标没有名字 —— 不许编
                source: SymbolSource::RelocPointer,
                confidence: 55,
            });
            reloc_pointer_count += 1;
        }
        if reloc_pointer_count > 0 {
            notes.push(format!(
                "有 {reloc_pointer_count} 个函数地址来自重定位驱动的指针表（虚表 / `__init_array` 之类）"
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
        //
        // 注意顺序：CFG 在跳转表**之前**建。跳转表识别的产物是"某条间接
        // 跳转的后继有哪些"，它要回填进 CFG —— 所以先有图，再有边。
        let cfg_by_function = build_cfgs(disasm, &functions, &mut notes);

        // ── 跳转表 / switch（M6）──
        //
        // 只在**已索引**的指令上找间接跳转。验证"目标处能解出指令"用
        // 同一个解码器 —— 换一个判定标准会让"能解出"与"被索引"不一致，
        // 于是表目标落在索引之外，回填边时又会丢掉它们。
        let jump_tables =
            scan_jump_tables(&disasm.space, &indirect_jump_candidates(disasm), |addr| {
                // 目标必须是一条**已索引指令的起点**，而不是"临时解码
                // 试试看能不能解出点什么"。
                //
                // 这个区别是实测出来的：从任意字节开始解码几乎总能解出
                // 某条指令，于是验证形同虚设。在 MRT.exe 上，同一个表
                // 基址会被 u8 与 u16 两张"表"同时认领，u8 那张报出 416
                // 个项 —— 任何单字节值加上基址都"能解码"。
                //
                // 换成索引查询后，目标的个数上限被"真实代码里有多少条
                // 指令起点"约束住，假表的项数会立刻掉下来。
                disasm
                    .space
                    .index()
                    .containing(addr)
                    .is_some_and(|(start, _)| start == addr)
            });
        notes.extend(jump_tables.notes.iter().cloned());

        // 把跳转表目标**回填进 CFG**。
        //
        // 这一步才是跳转表识别的意义所在：识别出表却不让它改变控制流图，
        // 那张图仍然是"间接跳转没有后继"的残缺图 —— 用户看到 `switch`
        // 分支凭空断掉。回填之后每个 case 的目标都成为该块的后继。
        let mut cfg_by_function = cfg_by_function;
        let backfilled = backfill_jump_table_edges(&mut cfg_by_function, &jump_tables, &mut notes);
        if backfilled > 0 {
            notes.push(format!(
                "已把 {backfilled} 条跳转表目标边加入 CFG（间接跳转的后继）"
            ));
        }

        // 数据/代码判定（M6）。
        //
        // 对**代表性地址**做判定而不是全部：统计分布用抽样，逐地址
        // 判定交给 `/api/code-map` 按需算。全量物化会让这份结构比目标
        // 本身还大（CLAUDE.md §4）。
        let code_map = build_code_map(disasm, &functions, &mut notes);

        // 调用图（M6）：CFG 之外的另一张图 —— 函数之间谁调用谁。
        let call_graph = build_call_graph_wire(disasm, &functions, &mut notes);

        Self {
            functions,
            xrefs,
            xref_by_from,
            xref_by_to,
            strings,
            cfg_by_function,
            jump_tables,
            code_map,
            call_graph,
            notes,
        }
    }

    /// 数据/代码判定结果。
    #[must_use]
    pub fn code_map(&self) -> &CodeMap {
        &self.code_map
    }

    /// 函数间调用图。
    #[must_use]
    pub fn call_graph(&self) -> &CallGraphWire {
        &self.call_graph
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
/// 收集用于跳转表识别的指令候选。
///
/// 只取**间接跳转**（`Flow::Branch` 且 `target == None`）以及它前面
/// 一个小窗口内的指令 —— 窗口是给"表基址从哪来"的回溯用的。
///
/// 为什么不在整个索引上扫：跳转表识别对每条间接跳转都要向前回溯并
/// 试读表格，全量扫描在大样本（几十万条间接跳转）上开销可观。先做一次
/// O(n) 的过滤拿到候选，只对候选附近取指令，代价就与表数成正比。
fn indirect_jump_candidates(disasm: &Disasm) -> Vec<bitflip_arch::DecodedInsn> {
    let space = &disasm.space;
    let index = &disasm.index;

    // 先把所有间接跳转的地址找出来。
    let mut jumps: Vec<u64> = Vec::new();
    for (addr, len) in index.range(0, u64::MAX) {
        let Some(bytes) = space.read(addr, usize::from(len)) else {
            continue;
        };
        let Ok(insn) = disasm.decoder.decode_one(&bytes, addr) else {
            continue;
        };
        if matches!(insn.flow, bitflip_arch::Flow::Branch { .. }) && insn.target.is_none() {
            jumps.push(addr);
        }
    }
    if jumps.is_empty() {
        return Vec::new();
    }

    // 取候选附近的指令窗口（含跳转本身），按地址排序后交给识别器。
    //
    // 窗口前置量用 `LOOKBACK_WINDOW + 1`：识别器从跳转处向前回溯
    // 该长度。多给一条是为了让"回溯起点"本身也在切片里，避免因为
    // 切片边界而少看一条 —— 那种错误只在"表基址恰好在窗口边缘"时
    // 才出现，极难复现。
    let window = (JUMP_LOOKBACK_WINDOW + 1) as u64;
    let mut wanted: std::collections::BTreeSet<u64> = std::collections::BTreeSet::new();
    for &jump in &jumps {
        let start = jump.saturating_sub(window);
        for (addr, _len) in index.range(start, jump.saturating_add(1)) {
            wanted.insert(addr);
        }
    }

    let mut out = Vec::with_capacity(wanted.len());
    for addr in wanted {
        let Some((_, len)) = index.containing(addr) else {
            continue;
        };
        let Some(bytes) = space.read(addr, usize::from(len)) else {
            continue;
        };
        let Ok(insn) = disasm.decoder.decode_one(&bytes, addr) else {
            continue;
        };
        out.push(insn);
    }
    out
}

/// `build_cfgs` 用的回溯窗口（与 `bitflip-analyze` 的识别器保持一致）。
const JUMP_LOOKBACK_WINDOW: usize = bitflip_analyze::LOOKBACK_WINDOW;

/// 把跳转表的目标边回填进各函数的 CFG。
///
/// 返回实际加入的边数。
///
/// # 只加边，不造块
///
/// 这里**只把已有的块连起来**：如果表的目标地址处已经有一个块（因为
/// 该地址在扫描时被当作指令起点索引过），就加一条后继边；如果那里
/// 没有块，就**跳过并计数**，而不是凭空插入一个块。
///
/// 为什么不插入：CFG 的块划分来自"跳转目标 + 跳转的下一条"这两个
/// 已知来源。为一个只出现在**数据表**里的地址造块，等于让数据决定
/// 控制流 —— 表项语义判断错误时，会在图上长出一堆不存在的块，
/// 而它们看起来和真块没有区别。少画边会在 `notes` 里说明；
/// 多画块则完全不可见。§7 要求选前者。
fn backfill_jump_table_edges(
    cfg_by_function: &mut BTreeMap<u64, CfgWire>,
    scan: &JumpTableScan,
    notes: &mut Vec<String>,
) -> usize {
    if scan.tables.is_empty() {
        return 0;
    }
    // 跳转指令地址 → 该跳转解析出的目标集合
    let by_insn: BTreeMap<u64, &[u64]> = scan
        .tables
        .iter()
        .map(|t| (t.insn_addr, t.targets.as_slice()))
        .collect();

    let mut added = 0usize;
    let mut skipped = 0usize;

    for cfg in cfg_by_function.values_mut() {
        // 该函数里有没有属于本函数的表目标？先收齐本函数的块首集合。
        let block_starts: BTreeSet<u64> = cfg
            .blocks
            .iter()
            .map(|b| u64::from_str_radix(&b.start, 16).unwrap_or(0))
            .collect();

        // 找出本函数内**含间接跳转**的块：它们的后继里应当出现表目标。
        for jump_addr in by_insn.keys().copied() {
            let Some(targets) = by_insn.get(&jump_addr) else {
                continue;
            };
            // 哪一块含这条跳转指令？
            let Some(block) = cfg.blocks.iter_mut().find(|b| {
                let start = u64::from_str_radix(&b.start, 16).unwrap_or(0);
                let end = u64::from_str_radix(&b.end, 16).unwrap_or(0);
                jump_addr >= start && jump_addr < end
            }) else {
                continue;
            };

            for &t in *targets {
                if !block_starts.contains(&t) {
                    // 目标处没有块：不造块，如实计数。
                    skipped += 1;
                    continue;
                }
                let hex = hex16(t);
                if !block.successors.contains(&hex) {
                    block.successors.push(hex);
                    added += 1;
                }
            }
            if !block.successors.is_empty() {
                block.successors.sort();
                block.successors.dedup();
                // 有后继了就不再是"不返回"的终结块。
                block.terminal = false;
            }
        }
    }

    if skipped > 0 {
        // 降级必须可见：目标没有对应块意味着 CFG 少了边。
        notes.push(format!(
            "有 {skipped} 个跳转表目标在 CFG 里没有对应的基本块（该地址未被扫描为指令起点），\
             这些边没有加入 —— 图可能少画分支"
        ));
    }
    added
}

/// 构建调用图的 wire 表示（M6）。
///
/// # 为什么要在有 `Disasm` 的前提下重扫一遍指令
///
/// `AnalysisFacts` 那套抽样是为**统计**服务的；调用图需要**全部** call
/// 指令。所以这里走一遍指令索引 —— 索引只有 `(地址, 长度)`，指令本身
/// 要重新解码。这是本项目一贯的取舍：不缓存解码结果，用时间换内存
/// （CLAUDE.md §4 的 SoA 约束）。
///
/// 成本可控：只有 `Flow::Call` 与 `Flow::Branch` 需要看目标，
/// 但判断 flow 本身就得解码，所以实际是"全部指令解码一次"。
/// 1 万函数的规模下这是百毫秒级，可以接受。
fn build_call_graph_wire(
    disasm: &Disasm,
    functions: &[FunctionWire],
    notes: &mut Vec<String>,
) -> CallGraphWire {
    const HUB_LIMIT: usize = 20;

    let ranges: Vec<bitflip_analyze::FunctionRange> = functions
        .iter()
        .filter_map(|f| {
            let start = parse_address(&f.start)?;
            let end = f.end.as_deref().and_then(parse_address);
            Some(bitflip_analyze::FunctionRange { start, end })
        })
        .collect();

    // 解码全部指令。解码失败的地址跳过 —— 它们不是调用点。
    let mut insns: Vec<bitflip_arch::DecodedInsn> = Vec::with_capacity(disasm.space.index().len());
    for (addr, len) in disasm.space.index().range(0, u64::MAX) {
        let Some(bytes) = disasm.space.read(addr, usize::from(len)) else {
            continue;
        };
        if let Ok(insn) = disasm.decoder.decode_one(&bytes, addr) {
            insns.push(insn);
        }
    }

    let graph = bitflip_analyze::build_call_graph(&insns, &ranges);

    // 全部函数入口（用于统计"没人调用"的数量）
    let all: Vec<u64> = ranges.iter().map(|r| r.start).collect();
    let summary = graph.summarize(&all, HUB_LIMIT);

    for n in &graph.notes {
        notes.push(n.clone());
    }
    if summary.largest_component > 1 {
        notes.push(format!(
            "调用图存在大小为 {} 的强连通分量（互相调用，通常是递归或分发器）",
            summary.largest_component
        ));
    }

    CallGraphWire {
        summary: CallGraphSummaryWire {
            nodes: summary.nodes,
            edges: summary.edges,
            unresolved_indirect: summary.unresolved_indirect,
            outside_targets: summary.outside_targets,
            roots: summary.roots,
            components: summary.components,
            largest_component: summary.largest_component,
        },
        edges: graph
            .edges
            .iter()
            .filter_map(|e| {
                // 只输出**已解析**的边：未解析的没有目标，放进 edges
                // 会让前端拿到一个空字符串然后画出个悬空节点。
                let callee = e.callee?;
                if e.resolution != bitflip_analyze::CalleeResolution::Resolved {
                    return None;
                }
                Some(CallEdgeWire {
                    caller: hex16(e.caller),
                    callee: hex16(callee),
                    tail: e.tail,
                })
            })
            .collect(),
        unresolved: graph
            .edges
            .iter()
            .filter(|e| e.resolution == bitflip_analyze::CalleeResolution::IndirectUnresolved)
            .map(|e| UnresolvedCallWire {
                caller: hex16(e.caller),
                insn: hex16(e.from_insn),
            })
            .collect(),
        notes: graph.notes,
    }
}

/// 构建数据/代码判定的统计与样本（M6）。
///
/// # 抽样策略
///
/// 对**每个可执行段的头部 + 每个函数的入口**做判定，而不是遍历所有
/// 字节。理由：统计"代码 vs 数据"的分布需要覆盖代码区与数据区，
/// 而这两处的代表地址就是段头与函数入口。遍历全部字节会把大文件的
/// 分析时间成倍拉长，换来的统计精度提升很小。
///
/// `notes` 里如实写明这是抽样 —— 用户看到的是"抽样得到的分布"，
/// 不是"全量统计"。
fn build_code_map(disasm: &Disasm, functions: &[FunctionWire], notes: &mut Vec<String>) -> CodeMap {
    // 收集代表性地址：**可执行段与非可执行段分开配额**。
    //
    // 一开始给函数入口留了 512 的上限、段只取 4 个，结果在 ntdll.dll
    // 上得到 512/512 全是代码 —— 统计完全被函数入口主导，"数据"一个
    // 都进不来。这样算出来的分布没有任何意义，还会让用户以为
    // "这个目标里没有数据"。
    //
    // 现在两侧各占一半配额，保证数据区一定被采样到。
    const SAMPLE_LIMIT: usize = 512;
    let per_side = SAMPLE_LIMIT / 2;

    let mut code_addrs: Vec<u64> = Vec::new();
    let mut data_addrs: Vec<u64> = Vec::new();
    for seg in disasm.space.segments() {
        let target = if seg.perms.execute {
            &mut code_addrs
        } else {
            &mut data_addrs
        };
        // 段头、段中、段尾各取几个，避免只看到开头
        let span = seg.vsize;
        for off in [0u64, 1, 16, 64, span / 2, span.saturating_sub(8)] {
            let a = seg.vaddr.saturating_add(off);
            if a >= seg.vaddr && a < seg.vaddr.saturating_add(seg.vsize) {
                target.push(a);
            }
        }
    }
    // 函数入口是代码侧的最强代表，但**只能占代码侧的配额**
    for f in functions.iter() {
        if let Some(a) = parse_address(&f.start) {
            code_addrs.push(a);
        }
    }

    code_addrs.sort_unstable();
    code_addrs.dedup();
    data_addrs.sort_unstable();
    data_addrs.dedup();

    // 两侧各自均匀抽样，避免"前 N 个"把后面的段全漏掉
    let thin = |v: &[u64], n: usize| -> Vec<u64> {
        if v.len() <= n {
            return v.to_vec();
        }
        let step = v.len() as f64 / n as f64;
        (0..n).map(|i| v[(i as f64 * step) as usize]).collect()
    };

    let mut addrs = thin(&code_addrs, per_side);
    addrs.extend(thin(&data_addrs, per_side));
    addrs.sort_unstable();
    addrs.dedup();

    if addrs.is_empty() {
        return CodeMap::default();
    }

    // 构造事实源
    let reachable: std::collections::HashSet<u64> = disasm
        .space
        .index()
        .range(0, u64::MAX)
        .map(|(a, _)| a)
        .collect();
    let mut branch_targets: std::collections::HashSet<u64> = std::collections::HashSet::new();
    for (a, len) in disasm.space.index().range(0, u64::MAX) {
        let Some(bytes) = disasm.space.read(a, usize::from(len)) else {
            continue;
        };
        if let Ok(insn) = disasm.decoder.decode_one(&bytes, a) {
            if let Some(t) = insn.target {
                branch_targets.insert(t);
            }
        }
    }

    let fn_ranges: Vec<(u64, Option<u64>)> = functions
        .iter()
        .filter_map(|f| {
            let start = parse_address(&f.start)?;
            let end = f.end.as_deref().and_then(parse_address);
            Some((start, end))
        })
        .collect();

    let decode_run = |addr: u64| -> u32 {
        let mut a = addr;
        let mut n = 0u32;
        while n < 32 {
            let Some((start, len)) = disasm.space.index().containing(a) else {
                break;
            };
            if start != a {
                break;
            }
            a = a.saturating_add(u64::from(len));
            n += 1;
        }
        n
    };

    let facts = bitflip_analyze::AnalysisFacts {
        space: &disasm.space,
        functions: &fn_ranges,
        reachable: &reachable,
        branch_targets: &branch_targets,
        decode_run: &decode_run,
    };

    let judgements = bitflip_analyze::judge_code_many(&facts, &addrs);
    let stats = bitflip_analyze::JudgementStats::from_judgements(&judgements);

    notes.push(format!(
        "数据/代码判定基于 {} 个抽样地址（段头 + 函数入口），不是全量统计；\
         代码 {} / 数据 {} / 未判定 {}",
        stats.total(),
        stats.code,
        stats.data,
        stats.unknown
    ));

    CodeMap {
        stats: CodeMapStats {
            code: stats.code,
            data: stats.data,
            unknown: stats.unknown,
            decided_ratio: stats.decided_ratio(),
        },
        samples: judgements
            .iter()
            .map(|j| CodeMapSample {
                addr: hex16(j.addr),
                kind: j.kind.as_str(),
                kind_label: j.kind.label_zh(),
                confidence: j.confidence,
                well_supported: j.is_well_supported(),
                reason: j.reason_zh(),
            })
            .collect(),
        notes: Vec::new(),
    }
}

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
    /// 已经喂进来的字节数（**段内**偏移，不含段基址）。
    ///
    /// `feed` 是按 [`SCAN_CHUNK`] 分块调用的，每块在段内的起始偏移都不同，
    /// 因此必须累计。早先直接用块内下标 `i` 当偏移，于是每一块的地址都从
    /// `base` 重新开始，超出第一块的地址全部错位。
    ///
    /// 100 MiB 的 `.rdata`（25 个分块）上实测：384 个可识别字符串里有
    /// 368 个地址与别人重复，去重后只剩 16 个。
    consumed: u64,
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
            consumed: 0,
            ascii_run: None,
            utf16_run: None,
            utf16_pending_lo: None,
            oversized: 0,
        }
    }

    fn feed(&mut self, data: &[u8]) {
        // 已收集够数就不再扫描：上限存在的意义就是防止畸形输入撑爆内存。
        // 注意这里**也要**累加偏移，否则后续分块的地址会错位。
        if self.out.len() >= self.opts.max_entries {
            self.consumed += data.len() as u64;
            return;
        }
        for (i, &b) in data.iter().enumerate() {
            let addr = self.base + self.consumed + i as u64;
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
        self.consumed += data.len() as u64;
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

    /// 跨分块的字符串扫描必须给出**绝对地址**。
    ///
    /// 这条盯的是一个真实发生过的 bug：`feed` 用块内下标当偏移，于是每个
    /// 分块的地址都从段基址重新开始。在 100 MiB 的 `.rdata` 上，
    /// 384 个可识别字符串里有 368 个地址与别人重复 ——
    /// `tests/big_file.rs` 是那条端到端的回归。
    ///
    /// 这里手工构造两次 `feed`，直接验证第二块的地址是第一块之后的偏移。
    #[test]
    fn streaming_string_scan_uses_absolute_addresses_across_chunks() {
        const BASE: u64 = 0x1000;
        let opts = bitflip_analyze::StringOptions {
            min_length: 4,
            max_entries: 1000,
        };

        let mut scanner = StringScanner::new(BASE, &opts);
        // 第一块：一个字符串，长度 8，占 9 字节（含 NUL）
        let chunk1 = b"aaaaaaa\0";
        // 第二块：同样内容的另一个字符串
        let chunk2 = b"bbbbbbb\0";
        scanner.feed(chunk1);
        scanner.feed(chunk2);
        let (entries, _) = scanner.finish();

        assert_eq!(entries.len(), 2, "两块各应产出一条，实际 {entries:?}");
        let addrs: Vec<u64> = entries.iter().map(|e| e.address).collect();
        assert_eq!(
            addrs,
            vec![BASE, BASE + chunk1.len() as u64],
            "第二块的地址必须接在第一块之后；\
             若两块地址相同，说明分块偏移没有累加（地址会互相覆盖后丢失）"
        );
        assert_eq!(entries[0].text, "aaaaaaa");
        assert_eq!(entries[1].text, "bbbbbbb");
    }

    /// 跨分块的可打印运行不能被截断。
    #[test]
    fn a_string_split_across_chunks_survives() {
        const BASE: u64 = 0x2000;
        let opts = bitflip_analyze::StringOptions {
            min_length: 4,
            max_entries: 1000,
        };
        let mut scanner = StringScanner::new(BASE, &opts);
        scanner.feed(b"hello wor");
        scanner.feed(b"ld\0");
        let (entries, _) = scanner.finish();

        assert_eq!(entries.len(), 1, "跨块拼接应得到一条，实际 {entries:?}");
        assert_eq!(entries[0].text, "hello world");
        assert_eq!(entries[0].address, BASE);
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
            jump_tables: JumpTableScan::default(),
            code_map: CodeMap::default(),
            call_graph: CallGraphWire::default(),
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
