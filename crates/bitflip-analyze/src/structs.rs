//! 结构体字段布局的**只读推断**（阶段 2 第一片）。
//!
//! # 这是什么
//!
//! 从指令流里把形如 `[base + disp]` 的内存访问聚合成"**疑似结构体布局**"：某个基址寄存器上
//! 被访问到的每个 `offset` 视为一个字段，记下它的**访问宽度**与**读/写次数**，字段集合按
//! offset 排序，结构体**推断大小** = 最大 `offset + width`。
//!
//! # 边界（很重要）
//!
//! 这是**启发式证据，不是真实的 C 类型**：没有类型信息、没有数据流、不跨基本块跟踪指针来源，
//! 所以只能说"这台基址寄存器被当作某个对象用，看到这些偏移与宽度"，不能保证这些偏移真属于
//! 同一个结构体、也不能给出字段类型。UI/输出里必须如实标注为"疑似"，判断权留给用户。
//!
//! 刻意**不做**的：
//! - 带索引寄存器的访问 `[base + index*scale]` 是数组遍历，不是字段偏移，跳过。
//! - 负位移 `[base - 0x8]` 多为栈帧局部变量，不是结构体字段，跳过（单列计数）。
//! - 只有一个偏移的基址：那是"一个字段"，称不上结构体布局，跳过。

use std::collections::BTreeMap;

use bitflip_arch::{DecodedInsn, Operand, RegId};

/// 视为"结构体"所需的最少不同字段偏移数。
///
/// 两个偏移才可能是"对象的两个不同字段"；只有一个偏移时，无法把它和普通标量变量区分开，
/// 硬凑成"结构体"是编造。要求 ≥2。
const MIN_FIELDS: usize = 2;

/// 单个字段的访问统计。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StructField {
    /// 字段偏移（字节，相对基址）。
    pub offset: u64,
    /// 观测到的访问宽度（字节，升序去重；同一偏移可能有多种宽度，如既有 1 字节又有 8 字节读）。
    pub widths: Vec<u8>,
    /// 读访问次数。
    pub reads: usize,
    /// 写访问次数。
    pub writes: usize,
}

impl StructField {
    /// 访问总次数。
    #[must_use]
    pub fn access_count(&self) -> usize {
        self.reads + self.writes
    }
}

/// 一个疑似结构体：某个函数里、某个基址寄存器上的一组字段。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StructCandidate {
    /// 归属函数入口（已知函数上下文；`None` 仅作占位，正常推断结果都有值）。
    pub function: Option<u64>,
    /// 基址寄存器。
    pub base: RegId,
    /// 字段（按 offset 升序）。
    pub fields: Vec<StructField>,
    /// 推断大小 = 最大 `offset + width`。
    pub size: u64,
}

impl StructCandidate {
    /// 字段数。
    #[must_use]
    pub fn field_count(&self) -> usize {
        self.fields.len()
    }
    /// 访问总次数（所有字段）。
    #[must_use]
    pub fn access_count(&self) -> usize {
        self.fields.iter().map(StructField::access_count).sum()
    }
}

/// 推断结果。
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct StructReport {
    /// 疑似结构体（按基址寄存器升序；字段多的在前）。
    pub candidates: Vec<StructCandidate>,
    /// 降级/统计说明（中文）。
    pub notes: Vec<String>,
}

/// 从指令流推断结构体字段布局。
///
/// `functions` 是 `(入口, 结束)` 的函数区间列表（结束可能未知）。**必须**按函数分组：
/// 同一个寄存器编号在**不同函数**里是完全不同的变量——把全程序同号寄存器的访问混在一起，
/// 偏移会横跨整个文件，凑出一个荒唐的"巨型结构体"（实测 kernel32.dll 上曾出现 size≈1.1GB
/// 的假结构体）。因此候选是**per (函数, 基址)** 的。
///
/// 归属规则同 [`crate::consts::aggregate_string_refs`]：落在所有函数之外的访问不归给任何
/// 函数，也不参与结构体推断（不编造归属）。
///
/// 只读、可复现：同一输入必得同一输出。
#[must_use]
pub fn infer_struct_fields(
    insns: &[DecodedInsn],
    functions: &[(u64, Option<u64>)],
) -> StructReport {
    // (函数入口, base) -> offset -> 累积器
    let mut by_key: BTreeMap<(u64, u16), BTreeMap<u64, FieldAcc>> = BTreeMap::new();
    let mut indexed_skipped = 0usize;
    let mut negative_skipped = 0usize;
    let mut width_unknown_sites = 0usize;
    let mut unattributed = 0usize;

    for insn in insns {
        for op in &insn.operands {
            let Operand::Mem(m) = op else { continue };
            let Some(base) = m.base else { continue };
            // 数组遍历：有索引寄存器 → 不是字段偏移。
            if m.index.is_some() {
                indexed_skipped += 1;
                continue;
            }
            // 负位移：多为栈帧局部，不当结构体字段。
            if m.disp < 0 {
                negative_skipped += 1;
                continue;
            }
            let Some(func) = find_owner(functions, insn.addr) else {
                unattributed += 1;
                continue;
            };
            let offset = m.disp as u64;
            let acc = by_key
                .entry((func, base.0))
                .or_default()
                .entry(offset)
                .or_default();
            // `size == 0` = 解码层没给出访问宽度（如 AArch64 路径目前不填 size）。
            if m.size == 0 {
                width_unknown_sites += 1;
            } else if !acc.widths.contains(&m.size) {
                acc.widths.push(m.size);
            }
            if m.write {
                acc.writes += 1;
            } else {
                acc.reads += 1;
            }
        }
    }

    let mut candidates: Vec<StructCandidate> = Vec::new();
    let mut single_field_keys = 0usize;
    for ((func, base_id), offsets) in by_key {
        if offsets.len() < MIN_FIELDS {
            single_field_keys += 1;
            continue;
        }
        let mut fields: Vec<StructField> = Vec::with_capacity(offsets.len());
        let mut size = 0u64;
        for (offset, acc) in offsets {
            let mut widths = acc.widths;
            widths.sort_unstable();
            let max_w = widths.last().copied().unwrap_or(0);
            size = size.max(offset + u64::from(max_w));
            fields.push(StructField {
                offset,
                widths,
                reads: acc.reads,
                writes: acc.writes,
            });
        }
        candidates.push(StructCandidate {
            function: Some(func),
            base: RegId(base_id),
            fields,
            size,
        });
    }

    // 访问多的在前，其次按函数入口、再按基址（稳定、可复现）。
    candidates.sort_by(|a, b| {
        b.access_count()
            .cmp(&a.access_count())
            .then(a.function.unwrap_or(0).cmp(&b.function.unwrap_or(0)))
            .then(a.base.0.cmp(&b.base.0))
    });

    let mut notes = Vec::new();
    if candidates.is_empty() {
        notes.push(
            "没有可推断的结构体布局（需要同一函数内、同一基址寄存器上 ≥2 个不同偏移的访问；\
             单偏移、数组遍历、负位移都不算）"
                .to_string(),
        );
    } else {
        notes.push(format!(
            "疑似结构体 {} 个（启发式：按函数分组；非真实 C 类型，仅表示这些偏移在同一函数里\
             被当作同一对象的字段访问）",
            candidates.len()
        ));
        notes.push(
            "未排除栈帧/参数寄存器：`[rbp-..]`、`[rsp+..]`、AArch64 `[x29/.. sp]` 一类可能把局部\
             变量误当结构体字段，请结合反汇编判断"
                .to_string(),
        );
    }
    if indexed_skipped > 0 {
        notes.push(format!(
            "跳过 {indexed_skipped} 处带索引寄存器的访问（数组遍历，不是字段偏移）"
        ));
    }
    if negative_skipped > 0 {
        notes.push(format!(
            "跳过 {negative_skipped} 处负位移访问（多为栈帧局部变量）"
        ));
    }
    if single_field_keys > 0 {
        notes.push(format!(
            "跳过 {single_field_keys} 个只有单一偏移的 (函数,基址) 组合（称不上结构体布局）"
        ));
    }
    if unattributed > 0 {
        notes.push(format!(
            "{unattributed} 处访问落在所有已知函数之外，未参与推断（不编造归属）"
        ));
    }
    if width_unknown_sites > 0 {
        notes.push(format!(
            "{width_unknown_sites} 处访问未给出宽度（解码层未提供，如 AArch64 路径）：\
             这些字段的\"宽度\"与\"推断大小\"偏保守，别当成真实字段尺寸"
        ));
    }

    StructReport { candidates, notes }
}

/// 找包含 `addr` 的函数入口。区间为半开 `[entry, end)`；`end` 为 `None` 时只按"下一个函数"
/// 兜底（若无下一个，则视为直到无穷）。与 `consts::find_owner` 同义，这里内联一份避免跨模块耦合。
fn find_owner(functions: &[(u64, Option<u64>)], addr: u64) -> Option<u64> {
    // 先按已知 end 精确判。
    for &(entry, end) in functions {
        if addr < entry {
            continue;
        }
        if let Some(end) = end {
            if addr < end {
                return Some(entry);
            }
        } else {
            // 无 end：需要看是否存在更靠后的 entry 来界定上界。
            let next = functions
                .iter()
                .map(|&(e, _)| e)
                .filter(|&e| e > entry)
                .min();
            match next {
                Some(next) if addr >= next => continue,
                _ => return Some(entry),
            }
        }
    }
    None
}

/// 累积器：某偏移上的宽度集合与读写计数。
#[derive(Default)]
struct FieldAcc {
    widths: Vec<u8>,
    reads: usize,
    writes: usize,
}

#[cfg(test)]
mod tests {
    use super::*;
    use bitflip_arch::{Arch, Flow, MemRef, MnemonicId};

    fn mem_insn(addr: u64, base: u32, disp: i64, size: u8, write: bool) -> DecodedInsn {
        DecodedInsn {
            addr,
            len: 4,
            arch: Arch::X86_64,
            mnemonic: MnemonicId::UNKNOWN,
            flow: Flow::Fallthrough,
            target: None,
            condition: None,
            operands: vec![Operand::Mem(MemRef {
                base: Some(RegId(base as u16)),
                index: None,
                scale: 1,
                index_extend: None,
                disp,
                size,
                write,
            })],
            reads: Default::default(),
            writes: Default::default(),
            privileged: false,
        }
    }

    #[test]
    fn groups_fields_by_base_and_computes_size() {
        // base 1 上访问 [1+0x0](8B 读)、[1+0x8](8B 写)、[1+0x10](4B 读) → 3 字段，size=0x14。
        let insns = vec![
            mem_insn(0x1000, 1, 0x0, 8, false),
            mem_insn(0x1010, 1, 0x8, 8, true),
            mem_insn(0x1020, 1, 0x10, 4, false),
        ];
        let report = infer_struct_fields(&insns, &[(0x1000, None)]);
        assert_eq!(report.candidates.len(), 1);
        let c = &report.candidates[0];
        assert_eq!(c.base, RegId(1));
        assert_eq!(c.function, Some(0x1000));
        assert_eq!(c.fields.len(), 3);
        assert_eq!(c.fields[0].offset, 0);
        assert_eq!(c.fields[2].offset, 0x10);
        assert_eq!(c.size, 0x10 + 4, "size = 最大 offset + width");
        // 写统计正确。
        assert_eq!(c.fields[1].writes, 1);
        assert_eq!(c.fields[1].reads, 0);
    }

    #[test]
    fn single_field_base_is_not_a_struct() {
        let insns = vec![
            mem_insn(0x1000, 2, 0x0, 8, false),
            mem_insn(0x1010, 2, 0x0, 4, false), // 同偏移不同宽度仍是 1 个字段
        ];
        let report = infer_struct_fields(&insns, &[(0x1000, None)]);
        assert!(report.candidates.is_empty(), "单偏移不该成结构体");
        // 同一偏移两种宽度应合并为一个字段（这里没进报告，下面单独验）。
    }

    #[test]
    fn same_offset_multiple_widths_merge() {
        // base 3：offset 0 有 1B 和 4B 读，offset 4 有 8B 读 → 2 字段，宽度去重升序。
        let insns = vec![
            mem_insn(0x1000, 3, 0x0, 1, false),
            mem_insn(0x1004, 3, 0x0, 4, false),
            mem_insn(0x1008, 3, 0x4, 8, false),
        ];
        let report = infer_struct_fields(&insns, &[(0x1000, None)]);
        assert_eq!(report.candidates.len(), 1);
        let c = &report.candidates[0];
        assert_eq!(c.fields.len(), 2);
        assert_eq!(c.fields[0].widths, vec![1, 4], "同偏移宽度去重升序");
        assert_eq!(c.size, 4 + 8);
    }

    #[test]
    fn indexed_and_negative_are_skipped() {
        let mut indexed = mem_insn(0x1000, 4, 0x0, 8, false);
        if let Operand::Mem(m) = &mut indexed.operands[0] {
            m.index = Some(RegId(7));
            m.scale = 8;
        }
        let negative = mem_insn(0x1010, 4, -0x8, 8, false);
        let normal = mem_insn(0x1020, 4, 0x10, 8, false);
        let report = infer_struct_fields(&[indexed, negative, normal], &[(0x1000, None)]);
        // base 4 只剩 1 个有效偏移 → 不成结构体。
        assert!(report.candidates.is_empty());
        assert!(report.notes.iter().any(|n| n.contains("索引寄存器")));
        assert!(report.notes.iter().any(|n| n.contains("负位移")));
    }

    #[test]
    fn groups_are_per_function_not_global() {
        // 同一寄存器编号（base 9）在两个不同函数里各访问两个不同偏移。
        // 正确做法：分成两个 per-function 候选，而不是跨函数混成一个巨型结构体。
        let insns = vec![
            // 函数 A（0x1000）：offset 0、8
            mem_insn(0x1000, 9, 0x0, 8, false),
            mem_insn(0x1010, 9, 0x8, 8, false),
            // 函数 B（0x5000）：offset 0、0x10（远离 A 的偏移）
            mem_insn(0x5000, 9, 0x0, 8, false),
            mem_insn(0x5010, 9, 0x10, 8, false),
        ];
        let funcs = [(0x1000u64, Some(0x2000u64)), (0x5000u64, Some(0x6000u64))];
        let report = infer_struct_fields(&insns, &funcs);
        assert_eq!(report.candidates.len(), 2, "每个函数各一个候选");
        let fa = report
            .candidates
            .iter()
            .find(|c| c.function == Some(0x1000))
            .unwrap();
        let fb = report
            .candidates
            .iter()
            .find(|c| c.function == Some(0x5000))
            .unwrap();
        assert_eq!(fa.size, 8 + 8, "函数 A 的 size 不掺入函数 B 的 0x10");
        assert_eq!(fb.size, 0x10 + 8);
    }

    #[test]
    fn unattributed_accesses_are_dropped() {
        // 访问落在所有函数之外（0x9000 不在 [0x1000,0x2000)）→ 不参与推断。
        let insns = vec![
            mem_insn(0x9000, 5, 0x0, 8, false),
            mem_insn(0x9008, 5, 0x8, 8, false),
        ];
        let report = infer_struct_fields(&insns, &[(0x1000, Some(0x2000))]);
        assert!(report.candidates.is_empty());
        assert!(report.notes.iter().any(|n| n.contains("函数之外")));
    }

    #[test]
    fn ties_sorted_by_access_count() {
        let insns = vec![
            // base 10：3 字段各访问 1 次 = 3 次
            mem_insn(0x1000, 10, 0x0, 8, false),
            mem_insn(0x1008, 10, 0x8, 8, false),
            mem_insn(0x1010, 10, 0x10, 8, false),
            // base 5：2 字段各访问 2 次 = 4 次 → 访问更多，排前面
            mem_insn(0x1020, 5, 0x0, 4, false),
            mem_insn(0x1024, 5, 0x0, 4, false),
            mem_insn(0x1028, 5, 0x4, 4, false),
            mem_insn(0x102c, 5, 0x4, 4, false),
        ];
        let report = infer_struct_fields(&insns, &[(0x1000, None)]);
        assert_eq!(report.candidates.len(), 2);
        assert_eq!(report.candidates[0].base, RegId(5), "访问多的在前");
    }
}
