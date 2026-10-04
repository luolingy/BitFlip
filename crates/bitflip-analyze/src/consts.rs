//! 常量与结构体初步推断（M6）。
//!
//! # 这个模块能做什么，不能做什么
//!
//! 这一项最容易变成"算命"：从几条指令里推断出"这是一个 `struct
//! FILE`，字段 0x18 是 fd"—— 那不是分析，是编故事。所以这里只做
//! **有证据支撑、且可以被用户核对** 的三件事：
//!
//! 1. **字符串引用聚合**（[`StringUsage`]）：哪个函数引用了哪条
//!    字符串。证据是 xref（`lea rcx, [rip+...]` 这类），可以直接
//!    跳过去看。这一项几乎不会错，因为引用的目标地址是指令里写死的。
//! 2. **内存访问步长**（[`AccessStride`]）：同一个基址寄存器上，
//!    相邻位移的差。`mov eax,[rbx+0x18]` / `mov ecx,[rbx+0x20]` 相差 8，
//!    说明在按 8 字节步长走一个数组。这是**步长**，不是"字段类型"。
//! 3. **立即数常见值**（[`ImmediateProfile`]）：出现频率高的立即数。
//!    用途是识别魔数/标志位，而不是宣称它是枚举。
//!
//! # 明确不做的
//!
//! * **不推断字段类型**。看到 `movsd` 就说"这是 double"需要数据流
//!   分析追踪类型传播，M6 没有。
//! * **不命名结构体**。没有调试信息就没有名字，编一个 `struct_1`
//!   正是 CLAUDE.md §7 禁止的假名。
//! * **不给"确认有的字段列表"**。给的是"被访问过的位移"，那是观测
//!   事实，不是结构体定义。差一个字节都不算同一个字段 —— 因为
//!   `[rbx+0x18]` 读 4 字节和读 8 字节本来就是不同字段（或不同视角）。
//!
//! # 为什么步长要按"访问宽度"分组
//!
//! 上面那个"0x18 / 0x20 相差 8"的推理有个陷阱：`mov eax,[rbx+0x18]`
//! （4 字节）和 `mov rax,[rbx+0x20]`（8 字节）不一定是同一个数组。
//! 4 字节步长和 8 字节步长混在一起算，会得出不存在的结构体。
//! 所以步长**按访问宽度分别统计**，用户看到的是"8 字节访问的步长
//! 是 8"这种可以自己判断的结论。

use std::collections::{BTreeMap, BTreeSet};

use bitflip_arch::{DecodedInsn, Operand, RegId};

/// 一条被引用的字符串，以及引用它的地方。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StringUsage {
    /// 字符串地址。
    pub string: u64,
    /// 引用它的函数入口集合（升序去重）。
    ///
    /// 空集是**有意义的**：说明这条字符串被引用了，但引用点在所有
    /// 已知函数之外（或者根本没被引用）。不编一个函数来填。
    pub functions: Vec<u64>,
    /// 引用点（指令地址，升序去重）。
    pub sites: Vec<u64>,
}

impl StringUsage {
    /// 引用者数量。
    #[must_use]
    pub fn function_count(&self) -> usize {
        self.functions.len()
    }

    /// 引用点数量。
    #[must_use]
    pub fn site_count(&self) -> usize {
        self.sites.len()
    }
}

/// 某个基址寄存器上的访问步长。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AccessStride {
    /// 基址寄存器。
    pub base: RegId,
    /// 访问宽度（字节）。步长只在**同宽度**内比较。
    pub width: u8,
    /// 观测到的步长（升序去重）。
    pub strides: Vec<u64>,
    /// 参与推断的位移（升序去重）。
    pub offsets: Vec<u64>,
}

impl AccessStride {
    /// 最可能的步长：出现次数最多的那个。
    ///
    /// 返回 `None` 而不是 0：一个只被访问过一次的位移推不出步长，
    /// 填 0 会让 UI 显示"步长 0"，那是编的。
    #[must_use]
    pub fn dominant(&self) -> Option<u64> {
        self.strides.first().copied()
    }
}

/// 一次内存访问的观测（喂给 [`infer_strides`] 的原料）。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Access {
    /// 基址寄存器。
    pub base: RegId,
    /// 位移。
    pub disp: i64,
    /// 访问宽度（字节）。
    pub width: u8,
    /// 所在函数入口。
    pub function: u64,
}

/// 立即数画像。
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ImmediateProfile {
    /// 按出现次数降序的立即数（次数相同按值升序，保证可复现）。
    pub top: Vec<(i64, usize)>,
    /// 观测到的立即数总数（含重复）。
    pub total: usize,
    /// 去重后的不同立即数个数。
    pub distinct: usize,
}

/// 常量与结构的推断结果。
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ConstScan {
    /// 被引用的字符串（按字符串地址升序）。
    pub strings: Vec<StringUsage>,
    /// 内存访问步长（按基址寄存器、再按宽度排序）。
    pub strides: Vec<AccessStride>,
    /// 立即数画像。
    pub immediates: ImmediateProfile,
    /// 降级说明（中文）。
    pub notes: Vec<String>,
}

impl ImmediateProfile {
    /// 是否为空。
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.total == 0
    }
}

/// 步长的最大取值。
///
/// 超过这个值的差值几乎肯定是**两个不相关的变量**而不是数组步长
/// （比如 `[rbx+0x8]` 和 `[rbx+0x1010]` 分属两个对象）。不设上限
/// 会让每个基址寄存器都冒出一个荒唐的"步长"。
const MAX_STRIDE: u64 = 4096;

/// 步长推断所需的最少位移数。
///
/// 两个位移才有一个差值，而单个差值可能是巧合（两个不相邻的字段）。
/// 要求**至少 3 个位移**（2 个差值）并且差值一致，才认为看到了规律。
const MIN_OFFSETS_FOR_STRIDE: usize = 3;

/// 从指令流提取字符串引用。
///
/// `strings` 是已提取的字符串区间（起始地址，含 `size`），
/// `functions` 是 `(入口, 结束)` 列表（结束可能未知）。
///
/// # 归属规则
///
/// 引用点归给**包含它的函数**；落在所有函数之外的引用点仍然计入
/// `sites`，但 `functions` 里不会出现它 —— 不编造归属。
#[must_use]
pub fn aggregate_string_refs(
    insns: &[DecodedInsn],
    strings: &[(u64, u64)],
    functions: &[(u64, Option<u64>)],
) -> Vec<StringUsage> {
    // 建立"地址 → 字符串"的查找表。字符串可能被引用到**中间**
    // （比如 `"abc\0def"` 里的 `"def"`），所以按区间包含判断，
    // 而不是精确相等 —— 精确相等会漏掉大量真实引用。
    let mut sorted: Vec<(u64, u64)> = strings.to_vec();
    sorted.sort_by_key(|&(addr, _)| addr);

    let mut by_string: BTreeMap<u64, (BTreeSet<u64>, BTreeSet<u64>)> = BTreeMap::new();

    for insn in insns {
        let mut targets: Vec<u64> = Vec::new();

        // 1) rip-relative 数据引用：x64 上取字符串地址的标准形态
        for op in &insn.operands {
            if let Operand::PcRelative(disp) = op {
                let next = insn.addr + u64::from(insn.len);
                if let Some(to) = resolve(next, *disp) {
                    targets.push(to);
                }
            }
        }
        // 2) 绝对立即数地址（32 位目标、非 PIE 的 PE 常见）：
        //    只认真正的地址，避免把 sizeof/掩码之类的常量当引用
        for op in &insn.operands {
            if let Operand::Imm(v) = op {
                if let Ok(v) = u64::try_from(*v) {
                    targets.push(v);
                }
            }
        }

        for to in targets {
            if let Some(&(start, _)) = containing_string(&sorted, to) {
                let entry = by_string.entry(start).or_default();
                entry.1.insert(insn.addr);
                if let Some(f) = find_owner(functions, insn.addr) {
                    entry.0.insert(f);
                }
            }
        }
    }

    by_string
        .into_iter()
        .map(|(string, (functions, sites))| StringUsage {
            string,
            functions: functions.into_iter().collect(),
            sites: sites.into_iter().collect(),
        })
        .collect()
}

/// 计算 `next + disp`，溢出时返回 `None`（地址空间顶端的解码伪影）。
fn resolve(next: u64, disp: i64) -> Option<u64> {
    if disp >= 0 {
        next.checked_add(disp as u64)
    } else {
        next.checked_sub(disp.unsigned_abs())
    }
}

/// 找到包含 `addr` 的字符串起始地址（二分）。
fn containing_string(sorted: &[(u64, u64)], addr: u64) -> Option<&(u64, u64)> {
    let idx = sorted.partition_point(|&(start, _)| start <= addr);
    if idx == 0 {
        return None;
    }
    let cand = &sorted[idx - 1];
    // 落在区间内（含起点）；size 为 0 的字符串不可能包含任何地址
    if addr < cand.0 + cand.1 {
        Some(cand)
    } else {
        None
    }
}

/// 找到包含 `addr` 的函数入口。
///
/// 与 `callgraph::find_function` 同样的规则：有边界的必须严格落在
/// `[start, end)` 内；边界未知的只在**紧邻的下一个函数之前**才算。
/// 不做"最近的函数"兜底 —— 那会把远处的引用点硬塞给某个函数。
fn find_owner(functions: &[(u64, Option<u64>)], addr: u64) -> Option<u64> {
    let idx = functions.partition_point(|&(start, _)| start <= addr);
    if idx == 0 {
        return None;
    }
    let (start, end) = functions[idx - 1];
    match end {
        Some(e) if addr < e => Some(start),
        // 有边界但超出：不归属
        Some(_) => None,
        // 边界未知：只吸收到下一个函数开始之前
        None => {
            if idx < functions.len() && addr >= functions[idx].0 {
                None
            } else {
                Some(start)
            }
        }
    }
}

/// 从指令流推断内存访问步长。
///
/// # 只统计有基址寄存器的内存操作数
///
/// `[rip+...]` 是全局访问，没有"结构体"含义，跳过。
/// 有 index 寄存器的（`[rbx+rax*4]`）在遍历数组，其 disp 不是字段
/// 偏移，也跳过 —— 把 `*4` 的索引访问当成字段偏移，会凭空造出
/// 一个 float 数组那么大的结构体。
#[must_use]
pub fn infer_strides(insns: &[DecodedInsn]) -> Vec<AccessStride> {
    let mut groups: BTreeMap<(RegId, u8), BTreeSet<i64>> = BTreeMap::new();

    for insn in insns {
        for op in &insn.operands {
            let Operand::Mem(m) = op else { continue };
            let Some(base) = m.base else { continue };
            // 有索引寄存器 = 数组遍历，disp 是数组基址而不是字段偏移
            if m.index.is_some() {
                continue;
            }
            groups.entry((base, m.size)).or_default().insert(m.disp);
        }
    }

    let mut out: Vec<AccessStride> = Vec::new();
    for ((base, width), disps) in groups {
        let offsets: Vec<i64> = disps.into_iter().collect();

        let mut strides: BTreeSet<u64> = BTreeSet::new();
        if offsets.len() >= MIN_OFFSETS_FOR_STRIDE {
            // 相邻位移之差；只有在**所有**差值都相等时才认定一个步长。
            // 只要有一个不一致，就说明这些位移不是同一个数组的元素，
            // 此时宁可不给结论（返回空 strides）。
            let mut diffs: Vec<u64> = Vec::new();
            for w in offsets.windows(2) {
                let d = (w[1] - w[0]).unsigned_abs();
                if d > 0 {
                    diffs.push(d);
                }
            }
            if !diffs.is_empty() && diffs.iter().all(|&d| d == diffs[0]) && diffs[0] <= MAX_STRIDE {
                strides.insert(diffs[0]);
            }
        }

        out.push(AccessStride {
            base,
            width,
            strides: strides.into_iter().collect(),
            offsets: offsets.into_iter().map(|d| d.unsigned_abs()).collect(),
        });
    }

    out.sort_by_key(|s| (s.base.0, s.width));
    out
}

/// 从指令流汇总立即数。
///
/// `top_n` 控制返回条数。负数立即数一并统计（`-1` 之类的哨兵值
/// 很常见），但 `0` 通常是编译器填充或清零，仍然计入 ——
/// 过滤掉它等于替用户做判断。
#[must_use]
pub fn profile_immediates(insns: &[DecodedInsn], top_n: usize) -> ImmediateProfile {
    let mut counts: BTreeMap<i64, usize> = BTreeMap::new();
    let mut total = 0usize;

    for insn in insns {
        for op in &insn.operands {
            // 只统计立即数操作数。位移已经在步长里体现了。
            if let Operand::Imm(v) = op {
                *counts.entry(*v).or_insert(0) += 1;
                total += 1;
            }
        }
    }

    let distinct = counts.len();
    let mut top: Vec<(i64, usize)> = counts.into_iter().collect();
    // 次数降序；次数相同按值升序 —— 保证输出可复现
    top.sort_by(|a, b| b.1.cmp(&a.1).then(a.0.cmp(&b.0)));
    top.truncate(top_n);

    ImmediateProfile {
        top,
        total,
        distinct,
    }
}

/// 一次性做完三件事。
#[must_use]
pub fn scan_constants(
    insns: &[DecodedInsn],
    strings: &[(u64, u64)],
    functions: &[(u64, Option<u64>)],
    top_n: usize,
) -> ConstScan {
    let string_usages = aggregate_string_refs(insns, strings, functions);
    let strides = infer_strides(insns);
    let immediates = profile_immediates(insns, top_n);

    let mut notes: Vec<String> = Vec::new();

    let referenced = string_usages.len();
    if referenced == 0 && !strings.is_empty() {
        notes.push(format!(
            "提取到 {} 条字符串，但没有一条被指令直接引用 —— \
             可能是通过寄存器间接传递（M6 不做数据流分析）",
            strings.len()
        ));
    }

    // 有位移但没有步长：如实说明"看到了访问，但推不出规律"
    let with_offsets = strides.iter().filter(|s| s.offsets.len() > 1).count();
    let with_stride = strides.iter().filter(|s| !s.strides.is_empty()).count();
    if with_offsets > with_stride {
        notes.push(format!(
            "{with_offsets} 个基址寄存器被多个位移访问，其中只有 {with_stride} 个的位移间隔一致；\
             其余说明这些偏移不是同一个数组的元素，未给出步长（不猜）"
        ));
    }

    if immediates.is_empty() {
        notes.push("未观测到立即数操作数。".to_string());
    }

    ConstScan {
        strings: string_usages,
        strides,
        immediates,
        notes,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use bitflip_arch::{Arch, Flow, MemRef, RegId};

    const RAX: RegId = RegId(0);
    const RBX: RegId = RegId(1);

    fn insn(addr: u64, ops: Vec<Operand>) -> DecodedInsn {
        DecodedInsn {
            addr,
            len: 4,
            arch: Arch::X86_64,
            mnemonic: bitflip_arch::MnemonicId(1),
            flow: Flow::Fallthrough,
            target: None,
            condition: None,
            operands: ops,
            reads: bitflip_arch::RegSet::new(),
            writes: bitflip_arch::RegSet::new(),
            privileged: false,
        }
    }

    fn lea(addr: u64, disp: i64) -> DecodedInsn {
        insn(addr, vec![Operand::PcRelative(disp)])
    }

    /// 读 `[base+disp]`，给定访问宽度。
    fn load(addr: u64, base: RegId, disp: i64, size: u8) -> DecodedInsn {
        insn(
            addr,
            vec![Operand::Mem(MemRef {
                base: Some(base),
                index: None,
                scale: 0,
                disp,
                size,
                write: false,
            })],
        )
    }

    // ────────────── 字符串引用聚合 ──────────────

    #[test]
    fn string_reference_is_attributed_to_the_containing_function() {
        // 0x1000 是函数入口（到 0x1100），引用点在 0x1010
        // rip-relative：0x1010 处长 4，所以目标 = 0x1014 + 0x20 = 0x1034
        let insns = vec![lea(0x1010, 0x20)];
        let strings = vec![(0x1034u64, 8u64)];
        let funcs = vec![(0x1000u64, Some(0x1100u64))];

        let out = aggregate_string_refs(&insns, &strings, &funcs);
        assert_eq!(out.len(), 1);
        assert_eq!(out[0].string, 0x1034);
        assert_eq!(out[0].functions, vec![0x1000]);
        assert_eq!(out[0].sites, vec![0x1010]);
    }

    /// 引用到字符串**中间**（子串）也要认出来。
    ///
    /// 真实场景：`"HTTP/1.1 \r\n"` 里引用 `"1.1"`。按精确相等匹配
    /// 会漏掉这类引用，而它们是常见的。
    #[test]
    fn reference_into_the_middle_of_a_string_is_recognised() {
        // 字符串在 0x2000，长 16；引用目标 0x2004（中间）
        // 0x3000 处长 4 → next=0x3004，需要 disp = 0 → 目标 0x3004…
        // 换个做法：让 next 落在 0x2004 上
        let insns = vec![lea(0x2000 - 4 + 4, 0)]; // addr=0x2000, next=0x2004, disp=0
        let strings = vec![(0x2000u64, 16u64)];
        let funcs = vec![(0x1ff0u64, Some(0x2100u64))];

        let out = aggregate_string_refs(&insns, &strings, &funcs);
        assert_eq!(out.len(), 1, "引用到中间也算引用");
        assert_eq!(out[0].string, 0x2000, "归到字符串起点");
    }

    /// 引用点不在任何函数里时，`functions` 为空 —— **不编造归属**。
    #[test]
    fn reference_outside_every_function_has_no_owner_but_keeps_the_site() {
        let insns = vec![lea(0x5000, 0x10)];
        let strings = vec![(0x5014u64, 8u64)];
        // 函数在别处
        let funcs = vec![(0x1000u64, Some(0x1100u64))];

        let out = aggregate_string_refs(&insns, &strings, &funcs);
        assert_eq!(out.len(), 1);
        assert!(out[0].functions.is_empty(), "不属于任何函数就留空");
        assert_eq!(out[0].sites, vec![0x5000], "引用点本身要保留");
    }

    #[test]
    fn same_string_referenced_twice_merges_into_one_entry() {
        let insns = vec![lea(0x1010, 0x20), lea(0x1020, 0x10)];
        let strings = vec![(0x1034u64, 8u64)];
        let funcs = vec![(0x1000u64, Some(0x1100u64))];

        let out = aggregate_string_refs(&insns, &strings, &funcs);
        assert_eq!(out.len(), 1, "同一条字符串只出一条记录");
        assert_eq!(out[0].site_count(), 2);
        assert_eq!(out[0].functions, vec![0x1000], "函数去重");
    }

    #[test]
    fn a_reference_that_misses_every_string_is_ignored() {
        let insns = vec![lea(0x1010, 0x20)];
        // 字符串在别处，0x1034 不在任何区间内
        let strings = vec![(0x9000u64, 8u64)];
        let funcs = vec![(0x1000u64, Some(0x1100u64))];

        let out = aggregate_string_refs(&insns, &strings, &funcs);
        assert!(out.is_empty(), "引用不到字符串就不该产生记录");
    }

    // ────────────── 步长推断 ──────────────

    #[test]
    fn consistent_offsets_yield_a_stride() {
        // [rbx+0x18] / [rbx+0x20] / [rbx+0x28]，都是 8 字节访问 → 步长 8
        let insns = vec![
            load(0x1000, RBX, 0x18, 8),
            load(0x1010, RBX, 0x20, 8),
            load(0x1020, RBX, 0x28, 8),
        ];
        let strides = infer_strides(&insns);
        assert_eq!(strides.len(), 1);
        assert_eq!(strides[0].base, RBX);
        assert_eq!(strides[0].width, 8);
        assert_eq!(strides[0].dominant(), Some(8));
    }

    #[test]
    fn inconsistent_offsets_yield_no_stride() {
        // 0x10 / 0x18 / 0x40：差值 8 和 0x28 不一致 → 不给结论
        let insns = vec![
            load(0x1000, RBX, 0x10, 8),
            load(0x1010, RBX, 0x18, 8),
            load(0x1020, RBX, 0x40, 8),
        ];
        let strides = infer_strides(&insns);
        assert_eq!(strides.len(), 1, "访问还是要报告");
        assert!(
            strides[0].dominant().is_none(),
            "位移间隔不一致时不能给出步长 —— 那会凭空造出一个数组"
        );
        assert_eq!(strides[0].offsets, vec![0x10, 0x18, 0x40], "观测事实照报");
    }

    #[test]
    fn two_offsets_are_not_enough_to_claim_a_stride() {
        // 只有两个位移：差值可能是两个不相邻字段的巧合
        let insns = vec![load(0x1000, RBX, 0x10, 8), load(0x1010, RBX, 0x18, 8)];
        let strides = infer_strides(&insns);
        assert!(
            strides[0].dominant().is_none(),
            "两个位移推不出步长（MIN_OFFSETS_FOR_STRIDE = 3）"
        );
    }

    /// 不同访问宽度分开统计，不能混着算步长。
    #[test]
    fn strides_are_grouped_by_access_width() {
        // 4 字节访问在 0x10/0x14/0x18（步长 4）；8 字节访问在 0x20/0x28/0x30（步长 8）
        let insns = vec![
            load(0x1000, RBX, 0x10, 4),
            load(0x1010, RBX, 0x14, 4),
            load(0x1020, RBX, 0x18, 4),
            load(0x1030, RBX, 0x20, 8),
            load(0x1040, RBX, 0x28, 8),
            load(0x1050, RBX, 0x30, 8),
        ];
        let strides = infer_strides(&insns);
        assert_eq!(strides.len(), 2, "同一基址、两种宽度 = 两组");
        let w4 = strides.iter().find(|s| s.width == 4).unwrap();
        let w8 = strides.iter().find(|s| s.width == 8).unwrap();
        assert_eq!(w4.dominant(), Some(4));
        assert_eq!(w8.dominant(), Some(8));
    }

    /// 带索引寄存器的访问是数组遍历，disp 不是字段偏移。
    #[test]
    fn indexed_access_is_not_treated_as_a_field_offset() {
        let insns = vec![
            insn(
                0x1000,
                vec![Operand::Mem(MemRef {
                    base: Some(RBX),
                    index: Some(RegId(2)),
                    scale: 4,
                    disp: 0,
                    size: 4,
                    write: false,
                })],
            ),
            insn(
                0x1010,
                vec![Operand::Mem(MemRef {
                    base: Some(RBX),
                    index: Some(RegId(2)),
                    scale: 4,
                    disp: 0,
                    size: 4,
                    write: false,
                })],
            ),
        ];
        let strides = infer_strides(&insns);
        assert!(strides.is_empty(), "有索引寄存器的访问不参与字段偏移推断");
    }

    /// 离谱的差值（两个不相关的对象）不算步长。
    ///
    /// **所有差值必须一致**才轮到 `MAX_STRIDE` 说话 —— 所以这里刻意
    /// 让间隔完全均匀（0x2000），只靠"太大"这一个理由把它挡掉。
    /// 早先的版本用 0x8/0x18/0x28/0x1010，差值本身就不一致，于是
    /// 测试走的是"差值不一致"那条分支，`MAX_STRIDE` 从没被执行到 ——
    /// 把上限删掉测试依然绿，是个假通过。
    #[test]
    fn absurdly_large_gaps_are_not_strides() {
        let insns = vec![
            load(0x1000, RBX, 0x8, 8),
            load(0x1010, RBX, 0x2008, 8),
            load(0x1020, RBX, 0x4008, 8),
        ];
        let strides = infer_strides(&insns);
        assert_eq!(strides.len(), 1);
        assert_eq!(strides[0].offsets, vec![0x8, 0x2008, 0x4008]);
        assert!(
            strides[0].dominant().is_none(),
            "间隔均匀但超过 MAX_STRIDE：两个不相关的对象不该被当成一个数组"
        );
    }

    #[test]
    fn rip_relative_has_no_base_so_it_never_becomes_a_stride() {
        let insns = vec![lea(0x1000, 0x10), lea(0x1010, 0x18), lea(0x1020, 0x20)];
        let strides = infer_strides(&insns);
        assert!(
            strides.is_empty(),
            "rip-relative 是全局访问，没有结构体含义"
        );
    }

    #[test]
    fn negative_offsets_are_reported_as_magnitudes() {
        // 负数位移（[rbx-0x8]）在真实代码里存在
        let insns = vec![
            load(0x1000, RBX, -8, 8),
            load(0x1010, RBX, 0, 8),
            load(0x1020, RBX, 8, 8),
        ];
        let strides = infer_strides(&insns);
        assert_eq!(strides[0].dominant(), Some(8));
    }

    // ────────────── 立即数 ──────────────

    #[test]
    fn immediates_are_ranked_by_frequency_then_value() {
        let insns = vec![
            insn(0x1000, vec![Operand::Imm(0)]),
            insn(0x1010, vec![Operand::Imm(0)]),
            insn(0x1020, vec![Operand::Imm(0x1000)]),
            insn(0x1030, vec![Operand::Imm(-1)]),
        ];
        let p = profile_immediates(&insns, 10);
        assert_eq!(p.total, 4);
        assert_eq!(p.distinct, 3);
        assert_eq!(p.top[0], (0, 2), "出现最多的排第一");
        // 次数相同按值升序：-1 在 0x1000 前面
        assert_eq!(p.top[1], (-1, 1));
        assert_eq!(p.top[2], (0x1000, 1));
    }

    #[test]
    fn immediate_top_n_truncates_without_losing_totals() {
        let insns: Vec<DecodedInsn> = (0..20)
            .map(|i| insn(0x1000 + i * 4, vec![Operand::Imm(i as i64)]))
            .collect();
        let p = profile_immediates(&insns, 5);
        assert_eq!(p.top.len(), 5, "只返回前 5 个");
        assert_eq!(p.total, 20, "总数仍然是完整的");
        assert_eq!(p.distinct, 20);
    }

    // ────────────── 整体 ──────────────

    #[test]
    fn strings_present_but_never_referenced_is_explained() {
        let insns = vec![load(0x1000, RBX, 0x10, 8)];
        let strings = vec![(0x9000u64, 16u64)];
        let funcs = vec![(0x1000u64, Some(0x1100u64))];

        let scan = scan_constants(&insns, &strings, &funcs, 10);
        assert!(scan.strings.is_empty());
        assert!(
            scan.notes
                .iter()
                .any(|n| n.contains("没有一条被指令直接引用")),
            "有字符串但零引用必须解释，否则看起来像提取失败"
        );
    }

    #[test]
    fn offsets_without_a_consistent_stride_are_explained() {
        let insns = vec![
            load(0x1000, RBX, 0x10, 8),
            load(0x1010, RBX, 0x18, 8),
            load(0x1020, RBX, 0x40, 8),
        ];
        let funcs: Vec<(u64, Option<u64>)> = vec![];
        let scan = scan_constants(&insns, &[], &funcs, 10);
        assert!(
            scan.notes.iter().any(|n| n.contains("位移间隔一致")),
            "推不出步长时要说明原因，不能让用户以为功能没生效"
        );
    }

    #[test]
    fn no_immediates_is_reported_rather_than_shown_as_empty_silently() {
        let insns = vec![load(0x1000, RBX, 0x10, 8)];
        let scan = scan_constants(&insns, &[], &[], 10);
        assert!(scan.immediates.is_empty());
        assert!(scan.notes.iter().any(|n| n.contains("未观测到立即数")));
    }

    #[test]
    fn boundless_function_owner_search_does_not_steal_far_away_sites() {
        // 边界未知的函数在 0x1000，下一个函数在 0x2000
        // 0x1500 属于前者；0x2500 不属于任何函数
        let funcs = vec![(0x1000u64, None), (0x2000u64, Some(0x2100u64))];
        assert_eq!(find_owner(&funcs, 0x1500), Some(0x1000));
        assert_eq!(find_owner(&funcs, 0x2500), None);
        assert_eq!(find_owner(&funcs, 0x0500), None, "函数之前没有归属");
    }

    #[test]
    fn public_struct_accessors_are_sensible() {
        let u = StringUsage {
            string: 0x1000,
            functions: vec![0x100, 0x200],
            sites: vec![0x10, 0x20, 0x30],
        };
        assert_eq!(u.function_count(), 2);
        assert_eq!(u.site_count(), 3);

        let s = AccessStride {
            base: RAX,
            width: 4,
            strides: vec![4],
            offsets: vec![0, 4, 8],
        };
        assert_eq!(s.dominant(), Some(4));

        let empty = AccessStride {
            base: RAX,
            width: 4,
            strides: vec![],
            offsets: vec![0, 4],
        };
        assert_eq!(empty.dominant(), None, "推不出步长就是 None，不是 0");
    }
}
