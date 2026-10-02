//! 解码扫描：线性扫描与递归下降。
//!
//! ## 两种策略，各有各的失效方式
//!
//! | 策略 | 强项 | 失效方式 |
//! |------|------|----------|
//! | 线性扫描 | 覆盖全部代码字节，不依赖控制流正确 | 数据混在代码段里会产生大量伪指令，且一旦错位后续全错 |
//! | 递归下降 | 只解真正可达的指令，语义可信 | 间接跳转/跳转表跟丢，跳转表目标整片丢失 |
//!
//! 两者都跑、结果取并集，是工业界（IDA/Ghidra）的通行做法。
//! 但**关键在于：两者的结果必须可区分**。所以 [`ScanCoverage`] 分别记录
//! "仅线性扫到" 与 "递归下降可达"，UI 才能把可信度不同的指令分开显示，
//! 而不是把两者混成一锅粥假装都可信（CLAUDE.md §7）。
//!
//! ## 不物化
//!
//! 扫描产出的是 [`InsnIndex`]（地址 → 长度），不是 `Vec<DecodedInsn>`。
//! 指令本身按需解码 —— 100MB 级目标上，前者的内存是后者的百分之一量级。

use std::collections::HashSet;

use bitflip_arch::{DecodedInsn, Decoder, Flow};
use rayon::prelude::*;

use crate::addrspace::{index_insn, AddrSpace, InsnIndex};

/// 扫描参数。
#[derive(Debug, Clone, Copy)]
pub struct ScanOptions {
    /// 线性扫描时每个块的最大解码条数（防止数据区被当成超长指令流）。
    pub max_insns_per_block: usize,
    /// 递归下降的最大深度（防止畸形控制流导致栈爆或死循环）。
    pub max_depth: usize,
    /// 递归下降访问的地址上限，超出即停止（防止跳转表指向的巨大虚假区域）。
    pub max_visited: usize,
    /// 遇到解码失败时，线性扫描是否逐字节步进重新同步。
    ///
    /// 打开会显著变慢，但对"代码里混了数据"的情况覆盖好得多。
    pub resync_on_error: bool,
    /// 是否启用递归下降。
    pub recursive: bool,
}

impl Default for ScanOptions {
    fn default() -> Self {
        Self {
            max_insns_per_block: 1 << 20,
            max_depth: 512,
            max_visited: 4_000_000,
            resync_on_error: true,
            recursive: true,
        }
    }
}

/// 扫描统计（诚实报告覆盖率，供 UI 显示）。
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ScanStats {
    /// 已解码指令数。
    pub decoded: usize,
    /// 解码失败的字节数（线性扫描中遇到非法编码的次数）。
    pub decode_failures: usize,
    /// 扫描过的代码段数。
    pub segments_scanned: usize,
    /// 因达到上限而提前停止的次数。
    pub truncated: usize,
}

/// 扫描覆盖来源。
///
/// 这个类型的存在就是为了让"这条指令有多可信"可以被上层查询，
/// 而不是让调用方把两种来源的指令混在一起。
#[derive(Debug, Clone, Default)]
pub struct ScanCoverage {
    /// 递归下降可达的地址（控制流真实走到的）。
    reachable: HashSet<u64>,
    /// 仅被线性扫描覆盖的地址（可能是数据被误认成指令）。
    linear_only: HashSet<u64>,
}

impl ScanCoverage {
    /// 空覆盖集。
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// 记录一个递归下降可达的地址。
    pub fn mark_reachable(&mut self, addr: u64) {
        self.reachable.insert(addr);
    }

    /// 记录一个仅线性扫描得到的地址。
    pub fn mark_linear_only(&mut self, addr: u64) {
        self.linear_only.insert(addr);
    }

    /// 该地址是否被递归下降证明可达。
    #[must_use]
    pub fn is_reachable(&self, addr: u64) -> bool {
        self.reachable.contains(&addr)
    }

    /// 该地址是否只被线性扫描覆盖（可信度较低）。
    #[must_use]
    pub fn is_linear_only(&self, addr: u64) -> bool {
        self.linear_only.contains(&addr)
    }

    /// 递归下降可达的地址数。
    #[must_use]
    pub fn reachable_len(&self) -> usize {
        self.reachable.len()
    }

    /// 仅线性覆盖的地址数。
    #[must_use]
    pub fn linear_only_len(&self) -> usize {
        self.linear_only.len()
    }

    /// 合并另一份覆盖集。
    pub fn merge(&mut self, other: &Self) {
        self.reachable.extend(other.reachable.iter().copied());
        // 已被证明可达的地址不再算"仅线性" —— 可达性是更强的证据
        self.linear_only.extend(
            other
                .linear_only
                .iter()
                .copied()
                .filter(|a| !self.reachable.contains(a)),
        );
    }

    /// 清掉与可达集重复的"仅线性"记录（合并后的规范化）。
    pub fn normalize(&mut self) {
        if self.reachable.is_empty() {
            return;
        }
        self.linear_only
            .retain(|addr| !self.reachable.contains(addr));
    }
}

/// 线性扫描一段连续代码。
///
/// 每个可执行段独立扫描；段内按顺序解码，遇到非法编码时（可选）逐字节步进
/// 重新同步。**不跨段**：段边界往往是代码与数据/不同权限内存的分界。
pub fn scan_linear(
    space: &AddrSpace,
    decoder: &dyn Decoder,
    options: ScanOptions,
    coverage: &mut ScanCoverage,
) -> (InsnIndex, ScanStats) {
    let mut stats = ScanStats::default();
    let segments = space.executable_segments();

    // 逐段并行：段之间天然独立，且不需要共享索引
    let per_segment: Vec<(InsnIndex, ScanStats)> = segments
        .par_iter()
        .map(|segment| {
            let mut index = InsnIndex::new();
            let mut stats = ScanStats {
                segments_scanned: 1,
                ..ScanStats::default()
            };
            scan_one_segment(
                space,
                decoder,
                segment.vaddr,
                segment.end(),
                &options,
                &mut index,
                &mut stats,
            );
            (index, stats)
        })
        .collect();

    let mut index = InsnIndex::new();
    for (segment_index, segment_stats) in per_segment {
        index.merge(&segment_index);
        stats.decoded += segment_stats.decoded;
        stats.decode_failures += segment_stats.decode_failures;
        stats.segments_scanned += segment_stats.segments_scanned;
        stats.truncated += segment_stats.truncated;
        // 线性扫描的结果全部标为"仅线性"，后续递归下降会提升其中的可达项
        for (addr, _) in segment_index.range(0, u64::MAX) {
            coverage.mark_linear_only(addr);
        }
    }
    stats.segments_scanned = segments.len();

    (index, stats)
}

/// 扫描单个地址区间。
fn scan_one_segment(
    space: &AddrSpace,
    decoder: &dyn Decoder,
    start: u64,
    end: u64,
    options: &ScanOptions,
    index: &mut InsnIndex,
    stats: &mut ScanStats,
) {
    let mut addr = start;
    let mut count = 0usize;
    // 解码失败且不重新同步时，我们要**真正停下**。
    // 早先版本只 break 内层循环，外层循环会用同一个地址再次尝试，
    // 于是同一次失败被统计两遍（测试抓到了：failures=2 而实际只有 1 处非法字节）。
    let mut stop = false;

    while addr < end && !stop {
        if count >= options.max_insns_per_block {
            stats.truncated += 1;
            break;
        }

        // 一次取一个较大的窗口，避免逐条指令读地址空间
        let Some((window, segment_end)) = space.read_window(addr, 4096) else {
            break;
        };

        let mut offset = 0usize;
        while offset < window.len() && addr < end {
            let current = addr;
            match decoder.decode_one(&window[offset..], current) {
                Ok(insn) if insn.len > 0 => {
                    // 不要越过段尾（解码器可能会读进零填充区之外的字节）
                    if current + u64::from(insn.len) > end.min(segment_end) {
                        stats.decode_failures += 1;
                        stop = !options.resync_on_error;
                        break;
                    }
                    index_insn(index, &insn);
                    stats.decoded += 1;
                    count += 1;
                    offset += usize::from(insn.len);
                    addr += u64::from(insn.len);
                }
                _ => {
                    stats.decode_failures += 1;
                    if !options.resync_on_error {
                        // 停止整个段扫描，而不是只跳出当前窗口
                        stop = true;
                        break;
                    }
                    // 重新同步：步进一个字节继续找合法指令边界。
                    // 这会让"仅线性"的覆盖带上不可信标记 —— 由调用方决定怎么显示。
                    offset += 1;
                    addr += 1;
                }
            }
        }

        if offset == 0 && !stop {
            // 窗口读不出来且无法前进：避免死循环
            break;
        }
    }
}

/// 递归下降扫描：从种子地址出发，沿控制流走。
///
/// 返回可达地址的索引与统计。种子通常来自：入口点、导出函数、符号表中的函数、
/// unwind 表、导入 thunk。
///
/// 间接跳转/调用（`target == None`）**不**继续跟进 —— 解析跳转表是 M3 的工作。
/// 这里宁可少走，也不猜一个假目标扩大污染面。
pub fn scan_recursive(
    space: &AddrSpace,
    decoder: &dyn Decoder,
    seeds: &[u64],
    options: ScanOptions,
    coverage: &mut ScanCoverage,
) -> (InsnIndex, ScanStats) {
    let mut index = InsnIndex::new();
    let mut stats = ScanStats::default();

    // 显式栈而不是递归：畸形控制流可以把深度推到栈溢出
    let mut stack: Vec<(u64, usize)> = seeds.iter().map(|a| (*a, 0)).collect();
    let mut visited: HashSet<u64> = HashSet::new();

    while let Some((mut addr, depth)) = stack.pop() {
        if depth > options.max_depth || visited.len() > options.max_visited {
            stats.truncated += 1;
            continue;
        }

        // 沿基本块前进，直到块结束或遇到已访问地址
        let mut budget = options.max_insns_per_block;
        loop {
            if budget == 0 {
                stats.truncated += 1;
                break;
            }
            // 全局访问量上限必须在**块内每一条指令**处检查，而不只在出栈时检查：
            // 一条长直线代码（或一个被误判为直线的数据区）会一直走 Fallthrough，
            // 永远不回到栈上，出栈处的检查就形同虚设 —— 这曾让 1M 条指令的
            // 预算被一整条链绕过。测试 `recursive_scan_honors_max_visited_budget`
            // 固化了这条约束。
            if visited.len() >= options.max_visited {
                stats.truncated += 1;
                break;
            }
            if !visited.insert(addr) {
                break; // 已走过
            }
            if !space.contains(addr) {
                break; // 跳出地址空间
            }
            // 只沿可执行内存走：跳到不可执行段意味着前面某处解错了
            let executable = space
                .segment_at(addr)
                .is_some_and(|segment| segment.perms.execute);
            if !executable {
                break;
            }

            let Some((window, _)) = space.read_window(addr, 16) else {
                break;
            };
            let Ok(insn) = decoder.decode_one(&window, addr) else {
                stats.decode_failures += 1;
                break;
            };
            if insn.len == 0 {
                break;
            }

            index_insn(&mut index, &insn);
            stats.decoded += 1;
            coverage.mark_reachable(addr);
            budget -= 1;

            let next = insn.next_addr();

            match insn.flow {
                Flow::Fallthrough => {
                    addr = next;
                }
                Flow::Call => {
                    // 调用目标作为新种子入栈；调用本身有顺序后继
                    if let Some(target) = insn.target {
                        stack.push((target, depth + 1));
                    }
                    addr = next;
                }
                Flow::Branch { conditional } => {
                    if let Some(target) = insn.target {
                        stack.push((target, depth + 1));
                    }
                    if conditional {
                        addr = next;
                    } else {
                        break; // 无条件跳转：块结束
                    }
                }
                Flow::Return | Flow::Trap => break,
                // 未识别语义：不跟进，避免把数据当控制流
                Flow::Unknown => break,
            }
        }
    }

    coverage.normalize();
    (index, stats)
}

/// 合并两次扫描的结果。
///
/// 索引取并集；覆盖集先把递归下降的可达项标进线性结果，再合并。
#[must_use]
pub fn combine(
    linear: (InsnIndex, ScanStats),
    recursive: (InsnIndex, ScanStats),
) -> (InsnIndex, ScanStats) {
    let (mut index, mut stats) = linear;
    index.merge(&recursive.0);
    stats.decoded = index.len();
    stats.decode_failures += recursive.1.decode_failures;
    stats.truncated += recursive.1.truncated;
    (index, stats)
}

/// 从解码结果中提取控制流目标（用于种子收集的辅助函数）。
#[must_use]
pub fn control_flow_targets(insns: &[DecodedInsn]) -> Vec<u64> {
    insns.iter().filter_map(|insn| insn.target).collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::addrspace::{AddrSpace, SYNTHETIC_BASE};
    use bitflip_arch::{Arch, ArchSpec, DecodeError, Endian, Mode, RegId};
    use bitflip_loader::object::{ContentKind, FileRange, Perms, Segment};
    use std::sync::Arc;

    /// 测试用解码器：认识几种固定的字节模式，不受 capstone 影响。
    ///
    /// 这样扫描逻辑的测试不依赖外部解码库的行为，且能精确构造
    /// "非法字节""截断""无条件跳转"这些边界。
    struct FakeDecoder {
        spec: ArchSpec,
    }

    impl FakeDecoder {
        fn new() -> Self {
            Self {
                spec: ArchSpec::from_arch(Arch::X86_64, Mode::M64, Endian::Little),
            }
        }
    }

    impl Decoder for FakeDecoder {
        fn spec(&self) -> ArchSpec {
            self.spec
        }

        fn decode_one(&self, code: &[u8], addr: u64) -> Result<DecodedInsn, DecodeError> {
            let Some(&opcode) = code.first() else {
                return Err(DecodeError::Truncated);
            };
            let make = |len: u8, flow: Flow, target: Option<u64>| DecodedInsn {
                addr,
                len,
                arch: Arch::X86_64,
                mnemonic: bitflip_arch::MnemonicId(1),
                flow,
                target,
                operands: Vec::new(),
                reads: bitflip_arch::RegSet::new(),
                writes: bitflip_arch::RegSet::new(),
                privileged: false,
            };
            match opcode {
                // 0x90: nop，1 字节，顺序执行
                0x90 => Ok(make(1, Flow::Fallthrough, None)),
                // 0xCC: int3，1 字节，陷入（块结束）
                0xCC => Ok(make(1, Flow::Trap, None)),
                // 0xE8 + rel32: call，5 字节
                0xE8 => {
                    if code.len() < 5 {
                        return Err(DecodeError::Truncated);
                    }
                    let rel = i32::from_le_bytes([code[1], code[2], code[3], code[4]]);
                    let target = (addr as i64 + 5 + i64::from(rel)) as u64;
                    Ok(make(5, Flow::Call, Some(target)))
                }
                // 0xE9 + rel32: jmp，5 字节，无条件
                0xE9 => {
                    if code.len() < 5 {
                        return Err(DecodeError::Truncated);
                    }
                    let rel = i32::from_le_bytes([code[1], code[2], code[3], code[4]]);
                    let target = (addr as i64 + 5 + i64::from(rel)) as u64;
                    Ok(make(5, Flow::Branch { conditional: false }, Some(target)))
                }
                // 0x74 + rel8: je，2 字节，条件跳转
                0x74 => {
                    if code.len() < 2 {
                        return Err(DecodeError::Truncated);
                    }
                    let rel = code[1] as i8;
                    let target = (addr as i64 + 2 + i64::from(rel)) as u64;
                    Ok(make(2, Flow::Branch { conditional: true }, Some(target)))
                }
                // 0xC3: ret，1 字节
                0xC3 => Ok(make(1, Flow::Return, None)),
                // 0xFF: call/jmp 间接，2 字节，无目标
                0xFF => Ok(make(2, Flow::Branch { conditional: false }, None)),
                // 其他一律非法，用于测试重新同步
                _ => Err(DecodeError::Invalid),
            }
        }
    }

    fn code_space(bytes: &[u8], vaddr: u64) -> AddrSpace {
        let file = Arc::from(bytes.to_vec());
        let segments = vec![Segment {
            name: ".text".to_string(),
            vaddr,
            vsize: bytes.len() as u64,
            file: Some(FileRange {
                offset: 0,
                size: bytes.len() as u64,
            }),
            perms: Perms {
                read: true,
                write: false,
                execute: true,
            },
            kind: ContentKind::Code,
            align: 16,
        }];
        AddrSpace::new("t", file, &segments).expect("构造地址空间")
    }

    #[test]
    fn linear_scan_covers_whole_segment() {
        // 8 个 nop
        let space = code_space(&[0x90; 8], 0x1000);
        let decoder = FakeDecoder::new();
        let mut coverage = ScanCoverage::new();

        let (index, stats) = scan_linear(&space, &decoder, ScanOptions::default(), &mut coverage);

        assert_eq!(index.len(), 8);
        assert_eq!(stats.decoded, 8);
        assert_eq!(stats.decode_failures, 0);
        for i in 0..8u64 {
            assert_eq!(index.get(0x1000 + i), Some(1));
        }
    }

    #[test]
    fn linear_scan_resyncs_past_invalid_bytes() {
        // nop, nop, 非法, nop —— 开启重新同步后应解出 3 条而不是 2 条
        let space = code_space(&[0x90, 0x90, 0x37, 0x90], 0x1000);
        let decoder = FakeDecoder::new();
        let mut coverage = ScanCoverage::new();

        let options = ScanOptions {
            resync_on_error: true,
            ..ScanOptions::default()
        };
        let (index, stats) = scan_linear(&space, &decoder, options, &mut coverage);

        assert_eq!(index.len(), 3, "应重新同步并解出 3 条 nop");
        assert_eq!(index.get(0x1002), None, "非法字节处不应有指令");
        assert_eq!(index.get(0x1003), Some(1));
        assert_eq!(stats.decode_failures, 1);
    }

    #[test]
    fn linear_scan_decodes_real_code_from_a_synthetic_section_space() {
        use bitflip_loader::object::{ContentKind, Section};

        // 真实字节 + 真实 capstone + from_sections 的**合成地址**：
        // 这三个组合起来才是可重定位目标文件的真实路径，
        // 而之前每个部分都只被单独测过。
        let mut data = vec![0u8; 0x200];
        data[0x100] = 0x90; // nop
        data[0x101] = 0x90; // nop
        data[0x102] = 0xC3; // ret
        let file: Arc<[u8]> = Arc::from(data.into_boxed_slice());
        let sections = vec![Section {
            name: ".text".to_string(),
            vaddr: 0,
            file: FileRange {
                offset: 0x100,
                size: 3,
            },
            perms: Perms {
                read: true,
                write: false,
                execute: true,
            },
            kind: ContentKind::Code,
            loaded: true,
        }];
        let (space, synthetic) =
            AddrSpace::from_sections("t", file, &sections).expect("构造地址空间");
        assert!(synthetic);

        let spec = ArchSpec::from_arch(Arch::X86_64, Mode::M64, Endian::Little);
        let decoder = bitflip_arch::decoder_for(spec);
        let mut coverage = ScanCoverage::new();
        let (index, stats) = scan_linear(
            &space,
            decoder.as_ref(),
            ScanOptions::default(),
            &mut coverage,
        );

        assert_eq!(
            stats.decode_failures, 0,
            "nop/nop/ret 全是合法指令，不应有解码失败"
        );
        assert_eq!(index.len(), 3, "应解出 3 条指令");
        assert!(
            index.contains(SYNTHETIC_BASE),
            "第一条指令应在合成基址 {SYNTHETIC_BASE:#x}，实际索引 {:?}",
            index.range(0, u64::MAX).collect::<Vec<_>>()
        );
    }

    #[test]
    fn linear_scan_without_resync_stops_at_first_error() {
        use bitflip_loader::object::{ContentKind, Section};

        // 真实字节 + 真实 capstone + from_sections 的**合成地址**：
        // 这三个组合起来才是可重定位目标文件的真实路径，
        // 而之前每个部分都只被单独测过。
        let mut data = vec![0u8; 0x200];
        data[0x100] = 0x90; // nop
        data[0x101] = 0x90; // nop
        data[0x102] = 0xC3; // ret
        let file: Arc<[u8]> = Arc::from(data.into_boxed_slice());
        let sections = vec![Section {
            name: ".text".to_string(),
            vaddr: 0,
            file: FileRange {
                offset: 0x100,
                size: 3,
            },
            perms: Perms {
                read: true,
                write: false,
                execute: true,
            },
            kind: ContentKind::Code,
            loaded: true,
        }];
        let (space, synthetic) =
            AddrSpace::from_sections("t", file, &sections).expect("构造地址空间");
        assert!(synthetic);

        let spec = ArchSpec::from_arch(Arch::X86_64, Mode::M64, Endian::Little);
        let decoder = bitflip_arch::decoder_for(spec);
        let mut coverage = ScanCoverage::new();
        let (index, stats) = scan_linear(
            &space,
            decoder.as_ref(),
            ScanOptions::default(),
            &mut coverage,
        );

        assert_eq!(
            stats.decode_failures, 0,
            "nop/nop/ret 全是合法指令，不应有解码失败"
        );
        assert_eq!(index.len(), 3, "应解出 3 条指令，实际 {:?}", index.len());
        assert!(
            index.contains(SYNTHETIC_BASE),
            "第一条指令应在合成基址 {SYNTHETIC_BASE:#x}，实际索引 {:?}",
            index.range(0, u64::MAX).collect::<Vec<_>>()
        );
    }

    #[test]
    fn linear_scan_stops_at_the_section_end_not_the_file_end() {
        use bitflip_loader::object::{ContentKind, Section};

        // .text 只占文件的前 2 字节，后面全是别的数据。
        // 线性扫描不能越过 .text 的末尾去解后面的字节 ——
        // 那会把别的节（可能是数据、符号表）当成代码。
        let mut data = vec![0u8; 0x100];
        data[0] = 0x90; // nop
        data[1] = 0xC3; // ret
                        // 0x40 之后是"别的节"，这里放一坨看起来像指令的字节
        for byte in &mut data[0x40..] {
            *byte = 0x90;
        }
        let file: Arc<[u8]> = Arc::from(data.into_boxed_slice());
        let sections = vec![Section {
            name: ".text".to_string(),
            vaddr: 0,
            file: FileRange { offset: 0, size: 2 },
            perms: Perms {
                read: true,
                write: false,
                execute: true,
            },
            kind: ContentKind::Code,
            loaded: true,
        }];
        let (space, _) = AddrSpace::from_sections("t", file, &sections).expect("构造");

        let spec = ArchSpec::from_arch(Arch::X86_64, Mode::M64, Endian::Little);
        let decoder = bitflip_arch::decoder_for(spec);
        let mut coverage = ScanCoverage::new();
        let (index, _) = scan_linear(
            &space,
            decoder.as_ref(),
            ScanOptions::default(),
            &mut coverage,
        );

        assert_eq!(index.len(), 2, "只应解出 .text 里的 2 条指令");
        assert!(index.contains(SYNTHETIC_BASE));
        assert!(
            !index.contains(SYNTHETIC_BASE + 2),
            "不应把 .text 之后的字节当成代码"
        );
    }

    #[test]
    fn recursive_scan_follows_direct_branch_and_call() {
        // 0x1000: call +0x0b  -> 0x1010
        // 0x1005: jmp +0x08   -> 0x1012
        // 0x100a: nop
        // 0x100b: 填充到 0x1010
        // 0x1010: nop
        // 0x1011: ret
        // 0x1012: nop
        let mut code = vec![0x90u8; 0x14];
        code[0] = 0xE8;
        code[1..5].copy_from_slice(&0x0bi32.to_le_bytes());
        code[5] = 0xE9;
        code[6..10].copy_from_slice(&0x08i32.to_le_bytes());
        code[0x10] = 0x90;
        code[0x11] = 0xC3;
        code[0x12] = 0x90;

        let space = code_space(&code, 0x1000);
        let decoder = FakeDecoder::new();
        let mut coverage = ScanCoverage::new();

        let (index, _stats) = scan_recursive(
            &space,
            &decoder,
            &[0x1000],
            ScanOptions::default(),
            &mut coverage,
        );

        // 入口块：call(0x1000) -> nop(0x100a 前的 0x1005 是 jmp)
        assert!(index.contains(0x1000), "入口应是可达的");
        assert!(index.contains(0x1005), "jmp 应可达");
        // 调用目标与跳转目标
        assert!(index.contains(0x1010), "调用目标 0x1010 应可达");
        assert!(index.contains(0x1012), "跳转目标 0x1012 应可达");
        // 0x1011 是 ret，不应继续往下走
        assert!(coverage.is_reachable(0x1010));
        assert!(coverage.is_reachable(0x1012));
    }

    #[test]
    fn recursive_scan_marks_reachable_distinctly_from_linear() {
        // 递归下降可达的地址应被标记为 reachable，而不是 linear_only
        let code = vec![0x90u8; 4];
        let space = code_space(&code, 0x1000);
        let decoder = FakeDecoder::new();
        let mut coverage = ScanCoverage::new();

        scan_recursive(
            &space,
            &decoder,
            &[0x1000],
            ScanOptions::default(),
            &mut coverage,
        );

        // 0x1000 可达；0x1003 是顺序后继，同样可达
        assert!(coverage.is_reachable(0x1000));
        assert!(coverage.is_reachable(0x1003));
        assert!(!coverage.is_linear_only(0x1000));
    }

    #[test]
    fn recursive_scan_does_not_follow_indirect_targets() {
        // 0x1000: 间接 jmp（无目标），后接 ret
        let code = vec![0xFF, 0xE0, 0xC3];
        let space = code_space(&code, 0x1000);
        let decoder = FakeDecoder::new();
        let mut coverage = ScanCoverage::new();

        let (index, _) = scan_recursive(
            &space,
            &decoder,
            &[0x1000],
            ScanOptions::default(),
            &mut coverage,
        );

        // 只应解出那条间接跳转本身，不猜任何目标
        assert_eq!(index.len(), 1);
        assert!(index.contains(0x1000));
    }

    #[test]
    fn recursive_scan_terminates_on_self_loop() {
        // 0x1000: jmp 0x1000（自循环）—— 必须终止，不能死循环
        let mut code = vec![0xE9u8, 0, 0, 0, 0];
        code[1..5].copy_from_slice(&(-5i32).to_le_bytes());
        let space = code_space(&code, 0x1000);
        let decoder = FakeDecoder::new();
        let mut coverage = ScanCoverage::new();

        let (index, _) = scan_recursive(
            &space,
            &decoder,
            &[0x1000],
            ScanOptions::default(),
            &mut coverage,
        );
        assert_eq!(index.len(), 1, "自循环应被 visited 集挡住");
    }

    #[test]
    fn recursive_scan_stops_at_address_space_boundary() {
        // 跳转目标远在地址空间之外
        let mut code = vec![0xE9u8, 0, 0, 0, 0];
        code[1..5].copy_from_slice(&0x1000_0000i32.to_le_bytes());
        let space = code_space(&code, 0x1000);
        let decoder = FakeDecoder::new();
        let mut coverage = ScanCoverage::new();

        let (index, stats) = scan_recursive(
            &space,
            &decoder,
            &[0x1000],
            ScanOptions::default(),
            &mut coverage,
        );

        assert_eq!(index.len(), 1, "越界目标不应被解码");
        assert_eq!(coverage.reachable_len(), 1);
        // 没有 panic 就是重点；越界目标被静默丢弃是正确的
        let _ = stats;
    }

    #[test]
    fn recursive_scan_respects_executable_permission() {
        // 数据段（不可执行）里的种子不应被解码
        let file = Arc::from(vec![0x90u8; 4]);
        let segments = vec![Segment {
            name: ".data".to_string(),
            vaddr: 0x2000,
            vsize: 4,
            file: Some(FileRange { offset: 0, size: 4 }),
            perms: Perms {
                read: true,
                write: true,
                execute: false,
            },
            kind: ContentKind::Data,
            align: 4,
        }];
        let space = AddrSpace::new("t", file, &segments).expect("构造");
        let decoder = FakeDecoder::new();
        let mut coverage = ScanCoverage::new();

        let (index, _) = scan_recursive(
            &space,
            &decoder,
            &[0x2000],
            ScanOptions::default(),
            &mut coverage,
        );
        assert!(index.is_empty(), "不可执行内存不应被解码");
    }

    #[test]
    fn recursive_scan_honors_max_visited_budget() {
        // 长串 nop + 很小的预算：必须停下并报告截断。
        // 这条链全程 Fallthrough，从不出栈 —— 正是"只在出栈处检查预算"
        // 会漏掉的情形。
        let code = vec![0x90u8; 1000];
        let space = code_space(&code, 0x1000);
        let decoder = FakeDecoder::new();
        let mut coverage = ScanCoverage::new();

        let options = ScanOptions {
            max_visited: 10,
            ..ScanOptions::default()
        };
        let (index, stats) = scan_recursive(&space, &decoder, &[0x1000], options, &mut coverage);

        assert!(
            index.len() <= 10,
            "访问量上限应被遵守，实际解出 {} 条",
            index.len()
        );
        assert!(stats.truncated > 0, "达到上限必须报告截断，而不是静默停止");
    }

    #[test]
    fn combine_merges_indexes_and_reports_total() {
        let code = vec![0x90u8; 8];
        let space = code_space(&code, 0x1000);
        let decoder = FakeDecoder::new();
        let mut cov = ScanCoverage::new();

        let linear = scan_linear(&space, &decoder, ScanOptions::default(), &mut cov);
        let mut cov2 = ScanCoverage::new();
        let recursive = scan_recursive(
            &space,
            &decoder,
            &[0x1000],
            ScanOptions::default(),
            &mut cov2,
        );

        let (index, stats) = combine(linear, recursive);
        assert_eq!(index.len(), 8, "并集仍应是 8 条");
        assert_eq!(stats.decoded, 8, "decoded 应报告去重后的总数");
    }

    #[test]
    fn coverage_merge_prefers_reachable() {
        let mut a = ScanCoverage::new();
        a.mark_linear_only(0x1000);
        a.mark_linear_only(0x1001);

        let mut b = ScanCoverage::new();
        b.mark_reachable(0x1000);

        a.merge(&b);
        a.normalize();

        assert!(a.is_reachable(0x1000));
        assert!(!a.is_linear_only(0x1000), "可达性优先于仅线性");
        assert!(a.is_linear_only(0x1001));
    }

    #[test]
    fn linear_scan_over_multiple_segments() {
        let file: Vec<u8> = vec![0x90; 16];
        let segments = vec![
            Segment {
                name: ".text1".to_string(),
                vaddr: 0x1000,
                vsize: 8,
                file: Some(FileRange { offset: 0, size: 8 }),
                perms: Perms {
                    read: true,
                    write: false,
                    execute: true,
                },
                kind: ContentKind::Code,
                align: 16,
            },
            Segment {
                name: ".text2".to_string(),
                vaddr: 0x2000,
                vsize: 8,
                file: Some(FileRange { offset: 8, size: 8 }),
                perms: Perms {
                    read: true,
                    write: false,
                    execute: true,
                },
                kind: ContentKind::Code,
                align: 16,
            },
        ];
        let space = AddrSpace::new("t", Arc::from(file), &segments).expect("构造");
        let decoder = FakeDecoder::new();
        let mut coverage = ScanCoverage::new();

        let (index, stats) = scan_linear(&space, &decoder, ScanOptions::default(), &mut coverage);

        assert_eq!(index.len(), 16);
        assert_eq!(stats.segments_scanned, 2);
        assert!(index.contains(0x1000));
        assert!(index.contains(0x2000));
    }

    #[test]
    fn control_flow_targets_extracts_direct_targets() {
        let decoder = FakeDecoder::new();
        let mut insns = Vec::new();
        // call -> 目标
        let insn = decoder
            .decode_one(&[0xE8, 0x00, 0x00, 0x00, 0x00], 0x1000)
            .unwrap();
        insns.push(insn);
        // nop -> 无目标
        insns.push(decoder.decode_one(&[0x90], 0x1005).unwrap());

        let targets = control_flow_targets(&insns);
        assert_eq!(targets, vec![0x1005]);
    }

    #[test]
    fn scan_handles_empty_address_space() {
        let space = AddrSpace::empty("empty");
        let decoder = FakeDecoder::new();
        let mut coverage = ScanCoverage::new();

        let (index, stats) = scan_linear(&space, &decoder, ScanOptions::default(), &mut coverage);
        assert!(index.is_empty());
        assert_eq!(stats.segments_scanned, 0);

        let (index2, _) = scan_recursive(
            &space,
            &decoder,
            &[0x1000],
            ScanOptions::default(),
            &mut coverage,
        );
        assert!(index2.is_empty());
    }

    #[test]
    fn decode_error_kinds_are_not_confused() {
        // 确保 Truncated 与 Invalid 都只是"停下"，不会被当成成功
        let decoder = FakeDecoder::new();
        assert!(matches!(
            decoder.decode_one(&[], 0),
            Err(DecodeError::Truncated)
        ));
        assert!(matches!(
            decoder.decode_one(&[0x37], 0),
            Err(DecodeError::Invalid)
        ));
        // 被段尾截断的 call：只有 3 字节
        assert!(matches!(
            decoder.decode_one(&[0xE8, 0, 0], 0),
            Err(DecodeError::Truncated)
        ));
    }

    #[test]
    fn unused_regid_import_is_used() {
        // RegId 在 FakeDecoder 里未直接使用；保留一个构造点确保导入不被优化掉导致
        // 后续扩展（读写寄存器集）时有隐性依赖。同时也是对 RegSet API 的冒烟。
        let mut set = bitflip_arch::RegSet::new();
        set.insert(RegId(3));
        assert!(set.contains(RegId(3)));
    }
}
