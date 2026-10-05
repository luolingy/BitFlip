//! 调用约定应用与参数推断（M6）。
//!
//! # 这一项最容易变成猜谜，所以先把边界划清楚
//!
//! "函数有几个参数"在**有调试信息**时是查表得到的。没有调试信息时，
//! 它只能靠指令观测推断，而观测本身有噪声。所以这里给的从来不是
//! "这个函数有 3 个参数"，而是：
//!
//! > 按 ABI 的前 N 个参数寄存器中，哪几个在**被写之前**被读过。
//!
//! 这个结论**可以被用户逐条核对**（跳过去看那条指令），误差方向也是
//! 保守的：
//!
//! * 参数寄存器被读 → 强烈提示有参数（编译器不会平白读入参寄存器）；
//! * 参数寄存器**没被读** ≠ 没有这个参数 —— 它可能只被透传给另一个
//!   调用、可能一进函数就存到栈上再也没读、也可能这个函数没分析全。
//!
//! 所以 [`ArgInference::used`] 只报告"确定用到的"，
//! [`ArgInference::lower_bound`] 是**下界**而非"参数个数"。
//! **不把没观测到读成"没有"**（CLAUDE.md §7）。
//!
//! # 为什么"在被写之前"这个顺序条件不能省
//!
//! 参数寄存器在函数内部也是**通用暂存器**。`rcx` 作为第 1 个参数传入，
//! 但函数完全可以 `xor rcx, rcx` 之后拿它当计数器。只看"读没读过 rcx"
//! 的话，每个用了 rcx 的函数都会被判成"有参数" —— 那是把实现细节
//! 当成接口。正确的判据是**先读后写**：在函数入口到第一次写该寄存器
//! 之间出现读，读到的必然是入参。
//!
//! # 架构差异怎么处理
//!
//! 全走 [`bitflip_arch::AbiSpec`]，不在本模块写架构分支（CLAUDE.md §4）。
//! 寄存器**名**（`"rdi"`）由 ABI 表给出，编号由
//! [`bitflip_arch::AbiSpec::reg_id`] 向真实后端查 —— 不写死编号，
//! 否则换后端会静默错位。

use std::collections::BTreeSet;

use bitflip_arch::{AbiSpec, DecodedInsn, Operand, RegId};

/// 一个函数的参数推断结果。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ArgInference {
    /// 函数入口。
    pub entry: u64,
    /// 推断所依据的指令条数。
    pub insn_count: usize,
    /// 按序**确定用到**的参数寄存器序号（0 起）。
    ///
    /// `[0, 2]` 表示第 1、3 个参数寄存器被读到了，第 2 个没有。
    /// **不重编号**：序号就是 ABI 序号，重编号会让用户对不上寄存器。
    pub used: Vec<usize>,
    /// 第一个未观测到读取的参数寄存器序号。
    ///
    /// `None` 表示全都用到了。这个数字的含义是"从哪往后开始不确定"，
    /// **不是**"参数个数"。
    pub first_unused: Option<usize>,
    /// ABI 规定的寄存器参数容量。
    pub register_slots: usize,
    /// 是否观测到从栈上读参数（寄存器不够用）。
    pub reads_stack_args: bool,
}

impl ArgInference {
    /// 参数个数的**下界**：确定用到的最大 ABI 序号 + 1。
    ///
    /// 用最大序号而不是 `used.len()`：参数可以中间断档（第 2 个没用
    /// 但第 3 个用了），此时下界是 3 而不是 2。
    #[must_use]
    pub fn lower_bound(&self) -> usize {
        self.used.last().map_or(0, |&i| i + 1)
    }

    /// 是否一个参数都没观测到。
    #[must_use]
    pub fn looks_like_no_args(&self) -> bool {
        self.used.is_empty() && !self.reads_stack_args
    }

    /// 参数寄存器名列表（按本次推断实际用到的那几个取名字）。
    ///
    /// 名字来自 ABI 表；序号超出表长时跳过（不该发生，防御性）。
    #[must_use]
    pub fn used_names(&self, abi: &AbiSpec) -> Vec<&'static str> {
        self.used
            .iter()
            .filter_map(|&i| abi.arg_reg_name(i))
            .collect()
    }
}

/// 每个函数的参数推断汇总。
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ArgScan {
    /// 按函数入口升序。
    pub functions: Vec<ArgInference>,
    /// 调用约定的中文名；不支持时为 `None`（**不编一个名字**）。
    pub abi_name: Option<String>,
    /// 参数寄存器名（按序），供界面显示"参数在哪些寄存器里"。
    pub arg_reg_names: Vec<String>,
    /// 降级说明（中文）。
    pub notes: Vec<String>,
}

/// 一个函数的指令范围。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct InsnRange {
    /// 入口。
    pub start: u64,
    /// 结束（不含）；`None` 表示只知道入口。
    pub end: Option<u64>,
}

/// 推断单个函数的参数使用情况。
///
/// `insns` 必须是这个函数自己的指令（调用方负责切分）。
/// `arg_regs` 是 ABI 给出的参数寄存器编号（按序）—— 由
/// [`AbiSpec::arg_reg_ids`] 解析而来，解析失败时调用方就不该调用本函数。
#[must_use]
pub fn infer_args(
    entry: u64,
    insns: &[DecodedInsn],
    arg_regs: &[RegId],
    abi: &AbiSpec,
) -> ArgInference {
    // 每个参数寄存器是否还是"活的入参"（还没被写过）
    let mut still_live: Vec<bool> = vec![true; arg_regs.len()];
    let mut used: BTreeSet<usize> = BTreeSet::new();

    let stack_pointer = abi.stack_pointer_name;
    let frame_pointer = abi.frame_pointer_name;
    let sp_id = abi.reg_id(stack_pointer);
    let fp_id = frame_pointer.and_then(|n| abi.reg_id(n));

    let mut reads_stack_args = false;

    for (idx, insn) in insns.iter().enumerate() {
        // ── 先看写，再看读，顺序不能反 ──
        //
        // 一条指令可以**同时**读和写同一个寄存器（`xor rdi, rdi`
        // 就是典型：它读 rdi、写 rdi）。这种指令**不是在读入参** ——
        // 它是在覆盖入参。所以必须先让"写"生效，再判断"读"。
        //
        // 反过来写（先读后写）会让每个 `xor rcx,rcx` / `mov rcx,0`
        // / `sub rdi,rdi` 都误判成"用到了参数"，而这类指令在真实
        // 代码里到处都是 —— 参数下界会系统性虚高。
        for (i, reg) in arg_regs.iter().enumerate() {
            if still_live[i] && insn.writes.contains(*reg) {
                still_live[i] = false;
            }
        }

        // 写在**上一条指令之后、本条之前**仍然存活的寄存器，其"读"
        // 才说明入参在函数入口处是活的。
        for (i, reg) in arg_regs.iter().enumerate() {
            if still_live[i] && insn.reads.contains(*reg) {
                used.insert(i);
            }
        }

        // ── 栈上取参 ──
        if reads_stack_param(insn, sp_id, fp_id, idx) {
            reads_stack_args = true;
        }
    }

    let used_vec: Vec<usize> = used.into_iter().collect();
    let first_unused = (0..arg_regs.len()).find(|i| !used_vec.contains(i));

    ArgInference {
        entry,
        insn_count: insns.len(),
        used: used_vec,
        first_unused,
        register_slots: arg_regs.len(),
        reads_stack_args,
    }
}

/// 这条指令是否在从栈上读参数。
///
/// 只看内存操作数：`base` 是栈指针或帧指针、`disp` 落在正偏移一侧、
/// 且是**读**。写栈上是保存局部变量/寄存器，不是取参。
///
/// # 两个门槛为什么必要
///
/// * `[rsp+0]` 在叶函数里其实是**返回地址**的位置，不是参数；
/// * 函数**第一条**指令里的栈访问通常是构帧（`mov rbp,[rsp]`），
///   此时 rsp 还停在返回地址上。
fn reads_stack_param(
    insn: &DecodedInsn,
    sp: Option<RegId>,
    fp: Option<RegId>,
    insn_index: usize,
) -> bool {
    if insn_index == 0 {
        return false;
    }

    for op in &insn.operands {
        let Operand::Mem(m) = op else { continue };
        if m.write {
            continue;
        }
        let base_is_sp = sp.is_some_and(|s| m.base == Some(s));
        let base_is_fp = fp.is_some_and(|f| m.base == Some(f));
        if !base_is_sp && !base_is_fp {
            continue;
        }
        // 帧指针正偏移 = 调用者的栈（参数）；rsp 正偏移要有余量才能
        // 排除返回地址与保存的寄存器。
        let min = if base_is_fp { 16 } else { 32 };
        if m.disp >= min {
            return true;
        }
    }
    false
}

/// 批量推断：按函数范围切分指令。
///
/// `insns` 必须按地址升序（解码产出的都是）。
#[must_use]
pub fn infer_args_all(
    insns: &[DecodedInsn],
    functions: &[InsnRange],
    arg_regs: &[RegId],
    abi: &AbiSpec,
) -> Vec<ArgInference> {
    let mut sorted: Vec<InsnRange> = functions.to_vec();
    sorted.sort_by_key(|f| f.start);

    let mut out: Vec<ArgInference> = Vec::with_capacity(sorted.len());
    let mut idx = 0usize;

    for (n, f) in sorted.iter().enumerate() {
        while idx < insns.len() && insns[idx].addr < f.start {
            idx += 1;
        }
        let begin = idx;
        // 结束由显式 end 或下一个函数入口决定；边界未知时不越过下一个
        // 函数（把别人的指令算进来会让参数个数虚高）。
        let limit = f
            .end
            .or_else(|| sorted.get(n + 1).map(|next| next.start))
            .unwrap_or(u64::MAX);
        while idx < insns.len() && insns[idx].addr < limit {
            idx += 1;
        }
        out.push(infer_args(f.start, &insns[begin..idx], arg_regs, abi));
    }

    out
}

/// 汇总一批推断结果，生成面向用户的说明。
///
/// `abi` 为 `None` 表示该架构没有调用约定（如 wasm32）—— 此时如实
/// 说明"不支持"，而不是给一堆空结论让用户以为"这些函数都没有参数"。
#[must_use]
pub fn summarize_args(
    inferences: &[ArgInference],
    abi: Option<&AbiSpec>,
    function_count: usize,
) -> ArgScan {
    let Some(abi) = abi else {
        return ArgScan {
            functions: Vec::new(),
            abi_name: None,
            arg_reg_names: Vec::new(),
            notes: vec!["该架构没有寄存器级调用约定（如 WebAssembly 的栈式传参），\
                 因此不提供参数推断 —— 不是\"没有参数\"，是这项能力不适用"
                .to_string()],
        };
    };

    let mut notes: Vec<String> = Vec::new();

    if inferences.is_empty() {
        if function_count == 0 {
            notes.push("没有可推断的函数。".to_string());
        } else {
            notes.push(format!(
                "有 {function_count} 个函数，但没有一个落在可推断的指令范围内。"
            ));
        }
    } else {
        let no_args = inferences.iter().filter(|i| i.looks_like_no_args()).count();
        let stack_args = inferences.iter().filter(|i| i.reads_stack_args).count();

        notes.push(format!(
            "按 {} 推断：{} 个函数中 {no_args} 个未观测到读取任何参数寄存器。\
             这**不等于**它们没有参数 —— 参数可能只被透传给别的调用，\
             或者一进函数就存到栈上后再也没读。给出的数字是**下界**，\
             不是参数个数",
            abi.name_zh,
            inferences.len()
        ));
        if stack_args > 0 {
            notes.push(format!(
                "{stack_args} 个函数从栈上读取参数（寄存器传参不够用，第 {} 个起走栈）",
                abi.register_arg_count()
            ));
        }
    }

    ArgScan {
        functions: inferences.to_vec(),
        abi_name: Some(abi.name_zh.to_string()),
        arg_reg_names: abi.arg_reg_names.iter().map(|s| (*s).to_string()).collect(),
        notes,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use bitflip_arch::{Arch, ArchSpec, Endian, Flow, MnemonicId, Mode, RegSet};

    fn x64() -> ArchSpec {
        ArchSpec::from_arch(Arch::X86_64, Mode::M64, Endian::Little)
    }

    fn sysv() -> AbiSpec {
        bitflip_arch::abi_for_spec(x64(), false).expect("sysv")
    }

    fn win() -> AbiSpec {
        bitflip_arch::abi_for_spec(x64(), true).expect("win")
    }

    fn insn(addr: u64, reads: &[RegId], writes: &[RegId]) -> DecodedInsn {
        let mut r = RegSet::new();
        for x in reads {
            r.insert(*x);
        }
        let mut w = RegSet::new();
        for x in writes {
            w.insert(*x);
        }
        DecodedInsn {
            addr,
            len: 4,
            arch: Arch::X86_64,
            mnemonic: MnemonicId(1),
            flow: Flow::Fallthrough,
            target: None,
            condition: None,
            operands: vec![],
            reads: r,
            writes: w,
            privileged: false,
        }
    }

    fn insn_mem(addr: u64, base: RegId, disp: i64, write: bool) -> DecodedInsn {
        DecodedInsn {
            addr,
            len: 4,
            arch: Arch::X86_64,
            mnemonic: MnemonicId(1),
            flow: Flow::Fallthrough,
            target: None,
            condition: None,
            operands: vec![Operand::Mem(bitflip_arch::MemRef {
                base: Some(base),
                index: None,
                scale: 1,
                disp,
                size: 8,
                write,
            })],
            reads: RegSet::new(),
            writes: RegSet::new(),
            privileged: false,
        }
    }

    #[test]
    fn reading_the_first_arg_register_means_at_least_one_argument() {
        let abi = sysv();
        let regs = abi.arg_reg_ids().expect("解析参数寄存器");
        let insns = vec![insn(0x1000, &[regs[0]], &[])];
        let r = infer_args(0x1000, &insns, &regs, &abi);

        assert_eq!(r.used, vec![0]);
        assert_eq!(r.lower_bound(), 1);
        assert!(!r.looks_like_no_args());
        assert_eq!(r.used_names(&abi), vec!["rdi"]);
    }

    /// 参数寄存器**先写后读**不算参数 —— 它只是被当暂存器用了。
    #[test]
    fn a_register_written_before_being_read_is_not_an_argument() {
        let abi = sysv();
        let regs = abi.arg_reg_ids().expect("解析");
        let insns = vec![
            insn(0x1000, &[regs[0]], &[regs[0]]), // xor rdi, rdi
            insn(0x1004, &[regs[0]], &[]),        // 之后再读
        ];
        let r = infer_args(0x1000, &insns, &regs, &abi);

        assert!(!r.used.contains(&0), "写过之后再读是用暂存器，不是读入参");
        assert!(r.looks_like_no_args());
    }

    /// 参数可以中间断档，序号不重编号。
    #[test]
    fn parameter_slots_are_not_renumbered_when_there_is_a_gap() {
        let abi = sysv();
        let regs = abi.arg_reg_ids().expect("解析");
        let insns = vec![insn(0x1000, &[regs[0]], &[]), insn(0x1004, &[regs[2]], &[])];
        let r = infer_args(0x1000, &insns, &regs, &abi);

        assert_eq!(r.used, vec![0, 2], "序号保持 ABI 序号");
        assert_eq!(r.lower_bound(), 3, "下界由最大序号决定");
        assert_eq!(r.first_unused, Some(1));
        assert_eq!(r.used_names(&abi), vec!["rdi", "rdx"]);
    }

    #[test]
    fn no_reads_means_no_observed_arguments() {
        let abi = sysv();
        let regs = abi.arg_reg_ids().expect("解析");
        let insns = vec![insn(0x1000, &[], &[])];
        let r = infer_args(0x1000, &insns, &regs, &abi);
        assert_eq!(r.first_unused, Some(0));
        assert!(r.looks_like_no_args());
        assert_eq!(r.lower_bound(), 0);
    }

    /// 两套约定对同一条指令给出不同结论 —— 猜错会让参数整体偏移。
    #[test]
    fn windows_and_sysv_disagree_on_the_first_argument() {
        let s = sysv();
        let w = win();
        let s_regs = s.arg_reg_ids().expect("sysv");
        let w_regs = w.arg_reg_ids().expect("win");
        assert_ne!(s_regs[0], w_regs[0], "首个参数寄存器不同");

        // rcx 在 Windows 是第 1 个，在 SysV 是第 4 个
        let insns = vec![insn(0x1000, &[w_regs[0]], &[])];
        assert_eq!(infer_args(0x1000, &insns, &w_regs, &w).used, vec![0]);
        assert_eq!(
            infer_args(0x1000, &insns, &s_regs, &s).used,
            vec![3],
            "同一个 rcx 在 SysV 里是第 4 个参数寄存器"
        );
    }

    #[test]
    fn stack_argument_read_is_detected() {
        let abi = sysv();
        let regs = abi.arg_reg_ids().expect("解析");
        let sp = abi.reg_id("rsp").expect("rsp");
        let insns = vec![insn(0x1000, &[], &[]), insn_mem(0x1004, sp, 0x40, false)];
        assert!(infer_args(0x1000, &insns, &regs, &abi).reads_stack_args);
    }

    #[test]
    fn writing_to_the_stack_is_not_a_stack_argument_read() {
        let abi = sysv();
        let regs = abi.arg_reg_ids().expect("解析");
        let sp = abi.reg_id("rsp").expect("rsp");
        let insns = vec![insn(0x1000, &[], &[]), insn_mem(0x1004, sp, 0x40, true)];
        assert!(!infer_args(0x1000, &insns, &regs, &abi).reads_stack_args);
    }

    /// 第一条指令的栈访问是构帧，不是取参。
    #[test]
    fn the_first_instruction_never_counts_as_a_stack_argument() {
        let abi = sysv();
        let regs = abi.arg_reg_ids().expect("解析");
        let sp = abi.reg_id("rsp").expect("rsp");
        let insns = vec![insn_mem(0x1000, sp, 0x40, false)];
        assert!(!infer_args(0x1000, &insns, &regs, &abi).reads_stack_args);
    }

    /// 紧挨着返回地址的 `[rsp+8]` 不算参数。
    #[test]
    fn offsets_below_the_threshold_are_not_stack_arguments() {
        let abi = sysv();
        let regs = abi.arg_reg_ids().expect("解析");
        let sp = abi.reg_id("rsp").expect("rsp");
        let insns = vec![insn(0x1000, &[], &[]), insn_mem(0x1004, sp, 8, false)];
        assert!(
            !infer_args(0x1000, &insns, &regs, &abi).reads_stack_args,
            "[rsp+8] 太靠近返回地址，不算参数区"
        );
    }

    // ── 批量切分 ──

    #[test]
    fn batch_splits_instructions_by_function_boundary() {
        let abi = sysv();
        let regs = abi.arg_reg_ids().expect("解析");
        let insns = vec![
            insn(0x1000, &[regs[0]], &[]),
            insn(0x1004, &[], &[]),
            insn(0x2000, &[], &[]),
            insn(0x2004, &[], &[]),
        ];
        let funcs = vec![
            InsnRange {
                start: 0x1000,
                end: Some(0x2000),
            },
            InsnRange {
                start: 0x2000,
                end: Some(0x2100),
            },
        ];
        let out = infer_args_all(&insns, &funcs, &regs, &abi);
        assert_eq!(out.len(), 2);
        assert_eq!(out[0].insn_count, 2);
        assert_eq!(out[1].insn_count, 2);
        assert_eq!(out[0].used, vec![0]);
        assert!(out[1].used.is_empty());
    }

    /// 边界未知的函数不越过下一个函数入口。
    #[test]
    fn boundless_function_stops_at_the_next_function() {
        let abi = sysv();
        let regs = abi.arg_reg_ids().expect("解析");
        let insns = vec![
            insn(0x1000, &[], &[]),
            insn(0x1004, &[regs[0]], &[]),
            insn(0x2000, &[], &[]),
        ];
        let funcs = vec![
            InsnRange {
                start: 0x1000,
                end: None,
            },
            InsnRange {
                start: 0x2000,
                end: Some(0x2100),
            },
        ];
        let out = infer_args_all(&insns, &funcs, &regs, &abi);
        assert_eq!(out[0].insn_count, 2, "不越界吃到下一个函数");
        assert_eq!(out[1].insn_count, 1);
    }

    #[test]
    fn summary_explains_that_no_observed_args_is_not_no_arguments() {
        let abi = sysv();
        let regs = abi.arg_reg_ids().expect("解析");
        let insns = vec![insn(0x1000, &[], &[])];
        let funcs = vec![InsnRange {
            start: 0x1000,
            end: Some(0x1100),
        }];
        let inferred = infer_args_all(&insns, &funcs, &regs, &abi);
        let scan = summarize_args(&inferred, Some(&abi), 1);

        assert!(
            scan.notes.iter().any(|n| n.contains("不等于")),
            "必须说清'没观测到参数'不等于'没有参数'"
        );
        assert_eq!(scan.abi_name.as_deref(), Some(abi.name_zh));
        assert_eq!(scan.arg_reg_names.len(), abi.arg_reg_names.len());
    }

    /// 没有调用约定的架构要如实说明"不适用"，而不是给一堆空结论。
    #[test]
    fn an_arch_without_an_abi_says_so_instead_of_reporting_zero_arguments() {
        let scan = summarize_args(&[], None, 42);
        assert!(scan.functions.is_empty());
        assert_eq!(scan.abi_name, None, "不编一个约定名字");
        assert!(
            scan.notes.iter().any(|n| n.contains("不适用")),
            "必须说清是'能力不适用'而不是'这些函数没有参数'：{:?}",
            scan.notes
        );
    }

    #[test]
    fn lower_bound_uses_the_highest_used_slot() {
        let r = ArgInference {
            entry: 0x1000,
            insn_count: 10,
            used: vec![0, 1, 4],
            first_unused: Some(2),
            register_slots: 6,
            reads_stack_args: false,
        };
        assert_eq!(r.lower_bound(), 5);
        assert!(!r.looks_like_no_args());
    }
}
