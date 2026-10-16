//! 守卫式测试：DEX 的 CFG 是**我们自己**构建的（`dex_library_boundary` 禁用库的控制流模块），
//! 所以它的每一条规则都必须在这里被单独钉住，而不是靠"库算得对"。
//!
//! 这些用例只按 Dalvik 规范构造输入，不按我们的实现构造 —— 否则就是自证其说
//! （CLAUDE.md §6.11）。

use std::collections::BTreeMap;

use bitflip_loader::{project_dex_code_item, DexEdgeKind};
use droidsaw_dex::decode::{
    CatchHandler, CodeItem, Instruction, PayloadData, RegList, TryItem, TypedCatch,
};
use droidsaw_dex::ids::TypeIdx;
use droidsaw_dex::opcodes::Opcode;

fn instruction(
    addr: u32,
    op: Opcode,
    size: u8,
    dst: Option<u16>,
    src: &[u16],
    literal: i64,
    target: Option<u32>,
) -> Instruction {
    Instruction {
        addr,
        op,
        size,
        dst,
        src: RegList::from_slice(src),
        literal,
        target,
        pool_idx: None,
    }
}

fn code(instructions: Vec<Instruction>, payloads: BTreeMap<u32, PayloadData>) -> CodeItem {
    CodeItem {
        registers_size: 4,
        ins_size: 1,
        outs_size: 2,
        debug_info_off: 0,
        instructions,
        tries: Vec::<TryItem>::new(),
        catch_handlers: Vec::<CatchHandler>::new(),
        payloads,
        invariant_violations: Vec::new(),
    }
}

fn return_void(addr: u32) -> Instruction {
    instruction(addr, Opcode::ReturnVoid, 1, None, &[], 0, None)
}

/// 条件分支：一条 `Branch` 到目标、一条 `FallThrough` 到下一条，且下一条自成一块。
#[test]
fn conditional_branch_gets_both_a_branch_and_a_fallthrough() {
    let item = code(
        vec![
            instruction(0, Opcode::IfEqz, 2, None, &[0], 0, Some(4)),
            return_void(2),
            return_void(4),
        ],
        BTreeMap::new(),
    );
    let view = project_dex_code_item(&item).expect("project");
    let cfg = &view.cfg;

    assert_eq!(cfg.block_starts, [0, 2, 4], "块首：入口 / 落空 / 分支目标");
    assert_eq!(cfg.entry_block, Some(0));
    assert_eq!(
        cfg.edge_kinds,
        [DexEdgeKind::Branch, DexEdgeKind::FallThrough]
    );
    // 边目标是块号：分支去 2 号块（地址 4），落空去 1 号块（地址 2）。
    assert_eq!(cfg.edge_targets, [2, 1]);
    assert!(cfg.unresolved_edge_targets.is_empty());
    assert!(cfg.consistency_problems().is_empty());
}

/// `goto` 只有一条分支边，**没有**落空 —— 落空是条件分支才有的。
#[test]
fn unconditional_goto_has_no_fallthrough_edge() {
    let item = code(
        vec![
            instruction(0, Opcode::Goto, 1, None, &[], 0, Some(3)),
            return_void(1),
            return_void(3),
        ],
        BTreeMap::new(),
    );
    let view = project_dex_code_item(&item).expect("project");
    assert_eq!(view.cfg.edge_kinds, [DexEdgeKind::Branch]);
    assert!(view.cfg.consistency_problems().is_empty());
}

/// `return*` 与 `throw` 是终结指令：其后没有边，但它仍然是所在块的结尾。
#[test]
fn terminal_instructions_have_no_successors() {
    let item = code(
        vec![
            instruction(0, Opcode::Throw, 1, None, &[0], 0, None),
            return_void(1),
        ],
        BTreeMap::new(),
    );
    let view = project_dex_code_item(&item).expect("project");
    assert!(
        view.cfg.edge_kinds.is_empty(),
        "终结指令不该有后继边：{:?}",
        view.cfg.edge_kinds
    );
    assert_eq!(view.cfg.block_starts, [0, 1], "翻转之后仍要另起一块");
}

/// switch：默认一条 `SwitchDefault` + 每个 case 一条 `SwitchCase`，key 取自 payload。
#[test]
fn switch_edges_carry_default_and_each_case_key() {
    let mut payloads = BTreeMap::new();
    payloads.insert(
        6,
        PayloadData::SparseSwitch {
            keys: vec![7, 9],
            targets: vec![3, 4],
        },
    );
    let item = code(
        vec![
            instruction(0, Opcode::SparseSwitch, 3, None, &[0], 0, Some(6)),
            return_void(3),
            return_void(4),
            return_void(6),
        ],
        payloads,
    );
    let view = project_dex_code_item(&item).expect("project");
    let cfg = &view.cfg;

    assert_eq!(
        cfg.edge_kinds,
        [
            DexEdgeKind::SwitchDefault,
            DexEdgeKind::SwitchCase,
            DexEdgeKind::SwitchCase
        ]
    );
    assert_eq!(cfg.edge_switch_keys, [None, Some(7), Some(9)]);
    // 边目标列存的是**块号**，不是地址：地址 3 → 1 号块，地址 4 → 2 号块。
    assert_eq!(
        cfg.edge_targets,
        [1, 1, 2],
        "默认落空去地址 3；两个 case 去地址 3 与 4"
    );
    assert!(cfg.unresolved_edge_targets.is_empty());
    assert!(cfg.consistency_problems().is_empty());
}

/// try 区间内的块要连到 handler；区间与 handler 地址各自成列。
#[test]
fn try_region_edges_and_columns_point_at_the_handler() {
    let mut item = code(
        vec![
            instruction(0, Opcode::Const4, 1, Some(0), &[], 1, None),
            return_void(1),
            return_void(2),
        ],
        BTreeMap::new(),
    );
    item.tries.push(TryItem {
        start_addr: 0,
        insn_count: 1,
        handler_idx: 0,
    });
    item.catch_handlers.push(CatchHandler {
        catches: vec![TypedCatch {
            exception_type: TypeIdx(9),
            handler_addr: 2,
        }],
        catch_all_addr: Some(2),
    });

    let view = project_dex_code_item(&item).expect("project");
    let cfg = &view.cfg;

    // 被保护的 0 号块连出：自己的落空 + 两条异常边（typed + catch-all）。
    assert_eq!(
        cfg.edge_kinds,
        [
            DexEdgeKind::FallThrough,
            DexEdgeKind::ExceptionHandler,
            DexEdgeKind::ExceptionCatchAll
        ],
        "只有落在 try 区间内的块才连异常边"
    );
    assert_eq!(cfg.edge_exception_type_indices, [None, Some(9), None]);

    assert_eq!(cfg.exception_regions.len(), 1);
    let region = &cfg.exception_regions[0];
    assert_eq!((region.start_addr, region.end_addr), (0, 1));
    assert_eq!(region.handler_addresses, [2, 2]);
    assert_eq!(
        region.handler_kinds,
        [
            DexEdgeKind::ExceptionHandler,
            DexEdgeKind::ExceptionCatchAll
        ]
    );
    assert_eq!(region.exception_type_indices, [Some(9), None]);
    // handler 地址 2 是真实指令起点，所以必须解析出块号，不能是 None。
    assert_eq!(region.handler_blocks, [Some(2), Some(2)]);
    assert!(cfg.consistency_problems().is_empty());
}

/// 目标不是指令起点的边**不连边**，但必须逐条记账 —— 不许悄悄丢。
#[test]
fn edges_into_non_instruction_addresses_are_recorded_not_dropped() {
    // 一条 `if-eqz` 跳到地址 1：那条指令在 0 处宽 2，1 落在它中间。
    let item = code(
        vec![
            instruction(0, Opcode::IfEqz, 2, None, &[0], 0, Some(1)),
            return_void(2),
        ],
        BTreeMap::new(),
    );
    let view = project_dex_code_item(&item).expect("project");
    let cfg = &view.cfg;

    assert_eq!(
        cfg.unresolved_edge_targets.len(),
        1,
        "跳进指令中间的边必须被记账：{:?}",
        cfg.unresolved_edge_targets
    );
    let unresolved = cfg.unresolved_edge_targets[0];
    assert_eq!(unresolved.target, 1);
    assert_eq!(unresolved.kind, DexEdgeKind::Branch);
    assert_eq!(unresolved.from_block, 0);
    // 记了账的边不进边列，所以边列里的只有落空那一条。
    assert_eq!(cfg.edge_kinds, [DexEdgeKind::FallThrough]);
    assert!(cfg.consistency_problems().is_empty());
}

/// 31t 的 `target` 指向 payload（不是指令起点），不能被当成跳转目标。
#[test]
fn payload_pointers_are_not_treated_as_branch_targets() {
    let mut payloads = BTreeMap::new();
    payloads.insert(
        4,
        PayloadData::FillArrayData {
            element_width: 1,
            data: vec![1, 2, 3, 4],
        },
    );
    let item = code(
        vec![
            instruction(0, Opcode::FillArrayData, 3, None, &[0], 0, Some(4)),
            instruction(3, Opcode::Goto, 1, None, &[], 0, Some(6)),
            return_void(6),
        ],
        payloads,
    );
    let view = project_dex_code_item(&item).expect("project");
    let cfg = &view.cfg;
    // 块 [0,3] 的最后一条是 `goto`，所以边只有它那一条分支。
    // 若把 31t 的 payload 指针当成跳转目标，这里会多出一条指向地址 4 的边。
    assert_eq!(
        cfg.edge_kinds,
        [DexEdgeKind::Branch],
        "fill-array-data 不产生分支边"
    );
    assert_eq!(cfg.edge_targets, [1], "唯一的分支边来自 goto → 地址 6");
    assert!(
        cfg.unresolved_edge_targets.is_empty(),
        "payload 指针不是边，不该进未解析列：{:?}",
        cfg.unresolved_edge_targets
    );
    assert_eq!(
        cfg.block_starts,
        [0, 6],
        "payload 地址 4 不是块首（它不是指令起点）"
    );
}

/// 没有指令的方法：空 CFG，入口为 `None`（而不是伪造一个 0 号块）。
#[test]
fn an_empty_method_has_no_entry_block() {
    let item = code(Vec::new(), BTreeMap::new());
    let view = project_dex_code_item(&item).expect("project");
    assert!(view.cfg.block_ids.is_empty());
    assert_eq!(view.cfg.entry_block, None);
    assert_eq!(view.cfg.block_instruction_offsets, [0]);
    assert_eq!(view.cfg.edge_offsets, [0]);
    assert_eq!(view.cfg.predecessor_offsets, [0]);
    assert!(view.cfg.consistency_problems().is_empty());
}

/// 前驱列与边列互为反向：每条边都在目标块的前驱里。
#[test]
fn predecessors_mirror_the_edge_list() {
    let item = code(
        vec![
            instruction(0, Opcode::IfEqz, 2, None, &[0], 0, Some(4)),
            return_void(2),
            return_void(4),
        ],
        BTreeMap::new(),
    );
    let view = project_dex_code_item(&item).expect("project");
    let cfg = &view.cfg;
    for (index, target) in cfg.edge_targets.iter().enumerate() {
        let from = cfg
            .edge_offsets
            .partition_point(|&end| end <= index)
            .saturating_sub(1);
        let target = usize::try_from(*target).expect("block index");
        let (begin, end) = (
            cfg.predecessor_offsets[target],
            cfg.predecessor_offsets[target + 1],
        );
        assert!(
            cfg.predecessors[begin..end].contains(&u32::try_from(from).expect("block index")),
            "第 {index} 条边（{from} -> {target}）没有出现在前驱列里"
        );
    }
}

/// 跨表对账：块里的指令必须**恰好**等于指令列，顺序相同、不重不漏。
///
/// 这条是 CFG 唯一能跟"原始字节"间接挂钩的地方（指令列已被独立的布局检查对拍过），
/// 所以它的"会响"必须被证明 —— 否则它只是一条恒真的绿灯。
#[test]
fn cross_check_catches_a_block_that_lost_an_instruction() {
    let item = code(
        vec![
            instruction(0, Opcode::Const4, 1, Some(0), &[], 1, None),
            return_void(1),
            return_void(2),
        ],
        BTreeMap::new(),
    );
    let good = project_dex_code_item(&item).expect("project");
    assert_eq!(good.cross_check_problems(), Vec::<String>::new());

    // 把 0 号块的第二条指令地址改成下一条指令的地址：长度不变、也仍然不小于块起点，
    // 所以单表对账看不出问题；只有跨表对账能发现 CFG 漏掉了真正的指令。
    let mut broken = good;
    assert_eq!(broken.cfg.block_instruction_addresses, [0, 1, 2]);
    broken.cfg.block_instruction_addresses[1] = 2;
    assert!(
        broken.consistency_problems().is_empty(),
        "这个破坏方式刻意绕开了单表对账，用来证明跨表对账是必要的"
    );
    let problems = broken.cross_check_problems();
    assert!(
        problems.iter().any(|p| p.contains("指令列")),
        "跨表对账没发现块里少了指令：{problems:?}"
    );
}

/// 载荷夹在指令之间时，**载荷之后那一段也要有块覆盖**。
///
/// 这是真实 APK 上抓到的一个真 bug：`CodeItem.instructions` 里没有 payload 的条目，
/// 所以指令列中间会出现断口；只按"分支目标 / 终结指令之后"取块首的话，断口之后
/// 那一段没有任何块覆盖，会被整段静默丢掉。
#[test]
fn instructions_after_a_payload_gap_are_still_covered_by_a_block() {
    let mut payloads = BTreeMap::new();
    payloads.insert(
        3,
        PayloadData::FillArrayData {
            element_width: 1,
            data: vec![1, 2, 3, 4],
        },
    );
    let item = code(
        vec![
            // 31t：占 0..3，指向地址 3 的 payload。
            instruction(0, Opcode::FillArrayData, 3, None, &[0], 0, Some(3)),
            // payload 之后的指令：地址 9 与上一条的结束地址 3 之间有断口。
            instruction(9, Opcode::ReturnVoid, 1, None, &[], 0, None),
        ],
        payloads,
    );
    let view = project_dex_code_item(&item).expect("project");

    assert_eq!(
        view.cfg.block_instruction_addresses,
        [0, 9],
        "断口之后的指令必须被某个块覆盖"
    );
    assert_eq!(view.cfg.block_starts, [0, 9]);
    assert_eq!(view.cross_check_problems(), Vec::<String>::new());
    assert_eq!(view.consistency_problems(), Vec::<String>::new());
}

/// 跨表对账也要能发现"块内地址不连续"。
#[test]
fn cross_check_catches_a_non_contiguous_block() {
    let item = code(
        vec![
            instruction(0, Opcode::Const4, 1, Some(0), &[], 1, None),
            return_void(1),
        ],
        BTreeMap::new(),
    );
    let mut view = project_dex_code_item(&item).expect("project");
    assert_eq!(view.cross_check_problems(), Vec::<String>::new());
    // 把块里的第二个地址推远一格：宽度 1 的指令之后应当是地址 1。
    if let Some(address) = view.cfg.block_instruction_addresses.get_mut(1) {
        *address = 5;
    }
    let problems = view.cross_check_problems();
    assert!(
        problems.iter().any(|p| p.contains("不连续")),
        "跨表对账没发现块内地址不连续：{problems:?}"
    );
}
