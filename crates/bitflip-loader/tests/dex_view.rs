//! DEX method view projection tests.

use std::collections::BTreeMap;

use bitflip_loader::{project_dex_code_item, render_dex_instructions};
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
        registers_size: 3,
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

#[test]
fn instruction_columns_and_rendering_keep_method_local_operands() {
    let code = code(
        vec![
            instruction(0, Opcode::Const4, 1, Some(0), &[], -1, None),
            instruction(1, Opcode::IfEqz, 2, None, &[0], 0, Some(4)),
            instruction(3, Opcode::ReturnVoid, 1, None, &[], 0, None),
            instruction(4, Opcode::Return, 1, None, &[0], 0, None),
        ],
        BTreeMap::new(),
    );
    let view = project_dex_code_item(&code).expect("project code item");
    let ins = &view.instructions;
    assert_eq!(ins.addresses, [0, 1, 3, 4]);
    assert_eq!(ins.widths, [1, 2, 1, 1]);
    assert_eq!(ins.destinations, [Some(0), None, None, None]);
    assert_eq!(ins.source_offsets, [0, 0, 1, 1, 2]);
    assert_eq!(ins.source_registers, [0, 0]);
    assert_eq!(ins.targets, [None, Some(4), None, None]);
    let mut text = String::new();
    render_dex_instructions(ins, &mut text).expect("render");
    assert!(text.contains("0000: const/4 v0, #-1"));
    assert!(text.contains("0001: if-eqz v0, :0004"));
    assert!(text.contains("0003: return-void"));
    assert_eq!(view.cfg.block_starts.first(), Some(&0));
    assert_eq!(view.cfg.entry_block, Some(0));
}

#[test]
fn payload_and_cfg_are_projected_to_flat_tables() {
    let mut payloads = BTreeMap::new();
    payloads.insert(
        6,
        PayloadData::PackedSwitch {
            first_key: -2,
            targets: vec![3, 4],
        },
    );
    payloads.insert(
        12,
        PayloadData::FillArrayData {
            element_width: 2,
            data: vec![0x34, 0x12],
        },
    );
    let code = code(
        vec![
            instruction(0, Opcode::PackedSwitch, 3, None, &[0], 0, Some(6)),
            instruction(3, Opcode::ReturnVoid, 1, None, &[], 0, None),
            instruction(4, Opcode::ReturnVoid, 1, None, &[], 0, None),
        ],
        payloads,
    );
    let view = project_dex_code_item(&code).expect("project code item");
    assert_eq!(view.payloads.addresses, [6, 12]);
    assert_eq!(view.payloads.kinds, [1, 3]);
    assert_eq!(view.payloads.keys, [-2, -1]);
    assert_eq!(view.payloads.targets, [3, 4]);
    assert_eq!(view.payloads.target_offsets, [0, 2, 2]);
    assert_eq!(view.payloads.key_offsets, [0, 2, 2]);
    assert_eq!(view.payloads.array_offsets, [0, 0, 2]);
    assert_eq!(view.payloads.element_widths, [0, 2]);
    assert_eq!(view.payloads.array_data, [0x34, 0x12]);
    assert!(view.cfg.block_ids.len() >= 2);
    assert_eq!(view.cfg.edge_offsets.len(), view.cfg.block_ids.len() + 1);
    assert!(view
        .cfg
        .edge_kinds
        .iter()
        .any(|kind| matches!(kind, bitflip_loader::DexEdgeKind::SwitchCase)));
    assert_eq!(
        view.cfg
            .edge_switch_keys
            .iter()
            .flatten()
            .copied()
            .collect::<Vec<_>>(),
        [-2, -1]
    );
}

#[test]
fn typed_and_catch_all_handlers_keep_their_targets_and_types() {
    let mut method = code(
        vec![
            instruction(0, Opcode::Nop, 1, None, &[], 0, None),
            instruction(1, Opcode::ReturnVoid, 1, None, &[], 0, None),
            instruction(2, Opcode::MoveException, 1, Some(0), &[], 0, None),
            instruction(3, Opcode::ReturnVoid, 1, None, &[], 0, None),
        ],
        BTreeMap::new(),
    );
    method.tries.push(TryItem {
        start_addr: 0,
        insn_count: 2,
        handler_idx: 0,
    });
    method.catch_handlers.push(CatchHandler {
        catches: vec![TypedCatch {
            exception_type: TypeIdx(7),
            handler_addr: 2,
        }],
        catch_all_addr: Some(2),
    });
    let view = project_dex_code_item(&method).expect("project code item");
    assert_eq!(view.payloads.exception_handlers.len(), 2);
    assert_eq!(
        view.payloads.exception_handlers[0].exception_type_index,
        Some(7)
    );
    assert_eq!(view.payloads.exception_handlers[0].handler_address, 2);
    assert_eq!(
        view.payloads.exception_handlers[1].exception_type_index,
        None
    );
    assert_eq!(view.payloads.exception_handlers[1].handler_address, 2);
    assert_eq!(view.cfg.exception_regions.len(), 1);
    assert_eq!(view.cfg.exception_regions[0].start_addr, 0);
    assert_eq!(view.cfg.exception_regions[0].end_addr, 2);
    assert_eq!(view.cfg.exception_regions[0].handler_addresses, [2, 2]);
}

#[test]
fn rendering_reports_invalid_instruction_index() {
    let code = code(
        vec![instruction(0, Opcode::Nop, 1, None, &[], 0, None)],
        BTreeMap::new(),
    );
    let view = project_dex_code_item(&code).expect("project code item");
    let mut text = String::new();
    assert!(view.instructions.render_instruction(1, &mut text).is_err());
}

#[test]
fn every_projected_view_is_internally_consistent() {
    let mut payloads = BTreeMap::new();
    payloads.insert(
        3,
        PayloadData::SparseSwitch {
            keys: vec![10, 20],
            targets: vec![5, 6],
        },
    );
    payloads.insert(
        8,
        PayloadData::FillArrayData {
            element_width: 1,
            data: vec![1, 2, 3],
        },
    );
    let mut method = code(
        vec![
            instruction(0, Opcode::SparseSwitch, 3, None, &[0], 0, Some(3)),
            instruction(4, Opcode::Nop, 1, None, &[], 0, None),
            instruction(5, Opcode::ReturnVoid, 1, None, &[], 0, None),
            instruction(6, Opcode::ReturnVoid, 1, None, &[], 0, None),
        ],
        payloads,
    );
    method.tries.push(TryItem {
        start_addr: 0,
        insn_count: 1,
        handler_idx: 0,
    });
    method.catch_handlers.push(CatchHandler {
        catches: Vec::new(),
        catch_all_addr: Some(5),
    });
    let view = project_dex_code_item(&method).expect("project code item");
    assert_eq!(view.consistency_problems(), Vec::<String>::new());
}

#[test]
fn a_misaligned_column_is_reported_rather_than_rendered() {
    // 手工拼一份"少 push 了一列"的 SoA：约定被破坏时必须报出来，
    // 而不是照样渲染出内容错位的文本。
    let code = code(
        vec![
            instruction(0, Opcode::Const4, 1, Some(0), &[], 1, None),
            instruction(1, Opcode::ReturnVoid, 1, None, &[], 0, None),
        ],
        BTreeMap::new(),
    );
    let good = project_dex_code_item(&code).expect("project code item");
    assert!(good.instructions.consistency_problems().is_empty());

    let mut broken = good.instructions;
    broken.widths.pop();
    let problems = broken.consistency_problems();
    assert!(
        problems.iter().any(|p| p.contains("widths")),
        "应当报出 widths 列长度不符，实际：{problems:?}"
    );
}
