//! 会话级结构体推断：把 [`bitflip_analyze::infer_struct_fields`] 用到一次真正打开的目标上。
//!
//! 这里是"打开会话 → 反汇编 → 廉价函数发现 → 推断"的统一实现，供 CLI 的 `structs` 子命令与
//! `export --format json-structs` 共用，避免两处各写一份函数边界逻辑（那正是最容易漂移的地方）。
//!
//! 边界与 [`bitflip_analyze::structs`] 一致：**启发式、非真实 C 类型**。

use std::collections::BTreeSet;

use bitflip_analyze::{derive_function_start_bounds, infer_struct_fields, StructReport};
use bitflip_arch::{DecodedInsn, Flow};

use crate::error::BitflipError;
use crate::session::Session;

/// 一次结构体推断的结果（附带解码了多少条指令，供 UI 展示规模）。
pub struct StructsOutcome {
    /// 推断报告。
    pub report: StructReport,
    /// 解码到的指令条数。
    pub instructions: usize,
    /// 用了多少个函数区间做分组。
    pub function_ranges: usize,
}

impl Session {
    /// 推断疑似结构体字段布局。
    ///
    /// 不调用完整 `analysis()`：那会做全 CFG，对大文件动辄几分钟。这里用文件自带函数起点
    /// （Mach-O `LC_FUNCTION_STARTS` 等）加直接调用目标补足——廉价函数发现，排序后以
    /// "下一个起点"为上一个的结束。
    pub fn structs_report(&self) -> Result<StructsOutcome, BitflipError> {
        let disasm = self.disassemble(crate::DisasmScanOptions::default())?;
        let insns = disasm.decode_range(0, u64::MAX);
        let functions = function_ranges(self, &insns);
        let report = infer_struct_fields(&insns, &functions);
        Ok(StructsOutcome {
            report,
            instructions: insns.len(),
            function_ranges: functions.len(),
        })
    }
}

/// 推导 `(函数入口, 结束)` 区间，供结构体推断按函数分组。
fn function_ranges(session: &Session, insns: &[DecodedInsn]) -> Vec<(u64, Option<u64>)> {
    let mut starts: BTreeSet<u64> = BTreeSet::new();

    // 1) 文件自带的函数起点。
    if let Some(object) = session.object() {
        for b in derive_function_start_bounds(object) {
            starts.insert(b.start);
        }
    }

    // 2) 直接调用目标（廉价函数发现）：落在已解码代码里的 target 视作函数入口。
    let mut code: BTreeSet<u64> = BTreeSet::new();
    for insn in insns {
        code.insert(insn.addr);
    }
    if let Some(&first) = insns.iter().map(|i| i.addr).min().as_ref() {
        starts.insert(first);
    }
    for insn in insns {
        if matches!(insn.flow, Flow::Call) {
            if let Some(t) = insn.target {
                if code.contains(&t) {
                    starts.insert(t);
                }
            }
        }
    }

    // 3) 起点排序 → 结束 = 下一个起点（最后一个无结束）。
    let sorted: Vec<u64> = starts.into_iter().collect();
    let mut out: Vec<(u64, Option<u64>)> = Vec::with_capacity(sorted.len());
    for (i, &s) in sorted.iter().enumerate() {
        let end = sorted.get(i + 1).copied();
        out.push((s, end));
    }
    out
}
