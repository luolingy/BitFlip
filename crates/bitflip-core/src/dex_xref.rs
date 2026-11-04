//! DEX 的调用边提取（M11：交叉引用 / 调用图的第一块）。
//!
//! # 只做"事实"，不做"猜测"（与整仓同一立场）
//!
//! Dalvik 的方法调用指令把**被调用者的池索引**写在指令里。这条边是**事实**：
//! `bar` 在这个码元调用了 `method@5`。它是不是真的会走到（分支可达性）、
//! 是虚分派的哪个实现、反射调用最终落在谁身上——那些是猜测，这里不做。
//!
//! 所以边的分类只有两档，判据是**可验证的**：
//!
//! * **internal**：被引用的 `(类, 名字, 原型)` 与本 DEX 里某个**已定义**方法
//!   完全一致 —— 这条边两端都在本文件里，调用图可以把它连起来；
//! * **external**：被引用者不在本 DEX（framework、其它 dex）——调用图连不上，
//!   但引用文本照给，因为"调用了谁"本身就有价值。
//!
//! 判据用**签名全等**而不是 method_idx 相等：`method_ids` 里同一逻辑方法
//! 可能出现多个条目吗？不会（规范要求 `(类, 名字, 原型)` 唯一），但**定义**
//! 与**引用**在两张表里（`class_data` 定义的方法挂在类下，`method_ids` 是
//! 全局引用池）——两边能对上的键只有签名。
//!
//! # 顺序与确定性
//!
//! 按 `class_defs` 顺序遍历类、类内按 `method_idx` 顺序遍历方法、方法内按
//! 码元顺序遍历指令 —— 全程下标，不碰 `HashMap` 迭代。同一输入两次构建
//! 必须逐字节相同（M2c §3 的同一条规矩）。

use serde::{Deserialize, Serialize};

/// 调用边 wire 格式版本。
pub const DEX_XREF_FORMAT_VERSION: u32 = 1;

/// 一条调用边。
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DexCallEdge {
    /// 调用方在 `class_data` 方法表里的下标（与 `dex-json` 的 `methods[].index` 同一身份）。
    pub caller_index: u32,
    /// 调用方的 smali 标识（`Lcom/Foo;->bar(I)V`）。
    pub caller: String,
    /// 调用点所在码元（方法内相对偏移，16 位码元单位）。
    pub code_unit: u32,
    /// 被调用者在 `method_ids` 池里的下标。
    pub callee_method_idx: u32,
    /// 被调用者的 smali 标识（**池**解析；拿不到文本时是 `None`，**不是占位符**）。
    pub callee: Option<String>,
    /// `internal`（两端都在本 DEX）/ `external`（被调用者不在本 DEX）。
    pub kind: DexEdgeKind,
    /// `internal` 时：被调用者在本 DEX 方法表里的下标；`external` 时为 `None`。
    pub callee_index: Option<u32>,
}

/// 边的两档分类。判据见模块注释——签名全等，没有第三档。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum DexEdgeKind {
    /// 两端都在本 DEX。
    Internal,
    /// 被调用者不在本 DEX（framework、跨 dex）。
    External,
}

impl DexEdgeKind {
    /// 稳定短名（CLI 过滤 / 文本渲染）。
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Internal => "internal",
            Self::External => "external",
        }
    }
}

/// 汇总（账目必须闭合：`internal + external == edges.len()`）。
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct DexXrefSummary {
    /// 扫过的方法数（有字节码的）。
    pub methods_scanned: u64,
    /// 投影失败的方法数（单方法失败不放弃整次构建，照 `dex-json` 的规矩）。
    pub methods_parse_failed: u64,
    /// internal 边数。
    pub internal: u64,
    /// external 边数。
    pub external: u64,
    /// 被引用但池文本拿不到的边数（`callee: null` 的条数）。
    pub callee_name_unavailable: u64,
}

impl DexXrefSummary {
    /// 边总数（两档之和——账目闭合的锚）。
    #[must_use]
    pub const fn total_edges(&self) -> u64 {
        self.internal + self.external
    }
}

/// 从一份已解析的 DEX 结构里提取全部调用边。
///
/// `bytes` 是该 DEX 的原始字节（方法投影要用）；`structure` 见
/// `bitflip_loader::parse_dex_structure`。
#[must_use]
pub fn build_call_edges(
    bytes: &[u8],
    structure: &bitflip_loader::DexStructure,
) -> (Vec<DexCallEdge>, DexXrefSummary) {
    // 内部方法按**定义签名**建索引：签名 → 方法表下标。BTreeMap 保序、可复现。
    // 同一签名定义两次（规范不允许）时保留**第一个**——这种文件库会先报
    // parse_errors，已经进 notes，不在这里重复记账。
    let mut by_signature: std::collections::BTreeMap<String, u32> =
        std::collections::BTreeMap::new();
    for index in 0..structure.methods.len() {
        if let Some(signature) = structure.method_signature(index) {
            by_signature.entry(signature).or_insert(index as u32);
        }
    }
    // 池引用的文本解析走渲染同款（`DexSymbols`）：它按 **pool 下标**查
    // `method_ids`，与定义表是两套编号空间——这条边界曾在这里被踩混
    // （用定义表下标查池，真实 APK 上 44% 的 callee 变成 null）。见
    // `write_method` 的文档：拿不到就报 Unavailable，绝不写占位符。
    let pool_symbols = structure.symbols();
    use bitflip_loader::DexSymbolResolver as _;

    let mut edges = Vec::new();
    let mut summary = DexXrefSummary::default();

    for (method_index, method) in structure.methods.iter().enumerate() {
        if method.code_off == 0 {
            continue; // 抽象 / native：没有字节码就没有调用点
        }
        summary.methods_scanned += 1;
        let view = match bitflip_loader::project_dex_method(bytes, method.code_off) {
            Ok(view) => view,
            Err(_) => {
                // 单方法投影失败不放弃整次构建（与 dex-json 同一条规矩）；
                // 计数在这里，失败原因由 dex-json / dex-smali 的导出负责展示。
                summary.methods_parse_failed += 1;
                continue;
            }
        };
        let caller = structure.method_signature(method_index).unwrap_or_default();

        let instructions = &view.instructions;
        for insn in 0..instructions.len() {
            // 只取方法调用池引用：invoke-* 是绝大多数，但 field/字符串不算边。
            if instructions.pool_kinds[insn] != Some(bitflip_loader::DexPoolKind::Method) {
                continue;
            }
            let Some(pool_idx) = instructions.pool_indices[insn] else {
                continue;
            };
            // 池 → smali 文本（与界面渲染同一条代码路径）。
            let mut callee_text = String::new();
            let resolved = pool_symbols.write_method(
                pool_idx,
                instructions.pool_proto_indices[insn],
                &mut callee_text,
            );
            let callee = match resolved {
                crate::dex::DexSymbolOutcome::Written => Some(callee_text),
                // NotSupported（call-site 之类还没做文本的）与 Unavailable 一样：
                // 这里没有文本可给。两者都如实计数，不冒充解析成功。
                crate::dex::DexSymbolOutcome::NotSupported
                | crate::dex::DexSymbolOutcome::Unavailable => {
                    summary.callee_name_unavailable += 1;
                    None
                }
            };
            // internal 判定：池文本与某个**定义**签名全等（两边都是完整
            // smali 标识，唯一键）。
            let callee_index = callee
                .as_deref()
                .and_then(|sig| by_signature.get(sig).copied());
            let kind = if callee_index.is_some() {
                summary.internal += 1;
                DexEdgeKind::Internal
            } else {
                summary.external += 1;
                DexEdgeKind::External
            };
            edges.push(DexCallEdge {
                caller_index: method_index as u32,
                caller: caller.clone(),
                code_unit: instructions.addresses[insn],
                callee_method_idx: pool_idx,
                callee,
                kind,
                callee_index,
            });
        }
    }
    (edges, summary)
}

#[cfg(test)]
mod tests {
    use super::*;

    // 共享合成样本（`#[path]` 引入，与其它 dex 测试同一份来源）。
    #[path = "../../../../bitflip-loader/tests/common/dex_fixture.rs"]
    #[allow(dead_code)]
    mod fixture;

    #[test]
    fn self_recursive_invoke_resolves_to_internal_edge() {
        let bytes = fixture::build_with_invoke();
        let structure = bitflip_loader::parse_dex_structure(&bytes).expect("合成样本可解析");
        let (edges, summary) = build_call_edges(&bytes, &structure);

        assert_eq!(summary.methods_scanned, 2, "<init> 与 bar 都有字节码");
        assert_eq!(summary.total_edges(), 1, "只有 bar 里那一条 invoke");
        assert_eq!(
            summary.internal, 1,
            "bar 调 method@1 = 自己，两端都在本 DEX"
        );
        assert_eq!(summary.external, 0);

        let edge = &edges[0];
        assert_eq!(edge.caller, "Lcom/example/Foo;->bar(I)V");
        assert_eq!(edge.callee.as_deref(), Some("Lcom/example/Foo;->bar(I)V"));
        assert_eq!(edge.kind, DexEdgeKind::Internal);
        assert_eq!(
            edge.callee_index,
            Some(edge.caller_index),
            "自递归：两端是同一个方法"
        );
        assert_eq!(edge.code_unit, 0, "调用点在方法开头");
    }

    #[test]
    fn plain_fixture_has_no_edges() {
        // `build()`（无 invoke）应得 0 边：没有调用点就没有边，
        // 但两个方法照样被扫过 —— 账目两头都对。
        let bytes = fixture::build();
        let structure = bitflip_loader::parse_dex_structure(&bytes).expect("合成样本可解析");
        let (edges, summary) = build_call_edges(&bytes, &structure);
        assert!(edges.is_empty());
        assert_eq!(summary.methods_scanned, 2);
        assert_eq!(summary.internal + summary.external, 0);
    }

    #[test]
    fn determinism_same_input_same_edges() {
        let bytes = fixture::build_with_invoke();
        let structure = bitflip_loader::parse_dex_structure(&bytes).expect("合成样本可解析");
        let (a, sa) = build_call_edges(&bytes, &structure);
        let (b, sb) = build_call_edges(&bytes, &structure);
        assert_eq!(a, b);
        assert_eq!(sa, sb);
    }
}
