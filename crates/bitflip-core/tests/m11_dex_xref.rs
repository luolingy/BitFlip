//! M11：DEX 调用边表（`bitflip_core::dex_xref`）。
//!
//! ## 这条测试要守什么
//!
//! 1. **internal 判据可信**：被引用的池方法必须与**定义**签名全等才叫 internal
//!    ——池下标与方法表下标是两套编号（真机踩过：查错表让 44% 的 callee 变 null），
//!    合成样本的自递归边两端必须解析到同一个方法。
//! 2. **没有调用点就没有边**：空样本零边但扫描数照报——账目两头闭合。
//! 3. **确定性**：同一输入两次构建逐项相同（M2c §3 同一条规矩）。
//!
//! 样本用 loader / CLI / server 测试共用的合成 DEX（`#[path]` 引入）。
//! 放在集成测试而不是模块内 `#[cfg(test)]`：那里的 `#[path]` 相对基准在
//! Linux CI 上解析不到（2026-11-04 实测），集成测试目录的两层相对路径两边都稳。

use bitflip_core::dex_xref::{build_call_edges, DexEdgeKind};

// 与 loader / CLI / server 测试共用的合成样本（`#[path]` 引入）。
#[path = "../../bitflip-loader/tests/common/dex_fixture.rs"]
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
    assert_eq!(
        edge.callee.as_deref(),
        Some("Lcom/example/Foo;->bar(I)V"),
        "池文本按池下标解析（与渲染同款），不是定义表下标"
    );
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
