//! 导出 JSON 的 **schema 快照**（M9 交付物 4 的收尾欠账，PLAN「未做」清单里明确的一条）。
//!
//! 现有测试只断言"信封里有 `format_version` 与 `producer`"，没有把**一份 schema 钉成
//! 快照**——于是"悄悄删掉一个字段"或"改个字段名"这类破坏外部消费方的变更，现有测试
//! 全绿。本文件把 schema 钉死：
//!
//! 1. **信封不变量**（对所有机器码 JSON 视图）：顶层必含 `format_version` / `producer` /
//!    `meta`；`meta` 的字段集；`meta.format_versions` 的字段集。
//! 2. **逐视图快照**：选两个视图（`json-functions` / `json-libraries`）把顶层键的
//!    **完整集合**钉死——多一个键、少一个键、改名，都会让快照断言变红。
//!
//! 这是**故意不快照数据内容**的：函数列表、库列表随样本与版本变化，快照数据只会
//! 制造无意义的维护负担。快照的边界是 **schema（键与类型形状）**，不是值。
//!
//! fixture 缺失时响亮失败（CLAUDE.md §7：跳过会让绿灯说谎），与 `m9_export.rs` 同款。

use bitflip_core::{
    export, ExportFormat, ExportOptions, OpenOptions, Session, EXPORT_FORMAT_VERSION,
};
use serde_json::Value;

fn fixture(name: &str) -> std::path::PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("..")
        .join("..")
        .join("tests")
        .join("fixtures")
        .join("generated")
        .join(name)
}

use std::path::PathBuf;

fn open(name: &str) -> Session {
    let path = fixture(name);
    assert!(
        path.exists(),
        "缺少 fixture {}；先跑 tests/fixtures/gen-fixtures.ps1 生成样本",
        path.display()
    );
    Session::open(&path, OpenOptions::default()).expect("打开样本")
}

fn export_json(session: &Session, format: ExportFormat) -> Value {
    let (text, _report) = export(session, format, &ExportOptions::default())
        .unwrap_or_else(|e| panic!("导出 {format:?} 失败：{e}"));
    serde_json::from_str(&text).expect("导出必须是合法 JSON（外部工具要能解析）")
}

/// 顶层键的**完整集合**必须与快照一致（多/少/改名都红）。
fn assert_top_level_keys(value: &Value, expected: &[&str], what: &str) {
    let obj = value
        .as_object()
        .unwrap_or_else(|| panic!("{what} 顶层必须是对象"));
    let mut actual: Vec<&str> = obj.keys().map(String::as_str).collect();
    actual.sort_unstable();
    let mut want: Vec<&str> = expected.to_vec();
    want.sort_unstable();
    assert_eq!(
        actual, want,
        "{what} 的顶层 schema 变了。这是对外契约：如果这是有意的破坏性变更，\
         请更新本测试并记录在 CHANGELOG（外部消费方要跟着改）；如果是无意的，请改回去。"
    );
}

// ── 信封不变量（所有机器码 JSON 视图共享）──────────────────────────────────

/// `meta` 对象的字段集（export.rs 的 `ExportMeta`）。
const META_KEYS: &[&str] = &[
    "format",
    "producer",
    "format_versions",
    "target",
    "file_size",
    "arch",
    "range_from",
    "range_to",
    "function",
    "member",
    "generated_at",
];

/// `meta.format_versions` 的字段集（export.rs 的 `FormatVersions`）。
/// **未用到的层是 `null` 不是 0** —— 由类型形状保证，这里只钉键名。
const FORMAT_VERSION_KEYS: &[&str] = &["export", "info", "disasm", "analysis", "dex"];

#[test]
fn json_functions_envelope_schema_is_pinned() {
    let session = open("m3-mingw-static.exe");
    let value = export_json(&session, ExportFormat::JsonFunctions);

    assert_top_level_keys(
        &value,
        &[
            "format_version",
            "producer",
            "meta",
            "totals",
            "functions",
            "analysis_notes",
        ],
        "json-functions",
    );

    // 信封不变量。
    assert_eq!(
        value["format_version"],
        serde_json::json!(EXPORT_FORMAT_VERSION),
        "format_version 必须等于本模块常量（外部靠它判别语义代次）"
    );
    let meta = &value["meta"];
    assert_top_level_keys(meta, META_KEYS, "json-functions meta");
    assert_top_level_keys(
        &meta["format_versions"],
        FORMAT_VERSION_KEYS,
        "format_versions",
    );
    // 非机器码视图（函数清单不涉及 DEX/反汇编细节之外的层）—— disasm/analysis 在
    // 函数清单里被用到与否由写出口径决定；这里只钉"是数字或 null"，防止变成 0/缺字段。
    for key in FORMAT_VERSION_KEYS {
        let v = &meta["format_versions"][key];
        assert!(
            v.is_u64() || v.is_null(),
            "format_versions.{key} 必须是版本数字或 null（没用到），实为 {v}"
        );
    }
}

#[test]
fn json_libraries_schema_is_pinned() {
    let session = open("m3-mingw-static.exe");
    let value = export_json(&session, ExportFormat::JsonLibraries);

    assert_top_level_keys(
        &value,
        &[
            "declared_dylibs",
            "declared_without_imports",
            "format_version",
            "imported_but_not_declared",
            "libraries",
            "meta",
            "object_notes",
            "producer",
            "totals",
        ],
        "json-libraries",
    );

    assert_top_level_keys(&value["meta"], META_KEYS, "json-libraries meta");
    assert_top_level_keys(
        &value["meta"]["format_versions"],
        FORMAT_VERSION_KEYS,
        "format_versions",
    );

    // 每个库条目的字段集也钉住（这是 diff/审计外部脚本真正消费的形状）。
    let libraries = value["libraries"]
        .as_array()
        .expect("json-libraries 的 libraries 必须是数组");
    assert!(
        !libraries.is_empty(),
        "mingw 静态样本至少依赖 KERNEL32 等系统库，库列表不应为空"
    );
    let mut first: Vec<&str> = libraries[0]
        .as_object()
        .expect("库条目必须是对象")
        .keys()
        .map(String::as_str)
        .collect();
    first.sort_unstable();
    assert_eq!(
        first,
        vec![
            "has_iat_slots",
            "import_count",
            "module",
            "named_count",
            "ordinal_only_count",
            "sample_names",
        ],
        "库条目的 schema 变了（同上：有意变更请改快照并记 CHANGELOG）"
    );
}

#[test]
fn json_xrefs_envelope_schema_is_pinned() {
    // 第三个视图只钉信封（不钉视图键——xrefs 的条目形状已有专门测试覆盖）。
    let session = open("m3-mingw-static.exe");
    let value = export_json(&session, ExportFormat::JsonXrefs);
    let obj = value.as_object().expect("json-xrefs 顶层必须是对象");
    assert!(
        obj.contains_key("format_version")
            && obj.contains_key("producer")
            && obj.contains_key("meta"),
        "json-xrefs 必须带完整信封（format_version/producer/meta），实有键：{:?}",
        obj.keys().collect::<Vec<_>>()
    );
    assert_top_level_keys(&value["meta"], META_KEYS, "json-xrefs meta");
    assert_top_level_keys(
        &value["meta"]["format_versions"],
        FORMAT_VERSION_KEYS,
        "format_versions",
    );
}
