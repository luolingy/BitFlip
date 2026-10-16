//! DEX 视图在 core 层的出口（M2b）。
//!
//! # 为什么 DEX 有出口，却不进对象模型
//!
//! DEX 不是 [`crate::ObjectInfo`] 意义上的可反汇编对象：它没有架构、没有线性地址空间，
//! 它的"指令"是寄存器机的码元序列（ADR-0020）。所以这里**刻意**只做三件事：
//!
//! 1. **原样出口** `bitflip-loader` 的 DEX 视图与解析入口。类型仍是 loader 自己的类型
//!    （[`DexStructure`] / [`DexMethodView`]），core 不包装、不改写 —— 将来换掉 DEX 库时
//!    改动面仍然只有 `bitflip-loader/src/format/dex/` 一处；
//! 2. 给 [`Session`] 上开一条**按成员名取原始字节**的路（[`read_member`]），
//!    因为 [`Session::member_session`] 要求成员是"可分析对象"，必然拒绝 DEX；
//! 3. 一个名字判据 [`is_dex_member_name`]（只认名字，不认内容）。
//!
//! 为什么出口必须在 core：分层约定是 `cli/app → server → core → {loader, …}`，
//! CLI 与 server 只依赖 `bitflip-core`。"让它们直接依赖 loader"不是更省事的写法，
//! 而是把分层里的一层挖掉 —— 这也正是 core 早就重新导出 [`crate::ApkRole`]、
//! [`crate::ArchiveMember`]、[`crate::MemberStorage`] 的理由。
//!
//! **不受影响的既有结论**（ADR-0020，改这里时不要顺手"修"）：
//!
//! * `ObjectKind::Dex` 仍然**没有解析器**：`has_parser(Dex) == false`；
//! * `parse_object(ObjectKind::Dex, …)` 仍然返回 `ParseError::NoParser`；
//! * `ObjectKind::Dex` 的 `arch` 仍然是 `None`。

use std::sync::Arc;

use crate::{BitflipError, Session};

/// DEX 报告的 wire 格式版本（`dex` 子命令与后续 `/api/dex*` 的 JSON 都用它）。
///
/// 与 [`crate::CORE_API_VERSION`] 分开演进：报告字段的增删改只动这个号，
/// 不必因为一个字段就宣称核心 API 破坏性变更（`docs/ARCHITECTURE.md` 的版本策略）。
pub const DEX_FORMAT_VERSION: u32 = 1;

/// `code_item` 的结构自检（不投影，只查布局）。
pub use bitflip_loader::check_code_item_layout;
/// DEX 结构解析（[`bitflip_loader::parse_dex_structure`] 的出口）。
pub use bitflip_loader::parse_dex_structure as parse;
/// 整条指令列的投影。
pub use bitflip_loader::project_dex_code_item as project_code_item;
/// 单个 `code_item` 的投影（方法视图 + CFG）。
pub use bitflip_loader::project_dex_method as project_method;
/// CFG 的文本渲染。
pub use bitflip_loader::render_dex_cfg_text as render_cfg_text;
/// 指令列的数值形式渲染。
pub use bitflip_loader::render_dex_instructions as render_instructions;
/// 指令列的符号形式渲染（返回解析结果的分类计数）。
pub use bitflip_loader::render_dex_instructions_with_symbols as render_instructions_with_symbols;
use bitflip_loader::ObjectKind;
pub use bitflip_loader::{
    payload_width_units, CodeHeaderFacts, DexCfgView, DexClass, DexCountMismatches, DexCounts,
    DexDeclaredSizes, DexEdgeKind, DexExceptionRegion, DexField, DexHandlerEntry, DexHeaderFacts,
    DexInstructions, DexMethod, DexMethodView, DexParseError, DexPayloads, DexPoolKind,
    DexRenderReport, DexStructure, DexSymbolOutcome, DexSymbolResolver, DexSymbols, DexViewError,
    LayoutCheck, LayoutProblem, LayoutProblemKind, UnresolvedEdgeTarget,
};

/// 成员名是不是"看起来是 DEX"（大小写不敏感的 `.dex` 后缀）。
///
/// 这是**名字判据**，不是内容判据：`true` 只表示"值得读出来看看"。名字可以骗人
/// （一个改名的 deflate 流也能叫 `classes.dex`），所以真正的判据是 [`read_member`]
/// 里的内容识别 —— 它在读出成员后会按内容复核，不匹配就报错，而不是照常解析。
///
/// APK 的强约定（`classes.dex` / `classes<N>.dex`）由 [`crate::ApkRole::of`] 表达；
/// 这里放宽到任意 `.dex` 后缀，是因为成员名不必遵守 APK 约定也能是 DEX。
#[must_use]
pub fn is_dex_member_name(name: &str) -> bool {
    name.len() > 4 && name[name.len() - 4..].eq_ignore_ascii_case(".dex")
}

/// 读出会话里某个成员的字节，并**按内容**确认它真的是 DEX。
///
/// 与 [`Session::member_session`] 的区别：那条路要求成员能被 `parse_object` 解析，
/// 因此必然拒绝 DEX（`ObjectKind::Dex` 没有解析器，ADR-0020）；这条路只要原始字节。
///
/// # Errors
///
/// 目标不是归档、成员名找不到或不唯一、成员数据越界或取出失败，以及**内容不是 DEX**。
pub fn read_member(session: &Session, name: &str) -> Result<Arc<[u8]>, BitflipError> {
    let (bytes, member) = session.member_bytes(name)?;
    let guess = bitflip_loader::sniff_bytes(&bytes);
    if guess.object != ObjectKind::Dex {
        return Err(BitflipError::InvalidInput(format!(
            "成员 {:?} 不是 DEX（按内容识别为 {}）：名字像 DEX 不等于内容是 DEX",
            member.name,
            guess.object.label_zh()
        )));
    }
    Ok(bytes)
}

/// 成员名按 **APK 命名约定**扮演的角色，给**人看**的中文短标签。
///
/// `None` 表示"这个名字不属于 APK 的那几个固定位置"（绝大多数成员都是这样：
/// 图片、字体、配置）—— **不是**"这个成员没用"。
///
/// 与 [`crate::ApkRole`] 的分工：那边给**稳定短名**（`"dex"` / `"manifest"`，
/// 走 wire 用），这里给**中文标签**（给人看）。放在 core 而不是各自实现，
/// 是因为同一条信息会同时出现在命令行与网页上：两处各写一份，迟早出现
/// "命令行说主 dex、网页说 dex 1"这种不一致，而这种不一致没有人会去汇报。
///
/// # 为什么只认名字
///
/// 这是**命名约定**知识，不是内容识别：`classes.dex` 里装的到底是不是 DEX，
/// 要真去解析才知道（见 [`read_member`]）。所以调用方只该在确实按 APK 约定
/// 解释成员名时用它 —— 拿这个标签去描述一个 ar / `.lib` 的成员是**无依据的**。
#[must_use]
pub fn apk_role_label(name: &str) -> Option<String> {
    match crate::ApkRole::of(name) {
        crate::ApkRole::Dex(None) => Some("主 dex".to_string()),
        crate::ApkRole::Dex(Some(ordinal)) => Some(format!("dex 序号 {ordinal}")),
        crate::ApkRole::NativeLib(abi) => Some(format!("原生库 {abi}")),
        crate::ApkRole::Manifest => Some("二进制清单".to_string()),
        crate::ApkRole::ResourceTable => Some("资源表".to_string()),
        crate::ApkRole::Signature => Some("v1 签名文件".to_string()),
        crate::ApkRole::Other => None,
    }
}
