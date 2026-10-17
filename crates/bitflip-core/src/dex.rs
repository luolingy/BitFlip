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
/// 并列数组（块内指令 / 出边 / 前驱）的**分段约定**：`offsets[i]..offsets[i + 1]`。
///
/// 导出 DEX 的 DOT 时要用它：约定只该有一处定义 —— 抄一份到导出层，
/// 下次库那边调整列宽时导出会静默错一格，而图看起来仍然"是个 CFG"。
pub use bitflip_loader::dex_column_range;
/// 边类别 → 中文标签（CFG 文本与 DOT 共用同一套措辞）。
pub use bitflip_loader::dex_edge_label;
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

/// 一个 DEX 输入的名字与角色标签。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DexInputName {
    /// 归档成员名，或单文件目标的文件名。
    pub name: String,
    /// APK 命名约定下的中文角色标签；`None` = 不属于那几个固定位置。
    pub role: Option<String>,
}

/// 本次目标里的 DEX 输入，**按容器顺序**。
///
/// 归档目标：成员名以 `.dex` 结尾（大小写不敏感）的那些，名字与顺序原样保留
/// （`classes2.dex` 不重编成 `classes1.dex` —— 文件名里的号码是构建产物的一部分）。
/// 单文件目标（`bitflip foo.dex`）：目标本身，名字取文件名。
///
/// 一个 DEX 都找不到时**报错**而不是返回空列表：空列表会让界面显示"这个目标里没有
/// DEX"，而那与"我们没有做这一步"长得一模一样（CLAUDE.md §7）。
///
/// # Errors
///
/// 归档里没有 `.dex` 结尾的成员。
pub fn input_names(session: &Session) -> Result<Vec<DexInputName>, BitflipError> {
    if session.info().is_archive() {
        let names: Vec<DexInputName> = session
            .members()
            .iter()
            .filter(|member| is_dex_member_name(&member.name))
            .map(|member| DexInputName {
                name: member.name.clone(),
                role: apk_role_label(&member.name),
            })
            .collect();
        if names.is_empty() {
            return Err(BitflipError::InvalidInput(format!(
                "目标 {:?} 里没有以 .dex 结尾的成员（成员数 {}）：DEX 视图需要 APK 或 .dex 文件",
                session.info().path,
                session.members().len()
            )));
        }
        return Ok(names);
    }

    Ok(vec![DexInputName {
        name: target_file_name(session),
        role: None,
    }])
}

/// 单文件目标在界面上的名字（文件名；没有文件名就用整条路径）。
#[must_use]
pub fn target_file_name(session: &Session) -> String {
    let info = session.info();
    std::path::Path::new(&info.path)
        .file_name()
        .map(|name| name.to_string_lossy().to_string())
        .unwrap_or_else(|| info.path.clone())
}

/// 一个 DEX 输入的字节与解析结果。
pub struct DexInput {
    /// 成员名 / 文件名。
    pub name: String,
    /// APK 角色标签。
    pub role: Option<String>,
    /// 原始字节。
    pub bytes: Arc<[u8]>,
    /// 解析出来的结构。
    pub structure: DexStructure,
}

/// 读出并解析一个 DEX 输入。
///
/// `name` 为 `None` 时的挑选规则**只有一条**：本次目标恰好只有一个 DEX 就用它，
/// 多于一个则报错并把可选名字列出来。不猜"通常大家都看 classes.dex"——
/// 猜错的表现是导出了一份**别的文件**的内容，而文件名还写着目标名。
///
/// # Errors
///
/// 输入列表取不到、`name` 不存在、有多个 DEX 却没给 `name`、读取失败、
/// 内容不是 DEX，或 DEX 解析失败。
pub fn read_input(session: &Session, name: Option<&str>) -> Result<DexInput, BitflipError> {
    let inputs = input_names(session)?;
    let available = || {
        inputs
            .iter()
            .map(|input| input.name.as_str())
            .collect::<Vec<_>>()
            .join("、")
    };

    let picked = match name.filter(|wanted| !wanted.is_empty()) {
        Some(wanted) => inputs
            .iter()
            .find(|input| input.name == wanted)
            .ok_or_else(|| {
                BitflipError::InvalidInput(format!(
                    "没有名为 {wanted:?} 的 DEX 输入（可用：{}）",
                    available()
                ))
            })?,
        None if inputs.len() > 1 => {
            return Err(BitflipError::InvalidInput(format!(
                "缺少 member 参数：本次目标有 {} —— 请指定看哪一个",
                available()
            )));
        }
        None => inputs.first().ok_or_else(|| {
            // `input_names` 已经保证非空，这里只是不留 `unwrap`。
            BitflipError::InvalidInput("本次目标里没有 DEX 输入".to_string())
        })?,
    };

    let bytes = read_input_bytes(session, &picked.name)?;
    let structure = parse(&bytes).map_err(|error| {
        BitflipError::InvalidInput(format!("把 {} 当 DEX 解析失败：{error}", picked.name))
    })?;
    Ok(DexInput {
        name: picked.name.clone(),
        role: picked.role.clone(),
        bytes,
        structure,
    })
}

/// 取一个输入的原始字节（归档成员走 [`read_member`]；单文件从磁盘读）。
fn read_input_bytes(session: &Session, name: &str) -> Result<Arc<[u8]>, BitflipError> {
    if session.info().is_archive() {
        return read_member(session, name);
    }

    let path = session.info().path.clone();
    let bytes: Arc<[u8]> = std::fs::read(&path)
        .map_err(|error| BitflipError::InvalidInput(format!("读 {path} 失败：{error}")))?
        .into();
    // 与 `read_member` 同一条内容判据：单文件目标也可能只是**名字**像 DEX。
    let guess = bitflip_loader::sniff_bytes(&bytes);
    if guess.object != ObjectKind::Dex {
        return Err(BitflipError::InvalidInput(format!(
            "{path} 不是 DEX（按内容识别为 {}）：DEX 视图需要 APK 或 .dex 文件",
            guess.object.label_zh()
        )));
    }
    Ok(bytes)
}
