//! DEX 端点（M2b）：`/api/dex/inputs`、`/api/dex/classes`、`/api/dex/class`、
//! `/api/dex/method`。
//!
//! # 为什么不是"把 DEX 塞进 `/api/sections` / `/api/insns`"
//!
//! DEX 没有段表、没有线性地址空间，它的"指令"是寄存器机的码元序列
//! （ADR-0020）。硬塞进现有端点会让前端拿到一份"看起来完全正常、实际没有意义"
//! 的数据 —— 那正是本项目最不能接受的一类错误。所以这里是一个**独立的端点族**，
//! 与 `/api/members`（归档成员）并列而不是嵌进去。
//!
//! # 多个 DEX
//!
//! APK 里可以有 `classes.dex` / `classes2.dex` / … 。每个端点都要求 `member`
//! 参数**显式指定看哪一个**：不指定时返回 400 并列出可用的名字。
//! 这不是为了严格，而是因为"合并三个 DEX 的类列表"会让前端分不清
//! 第 5000 个类是哪个文件里的（用户 2026-10-16 的决定：网页端按文件名分标签页）。
//!
//! # 缓存
//!
//! 解析一个真实 `classes.dex` 是秒级工作（7000+ 类、5 万+ 方法）。
//! 每个请求重解析会让"点开一个类"变成"等一次完整解析"。所以
//! [`crate::AppState::dex_entry`] 按名字做 memo：**失败也缓存**
//! （一个畸形 DEX 不会因为用户多刷新几次就变得可以解析，重试只是浪费 CPU）。

use std::collections::HashMap;
use std::sync::{Arc, Mutex};

use axum::extract::{Query, State};
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use axum::Json;
use serde::{Deserialize, Serialize};

use crate::{error_response, AppState};

/// 类列表默认每页条数。
const DEFAULT_CLASSES_PAGE: usize = 200;

/// 类列表每页上限。请求更大的值会被 clamp 到这个数（并在响应里如实给出）。
const MAX_CLASSES_PAGE: usize = 1000;

/// 方法视图里指令的默认上限。
///
/// 一个真实方法可以有大几千条指令（真实 APK 上见过 5000+）。整个方法一次性
/// 返回会让"点开方法"变成一次几 MB 的响应，而前端一次也显示不了那么多。
const DEFAULT_INSN_PAGE: usize = 500;

/// 方法视图里指令的上限。
const MAX_INSN_PAGE: usize = 5000;

/// 分页说明。**页码越界也要说** —— 否则一个"空页"看起来就像
/// "这个 DEX 里没有类"，而那与"翻过头了"是两件完全不同的事（CLAUDE.md §7）。
///
/// 整份都在这一页里时返回 `None`：没有截断就不该有噪声。
fn paging_note(label: &str, offset: usize, shown: usize, total: usize) -> Option<String> {
    if shown >= total {
        return None;
    }
    if shown == 0 {
        return Some(format!(
            "offset={offset} 已越过末尾（共 {total} 个{label}），本页为空"
        ));
    }
    Some(format!(
        "本次只返回第 {offset}–{} 个{label}（共 {total} 个），用 offset/limit 翻页",
        offset + shown
    ))
}

/// 一个已解析的 DEX 输入（成员名 + 原始字节 + 结构）。
///
/// 三样放在一起缓存：字节是解压出来的（真实 APK 的 `classes.dex` 有十几 MB），
/// 结构又完全依赖它 —— 分开缓存只会让两者可能不一致。
pub(crate) struct DexEntry {
    /// 成员名（单文件目标时是文件名）。
    pub(crate) name: String,
    /// APK 命名约定下的角色标签；不适用时为 `None`（**不是**"没用"）。
    pub(crate) role: Option<String>,
    /// 原始字节（已按内容确认是 DEX）。
    pub(crate) bytes: Arc<[u8]>,
    /// 解析出来的结构模型。
    pub(crate) structure: bitflip_core::dex::DexStructure,
}

/// 按名字缓存的 DEX 输入表。
pub(crate) type DexCache = Mutex<HashMap<String, Result<Arc<DexEntry>, String>>>;

/// 本次目标的 DEX 输入名（以及 APK 角色标签）。
///
/// 归档目标：成员名以 `.dex` 结尾（大小写不敏感）的那些，**按容器里的顺序**，
/// 名字与顺序都原样保留（`classes2.dex` 不重编成 `classes1.dex` —— 文件名里的
/// 号码是构建产物的一部分）。
///
/// 单文件目标（`bitflip foo.dex`）：目标本身，名字取文件名。
///
/// 找不到任何 DEX 输入时报错而不是返回空列表：空列表会让界面显示"这个目标里
/// 没有 DEX"，而那与"我们没有做这一步"在界面上长得一模一样（CLAUDE.md §7）。
pub(crate) fn input_names(
    session: &bitflip_core::Session,
) -> Result<Vec<(String, Option<String>)>, String> {
    if session.info().is_archive() {
        let names: Vec<(String, Option<String>)> = session
            .members()
            .iter()
            .filter(|member| bitflip_core::dex::is_dex_member_name(&member.name))
            .map(|member| {
                (
                    member.name.clone(),
                    bitflip_core::dex::apk_role_label(&member.name),
                )
            })
            .collect();
        if names.is_empty() {
            return Err(format!(
                "目标 {:?} 里没有以 .dex 结尾的成员（成员数 {}）：DEX 视图需要 APK 或 .dex 文件",
                session.info().path,
                session.members().len()
            ));
        }
        return Ok(names);
    }

    Ok(vec![(target_file_name(session), None)])
}

/// 单文件目标在界面上的名字（文件名；没有文件名就用整条路径）。
pub(crate) fn target_file_name(session: &bitflip_core::Session) -> String {
    let info = session.info();
    std::path::Path::new(&info.path)
        .file_name()
        .map(|name| name.to_string_lossy().to_string())
        .unwrap_or_else(|| info.path.clone())
}

/// 读出并解析一个 DEX 输入。
///
/// 归档成员走 [`bitflip_core::dex::read_member`]（它按**内容**复核是不是 DEX ——
/// 名字可以骗人，内容不会）；单文件目标从磁盘读 `TargetInfo.path` 并同样复核内容。
pub(crate) fn load_input(
    session: &bitflip_core::Session,
    name: &str,
) -> Result<Arc<DexEntry>, String> {
    let role = bitflip_core::dex::apk_role_label(name);
    let bytes: Arc<[u8]> = if session.info().is_archive() {
        bitflip_core::dex::read_member(session, name).map_err(|error| error.to_string())?
    } else {
        read_dex_file(&session.info().path)?
    };
    let structure = bitflip_core::dex::parse(&bytes)
        .map_err(|error| format!("把 {name} 当 DEX 解析失败：{error}"))?;
    Ok(Arc::new(DexEntry {
        name: name.to_string(),
        role,
        bytes,
        structure,
    }))
}

/// 从磁盘读一个文件，并把 IO 错误写成中文短句。
fn read_dex_file(path: &str) -> Result<Arc<[u8]>, String> {
    let bytes = std::fs::read(path).map_err(|error| format!("读 {path} 失败：{error}"))?;
    Ok(bytes.into())
}

/// 找到要操作的那个 DEX 输入。
///
/// `member` 必填：三个端点都只看一个 DEX（理由见模块文档）。名字不存在时
/// 把可用名字列出来 —— "没找到"与"你没告诉我看哪个"要能区分。
fn pick<'a>(
    inputs: &'a [Arc<DexEntry>],
    member: Option<&str>,
) -> Result<&'a Arc<DexEntry>, String> {
    let names = || {
        inputs
            .iter()
            .map(|input| input.name.as_str())
            .collect::<Vec<_>>()
            .join("、")
    };
    let Some(member) = member.filter(|name| !name.is_empty()) else {
        return Err(format!(
            "缺少 member 参数：本次目标有 {} —— 请指定看哪一个",
            names()
        ));
    };
    inputs
        .iter()
        .find(|input| input.name == member)
        .ok_or_else(|| format!("没有名为 {member:?} 的 DEX 输入（可用：{}）", names()))
}

/// DEX 输入列表响应：`GET /api/dex/inputs`。
#[derive(Serialize)]
struct InputsResponse {
    /// 服务层 wire 版本（与 `/api/health` 同一个号）。
    server_api_version: u32,
    /// DEX 报告的字段版本。
    format_version: u32,
    /// 本次会话的目标路径。
    target: String,
    /// 逐个 DEX 输入。
    inputs: Vec<InputWire>,
    /// 说明（例如"这不是 DEX 目标"以外的上下文）。
    notes: Vec<String>,
}

/// 单个 DEX 输入的 wire 表示。
#[derive(Serialize)]
struct InputWire {
    /// 成员名（标签页就用它）。
    name: String,
    /// APK 命名约定下的角色标签；不适用时 `null`。
    role: Option<String>,
    /// 原始字节长度（解压后）。
    size: u64,
    /// 类数。
    class_count: usize,
    /// 方法数。
    method_count: usize,
    /// 其中**有字节码**的方法数。
    method_count_with_code: usize,
    /// 解析器的容错记录（有内容即表示"解析时跳过了什么"）。
    notes: Vec<String>,
}

/// DEX 输入列表：`GET /api/dex/inputs`。
///
/// 标签页的数据源。**每个输入的解析降级都单独带在 `notes` 里**：
/// 真实 APK 上 `classes.dex` 与 `classes2.dex` 各有一处
/// `OutOfOrder { pool: StringIds }` 容忍式跳过，那些说明必须跟着**那一个**文件，
/// 而不是合成一条总说明（否则用户没法判断是哪份 dex 的结论要打折）。
pub(crate) async fn inputs(State(state): State<AppState>) -> Response {
    let entries = match state.dex_inputs() {
        Ok(entries) => entries,
        Err(reason) => return error_response(StatusCode::BAD_REQUEST, &reason),
    };

    let inputs = entries
        .iter()
        .map(|entry| InputWire {
            name: entry.name.clone(),
            role: entry.role.clone(),
            size: entry.bytes.len() as u64,
            class_count: entry.structure.class_count(),
            method_count: entry.structure.method_count(),
            method_count_with_code: entry.structure.method_count_with_code(),
            notes: entry.structure.notes.clone(),
        })
        .collect();

    let target = state
        .target()
        .map(|info| info.path.clone())
        .unwrap_or_default();

    Json(InputsResponse {
        server_api_version: crate::SERVER_API_VERSION,
        format_version: bitflip_core::dex::DEX_FORMAT_VERSION,
        target,
        inputs,
        notes: Vec::new(),
    })
    .into_response()
}

/// 类列表查询参数。
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct ClassesQuery {
    /// 看哪个 DEX 输入（必填）。
    member: Option<String>,
    /// 从第几条开始（默认 0）。
    offset: Option<usize>,
    /// 取多少条（默认 200，上限 1000）。
    limit: Option<usize>,
    /// 按**描述符子串**过滤（大小写不敏感）；空 = 不过滤。
    search: Option<String>,
}

/// 类列表响应：`GET /api/dex/classes`。
#[derive(Serialize)]
struct ClassesResponse {
    /// 服务层 wire 版本。
    server_api_version: u32,
    /// DEX 报告的字段版本。
    format_version: u32,
    /// 数据来自哪个 DEX 输入。
    member: String,
    /// 匹配 `search` 的类总数（**分页前**）。
    total: usize,
    /// 本页第一条在匹配集合里的下标。
    offset: usize,
    /// 请求的条数（已 clamp）；响应里给的是生效值。
    limit: usize,
    /// 本页类。
    classes: Vec<ClassRefWire>,
    /// 说明（例如 DEX 自身的容错记录）。
    notes: Vec<String>,
}

/// 类列表里的一项。
#[derive(Serialize)]
struct ClassRefWire {
    /// smali 描述符（`Lcom/Foo;`）。
    descriptor: String,
    /// 短名（`Foo`）。
    short_name: Option<String>,
    /// 方法数。
    method_count: usize,
    /// 其中有字节码的方法数。
    methods_with_code: usize,
}

/// 类列表：`GET /api/dex/classes?member=…&offset=…&limit=…&search=…`。
///
/// 这个端点是给**人浏览**用的，所以带过滤与分页：
/// 真实 APK 的一个 DEX 有 7000+ 个类，前端一次全要既传不动也显示不了。
/// `total` 是**过滤后**的总数，`offset`/`limit` 是实际生效的值 —— 前端据此
/// 能说出"共 N 个、这是第 a–b 个"，而不是悄悄只给一页。
pub(crate) async fn classes(
    State(state): State<AppState>,
    Query(query): Query<ClassesQuery>,
) -> Response {
    let entries = match state.dex_inputs() {
        Ok(entries) => entries,
        Err(reason) => return error_response(StatusCode::BAD_REQUEST, &reason),
    };
    let entry = match pick(&entries, query.member.as_deref()) {
        Ok(entry) => entry,
        Err(reason) => return error_response(StatusCode::BAD_REQUEST, &reason),
    };

    let search = query
        .search
        .as_deref()
        .filter(|s| !s.is_empty())
        .map(str::to_lowercase);
    // 描述符拿不到（类定义指向越界的 type_id）时如实跳过并计数，不编一个名字出来。
    let mut skipped = 0usize;
    let mut matched: Vec<(usize, String)> = Vec::new();
    for class in 0..entry.structure.class_count() {
        let Some(descriptor) = entry.structure.class_descriptor(class) else {
            skipped += 1;
            continue;
        };
        if let Some(needle) = search.as_deref() {
            if !descriptor.to_lowercase().contains(needle) {
                continue;
            }
        }
        matched.push((class, descriptor.to_string()));
    }

    let total = matched.len();
    let offset = query.offset.unwrap_or(0).min(total);
    // `limit=0` 与"没给"都取默认值，而不是 clamp 成 1：0 在 HTTP 上更可能是
    // "我没填这个参数"而不是"我就要一条"，静默只给 1 条会让人以为类列表是空的。
    let limit = match query.limit {
        None | Some(0) => DEFAULT_CLASSES_PAGE,
        Some(limit) => limit.min(MAX_CLASSES_PAGE),
    };
    let classes: Vec<ClassRefWire> = matched
        .iter()
        .skip(offset)
        .take(limit)
        .map(|(class, descriptor)| {
            let (method_count, methods_with_code) = entry.structure.class_method_counts(*class);
            ClassRefWire {
                descriptor: descriptor.clone(),
                short_name: entry.structure.class_short_name(*class).map(str::to_string),
                method_count,
                methods_with_code,
            }
        })
        .collect();

    let mut notes = entry.structure.notes.clone();
    if skipped > 0 {
        notes.push(format!(
            "有 {skipped} 个类的描述符解析不出来（类定义指向的 type_id 越界），已如实跳过"
        ));
    }
    if let Some(note) = paging_note("类", offset, classes.len(), total) {
        notes.push(note);
    }

    Json(ClassesResponse {
        server_api_version: crate::SERVER_API_VERSION,
        format_version: bitflip_core::dex::DEX_FORMAT_VERSION,
        member: entry.name.clone(),
        total,
        offset,
        limit,
        classes,
        notes,
    })
    .into_response()
}

/// 类详情查询参数。
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct ClassQuery {
    /// 看哪个 DEX 输入（必填）。
    member: Option<String>,
    /// 类的 smali 描述符（必填，**精确匹配**）。
    descriptor: Option<String>,
}

/// 类详情响应：`GET /api/dex/class`。
#[derive(Serialize)]
struct ClassResponse {
    /// 服务层 wire 版本。
    server_api_version: u32,
    /// DEX 报告的字段版本。
    format_version: u32,
    /// 数据来自哪个 DEX 输入。
    member: String,
    /// 类的 smali 描述符。
    descriptor: String,
    /// 短名。
    short_name: Option<String>,
    /// 超类描述符；`null` 表示**没有**（`java.lang.Object` 自己）或拿不到。
    superclass: Option<String>,
    /// 源码文件名（`class_def` 里可能没有）。
    source_file: Option<String>,
    /// 实例 / 静态字段。
    fields: Vec<FieldWire>,
    /// 方法（含没有字节码的那些，`has_code = false`）。
    methods: Vec<MethodRefWire>,
    /// 说明。
    notes: Vec<String>,
}

/// 字段。
#[derive(Serialize)]
struct FieldWire {
    /// 字段名。
    name: String,
    /// 类型描述符（`I` / `Ljava/lang/String;`）。
    type_descriptor: Option<String>,
    /// 原始 `access_flags`。
    access_flags: u32,
    /// 是否静态。
    is_static: bool,
}

/// 方法的引用（列表用，不含指令）。
#[derive(Serialize)]
struct MethodRefWire {
    /// smali 风格标识（`Lcom/Foo;->bar(I)V`）。
    signature: String,
    /// 方法名。
    name: String,
    /// 原始 `access_flags`。
    access_flags: u32,
    /// 是不是直接方法（`<init>` / private / static）。
    is_direct: bool,
    /// `code_item` 的文件偏移（定长 16 位十六进制）；没有字节码时为 `null`。
    code_off: Option<String>,
    /// 是否有字节码（抽象 / `native` 方法没有，这是**合法结论**）。
    has_code: bool,
}

/// 类详情：`GET /api/dex/class?member=…&descriptor=…`。
///
/// `descriptor` **精确匹配**（与 CLI 同一立场）：短名、子串、参数通配混在一个
/// 返回值里，"命中哪个"就说不清了。写法不像描述符时给格式提示。
pub(crate) async fn class(
    State(state): State<AppState>,
    Query(query): Query<ClassQuery>,
) -> Response {
    let entries = match state.dex_inputs() {
        Ok(entries) => entries,
        Err(reason) => return error_response(StatusCode::BAD_REQUEST, &reason),
    };
    let entry = match pick(&entries, query.member.as_deref()) {
        Ok(entry) => entry,
        Err(reason) => return error_response(StatusCode::BAD_REQUEST, &reason),
    };
    let Some(descriptor) = query.descriptor.as_deref().filter(|s| !s.is_empty()) else {
        return error_response(
            StatusCode::BAD_REQUEST,
            "缺少 descriptor 参数：类要写成 smali 描述符，如 `Lcom/Foo;`（可先用 /api/dex/classes 浏览）",
        );
    };

    let structure = &entry.structure;
    let Some(class) = structure.find_class_by_descriptor(descriptor) else {
        let hint = if descriptor.starts_with('L') && descriptor.ends_with(';') {
            ""
        } else {
            "（只做精确匹配：类要写成 smali 描述符，如 `Lcom/Foo;`）"
        };
        return error_response(
            StatusCode::NOT_FOUND,
            &format!("{} 里没有类 {descriptor}{hint}", entry.name),
        );
    };

    let fields = structure
        .class_fields(class)
        .into_iter()
        .map(|field| {
            let facts = structure.fields.get(field);
            FieldWire {
                name: structure
                    .field_name(field)
                    .map_or_else(|| format!("<字段下标 {field} 无名>"), str::to_string),
                type_descriptor: structure.field_type_descriptor(field).map(str::to_string),
                // 静态与否来自 `class_data` 的分区（`DexField::is_static`），
                // 不在 `field_id` 里 —— 索引本身说明不了任何事。
                access_flags: facts.map_or(0, |f| f.access_flags),
                is_static: facts.is_some_and(|f| f.is_static),
            }
        })
        .collect();

    let methods = structure
        .class_methods(class)
        .into_iter()
        .map(|method| method_ref(structure, method))
        .collect();

    Json(ClassResponse {
        server_api_version: crate::SERVER_API_VERSION,
        format_version: bitflip_core::dex::DEX_FORMAT_VERSION,
        member: entry.name.clone(),
        descriptor: descriptor.to_string(),
        short_name: structure.class_short_name(class).map(str::to_string),
        superclass: structure.superclass_descriptor(class).map(str::to_string),
        source_file: structure.source_file(class).map(str::to_string),
        fields,
        methods,
        notes: structure.notes.clone(),
    })
    .into_response()
}

/// 一个方法的 wire 引用。
fn method_ref(structure: &bitflip_core::dex::DexStructure, method: usize) -> MethodRefWire {
    let facts = structure.methods.get(method);
    let code_off = facts.map_or(0, |m| m.code_off);
    MethodRefWire {
        signature: structure
            .method_signature(method)
            .unwrap_or_else(|| format!("<方法下标 {method} 的签名拼不出来>")),
        name: structure
            .method_name(method)
            .map_or_else(|| format!("<方法下标 {method}>"), str::to_string),
        access_flags: facts.map_or(0, |m| m.access_flags),
        is_direct: facts.is_some_and(|m| m.is_direct),
        code_off: (code_off != 0).then(|| format!("{code_off:016x}")),
        has_code: code_off != 0,
    }
}

/// 方法详情查询参数。
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct MethodQuery {
    /// 看哪个 DEX 输入（必填）。
    member: Option<String>,
    /// 方法的 smali 标识（必填，**精确匹配**）。
    signature: Option<String>,
    /// 从第几条指令开始（默认 0）。
    offset: Option<usize>,
    /// 取多少条指令（默认 500，上限 5000）。
    limit: Option<usize>,
}

/// 一条指令的 wire 表示。
#[derive(Serialize)]
struct InsnWire {
    /// 方法内码元地址（定长 16 位十六进制）。
    address: String,
    /// 原始 opcode 字节。**不是**地址，所以不走 16 位十六进制那套约定。
    opcode: u8,
    /// 渲染出来的文本（`0000: return-void`）。
    text: String,
}

/// 方法详情响应：`GET /api/dex/method`。
#[derive(Serialize)]
struct MethodResponse {
    /// 服务层 wire 版本。
    server_api_version: u32,
    /// DEX 报告的字段版本。
    format_version: u32,
    /// 数据来自哪个 DEX 输入。
    member: String,
    /// smali 风格标识。
    signature: String,
    /// `code_item` 的偏移（定长 16 位十六进制）。
    code_off: Option<String>,
    /// 是否有字节码。`false` 时 `instructions` 为空、`notes` 说明原因 ——
    /// 这是**合法结论**（抽象 / native 方法），不是错误。
    has_code: bool,
    /// 寄存器数。
    registers_size: Option<u16>,
    /// 入参寄存器数。
    ins_size: Option<u16>,
    /// 出参寄存器数。
    outs_size: Option<u16>,
    /// 指令总数（分页前）。
    instruction_count: usize,
    /// 本页第一条指令的下标。
    offset: usize,
    /// 实际生效的每页条数。
    limit: usize,
    /// 本页指令。
    instructions: Vec<InsnWire>,
    /// 符号解析是否开启（当前恒为 `true`：符号解析失败会**保留可数的池索引**
    /// 并计数，而不是整段降级成"不解析"）。
    symbols: bool,
    /// 已知缺口（例如 call-site 的池引用渲染不出来）的操作数个数。
    ///
    /// 与 `instruction_count` 一样是**整个方法**的数，不是本页的 ——
    /// 本页只显示 500 条时，"缺口 3 个"说的仍是整个方法。
    unsupported_operands: usize,
    /// 异常（索引越界、库拒绝解析）的操作数个数（同样整个方法）。
    unavailable_operands: usize,
    /// CFG 文本。
    cfg_text: String,
    /// CFG 块数。
    block_count: usize,
    /// CFG 边数。
    edge_count: usize,
    /// 连不上的边目标个数（**不为 0 时必须让用户看见**）。
    unresolved_edge_targets: usize,
    /// 说明（DEX 的容错记录 + 方法层的说明）。
    notes: Vec<String>,
}

/// 方法详情：`GET /api/dex/method?member=…&signature=…`。
///
/// 指令**分页**：真实方法可以有大几千条指令，一次全给会让响应变成几 MB。
/// `instruction_count` 与 `cfg_text` 始终是**整个方法**的（CFG 截断就没有意义了）。
pub(crate) async fn method(
    State(state): State<AppState>,
    Query(query): Query<MethodQuery>,
) -> Response {
    let entries = match state.dex_inputs() {
        Ok(entries) => entries,
        Err(reason) => return error_response(StatusCode::BAD_REQUEST, &reason),
    };
    let entry = match pick(&entries, query.member.as_deref()) {
        Ok(entry) => entry,
        Err(reason) => return error_response(StatusCode::BAD_REQUEST, &reason),
    };
    let Some(signature) = query.signature.as_deref().filter(|s| !s.is_empty()) else {
        return error_response(
            StatusCode::BAD_REQUEST,
            "缺少 signature 参数：方法要写成 smali 标识，如 `Lcom/Foo;->bar(I)V`（可先用 /api/dex/class 浏览）",
        );
    };

    let structure = &entry.structure;
    let Some(index) = structure.find_method_by_signature(signature) else {
        let hint = if signature.contains("->") && signature.contains('(') {
            ""
        } else {
            "（只做精确匹配：方法要写成 `Lcom/Foo;->bar(I)V`，参数表不能省）"
        };
        return error_response(
            StatusCode::NOT_FOUND,
            &format!("{} 里没有方法 {signature}{hint}", entry.name),
        );
    };

    let code_off = structure.methods.get(index).map_or(0, |m| m.code_off);
    let mut notes = structure.notes.clone();
    let offset = query.offset.unwrap_or(0);
    // 与类列表同一条：`0` 当作"没给"，不当成"只要一条"。
    let limit = match query.limit {
        None | Some(0) => DEFAULT_INSN_PAGE,
        Some(limit) => limit.min(MAX_INSN_PAGE),
    };

    // 没有字节码：这是合法结论，不是错误。给一份说明而不是"空结果"。
    if code_off == 0 {
        notes.push(
            "这个方法没有字节码（code_off = 0）：抽象方法或 native 方法，没有指令与 CFG。"
                .to_string(),
        );
        return Json(MethodResponse {
            server_api_version: crate::SERVER_API_VERSION,
            format_version: bitflip_core::dex::DEX_FORMAT_VERSION,
            member: entry.name.clone(),
            signature: signature.to_string(),
            code_off: None,
            has_code: false,
            registers_size: None,
            ins_size: None,
            outs_size: None,
            instruction_count: 0,
            offset: 0,
            limit,
            instructions: Vec::new(),
            symbols: true,
            unsupported_operands: 0,
            unavailable_operands: 0,
            cfg_text: String::new(),
            block_count: 0,
            edge_count: 0,
            unresolved_edge_targets: 0,
            notes,
        })
        .into_response();
    }

    let view = match bitflip_core::dex::project_method(&entry.bytes, code_off) {
        Ok(view) => view,
        Err(error) => {
            return error_response(
                StatusCode::BAD_REQUEST,
                &format!("投影方法 {signature}（code_off={code_off:#x}）失败：{error}"),
            )
        }
    };

    // 逐条渲染（与 CLI 同一条路：符号解析失败保留可数的池索引并计数）。
    //
    // 这里没有调 `render_instructions_with_symbols`（整列一次渲染、只交回总数），
    // 因为它不保留每条指令的文本下标，而本端点要按 `offset`/`limit` 取页。
    // 两边用的是同一个 `DexSymbolOutcome` 口径，所以计数对得上。
    // 代价是即便只要一页也会把整个方法渲染一遍 —— 这是**有意的**：
    // `unsupported_operands` / `unavailable_operands` 承诺的是整个方法的账，
    // 只渲染本页会让那两个数随翻页变化，那比多花一点 CPU 危险得多。
    let symbols = structure.symbols();
    let mut rows: Vec<InsnWire> = Vec::with_capacity(view.instructions.len());
    let mut unsupported = 0usize;
    let mut unavailable = 0usize;
    let mut text = String::new();
    for index in 0..view.instructions.len() {
        text.clear();
        match view
            .instructions
            .render_instruction_with_symbols(index, Some(&symbols), &mut text)
        {
            Ok(Some(bitflip_core::dex::DexSymbolOutcome::Written) | None) => {}
            Ok(Some(bitflip_core::dex::DexSymbolOutcome::NotSupported)) => unsupported += 1,
            Ok(Some(bitflip_core::dex::DexSymbolOutcome::Unavailable)) | Err(_) => unavailable += 1,
        }
        rows.push(InsnWire {
            address: format!(
                "{:016x}",
                view.instructions.addresses.get(index).copied().unwrap_or(0)
            ),
            opcode: view.instructions.opcodes.get(index).copied().unwrap_or(0),
            text: text.clone(),
        });
    }

    let mut cfg_text = String::new();
    bitflip_core::dex::render_cfg_text(&view, &mut cfg_text);

    let instruction_count = rows.len();
    let page: Vec<InsnWire> = rows.into_iter().skip(offset).take(limit).collect();
    if let Some(note) = paging_note("条指令", offset, page.len(), instruction_count) {
        notes.push(note);
    }
    if unsupported > 0 {
        notes.push(format!(
            "有 {unsupported} 个操作数是已知缺口（例如 call-site），按原始池索引输出"
        ));
    }
    if unavailable > 0 {
        notes.push(format!(
            "有 {unavailable} 个操作数解析不出来（索引越界或库拒绝解析），按原始池索引输出"
        ));
    }
    if !view.cfg.unresolved_edge_targets.is_empty() {
        notes.push(format!(
            "CFG 有 {} 条边的目标不是指令起点，已逐条记在 cfg_text 的末尾",
            view.cfg.unresolved_edge_targets.len()
        ));
    }

    Json(MethodResponse {
        server_api_version: crate::SERVER_API_VERSION,
        format_version: bitflip_core::dex::DEX_FORMAT_VERSION,
        member: entry.name.clone(),
        signature: signature.to_string(),
        code_off: Some(format!("{code_off:016x}")),
        has_code: true,
        registers_size: Some(view.registers_size),
        ins_size: Some(view.ins_size),
        outs_size: Some(view.outs_size),
        instruction_count,
        offset,
        limit,
        instructions: page,
        symbols: true,
        unsupported_operands: unsupported,
        unavailable_operands: unavailable,
        block_count: view.cfg.block_ids.len(),
        edge_count: view.cfg.edge_targets.len(),
        unresolved_edge_targets: view.cfg.unresolved_edge_targets.len(),
        cfg_text,
        notes,
    })
    .into_response()
}
