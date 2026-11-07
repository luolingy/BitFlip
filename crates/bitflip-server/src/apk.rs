//! APK 端点（M3）：`/api/apk/manifest`、`/api/apk/resources`、`/api/apk/resource`。
//!
//! # 为什么是独立的端点族
//!
//! 与 DEX（`/api/dex/*`）同一条理由：清单与资源表是 **APK 容器层**的东西，
//! 不是"某个地址段的对象"。塞进 `/api/sections` / `/api/insns` 会让前端拿到
//! "看起来正常、实际没意义"的数据（那里的一切都以线性地址为键，而清单和
//! 资源表没有地址）。
//!
//! # 缓存
//!
//! 解析一张真实 `resources.arsc`（1 MB 级）是亚秒级工作，但值查询
//! （`/api/apk/resource?id=…`）每次都要重建表 —— 与 DEX 缓存同一条理由，
//! 按成员名做 memo：**失败也缓存**（坏表不会因为多刷新几次就变好）。

use std::collections::HashMap;
use std::sync::{Arc, Mutex};

use axum::extract::{Query, State};
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use axum::Json;
use serde::Deserialize;

use crate::{error_response, AppState};

/// 资源表缓存：成员名 → 解析结果（失败也缓存）。
///
/// 值是 `Mutex<ArscTable>` 而不是裸 `ArscTable`：库的 `ARSC` 里有一个
/// `RefCell` 名字缓存（不 `Sync`），`Arc<Mutex<_>>` 把它包成可共享的。
/// 查询拿锁、查完就放 —— 查询本身是纯内存查找，不长时间持锁。
pub(crate) type ResourcesCache = Mutex<
    HashMap<String, Result<Arc<std::sync::Mutex<bitflip_core::resources::ArscTable>>, String>>,
>;

/// 从会话里取 `resources.arsc` 字节（与 core 的读取同一入口，错误翻成 String）。
fn resources_bytes(
    session: &bitflip_core::Session,
    member: Option<&str>,
) -> Result<(std::sync::Arc<[u8]>, String), String> {
    let wanted = member.unwrap_or(bitflip_core::axml::RESOURCES_MEMBER);
    let (bytes, found) = session
        .member_bytes(wanted)
        .map_err(|error| error.to_string())?;
    Ok((bytes, found.name))
}

/// 取（并缓存）一份可查询的资源表。返回成员名、字节数与表。
fn cached_table(
    state: &AppState,
    member: Option<&str>,
) -> Result<
    (
        String,
        usize,
        Arc<std::sync::Mutex<bitflip_core::resources::ArscTable>>,
    ),
    String,
> {
    let session = state.session()?;
    let (bytes, name) = resources_bytes(&session, member)?;
    let size = bytes.len();

    let cache = Arc::clone(&state.resources);
    let mut guard = cache
        .lock()
        .map_err(|_| "资源表缓存锁中毒（上一次解析在持锁时 panic）".to_string())?;
    if let Some(cached) = guard.get(&name) {
        let table = cached.clone()?;
        return Ok((name, size, table));
    }
    let parsed = bitflip_core::resources::ArscStructure::parse_table(&bytes)
        .map_err(|error| format!("把 {name} 当资源表解析失败：{error}"));
    let parsed = match parsed {
        Ok(table) => Ok(Arc::new(std::sync::Mutex::new(table))),
        Err(reason) => Err(reason),
    };
    guard.insert(name.clone(), parsed);
    let table = guard
        .get(&name)
        .and_then(|entry| entry.as_ref().ok())
        .cloned()
        .expect("刚插入过");
    Ok((name, size, table))
}

/// `GET /api/apk/resources`：资源表结构快照（与 CLI `resources --json` 同一形状）。
pub(crate) async fn resources(
    State(state): State<AppState>,
    Query(params): Query<ResourceParams>,
) -> Response {
    let (name, size, table) = match cached_table(&state, params.member.as_deref()) {
        Ok(found) => found,
        Err(reason) => return error_response(StatusCode::BAD_REQUEST, &reason),
    };
    let structure = table
        .lock()
        .map(|table| table.structure.clone())
        .map_err(|_| "资源表锁中毒".to_string());
    let structure = match structure {
        Ok(structure) => structure,
        Err(reason) => return error_response(StatusCode::INTERNAL_SERVER_ERROR, &reason),
    };
    Json(serde_json::json!({
        "server_api_version": crate::SERVER_API_VERSION,
        "format_version": 1,
        "member": name,
        "size": size,
        "structure": structure,
    }))
    .into_response()
}

/// `GET /api/apk/resource`：按资源 id 查一条（名字 + 值）。
pub(crate) async fn resource(
    State(state): State<AppState>,
    Query(params): Query<ResourceIdParams>,
) -> Response {
    let Some(id_text) = params.id.as_deref() else {
        return error_response(
            StatusCode::BAD_REQUEST,
            "缺 id 参数：/api/apk/resource?id=0x7f010000",
        );
    };
    // 与 core::resources::lookup_resource 同一条解析规则（三种写法）。
    let id = match parse_resource_id(id_text) {
        Ok(id) => id,
        Err(reason) => return error_response(StatusCode::BAD_REQUEST, &reason),
    };
    let (name, _size, table) = match cached_table(&state, params.member.as_deref()) {
        Ok(found) => found,
        Err(reason) => return error_response(StatusCode::BAD_REQUEST, &reason),
    };
    let lookup = table.lock().map(|table| {
        serde_json::json!({
            "name": table.resource_name(id),
            "value": table.resource_value(id),
        })
    });
    let lookup = match lookup {
        Ok(lookup) => lookup,
        Err(_) => {
            return error_response(StatusCode::INTERNAL_SERVER_ERROR, "资源表锁中毒");
        }
    };
    Json(serde_json::json!({
        "server_api_version": crate::SERVER_API_VERSION,
        "member": name,
        "id": format!("{id:#010x}"),
        "name": lookup["name"],
        "value": lookup["value"],
    }))
    .into_response()
}

/// `GET /api/apk/manifest`：清单字段摘要（与 CLI `manifest --json` 同一形状）。
pub(crate) async fn manifest(State(state): State<AppState>) -> Response {
    let session = match state.session() {
        Ok(session) => session,
        Err(reason) => return error_response(StatusCode::BAD_REQUEST, &reason),
    };
    match bitflip_core::axml::read_manifest(&session, None) {
        Ok(report) => Json(serde_json::json!({
            "server_api_version": crate::SERVER_API_VERSION,
            "format_version": 1,
            "member": report.member,
            "size": report.size,
            "headline": report.headline(),
            // `ManifestFacts` 没实现 `Serialize`（它没有 derive）—— 字段摘要
            // 逐项摆出来，与 CLI `manifest --json` 的 wire 完全同形。
            "facts": facts_wire(&report.facts),
        }))
        .into_response(),
        Err(error) => error_response(StatusCode::BAD_REQUEST, &error.to_string()),
    }
}

/// 清单字段摘要 → wire（与 CLI `manifest --json` 同一形状、同一键序）。
fn facts_wire(facts: &bitflip_core::axml::ManifestFacts) -> serde_json::Value {
    serde_json::json!({
        "root": facts.root,
        "package": facts.package,
        "version_code": facts.version_code,
        "version_name": facts.version_name,
        "min_sdk": facts.min_sdk,
        "target_sdk": facts.target_sdk,
        "main_activities": facts.main_activities,
        "activities": facts.activities,
        "services": facts.services,
        "receivers": facts.receivers,
        "providers": facts.providers,
        "permissions": facts.permissions,
        "unresolved_references": facts.unresolved_references,
        "notes": facts.notes,
    })
}

/// `/api/apk/resources` 的查询参数。
#[derive(Debug, Deserialize)]
pub(crate) struct ResourceParams {
    /// 归档成员名；缺省用 `resources.arsc`。
    pub member: Option<String>,
}

/// `/api/apk/resource` 的查询参数。
#[derive(Debug, Deserialize)]
pub(crate) struct ResourceIdParams {
    /// 资源 id（`0x7f010000` / `7f010000` / 十进制）。
    pub id: Option<String>,
    /// 归档成员名；缺省用 `resources.arsc`。
    pub member: Option<String>,
}

/// 资源 id 的三种写法 → u32（与 core 的 `lookup_resource` 同一条规则；
/// 两处各写一份迟早分叉 —— 但 core 的版本返回 wire，这里只需要 id，
/// 抽公共函数要连着错误文本一起搬，收益小于两条 10 行的规则。**记入
/// 设计文档：改这里必须同步改 core**）。
fn parse_resource_id(text: &str) -> Result<u32, String> {
    let normalized = text.trim().trim_start_matches('@');
    let parsed = if let Some(hex) = normalized
        .strip_prefix("0x")
        .or_else(|| normalized.strip_prefix("0X"))
    {
        u32::from_str_radix(hex, 16)
    } else if normalized.chars().all(|c| c.is_ascii_hexdigit()) && normalized.len() == 8 {
        u32::from_str_radix(normalized, 16)
    } else {
        normalized.parse::<u32>()
    };
    parsed.map_err(|_| {
        format!("{text} 不是资源 id：要 8 位十六进制（`0x7f010000` / `7f010000`）或十进制")
    })
}
