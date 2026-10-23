//! 打补丁端点（`bitflip-patch` 的 HTTP 门面）。
//!
//! # 安全边界（这一段很要紧，先说清）
//!
//! * `plan` 只读：只解析目标、生成补丁计划，**一行不写盘**。
//! * `apply` 会写盘，所以它**要求请求体里显式带 `confirm_unlock: true`**。
//!   这就是 Web UI 上"解锁"按钮对应的东西 —— 门在服务端，不在前端。
//!   不带（或 `false`）一律 400，绝不会"忘了点按钮就偷偷写了"。
//! * 即使 `apply`，也只写 `xxx.patched` 副本，**原文件在磁盘上始终不动**。
//! * 两条路由都挂在 `require_token` 之下（和别的 API 一样）。

use axum::extract::State;
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use axum::Json;

use super::{error_response, AppState};

/// 一处改动的 wire 形式：`{ "vaddr": "0x...", "new_hex": "9090" }`。
#[derive(Debug, serde::Deserialize)]
pub struct EditWire {
    /// 虚拟地址（十进制或 `0x` 十六进制字符串都行）。
    pub vaddr: String,
    /// 新字节（十六进制字符串，偶数位）。
    pub new_hex: String,
}

/// `POST /api/patch/plan` 的请求体。
#[derive(Debug, serde::Deserialize)]
pub struct PlanBody {
    /// 逐处改动。
    pub edits: Vec<EditWire>,
}

/// `POST /api/patch/apply` 的请求体。
#[derive(Debug, serde::Deserialize)]
pub struct ApplyBody {
    /// 逐处改动。
    pub edits: Vec<EditWire>,
    /// **显式解锁**：必须是 `true` 才会写盘。缺省/`false` 一律拒绝。
    #[serde(default)]
    pub confirm_unlock: bool,
}

/// 把 wire 的一串改动解析成 `bitflip-patch` 要的 `(vaddr, bytes)`。
fn parse_edits(edits: &[EditWire]) -> Result<Vec<(u64, Vec<u8>)>, String> {
    if edits.is_empty() {
        return Err("没有改动：edits 不能为空".to_string());
    }
    let mut out = Vec::with_capacity(edits.len());
    for (index, edit) in edits.iter().enumerate() {
        let vaddr = parse_addr(&edit.vaddr).ok_or_else(|| {
            format!(
                "第 {} 处改动的地址 {:?} 无法解析（十进制或 0x 十六进制）",
                index + 1,
                edit.vaddr
            )
        })?;
        let bytes = parse_hex(&edit.new_hex)
            .map_err(|reason| format!("第 {} 处改动的新字节无法解析：{reason}", index + 1))?;
        if bytes.is_empty() {
            return Err(format!("第 {} 处改动的新字节为空", index + 1));
        }
        out.push((vaddr, bytes));
    }
    Ok(out)
}

fn parse_addr(text: &str) -> Option<u64> {
    let text = text.trim();
    let cleaned = text.strip_prefix("0x").or_else(|| text.strip_prefix("0X"));
    match cleaned {
        Some(hex) => u64::from_str_radix(hex, 16).ok(),
        None => text.parse::<u64>().ok(),
    }
}

fn parse_hex(text: &str) -> Result<Vec<u8>, String> {
    let digits: Vec<char> = text.chars().filter(|c| !c.is_whitespace()).collect();
    if digits.is_empty() {
        return Err("字节为空".to_string());
    }
    if !digits.len().is_multiple_of(2) {
        return Err(format!("十六进制必须偶数位，实际 {} 位", digits.len()));
    }
    let mut out = Vec::with_capacity(digits.len() / 2);
    let mut i = 0;
    while i < digits.len() {
        let pair: String = [digits[i], digits[i + 1]].iter().collect();
        let byte = u8::from_str_radix(&pair, 16).map_err(|_| format!("不是十六进制：{pair:?}"))?;
        out.push(byte);
        i += 2;
    }
    Ok(out)
}

fn hex_bytes(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        out.push_str(&format!("{byte:02x}"));
    }
    out
}

/// 目标的磁盘路径。没有目标时给一句人话。
fn target_path(state: &AppState) -> Result<std::path::PathBuf, String> {
    state
        .target()
        .map(|info| std::path::PathBuf::from(&info.path))
        .ok_or_else(|| "本次会话没有打开目标".to_string())
}

/// 打开打补丁目标，把 `PatchError` 转成一句可读的话（各端点共用）。
fn open_target(path: &std::path::Path) -> Result<bitflip_patch::PatchTarget, String> {
    bitflip_patch::PatchTarget::open(path)
        .map_err(|error| format!("打开目标失败（可能是容器/归档或不支持的格式）：{error}"))
}

/// `POST /api/patch/plan`：只读预览。返回计划 diff，永不写盘。
pub(super) async fn plan(State(state): State<AppState>, Json(body): Json<PlanBody>) -> Response {
    let edits = match parse_edits(&body.edits) {
        Ok(edits) => edits,
        Err(reason) => return error_response(StatusCode::BAD_REQUEST, &reason),
    };
    let path = match target_path(&state) {
        Ok(path) => path,
        Err(reason) => return error_response(StatusCode::BAD_REQUEST, &reason),
    };
    let target = match open_target(&path) {
        Ok(target) => target,
        Err(reason) => return error_response(StatusCode::BAD_REQUEST, &reason),
    };
    let plan = match target.plan(&edits) {
        Ok(plan) => plan,
        Err(error) => return error_response(StatusCode::BAD_REQUEST, &error.to_string()),
    };
    Json(plan_json(&target, &plan)).into_response()
}

/// `POST /api/patch/apply`：**需显式 `confirm_unlock: true`**；写 `xxx.patched` 副本。
pub(super) async fn apply(State(state): State<AppState>, Json(body): Json<ApplyBody>) -> Response {
    // 第一道：显式解锁。门在这里，不在前端。
    if !body.confirm_unlock {
        return error_response(
            StatusCode::BAD_REQUEST,
            "写补丁需要显式解锁：请在请求体里带 `confirm_unlock: true`（UI 上是那个「解锁」按钮）",
        );
    }
    let edits = match parse_edits(&body.edits) {
        Ok(edits) => edits,
        Err(reason) => return error_response(StatusCode::BAD_REQUEST, &reason),
    };
    let path = match target_path(&state) {
        Ok(path) => path,
        Err(reason) => return error_response(StatusCode::BAD_REQUEST, &reason),
    };
    let mut target = match open_target(&path) {
        Ok(target) => target,
        Err(reason) => return error_response(StatusCode::BAD_REQUEST, &reason),
    };
    let plan = match target.plan(&edits) {
        Ok(plan) => plan,
        Err(error) => return error_response(StatusCode::BAD_REQUEST, &error.to_string()),
    };
    target.unlock();
    let report = match target.apply(&plan) {
        Ok(report) => report,
        Err(error) => return error_response(StatusCode::CONFLICT, &error.to_string()),
    };

    Json(serde_json::json!({
        "ok": true,
        "written": true,
        "copy_path": report.copy_path.to_string_lossy(),
        "original_path": path.to_string_lossy(),
        "changed_bytes": report.changed_bytes,
        "segments": report.segments,
        "sections": report.sections,
        "size_before": report.size_before,
        "size_after": report.size_after,
        "original_untouched": true,
    }))
    .into_response()
}

/// 把 `PatchPlan` 投影成稳定的 wire JSON。
fn plan_json(
    target: &bitflip_patch::PatchTarget,
    plan: &bitflip_patch::PatchPlan,
) -> serde_json::Value {
    let sites: Vec<serde_json::Value> = plan
        .sites
        .iter()
        .map(|site| {
            serde_json::json!({
                "vaddr": format!("{:#018x}", site.vaddr),
                "file_offset": site.file_offset,
                "original": hex_bytes(&site.original),
                "new": hex_bytes(&site.new),
                "segment": site.segment,
                "section": site.section,
            })
        })
        .collect();
    serde_json::json!({
        "ok": true,
        "written": false,
        "target": target.path().to_string_lossy(),
        "kind": target.kind().as_str(),
        "copy_path": plan.copy_path.to_string_lossy(),
        "changed_bytes": plan.changed_bytes(),
        "segments": plan.touched_segments(),
        "sections": plan.touched_sections(),
        "sites": sites,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;

    #[test]
    fn parse_hex_even_and_odd() {
        assert_eq!(parse_hex("9090").unwrap(), vec![0x90, 0x90]);
        assert!(parse_hex("909").is_err());
        assert!(parse_hex("zz").is_err());
    }

    #[test]
    fn parse_addr_decimal_and_hex() {
        assert_eq!(parse_addr("4198400"), Some(0x401000));
        assert_eq!(parse_addr("0x401000"), Some(0x401000));
        assert_eq!(parse_addr("nope"), None);
    }

    #[test]
    fn parse_edits_rejects_empty_and_bad() {
        assert!(parse_edits(&[]).is_err());
        let bad = EditWire {
            vaddr: "nope".to_string(),
            new_hex: "90".to_string(),
        };
        assert!(parse_edits(&[bad]).is_err());
    }

    /// 手拼一个最小 ELF64 可执行文件（一个 PT_LOAD，文件 0x1000 起 0x100 字节填 0xAA）。
    fn minimal_elf64_exec() -> Vec<u8> {
        let mut bytes = vec![0u8; 0x1100];
        bytes[0..4].copy_from_slice(b"\x7fELF");
        bytes[4] = 2;
        bytes[5] = 1;
        bytes[6] = 1;
        bytes[16..18].copy_from_slice(&2u16.to_le_bytes());
        bytes[18..20].copy_from_slice(&62u16.to_le_bytes());
        bytes[20..24].copy_from_slice(&1u32.to_le_bytes());
        bytes[24..32].copy_from_slice(&0x401000u64.to_le_bytes());
        bytes[32..40].copy_from_slice(&0x40u64.to_le_bytes());
        bytes[52..54].copy_from_slice(&64u16.to_le_bytes());
        bytes[54..56].copy_from_slice(&56u16.to_le_bytes());
        bytes[56..58].copy_from_slice(&1u16.to_le_bytes());
        let ph = 0x40;
        bytes[ph..ph + 4].copy_from_slice(&1u32.to_le_bytes());
        bytes[ph + 4..ph + 8].copy_from_slice(&5u32.to_le_bytes());
        bytes[ph + 8..ph + 16].copy_from_slice(&0x1000u64.to_le_bytes());
        bytes[ph + 16..ph + 24].copy_from_slice(&0x401000u64.to_le_bytes());
        bytes[ph + 24..ph + 32].copy_from_slice(&0x401000u64.to_le_bytes());
        bytes[ph + 32..ph + 40].copy_from_slice(&0x100u64.to_le_bytes());
        bytes[ph + 40..ph + 48].copy_from_slice(&0x100u64.to_le_bytes());
        bytes[ph + 48..ph + 56].copy_from_slice(&0x1000u64.to_le_bytes());
        for byte in &mut bytes[0x1000..0x1100] {
            *byte = 0xAA;
        }
        bytes
    }

    fn state_with_elf(dir: &std::path::Path) -> (AppState, std::path::PathBuf) {
        let path = dir.join("sample.elf");
        std::fs::write(&path, minimal_elf64_exec()).expect("写入样本");
        let session = Arc::new(
            bitflip_core::Session::open(&path, bitflip_core::OpenOptions::default())
                .expect("打开样本"),
        );
        (AppState::new("tok", None).with_session(session), path)
    }

    fn one_edit() -> Vec<EditWire> {
        vec![EditWire {
            vaddr: "0x401000".to_string(),
            new_hex: "9090".to_string(),
        }]
    }

    #[tokio::test]
    async fn apply_without_confirm_unlock_is_rejected_and_writes_nothing() {
        let dir = tempfile::tempdir().expect("tempdir");
        let (state, path) = state_with_elf(dir.path());
        let body = ApplyBody {
            edits: one_edit(),
            confirm_unlock: false,
        };
        let response = apply(State(state), Json(body)).await;
        assert_eq!(
            response.status(),
            StatusCode::BAD_REQUEST,
            "未确认解锁必须被拒"
        );
        assert!(
            !dir.path().join("sample.elf.patched").exists(),
            "被拒时不该写副本"
        );
        // 原文件不变。
        let now = std::fs::read(&path).expect("读原文件");
        assert_eq!(&now[0x1000..0x1002], &[0xAA, 0xAA]);
    }

    #[tokio::test]
    async fn plan_is_read_only_and_reports_sites() {
        let dir = tempfile::tempdir().expect("tempdir");
        let (state, path) = state_with_elf(dir.path());
        let before = std::fs::read(&path).expect("读原文件");
        let response = plan(State(state), Json(PlanBody { edits: one_edit() })).await;
        assert_eq!(response.status(), StatusCode::OK);
        assert!(
            !dir.path().join("sample.elf.patched").exists(),
            "plan 不该写副本"
        );
        let after = std::fs::read(&path).expect("再读原文件");
        assert_eq!(before, after, "plan 不该改原文件");
    }

    #[tokio::test]
    async fn apply_with_confirm_writes_copy_and_keeps_original() {
        let dir = tempfile::tempdir().expect("tempdir");
        let (state, path) = state_with_elf(dir.path());
        let before = std::fs::read(&path).expect("读原文件");
        let body = ApplyBody {
            edits: one_edit(),
            confirm_unlock: true,
        };
        let response = apply(State(state), Json(body)).await;
        assert_eq!(response.status(), StatusCode::OK, "确认后应当写出副本");

        let copy = dir.path().join("sample.elf.patched");
        assert!(copy.exists(), "应当写出 .patched 副本");
        let after = std::fs::read(&path).expect("再读原文件");
        assert_eq!(before, after, "原文件必须不变");
        let patched = std::fs::read(&copy).expect("读副本");
        assert_eq!(&patched[0x1000..0x1002], &[0x90, 0x90], "副本应被改");
    }
}
