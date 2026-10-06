//! M7 服务层脚本端点测试：运行 / 观察 / 取消。
//!
//! # 为什么这组测试要轮询
//!
//! `POST /api/script/run` 是**故意**不等脚本跑完的（否则看不到进度、也停不下来，
//! 还会把 async 线程占住）。所以测试必须像界面那样：发一个 run，然后轮询
//! `status`，直到状态变成 `done`。轮询带上限，卡住就报"脚本没有结束"而不是
//! 无限等 —— 一个挂死的测试比失败的测试更难查。

use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;

use axum::body::{to_bytes, Body};
use axum::http::{Request, StatusCode};
use bitflip_server::{router, AppState, TOKEN_HEADER};
use serde_json::Value;
use tower::ServiceExt;

const TOKEN: &str = "fedcba9876543210fedcba9876543210fedcba9876543210fedcba9876543210";
const PORT: u16 = 8795;

/// 轮询上限。脚本都是毫秒级的，超过这个数说明流程真的卡住了。
const POLL_LIMIT: usize = 200;

struct TempTarget {
    dir: std::path::PathBuf,
    path: std::path::PathBuf,
}

impl Drop for TempTarget {
    fn drop(&mut self) {
        // 用 Drop 而不是在每个测试末尾手写清理：测试 panic 时也要收干净。
        let _ = std::fs::remove_dir_all(&self.dir);
    }
}

/// 一个测试独占的临时目录 + 目标。
///
/// 独占目录是必需的，不是洁癖：工程库路径由**目标内容哈希**派生，
/// 字节相同的合成目标会指向同一个库，测试之间会互相看见对方的标注。
fn write_temp_dir(data: &[u8]) -> TempTarget {
    static COUNTER: AtomicU64 = AtomicU64::new(0);
    let mut dir = std::env::temp_dir();
    dir.push(format!(
        "bitflip-m7-{}-{}",
        std::process::id(),
        COUNTER.fetch_add(1, Ordering::Relaxed)
    ));
    std::fs::create_dir_all(&dir).expect("建临时目录");
    let path = dir.join("m7.elf");
    std::fs::write(&path, data).expect("写入临时目标");
    TempTarget { dir, path }
}

/// 一小段真实代码的合成 ELF：nop; nop; call +0; nop; ret …
fn build_elf_with_code() -> Vec<u8> {
    let code: Vec<u8> = vec![
        0x90, 0x90, 0xE8, 0x00, 0x00, 0x00, 0x00, 0x90, 0xC3, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90,
        0x90,
    ];

    let text_off = 0x1000usize;
    let text_vaddr = 0x401000u64;
    let mut bytes = vec![0u8; 0x2000];

    bytes[0..4].copy_from_slice(b"\x7fELF");
    bytes[4] = 2;
    bytes[5] = 1;
    bytes[6] = 1;
    bytes[16..18].copy_from_slice(&2u16.to_le_bytes());
    bytes[18..20].copy_from_slice(&62u16.to_le_bytes());
    bytes[20..24].copy_from_slice(&1u32.to_le_bytes());
    bytes[24..32].copy_from_slice(&text_vaddr.to_le_bytes());
    bytes[32..40].copy_from_slice(&64u64.to_le_bytes());
    bytes[52..54].copy_from_slice(&64u16.to_le_bytes());
    bytes[54..56].copy_from_slice(&56u16.to_le_bytes());
    bytes[56..58].copy_from_slice(&1u16.to_le_bytes());

    let ph = 64usize;
    bytes[ph..ph + 4].copy_from_slice(&1u32.to_le_bytes());
    bytes[ph + 4..ph + 8].copy_from_slice(&5u32.to_le_bytes());
    bytes[ph + 8..ph + 16].copy_from_slice(&(text_off as u64).to_le_bytes());
    bytes[ph + 16..ph + 24].copy_from_slice(&text_vaddr.to_le_bytes());
    bytes[ph + 24..ph + 32].copy_from_slice(&text_vaddr.to_le_bytes());
    bytes[ph + 32..ph + 40].copy_from_slice(&(code.len() as u64).to_le_bytes());
    bytes[ph + 40..ph + 48].copy_from_slice(&(code.len() as u64).to_le_bytes());
    bytes[ph + 48..ph + 56].copy_from_slice(&0x1000u64.to_le_bytes());

    bytes[text_off..text_off + code.len()].copy_from_slice(&code);
    bytes
}

fn state_with_target(data: &[u8]) -> (AppState, TempTarget) {
    let target = write_temp_dir(data);
    let session = bitflip_core::Session::open(&target.path, bitflip_core::OpenOptions::default())
        .expect("打开目标");
    let state = AppState::new(TOKEN, None)
        .with_session(std::sync::Arc::new(session))
        .with_allowed_origins(bitflip_server::default_allowed_origins(PORT, &[]));
    (state, target)
}

fn post_json(path: &str, body: Value) -> Request<Body> {
    Request::builder()
        .method("POST")
        .uri(path)
        .header(TOKEN_HEADER, TOKEN)
        .header("content-type", "application/json")
        .body(Body::from(body.to_string()))
        .expect("构造请求")
}

fn get_with_token(path: &str) -> Request<Body> {
    Request::builder()
        .uri(path)
        .header(TOKEN_HEADER, TOKEN)
        .body(Body::empty())
        .expect("构造请求")
}

async fn send(state: AppState, request: Request<Body>) -> (StatusCode, Value) {
    let response = router(state).oneshot(request).await.expect("路由响应");
    let status = response.status();
    let bytes = to_bytes(response.into_body(), 8 * 1024 * 1024)
        .await
        .expect("读响应体");
    let body = if bytes.is_empty() {
        Value::Null
    } else {
        serde_json::from_slice(&bytes)
            .unwrap_or_else(|_| Value::String(String::from_utf8_lossy(&bytes).to_string()))
    };
    (status, body)
}

/// 发一个运行请求，返回 202 时的初始状态。
async fn start_run(state: &AppState, source: &str) -> (StatusCode, Value) {
    send(
        state.clone(),
        post_json("/api/script/run", serde_json::json!({ "source": source })),
    )
    .await
}

async fn status_of(state: &AppState) -> Value {
    let (status, body) = send(state.clone(), get_with_token("/api/script/status")).await;
    assert_eq!(status, StatusCode::OK, "状态查询应当成功：{body}");
    body
}

/// 轮询直到运行结束（或超时断言失败）。
async fn wait_for_done(state: &AppState) -> Value {
    for _ in 0..POLL_LIMIT {
        let status = status_of(state).await;
        if status["state"] == "done" {
            return status;
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    panic!(
        "脚本在 {} 次轮询内没有结束：{}",
        POLL_LIMIT,
        status_of(state).await
    );
}

/// 轮询直到进入某个状态。
async fn wait_for_state(state: &AppState, wanted: &str) -> Value {
    for _ in 0..POLL_LIMIT {
        let status = status_of(state).await;
        if status["state"] == wanted {
            return status;
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    panic!(
        "脚本在 {} 次轮询内没有进入 {wanted} 状态：{}",
        POLL_LIMIT,
        status_of(state).await
    );
}

// ---------------------------------------------------------------------------

#[tokio::test]
async fn status_before_any_run_is_idle_with_a_null_run_id() {
    let (state, _target) = state_with_target(&build_elf_with_code());

    let status = status_of(&state).await;
    assert_eq!(status["state"], "idle");
    assert!(status["run_id"].is_null(), "没跑过就不该有运行编号");
    assert_eq!(status["logs"].as_array().map(Vec::len), Some(0));
    assert_eq!(status["can_cancel"], false, "没在跑就不该允许取消");
    assert!(
        status["progress"].is_null(),
        "没跑过就报 null，不能编一个 0% 出来"
    );
}

#[tokio::test]
async fn a_run_reports_its_logs_and_ends_in_done() {
    let (state, _target) = state_with_target(&build_elf_with_code());

    let (status, initial) = start_run(&state, "bitflip.log('你好'); bitflip.warn('注意');").await;
    assert_eq!(
        status,
        StatusCode::ACCEPTED,
        "run 应当立刻接受并返回观测点：{initial}"
    );
    assert!(
        matches!(initial["state"].as_str(), Some("warming" | "running")),
        "刚发出时应当是在跑（预热或执行中），实际：{initial}"
    );

    let done = wait_for_done(&state).await;
    let logs = done["logs"].as_array().expect("logs 应当是数组");
    assert_eq!(logs.len(), 2, "两条日志都应当回传：{done}");
    assert_eq!(logs[0]["level"], "info");
    assert_eq!(logs[0]["message"], "你好");
    assert_eq!(logs[1]["level"], "warn");
    assert_eq!(logs[1]["message"], "注意");
    assert!(done["error"].is_null(), "正常结束不该有错误：{done}");
    assert_eq!(done["can_cancel"], false, "结束了就不该允许取消");
}

#[tokio::test]
async fn a_script_can_read_the_target_through_http() {
    let (state, _target) = state_with_target(&build_elf_with_code());

    start_run(
        &state,
        "bitflip.log(bitflip.target.object); bitflip.log(bitflip.functions.count());",
    )
    .await;
    let done = wait_for_done(&state).await;

    let logs = done["logs"].as_array().expect("logs");
    assert_eq!(logs[0]["message"], "elf", "脚本必须能读到真实的目标信息");
    let count: u64 = logs[1]["message"]
        .as_str()
        .expect("函数数应当是字符串")
        .parse()
        .expect("函数数应当能解析");
    assert!(count > 0, "合成 ELF 里应当至少识别出一个函数");
}

#[tokio::test]
async fn a_script_write_lands_in_the_project_store() {
    let (state, _target) = state_with_target(&build_elf_with_code());

    start_run(
        &state,
        "bitflip.setComment('0000000000401000', '脚本写的注释');",
    )
    .await;
    let done = wait_for_done(&state).await;
    assert!(done["error"].is_null(), "写入应当成功：{done}");
    assert_eq!(done["committed"], 1, "应当提交一条：{done}");
    assert_eq!(done["staged_total"], 1);

    // 走标注端点读回来 —— 证明脚本写进了**用户看得见**的那一个库，
    // 而不是某个只有脚本自己知道的副本。
    //
    // 注意端点的参数是 `from`/`to`（范围查询），不是单个 `address`：
    // 写错参数名不会报错，只会因为默认窗口不含该地址而返回空数组，
    // 看起来像"脚本没写进去"。
    let (status, body) = send(
        state.clone(),
        get_with_token("/api/annotations?from=0000000000401000&to=0000000000402000"),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    let text = body.to_string();
    assert!(
        text.contains("脚本写的注释"),
        "标注端点应当读到脚本写的内容，实际：{text}"
    );
}

#[tokio::test]
async fn a_patch_written_by_a_script_reaches_the_ui_as_bytes() {
    let (state, _target) = state_with_target(&build_elf_with_code());

    start_run(&state, "bitflip.setPatch('0000000000401000', '90 90 90');").await;
    let done = wait_for_done(&state).await;
    assert!(done["error"].is_null(), "补丁应当写入成功：{done}");
    assert_eq!(done["committed"], 1, "应当提交一条：{done}");

    let (status, body) = send(
        state.clone(),
        get_with_token("/api/annotations?from=0000000000401000&to=0000000000402000"),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    let text = body.to_string();
    // `patch_hex` 是界面渲染补丁的内容来源。补丁必须按字节出现在这里，
    // 而不是变成一个 `text` 字段里的字符串 —— 后者界面会当注释渲染。
    assert!(
        text.contains("patch_hex") && text.contains("909090"),
        "补丁必须以十六进制字节到达界面，实际：{text}"
    );
    assert!(text.contains("patch"), "标注类别应当是 patch，实际：{text}");
}

#[tokio::test]
async fn a_syntax_error_comes_back_with_a_line_number() {
    let (state, _target) = state_with_target(&build_elf_with_code());

    start_run(&state, "bitflip.log('第一行');\nthis is not javascript;").await;
    let done = wait_for_done(&state).await;

    let error = &done["error"];
    assert_eq!(
        error["kind"], "syntax",
        "语法错误必须分类成 syntax，实际：{done}"
    );
    assert_eq!(
        error["line"], 2,
        "行号必须指到真正出错的那一行（用户报\"第 2 行错了\"要能核对）"
    );
    assert!(
        error["message"].as_str().is_some_and(|m| !m.is_empty()),
        "错误必须有说明"
    );
}

#[tokio::test]
async fn a_runtime_throw_is_reported_separately_from_a_syntax_error() {
    let (state, _target) = state_with_target(&build_elf_with_code());

    start_run(&state, "throw new Error('脚本自己抛的');").await;
    let done = wait_for_done(&state).await;

    assert_eq!(
        done["error"]["kind"], "runtime",
        "运行期异常与语法错误不能混为一类：{done}"
    );
    assert!(
        done["error"]["message"]
            .as_str()
            .is_some_and(|m| m.contains("脚本自己抛的")),
        "要带上脚本自己的消息：{done}"
    );
}

#[tokio::test]
async fn a_failed_script_leaves_no_annotations_behind() {
    let (state, _target) = state_with_target(&build_elf_with_code());

    start_run(
        &state,
        "bitflip.setComment('0000000000401000', '不该留下');\nthrow new Error('半路失败');",
    )
    .await;
    let done = wait_for_done(&state).await;
    assert_eq!(done["error"]["kind"], "runtime");

    let (_, body) = send(
        state.clone(),
        get_with_token("/api/annotations?from=0000000000401000&to=0000000000402000"),
    )
    .await;
    assert!(
        !body.to_string().contains("不该留下"),
        "失败的脚本不许留下写了一半的标注，实际：{body}"
    );
}

#[tokio::test]
async fn running_without_a_target_is_rejected_instead_of_silently_doing_nothing() {
    // 没有会话：脚本的读 API 会全部报错。这里明确拒绝，而不是让它跑到一半
    // 到处抛异常 —— 那样用户看到的是"脚本坏了"，而不是"你没打开目标"。
    let state = AppState::new(TOKEN, None)
        .with_allowed_origins(bitflip_server::default_allowed_origins(PORT, &[]));

    let (status, body) = start_run(&state, "bitflip.log('hi');").await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert!(
        body["error"]
            .as_str()
            .is_some_and(|e| e.contains("没有打开目标")),
        "要说清原因：{body}"
    );
}

// ---------------------------------------------------------------------------
// 取消与并发
// ---------------------------------------------------------------------------

#[tokio::test]
async fn a_dead_loop_can_be_cancelled() {
    let (state, _target) = state_with_target(&build_elf_with_code());

    start_run(&state, "bitflip.log('开始'); while (true) { }").await;

    // 预热（构建分析）阶段不可取消，必须等它真正开始执行。
    let running = wait_for_state(&state, "running").await;
    assert_eq!(
        running["can_cancel"], true,
        "执行阶段应当允许取消：{running}"
    );

    let (status, body) = send(state.clone(), post_json("/api/script/cancel", Value::Null)).await;
    assert_eq!(status, StatusCode::OK, "取消应当被接受：{body}");
    assert_eq!(body["ok"], true);

    let done = wait_for_done(&state).await;
    assert_eq!(
        done["error"]["kind"], "cancelled",
        "用户按的停止必须报成已取消，不能报成超时：{done}"
    );
    assert_eq!(done["can_cancel"], false);
}

#[tokio::test]
async fn cancelling_a_cancelled_run_is_reported_as_already_finished() {
    let (state, _target) = state_with_target(&build_elf_with_code());

    start_run(&state, "while (true) { }").await;
    wait_for_state(&state, "running").await;

    let (first, _) = send(state.clone(), post_json("/api/script/cancel", Value::Null)).await;
    assert_eq!(first, StatusCode::OK);

    let done = wait_for_done(&state).await;
    assert_eq!(done["error"]["kind"], "cancelled");

    // 已经结束了再点一次：要说"没有可取消的运行"，不能让界面显示"已取消"。
    let (status, body) = send(state.clone(), post_json("/api/script/cancel", Value::Null)).await;
    assert_eq!(status, StatusCode::CONFLICT);
    assert_eq!(body["ok"], false);
    assert!(
        body["message"]
            .as_str()
            .is_some_and(|m| m.contains("已经结束")),
        "要说清为什么没取消成：{body}"
    );
}

#[tokio::test]
async fn cancelling_with_nothing_running_is_rejected() {
    let (state, _target) = state_with_target(&build_elf_with_code());

    let (status, body) = send(state.clone(), post_json("/api/script/cancel", Value::Null)).await;
    assert_eq!(status, StatusCode::CONFLICT);
    assert_eq!(body["ok"], false);
    assert!(
        body["message"]
            .as_str()
            .is_some_and(|m| m.contains("没有脚本在运行")),
        "{body}"
    );
}

#[tokio::test]
async fn a_second_concurrent_run_is_rejected_with_conflict() {
    let (state, _target) = state_with_target(&build_elf_with_code());

    start_run(&state, "while (true) { }").await;
    wait_for_state(&state, "running").await;

    // 脚本会写标注、会读同一份缓存：两个并行跑会让日志与写入交错，
    // 用户没有任何办法分辨哪条是哪个脚本写的。
    let (status, body) = start_run(&state, "bitflip.log('第二个');").await;
    assert_eq!(
        status,
        StatusCode::CONFLICT,
        "第二个运行请求必须明确被拒，而不是排队（排队会让用户以为点了没反应）：{body}"
    );
    assert!(
        body["error"]
            .as_str()
            .is_some_and(|e| e.contains("已有脚本正在运行")),
        "{body}"
    );

    // 收尾，免得阻塞线程一直转。
    send(state.clone(), post_json("/api/script/cancel", Value::Null)).await;
    let done = wait_for_done(&state).await;
    assert_eq!(done["error"]["kind"], "cancelled");

    // 结束之后必须能再跑 —— 单槽不能变成"跑过一次就锁死"。
    let (status, _) = start_run(&state, "bitflip.log('再来一次');").await;
    assert_eq!(status, StatusCode::ACCEPTED);
    let done = wait_for_done(&state).await;
    assert!(done["error"].is_null(), "{done}");
    assert_eq!(done["logs"][0]["message"], "再来一次");
}

#[tokio::test]
async fn progress_is_visible_while_the_script_is_still_running() {
    let (state, _target) = state_with_target(&build_elf_with_code());

    // 上报进度后死循环：只有在运行**期间**才可能读到它。
    // 这正是"同步 POST"做不到的事，也是这个端点拆成三个的理由。
    start_run(
        &state,
        "bitflip.progress(3, 7, '正在处理'); while (true) { }",
    )
    .await;
    wait_for_state(&state, "running").await;

    let mut observed = None;
    for _ in 0..POLL_LIMIT {
        let status = status_of(&state).await;
        if status["state"] == "done" {
            break;
        }
        if !status["progress"].is_null() {
            observed = Some(status["progress"].clone());
            break;
        }
        tokio::time::sleep(Duration::from_millis(5)).await;
    }

    let progress = observed.expect("运行期间应当能读到进度");
    assert_eq!(progress["done"], 3);
    assert_eq!(progress["total"], 7);
    assert_eq!(progress["label"], "正在处理");

    send(state.clone(), post_json("/api/script/cancel", Value::Null)).await;
    wait_for_done(&state).await;
}

#[tokio::test]
async fn script_endpoints_require_a_token() {
    let (state, _target) = state_with_target(&build_elf_with_code());

    let without = |method: &str, path: &str| {
        Request::builder()
            .method(method)
            .uri(path)
            .header("content-type", "application/json")
            .body(Body::from("{}"))
            .expect("构造请求")
    };

    for (method, path) in [
        ("POST", "/api/script/run"),
        ("GET", "/api/script/status"),
        ("POST", "/api/script/cancel"),
        ("GET", "/api/script/library"),
    ] {
        let (status, _) = send(state.clone(), without(method, path)).await;
        assert_eq!(
            status,
            StatusCode::FORBIDDEN,
            "{method} {path} 没有令牌时必须 403"
        );
    }
}

// ---------------------------------------------------------------------------
// 脚本库
// ---------------------------------------------------------------------------

#[tokio::test]
async fn the_library_ships_source_and_the_current_api_version() {
    let (state, _target) = state_with_target(&build_elf_with_code());

    let (status, body) = send(state.clone(), get_with_token("/api/script/library")).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(
        body["api_version"],
        bitflip_script::SCRIPT_API_VERSION,
        "库要报出引擎当前的 API 版本，界面据此判断示例是否适用"
    );

    let scripts = body["scripts"].as_array().expect("scripts 应当是数组");
    assert!(!scripts.is_empty(), "内置脚本集不该是空的");
    for script in scripts {
        assert!(script["id"].as_str().is_some_and(|s| !s.is_empty()));
        assert!(script["name"].as_str().is_some_and(|s| !s.is_empty()));
        assert!(
            script["description"]
                .as_str()
                .is_some_and(|s| !s.is_empty()),
            "UI 上只有名字的脚本没人敢按"
        );
        assert_eq!(script["api_version"], bitflip_script::SCRIPT_API_VERSION);
        // 源码随库下发：用户必须能"看一眼再决定跑不跑"，
        // 且这份源码就是被测试真的执行过的那一份。
        assert!(
            script["source"]
                .as_str()
                .is_some_and(|s| s.contains("bitflip.")),
            "每份脚本都要真的调用脚本 API"
        );
    }

    let ids: Vec<&str> = scripts.iter().filter_map(|s| s["id"].as_str()).collect();
    for expected in [
        "memcpy-args",
        "rename-by-string",
        "export-functions",
        "library-patterns",
    ] {
        assert!(
            ids.contains(&expected),
            "PLAN §M7 交付物 4 要求的示例里少了 `{expected}`，实际：{ids:?}"
        );
    }
}

#[tokio::test]
async fn a_script_taken_from_the_library_runs_through_the_http_path() {
    // 这条是"示例脚本真的能用"的端到端证明：源码从库里取，原样 POST 回去跑。
    // 内置脚本的可执行性在 bitflip-script 的测试里已经逐份验过，
    // 这里验的是**HTTP 这条路**不会因为转义、长度或编码把源码弄坏。
    let (state, _target) = state_with_target(&build_elf_with_code());

    let (_, library) = send(state.clone(), get_with_token("/api/script/library")).await;
    let scripts = library["scripts"].as_array().expect("scripts");
    let chosen = scripts
        .iter()
        .find(|s| s["id"] == "export-functions")
        .expect("脚本库里应当有 export-functions");
    let source = chosen["source"].as_str().expect("源码应当是字符串");

    let (status, _) = start_run(&state, source).await;
    assert_eq!(status, StatusCode::ACCEPTED);

    let done = wait_for_done(&state).await;
    assert!(done["error"].is_null(), "库里的脚本原样跑应当成功：{done}");
    let text = done["logs"]
        .as_array()
        .expect("logs")
        .iter()
        .filter_map(|log| log["message"].as_str())
        .collect::<Vec<_>>()
        .join("\n");
    assert!(
        text.contains("函数总数="),
        "脚本的产出应当完整回传到界面，实际：{text}"
    );
}
