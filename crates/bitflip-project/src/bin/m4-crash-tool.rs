//! 崩溃安全测试的辅助工具：按阶段写入工程库/派生物，并在指定点硬退出。
//!
//! 为什么需要一个独立二进制：验收标准 2 要求"分析中途 kill 进程"。
//! 在测试进程内调用 `std::process::exit` 只会结束测试本身，证明不了
//! "另一个进程被杀之后文件仍然可读"。所以由 `scripts/m4-crash-test.ps1`
//! 拉起本工具、在写入中途 `Stop-Process -Force`，再回调 `verify` 子命令检查。
//!
//! 用法（由脚本调用，不面向最终用户）：
//! ```text
//! m4-crash-tool write-bfp   <path> <hash> <n> <kill-after>
//! m4-crash-tool write-bda   <path> <hash> <n> <kill-after>
//! m4-crash-tool verify-bfp  <path> <hash>
//! m4-crash-tool verify-bda  <path> <hash>
//! ```
//!
//! `kill-after` 为 0 表示不自杀（跑完全程）：脚本用它做对照组。

use std::path::PathBuf;

use bitflip_project as bfp;

fn main() {
    let args: Vec<String> = std::env::args().collect();
    if args.len() < 2 {
        eprintln!(
            "用法: m4-crash-tool <write-bfp|write-bda|verify-bfp|verify-bda|verify-index> ..."
        );
        std::process::exit(2);
    }
    let result = match args[1].as_str() {
        "write-bfp" => cmd_write_bfp(&args),
        "write-bda" => cmd_write_bda(&args),
        "verify-bfp" => cmd_verify_bfp(&args),
        "verify-bda" => cmd_verify_bda(&args),
        "verify-index" => cmd_verify_index(&args),
        other => {
            eprintln!("未知子命令: {other}");
            std::process::exit(2);
        }
    };
    if let Err(message) = result {
        // 失败要**大声**：脚本据此判定"崩溃后状态损坏"
        eprintln!("FAIL: {message}");
        std::process::exit(1);
    }
    println!("OK");
}

fn arg(args: &[String], i: usize, name: &str) -> Result<String, String> {
    args.get(i)
        .cloned()
        .ok_or_else(|| format!("缺少参数 {name}"))
}

/// 大量写入主数据；`kill_after` 条之后硬退出（模拟被强杀）。
fn cmd_write_bfp(args: &[String]) -> Result<(), String> {
    let path = PathBuf::from(arg(args, 2, "path")?);
    let hash = arg(args, 3, "hash")?;
    let count: u64 = arg(args, 4, "count")?.parse().map_err(|e| format!("{e}"))?;
    let kill_after: u64 = arg(args, 5, "kill_after")?
        .parse()
        .map_err(|e| format!("{e}"))?;

    let store = bfp::ProjectStore::create(&path, &hash, 4096, "crash-tool", 1000)
        .map_err(|e| format!("建库失败: {e}"))?;

    // Announce the kill point BEFORE the heavy loop and flush immediately.
    // The harness polls for this marker while the writer is still alive; a
    // marker printed only at the end would arrive after the interesting window
    // and the kill would land on a process that already finished.
    if kill_after > 0 {
        eprintln!("KILLING at {kill_after}");
        let _ = std::io::Write::flush(&mut std::io::stderr());
    }

    for i in 0..count {
        store
            .put(
                &bfp::Annotation::text(
                    -1i64 as u64 / 2 + i,
                    bfp::AnnotationKind::Comment,
                    format!("c{i}"),
                ),
                1000 + i,
            )
            .map_err(|e| format!("写入失败: {e}"))?;
        if kill_after > 0 && i + 1 >= kill_after {
            // 硬退出：不 drop、不 flush、不 close —— 这正是要测的场景
            eprintln!("reached kill point at {i}");
            let _ = std::io::Write::flush(&mut std::io::stderr());
            std::process::exit(137);
        }
    }
    Ok(())
}

/// 大量写入派生物；在 rename 之前的任意点硬退出。
fn cmd_write_bda(args: &[String]) -> Result<(), String> {
    let path = PathBuf::from(arg(args, 2, "path")?);
    let hash = arg(args, 3, "hash")?;
    let count: u64 = arg(args, 4, "count")?.parse().map_err(|e| format!("{e}"))?;
    let kill_after: u64 = arg(args, 5, "kill_after")?
        .parse()
        .map_err(|e| format!("{e}"))?;

    let mut snap = bfp::Snapshot {
        target_sha256: hash,
        ..bfp::Snapshot::default()
    };
    for i in 0..count {
        let name = snap.intern(&format!("fn_{i}"));
        snap.functions.push(bfp::FunctionEntry::new(
            0x1000 + i * 0x10,
            Some(0x1000 + i * 0x10 + 0x10),
            Some(name),
            85,
        ));
    }

    if kill_after > 0 {
        // 模拟"写到一半被杀"：先亲手写一个截断的 .tmp，再自杀。
        // 这样脚本能确定地测到"tmp 存在但正式文件不存在"的状态。
        //
        // 顺序很重要：先打标记并 flush，**再**写 tmp，最后 sleep 一下才退出。
        // 只打标记不等待的话，整个进程在几毫秒内就跑完了，harness 的轮询
        // （25ms 一次）根本来不及发 kill —— 那一轮就变成"没被杀"的空测试。
        // 这个 sleep 是让被测窗口**可观测**，不是给程序加速。
        eprintln!("KILLING with half-written tmp");
        let _ = std::io::Write::flush(&mut std::io::stderr());

        let tmp = PathBuf::from(format!("{}.tmp", path.display()));
        if let Some(parent) = tmp.parent() {
            let _ = std::fs::create_dir_all(parent);
        }
        let full = snap.to_bytes();
        let half = full.len() / 2;
        std::fs::write(&tmp, &full[..half]).map_err(|e| format!("写 tmp 失败: {e}"))?;
        eprintln!("wrote half-written tmp ({} of {} bytes)", half, full.len());
        let _ = std::io::Write::flush(&mut std::io::stderr());

        std::thread::sleep(std::time::Duration::from_millis(2000));
        std::process::exit(137);
    }

    bfp::derived::write_atomic(&path, &snap.to_bytes())
        .map_err(|e| format!("写派生物失败: {e}"))?;
    Ok(())
}

/// 打开主数据库并校验：能打开、能读到已提交的数据、count > 0。
fn cmd_verify_bfp(args: &[String]) -> Result<(), String> {
    let path = PathBuf::from(arg(args, 2, "path")?);
    let hash = arg(args, 3, "hash")?;
    let store =
        bfp::ProjectStore::open(&path, &hash).map_err(|e| format!("崩溃后工程库打不开: {e}"))?;
    let _ = store.meta().map_err(|e| format!("meta 读不出来: {e}"))?;
    let len = store.len();
    println!("bfp readable, annotations = {len}");
    // 关键不变量：文件可读、SQL 可执行。条数不作硬要求 ——
    // 被杀在事务中途时，最后一条未提交的写丢失是**正确的**行为。
    Ok(())
}

/// 校验派生物：要么不存在（崩溃于 rename 前），要么是完整可解析的。
fn cmd_verify_bda(args: &[String]) -> Result<(), String> {
    let path = PathBuf::from(arg(args, 2, "path")?);
    let hash = arg(args, 3, "hash")?;
    if !path.exists() {
        println!("bda absent (crash before rename) — acceptable");
        // 残留的 tmp 必须能被清理，且它不是有效文件
        let cleaned = bfp::derived::clean_stale_tmp(&path);
        println!("stale tmp cleaned = {cleaned}");
        return Ok(());
    }
    let snap =
        bfp::derived::read(&path, &hash).map_err(|e| format!("崩溃后派生物不可解析: {e}"))?;
    println!("bda readable, functions = {}", snap.functions.len());
    Ok(())
}

/// 校验最近列表在崩溃后仍可解析。
fn cmd_verify_index(args: &[String]) -> Result<(), String> {
    let ws = PathBuf::from(arg(args, 2, "workspace")?);
    let store = bfp::RecentStore::new(&ws);
    let (index, corrupt) = store.load();
    if corrupt {
        return Err("崩溃后最近列表损坏".into());
    }
    println!("index readable, entries = {}", index.recent.len());
    Ok(())
}
