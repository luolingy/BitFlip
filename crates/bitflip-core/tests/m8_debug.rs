//! M8 验收标准 2 的第一段：行号从调试信息一路走到 wire 上。
//!
//! 这里核对的是**全链路**：真值（`addr2line` 产出的黄金文件）→ `bitflip-debug`
//! → `Disasm` → `InsnWire`。任何一段断掉，这条测试就红：解析器读错了、
//! 行表挂错了、wire 没填，都会在这里暴露。
//!
//! 真值不来自本项目的任何代码：`scripts/gen-debug-fixture.ps1` 用 `addr2line`
//! 生成 `m8-debug.golden.txt`（见该脚本里对"为什么必须用独立工具"的说明）。

use std::collections::HashMap;
use std::path::{Path, PathBuf};

use bitflip_core::{DisasmScanOptions, OpenOptions, Session};

fn fixtures() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("..")
        .join("..")
        .join("tests")
        .join("fixtures")
        .join("generated")
}

/// 黄金文件里的 `line <addr> <line> <file>` 行。
fn golden_lines() -> Option<HashMap<u64, (u32, String)>> {
    let text = std::fs::read_to_string(fixtures().join("m8-debug.golden.txt")).ok()?;
    let mut rows = HashMap::new();
    for line in text.lines() {
        let Some(rest) = line.trim().strip_prefix("line ") else {
            continue;
        };
        let mut fields = rest.split(' ');
        let address = u64::from_str_radix(fields.next()?.trim_start_matches("0x"), 16).ok()?;
        let number: u32 = fields.next()?.parse().ok()?;
        let file = fields.next()?.to_owned();
        rows.insert(address, (number, file));
    }
    if rows.is_empty() {
        None
    } else {
        Some(rows)
    }
}

fn file_name(path: &str) -> &str {
    path.rsplit(['/', '\\']).next().unwrap_or(path)
}

fn open(name: &str) -> Option<Session> {
    let path = fixtures().join(name);
    if !path.exists() {
        return None;
    }
    Session::open(&path, OpenOptions::default()).ok()
}

#[test]
fn disassembly_rows_carry_the_line_addr2line_reports() {
    let Some(golden) = golden_lines() else {
        eprintln!("SKIPPED: 缺少 tests/fixtures/generated/m8-debug.golden.txt");
        return;
    };
    let Some(session) = open("m8-debug.exe") else {
        eprintln!("SKIPPED: 缺少 tests/fixtures/generated/m8-debug.exe");
        return;
    };

    let disasm = session
        .disassemble(DisasmScanOptions::default())
        .expect("调试样本应当能反汇编");
    let first = *golden.keys().min().expect("黄金文件非空");
    let last = *golden.keys().max().expect("黄金文件非空");
    let page = disasm.page(first, (last - first) as usize);

    let mut checked = 0usize;
    let mut mismatched = Vec::new();
    for insn in &page.instructions {
        let Ok(address) = u64::from_str_radix(&insn.address, 16) else {
            continue;
        };
        let Some((line, file)) = golden.get(&address) else {
            continue;
        };
        let ours = insn
            .line
            .zip(insn.file.as_deref())
            .map(|(line, file)| (line, file_name(file)));
        match ours {
            Some((our_line, our_file)) if our_line == *line && our_file == file_name(file) => {
                checked += 1;
            }
            other => mismatched.push(format!(
                "{address:#x}: 我们给 {other:?}，addr2line 给 {line} {}",
                file_name(file)
            )),
        }
    }

    assert!(
        checked >= 20,
        "只核对了 {checked} 条指令的行号（黄金文件 {} 行），太少了：接线可能没生效",
        golden.len()
    );
    assert!(
        mismatched.is_empty(),
        "{} 条指令的行号与 addr2line 不一致（前 5 条）：{:#?}",
        mismatched.len(),
        mismatched.iter().take(5).collect::<Vec<_>>()
    );
    println!("核对了 {checked} 条指令的源位置（真值来自 addr2line）");
}

#[test]
fn every_row_reports_a_position_or_null_but_never_guesses() {
    let Some(session) = open("m8-debug.exe") else {
        eprintln!("SKIPPED: 缺少 tests/fixtures/generated/m8-debug.exe");
        return;
    };
    let disasm = session
        .disassemble(DisasmScanOptions::default())
        .expect("应当能反汇编");
    // 从调试信息覆盖的最低地址开始翻 —— `.text` 开头是 CRT 胶水代码，
    // 它不在我们这份 DWARF 的行表里，从那里开始会看到一屏 null（那是对的，
    // 但证明不了接线生效）。
    let Some(golden) = golden_lines() else {
        eprintln!("SKIPPED: 缺少黄金文件");
        return;
    };
    let start = *golden.keys().min().expect("黄金文件非空");
    let page = disasm.page(start, 200);
    let with_line = page
        .instructions
        .iter()
        .filter(|i| i.line.is_some())
        .count();
    assert!(
        with_line > 0,
        "带调试信息的目标上一条行号都没有：{}",
        session.debug().notes.join("；")
    );
    // 有行号时必须同时有源文件（只有行号没有文件的"行号"对用户没有意义）。
    for insn in &page.instructions {
        if insn.line.is_some() {
            assert!(insn.file.is_some(), "{} 有行号却没有源文件", insn.address);
        }
    }
}

#[test]
fn a_target_without_debug_info_reports_null_positions_and_says_why() {
    let Some(session) = open("m3-mingw-static.exe") else {
        eprintln!("SKIPPED: 缺少 tests/fixtures/generated/m3-mingw-static.exe");
        return;
    };
    let disasm = session
        .disassemble(DisasmScanOptions::default())
        .expect("应当能反汇编");
    let page = disasm.page(0x140001000, 200);
    assert!(!page.instructions.is_empty(), "剥离目标应当有反汇编结果");
    for insn in &page.instructions {
        assert!(insn.line.is_none(), "{} 不该有行号", insn.address);
        assert!(insn.file.is_none(), "{} 不该有源文件", insn.address);
    }
    assert!(
        session
            .debug()
            .notes
            .iter()
            .any(|note| note.contains(".debug_info")),
        "没有调试信息时必须在说明里讲清楚，实际是 {:?}",
        session.debug().notes
    );
    assert!(
        session
            .info()
            .notes
            .iter()
            .any(|note| note.contains("调试信息：")),
        "说明要浮到目标信息里（界面能看到的地方），实际是 {:?}",
        session.info().notes
    );
}

#[test]
fn lines_survive_a_stripped_symbol_table() {
    let Some(session) = open("m8-debug-nosym.exe") else {
        eprintln!("SKIPPED: 缺少 tests/fixtures/generated/m8-debug-nosym.exe");
        return;
    };
    let object = session.object().expect("应当解析成功");
    assert!(
        object.symbols.is_empty(),
        "这个 fixture 应当没有符号表，实际有 {} 条",
        object.symbols.len()
    );
    let disasm = session
        .disassemble(DisasmScanOptions::default())
        .expect("应当能反汇编");
    let page = disasm.page(0x140001000, 500);
    let with_line = page
        .instructions
        .iter()
        .filter(|i| i.line.is_some())
        .count();
    assert!(
        with_line >= 20,
        "符号表没了之后行号也必须还在（这正是调试信息作为独立来源的意义），实际只有 {with_line} 条"
    );
}
