//! M8 交付物 1 的 DWARF 验收：逐条对照**独立工具**产生的黄金值。
//!
//! 黄金值来自 `scripts/gen-debug-fixture.ps1`，它用 `llvm-dwarfdump`
//! （函数）与 `addr2line`（地址 → 源位置）产出 `m8-debug.golden.txt`。
//! 用自己的解析器去比对 gimli 自己的输出等于什么都没验证 —— 所以这里的每一个
//! 期望值都来自第三方工具，而 fixture 是 `-g -O0` 编出来的，行号可以逐条核对。
//!
//! 没有 fixture 时整组测试**跳过并说明原因**（fixture 由脚本生成，不入库）。

use std::path::{Path, PathBuf};

use bitflip_debug::{read, DebugInfo};
use bitflip_loader::object::Object;

fn fixtures() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("..")
        .join("..")
        .join("tests")
        .join("fixtures")
        .join("generated")
}

/// 装载目标（与 `bitflip-core` 里的做法一致：先嗅探再按格式解析）。
fn load(path: &Path) -> Option<(Object, Vec<u8>)> {
    let bytes = std::fs::read(path).ok()?;
    let guess = bitflip_loader::sniff_bytes(&bytes);
    let id = bitflip_loader::object::ObjectId::Plain;
    let object = match guess.object {
        bitflip_loader::ObjectKind::Pe => bitflip_loader::pe::parse(&bytes, 0, id),
        bitflip_loader::ObjectKind::Elf => bitflip_loader::elf::parse(&bytes, 0, id),
        bitflip_loader::ObjectKind::Coff => bitflip_loader::coff::parse(&bytes, 0, id),
        _ => return None,
    }
    .ok()?;
    Some((object, bytes))
}

/// 黄金文件里的一行。
enum Golden {
    /// `<low_pc> <high_pc> <decl_line> <name> <decl_file>`
    Subprogram {
        low_pc: u64,
        high_pc: u64,
        decl_line: u32,
        name: String,
        file: String,
    },
    /// `<addr> <line> <file>`
    Line {
        address: u64,
        line: u32,
        file: String,
    },
}

fn golden() -> Option<Vec<Golden>> {
    let path = fixtures().join("m8-debug.golden.txt");
    let text = std::fs::read_to_string(path).ok()?;
    let mut rows = Vec::new();
    for line in text.lines() {
        let line = line.trim();
        if line.starts_with('#') || line.is_empty() {
            continue;
        }
        if let Some(rest) = line.strip_prefix("subprogram ") {
            let mut fields = rest.split(' ');
            let low_pc = u64::from_str_radix(fields.next()?.trim_start_matches("0x"), 16).ok()?;
            let high_pc = u64::from_str_radix(fields.next()?.trim_start_matches("0x"), 16).ok()?;
            let decl_line = fields.next()?.parse().ok()?;
            let name = fields.next()?.to_owned();
            let file = fields.next()?.to_owned();
            rows.push(Golden::Subprogram {
                low_pc,
                high_pc,
                decl_line,
                name,
                file,
            });
            continue;
        }
        if let Some(rest) = line.strip_prefix("line ") {
            let mut fields = rest.split(' ');
            let address = u64::from_str_radix(fields.next()?.trim_start_matches("0x"), 16).ok()?;
            let line = fields.next()?.parse().ok()?;
            let file = fields.next()?.to_owned();
            rows.push(Golden::Line {
                address,
                line,
                file,
            });
        }
    }
    if rows.is_empty() {
        None
    } else {
        Some(rows)
    }
}

macro_rules! skip_without_fixture {
    () => {
        if golden().is_none() {
            eprintln!(
                "SKIPPED: 缺少 tests/fixtures/generated/m8-debug.golden.txt（\
                 运行 scripts/gen-debug-fixture.ps1 生成）"
            );
            return;
        }
    };
}

#[test]
fn functions_match_dwarfdump() {
    skip_without_fixture!();
    let Some((object, bytes)) = load(&fixtures().join("m8-debug.exe")) else {
        eprintln!("SKIPPED: 缺少 tests/fixtures/generated/m8-debug.exe");
        return;
    };
    let info = read(&object, &bytes);
    assert!(
        !info.functions.is_empty(),
        "有 .debug_info 却一个函数都没读出来：{:?}",
        info.notes
    );

    let rows = golden().expect("黄金值");
    let mut checked = 0usize;
    for row in &rows {
        let Golden::Subprogram {
            low_pc,
            high_pc,
            decl_line,
            name,
            file,
        } = row
        else {
            continue;
        };
        let found = info
            .functions
            .iter()
            .find(|f| f.low_pc == *low_pc)
            .unwrap_or_else(|| panic!("{low_pc:#x} 处的函数没读出来（真值是 {name}）"));
        assert_eq!(&found.name, name, "{low_pc:#x} 的名字");
        assert_eq!(found.high_pc, *high_pc, "{name} 的结束地址");
        assert_eq!(found.decl_line, Some(*decl_line), "{name} 的声明行");
        let path = found
            .decl_file
            .as_deref()
            .unwrap_or_else(|| panic!("{name} 没有源文件"));
        assert_eq!(
            DebugInfo::file_name(path),
            DebugInfo::file_name(file),
            "{name} 的源文件（完整路径：{path}）"
        );
        checked += 1;
    }
    assert!(checked >= 5, "只核对了 {checked} 个函数，太少了");
    println!("核对了 {checked} 个函数（真值来自 llvm-dwarfdump）");
}

#[test]
fn line_table_matches_addr2line() {
    skip_without_fixture!();
    let Some((object, bytes)) = load(&fixtures().join("m8-debug.exe")) else {
        eprintln!("SKIPPED: 缺少 tests/fixtures/generated/m8-debug.exe");
        return;
    };
    let info = read(&object, &bytes);
    let rows = golden().expect("黄金值");
    let mut checked = 0usize;
    let mut mismatched = Vec::new();
    for row in &rows {
        let Golden::Line {
            address,
            line,
            file,
        } = row
        else {
            continue;
        };
        match info.location_at(*address) {
            Some(found) => {
                let found_file = found
                    .file
                    .as_deref()
                    .map(DebugInfo::file_name)
                    .unwrap_or("<没有文件>");
                if found.line != *line || found_file != DebugInfo::file_name(file) {
                    mismatched.push(format!(
                        "{address:#x}: 我们给 {}:{}，addr2line 给 {}:{}",
                        found_file,
                        found.line,
                        DebugInfo::file_name(file),
                        line
                    ));
                }
            }
            None => mismatched.push(format!("{address:#x}: 我们没有行信息")),
        }
        checked += 1;
    }
    assert!(checked >= 5, "只核对了 {checked} 个地址，太少了");
    assert!(
        mismatched.is_empty(),
        "{} 个地址的行号与 addr2line 不一致（前 5 个）：{:#?}",
        mismatched.len(),
        mismatched.iter().take(5).collect::<Vec<_>>()
    );
    println!("核对了 {checked} 个地址的行号（真值来自 addr2line）");
}

#[test]
fn a_stripped_symbol_table_does_not_hide_the_debug_info() {
    let nosym = fixtures().join("m8-debug-nosym.exe");
    if !nosym.exists() {
        eprintln!("SKIPPED: 缺少 tests/fixtures/generated/m8-debug-nosym.exe");
        return;
    }
    let Some((object, bytes)) = load(&nosym) else {
        eprintln!("SKIPPED: m8-debug-nosym.exe 解析失败");
        return;
    };
    // 这一条是"调试信息作为独立来源"的存在性证明：符号表被剥光了，
    // 函数名和行号只能来自 .debug_*。
    assert!(
        object.symbols.is_empty(),
        "这个 fixture 应当没有符号表，实际有 {} 条",
        object.symbols.len()
    );
    let info = read(&object, &bytes);
    assert!(
        info.functions.len() >= 5,
        "没有符号表时应当仍然从 DWARF 读出函数：{:?}",
        info.notes
    );
    assert!(
        info.lines.len() >= 5,
        "没有符号表时应当仍然从 DWARF 读出行表：{:?}",
        info.notes
    );
    let bf_add = info
        .functions
        .iter()
        .find(|f| f.name == "bf_add")
        .expect("应当有 bf_add");
    let line = info
        .location_at(bf_add.low_pc)
        .expect("bf_add 的入口地址应当有行信息");
    assert_eq!(line.line, bf_add.decl_line.unwrap_or(0));
}

#[test]
fn a_target_without_dwarf_says_so() {
    let Some((object, bytes)) = load(&fixtures().join("m3-mingw-static.exe")) else {
        eprintln!("SKIPPED: 缺少 tests/fixtures/generated/m3-mingw-static.exe");
        return;
    };
    let info = read(&object, &bytes);
    assert!(info.is_empty(), "剥离目标不该有 DWARF：{info:?}");
    assert!(
        info.notes.iter().any(|note| note.contains(".debug_info")),
        "没有调试信息时必须在 notes 里说明，实际是 {:?}",
        info.notes
    );
}

#[test]
fn gaps_between_lines_are_not_claimed() {
    // 纯逻辑测试：行表是稀疏的，落在行与行之间的地址必须返回 None，
    // 而不是"最近的一行" —— 那会把别的代码的行号安到这个地址上。
    let info = DebugInfo {
        functions: Vec::new(),
        units: Vec::new(),
        skipped: Default::default(),
        notes: Vec::new(),
        lines: vec![
            bitflip_debug::DebugLine {
                address: 0x1000,
                address_end: 0x1010,
                file: Some("a.c".to_owned()),
                line: 10,
                column: 0,
            },
            bitflip_debug::DebugLine {
                address: 0x2000,
                address_end: 0x2010,
                file: Some("a.c".to_owned()),
                line: 20,
                column: 0,
            },
        ],
    };
    assert_eq!(info.location_at(0x1000).map(|row| row.line), Some(10));
    assert_eq!(info.location_at(0x100f).map(|row| row.line), Some(10));
    assert_eq!(info.location_at(0x1010), None);
    assert_eq!(info.location_at(0x1fff), None, "行与行之间不许给最近的一行");
    assert_eq!(info.location_at(0x2000).map(|row| row.line), Some(20));
    assert_eq!(info.location_at(0xffff), None);
}
