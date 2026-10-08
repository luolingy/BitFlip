//! M8 交付物 1 的 PDB 验收：逐条对照**独立工具**产生的黄金值。
//!
//! 黄金值来自 `scripts/gen-pdb-fixture.ps1`：它用 `llvm-pdbutil dump -symbols/-l`
//! 取函数与行记录，用 `llvm-readobj` 取镜像节表把节内偏移换算成虚拟地址，产出
//! `m8-pdb.golden.txt`。用自己的解析器去比对 `pdb` crate 自己的输出等于什么都没验证 ——
//! 所以每个期望值都来自第三方工具，而且 fixture 是 `/Od` 编的，行号能逐条核对。
//!
//! fixture 的样本是 `tests/fixtures/m8_pdb_sample.c`（刻意不 include 任何头文件，
//! 好让 clang-cl 在不需要 Windows SDK 环境的情况下编译它）。
//!
//! 没有 fixture 时整组测试**跳过并说明原因**（fixture 由脚本生成，不入库）。
//!
//! 这里的 `fixtures` / `load` / `Golden` / `parse_golden` 与 `dwarf_golden.rs` 里的
//! 同名实现是重复的。抽到 `tests/common` 要同时改那份测试，价值不大、风险不小，
//! 所以先明说这份重复，而不是让它悄悄存在。

use std::path::{Path, PathBuf};

use bitflip_debug::{read, read_target};
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

/// 黄金文件里的一行（格式与 DWARF 那份相同）。
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

fn parse_golden(file: &str) -> Option<Vec<Golden>> {
    let text = std::fs::read_to_string(fixtures().join(file)).ok()?;
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
            // 路径里可能有空格，所以剩下的全是文件名。
            let file = fields.collect::<Vec<_>>().join(" ");
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
            let file = fields.collect::<Vec<_>>().join(" ");
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

/// 黄金值里记的是**这台机器**的绝对路径；比较只看文件名，
/// 因为"源文件叫什么"才是结论，"它在本机哪个目录"不是。
fn base_name(path: &str) -> &str {
    path.rsplit(['\\', '/']).next().unwrap_or(path)
}

macro_rules! skip_without_fixture {
    () => {
        if golden().is_none() {
            eprintln!(
                "SKIPPED: 缺少 tests/fixtures/generated/m8-pdb.golden.txt（\
                 运行 scripts/gen-pdb-fixture.ps1 生成）"
            );
            return;
        }
    };
}

fn golden() -> Option<Vec<Golden>> {
    parse_golden("m8-pdb.golden.txt")
}

#[test]
fn functions_match_the_pdb_dump() {
    skip_without_fixture!();
    let Some((object, bytes)) = load(&fixtures().join("m8-pdb.exe")) else {
        eprintln!("SKIPPED: 缺少 tests/fixtures/generated/m8-pdb.exe");
        return;
    };
    let info = read_target(Some(&fixtures().join("m8-pdb.exe")), &object, &bytes);

    let rows = golden().expect("黄金值");
    let expected: Vec<_> = rows
        .iter()
        .filter_map(|r| match r {
            Golden::Subprogram {
                low_pc,
                high_pc,
                decl_line,
                name,
                file,
            } => Some((*low_pc, *high_pc, *decl_line, name.clone(), file.clone())),
            Golden::Line { .. } => None,
        })
        .collect();

    assert_eq!(
        info.functions.len(),
        expected.len(),
        "函数个数与 llvm-pdbutil 不一致：{:?}",
        info.notes
    );
    for (low_pc, high_pc, decl_line, name, file) in expected {
        let found = info
            .functions
            .iter()
            .find(|f| f.low_pc == low_pc && f.name == name)
            .unwrap_or_else(|| panic!("PDB 里有 {name}（0x{low_pc:x}），我们没有"));
        assert_eq!(found.high_pc, high_pc, "{name} 的结束地址");
        assert_eq!(
            found.decl_line,
            Some(decl_line),
            "{name} 的声明行（取该函数第一条行记录）"
        );
        assert_eq!(
            found.decl_file.as_deref().map(base_name),
            Some(base_name(&file)),
            "{name} 的声明文件"
        );
    }
}

#[test]
fn line_records_match_llvm_pdbutil() {
    skip_without_fixture!();
    let Some((object, bytes)) = load(&fixtures().join("m8-pdb.exe")) else {
        eprintln!("SKIPPED: 缺少 tests/fixtures/generated/m8-pdb.exe");
        return;
    };
    let path = fixtures().join("m8-pdb.exe");
    let info = read_target(Some(&path), &object, &bytes);

    let rows = golden().expect("黄金值");
    let expected: Vec<_> = rows
        .iter()
        .filter_map(|r| match r {
            Golden::Line {
                address,
                line,
                file,
            } => Some((*address, *line, file.clone())),
            Golden::Subprogram { .. } => None,
        })
        .collect();

    assert_eq!(
        info.lines.len(),
        expected.len(),
        "行记录条数与 llvm-pdbutil 不一致：{:?}",
        info.notes
    );
    for (address, line, file) in expected {
        let found = info
            .lines
            .iter()
            .find(|l| l.address == address && l.line == line)
            .unwrap_or_else(|| panic!("PDB 里有 0x{address:x}:{line}，我们没有"));
        assert_eq!(
            found.file.as_deref().map(base_name),
            Some(base_name(&file)),
            "0x{address:x} 的源文件"
        );
    }

    // 每条行记录都要覆盖到下一跳：结束地址不能为零、也不能比开头小。
    for l in &info.lines {
        assert!(
            l.address_end > l.address,
            "0x{:x} 的结束地址没算出来（address_end={} ）",
            l.address,
            l.address_end
        );
    }
}

#[test]
fn a_stripped_symbol_table_does_not_hide_the_pdb() {
    let Some((object, bytes)) = load(&fixtures().join("m8-pdb-nosym.exe")) else {
        eprintln!("SKIPPED: 缺少 tests/fixtures/generated/m8-pdb-nosym.exe");
        return;
    };
    assert!(
        object.symbols.is_empty(),
        "这个 fixture 本该把符号表剥光，实际还剩 {} 条",
        object.symbols.len()
    );

    // 镜像里没有 DWARF（clang-cl 给的是 CodeView/PDB）。
    let dwarf_only = read(&object, &bytes);
    assert!(
        dwarf_only.functions.is_empty(),
        "没放 DWARF 的目标不该凭空读出{:?} 个函数：{:?}",
        dwarf_only.functions.len(),
        dwarf_only.notes
    );

    // 名字与行号全部来自旁边的 PDB，而且符号表被剥掉不影响它。
    let path = fixtures().join("m8-pdb-nosym.exe");
    let info = read_target(Some(&path), &object, &bytes);
    let names: Vec<&str> = info.functions.iter().map(|f| f.name.as_str()).collect();
    for expected in [
        "bf_pdb_add",
        "bf_pdb_sub",
        "bf_pdb_dot",
        "bf_pdb_tail",
        "bf_pdb_main",
        "bf_pdb_entry",
    ] {
        assert!(
            names.contains(&expected),
            "符号表被剥、但 PDB 在旁边，应该能给出 {expected}；实际 {names:?}（notes={:?}）",
            info.notes
        );
    }

    // 名字要能落到源位置：这是 M8 验收标准 2 要求的那件事。
    let add = info
        .functions
        .iter()
        .find(|f| f.name == "bf_pdb_add")
        .expect("bf_pdb_add");
    let place = info.location_at(add.low_pc).expect("入口地址应该有行记录");
    assert_eq!(place.line, 12, "bf_pdb_add 的入口行");
    assert_eq!(
        place.file.as_deref().map(base_name),
        Some("m8_pdb_sample.c"),
        "bf_pdb_add 的源文件"
    );
    assert_eq!(
        info.function_containing(add.low_pc)
            .map(|f| f.name.as_str()),
        Some("bf_pdb_add")
    );
}

#[test]
fn a_target_without_a_pdb_says_so() {
    // mingw 静态 exe：有 PE 外壳，旁边没有同名 PDB。
    let path = fixtures().join("m3-mingw-static.exe");
    let Some((object, bytes)) = load(&path) else {
        eprintln!("SKIPPED: 缺少 tests/fixtures/generated/m3-mingw-static.exe");
        return;
    };
    let info = read_target(Some(&path), &object, &bytes);
    // M8 收尾时改了文案：现在不仅说"没找到"，还要列出**试过哪些路径**
    // （CodeView 记录里的路径 → 目标旁边的同名文件 → 同名约定）。§7：拿不到要说清楚拿了哪里。
    assert!(
        info.notes.iter().any(|n| n.contains("没找到可读的 PDB")),
        "PE 目标找不到 PDB 时必须说明找过哪里，实际 notes={:?}",
        info.notes
    );
    assert!(
        info.notes.iter().any(|n| n.contains("m3-mingw-static.pdb")),
        "notes 要列出试过的路径，实际 notes={:?}",
        info.notes
    );
}

#[test]
fn an_empty_pdb_is_reported() {
    let Some((object, _)) = load(&fixtures().join("m8-pdb.exe")) else {
        eprintln!("SKIPPED: 缺少 tests/fixtures/generated/m8-pdb.exe");
        return;
    };
    let info = bitflip_debug::read_pdb(&object, &[]);
    assert!(info.functions.is_empty());
    assert!(
        info.notes.iter().any(|n| n.contains("0 字节")),
        "空 PDB 要说清楚是空的，实际 notes={:?}",
        info.notes
    );
}
