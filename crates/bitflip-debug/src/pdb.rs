//! PDB（MSVC 系调试信息）读取。
//!
//! 与 [`crate::read_dwarf`] 的关系：两者产出**同一个** [`DebugInfo`]，所以上层
//! （分析、wire、界面）不需要知道数据来自 DWARF 还是 PDB —— 这也是把格式解析
//! 与"谁的名字算数"分开的原因（见 `lib.rs` 的说明）。
//!
//! # 为什么 PDB 的入口与 DWARF 不同
//!
//! DWARF 就在目标文件里，所以 `read_dwarf(object, bytes)` 的 `bytes` 是镜像本身；
//! PDB 在**另一个文件**里，而且是按名找的（链接器把它写在 PE 的调试目录里，指向
//! 一个路径）。这里把两件事分开：
//!
//! * [`read_pdb`]：只解析，输入是 PDB 的字节，不碰文件系统（因此可测）；
//! * [`default_pdb_path`]：路径约定（`foo.exe` → 同目录 `foo.pdb`）；
//! * [`crate::read_target`]：把 DWARF 与 PDB 合起来，供分析层一次调用。
//!
//! **已知限制（如实写在这里，也会进 `notes`）**：还没有解析 PE 调试目录里的
//! CodeView 记录，所以路径不是从镜像里读出来的，而是按同名约定找的。路径不同名
//! （比如 `foo.exe` 配 `build\other.pdb`）时会找不到 —— 找不到就说找不到，不猜。
//!
//! # 与 DWARF 的语义差异（都会进 `notes`，不假装两边一样）
//!
//! * PDB 的符号记录里**没有**"声明行"这个字段：这里的 `decl_line` 指的是该函数
//!   第一条行记录所在的行（`/Od` 下就是入口那一行）。没有行记录就是 `None`，
//!   不拿 0 顶替。
//! * PDB 没有 DWARF 那种"有声明但无地址"和"被内联"的分类，因此 `skipped` 全为 0 ——
//!   不是"统计结果为零"，而是**不适用**，这一点写进 `notes`。
//! * 行记录的覆盖范围来自 PDB 自己的语义（"每条行记录有效到下一跳"）：用下一条行
//!   记录的开头当结束，最后一条收在函数末尾。这不是我们的发明。

use std::path::{Path, PathBuf};

use bitflip_loader::object::Object;
use pdb::{FallibleIterator, SymbolData, PDB};

use crate::{DebugFunction, DebugInfo, DebugLine, DebugSkip, DebugUnit};

/// `foo.exe` / `foo.dll` → 同目录下的 `foo.pdb`。找不到就不返回（调用方据此说明原因）。
///
/// 同时试大小写两种写法：Windows 上不区分大小写，但别的机器上区分，
/// 而"链接器写的是哪个大小写"我们并不知道。
#[must_use]
pub fn default_pdb_path(target: &Path) -> Option<PathBuf> {
    let stem = target.file_stem()?;
    let mut pdb = target.to_path_buf();
    pdb.set_file_name(stem);
    pdb.set_extension("pdb");
    if pdb.is_file() {
        return Some(pdb);
    }
    let mut upper = target.to_path_buf();
    upper.set_file_name(stem);
    upper.set_extension("PDB");
    if upper.is_file() {
        return Some(upper);
    }
    None
}

/// 解析一个 PDB。`object` 只用来取镜像基址（PDB 里存的是 RVA）。
///
/// 永远不失败：读不下去的部分变成 `notes` 里的一句话，已读出的部分照常返回。
#[must_use]
pub fn read_pdb(object: &Object, pdb_bytes: &[u8]) -> DebugInfo {
    let mut info = DebugInfo {
        units: Vec::new(),
        functions: Vec::new(),
        lines: Vec::new(),
        skipped: DebugSkip {
            declarations: 0,
            unnamed: 0,
            without_range: 0,
            inlined: 0,
        },
        notes: Vec::new(),
    };

    if pdb_bytes.is_empty() {
        info.notes
            .push("PDB：文件是空的（0 字节），没有可读的调试信息".to_string());
        return info;
    }

    let mut modules_total = 0u64;
    let mut modules_without_info = 0u64;
    let mut duplicates = 0u64;

    match collect(
        object,
        pdb_bytes,
        &mut info,
        &mut modules_total,
        &mut modules_without_info,
        &mut duplicates,
    ) {
        Ok(()) => {}
        Err(err) => {
            info.notes.push(format!(
                "PDB：读取出错（{err}）；已读出的部分仍然列出，缺失的部分就是没有"
            ));
        }
    }

    // 排序并去重：同一个函数可能被多个编译单元记录（内联副本、静态函数重名）。
    // 保留先到的那个，把重复数量如实报出来。
    info.functions.sort_by_key(|f| (f.low_pc, f.high_pc));
    info.functions
        .dedup_by(|a, b| a.low_pc == b.low_pc && a.name == b.name);
    info.lines.sort_by_key(|l| (l.address, l.line));

    info.notes.push(format!(
        "PDB：{} 个编译单元（其中 {} 个没有模块信息）、{} 个函数、{} 条行记录{}",
        modules_total,
        modules_without_info,
        info.functions.len(),
        info.lines.len(),
        if duplicates > 0 {
            format!("；另外有 {duplicates} 条重复的函数记录已合并")
        } else {
            String::new()
        }
    ));
    info.notes.push(
        "PDB：`skipped` 全为 0 是**不适用**（PDB 没有 DWARF 那种「无地址的声明」与「被内联」分类），\
         不是统计结果为零"
            .to_string(),
    );
    info
}

fn collect(
    object: &Object,
    pdb_bytes: &[u8],
    info: &mut DebugInfo,
    modules_total: &mut u64,
    modules_without_info: &mut u64,
    duplicates: &mut u64,
) -> Result<(), pdb::Error> {
    let cursor = std::io::Cursor::new(pdb_bytes);
    let mut pdb = PDB::open(cursor)?;

    let address_map = pdb.address_map()?;
    let string_table = pdb.string_table()?;

    let dbi = pdb.debug_information()?;
    let mut modules = dbi.modules()?;

    while let Some(module) = modules.next()? {
        *modules_total += 1;
        let module_name = module.module_name().to_string();
        info.units.push(DebugUnit {
            name: Some(module_name),
            // PDB 的模块名就是 `.obj` 的路径（编译目录已经在里面），没有单独的 comp dir。
            comp_dir: None,
            producer: None,
            language: None,
        });

        let Some(module_info) = pdb.module_info(&module)? else {
            *modules_without_info += 1;
            continue;
        };

        let program = module_info.line_program()?;
        let mut symbols = module_info.symbols()?;
        while let Some(symbol) = symbols.next()? {
            let Ok(SymbolData::Procedure(proc)) = symbol.parse() else {
                continue;
            };
            let Some(rva) = proc.offset.to_rva(&address_map) else {
                // 落在节表之外 —— 不说它在哪，也不假装它没有地址。
                continue;
            };
            let low_pc = object.image_base + u64::from(rva.0);
            let high_pc = low_pc + u64::from(proc.len);
            let name = proc.name.to_string();

            // 行记录：只取这个函数范围内的（PDB 的行表是模块级的一整张表）。
            let mut rows: Vec<DebugLine> = Vec::new();
            let mut lines = program.lines_for_symbol(proc.offset);
            while let Some(line) = lines.next()? {
                let Some(line_rva) = line.offset.to_rva(&address_map) else {
                    continue;
                };
                let address = object.image_base + u64::from(line_rva.0);
                if address < low_pc || address >= high_pc {
                    continue;
                }
                let file = program
                    .get_file_info(line.file_index)
                    .ok()
                    .and_then(|fi| fi.name.to_string_lossy(&string_table).ok())
                    .map(|s| s.to_string());
                rows.push(DebugLine {
                    address,
                    // 结束地址由后面的收尾步骤补：要看到下一条行记录才知道覆盖到哪。
                    address_end: address,
                    file,
                    line: line.line_start,
                    // PDB 的列号"即使有也常常是 0"，所以 0 就是**未知**，不是第 0 列。
                    column: line.column_start.unwrap_or(0),
                });
            }
            rows.sort_by_key(|l| l.address);
            for i in 0..rows.len() {
                let end = if i + 1 < rows.len() {
                    rows[i + 1].address
                } else {
                    high_pc
                };
                rows[i].address_end = end.max(rows[i].address);
            }

            let decl = rows.first().map(|l| (l.file.clone(), l.line));
            if info
                .functions
                .iter()
                .any(|f| f.low_pc == low_pc && f.name == name)
            {
                *duplicates += 1;
            } else {
                info.functions.push(DebugFunction {
                    // `proc.name` 是 pdb 自己的名字类型，它的 `to_string` 仍然是借用的 Cow；
                    // 这里必须拷成 `String` —— PDB 字节在函数返回后就没了。
                    name: name.to_string(),
                    // PDB 的符号名就是链接名（C++ 是 MSVC 修饰名）：不去猜一个"看起来更漂亮"的
                    // 名字，也不做反修饰（未实现的能力不假装）。
                    linkage_name: None,
                    low_pc,
                    high_pc,
                    decl_file: decl.as_ref().and_then(|(f, _)| f.clone()),
                    decl_line: decl.as_ref().map(|(_, l)| *l),
                });
            }
            info.lines.extend(rows);
        }
    }

    Ok(())
}
