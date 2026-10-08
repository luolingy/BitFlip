//! BitFlip 的调试信息来源（M8 交付物 1）：DWARF / PDB 里的函数名、源文件与行号。
//!
//! 单独一个 crate，而不是塞进 `bitflip-symbols`：解析格式与决定"谁的名字算数"
//! 是两件事。这里只做前者 —— 读出来、如实标注怎么读到的、读不到就说读不到；
//! 优先级与冲突合并由 `bitflip-core` 按符号来源决定。
//! 加一种格式（CodeView、dSYM）只动这里，不动分析层。
//!
//! 分层：`core → debug → loader`，与 `symbols` / `signature` 同级。
//!
//! # 为什么值得单独一层
//!
//! 符号表能给的是名字，调试信息能给的是**名字 + 源文件 + 行号**，而且在符号表被
//! 剥掉之后仍然在（事实上 `-g` 加 `strip --strip-all` 不会动 `.debug_*` 之外，
//! 用 `objcopy --keep-section` 甚至能只留调试信息）。这正是 M8 验收标准 2 要的东西：
//! 界面上（反汇编、交叉引用、调用图）能看到"这一行来自哪个源文件的哪一行"。
//!
//! # 两种格式，一个出口
//!
//! [`read_dwarf`] 与 [`read_pdb`] 产出**同一个** [`DebugInfo`]，所以分析层、wire 与
//! 界面不需要知道数据是哪来的。[`read_target`] 是给分析层用的那个出口：读目标里的
//! DWARF，再按同名约定找旁边有没有 PDB，两者都有就合并（[`merge`]）。
//!
//! PDB 与同类名的选择依据不同：DWARF 在镜像里，PDB 是**另一个文件**（见 [`pdb`] 的
//! 模块说明）；因此只有 PE（exe/dll）才会去找 PDB，静态库与归档成员不做 —— 那里的
//! 地址语义与镜像不同，没做就是没做，不假装做了。
//!
//! # 边界
//!
//! * 只读，不改写任何字节。
//! * 不做类型系统（M8 明确把类型后置）：结构体布局、变量位置一律不读。
//! * 不因为调试信息缺失而失败：返回空的 [`DebugInfo`] 加一条 `notes` 说明。

pub mod codeview;
mod dwarf;
pub mod pdb;

pub use dwarf::{read_dwarf, DebugFunction, DebugInfo, DebugLine, DebugSkip, DebugUnit};
pub use pdb::{default_pdb_path, read_pdb};

use std::path::Path;

use bitflip_loader::object::Object;

/// 读目标里的调试信息（只读 DWARF）。
///
/// 想同时要 PDB 请用 [`read_target`] —— 那个才知道目标文件在哪。
#[must_use]
pub fn read(object: &Object, bytes: &[u8]) -> DebugInfo {
    read_dwarf(object, bytes)
}

/// 读目标**及其同名 PDB** 里的调试信息。
///
/// `target` 是目标文件的路径；`None` 表示调用方不知道路径（例如归档成员），
/// 那就只读 DWARF —— 不去猜一个可能配错的 PDB。
#[must_use]
pub fn read_target(target: Option<&Path>, object: &Object, bytes: &[u8]) -> DebugInfo {
    let info = read(object, bytes);

    // 只有 PE 才找同名 PDB：静态库/归档成员里的 PDB 地址语义与镜像不同，
    // 那部分没做，所以也不去找。
    if object.kind != bitflip_loader::ObjectKind::Pe {
        return info;
    }
    let Some(path) = target else {
        return info;
    };

    // 找 PDB 的候选路径，按可信度排序：
    //
    // 1. PE 调试目录里 CodeView 记录写着的那条路径 —— 链接器当时用的，最权威（常是绝对路径）；
    // 2. 记录里的文件名放到**目标文件旁边** —— 目标连同 PDB 一起搬走时用这个；
    // 3. `foo.exe` → `foo.pdb` 的同名约定 —— 没有调试目录（不是 MSVC 链接、或记录被抹掉）时兜底。
    //
    // 三条都试不到就照实说"没找到"，并把试过哪些路径写进 notes。找到时也写清楚是**按哪条**
    // 找到的：CodeView 记录里的路径可能指向一次旧构建，用户得能看见我们用的是哪一个（§7）。
    let record = codeview::find(bytes);
    let mut candidates: Vec<std::path::PathBuf> = Vec::new();
    if let Some(record) = &record {
        let from_record = std::path::PathBuf::from(&record.path);
        if let Some(name) = from_record.file_name() {
            if let Some(dir) = path.parent() {
                candidates.push(dir.join(name));
            }
        }
        // 记录路径排最后入列、但可信度最高 —— 建列时先放它，前面 push 的名字只是它的旁支。
        let sibling = candidates.pop();
        candidates.insert(0, from_record);
        if let Some(sibling) = sibling {
            candidates.push(sibling);
        }
    }
    let convention = pdb_match_path(path);
    if !candidates.iter().any(|candidate| candidate == &convention) {
        candidates.push(convention);
    }

    let mut tried: Vec<String> = Vec::new();
    for candidate in &candidates {
        if candidate.is_file() {
            return match std::fs::read(candidate) {
                Ok(pdb_bytes) => {
                    let mut info = info;
                    info.notes.push(format!(
                        "读取 PDB {}（按{}找到）",
                        candidate.display(),
                        match &record {
                            Some(_) => "调试目录里的 CodeView 记录",
                            None => "同名约定",
                        }
                    ));
                    merge(info, read_pdb(object, &pdb_bytes))
                }
                Err(err) => {
                    let mut info = info;
                    info.notes.push(format!(
                        "找到 {} 但读不了（{err}）—— 只有 DWARF 可读",
                        candidate.display()
                    ));
                    info
                }
            };
        }
        tried.push(candidate.display().to_string());
    }
    let mut info = info;
    info.notes.push(format!(
        "目标是 PE，但没找到可读的 PDB —— 试过 {}；只有 DWARF 可读",
        tried.join("、")
    ));
    info
}

/// 按约定会去找的那个 PDB 路径（不检查是否存在），用于把"找过哪里"写进 `notes`。
fn pdb_match_path(target: &Path) -> std::path::PathBuf {
    let mut path = target.to_path_buf();
    if let Some(stem) = target.file_stem() {
        path.set_file_name(stem);
        path.set_extension("pdb");
    }
    path
}

/// 合并两种来源的调试信息（DWARF 与 PDB）。
///
/// 正常的目标只有其中一种；两种都有时（例如 `-g` 加 `-gcodeview`）合并，
/// 同一地址同一名字只留先到的那条，并把两边 `notes` 都保留 —— 用户能看到
/// 名字是从哪来的。`skipped` 相加：它是个计数，不是"有没有"。
#[must_use]
pub fn merge(mut base: DebugInfo, other: DebugInfo) -> DebugInfo {
    base.units.extend(other.units);
    base.functions.extend(other.functions);
    base.lines.extend(other.lines);
    base.skipped.declarations += other.skipped.declarations;
    base.skipped.unnamed += other.skipped.unnamed;
    base.skipped.without_range += other.skipped.without_range;
    base.skipped.inlined += other.skipped.inlined;
    base.notes.extend(other.notes);

    base.functions.sort_by_key(|f| (f.low_pc, f.high_pc));
    base.functions
        .dedup_by(|a, b| a.low_pc == b.low_pc && a.name == b.name);
    base.lines.sort_by_key(|l| (l.address, l.line));
    base.lines
        .dedup_by(|a, b| a.address == b.address && a.line == b.line && a.file == b.file);
    base
}
