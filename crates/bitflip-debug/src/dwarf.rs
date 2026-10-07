//! DWARF 读取（M8 交付物 1）。
//!
//! 只做一件事：把调试信息读成"有地址的函数"与"地址 → 源位置的行表"。
//! 不做命名优先级、不做类型系统、不改分析结果 —— 那些是 core 的事。
//!
//! 三条不变量：
//!
//! * **不猜。** 读不到就是 `None`，函数没有地址就不算函数，行号缺失的行就丢掉；
//!   不用 0 / 空串填空。
//! * **不失败。** 调试信息是"有更好、没有也行"的东西：格式不认识、某个编译单元
//!   坏掉了、节被截断，都变成 [`DebugInfo::notes`] 里的一句话，已经读到的结果保留。
//! * **不依赖符号表。** 本模块只看 `.debug_*` 节。目标有符号表时它是冗余的
//!   （符号表能给名字），真正的价值在符号表被剥掉之后 —— 那时名字和行号只剩这里
//!   一条来路。

use gimli::{AttributeValue, EndianSlice, RunTimeEndian, Unit};
use serde::Serialize;

use bitflip_loader::object::Object;

/// 读到的全部调试信息。
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize)]
pub struct DebugInfo {
    /// 编译单元（源文件、编译目录、生产者、语言）。
    pub units: Vec<DebugUnit>,
    /// 有地址的函数定义（按地址排序）。
    pub functions: Vec<DebugFunction>,
    /// 地址 → 源位置（按地址排序，`[address, address_end)` 有效）。
    pub lines: Vec<DebugLine>,
    /// 行表/单元里没有名字或没有地址而被丢掉的子程序个数（诚实计数，不静默）。
    pub skipped: DebugSkip,
    /// 降级说明（中文，直接可以在界面上显示）。
    pub notes: Vec<String>,
}

/// 被丢掉的子程序分类计数。
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize)]
pub struct DebugSkip {
    /// 只有声明没有代码（`DW_AT_declaration`，例如头文件里的 `printf`）。
    pub declarations: u64,
    /// 没有名字的子程序（DWARF 的抽象实例、模板实例）。
    pub unnamed: u64,
    /// 没有地址范围的子程序（被优化掉、或只有声明）。
    pub without_range: u64,
    /// 内联展开（`DW_TAG_inlined_subroutine`）：它们的行号不属于当前函数，未纳入。
    pub inlined: u64,
}

/// 编译单元。
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct DebugUnit {
    /// `DW_AT_name`：主源文件。
    pub name: Option<String>,
    /// `DW_AT_comp_dir`：编译目录。
    pub comp_dir: Option<String>,
    /// `DW_AT_producer`：编译器命令行。
    pub producer: Option<String>,
    /// `DW_AT_language` 的读法：常见语言给名字，其余给原始的 `DW_LANG_*` 代号。
    pub language: Option<String>,
}

/// 有地址的函数定义。
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct DebugFunction {
    /// `DW_AT_name`。
    pub name: String,
    /// `DW_AT_linkage_name`（C++ 的签名名；C 目标通常没有）。
    pub linkage_name: Option<String>,
    /// 起始地址（含）。
    pub low_pc: u64,
    /// 结束地址（不含）。
    pub high_pc: u64,
    /// `DW_AT_decl_file` 解析出的路径。
    pub decl_file: Option<String>,
    /// `DW_AT_decl_line`。
    pub decl_line: Option<u32>,
}

/// 地址 → 源位置。
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct DebugLine {
    /// 这一行覆盖的起始地址（含）。
    pub address: u64,
    /// 结束地址（不含）。
    pub address_end: u64,
    /// 源文件（解析出的路径，可能为 `None`：DWARF 允许没有文件表的行）。
    pub file: Option<String>,
    /// 行号。
    pub line: u32,
    /// 列号（0 表示没有）。
    pub column: u32,
}

impl DebugInfo {
    /// 有没有读到任何东西。
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.functions.is_empty() && self.lines.is_empty()
    }

    /// 某个地址落在哪一行（二分查找；`None` 表示这个地址没有行信息）。
    #[must_use]
    pub fn location_at(&self, address: u64) -> Option<&DebugLine> {
        let index = self.lines.partition_point(|row| row.address <= address);
        if index == 0 {
            return None;
        }
        let row = &self.lines[index - 1];
        if address < row.address_end {
            Some(row)
        } else {
            None
        }
    }

    /// 某个地址落在哪个函数里（二分查找）。
    #[must_use]
    pub fn function_containing(&self, address: u64) -> Option<&DebugFunction> {
        let index = self.functions.partition_point(|f| f.low_pc <= address);
        if index == 0 {
            return None;
        }
        let function = &self.functions[index - 1];
        if address < function.high_pc {
            Some(function)
        } else {
            None
        }
    }

    /// 源文件名（不含目录），界面上通常只显示这个。
    #[must_use]
    pub fn file_name(path: &str) -> &str {
        path.rsplit(['/', '\\']).next().unwrap_or(path)
    }
}

/// 读取目标里的 DWARF；没有调试信息时返回空的 [`DebugInfo`] 并在 `notes` 里说明。
#[must_use]
pub fn read_dwarf(object: &Object, bytes: &[u8]) -> DebugInfo {
    let mut info = DebugInfo::default();
    if object.section_by_name(".debug_info").is_none() {
        info.notes
            .push("目标里没有 `.debug_info`，无法提供源文件与行号".to_owned());
        if object
            .sections
            .iter()
            .any(|s| s.name.starts_with(".debug_"))
        {
            let names = object
                .sections
                .iter()
                .filter(|s| s.name.starts_with(".debug_"))
                .map(|s| s.name.as_str())
                .collect::<Vec<_>>()
                .join("、");
            info.notes
                .push(format!("目标里有调试节但没有 `.debug_info`：{names}"));
        }
        return info;
    }

    // 目标端序 → gimli 的端序枚举。端序是从目标读到的**值**，不是本层的判断：
    // `is_big()` 由 bitflip-arch 提供（见 scripts/check-arch-layering.ps1 的理由）。
    let endian = if object.endian.is_big() {
        RunTimeEndian::Big
    } else {
        RunTimeEndian::Little
    };
    let load = |id: gimli::SectionId| -> Result<EndianSlice<'_, RunTimeEndian>, gimli::Error> {
        let data = object
            .section_by_name(id.name())
            .and_then(|section| {
                let start = usize::try_from(section.file.offset).ok()?;
                let end = start.checked_add(usize::try_from(section.file.size).ok()?)?;
                bytes.get(start..end)
            })
            .unwrap_or(&[]);
        Ok(EndianSlice::new(data, endian))
    };

    let dwarf = match gimli::Dwarf::load(load) {
        Ok(dwarf) => dwarf,
        Err(error) => {
            info.notes.push(format!("DWARF 节表加载失败：{error}"));
            return info;
        }
    };

    let mut headers = dwarf.units();
    let mut unit_index = 0usize;
    loop {
        let header = match headers.next() {
            Ok(Some(header)) => header,
            Ok(None) => break,
            Err(error) => {
                // 读到节尾时 gimli 会报一次 `UnexpectedEof`：`.debug_*` 按对齐补零，
                // 补零之后再来一个"单元头"就撞到结尾了。已经读出过编译单元时，
                // 这是**正常结束**，但不说成"一切正常" —— 尾部确实有东西没被解析，
                // 万一是被截断的单元，用户在这里能看到线索。
                if unit_index == 0 {
                    info.notes
                        .push(format!("DWARF 编译单元列表在读取中断：{error}"));
                } else {
                    info.notes.push(format!(
                        "`.debug_info` 在最后一个编译单元之后还有读不下去的尾部（{error}），\
                         通常是补零对齐；已读出 {unit_index} 个编译单元"
                    ));
                }
                break;
            }
        };
        unit_index += 1;
        let unit = match dwarf.unit(header) {
            Ok(unit) => unit,
            Err(error) => {
                info.notes.push(format!(
                    "第 {unit_index} 个编译单元读不出来（{error}），已读到的结果保留"
                ));
                continue;
            }
        };
        match read_unit(&dwarf, &unit) {
            Ok(parsed) => {
                info.units.push(parsed.unit);
                info.functions.extend(parsed.functions);
                info.lines.extend(parsed.lines);
                info.skipped.declarations += parsed.skipped.declarations;
                info.skipped.unnamed += parsed.skipped.unnamed;
                info.skipped.without_range += parsed.skipped.without_range;
                info.skipped.inlined += parsed.skipped.inlined;
            }
            Err(error) => {
                info.notes.push(format!(
                    "第 {unit_index} 个编译单元在解析到一半时中断（{error}），已读到的结果保留"
                ));
            }
        }
    }

    info.functions.sort_by_key(|f| (f.low_pc, f.high_pc));
    info.functions
        .dedup_by(|a, b| a.low_pc == b.low_pc && a.name == b.name);

    // 行表：按地址排序，并补齐每行的结束地址。DWARF 的行是"从这里开始"的语义，
    // 一行的有效范围到下一行为止；行程序序列结束（end_sequence）时按序列末尾收敛。
    info.lines.sort_by_key(|row| row.address);
    let mut covered = Vec::with_capacity(info.lines.len());
    let mut dropped = 0u64;
    for index in 0..info.lines.len() {
        let next = info.lines.get(index + 1).map(|row| row.address);
        let row = info.lines[index].clone();
        let end = if row.address_end > row.address {
            row.address_end
        } else {
            match next {
                Some(next) => next,
                None => continue,
            }
        };
        if end <= row.address {
            dropped += 1;
            continue;
        }
        covered.push(DebugLine {
            address_end: end,
            ..row
        });
    }
    if dropped > 0 {
        info.notes
            .push(format!("有 {dropped} 条行记录没有覆盖范围，已丢弃"));
    }
    info.lines = covered;

    if !info.is_empty() {
        let units = info.units.len();
        let functions = info.functions.len();
        let lines = info.lines.len();
        info.notes.push(format!(
            "DWARF：{units} 个编译单元、{functions} 个有地址的函数、{lines} 条行记录"
        ));
    } else {
        info.notes.push(
            "目标里有 `.debug_info` 但没读出任何有地址的函数或行记录（可能被裁剪过）".to_owned(),
        );
    }
    if info.skipped.declarations > 0 {
        info.notes.push(format!(
            "有 {} 个子程序只有声明没有代码（例如头文件里的库函数），不算函数",
            info.skipped.declarations
        ));
    }
    if info.skipped.unnamed > 0 {
        info.notes.push(format!(
            "有 {} 个子程序没有名字，未纳入",
            info.skipped.unnamed
        ));
    }
    if info.skipped.without_range > 0 {
        info.notes.push(format!(
            "有 {} 个子程序没有地址范围（被优化掉或只有声明），未纳入",
            info.skipped.without_range
        ));
    }
    if info.skipped.inlined > 0 {
        info.notes.push(format!(
            "有 {} 处内联展开的行号未纳入（它们的位置属于被内联的那个函数）",
            info.skipped.inlined
        ));
    }
    info
}

/// 单个编译单元的解析结果。
struct UnitParse {
    unit: DebugUnit,
    functions: Vec<DebugFunction>,
    lines: Vec<DebugLine>,
    skipped: DebugSkip,
}

fn read_unit(
    dwarf: &gimli::Dwarf<EndianSlice<'_, RunTimeEndian>>,
    unit: &Unit<EndianSlice<'_, RunTimeEndian>>,
) -> Result<UnitParse, gimli::Error> {
    let mut parsed = UnitParse {
        unit: DebugUnit {
            name: None,
            comp_dir: None,
            producer: None,
            language: None,
        },
        functions: Vec::new(),
        lines: Vec::new(),
        skipped: DebugSkip::default(),
    };

    let mut entries = unit.entries();
    while let Some((_, entry)) = entries.next_dfs()? {
        if entry.tag() == gimli::DW_TAG_compile_unit {
            parsed.unit.name = attr_string(dwarf, unit, entry, gimli::DW_AT_name);
            parsed.unit.comp_dir = attr_string(dwarf, unit, entry, gimli::DW_AT_comp_dir);
            parsed.unit.producer = attr_string(dwarf, unit, entry, gimli::DW_AT_producer);
            parsed.unit.language = entry
                .attr_value(gimli::DW_AT_language)
                .ok()
                .flatten()
                .and_then(|value| match value {
                    AttributeValue::Language(language) => {
                        Some(language_name(u64::from(language.0)))
                    }
                    _ => None,
                });
            continue;
        }
        if entry.tag() == gimli::DW_TAG_inlined_subroutine {
            // 内联展开有它自己的行号（"被内联进来的那个函数"的位置），与"这段代码
            // 在哪个函数里"是两回事。混进行表会让函数的行号在源码里乱跳，所以不读；
            // 但要数出来 —— 数量不为零时，行号看着不全的原因就在这儿。
            parsed.skipped.inlined += 1;
            continue;
        }
        if entry.tag() != gimli::DW_TAG_subprogram {
            continue;
        }

        let declaration = entry
            .attr_value(gimli::DW_AT_declaration)
            .ok()
            .flatten()
            .is_some_and(|value| matches!(value, AttributeValue::Flag(true)));
        if declaration {
            parsed.skipped.declarations += 1;
            continue;
        }
        let name = attr_string(dwarf, unit, entry, gimli::DW_AT_name)
            .or_else(|| attr_string(dwarf, unit, entry, gimli::DW_AT_linkage_name));
        let Some(name) = name else {
            parsed.skipped.unnamed += 1;
            continue;
        };
        let Some(low_pc) = attr_address(dwarf, unit, entry, gimli::DW_AT_low_pc) else {
            parsed.skipped.without_range += 1;
            continue;
        };
        // high_pc 有两种形式：DWARF 4 之前是绝对地址，之后是相对 low_pc 的偏移。
        let Some(high_pc) = entry
            .attr_value(gimli::DW_AT_high_pc)
            .ok()
            .flatten()
            .and_then(|value| high_pc(value, low_pc))
        else {
            parsed.skipped.without_range += 1;
            continue;
        };
        if high_pc <= low_pc {
            parsed.skipped.without_range += 1;
            continue;
        }

        let decl_file = entry
            .attr_value(gimli::DW_AT_decl_file)
            .ok()
            .flatten()
            .and_then(|value| file_index(value))
            .and_then(|index| file_path(dwarf, unit, index));
        let decl_line = entry
            .attr_value(gimli::DW_AT_decl_line)
            .ok()
            .flatten()
            .and_then(|value| unsigned(value))
            .and_then(|value| u32::try_from(value).ok());
        parsed.functions.push(DebugFunction {
            name,
            linkage_name: attr_string(dwarf, unit, entry, gimli::DW_AT_linkage_name),
            low_pc,
            high_pc,
            decl_file,
            decl_line,
        });
    }

    // 行程序：一条编译单元一条。
    if let Some(program) = unit.line_program.clone() {
        let mut rows = program.rows();
        let mut previous: Option<usize> = None;
        // 行头（`header`）就是本单元行程序的头，`file_path` 会自己取它。
        while let Some((_header, row)) = rows.next_row()? {
            let address = row.address();
            if let Some(index) = previous.take() {
                parsed.lines[index].address_end = address;
            }
            if row.end_sequence() {
                continue;
            }
            let Some(line) = row.line() else {
                continue;
            };
            let file = file_path(dwarf, unit, row.file_index());
            parsed.lines.push(DebugLine {
                address,
                address_end: 0,
                file,
                line: u32::try_from(line.get()).unwrap_or(u32::MAX),
                column: column_of(row.column()),
            });
            previous = Some(parsed.lines.len() - 1);
        }
    }

    Ok(parsed)
}

/// 读一个字符串属性（`DW_AT_name` 这类）。
fn attr_string(
    dwarf: &gimli::Dwarf<EndianSlice<'_, RunTimeEndian>>,
    unit: &Unit<EndianSlice<'_, RunTimeEndian>>,
    entry: &gimli::DebuggingInformationEntry<'_, '_, EndianSlice<'_, RunTimeEndian>>,
    name: gimli::DwAt,
) -> Option<String> {
    let value = entry.attr_value(name).ok().flatten()?;
    let slice = dwarf.attr_string(unit, value).ok()?;
    let text = slice.to_string_lossy();
    let text = text.trim();
    if text.is_empty() {
        None
    } else {
        Some(text.to_owned())
    }
}

/// 读一个地址属性。
fn attr_address(
    dwarf: &gimli::Dwarf<EndianSlice<'_, RunTimeEndian>>,
    unit: &Unit<EndianSlice<'_, RunTimeEndian>>,
    entry: &gimli::DebuggingInformationEntry<'_, '_, EndianSlice<'_, RunTimeEndian>>,
    name: gimli::DwAt,
) -> Option<u64> {
    let value = entry.attr_value(name).ok().flatten()?;
    match value {
        AttributeValue::Addr(address) => Some(address),
        AttributeValue::DebugAddrIndex(index) => dwarf.address(unit, index).ok(),
        _ => unsigned(value),
    }
}

/// 列号：`LeftEdge` 表示"从行首开始"，与"没有列信息"不同，但都不给具体列号。
fn column_of(column: gimli::ColumnType) -> u32 {
    match column {
        gimli::ColumnType::LeftEdge => 0,
        gimli::ColumnType::Column(value) => u32::try_from(value.get()).unwrap_or(u32::MAX),
    }
}

/// 把 `DW_AT_high_pc` 的两种形式都算成绝对地址。
fn high_pc(value: AttributeValue<EndianSlice<'_, RunTimeEndian>>, low_pc: u64) -> Option<u64> {
    match value {
        AttributeValue::Addr(address) => Some(address),
        other => unsigned(other).map(|offset| low_pc.saturating_add(offset)),
    }
}

/// 取无符号数值（`udata` / `data*` 两种形式）。
fn unsigned(value: AttributeValue<EndianSlice<'_, RunTimeEndian>>) -> Option<u64> {
    match value {
        AttributeValue::Udata(value) => Some(value),
        AttributeValue::Data1(value) => Some(u64::from(value)),
        AttributeValue::Data2(value) => Some(u64::from(value)),
        AttributeValue::Data4(value) => Some(u64::from(value)),
        AttributeValue::Data8(value) => Some(value),
        AttributeValue::Sdata(value) => u64::try_from(value).ok(),
        _ => None,
    }
}

/// `DW_AT_decl_file`：DWARF 4 是行表文件表的下标，早期版本直接给数字。
fn file_index(value: AttributeValue<EndianSlice<'_, RunTimeEndian>>) -> Option<u64> {
    match value {
        AttributeValue::FileIndex(index) => Some(index),
        other => unsigned(other),
    }
}

/// 把文件表下标解析成路径。
fn file_path(
    dwarf: &gimli::Dwarf<EndianSlice<'_, RunTimeEndian>>,
    unit: &Unit<EndianSlice<'_, RunTimeEndian>>,
    index: u64,
) -> Option<String> {
    let program = unit.line_program.as_ref()?;
    let header = program.header();
    let file = header.file(index)?;
    let name = dwarf
        .attr_string(unit, file.path_name())
        .ok()?
        .to_string_lossy()
        .to_string();
    if name.is_empty() {
        return None;
    }
    let directory = file
        .directory(header)
        .and_then(|value| dwarf.attr_string(unit, value).ok())
        .map(|slice| slice.to_string_lossy().to_string())
        .filter(|text| !text.is_empty());
    Some(join_path(directory.as_deref(), &name))
}

/// 拼路径：已经有目录名就不动，否则接上目录（统一用 `/`，界面上好认）。
fn join_path(directory: Option<&str>, name: &str) -> String {
    let Some(directory) = directory else {
        return name.to_owned();
    };
    let absolute =
        name.starts_with('/') || name.starts_with('\\') || name.as_bytes().get(1) == Some(&b':');
    if absolute {
        return name.to_owned();
    }
    let directory = directory.replace('\\', "/");
    let name = name.replace('\\', "/");
    format!("{}/{}", directory.trim_end_matches('/'), name)
}

/// `DW_AT_language` 的常见取值。
fn language_name(code: u64) -> String {
    let known = match code {
        0x0001 => Some("C89"),
        0x0002 => Some("C"),
        0x0004 => Some("C++"),
        0x000c => Some("C99"),
        0x001d => Some("C11"),
        0x002a => Some("C++11"),
        0x002b => Some("C++14"),
        0x002c => Some("C++17"),
        0x0008 => Some("Rust"),
        _ => None,
    };
    match known {
        Some(name) => name.to_owned(),
        None => format!("DW_LANG_{code:#06x}"),
    }
}
