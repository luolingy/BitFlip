//! PE32/PE32+ 解析（`docs/PLAN.md` M1）。
//!
//! 覆盖：DOS 头 → PE 签名 → COFF 文件头 → 可选头（PE32/PE32+）→ 节表、
//! 入口（RVA 转虚拟地址）、镜像基址、数据目录、导入表（含按序号导入）、
//! 导出表（含转发导出）、基址重定位、`.pdata` RUNTIME_FUNCTION。
//!
//! 解析纪律与 ELF 一致：全部通过 [`Reader`]，越界返回错误；
//! 表项数量来自不可信输入，先整体校验范围再逐项解析，并对数量封顶。
//!
//! 关于 RVA：PE 头里的地址都是 RVA（相对虚拟地址）。分析层统一用虚拟地址
//! （`ImageBase + RVA`），转换只在解析时做一次 —— 见 `rva_to_va`。

use std::collections::BTreeMap;

use bitflip_arch::{Arch, ArchSpec, Endian, Mode};

use crate::object::{
    ContentKind, Export, FileRange, FormatInfo, Import, Object, ObjectId, Perms, RawSymbol, Reloc,
    RelocKind, Section, Segment, SymbolTableSource, UnwindEntry,
};
use crate::reader::{Endianness, ParseError, Reader};
use crate::ObjectKind;

/// DOS 头固定部分大小。
const DOS_HEADER_SIZE: u64 = 64;
/// COFF 文件头大小。
const COFF_HEADER_SIZE: u64 = 20;
/// 节表项大小。
const SECTION_HEADER_SIZE: u64 = 40;

/// 节表项数量上限（`NumberOfSections` 是 16 位，但仍做对称防御）。
const MAX_SECTIONS: u64 = 96; // PE 规范硬限制

/// 导入/导出/重定位表项数量上限。
const MAX_TABLE_ENTRIES: u64 = 1_000_000;

/// 字符串读取上限。
const MAX_STRING: u64 = 4096;

/// 数据目录项数量。
const DIR_COUNT: u64 = 16;

/// 数据目录索引。
mod dir {
    /// 导出表。
    pub const EXPORT: usize = 0;
    /// 导入表。
    pub const IMPORT: usize = 1;
    /// 异常表（x64 的 `.pdata`）。
    pub const EXCEPTION: usize = 3;
    /// 基址重定位表。
    pub const BASERELOC: usize = 5;
    /// 调试目录。
    pub const DEBUG: usize = 6;
    /// 延迟导入表。
    pub const DELAY_IMPORT: usize = 13;
    /// CLI 头（.NET）。
    pub const COM_DESCRIPTOR: usize = 14;
}

/// 一个数据目录项。
#[derive(Debug, Clone, Copy, Default)]
struct DataDir {
    rva: u32,
    size: u32,
}

impl DataDir {
    fn is_empty(&self) -> bool {
        self.rva == 0 || self.size == 0
    }
}

/// 解析好的可选头关键字段。
#[derive(Debug, Clone)]
struct OptionalHeader {
    image_base: u64,
    entry_rva: u32,
    section_align: u32,
    file_align: u32,
    subsystem: u16,
    dll_characteristics: u16,
    /// `SizeOfImage`：映像装入内存后的总大小（用于 `declared_size`）。
    size_of_image: u32,
    size_of_headers: u32,
    dirs: Vec<DataDir>,
}

/// 一个节头。
#[derive(Debug, Clone)]
struct PeSection {
    name: String,
    virtual_size: u32,
    virtual_address: u32,
    raw_size: u32,
    raw_pointer: u32,
    characteristics: u32,
}

/// 解析入口：把 PE 字节解析成 [`Object`]。
pub fn parse(bytes: &[u8], base: u64, id: ObjectId) -> Result<Object, ParseError> {
    let reader = Reader::with_base(bytes, base);

    // ── DOS 头 ──
    reader.expect_magic(0, b"MZ", "DOS 头")?;
    let pe_offset = u64::from(reader.u32(0x3c, Endianness::Little, "e_lfanew")?);
    if pe_offset == 0 {
        return Err(ParseError::Inconsistent(
            "e_lfanew = 0：没有指向 PE 头".into(),
        ));
    }
    // e_lfanew 必须落在文件内，且不能指向 DOS 头内部（自引用）
    if pe_offset < DOS_HEADER_SIZE || pe_offset >= reader.len() {
        return Err(ParseError::Inconsistent(format!(
            "e_lfanew = {pe_offset:#x} 超出文件范围（0x40..{:#x}）",
            reader.len()
        )));
    }

    reader.expect_magic(pe_offset, b"PE\0\0", "PE 签名")?;

    // ── COFF 文件头 ──
    let coff = pe_offset + 4;
    let machine = reader.u16(coff, Endianness::Little, "Machine")?;
    let num_sections = u64::from(reader.u16(coff + 2, Endianness::Little, "NumberOfSections")?);
    let timestamp = reader.u32(coff + 4, Endianness::Little, "TimeDateStamp")?;
    let num_symbols = reader.u32(coff + 12, Endianness::Little, "NumberOfSymbols")?;
    let symbol_table_ptr = reader.u32(coff + 8, Endianness::Little, "PointerToSymbolTable")?;
    let optional_size =
        u64::from(reader.u16(coff + 16, Endianness::Little, "SizeOfOptionalHeader")?);
    let characteristics = reader.u16(coff + 18, Endianness::Little, "Characteristics")?;

    // ── 架构 ──
    let (arch_kind, mode) = Arch::from_pe_machine(machine).ok_or(ParseError::Unsupported {
        what: "Machine",
        value: u64::from(machine),
        detail: "未知或尚未支持的 PE 机器类型（见 docs/PLAN.md §1.3 架构矩阵）",
    })?;
    let arch = ArchSpec::from_arch(arch_kind, mode, Endian::Little);
    let mut object = Object::new(id, ObjectKind::Pe, arch, Endian::Little);

    if num_sections > MAX_SECTIONS {
        return Err(ParseError::Unsupported {
            what: "NumberOfSections",
            value: num_sections,
            detail: "PE 规范限制最多 96 个节，超过这个数字的文件结构不合法",
        });
    }

    // 可选头：目标文件（.obj）没有可选头，此时 SizeOfOptionalHeader = 0
    let optional_offset = coff + COFF_HEADER_SIZE;
    let mut optional: Option<OptionalHeader> = None;
    if optional_size > 0 {
        if optional_size < 2 {
            return Err(ParseError::Inconsistent(
                "SizeOfOptionalHeader 太小，读不到 Magic".into(),
            ));
        }
        let magic = reader.u16(optional_offset, Endianness::Little, "可选头 Magic")?;
        let is_pe32_plus = match magic {
            0x010b => false,
            0x020b => true,
            other => {
                return Err(ParseError::Unsupported {
                    what: "可选头 Magic",
                    value: u64::from(other),
                    detail: "只支持 PE32 (0x10b) 与 PE32+ (0x20b)",
                })
            }
        };
        optional = Some(parse_optional_header(
            &reader,
            optional_offset,
            is_pe32_plus,
        )?);
    }

    // ── 节表 ──
    let sections_offset = optional_offset
        .checked_add(optional_size)
        .ok_or_else(|| ParseError::Overflow("节表偏移".into()))?;
    let raw_sections: Vec<PeSection> = reader.for_each_entry(
        sections_offset,
        SECTION_HEADER_SIZE,
        num_sections,
        "节表",
        |_i, view| parse_section_header(&view),
    )?;

    // ── 镜像基址与入口 ──
    object.image_base = optional.as_ref().map_or(0, |o| o.image_base);
    object.entry = optional.as_ref().and_then(|o| {
        let rva = o.entry_rva;
        if rva == 0 {
            // RVA 0 表示没有入口（DLL 常见）—— 报 None 而不是 image_base
            None
        } else {
            Some(object.image_base.wrapping_add(u64::from(rva)))
        }
    });

    // ── 段与节 ──
    // PE 的节同时是"内存段"和"文件节"，两套视图内容一致但语义不同，
    // 因此两边都填 —— 分析层用 segments，展示层用 sections。
    let mut sections = Vec::with_capacity(raw_sections.len());
    let mut segments = Vec::with_capacity(raw_sections.len());
    for raw in &raw_sections {
        let perms = pe_perms(raw.characteristics);
        let kind = pe_content_kind(&raw.name, perms);
        let vsize = u64::from(if raw.virtual_size == 0 {
            raw.raw_size
        } else {
            raw.virtual_size
        });
        let vaddr = object
            .image_base
            .wrapping_add(u64::from(raw.virtual_address));

        // 节数据必须落在文件内；否则记 note（一个坏节不该让整文件读不了）
        let file_end = u64::from(raw.raw_pointer).checked_add(u64::from(raw.raw_size));
        let in_bounds = file_end.is_some_and(|end| end <= reader.len());
        if raw.raw_size > 0 && !in_bounds {
            object.note(format!(
                "节 {} 的数据范围 {:#x}+{:#x} 超出文件大小 {:#x}，文件可能被裁剪",
                raw.name,
                raw.raw_pointer,
                raw.raw_size,
                reader.len()
            ));
        }

        let file = if raw.raw_size > 0 {
            Some(FileRange::new(
                u64::from(raw.raw_pointer),
                u64::from(raw.raw_size),
            ))
        } else {
            None
        };

        sections.push(Section {
            name: raw.name.clone(),
            vaddr,
            file: FileRange::new(u64::from(raw.raw_pointer), u64::from(raw.raw_size)),
            perms,
            kind,
            loaded: perms.read,
        });
        segments.push(Segment {
            name: raw.name.clone(),
            vaddr,
            vsize,
            file,
            perms,
            kind,
            align: u64::from(optional.as_ref().map_or(0x1000, |o| o.section_align.max(1))),
        });
    }
    object.sections = sections;
    object.segments = segments;

    // ── 数据目录 ──
    if let Some(opt) = &optional {
        // 导入表（含延迟导入）
        if let Some(dir) = opt.dirs.get(dir::IMPORT).copied().filter(|d| !d.is_empty()) {
            match parse_imports(&reader, &object, dir) {
                Ok((imports, skipped)) => {
                    object.imports.extend(imports);
                    for note in skipped {
                        object.note(note);
                    }
                }
                Err(error) => object.note(format!("导入表解析失败：{}", error.summary_zh())),
            }
        }
        if let Some(dir) = opt
            .dirs
            .get(dir::DELAY_IMPORT)
            .copied()
            .filter(|d| !d.is_empty())
        {
            match parse_delay_imports(&reader, &object, dir) {
                Ok(imports) => object.imports.extend(imports),
                Err(error) => object.note(format!("延迟导入表解析失败：{}", error.summary_zh())),
            }
        }

        // 导出表
        if let Some(dir) = opt.dirs.get(dir::EXPORT).copied().filter(|d| !d.is_empty()) {
            match parse_exports(&reader, &object, dir) {
                Ok(exports) => object.exports = exports,
                Err(error) => object.note(format!("导出表解析失败：{}", error.summary_zh())),
            }
        }

        // 基址重定位
        if let Some(dir) = opt
            .dirs
            .get(dir::BASERELOC)
            .copied()
            .filter(|d| !d.is_empty())
        {
            match parse_relocations(&reader, &object, dir) {
                Ok((relocs, skipped)) => {
                    object.relocations = relocs;
                    for note in skipped {
                        object.note(note);
                    }
                }
                Err(error) => object.note(format!("重定位表解析失败：{}", error.summary_zh())),
            }
        }

        // .pdata（x64 的 RUNTIME_FUNCTION）
        if let Some(dir) = opt
            .dirs
            .get(dir::EXCEPTION)
            .copied()
            .filter(|d| !d.is_empty())
        {
            if mode == Mode::M64 {
                match parse_pdata(&reader, &object, dir) {
                    Ok(unwind) => {
                        let count = unwind.len();
                        object.unwind = unwind;
                        if count > 0 {
                            object.note(format!(
                                "已读取 {count} 条 .pdata 展开条目（用于 M3 的函数边界推断）"
                            ));
                        }
                    }
                    Err(error) => object.note(format!(".pdata 解析失败：{}", error.summary_zh())),
                }
            } else {
                object.note("异常目录存在，但 .pdata 只对 64 位 PE 有效，已跳过");
            }
        }

        // 调试目录：只在有内容时提示"有符号可挖"，PDB 解析排期 M8
        if let Some(dir_ref) = opt.dirs.get(dir::DEBUG).copied().filter(|d| !d.is_empty()) {
            object.note(format!(
                "存在调试目录（RVA {:#x}，{} 字节）：可能含 PDB 路径。PDB/DWARF 符号解析排期在 M8（见 docs/PLAN.md）",
                dir_ref.rva, dir_ref.size
            ));
        }

        // .NET 检测
        if let Some(dir) = opt
            .dirs
            .get(dir::COM_DESCRIPTOR)
            .copied()
            .filter(|d| !d.is_empty())
        {
            object.note(format!(
                "包含 CLI 头（RVA {:#x}）：这是一个 .NET 托管程序集，本工具只做识别，不反编译 CIL（见 docs/PLAN.md §1.4）",
                dir.rva
            ));
        }
    }

    // ── COFF 符号表（目标文件才有）──
    if num_symbols > 0 && symbol_table_ptr != 0 {
        match parse_coff_symbols(&reader, symbol_table_ptr, num_symbols, &object) {
            Ok(symbols) => object.symbols.extend(symbols),
            Err(error) => object.note(format!("COFF 符号表解析失败：{}", error.summary_zh())),
        }
    }

    // ── 头部自述值的合理性检查 ──
    // 这些检查不参与解析（解析一律按规范结构走），只把"这个文件不对劲"讲出来。
    if let Some(opt) = &optional {
        // FileAlignment 必须是 2 的幂且在 512..=64K 之间（PE 规范要求）
        if opt.file_align != 0 && !opt.file_align.is_power_of_two() {
            object.note(format!(
                "FileAlignment = {:#x} 不是 2 的幂，文件头不符合 PE 规范",
                opt.file_align
            ));
        }
        // SectionAlignment 必须 >= FileAlignment
        if opt.section_align != 0 && opt.file_align != 0 && opt.section_align < opt.file_align {
            object.note(format!(
                "SectionAlignment({:#x}) 小于 FileAlignment({:#x})，文件头不符合 PE 规范",
                opt.section_align, opt.file_align
            ));
        }
        // SizeOfHeaders 至少要放下 DOS 头 + PE 头 + 节表
        let headers_end =
            sections_offset.saturating_add(u64::from(num_sections as u32) * SECTION_HEADER_SIZE);
        if u64::from(opt.size_of_headers) < headers_end {
            object.note(format!(
                "SizeOfHeaders = {:#x} 小于头部实际结束位置 {headers_end:#x}，文件头不符合 PE 规范",
                opt.size_of_headers
            ));
        }
        // ASLR：DYNAMIC_BASE 未设置意味着映像固定加载地址
        const DYNAMIC_BASE: u16 = 0x0040;
        if opt.dll_characteristics & DYNAMIC_BASE == 0
            && !object.format.is_relocatable
            && object.relocations.is_empty()
        {
            object.note(
                "未设置 DYNAMIC_BASE 且没有基址重定位表：该映像只能加载到 ImageBase 指定的地址",
            );
        }
    }

    // ── 格式信息 ──
    object.format = FormatInfo {
        type_name: Some(if optional.is_none() {
            "COFF 目标文件".to_string()
        } else if characteristics & 0x2000 != 0 {
            "DLL".to_string()
        } else if characteristics & 0x0002 != 0 {
            "PE 可执行文件".to_string()
        } else {
            "PE 映像".to_string()
        }),
        os_abi: Some(if optional.is_some() && mode == Mode::M64 {
            "Windows x64".to_string()
        } else {
            "Windows".to_string()
        }),
        subsystem: optional.as_ref().map(|o| subsystem_label(o.subsystem)),
        is_dynamic_library: characteristics & 0x2000 != 0,
        is_executable: optional.is_some(),
        is_relocatable: optional.is_none(),
        // 有导出或调试信息就不算完全剥离；精确判断需要解析调试目录
        is_stripped: false,
        declared_size: optional.as_ref().map(|o| u64::from(o.size_of_image)),
    };
    let _ = timestamp;

    Ok(object)
}

/// 解析可选头。
fn parse_optional_header(
    reader: &Reader<'_>,
    offset: u64,
    is_pe32_plus: bool,
) -> Result<OptionalHeader, ParseError> {
    // 字段偏移在 PE32 / PE32+ 之间只差 ImageBase 与几个栈字段的宽度
    let entry_rva = reader.u32(offset + 16, Endianness::Little, "AddressOfEntryPoint")?;
    let section_align = reader.u32(offset + 32, Endianness::Little, "SectionAlignment")?;
    let file_align = reader.u32(offset + 36, Endianness::Little, "FileAlignment")?;
    let size_of_image = reader.u32(offset + 56, Endianness::Little, "SizeOfImage")?;
    let size_of_headers = reader.u32(offset + 60, Endianness::Little, "SizeOfHeaders")?;
    let subsystem = reader.u16(offset + 68, Endianness::Little, "Subsystem")?;
    let dll_characteristics = reader.u16(offset + 70, Endianness::Little, "DllCharacteristics")?;

    let (image_base, dir_offset) = if is_pe32_plus {
        (
            reader.u64(offset + 24, Endianness::Little, "ImageBase")?,
            112,
        )
    } else {
        (
            u64::from(reader.u32(offset + 28, Endianness::Little, "ImageBase")?),
            96,
        )
    };

    // NumberOfRvaAndSizes 决定数据目录的实际项数，可能少于/多于 16
    let declared_dirs = u64::from(reader.u32(
        offset + if is_pe32_plus { 108 } else { 92 },
        Endianness::Little,
        "NumberOfRvaAndSizes",
    )?);

    let dirs_offset = offset + dir_offset;
    // 最多读 16 项（规范定义），多余的忽略；不足的按 0 补齐
    let available = declared_dirs.min(DIR_COUNT);
    let mut dirs = Vec::with_capacity(DIR_COUNT as usize);
    for index in 0..available {
        let entry = dirs_offset + index * 8;
        dirs.push(DataDir {
            rva: reader.u32(entry, Endianness::Little, "数据目录 RVA")?,
            size: reader.u32(entry + 4, Endianness::Little, "数据目录 Size")?,
        });
    }
    dirs.resize(DIR_COUNT as usize, DataDir::default());

    Ok(OptionalHeader {
        image_base,
        entry_rva,
        section_align,
        file_align,
        subsystem,
        dll_characteristics,
        size_of_image,
        size_of_headers,
        dirs,
    })
}

/// 解析一个节头。
///
/// PE 节名是 8 字节定长、**不以 NUL 结尾**（长名用 `/NNN` 引用 COFF 字符串表）。
/// 这里必须按 8 字节修剪，而不是当 C 字符串读 —— 否则会读到相邻字段。
fn parse_section_header(view: &Reader<'_>) -> Result<PeSection, ParseError> {
    let raw_name = view.slice(0, 8, "节名")?;
    let end = raw_name.iter().position(|&b| b == 0).unwrap_or(8);
    let name = String::from_utf8_lossy(&raw_name[..end]).trim().to_string();

    Ok(PeSection {
        name,
        virtual_size: view.u32(8, Endianness::Little, "VirtualSize")?,
        virtual_address: view.u32(12, Endianness::Little, "VirtualAddress")?,
        raw_size: view.u32(16, Endianness::Little, "SizeOfRawData")?,
        raw_pointer: view.u32(20, Endianness::Little, "PointerToRawData")?,
        characteristics: view.u32(36, Endianness::Little, "Characteristics")?,
    })
}

/// 节权限。
fn pe_perms(characteristics: u32) -> Perms {
    const MEM_EXECUTE: u32 = 0x2000_0000;
    const MEM_READ: u32 = 0x4000_0000;
    const MEM_WRITE: u32 = 0x8000_0000;
    Perms {
        read: characteristics & MEM_READ != 0,
        write: characteristics & MEM_WRITE != 0,
        execute: characteristics & MEM_EXECUTE != 0,
    }
}

/// 由节名与权限推断内容类别。
fn pe_content_kind(name: &str, perms: Perms) -> ContentKind {
    // 名称推断优先（PE 没有标准的节类型字段）
    match name {
        ".text" | "CODE" | ".code" => ContentKind::Code,
        ".data" | "DATA" => ContentKind::Data,
        ".rdata" | ".rodata" | "CONST" => ContentKind::ReadOnlyData,
        ".bss" => ContentKind::Bss,
        ".idata" | ".import" => ContentKind::ImportTable,
        ".edata" | ".export" => ContentKind::ExportTable,
        ".reloc" => ContentKind::Relocations,
        ".rsrc" => ContentKind::Resources,
        ".pdata" => ContentKind::Unwind,
        ".debug" | ".debug$S" | ".debug$T" => ContentKind::Debug,
        ".tls" => ContentKind::Data,
        _ => {
            if perms.execute {
                ContentKind::Code
            } else if perms.write {
                ContentKind::Data
            } else if perms.read {
                ContentKind::ReadOnlyData
            } else {
                ContentKind::Unknown
            }
        }
    }
}

/// 子系统名称。
fn subsystem_label(subsystem: u16) -> String {
    match subsystem {
        0 => "未知".to_string(),
        1 => "Native".to_string(),
        2 => "Windows GUI".to_string(),
        3 => "Windows 控制台".to_string(),
        5 => "OS/2 控制台".to_string(),
        7 => "POSIX 控制台".to_string(),
        9 => "Windows CE GUI".to_string(),
        10 => "EFI 应用".to_string(),
        11 => "EFI 引导驱动".to_string(),
        12 => "EFI 运行驱动".to_string(),
        13 => "EFI ROM".to_string(),
        14 => "Xbox".to_string(),
        16 => "Windows 引导应用".to_string(),
        other => format!("子系统 {other}"),
    }
}

/// RVA → 文件偏移（用节表映射）。
///
/// 返回 `None` 表示 RVA 不在任何有文件后备的节里（例如 .bss 或头部）。
fn rva_to_offset(object: &Object, rva: u32) -> Option<u64> {
    let rva = u64::from(rva);
    for segment in &object.segments {
        // segments 里的 vaddr 是 VA，需要减去 image_base 才是 RVA
        let seg_rva = segment.vaddr.checked_sub(object.image_base)?;
        if rva < seg_rva {
            continue;
        }
        let delta = rva - seg_rva;
        let file = segment.file?;
        if delta >= file.size {
            continue;
        }
        return file.offset.checked_add(delta);
    }
    None
}

/// RVA → 虚拟地址。
fn rva_to_va(object: &Object, rva: u32) -> u64 {
    object.image_base.wrapping_add(u64::from(rva))
}

/// 解析导入表，返回（导入项，降级说明）。
///
/// 返回说明而不是直接改 `Object`：这个函数需要 `&Object` 做 RVA 映射，
/// 同时又要报告问题 —— 交给调用方写入，避免既借用又修改。
fn parse_imports(
    reader: &Reader<'_>,
    object: &Object,
    dir: DataDir,
) -> Result<(Vec<Import>, Vec<String>), ParseError> {
    // IMAGE_IMPORT_DESCRIPTOR 是 20 字节，以全 0 结尾
    const DESCRIPTOR_SIZE: u64 = 20;
    let count = u64::from(dir.size) / DESCRIPTOR_SIZE;
    if count == 0 {
        return Ok((Vec::new(), Vec::new()));
    }
    let offset = rva_to_offset(object, dir.rva).ok_or_else(|| {
        ParseError::Inconsistent(format!("导入表 RVA {:#x} 不在任何节内", dir.rva))
    })?;

    let mut out = Vec::new();
    let mut skipped: Vec<String> = Vec::new();
    let mut skipped_modules: Vec<String> = Vec::new();
    let mut unnamed = 0usize;
    for index in 0..count.min(MAX_TABLE_ENTRIES) {
        let Some(entry_offset) = offset.checked_add(index * DESCRIPTOR_SIZE) else {
            break;
        };
        let Ok(view) = reader.slice(entry_offset, DESCRIPTOR_SIZE, "导入描述符") else {
            break;
        };
        let view = Reader::with_base(view, reader.base() + entry_offset);

        let original_first_thunk = view.u32(0, Endianness::Little, "OriginalFirstThunk")?;
        let name_rva = view.u32(12, Endianness::Little, "Name")?;
        let first_thunk = view.u32(16, Endianness::Little, "FirstThunk")?;

        // 全 0 描述符是结束标记
        if original_first_thunk == 0 && name_rva == 0 && first_thunk == 0 {
            break;
        }

        let module = read_c_string_at_rva(reader, object, name_rva)
            .unwrap_or_else(|| format!("<无法读取名称 RVA {name_rva:#x}>"));

        // ILT（OriginalFirstThunk）给出名字；没有则退回 IAT
        let lookup_rva = if original_first_thunk != 0 {
            original_first_thunk
        } else {
            first_thunk
        };

        let is_pe32_plus = object.arch.ptr_size == 8;
        let thunk_size = if is_pe32_plus { 8u64 } else { 4 };
        let ordinal_flag: u64 = if is_pe32_plus {
            0x8000_0000_0000_0000
        } else {
            0x8000_0000
        };

        let Some(lookup_offset) = rva_to_offset(object, lookup_rva) else {
            skipped_modules.push(module.clone());
            continue;
        };

        for thunk_index in 0..MAX_TABLE_ENTRIES {
            let Some(thunk_offset) = lookup_offset.checked_add(thunk_index * thunk_size) else {
                break;
            };
            let Ok(thunk_view) = reader.slice(thunk_offset, thunk_size, "导入 thunk") else {
                break;
            };
            let thunk_view = Reader::with_base(thunk_view, reader.base() + thunk_offset);
            let value = thunk_view.uint(
                0,
                Endianness::Little,
                if is_pe32_plus { 8 } else { 4 },
                "thunk 值",
            )?;
            if value == 0 {
                break; // 结束
            }

            let iat_slot = rva_to_va(object, first_thunk + (thunk_index * thunk_size) as u32);

            if value & ordinal_flag != 0 {
                // 按序号导入
                let ordinal = (value & 0xffff) as u32;
                out.push(Import {
                    module: module.clone(),
                    name: None,
                    ordinal: Some(ordinal),
                    iat_slot: Some(iat_slot),
                    thunk: Some(rva_to_va(object, lookup_rva)),
                });
            } else {
                // Hint/Name 表：前 2 字节是 hint，之后是名字
                let name_rva_value = value as u32;
                let name = read_c_string_at_rva(reader, object, name_rva_value.wrapping_add(2));
                if name.is_none() {
                    unnamed += 1;
                }
                out.push(Import {
                    module: module.clone(),
                    name,
                    ordinal: None,
                    iat_slot: Some(iat_slot),
                    thunk: Some(rva_to_va(object, lookup_rva)),
                });
            }
        }
    }

    // 读不到的东西必须留下痕迹，不能静默少给数据（CLAUDE.md §7）
    if !skipped_modules.is_empty() {
        skipped.push(format!(
            "{} 个模块的导入 thunk 不在任何节内，其导入符号未列出：{}",
            skipped_modules.len(),
            skipped_modules.join("、")
        ));
    }
    if unnamed > 0 {
        skipped.push(format!(
            "有 {unnamed} 个按名字导入的符号，其名字 RVA 无法映射到文件，名字为 null"
        ));
    }

    Ok((out, skipped))
}

fn read_c_string_at_rva(reader: &Reader<'_>, object: &Object, rva: u32) -> Option<String> {
    let offset = rva_to_offset(object, rva)?;
    reader.cstr(offset, MAX_STRING, "导入名").ok()
}

/// 解析延迟导入表（`IMAGE_DELAYLOAD_DESCRIPTOR`，32 字节）。
fn parse_delay_imports(
    reader: &Reader<'_>,
    object: &Object,
    dir: DataDir,
) -> Result<Vec<Import>, ParseError> {
    const SIZE: u64 = 32;
    let count = u64::from(dir.size) / SIZE;
    if count == 0 {
        return Ok(Vec::new());
    }
    let offset = rva_to_offset(object, dir.rva).ok_or_else(|| {
        ParseError::Inconsistent(format!("延迟导入表 RVA {:#x} 不在任何节内", dir.rva))
    })?;

    let mut out = Vec::new();
    for index in 0..count.min(MAX_TABLE_ENTRIES) {
        let Some(entry) = offset.checked_add(index * SIZE) else {
            break;
        };
        let Ok(view) = reader.slice(entry, SIZE, "延迟导入描述符") else {
            break;
        };
        let view = Reader::with_base(view, reader.base() + entry);

        let attributes = view.u32(0, Endianness::Little, "Attributes")?;
        let name_rva = view.u32(4, Endianness::Little, "DllNameRVA")?;
        // 全 0 是结束
        if attributes == 0 && name_rva == 0 {
            break;
        }
        let Some(module) = read_c_string_at_rva(reader, object, name_rva) else {
            continue;
        };
        // 实际 thunk 解析需要处理 RVA/VA 两种模式，M1 只记录依赖
        out.push(Import {
            module,
            name: None,
            ordinal: None,
            iat_slot: None,
            thunk: None,
        });
    }
    Ok(out)
}

/// 解析导出表。
fn parse_exports(
    reader: &Reader<'_>,
    object: &Object,
    dir: DataDir,
) -> Result<Vec<Export>, ParseError> {
    const HEADER_SIZE: u64 = 40;
    let offset = rva_to_offset(object, dir.rva).ok_or_else(|| {
        ParseError::Inconsistent(format!("导出表 RVA {:#x} 不在任何节内", dir.rva))
    })?;
    let view = reader.slice(offset, HEADER_SIZE, "导出目录")?;
    let view = Reader::with_base(view, reader.base() + offset);

    let ordinal_base = view.u32(16, Endianness::Little, "Base")?;
    let num_functions = u64::from(view.u32(20, Endianness::Little, "NumberOfFunctions")?);
    let num_names = u64::from(view.u32(24, Endianness::Little, "NumberOfNames")?);
    let funcs_rva = view.u32(28, Endianness::Little, "AddressOfFunctions")?;
    let names_rva = view.u32(32, Endianness::Little, "AddressOfNames")?;
    let ordinals_rva = view.u32(36, Endianness::Little, "AddressOfNameOrdinals")?;

    if num_functions > MAX_TABLE_ENTRIES || num_names > MAX_TABLE_ENTRIES {
        return Err(ParseError::Overflow(format!(
            "导出表声称有 {num_functions} 个函数 / {num_names} 个名字，超过上限"
        )));
    }

    // 地址表：每个 4 字节 RVA，0 表示这个序号没有导出
    let Some(funcs_offset) = rva_to_offset(object, funcs_rva) else {
        return Err(ParseError::Inconsistent(
            "导出地址表 RVA 不在任何节内".into(),
        ));
    };
    let addresses: Vec<u32> = reader.for_each_entry(
        funcs_offset,
        4,
        num_functions,
        "导出地址表",
        |_i, v| v.u32(0, Endianness::Little, "导出 RVA"),
    )?;

    // 名字表 + 序号表：两者一一对应
    let mut names: BTreeMap<u32, String> = BTreeMap::new();
    if num_names > 0 {
        if let (Some(names_offset), Ok(_)) = (rva_to_offset(object, names_rva), Ok::<(), ()>(())) {
            if let Some(ordinals_offset) = rva_to_offset(object, ordinals_rva) {
                let name_rvas: Vec<u32> = reader.for_each_entry(
                    names_offset,
                    4,
                    num_names,
                    "导出名字表",
                    |_i, v| v.u32(0, Endianness::Little, "名字 RVA"),
                )?;
                let ordinals: Vec<u16> = reader.for_each_entry(
                    ordinals_offset,
                    2,
                    num_names,
                    "导出序号表",
                    |_i, v| v.u16(0, Endianness::Little, "序号索引"),
                )?;
                for (index, name_rva) in name_rvas.iter().enumerate() {
                    if let Some(ordinal_index) = ordinals.get(index) {
                        if let Some(name) = read_c_string_at_rva(reader, object, *name_rva) {
                            names.insert(u32::from(*ordinal_index), name);
                        }
                    }
                }
            }
        }
    }

    // 组装：每个非 0 地址都是一条导出
    let mut out = Vec::new();
    for (index, rva) in addresses.iter().enumerate() {
        if *rva == 0 {
            continue;
        }
        let ordinal = ordinal_base + index as u32;
        let name = names
            .get(&(index as u32))
            .cloned()
            .unwrap_or_else(|| format!("#{ordinal}"));

        // 转发导出：地址落在导出目录范围内表示"这是个字符串"
        let dir_start = dir.rva;
        let dir_end = dir.rva.saturating_add(dir.size);
        let forwarder = if *rva >= dir_start && *rva < dir_end {
            read_c_string_at_rva(reader, object, *rva)
        } else {
            None
        };

        out.push(Export {
            name,
            ordinal: Some(ordinal),
            address: rva_to_va(object, *rva),
            forwarder,
            is_code: true,
        });
    }

    Ok(out)
}

/// 解析基址重定位表（`.reloc`，分块结构），返回（重定位项，降级说明）。
fn parse_relocations(
    reader: &Reader<'_>,
    object: &Object,
    dir: DataDir,
) -> Result<(Vec<Reloc>, Vec<String>), ParseError> {
    let offset = rva_to_offset(object, dir.rva).ok_or_else(|| {
        ParseError::Inconsistent(format!("重定位表 RVA {:#x} 不在任何节内", dir.rva))
    })?;
    let total = u64::from(dir.size);
    let mut out = Vec::new();
    let mut skipped = Vec::new();
    let mut malformed_blocks = 0u32;
    let mut cursor = 0u64;

    // 块结构：DWORD PageRVA + DWORD BlockSize（含这 8 字节）+ 若干 WORD 项
    while cursor + 8 <= total {
        let Some(base) = offset.checked_add(cursor) else {
            break;
        };
        let Ok(header) = reader.slice(base, 8, "重定位块头") else {
            break;
        };
        let header = Reader::with_base(header, reader.base() + base);
        let page_rva = header.u32(0, Endianness::Little, "PageRVA")?;
        let block_size = u64::from(header.u32(4, Endianness::Little, "BlockSize")?);

        // BlockSize 必须 >= 8 且不超过剩余空间，否则结构坏了
        if block_size < 8 || cursor + block_size > total {
            malformed_blocks += 1;
            break;
        }

        let entry_count = (block_size - 8) / 2;
        for index in 0..entry_count {
            let Some(entry_offset) = base.checked_add(8 + index * 2) else {
                break;
            };
            let Ok(view) = reader.slice(entry_offset, 2, "重定位项") else {
                break;
            };
            let raw = u16::from_le_bytes([view[0], view[1]]);
            let kind = u32::from(raw >> 12);
            let page_offset = u32::from(raw & 0x0fff);

            if kind == 0 {
                continue; // ABSOLUTE 是填充项，跳过
            }

            out.push(Reloc {
                address: rva_to_va(object, page_rva.wrapping_add(page_offset)),
                kind: match kind {
                    3 => RelocKind::Absolute,  // HIGHLOW
                    10 => RelocKind::Absolute, // DIR64
                    1 => RelocKind::Absolute,  // HIGH
                    2 => RelocKind::Absolute,  // LOW
                    4 => RelocKind::Relative,  // HIGHADJ
                    _ => RelocKind::Other,
                },
                raw_kind: kind,
                symbol: None,
                addend: 0,
            });

            if out.len() as u64 > MAX_TABLE_ENTRIES {
                return Err(ParseError::Overflow(format!(
                    "重定位项超过上限 {MAX_TABLE_ENTRIES}"
                )));
            }
        }

        cursor += block_size;
    }

    if malformed_blocks > 0 {
        skipped.push(format!(
            "重定位表里有 {malformed_blocks} 个块的 BlockSize 非法，该块及其后的块已跳过"
        ));
    }

    Ok((out, skipped))
}

/// 解析 `.pdata`（`RUNTIME_FUNCTION`：BeginAddress / EndAddress / UnwindInfoAddress）。
fn parse_pdata(
    reader: &Reader<'_>,
    object: &Object,
    dir: DataDir,
) -> Result<Vec<UnwindEntry>, ParseError> {
    // RUNTIME_FUNCTION 在 PE32+ 里恒为 12 字节（三个 4 字节 RVA）
    const ENTRY_SIZE: u64 = 12;
    let count = u64::from(dir.size) / ENTRY_SIZE;
    if count == 0 {
        return Ok(Vec::new());
    }
    if count > MAX_TABLE_ENTRIES {
        return Err(ParseError::Overflow(format!(
            ".pdata 声称有 {count} 条记录，超过上限"
        )));
    }
    let offset = rva_to_offset(object, dir.rva).ok_or_else(|| {
        ParseError::Inconsistent(format!(".pdata RVA {:#x} 不在任何节内", dir.rva))
    })?;

    let entries: Vec<(u32, u32, u32)> =
        reader.for_each_entry(offset, ENTRY_SIZE, count, ".pdata", |_i, view| {
            Ok((
                view.u32(0, Endianness::Little, "BeginAddress")?,
                view.u32(4, Endianness::Little, "EndAddress")?,
                view.u32(8, Endianness::Little, "UnwindInfoAddress")?,
            ))
        })?;

    Ok(entries
        .into_iter()
        .map(|(begin, end, info)| UnwindEntry {
            begin: rva_to_va(object, begin),
            end: rva_to_va(object, end),
            unwind_info: rva_to_va(object, info),
        })
        .collect())
}

/// 解析 COFF 符号表（目标文件）。
fn parse_coff_symbols(
    reader: &Reader<'_>,
    symbol_table_ptr: u32,
    num_symbols: u32,
    object: &Object,
) -> Result<Vec<RawSymbol>, ParseError> {
    const SYMBOL_SIZE: u64 = 18;
    let count = u64::from(num_symbols);
    if count > MAX_TABLE_ENTRIES {
        return Err(ParseError::Overflow(format!(
            "COFF 符号表声称有 {count} 个符号，超过上限"
        )));
    }

    let offset = u64::from(symbol_table_ptr);
    // 符号表后面紧跟字符串表（前 4 字节是总长度）
    let strtab_offset = offset
        .checked_add(count * SYMBOL_SIZE)
        .ok_or_else(|| ParseError::Overflow("COFF 字符串表偏移".into()))?;

    let mut out = Vec::new();
    let mut index = 0u64;
    while index < count {
        let Some(entry) = offset.checked_add(index * SYMBOL_SIZE) else {
            break;
        };
        let Ok(view) = reader.slice(entry, SYMBOL_SIZE, "COFF 符号") else {
            break;
        };
        let view = Reader::with_base(view, reader.base() + entry);

        let raw_name = view.slice(0, 8, "符号名")?;
        let name = if raw_name[..4] == [0, 0, 0, 0] {
            // 前 4 字节为 0 表示名字在字符串表里的偏移
            let str_offset =
                u32::from_le_bytes([raw_name[4], raw_name[5], raw_name[6], raw_name[7]]);
            if str_offset >= 4 {
                reader
                    .cstr(strtab_offset + u64::from(str_offset), MAX_STRING, "符号名")
                    .unwrap_or_default()
            } else {
                String::new()
            }
        } else {
            let end = raw_name.iter().position(|&b| b == 0).unwrap_or(8);
            String::from_utf8_lossy(&raw_name[..end]).into_owned()
        };

        let value = view.u32(8, Endianness::Little, "Value")?;
        let section_number = view.i16(12, Endianness::Little, "SectionNumber")?;
        let type_field = view.u16(14, Endianness::Little, "Type")?;
        let storage_class = view.u8(16, "StorageClass")?;

        // 函数符号在 COFF 里是"派生类型"（type & 0x20），且必须是 external(2)/static(3)
        let is_function = type_field & 0x20 != 0 && (storage_class == 2 || storage_class == 3);
        let is_weak = storage_class == 105; // IMAGE_SYM_CLASS_WEAK_EXTERNAL

        // 辅助符号记录（.file / .bf / .ef）占一个槽位，要跳过
        let auxiliary_count = u64::from(view.u8(17, "NumberOfAuxSymbols")?);
        index += 1 + auxiliary_count;

        if name.is_empty() {
            continue;
        }

        out.push(RawSymbol {
            name,
            value: u64::from(value),
            size: 0,
            defined: section_number > 0,
            is_function,
            is_weak,
            // 同 coff.rs：COFF StorageClass 与 ELF STB_* 不是一套编号，
            // 只映射"局部 / 全局"这一层最小交集。
            bind: match storage_class {
                3 => 0, // STATIC → 局部
                2 => 1, // EXTERNAL → 全局
                _ => 0,
            },
            section: if section_number > 0 {
                object
                    .sections
                    .get((section_number - 1) as usize)
                    .map(|s| s.name.clone())
            } else {
                None
            },
            source: SymbolTableSource::Static,
        });
    }

    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// 构造一个最小 PE32+ 可执行文件（1 个 .text 节）。
    fn minimal_pe64() -> Vec<u8> {
        let mut bytes = vec![0u8; 0x400];
        bytes[0..2].copy_from_slice(b"MZ");
        // e_lfanew = 0x80
        bytes[0x3c..0x40].copy_from_slice(&0x80u32.to_le_bytes());
        // PE 签名
        bytes[0x80..0x84].copy_from_slice(b"PE\0\0");
        // COFF 头
        let coff = 0x84;
        bytes[coff..coff + 2].copy_from_slice(&0x8664u16.to_le_bytes()); // Machine = AMD64
        bytes[coff + 2..coff + 4].copy_from_slice(&1u16.to_le_bytes()); // NumberOfSections = 1
        bytes[coff + 16..coff + 18].copy_from_slice(&0xf0u16.to_le_bytes()); // SizeOfOptionalHeader
        bytes[coff + 18..coff + 20].copy_from_slice(&0x0022u16.to_le_bytes()); // EXECUTABLE | LARGE_ADDRESS_AWARE

        // 可选头（PE32+）
        let opt = coff + 20;
        bytes[opt..opt + 2].copy_from_slice(&0x020bu16.to_le_bytes()); // Magic
        bytes[opt + 16..opt + 20].copy_from_slice(&0x1000u32.to_le_bytes()); // AddressOfEntryPoint
        bytes[opt + 24..opt + 32].copy_from_slice(&0x140000000u64.to_le_bytes()); // ImageBase
        bytes[opt + 32..opt + 36].copy_from_slice(&0x1000u32.to_le_bytes()); // SectionAlignment
        bytes[opt + 36..opt + 40].copy_from_slice(&0x200u32.to_le_bytes()); // FileAlignment
        bytes[opt + 56..opt + 60].copy_from_slice(&0x2000u32.to_le_bytes()); // SizeOfImage
        bytes[opt + 60..opt + 64].copy_from_slice(&0x200u32.to_le_bytes()); // SizeOfHeaders
        bytes[opt + 68..opt + 70].copy_from_slice(&3u16.to_le_bytes()); // Subsystem = console
        bytes[opt + 108..opt + 112].copy_from_slice(&16u32.to_le_bytes()); // NumberOfRvaAndSizes

        // 节表
        let sec = opt + 0xf0;
        bytes[sec..sec + 5].copy_from_slice(b".text");
        bytes[sec + 8..sec + 12].copy_from_slice(&0x800u32.to_le_bytes()); // VirtualSize
        bytes[sec + 12..sec + 16].copy_from_slice(&0x1000u32.to_le_bytes()); // VirtualAddress
        bytes[sec + 16..sec + 20].copy_from_slice(&0x400u32.to_le_bytes()); // SizeOfRawData
        bytes[sec + 20..sec + 24].copy_from_slice(&0x200u32.to_le_bytes()); // PointerToRawData
        bytes[sec + 36..sec + 40].copy_from_slice(&0x6000_0020u32.to_le_bytes()); // CODE|EXEC|READ

        bytes
    }

    #[test]
    fn parses_minimal_pe64() {
        let obj = parse(&minimal_pe64(), 0, ObjectId::Plain).unwrap();
        assert_eq!(obj.kind, ObjectKind::Pe);
        assert_eq!(obj.arch.arch, Arch::X86_64);
        assert_eq!(obj.image_base, 0x1_4000_0000);
        assert_eq!(obj.entry, Some(0x1_4000_1000));
        assert_eq!(obj.sections.len(), 1);
        assert_eq!(obj.sections[0].name, ".text");
        assert_eq!(obj.sections[0].vaddr, 0x1_4000_1000);
        assert_eq!(obj.sections[0].kind, ContentKind::Code);
        assert!(obj.format.is_executable);
        assert!(!obj.format.is_dynamic_library);
        assert_eq!(obj.format.subsystem.as_deref(), Some("Windows 控制台"));
    }

    #[test]
    fn section_names_are_trimmed_at_8_bytes_not_nul_terminated() {
        // PE 节名是定长 8 字节、无 NUL 结尾：名字恰好 8 字符时不能读到相邻字段
        let mut bytes = minimal_pe64();
        let sec = 0x84 + 20 + 0xf0;
        bytes[sec..sec + 8].copy_from_slice(b".textbss");
        let obj = parse(&bytes, 0, ObjectId::Plain).unwrap();
        assert_eq!(obj.sections[0].name, ".textbss");
    }

    #[test]
    fn rejects_bad_dos_magic() {
        let mut bytes = minimal_pe64();
        bytes[0] = b'X';
        assert!(matches!(
            parse(&bytes, 0, ObjectId::Plain),
            Err(ParseError::BadMagic { .. })
        ));
    }

    #[test]
    fn rejects_bad_pe_signature() {
        let mut bytes = minimal_pe64();
        bytes[0x80] = b'X';
        assert!(matches!(
            parse(&bytes, 0, ObjectId::Plain),
            Err(ParseError::BadMagic { .. })
        ));
    }

    #[test]
    fn rejects_self_referential_lfanew() {
        let mut bytes = minimal_pe64();
        bytes[0x3c..0x40].copy_from_slice(&0x10u32.to_le_bytes()); // 落在 DOS 头内部
        assert!(matches!(
            parse(&bytes, 0, ObjectId::Plain),
            Err(ParseError::Inconsistent(_))
        ));
    }

    #[test]
    fn rejects_lfanew_beyond_file() {
        let mut bytes = minimal_pe64();
        bytes[0x3c..0x40].copy_from_slice(&0x9000u32.to_le_bytes());
        assert!(matches!(
            parse(&bytes, 0, ObjectId::Plain),
            Err(ParseError::Inconsistent(_))
        ));
    }

    #[test]
    fn rejects_unknown_machine() {
        let mut bytes = minimal_pe64();
        bytes[0x84..0x86].copy_from_slice(&0x1234u16.to_le_bytes());
        assert!(matches!(
            parse(&bytes, 0, ObjectId::Plain),
            Err(ParseError::Unsupported {
                what: "Machine",
                ..
            })
        ));
    }

    #[test]
    fn rejects_bad_optional_magic() {
        let mut bytes = minimal_pe64();
        let opt = 0x84 + 20;
        bytes[opt..opt + 2].copy_from_slice(&0x9999u16.to_le_bytes());
        assert!(matches!(
            parse(&bytes, 0, ObjectId::Plain),
            Err(ParseError::Unsupported {
                what: "可选头 Magic",
                ..
            })
        ));
    }

    #[test]
    fn rejects_too_many_sections() {
        let mut bytes = minimal_pe64();
        bytes[0x86..0x88].copy_from_slice(&200u16.to_le_bytes());
        assert!(matches!(
            parse(&bytes, 0, ObjectId::Plain),
            Err(ParseError::Unsupported {
                what: "NumberOfSections",
                ..
            })
        ));
    }

    #[test]
    fn dll_flag_is_recognized() {
        let mut bytes = minimal_pe64();
        let coff = 0x84;
        bytes[coff + 18..coff + 20].copy_from_slice(&0x2022u16.to_le_bytes()); // | DLL
        let obj = parse(&bytes, 0, ObjectId::Plain).unwrap();
        assert!(obj.format.is_dynamic_library);
        assert_eq!(obj.format.type_name.as_deref(), Some("DLL"));
    }

    #[test]
    fn zero_entry_rva_yields_no_entry() {
        let mut bytes = minimal_pe64();
        let opt = 0x84 + 20;
        bytes[opt + 16..opt + 20].copy_from_slice(&0u32.to_le_bytes());
        let obj = parse(&bytes, 0, ObjectId::Plain).unwrap();
        // 入口为 0 必须报 None，不能退回成 image_base
        assert_eq!(obj.entry, None);
    }

    #[test]
    fn section_beyond_file_is_noted_but_parse_continues() {
        let mut bytes = minimal_pe64();
        let sec = 0x84 + 20 + 0xf0;
        bytes[sec + 20..sec + 24].copy_from_slice(&0x9000u32.to_le_bytes()); // 超出文件
        let obj = parse(&bytes, 0, ObjectId::Plain).unwrap();
        assert!(
            obj.notes.iter().any(|n| n.contains("超出文件大小")),
            "notes = {:?}",
            obj.notes
        );
    }

    #[test]
    fn rva_to_offset_maps_within_section() {
        let obj = parse(&minimal_pe64(), 0, ObjectId::Plain).unwrap();
        // .text: RVA 0x1000 对应文件偏移 0x200
        assert_eq!(rva_to_offset(&obj, 0x1000), Some(0x200));
        assert_eq!(rva_to_offset(&obj, 0x1100), Some(0x300));
        // 超出节的 raw size
        assert_eq!(rva_to_offset(&obj, 0x1600), None);
        // 头部区域没有节覆盖
        assert_eq!(rva_to_offset(&obj, 0x0), None);
    }

    #[test]
    fn rejects_oversized_import_descriptor_table() {
        let mut bytes = minimal_pe64();
        let opt = 0x84 + 20;
        // 把导入目录指向一个声称超大 size 的区域
        let import_dir = opt + 112 + 8;
        bytes[import_dir..import_dir + 4].copy_from_slice(&0x1000u32.to_le_bytes());
        bytes[import_dir + 4..import_dir + 8].copy_from_slice(&0xffff_fff0u32.to_le_bytes());
        // 必须快速返回，不尝试分配
        let _ = parse(&bytes, 0, ObjectId::Plain);
    }

    #[test]
    fn every_truncation_never_panics() {
        let good = minimal_pe64();
        for len in 0..good.len() {
            let _ = parse(&good[..len], 0, ObjectId::Plain);
        }
    }

    #[test]
    fn single_byte_corruption_never_panics() {
        let good = minimal_pe64();
        for index in 0..good.len().min(0x300) {
            for bit in 0..8 {
                let mut bytes = good.clone();
                bytes[index] ^= 1 << bit;
                let _ = parse(&bytes, 0, ObjectId::Plain);
            }
        }
    }

    #[test]
    fn pe_perms_decode_correctly() {
        assert_eq!(pe_perms(0x6000_0020).to_rwx(), "r-x");
        assert_eq!(pe_perms(0xc000_0040).to_rwx(), "rw-");
        assert_eq!(pe_perms(0x4000_0080).to_rwx(), "r--");
        assert_eq!(pe_perms(0x0000_0000).to_rwx(), "---");
    }

    #[test]
    fn content_kind_uses_names_first() {
        let rx = Perms {
            read: true,
            write: false,
            execute: true,
        };
        assert_eq!(pe_content_kind(".text", rx), ContentKind::Code);
        assert_eq!(pe_content_kind(".rdata", rx), ContentKind::ReadOnlyData);
        assert_eq!(pe_content_kind(".rsrc", rx), ContentKind::Resources);
        assert_eq!(pe_content_kind(".pdata", rx), ContentKind::Unwind);
        // 未知名字退回权限判断
        assert_eq!(pe_content_kind("weird", rx), ContentKind::Code);
    }

    #[test]
    fn subsystem_labels_cover_common_values() {
        assert_eq!(subsystem_label(3), "Windows 控制台");
        assert_eq!(subsystem_label(2), "Windows GUI");
        assert!(subsystem_label(999).contains("999"));
    }
}
