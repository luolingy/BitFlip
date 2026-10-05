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
    ContentKind, Export, FileRange, FormatInfo, Import, Object, ObjectId, PeUnwindInfo, PeUnwindOp,
    Perms, RawSymbol, Reloc, RelocKind, Section, Segment, SymbolTableSource, UnwindEntry,
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

        // .NET 检测：解析 IMAGE_COR20_HEADER，取出可核实的识别信息。
        //
        // PLAN §1.4 对这一项的要求是"仅识别（M3）：识别并提示，不做 CIL 反编译"，
        // 所以这里只读头、不解元数据表、不反编译。但也不该只报一句"有 CLI 头" ——
        // 头里的 flags / 入口 RVA / 运行时版本字符串都是**能核实**的事实，
        // 报出来才知道到底是 .NET 可执行体还是纯 IL 的 DLL。
        if let Some(dir) = opt
            .dirs
            .get(dir::COM_DESCRIPTOR)
            .copied()
            .filter(|d| !d.is_empty())
        {
            for note in describe_cli_header(&reader, &object, dir) {
                object.note(note);
            }
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

        // 转发导出**不是代码**：`address` 指向的是导出目录里的一个
        // 字符串（形如 `NTDLL.RtlAllocateHeap`），是一个"去哪找"的
        // 指路牌。把它当代码会让上层在字符串字节上建函数。
        //
        // 非转发导出也不一定就是代码（数据也可以被导出），但 PE 的
        // 导出表**不记录类型** —— 拿不到就说拿不到：这里只否定
        // **确定不是代码**的转发项，其余保留 `true` 并在上层用
        // "能否解码 / 是否可达"复核。
        let is_code = forwarder.is_none();

        out.push(Export {
            name,
            ordinal: Some(ordinal),
            address: rva_to_va(object, *rva),
            forwarder,
            is_code,
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
        .map(|(begin, end, info)| {
            let begin = rva_to_va(object, begin);
            let end = rva_to_va(object, end);
            let info_va = rva_to_va(object, info);
            UnwindEntry {
                begin,
                end,
                unwind_info: info_va,
                // 解码 UNWIND_INFO：帧大小与保存寄存器的权威来源。
                // 解不出来就如实留 None —— 不拿默认值冒充（CLAUDE.md §7）。
                decoded: parse_unwind_info(reader, object, info_va),
            }
        })
        .collect())
}

/// 解码 x64 的 `UNWIND_INFO`（`.pdata` 条目指向的展开数据）。
///
/// # 结构（Microsoft PE/COFF 规范）
///
/// ```text
/// byte 0: Version(3) | Flags(3) | 保留(2)      // x64 现行版本 = 1
/// byte 1: SizeOfProlog
/// byte 2: CountOfCodes
/// byte 3: FrameRegister(4) | FrameOffset(4)   // FrameOffset 缩放 16
/// 之后: CountOfCodes × UNWIND_CODE（每槽 2 字节），4 字节对齐
/// ```
///
/// `UNWIND_CODE` 每槽 2 字节：`CodeOffset`(前导偏移) + `UnwindOp(4)` + `OpInfo(4)`。
/// 部分操作（ALLOC_LARGE / *_FAR / SAVE_NONVOL）**额外消耗后续槽位**，
/// 而 `CountOfCodes` 把附加槽也数进去了 —— 遍历时必须跟着跳过，
/// 否则会把附加数据当成独立操作码。
fn parse_unwind_info(
    reader: &Reader<'_>,
    object: &Object,
    unwind_info_va: u64,
) -> Option<PeUnwindInfo> {
    let mut notes = Vec::new();

    // VA → 文件偏移。定位不到就返回 None（调用方如实显示"无展开信息"）。
    let rva = unwind_info_va.checked_sub(object.image_base)? as u32;
    let offset = rva_to_offset(object, rva)?;

    let header = reader.slice(offset, 4, "UNWIND_INFO 头").ok()?;
    let version = header[0] & 0x07;
    let flags = (header[0] >> 3) & 0x07;
    let prologue_size = header[1];
    let count_of_codes = u64::from(header[2]);
    let frame_reg_raw = header[3] & 0x0F;
    let frame_offset_scaled = (header[3] >> 4) & 0x0F;

    // 版本 1 = x64（PE/COFF 规范："Version: currently 1"）。
    // 其他版本（如 ARM64 用的 2）操作码语义不同，只记录头字段。
    //
    // 这里最初写成了"版本 0 才是 x64"，在真实 MinGW PE 上立刻暴露：
    // 127 条展开信息**全部**报版本 1，于是全部退化成"只记录头字段"，
    // 一条操作码都没解出来。规范里 0 是历史值，现行 x64 就是 1。
    if version != 1 {
        notes.push(format!(
            "展开信息版本 {version} 不是 x64 现行版本（1），仅记录头字段，不解码展开操作"
        ));
        return Some(PeUnwindInfo {
            version,
            flags,
            prologue_size,
            frame_register: None,
            frame_offset: 0,
            ops: Vec::new(),
            notes,
        });
    }

    let frame_register = (frame_reg_raw != 0)
        .then(|| x64_reg_name(frame_reg_raw))
        .flatten()
        .map(str::to_string);
    let frame_offset = u32::from(frame_offset_scaled) * 16;

    // ── 遍历 UNWIND_CODE 槽位 ──
    // 第一遍：解析操作序列并累计"栈分配"（帧大小）。第二遍用帧大小
    // 给 push 槽位定位（push 的槽位要等总帧大小定了才知道相对最终 RSP
    // 的位置）。
    let codes_base = offset + 4;
    struct RawOp {
        opcode: u8,
        info: u8,
        prolog_off: u8,
        /// 附加数据（如 ALLOC_LARGE 的大小、SAVE 的偏移）。
        extra: Option<u32>,
    }

    let mut raw: Vec<RawOp> = Vec::new();
    let mut slot: usize = 0;
    let mut truncated = false;
    while slot < count_of_codes as usize {
        let base = codes_base + (slot as u64) * 2;
        let (Ok(prolog_off), Ok(b1)) = (
            reader.u8(base, "UNWIND_CODE CodeOffset"),
            reader.u8(base + 1, "UNWIND_CODE 操作"),
        ) else {
            notes.push(format!("展开码在槽位 {slot} 越界，截断"));
            truncated = true;
            break;
        };
        let opcode = b1 & 0x0F;
        let info = (b1 >> 4) & 0x0F;

        // 该操作消耗的槽位数（含自身）。CountOfCodes 把附加槽也数进去了，
        // 遍历时必须跟着跳过，否则会把附加数据当成独立操作码。
        // 默认 1（push/setfpreg/alloc_small/machineframe 等不占附加槽）。
        let mut slots = 1usize;
        let mut extra = None;
        // 附加数据读取：从后续槽位读（2 字节 / 4 字节）。
        let next_slot = base + 2;
        match opcode {
            // ALLOC_LARGE：OpInfo=0 → 下 1 槽 4 字节大小；OpInfo=1 → 下 2 槽 8 字节
            1 => {
                slots = if info == 1 { 3 } else { 2 };
                let size = if info == 1 {
                    reader.u32(next_slot, Endianness::Little, "ALLOC_LARGE 大小")
                } else {
                    reader
                        .u16(next_slot, Endianness::Little, "ALLOC_LARGE 大小")
                        .map(u32::from)
                };
                match size {
                    Ok(s) => extra = Some(s),
                    Err(_) => {
                        notes.push("ALLOC_LARGE 的大小越界，该项按 0 处理".to_string());
                        extra = Some(0);
                    }
                }
            }
            // SAVE_NONVOL：下 1 槽 = 缩放偏移（×8）
            4 => {
                slots = 2;
                extra = reader
                    .u16(next_slot, Endianness::Little, "SAVE_NONVOL 偏移")
                    .ok()
                    .map(u32::from);
            }
            // SAVE_NONVOL_FAR：下 2 槽 = 32 位偏移
            5 => {
                slots = 3;
                extra = reader
                    .u32(next_slot, Endianness::Little, "SAVE_NONVOL_FAR 偏移")
                    .ok();
            }
            // SAVE_XMM128：下 1 槽 = 缩放偏移（×16）
            6 => {
                slots = 2;
                extra = reader
                    .u16(next_slot, Endianness::Little, "SAVE_XMM128 偏移")
                    .ok()
                    .map(u32::from);
            }
            // SAVE_XMM128_FAR：下 2 槽 = 32 位偏移
            7 => {
                slots = 3;
                extra = reader
                    .u32(next_slot, Endianness::Little, "SAVE_XMM128_FAR 偏移")
                    .ok();
            }
            _ => {}
        }

        raw.push(RawOp {
            opcode,
            info,
            prolog_off,
            extra,
        });
        slot += slots;
        if slot > count_of_codes as usize {
            notes.push("展开码消耗槽位越过 CountOfCodes，截断".to_string());
            truncated = true;
            break;
        }
    }
    if truncated && raw.is_empty() {
        // 一条都没解出来：返回带说明的骨架，而不是空着
        return Some(PeUnwindInfo {
            version,
            flags,
            prologue_size,
            frame_register,
            frame_offset,
            ops: Vec::new(),
            notes,
        });
    }

    // ── 按前导顺序重排 ──
    //
    // PE/COFF 规定展开码在数组里按**前导偏移递减**排列（最后一条前导
    // 指令排在最前）。这不是笔误，是规范：规范说 "the unwind codes are
    // ordered in the array in descending order of prolog offset"。
    //
    // 后果很实际：直接按数组顺序处理，保存寄存器列表会是反的，而且
    // **push 的栈槽位置会全部算错**（槽位依赖"这个 push 在序列中的
    // 位置"）。真实 MinGW PE 上第一版就是这样：8 个 push 解出来的
    // 顺序恰好与反汇编相反。
    //
    // 排序而不是 `reverse()`：规范保证的是递减，但排序对"顺序本来
    // 就乱"的畸形输入也成立，且结果可预测。
    raw.sort_by_key(|r| r.prolog_off);

    // 帧大小（只累计确定占栈的：push / alloc / machineframe）
    let frame_size: u64 = raw
        .iter()
        .map(|r| match r.opcode {
            0 => 8,                                // PUSH_NONVOL
            1 => u64::from(r.extra.unwrap_or(0)),  // ALLOC_LARGE
            2 => u64::from(r.info as u32 + 1) * 8, // ALLOC_SMALL
            8 => {
                // PUSH_MACHFRAME：x64 机器帧 0x28/帧
                u64::from(r.info as u32 + 1) * 0x28
            }
            _ => 0,
        })
        .sum();

    // 第二遍：按序组装操作，push 的槽位用"总帧大小 − 该点已累计"定位
    let mut ops = Vec::new();
    let mut accum: u64 = 0;
    for r in &raw {
        match r.opcode {
            0 => {
                // PUSH_NONVOL
                let reg = x64_reg_name(r.info)
                    .map(str::to_string)
                    .unwrap_or_else(|| format!("reg{}", r.info));
                // 该 push 之后累计 = accum + 8；槽位距最终 RSP = T − (accum+8)
                let after = accum + 8;
                let slot_from_top = frame_size.saturating_sub(after);
                ops.push(PeUnwindOp::PushNonVolatile { reg, slot_from_top });
                accum = after;
            }
            1 => {
                // ALLOC_LARGE
                if let Some(size) = r.extra {
                    ops.push(PeUnwindOp::Alloc { size });
                    accum += u64::from(size);
                }
            }
            2 => {
                // ALLOC_SMALL
                let size = u32::from(r.info) + 1;
                ops.push(PeUnwindOp::Alloc { size: size * 8 });
                accum += u64::from(size) * 8;
            }
            3 => {
                // SET_FPREG（FrameRegister 字段已给出）
                let reg = x64_reg_name(r.info).map(str::to_string);
                if let Some(reg) = reg {
                    ops.push(PeUnwindOp::SetFramePointer { reg });
                }
            }
            4 => {
                // SAVE_NONVOL
                let reg = x64_reg_name(r.info).map(str::to_string);
                if let (Some(reg), Some(scaled)) = (reg, r.extra) {
                    ops.push(PeUnwindOp::SaveNonVolatile {
                        reg,
                        scaled_offset: scaled,
                    });
                }
            }
            5 => {
                // SAVE_NONVOL_FAR
                let reg = x64_reg_name(r.info).map(str::to_string);
                if let (Some(reg), Some(offset)) = (reg, r.extra) {
                    ops.push(PeUnwindOp::SaveNonVolatileFar { reg, offset });
                }
            }
            6 | 7 => {
                // SAVE_XMM128[_FAR]：记录但不计入帧大小
                let reg = x64_reg_name(r.info)
                    .map(str::to_string)
                    .unwrap_or_else(|| format!("xmm{}", r.info));
                let offset = r.extra.unwrap_or(0);
                ops.push(PeUnwindOp::SaveXmm { reg, offset });
            }
            8 => {
                // PUSH_MACHFRAME
                let size = u32::from(r.info) + 1;
                ops.push(PeUnwindOp::PushMachineFrame { size: size * 0x28 });
                accum += u64::from(size) * 0x28;
            }
            other => {
                ops.push(PeUnwindOp::Unknown {
                    opcode: other,
                    info: r.info,
                    prolog_offset: r.prolog_off,
                });
                notes.push(format!(
                    "展开码 {other:#x}（info={:#x}，前导偏移 {:#x}）未识别",
                    r.info, r.prolog_off
                ));
            }
        }
    }

    if ops.iter().any(|o| matches!(o, PeUnwindOp::SaveXmm { .. })) {
        notes.push("存在 XMM 保存，其栈占用未计入帧大小（浮点寄存器宽度未做假设）".to_string());
    }

    Some(PeUnwindInfo {
        version,
        flags,
        prologue_size,
        frame_register,
        frame_offset,
        ops,
        notes,
    })
}

/// x64 展开码里寄存器编号 → 名字（0-15）。
fn x64_reg_name(n: u8) -> Option<&'static str> {
    match n {
        0 => Some("rax"),
        1 => Some("rcx"),
        2 => Some("rdx"),
        3 => Some("rbx"),
        4 => Some("rsp"),
        5 => Some("rbp"),
        6 => Some("rsi"),
        7 => Some("rdi"),
        8 => Some("r8"),
        9 => Some("r9"),
        10 => Some("r10"),
        11 => Some("r11"),
        12 => Some("r12"),
        13 => Some("r13"),
        14 => Some("r14"),
        15 => Some("r15"),
        _ => None,
    }
}

/// 解析 `IMAGE_COR20_HEADER` 并返回识别结论（notes）。
///
/// PLAN §1.4：这一项只做**识别**，不做 CIL 反编译。但"识别"不等于只报一句
/// "有 CLI 头" —— 头里有若干**能核实**的事实，报出来才能让用户判断这个文件
/// 到底是什么：
///
/// * `Flags` 的 `ILONLY` / `32BITREQUIRED` / `NATIVE_ENTRYPOINT` —— 决定它是
///   纯 IL 还是混合模式（C++/CLI），直接影响"能不能当普通 PE 反汇编"；
/// * `EntryPointToken` —— 托管入口的方法 token（0 表示没有），
///   **不是** PE 的 `AddressOfEntryPoint`。这两个很容易被混为一谈；
/// * `MetaData` 目录 —— 元数据根的 RVA/大小；
/// * `RuntimeVersion` —— 形如 `v4.0.30319` 的版本串，是 BCL 兼容性的直接依据。
///
/// `IMAGE_COR20_HEADER` 布局（72 字节，全部小端）：
/// ```text
///  0  cb                     u32   头字节数（应为 72）
///  4  MajorRuntimeVersion    u16
///  6  MinorRuntimeVersion    u16
///  8  MetaData               RVA+Size 目录（8 字节）
/// 16  Flags                  u32
/// 20  EntryPointToken        u32
/// 24  Resources              RVA+Size 目录
/// 32  StrongNameSignature    RVA+Size 目录
/// 40  CodeManagerTable       RVA+Size 目录
/// 48  VTableFixups           RVA+Size 目录
/// 56  ExportAddressTableJumps RVA+Size 目录
/// 64  ManagedNativeHeader    RVA+Size 目录
/// ```
fn describe_cli_header(reader: &Reader<'_>, object: &Object, dir: DataDir) -> Vec<String> {
    /// CLI 头的固定大小。
    const COR20_HEADER_SIZE: u64 = 72;

    let mut notes = Vec::new();

    let Some(offset) = rva_to_offset(object, dir.rva) else {
        notes.push(format!(
            "包含 CLI 头（RVA {:#x}），但该 RVA 无法映射到文件偏移：CLI 头内容不可读",
            dir.rva
        ));
        return notes;
    };

    let Ok(_probe) = reader.slice(offset, COR20_HEADER_SIZE, "CLI 头") else {
        notes.push(format!(
            "包含 CLI 头（RVA {:#x}，偏移 {offset:#x}），但文件在此处不足 {COR20_HEADER_SIZE} 字节，无法读取",
            dir.rva
        ));
        return notes;
    };

    // 用 reader 直接在绝对偏移处读：`slice` 只返回字节切片，没有读取方法。
    let read_u32 = |at: u64, what: &'static str| {
        reader
            .u32(offset + at, Endianness::Little, what)
            .unwrap_or(0)
    };
    let read_u16 = |at: u64, what: &'static str| {
        reader
            .u16(offset + at, Endianness::Little, what)
            .unwrap_or(0)
    };

    let cb = read_u32(0, "cb");
    let major = read_u16(4, "MajorRuntimeVersion");
    let minor = read_u16(6, "MinorRuntimeVersion");
    let metadata_rva = read_u32(8, "MetaData.RVA");
    let metadata_size = read_u32(12, "MetaData.Size");
    let flags = read_u32(16, "Flags");
    let entry_token = read_u32(20, "EntryPointToken");

    // Flags 位定义（ECMA-335 II.25.3.1）
    const COMIMAGE_FLAGS_ILONLY: u32 = 0x0000_0001;
    const COMIMAGE_FLAGS_32BITREQUIRED: u32 = 0x0000_0002;
    const COMIMAGE_FLAGS_32BITPREFERRED: u32 = 0x0002_0000;
    const COMIMAGE_FLAGS_NATIVE_ENTRYPOINT: u32 = 0x0000_0010;
    const COMIMAGE_FLAGS_STRONGNAMESIGNED: u32 = 0x0000_0008;

    let mut traits = Vec::new();
    if flags & COMIMAGE_FLAGS_ILONLY != 0 {
        traits.push("ILONLY");
    }
    if flags & COMIMAGE_FLAGS_NATIVE_ENTRYPOINT != 0 {
        traits.push("NATIVE_ENTRYPOINT");
    }
    if flags & COMIMAGE_FLAGS_32BITREQUIRED != 0 {
        traits.push("32BITREQUIRED");
    }
    if flags & COMIMAGE_FLAGS_32BITPREFERRED != 0 {
        traits.push("32BITPREFERRED");
    }
    if flags & COMIMAGE_FLAGS_STRONGNAMESIGNED != 0 {
        traits.push("STRONGNAMESIGNED");
    }
    let trait_text = if traits.is_empty() {
        "无标志位".to_string()
    } else {
        traits.join("|")
    };

    // 混合模式（C++/CLI）与纯 IL 的处理方式完全不同，值得单独点出来：
    // 混合模式里含真实原生代码，可以当普通 PE 反汇编；纯 IL 的 .text
    // 是 IL 字节码，按 x86/x64 反汇编只会得到一片无意义的指令。
    let il_only = flags & COMIMAGE_FLAGS_ILONLY != 0;
    let mixed = !il_only;

    notes.push(format!(
        "这是一个 .NET 托管程序集（CLI 头 RVA {:#x}，头大小 {cb} 字节，\
         运行时版本 {major}.{minor}，标志 {trait_text}）",
        dir.rva
    ));

    if mixed {
        notes.push(
            "该程序集不是纯 IL（缺 ILONLY 标志）：属于混合模式（很可能 C++/CLI），\
             其中包含真实的原生代码，可以按普通 PE 反汇编；托管部分不做 CIL 反编译"
                .to_string(),
        );
    } else {
        notes.push(
            "这是纯 IL 程序集：`.text` 段里是 IL 字节码，按 x86/x64 反汇编不会得到\
             有意义的指令。本工具只做识别，不反编译 CIL（见 docs/PLAN.md §1.4）"
                .to_string(),
        );
    }

    if entry_token != 0 {
        // 托管入口是**方法 token**（0x06xxxxxx 方法表 / 0x0Axxxxxx 方法规格），
        // 不是 PE 头的 AddressOfEntryPoint —— 两者数值相近但含义完全不同。
        let table = entry_token >> 24;
        let index = entry_token & 0x00ff_ffff;
        let table_name = match table {
            0x06 => "MethodDef",
            0x0a => "MethodSpec",
            0x01 => "TypeRef",
            0x02 => "TypeDef",
            _ => "未知表",
        };
        notes.push(format!(
            "托管入口是方法 token 0x{entry_token:08x}（{table_name} 表第 {index} 项），\
             与 PE 头的 AddressOfEntryPoint 不是同一概念"
        ));
    } else {
        notes.push("该程序集没有托管入口（EntryPointToken = 0），通常是类库".to_string());
    }

    if metadata_size == 0 || metadata_rva == 0 {
        notes.push(
            "CLI 头里的 MetaData 目录为空：元数据根不可定位，无法进一步识别程序集内容".to_string(),
        );
    } else {
        notes.push(format!(
            "元数据根位于 RVA {metadata_rva:#x}（{metadata_size} 字节）：程序集名与类型定义在那里，\
             M3 不做元数据表解析"
        ));
    }

    // 尝试读运行时版本字符串。它是 BCL 兼容性的直接依据，值得单独报。
    // 形如 "v4.0.30319" 或 "v2.0.50727"，以 NUL 结尾。
    if let Some(version) = read_runtime_version(reader, object, metadata_rva, metadata_size) {
        notes.push(format!("目标运行时版本字符串：{version}"));
    }

    notes
}

/// 从元数据根读运行时版本字符串。
///
/// 布局（`IMAGE_COR20_METADATA`，ECMA-335 II.24.2.1）：
/// ```text
///  0  Signature    u32   0x424A5342 ("BSJB")
///  4  MajorVersion u16
///  6  MinorVersion u16
///  8  Reserved     u32
/// 12  Length       u32   版本字符串字节数（**含** NUL，向上取整到 4 的倍数）
/// 16  Version      u8[Length]
/// ```
///
/// 只在签名对得上时返回；签名不对说明这不是标准的元数据根，返回 `None`
/// 让上层如实说"读不出来"，而不是猜一个版本号出来（§7）。
fn read_runtime_version(
    reader: &Reader<'_>,
    object: &Object,
    metadata_rva: u32,
    metadata_size: u32,
) -> Option<String> {
    // "BSJB" 的**小端**读数。
    //
    // 这个字面量极易写错：字节是 `42 53 4a 42`，小端读出来是 0x424a5342，
    // 而"按书写顺序"写会得到 0x4242534a（大端读数）。第一版就写错了，
    // 而且**手拼的单元测试跟着一起错**（测试里也写了同一个错常量），
    // 所以单元测试全绿 —— 直到用真实的 System.dll 才暴露出来。
    // 保留这条注释：这是"合成样本测不出编码理解错误"的活例子。
    const SIG_BSJB: u32 = u32::from_le_bytes(*b"BSJB");
    /// 版本串长度上限：真实值约 10-12 字节。给足余量但不是无限制。
    const MAX_VERSION_LEN: u32 = 1024;

    if metadata_size < 20 {
        return None;
    }
    let offset = rva_to_offset(object, metadata_rva)?;
    reader.slice(offset, 20, "元数据根").ok()?;
    let signature = reader.u32(offset, Endianness::Little, "BSJB 签名").ok()?;
    if signature != SIG_BSJB {
        return None;
    }
    let length = reader
        .u32(offset + 12, Endianness::Little, "版本串长度")
        .ok()?;
    if length == 0 || length > MAX_VERSION_LEN {
        return None;
    }
    let data = reader
        .slice(offset + 16, u64::from(length), "版本串")
        .ok()?;
    // 去掉尾部 NUL 与对齐填充
    let end = data.iter().position(|&b| b == 0).unwrap_or(data.len());
    let text = std::str::from_utf8(&data[..end]).ok()?;
    if text.is_empty() {
        return None;
    }
    Some(text.to_string())
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

    /// 构造一个**带导出表**的最小 PE32+。
    ///
    /// `forwarder` 为 `Some` 时，序号 1 的导出 RVA 指向导出目录内部的
    /// 一个字符串（转发导出的标准编码）；为 `None` 时指向 `.text` 里的
    /// 真实代码。
    fn pe64_with_export(forwarder: Option<&str>) -> Vec<u8> {
        let mut bytes = minimal_pe64();
        // 把 .text 撑大一点，容下导出目录
        let opt = 0x84 + 20;
        let sec = opt + 0xf0;

        // 导出目录放在 .text 内部偏移 0x40 → RVA 0x1040。
        // PE 导出目录固定 40 字节，各字段偏移：
        const DIR_RVA: u32 = 0x1040;
        const NAME_RVA: u32 = DIR_RVA + 0x40; // "dllname" 字符串
        const FUNCS_RVA: u32 = DIR_RVA + 0x60; // 地址表（1 项）
        const NAMES_RVA: u32 = DIR_RVA + 0x70; // 名字 RVA 表（1 项）
        const ORDS_RVA: u32 = DIR_RVA + 0x78; // 序号表（1 项，u16）
        const EXPORT_NAME_RVA: u32 = DIR_RVA + 0x80; // "exported" 字符串
        const FWD_RVA: u32 = DIR_RVA + 0x90; // 转发字符串

        let text_off = |rva: u32| -> usize { (0x200 + (rva - 0x1000)) as usize };

        // 导出目录
        let d = text_off(DIR_RVA);
        bytes[d + 12..d + 16].copy_from_slice(&NAME_RVA.to_le_bytes());
        bytes[d + 16..d + 20].copy_from_slice(&1u32.to_le_bytes()); // Base
        bytes[d + 20..d + 24].copy_from_slice(&1u32.to_le_bytes()); // NumberOfFunctions
        bytes[d + 24..d + 28].copy_from_slice(&1u32.to_le_bytes()); // NumberOfNames
        bytes[d + 28..d + 32].copy_from_slice(&FUNCS_RVA.to_le_bytes());
        bytes[d + 32..d + 36].copy_from_slice(&NAMES_RVA.to_le_bytes());
        bytes[d + 36..d + 40].copy_from_slice(&ORDS_RVA.to_le_bytes());

        // DLL 名
        let mut off = text_off(NAME_RVA);
        bytes[off..off + 8].copy_from_slice(b"test.dll");
        off = text_off(EXPORT_NAME_RVA);
        bytes[off..off + 9].copy_from_slice(b"exported\0");

        // 地址表：转发时指向目录内的字符串，否则指向 .text 里的代码
        let func_rva: u32 = match forwarder {
            Some(_) => FWD_RVA,
            None => 0x1000,
        };
        off = text_off(FUNCS_RVA);
        bytes[off..off + 4].copy_from_slice(&func_rva.to_le_bytes());

        // 名字表 → "exported"
        off = text_off(NAMES_RVA);
        bytes[off..off + 4].copy_from_slice(&EXPORT_NAME_RVA.to_le_bytes());
        // 序号表 → 0
        off = text_off(ORDS_RVA);
        bytes[off..off + 2].copy_from_slice(&0u16.to_le_bytes());

        if let Some(target) = forwarder {
            off = text_off(FWD_RVA);
            let s = format!("{target}\0");
            bytes[off..off + s.len()].copy_from_slice(s.as_bytes());
        }

        // 可选头里填数据目录 [0] = 导出表。
        //
        // `size` 必须**覆盖到转发字符串**（DIR_RVA + 0x90 附近）：
        // 解析器判断"这个 RVA 指向的是字符串而不是代码"的依据就是
        // "RVA 落在导出目录范围内"。填 40（只是目录结构本身的大小）
        // 会让转发字符串落到范围外，于是被当成普通导出。
        let opt = 0x84 + 20;
        bytes[opt + 112..opt + 116].copy_from_slice(&DIR_RVA.to_le_bytes());
        bytes[opt + 116..opt + 120].copy_from_slice(&0x100u32.to_le_bytes());

        let _ = sec;
        bytes
    }

    /// **转发导出不是代码。**
    ///
    /// 转发导出的"地址"其实指向导出目录里的一个字符串
    /// （形如 `NTDLL.RtlAllocateHeap`）。早先这里硬编码
    /// `is_code: true`，会让上层跑到字符串字节上去建函数 ——
    /// 一个凭空出现的"函数"，正是 M6 要量化的误判来源。
    #[test]
    fn forwarded_export_is_not_claimed_to_be_code() {
        let obj = parse(
            &pe64_with_export(Some("NTDLL.RtlAllocateHeap")),
            0,
            ObjectId::Plain,
        )
        .expect("解析带转发导出的 PE");
        let e = obj
            .exports
            .iter()
            .find(|e| e.name == "exported")
            .expect("应当解析出 exported 这个导出");

        assert_eq!(
            e.forwarder.as_deref(),
            Some("NTDLL.RtlAllocateHeap"),
            "转发目标字符串应当被读出来"
        );
        assert!(
            !e.is_code,
            "转发导出指向的是字符串，不是代码 —— 不能声称它是函数"
        );
    }

    /// 普通导出仍然是代码（这条守住不要修过头）。
    #[test]
    fn ordinary_export_is_still_code() {
        let obj = parse(&pe64_with_export(None), 0, ObjectId::Plain).expect("解析 PE");
        let e = obj
            .exports
            .iter()
            .find(|e| e.name == "exported")
            .expect("应当解析出 exported 这个导出");

        assert!(e.forwarder.is_none());
        assert!(
            e.is_code,
            "PE 导出表不记录类型，非转发导出默认按代码处理（上层再复核）"
        );
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

    /// 测试用：CLI 头 + 元数据根需要预留的字节数（72 + 版本串余量）。
    const COR20_TEST_SIZE: usize = 72 + 128;

    /// 构造一个带 CLI 头的 .NET 程序集。
    ///
    /// `flags` 决定是纯 IL 还是混合模式；`entry_token` 为 0 表示类库。
    /// 同时写入 `IMAGE_COR20_HEADER` 与一个可被识别的元数据根
    /// （含 `BSJB` 签名与版本串），以便验证版本串确实被读出来了。
    fn pe64_with_cli(flags: u32, entry_token: u32, runtime_version: &str) -> Vec<u8> {
        let mut bytes = minimal_pe64();
        let opt = 0x84 + 20;
        // CLI 头必须落在节声明覆盖的范围内，`rva_to_offset` 才能映射到它：
        // .text 是 RVA 0x1000 / SizeOfRawData 0x400 / PointerToRawData 0x200。
        // 这里放到 RVA 0x1200（节内偏移 0x200，文件偏移 0x400），
        // 与节表的声明保持一致 —— 否则解析器会（正确地）说"映射不到"。
        let cli_rva: u32 = 0x1200;
        let cli_off = 0x200 + (cli_rva as usize - 0x1000);
        // 头 + 元数据根需要约 140 字节，撑到 0x400+0x140 之后
        let need = cli_off + COR20_TEST_SIZE;
        if bytes.len() < need {
            bytes.resize(need, 0);
        }

        // 数据目录 14 项 = CLI
        let dir_cli = opt + 112 + 14 * 8;
        bytes[dir_cli..dir_cli + 4].copy_from_slice(&cli_rva.to_le_bytes());
        bytes[dir_cli + 4..dir_cli + 8].copy_from_slice(&72u32.to_le_bytes());

        // 元数据根紧随 CLI 头之后
        let meta_rva = cli_rva + 72;
        let meta_off = cli_off + 72;

        // ── IMAGE_COR20_HEADER ──
        bytes[cli_off..cli_off + 4].copy_from_slice(&72u32.to_le_bytes()); // cb
        bytes[cli_off + 4..cli_off + 6].copy_from_slice(&2u16.to_le_bytes()); // Major
        bytes[cli_off + 6..cli_off + 8].copy_from_slice(&5u16.to_le_bytes()); // Minor
        bytes[cli_off + 8..cli_off + 12].copy_from_slice(&meta_rva.to_le_bytes());
        bytes[cli_off + 12..cli_off + 16].copy_from_slice(&64u32.to_le_bytes()); // MetaData.Size
        bytes[cli_off + 16..cli_off + 20].copy_from_slice(&flags.to_le_bytes());
        bytes[cli_off + 20..cli_off + 24].copy_from_slice(&entry_token.to_le_bytes());

        // ── 元数据根 ──
        // 用 u32::from_le_bytes 从字节推常量，而不是手写十六进制字面量：
        // 手写时极易把 0x424a5342 写成 0x4242534a（大端读数），
        // 而且测试与实现会一起错、互相"验证"通过。
        bytes[meta_off..meta_off + 4].copy_from_slice(b"BSJB");
        bytes[meta_off + 4..meta_off + 6].copy_from_slice(&1u16.to_le_bytes());
        bytes[meta_off + 6..meta_off + 8].copy_from_slice(&1u16.to_le_bytes());
        // 版本串长度：含 NUL，向上取整到 4 的倍数
        let raw_len = runtime_version.len() + 1;
        let padded = raw_len.div_ceil(4) * 4;
        bytes[meta_off + 12..meta_off + 16].copy_from_slice(&(padded as u32).to_le_bytes());
        bytes[meta_off + 16..meta_off + 16 + runtime_version.len()]
            .copy_from_slice(runtime_version.as_bytes());

        bytes
    }

    /// 纯 IL 程序集：识别出 .NET，并指出 .text 是 IL 字节码、不可按 x64 反汇编。
    #[test]
    fn recognizes_pure_il_dotnet_assembly() {
        const ILONLY: u32 = 0x0000_0001;
        let bytes = pe64_with_cli(ILONLY, 0x0600_0002, "v4.0.30319");
        let obj = parse(&bytes, 0, ObjectId::Plain).unwrap();

        let joined = obj.notes.join("\n");
        assert!(
            joined.contains(".NET 托管程序集"),
            "应识别为 .NET 程序集：{:?}",
            obj.notes
        );
        assert!(
            joined.contains("ILONLY"),
            "应报出 ILONLY 标志：{:?}",
            obj.notes
        );
        assert!(
            joined.contains("纯 IL"),
            "纯 IL 程序集必须提示 .text 是 IL 字节码、不可按 x64 反汇编：{:?}",
            obj.notes
        );
        // 入口 token 要按"方法 token"解读，而不是冒充 AddressOfEntryPoint
        assert!(
            joined.contains("0x06000002") && joined.contains("MethodDef"),
            "托管入口应报为方法 token：{:?}",
            obj.notes
        );
        assert!(
            joined.contains("v4.0.30319"),
            "应读出运行时版本串：{:?}",
            obj.notes
        );
    }

    /// 混合模式（C++/CLI）：必须提示含真实原生代码，可以正常反汇编。
    ///
    /// 这条与纯 IL 的结论**相反**，所以不能只判断"有没有 CLI 头"就下结论 ——
    /// 两种程序的 .text 性质完全不同。
    #[test]
    fn recognizes_mixed_mode_assembly_differently() {
        // 没有 ILONLY，但有 NATIVE_ENTRYPOINT
        const NATIVE_ENTRYPOINT: u32 = 0x0000_0010;
        let bytes = pe64_with_cli(NATIVE_ENTRYPOINT, 0x0600_0001, "v4.0.30319");
        let obj = parse(&bytes, 0, ObjectId::Plain).unwrap();

        let joined = obj.notes.join("\n");
        assert!(
            joined.contains("混合模式"),
            "应识别为混合模式：{:?}",
            obj.notes
        );
        assert!(
            joined.contains("可以按普通 PE 反汇编"),
            "混合模式含原生代码，必须说明可以反汇编：{:?}",
            obj.notes
        );
        assert!(
            !joined.contains("这是纯 IL 程序集"),
            "混合模式不能被说成纯 IL：{:?}",
            obj.notes
        );
    }

    /// 没有托管入口的是类库，不是可执行体 —— 必须说清楚。
    #[test]
    fn library_without_entry_point_says_so() {
        const ILONLY: u32 = 0x0000_0001;
        let bytes = pe64_with_cli(ILONLY, 0, "v4.0.30319");
        let obj = parse(&bytes, 0, ObjectId::Plain).unwrap();
        let joined = obj.notes.join("\n");
        assert!(
            joined.contains("没有托管入口") && joined.contains("类库"),
            "EntryPointToken=0 应报为类库：{:?}",
            obj.notes
        );
    }

    /// 没有 CLI 数据目录的普通 PE **不能**被说成 .NET。
    ///
    /// 这是反面的关键一条：误报会让用户以为一个普通 C++ 程序是托管的。
    #[test]
    fn plain_pe_is_not_reported_as_dotnet() {
        let obj = parse(&minimal_pe64(), 0, ObjectId::Plain).unwrap();
        let joined = obj.notes.join("\n");
        assert!(
            !joined.contains(".NET"),
            "普通 PE 不该被报成 .NET：{:?}",
            obj.notes
        );
        assert!(!joined.contains("托管"), "普通 PE 不该出现托管字样");
    }

    /// CLI 头 RVA 指向文件外时，要如实说"读不出来"，不能编造标志位。
    #[test]
    fn cli_header_outside_the_file_is_reported_not_guessed() {
        let mut bytes = minimal_pe64();
        let opt = 0x84 + 20;
        let dir_cli = opt + 112 + 14 * 8;
        // RVA 远超出映像范围
        bytes[dir_cli..dir_cli + 4].copy_from_slice(&0x00ff_0000u32.to_le_bytes());
        bytes[dir_cli + 4..dir_cli + 8].copy_from_slice(&72u32.to_le_bytes());

        let obj = parse(&bytes, 0, ObjectId::Plain).unwrap();
        let joined = obj.notes.join("\n");
        assert!(joined.contains("CLI 头"), "应提到 CLI 头：{:?}", obj.notes);
        // 不能因为读不到就默认 ILONLY 之类的结论
        assert!(
            !joined.contains("纯 IL") && !joined.contains("混合模式"),
            "头读不出来时不该给出 IL/混合模式的结论：{:?}",
            obj.notes
        );
    }

    /// 元数据根签名不对时，不编造版本串。
    #[test]
    fn bogus_metadata_signature_yields_no_version_string() {
        let mut bytes = pe64_with_cli(0x0000_0001, 0x0600_0001, "v4.0.30319");
        let cli_off = 0x200 + (0x1200 - 0x1000);
        let meta_off = cli_off + 72;
        // 破坏 BSJB 签名
        bytes[meta_off] = 0xff;
        let obj = parse(&bytes, 0, ObjectId::Plain).unwrap();
        let joined = obj.notes.join("\n");
        assert!(
            !joined.contains("v4.0.30319"),
            "签名不对时不该报出版本串：{:?}",
            obj.notes
        );
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

    // ── UNWIND_INFO 解码 ──
    //
    // 造一个"文件字节 + 一个 .rdata 段"的最小对象，把 UNWIND_INFO 的
    // 字节放在段里，验证解码结果。段 RVA 0x2000 → 文件偏移 0x100。

    /// 构造一个带 .rdata 段的对象（image_base 0x140000000）。
    fn object_with_rdata(info_bytes: &[u8]) -> (Object, Vec<u8>) {
        const BASE: u64 = 0x1_4000_0000;
        let mut bytes = vec![0u8; 0x400];
        // 头部 0x100 是段内的 UNWIND_INFO，放在 0x100 处
        bytes[0x100..0x100 + info_bytes.len()].copy_from_slice(info_bytes);
        let mut obj = Object::new(
            ObjectId::Plain,
            crate::ObjectKind::Pe,
            ArchSpec::from_arch(Arch::X86_64, Mode::M64, Endian::Little),
            Endian::Little,
        );
        obj.image_base = BASE;
        obj.segments.push(Segment {
            name: ".rdata".to_string(),
            vaddr: BASE + 0x2000,
            vsize: 0x300,
            file: Some(FileRange::new(0x100, 0x300)),
            perms: Perms {
                read: true,
                write: false,
                execute: false,
            },
            kind: ContentKind::ReadOnlyData,
            align: 0x1000,
        });
        (obj, bytes)
    }

    /// `push rbx; push rbp; sub rsp, 0x28` 的展开信息。
    ///
    /// 帧大小 = 8 + 8 + 40 = 56 = 0x38；保存 rbx、rbp。
    #[test]
    fn unwind_push_and_alloc_sm_all_sum_to_frame_size() {
        // byte0: version 0, flags 0
        // byte1: SizeOfProlog = 0x10
        // byte2: CountOfCodes = 3
        // byte3: FrameRegister=0, FrameOffset=0
        // code0: PUSH_NONVOL rbx(3) @ 0
        // code1: PUSH_NONVOL rbp(5) @ 1
        // code2: ALLOC_SMALL info=4 (0x28/8-1=4) @ 3
        let blob = [
            0x01, 0x10, 0x03, 0x00, // 头（版本 1 = x64）
            0x00, 0x30, // push rbx：CodeOffset=0, op=0, info=3
            0x01, 0x50, // push rbp：CodeOffset=1, op=0, info=5
            0x03, 0x42, // alloc small：CodeOffset=3, op=2, info=4
            0x00, 0x00, // 对齐填充到 8 字节
        ];
        let (obj, bytes) = object_with_rdata(&blob);
        let reader = Reader::with_base(&bytes, 0);

        // 段 RVA 0x2000 → 文件 0x100；UNWIND_INFO 在段内偏移 0，
        // 所以 VA = image_base + 0x2000。
        let info = parse_unwind_info(&reader, &obj, 0x1_4000_2000).expect("能定位并解码");
        assert_eq!(info.prologue_size, 0x10);
        assert_eq!(info.frame_size(), Some(0x38));
        assert_eq!(info.saved_registers(), vec!["rbx", "rbp"]);
        assert!(info.frame_register.is_none());

        // push 的槽位：第一个 push（rbx）距最终 RSP 0x30，第二个（rbp）0x28
        match &info.ops[0] {
            PeUnwindOp::PushNonVolatile { reg, slot_from_top } => {
                assert_eq!(reg, "rbx");
                assert_eq!(*slot_from_top, 0x30);
            }
            other => panic!("第一个操作应是 push rbx，实际 {other:?}"),
        }
        match &info.ops[2] {
            PeUnwindOp::Alloc { size } => assert_eq!(*size, 0x28),
            other => panic!("第三个操作应是 alloc，实际 {other:?}"),
        }
    }

    /// 帧指针 + SAVE_NONVOL：`mov [rbp-0x10], rbx` 以缩放偏移记录。
    #[test]
    fn unwind_frame_register_and_save_nonvol() {
        // FrameRegister=5(rbp), FrameOffset=1 → 偏移 16 字节
        // code0: PUSH_NONVOL rbp @ 0
        // code1: SAVE_NONVOL rbx(3)，scaled offset 0x10(→0x80) — 占 2 槽
        // code2: （SAVE 的附加槽 —— 不解释为独立操作）
        //
        // 字节编码要当心：低 4 位是 UnwindOp、高 4 位是 OpInfo。
        // SAVE_NONVOL 的 op=4、rbx 的编号=3 → (3<<4)|4 = 0x34。
        // 写成 0x43 就变成 op=3(SET_FPREG)、info=4，是另一条操作了。
        let blob = [
            0x01, 0x0C, 0x02,
            0x15, // 头：版本1(x64)，前导0xC，2 个槽，frame=5, off=1
            0x00, 0x50, // push rbp
            0x02, 0x34, // SAVE_NONVOL rbx，scaled=0x10
            0x10, 0x00, // 附加槽：scaled offset = 0x10（LE u16）
        ];
        let (obj, bytes) = object_with_rdata(&blob);
        let reader = Reader::with_base(&bytes, 0);
        // 段 RVA 0x2000 → 文件 0x100；blob 在段内偏移 0，故 VA = image_base + 0x2000
        let va = 0x1_4000_2000;

        let info = parse_unwind_info(&reader, &obj, va).expect("解码");
        assert_eq!(info.frame_register.as_deref(), Some("rbp"));
        assert_eq!(info.frame_offset, 16);
        // push rbp(8) + 无 alloc；SAVE 不占帧
        assert_eq!(info.frame_size(), Some(8));
        assert_eq!(info.saved_registers(), vec!["rbp", "rbx"]);

        // SAVE_NONVOL 的缩放偏移
        let save = info
            .ops
            .iter()
            .find(|o| matches!(o, PeUnwindOp::SaveNonVolatile { .. }));
        match save {
            Some(PeUnwindOp::SaveNonVolatile { reg, scaled_offset }) => {
                assert_eq!(reg, "rbx");
                assert_eq!(*scaled_offset, 0x10);
            }
            other => panic!("应找到 SAVE_NONVOL，实际 {other:?}"),
        }
    }

    /// ALLOC_LARGE（info=1，8 字节大小，占 3 槽）。
    #[test]
    fn unwind_alloc_large_reads_full_width() {
        // version 0；SizeOfProlog=1；CountOfCodes=3
        // code0: ALLOC_LARGE info=1，大小 0x3000，占额外 2 槽
        let mut blob = vec![0x01u8, 0x01, 0x03, 0x00]; // 版本 1 = x64
        blob.push(0x00); // CodeOffset
        blob.push(0x11); // op=1, info=1
        blob.extend_from_slice(&0x3000u32.to_le_bytes()); // 2 个附加槽放 4 字节大小
        let (obj, bytes) = object_with_rdata(&blob);
        let reader = Reader::with_base(&bytes, 0);
        // 段 RVA 0x2000 → 文件 0x100；blob 在段内偏移 0，故 VA = image_base + 0x2000
        let va = 0x1_4000_2000;

        let info = parse_unwind_info(&reader, &obj, va).expect("解码");
        assert_eq!(info.frame_size(), Some(0x3000));
        match &info.ops[0] {
            PeUnwindOp::Alloc { size } => assert_eq!(*size, 0x3000),
            other => panic!("应为 alloc large，实际 {other:?}"),
        }
    }

    /// 版本 1（ARM64）只记录头字段，不解码展开码。
    #[test]
    fn unwind_non_x64_version_records_header_only() {
        let blob = [0x02u8, 0x08, 0x02, 0x00, 0x00, 0x30, 0x01, 0x50]; // 版本 2（非 x64）
        let (obj, bytes) = object_with_rdata(&blob);
        let reader = Reader::with_base(&bytes, 0);
        // 段 RVA 0x2000 → 文件 0x100；blob 在段内偏移 0，故 VA = image_base + 0x2000
        let va = 0x1_4000_2000;

        let info = parse_unwind_info(&reader, &obj, va).expect("返回骨架");
        assert_eq!(info.version, 2);
        assert!(info.ops.is_empty(), "非 x64 版本不解码展开码");
        assert!(
            info.notes.iter().any(|n| n.contains("版本 2")),
            "必须有降级说明：{:?}",
            info.notes
        );
    }

    /// 解析不到对象里的地址时返回 None，不 panic。
    #[test]
    fn unwind_out_of_bounds_returns_none() {
        let bundle = object_with_rdata(&[0x01, 0x01, 0x01, 0x00, 0x00, 0x30]);
        let reader = Reader::with_base(&bundle.1, 0);
        // 一个不在任何段内的 VA
        assert!(parse_unwind_info(&reader, &bundle.0, 0x4000_0000).is_none());
    }
}
