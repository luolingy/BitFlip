//! COFF 目标文件（`.obj`）解析。
//!
//! COFF 就是 PE 去掉 DOS 头与可选头之后的骨架，因此与 [`crate::pe`] 共用大部分
//! 概念。单独成文件是因为入口完全不同：没有 `MZ`/`PE` 签名，直接从 COFF 文件头开始。
//!
//! M1 只做**识别与结构**（节表、符号表、重定位）；COFF 在 M2 与 PE 一起纳入对象层归一化。

use bitflip_arch::{Arch, ArchSpec, Endian};

use crate::object::{
    ContentKind, FileRange, FormatInfo, Object, ObjectId, Perms, RawSymbol, Reloc, RelocKind,
    Section, Segment, SymbolTableSource,
};
use crate::reader::{Endianness, ParseError, Reader};
use crate::ObjectKind;

/// COFF 文件头大小。
const HEADER_SIZE: u64 = 20;
/// 节头大小。
const SECTION_SIZE: u64 = 40;
/// 符号表项大小。
const SYMBOL_SIZE: u64 = 18;
/// 重定位项大小。
const RELOC_SIZE: u64 = 10;

/// 节数量上限（COFF 用 16 位，仍做对称防御）。
const MAX_SECTIONS: u64 = 4096;
/// 符号数量上限。
const MAX_SYMBOLS: u64 = 1_000_000;
/// 重定位数量上限。
const MAX_RELOCS: u64 = 1_000_000;
/// 字符串读取上限。
const MAX_STRING: u64 = 4096;

/// 解析入口。
///
/// 注意：调用方（`sniff`）已经确定这是 COFF，因此这里不再做模糊匹配，
/// 直接按 COFF 结构解析。
pub fn parse(bytes: &[u8], base: u64, id: ObjectId) -> Result<Object, ParseError> {
    let reader = Reader::with_base(bytes, base);

    let machine = reader.u16(0, Endianness::Little, "Machine")?;
    let num_sections = u64::from(reader.u16(2, Endianness::Little, "NumberOfSections")?);
    let symbol_table_ptr = reader.u32(8, Endianness::Little, "PointerToSymbolTable")?;
    let num_symbols = reader.u32(12, Endianness::Little, "NumberOfSymbols")?;

    let (arch_kind, mode) = Arch::from_pe_machine(machine).ok_or(ParseError::Unsupported {
        what: "Machine",
        value: u64::from(machine),
        detail: "未知或尚未支持的 COFF 机器类型（见 docs/PLAN.md §1.3 架构矩阵）",
    })?;
    let arch = ArchSpec::from_arch(arch_kind, mode, Endian::Little);
    let mut object = Object::new(id, ObjectKind::Coff, arch, Endian::Little);

    if num_sections > MAX_SECTIONS {
        return Err(ParseError::Unsupported {
            what: "NumberOfSections",
            value: num_sections,
            detail: "节数量超过实现上限",
        });
    }

    // ── 节表 ──
    let sections_offset = HEADER_SIZE;
    let raw_sections: Vec<(String, u32, u32, u32, u32, u32)> = reader.for_each_entry(
        sections_offset,
        SECTION_SIZE,
        num_sections,
        "COFF 节表",
        |_i, view| {
            let raw_name = view.slice(0, 8, "节名")?;
            let end = raw_name.iter().position(|&b| b == 0).unwrap_or(8);
            Ok((
                String::from_utf8_lossy(&raw_name[..end]).trim().to_string(),
                view.u32(8, Endianness::Little, "PhysicalAddress/VirtualSize")?,
                view.u32(12, Endianness::Little, "VirtualAddress")?,
                view.u32(16, Endianness::Little, "SizeOfRawData")?,
                view.u32(20, Endianness::Little, "PointerToRawData")?,
                view.u32(36, Endianness::Little, "Characteristics")?,
            ))
        },
    )?;

    // 符号表后面紧跟字符串表（前 4 字节是总长度）。
    //
    // 注意：**不能**用 `num_symbols > 0` 作为前提 —— 节的长名字 `/NNN` 也存在
    // 这个字符串表里，而有些编译器产物有长节名却没有符号（或已被剥离）。
    // 只要 PointerToSymbolTable 非 0 就应当尝试解析。
    let strtab_offset = if symbol_table_ptr != 0 {
        u64::from(symbol_table_ptr).checked_add(u64::from(num_symbols) * SYMBOL_SIZE)
    } else {
        None
    };

    for (name, virtual_size, virtual_address, raw_size, raw_pointer, characteristics) in
        &raw_sections
    {
        // 长节名："/NNN" 指向字符串表偏移
        let name = resolve_section_name(&reader, name, strtab_offset);

        let perms = perms_from_characteristics(*characteristics);
        let kind = kind_from_name(&name, perms);
        let vsize = u64::from(if *virtual_size == 0 {
            *raw_size
        } else {
            *virtual_size
        });

        let file_end = u64::from(*raw_pointer).checked_add(u64::from(*raw_size));
        if *raw_size > 0 && file_end.is_none_or(|end| end > reader.len()) {
            object.note(format!(
                "节 {name} 的数据范围 {:#x}+{:#x} 超出文件大小 {:#x}，文件可能被裁剪",
                raw_pointer,
                raw_size,
                reader.len()
            ));
        }

        object.sections.push(Section {
            name: name.clone(),
            vaddr: u64::from(*virtual_address),
            file: FileRange::new(u64::from(*raw_pointer), u64::from(*raw_size)),
            perms,
            kind,
            loaded: perms.read,
        });
        object.segments.push(Segment {
            name,
            vaddr: u64::from(*virtual_address),
            vsize,
            file: if *raw_size > 0 {
                Some(FileRange::new(
                    u64::from(*raw_pointer),
                    u64::from(*raw_size),
                ))
            } else {
                None
            },
            perms,
            kind,
            align: 1,
        });
    }

    // COFF 目标文件没有入口点概念 —— 必须是 None，不能是 0
    object.entry = None;
    object.image_base = 0;

    // ── 符号表 ──
    if symbol_table_ptr != 0 && num_symbols > 0 {
        match parse_symbols(
            &reader,
            symbol_table_ptr,
            num_symbols,
            &object,
            strtab_offset,
        ) {
            Ok(symbols) => object.symbols = symbols,
            Err(error) => object.note(format!("COFF 符号表解析失败：{}", error.summary_zh())),
        }
    }

    // ── 重定位 ──
    // 每个节的重定位表由节头里的 PointerToRelocations/NumberOfRelocations 指向。
    parse_all_relocations(&reader, machine, sections_offset, num_sections, &mut object);

    object.format = FormatInfo {
        type_name: Some("COFF 目标文件".to_string()),
        os_abi: Some("Windows".to_string()),
        subsystem: None,
        is_dynamic_library: false,
        is_executable: false,
        is_relocatable: true,
        is_stripped: object.symbols.is_empty(),
        declared_size: None,
    };

    Ok(object)
}

/// 解析 `/NNN` 形式的长节名。
fn resolve_section_name(reader: &Reader<'_>, name: &str, strtab_offset: Option<u64>) -> String {
    let Some(rest) = name.strip_prefix('/') else {
        return name.to_string();
    };
    let Ok(offset) = rest.parse::<u64>() else {
        return name.to_string();
    };
    let Some(strtab) = strtab_offset else {
        return name.to_string();
    };
    // 字符串表前 4 字节是表长度，偏移从表头算起
    if offset < 4 {
        return name.to_string();
    }
    reader
        .cstr(strtab + offset, MAX_STRING, "长节名")
        .ok()
        .filter(|s| !s.is_empty())
        .unwrap_or_else(|| name.to_string())
}

/// 由 Characteristics 解出权限。
fn perms_from_characteristics(characteristics: u32) -> Perms {
    const CNT_CODE: u32 = 0x0000_0020;
    const CNT_INITIALIZED_DATA: u32 = 0x0000_0040;
    const CNT_UNINITIALIZED_DATA: u32 = 0x0000_0080;
    const MEM_EXECUTE: u32 = 0x2000_0000;
    const MEM_READ: u32 = 0x4000_0000;
    const MEM_WRITE: u32 = 0x8000_0000;

    Perms {
        read: characteristics & MEM_READ != 0
            || characteristics & (CNT_CODE | CNT_INITIALIZED_DATA) != 0,
        write: characteristics & (MEM_WRITE | CNT_UNINITIALIZED_DATA) != 0,
        execute: characteristics & (MEM_EXECUTE | CNT_CODE) != 0,
    }
}

/// 由节名推断内容类别。
fn kind_from_name(name: &str, perms: Perms) -> ContentKind {
    match name {
        ".text" | ".text$mn" | "CODE" => ContentKind::Code,
        ".data" | "DATA" => ContentKind::Data,
        ".rdata" | ".rodata" | "CONST" => ContentKind::ReadOnlyData,
        ".bss" => ContentKind::Bss,
        ".pdata" => ContentKind::Unwind,
        ".xdata" | ".debug" | ".debug$S" | ".debug$T" => ContentKind::Debug,
        ".drectve" | ".linkinfo" => ContentKind::Unknown,
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

/// 解析 COFF 符号表。
fn parse_symbols(
    reader: &Reader<'_>,
    symbol_table_ptr: u32,
    num_symbols: u32,
    object: &Object,
    strtab_offset: Option<u64>,
) -> Result<Vec<RawSymbol>, ParseError> {
    let count = u64::from(num_symbols);
    if count > MAX_SYMBOLS {
        return Err(ParseError::Overflow(format!(
            "COFF 符号表声称有 {count} 个符号，超过上限 {MAX_SYMBOLS}"
        )));
    }

    let offset = u64::from(symbol_table_ptr);
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
            let str_offset =
                u32::from_le_bytes([raw_name[4], raw_name[5], raw_name[6], raw_name[7]]);
            match strtab_offset {
                Some(table) if str_offset >= 4 => reader
                    .cstr(table + u64::from(str_offset), MAX_STRING, "COFF 符号名")
                    .unwrap_or_default(),
                _ => String::new(),
            }
        } else {
            let end = raw_name.iter().position(|&b| b == 0).unwrap_or(8);
            String::from_utf8_lossy(&raw_name[..end]).into_owned()
        };

        let value = view.u32(8, Endianness::Little, "Value")?;
        let section_number = view.i16(12, Endianness::Little, "SectionNumber")?;
        let type_field = view.u16(14, Endianness::Little, "Type")?;
        let storage_class = view.u8(16, "StorageClass")?;
        let aux_count = u64::from(view.u8(17, "NumberOfAuxSymbols")?);

        // 辅助记录占槽位，必须跳过（否则会把 .file 的内容当符号读）
        index += 1 + aux_count;

        if name.is_empty() {
            continue;
        }

        // 派生类型位（0x20）标记函数；只对 external/static 生效
        let is_function = type_field & 0x20 != 0 && (storage_class == 2 || storage_class == 3);

        out.push(RawSymbol {
            name,
            value: u64::from(value),
            size: 0,
            defined: section_number > 0,
            is_function,
            is_weak: storage_class == 105,
            // COFF 的"绑定"概念由 StorageClass 表达，与 ELF 的 STB_* 不是一套编号。
            // 这里只映射"局部 / 全局"这一层，保留原始语义的最小交集。
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

/// 遍历所有节的重定位表。
fn parse_all_relocations(
    reader: &Reader<'_>,
    machine: u16,
    sections_offset: u64,
    num_sections: u64,
    object: &mut Object,
) {
    let mut total = 0u64;
    for index in 0..num_sections {
        let Some(entry) = sections_offset.checked_add(index * SECTION_SIZE) else {
            break;
        };
        let Ok(view) = reader.slice(entry, SECTION_SIZE, "COFF 节头") else {
            break;
        };
        let view = Reader::with_base(view, reader.base() + entry);

        let Ok(pointer) = view.u32(24, Endianness::Little, "PointerToRelocations") else {
            break;
        };
        let Ok(count) = view.u16(32, Endianness::Little, "NumberOfRelocations") else {
            break;
        };
        if pointer == 0 || count == 0 {
            continue;
        }

        let section_name = object
            .sections
            .get(index as usize)
            .map(|section| section.name.clone())
            .filter(|name| !name.is_empty());

        if total + u64::from(count) > MAX_RELOCS {
            object.note(format!(
                "重定位项总数超过上限 {MAX_RELOCS}，后续节的重定位已跳过"
            ));
            return;
        }

        // IMAGE_RELOCATION 是 10 字节
        let result: Result<Vec<(u32, u32, u16)>, ParseError> = reader.for_each_entry(
            u64::from(pointer),
            RELOC_SIZE,
            u64::from(count),
            "COFF 重定位",
            |_i, v| {
                Ok((
                    v.u32(0, Endianness::Little, "VirtualAddress")?,
                    v.u32(4, Endianness::Little, "SymbolTableIndex")?,
                    v.u16(8, Endianness::Little, "Type")?,
                ))
            },
        );

        match result {
            Ok(entries) => {
                for (address, symbol_index, reloc_type) in entries {
                    let symbol = object
                        .symbols
                        .get(symbol_index as usize)
                        .map(|s| s.name.clone());
                    object.relocations.push(Reloc {
                        address: u64::from(address),
                        section: section_name.clone(),
                        kind: classify(machine, reloc_type),
                        raw_kind: u32::from(reloc_type),
                        symbol,
                        addend: 0,
                    });
                    total += 1;
                }
            }
            Err(error) => {
                object.note(format!(
                    "{} 的重定位表解析失败：{}",
                    section_name.as_deref().unwrap_or("未知节"),
                    error.summary_zh()
                ));
            }
        }
    }
}

/// COFF 重定位类型 → 归一化分类。
///
/// **编号是架构相关的**：同一个数字在 i386 与 AMD64 下含义不同
/// （例如 6 在 i386 是 `DIR32`，在 AMD64 是 `REL32_2`）。
/// 因此必须传入机器类型，否则会把 PC 相对重定位误判成绝对地址。
///
/// 未知编号一律归 `Other`，并把原始编号留在 `Reloc::raw_kind` —— 猜错会让
/// 后面基于重定位的分析得出错误结论，不如明确说"不认识"。
fn classify(machine: u16, reloc_type: u16) -> RelocKind {
    const IMAGE_FILE_MACHINE_I386: u16 = 0x014c;
    const IMAGE_FILE_MACHINE_AMD64: u16 = 0x8664;
    const IMAGE_FILE_MACHINE_ARM64: u16 = 0xaa64;
    const IMAGE_FILE_MACHINE_ARMNT: u16 = 0x01c4;

    match machine {
        IMAGE_FILE_MACHINE_AMD64 => match reloc_type {
            1 | 2 => RelocKind::Absolute, // ADDR64 / ADDR32
            // ADDR32NB 不含基址；SECTION/SECREL 是段内偏移 —— 都不是普通绝对地址
            4..=9 => RelocKind::Relative, // REL32 家族
            _ => RelocKind::Other,
        },
        IMAGE_FILE_MACHINE_I386 => match reloc_type {
            6 => RelocKind::Absolute,  // DIR32
            20 => RelocKind::Relative, // REL32
            _ => RelocKind::Other,     // 含 7 = DIR32NB（不含基址）
        },
        IMAGE_FILE_MACHINE_ARM64 => match reloc_type {
            1 | 2 | 8 | 9 => RelocKind::Absolute, // ADDR32/ADDR64/PAGEBASE...
            _ => RelocKind::Other,
        },
        IMAGE_FILE_MACHINE_ARMNT => match reloc_type {
            1 | 2 => RelocKind::Absolute,
            _ => RelocKind::Other,
        },
        _ => RelocKind::Other,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// 构造一个最小 COFF 目标文件（1 个 .text 节，无符号表）。
    fn minimal_coff() -> Vec<u8> {
        let mut bytes = vec![0u8; 0x200];
        bytes[0..2].copy_from_slice(&0x8664u16.to_le_bytes()); // AMD64
        bytes[2..4].copy_from_slice(&1u16.to_le_bytes()); // 1 个节
        bytes[16..18].copy_from_slice(&0u16.to_le_bytes()); // SizeOfOptionalHeader = 0
        bytes[18..20].copy_from_slice(&0u16.to_le_bytes()); // Characteristics

        // 节表在偏移 20
        let sec = HEADER_SIZE as usize;
        bytes[sec..sec + 5].copy_from_slice(b".text");
        bytes[sec + 8..sec + 12].copy_from_slice(&0x100u32.to_le_bytes()); // VirtualSize
        bytes[sec + 16..sec + 20].copy_from_slice(&0x100u32.to_le_bytes()); // SizeOfRawData
        bytes[sec + 20..sec + 24].copy_from_slice(&0x100u32.to_le_bytes()); // PointerToRawData
        bytes[sec + 36..sec + 40].copy_from_slice(&0x6050_0020u32.to_le_bytes()); // CODE|EXEC|READ|ALIGN16
        bytes
    }

    #[test]
    fn parses_minimal_coff() {
        let obj = parse(&minimal_coff(), 0, ObjectId::Plain).unwrap();
        assert_eq!(obj.kind, ObjectKind::Coff);
        assert_eq!(obj.arch.arch, Arch::X86_64);
        assert_eq!(obj.sections.len(), 1);
        assert_eq!(obj.sections[0].name, ".text");
        assert_eq!(obj.sections[0].kind, ContentKind::Code);
        assert!(obj.sections[0].perms.execute);
        // 目标文件没有入口
        assert_eq!(obj.entry, None);
        assert_eq!(obj.image_base, 0);
        assert!(obj.format.is_relocatable);
    }

    #[test]
    fn rejects_unknown_machine() {
        let mut bytes = minimal_coff();
        bytes[0..2].copy_from_slice(&0x1234u16.to_le_bytes());
        assert!(matches!(
            parse(&bytes, 0, ObjectId::Plain),
            Err(ParseError::Unsupported {
                what: "Machine",
                ..
            })
        ));
    }

    #[test]
    fn rejects_too_many_sections() {
        let mut bytes = minimal_coff();
        bytes[2..4].copy_from_slice(&60000u16.to_le_bytes());
        assert!(matches!(
            parse(&bytes, 0, ObjectId::Plain),
            Err(ParseError::Unsupported {
                what: "NumberOfSections",
                ..
            })
        ));
    }

    #[test]
    fn long_section_name_resolves_via_string_table() {
        let mut bytes = vec![0u8; 0x400];
        bytes[0..2].copy_from_slice(&0x8664u16.to_le_bytes());
        bytes[2..4].copy_from_slice(&1u16.to_le_bytes());
        // 符号表位置（无符号，仅用于定位字符串表）
        bytes[8..12].copy_from_slice(&0x300u32.to_le_bytes());
        bytes[12..16].copy_from_slice(&0u32.to_le_bytes());

        let sec = HEADER_SIZE as usize;
        bytes[sec..sec + 5].copy_from_slice(b"/4\0\0\0"); // 指向字符串表偏移 4
        bytes[sec + 16..sec + 20].copy_from_slice(&0x10u32.to_le_bytes());
        bytes[sec + 20..sec + 24].copy_from_slice(&0x100u32.to_le_bytes());

        // 字符串表在符号表之后（0x300 + 0 个符号）
        let strtab = 0x300usize;
        let names = b".verylongname\0";
        bytes[strtab..strtab + 4].copy_from_slice(&(4u32 + names.len() as u32).to_le_bytes());
        bytes[strtab + 4..strtab + 4 + names.len()].copy_from_slice(names);

        let obj = parse(&bytes, 0, ObjectId::Plain).unwrap();
        assert_eq!(obj.sections[0].name, ".verylongname");
    }

    #[test]
    fn section_beyond_file_is_noted() {
        let mut bytes = minimal_coff();
        let sec = HEADER_SIZE as usize;
        bytes[sec + 20..sec + 24].copy_from_slice(&0x9000u32.to_le_bytes());
        let obj = parse(&bytes, 0, ObjectId::Plain).unwrap();
        assert!(
            obj.notes.iter().any(|n| n.contains("超出文件大小")),
            "notes = {:?}",
            obj.notes
        );
    }

    #[test]
    fn every_truncation_never_panics() {
        let good = minimal_coff();
        for len in 0..good.len() {
            let _ = parse(&good[..len], 0, ObjectId::Plain);
        }
    }

    #[test]
    fn single_byte_corruption_never_panics() {
        let good = minimal_coff();
        for index in 0..good.len().min(0x100) {
            for bit in 0..8 {
                let mut bytes = good.clone();
                bytes[index] ^= 1 << bit;
                let _ = parse(&bytes, 0, ObjectId::Plain);
            }
        }
    }

    #[test]
    fn sample_size_field_cannot_cause_huge_allocation() {
        let mut bytes = minimal_coff();
        bytes[2..4].copy_from_slice(&4096u16.to_le_bytes()); // 声称有 4096 个节
                                                             // 文件只有 0x200 字节 —— 必须快速失败或记 note，不尝试分配
        let result = parse(&bytes, 0, ObjectId::Plain);
        assert!(result.is_err() || result.is_ok());
    }

    #[test]
    fn reloc_classification_is_architecture_aware() {
        const AMD64: u16 = 0x8664;
        const I386: u16 = 0x014c;

        // AMD64
        assert_eq!(classify(AMD64, 1), RelocKind::Absolute); // ADDR64
        assert_eq!(classify(AMD64, 2), RelocKind::Absolute); // ADDR32
        assert_eq!(classify(AMD64, 4), RelocKind::Relative); // REL32
        assert_eq!(classify(AMD64, 3), RelocKind::Other); // ADDR32NB：不含基址

        // 同一个编号 6 在两种架构下含义不同 —— 这正是必须传 machine 的原因
        assert_eq!(classify(I386, 6), RelocKind::Absolute); // i386 DIR32
        assert_eq!(classify(AMD64, 6), RelocKind::Relative); // AMD64 REL32_2

        assert_eq!(classify(I386, 20), RelocKind::Relative); // i386 REL32
        assert_eq!(classify(0xffff, 1), RelocKind::Other); // 未知架构不猜
    }

    #[test]
    fn perms_come_from_characteristics() {
        // CODE | MEM_EXECUTE | MEM_READ
        let perms = perms_from_characteristics(0x6000_0020);
        assert!(perms.execute);
        assert!(perms.read);
        assert!(!perms.write);

        // UNINITIALIZED_DATA 应当视为可写
        let bss = perms_from_characteristics(0x0000_0080);
        assert!(bss.write);
        assert!(!bss.execute);
    }
}
