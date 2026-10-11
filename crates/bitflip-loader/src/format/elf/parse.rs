//! ELF 的入口：把各层解析串成一份 [`Object`]。
//!
//! 这个文件刻意保持"像目录一样好读"：每一段做一件事，顺序就是 ELF 的结构顺序。
//! 真正的字节级解析在 `mod`（头部与取值）、`sym`（符号/重定位）、`dynamic`（动态与展开）。
//!
//! 一处值得注意的设计：**单个符号表或重定位表解析失败不会让整个对象失败**，
//! 而是把它降级成一条 `note` 并继续。理由是真实世界里 `.symtab` 损坏但
//! `.dynsym` 完好的文件是存在的，整体失败会让用户拿不到本来能拿到的信息。
//! 代价是"部分成功"必须**可见** —— 所以失败一定写进 `notes`，不静默吞掉。

use super::dynamic::{
    build_format_info, compute_image_base, derive_exports, extended_count, extended_sh_info,
    note_arch_flags, parse_dynamic_dependencies, parse_eh_frame_entries,
};
use super::sym::{parse_relocs, parse_symbols};
use super::{
    p_type, sh_flags, sh_type, ElfHeader, ProgramHeader, SectionHeader, EHDR32_SIZE, EHDR64_SIZE,
    MAX_SECTIONS, MAX_SEGMENTS, MAX_STRTAB,
};
use crate::object::{
    ContentKind, FileRange, Object, ObjectId, Perms, Section, Segment, SymbolTableSource,
};
use crate::reader::{ParseError, Reader};
use crate::ObjectKind;
use bitflip_arch::{Arch, ArchSpec, Mode};

/// 解析入口：把 ELF 字节解析成 [`Object`]。
///
/// `base` 是这段字节在宿主文件中的偏移（归档成员需要）。
pub fn parse(bytes: &[u8], base: u64, id: ObjectId) -> Result<Object, ParseError> {
    let reader = Reader::with_base(bytes, base);
    let header = ElfHeader::parse(&reader)?;

    let arch = resolve_arch(header.machine, header.is_64, &header)?;
    let mut object = Object::new(id, ObjectKind::Elf, arch, header.endian);

    // ── 段表 ────────────────────────────────────────────────────────────
    let mut segments = parse_segments(&reader, &header, &mut object)?;

    // ── 节表 ────────────────────────────────────────────────────────────
    let SectionTable {
        sections,
        raw: section_headers,
        shstrtab,
    } = parse_sections(&reader, &header, &mut object)?;

    // 段名从节名借：ELF 的 PT_LOAD 没有名字，UI 上显示 .text/.data 比 "段 0" 有用得多。
    name_segments_from_sections(&mut segments, &sections);
    object.segments = segments;
    object.sections = sections;

    // ── 入口 ────────────────────────────────────────────────────────────
    // 可重定位目标文件（.o）的 e_entry 恒为 0 且无意义，必须报 None 而不是 0。
    object.entry = if header.elf_type == 1 || header.entry == 0 {
        None
    } else {
        Some(header.entry)
    };

    // ── 符号表 ──────────────────────────────────────────────────────────
    for (index, sh) in section_headers.iter().enumerate() {
        if sh.sh_type != sh_type::SYMTAB && sh.sh_type != sh_type::DYNSYM {
            continue;
        }
        let source = if sh.sh_type == sh_type::DYNSYM {
            SymbolTableSource::Dynamic
        } else {
            SymbolTableSource::Static
        };
        match parse_symbols(
            &reader,
            &header,
            sh,
            &section_headers,
            &shstrtab,
            source,
            &mut object,
        ) {
            Ok(symbols) => object.symbols.extend(symbols),
            Err(error) => object.note(format!(
                "节 {index}（{}）符号表解析失败：{}",
                section_name(&section_headers, &shstrtab, index),
                error.summary_zh()
            )),
        }
    }

    // ── 重定位 ──────────────────────────────────────────────────────────
    for sh in &section_headers {
        if sh.sh_type != sh_type::RELA && sh.sh_type != sh_type::REL {
            continue;
        }
        match parse_relocs(&reader, &header, sh, &section_headers, &shstrtab) {
            Ok(relocs) => object.relocations.extend(relocs),
            Err(error) => object.note(format!("重定位表解析失败：{}", error.summary_zh())),
        }
    }

    // ── 头部一致性检查 ──────────────────────────────────────────────────
    // e_ehsize / e_*entsize 是头部自述的"结构体应有大小"。
    // 与解析器期望值不符时说明文件结构异常，但**不以此为准**去解析 ——
    // 按自述大小解析等于让输入决定内存布局，是典型的越界来源。
    object.header_flags = Some(header.flags);
    let expected_ehsize = if header.is_64 {
        EHDR64_SIZE
    } else {
        EHDR32_SIZE
    };
    if u64::from(header.ehsize) != expected_ehsize {
        object.note(format!(
            "e_ehsize = {}，与 Elf{} 期望的 {expected_ehsize} 不符；解析按实际结构进行",
            header.ehsize,
            if header.is_64 { 64 } else { 32 }
        ));
    }
    note_arch_flags(&mut object, &header);

    // ── 动态段：依赖列表 ────────────────────────────────────────────────
    parse_dynamic_dependencies(&reader, &header, &section_headers, &shstrtab, &mut object);

    // ── .eh_frame：解析 FDE，恢复函数边界 ───────────────────────────────
    //
    // 这是剥离符号场景下**唯一**还能给出精确函数边界的来源（PLAN §M3）。
    // 只解边界，不解 CFI 指令：栈回溯才需要那部分。
    parse_eh_frame_entries(&reader, &section_headers, &shstrtab, &mut object);

    // ── 格式信息 ────────────────────────────────────────────────────────
    object.format = build_format_info(&header, &object.sections);
    object.image_base = compute_image_base(&header, &object.segments);

    // 导出：动态符号表里已定义且全局可见的符号，就是 .so 的导出集。
    object.exports = derive_exports(&object.symbols);

    Ok(object)
}

/// 由 `e_machine` 解析架构；未知机器类型明确报错而不是猜。
pub(super) fn resolve_arch(
    machine: u16,
    is_64: bool,
    _header: &ElfHeader,
) -> Result<ArchSpec, ParseError> {
    let arch = Arch::from_elf_machine(machine, is_64).ok_or(ParseError::Unsupported {
        what: "e_machine",
        value: u64::from(machine),
        detail: "未知或尚未支持的 ELF 机器类型（见 docs/PLAN.md §1.3 架构矩阵）",
    })?;
    let mode = match (arch, is_64) {
        (Arch::X86, true) => Mode::M64,
        (Arch::X86, false) => Mode::M32,
        (Arch::Riscv32, _) => Mode::M32,
        (Arch::Riscv64, _) => Mode::M64,
        (Arch::Mips, _) => Mode::M32,
        (Arch::Mips64, _) => Mode::M64,
        (Arch::Wasm32, _) => Mode::M32,
        (_, true) => Mode::M64,
        (_, false) => Mode::M32,
    };
    // ELF 的字节序来自 EI_DATA，不是架构默认值 —— 大端 MIPS/ARM 真实存在。
    Ok(ArchSpec::from_arch(arch, mode, _header.endian))
}

/// 解析程序头表。
pub(super) fn parse_segments(
    reader: &Reader<'_>,
    header: &ElfHeader,
    object: &mut Object,
) -> Result<Vec<Segment>, ParseError> {
    if header.phoff == 0 || header.phnum == 0 {
        object.note("无程序头表（常见于可重定位目标文件 .o）");
        return Ok(Vec::new());
    }

    let entry_size = if header.phentsize == 0 {
        header.phdr_size()
    } else {
        u64::from(header.phentsize)
    };
    // 文件声明的表项大小小于我们期望的，说明结构对不上 —— 报错比读错好。
    if entry_size < header.phdr_size() {
        return Err(ParseError::Inconsistent(format!(
            "e_phentsize={entry_size} 小于 {} 位 ELF 的固定程序头大小 {}",
            if header.is_64 { 64 } else { 32 },
            header.phdr_size()
        )));
    }

    let mut count = u64::from(header.phnum);
    if let Some(cap) = extended_count(reader, 0xffff, count, MAX_SEGMENTS) {
        // PN_XNUM：段数异常时去 section 0 取真实值
        let real = extended_sh_info(reader, header, 0).unwrap_or(cap);
        if real == 0 {
            object.note("e_phnum = 0xffff 但未找到真实段数（PN_XNUM），按声明值处理");
        } else {
            count = real.min(MAX_SEGMENTS);
        }
    }

    let raw: Vec<ProgramHeader> = reader.for_each_entry(
        header.phoff,
        entry_size,
        count,
        "程序头表",
        |_i, view| ProgramHeader::parse(&view, header.is_64, header.endianness),
    )?;

    let mut segments = Vec::with_capacity(raw.len());
    // 只报一次 p_paddr ≠ p_vaddr：这类映像的每个段都会不同，逐段刷屏没有信息量
    let mut paddr_differs_noted = false;
    for (index, ph) in raw.iter().enumerate() {
        // 只把可加载段放进内存视角；NOTE/PHDR 之类的段不是地址空间的一部分。
        let kind = match ph.p_type {
            p_type::LOAD => ContentKind::Unknown,
            p_type::DYNAMIC => ContentKind::Dynamic,
            p_type::INTERP => ContentKind::ReadOnlyData,
            p_type::GNU_EH_FRAME => ContentKind::Unwind,
            p_type::GNU_STACK => ContentKind::Unknown,
            p_type::TLS => ContentKind::Data,
            _ => ContentKind::Unknown,
        };

        // 段名先留空，后面从覆盖它的节借名。
        segments.push(Segment {
            name: segment_placeholder_name(ph.p_type, index),
            vaddr: ph.vaddr,
            vsize: ph.memsz,
            file: if ph.filesz > 0 {
                Some(FileRange::new(ph.offset, ph.filesz))
            } else {
                None
            },
            perms: ph.perms(),
            kind,
            align: ph.align,
        });

        // p_paddr（物理地址）在普通用户态程序里等于 p_vaddr，但在裸机/内核映像里
        // 两者不同（加载到物理地址、运行在链接地址）。差异必须报出来，
        // 否则基于 vaddr 的地址映射在这类目标上会整体偏移。
        // 只报一次：这类映像的每个段都会不同，逐段刷屏没有信息量。
        if ph.paddr != 0 && ph.paddr != ph.vaddr && !paddr_differs_noted {
            object.note(format!(
                "段 {index} 的物理地址 p_paddr({:#x}) 与虚拟地址 p_vaddr({:#x}) 不同：\
                 这通常是裸机/内核映像（加载地址 ≠ 运行地址）",
                ph.paddr, ph.vaddr
            ));
            paddr_differs_noted = true;
        }

        // filesz > memsz 是矛盾文件，要报出来
        if ph.filesz > ph.memsz {
            object.note(format!(
                "段 {index} 的 p_filesz({:#x}) 大于 p_memsz({:#x})，文件可能被修改过",
                ph.filesz, ph.memsz
            ));
        }
        // PT_LOAD 的 file range 必须在文件内 —— 这是最常见的损坏点
        if ph.p_type == p_type::LOAD && ph.filesz > 0 {
            let end = ph
                .offset
                .checked_add(ph.filesz)
                .ok_or_else(|| ParseError::Overflow(format!("段 {index}: p_offset + p_filesz")))?;
            if end > reader.len() {
                object.note(format!(
                    "段 {index} 的文件范围 {:#x}..{:#x} 超出文件大小 {:#x}，文件可能被裁剪",
                    ph.offset,
                    end,
                    reader.len()
                ));
            }
        }
    }

    // 可执行栈是安全相关的事实，值得单独提示。
    if let Some(stack) = raw.iter().find(|ph| ph.p_type == p_type::GNU_STACK) {
        if stack.perms().execute {
            object.note("PT_GNU_STACK 标记为可执行（.note.GNU-stack 缺失）");
        }
    }

    Ok(segments)
}

/// 给没有名字的段一个占位名。
pub(super) fn segment_placeholder_name(p_type: u32, index: usize) -> String {
    let base = match p_type {
        p_type::LOAD => "LOAD",
        p_type::DYNAMIC => "DYNAMIC",
        p_type::INTERP => "INTERP",
        p_type::NOTE => "NOTE",
        p_type::PHDR => "PHDR",
        p_type::TLS => "TLS",
        p_type::GNU_EH_FRAME => "GNU_EH_FRAME",
        p_type::GNU_STACK => "GNU_STACK",
        p_type::GNU_RELRO => "GNU_RELRO",
        _ => "PT",
    };
    format!("{base}#{index}")
}

/// 用节名给段命名（覆盖优先）。
///
/// GNU 工具链的约定：`PT_LOAD` 常覆盖 `.init/.text/.fini` 多个节，
/// 此时用**第一个可执行的节**命名，用户在 UI 上找 `.text` 最直观。
pub(super) fn name_segments_from_sections(segments: &mut [Segment], sections: &[Section]) {
    for segment in segments.iter_mut() {
        if segment.vsize == 0 {
            continue;
        }
        let mut best: Option<&Section> = None;
        for section in sections {
            if section.file.is_empty() && section.name != ".bss" {
                continue;
            }
            if section.vaddr < segment.vaddr {
                continue;
            }
            if section.vaddr.wrapping_sub(segment.vaddr) >= segment.vsize {
                continue;
            }
            // 优先级：可执行节 > 已加载节 > 靠前的节
            let better = match best {
                None => true,
                Some(current) => {
                    let cur_rank = (current.perms.execute as u8) * 2 + (current.loaded as u8);
                    let new_rank = (section.perms.execute as u8) * 2 + (section.loaded as u8);
                    new_rank > cur_rank
                }
            };
            if better {
                best = Some(section);
            }
        }
        if let Some(section) = best {
            segment.name = section.name.clone();
            if segment.kind == ContentKind::Unknown {
                segment.kind = section.kind;
            }
        }
    }
}

/// 节表解析结果：归一化节、原始节头、节名字符串表。
pub(super) struct SectionTable {
    /// 归一化后的节（已去掉 SHT_NULL 占位）。
    sections: Vec<Section>,
    /// 原始节头，供后续按索引查节名。
    raw: Vec<SectionHeader>,
    /// `.shstrtab` 的内容。
    shstrtab: Vec<u8>,
}

/// 解析节表。
pub(super) fn parse_sections(
    reader: &Reader<'_>,
    header: &ElfHeader,
    object: &mut Object,
) -> Result<SectionTable, ParseError> {
    if header.shoff == 0 || header.shentsize == 0 {
        object.note("无节头表（文件可能已剥离节表）");
        return Ok(SectionTable {
            sections: Vec::new(),
            raw: Vec::new(),
            shstrtab: Vec::new(),
        });
    }

    let entry_size = u64::from(header.shentsize);
    if entry_size < header.shdr_size() {
        return Err(ParseError::Inconsistent(format!(
            "e_shentsize={entry_size} 小于 {} 位 ELF 的固定节头大小 {}",
            if header.is_64 { 64 } else { 32 },
            header.shdr_size()
        )));
    }

    // 至少要有 section 0，才能读 extended 的 shnum/shstrndx。
    let section0: SectionHeader = {
        let view = reader.slice(header.shoff, entry_size, "节头表[0]")?;
        SectionHeader::parse(
            &Reader::with_base(view, reader.base() + header.shoff),
            header.is_64,
            header.endianness,
        )?
    };

    // ── extended shnum（e_shnum == 0 → sh_size of section 0）──
    let mut count = u64::from(header.shnum);
    if count == 0 {
        if section0.size == 0 {
            object.note("e_shnum = 0 且 section 0 的 sh_size = 0：无法确定节数量");
            return Ok(SectionTable {
                sections: Vec::new(),
                raw: Vec::new(),
                shstrtab: Vec::new(),
            });
        }
        if section0.size > MAX_SECTIONS {
            object.note(format!(
                "节数量声明为 {} 超过上限 {MAX_SECTIONS}，按上限截断（文件可能被构造）",
                section0.size
            ));
        } else {
            object.note(format!(
                "节数量取自 section 0 的 sh_size（extended shnum）：{}",
                section0.size
            ));
        }
        count = section0.size.min(MAX_SECTIONS);
    }
    count = count.min(MAX_SECTIONS);

    // ── extended shstrndx（e_shstrndx == SHN_XINDEX 0xffff）──
    let mut shstrndx = u64::from(header.shstrndx);
    if header.shstrndx == 0xffff {
        shstrndx = section0.link as u64;
        object.note(format!(
            "节名表索引取自 section 0 的 sh_link（extended shstrndx）：{shstrndx}"
        ));
    }

    let raw: Vec<SectionHeader> =
        reader.for_each_entry(header.shoff, entry_size, count, "节头表", |_i, view| {
            SectionHeader::parse(&view, header.is_64, header.endianness)
        })?;

    // ── 节名字符串表 ──
    let shstrtab: Vec<u8> = if shstrndx < raw.len() as u64 && shstrndx != 0 {
        let sh = &raw[shstrndx as usize];
        if sh.sh_type != sh_type::STRTAB {
            object.note(format!(
                "节名表索引 {shstrndx} 指向的不是字符串表（sh_type={}），节名将不可用",
                sh.sh_type
            ));
            Vec::new()
        } else {
            let size = sh.size.min(MAX_STRTAB);
            match reader.slice(sh.offset, size, "节名字符串表") {
                Ok(bytes) => bytes.to_vec(),
                Err(error) => {
                    object.note(format!("节名字符串表读取失败：{}", error.summary_zh()));
                    Vec::new()
                }
            }
        }
    } else {
        if header.shstrndx != 0 && shstrndx >= raw.len() as u64 {
            object.note(format!(
                "节名表索引 {shstrndx} 越界（共 {} 个节）",
                raw.len()
            ));
        }
        Vec::new()
    };

    // ── 归一化 ──
    let mut sections = Vec::with_capacity(raw.len());
    for (index, sh) in raw.iter().enumerate() {
        // 节 0 按规范必须是 SHT_NULL，它不是真实节，只是"没有节"的占位。
        // 列进节表会让节数比 readelf 多 1，并且显示成一行空名字的噪声。
        if index == 0 && sh.sh_type == 0 {
            continue;
        }

        let name = if sh.name_offset == 0 {
            String::new()
        } else {
            read_strtab(&shstrtab, u64::from(sh.name_offset)).unwrap_or_default()
        };

        // 越界的节数据范围：记 note 但不中止 —— 一个坏节不该让整个文件读不了。
        let file_end = sh.offset.checked_add(sh.size);
        let in_bounds = match file_end {
            Some(end) => end <= reader.len(),
            None => false,
        };
        if !in_bounds {
            object.note(format!(
                "节 {}（{name}）的数据范围 {:#x}+{:#x} 超出文件大小 {:#x}，文件可能被裁剪",
                index,
                sh.offset,
                sh.size,
                reader.len()
            ));
        }

        // sh_addralign 必须是 0（无约束）或 2 的幂。非 2 的幂说明节头被破坏；
        // 这类文件后续按对齐做地址映射会得到错位结果，必须报出来。
        if sh.addralign != 0 && !sh.addralign.is_power_of_two() {
            object.note(format!(
                "节 {}（{name}）的 sh_addralign = {} 不是 2 的幂，节头可能已损坏",
                index, sh.addralign
            ));
        }

        sections.push(Section {
            name,
            vaddr: sh.addr,
            file: FileRange::new(sh.offset, sh.size),
            perms: section_perms(sh),
            kind: section_content_kind(sh),
            loaded: sh.is_loaded(),
        });
    }

    Ok(SectionTable {
        sections,
        raw,
        shstrtab,
    })
}

/// 从字符串表按偏移取字符串。
pub(super) fn read_strtab(table: &[u8], offset: u64) -> Option<String> {
    let start = usize::try_from(offset).ok()?;
    if start >= table.len() {
        return None;
    }
    let rest = &table[start..];
    let end = rest.iter().position(|&b| b == 0).unwrap_or(rest.len());
    Some(String::from_utf8_lossy(&rest[..end]).into_owned())
}

/// 节权限：ELF 用 SHF_WRITE / SHF_EXECINSTR，没有"可读"概念（可加载即可读）。
pub(super) fn section_perms(sh: &SectionHeader) -> Perms {
    Perms {
        read: sh.flags & sh_flags::ALLOC != 0,
        write: sh.flags & sh_flags::WRITE != 0,
        execute: sh.flags & sh_flags::EXECINSTR != 0,
    }
}

/// 由节类型与名字推断内容类别。
pub(super) fn section_content_kind(sh: &SectionHeader) -> ContentKind {
    match sh.sh_type {
        0 => ContentKind::Unknown, // SHT_NULL
        sh_type::SYMTAB | sh_type::DYNSYM => ContentKind::SymbolTable,
        sh_type::STRTAB => ContentKind::StringTable,
        sh_type::RELA | sh_type::REL => ContentKind::Relocations,
        sh_type::DYNAMIC => ContentKind::Dynamic,
        sh_type::NOBITS => ContentKind::Bss,
        sh_type::INIT_ARRAY | sh_type::FINI_ARRAY => ContentKind::Data,
        sh_type::HASH
        | sh_type::GNU_HASH
        | sh_type::GNU_VERDEF
        | sh_type::GNU_VERNEED
        | sh_type::GNU_VERSYM => ContentKind::Data,
        sh_type::NOTE => ContentKind::Metadata,
        sh_type::PROGBITS => {
            if sh.flags & sh_flags::EXECINSTR != 0 {
                ContentKind::Code
            } else if sh.flags & sh_flags::WRITE != 0 {
                ContentKind::Data
            } else if sh.flags & sh_flags::ALLOC != 0 {
                // 只有**会被映射**的段才是"只读数据"。
                ContentKind::ReadOnlyData
            } else {
                // 不参与映射的 PROGBITS（.comment / .debug_* 等）既不是代码也不是
                // 运行期数据 —— 它们是文件里的元数据。归为 ReadOnlyData 会让
                // 界面把 `.comment` 显示成"只读数据"却带着 `---` 权限，自相矛盾。
                ContentKind::Metadata
            }
        }
        _ => ContentKind::Unknown,
    }
}

/// 节名（越界时给出占位）。
pub(super) fn section_name(raw: &[SectionHeader], shstrtab: &[u8], index: usize) -> String {
    raw.get(index)
        .filter(|sh| sh.name_offset != 0)
        .and_then(|sh| read_strtab(shstrtab, u64::from(sh.name_offset)))
        .unwrap_or_else(|| format!("<节 {index}>"))
}
