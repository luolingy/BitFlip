//! 符号表与重定位表。
//!
//! 这两件事放一起，是因为它们共用同一个前提：**"符号 → 节 → 文件偏移"这条取数路径**。
//! 符号的值是虚拟地址，要拿到字节得先找到它落在哪个节、再换算成文件偏移；
//! 重定位的目标同理。分开写会让这条路径出现两份，而两份一定会漂移。
//!
//! `classify_reloc` 是纯查表：`(e_machine, r_type)` → 语义。未知组合**返回
//! `RelocKind::Other` 并保留原始编号**，不猜成某个已知语义 —— 猜错的后果是
//! 用户以为工具懂这条重定位，而它其实不懂。

use super::parse::{read_strtab, section_name};
use super::{
    sh_type, sym_bind, sym_type, ElfHeader, SectionHeader, MAX_RELOCS, MAX_STRTAB, MAX_SYMBOLS,
};
use crate::object::{Object, RawSymbol, Reloc, RelocKind, SymbolTableSource};
use crate::reader::{ParseError, Reader};

/// 解析符号表。
///
/// `shstrtab` 是**必须**的：符号的 `st_shndx` 只是个下标，要变成"这个符号在哪个节"
/// 就得查节名，而节名在 `.shstrtab` 里。少了它，符号的节名全部解析不出来
/// （`section_name` 会给出 `<节 N>` 占位，这里再判成 `None`），消费方就找不到
/// 这个符号所在的字节 —— 签名生成、交叉引用都要按"符号 → 节 → 文件偏移"取内容。
pub(super) fn parse_symbols(
    reader: &Reader<'_>,
    header: &ElfHeader,
    sh: &SectionHeader,
    raw_sections: &[SectionHeader],
    shstrtab: &[u8],
    source: SymbolTableSource,
    object: &mut Object,
) -> Result<Vec<RawSymbol>, ParseError> {
    let entry_size = if sh.entsize == 0 {
        if header.is_64 {
            24
        } else {
            16
        }
    } else {
        sh.entsize
    };
    if entry_size == 0 {
        return Err(ParseError::Inconsistent("符号表项大小为 0".into()));
    }
    let count = sh.size / entry_size;
    if count == 0 {
        return Ok(Vec::new());
    }
    if count > MAX_SYMBOLS {
        object.note(format!(
            "符号表声称有 {count} 个符号，超过上限 {MAX_SYMBOLS}，已跳过（文件可能被构造）"
        ));
        return Ok(Vec::new());
    }
    let mut tls_symbols = 0u64;
    let mut absolute_symbols = 0u64;

    // 符号名来自 sh_link 指向的字符串表。
    let strtab: Vec<u8> = match raw_sections.get(sh.link as usize) {
        Some(str_sh) if str_sh.sh_type == sh_type::STRTAB => {
            let size = str_sh.size.min(MAX_STRTAB);
            match reader.slice(str_sh.offset, size, "符号名字符串表") {
                Ok(bytes) => bytes.to_vec(),
                Err(error) => {
                    object.note(format!("符号名字符串表读取失败：{}", error.summary_zh()));
                    Vec::new()
                }
            }
        }
        _ => {
            object.note(format!(
                "符号表的 sh_link={} 未指向字符串表，符号名不可用",
                sh.link
            ));
            Vec::new()
        }
    };

    let mut out = Vec::new();
    out.try_reserve(count.min(65_536) as usize)
        .map_err(|_| ParseError::Overflow(format!("无法为 {count} 个符号预留内存")))?;

    for index in 0..count {
        let offset = sh
            .offset
            .checked_add(
                index
                    .checked_mul(entry_size)
                    .ok_or_else(|| ParseError::Overflow("符号表项偏移".into()))?,
            )
            .ok_or_else(|| ParseError::Overflow("符号表项偏移".into()))?;

        let view = Reader::with_base(
            reader.slice(offset, entry_size, "符号表项")?,
            reader.base() + offset,
        );

        let (name_offset, info, _other, shndx, value, size) = if header.is_64 {
            (
                view.u32(0, header.endianness, "st_name")?,
                view.u8(4, "st_info")?,
                view.u8(5, "st_other")?,
                view.u16(6, header.endianness, "st_shndx")?,
                view.u64(8, header.endianness, "st_value")?,
                view.u64(16, header.endianness, "st_size")?,
            )
        } else {
            (
                view.u32(0, header.endianness, "st_name")?,
                view.u8(12, "st_info")?,
                view.u8(13, "st_other")?,
                view.u16(14, header.endianness, "st_shndx")?,
                u64::from(view.u32(4, header.endianness, "st_value")?),
                u64::from(view.u32(8, header.endianness, "st_size")?),
            )
        };

        let bind = info >> 4;
        let sym_type = info & 0xf;

        let name = if name_offset == 0 {
            String::new()
        } else {
            read_strtab(&strtab, u64::from(name_offset)).unwrap_or_default()
        };

        // 节符号（STT_SECTION）的名字通常为空，用节名代替，否则这一堆符号全是空的。
        let section = if (shndx as usize) < raw_sections.len() {
            let name = section_name(raw_sections, shstrtab, shndx as usize);
            if name.starts_with("<节 ") {
                None
            } else {
                Some(name)
            }
        } else {
            None
        };

        // 0xFFF1 = SHN_ABS，0 = SHN_UNDEF
        const SHN_UNDEF: u16 = 0;
        const SHN_ABS: u16 = 0xfff1;
        let defined = shndx != SHN_UNDEF;

        // SHN_ABS 符号的值是一个**常量**（例如编译器生成的边界常量），
        // 不是进程地址空间里的地址。把它当地址用会产生虚假的交叉引用。
        if shndx == SHN_ABS {
            absolute_symbols += 1;
        }

        // 空名字 + 未定义 + 非节符号 = 纯粹的表项填充，丢掉以免污染符号列表
        if name.is_empty() && !defined && sym_type != sym_type::SECTION && index != 0 {
            continue;
        }

        // .file 符号（STT_FILE）标记编译单元，不是可引用实体。它们在符号列表里
        // 没有地址含义，只会让"符号数"虚高，因此直接跳过。
        if sym_type == sym_type::FILE {
            continue;
        }

        // STT_TLS 的值是线程局部存储里的偏移，**不是进程地址空间里的地址**。
        // 若把它当普通地址用，分析会把 TLS 变量误认成代码/数据引用。
        if sym_type == sym_type::TLS {
            tls_symbols += 1;
        }

        out.push(RawSymbol {
            name,
            value,
            size,
            defined,
            is_function: sym_type == sym_type::FUNC,
            is_weak: bind == sym_bind::WEAK,
            bind,
            section,
            source,
        });
    }

    if tls_symbols > 0 {
        object.note(format!(
            "有 {tls_symbols} 个 TLS 符号（STT_TLS）：它们的值是线程局部存储偏移，不是进程地址",
        ));
    }
    if absolute_symbols > 0 {
        object.note(format!(
            "有 {absolute_symbols} 个绝对符号（SHN_ABS）：它们的值是常量，不是地址",
        ));
    }

    Ok(out)
}

/// 解析重定位表。
pub(super) fn parse_relocs(
    reader: &Reader<'_>,
    header: &ElfHeader,
    sh: &SectionHeader,
    raw_sections: &[SectionHeader],
    shstrtab: &[u8],
) -> Result<Vec<Reloc>, ParseError> {
    let is_rela = sh.sh_type == sh_type::RELA;
    let entry_size = if sh.entsize != 0 {
        sh.entsize
    } else if header.is_64 {
        if is_rela {
            24
        } else {
            16
        }
    } else if is_rela {
        12
    } else {
        8
    };
    if entry_size == 0 {
        return Err(ParseError::Inconsistent("重定位项大小为 0".into()));
    }

    let count = sh.size / entry_size;
    if count == 0 {
        return Ok(Vec::new());
    }
    if count > MAX_RELOCS {
        return Err(ParseError::Overflow(format!(
            "重定位表声称有 {count} 项，超过上限 {MAX_RELOCS}"
        )));
    }

    // sh_link 指向关联的符号表（用于取符号名）
    let symtab = raw_sections.get(sh.link as usize);
    let sym_name_table: Vec<u8> = match symtab {
        Some(st) => match raw_sections.get(st.link as usize) {
            Some(str_sh) if str_sh.sh_type == sh_type::STRTAB => {
                let size = str_sh.size.min(MAX_STRTAB);
                reader
                    .slice(str_sh.offset, size, "重定位符号名字符串表")
                    .map(<[u8]>::to_vec)
                    .unwrap_or_default()
            }
            _ => Vec::new(),
        },
        None => Vec::new(),
    };
    let sym_entry_size = symtab.map_or(0, |st| {
        if st.entsize != 0 {
            st.entsize
        } else if header.is_64 {
            24
        } else {
            16
        }
    });

    let mut out = Vec::new();
    // `sh_info` 才是"这些重定位作用在哪个节上"（ELF 规范：SHT_REL/SHT_RELA 的
    // sh_info 是目标节的节头索引）。这里早先写的是字面量 0 —— 取到的当然是
    // 空节的名字，而且取完就被丢掉，所以一直没被发现。签名匹配要求
    // 「地址 + 节名」配对，这个字段从"没用"变成了"必需"，顺手改正。
    //
    // sh_info 为 0（`.rela.dyn` 这类作用于整个映像的重定位表）时如实给 `None`：
    // 它们不对应单个节。**不**退回 `<节 0>` 这种占位名 —— 那会把"没这个信息"
    // 伪装成一个看起来像名字的东西。
    let target_name = raw_sections
        .get(sh.info as usize)
        .filter(|section| section.name_offset != 0)
        .and_then(|section| read_strtab(shstrtab, u64::from(section.name_offset)))
        .filter(|name| !name.is_empty());

    for index in 0..count {
        let offset = sh
            .offset
            .checked_add(
                index
                    .checked_mul(entry_size)
                    .ok_or_else(|| ParseError::Overflow("重定位项偏移".into()))?,
            )
            .ok_or_else(|| ParseError::Overflow("重定位项偏移".into()))?;
        let view = Reader::with_base(
            reader.slice(offset, entry_size, "重定位项")?,
            reader.base() + offset,
        );

        let (r_offset, r_info, addend) = if header.is_64 {
            let addend = if is_rela {
                view.u64(16, header.endianness, "r_addend")? as i64
            } else {
                0
            };
            (
                view.u64(0, header.endianness, "r_offset")?,
                view.u64(8, header.endianness, "r_info")?,
                addend,
            )
        } else {
            let addend = if is_rela {
                view.u32(8, header.endianness, "r_addend")? as i32 as i64
            } else {
                0
            };
            (
                u64::from(view.u32(0, header.endianness, "r_offset")?),
                u64::from(view.u32(4, header.endianness, "r_info")?),
                addend,
            )
        };

        let (sym_index, raw_kind) = if header.is_64 {
            (r_info >> 32, (r_info & 0xffff_ffff) as u32)
        } else {
            (r_info >> 8, (r_info & 0xff) as u32)
        };

        // 取符号名（越界不报错，只是没有名字）
        let symbol = if sym_index != 0 && sym_entry_size != 0 {
            symtab.and_then(|st| {
                let sym_off = st
                    .offset
                    .checked_add(sym_index.checked_mul(sym_entry_size)?)?;
                // `st_name` 在 Elf32_Sym 与 Elf64_Sym 里都是第一个字段（偏移 0），
                // 因此两种位宽共用同一次读取。
                let name_off = reader.u32(sym_off, header.endianness, "st_name").ok()?;
                if name_off == 0 {
                    return None;
                }
                let name = read_strtab(&sym_name_table, u64::from(name_off))?;
                if name.is_empty() {
                    None
                } else {
                    Some(name)
                }
            })
        } else {
            None
        };

        out.push(Reloc {
            address: r_offset,
            section: target_name.clone(),
            kind: classify_reloc(header.machine, raw_kind),
            raw_kind,
            symbol,
            addend,
        });
    }

    Ok(out)
}

/// 把格式特有的重定位编号归一化成粗分类。
///
/// 只覆盖常见架构；未知编号归入 `Other` 并保留 `raw_kind`，
/// 这样 M2 需要精确编号时能拿到，而分析层不必理解每个架构的编号表。
pub(super) fn classify_reloc(machine: u16, raw_kind: u32) -> RelocKind {
    const EM_X86_64: u16 = 62;
    const EM_386: u16 = 3;
    const EM_AARCH64: u16 = 183;
    const EM_ARM: u16 = 40;
    const EM_RISCV: u16 = 243;

    match machine {
        // x86_64: 64=1, PC32=2, PLT32=4, GLOB_DAT=6, JUMP_SLOT=7,
        //         RELATIVE=8, GOTPCREL=9, RELATIVE64=38, PC64=42
        EM_X86_64 => match raw_kind {
            1 => RelocKind::Absolute,
            2 | 4 | 9 | 42 => RelocKind::Relative,
            6 | 7 => RelocKind::ImportLookup,
            // RELATIVE / RELATIVE64 是**数据槽位**指针（加载器写"基址+加数"），
            // 与指令里的 PC 相对重定位是两回事。分开归类，指针表识别才能
            // 只挑出它们而不误取指令重定位。
            8 | 38 => RelocKind::RelocPointer,
            _ => RelocKind::Other,
        },
        // i386: 32=1, PC32=2, GLOB_DAT=6, JMP_SLOT=7, RELATIVE=8
        EM_386 => match raw_kind {
            1 => RelocKind::Absolute,
            2 => RelocKind::Relative,
            6 | 7 => RelocKind::ImportLookup,
            8 => RelocKind::RelocPointer,
            _ => RelocKind::Other,
        },
        // aarch64: ABS64=257, PREL32=261, GLOB_DAT=1025, JUMP_SLOT=1026, RELATIVE=1027
        EM_AARCH64 => match raw_kind {
            257 => RelocKind::Absolute,
            261 => RelocKind::Relative,
            1025 | 1026 => RelocKind::ImportLookup,
            1027 => RelocKind::RelocPointer,
            _ => RelocKind::Other,
        },
        // arm: ABS32=2, REL32=3, GLOB_DAT=21, JUMP_SLOT=22, RELATIVE=23
        EM_ARM => match raw_kind {
            2 => RelocKind::Absolute,
            3 => RelocKind::Relative,
            21 | 22 => RelocKind::ImportLookup,
            23 => RelocKind::RelocPointer,
            _ => RelocKind::Other,
        },
        // riscv: 64/32=2, RELATIVE=3, JUMP_SLOT=5
        EM_RISCV => match raw_kind {
            2 => RelocKind::Absolute,
            3 => RelocKind::RelocPointer,
            5 => RelocKind::ImportLookup,
            _ => RelocKind::Other,
        },
        _ => RelocKind::Other,
    }
}
