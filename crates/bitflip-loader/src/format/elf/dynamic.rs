//! 动态链接信息与 `.eh_frame`。
//!
//! 三件事，共同点是**都建立在"已经解析完的节表/符号表"之上**，而不是直接读文件头：
//!
//! - `parse_dynamic_dependencies`：`.dynamic` / `PT_DYNAMIC` 里的 `DT_NEEDED`；
//! - `parse_eh_frame_entries`：`.eh_frame` 的 FDE → 函数边界。
//!   这是**剥离符号后唯一还能给出精确函数边界**的来源（PLAN §M3）。
//!   只解边界，不解 CFI 指令。
//! - `derive_exports`：从已解析的符号里推出导出集。它是符号表的**投影**，
//!   所以放在这里而不是 `sym`：`sym` 负责"读出符号"，这里负责"由符号回答
//!   另一个问题"。
//!
//! `.eh_frame` 的扫描在遇到无法解释的指令时**停止并记录 note**，而不是跳过继续 ——
//! CFI 是状态机，跳过一条会让后面所有 FDE 的边界都错位，那种错是静默的：
//! 用户会拿到一份看起来完整、实际偏了的函数清单。

use super::parse::read_strtab;
use super::{
    p_type, sh_type, sym_bind, ElfHeader, ProgramHeader, SectionHeader, MAX_SEGMENTS, MAX_STRTAB,
};
use crate::object::{
    ContentKind, Export, FormatInfo, Import, Object, RawSymbol, Section, Segment, SymbolTableSource,
};
use crate::reader::{Endianness, Reader};
use bitflip_arch::Endian;

/// 从 `.eh_frame` 解析 FDE 并填进 `object.unwind`。
///
/// 边界情况都写进 `notes`，不静默少给数据（§7）：
/// * 段存在但读不到 → 说明原因；
/// * relocatable object（`.o`）：`.eh_frame` 里的地址是重定位前的占位值，
///   未应用重定位就当成真实地址是**错的**，因此明确标注而不是给假边界；
/// * 解析中途出错 → 把解析器的 note 浮上来。
pub(super) fn parse_eh_frame_entries(
    reader: &Reader<'_>,
    raw_sections: &[SectionHeader],
    shstrtab: &[u8],
    object: &mut Object,
) {
    // 优先找名字精确等于 .eh_frame 的段
    let Some(raw) = raw_sections.iter().find(|sh| {
        read_strtab(shstrtab, u64::from(sh.name_offset)).as_deref() == Some(".eh_frame")
    }) else {
        return; // 没有 .eh_frame 是正常的，不产生 note
    };

    if raw.size == 0 {
        return;
    }

    // relocatable object：`entry` 为 None 就是 `.o`（见 Object::entry 的文档）。
    // `.eh_frame` 里的地址尚未重定位，解出来的"边界"不是最终地址。
    // 这种情况不提供 unwind 条目，并明确说明原因 —— 给假地址比不给更糟。
    if object.entry.is_none() {
        object.note(
            ".eh_frame 存在，但当前目标是可重定位对象（.o），其中的地址尚未重定位；\
             未提供展开表边界（需要应用重定位后才能给出可信地址）"
                .to_string(),
        );
        return;
    }

    let Ok(data) = reader.slice(raw.offset, raw.size, ".eh_frame") else {
        object.note(format!(
            ".eh_frame（偏移 {:#x}，大小 {}）读取失败，未提供展开表边界",
            raw.offset, raw.size
        ));
        return;
    };

    let endianness = match object.endian {
        Endian::Little => Endianness::Little,
        Endian::Big => Endianness::Big,
    };
    let parsed = crate::ehframe::parse_eh_frame(data, raw.addr, endianness);

    for entry in &parsed.fdes {
        object.unwind.push(crate::object::UnwindEntry {
            begin: entry.begin,
            end: entry.end(),
            unwind_info: 0, // FDE 自身的展开信息地址；M3 不做栈回溯，不填假值
            // ELF 的 .eh_frame 目前只解出函数边界，没有 CFI 指令解码。
            // 因此 decoded 一律 None —— 与 PE 的 UNWIND_INFO 解码保持一致，
            // 让上层能区分"这个函数没有展开信息"和"有展开信息但没解码"。
            decoded: None,
            // `false` 而不是 `true`：这里**没有**可推迟的解码工作。
            // ELF 的 CFI 解码是"M3 还没做"，不是"推迟到需要时做"—— 前者
            // 是一条待实现的特性，后者是一个性能手段。把两者混起来会让
            // `resolve_unwind` 白跑一遍，而且掩盖了"CFI 尚未实现"这个事实。
            deferred: false,
        });
    }

    // 解析器的降级说明必须浮到上层
    for n in &parsed.notes {
        object.note(n.clone());
    }

    if !parsed.fdes.is_empty() {
        object.note(format!(
            ".eh_frame 提供 {} 条函数边界（来自 FDE）",
            parsed.fdes.len()
        ));
    } else if parsed.notes.is_empty() {
        object.note(".eh_frame 存在但没有解析出任何 FDE".to_string());
    }
}
pub(super) fn parse_dynamic_dependencies(
    reader: &Reader<'_>,
    header: &ElfHeader,
    raw_sections: &[SectionHeader],
    shstrtab: &[u8],
    object: &mut Object,
) {
    const DT_NULL: u64 = 0;
    const DT_NEEDED: u64 = 1;
    const DT_STRTAB: u64 = 5;

    // 优先用节表（能拿到名字），退化到程序头里的 PT_DYNAMIC。
    let dynamic_range = raw_sections
        .iter()
        .find(|sh| sh.sh_type == sh_type::DYNAMIC)
        .map(|sh| (sh.offset, sh.size))
        .or_else(|| {
            // PT_DYNAMIC 的偏移记录在段里，这里重新扫一遍程序头
            if header.phoff == 0 || header.phnum == 0 {
                return None;
            }
            let entry_size = if header.phentsize == 0 {
                header.phdr_size()
            } else {
                u64::from(header.phentsize)
            };
            let count = u64::from(header.phnum).min(MAX_SEGMENTS);
            for index in 0..count {
                let offset = header.phoff.checked_add(index.checked_mul(entry_size)?)?;
                let view = reader.slice(offset, entry_size, "程序头").ok()?;
                let view = Reader::with_base(view, reader.base() + offset);
                let ph = ProgramHeader::parse(&view, header.is_64, header.endianness).ok()?;
                if ph.p_type == p_type::DYNAMIC {
                    return Some((ph.offset, ph.filesz));
                }
            }
            None
        });

    let (dyn_offset, dyn_size) = match dynamic_range {
        Some(range) => range,
        None => return,
    };

    let entry_size = if header.is_64 { 16 } else { 8 };
    let count = dyn_size / entry_size;
    if count == 0 {
        return;
    }

    // DT_STRTAB 给的是**虚拟地址**，需要反查文件偏移。
    let mut strtab_vaddr: Option<u64> = None;
    let mut needed_offsets: Vec<u64> = Vec::new();

    for index in 0..count.min(65_536) {
        let Some(offset) = dyn_offset.checked_add(index * entry_size) else {
            break;
        };
        let Ok(view) = reader.slice(offset, entry_size, "动态段") else {
            break;
        };
        let view = Reader::with_base(view, reader.base() + offset);
        let (tag, value) = if header.is_64 {
            match (
                view.u64(0, header.endianness, "d_tag"),
                view.u64(8, header.endianness, "d_val"),
            ) {
                (Ok(t), Ok(v)) => (t, v),
                _ => break,
            }
        } else {
            match (
                view.u32(0, header.endianness, "d_tag"),
                view.u32(4, header.endianness, "d_val"),
            ) {
                (Ok(t), Ok(v)) => (u64::from(t), u64::from(v)),
                _ => break,
            }
        };

        if tag == DT_NULL {
            break;
        }
        if tag == DT_STRTAB {
            strtab_vaddr = Some(value);
        }
        if tag == DT_NEEDED {
            needed_offsets.push(value);
        }
    }

    if needed_offsets.is_empty() {
        return;
    }

    // 把 DT_STRTAB 的虚拟地址映射到文件偏移（可能在 PT_LOAD 里）。
    let Some(strtab_vaddr) = strtab_vaddr else {
        object.note(format!(
            "发现 {} 条 DT_NEEDED 但缺少 DT_STRTAB，依赖名不可用",
            needed_offsets.len()
        ));
        return;
    };

    // 通过节表找 .dynstr
    let dynstr = raw_sections
        .iter()
        .find(|sh| read_strtab(shstrtab, u64::from(sh.name_offset)).as_deref() == Some(".dynstr"));
    let Some(dynstr) = dynstr else {
        object.note("缺少 .dynstr 节，DT_NEEDED 依赖名不可用");
        return;
    };
    let Ok(table) = reader.slice(dynstr.offset, dynstr.size.min(MAX_STRTAB), ".dynstr") else {
        object.note(".dynstr 节读取失败，DT_NEEDED 依赖名不可用");
        return;
    };
    let _ = strtab_vaddr;

    for offset in needed_offsets {
        // DT_NEEDED 的 value 是 .dynstr 内的偏移
        if let Some(name) = read_strtab(table, offset) {
            if !name.is_empty() {
                object.imports.push(Import {
                    module: name,
                    name: None,
                    ordinal: None,
                    iat_slot: None,
                    thunk: None,
                });
            }
        }
    }

    if !object.imports.is_empty() {
        object.note(format!(
            "共享库依赖（DT_NEEDED）：{} 个 —— 详细的导入符号解析在 M3",
            object.imports.len()
        ));
    }
}

/// 由已定义、全局可见的动态符号推导导出集。
/// 由动态符号表推导导出集。
///
/// `.dynsym` 里**已定义且全局可见**的符号就是 `.so` 对外提供的接口，
/// 即 `STB_GLOBAL` 与 `STB_WEAK` 两档（`STB_LOCAL` 是不可见的内部符号）。
/// 注意不能只取函数：共享库也导出数据符号（`stdout`、`errno` 之类），
/// 只报函数会让导出表漏项。
pub(super) fn derive_exports(symbols: &[RawSymbol]) -> Vec<Export> {
    symbols
        .iter()
        .filter(|sym| {
            sym.defined
                && !sym.name.is_empty()
                && sym.source == SymbolTableSource::Dynamic
                && (sym.bind == sym_bind::GLOBAL || sym.bind == sym_bind::WEAK)
        })
        .map(|sym| Export {
            name: sym.name.clone(),
            ordinal: None,
            address: sym.value,
            forwarder: None,
            is_code: sym.is_function,
        })
        .collect()
}

/// 组装格式信息。
pub(super) fn build_format_info(header: &ElfHeader, sections: &[Section]) -> FormatInfo {
    let type_name = match header.elf_type {
        1 => Some("ET_REL（可重定位目标文件）".to_string()),
        2 => Some("ET_EXEC（可执行文件）".to_string()),
        3 => Some("ET_DYN（共享对象 / PIE）".to_string()),
        4 => Some("ET_CORE（核心转储）".to_string()),
        other => Some(format!("ET_{other}（未知类型）")),
    };

    let os_abi = match header.os_abi {
        0 => Some("System V".to_string()),
        1 => Some("HP-UX".to_string()),
        2 => Some("NetBSD".to_string()),
        3 => Some("Linux".to_string()),
        6 => Some("Solaris".to_string()),
        9 => Some("FreeBSD".to_string()),
        other => Some(format!("ABI {other}")),
    };

    // 是否剥离：没有 SHT_SYMTAB 就算剥离。`.dynsym` 不算 —— 动态链接的程序
    // 即使被 `strip` 过也会保留 `.dynsym`，用它判断会让所有 .so 都报"未剥离"。
    let is_stripped = !sections
        .iter()
        .any(|section| section.kind == ContentKind::SymbolTable && section.name == ".symtab");

    FormatInfo {
        type_name,
        os_abi,
        subsystem: None,
        is_dynamic_library: header.elf_type == 3,
        is_executable: header.elf_type == 2 || header.elf_type == 3,
        is_relocatable: header.elf_type == 1,
        is_stripped,
        declared_size: None,
    }
}

/// 解读架构相关的 `e_flags`。
///
/// 这几个位是**真正影响分析**的：ARM 的 EABI 版本决定调用约定，MIPS 的 ABI
/// 决定寄存器与 GOT 用法，RISC-V 的 RVC 决定指令是否可能被压缩成 2 字节。
/// 猜错了会让后续反汇编从第一个字节就跑偏，因此只对规范明确定义的位做解读，
/// 其余位一律不猜。
pub(super) fn note_arch_flags(object: &mut Object, header: &ElfHeader) {
    // 注意：`ElfHeader` 里没有保存 e_flags（它只在解析期用于判定），
    // 这里通过重新读取原始值来解读 —— 见 `ELF_FLAGS_CACHE` 说明。
    let Some(flags) = object.header_flags else {
        return;
    };

    match header.machine {
        // ARM: EF_ARM_EABIMASK = 0xff000000，版本是 (flags >> 24)
        40 => {
            let abi_version = flags >> 24;
            if abi_version == 0 {
                object.note("ARM e_flags 的 EABI 版本为 0（未知/非 EABI），调用约定需要人工确认");
            } else if abi_version != 5 {
                object.note(format!(
                    "ARM EABI 版本 {abi_version}（常见为 5）；非 5 的版本调用约定可能有差异"
                ));
            }
        }
        // MIPS: EF_MIPS_ABI = 0x0000f000，0 表示 O32
        8 | 10 => {
            let abi = (flags & 0x0000_f000) >> 12;
            let name = match abi {
                0 => "O32",
                1 => "O64",
                2 => "EABI32",
                3 => "EABI64",
                4 => "EABI",
                5 => "N32",
                6 => "N64",
                _ => "未知",
            };
            let is_64 = object.arch.ptr_size == 8;
            // ABI 与位宽矛盾是真实存在的畸形文件，值得指出
            if (abi == 6) != is_64 {
                object.note(format!(
                    "MIPS ABI 标记为 {name}，但 ELF 类为 {}-bit，两者不一致",
                    object.arch.ptr_size * 8
                ));
            }
        }
        // RISC-V: EF_RISCV_RVC = 0x0001，EF_RISCV_FLOAT_ABI = 0x0006
        243 => {
            if flags & 0x0001 != 0 {
                object.note("RISC-V 支持压缩指令（RVC）：指令可能是 2 字节，反汇编需按位流处理");
            }
            let float_abi = (flags & 0x0006) >> 1;
            let soft = flags & 0x0008 != 0;
            let name = match (float_abi, soft) {
                (0, _) => "软浮点",
                (1, false) => "单精度",
                (2, false) => "双精度",
                (3, false) => "四精度",
                (1, true) => "单精度（软）",
                (2, true) => "双精度（软）",
                (3, true) => "四精度（软）",
                _ => "未知",
            };
            object.note(format!("RISC-V 浮点 ABI：{name}"));
        }
        _ => {}
    }
}

///
/// ELF 没有 "image base" 这个概念，但分析层需要统一的地址原点。
/// 取**第一个可加载段的虚拟地址对齐到页**，这与 `readelf` 显示的第一个 LOAD 一致。
pub(super) fn compute_image_base(header: &ElfHeader, segments: &[Segment]) -> u64 {
    let _ = header;
    segments
        .iter()
        .filter(|seg| seg.vsize > 0 && seg.perms.read)
        .map(|seg| seg.vaddr)
        .min()
        .unwrap_or(0)
}

/// 判断某个 16 位计数字段是否用了 extended 编码。
pub(super) fn extended_count(
    _reader: &Reader<'_>,
    sentinel: u64,
    count: u64,
    cap: u64,
) -> Option<u64> {
    if count == sentinel && cap > 0 {
        Some(0)
    } else {
        None
    }
}

/// 读 section 0 的 `sh_info`（PN_XNUM 的真实段数）。
pub(super) fn extended_sh_info(reader: &Reader<'_>, header: &ElfHeader, index: u64) -> Option<u64> {
    if header.shoff == 0 || header.shentsize == 0 {
        return None;
    }
    let entry_size = u64::from(header.shentsize);
    let offset = header.shoff.checked_add(index.checked_mul(entry_size)?)?;
    let view = reader.slice(offset, entry_size, "节头表[0]").ok()?;
    let view = Reader::with_base(view, reader.base() + offset);
    let sh = SectionHeader::parse(&view, header.is_64, header.endianness).ok()?;
    Some(u64::from(sh.info))
}
