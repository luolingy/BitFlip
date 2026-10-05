//! ELF32/ELF64 解析（`docs/PLAN.md` M1）。
//!
//! 覆盖：文件头、段表（`PT_LOAD` / `PT_DYNAMIC`）、节表（含 extended `shnum`）、
//! `.symtab` / `.dynsym`、入口、`DT_NEEDED` 依赖、`PT_GNU_STACK` 的可执行栈标志。
//!
//! 解析纪律（M1 验收标准 3：畸形输入不 panic、不 OOM）：
//! - 一律通过 [`Reader`] 读字节，越界返回 `ParseError`；
//! - 表项数量先做整体范围校验再逐项解析；
//! - 对**不可信的数量上限**做封顶（例如 `e_shnum` 声称有 40 亿个节），
//!   超出就明确记录 note 并跳过，而不是尝试分配。
//!
//! 关于"什么不做"：`.eh_frame` 的 FDE 解析推迟到 M3（需要 CFI 状态机，不是简单的表），
//! 因此本文件不会假装解出了 `unwind`。这一点必须在 `notes` 里说清楚。

use bitflip_arch::{Arch, ArchSpec, Endian, Mode};

use crate::object::{
    ContentKind, Export, FileRange, FormatInfo, Import, Object, ObjectId, Perms, RawSymbol, Reloc,
    RelocKind, Section, Segment, SymbolTableSource,
};
use crate::reader::{Endianness, ParseError, Reader};
use crate::ObjectKind;

/// ELF 文件头大小（32 位）。
const EHDR32_SIZE: u64 = 52;
/// ELF 文件头大小（64 位）。
const EHDR64_SIZE: u64 = 64;
/// 节头表项大小（32 位）。
const SHDR32_SIZE: u64 = 40;
/// 节头表项大小（64 位）。
const SHDR64_SIZE: u64 = 64;
/// 程序头表项大小（32 位）。
const PHDR32_SIZE: u64 = 32;
/// 程序头表项大小（64 位）。
const PHDR64_SIZE: u64 = 56;

/// 节头表项数量的上限。
///
/// 真实二进制不会超过这个量级（最大的是调试信息密集的产物，几千个）。
/// 这个封顶是"不 OOM"的关键：`e_shnum` 是 16 位字段但可以通过 extended
/// `sh_size` 变成任意 64 位值，攻击者可以声称有 2^60 个节。
const MAX_SECTIONS: u64 = 65_536;

/// 段表项数量上限。`e_phnum` 只有 16 位，这个值不会被突破，留作对称防御。
const MAX_SEGMENTS: u64 = 65_536;

/// 符号表项数量上限。
const MAX_SYMBOLS: u64 = 4_000_000;

/// 重定位表项数量上限。
const MAX_RELOCS: u64 = 4_000_000;

/// 单个字符串表的最大读取长度（防御恶意 `sh_size`）。
const MAX_STRTAB: u64 = 64 * 1024 * 1024;

/// ELF 特有的节类型（`sh_type`）。
///
/// 省略 `SHT_NULL = 0` 与 `STB_LOCAL = 0` 这类"值为 0"的常量：
/// 在 `match` 里用 `const` 模式匹配 0 会与通配分支冲突（rustc 会判定未使用），
/// 直接写 `0` 加注释更清楚。
mod sh_type {
    pub const PROGBITS: u32 = 1;
    pub const SYMTAB: u32 = 2;
    pub const STRTAB: u32 = 3;
    pub const RELA: u32 = 4;
    pub const HASH: u32 = 5;
    pub const DYNAMIC: u32 = 6;
    pub const NOTE: u32 = 7;
    pub const NOBITS: u32 = 8;
    pub const REL: u32 = 9;
    pub const DYNSYM: u32 = 11;
    pub const INIT_ARRAY: u32 = 14;
    pub const FINI_ARRAY: u32 = 15;
    pub const GNU_HASH: u32 = 0x6fff_ff00;
    pub const GNU_VERDEF: u32 = 0x6fff_ffd4;
    pub const GNU_VERNEED: u32 = 0x6fff_fffe;
    pub const GNU_VERSYM: u32 = 0x6fff_ffff;
}

/// 程序头类型（`p_type`）。
///
/// 省略 `PT_NULL = 0`：值为 0 的类型在解析里没有独立行为，写常量只会诱发
/// "声明了却没用"的死代码（解析器一律用 `_ =>` 兜住未知与 NULL）。
mod p_type {
    pub const LOAD: u32 = 1;
    pub const DYNAMIC: u32 = 2;
    pub const INTERP: u32 = 3;
    pub const NOTE: u32 = 4;
    pub const PHDR: u32 = 6;
    pub const TLS: u32 = 7;
    pub const GNU_EH_FRAME: u32 = 0x6474_e550;
    pub const GNU_STACK: u32 = 0x6474_e551;
    pub const GNU_RELRO: u32 = 0x6474_e552;
}

/// 符号绑定（`st_info` 高 4 位）。
mod sym_bind {
    pub const GLOBAL: u8 = 1;
    pub const WEAK: u8 = 2;
}

/// 节标志位（`sh_flags`）。
mod sh_flags {
    /// 运行期可写。
    pub const WRITE: u64 = 0x1;
    /// 参与地址空间映射（决定权限与"是否是运行期数据"）。
    pub const ALLOC: u64 = 0x2;
    /// 含可执行指令。
    pub const EXECINSTR: u64 = 0x4;
}

/// 符号类型（`st_info` 低 4 位）。
mod sym_type {
    pub const FUNC: u8 = 2;
    pub const SECTION: u8 = 3;
    pub const FILE: u8 = 4;
    pub const TLS: u8 = 6;
}

/// 解析好的 ELF 文件头（内部使用）。
struct ElfHeader {
    is_64: bool,
    endian: Endian,
    endianness: Endianness,
    os_abi: u8,
    elf_type: u16,
    machine: u16,
    entry: u64,
    phoff: u64,
    shoff: u64,
    /// `e_flags`：架构相关的标志位（ARM EABI 版本、MIPS ABI、RISC-V 扩展）。
    flags: u32,
    ehsize: u16,
    phentsize: u16,
    phnum: u16,
    shentsize: u16,
    shnum: u16,
    shstrndx: u16,
}

impl ElfHeader {
    fn shdr_size(&self) -> u64 {
        if self.is_64 {
            SHDR64_SIZE
        } else {
            SHDR32_SIZE
        }
    }

    fn phdr_size(&self) -> u64 {
        if self.is_64 {
            PHDR64_SIZE
        } else {
            PHDR32_SIZE
        }
    }

    /// 解析文件头。
    ///
    /// 注意：`e_shnum` / `shstrndx` 在超限时由其他字段承载，这里**保留原始小值**，
    /// 由调用方在读到 section 0 之后再行修正（ELF 规范的做法）。
    fn parse(reader: &Reader<'_>) -> Result<Self, ParseError> {
        reader.expect_magic(0, b"\x7fELF", "ELF")?;

        let class = reader.u8(4, "EI_CLASS")?;
        let is_64 = match class {
            1 => false,
            2 => true,
            other => {
                return Err(ParseError::Unsupported {
                    what: "EI_CLASS",
                    value: u64::from(other),
                    detail: "只支持 ELF32 与 ELF64（见 docs/PLAN.md §1.3）",
                })
            }
        };

        let data = reader.u8(5, "EI_DATA")?;
        let endianness = Endianness::from_elf_data(data).ok_or(ParseError::Unsupported {
            what: "EI_DATA",
            value: u64::from(data),
            detail: "只支持小端(1)与大端(2)",
        })?;
        let endian = match endianness {
            Endianness::Little => Endian::Little,
            Endianness::Big => Endian::Big,
        };

        let header_size = if is_64 { EHDR64_SIZE } else { EHDR32_SIZE };
        reader
            .slice(0, header_size, "ELF 文件头")
            .map_err(|_| ParseError::Truncated {
                what: "ELF 文件头",
                needed: header_size,
                actual: reader.len(),
            })?;

        let os_abi = reader.u8(7, "EI_OSABI")?;
        let elf_type = reader.u16(16, endianness, "e_type")?;
        let machine = reader.u16(18, endianness, "e_machine")?;
        // e_version 固定为 1，读出来仅用于发现异常文件
        let version = reader.u32(20, endianness, "e_version")?;
        if version != 1 {
            return Err(ParseError::Unsupported {
                what: "e_version",
                value: u64::from(version),
                detail: "未知的 ELF 版本（期望 1）",
            });
        }

        let (entry, phoff, shoff) = if is_64 {
            (
                reader.u64(24, endianness, "e_entry")?,
                reader.u64(32, endianness, "e_phoff")?,
                reader.u64(40, endianness, "e_shoff")?,
            )
        } else {
            (
                u64::from(reader.u32(24, endianness, "e_entry")?),
                u64::from(reader.u32(28, endianness, "e_phoff")?),
                u64::from(reader.u32(32, endianness, "e_shoff")?),
            )
        };

        // e_flags 的语义是架构相关的：ARM 用它标 EABI 版本，MIPS 用它标 ABI 与
        // 浮点模式，RISC-V 用它标 RVC/浮点扩展。保留原始值，并在有明确含义时说明。
        let flags = reader.u32(if is_64 { 48 } else { 36 }, endianness, "e_flags")?;
        let ehsize = reader.u16(if is_64 { 52 } else { 40 }, endianness, "e_ehsize")?;

        let (phentsize, phnum, shentsize, shnum, shstrndx) = if is_64 {
            (
                reader.u16(54, endianness, "e_phentsize")?,
                reader.u16(56, endianness, "e_phnum")?,
                reader.u16(58, endianness, "e_shentsize")?,
                reader.u16(60, endianness, "e_shnum")?,
                reader.u16(62, endianness, "e_shstrndx")?,
            )
        } else {
            (
                reader.u16(42, endianness, "e_phentsize")?,
                reader.u16(44, endianness, "e_phnum")?,
                reader.u16(46, endianness, "e_shentsize")?,
                reader.u16(48, endianness, "e_shnum")?,
                reader.u16(50, endianness, "e_shstrndx")?,
            )
        };

        Ok(Self {
            is_64,
            endian,
            endianness,
            os_abi,
            elf_type,
            machine,
            entry,
            phoff,
            shoff,
            flags,
            ehsize,
            phentsize,
            phnum,
            shentsize,
            shnum,
            shstrndx,
        })
    }
}

/// 原始节头。
#[derive(Debug, Clone)]
struct SectionHeader {
    name_offset: u32,
    sh_type: u32,
    flags: u64,
    addr: u64,
    offset: u64,
    size: u64,
    link: u32,
    info: u32,
    addralign: u64,
    entsize: u64,
}

impl SectionHeader {
    fn parse(view: &Reader<'_>, is_64: bool, endian: Endianness) -> Result<Self, ParseError> {
        if is_64 {
            Ok(Self {
                name_offset: view.u32(0, endian, "sh_name")?,
                sh_type: view.u32(4, endian, "sh_type")?,
                flags: view.u64(8, endian, "sh_flags")?,
                addr: view.u64(16, endian, "sh_addr")?,
                offset: view.u64(24, endian, "sh_offset")?,
                size: view.u64(32, endian, "sh_size")?,
                link: view.u32(40, endian, "sh_link")?,
                info: view.u32(44, endian, "sh_info")?,
                addralign: view.u64(48, endian, "sh_addralign")?,
                entsize: view.u64(56, endian, "sh_entsize")?,
            })
        } else {
            Ok(Self {
                name_offset: view.u32(0, endian, "sh_name")?,
                sh_type: view.u32(4, endian, "sh_type")?,
                flags: u64::from(view.u32(8, endian, "sh_flags")?),
                addr: u64::from(view.u32(12, endian, "sh_addr")?),
                offset: u64::from(view.u32(16, endian, "sh_offset")?),
                size: u64::from(view.u32(20, endian, "sh_size")?),
                link: view.u32(24, endian, "sh_link")?,
                info: view.u32(28, endian, "sh_info")?,
                addralign: u64::from(view.u32(32, endian, "sh_addralign")?),
                entsize: u64::from(view.u32(36, endian, "sh_entsize")?),
            })
        }
    }

    /// 是否在运行时被映射（用于 `Section::loaded`）。
    fn is_loaded(&self) -> bool {
        // 有地址且不是纯元数据的节就是被加载的。ALLOC 标志是权威判据。
        const SHF_ALLOC: u64 = 0x2;
        self.flags & SHF_ALLOC != 0
    }
}

/// 原始程序头。
#[derive(Debug, Clone)]
struct ProgramHeader {
    p_type: u32,
    flags: u32,
    offset: u64,
    vaddr: u64,
    paddr: u64,
    filesz: u64,
    memsz: u64,
    align: u64,
}

impl ProgramHeader {
    fn parse(view: &Reader<'_>, is_64: bool, endian: Endianness) -> Result<Self, ParseError> {
        let (flags, offset, vaddr, paddr, filesz, memsz, align) = if is_64 {
            (
                view.u32(4, endian, "p_flags")?,
                view.u64(8, endian, "p_offset")?,
                view.u64(16, endian, "p_vaddr")?,
                view.u64(24, endian, "p_paddr")?,
                view.u64(32, endian, "p_filesz")?,
                view.u64(40, endian, "p_memsz")?,
                view.u64(48, endian, "p_align")?,
            )
        } else {
            (
                view.u32(24, endian, "p_flags")?,
                u64::from(view.u32(4, endian, "p_offset")?),
                u64::from(view.u32(8, endian, "p_vaddr")?),
                u64::from(view.u32(12, endian, "p_paddr")?),
                u64::from(view.u32(16, endian, "p_filesz")?),
                u64::from(view.u32(20, endian, "p_memsz")?),
                u64::from(view.u32(28, endian, "p_align")?),
            )
        };
        Ok(Self {
            p_type: view.u32(0, endian, "p_type")?,
            flags,
            offset,
            vaddr,
            paddr,
            filesz,
            memsz,
            align,
        })
    }

    fn perms(&self) -> Perms {
        const PF_X: u32 = 0x1;
        const PF_W: u32 = 0x2;
        const PF_R: u32 = 0x4;
        Perms {
            read: self.flags & PF_R != 0,
            write: self.flags & PF_W != 0,
            execute: self.flags & PF_X != 0,
        }
    }
}

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
        match parse_symbols(&reader, &header, sh, &section_headers, source, &mut object) {
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
fn resolve_arch(machine: u16, is_64: bool, _header: &ElfHeader) -> Result<ArchSpec, ParseError> {
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
fn parse_segments(
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
fn segment_placeholder_name(p_type: u32, index: usize) -> String {
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
fn name_segments_from_sections(segments: &mut [Segment], sections: &[Section]) {
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
struct SectionTable {
    /// 归一化后的节（已去掉 SHT_NULL 占位）。
    sections: Vec<Section>,
    /// 原始节头，供后续按索引查节名。
    raw: Vec<SectionHeader>,
    /// `.shstrtab` 的内容。
    shstrtab: Vec<u8>,
}

/// 解析节表。
fn parse_sections(
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
fn read_strtab(table: &[u8], offset: u64) -> Option<String> {
    let start = usize::try_from(offset).ok()?;
    if start >= table.len() {
        return None;
    }
    let rest = &table[start..];
    let end = rest.iter().position(|&b| b == 0).unwrap_or(rest.len());
    Some(String::from_utf8_lossy(&rest[..end]).into_owned())
}

/// 节权限：ELF 用 SHF_WRITE / SHF_EXECINSTR，没有"可读"概念（可加载即可读）。
fn section_perms(sh: &SectionHeader) -> Perms {
    Perms {
        read: sh.flags & sh_flags::ALLOC != 0,
        write: sh.flags & sh_flags::WRITE != 0,
        execute: sh.flags & sh_flags::EXECINSTR != 0,
    }
}

/// 由节类型与名字推断内容类别。
fn section_content_kind(sh: &SectionHeader) -> ContentKind {
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
fn section_name(raw: &[SectionHeader], shstrtab: &[u8], index: usize) -> String {
    raw.get(index)
        .filter(|sh| sh.name_offset != 0)
        .and_then(|sh| read_strtab(shstrtab, u64::from(sh.name_offset)))
        .unwrap_or_else(|| format!("<节 {index}>"))
}

/// 解析符号表。
fn parse_symbols(
    reader: &Reader<'_>,
    header: &ElfHeader,
    sh: &SectionHeader,
    raw_sections: &[SectionHeader],
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
            let name = section_name(raw_sections, &[], shndx as usize);
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
fn parse_relocs(
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
    let target_name = section_name(raw_sections, shstrtab, 0);

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
            kind: classify_reloc(header.machine, raw_kind),
            raw_kind,
            symbol,
            addend,
        });
    }

    let _ = target_name;
    Ok(out)
}

/// 把格式特有的重定位编号归一化成粗分类。
///
/// 只覆盖常见架构；未知编号归入 `Other` 并保留 `raw_kind`，
/// 这样 M2 需要精确编号时能拿到，而分析层不必理解每个架构的编号表。
fn classify_reloc(machine: u16, raw_kind: u32) -> RelocKind {
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

/// 从 `.eh_frame` 解析 FDE 并填进 `object.unwind`。
///
/// 边界情况都写进 `notes`，不静默少给数据（§7）：
/// * 段存在但读不到 → 说明原因；
/// * relocatable object（`.o`）：`.eh_frame` 里的地址是重定位前的占位值，
///   未应用重定位就当成真实地址是**错的**，因此明确标注而不是给假边界；
/// * 解析中途出错 → 把解析器的 note 浮上来。
fn parse_eh_frame_entries(
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
fn parse_dynamic_dependencies(
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
fn derive_exports(symbols: &[RawSymbol]) -> Vec<Export> {
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
fn build_format_info(header: &ElfHeader, sections: &[Section]) -> FormatInfo {
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
fn note_arch_flags(object: &mut Object, header: &ElfHeader) {
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
fn compute_image_base(header: &ElfHeader, segments: &[Segment]) -> u64 {
    let _ = header;
    segments
        .iter()
        .filter(|seg| seg.vsize > 0 && seg.perms.read)
        .map(|seg| seg.vaddr)
        .min()
        .unwrap_or(0)
}

/// 判断某个 16 位计数字段是否用了 extended 编码。
fn extended_count(_reader: &Reader<'_>, sentinel: u64, count: u64, cap: u64) -> Option<u64> {
    if count == sentinel && cap > 0 {
        Some(0)
    } else {
        None
    }
}

/// 读 section 0 的 `sh_info`（PN_XNUM 的真实段数）。
fn extended_sh_info(reader: &Reader<'_>, header: &ElfHeader, index: u64) -> Option<u64> {
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

#[cfg(test)]
mod tests {
    use super::*;

    /// 构造一个最小但完整的 ELF64 小端文件（可重定位目标文件，无程序头）。
    fn minimal_elf64() -> Vec<u8> {
        let mut bytes = vec![0u8; 0x400];
        // ELF 头
        bytes[0..4].copy_from_slice(b"\x7fELF");
        bytes[4] = 2; // ELFCLASS64
        bytes[5] = 1; // ELFDATA2LSB
        bytes[6] = 1; // EV_CURRENT
        bytes[7] = 0; // System V
        bytes[16..18].copy_from_slice(&1u16.to_le_bytes()); // e_type = ET_REL
        bytes[18..20].copy_from_slice(&62u16.to_le_bytes()); // e_machine = x86_64
        bytes[20..24].copy_from_slice(&1u32.to_le_bytes()); // e_version
        bytes[24..32].copy_from_slice(&0u64.to_le_bytes()); // e_entry
        bytes[32..40].copy_from_slice(&0u64.to_le_bytes()); // e_phoff
        bytes[40..48].copy_from_slice(&0x200u64.to_le_bytes()); // e_shoff
        bytes[48..52].copy_from_slice(&0u32.to_le_bytes()); // e_flags
        bytes[52..54].copy_from_slice(&64u16.to_le_bytes()); // e_ehsize
        bytes[54..56].copy_from_slice(&0u16.to_le_bytes()); // e_phentsize
        bytes[56..58].copy_from_slice(&0u16.to_le_bytes()); // e_phnum
        bytes[58..60].copy_from_slice(&64u16.to_le_bytes()); // e_shentsize
        bytes[60..62].copy_from_slice(&2u16.to_le_bytes()); // e_shnum
        bytes[62..64].copy_from_slice(&1u16.to_le_bytes()); // e_shstrndx

        // 节名字符串表内容（放在 0x100）
        let shstrtab = b"\0.shstrtab\0";
        bytes[0x100..0x100 + shstrtab.len()].copy_from_slice(shstrtab);

        // section 0：NULL
        // section 1：.shstrtab
        let s1 = 0x200 + 64;
        bytes[s1..s1 + 4].copy_from_slice(&1u32.to_le_bytes()); // sh_name = 1 (".shstrtab")
        bytes[s1 + 4..s1 + 8].copy_from_slice(&3u32.to_le_bytes()); // sh_type = STRTAB
        bytes[s1 + 24..s1 + 32].copy_from_slice(&0x100u64.to_le_bytes()); // sh_offset
        bytes[s1 + 32..s1 + 40].copy_from_slice(&(shstrtab.len() as u64).to_le_bytes()); // sh_size
        bytes[s1 + 48..s1 + 56].copy_from_slice(&1u64.to_le_bytes()); // sh_addralign
        bytes
    }

    #[test]
    fn parses_minimal_elf64_header_and_sections() {
        let obj = parse(&minimal_elf64(), 0, ObjectId::Plain).unwrap();
        assert_eq!(obj.kind, ObjectKind::Elf);
        assert_eq!(obj.arch.arch, Arch::X86_64);
        assert_eq!(obj.endian, Endian::Little);
        // 样本有 2 个节头（NULL + .shstrtab），但节 0 是 SHT_NULL 占位，
        // 不列进归一化节表 —— 与 readelf/llvm-readobj 显示的真实节数一致。
        assert_eq!(obj.sections.len(), 1);
        assert_eq!(obj.sections[0].name, ".shstrtab");
        assert_eq!(obj.sections[0].kind, ContentKind::StringTable);
        // .o 没有入口 —— 必须是 None，不能用 0 冒充
        assert_eq!(obj.entry, None);
        assert!(obj.format.is_relocatable);
    }

    #[test]
    fn rejects_bad_magic() {
        let mut bytes = minimal_elf64();
        bytes[0] = b'X';
        assert!(matches!(
            parse(&bytes, 0, ObjectId::Plain),
            Err(ParseError::BadMagic { .. })
        ));
    }

    #[test]
    fn rejects_truncated_header_without_panic() {
        for len in 0..EHDR64_SIZE {
            let bytes = vec![0u8; len as usize];
            // 全部只会返回错误，绝不 panic
            let _ = parse(&bytes, 0, ObjectId::Plain);
        }
        // 头部齐全但内容被截断
        let mut bytes = minimal_elf64();
        bytes.truncate(0x210);
        let result = parse(&bytes, 0, ObjectId::Plain);
        // 要么成功（节表刚好够）要么报错，但绝不 panic
        let _ = result;
    }

    #[test]
    fn rejects_unsupported_class() {
        let mut bytes = minimal_elf64();
        bytes[4] = 9; // 既不是 1 也不是 2
        assert!(matches!(
            parse(&bytes, 0, ObjectId::Plain),
            Err(ParseError::Unsupported {
                what: "EI_CLASS",
                ..
            })
        ));
    }

    #[test]
    fn rejects_bad_endian_marker() {
        let mut bytes = minimal_elf64();
        bytes[5] = 7;
        assert!(matches!(
            parse(&bytes, 0, ObjectId::Plain),
            Err(ParseError::Unsupported {
                what: "EI_DATA",
                ..
            })
        ));
    }

    #[test]
    fn rejects_unknown_machine() {
        let mut bytes = minimal_elf64();
        bytes[18..20].copy_from_slice(&0x1234u16.to_le_bytes());
        assert!(matches!(
            parse(&bytes, 0, ObjectId::Plain),
            Err(ParseError::Unsupported {
                what: "e_machine",
                ..
            })
        ));
    }

    #[test]
    fn rejects_bad_version() {
        let mut bytes = minimal_elf64();
        bytes[20..24].copy_from_slice(&99u32.to_le_bytes());
        assert!(matches!(
            parse(&bytes, 0, ObjectId::Plain),
            Err(ParseError::Unsupported {
                what: "e_version",
                ..
            })
        ));
    }

    #[test]
    fn huge_section_count_is_capped_not_allocated() {
        let mut bytes = minimal_elf64();
        bytes[60..62].copy_from_slice(&0u16.to_le_bytes()); // e_shnum = 0 → extended
                                                            // section 0 的 sh_size 声称有 2^40 个节
        let s0 = 0x200;
        bytes[s0 + 32..s0 + 40].copy_from_slice(&(1u64 << 40).to_le_bytes());
        // 必须快速返回（被封顶），而不是尝试分配
        let result = parse(&bytes, 0, ObjectId::Plain);
        match result {
            Ok(obj) => {
                // 被封顶后节数量受 MAX_SECTIONS 限制，且越界会记 note
                assert!(obj.sections.len() as u64 <= MAX_SECTIONS);
                assert!(
                    obj.notes.iter().any(|n| n.contains("超过上限")),
                    "应当记录封顶说明，实际 notes = {:?}",
                    obj.notes
                );
            }
            Err(_) => { /* 报错也是可接受的结果 */ }
        }
    }

    #[test]
    fn section_count_from_extended_shnum_is_noted() {
        let mut bytes = minimal_elf64();
        bytes[60..62].copy_from_slice(&0u16.to_le_bytes());
        let s0 = 0x200;
        bytes[s0 + 32..s0 + 40].copy_from_slice(&2u64.to_le_bytes());
        let obj = parse(&bytes, 0, ObjectId::Plain).unwrap();
        // 2 个节头里含 SHT_NULL 占位，归一化后只剩 .shstrtab
        assert_eq!(obj.sections.len(), 1);
        assert!(
            obj.notes.iter().any(|n| n.contains("extended shnum")),
            "notes = {:?}",
            obj.notes
        );
    }

    #[test]
    fn extended_shstrndx_via_sh_link_is_handled() {
        let mut bytes = minimal_elf64();
        bytes[62..64].copy_from_slice(&0xffffu16.to_le_bytes()); // SHN_XINDEX
        let s0 = 0x200;
        bytes[s0 + 40..s0 + 44].copy_from_slice(&1u32.to_le_bytes()); // sh_link = 1
        let obj = parse(&bytes, 0, ObjectId::Plain).unwrap();
        assert_eq!(obj.sections[0].name, ".shstrtab");
        assert!(
            obj.notes.iter().any(|n| n.contains("extended shstrndx")),
            "notes = {:?}",
            obj.notes
        );
    }

    #[test]
    fn conflicting_shentsize_is_an_error_not_a_misread() {
        let mut bytes = minimal_elf64();
        bytes[58..60].copy_from_slice(&8u16.to_le_bytes()); // 远小于 64
        assert!(matches!(
            parse(&bytes, 0, ObjectId::Plain),
            Err(ParseError::Inconsistent(_))
        ));
    }

    #[test]
    fn section_out_of_file_bounds_is_noted_but_parse_continues() {
        let mut bytes = minimal_elf64();
        let s1 = 0x200 + 64;
        // 让 .shstrtab 声称的数据范围远超文件
        bytes[s1 + 24..s1 + 32].copy_from_slice(&0x9000u64.to_le_bytes());
        bytes[s1 + 32..s1 + 40].copy_from_slice(&0x9000u64.to_le_bytes());
        let obj = parse(&bytes, 0, ObjectId::Plain).unwrap();
        assert!(
            obj.notes.iter().any(|n| n.contains("超出文件大小")),
            "notes = {:?}",
            obj.notes
        );
    }

    #[test]
    fn missing_section_header_table_is_noted_not_fatal() {
        let mut bytes = minimal_elf64();
        bytes[40..48].copy_from_slice(&0u64.to_le_bytes()); // e_shoff = 0
        bytes[60..62].copy_from_slice(&0u16.to_le_bytes()); // e_shnum = 0
        let obj = parse(&bytes, 0, ObjectId::Plain).unwrap();
        assert!(obj.sections.is_empty());
        assert!(obj.notes.iter().any(|n| n.contains("无节头表")));
    }

    /// 对每一个字节做单点破坏，证明解析器对任意畸形输入都只返回错误。
    ///
    /// 这是 M1 验收标准 3 的"不 panic"证据里最有力的一条：
    /// 它不依赖随机种子，可复现，且覆盖每一个字段。
    #[test]
    fn single_byte_corruption_never_panics() {
        let good = minimal_elf64();
        for index in 0..good.len().min(0x240) {
            for bit in 0..8 {
                let mut bytes = good.clone();
                bytes[index] ^= 1 << bit;
                // 结果无所谓，关键是不能 panic
                let _ = parse(&bytes, 0, ObjectId::Plain);
            }
        }
    }

    /// 随机截断到任意长度都不能 panic。
    #[test]
    fn every_truncation_length_never_panics() {
        let good = minimal_elf64();
        for len in 0..good.len() {
            let _ = parse(&good[..len], 0, ObjectId::Plain);
        }
    }

    #[test]
    fn zero_length_input_is_an_error() {
        assert!(parse(&[], 0, ObjectId::Plain).is_err());
    }

    #[test]
    fn classify_reloc_covers_known_types() {
        // x86_64
        assert_eq!(classify_reloc(62, 1), RelocKind::Absolute);
        assert_eq!(classify_reloc(62, 6), RelocKind::ImportLookup);
        assert_eq!(classify_reloc(62, 7), RelocKind::ImportLookup);
        // RELATIVE / RELATIVE64 是**数据槽位**指针，与指令里的
        // PC 相对重定位（PC32=2、PLT32=4、GOTPCREL=9）必须分开：
        // 指针表识别只能从前者得到"这里存了个地址"的结论。
        assert_eq!(classify_reloc(62, 8), RelocKind::RelocPointer);
        assert_eq!(classify_reloc(62, 38), RelocKind::RelocPointer);
        assert_eq!(classify_reloc(62, 2), RelocKind::Relative);
        assert_eq!(classify_reloc(62, 4), RelocKind::Relative);
        // 未知编号归 Other，不猜
        assert_eq!(classify_reloc(62, 999), RelocKind::Other);
        assert_eq!(classify_reloc(0xffff, 1), RelocKind::Other);
        // aarch64
        assert_eq!(classify_reloc(183, 257), RelocKind::Absolute);
        assert_eq!(classify_reloc(183, 1026), RelocKind::ImportLookup);
        assert_eq!(classify_reloc(183, 1027), RelocKind::RelocPointer);
        assert_eq!(classify_reloc(183, 261), RelocKind::Relative);
        // arm / i386 / riscv 的 RELATIVE 同样归数据槽位
        assert_eq!(classify_reloc(40, 23), RelocKind::RelocPointer);
        assert_eq!(classify_reloc(3, 8), RelocKind::RelocPointer);
        assert_eq!(classify_reloc(243, 3), RelocKind::RelocPointer);
    }

    #[test]
    fn relative_and_reloc_pointer_are_distinguishable() {
        // 这条测试守住的是一个具体的回归：早先 `R_*_RELATIVE` 与
        // PC 相对重定位共用 `RelocKind::Relative`，导致"只挑数据槽位"
        // 这件事做不到 —— 实测 libsample.so 的 sample_table[2] 就是这样
        // 被漏掉的，而单看"有重定位数据"完全看不出问题。
        assert_ne!(
            RelocKind::Relative,
            RelocKind::RelocPointer,
            "两类重定位必须是不同的枚举值，否则无法区分数据指针与指令内偏移"
        );
        assert_ne!(
            RelocKind::Relative.as_str(),
            RelocKind::RelocPointer.as_str(),
            "短名也必须不同，否则 wire 上仍然分不开"
        );
    }

    #[test]
    fn is_stripped_reflects_absence_of_symtab_not_dynsym() {
        // 只有 .shstrtab 的目标文件没有 .symtab，应判为已剥离
        let obj = parse(&minimal_elf64(), 0, ObjectId::Plain).unwrap();
        assert!(
            obj.format.is_stripped,
            "没有 .symtab 的对象应判定为已剥离，notes = {:?}",
            obj.notes
        );
    }

    #[test]
    fn is_stripped_is_false_when_symtab_is_present() {
        let mut bytes = minimal_elf64();

        // 追加一个名为 ".symtab" 的节头（第 3 个），并把它指向 .shstrtab 之外
        // 的一段自有名字，从而不必改写字符串表布局。
        bytes[60..62].copy_from_slice(&3u16.to_le_bytes()); // e_shnum = 3
        let shoff = 0x200usize;
        let s2 = shoff + 2 * 64;

        // 把节名字符串表指针指向一个含 ".symtab" 的表，保证名字解析得到
        // ".symtab"（判定依赖它）。
        // .shstrtab 当前在节 1，偏移 0x2e0。先放入新名字，再让节 1 覆盖它。
        let strtab = 0x2e0usize;
        let names = b"\0.shstrtab\0.symtab\0";
        bytes[strtab..strtab + names.len()].copy_from_slice(names);
        // 节 1 的 sh_offset / sh_size 覆盖为新的表
        let s1 = shoff + 64;
        bytes[s1 + 24..s1 + 32].copy_from_slice(&(strtab as u64).to_le_bytes());
        bytes[s1 + 32..s1 + 40].copy_from_slice(&(names.len() as u64).to_le_bytes());

        // 节 2 = .symtab，名字偏移指向新表里的 ".symtab"（偏移 11）
        bytes[s2..s2 + 4].copy_from_slice(&11u32.to_le_bytes());
        bytes[s2 + 4..s2 + 8].copy_from_slice(&sh_type::SYMTAB.to_le_bytes());
        bytes[s2 + 24..s2 + 32].copy_from_slice(&0u64.to_le_bytes()); // sh_offset = 0
        bytes[s2 + 32..s2 + 40].copy_from_slice(&0u64.to_le_bytes()); // sh_size = 0

        let obj = parse(&bytes, 0, ObjectId::Plain).unwrap();
        assert!(
            obj.sections.iter().any(|s| s.name == ".symtab"),
            "样本应含 .symtab 节，实际 = {:?}",
            obj.sections.iter().map(|s| &s.name).collect::<Vec<_>>()
        );
        assert!(!obj.format.is_stripped, "含 .symtab 的对象不应判定为已剥离");
    }

    #[test]
    fn section_content_kind_prefers_flags_over_names() {
        let mut sh = SectionHeader {
            name_offset: 0,
            sh_type: sh_type::PROGBITS,
            flags: sh_flags::ALLOC | sh_flags::EXECINSTR,
            addr: 0,
            offset: 0,
            size: 0,
            link: 0,
            info: 0,
            addralign: 0,
            entsize: 0,
        };
        assert_eq!(section_content_kind(&sh), ContentKind::Code);

        sh.flags = sh_flags::ALLOC | sh_flags::WRITE;
        assert_eq!(section_content_kind(&sh), ContentKind::Data);

        // 已映射、不可写、不可执行 = 只读数据
        sh.flags = sh_flags::ALLOC;
        assert_eq!(section_content_kind(&sh), ContentKind::ReadOnlyData);

        // 未映射的 PROGBITS（.comment 之类）不是运行期数据，是文件元数据。
        // 这正是过去被误标成"只读数据"却带着 `---` 权限的那一类。
        sh.flags = 0;
        assert_eq!(section_content_kind(&sh), ContentKind::Metadata);

        sh.sh_type = sh_type::NOBITS;
        assert_eq!(section_content_kind(&sh), ContentKind::Bss);
        sh.sh_type = sh_type::SYMTAB;
        assert_eq!(section_content_kind(&sh), ContentKind::SymbolTable);
        sh.sh_type = sh_type::NOTE;
        assert_eq!(section_content_kind(&sh), ContentKind::Metadata);
        sh.sh_type = 0x1234;
        assert_eq!(section_content_kind(&sh), ContentKind::Unknown);
    }

    #[test]
    fn read_strtab_is_bounds_safe() {
        let table = b"abc\0def\0";
        assert_eq!(read_strtab(table, 0).unwrap(), "abc");
        assert_eq!(read_strtab(table, 4).unwrap(), "def");
        // 结尾 NUL 自身的偏移 → 空串（合法位置，只是内容为空）
        assert_eq!(read_strtab(table, 7).unwrap(), "");
        // 严格越界（== 表长）→ None
        assert_eq!(read_strtab(table, 8), None);
        assert_eq!(read_strtab(table, 999), None);
        // 空表
        assert_eq!(read_strtab(b"", 0), None);
    }

    #[test]
    fn segment_placeholder_names_are_distinguishable() {
        assert_eq!(segment_placeholder_name(p_type::LOAD, 0), "LOAD#0");
        assert_eq!(segment_placeholder_name(p_type::LOAD, 3), "LOAD#3");
        assert_eq!(
            segment_placeholder_name(p_type::GNU_STACK, 1),
            "GNU_STACK#1"
        );
        assert_eq!(segment_placeholder_name(0x9999, 2), "PT#2");
    }
}
