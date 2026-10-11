//! ELF32/ELF64 解析（`docs/PLAN.md` M1）。
//!
//! 覆盖：文件头、段表（`PT_LOAD` / `PT_DYNAMIC`）、节表（含 extended `shnum`）、
//! `.symtab` / `.dynsym`、入口、`DT_NEEDED` 依赖、`PT_GNU_STACK` 的可执行栈标志。
//!
//! # 这个模块里有什么
//!
//! | 文件 | 负责 |
//! |------|------|
//! | `mod`（本文件） | **磁盘上的布局**：常量、`sh_type`/`p_type` 等取值、三个头部结构体及取值方法 |
//! | `parse` | **编排**：唯一入口 [`parse`]，按"段 → 节 → 符号 → 重定位 → 动态 → 展开"顺序调用 |
//! | `sym` | 符号表、重定位表、重定位类型分类 |
//! | `dynamic` | `.eh_frame` 的 FDE 扫描、`PT_DYNAMIC` 依赖、导出推导 |
//! | `tests` | 单元测试 |
//!
//! 拆分的理由是**读的时候在解决什么问题**：本文件回答"这个字段在第几个字节、
//! 取值是什么意思"，而这些问题的答案与"拿到字段之后怎么办"是两件事。
//! 拆之前它们在同一份 2114 行的文件里交替出现。
//!
//! 拆分只动位置，不动行为：每一块的函数体逐字节搬到新文件，靠"切片拼回来必须与
//! 原文逐字节相同"的断言保证（与 PE 的做法一致）。
//!
//! # 解析纪律（M1 验收标准 3：畸形输入不 panic、不 OOM）
//!
//! - 一律通过 [`Reader`] 读字节，越界返回 `ParseError`；
//! - 表项数量先做整体范围校验再逐项解析；
//! - 对**不可信的数量上限**做封顶（例如 `e_shnum` 声称有 40 亿个节），
//!   超出就明确记录 note 并跳过，而不是尝试分配。
//!
//! # 关于"什么不做"
//!
//! `.eh_frame` 的解析**只解函数边界（FDE），不解 CFI 指令** —— 栈回溯才需要后者。
//! 因此本模块不会假装解出了 `unwind` 的完整语义，这一点在 `notes` 里说清楚。

use crate::object::Perms;
use crate::reader::{Endianness, ParseError, Reader};
use bitflip_arch::Endian;

mod dynamic;
mod parse;
mod sym;

#[cfg(test)]
mod tests;

/// ELF 的入口。
///
/// `pub` 而不是 `pub(crate)`：`tests/reloc_sections.rs` 直接调它做真实产物验证
/// （走集成测试的外部视角，能发现"只有单元测试编得过"这类问题）。其余各项保持
/// `pub(crate)` —— 拆分的目的是让**文件**各管一件事，不是让这个模块的公开面变大。
pub use parse::parse;

pub(crate) const EHDR32_SIZE: u64 = 52;
/// ELF 文件头大小（64 位）。
pub(crate) const EHDR64_SIZE: u64 = 64;
/// 节头表项大小（32 位）。
pub(crate) const SHDR32_SIZE: u64 = 40;
/// 节头表项大小（64 位）。
pub(crate) const SHDR64_SIZE: u64 = 64;
/// 程序头表项大小（32 位）。
pub(crate) const PHDR32_SIZE: u64 = 32;
/// 程序头表项大小（64 位）。
pub(crate) const PHDR64_SIZE: u64 = 56;

/// 节头表项数量的上限。
///
/// 真实二进制不会超过这个量级（最大的是调试信息密集的产物，几千个）。
/// 这个封顶是"不 OOM"的关键：`e_shnum` 是 16 位字段但可以通过 extended
/// `sh_size` 变成任意 64 位值，攻击者可以声称有 2^60 个节。
pub(crate) const MAX_SECTIONS: u64 = 65_536;

/// 段表项数量上限。`e_phnum` 只有 16 位，这个值不会被突破，留作对称防御。
pub(crate) const MAX_SEGMENTS: u64 = 65_536;

/// 符号表项数量上限。
pub(crate) const MAX_SYMBOLS: u64 = 4_000_000;

/// 重定位表项数量上限。
pub(crate) const MAX_RELOCS: u64 = 4_000_000;

/// 单个字符串表的最大读取长度（防御恶意 `sh_size`）。
pub(crate) const MAX_STRTAB: u64 = 64 * 1024 * 1024;

/// ELF 特有的节类型（`sh_type`）。
///
/// 省略 `SHT_NULL = 0` 与 `STB_LOCAL = 0` 这类"值为 0"的常量：
/// 在 `match` 里用 `const` 模式匹配 0 会与通配分支冲突（rustc 会判定未使用），
/// 直接写 `0` 加注释更清楚。
pub(crate) mod sh_type {
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
pub(crate) mod p_type {
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
pub(crate) mod sym_bind {
    pub const GLOBAL: u8 = 1;
    pub const WEAK: u8 = 2;
}

/// 节标志位（`sh_flags`）。
pub(crate) mod sh_flags {
    /// 运行期可写。
    pub const WRITE: u64 = 0x1;
    /// 参与地址空间映射（决定权限与"是否是运行期数据"）。
    pub const ALLOC: u64 = 0x2;
    /// 含可执行指令。
    pub const EXECINSTR: u64 = 0x4;
}

/// 符号类型（`st_info` 低 4 位）。
pub(crate) mod sym_type {
    pub const FUNC: u8 = 2;
    pub const SECTION: u8 = 3;
    pub const FILE: u8 = 4;
    pub const TLS: u8 = 6;
}

/// 解析好的 ELF 文件头（内部使用）。
pub(crate) struct ElfHeader {
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
pub(crate) struct SectionHeader {
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
pub(crate) struct ProgramHeader {
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
