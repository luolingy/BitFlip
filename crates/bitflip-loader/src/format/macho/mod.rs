//! Mach-O 结构层解析（`docs/PLAN.md` M12 **第一片**）。
//!
//! # 这一片覆盖什么
//!
//! | 结构 | 规范出处 | 状态 |
//! |------|---------|------|
//! | `mach_header` / `mach_header_64` | `mach-o/loader.h`（Apple XNU 的 `EXTERNAL_HEADERS`） | 全部字段 |
//! | `LC_SEGMENT` / `LC_SEGMENT_64` | 同上，`segment_command` / `segment_command_64` | 段 + 段内节 |
//! | `LC_MAIN` | 同上，`entry_point_command` | 入口点（**文件偏移** → 虚拟地址） |
//! | `LC_UNIXTHREAD` | 同上 `thread_command`；寄存器布局见 `mach/i386/thread_status.h`、`mach/arm/thread_status.h` | 解出 PC（四种架构），其余只记录存在性 |
//! | `LC_UUID` | 同上 `uuid_command` | 16 字节 → 小写十六进制 |
//! | `LC_LOAD_DYLIB` / `LC_LOAD_WEAK_DYLIB` | 同上 `dylib_command` | 依赖库名 |
//! | fat / universal | `mach-o/fat.h` | 见 [`fat`]：**容器层已实现**，但没接进会话（见下） |
//!
//! # 明确没做的（不要以为有）
//!
//! - **符号表**（`LC_SYMTAB` / `LC_DYSYMTAB`）：只记录"存在"这一个事实，
//!   [`Object::symbols`] 是**空**的，原因写在 `notes` 里。`LC_FUNCTION_STARTS`
//!   也没做，所以函数边界只能靠反汇编识别，没有权威来源。
//! - **dyld 绑定信息**（`LC_DYLD_INFO*` / `LC_DYLD_CHAINED_FIXUPS`）：没有解析，
//!   因此 [`Object::imports`] 是**空**的 —— 这是与 PE/ELF 的已知差距。
//! - **objc / swift 元数据**（`__objc_classname`、`__swift5_*` 等）：按普通节列出，
//!   不解析内容。
//! - **代码签名**（`LC_CODE_SIGNATURE`）：只记录存在性，**不做校验**。
//! - **`.app` bundle / IPA 容器语义**：`LoaderError::IsDirectory` 仍然是拒绝，
//!   IPA 的第二层（`Payload/*.app/`）也没有接进会话。
//!
//! # 几处判断，写在这里免得被当成 bug
//!
//! 1. **入口点换算。** `LC_MAIN.entryoff` 是**文件偏移**（相对文件开头），而对象模型
//!    与分析层要的是虚拟地址。换算方式：找文件范围 `[fileoff, fileoff+filesize)`
//!    覆盖它的段，用该段的 `(fileoff, vmaddr)` 做线性平移 —— 通常就是 `__TEXT`。
//!    换算式写进 `notes`（用户能核对）。**找不到覆盖它的段时入口点留 `None`**，不猜。
//! 2. **大端 Mach-O。** 结构层按文件端序读（[`Reader`] 两种端序都支持），所以
//!    `MH_CIGAM` / `MH_CIGAM_64` 不会被误读。但现实中大端 Mach-O 基本只有
//!    ppc/armeb，而 ppc 没有映射（见下），所以大端路径目前只在单测里走到。
//! 3. **ppc 明确拒绝。** `CPU_TYPE_POWERPC`（18）/ `ppc64`（`0x0100_0012`）能**识别**，
//!    但 `bitflip_arch::Arch` 没有 PowerPC 变体、也没有 ppc 解码后端。加一个
//!    **没有解码器**的架构变体会让分析层解出垃圾（CLAUDE.md §7），所以这里返回
//!    [`ParseError::Unsupported`] 并点名原因，而不是挑一个近似架构。
//! 4. **arm64e** 的 `cputype` 与 arm64 相同（`0x0100_000c`），区别只在
//!    `cpusubtype == 2`。架构按 AArch64 解码（指令层面这是对的），指针认证（PAC）
//!    语义不还原 —— 记进 `notes`。
//! 5. **`LC_UUID` / dylib 名不在 [`Object`] 里。** 对象模型没有对应字段，而把它们
//!    塞进 `notes` 会让程序化消费只能靠解析字符串。它们留在 [`MachOFile`] 里
//!    （[`read`] 的返回值）；要让 CLI / UI 显示，下一步需要给 `Object` 加字段。
//! 6. **fat 切片没接进容器抽象。** [`fat::read`] 能枚举切片（有测试），但
//!    `ContainerKind::Fat` 的成员化（把切片当成 `ArchiveMember` 走会话）是下一片。
//!    因此现在打开一个 fat 文件仍会报错，**不要**以为 fat 已经能用。
//!
//! # 解析纪律（与 PE/ELF 一致）
//!
//! 一律经 [`Reader`] 读字节，越界返回 `ParseError`；表项数量来自不可信输入
//! （`ncmds` / `sizeofcmds` / `nsects`），先整体校验范围再逐项解析，绝不先分配。
//! 能确定的就解析，不能确定的写进 `notes` —— 不猜、不留空白解释。

use std::fmt::Write as _;

use bitflip_arch::{Arch, ArchSpec, Endian};

use crate::object::{
    ContentKind, FileRange, FormatInfo, Object, ObjectId, Perms, Section, Segment,
};
use crate::reader::{Endianness, ParseError, Reader};
use crate::ObjectKind;

pub mod fat;

// ── 魔数（`mach-o/loader.h`） ───────────────────────────────────────────────
//
// 用法说明：下面四个常量是**按小端读文件头前 4 字节**得到的值。文件里的字节原样：
//
//   小端 32 位：CE FA ED FE → 按小端读 = 0xFEEDFACE（MH_MAGIC）
//   小端 64 位：CF FA ED FE → 按小端读 = 0xFEEDFACF（MH_MAGIC_64）
//   大端 32 位：FE ED FA CE → 按小端读 = 0xCEFAEDFE（MH_CIGAM）
//   大端 64 位：FE ED FA CF → 按小端读 = 0xCFFAEDFE（MH_CIGAM_64）

/// `MH_MAGIC`：32 位、小端文件。
pub const MH_MAGIC: u32 = 0xfeed_face;
/// `MH_MAGIC_64`：64 位、小端文件。
pub const MH_MAGIC_64: u32 = 0xfeed_facf;
/// `MH_CIGAM`：32 位、大端文件。
pub const MH_CIGAM: u32 = 0xcefa_edfe;
/// `MH_CIGAM_64`：64 位、大端文件。
pub const MH_CIGAM_64: u32 = 0xcffa_edfe;

// ── 头部尺寸 ────────────────────────────────────────────────────────────────

/// `sizeof(struct mach_header)`：7 个 `uint32`。
pub const HEADER32_SIZE: u64 = 28;
/// `sizeof(struct mach_header_64)`：8 个 `uint32`（多一个 `reserved`）。
pub const HEADER64_SIZE: u64 = 32;

// ── 加载命令（`mach-o/loader.h`） ──────────────────────────────────────────

/// `LC_SEGMENT`：32 位段命令（`segment_command`）。
pub const LC_SEGMENT: u32 = 0x1;
/// `LC_SYMTAB`：符号表。本片只记录存在性。
pub const LC_SYMTAB: u32 = 0x2;
/// `LC_UNIXTHREAD`：线程状态，老式可执行文件的入口点来源。
pub const LC_UNIXTHREAD: u32 = 0x5;
/// `LC_LOAD_DYLIB`：依赖的动态库。
pub const LC_LOAD_DYLIB: u32 = 0xc;
/// `LC_ID_DYLIB`：本镜像自己的 install name（"我是谁"，不是"我依赖谁"）。
pub const LC_ID_DYLIB: u32 = 0xd;
/// `LC_SEGMENT_64`：64 位段命令（`segment_command_64`）。
pub const LC_SEGMENT_64: u32 = 0x19;
/// `LC_UUID`。
pub const LC_UUID: u32 = 0x1b;
/// `LC_CODE_SIGNATURE`：代码签名数据的位置。**不做校验**。
pub const LC_CODE_SIGNATURE: u32 = 0x1d;
/// `LC_DYLD_INFO`。
pub const LC_DYLD_INFO: u32 = 0x22;
/// `LC_DYLD_INFO_ONLY`：带 `LC_REQ_DYLD` 位的 `LC_DYLD_INFO`。
pub const LC_DYLD_INFO_ONLY: u32 = 0x8000_0022;
/// `LC_LOAD_WEAK_DYLIB`：弱链接依赖。
pub const LC_LOAD_WEAK_DYLIB: u32 = 0x8000_0018;
/// `LC_MAIN`：主可执行文件的入口点（**文件偏移**）。
pub const LC_MAIN: u32 = 0x8000_0028;
/// `LC_DYLD_CHAINED_FIXUPS`：新版 dyld 的链式绑定信息。
pub const LC_DYLD_CHAINED_FIXUPS: u32 = 0x8000_0034;

/// `sizeof(struct segment_command)`（32 位，不含节）：8 + 16 + 8×4。
pub const SEGMENT_COMMAND32_SIZE: u64 = 56;
/// `sizeof(struct segment_command_64)`：8 + 16 + 8×4 + 4 + 4。
pub const SEGMENT_COMMAND64_SIZE: u64 = 72;
/// `sizeof(struct section)`（32 位）：16 + 16 + 4×9。
pub const SECTION32_SIZE: u64 = 68;
/// `sizeof(struct section_64)`：16 + 16 + 8 + 8 + 4×8。
pub const SECTION64_SIZE: u64 = 80;

/// `sizeof(struct entry_point_command)`：cmd + cmdsize + entryoff + stacksize。
pub const ENTRY_POINT_COMMAND_SIZE: u64 = 24;
/// `sizeof(struct uuid_command)`：cmd + cmdsize + uuid[16]。
pub const UUID_COMMAND_SIZE: u64 = 24;
/// `sizeof(struct dylib_command)` 的固定部分（`struct dylib` 是 4 个 `uint32`）。
pub const DYLIB_COMMAND_SIZE: u64 = 24;

/// 一条加载命令最短长度：`cmd` + `cmdsize`。
pub const LOAD_COMMAND_MIN_SIZE: u64 = 8;

// ── CPU 类型（`mach/machine.h`） ────────────────────────────────────────────

/// `CPU_TYPE_X86`。
pub const CPU_TYPE_X86: u32 = 7;
/// `CPU_TYPE_X86_64`。
pub const CPU_TYPE_X86_64: u32 = 0x0100_0007;
/// `CPU_TYPE_ARM`。
pub const CPU_TYPE_ARM: u32 = 12;
/// `CPU_TYPE_ARM64`。
pub const CPU_TYPE_ARM64: u32 = 0x0100_000c;
/// `CPU_TYPE_POWERPC`。**能识别但拒绝解析**（见模块文档第 3 条）。
pub const CPU_TYPE_POWERPC: u32 = 18;
/// `CPU_TYPE_POWERPC64`。
pub const CPU_TYPE_POWERPC64: u32 = 0x0100_0012;
/// `CPU_SUBTYPE_ARM64E`：与 arm64 共用 `cputype`，靠 subtype 区分。
pub const CPU_SUBTYPE_ARM64E: u32 = 2;

// ── filetype（`mach-o/loader.h`） ──────────────────────────────────────────

/// `MH_OBJECT`：可重定位目标文件（`.o`）。
pub const MH_OBJECT: u32 = 0x1;
/// `MH_EXECUTE`：可执行文件。
pub const MH_EXECUTE: u32 = 0x2;
/// `MH_DYLIB`：动态库。
pub const MH_DYLIB: u32 = 0x6;
/// `MH_BUNDLE`：bundle（插件）。
pub const MH_BUNDLE: u32 = 0x8;
/// `MH_DSYM`：调试符号文件。
pub const MH_DSYM: u32 = 0xa;

// ── 段/节权限与标志（`mach/vm_prot.h`、`mach-o/loader.h`） ────────────────

/// `VM_PROT_READ`。
pub const VM_PROT_READ: i32 = 0x1;
/// `VM_PROT_WRITE`。
pub const VM_PROT_WRITE: i32 = 0x2;
/// `VM_PROT_EXECUTE`。
pub const VM_PROT_EXECUTE: i32 = 0x4;

/// `S_ZEROFILL`：不占文件空间的零填充节（`__bss` 那类）。
pub const SECTION_TYPE_ZEROFILL: u32 = 0x1;
/// `S_GB_ZEROFILL`。
pub const SECTION_TYPE_GB_ZEROFILL: u32 = 0xc;
/// `S_THREAD_LOCAL_ZEROFILL`。
pub const SECTION_TYPE_TLS_ZEROFILL: u32 = 0x12;
/// `S_ATTR_PURE_INSTRUCTIONS`：节里全是指令。
pub const SECTION_ATTR_PURE_INSTRUCTIONS: u32 = 0x8000_0000;
/// `S_ATTR_SOME_INSTRUCTIONS`：节里有指令。
pub const SECTION_ATTR_SOME_INSTRUCTIONS: u32 = 0x0000_0400;

// ── 线程状态（`mach/i386/thread_status.h`、`mach/arm/thread_status.h`） ────

/// `x86_THREAD_STATE32`。
const X86_THREAD_STATE32: u32 = 1;
/// `x86_THREAD_STATE64`。
const X86_THREAD_STATE64: u32 = 4;
/// `ARM_THREAD_STATE`（32 位 ARM 状态）。
const ARM_THREAD_STATE: u32 = 1;
/// `ARM_THREAD_STATE64`。
const ARM_THREAD_STATE64: u32 = 6;

// ── 公开数据结构 ────────────────────────────────────────────────────────────

/// 一层**薄** Mach-O（非 fat）的结构层解析结果。
///
/// 为什么不直接给 [`Object`]：下面这几项在对象模型里没有位置，塞进 `notes`
/// 又会让程序化消费只能靠解析字符串 ——
///
/// * `uuid`（`LC_UUID`）与 `dylibs`（依赖库名）；
/// * `cputype` / `cpusubtype` / `filetype` / `ncmds` / `sizeofcmds` / `reserved`
///   这些**原始**头字段（对象模型只归一化了一部分）；
/// * 节的 `align` / `flags` / `offset`（[`crate::object::Section`] 会丢掉它们）。
///
/// 两种入口分工：要对象模型走 [`parse`]，要这些事实走 [`read`]。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MachOFile {
    /// 是 64 位 Mach-O（`mach_header_64`）吗。
    pub is_64: bool,
    /// 文件端序。
    pub endian: Endian,
    /// `cputype` 原始值。
    pub cputype: u32,
    /// `cpusubtype` 原始值。
    pub cpusubtype: u32,
    /// `filetype` 原始值（`MH_EXECUTE` 之类）。
    pub filetype: u32,
    /// 头里声明的加载命令条数。
    pub ncmds: u32,
    /// 头里声明的加载命令区字节数。
    pub sizeofcmds: u32,
    /// 头里的 `flags`。
    pub flags: u32,
    /// 头里的 `reserved`（只有 64 位有）。
    pub reserved: Option<u32>,
    /// 由 `cputype`（+ `cpusubtype`）映射出的架构。
    pub arch: ArchSpec,
    /// `LC_UUID` 的 16 字节，小写十六进制（32 个字符）。
    pub uuid: Option<String>,
    /// `LC_LOAD_DYLIB` / `LC_LOAD_WEAK_DYLIB` 给出的依赖库名（按命令顺序）。
    pub dylibs: Vec<String>,
    /// 入口点（已换算成虚拟地址）。`None` = 没有入口点或换不出来。
    pub entry: Option<EntryPoint>,
    /// 镜像基址（`__TEXT` 段的 `vmaddr`）。`None` = 没有 `__TEXT` 段。
    pub image_base: Option<u64>,
    /// 段及其节（按加载命令顺序）。
    pub segments: Vec<MachOSegment>,
    /// 是否存在 `LC_SYMTAB`。**只代表命令存在**，不代表符号表被解析过。
    pub has_symtab: bool,
    /// 解析过程中的说明（降级、跳过、没做的部分）。
    pub notes: Vec<String>,
}

/// 一个 Mach-O 段（`LC_SEGMENT` / `LC_SEGMENT_64`）。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MachOSegment {
    /// `segname`（NUL 填充的 16 字节；空串表示文件里就是空的）。
    pub name: String,
    /// `vmaddr`。
    pub vmaddr: u64,
    /// `vmsize`。
    pub vmsize: u64,
    /// `fileoff`。
    pub fileoff: u64,
    /// `filesize`（`__PAGEZERO` 合法地为 0）。
    pub filesize: u64,
    /// `maxprot`。
    pub maxprot: i32,
    /// `initprot`（运行期初始权限）。
    pub initprot: i32,
    /// 段内节。
    pub sections: Vec<MachOSection>,
}

/// 一个 Mach-O 节（`section` / `section_64`）。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MachOSection {
    /// `sectname`。
    pub sectname: String,
    /// `segname`（节自带的那个，正常与所在段同名）。
    pub segname: String,
    /// `addr`。
    pub addr: u64,
    /// `size`。
    pub size: u64,
    /// `offset`（**文件偏移**；零填充节里无意义）。
    pub offset: u32,
    /// `align`（**以 2 为底的对数**，规范如此，不是字节数）。
    pub align: u32,
    /// `flags`（低 8 位是 section type，高位是 attributes）。
    pub flags: u32,
}

/// 入口点，以及它是**从哪条命令**来的。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct EntryPoint {
    /// 虚拟地址（已按段映射换算）。
    pub vaddr: u64,
    /// 来源命令。
    pub source: EntrySource,
}

/// 入口点的来源。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EntrySource {
    /// `LC_MAIN`。`entryoff` 是**文件偏移**，`EntryPoint::vaddr` 是换算后的地址。
    Main {
        /// 原始 `entryoff`（文件偏移）。
        entryoff: u64,
    },
    /// `LC_UNIXTHREAD`：线程状态里的 PC，**本身就是虚拟地址**。
    UnixThread {
        /// 线程状态的 `flavor`（例如 `x86_THREAD_STATE64`）。
        flavor: u32,
        /// 线程状态的 `count`（以 32 位字为单位）。
        count: u32,
    },
}

// ── 入口 ────────────────────────────────────────────────────────────────────

/// 这个前缀看起来是 fat / universal Mach-O 吗（`mach-o/fat.h` 的两个魔数）。
///
/// 只判 4 字节魔数，**不**判断它是不是 Java class（两者都以 `CAFEBABE` 开头）
/// —— 那个区分要读架构表，见 [`fat::read`]。
#[must_use]
pub fn looks_like_fat(bytes: &[u8]) -> bool {
    bytes.len() >= 4
        && (bytes[0..4] == [0xca, 0xfe, 0xba, 0xbe] || bytes[0..4] == [0xca, 0xfe, 0xba, 0xbf])
}

/// 解析一层薄 Mach-O，返回**结构层事实**（[`MachOFile`]）。
///
/// 只接受薄（thin）Mach-O：fat / universal 用 [`fat::read`]，因为"多层切片里该选
/// 哪一层"不是解析器能替调用方回答的问题。
///
/// # Errors
///
/// 魔数不是 Mach-O；`cputype` 未映射（含 ppc，见模块文档）；命令区越界或
/// 自相矛盾；段/节的文件范围越界。这些都是"拒绝而不是误读"。
pub fn read(bytes: &[u8]) -> Result<MachOFile, ParseError> {
    read_with(&Reader::new(bytes))
}

/// 解析一层薄 Mach-O，组装成对象模型 [`Object`]。
///
/// `base` 是这段字节在宿主文件中的起始偏移，**只用于错误信息里的绝对偏移**
/// （与 [`crate::format::elf::parse`] 一致）：fat 切片被单独解析时，报错里的
/// 偏移指的是切片内的偏移，加上 `base` 才对应原文件。对象里的
/// [`FileRange`] 仍然是**切片内**的偏移。
///
/// fat / universal 输入在这里被明确拒绝（[`ParseError::NotSupported`]）——
/// 别让调用方以为拿到的是"某个架构"的对象。
///
/// # Errors
///
/// 同 [`read`]；另外 fat / universal 输入返回 `NotSupported`。
pub fn parse(bytes: &[u8], base: u64, id: ObjectId) -> Result<Object, ParseError> {
    if looks_like_fat(bytes) {
        return Err(ParseError::NotSupported {
            what: "容器",
            detail: "这是 fat / universal Mach-O：一个文件里有多层架构切片，没有\"这个文件\"的\
                     单一架构。切片枚举已经实现（`format::macho::fat::read`，有测试），\
                     但把切片接进容器抽象与成员会话是 M12 的下一片 —— 现在请把需要的那一片\
                     切出来（`fat::read` 给的 offset/size）再单独解析"
                .to_string(),
        });
    }
    let reader = Reader::with_base(bytes, base);
    let file = read_with(&reader)?;
    Ok(build_object(&file, id))
}

// ── 头部 ────────────────────────────────────────────────────────────────────

/// 解析好的 Mach-O 头。
struct MachHeader {
    is_64: bool,
    endian: Endian,
    endianness: Endianness,
    cputype: u32,
    cpusubtype: u32,
    filetype: u32,
    ncmds: u32,
    sizeofcmds: u32,
    flags: u32,
    reserved: Option<u32>,
}

impl MachHeader {
    fn size(&self) -> u64 {
        if self.is_64 {
            HEADER64_SIZE
        } else {
            HEADER32_SIZE
        }
    }

    fn parse(reader: &Reader<'_>) -> Result<Self, ParseError> {
        // 魔数按**小端**读一次，再按四个常量的含义反推文件端序 ——
        // 这样"文件里的字节序"与"字段怎么读"是同一个判断，不会两处各猜一次。
        let magic = reader.u32(0, Endianness::Little, "Mach-O 魔数")?;
        let (is_64, endianness) = match magic {
            MH_MAGIC => (false, Endianness::Little),
            MH_MAGIC_64 => (true, Endianness::Little),
            MH_CIGAM => (false, Endianness::Big),
            MH_CIGAM_64 => (true, Endianness::Big),
            other => {
                return Err(ParseError::BadMagic {
                    expected: "Mach-O 魔数（MH_MAGIC / MH_MAGIC_64 / MH_CIGAM / MH_CIGAM_64）",
                    actual: format!("{other:#010x}"),
                })
            }
        };
        let endian = match endianness {
            Endianness::Little => Endian::Little,
            Endianness::Big => Endian::Big,
        };

        let header_size = if is_64 { HEADER64_SIZE } else { HEADER32_SIZE };
        reader
            .slice(0, header_size, "Mach-O 文件头")
            .map_err(|_| ParseError::Truncated {
                what: "Mach-O 文件头",
                needed: header_size,
                actual: reader.len(),
            })?;

        Ok(Self {
            is_64,
            endian,
            endianness,
            cputype: reader.u32(4, endianness, "cputype")?,
            cpusubtype: reader.u32(8, endianness, "cpusubtype")?,
            filetype: reader.u32(12, endianness, "filetype")?,
            ncmds: reader.u32(16, endianness, "ncmds")?,
            sizeofcmds: reader.u32(20, endianness, "sizeofcmds")?,
            flags: reader.u32(24, endianness, "flags")?,
            reserved: if is_64 {
                Some(reader.u32(28, endianness, "reserved")?)
            } else {
                None
            },
        })
    }
}

/// `cputype`（+ `cpusubtype`）→ [`ArchSpec`]。
///
/// ppc 单独点名拒绝，理由见模块文档第 3 条。
fn resolve_arch(
    cputype: u32,
    cpusubtype: u32,
    endian: Endian,
    notes: &mut Vec<String>,
) -> Result<ArchSpec, ParseError> {
    match Arch::from_macho_cputype(cputype) {
        Some((arch, mode)) => {
            let spec = ArchSpec::from_arch(arch, mode, endian);
            if cputype == CPU_TYPE_ARM64 && cpusubtype == CPU_SUBTYPE_ARM64E {
                notes.push(
                    "cpusubtype = 2（CPU_SUBTYPE_ARM64E）：架构按 AArch64 解码，\
                     但指针认证（PAC）语义没有还原 —— 指针高位可能带签名，\
                     静态看到的裸值不等于运行期值"
                        .to_string(),
                );
            }
            Ok(spec)
        }
        None if cputype == CPU_TYPE_POWERPC || cputype == CPU_TYPE_POWERPC64 => {
            Err(ParseError::Unsupported {
                what: "cputype",
                value: u64::from(cputype),
                detail: "识别为 Mach-O 的 PowerPC（ppc / ppc64），但 bitflip_arch::Arch \
                         没有 PowerPC 变体、也没有 ppc 解码后端。加一个**没有解码器**的\
                         架构变体会让分析层解出垃圾，所以这里明确拒绝而不是猜一个近似架构\
                         （CLAUDE.md §7）。要真支持 ppc，得先给 bitflip-arch 加后端",
            })
        }
        None => Err(ParseError::Unsupported {
            what: "cputype",
            value: u64::from(cputype),
            detail: "未知或尚未映射的 Mach-O CPU 类型（已映射：x86 / x86_64 / arm / arm64）",
        }),
    }
}

// ── 加载命令 ────────────────────────────────────────────────────────────────

/// 遍历加载命令累计出来的原始事实（还没归一化）。
#[derive(Default)]
struct CommandFacts {
    segments: Vec<MachOSegment>,
    uuid: Option<String>,
    dylibs: Vec<String>,
    entry_off: Option<u64>,
    unix_thread: Option<UnixThread>,
    has_symtab: bool,
    has_dyld_info: bool,
    has_chained_fixups: bool,
    has_codesig: bool,
    unhandled: Vec<u32>,
    /// 走完 `ncmds` 条命令后，`sizeofcmds` 里还剩多少字节。
    trailing_bytes: u64,
}

/// `LC_UNIXTHREAD` 的线程状态。
struct UnixThread {
    flavor: u32,
    count: u32,
    /// 解出来的 PC；`None` = 这个架构/flavor 没有解（没有猜）。
    pc: Option<u64>,
}

/// 线程状态里 PC 的位置（表在 [`thread_state_slot`]）。
struct ThreadStateSlot {
    flavor: u32,
    count: u32,
    pc_index: u64,
    word_bytes: u64,
}

/// `cputype` → 线程状态布局。
///
/// # 这些数字的出处
///
/// `mach/i386/thread_status.h` 与 `mach/arm/thread_status.h` 里的结构体定义：
///
/// ```text
/// x86_thread_state32_t { uint32 eax..eip..; }   // eip 是第 11 个字段（下标 10），共 16 个 uint32
/// x86_thread_state64_t { uint64 rax..rip; }     // rip 是第 17 个字段（下标 16），共 21 个 uint64
/// arm_thread_state32_t { uint32 r[13]; sp; lr; pc; cpsr; }  // pc 下标 15，共 17 个 uint32
/// arm_thread_state64_t { uint64 x[29]; fp; lr; sp; pc; cpsr; pad; } // pc 下标 32，共 34 个 uint64
/// ```
///
/// `count` 是**以 32 位字为单位**的状态长度（规范如此），所以 64 位状态是
/// `168 / 4 = 42`、`272 / 4 = 68`。只解这四种：其余架构本来就没有映射，
/// 硬解一个偏移只会给出错地址。
fn thread_state_slot(cputype: u32) -> Option<ThreadStateSlot> {
    match cputype {
        CPU_TYPE_X86 => Some(ThreadStateSlot {
            flavor: X86_THREAD_STATE32,
            count: 16,
            pc_index: 10,
            word_bytes: 4,
        }),
        CPU_TYPE_X86_64 => Some(ThreadStateSlot {
            flavor: X86_THREAD_STATE64,
            count: 42,
            pc_index: 16,
            word_bytes: 8,
        }),
        CPU_TYPE_ARM => Some(ThreadStateSlot {
            flavor: ARM_THREAD_STATE,
            count: 17,
            pc_index: 15,
            word_bytes: 4,
        }),
        CPU_TYPE_ARM64 => Some(ThreadStateSlot {
            flavor: ARM_THREAD_STATE64,
            count: 68,
            pc_index: 32,
            word_bytes: 8,
        }),
        _ => None,
    }
}

fn read_with(reader: &Reader<'_>) -> Result<MachOFile, ParseError> {
    let header = MachHeader::parse(reader)?;

    let mut notes = Vec::new();
    if header.endian == Endian::Big {
        notes.push(
            "大端 Mach-O：所有字段按大端解析。现实中大端 Mach-O 基本只有 ppc/armeb，\
             而 ppc 没有映射（见 cputype 的拒绝说明）"
                .to_string(),
        );
    }
    let arch = resolve_arch(header.cputype, header.cpusubtype, header.endian, &mut notes)?;

    // ── 命令区的范围校验：先整体，再逐条 ────────────────────────────────
    //
    // 三件事必须在这里挡住，否则后面的循环会在错误的边界里读字节：
    // 1. `sizeofcmds` 声称的区域必须落在文件内；
    // 2. `ncmds` 条命令每条至少 8 字节，必须装得进 `sizeofcmds`；
    // 3. 每条命令的 `cmdsize` 必须 ≥ 8、4 字节对齐，且不越过 `sizeofcmds`。
    let header_end = header.size();
    let cmds_end = header_end
        .checked_add(u64::from(header.sizeofcmds))
        .ok_or_else(|| {
            ParseError::Overflow("Mach-O 加载命令区：头大小 + sizeofcmds".to_string())
        })?;
    if cmds_end > reader.len() {
        return Err(ParseError::Truncated {
            what: "Mach-O 加载命令区",
            needed: cmds_end,
            actual: reader.len(),
        });
    }
    let min_needed = u64::from(header.ncmds) * LOAD_COMMAND_MIN_SIZE;
    if min_needed > u64::from(header.sizeofcmds) {
        return Err(ParseError::Inconsistent(format!(
            "ncmds = {} 条加载命令每条至少 {LOAD_COMMAND_MIN_SIZE} 字节（共需 {min_needed} 字节），\
             但 sizeofcmds 只声明了 {} 字节 —— 头字段自相矛盾",
            header.ncmds, header.sizeofcmds
        )));
    }

    let facts = read_commands(reader, &header, cmds_end)?;

    // ── 段与节的文件范围 ────────────────────────────────────────────────
    //
    // 这一步要文件长度，所以放在这里而不是 `build_object` 里。
    // `__PAGEZERO` 的 `filesize == 0` 是**合法**的（它就是"这段内存不来自文件"），
    // 因此只校验 filesize > 0 的段；零填充节同理跳过。
    validate_memory_map(&facts.segments, reader.len(), &mut notes)?;

    // ── 入口点 ──────────────────────────────────────────────────────────
    let entry = resolve_entry(&header, &facts, &mut notes);

    // ── 镜像基址 ────────────────────────────────────────────────────────
    let image_base = facts
        .segments
        .iter()
        .find(|segment| segment.name == "__TEXT")
        .map(|segment| segment.vmaddr);
    if image_base.is_none() {
        notes.push(
            "没有 __TEXT 段：镜像基址未知。对象模型里 image_base 会记成 0，\
             那是占位值而不是真实基址（CLAUDE.md §7）"
                .to_string(),
        );
    }

    // ── 没做的部分：一律写进 notes，不让界面看起来"完整" ────────────────
    notes.push(if facts.has_symtab {
        "存在 LC_SYMTAB：符号表**没有解析**（M12 的下一片），所以 Object.symbols 是空的；\
         format.is_stripped 也只按「这条命令在不在」判断，不代表读到了符号。\
         也没有 LC_FUNCTION_STARTS，函数边界只能靠反汇编识别"
            .to_string()
    } else {
        "没有 LC_SYMTAB（符号表已被剥离或本来就没有）：Object.symbols 是空的，\
         也没有 LC_FUNCTION_STARTS，函数边界只能靠反汇编识别"
            .to_string()
    });
    if facts.has_dyld_info || facts.has_chained_fixups {
        notes.push(
            "存在 dyld 绑定信息（LC_DYLD_INFO* / LC_DYLD_CHAINED_FIXUPS）：**没有解析**，\
             导入表（Object.imports）因此是空的 —— 这是与 PE/ELF 的已知差距"
                .to_string(),
        );
    }
    if facts.has_codesig {
        notes.push("存在 LC_CODE_SIGNATURE：只记录存在性，**没有做签名校验**".to_string());
    }
    note_objc_and_swift(&facts.segments, &mut notes);
    if !facts.unhandled.is_empty() {
        let mut listed: Vec<String> = Vec::new();
        for cmd in &facts.unhandled {
            let text = format!("{cmd:#010x}");
            if !listed.contains(&text) {
                listed.push(text);
            }
        }
        let total = listed.len();
        listed.truncate(8);
        notes.push(format!(
            "有 {} 条加载命令本片未解析（共 {total} 种，列出前 {} 种：{}）",
            facts.unhandled.len(),
            listed.len(),
            listed.join("、")
        ));
    }
    if facts.trailing_bytes > 0 {
        notes.push(format!(
            "sizeofcmds 声明 {} 字节，但 {ncmds} 条命令合计用了 {} 字节：尾部还有 \
             {} 字节未解释（有的工具会填 0 补齐，不影响本次结论）",
            header.sizeofcmds,
            u64::from(header.sizeofcmds) - facts.trailing_bytes,
            facts.trailing_bytes,
            ncmds = header.ncmds
        ));
    }

    Ok(MachOFile {
        is_64: header.is_64,
        endian: header.endian,
        cputype: header.cputype,
        cpusubtype: header.cpusubtype,
        filetype: header.filetype,
        ncmds: header.ncmds,
        sizeofcmds: header.sizeofcmds,
        flags: header.flags,
        reserved: header.reserved,
        arch,
        uuid: facts.uuid,
        dylibs: facts.dylibs,
        entry,
        image_base,
        segments: facts.segments,
        has_symtab: facts.has_symtab,
        notes,
    })
}

/// 逐条读加载命令。
fn read_commands(
    reader: &Reader<'_>,
    header: &MachHeader,
    cmds_end: u64,
) -> Result<CommandFacts, ParseError> {
    let mut facts = CommandFacts::default();
    let mut cursor = header.size();
    let endianness = header.endianness;

    for index in 0..u64::from(header.ncmds) {
        // 走到这里时 cursor <= cmds_end 由上一轮保证；仍显式判一次，因为
        // `ncmds` 与 `sizeofcmds` 是两条独立的不可信输入。
        let command_end = cursor
            .checked_add(LOAD_COMMAND_MIN_SIZE)
            .ok_or_else(|| ParseError::Overflow(format!("加载命令 #{index} 的偏移")))?;
        if command_end > cmds_end {
            return Err(ParseError::Inconsistent(format!(
                "头声明 {} 条加载命令，但读到第 {index} 条时命令区（{cursor:#x}..{cmds_end:#x}）\
                 已经用完",
                header.ncmds
            )));
        }

        let cmd = reader.u32(cursor, endianness, "加载命令 cmd")?;
        let cmdsize = u64::from(reader.u32(cursor + 4, endianness, "加载命令 cmdsize")?);
        if cmdsize < LOAD_COMMAND_MIN_SIZE {
            return Err(ParseError::Inconsistent(format!(
                "加载命令 #{index}（cmd = {cmd:#010x}）的 cmdsize = {cmdsize}，\
                 小于最短长度 {LOAD_COMMAND_MIN_SIZE}"
            )));
        }
        // 规范要求 cmdsize 是 4 的倍数。不是的话下一条命令的起点就错位了，
        // 后面的解析全会读到错字节 —— 这类输入必须拒绝，不能"尽量读"。
        if cmdsize % 4 != 0 {
            return Err(ParseError::Inconsistent(format!(
                "加载命令 #{index}（cmd = {cmd:#010x}）的 cmdsize = {cmdsize} 不是 4 的倍数：\
                 命令区会错位"
            )));
        }
        let next = cursor
            .checked_add(cmdsize)
            .ok_or_else(|| ParseError::Overflow(format!("加载命令 #{index} 的结束偏移")))?;
        if next > cmds_end {
            return Err(ParseError::Inconsistent(format!(
                "加载命令 #{index}（cmd = {cmd:#010x}，cmdsize = {cmdsize}）越过 sizeofcmds \
                 声明的命令区（{cursor:#x}..{cmds_end:#x}）"
            )));
        }

        let view = Reader::with_base(
            reader.slice(cursor, cmdsize, "加载命令")?,
            reader.base() + cursor,
        );
        match cmd {
            LC_SEGMENT => facts
                .segments
                .push(parse_segment(&view, false, endianness)?),
            LC_SEGMENT_64 => facts.segments.push(parse_segment(&view, true, endianness)?),
            LC_MAIN => facts.entry_off = Some(read_entry_point_off(&view, endianness)?),
            LC_UNIXTHREAD => facts.unix_thread = Some(read_unix_thread(&view, header)?),
            LC_UUID => facts.uuid = Some(read_uuid(&view)?),
            LC_LOAD_DYLIB | LC_LOAD_WEAK_DYLIB => {
                if let Some(name) = read_dylib_name(&view, endianness)? {
                    facts.dylibs.push(name);
                }
            }
            LC_SYMTAB => facts.has_symtab = true,
            LC_DYLD_INFO | LC_DYLD_INFO_ONLY => facts.has_dyld_info = true,
            LC_DYLD_CHAINED_FIXUPS => facts.has_chained_fixups = true,
            LC_CODE_SIGNATURE => facts.has_codesig = true,
            // LC_ID_DYLIB 是"我是谁"，不是依赖；其余命令本片不解析。
            LC_ID_DYLIB => {}
            other => facts.unhandled.push(other),
        }

        cursor = next;
    }

    // 走完 ncmds 条命令后与 sizeofcmds 对账。多出来的字节不一定是坏文件
    // （有的工具会填 0 补齐），所以只说明，不当错误。
    facts.trailing_bytes = cmds_end.saturating_sub(cursor);
    Ok(facts)
}

/// 读 `LC_SEGMENT` / `LC_SEGMENT_64` 及其节。
///
/// `is_64` 由**命令本身**决定（不是文件头）：64 位文件里出现 32 位段命令属于
/// 结构异常，但按命令自己的布局读才是"不误读"。
fn parse_segment(
    view: &Reader<'_>,
    is_64: bool,
    endianness: Endianness,
) -> Result<MachOSegment, ParseError> {
    let command_size = if is_64 {
        SEGMENT_COMMAND64_SIZE
    } else {
        SEGMENT_COMMAND32_SIZE
    };
    let section_size = if is_64 {
        SECTION64_SIZE
    } else {
        SECTION32_SIZE
    };
    if view.len() < command_size {
        return Err(ParseError::Truncated {
            what: "段命令",
            needed: command_size,
            actual: view.len(),
        });
    }

    // `segment_command` 的字段偏移（两种宽度的固定字段偏移相同，宽度不同的
    // 项在下面分支里读）：
    //   +8  char segname[16]
    //   32 位：+24 vmaddr +28 vmsize +32 fileoff +36 filesize
    //          +40 maxprot +44 initprot +48 nsects +52 flags
    //   64 位：+24 vmaddr +32 vmsize +40 fileoff +48 filesize
    //          +56 maxprot +60 initprot +64 nsects +68 flags
    let name = view.cstr(8, 16, "segname")?;
    // 段自己的 `flags`（`SG_NORELOC` / `SG_PROTECTED_VERSION_1` 之类）本片没有用到：
    // 它对"段/节视图"没有影响，不建模也不假装建模（CLAUDE.md §7）。
    let (vmaddr, vmsize, fileoff, filesize, maxprot, initprot, nsects, _flags) = if is_64 {
        (
            view.u64(24, endianness, "vmaddr")?,
            view.u64(32, endianness, "vmsize")?,
            view.u64(40, endianness, "fileoff")?,
            view.u64(48, endianness, "filesize")?,
            view.u32(56, endianness, "maxprot")?,
            view.u32(60, endianness, "initprot")?,
            u64::from(view.u32(64, endianness, "nsects")?),
            view.u32(68, endianness, "flags")?,
        )
    } else {
        (
            u64::from(view.u32(24, endianness, "vmaddr")?),
            u64::from(view.u32(28, endianness, "vmsize")?),
            u64::from(view.u32(32, endianness, "fileoff")?),
            u64::from(view.u32(36, endianness, "filesize")?),
            view.u32(40, endianness, "maxprot")?,
            view.u32(44, endianness, "initprot")?,
            u64::from(view.u32(48, endianness, "nsects")?),
            view.u32(52, endianness, "flags")?,
        )
    };

    // 先校验"cmdsize 装得下 nsects 个节"，再按 nsects 循环 —— 否则一个编造的
    // nsects 会让我们一边失败一边已经分配/越界。
    let sections_bytes = nsects
        .checked_mul(section_size)
        .ok_or_else(|| ParseError::Overflow("段命令：nsects × sizeof(section)".to_string()))?;
    let needed = command_size
        .checked_add(sections_bytes)
        .ok_or_else(|| ParseError::Overflow("段命令：固定部分 + 节表".to_string()))?;
    if needed > view.len() {
        return Err(ParseError::Inconsistent(format!(
            "段 {name:?} 的 cmdsize = {} 装不下 {nsects} 个节（需要 {needed} 字节）",
            view.len()
        )));
    }

    let mut sections = Vec::with_capacity(nsects as usize);
    for index in 0..nsects {
        let offset = command_size + index * section_size;
        let view_offset = usize::try_from(offset)
            .map_err(|_| ParseError::Overflow("段命令：节的视图偏移".to_string()))?;
        let view_len = usize::try_from(section_size)
            .map_err(|_| ParseError::Overflow("段命令：节的视图长度".to_string()))?;
        let raw = &view.as_bytes()[view_offset..view_offset + view_len];
        let section_view = Reader::with_base(raw, view.base() + offset);
        sections.push(parse_section(&section_view, is_64, endianness)?);
    }

    Ok(MachOSegment {
        name,
        vmaddr,
        vmsize,
        fileoff,
        filesize,
        // 规范的 `vm_prot_t` 是 `int`；位含义不变，按 i32 保存以免下游再转一次。
        maxprot: maxprot as i32,
        initprot: initprot as i32,
        sections,
    })
}

/// 读一个 `section` / `section_64`（已经切成定长子视图）。
fn parse_section(
    view: &Reader<'_>,
    is_64: bool,
    endianness: Endianness,
) -> Result<MachOSection, ParseError> {
    // `section` / `section_64` 的字段偏移：
    //   +0  char sectname[16]
    //   +16 char segname[16]
    //   32 位：+32 addr +36 size +40 offset +44 align +48 reloff +52 nreloc +56 flags
    //   64 位：+32 addr(8) +40 size(8) +48 offset +52 align +56 reloff +60 nreloc +64 flags
    let sectname = view.cstr(0, 16, "sectname")?;
    let segname = view.cstr(16, 16, "节的 segname")?;
    let (addr, size, offset, align, flags) = if is_64 {
        (
            view.u64(32, endianness, "section.addr")?,
            view.u64(40, endianness, "section.size")?,
            view.u32(48, endianness, "section.offset")?,
            view.u32(52, endianness, "section.align")?,
            view.u32(64, endianness, "section.flags")?,
        )
    } else {
        (
            u64::from(view.u32(32, endianness, "section.addr")?),
            u64::from(view.u32(36, endianness, "section.size")?),
            view.u32(40, endianness, "section.offset")?,
            view.u32(44, endianness, "section.align")?,
            view.u32(56, endianness, "section.flags")?,
        )
    };
    Ok(MachOSection {
        sectname,
        segname,
        addr,
        size,
        offset,
        align,
        flags,
    })
}

/// 读 `LC_MAIN` 的 `entryoff`（**文件偏移**）。
fn read_entry_point_off(view: &Reader<'_>, endianness: Endianness) -> Result<u64, ParseError> {
    if view.len() < ENTRY_POINT_COMMAND_SIZE {
        return Err(ParseError::Truncated {
            what: "LC_MAIN",
            needed: ENTRY_POINT_COMMAND_SIZE,
            actual: view.len(),
        });
    }
    view.u64(8, endianness, "LC_MAIN.entryoff")
}

/// 读 `LC_UUID`。
fn read_uuid(view: &Reader<'_>) -> Result<String, ParseError> {
    if view.len() < UUID_COMMAND_SIZE {
        return Err(ParseError::Truncated {
            what: "LC_UUID",
            needed: UUID_COMMAND_SIZE,
            actual: view.len(),
        });
    }
    let raw = view.slice(8, 16, "LC_UUID.uuid")?;
    let mut out = String::with_capacity(32);
    for byte in raw {
        // 写 String 不会失败；`let _ =` 只是为了不让 `#[must_use]` 报未使用。
        let _ = write!(out, "{byte:02x}");
    }
    Ok(out)
}

/// 读 `LC_UNIXTHREAD` 的线程状态，尽量解出 PC。
///
/// 解不出来**不是错误**：这条命令在真实文件里主要是历史包袱，而猜错一个 PC
/// 会让整个分析从错误的地址开始。所以 flavor/count 对不上时 `pc = None`，
/// 由调用方在 `notes` 里说清"存在但没解"。
fn read_unix_thread(view: &Reader<'_>, header: &MachHeader) -> Result<UnixThread, ParseError> {
    let endianness = header.endianness;
    // `thread_command` = cmd + cmdsize + flavor + count，之后才是状态字数组。
    if view.len() < 16 {
        return Err(ParseError::Truncated {
            what: "LC_UNIXTHREAD",
            needed: 16,
            actual: view.len(),
        });
    }
    let flavor = view.u32(8, endianness, "LC_UNIXTHREAD.flavor")?;
    let count = view.u32(12, endianness, "LC_UNIXTHREAD.count")?;

    let pc = thread_state_slot(header.cputype).and_then(|slot| {
        if flavor != slot.flavor || count != slot.count {
            return None;
        }
        let pc_offset = 16 + slot.pc_index * slot.word_bytes;
        if pc_offset + slot.word_bytes > view.len() {
            return None;
        }
        if slot.word_bytes == 8 {
            view.u64(pc_offset, endianness, "LC_UNIXTHREAD.pc").ok()
        } else {
            view.u32(pc_offset, endianness, "LC_UNIXTHREAD.pc")
                .ok()
                .map(u64::from)
        }
    });

    Ok(UnixThread { flavor, count, pc })
}

/// 读 `LC_LOAD_DYLIB` / `LC_LOAD_WEAK_DYLIB` 的库名。
///
/// `dylib.name` 是 `lc_str`：**相对本条命令起点**的偏移。偏移非法时不猜名字，
/// 返回 `None` —— 刻意不把非法偏移编成空串，那样会变成"依赖了一个无名库"的假事实。
fn read_dylib_name(
    view: &Reader<'_>,
    endianness: Endianness,
) -> Result<Option<String>, ParseError> {
    if view.len() < DYLIB_COMMAND_SIZE {
        return Ok(None);
    }
    let name_offset = u64::from(view.u32(8, endianness, "dylib.name")?);
    if name_offset < DYLIB_COMMAND_SIZE || name_offset >= view.len() {
        return Ok(None);
    }
    let name = view.cstr(name_offset, view.len() - name_offset, "dylib 名字")?;
    if name.is_empty() {
        return Ok(None);
    }
    Ok(Some(name))
}

// ── 范围校验 ────────────────────────────────────────────────────────────────

/// 校验段与节的文件范围（拿着文件长度才能做）。
///
/// 三条必须**拒绝**的规则（写进 CLAUDE.md 精神里的"宁可报错不要误读"）：
///
/// 1. 段的 `fileoff + filesize` 越过文件末尾；
/// 2. 节的数据范围越过文件末尾；
/// 3. 节的数据范围不在**它所在段**的文件范围内。
///
/// `filesize == 0` 的段（`__PAGEZERO`）与零填充节（`S_ZEROFILL` 一族）**跳过**
/// —— 它们本来就不占文件空间，把它们当越界会把合法文件拒之门外。
fn validate_memory_map(
    segments: &[MachOSegment],
    file_len: u64,
    notes: &mut Vec<String>,
) -> Result<(), ParseError> {
    for segment in segments {
        if segment.filesize > 0 {
            let end = segment
                .fileoff
                .checked_add(segment.filesize)
                .ok_or_else(|| {
                    ParseError::Overflow(format!("段 {} 的 fileoff + filesize", segment.name))
                })?;
            if end > file_len {
                return Err(ParseError::Inconsistent(format!(
                    "段 {} 的文件范围 {:#x}..{end:#x} 超出文件大小 {file_len:#x}：\
                     文件被裁剪或被人为改过",
                    segment.name, segment.fileoff
                )));
            }
        }
        if segment.filesize > segment.vmsize {
            notes.push(format!(
                "段 {} 的 filesize({:#x}) 大于 vmsize({:#x})：文件可能被修改过",
                segment.name, segment.filesize, segment.vmsize
            ));
        }

        for section in &segment.sections {
            if is_zerofill_section(section.flags) || section.size == 0 {
                continue;
            }
            let offset = u64::from(section.offset);
            let end = offset.checked_add(section.size).ok_or_else(|| {
                ParseError::Overflow(format!(
                    "节 {},{} 的 offset + size",
                    section.segname, section.sectname
                ))
            })?;
            if end > file_len {
                return Err(ParseError::Inconsistent(format!(
                    "节 {},{} 的数据范围 {offset:#x}..{end:#x} 超出文件大小 {file_len:#x}",
                    section.segname, section.sectname
                )));
            }
            let segment_end = segment.fileoff.saturating_add(segment.filesize);
            if offset < segment.fileoff || end > segment_end {
                return Err(ParseError::Inconsistent(format!(
                    "节 {},{} 的数据范围 {offset:#x}..{end:#x} 不在所在段 {} 的文件范围 \
                     {:#x}..{segment_end:#x} 内",
                    section.segname, section.sectname, segment.name, segment.fileoff
                )));
            }
        }
    }
    Ok(())
}

/// 有 objc / swift 元数据节时说明"没解析"。
fn note_objc_and_swift(segments: &[MachOSegment], notes: &mut Vec<String>) {
    let mut objc = 0usize;
    let mut swift = 0usize;
    for segment in segments {
        for section in &segment.sections {
            let name = section.sectname.as_str();
            if name.starts_with("__objc") {
                objc += 1;
            } else if name.starts_with("__swift") {
                swift += 1;
            }
        }
    }
    if objc > 0 {
        notes.push(format!(
            "有 {objc} 个 __objc_* 节（类名/方法名/选择器都在里面）：**没有解析**，\
             所以这些名字不会出现在结果里"
        ));
    }
    if swift > 0 {
        notes.push(format!(
            "有 {swift} 个 __swift* 节：**没有解析**，Swift 类型/函数名不会出现在结果里，\
             也没有做 name demangling"
        ));
    }
}

// ── 入口点与对象模型 ────────────────────────────────────────────────────────

/// 决定入口点。
fn resolve_entry(
    header: &MachHeader,
    facts: &CommandFacts,
    notes: &mut Vec<String>,
) -> Option<EntryPoint> {
    if facts.entry_off.is_some() && facts.unix_thread.is_some() {
        notes.push(
            "同时存在 LC_MAIN 与 LC_UNIXTHREAD：按 LC_MAIN 取入口点\
             （dyld 启动主可执行文件用的就是它）"
                .to_string(),
        );
    }

    if let Some(entryoff) = facts.entry_off {
        // 找文件范围覆盖 entryoff 的段。`__TEXT` 的 fileoff 通常是 0，所以绝大多数
        // 情况下命中的就是它；用"覆盖"而不是"名字等于 __TEXT"是为了不假设某个
        // 文件的段布局。
        let mapped = facts.segments.iter().find_map(|segment| {
            if segment.filesize == 0 || entryoff < segment.fileoff {
                return None;
            }
            let delta = entryoff - segment.fileoff;
            if delta >= segment.filesize {
                return None;
            }
            Some((segment, segment.vmaddr.wrapping_add(delta)))
        });
        return match mapped {
            Some((segment, vaddr)) => {
                notes.push(format!(
                    "入口点来自 LC_MAIN.entryoff = {entryoff:#x}（**文件偏移**），\
                     按段 {} 的 (fileoff = {:#x}, vmaddr = {:#x}) 换算成虚拟地址 {vaddr:#x}",
                    segment.name, segment.fileoff, segment.vmaddr
                ));
                Some(EntryPoint {
                    vaddr,
                    source: EntrySource::Main { entryoff },
                })
            }
            None => {
                notes.push(format!(
                    "LC_MAIN.entryoff = {entryoff:#x} 是文件偏移，但没有任何段的文件范围覆盖它：\
                     入口点记为未知（不猜）"
                ));
                None
            }
        };
    }

    let thread = facts.unix_thread.as_ref()?;
    let expected = thread_state_slot(header.cputype).map_or_else(
        || format!("cputype = {:#x} 不在已解的线程状态表里", header.cputype),
        |slot| {
            format!(
                "期望 flavor = {:#x} / count = {}，实际 flavor = {:#x} / count = {}",
                slot.flavor, slot.count, thread.flavor, thread.count
            )
        },
    );
    match thread.pc {
        Some(0) => {
            notes.push(
                "LC_UNIXTHREAD 的 PC 是 0：不把它当入口点（0 更像\"没填\"而不是\"入口在 0\"）"
                    .to_string(),
            );
            None
        }
        Some(pc) => {
            notes.push(format!(
                "入口点来自 LC_UNIXTHREAD 的线程状态（flavor = {:#x} / count = {}）：\
                 PC = {pc:#x}。线程状态里的 PC **本身就是虚拟地址**，没有做偏移换算",
                thread.flavor, thread.count
            ));
            Some(EntryPoint {
                vaddr: pc,
                source: EntrySource::UnixThread {
                    flavor: thread.flavor,
                    count: thread.count,
                },
            })
        }
        None => {
            notes.push(format!(
                "存在 LC_UNIXTHREAD，但线程状态没有解出 PC（{expected}）：\
                 入口点记为未知，没有猜"
            ));
            None
        }
    }
}

/// `filetype` → 面向用户的说明。
fn filetype_label(filetype: u32) -> String {
    match filetype {
        MH_OBJECT => "MH_OBJECT（可重定位目标文件）".to_string(),
        MH_EXECUTE => "MH_EXECUTE（可执行文件）".to_string(),
        MH_DYLIB => "MH_DYLIB（动态库）".to_string(),
        MH_BUNDLE => "MH_BUNDLE（bundle / 插件）".to_string(),
        MH_DSYM => "MH_DSYM（调试符号文件）".to_string(),
        _ => format!("filetype {filetype}（未知）"),
    }
}

/// 段权限（`initprot`）。
///
/// 用 `initprot` 而不是 `maxprot`：前者是**运行期初始权限**，分析要问的正是
/// "这段内存能不能执行"；`maxprot` 只是上限。
fn segment_perms(initprot: i32) -> Perms {
    Perms {
        read: initprot & VM_PROT_READ != 0,
        write: initprot & VM_PROT_WRITE != 0,
        execute: initprot & VM_PROT_EXECUTE != 0,
    }
}

fn is_zerofill_section(flags: u32) -> bool {
    matches!(
        flags & 0xff,
        SECTION_TYPE_ZEROFILL | SECTION_TYPE_GB_ZEROFILL | SECTION_TYPE_TLS_ZEROFILL
    )
}

fn is_executable_section(flags: u32) -> bool {
    flags & (SECTION_ATTR_PURE_INSTRUCTIONS | SECTION_ATTR_SOME_INSTRUCTIONS) != 0
}

/// 段的内容类别。
///
/// Mach-O 的段**没有** ELF 那种 `sh_type` 语义，只有名字与权限可用 ——
/// 所以这是一条**按名字/权限的启发式**，认不出来就 `Unknown`（不猜）。
fn segment_kind(segment: &MachOSegment, perms: Perms) -> ContentKind {
    if segment.name == "__LINKEDIT" {
        return ContentKind::Dynamic;
    }
    if segment.name.starts_with("__DWARF") {
        return ContentKind::Debug;
    }
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

/// 节的内容类别（同样按名字/标志的启发式，认不出来就 `Unknown`）。
fn section_kind(segment_name: &str, section: &MachOSection) -> ContentKind {
    if segment_name.starts_with("__DWARF") || section.sectname.starts_with("__debug") {
        return ContentKind::Debug;
    }
    if is_zerofill_section(section.flags) {
        return ContentKind::Bss;
    }
    if is_executable_section(section.flags) {
        return ContentKind::Code;
    }
    match segment_name {
        "__TEXT" => ContentKind::ReadOnlyData,
        "__OBJC" | "__AUTH" | "__AUTH_CONST" => ContentKind::Data,
        name if name.starts_with("__DATA") => ContentKind::Data,
        _ => ContentKind::Unknown,
    }
}

/// 把结构层事实组装成对象模型。
fn build_object(file: &MachOFile, id: ObjectId) -> Object {
    let mut object = Object::new(id, ObjectKind::MachO, file.arch, file.endian);

    object.format = FormatInfo {
        type_name: Some(filetype_label(file.filetype)),
        // Mach-O 头里没有 OS/ABI 字段：平台信息在 `LC_BUILD_VERSION` /
        // `LC_VERSION_MIN_*` 这类命令里，而它们本片没解析 —— 所以留 `None`
        // 而不是拿 cputype 猜一个平台。
        os_abi: None,
        subsystem: None,
        is_dynamic_library: file.filetype == MH_DYLIB,
        is_executable: file.filetype == MH_EXECUTE,
        is_relocatable: file.filetype == MH_OBJECT,
        // 判据是"有没有 LC_SYMTAB"，**不是**符号表被解析过。符号表本身没解析，
        // 这一点在 notes 里另外说明。
        is_stripped: !file.has_symtab,
        declared_size: None,
    };
    object.header_flags = Some(file.flags);
    object.image_base = file.image_base.unwrap_or(0);
    object.entry = file.entry.map(|entry| entry.vaddr);

    for state in &file.segments {
        let perms = segment_perms(state.initprot);

        // 段的对齐：Mach-O 的段命令**没有** align 字段（只有节有，且是以 2 为底的
        // 对数）。这里取段内节的最大对齐；没有节时记 0（未知）。
        let align = state
            .sections
            .iter()
            .filter_map(|section| 1u64.checked_shl(section.align))
            .max()
            .unwrap_or(0);

        object.segments.push(Segment {
            name: state.name.clone(),
            vaddr: state.vmaddr,
            vsize: state.vmsize,
            file: if state.filesize > 0 {
                Some(FileRange::new(state.fileoff, state.filesize))
            } else {
                None
            },
            perms,
            kind: segment_kind(state, perms),
            align,
        });

        for section in &state.sections {
            // 节名的身份是 (segname, sectname) 这一**对** —— 不同段里可以有同名节
            // （`__TEXT,__const` 与 `__DATA,__const` 都真实存在）。`segname,sectname`
            // 的写法与 `otool -l` 的输出一致，不会把两个不同的节合并成一个名字。
            let name = if section.segname.is_empty() {
                section.sectname.clone()
            } else {
                format!("{},{}", section.segname, section.sectname)
            };

            // 零填充节在文件里**没有**字节：`file` 给 0 长度（而不是把 offset 当真）。
            let file_range = if is_zerofill_section(section.flags) {
                FileRange::new(u64::from(section.offset), 0)
            } else {
                FileRange::new(u64::from(section.offset), section.size)
            };

            object.sections.push(Section {
                name,
                vaddr: section.addr,
                file: file_range,
                perms: Perms {
                    // 节自己没有权限字段：读/写取自所在段的 initprot，
                    // 可执行性取自节标志（段是 r-x 不代表 __cstring 是代码）。
                    read: perms.read,
                    write: perms.write,
                    execute: is_executable_section(section.flags),
                },
                kind: section_kind(&state.name, section),
                // `__DWARF` 段不参与运行期映射（dSYM 里的调试段）。
                loaded: !state.name.starts_with("__DWARF") && state.vmsize > 0,
            });
        }
    }

    for note in &file.notes {
        object.note(note.clone());
    }

    object
}

/// 合成样本构造器：**单测与集成测试共用同一份**（理由见该文件的模块文档）。
///
/// 两个测试文件都从这里取，而不是各自 `#[path]` 引一次 —— 同一个文件在一个 crate
/// 里被当模块加载两次，rustc 会直接报 "file is loaded as a module multiple times"。
#[cfg(test)]
#[path = "../../../tests/common/macho_fixture.rs"]
mod fixture;

#[cfg(test)]
mod tests;
