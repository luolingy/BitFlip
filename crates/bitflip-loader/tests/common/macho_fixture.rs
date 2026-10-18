//! 合成 Mach-O 样本：**逐字节按规范拼，不按解析器的实现拼**（CLAUDE.md §6.11）。
//!
//! 这份构造器被两处共用：
//!
//! * 单元测试：`src/format/macho/mod.rs` 里的 `#[cfg(test)] #[path] mod fixture`
//!   （薄 Mach-O 的 `tests.rs` 与 fat 的 `fat/tests.rs` 都从那里取，**一个 crate
//!   里同一个文件只能当模块加载一次**）；
//! * 集成测试：`tests/macho_thin.rs`（`#[path = "common/macho_fixture.rs"] mod fixture`）。
//!
//! 共用是刻意的：两份拼法迟早有一份先过时，而过时的那一份会让"单测是绿的"
//! 变成一句谎话（§6.11 的教训正是合成镜像按同一个错误假设拼出来）。
//! **唯一的规矩是：这里只按规范写字节，不许 `use` 任何解析代码。**
//!
//! # 规范出处与字段偏移
//!
//! 全部出自 Apple XNU 的 `EXTERNAL_HEADERS`：
//!
//! ```text
//! mach-o/loader.h
//!   struct mach_header {                  // 32 位，28 字节
//!     uint32_t magic;        +0
//!     cpu_type_t cputype;    +4
//!     cpu_subtype_t cpusubtype; +8
//!     uint32_t filetype;     +12
//!     uint32_t ncmds;        +16
//!     uint32_t sizeofcmds;   +20
//!     uint32_t flags;        +24
//!   };
//!   struct mach_header_64 {               // 64 位，32 字节（末尾多 reserved）
//!     ... 同上 ...           +0..+24
//!     uint32_t reserved;     +28
//!   };
//!   struct segment_command {              // 32 位，56 字节
//!     uint32_t cmd;          +0   (= LC_SEGMENT 0x1)
//!     uint32_t cmdsize;      +4
//!     char     segname[16];  +8
//!     uint32_t vmaddr;       +24
//!     uint32_t vmsize;       +28
//!     uint32_t fileoff;      +32
//!     uint32_t filesize;     +36
//!     vm_prot_t maxprot;     +40
//!     vm_prot_t initprot;    +44
//!     uint32_t nsects;       +48
//!     uint32_t flags;        +52
//!   };
//!   struct segment_command_64 {           // 64 位，72 字节
//!     uint32_t cmd;          +0   (= LC_SEGMENT_64 0x19)
//!     uint32_t cmdsize;      +4
//!     char     segname[16];  +8
//!     uint64_t vmaddr;       +24
//!     uint64_t vmsize;       +32
//!     uint64_t fileoff;      +40
//!     uint64_t filesize;     +48
//!     vm_prot_t maxprot;     +56
//!     vm_prot_t initprot;    +60
//!     uint32_t nsects;       +64
//!     uint32_t flags;        +68
//!   };
//!   struct section {                      // 32 位，68 字节
//!     char     sectname[16]; +0
//!     char     segname[16];  +16
//!     uint32_t addr;         +32
//!     uint32_t size;         +36
//!     uint32_t offset;       +40
//!     uint32_t align;        +44   (log2)
//!     uint32_t reloff;       +48
//!     uint32_t nreloc;       +52
//!     uint32_t flags;        +56
//!     uint32_t reserved1;    +60
//!     uint32_t reserved2;    +64
//!   };
//!   struct section_64 {                   // 64 位，80 字节
//!     char     sectname[16]; +0
//!     char     segname[16];  +16
//!     uint64_t addr;         +32
//!     uint64_t size;         +40
//!     uint32_t offset;       +48
//!     uint32_t align;        +52   (log2)
//!     uint32_t reloff;       +56
//!     uint32_t nreloc;       +60
//!     uint32_t flags;        +64
//!     uint32_t reserved1;    +68
//!     uint32_t reserved2;    +72
//!     uint32_t reserved3;    +76
//!   };
//!   struct entry_point_command {          // LC_MAIN 0x80000028，24 字节
//!     uint32_t cmd; uint32_t cmdsize; uint64_t entryoff; uint64_t stacksize;
//!   };
//!   struct uuid_command {                 // LC_UUID 0x1b，24 字节
//!     uint32_t cmd; uint32_t cmdsize; unsigned char uuid[16];
//!   };
//!   struct dylib_command {                // LC_LOAD_DYLIB 0xc，24 字节 + 名字
//!     uint32_t cmd; uint32_t cmdsize;
//!     struct dylib { uint32_t name;       // 名字相对**本条命令起点**的偏移
//!                    uint32_t timestamp; uint32_t current_version;
//!                    uint32_t compatibility_version; } dylib;
//!   };
//!   struct thread_command {               // LC_UNIXTHREAD 0x5
//!     uint32_t cmd; uint32_t cmdsize; uint32_t flavor; uint32_t count;
//!     uint32_t state[count];              // count 以 32 位字为单位
//!   };
//!   struct symtab_command {               // LC_SYMTAB 0x2，24 字节
//!     uint32_t cmd;          +0
//!     uint32_t cmdsize;      +4
//!     uint32_t symoff;       +8   符号表在文件里的偏移
//!     uint32_t nsyms;        +12  符号条目数
//!     uint32_t stroff;       +16  字符串表在文件里的偏移
//!     uint32_t strsize;      +20  字符串表的字节数
//!   };
//!   struct nlist_64 {                     // 64 位，16 字节
//!     uint32_t n_strx;       +0   名字在字符串表里的偏移（0 = 没有名字）
//!     uint8_t  n_type;       +4
//!     uint8_t  n_sect;       +5   1 基节号；0 = NO_SECT
//!     uint16_t n_desc;       +6
//!     uint64_t n_value;      +8
//!   };
//!   struct nlist {                        // 32 位，12 字节（只有 n_value 窄了）
//!     uint32_t n_strx;       +0
//!     uint8_t  n_type;       +4
//!     uint8_t  n_sect;       +5
//!     uint16_t n_desc;       +6
//!     uint32_t n_value;      +8
//!   };
//!   struct linkedit_data_command {        // LC_FUNCTION_STARTS 0x26，16 字节
//!     uint32_t cmd;          +0
//!     uint32_t cmdsize;      +4
//!     uint32_t dataoff;      +8
//!     uint32_t datasize;     +12
//!   };
//!   struct dyld_info_command {            // LC_DYLD_INFO 0x22 / LC_DYLD_INFO_ONLY 0x80000022
//!     uint32_t cmd;            +0         // 48 字节
//!     uint32_t cmdsize;        +4
//!     uint32_t rebase_off;     +0x08
//!     uint32_t rebase_size;    +0x0C
//!     uint32_t bind_off;       +0x10
//!     uint32_t bind_size;      +0x14
//!     uint32_t weak_bind_off;  +0x18
//!     uint32_t weak_bind_size; +0x1C
//!     uint32_t lazy_bind_off;  +0x20
//!     uint32_t lazy_bind_size; +0x24
//!     uint32_t export_off;     +0x28
//!     uint32_t export_size;    +0x2C
//!   };
//! ```
//!
//! 导出 trie 与 dyld 绑定操作码的编码见本文件后半段对应的构造器（那里同样逐条
//! 写了规范里的一句话依据）。
//!
//! mach-o/nlist.h 的 `n_type` 位（注意 `N_SECT` 是 `N_TYPE` 里的**取值** 0xe，
//! 不是单独的一位）：
//!
//! ```text
//! N_STAB 0xe0   N_PEXT 0x10   N_TYPE 0x0e   N_EXT 0x01
//! N_UNDF 0x0    N_ABS  0x2    N_SECT 0xe    N_PBUD 0xc
//! N_WEAK_REF 0x0040 (n_desc)  N_WEAK_DEF 0x0080 (n_desc)
//! ```
//!
//! `LC_FUNCTION_STARTS` 的 payload 是 ULEB128 增量序列：第一个值相对镜像基址
//! （`__TEXT.vmaddr`），其后每个值相对上一个函数起点，0 字节终止。ULEB128 的
//! 编码是"每字节低 7 位有效、最高位表示还有下一个字节"，字节顺序为小端序。
//!
//! mach-o/fat.h
//!   struct fat_header {                   // 8 字节，**恒为大端**
//!     uint32_t magic;        +0   (= FAT_MAGIC 0xcafebabe / FAT_MAGIC_64 0xcafebabf)
//!     uint32_t nfat_arch;    +4
//!   };
//!   struct fat_arch {                     // 20 字节，大端
//!     uint32_t cputype; +0  cpu_subtype_t cpusubtype; +4
//!     uint32_t offset;  +8  uint32_t size; +12  uint32_t align; +16
//!   };
//!   struct fat_arch_64 {                  // 32 字节，大端
//!     uint32_t cputype; +0  uint32_t cpusubtype; +4
//!     uint64_t offset;  +8  uint64_t size;  +16
//!     uint32_t align;   +24 uint32_t reserved; +28
//!   };
//! ```
//!
//! 另外几个规范常量（同样出自 `loader.h` / `machine.h` / `vm_prot.h`）：
//!
//! * 小端 32 位魔数是 `0xFEEDFACE`，**文件里的字节**是 `CE FA ED FE`；
//!   大端 32 位是 `0xCEFAEDFE`（字节 `FE ED FA CE`）。64 位同理换 `CF`。
//! * `sectname`/`segname` 是 NUL 填充的 16 字节；正好 16 字节的名字没有结尾 NUL。
//! * `section.align` 是**以 2 为底的对数**，不是字节数。
//! * `S_ATTR_PURE_INSTRUCTIONS = 0x80000000`、`S_ATTR_SOME_INSTRUCTIONS = 0x00000400`，
//!   代码节通常两个都置上（`0x80000400`）；`S_ZEROFILL = 0x1`。
//! * `VM_PROT_READ = 1`、`VM_PROT_WRITE = 2`、`VM_PROT_EXECUTE = 4`。
//!
//! # 这个构造器负责什么、不负责什么
//!
//! 它负责：头、命令区、节数据的**文件偏移分配**（和真实链接器一样，节数据紧接
//! 命令区）、以及把文件补齐到"所有段声明的文件范围"都能落下的长度。
//!
//! 它**不**替调用方保证语义正确：比如段 `filesize` 写多大、`entryoff` 落在哪个段，
//! 都由调用方给 —— 那正是测试要断言的东西。

#![allow(dead_code)]

// ── 规范常量（故意在这里重写一遍，不引用解析器的常量） ──────────────────────

/// `MH_MAGIC`：32 位小端文件里**按小端读**到的值。
pub const MH_MAGIC: u32 = 0xfeed_face;
/// `MH_MAGIC_64`。
pub const MH_MAGIC_64: u32 = 0xfeed_facf;
/// `MH_CIGAM`：32 位大端文件里按小端读到的值。
pub const MH_CIGAM: u32 = 0xcefa_edfe;
/// `MH_CIGAM_64`。
pub const MH_CIGAM_64: u32 = 0xcffa_edfe;

/// `MH_EXECUTE`。
pub const MH_EXECUTE: u32 = 0x2;
/// `LC_SEGMENT`。
pub const LC_SEGMENT: u32 = 0x1;
/// `LC_SEGMENT_64`。
pub const LC_SEGMENT_64: u32 = 0x19;
/// `LC_MAIN`。
pub const LC_MAIN: u32 = 0x8000_0028;
/// `LC_UUID`。
pub const LC_UUID: u32 = 0x1b;
/// `LC_LOAD_DYLIB`。
pub const LC_LOAD_DYLIB: u32 = 0xc;
/// `LC_LOAD_WEAK_DYLIB`。
pub const LC_LOAD_WEAK_DYLIB: u32 = 0x8000_0018;
/// `LC_UNIXTHREAD`。
pub const LC_UNIXTHREAD: u32 = 0x5;
/// `LC_SYMTAB`。
pub const LC_SYMTAB: u32 = 0x2;
/// `LC_FUNCTION_STARTS`。
pub const LC_FUNCTION_STARTS: u32 = 0x26;
/// `LC_DYLD_INFO_ONLY`（带 `LC_REQ_DYLD` 位的 `LC_DYLD_INFO`）。
pub const LC_DYLD_INFO_ONLY: u32 = 0x8000_0022;
/// `LC_DYLD_EXPORTS_TRIE`（导出 trie 的独立命令形式）。
pub const LC_DYLD_EXPORTS_TRIE: u32 = 0x8000_0033;
/// `LC_DYLD_CHAINED_FIXUPS`（链式修复；`linkedit_data_command` 形式，iOS 13+）。
pub const LC_DYLD_CHAINED_FIXUPS: u32 = 0x8000_0034;

/// `nlist.n_type` 的位（`mach-o/nlist.h`）。
pub const N_STAB: u8 = 0xe0;
/// `N_PEXT`。
pub const N_PEXT: u8 = 0x10;
/// `N_TYPE`（类型位掩码）。
pub const N_TYPE: u8 = 0x0e;
/// `N_EXT`（外部符号位）。
pub const N_EXT: u8 = 0x01;
/// `N_UNDF`（未定义；`n_sect == NO_SECT`）。
pub const N_UNDF: u8 = 0x0;
/// `N_SECT`（定义在 `n_sect` 号节里）。注意它是 `N_TYPE` 的取值 0xe。
pub const N_SECT: u8 = 0xe;
/// `N_FUN`（`N_STAB` 一族的函数调试条目）：`0x24 & N_STAB == 0x20`，所以它算 stab。
pub const N_FUN: u8 = 0x24;
/// `N_WEAK_DEF`（`n_desc`）：弱定义。
pub const N_WEAK_DEF: u16 = 0x0080;

/// `sizeof(struct nlist_64)`。
pub const NLIST64_SIZE: usize = 16;
/// `sizeof(struct nlist)`。
pub const NLIST32_SIZE: usize = 12;

/// `CPU_TYPE_X86`。
pub const CPU_TYPE_X86: u32 = 7;
/// `CPU_TYPE_X86_64`。
pub const CPU_TYPE_X86_64: u32 = 0x0100_0007;
/// `CPU_TYPE_ARM`。
pub const CPU_TYPE_ARM: u32 = 12;
/// `CPU_TYPE_ARM64`。
pub const CPU_TYPE_ARM64: u32 = 0x0100_000c;
/// `CPU_TYPE_POWERPC`（`mach/machine.h`：18）。
pub const CPU_TYPE_POWERPC: u32 = 18;
/// `CPU_TYPE_POWERPC64`（`CPU_TYPE_POWERPC | CPU_ARCH_ABI64` = `0x01000012`）。
pub const CPU_TYPE_POWERPC64: u32 = 0x0100_0012;
/// `CPU_SUBTYPE_ARM64E`（与 `CPU_TYPE_ARM64` 共用 cputype）。
pub const CPU_SUBTYPE_ARM64E: u32 = 2;

/// `S_ATTR_PURE_INSTRUCTIONS | S_ATTR_SOME_INSTRUCTIONS`（代码节的典型 flags）。
pub const CODE_FLAGS: u32 = 0x8000_0400;
/// `S_ZEROFILL`。
pub const SECTION_ZEROFILL: u32 = 0x1;

/// `VM_PROT_READ | VM_PROT_EXECUTE`（`__TEXT` 的典型 initprot）。
pub const RX: u32 = 1 | 4;
/// `VM_PROT_READ | VM_PROT_WRITE`（`__DATA` 的典型 initprot）。
pub const RW: u32 = 1 | 2;
/// `VM_PROT_READ`（`__LINKEDIT` 的典型 initprot）。
pub const R_ONLY: u32 = 1;

// ── 字节写入 ────────────────────────────────────────────────────────────────

fn put_u32(out: &mut [u8], offset: usize, value: u32, little: bool) {
    let raw = if little {
        value.to_le_bytes()
    } else {
        value.to_be_bytes()
    };
    out[offset..offset + 4].copy_from_slice(&raw);
}

fn put_u64(out: &mut [u8], offset: usize, value: u64, little: bool) {
    let raw = if little {
        value.to_le_bytes()
    } else {
        value.to_be_bytes()
    };
    out[offset..offset + 8].copy_from_slice(&raw);
}

fn put_name(out: &mut [u8], offset: usize, name: &str) {
    let raw = name.as_bytes();
    // 16 字节定长字段：写满 16 字节就**没有**结尾 NUL（规范允许）。
    let len = raw.len().min(16);
    out[offset..offset + len].copy_from_slice(&raw[..len]);
}

fn align_up(value: u64, align: u64) -> u64 {
    if align <= 1 {
        return value;
    }
    value.div_ceil(align) * align
}

/// 直接改文件里某个 `u32`（造畸形样本时用；`offset` 用上面文档里的字段偏移）。
pub fn patch_u32(bytes: &mut [u8], offset: usize, value: u32, little: bool) {
    put_u32(bytes, offset, value, little);
}

/// 直接改文件里某个 `u64`。
pub fn patch_u64(bytes: &mut [u8], offset: usize, value: u64, little: bool) {
    put_u64(bytes, offset, value, little);
}

// ── 节的规格 ────────────────────────────────────────────────────────────────

/// 一个节的规格（`section` / `section_64` 里除了 `offset` 都由这里给）。
#[derive(Debug, Clone)]
pub struct SectionSpec {
    /// `sectname`。
    pub sectname: &'static str,
    /// 节自带的 `segname`（正常与所在段同名）。
    pub segname: &'static str,
    /// `addr`（虚拟地址）。
    pub addr: u64,
    /// `size`。
    pub size: u64,
    /// `align`（log2）。
    pub align: u32,
    /// `flags`。
    pub flags: u32,
    /// 是否零填充（`S_ZEROFILL`）：文件里没有字节，`offset` 写 0。
    pub zerofill: bool,
}

impl SectionSpec {
    /// 一个普通节（`align = 0`、`flags = 0`、不零填充）。
    #[must_use]
    pub fn new(sectname: &'static str, segname: &'static str, addr: u64, size: u64) -> Self {
        Self {
            sectname,
            segname,
            addr,
            size,
            align: 0,
            flags: 0,
            zerofill: false,
        }
    }

    /// 设置 `align`（log2）。
    #[must_use]
    pub fn align(mut self, align: u32) -> Self {
        self.align = align;
        self
    }

    /// 设置 `flags`。
    #[must_use]
    pub fn flags(mut self, flags: u32) -> Self {
        self.flags = flags;
        self
    }

    /// 改成一个零填充节（`S_ZEROFILL`，文件里没有字节）。
    #[must_use]
    pub fn zerofill(mut self) -> Self {
        self.zerofill = true;
        self.flags = (self.flags & !0xff) | SECTION_ZEROFILL;
        self
    }
}

// ── 段的规格 ────────────────────────────────────────────────────────────────

/// 一个段的规格。
#[derive(Debug, Clone)]
pub struct SegmentSpec {
    /// `segname`。
    pub name: &'static str,
    /// `vmaddr`。
    pub vmaddr: u64,
    /// `vmsize`。
    pub vmsize: u64,
    /// `fileoff`。
    pub fileoff: u64,
    /// `filesize`（`__PAGEZERO` 合法地为 0）。
    pub filesize: u64,
    /// `maxprot`。
    pub maxprot: u32,
    /// `initprot`。
    pub initprot: u32,
    /// `flags`。
    pub flags: u32,
    /// 段内的节。
    pub sections: Vec<SectionSpec>,
}

impl SegmentSpec {
    /// 一个段（`maxprot = initprot`、`flags = 0`）。
    #[must_use]
    pub fn new(name: &'static str, vmaddr: u64, vmsize: u64, fileoff: u64, filesize: u64) -> Self {
        Self {
            name,
            vmaddr,
            vmsize,
            fileoff,
            filesize,
            maxprot: R_ONLY,
            initprot: R_ONLY,
            flags: 0,
            sections: Vec::new(),
        }
    }

    /// 设置权限。
    #[must_use]
    pub fn perms(mut self, maxprot: u32, initprot: u32) -> Self {
        self.maxprot = maxprot;
        self.initprot = initprot;
        self
    }

    /// 追加一个节。
    #[must_use]
    pub fn section(mut self, section: SectionSpec) -> Self {
        self.sections.push(section);
        self
    }
}

// ── 追加命令 ────────────────────────────────────────────────────────────────

/// 一条"除段命令之外"的加载命令（字节已经是完整的命令，含 `cmd` 与 `cmdsize`）。
#[derive(Debug, Clone)]
pub struct RawCommand {
    /// 命令字节。
    pub bytes: Vec<u8>,
}

/// `LC_MAIN`：`entryoff` 是**文件偏移**。
#[must_use]
pub fn lc_main(entryoff: u64, stacksize: u64, little: bool) -> RawCommand {
    let mut bytes = vec![0u8; 24];
    put_u32(&mut bytes, 0, LC_MAIN, little);
    put_u32(&mut bytes, 4, 24, little);
    put_u64(&mut bytes, 8, entryoff, little);
    put_u64(&mut bytes, 16, stacksize, little);
    RawCommand { bytes }
}

/// `LC_UUID`。
#[must_use]
pub fn lc_uuid(uuid: [u8; 16]) -> RawCommand {
    // `cmd`/`cmdsize` 与端序无关（`cmd` 的取值是规范定的常量，两种端序写法相同）。
    let mut bytes = vec![0u8; 24];
    put_u32(&mut bytes, 0, LC_UUID, true);
    put_u32(&mut bytes, 4, 24, true);
    bytes[8..24].copy_from_slice(&uuid);
    RawCommand { bytes }
}

/// `LC_LOAD_DYLIB` / `LC_LOAD_WEAK_DYLIB`。
#[must_use]
pub fn lc_load_dylib(name: &str, weak: bool, little: bool) -> RawCommand {
    let cmd = if weak {
        LC_LOAD_WEAK_DYLIB
    } else {
        LC_LOAD_DYLIB
    };
    // 名字紧跟在 24 字节固定部分之后（`dylib.name` 相对命令起点）。
    let raw_len = 24 + name.len() + 1;
    let cmdsize = align_up(raw_len as u64, 8) as usize;
    let mut bytes = vec![0u8; cmdsize];
    put_u32(&mut bytes, 0, cmd, little);
    put_u32(&mut bytes, 4, cmdsize as u32, little);
    put_u32(&mut bytes, 8, 24, little); // dylib.name
    put_u32(&mut bytes, 12, 2, little); // dylib.timestamp
    put_u32(&mut bytes, 16, 0x0001_0000, little); // dylib.current_version
    put_u32(&mut bytes, 20, 0x0001_0000, little); // dylib.compatibility_version
    bytes[24..24 + name.len()].copy_from_slice(name.as_bytes());
    RawCommand { bytes }
}

/// `LC_UNIXTHREAD`：`state` 按给定的 `flavor` / `count` 原样写入。
///
/// `state.len()` 必须等于 `count`（调用方自己保证；这里按给的长度写）。
#[must_use]
pub fn lc_unix_thread(flavor: u32, count: u32, state: &[u32], little: bool) -> RawCommand {
    let cmdsize = 16 + state.len() * 4;
    let mut bytes = vec![0u8; cmdsize];
    put_u32(&mut bytes, 0, LC_UNIXTHREAD, little);
    put_u32(&mut bytes, 4, cmdsize as u32, little);
    put_u32(&mut bytes, 8, flavor, little);
    put_u32(&mut bytes, 12, count, little);
    for (index, word) in state.iter().enumerate() {
        put_u32(&mut bytes, 16 + index * 4, *word, little);
    }
    RawCommand { bytes }
}

/// `LC_SYMTAB`（`struct symtab_command`，24 字节）。
///
/// 字段偏移见模块文档：`symoff +8`、`nsyms +0xC`、`stroff +0x10`、`strsize +0x14`。
#[must_use]
pub fn lc_symtab(symoff: u32, nsyms: u32, stroff: u32, strsize: u32, little: bool) -> RawCommand {
    let mut bytes = vec![0u8; 24];
    put_u32(&mut bytes, 0, LC_SYMTAB, little);
    put_u32(&mut bytes, 4, 24, little);
    put_u32(&mut bytes, 8, symoff, little);
    put_u32(&mut bytes, 12, nsyms, little);
    put_u32(&mut bytes, 16, stroff, little);
    put_u32(&mut bytes, 20, strsize, little);
    RawCommand { bytes }
}

/// `LC_FUNCTION_STARTS`（`struct linkedit_data_command`，16 字节）。
#[must_use]
pub fn lc_function_starts(dataoff: u32, datasize: u32, little: bool) -> RawCommand {
    let mut bytes = vec![0u8; 16];
    put_u32(&mut bytes, 0, LC_FUNCTION_STARTS, little);
    put_u32(&mut bytes, 4, 16, little);
    put_u32(&mut bytes, 8, dataoff, little);
    put_u32(&mut bytes, 12, datasize, little);
    RawCommand { bytes }
}

/// `LC_DYLD_INFO_ONLY`（`dyld_info_command`：cmd + cmdsize + 5 对 `uint32`，共 48 字节）。
///
/// 真实可执行文件几乎都有它（新版换成了 `LC_DYLD_CHAINED_FIXUPS`）。
/// 这里的偏移/长度全写 0：本片不读里面的内容，只验证"存在但没解析"这条说明。
#[must_use]
pub fn lc_dyld_info_only(little: bool) -> RawCommand {
    let mut bytes = vec![0u8; 48];
    put_u32(&mut bytes, 0, LC_DYLD_INFO_ONLY, little);
    put_u32(&mut bytes, 4, 48, little);
    RawCommand { bytes }
}

// ── 薄 Mach-O 的规格与构造 ──────────────────────────────────────────────────

/// 一层薄 Mach-O 的完整规格。
#[derive(Debug, Clone)]
pub struct ThinSpec {
    /// 32 位还是 64 位（决定魔数与头部尺寸）。
    pub is_64: bool,
    /// 小端文件？`false` = 大端（`MH_CIGAM` / `MH_CIGAM_64`）。
    pub little: bool,
    /// `cputype`。
    pub cputype: u32,
    /// `cpusubtype`。
    pub cpusubtype: u32,
    /// `filetype`。
    pub filetype: u32,
    /// 头部 `flags`。
    pub flags: u32,
    /// 段（按命令顺序写在其余命令之前）。
    pub segments: Vec<SegmentSpec>,
    /// 段命令之后的其它命令。
    pub commands: Vec<RawCommand>,
    /// 覆盖头里的 `ncmds`（造畸形样本）。
    pub ncmds_override: Option<u32>,
    /// 覆盖头里的 `sizeofcmds`（造畸形样本）。
    pub sizeofcmds_override: Option<u32>,
    /// 文件至少补齐到这个长度（不够就用 0 填）。
    pub min_file_size: u64,
}

impl ThinSpec {
    /// 一份 64 位小端样本的骨架（无段、无命令）。
    #[must_use]
    pub fn new64(cputype: u32, cpusubtype: u32) -> Self {
        Self {
            is_64: true,
            little: true,
            cputype,
            cpusubtype,
            filetype: MH_EXECUTE,
            flags: 0,
            segments: Vec::new(),
            commands: Vec::new(),
            ncmds_override: None,
            sizeofcmds_override: None,
            min_file_size: 0,
        }
    }

    /// 一份 32 位小端样本的骨架（无段、无命令）。
    #[must_use]
    pub fn new32(cputype: u32, cpusubtype: u32) -> Self {
        Self {
            is_64: false,
            little: true,
            cputype,
            cpusubtype,
            filetype: MH_EXECUTE,
            flags: 0,
            segments: Vec::new(),
            commands: Vec::new(),
            ncmds_override: None,
            sizeofcmds_override: None,
            min_file_size: 0,
        }
    }

    /// 改成大端文件。
    #[must_use]
    pub fn big_endian(mut self) -> Self {
        self.little = false;
        self
    }

    /// 追加一个段。
    #[must_use]
    pub fn segment(mut self, segment: SegmentSpec) -> Self {
        self.segments.push(segment);
        self
    }

    /// 追加一条非段命令。
    #[must_use]
    pub fn command(mut self, command: RawCommand) -> Self {
        self.commands.push(command);
        self
    }

    /// 设置最小文件长度。
    #[must_use]
    pub fn min_file_size(mut self, size: u64) -> Self {
        self.min_file_size = size;
        self
    }

    /// 头部尺寸（28 / 32）。
    #[must_use]
    pub fn header_size(&self) -> u64 {
        if self.is_64 {
            32
        } else {
            28
        }
    }

    /// 段命令 + 若干定长项的尺寸辅助（只用于内部布局计算）。
    fn segment_command_size(&self, segment: &SegmentSpec) -> u64 {
        let section_size = if self.is_64 { 80 } else { 68 };
        let fixed = if self.is_64 { 72 } else { 56 };
        fixed + segment.sections.len() as u64 * section_size
    }
}

/// 按规格拼出一层薄 Mach-O。
#[must_use]
pub fn build(spec: &ThinSpec) -> Vec<u8> {
    let little = spec.little;
    let magic = match (spec.is_64, little) {
        (true, true) => MH_MAGIC_64,
        (true, false) => MH_CIGAM_64,
        (false, true) => MH_MAGIC,
        (false, false) => MH_CIGAM,
    };
    let header_size = spec.header_size();

    // 第一步：算 sizeofcmds（段命令长度只取决于节数，与数据偏移无关）。
    let mut sizeofcmds = 0u64;
    for segment in &spec.segments {
        sizeofcmds += spec.segment_command_size(segment);
    }
    for command in &spec.commands {
        sizeofcmds += command.bytes.len() as u64;
    }
    let ncmds = (spec.segments.len() + spec.commands.len()) as u32;

    // 第二步：给非零填充节分配文件偏移。数据区紧接命令区之后，
    // 与真实链接器的做法一致（节数据不重叠、按节自己的 align 对齐）。
    //
    // 每个节的偏移取 `max(数据游标, 所在段的 fileoff)`：真实文件里段可以
    // 不连续（`__TEXT` 在 0，`__DATA` 在 0x4000），而**节必须落在自己段的
    // 文件范围内**才会被解析器接受。让构造器自己满足这条契约，测试才能专心
    // 验证"段声明得对不对"。
    let data_start = header_size + sizeofcmds;
    let mut cursor = data_start;
    let mut section_offsets: Vec<Vec<u64>> = Vec::with_capacity(spec.segments.len());
    for segment in &spec.segments {
        let mut offsets = Vec::with_capacity(segment.sections.len());
        for section in &segment.sections {
            if section.zerofill || section.size == 0 {
                // 零填充节在文件里没有字节；规范里这类节的 offset 无意义，写 0。
                offsets.push(0);
                continue;
            }
            let align = 1u64 << section.align.min(32);
            let offset = align_up(cursor.max(segment.fileoff), align);
            offsets.push(offset);
            cursor = offset + section.size;
        }
        section_offsets.push(offsets);
    }

    // 第三步：算文件总长 —— 所有段声明的文件范围、节数据、调用方要求的最小长度。
    let mut file_len = cursor;
    for segment in &spec.segments {
        if segment.filesize > 0 {
            file_len = file_len.max(segment.fileoff + segment.filesize);
        }
    }
    file_len = file_len.max(spec.min_file_size);

    let mut out = vec![0u8; file_len as usize];

    // 第四步：写头。
    put_u32(&mut out, 0, magic, true); // 魔数按小端读的意义写入：见模块文档
    put_u32(&mut out, 4, spec.cputype, little);
    put_u32(&mut out, 8, spec.cpusubtype, little);
    put_u32(&mut out, 12, spec.filetype, little);
    put_u32(&mut out, 16, spec.ncmds_override.unwrap_or(ncmds), little);
    put_u32(
        &mut out,
        20,
        spec.sizeofcmds_override.unwrap_or(sizeofcmds as u32),
        little,
    );
    put_u32(&mut out, 24, spec.flags, little);
    if spec.is_64 {
        put_u32(&mut out, 28, 0, little); // reserved
    }

    // 第五步：写命令区。
    let mut at = header_size as usize;
    for (index, segment) in spec.segments.iter().enumerate() {
        let cmd = if spec.is_64 {
            LC_SEGMENT_64
        } else {
            LC_SEGMENT
        };
        let cmdsize = spec.segment_command_size(segment);
        put_u32(&mut out, at, cmd, little);
        put_u32(&mut out, at + 4, cmdsize as u32, little);
        put_name(&mut out, at + 8, segment.name);
        if spec.is_64 {
            put_u64(&mut out, at + 24, segment.vmaddr, little);
            put_u64(&mut out, at + 32, segment.vmsize, little);
            put_u64(&mut out, at + 40, segment.fileoff, little);
            put_u64(&mut out, at + 48, segment.filesize, little);
            put_u32(&mut out, at + 56, segment.maxprot, little);
            put_u32(&mut out, at + 60, segment.initprot, little);
            put_u32(&mut out, at + 64, segment.sections.len() as u32, little);
            put_u32(&mut out, at + 68, segment.flags, little);
        } else {
            put_u32(&mut out, at + 24, segment.vmaddr as u32, little);
            put_u32(&mut out, at + 28, segment.vmsize as u32, little);
            put_u32(&mut out, at + 32, segment.fileoff as u32, little);
            put_u32(&mut out, at + 36, segment.filesize as u32, little);
            put_u32(&mut out, at + 40, segment.maxprot, little);
            put_u32(&mut out, at + 44, segment.initprot, little);
            put_u32(&mut out, at + 48, segment.sections.len() as u32, little);
            put_u32(&mut out, at + 52, segment.flags, little);
        }
        let section_size = if spec.is_64 { 80usize } else { 68usize };
        let mut section_at = at + if spec.is_64 { 72 } else { 56 };
        for (section_index, section) in segment.sections.iter().enumerate() {
            put_name(&mut out, section_at, section.sectname);
            put_name(&mut out, section_at + 16, section.segname);
            if spec.is_64 {
                put_u64(&mut out, section_at + 32, section.addr, little);
                put_u64(&mut out, section_at + 40, section.size, little);
                put_u32(
                    &mut out,
                    section_at + 48,
                    section_offsets[index][section_index] as u32,
                    little,
                );
                put_u32(&mut out, section_at + 52, section.align, little);
                put_u32(&mut out, section_at + 64, section.flags, little);
            } else {
                put_u32(&mut out, section_at + 32, section.addr as u32, little);
                put_u32(&mut out, section_at + 36, section.size as u32, little);
                put_u32(
                    &mut out,
                    section_at + 40,
                    section_offsets[index][section_index] as u32,
                    little,
                );
                put_u32(&mut out, section_at + 44, section.align, little);
                put_u32(&mut out, section_at + 56, section.flags, little);
            }
            section_at += section_size;
        }
        at += cmdsize as usize;
    }
    for command in &spec.commands {
        out[at..at + command.bytes.len()].copy_from_slice(&command.bytes);
        at += command.bytes.len();
    }

    out
}

// ── 现成的样本 ──────────────────────────────────────────────────────────────

/// 64 位小端、**2 个段 / 3 个节**、带 `LC_MAIN`（`entryoff = 0xF00`）、`LC_UUID`
/// 与两个 dylib 的样本。
///
/// 段布局：
///
/// * `__PAGEZERO`（`vmaddr = 0`、`filesize = 0`、`initprot = 0`）；
/// * `__TEXT`（`vmaddr = 0x1_0000_0000`、`fileoff = 0`、`filesize = 0x4000`、r-x），
///   含 `__text`（代码）、`__cstring`（字面量）、`__const`（只读数据）三个节。
///
/// `LC_MAIN.entryoff = 0xF00` 落在 `__TEXT` 的文件范围内，换算后的虚拟地址应当是
/// `0x1_0000_0F00`。
#[must_use]
pub fn demo_thin64() -> Vec<u8> {
    const TEXT_VMADDR: u64 = 0x1_0000_0000;
    let spec = ThinSpec::new64(CPU_TYPE_X86_64, 3)
        .segment(SegmentSpec::new("__PAGEZERO", 0, 0x1_0000_0000, 0, 0).perms(0, 0))
        .segment(
            SegmentSpec::new("__TEXT", TEXT_VMADDR, 0x4000, 0, 0x4000)
                .perms(RX, RX)
                .section(
                    SectionSpec::new("__text", "__TEXT", TEXT_VMADDR + 0xF00, 0x100)
                        .align(4)
                        .flags(CODE_FLAGS),
                )
                .section(SectionSpec::new(
                    "__cstring",
                    "__TEXT",
                    TEXT_VMADDR + 0x1100,
                    0x40,
                ))
                .section(SectionSpec::new(
                    "__const",
                    "__TEXT",
                    TEXT_VMADDR + 0x1140,
                    0x10,
                )),
        )
        .command(lc_main(0xF00, 0, true))
        .command(lc_uuid([
            0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef, 0xfe, 0xdc, 0xba, 0x98, 0x76, 0x54,
            0x32, 0x10,
        ]))
        .command(lc_load_dylib("/usr/lib/libSystem.B.dylib", false, true))
        .command(lc_load_dylib(
            "/System/Library/Frameworks/UIKit.framework/UIKit",
            true,
            true,
        ))
        // 真实可执行文件几乎都有 LC_DYLD_INFO_ONLY 与 LC_SYMTAB。加进来是为了让
        // "有这条命令但表是空的（nsyms = 0）"与"dyld 绑定没有解析"各走一遍。
        .command(lc_dyld_info_only(true))
        .command(lc_symtab(0, 0, 0, 0, true))
        .min_file_size(0x4000);
    build(&spec)
}

/// 32 位小端、1 个段 / 1 个节、带 `LC_MAIN`（`entryoff = 0x800`）的样本。
///
/// `__TEXT` 的 `vmaddr = 0x1000`、`fileoff = 0`，所以入口换算后是 `0x1800`，
/// 正好是 `__text` 的起始地址。
#[must_use]
pub fn demo_thin32() -> Vec<u8> {
    let spec = ThinSpec::new32(CPU_TYPE_X86, 3)
        .segment(
            SegmentSpec::new("__TEXT", 0x1000, 0x2000, 0, 0x2000)
                .perms(RX, RX)
                .section(
                    SectionSpec::new("__text", "__TEXT", 0x1800, 0x80)
                        .align(4)
                        .flags(CODE_FLAGS),
                ),
        )
        .command(lc_main(0x800, 0, true))
        .min_file_size(0x2000);
    build(&spec)
}

/// 一个 **32 位大端 PowerPC** 的样本：1 个段 / 1 个节、带 `LC_MAIN`。
///
/// 为什么单独有一个 ppc 样本，而不是复用 `demo_thin32`：
///
/// * Mach-O 的 ppc 是**大端**（`MH_CIGAM`，文件里魔数字节是 `FE ED FA CE`），
///   与 x86/arm 的小端样本走的不是同一条读字段的路径；
/// * `cputype = 18` 直到 M12 第二片才被映射成架构（此前是"识别但拒绝"），
///   这一份就是那条路径的回归样本。
///
/// 布局照 `mach-o/loader.h` 与真实 ppc 可执行文件的习惯：`__TEXT` 从
/// `vmaddr = 0x1000` 起、`fileoff = 0`，`LC_MAIN.entryoff = 0x400` 落在
/// `__TEXT` 的文件范围内，换算后的虚拟地址应当是 `0x1400`。
///
/// 注意 `__text` 的字节是**零填充**的（构造器不写机器码）：这份样本证明的是
/// "结构层与架构映射对"，ppc 的**指令解码**由 `bitflip-arch` 的单测用真实
/// 编码的黄金值钉住（`backend::tests` 里的 `addc` / `blr` / `bne`）。
#[must_use]
pub fn demo_thin_ppc32() -> Vec<u8> {
    let spec = ThinSpec::new32(CPU_TYPE_POWERPC, 0)
        .big_endian()
        .segment(
            SegmentSpec::new("__TEXT", 0x1000, 0x1000, 0, 0x1000)
                .perms(RX, RX)
                .section(
                    SectionSpec::new("__text", "__TEXT", 0x1400, 0x40)
                        .align(4)
                        .flags(CODE_FLAGS),
                ),
        )
        .command(lc_main(0x400, 0, false))
        .min_file_size(0x1000);
    build(&spec)
}

/// 一个 **64 位大端 PowerPC** 的样本：1 个段 / 1 个节、带 `LC_MAIN`。
///
/// `cputype = CPU_TYPE_POWERPC64`（`0x01000012`）、`mach_header_64`（32 字节头）。
/// ppc64 的 Mach-O 同样是大端。`__TEXT` 在 `vmaddr = 0x1_0000_0000`、
/// `fileoff = 0`，`LC_MAIN.entryoff = 0x500` → 入口 `0x1_0000_0500`。
#[must_use]
pub fn demo_thin_ppc64() -> Vec<u8> {
    const TEXT_VMADDR: u64 = 0x1_0000_0000;
    let spec = ThinSpec::new64(CPU_TYPE_POWERPC64, 0)
        .big_endian()
        .segment(
            SegmentSpec::new("__TEXT", TEXT_VMADDR, 0x1000, 0, 0x1000)
                .perms(RX, RX)
                .section(
                    SectionSpec::new("__text", "__TEXT", TEXT_VMADDR + 0x500, 0x40)
                        .align(4)
                        .flags(CODE_FLAGS),
                ),
        )
        .command(lc_main(0x500, 0, false))
        .min_file_size(0x1000);
    build(&spec)
}

/// 一个 fat 容器，装着 [`demo_thin32`] 与 [`demo_thin64`] 两层。
///
/// 架构表按 `mach-o/fat.h`：大端头 + 两条 `fat_arch`（20 字节），
/// 切片偏移按 0x1000 对齐（真实 fat 文件的对齐值是 2^12 或 2^14）。
#[must_use]
pub fn demo_fat() -> Vec<u8> {
    let slice0 = demo_thin32();
    let slice1 = demo_thin64();
    let align = 0x1000u64;
    let offset0 = align; // 架构表结束后第一个对齐点（8 + 2*20 = 48 == 0x30）
    let offset1 = align_up(offset0 + slice0.len() as u64, align);
    let total = offset1 + slice1.len() as u64;

    let mut out = vec![0u8; total as usize];
    put_u32(&mut out, 0, 0xcafe_babe, false); // FAT_MAGIC（大端）
    put_u32(&mut out, 4, 2, false); // nfat_arch

    // 第 0 条 fat_arch：32 位 x86 切片。
    put_u32(&mut out, 8, CPU_TYPE_X86, false);
    put_u32(&mut out, 12, 3, false);
    put_u32(&mut out, 16, offset0 as u32, false);
    put_u32(&mut out, 20, slice0.len() as u32, false);
    put_u32(&mut out, 24, 12, false); // align = 2^12

    // 第 1 条 fat_arch：64 位 x86_64 切片。
    put_u32(&mut out, 28, CPU_TYPE_X86_64, false);
    put_u32(&mut out, 32, 3, false);
    put_u32(&mut out, 36, offset1 as u32, false);
    put_u32(&mut out, 40, slice1.len() as u32, false);
    put_u32(&mut out, 44, 12, false);

    out[offset0 as usize..offset0 as usize + slice0.len()].copy_from_slice(&slice0);
    out[offset1 as usize..offset1 as usize + slice1.len()].copy_from_slice(&slice1);
    out
}

/// 一个用 **64 位架构表**（`FAT_MAGIC_64` / `fat_arch_64`，32 字节表项）的 fat 容器，
/// 只装一层 [`demo_thin64`]。
///
/// 存在的理由：`fat_arch_64` 的 `offset`/`size` 是 8 字节，表项多 12 字节 ——
/// 两条表格式都得有样本，否则 64 位那条分支只有"看起来对"的份。
#[must_use]
pub fn demo_fat64() -> Vec<u8> {
    let slice = demo_thin64();
    let offset = 0x1000u64; // 8 + 1*32 = 40，取下一个 0x1000 对齐点
    let total = offset + slice.len() as u64;

    let mut out = vec![0u8; total as usize];
    put_u32(&mut out, 0, 0xcafe_babf, false); // FAT_MAGIC_64（大端）
    put_u32(&mut out, 4, 1, false); // nfat_arch

    // fat_arch_64：cputype +0、cpusubtype +4、offset +8（8 字节）、
    // size +16（8 字节）、align +24、reserved +28。
    put_u32(&mut out, 8, CPU_TYPE_X86_64, false);
    put_u32(&mut out, 12, 3, false);
    put_u64(&mut out, 16, offset, false);
    put_u64(&mut out, 24, slice.len() as u64, false);
    put_u32(&mut out, 32, 12, false);
    put_u32(&mut out, 36, 0, false);

    out[offset as usize..offset as usize + slice.len()].copy_from_slice(&slice);
    out
}

// ── 符号表（LC_SYMTAB）与函数起点（LC_FUNCTION_STARTS） ────────────────────

/// 一条 `nlist` / `nlist_64` 的规格（字段语义见 `mach-o/nlist.h`，偏移见模块文档）。
#[derive(Debug, Clone, Copy)]
pub struct NlistSpec {
    /// `n_strx`：名字在字符串表里的偏移（0 = 没有名字）。
    pub n_strx: u32,
    /// `n_type`。
    pub n_type: u8,
    /// `n_sect`（1 基；0 = `NO_SECT`）。
    pub n_sect: u8,
    /// `n_desc`。
    pub n_desc: u16,
    /// `n_value`。
    pub n_value: u64,
}

impl NlistSpec {
    /// 一条 `n_desc = 0` 的符号。
    #[must_use]
    pub const fn new(n_strx: u32, n_type: u8, n_sect: u8, n_value: u64) -> Self {
        Self {
            n_strx,
            n_type,
            n_sect,
            n_desc: 0,
            n_value,
        }
    }
}

/// 按规范布局编码一条符号（`nlist_64` 16 字节 / `nlist` 12 字节）。
fn encode_nlist(spec: &NlistSpec, is_64: bool, little: bool) -> Vec<u8> {
    let mut out = vec![0u8; if is_64 { NLIST64_SIZE } else { NLIST32_SIZE }];
    put_u32(&mut out, 0, spec.n_strx, little);
    out[4] = spec.n_type;
    out[5] = spec.n_sect;
    // `n_desc` 在规范里是 `int16_t`：按位原样写（弱符号位在低位）。
    let desc = if little {
        spec.n_desc.to_le_bytes()
    } else {
        spec.n_desc.to_be_bytes()
    };
    out[6..8].copy_from_slice(&desc);
    if is_64 {
        put_u64(&mut out, 8, spec.n_value, little);
    } else {
        put_u32(&mut out, 8, spec.n_value as u32, little);
    }
    out
}

/// 字符串表（`LC_SYMTAB.strsize` 那段）：`n_strx` 是表内**字节偏移**。
///
/// 一开始就写一个前缀字节（空格 `0x20`），所以第一条放进来的名字偏移是 **1**
/// 而不是 0 —— 这正是这份样本要钉住的东西：解析器必须按 `n_strx` 取名字，
/// 而不是"按顺序取下一个"，也不是"假定偏移 0 就是第一个名字"。
#[derive(Debug, Clone)]
pub struct StringTable {
    bytes: Vec<u8>,
}

impl StringTable {
    /// 空表 + 一个前缀字节。
    #[must_use]
    pub fn new() -> Self {
        Self { bytes: vec![b' '] }
    }

    /// 追加一个名字，返回它的 `n_strx`。
    pub fn add(&mut self, name: &str) -> u32 {
        let offset = self.bytes.len() as u32;
        self.bytes.extend_from_slice(name.as_bytes());
        self.bytes.push(0);
        offset
    }

    /// 表里的字节。
    #[must_use]
    pub fn bytes(&self) -> &[u8] {
        &self.bytes
    }

    /// 表的字节数（`LC_SYMTAB.strsize`）。
    #[must_use]
    pub fn len(&self) -> u64 {
        self.bytes.len() as u64
    }
}

impl Default for StringTable {
    fn default() -> Self {
        Self::new()
    }
}

/// 把 `payload` 追加到镜像末尾（按 `align` 对齐、中间补 0），返回它的文件偏移。
fn append_payload(out: &mut Vec<u8>, align: u64, payload: &[u8]) -> u64 {
    let offset = align_up(out.len() as u64, align);
    out.resize(offset as usize, 0);
    out.extend_from_slice(payload);
    offset
}

/// 符号表样本的 64 位骨架：`__PAGEZERO` + `__TEXT`（含 1 个 `__text` 节）。
///
/// 地址空间与 [`demo_thin64`] 同一形状（`__TEXT.vmaddr = 0x1_0000_0000`），
/// 只是 `filesize` 小一些：符号表与字符串表放在文件**末尾**，而段不声明覆盖它们
/// （真实文件里它们在 `__LINKEDIT`，这里不建那个段 —— `LC_SYMTAB` 的
/// symoff/stroff 是**文件偏移**，规范并不要求有段覆盖它们）。
fn symbols_base64() -> ThinSpec {
    ThinSpec::new64(CPU_TYPE_X86_64, 3)
        .segment(SegmentSpec::new("__PAGEZERO", 0, 0x1_0000_0000, 0, 0).perms(0, 0))
        .segment(
            SegmentSpec::new("__TEXT", 0x1_0000_0000, 0x1000, 0, 0x1000)
                .perms(RX, RX)
                .section(
                    SectionSpec::new("__text", "__TEXT", 0x1_0000_0F00, 0x10)
                        .align(4)
                        .flags(CODE_FLAGS),
                ),
        )
        .command(lc_main(0xF00, 0, true))
}

/// 符号表样本的 32 位骨架：`__TEXT` + 1 个 `__text` 节（`vmaddr = 0x1000`）。
fn symbols_base32() -> ThinSpec {
    ThinSpec::new32(CPU_TYPE_X86, 3)
        .segment(
            SegmentSpec::new("__TEXT", 0x1000, 0x1000, 0, 0x1000)
                .perms(RX, RX)
                .section(
                    SectionSpec::new("__text", "__TEXT", 0x1800, 0x10)
                        .align(4)
                        .flags(CODE_FLAGS),
                ),
        )
        .command(lc_main(0x800, 0, true))
}

/// 命令在命令区里的文件偏移（段命令在前，其余命令按给出的顺序）。
fn last_command_offset(spec: &ThinSpec) -> usize {
    let mut offset = spec.header_size();
    for segment in &spec.segments {
        offset += spec.segment_command_size(segment);
    }
    // 最后一条非段命令：前面的都要跨过去。
    for command in spec
        .commands
        .iter()
        .take(spec.commands.len().saturating_sub(1))
    {
        offset += command.bytes.len() as u64;
    }
    offset as usize
}

/// 拼一份带 `LC_SYMTAB` 的镜像，返回（字节、`LC_SYMTAB` 命令的文件偏移）。
///
/// **两遍构造**：先按占位字段（symoff/nsyms/stroff/strsize 全 0）拼一遍，拿到
/// "命令区结束时文件多长"，由此算出 symoff/stroff，再填真值重拼一次。这样样本的
/// 偏移是**布局算出来的**，不是写死的常数 —— 换段布局也不会让 fixture 悄悄指错位置。
fn build_symtab_image(is_64: bool, entries: &[NlistSpec], strings: &[u8]) -> (Vec<u8>, usize) {
    let entry_size = if is_64 { NLIST64_SIZE } else { NLIST32_SIZE };
    let with_symtab = |symoff: u32, nsyms: u32, stroff: u32, strsize: u32| -> ThinSpec {
        let base = if is_64 {
            symbols_base64()
        } else {
            symbols_base32()
        };
        base.command(lc_symtab(symoff, nsyms, stroff, strsize, true))
    };

    let layout = build(&with_symtab(0, 0, 0, 0));
    let symoff = align_up(layout.len() as u64, 8);
    let stroff = symoff + entries.len() as u64 * entry_size as u64;

    let spec = with_symtab(
        symoff as u32,
        entries.len() as u32,
        stroff as u32,
        strings.len() as u32,
    );
    let command_offset = last_command_offset(&spec);
    let mut out = build(&spec);
    out.resize(symoff as usize, 0);
    for entry in entries {
        out.extend_from_slice(&encode_nlist(entry, is_64, true));
    }
    out.extend_from_slice(strings);
    (out, command_offset)
}

/// 64 位、带 `LC_SYMTAB` 的样本：**3 条符号**（2 条普通 + 1 条 stab）。
///
/// | # | 名字 | `n_type` | `n_sect` | 含义 |
/// |---|------|----------|----------|------|
/// | 0 | `_main` | `N_SECT \| N_EXT` = `0x0e \| 0x01` = `0x0f` | 1 | 定义在 `__TEXT,__text` 的外部符号 |
/// | 1 | `_printf` | `N_UNDF \| N_EXT` = `0x00 \| 0x01` = `0x01` | 0 | 外部未定义（来自共享库的引用） |
/// | 2 | `main.c` | `N_FUN` = `0x24` | 1 | 调试 stab（`0x24 & N_STAB(0xe0) = 0x20 != 0`） |
///
/// 对象模型的 [`Object::symbols`] 里应当只有前两条：stab 不是普通符号。
#[must_use]
pub fn demo_symbols64() -> Vec<u8> {
    let mut strings = StringTable::new();
    // 第一条名字的 n_strx 是 1（前缀字节占了偏移 0）—— 故意非平凡。
    let main_strx = strings.add("_main");
    let printf_strx = strings.add("_printf");
    let file_strx = strings.add("main.c");
    let entries = [
        NlistSpec::new(main_strx, N_SECT | N_EXT, 1, 0x1_0000_0F00),
        // `N_UNDF` 是 0，所以"未定义 + 外部"就是 `N_EXT` 这一位。
        NlistSpec::new(printf_strx, N_EXT, 0, 0),
        NlistSpec::new(file_strx, N_FUN, 1, 0x1_0000_0F00),
    ];
    let (bytes, _) = build_symtab_image(true, &entries, strings.bytes());
    bytes
}

/// 32 位、带 `LC_SYMTAB` 的样本：`nlist` 是 **12 字节**（不是 16）。
///
/// 存在的意义就是钉住"按文件的位宽选表项宽度"：解析器若一律按 16 字节走，
/// 第 2 条的字段会从错位置读出来（甚至整表越界），断言就会红。
#[must_use]
pub fn demo_symbols32() -> Vec<u8> {
    let mut strings = StringTable::new();
    let start_strx = strings.add("_start");
    let abort_strx = strings.add("_abort");
    let entries = [
        NlistSpec::new(start_strx, N_SECT | N_EXT, 1, 0x1800),
        NlistSpec::new(abort_strx, N_EXT, 0, 0),
    ];
    let (bytes, _) = build_symtab_image(false, &entries, strings.bytes());
    bytes
}

/// 拼一份带 `LC_FUNCTION_STARTS` 的镜像（payload 追加到文件末尾）。
fn build_function_starts_image(payload: &[u8]) -> Vec<u8> {
    let placeholder = symbols_base64().command(lc_function_starts(0, 0, true));
    let layout = build(&placeholder);
    let dataoff = align_up(layout.len() as u64, 8);
    let spec = symbols_base64().command(lc_function_starts(
        dataoff as u32,
        payload.len() as u32,
        true,
    ));
    let mut out = build(&spec);
    append_payload(&mut out, 8, payload);
    out
}

/// 64 位、带 `LC_FUNCTION_STARTS` 的样本：3 个起点，其中**一个增量为 300**（多字节）。
///
/// payload = `A0 02 | AC 02 | 10 | 00`，按 ULEB128（低 7 位有效、最高位表示续）解：
///
/// * `A0 02`：`0x20 | 0x80` 与 `0x02` → 2×128 + 0x20 = **0x120**
///   ⇒ 第一个起点 = `__TEXT.vmaddr`（`0x1_0000_0000`）+ 0x120 = `0x1_0000_0120`
/// * `AC 02`：`0x2C | 0x80` 与 `0x02` → 2×128 + 44 = **300（两字节）**
///   ⇒ `0x1_0000_0120` + 300 = `0x1_0000_024C`
/// * `10`：16 ⇒ `0x1_0000_025C`
/// * `00`：终止符
#[must_use]
pub fn demo_function_starts64() -> Vec<u8> {
    build_function_starts_image(&[0xa0, 0x02, 0xac, 0x02, 0x10, 0x00])
}

/// 畸形样本：`LC_FUNCTION_STARTS` 的 payload 在最后一个增量中间就结束了。
///
/// `A0 02` 与 `AC 02` 是两个完整增量，最后的 `80` 是"还有下一字节"却再没有下一字节
/// —— 期望行为是**解出前两个并说明表可能被截断**，而不是报错或静默返回。
#[must_use]
pub fn function_starts_without_terminator64() -> Vec<u8> {
    build_function_starts_image(&[0xa0, 0x02, 0xac, 0x02, 0x80])
}

/// 畸形样本：`LC_FUNCTION_STARTS.dataoff` 指向文件末尾之外。
///
/// 文件正好 0x1000 字节（`__TEXT.filesize`），dataoff = 0x1000 + 0x40 字节必然越界。
/// 期望**拒绝**：读表外字节没有合法解释。
#[must_use]
pub fn malformed_function_starts_past_eof() -> Vec<u8> {
    build(&symbols_base64().command(lc_function_starts(0x1000, 0x40, true)))
}

/// 畸形样本：某条符号的 `n_strx` 指向字符串表**之外**（`strsize` 之后）。
///
/// 期望**拒绝**：读表外的字节没有合法解释，退回空名字则会把"坏文件"伪装成
/// "无名符号"（CLAUDE.md §7）。
#[must_use]
pub fn malformed_symbol_name_past_strsize() -> Vec<u8> {
    let mut strings = StringTable::new();
    let main_strx = strings.add("_main");
    let entries = [
        NlistSpec::new(main_strx, N_SECT | N_EXT, 1, 0x1_0000_0F00),
        // 字符串表只有十几个字节：这个偏移远远超出表尾。
        NlistSpec::new(0x1_0000, N_EXT, 0, 0),
    ];
    let (bytes, _) = build_symtab_image(true, &entries, strings.bytes());
    bytes
}

/// 畸形样本：`LC_SYMTAB.symoff` 指向文件末尾之外。
///
/// 期望**拒绝**：整表范围先校验，`symoff + nsyms × 16` 越界就不能"尽量读"。
#[must_use]
pub fn malformed_symoff_past_eof() -> Vec<u8> {
    let mut strings = StringTable::new();
    let main_strx = strings.add("_main");
    let entries = [NlistSpec::new(main_strx, N_SECT | N_EXT, 1, 0x1_0000_0F00)];
    let (mut bytes, command_offset) = build_symtab_image(true, &entries, strings.bytes());
    // `symoff` 在命令的 +8（见模块文档）；改成"文件末尾再往后 0x100"。
    let symoff_past_eof = (bytes.len() + 0x100) as u32;
    patch_u32(&mut bytes, command_offset + 8, symoff_past_eof, true);
    bytes
}

/// 畸形样本：`sizeofcmds` 声明得比文件还大。
///
/// 期望行为是**拒绝**（`Truncated`），而不是按 `ncmds` 尽量读 —— 后者会读到
/// 文件外，或把 0 当成命令。
#[must_use]
pub fn malformed_sizeofcmds_too_big() -> Vec<u8> {
    let mut bytes = demo_thin64();
    let len = bytes.len() as u32;
    patch_u32(&mut bytes, 20, len + 0x100, true);
    bytes
}

/// 畸形样本：`ncmds` 声称的条数装不进 `sizeofcmds`（每条至少 8 字节）。
#[must_use]
pub fn malformed_ncmds_too_big() -> Vec<u8> {
    let mut bytes = demo_thin64();
    patch_u32(&mut bytes, 16, 0xffff, true);
    bytes
}

// ── 导出 trie 与 dyld 绑定（LC_DYLD_INFO / LC_DYLD_EXPORTS_TRIE） ───────────

/// ULEB128 编码一个值（低 7 位有效、最高位表示还有下一字节，小端顺序）。
fn push_uleb(out: &mut Vec<u8>, mut value: u64) {
    loop {
        let low = (value & 0x7f) as u8;
        value >>= 7;
        if value == 0 {
            out.push(low);
            return;
        }
        out.push(low | 0x80);
    }
}

/// 编码一个值需要几个字节（布局计算用）。
fn uleb_len(value: u64) -> usize {
    let mut len = 1;
    let mut rest = value >> 7;
    while rest != 0 {
        len += 1;
        rest >>= 7;
    }
    len
}

/// SLEB128 编码一个有符号值：与 ULEB 的区别是"最后一个字节的 bit6 是符号位"，
/// 所以正数在最坏情况下要多一个 `0x00` 字节来避免被解读成负数。
fn push_sleb(out: &mut Vec<u8>, mut value: i64) {
    loop {
        let byte = (value & 0x7f) as u8;
        value >>= 7;
        let done = (value == 0 && byte & 0x40 == 0) || (value == -1 && byte & 0x40 != 0);
        if done {
            out.push(byte);
            return;
        }
        out.push(byte | 0x80);
    }
}

/// `LC_DYLD_INFO` / `LC_DYLD_INFO_ONLY`（`dyld_info_command`，48 字节）。
///
/// 字段偏移见模块文档：五组 `(off, size)` 依次是 rebase / bind / weak_bind /
/// lazy_bind / export，从 `+8` 开始每 4 字节一个，到 `+0x2C` 为止。
#[must_use]
#[allow(clippy::too_many_arguments)]
pub fn lc_dyld_info(
    rebase_off: u32,
    rebase_size: u32,
    bind_off: u32,
    bind_size: u32,
    weak_bind_off: u32,
    weak_bind_size: u32,
    lazy_bind_off: u32,
    lazy_bind_size: u32,
    export_off: u32,
    export_size: u32,
    little: bool,
) -> RawCommand {
    let mut bytes = vec![0u8; 48];
    put_u32(&mut bytes, 0, LC_DYLD_INFO_ONLY, little);
    put_u32(&mut bytes, 4, 48, little);
    put_u32(&mut bytes, 8, rebase_off, little);
    put_u32(&mut bytes, 12, rebase_size, little);
    put_u32(&mut bytes, 16, bind_off, little);
    put_u32(&mut bytes, 20, bind_size, little);
    put_u32(&mut bytes, 24, weak_bind_off, little);
    put_u32(&mut bytes, 28, weak_bind_size, little);
    put_u32(&mut bytes, 32, lazy_bind_off, little);
    put_u32(&mut bytes, 36, lazy_bind_size, little);
    put_u32(&mut bytes, 40, export_off, little);
    put_u32(&mut bytes, 44, export_size, little);
    RawCommand { bytes }
}

/// `LC_DYLD_EXPORTS_TRIE`（`linkedit_data_command`，16 字节）。
#[must_use]
pub fn lc_exports_trie(dataoff: u32, datasize: u32, little: bool) -> RawCommand {
    let mut bytes = vec![0u8; 16];
    put_u32(&mut bytes, 0, LC_DYLD_EXPORTS_TRIE, little);
    put_u32(&mut bytes, 4, 16, little);
    put_u32(&mut bytes, 8, dataoff, little);
    put_u32(&mut bytes, 12, datasize, little);
    RawCommand { bytes }
}

/// `LC_DYLD_CHAINED_FIXUPS`（也是 `linkedit_data_command`，字段布局与
/// `LC_FUNCTION_STARTS` / `LC_DYLD_EXPORTS_TRIE` 完全相同：`cmd +0`、`cmdsize +4`、
/// `dataoff +8`、`datasize +0xC`）。
#[must_use]
pub fn lc_chained_fixups(dataoff: u32, datasize: u32, little: bool) -> RawCommand {
    let mut bytes = vec![0u8; 16];
    put_u32(&mut bytes, 0, LC_DYLD_CHAINED_FIXUPS, little);
    put_u32(&mut bytes, 4, 16, little);
    put_u32(&mut bytes, 8, dataoff, little);
    put_u32(&mut bytes, 12, datasize, little);
    RawCommand { bytes }
}

/// 一条导出的 terminal 规格。
///
/// 规范里 terminal 的字段顺序（ld64 `ExportFile` 写、dyld `ExportInfo` 读）：
/// `flags` 先读，再由 `REEXPORT` 决定后面是"序号 + 名字"还是"地址"。
#[derive(Debug, Clone)]
pub enum TrieTerminalSpec {
    /// 普通导出：`flags = 0`，后跟 `address`（相对镜像基址的偏移）。
    Regular {
        /// 相对镜像基址的偏移。
        address: u64,
    },
    /// `EXPORT_SYMBOL_FLAGS_REEXPORT = 0x08`：`flags`、库序号（1 基）、原始名字 C 串。
    /// 原始名字可以是空串（规范里表示"与导出名同名"）。
    Reexport {
        /// `LC_LOAD_DYLIB` 的 1 基序号。
        ordinal: u64,
        /// 原始名字（空串 = 同名）。
        original: &'static str,
    },
    /// `EXPORT_SYMBOL_FLAGS_STUB_AND_RESOLVER = 0x10`：`flags`、`address`、`other`。
    StubAndResolver {
        /// 第一个地址（相对基址）。
        address: u64,
        /// 第二个地址（就是规范里的 `other` 字段）。
        other: u64,
    },
}

/// 一个 trie 节点：可选的 terminal + 若干（边标签, 子节点下标）。
#[derive(Debug, Clone)]
pub struct TrieNodeSpec {
    /// 本节点的 terminal；`None` = 没有导出（规范里 `terminal_size = 0`）。
    pub terminal: Option<TrieTerminalSpec>,
    /// 子节点：`(边标签, nodes 里的下标)`。
    pub children: Vec<(&'static str, usize)>,
}

impl TrieNodeSpec {
    /// 一个只有 terminal 的叶子。
    #[must_use]
    pub fn leaf(terminal: TrieTerminalSpec) -> Self {
        Self {
            terminal: Some(terminal),
            children: Vec::new(),
        }
    }

    /// 一个没有 terminal、只有子节点的内部节点。
    #[must_use]
    pub fn branch(children: Vec<(&'static str, usize)>) -> Self {
        Self {
            terminal: None,
            children,
        }
    }
}

/// 按规范拼一张导出 trie（节点按数组顺序**紧邻排列**，子节点偏移由此算出）。
///
/// 布局：每个节点 = `uleb128(terminal_size)` + terminal + `uint8 child_count` +
/// `child_count × (cstring edge_label + uleb128 child_offset)`。
/// 子节点偏移是"相对 trie 起点"的绝对位置，所以要先把布局迭代到不动点
/// （偏移变了，ULEB 的字节数可能跟着变）。
#[must_use]
pub fn build_export_trie(nodes: &[TrieNodeSpec]) -> Vec<u8> {
    let terminals: Vec<Vec<u8>> = nodes
        .iter()
        .map(|node| match &node.terminal {
            None => Vec::new(),
            Some(TrieTerminalSpec::Regular { address }) => {
                let mut out = Vec::new();
                push_uleb(&mut out, 0);
                push_uleb(&mut out, *address);
                out
            }
            Some(TrieTerminalSpec::Reexport { ordinal, original }) => {
                let mut out = Vec::new();
                push_uleb(&mut out, 0x08);
                push_uleb(&mut out, *ordinal);
                out.extend_from_slice(original.as_bytes());
                out.push(0);
                out
            }
            Some(TrieTerminalSpec::StubAndResolver { address, other }) => {
                let mut out = Vec::new();
                push_uleb(&mut out, 0x10);
                push_uleb(&mut out, *address);
                push_uleb(&mut out, *other);
                out
            }
        })
        .collect();

    // 迭代到不动点：先假设所有偏移是 1 字节 ULEB，再按新偏移重算。
    let mut offsets = vec![0usize; nodes.len()];
    for _ in 0..16 {
        let mut cursor = 0usize;
        let mut next = Vec::with_capacity(nodes.len());
        for (index, node) in nodes.iter().enumerate() {
            next.push(cursor);
            cursor += uleb_len(terminals[index].len() as u64);
            cursor += terminals[index].len();
            cursor += 1;
            for (label, child) in &node.children {
                cursor += label.len() + 1;
                cursor += uleb_len(offsets[*child] as u64);
            }
        }
        if next == offsets {
            break;
        }
        offsets = next;
    }

    let mut out = Vec::new();
    for (index, node) in nodes.iter().enumerate() {
        // 构造器自己校验布局：写出每个节点时它必须正好落在算好的偏移上。
        assert_eq!(
            out.len(),
            offsets[index],
            "trie 布局迭代没收敛：节点 {index} 应当落在 +{:#x}，实际在 +{:#x}",
            offsets[index],
            out.len()
        );
        push_uleb(&mut out, terminals[index].len() as u64);
        out.extend_from_slice(&terminals[index]);
        out.push(node.children.len() as u8);
        for (label, child) in &node.children {
            out.extend_from_slice(label.as_bytes());
            out.push(0);
            push_uleb(&mut out, offsets[*child] as u64);
        }
    }
    out
}

/// 三符号以上的导出 trie：`_main` / `_helper` 普通导出（落在 `__TEXT,__text` 里）、
/// `_reexported`（re-export 到 1 号库、原始名 `_originalImpl`）、
/// `_stub`（stub + resolver，两个地址）。
///
/// 子节点的书写顺序是 main / helper / reexported / stub，解出来的顺序与它一致
/// （解析器不额外排序）。
#[must_use]
pub fn demo_export_trie() -> Vec<u8> {
    build_export_trie(&[
        // 根：没有导出，只有一条边 "_"。
        TrieNodeSpec::branch(vec![("_", 1)]),
        TrieNodeSpec::branch(vec![
            ("main", 2),
            ("helper", 3),
            ("reexported", 4),
            ("stub", 5),
        ]),
        TrieNodeSpec::leaf(TrieTerminalSpec::Regular { address: 0xF00 }),
        TrieNodeSpec::leaf(TrieTerminalSpec::Regular { address: 0xF80 }),
        TrieNodeSpec::leaf(TrieTerminalSpec::Reexport {
            ordinal: 1,
            original: "_originalImpl",
        }),
        TrieNodeSpec::leaf(TrieTerminalSpec::StubAndResolver {
            address: 0xF40,
            other: 0x1200,
        }),
    ])
}

/// 只有一条导出的**手写** trie（不经构造器），逐字节钉住规范布局：
///
/// ```text
/// +0x00  00              terminal_size = 0（根没有导出）
/// +0x01  01              child_count = 1
/// +0x02  5F 6D 61 69 6E  edge label "_main"（5 字节，到 +0x06）
/// +0x07  00              edge label 的 NUL 终止符
/// +0x08  09              child node offset = 9
/// +0x09  02              terminal_size = 2（flags 1 字节 + address 1 字节）
/// +0x0A  00              flags = 0（普通导出）
/// +0x0B  10              address = 0x10（相对镜像基址）
/// +0x0C  00              child_count = 0
/// ```
#[must_use]
pub fn hand_written_export_trie() -> Vec<u8> {
    vec![
        0x00, 0x01, b'_', b'm', b'a', b'i', b'n', 0x00, 0x09, 0x02, 0x00, 0x10, 0x00,
    ]
}

/// 环状 trie：节点 1 的子节点指回根节点 0 —— 必须被**拒绝**，不许无限循环。
#[must_use]
pub fn cyclic_export_trie() -> Vec<u8> {
    build_export_trie(&[
        TrieNodeSpec::branch(vec![("_", 1)]),
        // 指回 0：遍历会永远在 0 → 1 → 0 → 1 之间打转。
        TrieNodeSpec::branch(vec![("cycle", 0)]),
    ])
}

/// 自引用 trie：根节点的子节点就是根自己。
#[must_use]
pub fn self_referencing_export_trie() -> Vec<u8> {
    build_export_trie(&[TrieNodeSpec::branch(vec![("a", 0)])])
}

/// 截断的 ULEB128：`terminal_size` 的最后一个字节续位仍是 1，后面没有字节了。
#[must_use]
pub fn truncated_uleb_export_trie() -> Vec<u8> {
    vec![0x80]
}

/// terminal 声称 2 字节但只给了 1 字节（表被裁剪）。
#[must_use]
pub fn truncated_terminal_export_trie() -> Vec<u8> {
    vec![0x02, 0x00]
}

/// 一条绑定流里的操作（对应 dyld `enum BindOpcode`）。
#[derive(Debug, Clone)]
pub enum BindOp {
    /// `0x00`。
    Done,
    /// `0x10` + 立即数：库序号（0 = self）。
    SetDylibOrdinalImm(u8),
    /// `0x20` + uleb：库序号。
    SetDylibOrdinalUleb(u64),
    /// `0x30` + 立即数：特殊序号。立即数只有 4 位，dyld 用 `0xF0 | imm` 按 8 位补码
    /// 解释 —— 所以 main-executable(-1) 的立即数是 `0x0F`（字节 `0x3F`）、
    /// flat lookup(-2) 是 `0x0E`、weak lookup(-3) 是 `0x0D`。
    SetDylibSpecialImm(u8),
    /// `0x40` + 立即数（flags）+ C 串（符号名）。
    SetSymbol {
        /// `BIND_SYMBOL_FLAGS_*`（0 = 普通）。
        flags: u8,
        /// 符号名。
        name: &'static str,
    },
    /// `0x50` + 立即数：绑定类型。
    SetTypeImm(u8),
    /// `0x60` + sleb：加数。
    SetAddendSleb(i64),
    /// `0x70` + 立即数（段序号）+ uleb（段内偏移）。
    SetSegmentAndOffsetUleb {
        /// 段序号（0 基，按加载命令顺序）。
        segment: u8,
        /// 段内偏移。
        offset: u64,
    },
    /// `0x80` + uleb：段内偏移 += 操作数（不绑定）。
    AddAddrUleb(u64),
    /// `0x90`：把当前符号绑到当前槽位。
    DoBind,
    /// `0xA0` + uleb：先 `DO_BIND`，再 偏移 += 操作数。
    DoBindAddAddrUleb(u64),
    /// `0xB0` + 立即数：先 `DO_BIND`，再 偏移 += 立即数 × 指针大小。
    DoBindAddAddrImmScaled(u8),
    /// `0xC0` + uleb（次数）+ uleb（跳过量，**单位是字节**）：重复绑定。
    DoBindUlebTimesSkippingUleb {
        /// 次数。
        count: u64,
        /// 每次之后的跳过量（字节；dyld 会再加一个指针让槽位前进）。
        skip: u64,
    },
}

/// 按规范把一串操作编码成绑定流（`bind.h` 的高 4 位/低 4 位约定）。
#[must_use]
pub fn bind_stream(ops: &[BindOp]) -> Vec<u8> {
    let mut out = Vec::new();
    for op in ops {
        match op {
            BindOp::Done => out.push(0x00),
            BindOp::SetDylibOrdinalImm(value) => out.push(0x10 | (value & 0x0f)),
            BindOp::SetDylibOrdinalUleb(value) => {
                out.push(0x20);
                push_uleb(&mut out, *value);
            }
            BindOp::SetDylibSpecialImm(value) => out.push(0x30 | (value & 0x0f)),
            BindOp::SetSymbol { flags, name } => {
                out.push(0x40 | (flags & 0x0f));
                out.extend_from_slice(name.as_bytes());
                out.push(0);
            }
            BindOp::SetTypeImm(value) => out.push(0x50 | (value & 0x0f)),
            BindOp::SetAddendSleb(value) => {
                out.push(0x60);
                push_sleb(&mut out, *value);
            }
            BindOp::SetSegmentAndOffsetUleb { segment, offset } => {
                out.push(0x70 | (segment & 0x0f));
                push_uleb(&mut out, *offset);
            }
            BindOp::AddAddrUleb(value) => {
                out.push(0x80);
                push_uleb(&mut out, *value);
            }
            BindOp::DoBind => out.push(0x90),
            BindOp::DoBindAddAddrUleb(value) => {
                out.push(0xa0);
                push_uleb(&mut out, *value);
            }
            BindOp::DoBindAddAddrImmScaled(value) => out.push(0xb0 | (value & 0x0f)),
            BindOp::DoBindUlebTimesSkippingUleb { count, skip } => {
                out.push(0xc0);
                push_uleb(&mut out, *count);
                push_uleb(&mut out, *skip);
            }
        }
    }
    out
}

/// 普通绑定流：跨 2 个库 + 特殊序号 + `DO_BIND_ULEB_TIMES_SKIPPING_ULEB`。
///
/// 段序号 2 = `__DATA`（0 是 `__PAGEZERO`、1 是 `__TEXT`），指针 8 字节。按 dyld 的
/// 语义（每条 `DO_BIND` 之后槽位前移一个指针；带跳过的操作码再加跳过量），槽位是：
///
/// * `_objc_msgSend` @ `__DATA+0x100` → 地址 `0x1_0000_2100`（1 号库 libSystem）
/// * `_malloc` @ `0x108`、`0x118` —— `DO_BIND_ULEB_TIMES_SKIPPING_ULEB{count=2, skip=8}`：
///   每次绑完 `偏移 += 8 + 8`（skip 是字节数），所以两次之间差 16 字节
/// * `_main_ref` @ `0x128`，特殊序号 0x3F（= 0xFF）= main-executable
/// * `_UIKitRef` @ `0x130`，2 号库 UIKit、加数 -4；`DO_BIND_ADD_ADDR_ULEB(0x20)` 之后
///   `偏移 += 0x20 + 8` → `0x158`
/// * `_UIKitScaled` @ `0x158`，`DO_BIND_ADD_ADDR_IMM_SCALED(2)` 之后 `偏移 += 2×8 + 8`
///
/// 共 6 条绑定、3 个 module（libSystem / main-executable / UIKit）。
#[must_use]
pub fn demo_bind_stream() -> Vec<u8> {
    bind_stream(&[
        BindOp::SetSegmentAndOffsetUleb {
            segment: 2,
            offset: 0x100,
        },
        BindOp::SetDylibOrdinalImm(1),
        BindOp::SetTypeImm(1),
        BindOp::SetSymbol {
            flags: 0,
            name: "_objc_msgSend",
        },
        BindOp::DoBind,
        BindOp::SetSymbol {
            flags: 0,
            name: "_malloc",
        },
        BindOp::DoBindUlebTimesSkippingUleb { count: 2, skip: 8 },
        BindOp::SetDylibSpecialImm(0x0f),
        BindOp::SetSymbol {
            flags: 0,
            name: "_main_ref",
        },
        BindOp::DoBind,
        BindOp::SetDylibOrdinalUleb(2),
        BindOp::SetAddendSleb(-4),
        BindOp::SetSymbol {
            flags: 0,
            name: "_UIKitRef",
        },
        BindOp::DoBindAddAddrUleb(0x20),
        BindOp::SetAddendSleb(0),
        BindOp::SetSymbol {
            flags: 0x1,
            name: "_UIKitScaled",
        },
        BindOp::DoBindAddAddrImmScaled(2),
        BindOp::Done,
    ])
}

/// 惰性绑定流：两条 entry，**每条以 `DONE` 结尾**，各自从头设状态。
#[must_use]
pub fn demo_lazy_bind_stream() -> Vec<u8> {
    bind_stream(&[
        BindOp::SetSegmentAndOffsetUleb {
            segment: 2,
            offset: 0x200,
        },
        BindOp::SetDylibOrdinalImm(1),
        BindOp::SetSymbol {
            flags: 0,
            name: "_lazyOne",
        },
        BindOp::DoBind,
        BindOp::Done,
        // 第二条自己重设段/库/符号：DONE 之后状态归零（dyld 每条 entry 一个局部状态）。
        BindOp::SetSegmentAndOffsetUleb {
            segment: 2,
            offset: 0x208,
        },
        BindOp::SetDylibOrdinalUleb(2),
        BindOp::SetSymbol {
            flags: 0,
            name: "_lazyTwo",
        },
        BindOp::DoBind,
        BindOp::Done,
    ])
}

/// 拼一份带 dyld 信息的 64 位样本，返回字节与"命令/数据在文件里的位置"。
///
/// 布局与真实文件同一形状：`__PAGEZERO` + `__TEXT`（含一个 `__text`）+
/// `__DATA`，两条 `LC_LOAD_DYLIB`，然后是承载 trie 的命令（`LC_DYLD_INFO_ONLY`
/// 或 `LC_DYLD_EXPORTS_TRIE`），最后把 trie / bind / lazy_bind 三段数据追加到文件尾。
pub struct DyldImage {
    /// 完整文件字节。
    pub bytes: Vec<u8>,
    /// `LC_DYLD_INFO_ONLY` 命令的文件偏移（用这条命令时是 `Some`）。
    pub dyld_info_offset: Option<usize>,
    /// `LC_DYLD_EXPORTS_TRIE` 命令的文件偏移（用这条命令时是 `Some`）。
    pub exports_trie_offset: Option<usize>,
    /// 导出 trie 数据在文件里的偏移。
    pub export_dataoff: u64,
    /// bind 流在文件里的偏移。
    pub bind_dataoff: u64,
    /// lazy bind 流在文件里的偏移。
    pub lazy_bind_dataoff: u64,
}

/// 样本里的镜像基址（`__TEXT.vmaddr`）。
pub const DYLD_TEXT_VMADDR: u64 = 0x1_0000_0000;
/// 样本里 `__DATA` 的 `vmaddr`（绑定槽位都落在这里）。
pub const DYLD_DATA_VMADDR: u64 = 0x1_0000_2000;

/// dyld 样本的骨架（两条 dylib 的顺序就是库序号的顺序）。
fn dyld_base64() -> ThinSpec {
    ThinSpec::new64(CPU_TYPE_X86_64, 3)
        .segment(SegmentSpec::new("__PAGEZERO", 0, 0x1_0000_0000, 0, 0).perms(0, 0))
        .segment(
            SegmentSpec::new("__TEXT", DYLD_TEXT_VMADDR, 0x2000, 0, 0x2000)
                .perms(RX, RX)
                .section(
                    SectionSpec::new("__text", "__TEXT", DYLD_TEXT_VMADDR + 0xF00, 0x100)
                        .align(4)
                        .flags(CODE_FLAGS),
                ),
        )
        .segment(SegmentSpec::new("__DATA", DYLD_DATA_VMADDR, 0x2000, 0x2000, 0x2000).perms(RW, RW))
        .command(lc_load_dylib("/usr/lib/libSystem.B.dylib", false, true))
        .command(lc_load_dylib(
            "/System/Library/Frameworks/UIKit.framework/UIKit",
            false,
            true,
        ))
        .min_file_size(0x4000)
}

/// 命令在命令区里的文件偏移（段命令在前，其余命令按给出的顺序）。
fn command_offset_in(spec: &ThinSpec, index: usize) -> usize {
    let mut offset = spec.header_size();
    for segment in &spec.segments {
        offset += spec.segment_command_size(segment);
    }
    for command in spec.commands.iter().take(index) {
        offset += command.bytes.len() as u64;
    }
    offset as usize
}

/// 拼一份带导出 trie 与绑定的样本。
///
/// `exports_trie_command` 决定用哪条命令承载 trie：`true` 用
/// `LC_DYLD_EXPORTS_TRIE`（iOS 13+ 的形式），`false` 用 `LC_DYLD_INFO_ONLY`。
fn dyld_image(exports_trie_command: bool, trie: &[u8], bind: &[u8], lazy_bind: &[u8]) -> DyldImage {
    // 第一遍：占位（数据偏移全 0），只为拿到"命令区结束时文件多长"。
    let placeholder = if exports_trie_command {
        dyld_base64().command(lc_exports_trie(0, 0, true))
    } else {
        dyld_base64().command(lc_dyld_info(0, 0, 0, 0, 0, 0, 0, 0, 0, 0, true))
    };
    let layout = build(&placeholder);

    // 三段数据依次追加，各自 8 字节对齐。
    let mut cursor = layout.len() as u64;
    let export_dataoff = {
        let at = align_up(cursor, 8);
        cursor = at + trie.len() as u64;
        at
    };
    let bind_dataoff = {
        let at = align_up(cursor, 8);
        cursor = at + bind.len() as u64;
        at
    };
    let lazy_bind_dataoff = {
        let at = align_up(cursor, 8);
        cursor = at + lazy_bind.len() as u64;
        at
    };

    // 第二遍：填真偏移。命令字节数不变，所以布局与第一遍完全相同。
    let spec = if exports_trie_command {
        dyld_base64().command(lc_exports_trie(
            export_dataoff as u32,
            trie.len() as u32,
            true,
        ))
    } else {
        dyld_base64().command(lc_dyld_info(
            0,
            0,
            bind_dataoff as u32,
            bind.len() as u32,
            0,
            0,
            lazy_bind_dataoff as u32,
            lazy_bind.len() as u32,
            export_dataoff as u32,
            trie.len() as u32,
            true,
        ))
    };
    let command_index = spec.commands.len() - 1;
    let command_offset = command_offset_in(&spec, command_index);

    let mut bytes = build(&spec);
    let total = cursor as usize;
    if bytes.len() < total {
        bytes.resize(total, 0);
    }
    bytes[export_dataoff as usize..export_dataoff as usize + trie.len()].copy_from_slice(trie);
    bytes[bind_dataoff as usize..bind_dataoff as usize + bind.len()].copy_from_slice(bind);
    bytes[lazy_bind_dataoff as usize..lazy_bind_dataoff as usize + lazy_bind.len()]
        .copy_from_slice(lazy_bind);

    DyldImage {
        bytes,
        dyld_info_offset: if exports_trie_command {
            None
        } else {
            Some(command_offset)
        },
        exports_trie_offset: if exports_trie_command {
            Some(command_offset)
        } else {
            None
        },
        export_dataoff,
        bind_dataoff,
        lazy_bind_dataoff,
    }
}

/// 同 [`demo_dyld_info64`]，但导出 trie 用调用方给的字节。
///
/// 单测靠它把"手写 trie / 环 / 截断"这些样本塞进同一个镜像骨架里 ——
/// 骨架（段表、两条 dylib、绑定流）只写一份。
#[must_use]
pub fn dyld_image_with_trie(trie: &[u8]) -> DyldImage {
    dyld_image(false, trie, &demo_bind_stream(), &demo_lazy_bind_stream())
}

/// 同 [`demo_dyld_info64`]，但绑定流用调用方给的字节（普通绑定）。
#[must_use]
pub fn dyld_image_with_bind(bind: &[u8]) -> DyldImage {
    dyld_image(false, &demo_export_trie(), bind, &[])
}

/// 完整样本：`LC_DYLD_INFO_ONLY` 承载导出 trie + 普通绑定 + 惰性绑定。
#[must_use]
pub fn demo_dyld_info64() -> DyldImage {
    dyld_image(
        false,
        &demo_export_trie(),
        &demo_bind_stream(),
        &demo_lazy_bind_stream(),
    )
}

/// 同上的 `LC_DYLD_EXPORTS_TRIE` 形式（没有绑定数据）。
#[must_use]
pub fn demo_exports_trie64() -> DyldImage {
    dyld_image(true, &demo_export_trie(), &[], &[])
}

/// 畸形样本：导出 trie 的 `export_off` 指向文件末尾之外 —— 必须拒绝。
#[must_use]
pub fn malformed_export_off_past_eof() -> Vec<u8> {
    let image = demo_dyld_info64();
    let mut bytes = image.bytes;
    let command = image
        .dyld_info_offset
        .expect("样本用的是 LC_DYLD_INFO_ONLY");
    let past_eof = (bytes.len() + 0x100) as u32;
    // `export_off` 在 dyld_info_command 的 +0x28（见模块文档的字段偏移）。
    patch_u32(&mut bytes, command + 0x28, past_eof, true);
    bytes
}

/// 畸形样本：`bind_size` 声称的范围越过文件末尾 —— 必须拒绝。
#[must_use]
pub fn malformed_bind_off_past_eof() -> Vec<u8> {
    let image = demo_dyld_info64();
    let mut bytes = image.bytes;
    let command = image
        .dyld_info_offset
        .expect("样本用的是 LC_DYLD_INFO_ONLY");
    let past_eof = (bytes.len() + 0x100) as u32;
    patch_u32(&mut bytes, command + 0x14, 0x40, true); // bind_size
    patch_u32(&mut bytes, command + 0x10, past_eof, true); // bind_off
    bytes
}

/// 畸形样本：绑定流以 `SET_DYLIB_ORDINAL_ULEB 0x80` 结尾（ULEB128 被截断）。
#[must_use]
pub fn malformed_bind_truncated_uleb() -> Vec<u8> {
    dyld_image(false, &[], &[0x20, 0x80], &[]).bytes
}

/// 畸形样本：绑定流指向段 #15，但样本只有 3 个段。
#[must_use]
pub fn malformed_bind_segment_out_of_range() -> Vec<u8> {
    dyld_image(false, &[], &[0x7f, 0x00], &[]).bytes
}

// ── LC_DYLD_CHAINED_FIXUPS（链式修复的导入表） ──────────────────────────────
//
// 规范出处：Apple XNU 的 `EXTERNAL_HEADERS/mach-o/fixup-chains.h`。下半段构造器
// 逐字节按那里面的结构声明写，**不**调用解析代码（CLAUDE.md §6.11）。
//
// ```text
// struct dyld_chained_fixups_header {          // 28 字节，小端
//     uint32_t fixups_version;   // +0x00
//     uint32_t starts_offset;    // +0x04
//     uint32_t imports_offset;   // +0x08
//     uint32_t symbols_offset;   // +0x0C
//     uint32_t imports_count;    // +0x10
//     uint32_t imports_format;   // +0x14  1 / 2 / 3
//     uint32_t symbols_format;   // +0x18  0 = 未压缩，1 = zlib
// };
//
// struct dyld_chained_import {                 // 4 字节
//     uint32_t lib_ordinal : 8,                // bits  0..8
//              weak_import : 1,                // bit   8
//              name_offset : 23;               // bits  9..32
// };
// struct dyld_chained_import_addend {          // 8 字节
//     uint32_t lib_ordinal : 8, weak_import : 1, name_offset : 23;
//     int32_t  addend;                         // +4
// };
// struct dyld_chained_import_addend64 {        // 16 字节
//     uint64_t lib_ordinal : 16,               // bits  0..16
//              weak_import : 1,                // bit   16
//              reserved    : 15,               // bits 17..32
//              name_offset : 32;               // bits 32..64
//     uint64_t addend;                         // +8
// };
// #define DYLD_CHAINED_IMPORT          1
// #define DYLD_CHAINED_IMPORT_ADDEND   2
// #define DYLD_CHAINED_IMPORT_ADDEND64 3
// ```
//
// 位域在 Little-endian 上是 **LSB-first** 排布的：`lib_ordinal : 8, weak_import : 1,
// name_offset : 23` 的声明意味着 lib_ordinal 占最低 8 位、weak 占第 8 位、
// name_offset 从第 9 位开始 —— 所以一个 `u32` 可以写成
// `(name_offset << 9) | (weak << 8) | lib_ordinal`。链式修复数据本身在真实
// Apple 平台上只有小端（arm64 / x86_64），所以这里固定按小端拼。

/// `DYLD_CHAINED_IMPORT`：`u32` 位域，4 字节。
pub const DYLD_CHAINED_IMPORT: u32 = 1;
/// `DYLD_CHAINED_IMPORT_ADDEND`：`u32` 位域 + `int32_t`，8 字节。
pub const DYLD_CHAINED_IMPORT_ADDEND: u32 = 2;
/// `DYLD_CHAINED_IMPORT_ADDEND64`：`u64` 位域 + `uint64_t`，16 字节。
pub const DYLD_CHAINED_IMPORT_ADDEND64: u32 = 3;
/// `DYLD_CHAINED_SYMBOLS_UNCOMPRESSED`。
pub const SYMBOLS_FORMAT_UNCOMPRESSED: u32 = 0;
/// `DYLD_CHAINED_SYMBOLS_ZLIB`（本片不解；样本用来验证"明确拒绝"）。
pub const SYMBOLS_FORMAT_ZLIB: u32 = 1;

/// 一条导入表条目的规格（位域值按"未做符号扩展的原始值"给）。
#[derive(Debug, Clone)]
pub struct ChainedImportSpec {
    /// `lib_ordinal` 位域（8 位或 16 位，按 `imports_format` 截断写入）。
    /// `0xFF` = 主可执行文件、`0xFE` = flat lookup（二补码的 -1 / -2）。
    pub lib_ordinal: u32,
    /// `weak_import` 位。
    pub weak_import: bool,
    /// 符号池内的名字偏移。
    pub name_offset: u32,
    /// 加数：`imports_format` 2 写成 `i32`、3 写成 `u64`；格式 1 **不写**（字段不存在）。
    pub addend: i64,
}

/// 一份 `LC_DYLD_CHAINED_FIXUPS` payload 的规格。
#[derive(Debug, Clone)]
pub struct ChainedFixupsSpec {
    /// `fixups_version`（规范只定义 0）。
    pub fixups_version: u32,
    /// `imports_format`（1 / 2 / 3；畸形样本可以给别的值）。
    pub imports_format: u32,
    /// `symbols_format`（0 = 未压缩；1 = zlib）。
    pub symbols_format: u32,
    /// `starts_offset` 指向的链描述字节。空 = 没有链（`starts_offset = 0`）。
    pub starts: Vec<u8>,
    /// 导入表条目。
    pub imports: Vec<ChainedImportSpec>,
    /// 符号池字节（NUL 结尾名字的拼接，见 [`symbol_pool`]）。
    pub symbols: Vec<u8>,
    /// 覆盖头里的 `imports_offset`（畸形样本）。
    pub imports_offset_override: Option<u32>,
    /// 覆盖头里的 `symbols_offset`（畸形样本）。
    pub symbols_offset_override: Option<u32>,
    /// 覆盖头里的 `imports_count`（畸形样本）。
    pub imports_count_override: Option<u32>,
}

impl ChainedFixupsSpec {
    /// 一份空的规格（没有链描述、没有导入、空符号池）。
    #[must_use]
    pub fn new(imports_format: u32) -> Self {
        Self {
            fixups_version: 0,
            imports_format,
            symbols_format: SYMBOLS_FORMAT_UNCOMPRESSED,
            starts: Vec::new(),
            imports: Vec::new(),
            symbols: Vec::new(),
            imports_offset_override: None,
            symbols_offset_override: None,
            imports_count_override: None,
        }
    }

    /// 一条导入表条目（顺序就是表里的顺序）。
    #[must_use]
    pub fn import(mut self, entry: ChainedImportSpec) -> Self {
        self.imports.push(entry);
        self
    }

    /// 设置符号池与链描述（链描述用 [`minimal_starts_in_image`]）。
    #[must_use]
    pub fn pool(mut self, symbols: Vec<u8>, starts: Vec<u8>) -> Self {
        self.symbols = symbols;
        self.starts = starts;
        self
    }

    /// 单个条目的字节宽度（`fixup-chains.h` 里的 `sizeof`）。
    #[must_use]
    pub fn entry_size(&self) -> usize {
        match self.imports_format {
            DYLD_CHAINED_IMPORT => 4,
            DYLD_CHAINED_IMPORT_ADDEND => 8,
            DYLD_CHAINED_IMPORT_ADDEND64 => 16,
            // 未知格式在真实文件里不存在；畸形样本用它验证"明确拒绝"，
            // 这里沿用 4 字节（关键是**头里的 imports_format**）。
            _ => 4,
        }
    }
}

/// 符号池 + 每个名字的 `name_offset`（相对池起点）。
///
/// 名字按给定顺序拼成 NUL 结尾的串，偏移由拼接本身算出来 —— 手写数字容易错一位。
#[must_use]
pub fn symbol_pool(names: &[&str]) -> (Vec<u8>, Vec<u32>) {
    let mut pool: Vec<u8> = Vec::new();
    let mut offsets: Vec<u32> = Vec::with_capacity(names.len());
    for name in names {
        offsets.push(pool.len() as u32);
        pool.extend_from_slice(name.as_bytes());
        pool.push(0);
    }
    (pool, offsets)
}

/// 最小的 `dyld_chained_starts_in_image`（`mach-o/fixup-chains.h`）：
///
/// ```text
/// struct dyld_chained_starts_in_image {
///     uint32_t seg_count;                  // +0
///     uint32_t seg_info_offset[seg_count]; // +4，每项相对**本结构**起点
/// };
/// ```
///
/// 每个段的偏移都给 0 = 这个段没有链。fixture 只验证导入表，所以链描述给这段
/// 最小的合法内容：`starts_offset` 有真实指向，同时不假装解过链。
#[must_use]
pub fn minimal_starts_in_image(seg_count: u32) -> Vec<u8> {
    let mut bytes = vec![0u8; 4 + 4 * seg_count as usize];
    put_u32(&mut bytes, 0, seg_count, true);
    bytes
}

/// 按 `mach-o/fixup-chains.h` 拼一段 `LC_DYLD_CHAINED_FIXUPS` 的 payload。
///
/// 布局：`header(28)` → 链描述（若有）→ 导入表 → 符号池。三个偏移**由布局算出来**，
/// 覆盖字段只改头里的值、不改实际布局（畸形样本要的正是"头说的与实际不一致"）。
#[must_use]
pub fn build_chained_fixups(spec: &ChainedFixupsSpec) -> Vec<u8> {
    let entry_size = spec.entry_size();
    let header_size = 28usize;

    // 头与链描述：头里 `starts_offset` 指向紧随其后的链描述（没有链时写 0）。
    let starts_offset = if spec.starts.is_empty() {
        0u32
    } else {
        header_size as u32
    };
    let starts_end = header_size + spec.starts.len();
    // 导入表按 4 字节对齐（规范没有强制，但真实链接器都这么做；不影响解析）。
    let imports_offset = if spec.imports.is_empty() {
        starts_end
    } else {
        align_up(starts_end as u64, 4) as usize
    };
    let table_end = imports_offset + spec.imports.len() * entry_size;
    let symbols_offset = if spec.symbols.is_empty() {
        table_end
    } else {
        align_up(table_end as u64, 4) as usize
    };

    let total = (symbols_offset + spec.symbols.len()).max(header_size);
    let mut out = vec![0u8; total];

    // 七个 u32，偏移见上面的结构声明。
    let written_imports_offset = spec
        .imports_offset_override
        .unwrap_or(imports_offset as u32);
    let written_symbols_offset = spec
        .symbols_offset_override
        .unwrap_or(symbols_offset as u32);
    let written_count = spec
        .imports_count_override
        .unwrap_or(spec.imports.len() as u32);
    put_u32(&mut out, 0x00, spec.fixups_version, true);
    put_u32(&mut out, 0x04, starts_offset, true);
    put_u32(&mut out, 0x08, written_imports_offset, true);
    put_u32(&mut out, 0x0C, written_symbols_offset, true);
    put_u32(&mut out, 0x10, written_count, true);
    put_u32(&mut out, 0x14, spec.imports_format, true);
    put_u32(&mut out, 0x18, spec.symbols_format, true);

    if !spec.starts.is_empty() {
        out[header_size..header_size + spec.starts.len()].copy_from_slice(&spec.starts);
    }

    // 条目：位域按 LSB-first 拼。`imports_offset` 用**实际**布局（覆盖只影响头），
    // 否则畸形样本会写到随机位置。
    for (index, entry) in spec.imports.iter().enumerate() {
        let at = imports_offset + index * entry_size;
        match spec.imports_format {
            DYLD_CHAINED_IMPORT => {
                let word = ((entry.name_offset & 0x7F_FFFF) << 9)
                    | (u32::from(entry.weak_import) << 8)
                    | (entry.lib_ordinal & 0xFF);
                put_u32(&mut out, at, word, true);
            }
            DYLD_CHAINED_IMPORT_ADDEND => {
                let word = ((entry.name_offset & 0x7F_FFFF) << 9)
                    | (u32::from(entry.weak_import) << 8)
                    | (entry.lib_ordinal & 0xFF);
                put_u32(&mut out, at, word, true);
                put_u32(&mut out, at + 4, entry.addend as i32 as u32, true);
            }
            DYLD_CHAINED_IMPORT_ADDEND64 => {
                let low = (u64::from(entry.name_offset) << 32)
                    | (u64::from(entry.weak_import) << 16)
                    | u64::from(entry.lib_ordinal & 0xFFFF);
                put_u64(&mut out, at, low, true);
                put_u64(&mut out, at + 8, entry.addend as u64, true);
            }
            _ => {
                // 未知格式：畸形样本只关心头里的 imports_format 被拒绝，条目内容无关。
                put_u32(&mut out, at, entry.name_offset, true);
            }
        }
    }

    if !spec.symbols.is_empty() {
        out[symbols_offset..symbols_offset + spec.symbols.len()].copy_from_slice(&spec.symbols);
    }
    out
}

/// 带链式修复数据的样本：字节 + 命令/数据在文件里的位置。
pub struct ChainedImage {
    /// 完整文件字节。
    pub bytes: Vec<u8>,
    /// `LC_DYLD_CHAINED_FIXUPS` 命令的文件偏移（改头字段的畸形样本要用）。
    pub command_offset: usize,
    /// payload 在文件里的偏移。
    pub dataoff: u64,
}

/// 把一段 `LC_DYLD_CHAINED_FIXUPS` payload 装进 [`dyld_base64`] 那个骨架。
///
/// 骨架有三段（`__PAGEZERO` / `__TEXT` / `__DATA`）与两条 `LC_LOAD_DYLIB`
/// （1 = `libSystem.B.dylib`、2 = `UIKit`），所以库序号的期望值是确定的。
/// payload 追加在骨架之后（8 字节对齐），与真实文件的 `__LINKEDIT` 位置同一形状。
#[must_use]
pub fn chained_image(payload: &[u8]) -> ChainedImage {
    // 第一遍：占位，只为拿到"骨架本身多长"。
    let placeholder = dyld_base64().command(lc_chained_fixups(0, 0, true));
    let layout = build(&placeholder);
    let dataoff = align_up(layout.len() as u64, 8);

    // 第二遍：填真偏移。命令字节数不变，所以布局与第一遍相同。
    let spec = dyld_base64().command(lc_chained_fixups(
        dataoff as u32,
        payload.len() as u32,
        true,
    ));
    let command_offset = command_offset_in(&spec, spec.commands.len() - 1);
    let mut bytes = build(&spec);
    let total = dataoff as usize + payload.len();
    if bytes.len() < total {
        bytes.resize(total, 0);
    }
    bytes[dataoff as usize..total].copy_from_slice(payload);

    ChainedImage {
        bytes,
        command_offset,
        dataoff,
    }
}

/// 完整样本：`imports_format = 1`，4 条导入跨 2 个库 —— 其中 `_UIApplicationMain`
/// 是 weak，`_mainRef` 的库序号是 `0xFF`（二补码 -1 = 主可执行文件）。
#[must_use]
pub fn demo_chained_fixups64() -> ChainedImage {
    let (symbols, offsets) = symbol_pool(&[
        "_objc_msgSend",
        "_UIApplicationMain",
        "_dispatch_async",
        "_mainRef",
    ]);
    let spec = ChainedFixupsSpec::new(DYLD_CHAINED_IMPORT)
        .pool(symbols, minimal_starts_in_image(3))
        .import(ChainedImportSpec {
            lib_ordinal: 1, // libSystem
            weak_import: false,
            name_offset: offsets[0],
            addend: 0,
        })
        .import(ChainedImportSpec {
            lib_ordinal: 2, // UIKit
            weak_import: true,
            name_offset: offsets[1],
            addend: 0,
        })
        .import(ChainedImportSpec {
            lib_ordinal: 1, // libSystem
            weak_import: false,
            name_offset: offsets[2],
            addend: 0,
        })
        .import(ChainedImportSpec {
            lib_ordinal: 0xFF, // -1 = main executable
            weak_import: false,
            name_offset: offsets[3],
            addend: 0,
        });
    chained_image(&build_chained_fixups(&spec))
}

/// `imports_format = 2`（`DYLD_CHAINED_IMPORT_ADDEND`）：带 `i32` 加数。
#[must_use]
pub fn demo_chained_addend64() -> ChainedImage {
    let (symbols, offsets) = symbol_pool(&["_firstSight", "_scaled"]);
    let spec = ChainedFixupsSpec::new(DYLD_CHAINED_IMPORT_ADDEND)
        .pool(symbols, minimal_starts_in_image(3))
        .import(ChainedImportSpec {
            lib_ordinal: 1,
            weak_import: false,
            name_offset: offsets[0],
            addend: -4,
        })
        .import(ChainedImportSpec {
            lib_ordinal: 2,
            weak_import: true,
            name_offset: offsets[1],
            addend: 0x20,
        });
    chained_image(&build_chained_fixups(&spec))
}

/// `imports_format = 3`（`DYLD_CHAINED_IMPORT_ADDEND64`）：16 位库序号 + 64 位加数。
#[must_use]
pub fn demo_chained_addend64_wide() -> ChainedImage {
    let (symbols, offsets) = symbol_pool(&["_wideOne"]);
    let spec = ChainedFixupsSpec::new(DYLD_CHAINED_IMPORT_ADDEND64)
        .pool(symbols, minimal_starts_in_image(3))
        .import(ChainedImportSpec {
            lib_ordinal: 2,
            weak_import: false,
            name_offset: offsets[0],
            addend: 0x100,
        });
    chained_image(&build_chained_fixups(&spec))
}

/// 畸形：`imports_format = 9`（规范里不存在）—— 必须明确报错。
#[must_use]
pub fn malformed_chained_imports_format() -> Vec<u8> {
    let (symbols, offsets) = symbol_pool(&["_x"]);
    let spec = ChainedFixupsSpec::new(9)
        .pool(symbols, minimal_starts_in_image(3))
        .import(ChainedImportSpec {
            lib_ordinal: 1,
            weak_import: false,
            name_offset: offsets[0],
            addend: 0,
        });
    chained_image(&build_chained_fixups(&spec)).bytes
}

/// 畸形：`name_offset` 指向符号池之外 —— 必须拒绝（不许读越界的字节）。
#[must_use]
pub fn malformed_chained_name_offset_outside_pool() -> Vec<u8> {
    let (symbols, _offsets) = symbol_pool(&["_x"]);
    let spec = ChainedFixupsSpec::new(DYLD_CHAINED_IMPORT)
        .pool(symbols, minimal_starts_in_image(3))
        .import(ChainedImportSpec {
            lib_ordinal: 1,
            weak_import: false,
            // 池只有 3 字节（"_x\0"），这里指到 0x7FFF。
            name_offset: 0x7FFF,
            addend: 0,
        });
    chained_image(&build_chained_fixups(&spec)).bytes
}

/// 畸形：`symbols_format = 1`（zlib）—— 这是"本片没实现"，必须明确报错。
#[must_use]
pub fn malformed_chained_symbols_zlib() -> Vec<u8> {
    let (symbols, offsets) = symbol_pool(&["_x"]);
    let mut spec = ChainedFixupsSpec::new(DYLD_CHAINED_IMPORT)
        .pool(symbols, minimal_starts_in_image(3))
        .import(ChainedImportSpec {
            lib_ordinal: 1,
            weak_import: false,
            name_offset: offsets[0],
            addend: 0,
        });
    spec.symbols_format = SYMBOLS_FORMAT_ZLIB;
    chained_image(&build_chained_fixups(&spec)).bytes
}

/// 畸形：payload 只有 12 字节，装不下 28 字节的头 —— 必须报截断。
#[must_use]
pub fn malformed_chained_truncated_header() -> Vec<u8> {
    chained_image(&[0u8; 12]).bytes
}

/// 畸形：头里 `imports_count = 64`，实际只有 1 条 —— 表越过 payload，必须拒绝。
#[must_use]
pub fn malformed_chained_imports_count_past_payload() -> Vec<u8> {
    let (symbols, offsets) = symbol_pool(&["_x"]);
    let mut spec = ChainedFixupsSpec::new(DYLD_CHAINED_IMPORT)
        .pool(symbols, minimal_starts_in_image(3))
        .import(ChainedImportSpec {
            lib_ordinal: 1,
            weak_import: false,
            name_offset: offsets[0],
            addend: 0,
        });
    spec.imports_count_override = Some(64);
    chained_image(&build_chained_fixups(&spec)).bytes
}

/// 畸形：库序号 7，但样本只链接了 2 个 dylib —— 必须报错而不是静默索引。
#[must_use]
pub fn malformed_chained_ordinal_out_of_range() -> Vec<u8> {
    let (symbols, offsets) = symbol_pool(&["_x"]);
    let spec = ChainedFixupsSpec::new(DYLD_CHAINED_IMPORT)
        .pool(symbols, minimal_starts_in_image(3))
        .import(ChainedImportSpec {
            lib_ordinal: 7,
            weak_import: false,
            name_offset: offsets[0],
            addend: 0,
        });
    chained_image(&build_chained_fixups(&spec)).bytes
}
