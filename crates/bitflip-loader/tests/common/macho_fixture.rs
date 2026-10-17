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
/// `LC_DYLD_INFO_ONLY`（带 `LC_REQ_DYLD` 位的 `LC_DYLD_INFO`）。
pub const LC_DYLD_INFO_ONLY: u32 = 0x8000_0022;

/// `CPU_TYPE_X86`。
pub const CPU_TYPE_X86: u32 = 7;
/// `CPU_TYPE_X86_64`。
pub const CPU_TYPE_X86_64: u32 = 0x0100_0007;
/// `CPU_TYPE_ARM`。
pub const CPU_TYPE_ARM: u32 = 12;
/// `CPU_TYPE_ARM64`。
pub const CPU_TYPE_ARM64: u32 = 0x0100_000c;
/// `CPU_TYPE_POWERPC`。
pub const CPU_TYPE_POWERPC: u32 = 18;
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

/// `LC_SYMTAB`（只为了让"有符号表"这个分支可测；本片不解析符号表内容）。
#[must_use]
pub fn lc_symtab(little: bool) -> RawCommand {
    let mut bytes = vec![0u8; 24];
    put_u32(&mut bytes, 0, LC_SYMTAB, little);
    put_u32(&mut bytes, 4, 24, little);
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
        // "存在但**没有解析**"这两条 notes 各走一遍（本片不读它们的内容）。
        .command(lc_dyld_info_only(true))
        .command(lc_symtab(true))
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
