//! Mach-O 结构层解析（`docs/PLAN.md` M12）。
//!
//! # 已经覆盖什么
//!
//! | 结构 | 规范出处 | 状态 |
//! |------|---------|------|
//! | `mach_header` / `mach_header_64` | `mach-o/loader.h`（Apple XNU 的 `EXTERNAL_HEADERS`） | 全部字段 |
//! | `LC_SEGMENT` / `LC_SEGMENT_64` | 同上，`segment_command` / `segment_command_64` | 段 + 段内节 |
//! | `LC_MAIN` | 同上，`entry_point_command` | 入口点（**文件偏移** → 虚拟地址） |
//! | `LC_UNIXTHREAD` | 同上 `thread_command`；寄存器布局见 `mach/i386/thread_status.h`、`mach/arm/thread_status.h` | 解出 PC（四种架构），其余只记录存在性 |
//! | `LC_UUID` | 同上 `uuid_command` | 16 字节 → 小写十六进制 |
//! | `LC_LOAD_DYLIB` / `LC_LOAD_WEAK_DYLIB` | 同上 `dylib_command` | 依赖库名 |
//! | `LC_SYMTAB` | 同上 `symtab_command` + `mach-o/nlist.h` 的 `nlist` / `nlist_64` | 符号名/地址/节/外部性；32 位与 64 位各自按表项宽度（12 / 16 字节）解 |
//! | `LC_FUNCTION_STARTS` | 同上 `linkedit_data_command` + ULEB128 增量 | 函数起点（绝对虚拟地址，升序） |
//! | `LC_DYLD_INFO` / `LC_DYLD_INFO_ONLY` | 同上 `dyld_info_command` | 导出 trie（`export_off`）+ bind / lazy_bind 操作码流 |
//! | `LC_DYLD_EXPORTS_TRIE` | 同上 `linkedit_data_command` | 导出 trie 的另一种来处（iOS 13+ 的命令形式） |
//! | `LC_DYLD_CHAINED_FIXUPS` | `mach-o/fixup-chains.h`（`dyld_chained_fixups_header` + 三种 `dyld_chained_import*` + `dyld_chained_starts_in_image` / `_in_segment` + `dyld_chained_ptr_*`） | 导入表（名字 / 库 / weak / 加数）+ **指针链**（每条导入的槽位地址），见 [`chained`]：64 位的链格式全走；32 位格式明确报"暂不支持" |
//! | fat / universal | `mach-o/fat.h` | 见 [`fat`]：切片枚举 + 选片 + `parse_slice`，已接进容器与会话 |
//!
//! # 明确没做的（不要以为有）
//!
//! - **`LC_DYSYMTAB`**：动态符号表/间接符号表没有解析。
//! - **`LC_DYLD_CHAINED_FIXUPS` 的指针链：64 位格式已走，32 位没走。**
//!   链式修复（iOS 13 之后的新格式）把绑定写进 `LC_DYLD_CHAINED_FIXUPS`，
//!   `LC_DYLD_INFO` 的 bind 流**整条不存在** —— 实测 `temp/` 下四份 IPA 里三份是
//!   这样（SideStore / LiveContainer / Stapxs）。本片解它的**导入表**（[`chained`]：
//!   `imports_offset` / 符号池），并且沿 `starts_offset` 的指针链走，把每条导入
//!   写进的槽位地址填进 `iat_slot`（见 [`chained::walk_chains`]）。**没做的**是
//!   32 位的链格式（`DYLD_CHAINED_PTR_32*`）与 x86_64 / dyld 共享缓存的内核格式：
//!   遇到就明确报 `NotSupported`，不按 64 位硬读给出错地址。链里的 **rebase** 指针
//!   只计数、不当作导入（它们指向本镜像内部）。老格式（`LC_DYLD_INFO_ONLY`，如
//!   `net.kdt.pojavlauncher…ipa`）仍走 bind 流，那条路上 `iat_slot` 同样有地址
//!   （1 382 + 165 条）。
//! - **weak bind**（`weak_bind_off` / `weak_bind_size`）：操作码语言与普通 bind 相同，
//!   但语义是"弱定义解析"，本片没有接（`notes` 会说明存在但没解）。
//! - **arm64e 的线程化绑定**（`BIND_OPCODE_THREADED` 的 APPLY 分支）：要用线程化指针表
//!   与 rebase 信息，本片不解；遇到时记 `notes` 并停止那条流。
//! - **objc / swift 元数据**（`__objc_classname`、`__swift5_*` 等）：按普通节列出，
//!   不解析内容。
//! - **代码签名**（`LC_CODE_SIGNATURE`）：只记录存在性，**不做校验**。
//! - **`.app` bundle / IPA 容器语义**：目录容器由 [`crate::sniff_file`] 识别
//!   （`looks_like_app_directory`），主二进制由 [`crate::bundle::find_main_binary`]
//!   定位 —— 那是打包约定层面的判断，不是 Mach-O 格式的一部分；`LoaderError::IsDirectory`
//!   现在只拒绝"不是 `.app` 形状"的目录。
//!
//! # 几处判断，写在这里免得被当成 bug
//!
//! 1. **入口点换算。** `LC_MAIN.entryoff` 是**文件偏移**（相对文件开头），而对象模型
//!    与分析层要的是虚拟地址。换算方式：找文件范围 `[fileoff, fileoff+filesize)`
//!    覆盖它的段，用该段的 `(fileoff, vmaddr)` 做线性平移 —— 通常就是 `__TEXT`。
//!    换算式写进 `notes`（用户能核对）。**找不到覆盖它的段时入口点留 `None`**，不猜。
//! 2. **大端 Mach-O。** 结构层按文件端序读（[`Reader`] 两种端序都支持），所以
//!    `MH_CIGAM` / `MH_CIGAM_64` 不会被误读。现实里大端 Mach-O 基本只有
//!    ppc/armeb —— ppc 现在有解码后端了（见下），所以这条路径**不再只是**单测里
//!    走到：一个 `cputype = 18` 且文件头是 `MH_CIGAM` 的样本会被解析成
//!    `ppc/32/be` 并交给 capstone 的 ppc 后端（有单测；本机没有真实 ppc 样本）。
//! 3. **ppc / ppc64 是真支持。** `CPU_TYPE_POWERPC`（18）/ `ppc64`（`0x0100_0012`）
//!    映射到 `bitflip_arch::Arch::PowerPc` / `PowerPc64`，解码走 capstone 的
//!    `arch_powerpc` 后端（`Capstone::new().ppc()`），端序按文件给（ppc Mach-O
//!    都是大端）。**仍然没做的**：`LC_UNIXTHREAD` 的 ppc 线程状态没有解 ——
//!    `ppc_thread_state(_64)` 的 `srr0` 是 PC，但它的 `count` 与字段表本机
//!    没有权威来源可对照，所以 ppc 的入口点只有 `LC_MAIN` 那条路；
//!    走 `LC_UNIXTHREAD` 的 ppc 可执行文件入口点会记成未知并在 `notes` 里说明。
//! 4. **arm64e** 的 `cputype` 与 arm64 相同（`0x0100_000c`），区别只在
//!    `cpusubtype == 2`。架构按 AArch64 解码（指令层面这是对的），指针认证（PAC）
//!    语义不还原 —— 记进 `notes`。
//! 5. **`LC_UUID` / dylib 名 / 符号 / 函数起点都在 [`Object`] 里。** `parse` 会把
//!    它们填进 [`Object::uuid`] / [`Object::dylibs`] / [`Object::symbols`] /
//!    [`Object::function_starts`]（结构层的原始事实仍在 [`MachOFile`] 里，两者同源）。
//!    刻意**不**只写进 `notes`：那样程序化消费只能去解析字符串，而字符串是给人看的
//!    降级说明，不是数据通道。
//! 6. **符号表的两个"不是事实"的地方，对象模型里如实标注。** `nlist` 没有大小字段，
//!    所以 `RawSymbol::size` 一律 0（未知）；`nlist` 也没有"这是函数"标志，所以
//!    `RawSymbol::is_function` 是从**符号所在节的指令标志**推出来的（`MachOSymbol`
//!    上写明了这一点）。`n_type & N_TYPE == N_SECT` 的取值是 0xe —— 它是类型字段里
//!    的一个取值，不是单独的位，判"定义在节里"必须按掩码比较。
//! 7. **调试 stab 不进 `Object.symbols`，但也不被悄悄丢掉。** `N_STAB != 0` 的条目
//!    留在 [`MachOFile::symbols`] 里，条数记在 [`MachOFile::stab_symbols`]，并写进
//!    `notes` —— 让 `nm` 风格的输出混进 `N_FUN` / `N_SO` 会让"符号数"这个数字失真。
//! 8. **`LC_FUNCTION_STARTS` 的增量基准。** 第一个值是相对**镜像基址**
//!    （`__TEXT.vmaddr`）的增量，其后每个值是相对**上一个函数起点**的增量，0 字节
//!    终止。没有 `__TEXT` 段时基址未知，函数起点留空并在 `notes` 里说明 ——
//!    delta 无从还原成地址，猜一个基址等于编造地址。payload 没遇到终止符时
//!    记一条"可能被截断"，不静默返回短表。
//! 9. **导出与导入走 `Object.exports` / `Object.imports`，不是只写 `notes`。**
//!    导出 trie 解成 [`Object::exports`]（`address` 是**基址 + trie 里的偏移**），
//!    bind / lazy_bind 操作码流解成 [`Object::imports`]（`iat_slot` 就是被写入的
//!    指针槽地址，`module` 是**解析后的库名**，不是裸序号）。re-export 没有本地地址，
//!    所以它的 `address` 是 0 —— 那是"trie 里没有地址字段"的如实表达，`forwarder`
//!    给出"库名#原始名"。`STUB_AND_RESOLVER` 的第二个地址保留在
//!    [`MachOExport::other`]，并且**逐条**写进 `notes`（对象模型里 `Export` 只有一个
//!    `address` 字段，放不下两个 —— 宁可用 notes 说清楚，也不丢第二条地址）。
//!    `LC_DYLD_CHAINED_FIXUPS` 的导入表同样进 [`Object::imports`]（`module` 是解析后
//!    的库名），它的**槽位地址来自指针链**：走链时按 bind 指针里的 `ordinal`（导入表
//!    下标）把地址填到该条导入上，所以 `iat_slot` 现在有真实地址；链里没有绑定到的
//!    导入（例如没被引用的 weak 导入）保持 `None`（未知），不是 0。weak 与 addend 在
//!    `Import` 里没有字段，条数与样例写进 `notes`（结构化细节保留在
//!    [`MachOFile::chained_fixups`]）。
//!
//! # 解析纪律（与 PE/ELF 一致）
//!
//! 一律经 [`Reader`] 读字节，越界返回 `ParseError`；表项数量来自不可信输入
//! （`ncmds` / `sizeofcmds` / `nsects` / `nsyms`），先整体校验范围再逐项解析，
//! 绝不先分配。能确定的就解析，不能确定的写进 `notes` —— 不猜、不留空白解释。

use std::fmt::Write as _;

use bitflip_arch::{Arch, ArchSpec, Endian};

use crate::object::{
    ContentKind, Export, FileRange, FormatInfo, Import, Object, ObjectId, Perms, RawSymbol,
    Section, Segment, SymbolTableSource,
};
use crate::reader::{Endianness, ParseError, Reader};
use crate::ObjectKind;

pub mod bind;
pub mod chained;
pub mod export_trie;
pub mod fat;

pub use bind::{BindImport, BindKind};
pub use chained::{ChainWalk, ChainedFixups, ChainedImport};
pub use export_trie::MachOExport;

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
/// `LC_SYMTAB`：符号表（`symtab_command`）。
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
/// `LC_FUNCTION_STARTS`：函数起点表（`linkedit_data_command`，ULEB128 增量）。
pub const LC_FUNCTION_STARTS: u32 = 0x26;
/// `LC_DYLD_CHAINED_FIXUPS`：新版 dyld 的链式绑定信息。
pub const LC_DYLD_CHAINED_FIXUPS: u32 = 0x8000_0034;
/// `LC_DYLD_EXPORTS_TRIE`：导出 trie 的独立命令（`linkedit_data_command` 形式）。
///
/// iOS 13 之后 Xcode 不再写 `LC_DYLD_INFO`（绑定改走链式修复），但导出 trie 仍然要
/// 有，于是它搬到了这条带 `LC_REQ_DYLD` 位的独立命令里。
pub const LC_DYLD_EXPORTS_TRIE: u32 = 0x8000_0033;

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
/// `sizeof(struct symtab_command)`：cmd + cmdsize + 4 个 `uint32`。
pub const SYMTAB_COMMAND_SIZE: u64 = 24;
/// `sizeof(struct nlist_64)`：`uint32 n_strx` + 4 个 1/2 字节字段 + `uint64 n_value`。
pub const NLIST64_SIZE: u64 = 16;
/// `sizeof(struct nlist)`（32 位）：`uint32 n_strx` + 4 个 1/2 字节字段 + `uint32 n_value`。
pub const NLIST32_SIZE: u64 = 12;
/// `sizeof(struct linkedit_data_command)`：cmd + cmdsize + dataoff + datasize。
pub const LINKEDIT_DATA_COMMAND_SIZE: u64 = 16;

// ── nlist 的 `n_type` / `n_desc` 位（`mach-o/nlist.h`） ─────────────────────
//
// 规范原文：
//   #define N_STAB 0xe0  /* if any of these bits set, a symbolic debugging entry */
//   #define N_PEXT 0x10  /* private external symbol bit */
//   #define N_TYPE 0x0e  /* mask for the type bits */
//   #define N_EXT  0x01  /* external symbol bit, set for external symbols */
//   #define N_UNDF 0x0   /* undefined, n_sect == NO_SECT */
//   #define N_ABS  0x2   /* absolute, n_sect == NO_SECT */
//   #define N_SECT 0xe   /* defined in section number n_sect */
//   #define N_PBUD 0xc   /* prebound undefined (defunct) */
//   #define N_INDR 0xa   /* indirect */
// 注意 `N_SECT` 的取值是 0xe，它是 `N_TYPE` 里的一个**取值**而不是单独的位 ——
// 判断"定义在某个节里"必须写 `n_type & N_TYPE == N_SECT`。

/// `N_STAB`：置位表示这是调试用的 stab，不是普通符号。
pub const N_STAB: u8 = 0xe0;
/// `N_PEXT`：私有外部符号。
pub const N_PEXT: u8 = 0x10;
/// `N_TYPE`：类型位掩码。
pub const N_TYPE: u8 = 0x0e;
/// `N_EXT`：外部符号位。
pub const N_EXT: u8 = 0x01;
/// `N_UNDF`：未定义（`n_sect == NO_SECT`）。
pub const N_UNDF: u8 = 0x0;
/// `N_ABS`：绝对符号（值是常量，不是地址）。
pub const N_ABS: u8 = 0x2;
/// `N_SECT`：定义在 `n_sect` 号节里。
pub const N_SECT: u8 = 0xe;
/// `N_PBUD`：prebound undefined（已废弃，含义同未定义）。
pub const N_PBUD: u8 = 0xc;

/// `N_WEAK_REF`（`n_desc`）：未定义引用的弱链接。
pub const N_WEAK_REF: u16 = 0x0040;
/// `N_WEAK_DEF`（`n_desc`）：弱定义。
pub const N_WEAK_DEF: u16 = 0x0080;

/// 符号表条目上限（与 ELF 的 `MAX_SYMBOLS` 同一量级）。
///
/// 范围校验已经保证 `nsyms × entsize` 落在文件内，所以这个上限挡的是
/// "文件本身有几百 MB 且符号表填满"的放大输入 —— 一条表项要分配一个 `String`，
/// 不设上限就是拿不可信输入换内存。
const MAX_SYMBOLS: u64 = 4_000_000;
/// `LC_FUNCTION_STARTS` 的条目上限（每项 8 字节内存，量级同 `MAX_SYMBOLS`）。
const MAX_FUNCTION_STARTS: u64 = 4_000_000;

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
/// `CPU_TYPE_POWERPC`：ppc 32 位（Mach-O 的 ppc 一律大端）。
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
/// 为什么不直接给 [`Object`]：下面这几项要么在对象模型里没有位置，要么
/// 对象模型只留了归一化后的形状 ——
///
/// * `cputype` / `cpusubtype` / `filetype` / `ncmds` / `sizeofcmds` / `reserved`
///   这些**原始**头字段（对象模型只归一化了一部分）；
/// * 节的 `align` / `flags` / `offset`（[`crate::object::Section`] 会丢掉它们）。
///
/// `uuid` 与 `dylibs` **两边都有**（M12 第二片起 [`Object::uuid`] /
/// [`Object::dylibs`] 也有了）：要对象模型走 [`parse`]，要全部原始事实走 [`read`]。
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
    /// 符号表条目（`LC_SYMTAB` 的 `nlist` / `nlist_64`，**按表里的顺序**）。
    ///
    /// **含调试 stab**（[`MachOSymbol::is_stab`]）：结构层不替调用方过滤，
    /// 但对象模型只把非 stab 的那些放进 [`Object::symbols`] —— 让 `nm` 风格的
    /// 输出里混进 `N_FUN` / `N_SO` 这类调试条目，会让"符号数"这个数字失真。
    /// 没有 `LC_SYMTAB` 时是空表；有但 `nsyms = 0` 时也是空表（原因在 `notes` 里）。
    pub symbols: Vec<MachOSymbol>,
    /// `N_STAB != 0` 的条目数（它们不在 [`Object::symbols`] 里，但也没有被悄悄丢掉）。
    pub stab_symbols: usize,
    /// `LC_FUNCTION_STARTS` 解出的函数起点（**绝对虚拟地址，升序**）。
    ///
    /// 空表可能是"没有这条命令"，也可能是"表是空的"或"没有镜像基址、无从还原"
    /// —— 三种情形的 `notes` 不同，别把它们读成同一件事。
    pub function_starts: Vec<u64>,
    /// 是否存在 `LC_SYMTAB`。**只代表命令存在**；符号是否解析出来看 [`Self::symbols`]。
    pub has_symtab: bool,
    /// `LC_DYLD_INFO` / `LC_DYLD_INFO_ONLY` 的十条字段（`dyld_info_command`）。
    ///
    /// `None` = 没有这条命令。新版 Xcode 的产物通常没有它（改走
    /// `LC_DYLD_CHAINED_FIXUPS` + `LC_DYLD_EXPORTS_TRIE`），所以 `None` 不代表
    /// "这个文件没有绑定信息"，只代表"不是这种写法"。
    pub dyld_info: Option<DyldInfo>,
    /// 导出 trie 的文件范围与实际来处。
    pub export_trie: Option<ExportTrieSource>,
    /// 导出 trie 解出的导出（**按 trie 里边出现的顺序**）。
    ///
    /// ld64 写出来时这个顺序就是字典序，但本层**不额外排序** —— 再排一次会把
    /// "trie 没按规范解出来"这种问题盖住。
    ///
    /// 空表有三种含义，`notes` 里分得清：没有这张表 / 表是空的 / 没有镜像基址
    /// 算不出地址。
    pub exports: Vec<MachOExport>,
    /// `bind` + `lazy_bind` 解出的导入（按流里的执行顺序）。
    ///
    /// 空表同样不止一种含义：没有 `LC_DYLD_INFO`（新版走链式修复）、
    /// 流是空的、或流里遇到本片不解的 `THREADED`（`notes` 会写）。
    pub imports: Vec<BindImport>,
    /// `LC_DYLD_CHAINED_FIXUPS` 的导入表（iOS 13 之后 Xcode 的绑定写法）。
    ///
    /// `None` = 没有这条命令；`Some` 而 [`ChainedFixups::imports`] 为空 = 文件里
    /// 明确写着 `imports_count = 0` —— 两种含义不同，别读成同一件事。
    ///
    /// 导入的槽位地址来自 [`ChainedFixups::chains`] 那次走链（每条
    /// [`ChainedImport::iat_slot`]）；`chains` 为 `None` 时地址未知，原因在 `notes`
    /// 里（没有链描述 / 没有镜像基址换不出地址）。
    pub chained_fixups: Option<ChainedFixups>,
    /// 解析过程中的说明（降级、跳过、没做的部分）。
    pub notes: Vec<String>,
}

/// `dyld_info_command` 的十个 `uint32` 字段（`mach-o/loader.h`）。
///
/// 字段偏移：`rebase_off +0x8`、`rebase_size +0xC`、`bind_off +0x10`、
/// `bind_size +0x14`、`weak_bind_off +0x18`、`weak_bind_size +0x1C`、
/// `lazy_bind_off +0x20`、`lazy_bind_size +0x24`、`export_off +0x28`、
/// `export_size +0x2C`（命令本身 48 字节）。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct DyldInfo {
    /// 原始 `cmd` 值（[`LC_DYLD_INFO`] 还是 [`LC_DYLD_INFO_ONLY`]）。
    pub command: u32,
    /// rebase 流的文件偏移与大小（本片**没有**执行 rebase 流）。
    pub rebase_off: u64,
    /// rebase 流的字节数。
    pub rebase_size: u64,
    /// bind 流的文件偏移。
    pub bind_off: u64,
    /// bind 流的字节数。
    pub bind_size: u64,
    /// weak bind 流的文件偏移（本片**没有**解它）。
    pub weak_bind_off: u64,
    /// weak bind 流的字节数。
    pub weak_bind_size: u64,
    /// lazy bind 流的文件偏移。
    pub lazy_bind_off: u64,
    /// lazy bind 流的字节数。
    pub lazy_bind_size: u64,
    /// 导出 trie 的文件偏移。
    pub export_off: u64,
    /// 导出 trie 的字节数。
    pub export_size: u64,
}

/// 导出 trie 的来处：哪条命令、什么范围。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ExportTrieSource {
    /// 给出这张表的加载命令（[`LC_DYLD_EXPORTS_TRIE`] 或 [`LC_DYLD_INFO`] /
    /// [`LC_DYLD_INFO_ONLY`]）。
    pub command: u32,
    /// 文件偏移。
    pub dataoff: u64,
    /// 字节数。
    pub datasize: u64,
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

/// 一条符号表条目（`struct nlist_64` / `struct nlist`，见 `mach-o/nlist.h`）。
///
/// 字段全部是**原始值**：`n_type` / `n_sect` / `n_desc` 的位语义由下面的访问器
/// 解释，不在这里归一化 —— 归一化会丢掉"这条符号到底是什么"的取证材料。
///
/// `nlist` 没有大小字段，也没有"这是函数"标志：所以对象模型里的
/// [`crate::object::RawSymbol::size`] 一律是 0（未知），
/// `is_function` 只能从"所在的节是不是代码节"推出来（见 [`Self::is_function`]）。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MachOSymbol {
    /// 名字（来自字符串表；`n_strx == 0` 时是空串，规范里 0 表示"没有名字"）。
    pub name: String,
    /// `n_value`：已定义的符号是虚拟地址，未定义的是 0。
    pub value: u64,
    /// `n_type` 原始值。
    pub n_type: u8,
    /// `n_sect` 原始值（**1 基**，0 = `NO_SECT`）。
    pub n_sect: u8,
    /// `n_desc` 原始值（`N_WEAK_DEF` / `N_WEAK_REF` 等位）。
    pub n_desc: u16,
    /// 解析出来的所在节名（与 [`Object::sections`] 同一命名 `段名,节名`）。
    ///
    /// `None` = `n_sect == 0`（没有节）或 `n_sect` 超出节总数 —— 后者是文件自相
    /// 矛盾，会连同错误一起在 `notes` 里说明；这里不编一个节名。
    pub section: Option<String>,
    /// 是否落在**代码节**里（`S_ATTR_PURE_INSTRUCTIONS` / `S_ATTR_SOME_INSTRUCTIONS`）。
    ///
    /// 这是从节的 `flags` 推出来的，**不是** `nlist` 里的事实（`nlist` 没有类型
    /// 字段能区分函数与数据）。文档这样写，是为了让调用方知道这一位有多可信。
    pub is_function: bool,
}

impl MachOSymbol {
    /// 是调试 stab 吗（`N_STAB` 任一位置位）。
    #[must_use]
    pub const fn is_stab(&self) -> bool {
        self.n_type & N_STAB != 0
    }

    /// 是外部符号吗（`N_EXT`）。
    #[must_use]
    pub const fn is_external(&self) -> bool {
        self.n_type & N_EXT != 0
    }

    /// 是私有外部符号吗（`N_PEXT`）。
    #[must_use]
    pub const fn is_private_external(&self) -> bool {
        self.n_type & N_PEXT != 0
    }

    /// 未定义吗（`N_UNDF` / `N_PBUD`）。
    #[must_use]
    pub const fn is_undefined(&self) -> bool {
        matches!(self.n_type & N_TYPE, N_UNDF | N_PBUD)
    }

    /// 是弱符号吗。
    ///
    /// 弱定义看 `n_desc` 的 `N_WEAK_DEF`，未定义引用的弱链接看 `N_WEAK_REF` ——
    /// 两个位在**不同**的 `n_type` 分支上有意义，所以这里按"是否已定义"分。
    #[must_use]
    pub const fn is_weak(&self) -> bool {
        self.n_desc & N_WEAK_DEF != 0 || (self.is_undefined() && self.n_desc & N_WEAK_REF != 0)
    }
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
/// 魔数不是 Mach-O；`cputype` 未映射；命令区越界或
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
                     单一架构。切片枚举与会话成员化都已经实现（`format::macho::fat::read` /\
                     `fat::parse_slice`，会话层按 `fat::SELECTION_RULE_ZH` 选片），\
                     所以请走那条路：`parse` 只接受**一层**薄 Mach-O"
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
/// 架构表在 `bitflip_arch`（`Arch::from_macho_cputype`）—— 解析器**不**自己
/// 维护一份 CPU 编号表，否则"哪几个 CPU 能解"会在两处各说一次，迟早分叉。
/// 这里只做 Mach-O 特有的事：把文件端序拼进去、给 arm64e 与 ppc 记说明。
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
            // Mach-O 的 ppc 事实上都是大端（`MH_CIGAM`）。小端文件配 ppc 的
            // `cputype` 虽然能解，但那不是 Apple 工具链的产物；这是**事实说明**
            // 而不是拒绝 —— 结构层按文件端序读，结论仍然自洽。
            if (cputype == CPU_TYPE_POWERPC || cputype == CPU_TYPE_POWERPC64)
                && endian == Endian::Little
            {
                notes.push(
                    "cputype 是 PowerPC，但文件头是 MH_MAGIC（小端）：现实里 Mach-O 的 \
                     ppc 切片一律是大端，这份文件不是 Apple 工具链的常规产物"
                        .to_string(),
                );
            }
            Ok(spec)
        }
        None => Err(ParseError::Unsupported {
            what: "cputype",
            value: u64::from(cputype),
            detail: "未知或尚未映射的 Mach-O CPU 类型（已映射：x86 / x86_64 / arm / \
                     arm64 / ppc / ppc64）",
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
    symtab: Option<SymtabCommand>,
    function_starts: Option<LinkeditData>,
    /// `LC_DYLD_INFO` / `LC_DYLD_INFO_ONLY` 的十条字段。
    dyld_info: Option<DyldInfo>,
    /// `LC_DYLD_EXPORTS_TRIE` 的 `linkedit_data_command`。
    exports_trie: Option<LinkeditData>,
    /// `LC_DYLD_CHAINED_FIXUPS` 的 `linkedit_data_command`。
    chained_fixups: Option<LinkeditData>,
    has_codesig: bool,
    unhandled: Vec<u32>,
    /// 命令本身合法、但需要说明的事（重复命令等）。逐条走到 `notes` 里。
    notes: Vec<String>,
    /// 走完 `ncmds` 条命令后，`sizeofcmds` 里还剩多少字节。
    trailing_bytes: u64,
}

/// `LC_SYMTAB` 的原始字段（`struct symtab_command`）。
#[derive(Debug, Clone, Copy)]
struct SymtabCommand {
    /// 符号表在文件里的偏移。
    symoff: u64,
    /// 符号条目数。
    nsyms: u64,
    /// 字符串表在文件里的偏移。
    stroff: u64,
    /// 字符串表的字节数。
    strsize: u64,
}

/// `linkedit_data_command` 的文件范围（`LC_FUNCTION_STARTS` / `LC_CODE_SIGNATURE` 共用）。
#[derive(Debug, Clone, Copy)]
struct LinkeditData {
    /// 数据在文件里的偏移。
    dataoff: u64,
    /// 数据的字节数。
    datasize: u64,
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
            "大端 Mach-O：所有字段按大端解析。现实里大端 Mach-O 基本只有 ppc/armeb，\
             而 ppc 的指令解码走 capstone 的 ppc 后端（端序同样按文件给）"
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

    // ── 符号表与函数起点 ────────────────────────────────────────────────
    //
    // 放在镜像基址之后：`LC_FUNCTION_STARTS` 的第一个增量是相对 `__TEXT.vmaddr`
    // 的，没有基址就无从还原（那时留空并说明，不猜）。
    let symbols = match facts.symtab {
        Some(command) => parse_symbols(reader, command, &header, &facts.segments, &mut notes)?,
        None => Vec::new(),
    };
    let stab_symbols = symbols.iter().filter(|symbol| symbol.is_stab()).count();
    let ordinary_symbols = symbols.len() - stab_symbols;
    let function_starts = match facts.function_starts {
        Some(range) => decode_function_starts(reader, range, image_base, &mut notes)?,
        None => {
            notes.push(
                "没有 LC_FUNCTION_STARTS：函数边界没有权威来源，只能靠符号表或反汇编识别\
                 （Object.function_starts 因此是空表 —— 那是\"表不存在\"，不是\"没有函数\"）"
                    .to_string(),
            );
            Vec::new()
        }
    };

    // ── 导出 trie 与导入（bind / lazy_bind） ───────────────────────────
    //
    // 放在符号表之后：这两段都要镜像基址（导出地址是"基址 + 偏移"）与段表
    // （绑定槽位是"段基址 + 段内偏移"），而段表与基址在这一步之前已经定了。
    let (export_trie, exports) = decode_exports(reader, &facts, image_base, &mut notes)?;
    let imports = decode_imports(reader, &facts, &header, &mut notes)?;
    // 链式修复：导入表（`imports_offset`）+ 指针链（`starts_offset`，要镜像基址与段表）。
    let chained_fixups = decode_chained_fixups(reader, &facts, image_base, &mut notes)?;

    // ── 没做的部分：一律写进 notes，不让界面看起来"完整" ────────────────
    match facts.symtab {
        None => notes.push(
            "没有 LC_SYMTAB（符号表已被剥离或本来就没有）：Object.symbols 是空的，\
             这是文件里写着的事实，不是没解析"
                .to_string(),
        ),
        Some(_) if ordinary_symbols > 0 => {
            notes.push(format!(
                "已解析 LC_SYMTAB：{ordinary_symbols} 条普通符号{}",
                if stab_symbols > 0 {
                    format!("，另有 {stab_symbols} 条调试 stab 不计入 Object.symbols")
                } else {
                    String::new()
                }
            ));
            notes.push(
                "Mach-O 的 nlist **没有大小字段**：Object.symbols 的 size 一律为 0（未知）；\
                 is_function 是从符号所在节的指令标志推出来的，不是 nlist 里的事实"
                    .to_string(),
            );
        }
        Some(_) => {}
    }
    if stab_symbols > 0 && ordinary_symbols == 0 {
        notes.push(format!(
            "LC_SYMTAB 里只有 {stab_symbols} 条调试 stab（N_STAB != 0）：它们不是普通符号，\
             因此 Object.symbols 为空 —— 调试信息本身也没有解析"
        ));
    }
    if !function_starts.is_empty() {
        notes.push(format!(
            "已解析 LC_FUNCTION_STARTS：{} 个函数起点（第一个增量相对镜像基址 \
             {:#x}，其后都是相对上一个起点的增量，0 字节终止）",
            function_starts.len(),
            image_base.unwrap_or(0)
        ));
    }
    // ── 导出：解出多少、没解什么，都要说 ──────────────────────────────
    match &export_trie {
        Some(source) => {
            if !exports.is_empty() {
                let reexports = exports.iter().filter(|item| item.is_reexport()).count();
                let stubs = exports
                    .iter()
                    .filter(|item| item.is_stub_and_resolver())
                    .count();
                notes.push(format!(
                    "已解析导出 trie（{:#010x}，文件范围 {:#x}..{:#x}）：{} 条导出\
                     {}{}（地址 = 镜像基址 {:#x} + trie 里的偏移）",
                    source.command,
                    source.dataoff,
                    source.dataoff + source.datasize,
                    exports.len(),
                    if reexports > 0 {
                        format!("，其中 {reexports} 条是 re-export（转发到别的库，没有本地地址）")
                    } else {
                        String::new()
                    },
                    if stubs > 0 {
                        format!("，{stubs} 条是 STUB_AND_RESOLVER（带第二个地址）")
                    } else {
                        String::new()
                    },
                    image_base.unwrap_or(0)
                ));
            }
            // `STUB_AND_RESOLVER` 的第二个地址在对象模型里放不下（`Export` 只有一个
            // `address`）：逐条写进 notes，不丢。真实二进制里这种导出很少。
            for item in exports.iter().filter(|item| item.is_stub_and_resolver()) {
                notes.push(format!(
                    "导出 {} 带第二个地址（STUB_AND_RESOLVER 的 `other` 字段）：\
                     address = {:#x} / other = {:#x}。规范没有说明哪个是 stub、哪个是 \
                     resolver，所以这里只报两个地址，不替它下结论",
                    item.name,
                    item.address.unwrap_or(0),
                    item.other.unwrap_or(0)
                ));
            }
        }
        None => notes.push(
            "没有导出 trie（既没有 LC_DYLD_EXPORTS_TRIE，也没有 LC_DYLD_INFO 的 \
             export_off/export_size）：Object.exports 为空 —— 那是\"这个文件没有这张表\"，\
             不是没解析"
                .to_string(),
        ),
    }

    // ── 导入：哪些解了、哪些在这份文件里根本没有 ──────────────────────
    match facts.dyld_info {
        Some(info) => {
            let regular = imports
                .iter()
                .filter(|item| item.kind == BindKind::Regular)
                .count();
            let lazy = imports.len() - regular;
            if imports.is_empty() {
                if info.bind_size > 0 || info.lazy_bind_size > 0 {
                    notes.push(format!(
                        "有 LC_DYLD_INFO 的绑定流（bind {} 字节 / lazy_bind {} 字节），\
                         但一条导入都没解出来：流里只有段/符号的设置而没有 DO_BIND ——\
                         这是文件里的事实，不是没解析",
                        info.bind_size, info.lazy_bind_size
                    ));
                } else {
                    notes.push(
                        "有 LC_DYLD_INFO，但 bind / lazy_bind 两段都是空的：这个文件没有经典\
                         绑定数据，Object.imports 因此为空（不是\"没有导入\"，是这份文件\
                         没写这种数据）"
                            .to_string(),
                    );
                }
            } else {
                let libraries = imports
                    .iter()
                    .map(|item| item.dylib.as_str())
                    .collect::<std::collections::BTreeSet<_>>()
                    .len();
                notes.push(format!(
                    "已解析 dyld 绑定：{} 条导入（普通 {regular} + 惰性 {lazy}），\
                     分布在 {libraries} 个库里（库序号已按 LC_LOAD_DYLIB 的顺序解析成库名；\
                     槽位地址 = 段 vmaddr + 段内偏移）",
                    imports.len()
                ));
            }
            if info.weak_bind_size > 0 {
                notes.push(format!(
                    "有 weak bind 流（{} 字节）：本片**没有**解它（弱定义的语义与普通 bind \
                     不同），这部分导入不在 Object.imports 里",
                    info.weak_bind_size
                ));
            }
            if info.rebase_size > 0 {
                notes.push(format!(
                    "有 rebase 流（{} 字节）：本片**没有**执行它。rebase 写的是本镜像内部\
                     指针，不是导入，所以不影响 Object.imports",
                    info.rebase_size
                ));
            }
        }
        None => {
            if facts.chained_fixups.is_some() {
                notes.push(
                    "没有 LC_DYLD_INFO：新版 Xcode 的产物把绑定写进 LC_DYLD_CHAINED_FIXUPS，\
                     导入改从它的**导入表**解（链式修复那条说明里写了条数与\"没有走链\"的\
                     限制）—— 这里缺的是\"经典 bind 流\"，不是\"没有导入\""
                        .to_string(),
                );
            } else {
                notes.push(
                    "没有 LC_DYLD_INFO，也没有 LC_DYLD_CHAINED_FIXUPS：Mach-O 的导入表只存在\
                     于这两种数据里，这份文件两种都没有 —— Object.imports 为空是文件里的事实"
                        .to_string(),
                );
            }
        }
    }

    // ── 链式修复（LC_DYLD_CHAINED_FIXUPS）：解了导入表，没走指针链 ──────
    //
    // 两件事必须分开说（CLAUDE.md §7）："导入了什么"这次是真的解出来了；
    // "写进哪个槽位"要靠沿链走 + pointer_format 还原，本片没做 —— 所以对象模型里
    // 这些导入的 iat_slot 是 None（未知），不是 0。
    if let Some(fixups) = &chained_fixups {
        if fixups.imports.is_empty() {
            notes.push(format!(
                "有 LC_DYLD_CHAINED_FIXUPS（imports_format = {} / {}，symbols_format = {}），\
                 但头里写着 imports_count = 0、解出 0 条导入：Object.imports 为空是文件里的\
                 事实，不是没解析",
                fixups.imports_format,
                fixups.imports_format_name(),
                fixups.symbols_format
            ));
        } else {
            let libraries = fixups
                .imports
                .iter()
                .map(|item| item.dylib.as_str())
                .collect::<std::collections::BTreeSet<_>>()
                .len();
            notes.push(format!(
                "已解析 LC_DYLD_CHAINED_FIXUPS 的**导入表**（imports_format = {} / {}，\
                 symbols_format = {}，imports_count = {}）：{} 条导入，分布在 {libraries} 个库里\
                 （lib_ordinal 已按 LC_LOAD_DYLIB 的顺序解析成库名；0xFF/0xFFFF = \
                 <main-executable>、0xFE/0xFFFE = <flat-lookup>）",
                fixups.imports_format,
                fixups.imports_format_name(),
                fixups.symbols_format,
                fixups.imports_count,
                fixups.imports.len()
            ));

            // 对象模型的 `Import` 没有 weak / addend 字段：不编字段，改成有界的说明
            // （条数 + 前几条样例），结构化细节仍在 `MachOFile::chained_fixups` 里。
            let weak: Vec<&str> = fixups
                .imports
                .iter()
                .filter(|item| item.weak_import)
                .map(|item| item.name.as_str())
                .collect();
            if !weak.is_empty() {
                notes.push(format!(
                    "导入表里有 {} 条 weak_import（位 8 / 位 16）。对象模型的 `Import` 没有\
                     weak 字段，这里只给条数与样例（前 {} 条：{}），结构化事实保留在 \
                     `MachOFile::chained_fixups.imports[].weak_import` 里",
                    weak.len(),
                    weak.len().min(5),
                    weak[..weak.len().min(5)].join("、")
                ));
            }
            let with_addend: Vec<String> = fixups
                .imports
                .iter()
                .filter_map(|item| {
                    item.addend
                        .map(|addend| format!("{} ({addend})", item.name))
                })
                .collect();
            if !with_addend.is_empty() {
                notes.push(format!(
                    "导入表里有 {} 条带 addend（imports_format {} 的第二个字段）。对象模型的 \
                     `Import` 没有 addend 字段 —— 把加数硬塞进 iat_slot 等于编造地址，\
                     所以它只保留在 `MachOFile::chained_fixups.imports[].addend` 里\
                     （前 {} 条：{}）",
                    with_addend.len(),
                    fixups.imports_format,
                    with_addend.len().min(5),
                    with_addend[..with_addend.len().min(5)].join("、")
                ));
            }
        }

        // 走链的结论由 `chained::walk_chains` 写进 notes（走过的段/页/链/指针、
        // 多少个导入拿到地址、重复绑定、以及与 LC_SEGMENT 的差额）。这里只补两种
        // "没有走到"的情形各自的说明 —— 不让界面看起来"地址是有的"。
        match (&fixups.chains, fixups.has_starts()) {
            (Some(_), _) => {}
            (None, true) => {
                // walk_chains 已经写明原因（例如没有 __TEXT 段、镜像基址未知）。
            }
            (None, false) => {
                notes.push(
                    "LC_DYLD_CHAINED_FIXUPS 的 starts_offset = 0：这份文件没有链描述（只有导入表\
                     与符号池），所以\"导入没有地址\"不是本片没走链，而是文件里就没有链"
                        .to_string(),
                );
            }
        }
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

    // 命令层自己的说明（重复命令等）追加到同一条 `notes` 里：解析结果只有一个
    // `notes`，分两个通道会让其中一条被界面漏掉。
    notes.extend(facts.notes);

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
        symbols,
        stab_symbols,
        function_starts,
        has_symtab: facts.symtab.is_some(),
        dyld_info: facts.dyld_info,
        export_trie,
        exports,
        imports,
        chained_fixups,
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
            LC_SYMTAB => {
                if facts.symtab.is_some() {
                    facts
                        .notes
                        .push("有多条 LC_SYMTAB：只用第一条，其余忽略".to_string());
                } else {
                    facts.symtab = Some(read_symtab(&view, endianness)?);
                }
            }
            LC_FUNCTION_STARTS => {
                if facts.function_starts.is_some() {
                    facts
                        .notes
                        .push("有多条 LC_FUNCTION_STARTS：只用第一条，其余忽略".to_string());
                } else {
                    facts.function_starts = Some(read_linkedit_data(
                        &view,
                        endianness,
                        "linkedit_data_command（LC_FUNCTION_STARTS）",
                    )?);
                }
            }
            LC_DYLD_INFO | LC_DYLD_INFO_ONLY => {
                if facts.dyld_info.is_some() {
                    facts.notes.push(format!(
                        "有多条 LC_DYLD_INFO：只用第一条，{cmd:#010x} 这条的其余字段忽略"
                    ));
                } else {
                    facts.dyld_info = Some(read_dyld_info(&view, endianness, cmd)?);
                }
            }
            LC_DYLD_EXPORTS_TRIE => {
                if facts.exports_trie.is_some() {
                    facts
                        .notes
                        .push("有多条 LC_DYLD_EXPORTS_TRIE：只用第一条，其余忽略".to_string());
                } else {
                    facts.exports_trie = Some(read_linkedit_data(
                        &view,
                        endianness,
                        "linkedit_data_command（LC_DYLD_EXPORTS_TRIE）",
                    )?);
                }
            }
            LC_DYLD_CHAINED_FIXUPS => {
                if facts.chained_fixups.is_some() {
                    facts
                        .notes
                        .push("有多条 LC_DYLD_CHAINED_FIXUPS：只用第一条，其余忽略".to_string());
                } else {
                    facts.chained_fixups = Some(read_linkedit_data(
                        &view,
                        endianness,
                        "linkedit_data_command（LC_DYLD_CHAINED_FIXUPS）",
                    )?);
                }
            }
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

/// 读 `LC_SYMTAB`（`struct symtab_command`）。
///
/// 字段偏移出自 `mach-o/loader.h`：`cmd +0` / `cmdsize +4` / `symoff +8` /
/// `nsyms +0xC` / `stroff +0x10` / `strsize +0x14`，共 24 字节。
/// 这里只读字段；范围校验与条目解析在 [`parse_symbols`]（那里才拿得到文件长度）。
fn read_symtab(view: &Reader<'_>, endianness: Endianness) -> Result<SymtabCommand, ParseError> {
    if view.len() < SYMTAB_COMMAND_SIZE {
        return Err(ParseError::Truncated {
            what: "LC_SYMTAB",
            needed: SYMTAB_COMMAND_SIZE,
            actual: view.len(),
        });
    }
    Ok(SymtabCommand {
        symoff: u64::from(view.u32(8, endianness, "LC_SYMTAB.symoff")?),
        nsyms: u64::from(view.u32(12, endianness, "LC_SYMTAB.nsyms")?),
        stroff: u64::from(view.u32(16, endianness, "LC_SYMTAB.stroff")?),
        strsize: u64::from(view.u32(20, endianness, "LC_SYMTAB.strsize")?),
    })
}

/// 读 `linkedit_data_command`（`LC_FUNCTION_STARTS` / `LC_DYLD_EXPORTS_TRIE` /
/// `LC_DYLD_CHAINED_FIXUPS`）：`dataoff +8` / `datasize +0xC`。
fn read_linkedit_data(
    view: &Reader<'_>,
    endianness: Endianness,
    what: &'static str,
) -> Result<LinkeditData, ParseError> {
    if view.len() < LINKEDIT_DATA_COMMAND_SIZE {
        return Err(ParseError::Truncated {
            what,
            needed: LINKEDIT_DATA_COMMAND_SIZE,
            actual: view.len(),
        });
    }
    Ok(LinkeditData {
        dataoff: u64::from(view.u32(8, endianness, "linkedit_data_command.dataoff")?),
        datasize: u64::from(view.u32(12, endianness, "linkedit_data_command.datasize")?),
    })
}

/// 读 `dyld_info_command` 的十个 `uint32` 字段（共 48 字节）。
///
/// 字段偏移出自 `mach-o/loader.h`（见 [`DyldInfo`] 的文档）。这里只读字段，
/// 真正解释 `bind_off` / `export_off` 指向的数据在 [`bind::parse`] /
/// [`export_trie::parse`] 里（那里才拿得到文件长度与段表）。
fn read_dyld_info(
    view: &Reader<'_>,
    endianness: Endianness,
    command: u32,
) -> Result<DyldInfo, ParseError> {
    /// `sizeof(struct dyld_info_command)`：cmd + cmdsize + 10 个 `uint32`。
    const DYLD_INFO_COMMAND_SIZE: u64 = 48;
    if view.len() < DYLD_INFO_COMMAND_SIZE {
        return Err(ParseError::Truncated {
            what: "dyld_info_command（LC_DYLD_INFO*）",
            needed: DYLD_INFO_COMMAND_SIZE,
            actual: view.len(),
        });
    }
    Ok(DyldInfo {
        command,
        rebase_off: u64::from(view.u32(8, endianness, "dyld_info.rebase_off")?),
        rebase_size: u64::from(view.u32(12, endianness, "dyld_info.rebase_size")?),
        bind_off: u64::from(view.u32(16, endianness, "dyld_info.bind_off")?),
        bind_size: u64::from(view.u32(20, endianness, "dyld_info.bind_size")?),
        weak_bind_off: u64::from(view.u32(24, endianness, "dyld_info.weak_bind_off")?),
        weak_bind_size: u64::from(view.u32(28, endianness, "dyld_info.weak_bind_size")?),
        lazy_bind_off: u64::from(view.u32(32, endianness, "dyld_info.lazy_bind_off")?),
        lazy_bind_size: u64::from(view.u32(36, endianness, "dyld_info.lazy_bind_size")?),
        export_off: u64::from(view.u32(40, endianness, "dyld_info.export_off")?),
        export_size: u64::from(view.u32(44, endianness, "dyld_info.export_size")?),
    })
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

// ── 符号表（LC_SYMTAB）与函数起点（LC_FUNCTION_STARTS） ────────────────────

/// 节的显示名（`段名,节名`）：节名只在段内唯一，所以身份是这一**对**。
///
/// 对象模型的 [`Object::sections`] 与符号的 `section` 都用它 —— 两处各拼一遍
/// 迟早会分叉（一处 trim 了、一处没有），而分叉的后果是"符号指向一个不存在的节"。
fn section_display_name(section: &MachOSection) -> String {
    if section.segname.is_empty() {
        section.sectname.clone()
    } else {
        format!("{},{}", section.segname, section.sectname)
    }
}

/// 把 `n_sect` 映射到节（`nlist.h`：`n_sect` 是**跨所有段的 1 基**节号）。
fn section_by_index(segments: &[MachOSegment], n_sect: u8) -> Option<&MachOSection> {
    if n_sect == 0 {
        // `NO_SECT`：未定义/绝对符号都是这个值，不是"第 0 节"。
        return None;
    }
    segments
        .iter()
        .flat_map(|segment| segment.sections.iter())
        .nth(usize::from(n_sect) - 1)
}

/// 解析 `LC_SYMTAB` 指向的符号表。
///
/// # 拒绝什么，说明什么
///
/// 三条范围必须同时成立，任何一条不成立都返回 `ParseError`（不"尽量读"）：
///
/// 1. `symoff + nsyms × entsize <= 文件长度`（条表不越过 EOF）；
/// 2. `stroff + strsize <= 文件长度`（字符串表不越过 EOF）；
/// 3. 每条的 `n_strx < strsize`，且该名字在字符串表内有 NUL 终止符。
///
/// 能继续、但会**少给数据**的情形（条目数超上限）写进 `notes` 并写明丢了多少条 ——
/// 那正好是"截断说明 + 停止解析"里可以精确陈述的那一类。
fn parse_symbols(
    reader: &Reader<'_>,
    command: SymtabCommand,
    header: &MachHeader,
    segments: &[MachOSegment],
    notes: &mut Vec<String>,
) -> Result<Vec<MachOSymbol>, ParseError> {
    let is_64 = header.is_64;
    let endianness = header.endianness;
    let entry_size = if is_64 { NLIST64_SIZE } else { NLIST32_SIZE };

    // `nsyms = 0` 是合法且常见的情形（`ld -S` 之后又加了别的链接edit 数据）。
    // 这不是错误，但也**不是**"解析失败"：符号表里就是没有条目。
    if command.nsyms == 0 {
        notes.push(
            "存在 LC_SYMTAB，但 nsyms = 0：符号表里没有条目（Object.symbols 为空是文件里\
             写着的事实，不是没解析）"
                .to_string(),
        );
        return Ok(Vec::new());
    }

    // ── 表格范围：先整体校验，再逐项读 ──────────────────────────────────
    let table_size = command.nsyms.checked_mul(entry_size).ok_or_else(|| {
        ParseError::Overflow(format!(
            "LC_SYMTAB：nsyms({}) × 表项大小({entry_size})",
            command.nsyms
        ))
    })?;
    let table_end = command.symoff.checked_add(table_size).ok_or_else(|| {
        ParseError::Overflow(format!("LC_SYMTAB：symoff({:#x}) + 表大小", command.symoff))
    })?;
    if table_end > reader.len() {
        return Err(ParseError::Inconsistent(format!(
            "LC_SYMTAB 的符号表范围 {:#x}..{table_end:#x}（symoff + {} 条 × {entry_size} 字节）\
             超出文件大小 {:#x}：文件被裁剪或头字段被人为改过",
            command.symoff,
            command.nsyms,
            reader.len()
        )));
    }
    let str_end = command.stroff.checked_add(command.strsize).ok_or_else(|| {
        ParseError::Overflow(format!(
            "LC_SYMTAB：stroff({:#x}) + strsize({:#x})",
            command.stroff, command.strsize
        ))
    })?;
    if str_end > reader.len() {
        return Err(ParseError::Inconsistent(format!(
            "LC_SYMTAB 的字符串表范围 {:#x}..{str_end:#x}（stroff + strsize）超出文件大小 {:#x}",
            command.stroff,
            reader.len()
        )));
    }
    let strtab = reader.slice(command.stroff, command.strsize, "符号名字符串表")?;

    // ── 条目上限：挡住"文件很大且符号表填满"的放大输入 ─────────────────
    let mut count = command.nsyms;
    if count > MAX_SYMBOLS {
        notes.push(format!(
            "LC_SYMTAB 声称有 {count} 条符号，超过上限 {MAX_SYMBOLS}：只解析前 {MAX_SYMBOLS} 条，\
             其余 {} 条已丢弃（文件可能被构造）",
            count - MAX_SYMBOLS
        ));
        count = MAX_SYMBOLS;
    }

    let mut out = Vec::new();
    out.try_reserve(count.min(65_536) as usize)
        .map_err(|_| ParseError::Overflow(format!("无法为 {count} 条符号预留内存")))?;

    let mut nameless = 0u64;
    let mut bad_sect = 0u64;
    let mut cursor = command.symoff;
    for index in 0..count {
        // 整表范围上面已经校验过，所以逐项读只用 `cursor + 字段偏移`。
        // `nlist` 与 `nlist_64` 的字段偏移相同，只有 `n_value` 的宽度不同
        // （`mach-o/nlist.h`）：n_strx +0、n_type +4、n_sect +5、n_desc +6、n_value +8。
        let n_strx = u64::from(reader.u32(cursor, endianness, "n_strx")?);
        let n_type = reader.u8(cursor + 4, "n_type")?;
        let n_sect = reader.u8(cursor + 5, "n_sect")?;
        let n_desc = reader.u16(cursor + 6, endianness, "n_desc")?;
        let value = if is_64 {
            reader.u64(cursor + 8, endianness, "n_value")?
        } else {
            u64::from(reader.u32(cursor + 8, endianness, "n_value")?)
        };

        if n_strx >= command.strsize {
            // 名字偏移必须落在字符串表内 —— 越界就拒绝，不读表外的字节，
            // 也不退回空名字（那会把"坏文件"伪装成"无名符号"）。
            return Err(ParseError::Inconsistent(format!(
                "第 {index} 条符号的 n_strx = {n_strx:#x} 超出字符串表大小 {:#x}",
                command.strsize
            )));
        }
        let name = if n_strx == 0 {
            // 规范：`n_strx == 0` 表示**没有名字**（不是"名字在偏移 0"）。
            nameless += 1;
            String::new()
        } else {
            read_symbol_name(strtab, n_strx, index)?
        };

        let section = section_by_index(segments, n_sect);
        let section_name = section.map(section_display_name);
        if n_sect != 0 && section.is_none() {
            bad_sect += 1;
        }
        let is_function = section.is_some_and(|section| is_executable_section(section.flags));

        out.push(MachOSymbol {
            name,
            value,
            n_type,
            n_sect,
            n_desc,
            section: section_name,
            is_function,
        });

        cursor = cursor
            .checked_add(entry_size)
            .ok_or_else(|| ParseError::Overflow("符号表项偏移".to_string()))?;
    }

    if nameless > 0 {
        notes.push(format!(
            "有 {nameless} 条符号的 n_strx = 0（规范里表示\"没有名字\"）：它们按无名字保留，\
             没有编造名字"
        ));
    }
    if bad_sect > 0 {
        notes.push(format!(
            "有 {bad_sect} 条符号的 n_sect 指向不存在的节：它们的 section 留空（不猜）"
        ));
    }
    Ok(out)
}

/// 从字符串表读一个名字，要求它在表内有 NUL 终止符。
///
/// 不用 [`Reader::cstr`]：那个函数在找不到 NUL 时会**返回整段**（对 `segname`
/// 这种定长字段是对的），而字符串表里没有 NUL 终止符意味着文件坏了 ——
/// 静默接受会给出一个被截断的名字，比报错更误导。
fn read_symbol_name(strtab: &[u8], n_strx: u64, index: u64) -> Result<String, ParseError> {
    let start = usize::try_from(n_strx)
        .map_err(|_| ParseError::Overflow(format!("第 {index} 条符号的 n_strx = {n_strx:#x}")))?;
    let Some(tail) = strtab.get(start..) else {
        return Err(ParseError::Inconsistent(format!(
            "第 {index} 条符号的 n_strx = {n_strx:#x} 超出字符串表大小 {:#x}",
            strtab.len()
        )));
    };
    let Some(end) = tail.iter().position(|&byte| byte == 0) else {
        return Err(ParseError::Inconsistent(format!(
            "第 {index} 条符号的名字（n_strx = {n_strx:#x}）在字符串表末尾之前没有 NUL \
             终止符：字符串表被裁剪或 n_strx 指向了表中间"
        )));
    };
    Ok(String::from_utf8_lossy(&tail[..end]).into_owned())
}

/// ULEB128 解一个值的结局。
enum Uleb {
    /// 解出的值与占用的字节数。
    Value(u64, usize),
    /// 数据在这一个值的中间就结束了（payload 被裁剪）。
    Truncated,
    /// 编码超过 `u64` 能表示的范围（payload 被构造）。
    Overflow,
}

/// 从 `bytes[start..]` 解一个 ULEB128。
///
/// 编码（`mach-o/loader.h` 对 `LC_FUNCTION_STARTS` 的说明 + `dyld` 的
/// `uleb128` 编码约定）：每个字节低 7 位是有效位、最高位表示"还有下一个字节"，
/// 字节按**小端**顺序排列。`u64` 最多占 10 字节。
fn uleb128_at(bytes: &[u8], start: usize) -> Uleb {
    let mut value: u64 = 0;
    let mut shift: u32 = 0;
    for (offset, &byte) in bytes[start..].iter().enumerate() {
        let low = u64::from(byte & 0x7f);
        let shifted = low << shift;
        // 左移把有效位挤出去的检查：挤出去就不是一个合法的 u64 编码。
        if shifted >> shift != low {
            return Uleb::Overflow;
        }
        value |= shifted;
        if byte & 0x80 == 0 {
            return Uleb::Value(value, offset + 1);
        }
        shift += 7;
        if shift >= 64 {
            return Uleb::Overflow;
        }
    }
    Uleb::Truncated
}

/// 解析 `LC_FUNCTION_STARTS`：ULEB128 增量序列 → 绝对虚拟地址（升序）。
///
/// 编码方式（`mach-o/loader.h` 里 `LC_FUNCTION_STARTS` 的说明，实现见 dyld）：
/// **第一个值是相对镜像基址（`__TEXT.vmaddr`）的增量**，其后每个值是相对**上一个
/// 函数起点**的增量，遇到 `0` 字节列表结束（补齐用的 0 也在这里被吃掉）。
///
/// 三件事按 §7 处理：
///
/// * 数据范围越过 EOF ⇒ `ParseError`（文件被裁剪，不能读表外字节）；
/// * 没有镜像基址 ⇒ 空表 + 说明（delta 无从还原成地址，不猜）；
/// * payload 没遇到终止符（或最后一个 ULEB128 被截断）⇒ 已解出多少就是多少，
///   但**必须**在 `notes` 里说是被截断的，不许静默返回短表。
fn decode_function_starts(
    reader: &Reader<'_>,
    range: LinkeditData,
    image_base: Option<u64>,
    notes: &mut Vec<String>,
) -> Result<Vec<u64>, ParseError> {
    let end = range.dataoff.checked_add(range.datasize).ok_or_else(|| {
        ParseError::Overflow(format!(
            "LC_FUNCTION_STARTS：dataoff({:#x}) + datasize({:#x})",
            range.dataoff, range.datasize
        ))
    })?;
    if end > reader.len() {
        return Err(ParseError::Inconsistent(format!(
            "LC_FUNCTION_STARTS 的数据范围 {:#x}..{end:#x} 超出文件大小 {:#x}：\
             文件被裁剪或头字段被人为改过",
            range.dataoff,
            reader.len()
        )));
    }
    if range.datasize == 0 {
        notes.push(
            "有 LC_FUNCTION_STARTS，但 datasize = 0：表是空的（函数边界没有权威来源）".to_string(),
        );
        return Ok(Vec::new());
    }
    let Some(base) = image_base else {
        notes.push(
            "有 LC_FUNCTION_STARTS，但没有 __TEXT 段、镜像基址未知：第一个增量相对基址，\
             基址都没有就无从还原成地址 —— 函数起点留空（不猜）"
                .to_string(),
        );
        return Ok(Vec::new());
    };

    let payload = reader.slice(range.dataoff, range.datasize, "LC_FUNCTION_STARTS 的数据")?;
    let mut out = Vec::new();
    let mut cursor = 0usize;
    let mut current = base;
    let mut terminated = false;
    let mut overflow = false;

    while cursor < payload.len() {
        match uleb128_at(payload, cursor) {
            Uleb::Value(0, used) => {
                cursor += used;
                terminated = true;
                break;
            }
            Uleb::Value(delta, used) => {
                cursor += used;
                current = current.checked_add(delta).ok_or_else(|| {
                    ParseError::Overflow(format!(
                        "LC_FUNCTION_STARTS：{current:#x} + 增量 {delta:#x}"
                    ))
                })?;
                out.push(current);
                if out.len() as u64 >= MAX_FUNCTION_STARTS {
                    notes.push(format!(
                        "LC_FUNCTION_STARTS 超过上限 {MAX_FUNCTION_STARTS} 条：只保留前 \
                         {MAX_FUNCTION_STARTS} 条，payload 里还有 {} 字节未解",
                        payload.len() - cursor
                    ));
                    return Ok(out);
                }
            }
            Uleb::Truncated => break,
            Uleb::Overflow => {
                overflow = true;
                break;
            }
        }
    }

    if overflow {
        return Err(ParseError::Inconsistent(format!(
            "LC_FUNCTION_STARTS 在 payload 偏移 +{cursor:#x} 处的 ULEB128 超出 64 位：\
             payload 被人为构造过"
        )));
    }
    if !terminated {
        notes.push(format!(
            "LC_FUNCTION_STARTS 的 payload（{} 字节）在结尾之前没有遇到 0 终止符：已解出 {} \
             个函数起点，表**可能被截断**（文件被裁剪，或 dataoff/datasize 写错）",
            payload.len(),
            out.len()
        ));
    } else if payload[cursor..].iter().any(|&byte| byte != 0) {
        // 真实文件里终止符之后是补齐到 4/8 字节的 0；出现非零字节说明这段数据里
        // 还有别的东西（或者是别人改的），按规范在 0 处停止，但要说出来。
        notes.push(format!(
            "LC_FUNCTION_STARTS 的终止符之后还有 {} 字节非零数据：按规范在 0 处停止解析",
            payload.len() - cursor
        ));
    }
    Ok(out)
}

// ── 导出 trie 与 dyld 绑定（导入表） ────────────────────────────────────────

/// 决定导出 trie 从哪来，并把它解出来。
///
/// 两种来处都要认：`LC_DYLD_EXPORTS_TRIE`（iOS 13+ 的独立命令）与
/// `LC_DYLD_INFO(_ONLY).export_off`。两者同时存在时用前者并说明 —— 新版工具链
/// 只写后者时也照解，不因为"命令形式"不同就把导出集丢掉。
///
/// 这里只做**范围校验**与"基址有没有"两件事，trie 内部的结构问题交给
/// [`export_trie::parse`]（它是纯函数，能单测）。
fn decode_exports(
    reader: &Reader<'_>,
    facts: &CommandFacts,
    image_base: Option<u64>,
    notes: &mut Vec<String>,
) -> Result<(Option<ExportTrieSource>, Vec<MachOExport>), ParseError> {
    let source = if let Some(range) = facts.exports_trie {
        if facts.dyld_info.is_some() {
            notes.push(
                "同时存在 LC_DYLD_EXPORTS_TRIE 与 LC_DYLD_INFO：导出 trie 取前者\
                 （新版工具链的形式），后者只用来解绑定流"
                    .to_string(),
            );
        }
        ExportTrieSource {
            command: LC_DYLD_EXPORTS_TRIE,
            dataoff: range.dataoff,
            datasize: range.datasize,
        }
    } else if let Some(info) = facts.dyld_info {
        ExportTrieSource {
            command: info.command,
            dataoff: info.export_off,
            datasize: info.export_size,
        }
    } else {
        return Ok((None, Vec::new()));
    };

    if source.datasize == 0 {
        notes.push(format!(
            "导出 trie 的范围是空的（{:#010x} 的 export_off/export_size 为 0）：\
             Object.exports 为空 —— 命令在、表没内容，不是没解析",
            source.command
        ));
        return Ok((Some(source), Vec::new()));
    }

    let end = source.dataoff.checked_add(source.datasize).ok_or_else(|| {
        ParseError::Overflow(format!(
            "导出 trie：dataoff {:#x} + datasize {:#x}",
            source.dataoff, source.datasize
        ))
    })?;
    if end > reader.len() {
        return Err(ParseError::Inconsistent(format!(
            "导出 trie 的范围 {:#x}..{end:#x}（dataoff + datasize）超出文件大小 {:#x}：\
             文件被裁剪或头字段被人为改过",
            source.dataoff,
            reader.len()
        )));
    }

    // 地址是"基址 + 偏移"。没有 __TEXT 就没有基址 —— 那时**不**拿偏移冒充地址。
    let Some(base) = image_base else {
        notes.push(
            "有导出 trie，但没有 __TEXT 段、镜像基址未知：trie 里的地址是相对基址的偏移，\
             基址都没有就无从还原成地址 —— Object.exports 留空（不猜）"
                .to_string(),
        );
        return Ok((Some(source), Vec::new()));
    };

    let payload = reader.slice(source.dataoff, source.datasize, "导出 trie")?;
    let exports = export_trie::parse(payload, base, &facts.dylibs)?;
    Ok((Some(source), exports))
}

/// 把 `bind` 与 `lazy_bind` 两条流解成导入表。
///
/// 没有 `LC_DYLD_INFO` 就是"这个文件不是这种写法"（新版是链式修复），返回空表；
/// 原因由调用方写进 `notes`（它才知道 `LC_DYLD_CHAINED_FIXUPS` 在不在）。
fn decode_imports(
    reader: &Reader<'_>,
    facts: &CommandFacts,
    header: &MachHeader,
    notes: &mut Vec<String>,
) -> Result<Vec<BindImport>, ParseError> {
    let Some(info) = facts.dyld_info else {
        return Ok(Vec::new());
    };
    // 槽位宽度由**文件位宽**决定（不是架构）：32 位 Mach-O 的指针就是 4 字节。
    let pointer_size = if header.is_64 { 8 } else { 4 };

    let mut out = Vec::new();
    if info.bind_size > 0 {
        out.extend(read_bind_stream(
            reader,
            (info.bind_off, info.bind_size),
            &facts.segments,
            &facts.dylibs,
            pointer_size,
            BindKind::Regular,
            notes,
        )?);
    }
    if info.lazy_bind_size > 0 {
        out.extend(read_bind_stream(
            reader,
            (info.lazy_bind_off, info.lazy_bind_size),
            &facts.segments,
            &facts.dylibs,
            pointer_size,
            BindKind::Lazy,
            notes,
        )?);
    }
    Ok(out)
}

/// 切一条绑定流并解它（范围校验在这里做，操作码解码在 [`bind::parse`]）。
///
/// `range` 是 `(dataoff, datasize)` —— 两个值总是一起用，所以合成一个参数
/// （函数参数已经够多了，`clippy::too_many_arguments` 是对的）。
fn read_bind_stream(
    reader: &Reader<'_>,
    range: (u64, u64),
    segments: &[MachOSegment],
    dylibs: &[String],
    pointer_size: u64,
    kind: BindKind,
    notes: &mut Vec<String>,
) -> Result<Vec<BindImport>, ParseError> {
    let (dataoff, datasize) = range;
    let end = dataoff
        .checked_add(datasize)
        .ok_or_else(|| ParseError::Overflow(format!("{}：dataoff + datasize", kind.as_str())))?;
    if end > reader.len() {
        return Err(ParseError::Inconsistent(format!(
            "{} 流的范围 {:#x}..{end:#x}（dataoff + datasize）超出文件大小 {:#x}：\
             文件被裁剪或头字段被人为改过",
            kind.as_str(),
            dataoff,
            reader.len()
        )));
    }
    let payload = reader.slice(dataoff, datasize, "dyld 绑定流")?;
    bind::parse(payload, segments, dylibs, pointer_size, kind, notes)
}

/// 切 `LC_DYLD_CHAINED_FIXUPS` 的 payload，解它的**导入表**，再沿指针链走一遍。
///
/// 返回 `None` 表示文件里没有这条命令（不是"有这条命令但 0 条导入"—— 那种情形
/// 是 `Some` + 空 `imports`，`notes` 里说得不一样）。范围校验在这里做（与
/// [`read_bind_stream`] 同一套），编码细节在 [`chained::parse`]（导入表）与
/// [`chained::walk_chains`]（指针链）。
///
/// 走链要**整份文件**的字节：指针链本身在各个段的数据里（`__DATA` 等），不在
/// `LC_DYLD_CHAINED_FIXUPS` 的 payload 里 —— payload 只描述"哪些段、哪些页、
/// 页里哪个偏移有链"。
fn decode_chained_fixups(
    reader: &Reader<'_>,
    facts: &CommandFacts,
    image_base: Option<u64>,
    notes: &mut Vec<String>,
) -> Result<Option<ChainedFixups>, ParseError> {
    let Some(range) = facts.chained_fixups else {
        return Ok(None);
    };
    let end = range.dataoff.checked_add(range.datasize).ok_or_else(|| {
        ParseError::Overflow("LC_DYLD_CHAINED_FIXUPS：dataoff + datasize".to_string())
    })?;
    if end > reader.len() {
        return Err(ParseError::Inconsistent(format!(
            "LC_DYLD_CHAINED_FIXUPS 的范围 {:#x}..{end:#x}（dataoff + datasize）超出文件大小 \
             {:#x}：文件被裁剪或头字段被人为改过",
            range.dataoff,
            reader.len()
        )));
    }
    if range.datasize == 0 {
        // `datasize = 0` 是"这条命令没写数据"：没有头可解，如实记 None 之外的一件事
        // —— 由 notes 说明，而不是把空 payload 当成一张空导入表。
        notes.push(
            "有 LC_DYLD_CHAINED_FIXUPS，但 dataoff/datasize 指向 0 字节：没有链式修复数据可解\
             （Object.imports 因此拿不到任何导入，这是文件里的事实）"
                .to_string(),
        );
        return Ok(None);
    }
    let payload = reader.slice(range.dataoff, range.datasize, "LC_DYLD_CHAINED_FIXUPS")?;
    let mut fixups = chained::parse(payload, &facts.dylibs)?;
    // 导入表没有地址：地址在指针链里，走一遍才填得上。
    if fixups.has_starts() {
        let walked = chained::walk_chains(
            payload,
            reader.as_bytes(),
            &facts.segments,
            image_base,
            fixups.starts_offset,
            &mut fixups.imports,
            notes,
        )?;
        fixups.chains = walked;
    }
    Ok(Some(fixups))
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

/// 地址是否落在**可执行节**里。
///
/// 导出 trie 只写"这个名字在哪个地址"，**没有**"这是函数还是数据"的字段
/// （`EXPORT_SYMBOL_FLAGS_KIND_MASK` 分的是 regular / thread_local / absolute，
/// 不是 code / data）。所以 `Export::is_code` 是**推出来的**：落在带指令标志的节里
/// 才算代码。落不进任何节就是 `false`（未知不当成代码）。
fn address_is_code(segments: &[MachOSegment], address: u64) -> bool {
    segments
        .iter()
        .flat_map(|segment| segment.sections.iter())
        .any(|section| {
            address >= section.addr
                && address - section.addr < section.size
                && is_executable_section(section.flags)
        })
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

    // 普通符号（去掉 stab）：`is_stripped` 与 `Object.symbols` 用的是**同一个**
    // 判据 —— 此前的 `!has_symtab` 会把"有 LC_SYMTAB 但 nsyms = 0"的文件说成
    // "没有剥离"，而它一个可引用的符号都没有（CLAUDE.md §7）。
    let ordinary: Vec<&MachOSymbol> = file
        .symbols
        .iter()
        .filter(|symbol| !symbol.is_stab())
        .collect();

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
        is_stripped: ordinary.is_empty(),
        declared_size: None,
    };
    object.header_flags = Some(file.flags);
    object.image_base = file.image_base.unwrap_or(0);
    object.entry = file.entry.map(|entry| entry.vaddr);
    // 函数起点是**分析层要的地址**（函数边界），不是给人看的字符串，因此直接
    // 进对象模型。非 Mach-O 格式留空表（"没有这样一张表"）。
    object.function_starts = file.function_starts.clone();
    // `LC_UUID` 与依赖库现在有结构化字段了（M12 第二片）。它们**不再**塞进
    // `notes` 让消费方去解析字符串：那是把结构丢给字符串，而 `notes` 是
    // 给人读的降级说明，不是数据通道。
    object.uuid = file.uuid.clone();
    object.dylibs = file.dylibs.clone();

    for symbol in ordinary {
        // `bind` 沿用 PE/COFF 那条先例（`format::pe::inspect`）：只映射
        // "局部 / 全局 / 弱"这一层最小交集，不硬套 ELF 的编号语义。
        // Mach-O 的"外部"位是 `n_type & N_EXT`，弱符号看 `n_desc`。
        let bind: u8 = if symbol.is_weak() {
            2 // STB_WEAK
        } else if symbol.is_external() {
            1 // STB_GLOBAL
        } else {
            0 // STB_LOCAL
        };
        object.symbols.push(RawSymbol {
            name: symbol.name.clone(),
            value: symbol.value,
            // nlist 没有大小字段：0 = 未知（不是"零字节"）。
            size: 0,
            defined: !symbol.is_undefined(),
            is_function: symbol.is_function,
            is_weak: symbol.is_weak(),
            bind,
            section: symbol.section.clone(),
            source: SymbolTableSource::Static,
        });
    }

    // 导出 trie → `Object.exports`。
    //
    // `address` 是**基址 + 偏移**（trie 里存的是相对镜像基址的偏移）。re-export 的
    // terminal 里没有地址字段，那时记 0 并把转发目标写进 `forwarder` —— 0 在这里是
    // "文件里没有这个字段"的如实表达，`forwarder` 是它真正说明"去哪找"的地方。
    for export in &file.exports {
        let is_code = export
            .address
            .is_some_and(|address| address_is_code(&file.segments, address));
        let forwarder = match (&export.reexport_library, &export.reexport_name) {
            (Some(library), Some(original)) => {
                // 规范允许 original 为空串（= 与导出名同名）；空串就直接写导出名，
                // 但 `#` 右边空着会让人以为是解析失败，所以这里补上实际名字。
                let target = if original.is_empty() {
                    export.name.as_str()
                } else {
                    original.as_str()
                };
                Some(format!("{library}#{target}"))
            }
            _ => None,
        };
        object.exports.push(Export {
            name: export.name.clone(),
            // Mach-O 的导出 trie 里**没有**"导出序号"这个概念（那是 PE 的）。
            ordinal: None,
            address: export.address.unwrap_or(0),
            forwarder,
            is_code,
        });
    }

    // dyld 绑定 → `Object.imports`。
    //
    // `iat_slot` 就是被写入的指针槽地址（分析层做交叉引用要的就是它）；
    // `module` 是解析后的库名；`ordinal` 留空 —— 那个字段在 `Import` 里是
    // "按序号导入的符号序号"（PE 的序号导入），不是库序号，两者不能混。
    for import in &file.imports {
        object.imports.push(Import {
            module: import.dylib.clone(),
            name: Some(import.name.clone()),
            ordinal: None,
            iat_slot: Some(import.address),
            thunk: None,
        });
    }

    // 链式修复的**导入表** → `Object.imports`（新版 Xcode 产物的导入只在这里）。
    //
    // `iat_slot` 来自走链（`chained::walk_chains` 按 bind 指针里的 ordinal 下标填）：
    // 没被链绑定到的导入保持 None（未知），绝不填 0（CLAUDE.md §7）。
    if let Some(fixups) = &file.chained_fixups {
        for import in &fixups.imports {
            object.imports.push(Import {
                module: import.dylib.clone(),
                name: Some(import.name.clone()),
                ordinal: None,
                iat_slot: import.iat_slot,
                thunk: None,
            });
        }
    }

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
            // （`__TEXT,__const` 与 `__DATA,__const` 都真实存在）。命名与符号的
            // `section` 共用 `section_display_name`，两处各拼一遍迟早分叉。
            let name = section_display_name(section);

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
