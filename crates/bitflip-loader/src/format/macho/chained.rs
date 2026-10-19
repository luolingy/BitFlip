//! `LC_DYLD_CHAINED_FIXUPS`：**导入表**（`imports` 段 + 符号池）与**指针链**
//! （`starts_offset` 指向的 `dyld_chained_starts_in_image`）。
//!
//! # 为什么要有它
//!
//! iOS 13 之后 Xcode 不再写 `LC_DYLD_INFO` 的 bind / lazy_bind 流，绑定改写成
//! "链式修复"（chained fixups）：`LC_DYLD_CHAINED_FIXUPS`（`0x8000_0034`，一个
//! `linkedit_data_command`，`dataoff` / `datasize` 指向 `__LINKEDIT` 里的
//! `dyld_chained_fixups_header` + 若干段数据）。实测 `temp/` 下四份 IPA 里三份
//! （`LiveContainer` / `SideStore` / `Stapxs`）都是这种新格式 —— 在那个文件里
//! "导入了什么"只存在于这张表的 `imports` 段与符号池里，`LC_DYLD_INFO` 整条不存在。
//!
//! 导入表回答"导入了什么"；"写进哪个指针槽"要沿 `starts_offset` 描述的指针链走、
//! 按 `pointer_format` 还原每个指针。本文件两件事都做：
//!
//! * [`parse`] 解**导入表**（名字 / 库 / weak / 加数）；
//! * [`walk_chains`] 走**指针链**，把每条导入被写入的槽位地址填进
//!   [`ChainedImport::iat_slot`]。
//!
//! 地址是"这个函数调用了 `_objc_msgSend`"变成一条真实的边的前提：只知道导入了
//! 什么、不知道写在哪，交叉引用就接不上。
//!
//! # 编码（出处：Apple XNU `EXTERNAL_HEADERS/mach-o/fixup-chains.h`）
//!
//! 规范里的头结构（小端；本文件按这个顺序读，偏移写在注释里）：
//!
//! ```text
//! struct dyld_chained_fixups_header {      // 28 字节
//!     uint32_t fixups_version;             // +0x00  （目前只定义 0）
//!     uint32_t starts_offset;              // +0x04  dyld_chained_starts_in_image 的偏移
//!     uint32_t imports_offset;             // +0x08  导入表的偏移（相对 payload 起点）
//!     uint32_t symbols_offset;             // +0x0C  符号池的偏移（相对 payload 起点）
//!     uint32_t imports_count;              // +0x10  导入表条目数
//!     uint32_t imports_format;             // +0x14  导入表条目的编码（见下）
//!     uint32_t symbols_format;             // +0x18  符号池的编码（0 = 未压缩）
//! };
//! ```
//!
//! `imports_format` 的三种取值与条目布局（位域按 Little-endian 的 LSB-first 顺序
//! 说明，也就是规范里 `uint32_t lib_ordinal : 8` 这类声明的实际比特位置）：
//!
//! ```text
//! #define DYLD_CHAINED_IMPORT          1
//! struct dyld_chained_import {             // 4 字节
//!     uint32_t lib_ordinal : 8,            // bits  0..8
//!              weak_import : 1,            // bit   8
//!              name_offset : 23;           // bits  9..32（相对符号池的偏移）
//! };
//!
//! #define DYLD_CHAINED_IMPORT_ADDEND   2
//! struct dyld_chained_import_addend {      // 8 字节
//!     uint32_t lib_ordinal : 8, weak_import : 1, name_offset : 23;
//!     int32_t  addend;                     // +4
//! };
//!
//! #define DYLD_CHAINED_IMPORT_ADDEND64 3
//! struct dyld_chained_import_addend64 {    // 16 字节
//!     uint64_t lib_ordinal : 16,           // bits  0..16
//!              weak_import : 1,            // bit   16
//!              reserved    : 15,           // bits 17..32（规范要求它是 0）
//!              name_offset : 32;           // bits 32..64
//!     uint64_t addend;                     // +8（有符号加数，按二补码读）
//! };
//! ```
//!
//! 符号池（`symbols_offset` 起）在 `symbols_format == 0` 时是一串 NUL 结尾的
//! C 字符串，`name_offset` 是**相对池起点**的偏移；`symbols_format == 1` 表示
//! zlib 压缩（本文件不解，见下）。
//!
//! 全部字段按**小端**读。链式修复只出现在 64 位的 Apple 平台（arm64 / x86_64），
//! 那里没有大端 Mach-O；dyld 也是按宿主原生端序直接读这块数据的。
//!
//! # 指针链（`starts_offset`）
//!
//! 这三段结构同样出自 `mach-o/fixup-chains.h`（小端；偏移写在注释里）：
//!
//! ```text
//! struct dyld_chained_starts_in_image {      // 4 + 4×seg_count 字节起
//!     uint32_t seg_count;                    // +0x00
//!     uint32_t seg_info_offset[seg_count];   // +0x04 每项相对**本结构**起点；0 = 该段没有链
//! };
//!
//! struct dyld_chained_starts_in_segment {    // 22 字节头 + 数组
//!     uint32_t size;                          // +0x00 整段字节数（含后面的数组）
//!     uint16_t page_size;                     // +0x04 0x1000 / 0x4000
//!     uint16_t pointer_format;                // +0x06 DYLD_CHAINED_PTR_*（见下）
//!     uint64_t segment_offset;                // +0x08 段相对**镜像基址**的内存偏移
//!     uint32_t max_valid_pointer;             // +0x10 只有 32 位格式用
//!     uint16_t page_count;                    // +0x14
//!     uint16_t page_start[page_count];        // +0x16（第一项；紧跟 chain_starts[]）
//! };
//! ```
//!
//! `+0x08` 那个位置是因为 `uint64_t` 的自然对齐：`size`(4) + `page_size`(2) +
//! `pointer_format`(2) 正好 8 字节，`segment_offset` 从 8 开始，`max_valid_pointer`
//! 在 16、`page_count` 在 20、`page_start` 在 22。**`segment_offset` 是内存偏移，
//! 不是文件偏移** —— dyld 里它被加到"镜像的 preferred load address"上：
//!
//! ```text
//! 槽位地址 = 镜像基址 + segment_offset + page_index × page_size + 页内偏移
//! ```
//!
//! 正常文件里 `镜像基址 + segment_offset` 恰好等于该段 `LC_SEGMENT_64.vmaddr`；
//! 两者不等时本文件在 `notes` 里报出差额（不悄悄用其中一个顶替另一个）。
//!
//! `page_start[i]` 的三种取值（`fixup-chains.h` 的 `DYLD_CHAINED_PTR_START_*`）：
//!
//! ```text
//! DYLD_CHAINED_PTR_START_NONE  = 0xFFFF  // 这一页没有修复
//! DYLD_CHAINED_PTR_START_MULTI = 0x8000  // 置位 = 多起点页：低 15 位是**下标**，指向
//!                                        //   整个 u16 数组（从 page_start[0] 起算，
//!                                        //   也就是 dyld 的 page_start[index]）里的
//!                                        //   一项；列表逐项给出页内起始偏移，最后
//! DYLD_CHAINED_PTR_START_LAST  = 0x8000  //   一项再置这一位，表示列表结束
//! 其余                                    // 页内第一个指针的偏移
//! ```
//!
//! 关于多起点下标从哪算：`fixup-chains.h` 在结构里把 `page_start[]` 之后那段注释成
//! `chain_starts[]`，并说置位时"it is index into chain_starts[]"，字面读像是相对
//! `chain_starts[]` 起算；但 dyld 自己走链时读的是 `page_start[overflowIndex]`
//! （整个数组的绝对下标），本文件按 dyld 的读法实现。为了不把两种读法混成"猜一下"，
//! 下标落进 `page_start[0..page_count]` 自己的区域时**直接报错**并说明这个歧义，
//! 而不是按另一种读法悄悄再走一遍（§7：宁可报错，不许编地址）。
//!
//! `pointer_format` 的取值与每个 `next` 的 stride（同一段头文件的 enum 注释，
//! 原文就是 "stride N"）：
//!
//! ```text
//! DYLD_CHAINED_PTR_ARM64E              = 1   stride 8，未认证 target 是 vmaddr
//! DYLD_CHAINED_PTR_64                  = 2   stride 4，target 是 vmaddr
//! DYLD_CHAINED_PTR_32                  = 3   32 位（本片不解，见"没做"）
//! DYLD_CHAINED_PTR_32_CACHE            = 4   32 位（本片不解）
//! DYLD_CHAINED_PTR_32_FIRMWARE         = 5   32 位（本片不解）
//! DYLD_CHAINED_PTR_64_OFFSET           = 6   stride 4，target 是 vm 偏移
//! DYLD_CHAINED_PTR_ARM64E_OFFSET       = 7   旧名
//! DYLD_CHAINED_PTR_ARM64E_KERNEL       = 7   stride 4，未认证 target 是 vm 偏移
//! DYLD_CHAINED_PTR_64_KERNEL_CACHE     = 8   stride 4，**没有 bind 位**
//! DYLD_CHAINED_PTR_ARM64E_USERLAND     = 9   stride 8，未认证 target 是 vm 偏移
//! DYLD_CHAINED_PTR_ARM64E_FIRMWARE     = 10  stride 4
//! DYLD_CHAINED_PTR_X86_64_KERNEL_CACHE = 11  stride 1（本片不解）
//! DYLD_CHAINED_PTR_ARM64E_USERLAND24   = 12  stride 8，bind 的 ordinal 是 24 位
//! DYLD_CHAINED_PTR_ARM64E_SHARED_CACHE = 13  stride 8（dyld 共享缓存，本片不解）
//! ```
//!
//! 指针字的位域（同样是 LSB-first；一个指针字 8 字节，小端）：
//!
//! ```text
//! // arm64e 家族：格式 1 / 7 / 9 / 10 / 12（next 11 位，bind 在 bit 62，auth 在 bit 63）
//! struct dyld_chained_ptr_arm64e_rebase    { target:43, high8:8, next:11, bind:1, auth:1 };
//! struct dyld_chained_ptr_arm64e_bind      { ordinal:16, zero:16, addend:19, next:11, bind:1, auth:1 };
//! struct dyld_chained_ptr_arm64e_auth_bind { ordinal:16, zero:16, diversity:16, addrDiv:1,
//!                                            key:2, next:11, bind:1, auth:1 };
//! // USERLAND24（格式 12）只是把 ordinal 放宽到 24 位、zero 收到 8 位，其余不变：
//! struct dyld_chained_ptr_arm64e_bind24    { ordinal:24, zero:8, addend:19, next:11, bind:1, auth:1 };
//!
//! //   位：ordinal 0..16（12 是 0..24）、addend 32..51（**19 位二补码**）、
//! //       next 51..62（11 位）、bind 62、auth 63
//! //   认证绑定（auth == 1）没有 addend：32..51 那 19 位是 diversity/addrDiv/key
//!
//! // 64 位家族：格式 2 / 6（next 12 位，bind 在 bit 63）
//! struct dyld_chained_ptr_64_rebase { target:36, high8:8, reserved:7, next:12, bind:1 };
//! struct dyld_chained_ptr_64_bind   { ordinal:24, addend:8, reserved:19, next:12, bind:1 };
//! //   位：ordinal 0..24、addend 24..32（8 位，0..255，**无符号**）、next 51..63、bind 63
//!
//! // 64 位内核缓存：格式 8（同样 12 位 next，但 bit 63 是 isAuth 而不是 bind）
//! struct dyld_chained_ptr_64_kernel_cache_rebase { target:30, cacheLevel:2, diversity:16,
//!                                                  addrDiv:1, key:2, next:12, isAuth:1 };
//! ```
//!
//! `next` 的语义是**下一个指针相对当前指针的偏移，单位是 stride**（dyld 的
//! `offset += next * stride`）；`next == 0` 表示链到此结束。链**不跨页**：dyld 逐页
//! 走链，下一个偏移冲出页尾就是坏文件（本文件同样判错，不硬走下去）。
//!
//! 多起点页的 `chain_starts[]` 里每一项只给"页内起始偏移"，高位置位表示列表结束 ——
//! `page_start` 与 `chain_starts` **是同一个数组**：`page_start[0..page_count]` 是每页的
//! 入口，`page_start[page_count..]`（结构里注释成 `chain_starts[]`）是多起点列表的池子。
//! `size` 字段决定这个数组总共有多少项，本文件按 `size` 定界；下标按 dyld 的绝对读法
//! （`page_start[index]`），落进 `page_count` 以内则报错（见上面关于歧义的那一段）。
//!
//! # 库序号（`lib_ordinal`）
//!
//! 正数是 `LC_LOAD_DYLIB` 列表的 **1 基**序号（与 bind 流同一套编号）。位域的
//! 宽度只有 8 / 16 位，所以"负数"要靠二补码表达：`0xFF`（8 位）/ `0xFFFF`（16 位）
//! 就是 -1 = **主可执行文件**，`0xFE` / `0xFFFE` 是 -2 = **flat lookup**，
//! `0xFD` / `0xFFFD` 是 -3 = weak lookup —— 这正是 dyld bind 流里
//! `BIND_SPECIAL_DYLIB_*` 的那几个值（见 [`super::bind`]）。本文件把它们翻成
//! 带尖括号的可读标签，而不是把裸位域值透传出去让上层猜。
//! 0、以及不在上面那套特殊值里的负数，一律是**错误**（文件被构造或位域读错），
//! 越界的正数同样报错 —— 绝不把 `0xFF` 当成第 255 个库去索引。
//!
//! # 本文件**没做**什么（这一条必须跟着结论一起说）
//!
//! * **32 位的链格式没有解**（`DYLD_CHAINED_PTR_32` / `_32_CACHE` / `_32_FIRMWARE`，
//!   值 3 / 4 / 5）：它们的指针字是 4 字节、位域完全不同。iOS 13 之后链式修复只出现
//!   在 64 位上，所以现实里走不到；但**不猜**，遇到就返回 `ParseError::NotSupported`。
//!   同样没解的是 x86_64 内核缓存（11）与 dyld 共享缓存（13）。
//! * **没有解 rebase 的目标**：链里同时混着本镜像内部的 rebase 指针（`bind == 0`），
//!   它们不是导入，本文件只计数（[`ChainWalk::rebases`]），不产出地址。
//! * **没有解 zlib 压缩的符号池**（`symbols_format == 1`）：返回明确的"暂不支持"，
//!   而不是拿压缩字节当名字。
//! * 没有解 `fixups_version != 0` 的头（目前规范只定义 0）。
//! * **bind 只能按 ordinal 精确匹配，不能用名字。** 指针字里只有"导入表第几条"
//!   （`ordinal`），没有名字；名字在导入表里。所以本文件把 `ordinal` 当导入表的
//!   下标用，越界即 `ParseError` —— 不存在"按名字猜一条"的路。
//! * **没有把 weak / addend 写进对象模型**：`Import` 没有这两个字段，它们留在
//!   [`ChainedImport`] 里，条数与样例写进 `notes`（不硬塞进 `iat_slot` 编造地址）。
//!
//! # 恶性输入
//!
//! 每个偏移 / 长度都先与 payload 或文件长度比对（`checked_add` + `checked_mul`）。
//! 导入表条目数有上限 [`MAX_CHAINED_IMPORTS`]，符号名必须在池内有 NUL 终止符且不超过
//! [`MAX_SYMBOL_NAME_LEN`] 字节；走链有段数上限 [`MAX_CHAINED_SEGMENTS`]、总指针数上限
//! [`MAX_CHAINED_POINTERS`]，而且每个 `next` 增量必须让页内偏移**严格递增**（否则永远
//! 到不了 `next == 0`，就是一条环）并留在本页内 —— 所以"链不终止"在这里是**立即**的
//! `ParseError`，不是挂死。任何一条不成立都是 `ParseError` —— 不 panic、不挂死、
//! 也不"尽量读"给出一张错表。

use std::fmt::Write as _;

use super::MachOSegment;
use crate::reader::ParseError;

/// `sizeof(struct dyld_chained_fixups_header)`：七个 `uint32`。
pub const DYLD_CHAINED_FIXUPS_HEADER_SIZE: usize = 28;

/// `dyld_chained_starts_in_segment` 里 `page_start[]` 之前的固定头：22 字节。
///
/// `size`(+0x00, 4) + `page_size`(+0x04, 2) + `pointer_format`(+0x06, 2) +
/// `segment_offset`(+0x08, 8) + `max_valid_pointer`(+0x10, 4) +
/// `page_count`(+0x14, 2) = 22，`page_start[0]` 在 +0x16。
pub const DYLD_CHAINED_STARTS_IN_SEGMENT_HEADER_SIZE: usize = 22;

/// `DYLD_CHAINED_PTR_START_NONE`：`page_start[i]` 的这个值表示该页没有修复。
pub const DYLD_CHAINED_PTR_START_NONE: u16 = 0xFFFF;
/// `DYLD_CHAINED_PTR_START_MULTI`：`page_start[i]` 的这个位表示多起点页
/// （低 15 位是整个 u16 数组的下标，dyld 读作 `page_start[index]`）。
pub const DYLD_CHAINED_PTR_START_MULTI: u16 = 0x8000;
/// `DYLD_CHAINED_PTR_START_LAST`：`chain_starts[]` 的池子里这一位置位表示列表结束
/// （与 [`DYLD_CHAINED_PTR_START_MULTI`] 是同一个位，语义按所在位置区分）。
pub const DYLD_CHAINED_PTR_START_LAST: u16 = 0x8000;

/// `DYLD_CHAINED_PTR_ARM64E`：stride 8，未认证 target 是 vmaddr。
pub const DYLD_CHAINED_PTR_ARM64E: u16 = 1;
/// `DYLD_CHAINED_PTR_64`：stride 4，target 是 vmaddr。
pub const DYLD_CHAINED_PTR_64: u16 = 2;
/// `DYLD_CHAINED_PTR_32`：32 位（本文件不解）。
pub const DYLD_CHAINED_PTR_32: u16 = 3;
/// `DYLD_CHAINED_PTR_32_CACHE`：32 位（本文件不解）。
pub const DYLD_CHAINED_PTR_32_CACHE: u16 = 4;
/// `DYLD_CHAINED_PTR_32_FIRMWARE`：32 位（本文件不解）。
pub const DYLD_CHAINED_PTR_32_FIRMWARE: u16 = 5;
/// `DYLD_CHAINED_PTR_64_OFFSET`：stride 4，target 是 vm 偏移。
pub const DYLD_CHAINED_PTR_64_OFFSET: u16 = 6;
/// `DYLD_CHAINED_PTR_ARM64E_OFFSET`（旧名）/ `DYLD_CHAINED_PTR_ARM64E_KERNEL`：
/// stride 4，未认证 target 是 vm 偏移。两个名字在规范里是**同一个值**。
pub const DYLD_CHAINED_PTR_ARM64E_OFFSET: u16 = 7;
/// `DYLD_CHAINED_PTR_ARM64E_KERNEL`：见 [`DYLD_CHAINED_PTR_ARM64E_OFFSET`]。
pub const DYLD_CHAINED_PTR_ARM64E_KERNEL: u16 = 7;
/// `DYLD_CHAINED_PTR_64_KERNEL_CACHE`：stride 4，**没有 bind 位**（bit 63 是 isAuth）。
pub const DYLD_CHAINED_PTR_64_KERNEL_CACHE: u16 = 8;
/// `DYLD_CHAINED_PTR_ARM64E_USERLAND`：stride 8，未认证 target 是 vm 偏移。
pub const DYLD_CHAINED_PTR_ARM64E_USERLAND: u16 = 9;
/// `DYLD_CHAINED_PTR_ARM64E_FIRMWARE`：stride 4。
pub const DYLD_CHAINED_PTR_ARM64E_FIRMWARE: u16 = 10;
/// `DYLD_CHAINED_PTR_X86_64_KERNEL_CACHE`：stride 1（本文件不解）。
pub const DYLD_CHAINED_PTR_X86_64_KERNEL_CACHE: u16 = 11;
/// `DYLD_CHAINED_PTR_ARM64E_USERLAND24`：stride 8，bind 的 ordinal 是 24 位。
pub const DYLD_CHAINED_PTR_ARM64E_USERLAND24: u16 = 12;
/// `DYLD_CHAINED_PTR_ARM64E_SHARED_CACHE`：dyld 共享缓存的格式（本文件不解）。
pub const DYLD_CHAINED_PTR_ARM64E_SHARED_CACHE: u16 = 13;

/// `DYLD_CHAINED_IMPORT`：`u32` 位域，4 字节。
pub const DYLD_CHAINED_IMPORT: u32 = 1;
/// `DYLD_CHAINED_IMPORT_ADDEND`：`u32` 位域 + `int32_t`，8 字节。
pub const DYLD_CHAINED_IMPORT_ADDEND: u32 = 2;
/// `DYLD_CHAINED_IMPORT_ADDEND64`：`u64` 位域 + `uint64_t`，16 字节。
pub const DYLD_CHAINED_IMPORT_ADDEND64: u32 = 3;

/// `DYLD_CHAINED_SYMBOLS_UNCOMPRESSED`：符号池是未压缩的 NUL 结尾字符串。
pub const SYMBOLS_FORMAT_UNCOMPRESSED: u32 = 0;
/// `DYLD_CHAINED_SYMBOLS_ZLIB`：符号池是 zlib 压缩的（本文件不解）。
pub const SYMBOLS_FORMAT_ZLIB: u32 = 1;

/// 导入表条目数的上限。
///
/// 量级与 [`super::bind::MAX_BIND_SITES`] 一致：真实 App 的导入条数是几百到几千，
/// 一条条目要分配一个 `String`，不设上限就是拿不可信输入换内存。
pub const MAX_CHAINED_IMPORTS: u64 = 500_000;

/// 单个符号名的最大字节数（与导出 trie 的 `MAX_NAME_LEN` 同一阈值）。
pub const MAX_SYMBOL_NAME_LEN: usize = 4096;

/// 预分配导入表容量时的上限。
///
/// 表本身的条数上限是 [`MAX_CHAINED_IMPORTS`]，但那是"拒绝"的阈值：一份 2 MB 的
/// 文件可以合法声明 50 万条 4 字节条目，按 `ChainedImport` 的宽度预分配会是几十 MB
/// 的放大。所以先只备这么多个位置，超出的按需增长。
const MAX_PREALLOCATED_IMPORTS: usize = 4096;

/// 一条从链式修复导入表里解出来的导入。
///
/// 导入表本身**不含地址**；[`Self::iat_slot`] 是[`walk_chains`] 沿指针链走出来的。
/// 没有走链、或这条导入在链里没有被绑定（例如从未被引用的 weak 导入）时它是
/// `None`（未知），不是 `0`（CLAUDE.md §7）。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ChainedImport {
    /// 符号名（来自符号池，已去掉 NUL）。
    pub name: String,
    /// 解析后的库名（`LC_LOAD_DYLIB` 的顺序）或尖括号标签
    /// （`<main-executable>` / `<flat-lookup>` / `<weak-lookup>`）。
    pub dylib: String,
    /// 原始位域值（8 位或 16 位；**没有**做符号扩展 —— 取证用）。
    pub lib_ordinal: u32,
    /// `weak_import` 位（bit 8 / bit 16）。
    pub weak_import: bool,
    /// 加数：只有 `imports_format` 2 / 3 才在文件里有这个字段，
    /// 否则是 `None`（"文件里没写"，不是 0）。
    pub addend: Option<i64>,
    /// 符号池内的名字偏移（原始值）。
    pub name_offset: u32,
    /// 这条导入被绑定到的**第一个**指针槽地址（= 镜像基址 + `segment_offset` +
    /// 页偏移 + 页内偏移）。`None` = 链里没有出现这条导入的 bind 指针。
    ///
    /// 一条导入可以被绑在多个地址（多个指针指向同一个符号）：这里保留**第一个**
    /// （按段/页/偏移的遍历顺序），其余次数记在 [`ChainWalk::extra_bind_sites`]
    /// 并写进 `notes` —— 不悄悄丢掉。
    pub iat_slot: Option<u64>,
}

/// 走一遍指针链之后的计数（进 `notes`，也是"到底走没走、走到多少"的证据）。
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ChainWalk {
    /// 有链描述（`seg_info_offset != 0`）的段数。
    pub segments: usize,
    /// 真正走到的页数（`page_start` 不是 `0xFFFF` 且列表能终止的页）。
    pub pages: usize,
    /// 链的条数（多起点页里一页可能有多条）。
    pub chains: usize,
    /// 读到的指针总数。
    pub pointers: usize,
    /// 其中是 bind（导入绑定）的条数。
    pub binds: usize,
    /// 其中是 rebase（镜像内部指针）的条数。
    pub rebases: usize,
    /// 其中是 arm64e **认证**绑定的条数（没有 addend 字段，见 [`ChainedImport::addend`]）。
    pub auth_binds: usize,
    /// 其中 bind 的加数**非零**的条数。
    ///
    /// 加数在指针字里（`imports_format` 1 的导入表没有这个字段）；它不改变槽位地址，
    /// 所以只计数 —— 但"有多少条导入带了加数"是真实事实，不该悄悄丢。
    pub bind_addends: usize,
    /// 拿到槽位地址的导入条数（= `imports[].iat_slot.is_some()` 的数量）。
    pub imports_with_slot: usize,
    /// 同一条导入被绑在**多个**地址时，除第一处之外的次数。
    pub extra_bind_sites: usize,
    /// 那些额外绑定的样例（`ordinal`, 地址），最多 [`MAX_DUPLICATE_SAMPLES`] 个。
    pub duplicate_samples: Vec<(u32, u64)>,
}

/// 一份 `LC_DYLD_CHAINED_FIXUPS` 解析的完整结果。
///
/// 头字段原样保留：它们是"这份文件用的是哪种编码"的证据，`notes` 里报的
/// `imports_format` / `symbols_format` 就是从这里来的。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ChainedFixups {
    /// `fixups_version`（规范只定义 0）。
    pub fixups_version: u32,
    /// `starts_offset`：指针链描述的偏移（0 = 没有链描述）。
    ///
    /// 指向的数据由 [`walk_chains`] 走，结论在 [`Self::chains`] 里。
    pub starts_offset: u32,
    /// `imports_offset`。
    pub imports_offset: u32,
    /// `symbols_offset`。
    pub symbols_offset: u32,
    /// `imports_count`（头里声明的条数；与 `imports.len()` 相等）。
    pub imports_count: u32,
    /// `imports_format`（1 / 2 / 3）。
    pub imports_format: u32,
    /// `symbols_format`（0 = 未压缩；1 会直接被拒绝）。
    pub symbols_format: u32,
    /// 解出来的导入（按表里的顺序）。
    ///
    /// 空表明确对应"文件里写着 `imports_count = 0`"，不是"没解析"。
    pub imports: Vec<ChainedImport>,
    /// 走链的结果。`None` = 没有链描述（`starts_offset == 0`）、或链没法走
    /// （原因在 `notes` 里，例如没有 `__TEXT` 段因而不知道镜像基址）。
    pub chains: Option<ChainWalk>,
}

impl ChainedFixups {
    /// 文件里有没有链描述（`starts_offset != 0`）。
    #[must_use]
    pub const fn has_starts(&self) -> bool {
        self.starts_offset != 0
    }

    /// `imports_format` 的稳定短名（进 `notes` 与错误信息）。
    #[must_use]
    pub const fn imports_format_name(&self) -> &'static str {
        match self.imports_format {
            DYLD_CHAINED_IMPORT => "DYLD_CHAINED_IMPORT",
            DYLD_CHAINED_IMPORT_ADDEND => "DYLD_CHAINED_IMPORT_ADDEND",
            DYLD_CHAINED_IMPORT_ADDEND64 => "DYLD_CHAINED_IMPORT_ADDEND64",
            _ => "未知",
        }
    }
}

/// 解一段 `LC_DYLD_CHAINED_FIXUPS` 的 payload。
///
/// `payload` 是 `dataoff` / `datasize` 圈出来的字节（调用方已校验过它落在文件内），
/// `dylibs` 是 `LC_LOAD_DYLIB` / `LC_LOAD_WEAK_DYLIB` 的库名表（按加载命令顺序），
/// 用来把 `lib_ordinal` 解析成库名。
///
/// # Errors
///
/// * 头不足 28 字节、导入表 / 符号池越过 payload —— `ParseError::Truncated` 或
///   `ParseError::Inconsistent`；
/// * `fixups_version != 0`、`imports_format` 不认识、`lib_ordinal` 越界或落在
///   未知的负值上、`name_offset` 指向池外、名字没有 NUL 终止符或不是合法 UTF-8、
///   `imports_count` 超过 [`MAX_CHAINED_IMPORTS`] —— `ParseError::Inconsistent`
///   （库序号 / 名字那几类是"文件自相矛盾"）；
/// * `symbols_format == 1`（zlib）—— `ParseError::NotSupported`：这是**没实现**的
///   能力，不是文件坏了，所以变体分开（CLAUDE.md §7）。
pub fn parse(payload: &[u8], dylibs: &[String]) -> Result<ChainedFixups, ParseError> {
    if payload.len() < DYLD_CHAINED_FIXUPS_HEADER_SIZE {
        return Err(ParseError::Truncated {
            what: "dyld_chained_fixups_header",
            needed: DYLD_CHAINED_FIXUPS_HEADER_SIZE as u64,
            actual: payload.len() as u64,
        });
    }

    // 字段偏移见模块文档：+0x00 … +0x18，七个 u32。
    let fixups_version = read_u32(payload, 0x00, "dyld_chained_fixups_header.fixups_version")?;
    let starts_offset = read_u32(payload, 0x04, "dyld_chained_fixups_header.starts_offset")?;
    let imports_offset = read_u32(payload, 0x08, "dyld_chained_fixups_header.imports_offset")?;
    let symbols_offset = read_u32(payload, 0x0C, "dyld_chained_fixups_header.symbols_offset")?;
    let imports_count = read_u32(payload, 0x10, "dyld_chained_fixups_header.imports_count")?;
    let imports_format = read_u32(payload, 0x14, "dyld_chained_fixups_header.imports_format")?;
    let symbols_format = read_u32(payload, 0x18, "dyld_chained_fixups_header.symbols_format")?;

    // dyld 只认 0（C++ 那边是一条 assert）。将来的版本可能在这七个字段之后追加，
    // 那时按旧布局读会读错 —— 所以这里明确报错，不猜。
    if fixups_version != 0 {
        return Err(ParseError::Inconsistent(format!(
            "dyld_chained_fixups_header.fixups_version = {fixups_version}：规范只定义了 0，\
             本片不认其他版本（按旧布局硬读会读错字段）"
        )));
    }

    let entry_size = match imports_format {
        DYLD_CHAINED_IMPORT => 4usize,
        DYLD_CHAINED_IMPORT_ADDEND => 8,
        DYLD_CHAINED_IMPORT_ADDEND64 => 16,
        other => {
            return Err(ParseError::Inconsistent(format!(
                "dyld_chained_fixups_header.imports_format = {other}：规范只定义了 \
                 {DYLD_CHAINED_IMPORT} / {DYLD_CHAINED_IMPORT_ADDEND} / \
                 {DYLD_CHAINED_IMPORT_ADDEND64}，本片不猜其他编码（猜错会给出一整张错表）"
            )));
        }
    };

    match symbols_format {
        SYMBOLS_FORMAT_UNCOMPRESSED => {}
        SYMBOLS_FORMAT_ZLIB => {
            return Err(ParseError::NotSupported {
                what: "LC_DYLD_CHAINED_FIXUPS 的符号池",
                detail: format!(
                    "symbols_format = {SYMBOLS_FORMAT_ZLIB}（zlib 压缩）：解压不是本片的能力，\
                     拿压缩字节当名字只会给出垃圾。等实现解压后这条会变成真实结果"
                ),
            });
        }
        other => {
            return Err(ParseError::Inconsistent(format!(
                "dyld_chained_fixups_header.symbols_format = {other}：规范只定义了 \
                 {SYMBOLS_FORMAT_UNCOMPRESSED}（未压缩）与 {SYMBOLS_FORMAT_ZLIB}（zlib）"
            )));
        }
    }

    // 条目数上限：先挡放大输入，再做范围乘法。
    let count = u64::from(imports_count);
    if count > MAX_CHAINED_IMPORTS {
        return Err(ParseError::Inconsistent(format!(
            "dyld_chained_fixups_header.imports_count = {imports_count} 超过上限 \
             {MAX_CHAINED_IMPORTS}：文件可能被构造（一条条目要分配一个 String）"
        )));
    }

    // starts_offset 描述指针链，本文件不解，但它必须落在 payload 里：
    // 越界说明头字段自相矛盾（真去走链时第一件事就会越界）。
    if starts_offset != 0 {
        let offset = usize::try_from(starts_offset).map_err(|_| {
            ParseError::Inconsistent(format!(
                "dyld_chained_fixups_header.starts_offset = {starts_offset:#x} 超出 usize"
            ))
        })?;
        if offset >= payload.len() {
            return Err(ParseError::Inconsistent(format!(
                "dyld_chained_fixups_header.starts_offset = {starts_offset:#x} 超出 payload \
                 {:#x} 字节：头字段自相矛盾",
                payload.len()
            )));
        }
    }

    // 符号池的起点也必须落在 payload 内（名字从它开始按偏移取）。
    let pool_start = usize::try_from(symbols_offset).map_err(|_| {
        ParseError::Inconsistent(format!(
            "dyld_chained_fixups_header.symbols_offset = {symbols_offset:#x} 超出 usize"
        ))
    })?;
    if count > 0 && pool_start >= payload.len() {
        return Err(ParseError::Inconsistent(format!(
            "dyld_chained_fixups_header.symbols_offset = {symbols_offset:#x} 超出 payload \
             {:#x} 字节：导入表里的名字无从取起",
            payload.len()
        )));
    }
    let pool = payload.get(pool_start..).unwrap_or(&[]);

    // 导入表整段的结束偏移。`imports_count × entry_size` 先做 u64 乘法，再转 usize。
    let table_bytes = count.checked_mul(entry_size as u64).ok_or_else(|| {
        ParseError::Overflow("链式修复导入表：imports_count × 条目宽度".to_string())
    })?;
    let table_start = usize::try_from(imports_offset).map_err(|_| {
        ParseError::Inconsistent(format!(
            "dyld_chained_fixups_header.imports_offset = {imports_offset:#x} 超出 usize"
        ))
    })?;
    let table_end_u64 = u64::try_from(table_start)
        .ok()
        .and_then(|start| start.checked_add(table_bytes))
        .ok_or_else(|| {
            ParseError::Overflow(format!(
                "链式修复导入表：imports_offset {imports_offset:#x} + {table_bytes} 字节"
            ))
        })?;
    if count > 0 && table_end_u64 > payload.len() as u64 {
        return Err(ParseError::Inconsistent(format!(
            "链式修复导入表声明 {imports_count} 条（每条 {entry_size} 字节）从 \
             {imports_offset:#x} 开始，结束偏移 {table_end_u64:#x} 超出 payload {:#x} 字节：\
             表被裁剪或头字段被人为改过",
            payload.len()
        )));
    }

    let mut imports: Vec<ChainedImport> = Vec::with_capacity(
        usize::try_from(count)
            .unwrap_or(0)
            .min(MAX_PREALLOCATED_IMPORTS),
    );
    for index in 0..count {
        let offset_in_table = usize::try_from(index)
            .ok()
            .and_then(|index| index.checked_mul(entry_size))
            .ok_or_else(|| ParseError::Overflow("链式修复导入表条目偏移".to_string()))?;
        let base = table_start
            .checked_add(offset_in_table)
            .ok_or_else(|| ParseError::Overflow("链式修复导入表条目偏移".to_string()))?;
        let (lib_bits, weak_import, name_offset, addend) = match imports_format {
            DYLD_CHAINED_IMPORT => {
                let word = read_u32(payload, base, "dyld_chained_import")?;
                // LSB-first：lib_ordinal 在 0..8，weak 在 bit 8，name_offset 在 9..32。
                (word & 0xFF, word & (1 << 8) != 0, word >> 9, None)
            }
            DYLD_CHAINED_IMPORT_ADDEND => {
                let word = read_u32(payload, base, "dyld_chained_import_addend")?;
                let addend = read_u32(payload, base + 4, "dyld_chained_import_addend.addend")?;
                (
                    word & 0xFF,
                    word & (1 << 8) != 0,
                    word >> 9,
                    // 规范里是 int32_t：按二补码解释。
                    Some(i64::from(addend as i32)),
                )
            }
            DYLD_CHAINED_IMPORT_ADDEND64 => {
                let low = read_u64(payload, base, "dyld_chained_import_addend64")?;
                let raw_addend =
                    read_u64(payload, base + 8, "dyld_chained_import_addend64.addend")?;
                (
                    // lib_ordinal 16 位、weak 在 bit 16、name_offset 在 bits 32..64。
                    (low & 0xFFFF) as u32,
                    low & (1 << 16) != 0,
                    (low >> 32) as u32,
                    // 规范里是 uint64_t，但加数是二补码语义：按位保留。
                    Some(raw_addend as i64),
                )
            }
            other => {
                // 上面已经挡过，这里只是让 match 穷尽；保留一条明确的错误而不是 unreachable。
                return Err(ParseError::Inconsistent(format!(
                    "链式修复导入表的 imports_format = {other} 在条目循环里没有对应布局"
                )));
            }
        };

        let ordinal_width = if imports_format == DYLD_CHAINED_IMPORT_ADDEND64 {
            16
        } else {
            8
        };
        let dylib = resolve_ordinal(lib_bits, ordinal_width, dylibs, index as u32)?;
        let name = read_symbol_name(pool, name_offset, index as u32)?;

        imports.push(ChainedImport {
            name,
            dylib,
            lib_ordinal: lib_bits,
            weak_import,
            addend,
            name_offset,
            // 导入表本身没有地址：由 [`walk_chains`] 填（没走链就是 None）。
            iat_slot: None,
        });
    }

    Ok(ChainedFixups {
        fixups_version,
        starts_offset,
        imports_offset,
        symbols_offset,
        imports_count,
        imports_format,
        symbols_format,
        imports,
        // 走链是另一件事（要整份文件的字节与段表），由调用方用 [`walk_chains`] 填。
        chains: None,
    })
}

// ── 指针链（dyld_chained_starts_in_image） ─────────────────────────────────

/// 一份链描述里最多认多少个段（`seg_count`）。
///
/// Mach-O 的段数是个位到几十；这个上限只用来挡住"声明 40 亿个段"的放大输入。
pub const MAX_CHAINED_SEGMENTS: u32 = 65_535;

/// 一份文件最多走多少个指针。
///
/// 真实 App 的绑定槽位是几万个（SideStore 19.6 MB）；4M 是"远大于真实值、又远小于
/// 让不可信输入把 CPU 花光"的量级。超过即 `ParseError` —— 截断会让"走了多少"
/// 变成一个说不清的数字。
pub const MAX_CHAINED_POINTERS: u64 = 4_000_000;

/// 同一条导入被绑定多次时，`notes` 里最多留几个样例（总次数另外统计）。
pub const MAX_DUPLICATE_SAMPLES: usize = 8;

/// 本文件支持的链格式的指针字宽度（32 位格式在 [`pointer_layout`] 里被拒绝）。
const CHAINED_POINTER_WORD_BYTES: u64 = 8;

/// 一种 `pointer_format` 的位布局（出处见模块文档"指针链"一节的 `dyld_chained_ptr_*`）。
#[derive(Debug, Clone, Copy)]
struct PointerLayout {
    /// `next` 位域的起始位（LSB-first）。
    next_shift: u32,
    /// `next` 位域的宽度。
    next_bits: u32,
    /// 一个 `next` 单位等于多少字节（规范 enum 注释里的 stride）。
    stride: u64,
    /// `bind` 位；`None` = 这种格式没有 bind 位（内核缓存）。
    bind_bit: Option<u32>,
    /// `auth` 位（只有 arm64e 家族有）。
    auth_bit: Option<u32>,
    /// bind 里 `ordinal` 的位宽。
    ordinal_bits: u32,
    /// bind 里 `addend` 的起始位。
    addend_shift: u32,
    /// bind 里 `addend` 的位宽；`None` = 认证绑定没有 addend 字段。
    addend_bits: Option<u32>,
}

impl PointerLayout {
    /// arm64e 家族（格式 1 / 7 / 9 / 10 / 12）：`ordinal` 在 bits 0..16（格式 12 是
    /// 0..24）、`addend` 在 bits 32..51（**19 位二补码**）、`next` 在 bits 51..62（11 位）、
    /// `bind` 在 bit 62、`auth` 在 bit 63。
    const fn arm64e(stride: u64, ordinal_bits: u32) -> Self {
        Self {
            next_shift: 51,
            next_bits: 11,
            stride,
            bind_bit: Some(62),
            auth_bit: Some(63),
            ordinal_bits,
            addend_shift: 32,
            addend_bits: Some(19),
        }
    }

    /// 64 位家族（格式 2 / 6）：`ordinal` 在 bits 0..24、`addend` 在 bits 24..32
    /// （8 位**无符号**）、`next` 在 bits 51..63（12 位）、`bind` 在 bit 63（没有 auth）。
    const fn ptr64() -> Self {
        Self {
            next_shift: 51,
            next_bits: 12,
            stride: 4,
            bind_bit: Some(63),
            auth_bit: None,
            ordinal_bits: 24,
            addend_shift: 24,
            addend_bits: Some(8),
        }
    }
}

/// `pointer_format` → 位布局；不支持的格式返回 [`ParseError::NotSupported`]。
///
/// **不猜**：32 位格式（3 / 4 / 5）、x86_64 内核缓存（11）、dyld 共享缓存（13）的
/// 指针字布局与 64 位完全不同，硬按 64 位读会给出"看起来对"的错地址。
fn pointer_layout(format: u16) -> Result<PointerLayout, ParseError> {
    match format {
        DYLD_CHAINED_PTR_ARM64E => Ok(PointerLayout::arm64e(8, 16)),
        DYLD_CHAINED_PTR_ARM64E_USERLAND => Ok(PointerLayout::arm64e(8, 16)),
        DYLD_CHAINED_PTR_ARM64E_USERLAND24 => Ok(PointerLayout::arm64e(8, 24)),
        DYLD_CHAINED_PTR_ARM64E_FIRMWARE => Ok(PointerLayout::arm64e(4, 16)),
        DYLD_CHAINED_PTR_ARM64E_KERNEL => Ok(PointerLayout::arm64e(4, 16)),
        DYLD_CHAINED_PTR_64 | DYLD_CHAINED_PTR_64_OFFSET => Ok(PointerLayout::ptr64()),
        DYLD_CHAINED_PTR_64_KERNEL_CACHE => Ok(PointerLayout {
            next_shift: 51,
            next_bits: 12,
            stride: 4,
            // 内核缓存里没有导入：bit 63 是 isAuth，不是 bind。
            bind_bit: None,
            auth_bit: Some(63),
            ordinal_bits: 0,
            addend_shift: 0,
            addend_bits: None,
        }),
        other => Err(ParseError::NotSupported {
            what: "LC_DYLD_CHAINED_FIXUPS 的 pointer_format",
            detail: format!(
                "pointer_format = {other}，不是本片认识的 64 位链格式（已支持：\
                 ARM64E={DYLD_CHAINED_PTR_ARM64E}、64={DYLD_CHAINED_PTR_64}、\
                 64_OFFSET={DYLD_CHAINED_PTR_64_OFFSET}、\
                 ARM64E_KERNEL/ARM64E_OFFSET={DYLD_CHAINED_PTR_ARM64E_KERNEL}、\
                 64_KERNEL_CACHE={DYLD_CHAINED_PTR_64_KERNEL_CACHE}、\
                 ARM64E_USERLAND={DYLD_CHAINED_PTR_ARM64E_USERLAND}、\
                 ARM64E_FIRMWARE={DYLD_CHAINED_PTR_ARM64E_FIRMWARE}、\
                 ARM64E_USERLAND24={DYLD_CHAINED_PTR_ARM64E_USERLAND24}）。\
                 32 位格式（{DYLD_CHAINED_PTR_32} / {DYLD_CHAINED_PTR_32_CACHE} / \
                 {DYLD_CHAINED_PTR_32_FIRMWARE}）、x86_64 内核缓存（\
                 {DYLD_CHAINED_PTR_X86_64_KERNEL_CACHE}）与 dyld 共享缓存（\
                 {DYLD_CHAINED_PTR_ARM64E_SHARED_CACHE}）的指针字布局不同，按 64 位硬读\
                 只会给出错地址 —— 这里是**没实现**，不是文件坏了"
            ),
        }),
    }
}

/// `bits` 个低位全 1（`bits == 0` 时是 0）。
const fn low_mask(bits: u32) -> u64 {
    if bits >= 64 {
        u64::MAX
    } else {
        (1u64 << bits) - 1
    }
}

/// 把 `bits` 位二补码符号扩展成 `i64`。
///
/// 规范里 arm64e 的 `addend: 19` 是 `int` 语义（注释写 ±256K），64 位家族的
/// `addend: 8` 是 `uint64_t` 位域但注释写 0..255 —— 两者都按"位域里的值"读，
/// 这里只对 19 位那条做符号扩展（调用方按格式决定是否调用）。
fn sign_extend(value: u64, bits: u32) -> i64 {
    if bits == 0 || bits >= 64 {
        return value as i64;
    }
    let shift = 64 - bits;
    ((value << shift) as i64) >> shift
}

/// 一个指针字的解码结果。
struct ChainPointerWord {
    /// 是导入绑定（`bind` 位置位）还是 rebase。
    is_bind: bool,
    /// bind 的导入表下标。
    ordinal: usize,
    /// bind 的加数；认证绑定没有这个字段（`None`，不是 0）。
    addend: Option<i64>,
    /// 是否是 arm64e 认证绑定（`auth` 位置位）。
    is_auth: bool,
    /// 下一个指针相对当前指针的增量（字节）。`0` = 链结束。
    next: u64,
}

/// 按 `layout` 解一个指针字；`address` 只用于错误信息。
fn decode_pointer(
    word: u64,
    layout: PointerLayout,
    address: u64,
) -> Result<ChainPointerWord, ParseError> {
    let is_bind = layout.bind_bit.is_some_and(|bit| word & (1 << bit) != 0);
    let is_auth = layout.auth_bit.is_some_and(|bit| word & (1 << bit) != 0);
    let next = ((word >> layout.next_shift) & low_mask(layout.next_bits))
        .checked_mul(layout.stride)
        .ok_or_else(|| {
            ParseError::Overflow(format!(
                "链里的指针（槽位 {address:#x}）的 next 字段乘以 stride {} 溢出",
                layout.stride
            ))
        })?;
    if !is_bind {
        return Ok(ChainPointerWord {
            is_bind: false,
            ordinal: 0,
            addend: None,
            is_auth,
            next,
        });
    }
    let ordinal = usize::try_from(word & low_mask(layout.ordinal_bits)).unwrap_or(usize::MAX);
    // 认证绑定把那几位（32..51）当作 diversity / addrDiv / key，**没有** addend。
    let addend = match (layout.addend_bits, is_auth) {
        (Some(bits), false) => Some(sign_extend(
            (word >> layout.addend_shift) & low_mask(bits),
            bits,
        )),
        _ => None,
    };
    Ok(ChainPointerWord {
        is_bind: true,
        ordinal,
        addend,
        is_auth,
        next,
    })
}

/// 走一条指针链的累加器（把整份文件与导入表绑在一起，避免十几个参数的签名）。
struct ChainWalker<'a> {
    image: &'a [u8],
    imports: &'a mut [ChainedImport],
    walk: ChainWalk,
}

impl ChainWalker<'_> {
    /// 从 `start` 开始走**同一页内**的一条链。
    ///
    /// `within` 是 `segment_offset` 相对 `LC_SEGMENT.vmaddr` 的差（正常是 0），
    /// `page_index` 是页号。每读一个指针就校验它落在本段的内存范围、文件范围与
    /// 本页内 —— 任何一条不成立都是 `ParseError`，绝不越界读、也不无限走。
    fn run_chain(
        &mut self,
        segment: &MachOSegment,
        layout: PointerLayout,
        page_size: u64,
        within: u64,
        page_index: usize,
        start: u64,
    ) -> Result<(), ParseError> {
        let page_mem = within
            .checked_add(
                u64::try_from(page_index)
                    .ok()
                    .and_then(|page| page.checked_mul(page_size))
                    .ok_or_else(|| {
                        ParseError::Overflow(format!(
                            "段 {} 第 {page_index} 页的内存偏移",
                            segment.name
                        ))
                    })?,
            )
            .ok_or_else(|| ParseError::Overflow("指针链的页偏移".to_string()))?;
        // 同一条链的偏移必须严格递增，而下一个偏移必须还在本页内 —— 所以"永远到不了
        // next == 0"最多只能撑 page_size / stride 步；再多就是坏文件（不是慢，是不终止）。
        let max_steps = page_size / layout.stride + 1;
        let mut offset = start;
        let mut steps: u64 = 0;
        loop {
            steps += 1;
            if steps > max_steps {
                return Err(ParseError::Inconsistent(format!(
                    "段 {} 第 {page_index} 页第 {start:#x} 字节处的链走了 {steps} 步还没到 \
                     next == 0（一页最多只能放 {} 个 stride 为 {} 的指针）：链没有终点",
                    segment.name,
                    page_size / layout.stride,
                    layout.stride
                )));
            }
            if offset
                .checked_add(CHAINED_POINTER_WORD_BYTES)
                .is_none_or(|end| end > page_size)
            {
                return Err(ParseError::Inconsistent(format!(
                    "段 {} 第 {page_index} 页的链走到页内偏移 {offset:#x}，一个 {} 字节的指针\
                     会越过页尾 {page_size:#x}：链跨页了（dyld 逐页走链，不跨页）",
                    segment.name, CHAINED_POINTER_WORD_BYTES
                )));
            }
            let mem_offset = page_mem.checked_add(offset).ok_or_else(|| {
                ParseError::Overflow(format!("段 {} 的指针内存偏移", segment.name))
            })?;
            let end_mem = mem_offset
                .checked_add(CHAINED_POINTER_WORD_BYTES)
                .ok_or_else(|| {
                    ParseError::Overflow(format!("段 {} 的指针结束偏移", segment.name))
                })?;
            if segment.vmsize == 0 || end_mem > segment.vmsize {
                return Err(ParseError::Inconsistent(format!(
                    "段 {} 的指针在段内偏移 {mem_offset:#x}（页 {page_index}、页内 {offset:#x}），\
                     但段的内存大小只有 {:#x}：starts_in_segment 与 LC_SEGMENT 自相矛盾",
                    segment.name, segment.vmsize
                )));
            }
            if segment.filesize == 0 {
                return Err(ParseError::Inconsistent(format!(
                    "段 {} 在文件里没有字节（filesize = 0），却声称有指针链",
                    segment.name
                )));
            }
            let file_offset = segment.fileoff.checked_add(mem_offset).ok_or_else(|| {
                ParseError::Overflow(format!("段 {} 的指针文件偏移", segment.name))
            })?;
            let end_file = file_offset
                .checked_add(CHAINED_POINTER_WORD_BYTES)
                .ok_or_else(|| {
                    ParseError::Overflow(format!("段 {} 的指针结束文件偏移", segment.name))
                })?;
            let segment_file_end = segment
                .fileoff
                .checked_add(segment.filesize)
                .ok_or_else(|| ParseError::Overflow(format!("段 {} 的文件范围", segment.name)))?;
            if end_file > segment_file_end {
                return Err(ParseError::Inconsistent(format!(
                    "段 {} 的指针在文件偏移 {file_offset:#x}，越过段的文件范围 \
                     {:#x}..{segment_file_end:#x}：starts_in_segment 与 LC_SEGMENT 自相矛盾",
                    segment.name, segment.fileoff
                )));
            }
            let bytes = usize::try_from(file_offset)
                .ok()
                .and_then(|start| {
                    usize::try_from(end_file)
                        .ok()
                        .and_then(|end| self.image.get(start..end))
                })
                .ok_or(ParseError::Truncated {
                    what: "链式修复的指针字",
                    needed: end_file,
                    actual: self.image.len() as u64,
                })?;
            let word = u64::from_le_bytes(bytes.try_into().map_err(|_| {
                ParseError::Inconsistent(format!(
                    "读链式修复的指针字时长度与 {CHAINED_POINTER_WORD_BYTES} 不符"
                ))
            })?);

            self.walk.pointers += 1;
            if self.walk.pointers as u64 > MAX_CHAINED_POINTERS {
                return Err(ParseError::Inconsistent(format!(
                    "指针链里走过的指针超过上限 {MAX_CHAINED_POINTERS}：文件被构造过，\
                     或者链描述把整份文件当成了指针"
                )));
            }

            let address = segment
                .vmaddr
                .checked_add(mem_offset)
                .ok_or_else(|| ParseError::Overflow(format!("段 {} 的指针地址", segment.name)))?;
            let pointer = decode_pointer(word, layout, address)?;
            if pointer.is_bind {
                self.walk.binds += 1;
                if pointer.is_auth {
                    self.walk.auth_binds += 1;
                }
                // 加数在**指针字**里（`imports_format` 1 的导入表没有这个字段）；
                // bind 的槽位地址不受加数影响，所以这里只计数、不改地址。
                if pointer.addend.is_some_and(|addend| addend != 0) {
                    self.walk.bind_addends += 1;
                }
                self.record_bind(pointer.ordinal, address)?;
            } else {
                self.walk.rebases += 1;
            }

            if pointer.next == 0 {
                break;
            }
            let next_offset = offset.checked_add(pointer.next).ok_or_else(|| {
                ParseError::Overflow(format!("段 {} 的链的下一个页内偏移", segment.name))
            })?;
            if next_offset <= offset {
                // next 是无符号增量、stride > 0，正常情况下不可能发生；留着是为了
                // 让"偏移必须严格递增"这个终止条件在代码里是**显式**的。
                return Err(ParseError::Inconsistent(format!(
                    "段 {} 第 {page_index} 页的链在页内偏移 {offset:#x} 处的 next 没有让偏移递增：\
                     这会是一条环，文件被构造过",
                    segment.name
                )));
            }
            offset = next_offset;
        }
        self.walk.chains += 1;
        Ok(())
    }

    /// 记一条导入绑定：第一条地址留下，其余只计数（并留样例），不悄悄丢。
    fn record_bind(&mut self, ordinal: usize, address: u64) -> Result<(), ParseError> {
        let count = self.imports.len();
        let Some(import) = self.imports.get_mut(ordinal) else {
            return Err(ParseError::Inconsistent(format!(
                "链里的 bind 指针（槽位 {address:#x}）写着 ordinal = {ordinal}，但导入表只有 \
                 {count} 条：指针链与导入表自相矛盾（这条地址不记，也不猜是哪一条导入）"
            )));
        };
        if import.iat_slot.is_none() {
            import.iat_slot = Some(address);
            self.walk.imports_with_slot += 1;
        } else {
            self.walk.extra_bind_sites += 1;
            if self.walk.duplicate_samples.len() < MAX_DUPLICATE_SAMPLES {
                self.walk
                    .duplicate_samples
                    .push((u32::try_from(ordinal).unwrap_or(u32::MAX), address));
            }
        }
        Ok(())
    }
}

/// 走 `starts_offset` 描述的指针链，把每条导入被写入的槽位地址填进
/// [`ChainedImport::iat_slot`]，并把过程写进 `notes`。
///
/// * `payload`：`LC_DYLD_CHAINED_FIXUPS` 的字节（链描述在里面）；
/// * `image`：**整份薄 Mach-O** 的字节（指针链本身在各段的数据里，不在 payload 里）；
/// * `segments`：`LC_SEGMENT` / `LC_SEGMENT_64` 解出来的段（按命令顺序，链描述里的
///   段序号就是这个顺序）；
/// * `image_base`：`__TEXT.vmaddr`（dyld 的 preferred load address）。`None` 表示
///   没有 `__TEXT`，那时 `segment_offset` 无从换算成地址 —— 记 `notes` 后返回
///   `Ok(None)`（不是"走了但没结果"）。
///
/// 返回 `Ok(None)` 的两种情形：没有镜像基址、以及调用方本不该调用（`starts_offset == 0`
/// 时也返回 `Ok(None)` 并记一条说明）。
///
/// # Errors
///
/// 链描述越界、`pointer_format` 不认识（[`ParseError::NotSupported`]）、
/// `segment_offset` 与 `LC_SEGMENT.vmaddr` 对不上、指针越出段的内存/文件范围、
/// 指针跨页、链不终止（偏移不递增或步数超过页容量）、bind 的 `ordinal` 越界、
/// 指针总数超过 [`MAX_CHAINED_POINTERS`] —— 都是 `ParseError`。
pub fn walk_chains(
    payload: &[u8],
    image: &[u8],
    segments: &[MachOSegment],
    image_base: Option<u64>,
    starts_offset: u32,
    imports: &mut [ChainedImport],
    notes: &mut Vec<String>,
) -> Result<Option<ChainWalk>, ParseError> {
    if starts_offset == 0 {
        notes.push(
            "LC_DYLD_CHAINED_FIXUPS 的 starts_offset = 0：这份文件没有链描述（只有导入表\
             与符号池），所以导入没有槽位地址这件事是文件里的事实，不是本片没走链"
                .to_string(),
        );
        return Ok(None);
    }
    let Some(image_base) = image_base else {
        notes.push(
            "LC_DYLD_CHAINED_FIXUPS 有链描述，但这份文件没有 __TEXT 段、镜像基址未知：\
             starts_in_segment.segment_offset 是相对镜像基址的内存偏移，没有基址就换不出\
             地址 —— 因此**没有走链**，导入的 iat_slot 保持 None（未知，不是 0）"
                .to_string(),
        );
        return Ok(None);
    };

    let starts = usize::try_from(starts_offset).map_err(|_| {
        ParseError::Inconsistent(format!(
            "dyld_chained_fixups_header.starts_offset = {starts_offset:#x} 超出 usize"
        ))
    })?;
    let seg_count = read_u32(payload, starts, "dyld_chained_starts_in_image.seg_count")?;
    if seg_count > MAX_CHAINED_SEGMENTS {
        return Err(ParseError::Inconsistent(format!(
            "dyld_chained_starts_in_image.seg_count = {seg_count} 超过上限 \
             {MAX_CHAINED_SEGMENTS}：文件被构造过"
        )));
    }
    let seg_count = seg_count as usize;
    if seg_count > segments.len() {
        return Err(ParseError::Inconsistent(format!(
            "dyld_chained_starts_in_image 声明 {seg_count} 个段，但这个镜像只有 {} 个 \
             LC_SEGMENT：链描述与加载命令自相矛盾（多出来的段没有地址可落）",
            segments.len()
        )));
    }
    if seg_count != segments.len() {
        notes.push(format!(
            "dyld_chained_starts_in_image 声明 {seg_count} 个段，镜像有 {} 个 \
             LC_SEGMENT：多出来的段没有链描述（按规范没有链，不影响结论）",
            segments.len()
        ));
    }

    let mut walker = ChainWalker {
        image,
        imports,
        walk: ChainWalk::default(),
    };

    for (seg_index, segment) in segments.iter().enumerate().take(seg_count) {
        let entry_offset = read_u32(
            payload,
            starts
                .checked_add(4)
                .and_then(|base| base.checked_add(4 * seg_index))
                .ok_or_else(|| {
                    ParseError::Overflow("dyld_chained_starts_in_image.seg_info_offset".to_string())
                })?,
            "dyld_chained_starts_in_image.seg_info_offset",
        )?;
        if entry_offset == 0 {
            // 这个段没有修复（__PAGEZERO 几乎总是这样）。
            continue;
        }
        let seg_info = starts
            .checked_add(usize::try_from(entry_offset).map_err(|_| {
                ParseError::Inconsistent(format!(
                    "第 {seg_index} 个段的 seg_info_offset = {entry_offset:#x} 超出 usize"
                ))
            })?)
            .ok_or_else(|| {
                ParseError::Overflow("dyld_chained_starts_in_image.seg_info_offset".to_string())
            })?;

        let size = read_u32(payload, seg_info, "dyld_chained_starts_in_segment.size")?;
        let page_size_raw = read_u16(
            payload,
            seg_info + 0x04,
            "dyld_chained_starts_in_segment.page_size",
        )?;
        let pointer_format = read_u16(
            payload,
            seg_info + 0x06,
            "dyld_chained_starts_in_segment.pointer_format",
        )?;
        let segment_offset = read_u64(
            payload,
            seg_info + 0x08,
            "dyld_chained_starts_in_segment.segment_offset",
        )?;
        // `max_valid_pointer` 只对 32 位格式有意义（那些格式本片不接受，见 pointer_layout）。
        read_u32(
            payload,
            seg_info + 0x10,
            "dyld_chained_starts_in_segment.max_valid_pointer",
        )?;
        let page_count = read_u16(
            payload,
            seg_info + 0x14,
            "dyld_chained_starts_in_segment.page_count",
        )?;

        let layout = pointer_layout(pointer_format)?;

        // `size` 必须至少装下固定头 + page_count 项 `page_start`，而且整段得在 payload 里。
        let needed = DYLD_CHAINED_STARTS_IN_SEGMENT_HEADER_SIZE as u64 + 2 * u64::from(page_count);
        if u64::from(size) < needed {
            return Err(ParseError::Inconsistent(format!(
                "第 {seg_index} 个段（{}）的 starts_in_segment.size = {size}，装不下固定头 \
                 {DYLD_CHAINED_STARTS_IN_SEGMENT_HEADER_SIZE} 字节 + {page_count} 项 page_start \
                 （共需 {needed} 字节）：文件被裁剪或头字段被人为改过",
                segment.name
            )));
        }
        let entries_end = seg_info
            .checked_add(usize::try_from(size).map_err(|_| {
                ParseError::Inconsistent(format!("第 {seg_index} 个段的 size = {size} 超出 usize"))
            })?)
            .ok_or_else(|| ParseError::Overflow("starts_in_segment 的结束偏移".to_string()))?;
        if entries_end > payload.len() {
            return Err(ParseError::Inconsistent(format!(
                "第 {seg_index} 个段（{}）的 starts_in_segment 从偏移 {seg_info:#x} 起声明 \
                 {size} 字节，结束偏移 {entries_end:#x} 超出 payload {:#x} 字节",
                segment.name,
                payload.len()
            )));
        }
        // 数组的总项数（page_start[page_count] + chain_starts[]）：按 `size` 定界。
        let total_entries = (size as usize - DYLD_CHAINED_STARTS_IN_SEGMENT_HEADER_SIZE) / 2;
        let page_array = seg_info + DYLD_CHAINED_STARTS_IN_SEGMENT_HEADER_SIZE;

        if page_size_raw == 0 || !page_size_raw.is_power_of_two() {
            return Err(ParseError::Inconsistent(format!(
                "第 {seg_index} 个段（{}）的 page_size = {page_size_raw}：规范里是 0x1000 / 0x4000\
                 （2 的幂），0 或非 2 的幂会让每页的边界无从判断",
                segment.name
            )));
        }
        let page_size = u64::from(page_size_raw);
        if page_size < CHAINED_POINTER_WORD_BYTES {
            return Err(ParseError::Inconsistent(format!(
                "第 {seg_index} 个段（{}）的 page_size = {page_size:#x} 装不下一个 {} 字节的指针",
                segment.name, CHAINED_POINTER_WORD_BYTES
            )));
        }

        // 地址基准：dyld 用 preferredLoadAddress + segment_offset。它与该段的
        // LC_SEGMENT.vmaddr 应当相等；不等时如实记下来，但地址仍按 dyld 的算式算。
        let mem_base = image_base.checked_add(segment_offset).ok_or_else(|| {
            ParseError::Overflow(format!(
                "第 {seg_index} 个段（{}）的镜像基址 + segment_offset",
                segment.name
            ))
        })?;
        if mem_base < segment.vmaddr {
            return Err(ParseError::Inconsistent(format!(
                "第 {seg_index} 个段（{}）的 segment_offset = {segment_offset:#x}（镜像基址 \
                 {image_base:#x} → {mem_base:#x}）落在段自己的 vmaddr {:#x} 之前：\
                 starts_in_segment 与 LC_SEGMENT 自相矛盾",
                segment.name, segment.vmaddr
            )));
        }
        let within = mem_base - segment.vmaddr;
        if segment.vmsize > 0 && within >= segment.vmsize {
            return Err(ParseError::Inconsistent(format!(
                "第 {seg_index} 个段（{}）的 segment_offset 把段起点推到段内偏移 {within:#x}，\
                 超出段的内存大小 {:#x}：starts_in_segment 与 LC_SEGMENT 自相矛盾",
                segment.name, segment.vmsize
            )));
        }
        if within != 0 {
            notes.push(format!(
                "第 {seg_index} 个段（{}）的 dyld_chained_starts_in_segment.segment_offset = \
                 {segment_offset:#x}，镜像基址 {image_base:#x} + segment_offset = {mem_base:#x}，\
                 与该段 LC_SEGMENT 的 vmaddr {:#x} 差 {within:#x}：地址按 dyld 的算式\
                 （基址 + segment_offset + 页偏移）算，差额记在这里",
                segment.name, segment.vmaddr
            ));
        }

        for page_index in 0..usize::from(page_count) {
            let raw = read_u16(
                payload,
                page_array + 2 * page_index,
                "dyld_chained_starts_in_segment.page_start",
            )?;
            if raw == DYLD_CHAINED_PTR_START_NONE {
                continue;
            }
            let mut starts_list: Vec<u64> = Vec::new();
            if raw & DYLD_CHAINED_PTR_START_MULTI != 0 {
                // 多起点页：低 15 位是整个 u16 数组（从 page_start[0] 起算）的下标 ——
                // dyld 读作 `segInfo->page_start[overflowIndex]`。`fixup-chains.h` 把这段
                // 注释成 "index into chain_starts[]"，字面也能读成"相对 chain_starts 起算"，
                // 所以下标落进 page_count 以内时直接报错说明歧义，不按另一种读法猜。
                let mut index = usize::from(raw & !DYLD_CHAINED_PTR_START_MULTI);
                if index < usize::from(page_count) {
                    return Err(ParseError::Inconsistent(format!(
                        "第 {seg_index} 个段（{}）第 {page_index} 页是多起点页（page_start = \
                         {raw:#x}），下标 {index} 落在 page_start[0..{page_count}] 自己的区域里：\
                         合法文件的多起点项都存在 page_start[{page_count}..] 这段池子里，下标 \
                         必须 >= {page_count}。fixup-chains.h 把这段注释成 \"index into \
                         chain_starts[]\"，如果这个文件是按相对 chain_starts 起算的下标写的，\
                         那本文件按 dyld 的 page_start[index] 读法就读错了 —— 与其猜，报错",
                        segment.name
                    )));
                }
                loop {
                    if index >= total_entries {
                        return Err(ParseError::Inconsistent(format!(
                            "第 {seg_index} 个段（{}）第 {page_index} 页是多起点页\
                             （page_start = {raw:#x}），但从下标 {index} 开始读到数组末尾\
                             （共 {total_entries} 项，size = {size}）也没有出现 \
                             DYLD_CHAINED_PTR_START_LAST 位：列表没有终点",
                            segment.name
                        )));
                    }
                    let value = read_u16(
                        payload,
                        page_array + 2 * index,
                        "dyld_chained_starts_in_segment.chain_starts",
                    )?;
                    let last = value & DYLD_CHAINED_PTR_START_LAST != 0;
                    starts_list.push(u64::from(value & !DYLD_CHAINED_PTR_START_LAST));
                    index += 1;
                    if last {
                        break;
                    }
                }
            } else {
                starts_list.push(u64::from(raw));
            }
            for start in starts_list {
                walker.run_chain(segment, layout, page_size, within, page_index, start)?;
            }
            walker.walk.pages += 1;
        }
        walker.walk.segments += 1;
    }

    let walk = walker.walk;
    let total_imports = walker.imports.len();
    let mut bind_clause = String::new();
    if walk.auth_binds > 0 {
        let _ = write!(
            bind_clause,
            "，其中 {} 条是 arm64e 认证绑定（没有 addend 字段）",
            walk.auth_binds
        );
    }
    if walk.bind_addends > 0 {
        let _ = write!(
            bind_clause,
            "，另有 {} 条带非零加数（加数在指针字里，不影响槽位地址）",
            walk.bind_addends
        );
    }
    notes.push(format!(
        "已走 LC_DYLD_CHAINED_FIXUPS 的指针链（starts_offset = {starts_offset:#x}）：\
         {} 个段 / {} 页 / {} 条链 / {} 个指针（{} 个 bind{bind_clause}、{} 个 rebase）；\
         {total_imports} 条导入里 {} 条拿到槽位地址（地址 = 镜像基址 {image_base:#x} + \
         segment_offset + 页偏移 + 页内偏移）",
        walk.segments,
        walk.pages,
        walk.chains,
        walk.pointers,
        walk.binds,
        walk.rebases,
        walk.imports_with_slot
    ));
    if walk.extra_bind_sites > 0 {
        let samples = walk
            .duplicate_samples
            .iter()
            .map(|(ordinal, address)| format!("#{ordinal}@{address:#x}"))
            .collect::<Vec<_>>()
            .join("、");
        notes.push(format!(
            "有 {} 处 bind 指向**已经绑过**的导入（同一条导入被写进多个指针槽）：每条导入的 \
             iat_slot 只保留第一个地址，其余 {} 处不丢 —— 计数在这里，前 {} 个样例：{samples}",
            walk.extra_bind_sites,
            walk.extra_bind_sites,
            walk.duplicate_samples.len()
        ));
    }
    Ok(Some(walk))
}

/// 库序号 → 库名（含特殊序号的尖括号标签）。
///
/// `ordinal_width` 是位域宽度（8 或 16）：二补码的负值只能按宽度解释，
/// `0xFF` 与 `0xFFFF` 都表示 -1（主可执行文件）。
fn resolve_ordinal(
    ordinal: u32,
    ordinal_width: u32,
    dylibs: &[String],
    index: u32,
) -> Result<String, ParseError> {
    let signed = match ordinal_width {
        8 => i64::from(ordinal as u8 as i8),
        16 => i64::from(ordinal as u16 as i16),
        other => {
            return Err(ParseError::Inconsistent(format!(
                "链式修复导入表第 {index} 条的库序号宽度是 {other} 位：规范只有 8 / 16 两种"
            )));
        }
    };

    match signed {
        -1 => Ok("<main-executable>".to_string()),
        -2 => Ok("<flat-lookup>".to_string()),
        -3 => Ok("<weak-lookup>".to_string()),
        0 => Err(ParseError::Inconsistent(format!(
            "链式修复导入表第 {index} 条的 lib_ordinal 是 0：LC_LOAD_DYLIB 的序号是 1 基的，\
             0 在这里没有对应库（特殊序号是 0xFF/0xFFFF = 主可执行文件、0xFE/0xFFFE = flat \
             lookup）：文件被构造过"
        ))),
        n if n > 0 => {
            let slot = usize::try_from(n - 1).unwrap_or(usize::MAX);
            dylibs.get(slot).cloned().ok_or_else(|| {
                ParseError::Inconsistent(format!(
                    "链式修复导入表第 {index} 条的 lib_ordinal = {n}，但这个镜像的 \
                     LC_LOAD_DYLIB 只有 {} 条（序号是 1 基的）：导入表与加载命令自相矛盾",
                    dylibs.len()
                ))
            })
        }
        other => Err(ParseError::Inconsistent(format!(
            "链式修复导入表第 {index} 条的 lib_ordinal（按 {ordinal_width} 位二补码）= \
             {other}，不在已知的特殊序号表里（-1 主可执行文件、-2 flat lookup、\
             -3 weak lookup）：文件被构造过"
        ))),
    }
}

/// 从符号池里取第 `index` 条导入的名字。
///
/// 三条硬要求：偏移必须落在池内、名字必须在池内有 NUL 终止符、长度不超过
/// [`MAX_SYMBOL_NAME_LEN`]。名字按 UTF-8 校验 —— Mach-O 的符号名都是 ASCII，
/// 出现非法 UTF-8 说明 `name_offset` 指的其实是别的字节。
fn read_symbol_name(pool: &[u8], name_offset: u32, index: u32) -> Result<String, ParseError> {
    let start = usize::try_from(name_offset).map_err(|_| {
        ParseError::Inconsistent(format!(
            "链式修复导入表第 {index} 条的 name_offset = {name_offset:#x} 超出 usize"
        ))
    })?;
    let tail = pool.get(start..).ok_or_else(|| {
        ParseError::Inconsistent(format!(
            "链式修复导入表第 {index} 条的 name_offset = {name_offset:#x} 超出符号池 \
             {} 字节：名字无从取起",
            pool.len()
        ))
    })?;
    let nul = tail.iter().position(|&byte| byte == 0).ok_or_else(|| {
        ParseError::Inconsistent(format!(
            "链式修复导入表第 {index} 条的名字（池内偏移 {name_offset:#x}）到池尾都没有 \
                 NUL 终止符：符号池被裁剪"
        ))
    })?;
    if nul > MAX_SYMBOL_NAME_LEN {
        return Err(ParseError::Inconsistent(format!(
            "链式修复导入表第 {index} 条的名字有 {nul} 字节，超过上限 {MAX_SYMBOL_NAME_LEN}：\
             偏移很可能指错了位置"
        )));
    }
    if nul == 0 {
        return Err(ParseError::Inconsistent(format!(
            "链式修复导入表第 {index} 条的名字是空串（池内偏移 {name_offset:#x} 处就是 NUL）：\
             真实链接器不会这样写"
        )));
    }
    std::str::from_utf8(&tail[..nul])
        .map(str::to_string)
        .map_err(|_| {
            ParseError::Inconsistent(format!(
                "链式修复导入表第 {index} 条的名字（池内偏移 {name_offset:#x}）不是合法 UTF-8：\
                 name_offset 很可能指错了位置"
            ))
        })
}

/// 读一个 `u16`（小端），并做范围检查。
fn read_u16(payload: &[u8], offset: usize, what: &'static str) -> Result<u16, ParseError> {
    let bytes = read_bytes::<2>(payload, offset, what)?;
    Ok(u16::from_le_bytes(bytes))
}

/// 读一个 `u32`（小端），并做范围检查。
fn read_u32(payload: &[u8], offset: usize, what: &'static str) -> Result<u32, ParseError> {
    let bytes = read_bytes::<4>(payload, offset, what)?;
    Ok(u32::from_le_bytes(bytes))
}

/// 读一个 `u64`（小端），并做范围检查。
fn read_u64(payload: &[u8], offset: usize, what: &'static str) -> Result<u64, ParseError> {
    let bytes = read_bytes::<8>(payload, offset, what)?;
    Ok(u64::from_le_bytes(bytes))
}

/// 取 `N` 字节并翻成 `[u8; N]`；越界是 [`ParseError::Truncated`]。
fn read_bytes<const N: usize>(
    payload: &[u8],
    offset: usize,
    what: &'static str,
) -> Result<[u8; N], ParseError> {
    let end = offset
        .checked_add(N)
        .ok_or_else(|| ParseError::Overflow(format!("读 {what} 的结束偏移")))?;
    payload
        .get(offset..end)
        .ok_or(ParseError::Truncated {
            what,
            needed: end as u64,
            actual: payload.len() as u64,
        })?
        .try_into()
        .map_err(|_| ParseError::Inconsistent(format!("读 {what} 时长度与预期不符")))
}
