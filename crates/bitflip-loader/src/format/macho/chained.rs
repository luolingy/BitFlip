//! `LC_DYLD_CHAINED_FIXUPS` 的**导入表**（`imports_offset` 那一段）。
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
//! 所以本文件只解**导入表**：它给出"导入了哪些符号、来自哪个库、是否 weak、
//! 是否带加数"。它**不**给出每条导入写进哪个指针槽 —— 那是另一件事，见下面的
//! "本文件没做什么"。
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
//! * **没有走指针链。** `starts_offset` 指向的 `dyld_chained_starts_in_image` /
//!   `starts_in_segment` 描述的是"哪些页、页里哪个偏移有一条指针对链"，沿链走
//!   （并且按 `pointer_format` 还原指针）才能得到**每条导入被写进哪个地址**。
//!   本文件不碰那部分：所以解出来的是"导入集"，**没有地址**。对象模型里这些
//!   导入的 `iat_slot` 因此是 `None`（未知），不是 `0`（CLAUDE.md §7）。
//! * **没有解 rebase**：链里同时混着本镜像内部的 rebase 指针，它们不是导入。
//! * **没有解 zlib 压缩的符号池**（`symbols_format == 1`）：返回明确的"暂不支持"，
//!   而不是拿压缩字节当名字。
//! * 没有解 `fixups_version != 0` 的头（目前规范只定义 0）。
//!
//! # 恶性输入
//!
//! 每个偏移 / 长度都先与 payload 长度比对（`checked_add` + `checked_mul`），条目数
//! 有上限 [`MAX_CHAINED_IMPORTS`]，符号名必须在池内有 NUL 终止符且不超过
//! [`MAX_SYMBOL_NAME_LEN`] 字节。任何一条不成立都是 `ParseError` —— 不 panic、
//! 不挂死、也不"尽量读"给出一张错表。

use crate::reader::ParseError;

/// `sizeof(struct dyld_chained_fixups_header)`：七个 `uint32`。
pub const DYLD_CHAINED_FIXUPS_HEADER_SIZE: usize = 28;

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

/// 一条从链式修复导入表里解出来的导入（结构层事实，**没有地址**）。
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
}

/// 一次 `LC_DYLD_CHAINED_FIXUPS` 解析的完整结果。
///
/// 头字段原样保留：它们是"这份文件用的是哪种编码"的证据，`notes` 里报的
/// `imports_format` / `symbols_format` 就是从这里来的。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ChainedFixups {
    /// `fixups_version`（规范只定义 0）。
    pub fixups_version: u32,
    /// `starts_offset`：指针链描述的偏移（0 = 没有链描述）。
    ///
    /// 本文件**没有**解它指向的数据，只保留偏移并在 [`Self::has_starts`] 里说明
    /// "文件里确实有链，只是没走"。
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
    })
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
