//! fat / universal Mach-O 容器（`mach-o/fat.h`）。
//!
//! # 这里只做"容器层"
//!
//! 一个 fat 文件就是"头 + 架构表 + 若干层薄 Mach-O"。本模块回答的问题只有两个：
//! **里面有几层、每层是什么架构、每层的字节范围是多少**。把某一层当成对象去解析
//! 是 [`parse_slice`] 的事（它转手调 [`super::parse`]）。
//!
//! # 为什么还没接进容器抽象
//!
//! `ContainerKind::Fat` 从 M0 就存在（抽象预留），但"把切片当成 `ArchiveMember`
//! 走成员会话"要动 `sniff`、`bitflip-core` 的成员路径与 CLI —— 那是 M12 的下一片。
//! 所以现在：`bitflip_loader::format::macho::fat` 能用（有测试），但 CLI 打开一个
//! fat 文件仍然会报错。**不要**把"能枚举切片"当成"fat 已经能用"。
//!
//! # `CAFEBABE` 也是 Java class 的魔数
//!
//! 两者的前 4 字节完全一样。区分办法与 [`crate::sniff`] 一致：看架构表的
//! **第一个 `cputype` 是不是已知的 Mach-O CPU**。Java class 的"切片数"位置上是
//! 版本号、`cputype` 位置上是常量池的内容，几乎不可能撞上 Mach-O 的 CPU 值。
//! 撞上了也不是灾难：接下来的范围校验会拒绝。

use bitflip_arch::{Arch, ArchSpec, Endian};

use super::{
    looks_like_fat, CPU_TYPE_POWERPC, CPU_TYPE_POWERPC64, MH_CIGAM, MH_CIGAM_64, MH_MAGIC,
    MH_MAGIC_64,
};
use crate::object::{Object, ObjectId};
use crate::reader::{Endianness, ParseError, Reader};

/// `FAT_MAGIC`：32 位 fat 头（架构表项是 `fat_arch`，20 字节）。
pub const FAT_MAGIC: u32 = 0xcafe_babe;
/// `FAT_MAGIC_64`：64 位 fat 头（架构表项是 `fat_arch_64`，32 字节）。
pub const FAT_MAGIC_64: u32 = 0xcafe_babf;

/// `sizeof(struct fat_header)`：magic + nfat_arch。
pub const FAT_HEADER_SIZE: u64 = 8;
/// `sizeof(struct fat_arch)`：5 个 `uint32`（cputype / cpusubtype / offset / size / align）。
pub const FAT_ARCH_SIZE: u64 = 20;
/// `sizeof(struct fat_arch_64)`：cputype + cpusubtype + offset(8) + size(8) + align + reserved。
pub const FAT_ARCH64_SIZE: u64 = 32;

/// 切片数上限。
///
/// 真实 fat 文件最多 2–4 层（i386/x86_64/arm/arm64）。上限存在的意义是挡住
/// "nfat_arch 编成 40 亿"这种输入 —— 架构表先按这个数校验范围，超了直接拒绝，
/// 不会尝试分配。
pub const MAX_FAT_SLICES: u32 = 64;

/// 一个 fat 容器。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FatFile {
    /// 架构表项是 `fat_arch_64`（`FAT_MAGIC_64`）吗。
    pub is_64: bool,
    /// 切片（按架构表顺序）。
    pub slices: Vec<FatSlice>,
    /// 解析过程中的说明。
    pub notes: Vec<String>,
}

/// 一个架构切片。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FatSlice {
    /// 架构表里的下标（从 0 起）。
    pub index: usize,
    /// `cputype` 原始值。
    pub cputype: u32,
    /// `cpusubtype` 原始值。
    pub cpusubtype: u32,
    /// 切片在**宿主文件**里的起始偏移。
    pub offset: u64,
    /// 切片字节数。
    pub size: u64,
    /// `align`（**以 2 为底的对数**，规范如此）。
    pub align: u32,
    /// `fat_arch_64` 里的 `reserved`（32 位表项没有）。
    pub reserved: Option<u32>,
    /// 切片的架构（读切片自己的魔数与 `cputype` 得到）。
    ///
    /// `None` = 切片开头不是 Mach-O 魔数，或 `cputype` 未映射（ppc 也在这里）——
    /// 两种情况都**不猜**，原因在 [`FatFile::notes`] 里。
    pub arch: Option<ArchSpec>,
}

/// 枚举 fat 容器里的切片。
///
/// `bytes` 必须是**完整文件**（切片范围要对整个文件校验）。
///
/// # Errors
///
/// 魔数不是 fat；`nfat_arch = 0` 或超过 [`MAX_FAT_SLICES`]；架构表越界；
/// 切片范围越界或相互冲突；看起来是 Java class 而不是 fat Mach-O。
pub fn read(bytes: &[u8]) -> Result<FatFile, ParseError> {
    let reader = Reader::new(bytes);
    // fat 头**恒为大端**（`mach-o/fat.h` 的注释写死了这一点，与切片自己的端序无关）。
    let magic = reader.u32(0, Endianness::Big, "fat 头 magic")?;
    let is_64 = match magic {
        FAT_MAGIC => false,
        FAT_MAGIC_64 => true,
        other => {
            return Err(ParseError::BadMagic {
                expected: "fat Mach-O 魔数（0xcafebabe / 0xcafebabf）",
                actual: format!("{other:#010x}"),
            })
        }
    };
    let nfat = reader.u32(4, Endianness::Big, "nfat_arch")?;
    if nfat == 0 {
        return Err(ParseError::Inconsistent(
            "nfat_arch = 0：fat 容器里至少要有 1 个切片".to_string(),
        ));
    }
    if nfat > MAX_FAT_SLICES {
        return Err(ParseError::Unsupported {
            what: "nfat_arch",
            value: u64::from(nfat),
            detail: "切片数超过上限 64：真实 fat 文件只有 2–4 层，这个数字不像真的",
        });
    }

    let arch_size = if is_64 {
        FAT_ARCH64_SIZE
    } else {
        FAT_ARCH_SIZE
    };
    let table_end = FAT_HEADER_SIZE
        .checked_add(u64::from(nfat) * arch_size)
        .ok_or_else(|| ParseError::Overflow("fat 架构表范围".to_string()))?;
    if table_end > reader.len() {
        return Err(ParseError::Truncated {
            what: "fat 架构表",
            needed: table_end,
            actual: reader.len(),
        });
    }

    let mut notes = Vec::new();
    let mut slices = Vec::with_capacity(nfat as usize);
    for index in 0..u64::from(nfat) {
        let base = FAT_HEADER_SIZE + index * arch_size;
        let cputype = reader.u32(base, Endianness::Big, "fat cputype")?;
        let cpusubtype = reader.u32(base + 4, Endianness::Big, "fat cpusubtype")?;
        let (offset, size, align, reserved) = if is_64 {
            (
                reader.u64(base + 8, Endianness::Big, "fat offset")?,
                reader.u64(base + 16, Endianness::Big, "fat size")?,
                reader.u32(base + 24, Endianness::Big, "fat align")?,
                Some(reader.u32(base + 28, Endianness::Big, "fat reserved")?),
            )
        } else {
            (
                u64::from(reader.u32(base + 8, Endianness::Big, "fat offset")?),
                u64::from(reader.u32(base + 12, Endianness::Big, "fat size")?),
                reader.u32(base + 16, Endianness::Big, "fat align")?,
                None,
            )
        };

        // 第一片用来区分"fat Mach-O"与"Java class"（两者魔数相同）。
        if index == 0 && !is_known_macho_cpu(cputype) {
            return Err(ParseError::Inconsistent(format!(
                "以 0xcafebabe 开头，但架构表第一项的 cputype = {cputype:#010x} 不是已知的 \
                 Mach-O CPU：这多半是 Java class 文件（两者魔数相同），不是 fat Mach-O"
            )));
        }

        if cputype == CPU_TYPE_POWERPC || cputype == CPU_TYPE_POWERPC64 {
            notes.push(format!(
                "切片 #{index} 是 PowerPC（cputype = {cputype:#x}）：能识别，但 bitflip_arch \
                 没有 PowerPC 变体，这一片解析会明确报错（见 format::macho 的模块文档）"
            ));
        }

        if size == 0 {
            return Err(ParseError::Inconsistent(format!(
                "切片 #{index}（cputype = {cputype:#x}）的 size 为 0"
            )));
        }
        let end = offset
            .checked_add(size)
            .ok_or_else(|| ParseError::Overflow(format!("切片 #{index} 的 offset + size")))?;
        if end > reader.len() {
            return Err(ParseError::Inconsistent(format!(
                "切片 #{index} 的范围 {offset:#x}..{end:#x} 超出文件大小 {:#x}",
                reader.len()
            )));
        }
        // 切片不能压在 fat 头/架构表上：那会让"切片字节"与"容器描述"重叠，
        // 取出来的对象头就是垃圾。
        if offset < table_end {
            return Err(ParseError::Inconsistent(format!(
                "切片 #{index} 的偏移 {offset:#x} 落在 fat 头/架构表（0..{table_end:#x}）内部"
            )));
        }

        let arch = peek_slice_arch(bytes, offset, size, cputype, index, &mut notes);
        slices.push(FatSlice {
            index: usize::try_from(index)
                .map_err(|_| ParseError::Overflow("切片下标".to_string()))?,
            cputype,
            cpusubtype,
            offset,
            size,
            align,
            reserved,
            arch,
        });
    }

    notes.push(format!(
        "fat 容器：{} 个切片。切片**选择**（把某一片当成目标）还没有接进容器抽象与成员会话，\
         这是 M12 的下一片",
        slices.len()
    ));

    Ok(FatFile {
        is_64,
        slices,
        notes,
    })
}

/// 这个 `cputype` 是已知的 Mach-O CPU 吗（含"能识别但不能解析"的 ppc）。
fn is_known_macho_cpu(cputype: u32) -> bool {
    Arch::from_macho_cputype(cputype).is_some()
        || cputype == CPU_TYPE_POWERPC
        || cputype == CPU_TYPE_POWERPC64
}

/// 读切片自己的 Mach-O 魔数，得出端序与位宽，再映射架构。
///
/// 映射不出来时**不猜**：`arch = None` + 一条 note。
fn peek_slice_arch(
    bytes: &[u8],
    offset: u64,
    size: u64,
    cputype: u32,
    index: u64,
    notes: &mut Vec<String>,
) -> Option<ArchSpec> {
    let start = usize::try_from(offset).ok()?;
    let available = usize::try_from(size).ok().unwrap_or(0);
    let head = bytes.get(start..start.checked_add(4)?.min(bytes.len()))?;
    if head.len() < 4 || available < 4 {
        notes.push(format!("切片 #{index} 不足 4 字节，读不到 Mach-O 魔数"));
        return None;
    }
    let magic = u32::from_le_bytes([head[0], head[1], head[2], head[3]]);
    let endian = match magic {
        MH_MAGIC | MH_MAGIC_64 => Endian::Little,
        MH_CIGAM | MH_CIGAM_64 => Endian::Big,
        other => {
            notes.push(format!(
                "切片 #{index} 的前 4 字节是 {other:#010x}，不是 Mach-O 魔数：\
                 这一片的架构未知（不猜）"
            ));
            return None;
        }
    };
    match Arch::from_macho_cputype(cputype) {
        Some((arch, mode)) => Some(ArchSpec::from_arch(arch, mode, endian)),
        None => {
            notes.push(format!(
                "切片 #{index} 的 cputype = {cputype:#010x} 未映射：架构未知（不猜）"
            ));
            None
        }
    }
}

/// 取出切片的字节（`offset..offset+size`）。
///
/// # Errors
///
/// 切片范围越界（正常输入在校验阶段已经挡住，这里只是不信任 `FatSlice` 的来源）。
pub fn slice_bytes<'a>(bytes: &'a [u8], slice: &FatSlice) -> Result<&'a [u8], ParseError> {
    let end = slice
        .offset
        .checked_add(slice.size)
        .ok_or_else(|| ParseError::Overflow("切片 offset + size".to_string()))?;
    let total = bytes.len() as u64;
    if end > total {
        return Err(ParseError::OutOfBounds {
            offset: slice.offset,
            len: slice.size,
            size: total,
            what: "fat 切片",
        });
    }
    usize::try_from(slice.offset)
        .ok()
        .and_then(|start| usize::try_from(end).ok().map(|stop| &bytes[start..stop]))
        .ok_or_else(|| ParseError::Overflow("切片偏移超出 usize".to_string()))
}

/// 解析 fat 容器里的**某一片**。
///
/// 这是"fat 文件怎么变成可分析对象"的现成答案：枚举 → 取一片 → 按薄 Mach-O 解析。
/// `id` 是对象标识（fat 切片没有名字，调用方通常传 [`ObjectId::Plain`] 或
/// 自己按架构命名）。
///
/// # Errors
///
/// 容器层错误（同 [`read`]）；`index` 越界；该切片本身不是合法薄 Mach-O。
pub fn parse_slice(bytes: &[u8], index: usize, id: ObjectId) -> Result<Object, ParseError> {
    let file = read(bytes)?;
    let slice = file.slices.get(index).ok_or_else(|| {
        ParseError::Inconsistent(format!(
            "fat 容器只有 {} 个切片，请求的是第 {index} 片",
            file.slices.len()
        ))
    })?;
    let raw = slice_bytes(bytes, slice)?;
    // `base` 传切片的宿主偏移：报错里的偏移才会指向原文件而不只是切片内部。
    super::parse(raw, slice.offset, id)
}

/// 这个前缀看起来是 fat / universal Mach-O 吗（只判魔数）。
///
/// 与 [`read`] 的区别：这个不会失败、不读架构表，只回答"要不要走 [`read`]"。
#[must_use]
pub fn looks_like(bytes: &[u8]) -> bool {
    looks_like_fat(bytes)
}

#[cfg(test)]
mod tests;
