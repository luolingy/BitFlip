//! fat / universal Mach-O 容器（`mach-o/fat.h`）。
//!
//! # 这里做什么
//!
//! 一个 fat 文件就是"头 + 架构表 + 若干层薄 Mach-O"。本模块回答三个问题：
//! **里面有几层、每层是什么架构、每层的字节范围是多少**（[`read`]），
//! **默认该开哪一层**（[`FatFile::select`]，规则写在 [`SELECTION_RULE_ZH`] 里），
//! 以及**把某一层当成对象去解析**（[`parse_slice`]）。
//!
//! 切片同时被表示成容器成员（[`members`]）：每个切片是一个
//! [`ArchiveMember`]（`MemberStorage::Inline`，`offset`/`size` 就是切片范围），
//! 名字形如 `slice 0: aarch64/64/le`。名字是**生成的、不是文件里的事实** ——
//! fat 的切片没有名字，只有架构，所以名字必须把架构说全，而不是编一个文件名。
//!
//! # 默认选哪一片，以及为什么必须写出来
//!
//! 用户不指定架构时总得开一片，但"挑了第 0 片"与"挑了 arm64"是两件不同的事：
//! 前者是兜底，后者是偏好。两者都写在 [`SELECTION_RULE_ZH`] 这一句话里，
//! 并且由 [`FatFile::selection_note`] 拼进解析结果的 `notes` ——
//! 用户不必去反推"为什么给我看的是这一片"（CLAUDE.md §7：降级要写在界面上）。
//!
//! 指定的架构不存在时**报错并列出手上有哪些切片**（[`FatError::ArchAbsent`]），
//! 绝不"找不到就退回默认那片" —— 那会让用户以为他指定成功了。
//!
//! # `CAFEBABE` 也是 Java class 的魔数
//!
//! 两者的前 4 字节完全一样。区分办法与 [`crate::sniff`] 一致：看架构表的
//! **第一个 `cputype` 是不是已知的 Mach-O CPU**。Java class 的"切片数"位置上是
//! 版本号、`cputype` 位置上是常量池的内容，几乎不可能撞上 Mach-O 的 CPU 值。
//! 撞上了也不是灾难：接下来的范围校验会拒绝。

use bitflip_arch::{Arch, ArchSpec, Endian};
use thiserror::Error;

use super::{looks_like_fat, MH_CIGAM, MH_CIGAM_64, MH_MAGIC, MH_MAGIC_64};
use crate::object::{Object, ObjectId};
use crate::reader::{Endianness, ParseError, Reader};
use crate::{ArchiveMember, MemberStorage};

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
    /// `None` = 切片开头不是 Mach-O 魔数，或 `cputype` 未映射 ——
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
        "fat 容器：{} 个切片（每个切片是一个容器成员，名字形如 `slice 0: <架构>`）。\
         默认打开哪一片由 `format::macho::fat::SELECTION_RULE_ZH` 决定，\
         会话层会把选中的那片与依据写进解析结果的 notes",
        slices.len()
    ));

    Ok(FatFile {
        is_64,
        slices,
        notes,
    })
}

/// 切片选择规则（**一句话**，原样进 `notes` 与 CLI）。
///
/// 规则本身是**偏好**，不是规范：fat 文件里没有"哪一片是主 slice"的字段。
/// 之所以按这个顺序：
///
/// 1. `arm64` —— iOS 设备上真正跑的就是它（本仓库的四份真实 IPA 全是薄 arm64）；
/// 2. `x86_64` —— Intel Mac / 模拟器上的那一层；
/// 3. `arm64e` —— 同样跑在 arm64 设备上，但指针认证（PAC）语义更复杂；
///    排序放在 arm64 之后是因为一般分析不需要 PAC 变体；
/// 4. 第 0 片 —— 兜底，**仍然是猜测**，所以 [`SelectionBasis::FirstSlice`]
///    会把自己的名字写进说明里。
pub const SELECTION_RULE_ZH: &str =
    "优先 arm64（aarch64）、其次 x86_64、再次 arm64e、最后取第 0 片";

/// 这一片是**按什么依据**选出来的。
///
/// 单独一个枚举而不是一个布尔值：`FirstSlice` 与 `Preferred*` 的区别正是
/// "这是兜底"与"这是偏好"，而界面上必须能分开（§7）。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SelectionBasis {
    /// 调用方显式指定了架构，且这一片的架构正好是它。
    Requested,
    /// 默认规则第 1 步：arm64（aarch64，且不是 arm64e）。
    PreferredArm64,
    /// 默认规则第 2 步：x86_64。
    PreferredX86_64,
    /// 默认规则第 3 步：arm64e（`cputype` 与 arm64 相同，`cpusubtype = 2`）。
    PreferredArm64e,
    /// 默认规则第 4 步：没有一条偏好命中，取第 0 片。
    FirstSlice,
}

impl SelectionBasis {
    /// 稳定的短名（JSON / 日志）。
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Requested => "requested",
            Self::PreferredArm64 => "prefer-arm64",
            Self::PreferredX86_64 => "prefer-x86_64",
            Self::PreferredArm64e => "prefer-arm64e",
            Self::FirstSlice => "first-slice",
        }
    }

    /// 面向界面的中文说明（**不含**切片名，切片名由调用方拼上）。
    #[must_use]
    pub const fn label_zh(self) -> &'static str {
        match self {
            Self::Requested => "按调用方指定的架构挑的",
            Self::PreferredArm64 => "按默认规则命中 arm64",
            Self::PreferredX86_64 => "按默认规则命中 x86_64",
            Self::PreferredArm64e => "按默认规则命中 arm64e",
            Self::FirstSlice => "没有命中规则里的优先架构，取第 0 片（兜底，不是偏好）",
        }
    }
}

/// 一次切片选择的结果。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Selection {
    /// 选中的切片下标（架构表里的顺序，从 0 起）。
    pub index: usize,
    /// 凭什么选它。
    pub basis: SelectionBasis,
}

/// fat 相关的**选择**错误。
///
/// 与 [`ParseError`] 分开：容器本身可能是完全合法的，只是里面没有用户要的那一片。
/// 把这种情况塞进 `ParseError::Inconsistent`（"文件自相矛盾"）是错的归因。
#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum FatError {
    /// 调用方指定的架构不在这份 fat 文件里。
    ///
    /// 消息里**必须**列出手上有哪些切片：只说"没有 arm64"会让用户以为文件坏了，
    /// 而真正的问题是"这份文件里有的是 x86 / x86_64"。
    #[error("这份 fat 文件里没有 {requested} 切片；它有 {available} 个切片：{list}")]
    ArchAbsent {
        /// 用户要的架构短名。
        requested: String,
        /// 文件里实际的切片数。
        available: usize,
        /// 实际有的切片（逗号分隔的 `slice N: <arch>`）。
        list: String,
    },
}

impl FatSlice {
    /// 这一片的 `cpusubtype` 是不是 `arm64e`。
    ///
    /// 判据是"`cputype` 等于 arm64 **且** `cpusubtype` 等于 2"（`mach/machine.h`
    /// 的 `CPU_SUBTYPE_ARM64E`）—— 只比 `cputype` 会把 arm64 也认成 arm64e。
    #[must_use]
    pub fn is_arm64e(&self) -> bool {
        self.cputype == super::CPU_TYPE_ARM64 && self.cpusubtype == super::CPU_SUBTYPE_ARM64E
    }

    /// 成员名：`slice 0: aarch64/64/le`，arm64e 再补一个 `(arm64e)`。
    ///
    /// 为什么不是文件名：fat 的切片**没有名字**，编一个 `libfoo.dylib` 之类
    /// 的名字就是把生成物说成事实。名字里带架构是唯一诚实的命名方式，
    /// 而"选哪一片"也正是用户要回答的问题。
    ///
    /// 架构未知时写"架构未知"（不猜）；arm64e 与 arm64 的 `cputype` 相同，
    /// 光看架构串分不出来，所以补一个后缀。
    #[must_use]
    pub fn member_name(&self) -> String {
        let arch = self.arch.map_or_else(
            || "架构未知".to_string(),
            |spec: ArchSpec| spec.to_string(),
        );
        if self.is_arm64e() {
            format!("slice {}: {arch}（arm64e）", self.index)
        } else {
            format!("slice {}: {arch}", self.index)
        }
    }
}

impl FatFile {
    /// 默认选哪一片（按 [`SELECTION_RULE_ZH`]）。
    ///
    /// 返回值**总是**合法的下标：`read` 保证至少有 1 个切片。
    #[must_use]
    pub fn default_selection(&self) -> Selection {
        // 第 1 步：arm64（排除 arm64e —— 它走第 3 步，理由见规则说明）。
        if let Some(index) = self
            .slices
            .iter()
            .position(|slice| matches_arch(slice, Arch::Aarch64) && !slice.is_arm64e())
        {
            return Selection {
                index,
                basis: SelectionBasis::PreferredArm64,
            };
        }
        if let Some(index) = self
            .slices
            .iter()
            .position(|slice| matches_arch(slice, Arch::X86_64))
        {
            return Selection {
                index,
                basis: SelectionBasis::PreferredX86_64,
            };
        }
        if let Some(index) = self.slices.iter().position(FatSlice::is_arm64e) {
            return Selection {
                index,
                basis: SelectionBasis::PreferredArm64e,
            };
        }
        // 兜底：第 0 片。仍然要说清这是兜底。
        Selection {
            index: 0,
            basis: SelectionBasis::FirstSlice,
        }
    }

    /// 选一片：`requested` 为 `None` 走默认规则，为 `Some(arch)` 按架构挑。
    ///
    /// # Errors
    ///
    /// 指定的架构不在这份文件里 → [`FatError::ArchAbsent`]（消息里列出实际切片）。
    pub fn select(&self, requested: Option<Arch>) -> Result<Selection, FatError> {
        let Some(wanted) = requested else {
            return Ok(self.default_selection());
        };
        match self
            .slices
            .iter()
            .position(|slice| matches_arch(slice, wanted))
        {
            Some(index) => Ok(Selection {
                index,
                basis: SelectionBasis::Requested,
            }),
            None => Err(FatError::ArchAbsent {
                requested: wanted.as_str().to_string(),
                available: self.slices.len(),
                list: self
                    .slices
                    .iter()
                    .map(FatSlice::member_name)
                    .collect::<Vec<_>>()
                    .join("、"),
            }),
        }
    }

    /// "这份文件有几片、本次开哪片、凭什么是它"—— 一句话，直接进 `notes`。
    ///
    /// 这是 §7 要求的"降级写在界面上"的载体：默认挑一片是**猜测**，
    /// 猜测必须自报家门，否则用户会把它当成文件里写着的事实。
    #[must_use]
    pub fn selection_note(&self, selection: Selection) -> String {
        let chosen = self
            .slices
            .get(selection.index)
            .map_or_else(|| format!("第 {} 片", selection.index), FatSlice::member_name);
        let others = if self.slices.len() > 1 {
            format!(
                "（全部切片：{}）",
                self.slices
                    .iter()
                    .map(FatSlice::member_name)
                    .collect::<Vec<_>>()
                    .join("、")
            )
        } else {
            String::new()
        };
        format!(
            "这份 fat 文件有 {} 个切片；本次打开的是 {chosen}（{}；规则：{SELECTION_RULE_ZH}）{others}",
            self.slices.len(),
            selection.basis.label_zh()
        )
    }

    /// 把每个切片表示成容器成员（M12 第三片）。
    ///
    /// `MemberStorage::Inline` 是**准确的**而不是偷懒：切片的字节就是
    /// `offset..offset+size`，没有压缩、也没有第二层目录。
    #[must_use]
    pub fn members(&self) -> Vec<ArchiveMember> {
        self.slices
            .iter()
            .map(|slice| ArchiveMember {
                index: slice.index,
                name: slice.member_name(),
                offset: Some(slice.offset),
                size: slice.size,
                // 切片范围在 `read` 里已经对整个文件校验过，能走到这里就是完整的。
                truncated: false,
                storage: MemberStorage::Inline,
                // 架构在容器层就知道（架构表 + 切片自己的魔数），这是 fat 的特权。
                arch: slice.arch,
                payload: true,
            })
            .collect()
    }
}

/// 这一片的架构是不是 `wanted`（架构未知的切片不匹配任何请求）。
fn matches_arch(slice: &FatSlice, wanted: Arch) -> bool {
    slice.arch.is_some_and(|spec| spec.arch == wanted)
}

/// 这个 `cputype` 是已知的 Mach-O CPU 吗。
///
/// 判据就是 `bitflip_arch` 的映射表 —— 不在这里再列一遍 CPU 编号：
/// 那份表在 ppc 之前是"能识别但拒绝解析"的，两处各写一份的话，
/// 加 ppc 时就只有一份会跟上（这正是把判据收敛到 arch 层的理由）。
fn is_known_macho_cpu(cputype: u32) -> bool {
    Arch::from_macho_cputype(cputype).is_some()
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
