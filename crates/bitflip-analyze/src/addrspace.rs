//! 地址空间：按段组织的虚拟内存视图。
//!
//! ## 为什么需要它
//!
//! 分析器不该知道文件格式。`AddrSpace` 是 `bitflip-loader` 与 `bitflip-analyze`
//! 之间的那一层：loader 把 PE/ELF/COFF 归一化成 `Segment`，这里把它们拼成
//! **一段可随机访问的虚拟地址空间**，分析器只管问"地址 X 处的字节是什么"。
//!
//! ## 设计约束（直接来自 PLAN §2 对参照实现的批评）
//!
//! 1. **不整份读进内存。** 段的字节来自 `ByteSource`，可以是 mmap 也可以是自有缓冲；
//!    100MB 的目标只映射需要的页。
//! 2. **不预解码。** 指令索引是**稀疏**的：只记录扫过的地方，`BTreeMap` 按地址排序。
//!    参照实现把每条指令物化成带 `String` 的对象，100MB 级目标直接 OOM。
//! 3. **不猜。** 地址不在任何段里就是"不在"，返回 `None`；
//!    不返回零填充的假数据，因为零填充和"真实的全零字节"在分析上完全不同。
//!
//! ## 分页
//!
//! 页大小固定 4 KiB。这对齐了绝大多数平台的最小页大小，因而段与页的边界关系
//! 是可预测的：一个段要么整页覆盖，要么根本不碰这一页。

use std::collections::BTreeMap;
use std::sync::Arc;

use bitflip_arch::DecodedInsn;
use bitflip_loader::object::{Section, Segment};

/// 地址空间页大小（字节）。
pub const PAGE_SIZE: u64 = 4096;

/// 页内偏移的掩码。
pub const PAGE_MASK: u64 = PAGE_SIZE - 1;

/// 可重定位目标文件的**合成**地址基址。
///
/// 选 `0x0000_0001_0000_0000` 而不是 `0x400000`（常见的 PE 镜像基址）是刻意的：
/// 这个值不会与任何真实加载地址混淆，一眼就能看出"这不是真实地址"。
///
/// 见 [`AddrSpace::from_sections`]。
pub const SYNTHETIC_BASE: u64 = 0x0000_0001_0000_0000;

/// 段内字节的来源。
///
/// 内部的 `Arc<[u8]>` 让同一份文件数据可以被多个段共享（例如 PE 里两个段
/// 引用同一个文件区域），也让 `AddrSpace` 克隆的代价保持在计数器级别。
#[derive(Debug, Clone)]
pub enum ByteSource {
    /// 文件区间：`base` 是文件内偏移，`len` 是长度。
    ///
    /// 数据由 `AddrSpace` 持有的整体缓冲提供 —— 这样读取只需要算偏移，
    /// 不需要每个段各自有一份 `Vec`。
    FileRange {
        /// 文件内起始偏移。
        base: u64,
        /// 长度（字节）。
        len: u64,
    },
    /// 自有数据（例如 mmap 之外手工构造的段、BSS 的零填充）。
    Owned(Arc<[u8]>),
    /// 无文件内容（`SHT_NOBITS` / `p_memsz > p_filesz` 的尾部）。
    ///
    /// 读取返回 0，但**这是有意的语义**（未初始化数据在加载后确实是零），
    /// 与"地址不存在"严格区分。
    ZeroFill,
}

impl ByteSource {
    /// 长度。
    #[must_use]
    pub fn len(&self) -> u64 {
        match self {
            Self::FileRange { len, .. } => *len,
            Self::Owned(bytes) => bytes.len() as u64,
            Self::ZeroFill => 0,
        }
    }

    /// 是否为空。
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

/// 地址空间里的一个映射段。
#[derive(Debug, Clone)]
pub struct MappedSegment {
    /// 段名（ELF 的程序头通常没有名字，PE 用节名代替）。
    pub name: String,
    /// 虚拟地址起点。
    pub vaddr: u64,
    /// 内存大小（`vsize`，可能大于文件大小，尾部零填充）。
    pub vsize: u64,
    /// 字节来源。
    pub source: ByteSource,
    /// 权限。
    pub perms: bitflip_loader::object::Perms,
}

impl MappedSegment {
    /// 段的虚拟地址上界（不含）。
    #[must_use]
    pub fn end(&self) -> u64 {
        self.vaddr.saturating_add(self.vsize)
    }

    /// 是否包含地址。
    #[must_use]
    pub fn contains(&self, addr: u64) -> bool {
        addr >= self.vaddr && addr < self.end()
    }

    /// 文件内容覆盖的字节数（不含尾部零填充）。
    #[must_use]
    pub fn file_len(&self) -> u64 {
        match &self.source {
            ByteSource::ZeroFill => 0,
            other => other.len(),
        }
    }
}

/// 地址空间错误。
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum AddrSpaceError {
    /// 段区间溢出或超出可表示范围。
    #[error("段 {name} 的地址区间非法：vaddr={vaddr:#x} vsize={vsize:#x}")]
    BadSegment {
        /// 段名。
        name: String,
        /// 虚拟地址。
        vaddr: u64,
        /// 大小。
        vsize: u64,
    },
    /// 段的文件区间超出提供的缓冲。
    #[error("段 {name} 的文件区间 [{base:#x}, +{len:#x}) 超出缓冲大小 {available:#x}")]
    SourceOutOfRange {
        /// 段名。
        name: String,
        /// 起始偏移。
        base: u64,
        /// 长度。
        len: u64,
        /// 缓冲大小。
        available: u64,
    },
}

/// 一次解码扫描的结论。
///
/// 只记录"这段范围内哪些地址是已解码指令的起点"，不保存指令本身 ——
/// 指令按需解码。这是与参照实现最大的分野：索引是 `O(基本块数)`，
/// 而全量物化是 `O(指令数 × 每指令内存)`。
#[derive(Debug, Clone, Default)]
pub struct InsnIndex {
    /// 指令起点 → 解码长度。
    ///
    /// 用 `BTreeMap<u64, u8>` 而不是 `Vec<DecodedInsn>`：
    /// 100 万条指令的索引约占 16MB（键 8 + 值 1 + 树开销），
    /// 而物化 `DecodedInsn`（含 `Vec<Operand>`）要数百 MB 到 GB 级。
    entries: BTreeMap<u64, u8>,
}

impl InsnIndex {
    /// 空索引。
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// 已索引的指令条数。
    #[must_use]
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    /// 是否为空。
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// 记录一条指令（重复记录同一地址时保留首条）。
    pub fn insert(&mut self, addr: u64, len: u8) {
        self.entries.entry(addr).or_insert(len);
    }

    /// 查询某地址是否为已解码指令的起点。
    #[must_use]
    pub fn get(&self, addr: u64) -> Option<u8> {
        self.entries.get(&addr).copied()
    }

    /// 是否已索引该地址。
    #[must_use]
    pub fn contains(&self, addr: u64) -> bool {
        self.entries.contains_key(&addr)
    }

    /// 不小于 `addr` 的第一条已索引指令。
    ///
    /// 返回 `(地址, 长度)`。用于"跳到下一个已知指令边界"。
    #[must_use]
    pub fn next_at_or_after(&self, addr: u64) -> Option<(u64, u8)> {
        self.entries.range(addr..).next().map(|(a, l)| (*a, *l))
    }

    /// 包含 `addr` 的指令，或其后第一条指令。
    ///
    /// `addr` 落在某条指令**中间**时返回那条指令本身，而不是它的下一条。
    ///
    /// ## 为什么需要这个语义
    ///
    /// 用户用地址跳转（"跳到 0x401005"）时，给出的地址很可能落在指令中间 ——
    /// 那是数据里的一个偏移、一条被截断的日志地址、或者用户自己数错了。
    /// 这时最有用的是**把包含该地址的那条指令显示出来并高亮**；
    /// 直接跳到下一条会让用户以为自己跳错了，而且会丢掉"这个地址属于谁"的信息。
    ///
    /// 实现上只需要回看：指令最长 16 字节（x86 上限），因此最多回退 15 个字节
    /// 就能找到包含 `addr` 的那条。回看是 O(15 log n)，可以忽略。
    #[must_use]
    pub fn containing(&self, addr: u64) -> Option<(u64, u8)> {
        // x86 单条指令最长 15 字节；用 16 覆盖所有架构的常见上限
        const MAX_INSN_LEN: u64 = 16;
        let lower = addr.saturating_sub(MAX_INSN_LEN - 1);

        // 先看回退窗口里有没有指令覆盖 addr（从后往前找最近的起点）
        if let Some((start, len)) = self.entries.range(lower..=addr).next_back() {
            // 用 checked_add 而不是 saturating_add：指令末尾越过地址空间顶端
            // （u64::MAX）时，饱和会把末尾压回 u64::MAX，于是"最后几个字节"
            // 永远不算被覆盖。那种情况下这条指令确实延伸到了可表示范围之外，
            // 应当视为覆盖了 `addr`。
            let covers = match start.checked_add(u64::from(*len)) {
                Some(end) => addr < end,
                None => true, // 溢出 => 它一直覆盖到地址空间尽头
            };
            if covers {
                return Some((*start, *len));
            }
        }

        self.next_at_or_after(addr)
    }

    /// 迭代某个地址区间内的全部指令。
    pub fn range(&self, start: u64, end: u64) -> impl Iterator<Item = (u64, u8)> + '_ {
        self.entries.range(start..end).map(|(a, l)| (*a, *l))
    }

    /// 合并另一个索引（后写入的不覆盖已有项）。
    pub fn merge(&mut self, other: &Self) {
        for (addr, len) in &other.entries {
            self.entries.entry(*addr).or_insert(*len);
        }
    }

    /// 估算常驻内存占用（字节）。
    ///
    /// 用于把"索引有多大"诚实报给 UI 与基准测试；`BTreeMap` 的节点开销
    /// 依赖分配器，这里给出的是量级估算而不是精确值。
    #[must_use]
    pub fn estimated_bytes(&self) -> usize {
        // 每个条目：键 8 + 值 1 + padding + 树节点分摊，保守按 32 字节估
        self.entries.len() * 32
    }
}

/// 按段组织的虚拟地址空间。
///
/// 克隆是廉价的：文件缓冲与自有数据都是 `Arc`，索引是唯一需要复制的部分
/// （且在实践中它会被 `Arc` 共享 —— 见 [`AddrSpace::index_arc`]）。
#[derive(Debug, Clone)]
pub struct AddrSpace {
    /// 整个目标文件的字节（mmap 或读入）。段通过偏移引用它。
    file: Arc<[u8]>,
    /// 按虚拟地址排序的段。
    segments: Vec<MappedSegment>,
    /// 稀疏指令索引。
    index: Arc<InsnIndex>,
    /// 地址空间名（目标路径或成员名），用于报错与 UI。
    name: String,
}

impl AddrSpace {
    /// 从 loader 的段列表构造地址空间。
    ///
    /// `file` 是整份文件字节；段的 `file` 区间被解析为对它的引用。
    /// 没有任何段的段（`file == None` 且 `vsize > 0`）会变成零填充段 ——
    /// 这是 `.bss` 的正确语义。
    pub fn new(
        name: impl Into<String>,
        file: Arc<[u8]>,
        segments: &[Segment],
    ) -> Result<Self, AddrSpaceError> {
        let mut mapped = Vec::with_capacity(segments.len());
        let file_len = file.len() as u64;

        for segment in segments {
            if segment.vsize == 0 {
                continue;
            }
            // 区间溢出检查必须在构造时做：之后所有 contains() 都假设区间有效
            let end = segment.vaddr.checked_add(segment.vsize).ok_or_else(|| {
                AddrSpaceError::BadSegment {
                    name: segment.name.clone(),
                    vaddr: segment.vaddr,
                    vsize: segment.vsize,
                }
            })?;
            let _ = end;

            let source = match segment.file {
                Some(range) if range.size > 0 => {
                    let base = range.offset;
                    let len = range.size;
                    // 越界的文件区间是畸形输入：拒绝而不是截断
                    let range_end =
                        base.checked_add(len)
                            .ok_or_else(|| AddrSpaceError::SourceOutOfRange {
                                name: segment.name.clone(),
                                base,
                                len,
                                available: file_len,
                            })?;
                    if range_end > file_len {
                        return Err(AddrSpaceError::SourceOutOfRange {
                            name: segment.name.clone(),
                            base,
                            len,
                            available: file_len,
                        });
                    }
                    ByteSource::FileRange { base, len }
                }
                _ => ByteSource::ZeroFill,
            };

            mapped.push(MappedSegment {
                name: segment.name.clone(),
                vaddr: segment.vaddr,
                vsize: segment.vsize,
                source,
                perms: segment.perms,
            });
        }

        mapped.sort_by_key(|s| s.vaddr);

        Ok(Self {
            file,
            segments: mapped,
            index: Arc::new(InsnIndex::new()),
            name: name.into(),
        })
    }

    /// 空地址空间（用于 raw 目标尚未定义段时）。
    #[must_use]
    pub fn empty(name: impl Into<String>) -> Self {
        Self {
            file: Arc::from(Vec::new()),
            segments: Vec::new(),
            index: Arc::new(InsnIndex::new()),
            name: name.into(),
        }
    }

    /// 从**节**表构造地址空间（可重定位目标文件用）。
    ///
    /// ## 为什么需要这个
    ///
    /// `.o` / `.obj` 是 `ET_REL`：它们**没有程序头（segment）**，只有节表，
    /// 而且每个节的可重定位地址都是 0 —— 节之间的相对位置要到链接期才确定。
    ///
    /// 如果只用 `segments`，这类文件会得到一个空地址空间，
    /// 反汇编就完全做不了 —— 而"能看 .o 文件里的代码"正是逆向工作的日常需求。
    ///
    /// ## 合成地址是显式的，不是偷偷来的
    ///
    /// 这里给每个节分配一段**合成的**连续地址，从 [`SYNTHETIC_BASE`] 开始，
    /// 按节在表里的顺序依次排列。调用方必须把这件事告诉用户
    /// （返回值里的 `synthetic` 标志 + 说明），因为打印出来的地址
    /// **不是**目标文件里真实存在的地址 —— 它们只是本次会话内的标识。
    ///
    /// 用 `0x400000 + n` 这种"看起来像真实基址"的数字是错的：那会让人
    /// 误以为这是加载后的地址。所以基址选在一个明显不像真实映射的值上。
    ///
    /// 只有 `alloc` 或 `execute` 的节会被映射：调试节、符号表、重定位表
    /// 不是运行时内存的一部分，把它们映射进来只会污染地址空间。
    pub fn from_sections(
        name: impl Into<String>,
        file: Arc<[u8]>,
        sections: &[Section],
    ) -> Result<(Self, bool), AddrSpaceError> {
        let file_len = file.len() as u64;
        let mut mapped: Vec<MappedSegment> = Vec::new();
        let mut next_addr = SYNTHETIC_BASE;
        let mut synthetic = false;

        for section in sections {
            // 只映射真正会被加载的节。重定位表、符号表、调试节
            // 不是运行时内存的一部分，映射进来只会污染地址空间。
            // `loaded` 由 loader 按各格式的规则算出（ELF: SHF_ALLOC；
            // PE: 在节表里且非 discardable），比在这里重判权限可靠。
            if !section.loaded || section.file.size == 0 {
                continue;
            }

            // 节本身带 vaddr 且非零时用它（有些 .o 会预填），否则合成。
            // 基址判断用 SYNTHETIC_BASE 之外的真实地址：可重定位文件的节
            // 地址全是 0，只有链接后的映像才有真实地址。
            let vaddr = if section.vaddr != 0 {
                section.vaddr
            } else {
                synthetic = true;
                // 按 16 字节对齐：让反汇编地址整齐，便于阅读
                let aligned = (next_addr + 15) & !15u64;
                next_addr = aligned;
                aligned
            };

            let vsize = section.file.size;
            let end = vaddr
                .checked_add(vsize)
                .ok_or_else(|| AddrSpaceError::BadSegment {
                    name: section.name.clone(),
                    vaddr,
                    vsize,
                })?;
            next_addr = next_addr.max(end);

            let base = section.file.offset;
            let range_end = base.checked_add(section.file.size).ok_or_else(|| {
                AddrSpaceError::SourceOutOfRange {
                    name: section.name.clone(),
                    base,
                    len: section.file.size,
                    available: file_len,
                }
            })?;
            if range_end > file_len {
                return Err(AddrSpaceError::SourceOutOfRange {
                    name: section.name.clone(),
                    base,
                    len: section.file.size,
                    available: file_len,
                });
            }

            mapped.push(MappedSegment {
                name: section.name.clone(),
                vaddr,
                vsize,
                source: ByteSource::FileRange {
                    base,
                    len: section.file.size,
                },
                perms: section.perms,
            });
        }

        mapped.sort_by_key(|s| s.vaddr);

        Ok((
            Self {
                file,
                segments: mapped,
                index: Arc::new(InsnIndex::new()),
                name: name.into(),
            },
            synthetic,
        ))
    }

    /// 名字。
    #[must_use]
    pub fn name(&self) -> &str {
        &self.name
    }

    /// 全部映射段（按虚拟地址排序）。
    #[must_use]
    pub fn segments(&self) -> &[MappedSegment] {
        &self.segments
    }

    /// 指令索引。
    #[must_use]
    pub fn index(&self) -> &InsnIndex {
        &self.index
    }

    /// 索引的共享句柄（用于把索引交给另一个线程而不复制）。
    #[must_use]
    pub fn index_arc(&self) -> Arc<InsnIndex> {
        Arc::clone(&self.index)
    }

    /// 替换索引。
    pub fn set_index(&mut self, index: InsnIndex) {
        self.index = Arc::new(index);
    }

    /// 找到包含该地址的段。
    #[must_use]
    pub fn segment_at(&self, addr: u64) -> Option<&MappedSegment> {
        // 段可能有重叠（恶意/畸形输入），取第一个匹配 —— 段已按 vaddr 排序，
        // 因此这是地址最低的那个，行为是确定的。
        self.segments.iter().find(|s| s.contains(addr))
    }

    /// 地址是否落在任何段内。
    #[must_use]
    pub fn contains(&self, addr: u64) -> bool {
        self.segment_at(addr).is_some()
    }

    /// 读取一个字节。地址不在任何段内返回 `None`。
    #[must_use]
    pub fn read_u8(&self, addr: u64) -> Option<u8> {
        let segment = self.segment_at(addr)?;
        let offset = addr - segment.vaddr;
        match &segment.source {
            ByteSource::FileRange { base, len } => {
                // 段尾部的零填充区（vsize > filesz）读作 0
                if offset >= *len {
                    return Some(0);
                }
                let index = base.checked_add(offset)?;
                self.file.get(index as usize).copied()
            }
            ByteSource::Owned(bytes) => {
                // 自有数据尾部同样是零填充
                bytes.get(offset as usize).copied().or(Some(0))
            }
            ByteSource::ZeroFill => Some(0),
        }
    }

    /// 读取一段连续字节。
    ///
    /// **不跨段**：请求范围必须完整落在同一个段内，否则返回 `None`。
    /// 这是有意的 —— 跨段读取会把两个不同权限/来源的内存拼在一起，
    /// 解码器拿到这种数据只会解出错误的指令。调用方应当按段边界切分。
    ///
    /// 长度为 0 时仍然要求地址在段内：这让"能不能读这个地址"这个问题
    /// 有一个统一答案，而不是"读 0 字节时到处都算存在"。
    #[must_use]
    pub fn read(&self, addr: u64, len: usize) -> Option<Vec<u8>> {
        let segment = self.segment_at(addr)?;
        if len == 0 {
            return Some(Vec::new());
        }
        let offset = addr - segment.vaddr;
        // 请求范围必须完整落在段内
        let end_offset = offset.checked_add(len as u64)?;
        if end_offset > segment.vsize {
            return None;
        }

        let mut out = vec![0u8; len];
        match &segment.source {
            ByteSource::FileRange { base, len: flen } => {
                for (i, slot) in out.iter_mut().enumerate() {
                    let off = offset + i as u64;
                    if off >= *flen {
                        break; // 剩余部分保持 0（尾部零填充）
                    }
                    let index = base + off;
                    *slot = *self.file.get(index as usize)?;
                }
            }
            ByteSource::Owned(bytes) => {
                for (i, slot) in out.iter_mut().enumerate() {
                    *slot = bytes.get(offset as usize + i).copied().unwrap_or(0);
                }
            }
            ByteSource::ZeroFill => {}
        }
        Some(out)
    }

    /// 读取用于解码的字节窗口。
    ///
    /// 与 [`AddrSpace::read`] 的区别：这个**允许读到段尾就停**，返回比请求短
    /// 的切片。解码器需要"尽可能多的字节"，最后一条指令被段尾截断是正常情况，
    /// 应当交给解码器判断 `Truncated`，而不是让调用层把整块丢掉。
    ///
    /// 返回的字节数最多到段尾，绝不跨段。
    #[must_use]
    pub fn read_window(&self, addr: u64, max: usize) -> Option<(Vec<u8>, u64)> {
        let segment = self.segment_at(addr)?;
        let offset = addr - segment.vaddr;
        let available = (segment.vsize - offset).min(max as u64);
        if available == 0 {
            return None;
        }
        let bytes = self.read(addr, available as usize)?;
        Some((bytes, segment.end()))
    }

    /// 可执行段列表（解码扫描的输入）。
    #[must_use]
    pub fn executable_segments(&self) -> Vec<&MappedSegment> {
        self.segments.iter().filter(|s| s.perms.execute).collect()
    }

    /// 地址空间的字节总量（各段 `vsize` 之和）。
    #[must_use]
    pub fn total_vsize(&self) -> u64 {
        self.segments.iter().map(|s| s.vsize).sum()
    }

    /// 段数量。
    #[must_use]
    pub fn segment_count(&self) -> usize {
        self.segments.len()
    }
}

/// 把一条已解码指令登记进索引。
///
/// 独立函数而不是 `AddrSpace` 的方法：解码在并行路径上进行，各线程产出
/// 自己的索引片段，最后合并 —— 这样索引构建不需要加锁。
pub fn index_insn(index: &mut InsnIndex, insn: &DecodedInsn) {
    index.insert(insn.addr, insn.len);
}

#[cfg(test)]
mod tests {
    use super::*;
    use bitflip_loader::object::{FileRange, Perms, Segment};

    /// 构造权限位。
    fn perms(read: bool, write: bool, execute: bool) -> Perms {
        Perms {
            read,
            write,
            execute,
        }
    }

    /// 构造一个测试段。`file` 为 `None` 时是纯零填充段（等价 `.bss`）。
    fn segment(
        name: &str,
        vaddr: u64,
        vsize: u64,
        file: Option<(u64, u64)>,
        perms: Perms,
    ) -> Segment {
        Segment {
            name: name.to_string(),
            vaddr,
            vsize,
            file: file.map(|(offset, size)| FileRange { offset, size }),
            perms,
            kind: bitflip_loader::object::ContentKind::Unknown,
            align: 1,
        }
    }

    /// 两个段的地址空间：`.text` 是可执行的文件映射段（0x1000 起 16 字节，
    /// 内容为 0..15），`.data` 是段内零填充的不可执行段。
    fn space_with_two_segments() -> AddrSpace {
        let file: Vec<u8> = (0u8..16).collect();
        let segments = vec![
            segment(".text", 0x1000, 16, Some((0, 16)), perms(true, false, true)),
            segment(".data", 0x2000, 0x100, None, perms(true, true, false)),
        ];
        AddrSpace::new("t", Arc::from(file), &segments).expect("构造地址空间")
    }

    #[test]
    fn reads_bytes_from_file_backed_segment() {
        let space = space_with_two_segments();
        assert_eq!(space.read_u8(0x1000), Some(0));
        assert_eq!(space.read_u8(0x100f), Some(15));
        assert_eq!(space.read(0x1004, 4), Some(vec![4, 5, 6, 7]));
    }

    #[test]
    fn address_outside_any_segment_is_none_not_zero() {
        // 这是与"零填充"的关键区分：段外地址必须返回 None
        let space = space_with_two_segments();
        assert_eq!(space.read_u8(0x0fff), None);
        assert_eq!(space.read_u8(0x1010), None);
        assert_eq!(space.read(0x0fff, 1), None);
        assert!(!space.contains(0x0fff));
    }

    #[test]
    fn containing_snaps_to_the_instruction_that_covers_the_address() {
        let mut index = InsnIndex::new();
        index.insert(0x1000, 5);
        index.insert(0x1005, 2);
        index.insert(0x1007, 10);

        // 指令起点
        assert_eq!(index.containing(0x1000), Some((0x1000, 5)));
        assert_eq!(index.containing(0x1005), Some((0x1005, 2)));
        // 指令中间：应给出**包含它**的那条，而不是下一条
        assert_eq!(index.containing(0x1002), Some((0x1000, 5)));
        assert_eq!(index.containing(0x1006), Some((0x1005, 2)));
        assert_eq!(index.containing(0x1010), Some((0x1007, 10)));
        // 最后一条之后：没有指令覆盖它，回到"下一条"语义
        assert_eq!(index.containing(0x1011), None);
        assert_eq!(index.containing(0x2000), None);
        // 正好落在边界上（0x1007 是 0x1005 的末尾）：属于下一条
        assert_eq!(index.containing(0x1007), Some((0x1007, 10)));
    }

    #[test]
    fn containing_handles_overflow_at_the_top_of_the_address_space() {
        let mut index = InsnIndex::new();
        index.insert(u64::MAX - 1, 4);
        // start + len 会溢出，不能 panic
        assert_eq!(index.containing(u64::MAX), Some((u64::MAX - 1, 4)));
        assert_eq!(index.containing(u64::MAX - 1), Some((u64::MAX - 1, 4)));
    }

    #[test]
    fn containing_on_empty_index_is_none() {
        let index = InsnIndex::new();
        assert_eq!(index.containing(0), None);
        assert_eq!(index.containing(u64::MAX), None);
    }

    #[test]
    fn next_at_or_after_keeps_its_original_semantics() {
        // containing() 是新语义，不能悄悄改掉 next_at_or_after 的行为 ——
        // 分页游标依赖后者严格"向前看"。
        let mut index = InsnIndex::new();
        index.insert(0x1000, 5);
        index.insert(0x1005, 2);
        assert_eq!(index.next_at_or_after(0x1000), Some((0x1000, 5)));
        assert_eq!(index.next_at_or_after(0x1001), Some((0x1005, 2)));
        assert_eq!(index.next_at_or_after(0x1006), None);
    }

    #[test]
    fn from_sections_maps_only_loaded_sections() {
        use bitflip_loader::object::{ContentKind, FileRange, Perms, Section};

        let bytes: Arc<[u8]> = Arc::from(vec![0x90u8; 64].into_boxed_slice());
        let sections = vec![
            Section {
                name: ".text".to_string(),
                vaddr: 0,
                file: FileRange {
                    offset: 0,
                    size: 16,
                },
                perms: Perms {
                    read: true,
                    write: false,
                    execute: true,
                },
                kind: ContentKind::Code,
                loaded: true,
            },
            Section {
                name: ".symtab".to_string(),
                vaddr: 0,
                file: FileRange {
                    offset: 16,
                    size: 16,
                },
                perms: Perms::none(),
                kind: ContentKind::SymbolTable,
                loaded: false,
            },
        ];

        let (space, synthetic) = AddrSpace::from_sections("t", bytes, &sections).expect("构造");
        assert!(synthetic, "节地址为 0 时必须报告用了合成地址");
        assert_eq!(space.segment_count(), 1, "只应映射 loaded 的节");
        assert!(
            space.segment_at(SYNTHETIC_BASE).is_some(),
            "合成地址应从 SYNTHETIC_BASE 开始"
        );
        assert!(
            space.segment_at(16).is_none(),
            "未加载的节不应出现在地址空间里"
        );
    }

    #[test]
    fn from_sections_uses_real_vaddr_when_present() {
        use bitflip_loader::object::{ContentKind, FileRange, Perms, Section};

        let bytes: Arc<[u8]> = Arc::from(vec![0x90u8; 64].into_boxed_slice());
        let sections = vec![Section {
            name: ".text".to_string(),
            vaddr: 0x401000,
            file: FileRange {
                offset: 0,
                size: 16,
            },
            perms: Perms {
                read: true,
                write: false,
                execute: true,
            },
            kind: ContentKind::Code,
            loaded: true,
        }];

        let (space, synthetic) = AddrSpace::from_sections("t", bytes, &sections).expect("构造");
        assert!(!synthetic, "节带真实 vaddr 时不应报告合成");
        assert!(
            space.segment_at(0x401000).is_some(),
            "应使用节自带的真实地址"
        );
    }

    #[test]
    fn from_sections_rejects_out_of_range_file_span() {
        use bitflip_loader::object::{ContentKind, FileRange, Perms, Section};

        let bytes: Arc<[u8]> = Arc::from(vec![0x90u8; 8].into_boxed_slice());
        let sections = vec![Section {
            name: ".text".to_string(),
            vaddr: 0,
            // 文件只有 8 字节，这里声称 64 字节
            file: FileRange {
                offset: 0,
                size: 64,
            },
            perms: Perms {
                read: true,
                write: false,
                execute: true,
            },
            kind: ContentKind::Code,
            loaded: true,
        }];

        let error = AddrSpace::from_sections("t", bytes, &sections).unwrap_err();
        assert!(
            matches!(error, AddrSpaceError::SourceOutOfRange { .. }),
            "越界的文件区间必须被拒绝，实际 {error:?}"
        );
    }

    #[test]
    fn zerofill_segment_reads_zero_and_has_no_file_lifetime() {
        let space = space_with_two_segments();
        assert_eq!(space.read_u8(0x2000), Some(0));
        assert_eq!(space.read_u8(0x20ff), Some(0));
        assert_eq!(space.read(0x2000, 0x100), Some(vec![0u8; 0x100]));
        let seg = space.segment_at(0x2000).expect("bss 段");
        assert_eq!(seg.file_len(), 0);
    }

    #[test]
    fn read_does_not_cross_segment_boundary() {
        let space = space_with_two_segments();
        // 段 A 只覆盖 [0x1000, 0x1010)：从 0x100e 读 4 字节必须失败，
        // 而不是把 0x1010 处的"段 B 之外的地址"拼进来
        assert_eq!(space.read(0x100e, 4), None);
        assert_eq!(space.read(0x100f, 1), Some(vec![15]));
    }

    #[test]
    fn read_window_stops_at_segment_end_instead_of_failing() {
        let space = space_with_two_segments();
        // 请求 64 字节，段内只剩 2 字节：返回 2 字节，让解码器自行判断截断
        let (bytes, end) = space.read_window(0x100e, 64).expect("窗口");
        assert_eq!(bytes, vec![14, 15]);
        assert_eq!(end, 0x1010);
    }

    #[test]
    fn segment_tail_beyond_file_size_reads_as_zero() {
        // vsize > filesz 是 .bss 的标准形态（ELF 的 p_memsz > p_filesz）
        let file: Vec<u8> = vec![0xaa, 0xbb];
        let segments = vec![segment(
            ".data",
            0x3000,
            8,
            Some((0, 2)),
            perms(true, true, false),
        )];
        let space = AddrSpace::new("t", Arc::from(file), &segments).expect("构造");
        assert_eq!(space.read_u8(0x3000), Some(0xaa));
        assert_eq!(space.read_u8(0x3001), Some(0xbb));
        // 文件内容之后的 6 字节是零填充
        assert_eq!(space.read_u8(0x3002), Some(0));
        assert_eq!(
            space.read(0x3000, 8),
            Some(vec![0xaa, 0xbb, 0, 0, 0, 0, 0, 0])
        );
    }

    #[test]
    fn rejects_file_range_beyond_buffer() {
        let file: Vec<u8> = vec![0u8; 16];
        let segments = vec![segment(
            ".text",
            0x1000,
            0x100,
            Some((8, 0x100)),
            perms(true, false, true),
        )];
        let err = AddrSpace::new("t", Arc::from(file), &segments).unwrap_err();
        match err {
            AddrSpaceError::SourceOutOfRange {
                base,
                len,
                available,
                ..
            } => {
                assert_eq!(base, 8);
                assert_eq!(len, 0x100);
                assert_eq!(available, 16);
            }
            other => panic!("期望 SourceOutOfRange，得到 {other:?}"),
        }
    }

    #[test]
    fn rejects_vaddr_overflow() {
        let segments = vec![segment(
            ".text",
            u64::MAX - 8,
            0x100,
            None,
            perms(true, false, true),
        )];
        let err = AddrSpace::new("t", Arc::from(Vec::new()), &segments).unwrap_err();
        assert!(matches!(err, AddrSpaceError::BadSegment { .. }));
    }

    #[test]
    fn zero_sized_segments_are_skipped() {
        let segments = vec![
            segment(".none", 0x1000, 0, None, perms(true, false, false)),
            segment(".text", 0x2000, 4, None, perms(true, false, true)),
        ];
        let space = AddrSpace::new("t", Arc::from(Vec::new()), &segments).expect("构造");
        assert_eq!(space.segment_count(), 1);
        assert_eq!(space.segment_at(0x1000).map(|s| s.name.as_str()), None);
    }

    #[test]
    fn index_records_starts_and_is_queryable() {
        let mut index = InsnIndex::new();
        assert!(index.is_empty());
        index.insert(0x1000, 1);
        index.insert(0x1001, 3);
        index.insert(0x1001, 9); // 重复：保留首条
        assert_eq!(index.len(), 2);
        assert_eq!(index.get(0x1000), Some(1));
        assert_eq!(index.get(0x1001), Some(3), "重复插入应保留首条");
        assert_eq!(index.get(0x1002), None);
        assert!(index.contains(0x1000));
    }

    #[test]
    fn index_is_sparse_and_supports_navigation() {
        let mut index = InsnIndex::new();
        // 只索引两处，中间 64KB 完全没记录 —— 这就是"稀疏"
        index.insert(0x1000, 2);
        index.insert(0x11000, 5);

        assert_eq!(index.next_at_or_after(0x1000), Some((0x1000, 2)));
        assert_eq!(index.next_at_or_after(0x1001), Some((0x11000, 5)));
        assert_eq!(index.next_at_or_after(0x11001), None);

        let within: Vec<(u64, u8)> = index.range(0x1000, 0x11000).collect();
        assert_eq!(within, vec![(0x1000, 2)]);
    }

    #[test]
    fn index_memory_estimate_stays_linear() {
        let mut index = InsnIndex::new();
        for i in 0..100_000u64 {
            index.insert(0x1000 + i * 4, 4);
        }
        assert_eq!(index.len(), 100_000);
        // 10 万条指令的索引应在个位数 MB —— 对照：物化 DecodedInsn 会到几十 MB 以上
        let bytes = index.estimated_bytes();
        assert!(
            bytes < 8 * 1024 * 1024,
            "10 万条指令的索引占用 {bytes} 字节，超出预期"
        );
    }

    #[test]
    fn index_merge_keeps_existing_entries() {
        let mut a = InsnIndex::new();
        a.insert(0x1000, 1);
        let mut b = InsnIndex::new();
        b.insert(0x1000, 9);
        b.insert(0x1001, 2);
        a.merge(&b);
        assert_eq!(a.get(0x1000), Some(1), "已有项不被覆盖");
        assert_eq!(a.get(0x1001), Some(2), "新项被合并进来");
    }

    #[test]
    fn executable_segments_filter() {
        let space = space_with_two_segments();
        let exec = space.executable_segments();
        assert_eq!(exec.len(), 1);
        assert_eq!(exec[0].name, ".text");
    }

    #[test]
    fn overlapping_segments_resolve_deterministically() {
        // 畸形输入可能给出重叠段：必须确定性地选一个，而不是随机
        let segments = vec![
            segment(".a", 0x1000, 0x100, None, perms(true, false, false)),
            segment(".b", 0x1080, 0x100, None, perms(true, true, false)),
        ];
        let space = AddrSpace::new("t", Arc::from(Vec::new()), &segments).expect("构造");
        // 排序后取地址最低的
        assert_eq!(
            space.segment_at(0x1090).map(|s| s.name.as_str()),
            Some(".a")
        );
    }

    #[test]
    fn read_at_exact_segment_end_is_out_of_range() {
        let space = space_with_two_segments();
        let seg = space.segment_at(0x1000).expect("段");
        assert!(!seg.contains(seg.end()), "段尾地址不含在内");
        assert_eq!(space.read_u8(0x1010), None);
    }

    #[test]
    fn zero_length_read_is_empty_not_none() {
        let space = space_with_two_segments();
        // 读 0 字节是合法的空操作；但段外地址仍然拒绝
        assert_eq!(space.read(0x1000, 0), Some(Vec::new()));
        assert_eq!(space.read(0x0fff, 0), None);
    }
}
