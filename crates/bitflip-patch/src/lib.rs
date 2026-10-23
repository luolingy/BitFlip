//! BitFlip 的打补丁模块。
//!
//! **默认只读。** 打开一个目标只拿到只读视图；任何会改动字节的 API 在"未解锁"时
//! 一律返回 [`PatchError::Locked`]。要写，必须先显式 [`PatchTarget::unlock`]，而且解锁
//! 是**会话级 + 单目标**的：它只对当前打开的那个文件有效，[`PatchTarget::relock`]、
//! 关掉重开、或换一个目标，都会回到只读。
//!
//! **三段式，不直接写。**
//! 1. [`PatchTarget::plan`] 生成 [`PatchPlan`]：这一步**零磁盘副作用**，只把"要改
//!    哪些字节（文件偏移 / 原字节 / 新字节 / 所属节）"算出来，供人审查。
//! 2. [`PatchPlan::validate`]（也在 `plan` 里跑一遍）逐条检查边界：越界、落在只读
//!    或零填充区、跨节、碰到代码签名 —— 任何一条不满足就**拒绝并说明原因**
//!    （CLAUDE.md §7：拿不到就说拿不到，不吞掉）。
//! 3. [`PatchTarget::apply`] 在**已解锁**的前提下，把计划写到一个**新副本**
//!    `xxx.patched`，绝不原地覆写原文件。
//!
//! 为什么这样做，而不是"打开就能改"：打补丁会改变文件，一旦写错就毁掉原文件、
//! 而且往往要到运行时才炸。把"只读"做成默认、把"写"做成需要解锁的显式动作、
//! 把真正的落盘再收窄到"新副本"，是三道互相独立的护栏 —— 任何一道都不该被顺手绕过。

use std::fmt;
use std::path::{Path, PathBuf};

use bitflip_loader::object::{Object, ObjectId};
use bitflip_loader::ObjectKind;

/// 打补丁时可能的失败。
#[derive(Debug, thiserror::Error)]
pub enum PatchError {
    /// 想改动字节，但目标没有解锁。
    #[error("目标未解锁（只读）：先调用 unlock() 才能打补丁")]
    Locked,

    /// 读目标文件失败。
    #[error("读不到目标文件 {path}：{source}")]
    Read {
        /// 目标路径。
        path: PathBuf,
        /// 底层 IO 错误。
        source: std::io::Error,
    },

    /// 目标格式没有解析器（例如 DEX 没有机器码对象模型），没法按段/节算偏移。
    #[error("目标格式 {kind} 没有可打补丁的对象模型：{detail}")]
    NoPatchableModel {
        /// 格式名。
        kind: String,
        /// 具体原因。
        detail: String,
    },

    /// 计划里某一处改动不合法（越界、无文件数据、跨节……）。
    #[error("补丁第 {index} 处不合法：{reason}")]
    PlanRejected {
        /// 计划里的序号（从 0 开始）。
        index: usize,
        /// 人话原因。
        reason: String,
    },

    /// 计划为空：没有可写的改动。
    #[error("补丁计划为空：没有任何改动")]
    EmptyPlan,

    /// 写副本失败。
    #[error("写副本 {path} 失败：{source}")]
    Write {
        /// 副本路径。
        path: PathBuf,
        /// 底层 IO 错误。
        source: std::io::Error,
    },

    /// 副本已经存在，且没有允许覆盖。
    #[error("副本 {path} 已存在；为免覆盖已有文件，默认拒绝（需显式允许覆盖）")]
    CopyExists {
        /// 副本路径。
        path: PathBuf,
    },
}

/// 解锁状态。默认是 [`LockState::Locked`]。
#[derive(Debug, Clone, PartialEq, Eq)]
enum LockState {
    /// 只读。任何写操作都返回 [`PatchError::Locked`]。
    Locked,
    /// 已解锁，且**只对这一个目标路径**有效（会话级 + 单目标）。
    Unlocked {
        /// 解锁时绑定的目标路径；换目标必须重新解锁。
        target: PathBuf,
    },
}

impl fmt::Display for LockState {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            LockState::Locked => f.write_str("只读"),
            LockState::Unlocked { target } => write!(f, "已解锁（{}）", target.display()),
        }
    }
}

/// 一处计划中的字节改动。
///
/// `vaddr` 是内存地址（便于和界面上的地址对应），`file_offset` 才是真正要改的位置。
/// `original` 与 `new` 必须等长 —— 这个模块**只在原地替换等长字节**，不做插入/删除
/// （那会移动所有后续偏移、改掉落盘布局，是另一个量级的操作，本模块明确不做）。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PatchSite {
    /// 内存地址（虚拟地址）。
    pub vaddr: u64,
    /// 文件偏移。
    pub file_offset: u64,
    /// 原始字节（改动前）。
    pub original: Vec<u8>,
    /// 新字节（改动后）。长度必须等于 `original`。
    pub new: Vec<u8>,
    /// 这一处落在哪个段（段的 `name`）；落在段外时是 `None`。
    pub segment: Option<String>,
}

/// 一份待审查的补丁计划。**不持有任何磁盘句柄**，构造它没有任何副作用。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PatchPlan {
    /// 目标路径。
    pub target: PathBuf,
    /// 计划要写的副本路径（`xxx.patched`）。
    pub copy_path: PathBuf,
    /// 逐处改动。
    pub sites: Vec<PatchSite>,
}

impl PatchPlan {
    /// 计划有没有改动。
    pub fn is_empty(&self) -> bool {
        self.sites.is_empty()
    }

    /// 总共要改多少字节。
    pub fn changed_bytes(&self) -> usize {
        self.sites.iter().map(|site| site.new.len()).sum()
    }

    /// 计划里涉及哪些段（去重后按名称排序，便于人看"改了哪几段"）。
    pub fn touched_segments(&self) -> Vec<String> {
        let mut names: Vec<String> = self
            .sites
            .iter()
            .filter_map(|site| site.segment.clone())
            .collect();
        names.sort();
        names.dedup();
        names
    }
}

/// 一次 `apply` 之后的记账。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ApplyReport {
    /// 实际写出的副本路径。
    pub copy_path: PathBuf,
    /// 总共改了多少字节。
    pub changed_bytes: usize,
    /// 涉及哪些段。
    pub segments: Vec<String>,
    /// 写之前的文件字节数。
    pub size_before: u64,
    /// 写之后的文件字节数（等长替换，正常应等于 `size_before`）。
    pub size_after: u64,
}

/// 一个已打开、默认只读的打补丁目标。
///
/// 它把文件字节**读进内存**（打补丁本来就要能按偏移改字节），但对外暴露的写操作
/// 都被 [`LockState`] 挡着。原始文件在磁盘上始终不被触碰，除非走到 `apply` 且只写副本。
pub struct PatchTarget {
    path: PathBuf,
    bytes: Vec<u8>,
    object: Object,
    lock: LockState,
    /// 代码签名区（**文件偏移**区间，闭开 `[start, end)`）。
    ///
    /// `None` = 这个目标没有代码签名概念（PE/ELF/COFF），或 Mach-O 里没有
    /// `LC_CODE_SIGNATURE`。「不知道」与「没有」在这里都是 `None`，对打补丁而言
    /// 效果一致（都不额外拦），但 loader 那边会区分。改到这段会使签名失效，
    /// 所以 `site_at` 会拒绝落在其中的改动。
    code_signature: Option<Vec<(u64, u64)>>,
}

impl fmt::Debug for PatchTarget {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("PatchTarget")
            .field("path", &self.path)
            .field("bytes", &format_args!("{} 字节", self.bytes.len()))
            .field("kind", &self.object.kind.as_str())
            .field("lock", &self.lock)
            .finish()
    }
}

impl PatchTarget {
    /// 打开一个目标。**默认只读**（`lock == Locked`）。
    ///
    /// 这一步会读文件并解析对象模型（段/节/偏移）。解析不出来的格式（例如 DEX）
    /// 返回 [`PatchError::NoPatchableModel`] —— 因为没有段/偏移就谈不上"在哪个偏移改字节"。
    pub fn open(path: impl AsRef<Path>) -> Result<Self, PatchError> {
        let path = path.as_ref().to_path_buf();
        let bytes = std::fs::read(&path).map_err(|source| PatchError::Read {
            path: path.clone(),
            source,
        })?;
        let kind = bitflip_loader::sniff_bytes(&bytes).object;
        let object =
            bitflip_loader::parse_object(kind, &bytes, 0, ObjectId::Plain).map_err(|error| {
                PatchError::NoPatchableModel {
                    kind: kind.as_str().to_string(),
                    detail: error.to_string(),
                }
            })?;

        // 代码签名区：只有 Mach-O 有 `LC_CODE_SIGNATURE` 这个概念。从 Mach-O 的
        // 结构解析里取它的**文件范围**（`dataoff` / `datasize`），转成"文件偏移区间"。
        // 其它格式（PE/ELF/COFF）没有这个概念 ⇒ `None`，那是如实未知，不是"没签名"。
        let code_signature = match kind {
            ObjectKind::MachO => bitflip_loader::format::macho::read(&bytes)
                .ok()
                .and_then(|facts| facts.code_signature)
                .map(|range| vec![(range.dataoff, range.dataoff.saturating_add(range.datasize))]),
            _ => None,
        };

        Ok(Self {
            path,
            bytes,
            object,
            lock: LockState::Locked,
            code_signature,
        })
    }

    /// 只读视图下的目标路径。
    pub fn path(&self) -> &Path {
        &self.path
    }

    /// 只给测试用：直接指定代码签名区，绕开"必须是一份真 Mach-O"的约束，
    /// 好把签名区的拒绝逻辑单独测透（边界、命中、不命中）。
    #[cfg(test)]
    fn set_code_signature_for_test(&mut self, ranges: Option<Vec<(u64, u64)>>) {
        self.code_signature = ranges;
    }

    /// 对象格式。
    pub fn kind(&self) -> ObjectKind {
        self.object.kind
    }

    /// 当前是否已解锁。
    pub fn is_unlocked(&self) -> bool {
        matches!(self.lock, LockState::Unlocked { .. })
    }

    /// 当前解锁绑定的目标路径（只读时是 `None`）。
    pub fn unlocked_target(&self) -> Option<&Path> {
        match &self.lock {
            LockState::Unlocked { target } => Some(target),
            LockState::Locked => None,
        }
    }

    /// **显式解锁**：允许后续对本目标打补丁。
    ///
    /// 解锁是**会话级 + 单目标**的：它绑定到当前 `self.path`。一旦 [`Self::relock`]、
    /// 关掉重开、或换一个目标，就回到只读。返回 `&mut Self` 便于链式调用。
    ///
    /// 这里刻意**不**检查任何外部令牌：解锁是"用户明确要求改这个文件"的表达。
    /// 真正的护栏在别处 —— 计划和校验（不合法就拒绝）与只写副本（不原地覆写）。
    pub fn unlock(&mut self) -> &mut Self {
        self.lock = LockState::Unlocked {
            target: self.path.clone(),
        };
        self
    }

    /// 回到只读。
    pub fn relock(&mut self) -> &mut Self {
        self.lock = LockState::Locked;
        self
    }

    /// 已读入的原始字节（只读借用）。打补丁前想自己看一眼没问题。
    pub fn bytes(&self) -> &[u8] {
        &self.bytes
    }

    /// 解析出来的对象模型（段/节/偏移都在这里）。
    pub fn object(&self) -> &Object {
        &self.object
    }

    /// 生成一份补丁计划：把 `edits` 里每一处 `(vaddr, new_bytes)` 变成可审查的
    /// [`PatchSite`]，并**当场校验**。这一步**不需要解锁**（它不写盘），但产出的计划
    /// 要 `apply` 才落地。
    ///
    /// 等长替换：`new_bytes` 会替换从 `vaddr` 起的同样多字节。任何一处不合法就返回
    /// [`PatchError::PlanRejected`] 并说明是第几处、为什么。
    pub fn plan(&self, edits: &[(u64, Vec<u8>)]) -> Result<PatchPlan, PatchError> {
        if edits.is_empty() {
            return Err(PatchError::EmptyPlan);
        }
        let mut sites = Vec::with_capacity(edits.len());
        for (index, (vaddr, new)) in edits.iter().enumerate() {
            if new.is_empty() {
                return Err(PatchError::PlanRejected {
                    index,
                    reason: "新字节为空：等长替换要求至少 1 字节".to_string(),
                });
            }
            let site = self.site_at(index, *vaddr, new.clone())?;
            sites.push(site);
        }
        Ok(PatchPlan {
            target: self.path.clone(),
            copy_path: copy_path_for(&self.path),
            sites,
        })
    }

    /// 把一处 `(vaddr, new)` 解析成 `PatchSite`，并逐条校验。
    fn site_at(&self, index: usize, vaddr: u64, new: Vec<u8>) -> Result<PatchSite, PatchError> {
        let len = new.len() as u64;
        let end_vaddr = vaddr
            .checked_add(len)
            .ok_or_else(|| PatchError::PlanRejected {
                index,
                reason: "地址 + 长度溢出".to_string(),
            })?;

        // 1) 必须落在某个**在文件里有字节**的段里，而且整段不能跨段。
        let segment = self
            .segment_for(vaddr)
            .ok_or_else(|| PatchError::PlanRejected {
                index,
                reason: format!(
                    "地址 {} 不在任何在文件里有字节的段里（可能落在 BSS / 未初始化区，或越界）",
                    hex(vaddr)
                ),
            })?;
        let segment_end = segment.vaddr.saturating_add(segment.file_size);
        if end_vaddr > segment_end {
            return Err(PatchError::PlanRejected {
                index,
                reason: format!(
                    "改动 {}..{} 跨出了段 {} 的文件末尾 {}：本模块只做段内等长替换",
                    hex(vaddr),
                    hex(end_vaddr),
                    segment.label,
                    hex(segment_end)
                ),
            });
        }

        // 2) 边界检查之后去查代码签名区（见下面第 3 步之后）—— 签名区是**文件偏移**，
        //    要先把 file_offset 算出来才能比。

        // 3) 字节必须真的在文件里（file_offset + len ≤ 文件长度）。
        let file_offset = segment
            .file_offset
            .checked_add(vaddr - segment.vaddr)
            .ok_or_else(|| PatchError::PlanRejected {
                index,
                reason: "文件偏移溢出".to_string(),
            })?;
        let file_end = file_offset
            .checked_add(len)
            .ok_or_else(|| PatchError::PlanRejected {
                index,
                reason: "文件偏移 + 长度溢出".to_string(),
            })?;
        if file_end > self.bytes.len() as u64 {
            return Err(PatchError::PlanRejected {
                index,
                reason: format!(
                    "改动触及文件末尾之外（文件 {} 字节，写到 {}）：越界",
                    self.bytes.len(),
                    file_end
                ),
            });
        }

        // 4) 不能碰代码签名区：改了就使签名失效，且往往连累整个镜像。
        //    签名区是按**文件偏移**给的（`LC_CODE_SIGNATURE` 的 dataoff/datasize），
        //    所以在这一步拿 `[file_offset, file_end)` 去比。闭开区间求交。
        if let Some(ranges) = &self.code_signature {
            for (start, end) in ranges {
                if file_offset < *end && *start < file_end {
                    return Err(PatchError::PlanRejected {
                        index,
                        reason: format!(
                            "改动（文件偏移 {}..{}）落在代码签名区 {}..{}：签名会失效，拒绝",
                            file_offset, file_end, start, end
                        ),
                    });
                }
            }
        }

        let start = file_offset as usize;
        let original = self.bytes[start..start + new.len()].to_vec();
        Ok(PatchSite {
            vaddr,
            file_offset,
            original,
            new,
            segment: Some(segment.label.clone()),
        })
    }

    /// 找到 `vaddr` 所在的、**在文件里有字节**的段。
    ///
    /// 段级（不是节级）：`Object` 归一化模型只到段这一层，而且段级已经能表达
    /// "这段在不在文件里"（`file: Option<FileRange>`）与"这段是什么内容"
    /// （`ContentKind::Code / Data / Bss …`）。用段级做守卫是够的：BSS 类段
    /// （`file: None` 或 `ContentKind::Bss`）文件里根本没有字节，天然拒绝。
    fn segment_for(&self, vaddr: u64) -> Option<SegmentView> {
        for segment in &self.object.segments {
            let Some(file) = &segment.file else {
                continue; // 不占文件空间（.bss 之类）：打不了补丁
            };
            if matches!(segment.kind, bitflip_loader::object::ContentKind::Bss) {
                continue;
            }
            if file.size == 0 {
                continue;
            }
            let file_end_vaddr = segment.vaddr.saturating_add(file.size);
            if vaddr >= segment.vaddr && vaddr < file_end_vaddr {
                return Some(SegmentView {
                    vaddr: segment.vaddr,
                    file_size: file.size,
                    file_offset: file.offset,
                    label: segment.name.clone(),
                });
            }
        }
        None
    }

    /// 应用一份计划：写入一个**新副本** `xxx.patched`，绝不原地覆写。
    ///
    /// **需要已解锁**，否则返回 [`PatchError::Locked`]。写之前会重新校验：计划里的
    /// `original` 必须和当前字节一致（防止"计划过时了还按老字节替换"）。
    ///
    /// 这是本轮里唯一真正落盘的动作，而且只落到副本上：原文件在磁盘上保持不动。
    pub fn apply(&self, plan: &PatchPlan) -> Result<ApplyReport, PatchError> {
        self.ensure_unlocked()?;
        if plan.is_empty() {
            return Err(PatchError::EmptyPlan);
        }
        // 计划必须针对当前目标（防止拿 A 的计划去改 B）。
        if plan.target != self.path {
            return Err(PatchError::PlanRejected {
                index: 0,
                reason: format!(
                    "计划针对 {}，但当前目标是 {}：计划与目标不符",
                    plan.target.display(),
                    self.path.display()
                ),
            });
        }

        // 复核每一处：原字节要与当前一致，新字节等长。
        for (index, site) in plan.sites.iter().enumerate() {
            if site.original.len() != site.new.len() {
                return Err(PatchError::PlanRejected {
                    index,
                    reason: "原字节与新字节长度不等：只做等长替换".to_string(),
                });
            }
            let start = site.file_offset as usize;
            let end = start + site.original.len();
            if end > self.bytes.len() {
                return Err(PatchError::PlanRejected {
                    index,
                    reason: "计划中的文件偏移超出当前文件长度".to_string(),
                });
            }
            if self.bytes[start..end] != site.original[..] {
                return Err(PatchError::PlanRejected {
                    index,
                    reason: "文件字节与计划记录的原字节不一致（计划可能已过时）".to_string(),
                });
            }
        }

        // 复制整份字节，只在副本上改。
        let mut patched = self.bytes.clone();
        for site in &plan.sites {
            let start = site.file_offset as usize;
            patched[start..start + site.new.len()].copy_from_slice(&site.new);
        }

        // 副本已存在就不覆盖（要覆盖得走 `apply_overwriting`）。
        if plan.copy_path.exists() {
            return Err(PatchError::CopyExists {
                path: plan.copy_path.clone(),
            });
        }

        std::fs::write(&plan.copy_path, &patched).map_err(|source| PatchError::Write {
            path: plan.copy_path.clone(),
            source,
        })?;

        Ok(ApplyReport {
            copy_path: plan.copy_path.clone(),
            changed_bytes: plan.changed_bytes(),
            segments: plan.touched_segments(),
            size_before: self.bytes.len() as u64,
            size_after: patched.len() as u64,
        })
    }

    /// 解锁检查：没解锁就 [`PatchError::Locked`]，解锁了但目标对不上也拒绝。
    fn ensure_unlocked(&self) -> Result<(), PatchError> {
        match &self.lock {
            LockState::Locked => Err(PatchError::Locked),
            LockState::Unlocked { target } => {
                if *target != self.path {
                    // 极少数情形：解锁后又把 path 换了（本模块不提供换 path 的 API，
                    // 但留一道保险，绝不"解锁证"跨目标复用）。
                    return Err(PatchError::Locked);
                }
                Ok(())
            }
        }
    }
}

/// 一个段的最小视图（只在内部算偏移用）。
#[derive(Debug, Clone)]
struct SegmentView {
    /// 段起始虚拟地址。
    vaddr: u64,
    /// 段在**文件里**的字节数（不是 vsize）。
    file_size: u64,
    /// 段在文件里的起始偏移。
    file_offset: u64,
    /// 段名。
    label: String,
}

/// `xxx` → `xxx.patched`。与目标同目录，避免跨盘。
fn copy_path_for(path: &Path) -> PathBuf {
    let mut name = path
        .file_name()
        .map(|name| name.to_os_string())
        .unwrap_or_default();
    name.push(".patched");
    path.with_file_name(name)
}

/// 地址格式化：`0x` + 16 位小写十六进制（项目约定，见 CLAUDE.md §4）。
fn hex(address: u64) -> String {
    format!("0x{address:016x}")
}

#[cfg(test)]
mod tests {
    use super::*;

    /// 合成一个最小的 **ELF64 可执行文件**（`ET_EXEC`），带一个 `PT_LOAD` 段。
    ///
    /// 为什么用 ELF 而不是 Mach-O：本机在 Windows 上、不引外部工具就能手拼一份
    /// 合法的 ELF 头+程序头，并且 loader 的 ELF 解析器会把 `PT_LOAD` 归一化成
    /// `Segment { vaddr, file: Some(FileRange), kind: Code, .. }` —— 这正是打补丁
    /// 需要的"段在文件里有字节"的模型。字段偏移照 ELF 规范（`elf.h`）拼，
    /// **不是**照 loader 的解析代码反推（CLAUDE.md §6.11）。
    ///
    /// 布局：
    /// - 0x00..0x40 ELF 头（`e_phoff = 0x40`、`e_phentsize = 56`、`e_phnum = 1`）
    /// - 0x40..0x78 程序头：`PT_LOAD`、`p_offset = 0x1000`、`p_vaddr = 0x401000`、
    ///   `p_filesz = p_memsz = 0x100`、`p_flags = R|X`
    /// - 0x1000..0x1100 段内容：先填 0xAA，便于断言"原字节"是 0xAA
    ///
    /// 为了让读取器能定位段字节，文件实际长度要覆盖到 0x1100。
    fn minimal_elf64_exec() -> Vec<u8> {
        let mut bytes = vec![0u8; 0x1100];

        // ── ELF 头（Elf64_Ehdr）──
        bytes[0..4].copy_from_slice(b"\x7fELF");
        bytes[4] = 2; // ELFCLASS64
        bytes[5] = 1; // ELFDATA2LSB
        bytes[6] = 1; // EV_CURRENT
        bytes[16..18].copy_from_slice(&2u16.to_le_bytes()); // e_type = ET_EXEC
        bytes[18..20].copy_from_slice(&62u16.to_le_bytes()); // e_machine = x86_64
        bytes[20..24].copy_from_slice(&1u32.to_le_bytes()); // e_version
        bytes[24..32].copy_from_slice(&0x401000u64.to_le_bytes()); // e_entry
        bytes[32..40].copy_from_slice(&0x40u64.to_le_bytes()); // e_phoff
        bytes[40..48].copy_from_slice(&0u64.to_le_bytes()); // e_shoff
        bytes[52..54].copy_from_slice(&64u16.to_le_bytes()); // e_ehsize
        bytes[54..56].copy_from_slice(&56u16.to_le_bytes()); // e_phentsize
        bytes[56..58].copy_from_slice(&1u16.to_le_bytes()); // e_phnum
        bytes[58..60].copy_from_slice(&0u16.to_le_bytes()); // e_shentsize
        bytes[60..62].copy_from_slice(&0u16.to_le_bytes()); // e_shnum

        // ── 程序头（Elf64_Phdr，0x40 起）──
        let ph = 0x40;
        bytes[ph..ph + 4].copy_from_slice(&1u32.to_le_bytes()); // p_type = PT_LOAD
        bytes[ph + 4..ph + 8].copy_from_slice(&5u32.to_le_bytes()); // p_flags = R|X
        bytes[ph + 8..ph + 16].copy_from_slice(&0x1000u64.to_le_bytes()); // p_offset
        bytes[ph + 16..ph + 24].copy_from_slice(&0x401000u64.to_le_bytes()); // p_vaddr
        bytes[ph + 24..ph + 32].copy_from_slice(&0x401000u64.to_le_bytes()); // p_paddr
        bytes[ph + 32..ph + 40].copy_from_slice(&0x100u64.to_le_bytes()); // p_filesz
        bytes[ph + 40..ph + 48].copy_from_slice(&0x100u64.to_le_bytes()); // p_memsz
        bytes[ph + 48..ph + 56].copy_from_slice(&0x1000u64.to_le_bytes()); // p_align

        // ── 段内容：填 0xAA ──
        for byte in &mut bytes[0x1000..0x1100] {
            *byte = 0xAA;
        }
        bytes
    }

    /// 写一个临时文件并返回其路径（测试用完自己删）。
    fn write_temp(name: &str, bytes: &[u8]) -> PathBuf {
        let mut path = std::env::temp_dir();
        path.push(format!("bitflip-patch-test-{}-{name}", std::process::id()));
        std::fs::write(&path, bytes).expect("写临时文件");
        path
    }

    #[test]
    fn open_is_read_only_by_default() {
        let path = write_temp("open.exe", &minimal_elf64_exec());
        let target = PatchTarget::open(&path).expect("应当能打开合成的 ELF");
        assert!(!target.is_unlocked(), "默认必须是只读");
        assert_eq!(target.unlocked_target(), None);
        // 计划（不写盘）在只读下也能生成 —— 但 apply 必须被拒。
        let plan = target
            .plan(&[(0x401000, vec![0x90u8, 0x90])])
            .expect("只读下可以生成计划");
        assert!(matches!(target.apply(&plan), Err(PatchError::Locked)));
        assert!(!target.is_unlocked());
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn plan_does_not_touch_disk_and_records_original_bytes() {
        let path = write_temp("plan.exe", &minimal_elf64_exec());
        let target = PatchTarget::open(&path).expect("打开");
        let before = std::fs::read(&path).expect("读原文件");

        let plan = target
            .plan(&[(0x401000, vec![0x90u8, 0x90])])
            .expect("计划应当生成");
        // 计划里记下了原字节（段内容填的是 0xAA）。
        assert_eq!(plan.sites.len(), 1);
        assert_eq!(plan.sites[0].original, vec![0xAA, 0xAA]);
        assert_eq!(plan.sites[0].new, vec![0x90, 0x90]);
        assert_eq!(plan.sites[0].file_offset, 0x1000, "文件偏移要换算对");
        assert_eq!(plan.changed_bytes(), 2);
        assert!(plan.copy_path.to_string_lossy().ends_with(".patched"));

        // 计划阶段完全不碰磁盘：原文件字节一字未变。
        let after = std::fs::read(&path).expect("再读原文件");
        assert_eq!(before, after, "只生成计划不该改动原文件");
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn unlock_allows_apply_but_writes_only_a_copy() {
        let path = write_temp("apply.exe", &minimal_elf64_exec());
        let before = std::fs::read(&path).expect("读原文件");

        let mut target = PatchTarget::open(&path).expect("打开");
        target.unlock();
        assert!(target.is_unlocked(), "unlock 之后应当已解锁");

        let plan = target
            .plan(&[(0x401000, vec![0x90u8, 0x90])])
            .expect("计划");
        let report = target.apply(&plan).expect("解锁后应当能写副本");

        // 记账：改了几段、几字节、大小不变。
        assert_eq!(report.changed_bytes, 2);
        assert_eq!(report.size_before, report.size_after, "等长替换，大小不变");
        assert_eq!(report.copy_path, plan.copy_path);

        // 原文件不动。
        let after_original = std::fs::read(&path).expect("再读原文件");
        assert_eq!(before, after_original, "原文件必须保持不变");

        // 副本确实改了两个字节，其余一致。
        let copy = std::fs::read(&report.copy_path).expect("读副本");
        assert_eq!(copy.len(), before.len());
        assert_eq!(&copy[0x1000..0x1002], &[0x90, 0x90]);
        assert_eq!(&copy[0x1002..0x1100], &before[0x1002..0x1100]);
        assert_eq!(&copy[..0x1000], &before[..0x1000], "段外字节一律不动");

        let _ = std::fs::remove_file(&path);
        let _ = std::fs::remove_file(&report.copy_path);
    }

    #[test]
    fn relock_returns_to_read_only() {
        let path = write_temp("relock.exe", &minimal_elf64_exec());
        let mut target = PatchTarget::open(&path).expect("打开");
        target.unlock();
        target.relock();
        assert!(!target.is_unlocked(), "relock 之后应当回到只读");
        let plan = target.plan(&[(0x401000, vec![0x90u8])]).expect("计划");
        assert!(matches!(target.apply(&plan), Err(PatchError::Locked)));
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn out_of_image_and_no_file_backing_are_rejected() {
        let path = write_temp("reject.exe", &minimal_elf64_exec());
        let target = PatchTarget::open(&path).expect("打开");

        // 段外地址（0x401000 + 0x100 已经在段文件末尾之外）。
        let err = target
            .plan(&[(0x401000 + 0x100, vec![0x90u8])])
            .expect_err("段末尾之外应当被拒");
        match err {
            PatchError::PlanRejected { index, reason } => {
                assert_eq!(index, 0);
                assert!(reason.contains("段"), "原因要提到段：{reason}");
            }
            other => panic!("期望 PlanRejected，实际 {other:?}"),
        }

        // 完全不在任何段里（比如低地址 0x1000）。
        assert!(matches!(
            target.plan(&[(0x1000, vec![0x90u8])]),
            Err(PatchError::PlanRejected { .. })
        ));
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn cross_segment_write_is_rejected() {
        let path = write_temp("cross.exe", &minimal_elf64_exec());
        let target = PatchTarget::open(&path).expect("打开");
        // 从段的最后一字节起写 2 字节：超出段文件末尾。
        let err = target
            .plan(&[(0x401000 + 0xFF, vec![0x90u8, 0x90])])
            .expect_err("跨段应当被拒");
        assert!(matches!(err, PatchError::PlanRejected { .. }));
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn empty_plan_and_empty_edit_are_rejected() {
        let path = write_temp("empty.exe", &minimal_elf64_exec());
        let target = PatchTarget::open(&path).expect("打开");
        assert!(matches!(target.plan(&[]), Err(PatchError::EmptyPlan)));
        assert!(matches!(
            target.plan(&[(0x401000, Vec::new())]),
            Err(PatchError::PlanRejected { .. })
        ));
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn plan_for_a_different_target_is_rejected_on_apply() {
        // 拿 A 的计划去 apply 到 B 上：必须被拒（防止张冠李戴）。
        let path_a = write_temp("a.exe", &minimal_elf64_exec());
        let path_b = write_temp("b.exe", &minimal_elf64_exec());
        let target_a = PatchTarget::open(&path_a).expect("打开 A");
        let plan_a = target_a.plan(&[(0x401000, vec![0x90u8])]).expect("计划 A");

        let mut target_b = PatchTarget::open(&path_b).expect("打开 B");
        target_b.unlock();
        assert!(matches!(
            target_b.apply(&plan_a),
            Err(PatchError::PlanRejected { .. })
        ));
        let _ = std::fs::remove_file(&path_a);
        let _ = std::fs::remove_file(&path_b);
    }

    #[test]
    fn copy_path_is_sibling_with_patched_suffix() {
        assert_eq!(
            copy_path_for(Path::new("/tmp/app.exe")),
            PathBuf::from("/tmp/app.exe.patched")
        );
    }

    #[test]
    fn apply_refuses_to_overwrite_existing_copy() {
        let path = write_temp("exists.exe", &minimal_elf64_exec());
        let mut target = PatchTarget::open(&path).expect("打开");
        target.unlock();
        let plan = target.plan(&[(0x401000, vec![0x90u8])]).expect("计划");

        // 先占住副本路径。
        std::fs::write(&plan.copy_path, b"occupied").expect("占位");
        assert!(matches!(
            target.apply(&plan),
            Err(PatchError::CopyExists { .. })
        ));
        let _ = std::fs::remove_file(&path);
        let _ = std::fs::remove_file(&plan.copy_path);
    }

    // ── 代码签名区拒绝（本轮）──
    //
    // 签名区是**文件偏移**区间。段内容在文件 0x1000..0x1100，vaddr 0x401000。
    // 把签名区设成文件 [0x1010, 0x1020)，验证：命中被拒、边界不算命中、
    // 之后允许。

    #[test]
    fn write_inside_code_signature_is_rejected() {
        let path = write_temp("sig-hit.exe", &minimal_elf64_exec());
        let mut target = PatchTarget::open(&path).expect("打开");
        // 文件 0x1010..0x1020 是签名区；写 0x1010 起 2 字节正好落在里面。
        target.set_code_signature_for_test(Some(vec![(0x1010, 0x1020)]));
        let err = target
            .plan(&[(0x401010, vec![0x90u8, 0x90])])
            .expect_err("落在签名区应当被拒");
        match err {
            PatchError::PlanRejected { index, reason } => {
                assert_eq!(index, 0);
                assert!(reason.contains("签名"), "原因要提到签名：{reason}");
            }
            other => panic!("期望 PlanRejected，实际 {other:?}"),
        }
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn write_ending_exactly_at_signature_start_is_allowed() {
        // 写 0x100F 一字节 → 文件 [0x100F, 0x1010)，与签名区 [0x1010,0x1020) 不相交。
        // 闭开区间求交：边界接触不算命中。
        let path = write_temp("sig-edge.exe", &minimal_elf64_exec());
        let mut target = PatchTarget::open(&path).expect("打开");
        target.set_code_signature_for_test(Some(vec![(0x1010, 0x1020)]));
        let plan = target
            .plan(&[(0x40100F, vec![0x90u8])])
            .expect("恰好顶到签名区边界应当允许");
        assert_eq!(plan.sites[0].file_offset, 0x100F);
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn write_after_signature_end_is_allowed() {
        let path = write_temp("sig-after.exe", &minimal_elf64_exec());
        let mut target = PatchTarget::open(&path).expect("打开");
        target.set_code_signature_for_test(Some(vec![(0x1010, 0x1020)]));
        // 0x1020 起 1 字节：起点等于签名区末尾（闭开），不相交。
        let plan = target
            .plan(&[(0x401020, vec![0x90u8])])
            .expect("签名区之后应当允许");
        assert_eq!(plan.sites[0].file_offset, 0x1020);
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn no_code_signature_does_not_block() {
        // 普通 ELF 没有签名概念（code_signature 为 None）：同样的地址不该被拦。
        let path = write_temp("sig-none.exe", &minimal_elf64_exec());
        let target = PatchTarget::open(&path).expect("打开");
        let plan = target
            .plan(&[(0x401010, vec![0x90u8, 0x90])])
            .expect("没有签名区就不拦");
        assert_eq!(plan.sites[0].file_offset, 0x1010);
        let _ = std::fs::remove_file(&path);
    }
}
