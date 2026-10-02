//! 容器与对象格式的解析层。
//!
//! 三层抽象（见 `docs/ARCHITECTURE.md` §3）：
//!
//! - **容器（[`ContainerKind`]）**：一个文件里可能装着多个对象 —— 归档（ar / MSVC `.lib`）、
//!   fat/universal。M0–M9 实现 ar 与 `.lib`，fat 只识别（解析推迟到 M10）。
//! - **对象（[`ObjectKind`]）**：可分析的基本单位 —— PE、COFF、ELF、Mach-O、raw。
//! - **架构（[`bitflip_arch::ArchSpec`]）**：由格式的 machine 字段映射得到。
//!
//! 本阶段（M0）实现的是**嗅探**：只读文件头与容器结构，给出可验证的识别结论，
//! 不做完整解析（段/节/导入导出/符号在 M1）。做不到的地方明确记入 `notes`，
//! 不猜、不留空白解释。

mod sniff;

use bitflip_arch::{ArchSpec, Endian};
use thiserror::Error;

pub use sniff::{sniff_bytes, sniff_file, SNIFF_WINDOW};

/// 解析层错误。
#[derive(Debug, Error)]
pub enum LoaderError {
    /// 读取目标文件失败。
    #[error("读取目标失败 {path}: {source}")]
    Io {
        /// 目标路径。
        path: String,
        /// 底层 IO 错误。
        #[source]
        source: std::io::Error,
    },
    /// 目标是目录（例如 macOS `.app` bundle）。
    #[error(
        "目标是目录而不是文件: {0} —— .app bundle 之类的容器解析排期在 M10（见 docs/PLAN.md）"
    )]
    IsDirectory(String),
    /// 目标既不是文件也不是目录（设备、管道等）。
    #[error("目标不是普通文件: {0}")]
    NotRegularFile(String),
}

/// 容器类别。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ContainerKind {
    /// 单对象文件（PE/ELF/Mach-O/COFF/raw）。
    Plain,
    /// 通用 ar 归档（GNU/BSD `.a`）。
    Ar,
    /// Microsoft 静态库 `.lib`（ar 结构 + MSVC 长名/符号成员）。
    MsvcLib,
    /// fat / universal 容器（Mach-O，解析推迟到 M10）。
    Fat,
}

impl ContainerKind {
    /// 稳定的短名（JSON / CLI）。
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Plain => "plain",
            Self::Ar => "ar",
            Self::MsvcLib => "msvc-lib",
            Self::Fat => "fat",
        }
    }

    /// 面向界面的中文名。
    #[must_use]
    pub const fn label_zh(self) -> &'static str {
        match self {
            Self::Plain => "单对象文件",
            Self::Ar => "ar 归档",
            Self::MsvcLib => "MSVC 静态库",
            Self::Fat => "fat 通用容器",
        }
    }
}

/// 对象格式。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ObjectKind {
    /// Windows PE（exe/dll/sys）。
    Pe,
    /// COFF 目标文件（`.obj`）。
    Coff,
    /// ELF（可执行 / `.so` / `.o`）。
    Elf,
    /// Mach-O（仅识别，解析推迟到 M10）。
    MachO,
    /// 未识别：按原始二进制处理。
    Raw,
}

impl ObjectKind {
    /// 稳定的短名。
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Pe => "pe",
            Self::Coff => "coff",
            Self::Elf => "elf",
            Self::MachO => "macho",
            Self::Raw => "raw",
        }
    }

    /// 面向界面的中文名。
    #[must_use]
    pub const fn label_zh(self) -> &'static str {
        match self {
            Self::Pe => "PE",
            Self::Coff => "COFF 目标文件",
            Self::Elf => "ELF",
            Self::MachO => "Mach-O",
            Self::Raw => "原始二进制",
        }
    }
}

/// 归档成员。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ArchiveMember {
    /// 成员名（已尽量解析长名表；解析不出来时保留原始引用形式）。
    pub name: String,
    /// 成员数据的文件偏移。
    pub offset: u64,
    /// 成员数据长度（已扣除 BSD `#1/` 内联名字）。
    pub size: u64,
    /// 成员数据是否超出嗅探窗口（内容未完整读取）。
    pub truncated: bool,
}

/// 嗅探结论。
///
/// 字段的语义都指向"我已经确定知道的事实"：拿不到的信息是 `None`，
/// 并用 [`Guess::notes`] 说明为什么拿不到。禁止用 0 / 空字符串冒充未知。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Guess {
    /// 容器类别。
    pub container: ContainerKind,
    /// 对象格式（容器为归档时表示容器本身的情况，成员格式见 `member_kind`）。
    pub object: ObjectKind,
    /// 归档成员的格式（`None` = 未识别或容器不是归档）。
    pub member_kind: Option<ObjectKind>,
    /// 架构规格（`None` = 未识别）。
    pub arch: Option<ArchSpec>,
    /// 位宽（0 = 未知）。
    pub bits: u8,
    /// 字节序（`None` = 未知）。
    pub endian: Option<Endian>,
    /// 入口点虚拟地址（`None` = 无入口或未识别）。
    pub entry: Option<u64>,
    /// 镜像基址（PE）。
    pub image_base: Option<u64>,
    /// 节数。
    pub sections: Option<u16>,
    /// 归档成员列表。
    pub members: Vec<ArchiveMember>,
    /// 成员列表是否因窗口/上限而截断。
    pub members_truncated: bool,
    /// 判定依据与限制说明（面向用户，可直接展示）。
    pub notes: Vec<String>,
    /// 实际参与嗅探的字节数。
    pub sniffed_bytes: usize,
    /// 文件是否大于嗅探窗口（结论仅覆盖前 [`SNIFF_WINDOW`] 字节）。
    pub file_truncated: bool,
}

impl Guess {
    /// 空结论（内部使用）。
    fn new(sniffed_bytes: usize) -> Self {
        Self {
            container: ContainerKind::Plain,
            object: ObjectKind::Raw,
            member_kind: None,
            arch: None,
            bits: 0,
            endian: None,
            entry: None,
            image_base: None,
            sections: None,
            members: Vec::new(),
            members_truncated: false,
            notes: Vec::new(),
            sniffed_bytes,
            file_truncated: false,
        }
    }

    /// 一行中文摘要，供 CLI 与 UI 直接展示。
    ///
    /// 归档的读法不一样：`object` 说的是**容器自己**（ar 归档里没有"整个文件的
    /// 对象格式"），真正有意义的是成员格式。所以归档分支不再打印
    /// "原始二进制"这种会误导人的字段，而是把成员格式提到主体位置。
    #[must_use]
    pub fn summary_zh(&self) -> String {
        let arch = self
            .arch
            .map_or_else(|| "架构未识别".to_string(), |a| a.to_string());
        let members = if self.members.is_empty() {
            String::new()
        } else {
            let extra = if self.members_truncated { "+" } else { "" };
            format!("，成员 {}{}", self.members.len(), extra)
        };

        if self.container != ContainerKind::Plain {
            let payload = self.member_kind.map_or_else(
                || "成员格式未识别".to_string(),
                |k| format!("成员格式 {}", k.as_str()),
            );
            return format!(
                "{} / {payload} / {arch}{members}",
                self.container.label_zh()
            );
        }

        let entry = self
            .entry
            .map_or_else(|| "-".to_string(), |e| format!("{e:#x}"));
        let sections = self
            .sections
            .map_or_else(|| "-".to_string(), |s| s.to_string());
        format!(
            "{} / {} / {}，入口 {}，节 {}{}",
            self.container.label_zh(),
            self.object.label_zh(),
            arch,
            entry,
            sections,
            members
        )
    }

    /// 该结论是否包含"看不懂"的记录（用于 CLI 高亮与测试断言）。
    #[must_use]
    pub fn has_notes(&self) -> bool {
        !self.notes.is_empty()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn summary_mentions_unknown_arch_explicitly() {
        let g = Guess::new(16);
        let s = g.summary_zh();
        assert!(s.contains("架构未识别"), "{s}");
        assert!(s.contains("原始二进制"), "{s}");
    }

    #[test]
    fn archive_summary_reports_member_format_not_container_object() {
        let mut g = Guess::new(64);
        g.container = ContainerKind::Ar;
        g.member_kind = Some(ObjectKind::Elf);
        let s = g.summary_zh();
        assert!(s.contains("ar 归档"), "{s}");
        assert!(s.contains("成员格式 elf"), "{s}");
        // 归档里没有"整个文件的对象格式"，不能打印"原始二进制"误导用户
        assert!(!s.contains("原始二进制"), "{s}");

        g.member_kind = None;
        let s = g.summary_zh();
        assert!(s.contains("成员格式未识别"), "{s}");
    }
}
