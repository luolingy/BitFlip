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
//!
//! # 通用层与格式层的分界
//!
//! 本模块（`object` / `reader` / `sniff` / `ehframe`）是**通用层**：对象模型、
//! 带边界检查的读取器、识别结论、展开表。各格式的具体解析在 [`format`] 下 ——
//! **在 `format/` 外面的代码不该出现格式类型名**，新增一种格式也不该改这些文件。
//! 派发只有一个入口：[`parse_object`]。理由写在 `format/mod.rs` 与
//! `parse_object` 的文档里（那里记录了这条边界是被什么错误撞出来的）。

mod sniff;

pub mod ehframe;
pub mod format;
pub mod object;
pub mod reader;

#[cfg(test)]
mod fuzz;

use bitflip_arch::{ArchSpec, Endian};
use thiserror::Error;

// 让 `parse_object` 的签名能直接写出返回类型。**刻意用私有 `use` 而不是 `pub use`**：
// 调用方现在走 `bitflip_loader::object::Object` / `bitflip_loader::reader::ParseError`，
// 那是既有的公开路径，没有理由为了少打几个字符再开一套别名（多一条路径就多一份
// "该用哪个"的疑问，而两者的可见性还不一样）。
use object::{Object, ObjectId};
use reader::ParseError;

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

/// 这个对象类别是否由本层直接解析。
///
/// `Raw` 是"用户指定按原始二进制处理"——没有头可读，由上层合成对象
/// （见 `bitflip-core` 的 `parse_raw`）；`Mach-O` 目前只识别不解析。
/// 两者都**不该**让 [`parse_object`] 返回一个空对象：那会让上层显示
/// "分析完成但什么都没有"（CLAUDE.md §7）。
#[must_use]
pub const fn has_parser(kind: ObjectKind) -> bool {
    matches!(kind, ObjectKind::Pe | ObjectKind::Coff | ObjectKind::Elf)
}

/// 解析一个对象：**格式派发的唯一入口**。
///
/// # 为什么这个函数必须只有一个
///
/// `match kind { Pe => pe::parse(..), Elf => elf::parse(..), Coff => coff::parse(..) }`
/// 曾经在三个地方各写了一遍：核心层"打开目标"、核心层"打开归档成员"、签名生成器。
/// 三份派发意味着**新增一种格式要记得改三处**，而漏掉一处的后果是静默的 ——
/// 那个格式会走进兜底分支，被报成"不是可分析对象（识别为 X）"：
/// 看起来像识别出了问题，实际是派发漏了。
///
/// 所以这不是"格式层不够模块化"，是**接口**不够模块化：每个调用方都在自己重新
/// 实现"格式 → 解析器"的映射。派发收敛到这一处之后，调用方只回答两件事：
/// 这个类别有没有解析器（[`has_parser`]）、失败怎么表述。
///
/// # 参数
///
/// `base` 只在解析**可重定位**目标（`.o` / `.obj`）时才需要非零值：那类文件的
/// 节地址全是 0，要由调用方给一个基址才能建起地址空间。可执行映像的基址在文件头里，
/// 给 `0` 即可（解析器会读自己的 `ImageBase` / 程序头）。
///
/// # Errors
///
/// 具体格式的解析失败原样返回该格式的 [`ParseError`]（调用方按需要包成
/// "PE 解析失败：…" 这样的说明）；`Raw` / `MachO` 返回 [`ParseError::NoParser`]。
///
/// # Panics
///
/// 不会 panic。调用方漏了 [`has_parser`] 检查时，用户看到的是一条说明
/// "这个格式没有解析器"的错误，而不是进程崩溃。
pub fn parse_object(
    kind: ObjectKind,
    bytes: &[u8],
    base: u64,
    id: ObjectId,
) -> Result<Object, ParseError> {
    match kind {
        ObjectKind::Pe => format::pe::parse(bytes, base, id),
        ObjectKind::Coff => format::coff::parse(bytes, base, id),
        ObjectKind::Elf => format::elf::parse(bytes, base, id),
        ObjectKind::MachO => Err(ParseError::NoParser {
            kind: kind.as_str(),
            detail: "Mach-O 当前只做识别，解析未实现（见 docs/PLAN.md §1.3 的里程碑排期）",
        }),
        ObjectKind::Raw => Err(ParseError::NoParser {
            kind: kind.as_str(),
            detail: "原始二进制没有可解析的头，由上层按用户给的架构与基址合成对象",
        }),
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
    /// 这个成员是否**装载目标对象**。
    ///
    /// 归档里的符号索引（`/`）、长名表（`//`）、以及名字解析失败的长名引用
    /// 都是**元数据**：它们确实在文件里，也确实是"成员"，但内容不是对象。
    /// 消费方（成员遍历、签名生成）需要能区分这两件事 —— 靠名字前缀去猜
    /// （`/...`）会把"解析失败"和"元数据"混成一类，而这两者的处置并不相同。
    pub payload: bool,
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
