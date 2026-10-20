//! 容器与对象格式的解析层。
//!
//! 三层抽象（见 `docs/ARCHITECTURE.md` §3）：
//!
//! - **容器（[`ContainerKind`]）**：一个文件里可能装着多个对象 —— 归档（ar / MSVC `.lib`）、
//!   fat/universal、ZIP。ar 与 `.lib` 从 M0 起可枚举；fat/universal 的切片枚举、
//!   选片与成员化在 M12 落地（[`format::macho::fat`]）；
//!   ZIP 只做容器层（[`list_zip_members`] / [`read_zip_member`]）。
//! - **对象（[`ObjectKind`]）**：可分析的基本单位 —— PE、COFF、ELF、Mach-O、raw。
//! - **架构（[`bitflip_arch::ArchSpec`]）**：由格式的 machine 字段映射得到。
//!
//! 各格式的覆盖程度**不一样**，且这种不一样必须能被用户看到：PE/ELF 有导入导出与
//! 符号，Mach-O 已经有段/节/入口/符号表（`LC_SYMTAB`）/函数起点
//! （`LC_FUNCTION_STARTS`），但 dyld 绑定、objc/swift 元数据、代码签名校验都没做。
//! 每一处缺失都要落在解析结果的 `notes` 里，见 [`format::macho`] 的模块文档；
//! 不猜、不留空白解释。
//!
//! # 通用层与格式层的分界
//!
//! 本模块（`object` / `reader` / `sniff` / `ehframe`）是**通用层**：对象模型、
//! 带边界检查的读取器、识别结论、展开表。各格式的具体解析在 [`format`] 下 ——
//! **在 `format/` 外面的代码不该出现格式类型名**，新增一种格式也不该改这些文件。
//! 派发只有一个入口：[`parse_object`]。理由写在 `format/mod.rs` 与
//! `parse_object` 的文档里（那里记录了这条边界是被什么错误撞出来的）。
//!
//! 例外是 `sniff`：它按定义要认得"每个格式的第一眼特征"（魔数、文件头几个字段），
//! 所以那里会出现格式名 —— 但**只有识别、没有解析**，真正的解析一律在 [`format`]。

mod sniff;

pub mod bundle;
pub mod ehframe;
pub mod format;
pub mod object;
pub mod plist;
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

// ZIP 容器的对外入口。**刻意重命名**成 `list_zip_members` / `read_zip_member`：
// `format::zip::list_members` 单独看是清楚的，但提到 crate 根上就太泛了 ——
// 将来若有别的容器也暴露"list_members"，两个同名函数会在这里撞车。
//
// 这两件事**必须成对使用**：`list_zip_members` 给的 `index` 就是
// `read_zip_member` 要的参数，中间不能被过滤或重排改掉（见 `ArchiveMember::index`）。
pub use format::zip::{
    list_members as list_zip_members, read_member as read_zip_member, ApkRole, SignaturePresence,
    ZipListing,
};

// DEX 结构模型的对外入口。与 `list_zip_members` 同样的理由重命名：`format::dex::parse`
// 单独看很清楚，提到 crate 根上就只剩一个 `parse` —— 而这里已经有一个
// `parse_object` 了，两个 `parse*` 摆在一起分不出谁吃 DEX、谁吃机器码对象。
pub use format::dex::layout::{
    check_code_item_layout, payload_width_units, CodeHeaderFacts, LayoutCheck, LayoutProblem,
    LayoutProblemKind,
};
pub use format::dex::view::{
    column_range as dex_column_range, edge_label as dex_edge_label,
    project_code_item as project_dex_code_item, project_method as project_dex_method,
    render_cfg_text as render_dex_cfg_text, render_instructions as render_dex_instructions,
    render_instructions_with_symbols as render_dex_instructions_with_symbols, DexCfgView,
    DexEdgeKind, DexExceptionRegion, DexHandlerEntry, DexInstructions, DexMethodView, DexPayloads,
    DexPoolKind, DexRenderReport, DexSymbolOutcome, DexSymbolResolver, DexSymbols, DexViewError,
    UnresolvedEdgeTarget,
};
pub use format::dex::{
    parse as parse_dex_structure, DexClass, DexCountMismatches, DexCounts, DexDeclaredSizes,
    DexField, DexHeaderFacts, DexMethod, DexParseError, DexStructure, MAX_DEX_BYTES,
};

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
        "目标是目录而不是文件: {0} —— .app bundle 之类的目录容器排期在 M12（见 docs/PLAN.md）"
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
    /// ZIP 容器（APK / JAR / XAPK 等以 ZIP 为外壳的东西）。
    ///
    /// 与 `Ar` 同为"一个文件多个命名成员"，但有两处**结构性**不同，
    /// 它们决定了实现方式，所以记在这里而不是留给读者去发现：
    ///
    /// 1. **目录在文件末尾。** ar 的成员头紧跟在成员数据前面，所以读前缀
    ///    就能枚举完；ZIP 的中央目录在**最后一个成员之后**，文件有多大
    ///    就要往后翻多远。因此嗅探（只看前 [`SNIFF_WINDOW`] 字节）
    ///    **只能认出"这是个 ZIP"**，枚举成员必须拿到完整字节 —— 见
    ///    [`crate::list_zip_members`]。
    /// 2. **成员是压缩的。** ar 成员就是 `offset..offset+size` 的裸字节，
    ///    可以直接切片去解析；ZIP 成员默认是 DEFLATE，**必须先解压**。
    ///    两者靠 [`ArchiveMember::storage`] 区分，由
    ///    `bitflip-core` 的成员会话按它选择"切片"还是"解压"。
    Zip,
    /// fat / universal 容器（Mach-O，一个文件里多个架构切片）。
    ///
    /// 这个变体从 M0 就存在，是因为**抽象要提前留出来**：
    /// fat 与 ar 都是"一个文件多个对象"，但切片**没有名字**（只有架构），
    /// 混进 `Ar` 会让"按名字找成员"这条既有逻辑带上一个说不通的空名字。
    ///
    /// **M12 第三片的状态**：切片枚举（[`format::macho::fat::read`]）、默认选片
    /// 规则（[`format::macho::fat::SELECTION_RULE_ZH`]）与会话成员化都做了 ——
    /// `bitflip-core` 的成员会话把每个切片当成 `ArchiveMember` 列出来，
    /// 也能按 `--arch` 挑一片（`format::macho::fat::parse_slice`）。
    /// 但**整份** fat 文件本身仍然不是一个对象：直接 `parse` 它依旧明确报错。
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
            Self::Zip => "zip",
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
            Self::Zip => "ZIP 容器",
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
    /// DEX（Dalvik Executable；APK 里的 `classes*.dex`）。
    ///
    /// **有解析器，但不在 [`parse_object`] 这条路里**：DEX 是寄存器机字节码，
    /// 没有机器架构、没有段权限、没有 `image_base`，套进机器码对象模型会
    /// 产出一堆"看起来正常、实际无意义"的结论。它的结构模型在
    /// [`crate::format::dex`]，入口是 [`crate::parse_dex_structure`]。
    Dex,
    /// Mach-O（可执行 / `.dylib`；结构层解析见 [`format::macho`]，M12 第一～五片）。
    ///
    /// "有解析器"覆盖的范围要说清楚：**头/段/节/入口/`LC_UUID`/dylib 名/符号表/
    /// 函数起点/导入**都在（导入来自 `LC_DYLD_INFO` 的 bind 与
    /// `LC_DYLD_CHAINED_FIXUPS`，带槽位地址 `iat_slot`），而 objc/swift 元数据、
    /// 代码签名**不在** —— 缺的那些写在 `notes` 里。
    /// `symbols` / `function_starts` / `imports` 为空**可能是**"文件里没有"，
    /// 也可能是解析没做到，两种情形的 `notes` 不同：以那里的说明为准，
    /// 不要用空表反推结论。
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
            Self::Dex => "dex",
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
            Self::Dex => "DEX（Dalvik 字节码）",
            Self::MachO => "Mach-O",
            Self::Raw => "原始二进制",
        }
    }
}

/// 这个对象类别能不能解析成**机器码对象模型**（即能不能走 [`parse_object`]）。
///
/// 名字只回答这一个问题，**不回答"我们支不支持这个格式"** —— 这两件事在 DEX
/// 上正好分开了：DEX 有解析器（[`crate::format::dex`]），但它不产生 `Object`
/// （没有机器架构、没有段权限、没有 `image_base`），所以这里仍然是 `false`。
/// 让它为 `true` 只会在调用方那里变成一次必然失败的调用，而失败的时机
/// 还离"谁该为此负责"很远。
///
/// Mach-O 从 M12 第一片起是 `true`：结构层解析已经落地（[`format::macho`]）。
/// 但它**能解析**不等于**解析得完整** —— 符号表/dyld 绑定/代码签名都没做，
/// 这一点由解析结果里的 `notes` 说，而不是靠这个布尔值暗示。
///
/// `Raw` 是"用户指定按原始二进制处理"——没有头可读，由上层合成对象
/// （见 `bitflip-core` 的 `parse_raw`）。它**不该**让 [`parse_object`] 返回一个
/// 空对象：那会让上层显示"分析完成但什么都没有"（CLAUDE.md §7）。
#[must_use]
pub const fn has_parser(kind: ObjectKind) -> bool {
    matches!(
        kind,
        ObjectKind::Pe | ObjectKind::Coff | ObjectKind::Elf | ObjectKind::MachO
    )
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
/// "PE 解析失败：…" 这样的说明）；`Dex` / `Raw` 返回 [`ParseError::NoParser`]。
/// fat / universal Mach-O 返回 [`ParseError::NotSupported`]：容器里没有"这个文件"
/// 的单一架构，得先用 [`format::macho::fat::read`] 选切片。
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
        ObjectKind::Dex => Err(ParseError::NoParser {
            kind: kind.as_str(),
            detail: "DEX 不做机器码对象模型（没有机器架构、没有段权限、没有 image_base）—— \
                     它的结构模型在 format::dex，入口是 parse_dex_structure；\
                     接进反汇编/CFG 流水线是 M11 的后续里程碑（见 docs/APK-DEX-DESIGN.md）",
        }),
        ObjectKind::MachO => format::macho::parse(bytes, base, id),
        ObjectKind::Raw => Err(ParseError::NoParser {
            kind: kind.as_str(),
            detail: "原始二进制没有可解析的头，由上层按用户给的架构与基址合成对象",
        }),
    }
}

/// 成员内容**怎么取** —— 这决定消费方是"直接切片"还是"向容器要"。
///
/// # 为什么不叫 `Plain` / `Compressed`
///
/// 一开始的分法是"压缩了没有"，但那个分法立刻逼出一个说不通的格子：
/// ZIP 里 method 0（stored，不压缩）的成员按这个分法该算"可直接切片"，
/// 可它的数据起点**不在中央目录里**（中央目录只记本地头的位置），
/// 要另外解析本地头才算得出来 —— 本地头一旦对不上，它连"能不能切片"
/// 都取决于别的东西。一个格子里的语义依赖另一处解析的结果，就是分法错了。
///
/// 所以依据换成**取内容的途径**：能不能只靠 `offset..offset+size`？
/// 能就是 [`Self::Inline`]；不能就是 [`Self::Container`]（按 `index` 走容器
/// 自己的读取接口，它内部怎么处理压缩与本地头与我们无关）。
///
/// 换成这个分法后每个格子都说得通：ar / MSVC `.lib` 恒为 `Inline`；
/// ZIP 恒为 `Container`（无论 method 是 0 还是 8）—— "数据在哪、要不要解压"
/// 本来就该由容器说了算，不该由我们按偏移猜。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MemberStorage {
    /// 内联：文件 `offset..offset+size` 就是成员内容，可直接切片。
    ///
    /// ar / MSVC `.lib`。**此时 [`ArchiveMember::offset`] 必然有值**
    /// （`None` 会让切片无从下手）。
    Inline,
    /// 要经容器取出：用 [`ArchiveMember::index`] 调容器的读取接口
    /// （ZIP 走 [`crate::read_zip_member`]）。
    ///
    /// 此时 [`ArchiveMember::offset`] / [`ArchiveMember::size`]
    /// **只是诊断信息**，取内容一律不走它们。
    Container {
        /// 容器自己的存储方法号（ZIP：0 = stored，8 = deflate；APPNOTE §4.4.5）。
        ///
        /// 刻意保留原始号码而不是映射成自造的枚举：遇到没见过的号码时，
        /// 把它**如实打出来**比归进"其他"有用得多（§7）。
        method: u16,
        /// 解压后的长度（ZIP 即中央目录里的 `uncompressed size`）。
        ///
        /// 可能为 `0`：写了 data descriptor（APPNOTE §4.3.9.2）的条目，
        /// 其长度在**本地头**里是空的。此时按"长度未知"处理，不要当 0 用。
        uncompressed_size: u64,
    },
}

impl MemberStorage {
    /// 成员内容能否直接用 `offset..offset+size` 切片取得。
    #[must_use]
    pub const fn is_inline(self) -> bool {
        matches!(self, Self::Inline)
    }

    /// 稳定的短名（JSON / CLI）。
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Inline => "inline",
            Self::Container { .. } => "container",
        }
    }

    /// 存储方式的中文说明，含**原始**方法号（CLI / UI 直接用）。
    ///
    /// 只给实测见过的号码配人类可读的名字；其余**如实打印号码**并注明未知，
    /// 而不是归进"其他"或"未知压缩" —— 号码本身才是能拿去查 APPNOTE 的线索
    /// （CLAUDE.md §7）。
    #[must_use]
    pub fn label_zh(self) -> String {
        match self {
            Self::Inline => "内联裸字节".to_string(),
            Self::Container { method, .. } => match method {
                0 => "容器内，方法 0（stored，不压缩）".to_string(),
                8 => "容器内，方法 8（deflate）".to_string(),
                other => format!("容器内，方法 {other}（未知方法，保留原始号码）"),
            },
        }
    }

    /// 容器自己的存储方法号（内联成员没有方法号，返回 `None`）。
    #[must_use]
    pub const fn method(self) -> Option<u16> {
        match self {
            Self::Inline => None,
            Self::Container { method, .. } => Some(method),
        }
    }

    /// 容器声明的**解压后**长度（内联成员没有这一层，返回 `None`）。
    ///
    /// 返回 `Some(0)` 不代表"空成员"：写了 data descriptor 的 ZIP 条目
    /// 在中央目录里可能记 `0`，真实长度要到本地头之后才知道。
    /// 调用方要按"长度未知"处理这种情况，不要当 0 用。
    #[must_use]
    pub const fn uncompressed_size(self) -> Option<u64> {
        match self {
            Self::Inline => None,
            Self::Container {
                uncompressed_size, ..
            } => Some(uncompressed_size),
        }
    }
}

/// 容器成员。
///
/// 名字里的"归档"是历史叫法：ar / MSVC `.lib` 先落地，ZIP 后来才有。
/// 三种容器共用这个结构，共同点是"一个文件里装着多个**有名字**的成员"。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ArchiveMember {
    /// 成员在容器目录里的序号（从 0 起）。
    ///
    /// **取成员内容时要靠它**，所以不能拿"在 `Vec` 里的下标"临时替代：
    /// 上层可能按名字匹配、过滤或排序，而下标会跟着变。
    ///
    /// * ZIP：中央目录里的下标 —— [`crate::read_zip_member`] 用它定位条目；
    /// * ar / MSVC `.lib`：就是出现顺序（ar 没有索引，顺序即定义）。
    pub index: usize,
    /// 成员名（已尽量解析长名表；解析不出来时保留原始引用形式）。
    pub name: String,
    /// 成员**数据**的文件偏移（`None` = 定位不到）。
    ///
    /// 注意是数据本身，不是成员头：ZIP 成员的头（local file header + 文件名 +
    /// extra field）长度可变，数据起点要从本地头算出来，不能像 ar 那样
    /// "接着上一个成员的尾巴"。
    ///
    /// # 为什么是 `Option`
    ///
    /// 对 **ZIP**，数据起点不在中央目录里 —— 中央目录只记 `header_start`
    /// （本地头的位置），真正的起点要靠本地头里的文件名/extra 长度算。
    /// 本地头缺失或对不上时**就真的不知道**它在哪儿。
    ///
    /// 那时给 `0` 是**最坏**的答案：`0` 是个合法偏移，界面会把它显示成
    /// "数据在文件开头"，用户拿去对照十六进制却什么也找不到 ——
    /// 这正是 CLAUDE.md §7 禁止的"用 0 冒充未知"。所以留 `None`，
    /// 由界面显示"未知"。
    ///
    /// ar / MSVC `.lib` 永远是 `Some`（成员头里就写着长度，数据紧随其后）。
    pub offset: Option<u64>,
    /// 成员数据在文件里占的字节数（ZIP 即**压缩后**大小）。
    pub size: u64,
    /// 成员数据是否超出嗅探窗口（内容未完整读取）。
    pub truncated: bool,
    /// 成员内容怎么取 —— 切片还是解压。
    pub storage: MemberStorage,
    /// 成员**自己的架构**（拿到确切结论时才有值）。
    ///
    /// 只有 fat / universal 切片在容器层就能确定架构：架构表里写着 `cputype`，
    /// 切片的头里写着端序，两件事都不必先解析成对象。其余容器（ar / MSVC `.lib` /
    /// ZIP）在这一层**不知道**成员是什么架构 —— 那要等成员内容被解析出来，
    /// 所以给 `None`，而不是拿"容器第一个成员的架构"顶替所有成员。
    ///
    /// 这个字段存在的理由很具体：fat 的成员**没有名字**（只有架构），
    /// 用户要"打开 arm64 那一片"，唯一稳定的判据就是这个字段。
    pub arch: Option<bitflip_arch::ArchSpec>,
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

        // ZIP（APK）单独一条分支，**不能**沿用下面那条"归档"分支。
        //
        // 归档（ar / .lib）的成员是同一类东西（编译出来的对象文件），所以
        // "成员格式 X" 有意义。ZIP 成员的格式**本来就是混的**（APK 里同时有
        // dex / `.so` / 二进制清单 / 资源表），没有"那个成员格式"可以填。
        //
        // 若沿用归档分支，`member_kind` 是 `None`，会打印出"成员格式未识别" ——
        // 而那不是"我没认出来"，是"它本来就不止一种"。把"还没看"说成
        // "没认出来"是 §7 禁止的误导。
        if self.container == ContainerKind::Zip {
            // 嗅探阶段（只有前缀）还枚举不到成员，此时**不能**说"成员 0"
            // —— 那是把"还没数"说成"数出来是零"。
            let members = if self.members.is_empty() {
                "成员清单未枚举".to_string()
            } else {
                let extra = if self.members_truncated { "+" } else { "" };
                format!("成员 {}{}", self.members.len(), extra)
            };
            return format!(
                "{}，{members}（成员格式各不相同，按成员逐个判定）",
                self.container.label_zh()
            );
        }

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
