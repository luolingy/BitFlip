//! 对象模型：容器解析之后，分析层看到的统一视图（`docs/ARCHITECTURE.md` §3）。
//!
//! 关键区分：**段（内存视角）优先于节**。分析走地址空间，节只用于命名与边界提示。
//! 这不是学究式区分 —— PE 的节与 ELF 的段对"可执行/可写/是否加载"的表达不同，
//! 把它们统一到 `Segment` 上，M2 的地址空间就只需要一种输入。
//!
//! 另一个刻意的选择：这里的字段**要么是确定的值，要么是 `None` + `notes` 里的原因**。
//! 不用 `0` 或空串冒充"未知"，否则 UI 无法区分"入口就是 0"和"没读到入口"。

use bitflip_arch::{ArchSpec, Endian};

use crate::reader::ParseError;

/// 对象在容器内的标识。
#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum ObjectId {
    /// 单对象文件的唯一对象。
    Plain,
    /// 归档成员：成员名（重名时带序号）。
    ArchiveMember(String),
}

impl ObjectId {
    /// 稳定的显示名。
    #[must_use]
    pub fn display(&self) -> String {
        match self {
            Self::Plain => "<主对象>".to_string(),
            Self::ArchiveMember(name) => name.clone(),
        }
    }
}

/// 段/节的权限标志。
///
/// 用位标志而不是三个 `bool`：UI 与 JSON 都能直接渲染成 `r-x` 这种形式。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct Perms {
    /// 可读。
    pub read: bool,
    /// 可写。
    pub write: bool,
    /// 可执行。
    pub execute: bool,
}

impl Perms {
    /// 全不可访问。
    #[must_use]
    pub const fn none() -> Self {
        Self {
            read: false,
            write: false,
            execute: false,
        }
    }

    /// 渲染成 `r-x` / `rw-` 这样的三字符形式。
    #[must_use]
    pub fn to_rwx(self) -> String {
        let mut out = String::with_capacity(3);
        out.push(if self.read { 'r' } else { '-' });
        out.push(if self.write { 'w' } else { '-' });
        out.push(if self.execute { 'x' } else { '-' });
        out
    }
}

/// 节/段的内容类别。
///
/// 保留 `Unknown` 而不是猜：猜错的类别会误导用户（例如把跳转表显示成代码）。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ContentKind {
    /// 代码。
    Code,
    /// 只读数据。
    ReadOnlyData,
    /// 可写数据（含 BSS）。
    Data,
    /// 未初始化数据（不占文件空间）。
    Bss,
    /// 符号表。
    SymbolTable,
    /// 字符串表。
    StringTable,
    /// 重定位表。
    Relocations,
    /// 动态链接信息。
    Dynamic,
    /// 调试信息。
    Debug,
    /// 异常/展开信息（`.pdata` / `.eh_frame`）。
    Unwind,
    /// 导入表。
    ImportTable,
    /// 导出表。
    ExportTable,
    /// 资源。
    Resources,
    /// 只存在于文件、不参与地址空间映射的元数据（`.comment`、`.note.*` 等）。
    ///
    /// 与 `ReadOnlyData` 的区别是**是否会出现在运行期内存里**：元数据节
    /// 没有 `SHF_ALLOC`，不会被加载，因此不该显示成"只读数据"。
    Metadata,
    /// 无法判断。
    Unknown,
}

impl ContentKind {
    /// 稳定的短名（JSON / CLI）。
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Code => "code",
            Self::ReadOnlyData => "rodata",
            Self::Data => "data",
            Self::Bss => "bss",
            Self::SymbolTable => "symtab",
            Self::StringTable => "strtab",
            Self::Relocations => "reloc",
            Self::Dynamic => "dynamic",
            Self::Debug => "debug",
            Self::Unwind => "unwind",
            Self::ImportTable => "import",
            Self::ExportTable => "export",
            Self::Resources => "rsrc",
            Self::Metadata => "meta",
            Self::Unknown => "unknown",
        }
    }

    /// 中文标签（UI）。
    #[must_use]
    pub const fn label_zh(self) -> &'static str {
        match self {
            Self::Code => "代码",
            Self::ReadOnlyData => "只读数据",
            Self::Data => "数据",
            Self::Bss => "未初始化数据",
            Self::SymbolTable => "符号表",
            Self::StringTable => "字符串表",
            Self::Relocations => "重定位表",
            Self::Dynamic => "动态链接",
            Self::Debug => "调试信息",
            Self::Unwind => "异常展开",
            Self::ImportTable => "导入表",
            Self::ExportTable => "导出表",
            Self::Resources => "资源",
            Self::Metadata => "文件元数据",
            Self::Unknown => "未知",
        }
    }
}

/// 文件内的一段字节范围。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FileRange {
    /// 文件内偏移。
    pub offset: u64,
    /// 字节数。
    pub size: u64,
}

impl FileRange {
    /// 构造。
    #[must_use]
    pub const fn new(offset: u64, size: u64) -> Self {
        Self { offset, size }
    }

    /// 结束偏移（不含）。
    pub fn end(self) -> Result<u64, ParseError> {
        self.offset.checked_add(self.size).ok_or_else(|| {
            ParseError::Overflow(format!("文件范围 {:#x}+{:#x}", self.offset, self.size))
        })
    }

    /// 是否为空。
    #[must_use]
    pub const fn is_empty(self) -> bool {
        self.size == 0
    }
}

/// 段：内存视角的一块连续地址区间。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Segment {
    /// 名称（PE 节名 / ELF 段名，可能为空）。
    pub name: String,
    /// 虚拟地址。
    pub vaddr: u64,
    /// 虚拟大小（可能大于文件大小，例如 BSS）。
    pub vsize: u64,
    /// 对应的文件范围；`None` 表示不占文件空间（.bss）。
    pub file: Option<FileRange>,
    /// 权限。
    pub perms: Perms,
    /// 内容类别。
    pub kind: ContentKind,
    /// 对齐要求。
    pub align: u64,
}

impl Segment {
    /// 虚拟地址区间（不含结束）。
    pub fn end_vaddr(&self) -> Result<u64, ParseError> {
        self.vaddr
            .checked_add(self.vsize)
            .ok_or_else(|| ParseError::Overflow(format!("段 {:#x}+{:#x}", self.vaddr, self.vsize)))
    }

    /// 地址是否落在本段内。
    #[must_use]
    pub fn contains(&self, addr: u64) -> bool {
        addr >= self.vaddr && addr.wrapping_sub(self.vaddr) < self.vsize
    }
}

/// 节：文件视角的一块区域（含不加载的节，例如调试信息）。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Section {
    /// 名称。
    pub name: String,
    /// 虚拟地址（不加载的节通常为 0）。
    pub vaddr: u64,
    /// 文件范围。
    pub file: FileRange,
    /// 权限。
    pub perms: Perms,
    /// 内容类别。
    pub kind: ContentKind,
    /// 是否在运行时被映射进内存。
    pub loaded: bool,
}

/// 导入符号来源。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Import {
    /// 所在模块（DLL 名 / `DT_NEEDED`）。
    pub module: String,
    /// 符号名；按序号导入时为 `None`。
    pub name: Option<String>,
    /// 按序号导入时的序号。
    pub ordinal: Option<u32>,
    /// IAT / GOT 槽的虚拟地址（分析交叉引用时要用）。
    pub iat_slot: Option<u64>,
    /// 名字/序号的来源地址（thunk 内容所在位置）。
    pub thunk: Option<u64>,
}

/// 导出符号。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Export {
    /// 导出名。
    pub name: String,
    /// 序号。
    pub ordinal: Option<u32>,
    /// 导出地址（RVA 已转成虚拟地址）。
    pub address: u64,
    /// 转发目标（`Name.Function` 形式），转发导出没有本地代码。
    pub forwarder: Option<String>,
    /// 是否作为代码导出（`IMAGE_FILE_EXECUTABLE_IMAGE` 之外的判断）。
    pub is_code: bool,
}

/// 重定位类型（归一化后的粗分类）。
///
/// 不保留格式特有的类型编号：分析层只关心"要往哪写什么"，具体编号是格式细节。
/// 需要精确编号时从 `raw_kind` 取。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum RelocKind {
    /// 绝对地址（32/64 位指针）。
    Absolute,
    /// 相对地址（PC 相对）。
    Relative,
    /// 相对基址的指针槽位（ELF `R_*_RELATIVE`、PE `IMAGE_REL_BASED_DIR64`）。
    ///
    /// 与 [`Self::Relative`] 分开是必要的：PC 相对重定位出现在**指令**里
    /// （`call`/`lea` 的目标），而这一种出现在**数据**里 —— 加载器会往
    /// 该槽位写"基址 + 加数"，也就是一个函数/对象指针。
    ///
    /// 早先两者都归到 `Relative`，导致指针表识别没法只挑出数据指针：
    /// 实测 `libsample.so` 的 `sample_table[2]` 就是一条
    /// `R_X86_64_RELATIVE`（加数即目标地址），归错类就完全看不见它。
    RelocPointer,
    /// 需要导入符号解析。
    ImportLookup,
    /// 其他/未知类型。
    Other,
}

impl RelocKind {
    /// 稳定的短名。
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Absolute => "abs",
            Self::Relative => "rel",
            Self::RelocPointer => "relptr",
            Self::ImportLookup => "import",
            Self::Other => "other",
        }
    }
}

/// 一条重定位。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Reloc {
    /// 需要修改的位置。
    ///
    /// **语义随文件类别而不同，这一点必须按 [`Self::section`] 配对理解**：
    ///
    /// * 已链接的镜像（PE/ELF 可执行与 `.so`/`.dll`）里是虚拟地址；
    /// * 可重定位对象（`.o`/`.obj`）里是**该节内的偏移** —— 那些文件的
    ///   节虚拟地址通常全是 0，几个节的偏移会落在同一批数值上。
    ///
    /// 早先这里只写了"虚拟地址"，于是 `.text` 与 `.data` 的重定位在地址上
    /// 混成一堆且无从分辨（M8 做签名匹配时踩到）。
    pub address: u64,
    /// 该重定位**修改的节**的名字。
    ///
    /// 对可重定位对象是必需的：没有它，[`Self::address`] 无法定位到具体位置。
    /// `None` 表示来源没有给出（而不是"不属于任何节"）。
    pub section: Option<String>,
    /// 归一化类型。
    pub kind: RelocKind,
    /// 格式特有的原始类型编号（排错用）。
    pub raw_kind: u32,
    /// 关联的符号名（若可得）。
    pub symbol: Option<String>,
    /// 加数。
    pub addend: i64,
}

/// 原始符号（未去重、未优选）。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RawSymbol {
    /// 符号名（可能为空，例如节符号）。
    pub name: String,
    /// 符号值（虚拟地址或节内偏移，取决于 `kind`）。
    pub value: u64,
    /// 大小（0 表示未知）。
    pub size: u64,
    /// 是否已定义（`false` 表示未定义/外部符号）。
    pub defined: bool,
    /// 是否为函数符号。
    pub is_function: bool,
    /// 是否为弱符号。
    pub is_weak: bool,
    /// 绑定类型原始值（ELF 的 `STB_*`；其他格式填 0）。
    ///
    /// 保留原始值是因为"可见性"的判定依赖它：只有非 LOCAL 的动态符号才是导出，
    /// 而 LOCAL/GLOBAL/WEAK 的语义在格式间并不完全一致，不适合强行归一化成 bool。
    pub bind: u8,
    /// 所属节名（若可得）。
    pub section: Option<String>,
    /// 来源（`symtab` / `dynsym` / COFF 符号表），用于置信度排序。
    pub source: SymbolTableSource,
}

/// 符号来自哪张表。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum SymbolTableSource {
    /// 完整符号表。
    Static,
    /// 动态符号表。
    Dynamic,
    /// 导出表衍生。
    Export,
    /// 仅调试信息。
    Debug,
}

impl SymbolTableSource {
    /// 稳定的短名。
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Static => "symtab",
            Self::Dynamic => "dynsym",
            Self::Export => "export",
            Self::Debug => "debug",
        }
    }

    /// 优先级（越小越可信）。
    #[must_use]
    pub const fn priority(self) -> u8 {
        match self {
            Self::Static => 0,
            Self::Dynamic => 1,
            Self::Export => 2,
            Self::Debug => 3,
        }
    }
}

/// 异常展开表条目（PE `.pdata` RUNTIME_FUNCTION / ELF `.eh_frame` FDE）。
///
/// M1 只读取并保存，M3 才用它推断函数边界 —— 但表要现在就解析对，
/// 否则 M3 会拿到错误输入且很难查。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UnwindEntry {
    /// 函数起始地址。
    pub begin: u64,
    /// 函数结束地址（不含）。
    pub end: u64,
    /// 展开信息地址。
    pub unwind_info: u64,
    /// 解码出的展开细节（PE 的 `UNWIND_INFO`）。
    ///
    /// `None` 表示该条目没有解码（ELF 的 `.eh_frame` 目前只给出函数
    /// 边界，没有 CFI 指令解码；PE 的 `.pdata` 若能解出就填上）。
    /// **不拿一个默认值冒充**：没有解码就是没有。
    ///
    /// 通用分析层（栈帧推导）**不要直接摸这个字段**，用下面那组访问器 ——
    /// 理由见 [`UnwindEntry::frame_size`]。
    pub decoded: Option<PeUnwindInfo>,
    /// 该条目的 `decoded` 是**推迟解码**的（还没有解），而不是"解了但没有细节"。
    ///
    /// # 为什么需要这个标志
    ///
    /// `.pdata` 在 64 位 PE 里每个函数一条记录。实测 owo-terminal.exe 有
    /// **417,629** 条，而 `Session::open`（`info` 也走它）原本会把每一条的
    /// `UNWIND_INFO` 全部解开 —— 1.2 秒，其中 `info` 一个字段都用不到。
    ///
    /// 于是改为：建表时只读 `begin`/`end`/`unwind_info` 三个 RVA（那才是
    /// 函数边界需要的），`UNWIND_INFO` 留到调用方真的要问帧大小时再解。
    ///
    /// **`deferred` 与 `decoded: None` 必须分得开**（CLAUDE.md §7）：
    /// 前者是"还没问"，后者是"问了但解不出来"。把两者混成一个 `None`，
    /// 就是在用"未知"冒充"没有"，界面会把"尚未解码"显示成"这个函数没有
    /// 展开信息"。
    pub deferred: bool,
}

impl UnwindEntry {
    /// 把这一条的展开细节真正解出来（如果之前是推迟的）。
    ///
    /// 需要 `reader` 是因为解码要读 `.rdata` 里的 `UNWIND_INFO` 字节，
    /// 而对象模型本身不持有文件字节。
    ///
    /// 重复调用是廉价的：已经解过的直接返回。解不出来时把 `deferred`
    /// 清掉并留下 `decoded = None` —— 那就是一个**确定的**"这一条没有
    /// 展开细节"，之后不会再反复尝试。
    pub fn resolve(&mut self, reader: &crate::reader::Reader<'_>, object: &Object) {
        if !self.deferred {
            return;
        }
        self.deferred = false;
        self.decoded =
            crate::format::pe::unwind::parse_unwind_info(reader, object, self.unwind_info);
    }
}

/// 展开信息的**格式无关读法**。
///
/// # 为什么需要这一层，而不是让调用方去读 `decoded`
///
/// 栈帧推导（`bitflip-analyze::frames`）是通用分析层，它问的只有三件与格式无关的
/// 事：帧多大、保存了哪些寄存器、帧指针是哪个。此前它直接 `use` 了
/// `PeUnwindInfo`，于是**分析层知道 PE 的 opcode 怎么编码** —— 每加一种格式的
/// 展开信息（例如 ELF 的 CFI 指令解码）都要回去改分析层，而分析层本来完全
/// 不需要知道这些。这不是"格式层不够模块化"，是**接口**没把格式差异挡住。
///
/// 现在差异收敛到这四个方法里（它们与 `decoded` 同处一个 crate），分析层只读
/// 这里的答案。`decoded` 仍然公开：格式层自己的测试与展示需要原始细节
/// （PE 的 opcode 序列），拿它是对的 —— 通用层不该拿。
///
/// # 加新格式时要改哪里
///
/// `decoded` 变成多格式的枚举后，**改这四个方法就够**，调用方不动。
impl UnwindEntry {
    /// 展开信息给出的栈帧大小（字节）。
    ///
    /// `None` = 这一条没有解码出展开细节。注意 `Some(0)` 是"解码了，且帧大小为 0"
    /// （叶子函数的常见形态），与 `None` 不是一回事 —— 把两者混起来会让
    /// "不知道"显示成"零字节"。
    ///
    /// **推迟解码的条目在这里也返回 `None`**（它确实还没有答案）。调用方要
    /// 区分"尚未解码"与"解不出来"，看 [`UnwindEntry::is_deferred`] —— 或者
    /// 先调 [`UnwindEntry::resolve`] 让它变成确定的结论。
    #[must_use]
    pub fn frame_size(&self) -> Option<u64> {
        self.decoded.as_ref().and_then(PeUnwindInfo::frame_size)
    }

    /// 这一条是否**还没解码**（不是"解码失败"）。
    ///
    /// 存在的意义就是让"尚未解码"与"没有展开细节"分得开（CLAUDE.md §7）。
    #[must_use]
    pub const fn is_deferred(&self) -> bool {
        self.deferred
    }

    /// 展开信息说保存了哪些非易失寄存器（按前导顺序）。
    #[must_use]
    pub fn saved_registers(&self) -> Vec<&str> {
        self.decoded
            .as_ref()
            .map_or_else(Vec::new, PeUnwindInfo::saved_registers)
    }

    /// 展开信息说的帧寄存器（frame pointer）；`None` = 没有帧指针。
    #[must_use]
    pub fn frame_register(&self) -> Option<&str> {
        self.decoded
            .as_ref()
            .and_then(|detail| detail.frame_register.as_deref())
    }

    /// 这一条展开信息自己的说明（未识别的操作等）。没有解码时为空。
    #[must_use]
    pub fn notes(&self) -> &[String] {
        match &self.decoded {
            Some(detail) => detail.notes.as_slice(),
            None => &[],
        }
    }
}

/// PE `UNWIND_INFO` 解码结果（x64 展开信息）。
///
/// # 它是"帧大小 + 保存寄存器"的权威来源
///
/// 编译器生成的展开表描述"如何撤销这个函数的栈操作"，其中前导段
/// （prologue）的指令序列直接决定栈帧大小与保存了哪些寄存器。
/// 栈帧视图（M6）拿它做**交叉核对**：与前导扫描对照，两边一致才敢
/// 说是帧大小。
///
/// # 边界：只解码能确定的
///
/// 版本号、标志位、前导大小、帧寄存器、保存/分配操作都直接取自
/// `UNWIND_INFO`。XMM 保存记录在案但**不计入帧大小**（它们也占栈，
/// 但字节数取决于浮点寄存器宽度，先不猜）；看不懂的操作原样记下，
/// 让上层如实显示"有未识别的展开操作"。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PeUnwindInfo {
    /// 展开信息版本（0 = 仅 x64 语义，1 = 含 ARM64）。
    pub version: u8,
    /// 标志位（低 3 位：EHANDLER / UHANDLER / CHAININFO）。
    pub flags: u8,
    /// 前导长度（字节）。
    pub prologue_size: u8,
    /// 帧寄存器（`SET_FPREG` 或 `FrameRegister` 字段）；`None` = 无帧指针。
    pub frame_register: Option<String>,
    /// 帧寄存器相对前导结束时 RSP 的偏移（`FrameOffset << 4`，单位字节）。
    pub frame_offset: u32,
    /// 展开操作序列（按前导顺序）。
    pub ops: Vec<PeUnwindOp>,
    /// 解码过程中的说明（无法定位、未知操作等）。
    pub notes: Vec<String>,
}

/// 一条 `UNWIND_CODE` 展开操作。
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PeUnwindOp {
    /// `push reg`：保存非易失寄存器，占 8 字节栈。
    PushNonVolatile {
        /// 寄存器名。
        reg: String,
        /// 该 push 在**最终** RSP 之上的偏移（即相对帧顶的槽位）。
        slot_from_top: u64,
    },
    /// `sub rsp, size`：栈分配。
    Alloc {
        /// 分配字节数。
        size: u32,
    },
    /// `mov <frame_reg>, rsp`：建立帧指针。
    SetFramePointer {
        /// 帧寄存器名。
        reg: String,
    },
    /// `mov [rsp+off*8], reg`：把寄存器保存到栈槽。
    SaveNonVolatile {
        /// 寄存器名。
        reg: String,
        /// 缩放前的偏移（实际偏移 = `scaled * 8`）。
        scaled_offset: u32,
    },
    /// `mov [rsp+off], reg`：32 位偏移版本。
    SaveNonVolatileFar {
        /// 寄存器名。
        reg: String,
        /// 实际偏移（字节）。
        offset: u32,
    },
    /// XMM 寄存器保存（128 位）。**不计入帧大小**（见 [`PeUnwindInfo`]）。
    SaveXmm {
        /// 寄存器名。
        reg: String,
        /// 实际偏移（字节）。
        offset: u32,
    },
    /// `push machineframe`：异常帧（中断/异常处理用）。
    PushMachineFrame {
        /// 机器帧宽度（字节）。
        size: u32,
    },
    /// 未识别的操作码。原样保留，让上层如实显示。
    Unknown {
        /// 未识别操作码值。
        opcode: u8,
        /// 操作数信息。
        info: u8,
        /// 在前导中的偏移。
        prolog_offset: u8,
    },
}

impl PeUnwindInfo {
    /// 从展开操作累计出的栈帧大小（字节）。
    ///
    /// 只累计"确定占栈"的操作：push 与 alloc。XMM 保存、未知操作
    /// **不计入** —— 宁可低估并在 notes 里说明，也不要猜一个数。
    #[must_use]
    pub fn frame_size(&self) -> Option<u64> {
        let mut total: u64 = 0;
        for op in &self.ops {
            match op {
                PeUnwindOp::PushNonVolatile { .. } => total += 8,
                PeUnwindOp::Alloc { size } => total += u64::from(*size),
                PeUnwindOp::PushMachineFrame { size } => total += u64::from(*size),
                // 保存不分配栈；未知/XMM 不猜
                _ => {}
            }
        }
        Some(total)
    }

    /// 保存了哪些非易失寄存器（push 或 save）。
    #[must_use]
    pub fn saved_registers(&self) -> Vec<&str> {
        let mut out = Vec::new();
        for op in &self.ops {
            match op {
                PeUnwindOp::PushNonVolatile { reg, .. } => out.push(reg.as_str()),
                PeUnwindOp::SaveNonVolatile { reg, .. } => out.push(reg.as_str()),
                PeUnwindOp::SaveNonVolatileFar { reg, .. } => out.push(reg.as_str()),
                // XMM 保存也是保存动作（Windows x64 的非易失 XMM6–15），
                // 只是占栈宽度未计入 frame_size —— 见 notes 的说明。
                PeUnwindOp::SaveXmm { reg, .. } => out.push(reg.as_str()),
                _ => {}
            }
        }
        out
    }
}

/// 对象的格式细节（各格式共有的头字段归一化）。
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct FormatInfo {
    /// 格式内部标识（例如 ELF `e_type` 的 `ET_DYN`、PE 的 `DLL`）。
    pub type_name: Option<String>,
    /// 目标操作系统 / ABI。
    pub os_abi: Option<String>,
    /// 子系统（PE）或空。
    pub subsystem: Option<String>,
    /// 是否为动态库 / 共享对象。
    pub is_dynamic_library: bool,
    /// 是否为可执行文件。
    pub is_executable: bool,
    /// 是否为可重定位目标文件（`.o` / `.obj`）。
    pub is_relocatable: bool,
    /// 是否已剥离符号。
    pub is_stripped: bool,
    /// 文件头声明的大小（用于校验文件是否被裁剪）。
    pub declared_size: Option<u64>,
}

/// ObjC 选择器引用（`__objc_selrefs` 里的一格）。
///
/// 一格就是一个**指针槽**：槽里的值指向 `__objc_methname` 里的选择器名。
/// `slot` 是槽自己的地址（调用点用它来认"这条消息发的是哪个选择器"），
/// `target` 是名字字符串的地址。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ObjcSelectorRef {
    /// 槽地址（`__objc_selrefs` 里的那一格）。
    pub slot: u64,
    /// 槽指向的字符串地址（选择器名在 `__objc_methname` 里）。
    pub target: u64,
    /// 选择器名（`initWithPathForMainBundle:` 这种）。
    pub name: String,
}

/// ObjC 方法（方法表里的一项）。
///
/// `types` 是类型编码（`v24@0:8@16` 这种），`imp` 是实现地址。
/// 两者解不出来时是 `None` —— 那是**确实不知道**，不是"零值也不是空串"。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ObjcMethod {
    /// 方法表地址（`method_list_t` 自己的地址）。
    pub list: u64,
    /// 选择器名。
    pub selector: String,
    /// 类型编码。解不出时是 `None`。
    pub types: Option<String>,
    /// 实现地址（IMP）。解不出时是 `None`。
    pub imp: Option<u64>,
}

/// ObjC 消息转发桩（`__objc_stubs` 里的一格）。
///
/// 这种桩先取出一个选择器，再跳到 `objc_msgSend`。**桩地址本身就是这条消息的
/// 全部意义**：把桩解析成"调用了 objc_msgSend"会把选择器丢掉（见
/// `bitflip_core::import_edges` 的模块文档）。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ObjcStub {
    /// 桩地址。
    pub address: u64,
    /// 桩对应的选择器名。
    pub selector: String,
}

/// ObjC 类（`__objc_classlist` 里的一格解出来的）。
///
/// 这张表回答的是**归属**问题：前面那一版的 objc 解析只给"选择器 → 实现地址"，
/// 于是界面上只有一百多个裸选择器，看不出它们分别属于哪个类。类结构
/// （`class_t` → `class_ro_t`）里写着类名与方法表的连接，所以这里能说
/// "`-[LiveContainer setup]`"而不只是"`setup`"。
///
/// 每一项都可能是 `None`：名字读不到、父类指针是 bind（父类在别的库里）——
/// 那是**确实不知道**，不编造（CLAUDE.md §7）。
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ObjcClass {
    /// 类对象地址（`class_t` 自己的地址）。
    pub address: u64,
    /// 类名（来自 `class_ro_t.name`）。读不到时 `None`。
    pub name: Option<String>,
    /// 父类名（`class_t.superclass` → 父类的 `class_ro_t.name`）。
    ///
    /// 父类是外部符号（例如 `NSObject` 来自 Foundation）时指针是 bind，
    /// 静态文件里没有名字 ⇒ `None`。
    pub superclass: Option<String>,
    /// 实例方法（`class_ro_t.baseMethods`）。
    pub instance_methods: Vec<ObjcMethod>,
    /// 类方法（元类的 `class_ro_t.baseMethods`）。
    pub class_methods: Vec<ObjcMethod>,
    /// 实例变量名（`class_ro_t.ivars`）。
    pub ivars: Vec<String>,
    /// 遵循的协议名（`class_ro_t.baseProtocols`）。
    pub protocols: Vec<String>,
}

/// ObjC 类别（`__objc_catlist` 里的一格）。
///
/// 类别**没有自己的类**：它给已有的类加方法。所以这里的 `class_name` 是
/// "被扩展的类"，`name` 是类别自己的名字（`LiveContainer (Hooks)` 里的 `Hooks`）。
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ObjcCategory {
    /// 类别对象地址（`category_t` 自己的地址）。
    pub address: u64,
    /// 类别名（`category_t.name`）。
    pub name: Option<String>,
    /// 被扩展的类名（`category_t.cls` → 那个类的 `class_ro_t.name`）。
    pub class_name: Option<String>,
    /// 类别里的实例方法。
    pub instance_methods: Vec<ObjcMethod>,
    /// 类别里的类方法。
    pub class_methods: Vec<ObjcMethod>,
}

/// ObjC 元数据（来自 `__objc_*` 节）。
///
/// 只有一个二进制里真的带 objc 元数据时才有内容；**空表 ≠ "这个二进制没有
/// objc"** —— 别的格式（PE/ELF/COFF）根本没有这套节，那种情形是
/// "这个格式里没有这样一张表"（见 `notes`）。
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ObjcMetadata {
    /// 选择器引用（`__objc_selrefs`）。
    pub selector_refs: Vec<ObjcSelectorRef>,
    /// 方法（`__objc_methlist` 与类的方法表）。
    ///
    /// 只有 `__objc_methlist` 里那部分（老 ABI 会把所有方法表连成一节）；
    /// 现代二进制里每个类的方法表是**独立的**，那部分在 [`Self::classes`] 与
    /// [`Self::categories`] 里，按类归属给出来。
    pub methods: Vec<ObjcMethod>,
    /// 消息转发桩（`__objc_stubs`）。
    pub stubs: Vec<ObjcStub>,
    /// 类（`__objc_classlist`）：类名 + 实例方法 + 类方法 + ivar + 协议。
    pub classes: Vec<ObjcClass>,
    /// 类别（`__objc_catlist`）。
    pub categories: Vec<ObjcCategory>,
    /// 类名池（`__objc_classname`）里的名字。
    pub class_names: Vec<String>,
    /// 解析说明（降级、未能解析的部分）。
    pub notes: Vec<String>,
}

impl ObjcMetadata {
    /// 这份元数据里有没有任何内容。
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.selector_refs.is_empty()
            && self.methods.is_empty()
            && self.stubs.is_empty()
            && self.classes.is_empty()
            && self.categories.is_empty()
            && self.class_names.is_empty()
    }
}

/// 一个 Swift 描述符解出来的名字（mangled）。
///
/// 保留 mangled 原文而**不做** Swift demangle：demangle 是完整的符号文法还原，
/// 做不好会把名字搅乱；mangled 名本身已可读（`_$s7SideStore12ImportExportC`），
/// 下游可自行决定要不要 demangle。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SwiftSymbol {
    /// 描述符自身地址（虚拟地址）。
    pub address: u64,
    /// mangled 名字（文件里的原始字节，读到第一个 NUL 为止）。
    pub name: String,
}

/// Swift 元数据（`__swift5_*`）的解析结果。**尽量少猜**：解不出来的计入 `skipped` 并说明。
///
/// 只有 Mach-O 有这套节；其它格式是空表（"这个格式没有这个概念"，§7）。
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct SwiftMetadata {
    /// `__swift5_types` 里的类型（解出名字的那些）。
    pub types: Vec<SwiftSymbol>,
    /// `__swift5_protos` 里的协议（解出名字的那些）。
    pub protocols: Vec<SwiftSymbol>,
    /// `__swift5_entry` 是否存在（Swift 入口点）。
    pub has_entry: bool,
    /// 类型条目总数（含没解出名字的），用于"解出几个 / 一共几个"的对照。
    pub type_count: usize,
    /// 协议条目总数。
    pub protocol_count: usize,
    /// 存在但**没有解析**的其它 Swift 节（节名 + 字节数），如实列出。
    pub unparsed_sections: Vec<(String, u64)>,
    /// 条目里相对指针解不出来的个数（越界 / 落在非节区 / 名字不是合法 C 串）。
    pub skipped: usize,
    /// 解析说明（降级、跳过、未做项）。
    pub notes: Vec<String>,
}

impl SwiftMetadata {
    /// 这份元数据里有没有任何内容（用于"没 Swift 就什么都不显示"）。
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.types.is_empty()
            && self.protocols.is_empty()
            && !self.has_entry
            && self.unparsed_sections.is_empty()
    }
}

/// 代码签名里 CodeDirectory 声明的哈希算法（Swift/Mach-O 规范里的 `hashType`）。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HashAlgorithm {
    /// `hashType == 1`：SHA-1，20 字节。
    Sha1,
    /// `hashType == 2`：SHA-256，32 字节。
    Sha256,
    /// `hashType == 3`：SHA-256 截断（20 字节）。
    Sha256Truncated,
    /// `hashType == 4`：SHA-384，48 字节。
    Sha384,
}

impl HashAlgorithm {
    /// 规范里的 `hashType` 字节 → 算法；未知值返回 `None`（不猜）。
    #[must_use]
    pub fn from_hash_type(value: u8) -> Option<Self> {
        match value {
            1 => Some(Self::Sha1),
            2 => Some(Self::Sha256),
            3 => Some(Self::Sha256Truncated),
            4 => Some(Self::Sha384),
            _ => None,
        }
    }

    /// 规范名（`SHA-1` / `SHA-256` / …）。
    #[must_use]
    pub fn name(self) -> &'static str {
        match self {
            Self::Sha1 => "SHA-1",
            Self::Sha256 => "SHA-256",
            Self::Sha256Truncated => "SHA-256(截断)",
            Self::Sha384 => "SHA-384",
        }
    }

    /// 本模块**是否真能校验**它。只接 SHA-1 / SHA-256；截断与 SHA-384 没接（如实标"不支持"）。
    #[must_use]
    pub fn is_verifiable(self) -> bool {
        matches!(self, Self::Sha1 | Self::Sha256)
    }
}

/// 代码签名的有界校验结论。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CodeSignVerdict {
    /// 没有 `LC_CODE_SIGNATURE`（未签名）。
    NotSigned,
    /// 有签名，但**没有 CMS 签名槽**（`CSSLOT_SIGNATURESLOT`）——ad-hoc 签名。
    AdHoc,
    /// 读了 CodeDirectory，但算法本模块不校验（SHA-384 / 截断 / 未知 hashType）。
    UnsupportedAlgorithm,
    /// 签名区结构读不出来（SuperBlob / CodeDirectory magic 或长度不对）。
    Malformed,
    /// 所有 code page 的哈希都与 CodeDirectory 里存的槽一致（**完整性**通过）。
    Intact,
    /// 有 code page 的哈希对不上（从 `first_mismatch` 起出现不一致）。
    Mismatch,
}

/// 一条 entitlement 的值（XML plist 里能低风险识别的那几种）。
///
/// 只解**标量布尔/字符串**与**字符串数组**——这是 iOS entitlements 的绝大多数形态。
/// 更复杂的嵌套（dict 里套 dict、data 等）不强行解，标 `Other`（§7：不知道就说不知道）。
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum EntitlementValue {
    /// `<true/>` / `<false/>`。
    Bool(bool),
    /// `<string>…</string>`。
    String(String),
    /// `<array>` 里的一串 `<string>`。
    Strings(Vec<String>),
    /// 其它形态（嵌套 dict / data / integer / real …）：**没解**，只保留原始元素名。
    Other(String),
}

/// 一条 entitlement：键 + 值。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Entitlement {
    /// 键（如 `get-task-allow`、`application-identifier`）。
    pub key: String,
    /// 值。
    pub value: EntitlementValue,
}

/// 从签名里解出的 entitlements 事实。
///
/// `list` 是 XML plist（`CSSLOT_ENTITLEMENTS`，magic `0xfade7171`）里按出现顺序解出的键值。
/// 另外记录是否还存在 **DER 形态**的 entitlements（`0xfade7172`）：那个是另一种编码，
/// 本模块**不解**，只报存在（不猜内容）。
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct Entitlements {
    /// 解出的键值（按 plist 里的顺序）。
    pub list: Vec<Entitlement>,
    /// 是否还存在 DER 编码的 entitlements（`0xfade7172`）：存在但不解。
    pub has_der_form: bool,
}

impl Entitlements {
    /// 有没有任何内容。
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.list.is_empty() && !self.has_der_form
    }

    /// 按 key 找一条（便于调用方取 `get-task-allow` 之类）。
    #[must_use]
    pub fn get(&self, key: &str) -> Option<&EntitlementValue> {
        self.list
            .iter()
            .find(|item| item.key == key)
            .map(|item| &item.value)
    }
}

/// 需求（`CSSLOT_REQUIREMENTS`，type 2）blob 的存在性事实。
///
/// **只报存在与字节数，不实现需求表达式求值**——那是一个独立的表达式语言（opcode 流 +
/// 证书/信息项匹配），超出"有界、可离线复现"的范围。
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct Requirements {
    /// 是否有 requirements blob。
    pub present: bool,
    /// blob 头里声明的字节数（含 8 字节 blob 头）。
    pub size: u64,
}

/// 一个 Mach-O 的代码签名摘要 + 有界完整性校验结果。
///
/// **只校验完整性**：逐页重算文件哈希、与 CodeDirectory 里存的 code slot 比对。
/// **不校验**信任链（CMS / X.509）、不校资源封印（`CodeResources`）、不校需求
/// （Requirement）。这些都超出"离线、可复现、有界"的范围，`notes` 里逐条写明。
///
/// 只有 Mach-O 有这套概念；其它格式 `Object::signature` 为 `None`。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CodeSignature {
    /// CodeDirectory 声明的哈希算法。
    pub algorithm: HashAlgorithm,
    /// CodeDirectory 的 identifier（如 `com.kdt.livecontainer` / `SideStore`）。
    pub identifier: String,
    /// 被哈希覆盖的文件字节上限（`codeLimit`）：签名数据本身在它之外。
    pub code_limit: u64,
    /// 分页大小（字节）。
    pub page_size: u64,
    /// CodeDirectory 声明的 code slot 总数。
    pub code_slots: u64,
    /// 实际逐页**校验通过**的 slot 数（≤ `code_slots`；不支持算法时为 0）。
    pub verified_slots: u64,
    /// 第一个不一致的 slot 下标（`Mismatch` 时有值）。
    pub first_mismatch: Option<u64>,
    /// SuperBlob 里是否带 CMS 签名槽（`CSSLOT_SIGNATURESLOT`，type 0x1000）。
    pub has_cms_signature: bool,
    /// 从 XML entitlements blob 解出的键值（没有就是 `None`，不编造）。
    pub entitlements: Option<Entitlements>,
    /// CodeDirectory 的 CDHash（对整段 CodeDirectory 按 `hashType` 再哈希，小写十六进制）。
    ///
    /// 这是**签名结构的指纹**（`codesign -d` 里那个 `CDHash`），与"内容是否被改"无关。
    /// 算不出（SHA-384 未接 / 结构缺失）为 `None`，不猜。
    pub cd_hash: Option<String>,
    /// 需求（type 2）blob 的存在性事实（不实现求值）。
    pub requirements: Requirements,
    /// 结论。
    pub verdict: CodeSignVerdict,
    /// 解析与校验说明（降级、未做项，§7）。
    pub notes: Vec<String>,
}

impl CodeSignature {
    /// 有没有"读出了签名结构"（ad-hoc 及以上；未签名/读坏了没有）。
    #[must_use]
    pub fn is_signed(&self) -> bool {
        !matches!(
            self.verdict,
            CodeSignVerdict::NotSigned | CodeSignVerdict::Malformed
        )
    }

    /// 一个"未签名"的结果：Mach-O 里没有 `LC_CODE_SIGNATURE` 时用它。
    ///
    /// 注意与 `Object::signature == None` 的区别：`None` 是"这个格式没有代码签名
    /// 这个概念"（非 Mach-O）；`not_signed()` 是"这是 Mach-O，但它没签名"（§7）。
    #[must_use]
    pub fn not_signed() -> Self {
        Self {
            algorithm: HashAlgorithm::Sha256,
            identifier: String::new(),
            code_limit: 0,
            page_size: 0,
            code_slots: 0,
            verified_slots: 0,
            first_mismatch: None,
            has_cms_signature: false,
            entitlements: None,
            cd_hash: None,
            requirements: Requirements::default(),
            verdict: CodeSignVerdict::NotSigned,
            notes: vec!["没有 LC_CODE_SIGNATURE：这个 Mach-O 未签名".to_string()],
        }
    }
}

/// 解析结果：一个可分析的对象。
#[derive(Debug, Clone)]
pub struct Object {
    /// 容器内标识。
    pub id: ObjectId,
    /// 对象格式。
    pub kind: crate::ObjectKind,
    /// 架构 + 位宽 + 端序。
    pub arch: ArchSpec,
    /// 字节序。
    pub endian: Endian,
    /// 归一化的格式细节。
    pub format: FormatInfo,
    /// 镜像基址。
    pub image_base: u64,
    /// 入口点；`None` 表示该对象没有入口（例如 `.o`）。
    pub entry: Option<u64>,
    /// 函数起点（绝对虚拟地址，**升序**）。
    ///
    /// 来源是 Mach-O 的 `LC_FUNCTION_STARTS`（dyld 用它按需建立函数边界，表里
    /// 存的是 ULEB128 增量，解析器已还原成地址）。**其他格式是空表** ——
    /// 那同样是"这个格式里没有这样一张表"的如实未知，不是"这个文件没有函数"：
    /// PE 的函数边界在 `.pdata`（见 [`Object::unwind`]），ELF 没有等价的表，
    /// 只能靠符号表或反汇编识别。
    ///
    /// 空表 ≠ "没有函数"。想区分"表不存在"与"表是空的"，看 `notes`：
    /// 解析器对这两种情形写的是**不同**的说明（CLAUDE.md §7）。
    pub function_starts: Vec<u64>,
    /// `LC_UUID` 的 16 字节，小写十六进制（32 个字符）。
    ///
    /// 只有 Mach-O 有这个概念（dyld 用它标识镜像）。**其他格式是 `None`** ——
    /// 那是"这个格式里没有这样一个字段"的如实未知，不是"读出来是空的"。
    /// 所以不要拿 `None` 去推断"符号表里没有 UUID"，那是两件事。
    pub uuid: Option<String>,
    /// 依赖库名（Mach-O 的 `LC_LOAD_DYLIB` / `LC_LOAD_WEAK_DYLIB`，按命令顺序）。
    ///
    /// 只有 Mach-O 有：PE 的依赖在导入表里（见 [`Import::module`]）、
    /// ELF 的依赖在 `.dynamic` 的 `DT_NEEDED` 里（本片也没有归一化到这一层）。
    /// **其他格式是空表** —— 同样的如实未知，不是"没有依赖"。
    ///
    /// 顺序**保序**：加载命令的先后是文件里的事实，重排会丢掉信息。
    pub dylibs: Vec<String>,
    /// 段（内存视角）。
    pub segments: Vec<Segment>,
    /// 节（文件视角）。
    pub sections: Vec<Section>,
    /// 导入。
    pub imports: Vec<Import>,
    /// 导出。
    pub exports: Vec<Export>,
    /// 原始符号。
    pub symbols: Vec<RawSymbol>,
    /// 重定位。
    pub relocations: Vec<Reloc>,
    /// 展开表。
    pub unwind: Vec<UnwindEntry>,
    /// 格式头里架构相关的标志位原始值。
    ///
    /// ELF 是 `e_flags`，PE/COFF 是 `Characteristics`。语义随架构变化，
    /// 因此保存原始值而不强行归一化 —— 强行归一化会丢掉信息并可能解读错误。
    pub header_flags: Option<u32>,
    /// ObjC 元数据（选择器、方法、消息桩）。
    ///
    /// 只有 Mach-O 有这套概念。**其他格式是空表** —— 同样的如实未知，
    /// 不是"这个二进制里没有 objc"。
    pub objc: ObjcMetadata,
    /// Swift 元数据（`__swift5_*`）。
    ///
    /// 只有 Mach-O 有这套节。**其他格式是空表** —— 与 `objc` 一样，是"这个格式没有
    /// 这个概念"，不是"这个二进制里没有 Swift 代码"的否定结论（§7）。
    pub swift: SwiftMetadata,
    /// 代码签名摘要 + 有界完整性校验（只有 Mach-O 有；其它格式是 `None`）。
    ///
    /// `None` = "这个对象没有代码签名这个概念"（非 Mach-O），或"没读到签名区"；
    /// Mach-O 里"没有 `LC_CODE_SIGNATURE`"会给出 `verdict = NotSigned` 的 `Some` 值，
    /// 两者在语义上要分开（§7）。
    pub signature: Option<CodeSignature>,
    /// 解析过程中的说明（降级、跳过、未支持项）。
    ///
    /// 这是"诚实"的载体：任何没解析出来的东西都要在这里留下痕迹，
    /// 不能让 UI 呈现一个看起来完整但实际缺数据的视图（见 CLAUDE.md §7）。
    pub notes: Vec<String>,
}

impl Object {
    /// 把**推迟解码**的展开条目真正解出来，返回解出了多少条。
    ///
    /// # 为什么要单独一步，而不是在解析时就解
    ///
    /// `.pdata` 在 64 位 PE 里每个函数一条记录。实测 `owo-terminal.exe`
    /// （201 MiB）有 **417,629** 条，解析时全部解开要 **1.2 秒** —— 而
    /// `info` / `functions` 的入口路径一个字段都用不到它们。真正的消费者只有
    /// 栈帧视图（`bitflip-analyze::frames`）。
    ///
    /// 所以解析只建表（读三个 RVA，那才是函数边界要用的），解码推迟到
    /// 确实要问帧大小时。本方法就是那个"确实要问"的时刻。
    ///
    /// # 诚实性
    ///
    /// - 返回"解出了多少条"而不是默默做完：调用方要把这个数字写进 `notes`，
    ///   否则用户看到"帧大小只能靠前导扫描"却不知道为什么（CLAUDE.md §7）。
    /// - 解不出来的条目保持 `decoded = None` 且 `deferred = false` —— 那是
    ///   **确定的**"这条没有展开细节"，与"还没解"分得开。
    /// - 重复调用只解没解过的，不会重复计费。
    ///
    /// # 参数
    ///
    /// `bytes` 是对象的**完整文件字节**（与 `parse_object` 传入的是同一份）。
    /// `base` 是加载基址，要与解析时一致。
    pub fn resolve_unwind(&mut self, bytes: &[u8], base: u64) -> usize {
        let pending: Vec<usize> = self
            .unwind
            .iter()
            .enumerate()
            .filter(|(_, entry)| entry.is_deferred())
            .map(|(index, _)| index)
            .collect();
        if pending.is_empty() {
            return 0;
        }

        let reader = crate::reader::Reader::with_base(bytes, base);
        // `Reader` 借用了 `bytes`，而 `resolve` 需要 `&Object` —— 用 take/put
        // 把 unwind 临时移出来，避免同时借 `self` 的可变与不可变。
        let mut entries = std::mem::take(&mut self.unwind);
        let mut decoded = 0usize;
        for index in pending {
            entries[index].resolve(&reader, self);
            if entries[index].decoded.is_some() {
                decoded += 1;
            }
        }
        self.unwind = entries;
        decoded
    }
}

impl Object {
    /// 空对象骨架（解析器逐步填充）。
    #[must_use]
    pub fn new(id: ObjectId, kind: crate::ObjectKind, arch: ArchSpec, endian: Endian) -> Self {
        Self {
            id,
            kind,
            arch,
            endian,
            format: FormatInfo::default(),
            image_base: 0,
            entry: None,
            function_starts: Vec::new(),
            uuid: None,
            dylibs: Vec::new(),
            segments: Vec::new(),
            sections: Vec::new(),
            imports: Vec::new(),
            exports: Vec::new(),
            symbols: Vec::new(),
            relocations: Vec::new(),
            unwind: Vec::new(),
            header_flags: None,
            objc: ObjcMetadata::default(),
            swift: SwiftMetadata::default(),
            signature: None,
            notes: Vec::new(),
        }
    }

    /// 记录一条降级说明（去重，避免同一条重复几十次刷屏）。
    pub fn note(&mut self, message: impl Into<String>) {
        let message = message.into();
        if !self.notes.contains(&message) {
            self.notes.push(message);
        }
    }

    /// 按虚拟地址查找所在段。
    #[must_use]
    pub fn segment_at(&self, addr: u64) -> Option<&Segment> {
        // 段数量很小（通常 < 20），线性扫描比建索引更省事且无维护成本。
        self.segments.iter().find(|segment| segment.contains(addr))
    }

    /// 按虚拟地址查找所在节。
    ///
    /// 与 [`Self::segment_at`] 的分工：段是**内存视角**（加载器按权限归类），
    /// 节是**文件视角**（链接器/编译器写的）。两者边界并不一致，所以不能互相替代。
    ///
    /// 注意：**可重定位对象（`.o`/`.obj`）的节虚拟地址通常全是 0**，此时
    /// 该函数无法区分节 —— 那种情况下"这个地址属于哪一节"只能由数据来源
    /// 自己说清（例如 [`Reloc::section`]）。
    #[must_use]
    pub fn section_at(&self, addr: u64) -> Option<&Section> {
        self.sections
            .iter()
            .find(|section| addr >= section.vaddr && addr - section.vaddr < section.file.size)
    }

    /// 按名称查找节。
    #[must_use]
    pub fn section_by_name(&self, name: &str) -> Option<&Section> {
        self.sections.iter().find(|section| section.name == name)
    }

    /// 反映射：虚拟地址 → 文件偏移。
    ///
    /// 返回 `None` 表示该地址没有文件后备（.bss 之类）。
    pub fn vaddr_to_offset(&self, addr: u64) -> Option<u64> {
        for segment in &self.segments {
            if !segment.contains(addr) {
                continue;
            }
            let file = segment.file?;
            let delta = addr - segment.vaddr;
            if delta >= file.size {
                // 落在段的零填充部分（BSS）
                return None;
            }
            return file.offset.checked_add(delta);
        }
        None
    }

    /// 文件偏移 → 虚拟地址（IMAGE_SCN 的 `PointerToRawData` 反查）。
    pub fn offset_to_vaddr(&self, offset: u64) -> Option<u64> {
        for segment in &self.segments {
            let file = match segment.file {
                Some(file) if !file.is_empty() => file,
                _ => continue,
            };
            if offset < file.offset {
                continue;
            }
            let delta = offset - file.offset;
            if delta >= file.size {
                continue;
            }
            return segment.vaddr.checked_add(delta);
        }
        None
    }

    /// 供 UI 顶部摘要使用的一行结论。
    #[must_use]
    pub fn summary_zh(&self) -> String {
        let entry = match self.entry {
            Some(addr) => format!("{addr:#x}"),
            None => "-".to_string(),
        };
        let detail = match self.kind {
            crate::ObjectKind::Elf => self
                .format
                .type_name
                .clone()
                .unwrap_or_else(|| "ELF".to_string()),
            crate::ObjectKind::Pe => self
                .format
                .type_name
                .clone()
                .unwrap_or_else(|| "PE".to_string()),
            other => other.as_str().to_string(),
        };
        format!(
            "{detail} / {} / 入口 {entry}，节 {}，段 {}",
            self.arch,
            self.sections.len(),
            self.segments.len()
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use bitflip_arch::{Arch, ArchSpec, Mode};

    fn spec() -> ArchSpec {
        ArchSpec::from_arch(Arch::X86_64, Mode::M64, Endian::Little)
    }

    fn sample() -> Object {
        let mut obj = Object::new(
            ObjectId::Plain,
            crate::ObjectKind::Elf,
            spec(),
            Endian::Little,
        );
        obj.segments.push(Segment {
            name: ".text".into(),
            vaddr: 0x1000,
            vsize: 0x200,
            file: Some(FileRange::new(0x1000, 0x200)),
            perms: Perms {
                read: true,
                write: false,
                execute: true,
            },
            kind: ContentKind::Code,
            align: 16,
        });
        obj.segments.push(Segment {
            name: ".bss".into(),
            vaddr: 0x2000,
            vsize: 0x100,
            file: None,
            perms: Perms {
                read: true,
                write: true,
                execute: false,
            },
            kind: ContentKind::Bss,
            align: 16,
        });
        obj
    }

    #[test]
    fn a_fresh_object_reports_uuid_and_dylibs_as_unknown_not_empty() {
        // 空骨架的含义是"还没有从文件里读到"，不是"文件里写的就是空的"。
        // 这条钉住默认值：非 Mach-O 的解析器不填这两个字段，结论就该是
        // `None` / 空表（CLAUDE.md §7：未知用 None，不用空串/0 冒充）。
        let obj = sample();
        assert_eq!(obj.uuid, None);
        assert!(obj.dylibs.is_empty());
        // `function_starts` 同理：只有 Mach-O 的 `LC_FUNCTION_STARTS` 会填它，
        // 其他格式留空表（"没有这样一张表"）。断言它不是"默认有一个假起点"。
        assert!(obj.function_starts.is_empty());
    }

    #[test]
    fn perms_render_as_rwx() {
        let perms = Perms {
            read: true,
            write: false,
            execute: true,
        };
        assert_eq!(perms.to_rwx(), "r-x");
        assert_eq!(Perms::none().to_rwx(), "---");
        let rw = Perms {
            read: true,
            write: true,
            execute: false,
        };
        assert_eq!(rw.to_rwx(), "rw-");
    }

    #[test]
    fn segment_contains_is_wraparound_safe() {
        let seg = Segment {
            name: ".text".into(),
            vaddr: 0x1000,
            vsize: 0x100,
            file: Some(FileRange::new(0, 0x100)),
            perms: Perms::none(),
            kind: ContentKind::Code,
            align: 1,
        };
        assert!(seg.contains(0x1000));
        assert!(seg.contains(0x10ff));
        assert!(!seg.contains(0x1100));
        assert!(!seg.contains(0x0fff));
        // 关键：地址空间末尾不能让 contains 回绕成 true
        assert!(!seg.contains(u64::MAX));
        assert!(!seg.contains(0));
    }

    #[test]
    fn segment_end_vaddr_detects_overflow() {
        let seg = Segment {
            name: "bad".into(),
            vaddr: u64::MAX,
            vsize: 2,
            file: None,
            perms: Perms::none(),
            kind: ContentKind::Unknown,
            align: 1,
        };
        assert!(seg.end_vaddr().is_err());
    }

    #[test]
    fn vaddr_to_offset_maps_backed_regions_only() {
        let obj = sample();
        assert_eq!(obj.vaddr_to_offset(0x1000), Some(0x1000));
        assert_eq!(obj.vaddr_to_offset(0x1100), Some(0x1100));
        // .bss 没有文件后备 —— 必须返回 None，不能假装有偏移
        assert_eq!(obj.vaddr_to_offset(0x2000), None);
        // 段外
        assert_eq!(obj.vaddr_to_offset(0x3000), None);
    }

    #[test]
    fn offset_to_vaddr_is_the_inverse() {
        let obj = sample();
        assert_eq!(obj.offset_to_vaddr(0x1000), Some(0x1000));
        assert_eq!(obj.offset_to_vaddr(0x11ff), Some(0x11ff));
        assert_eq!(obj.offset_to_vaddr(0x1200), None);
        // 往返一致
        let addr = 0x1080;
        let offset = obj.vaddr_to_offset(addr).unwrap();
        assert_eq!(obj.offset_to_vaddr(offset), Some(addr));
    }

    #[test]
    fn segment_at_finds_the_right_segment() {
        let obj = sample();
        assert_eq!(obj.segment_at(0x1000).unwrap().name, ".text");
        assert_eq!(obj.segment_at(0x2050).unwrap().name, ".bss");
        assert!(obj.segment_at(0x0500).is_none());
    }

    #[test]
    fn note_deduplicates() {
        let mut obj = sample();
        obj.note("符号表缺失");
        obj.note("符号表缺失");
        obj.note("另一条");
        assert_eq!(obj.notes.len(), 2);
    }

    #[test]
    fn summary_mentions_format_arch_and_counts() {
        let mut obj = sample();
        obj.entry = Some(0x1010);
        obj.format.type_name = Some("ET_DYN".into());
        let summary = obj.summary_zh();
        assert!(summary.contains("ET_DYN"), "{summary}");
        assert!(summary.contains("x86_64"), "{summary}");
        assert!(summary.contains("0x1010"), "{summary}");
        assert!(summary.contains("段 2"), "{summary}");
    }

    #[test]
    fn summary_says_dash_when_entry_is_unknown() {
        let obj = sample();
        // 没有入口必须是 "-"，不能用 0 冒充
        assert!(obj.summary_zh().contains("入口 -"));
    }

    #[test]
    fn object_id_displays_readably() {
        assert_eq!(ObjectId::Plain.display(), "<主对象>");
        assert_eq!(ObjectId::ArchiveMember("mod.o".into()).display(), "mod.o");
    }
}
