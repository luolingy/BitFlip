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
    /// 需要修改的位置的虚拟地址。
    pub address: u64,
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
    pub decoded: Option<PeUnwindInfo>,
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
    /// 解析过程中的说明（降级、跳过、未支持项）。
    ///
    /// 这是"诚实"的载体：任何没解析出来的东西都要在这里留下痕迹，
    /// 不能让 UI 呈现一个看起来完整但实际缺数据的视图（见 CLAUDE.md §7）。
    pub notes: Vec<String>,
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
            segments: Vec::new(),
            sections: Vec::new(),
            imports: Vec::new(),
            exports: Vec::new(),
            symbols: Vec::new(),
            relocations: Vec::new(),
            unwind: Vec::new(),
            header_flags: None,
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
