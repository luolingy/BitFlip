//! 会话：一个被打开的目标及其识别结论。

use std::path::{Path, PathBuf};
use std::sync::Arc;

use bitflip_analyze::{JobHandle, NullSink, StageId};
use bitflip_arch::ArchSpec;
use bitflip_loader::object::{Object, ObjectId};
use bitflip_loader::{sniff_file, ContainerKind, Guess, ObjectKind};
use bitflip_project::ProjectStore;
use serde::Serialize;

use crate::disasm::Disasm;
use crate::error::BitflipError;
use bitflip_analyze::ScanOptions as DisasmScanOptions;

/// 地址的 wire 表示：定长小写 16 位十六进制（CLAUDE.md §4）。
fn hex16(value: u64) -> String {
    format!("{value:016x}")
}

/// 解析结果的 wire 版本号。
///
/// 消费者（脚本、UI）靠它判断字段含义是否变化。任何破坏性字段调整都必须递增，
/// 并在此处说明变更 —— 这是 M1 验收标准 2 要求的"稳定 schema"。
pub const INFO_FORMAT_VERSION: u32 = 1;

/// 节的 wire 表示。
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct SectionInfo {
    /// 节名（可能为空）。
    pub name: String,
    /// 虚拟地址（定长 hex）。
    pub vaddr: String,
    /// 文件偏移。
    pub file_offset: u64,
    /// 文件内大小。
    pub file_size: u64,
    /// 权限（`r-x` 形式）。
    pub perms: String,
    /// 内容类别短名。
    pub kind: String,
    /// 内容类别中文名。
    pub kind_label: String,
    /// 是否在运行时被映射。
    pub loaded: bool,
}

/// 段的 wire 表示（内存视角）。
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct SegmentInfo {
    /// 段名。
    pub name: String,
    /// 虚拟地址（定长 hex）。
    pub vaddr: String,
    /// 虚拟大小。
    pub vsize: u64,
    /// 对应的文件范围；`null` 表示不占文件空间（.bss）。
    pub file_offset: Option<u64>,
    /// 文件内大小。
    pub file_size: Option<u64>,
    /// 权限（`r-x` 形式）。
    pub perms: String,
    /// 内容类别短名。
    pub kind: String,
    /// 内容类别中文名。
    pub kind_label: String,
}

/// 符号的 wire 表示。
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct SymbolInfo {
    /// 符号名。
    pub name: String,
    /// 值（定长 hex）。
    pub value: String,
    /// 大小。
    pub size: u64,
    /// 是否已定义。
    pub defined: bool,
    /// 是否为函数。
    pub is_function: bool,
    /// 是否为弱符号。
    pub is_weak: bool,
    /// 所属节名。
    pub section: Option<String>,
    /// 来源（`symtab` / `dynsym` / `export` / `debug`）。
    pub source: String,
}

/// 导入的 wire 表示。
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct ImportInfo {
    /// 所属模块 / 依赖库名。
    pub module: String,
    /// 符号名。
    pub name: Option<String>,
    /// 序号。
    pub ordinal: Option<u32>,
    /// IAT / GOT 槽地址（定长 hex）。
    pub iat_slot: Option<String>,
}

/// 导出的 wire 表示。
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct ExportInfo {
    /// 导出名。
    pub name: String,
    /// 序号。
    pub ordinal: Option<u32>,
    /// 地址（定长 hex）。
    pub address: String,
    /// 转发目标。
    pub forwarder: Option<String>,
}

/// 重定位的 wire 表示。
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct RelocInfo {
    /// 待修改位置的地址（定长 hex）。
    pub address: String,
    /// 归一化类型。
    pub kind: String,
    /// 格式特有的原始类型编号。
    pub raw_kind: u32,
    /// 关联符号名。
    pub symbol: Option<String>,
}

/// 完整解析结果（对象级）。
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct ObjectInfo {
    /// 对象在容器内的标识。
    pub id: String,
    /// 格式类型名（`ET_DYN` / `DLL` 等）。
    pub format_type: Option<String>,
    /// 目标 OS/ABI（ELF）或子系统（PE）。
    pub os_abi: Option<String>,
    /// 子系统的中文名（PE）。
    pub subsystem: Option<String>,
    /// 是否为动态库 / 共享对象。
    pub is_dynamic_library: bool,
    /// 是否可执行。
    pub is_executable: bool,
    /// 是否可重定位目标文件。
    pub is_relocatable: bool,
    /// 是否已剥离符号。
    pub is_stripped: bool,
    /// 段（内存视角）。
    pub segments: Vec<SegmentInfo>,
    /// 节（文件视角）。
    pub sections: Vec<SectionInfo>,
    /// 导入。
    pub imports: Vec<ImportInfo>,
    /// 导出。
    pub exports: Vec<ExportInfo>,
    /// 符号。
    pub symbols: Vec<SymbolInfo>,
    /// 重定位。
    pub relocations: Vec<RelocInfo>,
    /// 解析说明（降级、跳过、未支持项）。
    pub notes: Vec<String>,
}

impl ObjectInfo {
    /// 由 loader 的对象构造。
    #[must_use]
    pub fn from_object(object: &Object) -> Self {
        Self {
            id: object.id.display(),
            format_type: object.format.type_name.clone(),
            os_abi: object.format.os_abi.clone(),
            subsystem: object.format.subsystem.clone(),
            is_dynamic_library: object.format.is_dynamic_library,
            is_executable: object.format.is_executable,
            is_relocatable: object.format.is_relocatable,
            is_stripped: object.format.is_stripped,
            segments: object
                .segments
                .iter()
                .map(|seg| SegmentInfo {
                    name: seg.name.clone(),
                    vaddr: hex16(seg.vaddr),
                    vsize: seg.vsize,
                    file_offset: seg.file.map(|f| f.offset),
                    file_size: seg.file.map(|f| f.size),
                    perms: seg.perms.to_rwx(),
                    kind: seg.kind.as_str().to_string(),
                    kind_label: seg.kind.label_zh().to_string(),
                })
                .collect(),
            sections: object
                .sections
                .iter()
                .map(|sec| SectionInfo {
                    name: sec.name.clone(),
                    vaddr: hex16(sec.vaddr),
                    file_offset: sec.file.offset,
                    file_size: sec.file.size,
                    perms: sec.perms.to_rwx(),
                    kind: sec.kind.as_str().to_string(),
                    kind_label: sec.kind.label_zh().to_string(),
                    loaded: sec.loaded,
                })
                .collect(),
            imports: object
                .imports
                .iter()
                .map(|imp| ImportInfo {
                    module: imp.module.clone(),
                    name: imp.name.clone(),
                    ordinal: imp.ordinal,
                    iat_slot: imp.iat_slot.map(hex16),
                })
                .collect(),
            exports: object
                .exports
                .iter()
                .map(|exp| ExportInfo {
                    name: exp.name.clone(),
                    ordinal: exp.ordinal,
                    address: hex16(exp.address),
                    forwarder: exp.forwarder.clone(),
                })
                .collect(),
            symbols: object
                .symbols
                .iter()
                .map(|sym| SymbolInfo {
                    name: sym.name.clone(),
                    value: hex16(sym.value),
                    size: sym.size,
                    defined: sym.defined,
                    is_function: sym.is_function,
                    is_weak: sym.is_weak,
                    section: sym.section.clone(),
                    source: sym.source.as_str().to_string(),
                })
                .collect(),
            relocations: object
                .relocations
                .iter()
                .map(|rel| RelocInfo {
                    address: hex16(rel.address),
                    kind: rel.kind.as_str().to_string(),
                    raw_kind: rel.raw_kind,
                    symbol: rel.symbol.clone(),
                })
                .collect(),
            notes: object.notes.clone(),
        }
    }
}

/// 打开目标时的选项。M0 只有占位字段，M2 起加入 raw 二进制的基址/架构覆写。
#[derive(Debug, Clone, Default)]
pub struct OpenOptions {
    /// 视作原始二进制（忽略格式嗅探），M2 实现。
    pub force_raw: bool,
}

/// 目标识别结论的对外表示（JSON wire 契约）。
///
/// 所有"未知"都显式表达为 `null` + `notes` 里的原因，不用 0 / 空串冒充。
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct TargetInfo {
    /// 本结构的 wire 版本号。
    pub format_version: u32,
    /// 目标路径。
    pub path: String,
    /// 文件大小（字节）。
    pub file_size: u64,
    /// 容器短名（`plain` / `ar` / `msvc-lib` / `fat`）。
    pub container: String,
    /// 容器中文名。
    pub container_label: String,
    /// 对象格式短名（`pe` / `coff` / `elf` / `macho` / `raw`）。
    pub object: String,
    /// 对象格式中文名。
    pub object_label: String,
    /// 归档成员格式（短名）。
    pub member_kind: Option<String>,
    /// 架构规格（`x86_64/64/le` 形式）。
    pub arch: Option<String>,
    /// 架构族（`x86_64`）。
    pub arch_family: Option<String>,
    /// 位宽（0 = 未知）。
    pub bits: u8,
    /// 端序（`le` / `be`）。
    pub endian: Option<String>,
    /// 入口点（定长 hex）。
    pub entry: Option<String>,
    /// 镜像基址（定长 hex，PE 有）。
    pub image_base: Option<String>,
    /// 节数。
    pub sections: Option<u16>,
    /// 归档成员数。
    pub member_count: usize,
    /// 成员列表是否被截断。
    pub members_truncated: bool,
    /// 一行中文摘要。
    pub summary: String,
    /// 判定依据与限制说明。
    pub notes: Vec<String>,
    /// 参与嗅探的字节数。
    pub sniffed_bytes: usize,
    /// 文件是否大于嗅探窗口。
    pub file_truncated: bool,
}

/// 完整解析（而非嗅探）允许的最大文件大小。
///
/// 解析要把整个文件读进内存，之后再按虚拟地址随机访问，因此上限由**内存**
/// 决定，而不是由嗅探窗口决定。取 512 MiB：能覆盖绝大多数真实二进制，
/// 又不至于在只有几 GB 可用内存的机器上把进程打爆。
///
/// 超过这个上限时明确拒绝并说清原因，绝不给"基于部分数据"的结论
/// （CLAUDE.md §7）。
pub const MAX_FULL_PARSE_BYTES: u64 = 512 * 1024 * 1024;

impl TargetInfo {
    fn from_guess(path: &Path, file_size: u64, guess: &Guess) -> Self {
        Self {
            format_version: INFO_FORMAT_VERSION,
            path: path.display().to_string(),
            file_size,
            container: guess.container.as_str().to_string(),
            container_label: guess.container.label_zh().to_string(),
            object: guess.object.as_str().to_string(),
            object_label: guess.object.label_zh().to_string(),
            member_kind: guess.member_kind.map(|k| k.as_str().to_string()),
            arch: guess.arch.map(|a| a.to_string()),
            arch_family: guess.arch.map(|a: ArchSpec| a.arch.as_str().to_string()),
            bits: guess.bits,
            endian: guess.endian.map(|e| e.as_str().to_string()),
            entry: guess.entry.map(hex16),
            image_base: guess.image_base.map(hex16),
            sections: guess.sections,
            member_count: guess.members.len(),
            members_truncated: guess.members_truncated,
            summary: guess.summary_zh(),
            notes: guess.notes.clone(),
            sniffed_bytes: guess.sniffed_bytes,
            file_truncated: guess.file_truncated,
        }
    }

    /// 是否为归档容器（ar / MSVC `.lib`）。
    #[must_use]
    pub fn is_archive(&self) -> bool {
        self.container == ContainerKind::Ar.as_str()
            || self.container == ContainerKind::MsvcLib.as_str()
    }

    /// 是否已识别出对象格式（非 raw）。
    #[must_use]
    pub fn object_identified(&self) -> bool {
        self.object != ObjectKind::Raw.as_str()
    }
}

/// 分析结果摘要（M0 占位；M2 起填入真实计数）。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize)]
pub struct AnalysisSummary {
    /// 已解码指令数。
    pub instructions: usize,
    /// 已识别函数数。
    pub functions: usize,
    /// 基本块数。
    pub basic_blocks: usize,
    /// 交叉引用数。
    pub xrefs: usize,
}

/// 一个打开的目标。
///
/// `Session` 是 `bitflip-core` 的核心类型，也是被其他项目嵌入时的入口。
/// 它是 `Send + Sync` 且可廉价共享（服务层用 `Arc<Session>`）。
#[derive(Debug, Clone)]
pub struct Session {
    path: PathBuf,
    guess: Guess,
    info: TargetInfo,
    object: Option<ObjectInfo>,
    object_raw: Option<Arc<Object>>,
    /// 整个文件的字节。
    ///
    /// 分析层需要按虚拟地址随机访问原始字节（反汇编、字符串搜索、交叉引用）。
    /// 用 `Arc<[u8]>` 而不是每次读盘：同一份字节要服务成千上万次查询，
    /// 且 `AddrSpace` 需要与它共享生命周期。
    ///
    /// 代价是文件大小的一份常驻内存 —— 这是 M2 验收指标里
    /// "内存 < 3× 文件大小"预算中的 1×。
    bytes: Arc<[u8]>,
    /// 目标内容哈希（sha256 小写十六进制）。
    ///
    /// 懒计算：打开一个 100MB 目标只为看一眼格式时，不该先付一次全文件
    /// 哈希的代价。用到（打开/创建工程库）时才算。
    hash: std::sync::OnceLock<String>,
}

impl Session {
    /// 打开目标：检查路径、嗅探格式，并做一次完整解析。
    ///
    /// 解析失败**不是**打开失败：嗅探结论仍然可用，此时 `parsed()` 返回 `None`
    /// 且原因记录在 `info().notes` 里。这样畸形文件也能被打开并查看"哪里坏了"，
    /// 而不是整个工具被一个坏节挡住（M1 要求"只返回错误，不 panic"）。
    pub fn open(path: impl AsRef<Path>, _opts: OpenOptions) -> Result<Self, BitflipError> {
        let path = path.as_ref().to_path_buf();
        let guess = sniff_file(&path)?;
        let file_size = std::fs::metadata(&path).map_or(guess.sniffed_bytes as u64, |m| m.len());
        let mut info = TargetInfo::from_guess(&path, file_size, &guess);

        let (object, object_raw) = match Self::parse_target(&path, file_size, &guess) {
            Ok(object) => {
                let wire = ObjectInfo::from_object(&object);
                (Some(wire), Some(Arc::new(object)))
            }
            Err(reason) => {
                // 明确说明"为什么没有解析结果"，不留空白
                info.notes.push(reason);
                (None, None)
            }
        };

        // 读入完整字节：分析层需要按虚拟地址随机访问。
        //
        // 只在解析成功时才读 ——  解析失败的目标反汇编无从谈起，
        // 没必要为一个"打不开的格式"占住文件大小的内存。
        let bytes: Arc<[u8]> = if object_raw.is_some() {
            match std::fs::read(&path) {
                Ok(data) => Arc::from(data),
                Err(error) => {
                    // 读失败不能让整个打开失败（嗅探与解析结论仍然有效），
                    // 但必须让用户知道反汇编不可用
                    info.notes.push(format!(
                        "读取文件字节失败（{error}），反汇编与字节级查询将不可用"
                    ));
                    Arc::from(Vec::new())
                }
            }
        } else {
            Arc::from(Vec::new())
        };

        Ok(Self {
            path,
            guess,
            info,
            object,
            object_raw,
            bytes,
            hash: std::sync::OnceLock::new(),
        })
    }

    /// 目标内容哈希（sha256，小写十六进制），首次调用时计算并缓存。
    ///
    /// 用内容哈希而不是 size+mtime 作目标身份：同名不同内容的文件必须是
    /// 不同目标，否则工程库会串味。
    pub fn target_hash(&self) -> Result<&str, BitflipError> {
        if let Some(h) = self.hash.get() {
            return Ok(h.as_str());
        }
        let computed = bitflip_project::target_hash(&self.path)
            .map_err(|e| BitflipError::Project(e.to_string()))?;
        // get_or_init 是幂等的：并发调用只会有一个值胜出，都拿到同一个引用
        Ok(self.hash.get_or_init(|| computed).as_str())
    }

    /// 打开该目标的工程库（不存在则创建），用于读写用户标注。
    ///
    /// **标注是主数据，分析结果是可重建的派生物** —— 这个切分是 M4 的
    /// 核心设计（见 docs/DECISIONS.md D2）。因此：
    /// * 改名/加注释只写这本库，**不触发重新分析**；
    /// * 重新分析只重写派生物，**不会丢标注**。
    pub fn open_project(&self, workspace: impl AsRef<Path>) -> Result<ProjectStore, BitflipError> {
        let hash = self.target_hash()?.to_string();
        let path = bitflip_project::primary_path(workspace.as_ref(), &hash);
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);
        let store = ProjectStore::create(
            &path,
            &hash,
            self.info.file_size,
            env!("CARGO_PKG_VERSION"),
            now,
        )?;
        Ok(store)
    }

    /// 按嗅探结论选择解析器。
    ///
    /// 归档（`.a` / `.lib`）的成员解析属于 M5；M1 只解析单对象文件，
    /// 对归档明确说明"sections 描述的是容器"而不是假装解析了成员。
    fn parse_target(path: &Path, file_size: u64, guess: &Guess) -> Result<Object, String> {
        // 嗅探窗口与解析上限是**两件不同的事**，早先版本把它们混成了一个。
        //
        // 嗅探只读文件前缀（8 MiB）是为了便宜：文件头与容器目录都在前面，
        // 读 100MB 去认一个格式是浪费。所以 `guess.file_truncated` 对**识别**
        // 来说只是"结论只覆盖前 8 MiB"的说明，不是"不许解析"的理由 ——
        // 下面的 `std::fs::read` 会把整个文件读进来。
        //
        // 之前这里直接以 `file_truncated` 为由拒绝解析，后果是**任何大于 8 MiB
        // 的目标都拿不到解析结果，也就完全无法反汇编**（M2 的 100MB 验收标准
        // 因此结构性地无法达成）。而拒绝的理由"避免基于残缺数据的结论"
        // 并不成立：真正读进解析器的是完整文件。
        //
        // 所以真正需要守的是**内存**上限，不是嗅探窗口。超过这个上限时仍然
        // 明确拒绝并说清原因，而不是悄悄给出不完整的结果（CLAUDE.md §7）。
        if file_size > MAX_FULL_PARSE_BYTES {
            return Err(format!(
                "文件 {file_size} 字节超过完整解析上限 {} 字节：本次只做识别，不做解析与反汇编",
                MAX_FULL_PARSE_BYTES
            ));
        }

        if guess.container == ContainerKind::Ar || guess.container == ContainerKind::MsvcLib {
            let count = guess.members.len();
            return Err(format!(
                "这是归档容器（{count} 个成员）：成员级解析排期在 M5。当前 sections 描述的是容器本身"
            ));
        }

        let bytes =
            std::fs::read(path).map_err(|error| format!("重新读取文件失败，无法解析：{error}"))?;

        match guess.object {
            ObjectKind::Elf => bitflip_loader::elf::parse(&bytes, 0, ObjectId::Plain)
                .map_err(|error| format!("ELF 解析失败：{}", error.summary_zh())),
            ObjectKind::Pe => bitflip_loader::pe::parse(&bytes, 0, ObjectId::Plain)
                .map_err(|error| format!("PE 解析失败：{}", error.summary_zh())),
            ObjectKind::Coff => bitflip_loader::coff::parse(&bytes, 0, ObjectId::Plain)
                .map_err(|error| format!("COFF 解析失败：{}", error.summary_zh())),
            ObjectKind::Raw => Err(
                "未识别出对象格式：原始二进制需要手工指定基址与架构（见 docs/PLAN.md M2）"
                    .to_string(),
            ),
            ObjectKind::MachO => {
                Err("Mach-O 解析排期在 M10（见 docs/PLAN.md §1.3），当前只做识别".to_string())
            }
        }
    }

    /// 解析结果；`None` 表示解析失败，原因见 `info().notes`。
    #[must_use]
    pub fn parsed(&self) -> Option<&ObjectInfo> {
        self.object.as_ref()
    }

    /// 原始解析对象（loader 层类型，供需要精确字节的调用方使用）。
    #[must_use]
    pub fn object(&self) -> Option<&Arc<Object>> {
        self.object_raw.as_ref()
    }

    /// 建立反汇编（线性 + 递归下降扫描）。
    ///
    /// 每次调用都会重新扫描 —— 因此**服务层应当缓存结果**，不要每个请求调一次。
    /// 这里不做内部缓存是因为：会话本身是不可变的（`Session` 只读打开的目标），
    /// 把可变的分析状态塞进去会让"打开目标"的语义变得含糊；
    /// 缓存属于服务层的职责（见 `bitflip-server` 的 `AppState`）。
    ///
    /// 失败的情形：
    /// - 目标没有解析成功（格式不认识 / 解析失败）—— 原因在 `info().notes`；
    /// - 没有可执行的段 —— 目标里没有代码，反汇编无从谈起。
    ///
    /// 这两种都是**如实拒绝**，而不是返回一个空的反汇编让 UI 显示"分析完成"。
    pub fn disassemble(&self, options: DisasmScanOptions) -> Result<Disasm, BitflipError> {
        let Some(object) = self.object_raw.as_ref() else {
            let reason = self
                .info
                .notes
                .first()
                .cloned()
                .unwrap_or_else(|| "目标尚未成功解析，无法反汇编".to_string());
            return Err(BitflipError::unavailable(reason));
        };

        // 有没有可执行的代码区？段和节都要看 —— 可重定位目标文件（`.o`/`.obj`）
        // 没有程序头，只有节表（见 `AddrSpace::from_sections`）。
        let has_exec = object.segments.iter().any(|segment| segment.perms.execute)
            || object.sections.iter().any(|section| section.perms.execute);
        if !has_exec {
            return Err(BitflipError::unavailable(format!(
                "目标里没有可执行区域（{} 个段 / {} 个节），没有可供反汇编的代码",
                object.segments.len(),
                object.sections.len()
            )));
        }

        let bytes: Arc<[u8]> = self.bytes.clone();
        // 扫描产生的 notes（合成地址、截断、解码失败）随 `Disasm` 一起返回，
        // 由 UI 显示 —— 分析质量的"折扣"必须写在界面上（CLAUDE.md §7）。
        Ok(Disasm::build(object, bytes, options))
    }

    /// 目标路径。
    #[must_use]
    pub fn path(&self) -> &Path {
        &self.path
    }

    /// 原始识别结论（loader 层类型）。
    #[must_use]
    pub fn guess(&self) -> &Guess {
        &self.guess
    }

    /// 识别结论（wire 类型）。
    #[must_use]
    pub fn info(&self) -> &TargetInfo {
        &self.info
    }

    /// 克隆一份识别结论（服务层把它放进响应）。
    #[must_use]
    pub fn target_info(&self) -> TargetInfo {
        self.info.clone()
    }

    /// 新建一个丢弃事件的分析作业（无 UI 场景）。
    #[must_use]
    pub fn detached_job(&self) -> JobHandle {
        JobHandle::new(Arc::new(NullSink))
    }

    /// 运行分析。
    ///
    /// M0 明确返回 [`BitflipError::NotYetImplemented`]：宁可让调用方拿到"还没做"，
    /// 也不返回一个空的结果集让 UI 显示"分析完成但什么都没有"。
    pub fn analyze(&self, job: &JobHandle) -> Result<AnalysisSummary, BitflipError> {
        job.set_stage(StageId::Segments, 1.0, "分析流水线尚未接入（计划：M2）");
        Err(BitflipError::not_implemented(
            "分析流水线 S1–S9（计划：M2 起，见 docs/PLAN.md）",
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// 构造一个最小的 64 位 x86_64 ELF 头（与 loader 的测试保持一致）。
    fn elf64_x86_64() -> Vec<u8> {
        let mut v = vec![0u8; 64];
        v[..4].copy_from_slice(b"\x7fELF");
        v[4] = 2;
        v[5] = 1;
        v[6] = 1;
        v[16..18].copy_from_slice(&2u16.to_le_bytes());
        v[18..20].copy_from_slice(&62u16.to_le_bytes());
        v[24..32].copy_from_slice(&0x401000u64.to_le_bytes());
        v[60..62].copy_from_slice(&5u16.to_le_bytes());
        v
    }

    #[test]
    fn open_elf_reports_identified_target() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("sample.elf");
        std::fs::write(&path, elf64_x86_64()).expect("write");

        let session = Session::open(&path, OpenOptions::default()).expect("打开");
        let info = session.info();
        assert_eq!(info.object, "elf");
        assert_eq!(info.object_label, "ELF");
        assert_eq!(info.arch.as_deref(), Some("x86_64/64/le"));
        assert_eq!(info.arch_family.as_deref(), Some("x86_64"));
        assert_eq!(info.bits, 64);
        assert_eq!(info.endian.as_deref(), Some("le"));
        assert_eq!(info.entry.as_deref(), Some("0000000000401000"));
        assert_eq!(info.image_base, None);
        assert_eq!(info.sections, Some(5));
        assert!(info.object_identified());
        assert!(!info.is_archive());
        assert!(info.summary.contains("ELF"));

        // wire 契约：地址必须是定长 16 位
        assert_eq!(info.entry.as_ref().map(String::len), Some(16));
        let json = serde_json::to_value(info).expect("序列化");
        assert_eq!(json["object"], "elf");
        assert!(json["image_base"].is_null());
    }

    #[test]
    fn open_missing_path_is_a_clear_error() {
        let dir = tempfile::tempdir().expect("tempdir");
        let err =
            Session::open(dir.path().join("nope"), OpenOptions::default()).expect_err("应报错");
        assert!(matches!(err, BitflipError::Loader(_)));
        assert!(err.to_string().contains("读取目标失败"));
    }

    #[test]
    fn open_directory_points_at_m10_plan() {
        let dir = tempfile::tempdir().expect("tempdir");
        let err = Session::open(dir.path(), OpenOptions::default()).expect_err("应报错");
        assert!(err.to_string().contains(".app"));
    }

    #[test]
    fn analyze_is_honest_about_not_being_implemented() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("sample.elf");
        std::fs::write(&path, elf64_x86_64()).expect("write");
        let session = Session::open(&path, OpenOptions::default()).expect("打开");
        let job = session.detached_job();

        let err = session.analyze(&job).expect_err("M0 必须明确拒绝");
        assert!(matches!(err, BitflipError::NotYetImplemented { .. }));
        assert!(err.to_string().contains("M2"));
        // 即便拒绝，进度也应反映"停在第一个阶段"
        assert_eq!(job.progress().stage, StageId::Segments);
    }
}
