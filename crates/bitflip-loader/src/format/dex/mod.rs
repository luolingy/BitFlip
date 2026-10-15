//! DEX（Dalvik Executable）**结构模型** —— 只做事实层，不建 CFG、不反编译。
//!
//! 这是 M11 的 M1：把"这个 DEX 里有哪些类/字段/方法、它们从哪来"如实列出来。
//! 不做的是控制流、数据流、注解、`debug_info`（各自的后续里程碑）。
//!
//! # 解析全部交给 `droidsaw-dex`，本模块只做适配
//!
//! 用它的 `parser` / `ids` / `decode` 的事实层。**不接入**它的反编译侧
//! （`emit*` / `sugar` / `r8_inversion`）—— 用现成库解析**格式**是省工作量，
//! 用它**推断语义**则是把"推断"混进"事实"，而 BitFlip 的立身之本恰恰是
//! "说的就是真的"（CLAUDE.md §7）。这条线有 grep 守卫：
//! `tests/dex_library_boundary.rs`。
//!
//! # 为什么不复用机器码对象模型（`object::Object`）
//!
//! DEX 不是"另一种可执行格式"。它**没有栈帧**（寄存器机）、**没有段权限**、
//! **没有 image_base**。硬塞进 `Object` 会让"按 RVA 落在哪个节"这类既有逻辑
//! 在 DEX 上产出一堆无意义的结论 —— 看起来正常、实际无意义，比报错更坏。
//! 所以这里另起一个模型，`parse_object` 也**不**接它（见那里的说明）。
//!
//! # 列式，不是对象
//!
//! CLAUDE.md §4 禁止把每一项物化成带 `String` 的对象。这里三张表
//! （[`DexStructure::classes`] / [`DexStructure::fields`] / [`DexStructure::methods`]）
//! **只存索引与整数**：名字与类型始终按索引回到库里取。
//!
//! 也就是说**不另建 interned 字符串池** —— DEX 自己的 `string_ids` /
//! `type_ids` / `proto_ids` / `field_ids` / `method_ids` 就是池，
//! 再复制一份只会让内存翻倍，而且两份池一旦不同步就是新的 bug 来源。
//!
//! # 拿不到就说拿不到
//!
//! 库会把"规范不符、但 ART 容忍因而不致命"的地方记进 `parse_errors`
//! （实测真实 APK 上就有一条 `OutOfOrder { pool: StringIds }`）。
//! 这些**逐条抄进** [`DexStructure::notes`]，不合并、不排序、不吞掉：
//! 它们是"这份文件不完全规范"的证据，而"库没报错"不等于"文件规范"。

use thiserror::Error;

use droidsaw_dex::decode::parse_class_data;
use droidsaw_dex::ids::{FieldIdx, MethodIdx, StringIdx, TypeIdx};
use droidsaw_dex::{DexError, DexFile};

/// DEX 的魔数前缀（Dalvik 规范 §3.1：`dex\n` + 三位版本 + NUL）。
const DEX_MAGIC: &[u8; 4] = b"dex\n";

/// 参数可忽略的 DEX 解析错误。
///
/// 只有两类：库本身报的错，和逐类解析 `class_data` 时的错。**不吞任何一类** ——
/// 库用了"容忍式解析 + `parse_errors` 侧信道"，所以只要它返回 `Err`，
/// 那就是这份文件读不下去（魔数/版本/校验和/截断），不是"某处不规范"。
#[derive(Debug, Error)]
pub enum DexParseError {
    /// `droidsaw-dex` 拒绝了这份文件。
    #[error("DEX 解析失败: {source}")]
    Dex {
        /// 库的原始错误。
        #[source]
        source: DexError,
    },
    /// 某个类的 `class_data` 读不下去。
    ///
    /// 单独一类是因为它**带定位信息**：`class_data_off` 指向的字节坏了，
    /// 而用户需要知道是哪个类，不然没法去比对手里的反编译工具。
    #[error(
        "类的 class_data 解析失败（class_idx={class_idx}, class_data_off={off:#x}）: {source}"
    )]
    ClassData {
        /// 类在 `class_defs` 里的下标。
        class_idx: u32,
        /// `class_data_off` 的原始值。
        off: u32,
        /// 库的原始错误。
        #[source]
        source: DexError,
    },
}

/// 这个前缀看起来是 DEX 吗。
///
/// 只看前 4 字节 `dex\n`。版本号与终止 NUL **不在这里判**：那是解析器的职责，
/// 嗅探只要回答"该不该走 DEX 这条路"。判了反而会把"版本号不对"这种
/// 精确的结论降级成"不是 DEX"（见 `sniff` 的原则）。
#[must_use]
pub fn looks_like_dex(bytes: &[u8]) -> bool {
    bytes.starts_with(DEX_MAGIC)
}

/// 头里"声明"的各个池大小。
///
/// **逐字来自 header**，不是我们数出来的。库实际解析出的条数单独放在
/// [`DexCounts::actual`]：两者不一致就是"文件头与文件内容对不上"，
/// 必须看得见（[`DexCounts::mismatches`]）。
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct DexDeclaredSizes {
    /// `string_ids_size`。
    pub strings: u32,
    /// `type_ids_size`。
    pub type_ids: u32,
    /// `proto_ids_size`。
    pub proto_ids: u32,
    /// `field_ids_size`。
    pub field_ids: u32,
    /// `method_ids_size`。
    pub method_ids: u32,
    /// `class_defs_size`。
    pub class_defs: u32,
}

/// 库里实际解析出的各个池的条数。
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct DexActualSizes {
    /// `string_ids`。
    pub strings: u32,
    /// `type_ids`（类型描述符）。
    pub type_descriptors: u32,
    /// `proto_ids`。
    pub protos: u32,
    /// `field_ids`。
    pub fields: u32,
    /// `method_ids`。
    pub methods: u32,
    /// `class_defs`。
    pub class_defs: u32,
}

/// 声明值与实际值对不上的项。
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct DexCountMismatches {
    /// `string_ids`。
    pub strings: Option<(u32, u32)>,
    /// `type_ids`。
    pub type_ids: Option<(u32, u32)>,
    /// `proto_ids`。
    pub proto_ids: Option<(u32, u32)>,
    /// `field_ids`。
    pub field_ids: Option<(u32, u32)>,
    /// `method_ids`。
    pub method_ids: Option<(u32, u32)>,
    /// `class_defs`。
    pub class_defs: Option<(u32, u32)>,
}

impl DexCountMismatches {
    /// 有没有任何一项对不上。
    #[must_use]
    pub const fn is_empty(&self) -> bool {
        self.strings.is_none()
            && self.type_ids.is_none()
            && self.proto_ids.is_none()
            && self.field_ids.is_none()
            && self.method_ids.is_none()
            && self.class_defs.is_none()
    }

    /// 逐项的可读描述（`(项名, 声明值, 实际值)`）。
    #[must_use]
    pub fn entries(&self) -> Vec<(&'static str, u32, u32)> {
        let mut out = Vec::new();
        for (name, item) in [
            ("string_ids", self.strings),
            ("type_ids", self.type_ids),
            ("proto_ids", self.proto_ids),
            ("field_ids", self.field_ids),
            ("method_ids", self.method_ids),
            ("class_defs", self.class_defs),
        ] {
            if let Some((declared, actual)) = item {
                out.push((name, declared, actual));
            }
        }
        out
    }
}

/// header 声明 vs 库实际解析出的条数。
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct DexCounts {
    /// header 里声明的。
    pub declared: DexDeclaredSizes,
    /// 库实际解析出的。
    pub actual: DexActualSizes,
    /// 对不上的那些。
    pub mismatches: DexCountMismatches,
}

/// 文件头里的"事实"，逐字照抄，不做解释。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DexHeaderFacts {
    /// 版本号，取自魔数中间三位（`"035"` / `"038"` / `"041"` …）。
    pub version: String,
    /// `file_size`。
    pub file_size: u32,
    /// `header_size`（规范固定 `0x70`）。
    pub header_size: u32,
    /// `map_off`。
    pub map_off: u32,
    /// `data_off`。
    pub data_off: u32,
    /// `data_size`。
    pub data_size: u32,
    /// 头里存的 SHA-1（`signature`）是否等于 `SHA-1(data[32..file_size])`。
    ///
    /// **`false` 不是解析失败**：真实世界里就有"存的是 SHA-1(input[32..]) 之外
    /// 的东西"的 DEX，ART 容忍。但它是"这份文件被改过或重组过"的证据，
    /// 所以如实带出来，不藏。
    ///
    /// （Adler-32 `checksum` 字段不在这里：库在 `DexHeader::parse` 里
    /// **强制**校验它，对不上会直接返回 `Err` —— 那是硬失败，不是事实。）
    pub sha1_matches_stored: bool,
}

/// 一个类（`class_def_item` 的投影）。
///
/// 只有索引与计数，没有 `String` 字段（CLAUDE.md §4）。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DexClass {
    /// 类在 `class_defs` 里的下标。
    pub index: u32,
    /// `class_idx`（指向 `type_ids`）。
    pub type_idx: TypeIdx,
    /// `access_flags`。
    pub access_flags: u32,
    /// `superclass_idx`；`None` 表示"没有父类"（`java.lang.Object` 或接口）。
    pub superclass_idx: Option<TypeIdx>,
    /// `source_file_idx`（`SourceFile` 属性）。
    pub source_file_idx: Option<StringIdx>,
    /// `class_data_off`；`0` 表示这个类没有 `class_data`（接口、纯抽象类等）。
    pub class_data_off: u32,
    /// 静态字段数（来自 `class_data`）。
    pub static_field_count: u32,
    /// 实例字段数（来自 `class_data`）。
    pub instance_field_count: u32,
    /// 直接方法数（`<init>` / private / static）。
    pub direct_method_count: u32,
    /// 虚方法数。
    pub virtual_method_count: u32,
    /// 本类的字段在 [`DexStructure::fields`] 里的区间起点。
    pub field_start: u32,
    /// 本类的方法在 [`DexStructure::methods`] 里的区间起点。
    pub method_start: u32,
}

impl DexClass {
    /// 本类字段在 `fields` 里的区间。
    #[must_use]
    pub const fn field_range(&self) -> std::ops::Range<usize> {
        let start = self.field_start as usize;
        start..start + (self.static_field_count as usize + self.instance_field_count as usize)
    }

    /// 本类方法在 `methods` 里的区间。
    #[must_use]
    pub const fn method_range(&self) -> std::ops::Range<usize> {
        let start = self.method_start as usize;
        start..start + (self.direct_method_count as usize + self.virtual_method_count as usize)
    }
}

/// 一个字段（`encoded_field` 的投影）。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DexField {
    /// 所属类在 [`DexStructure::classes`] 里的下标。
    pub class_index: u32,
    /// 指向全局 `field_ids`。
    pub field_idx: FieldIdx,
    /// `access_flags`。
    pub access_flags: u32,
    /// 是不是静态字段。
    pub is_static: bool,
}

/// 一个方法（`encoded_method` 的投影）。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DexMethod {
    /// 所属类在 [`DexStructure::classes`] 里的下标。
    pub class_index: u32,
    /// 指向全局 `method_ids`。
    pub method_idx: MethodIdx,
    /// `access_flags`。
    pub access_flags: u32,
    /// 是不是直接方法（`<init>` / private / static）。
    pub is_direct: bool,
    /// `code_off`；`0` 表示抽象或 native，**没有字节码**。
    pub code_off: u32,
}

impl DexMethod {
    /// 这个方法有没有字节码。
    #[must_use]
    pub const fn has_code(&self) -> bool {
        self.code_off != 0
    }
}

/// 一份 DEX 的结构模型。
///
/// 库的 [`DexFile`] 是**私有字段**：它是实现细节，不该从我们的 API 里漏出去
/// （否则调用方会开始依赖它的类型，换库或升级就变成全仓改动）。
pub struct DexStructure {
    file: DexFile,
    /// 文件头事实。
    pub header: DexHeaderFacts,
    /// 池大小（声明 vs 实际）。
    pub counts: DexCounts,
    /// 类表（按 `class_defs` 顺序）。
    pub classes: Vec<DexClass>,
    /// 字段表（按类分组，静态在前）。
    pub fields: Vec<DexField>,
    /// 方法表（按类分组，直接方法在前）。
    pub methods: Vec<DexMethod>,
    /// 解析过程中值得说出来的事：库的 `parse_errors`、计数不符、成员被跳过等。
    pub notes: Vec<String>,
}

impl std::fmt::Debug for DexStructure {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // 不打印 `file`：那会把十万条字符串灌进调试输出。
        f.debug_struct("DexStructure")
            .field("header", &self.header)
            .field("counts", &self.counts)
            .field("classes", &self.classes.len())
            .field("fields", &self.fields.len())
            .field("methods", &self.methods.len())
            .field("notes", &self.notes.len())
            .finish()
    }
}

/// 解析一份 DEX 的**结构**。
///
/// # Errors
///
/// 见 [`DexParseError`]。
///
/// # 关于资源上限
///
/// `droidsaw-dex` 的 `parse` 接受一个可选预算（`budget`），本模块**暂时传
/// `None`**，也就是不做解析预算。这是个**已知缺口**，不是"已经处理好了"：
/// 恶意构造的 DEX 可以靠超大计数把内存顶上去。M11 的风险清单里已经记了
/// 这一条（APK/ZIP 那边同样），接入预算属于后续工作 —— 在此之前，
/// 调用方只应把**已经有尺寸上限**的字节交给本函数。
pub fn parse(bytes: &[u8]) -> Result<DexStructure, DexParseError> {
    let file = DexFile::parse(bytes, None).map_err(|source| DexParseError::Dex { source })?;

    // 头的字段在下面会被反复读，但**不在这里留一个长借用**：函数末尾要把
    // `file` 移进 `DexStructure`，一个活到那时的借用会让那一步编译不过。
    let mut notes = Vec::new();

    // 库报出的"规范不符但容忍"的地方：逐条抄下来，不改写、不合并。
    // 用 `kind` 的 Debug 而不是自己编名字 —— 名字表在库里，抄一份会漂移。
    for failure in &file.parse_errors {
        notes.push(format!(
            "解析器记录了一处容忍式跳过：{:?} @ {:#x}",
            failure.kind, failure.offset
        ));
    }
    if !file.input_checksums_canonical {
        notes.push(
            "头里的 SHA-1 与 SHA-1(data[32..file_size]) 不一致：文件被改过或重组过，\
             ART 容忍这种文件，但不是原样产物"
                .to_string(),
        );
    }
    // 头声明的长度与实际字节数对不上：说明这份输入被截断，或者尾部挂着别的东西
    // （APK 的成员解压出来一般不会这样，但"从更大的文件里切出来的片段"很常见）。
    // 现在能读到这儿说明解析没被截断挡住，所以这条只是**事实**，不是失败。
    if let Ok(declared) = usize::try_from(file.header.file_size) {
        if declared != bytes.len() {
            notes.push(format!(
                "头里声明 file_size={declared}，实际给了 {} 字节 —— 两者不一致",
                bytes.len()
            ));
        }
    }

    let declared = DexDeclaredSizes {
        strings: file.header.string_ids_size,
        type_ids: file.header.type_ids_size,
        proto_ids: file.header.proto_ids_size,
        field_ids: file.header.field_ids_size,
        method_ids: file.header.method_ids_size,
        class_defs: file.header.class_defs_size,
    };
    let actual = DexActualSizes {
        strings: len_u32(file.strings.len(), "string_ids"),
        type_descriptors: len_u32(file.type_descriptors.len(), "type_ids"),
        protos: len_u32(file.protos.len(), "proto_ids"),
        fields: len_u32(file.fields.len(), "field_ids"),
        methods: len_u32(file.methods.len(), "method_ids"),
        class_defs: len_u32(file.class_defs.len(), "class_defs"),
    };

    // 逐类解析 class_data。**这是本模块唯一自己驱动的一步**：库的
    // `list_methods` 只给方法，拿不到字段，而"字段清单"是 M1 的交付物之一。
    let mut classes = Vec::with_capacity(file.class_defs.len());
    let mut fields = Vec::new();
    let mut methods = Vec::new();

    for (i, cd) in file.class_defs.iter().enumerate() {
        let index = len_u32(i, "class_defs 下标");
        let (static_fields, instance_fields, direct_methods, virtual_methods) =
            if cd.class_data_off == 0 {
                (0u32, 0u32, 0u32, 0u32)
            } else {
                let data = parse_class_data(bytes, cd.class_data_off).map_err(|source| {
                    DexParseError::ClassData {
                        class_idx: index,
                        off: cd.class_data_off,
                        source,
                    }
                })?;

                for ef in &data.static_fields {
                    fields.push(DexField {
                        class_index: index,
                        field_idx: ef.field_idx,
                        access_flags: ef.access_flags,
                        is_static: true,
                    });
                }
                for ef in &data.instance_fields {
                    fields.push(DexField {
                        class_index: index,
                        field_idx: ef.field_idx,
                        access_flags: ef.access_flags,
                        is_static: false,
                    });
                }
                for em in &data.direct_methods {
                    methods.push(DexMethod {
                        class_index: index,
                        method_idx: em.method_idx,
                        access_flags: em.access_flags,
                        is_direct: true,
                        code_off: em.code_off,
                    });
                }
                for em in &data.virtual_methods {
                    methods.push(DexMethod {
                        class_index: index,
                        method_idx: em.method_idx,
                        access_flags: em.access_flags,
                        is_direct: false,
                        code_off: em.code_off,
                    });
                }

                (
                    len_u32(data.static_fields.len(), "static_fields"),
                    len_u32(data.instance_fields.len(), "instance_fields"),
                    len_u32(data.direct_methods.len(), "direct_methods"),
                    len_u32(data.virtual_methods.len(), "virtual_methods"),
                )
            };

        classes.push(DexClass {
            index,
            type_idx: cd.class_idx,
            access_flags: cd.access_flags,
            superclass_idx: cd.superclass_idx,
            source_file_idx: cd.source_file_idx,
            class_data_off: cd.class_data_off,
            static_field_count: static_fields,
            instance_field_count: instance_fields,
            direct_method_count: direct_methods,
            virtual_method_count: virtual_methods,
            field_start: len_u32(
                fields.len() - (static_fields + instance_fields) as usize,
                "fields 区间起点",
            ),
            method_start: len_u32(
                methods.len() - (direct_methods + virtual_methods) as usize,
                "methods 区间起点",
            ),
        });
    }

    let mismatches = DexCountMismatches {
        strings: mismatch(declared.strings, actual.strings),
        type_ids: mismatch(declared.type_ids, actual.type_descriptors),
        proto_ids: mismatch(declared.proto_ids, actual.protos),
        field_ids: mismatch(declared.field_ids, actual.fields),
        method_ids: mismatch(declared.method_ids, actual.methods),
        class_defs: mismatch(declared.class_defs, actual.class_defs),
    };
    if !mismatches.is_empty() {
        for (name, declared_n, actual_n) in mismatches.entries() {
            notes.push(format!(
                "{name}：头里声明 {declared_n} 条，实际解析出 {actual_n} 条 —— 文件头与内容对不上"
            ));
        }
    }

    // 先把头的事儿抄成一份独立的值，再移 `file`：顺序反了就是
    // "借用还没结束就搬走"（编译器会直接拒绝，这里写明是为了下次不重犯）。
    let header_facts = DexHeaderFacts {
        version: String::from_utf8_lossy(&file.header.magic[4..7]).into_owned(),
        file_size: file.header.file_size,
        header_size: file.header.header_size,
        map_off: file.header.map_off,
        data_off: file.header.data_off,
        data_size: file.header.data_size,
        sha1_matches_stored: file.input_checksums_canonical,
    };

    Ok(DexStructure {
        file,
        header: header_facts,
        counts: DexCounts {
            declared,
            actual,
            mismatches,
        },
        classes,
        fields,
        methods,
        notes,
    })
}

/// `usize → u32`：DEX 的所有计数都是 32 位，池装不下 40 亿条（那要有 8 GB 文件）。
/// 真溢出就用 `u32::MAX` 饱和 —— 这里**不能**用 `as`（§4 与 workspace lint），
/// 也不该 panic（那是把"文件太大"变成"进程没了"）。
fn len_u32(len: usize, what: &str) -> u32 {
    match u32::try_from(len) {
        Ok(v) => v,
        Err(_) => {
            debug_assert!(false, "{what} 的条数超过了 u32：{len}");
            u32::MAX
        }
    }
}

/// 声明 != 实际时给出 `(声明, 实际)`。
const fn mismatch(declared: u32, actual: u32) -> Option<(u32, u32)> {
    if declared == actual {
        None
    } else {
        Some((declared, actual))
    }
}

impl DexStructure {
    /// 类的类型描述符（`Lcom/foo/Bar;`）。
    ///
    /// 取不到时返回 `None`（而不是 `"?"` 或空串）—— 拿不到就说拿不到。
    #[must_use]
    pub fn class_descriptor(&self, class: usize) -> Option<&str> {
        let cd = self.classes.get(class)?;
        self.file.get_type_descriptor(cd.type_idx).ok()
    }

    /// 类的短名（`Lcom/foo/Bar;` → `Bar`）。取不到时 `None`。
    #[must_use]
    pub fn class_short_name(&self, class: usize) -> Option<&str> {
        short_descriptor_name(self.class_descriptor(class)?)
    }

    /// 父类的描述符。没有父类（或取不到）时 `None`。
    #[must_use]
    pub fn superclass_descriptor(&self, class: usize) -> Option<&str> {
        let cd = self.classes.get(class)?;
        self.file.get_type_descriptor(cd.superclass_idx?).ok()
    }

    /// `SourceFile` 属性的内容。没有该属性时 `None`。
    #[must_use]
    pub fn source_file(&self, class: usize) -> Option<&str> {
        let cd = self.classes.get(class)?;
        self.file.get_string(cd.source_file_idx?).ok()
    }

    /// 字段名（`foo`）。取不到时 `None`。
    #[must_use]
    pub fn field_name(&self, field: usize) -> Option<&str> {
        let f = self.fields.get(field)?;
        let id = self.file.fields.get(f.field_idx.0 as usize)?;
        self.file.get_string(id.name_idx).ok()
    }

    /// 字段的类型描述符（`I` / `Ljava/lang/String;`）。
    #[must_use]
    pub fn field_type_descriptor(&self, field: usize) -> Option<&str> {
        let f = self.fields.get(field)?;
        let id = self.file.fields.get(f.field_idx.0 as usize)?;
        self.file.get_type_descriptor(id.type_idx).ok()
    }

    /// 字段的声明类描述符。
    #[must_use]
    pub fn field_declaring_class(&self, field: usize) -> Option<&str> {
        let f = self.fields.get(field)?;
        let id = self.file.fields.get(f.field_idx.0 as usize)?;
        self.file.get_type_descriptor(id.class_idx).ok()
    }

    /// 方法名（`<init>` / `onCreate` …）。取不到时 `None`。
    #[must_use]
    pub fn method_name(&self, method: usize) -> Option<&str> {
        let m = self.methods.get(method)?;
        let id = self.file.methods.get(m.method_idx.0 as usize)?;
        self.file.get_string(id.name_idx).ok()
    }

    /// 方法返回类型的描述符。
    #[must_use]
    pub fn method_return_descriptor(&self, method: usize) -> Option<&str> {
        let m = self.methods.get(method)?;
        let id = self.file.methods.get(m.method_idx.0 as usize)?;
        let proto = self.file.protos.get(id.proto_idx.0 as usize)?;
        self.file.get_type_descriptor(proto.return_type_idx).ok()
    }

    /// 方法参数的类型描述符列表（按顺序）。取不到时返回空表 ——
    /// "没有参数"与"参数表读不到"由调用方看着 `notes` 区分。
    #[must_use]
    pub fn method_parameters(&self, method: usize) -> Vec<&str> {
        let Some(m) = self.methods.get(method) else {
            return Vec::new();
        };
        let Some(id) = self.file.methods.get(m.method_idx.0 as usize) else {
            return Vec::new();
        };
        let Some(proto) = self.file.protos.get(id.proto_idx.0 as usize) else {
            return Vec::new();
        };
        self.file
            .type_lists
            .get(&proto.parameters_off)
            .map(|tl| {
                tl.iter()
                    .filter_map(|t| self.file.get_type_descriptor(*t).ok())
                    .collect()
            })
            .unwrap_or_default()
    }

    /// 方法所属的类在 [`Self::classes`] 里的下标。
    #[must_use]
    pub fn method_class_index(&self, method: usize) -> Option<u32> {
        self.methods.get(method).map(|m| m.class_index)
    }

    /// 按描述符精确找类；找不到返回 `None`。
    ///
    /// **只做精确匹配**。库的 `find_class` 还支持短名与子串匹配，但那三种匹配
    /// 混在一个返回值里，"我找到的到底是哪一个"就说不清了 —— 一个类名可能
    /// 同时是另一个类的短名。要模糊匹配就让调用方显式地做（并在结果里说清
    /// 用的是哪种依据），不要藏在查找函数里。
    #[must_use]
    pub fn find_class_by_descriptor(&self, descriptor: &str) -> Option<usize> {
        (0..self.classes.len()).find(|i| self.class_descriptor(*i) == Some(descriptor))
    }

    /// 类的字段：`(下标, 名字, 类型描述符, access_flags, 是否静态)`。
    #[must_use]
    pub fn class_fields(&self, class: usize) -> Vec<usize> {
        self.classes
            .get(class)
            .map(|c| c.field_range().collect())
            .unwrap_or_default()
    }

    /// 类的方法下标列表。
    #[must_use]
    pub fn class_methods(&self, class: usize) -> Vec<usize> {
        self.classes
            .get(class)
            .map(|c| c.method_range().collect())
            .unwrap_or_default()
    }

    /// 方法总数（含抽象/native）。
    #[must_use]
    pub fn method_count(&self) -> usize {
        self.methods.len()
    }

    /// 有字节码的方法数。
    #[must_use]
    pub fn method_count_with_code(&self) -> usize {
        self.methods.iter().filter(|m| m.has_code()).count()
    }

    /// 类总数。
    #[must_use]
    pub fn class_count(&self) -> usize {
        self.classes.len()
    }

    /// 字段总数。
    #[must_use]
    pub fn field_count(&self) -> usize {
        self.fields.len()
    }

    /// `class_data` 四个计数之和 —— 也就是"按类的元数据数出来的符号总数"。
    ///
    /// 与 [`Self::field_count`] + [`Self::method_count`] 相等是**结构性**要求；
    /// 黄金测试会断言这一点。它同时是"我们没在遍历时漏掉某一类符号"的守卫。
    #[must_use]
    pub fn symbols_declared_in_class_data(&self) -> u64 {
        self.classes.iter().fold(0u64, |acc, c| {
            acc + u64::from(c.static_field_count)
                + u64::from(c.instance_field_count)
                + u64::from(c.direct_method_count)
                + u64::from(c.virtual_method_count)
        })
    }
}

/// `Lcom/foo/Bar;` → `Bar`。不是类描述符时 `None`（`I` / `[I` / `<unknown>`）。
fn short_descriptor_name(descriptor: &str) -> Option<&str> {
    let inner = descriptor.strip_prefix('L')?.strip_suffix(';')?;
    Some(inner.rsplit('/').next().unwrap_or(inner))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn short_descriptor_name_is_not_guessed_for_non_class_descriptors() {
        assert_eq!(short_descriptor_name("Lcom/foo/Bar;"), Some("Bar"));
        assert_eq!(short_descriptor_name("LBar;"), Some("Bar"));
        assert_eq!(short_descriptor_name("Lcom/a/B$C;"), Some("B$C"));
        // 基本类型与数组不是类：不能硬编一个"短名"出来。
        assert_eq!(short_descriptor_name("I"), None);
        assert_eq!(short_descriptor_name("[Ljava/lang/String;"), None);
    }

    #[test]
    fn magic_detection_only_looks_at_the_prefix() {
        assert!(looks_like_dex(b"dex\n035\0"));
        assert!(looks_like_dex(b"dex\n"));
        // 版本不对也"像 DEX"：那是解析器的结论，不是嗅探的。
        assert!(looks_like_dex(b"dex\n999\0"));
        assert!(!looks_like_dex(b"PK\x03\x04"));
        assert!(!looks_like_dex(b""));
        assert!(!looks_like_dex(b"dex"));
    }

    #[test]
    fn count_mismatches_are_reported_per_field() {
        let none = DexCountMismatches::default();
        assert!(none.is_empty());
        assert!(none.entries().is_empty());

        let one = DexCountMismatches {
            strings: Some((10, 9)),
            ..Default::default()
        };
        assert!(!one.is_empty());
        assert_eq!(one.entries(), vec![("string_ids", 10, 9)]);
    }

    #[test]
    fn truncated_input_is_an_error_not_an_empty_structure() {
        // 只有魔数、没有头：必须是 Err（§7：不能给出"空但看起来完成"的结果）。
        let err = parse(b"dex\n035\0");
        assert!(matches!(err, Err(DexParseError::Dex { .. })));
    }

    #[test]
    fn non_dex_input_is_an_error() {
        let err = parse(b"not a dex file at all");
        assert!(matches!(err, Err(DexParseError::Dex { .. })));
    }
}
