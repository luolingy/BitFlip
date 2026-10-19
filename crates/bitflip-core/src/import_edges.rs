//! 把"调用目标是导入槽 / 导入桩"解析成导入符号（M12 第五片）。
//!
//! # 这件事在解决什么
//!
//! 调用图此前只有**落在本镜像里**的边。`bl` 到 `__stubs` 里的一个跳板桩、
//! 或直接跳到 GOT 槽的调用，终点不是任何函数：既没有名字，也没有反汇编、
//! 没有大小、没有 CFG。它落进"已知函数之外"那一类，于是被安静地丢掉 ——
//! 用户看到的是一张**看起来完整**的图，其实缺了所有调外部函数的那部分。
//!
//! 这一片把那些目标翻译成"这是 `<dylib>` 的 `<符号>`"：调用图因此可以对
//! 那条边说清楚"被调用方在**本二进制之外**"，而不是把一个桩地址当成函数。
//!
//! # 只对 Mach-O 建表（以及为什么）
//!
//! 判据是 [`formats_with_import_edges`]。**不是**因为别的格式没有导入表 ——
//! 恰恰相反：PE 解析器同样填 `iat_slot`（实测 `m3-mingw-static.exe` 46 条
//! 导入全部有槽位），ELF 也有自己的 `JUMP_SLOT`。在它们身上启用这套解析
//! 会**改变它们今天的调用图**：PE 的 `__imp_xxx` 跳板就在 `.text` 里、
//! 形状与 `jmp *[rip+disp]` 完全相同，一旦按桩解析就会多出一批外部边；
//! ELF 的 `.plt` 桩则已经由另一条路径按重定位表命名成 `名字@plt` 的**函数**
//! （见 `TargetAnalysis::build` 里"来源 5b"），再补一条外部边就是同一件事
//! 说两遍。本片的验收要求是 PE/ELF 行为**逐字节不变**，所以这里按格式收窄，
//! 由 `crates/bitflip-core/tests/import_edges_regression.rs` 用真实 PE
//! （46 条有槽导入）与 ELF（5 条边含 `.plt`）钉住。
//!
//! # 两条解析规则
//!
//! 1. **目标地址就是某个导入的槽位**（`Import::iat_slot`）→ 这条边是导入调用。
//! 2. **目标落在桩节里、且那几条字节是一条跳板桩**（`bitflip_arch::import_stub_slot`）
//!    → 桩读的那个槽位是某个导入的槽位 → 这条边是导入调用。
//!
//! 两条都**只**认"槽位与导入表里的地址逐位相同"。没有学习、没有启发式：
//! 对不上就不产生边（`None`），由调用方如实计入"解析不了的桩目标"。
//!
//! # 不知道就是不知道
//!
//! * `iat_slot == None` 的导入（classic bind、或链里没被绑定）**不产生任何边** ——
//!   没有地址可比，编一个地址就是编事实；
//! * 按序号导入（`name == None`）仍会产生边，但 `import_name` 是 `null`：
//!   序号不能伪装成名字（CLAUDE.md §7）；
//! * `__objc_stubs` **不**算桩节：那是 objc 消息转发的跳板（先取 selector，
//!   再跳 `_objc_msgSend`），把它解析成"调用了 objc_msgSend"会丢掉 selector，
//!   而那正是那条边的全部意义。这一片明确不做 objc/sel 解析。

use std::collections::HashMap;

use bitflip_arch::{import_stub_slot, supports_import_stub, ArchSpec};
use bitflip_loader::object::{Import, Object};
use bitflip_loader::ObjectKind;

/// 读目标地址处字节的闭包（桩形状识别要原始字节）。
pub(crate) type ReadBytes<'a> = &'a dyn Fn(u64, usize) -> Option<Vec<u8>>;

/// 导入跳板桩所在节的名字。
///
/// Mach-O 的节名是 `段,节` 形式（实测 `__TEXT,__stubs`），所以只在**逗号右边**
/// 比较：`__TEXT,__objc_stubs` 的节名同样以 `__stubs` 结尾，但它是 objc
/// 消息转发跳板，不是导入桩（见模块文档）。
const STUB_SECTION: &str = "__stubs";

/// 识别一条桩最多需要读多少字节。
///
/// AArch64 的三连桩是 12 字节；x86_64 / i386 的 `jmp *[rip+disp]` 是 6 字节。
/// 取 12：短了 AArch64 就解不出槽位。
const MAX_STUB_BYTES: usize = 12;

/// 这个格式的调用图能不能把目标解析成导入符号。
///
/// 只有 Mach-O。理由见模块文档（PE/ELF 今天的行为被验收要求冻结）。
#[must_use]
pub(crate) const fn formats_with_import_edges(kind: ObjectKind) -> bool {
    matches!(kind, ObjectKind::MachO)
}

/// 导入槽 / 导入桩的对照表。
///
/// 生命周期与 `&Object` 一致：这里只借用导入表，不复制符号名。
pub(crate) struct ImportEdges<'a> {
    /// 导入表（借用自 [`Object`]）。
    imports: &'a [Import],
    /// 槽地址 → `imports` 下标。同一个槽出现多次时保留**第一个**。
    by_slot: HashMap<u64, usize>,
    /// 桩节范围 `[vaddr, vaddr + size)`。
    stub_ranges: Vec<(u64, u64)>,
    /// 架构规格（桩的形状是架构知识）。
    spec: ArchSpec,
    /// 读字节的闭包。
    read: ReadBytes<'a>,
    /// 有槽位的导入条数。
    slotted: usize,
    /// 没有槽位的导入条数（classic bind / 链里没绑定）。
    unslotted: usize,
}

impl<'a> ImportEdges<'a> {
    /// 从导入表 + 桩节范围建表。
    #[must_use]
    pub(crate) fn from_parts(
        imports: &'a [Import],
        spec: ArchSpec,
        stub_ranges: Vec<(u64, u64)>,
        read: ReadBytes<'a>,
    ) -> Self {
        let mut by_slot: HashMap<u64, usize> = HashMap::with_capacity(imports.len());
        let mut slotted = 0usize;
        for (index, import) in imports.iter().enumerate() {
            if let Some(slot) = import.iat_slot {
                slotted += 1;
                // 同一个槽被两条导入声明时保留第一条：不合并、不猜谁对。
                by_slot.entry(slot).or_insert(index);
            }
        }
        Self {
            imports,
            by_slot,
            stub_ranges,
            spec,
            read,
            slotted,
            unslotted: imports.len().saturating_sub(slotted),
        }
    }

    /// 从解析出来的对象建表；`None` = 这个格式/这个对象没有可解析的导入边。
    ///
    /// 返回 `None` 的两种情形要分开看：
    ///
    /// * 格式不在 [`formats_with_import_edges`] 里（PE/ELF/COFF/DEX/raw）；
    /// * Mach-O 但一条导入都没有（抠掉导入的二进制、或解析没解出导入）——
    ///   这时没有可比对的地址，写一条"0 条边"的 notes 只是噪音。
    #[must_use]
    pub(crate) fn build(object: &'a Object, read: ReadBytes<'a>) -> Option<Self> {
        if !formats_with_import_edges(object.kind) || object.imports.is_empty() {
            return None;
        }
        let stub_ranges: Vec<(u64, u64)> = object
            .sections
            .iter()
            .filter(|section| section.file.size > 0)
            .filter(|section| {
                section
                    .name
                    .rsplit(',')
                    .next()
                    .is_some_and(|name| name.eq_ignore_ascii_case(STUB_SECTION))
            })
            .map(|section| {
                (
                    section.vaddr,
                    section.vaddr.saturating_add(section.file.size),
                )
            })
            .collect();
        Some(Self::from_parts(
            &object.imports,
            object.arch,
            stub_ranges,
            read,
        ))
    }

    /// 把调用目标解析成导入符号，返回它在导入表里的下标。
    ///
    /// `None` = 目标不是任何导入（保持原来的处理）。用下标而不是 `&Import`
    /// 是为了让调用方能把"命中了哪几条不同的导入"去重计数。
    #[must_use]
    pub(crate) fn lookup_index(&self, target: u64) -> Option<usize> {
        // 规则 1：目标地址本身就是槽位。
        if let Some(&index) = self.by_slot.get(&target) {
            return Some(index);
        }

        // 规则 2：目标是一条桩，桩读的槽位是导入槽。
        if !supports_import_stub(self.spec) || !self.in_stub_section(target) {
            return None;
        }
        // 先按最长形态读；读不到（节尾/页边界）再退到 6 字节 —— 短读只影响
        // AArch64（它需要 12 字节），那种情况如实返回 `None`。
        let bytes = (self.read)(target, MAX_STUB_BYTES).or_else(|| (self.read)(target, 6))?;
        let stub = import_stub_slot(self.spec, &bytes, target)?;
        self.by_slot.get(&stub.slot).copied()
    }

    /// 导入表里第 `index` 条导入。
    #[must_use]
    pub(crate) fn import_at(&self, index: usize) -> Option<&'a Import> {
        self.imports.get(index)
    }

    /// [`Self::lookup_index`] 的便捷形态：直接给出导入条目（测试用）。
    #[cfg(test)]
    #[must_use]
    pub(crate) fn lookup(&self, target: u64) -> Option<&'a Import> {
        self.lookup_index(target)
            .and_then(|index| self.import_at(index))
    }

    /// `target` 是否落在某个桩节里。
    ///
    /// 与 [`Self::lookup`] 分开：调用方要用它区分"这里根本没有桩"与
    /// "这里有桩但没认出来"（后者必须进 notes，否则桩识别失效是静默的）。
    #[must_use]
    pub(crate) fn in_stub_section(&self, target: u64) -> bool {
        self.stub_ranges
            .iter()
            .any(|&(start, end)| target >= start && target < end)
    }

    /// 有槽位的导入条数。
    #[must_use]
    pub(crate) const fn slotted(&self) -> usize {
        self.slotted
    }

    /// 没有槽位的导入条数（这些导入不产生边）。
    #[must_use]
    pub(crate) const fn unslotted(&self) -> usize {
        self.unslotted
    }

    /// 本架构是否实现了导入桩的形状识别（不看有没有桩节）。
    #[must_use]
    pub(crate) fn stub_arch_supported(&self) -> bool {
        supports_import_stub(self.spec)
    }

    /// 这份对象里有没有桩节。
    #[must_use]
    pub(crate) fn has_stub_sections(&self) -> bool {
        !self.stub_ranges.is_empty()
    }

    /// 架构规格（notes 里要说明"哪个架构还没实现"）。
    #[must_use]
    pub(crate) const fn spec(&self) -> ArchSpec {
        self.spec
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use bitflip_arch::ArchSpec;
    use bitflip_loader::object::ObjectId;

    /// 一条导入。
    fn import(module: &str, name: Option<&str>, slot: Option<u64>) -> Import {
        Import {
            module: module.to_string(),
            name: name.map(str::to_string),
            ordinal: None,
            iat_slot: slot,
            thunk: None,
        }
    }

    /// 什么都不给的读字节函数。
    fn no_bytes(_: u64, _: usize) -> Option<Vec<u8>> {
        None
    }

    /// 只有 `target` 这一处有桩字节。
    fn stub_at(target: u64, words: [u32; 3]) -> impl Fn(u64, usize) -> Option<Vec<u8>> {
        move |addr: u64, len: usize| {
            if addr != target || len < 12 {
                return None;
            }
            let mut out = Vec::with_capacity(12);
            for word in words {
                out.extend_from_slice(&word.to_le_bytes());
            }
            Some(out)
        }
    }

    #[test]
    fn only_imports_with_a_slot_can_be_matched() {
        let imports = vec![
            import("/usr/lib/libz.dylib", Some("_inflate"), Some(0x3000)),
            import("/usr/lib/libq.dylib", Some("_never_bound"), None),
        ];
        let edges = ImportEdges::from_parts(&imports, ArchSpec::aarch64(), Vec::new(), &no_bytes);

        assert_eq!(edges.slotted(), 1, "只有一条导入有槽位");
        assert_eq!(edges.unslotted(), 1);
        let hit = edges.lookup(0x3000).expect("槽位地址应当命中");
        assert_eq!(hit.name.as_deref(), Some("_inflate"));
        assert_eq!(hit.module, "/usr/lib/libz.dylib");
        // 没有槽位的那条导入没有任何地址可比：不会凭空命中任何目标。
        assert!(edges.lookup(0x3008).is_none());
        assert!(edges.lookup(0).is_none());
    }

    #[test]
    fn a_stub_target_is_resolved_through_the_slot_it_jumps_to() {
        // 真实字节（见 bitflip_arch::plt 的 LIVE_CONTAINER_STUB_CF 与其出处）：
        // adrp x16, #0x100010000 / ldr x16, [x16] / br x16
        let imports = vec![import(
            "/System/Library/Frameworks/CoreFoundation.framework/CoreFoundation",
            Some("_CFBundleCreate"),
            Some(0x1_0001_0000),
        )];
        let read = stub_at(0x1_0000_b588, [0xB000_0030, 0xF940_0210, 0xD61F_0200]);
        let edges = ImportEdges::from_parts(
            &imports,
            ArchSpec::aarch64(),
            vec![(0x1_0000_b588, 0x1_0000_b588 + 0x3a8)],
            &read,
        );

        let hit = edges.lookup(0x1_0000_b588).expect("桩目标应当解析到导入");
        assert_eq!(hit.name.as_deref(), Some("_CFBundleCreate"));
        // 桩目标旁边（桩内偏移）不是桩入口：不认。
        assert!(edges.lookup(0x1_0000_b58c).is_none());
        // 桩节之外的同形状字节也不认（没有节就不试桩）。
        let outside = ImportEdges::from_parts(
            &imports,
            ArchSpec::aarch64(),
            vec![(0x1_0000_0000, 0x1_0000_0fff)],
            &read,
        );
        assert!(outside.lookup(0x1_0000_b588).is_none());
    }

    #[test]
    fn an_unslotted_import_never_produces_an_edge_even_through_a_stub() {
        // 桩的槽位 0x2000 上没有任何导入（这条导入没有槽位地址）
        let imports = vec![import("/usr/lib/libq.dylib", Some("_nope"), None)];
        let read = stub_at(0x1000, [0xB000_0020, 0xF940_0210, 0xD61F_0200]);
        let edges =
            ImportEdges::from_parts(&imports, ArchSpec::aarch64(), vec![(0x1000, 0x1010)], &read);
        assert!(edges.lookup(0x1000).is_none());
    }

    #[test]
    fn ordinal_only_imports_still_stay_honest_about_missing_names() {
        // 按序号导入：有槽位、没有名字。边可以有，名字必须是 None。
        let imports = vec![import("libSystem.dylib", None, Some(0x100))];
        let edges = ImportEdges::from_parts(&imports, ArchSpec::aarch64(), Vec::new(), &no_bytes);
        let hit = edges.lookup(0x100).expect("有槽位就该命中");
        assert!(hit.name.is_none(), "序号不能伪装成名字");
    }

    #[test]
    fn only_macho_gets_import_edges() {
        assert!(formats_with_import_edges(ObjectKind::MachO));
        for kind in [
            ObjectKind::Pe,
            ObjectKind::Coff,
            ObjectKind::Elf,
            ObjectKind::Dex,
            ObjectKind::Raw,
        ] {
            assert!(
                !formats_with_import_edges(kind),
                "{} 今天的调用图必须保持原样",
                kind.as_str()
            );
        }
    }

    #[test]
    fn build_returns_none_for_non_macho_even_with_slotted_imports() {
        // PE 实测有 46 条带槽位的导入（m3-mingw-static.exe）。有槽位也不建表 ——
        // 这不是"没有数据"，是"本片不给它加外部边"。
        let mut object = Object::new(
            ObjectId::Plain,
            ObjectKind::Pe,
            ArchSpec::x86_64(),
            bitflip_arch::Endian::Little,
        );
        object.imports.push(import(
            "KERNEL32.dll",
            Some("_ExitProcess"),
            Some(0x1400_2000),
        ));
        assert!(ImportEdges::build(&object, &no_bytes).is_none());
    }

    #[test]
    fn a_macho_object_without_imports_says_nothing() {
        let object = Object::new(
            ObjectId::Plain,
            ObjectKind::MachO,
            ArchSpec::aarch64(),
            bitflip_arch::Endian::Little,
        );
        assert!(
            ImportEdges::build(&object, &no_bytes).is_none(),
            "没有导入就没有可解析的边，不该产生一条 0 条边的噪音 notes"
        );
    }

    #[test]
    fn a_macho_object_with_slotted_imports_builds_a_table() {
        let mut object = Object::new(
            ObjectId::Plain,
            ObjectKind::MachO,
            ArchSpec::aarch64(),
            bitflip_arch::Endian::Little,
        );
        object.imports.push(import(
            "libSystem.dylib",
            Some("_malloc"),
            Some(0x1000_1000),
        ));
        object
            .imports
            .push(import("libSystem.dylib", Some("_free"), None));
        object.sections.push(bitflip_loader::object::Section {
            name: "__TEXT,__stubs".to_string(),
            vaddr: 0x1000_0b00,
            file: bitflip_loader::object::FileRange::new(0x1000, 0x18),
            perms: bitflip_loader::object::Perms {
                read: true,
                write: false,
                execute: true,
            },
            kind: bitflip_loader::object::ContentKind::Code,
            loaded: true,
        });
        // `__objc_stubs` 不是导入桩节，必须被排除。
        object.sections.push(bitflip_loader::object::Section {
            name: "__TEXT,__objc_stubs".to_string(),
            vaddr: 0x1000_0c00,
            file: bitflip_loader::object::FileRange::new(0x1018, 0x40),
            perms: bitflip_loader::object::Perms {
                read: true,
                write: false,
                execute: true,
            },
            kind: bitflip_loader::object::ContentKind::Code,
            loaded: true,
        });

        let edges = ImportEdges::build(&object, &no_bytes).expect("应当建表");
        assert_eq!(edges.slotted(), 1);
        assert_eq!(edges.unslotted(), 1);
        assert!(edges.stub_arch_supported() && edges.has_stub_sections());
        assert!(edges.in_stub_section(0x1000_0b00));
        assert!(!edges.in_stub_section(0x1000_0c00), "__objc_stubs 不算桩节");
        assert!(!edges.in_stub_section(0x1000_0b00 - 1));
    }
}
