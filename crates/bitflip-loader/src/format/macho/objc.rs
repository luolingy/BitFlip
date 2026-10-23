//! ObjC 元数据解析（`__objc_*` 节）。
//!
//! # 这件事在解决什么
//!
//! Objective-C 的**名字**（类名、选择器、方法名、类型编码）不躺在符号表里，
//! 而是躺在几个专门的节里：`__objc_methname`（选择器名）、`__objc_classname`
//! （类名）、`__objc_methtype`（类型编码）、`__objc_selrefs`（选择器指针表）、
//! `__objc_methlist`（方法表）、`__objc_stubs`（消息转发桩）。
//!
//! 不解析它们的后果是**具体**的：
//!
//! * 方法名看不到 —— 函数清单里那些 objc 方法全是"未识别"；
//! * `__objc_stubs` 里的桩发的是哪条消息看不到 —— 调用图上那几百条边
//!   只能停在"调用了一个跳板"，而**选择器正是那条边的全部意义**
//!   （见 `bitflip_core::import_edges` 的模块文档）。
//!
//! # 指针不是指针：两种编码都要认
//!
//! `__objc_selrefs` 那一格里的 8 字节，在现代二进制里**不是**一个普通指针，
//! 而是 dyld 的**链式修复**（chained fixups）里的一个 *rebase* 指针：
//!
//! ```text
//! bit 63      = bind 标志（1 = 绑定到符号池，静态文件里没有目标地址）
//! bit 62..51  = 链上的下一个
//! bit 50..36  = 保留 / high8
//! bit 35..0   = 目标相对**镜像基址**的偏移
//! ```
//!
//! 所以 `0x0010_0000_0000_dd3d` 这样的 8 字节不是地址 `0x1000000000dd3d`，
//! 而是"基址 + 0xdd3d"。**先按 rebase 解释、落在已知节里才算数**；
//! 对不上再按普通指针试一遍（没有链式修复的老文件里，槽里就是普通指针）。
//! 两种解释都要求目标落在**已知节**内 —— 落不进去就是解不出来，如实记数。
//!
//! # 方法表：相对指针 ABI
//!
//! `__objc_methlist` 里的方法表用的是 objc4 的**相对指针** ABI：
//!
//! ```text
//! method_list_t: entsize_and_flags(u32) count(u32)
//! method_t:      name(i32，相对 name 字段自己) types(i32) imp(i32)
//! ```
//!
//! `name` 指向的是**选择器槽**（`SEL*`），不是字符串；字符串要再走一跳
//! （槽 → 名字）。`entsize` 有三种取值：
//!
//! | entsize | 布局 |
//! | --- | --- |
//! | 12 | `name` / `types` / `imp` 三个相对偏移（现代 ABI） |
//! | 8  | `name` / `imp` 两个相对偏移（"小"方法表，`name` 直接指字符串） |
//! | 24 | `name` / `types` / `imp` 三个**绝对**指针（老 ABI） |
//!
//! # 诚实性
//!
//! 解不出来的部分**不猜**：bind 指针（目标在符号池里）、形状不认识的
//! 方法表、认不出的桩形态，都分别计数并写进 [`ObjcMetadata::notes`]。
//! 没有 objc 节的二进制得到的是**空表**加一句"这个格式里没有这套节"，
//! 而不是"这个二进制没有 objc"（CLAUDE.md §7）。

use std::collections::HashMap;

use bitflip_arch::Arch;

use crate::object::{ObjcCategory, ObjcClass, ObjcMetadata, ObjcMethod, ObjcSelectorRef, ObjcStub};

use super::{MachOSection, MachOSegment};

/// 选择器名池（`__objc_methname`）。
const SEC_METHNAME: &str = "__objc_methname";
/// 类名池（`__objc_classname`）。
const SEC_CLASSNAME: &str = "__objc_classname";
/// 方法类型编码池（`__objc_methtype`）。
const SEC_METHTYPE: &str = "__objc_methtype";
/// 选择器引用表（指针表）。
const SEC_SELREFS: &str = "__objc_selrefs";
/// 方法表。
const SEC_METHLIST: &str = "__objc_methlist";
/// 消息转发桩。
/// 类表（类的归属关系从这儿开始）。
const SEC_CLASSLIST: &str = "__objc_classlist";
/// 类别表。
const SEC_CATLIST: &str = "__objc_catlist";
/// 消息转发桩。
const SEC_STUBS: &str = "__objc_stubs";

/// 链式修复 rebase 指针的目标偏移（低 36 位）。
const REBASE_TARGET_MASK: u64 = 0xF_FFFF_FFFF;
/// 链式修复的 bind 标志（最高位）：目标是符号池里的符号，静态文件里没有地址。
const CHAINED_BIND: u64 = 1 << 63;

/// 一个方法表里最多认多少个方法。
///
/// `count` 是文件里的 32 位数，损坏的文件能给出天文数字。不设上限的话，
/// 一个坏值就能让解析器试图分配几十亿条记录 —— 宁可在这里停下并如实说明。
const MAX_METHODS_PER_LIST: u32 = 1 << 20;

/// 消息桩扫描：一次最多看多少条指令。
///
/// 一个节里全是桩，节本身的大小就是上限；这个上限只是防止损坏的长度字段
/// 让扫描跑飞。
const MAX_STUB_INSNS: usize = 1 << 20;

/// 一个节在文件里的位置。
#[derive(Debug, Clone, Copy)]
struct SectionInfo {
    /// 虚拟地址。
    addr: u64,
    /// 字节数（**文件里**的字节数；零填充节没有文件数据）。
    size: u64,
    /// 文件偏移。
    offset: u64,
}

/// 一个指针的静态解析结果。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Pointer {
    /// 目标地址（静态可解）。
    Address(u64),
    /// 链式修复的 bind 指针：目标在符号池里，静态文件里没有目标地址。
    Bound,
    /// 解不出来。
    Unknown,
}

/// 解析上下文：文件字节 + 节表 + 镜像基址。
struct Ctx<'a> {
    /// 文件字节。
    bytes: &'a [u8],
    /// 镜像基址（rebase 偏移是相对它的）。
    base: u64,
    /// 文件是不是小端。
    little: bool,
    /// 指针宽度（字节）。
    ptr_size: u64,
    /// 节名 → 位置（每个名字只留第一个，用于按名取节）。
    sections: HashMap<&'a str, SectionInfo>,
    /// **所有**有文件数据的节（含同名重复），用于"这个地址落在哪个节里"。
    ///
    /// 为什么不能只用 `sections`：现代二进制里 `__objc_const` 会同时出现在
    /// `__DATA` 和 `__DATA_CONST` 两个段里，同名。只认第一个的话，落在另一个
    /// 段里的 `class_ro_t` 就"不在任何节里"，于是类名读不出来 —— 实测在
    /// SideStore 上这让 177 个类丢了名字。按地址范围查才是对的。
    ranges: Vec<SectionInfo>,
}

impl<'a> Ctx<'a> {
    /// 建上下文。
    fn new(
        bytes: &'a [u8],
        base: u64,
        little: bool,
        is_64: bool,
        segments: &'a [MachOSegment],
    ) -> Self {
        let mut sections = HashMap::new();
        let mut ranges = Vec::new();
        for segment in segments {
            for section in &segment.sections {
                if section.size == 0 || super::is_zerofill_section(section.flags) {
                    continue;
                }
                let info = SectionInfo {
                    addr: section.addr,
                    size: section.size,
                    offset: u64::from(section.offset),
                };
                // 同名节只认第一个（文件里不该有两个同名节；真有了也只取第一个，
                // 不猜哪个是真的）。
                sections.entry(section.sectname.as_str()).or_insert(info);
                // 但"地址属于哪个节"必须看**全部**节，否则同名重复段里的数据
                // 会被当成"不在任何节里"（见 `ranges` 的文档）。
                ranges.push(info);
            }
        }
        Self {
            bytes,
            base,
            little,
            ptr_size: if is_64 { 8 } else { 4 },
            sections,
            ranges,
        }
    }

    /// 取节。
    fn section(&self, name: &str) -> Option<&SectionInfo> {
        self.sections.get(name)
    }

    /// 虚拟地址落在哪个节里。
    fn section_containing(&self, vaddr: u64) -> Option<&SectionInfo> {
        self.ranges.iter().find(|section| {
            vaddr >= section.addr && vaddr < section.addr.saturating_add(section.size)
        })
    }

    /// 虚拟地址 → 文件偏移。
    fn file_offset(&self, vaddr: u64) -> Option<u64> {
        let section = self.section_containing(vaddr)?;
        Some(section.offset + (vaddr - section.addr))
    }

    /// 读一个 32 位小端/大端值。
    fn u32_at(&self, file_offset: u64) -> Option<u32> {
        let start = usize::try_from(file_offset).ok()?;
        let arr: [u8; 4] = self
            .bytes
            .get(start..start.checked_add(4)?)?
            .try_into()
            .ok()?;
        Some(if self.little {
            u32::from_le_bytes(arr)
        } else {
            u32::from_be_bytes(arr)
        })
    }

    /// 读一个 64 位值。
    fn u64_at(&self, file_offset: u64) -> Option<u64> {
        let start = usize::try_from(file_offset).ok()?;
        let arr: [u8; 8] = self
            .bytes
            .get(start..start.checked_add(8)?)?
            .try_into()
            .ok()?;
        Some(if self.little {
            u64::from_le_bytes(arr)
        } else {
            u64::from_be_bytes(arr)
        })
    }

    /// 读一个 32 位有符号相对偏移。
    fn i32_at(&self, file_offset: u64) -> Option<i32> {
        self.u32_at(file_offset).map(|value| value as i32)
    }

    /// 解析一个指针槽。
    ///
    /// 顺序：**先按链式 rebase 解释**（现代二进制的常态），落在已知节里才算；
    /// 对不上再按普通指针试一遍（没有链式修复的老文件）。两处都对不上就是
    /// 解不出来。
    fn resolve_pointer(&self, vaddr: u64) -> Pointer {
        let Some(offset) = self.file_offset(vaddr) else {
            return Pointer::Unknown;
        };
        let Some(raw) = self.u64_at(offset) else {
            return Pointer::Unknown;
        };
        if raw == 0 {
            return Pointer::Unknown;
        }
        if raw & CHAINED_BIND != 0 {
            return Pointer::Bound;
        }
        // 链式 rebase：低 36 位是相对镜像基址的偏移。
        let rebased = self.base.wrapping_add(raw & REBASE_TARGET_MASK);
        if self.section_containing(rebased).is_some() {
            return Pointer::Address(rebased);
        }
        // 没有链式修复的老文件：槽里就是普通指针。
        if self.section_containing(raw).is_some() {
            return Pointer::Address(raw);
        }
        Pointer::Unknown
    }

    /// 读一个以 NUL 结尾的字符串（范围限在所在节内）。
    fn cstring(&self, vaddr: u64) -> Option<String> {
        let section = self.section_containing(vaddr)?;
        let start = usize::try_from(section.offset).ok()?;
        let offset_in_section = usize::try_from(vaddr - section.addr).ok()?;
        let begin = start.checked_add(offset_in_section)?;
        let end = start.checked_add(usize::try_from(section.size).ok()?)?;
        let bytes = self.bytes.get(begin..end)?;
        let nul = bytes.iter().position(|&byte| byte == 0)?;
        let text = String::from_utf8_lossy(&bytes[..nul]).into_owned();
        Some(text)
    }

    /// 读一个字符串池（`__objc_methname` 这类）。
    ///
    /// 返回 `(地址, 文本)`。空串**不**算名字（池里可以有占位的空串）。
    fn string_pool(&self, name: &str) -> Vec<(u64, String)> {
        let Some(section) = self.section(name) else {
            return Vec::new();
        };
        let Some(start) = usize::try_from(section.offset).ok() else {
            return Vec::new();
        };
        let Some(len) = usize::try_from(section.size).ok() else {
            return Vec::new();
        };
        let Some(end) = start.checked_add(len) else {
            return Vec::new();
        };
        let Some(bytes) = self.bytes.get(start..end) else {
            return Vec::new();
        };
        let mut out = Vec::new();
        let mut pos = 0usize;
        while pos < bytes.len() {
            let nul = bytes[pos..].iter().position(|&byte| byte == 0);
            let end = pos + nul.unwrap_or(bytes.len() - pos);
            if end > pos {
                out.push((
                    section.addr + pos as u64,
                    String::from_utf8_lossy(&bytes[pos..end]).into_owned(),
                ));
            }
            match nul {
                Some(offset) => pos = pos + offset + 1,
                None => break,
            }
        }
        out
    }
}

/// 解析 objc 元数据。
///
/// 没有 `__objc_*` 节时返回**空表**加一句说明（不是"这个二进制没有 objc"，
/// 而是"这个文件里没有这套节"）。
pub(crate) fn parse(
    bytes: &[u8],
    base: u64,
    little: bool,
    is_64: bool,
    arch: Arch,
    segments: &[MachOSegment],
) -> ObjcMetadata {
    let mut meta = ObjcMetadata::default();

    let objc_sections: Vec<&str> = segments
        .iter()
        .flat_map(|segment| segment.sections.iter())
        .map(|section: &MachOSection| section.sectname.as_str())
        .filter(|name| name.starts_with("__objc"))
        .collect();
    if objc_sections.is_empty() {
        return meta;
    }

    let ctx = Ctx::new(bytes, base, little, is_64, segments);

    // 名字池。
    let methnames: HashMap<u64, String> = ctx.string_pool(SEC_METHNAME).into_iter().collect();
    let class_names: Vec<String> = ctx
        .string_pool(SEC_CLASSNAME)
        .into_iter()
        .map(|(_, text)| text)
        .collect();
    let methtypes: HashMap<u64, String> = ctx.string_pool(SEC_METHTYPE).into_iter().collect();

    // 选择器引用（槽 → 名字）。
    let mut selector_refs = Vec::new();
    let mut bound_slots = 0usize;
    let mut unknown_slots = 0usize;
    if let Some(section) = ctx.section(SEC_SELREFS) {
        let count = section.size / ctx.ptr_size;
        for index in 0..count {
            let slot = section.addr + index * ctx.ptr_size;
            match ctx.resolve_pointer(slot) {
                Pointer::Address(target) => {
                    if let Some(name) = methnames.get(&target) {
                        selector_refs.push(ObjcSelectorRef {
                            slot,
                            target,
                            name: name.clone(),
                        });
                    } else {
                        unknown_slots += 1;
                    }
                }
                Pointer::Bound => bound_slots += 1,
                Pointer::Unknown => unknown_slots += 1,
            }
        }
    }

    // 槽 → 名字（消息桩解码要用）。
    let selectors_by_slot: HashMap<u64, String> = selector_refs
        .iter()
        .map(|entry| (entry.slot, entry.name.clone()))
        .collect();

    // 方法表（`__objc_methlist`：老 ABI 的连续扫描）。
    let (methods, unnamed_methods) = parse_method_lists(&ctx, &selectors_by_slot, &methtypes);

    // 类与类别：归属关系。现代二进制里每个类的方法表是独立的一张，
    // 上面那一步只看得到 `__objc_methlist` 那一节（往往是空的）。
    let (classes, class_account) = parse_classes(&ctx, &selectors_by_slot, &methtypes);
    let (categories, category_account) = parse_categories(&ctx, &selectors_by_slot, &methtypes);

    // 消息转发桩。
    let (stubs, not_selector) = parse_stubs(&ctx, &selectors_by_slot, arch);

    let class_methods_total: usize = classes
        .iter()
        .map(|class| class.instance_methods.len() + class.class_methods.len())
        .sum();
    let category_methods_total: usize = categories
        .iter()
        .map(|category| category.instance_methods.len() + category.class_methods.len())
        .sum();

    meta.selector_refs = selector_refs;
    meta.methods = methods;
    meta.stubs = stubs;
    meta.classes = classes;
    meta.categories = categories;
    meta.class_names = class_names;

    // 说明（CLAUDE.md §7：降级要写在界面上）。
    let mut notes = Vec::new();
    notes.push(format!(
        "ObjC 元数据：{} 个 __objc_* 节；解出选择器引用 {} 个（{} 个槽位）、方法 {} 个、消息桩 {} 个",
        objc_sections.len(),
        meta.selector_refs.len(),
        ctx.section(SEC_SELREFS).map_or(0, |section| section.size / ctx.ptr_size),
        meta.methods.len(),
        meta.stubs.len(),
    ));
    if bound_slots > 0 {
        notes.push(format!(
            "{SEC_SELREFS} 里有 {bound_slots} 个槽是链式修复的 bind 指针（目标在符号池里，\
             静态文件里没有目标地址）：这 {bound_slots} 个槽没有名字"
        ));
    }
    if unknown_slots > 0 {
        notes.push(format!(
            "{SEC_SELREFS} 里有 {unknown_slots} 个槽没解出目标（零值、越界或指向不认识的地方）"
        ));
    }
    if unnamed_methods > 0 {
        notes.push(format!(
            "方法表里有 {unnamed_methods} 个方法没解出选择器名：这些方法在结果里只有实现地址"
        ));
    }
    if ctx.section(SEC_STUBS).is_some() && meta.stubs.is_empty() {
        notes.push(format!(
            "{SEC_STUBS} 存在但没认出任何消息桩：消息桩识别只实现了 AArch64 的 \
             `adrp` + `ldr` 取选择器那种形态（这个二进制是 {}）",
            arch.as_str()
        ));
    }
    if not_selector > 0 {
        notes.push(format!(
            "{SEC_STUBS} 里有 {not_selector} 处 `adrp` + `ldr` 取的槽不在选择器表里 \
             （例如取 GOT 条目）：按事实不当作消息桩"
        ));
    }
    // 归属关系：类与类别。这一段的账目要单独说 —— "有类名"和"知道方法属于谁"
    // 是两件事，后者才是这张片要给的东西。
    if !meta.classes.is_empty() || !meta.categories.is_empty() {
        let named_classes = meta
            .classes
            .iter()
            .filter(|class| class.name.is_some())
            .count();
        notes.push(format!(
            "ObjC 归属：{} 个类（{} 个解出类名）、{} 个类别；类里解出方法 {} 个、类别里解出方法 {} 个",
            meta.classes.len(),
            named_classes,
            meta.categories.len(),
            class_methods_total,
            category_methods_total,
        ));
    }
    if class_account.superclass_bound + category_account.superclass_bound > 0 {
        notes.push(format!(
            "有 {} 个类/类别指向的父类（或被扩展的类）是链式修复的 bind 指针 —— 那个类在**别的库**里，\
             静态文件里没有它的名字，所以这些归属关系只能标未知",
            class_account.superclass_bound + category_account.superclass_bound
        ));
    }
    if class_account.name_unresolved + category_account.name_unresolved > 0 {
        notes.push(format!(
            "有 {} 个类/类别的名字没解出来（`class_ro_t.name` 或 `category_t.name` 读不到）",
            class_account.name_unresolved + category_account.name_unresolved
        ));
    }
    if class_account.ro_unresolved + class_account.metaclass_unresolved > 0 {
        notes.push(format!(
            "有 {} 个类的 `class_ro_t` 解不出来、{} 个类的元类解不出来：这些类只有名字，\
             方法表读不到（这不等于「这个类没有方法」）",
            class_account.ro_unresolved, class_account.metaclass_unresolved
        ));
    }
    if class_account.pointer_unresolved + category_account.pointer_unresolved > 0 {
        notes.push(format!(
            "类表/类别表里有 {} 个指针解不出来（bind 或坏指针）：这些项整条跳过",
            class_account.pointer_unresolved + category_account.pointer_unresolved
        ));
    }
    if class_account.ivars_unparsed + category_account.ivars_unparsed > 0 {
        notes.push(format!(
            "有 {} 张 ivar 表的 `entsize` 不是已知布局（20 相对偏移 / 32 绝对指针）：\
             ivar 名按事实不猜，留空",
            class_account.ivars_unparsed + category_account.ivars_unparsed
        ));
    }
    meta.notes = notes;
    meta
}

/// 解析方法表（`__objc_methlist`）。
///
/// 返回 `(方法列表, 没解出名字的方法数)`。
fn parse_method_lists(
    ctx: &Ctx<'_>,
    selectors_by_slot: &HashMap<u64, String>,
    methtypes: &HashMap<u64, String>,
) -> (Vec<ObjcMethod>, usize) {
    let mut methods = Vec::new();
    let mut unnamed = 0usize;
    let Some(section) = ctx.section(SEC_METHLIST) else {
        return (methods, unnamed);
    };

    // 老 ABI 把**所有**方法表连成一节，所以这里要一张接一张地走。
    // 现代二进制里每个类的方法表是独立的，由 `parse_classes` 直接按指针解。
    let end = section.addr + section.size;
    let mut addr = section.addr;
    while addr + 8 <= end {
        let Some((list, list_unnamed, next)) =
            parse_method_list_at(ctx, addr, selectors_by_slot, methtypes)
        else {
            break;
        };
        methods.extend(list);
        unnamed += list_unnamed;
        if next <= addr {
            // 不前进就停：表头是坏的时候不能原地转圈。
            break;
        }
        addr = next;
    }
    (methods, unnamed)
}

/// 解**一张**方法表（`method_list_t`）。
///
/// 返回 `(方法, 无名项数, 表尾之后的对齐地址)`。经典 ABI 里方法表是首尾相接的
/// 一节，所以要靠 `next` 接着往下走；现代二进制里 `class_ro_t.baseMethods`
/// 直接指着某一张表，只需要第一项。
fn parse_method_list_at(
    ctx: &Ctx<'_>,
    list_addr: u64,
    selectors_by_slot: &HashMap<u64, String>,
    methtypes: &HashMap<u64, String>,
) -> Option<(Vec<ObjcMethod>, usize, u64)> {
    let mut methods = Vec::new();
    let mut unnamed = 0usize;

    let header = ctx.file_offset(list_addr)?;
    let entsize_flags = ctx.u32_at(header)?;
    let count = ctx.u32_at(header + 4)?;
    let entsize = entsize_flags & 0xFFFF;
    // 只认已实现过的三种布局（见 `decode_method`）；其余形态如实不认。
    if !matches!(entsize, 8 | 12 | 24) || count > MAX_METHODS_PER_LIST {
        return None;
    }

    for index in 0..u64::from(count) {
        let entry_addr = list_addr + 8 + index * u64::from(entsize);
        let Some(file_offset) = ctx.file_offset(entry_addr) else {
            break;
        };
        let Some(method) = decode_method(
            ctx,
            file_offset,
            entry_addr,
            entsize,
            selectors_by_slot,
            methtypes,
        ) else {
            continue;
        };
        if method.selector.is_empty() {
            unnamed += 1;
            continue;
        }
        methods.push(method);
    }

    // 表尾按 8 字节对齐（方法表里含指针，运行时保持指针对齐）。
    let next = (list_addr + 8 + u64::from(count) * u64::from(entsize) + 7) & !7;
    Some((methods, unnamed, next))
}

/// 解一个方法项。
///
/// `entsize` 决定字段布局（12 = 相对指针三件套，8 = 小方法表，24 = 绝对指针）。
fn decode_method(
    ctx: &Ctx<'_>,
    file_offset: u64,
    entry_addr: u64,
    entsize: u32,
    selectors_by_slot: &HashMap<u64, String>,
    methtypes: &HashMap<u64, String>,
) -> Option<ObjcMethod> {
    let (selector, types, imp) = match entsize {
        12 => {
            // 相对偏移：相对**字段自己**的地址。
            let name_rel = ctx.i32_at(file_offset)?;
            let types_rel = ctx.i32_at(file_offset + 4)?;
            let imp_rel = ctx.i32_at(file_offset + 8)?;
            let name_field = entry_addr;
            let types_field = entry_addr + 4;
            let imp_field = entry_addr + 8;
            let selector =
                resolve_relative_name(ctx, name_field, name_rel, selectors_by_slot, file_offset);
            let types = resolve_relative_string(ctx, types_field, types_rel, methtypes);
            let imp = relative_address(imp_field, imp_rel);
            (selector, types, Some(imp))
        }
        8 => {
            let name_rel = ctx.i32_at(file_offset)?;
            let imp_rel = ctx.i32_at(file_offset + 4)?;
            let name_field = entry_addr;
            let imp_field = entry_addr + 4;
            // 小方法表的 `name` 直接指字符串（不经过选择器槽）。
            let selector =
                resolve_relative_name(ctx, name_field, name_rel, selectors_by_slot, file_offset);
            let types = None;
            let imp = relative_address(imp_field, imp_rel);
            (selector, types, Some(imp))
        }
        _ => {
            // 老 ABI：三个绝对指针。
            let name_ptr = ctx.u64_at(file_offset)?;
            let types_ptr = ctx.u64_at(file_offset + 8)?;
            let imp_ptr = ctx.u64_at(file_offset + 16)?;
            let selector = match ctx.resolve_pointer(entry_addr) {
                Pointer::Address(target) => ctx.cstring(target).unwrap_or_default(),
                _ => String::new(),
            };
            let types = match ctx.resolve_pointer(entry_addr + 8) {
                Pointer::Address(target) => ctx.cstring(target),
                _ => None,
            };
            let imp = if imp_ptr == 0 { None } else { Some(imp_ptr) };
            let _ = (name_ptr, types_ptr);
            (selector, types, imp)
        }
    };
    Some(ObjcMethod {
        list: entry_addr,
        selector,
        types,
        imp,
    })
}

/// 相对偏移解出选择器名。
///
/// 12 字节的现代 ABI 里，`name` 指向的是**选择器槽**（`SEL*`）：槽里才是名字。
/// 8 字节的小方法表里，`name` 直接指名字字符串。
fn resolve_relative_name(
    ctx: &Ctx<'_>,
    field_addr: u64,
    relative: i32,
    selectors_by_slot: &HashMap<u64, String>,
    file_offset: u64,
) -> String {
    let target = relative_address(field_addr, relative);
    let _ = file_offset;
    if let Some(name) = selectors_by_slot.get(&target) {
        return name.clone();
    }
    // 不是已知的选择器槽：可能直接指名字字符串（8 字节的小方法表）。
    ctx.cstring(target).unwrap_or_default()
}

/// 相对偏移解出类型编码。
fn resolve_relative_string(
    ctx: &Ctx<'_>,
    field_addr: u64,
    relative: i32,
    methtypes: &HashMap<u64, String>,
) -> Option<String> {
    let target = relative_address(field_addr, relative);
    if let Some(text) = methtypes.get(&target) {
        return Some(text.clone());
    }
    ctx.cstring(target)
}

/// 相对偏移 → 绝对地址。
fn relative_address(field_addr: u64, relative: i32) -> u64 {
    field_addr.wrapping_add(i64::from(relative) as u64)
}

/// 解析消息转发桩（`__objc_stubs`）。
///
/// 形态是 AArch64 的两连指令：
///
/// ```text
/// adrp x1, <页>
/// ldr  x1, [x1, #偏移]   ; 取选择器槽
/// ```
///
/// 槽的地址 = 页 + 偏移。落在选择器表里就是一条消息 —— 这就是桩的全部意义。
///
/// 返回 `(桩列表, 取的不是选择器槽的处数)`。
fn parse_stubs(
    ctx: &Ctx<'_>,
    selectors_by_slot: &HashMap<u64, String>,
    arch: Arch,
) -> (Vec<ObjcStub>, usize) {
    let mut stubs = Vec::new();
    let mut not_selector = 0usize;
    if arch != Arch::Aarch64 {
        return (stubs, not_selector);
    }
    let Some(section) = ctx.section(SEC_STUBS) else {
        return (stubs, not_selector);
    };

    let mut offset = 0u64;
    let mut scanned = 0usize;
    while offset + 8 <= section.size && scanned < MAX_STUB_INSNS {
        let Some(insn) = ctx.u32_at(section.offset + offset) else {
            break;
        };
        let Some(next) = ctx.u32_at(section.offset + offset + 4) else {
            break;
        };
        scanned += 1;
        if let (Some((page, reg)), Some((disp, rn, rt))) = (
            decode_adrp(insn, section.addr + offset),
            decode_ldr_imm64(next),
        ) {
            if reg == rn && rn == rt {
                let slot = page + disp;
                if let Some(selector) = selectors_by_slot.get(&slot) {
                    stubs.push(ObjcStub {
                        address: section.addr + offset,
                        selector: selector.clone(),
                    });
                    offset += 8;
                    continue;
                }
                // 取的不是选择器槽（例如取 GOT 条目）：按事实不当作消息桩。
                not_selector += 1;
            }
        }
        // 桩的条数与间隔不固定，逐条扫比猜一个步长可靠。
        offset += 4;
    }
    (stubs, not_selector)
}

/// 解 AArch64 的 `adrp`。
///
/// 编码：`1 immlo(2) 1 10000 immhi(19) Rd(5)`。目标页 = `(PC & !0xFFF) + (imm << 12)`
/// —— **PC 的页基址是寻址的一部分**，漏掉它算出来的页会差一整页。
/// 返回 `(页地址, 目标寄存器)`。
fn decode_adrp(insn: u32, pc: u64) -> Option<(u64, u8)> {
    if insn & 0x9F00_0000 != 0x9000_0000 {
        return None;
    }
    let immlo = (insn >> 29) & 0x3;
    let immhi = (insn >> 5) & 0x7_FFFF;
    let mut imm = ((immhi << 2) | immlo) as i32;
    if imm & (1 << 20) != 0 {
        imm -= 1 << 21;
    }
    let page = (pc & !0xFFF).wrapping_add_signed(i64::from(imm) << 12);
    Some((page, (insn & 0x1F) as u8))
}

/// 解 AArch64 的 `ldr <Xt>, [<Xn>, #imm]`（64 位、无符号偏移）。
///
/// 编码：`1111 1001 01 imm12(12) Rn(5) Rt(5)`。返回 `(字节偏移, 基址寄存器, 目标寄存器)`。
fn decode_ldr_imm64(insn: u32) -> Option<(u64, u8, u8)> {
    if insn & 0xFFC0_0000 != 0xF940_0000 {
        return None;
    }
    let imm12 = (insn >> 10) & 0xFFF;
    Some((
        u64::from(imm12) * 8,
        ((insn >> 5) & 0x1F) as u8,
        (insn & 0x1F) as u8,
    ))
}

// ───────────────────────── 类与类别：归属关系 ─────────────────────────

/// `class_ro_t` 里几个字段的偏移（按指针宽度分）。
///
/// 偏移照 objc4 的头文件（`objc-runtime-new.h`）逐字段累加，**不是**照本文件的
/// 解析代码反推（CLAUDE.md §6.11）：
///
/// ```text
/// 64 位：flags(4) instanceStart(4) instanceSize(4) reserved(4)
///        ivarLayout(8)@16 name(8)@24 baseMethodList(8)@32
///        baseProtocols(8)@40 ivars(8)@48 weakIvarLayout(8)@56 baseProperties(8)@64
/// 32 位：flags(4) instanceStart(4) instanceSize(4)
///        ivarLayout(4)@12 name(4)@16 baseMethodList(4)@20
///        baseProtocols(4)@24 ivars(4)@28 …
/// ```
///
/// 64 位多出来的那个 4 字节 `reserved` 是关键：漏了它，`name` 会读在 +20 上，
/// 于是类名恒为空 —— 而单测若按同一个错误假设拼镜像，会一路绿着（§6.11 的原话）。
#[derive(Debug, Clone, Copy)]
struct RoLayout {
    name: u64,
    methods: u64,
    protocols: u64,
    ivars: u64,
}

impl RoLayout {
    fn for_ctx(ctx: &Ctx<'_>) -> Self {
        if ctx.ptr_size == 8 {
            Self {
                name: 24,
                methods: 32,
                protocols: 40,
                ivars: 48,
            }
        } else {
            Self {
                name: 16,
                methods: 20,
                protocols: 24,
                ivars: 28,
            }
        }
    }
}

/// 从 `class_t` 的地址读出类名。
///
/// 路径：`class_t.data`（第 5 个指针）→ `class_ro_t` → `name`。
/// 任何一步解不出来就是 `None`，不拿 `__objc_classname` 池里的名字去凑。
fn class_name_at(ctx: &Ctx<'_>, class_addr: u64) -> Option<String> {
    let layout = RoLayout::for_ctx(ctx);
    let Pointer::Address(ro) = ctx.resolve_pointer(class_addr + 4 * ctx.ptr_size) else {
        return None;
    };
    let Pointer::Address(name) = ctx.resolve_pointer(ro + layout.name) else {
        return None;
    };
    ctx.cstring(name).filter(|text| !text.is_empty())
}

/// 解一张类方法表指针（`class_ro_t.baseMethods` 那个槽）。
fn methods_at(
    ctx: &Ctx<'_>,
    field_addr: u64,
    selectors_by_slot: &HashMap<u64, String>,
    methtypes: &HashMap<u64, String>,
    unnamed: &mut usize,
) -> Vec<ObjcMethod> {
    let Pointer::Address(list) = ctx.resolve_pointer(field_addr) else {
        return Vec::new();
    };
    match parse_method_list_at(ctx, list, selectors_by_slot, methtypes) {
        Some((methods, list_unnamed, _next)) => {
            *unnamed += list_unnamed;
            methods
        }
        None => Vec::new(),
    }
}

/// 解协议名列表（`protocol_list_t`）：`count` + `protocol_t*[count]`，
/// `protocol_t` 的第 2 个字段就是协议名。
fn protocols_at(ctx: &Ctx<'_>, field_addr: u64) -> Vec<String> {
    let Pointer::Address(list) = ctx.resolve_pointer(field_addr) else {
        return Vec::new();
    };
    let Some(header) = ctx.file_offset(list) else {
        return Vec::new();
    };
    let Some(count) = ctx.u64_at(header) else {
        return Vec::new();
    };
    if count > MAX_METHODS_PER_LIST as u64 {
        return Vec::new();
    }
    let mut out = Vec::new();
    for index in 1..=count {
        let entry = list + index * ctx.ptr_size;
        let Pointer::Address(protocol) = ctx.resolve_pointer(entry) else {
            continue;
        };
        let Pointer::Address(name) = ctx.resolve_pointer(protocol + ctx.ptr_size) else {
            continue;
        };
        if let Some(text) = ctx.cstring(name) {
            if !text.is_empty() {
                out.push(text);
            }
        }
    }
    out
}

/// 解实例变量名（`ivar_list_t`）。
///
/// `ivar_t` 有两种布局，按表头的 `entsize` 分：
///
/// * `32`（64 位绝对指针）：offset(8) name(8)@+8 type(8) alignment(4) size(4)
/// * `20`（相对偏移）：offset(i32) name(i32)@+4 type(i32) alignment(4) size(4)
///
/// 别的 `entsize` 一律不认并记账 —— 认错布局读出来的是别处的字节，
/// 那种"名字"比没有更糟。
fn ivars_at(ctx: &Ctx<'_>, field_addr: u64, unparsed: &mut usize) -> Vec<String> {
    let Pointer::Address(list) = ctx.resolve_pointer(field_addr) else {
        return Vec::new();
    };
    let Some(header) = ctx.file_offset(list) else {
        return Vec::new();
    };
    let (Some(entsize), Some(count)) = (ctx.u32_at(header), ctx.u32_at(header + 4)) else {
        return Vec::new();
    };
    if count > MAX_METHODS_PER_LIST {
        return Vec::new();
    }
    if !matches!(entsize, 20 | 32) {
        *unparsed += 1;
        return Vec::new();
    }
    let mut out = Vec::new();
    for index in 0..u64::from(count) {
        let entry = list + 8 + index * u64::from(entsize);
        let name = if entsize == 32 {
            match ctx.resolve_pointer(entry + 8) {
                Pointer::Address(addr) => ctx.cstring(addr),
                _ => None,
            }
        } else {
            let Some(offset) = ctx.file_offset(entry + 4) else {
                continue;
            };
            let Some(relative) = ctx.i32_at(offset) else {
                continue;
            };
            ctx.cstring(relative_address(entry + 4, relative))
        };
        if let Some(text) = name {
            if !text.is_empty() {
                out.push(text);
            }
        }
    }
    out
}

/// 解一张类表（`__objc_classlist`）。
///
/// 返回 `(类列表, 解不出类名的项数)`。
fn parse_classes(
    ctx: &Ctx<'_>,
    selectors_by_slot: &HashMap<u64, String>,
    methtypes: &HashMap<u64, String>,
) -> (Vec<ObjcClass>, ClassAccount) {
    let mut classes = Vec::new();
    let mut account = ClassAccount::default();
    let Some(section) = ctx.section(SEC_CLASSLIST) else {
        return (classes, account);
    };
    let layout = RoLayout::for_ctx(ctx);
    let count = section.size / ctx.ptr_size;

    for index in 0..count {
        let slot = section.addr + index * ctx.ptr_size;
        // 类指针本身也可能是 bind（类的实现在别的 dylib 里）：那种情形只能记账。
        let Pointer::Address(class_addr) = ctx.resolve_pointer(slot) else {
            account.pointer_unresolved += 1;
            continue;
        };
        let mut entry = ObjcClass {
            address: class_addr,
            ..ObjcClass::default()
        };
        entry.name = class_name_at(ctx, class_addr);
        if entry.name.is_none() {
            account.name_unresolved += 1;
        }

        // 父类：`nil` 根类、或 bind（父类在别的库里）。
        match ctx.resolve_pointer(class_addr + ctx.ptr_size) {
            Pointer::Address(super_addr) => {
                entry.superclass = class_name_at(ctx, super_addr);
                if entry.superclass.is_none() {
                    account.superclass_unresolved += 1;
                }
            }
            Pointer::Bound => account.superclass_bound += 1,
            Pointer::Unknown => {}
        }

        if let Pointer::Address(ro) = ctx.resolve_pointer(class_addr + 4 * ctx.ptr_size) {
            entry.instance_methods = methods_at(
                ctx,
                ro + layout.methods,
                selectors_by_slot,
                methtypes,
                &mut account.unnamed_methods,
            );
            entry.protocols = protocols_at(ctx, ro + layout.protocols);
            entry.ivars = ivars_at(ctx, ro + layout.ivars, &mut account.ivars_unparsed);
        } else {
            account.ro_unresolved += 1;
        }

        // 类方法在**元类**的 `class_ro_t` 里：`class_t.isa` → 元类 → data。
        if let Pointer::Address(meta) = ctx.resolve_pointer(class_addr) {
            if let Pointer::Address(ro) = ctx.resolve_pointer(meta + 4 * ctx.ptr_size) {
                entry.class_methods = methods_at(
                    ctx,
                    ro + layout.methods,
                    selectors_by_slot,
                    methtypes,
                    &mut account.unnamed_methods,
                );
            } else {
                account.metaclass_unresolved += 1;
            }
        } else {
            account.metaclass_unresolved += 1;
        }

        classes.push(entry);
    }
    (classes, account)
}

/// 解一张类别表（`__objc_catlist`）。
///
/// `category_t` 的布局（`objc-runtime-new.h`，全是指针）：
///
/// ```text
/// +0  name                  +1*ptr  cls
/// +2*ptr instanceMethods    +3*ptr  classMethods
/// +4*ptr protocols          +5*ptr  instanceProperties
/// ```
fn parse_categories(
    ctx: &Ctx<'_>,
    selectors_by_slot: &HashMap<u64, String>,
    methtypes: &HashMap<u64, String>,
) -> (Vec<ObjcCategory>, ClassAccount) {
    let mut categories = Vec::new();
    let mut account = ClassAccount::default();
    let Some(section) = ctx.section(SEC_CATLIST) else {
        return (categories, account);
    };
    let count = section.size / ctx.ptr_size;

    for index in 0..count {
        let slot = section.addr + index * ctx.ptr_size;
        let Pointer::Address(cat_addr) = ctx.resolve_pointer(slot) else {
            account.pointer_unresolved += 1;
            continue;
        };
        let mut entry = ObjcCategory {
            address: cat_addr,
            ..ObjcCategory::default()
        };
        if let Pointer::Address(name) = ctx.resolve_pointer(cat_addr) {
            entry.name = ctx.cstring(name).filter(|text| !text.is_empty());
        }
        if entry.name.is_none() {
            account.name_unresolved += 1;
        }
        // 被扩展的类：指针指向一个 `class_t`（本地类）或是 bind（外部类）。
        match ctx.resolve_pointer(cat_addr + ctx.ptr_size) {
            Pointer::Address(class_addr) => {
                entry.class_name = class_name_at(ctx, class_addr);
                if entry.class_name.is_none() {
                    account.superclass_unresolved += 1;
                }
            }
            Pointer::Bound => account.superclass_bound += 1,
            Pointer::Unknown => {}
        }
        entry.instance_methods = methods_at(
            ctx,
            cat_addr + 2 * ctx.ptr_size,
            selectors_by_slot,
            methtypes,
            &mut account.unnamed_methods,
        );
        entry.class_methods = methods_at(
            ctx,
            cat_addr + 3 * ctx.ptr_size,
            selectors_by_slot,
            methtypes,
            &mut account.unnamed_methods,
        );
        categories.push(entry);
    }
    (categories, account)
}

/// 类/类别解析的账目（CLAUDE.md §7：解不出来的要能说清是哪一种"解不出来"）。
#[derive(Debug, Clone, Copy, Default)]
struct ClassAccount {
    /// 表项指针本身解不出来（bind 或坏指针）。
    pointer_unresolved: usize,
    /// 类名/类别名解不出来。
    name_unresolved: usize,
    /// 父类指针是 bind：父类在别的库里，静态文件里没有名字。
    superclass_bound: usize,
    /// 父类/被扩展类的名字解不出来。
    superclass_unresolved: usize,
    /// `class_ro_t` 解不出来。
    ro_unresolved: usize,
    /// 元类（类方法所在）解不出来。
    metaclass_unresolved: usize,
    /// 方法表里没解出名字的项。
    unnamed_methods: usize,
    /// ivar 表布局不认识。
    ivars_unparsed: usize,
}

/// 把一张 `class_ro_t` 读成 `(类名, 实例方法, 类方法, ivar, 协议)` —— 只给测试用。
///
/// 单测要单独验一个类对象的各个字段，又不想把整套 `parse` 的产物搬来搬去。
#[cfg(test)]
fn decode_class_for_test(
    ctx: &Ctx<'_>,
    class_addr: u64,
    selectors_by_slot: &HashMap<u64, String>,
    methtypes: &HashMap<u64, String>,
) -> ObjcClass {
    let layout = RoLayout::for_ctx(ctx);
    let mut unnamed = 0usize;
    let mut ivars_unparsed = 0usize;
    let mut out = ObjcClass {
        address: class_addr,
        ..ObjcClass::default()
    };
    out.name = class_name_at(ctx, class_addr);
    if let Pointer::Address(super_addr) = ctx.resolve_pointer(class_addr + ctx.ptr_size) {
        out.superclass = class_name_at(ctx, super_addr);
    }
    if let Pointer::Address(ro) = ctx.resolve_pointer(class_addr + 4 * ctx.ptr_size) {
        out.instance_methods = methods_at(
            ctx,
            ro + layout.methods,
            selectors_by_slot,
            methtypes,
            &mut unnamed,
        );
        out.protocols = protocols_at(ctx, ro + layout.protocols);
        out.ivars = ivars_at(ctx, ro + layout.ivars, &mut ivars_unparsed);
    }
    if let Pointer::Address(meta) = ctx.resolve_pointer(class_addr) {
        if let Pointer::Address(ro) = ctx.resolve_pointer(meta + 4 * ctx.ptr_size) {
            out.class_methods = methods_at(
                ctx,
                ro + layout.methods,
                selectors_by_slot,
                methtypes,
                &mut unnamed,
            );
        }
    }
    out
}

#[cfg(test)]
#[allow(clippy::unusual_byte_groupings)] // 测试里的地址字面量按节偏移紧凑书写
mod tests {
    use super::*;
    use crate::format::macho::{MachOSection, MachOSegment};

    /// 一条合成节。
    ///
    /// `flags = 0`：不是零填充节（Ctx 只收有文件数据的节）。
    fn section(sectname: &str, addr: u64, size: u64, offset: u32) -> MachOSection {
        MachOSection {
            sectname: sectname.to_string(),
            segname: "__DATA".to_string(),
            addr,
            size,
            offset,
            align: 3,
            flags: 0,
        }
    }

    /// 合成一份"带完整 objc 元数据"的文件字节与段表。
    ///
    /// 字节布局（偏移与地址**独立**算好，见各测试的注释；这些常量不是
    /// 从解析代码推出来的，是拿真实样本 + llvm-objdump 的实读输出对的）：
    ///
    /// | 文件偏移 | 内容 |
    /// | --- | --- |
    /// | 0x1000 | `__objc_methlist`：一个方法表（entsize 12，count 1） |
    /// | 0x1200 | `__objc_selrefs`：一格，链式 rebase → 0xdd3d |
    /// | 0x1300 | `__objc_methname`：`URLByAppendingPathComponent:\0` |
    /// | 0x1400 | `__objc_methtype`：`v24@0:8@16\0` |
    /// | 0x1500 | `__objc_stubs`：`adrp x1` + `ldr x1, [x1, #0x1a8]` |
    fn fixture() -> (Vec<u8>, Vec<MachOSegment>) {
        let mut bytes = vec![0u8; 0x2000];
        // 方法表（objc4 相对指针 ABI，见模块文档）：
        // entsize_and_flags = 0x8000000c（entsize 12，flags = ML_INITIALIZED）
        // count = 1
        // name  = 相对 name 字段自己的地址 → 选择器槽 0x1000141a8（差量 0x7920）
        // types = 相对 types 字段 → 类型编码 0x10000e8d4（差量 0x2048）
        // imp   = 相对 imp 字段 → 0x100004518（差量 0xffff7c88）
        bytes[0x1000..0x1014].copy_from_slice(&[
            0x0c, 0x00, 0x00, 0x80, 0x01, 0x00, 0x00, 0x00, 0x20, 0x79, 0x00, 0x00, 0x48, 0x20,
            0x00, 0x00, 0x88, 0x7c, 0xff, 0xff,
        ]);
        // 选择器槽：链式 rebase 指针，目标偏移 0xdd3d（相对镜像基址 0x100000000）。
        bytes[0x1200..0x1208].copy_from_slice(&[0x3d, 0xdd, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00]);
        // 选择器名池（真实样本里就有这个名字）。
        let name = b"URLByAppendingPathComponent:\0";
        bytes[0x1300..0x1300 + name.len()].copy_from_slice(name);
        // 类型编码池。
        let types = b"v24@0:8@16\0";
        bytes[0x1400..0x1400 + types.len()].copy_from_slice(types);
        // 消息桩：adrp x1（0xb0000041）+ ldr x1, [x1, #0x1a8]（0xf940d421）。
        // 真实字节与 llvm-objdump 的实读基准一致（见 `bitflip_arch::plt` 的常量出处）。
        bytes[0x1500..0x1508].copy_from_slice(&[0x41, 0x00, 0x00, 0xb0, 0x21, 0xd4, 0x40, 0xf9]);

        let sections = vec![
            section("__objc_methlist", 0x10000_c880, 0x14, 0x1000),
            section("__objc_selrefs", 0x10001_41a8, 8, 0x1200),
            section("__objc_methname", 0x10000_dd3d, name.len() as u64, 0x1300),
            section("__objc_methtype", 0x10000_e8d4, types.len() as u64, 0x1400),
            section("__objc_stubs", 0x10000_b940, 8, 0x1500),
        ];
        let segments = vec![MachOSegment {
            name: "__DATA".to_string(),
            vmaddr: 0x10000_0000,
            vmsize: 0x2000,
            fileoff: 0,
            filesize: 0x2000,
            maxprot: 3,
            initprot: 3,
            sections,
        }];
        (bytes, segments)
    }

    #[test]
    fn adrp_decodes_page_from_pc() {
        // 真实字节（llvm-objdump：`adrp x1, 0x9000`，PC 页 0x10000b000 + 0x9000）：
        let (page, reg) = decode_adrp(0xb000_0041, 0x10000_b940).expect("应当解出 adrp");
        assert_eq!(page, 0x10001_4000, "页 = PC 页 + imm << 12");
        assert_eq!(reg, 1, "目标寄存器是 x1");
    }

    #[test]
    fn adrp_negative_immediate_wraps() {
        // 手工拼的 `adrp x0, #-0x1000`（imm 全 1 = -1）：页向低回卷一整页。
        let (page, reg) = decode_adrp(0xf0ff_ffe0, 0x10000_b940).expect("应当解出 adrp");
        assert_eq!(page, 0x10000_a000, "PC 页 0x10000b000 - 0x1000");
        assert_eq!(reg, 0);
    }

    #[test]
    fn adrp_rejects_non_adrp() {
        // `br x16`（0xd61f0200）不是 adrp。
        assert!(decode_adrp(0xd61f_0200, 0x1000).is_none());
    }

    #[test]
    fn ldr_imm64_decodes_scaled_offset() {
        // 真实字节（样本第一条消息桩的取选择器）：`ldr x1, [x1, #0x1a8]`。
        assert_eq!(decode_ldr_imm64(0xf940_d421), Some((0x1a8, 1, 1)));
        // 真实字节（取 GOT 的 `ldr x16, [x16, #0x228]`）。
        assert_eq!(decode_ldr_imm64(0xf941_1610), Some((0x228, 16, 16)));
    }

    #[test]
    fn ldr_imm64_rejects_other_loads() {
        // `ldr w1, [x1]`（32 位）不是 64 位无符号偏移形态。
        assert!(decode_ldr_imm64(0xb940_0021).is_none());
    }

    #[test]
    fn pointer_resolution_recognizes_rebase_plain_and_bind() {
        let mut bytes = vec![0u8; 0x1000];
        // 普通指针（绝对地址写在槽里）。
        bytes[0x100] = 0x3d;
        bytes[0x101] = 0xdd;
        bytes[0x106] = 0x01;
        // 链式 rebase（低 36 位 = 相对基址的偏移，高位是链信息）。
        bytes[0x108..0x110].copy_from_slice(&[0x3d, 0xdd, 0x00, 0x00, 0x00, 0x00, 0x10, 0x00]);
        // bind（最高位置 1）。
        bytes[0x110..0x118].copy_from_slice(&[0x67, 0x00, 0x00, 0x00, 0x00, 0x00, 0x10, 0x80]);
        let sections = vec![
            section("__DATA_PLACEHOLDER", 0x10000_0000, 0x1000, 0),
            section("__objc_methname", 0x10000_dd3d, 0x100, 0x100),
        ];
        let segments = vec![MachOSegment {
            name: "__DATA".to_string(),
            vmaddr: 0x10000_0000,
            vmsize: 0x2000,
            fileoff: 0,
            filesize: 0x2000,
            maxprot: 3,
            initprot: 3,
            sections,
        }];
        let ctx = Ctx::new(&bytes, 0x10000_0000, true, true, &segments);
        // 槽 0x100000100 里的普通指针解成绝对地址。
        assert_eq!(
            ctx.resolve_pointer(0x10000_0100),
            Pointer::Address(0x10000_dd3d)
        );
        // 槽 0x100000108 里的链式 rebase 解成 基址 + 偏移。
        assert_eq!(
            ctx.resolve_pointer(0x10000_0108),
            Pointer::Address(0x10000_dd3d)
        );
        // bind 指针：目标在符号池里，静态文件里没有地址。
        assert_eq!(ctx.resolve_pointer(0x10000_0110), Pointer::Bound);
        // 零值：解不出来。
        assert_eq!(ctx.resolve_pointer(0x10000_0200), Pointer::Unknown);
    }

    #[test]
    fn full_parse_gives_selectors_methods_and_stubs() {
        let (bytes, segments) = fixture();
        let ctx = Ctx::new(&bytes, 0x10000_0000, true, true, &segments);
        let meta = parse(&bytes, 0x10000_0000, true, true, Arch::Aarch64, &segments);
        let _ = ctx;

        // 选择器引用：槽 → 名字。
        assert_eq!(meta.selector_refs.len(), 1);
        assert_eq!(meta.selector_refs[0].slot, 0x10001_41a8);
        assert_eq!(meta.selector_refs[0].target, 0x10000_dd3d);
        assert_eq!(meta.selector_refs[0].name, "URLByAppendingPathComponent:");

        // 方法：选择器 + 类型编码 + 实现地址。
        assert_eq!(meta.methods.len(), 1);
        assert_eq!(meta.methods[0].selector, "URLByAppendingPathComponent:");
        assert_eq!(meta.methods[0].types.as_deref(), Some("v24@0:8@16"));
        assert_eq!(meta.methods[0].imp, Some(0x10000_4518));

        // 消息桩：adrp + ldr 解出的槽在表里 → 桩有名字。
        assert_eq!(meta.stubs.len(), 1);
        assert_eq!(meta.stubs[0].address, 0x10000_b940);
        assert_eq!(meta.stubs[0].selector, "URLByAppendingPathComponent:");

        // 说明里有账。
        assert!(
            meta.notes
                .iter()
                .any(|note| note.contains("选择器引用 1 个")),
            "{:?}",
            meta.notes
        );
    }

    // ───────────────── 类 / 类别的归属关系 ─────────────────

    /// 写一个 32 位小端。
    fn put_u32(bytes: &mut [u8], offset: usize, value: u32) {
        bytes[offset..offset + 4].copy_from_slice(&value.to_le_bytes());
    }

    /// 写一个 64 位小端。
    fn put_u64(bytes: &mut [u8], offset: usize, value: u64) {
        bytes[offset..offset + 8].copy_from_slice(&value.to_le_bytes());
    }

    /// 写一个"链式 rebase 指针"：值是相对镜像基址的偏移（§ `resolve_pointer`）。
    fn put_rebase(bytes: &mut [u8], offset: usize, target_vaddr: u64) {
        put_u64(bytes, offset, target_vaddr - 0x1_0000_0000);
    }

    /// 写一个"相对字段自己地址"的 int32（现代方法表 ABI）。
    fn put_rel32(bytes: &mut [u8], entry_vaddr: u64, field_in_entry: u64, target_vaddr: u64) {
        let field_vaddr = entry_vaddr + field_in_entry;
        let relative = (target_vaddr as i64 - field_vaddr as i64) as i32;
        let offset =
            usize::try_from(field_vaddr - 0x1_0000_0000).expect("测试地址在 0x100000000 之上");
        bytes[offset..offset + 4].copy_from_slice(&relative.to_le_bytes());
    }

    /// 合成一份"有类、有类别"的镜像。
    ///
    /// 布局**照 objc4 的结构定义算**（不是从解析代码反推，CLAUDE.md §6.11）：
    /// `class_t` 五个指针 40 字节、`class_ro_t` 的字段偏移见 `RoLayout` 的文档、
    /// `method_list_t` 是 8 字节表头 + `entsize` 项、`category_t` 六个指针。
    ///
    /// 地址约定：镜像基址 0x1_0000_0000，段覆盖 0x2000 字节，文件偏移 = 地址低位。
    ///
    /// | 区 | 地址 | 内容 |
    /// | --- | --- | --- |
    /// | 类表 | 0x1000 | 1 格 → `class_t` 0x1800 |
    /// | 类别表 | 0x1100 | 1 格 → `category_t` 0x1900 |
    /// | 名字池 | 0x1200… | 选择器、类名、类别名、协议名 |
    /// | const | 0x1300 | 类 ro、元类 ro、方法表、协议表、ivar 表 |
    /// | data | 0x1800 | class_t、元类 class_t、category_t、父类 class_t 与 ro |
    ///
    /// `superclass_bind` 为真时父类指针写成 bind（父类在别的库），用来验"如实标未知"。
    fn class_fixture(superclass_bind: bool) -> (Vec<u8>, Vec<MachOSegment>) {
        let mut bytes = vec![0u8; 0x2000];

        // ── 名字池（都是 NUL 结尾的 cstring）──
        let names: &[(usize, &str)] = &[
            (0x1200, "setup"),
            (0x1210, "shared"),
            (0x1220, "doHook:"),
            (0x1240, "MyClass"),
            (0x1250, "MyParent"),
            (0x1260, "MyProto"),
            (0x1270, "Hooks"),
            (0x1280, "count"),  // ivar 名
            (0x1290, "v8@0:4"), // 类型编码
        ];
        for &(offset, text) in names {
            bytes[offset..offset + text.len()].copy_from_slice(text.as_bytes());
            bytes[offset + text.len()] = 0;
        }

        // ── 类表 / 类别表：各一格 rebase 指针 ──
        put_rebase(&mut bytes, 0x1000, 0x1_0000_1800); // → class_t
        put_rebase(&mut bytes, 0x1100, 0x1_0000_1900); // → category_t

        // ── 类 ro（0x1300，64 位布局）──
        put_u32(&mut bytes, 0x1300, 0x0); // flags
        put_u32(&mut bytes, 0x1304, 8); // instanceStart
        put_u32(&mut bytes, 0x1308, 16); // instanceSize
        put_u32(&mut bytes, 0x130c, 0); // reserved（64 位专有！）
        put_u64(&mut bytes, 0x1310, 0); // ivarLayout = nil
        put_rebase(&mut bytes, 0x1318, 0x1_0000_1240); // name → "MyClass"
        put_rebase(&mut bytes, 0x1320, 0x1_0000_1600); // baseMethods
        put_rebase(&mut bytes, 0x1328, 0x1_0000_1700); // baseProtocols
        put_rebase(&mut bytes, 0x1330, 0x1_0000_1740); // ivars
                                                       // weakIvarLayout(0x1338) 与 baseProperties(0x1340) 留 0。

        // ── 元类 ro（0x1380）：flags 带 RO_META(1)，baseMethods 是类方法表 ──
        put_u32(&mut bytes, 0x1380, 0x1); // flags = RO_META
        put_rebase(&mut bytes, 0x1380 + 0x18, 0x1_0000_1240); // name → "MyClass"
        put_rebase(&mut bytes, 0x1380 + 0x20, 0x1_0000_1650); // baseMethods（类方法）

        // ── 实例方法表（0x1600）：表头 8 字节 + 1 项 entsize 12 ──
        put_u32(&mut bytes, 0x1600, 0x0c); // entsize = 12
        put_u32(&mut bytes, 0x1604, 1); // count = 1
                                        // entry 在 0x1608：name @+0、types @+4、imp @+8
        put_rel32(&mut bytes, 0x1_0000_1608, 0, 0x1_0000_1200); // → "setup"
        put_rel32(&mut bytes, 0x1_0000_1608, 4, 0x1_0000_1290); // → "v8@0:4"
        put_rel32(&mut bytes, 0x1_0000_1608, 8, 0x1_0000_0a00); // imp

        // ── 类方法表（0x1650）：1 项 → "shared" ──
        put_u32(&mut bytes, 0x1650, 0x0c);
        put_u32(&mut bytes, 0x1654, 1);
        put_rel32(&mut bytes, 0x1_0000_1658, 0, 0x1_0000_1210);
        put_rel32(&mut bytes, 0x1_0000_1658, 4, 0x1_0000_1290);
        put_rel32(&mut bytes, 0x1_0000_1658, 8, 0x1_0000_0a40);

        // ── 类别方法表（0x1680）：1 项 → "doHook:" ──
        put_u32(&mut bytes, 0x1680, 0x0c);
        put_u32(&mut bytes, 0x1684, 1);
        put_rel32(&mut bytes, 0x1_0000_1688, 0, 0x1_0000_1220);
        put_rel32(&mut bytes, 0x1_0000_1688, 4, 0x1_0000_1290);
        put_rel32(&mut bytes, 0x1_0000_1688, 8, 0x1_0000_0b00);

        // ── 协议表（0x1700）：count 1 + protocol_t* ──
        put_u64(&mut bytes, 0x1700, 1); // count（无符号指针）
        put_rebase(&mut bytes, 0x1708, 0x1_0000_1720); // → protocol_t
                                                       // protocol_t（0x1720）：isa、name。
        put_rebase(&mut bytes, 0x1728, 0x1_0000_1260); // name → "MyProto"

        // ── ivar 表（0x1740）：表头 8 字节 + 1 项 entsize 32（绝对指针）──
        put_u32(&mut bytes, 0x1740, 32); // entsize = 32
        put_u32(&mut bytes, 0x1744, 1); // count = 1
                                        // entry 在 0x1748：offset(0)、name@+8、type@+16
        put_rebase(&mut bytes, 0x1748 + 8, 0x1_0000_1280); // name → "count"
        put_u32(&mut bytes, 0x1748 + 24, 3); // alignment_raw
        put_u32(&mut bytes, 0x1748 + 28, 8); // size

        // ── class_t（0x1800）：isa、superclass、cache、vtable、data ──
        put_rebase(&mut bytes, 0x1800, 0x1_0000_1880); // isa → 元类 class_t
        if superclass_bind {
            // bind 指针：高位置 1（CHAINED_BIND），低位是符号池序号。
            put_u64(&mut bytes, 0x1800 + 8, 0x8000_0000_0000_0064);
        } else {
            put_rebase(&mut bytes, 0x1800 + 8, 0x1_0000_1a00); // superclass → 父类 class_t
        }
        put_rebase(&mut bytes, 0x1800 + 32, 0x1_0000_1300); // data → 类 ro

        // ── 元类 class_t（0x1880）：data 指向元类 ro ──
        put_rebase(&mut bytes, 0x1880 + 32, 0x1_0000_1380);

        // ── category_t（0x1900）：name、cls、instanceMethods、classMethods ──
        put_rebase(&mut bytes, 0x1900, 0x1_0000_1270); // name → "Hooks"
        put_rebase(&mut bytes, 0x1900 + 8, 0x1_0000_1a00); // cls → 父类（复用）
        put_rebase(&mut bytes, 0x1900 + 16, 0x1_0000_1680); // instanceMethods

        // ── 父类 class_t（0x1a00）与父类 ro（0x1a40）──
        put_rebase(&mut bytes, 0x1a00 + 32, 0x1_0000_1a40);
        put_rebase(&mut bytes, 0x1a40 + 0x18, 0x1_0000_1250); // name → "MyParent"

        let sections = vec![
            section("__objc_classlist", 0x1_0000_1000, 8, 0x1000),
            section("__objc_catlist", 0x1_0000_1100, 8, 0x1100),
            section("__objc_classname", 0x1_0000_1200, 0x100, 0x1200),
            section("__objc_const", 0x1_0000_1300, 0x500, 0x1300),
            section("__objc_data", 0x1_0000_1800, 0x300, 0x1800),
        ];
        let segments = vec![MachOSegment {
            name: "__DATA".to_string(),
            vmaddr: 0x1_0000_0000,
            vmsize: 0x2000,
            fileoff: 0,
            filesize: 0x2000,
            maxprot: 3,
            initprot: 3,
            sections,
        }];
        (bytes, segments)
    }

    #[test]
    fn a_class_ro_yields_name_superclass_methods_ivars_and_protocols() {
        let (bytes, segments) = class_fixture(false);
        let ctx = Ctx::new(&bytes, 0x1_0000_0000, true, true, &segments);

        let class = decode_class_for_test(&ctx, 0x1_0000_1800, &HashMap::new(), &HashMap::new());

        assert_eq!(
            class.name.as_deref(),
            Some("MyClass"),
            "类名在 ro +24（64 位有 reserved）"
        );
        assert_eq!(
            class.superclass.as_deref(),
            Some("MyParent"),
            "父类走 superclass → ro.name"
        );

        // 实例方法：相对偏移 ABI（entsize 12）。
        assert_eq!(class.instance_methods.len(), 1);
        let method = &class.instance_methods[0];
        assert_eq!(method.selector, "setup");
        assert_eq!(method.types.as_deref(), Some("v8@0:4"));
        assert_eq!(method.imp, Some(0x1_0000_0a00));

        // 类方法在元类的 ro 里。
        assert_eq!(class.class_methods.len(), 1);
        assert_eq!(class.class_methods[0].selector, "shared");
        assert_eq!(class.class_methods[0].imp, Some(0x1_0000_0a40));

        // ivar 与协议。
        assert_eq!(class.ivars, vec!["count".to_string()]);
        assert_eq!(class.protocols, vec!["MyProto".to_string()]);
    }

    #[test]
    fn a_category_carries_its_owner_class_and_methods() {
        let (bytes, segments) = class_fixture(false);

        let meta = parse(&bytes, 0x1_0000_0000, true, true, Arch::Aarch64, &segments);

        assert_eq!(meta.categories.len(), 1);
        let category = &meta.categories[0];
        assert_eq!(category.name.as_deref(), Some("Hooks"));
        assert_eq!(category.class_name.as_deref(), Some("MyParent"));
        assert_eq!(category.instance_methods.len(), 1);
        assert_eq!(category.instance_methods[0].selector, "doHook:");
        assert_eq!(category.instance_methods[0].imp, Some(0x1_0000_0b00));
    }

    #[test]
    fn a_bound_superclass_is_reported_as_unknown_not_invented() {
        let (bytes, segments) = class_fixture(true);
        let ctx = Ctx::new(&bytes, 0x1_0000_0000, true, true, &segments);

        let (classes, account) = parse_classes(&ctx, &HashMap::new(), &HashMap::new());
        assert_eq!(classes.len(), 1);
        assert_eq!(
            classes[0].superclass, None,
            "父类是 bind（在别的库里）⇒ 名字未知，不许编造"
        );
        assert_eq!(account.superclass_bound, 1, "这件事要记账");
        assert_eq!(
            classes[0].name.as_deref(),
            Some("MyClass"),
            "类本身的名字照样解得出来"
        );
    }

    #[test]
    fn the_full_parse_reports_class_ownership_in_notes() {
        let (bytes, segments) = class_fixture(false);
        let meta = parse(&bytes, 0x1_0000_0000, true, true, Arch::Aarch64, &segments);

        assert!(
            meta.notes.iter().any(|note| note.contains("ObjC 归属")),
            "归属的账目要在 notes 里：{:?}",
            meta.notes
        );
        assert!(!meta.is_empty());
        assert_eq!(meta.classes.len(), 1);
        assert_eq!(meta.categories.len(), 1);
    }
}
