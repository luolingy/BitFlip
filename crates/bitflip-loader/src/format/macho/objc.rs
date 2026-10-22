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

use crate::object::{ObjcMetadata, ObjcMethod, ObjcSelectorRef, ObjcStub};

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
    /// 节名 → 位置。
    sections: HashMap<&'a str, SectionInfo>,
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
        for segment in segments {
            for section in &segment.sections {
                if section.size == 0 || super::is_zerofill_section(section.flags) {
                    continue;
                }
                // 同名节只认第一个（文件里不该有两个同名节；真有了也只取第一个，
                // 不猜哪个是真的）。
                sections
                    .entry(section.sectname.as_str())
                    .or_insert(SectionInfo {
                        addr: section.addr,
                        size: section.size,
                        offset: u64::from(section.offset),
                    });
            }
        }
        Self {
            bytes,
            base,
            little,
            ptr_size: if is_64 { 8 } else { 4 },
            sections,
        }
    }

    /// 取节。
    fn section(&self, name: &str) -> Option<&SectionInfo> {
        self.sections.get(name)
    }

    /// 虚拟地址落在哪个节里。
    fn section_containing(&self, vaddr: u64) -> Option<&SectionInfo> {
        self.sections.values().find(|section| {
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

    // 方法表。
    let (methods, unnamed_methods) = parse_method_lists(&ctx, &selectors_by_slot, &methtypes);

    // 消息转发桩。
    let (stubs, not_selector) = parse_stubs(&ctx, &selectors_by_slot, arch);

    meta.selector_refs = selector_refs;
    meta.methods = methods;
    meta.stubs = stubs;
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

    let mut offset = 0u64;
    while offset + 8 <= section.size {
        let Some(entsize_flags) = ctx.u32_at(section.offset + offset) else {
            break;
        };
        let Some(count) = ctx.u32_at(section.offset + offset + 4) else {
            break;
        };
        let entsize = entsize_flags & 0xFFFF;
        if !matches!(entsize, 8 | 12 | 24) {
            break;
        }
        if count > MAX_METHODS_PER_LIST {
            break;
        }
        for index in 0..u64::from(count) {
            let entry = offset + 8 + index * u64::from(entsize);
            if entry + u64::from(entsize) > section.size {
                break;
            }
            let entry_addr = section.addr + entry;
            let file_offset = section.offset + entry;
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
        // 下一个方法表：`8 + count * entsize`，按 8 字节对齐
        // （方法表里含指针，运行时保持指针对齐）。
        let mut next = offset + 8 + u64::from(count) * u64::from(entsize);
        let aligned_addr = (section.addr + next + 7) & !7;
        let aligned = aligned_addr.saturating_sub(section.addr);
        if aligned < section.size {
            next = aligned;
        }
        offset = next;
    }
    (methods, unnamed)
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
}
