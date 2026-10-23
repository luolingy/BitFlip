//! Swift 元数据解析（`__swift5_*` 节）——**有界、如实**的那一层。
//!
//! 目标不是"完整还原 Swift 语义"（那要连同类型元数据、泛型、字段描述一起重建，
//! 是另一个量级），而是先把**文件里明明白白写着、又能低风险读出来**的东西给出：
//!
//! - `__swift5_types`：每个条目是 4 字节**相对**指针，指向一个类型描述符
//!   （`ContextDescriptor`）；描述符偏移 8 处的 `int32` 相对指针指向**名字**
//!   （mangled symbol，如 `_$s7SideStore12ImportExportC`）。这里解出类型个数与名字。
//! - `__swift5_protos`：同构，指向协议描述符，解出协议个数与名字。
//! - `__swift5_entry`：单个相对指针，指向 Swift 入口（`_main`）。
//!
//! 其余 Swift 节（`__swift5_reflstr` / `__swift5_fieldmd` / `__swift5_typeref` /
//! `__swift5_assocty` / `__swift5_mpenum` / `__swift5_capture` 及 hook 节）**只报
//! 存在与字节数，不假装解出字段/反映射**：那些要跟着类型元数据逐层走，读错了比
//! 不读更糟（§7）。名字是文件的字面事实；解不出的描述符计数进 `skipped`，
//! 原因写进 `notes`。
//!
//! 复用 [`super::objc::Ctx`] 的节表与读字节能力（不重复造一套）；相对指针的解引用
//! 就三步：`file_offset` → `i32_at` → 目标地址 = 字段自身地址 + 相对值。

use super::objc::Ctx;
use crate::object::{SwiftMetadata, SwiftSymbol};

/// 一个 Swift 描述符解出来的名字（mangled）。类型定义在 [`crate::object`]。
///
/// Swift 元数据的解析结果结构也定义在 [`crate::object`]（`SwiftMetadata`），这里
/// 只负责**填空**它：loader 的对象模型是对外契约，`format` 层只生产、不改形状。
const CONTEXT_DESCRIPTOR_NAME_OFFSET: u64 = 8;

/// 解一个 `int32` 相对指针数组（`__swift5_types` / `__swift5_protos` 的形态）。
///
/// 返回 `(解出的名字列表, 条目总数, 跳过数)`。数组本身按 4 字节步进；每个条目读一个
/// `int32` 相对值，目标 = 条目地址 + 值；再按描述符偏移 8 读名字相对指针 → C 串。
fn parse_descriptor_array(ctx: &Ctx<'_>, section_name: &str) -> (Vec<SwiftSymbol>, usize, usize) {
    let Some(section) = ctx.section(section_name) else {
        return (Vec::new(), 0, 0);
    };
    if section.size < 4 {
        return (Vec::new(), 0, 0);
    }
    let entries = usize::try_from(section.size / 4).unwrap_or(0);
    let mut out = Vec::new();
    let mut skipped = 0usize;
    for index in 0..entries {
        let entry_addr = section.addr + (index as u64) * 4;
        let Some(entry_off) = ctx.file_offset(entry_addr) else {
            skipped += 1;
            continue;
        };
        let Some(relative) = ctx.i32_at(entry_off) else {
            skipped += 1;
            continue;
        };
        let descriptor = entry_addr.wrapping_add(i64::from(relative) as u64);
        match descriptor_name(ctx, descriptor) {
            Some(name) => out.push(SwiftSymbol {
                address: descriptor,
                name,
            }),
            None => skipped += 1,
        }
    }
    (out, entries, skipped)
}

/// 从描述符读出名字：偏移 8 的 `int32` 相对指针 → C 串。
fn descriptor_name(ctx: &Ctx<'_>, descriptor: u64) -> Option<String> {
    let name_field = descriptor.checked_add(CONTEXT_DESCRIPTOR_NAME_OFFSET)?;
    let name_off = ctx.file_offset(name_field)?;
    let relative = ctx.i32_at(name_off)?;
    let name_addr = name_field.wrapping_add(i64::from(relative) as u64);
    let text = ctx.cstring(name_addr)?;
    if text.is_empty() {
        // 空名字：可能是 parent 描述符（非名义类型），不算"解出"。
        return None;
    }
    Some(text)
}

/// 解析一个 Mach-O 的 Swift 元数据。没有任何 `__swift5_*` 节时返回空表（如实"没有"）。
pub(super) fn parse(
    bytes: &[u8],
    base: u64,
    little: bool,
    is_64: bool,
    segments: &[super::MachOSegment],
) -> SwiftMetadata {
    let ctx = Ctx::new(bytes, base, little, is_64, segments);
    let mut metadata = SwiftMetadata::default();

    // 先扫一遍：哪些 __swift5_* 节存在、各多少字节；把"不解析的"如实记下来。
    let mut saw_any = false;
    for segment in segments {
        for section in &segment.sections {
            if section.size == 0 || !section.sectname.starts_with("__swift") {
                continue;
            }
            saw_any = true;
            match section.sectname.as_str() {
                "__swift5_types" | "__swift5_protos" | "__swift5_entry" => {}
                other => metadata
                    .unparsed_sections
                    .push((other.to_string(), section.size)),
            }
        }
    }
    if !saw_any {
        return metadata; // 没有 Swift 元数据：空表，不编 note。
    }

    let (types, type_total, type_skipped) = parse_descriptor_array(&ctx, "__swift5_types");
    metadata.type_count = type_total;
    metadata.types = types;
    metadata.skipped += type_skipped;

    let (protocols, proto_total, proto_skipped) = parse_descriptor_array(&ctx, "__swift5_protos");
    metadata.protocol_count = proto_total;
    metadata.protocols = protocols;
    metadata.skipped += proto_skipped;

    if let Some(section) = ctx.section("__swift5_entry") {
        metadata.has_entry = section.size >= 4;
    }

    // 说明（§7）：把"解出了多少 / 一共多少 / 跳过了多少 / 哪些没解"写清。
    if type_total > 0 {
        metadata.notes.push(format!(
            "__swift5_types：{} 个类型，解出名字 {} 个{}",
            type_total,
            metadata.types.len(),
            if type_skipped > 0 {
                format!("，{} 个描述符名字解不出（已跳过，非编造）", type_skipped)
            } else {
                String::new()
            }
        ));
    }
    if proto_total > 0 {
        metadata.notes.push(format!(
            "__swift5_protos：{} 个协议，解出名字 {} 个",
            proto_total,
            metadata.protocols.len()
        ));
    }
    if !metadata.unparsed_sections.is_empty() {
        let names: Vec<String> = metadata
            .unparsed_sections
            .iter()
            .map(|(name, size)| format!("{name}（{size} 字节）"))
            .collect();
        metadata.notes.push(format!(
            "这些 Swift 节**只列出、没有解析**（要靠完整类型元数据重建字段/反映射，\
             读错比不读更糟）：{}",
            names.join("、")
        ));
    }
    metadata
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::format::macho::{MachOSection, MachOSegment};

    /// 一节的最小构造（测试用）。
    fn section(sectname: &str, addr: u64, size: u64, offset: u32) -> MachOSection {
        MachOSection {
            sectname: sectname.to_string(),
            segname: "__DATA".to_string(),
            addr,
            size,
            offset,
            align: 2,
            flags: 0,
        }
    }

    fn segment(
        name: &str,
        vmaddr: u64,
        fileoff: u64,
        filesize: u64,
        sections: Vec<MachOSection>,
    ) -> MachOSegment {
        MachOSegment {
            name: name.to_string(),
            vmaddr,
            vmsize: filesize,
            fileoff,
            filesize,
            maxprot: 7,
            initprot: 3,
            sections,
        }
    }

    /// 造一个最小 Mach-O 形态：
    /// - `__swift5_types`（addr 0x1000，size 4，offset 0x1000）：一个 int32 相对指针，
    ///   值 = 目标描述符(0x1004) - 条目地址(0x1000) = 4。
    /// - `__const`（addr 0x1004，size 0xFC，offset 0x1004）：放描述符与名字串。
    /// - 描述符 0x1004：flags(u32)=0、parent(i32)=0、name(i32)@0x100C 相对指向名字串。
    /// - 名字串 "Foo\0" 放在 0x1014（相对 name 字段 0x100C = 8）。
    fn build_types_fixture() -> (Vec<u8>, Vec<MachOSegment>) {
        let mut bytes = vec![0u8; 0x1100];
        // 条目：相对指针 4（小端 int32）
        bytes[0x1000..0x1004].copy_from_slice(&4i32.to_le_bytes());
        // 描述符 0x1004：flags=0, parent=0, name_relative=8
        bytes[0x1004..0x1008].copy_from_slice(&0u32.to_le_bytes()); // flags
        bytes[0x1008..0x100C].copy_from_slice(&0i32.to_le_bytes()); // parent
        bytes[0x100C..0x1010].copy_from_slice(&8i32.to_le_bytes()); // name 相对 0x100C → 0x1014
                                                                    // 名字串
        bytes[0x1014..0x1018].copy_from_slice(b"Foo\0");

        let segments = vec![segment(
            "__DATA",
            0x1000,
            0x1000,
            0x100,
            vec![
                section("__swift5_types", 0x1000, 4, 0x1000),
                section("__const", 0x1004, 0xFC, 0x1004),
            ],
        )];
        (bytes, segments)
    }

    #[test]
    fn parses_a_single_type_descriptor_name() {
        let (bytes, segments) = build_types_fixture();
        let metadata = parse(&bytes, 0x1000, true, true, &segments);
        assert_eq!(metadata.type_count, 1, "应有一个类型条目");
        assert_eq!(metadata.types.len(), 1, "应解出一个名字");
        assert_eq!(metadata.types[0].address, 0x1004, "描述符地址");
        assert_eq!(metadata.types[0].name, "Foo", "名字串应读出");
        assert_eq!(metadata.skipped, 0);
        assert!(!metadata.is_empty());
    }

    #[test]
    fn no_swift_sections_yields_empty_metadata() {
        // 一个没有 __swift* 节的段：空表，且不编 note。
        let segments = vec![segment(
            "__TEXT",
            0x1000,
            0x1000,
            0x100,
            vec![section("__text", 0x1000, 0x100, 0x1000)],
        )];
        let bytes = vec![0u8; 0x1100];
        let metadata = parse(&bytes, 0x1000, true, true, &segments);
        assert!(metadata.is_empty(), "没有 Swift 节就该是空表");
        assert!(metadata.notes.is_empty(), "不该编造说明");
    }

    #[test]
    fn unparsed_sections_are_listed_not_decoded() {
        // 只有 __swift5_fieldmd（我们不解它）：unparsed 里要如实列出，不假装解析。
        let bytes = vec![0u8; 0x1100];
        let segments = vec![segment(
            "__TEXT",
            0x1000,
            0x1000,
            0x100,
            vec![section("__swift5_fieldmd", 0x1000, 0x40, 0x1000)],
        )];
        let metadata = parse(&bytes, 0x1000, true, true, &segments);
        assert_eq!(metadata.unparsed_sections.len(), 1);
        assert_eq!(metadata.unparsed_sections[0].0, "__swift5_fieldmd");
        assert!(metadata
            .notes
            .iter()
            .any(|note| note.contains("没有解析") && note.contains("__swift5_fieldmd")));
    }
}
