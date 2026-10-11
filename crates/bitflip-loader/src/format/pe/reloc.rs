//! PE 基址重定位表（`.reloc`）。
//!
//! 表是**分块**的：每块一个 4 KiB 页基址加若干 12 位偏移的条目，块尾用
//! `IMAGE_REL_BASED_ABSOLUTE`（0）填充对齐。所以"条目数"不等于"有效重定位数"，
//! 填充项必须与真实项分开记账，否则报出来的数字会虚高 —— 而虚高的数字看起来
//! 完全正常，没人会去怀疑它。

use super::*;

/// 解析基址重定位表（`.reloc`，分块结构），返回（重定位项，降级说明）。
pub(super) fn parse_relocations(
    reader: &Reader<'_>,
    object: &Object,
    dir: DataDir,
) -> Result<(Vec<Reloc>, Vec<String>), ParseError> {
    let offset = rva_to_offset(object, dir.rva).ok_or_else(|| {
        ParseError::Inconsistent(format!(
            "重定位表 RVA {:#x} 不在任何有文件后备的节里",
            dir.rva
        ))
    })?;
    let total = u64::from(dir.size);
    let mut out = Vec::new();
    let mut skipped = Vec::new();
    let mut malformed_blocks = 0u32;
    let mut cursor = 0u64;

    // 块结构：DWORD PageRVA + DWORD BlockSize（含这 8 字节）+ 若干 WORD 项
    while cursor + 8 <= total {
        let Some(base) = offset.checked_add(cursor) else {
            break;
        };
        let Ok(header) = reader.slice(base, 8, "重定位块头") else {
            break;
        };
        let header = Reader::with_base(header, reader.base() + base);
        let page_rva = header.u32(0, Endianness::Little, "PageRVA")?;
        let block_size = u64::from(header.u32(4, Endianness::Little, "BlockSize")?);

        // BlockSize 必须 >= 8 且不超过剩余空间，否则结构坏了
        if block_size < 8 || cursor + block_size > total {
            malformed_blocks += 1;
            break;
        }

        let entry_count = (block_size - 8) / 2;
        for index in 0..entry_count {
            let Some(entry_offset) = base.checked_add(8 + index * 2) else {
                break;
            };
            let Ok(view) = reader.slice(entry_offset, 2, "重定位项") else {
                break;
            };
            let raw = u16::from_le_bytes([view[0], view[1]]);
            let kind = u32::from(raw >> 12);
            let page_offset = u32::from(raw & 0x0fff);

            if kind == 0 {
                continue; // ABSOLUTE 是填充项，跳过
            }

            let address = rva_to_va(object, page_rva.wrapping_add(page_offset));
            out.push(Reloc {
                address,
                // 镜像里的重定位项写的是虚拟地址，按节查回去即可；查不到就如实给
                // `None`（地址落在任何节之外，例如头里）。
                section: object
                    .section_at(address)
                    .map(|section| section.name.clone())
                    .filter(|name| !name.is_empty()),
                kind: match kind {
                    3 => RelocKind::Absolute,  // HIGHLOW
                    10 => RelocKind::Absolute, // DIR64
                    1 => RelocKind::Absolute,  // HIGH
                    2 => RelocKind::Absolute,  // LOW
                    4 => RelocKind::Relative,  // HIGHADJ
                    _ => RelocKind::Other,
                },
                raw_kind: kind,
                symbol: None,
                addend: 0,
            });

            if out.len() as u64 > MAX_TABLE_ENTRIES {
                return Err(ParseError::Overflow(format!(
                    "重定位项超过上限 {MAX_TABLE_ENTRIES}"
                )));
            }
        }

        cursor += block_size;
    }

    if malformed_blocks > 0 {
        skipped.push(format!(
            "重定位表里有 {malformed_blocks} 个块的 BlockSize 非法，该块及其后的块已跳过"
        ));
    }

    Ok((out, skipped))
}
