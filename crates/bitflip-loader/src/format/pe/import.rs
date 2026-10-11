//! PE 导入表、延迟导入表与导出表。
//!
//! 三张表的共同点是"目录项指向一张变长记录数组"，而**长度来自文件本身**：
//! 因此每一项都要先做范围校验再读，并且整体封顶（见 `MAX_TABLE_ENTRIES`）。
//! 按序号导入（名字 RVA 落在序号区间）与转发导出（导出地址落在导出目录内）
//! 是这两种表各自的暗礁，都在这里如实标注。
//!
//! 每个函数返回 `(结果, 降级说明)` 而不是直接改 `Object`：它们都需要 `&Object`
//! 做 RVA 映射（映射要查节表），同时又要报告问题 —— 交给调用方写入，
//! 避免既借用又修改。

use super::*;

/// 解析导入表，返回（导入项，降级说明）。
///
/// 返回说明而不是直接改 `Object`：这个函数需要 `&Object` 做 RVA 映射，
/// 同时又要报告问题 —— 交给调用方写入，避免既借用又修改。
pub(super) fn parse_imports(
    reader: &Reader<'_>,
    object: &Object,
    dir: DataDir,
) -> Result<(Vec<Import>, Vec<String>), ParseError> {
    // IMAGE_IMPORT_DESCRIPTOR 是 20 字节，以全 0 结尾
    const DESCRIPTOR_SIZE: u64 = 20;
    let count = u64::from(dir.size) / DESCRIPTOR_SIZE;
    if count == 0 {
        return Ok((Vec::new(), Vec::new()));
    }
    let offset = rva_to_offset(object, dir.rva).ok_or_else(|| {
        ParseError::Inconsistent(format!(
            "导入表 RVA {:#x} 不在任何有文件后备的节里",
            dir.rva
        ))
    })?;

    let mut out = Vec::new();
    let mut skipped: Vec<String> = Vec::new();
    let mut skipped_modules: Vec<String> = Vec::new();
    let mut unnamed = 0usize;
    for index in 0..count.min(MAX_TABLE_ENTRIES) {
        let Some(entry_offset) = offset.checked_add(index * DESCRIPTOR_SIZE) else {
            break;
        };
        let Ok(view) = reader.slice(entry_offset, DESCRIPTOR_SIZE, "导入描述符") else {
            break;
        };
        let view = Reader::with_base(view, reader.base() + entry_offset);

        let original_first_thunk = view.u32(0, Endianness::Little, "OriginalFirstThunk")?;
        let name_rva = view.u32(12, Endianness::Little, "Name")?;
        let first_thunk = view.u32(16, Endianness::Little, "FirstThunk")?;

        // 全 0 描述符是结束标记
        if original_first_thunk == 0 && name_rva == 0 && first_thunk == 0 {
            break;
        }

        let module = read_c_string_at_rva(reader, object, name_rva)
            .unwrap_or_else(|| format!("<无法读取名称 RVA {name_rva:#x}>"));

        // ILT（OriginalFirstThunk）给出名字；没有则退回 IAT
        let lookup_rva = if original_first_thunk != 0 {
            original_first_thunk
        } else {
            first_thunk
        };

        let is_pe32_plus = object.arch.ptr_size == 8;
        let thunk_size = if is_pe32_plus { 8u64 } else { 4 };
        let ordinal_flag: u64 = if is_pe32_plus {
            0x8000_0000_0000_0000
        } else {
            0x8000_0000
        };

        let Some(lookup_offset) = rva_to_offset(object, lookup_rva) else {
            skipped_modules.push(module.clone());
            continue;
        };

        for thunk_index in 0..MAX_TABLE_ENTRIES {
            let Some(thunk_offset) = lookup_offset.checked_add(thunk_index * thunk_size) else {
                break;
            };
            let Ok(thunk_view) = reader.slice(thunk_offset, thunk_size, "导入 thunk") else {
                break;
            };
            let thunk_view = Reader::with_base(thunk_view, reader.base() + thunk_offset);
            let value = thunk_view.uint(
                0,
                Endianness::Little,
                if is_pe32_plus { 8 } else { 4 },
                "thunk 值",
            )?;
            if value == 0 {
                break; // 结束
            }

            let iat_slot = rva_to_va(object, first_thunk + (thunk_index * thunk_size) as u32);

            if value & ordinal_flag != 0 {
                // 按序号导入
                let ordinal = (value & 0xffff) as u32;
                out.push(Import {
                    module: module.clone(),
                    name: None,
                    ordinal: Some(ordinal),
                    iat_slot: Some(iat_slot),
                    thunk: Some(rva_to_va(object, lookup_rva)),
                });
            } else {
                // Hint/Name 表：前 2 字节是 hint，之后是名字
                let name_rva_value = value as u32;
                let name = read_c_string_at_rva(reader, object, name_rva_value.wrapping_add(2));
                if name.is_none() {
                    unnamed += 1;
                }
                out.push(Import {
                    module: module.clone(),
                    name,
                    ordinal: None,
                    iat_slot: Some(iat_slot),
                    thunk: Some(rva_to_va(object, lookup_rva)),
                });
            }
        }
    }

    // 读不到的东西必须留下痕迹，不能静默少给数据（CLAUDE.md §7）
    if !skipped_modules.is_empty() {
        skipped.push(format!(
            "{} 个模块的导入 thunk 不在任何有文件后备的节里，其导入符号未列出：{}",
            skipped_modules.len(),
            skipped_modules.join("、")
        ));
    }
    if unnamed > 0 {
        skipped.push(format!(
            "有 {unnamed} 个按名字导入的符号，其名字 RVA 无法映射到文件，名字为 null"
        ));
    }

    Ok((out, skipped))
}

fn read_c_string_at_rva(reader: &Reader<'_>, object: &Object, rva: u32) -> Option<String> {
    let offset = rva_to_offset(object, rva)?;
    reader.cstr(offset, MAX_STRING, "导入名").ok()
}

/// 解析延迟导入表（`IMAGE_DELAYLOAD_DESCRIPTOR`，32 字节）。
pub(super) fn parse_delay_imports(
    reader: &Reader<'_>,
    object: &Object,
    dir: DataDir,
) -> Result<Vec<Import>, ParseError> {
    const SIZE: u64 = 32;
    let count = u64::from(dir.size) / SIZE;
    if count == 0 {
        return Ok(Vec::new());
    }
    let offset = rva_to_offset(object, dir.rva).ok_or_else(|| {
        ParseError::Inconsistent(format!(
            "延迟导入表 RVA {:#x} 不在任何有文件后备的节里",
            dir.rva
        ))
    })?;

    let mut out = Vec::new();
    for index in 0..count.min(MAX_TABLE_ENTRIES) {
        let Some(entry) = offset.checked_add(index * SIZE) else {
            break;
        };
        let Ok(view) = reader.slice(entry, SIZE, "延迟导入描述符") else {
            break;
        };
        let view = Reader::with_base(view, reader.base() + entry);

        let attributes = view.u32(0, Endianness::Little, "Attributes")?;
        let name_rva = view.u32(4, Endianness::Little, "DllNameRVA")?;
        // 全 0 是结束
        if attributes == 0 && name_rva == 0 {
            break;
        }
        let Some(module) = read_c_string_at_rva(reader, object, name_rva) else {
            continue;
        };
        // 实际 thunk 解析需要处理 RVA/VA 两种模式，M1 只记录依赖
        out.push(Import {
            module,
            name: None,
            ordinal: None,
            iat_slot: None,
            thunk: None,
        });
    }
    Ok(out)
}

/// 解析导出表。
pub(super) fn parse_exports(
    reader: &Reader<'_>,
    object: &Object,
    dir: DataDir,
) -> Result<Vec<Export>, ParseError> {
    const HEADER_SIZE: u64 = 40;
    let offset = rva_to_offset(object, dir.rva).ok_or_else(|| {
        ParseError::Inconsistent(format!(
            "导出表 RVA {:#x} 不在任何有文件后备的节里",
            dir.rva
        ))
    })?;
    let view = reader.slice(offset, HEADER_SIZE, "导出目录")?;
    let view = Reader::with_base(view, reader.base() + offset);

    let ordinal_base = view.u32(16, Endianness::Little, "Base")?;
    let num_functions = u64::from(view.u32(20, Endianness::Little, "NumberOfFunctions")?);
    let num_names = u64::from(view.u32(24, Endianness::Little, "NumberOfNames")?);
    let funcs_rva = view.u32(28, Endianness::Little, "AddressOfFunctions")?;
    let names_rva = view.u32(32, Endianness::Little, "AddressOfNames")?;
    let ordinals_rva = view.u32(36, Endianness::Little, "AddressOfNameOrdinals")?;

    if num_functions > MAX_TABLE_ENTRIES || num_names > MAX_TABLE_ENTRIES {
        return Err(ParseError::Overflow(format!(
            "导出表声称有 {num_functions} 个函数 / {num_names} 个名字，超过上限"
        )));
    }

    // 地址表：每个 4 字节 RVA，0 表示这个序号没有导出
    let Some(funcs_offset) = rva_to_offset(object, funcs_rva) else {
        return Err(ParseError::Inconsistent(
            "导出地址表 RVA 不在任何有文件后备的节里".into(),
        ));
    };
    let addresses: Vec<u32> = reader.for_each_entry(
        funcs_offset,
        4,
        num_functions,
        "导出地址表",
        |_i, v| v.u32(0, Endianness::Little, "导出 RVA"),
    )?;

    // 名字表 + 序号表：两者一一对应
    let mut names: BTreeMap<u32, String> = BTreeMap::new();
    if num_names > 0 {
        if let (Some(names_offset), Ok(_)) = (rva_to_offset(object, names_rva), Ok::<(), ()>(())) {
            if let Some(ordinals_offset) = rva_to_offset(object, ordinals_rva) {
                let name_rvas: Vec<u32> = reader.for_each_entry(
                    names_offset,
                    4,
                    num_names,
                    "导出名字表",
                    |_i, v| v.u32(0, Endianness::Little, "名字 RVA"),
                )?;
                let ordinals: Vec<u16> = reader.for_each_entry(
                    ordinals_offset,
                    2,
                    num_names,
                    "导出序号表",
                    |_i, v| v.u16(0, Endianness::Little, "序号索引"),
                )?;
                for (index, name_rva) in name_rvas.iter().enumerate() {
                    if let Some(ordinal_index) = ordinals.get(index) {
                        if let Some(name) = read_c_string_at_rva(reader, object, *name_rva) {
                            names.insert(u32::from(*ordinal_index), name);
                        }
                    }
                }
            }
        }
    }

    // 组装：每个非 0 地址都是一条导出
    let mut out = Vec::new();
    for (index, rva) in addresses.iter().enumerate() {
        if *rva == 0 {
            continue;
        }
        let ordinal = ordinal_base + index as u32;
        let name = names
            .get(&(index as u32))
            .cloned()
            .unwrap_or_else(|| format!("#{ordinal}"));

        // 转发导出：地址落在导出目录范围内表示"这是个字符串"
        let dir_start = dir.rva;
        let dir_end = dir.rva.saturating_add(dir.size);
        let forwarder = if *rva >= dir_start && *rva < dir_end {
            read_c_string_at_rva(reader, object, *rva)
        } else {
            None
        };

        // 转发导出**不是代码**：`address` 指向的是导出目录里的一个
        // 字符串（形如 `NTDLL.RtlAllocateHeap`），是一个"去哪找"的
        // 指路牌。把它当代码会让上层在字符串字节上建函数。
        //
        // 非转发导出也不一定就是代码（数据也可以被导出），但 PE 的
        // 导出表**不记录类型** —— 拿不到就说拿不到：这里只否定
        // **确定不是代码**的转发项，其余保留 `true` 并在上层用
        // "能否解码 / 是否可达"复核。
        let is_code = forwarder.is_none();

        out.push(Export {
            name,
            ordinal: Some(ordinal),
            address: rva_to_va(object, *rva),
            forwarder,
            is_code,
        });
    }

    Ok(out)
}
