//! PE 里"只识别、不解析"的两项。
//!
//! `docs/PLAN.md` §1.4 把 .NET / CIL 反编译列为非目标，但**识别不等于只报一句
//! "有 CLI 头"**：头里有若干能核实的事实（`ILONLY` / `32BITREQUIRED` /
//! 入口 token / 元数据根 / 运行时版本串），报出来用户才能判断这个文件到底是
//! 纯 IL、混合模式还是普通 PE —— 这直接决定"能不能当普通 PE 反汇编"。
//!
//! COFF 符号表也放在这里：它服务的是**目标文件**（`.obj`）场景，作用与导入
//! 导出不同 —— 那两张构成映像的运行期结构，而符号表只是给后续分析提供事实。

use super::*;

/// 解析 `IMAGE_COR20_HEADER` 并返回识别结论（notes）。
///
/// PLAN §1.4：这一项只做**识别**，不做 CIL 反编译。但"识别"不等于只报一句
/// "有 CLI 头" —— 头里有若干**能核实**的事实，报出来才能让用户判断这个文件
/// 到底是什么：
///
/// * `Flags` 的 `ILONLY` / `32BITREQUIRED` / `NATIVE_ENTRYPOINT` —— 决定它是
///   纯 IL 还是混合模式（C++/CLI），直接影响"能不能当普通 PE 反汇编"；
/// * `EntryPointToken` —— 托管入口的方法 token（0 表示没有），
///   **不是** PE 的 `AddressOfEntryPoint`。这两个很容易被混为一谈；
/// * `MetaData` 目录 —— 元数据根的 RVA/大小；
/// * `RuntimeVersion` —— 形如 `v4.0.30319` 的版本串，是 BCL 兼容性的直接依据。
///
/// `IMAGE_COR20_HEADER` 布局（72 字节，全部小端）：
/// ```text
///  0  cb                     u32   头字节数（应为 72）
///  4  MajorRuntimeVersion    u16
///  6  MinorRuntimeVersion    u16
///  8  MetaData               RVA+Size 目录（8 字节）
/// 16  Flags                  u32
/// 20  EntryPointToken        u32
/// 24  Resources              RVA+Size 目录
/// 32  StrongNameSignature    RVA+Size 目录
/// 40  CodeManagerTable       RVA+Size 目录
/// 48  VTableFixups           RVA+Size 目录
/// 56  ExportAddressTableJumps RVA+Size 目录
/// 64  ManagedNativeHeader    RVA+Size 目录
/// ```
pub(super) fn describe_cli_header(
    reader: &Reader<'_>,
    object: &Object,
    dir: DataDir,
) -> Vec<String> {
    /// CLI 头的固定大小。
    const COR20_HEADER_SIZE: u64 = 72;

    let mut notes = Vec::new();

    let Some(offset) = rva_to_offset(object, dir.rva) else {
        notes.push(format!(
            "包含 CLI 头（RVA {:#x}），但该 RVA 无法映射到文件偏移：CLI 头内容不可读",
            dir.rva
        ));
        return notes;
    };

    let Ok(_probe) = reader.slice(offset, COR20_HEADER_SIZE, "CLI 头") else {
        notes.push(format!(
            "包含 CLI 头（RVA {:#x}，偏移 {offset:#x}），但文件在此处不足 {COR20_HEADER_SIZE} 字节，无法读取",
            dir.rva
        ));
        return notes;
    };

    // 用 reader 直接在绝对偏移处读：`slice` 只返回字节切片，没有读取方法。
    let read_u32 = |at: u64, what: &'static str| {
        reader
            .u32(offset + at, Endianness::Little, what)
            .unwrap_or(0)
    };
    let read_u16 = |at: u64, what: &'static str| {
        reader
            .u16(offset + at, Endianness::Little, what)
            .unwrap_or(0)
    };

    let cb = read_u32(0, "cb");
    let major = read_u16(4, "MajorRuntimeVersion");
    let minor = read_u16(6, "MinorRuntimeVersion");
    let metadata_rva = read_u32(8, "MetaData.RVA");
    let metadata_size = read_u32(12, "MetaData.Size");
    let flags = read_u32(16, "Flags");
    let entry_token = read_u32(20, "EntryPointToken");

    // Flags 位定义（ECMA-335 II.25.3.1）
    const COMIMAGE_FLAGS_ILONLY: u32 = 0x0000_0001;
    const COMIMAGE_FLAGS_32BITREQUIRED: u32 = 0x0000_0002;
    const COMIMAGE_FLAGS_32BITPREFERRED: u32 = 0x0002_0000;
    const COMIMAGE_FLAGS_NATIVE_ENTRYPOINT: u32 = 0x0000_0010;
    const COMIMAGE_FLAGS_STRONGNAMESIGNED: u32 = 0x0000_0008;

    let mut traits = Vec::new();
    if flags & COMIMAGE_FLAGS_ILONLY != 0 {
        traits.push("ILONLY");
    }
    if flags & COMIMAGE_FLAGS_NATIVE_ENTRYPOINT != 0 {
        traits.push("NATIVE_ENTRYPOINT");
    }
    if flags & COMIMAGE_FLAGS_32BITREQUIRED != 0 {
        traits.push("32BITREQUIRED");
    }
    if flags & COMIMAGE_FLAGS_32BITPREFERRED != 0 {
        traits.push("32BITPREFERRED");
    }
    if flags & COMIMAGE_FLAGS_STRONGNAMESIGNED != 0 {
        traits.push("STRONGNAMESIGNED");
    }
    let trait_text = if traits.is_empty() {
        "无标志位".to_string()
    } else {
        traits.join("|")
    };

    // 混合模式（C++/CLI）与纯 IL 的处理方式完全不同，值得单独点出来：
    // 混合模式里含真实原生代码，可以当普通 PE 反汇编；纯 IL 的 .text
    // 是 IL 字节码，按 x86/x64 反汇编只会得到一片无意义的指令。
    let il_only = flags & COMIMAGE_FLAGS_ILONLY != 0;
    let mixed = !il_only;

    notes.push(format!(
        "这是一个 .NET 托管程序集（CLI 头 RVA {:#x}，头大小 {cb} 字节，\
         运行时版本 {major}.{minor}，标志 {trait_text}）",
        dir.rva
    ));

    if mixed {
        notes.push(
            "该程序集不是纯 IL（缺 ILONLY 标志）：属于混合模式（很可能 C++/CLI），\
             其中包含真实的原生代码，可以按普通 PE 反汇编；托管部分不做 CIL 反编译"
                .to_string(),
        );
    } else {
        notes.push(
            "这是纯 IL 程序集：`.text` 段里是 IL 字节码，按 x86/x64 反汇编不会得到\
             有意义的指令。本工具只做识别，不反编译 CIL（见 docs/PLAN.md §1.4）"
                .to_string(),
        );
    }

    if entry_token != 0 {
        // 托管入口是**方法 token**（0x06xxxxxx 方法表 / 0x0Axxxxxx 方法规格），
        // 不是 PE 头的 AddressOfEntryPoint —— 两者数值相近但含义完全不同。
        let table = entry_token >> 24;
        let index = entry_token & 0x00ff_ffff;
        let table_name = match table {
            0x06 => "MethodDef",
            0x0a => "MethodSpec",
            0x01 => "TypeRef",
            0x02 => "TypeDef",
            _ => "未知表",
        };
        notes.push(format!(
            "托管入口是方法 token 0x{entry_token:08x}（{table_name} 表第 {index} 项），\
             与 PE 头的 AddressOfEntryPoint 不是同一概念"
        ));
    } else {
        notes.push("该程序集没有托管入口（EntryPointToken = 0），通常是类库".to_string());
    }

    if metadata_size == 0 || metadata_rva == 0 {
        notes.push(
            "CLI 头里的 MetaData 目录为空：元数据根不可定位，无法进一步识别程序集内容".to_string(),
        );
    } else {
        notes.push(format!(
            "元数据根位于 RVA {metadata_rva:#x}（{metadata_size} 字节）：程序集名与类型定义在那里，\
             M3 不做元数据表解析"
        ));
    }

    // 尝试读运行时版本字符串。它是 BCL 兼容性的直接依据，值得单独报。
    // 形如 "v4.0.30319" 或 "v2.0.50727"，以 NUL 结尾。
    if let Some(version) = read_runtime_version(reader, object, metadata_rva, metadata_size) {
        notes.push(format!("目标运行时版本字符串：{version}"));
    }

    notes
}

/// 从元数据根读运行时版本字符串。
///
/// 布局（`IMAGE_COR20_METADATA`，ECMA-335 II.24.2.1）：
/// ```text
///  0  Signature    u32   0x424A5342 ("BSJB")
///  4  MajorVersion u16
///  6  MinorVersion u16
///  8  Reserved     u32
/// 12  Length       u32   版本字符串字节数（**含** NUL，向上取整到 4 的倍数）
/// 16  Version      u8[Length]
/// ```
///
/// 只在签名对得上时返回；签名不对说明这不是标准的元数据根，返回 `None`
/// 让上层如实说"读不出来"，而不是猜一个版本号出来（§7）。
fn read_runtime_version(
    reader: &Reader<'_>,
    object: &Object,
    metadata_rva: u32,
    metadata_size: u32,
) -> Option<String> {
    // "BSJB" 的**小端**读数。
    //
    // 这个字面量极易写错：字节是 `42 53 4a 42`，小端读出来是 0x424a5342，
    // 而"按书写顺序"写会得到 0x4242534a（大端读数）。第一版就写错了，
    // 而且**手拼的单元测试跟着一起错**（测试里也写了同一个错常量），
    // 所以单元测试全绿 —— 直到用真实的 System.dll 才暴露出来。
    // 保留这条注释：这是"合成样本测不出编码理解错误"的活例子。
    const SIG_BSJB: u32 = u32::from_le_bytes(*b"BSJB");
    /// 版本串长度上限：真实值约 10-12 字节。给足余量但不是无限制。
    const MAX_VERSION_LEN: u32 = 1024;

    if metadata_size < 20 {
        return None;
    }
    let offset = rva_to_offset(object, metadata_rva)?;
    reader.slice(offset, 20, "元数据根").ok()?;
    let signature = reader.u32(offset, Endianness::Little, "BSJB 签名").ok()?;
    if signature != SIG_BSJB {
        return None;
    }
    let length = reader
        .u32(offset + 12, Endianness::Little, "版本串长度")
        .ok()?;
    if length == 0 || length > MAX_VERSION_LEN {
        return None;
    }
    let data = reader
        .slice(offset + 16, u64::from(length), "版本串")
        .ok()?;
    // 去掉尾部 NUL 与对齐填充
    let end = data.iter().position(|&b| b == 0).unwrap_or(data.len());
    let text = std::str::from_utf8(&data[..end]).ok()?;
    if text.is_empty() {
        return None;
    }
    Some(text.to_string())
}

/// 解析 COFF 符号表（目标文件）。
pub(super) fn parse_coff_symbols(
    reader: &Reader<'_>,
    symbol_table_ptr: u32,
    num_symbols: u32,
    object: &Object,
) -> Result<Vec<RawSymbol>, ParseError> {
    const SYMBOL_SIZE: u64 = 18;
    let count = u64::from(num_symbols);
    if count > MAX_TABLE_ENTRIES {
        return Err(ParseError::Overflow(format!(
            "COFF 符号表声称有 {count} 个符号，超过上限"
        )));
    }

    let offset = u64::from(symbol_table_ptr);
    // 符号表后面紧跟字符串表（前 4 字节是总长度）
    let strtab_offset = offset
        .checked_add(count * SYMBOL_SIZE)
        .ok_or_else(|| ParseError::Overflow("COFF 字符串表偏移".into()))?;

    let mut out = Vec::new();
    let mut index = 0u64;
    while index < count {
        let Some(entry) = offset.checked_add(index * SYMBOL_SIZE) else {
            break;
        };
        let Ok(view) = reader.slice(entry, SYMBOL_SIZE, "COFF 符号") else {
            break;
        };
        let view = Reader::with_base(view, reader.base() + entry);

        let raw_name = view.slice(0, 8, "符号名")?;
        let name = if raw_name[..4] == [0, 0, 0, 0] {
            // 前 4 字节为 0 表示名字在字符串表里的偏移
            let str_offset =
                u32::from_le_bytes([raw_name[4], raw_name[5], raw_name[6], raw_name[7]]);
            if str_offset >= 4 {
                reader
                    .cstr(strtab_offset + u64::from(str_offset), MAX_STRING, "符号名")
                    .unwrap_or_default()
            } else {
                String::new()
            }
        } else {
            let end = raw_name.iter().position(|&b| b == 0).unwrap_or(8);
            String::from_utf8_lossy(&raw_name[..end]).into_owned()
        };

        let value = view.u32(8, Endianness::Little, "Value")?;
        let section_number = view.i16(12, Endianness::Little, "SectionNumber")?;
        let type_field = view.u16(14, Endianness::Little, "Type")?;
        let storage_class = view.u8(16, "StorageClass")?;

        // 函数符号在 COFF 里是"派生类型"（type & 0x20），且必须是 external(2)/static(3)
        let is_function = type_field & 0x20 != 0 && (storage_class == 2 || storage_class == 3);
        let is_weak = storage_class == 105; // IMAGE_SYM_CLASS_WEAK_EXTERNAL

        // 辅助符号记录（.file / .bf / .ef）占一个槽位，要跳过
        let auxiliary_count = u64::from(view.u8(17, "NumberOfAuxSymbols")?);
        index += 1 + auxiliary_count;

        if name.is_empty() {
            continue;
        }

        let section = if section_number > 0 {
            object.sections.get((section_number - 1) as usize)
        } else {
            None
        };

        // COFF 符号的 Value 是**节内偏移**，不是虚拟地址。
        //
        // 这一点值得写清楚，因为常见的说法是"映像里的符号值就是 RVA"，
        // 而 GNU ld 产出的 PE 映像不是这样 —— 实测才对得上：
        // memcpy 的原始值是 0x8218，.text 的 VA 是 0x140001000，
        // 0x140001000 + 0x8218 = 0x140009218，正是 objdump 给出的绝对地址。
        //
        // 少了这一加的后果不是"名字丢了"，而是**同一个映像里出现两套地址**：
        // 符号表来的函数落在 0x8218，分析发现的函数落在 0x1400096c0，
        // 两者其实是同一段代码。界面与脚本都会据此认错地址。
        let value = match section {
            Some(section) => section.vaddr.wrapping_add(u64::from(value)),
            // 有节号却查不到节：这不是能猜的情形，保持原值（并且这条符号
            // 会因为 `defined` 之外的证据不足而不被当作函数候选）。
            None => u64::from(value),
        };

        out.push(RawSymbol {
            name,
            value,
            size: 0,
            defined: section_number > 0,
            is_function,
            is_weak,
            // 同 coff.rs：COFF StorageClass 与 ELF STB_* 不是一套编号，
            // 只映射"局部 / 全局"这一层最小交集。
            bind: match storage_class {
                3 => 0, // STATIC → 局部
                2 => 1, // EXTERNAL → 全局
                _ => 0,
            },
            section: section.map(|s| s.name.clone()),
            source: SymbolTableSource::Static,
        });
    }

    Ok(out)
}
