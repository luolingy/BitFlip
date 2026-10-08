//! PE 调试目录里的 CodeView 记录（M8 交付物 1 的收尾）。
//!
//! MSVC 系的 PDB 不在镜像里，但链接器会把"我用的是哪个 PDB"写进 PE 的**调试目录**：
//! 一条 `RSDS` 记录，里面有 GUID、age 和当时的路径。以前只按 `foo.exe` → `foo.pdb`
//! 的同名约定找，目标一改名或搬家就找不到；读这条记录才是正路。
//!
//! 解析原则：**只读、绝不 panic**。畸形输入是可预期的（用户会丢各种东西进来），
//! 越界、长度不够、没有 PE 头 —— 一律返回 `None`，由调用方按"找不到 PDB"照实报。
//!
//! 已知没做：GUID/age 还没有拿来校验候选 PDB 是否配得上这个镜像（现在只用了路径）。
//! 拿错 PDB 的风险靠 `notes` 里报出"用的是哪个路径、按什么找到的"来暴露。

/// 一条 CodeView 记录。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Record {
    /// PDB 的 GUID（按记录里的原始字节序保存，暂不解释）。
    pub guid: [u8; 16],
    /// PDB 的 age（同一次链接内递增；用来区分同 GUID 的多次写入）。
    pub age: u32,
    /// 链接时的 PDB 路径。可能是绝对路径，也可能是相对路径 —— 原样返回，不猜。
    pub path: String,
}

/// 调试目录条目大小。
const DEBUG_DIRECTORY_ENTRY: usize = 28;
/// `IMAGE_DEBUG_TYPE_CODEVIEW`。
const TYPE_CODEVIEW: u32 = 2;

fn u16_at(bytes: &[u8], at: usize) -> Option<u16> {
    let slice = bytes.get(at..at + 2)?;
    Some(u16::from_le_bytes([slice[0], slice[1]]))
}

fn u32_at(bytes: &[u8], at: usize) -> Option<u32> {
    let slice = bytes.get(at..at + 4)?;
    Some(u32::from_le_bytes([slice[0], slice[1], slice[2], slice[3]]))
}

/// RVA → 文件偏移：在节表里找包含该 RVA 的节。
fn rva_to_offset(
    bytes: &[u8],
    sections_at: usize,
    section_count: usize,
    rva: u32,
) -> Option<usize> {
    for index in 0..section_count {
        let entry = sections_at + index * 40;
        let virtual_address = u32_at(bytes, entry + 12)?;
        let size_of_raw_data = u32_at(bytes, entry + 16)?;
        let pointer_to_raw_data = u32_at(bytes, entry + 20)?;
        if rva >= virtual_address && rva - virtual_address < size_of_raw_data.max(1) {
            let delta = rva - virtual_address;
            let offset = usize::try_from(u64::from(pointer_to_raw_data) + u64::from(delta)).ok()?;
            if offset < bytes.len() {
                return Some(offset);
            }
            return None;
        }
    }
    None
}

/// 从 PE 镜像字节里读 CodeView 记录。不是 PE、没有调试目录、不是 `RSDS`、越界 —— 都是 `None`。
#[must_use]
pub fn find(pe: &[u8]) -> Option<Record> {
    let e_lfanew = u32_at(pe, 0x3c)?;
    let pe_offset = usize::try_from(e_lfanew).ok()?;
    if pe.get(pe_offset..pe_offset + 4)? != b"PE\0\0" {
        return None;
    }
    let coff = pe_offset + 4;
    let section_count = usize::from(u16_at(pe, coff + 2)?);
    let optional_size = usize::from(u16_at(pe, coff + 16)?);
    let optional = coff + 20;
    let magic = u16_at(pe, optional)?;
    // PE32 与 PE32+ 的 data directory 起点不同（0x10b / 0x20b）。
    let data_directory = match magic {
        0x10b => optional + 96,
        0x20b => optional + 112,
        _ => return None,
    };
    // 目录 6 = 调试目录。
    let debug_rva = u32_at(pe, data_directory + 6 * 8)?;
    let debug_size = u32_at(pe, data_directory + 6 * 8 + 4)?;
    if debug_rva == 0 || debug_size < DEBUG_DIRECTORY_ENTRY as u32 {
        return None;
    }
    let sections_at = optional + optional_size;
    let debug_at = rva_to_offset(pe, sections_at, section_count, debug_rva)?;

    // 一个镜像可能有多个条目（PDB、ILTCG、VC feature…），找 CodeView 那条。
    let entries = usize::try_from(debug_size).ok()? / DEBUG_DIRECTORY_ENTRY;
    for index in 0..entries {
        let entry = debug_at + index * DEBUG_DIRECTORY_ENTRY;
        // `IMAGE_DEBUG_DIRECTORY` 的字段顺序：Characteristics(+0)、TimeDateStamp(+4)、
        // MajorVersion(+8)、MinorVersion(+10)、**Type(+12)**、SizeOfData(+16)、
        // AddressOfRawData(+20)、PointerToRawData(+24)。
        // 踩过的坑：把 Type 读在 +0（那是 Characteristics），于是永远匹配不上 —— 单元测试
        // 当时是绿的，因为测试里的合成镜像按同一个错误假设拼的（自证其说）。
        // 所以这里写下偏移，测试也按同一份规格拼，另外有一条真实样本测试兜底。
        if u32_at(pe, entry + 12)? != TYPE_CODEVIEW {
            continue;
        }
        let size = usize::try_from(u32_at(pe, entry + 16)?).ok()?;
        let raw = usize::try_from(u32_at(pe, entry + 24)?).ok()?;
        let data = pe.get(raw..raw + size)?;
        return parse_rsds(data);
    }
    None
}

/// 解析 `RSDS` 记录本体。
fn parse_rsds(data: &[u8]) -> Option<Record> {
    if data.len() < 24 || data.get(..4)? != b"RSDS" {
        return None;
    }
    let mut guid = [0u8; 16];
    guid.copy_from_slice(data.get(4..20)?);
    let age = u32_at(data, 20)?;
    let text = data.get(24..)?;
    let end = text
        .iter()
        .position(|byte| *byte == 0)
        .unwrap_or(text.len());
    let path = text.get(..end)?;
    if path.is_empty() {
        return None;
    }
    Some(Record {
        guid,
        age,
        path: String::from_utf8_lossy(path).into_owned(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    /// 拼一个最小的 PE32+ 镜像：一个节、调试目录一条 CodeView 记录。
    fn synthetic_pe(cv: &[u8]) -> Vec<u8> {
        let mut pe = vec![0u8; 0x600];
        let pe_offset = 0x40usize;
        pe[0x3c..0x40].copy_from_slice(&(pe_offset as u32).to_le_bytes());
        pe[pe_offset..pe_offset + 4].copy_from_slice(b"PE\0\0");
        let coff = pe_offset + 4;
        pe[coff + 2..coff + 4].copy_from_slice(&1u16.to_le_bytes()); // NumberOfSections
        pe[coff + 16..coff + 18].copy_from_slice(&0xF0u16.to_le_bytes()); // SizeOfOptionalHeader
        let optional = coff + 20;
        pe[optional..optional + 2].copy_from_slice(&0x20bu16.to_le_bytes()); // PE32+
        let data_directory = optional + 112;
        let debug_rva = 0x1000u32;
        pe[data_directory + 6 * 8..data_directory + 6 * 8 + 4]
            .copy_from_slice(&debug_rva.to_le_bytes());
        pe[data_directory + 6 * 8 + 4..data_directory + 6 * 8 + 8]
            .copy_from_slice(&(DEBUG_DIRECTORY_ENTRY as u32).to_le_bytes());
        // 节表：一节，RVA 0x1000 → 文件偏移 0x200
        let sections = optional + 0xF0;
        pe[sections + 12..sections + 16].copy_from_slice(&debug_rva.to_le_bytes());
        pe[sections + 16..sections + 20].copy_from_slice(&0x200u32.to_le_bytes());
        pe[sections + 20..sections + 24].copy_from_slice(&0x200u32.to_le_bytes());
        // 调试目录条目：CodeView，数据在文件偏移 0x400
        let entry = 0x200usize;
        pe[entry + 12..entry + 16].copy_from_slice(&TYPE_CODEVIEW.to_le_bytes());
        pe[entry + 16..entry + 20].copy_from_slice(&(cv.len() as u32).to_le_bytes());
        pe[entry + 20..entry + 24].copy_from_slice(&debug_rva.to_le_bytes());
        pe[entry + 24..entry + 28].copy_from_slice(&0x400u32.to_le_bytes());
        pe[0x400..0x400 + cv.len()].copy_from_slice(cv);
        pe
    }

    fn rsds(path: &str) -> Vec<u8> {
        let mut cv = Vec::new();
        cv.extend_from_slice(b"RSDS");
        cv.extend_from_slice(&[0xab; 16]);
        cv.extend_from_slice(&7u32.to_le_bytes());
        cv.extend_from_slice(path.as_bytes());
        cv.push(0);
        cv
    }

    #[test]
    fn a_codeview_record_is_read_from_the_debug_directory() {
        let pe = synthetic_pe(&rsds("C:\\sym\\x.pdb"));
        let record = find(&pe).expect("应当读到记录");
        assert_eq!(record.path, "C:\\sym\\x.pdb");
        assert_eq!(record.age, 7);
        assert_eq!(record.guid, [0xab; 16]);
    }

    #[test]
    fn a_record_without_a_path_is_not_used() {
        // 只有头、没有路径：名字无从谈起，宁可不认。
        let mut cv = Vec::new();
        cv.extend_from_slice(b"RSDS");
        cv.extend_from_slice(&[0u8; 16]);
        cv.extend_from_slice(&1u32.to_le_bytes());
        cv.push(0);
        assert!(find(&synthetic_pe(&cv)).is_none());
    }

    #[test]
    fn jumbled_input_returns_none_instead_of_panicking() {
        // 截断到各种长度都不该 panic（畸形输入是可预期的）。
        let pe = synthetic_pe(&rsds("x.pdb"));
        for len in 0..pe.len() {
            let _ = find(&pe[..len]);
        }
        // 非 PE、空、短头。
        assert!(find(b"").is_none());
        assert!(find(b"MZ").is_none());
        assert!(find(&[0xff; 0x100]).is_none());
    }

    #[test]
    fn a_non_codeview_debug_entry_is_skipped() {
        let mut pe = synthetic_pe(&rsds("x.pdb"));
        let entry = 0x200usize;
        pe[entry + 12..entry + 16].copy_from_slice(&16u32.to_le_bytes()); // IMAGE_DEBUG_TYPE_VC_FEATURE
        assert!(find(&pe).is_none(), "非 CodeView 条目不该被当成记录");
    }
}
