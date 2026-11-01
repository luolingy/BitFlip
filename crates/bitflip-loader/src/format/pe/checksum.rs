//! PE 映像的 **CheckSum** 字段：按规范重算与写回。
//!
//! `IMAGE_OPTIONAL_HEADER.CheckSum`（可选头偏移 64，32/64 位同位置）是 Windows
//! 加载器用来判断"映像在签名/分发后有没有被改动"的一个 16 位折叠和。打补丁改了字节
//! 之后，这个字段就**对不上了** —— 某些驱动/受保护进程会因此拒绝加载（校验失败的报错
//! 是"映像损坏"，而不是"签名无效"，很好辨认）。
//!
//! 本模块只做**一个**算法上的事：按 PE 规范（`CheckSumMappedFile` 的算法）
//! 把整份文件按 16 位小端求和、折叠进位、再加文件长度，得到该写的值；`update`
//! 把它写回文件。它**不改任何其它字节**、**不校验签名**（那是 M12 代码签名的事）。
//!
//! 算法（与 Microsoft `CheckSumMappedFile` 一致）：
//! 1. 把 CheckSum 字段本身当 0（否则"算进去又写回去"永远不收敛）；
//! 2. 每 2 字节按小端拼成 16 位 word 相加（奇数长度尾部补 0）；
//! 3. 每加一次就把高位进位折回低位（`(sum & 0xffff) + (sum >> 16)`）；
//! 4. 最后累加"文件长度"的 16 位折叠和。
//!
//! 注意：PE 的 CheckSum **不是**校验和意义上的安全量，也不等于文件的 hash —— 换一个从没
//! 加载过的映像，它可能就是 0（链接器可以省略）。所以"算出来和原值一样"不代表没改过，
//! 它只是让加载器那一条一致性检查能过。诚实边界写在 [`PeChecksumReport`] 的注释里。

use crate::reader::Reader;

/// CheckSum 字段在可选头里的偏移（`IMAGE_OPTIONAL_HEADER32/64` 都是 64）。
const CHECKSUM_FIELD_OFFSET_IN_OPTIONAL: u64 = 64;

/// 一次 PE checksum 重算的记账。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PeChecksumReport {
    /// CheckSum 字段在**文件里**的绝对偏移（算不出来就是 `None`，例如目标不是带可选头的 PE）。
    pub field_offset: Option<u64>,
    /// 文件里原本的 CheckSum 值（读不到就是 `None`）。
    pub original: Option<u32>,
    /// 重算出的 CheckSum 值（该写回的值）。
    pub recomputed: Option<u32>,
    /// 是否真的改写了（`original != recomputed` 且字段存在）。
    pub changed: bool,
}

/// 找到 PE 可选头里 CheckSum 字段的**文件绝对偏移**。
///
/// 只认真正的 PE 映像（`MZ` + `PE\0\0` + 非零 `SizeOfOptionalHeader`，因为 `.obj`
/// 没有可选头）。任何一步读不到就返回 `None` —— 不猜，让调用方知道"这不是可校验的 PE"。
fn checksum_field_offset(bytes: &[u8]) -> Option<usize> {
    let reader = Reader::with_base(bytes, 0);
    // DOS 头魔数。
    if reader.slice(0, 2, "DOS 头").ok()? != b"MZ" {
        return None;
    }
    let pe_offset = reader
        .u32(0x3c, crate::reader::Endianness::Little, "e_lfanew")
        .ok()? as usize;
    if pe_offset == 0 || pe_offset >= bytes.len() {
        return None;
    }
    if reader.slice(pe_offset as u64, 4, "PE 签名").ok()? != b"PE\0\0" {
        return None;
    }
    // COFF 头紧随 PE 签名之后（4 字节）。SizeOfOptionalHeader 在 COFF +16。
    let coff = pe_offset + 4;
    let optional_size = reader
        .u16(
            (coff + 16) as u64,
            crate::reader::Endianness::Little,
            "SizeOfOptionalHeader",
        )
        .ok()?;
    if optional_size == 0 {
        return None; // 目标文件（.obj）没有可选头
    }
    let optional_offset = coff + 20; // COFF 头固定 20 字节
    let field = optional_offset + CHECKSUM_FIELD_OFFSET_IN_OPTIONAL as usize;
    // 字段必须在文件里（4 字节）。
    if field.checked_add(4)? > bytes.len() {
        return None;
    }
    Some(field)
}

/// 按 PE 规范计算整份文件的 CheckSum（字段本身按 0 计）。
///
/// 返回 `None` 仅当"这根本不是带可选头的 PE 映像"（见 [`checksum_field_offset`]）。
/// 参数 `field_offset` 是 CheckSum 字段绝对偏移，用来在求和时把 4 个字节跳过（当 0）。
fn compute(bytes: &[u8], field_offset: usize) -> u32 {
    let mut sum: u64 = 0;
    let mut i = 0usize;
    let len = bytes.len();
    while i + 1 < len {
        // 落在 CheckSum 字段 4 字节里的一律当 0。
        let in_field = i >= field_offset && i < field_offset + 4;
        let word = if in_field {
            0u16
        } else {
            u16::from_le_bytes([bytes[i], bytes[i + 1]])
        };
        sum += u64::from(word);
        // 折叠进位：保持低 16 位，把溢出高位加回。
        sum = (sum & 0xffff) + (sum >> 16);
        i += 2;
    }
    // 奇数长度尾部补一个字节（高字节 0）。
    if i < len {
        let in_field = i >= field_offset && i < field_offset + 4;
        let word = if in_field { 0u16 } else { u16::from(bytes[i]) };
        sum += u64::from(word);
        sum = (sum & 0xffff) + (sum >> 16);
    }
    // 再加文件长度的折叠和。
    sum = (sum & 0xffff) + (sum >> 16);
    sum += len as u64;
    (sum & 0xffff) as u32
}

/// 重算并把 CheckSum 写回 `bytes`（原地）。返回记账。
///
/// 目标不是带可选头的 PE 时（`field_offset` 为 `None`）**什么都不改**，返回一份
/// `field_offset: None` 的记账 —— 调用方据此知道"这个格式没有 PE checksum 可校验"。
pub fn update_pe_checksum(bytes: &mut [u8]) -> PeChecksumReport {
    let Some(field_offset) = checksum_field_offset(bytes) else {
        return PeChecksumReport {
            field_offset: None,
            original: None,
            recomputed: None,
            changed: false,
        };
    };
    let original = u32::from_le_bytes([
        bytes[field_offset],
        bytes[field_offset + 1],
        bytes[field_offset + 2],
        bytes[field_offset + 3],
    ]);
    let recomputed = compute(bytes, field_offset);
    let changed = recomputed != original;
    if changed {
        bytes[field_offset..field_offset + 4].copy_from_slice(&recomputed.to_le_bytes());
    }
    PeChecksumReport {
        field_offset: Some(field_offset as u64),
        original: Some(original),
        recomputed: Some(recomputed),
        changed,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// 手拼一个最小的 PE32+ 映像（够 `checksum_field_offset` 认出来即可）。
    /// 布局：DOS 64 字节（e_lfanew=0x40 指向 PE），PE 签名 4 字节，COFF 20 字节
    /// （SizeOfOptionalHeader=0xF0），可选头 0xF0 字节（CheckSum 在 +64）。
    fn minimal_pe() -> Vec<u8> {
        let mut b = vec![0u8; 0x40 + 4 + 20 + 0xF0 + 16];
        b[0..2].copy_from_slice(b"MZ");
        b[0x3c..0x40].copy_from_slice(&0x40u32.to_le_bytes()); // e_lfanew
        b[0x40..0x44].copy_from_slice(b"PE\0\0");
        // SizeOfOptionalHeader 在 coff+16 = 0x40+4+16 = 0x54。
        b[0x54..0x56].copy_from_slice(&0xF0u16.to_le_bytes());
        // 可选头起点 = 0x40+4+20 = 0x58；CheckSum 字段 = 0x58+64 = 0x98。
        b
    }

    #[test]
    fn non_pe_has_no_checksum_field() {
        let mut b = b"\x7fELF....".to_vec();
        let report = update_pe_checksum(&mut b);
        assert_eq!(report.field_offset, None);
        assert!(!report.changed);
    }

    #[test]
    fn obj_without_optional_header_is_skipped() {
        // 有 MZ+PE 但 SizeOfOptionalHeader=0 → 不认作可校验 PE。
        let mut b = minimal_pe();
        b[0x54..0x56].copy_from_slice(&0u16.to_le_bytes());
        let report = update_pe_checksum(&mut b);
        assert_eq!(report.field_offset, None);
    }

    #[test]
    fn field_is_located_and_written() {
        let mut b = minimal_pe();
        // 先放一个明显错的 checksum。
        b[0x98..0x9c].copy_from_slice(&0xDEAD_BEEFu32.to_le_bytes());
        let report = update_pe_checksum(&mut b);
        assert_eq!(report.field_offset, Some(0x98));
        assert_eq!(report.original, Some(0xDEAD_BEEF));
        assert!(report.changed, "错值应被改成重算值");
        let written = u32::from_le_bytes([b[0x98], b[0x99], b[0x9a], b[0x9b]]);
        assert_eq!(Some(written), report.recomputed);
        // 幂等：再算一次应不再变化（说明算法把字段本身正确地当 0 了）。
        let again = update_pe_checksum(&mut b);
        assert!(!again.changed, "重算一次后应稳定，不再变化");
        assert_eq!(again.recomputed, report.recomputed);
    }

    #[test]
    fn changing_a_byte_changes_the_checksum() {
        let mut b = minimal_pe();
        update_pe_checksum(&mut b);
        let first = b[0x98..0x9c].to_vec();
        // 改一个"数据"字节（可选头末尾之后的填充区），checksum 应随之变。
        let last = b.len() - 1;
        b[last] ^= 0xFF;
        let report = update_pe_checksum(&mut b);
        assert!(report.changed, "内容变了 checksum 应变");
        assert_ne!(b[0x98..0x9c].to_vec(), first);
    }
}
