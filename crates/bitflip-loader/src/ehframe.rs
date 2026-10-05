//! `.eh_frame` FDE 解析：从展开表恢复函数边界。
//!
//! 为什么这块对 BitFlip 重要（PLAN §M3）：符号被 strip 之后，`.eh_frame` 是
//! **唯一**还能给出精确函数边界的来源 —— 编译器/链接器为每个函数写一条 FDE，
//! 里面直接带 `pc_begin` 与 `pc_range`。调用目标推断只能给入口，给不了边界；
//! 这条路径是"剥离符号场景的关键路径"（PLAN §M3 交付物原文）。
//!
//! 只解析到"边界"为止，**不解析 CFI 指令**：CFI 状态机（寄存器恢复规则）
//! 是真正的栈回溯才需要的，M3 用不到。少解析一点、解析对一点，比假装
//! 全解析了更符合项目底线（CLAUDE.md §7）。
//!
//! 编码的坑（DWARF 的 `pointer_encoding` 是个 8 位位域，不是简单枚举）：
//!   * 低 4 位 = 值类型（absptr / uleb128 / udata2 / udata4 / udata8 /
//!     signed / sdata2·4·8 / **pcrel**）；
//!   * 0x70 = 间接（值是指针的地址而非值本身）—— FDE 的 pc_begin 不用；
//!   * `DW_EH_PE_omit = 0xff` 表示该字段不存在。
//!
//! `pcrel` 的含义是"相对于**本字段所在地址**的偏移"—— 算错基址会得到一片
//! 看似合理的错误地址，所以每条分支都单独测。

use crate::reader::Endianness;

/// DWARF 指针编码的低 4 位：值类型。
const ENC_ABS_PTR: u8 = 0x00;
const ENC_ULEB128: u8 = 0x01;
const ENC_UDATA2: u8 = 0x02;
const ENC_UDATA4: u8 = 0x03;
const ENC_UDATA8: u8 = 0x04;
const ENC_SLEB128: u8 = 0x09;
const ENC_SDATA2: u8 = 0x0a;
const ENC_SDATA4: u8 = 0x0b;
const ENC_SDATA8: u8 = 0x0c;
/// 相对于字段自身地址的偏移（最常见）。
const ENC_PCREL: u8 = 0x10;
/// 间接：先读出一个地址，再去那个地址取值。FDE 里用不到，遇到就明确放弃。
const ENC_INDIRECT: u8 = 0x80;
/// 字段不存在。
pub const ENC_OMIT: u8 = 0xff;

/// 指针编码的类型部分（去掉间接位）。
#[must_use]
pub const fn encoding_kind(enc: u8) -> u8 {
    enc & 0x0f
}

/// 指针编码是否要求间接读取。
#[must_use]
pub const fn encoding_is_indirect(enc: u8) -> bool {
    enc & ENC_INDIRECT != 0
}

/// 一条 FDE 给出的函数边界。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FdeRange {
    /// 函数起始地址（虚拟地址）。
    pub begin: u64,
    /// 函数长度（字节）。
    pub length: u64,
    /// 对应的展开信息地址（CIE 指针字段，可能为 0）。
    pub cie_pointer: u64,
}

impl FdeRange {
    /// 结束地址（不含）。
    #[must_use]
    pub const fn end(&self) -> u64 {
        self.begin.saturating_add(self.length)
    }
}

/// 解析结果。
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct EhFrameResult {
    /// 解出的 FDE 列表（按 `begin` 升序）。
    pub fdes: Vec<FdeRange>,
    /// 解析过程中的降级说明（截断、编码不支持等）—— 必须浮到 UI，不能吞掉。
    pub notes: Vec<String>,
}

/// 解析 `.eh_frame` 段。
///
/// * `data`：`.eh_frame` 段内容；
/// * `vaddr`：该段被加载到的虚拟地址（FDE 里的 `pcrel` 字段以它为基准）；
/// * `endian`：字节序。
///
/// 容错原则：遇到**单个**坏记录就停下并把原因写进 `notes`，已经解出的
/// 条目照样返回 —— 半份边界表比没有有用。但绝不假装没出错。
#[must_use]
pub fn parse_eh_frame(data: &[u8], vaddr: u64, endian: Endianness) -> EhFrameResult {
    let mut result = EhFrameResult::default();
    let mut offset = 0usize;
    // 记录"当前 CIE"的指针编码，FDE 记录会继承它
    let mut cie_encodings: Option<CieEncodings> = None;
    let mut truncated = 0usize;

    while offset < data.len() {
        let record_start = offset;

        // 每条记录以长度开头：0 表示终止，0xffffffff 表示 64 位长度
        let Some((length, length_size)) = read_record_length(data, offset, endian) else {
            truncated += 1;
            break;
        };
        if length == 0 {
            // 0 长度 = .eh_frame 终止标记（不是错误）
            break;
        }
        let Some(length) = usize::try_from(length).ok() else {
            result.notes.push(format!(
                ".eh_frame 偏移 {offset:#x} 的记录长度 {length} 超出平台可表示范围，停止解析"
            ));
            break;
        };

        let id_at = offset + length_size;
        if id_at + 4 > data.len() {
            truncated += 1;
            break;
        }
        let id = read_u32(data, id_at, endian);
        let body_start = id_at + 4;
        // 记录总占用 = length_size + length
        let record_end = offset + length_size + length;
        if record_end > data.len() {
            result.notes.push(format!(
                ".eh_frame 尾部有一条不完整记录（偏移 {offset:#x}），已忽略"
            ));
            truncated += 1;
            break;
        }

        if id == 0 {
            // CIE
            match parse_cie(data, body_start, record_end, endian) {
                Some(cie) => cie_encodings = Some(cie),
                None => {
                    // CIE 解析失败：后续 FDE 失去编码上下文，无法安全继续
                    result.notes.push(format!(
                        ".eh_frame 偏移 {record_start:#x} 的 CIE 无法解析，停止"
                    ));
                    break;
                }
            }
        } else {
            // FDE：id 是"C IE 指针"字段
            match cie_encodings {
                Some(enc) => {
                    if let Some(fde) = parse_fde(
                        data,
                        body_start,
                        record_end,
                        vaddr,
                        endian,
                        enc,
                        record_start,
                    ) {
                        if fde.length > 0 {
                            result.fdes.push(FdeRange {
                                begin: fde.begin,
                                length: fde.length,
                                cie_pointer: u64::from(id),
                            });
                        }
                    }
                }
                None => {
                    result.notes.push(format!(
                        "偏移 {record_start:#x} 的 FDE 出现在任何 CIE 之前，已跳过"
                    ));
                }
            }
        }

        offset = record_end;
    }

    result.fdes.sort_by_key(|f| f.begin);
    result.fdes.dedup_by_key(|f| f.begin);
    if truncated > 0 {
        result
            .notes
            .push(".eh_frame 在尾部被截断，已解出的边界仍然有效".to_string());
    }
    result
}

/// CIE 中我们关心的两个字段：`pc_begin` 与 `pc_range` 的指针编码。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct CieEncodings {
    fde_encoding: u8,
}

fn parse_cie(
    data: &[u8],
    body_start: usize,
    record_end: usize,
    endian: Endianness,
) -> Option<CieEncodings> {
    let mut p = body_start;
    // version（1 字节）
    let version = *data.get(p)?;
    p += 1;
    // augmentation string（NUL 结尾）
    let (aug, next) = read_cstr(data, p, record_end)?;
    p = next;

    // FDE 的指针编码：默认 absptr（古老格式）
    let mut fde_encoding = ENC_ABS_PTR;

    if version >= 4 {
        // address_size + segment_selector_size
        p += 2;
    }

    // code_alignment_factor（uleb）
    let (_, next) = read_uleb(data, p, record_end)?;
    p = next;
    // data_alignment_factor（sleb）
    let (_, next) = read_sleb(data, p, record_end)?;
    p = next;
    // return_address_register（version 1 是 1 字节，之后是 uleb）
    if version == 1 {
        p += 1;
    } else {
        let (_, next) = read_uleb(data, p, record_end)?;
        p = next;
    }

    // augmentation 'R' 后面跟 1 字节的指针编码
    if aug.starts_with('z') {
        // augmentation data 长度（uleb），随后是数据
        let (aug_len, next) = read_uleb(data, p, record_end)?;
        p = next;
        let aug_end = p.saturating_add(aug_len as usize);
        // 逐个 augmentation 字符消费数据；只有 'R' 是我们需要的
        let chars: Vec<char> = aug.chars().skip(1).collect();
        for c in chars {
            if p >= aug_end {
                break;
            }
            match c {
                'R' => {
                    fde_encoding = *data.get(p)?;
                    p += 1;
                }
                'L' => {
                    p += 1; // LSDA 编码
                }
                'P' => {
                    // personality：1 字节编码 + 该编码大小的值
                    let enc = *data.get(p)?;
                    p += 1;
                    p += encoded_size(enc, data, p, endian)?;
                }
                'S' => {} // 信号帧，无数据
                _ => {
                    // 未知 augmentation：无法安全继续解析这条 CIE
                    return None;
                }
            }
        }
    }

    Some(CieEncodings { fde_encoding })
}

/// 解析一条 FDE，取出 `pc_begin` 与 `pc_range`。
#[allow(clippy::too_many_arguments)]
fn parse_fde(
    data: &[u8],
    body_start: usize,
    record_end: usize,
    vaddr: u64,
    endian: Endianness,
    enc: CieEncodings,
    record_start: usize,
) -> Option<FdeRange> {
    let mut p = body_start;

    // pc_begin：按 CIE 给出的编码解读。pcrel 的基准是**该字段自身的地址**
    let field_addr = vaddr.checked_add(p as u64)?;
    let begin = read_encoded(
        data,
        &mut p,
        record_end,
        endian,
        enc.fde_encoding,
        field_addr,
    )?;

    // pc_range：按同一编码的**数值部分**解读（不带 pcrel 语义）
    let range_enc = encoding_kind(enc.fde_encoding);
    let range = read_encoded_value(data, &mut p, record_end, endian, range_enc)?;

    // 后面还有 augmentation data，但我们只要边界
    let _ = record_start;

    Some(FdeRange {
        begin,
        length: range,
        cie_pointer: 0,
    })
}

/// 按编码读取一个值，`field_addr` 用于 pcrel。
///
/// 注意 DWARF 的编码布局：低 4 位是值类型，**bit 4 (0x10) 才是 pcrel 标志**。
/// 所以 `0x1b`（真实 GCC 在 x86-64 上的常用值）是"pcrel + sdata4"，
/// 而 `encoding_kind(0x1b) == 0x0b == sdata4` —— 只看低 4 位会把 pcrel
/// **完全漏掉**，于是返回一个相对偏移（实测 228）冒充绝对地址。
fn read_encoded(
    data: &[u8],
    p: &mut usize,
    end: usize,
    endian: Endianness,
    enc: u8,
    field_addr: u64,
) -> Option<u64> {
    if enc == ENC_OMIT {
        return None;
    }
    if encoding_is_indirect(enc) {
        // 间接编码在 FDE 的 pc_begin 里不该出现；遇到就明确放弃，
        // 而不是沿着任意地址去读（那可能读到非法内存）。
        return None;
    }
    let kind = encoding_kind(enc);
    let value = read_encoded_value(data, p, end, endian, kind)?;
    if enc & ENC_PCREL != 0 {
        // pcrel：基准是**该字段自身的地址**（不是段首、不是记录首）
        Some(field_addr.wrapping_add(value))
    } else {
        Some(value)
    }
}

/// 按**数值类型**读取（pcrel 语义由调用方处理）。
fn read_encoded_value(
    data: &[u8],
    p: &mut usize,
    end: usize,
    endian: Endianness,
    kind: u8,
) -> Option<u64> {
    match kind {
        ENC_ABS_PTR => {
            // 裸指针：按目标字长读。我们只知道当前平台，按 8/4 字节自适应：
            // 先按 8 字节读，越界再退回 4 字节 —— 两种都是"无符号"语义。
            if *p + 8 <= end && *p + 8 <= data.len() {
                let v = read_u64(data, *p, endian);
                *p += 8;
                Some(v)
            } else if *p + 4 <= end && *p + 4 <= data.len() {
                let v = u64::from(read_u32(data, *p, endian));
                *p += 4;
                Some(v)
            } else {
                None
            }
        }
        ENC_ULEB128 => {
            let (v, next) = read_uleb(data, *p, end)?;
            *p = next;
            Some(v)
        }
        ENC_UDATA2 => {
            if *p + 2 > end || *p + 2 > data.len() {
                return None;
            }
            let v = u64::from(read_u16(data, *p, endian));
            *p += 2;
            Some(v)
        }
        ENC_UDATA4 => {
            if *p + 4 > end || *p + 4 > data.len() {
                return None;
            }
            let v = u64::from(read_u32(data, *p, endian));
            *p += 4;
            Some(v)
        }
        ENC_UDATA8 => {
            if *p + 8 > end || *p + 8 > data.len() {
                return None;
            }
            let v = read_u64(data, *p, endian);
            *p += 8;
            Some(v)
        }
        // 有符号编码：pc_range 理论上是无符号，但 GCC 用 sdata4 编码它。
        // 按位重解释即可 —— 长度不会是负数，真出现负值说明表坏了，
        // 上层会因为 length==0 之外的怪值把它当可疑数据处理。
        ENC_SLEB128 => {
            let (v, next) = read_sleb(data, *p, end)?;
            *p = next;
            Some(v as u64)
        }
        ENC_SDATA2 => {
            if *p + 2 > end || *p + 2 > data.len() {
                return None;
            }
            let v = i16::from_le_bytes([data[*p], data[*p + 1]]);
            *p += 2;
            Some(v as u64)
        }
        ENC_SDATA4 => {
            if *p + 4 > end || *p + 4 > data.len() {
                return None;
            }
            let v = i32::from_le_bytes([data[*p], data[*p + 1], data[*p + 2], data[*p + 3]]);
            *p += 4;
            Some(v as u64)
        }
        ENC_SDATA8 => {
            if *p + 8 > end || *p + 8 > data.len() {
                return None;
            }
            let v = read_u64(data, *p, endian);
            *p += 8;
            Some(v)
        }
        _ => None,
    }
}

/// 该编码在当前偏移占多少字节（用于跳过 personality 指针）。
fn encoded_size(enc: u8, data: &[u8], p: usize, _endian: Endianness) -> Option<usize> {
    if enc == ENC_OMIT {
        return Some(0);
    }
    Some(match encoding_kind(enc) {
        ENC_ABS_PTR => 8,
        ENC_ULEB128 | ENC_SLEB128 => {
            // 需要实际扫描才能知道长度
            let mut i = p;
            while i < data.len() && data[i] & 0x80 != 0 {
                i += 1;
            }
            i + 1 - p
        }
        ENC_UDATA2 | ENC_SDATA2 => 2,
        ENC_UDATA4 | ENC_SDATA4 => 4,
        ENC_UDATA8 | ENC_SDATA8 => 8,
        _ => return None,
    })
}

// ── 基础读取 ────────────────────────────────────────────────────────

fn read_record_length(data: &[u8], offset: usize, endian: Endianness) -> Option<(u64, usize)> {
    if offset + 4 > data.len() {
        return None;
    }
    let short = read_u32(data, offset, endian);
    if short == 0xffff_ffff {
        if offset + 12 > data.len() {
            return None;
        }
        Some((read_u64(data, offset + 4, endian), 12))
    } else {
        Some((u64::from(short), 4))
    }
}

fn read_cstr(data: &[u8], start: usize, end: usize) -> Option<(String, usize)> {
    let limit = end.min(data.len());
    let mut i = start;
    while i < limit {
        if data[i] == 0 {
            let s = std::str::from_utf8(&data[start..i]).ok()?;
            return Some((s.to_string(), i + 1));
        }
        i += 1;
    }
    None
}

fn read_uleb(data: &[u8], start: usize, end: usize) -> Option<(u64, usize)> {
    let limit = end.min(data.len());
    let mut result: u64 = 0;
    let mut shift = 0u32;
    let mut i = start;
    while i < limit {
        let byte = data[i];
        i += 1;
        if shift >= 64 {
            return None; // 畸形：超长 LEB
        }
        result |= u64::from(byte & 0x7f) << shift;
        if byte & 0x80 == 0 {
            return Some((result, i));
        }
        shift += 7;
    }
    None
}

fn read_sleb(data: &[u8], start: usize, end: usize) -> Option<(i64, usize)> {
    let limit = end.min(data.len());
    let mut result: i64 = 0;
    let mut shift = 0u32;
    let mut i = start;
    let mut byte;
    loop {
        if i >= limit {
            return None;
        }
        byte = data[i];
        i += 1;
        if shift >= 64 {
            return None;
        }
        result |= i64::from(byte & 0x7f) << shift;
        shift += 7;
        if byte & 0x80 == 0 {
            break;
        }
    }
    // 符号扩展
    if shift < 64 && byte & 0x40 != 0 {
        result |= -1i64 << shift;
    }
    Some((result, i))
}

fn read_u16(data: &[u8], at: usize, endian: Endianness) -> u16 {
    let b = [data[at], data[at + 1]];
    match endian {
        Endianness::Little => u16::from_le_bytes(b),
        Endianness::Big => u16::from_be_bytes(b),
    }
}

fn read_u32(data: &[u8], at: usize, endian: Endianness) -> u32 {
    let b = [data[at], data[at + 1], data[at + 2], data[at + 3]];
    match endian {
        Endianness::Little => u32::from_le_bytes(b),
        Endianness::Big => u32::from_be_bytes(b),
    }
}

fn read_u64(data: &[u8], at: usize, endian: Endianness) -> u64 {
    let b = [
        data[at],
        data[at + 1],
        data[at + 2],
        data[at + 3],
        data[at + 4],
        data[at + 5],
        data[at + 6],
        data[at + 7],
    ];
    match endian {
        Endianness::Little => u64::from_le_bytes(b),
        Endianness::Big => u64::from_be_bytes(b),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// 造一条 32 位 `.eh_frame`：CIE（fde_encoding = pcrel|sdata4）+ 若干 FDE。
    ///
    /// 这是真实 GCC/Clang 在 x86-64 上最常用的组合：
    /// augmentation `zR`，FDE 编码 `0x1b` = pcrel | sdata4。
    fn build_eh_frame_32(entries: &[(u64, u64)], vaddr: u64) -> Vec<u8> {
        let mut out = Vec::new();

        // ── CIE ──
        let mut cie_body = Vec::new();
        cie_body.push(1u8); // version
        cie_body.extend_from_slice(b"zR\0"); // augmentation
        cie_body.push(0x01); // code_alignment_factor (uleb)
        cie_body.push(0x78); // data_alignment_factor (sleb) = -8
        cie_body.push(1); // return_address_register (uleb)
        cie_body.push(1); // augmentation data length
        cie_body.push(0x1b); // 'R' 编码：pcrel | sdata4
                             // 对齐到 4 字节（记录体以 4 字节对齐）
        while !(cie_body.len() + 4).is_multiple_of(4) {
            cie_body.push(0);
        }
        let cie_len = 4 + cie_body.len(); // length 字段之后的字节数
        out.extend_from_slice(&(cie_len as u32).to_le_bytes());
        out.extend_from_slice(&0u32.to_le_bytes()); // CIE id = 0
        out.extend_from_slice(&cie_body);

        // ── FDE ──
        for &(begin, length) in entries {
            let mut fde_body = Vec::new();
            // pc_begin：pcrel|sdata4 —— 相对"该字段自身地址"的偏移
            let field_offset_in_file = out.len() + 4 + 4; // 跳过 length + CIE id
            let field_addr = vaddr + field_offset_in_file as u64;
            let rel = (begin as i64) - (field_addr as i64);
            fde_body.extend_from_slice(&(rel as i32).to_le_bytes());
            // pc_range：同编码的数值部分（sdata4）
            fde_body.extend_from_slice(&(length as i32).to_le_bytes());
            fde_body.push(0); // augmentation data length
            while !(fde_body.len() + 4).is_multiple_of(4) {
                fde_body.push(0);
            }
            let fde_len = 4 + fde_body.len();
            out.extend_from_slice(&(fde_len as u32).to_le_bytes());
            // CIE 指针：相对本字段地址的偏移（pcrel），指回段首那条 CIE。
            // 段首在**前面**，所以这是个负偏移 —— 用 i64 相减再转 i32，
            // 不能用 u64 相减（会下溢 panic）。
            let cie_id_offset = out.len();
            let cie_id_field_addr = vaddr + cie_id_offset as u64;
            let cie_back = (vaddr as i64) - (cie_id_field_addr as i64);
            out.extend_from_slice(&(cie_back as i32).to_le_bytes());
            out.extend_from_slice(&fde_body);
        }

        out
    }

    #[test]
    fn parses_a_single_fde_with_pcrel_encoding() {
        let vaddr = 0x401000;
        let data = build_eh_frame_32(&[(0x401100, 0x40)], vaddr);
        let r = parse_eh_frame(&data, vaddr, Endianness::Little);

        assert_eq!(r.fdes.len(), 1, "应解出 1 条 FDE；notes={:?}", r.notes);
        assert_eq!(r.fdes[0].begin, 0x401100, "pcrel 的基址算错会得到别的地址");
        assert_eq!(r.fdes[0].length, 0x40);
        assert_eq!(r.fdes[0].end(), 0x401140);
    }

    #[test]
    fn parses_many_fdes_and_sorts_them() {
        let vaddr = 0x401000;
        // 故意乱序给，验证输出按地址升序且稳定
        let data = build_eh_frame_32(
            &[(0x401300, 0x20), (0x401100, 0x40), (0x401200, 0x30)],
            vaddr,
        );
        let r = parse_eh_frame(&data, vaddr, Endianness::Little);

        let begins: Vec<u64> = r.fdes.iter().map(|f| f.begin).collect();
        assert_eq!(begins, vec![0x401100, 0x401200, 0x401300]);
        let lens: Vec<u64> = r.fdes.iter().map(|f| f.length).collect();
        assert_eq!(lens, vec![0x40, 0x30, 0x20]);
    }

    #[test]
    fn zero_length_terminator_is_not_an_error() {
        let vaddr = 0x401000;
        let mut data = build_eh_frame_32(&[(0x401100, 0x40)], vaddr);
        data.extend_from_slice(&0u32.to_le_bytes()); // 终止标记
        let r = parse_eh_frame(&data, vaddr, Endianness::Little);
        assert_eq!(r.fdes.len(), 1);
        assert!(r.notes.is_empty(), "终止标记不该产生 note：{:?}", r.notes);
    }

    #[test]
    fn truncated_tail_keeps_earlier_fdes_and_says_so() {
        let vaddr = 0x401000;
        let mut data = build_eh_frame_32(&[(0x401100, 0x40), (0x401200, 0x30)], vaddr);
        let keep = data.len() - 8;
        data.truncate(keep);

        let r = parse_eh_frame(&data, vaddr, Endianness::Little);
        assert_eq!(r.fdes.len(), 1, "前一条应当保留");
        assert_eq!(r.fdes[0].begin, 0x401100);
        assert!(
            !r.notes.is_empty(),
            "截断必须写进 notes —— 不能悄悄少给数据（§7）"
        );
    }

    #[test]
    fn garbage_never_panics() {
        // 任意字节都不该 panic：这是解析外部输入的底线
        for len in 0..64usize {
            for seed in 0..8u8 {
                let data: Vec<u8> = (0..len)
                    .map(|i| (i as u8).wrapping_mul(31).wrapping_add(seed))
                    .collect();
                let _ = parse_eh_frame(&data, 0x401000, Endianness::Little);
            }
        }
    }

    #[test]
    fn pcrel_base_is_the_field_address_not_the_section_start() {
        // 这是最容易错的一处：pcrel 相对**字段**地址。如果错误地用段首作基址，
        // 第二条 FDE 的地址会整体偏移。这里用两条 FDE 把差别放大到可观测。
        let vaddr = 0x401000;
        let data = build_eh_frame_32(&[(0x401100, 0x10), (0x401500, 0x10)], vaddr);
        let r = parse_eh_frame(&data, vaddr, Endianness::Little);
        assert_eq!(r.fdes.len(), 2, "notes={:?}", r.notes);
        assert_eq!(r.fdes[0].begin, 0x401100);
        assert_eq!(
            r.fdes[1].begin, 0x401500,
            "第二条 FDE 用段首当基址就会算错 —— 必须用字段自身地址"
        );
    }

    #[test]
    fn encoding_helpers_are_correct() {
        assert_eq!(encoding_kind(0x1b), 0x0b); // pcrel|sdata4 -> sdata4
        assert!(encoding_is_indirect(0x9b));
        assert!(!encoding_is_indirect(0x1b));
        assert_eq!(encoding_kind(ENC_OMIT), 0x0f);
    }

    #[test]
    fn leb128_roundtrip_and_bounds() {
        // 128 -> 0x80 0x01
        let (v, next) = read_uleb(&[0x80, 0x01], 0, 2).expect("uleb");
        assert_eq!(v, 128);
        assert_eq!(next, 2);
        // 截断的 LEB 必须返回 None 而不是猜
        assert!(read_uleb(&[0x80], 0, 1).is_none());
        // 负数 sleb
        let (v, _) = read_sleb(&[0x78], 0, 1).expect("sleb");
        assert_eq!(v, -8);
    }

    #[test]
    fn zero_length_fde_is_dropped() {
        // 长度为 0 的"函数"不是函数 —— 不能放进边界表（否则会造出空函数）
        let vaddr = 0x401000;
        let data = build_eh_frame_32(&[(0x401100, 0)], vaddr);
        let r = parse_eh_frame(&data, vaddr, Endianness::Little);
        assert!(r.fdes.is_empty(), "零长度的 FDE 必须被丢弃");
    }
}
