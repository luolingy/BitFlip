//! 字符串提取：ASCII / UTF-16LE。
//!
//! 策略：对可读段做线性扫描，找**连续可打印字节段**，最小长度可调。
//! 这与"把整个文件当文本"的区别在于：只扫**已映射且可读**的段
//! （代码段里也可能有内联字符串，但跳转表/对齐填充混进来的概率低得多）。
//!
//! 编码判定是**启发式**，结果带编码标签但**不是保证**：
//! UTF-16 判定要求"字节对 + 高位字节模式"，误判率存在，UI 必须能显示原始字节。

/// 一个提取到的字符串。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StringEntry {
    /// 字符串数据起始地址。
    pub address: u64,
    /// 字节长度（编码无关，就是占了多少字节）。
    pub size: u64,
    /// 判定的编码。
    pub encoding: StringEncoding,
    /// 解码后的内容（提取时就解好，UI 不用再猜）。
    pub text: String,
}

/// 字符串编码。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum StringEncoding {
    /// ASCII（单字节，全可打印）。
    Ascii,
    /// UTF-16LE（Windows 宽字符的存储形态）。
    Utf16Le,
}

impl StringEncoding {
    /// 稳定短名（wire 用）。
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Ascii => "ascii",
            Self::Utf16Le => "utf-16le",
        }
    }
}

/// 提取选项。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct StringOptions {
    /// 最小长度（字符数，不是字节数）。
    pub min_length: usize,
    /// 单次扫描最多提取的字符串条数（防畸形输入触发海量小串）。
    pub max_entries: usize,
}

impl Default for StringOptions {
    fn default() -> Self {
        Self {
            min_length: 4,
            max_entries: 100_000,
        }
    }
}

/// 是否为"可打印且不是空白麻烦"的 ASCII 字节。
///
/// 允许 tab/CR/LF（字符串里带换行是常态），拒绝其他控制字符。
#[must_use]
fn printable(b: u8) -> bool {
    (0x20..0x7f).contains(&b) || b == b'\t' || b == b'\r' || b == b'\n'
}

/// 提取 ASCII 字符串：连续可打印字节 + NUL 终止。
fn scan_ascii(data: &[u8], base: u64, opts: &StringOptions, out: &mut Vec<StringEntry>) {
    let mut start: Option<usize> = None;
    for (i, &b) in data.iter().enumerate() {
        if printable(b) {
            if start.is_none() {
                start = Some(i);
            }
        } else {
            // 一段结束：NUL（或不可打印字节）是终止符
            if let Some(s) = start {
                let len = i - s;
                if len >= opts.min_length {
                    // 仅当终止字节是 NUL 时才算"字符串"：
                    // 不可打印字节结束的可打印段更可能是代码/表数据的伪影
                    if b == 0 {
                        out.push(StringEntry {
                            address: base + s as u64,
                            size: len as u64,
                            encoding: StringEncoding::Ascii,
                            text: String::from_utf8_lossy(&data[s..s + len]).into_owned(),
                        });
                    }
                }
            }
            start = None;
        }
    }
    // 段尾悬空段：没有 NUL 终止的不收（截断的串是伪影，真串有终止符）
}

/// 提取 UTF-16LE 字符串：ASCII 范围字符 + 高位字节 0 + NUL 终止。
fn scan_utf16le(data: &[u8], base: u64, opts: &StringOptions, out: &mut Vec<StringEntry>) {
    // UTF-16LE 里 "abc" 是 61 00 62 00 63 00 00 00。
    // 找"偶数对齐 + 低位可打印 + 高位为 0"的连续段。
    let n = data.len();
    let mut i = 0usize;
    while i + 1 < n {
        // 段必须从偶数偏移开始（相对段基址；真 UTF-16 串是对齐的）
        let mut start: Option<usize> = None;
        let mut j = i;
        while j + 1 < n {
            let lo = data[j];
            let hi = data[j + 1];
            if hi == 0 && printable(lo) {
                if start.is_none() {
                    start = Some(j);
                }
                j += 2;
            } else {
                break;
            }
        }
        if let Some(s) = start {
            let char_len = (j - s) / 2;
            // 终止条件：接下来的 2 字节是 00 00（NUL 终止）
            if char_len >= opts.min_length && j + 1 < n && data[j] == 0 && data[j + 1] == 0 {
                let bytes = &data[s..j];
                let mut chars = Vec::with_capacity(char_len);
                for pair in bytes.chunks_exact(2) {
                    chars.push(pair[0]);
                }
                out.push(StringEntry {
                    address: base + s as u64,
                    size: (j - s) as u64,
                    encoding: StringEncoding::Utf16Le,
                    text: String::from_utf8_lossy(&chars).into_owned(),
                });
                i = j + 2; // 跳过终止符
                continue;
            }
            // 不构成合格串：从下一个对齐点重试
            i = if s.is_multiple_of(2) { s + 2 } else { s + 1 };
        } else {
            i += 2; // 非对齐步进：只在偶数偏移找对
        }
    }
}

/// 对一段内存（段基址 `base` + 数据）做字符串提取。
///
/// 先 ASCII 后 UTF-16：ASCII 命中的区间 UTF-16 不会再命中
/// （UTF-16 的偶数偏移要求 + 高位 0 使两者互斥），重叠不会产生重复条目。
#[must_use]
pub fn extract_strings(data: &[u8], base: u64, opts: &StringOptions) -> Vec<StringEntry> {
    let mut out = Vec::new();
    scan_ascii(data, base, opts, &mut out);
    scan_utf16le(data, base, opts, &mut out);
    out.sort_by_key(|e| e.address);
    out.dedup_by_key(|e| e.address);
    out.truncate(opts.max_entries);
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ascii_extraction_finds_nul_terminated() {
        let mut data = b"hello world\0".to_vec();
        data.extend_from_slice(b"\x00\x00\x00");
        let s = extract_strings(&data, 0x1000, &StringOptions::default());
        assert_eq!(s.len(), 1);
        assert_eq!(s[0].text, "hello world");
        assert_eq!(s[0].address, 0x1000);
        assert_eq!(s[0].encoding, StringEncoding::Ascii);
    }

    #[test]
    fn short_strings_below_min_length_are_skipped() {
        let data = b"ab\0cd\0".to_vec();
        let s = extract_strings(&data, 0, &StringOptions::default());
        assert!(s.is_empty(), "min_length=4 时 ab/cd 都太短");
    }

    #[test]
    fn printable_run_without_nul_is_not_a_string() {
        // 没有终止符的可打印段是伪影：代码字节恰好落在可打印范围
        let data = b"abcdefgh".to_vec();
        let s = extract_strings(&data, 0, &StringOptions::default());
        assert!(s.is_empty(), "没有 NUL 终止不许收");
    }

    #[test]
    fn utf16le_extraction() {
        // "wide" 的 UTF-16LE 编码 + NUL 终止
        let mut data: Vec<u8> = Vec::new();
        for c in b"wide" {
            data.push(*c);
            data.push(0);
        }
        data.push(0);
        data.push(0);
        let s = extract_strings(&data, 0x2000, &StringOptions::default());
        assert_eq!(s.len(), 1, "应恰好命中 1 条 UTF-16 串，实际 {s:?}");
        assert_eq!(s[0].encoding, StringEncoding::Utf16Le);
        assert_eq!(s[0].text, "wide");
        assert_eq!(s[0].address, 0x2000);
    }

    #[test]
    fn utf16_needs_even_alignment() {
        // 前置 1 字节把 UTF-16 串推到奇数偏移：不应命中（真 UTF-16 串是对齐的）
        let mut data: Vec<u8> = vec![0x41];
        for c in b"wide" {
            data.push(*c);
            data.push(0);
        }
        data.push(0);
        data.push(0);
        let s = extract_strings(&data, 0, &StringOptions::default());
        assert!(s.is_empty(), "奇数对齐的'UTF-16'是伪影，实际 {s:?}");
    }

    #[test]
    fn max_entries_caps_output() {
        let data = b"aaa1\0aaa2\0aaa3\0aaa4\0aaa5\0".to_vec();
        let opts = StringOptions {
            min_length: 4,
            max_entries: 3,
        };
        let s = extract_strings(&data, 0, &opts);
        assert_eq!(s.len(), 3, "上限生效");
    }

    #[test]
    fn addresses_are_sorted() {
        let mut data = b"second\0zzz\0first\0".to_vec();
        // 故意乱序：把 "first" 的字节放到最后，地址也是最后
        data.extend_from_slice(b"\x00");
        let s = extract_strings(&data, 0x4000, &StringOptions::default());
        let mut addrs: Vec<u64> = s.iter().map(|e| e.address).collect();
        let sorted = addrs.clone();
        addrs.sort_unstable();
        assert_eq!(addrs, sorted, "输出必须按地址升序");
    }
}
