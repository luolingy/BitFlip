//! 边界安全的二进制读取原语。
//!
//! 这是整个解析层的地基：**任何**解析器都必须通过这里读字节，不允许直接索引切片。
//! 原因很直接 —— 输入是不可信的二进制文件，而 `bytes[i]` 在越界时会 panic。
//! M1 验收标准里写明"畸形输入只返回错误，不 panic、不 OOM"，那条标准的实现方式
//! 就是"只给这一条读取路径，且它返回 `Result`"。
//!
//! 设计约束：
//! - 全部为 `Result` 返回，不用 `Option` —— 调用方需要知道"为什么读不到"（越界 vs 偏差）。
//! - 所有偏移运算用 `checked_add` / `checked_mul`，杜绝整数回绕。
//! - 读取不复制数据（`Reader` 只是视图），需要时显式 `to_vec`。

use thiserror::Error;

/// 解析期错误。
///
/// 变体刻意区分"文件本身坏了"（`OutOfBounds` / `Truncated`）与"我们不支持"（`Unsupported`），
/// 因为前者要给用户看"文件可能损坏"，后者要给用户看"这个格式我们还没做（见计划里程碑）"。
#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum ParseError {
    /// 读取位置超出文件范围。
    #[error("越界读取：偏移 {offset:#x} 长度 {len:#x}，文件仅 {size:#x} 字节（{what}）")]
    OutOfBounds {
        /// 请求的偏移。
        offset: u64,
        /// 请求的长度。
        len: u64,
        /// 文件（或当前视图）总长度。
        size: u64,
        /// 正在解析的结构名，用于定位问题。
        what: &'static str,
    },
    /// 文件在结构需要的位置就结束了。
    #[error("文件被截断：{what} 需要至少 {needed:#x} 字节，实际 {actual:#x} 字节")]
    Truncated {
        /// 正在解析的结构名。
        what: &'static str,
        /// 需要的字节数。
        needed: u64,
        /// 实际可用的字节数。
        actual: u64,
    },
    /// 魔法数不匹配。
    #[error("格式标识不匹配：期望 {expected}，实际 {actual}")]
    BadMagic {
        /// 期望的标识（人类可读，例如 `ELF` / `PE`）。
        expected: &'static str,
        /// 实际读到的标识（十六进制或可见 ASCII）。
        actual: String,
    },
    /// 结构合法但取值超出实现范围（例如 `e_machine` 未映射）。
    #[error("不支持的取值：{what} = {value:#x}（{detail}）")]
    Unsupported {
        /// 字段名。
        what: &'static str,
        /// 实际取值。
        value: u64,
        /// 说明与计划里程碑。
        detail: &'static str,
    },
    /// 字段之间互相矛盾（例如节偏移指向头内部、表项自引用）。
    #[error("结构自相矛盾：{0}")]
    Inconsistent(String),
    /// 数值转换溢出（例如 32 位偏移加到 64 位基址后越界）。
    #[error("数值溢出：{0}")]
    Overflow(String),
}

impl ParseError {
    /// 面向用户的短说明（UI 与 CLI 直接展示）。
    ///
    /// 与 `Display` 的区别：这里**只说事实与后果**，不带内部字段名，
    /// 因为用户看到的是"这个文件读不了"，而不是我们的数据结构。
    #[must_use]
    pub fn summary_zh(&self) -> String {
        match self {
            Self::OutOfBounds { what, .. } => {
                format!("文件结构越界：{what} 指向的位置超出文件范围，文件可能已损坏或被裁剪")
            }
            Self::Truncated { what, .. } => {
                format!("文件被截断：{what} 不完整，可能是下载未完成或被人为裁剪")
            }
            Self::BadMagic { .. } => "格式标识不匹配，可能选错了文件类型".to_string(),
            Self::Unsupported { detail, .. } => format!("暂不支持：{detail}"),
            Self::Inconsistent(detail) => format!("文件结构自相矛盾：{detail}"),
            Self::Overflow(detail) => format!("地址或长度计算溢出：{detail}"),
        }
    }
}

/// 对一段字节的只读视图，所有访问都做边界检查。
///
/// `base` 是这段视图在**宿主文件**中的起始偏移。保留它是为了让错误信息里的偏移
/// 是文件内的绝对偏移（用户能拿去和十六进制查看器对照），而不是视图内的相对值。
#[derive(Debug, Clone, Copy)]
pub struct Reader<'a> {
    bytes: &'a [u8],
    base: u64,
}

/// 字节序。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Endianness {
    /// 小端。
    Little,
    /// 大端。
    Big,
}

impl Endianness {
    /// 从 ELF `EI_DATA` 取值转换。
    #[must_use]
    pub const fn from_elf_data(data: u8) -> Option<Self> {
        match data {
            1 => Some(Self::Little),
            2 => Some(Self::Big),
            _ => None,
        }
    }
}

impl<'a> Reader<'a> {
    /// 用整段字节构造视图，`base` 为 0。
    #[must_use]
    pub const fn new(bytes: &'a [u8]) -> Self {
        Self { bytes, base: 0 }
    }

    /// 用整段字节构造视图，并声明它在宿主文件中的起始偏移。
    #[must_use]
    pub const fn with_base(bytes: &'a [u8], base: u64) -> Self {
        Self { bytes, base }
    }

    /// 视图覆盖的字节数。
    #[must_use]
    pub const fn len(&self) -> u64 {
        self.bytes.len() as u64
    }

    /// 视图是否为空。
    #[must_use]
    pub const fn is_empty(&self) -> bool {
        self.bytes.is_empty()
    }

    /// 视图在宿主文件中的起始偏移。
    #[must_use]
    pub const fn base(&self) -> u64 {
        self.base
    }

    /// 取出原始字节（用于把范围交给上层，例如 mmap 直读）。
    #[must_use]
    pub const fn as_bytes(&self) -> &'a [u8] {
        self.bytes
    }

    /// 在 `offset` 处取 `len` 字节。
    ///
    /// 这是唯一的取字节入口。越界返回 [`ParseError::OutOfBounds`]，绝不 panic。
    pub fn slice(&self, offset: u64, len: u64, what: &'static str) -> Result<&'a [u8], ParseError> {
        let end = offset
            .checked_add(len)
            .ok_or_else(|| ParseError::Overflow(format!("{what}: {offset:#x} + {len:#x}")))?;
        let size = self.len();
        if end > size {
            return Err(ParseError::OutOfBounds {
                offset: self.base.saturating_add(offset),
                len,
                size: self.base.saturating_add(size),
                what,
            });
        }
        // 上面已经确认 end <= len()，而 len() 来自 bytes.len()，故切片安全。
        let start = offset as usize;
        let stop = end as usize;
        Ok(&self.bytes[start..stop])
    }

    /// 从 `offset` 读一个 `u8`。
    pub fn u8(&self, offset: u64, what: &'static str) -> Result<u8, ParseError> {
        Ok(self.slice(offset, 1, what)?[0])
    }

    /// 从 `offset` 读 `u16`。
    pub fn u16(
        &self,
        offset: u64,
        endian: Endianness,
        what: &'static str,
    ) -> Result<u16, ParseError> {
        let raw = self.slice(offset, 2, what)?;
        let arr = [raw[0], raw[1]];
        Ok(match endian {
            Endianness::Little => u16::from_le_bytes(arr),
            Endianness::Big => u16::from_be_bytes(arr),
        })
    }

    /// 从 `offset` 读 `u32`。
    pub fn u32(
        &self,
        offset: u64,
        endian: Endianness,
        what: &'static str,
    ) -> Result<u32, ParseError> {
        let raw = self.slice(offset, 4, what)?;
        let arr = [raw[0], raw[1], raw[2], raw[3]];
        Ok(match endian {
            Endianness::Little => u32::from_le_bytes(arr),
            Endianness::Big => u32::from_be_bytes(arr),
        })
    }

    /// 从 `offset` 读 `u64`。
    pub fn u64(
        &self,
        offset: u64,
        endian: Endianness,
        what: &'static str,
    ) -> Result<u64, ParseError> {
        let raw = self.slice(offset, 8, what)?;
        let arr = [
            raw[0], raw[1], raw[2], raw[3], raw[4], raw[5], raw[6], raw[7],
        ];
        Ok(match endian {
            Endianness::Little => u64::from_le_bytes(arr),
            Endianness::Big => u64::from_be_bytes(arr),
        })
    }

    /// 从 `offset` 读一个有符号 `i16`。
    ///
    /// COFF 的 `SectionNumber` 是有符号的：负数表示特殊节
    /// （-1 = ABSOLUTE、-2 = DEBUG 等），不能当无符号读。
    pub fn i16(
        &self,
        offset: u64,
        endian: Endianness,
        what: &'static str,
    ) -> Result<i16, ParseError> {
        let raw = self.slice(offset, 2, what)?;
        let arr = [raw[0], raw[1]];
        Ok(match endian {
            Endianness::Little => i16::from_le_bytes(arr),
            Endianness::Big => i16::from_be_bytes(arr),
        })
    }

    /// 按 `ptr_size`（4 或 8 字节）读一个无符号整数。
    ///
    /// ELF32/ELF64、PE32/PE32+ 的字段宽度只差这一点，用它避免两套解析代码。
    pub fn uint(
        &self,
        offset: u64,
        endian: Endianness,
        ptr_size: u8,
        what: &'static str,
    ) -> Result<u64, ParseError> {
        match ptr_size {
            4 => self.u32(offset, endian, what).map(u64::from),
            8 => self.u64(offset, endian, what),
            _ => Err(ParseError::Unsupported {
                what: "指针宽度",
                value: u64::from(ptr_size),
                detail: "只支持 32 位与 64 位目标（见 docs/PLAN.md §1.3 架构矩阵）",
            }),
        }
    }

    /// 读一串以 NUL 结尾的字符串，最多 `max` 字节。
    ///
    /// 找不到 NUL 时返回整段（截到 `max`），由调用方决定是否接受 —— 真实二进制里
    /// 超长名字是存在的，强行报错会把可解析的文件拒之门外。
    pub fn cstr(&self, offset: u64, max: u64, what: &'static str) -> Result<String, ParseError> {
        let available = self.len().saturating_sub(offset).min(max);
        if available == 0 {
            // 偏移正好在末尾：不是错误，是"空字符串"。
            if offset <= self.len() {
                return Ok(String::new());
            }
            return Err(ParseError::OutOfBounds {
                offset: self.base.saturating_add(offset),
                len: 1,
                size: self.base.saturating_add(self.len()),
                what,
            });
        }
        let raw = self.slice(offset, available, what)?;
        let end = raw.iter().position(|&b| b == 0).unwrap_or(raw.len());
        Ok(String::from_utf8_lossy(&raw[..end]).into_owned())
    }

    /// 校验 `offset` 处 4 字节等于 `magic`。
    pub fn expect_magic(
        &self,
        offset: u64,
        magic: &[u8],
        expected: &'static str,
    ) -> Result<(), ParseError> {
        let len = magic.len() as u64;
        let actual = self.slice(offset, len, expected)?;
        if actual == magic {
            return Ok(());
        }
        Err(ParseError::BadMagic {
            expected,
            actual: actual
                .iter()
                .map(|b| {
                    if b.is_ascii_graphic() {
                        (*b as char).to_string()
                    } else {
                        format!("\\x{b:02x}")
                    }
                })
                .collect(),
        })
    }

    /// 把 `offset` 处的 `count` 个定长项切成子视图，逐项交给 `f`。
    ///
    /// 表项数量来自不可信输入，因此这里先做 `checked_mul` 整体校验，
    /// 再逐项解析 —— 避免"先分配容量再发现越界"式的 OOM。
    pub fn for_each_entry<T, F>(
        &self,
        offset: u64,
        entry_size: u64,
        count: u64,
        what: &'static str,
        mut f: F,
    ) -> Result<Vec<T>, ParseError>
    where
        F: FnMut(usize, Reader<'_>) -> Result<T, ParseError>,
    {
        let total = entry_size
            .checked_mul(count)
            .ok_or_else(|| ParseError::Overflow(format!("{what}: {entry_size} × {count}")))?;
        // 先整段校验：一次性发现"表比文件长"，避免逐项失败却已分配大量内存。
        self.slice(offset, total, what)?;

        let mut out = Vec::new();
        out.try_reserve(count.min(4096) as usize)
            .map_err(|_| ParseError::Overflow(format!("{what}: 无法为 {count} 个表项预留内存")))?;

        let mut cursor = offset;
        for index in 0..count {
            let raw = self.slice(cursor, entry_size, what)?;
            let view = Reader::with_base(raw, self.base + cursor);
            out.push(f(index as usize, view)?);
            cursor = cursor
                .checked_add(entry_size)
                .ok_or_else(|| ParseError::Overflow(format!("{what}: 第 {index} 项后偏移溢出")))?;
        }
        Ok(out)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reads_integers_in_both_endians() {
        let bytes = [0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08];
        let r = Reader::new(&bytes);
        assert_eq!(r.u16(0, Endianness::Little, "t").unwrap(), 0x0201);
        assert_eq!(r.u16(0, Endianness::Big, "t").unwrap(), 0x0102);
        assert_eq!(r.u32(0, Endianness::Little, "t").unwrap(), 0x0403_0201);
        assert_eq!(
            r.u64(0, Endianness::Little, "t").unwrap(),
            0x0807_0605_0403_0201
        );
        assert_eq!(
            r.u64(0, Endianness::Big, "t").unwrap(),
            0x0102_0304_0506_0708
        );
    }

    #[test]
    fn out_of_bounds_is_an_error_not_a_panic() {
        let bytes = [0u8; 4];
        let r = Reader::new(&bytes);
        // 恰好读完是允许的
        assert_eq!(r.slice(0, 4, "t").unwrap().len(), 4);
        assert_eq!(r.slice(4, 0, "t").unwrap().len(), 0);
        // 多一个字节就越界
        assert!(matches!(
            r.slice(0, 5, "t"),
            Err(ParseError::OutOfBounds { .. })
        ));
        assert!(matches!(
            r.slice(4, 1, "t"),
            Err(ParseError::OutOfBounds { .. })
        ));
        assert!(matches!(
            r.u64(0, Endianness::Little, "t"),
            Err(ParseError::OutOfBounds { .. })
        ));
    }

    #[test]
    fn offset_plus_len_overflow_is_caught() {
        let bytes = [0u8; 8];
        let r = Reader::new(&bytes);
        assert!(matches!(
            r.slice(u64::MAX, 1, "t"),
            Err(ParseError::Overflow(_))
        ));
        assert!(matches!(
            r.slice(u64::MAX - 1, 8, "t"),
            Err(ParseError::Overflow(_))
        ));
    }

    #[test]
    fn error_reports_absolute_offset_using_base() {
        let bytes = [0u8; 4];
        let r = Reader::with_base(&bytes, 0x1000);
        match r.slice(4, 1, "节表") {
            Err(ParseError::OutOfBounds { offset, size, .. }) => {
                // 偏移必须能直接拿去和十六进制查看器对照
                assert_eq!(offset, 0x1004);
                assert_eq!(size, 0x1004);
            }
            other => panic!("期望 OutOfBounds，实际 {other:?}"),
        }
    }

    #[test]
    fn cstr_stops_at_nul_and_tolerates_missing_nul() {
        let bytes = b"abc\0def";
        let r = Reader::new(bytes);
        assert_eq!(r.cstr(0, 64, "t").unwrap(), "abc");
        // 没有 NUL 时返回剩余全部，由调用方决定是否接受
        assert_eq!(r.cstr(4, 64, "t").unwrap(), "def");
        // 偏移正好在末尾 → 空串，不是错误
        assert_eq!(r.cstr(7, 64, "t").unwrap(), "");
        // 超过末尾才是错误
        assert!(r.cstr(8, 64, "t").is_err());
    }

    #[test]
    fn cstr_respects_max_length() {
        let bytes = b"abcdefghij";
        let r = Reader::new(bytes);
        assert_eq!(r.cstr(0, 3, "t").unwrap(), "abc");
    }

    #[test]
    fn expect_magic_is_precise() {
        let bytes = b"\x7fELF";
        let r = Reader::new(bytes);
        assert!(r.expect_magic(0, b"\x7fELF", "ELF").is_ok());
        match r.expect_magic(0, b"MZ\0\0", "PE") {
            Err(ParseError::BadMagic { expected, actual }) => {
                assert_eq!(expected, "PE");
                // 不可见字符用 \xNN 表示，可读字符原样显示
                assert!(
                    actual.contains("ELF") || actual.contains("\\x7f"),
                    "{actual}"
                );
            }
            other => panic!("期望 BadMagic，实际 {other:?}"),
        }
        // 魔法数本身越界也要报 OutOfBounds，而不是 panic
        assert!(matches!(
            r.expect_magic(0, b"toolongmagic", "X"),
            Err(ParseError::OutOfBounds { .. })
        ));
    }

    #[test]
    fn for_each_entry_validates_table_extent_before_allocating() {
        // 声称有 100 万个 64 字节表项，但文件只有 16 字节。
        // 必须在分配前就失败 —— 这是"不 OOM"的关键。
        let bytes = [0u8; 16];
        let r = Reader::new(&bytes);
        let result: Result<Vec<u64>, _> = r.for_each_entry(0, 64, 1_000_000, "表", |_i, view| {
            view.u64(0, Endianness::Little, "项")
        });
        assert!(matches!(result, Err(ParseError::OutOfBounds { .. })));
    }

    #[test]
    fn for_each_entry_size_overflow_is_caught() {
        let bytes = [0u8; 16];
        let r = Reader::new(&bytes);
        let result: Result<Vec<u64>, _> = r.for_each_entry(0, u64::MAX, 2, "表", |_i, view| {
            view.u64(0, Endianness::Little, "项")
        });
        assert!(matches!(result, Err(ParseError::Overflow(_))));
    }

    #[test]
    fn for_each_entry_reads_each_item_with_correct_base() {
        let bytes = [1u8, 0, 0, 0, 2, 0, 0, 0, 3, 0, 0, 0];
        let r = Reader::new(&bytes);
        let items: Vec<u32> = r
            .for_each_entry(0, 4, 3, "表", |_i, view| {
                view.u32(0, Endianness::Little, "项")
            })
            .unwrap();
        assert_eq!(items, vec![1, 2, 3]);
    }

    #[test]
    fn uint_handles_both_pointer_sizes() {
        let bytes = [0xff; 8];
        let r = Reader::new(&bytes);
        assert_eq!(r.uint(0, Endianness::Little, 4, "t").unwrap(), 0xffff_ffff);
        assert_eq!(r.uint(0, Endianness::Little, 8, "t").unwrap(), u64::MAX);
        // 宽度 2/3 之类明确报不支持，而不是猜
        assert!(matches!(
            r.uint(0, Endianness::Little, 2, "t"),
            Err(ParseError::Unsupported { .. })
        ));
    }

    #[test]
    fn error_summaries_are_human_readable() {
        let err = ParseError::Truncated {
            what: "节表",
            needed: 0x100,
            actual: 0x40,
        };
        let summary = err.summary_zh();
        assert!(summary.contains("截断"), "{summary}");
        assert!(summary.contains("节表"), "{summary}");

        let unsupported = ParseError::Unsupported {
            what: "e_machine",
            value: 0x1234,
            detail: "未知的 ELF 机器类型",
        };
        assert!(unsupported.summary_zh().contains("暂不支持"));
    }

    /// 穷举一批畸形输入，证明任何偏移/长度组合都只返回错误。
    ///
    /// 这是"不 panic"的最小化随机测试：不引入 fuzz 依赖也能在 `cargo test` 里跑。
    #[test]
    fn arbitrary_offsets_and_lengths_never_panic() {
        let bytes: Vec<u8> = (0..64u8).collect();
        let r = Reader::new(&bytes);
        let interesting = [
            0u64,
            1,
            2,
            63,
            64,
            65,
            u32::MAX as u64,
            u64::MAX - 1,
            u64::MAX,
        ];
        for &offset in &interesting {
            for &len in &interesting {
                let _ = r.slice(offset, len, "fuzz");
                let _ = r.u8(offset, "fuzz");
                let _ = r.u16(offset, Endianness::Little, "fuzz");
                let _ = r.u32(offset, Endianness::Big, "fuzz");
                let _ = r.u64(offset, Endianness::Little, "fuzz");
                let _ = r.cstr(offset, len, "fuzz");
                let _ = r.uint(offset, Endianness::Little, 8, "fuzz");
            }
        }
    }
}
