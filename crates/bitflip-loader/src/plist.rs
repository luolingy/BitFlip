//! plist（`bplist00` 二进制与 `<?xml ...` 文本两种）的**最小**读取器：
//! 只回答一个问题 —— `CFBundleExecutable` 是什么。
//!
//! # 两种格式都得读
//!
//! 实测本机四份真实 IPA：`SideStore` 与 `Stapxs.QQ.Lite` 的 `Info.plist` 是
//! `bplist00`，`LiveContainer` 与 `PojavLauncher` 的是 XML。只认一种，另一半样本的
//! "主二进制"就永远只能靠猜 —— 等于没做。
//!
//! # 为什么自己写，而不是引一个 plist crate
//!
//! 认定主二进制只需要读顶层字典里的**一个字符串键**。引一个通用 plist 库要付两份
//! 代价：一份新的供应链与许可闸门，以及一个"能解全能解"的 API 会诱使上层把整份
//! `Info.plist` 当结构化数据用 —— 而 BitFlip 对它的其余字段没有结论可下。这里只实现
//! "定位一个字符串"，遇到不认识的结构一律报错，不猜。
//!
//! # 二进制格式（本模块用到的那部分）
//!
//! 出处：Apple 的 `CFBinaryPList`（`bplist00`）格式。布局是：
//!
//! ```text
//! "bplist00"                8 字节魔数
//! 对象区                     每个对象以 marker 开头，顺序不保证有意义
//! 偏移表                     numObjects 个 offsetIntSize 字节的大端偏移
//! trailer（末尾 32 字节）      5 字节未用、1 字节 sortVersion、
//!                           1 字节 offsetIntSize、1 字节 objectRefSize、
//!                           8 字节 numObjects、8 字节 topObject、
//!                           8 字节 offsetTableOffset（后三个都是大端 u64）
//! ```
//!
//! 对象 marker 的高 4 位是类型、低 4 位是信息（元素个数，或整数宽度的幂）。个数写
//! `0xF` 时表示"个数在后随的一个整数对象里"。本模块认得：`0x5` ASCII 串、`0x6`
//! UTF-16BE 串、`0xD` 字典，以及只用来承载个数的 `0x1` 整数。其余类型要么不参与
//! 结论（比如布尔、日期），要么直接报错。
//!
//! # XML 格式（同上）
//!
//! 只做有界扫描：找 `<key>CFBundleExecutable</key>`，再取它后面第一个 `<string>`。
//! 不建 DOM，也不解释 DTD —— 需要的那一个值之外的任何结构都与本模块的结论无关。
//! 文本按 UTF-8 解（XML plist 实际只有这一种；UTF-16 的 BOM 明确报错，不硬猜）。
//!
//! # 边界
//!
//! 每一处偏移、长度、对象引用都做上界检查，且一切对象数据必须落在"魔数之后、偏移表
//! 之前"—— 否则少量篡改就能让读取器把偏移表或 trailer 当成对象体。字符串长度上限见
//! [`MAX_STRING_BYTES`]。这个模块不可 panic，也不做递归。

use thiserror::Error;

/// 一份二进制 plist 里，字符串对象允许的最大字节数。
///
/// `CFBundleExecutable` 是个文件名，真实文件里几十字节。给到 64 KiB 是给非 ASCII
/// 名字留余量，同时把"长度字段写了 2^40"这类输入挡在分配内存之前 —— 否则一份
/// 几十字节的坏文件就能让读取器申请 4 GiB。
const MAX_STRING_BYTES: usize = 64 * 1024;

/// 二进制 plist 的魔数。
const MAGIC: &[u8; 8] = b"bplist00";

/// trailer 的固定长度（见模块文档的布局）。
const TRAILER_SIZE: usize = 32;

/// 读一份二进制 plist 可能失败的原因。
///
/// 每一档都带出"卡在哪"，因为调用方要把这档降级**写在界面上**（CLAUDE.md §7）：
/// 一句"Info.plist 解析失败（偏移表越界）"比"主二进制是猜的"有用得多。
#[derive(Debug, Error, PartialEq, Eq)]
pub enum PlistError {
    /// 头 8 字节既不是 `bplist00`，也看不出是 XML plist。
    #[error("既不是二进制 plist（缺 bplist00 魔数），也看不出是 XML plist")]
    UnknownFormat,

    /// XML plist 的结构读不通（缺闭合标签、实体写坏、不是 UTF-8 等）。
    #[error("XML plist 读不通：{why}")]
    MalformedXml { why: String },

    /// XML 里 `CFBundleExecutable` 后面跟的不是 `<string>`。
    #[error("XML plist 里 CFBundleExecutable 的值是 <{element}>，不是 <string>")]
    XmlValueNotString { element: String },

    /// 文件连魔数加 trailer 都不够。
    #[error("文件只有 {size} 字节：二进制 plist 至少要 8 字节魔数 + 32 字节 trailer")]
    TooShort { size: usize },

    /// trailer 里的两个宽度字段不在 `1..=8`。
    #[error(
        "trailer 的宽度字段不合法（offsetIntSize={offset_int_size}，objectRefSize={object_ref_size}，都必须在 1..=8）"
    )]
    BadTrailerWidth {
        offset_int_size: usize,
        object_ref_size: usize,
    },

    /// 偏移表整块不在 trailer 之前。
    #[error("偏移表越界：起点 {start}、长度 {len}，文件 {size} 字节（末尾 32 字节是 trailer）")]
    OffsetTableOutOfRange { start: u64, len: u64, size: usize },

    /// 偏移表条目指向对象区之外。
    #[error("对象 #{index} 的偏移 {offset} 不在对象区 {start}..{end} 里")]
    ObjectOutOfRange {
        index: usize,
        offset: u64,
        start: usize,
        end: usize,
    },

    /// 某段数据被要求落在对象区之外。
    #[error("对象 #{index} 的数据区 [{start}, {end}) 不在对象区 {object_start}..{object_end} 里")]
    ObjectRangeOutsideObjectArea {
        index: usize,
        start: usize,
        end: usize,
        object_start: usize,
        object_end: usize,
    },

    /// 顶层对象不是字典。
    #[error("顶层对象不是字典（marker 0x{marker:02x}）")]
    TopNotDict { marker: u8 },

    /// 个数写 0xF 时，后随的不是整数对象。
    #[error("长度字段不是整数对象（marker 0x{marker:02x}）")]
    LengthNotInteger { marker: u8 },

    /// 长度或偏移超出本进程能表示的范围。
    #[error("长度 {len} 超出可用范围")]
    LengthTooLarge { len: u64 },

    /// 字符串长度超过 [`MAX_STRING_BYTES`]。
    #[error("字符串长度 {len} 超过上限 {MAX_STRING_BYTES} 字节")]
    StringTooLong { len: usize },

    /// 整数对象的宽度不是 1/2/4/8 字节。
    #[error("整数对象宽度不支持（2^{exponent} 字节）")]
    UnsupportedIntWidth { exponent: u8 },

    /// 对象引用超出对象总数。
    #[error("对象引用 #{reference} 越界（对象总数 {total}）")]
    ReferenceOutOfRange { reference: u64, total: usize },

    /// 字典的键不是字符串。
    #[error("字典的键不是字符串（marker 0x{marker:02x}）")]
    KeyNotString { marker: u8 },

    /// `CFBundleExecutable` 的值不是字符串。
    #[error("CFBundleExecutable 不是字符串（marker 0x{marker:02x}）")]
    ValueNotString { marker: u8 },

    /// 被要求当字符串读的对象不是字符串。
    #[error("对象 #{index} 不是字符串（marker 0x{marker:02x}）")]
    NotString { marker: u8, index: usize },

    /// ASCII 串那一档里的字节不是合法 UTF-8。
    #[error("字符串对象 #{index} 不是合法 UTF-8")]
    InvalidUtf8 { index: usize },

    /// UTF-16BE 串的字节数不是偶数，或含不成对的代理项。
    #[error("字符串对象 #{index} 不是合法的 UTF-16BE")]
    BadUtf16 { index: usize },
}

/// 从一份 plist（二进制或 XML）里取出 `CFBundleExecutable`。
///
/// - `Ok(Some(name))`：文件里写着它的可执行名 —— 这是**事实**；
/// - `Ok(None)`：结构读得通，但没有这个键；
/// - `Err(..)`：读不出来（格式不对 / 结构不认识）。调用方必须把这一档当成**降级**，
///   而不是当成"没有"。
pub fn bundle_executable(bytes: &[u8]) -> Result<Option<String>, PlistError> {
    if bytes.starts_with(MAGIC) {
        return bundle_executable_binary(bytes);
    }
    if xml::looks_like_plist(bytes) {
        return xml::bundle_executable(bytes);
    }
    Err(PlistError::UnknownFormat)
}

/// 二进制 plist（`bplist00`）分支。
fn bundle_executable_binary(bytes: &[u8]) -> Result<Option<String>, PlistError> {
    let plist = Bplist::new(bytes)?;
    let top = usize::try_from(plist.top_object).map_err(|_| PlistError::ReferenceOutOfRange {
        reference: plist.top_object,
        total: plist.num_objects,
    })?;
    let (marker, body) = plist.object_head(top)?;
    if marker & 0xf0 != 0xd0 {
        return Err(PlistError::TopNotDict { marker });
    }

    let (count, keys_start) = plist.length_of(marker, body, top)?;
    let ref_size = plist.object_ref_size;
    let keys_len = count
        .checked_mul(ref_size)
        .ok_or(PlistError::LengthTooLarge { len: count as u64 })?;
    let values_start = keys_start
        .checked_add(keys_len)
        .ok_or(PlistError::LengthTooLarge { len: count as u64 })?;
    let refs_end = values_start
        .checked_add(keys_len)
        .ok_or(PlistError::LengthTooLarge { len: count as u64 })?;
    // 键引用区和值引用区必须整块在对象区里：这两个数组的边界只由 trailer 的数字决定，
    // 不校验就等于让 trailer 直接指向偏移表。
    plist.check_object_area(keys_start, refs_end, top)?;

    for i in 0..count {
        let key_ref = plist.ref_at(keys_start + i * ref_size, top)?;
        let key = match plist.string_at(key_ref) {
            Ok(key) => key,
            Err(PlistError::NotString { marker, .. }) => {
                return Err(PlistError::KeyNotString { marker })
            }
            Err(error) => return Err(error),
        };
        if key != "CFBundleExecutable" {
            continue;
        }
        let value_ref = plist.ref_at(values_start + i * ref_size, top)?;
        return match plist.string_at(value_ref) {
            Ok(value) => Ok(Some(value)),
            Err(PlistError::NotString { marker, .. }) => Err(PlistError::ValueNotString { marker }),
            Err(error) => Err(error),
        };
    }
    Ok(None)
}

/// 校验过边界的 `bplist00` 视图。
struct Bplist<'a> {
    bytes: &'a [u8],
    /// 偏移表里每个条目占多少字节（trailer 的 `offsetIntSize`）。
    offset_int_size: usize,
    /// 对象引用占多少字节（trailer 的 `objectRefSize`）。
    object_ref_size: usize,
    /// 对象总数（trailer 的 `numObjects`）。
    num_objects: usize,
    /// 顶层对象的序号（trailer 的 `topObject`）。
    top_object: u64,
    /// 偏移表起点，同时是对象区的右边界。
    offset_table_start: usize,
}

impl<'a> Bplist<'a> {
    fn new(bytes: &'a [u8]) -> Result<Self, PlistError> {
        let size = bytes.len();
        if size < MAGIC.len() + TRAILER_SIZE {
            return Err(PlistError::TooShort { size });
        }
        if &bytes[..MAGIC.len()] != MAGIC {
            return Err(PlistError::UnknownFormat);
        }

        let trailer = &bytes[size - TRAILER_SIZE..];
        let offset_int_size = usize::from(trailer[6]);
        let object_ref_size = usize::from(trailer[7]);
        if !(1..=8).contains(&offset_int_size) || !(1..=8).contains(&object_ref_size) {
            return Err(PlistError::BadTrailerWidth {
                offset_int_size,
                object_ref_size,
            });
        }
        let num_objects_raw = read_be_uint(&trailer[8..16]);
        let top_object = read_be_uint(&trailer[16..24]);
        let offset_table_offset = read_be_uint(&trailer[24..32]);

        let num_objects =
            usize::try_from(num_objects_raw).map_err(|_| PlistError::LengthTooLarge {
                len: num_objects_raw,
            })?;
        // 每个对象至少占 1 字节，所以对象数不可能超过文件长度。先挡掉离谱的
        // numObjects，后面乘 offset_int_size 才不会溢出。
        if num_objects == 0 || num_objects > size {
            return Err(PlistError::LengthTooLarge {
                len: num_objects_raw,
            });
        }

        let table_len =
            num_objects
                .checked_mul(offset_int_size)
                .ok_or(PlistError::LengthTooLarge {
                    len: num_objects_raw,
                })?;
        let table_start =
            usize::try_from(offset_table_offset).map_err(|_| PlistError::LengthTooLarge {
                len: offset_table_offset,
            })?;
        let table_end = table_start
            .checked_add(table_len)
            .ok_or(PlistError::LengthTooLarge {
                len: offset_table_offset,
            })?;
        // 偏移表必须整块落在 trailer 之前，对象区又必须整块落在偏移表之前。
        if table_end > size - TRAILER_SIZE || table_start < MAGIC.len() {
            return Err(PlistError::OffsetTableOutOfRange {
                start: offset_table_offset,
                len: table_len as u64,
                size,
            });
        }

        Ok(Self {
            bytes,
            offset_int_size,
            object_ref_size,
            num_objects,
            top_object,
            offset_table_start: table_start,
        })
    }

    /// 校验 `[start, end)` 整块落在对象区里（魔数之后、偏移表之前）。
    fn check_object_area(&self, start: usize, end: usize, index: usize) -> Result<(), PlistError> {
        if start < MAGIC.len() || start > end || end > self.offset_table_start {
            return Err(PlistError::ObjectRangeOutsideObjectArea {
                index,
                start,
                end,
                object_start: MAGIC.len(),
                object_end: self.offset_table_start,
            });
        }
        Ok(())
    }

    /// 对象区里 `[at, at + len)` 这一段。
    fn object_slice(&self, at: usize, len: usize, index: usize) -> Result<&'a [u8], PlistError> {
        let end = at
            .checked_add(len)
            .ok_or(PlistError::LengthTooLarge { len: len as u64 })?;
        self.check_object_area(at, end, index)?;
        Ok(&self.bytes[at..end])
    }

    /// 第 `index` 个对象的 marker 与其对象体的起点。
    fn object_head(&self, index: usize) -> Result<(u8, usize), PlistError> {
        if index >= self.num_objects {
            return Err(PlistError::ReferenceOutOfRange {
                reference: index as u64,
                total: self.num_objects,
            });
        }
        let entry = self
            .offset_table_start
            .checked_add(
                index
                    .checked_mul(self.offset_int_size)
                    .ok_or(PlistError::LengthTooLarge { len: index as u64 })?,
            )
            .ok_or(PlistError::LengthTooLarge { len: index as u64 })?;
        // 偏移表整块已校验过在文件内，所以这里可以直接切。
        let raw = &self.bytes[entry..entry + self.offset_int_size];
        let offset = read_be_uint(raw);
        let Ok(offset) = usize::try_from(offset) else {
            return Err(PlistError::ObjectOutOfRange {
                index,
                offset,
                start: MAGIC.len(),
                end: self.offset_table_start,
            });
        };
        if offset < MAGIC.len() || offset >= self.offset_table_start {
            return Err(PlistError::ObjectOutOfRange {
                index,
                offset: offset as u64,
                start: MAGIC.len(),
                end: self.offset_table_start,
            });
        }
        Ok((self.bytes[offset], offset + 1))
    }

    /// 读一个带长度语义的对象的元素个数，返回 `(个数, 个数之后的游标)`。
    ///
    /// marker 低 4 位不是 `0xF` 时个数就是它本身；是 `0xF` 时个数写在后随的一个
    /// 整数对象里（那个整数**不占**对象编号）。
    fn length_of(
        &self,
        marker: u8,
        cursor: usize,
        index: usize,
    ) -> Result<(usize, usize), PlistError> {
        let info = usize::from(marker & 0x0f);
        if info != 0x0f {
            return Ok((info, cursor));
        }

        let head = self.object_slice(cursor, 1, index)?;
        let int_marker = head[0];
        if int_marker & 0xf0 != 0x10 {
            return Err(PlistError::LengthNotInteger { marker: int_marker });
        }
        let exponent = int_marker & 0x0f;
        let width = 1usize << exponent;
        if !(1..=8).contains(&width) {
            return Err(PlistError::UnsupportedIntWidth { exponent });
        }
        let raw = self.object_slice(cursor + 1, width, index)?;
        let value = read_be_uint(raw);
        let count =
            usize::try_from(value).map_err(|_| PlistError::LengthTooLarge { len: value })?;
        Ok((count, cursor + 1 + width))
    }

    /// 读一个对象引用（大端，宽度由 trailer 的 `objectRefSize` 决定）。
    fn ref_at(&self, at: usize, index: usize) -> Result<usize, PlistError> {
        let raw = self.object_slice(at, self.object_ref_size, index)?;
        let value = read_be_uint(raw);
        usize::try_from(value).map_err(|_| PlistError::LengthTooLarge { len: value })
    }

    /// 把第 `index` 个对象当字符串读出来。
    fn string_at(&self, index: usize) -> Result<String, PlistError> {
        let (marker, body) = self.object_head(index)?;
        match marker & 0xf0 {
            0x50 => {
                let (len, start) = self.length_of(marker, body, index)?;
                if len > MAX_STRING_BYTES {
                    return Err(PlistError::StringTooLong { len });
                }
                let raw = self.object_slice(start, len, index)?;
                // 这一档按规范是 ASCII；真实文件里偶尔直接写 UTF-8。两种都接受，
                // 但必须是合法 UTF-8 —— 拿到什么算什么，不替换字符。
                String::from_utf8(raw.to_vec()).map_err(|_| PlistError::InvalidUtf8 { index })
            }
            0x60 => {
                let (len, start) = self.length_of(marker, body, index)?;
                if len > MAX_STRING_BYTES / 2 {
                    return Err(PlistError::StringTooLong { len });
                }
                let bytes = len
                    .checked_mul(2)
                    .ok_or(PlistError::LengthTooLarge { len: len as u64 })?;
                let raw = self.object_slice(start, bytes, index)?;
                decode_utf16be(raw).ok_or(PlistError::BadUtf16 { index })
            }
            other => Err(PlistError::NotString {
                marker: other,
                index,
            }),
        }
    }
}

/// 大端无符号整数。`bytes` 长度由调用方限制在 8 字节以内（宽度字段已校验）。
fn read_be_uint(bytes: &[u8]) -> u64 {
    let mut value = 0u64;
    for byte in bytes {
        value = (value << 8) | u64::from(*byte);
    }
    value
}

/// UTF-16BE 解码。字节数为奇数或含不成对代理项时返回 `None`。
fn decode_utf16be(bytes: &[u8]) -> Option<String> {
    if !bytes.len().is_multiple_of(2) {
        return None;
    }
    let units: Vec<u16> = bytes
        .chunks_exact(2)
        .map(|pair| u16::from_be_bytes([pair[0], pair[1]]))
        .collect();
    String::from_utf16(&units).ok()
}

/// XML plist（`<?xml ...`）分支：一次有界文本扫描，不建 DOM。
///
/// 只需要"`<key>CFBundleExecutable</key>` 后面第一个 `<string>`"这一段，所以不引
/// XML 库：这里对 DTD、命名空间、注释之外的任何结构都没有结论要下。
mod xml {
    use super::{PlistError, MAX_STRING_BYTES};

    const KEY_OPEN: &str = "<key>";
    const KEY_CLOSE: &str = "</key>";
    const STRING_OPEN: &str = "<string>";
    const STRING_CLOSE: &str = "</string>";

    /// 跳掉 BOM 与空白后，看起来是不是一份 XML plist。
    pub(super) fn looks_like_plist(bytes: &[u8]) -> bool {
        // UTF-16 的 BOM 说明它**想**是 XML plist：交给 XML 分支，让 decode 给出
        // "只解 UTF-8"这句明确的错误，而不是含糊的"认不出格式"。
        if bytes.starts_with(&[0xff, 0xfe]) || bytes.starts_with(&[0xfe, 0xff]) {
            return true;
        }
        let text = trimmed_start(strip_bom(bytes));
        text.starts_with(b"<?xml")
            || text.starts_with(b"<plist")
            || text.starts_with(b"<!DOCTYPE plist")
    }

    /// 从 XML plist 里取出 `CFBundleExecutable`。
    pub(super) fn bundle_executable(bytes: &[u8]) -> Result<Option<String>, PlistError> {
        let text = decode(bytes)?;
        let mut cursor = 0usize;
        while let Some(found) = text[cursor..].find(KEY_OPEN) {
            let open = cursor + found;
            let inner_start = open + KEY_OPEN.len();
            let Some(close) = text[inner_start..].find(KEY_CLOSE) else {
                return Err(PlistError::MalformedXml {
                    why: "`<key>` 没有对应的 `</key>`".to_string(),
                });
            };
            let inner_end = inner_start + close;
            let key = unescape(text[inner_start..inner_end].trim())?;
            let after_key = inner_end + KEY_CLOSE.len();
            if key == "CFBundleExecutable" {
                return string_after(text, after_key).map(Some);
            }
            cursor = after_key;
        }
        Ok(None)
    }

    /// 取 `from` 之后的第一个元素，要求它是 `<string>`。
    fn string_after(text: &str, from: usize) -> Result<String, PlistError> {
        let rest = &text[from..];
        let Some(open_rel) = rest.find('<') else {
            return Err(PlistError::MalformedXml {
                why: "`CFBundleExecutable` 后面没有值元素".to_string(),
            });
        };
        let open = from + open_rel;
        if !text[open..].starts_with(STRING_OPEN) {
            return Err(PlistError::XmlValueNotString {
                element: element_name(&text[open..]),
            });
        }
        let inner_start = open + STRING_OPEN.len();
        let Some(close) = text[inner_start..].find(STRING_CLOSE) else {
            return Err(PlistError::MalformedXml {
                why: "`<string>` 没有对应的 `</string>`".to_string(),
            });
        };
        let value = unescape(&text[inner_start..inner_start + close])?;
        if value.len() > MAX_STRING_BYTES {
            return Err(PlistError::StringTooLong { len: value.len() });
        }
        Ok(value)
    }

    /// `<name ...>` 里的 `name`，只为把报错说清楚。
    fn element_name(from: &str) -> String {
        let head = &from[1..];
        let end = head
            .find(|c: char| c.is_whitespace() || c == '>' || c == '/')
            .unwrap_or(head.len());
        head[..end].to_string()
    }

    /// UTF-8 解码。UTF-16 的 BOM 明确报错 —— 与其猜，不如说清读不了。
    fn decode(bytes: &[u8]) -> Result<&str, PlistError> {
        let bytes = strip_bom(bytes);
        if bytes.starts_with(&[0xff, 0xfe]) || bytes.starts_with(&[0xfe, 0xff]) {
            return Err(PlistError::MalformedXml {
                why: "XML plist 是 UTF-16（带 BOM），本读取器只解 UTF-8".to_string(),
            });
        }
        std::str::from_utf8(bytes).map_err(|_| PlistError::MalformedXml {
            why: "不是合法 UTF-8".to_string(),
        })
    }

    fn strip_bom(bytes: &[u8]) -> &[u8] {
        bytes.strip_prefix(&[0xef, 0xbb, 0xbf]).unwrap_or(bytes)
    }

    fn trimmed_start(bytes: &[u8]) -> &[u8] {
        let mut start = 0;
        while start < bytes.len() && bytes[start].is_ascii_whitespace() {
            start += 1;
        }
        &bytes[start..]
    }

    /// 解码 XML 实体：五个预定义实体 + 十进制/十六进制数字引用。
    ///
    /// 不认识的实体**原样保留**（比如 DOCTYPE 里自定义的那些）：宁可让名字里带着
    /// `&foo;` 这个字面量，也不要悄悄吞掉它 —— 后者会让"文件里写着什么"变得不可信。
    fn unescape(raw: &str) -> Result<String, PlistError> {
        let mut out = String::with_capacity(raw.len());
        let mut rest = raw;
        while let Some(position) = rest.find('&') {
            out.push_str(&rest[..position]);
            let tail = &rest[position..];
            let Some(semi) = tail.find(';') else {
                return Err(PlistError::MalformedXml {
                    why: "`&` 后面没有 `;`".to_string(),
                });
            };
            let entity = &tail[1..semi];
            match entity {
                "amp" => out.push('&'),
                "lt" => out.push('<'),
                "gt" => out.push('>'),
                "quot" => out.push('"'),
                "apos" => out.push('\''),
                _ if entity.starts_with("#x") || entity.starts_with("#X") => {
                    let code = u32::from_str_radix(&entity[2..], 16).map_err(|_| {
                        PlistError::MalformedXml {
                            why: "数字字符引用不是合法的十六进制".to_string(),
                        }
                    })?;
                    out.push(
                        char::from_u32(code).ok_or_else(|| PlistError::MalformedXml {
                            why: "数字字符引用不是合法的码点".to_string(),
                        })?,
                    );
                }
                _ if entity.starts_with('#') => {
                    let code =
                        entity[1..]
                            .parse::<u32>()
                            .map_err(|_| PlistError::MalformedXml {
                                why: "数字字符引用不是合法的十进制".to_string(),
                            })?;
                    out.push(
                        char::from_u32(code).ok_or_else(|| PlistError::MalformedXml {
                            why: "数字字符引用不是合法的码点".to_string(),
                        })?,
                    );
                }
                _ => out.push_str(&tail[..=semi]),
            }
            rest = &tail[semi + 1..];
        }
        out.push_str(rest);
        Ok(out)
    }
}

/// 测试用的 `bplist00` 拼装器。
///
/// 放在 `pub(crate)` 而不是 `mod tests` 里，是因为 `bundle` 的单元测试也要造
/// `Info.plist` 的字节 —— 两处各写一份拼装器，等于给"格式理解"留两个真相。
#[cfg(test)]
pub(crate) mod support {
    use super::{MAGIC, TRAILER_SIZE};

    /// 按格式规范拼一份 `bplist00`。
    ///
    /// 这是**照规范拼**，不是照解析代码拼（CLAUDE.md §6.11）：布局见模块文档，
    /// 偏移表放在对象之后、trailer 之前，`offsetIntSize = 4`、`objectRefSize = 1`。
    pub(crate) fn build(objects: &[Vec<u8>], top: usize) -> Vec<u8> {
        let mut out = MAGIC.to_vec();
        let mut offsets = Vec::with_capacity(objects.len());
        for object in objects {
            offsets.push(out.len());
            out.extend_from_slice(object);
        }
        let offset_table_offset = out.len();
        for offset in &offsets {
            out.extend_from_slice(&(*offset as u32).to_be_bytes());
        }
        // trailer：5 字节未用、sortVersion、offsetIntSize、objectRefSize、
        // numObjects、topObject、offsetTableOffset。
        out.extend_from_slice(&[0u8; 5]);
        out.push(0);
        out.push(4);
        out.push(1);
        out.extend_from_slice(&(objects.len() as u64).to_be_bytes());
        out.extend_from_slice(&(top as u64).to_be_bytes());
        out.extend_from_slice(&(offset_table_offset as u64).to_be_bytes());
        assert_eq!(
            out.len(),
            offset_table_offset + objects.len() * 4 + TRAILER_SIZE
        );
        out
    }

    /// ASCII 串对象（`0x5n`；n >= 15 时用 `0x5F` + 1 字节整数）。
    pub(crate) fn ascii(text: &str) -> Vec<u8> {
        let mut out = length_marker(0x50, text.len());
        out.extend_from_slice(text.as_bytes());
        out
    }

    /// UTF-16BE 串对象（`0x6n`，n 是**字符**数）。
    pub(crate) fn utf16(text: &str) -> Vec<u8> {
        let units: Vec<u16> = text.encode_utf16().collect();
        let mut out = length_marker(0x60, units.len());
        for unit in units {
            out.extend_from_slice(&unit.to_be_bytes());
        }
        out
    }

    /// 字典对象（`0xDn`）：先 n 个键引用、再 n 个值引用。
    pub(crate) fn dict(keys: &[u8], values: &[u8]) -> Vec<u8> {
        let count = keys.len();
        assert_eq!(count, values.len(), "字典的键与值必须一样多");
        let mut out = length_marker(0xd0, count);
        out.extend_from_slice(keys);
        out.extend_from_slice(values);
        out
    }

    /// 长度前缀：小于 15 直接写在低 4 位，否则 `xF` + 1 字节整数对象。
    fn length_marker(high: u8, len: usize) -> Vec<u8> {
        if len < 15 {
            vec![high | len as u8]
        } else {
            assert!(len <= 255, "测试里只用到 1 字节长度");
            vec![high | 0x0f, 0x10, len as u8]
        }
    }

    /// 一份最小可用的 Info.plist：`{CFBundleExecutable: <exec>}`。
    ///
    /// 对象顺序：0 = 顶层字典，1 = 键，2 = 值。所以字典的键引用是 1、值引用是 2。
    pub(crate) fn info_plist(exec: &str) -> Vec<u8> {
        build(
            &[dict(&[1], &[2]), ascii("CFBundleExecutable"), ascii(exec)],
            0,
        )
    }
}

#[cfg(test)]
mod tests {
    use super::support::{ascii, build, dict, info_plist, utf16};
    use super::*;

    #[test]
    fn ascii_executable_name_is_read_from_the_top_dictionary() {
        let bytes = info_plist("SideStore");
        assert_eq!(
            bundle_executable(&bytes).expect("应当解析成功"),
            Some("SideStore".to_string())
        );
    }

    #[test]
    fn a_long_ascii_key_and_value_use_the_extended_length_form() {
        // "CFBundleExecutable" 是 18 个字符，走 0x5F + 整数长度那一档。
        let exec = "LiveContainer_PleaseDoNotShortenTheExecutableName";
        let bytes = info_plist(exec);
        assert_eq!(
            bundle_executable(&bytes).expect("应当解析成功"),
            Some(exec.to_string())
        );
    }

    #[test]
    fn utf16_executable_names_are_decoded() {
        let bytes = build(
            &[
                dict(&[1], &[2]),
                ascii("CFBundleExecutable"),
                utf16("应用名"),
            ],
            0,
        );
        assert_eq!(
            bundle_executable(&bytes).expect("应当解析成功"),
            Some("应用名".to_string())
        );
    }

    #[test]
    fn a_dict_without_the_key_is_none_and_that_is_not_an_error() {
        let bytes = build(
            &[dict(&[1], &[2]), ascii("CFBundleIdentifier"), ascii("x")],
            0,
        );
        assert_eq!(bundle_executable(&bytes).expect("结构没问题"), None);
    }

    #[test]
    fn a_non_string_value_is_an_error_with_the_marker() {
        // 值是个 1 字节整数对象（0x10 0x01），不是字符串。
        let bytes = build(
            &[
                dict(&[1], &[2]),
                ascii("CFBundleExecutable"),
                vec![0x10, 0x01],
            ],
            0,
        );
        assert_eq!(
            bundle_executable(&bytes),
            Err(PlistError::ValueNotString { marker: 0x10 })
        );
    }

    #[test]
    fn a_non_dict_top_object_is_rejected() {
        let bytes = build(&[ascii("CFBundleExecutable")], 0);
        assert_eq!(
            bundle_executable(&bytes),
            Err(PlistError::TopNotDict { marker: 0x5f })
        );
    }

    #[test]
    fn neither_binary_nor_xml_is_reported_as_unknown_format() {
        // 两种都不是：必须明确报"认不出格式"，而不是返回 None（那会被当成"没有这个键"）。
        assert_eq!(
            bundle_executable(b"hello, this is not a plist"),
            Err(PlistError::UnknownFormat)
        );
        // 只有魔数、连 trailer 都没有的二进制 plist。
        assert_eq!(
            bundle_executable(b"bplist00"),
            Err(PlistError::TooShort { size: 8 })
        );
        // XML 形状但没有这个键：那是"读得通、没有"，与"认不出格式"是两码事。
        let xml = br#"<?xml version="1.0"?><plist><dict/></plist>"#;
        assert_eq!(bundle_executable(xml), Ok(None));
    }

    #[test]
    fn an_xml_plist_yields_the_executable_as_a_fact() {
        // 形状取自真实 IPA（LiveContainer）：DTD + 缩进 + 前面还有别的键。
        let xml = br#"<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
	<key>CFBundleIdentifier</key>
	<string>com.example.app</string>
	<key>CFBundleExecutable</key>
	<string>LiveContainer_PleaseDoNotShortenTheExecutableName</string>
</dict>
</plist>"#;
        assert_eq!(
            bundle_executable(xml).expect("XML plist 应当解析成功"),
            Some("LiveContainer_PleaseDoNotShortenTheExecutableName".to_string())
        );
    }

    #[test]
    fn xml_keys_are_matched_exactly_not_by_substring() {
        let xml = br#"<plist><dict>
            <key>CFBundleExecutableCopy</key><string>Nope</string>
            <key>CFBundleExecutable</key><string>Yes</string>
        </dict></plist>"#;
        assert_eq!(
            bundle_executable(xml).expect("应当解析成功"),
            Some("Yes".to_string())
        );
    }

    #[test]
    fn xml_entities_in_the_value_are_decoded() {
        // `&amp;` 是预定义实体，`&#65;` 与 `&#x42;` 是十进制/十六进制字符引用。
        let xml = br#"<plist><dict><key>CFBundleExecutable</key><string>A&amp;B&#65;&#x42;</string></dict></plist>"#;
        assert_eq!(
            bundle_executable(xml).expect("应当解析成功"),
            Some("A&BAB".to_string())
        );
    }

    #[test]
    fn an_xml_value_that_is_not_a_string_is_an_error() {
        let xml =
            br#"<plist><dict><key>CFBundleExecutable</key><integer>7</integer></dict></plist>"#;
        assert_eq!(
            bundle_executable(xml),
            Err(PlistError::XmlValueNotString {
                element: "integer".to_string()
            })
        );
    }

    #[test]
    fn an_unclosed_xml_key_is_an_error_not_a_silent_miss() {
        let xml = br#"<plist><dict><key>CFBundleExecutable<string>X</string></dict></plist>"#;
        assert!(matches!(
            bundle_executable(xml),
            Err(PlistError::MalformedXml { .. })
        ));
    }

    #[test]
    fn a_utf16_xml_plist_is_reported_rather_than_guessed() {
        let mut bytes = vec![0xff, 0xfe];
        bytes.extend_from_slice(&[b'<', 0, b'p', 0, b'l', 0, b'i', 0, b's', 0, b't', 0]);
        assert!(matches!(
            bundle_executable(&bytes),
            Err(PlistError::MalformedXml { .. })
        ));
    }

    #[test]
    fn an_offset_table_pointing_past_the_trailer_is_rejected() {
        let mut bytes = info_plist("SideStore");
        let len = bytes.len();
        // trailer 最后 8 字节是 offsetTableOffset：故意写得远超文件。
        bytes[len - 8..].copy_from_slice(&0xffff_ffffu64.to_be_bytes());
        assert!(matches!(
            bundle_executable(&bytes),
            Err(PlistError::OffsetTableOutOfRange { .. })
        ));
    }

    #[test]
    fn an_object_offset_pointing_into_the_trailer_is_rejected() {
        let mut bytes = info_plist("SideStore");
        let len = bytes.len();
        // 偏移表起点 = trailer 起点 - 表长；表长 = 对象数(3) * 4 = 12。
        let table_start = len - TRAILER_SIZE - 12;
        // 第 0 个对象（顶层字典）的偏移改成 trailer 里的位置。
        bytes[table_start..table_start + 4].copy_from_slice(&(len as u32 - 1).to_be_bytes());
        assert!(matches!(
            bundle_executable(&bytes),
            Err(PlistError::ObjectOutOfRange { index: 0, .. })
        ));
    }

    #[test]
    fn a_length_that_would_have_to_read_past_the_object_area_is_rejected() {
        // 值对象的个数写成 200（0x11 = 2 字节整数），而文件里没有 200 字节。
        let objects = vec![
            dict(&[1], &[2]),
            ascii("CFBundleExecutable"),
            vec![0x5f, 0x11, 0x00, 0xc8],
        ];
        let bytes = build(&objects, 0);
        let result = bundle_executable(&bytes);
        assert!(
            result.is_err(),
            "长度越过对象区必须报错，不能读进偏移表：{result:?}"
        );
    }

    #[test]
    fn every_prefix_of_a_valid_plist_is_rejected_without_panicking() {
        let bytes = info_plist("SideStore");
        for cut in 0..bytes.len() {
            // 只要求"不 panic、不越界"。截断的输入既可能报错，也可能仍然自洽 ——
            // 但绝不能让读取器崩掉（CLAUDE.md §7：拿不到就说拿不到，不是崩）。
            let _ = bundle_executable(&bytes[..cut]);
        }
    }

    #[test]
    fn mutated_bytes_never_panic() {
        let bytes = info_plist("SideStore");
        for index in 0..bytes.len() {
            for patch in [0x00u8, 0x0f, 0x7f, 0xff] {
                let mut mutated = bytes.clone();
                mutated[index] = patch;
                let _ = bundle_executable(&mutated);
            }
        }
    }
}
