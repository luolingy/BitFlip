//! 字节模式：确定字节 + 通配，以及用于校验的 CRC16。
//!
//! # 为什么要有"通配"
//!
//! 签名是从**静态库成员**（`.o`/`.obj`）里的函数字节生成的，却要拿去**已链接的
//! 目标**里匹配。两边的差别恰好是链接器改写过的那些字节 —— 也就是重定位覆盖的位置
//! （`call` 的相对位移、绝对地址槽位……）。这些位置的取值随链接结果而变，必须在模式里
//! 标成通配：不标就是"拿一个只在库里成立的字节串去目标里找"，找到的只能是巧合。
//!
//! # 文本形式
//!
//! 模式在文件里写成十六进制字符串，通配用 `?`：`554889e5e8????????`。
//! 这样签名文件肉眼可读、可 diff，出问题能直接看出来是哪一个字节被屏蔽了 ——
//! 二进制格式省下的那点体积换不来这个。

use std::fmt;

use serde::de::{Deserialize, Deserializer};
use serde::ser::{Serialize, Serializer};
use thiserror::Error;

/// 模式里的一个字节。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PatternByte {
    /// 必须逐位相同。
    Exact(u8),
    /// 链接期被改写的字节：任何取值都接受。
    Wildcard,
}

impl PatternByte {
    /// 是否接受该字节。
    #[must_use]
    pub const fn accepts(self, byte: u8) -> bool {
        match self {
            Self::Exact(expected) => expected == byte,
            Self::Wildcard => true,
        }
    }

    /// 文本形式：两位十六进制，或 `?`。
    #[must_use]
    pub fn to_hex(self) -> String {
        match self {
            Self::Exact(byte) => format!("{byte:02x}"),
            Self::Wildcard => "?".to_string(),
        }
    }
}

impl fmt::Display for PatternByte {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.to_hex())
    }
}

/// 模式解析失败。
#[derive(Debug, Error, PartialEq, Eq)]
pub enum PatternError {
    /// 文本长度为奇数。
    #[error("模式 {text:?} 的长度是奇数：每个字节要两位十六进制（通配写一个 ?）")]
    OddLength {
        /// 原始文本。
        text: String,
    },
    /// 出现了既不是十六进制、也不是 `?` 的字符。
    #[error("模式 {text:?} 里有非法字符 {ch:?}：只允许十六进制与 ?（通配）")]
    BadChar {
        /// 原始文本。
        text: String,
        /// 非法字符。
        ch: char,
    },
    /// 空模式。
    #[error("模式为空：没有任何字节可比对，这样的签名只会到处乱匹配")]
    Empty,
}

/// 一段字节模式。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Pattern {
    bytes: Vec<PatternByte>,
}

impl Pattern {
    /// 由字节序列构造。
    #[must_use]
    pub fn new(bytes: Vec<PatternByte>) -> Self {
        Self { bytes }
    }

    /// 由确定字节构造（无通配）。
    #[must_use]
    pub fn exact(bytes: &[u8]) -> Self {
        Self {
            bytes: bytes.iter().copied().map(PatternByte::Exact).collect(),
        }
    }

    /// 长度（字节数，含通配）。
    #[must_use]
    pub fn len(&self) -> usize {
        self.bytes.len()
    }

    /// 是否为空。
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.bytes.is_empty()
    }

    /// 逐个字节。
    #[must_use]
    pub fn bytes(&self) -> &[PatternByte] {
        &self.bytes
    }

    /// 确定字节的个数。
    #[must_use]
    pub fn exact_count(&self) -> usize {
        self.bytes
            .iter()
            .filter(|byte| matches!(byte, PatternByte::Exact(_)))
            .count()
    }

    /// 通配字节的个数。
    #[must_use]
    pub fn wildcard_count(&self) -> usize {
        self.len() - self.exact_count()
    }

    /// 开头连续确定字节的个数。
    ///
    /// 这是**能不能建索引**的前提：索引键只取确定字节（通配处目标里是什么值
    /// 我们并不知道，写进键就等于按一个未知值查表）。
    #[must_use]
    pub fn leading_exact(&self) -> usize {
        self.bytes
            .iter()
            .take_while(|byte| matches!(byte, PatternByte::Exact(_)))
            .count()
    }

    /// 目标字节是否满足本模式。
    ///
    /// 目标比模式短时返回 `false`：**长度不足不是"匹配"**。把它当成匹配会让
    /// 函数末尾那几条凑巧相同的字节变成一整片假名字。
    #[must_use]
    pub fn matches(&self, target: &[u8]) -> bool {
        if target.len() < self.len() {
            return false;
        }
        self.bytes
            .iter()
            .zip(target.iter())
            .all(|(pattern, byte)| pattern.accepts(*byte))
    }

    /// 文本形式（十六进制 + `?`）。
    #[must_use]
    pub fn to_hex(&self) -> String {
        let mut out = String::with_capacity(self.bytes.len() * 2);
        for byte in &self.bytes {
            out.push_str(&byte.to_hex());
        }
        out
    }

    /// 解析文本形式。
    pub fn parse_hex(text: &str) -> Result<Self, PatternError> {
        if text.is_empty() {
            return Err(PatternError::Empty);
        }
        let mut bytes = Vec::with_capacity(text.len() / 2);
        let chars: Vec<char> = text.chars().collect();
        let mut index = 0;
        while index < chars.len() {
            let ch = chars[index];
            if ch == '?' {
                bytes.push(PatternByte::Wildcard);
                index += 1;
                continue;
            }
            if !ch.is_ascii_hexdigit() {
                return Err(PatternError::BadChar {
                    text: text.to_string(),
                    ch,
                });
            }
            let Some(next) = chars.get(index + 1) else {
                return Err(PatternError::OddLength {
                    text: text.to_string(),
                });
            };
            if !next.is_ascii_hexdigit() {
                return Err(PatternError::BadChar {
                    text: text.to_string(),
                    ch: *next,
                });
            }
            let pair: String = [ch, *next].iter().collect();
            let byte = u8::from_str_radix(&pair, 16).map_err(|_| PatternError::BadChar {
                text: text.to_string(),
                ch,
            })?;
            bytes.push(PatternByte::Exact(byte));
            index += 2;
        }
        Ok(Self { bytes })
    }
}

impl fmt::Display for Pattern {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.to_hex())
    }
}

impl Serialize for Pattern {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(&self.to_hex())
    }
}

impl<'de> Deserialize<'de> for Pattern {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let text = String::deserialize(deserializer)?;
        Self::parse_hex(&text).map_err(serde::de::Error::custom)
    }
}

/// CRC-16/CCITT-FALSE（多项式 `0x1021`，初值 `0xFFFF`）。
///
/// 选它的理由只有一条：**它是有标准校验值的一种**（`"123456789"` → `0x29B1`），
/// 因此实现可以被一个外部常量钉住，而不是"我自己算一遍自己信"。
#[must_use]
pub fn crc16_ccitt(bytes: &[u8]) -> u16 {
    let mut crc: u16 = 0xFFFF;
    for byte in bytes {
        crc ^= u16::from(*byte) << 8;
        for _ in 0..8 {
            crc = if crc & 0x8000 != 0 {
                (crc << 1) ^ 0x1021
            } else {
                crc << 1
            };
        }
    }
    crc
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn crc16_matches_the_standard_check_value() {
        // CRC-16/CCITT-FALSE 的标准校验值，来自算法规范而不是本实现。
        assert_eq!(crc16_ccitt(b"123456789"), 0x29B1);
        assert_eq!(crc16_ccitt(b""), 0xFFFF);
    }

    #[test]
    fn a_pattern_round_trips_through_its_text_form() {
        let pattern = Pattern::new(vec![
            PatternByte::Exact(0x55),
            PatternByte::Exact(0x48),
            PatternByte::Wildcard,
            PatternByte::Exact(0xe5),
        ]);
        assert_eq!(pattern.to_hex(), "5548?e5");
        assert_eq!(Pattern::parse_hex("5548?e5").expect("解析"), pattern);
    }

    #[test]
    fn wildcards_accept_anything_but_exact_bytes_do_not() {
        let pattern = Pattern::parse_hex("5548?e5").expect("解析");
        assert!(pattern.matches(&[0x55, 0x48, 0xff, 0xe5]));
        assert!(!pattern.matches(&[0x55, 0x48, 0xff, 0xe4]));
        assert_eq!(pattern.exact_count(), 3);
        assert_eq!(pattern.leading_exact(), 2);
    }

    #[test]
    fn a_short_target_never_matches() {
        // 长度不足是"不知道"，不是"满足"。
        let pattern = Pattern::parse_hex("554889e5").expect("解析");
        assert!(!pattern.matches(&[0x55, 0x48, 0x89]));
        assert!(pattern.matches(&[0x55, 0x48, 0x89, 0xe5]));
    }

    #[test]
    fn malformed_patterns_are_refused_with_the_reason() {
        assert!(matches!(Pattern::parse_hex(""), Err(PatternError::Empty)));
        assert!(matches!(
            Pattern::parse_hex("554"),
            Err(PatternError::OddLength { .. })
        ));
        assert!(matches!(
            Pattern::parse_hex("55gg"),
            Err(PatternError::BadChar { ch: 'g', .. })
        ));
        // `?` 后面跟半个字节也是错：通配是按**字节**屏蔽的。
        assert!(matches!(
            Pattern::parse_hex("5?"),
            Err(PatternError::BadChar { .. })
        ));
    }

    #[test]
    fn an_all_wildcard_pattern_reports_no_exact_bytes() {
        let pattern = Pattern::parse_hex("????").expect("解析");
        assert_eq!(pattern.exact_count(), 0);
        assert_eq!(pattern.leading_exact(), 0);
        assert_eq!(pattern.wildcard_count(), 4);
    }
}
