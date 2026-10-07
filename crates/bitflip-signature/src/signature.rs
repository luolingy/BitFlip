//! 签名的数据模型与文件格式。
//!
//! 一个签名回答的问题是："**库里的这个函数**，在目标里长什么样？"
//! 因此它存三样东西：
//!
//! 1. [`FunctionSignature::prefix`]：函数开头若干字节的模式（通配 = 链接期被改写的位置）；
//! 2. [`FunctionSignature::tail`]：函数尾部一段**连续无通配**字节的 CRC16；
//! 3. [`FunctionSignature::name`]：匹配上之后要写的名字。
//!
//! # 为什么要有尾部 CRC
//!
//! 只靠开头 24 字节，短函数之间会互相混淆（编译器生成的小例程开头往往一模一样）。
//! 尾部 CRC 拿函数**另一端**的字节再确认一次：两处都撞上同一个签名的概率，比只撞
//! 一处低得多。这也是 FLIRT 的做法。
//!
//! # 生成期就要扔掉的
//!
//! 生成期做三道过滤，**并且每一道都记账**（[`GenerationStats`]）：
//! 确定字节太少、开头就是通配（建不了索引）、以及两条不同名字的签名长得一模一样
//! （匹配时无法区分）。宁可少给名字，也不给一个"有一半概率是别人"的名字 ——
//! 这正是本项目的立身之本。

use std::collections::BTreeMap;
use std::fmt;

use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::pattern::Pattern;

/// 签名文件格式版本。
///
/// 签名文件是**本地生成的派生物**（从用户自己机器上的静态库生成），所以版本不符
/// 时没有迁移路径：直接要求重新生成。这不是偷懒 —— 迁移一个"从别的库重新生成只要
/// 十秒"的文件，比写迁移代码更省事也更不容易错。
pub const SIGNATURE_FORMAT_VERSION: u32 = 1;

/// 生成签名时写进文件的工具名。
pub const SIGNATURE_TOOL: &str = concat!("bitflip ", env!("CARGO_PKG_VERSION"));

/// 签名适用的目标形态。
///
/// 刻意**不存架构枚举**：本层不解释架构、也不按架构分支，它只做相等比较。
/// 字节如何被解释（位宽、字节序、指令编码族）由调用方从 `ArchSpec` 折算进来，
/// 交给本层做"这份签名和这个目标是不是一路货"的判断。
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub struct SignatureArch {
    /// 指针宽度（位）。
    pub bits: u16,
    /// 字节序短名（`le` / `be`）。
    pub endian: String,
    /// 指令编码族的稳定短名，由调用方给出。
    pub family: String,
}

impl SignatureArch {
    /// 由目标形态折算。
    #[must_use]
    pub fn new(bits: u16, endian: impl Into<String>, family: impl Into<String>) -> Self {
        Self {
            bits,
            endian: endian.into(),
            family: family.into(),
        }
    }

    /// 指针宽度（字节）—— 决定绝对地址槽位的宽度。
    #[must_use]
    pub const fn pointer_size(&self) -> usize {
        (self.bits / 8) as usize
    }
}

impl fmt::Display for SignatureArch {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}/{}/{}", self.family, self.bits, self.endian)
    }
}

/// 尾部校验：函数尾部一段连续无通配字节的 CRC16。
///
/// `offset`/`bytes` 是相对**函数开头**的位置，不是节内位置 —— 匹配时目标是另一个
/// 文件，只有"从函数开头数第几个字节"这个说法在两边都成立。
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub struct TailCheck {
    /// 窗口起点（相对函数开头）。
    pub offset: u32,
    /// 窗口长度（字节）。
    pub bytes: u16,
    /// 窗口内字节的 CRC16。
    pub crc16: u16,
}

/// 一条函数签名。
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FunctionSignature {
    /// 匹配成功后要写的名字。
    pub name: String,
    /// 适用形态。
    pub arch: SignatureArch,
    /// 生成时这个函数有多少字节（尾部窗口按它定位）。
    pub length: u32,
    /// 开头字节模式。
    pub prefix: Pattern,
    /// 尾部校验；`None` = 没有可用的连续无通配窗口。
    pub tail: Option<TailCheck>,
    /// 前缀里的确定字节数（质量指标，也是置信度的依据）。
    pub exact_bytes: u16,
}

impl FunctionSignature {
    /// 匹配上之后写入的置信度（0–100）。
    ///
    /// 这是**同一来源内部的相对排序**，不是概率：证据越硬（确定字节多、尾部校验
    /// 通过）就越高。它不参与跨来源比较 —— 跨来源由 `SymbolSource` 的优先级决定。
    #[must_use]
    pub fn confidence(&self) -> u8 {
        match (self.exact_bytes, self.tail.is_some()) {
            (exact, true) if exact >= 16 => 95,
            (exact, true) if exact >= 10 => 88,
            (exact, _) if exact >= 16 => 85,
            _ => 75,
        }
    }
}

/// 一条签名被丢弃的原因。
///
/// **必须有这个枚举**：生成过程如果静默少给数据，用户看到"识别出 300 个函数"就
/// 无从判断这 300 是"库里只有 300 个能签名"还是"另外 5000 个被悄悄扔了"。
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum DropReason {
    /// 不是函数符号。
    NotAFunction,
    /// 未定义（外部）符号。
    Undefined,
    /// 没有名字。
    EmptyName,
    /// 不知道属于哪个节，或那个节不在节表里。
    NoSection,
    /// 不在可执行节里（数据里的"函数符号"多半是误标）。
    NotExecutable,
    /// 字节范围取不到（越界、被截断）。
    NoBytes,
    /// 太短，装不下一个有意义的前缀。
    TooShort,
    /// 确定字节太少。
    TooFewExact,
    /// 开头就是通配，建不了索引。
    PrefixWildcard,
    /// 与另一条不同名字的签名完全同形 —— 匹配时无法区分。
    Ambiguous,
    /// 与已有签名重复（同一函数出现在多个成员里）。
    Duplicate,
    /// 来自已链接映像：符号位置的约定无法可靠区分，整体不生成。
    NotRelocatable,
}

impl DropReason {
    /// 稳定的短名（写进报告与 JSON）。
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::NotAFunction => "not-a-function",
            Self::Undefined => "undefined",
            Self::EmptyName => "empty-name",
            Self::NoSection => "no-section",
            Self::NotExecutable => "not-executable",
            Self::NoBytes => "no-bytes",
            Self::TooShort => "too-short",
            Self::TooFewExact => "too-few-exact",
            Self::PrefixWildcard => "prefix-wildcard",
            Self::Ambiguous => "ambiguous",
            Self::Duplicate => "duplicate",
            Self::NotRelocatable => "not-relocatable",
        }
    }

    /// 面向界面的中文说明。
    #[must_use]
    pub const fn label_zh(self) -> &'static str {
        match self {
            Self::NotAFunction => "不是函数符号",
            Self::Undefined => "未定义符号",
            Self::EmptyName => "没有名字",
            Self::NoSection => "不知道属于哪个节",
            Self::NotExecutable => "不在可执行节里",
            Self::NoBytes => "取不到字节范围",
            Self::TooShort => "太短",
            Self::TooFewExact => "确定字节太少",
            Self::PrefixWildcard => "开头即通配，建不了索引",
            Self::Ambiguous => "与另一条同名无法区分",
            Self::Duplicate => "重复（同一函数在多个成员里）",
            Self::NotRelocatable => "来自已链接映像",
        }
    }
}

/// 生成过程的账。
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct GenerationStats {
    /// 扫描过的对象个数（归档成员按个数计）。
    pub objects: u64,
    /// 归档成员里内容未读全而被跳过的个数。
    pub truncated_members: u64,
    /// 归档里被跳过的元数据成员个数（符号索引、长名表 —— 不是对象）。
    pub metadata_members: u64,
    /// 解析失败的对象个数。
    pub unparsable_objects: u64,
    /// 见过的函数符号总数。
    pub functions_seen: u64,
    /// 最终写进文件的签名数。
    pub emitted: u64,
    /// 因为重定位类型不认识而按保守宽度屏蔽的函数数（诚实记账）。
    pub widened_wildcards: u64,
    /// 各丢弃原因的数量。
    pub dropped: BTreeMap<DropReason, u64>,
}

impl GenerationStats {
    /// 记一次丢弃。
    pub fn drop_one(&mut self, reason: DropReason) {
        self.drop_many(reason, 1);
    }

    /// 记一批丢弃（同一个原因一次计很多条时用）。
    pub fn drop_many(&mut self, reason: DropReason, count: u64) {
        *self.dropped.entry(reason).or_insert(0) += count;
    }

    /// 丢了多少条。
    #[must_use]
    pub fn dropped_total(&self) -> u64 {
        self.dropped.values().sum()
    }

    /// 面向界面的一行摘要。
    #[must_use]
    pub fn summary_zh(&self) -> String {
        let mut parts = vec![format!("对象 {} 个", self.objects)];
        parts.push(format!("函数符号 {} 个", self.functions_seen));
        parts.push(format!("产出签名 {} 条", self.emitted));
        if self.dropped_total() > 0 {
            let detail: Vec<String> = self
                .dropped
                .iter()
                .map(|(reason, count)| format!("{} {} 条", reason.label_zh(), count))
                .collect();
            parts.push(format!(
                "丢弃 {} 条（{}）",
                self.dropped_total(),
                detail.join("、")
            ));
        }
        if self.unparsable_objects > 0 {
            parts.push(format!("无法解析的对象 {} 个", self.unparsable_objects));
        }
        if self.truncated_members > 0 {
            parts.push(format!("内容未读全的成员 {} 个", self.truncated_members));
        }
        if self.metadata_members > 0 {
            parts.push(format!("跳过的元数据成员 {} 个", self.metadata_members));
        }
        if self.widened_wildcards > 0 {
            parts.push(format!(
                "其中 {} 条函数因重定位类型不认识而按更宽的窗口屏蔽",
                self.widened_wildcards
            ));
        }
        parts.join("；")
    }
}

/// 一份签名集。
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SignatureSet {
    /// 格式版本（见 [`SIGNATURE_FORMAT_VERSION`]）。
    pub format_version: u32,
    /// 生成者（工具 + 版本）。
    pub tool: String,
    /// 生成账（签名文件的来源说明）。
    pub stats: GenerationStats,
    /// 签名本体。
    pub signatures: Vec<FunctionSignature>,
}

/// 签名层的错误。
#[derive(Debug, Error)]
pub enum SignatureError {
    /// 版本不符。
    #[error(
        "签名文件版本 {found}，本程序只认 {expected}：请重新生成（签名是本地生成的派生物，没有迁移路径）"
    )]
    BadVersion {
        /// 文件里的版本。
        found: u32,
        /// 本程序支持的版本。
        expected: u32,
    },
    /// 解析失败。
    #[error("签名文件解析失败：{detail}")]
    Parse {
        /// 细节。
        detail: String,
    },
}

impl SignatureSet {
    /// 空集合。
    #[must_use]
    pub fn new(signatures: Vec<FunctionSignature>, stats: GenerationStats) -> Self {
        Self {
            format_version: SIGNATURE_FORMAT_VERSION,
            tool: SIGNATURE_TOOL.to_string(),
            stats,
            signatures,
        }
    }

    /// 签名条数。
    #[must_use]
    pub fn len(&self) -> usize {
        self.signatures.len()
    }

    /// 是否为空。
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.signatures.is_empty()
    }

    /// 涉及的形态（用于报告"这份签名服务哪些目标"）。
    #[must_use]
    pub fn arches(&self) -> Vec<SignatureArch> {
        let mut set: Vec<SignatureArch> = self
            .signatures
            .iter()
            .map(|signature| signature.arch.clone())
            .collect();
        set.sort();
        set.dedup();
        set
    }

    /// 序列化（`pretty` 供人阅读，紧凑供体积）。
    pub fn to_json(&self, pretty: bool) -> Result<String, SignatureError> {
        let result = if pretty {
            serde_json::to_string_pretty(self)
        } else {
            serde_json::to_string(self)
        };
        result.map_err(|error| SignatureError::Parse {
            detail: error.to_string(),
        })
    }

    /// 反序列化，并**校验格式版本**。
    pub fn from_json(text: &str) -> Result<Self, SignatureError> {
        let set: Self = serde_json::from_str(text).map_err(|error| SignatureError::Parse {
            detail: error.to_string(),
        })?;
        if set.format_version != SIGNATURE_FORMAT_VERSION {
            return Err(SignatureError::BadVersion {
                found: set.format_version,
                expected: SIGNATURE_FORMAT_VERSION,
            });
        }
        Ok(set)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::pattern::PatternByte;

    fn sample() -> SignatureSet {
        SignatureSet::new(
            vec![FunctionSignature {
                name: "memcpy".to_string(),
                arch: SignatureArch::new(64, "le", "test"),
                length: 32,
                prefix: Pattern::new(vec![
                    PatternByte::Exact(0x55),
                    PatternByte::Wildcard,
                    PatternByte::Exact(0xe5),
                ]),
                tail: Some(TailCheck {
                    offset: 24,
                    bytes: 8,
                    crc16: 0x1234,
                }),
                exact_bytes: 17,
            }],
            GenerationStats {
                emitted: 1,
                ..GenerationStats::default()
            },
        )
    }

    #[test]
    fn a_set_round_trips_through_json() {
        let set = sample();
        let text = set.to_json(true).expect("序列化");
        assert!(
            text.contains("\"format_version\": 1"),
            "版本要写在文件里：{text}"
        );
        let back = SignatureSet::from_json(&text).expect("反序列化");
        assert_eq!(back, set);
    }

    #[test]
    fn a_foreign_format_version_is_refused_with_the_numbers() {
        let mut set = sample();
        set.format_version = 99;
        let text = serde_json::to_string(&set).expect("序列化");
        match SignatureSet::from_json(&text) {
            Err(SignatureError::BadVersion { found, expected }) => {
                assert_eq!(found, 99);
                assert_eq!(expected, SIGNATURE_FORMAT_VERSION);
            }
            other => panic!("应当因版本不符而拒绝，实际 {other:?}"),
        }
    }

    #[test]
    fn confidence_rises_with_the_evidence() {
        let mut signature = sample().signatures[0].clone();
        signature.exact_bytes = 16;
        signature.tail = Some(TailCheck {
            offset: 0,
            bytes: 8,
            crc16: 0,
        });
        assert_eq!(signature.confidence(), 95);
        signature.tail = None;
        assert_eq!(signature.confidence(), 85);
        signature.exact_bytes = 8;
        assert_eq!(signature.confidence(), 75);
        signature.tail = Some(TailCheck {
            offset: 0,
            bytes: 8,
            crc16: 0,
        });
        assert_eq!(signature.confidence(), 75);
    }

    #[test]
    fn stats_report_every_drop_reason() {
        let mut stats = GenerationStats::default();
        stats.drop_one(DropReason::TooShort);
        stats.drop_one(DropReason::TooShort);
        stats.drop_one(DropReason::Ambiguous);
        stats.emitted = 3;
        assert_eq!(stats.dropped_total(), 3);
        let text = stats.summary_zh();
        assert!(text.contains("太短 2 条"), "{text}");
        assert!(text.contains("与另一条同名无法区分 1 条"), "{text}");
    }

    #[test]
    fn drop_reasons_have_stable_short_names() {
        assert_eq!(DropReason::TooFewExact.as_str(), "too-few-exact");
        assert_eq!(DropReason::Ambiguous.label_zh(), "与另一条同名无法区分");
        // 短名必须唯一且非空，否则报告里两个原因会看起来是同一个。
        let all = [
            DropReason::NotAFunction,
            DropReason::Undefined,
            DropReason::EmptyName,
            DropReason::NoSection,
            DropReason::NotExecutable,
            DropReason::NoBytes,
            DropReason::TooShort,
            DropReason::TooFewExact,
            DropReason::PrefixWildcard,
            DropReason::Ambiguous,
            DropReason::Duplicate,
            DropReason::NotRelocatable,
        ];
        let mut names: Vec<&str> = all.iter().map(|reason| reason.as_str()).collect();
        names.sort_unstable();
        names.dedup();
        assert_eq!(names.len(), all.len());
    }
}
