//! 在目标里匹配签名。
//!
//! # 匹配过程
//!
//! 1. **索引**：按前缀开头 [`INDEX_BYTES`] 个确定字节建表。通配位置不能进键
//!    （它的取值在目标里是什么我们并不知道），所以只有"开头 4 个字节都没有
//!    被重定位改写"的签名能进索引 —— 生成期已经把剩下的丢掉了，并且记了账。
//! 2. **比对前缀**：确定字节必须逐位相同。
//! 3. **比对尾部 CRC**：有尾部窗口就要求它在目标里也对得上。
//! 4. 多个候选取确定字节最多的那个；**不同名字的候选同时命中时不给名字**，
//!    而是记成一次"无法区分"（[`MatchReport::ambiguous`]）。
//!
//! # 为什么第 4 步重要
//!
//! 生成期已经扔掉了"同名同形"之外的所有同形签名，但**不同形**的签名仍可能在
//! 某个具体目标上同时命中（目标里的字节恰好同时满足两套模式）。这时候给出其中
//! 一个名字，就等于把 50% 的错误率伪装成一次成功识别。宁可报"这里有两个可能"，
//! 让人知道要看一眼。

use std::collections::HashMap;

use crate::pattern::crc16_ccitt;
use crate::signature::{FunctionSignature, SignatureArch, SignatureSet};

/// 目标里的一个函数（配合签名去比对）。
#[derive(Debug, Clone, Copy)]
pub struct TargetFunction<'a> {
    /// 函数起始地址。
    pub addr: u64,
    /// 从起始地址开始的字节。
    ///
    /// 至少要覆盖签名前缀与尾部窗口；不够长的签名会被跳过（而不是当成匹配）。
    pub bytes: &'a [u8],
    /// 分析给出的函数大小（`None` = 未知）。
    pub size: Option<u64>,
}

/// 一次匹配。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Match {
    /// 地址。
    pub addr: u64,
    /// 匹配到的名字。
    pub name: String,
    /// 置信度（来自签名，见 [`FunctionSignature::confidence`]）。
    pub confidence: u8,
    /// 命中的签名里有多少确定字节（报告用）。
    pub exact_bytes: u16,
}

/// 一次"无法区分"的命中。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AmbiguousMatch {
    /// 地址。
    pub addr: u64,
    /// 同时命中的名字（升序去重）。
    pub names: Vec<String>,
}

/// 一次匹配的汇总。
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct MatchReport {
    /// 确定的匹配。
    pub matches: Vec<Match>,
    /// 无法区分的命中。
    pub ambiguous: Vec<AmbiguousMatch>,
    /// 比对了多少个函数。
    pub checked: u64,
    /// 因为"目标里可读字节不够验证签名"而跳过的次数（诚实计数，不是匹配）。
    pub skipped_short: u64,
    /// 因为"目标函数大小装不下这条签名"而被排除的候选条数。
    ///
    /// 与"证据不足"区分开：这是**明确不是**这个函数（例如 8 字节的桩函数里
    /// 不可能有 24 字节的前缀）。
    pub rejected_by_size: u64,
}

impl MatchReport {
    /// 可疑命中数（无法区分）。
    #[must_use]
    pub fn ambiguous_count(&self) -> usize {
        self.ambiguous.len()
    }
}

/// 匹配器：持有某个形态下签名的索引。
///
/// 借用签名集而不复制：一份从静态库生成的签名集可以有上万条，
/// 每换一个目标就复制一遍是没必要的开销。
pub struct Matcher<'a> {
    set: &'a SignatureSet,
    arch: SignatureArch,
    buckets: HashMap<u32, Vec<u32>>,
}

impl<'a> Matcher<'a> {
    /// 为某个形态建索引；其它形态的签名不参与匹配。
    ///
    /// 形态必须相等才建索引：同一个字节串在不同指令集下是完全不同的东西，
    /// 跨形态匹配没有任何依据。
    #[must_use]
    pub fn new(set: &'a SignatureSet, arch: &SignatureArch) -> Self {
        let mut buckets: HashMap<u32, Vec<u32>> = HashMap::new();
        for (index, signature) in set.signatures.iter().enumerate() {
            if signature.arch != *arch {
                continue;
            }
            if let Some(key) = index_key(&signature.prefix) {
                buckets.entry(key).or_default().push(index as u32);
            }
        }
        Self {
            set,
            arch: arch.clone(),
            buckets,
        }
    }

    /// 索引里的签名条数。
    #[must_use]
    pub fn indexed(&self) -> usize {
        self.buckets.values().map(Vec::len).sum()
    }

    /// 形态。
    #[must_use]
    pub fn arch(&self) -> &SignatureArch {
        &self.arch
    }

    /// 比对单个函数。
    #[must_use]
    pub fn match_at(&self, addr: u64, bytes: &[u8], size: Option<u64>) -> Option<Hit> {
        let mut ignored = 0u64;
        self.match_at_inner(addr, bytes, size, &mut ignored)
    }

    /// 比对单个函数，并累计"被大小排除掉"的候选条数。
    fn match_at_inner(
        &self,
        addr: u64,
        bytes: &[u8],
        size: Option<u64>,
        rejected_by_size: &mut u64,
    ) -> Option<Hit> {
        if bytes.len() < crate::generate::INDEX_BYTES {
            return None;
        }
        let key = u32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]);
        let candidates = self.buckets.get(&key)?;

        let mut best: Option<Match> = None;
        let mut names: Vec<String> = Vec::new();
        for index in candidates {
            let Some(signature) = self.set.signatures.get(*index as usize) else {
                continue;
            };
            if !fits_in(signature, size) {
                *rejected_by_size += 1;
                continue;
            }
            let Some(matched) = self.verify(signature, bytes, size) else {
                continue;
            };
            match &best {
                Some(current) if current.name == matched.name => {
                    if matched.exact_bytes > current.exact_bytes {
                        best = Some(matched);
                    }
                }
                Some(_) => names.push(matched.name),
                None => {
                    names.push(matched.name.clone());
                    best = Some(matched);
                }
            }
        }

        let best = best?;
        if !names.is_empty() && names.iter().any(|name| *name != best.name) {
            // 同一个地址上有两个不同的名字都说自己对：一个都不给。
            names.push(best.name);
            names.sort_unstable();
            names.dedup();
            return Some(Hit::Ambiguous(AmbiguousMatch { addr, names }));
        }
        Some(Hit::Match(Match {
            addr,
            name: best.name,
            confidence: best.confidence,
            exact_bytes: best.exact_bytes,
        }))
    }

    /// 前缀 + 尾部校验。
    ///
    /// `size` 是调用方知道的**目标函数大小**（`None` = 不知道）。它只用来做
    /// "物理上装不下"的排除：函数比模式覆盖的字节还短时，模式不可能整段落在它里面。
    /// 这类排除会单独计数（[`MatchReport::rejected_by_size`]），因为它是"明确不是"
    /// 而不是"看不出来"。
    ///
    /// 注意：目标字节不够验证尾部校验时这里返回 `None`（当作不匹配）——
    /// 调用方必须按 [`Matcher::longest_needed`] 提供字节，否则最长的那些签名会被
    /// 静默漏掉。批量入口 [`Matcher::match_all`] 会为这种情况单独计数。
    fn verify(
        &self,
        signature: &FunctionSignature,
        bytes: &[u8],
        size: Option<u64>,
    ) -> Option<Match> {
        if !fits_in(signature, size) {
            return None;
        }
        if !signature.prefix.matches(bytes) {
            return None;
        }
        if let Some(tail) = &signature.tail {
            let start = tail.offset as usize;
            let end = start.checked_add(tail.bytes as usize)?;
            let window = bytes.get(start..end)?;
            if crc16_ccitt(window) != tail.crc16 {
                return None;
            }
        }
        Some(Match {
            addr: 0,
            name: signature.name.clone(),
            confidence: signature.confidence(),
            exact_bytes: signature.exact_bytes,
        })
    }

    /// 批量比对。
    #[must_use]
    pub fn match_all(&self, targets: &[TargetFunction<'_>]) -> MatchReport {
        let mut report = MatchReport::default();
        for target in targets {
            report.checked += 1;
            let needed = self.longest_needed();
            if needed > 1 && (target.bytes.len() as u64) < needed {
                // 目标里能读到的字节不够验证：这**不是**"不匹配"，是"无法判断"。
                // 分开计数，免得报告里"未匹配"混进两件不同的事。
                report.skipped_short += 1;
            }
            match self.match_at_inner(
                target.addr,
                target.bytes,
                target.size,
                &mut report.rejected_by_size,
            ) {
                Some(Hit::Match(found)) => report.matches.push(found),
                Some(Hit::Ambiguous(found)) => report.ambiguous.push(found),
                None => {}
            }
        }
        report
    }

    /// 索引里最长的签名需要目标提供多少字节。
    ///
    /// 调用方据此决定"每个目标函数该读多少字节"：读少了会让最长的那些签名永远
    /// 验证不了（会被计入 [`MatchReport::skipped_short`]）。生成期已经把尾部校验
    /// 限制在 [`crate::generate::TAIL_MAX_EXTENT`] 之内，所以这个值有上界。
    #[must_use]
    pub fn longest_needed(&self) -> u64 {
        self.set
            .signatures
            .iter()
            .filter(|signature| signature.arch == self.arch)
            .map(|signature| {
                let tail_end = signature
                    .tail
                    .map_or(0, |tail| u64::from(tail.offset) + u64::from(tail.bytes));
                (signature.prefix.len() as u64).max(tail_end)
            })
            .max()
            .unwrap_or(0)
    }
}

/// 目标函数的字节数放得下这条签名要比对的所有字节吗？
///
/// 两件事都要成立：
///
/// * 前缀与尾部覆盖到的**最远字节**不能超出函数末尾 —— 超出的部分是**别的函数
///   或填充**，拿它比对等于把"邻近代码长得像"当成"这个函数就是它"；
/// * 签名自称的**精确长度**不能大于目标函数长度 —— 同一段代码在库里和链接后
///   长度一致，"库里的函数比目标里这个函数还长"说明它们不是同一个函数。
///
/// 这两条只在目标大小**已知**时才成立（`None` 时一律放过）。它们排除的是"物理上
/// 不可能"，而不是"证据不足"，所以单独计数。
#[must_use]
fn fits_in(signature: &FunctionSignature, size: Option<u64>) -> bool {
    let Some(size) = size else {
        return true;
    };
    let farthest = signature.tail.as_ref().map_or(0, |tail| {
        u64::from(tail.offset).saturating_add(u64::from(tail.bytes))
    });
    let coverage = (signature.prefix.len() as u64).max(farthest);
    if size < coverage {
        return false;
    }
    !(signature.length_exact && u64::from(signature.length) > size)
}

/// 一次比对的结果。
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Hit {
    /// 确定匹配。
    Match(Match),
    /// 无法区分（两个以上不同名字同时命中）。
    Ambiguous(AmbiguousMatch),
}

/// 前缀的索引键：开头 [`crate::generate::INDEX_BYTES`] 个字节。
///
/// 前缀开头必须全是确定字节，否则返回 `None`（不索引）。生成期已经保证了这一点，
/// 这里是第二道防线：签名文件可以被手工编辑，本函数不假设它守规矩。
#[must_use]
pub fn index_key(prefix: &crate::pattern::Pattern) -> Option<u32> {
    let bytes = prefix.bytes();
    if bytes.len() < crate::generate::INDEX_BYTES {
        return None;
    }
    let mut key = [0u8; 4];
    for (slot, byte) in key.iter_mut().zip(bytes.iter().take(4)) {
        match byte {
            crate::pattern::PatternByte::Exact(value) => *slot = *value,
            crate::pattern::PatternByte::Wildcard => return None,
        }
    }
    Some(u32::from_le_bytes(key))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::pattern::{Pattern, PatternByte};

    fn signature(name: &str, exact: &[u8], tail: Option<(u32, u16, u16)>) -> FunctionSignature {
        FunctionSignature {
            name: name.to_string(),
            arch: SignatureArch::new(64, "le", "test"),
            length: exact.len() as u32,
            length_exact: true,
            prefix: Pattern::exact(exact),
            tail: tail.map(|(offset, bytes, crc16)| crate::signature::TailCheck {
                offset,
                bytes,
                crc16,
            }),
            exact_bytes: exact.len() as u16,
        }
    }

    fn set(signatures: Vec<FunctionSignature>) -> SignatureSet {
        SignatureSet::new(signatures, crate::signature::GenerationStats::default())
    }

    fn arch() -> SignatureArch {
        SignatureArch::new(64, "le", "test")
    }

    #[test]
    fn an_exact_match_is_reported_with_its_name() {
        let set = set(vec![signature(
            "memcpy",
            &[0x55, 0x48, 0x89, 0xe5, 0x41],
            None,
        )]);
        let matcher = Matcher::new(&set, &arch());
        let hit = matcher.match_at(0x1000, &[0x55, 0x48, 0x89, 0xe5, 0x41], Some(5));
        assert_eq!(
            hit,
            Some(Hit::Match(Match {
                addr: 0x1000,
                name: "memcpy".to_string(),
                confidence: 75,
                exact_bytes: 5,
            }))
        );
    }

    #[test]
    fn a_single_differing_byte_kills_the_match() {
        let set = set(vec![signature(
            "memcpy",
            &[0x55, 0x48, 0x89, 0xe5, 0x41],
            None,
        )]);
        let matcher = Matcher::new(&set, &arch());
        assert!(matcher
            .match_at(0x1000, &[0x55, 0x48, 0x89, 0xe5, 0x42], None)
            .is_none());
    }

    #[test]
    fn a_wrong_tail_crc_kills_the_match() {
        let body = [0x55u8, 0x48, 0x89, 0xe5, 0x41, 0x90, 0x90, 0x90, 0xc3];
        let crc = crc16_ccitt(&body[4..]);
        let set = set(vec![signature("x", &body, Some((4, 5, crc)))]);
        let matcher = Matcher::new(&set, &arch());
        assert!(matcher.match_at(0, &body, None).is_some());

        let mut broken = body;
        broken[8] = 0x00;
        assert!(
            matcher.match_at(0, &broken, None).is_none(),
            "尾部 CRC 不对就不能算匹配"
        );
    }

    #[test]
    fn a_target_shorter_than_the_signature_never_matches() {
        let set = set(vec![signature(
            "long",
            &[0x55, 0x48, 0x89, 0xe5, 0x41, 0x42, 0x43, 0x44],
            None,
        )]);
        let matcher = Matcher::new(&set, &arch());
        // 前 4 个字节能建键，但整段装不下 —— 不算匹配。
        assert!(matcher
            .match_at(0, &[0x55, 0x48, 0x89, 0xe5], None)
            .is_none());
        // 分析说这个函数只有 4 字节，而模式要 8 字节：同样不算。
        assert!(matcher
            .match_at(
                0,
                &[0x55, 0x48, 0x89, 0xe5, 0x41, 0x42, 0x43, 0x44],
                Some(4)
            )
            .is_none());
    }

    #[test]
    fn two_names_hitting_the_same_bytes_are_reported_as_ambiguous() {
        // 生成期会丢掉同形签名，但**不同形**的两条仍可能同时命中一段具体字节：
        // 一条在某位是通配（"这里被重定位改写过，什么值都行"），另一条在那里写着具体值。
        // 两条的索引键必须相同，否则它们压根不会在同一个桶里相遇 —— 这正是真实情形：
        // 索引窗口内的通配会被生成期直接丢掉，能被混淆的通配都在窗口之后。
        let mut loose = signature("loose", &[0x55, 0x48, 0x89, 0xe5, 0x41], None);
        loose.prefix = Pattern::parse_hex("554889e54190?90c3").expect("模式");
        loose.exact_bytes = 8;
        let strict = signature(
            "strict",
            &[0x55, 0x48, 0x89, 0xe5, 0x41, 0x90, 0xaa, 0x90, 0xc3],
            None,
        );
        let set = set(vec![loose, strict]);
        let matcher = Matcher::new(&set, &arch());
        assert_eq!(
            matcher.indexed(),
            2,
            "两条都要进索引，否则这条测试没测到该测的"
        );
        let hit = matcher.match_at(
            0x2000,
            &[0x55, 0x48, 0x89, 0xe5, 0x41, 0x90, 0xaa, 0x90, 0xc3, 0x90],
            None,
        );
        match hit {
            Some(Hit::Ambiguous(ambiguous)) => {
                assert_eq!(ambiguous.names, vec!["loose", "strict"]);
            }
            other => panic!("应当报无法区分，实际 {other:?}"),
        }
    }

    #[test]
    fn signatures_for_another_arch_are_not_indexed() {
        let mut other = arch();
        other.family = "other".to_string();
        let mut signature = signature("elsewhere", &[0x55, 0x48, 0x89, 0xe5, 0x41], None);
        signature.arch = other;
        let set = set(vec![signature]);
        let matcher = Matcher::new(&set, &arch());
        assert_eq!(matcher.indexed(), 0);
        assert!(matcher
            .match_at(0, &[0x55, 0x48, 0x89, 0xe5, 0x41], None)
            .is_none());
    }

    #[test]
    fn a_wildcard_prefix_is_not_indexed_at_all() {
        let mut signature = signature("wild", &[0x55, 0x48, 0x89, 0xe5, 0x41], None);
        signature.prefix = Pattern::new(vec![
            PatternByte::Wildcard,
            PatternByte::Exact(0x48),
            PatternByte::Exact(0x89),
            PatternByte::Exact(0xe5),
            PatternByte::Exact(0x41),
        ]);
        let set = set(vec![signature]);
        let matcher = Matcher::new(&set, &arch());
        assert_eq!(matcher.indexed(), 0, "开头即通配的签名没有可用的索引键");
    }

    #[test]
    fn the_report_counts_what_it_could_not_verify() {
        let set = set(vec![signature(
            "long",
            &[0x55, 0x48, 0x89, 0xe5, 0x41, 0x42, 0x43, 0x44, 0x45, 0x46],
            None,
        )]);
        let matcher = Matcher::new(&set, &arch());
        let report = matcher.match_all(&[
            TargetFunction {
                addr: 0x10,
                bytes: &[0x55, 0x48],
                size: None,
            },
            TargetFunction {
                addr: 0x20,
                bytes: &[0x55, 0x48, 0x89, 0xe5, 0x41, 0x42, 0x43, 0x44, 0x45, 0x46],
                size: None,
            },
        ]);
        assert_eq!(report.checked, 2);
        assert_eq!(report.skipped_short, 1, "读不到足够字节的那次要单独计数");
        assert_eq!(report.matches.len(), 1);
        assert_eq!(report.matches[0].addr, 0x20);
    }
}
