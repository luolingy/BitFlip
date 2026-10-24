//! 代码签名的**有界**解析与完整性校验（`LC_CODE_SIGNATURE` → SuperBlob → CodeDirectory）。
//!
//! 这里做两件可离线复现、结论确定的事：
//! 1. **完整性**：逐页重算文件哈希，与 CodeDirectory 里存的 code slot 比对，判断
//!    "文件内容是否自签名以来被改过"。改过 → 签名失效（哪怕只是一个字节）。
//! 2. **明文事实**：解出 entitlements（XML plist，`fade7171`）的键值，并记录
//!    requirements blob（type 2）的存在与大小。
//!
//! 这两件都与"这个签名是否可信"是两回事：
//!
//! **不做（明确边界，写进 `notes`）**：
//! - CMS / X.509 信任链校验（签名者证书是否被 Apple 信任）；
//! - 资源封印 `CodeResources` 校验；
//! - 需求（`Designated Requirement`）校验；
//! - CDHash 与系统策略比对。
//!
//! 一旦越界去"判可信"，就是把"我不知道"冒充成"我判过了"——那正是 §7 禁止的。
//!
//! # 规范（照结构规范，不反推）
//!
//! `LC_CODE_SIGNATURE`（`linkedit_data_command`）指向文件里的 **SuperBlob**：
//!
//! ```text
//! SuperBlob: magic=0xfade0cc0  length(u32)  count(u32)  count × BlobIndex{ type(u32), offset(u32) }
//! ```
//!
//! 里面 `type == 0`（`CSSLOT_CODEDIRECTORY`）的那条 → **CodeDirectory**：
//!
//! ```text
//! CodeDirectory: magic=0xfade0c02  length(u32)  version(u32)  flags(u32)
//!   hashOffset(u32)  identOffset(u32)  nSpecialSlots(u32)  nCodeSlots(u32)
//!   codeLimit(u32)  hashSize(u8)  hashType(u8)  platform(u8)  pageSizeLog(u8)  spare2(u32)  ...
//! ```
//!
//! code slot 的哈希数组从 `hashOffset` 起，每个 `hashSize` 字节；**special slot 在
//! `hashOffset` 之前**（负下标）。第 i 个 code page 的哈希在 `hashOffset + i*hashSize`，
//! 对应的文件内容是 `[i*pageSize, min((i+1)*pageSize, codeLimit))`。
//!
//! 实测核对（本机真实样本，非反推）：LiveContainer ad-hoc / SHA-256 / codeLimit 134928 /
//! 33 个 code slot 全部逐页一致；SideStore SHA-1 / codeLimit 19364128 / 4728 个 slot。

use bitflip_arch::Endian;

use super::LinkeditRange;
use crate::object::{
    CodeSignVerdict, CodeSignature, Entitlement, EntitlementValue, Entitlements, HashAlgorithm,
    Requirements,
};

/// SuperBlob 魔数（大端）。
const CSMAGIC_EMBEDDED_SIGNATURE: u32 = 0xfade_0cc0;
/// CodeDirectory 魔数（大端）。
const CSMAGIC_CODEDIRECTORY: u32 = 0xfade_0c02;
/// 内嵌 entitlements（XML plist）blob 魔数。
const CSMAGIC_EMBEDDED_ENTITLEMENTS: u32 = 0xfade_7171;
/// 内嵌 entitlements（DER 编码）blob 魔数：存在但不解。
const CSMAGIC_EMBEDDED_DER_ENTITLEMENTS: u32 = 0xfade_7172;
/// `CSSLOT_CODEDIRECTORY`（SuperBlob 里的 blob 类型）。
const CSSLOT_CODEDIRECTORY: u32 = 0;
/// `CSSLOT_SIGNATURESLOT`（CMS / X.509 签名槽；有它 = 非 ad-hoc）。
const CSSLOT_SIGNATURESLOT: u32 = 0x1000;
/// `CSSLOT_REQUIREMENTS`（需求 blob）。
const CSSLOT_REQUIREMENTS: u32 = 2;
/// `CSSLOT_ENTITLEMENTS`（entitlements blob）。
const CSSLOT_ENTITLEMENTS: u32 = 5;
/// CodeDirectory 头部到 `pageSizeLog` 为止的固定长度（含 spare2 前）。
const CD_FIXED_LEN: usize = 44;

/// 大端读 u32（代码签名结构全部大端，与 Mach-O 头本身的端序无关）。
fn be_u32(bytes: &[u8], at: usize) -> Option<u32> {
    let slice = bytes.get(at..at + 4)?;
    Some(u32::from_be_bytes([slice[0], slice[1], slice[2], slice[3]]))
}

/// 从 `bytes[base..]` 起读一个 C 串。
fn cstring_at(bytes: &[u8], at: usize) -> Option<String> {
    let rest = bytes.get(at..)?;
    let nul = rest.iter().position(|&b| b == 0)?;
    let text = &rest[..nul];
    // identifier 是 ASCII（反向域名 / 可执行名）；非 ASCII 就放弃，别塞乱码。
    if !text.is_ascii() {
        return None;
    }
    Some(String::from_utf8_lossy(text).into_owned())
}

/// 解析并校验一段代码签名数据。
///
/// `bytes` 是整个（薄）Mach-O 的字节；`range` 是 `LC_CODE_SIGNATURE` 在文件里的范围。
/// 结构读不出来时返回 `Malformed` 的 `CodeSignature`（**不 panic**：坏输入是常态）。
pub(super) fn parse(bytes: &[u8], range: LinkeditRange, endian: Endian) -> CodeSignature {
    // 代码签名结构**始终是大端**，与 `endian` 无关；`endian` 参数留作对照与注释用。
    let _ = endian;
    let mut signature = CodeSignature {
        algorithm: HashAlgorithm::Sha256, // 占位，下面覆盖；解析失败时无意义
        identifier: String::new(),
        code_limit: 0,
        page_size: 0,
        code_slots: 0,
        verified_slots: 0,
        first_mismatch: None,
        has_cms_signature: false,
        entitlements: None,
        cd_hash: None,
        requirements: Requirements::default(),
        verdict: CodeSignVerdict::Malformed,
        notes: Vec::new(),
    };

    let start = match usize::try_from(range.dataoff) {
        Ok(value) => value,
        Err(_) => {
            signature
                .notes
                .push("LC_CODE_SIGNATURE 的 dataoff 超出 usize".to_string());
            return signature;
        }
    };
    let blob = match bytes.get(start..) {
        Some(slice) => slice,
        None => {
            signature.notes.push(format!(
                "LC_CODE_SIGNATURE 的 dataoff（{start}）落在文件之外"
            ));
            return signature;
        }
    };

    // ── SuperBlob 头 ──
    let Some(magic) = be_u32(blob, 0) else {
        signature
            .notes
            .push("签名区太短，读不出 SuperBlob 头".to_string());
        return signature;
    };
    if magic != CSMAGIC_EMBEDDED_SIGNATURE {
        signature.notes.push(format!(
            "SuperBlob 魔数不对：期望 0x{CSMAGIC_EMBEDDED_SIGNATURE:08x}，读到 0x{magic:08x}（不是内嵌签名）"
        ));
        return signature;
    }
    let Some(count) = be_u32(blob, 8) else {
        signature.notes.push("SuperBlob 读不出 blob 数".to_string());
        return signature;
    };
    // 上限：防止损坏的 count 让循环跑飞。真实样本 ≤ 数十。
    if count > 1024 {
        signature.notes.push(format!(
            "SuperBlob 声称有 {count} 个 blob，超出合理上限，拒绝解析"
        ));
        return signature;
    }

    // ── 遍历 BlobIndex，找 CodeDirectory、entitlements、requirements、CMS 槽 ──
    let mut code_directory_offset: Option<usize> = None;
    let mut entitlements_offset: Option<usize> = None;
    for index in 0..count as usize {
        let entry = 12 + index * 8;
        let (Some(blob_type), Some(blob_off)) = (be_u32(blob, entry), be_u32(blob, entry + 4))
        else {
            signature
                .notes
                .push(format!("第 {index} 个 blob 索引读不出，跳过"));
            continue;
        };
        if blob_type == CSSLOT_CODEDIRECTORY {
            code_directory_offset = Some(blob_off as usize);
        } else if blob_type == CSSLOT_SIGNATURESLOT {
            signature.has_cms_signature = true;
        } else if blob_type == CSSLOT_ENTITLEMENTS {
            entitlements_offset = Some(blob_off as usize);
        } else if blob_type == CSSLOT_REQUIREMENTS {
            // 需求 blob 只报存在与字节数，不实现表达式求值。
            signature.requirements.present = true;
            if let Some(length) = be_u32(blob, blob_off as usize + 4) {
                signature.requirements.size = u64::from(length);
            }
        }
    }

    // entitlements：解 XML plist；同时探测 DER 形态是否也在这块数据里。
    if let Some(offset) = entitlements_offset {
        signature.entitlements = parse_entitlements(blob, offset);
    }

    let Some(cd_offset) = code_directory_offset else {
        signature
            .notes
            .push("SuperBlob 里没有 CodeDirectory（type 0）槽".to_string());
        return signature;
    };

    // ── CodeDirectory 头 ──
    let Some(cd) = blob.get(cd_offset..) else {
        signature
            .notes
            .push("CodeDirectory 偏移落在签名区之外".to_string());
        return signature;
    };
    let Some(cd_magic) = be_u32(cd, 0) else {
        signature.notes.push("CodeDirectory 太短".to_string());
        return signature;
    };
    if cd_magic != CSMAGIC_CODEDIRECTORY {
        signature.notes.push(format!(
            "CodeDirectory 魔数不对：期望 0x{CSMAGIC_CODEDIRECTORY:08x}，读到 0x{cd_magic:08x}"
        ));
        return signature;
    }
    if cd.len() < CD_FIXED_LEN {
        signature
            .notes
            .push(format!("CodeDirectory 头部不足 {CD_FIXED_LEN} 字节"));
        return signature;
    }

    let read_u32 = |at: usize| be_u32(cd, at);
    let (Some(hash_offset), Some(ident_offset), Some(_n_special), Some(n_code)) =
        (read_u32(16), read_u32(20), read_u32(24), read_u32(28))
    else {
        signature
            .notes
            .push("CodeDirectory 关键字段读不出".to_string());
        return signature;
    };
    let Some(code_limit) = read_u32(32) else {
        signature
            .notes
            .push("CodeDirectory 读不出 codeLimit".to_string());
        return signature;
    };
    let hash_size = cd[36];
    let hash_type = cd[37];
    let page_size_log = cd[39];

    signature.identifier = cstring_at(cd, ident_offset as usize).unwrap_or_default();
    signature.code_limit = u64::from(code_limit);
    signature.code_slots = u64::from(n_code);
    signature.page_size = if page_size_log == 0 {
        0
    } else {
        1u64 << page_size_log
    };

    let Some(algorithm) = HashAlgorithm::from_hash_type(hash_type) else {
        signature.notes.push(format!(
            "未知的 hashType={hash_type}，本模块不校验（不猜算法，也不编造结论）"
        ));
        signature.verdict = CodeSignVerdict::UnsupportedAlgorithm;
        return signature;
    };
    signature.algorithm = algorithm;

    // CDHash：CodeDirectory 整个 blob（从魔数到它自己的 length）按同一 hashType 再哈希，
    // 是这份签名结构的"指纹"（与 CodeDirectory 是否覆盖文件内容是两回事）。
    // 只对本文能算的算法（SHA-1 / SHA-256）给出；截断态按规范截断；SHA-384 不算（不猜）。
    if let Some(cd_length) = be_u32(cd, 4) {
        let cd_length = cd_length as usize;
        if let Some(cd_blob) = cd.get(0..cd_length) {
            signature.cd_hash = code_directory_hash(algorithm, cd_blob);
        }
    }

    if page_size_log == 0 || signature.page_size == 0 {
        signature
            .notes
            .push("pageSizeLog=0（无分页 / 整文件一个哈希），本模块暂不支持".to_string());
        signature.verdict = CodeSignVerdict::UnsupportedAlgorithm;
        return signature;
    }

    // ad-hoc vs 正式签名：先定性（CMS 槽有无），完整性结论稍后可能覆盖为 Intact/Mismatch。
    let base_verdict = if signature.has_cms_signature {
        CodeSignVerdict::Intact // 保守占位，下面用真实校验结果覆盖
    } else {
        CodeSignVerdict::AdHoc
    };

    if !algorithm.is_verifiable() {
        signature.notes.push(format!(
            "算法 {} 本模块没接（只校 SHA-1 / SHA-256）；只看结构，不判完整性",
            algorithm.name()
        ));
        signature.verdict = CodeSignVerdict::UnsupportedAlgorithm;
        return signature;
    }

    // ── 有界完整性校验：逐 code page 重算哈希、比对 code slot ──
    let slots = n_code as usize;
    let slot_stride = hash_size as usize;
    let page = signature.page_size as usize;
    let limit = code_limit as usize;
    if page == 0 || slot_stride == 0 {
        signature
            .notes
            .push("pageSize 或 hashSize 为 0，无法校验".to_string());
        signature.verdict = CodeSignVerdict::UnsupportedAlgorithm;
        return signature;
    }

    let mut verified = 0u64;
    let mut first_mismatch = None;
    let mut out_of_range = false;
    for slot in 0..slots {
        let offset_in_cd = hash_offset as usize + slot * slot_stride;
        let Some(stored) = cd.get(offset_in_cd..offset_in_cd + slot_stride) else {
            out_of_range = true;
            break;
        };
        let content_start = slot * page;
        if content_start >= limit {
            // 超出 codeLimit 的 slot（尾部可能空挂）：不再算内容，停止。
            break;
        }
        let content_end = (content_start + page).min(limit);
        let Some(chunk) = bytes.get(content_start..content_end) else {
            out_of_range = true;
            break;
        };
        let digest = match algorithm {
            HashAlgorithm::Sha1 => crate::format::macho::codesign::sha1_digest(chunk),
            HashAlgorithm::Sha256 => sha256_digest(chunk),
            _ => unreachable!("上面已挡掉不可校验算法"),
        };
        let Some(digest) = digest else {
            signature
                .notes
                .push("哈希实现内部错误（应不可达）".to_string());
            break;
        };
        if digest.as_slice() == stored {
            verified += 1;
        } else if first_mismatch.is_none() {
            first_mismatch = Some(slot as u64);
        }
    }

    if out_of_range {
        signature.notes.push(format!(
            "CodeDirectory 的哈希数组越界（hashOffset={hash_offset} nCodeSlots={n_code} hashSize={hash_size}）"
        ));
        signature.verdict = CodeSignVerdict::Malformed;
        return signature;
    }

    signature.verified_slots = verified;
    signature.first_mismatch = first_mismatch;

    if let Some(slot) = first_mismatch {
        signature.verdict = CodeSignVerdict::Mismatch;
        signature.notes.push(format!(
            "第 {slot} 页起哈希与签名里存的不一致：文件内容自签名以来被改过，签名已失效"
        ));
    } else {
        // 全部一致：区分 ad-hoc 与正式签名（结论都是"完整性通过"）。
        signature.verdict = base_verdict;
        if signature.has_cms_signature {
            signature.notes.push(format!(
                "全部 {} 个 code page 哈希一致（完整性通过）；带 CMS 签名槽",
                verified
            ));
        } else {
            signature.notes.push(format!(
                "全部 {} 个 code page 哈希一致（完整性通过）；**ad-hoc 签名**（无 CMS/证书）",
                verified
            ));
        }
    }
    signature.notes.push(
        "只校验了完整性（逐页哈希）；**未校**信任链（CMS/X.509）、资源封印与需求校验".to_string(),
    );
    signature
}

/// 解析 entitlements blob（`blob[offset..]`）里的 XML plist。
///
/// `blob` 是整个签名区；`offset` 是 entitlements blob 在其中的偏移。blob 头是
/// magic(`fade7171`) + 长度（均为大端 u32），XML 从第 8 字节起。
///
/// 只解标量（bool/string）与字符串数组；其它形态标 `Other`。解不出来返回 `None`
/// 并把原因写给调用方（§7：不编造）。同时探测这块数据里是否还有 DER 形态
/// （`fade7172`）——它不解，只置 `has_der_form`。
fn parse_entitlements(blob: &[u8], offset: usize) -> Option<Entitlements> {
    let header = blob.get(offset..)?;
    let magic = be_u32(header, 0)?;
    if magic != CSMAGIC_EMBEDDED_ENTITLEMENTS {
        // 不是 XML entitlements（可能是别的类型或损坏），如实返回 None。
        return Some(Entitlements {
            list: Vec::new(),
            has_der_form: magic == CSMAGIC_EMBEDDED_DER_ENTITLEMENTS,
        });
    }
    let length = be_u32(header, 4)? as usize;
    // blob 头 8 字节 + 载荷；载荷边界至少 8，且不超过这块数据。
    if length < 8 {
        return Some(Entitlements::default());
    }
    let body = header.get(8..length.min(header.len()))?;
    let xml = std::str::from_utf8(body).ok()?;

    let list = parse_plist_dict(xml);
    // DER 形态：整块签名区里可能存在一个 `fade7172` 头（通常紧跟 XML blob）。
    let has_der_form = find_der_entitlements(blob);
    Some(Entitlements { list, has_der_form })
}

/// 在一块数据里扫 `fade7172`（DER entitlements 魔数）头。
fn find_der_entitlements(blob: &[u8]) -> bool {
    let needle = CSMAGIC_EMBEDDED_DER_ENTITLEMENTS.to_be_bytes();
    blob.windows(4).any(|window| window == needle)
}

/// 从一段 XML plist 的字符串里，按 `<key>…</key>` + 随后的值元素，抽成键值列表。
///
/// **刻意轻量**：不引入 plist 依赖，只认最常见形态。规则：
/// - `<key>NAME</key>` 后面紧跟一个值元素，构成一条；
/// - 值元素：`<true/>`/`<false/>`→`Bool`；`<string>V</string>`→`String`；
///   `<array>` 里的连续 `<string>`→`Strings`；其它（`<dict>`/`<data>`/`<integer>`…）→`Other(标签名)`。
///
/// 这不是通用 XML 解析器：只对标准 `plutil -convert xml1` 风格的 entitlements 成立。
/// 解不出的条目一律标 `Other`，不猜。
fn parse_plist_dict(xml: &str) -> Vec<Entitlement> {
    let mut out = Vec::new();
    let mut rest = xml;

    while let Some(key_open) = rest.find("<key>") {
        let after_open = &rest[key_open + 5..];
        let Some(key_close) = after_open.find("</key>") else {
            break;
        };
        let key = decode_entities(after_open[..key_close].trim());
        let after_key = &after_open[key_close + 6..];
        let trimmed = after_key.trim_start();

        let (value, consumed_len) = parse_value(trimmed);
        out.push(Entitlement { key, value });

        // 跳过本条的键 + 值，继续找下一条 key。
        // 用值元素的结束位置推进（consumed_len 是相对 trimmed 的字节数）。
        let skip = (after_key.len() - trimmed.len()) + consumed_len;
        if skip == 0 || skip > after_key.len() {
            break;
        }
        rest = &after_key[skip..];
    }
    out
}

/// 从 `s`（已 trim_start，以某个值元素开头）解析一个值，返回 `(值, 消耗字节数)`。
fn parse_value(s: &str) -> (EntitlementValue, usize) {
    if let Some(after) = s.strip_prefix("<true/>") {
        return (EntitlementValue::Bool(true), s.len() - after.len());
    }
    if let Some(after) = s.strip_prefix("<false/>") {
        return (EntitlementValue::Bool(false), s.len() - after.len());
    }
    if let Some(rest) = s.strip_prefix("<string>") {
        if let Some(close) = rest.find("</string>") {
            let value = decode_entities(rest[..close].trim());
            return (
                EntitlementValue::String(value),
                "<string>".len() + close + "</string>".len(),
            );
        }
    }
    if s.starts_with("<array>") {
        let array_close = s.find("</array>");
        let end = array_close.map_or(s.len(), |close| close + "</array>".len());
        let block = &s[..end];
        let mut items = Vec::new();
        let mut cursor = block;
        while let Some(open) = cursor.find("<string>") {
            let after = &cursor[open + "<string>".len()..];
            let Some(close) = after.find("</string>") else {
                break;
            };
            items.push(decode_entities(after[..close].trim()));
            cursor = &after[close + "</string>".len()..];
        }
        return (EntitlementValue::Strings(items), end);
    }
    // 其它形态：抓标签名，标 Other，消耗到整个元素的匹配结束（用宽松的定位）。
    let tag = s
        .strip_prefix('<')
        .and_then(|t| {
            t.split(|c: char| c == '>' || c.is_whitespace() || c == '/')
                .next()
        })
        .unwrap_or("")
        .to_string();
    // 尝试推进到该标签的闭合（或自闭合）。
    let consumed = tag_end(s, &tag);
    (EntitlementValue::Other(tag), consumed)
}

/// 尽力估算一个非白名单元素在 `s` 里占的字节数：成对 `<x>…</x>` 到 `</x>`；否则到第一个 `>`。
fn tag_end(s: &str, tag: &str) -> usize {
    if tag.is_empty() {
        return s.len();
    }
    let close = format!("</{tag}>");
    if let Some(pos) = s.find(&close) {
        return pos + close.len();
    }
    // 没成对闭合：推进到第一个 `>` 之后（自闭合或空元素）。
    if let Some(gt) = s.find('>') {
        return gt + 1;
    }
    s.len()
}

/// 解 XML 里最常见的几个实体（entitlements 值里偶见 `&amp;` 等）。
fn decode_entities(text: &str) -> String {
    text.replace("&lt;", "<")
        .replace("&gt;", ">")
        .replace("&quot;", "\"")
        .replace("&apos;", "'")
        .replace("&amp;", "&")
}

/// SHA-1 摘要（20 字节）。
fn sha1_digest(data: &[u8]) -> Option<Vec<u8>> {
    use sha1::{Digest, Sha1};
    Some(Sha1::digest(data).to_vec())
}
/// SHA-256 摘要（32 字节）。
fn sha256_digest(data: &[u8]) -> Option<Vec<u8>> {
    use sha2::{Digest, Sha256};
    Some(Sha256::digest(data).to_vec())
}

/// CodeDirectory 的 CDHash：对整段 CodeDirectory blob 按 `algorithm` 再哈希，转小写十六进制。
///
/// 这是签名结构的"指纹"（常见于 `codesign -d` 输出）。与"内容是否被改"是两回事：
/// CDHash 只标识"这份 CodeDirectory 长什么样"。SHA-1 / SHA-256 / SHA-256 截断可算；
/// SHA-384 本模块没接哈希实现，返回 `None`（不猜）。
fn code_directory_hash(algorithm: HashAlgorithm, cd_blob: &[u8]) -> Option<String> {
    let digest = match algorithm {
        HashAlgorithm::Sha1 => sha1_digest(cd_blob)?,
        HashAlgorithm::Sha256 => sha256_digest(cd_blob)?,
        // 截断态 = SHA-256 前 20 字节（规范如此）。
        HashAlgorithm::Sha256Truncated => sha256_digest(cd_blob)?[..20].to_vec(),
        // SHA-384 本模块没有哈希实现，不编造。
        HashAlgorithm::Sha384 => return None,
    };
    Some(digest.iter().map(|b| format!("{b:02x}")).collect())
}

// ───────────────────────── 重签（A 阶段：纯函数，不写盘） ─────────────────────────
//
// 只做"算对"：给定内容与旧 CodeDirectory 参数，产出新的 CodeDirectory 字节，并把各 blob
// 拼回 SuperBlob。**不写盘、不接证书、不产生 CMS**（ad-hoc 路径）。设计见
// `docs/MACHO-RESIGN-DESIGN.md` §8 第 1-2 步。
//
// 边界（§7）：算不出（未知 hashType / pageSizeLog=0 / 内容比 codeLimit 短 / 空内容）就返回
// 明确的错误，绝不猜一个"看起来能过"的东西。

/// 重签参数：从旧 CodeDirectory 抄来的、决定新签名的那些值（沿用旧值最稳）。
#[derive(Debug, Clone)]
pub struct ResignParams {
    /// `hashType`：1=SHA-1、2=SHA-256、3=SHA-256 截断（本模块支持这三种）。
    pub hash_type: u8,
    /// `pageSizeLog`（如 12 表示 4096 字节一页）。
    pub page_size_log: u8,
    /// `codeLimit`：被签名内容的字节数（签名区从这之后开始）。
    pub code_limit: u32,
    /// `identifier`（如 `com.example.app`）。
    pub identifier: String,
    /// 可选：要一并写入 `CSSLOT_ENTITLEMENTS` 槽的 entitlements **blob 原始字节**
    /// （`fade7171`+len+XML）。给了就把它整块嵌入，并把它按 hashType 的哈希放进 special slot 5。
    pub entitlements_blob: Option<Vec<u8>>,
}

/// 重签构造过程中的错误（都带人话原因，调用方直接转成 notes 即可）。
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ResignError {
    /// 未知 / 不支持的 `hashType`。
    UnsupportedHashType(u8),
    /// 不支持的 `hashType`（内部用；`from_hash_type` 判不出时）。
    ZeroPageSizeLog,
    /// 空内容（`codeLimit == 0` 或内容为空）。
    EmptyContent,
    /// 内容比 `codeLimit` 短（不能对不存在的字节签名）。
    ContentShorterThanLimit { have: usize, need: u32 },
}

impl std::fmt::Display for ResignError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::UnsupportedHashType(t) => write!(
                f,
                "不支持的 hashType={t}（本模块只算 SHA-1=1 / SHA-256=2 / SHA-256 截断=3）"
            ),
            Self::ZeroPageSizeLog => write!(f, "pageSizeLog=0（无分页 / 整文件一个哈希），不支持"),
            Self::EmptyContent => write!(f, "内容为空（codeLimit=0 或没有字节），无法重签"),
            Self::ContentShorterThanLimit { have, need } => write!(
                f,
                "内容只有 {have} 字节，比 codeLimit={need} 短，不能对不存在的字节签名"
            ),
        }
    }
}

impl std::error::Error for ResignError {}

/// 由 `hashType` 得到 `(hash_size, 是否截断)`；不可算返回 `None`。
fn hash_size_for(hash_type: u8) -> Option<usize> {
    match hash_type {
        1 => Some(20), // SHA-1
        2 => Some(32), // SHA-256
        3 => Some(20), // SHA-256 truncated to 20
        _ => None,
    }
}

/// 按 `hash_type` 对一段数据哈希；截断态取 SHA-256 前 20 字节。
fn digest_for(hash_type: u8, data: &[u8]) -> Option<Vec<u8>> {
    match hash_type {
        1 => sha1_digest(data),
        2 => sha256_digest(data),
        3 => Some(sha256_digest(data)?[..20].to_vec()),
        _ => None,
    }
}

/// 构造一份新的 CodeDirectory 字节（含逐页 code slot 哈希 + entitlements special slot）。
///
/// 布局与 [`parse`] 对称：`[44 字节头][identifier\0][special slots][code slots]`，
/// `hashOffset` 指向 code slot 数组起点；special slot `j`（1..=nSpecial）位于
/// `hashOffset - j*hash_size`。ad-hoc：不含 CMS。**纯函数，不改动 `content`。**
pub fn build_code_directory(content: &[u8], params: &ResignParams) -> Result<Vec<u8>, ResignError> {
    let hash_size = hash_size_for(params.hash_type)
        .ok_or(ResignError::UnsupportedHashType(params.hash_type))?;
    if params.page_size_log == 0 {
        return Err(ResignError::ZeroPageSizeLog);
    }
    let page_size = 1usize << params.page_size_log;
    let limit = params.code_limit as usize;
    if limit == 0 || content.is_empty() {
        return Err(ResignError::EmptyContent);
    }
    if content.len() < limit {
        return Err(ResignError::ContentShorterThanLimit {
            have: content.len(),
            need: params.code_limit,
        });
    }

    // 逐页 code slot 哈希（页数 = ceil(limit / page_size)）。
    let n_code = limit.div_ceil(page_size);
    let mut code_slots: Vec<Vec<u8>> = Vec::with_capacity(n_code);
    for slot in 0..n_code {
        let start = slot * page_size;
        let end = (start + page_size).min(limit);
        let digest = digest_for(params.hash_type, &content[start..end])
            .ok_or(ResignError::UnsupportedHashType(params.hash_type))?;
        debug_assert_eq!(digest.len(), hash_size);
        code_slots.push(digest);
    }

    // special slots：目前只填 entitlements（CSSLOT_ENTITLEMENTS=5）。给了就 nSpecial=5，
    // 槽 1..4 留空哈希（全 0）；没给就 nSpecial=0。
    let n_special: usize = if params.entitlements_blob.is_some() {
        5
    } else {
        0
    };
    let mut special_slots: Vec<Vec<u8>> = vec![vec![0u8; hash_size]; n_special];
    if let Some(blob) = &params.entitlements_blob {
        // special slot 5 = 从末尾数第 5 个，即 index n_special-5。
        let idx = n_special - (CSSLOT_ENTITLEMENTS as usize);
        let digest = digest_for(params.hash_type, blob)
            .ok_or(ResignError::UnsupportedHashType(params.hash_type))?;
        special_slots[idx] = digest;
    }

    // 头部固定 44 字节 + identifier 串 + special slots + code slots。
    let ident_bytes = {
        let mut v = params.identifier.clone().into_bytes();
        v.push(0);
        v
    };
    let ident_offset = CD_FIXED_LEN as u32;
    // 布局（与 Apple 一致）：[44 头][identifier\0][special slots][code slots]。
    // hashOffset 指向 **code slot 数组起点**，即 special slots 之后；special slot j（1..=nSpecial）
    // 位于 hashOffset - j*hash_size（j 从 1 数，包含 special slots 紧贴 identifier 之后）。
    let hash_region_start = CD_FIXED_LEN + ident_bytes.len(); // special slots 起点
    let hash_offset = (hash_region_start + n_special * hash_size) as u32;
    let cd_len = hash_region_start + n_special * hash_size + n_code * hash_size;

    let mut cd = vec![0u8; cd_len];
    cd[0..4].copy_from_slice(&CSMAGIC_CODEDIRECTORY.to_be_bytes());
    cd[4..8].copy_from_slice(&(cd_len as u32).to_be_bytes());
    // version：沿用现代版本号 0x20400（与实测样本同一族）。
    cd[8..12].copy_from_slice(&0x0002_0400u32.to_be_bytes());
    cd[12..16].copy_from_slice(&0u32.to_be_bytes()); // flags
    cd[16..20].copy_from_slice(&hash_offset.to_be_bytes());
    cd[20..24].copy_from_slice(&ident_offset.to_be_bytes());
    cd[24..28].copy_from_slice(&(n_special as u32).to_be_bytes());
    cd[28..32].copy_from_slice(&(n_code as u32).to_be_bytes());
    cd[32..36].copy_from_slice(&params.code_limit.to_be_bytes());
    cd[36] = hash_size as u8;
    cd[37] = params.hash_type;
    cd[38] = 0; // platform
    cd[39] = params.page_size_log;
    cd[40..44].copy_from_slice(&0u32.to_be_bytes()); // spare2

    cd[CD_FIXED_LEN..CD_FIXED_LEN + ident_bytes.len()].copy_from_slice(&ident_bytes);

    // special slots：index j（0-based）位于 hash_region_start + j*hash_size。
    for (j, slot) in special_slots.iter().enumerate() {
        let at = hash_region_start + j * hash_size;
        cd[at..at + hash_size].copy_from_slice(slot);
    }
    // code slots：从 hashOffset 起。
    for (i, slot) in code_slots.iter().enumerate() {
        let at = hash_offset as usize + i * hash_size;
        cd[at..at + hash_size].copy_from_slice(slot);
    }

    Ok(cd)
}

/// 把各 blob 拼回一个 SuperBlob（ad-hoc：不含 CMS 槽）。
///
/// 顺序与惯例一致：CodeDirectory（type 0）→ requirements（type 2，可选）→
/// entitlements（type 5，可选）。各 blob 在其偏移处按 4 字节对齐。**纯函数**。
#[must_use]
pub fn build_superblob(
    code_directory: &[u8],
    requirements: Option<&[u8]>,
    entitlements: Option<&[u8]>,
) -> Vec<u8> {
    // 组装 (type, bytes) 列表。
    let mut blobs: Vec<(u32, &[u8])> = vec![(CSSLOT_CODEDIRECTORY, code_directory)];
    if let Some(req) = requirements {
        blobs.push((CSSLOT_REQUIREMENTS, req));
    }
    if let Some(ent) = entitlements {
        blobs.push((CSSLOT_ENTITLEMENTS, ent));
    }

    let count = blobs.len();
    let index_len = 12 + count * 8;

    // 先算每个 blob 的偏移（按 4 字节对齐累加）。
    let mut offsets: Vec<u32> = Vec::with_capacity(count);
    let mut cursor = index_len;
    for (_, bytes) in &blobs {
        offsets.push(cursor as u32);
        cursor += bytes.len();
        cursor = (cursor + 3) & !3; // 4 字节对齐
    }
    let total_len = cursor;

    let mut sb = vec![0u8; total_len];
    sb[0..4].copy_from_slice(&CSMAGIC_EMBEDDED_SIGNATURE.to_be_bytes());
    sb[4..8].copy_from_slice(&(total_len as u32).to_be_bytes());
    sb[8..12].copy_from_slice(&(count as u32).to_be_bytes());
    for (i, ((blob_type, bytes), off)) in blobs.iter().zip(offsets.iter()).enumerate() {
        let entry = 12 + i * 8;
        sb[entry..entry + 4].copy_from_slice(&blob_type.to_be_bytes());
        sb[entry + 4..entry + 8].copy_from_slice(&off.to_be_bytes());
        let at = *off as usize;
        sb[at..at + bytes.len()].copy_from_slice(bytes);
    }
    sb
}

#[cfg(test)]
mod tests {
    use super::*;

    /// 造一个最小的 CodeDirectory + SuperBlob，两个 code page。
    /// `tamper` 为真时改坏第二个 page 的内容，好验证 Mismatch。
    fn build_signed(tamper: bool) -> Vec<u8> {
        use sha2::{Digest, Sha256};
        let page_size: usize = 4096;
        let n_code = 2usize;
        let code_limit = n_code * page_size; // 8192
                                             // 文件内容：codeLimit 字节 + 若干尾部（签名区在 codeLimit 之后，不参与）。
        let mut file = vec![0u8; code_limit + 64];
        for (i, byte) in file.iter_mut().take(code_limit).enumerate() {
            *byte = (i % 251) as u8;
        }
        // 先用**未篡改**的内容算 code slot 哈希（签名是对原始内容签的）。
        let mut slots = Vec::new();
        for slot in 0..n_code {
            let s = slot * page_size;
            let e = (s + page_size).min(code_limit);
            slots.push(Sha256::digest(&file[s..e]).to_vec());
        }
        if tamper {
            file[page_size + 10] ^= 0xff; // 签名之后改坏第二页
        }
        // CodeDirectory：magic+len+version+flags+hashOffset+identOffset+nSpecial+nCode+codeLimit
        //   +hashSize+hashType+platform+pageSizeLog+spare2 ; ident 串 ; special slots(0) ; code slots
        let hash_size = 32usize;
        let n_special = 0usize;
        let cd_fixed = 44usize;
        // ident 放在固定头之后。
        let ident = b"test.ident\0";
        let ident_offset = cd_fixed as u32;
        let hash_offset = (cd_fixed + ident.len()) as u32;
        let cd_len = cd_fixed + ident.len() + n_special * hash_size + n_code * hash_size;

        let mut cd = vec![0u8; cd_len];
        cd[0..4].copy_from_slice(&CSMAGIC_CODEDIRECTORY.to_be_bytes());
        cd[4..8].copy_from_slice(&(cd_len as u32).to_be_bytes());
        cd[8..12].copy_from_slice(&0x0002_0400u32.to_be_bytes()); // version
        cd[12..16].copy_from_slice(&0u32.to_be_bytes()); // flags
        cd[16..20].copy_from_slice(&hash_offset.to_be_bytes());
        cd[20..24].copy_from_slice(&ident_offset.to_be_bytes());
        cd[24..28].copy_from_slice(&(n_special as u32).to_be_bytes());
        cd[28..32].copy_from_slice(&(n_code as u32).to_be_bytes());
        cd[32..36].copy_from_slice(&(code_limit as u32).to_be_bytes());
        cd[36] = hash_size as u8;
        cd[37] = 2; // hashType = SHA256
        cd[38] = 0; // platform
        cd[39] = 12; // pageSizeLog -> 4096
        cd[40..44].copy_from_slice(&0u32.to_be_bytes()); // spare2
        cd[cd_fixed..cd_fixed + ident.len()].copy_from_slice(ident);
        for (i, slot) in slots.iter().enumerate() {
            let at = hash_offset as usize + i * hash_size;
            cd[at..at + hash_size].copy_from_slice(slot);
        }

        // SuperBlob：magic+len+count(1); index{type0, off=12+8=20}; then CD.
        let index_len = 12 + 8;
        let sb_len = index_len + cd_len;
        let mut sb = vec![0u8; sb_len];
        sb[0..4].copy_from_slice(&CSMAGIC_EMBEDDED_SIGNATURE.to_be_bytes());
        sb[4..8].copy_from_slice(&(sb_len as u32).to_be_bytes());
        sb[8..12].copy_from_slice(&1u32.to_be_bytes());
        sb[12..16].copy_from_slice(&CSSLOT_CODEDIRECTORY.to_be_bytes());
        sb[16..20].copy_from_slice(&(index_len as u32).to_be_bytes());
        sb[index_len..].copy_from_slice(&cd);

        // 把 SuperBlob 接到文件末尾（紧接 codeLimit 后）。
        let dataoff = code_limit;
        file.truncate(dataoff);
        file.extend_from_slice(&sb);
        file
    }

    #[test]
    fn intact_when_pages_match() {
        let file = build_signed(false);
        let sb_len = file.len() as u64 - 2 * 4096;
        let sig = parse(
            &file,
            LinkeditRange {
                dataoff: 2 * 4096,
                datasize: sb_len,
            },
            Endian::Little,
        );
        assert_eq!(sig.verdict, CodeSignVerdict::AdHoc, "无 CMS → ad-hoc");
        assert_eq!(sig.algorithm, HashAlgorithm::Sha256);
        assert_eq!(sig.identifier, "test.ident");
        assert_eq!(sig.code_slots, 2);
        assert_eq!(sig.verified_slots, 2, "两页都应一致");
        assert!(sig.first_mismatch.is_none());
        // CDHash（SHA-256）应是 64 位小写十六进制，且可复现（同一 CD 反复算一致）。
        let cd_hash = sig.cd_hash.as_deref().expect("SHA-256 CD 应能算 CDHash");
        assert_eq!(cd_hash.len(), 64, "SHA-256 CDHash 应 64 个十六进制字符");
        assert!(
            cd_hash
                .chars()
                .all(|c| c.is_ascii_hexdigit() && !c.is_ascii_uppercase()),
            "CDHash 应是小写十六进制：{cd_hash}"
        );
        let again = parse(
            &file,
            LinkeditRange {
                dataoff: 2 * 4096,
                datasize: sb_len,
            },
            Endian::Little,
        );
        assert_eq!(again.cd_hash.as_deref(), Some(cd_hash), "CDHash 应可复现");
    }

    #[test]
    fn mismatch_when_a_page_is_tampered() {
        let file = build_signed(true);
        let sb_len = file.len() as u64 - 2 * 4096;
        let sig = parse(
            &file,
            LinkeditRange {
                dataoff: 2 * 4096,
                datasize: sb_len,
            },
            Endian::Little,
        );
        assert_eq!(sig.verdict, CodeSignVerdict::Mismatch);
        assert_eq!(sig.first_mismatch, Some(1), "第二个 page 被改坏");
        assert_eq!(sig.verified_slots, 1, "第一页仍一致");
    }

    #[test]
    fn wrong_superblob_magic_is_malformed() {
        let mut file = build_signed(false);
        let dataoff = 2 * 4096;
        file[dataoff] = 0xff; // 破坏魔数
        let sig = parse(
            &file,
            LinkeditRange {
                dataoff: dataoff as u64,
                datasize: (file.len() as u64) - dataoff as u64,
            },
            Endian::Little,
        );
        assert_eq!(sig.verdict, CodeSignVerdict::Malformed);
    }

    #[test]
    fn plist_parser_extracts_scalars_arrays_and_others() {
        let xml = r#"<?xml version="1.0" encoding="UTF-8"?>
<plist version="1.0"><dict>
  <key>get-task-allow</key><true/>
  <key>aps-environment</key><string>development</string>
  <key>application-identifier</key><string>ABC.com.example</string>
  <key>com.apple.security.application-groups</key>
  <array><string>group.one</string><string>group.two</string></array>
  <key>weird</key><dict><key>n</key><integer>1</integer></dict>
</dict></plist>"#;
        let list = parse_plist_dict(xml);
        let keys: Vec<&str> = list.iter().map(|e| e.key.as_str()).collect();
        assert_eq!(
            keys,
            vec![
                "get-task-allow",
                "aps-environment",
                "application-identifier",
                "com.apple.security.application-groups",
                "weird"
            ]
        );
        assert_eq!(list[0].value, EntitlementValue::Bool(true));
        assert_eq!(
            list[1].value,
            EntitlementValue::String("development".to_string())
        );
        assert_eq!(
            list[3].value,
            EntitlementValue::Strings(vec!["group.one".to_string(), "group.two".to_string()])
        );
        // 嵌套 dict 不解，标 Other。
        assert!(matches!(list[4].value, EntitlementValue::Other(_)));
    }

    #[test]
    fn entitlements_blob_is_parsed_and_der_form_detected() {
        // 造一个 entitlements blob：fade7171 + 长度 + XML，随后跟一个 DER 头 fade7172。
        let xml = r#"<?xml version="1.0"?><plist version="1.0"><dict><key>get-task-allow</key><true/><key>application-identifier</key><string>Q.com.x</string></dict></plist>"#;
        let xml_bytes = xml.as_bytes();
        let blob_len = 8 + xml_bytes.len();
        let mut blob = vec![0u8; blob_len + 8];
        blob[0..4].copy_from_slice(&CSMAGIC_EMBEDDED_ENTITLEMENTS.to_be_bytes());
        blob[4..8].copy_from_slice(&(blob_len as u32).to_be_bytes());
        blob[8..8 + xml_bytes.len()].copy_from_slice(xml_bytes);
        // 尾部 DER 头
        blob[blob_len..blob_len + 4]
            .copy_from_slice(&CSMAGIC_EMBEDDED_DER_ENTITLEMENTS.to_be_bytes());

        let ent = parse_entitlements(&blob, 0).expect("能解析 entitlements");
        assert_eq!(ent.list.len(), 2);
        assert_eq!(
            ent.get("get-task-allow"),
            Some(&EntitlementValue::Bool(true))
        );
        assert_eq!(
            ent.get("application-identifier"),
            Some(&EntitlementValue::String("Q.com.x".to_string()))
        );
        assert!(ent.has_der_form, "应探测到 DER 形态");
        assert!(!ent.is_empty());
    }

    #[test]
    fn non_entitlements_magic_yields_empty_list() {
        // 头不是 fade7171 → 空列表（不编造），has_der_form 按 magic 判断。
        let mut blob = vec![0u8; 16];
        blob[0..4].copy_from_slice(&CSMAGIC_EMBEDDED_DER_ENTITLEMENTS.to_be_bytes());
        let ent = parse_entitlements(&blob, 0).expect("返回 Some");
        assert!(ent.list.is_empty());
        assert!(ent.has_der_form);
    }

    // ── 重签（A 阶段）自校验闭环 ──

    /// 造一段确定内容：`limit` 字节，值 i%251，便于篡改。
    fn resign_content(limit: usize) -> Vec<u8> {
        (0..limit).map(|i| (i % 251) as u8).collect()
    }

    /// 把内容 + SuperBlob 拼成一个"文件"，签名区在 codeLimit 之后。
    fn assemble(content: &[u8], code_limit: u32, superblob: &[u8]) -> (Vec<u8>, u64, u64) {
        let mut file = content[..code_limit as usize].to_vec();
        file.extend_from_slice(superblob);
        (file, code_limit as u64, superblob.len() as u64)
    }

    fn resign_and_parse(
        content: &[u8],
        params: &ResignParams,
        entries: Option<&[u8]>,
    ) -> crate::object::CodeSignature {
        let cd = build_code_directory(content, params).expect("构造 CodeDirectory");
        let sb = build_superblob(&cd, None, entries);
        let (file, dataoff, datasize) = assemble(content, params.code_limit, &sb);
        parse(&file, LinkeditRange { dataoff, datasize }, Endian::Little)
    }

    #[test]
    fn resign_roundtrip_is_intact_sha256() {
        let limit = 2 * 4096u32;
        let content = resign_content(limit as usize);
        let params = ResignParams {
            hash_type: 2,
            page_size_log: 12,
            code_limit: limit,
            identifier: "com.example.resigned".to_string(),
            entitlements_blob: None,
        };
        let sig = resign_and_parse(&content, &params, None);
        assert_eq!(sig.verified_slots, 2, "两页全过");
        assert!(sig.first_mismatch.is_none());
        assert!(
            matches!(sig.verdict, CodeSignVerdict::AdHoc),
            "ad-hoc（无 CMS）且完整性通过，实际 {:?}",
            sig.verdict
        );
        assert_eq!(sig.identifier, "com.example.resigned");
        assert_eq!(sig.code_limit, u64::from(limit));
        assert!(!sig.has_cms_signature);
    }

    #[test]
    fn resign_roundtrip_is_intact_sha1() {
        let limit = 4096u32;
        let content = resign_content(limit as usize);
        let params = ResignParams {
            hash_type: 1,
            page_size_log: 12,
            code_limit: limit,
            identifier: "com.example.sha1".to_string(),
            entitlements_blob: None,
        };
        let sig = resign_and_parse(&content, &params, None);
        assert_eq!(sig.verified_slots, 1);
        assert!(matches!(sig.verdict, CodeSignVerdict::AdHoc));
        assert_eq!(sig.algorithm, HashAlgorithm::Sha1);
    }

    #[test]
    fn resign_fixes_a_tampered_mismatch() {
        // 先签原始内容，再篡改内容 → parse 报 Mismatch；对篡改后的内容重签 → Intact。
        let limit = 2 * 4096u32;
        let mut content = resign_content(limit as usize);
        let params = ResignParams {
            hash_type: 2,
            page_size_log: 12,
            code_limit: limit,
            identifier: "com.example.fix".to_string(),
            entitlements_blob: None,
        };
        // 用原始内容签一份文件。
        let cd = build_code_directory(&content, &params).expect("cd");
        let sb = build_superblob(&cd, None, None);
        let (file, dataoff, datasize) = assemble(&content, limit, &sb);
        // 篡改第二页 → Mismatch。
        content[4096 + 100] ^= 0xff;
        let mut tampered_file = file.clone();
        tampered_file[4096 + 100] ^= 0xff;
        let sig_before = parse(
            &tampered_file,
            LinkeditRange { dataoff, datasize },
            Endian::Little,
        );
        assert!(
            matches!(sig_before.verdict, CodeSignVerdict::Mismatch),
            "篡改后应报 Mismatch，实际 {:?}",
            sig_before.verdict
        );
        assert_eq!(sig_before.first_mismatch, Some(1));

        // 对篡改后的内容重签 → 重新组装 → Intact。
        let sig_after = resign_and_parse(&content, &params, None);
        assert!(
            matches!(sig_after.verdict, CodeSignVerdict::AdHoc),
            "重签后应完整性通过（ad-hoc），实际 {:?}",
            sig_after.verdict
        );
        assert_eq!(sig_after.verified_slots, 2);
        assert!(sig_after.first_mismatch.is_none());
    }

    #[test]
    fn resign_with_entitlements_sets_special_slot_and_stays_intact() {
        // 造 entitlements blob（fade7171+len+XML）。
        let xml = r#"<?xml version="1.0"?><plist version="1.0"><dict><key>get-task-allow</key><true/></dict></plist>"#;
        let xml_bytes = xml.as_bytes();
        let bloc_len = 8 + xml_bytes.len();
        let mut ent = vec![0u8; bloc_len];
        ent[0..4].copy_from_slice(&CSMAGIC_EMBEDDED_ENTITLEMENTS.to_be_bytes());
        ent[4..8].copy_from_slice(&(bloc_len as u32).to_be_bytes());
        ent[8..8 + xml_bytes.len()].copy_from_slice(xml_bytes);

        let limit = 4096u32;
        let content = resign_content(limit as usize);
        let params = ResignParams {
            hash_type: 2,
            page_size_log: 12,
            code_limit: limit,
            identifier: "com.example.ent".to_string(),
            entitlements_blob: Some(ent.clone()),
        };
        let sig = resign_and_parse(&content, &params, Some(&ent));

        // CD 里应写入了 entitlements special slot：nSpecial=5。
        let cd = build_code_directory(&content, &params).expect("cd");
        assert_eq!(be_u32(&cd, 24), Some(5), "nSpecialSlots 应为 5");
        // 解析仍 Intact，且解出了 entitlements。
        assert!(matches!(sig.verdict, CodeSignVerdict::AdHoc));
        assert_eq!(sig.verified_slots, 1);
        let parsed_ent = sig.entitlements.as_ref().expect("应解出 entitlements");
        assert_eq!(
            parsed_ent.get("get-task-allow"),
            Some(&EntitlementValue::Bool(true))
        );
    }

    #[test]
    fn resign_rejects_unknown_hash_type() {
        let content = resign_content(4096);
        let params = ResignParams {
            hash_type: 9,
            page_size_log: 12,
            code_limit: 4096,
            identifier: "x".to_string(),
            entitlements_blob: None,
        };
        assert_eq!(
            build_code_directory(&content, &params),
            Err(ResignError::UnsupportedHashType(9))
        );
    }

    #[test]
    fn resign_rejects_zero_page_size_and_short_content() {
        let content = resign_content(4096);
        let zero_page = ResignParams {
            hash_type: 2,
            page_size_log: 0,
            code_limit: 4096,
            identifier: "x".to_string(),
            entitlements_blob: None,
        };
        assert_eq!(
            build_code_directory(&content, &zero_page),
            Err(ResignError::ZeroPageSizeLog)
        );
        let short = ResignParams {
            hash_type: 2,
            page_size_log: 12,
            code_limit: 8192,
            identifier: "x".to_string(),
            entitlements_blob: None,
        };
        assert_eq!(
            build_code_directory(&content, &short),
            Err(ResignError::ContentShorterThanLimit {
                have: 4096,
                need: 8192
            })
        );
    }
}
