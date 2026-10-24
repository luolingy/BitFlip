//! 代码签名的**有界**解析与完整性校验（`LC_CODE_SIGNATURE` → SuperBlob → CodeDirectory）。
//!
//! 这里只做一件可离线复现、结论确定的事：**逐页重算文件哈希，与 CodeDirectory 里存的
//! code slot 比对**，判断"文件内容是否自签名以来被改过"。改过 → 签名失效（哪怕只是
//! 一个字节）。这与"这个签名是否可信"是两回事：
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
use crate::object::{CodeSignVerdict, CodeSignature, HashAlgorithm};

/// SuperBlob 魔数（大端）。
const CSMAGIC_EMBEDDED_SIGNATURE: u32 = 0xfade_0cc0;
/// CodeDirectory 魔数（大端）。
const CSMAGIC_CODEDIRECTORY: u32 = 0xfade_0c02;
/// `CSSLOT_CODEDIRECTORY`（SuperBlob 里的 blob 类型）。
const CSSLOT_CODEDIRECTORY: u32 = 0;
/// `CSSLOT_SIGNATURESLOT`（CMS / X.509 签名槽；有它 = 非 ad-hoc）。
const CSSLOT_SIGNATURESLOT: u32 = 0x1000;
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

    // ── 遍历 BlobIndex，找 CodeDirectory、记 CMS 槽存在性 ──
    let mut code_directory_offset: Option<usize> = None;
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
        }
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
}
