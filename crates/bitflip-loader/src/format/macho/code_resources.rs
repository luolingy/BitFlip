//! `_CodeSignature/CodeResources` 的**只读事实**解析（M12 代码签名支线）。
//!
//! # 这是什么
//!
//! `.app` / framework bundle 里 `_CodeSignature/CodeResources` 是一份 plist，列出
//! 包里被"封印"的文件与它们的哈希（`files` 是 SHA-1，`files2` 里带 `hash`/`hash2`
//! 即 SHA-1/SHA-256），外加一组 `rules`/`rules2` 正则决定哪些文件参与封印。
//!
//! # 边界（§7，很重要）
//!
//! 本模块**只做只读事实抽取**：告诉你这份封印"覆盖了哪些文件、有多少条"。
//! 它**不校验**这些哈希、**不校封印**（不说"包完整"或"包被改"）、**不校信任链**
//! （CMS / X.509 是另一回事）。想拿它当"这个 app 没被动过"的证据是错的 ——
//! 它只是把封印清单原样读出来，判断权留给用户。
//!
//! # 支持到什么程度
//!
//! - **XML plist**：抽 `files` / `files2` 两段的条目数与文件名样例，以及有没有
//!   `rules`/`rules2`。用深度计数的键扫描，不做完整 plist 语义。
//! - **二进制 plist**（`bplist00`）：只报"是二进制 plist"，条目数**不解**（真解析
//!   二进制 plist 是另一件事，没做就如实说没做，不猜）。
//! - 其它形态：`is_plist=false`，附一条说明。

use crate::object::CodeResourcesSummary;

/// 文件名样例上限（展示前 N 条 + 总数）。
pub const NAME_SAMPLE_LIMIT: usize = 16;

/// 解析 `CodeResources` 字节，得到只读摘要。永不 panic；不认识的形态如实降级。
#[must_use]
pub fn parse(bytes: &[u8]) -> CodeResourcesSummary {
    let mut summary = CodeResourcesSummary::default();

    // 二进制 plist：只认出来，不解内容（不猜）。
    if bytes.starts_with(b"bplist00") {
        summary.format = "binary-plist".to_string();
        summary.notes.push(
            "这是二进制 plist 形态的 CodeResources（bplist00）；本模块不解二进制 plist，\
             只如实标注形态，不给出条目数"
                .to_string(),
        );
        return summary;
    }

    // XML plist：得先能当文本读。
    let Ok(text) = std::str::from_utf8(bytes) else {
        summary.format = "unknown".to_string();
        summary
            .notes
            .push("CodeResources 不是合法 UTF-8，也不是二进制 plist；形态未识别".to_string());
        return summary;
    };

    if !looks_like_xml_plist(text) {
        summary.format = "unknown".to_string();
        summary.notes.push(
            "Content 看起来既不是 XML plist 也不是二进制 plist；形态未识别（不猜）".to_string(),
        );
        return summary;
    }

    summary.format = "xml-plist".to_string();

    // 顶层字典里找 files / files2 / rules / rules2 这几个 key，各自的 dict 展开计数。
    for key in ["files", "files2"] {
        let entries = dict_entries_after_key(text, key);
        match entries {
            Some(names) => {
                let count = names.len();
                if key == "files" {
                    summary.files = count;
                } else {
                    summary.files2 = count;
                }
                for name in names.into_iter().take(NAME_SAMPLE_LIMIT) {
                    summary.name_samples.push((key.to_string(), name));
                }
            }
            None => {
                // 顶层没有这个键是正常的（很多新式 bundle 只写 files2）；不报警。
            }
        }
    }

    summary.has_rules = has_top_level_key(text, "rules") || has_top_level_key(text, "rules2");

    // 账目要闭合：如果两个 files 段都没找到，说明这份 plist 不是我们认识的
    // CodeResources 形态（比如只有 rules），如实说。
    if summary.files == 0 && summary.files2 == 0 && !summary.has_rules {
        summary.notes.push(
            "XML plist 里没找到 files / files2 / rules 任一段，可能不是 CodeResources".to_string(),
        );
    }

    summary
}

fn looks_like_xml_plist(text: &str) -> bool {
    let head = text.trim_start();
    head.starts_with("<?xml") || head.starts_with("<plist") || head.contains("<plist")
}

/// 顶层（深度 1 的 dict 内）是否存在某个 `<key>NAME</key>`。
fn has_top_level_key(text: &str, name: &str) -> bool {
    // 顶层 key 的判据：紧跟在第一个 `<dict>` 之后、且深度恰为 1 的 `<key>`。
    // 简化：只要出现 `<key>name</key>` 且其后不是嵌套更深——这里宽松地认为存在。
    text.contains(&format!("<key>{name}</key>"))
}

/// 取 `<key>NAME</key>` 之后那个 `<dict>...</dict>` 里**直接子级** `<key>` 的文本。
///
/// 只处理第一处匹配。找不到 key 或其后不是 `<dict>` 就返回 `None`。
/// 用深度计数跳过嵌套 dict（files2 的值是 dict，不是直接子 key）。
fn dict_entries_after_key(text: &str, name: &str) -> Option<Vec<String>> {
    let needle = format!("<key>{name}</key>");
    let at = text.find(&needle)?;
    let rest = &text[at + needle.len()..];

    // 跳过空白，必须紧接 `<dict>`（允许中间有空白/换行）。
    let trimmed = rest.trim_start();
    let after_dict = trimmed.strip_prefix("<dict>")?;
    // 有的写成 `<dict/>`（空字典）。
    if trimmed.starts_with("<dict/>") {
        return Some(Vec::new());
    }

    // 在 after_dict 里走进深度 1：收集 depth==1 处的 <key>。
    let mut names = Vec::new();
    let mut depth: i32 = 1; // 已经进入了外层 <dict>
    let mut cursor = 0usize;
    let bytes = after_dict.as_bytes();
    while cursor < bytes.len() {
        let slice = &after_dict[cursor..];
        if let Some(pos) = slice.find('<') {
            cursor += pos;
            let tail = &after_dict[cursor..];
            if tail.starts_with("<dict>") {
                depth += 1;
                cursor += "<dict>".len();
            } else if tail.starts_with("<dict/>") {
                cursor += "<dict/>".len();
            } else if tail.starts_with("</dict>") {
                depth -= 1;
                cursor += "</dict>".len();
                if depth == 0 {
                    return Some(names);
                }
            } else if tail.starts_with("<key>") && depth == 1 {
                let start = cursor + "<key>".len();
                if let Some(end_rel) = after_dict[start..].find("</key>") {
                    let key_text = &after_dict[start..start + end_rel];
                    names.push(unescape_xml(key_text.trim()));
                    cursor = start + end_rel + "</key>".len();
                } else {
                    return Some(names);
                }
            } else {
                // 其它标签（<data>/<true/>/<real>/<array>/<string>/<dict>已处理等）：
                // 跳过这个标签本身，不深入。
                cursor += 1;
            }
        } else {
            break;
        }
    }
    Some(names)
}

fn unescape_xml(s: &str) -> String {
    s.replace("&lt;", "<")
        .replace("&gt;", ">")
        .replace("&quot;", "\"")
        .replace("&apos;", "'")
        .replace("&amp;", "&")
}

// ───────────────────── 哈希抽取/重写（F 阶段：.app 重签一致性） ─────────────────────
//
// 这些是**纯函数**：从 XML plist 的 `files` / `files2` 里把条目的哈希字节读出来，或在重签后
// 把对应条目的哈希**替换**成新值。它们只保证"清单自洽"，**不是可信封印**（没有 Apple 私钥，
// 真机仍需 `codesign` 复核）。二进制 plist 不支持（如实返回 None，不猜）。

/// 一个封印条目在清单里记录的哈希（能读到哪几种就给哪几种）。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CodeResourceHash {
    /// 相对 `.app` 根的资源路径（`files`/`files2` 里的 key）。
    pub path: String,
    /// `files` 段里的 SHA-1（20 字节）。
    pub sha1: Option<Vec<u8>>,
    /// `files2` 段里的 `hash2`（通常 SHA-256，32 字节）。
    pub sha256: Option<Vec<u8>>,
}

/// 从 XML plist 形态的 CodeResources 里抽出每条目的哈希。
///
/// 只认 XML plist；二进制 plist 或结构不认识时返回 `None`（不猜）。哈希按 base64 解码。
#[must_use]
pub fn extract_hashes(bytes: &[u8]) -> Option<Vec<CodeResourceHash>> {
    let text = std::str::from_utf8(bytes).ok()?;
    if !looks_like_xml_plist(text) {
        return None;
    }
    // files：key -> <data>base64</data>（SHA-1）。
    let files = dict_key_data_map(text, "files")?;
    // files2：key -> dict{ hash: <data>, hash2: <data> }（hash=SHA-1, hash2=SHA-256）。
    let files2 = dict2_hash_map(text);

    let mut by_path: std::collections::BTreeMap<String, CodeResourceHash> =
        std::collections::BTreeMap::new();
    for (path, b64) in files {
        let h = base64_decode(b64.trim())?;
        by_path
            .entry(path.clone())
            .or_insert_with(|| CodeResourceHash {
                path,
                sha1: None,
                sha256: None,
            })
            .sha1 = Some(h);
    }
    for (path, (hash1, hash2)) in files2 {
        let e = by_path
            .entry(path.clone())
            .or_insert_with(|| CodeResourceHash {
                path,
                sha1: None,
                sha256: None,
            });
        if let Some(b64) = hash1 {
            if let Some(v) = base64_decode(b64.trim()) {
                e.sha1 = Some(v);
            }
        }
        if let Some(b64) = hash2 {
            if let Some(v) = base64_decode(b64.trim()) {
                e.sha256 = Some(v);
            }
        }
    }
    Some(by_path.into_values().collect())
}

/// 重写 XML plist 里**指定路径**的哈希值：`files` 段的 `<data>` 换成 `sha1`，`files2` 段里
/// `<key>hash</key><data>` 换成 `sha1`、`<key>hash2</key><data>` 换成 `sha256`（给哪个换哪个）。
///
/// 只动匹配到的条目，其余字节原样保留（返回新 `String` 的字节，不原地改）。找不到路径就跳过。
/// 这是**尽力而为**的清单自洽，不代表可信封印。
#[must_use]
pub fn rewrite_hashes(bytes: &[u8], updates: &[CodeResourceHash]) -> Option<Vec<u8>> {
    let text = std::str::from_utf8(bytes).ok()?;
    if !looks_like_xml_plist(text) {
        return None;
    }
    let mut out = text.to_string();
    for upd in updates {
        // files 段：<key>path</key> ... <data>OLD</data>（首次出现）。
        if let Some(sha1) = &upd.sha1 {
            out = replace_first_data_after_key(&out, upd.path.as_str(), sha1);
            // files2 段的 hash（SHA-1）：<key>path</key>...<key>hash</key><data>OLD</data>
            out = replace_nested_after_key(&out, upd.path.as_str(), "hash", sha1);
        }
        if let Some(sha256) = &upd.sha256 {
            out = replace_nested_after_key(&out, upd.path.as_str(), "hash2", sha256);
        }
    }
    Some(out.into_bytes())
}

/// 找 `<key>PATH</key>` 之后**紧接**（中间仅空白）指定标记（`<data>` 或 `<dict>`）的那一处出现的
/// key 结束位置；用于消除"同一路径在 files 与 files2 各出现一次"的歧义。
fn find_key_followed_by(text: &str, path: &str, marker: &str) -> Option<usize> {
    let needle = format!("<key>{}</key>", escape_xml(path));
    let mut from = 0usize;
    while let Some(rel) = text[from..].find(&needle) {
        let at = from + rel;
        let after_key = at + needle.len();
        let rest = &text[after_key..];
        let ws = rest.len() - rest.trim_start().len();
        if rest[ws..].starts_with(marker) {
            return Some(after_key + ws);
        }
        from = after_key;
    }
    None
}

/// 找 `<key>path</key>` 之后**紧接**的 `<data>...</data>`（中间只有空白），替换其内容为 base64(sha)。
/// 只替换第一处匹配；找不到返回原串。
fn replace_first_data_after_key(text: &str, path: &str, digest: &[u8]) -> String {
    let Some(data_tag_at) = find_key_followed_by(text, path, "<data>") else {
        return text.to_string();
    };
    let data_start = data_tag_at + "<data>".len();
    let Some(close_rel) = text[data_start..].find("</data>") else {
        return text.to_string();
    };
    let data_end = data_start + close_rel;
    let mut new_text = String::with_capacity(text.len());
    new_text.push_str(&text[..data_start]);
    new_text.push_str(&base64_encode(digest));
    new_text.push_str(&text[data_end..]);
    new_text
}

/// 在 `path` 对应的 **files2 `<dict>`** 里，替换 `<key>field</key><data>...</data>` 的 `<data>` 内容。
/// 关键：必须定位到 `path` 后面紧跟 `<dict>` 的那一处（files2 形态），避免误改 files 段的同名 key。
/// 只替换第一处；找不到返回原串。
fn replace_nested_after_key(text: &str, path: &str, field: &str, digest: &[u8]) -> String {
    let Some(dict_tag_at) = find_key_followed_by(text, path, "<dict>") else {
        return text.to_string();
    };
    // 在该 dict 之后、到对应 </dict> 之前找 <key>field</key><data>。
    let seg = &text[dict_tag_at..];
    let field_key = format!("<key>{field}</key>");
    let Some(rel) = seg.find(&field_key) else {
        return text.to_string();
    };
    let fk_end = dict_tag_at + rel + field_key.len();
    let rest = &text[fk_end..];
    let ws = rest.len() - rest.trim_start().len();
    let after_ws = &rest[ws..];
    if !after_ws.starts_with("<data>") {
        return text.to_string();
    }
    let data_start = fk_end + ws + "<data>".len();
    let Some(close_rel) = text[data_start..].find("</data>") else {
        return text.to_string();
    };
    let data_end = data_start + close_rel;
    let mut new_text = String::with_capacity(text.len());
    new_text.push_str(&text[..data_start]);
    new_text.push_str(&base64_encode(digest));
    new_text.push_str(&text[data_end..]);
    new_text
}

/// 从 `files` 段（key -> 单个 `<data>`）抽出 (path, base64_text)。结构不认识返回 None。
fn dict_key_data_map(text: &str, section: &str) -> Option<Vec<(String, String)>> {
    let needle = format!("<key>{section}</key>");
    let at = text.find(&needle)?;
    let rest = text[at + needle.len()..].trim_start();
    if rest.starts_with("<dict/>") {
        return Some(Vec::new());
    }
    let after = rest.strip_prefix("<dict>")?;
    let mut pairs = Vec::new();
    let mut cursor = 0usize;
    let mut pending_key: Option<String> = None;
    let mut depth = 1i32;
    while cursor < after.len() {
        let slice = &after[cursor..];
        if let Some(pos) = slice.find('<') {
            cursor += pos;
            let tail = &after[cursor..];
            if tail.starts_with("<dict>") {
                depth += 1;
                cursor += 6;
            } else if tail.starts_with("<dict/>") {
                cursor += 7;
            } else if tail.starts_with("</dict>") {
                depth -= 1;
                cursor += 7;
                if depth == 0 {
                    return Some(pairs);
                }
            } else if tail.starts_with("<key>") && depth == 1 {
                let start = cursor + 5;
                let end_rel = after[start..].find("</key>")?;
                pending_key = Some(unescape_xml(after[start..start + end_rel].trim()));
                cursor = start + end_rel + 6;
            } else if tail.starts_with("<data>") && depth == 1 {
                let start = cursor + 6;
                let end_rel = after[start..].find("</data>")?;
                if let Some(k) = pending_key.take() {
                    let b64: String = after[start..start + end_rel]
                        .chars()
                        .filter(|c| !c.is_whitespace())
                        .collect();
                    pairs.push((k, b64));
                }
                cursor = start + end_rel + 7;
            } else {
                cursor += 1;
            }
        } else {
            break;
        }
    }
    Some(pairs)
}

/// `files2` 每条的哈希对：`(path, (hash_b64, hash2_b64))`。
type Files2Entry = (String, (Option<String>, Option<String>));

/// 从 `files2` 段抽出 `(path -> (hash_b64, hash2_b64))`。结构不认识返回空。
fn dict2_hash_map(text: &str) -> Vec<Files2Entry> {
    let needle = "<key>files2</key>";
    let Some(at) = text.find(needle) else {
        return Vec::new();
    };
    let rest = text[at + needle.len()..].trim_start();
    let Some(after) = rest.strip_prefix("<dict>") else {
        return Vec::new();
    };
    // 逐条：<key>path</key><dict>...<key>hash</key><data>..</data>..<key>hash2</key><data>..</data>...</dict>
    let mut out = Vec::new();
    let mut cursor = 0usize;
    let mut pending_path: Option<String> = None;
    let mut depth = 1i32;
    let mut cur_hash1: Option<String> = None;
    let mut cur_hash2: Option<String> = None;
    let mut last_field: Option<String> = None;
    while cursor < after.len() {
        let tail = &after[cursor..];
        if tail.starts_with("<dict>") {
            depth += 1;
            cursor += 6;
        } else if tail.starts_with("<dict/>") {
            cursor += 7;
        } else if tail.starts_with("</dict>") {
            depth -= 1;
            cursor += 7;
            if depth == 1 {
                // 结束一个条目 dict
                if let Some(p) = pending_path.take() {
                    out.push((p, (cur_hash1.take(), cur_hash2.take())));
                }
            } else if depth == 0 {
                return out;
            }
        } else if tail.starts_with("<key>") {
            let start = cursor + 5;
            let Some(end_rel) = after[start..].find("</key>") else {
                return out;
            };
            let key = unescape_xml(after[start..start + end_rel].trim());
            cursor = start + end_rel + 6;
            if depth == 1 {
                pending_path = Some(key);
            } else {
                last_field = Some(key);
            }
        } else if tail.starts_with("<data>") {
            let start = cursor + 6;
            let Some(end_rel) = after[start..].find("</data>") else {
                return out;
            };
            let b64: String = after[start..start + end_rel]
                .chars()
                .filter(|c| !c.is_whitespace())
                .collect();
            match last_field.as_deref() {
                Some("hash") => cur_hash1 = Some(b64),
                Some("hash2") => cur_hash2 = Some(b64),
                _ => {}
            }
            last_field = None;
            cursor = start + end_rel + 7;
        } else {
            cursor += 1;
        }
    }
    out
}

fn escape_xml(s: &str) -> String {
    s.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
}

// ── 自带的极简 base64（标准字母表，带 `=` 填充）──

fn base64_encode(data: &[u8]) -> String {
    const T: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut out = String::with_capacity(data.len().div_ceil(3) * 4);
    for chunk in data.chunks(3) {
        let b0 = chunk[0] as u32;
        let b1 = *chunk.get(1).unwrap_or(&0) as u32;
        let b2 = *chunk.get(2).unwrap_or(&0) as u32;
        let n = (b0 << 16) | (b1 << 8) | b2;
        out.push(T[((n >> 18) & 63) as usize] as char);
        out.push(T[((n >> 12) & 63) as usize] as char);
        if chunk.len() > 1 {
            out.push(T[((n >> 6) & 63) as usize] as char);
        } else {
            out.push('=');
        }
        if chunk.len() > 2 {
            out.push(T[(n & 63) as usize] as char);
        } else {
            out.push('=');
        }
    }
    out
}

fn base64_decode(s: &str) -> Option<Vec<u8>> {
    fn val(c: u8) -> Option<u32> {
        Some(match c {
            b'A'..=b'Z' => (c - b'A') as u32,
            b'a'..=b'z' => (c - b'a') as u32 + 26,
            b'0'..=b'9' => (c - b'0') as u32 + 52,
            b'+' => 62,
            b'/' => 63,
            _ => return None,
        })
    }
    let bytes: Vec<u8> = s
        .bytes()
        .filter(|b| !b.is_ascii_whitespace() && *b != b'=')
        .collect();
    let mut out = Vec::with_capacity(bytes.len() * 3 / 4);
    let mut buf: u32 = 0;
    let mut bits = 0u32;
    for c in bytes {
        let v = val(c)?;
        buf = (buf << 6) | v;
        bits += 6;
        if bits >= 8 {
            bits -= 8;
            out.push(((buf >> bits) & 0xff) as u8);
        }
    }
    Some(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    const SAMPLE: &str = r#"<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
	<key>files</key>
	<dict>
		<key>Info.plist</key>
		<data>
		90LCNJaJ3n78biUBztejKdqkfdw=
		</data>
		<key>Image.png</key>
		<data>
		AL1dh5ctObXBjoBiabSJ86M3HQs=
		</data>
	</dict>
	<key>files2</key>
	<dict>
		<key>Image.png</key>
		<dict>
			<key>hash</key>
			<data>
			AL1dh5ctObXBjoBiabSJ86M3HQs=
			</data>
			<key>hash2</key>
			<data>
			WpuPwM3bECAbtHzCgEs/AExyUUdmItJb/E61TtRuEIQ=
			</data>
		</dict>
	</dict>
	<key>rules</key>
	<dict>
		<key>^.*</key>
		<true/>
	</dict>
</dict>
</plist>
"#;

    #[test]
    fn parses_xml_plist_counts_and_names() {
        let summary = parse(SAMPLE.as_bytes());
        assert_eq!(summary.format, "xml-plist");
        assert_eq!(summary.files, 2, "files 段两条（Info.plist、Image.png）");
        assert_eq!(
            summary.files2, 1,
            "files2 段一条（Image.png），嵌套 dict 不该被当条目"
        );
        assert!(summary.has_rules, "有 rules");
        let names: Vec<&str> = summary
            .name_samples
            .iter()
            .map(|(_, n)| n.as_str())
            .collect();
        assert!(names.contains(&"Info.plist"));
        assert!(names.contains(&"Image.png"));
    }

    #[test]
    fn empty_self_closing_files2_is_zero() {
        let text = "<plist><dict><key>files</key><dict><key>A</key><data>AA==</data></dict>\
                    <key>files2</key><dict/></dict></plist>";
        let summary = parse(text.as_bytes());
        assert_eq!(summary.files, 1);
        assert_eq!(summary.files2, 0);
    }

    #[test]
    fn binary_plist_is_reported_not_parsed() {
        let mut bytes = b"bplist00".to_vec();
        bytes.extend_from_slice(&[0u8; 16]);
        let summary = parse(&bytes);
        assert_eq!(summary.format, "binary-plist");
        assert_eq!(summary.files, 0);
        assert!(summary.notes.iter().any(|n| n.contains("二进制 plist")));
    }

    #[test]
    fn garbage_is_unknown_not_guessed() {
        let summary = parse(b"\x00\x01\x02not a plist");
        assert_eq!(summary.format, "unknown");
        assert!(summary.notes.iter().any(|n| n.contains("未识别")));
    }

    /// 真实样本：把一份从真实 IPA 里抽出的 `_CodeSignature/CodeResources` 指过来
    /// （`BITFLIP_CODERES_SAMPLE=<path>`），核对条目数非零、形态是 XML plist。
    /// 不给就用 `#[ignore]` 跳过（不假装通过）。
    #[test]
    #[ignore = "需要真实 CodeResources 样本：设 BITFLIP_CODERES_SAMPLE 后加 --ignored"]
    fn real_code_resources_summary() {
        let Ok(path) = std::env::var("BITFLIP_CODERES_SAMPLE") else {
            eprintln!("跳过：未设 BITFLIP_CODERES_SAMPLE");
            return;
        };
        let bytes = std::fs::read(&path).expect("读样本");
        let summary = parse(&bytes);
        eprintln!(
            "format={} files={} files2={} rules={} samples={:?}",
            summary.format,
            summary.files,
            summary.files2,
            summary.has_rules,
            summary.name_samples.iter().take(4).collect::<Vec<_>>()
        );
        assert_eq!(
            summary.format, "xml-plist",
            "真实 CodeResources 应是 XML plist"
        );
        assert!(
            summary.files + summary.files2 > 0,
            "真实包至少有一个封印条目"
        );
        assert!(summary.has_rules, "真实 CodeResources 应带 rules");
    }

    // ── F 阶段：哈希抽取 / 重写 ──

    #[test]
    fn base64_roundtrips() {
        for sample in [
            &b""[..],
            b"a",
            b"ab",
            b"abc",
            b"abcd",
            b"\x00\xff\x10\x20\x30",
        ] {
            let enc = base64_encode(sample);
            let dec = base64_decode(&enc).expect("解码");
            assert_eq!(dec, sample, "base64 往返失败：{enc}");
        }
        // 已知值：SHA-1 空串 = da39a3ee5e6b4b0d3255bfef95601890afd80709
        // base64("\xda\x39\xa3\xee...") 用标准字母表核对一条即可。
        assert_eq!(base64_encode(b"Man"), "TWFu");
        assert_eq!(base64_decode("TWFu").unwrap(), b"Man");
    }

    #[test]
    fn extract_and_rewrite_hashes_from_sample() {
        // 用 SAMPLE（含 files 两条、files2 一条带 hash/hash2）。
        let hashes = extract_hashes(SAMPLE.as_bytes()).expect("能抽出哈希");
        // 找 Image.png：应同时有 sha1（files）与 sha1+sha256（files2）。
        let img = hashes
            .iter()
            .find(|h| h.path == "Image.png")
            .expect("Image.png 条目");
        assert_eq!(img.sha1.as_ref().map(Vec::len), Some(20));
        assert_eq!(img.sha256.as_ref().map(Vec::len), Some(32));
        // Info.plist 只在 files 段，有 sha1、无 sha256。
        let info = hashes
            .iter()
            .find(|h| h.path == "Info.plist")
            .expect("Info.plist 条目");
        assert_eq!(info.sha1.as_ref().map(Vec::len), Some(20));
        assert!(info.sha256.is_none());

        // 重写 Image.png 的 sha1 为全 0x11，sha256 为全 0x22。
        let upd = CodeResourceHash {
            path: "Image.png".to_string(),
            sha1: Some(vec![0x11u8; 20]),
            sha256: Some(vec![0x22u8; 32]),
        };
        let rewritten = rewrite_hashes(SAMPLE.as_bytes(), &[upd]).expect("能重写");
        // 重新抽取，Image.png 的哈希应变成新值。
        let hashes2 = extract_hashes(&rewritten).expect("重写后仍可解析");
        let img2 = hashes2.iter().find(|h| h.path == "Image.png").unwrap();
        assert_eq!(img2.sha1.as_ref().unwrap(), &vec![0x11u8; 20]);
        assert_eq!(img2.sha256.as_ref().unwrap(), &vec![0x22u8; 32]);
        // 其它条目（Info.plist）不受影响。
        let info2 = hashes2.iter().find(|h| h.path == "Info.plist").unwrap();
        assert_eq!(info2.sha1, info.sha1);
    }

    #[test]
    fn binary_plist_has_no_hashes() {
        let mut bytes = b"bplist00".to_vec();
        bytes.extend_from_slice(&[0u8; 16]);
        assert!(extract_hashes(&bytes).is_none());
        assert!(rewrite_hashes(&bytes, &[]).is_none());
    }
}
