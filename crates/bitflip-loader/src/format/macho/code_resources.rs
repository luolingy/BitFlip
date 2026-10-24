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
}
