//! AXML（Android 二进制 XML）—— M11 · M3 的第一片：只解 `AndroidManifest.xml`。
//!
//! # 为什么先只做清单
//!
//! 设计文档（`docs/APK-DEX-DESIGN.md` §M3）把 AXML 与 `resources.arsc` 放在同一个
//! 里程碑里，但明确允许"第一版只做能读出包名与权限"。先做清单的理由是**价值/风险比**：
//! 清单是一个**自足**的二进制 XML（字符串池 + 元素/属性树），不依赖资源表；
//! 而 `resources.arsc` 是带类型、配置、别名链的资源数据库，复杂度与它对用户的价值
//! （把 `@7f13002e` 变成"应用名"）不成正比 —— 它排在下一片。
//!
//! **不读 `resources.arsc` 的后果必须说出来**：属性值以 `@` 开头的是**资源引用**，
//! 我们没有资源表，解不出来。这时**原样保留**（`@7f13002e`），并列进
//! [`ManifestFacts::unresolved_references`] —— 不是"解析失败"，也不是 0。
//!
//! # 解析交给 `apk-info-axml`，本模块只做适配
//!
//! 与 DEX 那边同一条边界：只借它的**事实层**（`AXML::new` 与元素的遍历），
//! 不接它的转换器/JSON 导出（`converter` 特性我们没开）。它输出的文本与属性值
//! 我们**不重新解释**：它给什么就是什么，我们只负责组织成稳定的形状。
//!
//! # 一个坑：属性名
//!
//! AXML 里属性名是**字符串池索引**，不是文本；文本要过 `res_value` 的类型。
//! 库用 phf 预编译的表把 `android:name` 这类名字还原出来 —— 所以我们不自己
//! `match` 名字表：那会漏掉新版本 Android 的属性，而且错了很难发现
//! （`value` 照样有值，只是挂在别的名字下）。

use apk_info_axml::AXML;
use apk_info_xml::Element;
use thiserror::Error;

/// AXML 文件头的类型码与头长度（`03 00 08 00`，即 `RES_XML_TYPE` + headerSize 8）。
///
/// 规范（`frameworks/base/libs/androidfw/include/androidfw/ResourceTypes.h`）里
/// `RES_XML_TYPE = 0x0003`，`ResChunk_header.headerSize = 8`。
pub const AXML_MAGIC: u32 = 0x0008_0003;

/// 单份 AXML 的字节上限：32 MiB。
///
/// 清单是**小文件**（真实上架 APK 里 100 KB 量级），32 MiB 是三个数量级的余量。
/// 上限存在的理由与 DEX 那边一样：解析前先挡，不要用内存换一句"太大"
/// （见 `format::dex::MAX_DEX_BYTES` 的说明）。
pub const MAX_AXML_BYTES: usize = 32 * 1024 * 1024;

/// AXML 解析错误。
#[derive(Debug, Error)]
pub enum AxmlError {
    /// 这份输入超过 [`MAX_AXML_BYTES`]，**一个字节都没解析**。
    #[error("这份 AXML 有 {size} 字节，超过上限 {limit} 字节：解析器不解这么大的清单文件")]
    TooLarge {
        /// 实际字节数。
        size: usize,
        /// 上限（[`MAX_AXML_BYTES`]）。
        limit: usize,
    },
    /// 库拒绝了这份文件。
    ///
    /// 原样带出库的说明：它的错误枚举区分"头坏了 / 字符串池坏了 / 树坏了"，
    /// 这些信息对判断"是文件不完整还是我们读错"很关键，不该被压成一句话。
    #[error("AXML 解析失败: {source}")]
    Parse {
        /// 库的原始错误。
        #[source]
        source: apk_info_axml::errors::AXMLError,
    },
}

/// 这个前缀看起来是 AXML 吗。
///
/// 只看 4 字节的类型码 + 头长度。**不判内容合不合规** —— 那是解析器的职责，
/// 嗅探只要回答"该不该走 AXML 这条路"。判多了会把"版本/长度不对"这种精确结论
/// 降级成"不是 AXML"（与 `format::dex::looks_like_dex` 同一条原则）。
#[must_use]
pub fn looks_like_axml(bytes: &[u8]) -> bool {
    bytes.len() >= 4 && u32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]) == AXML_MAGIC
}

/// 一份解析好的 AXML 文档。
///
/// 内部持有库的结构，**不复制成我们自己的树**：XML 文本与摘要都按需从库取
/// （CLAUDE.md §4 禁止把每一项物化成带 `String` 的对象）。
pub struct AxmlDocument {
    axml: AXML,
}

impl std::fmt::Debug for AxmlDocument {
    // 手写而不是 `derive`：这份结构里有整棵元素树，`{:#?}` 会打出几万行，
    // 而它出现在 `Debug` 里的**唯一**场合是测试失败信息（`expect_err` 要 `Debug`）。
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AxmlDocument")
            .field("root", &self.axml.root.name())
            .finish_non_exhaustive()
    }
}

impl AxmlDocument {
    /// 还原出来的可读 XML 文本。
    ///
    /// 这是**库的渲染**，不是我们重新拼的：同样的输入两次调用逐字节相同。
    #[must_use]
    pub fn xml(&self) -> String {
        self.axml.get_xml_string()
    }

    /// 根元素的标签名（清单应当是 `manifest`）。
    #[must_use]
    pub fn root_element(&self) -> &str {
        self.axml.root.name()
    }

    /// 清单摘要。
    ///
    /// 根不是 `manifest` 时**不假装**：除了 `root` 之外全部是 `None`/空，并附一条
    /// 说明 —— 那说明"这不是清单"，不是"清单里没有这些字段"。
    #[must_use]
    pub fn manifest(&self) -> ManifestFacts {
        let mut facts = ManifestFacts {
            root: self.root_element().to_string(),
            ..ManifestFacts::default()
        };

        if facts.root != "manifest" {
            facts.notes.push(format!(
                "根元素是 <{}>，不是 <manifest>：这份 AXML 不是应用清单，摘要里的字段一律留空",
                facts.root
            ));
            facts
                .unresolved_references
                .extend(self.unresolved_references(&self.axml.root));
            return facts;
        }

        let root = &self.axml.root;
        facts.package = attr(root, "package");
        facts.version_code = attr(root, "versionCode");
        facts.version_name = attr(root, "versionName");
        // `uses-sdk` 是 manifest 的直接子元素；minSdk/targetSdk 挂在它身上。
        facts.min_sdk = self
            .axml
            .get_attribute_value("uses-sdk", "minSdkVersion", None);
        facts.target_sdk = self
            .axml
            .get_attribute_value("uses-sdk", "targetSdkVersion", None);

        facts.main_activities = strings(self.axml.get_main_activities());
        facts.activities = strings(self.axml.get_all_attribute_values("activity", "name"));
        facts.services = strings(self.axml.get_all_attribute_values("service", "name"));
        facts.receivers = strings(self.axml.get_all_attribute_values("receiver", "name"));
        facts.providers = strings(self.axml.get_all_attribute_values("provider", "name"));
        // 两种权限标签都要看：`uses-permission-sdk-23` 只在 Android 6+ 生效，
        // 但它出现在文件里就说明作者想要这条权限 —— 漏掉它，摘要会少一条真实声明。
        facts.permissions = strings(
            self.axml
                .get_all_attribute_values("uses-permission", "name")
                .chain(
                    self.axml
                        .get_all_attribute_values("uses-permission-sdk-23", "name"),
                ),
        );

        facts
            .unresolved_references
            .extend(self.unresolved_references(root));

        // 降级说明：只在这份文件**真的**有解不出来的引用时才说，不预先喊一遍。
        if !facts.unresolved_references.is_empty() {
            facts.notes.push(format!(
                "有 {} 处属性是资源引用（以 `@` 开头），本次**没有读 `resources.arsc`**：\
                 值按原始引用保留，没有替换成资源里的文本",
                facts.unresolved_references.len()
            ));
        }
        facts
    }

    /// 走一遍树，把"以 `@` 开头、因而需要资源表才能解"的属性值收集起来。
    fn unresolved_references(&self, root: &Element) -> Vec<String> {
        let mut out = Vec::new();
        let mut stack = vec![root];
        while let Some(element) = stack.pop() {
            for attribute in element.attributes() {
                if attribute.value().starts_with('@') {
                    out.push(format!(
                        "<{} {}={}>",
                        element.name(),
                        attribute.name(),
                        attribute.value()
                    ));
                }
            }
            stack.extend(element.childrens());
        }
        out
    }
}

/// 解析一份 AXML。
///
/// # Errors
///
/// 输入超过 [`MAX_AXML_BYTES`]（[`AxmlError::TooLarge`]），或库拒绝这份文件
/// （[`AxmlError::Parse`]，带出库的原始分类）。
pub fn parse(bytes: &[u8]) -> Result<AxmlDocument, AxmlError> {
    if bytes.len() > MAX_AXML_BYTES {
        return Err(AxmlError::TooLarge {
            size: bytes.len(),
            limit: MAX_AXML_BYTES,
        });
    }
    // 库的签名要一个 `&mut &[u8]`（它会推进游标）；我们只关心结果，不关心推进到哪。
    let mut cursor = bytes;
    let axml = AXML::new(&mut cursor, None).map_err(|source| AxmlError::Parse { source })?;
    Ok(AxmlDocument { axml })
}

/// 应用清单里我们**如实**能拿到的那些字段。
///
/// 全部是 `Option` / `Vec`：文件里没有就是 `None` / 空，不用 0 或空串冒充
/// （CLAUDE.md §7）。`versionCode` 之类在 AXML 里是**整数类型**，这里是库渲染出的
/// 文本 —— 保留原样是为了不丢掉"它本来是什么类型"这个信息。
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ManifestFacts {
    /// 根元素标签名（真实清单是 `manifest`）。
    pub root: String,
    /// `package=` 属性。
    pub package: Option<String>,
    /// `android:versionCode`。
    pub version_code: Option<String>,
    /// `android:versionName`。
    pub version_name: Option<String>,
    /// `<uses-sdk android:minSdkVersion>`。
    pub min_sdk: Option<String>,
    /// `<uses-sdk android:targetSdkVersion>`。
    pub target_sdk: Option<String>,
    /// 带 `MAIN` + `LAUNCHER`/`INFO` 的 activity（库按系统的判定规则算出来的）。
    pub main_activities: Vec<String>,
    /// `<activity android:name>`（按文件顺序）。
    pub activities: Vec<String>,
    /// `<service android:name>`。
    pub services: Vec<String>,
    /// `<receiver android:name>`。
    pub receivers: Vec<String>,
    /// `<provider android:name>`。
    pub providers: Vec<String>,
    /// `<uses-permission>` / `<uses-permission-sdk-23>` 的 `android:name`。
    pub permissions: Vec<String>,
    /// 以 `@` 开头、需要 `resources.arsc` 才能解的属性（原样保留的值）。
    pub unresolved_references: Vec<String>,
    /// 降级说明（"没读资源表"、"根不是 manifest"这类）。
    pub notes: Vec<String>,
}

/// 读一个属性；空字符串按"没有"处理（AXML 里不该出现，出现了就是文件的问题）。
fn attr(element: &Element, name: &str) -> Option<String> {
    element
        .attr(name)
        .filter(|v| !v.is_empty())
        .map(String::from)
}

fn strings<'a>(iter: impl Iterator<Item = &'a str>) -> Vec<String> {
    iter.filter(|value| !value.is_empty())
        .map(String::from)
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_magic_check_only_answers_whether_this_is_axml() {
        assert!(looks_like_axml(&[0x03, 0x00, 0x08, 0x00]));
        // 头长度不是 8：**不算** AXML 这条路。规范里文件头的 `headerSize` 恒为 8，
        // 别的是"头坏了"，而坏头交给 `parse` 报 `HeaderSizeError`（比嗅探更精确）。
        assert!(!looks_like_axml(&[0x03, 0x00, 0x04, 0x00]));
        assert!(!looks_like_axml(&[0x03, 0x00, 0x08]));
        assert!(!looks_like_axml(b"<manifest></manifest>"));
        assert!(!looks_like_axml(&[]));
    }

    #[test]
    fn an_oversized_input_is_refused_before_parsing() {
        let error = parse(&vec![0u8; MAX_AXML_BYTES + 1]).expect_err("超限必须拒绝");
        assert!(matches!(
            error,
            AxmlError::TooLarge { size, limit }
                if size == MAX_AXML_BYTES + 1 && limit == MAX_AXML_BYTES
        ));
    }

    #[test]
    fn a_non_axml_blob_is_an_error_not_an_empty_document() {
        // 4 字节的"像 AXML"的头 + 一堆垃圾：库必须报错，而不是给出一份空清单。
        let mut bytes = vec![0x03, 0x00, 0x08, 0x00];
        bytes.extend(std::iter::repeat_n(0x41u8, 64));
        let error = parse(&bytes).expect_err("垃圾输入必须报错");
        assert!(matches!(error, AxmlError::Parse { .. }), "{error:?}");
    }
}
