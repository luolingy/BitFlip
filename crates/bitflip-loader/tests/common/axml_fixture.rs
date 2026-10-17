//! 合成 AXML（Android 二进制 XML）样本。
//!
//! # 逐字节按规范拼，不按解析器的实现拼（CLAUDE.md §6.11）
//!
//! 布局出处：`frameworks/base/libs/androidfw/include/androidfw/ResourceTypes.h`
//! （Android 16 对应版本），各结构的字段顺序与大小如下：
//!
//! ```text
//! ResChunk_header      u16 type; u16 headerSize; u32 size;      // 8 字节
//! ResStringPool_header u16 type; u16 headerSize; u32 size;
//!                      u32 stringCount; u32 styleCount; u32 flags;
//!                      u32 stringsStart; u32 stylesStart;        // 28 字节头
//! ResXMLTree_node      ResChunk_header header; u32 lineNumber; u32 comment;
//!                      // headerSize = 0x10（库只认这个值，见下）
//! ResXMLTree_attrExt   u32 ns; u32 name; u16 attributeStart; u16 attributeSize;
//!                      u16 attributeCount; u16 idIndex; u16 classIndex; u16 styleIndex;
//! ResXMLTree_attribute u32 ns; u32 name; u32 rawValue;
//!                      u16 size; u8 res0; u8 dataType; u32 data;   // 20 字节
//! ResXMLTree_endElementExt u32 ns; u32 name;
//! ```
//!
//! 三个**必须照抄**的细节（错了会被库跳过或整棵树错位）：
//!
//! 1. XML 各类节点的 `headerSize` 必须是 **0x10**。库对 `!= 0x10` 的块直接跳过并告警，
//!    这是它兼容"打包工具乱改头"的策略，不是规范要求 —— 但我们要生成"正常"的文件。
//! 2. `ResXMLTree_node.size` 必须**恰好**等于 `0x10 + 20 + 20 × 属性数`。库会按
//!    `size` 把多余字节吞掉，写大了就会吃掉后面的块。
//! 3. 元素/属性没有命名空间时写 **0xFFFF_FFFF**，不是 0。写 0 会命中字符串池的第 0 条
//!    （"android"），于是属性凭空带上 `android:` 前缀。
//!
//! # 这份样本走的是"属性名回退"路径
//!
//! 真实 APK 里属性名通常靠 `RES_XML_RESOURCE_MAP_TYPE` 把字符串池索引映射成
//! `0x0101xxxx` 资源 id，再由库的属性名表还原成 `name`/`versionCode` 这类名字。
//! 这里我们**故意不写资源映射**（只放一个空映射块），让属性名直接来自字符串池 ——
//! 因为这份样本要验证的是我们自己的适配层，而不是库的内部表（那张表由真实 APK
//! 的 `#[ignore]` 测试覆盖）。两种路径都真实存在，不写资源映射**不是**在糊弄。

use std::collections::HashMap;

/// 文件头：`RES_XML_TYPE` + `headerSize = 8`（`03 00 08 00`）。
const RES_XML_TYPE: u16 = 0x0003;
/// 字符串池。
const RES_STRING_POOL_TYPE: u16 = 0x0001;
/// 资源映射（这里只写空块，见模块文档）。
const RES_XML_RESOURCE_MAP_TYPE: u16 = 0x0180;
const RES_XML_START_NAMESPACE_TYPE: u16 = 0x0100;
const RES_XML_END_NAMESPACE_TYPE: u16 = 0x0101;
const RES_XML_START_ELEMENT_TYPE: u16 = 0x0102;
const RES_XML_END_ELEMENT_TYPE: u16 = 0x0103;

/// `Res_value.dataType`：字符串池索引。
const TYPE_STRING: u8 = 0x03;
/// `Res_value.dataType`：十进制整数。
const TYPE_INT_DEC: u8 = 0x10;
/// `Res_value.dataType`：资源引用。
const TYPE_REFERENCE: u8 = 0x01;

/// "没有命名空间"的约定值。
const NO_NS: u32 = 0xFFFF_FFFF;

const ANDROID_NS_PREFIX: &str = "android";
const ANDROID_NS_URI: &str = "http://schemas.android.com/apk/res/android";

/// 一份要生成的清单。
///
/// 字段刻意只覆盖**我们真的会读**的那些：写不出来的字段，测不出来的行为。
pub struct ManifestSpec<'a> {
    /// 根元素名。真实清单是 `manifest`；用别的名字可以测"根不是 manifest"的分支。
    pub root: &'a str,
    /// 根元素的 `package=`。
    pub package: &'a str,
    /// `android:versionCode`（整数类型）。
    pub version_code: u32,
    /// `android:versionName`。
    pub version_name: &'a str,
    /// `<uses-sdk android:minSdkVersion>`。
    pub min_sdk: u32,
    /// `<uses-sdk android:targetSdkVersion>`。
    pub target_sdk: u32,
    /// 每个 `<uses-permission android:name>`。
    pub permissions: &'a [&'a str],
    /// `(类名, 是否带 MAIN/LAUNCHER)`。
    pub activities: &'a [(&'a str, bool)],
    /// `<application android:label>` 写成**资源引用**时给的资源 id（例如 `0x7f0d0001`）。
    ///
    /// 用来验证"没读 `resources.arsc` 时引用原样保留并列进 `unresolved_references`"。
    /// 存 id 而不是 `@string/app_label` 这样的文本：AXML 的引用属性里真正的值就是 id，
    /// 文本只在有资源表时才能反查 —— 存文本等于让样本假装自己有资源表。
    pub label_reference: Option<u32>,
}

/// 一份完整、正常的清单（字段全部非空，便于断言具体值）。
#[must_use]
pub fn demo() -> ManifestSpec<'static> {
    ManifestSpec {
        root: "manifest",
        package: "com.example.demo",
        version_code: 42,
        version_name: "1.2.3",
        min_sdk: 21,
        target_sdk: 33,
        permissions: &["android.permission.INTERNET", "android.permission.CAMERA"],
        activities: &[
            ("com.example.demo.MainActivity", true),
            ("com.example.demo.OtherActivity", false),
        ],
        label_reference: Some(0x7f0d_0001),
    }
}

/// 一份**不是**清单的 AXML（根元素是 `resources`）。
#[must_use]
pub fn not_a_manifest() -> ManifestSpec<'static> {
    ManifestSpec {
        root: "resources",
        package: "com.example.demo",
        version_code: 0,
        version_name: "",
        min_sdk: 0,
        target_sdk: 0,
        permissions: &[],
        activities: &[],
        label_reference: None,
    }
}

/// 字符串池：按需 intern，保证同一文本只有一个索引。
///
/// 用 **UTF-16** 编码（`flags` 最高位为 0）：每条是 `u16 长度(码元数) + 码元 + u16 0`。
/// UTF-8 编码要多写"字符数 + 字节数"两段变长长度，这里没有收益，就不引入多一种编码。
#[derive(Default)]
struct Strings {
    values: Vec<String>,
    index: HashMap<String, u32>,
}

impl Strings {
    fn intern(&mut self, text: &str) -> u32 {
        if let Some(&idx) = self.index.get(text) {
            return idx;
        }
        let idx = self.values.len() as u32;
        self.values.push(text.to_string());
        self.index.insert(text.to_string(), idx);
        idx
    }

    fn encode(&self) -> Vec<u8> {
        let mut data = Vec::new();
        let mut offsets = Vec::with_capacity(self.values.len());
        for text in &self.values {
            offsets.push(u32::try_from(data.len()).expect("样本很小"));
            let units: Vec<u16> = text.encode_utf16().collect();
            data.extend_from_slice(&u16::try_from(units.len()).expect("样本很小").to_le_bytes());
            for unit in units {
                data.extend_from_slice(&unit.to_le_bytes());
            }
            data.extend_from_slice(&0u16.to_le_bytes());
        }
        // 头部 28 字节 + 偏移表，之后才是字符串本体。
        let strings_start = 28 + 4 * self.values.len();
        let mut out = Vec::with_capacity(strings_start + data.len());
        out.extend_from_slice(&RES_STRING_POOL_TYPE.to_le_bytes());
        out.extend_from_slice(&28u16.to_le_bytes());
        out.extend_from_slice(
            &u32::try_from(strings_start + data.len())
                .expect("样本很小")
                .to_le_bytes(),
        );
        out.extend_from_slice(
            &u32::try_from(self.values.len())
                .expect("样本很小")
                .to_le_bytes(),
        );
        out.extend_from_slice(&0u32.to_le_bytes()); // styleCount
        out.extend_from_slice(&0u32.to_le_bytes()); // flags：0 = UTF-16
        out.extend_from_slice(
            &u32::try_from(strings_start)
                .expect("样本很小")
                .to_le_bytes(),
        );
        out.extend_from_slice(&0u32.to_le_bytes()); // stylesStart
        for offset in offsets {
            out.extend_from_slice(&offset.to_le_bytes());
        }
        out.extend_from_slice(&data);
        out
    }
}

/// 一个 XML 节点块：`ResXMLTree_node` 头（`headerSize` 固定 0x10）+ 节点体。
fn xml_chunk(kind: u16, body: &[u8]) -> Vec<u8> {
    let size = 16 + body.len();
    let mut out = Vec::with_capacity(size);
    out.extend_from_slice(&kind.to_le_bytes());
    out.extend_from_slice(&0x0010u16.to_le_bytes());
    out.extend_from_slice(&u32::try_from(size).expect("样本很小").to_le_bytes());
    out.extend_from_slice(&1u32.to_le_bytes()); // lineNumber
    out.extend_from_slice(&NO_NS.to_le_bytes()); // comment：-1 表示没有
    out.extend_from_slice(body);
    out
}

/// 一个属性（20 字节）。
fn attribute(ns: u32, name: u32, raw: u32, data_type: u8, data: u32) -> Vec<u8> {
    let mut out = Vec::with_capacity(20);
    out.extend_from_slice(&ns.to_le_bytes());
    out.extend_from_slice(&name.to_le_bytes());
    out.extend_from_slice(&raw.to_le_bytes());
    out.extend_from_slice(&8u16.to_le_bytes()); // Res_value.size
    out.push(0); // res0
    out.push(data_type);
    out.extend_from_slice(&data.to_le_bytes());
    out
}

/// `RES_XML_START_ELEMENT_TYPE`：`ns + name + 属性表`。
fn start_element(name: u32, attributes: &[Vec<u8>]) -> Vec<u8> {
    let mut body = Vec::with_capacity(20 + 20 * attributes.len());
    body.extend_from_slice(&NO_NS.to_le_bytes());
    body.extend_from_slice(&name.to_le_bytes());
    body.extend_from_slice(&20u16.to_le_bytes()); // attributeStart
    body.extend_from_slice(&20u16.to_le_bytes()); // attributeSize
    body.extend_from_slice(
        &u16::try_from(attributes.len())
            .expect("样本很小")
            .to_le_bytes(),
    );
    body.extend_from_slice(&0u16.to_le_bytes()); // idIndex
    body.extend_from_slice(&0u16.to_le_bytes()); // classIndex
    body.extend_from_slice(&0u16.to_le_bytes()); // styleIndex
    for attribute in attributes {
        body.extend_from_slice(attribute);
    }
    xml_chunk(RES_XML_START_ELEMENT_TYPE, &body)
}

/// `RES_XML_END_ELEMENT_TYPE`：只有 `ns + name`。
fn end_element(name: u32) -> Vec<u8> {
    let mut body = Vec::with_capacity(8);
    body.extend_from_slice(&NO_NS.to_le_bytes());
    body.extend_from_slice(&name.to_le_bytes());
    xml_chunk(RES_XML_END_ELEMENT_TYPE, &body)
}

/// 命名空间开始/结束块。
fn namespace(kind: u16, prefix: u32, uri: u32) -> Vec<u8> {
    let mut body = Vec::with_capacity(8);
    body.extend_from_slice(&prefix.to_le_bytes());
    body.extend_from_slice(&uri.to_le_bytes());
    xml_chunk(kind, &body)
}

/// 按 [`ManifestSpec`] 生成一份 AXML 字节流。
#[must_use]
pub fn build(spec: &ManifestSpec<'_>) -> Vec<u8> {
    let mut strings = Strings::default();
    let android = strings.intern(ANDROID_NS_PREFIX);
    let android_uri = strings.intern(ANDROID_NS_URI);

    // 先把要用的名字 intern 出来，再拼块 —— 顺序决定池里的索引，但索引只在本函数内用。
    let root = strings.intern(spec.root);
    let package_attr = strings.intern("package");
    let package_value = strings.intern(spec.package);
    let version_code = strings.intern("versionCode");
    let version_name = strings.intern("versionName");
    let uses_sdk = strings.intern("uses-sdk");
    let min_sdk = strings.intern("minSdkVersion");
    let target_sdk = strings.intern("targetSdkVersion");
    let uses_permission = strings.intern("uses-permission");
    let name = strings.intern("name");
    let application = strings.intern("application");
    let label = strings.intern("label");

    let mut body = Vec::new();
    body.extend_from_slice(&namespace(
        RES_XML_START_NAMESPACE_TYPE,
        android,
        android_uri,
    ));

    let vc = strings.intern(spec.version_name);
    body.extend_from_slice(&start_element(
        root,
        &[
            attribute(
                NO_NS,
                package_attr,
                package_value,
                TYPE_STRING,
                package_value,
            ),
            attribute(NO_NS, version_code, NO_NS, TYPE_INT_DEC, spec.version_code),
            attribute(NO_NS, version_name, vc, TYPE_STRING, vc),
        ],
    ));

    // 只有真正的清单才有这些子元素；根不是 manifest 时保持朴素，免得样本自相矛盾。
    if spec.root == "manifest" {
        body.extend_from_slice(&start_element(
            uses_sdk,
            &[
                attribute(NO_NS, min_sdk, NO_NS, TYPE_INT_DEC, spec.min_sdk),
                attribute(NO_NS, target_sdk, NO_NS, TYPE_INT_DEC, spec.target_sdk),
            ],
        ));
        body.extend_from_slice(&end_element(uses_sdk));

        for permission in spec.permissions {
            let text = strings.intern(permission);
            body.extend_from_slice(&start_element(
                uses_permission,
                &[attribute(NO_NS, name, text, TYPE_STRING, text)],
            ));
            body.extend_from_slice(&end_element(uses_permission));
        }

        let mut application_attributes = Vec::new();
        if let Some(reference) = spec.label_reference {
            // 引用类型：`data` 是资源 id，`rawValue` 没有（-1）。库渲染成 `@7f0d0001`。
            application_attributes.push(attribute(NO_NS, label, NO_NS, TYPE_REFERENCE, reference));
        }
        body.extend_from_slice(&start_element(application, &application_attributes));

        let action = strings.intern("action");
        let category = strings.intern("category");
        let intent_filter = strings.intern("intent-filter");
        let activity = strings.intern("activity");
        for (class, is_main) in spec.activities {
            let class_idx = strings.intern(class);
            body.extend_from_slice(&start_element(
                activity,
                &[attribute(NO_NS, name, class_idx, TYPE_STRING, class_idx)],
            ));
            if *is_main {
                body.extend_from_slice(&start_element(intent_filter, &[]));
                let main = strings.intern("android.intent.action.MAIN");
                body.extend_from_slice(&start_element(
                    action,
                    &[attribute(NO_NS, name, main, TYPE_STRING, main)],
                ));
                body.extend_from_slice(&end_element(action));
                let launcher = strings.intern("android.intent.category.LAUNCHER");
                body.extend_from_slice(&start_element(
                    category,
                    &[attribute(NO_NS, name, launcher, TYPE_STRING, launcher)],
                ));
                body.extend_from_slice(&end_element(category));
                body.extend_from_slice(&end_element(intent_filter));
            }
            body.extend_from_slice(&end_element(activity));
        }

        body.extend_from_slice(&end_element(application));
    }
    body.extend_from_slice(&end_element(root));
    body.extend_from_slice(&namespace(RES_XML_END_NAMESPACE_TYPE, android, android_uri));

    let pool = strings.encode();
    // 空的资源映射块（8 字节头，无条目）—— 见模块文档第 3 段。
    let mut resource_map = Vec::with_capacity(8);
    resource_map.extend_from_slice(&RES_XML_RESOURCE_MAP_TYPE.to_le_bytes());
    resource_map.extend_from_slice(&8u16.to_le_bytes());
    resource_map.extend_from_slice(&8u32.to_le_bytes());

    let total = 8 + pool.len() + resource_map.len() + body.len();
    let mut out = Vec::with_capacity(total);
    out.extend_from_slice(&RES_XML_TYPE.to_le_bytes());
    out.extend_from_slice(&8u16.to_le_bytes());
    out.extend_from_slice(&u32::try_from(total).expect("样本很小").to_le_bytes());
    out.extend_from_slice(&pool);
    out.extend_from_slice(&resource_map);
    out.extend_from_slice(&body);
    out
}
