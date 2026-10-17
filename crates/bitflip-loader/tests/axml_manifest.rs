//! AXML 适配层的黄金测试：合成样本在默认（非 `--ignored`）测试里跑。
//!
//! 合成样本由 `common/axml_fixture.rs` 按规范逐字节拼出（那里的模块文档写了
//! 三个必须照抄的细节）。**真实上架 APK 的清单**另有一条 `#[ignore]` 测试
//! （`axml_real_apk.rs`）—— 两种来源都要：合成样本证明我们的适配层按契约工作，
//! 真实样本证明库在真实打包工具产物上不抖。

#[path = "common/axml_fixture.rs"]
mod fixture;

use bitflip_loader::format::axml;

#[test]
fn a_synthetic_manifest_yields_the_fields_it_declares() {
    let bytes = fixture::build(&fixture::demo());
    let document = axml::parse(&bytes).expect("合成样本必须能解析");

    assert_eq!(document.root_element(), "manifest");

    let facts = document.manifest();
    assert_eq!(facts.root, "manifest");
    assert_eq!(facts.package.as_deref(), Some("com.example.demo"));
    // versionCode 在 AXML 里是**整数类型**（`TYPE_INT_DEC`），适配层保留库渲染出的文本。
    assert_eq!(facts.version_code.as_deref(), Some("42"));
    assert_eq!(facts.version_name.as_deref(), Some("1.2.3"));
    assert_eq!(facts.min_sdk.as_deref(), Some("21"));
    assert_eq!(facts.target_sdk.as_deref(), Some("33"));

    assert_eq!(
        facts.permissions,
        vec![
            "android.permission.INTERNET".to_string(),
            "android.permission.CAMERA".to_string(),
        ]
    );
    // 文件顺序要保住：摘要的用处之一就是"这个 APK 声明了哪些组件"，
    // 乱序会让与 `aapt dump` 之类的输出对不上。
    assert_eq!(
        facts.activities,
        vec![
            "com.example.demo.MainActivity".to_string(),
            "com.example.demo.OtherActivity".to_string(),
        ]
    );
    assert_eq!(
        facts.main_activities,
        vec!["com.example.demo.MainActivity".to_string()],
        "只有带 MAIN + LAUNCHER 的那个才算入口 activity"
    );

    // 引用属性的真实值是**资源 id**（`@7f0d0001`），文本要靠资源表才能反查；
    // 没读 `resources.arsc` 就该原样保留并如实列出，不能悄悄丢掉、也不能用空串冒充。
    assert!(
        facts
            .unresolved_references
            .iter()
            .any(|item| item.contains("label=@7f0d0001")),
        "解不出来的引用必须在 unresolved_references 里，实际是 {:?}",
        facts.unresolved_references
    );
    assert!(
        facts
            .notes
            .iter()
            .any(|note| note.contains("resources.arsc")),
        "没读资源表这件事必须说出来，实际 notes 是 {:?}",
        facts.notes
    );

    let xml = document.xml();
    assert!(
        xml.contains("<manifest"),
        "还原出的 XML 应当有根元素：{xml}"
    );
    assert!(xml.contains("com.example.demo.MainActivity"), "{xml}");
}

#[test]
fn a_non_manifest_axml_reports_its_root_instead_of_pretending() {
    let bytes = fixture::build(&fixture::not_a_manifest());
    let document = axml::parse(&bytes).expect("样本本身是合法 AXML");

    let facts = document.manifest();
    assert_eq!(facts.root, "resources");
    // 关键：不是"清单里没有这些字段"，而是"这不是清单"。两者在界面上要能分开。
    assert_eq!(facts.package, None);
    assert!(facts.activities.is_empty());
    assert!(
        facts.notes.iter().any(|note| note.contains("<resources>")),
        "根元素不是 manifest 时必须点名说清楚，实际 notes 是 {:?}",
        facts.notes
    );
}

#[test]
fn the_same_input_renders_the_same_xml_twice() {
    // 渲染交给我们信任的库，但"两次一样"是适配层的契约：界面上刷新不该跳字。
    let bytes = fixture::build(&fixture::demo());
    let first = axml::parse(&bytes).expect("能解析").xml();
    let second = axml::parse(&bytes).expect("能解析").xml();
    assert_eq!(first, second);
    assert!(!first.is_empty());
}
