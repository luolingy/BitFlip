//! 真实上架 APK 的 `AndroidManifest.xml`：默认 `#[ignore]`。
//!
//! 为什么必须有一条真实样本测试（CLAUDE.md §7 与 §6.11）：合成样本证明"按契约工作"，
//! 但真实打包工具（aapt2 + R8 + 加固）产出的清单里，属性名靠**资源映射表**还原、
//! 字符串池可能是 UTF-8、还有各种"打包工具乱改头"的兼容分支。合成样本走的是
//! 字符串池回退路径，覆盖不到这些。
//!
//! 跑法（`--ignored` 要通过测试可执行文件直接传，`scripts/cargo.ps1` 会吃掉 `--`）：
//!
//! ```text
//! & .\scripts\cargo.ps1 test --offline -p bitflip-loader --test axml_real_apk --no-run
//! & .\.cargo-target\debug\deps\axml_real_apk-<hash>.exe --ignored --nocapture
//! ```

use std::path::PathBuf;

use bitflip_loader::format::{axml, zip};

/// 本机真实 APK 的位置：优先 `BITFLIP_TEST_APK`，否则退回本机已知的那一份。
fn sample_path() -> PathBuf {
    if let Ok(from_env) = std::env::var("BITFLIP_TEST_APK") {
        return PathBuf::from(from_env);
    }
    // 与 `dex_structure.rs` 同一个样本：本机唯一一个真实上架 APK（32 MB）。
    PathBuf::from(r"C:\Users\Administrator\Downloads\ah-app-release.apk")
}

fn read_manifest_member() -> (Vec<u8>, usize) {
    let path = sample_path();
    let bytes = std::fs::read(&path).unwrap_or_else(|error| {
        panic!(
            "读不到真实样本 {}: {error}\n（设 BITFLIP_TEST_APK 指向任意一个含 AndroidManifest.xml 的 APK）",
            path.display()
        )
    });
    let listing = zip::list_members(&bytes).expect("APK 本身应当是个能列成员的 ZIP");
    let index = listing
        .members
        .iter()
        .position(|member| member.name == "AndroidManifest.xml")
        .unwrap_or_else(|| panic!("样本里没有 AndroidManifest.xml"));
    let member = zip::read_member(&bytes, index).expect("能取出清单成员");
    (member, index)
}

#[test]
#[ignore = "需要本机真实 APK（32MB）；用 --ignored 手动跑"]
fn a_real_apk_manifest_parses_into_the_expected_fields() {
    let (member, index) = read_manifest_member();
    eprintln!(
        "样本 {} 的 AndroidManifest.xml：成员 #{index}、{} 字节",
        sample_path().display(),
        member.len()
    );
    assert!(
        axml::looks_like_axml(&member),
        "真实 APK 的清单必须是 AXML（头 03 00 08 00）"
    );

    let document = axml::parse(&member).expect("真实清单必须能解析");
    let facts = document.manifest();
    let xml = document.xml();

    eprintln!("包名 = {:?}", facts.package);
    eprintln!("versionCode = {:?}", facts.version_code);
    eprintln!("versionName = {:?}", facts.version_name);
    eprintln!(
        "minSdk = {:?} / targetSdk = {:?}",
        facts.min_sdk, facts.target_sdk
    );
    eprintln!(
        "组件：{} activity / {} service / {} receiver / {} provider，权限 {} 条",
        facts.activities.len(),
        facts.services.len(),
        facts.receivers.len(),
        facts.providers.len(),
        facts.permissions.len()
    );
    eprintln!("入口 activity = {:?}", facts.main_activities);
    eprintln!(
        "还原出的 XML {} 字节（设计文档实测 29 392 字节），解不出的引用 {} 处",
        xml.len(),
        facts.unresolved_references.len()
    );
    if !facts.notes.is_empty() {
        eprintln!("notes = {:?}", facts.notes);
    }

    assert_eq!(facts.root, "manifest", "根元素必须是 manifest");
    // 包名：至少要像"反向域名"，不写死具体值 —— 换样本不该让测试变红。
    let package = facts.package.as_deref().expect("真实 APK 一定有 package=");
    assert!(
        package.contains('.') && !package.contains(' '),
        "包名看起来不对：{package:?}"
    );
    assert!(
        !facts.activities.is_empty(),
        "上架 APK 不可能没有任何 activity"
    );
    assert!(!facts.permissions.is_empty(), "这个样本声明了权限");
    assert!(
        facts.version_code.is_some(),
        "versionCode 必须能读到（它是整数类型，最容易在类型处理上翻车）"
    );
    assert!(xml.contains("<manifest"), "还原出的 XML 必须有根元素");
    assert!(
        xml.len() > 10_000,
        "还原出的 XML 只有 {} 字节，与设计文档实测的 29 392 字节差太多",
        xml.len()
    );
}
