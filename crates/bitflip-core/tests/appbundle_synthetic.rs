//! `.app` 批量重签的**合成样本** CI 回归：不依赖真实 Mach-O 样本，可常驻 CI。
//!
//! 现存 `appbundle_real_app.rs` 是 `#[ignore]`（需真实 `.app`，CI 没有）。这条测试用
//! **合成**的已签名薄 Mach-O 二进制拼一个小 `.app`，把端到端契约钉进 CI：
//!
//! 1. 枚举数正确（造几个就是几个）；
//! 2. `--apply` 写到新目录、绝不原地改；
//! 3. 重签后每个二进制 `Session::open` 能解析且签名结论 **Intact/AdHoc**（自己自洽）；
//! 4. `CodeResources` 能读、条目数不丢、受影响条目的哈希被重算成磁盘新文件的真实哈希。
//!
//! 边界：合成二进制没有 CMS、没有 Apple 私钥——只验证"结构自洽 + 哈希自洽"，**不是**可信封印。

use bitflip_core::appbundle::{
    apply_resign_app, enumerate_machos, plan_resign_app, CodeResourcesStatus,
};
use bitflip_core::{OpenOptions, Session};
use bitflip_loader::format::macho::codesign::{
    build_code_directory, build_superblob, ResignParams,
};

fn align_up(v: u64, a: u64) -> u64 {
    (v + a - 1) & !(a - 1)
}

/// 造一个**合成的最小已签名薄 Mach-O 64 位小端**。带 `__TEXT` + `__LINKEDIT` +
/// `LC_CODE_SIGNATURE`，`codeLimit == dataoff`（Apple 真实布局）。签的是文件自身内容，
/// 但命令头是签后回填的，所以原始文件通常是 `Mismatch`（真实工具也是先填命令再签）；
/// 重签（`resign_macho_file`）会基于当前文件重算 → **重签后必为 Intact/AdHoc**。
/// `tag` 决定内容字节，让不同的二进制彼此不同。
fn build_signed_thin(tag: u8) -> Vec<u8> {
    let header_size = 32usize;
    let text_cmd = 72usize;
    let linkedit_cmd = 72usize;
    let codesig_cmd = 16usize;
    let sizeofcmds = (text_cmd + linkedit_cmd + codesig_cmd) as u32;
    let fixed = header_size + sizeofcmds as usize;
    let text_len = 0x1000usize;
    let code_limit = (fixed + text_len) as u32;

    let mut region = vec![0u8; fixed];
    region[0..4].copy_from_slice(&0xfeed_facfu32.to_le_bytes()); // MH_MAGIC_64
    region[4..8].copy_from_slice(&0x0100_0007u32.to_le_bytes()); // CPU_TYPE_X86_64
    region[8..12].copy_from_slice(&3u32.to_le_bytes()); // CPU_SUBTYPE_X86_64_ALL
    region[12..16].copy_from_slice(&3u32.to_le_bytes()); // cputype/subtype low
    region[16..20].copy_from_slice(&3u32.to_le_bytes()); // ncmds = 3
    region[20..24].copy_from_slice(&sizeofcmds.to_le_bytes());
    let mut content = vec![0u8; text_len];
    for (i, b) in content.iter_mut().enumerate() {
        *b = ((i as u8) ^ tag).wrapping_mul(31);
    }
    region.extend_from_slice(&content);
    assert_eq!(region.len(), code_limit as usize);

    let params = ResignParams {
        hash_type: 2,
        page_size_log: 12,
        code_limit,
        identifier: format!("com.example.mini{tag}"),
        entitlements_blob: None,
    };
    let cd = build_code_directory(&region, &params).expect("构造 CodeDirectory");
    let sb = build_superblob(&cd, None, None);

    let mut file = region;
    let dataoff = file.len() as u64;
    file.extend_from_slice(&sb);
    let datasize = sb.len() as u64;

    // __TEXT 段（header_size 处）。
    let text_at = header_size;
    file[text_at..text_at + 4].copy_from_slice(&0x19u32.to_le_bytes()); // LC_SEGMENT_64
    file[text_at + 4..text_at + 8].copy_from_slice(&(text_cmd as u32).to_le_bytes());
    file[text_at + 8..text_at + 24].copy_from_slice(b"__TEXT\0\0\0\0\0\0\0\0\0\0");
    let text_vmsize = align_up(u64::from(code_limit), 0x1000);
    file[text_at + 32..text_at + 40].copy_from_slice(&text_vmsize.to_le_bytes());
    file[text_at + 48..text_at + 56].copy_from_slice(&(u64::from(code_limit)).to_le_bytes());
    file[text_at + 56..text_at + 60].copy_from_slice(&5u32.to_le_bytes()); // maxprot RX
    file[text_at + 60..text_at + 64].copy_from_slice(&5u32.to_le_bytes()); // initprot RX

    // __LINKEDIT 段。
    let le_at = header_size + text_cmd;
    file[le_at..le_at + 4].copy_from_slice(&0x19u32.to_le_bytes());
    file[le_at + 4..le_at + 8].copy_from_slice(&(linkedit_cmd as u32).to_le_bytes());
    file[le_at + 8..le_at + 24].copy_from_slice(b"__LINKEDIT\0\0\0\0\0\0");
    let le_vmaddr = align_up(text_vmsize, 0x1000);
    file[le_at + 24..le_at + 32].copy_from_slice(&le_vmaddr.to_le_bytes());
    let le_vmsize = align_up(datasize.max(0x4000), 0x1000);
    file[le_at + 32..le_at + 40].copy_from_slice(&le_vmsize.to_le_bytes());
    file[le_at + 40..le_at + 48].copy_from_slice(&dataoff.to_le_bytes());
    file[le_at + 48..le_at + 56].copy_from_slice(&datasize.to_le_bytes());
    file[le_at + 56..le_at + 60].copy_from_slice(&1u32.to_le_bytes()); // initprot R

    // LC_CODE_SIGNATURE。
    let cs_at = header_size + text_cmd + linkedit_cmd;
    file[cs_at..cs_at + 4].copy_from_slice(&0x1du32.to_le_bytes());
    file[cs_at + 4..cs_at + 8].copy_from_slice(&(codesig_cmd as u32).to_le_bytes());
    file[cs_at + 8..cs_at + 12].copy_from_slice(&(dataoff as u32).to_le_bytes());
    file[cs_at + 12..cs_at + 16].copy_from_slice(&(datasize as u32).to_le_bytes());

    file
}

/// 造一份最小 XML-plist 形态的 `CodeResources`，把 `files2` 里每个路径的 `hash`/`hash2`
/// 填成占位（长度无所谓）——真实文件哈希必然不同，于是 `plan` 会把这些条目标为"受影响"。
fn build_code_resources(paths: &[&str]) -> String {
    let mut s = String::from(
        "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n<plist version=\"1.0\">\n<dict>\n\
         \t<key>files</key>\n\t<dict>\n",
    );
    for p in paths {
        s.push_str(&format!(
            "\t\t<key>{p}</key>\n\t\t<data>AAAAAAAAAAAAAAAAAAAAAAAAAAA=</data>\n"
        ));
    }
    s.push_str("\t</dict>\n\t<key>files2</key>\n\t<dict>\n");
    for p in paths {
        s.push_str(&format!(
            "\t\t<key>{p}</key>\n\t\t<dict>\n\
             \t\t\t<key>hash</key>\n\t\t\t<data>AAAAAAAAAAAAAAAAAAAAAAAAAAA=</data>\n\
             \t\t\t<key>hash2</key>\n\t\t\t<data>AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=</data>\n\
             \t\t</dict>\n"
        ));
    }
    s.push_str("\t</dict>\n\t<key>rules</key>\n\t<dict>\n\t\t<key>^.*</key>\n\t\t<true/>\n\t</dict>\n</dict>\n</plist>\n");
    s
}

#[test]
fn synthetic_app_resign_roundtrip_is_ci_safe() {
    let tmp = tempfile::tempdir().expect("临时目录");
    let app = tmp.path().join("Mini.app");
    let fw = app.join("Frameworks");
    std::fs::create_dir_all(&fw).expect("建目录");
    std::fs::create_dir_all(app.join("_CodeSignature")).expect("建 _CodeSignature");

    // 主可执行 + 一个 Frameworks 下的 dylib：两个不同的合成二进制。
    let main_bin = build_signed_thin(0x11);
    let lib_bin = build_signed_thin(0x77);
    std::fs::write(app.join("Mini"), &main_bin).expect("写主可执行");
    std::fs::write(fw.join("libMini.dylib"), &lib_bin).expect("写 dylib");

    // CodeResources 覆盖这两个二进制（占位哈希）。
    let cr = build_code_resources(&["Mini", "Frameworks/libMini.dylib"]);
    std::fs::write(app.join("_CodeSignature/CodeResources"), cr.as_bytes()).expect("写 CR");

    // 1) 枚举：正好 2 个 Mach-O。
    let machos = enumerate_machos(&app).expect("枚举");
    assert_eq!(machos.len(), 2, "应枚举到 2 个 Mach-O：{machos:?}");
    let rels: Vec<&str> = machos.iter().map(|m| m.rel.as_str()).collect();
    assert!(rels.contains(&"Mini"));
    assert!(
        rels.contains(&"Frameworks/libMini.dylib"),
        "相对路径用 / 分隔"
    );

    // 2) 只读计划：都能重签、CodeResources 解析到 2 条、两条都受影响。
    let plan = plan_resign_app(&app).expect("规划");
    assert_eq!(plan.machos.len(), 2);
    assert_eq!(
        plan.resignable.len(),
        2,
        "两个都应能重签：{:?}",
        plan.failed
    );
    assert!(plan.failed.is_empty());
    match &plan.coderes {
        CodeResourcesStatus::Parsed { entries, .. } => assert_eq!(*entries, 2),
        other => panic!("CodeResources 应解析成 2 条，实为 {other:?}"),
    }
    assert_eq!(plan.affected.len(), 2, "两个条目都会因重签而失配");

    // 3) 应用：写到新目录，绝不原地改。原包字节不变。
    let out = tmp.path().join("Mini.app.resigned");
    let report = apply_resign_app(&plan, &out).expect("应用");
    assert_eq!(report.resigned, 2);
    assert!(report.coderes_rewritten, "XML plist 应被重写");
    assert_eq!(
        std::fs::read(app.join("Mini")).expect("原文件"),
        main_bin,
        "原包必须一字节不动（绝不原地改）"
    );
    assert!(
        out.join("Frameworks/libMini.dylib").exists(),
        "保持相对路径结构"
    );

    // 4) 重签后每个二进制重新 parse，签名自洽（Intact/AdHoc）。
    for rel in ["Mini", "Frameworks/libMini.dylib"] {
        let dst = out.join(rel);
        let session = Session::open(&dst, OpenOptions::default())
            .unwrap_or_else(|e| panic!("重签后打不开 {rel}：{e}"));
        let obj = session
            .parsed()
            .unwrap_or_else(|| panic!("重签后 {rel} 解析结果为空"));
        assert!(obj.signature.applicable, "{rel} 应是 Mach-O");
        let verdict = obj.signature.verdict.as_str();
        assert!(
            matches!(verdict, "Intact" | "AdHoc"),
            "{rel} 重签后签名结论应自洽（Intact/AdHoc），实为 {verdict}：{}",
            obj.signature.notes.join("; ")
        );
    }

    // 5) CodeResources 条目数不丢，受影响条目的哈希被重算成磁盘新文件的真实哈希。
    use sha1::Digest as _;
    let cr_after = std::fs::read(out.join("_CodeSignature/CodeResources")).expect("读新 CR");
    let hashes = bitflip_core::extract_code_resource_hashes(&cr_after)
        .expect("重写后仍应是可解析 XML plist");
    assert_eq!(hashes.len(), 2, "条目数必须保持");
    for rel in ["Mini", "Frameworks/libMini.dylib"] {
        let disk = std::fs::read(out.join(rel)).expect("读磁盘新文件");
        let want_sha256 = sha2::Sha256::digest(&disk).to_vec();
        let entry = hashes
            .iter()
            .find(|h| h.path == rel)
            .unwrap_or_else(|| panic!("清单里应仍有 {rel}"));
        assert_eq!(
            entry.sha256.as_deref(),
            Some(want_sha256.as_slice()),
            "{rel} 的清单 SHA-256 应等于磁盘新文件的真实哈希（自洽）"
        );
    }
}
