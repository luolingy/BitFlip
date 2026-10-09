//! PDB 身份核对（GUID/age）的测试。
//!
//! 为什么值得单独一个文件：只看**路径**找 PDB 是不够的 —— 同目录放着一个上一次构建留下的
//! 同名 PDB 是很常见的事，名字对、内容不对，用它就会把旧的行号/类型安到新镜像上。
//! 这里对照 lld-link 真实产物验证"配得上"的判定，并把不可能真造出来的那半边（GUID 不符）
//! 用构造数据钉住。

use std::path::PathBuf;

fn fixtures() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("..")
        .join("..")
        .join("tests")
        .join("fixtures")
        .join("generated")
}

fn record_for(name: &str) -> Option<bitflip_debug::codeview::Record> {
    let bytes = std::fs::read(fixtures().join(name)).ok()?;
    bitflip_debug::codeview::find(&bytes)
}

/// 真实样本上的"配得上"：记录里的 GUID/age 必须与 PDB 自己报告的一致。
///
/// 走不通说明两个解析器里有一个读错了 —— 这正是上一版 `Type` 偏移读错时缺的那条检查。
#[test]
fn the_recorded_identity_matches_the_pdb_it_names() {
    let Some(record) = record_for("m8-pdb.exe") else {
        eprintln!("SKIPPED: 缺少 tests/fixtures/generated/m8-pdb.exe");
        return;
    };
    let pdb_path = PathBuf::from(&record.path);
    let Ok(pdb_bytes) = std::fs::read(&pdb_path) else {
        eprintln!("SKIPPED: 记录里的 PDB 不在 {}", pdb_path.display());
        return;
    };
    let (guid, age) =
        bitflip_debug::pdb::pdb_identity(&pdb_bytes).expect("fixture 的 PDB 应当能读出 GUID/age");
    eprintln!(
        "record guid={} age={} | pdb guid={guid} age={age}",
        bitflip_debug::codeview::guid_text(&record.guid),
        record.age
    );
    assert!(
        bitflip_debug::codeview::matches(&record, &guid, age),
        "记录与 PDB 的 GUID/age 必须一致，否则就是有一个读错了"
    );
}

/// 跨格式的检查：同一个 PDB，换个 age 或 GUID 就**不许**再认。
///
/// 这半边（不匹配）没法用真实产物造 —— 要造就得再编译一次，而 fixture 脚本只产一份。
/// 所以用构造数据钉住：这块逻辑出错的表现是"静默用了别的构建的调试信息"，最坏的那种错。
#[test]
fn a_stale_or_foreign_pdb_is_not_accepted() {
    let Some(record) = record_for("m8-pdb.exe") else {
        eprintln!("SKIPPED: 缺少 tests/fixtures/generated/m8-pdb.exe");
        return;
    };
    let ok_guid = bitflip_debug::codeview::guid_text(&record.guid);
    assert!(bitflip_debug::codeview::matches(
        &record, &ok_guid, record.age
    ));
    assert!(
        !bitflip_debug::codeview::matches(&record, &ok_guid, record.age + 1),
        "age 不同就是另一次写入，不能认"
    );
    assert!(
        !bitflip_debug::codeview::matches(
            &record,
            "00000000-0000-0000-0000-000000000000",
            record.age
        ),
        "GUID 不同就是另一个程序，不能认"
    );
}

/// GUID 的文本形式要按 CodeView 的混合端序写：前三个字段小端，后两个原样。
///
/// 用 `llvm-readobj --coff-debug-directory` 在真样本上看到的字节序钉住这个映射
/// （`3C 14 67 8A ...` ↔ `8a67143c-...`）。写反了的话，核对永远失败 —— 表现为
/// "所有 PDB 都不被采用"，比用错 PDB 安全，但功能直接没了，所以要测。
#[test]
fn the_guid_text_uses_the_codeview_field_order() {
    let mut guid = [0u8; 16];
    guid[..4].copy_from_slice(&[0x3c, 0x14, 0x67, 0x8a]);
    guid[4..6].copy_from_slice(&[0x73, 0xd1]);
    guid[6..8].copy_from_slice(&[0xce, 0x1a]);
    guid[8..10].copy_from_slice(&[0x4c, 0x4c]);
    guid[10..].copy_from_slice(&[0x44, 0x20, 0x50, 0x44, 0x42, 0x2e]);
    assert_eq!(
        bitflip_debug::codeview::guid_text(&guid),
        "8a67143c-d173-1ace-4c4c-44205044422e"
    );
}
