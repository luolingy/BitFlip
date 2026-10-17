//! Mach-O 结构层的集成测试：走 `parse_object` 这条**公开**入口。
//!
//! 合成样本按规范逐字节拼在 `common/macho_fixture.rs`（那里的模块文档写了
//! 每个字段的偏移与出处）。单元测试在 `src/format/macho/tests.rs` 里覆盖
//! 边角情形；这里只验证"从 crate 外面看，行为是不是也说得出人话"。
//!
//! **真实** Mach-O 的验证在 `macho_real_sample.rs`（`#[ignore]`，需要一份 IPA）。

#[path = "common/macho_fixture.rs"]
mod fixture;

use bitflip_loader::object::ObjectId;
use bitflip_loader::reader::ParseError;
use bitflip_loader::{format, has_parser, parse_object, ObjectKind};

#[test]
fn parse_object_dispatches_macho_to_the_structure_parser() {
    assert!(
        has_parser(ObjectKind::MachO),
        "M12 第一片之后 Mach-O 有解析器"
    );

    let bytes = fixture::demo_thin64();
    let object = parse_object(ObjectKind::MachO, &bytes, 0, ObjectId::Plain).expect("能解析");

    assert_eq!(object.kind, ObjectKind::MachO);
    assert_eq!(object.arch.to_string(), "x86_64/64/le");
    assert_eq!(object.image_base, 0x1_0000_0000);
    assert_eq!(object.entry, Some(0x1_0000_0F00));
    assert_eq!(object.segments.len(), 2, "__PAGEZERO + __TEXT");
    assert_eq!(object.sections.len(), 3);

    let names: Vec<&str> = object
        .sections
        .iter()
        .map(|section| section.name.as_str())
        .collect();
    assert_eq!(
        names,
        vec!["__TEXT,__text", "__TEXT,__cstring", "__TEXT,__const"],
        "节名用「段名,节名」——Mach-O 里节名只在段内唯一"
    );

    // 没有符号表解析：这一点必须能从结果里看出来（§7）。
    assert!(object.symbols.is_empty());
    assert!(object.imports.is_empty());
    let notes = object.notes.join("\n");
    assert!(notes.contains("符号表"), "{notes}");
    assert!(notes.contains("dyld"), "{notes}");
}

#[test]
fn a_32bit_binary_yields_its_single_segment() {
    let bytes = fixture::demo_thin32();
    let object = parse_object(ObjectKind::MachO, &bytes, 0, ObjectId::Plain).expect("能解析");
    assert_eq!(object.arch.to_string(), "x86/32/le");
    assert_eq!(object.segments.len(), 1);
    assert_eq!(object.segments[0].name, "__TEXT");
    assert_eq!(object.entry, Some(0x1800));
}

#[test]
fn a_fat_container_is_enumerated_and_each_slice_parses() {
    let bytes = fixture::demo_fat();
    let container = format::macho::fat::read(&bytes).expect("能枚举切片");
    assert_eq!(container.slices.len(), 2);

    let architectures: Vec<String> = container
        .slices
        .iter()
        .filter_map(|slice| slice.arch.map(|spec| spec.to_string()))
        .collect();
    assert_eq!(architectures, vec!["x86/32/le", "x86_64/64/le"]);

    for (index, _) in container.slices.iter().enumerate() {
        let object = format::macho::fat::parse_slice(&bytes, index, ObjectId::Plain)
            .unwrap_or_else(|error| panic!("第 {index} 片应当能解析：{}", error.summary_zh()));
        assert_eq!(object.kind, ObjectKind::MachO);
    }

    // 但**整份文件**不能被当成一个对象：fat 没有单一的架构与入口点。
    let error = parse_object(ObjectKind::MachO, &bytes, 0, ObjectId::Plain)
        .expect_err("fat 输入必须明确报错");
    assert!(error.summary_zh().contains("fat"), "{}", error.summary_zh());
}

#[test]
fn a_malformed_sizeofcmds_is_rejected_not_guessed() {
    let bytes = fixture::malformed_sizeofcmds_too_big();
    let error =
        parse_object(ObjectKind::MachO, &bytes, 0, ObjectId::Plain).expect_err("畸形输入必须报错");
    match error {
        ParseError::Truncated {
            what,
            needed,
            actual,
        } => {
            assert!(what.contains("加载命令区"), "{what}");
            assert!(
                needed > actual,
                "报错要给出需要的字节数与实际字节数（{needed} vs {actual}）"
            );
        }
        other => panic!("期望 Truncated，实际是 {other:?}"),
    }
}
