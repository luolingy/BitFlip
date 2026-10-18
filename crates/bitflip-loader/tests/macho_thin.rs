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

    // 这份样本的 LC_SYMTAB 是 nsyms = 0（命令在、表是空的），所以 symbols 为空是
    // **文件里的事实**；它与"没有这条命令"在 notes 里说得不一样（§7）。
    // 它的 LC_DYLD_INFO_ONLY 的 bind / lazy_bind 也是空的，所以导入表同样为空 ——
    // notes 必须说清是"命令在、流是空的"，不是"没解析"。
    assert!(object.symbols.is_empty());
    assert!(object.imports.is_empty());
    let notes = object.notes.join("\n");
    assert!(notes.contains("符号表"), "{notes}");
    assert!(
        notes.contains("LC_DYLD_INFO") && notes.contains("两段都是空的"),
        "{notes}"
    );
}

#[test]
fn symbols_and_function_starts_reach_the_object_model() {
    // M12 第三片：这两项此前一个恒空（符号表没解析）、一个根本不存在
    // （函数边界只能靠反汇编）。这里从 crate 外面各验一遍。
    let bytes = fixture::demo_symbols64();
    let object = parse_object(ObjectKind::MachO, &bytes, 0, ObjectId::Plain).expect("能解析");
    assert_eq!(
        object
            .symbols
            .iter()
            .map(|symbol| symbol.name.as_str())
            .collect::<Vec<_>>(),
        vec!["_main", "_printf"],
        "调试 stab 不进 symbols"
    );
    assert!(!object.format.is_stripped);

    let bytes = fixture::demo_function_starts64();
    let object = parse_object(ObjectKind::MachO, &bytes, 0, ObjectId::Plain).expect("能解析");
    assert_eq!(
        object.function_starts,
        vec![0x1_0000_0120, 0x1_0000_024C, 0x1_0000_025C],
        "一个增量是 300（两字节 ULEB128），必须解对"
    );
}

#[test]
fn lc_uuid_and_dylibs_reach_the_object_model() {
    // M12 第二片：这两项此前只存在于 `MachOFile`，对象模型里没有位置 ——
    // 于是 CLI / UI 拿不到、程序化消费只能去解析 notes 里的字符串。
    let bytes = fixture::demo_thin64();
    let object = parse_object(ObjectKind::MachO, &bytes, 0, ObjectId::Plain).expect("能解析");

    let uuid = object.uuid.as_deref().expect("样本里有 LC_UUID");
    assert_eq!(uuid.len(), 32, "LC_UUID 是 16 字节 → 32 个字符");
    assert_eq!(uuid, "0123456789abcdeffedcba9876543210");
    assert!(
        uuid.chars()
            .all(|c| c.is_ascii_hexdigit() && !c.is_ascii_uppercase()),
        "必须是小写十六进制：{uuid:?}"
    );

    // 顺序**就是**加载命令的顺序：`libSystem` 是强链接、`UIKit` 是弱链接，
    // 两者都在样本里，且 UIKit 在后。重排会丢掉文件里的事实。
    assert_eq!(
        object.dylibs,
        vec![
            "/usr/lib/libSystem.B.dylib".to_string(),
            "/System/Library/Frameworks/UIKit.framework/UIKit".to_string(),
        ]
    );

    // 没有 dylib 的样本必须是**空表**，不是占位名。
    let thin32 = fixture::demo_thin32();
    let object = parse_object(ObjectKind::MachO, &thin32, 0, ObjectId::Plain).expect("能解析");
    assert_eq!(object.uuid, None, "这份样本没有 LC_UUID");
    assert!(object.dylibs.is_empty());
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
fn powerpc_binaries_parse_through_the_public_entry() {
    // ppc 曾经是"识别但拒绝"（arch 层没有变体、也没有解码后端）。
    // 现在两条路都得通：结构层给架构，解码器给指令。
    let thin32 = fixture::demo_thin_ppc32();
    let object = parse_object(ObjectKind::MachO, &thin32, 0, ObjectId::Plain).expect("ppc 能解析");
    assert_eq!(object.arch.to_string(), "ppc/32/be");
    assert_eq!(object.arch.ptr_size, 4);
    assert_eq!(object.entry, Some(0x1400));

    let thin64 = fixture::demo_thin_ppc64();
    let object =
        parse_object(ObjectKind::MachO, &thin64, 0, ObjectId::Plain).expect("ppc64 能解析");
    assert_eq!(object.arch.to_string(), "ppc64/64/be");
    assert_eq!(object.arch.ptr_size, 8);
    assert_eq!(object.entry, Some(0x1_0000_0500));
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
