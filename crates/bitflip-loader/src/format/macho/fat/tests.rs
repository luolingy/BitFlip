//! fat / universal 容器层的单元测试。
//!
//! 合成样本同样来自 `tests/common/macho_fixture.rs`（与薄 Mach-O 的测试共用
//! 一个构造器，理由见那里）。

use super::*;
use crate::format::macho::fixture;
use crate::ObjectKind;

#[test]
fn two_slices_are_enumerated_with_their_architectures() {
    let bytes = fixture::demo_fat();
    let file = read(&bytes).expect("合成 fat 样本必须能解析");

    assert!(!file.is_64, "样本用的是 32 位 fat 头（FAT_MAGIC）");
    assert_eq!(file.slices.len(), 2);
    let first = &file.slices[0];
    let second = &file.slices[1];
    assert_eq!(first.index, 0);
    assert_eq!(first.cputype, fixture::CPU_TYPE_X86);
    assert_eq!(
        first.arch.map(|spec| spec.to_string()).as_deref(),
        Some("x86/32/le")
    );
    assert_eq!(second.cputype, fixture::CPU_TYPE_X86_64);
    assert_eq!(
        second.arch.map(|spec| spec.to_string()).as_deref(),
        Some("x86_64/64/le")
    );
    // 架构表本身不参与切片：偏移必须落在表之后。
    assert!(first.offset >= FAT_HEADER_SIZE + 2 * FAT_ARCH_SIZE);
    assert!(second.offset > first.offset);
    assert_eq!(first.align, 12, "align 是 log2");
    assert_eq!(first.reserved, None, "32 位表项没有 reserved 字段");
    assert!(
        file.notes.iter().any(|note| note.contains("切片")),
        "fat 切片还没接进会话这件事必须说出来：{:?}",
        file.notes
    );
}

#[test]
fn each_slice_can_be_parsed_as_a_thin_object() {
    let bytes = fixture::demo_fat();

    let first = parse_slice(&bytes, 0, ObjectId::Plain).expect("第 0 片能解析");
    assert_eq!(first.kind, ObjectKind::MachO);
    assert_eq!(first.arch.to_string(), "x86/32/le");
    assert_eq!(first.entry, Some(0x1800));
    assert_eq!(first.sections.len(), 1);

    let second = parse_slice(&bytes, 1, ObjectId::Plain).expect("第 1 片能解析");
    assert_eq!(second.arch.to_string(), "x86_64/64/le");
    assert_eq!(second.image_base, 0x1_0000_0000);
    assert_eq!(second.entry, Some(0x1_0000_0F00));
    assert_eq!(second.sections.len(), 3);

    // 越界的切片下标要报错，而不是回落到第 0 片。
    let error = parse_slice(&bytes, 9, ObjectId::Plain).expect_err("下标越界必须报错");
    assert!(matches!(error, ParseError::Inconsistent(_)), "{error:?}");
}

#[test]
fn the_64bit_fat_table_is_read_with_64bit_fields() {
    let bytes = fixture::demo_fat64();
    let file = read(&bytes).expect("64 位 fat 头必须能解析");
    assert!(file.is_64);
    assert_eq!(file.slices.len(), 1);
    let slice = &file.slices[0];
    assert_eq!(slice.cputype, fixture::CPU_TYPE_X86_64);
    assert_eq!(slice.reserved, Some(0));
    assert_eq!(
        slice.arch.map(|spec| spec.to_string()).as_deref(),
        Some("x86_64/64/le")
    );
    // 切片的字节范围必须原样取出，且开头是薄 Mach-O 的魔数。
    let raw = slice_bytes(&bytes, slice).expect("能取出切片字节");
    assert_eq!(raw.len() as u64, slice.size);
    assert_eq!(&raw[0..4], &[0xcf, 0xfa, 0xed, 0xfe]);
}

#[test]
fn a_slice_beyond_the_end_of_the_file_is_rejected() {
    let mut bytes = fixture::demo_fat();
    // 第 0 条 fat_arch 在 +8，offset 字段在 +8+8 = +16。
    let size = bytes.len() as u32;
    fixture::patch_u32(&mut bytes, 16, size + 0x1000, false);
    let error = read(&bytes).expect_err("切片越过文件末尾必须拒绝");
    let message = error.summary_zh();
    assert!(matches!(error, ParseError::Inconsistent(_)), "{error:?}");
    assert!(message.contains("超出文件大小"), "{message}");
}

#[test]
fn a_slice_overlapping_the_arch_table_is_rejected() {
    let mut bytes = fixture::demo_fat();
    // 把第 0 片挪进 fat 头里（+16 是它的 offset 字段）。
    fixture::patch_u32(&mut bytes, 16, 0x10, false);
    let error = read(&bytes).expect_err("切片压在架构表上必须拒绝");
    let message = error.summary_zh();
    assert!(matches!(error, ParseError::Inconsistent(_)), "{error:?}");
    assert!(message.contains("架构表"), "{message}");
}

#[test]
fn nfat_arch_zero_is_rejected() {
    let mut bytes = fixture::demo_fat();
    fixture::patch_u32(&mut bytes, 4, 0, false);
    let error = read(&bytes).expect_err("nfat_arch = 0 不是合法容器");
    assert!(matches!(error, ParseError::Inconsistent(_)), "{error:?}");
}

#[test]
fn nfat_arch_above_the_limit_is_rejected_before_allocating() {
    let mut bytes = fixture::demo_fat();
    fixture::patch_u32(&mut bytes, 4, 100_000, false);
    match read(&bytes) {
        Err(ParseError::Unsupported { what, value, .. }) => {
            assert_eq!(what, "nfat_arch");
            assert_eq!(value, 100_000);
        }
        other => panic!("期望 Unsupported，实际是 {other:?}"),
    }
}

#[test]
fn a_java_class_is_not_mistaken_for_a_fat_binary() {
    // `CAFEBABE` 也是 Java class 的魔数。class 文件里"nfat_arch"位置上是版本号、
    // "cputype"位置上是常量池内容，所以判据是"第一个 cputype 是不是已知 Mach-O CPU"。
    let mut bytes = vec![0u8; 2048];
    bytes[0..4].copy_from_slice(&[0xca, 0xfe, 0xba, 0xbe]);
    bytes[4..8].copy_from_slice(&52u32.to_be_bytes()); // 版本号被当成 nfat_arch
    let error = read(&bytes).expect_err("Java class 不是 fat Mach-O");
    let message = error.summary_zh();
    assert!(matches!(error, ParseError::Inconsistent(_)), "{error:?}");
    assert!(message.contains("Java"), "{message}");
}

#[test]
fn a_wrong_magic_is_reported_as_a_bad_magic() {
    let error = read(&fixture::demo_thin64()).expect_err("薄 Mach-O 不是 fat 容器");
    assert!(matches!(error, ParseError::BadMagic { .. }), "{error:?}");
}
