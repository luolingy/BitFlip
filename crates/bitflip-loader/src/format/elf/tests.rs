//! ELF 解析的单元测试。
//!
//! 这里的合成镜像**按 ELF 规格拼**，不是按解析器的假设拼（CLAUDE.md §6.11：
//! 照自己的解析代码拼 fixture 是自证其说，测试会绿而解析是错的）。
//! 每条合成镜像都要能说出"哪个字段在哪个偏移、出处是哪份规格"。
//!
//! 搭配的真实产物测试在 `tests/reloc_sections.rs`（用生成脚本产出的 `.o`/`.so` 兜底）。

// `use super::*` 只带进本模块（`mod.rs`）的项，**不带进子模块** —— Rust 的 glob
// 不跨模块边界。拆分前这些函数与测试同处一个模块，所以靠 glob 就拿到了；
// 现在必须逐个点名。这是拆分唯一"暴露出来"的东西，而它本来是个隐式依赖：
// 测试能用哪些内部函数，之前是"碰巧都在同一个文件里"决定的。
use super::parse::{parse, read_strtab, section_content_kind, segment_placeholder_name};
use super::sym::classify_reloc;
use super::*;
use crate::object::{ContentKind, ObjectId, RelocKind};
use crate::ObjectKind;
use bitflip_arch::Arch;

/// 构造一个最小但完整的 ELF64 小端文件（可重定位目标文件，无程序头）。
fn minimal_elf64() -> Vec<u8> {
    let mut bytes = vec![0u8; 0x400];
    // ELF 头
    bytes[0..4].copy_from_slice(b"\x7fELF");
    bytes[4] = 2; // ELFCLASS64
    bytes[5] = 1; // ELFDATA2LSB
    bytes[6] = 1; // EV_CURRENT
    bytes[7] = 0; // System V
    bytes[16..18].copy_from_slice(&1u16.to_le_bytes()); // e_type = ET_REL
    bytes[18..20].copy_from_slice(&62u16.to_le_bytes()); // e_machine = x86_64
    bytes[20..24].copy_from_slice(&1u32.to_le_bytes()); // e_version
    bytes[24..32].copy_from_slice(&0u64.to_le_bytes()); // e_entry
    bytes[32..40].copy_from_slice(&0u64.to_le_bytes()); // e_phoff
    bytes[40..48].copy_from_slice(&0x200u64.to_le_bytes()); // e_shoff
    bytes[48..52].copy_from_slice(&0u32.to_le_bytes()); // e_flags
    bytes[52..54].copy_from_slice(&64u16.to_le_bytes()); // e_ehsize
    bytes[54..56].copy_from_slice(&0u16.to_le_bytes()); // e_phentsize
    bytes[56..58].copy_from_slice(&0u16.to_le_bytes()); // e_phnum
    bytes[58..60].copy_from_slice(&64u16.to_le_bytes()); // e_shentsize
    bytes[60..62].copy_from_slice(&2u16.to_le_bytes()); // e_shnum
    bytes[62..64].copy_from_slice(&1u16.to_le_bytes()); // e_shstrndx

    // 节名字符串表内容（放在 0x100）
    let shstrtab = b"\0.shstrtab\0";
    bytes[0x100..0x100 + shstrtab.len()].copy_from_slice(shstrtab);

    // section 0：NULL
    // section 1：.shstrtab
    let s1 = 0x200 + 64;
    bytes[s1..s1 + 4].copy_from_slice(&1u32.to_le_bytes()); // sh_name = 1 (".shstrtab")
    bytes[s1 + 4..s1 + 8].copy_from_slice(&3u32.to_le_bytes()); // sh_type = STRTAB
    bytes[s1 + 24..s1 + 32].copy_from_slice(&0x100u64.to_le_bytes()); // sh_offset
    bytes[s1 + 32..s1 + 40].copy_from_slice(&(shstrtab.len() as u64).to_le_bytes()); // sh_size
    bytes[s1 + 48..s1 + 56].copy_from_slice(&1u64.to_le_bytes()); // sh_addralign
    bytes
}

#[test]
fn parses_minimal_elf64_header_and_sections() {
    let obj = parse(&minimal_elf64(), 0, ObjectId::Plain).unwrap();
    assert_eq!(obj.kind, ObjectKind::Elf);
    assert_eq!(obj.arch.arch, Arch::X86_64);
    assert_eq!(obj.endian, Endian::Little);
    // 样本有 2 个节头（NULL + .shstrtab），但节 0 是 SHT_NULL 占位，
    // 不列进归一化节表 —— 与 readelf/llvm-readobj 显示的真实节数一致。
    assert_eq!(obj.sections.len(), 1);
    assert_eq!(obj.sections[0].name, ".shstrtab");
    assert_eq!(obj.sections[0].kind, ContentKind::StringTable);
    // .o 没有入口 —— 必须是 None，不能用 0 冒充
    assert_eq!(obj.entry, None);
    assert!(obj.format.is_relocatable);
}

#[test]
fn rejects_bad_magic() {
    let mut bytes = minimal_elf64();
    bytes[0] = b'X';
    assert!(matches!(
        parse(&bytes, 0, ObjectId::Plain),
        Err(ParseError::BadMagic { .. })
    ));
}

#[test]
fn rejects_truncated_header_without_panic() {
    for len in 0..EHDR64_SIZE {
        let bytes = vec![0u8; len as usize];
        // 全部只会返回错误，绝不 panic
        let _ = parse(&bytes, 0, ObjectId::Plain);
    }
    // 头部齐全但内容被截断
    let mut bytes = minimal_elf64();
    bytes.truncate(0x210);
    let result = parse(&bytes, 0, ObjectId::Plain);
    // 要么成功（节表刚好够）要么报错，但绝不 panic
    let _ = result;
}

#[test]
fn rejects_unsupported_class() {
    let mut bytes = minimal_elf64();
    bytes[4] = 9; // 既不是 1 也不是 2
    assert!(matches!(
        parse(&bytes, 0, ObjectId::Plain),
        Err(ParseError::Unsupported {
            what: "EI_CLASS",
            ..
        })
    ));
}

#[test]
fn rejects_bad_endian_marker() {
    let mut bytes = minimal_elf64();
    bytes[5] = 7;
    assert!(matches!(
        parse(&bytes, 0, ObjectId::Plain),
        Err(ParseError::Unsupported {
            what: "EI_DATA",
            ..
        })
    ));
}

#[test]
fn rejects_unknown_machine() {
    let mut bytes = minimal_elf64();
    bytes[18..20].copy_from_slice(&0x1234u16.to_le_bytes());
    assert!(matches!(
        parse(&bytes, 0, ObjectId::Plain),
        Err(ParseError::Unsupported {
            what: "e_machine",
            ..
        })
    ));
}

#[test]
fn rejects_bad_version() {
    let mut bytes = minimal_elf64();
    bytes[20..24].copy_from_slice(&99u32.to_le_bytes());
    assert!(matches!(
        parse(&bytes, 0, ObjectId::Plain),
        Err(ParseError::Unsupported {
            what: "e_version",
            ..
        })
    ));
}

#[test]
fn huge_section_count_is_capped_not_allocated() {
    let mut bytes = minimal_elf64();
    bytes[60..62].copy_from_slice(&0u16.to_le_bytes()); // e_shnum = 0 → extended
                                                        // section 0 的 sh_size 声称有 2^40 个节
    let s0 = 0x200;
    bytes[s0 + 32..s0 + 40].copy_from_slice(&(1u64 << 40).to_le_bytes());
    // 必须快速返回（被封顶），而不是尝试分配
    let result = parse(&bytes, 0, ObjectId::Plain);
    match result {
        Ok(obj) => {
            // 被封顶后节数量受 MAX_SECTIONS 限制，且越界会记 note
            assert!(obj.sections.len() as u64 <= MAX_SECTIONS);
            assert!(
                obj.notes.iter().any(|n| n.contains("超过上限")),
                "应当记录封顶说明，实际 notes = {:?}",
                obj.notes
            );
        }
        Err(_) => { /* 报错也是可接受的结果 */ }
    }
}

#[test]
fn section_count_from_extended_shnum_is_noted() {
    let mut bytes = minimal_elf64();
    bytes[60..62].copy_from_slice(&0u16.to_le_bytes());
    let s0 = 0x200;
    bytes[s0 + 32..s0 + 40].copy_from_slice(&2u64.to_le_bytes());
    let obj = parse(&bytes, 0, ObjectId::Plain).unwrap();
    // 2 个节头里含 SHT_NULL 占位，归一化后只剩 .shstrtab
    assert_eq!(obj.sections.len(), 1);
    assert!(
        obj.notes.iter().any(|n| n.contains("extended shnum")),
        "notes = {:?}",
        obj.notes
    );
}

#[test]
fn extended_shstrndx_via_sh_link_is_handled() {
    let mut bytes = minimal_elf64();
    bytes[62..64].copy_from_slice(&0xffffu16.to_le_bytes()); // SHN_XINDEX
    let s0 = 0x200;
    bytes[s0 + 40..s0 + 44].copy_from_slice(&1u32.to_le_bytes()); // sh_link = 1
    let obj = parse(&bytes, 0, ObjectId::Plain).unwrap();
    assert_eq!(obj.sections[0].name, ".shstrtab");
    assert!(
        obj.notes.iter().any(|n| n.contains("extended shstrndx")),
        "notes = {:?}",
        obj.notes
    );
}

#[test]
fn conflicting_shentsize_is_an_error_not_a_misread() {
    let mut bytes = minimal_elf64();
    bytes[58..60].copy_from_slice(&8u16.to_le_bytes()); // 远小于 64
    assert!(matches!(
        parse(&bytes, 0, ObjectId::Plain),
        Err(ParseError::Inconsistent(_))
    ));
}

#[test]
fn section_out_of_file_bounds_is_noted_but_parse_continues() {
    let mut bytes = minimal_elf64();
    let s1 = 0x200 + 64;
    // 让 .shstrtab 声称的数据范围远超文件
    bytes[s1 + 24..s1 + 32].copy_from_slice(&0x9000u64.to_le_bytes());
    bytes[s1 + 32..s1 + 40].copy_from_slice(&0x9000u64.to_le_bytes());
    let obj = parse(&bytes, 0, ObjectId::Plain).unwrap();
    assert!(
        obj.notes.iter().any(|n| n.contains("超出文件大小")),
        "notes = {:?}",
        obj.notes
    );
}

#[test]
fn missing_section_header_table_is_noted_not_fatal() {
    let mut bytes = minimal_elf64();
    bytes[40..48].copy_from_slice(&0u64.to_le_bytes()); // e_shoff = 0
    bytes[60..62].copy_from_slice(&0u16.to_le_bytes()); // e_shnum = 0
    let obj = parse(&bytes, 0, ObjectId::Plain).unwrap();
    assert!(obj.sections.is_empty());
    assert!(obj.notes.iter().any(|n| n.contains("无节头表")));
}

/// 对每一个字节做单点破坏，证明解析器对任意畸形输入都只返回错误。
///
/// 这是 M1 验收标准 3 的"不 panic"证据里最有力的一条：
/// 它不依赖随机种子，可复现，且覆盖每一个字段。
#[test]
fn single_byte_corruption_never_panics() {
    let good = minimal_elf64();
    for index in 0..good.len().min(0x240) {
        for bit in 0..8 {
            let mut bytes = good.clone();
            bytes[index] ^= 1 << bit;
            // 结果无所谓，关键是不能 panic
            let _ = parse(&bytes, 0, ObjectId::Plain);
        }
    }
}

/// 随机截断到任意长度都不能 panic。
#[test]
fn every_truncation_length_never_panics() {
    let good = minimal_elf64();
    for len in 0..good.len() {
        let _ = parse(&good[..len], 0, ObjectId::Plain);
    }
}

#[test]
fn zero_length_input_is_an_error() {
    assert!(parse(&[], 0, ObjectId::Plain).is_err());
}

#[test]
fn classify_reloc_covers_known_types() {
    // x86_64
    assert_eq!(classify_reloc(62, 1), RelocKind::Absolute);
    assert_eq!(classify_reloc(62, 6), RelocKind::ImportLookup);
    assert_eq!(classify_reloc(62, 7), RelocKind::ImportLookup);
    // RELATIVE / RELATIVE64 是**数据槽位**指针，与指令里的
    // PC 相对重定位（PC32=2、PLT32=4、GOTPCREL=9）必须分开：
    // 指针表识别只能从前者得到"这里存了个地址"的结论。
    assert_eq!(classify_reloc(62, 8), RelocKind::RelocPointer);
    assert_eq!(classify_reloc(62, 38), RelocKind::RelocPointer);
    assert_eq!(classify_reloc(62, 2), RelocKind::Relative);
    assert_eq!(classify_reloc(62, 4), RelocKind::Relative);
    // 未知编号归 Other，不猜
    assert_eq!(classify_reloc(62, 999), RelocKind::Other);
    assert_eq!(classify_reloc(0xffff, 1), RelocKind::Other);
    // aarch64
    assert_eq!(classify_reloc(183, 257), RelocKind::Absolute);
    assert_eq!(classify_reloc(183, 1026), RelocKind::ImportLookup);
    assert_eq!(classify_reloc(183, 1027), RelocKind::RelocPointer);
    assert_eq!(classify_reloc(183, 261), RelocKind::Relative);
    // arm / i386 / riscv 的 RELATIVE 同样归数据槽位
    assert_eq!(classify_reloc(40, 23), RelocKind::RelocPointer);
    assert_eq!(classify_reloc(3, 8), RelocKind::RelocPointer);
    assert_eq!(classify_reloc(243, 3), RelocKind::RelocPointer);
}

#[test]
fn relative_and_reloc_pointer_are_distinguishable() {
    // 这条测试守住的是一个具体的回归：早先 `R_*_RELATIVE` 与
    // PC 相对重定位共用 `RelocKind::Relative`，导致"只挑数据槽位"
    // 这件事做不到 —— 实测 libsample.so 的 sample_table[2] 就是这样
    // 被漏掉的，而单看"有重定位数据"完全看不出问题。
    assert_ne!(
        RelocKind::Relative,
        RelocKind::RelocPointer,
        "两类重定位必须是不同的枚举值，否则无法区分数据指针与指令内偏移"
    );
    assert_ne!(
        RelocKind::Relative.as_str(),
        RelocKind::RelocPointer.as_str(),
        "短名也必须不同，否则 wire 上仍然分不开"
    );
}

#[test]
fn is_stripped_reflects_absence_of_symtab_not_dynsym() {
    // 只有 .shstrtab 的目标文件没有 .symtab，应判为已剥离
    let obj = parse(&minimal_elf64(), 0, ObjectId::Plain).unwrap();
    assert!(
        obj.format.is_stripped,
        "没有 .symtab 的对象应判定为已剥离，notes = {:?}",
        obj.notes
    );
}

#[test]
fn is_stripped_is_false_when_symtab_is_present() {
    let mut bytes = minimal_elf64();

    // 追加一个名为 ".symtab" 的节头（第 3 个），并把它指向 .shstrtab 之外
    // 的一段自有名字，从而不必改写字符串表布局。
    bytes[60..62].copy_from_slice(&3u16.to_le_bytes()); // e_shnum = 3
    let shoff = 0x200usize;
    let s2 = shoff + 2 * 64;

    // 把节名字符串表指针指向一个含 ".symtab" 的表，保证名字解析得到
    // ".symtab"（判定依赖它）。
    // .shstrtab 当前在节 1，偏移 0x2e0。先放入新名字，再让节 1 覆盖它。
    let strtab = 0x2e0usize;
    let names = b"\0.shstrtab\0.symtab\0";
    bytes[strtab..strtab + names.len()].copy_from_slice(names);
    // 节 1 的 sh_offset / sh_size 覆盖为新的表
    let s1 = shoff + 64;
    bytes[s1 + 24..s1 + 32].copy_from_slice(&(strtab as u64).to_le_bytes());
    bytes[s1 + 32..s1 + 40].copy_from_slice(&(names.len() as u64).to_le_bytes());

    // 节 2 = .symtab，名字偏移指向新表里的 ".symtab"（偏移 11）
    bytes[s2..s2 + 4].copy_from_slice(&11u32.to_le_bytes());
    bytes[s2 + 4..s2 + 8].copy_from_slice(&sh_type::SYMTAB.to_le_bytes());
    bytes[s2 + 24..s2 + 32].copy_from_slice(&0u64.to_le_bytes()); // sh_offset = 0
    bytes[s2 + 32..s2 + 40].copy_from_slice(&0u64.to_le_bytes()); // sh_size = 0

    let obj = parse(&bytes, 0, ObjectId::Plain).unwrap();
    assert!(
        obj.sections.iter().any(|s| s.name == ".symtab"),
        "样本应含 .symtab 节，实际 = {:?}",
        obj.sections.iter().map(|s| &s.name).collect::<Vec<_>>()
    );
    assert!(!obj.format.is_stripped, "含 .symtab 的对象不应判定为已剥离");
}

#[test]
fn section_content_kind_prefers_flags_over_names() {
    let mut sh = SectionHeader {
        name_offset: 0,
        sh_type: sh_type::PROGBITS,
        flags: sh_flags::ALLOC | sh_flags::EXECINSTR,
        addr: 0,
        offset: 0,
        size: 0,
        link: 0,
        info: 0,
        addralign: 0,
        entsize: 0,
    };
    assert_eq!(section_content_kind(&sh), ContentKind::Code);

    sh.flags = sh_flags::ALLOC | sh_flags::WRITE;
    assert_eq!(section_content_kind(&sh), ContentKind::Data);

    // 已映射、不可写、不可执行 = 只读数据
    sh.flags = sh_flags::ALLOC;
    assert_eq!(section_content_kind(&sh), ContentKind::ReadOnlyData);

    // 未映射的 PROGBITS（.comment 之类）不是运行期数据，是文件元数据。
    // 这正是过去被误标成"只读数据"却带着 `---` 权限的那一类。
    sh.flags = 0;
    assert_eq!(section_content_kind(&sh), ContentKind::Metadata);

    sh.sh_type = sh_type::NOBITS;
    assert_eq!(section_content_kind(&sh), ContentKind::Bss);
    sh.sh_type = sh_type::SYMTAB;
    assert_eq!(section_content_kind(&sh), ContentKind::SymbolTable);
    sh.sh_type = sh_type::NOTE;
    assert_eq!(section_content_kind(&sh), ContentKind::Metadata);
    sh.sh_type = 0x1234;
    assert_eq!(section_content_kind(&sh), ContentKind::Unknown);
}

#[test]
fn read_strtab_is_bounds_safe() {
    let table = b"abc\0def\0";
    assert_eq!(read_strtab(table, 0).unwrap(), "abc");
    assert_eq!(read_strtab(table, 4).unwrap(), "def");
    // 结尾 NUL 自身的偏移 → 空串（合法位置，只是内容为空）
    assert_eq!(read_strtab(table, 7).unwrap(), "");
    // 严格越界（== 表长）→ None
    assert_eq!(read_strtab(table, 8), None);
    assert_eq!(read_strtab(table, 999), None);
    // 空表
    assert_eq!(read_strtab(b"", 0), None);
}

#[test]
fn segment_placeholder_names_are_distinguishable() {
    assert_eq!(segment_placeholder_name(p_type::LOAD, 0), "LOAD#0");
    assert_eq!(segment_placeholder_name(p_type::LOAD, 3), "LOAD#3");
    assert_eq!(
        segment_placeholder_name(p_type::GNU_STACK, 1),
        "GNU_STACK#1"
    );
    assert_eq!(segment_placeholder_name(0x9999, 2), "PT#2");
}
