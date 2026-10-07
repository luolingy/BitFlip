//! 重定位的「属于哪个节」以及 PE 表映射的回归测试（M8 前置）。
//!
//! # 为什么这组测试存在
//!
//! M8 要用**静态库成员里的函数字节**生成签名，再拿它去**已链接的目标**里找同样的
//! 字节。两边的差别恰好就是"链接器改写过的那些字节"—— 也就是重定位覆盖的位置。
//! 所以生成签名时必须能回答"这一条重定位改的是哪几个字节"，而这个问题的前提是
//! "这条重定位属于哪个节"。
//!
//! 这两条在**可重定位对象**（`.o`/`.obj`）上是硬需求：那些文件里节的虚拟地址
//! 通常全是 0，`Reloc::address` 是**节内偏移**，`.rela.text` 与 `.rela.data` 的
//! 偏移会落在同一批数值上。只给偏移不给节，等于给不出位置。
//!
//! 顺带守住两个已经踩过的坑：
//!
//! 1. ELF 侧 `target_name` 曾经用字面量 0 当节号（应为 `sh_info`），取到的是空节
//!    的名字，又因为没人用而被丢掉；
//! 2. PE 侧 `rva_to_offset` 曾经用 `?` 提前返回：`.bss` 这类没有文件后备的段会让
//!    整个查找放弃，于是**排在它之后的每个表都解析不了**（`.idata`/`.tls`/`.reloc`），
//!    而降级说明把原因写成"文件结构自相矛盾" —— 文件没问题，是查找写错了。
//!
//! 期望值尽量来自**外部工具**（`llvm-readobj`）而不是本程序的输出，否则只是拿
//! 自己的理解验证自己的实现。

use std::path::PathBuf;

use bitflip_loader::elf;
use bitflip_loader::object::{Object, ObjectId};
use bitflip_loader::{coff, pe};

fn fixture(name: &str) -> PathBuf {
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../tests/fixtures/generated")
        .join(name);
    // 硬断言而不是静默跳过：fixture 缺失时"通过"是最坏的结果。
    assert!(
        path.exists(),
        "缺少 fixture：{}（由 tests/fixtures 脚本生成，见 docs/PLAN.md §5.2）",
        path.display()
    );
    path
}

fn read(path: &PathBuf) -> Vec<u8> {
    std::fs::read(path).expect("读取样本")
}

/// 任何一节的名字都不能是占位形式：占位名会把"没有这个信息"伪装成有名字。
fn assert_no_placeholder_section(object: &Object, what: &str) {
    for reloc in &object.relocations {
        if let Some(section) = &reloc.section {
            assert!(
                !section.starts_with('<') && !section.is_empty(),
                "{what}：重定位带了占位节名 {section:?}"
            );
            // 说得出节名，就必须是文件里真的存在的节。
            assert!(
                object.section_by_name(section).is_some(),
                "{what}：重定位声称在节 {section:?}，但该节不在节表里"
            );
        }
    }
}

#[test]
fn elf_object_relocations_say_which_section_they_patch() {
    let object = elf::parse(&read(&fixture("elf-x86_64.o")), 0, ObjectId::Plain).expect("解析 .o");
    assert_no_placeholder_section(&object, "elf-x86_64.o");

    let text_size = object
        .section_by_name(".text")
        .expect(".o 里应有 .text")
        .file
        .size;
    let data_size = object
        .section_by_name(".data")
        .expect(".o 里应有 .data")
        .file
        .size;

    let in_text: Vec<_> = object
        .relocations
        .iter()
        .filter(|r| r.section.as_deref() == Some(".text"))
        .collect();
    let in_data: Vec<_> = object
        .relocations
        .iter()
        .filter(|r| r.section.as_deref() == Some(".data"))
        .collect();

    assert!(
        !in_text.is_empty() && !in_data.is_empty(),
        "两个节的重定位都要能分辨出来，实际 .text={} 条、.data={} 条",
        in_text.len(),
        in_data.len()
    );

    // 调用 bf_banner 的那条（外部工具看到的：R_X86_64_PC32，加数 -4）。
    let call = in_text
        .iter()
        .find(|r| r.symbol.as_deref() == Some("bf_banner"))
        .expect(".text 里应有引用 bf_banner 的重定位");
    assert_eq!(call.address, 0x47, "地址应是节内偏移");
    assert_eq!(call.kind, bitflip_loader::object::RelocKind::Relative);

    // 地址是**节内偏移**：两条证据。一是它们落在各自节的长度之内；
    // 二是 `.text` 与 `.data` 的地址集合无法靠数值本身区分来源。
    for reloc in &in_text {
        assert!(
            reloc.address < text_size,
            "声称在 .text 里的重定位地址 {:#x} 超出了 .text 的大小 {}",
            reloc.address,
            text_size
        );
    }
    for reloc in &in_data {
        assert!(
            reloc.address < data_size,
            "声称在 .data 里的重定位地址 {:#x} 超出了 .data 的大小 {}",
            reloc.address,
            data_size
        );
    }
}

#[test]
fn coff_object_relocations_say_which_section_they_patch() {
    let object =
        coff::parse(&read(&fixture("pe-x86_64.obj")), 0, ObjectId::Plain).expect("解析 .obj");
    assert_no_placeholder_section(&object, "pe-x86_64.obj");

    let text_size = object
        .section_by_name(".text")
        .expect(".obj 里应有 .text")
        .file
        .size;
    let pdata_size = object
        .section_by_name(".pdata")
        .expect(".obj 里应有 .pdata")
        .file
        .size;

    let in_text: Vec<_> = object
        .relocations
        .iter()
        .filter(|r| r.section.as_deref() == Some(".text"))
        .collect();
    let in_pdata: Vec<_> = object
        .relocations
        .iter()
        .filter(|r| r.section.as_deref() == Some(".pdata"))
        .collect();

    assert!(
        !in_text.is_empty(),
        "x64 的 .obj 应当有 .text 重定位（对 .rdata 的引用）"
    );
    assert!(
        !in_pdata.is_empty(),
        ".pdata 的重定位（IMAGE_REL_AMD64_ADDR32NB）必须能与 .text 的分开"
    );

    // 关键点：两组地址都从 0 附近开始，只给偏移是分不清的 ——
    // 这正是"必须带上节名"的实证。
    assert!(
        in_pdata.iter().any(|r| r.address == 0),
        ".pdata 的重定位应当从偏移 0 开始（否则这条测试没测到混淆情形）"
    );
    for reloc in &in_text {
        assert!(reloc.address < text_size, ".text 的偏移应落在 .text 内");
    }
    for reloc in &in_pdata {
        assert!(reloc.address < pdata_size, ".pdata 的偏移应落在 .pdata 内");
    }

    // 两种类型的重定位不能混为一谈：`.text` 里那条是 PC 相对，`.pdata` 的是"节内
    // RVA"（`Other`），把它们归一化成同一类会让下游按错误宽度去屏蔽字节。
    assert!(
        in_text
            .iter()
            .any(|r| r.kind == bitflip_loader::object::RelocKind::Relative),
        ".text 里应有 PC 相对重定位"
    );
}

#[test]
fn pe_image_relocations_are_linked_to_a_section() {
    let object = pe::parse(&read(&fixture("pe-x86_64.dll")), 0, ObjectId::Plain).expect("解析 DLL");
    assert_no_placeholder_section(&object, "pe-x86_64.dll");

    // 外部工具（llvm-readobj --coff-basereloc）看到：一条 DIR64，RVA 0x2000。
    // 该 DLL 的映像基址是 0x241aa0000，RVA 0x2000 落在 .data（0x241aa2000）。
    let reloc = object
        .relocations
        .iter()
        .find(|r| r.kind == bitflip_loader::object::RelocKind::Absolute)
        .expect("DLL 应有一条 DIR64 基址重定位");
    assert_eq!(reloc.address, 0x0000_0002_41aa_2000);
    assert_eq!(reloc.section.as_deref(), Some(".data"));
}

#[test]
fn linked_elf_dynamic_relocations_have_no_bogus_section() {
    // `.rela.dyn` 作用于整个映像（ELF 规范里 sh_info = 0），不指向单个节。
    // 这时如实给 `None`：**不**退回 `<节 0>` 这种占位名。
    let object = elf::parse(&read(&fixture("libsample.so")), 0, ObjectId::Plain).expect("解析 .so");
    assert_no_placeholder_section(&object, "libsample.so");

    assert!(
        object.relocations.iter().any(|r| r.section.is_none()),
        "`.rela.dyn` 的重定位不应声称自己属于某个节"
    );
    assert!(
        object
            .relocations
            .iter()
            .any(|r| r.section.as_deref() == Some(".got.plt")),
        "`.rela.plt` 的 JUMP_SLOT 重定位应当指向 .got.plt"
    );
}

#[test]
fn a_pe_whose_tables_sit_after_bss_still_has_them_parsed() {
    // mingw 链接出来的 PE 把 `.text/.rdata/.pdata/.xdata` 放在 `.bss` 之前，
    // `.idata`/`.tls`/`.reloc` 放在它之后。`.bss` 没有文件后备 —— 查找如果
    // 在它身上放弃，后面三个表全都读不出来。
    let object =
        pe::parse(&read(&fixture("m3-mingw-static.exe")), 0, ObjectId::Plain).expect("解析 PE");

    for note in &object.notes {
        assert!(
            !note.contains("解析失败"),
            "这张表里有节排在 .bss 之后，不该解析失败：{note}"
        );
    }

    // 外部工具（llvm-readobj --coff-imports）看到：两个模块、46 个导入符号。
    let modules: Vec<&str> = object
        .imports
        .iter()
        .map(|import| import.module.as_str())
        .collect();
    assert!(
        modules.contains(&"KERNEL32.dll") && modules.contains(&"msvcrt.dll"),
        "导入表应当解析出两个模块，实际 {modules:?}"
    );
    assert_eq!(object.imports.len(), 46, "导入符号条数应与外部工具一致");
    for import in &object.imports {
        assert!(
            import.iat_slot.is_some(),
            "每个导入都应当有 IAT 槽位：{:?}",
            import.name
        );
    }

    // 外部工具（llvm-readobj --coff-basereloc）看到 44 条 DIR64。
    assert_eq!(
        object.relocations.len(),
        44,
        "基址重定位条数应与外部工具一致"
    );
}
