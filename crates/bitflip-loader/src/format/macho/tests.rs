//! Mach-O 结构层解析的单元测试。
//!
//! 合成样本来自 `tests/common/macho_fixture.rs`，**与集成测试共用同一个构造器**
//! （理由写在那个文件的模块文档里：两份拼法迟早有一份先过时）。字段偏移一律按
//! `mach-o/loader.h` 手写，不调用被测代码去"算"偏移。

use super::*;
use crate::format::macho::fixture;
use crate::object::{ContentKind, ObjectId};

fn parse_bytes(bytes: &[u8]) -> Result<Object, ParseError> {
    parse(bytes, 0, ObjectId::Plain)
}

fn find_section<'a>(object: &'a Object, name: &str) -> &'a Section {
    object
        .sections
        .iter()
        .find(|section| section.name == name)
        .unwrap_or_else(|| {
            panic!(
                "对象里没有节 {name:?}，实际有：{:?}",
                object
                    .sections
                    .iter()
                    .map(|section| section.name.as_str())
                    .collect::<Vec<_>>()
            )
        })
}

// ── 正常路径 ────────────────────────────────────────────────────────────────

#[test]
fn a_64bit_binary_yields_segments_sections_and_entry() {
    let bytes = fixture::demo_thin64();
    let file = read(&bytes).expect("合成样本必须能解析");

    assert!(file.is_64, "样本是 mach_header_64");
    assert_eq!(file.endian, Endian::Little);
    assert_eq!(file.cputype, fixture::CPU_TYPE_X86_64);
    assert_eq!(file.filetype, fixture::MH_EXECUTE);
    assert_eq!(file.segments.len(), 2, "样本有 __PAGEZERO 与 __TEXT");
    assert_eq!(
        file.segments
            .iter()
            .map(|segment| segment.sections.len())
            .sum::<usize>(),
        3,
        "样本的 __TEXT 里有 __text / __cstring / __const"
    );
    assert_eq!(
        file.image_base,
        Some(0x1_0000_0000),
        "镜像基址取 __TEXT.vmaddr"
    );

    // LC_MAIN.entryoff = 0xF00 是文件偏移，__TEXT 的 (fileoff=0, vmaddr=0x1_0000_0000)
    // 把它换算成 0x1_0000_0F00。
    let entry = file.entry.expect("样本有 LC_MAIN");
    assert_eq!(entry.vaddr, 0x1_0000_0F00);
    assert_eq!(entry.source, EntrySource::Main { entryoff: 0xF00 });
    assert!(
        file.notes.iter().any(|note| note.contains("LC_MAIN")),
        "换算式必须写进 notes，用户要能核对：{:?}",
        file.notes
    );

    assert_eq!(
        file.uuid.as_deref(),
        Some("0123456789abcdeffedcba9876543210"),
        "LC_UUID 的 16 字节要按小写十六进制原样拼出"
    );
    assert_eq!(
        file.dylibs,
        vec![
            "/usr/lib/libSystem.B.dylib".to_string(),
            "/System/Library/Frameworks/UIKit.framework/UIKit".to_string(),
        ],
        "LC_LOAD_DYLIB 与 LC_LOAD_WEAK_DYLIB 的名字都要记下来"
    );

    // 节的原始字段（对象模型会丢掉的那些）。
    let text = file
        .segments
        .iter()
        .flat_map(|segment| segment.sections.iter())
        .find(|section| section.sectname == "__text")
        .expect("有 __text");
    assert_eq!(text.flags, fixture::CODE_FLAGS);
    assert_eq!(text.align, 4, "align 是 log2，规范如此");
    assert!(text.offset > 0, "非零填充节必须有文件偏移");
}

#[test]
fn the_object_model_carries_the_converted_facts() {
    let object = parse_bytes(&fixture::demo_thin64()).expect("能解析");
    assert_eq!(object.kind, ObjectKind::MachO);
    assert_eq!(object.arch.to_string(), "x86_64/64/le");
    assert_eq!(object.image_base, 0x1_0000_0000);
    assert_eq!(object.entry, Some(0x1_0000_0F00));
    assert_eq!(
        object.format.type_name.as_deref(),
        Some("MH_EXECUTE（可执行文件）")
    );
    assert!(object.format.is_executable);
    assert!(!object.format.is_dynamic_library);

    let text = find_section(&object, "__TEXT,__text");
    assert_eq!(text.kind, ContentKind::Code);
    assert!(text.perms.execute && text.perms.read && !text.perms.write);
    assert!(text.loaded);

    let cstring = find_section(&object, "__TEXT,__cstring");
    assert_eq!(cstring.kind, ContentKind::ReadOnlyData);
    assert!(
        !cstring.perms.execute,
        "__TEXT 段是 r-x，但 __cstring 不是代码：可执行性取自节标志"
    );

    // 段权限来自 initprot。
    let pagezero = object
        .segments
        .iter()
        .find(|segment| segment.name == "__PAGEZERO")
        .expect("有 __PAGEZERO");
    assert!(
        !pagezero.perms.read && !pagezero.perms.write && !pagezero.perms.execute,
        "__PAGEZERO 的 initprot 是 0"
    );
}

#[test]
fn pagezero_with_zero_filesize_is_not_rejected() {
    // 规范里 __PAGEZERO 的 filesize 就是 0 —— 它是"这段内存不来自文件"，
    // 不是"文件坏了"。把它当越界会把所有正常的 64 位可执行文件拒之门外。
    let bytes = fixture::demo_thin64();
    let file = read(&bytes).expect("__PAGEZERO 不该让解析失败");
    let pagezero = file
        .segments
        .iter()
        .find(|segment| segment.name == "__PAGEZERO")
        .expect("样本里有 __PAGEZERO");
    assert_eq!(pagezero.filesize, 0);
    assert!(pagezero.sections.is_empty());

    let object = parse_bytes(&bytes).expect("能解析");
    let pagezero = object
        .segments
        .iter()
        .find(|segment| segment.name == "__PAGEZERO")
        .expect("对象里也有它");
    assert!(
        pagezero.file.is_none(),
        "filesize == 0 的段在对象模型里不能有文件范围"
    );
}

#[test]
fn a_32bit_binary_maps_to_x86_and_its_entry_is_converted() {
    let bytes = fixture::demo_thin32();
    let file = read(&bytes).expect("合成样本必须能解析");
    assert!(!file.is_64);
    assert_eq!(file.arch.to_string(), "x86/32/le");
    assert_eq!(file.segments.len(), 1);
    // 32 位 __TEXT：vmaddr = 0x1000、fileoff = 0，entryoff = 0x800 → 0x1800。
    assert_eq!(file.entry.map(|entry| entry.vaddr), Some(0x1800));
}

#[test]
fn a_big_endian_binary_is_read_in_file_order() {
    // 大端 Mach-O 现实中基本只有 ppc/armeb；这里用 arm(12) 走一遍结构层，
    // 证明字段按**文件端序**读，而不是一律小端。
    let spec = fixture::ThinSpec::new32(fixture::CPU_TYPE_ARM, 9)
        .big_endian()
        .segment(
            fixture::SegmentSpec::new("__TEXT", 0x4000, 0x1000, 0, 0x1000)
                .perms(fixture::RX, fixture::RX)
                .section(
                    fixture::SectionSpec::new("__text", "__TEXT", 0x4200, 0x10)
                        .flags(fixture::CODE_FLAGS),
                ),
        )
        .command(fixture::lc_main(0x200, 0, false))
        .min_file_size(0x1000);
    let bytes = fixture::build(&spec);

    let file = read(&bytes).expect("大端结构层应当能解析");
    assert_eq!(file.endian, Endian::Big);
    assert_eq!(file.cputype, fixture::CPU_TYPE_ARM);
    assert_eq!(file.arch.to_string(), "arm/32/be");
    assert_eq!(file.entry.map(|entry| entry.vaddr), Some(0x4200));
    assert!(
        file.notes.iter().any(|note| note.contains("大端")),
        "大端这件事要写在 notes 里：{:?}",
        file.notes
    );
}

#[test]
fn unixthread_pc_is_decoded_for_x86_64() {
    // x86_thread_state64_t 的 rip 是第 17 个 uint64（下标 16），
    // 状态从命令的 +16 开始，所以文件偏移是 16 + 16×8 = 144。
    // 构造器按 32 位字写状态（规范里 `count` 就是以 32 位字计的），
    // 于是 (144 - 16) / 4 = 第 32 个字起：state[32] 是低 32 位、state[33] 是高 32 位。
    let pc = 0x1_0000_2340u64;
    let mut state = vec![0u32; 42];
    state[32] = pc as u32;
    state[33] = (pc >> 32) as u32;

    let spec = fixture::ThinSpec::new64(fixture::CPU_TYPE_X86_64, 3)
        .segment(fixture::SegmentSpec::new(
            "__TEXT",
            0x1_0000_0000,
            0x1000,
            0,
            0x1000,
        ))
        .command(fixture::lc_unix_thread(4, 42, &state, true))
        .min_file_size(0x1000);
    let bytes = fixture::build(&spec);

    let file = read(&bytes).expect("能解析");
    let entry = file.entry.expect("LC_UNIXTHREAD 的 PC 应当解出来");
    assert_eq!(entry.vaddr, pc);
    assert_eq!(
        entry.source,
        EntrySource::UnixThread {
            flavor: 4,
            count: 42
        }
    );
    assert!(
        file.notes
            .iter()
            .any(|note| note.contains("本身就是虚拟地址")),
        "线程状态的 PC 已经是虚拟地址，这件事要说清楚：{:?}",
        file.notes
    );
}

#[test]
fn unixthread_with_an_unknown_flavor_yields_no_entry_and_says_why() {
    // flavor 99 不在已知表里。猜一个偏移会给出错地址，所以入口点留 None。
    let state = vec![0u32; 42];
    let spec = fixture::ThinSpec::new64(fixture::CPU_TYPE_X86_64, 3)
        .segment(fixture::SegmentSpec::new(
            "__TEXT",
            0x1_0000_0000,
            0x1000,
            0,
            0x1000,
        ))
        .command(fixture::lc_unix_thread(99, 42, &state, true))
        .min_file_size(0x1000);
    let bytes = fixture::build(&spec);

    let file = read(&bytes).expect("结构本身合法");
    assert_eq!(file.entry, None, "解不出来就不能编一个入口点");
    let joined = file.notes.join("\n");
    assert!(joined.contains("LC_UNIXTHREAD"), "{joined}");
    assert!(
        joined.contains("没有猜") || joined.contains("没有解"),
        "{joined}"
    );
}

#[test]
fn a_zerofill_section_has_no_file_bytes() {
    // S_ZEROFILL 一族的节在文件里没有字节（__bss 那类）：offset 无意义，
    // 对象模型里文件范围必须是 0 长度，而不是把 offset 当真。
    let spec = fixture::ThinSpec::new64(fixture::CPU_TYPE_ARM64, 0)
        .segment(
            fixture::SegmentSpec::new("__DATA", 0x1_0000_4000, 0x4000, 0x4000, 0x100)
                .perms(fixture::RW, fixture::RW)
                .section(fixture::SectionSpec::new(
                    "__data",
                    "__DATA",
                    0x1_0000_4000,
                    0x10,
                ))
                .section(
                    fixture::SectionSpec::new("__bss", "__DATA", 0x1_0000_4010, 0x100).zerofill(),
                ),
        )
        .min_file_size(0x4100);
    let bytes = fixture::build(&spec);
    let object = parse_bytes(&bytes).expect("能解析");

    let bss = find_section(&object, "__DATA,__bss");
    assert_eq!(bss.kind, ContentKind::Bss);
    assert_eq!(bss.file.size, 0, "零填充节在文件里没有字节");
    assert_eq!(bss.vaddr, 0x1_0000_4010);
}

// ── 拒绝路径（CLAUDE.md §7：畸形输入要精确报错，不要"尽量读"） ──────────────

#[test]
fn sizeofcmds_beyond_the_file_is_rejected() {
    let bytes = fixture::malformed_sizeofcmds_too_big();
    let error = read(&bytes).expect_err("sizeofcmds 比文件还大必须拒绝");
    match error {
        ParseError::Truncated { what, .. } => {
            assert!(what.contains("加载命令区"), "错误要指向命令区：{what}");
        }
        other => panic!("期望 Truncated，实际是 {other:?}"),
    }
}

#[test]
fn ncmds_that_cannot_fit_sizeofcmds_is_rejected() {
    let bytes = fixture::malformed_ncmds_too_big();
    let error = read(&bytes).expect_err("ncmds 装不进 sizeofcmds 必须拒绝");
    assert!(matches!(error, ParseError::Inconsistent(_)), "{error:?}");
    let message = error.summary_zh();
    assert!(message.contains("ncmds"), "{message}");
    assert!(message.contains("sizeofcmds"), "{message}");
}

#[test]
fn a_load_command_overrunning_sizeofcmds_is_rejected() {
    let mut bytes = fixture::demo_thin64();
    // 把命令区压到"头 + 8 字节"，并声明只有 1 条命令：
    // 第一条命令是 72 字节的 __PAGEZERO 段命令，必然越界。
    fixture::patch_u32(&mut bytes, 16, 1, true); // ncmds
    fixture::patch_u32(&mut bytes, 20, 32 + 8, true); // sizeofcmds
    let error = read(&bytes).expect_err("越界的加载命令必须拒绝");
    let message = error.summary_zh();
    assert!(matches!(error, ParseError::Inconsistent(_)), "{error:?}");
    assert!(message.contains("sizeofcmds"), "{message}");
}

#[test]
fn a_cmdsize_that_is_not_a_multiple_of_four_is_rejected() {
    let mut bytes = fixture::demo_thin64();
    // 第一条命令（__PAGEZERO）在 +32，cmdsize 在 +36。规范要求 4 的倍数，
    // 不是的话下一条命令的起点就错位了。
    fixture::patch_u32(&mut bytes, 32 + 4, 74, true);
    let error = read(&bytes).expect_err("cmdsize 非 4 的倍数必须拒绝");
    let message = error.summary_zh();
    assert!(matches!(error, ParseError::Inconsistent(_)), "{error:?}");
    assert!(message.contains("4 的倍数"), "{message}");
}

#[test]
fn a_segment_past_the_end_of_the_file_is_rejected() {
    // 把文件截短到 0x1000，而 __TEXT 声明到 0x4000 —— 文件被裁剪的情形。
    let mut bytes = fixture::demo_thin64();
    bytes.truncate(0x1000);
    let error = read(&bytes).expect_err("段的文件范围越过 EOF 必须拒绝");
    let message = error.summary_zh();
    assert!(matches!(error, ParseError::Inconsistent(_)), "{error:?}");
    assert!(message.contains("__TEXT"), "{message}");
}

#[test]
fn a_section_outside_its_segment_is_rejected() {
    // 段只声明 8 字节的文件范围，却挂着一个 0x80 字节的节：节落在段外。
    let spec = fixture::ThinSpec::new64(fixture::CPU_TYPE_X86_64, 3).segment(
        fixture::SegmentSpec::new("__TEXT", 0x1_0000_0000, 0x4000, 0x1000, 0x8)
            .perms(fixture::RX, fixture::RX)
            .section(fixture::SectionSpec::new(
                "__text",
                "__TEXT",
                0x1_0000_0F00,
                0x80,
            )),
    );
    let bytes = fixture::build(&spec);
    let error = read(&bytes).expect_err("节落在段外必须拒绝");
    let message = error.summary_zh();
    assert!(matches!(error, ParseError::Inconsistent(_)), "{error:?}");
    assert!(message.contains("不在所在段"), "{message}");
}

/// ppc 32 位：`cputype = 18` 现在**能解析**，架构是 `ppc/32/be`。
///
/// 这条测试曾经断言的是"点名拒绝"（`bitflip_arch` 没有 PowerPC 变体也没有
/// 解码后端）。M12 第二片给 arch 层加了变体与 capstone 的 ppc 后端，所以
/// 断言反过来：**能解析，且架构映射对**。ppc 的指令解码由
/// `bitflip-arch` 的单测用真实编码的黄金值覆盖（这里不重复）。
#[test]
fn powerpc_binaries_now_parse_with_their_architecture() {
    let bytes = fixture::demo_thin_ppc32();
    let file = read(&bytes).expect("ppc 32 位样本必须能解析");
    assert_eq!(file.cputype, fixture::CPU_TYPE_POWERPC);
    assert_eq!(file.endian, Endian::Big, "Mach-O 的 ppc 是大端");
    assert_eq!(file.arch.to_string(), "ppc/32/be");
    assert_eq!(file.entry.map(|entry| entry.vaddr), Some(0x1400));
    assert_eq!(file.segments.len(), 1);
    assert!(
        file.notes.iter().any(|note| note.contains("大端")),
        "大端这件事要写在 notes 里：{:?}",
        file.notes
    );

    let object = parse_bytes(&bytes).expect("对象模型也要能建起来");
    assert_eq!(object.arch.to_string(), "ppc/32/be");
    assert_eq!(object.entry, Some(0x1400));
}

/// ppc64：`cputype = 0x01000012` → `ppc64/64/be`。
#[test]
fn powerpc64_binaries_map_to_the_64bit_architecture() {
    let bytes = fixture::demo_thin_ppc64();
    let file = read(&bytes).expect("ppc64 样本必须能解析");
    assert!(file.is_64);
    assert_eq!(file.cputype, fixture::CPU_TYPE_POWERPC64);
    assert_eq!(file.arch.to_string(), "ppc64/64/be");
    assert_eq!(file.entry.map(|entry| entry.vaddr), Some(0x1_0000_0500));
}

/// 小端文件头配 ppc 的 `cputype`：照读，但要说出"这不是常规产物"。
///
/// 现实里 Mach-O 的 ppc 切片一律是大端。这条不是拒绝，而是"事实说明" ——
/// 结构层按文件端序读，结论自洽；但用户看到一个 ppc 的 Mach-O 是小端时，
/// 有权知道这不合常规（CLAUDE.md §7：降级/反常要写在结论里）。
#[test]
fn a_little_endian_ppc_header_is_parsed_but_flagged() {
    let spec = fixture::ThinSpec::new32(fixture::CPU_TYPE_POWERPC, 0).segment(
        fixture::SegmentSpec::new("__TEXT", 0x1000, 0x1000, 0, 0x1000)
            .perms(fixture::RX, fixture::RX),
    );
    let bytes = fixture::build(&spec);
    let file = read(&bytes).expect("小端 ppc 头不是格式错误");
    assert_eq!(file.endian, Endian::Little);
    assert_eq!(file.arch.to_string(), "ppc/32/le");
    assert!(
        file.notes
            .iter()
            .any(|note| note.contains("不是 Apple 工具链的常规产物")),
        "小端 ppc 这件反常必须写进 notes：{:?}",
        file.notes
    );
}

#[test]
fn an_unknown_cputype_is_rejected_instead_of_guessed() {
    let spec = fixture::ThinSpec::new32(0x1234, 0).segment(
        fixture::SegmentSpec::new("__TEXT", 0x1000, 0x1000, 0, 0x1000)
            .perms(fixture::RX, fixture::RX),
    );
    let bytes = fixture::build(&spec);
    match read(&bytes) {
        Err(ParseError::Unsupported { what, value, .. }) => {
            assert_eq!(what, "cputype");
            assert_eq!(value, 0x1234);
        }
        other => panic!("期望 Unsupported，实际是 {other:?}"),
    }
}

#[test]
fn a_bad_magic_is_reported_as_a_bad_magic() {
    let error = read(b"\x7fELF\x02\x01\x01\x00").expect_err("ELF 不是 Mach-O");
    match error {
        ParseError::BadMagic { expected, actual } => {
            assert!(expected.contains("Mach-O"), "{expected}");
            assert!(actual.contains("0x"), "{actual}");
        }
        other => panic!("期望 BadMagic，实际是 {other:?}"),
    }
}

#[test]
fn fat_input_is_refused_by_the_thin_parser() {
    // fat 文件没有"这个文件"的单一架构：薄解析器必须明确拒绝，
    // 而不是把架构表当加载命令去读。
    let bytes = fixture::demo_fat();
    let error = parse_bytes(&bytes).expect_err("fat 输入不能走薄解析");
    match error {
        ParseError::NotSupported { what, detail } => {
            assert_eq!(what, "容器");
            assert!(detail.contains("fat"), "{detail}");
        }
        other => panic!("期望 NotSupported，实际是 {other:?}"),
    }
}

// ── 符号表（LC_SYMTAB） ────────────────────────────────────────────────────

/// 64 位样本的 `LC_SYMTAB`：3 条符号里 1 条是 stab，对象模型只收另外 2 条。
///
/// 名字断言盯着"前缀字节占掉偏移 0"这一点：字符串表是 `" " + "_main\0…"`，
/// 所以按 `n_strx` 取到的名字是 `_main`；要是解析器按偏移 0 或按顺序取，
/// 这里会变成 `" _main"` 或别的东西（CLAUDE.md §6.11：样本按规范拼，不按解析器拼）。
#[test]
fn symtab_symbols_carry_names_sections_and_externality() {
    let bytes = fixture::demo_symbols64();
    let file = read(&bytes).expect("带 LC_SYMTAB 的样本必须能解析");

    assert!(file.has_symtab);
    assert_eq!(file.symbols.len(), 3, "样本里有 3 条 nlist_64");
    assert_eq!(file.stab_symbols, 1, "其中第 3 条是 N_FUN 调试 stab");
    assert_eq!(
        file.symbols
            .iter()
            .map(|s| s.name.as_str())
            .collect::<Vec<_>>(),
        vec!["_main", "_printf", "main.c"],
        "名字必须按 n_strx 从字符串表里取（偏移 0 是前缀字节，不是名字）"
    );

    let main = &file.symbols[0];
    assert_eq!(main.value, 0x1_0000_0F00);
    assert_eq!(main.n_type, fixture::N_SECT | fixture::N_EXT);
    assert_eq!(main.n_sect, 1, "n_sect 是 1 基的跨段节号");
    assert_eq!(main.section.as_deref(), Some("__TEXT,__text"));
    assert!(main.is_external() && !main.is_undefined() && !main.is_stab());
    assert!(main.is_function, "__text 是代码节，符号落在这里才算函数");
    assert!(!main.is_weak());

    let printf = &file.symbols[1];
    assert_eq!(printf.value, 0, "未定义符号的 n_value 是 0");
    assert_eq!(printf.n_sect, 0, "NO_SECT");
    assert_eq!(printf.section, None, "没有节号就没有节名（不猜）");
    assert!(printf.is_undefined() && printf.is_external());
    assert!(!printf.is_function);

    let stab = &file.symbols[2];
    assert_eq!(stab.n_type, fixture::N_FUN);
    assert!(stab.is_stab(), "0x24 & N_STAB(0xe0) = 0x20 != 0");
}

#[test]
fn the_object_model_drops_stabs_but_keeps_the_count_in_notes() {
    let object = parse_bytes(&fixture::demo_symbols64()).expect("能解析");

    assert_eq!(object.symbols.len(), 2, "stab 不是普通符号");
    assert!(!object.format.is_stripped, "有普通符号就不是剥离过的");
    let names: Vec<&str> = object
        .symbols
        .iter()
        .map(|symbol| symbol.name.as_str())
        .collect();
    assert_eq!(names, vec!["_main", "_printf"]);

    let main = &object.symbols[0];
    assert_eq!(main.value, 0x1_0000_0F00);
    // `nlist` 没有大小字段：0 是"未知"，不是"零字节"。
    assert_eq!(main.size, 0);
    assert!(main.defined && main.is_function && !main.is_weak);
    assert_eq!(main.section.as_deref(), Some("__TEXT,__text"));
    // `bind` 沿用 PE/COFF 那条最小交集映射：N_EXT → 全局(1)。
    assert_eq!(main.bind, 1);

    let printf = &object.symbols[1];
    assert!(!printf.defined, "N_UNDF 就是未定义");
    assert_eq!(printf.bind, 1, "外部未定义符号仍然是外部符号");
    assert_eq!(
        printf.source.as_str(),
        "symtab",
        "来源记 Static，表示它来自完整符号表"
    );

    let joined = object.notes.join("\n");
    assert!(
        joined.contains("调试 stab") && joined.contains("1"),
        "stab 被排除这件事必须写进 notes：{joined}"
    );
    assert!(
        joined.contains("没有大小字段"),
        "size = 0 是未知而不是零字节，这一点要说出来：{joined}"
    );
}

/// 32 位样本用 12 字节的 `nlist`（不是 16 字节的 `nlist_64`）。
#[test]
fn a_32bit_symtab_uses_twelve_byte_entries() {
    let bytes = fixture::demo_symbols32();
    assert!(!read(&bytes).expect("能解析").is_64);
    let file = read(&bytes).expect("能解析");

    assert_eq!(file.symbols.len(), 2);
    assert_eq!(file.symbols[0].name, "_start");
    assert_eq!(file.symbols[0].value, 0x1800);
    assert!(file.symbols[0].is_function);
    // 第 2 条在第 1 条之后 12 字节处。若按 16 字节步进，这一条会读到
    // 字符串表或表外，名字/值都不可能是这个。
    assert_eq!(file.symbols[1].name, "_abort");
    assert_eq!(file.symbols[1].value, 0);
    assert!(file.symbols[1].is_undefined());

    let object = parse_bytes(&bytes).expect("对象模型也要能建起来");
    assert_eq!(
        object
            .symbols
            .iter()
            .map(|symbol| symbol.name.as_str())
            .collect::<Vec<_>>(),
        vec!["_start", "_abort"]
    );
}

/// `n_strx` 指向字符串表之外 ⇒ 拒绝（不读表外字节，也不退回空名字）。
#[test]
fn a_name_offset_past_the_string_table_is_rejected() {
    let bytes = fixture::malformed_symbol_name_past_strsize();
    let error = read(&bytes).expect_err("n_strx 越界必须拒绝");
    assert!(matches!(error, ParseError::Inconsistent(_)), "{error:?}");
    let message = error.to_string();
    assert!(message.contains("n_strx"), "{message}");
    assert!(message.contains("字符串表"), "{message}");
}

/// `symoff` 指向文件之外 ⇒ 拒绝（整表范围先校验）。
#[test]
fn a_symbol_table_past_the_end_of_the_file_is_rejected() {
    let bytes = fixture::malformed_symoff_past_eof();
    let error = read(&bytes).expect_err("symoff 越界必须拒绝");
    assert!(matches!(error, ParseError::Inconsistent(_)), "{error:?}");
    let message = error.to_string();
    assert!(message.contains("LC_SYMTAB"), "{message}");
    assert!(message.contains("超出文件大小"), "{message}");
}

// ── 函数起点（LC_FUNCTION_STARTS） ─────────────────────────────────────────

/// ULEB128 增量序列：第一个相对镜像基址，其后相对上一个起点。
#[test]
fn function_starts_are_decoded_from_uleb_deltas() {
    let bytes = fixture::demo_function_starts64();
    let file = read(&bytes).expect("带 LC_FUNCTION_STARTS 的样本必须能解析");

    assert_eq!(
        file.function_starts,
        vec![0x1_0000_0120, 0x1_0000_024C, 0x1_0000_025C],
        "0x120 是相对 __TEXT.vmaddr 的增量，300 是**两字节** ULEB128，0x10 是再下一个增量"
    );
    // 升序是契约的一部分：分析层拿它当函数边界，顺序错了边界就错。
    assert!(file.function_starts.windows(2).all(|w| w[0] < w[1]));

    let object = parse_bytes(&bytes).expect("对象模型也要能建起来");
    assert_eq!(object.function_starts, file.function_starts);
    let joined = object.notes.join("\n");
    assert!(
        joined.contains("LC_FUNCTION_STARTS") && joined.contains('3'),
        "解出几个起点必须写进 notes：{joined}"
    );
}

/// payload 在最后一个增量中间结束 ⇒ 解出能解的，并说明"可能被截断"。
///
/// 这条钉住的是 §7 里最容易犯错的那一类：**短表**看起来像"这个文件只有两个函数"，
/// 所以必须有一条 notes 说明它是被截断的。
#[test]
fn a_truncated_function_starts_payload_is_reported_not_silently_short() {
    let bytes = fixture::function_starts_without_terminator64();
    let file = read(&bytes).expect("截断的 payload 不是解析错误");
    assert_eq!(file.function_starts.len(), 2, "完整的那两个增量要解出来");
    let joined = file.notes.join("\n");
    assert!(joined.contains("截断"), "{joined}");
    assert!(joined.contains("终止符"), "{joined}");
}

/// `dataoff` 越过 EOF ⇒ 拒绝（表外没有合法解释）。
#[test]
fn function_starts_past_the_end_of_the_file_are_rejected() {
    let bytes = fixture::malformed_function_starts_past_eof();
    let error = read(&bytes).expect_err("dataoff 越界必须拒绝");
    assert!(matches!(error, ParseError::Inconsistent(_)), "{error:?}");
    let message = error.to_string();
    assert!(message.contains("LC_FUNCTION_STARTS"), "{message}");
    assert!(message.contains("超出文件大小"), "{message}");
}

// ── 诚实性：没做的部分必须出现在 notes 里 ──────────────────────────────────

#[test]
fn unimplemented_capabilities_are_stated_in_notes() {
    // `demo_thin64` 里那条 LC_SYMTAB 的 nsyms 是 0：这是"命令在、表是空的"，
    // 必须与"没有这条命令"说得不一样（§7）。dyld 绑定仍然没解析。
    let object = parse_bytes(&fixture::demo_thin64()).expect("能解析");
    assert!(
        object.symbols.is_empty(),
        "nsyms = 0 的符号表解不出符号，这是文件里的事实"
    );
    assert!(object.imports.is_empty(), "本片没有 dyld 绑定信息");
    assert!(object.function_starts.is_empty(), "样本里没有这条命令");
    let joined = object.notes.join("\n");
    assert!(
        joined.contains("LC_SYMTAB") && joined.contains("nsyms = 0"),
        "空符号表这件事必须说出来：{joined}"
    );
    assert!(
        joined.contains("没有 LC_FUNCTION_STARTS"),
        "缺哪张表就说哪张表，而不是让空表冒充\"没有函数\"：{joined}"
    );
    // 样本里没有 LC_DYLD_INFO / LC_CODE_SIGNATURE，所以那两条不该出现。
    assert!(!joined.contains("LC_CODE_SIGNATURE"), "{joined}");
}

#[test]
fn a_binary_without_symtab_says_it_is_stripped() {
    let spec = fixture::ThinSpec::new64(fixture::CPU_TYPE_ARM64, 2)
        .segment(fixture::SegmentSpec::new(
            "__TEXT",
            0x1_0000_0000,
            0x1000,
            0,
            0x1000,
        ))
        .min_file_size(0x1000);
    let bytes = fixture::build(&spec);
    let object = parse_bytes(&bytes).expect("能解析");
    assert!(
        object.format.is_stripped,
        "没有 LC_SYMTAB 就没有可引用的符号，所以是「已剥离」"
    );
    let joined = object.notes.join("\n");
    assert!(joined.contains("没有 LC_SYMTAB"), "{joined}");
}

#[test]
fn the_arm64e_subtype_is_noted() {
    let spec = fixture::ThinSpec::new64(fixture::CPU_TYPE_ARM64, fixture::CPU_SUBTYPE_ARM64E)
        .segment(fixture::SegmentSpec::new(
            "__TEXT",
            0x1_0000_0000,
            0x1000,
            0,
            0x1000,
        ))
        .min_file_size(0x1000);
    let bytes = fixture::build(&spec);
    let file = read(&bytes).expect("arm64e 应当能解析");
    assert_eq!(file.arch.to_string(), "aarch64/64/le");
    assert!(
        file.notes
            .iter()
            .any(|note| note.contains("CPU_SUBTYPE_ARM64E")),
        "arm64e 的 PAC 语义没还原这件事必须说出来：{:?}",
        file.notes
    );
}

#[test]
fn objc_and_swift_sections_are_listed_but_not_parsed() {
    let spec = fixture::ThinSpec::new64(fixture::CPU_TYPE_ARM64, 0)
        .segment(
            fixture::SegmentSpec::new("__DATA", 0x1_0000_4000, 0x4000, 0x1000, 0x100)
                .perms(fixture::RW, fixture::RW)
                .section(fixture::SectionSpec::new(
                    "__objc_classname",
                    "__DATA",
                    0x1_0000_4000,
                    0x20,
                ))
                .section(fixture::SectionSpec::new(
                    "__swift5_types",
                    "__DATA",
                    0x1_0000_4020,
                    0x10,
                )),
        )
        .min_file_size(0x1100);
    let bytes = fixture::build(&spec);
    let object = parse_bytes(&bytes).expect("能解析");
    let joined = object.notes.join("\n");
    assert!(joined.contains("__objc_*"), "{joined}");
    assert!(joined.contains("__swift*"), "{joined}");
}
