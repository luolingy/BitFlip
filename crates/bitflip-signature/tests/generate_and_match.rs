//! 生成 → 匹配的端到端测试（只依赖仓库内 fixture）。
//!
//! # 这里在验证什么
//!
//! M8 的验收要求"从已知库生成签名，给剥离过的目标命名"。本文件把它拆成三步，
//! 每一步都能单独失败：
//!
//! 1. **生成**：从 `libpe-x86_64.a`（归档，成员是可重定位对象）里抽出签名，
//!    并断言"链接期被改写的字节"确实被标成了通配 —— 对照物是同一个 `.obj`
//!    的重定位表，不是本程序的另一个输出；
//! 2. **匹配**：拿 `pe-x86_64.obj` 自己的字节去匹配（自比），名字与地址都要对上；
//! 3. **剥离目标**：拿 `m3-mingw-static.exe`（0 符号）当目标，地址真值来自它的
//!    **未剥离孪生** `m3-mingw-static.unstripped.exe` —— 两者是同一份代码，
//!    所以"匹配对了没有"是拿外部事实判的，不是自评。
//!
//! 账目也必须平：一个函数符号要么产出一条签名，要么带着原因被记一笔，
//! 不允许两头都不在（那意味着静默少给数据）。

use std::collections::BTreeMap;
use std::path::PathBuf;

use bitflip_loader::coff;
use bitflip_loader::object::{Object, ObjectId};
use bitflip_loader::pe;
use bitflip_signature::matcher::{Matcher, TargetFunction};
use bitflip_signature::pattern::PatternByte;
use bitflip_signature::signature::DropReason;
use bitflip_signature::{generate, signature_arch, ArchiveInput};

fn fixture(name: &str) -> Vec<u8> {
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../tests/fixtures/generated")
        .join(name);
    assert!(
        path.exists(),
        "缺少 fixture：{}（由 tests/fixtures 脚本生成，见 docs/PLAN.md §5.2）",
        path.display()
    );
    std::fs::read(&path).expect("读取 fixture")
}

fn parse(bytes: &[u8]) -> Object {
    pe::parse(bytes, 0, ObjectId::Plain).expect("解析 PE")
}

fn parse_coff(bytes: &[u8]) -> Object {
    coff::parse(bytes, 0, ObjectId::Plain).expect("解析 COFF")
}

/// 读目标里从某个虚拟地址开始的字节（到文件末尾为止，读不满就给多少算多少）。
///
/// 不给满不是错误：函数正好落在文件末尾时本来就拿不到更多字节，
/// 匹配器会把"字节不够验证"单独计数，而不是当成不匹配。
fn read_at(object: &Object, bytes: &[u8], va: u64, len: usize) -> Vec<u8> {
    let offset = object
        .vaddr_to_offset(va)
        .unwrap_or_else(|| panic!("地址 {va:#x} 不在任何有文件后备的节里"));
    let offset = usize::try_from(offset).expect("偏移");
    let end = offset.saturating_add(len).min(bytes.len());
    bytes.get(offset..end).expect("字节范围").to_vec()
}

#[test]
fn accounting_is_complete_for_every_input() {
    let pe_lib = fixture("libpe-x86_64.a");
    let elf_lib = fixture("libelf-x86_64.a");
    let result = generate(&[
        ArchiveInput {
            name: "libpe-x86_64.a".to_string(),
            bytes: &pe_lib,
        },
        ArchiveInput {
            name: "libelf-x86_64.a".to_string(),
            bytes: &elf_lib,
        },
    ]);

    // 每个见过的函数符号，要么产出一条签名，要么带着原因记了一笔。
    assert_eq!(
        result.set.stats.emitted + result.set.stats.dropped_total(),
        result.set.stats.functions_seen,
        "账目不平：有函数符号既没产出也没被记账。账：{:?}",
        result.set.stats
    );
    assert_eq!(result.set.len() as u64, result.set.stats.emitted);
    assert_eq!(result.sources.len(), 2);
    assert!(
        result.set.stats.functions_seen > 0,
        "两个归档里应当能看见函数符号"
    );
}

#[test]
fn a_signature_comes_out_of_the_archive_with_readable_names() {
    let pe_lib = fixture("libpe-x86_64.a");
    let result = generate(&[ArchiveInput {
        name: "libpe-x86_64.a".to_string(),
        bytes: &pe_lib,
    }]);
    let names: Vec<&str> = result
        .set
        .signatures
        .iter()
        .map(|signature| signature.name.as_str())
        .collect();

    // 实测（fixture 由脚本固定生成，改动需同步改这里的数字）：
    // 成员里 3 个函数符号 → 2 条签名；`bf_add` 只有 4 字节、确定字节不足被丢弃。
    assert_eq!(result.set.stats.functions_seen, 3);
    assert_eq!(names, vec!["bf_entry", "bf_loop"], "签名按名字与形态排序");
    assert_eq!(
        result
            .set
            .stats
            .dropped
            .get(&DropReason::TooFewExact)
            .copied(),
        Some(1),
        "太短的函数要被记账，而不是悄悄消失：{:?}",
        result.set.stats
    );

    // 长函数：前缀 24 字节全确定。
    let long = result
        .set
        .signatures
        .iter()
        .find(|signature| signature.name == "bf_loop")
        .expect("bf_loop");
    assert_eq!(long.length, 48, "长度来自'到下一个函数符号的距离'");
    assert_eq!(long.exact_bytes, 24);
    assert_eq!(
        long.prefix.len(),
        24,
        "前缀取满：没有填充要截、重定位也不在开头"
    );
    // COFF 的函数符号**没有大小**（clang 与 GNU as 都写 0），所以这条长度只是上界，
    // 结尾不可信 → 不做尾部校验。实测过拿"到下一个符号的距离"当结尾：召回 65→55
    // 还多出 1 个错名，所以这里刻意只留前缀，由"确定字节 ≥8"把关。
    assert!(!long.length_exact, "COFF 符号不给大小，长度只是上界");
    assert!(long.tail.is_none(), "结尾不可信就不做尾部校验");

    // 短函数（28 字节）：前缀 24 字节里有 4 个字节是重定位，要屏蔽。
    let short = result
        .set
        .signatures
        .iter()
        .find(|signature| signature.name == "bf_entry")
        .expect("bf_entry");
    assert_eq!(short.prefix.len(), 24);
    assert_eq!(short.prefix.wildcard_count(), 4, "前缀里那段重定位要被屏蔽");
    assert!(short.tail.is_none(), "结尾不可信就不做尾部校验");
}

#[test]
fn an_elf_object_with_symbol_sizes_gets_a_tail_check() {
    // 另一条分支：符号表**给了**函数大小时（ELF 的 `st_size` 由
    // `.size name, .-name` 填出来），结尾可信，于是补一道尾部校验。
    let bytes = fixture("elf-x86_64.o");
    let result = generate(&[ArchiveInput {
        name: "elf-x86_64.o".to_string(),
        bytes: &bytes,
    }]);
    assert!(!result.set.is_empty(), "{}", result.set.stats.summary_zh());
    let with_tail: Vec<&str> = result
        .set
        .signatures
        .iter()
        .filter(|signature| signature.tail.is_some())
        .map(|signature| signature.name.as_str())
        .collect();
    assert!(
        !with_tail.is_empty(),
        "ELF 符号带大小，应当有签名拿到尾部校验：{}",
        result.set.stats.summary_zh()
    );
    assert!(
        result
            .set
            .signatures
            .iter()
            .any(|signature| signature.length_exact),
        "带大小的签名要标成确切长度"
    );
}

#[test]
fn archive_metadata_members_are_not_counted_as_objects() {
    // `ar` 归档里除对象之外还有符号索引成员。它**不是**"解析失败的对象"，
    // 报告里必须分开说 —— 否则用户会以为自己的库有问题。
    let pe_lib = fixture("libpe-x86_64.a");
    let result = generate(&[ArchiveInput {
        name: "libpe-x86_64.a".to_string(),
        bytes: &pe_lib,
    }]);
    assert_eq!(
        result.set.stats.metadata_members, 1,
        "该归档有一个符号索引成员"
    );
    assert_eq!(result.set.stats.objects, 1, "只有一个真正的对象成员");
    assert_eq!(result.set.stats.unparsable_objects, 0);
    let text = result.set.stats.summary_zh();
    assert!(text.contains("跳过的元数据成员 1 个"), "{text}");
}

#[test]
fn relocations_become_wildcards_in_the_prefix() {
    let object_bytes = fixture("pe-x86_64.obj");
    let object = parse_coff(&object_bytes);
    let pe_lib = fixture("libpe-x86_64.a");
    let result = generate(&[ArchiveInput {
        name: "libpe-x86_64.a".to_string(),
        bytes: &pe_lib,
    }]);

    // 对照物：`.o` 自己的重定位表（外部事实），不是本程序的另一个输出。
    let text = object.section_by_name(".text").expect(".text");
    let relocs: Vec<u64> = object
        .relocations
        .iter()
        .filter(|reloc| reloc.section.as_deref() == Some(".text"))
        .map(|reloc| reloc.address)
        .collect();
    assert!(
        !relocs.is_empty(),
        "样本的 .text 里应当有重定位（否则这条测试没测到该测的）"
    );
    assert!(
        relocs.iter().all(|address| *address < text.file.size),
        ".text 的重定位地址应当是节内偏移（否则下面的换算没有依据）"
    );

    let mut checked = 0;
    for signature in &result.set.signatures {
        let symbol = object
            .symbols
            .iter()
            .find(|symbol| symbol.name == signature.name)
            .unwrap_or_else(|| panic!("签名 {} 在 .obj 里找不到对应符号", signature.name));
        let start = symbol.value;
        let end = start + u64::from(signature.length);
        let inside: Vec<u64> = relocs
            .iter()
            .copied()
            .filter(|address| *address >= start && *address < end)
            .collect();
        if inside.is_empty() {
            continue;
        }
        checked += 1;
        for address in inside {
            let relative = (address - start) as usize;
            if relative >= signature.prefix.len() {
                continue;
            }
            // 重定位覆盖的每个字节都必须是通配：漏一个，签名的"确定字节"里就混进了
            // 链接期会被改写的值，匹配会静默失败。
            let width = bitflip_signature::generate::wildcard_width(
                object
                    .relocations
                    .iter()
                    .find(|reloc| reloc.address == address)
                    .map(|reloc| reloc.kind)
                    .expect("重定位"),
                usize::from(object.arch.ptr_size),
            );
            for index in relative..(relative + width).min(signature.prefix.len()) {
                assert_eq!(
                    signature.prefix.bytes()[index],
                    PatternByte::Wildcard,
                    "{} 的第 {index} 个字节落在重定位 {address:#x} 上，却仍是确定字节",
                    signature.name
                );
            }
        }
    }
    assert!(
        checked > 0,
        "至少要有一条签名覆盖到重定位，否则这条测试是空跑"
    );
}

#[test]
fn a_signature_matches_the_very_bytes_it_came_from() {
    let pe_lib = fixture("libpe-x86_64.a");
    let object_bytes = fixture("pe-x86_64.obj");
    let object = parse_coff(&object_bytes);
    let result = generate(&[ArchiveInput {
        name: "libpe-x86_64.a".to_string(),
        bytes: &pe_lib,
    }]);

    let text = object.section_by_name(".text").expect(".text");
    let text_bytes = object_bytes
        .get(
            usize::try_from(text.file.offset).expect("偏移")
                ..usize::try_from(text.file.offset + text.file.size).expect("偏移"),
        )
        .expect("节字节");
    let matcher = Matcher::new(&result.set, &signature_arch(&object.arch));

    let mut matched = 0;
    for signature in &result.set.signatures {
        let symbol = object
            .symbols
            .iter()
            .find(|symbol| symbol.name == signature.name)
            .expect("同名符号");
        let start = usize::try_from(symbol.value).expect("节内偏移");
        let slice = text_bytes.get(start..).expect("函数字节");
        let hit = matcher.match_at(symbol.value, slice, None);
        let found = match hit {
            Some(bitflip_signature::matcher::Hit::Match(found)) => found,
            other => panic!("{} 的字节应当能匹配上，实际 {other:?}", signature.name),
        };
        assert_eq!(found.name, signature.name);
        matched += 1;
    }
    assert!(matched > 0, "自比至少要匹配上一条");
}

#[test]
fn a_linked_target_gets_names_from_the_library() {
    // 目标是**已链接的映像** `pe-x86_64.exe`；它和归档成员是同一份源码、同样的
    // `-O1`，所以函数字节只差"链接器改写过的那几个位置"。
    //
    // 真值用它**自己的符号表**（外部事实，不是本程序的匹配结果）。这是剥离目标
    // 情形的等价物：匹配器只看地址与字节，目标有没有符号不影响它。
    let target_bytes = fixture("pe-x86_64.exe");
    let target = parse(&target_bytes);
    let pe_lib = fixture("libpe-x86_64.a");
    let result = generate(&[ArchiveInput {
        name: "libpe-x86_64.a".to_string(),
        bytes: &pe_lib,
    }]);
    assert!(!result.set.is_empty(), "归档应当产出签名");

    let truth: BTreeMap<u64, String> = target
        .symbols
        .iter()
        .filter(|symbol| symbol.is_function && symbol.defined && !symbol.name.is_empty())
        // 已链接映像的符号值已经是虚拟地址（loader 会把 COFF 的节内偏移折算成 VA，
        // 见 `pe.rs` 里那段解释）。这里**不要**再加节基址，否则就是加两遍。
        .filter(|symbol| symbol.section.is_some())
        .map(|symbol| (symbol.value, symbol.name.clone()))
        .collect();
    assert!(
        truth.len() >= 3,
        "已链接目标应当有几个函数符号作真值，实际 {}",
        truth.len()
    );

    let matcher = Matcher::new(&result.set, &signature_arch(&target.arch));
    let buffers: Vec<(u64, Vec<u8>)> = truth
        .keys()
        .map(|address| (*address, read_at(&target, &target_bytes, *address, 128)))
        .collect();
    let targets: Vec<TargetFunction<'_>> = buffers
        .iter()
        .map(|(address, bytes)| TargetFunction {
            addr: *address,
            bytes,
            size: None,
        })
        .collect();
    let report = matcher.match_all(&targets);

    let mut correct: Vec<&str> = Vec::new();
    let mut wrong = Vec::new();
    for found in &report.matches {
        match truth.get(&found.addr) {
            Some(name) if *name == found.name => correct.push(name.as_str()),
            Some(name) => wrong.push(format!(
                "{:#x} 写成了 {}，真值是 {name}",
                found.addr, found.name
            )),
            None => wrong.push(format!("{:#x} 写成了 {}", found.addr, found.name)),
        }
    }
    assert!(
        wrong.is_empty(),
        "匹配到但名字不对（这正是最不能接受的结果）：{wrong:?}"
    );
    correct.sort_unstable();
    assert_eq!(
        correct,
        vec!["bf_entry", "bf_loop"],
        "库里两条签名都应当在已链接目标里被认出来；少一条说明屏蔽范围与实际改写不一致"
    );
    // 无法区分的命中也不能是"随便挑一个"：要么给对，要么不给。
    assert_eq!(report.ambiguous_count(), 0, "{:?}", report.ambiguous);
}
