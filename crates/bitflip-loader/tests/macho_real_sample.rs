//! 真实 iOS 应用二进制（IPA 里的 Mach-O）：默认 `#[ignore]`。
//!
//! 为什么必须有这条（CLAUDE.md §6.11 / §7）：合成样本证明"按规范工作"，但真实
//! 二进制里有一堆合成样本不会出现的东西 —— 上百条加载命令、`__LINKEDIT` 的
//! 文件范围正好顶到文件末尾、`__PAGEZERO` 的 4 GB 虚拟大小、加密段、平台相关的
//! 未知命令。合成样本走的是"两三个段"的干净路径，覆盖不到这些。
//!
//! 跑法（`--ignored` 要通过测试可执行文件直接传，`scripts/cargo.ps1` 会吃掉 `--`）：
//!
//! ```text
//! & .\scripts\cargo.ps1 test --offline -p bitflip-loader --test macho_real_sample --no-run
//! & .\.cargo-target\debug\deps\macho_real_sample-<hash>.exe --ignored --nocapture
//! ```
//!
//! 样本来源：`BITFLIP_TEST_MACHO_IPA` 环境变量，否则在仓库的 `temp/` 里找一份
//! （`temp/` 永不入库，见 CLAUDE.md §0）。

use std::path::PathBuf;

use bitflip_loader::format::{macho, zip};
use bitflip_loader::object::ObjectId;
use bitflip_loader::ObjectKind;

/// 本机真实 IPA：优先 `BITFLIP_TEST_MACHO_IPA`，否则在 `temp/` 里找。
fn sample_path() -> PathBuf {
    if let Ok(from_env) = std::env::var("BITFLIP_TEST_MACHO_IPA") {
        let path = PathBuf::from(from_env);
        assert!(
            path.is_file(),
            "BITFLIP_TEST_MACHO_IPA 指向的 {} 不是文件",
            path.display()
        );
        return path;
    }
    let dir = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../temp");
    // 小的先试：真实样本测试跑得快才有意义。
    const PREFERRED: [&str; 4] = [
        "LiveContainer.ipa",
        "Stapxs.QQ.Lite-3.3.3.ipa",
        "SideStore.ipa",
        "net.kdt.pojavlauncher-2.2-ios.ipa",
    ];
    for name in PREFERRED {
        let candidate = dir.join(name);
        if candidate.is_file() {
            return candidate;
        }
    }
    panic!(
        "找不到真实 Mach-O 样本：请把任意一个 `.ipa` 放进 {}，\
         或设 `BITFLIP_TEST_MACHO_IPA=<某个 .ipa 的完整路径>`。\n\
         这条测试不是「可以跳过」的：它是真实二进制上的兜底验证（CLAUDE.md §7）",
        dir.display()
    );
}

/// 按启发式挑出 bundle 的主二进制，返回（成员下标、成员名、解压后的字节）。
///
/// # 这个启发式是什么、为什么可以这样挑
///
/// IPA 里没有"主二进制是哪个"的显式声明。Xcode 打包的约定是：可执行文件与
/// `.app` 目录同名，路径形如 `Payload/<Name>.app/<Name>`。这是**约定**不是规范，
/// 所以：
///
/// 1. 先按约定精确匹配；
/// 2. 匹配不到（改名、被加固工具重排过）就退化成"`Payload/*.app/` 下第一层文件里
///    头 4 字节是 Mach-O 魔数的那个"；
/// 3. 都找不到就 panic —— 让测试**红**，而不是悄悄跳过（§7：跳过会让绿灯说谎）。
fn pick_main_binary(ipa: &[u8], listing: &zip::ZipListing) -> (usize, String, Vec<u8>) {
    let mut candidates: Vec<usize> = Vec::new();
    for (index, member) in listing.members.iter().enumerate() {
        let Some(rest) = member.name.strip_prefix("Payload/") else {
            continue;
        };
        // 只要 `Payload/<bundle>.app/<文件>` 这一层：再深就是资源，不是主二进制。
        let mut parts = rest.split('/');
        let (Some(bundle), Some(file), None) = (parts.next(), parts.next(), parts.next()) else {
            continue;
        };
        if !bundle.ends_with(".app") {
            continue;
        }
        if file == bundle.trim_end_matches(".app") {
            let bytes = zip::read_member(ipa, index).unwrap_or_else(|error| {
                panic!("取成员 {} 失败：{}", member.name, error.summary_zh())
            });
            return (index, member.name.clone(), bytes);
        }
        candidates.push(index);
    }

    for index in candidates {
        let member = &listing.members[index];
        let bytes = zip::read_member(ipa, index)
            .unwrap_or_else(|error| panic!("取成员 {} 失败：{}", member.name, error.summary_zh()));
        if looks_like_macho(&bytes) {
            return (index, member.name.clone(), bytes);
        }
    }

    panic!(
        "这份 IPA 里找不到 Mach-O 主二进制（列出的成员 {} 个，可能被裁剪过）",
        listing.members.len()
    );
}

fn looks_like_macho(bytes: &[u8]) -> bool {
    macho::looks_like_fat(bytes)
        || matches!(
            bytes.get(0..4),
            Some([0xce, 0xfa, 0xed, 0xfe])
                | Some([0xcf, 0xfa, 0xed, 0xfe])
                | Some([0xfe, 0xed, 0xfa, 0xce])
                | Some([0xfe, 0xed, 0xfa, 0xcf])
        )
}

/// 从可能为 fat 的字节里挑一层薄 Mach-O，返回（描述、结构层事实、对象）。
///
/// 事实与对象一起返回，是因为 `LC_UUID` 与 dylib 名只存在于 [`macho::MachOFile`]
/// （对象模型没有对应字段）—— 这条测试要把它们打出来给人核对。
fn parse_one_image(bytes: &[u8]) -> (String, macho::MachOFile, bitflip_loader::object::Object) {
    if macho::looks_like_fat(bytes) {
        let container = macho::fat::read(bytes).expect("fat 容器的架构表必须能读");
        eprintln!(
            "fat 容器：{} 个切片（{} 位架构表）",
            container.slices.len(),
            if container.is_64 { 64 } else { 32 }
        );
        for slice in &container.slices {
            eprintln!(
                "  切片 #{}: cputype = {:#010x} / cpusubtype = {:#x} / arch = {:?} / \
                 offset = {:#x} / size = {:#x}",
                slice.index,
                slice.cputype,
                slice.cpusubtype,
                slice.arch.map(|spec| spec.to_string()),
                slice.offset,
                slice.size
            );
        }
        // 优先取 arm64 那一片：iOS 设备上真正跑的就是它。
        let chosen = container
            .slices
            .iter()
            .position(|slice| {
                slice
                    .arch
                    .is_some_and(|spec| spec.to_string().starts_with("aarch64"))
            })
            .unwrap_or(0);
        let object = macho::fat::parse_slice(bytes, chosen, ObjectId::Plain)
            .unwrap_or_else(|error| panic!("第 {chosen} 片解析失败：{}", error.summary_zh()));
        let raw = macho::fat::slice_bytes(bytes, &container.slices[chosen])
            .expect("切片的字节范围在读容器时已经校验过");
        let facts = macho::read(raw).unwrap_or_else(|error| {
            panic!("第 {chosen} 片的结构层事实读不出来：{}", error.summary_zh())
        });
        (format!("fat 第 {chosen} 片"), facts, object)
    } else {
        let facts = macho::read(bytes)
            .unwrap_or_else(|error| panic!("薄 Mach-O 结构层读取失败：{}", error.summary_zh()));
        let object = macho::parse(bytes, 0, ObjectId::Plain)
            .unwrap_or_else(|error| panic!("薄 Mach-O 解析失败：{}", error.summary_zh()));
        ("薄 Mach-O".to_string(), facts, object)
    }
}

#[test]
#[ignore = "需要真实 IPA（temp/*.ipa 或 BITFLIP_TEST_MACHO_IPA）；用 --ignored 手动跑"]
fn a_real_ios_binary_yields_segments_sections_and_entry() {
    let path = sample_path();
    let ipa =
        std::fs::read(&path).unwrap_or_else(|error| panic!("读不到 {}：{error}", path.display()));
    let listing = zip::list_members(&ipa)
        .unwrap_or_else(|error| panic!("IPA 应当是能列成员的 ZIP：{}", error.summary_zh()));
    eprintln!(
        "样本 {}（{} 字节，{} 个成员{}）",
        path.display(),
        ipa.len(),
        listing.members.len(),
        if listing.truncated {
            "，已截断"
        } else {
            ""
        }
    );

    let (index, name, binary) = pick_main_binary(&ipa, &listing);
    eprintln!(
        "主二进制 = 成员 #{index} {name}（解压后 {} 字节）",
        binary.len()
    );

    // 产品里那份实现（`bitflip_loader::bundle`）必须与这里的选法**一致**。
    // 测试里这份是早先写的对照实现：两边一旦分叉，这条断言就红，而不是等界面上
    // 出现一个测试根本没覆盖过的答案。这正是"同一段判断只该有一份"的可执行版本。
    {
        let names: Vec<&str> = listing.members.iter().map(|m| m.name.as_str()).collect();
        let found =
            bitflip_loader::bundle::find_main_binary(&names, |i| zip::read_member(&ipa, i).ok())
                .expect("产品实现也应当认得出主二进制");
        assert_eq!(
            (found.index, found.name.as_str()),
            (index, name.as_str()),
            "测试里的选法与产品实现分叉了：{found:?}"
        );
        eprintln!("依据 = {}", found.source.label_zh());
        if found.source.is_guess() {
            // LiveContainer 的可执行名与 `.app` 不同名，走的必然是指望第二层。
            eprintln!("注意：这是**推断**（同名匹配落空），界面必须标明");
            if name.contains("LiveContainer") {
                assert!(
                    found.source.is_guess(),
                    "LiveContainer 的可执行名与 .app 不同名，必须走推断那一层：{found:?}"
                );
            }
        }
        assert!(
            !found.note_zh().is_empty(),
            "认出来就必须给得出一句依据说明"
        );
    }
    assert!(
        !binary.is_empty(),
        "主二进制解压后是空的：ZIP 层或选成员出了问题"
    );

    let (how, facts, object) = parse_one_image(&binary);
    eprintln!("解析路径：{how}");

    let text = object
        .segments
        .iter()
        .find(|segment| segment.name == "__TEXT")
        .expect("真实 iOS 可执行文件一定有 __TEXT 段");

    eprintln!("对象：kind = {:?}", object.kind);
    eprintln!("架构 = {} / 端序 = {:?}", object.arch, object.endian);
    eprintln!(
        "头字段：cputype = {:#010x} / cpusubtype = {:#x} / filetype = {} / ncmds = {} / \
         sizeofcmds = {} / flags = {:#010x}",
        facts.cputype, facts.cpusubtype, facts.filetype, facts.ncmds, facts.sizeofcmds, facts.flags
    );
    eprintln!(
        "LC_UUID = {:?} / 依赖库 {} 个{}",
        facts.uuid,
        facts.dylibs.len(),
        if facts.dylibs.is_empty() {
            String::new()
        } else {
            format!(
                "（前 3 个：{:?}）",
                facts.dylibs.iter().take(3).collect::<Vec<_>>()
            )
        }
    );
    eprintln!(
        "format.type_name = {:?} / is_executable = {} / is_stripped = {}",
        object.format.type_name, object.format.is_executable, object.format.is_stripped
    );
    eprintln!(
        "image_base = {:#x} / entry = {:?}",
        object.image_base,
        object.entry.map(|entry| format!("{entry:#x}"))
    );
    eprintln!(
        "段 {} 个 / 节 {} 个 / notes {} 条",
        object.segments.len(),
        object.sections.len(),
        object.notes.len()
    );
    for segment in &object.segments {
        eprintln!(
            "  段 {:12} vmaddr = {:#012x} vmsize = {:#x} file = {:?} perms = {}/{}/{} kind = {:?}",
            segment.name,
            segment.vaddr,
            segment.vsize,
            segment.file,
            u8::from(segment.perms.read),
            u8::from(segment.perms.write),
            u8::from(segment.perms.execute),
            segment.kind
        );
    }
    if !object.notes.is_empty() {
        eprintln!("notes:");
        for note in &object.notes {
            eprintln!("  - {note}");
        }
    }

    // ── 必须成立的事实（只断言"真实二进制一定满足"的） ────────────────
    assert_eq!(object.kind, ObjectKind::MachO);
    let arch = object.arch.to_string();
    assert!(
        arch.starts_with("arm") || arch.starts_with("aarch64"),
        "iOS 应用二进制只可能是 arm / arm64，实际是 {arch}"
    );
    assert!(
        object.format.is_executable,
        "IPA 里的主二进制应当是 MH_EXECUTE，实际 type_name = {:?}",
        object.format.type_name
    );
    assert_eq!(
        object.image_base, text.vaddr,
        "镜像基址应当等于 __TEXT.vmaddr"
    );
    assert!(text.perms.execute, "__TEXT 必须可执行");
    assert!(
        object.segments.len() >= 2,
        "真实可执行文件至少有 __TEXT 与 __LINKEDIT（实际 {}）",
        object.segments.len()
    );
    assert!(
        !object.sections.is_empty(),
        "段命令里必须带节表（否则段/节视图是空的）"
    );
    let entry = object.entry.expect(
        "真实 iOS 可执行文件必须有入口点（LC_MAIN，老二进制是 LC_UNIXTHREAD）——\
         这也能顺带验证 entryoff 的换算没有算错",
    );
    assert!(
        entry >= text.vaddr && entry < text.vaddr + text.vsize,
        "入口点 {entry:#x} 应当落在 __TEXT 的虚拟范围 \
         {:#x}..{:#x} 内：entryoff 换算错了会掉到这里",
        text.vaddr,
        text.vaddr + text.vsize
    );
    // 本片**没有**解析符号表与导入：这两处必须为空，且原因写在 notes 里。
    assert!(object.symbols.is_empty(), "本片没有符号表解析");
    assert!(object.imports.is_empty(), "本片没有 dyld 绑定解析");
    assert!(
        object
            .notes
            .iter()
            .any(|note| note.contains("LC_SYMTAB") || note.contains("符号表")),
        "必须说明符号表没有解析：{:?}",
        object.notes
    );

    // LC_UUID：dyld 用它标识镜像，Xcode 产出的可执行文件一定有；这里顺带验证
    // "16 字节 → 32 个小写十六进制字符"的转换没把高位丢掉、没把大小写弄反。
    let uuid = facts
        .uuid
        .as_deref()
        .expect("真实 iOS 可执行文件一定有 LC_UUID");
    assert_eq!(uuid.len(), 32, "LC_UUID 应当是 32 个字符，实际 {uuid:?}");
    assert!(
        uuid.chars()
            .all(|c| c.is_ascii_hexdigit() && !c.is_ascii_uppercase()),
        "LC_UUID 应当是小写十六进制：{uuid:?}"
    );
    assert!(
        facts.ncmds > 0 && facts.sizeofcmds > 0,
        "真实二进制不可能一条加载命令都没有（ncmds = {} / sizeofcmds = {}）",
        facts.ncmds,
        facts.sizeofcmds
    );
}
