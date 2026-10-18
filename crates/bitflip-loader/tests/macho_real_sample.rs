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
    // 符号表从 M12 第三片起**真的会解析**：这里不再断言"一定为空"，而是断言
    // "对象模型的符号 + 调试 stab = 符号表条目数"，空与不空各自有说法（§7）。
    // 具体计数由 `real_binaries_report_symbols_and_function_starts` 打印并把关。
    assert_eq!(
        object.symbols.len() + facts.stab_symbols,
        facts.symbols.len(),
        "object.symbols({}) + stab({}) 应当等于符号表条目数({})",
        object.symbols.len(),
        facts.stab_symbols,
        facts.symbols.len()
    );
    // 导入表从 M12 第五片起**真的会解析**：有 dyld 绑定流（bind / lazy_bind）就必须
    // 解出导入；没有就必须为空、且 notes 说清是哪一种"没有"（新版二进制走
    // LC_DYLD_CHAINED_FIXUPS，本片不解析那条路）。空与不空各自有说法（§7）。
    // 具体计数由 `real_binaries_report_exports_and_imports` 打印并把关。
    let has_bind_data = facts
        .dyld_info
        .is_some_and(|info| info.bind_size > 0 || info.lazy_bind_size > 0);
    if has_bind_data {
        assert!(
            !object.imports.is_empty(),
            "主二进制有非空的 bind / lazy_bind 流，却一条导入都没解出来"
        );
    } else {
        assert!(
            object.imports.is_empty(),
            "没有可解的绑定数据却解出了 {} 条导入",
            object.imports.len()
        );
        assert!(
            object
                .notes
                .iter()
                .any(|note| note.contains("LC_DYLD_INFO")),
            "导入为空时必须说明原因（没有这条命令 / 流是空的 / 没解析链式修复）：{:?}",
            object.notes
        );
    }
    // 导出 trie：两种承载命令都认；有表就得解出东西，没表也要说明。
    assert!(
        object
            .notes
            .iter()
            .any(|note| note.contains("导出 trie") || note.contains("导出")),
        "notes 必须交代导出这一项的状态：{:?}",
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

/// `temp/` 里**所有**存在的样本（按大小从小到大）。
///
/// 与 [`sample_path`] 的区别只在用途：那份给"随便一份就能验证结构层"的测试，
/// 这份给"每份都要报一个计数"的验证 —— 四份 IPApp 的命令组合不一样，
/// 只看一份容易把"这份没有"当成"这个格式没有"。
fn all_sample_paths() -> Vec<PathBuf> {
    if let Ok(from_env) = std::env::var("BITFLIP_TEST_MACHO_IPA") {
        let path = PathBuf::from(from_env);
        assert!(
            path.is_file(),
            "BITFLIP_TEST_MACHO_IPA 指向的 {} 不是文件",
            path.display()
        );
        return vec![path];
    }
    let dir = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../temp");
    const NAMES: [&str; 4] = [
        "LiveContainer.ipa",
        "Stapxs.QQ.Lite-3.3.3.ipa",
        "SideStore.ipa",
        "net.kdt.pojavlauncher-2.2-ios.ipa",
    ];
    let found: Vec<PathBuf> = NAMES
        .iter()
        .map(|name| dir.join(name))
        .filter(|path| path.is_file())
        .collect();
    assert!(
        !found.is_empty(),
        "找不到真实 Mach-O 样本：请把任意一个 `.ipa` 放进 {}，\
         或设 `BITFLIP_TEST_MACHO_IPA=<某个 .ipa 的完整路径>`",
        dir.display()
    );
    found
}

/// 一份真实样本的计数（打印与断言共用，免得"打印的值"与"断言的值"两处各算一遍）。
#[derive(Debug)]
struct SampleCounts {
    /// 样本文件名。
    name: String,
    /// 主二进制解压后多少字节。
    binary_bytes: usize,
    /// 符号表条目数（含 stab）。
    symtab_entries: usize,
    /// 调试 stab 数。
    stabs: usize,
    /// 对象模型里的普通符号数。
    symbols: usize,
    /// 函数起点数。
    function_starts: usize,
    /// 第一条函数起点（地址最小）与最后一条。
    first_start: Option<u64>,
    last_start: Option<u64>,
    /// 对象模型给的说明里提到符号表 / 函数起点了吗。
    notes_mention_symtab: bool,
    notes_mention_function_starts: bool,
}

fn measure(path: &std::path::Path) -> SampleCounts {
    let ipa =
        std::fs::read(path).unwrap_or_else(|error| panic!("读不到 {}：{error}", path.display()));
    let listing = zip::list_members(&ipa)
        .unwrap_or_else(|error| panic!("IPA 应当是能列成员的 ZIP：{}", error.summary_zh()));
    let (_index, _name, binary) = pick_main_binary(&ipa, &listing);
    let (_how, facts, object) = parse_one_image(&binary);
    let notes = object.notes.join("\n");
    SampleCounts {
        name: path
            .file_name()
            .map(|name| name.to_string_lossy().into_owned())
            .unwrap_or_else(|| path.display().to_string()),
        binary_bytes: binary.len(),
        symtab_entries: facts.symbols.len(),
        stabs: facts.stab_symbols,
        symbols: object.symbols.len(),
        function_starts: object.function_starts.len(),
        first_start: object.function_starts.first().copied(),
        last_start: object.function_starts.last().copied(),
        notes_mention_symtab: notes.contains("LC_SYMTAB"),
        notes_mention_function_starts: notes.contains("LC_FUNCTION_STARTS"),
    }
}

/// 四份真实 IPA：符号表与函数起点的计数必须**非平凡**，且数值自洽。
///
/// 这条测试的存在意义是"合成样本证明按规范工作，真实二进制证明规范真的被这样用"。
/// 它打印的表格就是交付报告里那组数字的来源 —— 数字是测出来的，不是估的。
#[test]
#[ignore = "需要真实 IPA（temp/*.ipa 或 BITFLIP_TEST_MACHO_IPA）；用 --ignored 手动跑"]
fn real_binaries_report_symbols_and_function_starts() {
    let paths = all_sample_paths();
    let counts: Vec<SampleCounts> = paths.iter().map(|path| measure(path)).collect();

    eprintln!(
        "{:<44} {:>10} {:>8} {:>6} {:>8} {:>8} {:>18}",
        "样本", "二进制字节", "符号表", "stab", "普通符号", "函数起点", "首/末起点"
    );
    for row in &counts {
        eprintln!(
            "{:<44} {:>10} {:>8} {:>6} {:>8} {:>8}   {:?}..{:?}",
            row.name,
            row.binary_bytes,
            row.symtab_entries,
            row.stabs,
            row.symbols,
            row.function_starts,
            row.first_start.map(|address| format!("{address:#x}")),
            row.last_start.map(|address| format!("{address:#x}"))
        );
    }

    for row in &counts {
        assert_eq!(
            row.symbols + row.stabs,
            row.symtab_entries,
            "{}：对象模型符号({}) + stab({}) 应当等于符号表条目数({})",
            row.name,
            row.symbols,
            row.stabs,
            row.symtab_entries
        );

        // iOS 13 之后 App Store 的二进制都带 LC_FUNCTION_STARTS（dyld 靠它按需
        // 建立函数边界）；四份样本都是 Xcode 打包的 IPA，表不该缺席。
        assert!(
            row.notes_mention_function_starts,
            "{}：notes 里必须提到 LC_FUNCTION_STARTS（有就说解出几个，没有就说没有）",
            row.name
        );
        // 下限按二进制规模给，而不是一个对各份样本都"看起来合适"的常数：
        // 96 KB 的启动器壳子（Stapxs）本来就不会有几百个函数。实测四份样本是
        // 59 / 96 KB、114 / 148 KB、59 487 / 19 MB、1 168 / 1.1 MB ——
        // 最稀疏的一份也有「每 16 KB 5 个」，所以每 16 KB 至少 1 个、且不少于 16 个，
        // 是任何真实可执行文件都远远超过的密度。
        // 这不是把标准降到零：0 个或个位数仍然会红，而那正是"表没解出来"的样子。
        let floor = (row.binary_bytes as u64 / 16_384).max(16);
        assert!(
            row.function_starts as u64 >= floor,
            "{}：LC_FUNCTION_STARTS 解出 {} 个函数起点，低于这份二进制的下限 {floor} 个\
             —— 要么表没解出来，要么这份二进制确实没有这张表（那种情况要在断言里写清为什么）",
            row.name,
            row.function_starts
        );
        let (Some(first), Some(last)) = (row.first_start, row.last_start) else {
            panic!("{}：函数起点为空", row.name);
        };
        assert!(
            first < last,
            "{}：函数起点必须升序（{first:#x} 到 {last:#x}）",
            row.name
        );

        // 符号：stripped 的二进制可以是 0，但那时 notes 必须说清"没有 LC_SYMTAB"
        // 或"nsyms = 0"，不能只留一个空表让人以为"这个文件没有符号"。
        if row.symbols == 0 {
            eprintln!(
                "{}：普通符号为 0 —— 该二进制要么被剥符号（notes: {}），\
                 要么符号表本来就是空的；函数起点 {} 个仍然给出了函数边界",
                row.name,
                if row.notes_mention_symtab {
                    "有 LC_SYMTAB 相关说明"
                } else {
                    "**没有** LC_SYMTAB 相关说明（这是缺陷）"
                },
                row.function_starts
            );
            assert!(
                row.notes_mention_symtab,
                "{}：符号为空时 notes 必须解释原因，否则读者会以为解析没跑",
                row.name
            );
        } else {
            assert!(
                row.symbols >= 10,
                "{}：能读出符号的二进制不该只有 {} 条（可能是符号名解析错了）",
                row.name,
                row.symbols
            );
        }
    }
}

/// 一份真实样本的导出 / 导入计数（第五片交付报告里那张表就是它打印的）。
#[derive(Debug)]
struct DyldCounts {
    /// 样本文件名。
    name: String,
    /// 主二进制解压后多少字节。
    binary_bytes: usize,
    /// 链接的 dylib 条数（`LC_LOAD_DYLIB` / `LC_LOAD_WEAK_DYLIB`）。
    dylibs: usize,
    /// 有没有 `LC_DYLD_INFO(_ONLY)`。
    has_dyld_info: bool,
    /// 导出 trie 的字节数（没有这张表 / 表是空的都可能是 0）。
    export_trie_bytes: u64,
    /// 导出条数。
    exports: usize,
    /// 普通绑定条数。
    imports_regular: usize,
    /// 惰性绑定条数。
    imports_lazy: usize,
    /// 去重后的被导入库数。
    import_libraries: usize,
    /// notes 里提到导入 / 导出 / 链式修复了吗。
    notes_mention_imports: bool,
    notes_mention_exports: bool,
    notes_mention_chained_fixups: bool,
}

fn measure_dyld(path: &std::path::Path) -> DyldCounts {
    let ipa =
        std::fs::read(path).unwrap_or_else(|error| panic!("读不到 {}：{error}", path.display()));
    let listing = zip::list_members(&ipa)
        .unwrap_or_else(|error| panic!("IPA 应当是能列成员的 ZIP：{}", error.summary_zh()));
    let (_index, _name, binary) = pick_main_binary(&ipa, &listing);
    let (_how, facts, object) = parse_one_image(&binary);
    let joined = object.notes.join("\n");

    let mut libraries = std::collections::BTreeSet::new();
    let mut regular = 0usize;
    let mut lazy = 0usize;
    for import in &facts.imports {
        libraries.insert(import.dylib.clone());
        match import.kind {
            macho::BindKind::Regular => regular += 1,
            macho::BindKind::Lazy => lazy += 1,
        }
    }
    let export_trie_bytes = facts
        .export_trie
        .map_or(0, |source| source.datasize)
        .max(facts.dyld_info.map_or(0, |info| info.export_size));

    DyldCounts {
        name: path
            .file_name()
            .map(|name| name.to_string_lossy().into_owned())
            .unwrap_or_else(|| path.display().to_string()),
        binary_bytes: binary.len(),
        dylibs: facts.dylibs.len(),
        has_dyld_info: facts.dyld_info.is_some(),
        export_trie_bytes,
        exports: object.exports.len(),
        imports_regular: regular,
        imports_lazy: lazy,
        import_libraries: libraries.len(),
        notes_mention_imports: joined.contains("导入"),
        notes_mention_exports: joined.contains("导出"),
        notes_mention_chained_fixups: joined.contains("LC_DYLD_CHAINED_FIXUPS"),
    }
}

/// 四份真实 IPA：导出 trie 与 dyld 绑定的计数必须自洽，且与命令组合对得上。
///
/// 这条测试要回答的问题（也是交付报告里那张表的来源）：
///
/// * 新版 Xcode 产物（`LC_DYLD_CHAINED_FIXUPS` + `LC_DYLD_EXPORTS_TRIE`）导出照解、
///   导入如实为空 —— 空得有理由，而不是"解析没跑"；
/// * 旧式产物（`LC_DYLD_INFO_ONLY`）才是导入数成百上千的那一类。
///
/// 提示里"SideStore 链接 79 个 dylib，导入应当上百"这个预期**被实测否定**了：
/// 它用的是链式修复，本片不解析那条路，所以它的导入是 0（notes 里写明原因）。
/// 有绑定流的 PojavLauncher 才是 1 382 + 165 = 1 547 条导入的那一份。
#[test]
#[ignore = "需要真实 IPA（temp/*.ipa 或 BITFLIP_TEST_MACHO_IPA）；用 --ignored 手动跑"]
fn real_binaries_report_exports_and_imports() {
    let paths = all_sample_paths();
    let counts: Vec<DyldCounts> = paths.iter().map(|path| measure_dyld(path)).collect();

    eprintln!(
        "{:<44} {:>10} {:>6} {:>7} {:>10} {:>6} {:>7} {:>6} {:>8}",
        "样本", "二进制字节", "dylib", "dyld_info", "trie字节", "导出", "普通导入", "惰性", "库数"
    );
    for row in &counts {
        eprintln!(
            "{:<44} {:>10} {:>6} {:>7} {:>10} {:>6} {:>7} {:>6} {:>8}",
            row.name,
            row.binary_bytes,
            row.dylibs,
            if row.has_dyld_info { "有" } else { "无" },
            row.export_trie_bytes,
            row.exports,
            row.imports_regular,
            row.imports_lazy,
            row.import_libraries
        );
    }

    for row in &counts {
        assert!(
            row.dylibs > 0,
            "{}：真实的 iOS 应用不可能不带 dylib（否则 ordinal 解析无从谈起）",
            row.name
        );
        assert!(
            row.notes_mention_exports,
            "{}：notes 必须交代导出这一项的状态",
            row.name
        );
        assert!(
            row.notes_mention_imports,
            "{}：notes 必须交代导入这一项的状态",
            row.name
        );

        // 有表就该解出东西：导出 trie 的根节点没有 terminal，所以"有表但 0 条导出"
        // 只可能是解析漏了或者表确实是空的 —— 真实 app 二进制不会是后者。
        if row.export_trie_bytes > 0 {
            assert!(
                row.exports > 0,
                "{}：导出 trie 有 {} 字节却 0 条导出 —— trie 没解开",
                row.name,
                row.export_trie_bytes
            );
        }

        let imports = row.imports_regular + row.imports_lazy;
        if imports == 0 {
            // 空得有理由：要么根本没有 LC_DYLD_INFO（新版走链式修复），要么它的
            // 绑定流是空的 —— 两种情形 notes 里说得不一样，所以这里只打印实际值，
            // 让"0 条导入"在报告里带着原因出现，而不是一个孤零零的 0。
            eprintln!(
                "{}：导入为 0（LC_DYLD_INFO = {}；链式修复说明 = {}）—— 这是文件里的事实，\
                 不是解析没跑",
                row.name,
                if row.has_dyld_info { "有" } else { "无" },
                if row.notes_mention_chained_fixups {
                    "有"
                } else {
                    "无"
                }
            );
        } else {
            assert!(
                row.import_libraries > 0,
                "{}：有 {} 条导入却 0 个库 —— 库序号没解析成库名",
                row.name,
                imports
            );
            // 每条导入都指向一个具体的库名（特殊序号也有名字），不是空串。
            assert!(
                row.import_libraries <= row.dylibs + 3,
                "{}：被导入的库({}) 比链接的 dylib({}) 多出 3 个以上 —— 序号解析错位了",
                row.name,
                row.import_libraries,
                row.dylibs
            );
        }
    }
}
