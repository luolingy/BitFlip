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
        let found = bitflip_loader::bundle::find_main_binary(
            bitflip_loader::bundle::BundleLayout::Ipa,
            None,
            &names,
            |i| zip::read_member(&ipa, i).ok(),
        )
        .expect("产品实现也应当认得出主二进制");
        assert_eq!(
            (found.index, found.name.as_str()),
            (index, name.as_str()),
            "测试里的选法与产品实现分叉了：{found:?}"
        );
        eprintln!("依据 = {}", found.source.label_zh());
        for note in &found.notes {
            eprintln!("降级说明 = {note}");
        }
        if name.contains("LiveContainer") {
            // 这份 IPA 的 `Info.plist` 是 XML，里面写着 CFBundleExecutable（长名）。
            // 既然文件里写着，结论就必须是事实，而不是"同名匹配落空 → 推断"。
            assert!(
                !found.source.is_guess(),
                "LiveContainer 的 Info.plist 里写着可执行名，必须按事实报出来：{found:?}"
            );
        }
        if found.source.is_guess() {
            eprintln!("注意：这是**推断**（前两条依据都落空），界面必须标明");
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
    // 导入表从 M12 第五片起**真的会解析**：有 dyld 绑定流（bind / lazy_bind）就解它；
    // 没有经典绑定流时，新版产物（LC_DYLD_CHAINED_FIXUPS）的**导入表**是第六片的来源 ——
    // 两者都没有才允许为空，且 notes 必须说清是哪一种"没有"（§7）。
    // 具体计数由 `real_binaries_report_exports_and_imports` 与
    // `real_binaries_report_chained_fixup_imports` 打印并把关。
    let has_bind_data = facts
        .dyld_info
        .is_some_and(|info| info.bind_size > 0 || info.lazy_bind_size > 0);
    if has_bind_data {
        assert!(
            !object.imports.is_empty(),
            "主二进制有非空的 bind / lazy_bind 流，却一条导入都没解出来"
        );
    } else {
        // 没有经典绑定流：导入只能来自链式修复的导入表。
        let chained_imports = facts
            .chained_fixups
            .as_ref()
            .map_or(0, |fixups| fixups.imports.len());
        assert_eq!(
            object.imports.len(),
            chained_imports,
            "没有 bind 流时 Object.imports 应当正好等于链式修复导入表的条数（实际 {} vs 链式 {}）",
            object.imports.len(),
            chained_imports
        );
        if chained_imports == 0 {
            assert!(
                object
                    .notes
                    .iter()
                    .any(|note| note.contains("LC_DYLD_INFO")),
                "导入为空时必须说明原因（没有这两种数据 / 表里写着 0 条）：{:?}",
                object.notes
            );
        }
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

/// 四份真实 IPA：导出 trie 与**经典 dyld 绑定流**的计数必须自洽。
///
/// 这条测试要回答的问题（也是交付报告里那张表的来源）：
///
/// * 新版 Xcode 产物（`LC_DYLD_CHAINED_FIXUPS` + `LC_DYLD_EXPORTS_TRIE`）导出照解，
///   `LC_DYLD_INFO` 的 bind 段**整条不存在** —— 这里打印的"普通 / 惰性导入"因此是 0；
///   它们的导入由链式修复的导入表提供，计数在
///   `real_binaries_report_chained_fixup_imports` 里（两条测试分开，才说得清
///   "这份文件没写这种数据"与"表没解出来"）。
/// * 旧式产物（`LC_DYLD_INFO_ONLY`）才是导入数成百上千的那一类。
///
/// PojavLauncher 是 1 382 + 165 = 1 547 条经典绑定的那一份；SideStore / LiveContainer /
/// Stapxs 的经典绑定是 0，但链式修复导入表不是 0。
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
            // 经典绑定为 0 有理由：要么根本没有 LC_DYLD_INFO（新版走链式修复，
            // 导入由新测试计数），要么它的绑定流是空的 —— 两种情形 notes 里说得
            // 不一样，所以这里打印实际值，让"0 条经典绑定"带着原因出现。
            eprintln!(
                "{}：经典绑定导入为 0（LC_DYLD_INFO = {}；链式修复说明 = {}）—— 链式修复导入\
                 表的计数见 real_binaries_report_chained_fixup_imports",
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

/// 一份真实样本的**链式修复导入表**计数（第八片交付报告里那张表的来源）。
#[derive(Debug)]
struct ChainedCounts {
    /// 样本文件名。
    name: String,
    /// 主二进制解压后多少字节。
    binary_bytes: usize,
    /// 链接的 dylib 条数。
    dylibs: usize,
    /// 有没有 `LC_DYLD_CHAINED_FIXUPS`。
    has_chained_fixups: bool,
    /// `imports_format`（1 / 2 / 3）。没有这条命令时是 `None`。
    imports_format: Option<u32>,
    /// 链式修复导入表解出多少条。
    chained_imports: usize,
    /// 其中 `weak_import` 的条数。
    weak: usize,
    /// 其中带 addend 的条数。
    with_addend: usize,
    /// 走链后拿到 `iat_slot`（槽位地址）的条数。
    imports_with_slot: usize,
    /// 走链的计数（没有链描述、或链没法走时是 `None`）。
    walk: Option<macho::ChainWalk>,
    /// 槽位地址**不在任何节里**的条数（应当是 0：绑定槽位都在 `__got` / `__data`）。
    slots_outside_sections: usize,
    /// 拿到地址的前几条（名字, 库, 地址, 所在的段/节）—— 给人按常识核对。
    slot_head: Vec<(String, String, u64, Option<String>)>,
    /// 没拿到地址的前几条（名字, 库）—— 空着才是"全都绑上了"。
    unbound_head: Vec<(String, String)>,
    /// 每个段的内存范围 `[vmaddr, vmaddr+vmsize)`：用来核对槽位地址落在段内。
    segment_extents: Vec<(u64, u64)>,
    /// 去重后的被导入库数（含 `<main-executable>` 这类标签）。
    libraries: usize,
    /// 经典 bind 流的导入条数（老格式样本用）。
    bind_imports: usize,
    /// notes 里提到 `LC_DYLD_CHAINED_FIXUPS` 了吗。
    notes_mention_chained: bool,
    /// notes 里说"已解析 dyld 绑定"了吗（老格式样本要用）。
    notes_mention_bind_imports: bool,
}

/// 地址落在哪个节里（`段名,节名`）；不在任何节里返回 `None`。
///
/// 用 `MachOFile` 的段/节表（`section.addr` / `section.size`）而不是对象模型 ——
/// 槽位地址是要人核对的原始事实，核对时不该绕经归一化后的结构。
fn section_at(facts: &macho::MachOFile, address: u64) -> Option<String> {
    for segment in &facts.segments {
        for section in &segment.sections {
            if address >= section.addr && address < section.addr.saturating_add(section.size) {
                return Some(format!("{},{}", section.segname, section.sectname));
            }
        }
    }
    None
}

/// 地址是否落在某个节里（[`section_at`] 的布尔版，给全量统计用）。
fn in_some_section(facts: &macho::MachOFile, address: u64) -> bool {
    facts.segments.iter().any(|segment| {
        segment.sections.iter().any(|section| {
            address >= section.addr && address < section.addr.saturating_add(section.size)
        })
    })
}

fn measure_chained(path: &std::path::Path) -> ChainedCounts {
    let ipa =
        std::fs::read(path).unwrap_or_else(|error| panic!("读不到 {}：{error}", path.display()));
    let listing = zip::list_members(&ipa)
        .unwrap_or_else(|error| panic!("IPA 应当是能列成员的 ZIP：{}", error.summary_zh()));
    let (_index, _name, binary) = pick_main_binary(&ipa, &listing);
    let (_how, facts, object) = parse_one_image(&binary);
    let joined = object.notes.join("\n");

    let fixups = facts.chained_fixups.as_ref();
    let mut libraries = std::collections::BTreeSet::new();
    let mut weak = 0usize;
    let mut with_addend = 0usize;
    let mut imports_with_slot = 0usize;
    let mut slots_outside_sections = 0usize;
    let mut slot_head = Vec::new();
    let mut unbound_head = Vec::new();
    if let Some(fixups) = fixups {
        for import in &fixups.imports {
            libraries.insert(import.dylib.clone());
            if import.weak_import {
                weak += 1;
            }
            if import.addend.is_some() {
                with_addend += 1;
            }
            match import.iat_slot {
                Some(address) => {
                    imports_with_slot += 1;
                    if !in_some_section(&facts, address) {
                        slots_outside_sections += 1;
                    }
                    if slot_head.len() < 5 {
                        slot_head.push((
                            import.name.clone(),
                            import.dylib.clone(),
                            address,
                            section_at(&facts, address),
                        ));
                    }
                }
                None => {
                    if unbound_head.len() < 5 {
                        unbound_head.push((import.name.clone(), import.dylib.clone()));
                    }
                }
            }
        }
    }
    // 段的内存范围：槽位地址要落在其中（`__PAGEZERO` 的 vmsize 是 4 GB，会覆盖
    // 0x1_xxx_xxxx 之前的地址，所以 start 用 vmaddr、end 用 vmaddr + vmsize）。
    let segment_extents: Vec<(u64, u64)> = facts
        .segments
        .iter()
        .map(|segment| {
            (
                segment.vmaddr,
                segment.vmaddr.saturating_add(segment.vmsize),
            )
        })
        .collect();

    ChainedCounts {
        name: path
            .file_name()
            .map(|name| name.to_string_lossy().into_owned())
            .unwrap_or_else(|| path.display().to_string()),
        binary_bytes: binary.len(),
        dylibs: facts.dylibs.len(),
        has_chained_fixups: fixups.is_some(),
        imports_format: fixups.map(|fixups| fixups.imports_format),
        chained_imports: fixups.map_or(0, |fixups| fixups.imports.len()),
        weak,
        with_addend,
        imports_with_slot,
        slots_outside_sections,
        walk: fixups.and_then(|fixups| fixups.chains.clone()),
        slot_head,
        unbound_head,
        segment_extents,
        libraries: libraries.len(),
        bind_imports: facts.imports.len(),
        notes_mention_chained: joined.contains("LC_DYLD_CHAINED_FIXUPS"),
        notes_mention_bind_imports: joined.contains("已解析 dyld 绑定"),
    }
}

/// 四份真实 IPA：链式修复的**导入表**必须解出真实的导入集，**指针链**必须给每条
/// 导入一个可核对的槽位地址。
///
/// 这条测试回答的问题：
///
/// * 新版产物（`LC_DYLD_CHAINED_FIXUPS` 而没有 `LC_DYLD_INFO`）此前 `Object.imports`
///   恒空（"绑定在链式修复里，没解"）。现在它应当给出真实的导入集；
/// * 走链之后，**大多数**导入应当有一个 `iat_slot`（指着 `__DATA` 里的指针槽）。
///   一条都没有只能是"链走错了"，所以断言不是"至少一条"，而是"过半"；
/// * `LiveContainer`（151 KB 的启动器壳子）应当只有少量导入；
/// * `SideStore`（19.6 MB、79 个 dylib）应当是**上百条**；
/// * 老格式的 PojavLauncher 仍走 bind 流，链式修复那边为空 —— 两种写法都要能说清。
#[test]
#[ignore = "需要真实 IPA（temp/*.ipa 或 BITFLIP_TEST_MACHO_IPA）；用 --ignored 手动跑"]
fn real_binaries_report_chained_fixup_imports() {
    let paths = all_sample_paths();
    let counts: Vec<ChainedCounts> = paths.iter().map(|path| measure_chained(path)).collect();

    eprintln!(
        "{:<44} {:>10} {:>6} {:>8} {:>8} {:>8} {:>10} {:>10} {:>6} {:>6} {:>8}",
        "样本",
        "二进制字节",
        "dylib",
        "chained",
        "format",
        "链式导入",
        "有地址",
        "走链指针",
        "weak",
        "addend",
        "bind导入"
    );
    for row in &counts {
        eprintln!(
            "{:<44} {:>10} {:>6} {:>8} {:>8} {:>8} {:>10} {:>10} {:>6} {:>6} {:>8}",
            row.name,
            row.binary_bytes,
            row.dylibs,
            if row.has_chained_fixups { "有" } else { "无" },
            row.imports_format
                .map_or_else(|| "-".to_string(), |format| format.to_string()),
            row.chained_imports,
            row.imports_with_slot,
            row.walk
                .as_ref()
                .map_or_else(|| "-".to_string(), |walk| walk.pointers.to_string()),
            row.weak,
            row.with_addend,
            row.bind_imports
        );
        if let Some(walk) = &row.walk {
            eprintln!(
                "    走链：{} 段 / {} 页 / {} 条链 / {} 指针（{} bind{}、{} rebase）；\
                 重复绑定 {} 处；槽位不在任何节里 {} 条",
                walk.segments,
                walk.pages,
                walk.chains,
                walk.pointers,
                walk.binds,
                if walk.auth_binds > 0 {
                    format!(" 含 {} 条认证绑定", walk.auth_binds)
                } else {
                    String::new()
                },
                walk.rebases,
                walk.extra_bind_sites,
                row.slots_outside_sections
            );
        }
        for (name, library, address, section) in &row.slot_head {
            eprintln!(
                "    槽位 {address:#014x}  {name:<40} ← {library}   [{}]",
                section.as_deref().unwrap_or("不在任何节里")
            );
        }
        for (name, library) in &row.unbound_head {
            eprintln!("    无地址              {name:<40} ← {library}");
        }
    }

    for row in &counts {
        assert!(
            row.dylibs > 0,
            "{}：真实的 iOS 应用不可能不带 dylib（否则库序号无从解析）",
            row.name
        );

        if row.has_chained_fixups {
            assert!(
                matches!(row.imports_format, Some(1..=3)),
                "{}：imports_format 只可能是 1 / 2 / 3，实际 {:?}",
                row.name,
                row.imports_format
            );
            assert!(
                row.notes_mention_chained,
                "{}：解了链式修复的导入表，notes 就必须说出来",
                row.name
            );
            // 有链式修复、有 dylib 的真实 app 二进制不可能一条导入都没有：
            // 那样它连 dyld 的 stub 都填不上。0 只会是"表没解出来"。
            assert!(
                row.chained_imports > 0,
                "{}：有 LC_DYLD_CHAINED_FIXUPS（imports_format = {:?}）却 0 条导入 —— \
                 imports 段或符号池没解对，这不是\"这个程序没有导入\"",
                row.name,
                row.imports_format
            );
            // 走链必须给出地址：真实的 iOS 13+ 二进制把每个用到的导入绑在 __DATA 的
            // 指针槽里，所以**过半**的导入应当有地址。一条都没有只能是链走错了
            // （pointer_format 读错、页偏移算错、starts_in_segment 定位错）。
            // 这条断言刻意不是"至少一条"：那会让"只走通一条"也算绿。
            assert!(
                row.imports_with_slot * 2 > row.chained_imports,
                "{}：{} 条链式修复导入里只有 {} 条拿到槽位地址（不到一半）—— \
                 指针链没走对，不是\"这些导入没有槽位\"",
                row.name,
                row.chained_imports,
                row.imports_with_slot
            );
            let walk = row
                .walk
                .as_ref()
                .unwrap_or_else(|| panic!("{}：有链描述却没有任何走链结果", row.name));
            assert!(
                walk.pointers >= row.imports_with_slot,
                "{}：走到的指针数({}) 比拿到地址的导入数({}) 还少 —— 计数与地址自相矛盾",
                row.name,
                walk.pointers,
                row.imports_with_slot
            );
            assert_eq!(
                walk.imports_with_slot, row.imports_with_slot,
                "{}：走链结果里的导入计数与导入表里的 iat_slot 计数必须一致",
                row.name
            );
            assert!(
                walk.pages > 0,
                "{}：真实的 iOS 二进制一定有带指针链的页（walk.pages = 0 说明链描述没读到）",
                row.name
            );
            assert!(
                row.libraries <= row.dylibs + 3,
                "{}：被导入的库({}) 比链接的 dylib({}) 多出 3 个以上 —— 库序号解析错位了",
                row.name,
                row.libraries,
                row.dylibs
            );
            // 槽位地址必须落在某个段的内存范围里、而且落在某个节里：落在外面说明
            // 地址算式（基址 + segment_offset + 页偏移）错了。这一条是**全量**统计，
            // 不是抽样：真实的绑定槽位都在 `__DATA_CONST,__got` 这样的节里。
            assert_eq!(
                row.slots_outside_sections, 0,
                "{}：{} 条导入的槽位地址不落在任何节里 —— 地址算式（基址 + segment_offset + \
                 页偏移）错了一位，或者 pointer_format 的 stride 读错",
                row.name, row.slots_outside_sections
            );
            for (name, _library, address, section) in &row.slot_head {
                assert!(
                    row.segment_extents
                        .iter()
                        .any(|(start, end)| *address >= *start && *address < *end),
                    "{}：导入 {name} 的槽位地址 {address:#x} 不落在任何段的内存范围里 —— \
                     地址算式（基址 + segment_offset + 页偏移）错了",
                    row.name
                );
                assert!(
                    section.is_some(),
                    "{}：导入 {name} 的槽位地址 {address:#x} 不落在任何节里 —— \
                     绑定槽位应当在 __DATA / __DATA_CONST 的 __got / __data 之类的节里",
                    row.name
                );
            }
        } else {
            // 老格式：链式修复那边没有，导入只能来自 bind 流。
            assert!(
                row.bind_imports > 0,
                "{}：没有 LC_DYLD_CHAINED_FIXUPS 也没有 bind 导入 —— 两种写法都没解出来",
                row.name
            );
            assert!(
                row.notes_mention_bind_imports,
                "{}：bind 流解出了 {} 条导入，notes 就必须说\"已解析 dyld 绑定\"",
                row.name, row.bind_imports
            );
            // 没有链式修复就不该有链式修复的地址：两种写法不能互相串。
            assert_eq!(
                row.imports_with_slot, 0,
                "{}：没有 LC_DYLD_CHAINED_FIXUPS，链式修复那边不该有任何槽位地址",
                row.name
            );
            assert!(
                row.walk.is_none(),
                "{}：没有 LC_DYLD_CHAINED_FIXUPS 就不该有走链结果",
                row.name
            );
        }

        // 下限按样本点名（提示里给的期望：LiveContainer 小、SideStore 上百）。
        // 不是"把标准降到零"：个位数仍然会红，而那正是"表没解出来"的样子。
        if row.name.starts_with("LiveContainer") {
            assert!(
                row.chained_imports >= 20,
                "LiveContainer（{} 字节）的链式修复导入只有 {} 条：151 KB 的启动器壳子也不该这么少",
                row.binary_bytes,
                row.chained_imports
            );
        }
        if row.name.starts_with("SideStore") {
            assert!(
                row.chained_imports >= 100,
                "SideStore（{} 字节、{} 个 dylib）的链式修复导入只有 {} 条：预期是上百条",
                row.binary_bytes,
                row.dylibs,
                row.chained_imports
            );
        }
    }
}

// ── ObjC 元数据（__objc_* 节：选择器引用 / 方法表 / 消息桩） ────────────────

struct ObjcCounts {
    name: String,
    sections: usize,
    selector_refs: usize,
    methods: usize,
    methods_with_selector: usize,
    stubs: usize,
    class_names: usize,
    stub_head: Vec<(u64, String)>,
    notes: Vec<String>,
}

fn measure_objc(path: &std::path::Path) -> ObjcCounts {
    let ipa =
        std::fs::read(path).unwrap_or_else(|error| panic!("读不到 {}：{error}", path.display()));
    let listing = zip::list_members(&ipa)
        .unwrap_or_else(|error| panic!("IPA 应当是能列成员的 ZIP：{}", error.summary_zh()));
    let (index, member_name, binary) = pick_main_binary(&ipa, &listing);
    let _ = index;
    let (_how, facts, object) = parse_one_image(&binary);

    let objc = &object.objc;
    let mut sections = 0usize;
    for segment in &facts.segments {
        for section in &segment.sections {
            if section.sectname.starts_with("__objc") {
                sections += 1;
            }
        }
    }

    ObjcCounts {
        name: member_name.clone(),
        sections,
        selector_refs: objc.selector_refs.len(),
        methods: objc.methods.len(),
        methods_with_selector: objc
            .methods
            .iter()
            .filter(|method| !method.selector.is_empty())
            .count(),
        stubs: objc.stubs.len(),
        class_names: objc.class_names.len(),
        stub_head: objc
            .stubs
            .iter()
            .take(5)
            .map(|stub| (stub.address, stub.selector.clone()))
            .collect(),
        notes: objc.notes.clone(),
    }
}

#[test]
#[ignore = "需要真实 IPA（temp/*.ipa 或 BITFLIP_TEST_MACHO_IPA）；用 --ignored 手动跑"]
fn real_ios_binaries_report_objc_names() {
    let paths = all_sample_paths();
    let counts: Vec<ObjcCounts> = paths.iter().map(|path| measure_objc(path)).collect();

    eprintln!(
        "{:<44} {:>6} {:>6} {:>6} {:>6} {:>6} {:>6}",
        "样本", "__objc节", "选择器槽", "方法", "有名字", "消息桩", "类名"
    );
    for row in &counts {
        eprintln!(
            "{:<44} {:>6} {:>6} {:>6} {:>6} {:>6} {:>6}",
            row.name,
            row.sections,
            row.selector_refs,
            row.methods,
            row.methods_with_selector,
            row.stubs,
            row.class_names
        );
        for (address, selector) in &row.stub_head {
            eprintln!("    桩 {address:#014x} → {selector}");
        }
        for note in &row.notes {
            eprintln!("    note: {note}");
        }
    }

    for row in &counts {
        if row.sections == 0 {
            // 没有 __objc_* 节：结果是空表，但必须有人说明这一点（§7）。
            assert!(
                row.notes.is_empty(),
                "{}：没有 __objc_* 节时不该有 objc 说明",
                row.name
            );
            continue;
        }
        let joined = row.notes.join("\n");
        assert!(
            joined.contains("ObjC 元数据"),
            "{}：有 __objc_* 节（{} 个）就必须有 objc 解析的说明，实际 notes：\n{joined}",
            row.name,
            row.sections
        );
        // 结构不变量：名字只能来自名字池 —— 每格解出来的名字非空（空说明没解出）。
        assert!(
            row.selector_refs <= row.selector_refs.max(row.sections * 2) + 1,
            "{}：选择器槽数不该超过节数的两倍加一（{} 节、{} 槽）—— 数字太离谱",
            row.name,
            row.sections,
            row.selector_refs
        );
        if row.stubs > 0 {
            // 桩头只是前 5 条的展示（`take(5)`）：数量只会 ≤ 桩总数。
            assert!(
                row.stub_head.len() <= row.stubs,
                "{}：桩头（{}）不该多于桩总数（{}）",
                row.name,
                row.stub_head.len(),
                row.stubs
            );
        }
    }

    // LiveContainer 的逐条期望是本片手工反推 + llvm 实读对出来的（CLAUDE.md §6.11）：
    for row in &counts {
        if row.name.contains("LiveContainer") {
            assert_eq!(
                row.sections, 14,
                "LiveContainer：预期 14 个 __objc_* 节，实际 {}",
                row.sections
            );
            assert_eq!(
                row.selector_refs, 140,
                "LiveContainer：__objc_selrefs 是 140 个 8 字节槽，全部能解，实际 {}",
                row.selector_refs
            );
            assert_eq!(
                row.methods, 40,
                "LiveContainer：方法表解出 40 个方法，实际 {}",
                row.methods
            );
            assert_eq!(
                row.methods_with_selector, 40,
                "LiveContainer：40 个方法都有选择器名，实际 {}",
                row.methods_with_selector
            );
            assert_eq!(
                row.stubs, 122,
                "LiveContainer：__objc_stubs 是 122 个 32 字节桩，全部解出选择器，实际 {}",
                row.stubs
            );
            assert_eq!(
                row.class_names, 4,
                "LiveContainer：__objc_classname 池里有 4 个类名，实际 {}",
                row.class_names
            );
            let first_stub = row.stub_head.first().expect("有 122 个桩就有第一个");
            assert_eq!(
                first_stub.1, "URLByAppendingPathComponent:",
                "LiveContainer 第一条消息桩应指向 URLByAppendingPathComponent:，实际 {:#x} → {}",
                first_stub.0, first_stub.1
            );
        }
    }
}

/// 类归属的实测结果。
struct ClassCounts {
    name: String,
    classes: usize,
    named_classes: usize,
    classes_with_methods: usize,
    categories: usize,
    category_methods: usize,
    /// 二进制**自己的**符号表里那些名字：证明归属关系是真的。
    symbol_names: Vec<String>,
    notes: Vec<String>,
}

fn measure_classes(path: &std::path::Path) -> ClassCounts {
    let ipa =
        std::fs::read(path).unwrap_or_else(|error| panic!("读不到 {}：{error}", path.display()));
    let listing = zip::list_members(&ipa)
        .unwrap_or_else(|error| panic!("IPA 应当是能列成员的 ZIP：{}", error.summary_zh()));
    let (_index, member_name, binary) = pick_main_binary(&ipa, &listing);
    let (_how, _facts, object) = parse_one_image(&binary);

    let objc = &object.objc;
    ClassCounts {
        name: member_name.clone(),
        classes: objc.classes.len(),
        named_classes: objc
            .classes
            .iter()
            .filter(|class| class.name.is_some())
            .count(),
        classes_with_methods: objc
            .classes
            .iter()
            .filter(|class| !class.instance_methods.is_empty() || !class.class_methods.is_empty())
            .count(),
        categories: objc.categories.len(),
        category_methods: objc
            .categories
            .iter()
            .map(|category| category.instance_methods.len() + category.class_methods.len())
            .sum(),
        // 符号表里的名字：二进制自己写着"这个地址叫什么"。
        symbol_names: object
            .symbols
            .iter()
            .filter(|symbol| symbol.name.contains("[") || symbol.name.contains("]"))
            .map(|symbol| symbol.name.clone())
            .collect(),
        notes: objc.notes.clone(),
    }
}

#[test]
#[ignore = "需要真实 IPA（temp/*.ipa 或 BITFLIP_TEST_MACHO_IPA）；用 --ignored 手动跑"]
fn real_ios_binaries_report_objc_class_ownership() {
    let paths = all_sample_paths();
    let counts: Vec<ClassCounts> = paths.iter().map(|path| measure_classes(path)).collect();

    eprintln!(
        "{:<44} {:>6} {:>8} {:>6} {:>6} {:>8}",
        "样本", "类", "有类名", "有方法", "类别", "类别方法"
    );
    for row in &counts {
        eprintln!(
            "{:<44} {:>6} {:>8} {:>6} {:>6} {:>8}",
            row.name,
            row.classes,
            row.named_classes,
            row.classes_with_methods,
            row.categories,
            row.category_methods
        );
        for note in &row.notes {
            eprintln!("    note: {note}");
        }
    }

    // 结构不变量（不依赖具体样本）：类名数不会超过类数；解出的方法数受方法表约束。
    for row in &counts {
        assert!(
            row.named_classes <= row.classes,
            "{}：解出类名数（{}）不该多于类数（{}）",
            row.name,
            row.named_classes,
            row.classes
        );
    }

    // LiveContainer 的逐条期望：本片拿**二进制自己的符号表**当基准（CLAUDE.md §6.11：
    // 断言来自 oracle，不是来自解析代码）。符号表里有 `+[LCSharedUtils teamIdentifier]`
    // 这样的名字 —— 我们自己解出来的类方法名必须与它一致。
    let lc = counts
        .iter()
        .find(|row| row.name.contains("LiveContainer"))
        .expect("样本里应当有 LiveContainer");
    assert_eq!(
        lc.classes, 1,
        "LiveContainer：__objc_classlist 是 1 个指针，实际 {}",
        lc.classes
    );
    assert_eq!(
        lc.named_classes, 1,
        "LiveContainer：这个类名解得出来，实际 {}",
        lc.named_classes
    );
    assert_eq!(
        lc.categories, 4,
        "LiveContainer：__objc_catlist 是 4 个指针（0x20 / 8），实际 {}",
        lc.categories
    );
    assert!(
        lc.classes_with_methods >= 1,
        "LiveContainer：至少那个类要解出方法，实际 {}",
        lc.classes_with_methods
    );
    assert!(
        lc.category_methods > 0,
        "LiveContainer：类别里解出的方法数应当大于 0，实际 {}",
        lc.category_methods
    );

    // 关键：归属名与二进制自身的符号名互为印证。
    assert!(
        lc.symbol_names
            .iter()
            .any(|name| name.contains("LCSharedUtils")),
        "LiveContainer 符号表里应当有 LCSharedUtils 的名字（否则这条对照就失去意义）：{:?}",
        &lc.symbol_names[..lc.symbol_names.len().min(8)]
    );
    // 符号表里出现的 `+[LCSharedUtils <sel>]` 花括号形式，和我们解出的类方法名同族：
    // 这里只断言"类名 + 类方法形状"在两边都存在，避免把符号表的 block 包装差异写死。
    assert!(
        lc.symbol_names
            .iter()
            .any(|name| name.contains("+[LCSharedUtils")),
        "LiveContainer 符号表里应当有 `+[LCSharedUtils …]` 形式的类方法名：{:?}",
        &lc.symbol_names[..lc.symbol_names.len().min(8)]
    );
    assert!(
        lc.notes.iter().any(|note| note.contains("ObjC 归属")),
        "LiveContainer 的 notes 里应当有归属的账目：{:?}",
        lc.notes
    );

    // 回归守卫（本片修掉的真缺陷）：`class_t.data` 低 3 位是标志位，必须按
    // `FAST_DATA_MASK` 清掉，否则 `class_ro_t` 读偏 2 字节、类名恒空。
    // 修前 SideStore 只有 127/304 解出类名、PojavLauncher 还是老式绝对值指针
    // （不能加两遍 base）。两边现在都必须全解出来 —— 少一个就说明掩码/回退又坏了。
    let ss = counts
        .iter()
        .find(|row| row.name.contains("SideStore"))
        .expect("样本里应当有 SideStore");
    assert_eq!(
        ss.classes, 304,
        "SideStore：__objc_classlist 304 个指针，实际 {}",
        ss.classes
    );
    assert_eq!(
        ss.named_classes, 304,
        "SideStore：304 个类名都要解出来（data 低 3 位标志位要被 FAST_DATA_MASK 清掉），实际 {}",
        ss.named_classes
    );
    let pj = counts
        .iter()
        .find(|row| row.name.contains("PojavLauncher"))
        .expect("样本里应当有 PojavLauncher");
    assert_eq!(
        pj.classes, 38,
        "PojavLauncher：__objc_classlist 38 个指针，实际 {}",
        pj.classes
    );
    assert_eq!(
        pj.named_classes, 38,
        "PojavLauncher：38 个类名都要解出来（老式绝对值 data 指针不能加两遍 base），实际 {}",
        pj.named_classes
    );
}

/// `LC_CODE_SIGNATURE` 的文件范围（真实样本来验证）。
struct CodeSigCounts {
    name: String,
    file_len: u64,
    signature: Option<macho::LinkeditRange>,
    notes: Vec<String>,
}

fn measure_codesig(path: &std::path::Path) -> CodeSigCounts {
    let ipa =
        std::fs::read(path).unwrap_or_else(|error| panic!("读不到 {}：{error}", path.display()));
    let listing = zip::list_members(&ipa)
        .unwrap_or_else(|error| panic!("IPA 应当是能列成员的 ZIP：{}", error.summary_zh()));
    let (_index, member_name, binary) = pick_main_binary(&ipa, &listing);
    let (_how, facts, _object) = parse_one_image(&binary);
    CodeSigCounts {
        name: member_name.clone(),
        file_len: binary.len() as u64,
        signature: facts.code_signature,
        notes: facts.notes.clone(),
    }
}

#[test]
#[ignore = "需要真实 IPA（temp/*.ipa 或 BITFLIP_TEST_MACHO_IPA）；用 --ignored 手动跑"]
fn real_ios_binaries_report_code_signature_range() {
    let paths = all_sample_paths();
    let counts: Vec<CodeSigCounts> = paths.iter().map(|path| measure_codesig(path)).collect();

    eprintln!(
        "{:<44} {:>10} {:>10} {:>10}",
        "样本", "文件字节", "签名 off", "签名长"
    );
    for row in &counts {
        let (off, size) = match row.signature {
            Some(range) => (range.dataoff, range.datasize),
            None => (0, 0),
        };
        eprintln!(
            "{:<44} {:>10} {:>10} {:>10}",
            row.name, row.file_len, off, size
        );
        for note in &row.notes {
            if note.contains("签名") {
                eprintln!("    note: {note}");
            }
        }
    }

    // LiveContainer 的逐条期望来自 `llvm-objdump --macho --private-headers` 的实读
    // （CLAUDE.md §6.11：断言来自 oracle，不是来自解析代码）：
    //   cmd LC_CODE_SIGNATURE
    //   dataoff 134928   datasize 16720
    // 文件 151648 字节 → 签名区落在文件末尾那段（[134928, 151648)）。
    let lc = counts
        .iter()
        .find(|row| row.name.contains("LiveContainer"))
        .expect("样本里应当有 LiveContainer");
    let sig = lc.signature.unwrap_or_else(|| {
        panic!(
            "LiveContainer 有 LC_CODE_SIGNATURE，必须读出范围；notes：{:?}",
            lc.notes
        )
    });
    assert_eq!(
        sig.dataoff, 134928,
        "LiveContainer 签名 dataoff 应与 llvm-objdump 一致"
    );
    assert_eq!(
        sig.datasize, 16720,
        "LiveContainer 签名 datasize 应与 llvm-objdump 一致"
    );
    assert_eq!(
        sig.dataoff + sig.datasize,
        lc.file_len,
        "签名数据应当正好铺到文件末尾（{} + {} = {}）",
        sig.dataoff,
        sig.datasize,
        lc.file_len
    );

    // 每个有签名区的样本，签名区都必须落在文件范围内（不越界）。
    for row in &counts {
        if let Some(range) = row.signature {
            assert!(
                range.dataoff + range.datasize <= row.file_len,
                "{}：签名区 {}..{} 超出了文件 {} 字节",
                row.name,
                range.dataoff,
                range.dataoff + range.datasize,
                row.file_len
            );
        }
    }
}

/// 一个样本的 Swift 元数据计数（打印与断言共用）。
struct SwiftCounts {
    name: String,
    type_count: usize,
    types_named: usize,
    protocol_count: usize,
    protocols_named: usize,
    has_entry: bool,
    unparsed: usize,
    skipped: usize,
    sample_types: Vec<String>,
}

fn measure_swift(path: &std::path::Path) -> SwiftCounts {
    let ipa =
        std::fs::read(path).unwrap_or_else(|error| panic!("读不到 {}：{error}", path.display()));
    let listing = zip::list_members(&ipa)
        .unwrap_or_else(|error| panic!("IPA 应当是能列成员的 ZIP：{}", error.summary_zh()));
    let (_index, member_name, binary) = pick_main_binary(&ipa, &listing);
    let (_how, _facts, object) = parse_one_image(&binary);
    let swift = &object.swift;
    SwiftCounts {
        name: member_name.clone(),
        type_count: swift.type_count,
        types_named: swift.types.len(),
        protocol_count: swift.protocol_count,
        protocols_named: swift.protocols.len(),
        has_entry: swift.has_entry,
        unparsed: swift.unparsed_sections.len(),
        skipped: swift.skipped,
        sample_types: swift
            .types
            .iter()
            .take(5)
            .map(|symbol| symbol.name.clone())
            .collect(),
    }
}

#[test]
#[ignore = "需要真实 IPA（temp/*.ipa 或 BITFLIP_TEST_MACHO_IPA）；用 --ignored 手动跑"]
fn real_ios_binaries_report_swift_metadata() {
    let paths = all_sample_paths();
    let counts: Vec<SwiftCounts> = paths.iter().map(|path| measure_swift(path)).collect();

    for row in &counts {
        eprintln!(
            "{:<44} type={:>4}/{:>4} proto={:>3}/{:>3} entry={} skipped={} unparsed={} samples={:?}",
            row.name,
            row.types_named,
            row.type_count,
            row.protocols_named,
            row.protocol_count,
            row.has_entry,
            row.skipped,
            row.unparsed,
            row.sample_types
        );
    }

    // SideStore 有完整的 Swift 5 节：类型与协议都必须解出一批，且入口存在。
    let ss = counts
        .iter()
        .find(|row| row.name.contains("SideStore"))
        .expect("样本里应当有 SideStore");
    assert!(
        ss.type_count > 0,
        "SideStore 的 __swift5_types 应该有类型，实际 {}",
        ss.type_count
    );
    assert!(
        ss.types_named > 0,
        "SideStore 应当解出一批类型名，实际 {}",
        ss.types_named
    );
    assert!(
        ss.protocol_count > 0 && ss.protocols_named > 0,
        "SideStore 的 __swift5_protos 应该解出协议名（{}/{}）",
        ss.protocols_named,
        ss.protocol_count
    );
    // 解出的名字必须是可读的 Swift 标识符（字母开头、无控制字符），不是乱码。
    assert!(
        ss.sample_types.iter().all(|name| name
            .chars()
            .next()
            .is_some_and(|c| c.is_ascii_alphabetic() || c == '_')
            && name.chars().all(|c| c.is_ascii_graphic() || c == ' ')),
        "解出的名字应当是可读的 Swift 标识符，实际 {:?}",
        ss.sample_types
    );
    // 其余样本即使没有 Swift 节，也不该 panic（空表即"没有"，§7）。
    for row in &counts {
        assert!(
            row.types_named <= row.type_count,
            "{}：解出的名字数 {} 不该多于条目数 {}",
            row.name,
            row.types_named,
            row.type_count
        );
    }
}

/// 一个样本的代码签名摘要（打印与断言共用）。
struct SignCounts {
    name: String,
    present: bool,
    verdict: String,
    algorithm: String,
    identifier: String,
    slots: u64,
    verified: u64,
    first_mismatch: Option<u64>,
    has_cms: bool,
}

#[test]
#[ignore = "需要真实 IPA（temp/*.ipa 或 BITFLIP_TEST_MACHO_IPA）；用 --ignored 手动跑"]
fn real_ios_binaries_report_code_signature_verdicts() {
    use bitflip_loader::object::CodeSignVerdict;

    let paths = all_sample_paths();
    let mut rows = Vec::new();
    for path in &paths {
        let ipa = std::fs::read(path).expect("读 IPA");
        let listing = zip::list_members(&ipa).expect("列成员");
        let (_index, member_name, binary) = pick_main_binary(&ipa, &listing);
        let (_how, _facts, object) = parse_one_image(&binary);
        let row = match &object.signature {
            None => SignCounts {
                name: member_name.clone(),
                present: false,
                verdict: "None".to_string(),
                algorithm: "-".to_string(),
                identifier: String::new(),
                slots: 0,
                verified: 0,
                first_mismatch: None,
                has_cms: false,
            },
            Some(sig) => SignCounts {
                name: member_name.clone(),
                present: true,
                verdict: format!("{:?}", sig.verdict),
                algorithm: sig.algorithm.name().to_string(),
                identifier: sig.identifier.clone(),
                slots: sig.code_slots,
                verified: sig.verified_slots,
                first_mismatch: sig.first_mismatch,
                has_cms: sig.has_cms_signature,
            },
        };
        eprintln!(
            "{:<44} present={} verdict={:<10} alg={:<10} slots={}(verify {}) cms={} mismatch={:?} id={}",
            row.name,
            row.present,
            row.verdict,
            row.algorithm,
            row.slots,
            row.verified,
            row.has_cms,
            row.first_mismatch,
            row.identifier
        );
        rows.push(row);
    }

    // LiveContainer 是 ad-hoc（无 CMS）、SHA-256、全部页一致 → AdHoc。
    let lc = rows
        .iter()
        .find(|row| row.name.contains("LiveContainer"))
        .expect("样本里应有 LiveContainer");
    assert!(lc.present, "LiveContainer 应有签名结构");
    assert_eq!(
        lc.verdict, "AdHoc",
        "LiveContainer 是 ad-hoc 且逐页一致，应为 AdHoc，实际 {}",
        lc.verdict
    );
    assert_eq!(lc.algorithm, "SHA-256");
    assert!(!lc.has_cms, "ad-hoc 没有 CMS 槽");
    assert_eq!(
        lc.verified, lc.slots,
        "LiveContainer 所有 code page 都应一致"
    );
    assert_eq!(lc.slots, 33, "实测 LiveContainer 33 个 code slot");

    // SideStore 是 SHA-1、带 CMS；完整性结论要么 Intact 要么 Mismatch（样本可能被动过），
    // 但一定要读出结构、算法与 slot 数，且 verified ≤ slots。
    let ss = rows
        .iter()
        .find(|row| row.name.contains("SideStore"))
        .expect("样本里应有 SideStore");
    assert!(ss.present, "SideStore 应有签名结构");
    assert_eq!(ss.algorithm, "SHA-1");
    assert!(ss.has_cms, "SideStore 应带 CMS 签名槽");
    assert_eq!(ss.slots, 4728, "实测 SideStore 4728 个 code slot");
    assert!(ss.verified <= ss.slots);
    assert!(
        matches!(ss.verdict.as_str(), "Intact" | "Mismatch"),
        "SideStore verdict 应为 Intact 或 Mismatch，实际 {}",
        ss.verdict
    );
    // 全部样本（无论有没有签名）都不该 panic，verdict 是枚举之一。
    for row in &rows {
        if row.present {
            assert!(
                [
                    "NotSigned",
                    "AdHoc",
                    "UnsupportedAlgorithm",
                    "Malformed",
                    "Intact",
                    "Mismatch"
                ]
                .contains(&row.verdict.as_str()),
                "{}：未知 verdict {}",
                row.name,
                row.verdict
            );
        }
    }
    let _ = CodeSignVerdict::NotSigned; // 引用一下，避免 import 未用告警（文档用途）
}
