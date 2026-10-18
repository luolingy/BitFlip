//! 真实 Mach-O 上"分析层真的用上了 `LC_FUNCTION_STARTS`"的验收测试（M12 第四片）。
//!
//! 默认 `#[ignore]`：它要一份真实 IPA（`temp/*.ipa` 或 `BITFLIP_TEST_MACHO_IPA`）。
//! **样本缺失时它 panic，不跳过** —— 跳过会让绿灯说谎（CLAUDE.md §7）。
//!
//! # 这条测试要回答的两个问题
//!
//! 1. **接上了没有**：加载器解出的每一个（落在已映射空间的）函数起点，分析结果里
//!    是否都有一个函数？光"解出来"不算数，要能用上才算。
//! 2. **接上之后多了什么**：把 `Object.function_starts` 清空再跑一遍就是**旧行为**
//!    （这条来源出现之前的分析），两次计数直接可比 —— 不需要翻历史版本。
//!
//! 跑法（`--ignored` 要通过测试可执行文件直接传，`scripts/cargo.ps1` 会吃掉 `--`）：
//!
//! ```text
//! & .\scripts\cargo.ps1 test --offline -p bitflip-core --test macho_real_analysis --no-run
//! & .\.cargo-target\debug\deps\macho_real_analysis-<hash>.exe --ignored --nocapture
//! ```

use std::collections::HashSet;
use std::path::PathBuf;
use std::sync::Arc;

use bitflip_analyze::StringOptions;
use bitflip_core::{Disasm, DisasmScanOptions, TargetAnalysis};
use bitflip_loader::format::macho;
use bitflip_loader::format::zip;
use bitflip_loader::object::ObjectId;

/// 本机真实 IPA：优先 `BITFLIP_TEST_MACHO_IPA`，否则在 `temp/` 里找。
///
/// 顺序按**解压后主二进制最小**排（LiveContainer 151 KB）：真实样本测试跑得快
/// 才有意义，而 19 MB 的那份在低配机上不便宜。
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
         这条测试不是「可以跳过」的：它是「分析层真的用上了 LC_FUNCTION_STARTS」\
         在真实二进制上的唯一证据（CLAUDE.md §7）",
        dir.display()
    );
}

/// 从 IPA 里取出主二进制并解析成对象，返回（描述、对象、文件字节）。
fn real_object(path: &std::path::Path) -> (String, bitflip_loader::object::Object, Arc<[u8]>) {
    let ipa =
        std::fs::read(path).unwrap_or_else(|error| panic!("读不到 {}：{error}", path.display()));
    let listing = zip::list_members(&ipa)
        .unwrap_or_else(|error| panic!("IPA 应当是能列成员的 ZIP：{}", error.summary_zh()));
    let names: Vec<&str> = listing.members.iter().map(|m| m.name.as_str()).collect();
    let found = bitflip_loader::bundle::find_main_binary(&names, |index| {
        zip::read_member(&ipa, index).ok()
    })
    .unwrap_or_else(|| panic!("这份 IPA 里找不到 Mach-O 主二进制：{}", path.display()));
    let member = zip::read_member(&ipa, found.index)
        .unwrap_or_else(|error| panic!("取成员 {} 失败：{}", found.name, error.summary_zh()));

    if macho::looks_like_fat(&member) {
        let container = macho::fat::read(&member).expect("fat 容器的架构表必须能读");
        let chosen = container
            .slices
            .iter()
            .position(|slice| {
                slice
                    .arch
                    .is_some_and(|spec| spec.to_string().starts_with("aarch64"))
            })
            .unwrap_or(0);
        let object = macho::fat::parse_slice(&member, chosen, ObjectId::Plain)
            .unwrap_or_else(|error| panic!("第 {chosen} 片解析失败：{}", error.summary_zh()));
        let slice = macho::fat::slice_bytes(&member, &container.slices[chosen])
            .expect("切片的字节范围在读容器时已经校验过");
        let bytes: Arc<[u8]> = slice.to_vec().into();
        return (format!("fat 第 {chosen} 片"), object, bytes);
    }

    let object = macho::parse(&member, 0, ObjectId::Plain)
        .unwrap_or_else(|error| panic!("薄 Mach-O 解析失败：{}", error.summary_zh()));
    (
        format!("薄 Mach-O（{}）", found.name),
        object,
        member.into(),
    )
}

fn analyze(object: &bitflip_loader::object::Object, bytes: Arc<[u8]>) -> (Disasm, TargetAnalysis) {
    let disasm = Disasm::build(object, bytes, DisasmScanOptions::default());
    let analysis = TargetAnalysis::build(&disasm, object, &StringOptions::default(), None, None);
    (disasm, analysis)
}

/// 一次分析的计数（打印与断言共用，免得两处各算一遍）。
struct Counts {
    functions: usize,
    /// 上界已知（也就是有大小）的函数数 —— 这一列就是"不用反汇编也拿到了函数大小"。
    known_ends: usize,
    /// 起点落在 `LC_FUNCTION_STARTS` 里的函数数。
    from_table: usize,
    /// `source` 显示为"函数起点表"的函数数（没有别的来源参与命名/佐证）。
    ///
    /// 注意它**不是**"因为这张表才存在"：一个地址可能先由符号表或调用目标发现，
    /// 边界再来自这张表。那种情况下函数数不变、只是大小有了。
    only_from_table: usize,
}

fn count(analysis: &TargetAnalysis, starts: &HashSet<u64>) -> Counts {
    let mut counts = Counts {
        functions: analysis.function_count(),
        known_ends: 0,
        from_table: 0,
        only_from_table: 0,
    };
    for function in analysis.functions() {
        if function.end.is_some() {
            counts.known_ends += 1;
        }
        let Ok(start) = u64::from_str_radix(&function.start, 16) else {
            continue;
        };
        if starts.contains(&start) {
            counts.from_table += 1;
        }
        if function.source == "function-start" {
            counts.only_from_table += 1;
        }
    }
    counts
}

/// 真实样本：函数起点必须**每一个**都用上，并且真的给出大小。
#[test]
#[ignore = "需要真实 IPA（temp/*.ipa 或 BITFLIP_TEST_MACHO_IPA）；用 --ignored 手动跑"]
fn real_macho_uses_function_starts_as_function_boundaries() {
    let path = sample_path();
    let (how, object, bytes) = real_object(&path);
    eprintln!(
        "样本 {}（{} 字节 IPA）→ {how}，主二进制 {} 字节",
        path.file_name().map_or_else(
            || path.display().to_string(),
            |name| name.to_string_lossy().into_owned()
        ),
        std::fs::metadata(&path).map_or(0, |meta| meta.len()),
        bytes.len()
    );
    eprintln!(
        "对象：{} / {} / 段 {} / 节 {} / 符号 {} / 函数起点 {}",
        object.arch,
        object.kind.as_str(),
        object.segments.len(),
        object.sections.len(),
        object.symbols.len(),
        object.function_starts.len()
    );
    for segment in &object.segments {
        eprintln!(
            "  段 {:<12} vaddr {:#012x} vsize {:#x} 权限 {}",
            segment.name,
            segment.vaddr,
            segment.vsize,
            segment.perms.to_rwx()
        );
    }

    assert!(
        !object.function_starts.is_empty(),
        "{}：加载器一个函数起点都没解出来。要么这份二进制被剥掉了 LC_FUNCTION_STARTS，\
         要么 M12 第三片的解析器退化了 —— 两种都要说清楚，不能拿一条绿色的测试盖过去",
        path.display()
    );

    let started = std::time::Instant::now();
    let (disasm, analysis) = analyze(&object, Arc::clone(&bytes));
    eprintln!(
        "接上函数起点表的一遍：{:.1}s（反汇编 + 分析，{} 条已索引指令）",
        started.elapsed().as_secs_f64(),
        disasm.index.len()
    );
    let starts: HashSet<u64> = object.function_starts.iter().copied().collect();
    let after = count(&analysis, &starts);

    // 旧行为 = 把这张表清空再跑一遍（这条来源出现之前，分析层看到的就是这样）。
    let mut without_table = object.clone();
    without_table.function_starts.clear();
    let started = std::time::Instant::now();
    let (_old_disasm, old_analysis) = analyze(&without_table, Arc::clone(&bytes));
    eprintln!(
        "旧行为的一遍（函数起点表清空）：{:.1}s",
        started.elapsed().as_secs_f64()
    );
    let before = count(&old_analysis, &HashSet::new());

    eprintln!(
        "分析：函数 {before_f} → {after_f}（+{delta}），上界已知 {before_e} → {after_e}，\
         起点命中表 {from_table}/{starts}，来源显示为该表的函数 {only}",
        before_f = before.functions,
        after_f = after.functions,
        delta = after.functions - before.functions,
        before_e = before.known_ends,
        after_e = after.known_ends,
        from_table = after.from_table,
        starts = object.function_starts.len(),
        only = after.only_from_table
    );

    // ① 每一个**落在已映射空间里**的起点都必须变成一个函数。
    //    不在映射空间里的那些是另一件事（表被截断/基址不符），分析层会单独报出来。
    let mapped: HashSet<u64> = object
        .function_starts
        .iter()
        .copied()
        .filter(|&start| disasm.space.read_u8(start).is_some())
        .collect();
    let produced: HashSet<u64> = analysis
        .functions()
        .iter()
        .filter_map(|function| u64::from_str_radix(&function.start, 16).ok())
        .collect();
    let mut missing: Vec<u64> = mapped.difference(&produced).copied().collect();
    missing.sort_unstable();
    eprintln!(
        "起点覆盖：映射内 {} 个，分析结果里缺 {} 个{}",
        mapped.len(),
        missing.len(),
        if missing.is_empty() {
            String::new()
        } else {
            format!("（前 5 个：{:x?}）", &missing[..missing.len().min(5)])
        }
    );
    assert!(
        missing.is_empty(),
        "有 {} 个函数起点没有变成函数 —— 表解出来了却没用上：{:x?}",
        missing.len(),
        &missing[..missing.len().min(10)]
    );

    // ② 用上之后必须**多出大小**：这是"不用反汇编也有边界"的唯一证据。
    assert!(
        after.known_ends > before.known_ends,
        "用上函数起点表之后，上界已知的函数数应当增加（{} → {}）—— 否则边界没有真的落地",
        before.known_ends,
        after.known_ends
    );
    // ③ 这条来源必须**真的落地**：要么多出函数，要么多出大小 —— 至少一个变了。
    //
    //    实测（LiveContainer，见 CHANGELOG）是后者：114 个起点本来就都被符号表/调用
    //    目标覆盖了，所以函数数 311 → 311 不变；变的是"上界已知"从 0 到 114 ——
    //    Mach-O 上没有 .pdata/e_frame，调试信息也没有，此前**一个函数都没有大小**。
    assert!(
        after.functions > before.functions || after.known_ends > before.known_ends,
        "接上函数起点表之后函数数与'上界已知'数都没变（{} → {}、{} → {}）—— \
         这条来源没有真的接入",
        before.functions,
        after.functions,
        before.known_ends,
        after.known_ends
    );
    // ④ 接上新来源不该**减少**任何已有的函数（只许加，不许吞）。
    assert!(
        after.functions >= before.functions,
        "接上函数起点表之后函数数反而变少了（{} → {}）：有来源把已有函数吞掉了",
        before.functions,
        after.functions
    );
    // ⑤ notes 必须说清"结束地址是推导的"（§7：推导出来的事实不能冒充文件事实）。
    let notes = analysis.notes().join("\n");
    assert!(
        notes.contains("LC_FUNCTION_STARTS") && notes.contains("推导"),
        "notes 里必须说明这批边界是推进出来的：{notes}"
    );

    eprintln!("notes（含函数起点表的那条）：");
    for note in analysis
        .notes()
        .iter()
        .filter(|note| note.contains("LC_FUNCTION_STARTS") || note.contains("函数起点"))
    {
        eprintln!("  - {note}");
    }
}
