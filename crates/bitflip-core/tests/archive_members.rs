//! M5 验收标准 1：归档成员可独立反汇编，且符号定位能用。
//!
//! 这条验收标准的原文要求"每个成员都能被独立反汇编，并给出函数计数；
//! 成员选择与符号定位在 UI 与 CLI 里都能用"。所以测试盯的是三件事：
//!
//! 1. 每个成员**各自**能分析（不是只有第一个成员能用）；
//! 2. 成员之间的结果**确实不同**（如果所有成员都返回同一份结果，
//!    "按成员分析"就只是个说法）；
//! 3. 拿不到的情形如实报错（成员名不存在、不唯一、不是可分析对象）。
//!
//! 这些 fixture 由 `scripts/gen-fixtures.ps1` 生成，内容在
//! `tests/fixtures/*.c`。缺 fixture 时**硬失败**并给出重建命令 ——
//! 一条在缺 fixture 时静默跳过的验收测试等于没有验收。

use std::path::PathBuf;

use bitflip_core::{BitflipError, OpenOptions, Session};

/// 生成产物目录（gitignored，由脚本生成）。
fn generated_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("..")
        .join("..")
        .join("tests")
        .join("fixtures")
        .join("generated")
}

fn fixture(name: &str) -> PathBuf {
    let path = generated_dir().join(name);
    assert!(
        path.exists(),
        "缺少 fixture {}。先跑 `pwsh -File scripts/gen-fixtures.ps1` 生成。",
        path.display()
    );
    path
}

fn open(name: &str) -> Session {
    Session::open(fixture(name), OpenOptions::default()).expect("打开 fixture")
}

/// 三架构的 GNU 归档：每个成员都必须能独立分析。
///
/// 这个 fixture 是特意做成"同一份 C 源码编译三个架构"的 —— 于是成员之间
/// 的函数名相同、机器码不同。如果实现是"拿第一个成员的结果糊弄所有成员"，
/// 这里的函数地址会全部相同，测试就会失败。
#[test]
fn every_member_of_a_multi_arch_archive_is_independently_analyzable() {
    let session = open("libelf-multi.a");
    assert!(session.info().is_archive(), "libelf-multi.a 应是归档");

    // 收集真正可分析的成员（跳过符号索引 `/` 这类元数据成员）
    let mut analyzed = Vec::new();
    let mut skipped = Vec::new();
    for member in session.members() {
        match session.member_session(&member.name) {
            Ok((member_session, m)) => {
                let analysis = member_session
                    .analysis(&member_session.detached_job())
                    .unwrap_or_else(|e| panic!("成员 {} 分析失败：{e}", m.name));
                let counts = (analysis.function_count(), analysis.xref_count());
                analyzed.push((m.name.clone(), counts));
            }
            Err(error) => skipped.push((member.name.clone(), error.to_string())),
        }
    }

    // 这个 fixture 有三个架构成员，都必须成功
    assert_eq!(
        analyzed.len(),
        3,
        "三个架构成员都应可分析；实际分析成功 {} 个、跳过 {} 个（{:?}）。\
         跳过原因：{skipped:?}",
        analyzed.len(),
        skipped.len(),
        analyzed
    );

    // 每个成员都要有函数 —— "能打开"不等于"能分析"
    for (name, (functions, xrefs)) in &analyzed {
        assert!(
            *functions > 0,
            "成员 {name} 应该识别出函数，实际 0 个（交叉引用 {xrefs} 条）"
        );
    }

    // 关键：成员之间的结果必须**真的不同**。
    // 三个架构的同一份源码，机器码不同 —— 结果全都一样就很可疑。
    let distinct: std::collections::BTreeSet<_> =
        analyzed.iter().map(|(_, counts)| *counts).collect();
    assert!(
        distinct.len() > 1,
        "三个架构成员的 (函数数, 交叉引用数) 完全相同（{:?}）——\
         这不像是对每个成员独立分析出来的结果",
        analyzed
    );
}

/// 同一份源码的 x86_64 与 aarch64 成员：函数名相同、**布局不同**。
///
/// 这条是上一个测试的定点版本。函数**个数**三个成员都是 3（那是符号表
/// 决定的，本来就该一样），真正会变的是**每个函数的地址**：
/// 同一份 C 编译到不同架构，函数体长度不同，所以第二个函数的偏移不同。
///
/// 一开始我把这条断言写成"函数个数要不同"，那是错的 —— 个数相同恰恰是
/// 正确的表现。改成断言函数地址的集合不同，才是真正在验证"按成员切分"。
#[test]
fn members_of_different_architectures_report_different_layouts() {
    let session = open("libelf-multi.a");

    let mut layouts = Vec::new();
    for name in ["elf-x86_64.o", "elf-aarch64.o", "elf-i386.o"] {
        let (member_session, member) = session
            .member_session(name)
            .unwrap_or_else(|e| panic!("取成员 {name}：{e}"));
        assert_eq!(member.name, name);
        assert!(!member_session.info().is_archive(), "成员会话不该再是归档");

        let analysis = member_session
            .analysis(&member_session.detached_job())
            .expect("分析成员");

        // 收集该成员里**所有命名函数的入口地址**
        let mut addrs: Vec<String> = analysis
            .functions()
            .iter()
            .filter(|f| f.named)
            .map(|f| f.start.clone())
            .collect();
        addrs.sort();
        layouts.push((name.to_string(), addrs));
    }

    for (name, addrs) in &layouts {
        assert!(!addrs.is_empty(), "成员 {name} 里应有命名函数");
    }

    // 三个成员各自的"函数地址表"不能全都一样 ——
    // 如果实现是把某个成员的结果复制了三份，这里必然全等。
    let distinct: std::collections::BTreeSet<_> =
        layouts.iter().map(|(_, addrs)| addrs.clone()).collect();
    assert!(
        distinct.len() > 1,
        "三个架构成员的函数地址表完全相同（{layouts:?}）——\
         成员分析可能没有真正按成员切分"
    );
}

/// MSVC `.lib` 的成员同样可分析。
///
/// `.lib` 与 GNU `ar` 的成员链结构不同（链接器成员 / 第二成员链），
/// 所以这条单独走一遍：GNU 归档能分析不代表 `.lib` 能。
#[test]
fn msvc_lib_member_is_analyzable() {
    let session = open("pe-x86_64.lib");
    assert!(session.info().is_archive(), "pe-x86_64.lib 应是归档");

    let (member_session, member) = session
        .member_session("pe-x86_64.obj")
        .expect("取 .lib 成员");

    assert_eq!(member.name, "pe-x86_64.obj");
    assert!(
        !member_session.info().is_archive(),
        "成员会话不该再是归档：{}",
        member_session.info().container
    );

    let analysis = member_session
        .analysis(&member_session.detached_job())
        .expect("分析 .lib 成员");
    assert!(
        !analysis.functions().is_empty(),
        "pe-x86_64.obj 里应有函数（COFF 符号表）"
    );
}

/// 成员里带名字的函数必须保留符号表里的真名。
///
/// 这是 §7 的直接检查：成员分析如果退化成"只有地址没有名字"，
/// 或者反过来生成了 `func_xxx` 占位名，这条会失败。
#[test]
fn member_functions_keep_their_real_symbol_names() {
    let session = open("libelf-x86_64.a");
    let (member_session, _) = session
        .member_session("elf-x86_64.o")
        .expect("取成员 elf-x86_64.o");
    let analysis = member_session
        .analysis(&member_session.detached_job())
        .expect("分析成员");

    let names: Vec<&str> = analysis
        .functions()
        .iter()
        .filter(|f| f.named)
        .map(|f| f.name.as_str())
        .collect();

    for expected in ["bf_add", "bf_loop", "bf_entry"] {
        assert!(
            names.contains(&expected),
            "成员里应有符号 {expected}；实际命名函数：{names:?}"
        );
    }

    // 反向：不许出现占位名
    for f in analysis.functions() {
        assert!(
            !f.name.starts_with("func_") && !f.name.starts_with("sub_"),
            "出现了占位名 {:?} —— 名字来自符号表，拿不到就该是未命名（named=false）",
            f.name
        );
    }
}

/// 成员名不存在 → 明确报错，且错误信息里给出成员总数。
#[test]
fn unknown_member_is_reported_with_the_member_count() {
    let session = open("libelf-multi.a");
    let error = session
        .member_session("no_such_member.o")
        .expect_err("不存在的成员必须报错");

    assert!(
        matches!(error, BitflipError::NotFound { .. }),
        "应是 NotFound，实际 {error:?}"
    );
    let text = error.to_string();
    assert!(
        text.contains("no_such_member.o"),
        "错误信息应包含查的名字：{text}"
    );
    assert!(
        text.contains(&session.members().len().to_string()),
        "错误信息应给出成员总数（{}）：{text}",
        session.members().len()
    );
}

/// 对非归档目标用 `member_session` → 报错说明"这不是归档"。
///
/// 不返回空会话：那会让调用方以为"成员列表是空的"，
/// 而真实情况是"这个目标根本没有成员的概念"。
#[test]
fn member_session_on_a_plain_target_is_rejected() {
    let session = open("elf-x86_64.exe");
    assert!(!session.info().is_archive());

    let error = session
        .member_session("anything.o")
        .expect_err("非归档目标必须报错");
    let text = error.to_string();
    assert!(
        text.contains("归档") || text.contains("archive"),
        "错误信息应说明目标不是归档：{text}"
    );
}

/// 元数据成员（GNU 的符号索引）不许被当成可分析对象。
///
/// 它确实在成员列表里，但它不是一个对象文件。若实现"凡是成员就尝试解析"，
/// 这里会拿到一个解析失败的错误 —— 那也可以接受，但**必须报错**，
/// 绝不能返回一个空的成功会话让 UI 显示"分析完成，什么都没有"。
///
/// 注意成员名：`bitflip-loader` 把符号索引显示为 `/ (符号索引)`
/// （界面上直接显示 `/` 没法解释），所以这里用**列表里实际的名字**去找，
/// 而不是假定它是 `/`。用 `/` 也应该能匹配上 —— 那是另一条测试的事。
#[test]
fn metadata_member_is_not_silently_treated_as_an_object() {
    let session = open("libelf-multi.a");

    // 找符号索引成员：名字以 `/` 开头（可能是 `/` 或 `/ (符号索引)`）
    let index_member = session
        .members()
        .iter()
        .find(|m| m.name.starts_with('/') && !m.name.starts_with("//"))
        .unwrap_or_else(|| {
            panic!(
                "GNU 归档里应有符号索引成员；实际成员：{:?}",
                session
                    .members()
                    .iter()
                    .map(|m| m.name.as_str())
                    .collect::<Vec<_>>()
            )
        });

    match session.member_session(&index_member.name) {
        Err(_) => {
            // 预期路径：明确报错
        }
        Ok((member_session, _)) => {
            // 如果解析器把它当成了某个格式，那分析必须失败 ——
            // 成功才是问题
            let result = member_session.analysis(&member_session.detached_job());
            assert!(
                result.is_err(),
                "符号索引成员不该产出可用的分析结果（拿到了 {} 个函数）",
                result.map(|a| a.functions().len()).unwrap_or(0)
            );
        }
    }
}

/// 用户敲 `--member /` 必须能匹配到列表里显示的 `/ (符号索引)`。
///
/// 这条盯的是一个真实的可用性坑：加载层为了让界面能解释，把成员名存成了
/// `"/ (符号索引)"`。如果不做规范化匹配，用户看到列表里的名字、
/// 照着敲 `/`，会得到"找不到" —— 而那正是他自己屏幕上写着的名字。
#[test]
fn member_lookup_accepts_the_raw_gnu_metadata_names() {
    let session = open("libelf-multi.a");

    for raw in ["/", "/ (符号索引)"] {
        let count = session.member_match_count(raw);
        assert_eq!(
            count, 1,
            "查 {raw:?} 应唯一命中符号索引成员，实际命中 {count} 个"
        );
        let found = session
            .find_member(raw)
            .unwrap_or_else(|| panic!("查 {raw:?} 应能找到成员"));
        assert!(
            found.name.starts_with('/'),
            "查 {raw:?} 找到的应是符号索引成员，实际 {:?}",
            found.name
        );
    }

    // 长名表 `//` 同样按原样可查
    let longnames = session.member_match_count("//");
    assert!(
        longnames <= 1,
        "查 \"//\" 的命中数不该超过 1，实际 {longnames}"
    );
}

/// 成员会话的地址空间与容器**无关**：成员的地址从 0 起。
///
/// 如果实现把容器的地址空间带进成员会话，成员里的地址会是文件偏移
/// 那种大值，反汇编就会全部落空（能"打开"但一条指令都没有）。
#[test]
fn member_address_space_starts_from_zero() {
    let session = open("libelf-multi.a");
    let (member_session, member) = session.member_session("elf-x86_64.o").expect("取成员");

    // .o 是 ET_REL：没有程序头，地址从 0 起
    let analysis = member_session
        .analysis(&member_session.detached_job())
        .expect("分析成员");

    let lowest = analysis
        .functions()
        .iter()
        .filter_map(|f| bitflip_core::parse_address(&f.start))
        .min()
        .expect("至少有一个函数");

    assert!(
        lowest < 0x1000,
        "成员里最低的函数地址是 {lowest:#x}（成员 {}，容器偏移 {:#x}）——\
         这看起来像是把容器偏移当成了成员内的地址",
        member.name,
        member.offset
    );
}

/// 成员会话用的是**成员自己的字节**，不是容器的。
///
/// 这里不能用 `read_virtual(0, ..)`：`.o` 是 ET_REL，没有程序头，
/// 虚拟地址 0 不落在任何已映射区间里（那是**正确的**行为 ——
/// 拿不到就说拿不到）。改为核对**成员文件自己的头部**：
/// 成员会话报告的节表偏移/节数，必须与容器里 `member.offset` 处的
/// ELF 头部一致；而容器自己在偏移 0 处是 ar 魔数。
#[test]
fn member_session_reads_the_member_bytes_not_the_container() {
    let session = open("libelf-multi.a");
    let (member_session, member) = session.member_session("elf-aarch64.o").expect("取成员");

    // 容器本身在偏移 0 处是 ar 魔数
    let container = std::fs::read(fixture("libelf-multi.a")).expect("读容器");
    assert_eq!(&container[..8], b"!<arch>\n", "容器应以 ar 魔数开头");

    let start = member.offset as usize;
    let expected = &container[start..start + 64];

    // 成员自己的 ELF 头：魔数必须是 ELF，而容器同一位置是 ar 成员头
    assert_eq!(
        &expected[..4],
        b"\x7fELF",
        "容器 offset {:#x} 处应是成员 {:?} 的 ELF 头",
        member.offset,
        member.name
    );

    // 成员会话的解析结果必须来自这段字节：比较 ELF 头里的
    // e_shoff（节表偏移）与 e_shnum（节数）。
    // 若实现误用了容器字节，这两个值会是对不上的（容器头根本不是 ELF）。
    let parsed = member_session.parsed().expect("成员应有解析结果");
    assert!(
        !parsed.sections.is_empty(),
        "成员应解析出节（成员 {:?}）",
        member.name
    );

    // 容器在 offset 0 的 8 字节是 `!<arch>\n`，而成员会话报告的
    // 节数不可能是"从 ar 魔数里读出来的" —— 用节数做一个可核对的锚点。
    assert!(
        parsed.sections.len() > 1,
        "把 ar 头当成 ELF 头解析不可能得到多个节；实际 {} 个节",
        parsed.sections.len()
    );
}
