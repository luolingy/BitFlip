//! PE / ELF 的调用图必须与本片（M12 第五片：导入边）之前**逐条**相同。
//!
//! # 为什么要有这个文件
//!
//! 这一片给调用图加了"外部边"：目标落在导入槽位 / 导入跳板桩上的调用会被标成
//! `external = true` 并带上导入名。它会跑在**解析出来的对象**上，而 PE 解析器
//! 同样填 `iat_slot`（`m3-mingw-static.exe` 46 条导入全部有槽位）—— 也就是说，
//! 只要那个格式闸门被"顺手"放宽一格，PE 的调用图就会多出一批外部边。
//!
//! 所以"PE/ELF 行为不变"不能靠嘴说：这里的黄金文件是**本片代码之前**跑出来的
//! 那份（边、计数逐行比过），这里每次都逐行比对。桩节闸门之外还有第二道
//! 证明：文件末尾的 PE 用例断言这份样本**确实**有 46 条带槽位的导入，
//! 而且没有任何一条边的目标等于某个槽位 —— 有数据、没触发。
//!
//! # 黄金文件里为什么会有中文注释行
//!
//! `note` 行是从 `CallGraph` 的 notes 原样抄下来的（中文）。黄金文件由 Rust
//! 写文件生成（UTF-8）；早先用 PowerShell `Set-Content` 写过一版，注释行变成了
//! 乱码 —— 这正是 CLAUDE.md §6.1 的那类坑，记在这里免得下次重犯。

use std::path::PathBuf;

use bitflip_core::{OpenOptions, Session};

/// 参与回归的样本：一个 PE（有 46 条带槽导入）、两个 ELF（后者含 `.plt` 桩边）。
const FIXTURES: [&str; 3] = ["m3-mingw-static.exe", "libsample.so", "elf-ehframe.exe"];

fn fixture(name: &str) -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../tests/fixtures/generated")
        .join(name)
}

fn golden_path(name: &str) -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("tests/golden")
        .join(format!("callgraph_{name}.txt"))
}

/// 按黄金文件的格式把一张调用图渲染成文本。
///
/// 格式故意保持"一行一个事实"：出差异时能直接看出是哪条边变了，
/// 而不是"某个 17 KB 的 JSON 不一样"。
fn render(name: &str, response: &bitflip_core::CallGraphWire) -> String {
    let mut out = String::new();
    out.push_str(&format!("fixture {name}\n"));
    out.push_str(&format!("nodes {}\n", response.summary.nodes));
    out.push_str(&format!("edges {}\n", response.summary.edges));
    out.push_str(&format!(
        "unresolved_indirect {}\n",
        response.summary.unresolved_indirect
    ));
    out.push_str(&format!(
        "outside_targets {}\n",
        response.summary.outside_targets
    ));
    out.push_str(&format!("roots {}\n", response.summary.roots));
    out.push_str(&format!("components {}\n", response.summary.components));
    out.push_str(&format!(
        "largest_component {}\n",
        response.summary.largest_component
    ));
    out.push_str(&format!("wire_edges {}\n", response.edges.len()));
    out.push_str(&format!("unresolved {}\n", response.unresolved.len()));
    out.push_str(&format!(
        "external_edges {}\n",
        response.edges.iter().filter(|e| e.external).count()
    ));
    for e in &response.edges {
        out.push_str(&format!(
            "edge {} {} tail={} external={}\n",
            e.caller, e.callee, e.tail, e.external
        ));
    }
    for e in response.edges.iter().filter(|e| e.external) {
        out.push_str(&format!(
            "import {} {} name={}\n",
            e.caller,
            e.callee,
            e.import_name.as_deref().unwrap_or("-")
        ));
    }
    for u in &response.unresolved {
        out.push_str(&format!("unresolved_edge {} {}\n", u.caller, u.insn));
    }
    for note in &response.notes {
        out.push_str(&format!("note {}\n", note.replace('\n', " ")));
    }
    out
}

#[test]
fn pe_and_elf_call_graphs_are_unchanged() {
    for name in FIXTURES {
        let path = fixture(name);
        assert!(
            path.is_file(),
            "缺少 fixture：{} —— 跳过会让这道回归闸门假装绿（CLAUDE.md §7）",
            path.display()
        );
        let session = Session::open(&path, OpenOptions::default()).expect("open");
        let job = session.detached_job();
        let analysis = session.analysis(&job).expect("analysis");
        let response = analysis.call_graph();

        let actual = render(name, response);
        let expected = std::fs::read_to_string(golden_path(name)).expect("读黄金文件");

        // 逐行比：出差异时直接指出第几行、两边各是什么。
        let actual_lines: Vec<&str> = actual.lines().collect();
        let expected_lines: Vec<&str> = expected.lines().collect();
        let mut mismatch = None;
        for (index, (got, want)) in actual_lines.iter().zip(expected_lines.iter()).enumerate() {
            if got != want {
                mismatch = Some((index + 1, *want, *got));
                break;
            }
        }
        if mismatch.is_none() && actual_lines.len() != expected_lines.len() {
            mismatch = Some((
                actual_lines.len().min(expected_lines.len()) + 1,
                expected_lines
                    .get(actual_lines.len())
                    .copied()
                    .unwrap_or("<缺行>"),
                actual_lines
                    .get(expected_lines.len())
                    .copied()
                    .unwrap_or("<多行>"),
            ));
        }
        if let Some((line, want, got)) = mismatch {
            panic!(
                "{name} 的调用图与黄金文件不一致（第 {line} 行）\n  期望：{want}\n  实际：{got}\n\
                 这份黄金文件是加入导入边之前的输出；PE/ELF 的行为必须原样保持。\n\
                 若确实是**有意**改动，请在 CHANGELOG 里说明并重新生成黄金文件。"
            );
        }

        // 结构上再钉一遍：这个格式不该出现外部边。
        assert!(
            response.edges.iter().all(|e| !e.external),
            "{name}: 非 Mach-O 不该产生外部边"
        );
        assert!(
            response
                .notes
                .iter()
                .all(|n| !n.contains("条边指向导入符号")),
            "{name}: 非 Mach-O 的 notes 里不该出现导入边的账目"
        );
    }
}

/// 证明"闸门是有数据可用的"：PE 样本确实有 46 条带槽位的导入，
/// 但调用图里没有任何一条边的目标等于槽位 —— 所以上面那条"0 条外部边"
/// 是"有数据、没触发"，不是"没数据所以碰巧没变"。
#[test]
fn the_pe_fixture_has_slotted_imports_and_none_of_them_became_an_edge() {
    let path = fixture("m3-mingw-static.exe");
    assert!(path.is_file(), "缺少 fixture：{}", path.display());
    let session = Session::open(&path, OpenOptions::default()).expect("open");
    let object = session.object().expect("object");
    assert!(
        !object.imports.is_empty(),
        "这份 PE 应当有导入表；空表会让这条证明失效"
    );
    let slotted: Vec<u64> = object.imports.iter().filter_map(|i| i.iat_slot).collect();
    assert_eq!(
        slotted.len(),
        object.imports.len(),
        "样本里的导入应当全部带槽位（实测 46/46）"
    );

    let job = session.detached_job();
    let analysis = session.analysis(&job).expect("analysis");
    let response = analysis.call_graph();
    let hit = response.edges.iter().find(|e| {
        bitflip_core::parse_address(&e.callee).is_some_and(|addr| slotted.contains(&addr))
    });
    assert!(
        hit.is_none(),
        "这 46 个槽位一个都没被调用：{hit:#?}（若哪天有了，PE 就会开始出外部边）"
    );
}

/// ELF 样本的导入表是空的（本仓库的 ELF 夹具没链动态库），
/// 所以它连"有数据"这条都不成立 —— 这一点也要写下来，别让人以为
/// ELF 是被更严格地验证过。
#[test]
fn the_elf_fixtures_have_no_import_table_at_all() {
    for name in ["libsample.so", "elf-ehframe.exe"] {
        let session = Session::open(fixture(name), OpenOptions::default()).expect("open");
        let object = session.object().expect("object");
        assert!(
            object.imports.is_empty(),
            "{name}: 导入表为空才是这份夹具的实情（`.plt` 桩靠重定位表命名）"
        );
    }
}
