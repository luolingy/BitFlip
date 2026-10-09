//! M8 反修饰的端到端回归：符号表里的 MSVC 修饰名 → 界面显示可读名 + 原始名留在 `aliases`。
//!
//! 这条测试补的是一个具体的洞：反修饰函数本身有单测、接线也有单测，但没有任何一条
//! **真实**的 MSVC 修饰名流过整条链路（现有 fixture 全是 C 或 Itanium）。
//!
//! fixture 由 `scripts/gen-cxx-fixture.ps1` 生成（clang-cl + lld-link）。缺失时**响亮失败**
//! 而不是跳过 —— 按 CLAUDE.md §7：静默跳过会让这条测试在反修饰坏掉的情况下依然"通过"，
//! 那它就什么也没守住。

use std::path::PathBuf;

use bitflip_core::{OpenOptions, Session};

/// dumpbin /symbols 给出的原话（真值，不是手写的）。
const DECORATED: &str = "?bar@Widget@@QEAAHH@Z";

fn fixture(name: &str) -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("..")
        .join("..")
        .join("tests")
        .join("fixtures")
        .join("generated")
        .join(name)
}

#[test]
fn a_decorated_name_shows_readable_and_keeps_the_raw_name_as_an_alias() {
    let path = fixture("m8-cxx.obj");
    assert!(
        path.exists(),
        "缺少 fixture {}；先跑 scripts/gen-cxx-fixture.ps1（需要 clang-cl 与 lld-link）",
        path.display()
    );

    let session = Session::open(&path, OpenOptions::default()).expect("打开 C++ 样例");
    let analysis = session.analysis(&session.detached_job()).expect("分析");

    let mut seen = Vec::new();
    let mut found = false;
    for f in analysis.functions() {
        seen.push(f.name.clone());
        // 显示名必须是可读形式（LLVM 风格：不带 undname 的 `__ptr64`）。
        if !f.name.contains("Widget::bar") {
            continue;
        }
        // 而且原始修饰名必须作为别名留着 —— 签名库/脚本/地址表都按它匹配。
        let raw: Vec<&str> = f.aliases.iter().map(|a| a.name.as_str()).collect();
        assert!(
            raw.contains(&DECORATED),
            "显示名反修饰成了 `{}`，但别名里没有原始名 `{DECORATED}`：{raw:?}",
            f.name
        );
        found = true;
    }

    assert!(
        found,
        "没有任何函数显示成可读的 `Widget::bar`；看到的名字：{seen:?}"
    );
}

/// 反修饰不许碰不是 MSVC 修饰的名字（`extern "C"` 的符号必须原样）。
#[test]
fn a_plain_c_name_is_left_alone() {
    let path = fixture("m8-cxx.obj");
    assert!(
        path.exists(),
        "缺少 fixture {}；先跑 scripts/gen-cxx-fixture.ps1",
        path.display()
    );

    let session = Session::open(&path, OpenOptions::default()).expect("打开 C++ 样例");
    let analysis = session.analysis(&session.detached_job()).expect("分析");

    let names: Vec<String> = analysis
        .functions()
        .iter()
        .map(|f| f.name.clone())
        .collect();
    // 可重定位对象里所有符号都是节内偏移：f_cxx_entry 与成员函数同落在偏移 0，
    // 因此它出现在**别名**里而不是单独一个函数 —— 实测如此，这里照实测断言。
    let aliases: Vec<String> = analysis
        .functions()
        .iter()
        .flat_map(|f| f.aliases.iter().map(|a| a.name.clone()))
        .collect();
    assert!(
        aliases.iter().any(|n| n == "bf_cxx_entry"),
        "`extern \"C\"` 的入口应当原样保留（作为别名或函数名）：{names:?}"
    );
    assert!(
        !names.iter().any(|n| n.starts_with('?')),
        "界面上不该出现任何原始修饰名（都应被反修饰或原样保留）：{names:?}"
    );
}
