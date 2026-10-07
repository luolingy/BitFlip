//! 导入桩（import thunk）来源的回归门禁。
//!
//! # 为什么这条来源需要单独的测试
//!
//! 它是 M3 期间为"静态链接的 mingw 程序覆盖率停在 92.21%"这个问题加的：
//! 那些程序在 `.text` 里留着一批一指令函数（`jmp *__imp_xxx(%rip)` +
//! `nop` 对齐），既没有符号（已 strip）也不会被 `call`（调用点直接走 IAT），
//! 所以别的来源一个都碰不到它们。
//!
//! 这条来源有一个危险的失效模式：**它的判据是字节级的**，改错一个字节
//! （比如把填充判定挪个位置）就会让识别结果**静默变成 0 个** —— 不报错、
//! 不 panic，只是覆盖率掉回去，而当时没有任何测试会红。所以这里断言的是
//! "真的认出来了多少个"，不是"代码路径存在"。
//!
//! # 另一件要钉住的事：这条判据不能跨架构乱用
//!
//! 判据里的填充字节（`0x90`/`0xCC`/`66 0F 1F`）与"下一条桩的形状"
//! （`ff 25`）都是 x86 的知识。同样的字节在 AArch64/MIPS/RISC-V 上是
//! **别的指令**，拿它们去匹配会让那些目标上凭空出现一批"导入桩"。
//! 这一点原本没有测试守，现在有了。

use std::path::PathBuf;

use bitflip_core::{OpenOptions, Session, TargetAnalysis};

fn fixture(name: &str) -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("..")
        .join("..")
        .join("tests")
        .join("fixtures")
        .join("generated")
        .join(name)
}

fn analyze(name: &str) -> std::sync::Arc<TargetAnalysis> {
    let path = fixture(name);
    assert!(path.exists(), "缺少 fixture：{}", path.display());
    let session = Session::open(&path, OpenOptions::default()).expect("打开目标");
    let job = session.detached_job();
    session.analysis(&job).expect("构建分析结论")
}

fn import_thunks(analysis: &TargetAnalysis) -> usize {
    analysis
        .functions()
        .iter()
        .filter(|f| f.source == "import-thunk")
        .count()
}

#[test]
fn a_static_mingw_binary_really_yields_import_thunks() {
    let analysis = analyze("m3-mingw-static.exe");
    let count = import_thunks(&analysis);

    // 当前实测值 5（`notes` 里的数字与函数数一致）。这里断言的是**下限**
    // 而不是精确值：将来收紧判据导致少认一两个属于判断问题，不该让测试
    // 变红；但归零或接近归零一定是判据坏了 —— 而这正是它当年踩过的坑
    // （"最初 12 个桩一个都没认出来"）。
    assert!(
        count >= 3,
        "静态 mingw 程序里应当识别出成批的导入桩，实际 {count} 个 —— \
         判据可能已经静默失效（这条来源当年是为了把覆盖率从 92.21% 抬到 95% 才加的）"
    );

    assert!(
        analysis.notes().iter().any(|n| n.contains("导入桩")),
        "识别到桩时必须在 notes 里说明，否则用户不知道这批函数从哪来，实际：{:?}",
        analysis.notes()
    );
}

/// 反过来的门禁：这些桩的来源必须是 `import-thunk`，而且**没有名字**。
///
/// 桩的名字来自"经过它的槽位属于哪个导入"（那是 PLT 桩那条路径的事）。
/// mingw 的 IAT 桩走的是另一条路径，这里不许顺手编个名字 ——
/// 编出来就是拿假名冒充识别结果。
#[test]
fn mingw_thunks_are_reported_as_such_and_left_unnamed() {
    let analysis = analyze("m3-mingw-static.exe");
    for function in analysis.functions() {
        if function.source != "import-thunk" {
            continue;
        }
        if function.name.is_empty() {
            assert!(!function.named, "没有名字就不该标成 named");
        }
        assert!(
            !function.name.ends_with("@plt"),
            "`@plt` 名字只来自 PLT 桩那条路径（要有重定位依据），\
             实际出现：{}",
            function.name
        );
    }
}

/// 非 x86 目标上不许出现按 x86 字节形状认出来的"导入桩"。
///
/// AArch64 的导入要走 `adrp`/`ldr`/`br` 三连，与 `ff 25` 毫无关系。
/// 拿 x86 的字节去匹配 arm 目标，会把普通代码认成桩 —— 凭空造出一批函数，
/// 正是 CLAUDE.md §7 禁止的"让界面看起来完整"。
#[test]
fn non_x86_targets_do_not_gain_x86_shaped_thunks() {
    for name in ["elf-aarch64.exe", "elf-armv7.o", "elf-riscv64.o"] {
        let path = fixture(name);
        if !path.exists() {
            continue; // fixture 未生成时跳过，不假装通过
        }
        let analysis = analyze(name);
        let count = import_thunks(&analysis);
        assert_eq!(
            count, 0,
            "{name} 上不该出现 x86 形状的导入桩（判据是按 x86 字节写的），实际 {count} 个"
        );
    }
}
