//! 守卫：`droidsaw-dex` 只许当**事实层**用。
//!
//! # 为什么这条守卫必须是测试，而不是"记得别用"
//!
//! 那个库里躺着现成的反编译与推断（`emit*` / `sugar` / `r8_inversion` /
//! `optimize` / `emulator` …）。它们在**编译期**就能用，一个 `use` 就够了。
//! 而一旦用上，"事实"与"推断"在同一份输出里就再也分不开 —— 用户看到的
//! 反编译代码到底是**文件里写着的东西**，还是**库猜出来的东西**？
//! 这正是 CLAUDE.md §7 要防的事，而它只会在分发之后才暴露。
//!
//! 同一条道理也适用于"以后再说"：这个守卫在**改坏的那一刻**就失败，
//! 而不是等到有人对着反编译结果做决策的时候。
//!
//! # 检查的是我们，不是库
//!
//! 库当然可以有任何模块；我们只约束**自己的源码**怎么用它。

use std::path::{Path, PathBuf};

/// 唯一的适配层：只有它（以及它目录下的文件）可以提到这个 crate。
///
/// 有了这一条，"库只被用在一个地方"就不再是口头约定：想用库的新模块，
/// 必须先把代码写进适配层，也就必然经过下面那条禁用清单。
const ADAPTER_DIR: &str = "src/format/dex";

/// 禁止出现的模块路径片段（含 `droidsaw_dex::` 前缀，避免误伤普通词）。
///
/// 逐条的理由都归到一句话：**它们产出的是推断，不是文件里写着的事实**。
/// * `emit` / `emit_dex` —— 把 DEX 反编译成 Java 源码（M11 的"还原为高级语言"
///   是**我们自己**的里程碑，且必须逐条标注置信度，不能整段照抄别人的推断）；
/// * `sugar` —— 语法糖还原（同样是推断）；
/// * `r8_inversion` / `r8_identity` —— 从 R8 产物的特征**反推**原始名字/结构；
/// * `obfuscation_features` —— 混淆特征**判定**（判定即结论，必须由我们自己做并对
///   结果负责）；
/// * `optimize` —— 改写代码（我们不重写目标文件）；
/// * `emulator` / `ssa` / `cfg` —— 执行与数据流/控制流构建（M2 起由我们自己做，
///   并且要能逐条说清"这一步凭什么"）；
/// * `xrefs` / `structure` / `sdk_inventory` / `signatures` / `types` —— 交叉引用、
///   工程结构、SDK 清单、库指纹、类型推断（全是二级结论）。
const FORBIDDEN: &[&str] = &[
    "droidsaw_dex::emit",
    "droidsaw_dex::sugar",
    "droidsaw_dex::r8_inversion",
    "droidsaw_dex::r8_identity",
    "droidsaw_dex::obfuscation_features",
    "droidsaw_dex::optimize",
    "droidsaw_dex::emulator",
    "droidsaw_dex::ssa",
    "droidsaw_dex::cfg",
    "droidsaw_dex::xrefs",
    "droidsaw_dex::structure",
    "droidsaw_dex::sdk_inventory",
    "droidsaw_dex::signatures",
    "droidsaw_dex::types",
];

fn crate_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
}
fn rust_files(dir: &Path, out: &mut Vec<PathBuf>) {
    let Ok(entries) = std::fs::read_dir(dir) else {
        return;
    };
    for entry in entries.flatten() {
        let path = entry.path();
        if path.is_dir() {
            rust_files(&path, out);
        } else if path.extension().is_some_and(|e| e == "rs") {
            out.push(path);
        }
    }
}

/// 收集 `src/` 下所有提到 `droidsaw_dex::` 的地方。
fn files_mentioning_the_library() -> Vec<(PathBuf, String)> {
    let src = crate_root().join("src");
    let mut files = Vec::new();
    rust_files(&src, &mut files);

    // 守卫自己也要有话说：源文件一个都没扫到，说明路径算错了，
    // 那时下面的断言会"全绿"——那正是 §7 说的"绿灯说谎"。
    assert!(
        !files.is_empty(),
        "没有在 {} 下扫到任何 .rs 文件，守卫无法生效",
        src.display()
    );

    files
        .into_iter()
        .filter_map(|p| {
            let text = std::fs::read_to_string(&p).ok()?;
            text.contains("droidsaw_dex").then_some((p, text))
        })
        .collect()
}

#[test]
fn the_library_is_confined_to_one_adapter_directory() {
    let hits = files_mentioning_the_library();

    // 反过来的守卫（§7）：适配层**必须**在扫到的结果里，否则说明
    // "路径写错了 / 库被整个删掉了"，两种情况都不该让这个测试通过。
    assert!(
        !hits.is_empty(),
        "没有任何文件提到 droidsaw_dex —— 要么适配层不见了，要么这个守卫失效了"
    );

    let outside: Vec<String> = hits
        .iter()
        .filter(|(path, _)| {
            let rel = path
                .strip_prefix(crate_root())
                .unwrap_or(path)
                .to_string_lossy()
                .replace('\\', "/");
            !rel.starts_with(ADAPTER_DIR)
        })
        .map(|(path, _)| {
            path.strip_prefix(crate_root())
                .unwrap_or(path)
                .to_string_lossy()
                .replace('\\', "/")
        })
        .collect();

    assert!(
        outside.is_empty(),
        "这两处必须一起改：DEX 解析库只能被 {ADAPTER_DIR}/ 下的文件引用，\
         但这些文件也引用了它：{outside:?}\n\
         理由：换库、升级、或收紧「只用事实层」这条线时，改动面必须局限在适配层。"
    );
}

/// 拒绝库的 smali 渲染器。**理由与上面那条不同**，所以清单与措辞都分开：
/// 它不是"推断"，而是"拿不到就写占位符"。
///
/// 实测（`droidsaw-dex` 2.0 的 `src/smali.rs`）：类型/字段引用取不到时写 `"?"`，
/// 字符串引用取不到时写 `"<invalid>"`。CLAUDE.md §7 明令禁止用默认值冒充结果 ——
/// 读的人分不出"文件里就是 `?`"和"我们没解析出来"；我们的渲染路径在解析不出来时
/// 保留可数的池索引，并把失败数交回调用方。
///
/// 另一层代价：`fmt_instruction` 对每条指令返回一个 `String`（§4 的 SoA 取向），
/// 且签名带 `&DexFile`，会把库的池类型带进渲染调用面。
const FORBIDDEN_OUTPUT: &[&str] = &["droidsaw_dex::smali"];

#[test]
fn the_libraries_placeholder_output_is_not_used() {
    let hits = files_mentioning_the_library();
    let mut violations = Vec::new();

    for (path, text) in &hits {
        let rel = path
            .strip_prefix(crate_root())
            .unwrap_or(path)
            .to_string_lossy()
            .replace('\\', "/");
        for needle in FORBIDDEN_OUTPUT {
            if text.contains(needle) {
                violations.push(format!("{rel} 引用了 {needle}"));
            }
        }
    }

    assert!(
        violations.is_empty(),
        "不许把库的渲染器接到用户输出上，下列引用越界了：\n  {}\n\
         理由不是「库做不到」，而是它在解析失败时静默写问号 / <invalid> 之类的\
         占位符（CLAUDE.md §7：拿不到就说拿不到，不许用默认值冒充结果）。\
         我们自己的 `format::dex::view` 渲染路径在解析不出符号时保留可数的池索引，\
         并把失败数交回调用方 —— 要显示符号就在那里做。见 ADR-0020 的 2026-10-15 更正。",
        violations.join("\n  ")
    );
}

#[test]
fn the_inference_and_rewriting_modules_are_never_referenced() {
    let hits = files_mentioning_the_library();
    let mut violations = Vec::new();

    for (path, text) in &hits {
        let rel = path
            .strip_prefix(crate_root())
            .unwrap_or(path)
            .to_string_lossy()
            .replace('\\', "/");
        for needle in FORBIDDEN {
            if text.contains(needle) {
                violations.push(format!("{rel} 引用了 {needle}"));
            }
        }
    }

    assert!(
        violations.is_empty(),
        "DEX 只许当事实层用，下列引用越界了：\n  {}\n\
         这些模块产出的是**推断**（反编译/还原/改写/交叉引用/类型推断），\
         接进来会让「文件里写着什么」和「库猜的是什么」在同一份输出里分不开，\
         违反 CLAUDE.md §7。要在 M11 后续里程碑里做这些事，得由我们自己实现，\
         并把每一条结论的置信度与依据写出来。",
        violations.join("\n  ")
    );
}

/// 自检：禁用清单不能是空的，而且每条都必须真的能命中 —— 否则清单写错了前缀
/// 就会变成一条恒真的绿灯（"没匹配到"与"没有违规"长得一模一样，CLAUDE.md §7）。
#[test]
fn the_forbidden_lists_actually_match() {
    for (name, list) in [
        ("FORBIDDEN", FORBIDDEN),
        ("FORBIDDEN_OUTPUT", FORBIDDEN_OUTPUT),
    ] {
        assert!(!list.is_empty(), "{name} 是空的，守卫等于没写");
        for needle in list {
            assert!(
                needle.starts_with("droidsaw_dex::"),
                "{name} 里的 {needle} 没有 crate 前缀，容易误伤普通词"
            );
            let synthetic = format!("use {needle}::whatever;");
            assert!(
                synthetic.contains(needle),
                "{name} 里的 {needle} 匹配不到带这个前缀的代码"
            );
        }
    }
}

#[test]
fn the_adapter_really_does_use_the_library_facts() {
    // 防止"把库删掉换成本地实现，守卫却还绿着"：适配层必须实际用到
    // 事实层的那几个模块。少了这个断言，上面两条守卫在"库被搬走"之后
    // 会变成永真的空检查。
    let adapter = crate_root().join(ADAPTER_DIR).join("mod.rs");
    let text = std::fs::read_to_string(&adapter)
        .unwrap_or_else(|e| panic!("读不到适配层 {}: {e}", adapter.display()));

    for fact_module in ["droidsaw_dex::decode", "droidsaw_dex::ids"] {
        assert!(
            text.contains(fact_module),
            "适配层没有引用 {fact_module} —— 要么改用了别的事实来源（请同步更新这个守卫），\
             要么解析其实没在做"
        );
    }
}
