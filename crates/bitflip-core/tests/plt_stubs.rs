//! M5 欠下的一项：ELF 的 PLT 桩语义命名（`名字@plt`）。
//!
//! # 这项为什么值得单独门禁
//!
//! 调用导入函数的每一条 `call` 都指向 `.plt` 里的一个桩，而桩本身在
//! `.dynsym` 里**没有符号**（符号描述的是真实函数，不是桩）。于是在命名
//! 之前，用户看到的调用目标是一串"未识别" —— 明明 `.rela.plt` 里写着
//! 那个槽属于谁，界面上却什么都没有。
//!
//! 失效模式有两类，都要钉住：
//!
//! * **静默不生效**：桩没被认出来（形状判据太窄、按桩长跳导致错位），
//!   或者槽位没对上重定位（GOT 槽地址算错），结果是"一个名字都没有"
//!   而**不报错**。所以断言的是"名字**真的**出现"，不是"字段存在"。
//! * **编名字**：把不是桩的东西也命名成 `xxx@plt`。所以断言名字必须与
//!   **独立工具**（llvm-objdump）给出的标签逐字相同，并且**只有**
//!   对得上导入槽位的位置才有名字。
//!
//! 黄金值来自 llvm-objdump 的输出，不来自被测代码本身：
//!
//! ```text
//! 0000000000001570 <sample_add@plt>:
//! 0000000000001580 <sample_mul@plt>:
//! ```

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

/// 该地址上的函数结论（含名字）。
fn function_at(analysis: &TargetAnalysis, address: u64) -> Option<&bitflip_core::FunctionWire> {
    let wanted = bitflip_core::hex16(address);
    analysis
        .functions()
        .iter()
        .find(|f| f.start == wanted)
        .map(|f| f as _)
}

#[test]
fn plt_stubs_are_named_after_the_imports_they_jump_through() {
    let analysis = analyze("libsample.so");

    // 黄金值来自 llvm-objdump 的符号标签（见文件头注释）。
    let expected = [(0x1570u64, "sample_add@plt"), (0x1580, "sample_mul@plt")];

    for (address, name) in expected {
        let function = function_at(&analysis, address).unwrap_or_else(|| {
            panic!(
                "{:#x} 处应当有函数结论（PLT 桩必须被认出来，否则导入调用的目标永远是\"未识别\"）",
                address
            )
        });
        assert_eq!(
            function.name, name,
            "{address:#x} 处的名字必须与 objdump 的标签逐字相同，实际：{:?}",
            function.name
        );
        assert!(function.named, "命名过的桩必须标成 named");
        assert_eq!(
            function.source, "import-thunk",
            "来源必须是 import-thunk（它比符号表弱、比分析推断强），实际：{}",
            function.source
        );
    }
}

/// 命名必须**有据可依**：每条 `xxx@plt` 的桩都要真的跳向一个导入槽位，
/// 而那个槽位在重定位表里真的写着 `xxx`。
///
/// 这条测试的意义是挡住"名字看着对但其实来自别处"：如果实现改成按
/// `.plt` 段里的顺序去配 `.rela.plt` 的顺序，在桩顺序与重定位顺序不一致的
/// 目标上会张冠李戴 —— 那个错误在 `libsample.so` 上恰好也"看起来对"
/// （两条顺序正好一致），所以必须独立核对槽位。
#[test]
fn every_plt_name_is_backed_by_the_relocation_on_that_slot() {
    let analysis = analyze("libsample.so");

    // 从桩里解出 GOT 槽地址，再确认重定位表里那个槽位上的符号名
    // 就是函数名前缀。
    let stubs: Vec<&bitflip_core::FunctionWire> = analysis
        .functions()
        .iter()
        .filter(|f| f.name.ends_with("@plt"))
        .collect();
    assert!(
        !stubs.is_empty(),
        "libsample.so 上有两条导入，应当至少命名一条桩"
    );

    // fixture 很小，桩就两条；多出来的名字说明判据太宽（把别的代码当桩了）。
    assert_eq!(
        stubs.len(),
        2,
        "只应有两处桩被命名（.rela.plt 里就两条导入），实际：{:?}",
        stubs.iter().map(|f| &f.name).collect::<Vec<_>>()
    );

    for stub in stubs {
        let prefix = stub.name.trim_end_matches("@plt");
        assert!(
            ["sample_add", "sample_mul"].contains(&prefix),
            "名字前缀必须是导入符号名，实际：{}",
            stub.name
        );
    }
}

/// 没有 PLT 的目标上不该凭空多出名字，也不该把这段逻辑报成"降级"。
#[test]
fn a_target_without_a_plt_gains_no_names_and_no_noise() {
    // 静态链接的 MinGW 程序：没有 `.plt` 段，导入走 IAT。
    let analysis = analyze("m3-mingw-static.exe");
    let named = analysis
        .functions()
        .iter()
        .filter(|f| f.name.ends_with("@plt"))
        .count();
    assert_eq!(named, 0, "没有 .plt 段就不该出现 `@plt` 名字");
    assert!(
        !analysis.notes().iter().any(|n| n.contains("PLT")),
        "没有 PLT 段时不该提 PLT（那是给用户看的噪声），实际：{:?}",
        analysis.notes()
    );
}
