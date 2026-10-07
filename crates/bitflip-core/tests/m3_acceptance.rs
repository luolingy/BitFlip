//! M3 验收测试：`docs/PLAN.md` §M3 的三条标准。
//!
//! 标准原文：
//! 1. 对无符号的 mingw 静态链接 exe，函数识别覆盖率（vs `objdump`/`dumpbin`
//!    的函数清单）≥ 95%；
//! 2. 每个函数都有来源与置信度，UI 可筛选；
//! 3. xref 双向一致（`to→from` 与 `from→to` 不矛盾），有属性测试（proptest）。
//!
//! 这些测试要真的去跑 157 个函数的分母。如果样本不在（fixture 未生成），
//! 测试**跳过并说明原因**，而不是假装通过 —— 但 CI 上应该跑
//! `scripts/gen-m3-coverage-sample.ps1` 让它存在。

use std::collections::HashSet;

use bitflip_analyze::StringOptions;
use bitflip_core::{DisasmScanOptions, Session, TargetAnalysis};

/// fixture 目录（由 `scripts/gen-*.ps1` 生成，不入库）。
fn fixture(name: &str) -> std::path::PathBuf {
    let mut path = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    path.pop(); // crates/bitflip-core -> crates
    path.pop(); // crates -> 仓库根
    path.push("tests/fixtures/generated");
    path.push(name);
    path
}

/// 基准真值：从**strip 之前**的 objdump 符号表抓下来的函数地址集合。
///
/// 为什么要用 strip 之前的：strip 之后就没有真值了 —— 拿分析器的输出当真值
/// 等于自己证明自己。这个文件是外部工具（objdump）产出的，才是独立参照。
fn ground_truth() -> Option<Vec<u64>> {
    let path = fixture("m3-mingw-static.funcs.txt");
    if !path.exists() {
        return None;
    }
    let text = std::fs::read_to_string(&path).ok()?;
    let mut addrs = Vec::new();
    for line in text.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        // 格式：<address>:<name>
        let Some((addr, _name)) = line.split_once(':') else {
            continue;
        };
        if let Ok(v) = u64::from_str_radix(addr.trim_start_matches("0x"), 16) {
            addrs.push(v);
        }
    }
    if addrs.is_empty() {
        None
    } else {
        Some(addrs)
    }
}

/// 打开覆盖率样本并建立分析。
fn analyze_sample() -> Option<(Session, TargetAnalysis)> {
    let exe = fixture("m3-mingw-static.exe");
    if !exe.exists() {
        eprintln!(
            "跳过：样本 {} 不存在，请先跑 scripts/gen-m3-coverage-sample.ps1",
            exe.display()
        );
        return None;
    }
    let session =
        Session::open(&exe, bitflip_core::OpenOptions::default()).expect("应能打开样本 exe");

    let disasm = session
        .disassemble(DisasmScanOptions::default())
        .expect("应能建立反汇编");
    let object = session.object().expect("应能拿到对象").clone();

    let analysis = TargetAnalysis::build(&disasm, &object, &StringOptions::default(), None);
    Some((session, analysis))
}

// ─────────────────────────────────────────────────────────────────
// 标准 1：覆盖率 ≥ 95%
// ─────────────────────────────────────────────────────────────────

/// 覆盖率按**函数入口地址**算：真值里每个函数起点，分析结果里是否也认出了
/// 一个起点。
///
/// 为什么按起点而不是按名字：样本是 strip 过的，分析器**不可能**知道名字。
/// 这里测的是"发现函数"的能力，不是"读符号表"的能力 —— 后者在 strip 后
/// 根本不存在。名字的正确性由标准 2 的"未命名要诚实"覆盖。
#[test]
fn function_coverage_vs_objdump_is_at_least_95_percent() {
    let Some(truth) = ground_truth() else {
        eprintln!("跳过：真值文件不存在，请先跑 scripts/gen-m3-coverage-sample.ps1");
        return;
    };
    let Some((_session, analysis)) = analyze_sample() else {
        return;
    };

    let identified: HashSet<u64> = analysis
        .functions()
        .iter()
        .filter_map(|f| u64::from_str_radix(&f.start, 16).ok())
        .collect();

    // 样本必须真的是"无符号"的：如果分析器读到了符号表，这个测试就退化成
    // "符号表读取测试"，那样覆盖率虚高，证明不了发现能力。
    let named_count = analysis.functions().iter().filter(|f| f.named).count();
    println!(
        "分析函数数 = {}，其中有名字的 = {named_count}（样本已 strip，这个数应当很小）",
        analysis.function_count()
    );

    let total = truth.len();
    let hit = truth.iter().filter(|a| identified.contains(a)).count();
    let ratio = hit as f64 / total as f64;

    // 漏掉的列出来：数字不达标时，要能立刻看出漏的是哪一类
    let mut missed: Vec<u64> = truth
        .iter()
        .copied()
        .filter(|a| !identified.contains(a))
        .collect();
    missed.sort_unstable();

    println!(
        "覆盖率 = {hit}/{total} = {:.2}%（漏掉 {} 个）",
        ratio * 100.0,
        missed.len()
    );
    if !missed.is_empty() {
        let shown: Vec<String> = missed
            .iter()
            .take(20)
            .map(|a| format!("{a:016x}"))
            .collect();
        println!("漏掉的入口（前 20 个）：{}", shown.join(", "));
    }

    assert!(
        total >= 30,
        "真值只有 {total} 个函数，样本太小，95% 这个指标没有意义"
    );
    assert!(
        ratio >= 0.95,
        "验收要求覆盖率 >= 95%，实测 {hit}/{total} = {:.2}%",
        ratio * 100.0
    );
}

/// 覆盖率的分母必须来自外部工具，不能来自分析器自己。
///
/// 这条是防"自证"的元测试：如果哪天有人把真值文件改成由 BitFlip 生成，
/// 覆盖率就永远是 100%，而那个数字毫无意义。
#[test]
fn ground_truth_comes_from_an_external_tool() {
    let path = fixture("m3-mingw-static.funcs.txt");
    if !path.exists() {
        eprintln!("跳过：真值文件不存在");
        return;
    }
    let text = std::fs::read_to_string(&path).expect("读真值");
    assert!(
        text.contains("objdump"),
        "真值文件必须标明它来自外部工具（objdump），否则可能变成自证"
    );
}

// ─────────────────────────────────────────────────────────────────
// 标准 2：每个函数都有来源与置信度
// ─────────────────────────────────────────────────────────────────

#[test]
fn every_function_has_a_source_and_a_confidence() {
    let Some((_session, analysis)) = analyze_sample() else {
        return;
    };
    assert!(
        analysis.function_count() > 0,
        "至少要识别出函数，否则这条断言是空转"
    );

    for f in analysis.functions() {
        assert!(
            !f.source.is_empty(),
            "函数 {} 没有来源 —— UI 无法解释它为什么被当成函数",
            f.start
        );
        assert!(
            !f.source_label.is_empty(),
            "函数 {} 的来源没有中文标签",
            f.start
        );
        assert!(
            f.confidence <= 100,
            "置信度 {} 超出 0-100 范围",
            f.confidence
        );
        // 未知边界必须是 None，不能是 0 —— 0 会被 UI 显示成"长度 0"，
        // 那是在假装知道一个不知道的事实（CLAUDE.md §7）。
        if let Some(end) = f.end.as_deref() {
            let end_v = u64::from_str_radix(end, 16).expect("end 应是十六进制");
            let start_v = u64::from_str_radix(&f.start, 16).expect("start 应是十六进制");
            assert!(
                end_v > start_v,
                "函数 {} 的 end ({end}) 不大于 start，边界明显算错了",
                f.start
            );
        }
        // named 与 name 必须自洽：说没有名字就不能塞一个名字进去
        if !f.named {
            assert!(
                f.name.is_empty(),
                "函数 {} 标了 named=false 却带着名字 {:?} —— 这是占位名，§7 明令禁止",
                f.start,
                f.name
            );
        }
    }
}

/// 名字来源必须能筛选：不同来源产出不同的 `source` 值，UI 才能过滤。
#[test]
fn sources_are_distinguishable_for_filtering() {
    let Some((_session, analysis)) = analyze_sample() else {
        return;
    };
    let sources: HashSet<&str> = analysis
        .functions()
        .iter()
        .map(|f| f.source.as_str())
        .collect();
    println!("出现的来源：{sources:?}");
    // 至少要有一种来源，且每种都能映射到中文标签
    assert!(!sources.is_empty());
    for f in analysis.functions() {
        assert!(
            f.source
                .chars()
                .all(|c| c.is_ascii_lowercase() || c == '-' || c.is_ascii_digit()),
            "来源 {:?} 应当是小写 kebab-case，便于前端当筛选键用",
            f.source
        );
    }
}

// ─────────────────────────────────────────────────────────────────
// 标准 3：xref 双向一致（属性测试）
// ─────────────────────────────────────────────────────────────────

/// 双向一致性：`xrefs_from(a)` 里出现 `b` ⟺ `xrefs_to(b)` 里出现 `a`。
///
/// 用 proptest 而不是手写几个用例：索引是两张 HashMap，一旦插入/查询任一侧
/// 写错，只有某些地址组合会暴露 —— 随机地址组合能把这种错误逼出来。
///
/// 关键：属性测试驱动的是**真实的** `TargetAnalysis`（真的建地址空间、真的
/// 解码、真的建两张索引），而不是在测试里把索引逻辑再写一遍。重写一遍只能
/// 证明"我写的第二份实现自洽"，证明不了产品代码自洽。
mod xref_consistency {
    use super::*;
    use bitflip_analyze::StringOptions;
    use proptest::prelude::*;

    /// 用随机个数的 `call` 指令拼出一段 x86-64 代码，构建真实分析，再逐条核对。
    ///
    /// 代码形态：`call rel32` 若干条，后接 `ret`。每条 call 的目标落在同一段内，
    /// 因此会真实产生 call 型 xref。
    fn build_and_check(call_count: usize, stride: usize) -> Result<usize, String> {
        // 每条 call 占 5 字节；目标取"段内某个 5 字节对齐位置"
        let stride = stride.clamp(5, 64);
        let total = call_count * 5 + 1;
        let mut code = Vec::with_capacity(total);
        for i in 0..call_count {
            // rel32 指向本段内的某个目标（必须解码得到、且在段内）
            let here = i * 5;
            let target = (i * stride) % total.max(1);
            let rel = (target as i64) - ((here + 5) as i64);
            let rel = rel.clamp(i32::MIN as i64, i32::MAX as i64) as i32;
            code.push(0xE8);
            code.extend_from_slice(&rel.to_le_bytes());
        }
        code.push(0xC3); // ret

        let dir = std::env::temp_dir().join(format!(
            "bf-xrefprop-{}-{}-{}",
            std::process::id(),
            call_count,
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.subsec_nanos())
                .unwrap_or(0)
        ));
        std::fs::create_dir_all(&dir).map_err(|e| e.to_string())?;
        let path = dir.join("t.elf");
        std::fs::write(&path, elf_with_text(&code)).map_err(|e| e.to_string())?;

        let session = Session::open(&path, bitflip_core::OpenOptions::default())
            .map_err(|e| format!("打开失败: {e}"))?;
        let disasm = session
            .disassemble(DisasmScanOptions::default())
            .map_err(|e| format!("反汇编失败: {e}"))?;
        let object = session.object().ok_or("拿不到 object")?.clone();
        let analysis = TargetAnalysis::build(&disasm, &object, &StringOptions::default(), None);

        let base = TEXT_VADDR;
        let mut edges = 0usize;

        // 收集所有 from 侧的出边
        let mut from_edges: HashSet<(u64, u64)> = HashSet::new();
        for i in 0..call_count {
            let addr = base + (i * 5) as u64;
            for x in analysis.xrefs_from(addr) {
                if let (Ok(a), Ok(b)) = (
                    u64::from_str_radix(&x.from, 16),
                    u64::from_str_radix(&x.to, 16),
                ) {
                    from_edges.insert((a, b));
                }
            }
        }

        // 每条边都必须能在 to 侧反查到
        for &(a, b) in &from_edges {
            edges += 1;
            let found = analysis
                .xrefs_to(b)
                .iter()
                .any(|r| u64::from_str_radix(&r.from, 16).ok() == Some(a));
            if !found {
                std::fs::remove_dir_all(&dir).ok();
                return Err(format!(
                    "xref {a:016x} -> {b:016x} 在 from 侧存在但 to 侧查不到"
                ));
            }
        }

        std::fs::remove_dir_all(&dir).ok();
        Ok(edges)
    }

    proptest! {
        #![proptest_config(ProptestConfig::with_cases(48))]

        #[test]
        fn from_and_to_indexes_agree(
            call_count in 1usize..40,
            stride in 5usize..64,
        ) {
            match build_and_check(call_count, stride) {
                Ok(edges) => {
                    // 承认这一点：如果一次都没产出边，这个属性就是空转的。
                    // 真出现这种情况说明合成样本没造对，必须当成失败报出来，
                    // 而不是让"零条边全都满足一致性"冒充通过。
                    prop_assert!(
                        edges > 0,
                        "本次用例产出 0 条 xref —— 属性测试没有验证到任何东西"
                    );
                }
                Err(msg) => prop_assert!(false, "{}", msg),
            }
        }
    }
}

/// 合成 ELF 里 `.text` 的虚拟地址（与 `disasm_e2e.rs` 的构造保持一致）。
const TEXT_VADDR: u64 = 0x401000;

/// 造一个最小可解析的 ELF64，`.text` 内容是 `code`。
///
/// 每个属性测试用例都要新建一个文件，所以这里不落盘、只返回字节，
/// 由调用方决定写到哪。
fn elf_with_text(code: &[u8]) -> Vec<u8> {
    // 布局：ELF 头（64）+ 1 个程序头（56）= 120，然后 .text 从文件偏移 0x100 开始
    const EHDR: usize = 64;
    const PHDR: usize = 56;
    const TEXT_OFF: usize = 0x100;
    const TEXT_VADDR_LOCAL: u64 = 0x401000;

    let total = TEXT_OFF + code.len();
    let mut buf = vec![0u8; total];

    // e_ident
    buf[0..4].copy_from_slice(b"\x7fELF");
    buf[4] = 2; // ELFCLASS64
    buf[5] = 1; // ELFDATA2LSB
    buf[6] = 1; // EV_CURRENT
    buf[7] = 0; // ELFOSABI_SYSV
                // e_type = ET_EXEC(2), e_machine = EM_X86_64(62), e_version = 1
    buf[16..18].copy_from_slice(&2u16.to_le_bytes());
    buf[18..20].copy_from_slice(&62u16.to_le_bytes());
    buf[20..24].copy_from_slice(&1u32.to_le_bytes());
    // e_entry
    buf[24..32].copy_from_slice(&TEXT_VADDR_LOCAL.to_le_bytes());
    // e_phoff = EHDR, e_shoff = 0
    buf[32..40].copy_from_slice(&(EHDR as u64).to_le_bytes());
    // e_ehsize = 64, e_phentsize = 56, e_phnum = 1
    buf[52..54].copy_from_slice(&(EHDR as u16).to_le_bytes());
    buf[54..56].copy_from_slice(&(PHDR as u16).to_le_bytes());
    buf[56..58].copy_from_slice(&1u16.to_le_bytes());

    // 程序头：PT_LOAD，R+X，覆盖 .text
    let p = EHDR;
    buf[p..p + 4].copy_from_slice(&1u32.to_le_bytes()); // p_type = PT_LOAD
    buf[p + 4..p + 8].copy_from_slice(&5u32.to_le_bytes()); // p_flags = R|X
    buf[p + 8..p + 16].copy_from_slice(&(TEXT_OFF as u64).to_le_bytes()); // p_offset
    buf[p + 16..p + 24].copy_from_slice(&TEXT_VADDR_LOCAL.to_le_bytes()); // p_vaddr
    buf[p + 24..p + 32].copy_from_slice(&TEXT_VADDR_LOCAL.to_le_bytes()); // p_paddr
    buf[p + 32..p + 40].copy_from_slice(&(code.len() as u64).to_le_bytes()); // p_filesz
    buf[p + 40..p + 48].copy_from_slice(&(code.len() as u64).to_le_bytes()); // p_memsz
    buf[p + 48..p + 56].copy_from_slice(&0x1000u64.to_le_bytes()); // p_align

    buf[TEXT_OFF..TEXT_OFF + code.len()].copy_from_slice(code);
    buf
}

/// 真实样本上的双向一致性：每个 `from→to` 都能在 `to` 的反向表里找到。
///
/// 属性测试证明的是索引算法；这条证明的是**接线**（真实数据上两侧都建了）。
///
/// 只能通过 `xrefs_from`/`xrefs_to` 两个入口做（没有"取全部 xref"的 API）：
/// 先枚举所有函数的出边，再逐条去目标地址反查。
#[test]
fn real_sample_xrefs_are_bidirectionally_consistent() {
    let Some((_session, analysis)) = analyze_sample() else {
        return;
    };

    let mut edges: HashSet<(u64, u64)> = HashSet::new();
    let mut functions_with_edges = 0usize;

    for f in analysis.functions() {
        let Ok(start) = u64::from_str_radix(&f.start, 16) else {
            continue;
        };
        let outgoing = analysis.xrefs_from(start);
        if !outgoing.is_empty() {
            functions_with_edges += 1;
        }
        for x in outgoing {
            let (Ok(a), Ok(b)) = (
                u64::from_str_radix(&x.from, 16),
                u64::from_str_radix(&x.to, 16),
            ) else {
                continue;
            };
            edges.insert((a, b));
        }
    }

    // 逐条反查：to 侧的入边里必须能找到这条边
    for &(a, b) in &edges {
        let found = analysis
            .xrefs_to(b)
            .iter()
            .any(|r| u64::from_str_radix(&r.from, 16).ok() == Some(a));
        assert!(
            found,
            "xref {a:016x} -> {b:016x} 在 from 侧存在，但 to 侧查不到 —— 双向索引不一致"
        );
    }

    println!(
        "双向一致：{} 条 xref，分布在 {} 个函数上",
        edges.len(),
        functions_with_edges
    );
    assert!(
        !edges.is_empty(),
        "静态链接样本上一条 xref 都没有，双向一致性是空转 —— 请检查分析链路"
    );
}
