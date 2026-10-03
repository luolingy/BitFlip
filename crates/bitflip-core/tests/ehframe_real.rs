//! `.eh_frame` 的真实二进制验收测试。
//!
//! 单元测试用的是手拼的 `.eh_frame` 字节，那只证明"解析器符合我的理解"。
//! 这里用**真实 clang 产物**验证"解析器符合编译器实际写出来的东西" ——
//! 编码理解错了，手拼的测试照样通过，真实样本才会暴露。
//!
//! 样本由 `scripts/gen-ehframe-fixture.ps1` 生成（x86_64 Linux ELF，
//! `-funwind-tables`，链完再 strip）。脚本同时用 `llvm-readobj` 数出
//! FDE 条数作为**独立**参照：如果我们解析出的边界数与 llvm 不一致，
//! 必有一方是错的。

use bitflip_core::{OpenOptions, Session};

fn fixture(name: &str) -> std::path::PathBuf {
    let mut path = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    path.pop();
    path.pop();
    path.push("tests/fixtures/generated");
    path.push(name);
    path
}

/// 从 meta 文件读一个 `key=value`。
fn meta(key: &str) -> Option<String> {
    let text = std::fs::read_to_string(fixture("elf-ehframe.meta.txt")).ok()?;
    for line in text.lines() {
        if let Some((k, v)) = line.split_once('=') {
            if k.trim() == key {
                return Some(v.trim().to_string());
            }
        }
    }
    None
}

/// 真实 ELF 上必须真的解出 FDE 边界。
#[test]
fn real_elf_yields_fde_boundaries() {
    let exe = fixture("elf-ehframe.exe");
    if !exe.exists() {
        eprintln!(
            "跳过：样本 {} 不存在，请先跑 scripts/gen-ehframe-fixture.ps1",
            exe.display()
        );
        return;
    }

    let session = Session::open(&exe, OpenOptions::default()).expect("应能打开 ELF 样本");
    let object = session.object().expect("应能拿到对象");

    let entries = &object.unwind;
    println!("解析出 {} 条展开表边界", entries.len());
    for e in entries.iter().take(12) {
        println!(
            "  {:#x}..{:#x} (len {:#x})",
            e.begin,
            e.end,
            e.end - e.begin
        );
    }
    for n in &object.notes {
        println!("  note: {n}");
    }

    assert!(
        !entries.is_empty(),
        "真实 ELF 的 .eh_frame 里一条 FDE 都没解出来 —— 解析器没有接上或编码读错了。\
         notes={:?}",
        object.notes
    );

    // 每条边界必须自洽：end > begin（长度非零），否则是"空函数"，
    // 那说明把坏数据当成了函数（§7）。
    for e in entries {
        assert!(
            e.end > e.begin,
            "边界 {:#x}..{:#x} 长度为 0 —— 空函数不该出现在边界表里",
            e.begin,
            e.end
        );
    }

    // 地址必须落在某个可执行段内：落到别处说明 pcrel 基址算错了。
    let exec: Vec<_> = object.segments.iter().filter(|s| s.perms.execute).collect();
    assert!(!exec.is_empty(), "样本应有可执行段");
    for e in entries {
        let inside = exec
            .iter()
            .any(|s| e.begin >= s.vaddr && e.begin < s.vaddr + s.vsize);
        assert!(
            inside,
            "函数起点 {:#x} 不在任何可执行段里 —— 地址算错了",
            e.begin
        );
    }
}

/// 解析出的边界条数必须与 `llvm-readobj` 的 `fde_count` 一致。
///
/// 这是**外部工具对拍**：两边独立实现同一个规格，条数对得上才有说服力。
/// 差一两条可能是我把某个边角记录跳过了，差很多就是解析错了。
#[test]
fn fde_count_matches_llvm_readobj() {
    let exe = fixture("elf-ehframe.exe");
    let meta_path = fixture("elf-ehframe.meta.txt");
    if !exe.exists() || !meta_path.exists() {
        eprintln!("跳过：样本或 meta 不存在");
        return;
    }

    let Some(expected) = meta("llvm_fdes").and_then(|v| v.parse::<usize>().ok()) else {
        eprintln!("跳过：meta 里没有 llvm_fdes");
        return;
    };
    if expected == 0 {
        eprintln!("跳过：llvm 报告 0 条 FDE，样本可能没开 -funwind-tables");
        return;
    }

    let session = Session::open(&exe, OpenOptions::default()).expect("打开");
    let object = session.object().expect("object");
    let ours = object.unwind.len();

    println!("llvm-readobj fde_count = {expected}，BitFlip 解析出 = {ours}");
    assert_eq!(
        ours, expected,
        "FDE 条数与 llvm-readobj 不一致（我们 {ours}，它 {expected}）—— 有一方是错的"
    );
}

/// strip 之后 `.eh_frame` 仍是唯一边界来源 —— 这条才证明这个功能的价值。
#[test]
fn stripped_binary_still_has_boundaries() {
    let exe = fixture("elf-ehframe.exe");
    let unstripped = fixture("elf-ehframe.unstripped.exe");
    if !exe.exists() || !unstripped.exists() {
        eprintln!("跳过：样本不存在");
        return;
    }

    // 前提：strip 过的样本**没有**函数符号。否则这个测试是假的 ——
    // 边界可能来自符号表，而不是 .eh_frame。
    let stripped_meta = meta("stripped_symbols")
        .and_then(|v| v.parse::<usize>().ok())
        .unwrap_or(usize::MAX);
    assert_eq!(
        stripped_meta, 0,
        "strip 过的样本仍暴露 {stripped_meta} 个函数符号 —— 本测试无法证明 .eh_frame 的作用"
    );

    let stripped_session = Session::open(&exe, OpenOptions::default()).expect("打开 stripped");
    let stripped_object = stripped_session.object().expect("object");

    // 符号表里应当没有函数符号了
    let func_symbols = stripped_object
        .symbols
        .iter()
        .filter(|s| s.is_function && s.defined)
        .count();
    println!(
        "stripped 样本：函数符号 {func_symbols} 个，.eh_frame 边界 {} 条",
        stripped_object.unwind.len()
    );

    assert!(
        !stripped_object.unwind.is_empty(),
        "符号被剥掉之后 .eh_frame 仍应给出函数边界 —— 这正是它存在的意义"
    );

    // 与未 strip 版本的边界集合应当一致：strip 不该改变代码
    let full_session = Session::open(&unstripped, OpenOptions::default()).expect("打开 full");
    let full_object = full_session.object().expect("object");

    let mut a: Vec<(u64, u64)> = stripped_object
        .unwind
        .iter()
        .map(|e| (e.begin, e.end))
        .collect();
    let mut b: Vec<(u64, u64)> = full_object
        .unwind
        .iter()
        .map(|e| (e.begin, e.end))
        .collect();
    a.sort_unstable();
    b.sort_unstable();
    assert_eq!(
        a, b,
        "strip 前/后的展开表边界应当完全一致（strip 不改变代码）"
    );
}

/// relocatable object（`.o`）里地址未重定位，**不能**给出边界。
///
/// 这条锁的是诚实性：`.o` 的 `.eh_frame` 里是重定位前的占位值，
/// 当成真实地址给出边界就是错的（§7）。
#[test]
fn relocatable_object_does_not_fake_boundaries() {
    // gen-fixtures 会产出 elf-x86_64.o
    let obj = fixture("elf-x86_64.o");
    if !obj.exists() {
        eprintln!("跳过：elf-x86_64.o 不存在");
        return;
    }
    let session = Session::open(&obj, OpenOptions::default()).expect("打开 .o");
    let object = session.object().expect("object");

    assert!(
        object.unwind.is_empty(),
        ".o 的 .eh_frame 地址尚未重定位，不该给出边界（实际给了 {} 条）",
        object.unwind.len()
    );
    // 但必须说清为什么没给，而不是悄悄留空
    let explained = object
        .notes
        .iter()
        .any(|n| n.contains("重定位") || n.contains("可重定位"));
    println!("notes: {:?}", object.notes);
    assert!(
        explained,
        "没给边界就必须在 notes 里说明是重定位问题，否则用户会以为这个文件没有展开表"
    );
}

/// `.eh_frame` 的边界必须真的**喂给扫描器**。
///
/// 光解析出边界还不够：`collect_seeds` 曾经只取入口/导出/符号表，
/// **完全忽略 `object.unwind`**。后果是剥离符号的目标上，递归下降无从
/// 进入这些函数 —— 边界表解析得再对，分析结果也是空的。
///
/// 判据：stripped 样本上，反汇编索引必须覆盖 .eh_frame 报出的每一个
/// 函数起点。这是"解析"到"用上"的端到端证据。
#[test]
fn unwind_boundaries_are_used_as_scan_seeds() {
    let exe = fixture("elf-ehframe.exe");
    if !exe.exists() {
        eprintln!("跳过：样本不存在");
        return;
    }

    let session = Session::open(&exe, OpenOptions::default()).expect("打开");
    let object = session.object().expect("object").clone();
    let boundaries: Vec<u64> = object.unwind.iter().map(|e| e.begin).collect();
    assert!(!boundaries.is_empty(), "样本应解出 .eh_frame 边界");

    let disasm = session
        .disassemble(bitflip_core::DisasmScanOptions::default())
        .expect("反汇编");

    let mut missing = Vec::new();
    for begin in &boundaries {
        // 索引里应当有这个地址处的指令
        let found = disasm
            .index
            .range(*begin, begin.saturating_add(1))
            .next()
            .is_some();
        if !found {
            missing.push(*begin);
        }
    }

    println!(
        "{} 个 .eh_frame 起点中，有 {} 个进入了反汇编索引",
        boundaries.len(),
        boundaries.len() - missing.len()
    );

    assert!(
        missing.is_empty(),
        "有 {} 个 .eh_frame 函数起点没被扫描到 —— 边界没喂给 collect_seeds：{:x?}",
        missing.len(),
        &missing[..missing.len().min(10)]
    );
}
