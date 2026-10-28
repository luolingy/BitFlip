//! 结构化伪代码的**端到端不变量**测试（阶段 1 二十多片成果的回归护栏）。
//!
//! ## 为什么需要它
//!
//! 阶段 1 沿"反编译深度"做了很多可读性增强（返回值归纳、栈帧注释、栈槽符号化/化简、入参
//! 符号化、条件真实比较…）。这些都不改语义，只改渲染。但**没有任何端到端断言**把它们钉住：
//! 将来任何一处翻译/结构化的改动，都可能悄悄让伪代码退化成 `无法翻译` / 裸 `flags` / 一堆
//! `*(uint64_t *)(rsp + 0x..)`，而单元测试全绿也发现不了。
//!
//! 这里用**手写机器码的最小合成 ELF**（无需外部 fixture），端到端导出 `pseudo-c-structured`，
//! 断言若干**不变量**必须成立。合成样本自给自足，CI 上任何环境都能跑、不依赖 `tests/fixtures`。

use std::path::PathBuf;

use bitflip_core::{export, ExportFormat, ExportOptions, OpenOptions, Session};

/// 合成 ELF 里 `.text` 的虚拟地址（与 `m3_acceptance.rs` 的构造保持一致）。
const TEXT_VADDR: u64 = 0x401000;

/// 被测函数的手写机器码（x86-64，Intel）：
///
/// ```text
/// 401000  53                 push rbx
/// 401001  48 83 EC 20        sub  rsp, 0x20          ; 栈帧 0x20
/// 401005  48 89 CB           mov  rbx, rcx           ; 入口先读 rcx → arg1
/// 401008  48 85 DB           test rbx, rbx
/// 40100b  74 06              je   0x401013           ; → if (rbx == 0)
/// 40100d  8B 44 24 10        mov  eax, [rsp+0x10]    ; 单宽度槽 → v10
/// 401011  EB 05              jmp  0x401018
/// 401013  B8 05 00 00 00     mov  eax, 5
/// 401018  C3                 ret                     ; → return <expr>
/// ```
const CODE: &[u8] = &[
    0x53, // push rbx
    0x48, 0x83, 0xEC, 0x20, // sub rsp, 0x20
    0x48, 0x89, 0xCB, // mov rbx, rcx
    0x48, 0x85, 0xDB, // test rbx, rbx
    0x74, 0x06, // je 0x401013
    0x8B, 0x44, 0x24, 0x10, // mov eax, [rsp+0x10]
    0xEB, 0x05, // jmp 0x401018
    0xB8, 0x05, 0x00, 0x00, 0x00, // mov eax, 5
    0xC3, // ret
];

/// 造一个最小可解析的 ELF64（ET_EXEC, x86-64），`.text` 内容是 `code`。
fn elf_with_text(code: &[u8]) -> Vec<u8> {
    const EHDR: usize = 64;
    const PHDR: usize = 56;
    const TEXT_OFF: usize = 0x100;

    let total = TEXT_OFF + code.len();
    let mut buf = vec![0u8; total];

    buf[0..4].copy_from_slice(b"\x7fELF");
    buf[4] = 2; // ELFCLASS64
    buf[5] = 1; // ELFDATA2LSB
    buf[6] = 1; // EV_CURRENT
    buf[7] = 0; // ELFOSABI_SYSV
    buf[16..18].copy_from_slice(&2u16.to_le_bytes()); // ET_EXEC
    buf[18..20].copy_from_slice(&62u16.to_le_bytes()); // EM_X86_64
    buf[20..24].copy_from_slice(&1u32.to_le_bytes()); // EV_CURRENT
    buf[24..32].copy_from_slice(&TEXT_VADDR.to_le_bytes()); // e_entry
    buf[32..40].copy_from_slice(&(EHDR as u64).to_le_bytes()); // e_phoff
    buf[52..54].copy_from_slice(&(EHDR as u16).to_le_bytes()); // e_ehsize
    buf[54..56].copy_from_slice(&(PHDR as u16).to_le_bytes()); // e_phentsize
    buf[56..58].copy_from_slice(&1u16.to_le_bytes()); // e_phnum

    let p = EHDR;
    buf[p..p + 4].copy_from_slice(&1u32.to_le_bytes()); // PT_LOAD
    buf[p + 4..p + 8].copy_from_slice(&5u32.to_le_bytes()); // R|X
    buf[p + 8..p + 16].copy_from_slice(&(TEXT_OFF as u64).to_le_bytes()); // p_offset
    buf[p + 16..p + 24].copy_from_slice(&TEXT_VADDR.to_le_bytes()); // p_vaddr
    buf[p + 24..p + 32].copy_from_slice(&TEXT_VADDR.to_le_bytes()); // p_paddr
    buf[p + 32..p + 40].copy_from_slice(&(code.len() as u64).to_le_bytes()); // p_filesz
    buf[p + 40..p + 48].copy_from_slice(&(code.len() as u64).to_le_bytes()); // p_memsz
    buf[p + 48..p + 56].copy_from_slice(&0x1000u64.to_le_bytes()); // p_align

    buf[TEXT_OFF..].copy_from_slice(code);
    buf
}

/// 把合成 ELF 写到临时文件（每个测试独立目录），打开成 Session，导出结构化伪代码。
fn export_structured() -> String {
    let dir: PathBuf = std::env::temp_dir().join(format!(
        "bf-pseudo-invariants-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_nanos())
            .unwrap_or(0)
    ));
    std::fs::create_dir_all(&dir).expect("建临时目录");
    let path = dir.join("t.elf");
    std::fs::write(&path, elf_with_text(CODE)).expect("写合成 ELF");

    let session = Session::open(&path, OpenOptions::default()).expect("打开合成 ELF");
    let (text, _report) = export(
        &session,
        ExportFormat::PseudoCStructured,
        &ExportOptions::default(),
    )
    .expect("导出 pseudo-c-structured");
    text
}

#[test]
fn structured_pseudo_keeps_phase_one_readability_invariants() {
    let text = export_structured();

    // 1) 关键可读性形态必须出现 —— 缺任一都说明对应能力回归了。
    assert!(
        text.contains("arg1"),
        "入参符号化回归：应出现 arg1（rcx 入口先读）。实际输出：\n{text}"
    );
    assert!(
        text.contains("return"),
        "返回值归纳/返回渲染回归：应出现 return。实际输出：\n{text}"
    );
    assert!(
        text.contains("if (rbx "),
        "条件真实比较回归：test rbx,rbx + je 应还原成 if (rbx …)。实际输出：\n{text}"
    );
    // 单宽度栈槽被化简成裸变量 v10（第十九、二十一片）。
    assert!(
        text.contains("v10"),
        "栈槽符号化/化简回归：应出现化简后的栈槽变量 v10。实际输出：\n{text}"
    );
    // 栈帧注释（第十五片）。
    assert!(
        text.contains("栈帧"),
        "栈帧注释回归：应出现「栈帧」注释。实际输出：\n{text}"
    );

    // 2) 反向不变量：这段代码完全可翻译，绝不能有「无法翻译」。
    assert!(
        !text.contains("无法翻译"),
        "这段合成代码应完全可翻译，却出现了「无法翻译」。实际输出：\n{text}"
    );
    // 3) 不该退化成裸 flags 占位（第十八片的成果）。
    assert!(
        !text.contains("flags) goto"),
        "条件应还原成真实比较，不应退化成 flags 占位。实际输出：\n{text}"
    );
    // 4) 固定栈槽应已符号化，不再有原始的 rsp + 0x 访存形态。
    assert!(
        !text.contains("rsp + 0x"),
        "固定栈槽应已符号化，不该残留 `rsp + 0x` 原形态。实际输出：\n{text}"
    );
}
