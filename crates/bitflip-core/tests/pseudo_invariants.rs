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

use std::path::{Path, PathBuf};

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

// ---------------------------------------------------------------------------
// 真实编译器产物上的产物级契约（gen-fixtures.ps1 会生成下面这些样本，CI 可复现）
// ---------------------------------------------------------------------------

/// `tests/fixtures/generated/` 下的 fixture（由 `scripts/gen-fixtures.ps1` 生成，不入库）。
fn generated_fixture(name: &str) -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("..")
        .join("..")
        .join("tests")
        .join("fixtures")
        .join("generated")
        .join(name)
}

/// 在真实编译器产物上导出结构化伪代码。fixture 缺失时**响亮失败**（§7：跳过会让绿灯说谎），
/// 并提示先跑 `scripts/gen-fixtures.ps1`——CI 会在测试前生成它们。
fn export_structured_of(name: &str) -> String {
    let path = generated_fixture(name);
    assert!(
        path.exists(),
        "缺少 fixture {}；先跑 scripts/gen-fixtures.ps1 生成样本（CI 会在测试前生成）",
        path.display()
    );
    let session = Session::open(&path, OpenOptions::default()).expect("打开真实样本");
    let (text, _report) = export(
        &session,
        ExportFormat::PseudoCStructured,
        &ExportOptions::default(),
    )
    .expect("导出真实样本的 pseudo-c-structured");
    text
}

/// 真实样本上的通用契约：无论 -O1 怎么优化，这些都**必须**成立。
fn assert_real_sample_contract(name: &str, text: &str) {
    // 1) 至少要分解出几个函数（样本里有 bf_add/bf_loop/bf_entry 等）。
    let fn_count = text.matches("(void) {").count();
    assert!(
        fn_count >= 3,
        "{}：应分解出至少 3 个函数，实际 {fn_count} 个。实际输出：\n{text}",
        name
    );

    // 2) 全文件必须完全可翻译 —— 真实编译器产物里不该有「无法翻译」。
    //    （剩余「无法翻译」只允许出现在刻意保留的诚实拒绝，不该出现在这些小样本里。）
    assert!(
        !text.contains("无法翻译"),
        "{}：真实样本应完全可翻译，却出现了「无法翻译」。实际输出：\n{text}",
        name
    );

    // 3) 返回值渲染：每个函数基本都以 return 收尾。
    assert!(
        text.contains("return"),
        "{}：应出现 return 语句。实际输出：\n{text}",
        name
    );

    // 4) 入参符号化：bf_add/bf_loop 有参数，应出现 argN 命名。
    assert!(
        text.contains("arg1") || text.contains("arg2") || text.contains("arg3"),
        "{}：应出现 argN 入参符号化。实际输出：\n{text}",
        name
    );

    // 5) 花括号必须配平 —— 结构化渲染的结构性底线。
    let opens = text.matches('{').count();
    let closes = text.matches('}').count();
    assert_eq!(
        opens, closes,
        "{}：花括号不配平（{{={opens}, }}={closes}）。实际输出：\n{text}",
        name
    );

    // 6) 每条渲染语句应可追溯到指令地址（行尾 `/* @0x… */`）。
    assert!(
        text.contains("/* @0x"),
        "{}：语句应带 `/* @0x… */` 来源地址注释。实际输出：\n{text}",
        name
    );
}

#[test]
fn pe_real_sample_meets_structured_contract() {
    // PE 的 mingw 样本：含栈帧（bf_entry 的 sub rsp）。
    let text = export_structured_of("pe-x86_64.exe");
    assert_real_sample_contract("pe-x86_64.exe", &text);
    // 这个样本里有真实栈帧分配 —— 栈帧注释能力必须在真实 PE 上生效。
    assert!(
        text.contains("栈帧"),
        "pe-x86_64.exe：应有「栈帧」注释。实际输出：\n{text}"
    );
}

#[test]
fn elf_real_sample_meets_structured_contract() {
    // ELF 的 x86-64 样本（clang -O1，无 libc）：跨格式的同一份契约。
    let text = export_structured_of("elf-x86_64.exe");
    assert_real_sample_contract("elf-x86_64.exe", &text);
}
