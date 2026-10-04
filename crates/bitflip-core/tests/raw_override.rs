//! M5：原始二进制的手工架构/基址覆盖。
//!
//! M5 交付物明确要求"架构自动识别 + 手动覆盖（raw 二进制必须有）"。
//! 原始二进制（固件、裸镜像、脱壳代码段）没有任何头可读，嗅探只能如实说
//! "未识别"—— 而"未识别"对用户是没有用的答案，他明确知道这是什么。
//!
//! 这组测试盯的是**覆盖真的生效**，以及**没给的时候如实说没给**：
//! 后者同样重要 —— 悄悄拿一个默认架构去解码，产出的是
//! "看起来成功但是垃圾"的指令，比明确报错危险得多。

use std::path::PathBuf;

use bitflip_core::{Arch, Endian, Mode, OpenOptions, Session};

/// 生成产物目录（gitignored）。
fn generated_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("..")
        .join("..")
        .join("tests")
        .join("fixtures")
        .join("generated")
}

/// 从 ELF fixture 里抽出来的裸 `.text`（见本文件末尾的说明）。
fn raw_fixture() -> PathBuf {
    let path = generated_dir().join("aarch64-raw.bin");
    assert!(
        path.exists(),
        "缺少原始二进制 fixture {}。生成方式：\n  \
         llvm-objcopy -O binary --only-section=.text \
         tests/fixtures/generated/elf-aarch64-cfg.exe tests/fixtures/generated/aarch64-raw.bin",
        path.display()
    );
    path
}

/// 确认 fixture 确实是"裸字节"：没有可识别的头。
#[test]
fn the_raw_fixture_really_has_no_recognizable_header() {
    let session = Session::open(raw_fixture(), OpenOptions::default()).expect("打开原始二进制");

    assert_eq!(
        session.info().object,
        "raw",
        "fixture 必须是无头的原始二进制，否则这组测试没有测到该测的东西"
    );
    assert!(
        session.info().arch.is_none(),
        "裸字节不该嗅探出架构；实际 {:?}——fixture 可能不是裸的",
        session.info().arch
    );
    assert!(
        session.parsed().is_none(),
        "没有头的原始二进制在未指定架构时不该产出解析结果"
    );
}

/// 未指定架构时：明确报错，指出要 `--arch`，且**不**给解析结果。
///
/// 这条是安全断言：随便挑一个架构去解码会产出"看起来成功"的垃圾指令。
#[test]
fn raw_without_arch_is_refused_with_guidance() {
    let session = Session::open(raw_fixture(), OpenOptions::default()).expect("打开原始二进制");

    assert!(session.parsed().is_none(), "不该有解析结果");
    assert!(
        session.info().entry.is_none(),
        "没有基址就没有入口，不该编一个"
    );
    let notes = session.info().notes.join("\n");
    assert!(
        notes.contains("--arch"),
        "说明里必须告诉用户用 --arch 指定；实际：{notes}"
    );
}

/// 指定架构后：解析成功，且架构/位宽/端序三项一致。
///
/// 位宽与端序是 `Guess` 里与 `arch` **并列的独立字段**。覆盖了架构却不同步
/// 这两个，界面会显示"架构 aarch64 / 位宽未识别"这种自相矛盾的结论 ——
/// 这个 bug 真实发生过，这条测试就是钉住它。
#[test]
fn specifying_arch_produces_a_consistent_spec() {
    let opts = OpenOptions {
        arch: Some(Arch::Aarch64),
        ..Default::default()
    };
    let session = Session::open(raw_fixture(), opts).expect("打开原始二进制");

    let info = session.info();
    assert_eq!(info.arch.as_deref(), Some("aarch64/64/le"), "架构结论");
    assert_eq!(info.bits, 64, "位宽必须跟着架构走，不能停在「未识别」");
    assert_eq!(info.endian.as_deref(), Some("le"), "端序必须跟着架构走");
    assert!(session.parsed().is_some(), "指定架构后应当能解析");
}

/// 指定基址后：虚拟地址从基址起，入口 = 基址。
#[test]
fn specifying_base_maps_the_image_at_that_address() {
    const BASE: u64 = 0x2102e0;
    let opts = OpenOptions {
        arch: Some(Arch::Aarch64),
        base_address: Some(BASE),
        ..Default::default()
    };
    let session = Session::open(raw_fixture(), opts).expect("打开原始二进制");

    let info = session.info();
    let expected = format!("{BASE:016x}");
    assert_eq!(
        info.entry.as_deref(),
        Some(expected.as_str()),
        "没有其它可作入口的地方，入口应等于基址"
    );
    assert_eq!(info.image_base.as_deref(), Some(expected.as_str()));

    let parsed = session.parsed().expect("应有解析结果");
    assert_eq!(parsed.segments.len(), 1, "原始二进制合成单段");
    assert_eq!(parsed.sections.len(), 1, "原始二进制合成单节");
    let seg = &parsed.segments[0];
    assert_eq!(seg.vaddr, expected, "段的虚拟地址应是基址（定长 hex）");
    assert_eq!(
        seg.vsize, info.file_size,
        "段大小应覆盖整个文件（裸文件全是代码）"
    );
    assert_eq!(seg.perms, "r-x", "裸文件按代码看待：可读可执行不可写");
}

/// 不指定基址时：从 0 起，而不是随便编一个。
#[test]
fn raw_without_base_starts_at_zero() {
    let opts = OpenOptions {
        arch: Some(Arch::X86_64),
        ..Default::default()
    };
    let session = Session::open(raw_fixture(), opts).expect("打开原始二进制");

    let parsed = session.parsed().expect("应有解析结果");
    assert_eq!(
        parsed.segments[0].vaddr, "0000000000000000",
        "没给基址就从 0 起"
    );
    assert_eq!(
        session.info().entry.as_deref(),
        Some("0000000000000000"),
        "入口 = 基址 = 0"
    );
}

/// 指定的架构真的被用来解码，而不是只写在字段里。
///
/// 判据是"解出来的指令数 > 0"。用**错的**架构解 ARM 字节通常也会
/// "成功"（x86 解码器对几乎任何字节都能给出指令），所以光看有没有指令
/// 不足以证明架构选对了 —— 那条由下面的对拍测试覆盖。这条先钉住
/// "至少解码器被切过去了"。
#[test]
fn the_specified_arch_is_actually_used_for_decoding() {
    let opts = OpenOptions {
        arch: Some(Arch::Aarch64),
        base_address: Some(0x2102e0),
        ..Default::default()
    };
    let session = Session::open(raw_fixture(), opts).expect("打开原始二进制");
    let disasm = session
        .disassemble(bitflip_core::DisasmScanOptions::default())
        .expect("反汇编");

    let mut count = 0usize;
    let mut lengths: Vec<u8> = Vec::new();
    for (addr, len) in disasm.index.range(0, u64::MAX) {
        if let Some(bytes) = disasm.space.read(addr, usize::from(len)) {
            if let Ok(insn) = disasm.decoder.decode_one(&bytes, addr) {
                lengths.push(insn.len);
                count += 1;
            }
        }
    }

    assert!(count > 0, "指定架构后应当能解出指令，实际 0 条");

    // AArch64 是**定长 4 字节**指令集。这是"解码器确实切到了 AArch64"
    // 的硬证据：x86 是变长的，用 x86 解码器解同样的字节几乎必然
    // 产出一堆 1~3 字节的指令。光断言"有指令"是不够的 ——
    // x86 解码器对几乎任何字节都能给出"成功"的结果。
    let all_four = lengths.iter().all(|&l| l == 4);
    assert!(
        all_four,
        "AArch64 指令必须全是 4 字节定长；实际长度分布：{:?}——\
         解码器可能没有切到 AArch64",
        {
            let mut l = lengths.clone();
            l.sort_unstable();
            l.dedup();
            l
        }
    );
}

/// `force_raw`：把一个**有头**的 ELF 当成裸字节看。
///
/// 用途是"头部损坏/加密，但代码是好的"。这条确认容器与对象都被忽略，
/// 且用户仍能靠 `--arch`/`--base` 指定怎么解。
#[test]
fn force_raw_ignores_a_recognizable_container() {
    let elf = generated_dir().join("elf-aarch64-cfg.exe");
    assert!(elf.exists(), "缺少 fixture {}", elf.display());

    // 不设 force_raw：正常识别成 ELF
    let normal = Session::open(&elf, OpenOptions::default()).expect("打开 ELF");
    assert_eq!(normal.info().object, "elf");

    // 设 force_raw：忽略 ELF 头，当裸字节
    let forced = Session::open(
        &elf,
        OpenOptions {
            force_raw: true,
            arch: Some(Arch::Aarch64),
            ..Default::default()
        },
    )
    .expect("按原始二进制打开");

    assert_eq!(
        forced.info().object,
        "raw",
        "force_raw 后对象类别必须是原始二进制"
    );
    let notes = forced.info().notes.join("\n");
    assert!(
        notes.contains("按原始二进制处理"),
        "必须说明用户强制按裸字节处理（否则结论看起来像是自己识别出来的）：{notes}"
    );
    // 段数应当是合成的 1 段，而不是 ELF 自己的段表
    let parsed = forced
        .parsed()
        .expect("force_raw 后仍应能解析（指定了架构）");
    assert_eq!(
        parsed.segments.len(),
        1,
        "force_raw 用合成的单段，不应保留 ELF 的段表"
    );
}

/// `mode` 单独覆盖：Thumb 与 ARM 是同一架构的两套编码。
#[test]
fn mode_override_selects_the_thumb_decoder() {
    let opts = OpenOptions {
        arch: Some(Arch::Arm),
        mode: Some(Mode::Thumb),
        ..Default::default()
    };
    let session = Session::open(raw_fixture(), opts).expect("打开原始二进制");

    assert_eq!(
        session.info().arch.as_deref(),
        Some("arm/thumb/le"),
        "模式覆盖必须体现在架构结论里（否则界面看不出用的是 Thumb）"
    );
}

/// 只给 `mode` 不给 `arch`：说明"光有模式定不了解码器"，但不崩。
#[test]
fn mode_without_arch_is_reported_but_not_fatal() {
    let opts = OpenOptions {
        mode: Some(Mode::Thumb),
        ..Default::default()
    };
    let session = Session::open(raw_fixture(), opts).expect("打开原始二进制");

    let notes = session.info().notes.join("\n");
    assert!(
        notes.contains("架构"),
        "应说明「只给模式无法确定解码器」：{notes}"
    );
    assert!(session.parsed().is_none(), "没有架构仍然不该解析出东西");
}

/// 端序覆盖：大端架构要考虑。
#[test]
fn endian_override_is_applied() {
    let opts = OpenOptions {
        arch: Some(Arch::Arm),
        endian: Some(Endian::Big),
        ..Default::default()
    };
    let session = Session::open(raw_fixture(), opts).expect("打开原始二进制");

    assert_eq!(
        session.info().arch.as_deref(),
        Some("arm/32/be"),
        "端序覆盖必须体现出来"
    );
    assert_eq!(session.info().endian.as_deref(), Some("be"));
}
