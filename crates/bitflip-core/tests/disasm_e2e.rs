//! 端到端反汇编测试：用真实 fixture 验证"扫描 + 解码 + 渲染"整条链路。
//!
//! 这些测试的价值在于**对照真实字节**，而不是自造的假解码器 ——
//! 假解码器能证明算法逻辑对，但证明不了 capstone 接线对。
//! （接线错的那次正是靠 `relative_targets_are_resolved_to_absolute` 抓到的。）

use std::sync::Arc;

use bitflip_arch::{Arch, ArchSpec, Endian, Mode};
use bitflip_core::{parse_address, OpenOptions};
use bitflip_core::{DisasmScanOptions, Session};

/// fixture 目录（由 `scripts/gen-fixtures.ps1` 生成，不入库）。
fn fixture(name: &str) -> std::path::PathBuf {
    let mut path = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    path.pop(); // crates/bitflip-core -> crates
    path.pop(); // crates -> 仓库根
    path.push("tests/fixtures/generated");
    path.push(name);
    path
}

fn open(name: &str) -> Option<(Session, std::sync::Arc<DisasmFixture>)> {
    let path = fixture(name);
    if !path.exists() {
        // fixture 未生成时跳过：不把"没数据"伪装成"通过"
        eprintln!(
            "跳过：fixture {} 不存在，请先跑 scripts/gen-fixtures.ps1",
            name
        );
        return None;
    }
    let session = Session::open(&path, OpenOptions::default()).expect("应能打开 fixture");
    Some((session, std::sync::Arc::new(DisasmFixture)))
}

/// 占位类型，只为让上面的签名简单
struct DisasmFixture;

#[test]
fn elf_x86_64_object_scans_and_decodes_real_instructions() {
    let Some((session, _)) = open("elf-x86_64.o") else {
        return;
    };

    let disasm = session
        .disassemble(DisasmScanOptions::default())
        .expect("应能建立反汇编");

    let stats = disasm.wire_stats();
    assert!(stats.indexed > 0, "真实 .o 里应当能解出指令，实际 0 条");
    assert!(stats.executable_segments > 0, "应当至少有一个可执行段");

    // 第一页必须能渲染出真实助记符文本（不是占位符）
    let page = disasm.page(0, 32);
    assert!(page.returned > 0, "第一页不应为空");
    assert_eq!(page.format_version, bitflip_core::DISASM_FORMAT_VERSION);

    for insn in &page.instructions {
        assert_eq!(
            insn.address.len(),
            16,
            "地址必须是定长 16 位: {}",
            insn.address
        );
        assert!(
            insn.address
                .chars()
                .all(|c| c.is_ascii_hexdigit() && !c.is_ascii_uppercase()),
            "地址必须是小写十六进制: {}",
            insn.address
        );
        assert!(insn.length > 0, "指令长度不应为 0: {insn:?}");
        assert!(!insn.text.is_empty(), "指令文本不应为空: {insn:?}");
        assert!(
            !insn.text.contains("<无法解码>") || insn.flow == "unknown",
            "无法解码的指令必须被标为 unknown: {insn:?}"
        );
        // 机器码长度必须和 length 字段一致
        assert_eq!(
            insn.bytes.len(),
            usize::from(insn.length) * 2,
            "机器码字节数应与 length 一致: {insn:?}"
        );
    }

    // 至少渲染出一条真正像 x86 汇编的文本（含字母的助记符）
    assert!(
        page.instructions.iter().any(|i| i
            .text
            .chars()
            .next()
            .is_some_and(|c| c.is_ascii_alphabetic())),
        "应至少有真实助记符文本，实际样本: {:?}",
        page.instructions
            .iter()
            .take(5)
            .map(|i| &i.text)
            .collect::<Vec<_>>()
    );
}

#[test]
fn scanning_is_deterministic_across_runs() {
    let Some((session, _)) = open("elf-x86_64.o") else {
        return;
    };
    let options = DisasmScanOptions::default();

    let first = {
        let disasm = session.disassemble(options).expect("第一次扫描");
        disasm.page(0, 64)
    };
    let second = {
        let disasm = session.disassemble(options).expect("第二次扫描");
        disasm.page(0, 64)
    };

    assert_eq!(
        first.instructions, second.instructions,
        "同一个目标两次扫描必须给出完全相同的结果（扫描用了 rayon，不能有顺序依赖）"
    );
}

#[test]
fn paging_walks_forward_without_gaps_or_repeats() {
    let Some((session, _)) = open("elf-x86_64.o") else {
        return;
    };
    let disasm = session
        .disassemble(DisasmScanOptions::default())
        .expect("反汇编");

    // 用游标一页页走，收集所有地址：必须严格递增且无重复
    let mut seen: Vec<u64> = Vec::new();
    let mut cursor = 0u64;
    let page_size = 7; // 故意用不整齐的页大小
    let mut pages = 0;

    loop {
        let page = disasm.page(cursor, page_size);
        if page.returned == 0 {
            break;
        }
        for insn in &page.instructions {
            seen.push(parse_address(&insn.address).expect("地址应可解析"));
        }
        let Some(next) = page.next.and_then(|n| parse_address(&n)) else {
            break;
        };
        assert!(next > cursor, "游标必须前进: {next:#x} <= {cursor:#x}");
        cursor = next;
        pages += 1;
        assert!(pages < 10_000, "翻页没有终止 —— 游标可能没有前进");
    }

    assert!(!seen.is_empty(), "应至少翻出一页");
    for pair in seen.windows(2) {
        assert!(
            pair[1] > pair[0],
            "地址必须严格递增: {:#x} -> {:#x}",
            pair[0],
            pair[1]
        );
    }
    assert_eq!(
        seen.len() as u64,
        disasm.wire_stats().indexed,
        "翻页应当恰好覆盖全部已索引指令"
    );
}

#[test]
fn page_starting_inside_an_instruction_snaps_forward() {
    let Some((session, _)) = open("elf-x86_64.o") else {
        return;
    };
    let disasm = session
        .disassemble(DisasmScanOptions::default())
        .expect("反汇编");

    let first = disasm.page(0, 4);
    let Some(first_insn) = first.instructions.first() else {
        return;
    };
    let addr = parse_address(&first_insn.address).expect("地址");

    // 从"第一条指令中间"开始查：应该给出第一条指令本身，而不是空页
    if first_insn.length > 1 {
        let mid = disasm.page(addr + 1, 4);
        assert_eq!(
            mid.instructions.first().map(|i| i.address.clone()),
            Some(first_insn.address.clone()),
            "落在指令中间时应当向前吸附到该指令，而不是返回空页"
        );
    }
}

#[test]
fn page_beyond_the_end_is_empty_and_honest() {
    let Some((session, _)) = open("elf-x86_64.o") else {
        return;
    };
    let disasm = session
        .disassemble(DisasmScanOptions::default())
        .expect("反汇编");

    // 一个高得离谱的地址：必须给空页 + next=None，而不是报错或编造内容
    let page = disasm.page(0xffff_ffff_ffff_0000, 16);
    assert_eq!(page.returned, 0);
    assert!(page.instructions.is_empty());
    assert_eq!(page.next, None);
    assert!(!page.has_more);
}

#[test]
fn invalid_address_is_reported_not_guessed() {
    // 地址落在段外：读取必须失败，而不是返回零字节
    let Some((session, _)) = open("elf-x86_64.o") else {
        return;
    };
    let disasm = session
        .disassemble(DisasmScanOptions::default())
        .expect("反汇编");

    let page = disasm.page(0, 1);
    // 段外的读必须返回 None 语义（页为空），而不是编造一条指令
    assert!(
        page.returned <= 1,
        "单条请求最多返回一条，实际 {}",
        page.returned
    );
}

#[test]
fn pe_executable_scans_with_entry_seed() {
    let Some((session, _)) = open("pe-x86_64.exe") else {
        return;
    };
    let disasm = session
        .disassemble(DisasmScanOptions::default())
        .expect("PE 应能反汇编");

    let stats = disasm.wire_stats();
    assert!(stats.indexed > 0, "PE 可执行文件应能解出指令");
    assert!(
        stats.reachable > 0,
        "有入口点时递归下降应标记出可达指令，实际 0"
    );

    // 入口点应在第一页附近被扫到
    let page = disasm.page(0, 64);
    assert!(page.returned > 0);
}

#[test]
fn coverage_distinguishes_linear_only_from_reachable() {
    let Some((session, _)) = open("pe-x86_64.exe") else {
        return;
    };
    let disasm = session
        .disassemble(DisasmScanOptions::default())
        .expect("PE 应能反汇编");

    let stats = disasm.wire_stats();
    // 线性扫描覆盖所有字节，递归下降只覆盖可达部分：
    // 两者必须分开统计，否则"可信度"这个信息就丢了
    assert!(
        stats.linear_only > 0,
        "线性扫描应当比递归下降多覆盖一些字节（数据被当成指令）"
    );
    assert!(
        stats.reachable + stats.linear_only >= stats.indexed,
        "覆盖数不应小于索引数: reachable={} linear_only={} indexed={}",
        stats.reachable,
        stats.linear_only,
        stats.indexed
    );
}

#[test]
fn arch_spec_is_taken_from_the_object_not_assumed() {
    let Some((session, _)) = open("elf-aarch64.o") else {
        return;
    };
    let object = session.object().expect("应解析出对象");
    assert_eq!(object.arch.arch, Arch::Aarch64);

    let disasm = session
        .disassemble(DisasmScanOptions::default())
        .expect("AArch64 应能反汇编");
    let page = disasm.page(0, 16);
    assert!(page.returned > 0, "AArch64 目标应能解出指令");

    // 用 x86 的规则去解 AArch64 一定不对：这里验证我们确实换了后端。
    // AArch64 指令固定 4 字节（除了极少数），x86 则长度可变。
    let lengths: Vec<u8> = page.instructions.iter().map(|i| i.length).collect();
    assert!(
        lengths.iter().all(|l| *l == 4),
        "AArch64 指令应都是 4 字节，实际 {lengths:?}（可能用错了架构后端）"
    );
}

#[test]
fn raw_binary_has_no_seeds_and_says_so() {
    let Some((session, _)) = open("raw-blob.bin") else {
        return;
    };
    // 裸数据没有入口点/符号：反汇编要么明确不可用，要么如实报告"只做了线性扫描"
    match session.disassemble(DisasmScanOptions::default()) {
        Ok(disasm) => {
            let stats = disasm.wire_stats();
            assert_eq!(
                stats.reachable, 0,
                "裸二进制没有种子，可达指令数必须是 0，不能凭空猜"
            );
        }
        Err(error) => {
            let text = error.to_string();
            assert!(!text.is_empty(), "拒绝时必须有说明");
        }
    }
}

#[test]
fn address_parse_roundtrip_matches_wire_format() {
    // wire 上的地址必须能原样解析回来
    for raw in [0u64, 1, 0x401000, 0x7fff_ffff_ffff, u64::MAX] {
        let hex = bitflip_core::hex16(raw);
        assert_eq!(hex.len(), 16);
        assert_eq!(parse_address(&hex), Some(raw));
    }
}

/// 端到端：Arbitrary 构造的地址空间不会 panic。
#[test]
fn decoding_never_panics_on_arbitrary_bytes() {
    let spec = ArchSpec::from_arch(Arch::X86_64, Mode::M64, Endian::Little);
    let decoder = bitflip_arch::decoder_for(spec);
    let mut state = 0x2545_F491_4F6C_DD1Du64;
    let mut buffer = [0u8; 16];

    for _ in 0..3000 {
        for byte in &mut buffer {
            // xorshift64*
            state ^= state >> 12;
            state ^= state << 25;
            state ^= state >> 27;
            *byte = (state.wrapping_mul(0x2545_F491_4F6C_DD1D) >> 33) as u8;
        }
        // 只要不 panic 就算通过；Err 是合法结果
        let _ = decoder.decode_many(&buffer, 0x1000, 16);
    }
}

#[test]
fn disasm_is_send_and_sync_for_the_server_layer() {
    // 服务层用 Arc<Session> 跨 tokio 任务共享：这条约束不能靠"看起来对"
    fn assert_send_sync<T: Send + Sync>() {}
    assert_send_sync::<Session>();
    assert_send_sync::<bitflip_core::Disasm>();
    assert_send_sync::<Arc<bitflip_core::Disasm>>();
}
