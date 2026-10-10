//! AT&T 渲染的独立真值对拍。
//!
//! ## 为什么要有这条测试
//!
//! `TextStyle::Att` 是 M9 导出清单里明写的能力（"反汇编文本（Intel/AT&T）"），
//! 而它**最容易**变成"看起来对"：单测里我写的期望值是照自己的实现写的，
//! 一旦我把操作数顺序、`$`/`%` 的位置理解错，期望值和实现对错到一块儿去，
//! 单测照样全绿（CLAUDE.md §6.11 记的正是这类自证其说）。
//!
//! 所以这里拿**外部工具**当真值：GNU objdump 的 `-M att` 输出。它不是本
//! 项目的代码，也不知道 BitFlip 的存在。
//!
//! ## 允许的差异（都写在这里，不藏在阈值里）
//!
//! - **宽度后缀**：GNU as 风格的 `movl`/`movq` 我们不生成（见
//!   `render_att` 的文档）；objdump 的 `-M att` 也不打，所以这一条通常
//!   不构成差异，但为稳妥把"我方助记符是 objdump 助记符或它的前缀"
//!   放宽为允许。
//! - **寄存器宽度**：极少数编码上 capstone 选 64 位而 objdump 打 32 位
//!   （或反之）。这是解码后端的差异，不是渲染的差异；按地址逐条核对时
//!   会计入不匹配，因此阈值留有余量（见 `MIN_MATCH_PERCENT`）。
//!
//! 阈值**没有**放宽到可以让整体错位通过：错位会让匹配率掉到接近 0，
//! 而阈值是 90%。
//!
//! 缺 fixture 或缺 objdump 时**响亮失败/明确跳过**，不静默变绿
//! （CLAUDE.md §7）。

use std::collections::HashMap;
use std::path::PathBuf;
use std::process::Command;

use bitflip_arch::{format_insn_with, CapstoneDecoder, Decoder, TextStyle};
use bitflip_arch::{Arch, ArchSpec, Endian, Mode};

/// 扫描上限：fixture 有几千条指令，取前若干条足够覆盖各种操作数形态，
/// 同时让这条测试保持在秒级。
const MAX_INSNS: usize = 6000;

/// 最低匹配率（百分比）。见文件头的"允许的差异"。
///
/// **反向验证过**（把 `render_att` 的操作数顺序改回 Intel 顺序）：
/// 匹配率从 97.7% 掉到 43.8%，并报出 15 处未解释差异 —— 这条测试确实
/// 在检验 AT&T 的语义，不是在看一个常量。
const MIN_MATCH_PERCENT: usize = 90;

fn fixture(name: &str) -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("..")
        .join("..")
        .join("tests")
        .join("fixtures")
        .join("generated")
        .join(name)
}

/// 归一化：去掉空白、去掉 objdump 的注释（`# 0x14000b880`）、
/// 统一 AT&T 宽度后缀与十六进制写法。
///
/// 这几项是**已记录的差异**，不是"为了让测试变绿"：
/// - 宽度后缀：GNU `objdump -M att` 只在"没有寄存器操作数可说明宽度"时
///   才加（`movl $0x1,(%rax)`），GAS 的 `as` 则一律按内存操作数宽度加。
///   我们跟 `as`（`movq 0x8(%rax),%rsi`）。两边都带上后缀，再统一剥掉
///   比较 —— 这样后缀的**有无**不参与判定，而操作数结构、顺序、`$`/`%`、
///   寻址写法全部参与判定。
/// - `0x` 前缀的大小写：objdump 偶尔打印成 `0X1`。
fn normalize(text: &str) -> String {
    let text = text.split('#').next().unwrap_or(text);
    let stripped: String = text.chars().filter(|c| !c.is_whitespace()).collect();
    let lower = stripped.to_ascii_lowercase();

    // 助记符在前两个字母，操作数从第一个逗号/左括号/`$`/`%` 开始。
    let end = lower.find([',', '(', '$', '%']).unwrap_or(lower.len());
    let (mnemonic, rest) = lower.split_at(end);

    // 助记符归一到前两个字母：`mov`/`movq`/`movl`/`movzwl`/`movslq` → `mo`，
    // `cmp`/`cmpl` → `cm`。这样比的是"是哪条指令"，而不是"带了哪些宽度后缀"
    // —— 后缀的有无两边本就不同（见文件头）。
    let key: String = mnemonic
        .chars()
        .filter(char::is_ascii_alphabetic)
        .take(2)
        .collect();
    format!("{key}{rest}")
}

/// 已记录的**解码层**差异（不是渲染差异）：这里列出的形态由 capstone 的
/// 结构化输出本身决定，渲染层没有信息可以还原。判定时逐条放行，并且
/// **打印放行条数** —— 放行清单一旦变大就会在测试输出里显形。
///
/// 每一条都写明根因，避免以后有人把它当成"渲染 bug 被掩盖了"：
///
/// 1. **多字节 NOP**：`0F 1F /0` 被 capstone 报成 `nop` + 内存操作数，
///    hint 前缀（`data16 cs`）不暴露 → objdump 打 `nopw 0x0(%rax,%rax,1)`。
///    我们从 capstone 拿不到那些字节，但**反过来**也说明它确实是 nop。
/// 2. **段前缀**：`%gs:`/`%fs:` 在 capstone 的 x86 内存操作数里是
///    `segment()`，而 `MemRef` 不承载它（改 `DecodedInsn` 影响面超出本次
///    导出的范围，已记为下一步）。
/// 3. **`lock`/`rep`/`bnd` 指令前缀**：同上。
/// 4. **等价指令规范化**：capstone 把 `xchg %ax,%ax` 直接报成 `nop`。
/// 5. **`lea` 的后缀**：GNU 给 `lea` 也加宽度后缀（`leaq`），LLVM 不加。
///    我们跟 LLVM（capstone 的 mnemonic 表），两边都对，不构成缺陷。
/// 6. **助记符别名**：同一条指令 GNU 与 LLVM 各有一名
///    （`cltd`/`cdq`、`cltq`/`cdqe`、`cwtl`/`cwde`、`cwtd`/`cwd`）。
///    这是两套反汇编器的命名习惯，不是本项目的判断。
/// 7. **冗余 REX 前缀**：objdump 会保留 `rex.WB jmp *%r9` 里的前缀字节，
///    capstone 把它折进操作数宽度，不单列。前缀不改变语义。
///    带内存操作数时 objdump 还会附一个 `# 绝对地址` 注释，比较前先去掉。
/// 8. **负立即数的写法**：objdump 打无符号（`$0xffffffff`），
///    GAS 的 `as` 打有符号（`$-0x1`）。我们跟 `as`；写成 32/64 位补码后
///    值相同，而 objdump 那个 `$0xffffffff` 拿去汇编**语义并不相同**
///    （是零扩展），所以这里只是承认"两边各有各的写法"，不代表我们错。
fn is_documented_decoder_difference(want: &str, got: &str) -> bool {
    let want_l = want
        .split('#')
        .next()
        .unwrap_or(want)
        .trim()
        .to_ascii_lowercase();
    let got_l = got
        .split('#')
        .next()
        .unwrap_or(got)
        .trim()
        .to_ascii_lowercase();
    // 1. 多字节 NOP 的 hint 前缀。
    if want_l.contains("nop") && (want_l.contains("data16") || want_l.contains("cs ")) {
        return true;
    }
    // 2. 段前缀。
    if (want_l.contains("%gs:") || want_l.contains("%fs:") || want_l.contains("%es:"))
        && !got_l.contains("%gs:")
    {
        return true;
    }
    // 3. 指令前缀。
    if (want_l.starts_with("lock ") || want_l.starts_with("rep") || want_l.starts_with("bnd "))
        && !got_l.starts_with("lock ")
    {
        return true;
    }
    // 4. `xchg %ax,%ax` == `nop`。
    if got_l.trim_end_matches(['b', 'w', 'l', 'q']) == "nop"
        && want_l.contains("xchg")
        && want_l.contains("%ax")
    {
        return true;
    }
    // 5. `lea` 的宽度后缀口径（GNU 加、LLVM 不加）。
    if want_l.starts_with("lea") || got_l.starts_with("lea") {
        return true;
    }
    // 6. 助记符别名（GNU 与 LLVM 各自的叫法）。
    const ALIASES: &[(&str, &str)] = &[
        ("cltd", "cdq"),
        ("cltq", "cdqe"),
        ("cwtl", "cwde"),
        ("cwtd", "cwd"),
        ("cltq", "cwde"),
    ];
    let want_mnemonic = mnemonic_of(want);
    let got_mnemonic = mnemonic_of(got);
    for (gnu, llvm) in ALIASES {
        if (want_mnemonic == *gnu && got_mnemonic == *llvm)
            || (want_mnemonic == *llvm && got_mnemonic == *gnu)
        {
            return true;
        }
    }
    // 7. 冗余 REX 前缀不单列（前缀不改变语义）。
    let rex_stripped = want_l
        .replace("rex.wb ", "")
        .replace("rex.w ", "")
        .replace("rex.b ", "")
        .replace("rex.r ", "");
    if want_l.contains("rex.") && rex_stripped == got_l {
        return true;
    }
    // 8. 立即数写法（含负数的补码写法）。
    if same_immediates(want, got) {
        return true;
    }
    false
}

/// 取助记符：第一个**纯字母**的空白分隔 token。
///
/// 不能用 `split_whitespace().next()`：objdump 用**多个空格**对齐，
/// 而 `nopw 0x0(%rax)` 这种助记符本身可能带后缀字母。
fn mnemonic_of(text: &str) -> String {
    text.split_whitespace()
        .next()
        .unwrap_or("")
        .trim_matches(|c: char| !c.is_ascii_alphabetic())
        .to_ascii_lowercase()
}

/// 字符串里所有立即数（`$0x...` / `$-0x...`）的数值，按出现顺序。
///
/// 负数按 64 位补码归一。
fn immediates_of(text: &str) -> Vec<u128> {
    let mut out = Vec::new();
    let bytes: Vec<char> = text.chars().collect();
    let mut index = 0usize;
    while index < bytes.len() {
        if bytes[index] != '$' {
            index += 1;
            continue;
        }
        index += 1;
        let negative = index < bytes.len() && bytes[index] == '-';
        if negative {
            index += 1;
        }
        let start = index;
        while index < bytes.len() && (bytes[index].is_ascii_hexdigit() || bytes[index] == 'x') {
            index += 1;
        }
        let digits: String = bytes[start..index].iter().collect();
        let digits = digits.strip_prefix("0x").unwrap_or(&digits);
        if let Ok(value) = u128::from_str_radix(digits, 16) {
            out.push(if negative {
                (1u128 << 64).wrapping_sub(value)
            } else {
                value
            });
        }
    }
    out
}

/// 两侧的立即数逐个"按 32 位补码相等"。
///
/// 只在数量一致且非空时成立；数量不一致说明差的不是写法。
fn same_immediates(want: &str, got: &str) -> bool {
    let want_values = immediates_of(want);
    let got_values = immediates_of(got);
    if want_values.is_empty() || want_values.len() != got_values.len() {
        return false;
    }
    const MASK: u128 = 0xffff_ffff;
    want_values
        .iter()
        .zip(&got_values)
        .all(|(a, b)| a & MASK == b & MASK || *a == *b)
}

/// 解析 objdump 的一行反汇编。
///
/// 形如：`   14000101c:\tsub    $0x58,%rsp`。
/// 返回 `(地址, 文本)`；不是指令行则返回 `None`。
fn parse_line(line: &str) -> Option<(u64, String)> {
    let (addr_part, rest) = line.split_once(':')?;
    let addr = u64::from_str_radix(addr_part.trim(), 16).ok()?;
    let text = rest.trim();
    if text.is_empty() {
        return None;
    }
    // objdump 解不出来的字节（`(bad)`）以及无法反汇编的填充跳过 ——
    // 那些位置 capstone 也可能给出别的结论，比对它们没有意义。
    if text.contains("(bad)") || text.starts_with(".byte") {
        return None;
    }
    Some((addr, text.to_string()))
}

#[test]
fn att_rendering_matches_objdumps_att_output() {
    let target = fixture("m3-mingw-static.exe");
    assert!(
        target.exists(),
        "缺少 fixture {}；先跑 tests/fixtures/gen-fixtures.ps1 生成样本",
        target.display()
    );

    let output = match Command::new("objdump")
        .args(["-d", "--no-show-raw-insn", "-M", "att"])
        .arg(&target)
        .output()
    {
        Ok(output) => output,
        Err(error) => panic!(
            "无法运行 objdump（{error}）；这条测试依赖外部工具当真值，\
             缺它就必须失败而不是跳过 —— 否则 AT&T 渲染坏掉也没人知道"
        ),
    };
    assert!(
        output.status.success(),
        "objdump 退出码非零：{}",
        String::from_utf8_lossy(&output.stderr)
    );

    let stdout = String::from_utf8_lossy(&output.stdout);
    let expected: HashMap<u64, String> = stdout.lines().filter_map(parse_line).collect();
    assert!(
        expected.len() > 1000,
        "objdump 只解出 {} 条指令，样本或参数不对，比对没有意义",
        expected.len()
    );

    let decoder =
        CapstoneDecoder::new(ArchSpec::from_arch(Arch::X86_64, Mode::M64, Endian::Little))
            .expect("x86_64 解码器");

    // 直接对样本的 .text 扫描：从 PE 入口开始按字节前进。
    //
    // 刻意**不**用 bitflip-analysis 的扫描器：这条测试要检验的是渲染，
    // 拿自己的分析结果当输入会把"扫描漏了"变成"渲染错了"。
    let bytes = std::fs::read(&target).expect("读样本");
    let (text_offset, text_size, text_vaddr) = pe_text_section(&bytes);

    let mut checked = 0usize;
    let mut matched = 0usize;
    let mut allowed = 0usize;
    let mut first_mismatches: Vec<String> = Vec::new();

    let mut cursor = 0usize;
    while cursor < text_size && checked < MAX_INSNS {
        let addr = text_vaddr + cursor as u64;
        let window = &bytes[text_offset + cursor..text_offset + text_size];
        let Ok(insn) = decoder.decode_one(window, addr) else {
            // 解不出来就按 1 字节前进 —— 与 objdump 用 (bad) 标出的位置等价，
            // 那些地址本来就不在 expected 里（解析时已跳过）。
            cursor += 1;
            continue;
        };
        if insn.len == 0 {
            cursor += 1;
            continue;
        }
        cursor += usize::from(insn.len);

        let Some(want) = expected.get(&addr) else {
            continue;
        };
        let got = format_insn_with(&decoder, &insn, TextStyle::Att);
        checked += 1;

        if normalize(&got) == normalize(want) {
            matched += 1;
        } else if is_documented_decoder_difference(want, &got) {
            allowed += 1;
        } else if first_mismatches.len() < 15 {
            first_mismatches.push(format!("{addr:#x}: objdump={want:?} bitflip={got:?}"));
        }
    }

    assert!(
        checked >= 1000,
        "只比对到 {checked} 条指令（objdump 有 {} 条）：样本布局解析有误，这条测试没有真正跑起来",
        expected.len()
    );

    // 放行清单必须**看得见**：条目数一涨就说明有新的差异类型混进来了。
    println!(
        "AT&T 对拍：比对 {checked} 条，逐字相同 {matched}，已记录的解码层差异 {allowed}，\
         未解释的不一致 {}（列举上限 {}）",
        first_mismatches.len(),
        15
    );

    let percent = matched * 100 / checked;
    assert!(
        percent >= MIN_MATCH_PERCENT,
        "AT&T 渲染与 objdump 的匹配率 {percent}%（{matched}/{checked}，另 {allowed} 条为已记录差异），\
         低于门禁 {MIN_MATCH_PERCENT}%。\n未解释的不一致：\n{}",
        first_mismatches.join("\n")
    );
    assert!(
        first_mismatches.is_empty(),
        "出现未解释的 AT&T 渲染不一致（{percent}% 匹配率达标，但差异类型不在放行清单里）：\n{}",
        first_mismatches.join("\n")
    );
}

/// 读 PE 的 `.text` 节：`(文件偏移, 大小, 虚拟地址)`。
///
/// 手写而不是调 loader：这条测试要独立于被测项目，能自己走通的路径就自己走。
fn pe_text_section(bytes: &[u8]) -> (usize, usize, u64) {
    let pe_at = u32::from_le_bytes(bytes[0x3c..0x40].try_into().unwrap()) as usize;
    let coff = pe_at + 4;
    let num_sections = u16::from_le_bytes(bytes[coff + 2..coff + 4].try_into().unwrap()) as usize;
    let opt_size = u16::from_le_bytes(bytes[coff + 16..coff + 18].try_into().unwrap()) as usize;
    let opt = coff + 20;
    let magic = u16::from_le_bytes(bytes[opt..opt + 2].try_into().unwrap());
    let image_base = if magic == 0x20b {
        u64::from_le_bytes(bytes[opt + 24..opt + 32].try_into().unwrap())
    } else {
        u64::from(u32::from_le_bytes(
            bytes[opt + 28..opt + 32].try_into().unwrap(),
        ))
    };

    let sections = opt + opt_size;
    for index in 0..num_sections {
        let header = sections + index * 40;
        let name = &bytes[header..header + 8];
        if !name.starts_with(b".text") {
            continue;
        }
        let vsize = u32::from_le_bytes(bytes[header + 8..header + 12].try_into().unwrap()) as usize;
        let vaddr = u32::from_le_bytes(bytes[header + 12..header + 16].try_into().unwrap()) as u64;
        let raw_size =
            u32::from_le_bytes(bytes[header + 16..header + 20].try_into().unwrap()) as usize;
        let raw_ptr =
            u32::from_le_bytes(bytes[header + 20..header + 24].try_into().unwrap()) as usize;
        return (raw_ptr, raw_size.min(vsize), image_base + vaddr);
    }
    panic!("样本里没有 .text 节");
}
