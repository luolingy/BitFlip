//! 编译器内置模式库（M8 交付物 3）。
//!
//! 这一层要解决的问题：**没有用户签名库时，也要能认出编译器/运行时自己生成的函数**。
//! 判据是"固定形状"，不是"猜名字" —— 每条判据都对应一份公开、可复核的生成代码
//! （GCC 的 `chkstk.S`、MSVC 的 `chkstk.asm` 之类），并且必须对着真样本验过。
//!
//! 三条纪律：
//!
//! 1. **没验过的判据不入库。** 判据写不对时的正确表现是"匹配不上"，而不是"认错"。
//!    本机没有能产生 MSVC `__chkstk` 的 fixture（需要整套 SDK 环境），所以它不在库里。
//! 2. **认不出就不认。** 库里没有的形状就老实说没命中（`notes` 里报账），
//!    绝不生成占位名（CLAUDE.md §7）。
//! 3. **理由和名字写在一起。** 名字是结论，形状是理由；只给结论，用户没法复核。
//!
//! 当前只有一条判据：GCC x64 的逐页栈探测助手 `___chkstk_ms`。
//! 考虑过但**没做**的见 `docs/PLAN.md` §M8，每条都写了为什么不够硬。

/// 判定窗口。GCC 的 `___chkstk_ms` 实测 50 字节（0x32），给一倍余量。
pub const PATTERN_WINDOW: usize = 0x60;

/// 页大小常量（小端 `00 10 00 00` = 4096）。
const PAGE_STEP: [u8; 4] = [0x00, 0x10, 0x00, 0x00];

/// `or qword ptr [rcx], 0` —— 探测指令，GCC 手写汇编里固定在 `rcx` 上。
const PROBE: [u8; 4] = [0x48, 0x83, 0x09, 0x00];

/// 认出来的一个内置函数。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BuiltinHit {
    /// 名字。用编译器/运行时自己的拼写，不加修饰。
    pub name: &'static str,
    /// 置信度（0–100）。形状是间接证据，所以低于符号表与调试信息。
    pub confidence: u8,
    /// 判据（凭什么说是它）。
    pub why: &'static str,
}

/// GCC x64 的逐页栈探测助手 `___chkstk_ms`。
///
/// 形状（`chkstk.S`，x86_64-w64-mingw32 gcc 14 实测；`tests/fixtures/m8_builtins_sample.c`
/// 里 8 KiB 的栈帧会把它连进来）：
///
/// ```text
/// push rcx ; push rax
/// cmp  rax, 0x1000          ; 48 3d 00 10 00 00
/// lea  rcx, [rsp+0x18]
/// jb   done
/// loop:
///   sub  rcx, 0x1000        ; 48 81 e9 00 10 00 00
///   or   [rcx], 0           ; 48 83 09 00    <- 摸一下这一页
///   sub  rax, 0x1000        ; 48 2d 00 10 00 00
///   cmp  rax, 0x1000
///   ja   loop
/// done:
///   sub  rcx, rax
///   or   [rcx], 0
///   pop rax ; pop rcx ; ret
/// ```
///
/// 判据（全部满足才算命中，都是从实测字节抄来的，不是推测）：
///
/// * 传入的字节要覆盖到函数的末尾。**函数体的末尾是窗口内第一条 `ret`** ——
///   不要求调用方事先知道边界：在剥离过的目标上，`.pdata` 未必覆盖这种纯汇编小助手
///   （实测本样本的 `___chkstk_ms` 就没有展开表条目），而"直线代码在第一条 `ret`
///   处结束"是 x86-64 上的事实，不是猜测。若某个 `ret` 的字节出现在指令的立即数里，
///   判定会提前结束 —— 那只会让它**匹配不上**，方向是安全的。
/// * 体长 ≥ 16 且 ≤ [`PATTERN_WINDOW`]；
/// * 页大小常量 `00 10 00 00` 至少出现两次（一次比大小、一次步进）；
/// * 出现 `48 83 09 00`（`or qword ptr [rcx], 0`）。
///
/// 工具链换版本后如果生成方式变了，正确表现是**匹配不上**（界面上仍是"未识别"），
/// 而不是认错 —— 所以这里宁可判据窄一点。
#[must_use]
pub fn match_gcc_x64_stack_probe(bytes: &[u8]) -> Option<BuiltinHit> {
    let window = bytes.get(..PATTERN_WINDOW).unwrap_or(bytes);
    let ret_at = window.iter().position(|byte| *byte == 0xc3)?;
    let body = &window[..=ret_at];
    if body.len() < 16 {
        return None;
    }
    if count_occurrences(body, &PAGE_STEP) < 2 {
        return None;
    }
    if count_occurrences(body, &PROBE) < 1 {
        return None;
    }
    Some(BuiltinHit {
        name: "___chkstk_ms",
        confidence: 55,
        why: "字节形状与 GCC x64 的 chkstk.S 一致（两处 0x1000 页步进 + or [rcx],0 探测 + 直线代码在 ret 处结束）",
    })
}

/// 全部内置判据。判据之间不应重叠；命中就返回。
///
/// 加新判据时：先造出真实的样本、拿到第三方工具给的真值、量出误报，再往这里加。
#[must_use]
pub fn match_builtin(bytes: &[u8]) -> Option<BuiltinHit> {
    match_gcc_x64_stack_probe(bytes)
}

/// 子串出现次数（朴素实现：判据窗口最长 0x60 字节，不值得上 KMP）。
fn count_occurrences(haystack: &[u8], needle: &[u8]) -> usize {
    if needle.is_empty() || haystack.len() < needle.len() {
        return 0;
    }
    haystack
        .windows(needle.len())
        .filter(|window| *window == needle)
        .count()
}

#[cfg(test)]
mod tests {
    use super::*;

    /// `___chkstk_ms` 的实测字节（逐字节抄自 `tests/fixtures/generated/m8-builtins.golden.txt`
    /// 里 mingw objdump 的反汇编，50 字节）。
    ///
    /// 抄进来的原因：单元测试要能独立跑，不该依赖生成出来的 fixture。fixture 那边另有
    /// 一条端到端测试（`crates/bitflip-core/tests/m8_builtins.rs`）对着真样本验证。
    const GCC_X64_STACK_PROBE: [u8; 50] = [
        0x51, // push rcx
        0x50, // push rax
        0x48, 0x3d, 0x00, 0x10, 0x00, 0x00, // cmp rax, 0x1000
        0x48, 0x8d, 0x4c, 0x24, 0x18, // lea rcx, [rsp+0x18]
        0x72, 0x19, // jb +0x28
        0x48, 0x81, 0xe9, 0x00, 0x10, 0x00, 0x00, // sub rcx, 0x1000
        0x48, 0x83, 0x09, 0x00, // or [rcx], 0
        0x48, 0x2d, 0x00, 0x10, 0x00, 0x00, // sub rax, 0x1000
        0x48, 0x3d, 0x00, 0x10, 0x00, 0x00, // cmp rax, 0x1000
        0x77, 0xe7, // ja -0x19
        0x48, 0x29, 0xc1, // sub rcx, rax
        0x48, 0x83, 0x09, 0x00, // or [rcx], 0
        0x58, // pop rax
        0x59, // pop rcx
        0xc3, // ret
    ];

    #[test]
    fn the_real_gcc_stack_probe_is_recognised() {
        let hit = match_builtin(&GCC_X64_STACK_PROBE).expect("实测字节必须命中");
        assert_eq!(hit.name, "___chkstk_ms");
        assert!(hit.confidence > 0 && hit.confidence < 70, "形状是间接证据");
        assert!(hit.why.contains("0x1000"), "判据要写清楚：{}", hit.why);
    }

    #[test]
    fn the_probe_is_recognised_behind_trailing_padding() {
        // 边界未知时调用方会多给一些字节：第一条 `ret` 就是函数末尾，后面的填充不算数。
        let mut bytes = Vec::new();
        bytes.extend_from_slice(&GCC_X64_STACK_PROBE);
        bytes.extend_from_slice(&[0x90; 0x10]);
        assert!(
            match_builtin(&bytes).is_some(),
            "ret 之后的填充不该影响判定"
        );
    }

    #[test]
    fn a_body_without_a_ret_is_not_the_probe() {
        // 窗口里一条 ret 都没有 → 拿不到函数末尾 → 不认。
        let mut bytes = Vec::new();
        bytes.extend_from_slice(&GCC_X64_STACK_PROBE[..GCC_X64_STACK_PROBE.len() - 1]);
        assert!(match_builtin(&bytes).is_none());
    }

    #[test]
    fn a_plain_tiny_function_is_not_the_probe() {
        // 小函数：push rbp; mov rbp,rsp; mov eax,esi; pop rbp; ret —— 没有页步进、没有探测。
        let plain = [0x55, 0x48, 0x89, 0xe5, 0x89, 0xf0, 0x5d, 0xc3];
        assert!(match_builtin(&plain).is_none());
    }

    #[test]
    fn a_page_step_without_a_probe_is_not_enough() {
        // 只有 0x1000 常量、没有 `or [rcx],0`：可能是普通的栈对齐或数组清零，不能认。
        let mut bytes = Vec::new();
        bytes.extend_from_slice(&[0x48, 0x81, 0xec, 0x00, 0x10, 0x00, 0x00]); // sub rsp, 0x1000
        bytes.extend_from_slice(&[0x48, 0x2d, 0x00, 0x10, 0x00, 0x00]); // sub rax, 0x1000
        bytes.extend_from_slice(&[0x48, 0x83, 0xc4, 0x08, 0x5d, 0xc3]); // add rsp,8; pop rbp; ret
        assert!(match_builtin(&bytes).is_none());
    }

    #[test]
    fn a_probe_without_two_page_constants_is_not_enough() {
        // 一个 0x1000 + 探测指令：可能是别人的固定套路，证据不足。
        let mut bytes = Vec::new();
        bytes.extend_from_slice(&[0x48, 0x83, 0x09, 0x00]); // or [rcx], 0
        bytes.extend_from_slice(&[0x48, 0x81, 0xe9, 0x00, 0x10, 0x00, 0x00]); // sub rcx, 0x1000
        bytes.extend_from_slice(&[0x90, 0x90, 0x90, 0xc3]);
        assert!(match_builtin(&bytes).is_none());
    }
}
