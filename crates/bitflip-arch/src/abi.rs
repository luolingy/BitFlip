//! 调用约定（ABI）的**具体实现**：参数寄存器、返回值、栈帧与对齐。
//!
//! # 为什么现在才补
//!
//! `decode.rs` 里的 [`Abi`] trait 从 M0/M1 就定义了，但**一直没有实现** ——
//! M5 要求说清动态库的"导出 thunk、导入 stub"边界，没有 ABI 就只能显示
//! 汇编而说不出"参数从哪来、返回往哪去"。本模块把它填上。
//!
//! # 边界（重要）
//!
//! 这里只描述**寄存器级的约定**，即"第 N 个整型参数走哪个寄存器"这一类
//! 可以从架构直接确定的事实。不做：
//!
//! * 不推断某个函数**实际有**几个参数 —— 那要看调用点或调试信息，
//!   没有证据时编一个数字正是 CLAUDE.md §7 禁止的假象；
//! * 不处理浮点/向量参数的完整分配规则（x86_64 走 xmm0-7、
//!   AArch64 走 v0-7）—— 尚未支持，因此不假装支持；
//! * 不覆盖变参函数的复杂情形（x86_64 用 `al` 传递向量寄存器个数）。

use crate::decode::Abi;
use crate::insn::RegId;
use crate::types::{Arch, ArchSpec, Mode};

/// 寄存器名的内部表示：用 `&'static str` 保存，转换成 [`RegId`] 时查表。
///
/// 为什么不直接写 `RegId`：这些名字是**给人看的契约**（界面要显示
/// "参数：rdi, rsi"），而 `RegId` 是 capstone 的编号，`bitflip-arch`
/// 之外的读者无从验证。名字与编号的对应由 `CapstoneDecoder` 保证一致，
/// 这里保留名字作为事实来源。
macro_rules! reg {
    ($name:literal) => {
        $name
    };
}

/// 一个具体架构的调用约定实现。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AbiSpec {
    /// 关联的架构规格。
    pub spec: ArchSpec,
    /// 参数寄存器名（按调用顺序）。
    pub arg_reg_names: &'static [&'static str],
    /// 返回值寄存器名。
    pub ret_reg_name: &'static str,
    /// 帧指针寄存器名（`None` 表示该 ABI 允许省略）。
    pub frame_pointer_name: Option<&'static str>,
    /// 栈指针寄存器名。
    pub stack_pointer_name: &'static str,
    /// 被调用者保存的寄存器名。
    pub callee_saved_names: &'static [&'static str],
    /// 返回地址的存放方式。
    pub return_address: ReturnAddress,
    /// 栈对齐要求（字节）。
    pub stack_align: u32,
    /// 约定的中文名，用于界面展示。
    pub name_zh: &'static str,
}

/// 返回地址的存放方式。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ReturnAddress {
    /// 由 `call` 指令压栈（x86、x86_64）。
    OnStack,
    /// 写在链接寄存器里（AArch64 的 `x30`、ARM 的 `lr`、RISC-V 的 `ra`）。
    LinkRegister(&'static str),
}

impl ReturnAddress {
    /// 面向界面的中文说明。
    #[must_use]
    pub const fn label_zh(self) -> &'static str {
        match self {
            Self::OnStack => "返回地址压栈",
            Self::LinkRegister(_) => "返回地址在链接寄存器",
        }
    }
}

impl AbiSpec {
    /// 取第 `index` 个（从 0 起）整型参数的寄存器名。
    ///
    /// 超出寄存器序列时返回 `None` —— 表示"走栈传递"。
    /// **不返回编造的寄存器名**：调用方看到 `None` 应当显示"经栈传递"。
    #[must_use]
    pub fn arg_reg_name(&self, index: usize) -> Option<&'static str> {
        self.arg_reg_names.get(index).copied()
    }

    /// 第 `index` 个参数是否经栈传递。
    #[must_use]
    pub fn arg_is_on_stack(&self, index: usize) -> bool {
        index >= self.arg_reg_names.len()
    }

    /// 寄存器传参的个数上限。
    #[must_use]
    pub fn register_arg_count(&self) -> usize {
        self.arg_reg_names.len()
    }

    /// 该寄存器名是否被本约定用于传参。
    #[must_use]
    pub fn is_arg_register(&self, name: &str) -> bool {
        self.arg_reg_names.contains(&name)
    }

    /// 把寄存器名解析成 capstone 的 [`RegId`]。
    ///
    /// # 为什么必须查真实后端而不是写死编号
    ///
    /// `RegId` 是 capstone 的编号，跨架构没有统一规律；写死一张
    /// "rdi = 39" 的表在换后端（或 capstone 版本变更）时会**静默错位** ——
    /// 参数标注整体偏一到两个寄存器，而没有任何报错。
    ///
    /// 所以走 `CapstoneDecoder::register_id` 向真实后端要编号。
    /// 查不到就返回 `None`，调用方据此跳过该寄存器 —— 不猜。
    ///
    /// # 别名兜底（AArch64 的 x29/x30）
    ///
    /// ABI 表里存的是**约定名**，capstone 有它自己的一套名字，两者对
    /// 同一个寄存器可能不同：AArch64 的 `x29` 在 capstone 里叫 `fp`，
    /// `x30` 叫 `lr`（`x19`–`x28` 则与约定名一致）。
    ///
    /// 这个差异是**静默**的：`reg_id("x29")` 返回 `None` 而不报错，
    /// 于是"帧指针 = x29"这条规则永远匹配不上 —— AArch64 的帧指针识别
    /// 整体失效，前导扫描还会在第二条指令就停下。只有真实目标能暴露。
    ///
    /// 处理方式是查完原名再查已知别名，见 [`aliases_of`]。
    /// 别名表**小而明确**：只在两个名字确实指同一寄存器时登记，
    /// 不做模糊匹配 —— 拼错的名字应当解析失败，而不是碰巧命中别人。
    #[must_use]
    pub fn reg_id(&self, name: &str) -> Option<RegId> {
        if let Some(id) = crate::backend::CapstoneDecoder::register_id(self.spec, name) {
            return Some(id);
        }
        for alias in aliases_of(name) {
            if let Some(id) = crate::backend::CapstoneDecoder::register_id(self.spec, alias) {
                return Some(id);
            }
        }
        None
    }
}

/// 寄存器名的**等价名**表：ABI 约定名 ↔ capstone 的名字。
///
/// # 为什么需要这张表
///
/// 大部分寄存器在两边同名（`rax`、`rcx`、`x0`、`x19`…），所以直接查名
/// 就够了。但 AArch64 的两个寄存器是例外：capstone 用 ABI 别名而不是
/// 编号名 —— `x29` 叫 `fp`、`x30` 叫 `lr`。
///
/// 这个差异不会报错，只会让 `reg_id` 返回 `None`，于是依赖它的规则
/// （帧指针识别、被调用者保存寄存器核对）**静默失效**。所以必须显式
/// 登记，不能指望"名字总是对得上"。
///
/// # 维护约定
///
/// * 只登记**确实指同一个寄存器**的名字，两个方向都要写（查 `x29` 和
///   查 `fp` 都应当命中）。
/// * 不登记"长得像"的名字 —— 拼错的名字应当解析失败，而不是碰巧命中。
/// * 新增架构时，如果 ABI 表里的名字查不到，先确认是不是这类别名差异，
///   是就补进来，不是就修名字本身。
///
/// 返回该名字的全部等价名。
fn aliases_of(name: &str) -> &'static [&'static str] {
    const ALIASES: &[(&str, &[&str])] = &[
        // AArch64：x29 = 帧指针，capstone 叫 fp
        ("x29", &["fp"]),
        ("fp", &["x29"]),
        // AArch64：x30 = 链接寄存器，capstone 叫 lr
        ("x30", &["lr"]),
        ("lr", &["x30"]),
    ];
    ALIASES
        .iter()
        .find(|(n, _)| n.eq_ignore_ascii_case(name))
        .map(|(_, list)| *list)
        .unwrap_or(&[])
}

/// 参数寄存器序列。
const X86_64_SYSV_ARGS: &[&str] = &["rdi", "rsi", "rdx", "rcx", "r8", "r9"];
const X86_64_SYSV_CALLEE_SAVED: &[&str] = &["rbx", "rbp", "r12", "r13", "r14", "r15"];

/// Windows x64：前四个参数走 rcx/rdx/r8/r9。
const X86_64_WIN_ARGS: &[&str] = &["rcx", "rdx", "r8", "r9"];
const X86_64_WIN_CALLEE_SAVED: &[&str] = &["rbx", "rbp", "rdi", "rsi", "r12", "r13", "r14", "r15"];

const I386_CALLEE_SAVED: &[&str] = &["ebx", "esi", "edi", "ebp"];

const AARCH64_ARGS: &[&str] = &["x0", "x1", "x2", "x3", "x4", "x5", "x6", "x7"];
const AARCH64_CALLEE_SAVED: &[&str] = &[
    "x19", "x20", "x21", "x22", "x23", "x24", "x25", "x26", "x27", "x28", "x29", "x30",
];

/// ARM 32 位 AAPCS：r0-r3 传参，r11 帧指针，r13 栈，r14 链接。
const ARM_ARGS: &[&str] = &["r0", "r1", "r2", "r3"];
const ARM_CALLEE_SAVED: &[&str] = &["r4", "r5", "r6", "r7", "r8", "r9", "r10", "r11"];

const RISCV_ARGS: &[&str] = &["a0", "a1", "a2", "a3", "a4", "a5", "a6", "a7"];
const RISCV_CALLEE_SAVED: &[&str] = &[
    "s0", "s1", "s2", "s3", "s4", "s5", "s6", "s7", "s8", "s9", "s10", "s11",
];

const MIPS_ARGS: &[&str] = &["a0", "a1", "a2", "a3"];
const MIPS_CALLEE_SAVED: &[&str] = &["s0", "s1", "s2", "s3", "s4", "s5", "s6", "s7", "fp"];

/// 取某个架构规格下的调用约定。
///
/// `windows` 用于区分 x86_64 的两套约定 —— 它们的前四个参数寄存器
/// **完全不同**（rdi/rsi/rdx/rcx vs rcx/rdx/r8/r9），猜错会让参数标注
/// 整体偏移。因此必须由调用方（loader 知道目标是 PE 还是 ELF）显式告知，
/// 而不是在这里按文件扩展名猜。
///
/// WebAssembly 没有寄存器调用约定这套概念，返回 `None`。
#[must_use]
pub fn abi_for_spec(spec: ArchSpec, windows: bool) -> Option<AbiSpec> {
    let abi = match spec.arch {
        Arch::X86_64 if windows => AbiSpec {
            spec,
            arg_reg_names: X86_64_WIN_ARGS,
            ret_reg_name: reg!("rax"),
            frame_pointer_name: Some("rbp"),
            stack_pointer_name: "rsp",
            callee_saved_names: X86_64_WIN_CALLEE_SAVED,
            return_address: ReturnAddress::OnStack,
            stack_align: 16,
            name_zh: "Windows x64",
        },
        Arch::X86_64 => AbiSpec {
            spec,
            arg_reg_names: X86_64_SYSV_ARGS,
            ret_reg_name: reg!("rax"),
            frame_pointer_name: Some("rbp"),
            stack_pointer_name: "rsp",
            callee_saved_names: X86_64_SYSV_CALLEE_SAVED,
            return_address: ReturnAddress::OnStack,
            stack_align: 16,
            name_zh: "System V AMD64",
        },
        Arch::X86 => AbiSpec {
            spec,
            // i386 cdecl 是**栈传参**：普通参数不经过寄存器。
            // 如实标注为空序列，让"参数经栈传递"这个结论是确定的 ——
            // 而不是填一套看起来像寄存器传参的假序列。
            arg_reg_names: &[],
            ret_reg_name: reg!("eax"),
            frame_pointer_name: Some("ebp"),
            stack_pointer_name: "esp",
            callee_saved_names: I386_CALLEE_SAVED,
            return_address: ReturnAddress::OnStack,
            stack_align: 4,
            name_zh: "cdecl（栈传参）",
        },
        Arch::Aarch64 => AbiSpec {
            spec,
            arg_reg_names: AARCH64_ARGS,
            ret_reg_name: reg!("x0"),
            frame_pointer_name: Some("x29"),
            stack_pointer_name: "sp",
            callee_saved_names: AARCH64_CALLEE_SAVED,
            // `bl` 把返回地址写进 x30，`ret` 从 x30 读回。
            return_address: ReturnAddress::LinkRegister("x30"),
            stack_align: 16,
            name_zh: "AAPCS64",
        },
        Arch::Arm => AbiSpec {
            spec,
            arg_reg_names: ARM_ARGS,
            ret_reg_name: reg!("r0"),
            frame_pointer_name: Some("r11"),
            stack_pointer_name: "sp",
            callee_saved_names: ARM_CALLEE_SAVED,
            return_address: ReturnAddress::LinkRegister("lr"),
            // AAPCS 在公共接口处要求 8 字节对齐。
            stack_align: 8,
            // Thumb 与 ARM 用**同一套** AAPCS 寄存器约定，区别只在指令
            // 编码与 PC 的读取方式，因此不分模式，但名称要标出来。
            name_zh: if spec.mode == Mode::Thumb {
                "AAPCS（Thumb 状态）"
            } else {
                "AAPCS（ARM 状态）"
            },
        },
        Arch::Riscv32 | Arch::Riscv64 => AbiSpec {
            spec,
            arg_reg_names: RISCV_ARGS,
            ret_reg_name: reg!("a0"),
            frame_pointer_name: Some("s0"),
            stack_pointer_name: "sp",
            callee_saved_names: RISCV_CALLEE_SAVED,
            return_address: ReturnAddress::LinkRegister("ra"),
            stack_align: 16,
            name_zh: "RISC-V psABI",
        },
        Arch::Mips | Arch::Mips64 => AbiSpec {
            spec,
            arg_reg_names: MIPS_ARGS,
            ret_reg_name: reg!("v0"),
            frame_pointer_name: Some("fp"),
            stack_pointer_name: "sp",
            callee_saved_names: MIPS_CALLEE_SAVED,
            return_address: ReturnAddress::LinkRegister("ra"),
            stack_align: 8,
            name_zh: "MIPS o32",
        },
        // WebAssembly 是栈式虚拟机，没有寄存器调用约定。
        // 返回 None 而不是硬套一套寄存器名。
        Arch::Wasm32 => return None,
    };
    // 注意：返回值寄存器**可以**同时是参数寄存器（AArch64 的 x0 既是
    // 第一个参数、也是返回值；ARM 的 r0 同理）。这是 AAPCS 的事实，
    // 不是配置错误 —— 早先在构造时"发现重复就清空"的做法会静默丢掉
    // 返回值信息，比不做检查更糟。
    Some(abi)
}

impl AbiSpec {
    /// 参数寄存器的 [`RegId`] 列表（按调用顺序）。
    ///
    /// 任何一个名字解析失败就**整体返回 `None`**：宁可说"这个架构的
    /// 参数推断不支持"，也不要给出一个少了一个寄存器的序列 ——
    /// 那会让后面所有参数的位置都错一位。
    #[must_use]
    pub fn arg_reg_ids(&self) -> Option<Vec<RegId>> {
        let mut out = Vec::with_capacity(self.arg_reg_names.len());
        for name in self.arg_reg_names {
            out.push(self.reg_id(name)?);
        }
        Some(out)
    }
}

impl Abi for AbiSpec {
    fn spec(&self) -> ArchSpec {
        self.spec
    }

    fn arg_regs(&self) -> &'static [RegId] {
        // 名字→编号的映射是运行期查 capstone 得到的，不是编译期常量，
        // 因此这里无法返回 `&'static [RegId]`。
        //
        // 需要编号请用 [`AbiSpec::arg_reg_ids`]（失败时返回 `None`，
        // 语义比"空表"明确）；需要名字请用
        // [`AbiSpec::arg_reg_names`]。
        &[]
    }

    fn return_reg(&self) -> RegId {
        // 同上：编号映射落地前返回 0，并**不声称**它就是返回值寄存器。
        // 需要名字时用 [`AbiSpec::ret_reg_name`]。
        RegId(0)
    }

    fn stack_pointer(&self) -> RegId {
        RegId(0)
    }

    fn frame_pointer(&self) -> Option<RegId> {
        None
    }

    fn is_callee_saved(&self, _reg: RegId) -> bool {
        false
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn spec(arch: Arch, mode: Mode) -> ArchSpec {
        ArchSpec::from_arch(arch, mode, arch.preferred_endian())
    }

    /// 名字到编号的映射必须真的能查到，且两套约定不混淆。
    ///
    /// 这条测试存在的理由：`arg_regs()` 长期返回空表（编号映射没建），
    /// 于是"参数推断"根本无从下手 —— `bitflip-analyze` 只能对所有函数
    /// 报"没有参数"。补齐映射后要有人盯着它别悄悄退化：一旦查不到，
    /// 参数推断会**静默**返回空结论，不报错。
    #[test]
    fn register_names_resolve_to_ids() {
        let sysv = abi_for_spec(spec(Arch::X86_64, Mode::M64), false).expect("sysv");
        let win = abi_for_spec(spec(Arch::X86_64, Mode::M64), true).expect("win");

        // SysV 第 1 个参数是 rdi，Windows 是 rcx —— 必须都能查到且不同
        let rdi = sysv.reg_id("rdi").expect("rdi 应当能解析");
        let rcx = win.reg_id("rcx").expect("rcx 应当能解析");
        assert_ne!(rdi, rcx, "rdi 与 rcx 是不同的寄存器");

        let ids = sysv.arg_reg_ids().expect("SysV 参数寄存器应当全部可解析");
        assert_eq!(ids.len(), sysv.arg_reg_names.len());
        assert_eq!(ids[0], rdi, "第 1 个是 rdi");
        for (i, id) in ids.iter().enumerate() {
            assert_eq!(
                sysv.reg_id(sysv.arg_reg_names[i]),
                Some(*id),
                "第 {i} 个名字与编号必须一致"
            );
        }

        // 返回值寄存器（rax）也要能查到 —— 变参检测要用
        assert!(sysv.reg_id("rax").is_some(), "rax 应当能解析");

        // 不存在的名字应当返回 None，而不是撞上某个寄存器
        assert_eq!(sysv.reg_id("not_a_register"), None);
    }

    /// 每个有 ABI 的架构，参数寄存器都必须能全部解析出来。
    ///
    /// 解析不出来时 `arg_reg_ids()` 返回 `None`，上层据此说"该架构不支持
    /// 参数推断" —— 可接受的降级。但**本可以支持却查不到**会让用户白白
    /// 失去这项能力，所以在这里把每个架构都试一遍。
    /// AArch64 的 `x29`/`x30` 在 capstone 里叫 `fp`/`lr`，靠别名表兜底。
    ///
    /// 这条测试是**真实目标暴露出来的**：没有别名时 `reg_id("x29")`
    /// 返回 `None` 而不报错，于是"帧指针 = x29"永远匹配不上 ——
    /// AArch64 的帧指针识别整体失效，前导扫描在第二条指令就停下。
    #[test]
    fn aarch64_frame_pointer_and_link_register_resolve_via_aliases() {
        let abi = abi_for_spec(spec(Arch::Aarch64, Mode::M64), false).expect("AAPCS64");
        assert_eq!(abi.frame_pointer_name, Some("x29"));

        // 约定名必须能查到编号 —— 这是帧指针识别的前提
        let fp = abi
            .reg_id("x29")
            .expect("x29 必须能解析（capstone 里叫 fp，靠别名兜底）");
        // 别名另一方向也要能查到同一个编号
        assert_eq!(abi.reg_id("fp"), Some(fp), "fp 与 x29 必须指向同一编号");

        let lr = abi
            .reg_id("x30")
            .expect("x30 必须能解析（capstone 里叫 lr，靠别名兜底）");
        assert_eq!(abi.reg_id("lr"), Some(lr), "lr 与 x30 必须指向同一编号");

        // 帧指针和链接寄存器不能是同一个寄存器
        assert_ne!(fp, lr, "x29 与 x30 必须是不同的寄存器");
    }

    /// 别名表不能变成"什么都查得到"：拼错的名字必须解析失败。
    #[test]
    fn unknown_register_names_still_fail_to_resolve() {
        let abi = abi_for_spec(spec(Arch::Aarch64, Mode::M64), false).expect("AAPCS64");
        for bogus in ["x29x", "xx29", "fpp", "", "r29", "rax"] {
            assert_eq!(
                abi.reg_id(bogus),
                None,
                "{bogus:?} 不该解析成功（别名表不能做模糊匹配）"
            );
        }
    }

    #[test]
    fn every_supported_arch_can_resolve_its_argument_registers() {
        for arch in [
            Arch::X86_64,
            Arch::X86,
            Arch::Aarch64,
            Arch::Arm,
            Arch::Riscv64,
            Arch::Riscv32,
            Arch::Mips,
            Arch::Mips64,
        ] {
            for windows in [false, true] {
                let mode = match arch {
                    Arch::X86_64 | Arch::Aarch64 | Arch::Riscv64 | Arch::Mips64 => Mode::M64,
                    _ => Mode::M32,
                };
                let Some(abi) = abi_for_spec(spec(arch, mode), windows) else {
                    continue;
                };
                let ids = abi.arg_reg_ids().unwrap_or_else(|| {
                    panic!(
                        "{arch:?}（windows={windows}）的参数寄存器解析失败：{:?}",
                        abi.arg_reg_names
                    )
                });
                assert_eq!(
                    ids.len(),
                    abi.arg_reg_names.len(),
                    "{arch:?} 解析出的数量与名字表不一致"
                );
                let unique: std::collections::BTreeSet<u16> = ids.iter().map(|r| r.0).collect();
                assert_eq!(
                    unique.len(),
                    ids.len(),
                    "{arch:?} 的参数寄存器编号有重复：{ids:?}"
                );
            }
        }
    }

    #[test]
    fn x86_64_sysv_and_windows_differ_in_the_first_four_registers() {
        let sysv = abi_for_spec(spec(Arch::X86_64, Mode::M64), false).expect("sysv");
        let win = abi_for_spec(spec(Arch::X86_64, Mode::M64), true).expect("win");

        assert_eq!(sysv.arg_reg_name(0), Some("rdi"));
        assert_eq!(win.arg_reg_name(0), Some("rcx"));
        assert_ne!(
            sysv.arg_reg_names, win.arg_reg_names,
            "两套 x86_64 约定的参数寄存器必须不同 —— 混淆会让参数标注整体偏移"
        );
        assert_eq!(sysv.ret_reg_name, win.ret_reg_name, "返回寄存器相同");
    }

    #[test]
    fn aarch64_follows_aapcs64() {
        let abi = abi_for_spec(spec(Arch::Aarch64, Mode::M64), false).expect("aarch64");
        assert_eq!(abi.arg_reg_name(0), Some("x0"));
        assert_eq!(abi.arg_reg_name(7), Some("x7"));
        // 第 9 个参数（下标 8）走栈，不能编一个寄存器出来
        assert_eq!(abi.arg_reg_name(8), None);
        assert!(abi.arg_is_on_stack(8));
        assert_eq!(abi.register_arg_count(), 8);
        assert_eq!(abi.return_address, ReturnAddress::LinkRegister("x30"));
        assert_eq!(abi.stack_align, 16);
    }

    #[test]
    fn arm_uses_r0_to_r3_and_thumb_shares_the_same_registers() {
        let arm = abi_for_spec(spec(Arch::Arm, Mode::M32), false).expect("arm");
        let thumb = abi_for_spec(spec(Arch::Arm, Mode::Thumb), false).expect("thumb");

        assert_eq!(arm.arg_reg_name(0), Some("r0"));
        assert_eq!(arm.arg_reg_name(3), Some("r3"));
        assert_eq!(arm.arg_reg_name(4), None, "第 5 个参数走栈");
        // Thumb 与 ARM 共用 AAPCS 寄存器约定，只有名称需要区分
        assert_eq!(arm.arg_reg_names, thumb.arg_reg_names);
        assert_eq!(arm.ret_reg_name, thumb.ret_reg_name);
        assert_ne!(arm.name_zh, thumb.name_zh, "名称要能区分 ARM/Thumb 状态");
    }

    #[test]
    fn i386_reports_stack_passing_rather_than_inventing_registers() {
        let abi = abi_for_spec(spec(Arch::X86, Mode::M32), false).expect("i386");
        assert!(
            abi.arg_reg_names.is_empty(),
            "i386 cdecl 是栈传参，参数寄存器序列必须为空"
        );
        assert!(abi.arg_is_on_stack(0), "第一个参数就已经在栈上");
        assert!(!abi.is_arg_register("rdi"), "rdi 不属于 i386");
    }

    #[test]
    fn wasm_has_no_register_abi() {
        assert!(
            abi_for_spec(spec(Arch::Wasm32, Mode::M32), false).is_none(),
            "WASM 是栈式虚拟机，不该硬套一套寄存器约定"
        );
    }

    #[test]
    fn every_abi_has_a_stack_pointer_and_a_return_path() {
        for arch in [
            Arch::X86,
            Arch::X86_64,
            Arch::Aarch64,
            Arch::Arm,
            Arch::Riscv32,
            Arch::Riscv64,
            Arch::Mips,
            Arch::Mips64,
        ] {
            let s = spec(arch, arch.default_mode());
            let abi = abi_for_spec(s, false).unwrap_or_else(|| panic!("{arch:?} 应当有调用约定"));
            assert!(!abi.stack_pointer_name.is_empty(), "{arch:?} 缺栈指针");
            assert!(!abi.ret_reg_name.is_empty(), "{arch:?} 缺返回寄存器");
            assert!(abi.stack_align > 0, "{arch:?} 栈对齐必须为正");
            assert!(!abi.name_zh.is_empty(), "{arch:?} 缺中文名");
        }
    }

    #[test]
    fn return_register_may_also_be_the_first_argument_register() {
        // AArch64 的 x0 与 ARM 的 r0 既是第一个参数、也是返回值。
        // 这是 AAPCS 的事实，不该被当成配置错误"修正"掉 ——
        // 早先的实现在构造时发现重复就清空返回寄存器，等于静默丢信息。
        for arch in [Arch::Aarch64, Arch::Arm] {
            let s = spec(arch, arch.default_mode());
            let abi = abi_for_spec(s, false).expect("abi");
            assert_eq!(
                abi.arg_reg_name(0),
                Some(abi.ret_reg_name),
                "{arch:?} 的第一个参数寄存器应当就是返回寄存器"
            );
        }
    }

    #[test]
    fn windows_flag_only_affects_x86_64() {
        // 其他架构不受 PE/ELF 影响：传 true 结果应当一致，
        // 否则说明某个分支误用了 windows 标志。
        for arch in [Arch::Aarch64, Arch::Arm, Arch::Riscv64] {
            let s = spec(arch, arch.default_mode());
            let a = abi_for_spec(s, false).expect("elf");
            let b = abi_for_spec(s, true).expect("pe");
            assert_eq!(
                a.arg_reg_names, b.arg_reg_names,
                "{arch:?} 的参数寄存器不该因 windows 标志而变"
            );
            assert_eq!(
                a.name_zh, b.name_zh,
                "{arch:?} 的名称不该因 windows 标志而变"
            );
        }
    }
}
