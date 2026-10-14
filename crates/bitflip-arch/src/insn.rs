//! 结构化指令表示与寄存器集合。

use std::fmt;

use crate::types::Arch;

/// interned 之后的助记符编号。
///
/// 真实实现里助记符存在全局字符串池中，指令只保存 `u32` 索引；
/// `0` 保留给"未解析"，避免用 `String` 逐条指令分配内存（adi 的 OOM 教训）。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct MnemonicId(pub u32);

impl MnemonicId {
    /// 未解析 / 非法指令。
    pub const UNKNOWN: Self = Self(0);

    /// 原始编号。
    #[must_use]
    pub const fn get(self) -> u32 {
        self.0
    }

    /// 是否为未解析指令。
    #[must_use]
    pub const fn is_unknown(self) -> bool {
        self.0 == Self::UNKNOWN.0
    }
}

/// 架构内的寄存器编号（具体含义由 [`crate::Abi`] 实现解释）。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct RegId(pub u16);

/// 寄存器集合（上限 256 个寄存器，足够覆盖当前所有目标架构）。
///
/// 用位图而不是 `Vec<RegId>`：解码热路径上不允许分配。
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct RegSet {
    bits: [u64; 4],
}

impl RegSet {
    /// 空集合。
    #[must_use]
    pub const fn new() -> Self {
        Self { bits: [0; 4] }
    }

    /// 加入一个寄存器。
    pub fn insert(&mut self, reg: RegId) {
        let idx = usize::from(reg.0);
        if idx < 256 {
            self.bits[idx / 64] |= 1u64 << (idx % 64);
        }
    }

    /// 是否包含该寄存器。
    #[must_use]
    pub fn contains(&self, reg: RegId) -> bool {
        let idx = usize::from(reg.0);
        idx < 256 && self.bits[idx / 64] & (1u64 << (idx % 64)) != 0
    }

    /// 是否为空集。
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.bits.iter().all(|w| *w == 0)
    }

    /// 元素个数。
    #[must_use]
    pub fn len(&self) -> usize {
        self.bits.iter().map(|w| w.count_ones() as usize).sum()
    }

    /// 迭代其中的寄存器。
    #[must_use]
    pub fn iter(&self) -> RegSetIter {
        RegSetIter {
            bits: self.bits,
            word: 0,
            index: 0,
            current: 0,
        }
    }
}

impl FromIterator<RegId> for RegSet {
    fn from_iter<T: IntoIterator<Item = RegId>>(iter: T) -> Self {
        let mut set = Self::new();
        for reg in iter {
            set.insert(reg);
        }
        set
    }
}

impl IntoIterator for &RegSet {
    type Item = RegId;
    type IntoIter = RegSetIter;

    fn into_iter(self) -> RegSetIter {
        self.iter()
    }
}

/// [`RegSet`] 的迭代器。
#[derive(Debug, Clone)]
pub struct RegSetIter {
    bits: [u64; 4],
    word: usize,
    index: usize,
    current: u64,
}

impl RegSetIter {
    /// 下一个非空字的下标；`None` 表示已耗尽。
    fn load_next_word(&mut self) -> Option<()> {
        while self.word < self.bits.len() {
            let word = self.bits[self.word];
            if word != 0 {
                self.current = word;
                // word 指向**当前**正在消费的字；自增发生在取到非空字之后，
                // 这样下面的下标计算不必再减 1（早先版本在这里少减一次，
                // 命中了 word==0 时的减法溢出）。
                self.index = self.word;
                self.word += 1;
                return Some(());
            }
            self.word += 1;
        }
        None
    }
}

impl Iterator for RegSetIter {
    type Item = RegId;

    fn next(&mut self) -> Option<RegId> {
        if self.current == 0 {
            self.load_next_word()?;
        }
        let bit = self.current.trailing_zeros() as usize;
        self.current &= self.current - 1;
        let index = self.index * 64 + bit;
        Some(RegId(index as u16))
    }
}

/// 内存操作数。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct MemRef {
    /// 基址寄存器。
    pub base: Option<RegId>,
    /// 索引寄存器。
    pub index: Option<RegId>,
    /// 索引比例（1/2/4/8）。
    pub scale: u8,
    /// 索引寄存器的**扩展修饰**（AArch64 的 `sxtw` / `uxtw` 等）。
    ///
    /// 为什么不并进 `scale`：x86 的 SIB 只能给索引一个比例，而 AArch64 还能
    /// 对索引做符号/零扩展 —— `[x9, w8, sxtw #3]` 与 `[x9, w8, lsl #3]`
    /// 在索引为负时**有效地址不同**，不是"同一个东西的两种写法"。
    ///
    /// `scale` 仍然是**有效比例**（`1 << 移位量`）；这个字段只回答
    /// "扩展是有符号还是无符号"。x86 上恒为 `None`。
    pub index_extend: Option<ShiftKind>,
    /// 位移（已按符号扩展）。
    pub disp: i64,
    /// 访问宽度（字节）。
    pub size: u8,
    /// 是否为写访问（读改写视为写）。
    pub write: bool,
}

/// 操作数。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Operand {
    /// 寄存器。
    Reg(RegId),
    /// 立即数。
    Imm(i64),
    /// 内存引用。
    Mem(MemRef),
    /// 相对于当前指令的位移（rip-relative / PC-relative），值是**相对偏移**。
    PcRelative(i64),
    /// 寄存器 + 移位/扩展修饰（AArch64 `add w10, w8, w10, lsl #1` 里的
    /// `lsl #1`；AArch32 的 `LSL #n` / `ASR #n`）。
    ///
    /// ## 为什么必须单独建模，不能丢掉
    ///
    /// `add w10, w8, w10` 与 `add w10, w8, w10, lsl #1` 算的是**不同的东西**
    /// （后者等于 `w8 + 2*w10`）。移位信息若在解码时被丢弃，反汇编会显示成
    /// 一条语法正确、语义错误的指令 —— 这是最难被发现的一类错误：
    /// 输出看起来完全合理，只有对着外部反汇编器逐条比才能看出来。
    ///
    /// 之前在 `convert_arm64_operand` 里正是这么丢的（capstone 把它放在
    /// `op.shift`，而转换只取了 `reg`）。本变体是那个 bug 的修复。
    Shifted {
        /// 被修饰的寄存器。
        reg: RegId,
        /// 移位/扩展类型。
        kind: ShiftKind,
        /// 移位量（位）。
        amount: u32,
    },
    /// AArch64 系统寄存器：`mrs x19, TPIDR_EL0` 的第二个操作数。
    SysReg(SysRegRef),
    /// AArch64 PState 字段：`msr DAIFSet, #0x2` 的 `DAIFSet`。
    Pstate(PstateField),
    /// AArch64 内存屏障选项：`dsb sy` 的 `sy`。
    ///
    /// `dsb` / `dsb sy` / `dsb ish` 是**三条不同的屏障**，丢掉这个操作数
    /// 等于把"全系统屏障"显示成一条语义不明、但看起来合法的指令。
    Barrier(BarrierOption),
    /// AArch64 预取操作：`prfm pldl1keep, [x1]` 的 `pldl1keep`。
    ///
    /// ## 为什么是 `Option`，而且现在只会是 `None`
    ///
    /// capstone 的 AArch64 detail **从不为预取操作数赋值**：`AArch64InstPrinter.c`
    /// 会写 `BARRIER`/`CIMM`/`FP`/`IMM`/`MEM`/`PSTATE`/`REG`/`REG_MRS`/
    /// `SME_INDEX`/`SVCR`/`SYS` 十一种，唯独没有 `ARM64_OP_PREFETCH`
    /// （它只出现在 `arm64.h` 的枚举和 `cstool` 里）。所以 `prfm` 的 detail
    /// 里只有那个内存操作数。
    ///
    /// 但**操作数位置确实存在**（`prfm` 的第一操作数就是 prfop），所以建模成
    /// "位置在、值拿不到"：渲染层打 `<prefetch:?>`，而不是输出看着完整的
    /// `prfm [x1]`（CLAUDE.md §7：拿不到就说拿不到）。
    ///
    /// 证据、以及"从指令第 5 位取 prfop"的可选方案，见
    /// `docs/research/capstone-prefetch-operand.md`。
    /// 若将来 capstone 补上这个字段，`Some` 分支自动生效，渲染层不用改。
    Prefetch(Option<PrefetchOp>),
    /// AArch64 系统指令的子操作：`dc civac, x0` 的 `civac`、
    /// `tlbi vmalle1` 的 `vmalle1`（IC/DC/AT/TLBI 四族）。
    ///
    /// ## 为什么它现在渲染成"未识别"
    ///
    /// capstone 把这四族的子操作合并成一个 **210 个成员**的枚举
    /// （`arm64_sys_op`：TLBI 164 / DC 28 / AT 14 / IC 3）。本版本**还没有**
    /// 把这 210 个名字落成表，所以渲染层如实打出 `<sys_op:22>` 这样的标记，
    /// 而不是把操作数丢掉。
    ///
    /// 丢掉会怎样：`dc civac, x0` 变成 `dc x0` —— 一条语法正确、但**不存在**
    /// 的指令。用户看不出这里少了东西，这正是 CLAUDE.md §7 禁止的失败模式。
    ///
    /// 补名字的地方就在这个变体：把 `SysOpRef` 换成"名字 + 原始值"即可，
    /// 渲染层跟着改一处。
    SysOp(SysOpRef),
    /// AArch64 浮点立即数（`fmov s0, #1.0`）。
    ///
    /// 载荷是 IEEE-754 双精度的**原始位**而不是 `f64`：这个枚举要能
    /// `Eq`/`Hash`（下游按值比较指令），而 `f64` 不是 `Eq`。
    /// 用位也顺带保证了"原样保留"，不做任何转换。
    FpImm(u64),
    /// AArch64 `SMSTART` / `SMSTOP` 的模式。
    Svcr(SvcrMode),
    /// AArch64 SME 的索引操作数（`za`/`zv` 的 `[x0, #0]` 形式）。
    ///
    /// 我们**不知道**它的 ARM 写法，所以只标记、不编造（§6.11：照自己的
    /// 猜测拼格式，错了会静悄悄地错）。ARMv9 SME 在 Android 目标里目前
    /// 不会出现，因此这里有意不建模。
    SmeIndex,
}

/// AArch64 系统寄存器引用（`mrs` / `msr` 的目标）。
///
/// 载荷是**原始编码**，不是"查表得到的名字"。原因见 `render.rs` 的
/// `format_sysreg`：ARM 为每一个编码都定义了规范写法
/// （`S<op0>_<op1>_C<CRn>_<CRm>_<op2>`），所以这个编码本身就是完整的、
/// 可查的表示，不需要（也不应该）再抄一张上千条的名字表进来。
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct SysRegRef {
    /// 指令里那个 16 位系统寄存器字段（`(word >> 5) & 0xffff`）。
    ///
    /// 类型是 `u32` 而不是 `u16`：万一上游给的字段比 16 位宽，我们要能
    /// **如实**把它带出来，而不是截断（截断是把数据悄悄改掉）。
    /// 渲染层对超出 16 位的值会打上明确标记，见 `format_sysreg`。
    pub raw: u32,
}

/// AArch64 的 IC/DC/AT/TLBI 子操作引用。
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct SysOpRef {
    /// capstone 的 `arm64_sys_op` 判别值。
    ///
    /// 保留它是为了让"未识别"这件事**可追查**：拿着这个数能直接对上
    /// capstone 的头文件（`.cargo-home/.../capstone-sys-0.18.0/capstone/
    /// include/capstone/arm64.h` 的 `arm64_sys_op`）。
    pub raw: u32,
}

/// AArch64 PState 字段（`msr` 的目标）。
///
/// 拼写按 ARM 汇编的**大小写**（`DAIFSet` 不是 `DAIFSET`）—— 与
/// LLVM/GNU as 一致，便于逐条对拍。
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum PstateField {
    /// 栈指针选择。
    Spsel,
    /// 置位 `DAIF` 的屏蔽位。
    DaifSet,
    /// 清零 `DAIF` 的屏蔽位。
    DaifClr,
    /// 特权访问禁止。
    Pan,
    /// 非特权访问覆盖。
    Uao,
    /// 数据独立定时。
    Dit,
}

impl PstateField {
    /// ARM 汇编里的写法。
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Spsel => "SPSel",
            Self::DaifSet => "DAIFSet",
            Self::DaifClr => "DAIFClr",
            Self::Pan => "PAN",
            Self::Uao => "UAO",
            Self::Dit => "DIT",
        }
    }
}

/// AArch64 内存屏障选项（`dsb` / `dmb` / `isb` 的操作数）。
///
/// 取值与拼写来自 capstone 的 `arm64_barrier_op`（头文件 arm64.h 里带
/// 显式数值），不是我们自己编号的。
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum BarrierOption {
    /// 外部共享域，仅读屏障。
    Oshld,
    /// 外部共享域，仅写屏障。
    Oshst,
    /// 外部共享域，读写屏障。
    Osh,
    /// 非共享域，仅读。
    Nshld,
    /// 非共享域，仅写。
    Nshst,
    /// 非共享域，读写。
    Nsh,
    /// 内部共享域，仅读。
    Ishld,
    /// 内部共享域，仅写。
    Ishst,
    /// 内部共享域，读写（多核 SMP 上最常用）。
    Ish,
    /// 仅读。
    Ld,
    /// 仅写。
    St,
    /// 全系统（最强）。
    Sy,
}

impl BarrierOption {
    /// ARM 汇编里的写法。
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Oshld => "oshld",
            Self::Oshst => "oshst",
            Self::Osh => "osh",
            Self::Nshld => "nshld",
            Self::Nshst => "nshst",
            Self::Nsh => "nsh",
            Self::Ishld => "ishld",
            Self::Ishst => "ishst",
            Self::Ish => "ish",
            Self::Ld => "ld",
            Self::St => "st",
            Self::Sy => "sy",
        }
    }
}

/// AArch64 预取操作（`prfm` / `prfum` 的操作数）。
///
/// 拼写与取值来自 capstone 的 `arm64_prefetch_op`。
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum PrefetchOp {
    /// 预取到 L1，数据会再次使用。
    Pldl1Keep,
    /// 预取到 L1，数据只用一次（流式）。
    Pldl1Strm,
    /// 预取到 L2，会再次使用。
    Pldl2Keep,
    /// 预取到 L2，流式。
    Pldl2Strm,
    /// 预取到 L3，会再次使用。
    Pldl3Keep,
    /// 预取到 L3，流式。
    Pldl3Strm,
    /// 取指令到 L1，会再次使用。
    Plil1Keep,
    /// 取指令到 L1，流式。
    Plil1Strm,
    /// 取指令到 L2，会再次使用。
    Plil2Keep,
    /// 取指令到 L2，流式。
    Plil2Strm,
    /// 取指令到 L3，会再次使用。
    Plil3Keep,
    /// 取指令到 L3，流式。
    Plil3Strm,
    /// 为写预取到 L1，会再次使用。
    Pstl1Keep,
    /// 为写预取到 L1，流式。
    Pstl1Strm,
    /// 为写预取到 L2，会再次使用。
    Pstl2Keep,
    /// 为写预取到 L2，流式。
    Pstl2Strm,
    /// 为写预取到 L3，会再次使用。
    Pstl3Keep,
    /// 为写预取到 L3，流式。
    Pstl3Strm,
}

impl PrefetchOp {
    /// ARM 汇编里的写法。
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Pldl1Keep => "pldl1keep",
            Self::Pldl1Strm => "pldl1strm",
            Self::Pldl2Keep => "pldl2keep",
            Self::Pldl2Strm => "pldl2strm",
            Self::Pldl3Keep => "pldl3keep",
            Self::Pldl3Strm => "pldl3strm",
            Self::Plil1Keep => "plil1keep",
            Self::Plil1Strm => "plil1strm",
            Self::Plil2Keep => "plil2keep",
            Self::Plil2Strm => "plil2strm",
            Self::Plil3Keep => "plil3keep",
            Self::Plil3Strm => "plil3strm",
            Self::Pstl1Keep => "pstl1keep",
            Self::Pstl1Strm => "pstl1strm",
            Self::Pstl2Keep => "pstl2keep",
            Self::Pstl2Strm => "pstl2strm",
            Self::Pstl3Keep => "pstl3keep",
            Self::Pstl3Strm => "pstl3strm",
        }
    }
}

/// AArch64 `SMSTART` / `SMSTOP` 的模式。
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum SvcrMode {
    /// 只切流式 SVE 模式。
    Sm,
    /// 只切 ZA 存储。
    Za,
    /// 两者一起。
    SmZa,
}

impl SvcrMode {
    /// ARM 汇编里的写法。
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Sm => "sm",
            Self::Za => "za",
            Self::SmZa => "smza",
        }
    }
}

/// 移位/扩展类型（AArch64 的 `LSL/LSR/ASR/ROR` 与 `UXTB` 系列）。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ShiftKind {
    /// 逻辑左移。
    Lsl,
    /// 逻辑右移。
    Lsr,
    /// 算术右移。
    Asr,
    /// 循环右移。
    Ror,
    /// 无符号扩展字节。
    Uxtb,
    /// 无符号扩展半字。
    Uxth,
    /// 无符号扩展字（32→64）。
    Uxtw,
    /// 无符号扩展双字（AArch64 里是空操作，但编码允许）。
    Uxtx,
    /// 有符号扩展字节。
    Sxtb,
    /// 有符号扩展半字。
    Sxth,
    /// 有符号扩展字。
    Sxtw,
    /// 有符号扩展双字。
    Sxtx,
}

impl ShiftKind {
    /// 稳定的汇编文本（小写，与 capstone/LLVM 一致）。
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Lsl => "lsl",
            Self::Lsr => "lsr",
            Self::Asr => "asr",
            Self::Ror => "ror",
            Self::Uxtb => "uxtb",
            Self::Uxth => "uxth",
            Self::Uxtw => "uxtw",
            Self::Uxtx => "uxtx",
            Self::Sxtb => "sxtb",
            Self::Sxth => "sxth",
            Self::Sxtw => "sxtw",
            Self::Sxtx => "sxtx",
        }
    }

    /// 是否是扩展（`Uxtb`…）而非移位。扩展类通常不写移位量，
    /// 除非量不为 0（例如 `uxtw #2`）。
    #[must_use]
    pub const fn is_extend(self) -> bool {
        matches!(
            self,
            Self::Uxtb
                | Self::Uxth
                | Self::Uxtw
                | Self::Uxtx
                | Self::Sxtb
                | Self::Sxth
                | Self::Sxtw
                | Self::Sxtx
        )
    }
}

/// 控制流语义。上层判断"是不是跳转/调用/返回"只看这里，不看助记符文本。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Flow {
    /// 顺序执行到下一字节。
    Fallthrough,
    /// 分支。`conditional` 为真时同时存在跳转目标与顺序后继。
    Branch {
        /// 是否有条件（为假时仅跳转目标一个后继）。
        conditional: bool,
    },
    /// 调用。
    Call,
    /// 返回。
    Return,
    /// 陷入 / 断点 / 系统调用等异常流。
    Trap,
    /// 解码失败或未知语义（字节仍在地址空间里，但不可解释为已知控制流）。
    Unknown,
}

impl Flow {
    /// 是否终止基本块（调用不终止，控制会回到下一条指令）。
    #[must_use]
    pub const fn ends_block(self) -> bool {
        matches!(self, Self::Branch { .. } | Self::Return | Self::Trap)
    }

    /// 是否存在顺序后继。
    #[must_use]
    pub const fn has_fallthrough(self) -> bool {
        match self {
            Self::Fallthrough | Self::Call => true,
            Self::Branch { conditional } => conditional,
            Self::Return | Self::Trap | Self::Unknown => false,
        }
    }
}

/// 条件码（AArch64 `b.lt` 的 `lt`、AArch32 的 `BEQ` 的 `eq`）。
///
/// ## 为什么必须单独建模
///
/// 条件码**不在** capstone 的指令 id 里：`b.lt` 与 `b` 的 `InsnId` 相同，
/// 差别只在编码的 cc 字段里。因此"用 InsnId 查助记符"必然得到裸 `b`。
///
/// 后果不是排版问题而是**语义问题**：
/// - `b 0x210294` 是无条件跳转 —— 执行流一定去那里，**没有顺序后继**；
/// - `b.lt 0x210294` 是条件跳转 —— 条件为假时**继续往下执行**。
///
/// 文本上少一个 `.lt`，读者（和写脚本的人）就会对这段代码的控制流得出
/// 相反的结论。CFG 分析幸好用的是结构化的 `Flow::Branch { conditional }`，
/// 所以跳转后继是对的；错的是给用户看的文本 —— 而文本同样要真。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ConditionCode {
    /// `eq` —— 相等。
    Equal,
    /// `ne` —— 不等。
    NotEqual,
    /// `hs` / `cs` —— 无符号高于或相同。
    CarrySet,
    /// `lo` / `cc` —— 无符号低于（借位）。
    CarryClear,
    /// `mi` —— 负数。
    Minus,
    /// `pl` —— 正数或零。
    Plus,
    /// `vs` —— 有溢出。
    Overflow,
    /// `vc` —— 无溢出。
    NoOverflow,
    /// `hi` —— 无符号高于。
    UnsignedHigher,
    /// `ls` —— 无符号低于或相同。
    UnsignedLowerOrSame,
    /// `ge` —— 有符号大于等于。
    SignedGreaterEqual,
    /// `lt` —— 有符号小于。
    SignedLessThan,
    /// `gt` —— 有符号大于。
    SignedGreaterThan,
    /// `le` —— 有符号小于等于。
    SignedLessOrEqual,
    /// `al` —— 总是（AArch64 里等同于无条件）。
    Always,
    /// `nv` —— 从不（保留）。
    Never,
}

impl ConditionCode {
    /// 稳定的汇编后缀（小写）。
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Equal => "eq",
            Self::NotEqual => "ne",
            Self::CarrySet => "hs",
            Self::CarryClear => "lo",
            Self::Minus => "mi",
            Self::Plus => "pl",
            Self::Overflow => "vs",
            Self::NoOverflow => "vc",
            Self::UnsignedHigher => "hi",
            Self::UnsignedLowerOrSame => "ls",
            Self::SignedGreaterEqual => "ge",
            Self::SignedLessThan => "lt",
            Self::SignedGreaterThan => "gt",
            Self::SignedLessOrEqual => "le",
            Self::Always => "al",
            Self::Never => "nv",
        }
    }

    /// 该条件是否值得写成后缀。
    ///
    /// `al`（always）与 `nv`（never）在 AArch64 里是"无条件"的编码形式，
    /// 汇编器通常直接写裸 `b`，因此渲染时不追加后缀。
    #[must_use]
    pub const fn is_meaningful(self) -> bool {
        !matches!(self, Self::Always | Self::Never)
    }
}

impl fmt::Display for ConditionCode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// 一条解码后的指令。
///
/// 这是**解码阶段的瞬时结果**，不是存储格式：工程库与传输层使用列式（SoA）表示，
/// 因此这里的 `Vec` 分配是可接受的，但不得被用来逐条指令长期驻留内存。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DecodedInsn {
    /// 虚拟地址。
    pub addr: u64,
    /// 编码长度（字节）。
    pub len: u8,
    /// 源架构（跨架构容器里逐条记录，避免"猜测上下文"）。
    pub arch: Arch,
    /// 助记符编号。
    pub mnemonic: MnemonicId,
    /// 控制流语义。
    pub flow: Flow,
    /// 直接控制流目标（间接跳转/调用为 `None`）。
    pub target: Option<u64>,
    /// 条件码；无条件指令为 `None`。
    ///
    /// 见 [`ConditionCode`]：它不在指令 id 里，因此必须单独带出来，
    /// 否则 `b.lt` 会被渲染成无条件的 `b`。
    pub condition: Option<ConditionCode>,
    /// 操作数。
    pub operands: Vec<Operand>,
    /// 读到的寄存器。
    pub reads: RegSet,
    /// 写到的寄存器。
    pub writes: RegSet,
    /// 是否特权/敏感指令（如 `int3` 之外的系统指令）。
    pub privileged: bool,
}

impl DecodedInsn {
    /// 下一条指令的地址（顺序）。
    #[must_use]
    pub const fn next_addr(&self) -> u64 {
        self.addr + self.len as u64
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reg_set_insert_contains_iter() {
        let mut set = RegSet::new();
        assert!(set.is_empty());
        set.insert(RegId(0));
        set.insert(RegId(63));
        set.insert(RegId(64));
        set.insert(RegId(200));
        set.insert(RegId(999)); // 超范围：忽略而不是 panic
        assert_eq!(set.len(), 4);
        assert!(set.contains(RegId(64)));
        assert!(!set.contains(RegId(999)));
        let collected: Vec<u16> = set.iter().map(|r| r.0).collect();
        assert_eq!(collected, vec![0, 63, 64, 200]);
        assert_eq!(set.iter().count(), 4);
    }

    #[test]
    fn flow_block_semantics() {
        assert!(Flow::Return.ends_block());
        assert!(Flow::Branch { conditional: true }.ends_block());
        assert!(!Flow::Call.ends_block());
        assert!(Flow::Call.has_fallthrough());
        assert!(!Flow::Branch { conditional: false }.has_fallthrough());
        assert!(Flow::Branch { conditional: true }.has_fallthrough());
    }
}
