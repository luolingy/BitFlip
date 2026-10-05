//! 跳转表 / `switch` 识别（M6）。
//!
//! # 问题
//!
//! `switch` 编译出来的形态是"间接跳转 + 一张地址表"：
//!
//! ```text
//!   cmp   edi, 4
//!   ja    .default
//!   lea   rax, [rip + table]      ; 表基址
//!   movsxd rcx, dword [rax + rdi*4] ; 读表项（32 位偏移）
//!   add   rax, rcx                ; 表项 = 相对基址的偏移
//!   jmp   rax                     ; 间接跳转
//! ```
//!
//! 或 AArch64 的 `adrp`/`add`/`ldr`/`br` 组合。间接跳转本身
//! [`bitflip_arch::DecodedInsn::target`] 是 `None` —— 目标不在指令里，
//! 在数据里。不把表读出来，CFG 就少一整片后继，`switch` 在图上看起来
//! 像"函数在这里就结束了"。
//!
//! # 本模块的做法
//!
//! **必须真的把表读出来，不能猜。** 流程：
//!
//! 1. 找候选跳转点：一条**无目标的间接跳转**（`Flow::Branch` 且
//!    `target == None`）。
//! 2. 从该点向前回溯，找"表基址"的来源：`lea`/`adr`/`adrp` 到某个
//!    寄存器，且该寄存器在跳转指令处仍然活着。
//! 3. 读表：按宽度（1/2/4/8）和**表项语义**（绝对地址 vs 相对基址的偏移）
//!    读出若干项。
//! 4. **验证**：每个表项都必须落在已映射的**可执行**区间里，且那里真的
//!    能解出指令。任何一项不满足就整体放弃这条表。
//!
//! 第 4 步是关键。地址表和数据表在内存里长得一样，唯一的区别是
//! "表里的值指向代码"。没有验证的话，一个普通的数据指针数组会被当成
//! 跳转表，凭空造出一堆假函数入口 —— 那正是 CLAUDE.md §7 禁止的。
//!
//! # 不知道就说不知道
//!
//! 识别不出来的间接跳转**保持无后继**，并在 [`JumpTableScan::notes`] 里
//! 说明"这里有一条间接跳转，目标未解析"。不拿"最近的一个函数入口"
//! 之类的猜测填上。

use std::collections::BTreeSet;

use bitflip_arch::{Arch, DecodedInsn, Flow, MemRef, Operand, RegId};

use crate::addrspace::AddrSpace;

/// 表项宽度的可能取值（字节）。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EntryWidth {
    /// 1 字节（`switch` 跳转表极少用，但 PIC 代码里的偏移表可能）。
    U8,
    /// 2 字节（AArch64 的 `tbz`/`tbnz` 之外较少见）。
    U16,
    /// 4 字节（x86_64 最常见的偏移表）。
    U32,
    /// 8 字节（绝对地址表）。
    U64,
}

impl EntryWidth {
    /// 字节数。
    #[must_use]
    pub const fn bytes(self) -> u64 {
        match self {
            Self::U8 => 1,
            Self::U16 => 2,
            Self::U32 => 4,
            Self::U64 => 8,
        }
    }

    /// 该宽度按**有符号**读取吗？
    ///
    /// 跳转表的项几乎总是**有符号**的偏移：目标既在表之前也在表之后，
    /// 编译器用 `movslq`（x86_64）/ `ldrsw`（AArch64）把 32 位项符号
    /// 扩展成 64 位。按无符号读会把 `0xfffff05f` 解释成 `+4294963295`
    /// 而不是 `-4001`，算出来的目标地址完全错位 —— 实测在 switch
    /// fixture 上得到 `0x24000105f` 这种不存在的地址。
    ///
    /// 8 字节项无法符号扩展（箱子里已经没有更高位），因此按位模式读，
    /// 由 `wrapping_add` 自然处理负数。
    #[must_use]
    pub const fn is_signed(self) -> bool {
        matches!(self, Self::U8 | Self::U16 | Self::U32)
    }

    /// 从字节数构造；不是 1/2/4/8 时返回 `None`（不猜）。
    #[must_use]
    pub const fn from_bytes(n: u64) -> Option<Self> {
        match n {
            1 => Some(Self::U8),
            2 => Some(Self::U16),
            4 => Some(Self::U32),
            8 => Some(Self::U64),
            _ => None,
        }
    }

    /// 短名。
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::U8 => "u8",
            Self::U16 => "u16",
            Self::U32 => "u32",
            Self::U64 => "u64",
        }
    }
}

/// 表项的语义 —— 这决定了怎么把"表里的数字"变成"目标地址"。
///
/// 搞错这一条会得到一整套**错位但看起来合理**的地址：每个表项都指向
/// 某段代码，验证也能过，只是全都不对。因此必须由指令序列确定，
/// 不能按架构默认值猜。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EntryKind {
    /// 表项就是绝对地址。
    Absolute,
    /// 表项是相对**表基址**的偏移（x86_64 PIC 的常见形态：
    /// `movsxd rcx, [rax + rdi*4]` 然后 `add rax, rcx`）。
    RelativeToBase,
    /// 表项是相对**跳转指令**的偏移（AArch64 `ldrsw` + `add` 的变体）。
    RelativeToInsn,
}

impl EntryKind {
    /// 短名。
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Absolute => "absolute",
            Self::RelativeToBase => "relative-to-base",
            Self::RelativeToInsn => "relative-to-insn",
        }
    }

    /// 面向界面的中文名。
    #[must_use]
    pub const fn label_zh(self) -> &'static str {
        match self {
            Self::Absolute => "绝对地址",
            Self::RelativeToBase => "相对表基址",
            Self::RelativeToInsn => "相对跳转指令",
        }
    }
}

/// 一张识别出来的跳转表。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct JumpTable {
    /// 间接跳转指令的地址。
    pub insn_addr: u64,
    /// 表基址（表第一项的地址）。
    pub base: u64,
    /// 表项宽度。
    pub width: EntryWidth,
    /// 表项语义。
    pub kind: EntryKind,
    /// 表项个数。
    pub count: usize,
    /// 解析出的目标地址（升序去重）。
    ///
    /// 每个都已验证落在可执行区间且能解出指令。
    pub targets: Vec<u64>,
}

impl JumpTable {
    /// 表占用的字节数。
    #[must_use]
    pub const fn byte_len(&self) -> u64 {
        self.width.bytes() * self.count as u64
    }
}

/// 跳转表扫描的结论。
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct JumpTableScan {
    /// 识别出的跳转表，按跳转指令地址升序。
    pub tables: Vec<JumpTable>,
    /// 扫描过程中的说明（面向用户，中文）。
    ///
    /// 包括"有多少条间接跳转没能解析"—— 降级必须可见（§7）。
    pub notes: Vec<String>,
}

impl JumpTableScan {
    /// 所有表的目标地址集合（升序去重）。
    #[must_use]
    pub fn all_targets(&self) -> Vec<u64> {
        let mut set = BTreeSet::new();
        for t in &self.tables {
            set.extend(t.targets.iter().copied());
        }
        set.into_iter().collect()
    }

    /// 某条间接跳转解析出的目标。
    #[must_use]
    pub fn targets_of(&self, insn_addr: u64) -> Option<&[u64]> {
        self.tables
            .iter()
            .find(|t| t.insn_addr == insn_addr)
            .map(|t| t.targets.as_slice())
    }
}

/// 一张表最多读多少项。
///
/// 上限存在的原因是**验证失败之前可能读很久**：如果表基址算错了，
/// 顺着往下读会一直读到"某项不落在可执行区间"才停。设个上限保证
/// 单条跳转的处理是常数时间。
pub const MAX_ENTRIES: usize = 4096;

/// 向前回溯找表基址时最多看多少条指令。
///
/// 编译器生成的序列通常在 10 条指令以内（`lea`/`add`/`cmp`/`ja`）。
/// 窗口太大会把无关的 `lea` 认成表基址。
pub const LOOKBACK_WINDOW: usize = 24;

/// 扫描一组函数内的跳转表。
///
/// `insns` 必须**按地址升序**（调用方通常来自 `InsnIndex::range`）。
/// 只扫描落在 `space` 已映射区间里的跳转。
///
/// `is_insn_start` 用来验证"该地址确实是一条指令的**起点**"。之所以由
/// 调用方传入而不是在这里建解码器：`bitflip-analyze` 不持有解码后端
/// （架构差异只在 `bitflip-arch` 里），硬塞一个会让这一层依赖解码器实例。
///
/// 注意它必须比"这里能解出指令"更强。调用方应当用**指令索引**查询
/// （`index.containing(addr) == Some((addr, _))`），而不是临时解码一次：
/// 从任意字节开始解码几乎总能解出点东西，那样 1 字节表项会几乎全部
/// 通过验证，读出几百项的假表（实测 MRT.exe 上正是如此）。
#[must_use]
pub fn scan_jump_tables(
    space: &AddrSpace,
    insns: &[DecodedInsn],
    is_insn_start: impl Fn(u64) -> bool,
) -> JumpTableScan {
    let mut scan = JumpTableScan::default();
    let mut unresolved = 0usize;
    // 已经因为是跳转表目标而认出来的地址：用于判断"这条间接跳转
    // 的候选目标是否全都落在已知函数入口上"。
    let mut seen_indirect = 0usize;

    for (i, insn) in insns.iter().enumerate() {
        // 候选：无目标的间接跳转。
        //
        // 注意 `Flow::Branch` 包含条件跳转 —— 间接条件跳转（x86 的
        // `jmp [table + rdi*8]` 是间接无条件，但有些 ISA 有间接条件）
        // 同样会把目标放在数据里，所以都要考虑。
        if !matches!(insn.flow, Flow::Branch { .. }) {
            continue;
        }
        if insn.target.is_some() {
            continue; // 直接跳转，目标就在指令里
        }
        seen_indirect += 1;

        match resolve_table(space, insns, i, &is_insn_start) {
            Some(table) => scan.tables.push(table),
            None => unresolved += 1,
        }
    }

    if !scan.tables.is_empty() {
        let total: usize = scan.tables.iter().map(|t| t.targets.len()).sum();
        scan.notes.push(format!(
            "识别出 {} 张跳转表（共 {total} 个目标），已作为间接跳转的后继加入 CFG",
            scan.tables.len()
        ));
    }
    if unresolved > 0 {
        // 降级必须可见：有间接跳转没解析出来，意味着 CFG 在这些点
        // 少画了边。不说的话用户会以为图是完整的。
        scan.notes.push(format!(
            "有 {unresolved} 处间接跳转的目标未能解析（表未识别或表项未通过验证），\
             这些跳转在 CFG 里没有后继"
        ));
    }
    if seen_indirect > 0 && scan.tables.is_empty() && unresolved == 0 {
        scan.notes.push("本范围内没有间接跳转".to_string());
    }

    scan
}

/// 尝试把 `insns[i]` 处的间接跳转解析成一张跳转表。
fn resolve_table(
    space: &AddrSpace,
    insns: &[DecodedInsn],
    i: usize,
    is_insn_start: &impl Fn(u64) -> bool,
) -> Option<JumpTable> {
    let jump = insns.get(i)?;

    let window_start = i.saturating_sub(LOOKBACK_WINDOW);

    // 在回溯窗口里找表基址：一条把**常量地址**放进寄存器的指令
    // （x86_64 的 `lea reg, [rip+disp]`、AArch64 的 `adrp`+`add`）。
    let mut candidates: Vec<(u64, RegId, EntryKind)> = Vec::new();
    for (offset, prev) in insns[window_start..i].iter().enumerate() {
        let Some((base, reg)) = load_address_into_reg(prev) else {
            continue;
        };
        let prev_index = window_start + offset;
        if !register_is_live_until(insns, prev_index, i, reg) {
            continue;
        }
        // 基址寄存器必须真的被**索引**用于取值（`[base + index*scale]`）。
        //
        // 少了这条，"间接跳转"会被大面积误判成跳转表。实测 ntdll.dll：
        //
        // ```text
        //   movq 0xa4aa1(%rip), %rax   ; 从数据槽取一个**函数指针**
        //   testq %rax, %rax
        //   jne  ...
        //   jmpq *%rax                 ; 尾调用，不是 switch
        // ```
        //
        // `load_address_into_reg` 会把那条 `movq` 看成"把常量地址
        // 0x180181238 放进 rax"（它确实是），于是把那个数据槽当成表基址，
        // 读出几百个"项"。但真正的跳转表一定是**用索引去查**的：
        // `movslq (%rcx,%rax,4), %rax`。没有索引寻址就没有表。
        if !register_is_indexed_into(insns, prev_index, i, reg) {
            continue;
        }
        // 表基址的三种语义都试，验证阶段决定哪个对。
        //
        // 这里**不猜**：全都读一遍，只有表项全部通过验证的那种才被接受。
        // 目标集合恰好对得上时语义仍可能错，所以测试会另外断言 kind。
        candidates.push((base, reg, EntryKind::RelativeToBase));
        candidates.push((base, reg, EntryKind::Absolute));
        candidates.push((base, reg, EntryKind::RelativeToInsn));
    }

    if candidates.is_empty() {
        return None;
    }

    // 宽度优先从**指令的寻址 scale** 推出，而不是把所有宽度都试一遍。
    //
    // 编译器读表项的那条指令（`movslq (%rcx,%rax,4), %rax`）里的 scale
    // 就是表项宽度。这是**编译器自己声明的**事实，比我们事后猜宽度强
    // 得多。
    //
    // 为什么必须这么做：只靠"表项指向代码"验证时，1 字节表项几乎无法
    // 被否决。实测 ntdll.dll 上一个 u8"表"报出 432 个项 —— 因为在密集
    // 代码里，任何字节值加上基址都极可能落在某条指令的起点上。而
    // 编译器从不会为 `%rax,4` 的表生成 1 字节表项：scale 与宽度必须
    // 一致，否则读出来的项全是错的。
    //
    // 推断不出来时（非 x86 形态、或索引寄存器不可见）退回"全都试"，
    // 让验证决定 —— 不因为推不出来就直接放弃。
    let hinted = table_entry_width(insns, i, window_start);
    let widths: Vec<EntryWidth> = match hinted {
        Some(w) => vec![w],
        None => vec![
            EntryWidth::U32,
            EntryWidth::U64,
            EntryWidth::U16,
            EntryWidth::U8,
        ],
    };

    // 宽度候选：按表基址之后的字节内容试。x86_64 的 PIC switch 常用
    // 4 字节偏移；AArch64 常用 4 或 8。全都试，让验证决定。
    //
    // **不能"第一个通过就收"**：`Absolute` 与 `RelativeToBase` 两种语义
    // 在同一份字节上都能读出**若干**看似合法的项（比如某些项恰好落在
    // 可执行区间）。先到的语义会赢，而它可能不是真语义 —— 实测
    // `Absolute` 在 switch fixture 上读出了 0x140001081 这类指向
    // **指令中间**的地址，验证却放它过了。
    //
    // 因此收集所有能读出来的候选，再用"连续有效项数最多"挑选：
    // 真语义会让**整个表**逐项通过，错误语义通常几项之内就断了。
    // 并列时按下面的固定顺序打破，保证结果可复现（黄金快照要求）。
    let mut best: Option<JumpTable> = None;
    for (base, _reg, kind) in candidates {
        for &width in &widths {
            let Some(table) = read_table(space, jump.addr, base, width, kind, is_insn_start) else {
                continue;
            };
            // 至少两项才叫表：单项"表"更可能是个普通指针。
            if table.targets.len() < 2 {
                continue;
            }
            if is_better_than(&table, best.as_ref()) {
                best = Some(table);
            }
        }
    }
    best
}

/// 从"读表项"的那条指令推断表项宽度。
///
/// 在跳转指令之前的回溯窗口里找一条**带索引寻址的内存读**
/// （`movslq (%rcx,%rax,4), %rax`），它的 `scale` 就是表项宽度：
/// 编译器必须让 scale 与表项宽度一致，否则算出的地址是错的。
///
/// 返回 `None` 表示推断不出来（架构不用这种形态、或窗口里没有索引读），
/// 调用方退回"所有宽度都试"。**不返回一个默认宽度** —— 猜出来的宽度
/// 会让验证通过一批本来该被否决的表。
///
/// # 为什么不能只靠"表项指向代码"来定宽度
///
/// 1 字节表项在密集代码里几乎无法被否决：任何字节值加上基址都极可能
/// 落在某条指令的起点上。实测 ntdll.dll 上一个 u8"表"报出 432 个项。
/// 而编译器从不会给 `scale=4` 的表生成 1 字节表项。
fn table_entry_width(
    insns: &[DecodedInsn],
    jump_index: usize,
    window_start: usize,
) -> Option<EntryWidth> {
    for insn in insns[window_start..jump_index].iter().rev() {
        for op in &insn.operands {
            let Operand::Mem(MemRef {
                index: Some(_),
                scale,
                write: false,
                ..
            }) = op
            else {
                continue;
            };
            // scale 是 1/2/4/8，正好对应表项宽度。其他值不是有效 scale。
            if let Some(w) = EntryWidth::from_bytes(u64::from(*scale)) {
                return Some(w);
            }
        }
    }
    None
}

/// 候选表排序：先比**有效项数**，再比语义强度，最后比宽度。
///
/// 用 `count`（连续通过验证的项数）而不是 `targets.len()`（去重后的目标数）：
/// 跳转表的多个 case 可以跳到同一个位置（`case 3: case 4:` 共用代码），
/// 去重后的数字会小于"表有多长"，于是短表可能因为恰好没有重复而胜出。
/// 表的**长度**才是"这一整片字节都是表"的证据强度。
///
/// 语义优先级 `RelativeToBase > Absolute > RelativeToInsn` 的理由：
/// 现代目标（PIC/PIE 是默认）用相对基址，绝对表见于非 PIC 的旧代码；
/// 相对指令的形态最少见。这个顺序只在**项数相同**时起作用 ——
/// 项数不同时以项数为准，因为"整个表都通过了验证"是更强的证据。
fn is_better_than(candidate: &JumpTable, current: Option<&JumpTable>) -> bool {
    let Some(current) = current else {
        return true;
    };
    let rank = |k: EntryKind| match k {
        EntryKind::RelativeToBase => 0u8,
        EntryKind::Absolute => 1,
        EntryKind::RelativeToInsn => 2,
    };
    let width_rank = |w: EntryWidth| match w {
        EntryWidth::U32 => 0u8,
        EntryWidth::U64 => 1,
        EntryWidth::U16 => 2,
        EntryWidth::U8 => 3,
    };
    (
        candidate.count,
        std::cmp::Reverse(rank(candidate.kind)),
        std::cmp::Reverse(width_rank(candidate.width)),
    ) > (
        current.count,
        std::cmp::Reverse(rank(current.kind)),
        std::cmp::Reverse(width_rank(current.width)),
    )
}

/// 一条指令是否把某个**常量地址**放进寄存器？
///
/// 返回 `(地址, 目标寄存器)`。
///
/// 识别的形态：
/// * `lea reg, [rip + disp]` —— x86_64 的位置无关取址（PIC 的主力形态）；
/// * `adr reg, label` / `adrp reg, page` —— AArch64；
/// * `mov reg, imm` —— 绝对地址（非 PIC 代码）。
///
/// # 为什么必须自己算 RIP 相对地址
///
/// capstone 把 `lea rcx, [rip+0xfaa]` 的 RIP 建模成一个**普通基址寄存器**，
/// `target` 留空，只给出 `disp`。实测该指令解码为：
///
/// ```text
/// op[1] = Mem(MemRef { base: Some(RegId(41)), disp: 4010, .. })
/// ```
///
/// `RegId(41)` 就是 RIP。不识别它的话，`target` 为 `None`、操作数里
/// 又没有 `Imm`，这条 `lea` 会被完全忽略 —— 而 x86_64 的 PIC 跳转表
/// **正是**用这条指令取表基址的。结果就是跳转表识别在所有 PIC 目标上
/// 静默失效（实测 switch fixture 上正是如此）。
fn load_address_into_reg(insn: &DecodedInsn) -> Option<(u64, RegId)> {
    // 直接给出了目标地址的（部分 `adr`、以及解码器已折叠的形态）。
    if let Some(target) = insn.target {
        // `call`/`jmp` 也带 target，但它们不是"取址"。
        if !matches!(insn.flow, Flow::Call) && !matches!(insn.flow, Flow::Branch { .. }) {
            if let Some(dest) = first_written_reg(insn) {
                return Some((target, dest));
            }
        }
    }

    let dest = first_written_reg(insn)?;

    // x86_64：`lea reg, [rip + disp]`。地址 = 下一条指令地址 + disp。
    //
    // 基准是**下一条指令**的地址（RIP 在指令执行时已指向下一条），
    // 不是当前指令地址。差一个指令长度在新样本上就会整体偏移。
    //
    // 操作数已经是解码层判定过的 `PcRelative`（`bitflip-arch` 在
    // 识别出 RIP 基址时产出它），这里**不再自己比对 RIP 寄存器**。
    // 早先这里手写了一遍"base == RIP"的判断，与解码层各有一份口径；
    // 解码层补上 `PcRelative` 之后，两份口径必然漂移 —— 一处认、
    // 一处不认，跳转表就会整体识别不出来（实测正是如此）。
    // 判定只留一处：谁产出操作数，谁负责判定。
    for op in &insn.operands {
        if let Operand::PcRelative(disp) = op {
            let next = insn.addr.wrapping_add(u64::from(insn.len));
            let addr = next.wrapping_add(*disp as u64);
            return Some((addr, dest));
        }
    }

    // `mov reg, imm` 形式的绝对地址（非 PIC 代码）。
    //
    // 立即数是有符号 `i64`，但地址要按无符号解释：编译器把高位地址
    // （如 PE 默认基址 0x140000000）放进 `mov` 时，立即数会以符号
    // 扩展形式出现。用 `as u64` 做位模式转换而不是 `try_into` ——
    // 后者会把这一类**合法地址**判成错误。
    let mut imm = None;
    for op in &insn.operands {
        if let Operand::Imm(v) = op {
            imm = Some(*v as u64);
            break;
        }
    }
    imm.map(|v| (v, dest))
}

/// 指令写入的第一个寄存器（按操作数顺序）。
fn first_written_reg(insn: &DecodedInsn) -> Option<RegId> {
    for op in &insn.operands {
        if let Operand::Reg(r) = op {
            if insn.writes.contains(*r) {
                return Some(*r);
            }
        }
    }
    None
}

/// `reg` 是否被当作**索引寻址的基址**用在一处内存读上？
///
/// 即窗口里存在 `MemRef { base: Some(reg), index: Some(_), .. }`。
///
/// 这是"跳转表"与"尾调用"的分界：
///
/// * 跳转表：`movslq (%rcx,%rax,4), %rax` —— 基址**加过索引**；
/// * 尾调用：`movq 0x…(%rip), %rax` + `jmpq *%rax` —— 只是取一个指针，
///   没有索引。把它当表会读出一堆无关字节。
///
/// 只认"读写都算"，因为编译器有时用 `cmp`/`mov` 做边界检查后取值。
fn register_is_indexed_into(
    insns: &[DecodedInsn],
    from: usize,
    jump_index: usize,
    reg: RegId,
) -> bool {
    insns
        .iter()
        .take(jump_index + 1)
        .skip(from + 1)
        .any(|insn| {
            insn.operands.iter().any(|op| {
                matches!(
                    op,
                    Operand::Mem(MemRef {
                        base: Some(b),
                        index: Some(_),
                        ..
                    }) if *b == reg
                )
            })
        })
}

/// `reg` 从 `from` 之后一直活着、直到 `jump_index` 处仍被使用吗？
///
/// 判据：在 `(from, jump_index]` 区间里，`reg` 先被**读**到（说明它参与了
/// 后续计算），且在被读到之前**没有**被别的指令覆盖。
///
/// # 为什么不能只判"跳转读 reg"
///
/// x86_64 的 PIC `switch` 序列里，表基址寄存器是**间接**参与跳转的：
///
/// ```text
///   lea     rcx, [rip+table]        ; rcx = 表基址
///   movslq  rax, [rcx + rax*4]      ; rax = 表项（读了 rcx！）
///   add     rax, rcx                ; rax += rcx（又读了 rcx）
///   jmp     rax                     ; 跳转读的是 rax，不是 rcx
/// ```
///
/// 跳转只读 `rax`，而基址在 `rcx`。要求"跳转直接读基址寄存器"会让
/// 这条最常见的形态**一条都匹配不上** —— 实测 switch fixture 正是如此。
///
/// 正确的判据是"基址寄存器在被覆盖前被读过"，把它交给后续的**表内容
/// 验证**去判断它到底是不是表基址：地址算错了，读出来的项不会全都
/// 落在可执行区间且能解出指令。
fn register_is_live_until(
    insns: &[DecodedInsn],
    from: usize,
    jump_index: usize,
    reg: RegId,
) -> bool {
    for insn in insns.iter().take(jump_index + 1).skip(from + 1) {
        if insn.reads.contains(reg) {
            return true; // 在被覆盖前读到了 —— 它参与了后续计算
        }
        if insn.writes.contains(reg) {
            return false; // 先被覆盖，基址没活到跳转
        }
    }
    // 一路到最后都没再读也没被覆盖：不算"活着参与计算"。
    // 保守返回 false —— 让验证阶段去否决，而不是在这里放宽。
    false
}

/// 按给定宽度与语义读表，并**验证**每个表项。
///
/// 返回 `None` 表示验证失败 —— 整张表作废，不做"部分接受"。
///
/// 为什么不做部分接受：地址表和数据表在内存里无法从内容区分，唯一
/// 的判据是"表项指向代码"。如果读到一半发现某项不是代码，更可能的
/// 解释是"这根本不是跳转表"（基址算错了），而不是"表在这一项结束"。
/// 部分接受会把数据指针数组的**前几项**当跳转目标，凭空造出函数。
///
/// `is_insn_start` 必须是**比"能解码"更强**的判据：它要回答"这个地址
/// 是不是一条已有指令的起点"。只判断"能解出指令"是不够的 —— 从任意
/// 字节开始解码几乎总能解出**某些**指令，于是 1 字节表项会几乎全部
/// 通过验证，读出几百项的假表。
fn read_table(
    space: &AddrSpace,
    insn_addr: u64,
    base: u64,
    width: EntryWidth,
    kind: EntryKind,
    is_insn_start: &impl Fn(u64) -> bool,
) -> Option<JumpTable> {
    let w = width.bytes();
    let mut targets = Vec::new();
    let mut count = 0usize;

    for idx in 0..MAX_ENTRIES {
        let addr = base.checked_add(w * idx as u64)?;
        let raw = read_entry(space, addr, width)?;

        // 把原始值按语义换算成地址。
        let target = match kind {
            EntryKind::Absolute => raw,
            EntryKind::RelativeToBase => base.wrapping_add(raw),
            EntryKind::RelativeToInsn => insn_addr.wrapping_add(raw),
        };

        // ── 验证 ──
        // 1. 必须落在已映射区间里
        if !space.contains(target) {
            break;
        }
        // 2. 必须落在**可执行**段里：数据段里的地址不是跳转目标
        if !space
            .executable_segments()
            .iter()
            .any(|s| s.contains(target))
        {
            break;
        }
        // 3. 那里必须真的是一条指令的起点（不是任意能解码的地址）
        if !is_insn_start(target) {
            break;
        }

        targets.push(target);
        count += 1;
    }

    if count == 0 {
        return None;
    }

    targets.sort_unstable();
    targets.dedup();

    Some(JumpTable {
        insn_addr,
        base,
        width,
        kind,
        count,
        targets,
    })
}

/// 从地址空间读一个表项，按宽度与**符号性**解释。
///
/// 返回值已经是"可直接加到基址上"的形式：有符号宽度做符号扩展，
/// 8 字节按位模式读（`wrapping_add` 会自然处理其负值语义）。
fn read_entry(space: &AddrSpace, addr: u64, width: EntryWidth) -> Option<u64> {
    let bytes = space.read(addr, width.bytes() as usize)?;
    Some(match width {
        EntryWidth::U8 => bytes[0] as i8 as i64 as u64,
        EntryWidth::U16 => {
            let v = i16::from_le_bytes([bytes[0], bytes[1]]);
            v as i64 as u64
        }
        EntryWidth::U32 => {
            let v = i32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]);
            v as i64 as u64
        }
        EntryWidth::U64 => {
            let mut buf = [0u8; 8];
            buf.copy_from_slice(&bytes[..8]);
            u64::from_le_bytes(buf)
        }
    })
}

/// 按架构给一个"合理的表项宽度"提示，用于说明文字。
///
/// **不做默认值使用** —— 宽度由验证决定。这个函数只用于在 notes 里
/// 解释"为什么优先试 4 字节"。
#[must_use]
pub const fn preferred_width(arch: Arch) -> EntryWidth {
    match arch {
        // x86_64 PIC 的 switch 几乎总是 4 字节相对偏移表。
        Arch::X86_64 | Arch::X86 => EntryWidth::U32,
        // AArch64 两种都常见，4 字节更省空间因此略多。
        Arch::Aarch64 | Arch::Arm => EntryWidth::U32,
        Arch::Riscv32 | Arch::Riscv64 => EntryWidth::U32,
        Arch::Mips | Arch::Mips64 => EntryWidth::U32,
        Arch::Wasm32 => EntryWidth::U32,
        // `Arch` 是 `#[non_exhaustive]`：未来新增架构时这里仍然要能编译。
        // 4 字节是现代目标上最常见的表项宽度，但这个值只是"先试哪个"
        // 的提示，最终由验证决定，所以兜底不会引入错误结论。
        _ => EntryWidth::U32,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use bitflip_arch::RegSet;

    /// 构造一个只含单段的地址空间，段里有给定字节。
    ///
    /// 直接用 `AddrSpace::new` 而不是走 loader：这些测试针对的是
    /// **读出与换算**逻辑，不该依赖任何具体的文件格式。
    fn space_with(bytes: &[u8], vaddr: u64, execute: bool) -> AddrSpace {
        use bitflip_loader::object::{ContentKind, FileRange, Perms, Segment};
        let seg = Segment {
            name: ".test".to_string(),
            vaddr,
            vsize: bytes.len() as u64,
            file: Some(FileRange {
                offset: 0,
                size: bytes.len() as u64,
            }),
            perms: Perms {
                read: true,
                write: false,
                execute,
            },
            kind: ContentKind::Code,
            align: 1,
        };
        let file: std::sync::Arc<[u8]> = std::sync::Arc::from(bytes.to_vec().into_boxed_slice());
        AddrSpace::new("test", file, &[seg]).expect("构造地址空间")
    }

    #[test]
    fn entry_width_reports_its_byte_size() {
        assert_eq!(EntryWidth::U8.bytes(), 1);
        assert_eq!(EntryWidth::U16.bytes(), 2);
        assert_eq!(EntryWidth::U32.bytes(), 4);
        assert_eq!(EntryWidth::U64.bytes(), 8);
        assert_eq!(EntryWidth::from_bytes(4), Some(EntryWidth::U32));
        assert_eq!(EntryWidth::from_bytes(3), None, "3 字节不是合法宽度");
    }

    /// **符号扩展**：这一条守住的是一个真实踩过的坑。
    ///
    /// 跳转表项是有符号偏移。以 switch fixture 的第一项为例，字节是
    /// `5f f0 ff ff`：
    ///
    /// * 按无符号读 → `0xfffff05f`，加到基址 0x140002000 得
    ///   `0x24000105f` —— 一个**不存在**的地址；
    /// * 按有符号读 → `-4001`，加到基址得 `0x14000105f` —— 正确目标。
    ///
    /// 搞错这一条时，验证阶段会让所有项都失败（目标不在映射区间），
    /// 于是整张表识别不出来。症状是"什么都没找到"，很容易被误判成
    /// "这个样本没有跳转表"。
    #[test]
    fn table_entries_are_sign_extended() {
        let base = 0x140002000u64;
        // 一条真实表项：0xfffff05f = -4001
        let bytes = [0x5fu8, 0xf0, 0xff, 0xff];
        let space = space_with(&bytes, base, false);

        let raw = read_entry(&space, base, EntryWidth::U32).expect("读表项");
        assert_eq!(
            raw as i64, -4001,
            "4 字节表项必须按有符号解释；按无符号会得到 {}",
            raw
        );
        assert_eq!(
            base.wrapping_add(raw),
            0x14000105f,
            "符号扩展后加基址才是正确目标"
        );

        // 反证：按无符号解释会得到完全错位的地址。
        // 这条断言把"两种解释差别有多大"写进测试，避免以后有人
        // 觉得"无符号也行"。
        let unsigned = u64::from(u32::from_le_bytes(bytes));
        assert_ne!(
            base.wrapping_add(unsigned),
            base.wrapping_add(raw),
            "两种解释必须给出不同结果，否则这条测试没有守住任何东西"
        );
    }

    #[test]
    fn one_and_two_byte_entries_are_sign_extended_too() {
        let base = 0x1000u64;
        // 1 字节：0xF6 = -10
        let s = space_with(&[0xf6u8], base, false);
        let raw = read_entry(&s, base, EntryWidth::U8).expect("u8");
        assert_eq!(raw as i64, -10);

        // 2 字节：0xFFF6 = -10
        let s = space_with(&[0xf6u8, 0xff], base, false);
        let raw = read_entry(&s, base, EntryWidth::U16).expect("u16");
        assert_eq!(raw as i64, -10);
    }

    #[test]
    fn eight_byte_entries_are_read_as_bit_patterns() {
        // 8 字节项无法"符号扩展"（箱子里已经装满了），按位模式读，
        // 由 wrapping_add 处理负数语义。
        let base = 0x1000u64;
        let neg_one = (-1i64) as u64;
        let bytes = neg_one.to_le_bytes();
        let s = space_with(&bytes, base, false);
        let raw = read_entry(&s, base, EntryWidth::U64).expect("u64");
        assert_eq!(raw, neg_one);
        // -1 加到基址上等价于基址 - 1
        assert_eq!(base.wrapping_add(raw), base - 1);
    }

    /// `RelativeToBase` 与 `RelativeToInsn` 必须给出不同结果。
    ///
    /// 这两种语义在真实样本上都存在，混淆会让所有目标整体偏移一个
    /// 常量，而偏移后的地址**往往仍然落在代码段里**（因此验证能过），
    /// 只是全都不对。这条测试把"两者不是一个东西"钉住。
    #[test]
    fn relative_kinds_shift_targets_differently() {
        let base = 0x1000u64;
        let insn = 0x2000u64;
        let raw = 0x10u64;
        assert_eq!(base.wrapping_add(raw), 0x1010);
        assert_eq!(insn.wrapping_add(raw), 0x2010);
        assert_ne!(base.wrapping_add(raw), insn.wrapping_add(raw));
    }

    #[test]
    fn every_width_has_a_chinese_free_short_name() {
        // 短名会出现在 wire 与 UI 上，必须稳定且互不相同。
        let mut names = std::collections::BTreeSet::new();
        for w in [
            EntryWidth::U8,
            EntryWidth::U16,
            EntryWidth::U32,
            EntryWidth::U64,
        ] {
            assert!(names.insert(w.as_str()), "宽度短名重复：{}", w.as_str());
        }
        // 语义短名同理
        let mut kinds = std::collections::BTreeSet::new();
        for k in [
            EntryKind::Absolute,
            EntryKind::RelativeToBase,
            EntryKind::RelativeToInsn,
        ] {
            assert!(kinds.insert(k.as_str()), "语义短名重复：{}", k.as_str());
            assert!(!k.label_zh().is_empty());
        }
    }

    /// RIP 相对寻址由**解码层**判定并产出 `Operand::PcRelative`。
    ///
    /// 这里曾经有一份 `rip_register()` 做同样的判断，与解码层各持一份
    /// 口径。解码层补上 `PcRelative` 之后两份口径立刻漂移：解码层不再
    /// 产出带 RIP 基址的 `Mem`，而这里仍在找它 —— 跳转表整体识别失败
    /// （6 个测试里挂了 3 个）。判定只留一处，所以这个函数被删掉了。
    ///
    /// 留下这条测试记录"判定归属解码层"这个决定，防止有人再补一份。
    #[test]
    fn rip_relative_judgement_belongs_to_the_decoder() {
        // 真实的 `lea rcx, [rip+disp]` 应当产出 PcRelative 而不是带基址的 Mem
        let dec = bitflip_arch::decoder_for(bitflip_arch::ArchSpec::from_arch(
            Arch::X86_64,
            bitflip_arch::Mode::M64,
            bitflip_arch::Endian::Little,
        ));
        let insn = dec
            .decode_one(&[0x48, 0x8d, 0x0d, 0x34, 0x12, 0x00, 0x00], 0x1000)
            .expect("解码 lea");
        assert!(
            insn.operands
                .iter()
                .any(|op| matches!(op, Operand::PcRelative(_))),
            "解码层必须把 RIP 相对识别成 PcRelative：{:?}",
            insn.operands
        );
    }

    /// 构造一条解码指令，只为测试纯逻辑判定（不依赖 capstone）。
    fn insn(
        addr: u64,
        flow: Flow,
        target: Option<u64>,
        operands: Vec<Operand>,
        reads: &[u16],
        writes: &[u16],
    ) -> DecodedInsn {
        let mk = |ids: &[u16]| {
            let mut s = RegSet::default();
            for id in ids {
                s.insert(RegId(*id));
            }
            s
        };
        DecodedInsn {
            addr,
            len: 4,
            arch: Arch::X86_64,
            mnemonic: bitflip_arch::MnemonicId(0),
            flow,
            target,
            condition: None,
            operands,
            reads: mk(reads),
            writes: mk(writes),
            privileged: false,
        }
    }

    /// **尾调用不能被当成跳转表** —— 这是实测踩到的误判。
    ///
    /// ntdll.dll 里大量出现这个模式：
    ///
    /// ```text
    ///   movq 0xa4aa1(%rip), %rax   ; 从数据槽取一个函数指针
    ///   testq %rax, %rax
    ///   jne  ...
    ///   movl $0xc000000d, %eax
    ///   retq
    ///   jmpq *%rax                 ; 尾调用
    /// ```
    ///
    /// 那条 `movq` 确实"把常量地址放进寄存器"，所以会被认成表基址，
    /// 于是那个**数据槽**被当成表，读出几百个"项"（实测 u8/432 项）。
    /// 但它没有索引寻址 —— 真正的跳转表一定是 `[base + index*scale]`。
    #[test]
    fn tail_call_through_a_pointer_is_not_a_jump_table() {
        // 复刻 ntdll.dll 的形态：数据槽里放着一堆"看起来像地址"的 4 字节
        // 内容，如果被当成表就会读出很多"项"。
        //
        // 段覆盖 0x2000..0x2200，全部可执行，且每个 4 字节边界都被当作
        // 指令起点 —— 这是最坏情况：如果只看"目标是不是指令起点"，
        // 这些字节几乎全部都会通过验证。
        let mut bytes = vec![0u8; 0x200];
        for i in 0..(0x200 / 4) {
            // 相对槽地址的小偏移，保证换算后落在段内
            let rel = ((i as i64) * 4) as i32;
            bytes[i * 4..i * 4 + 4].copy_from_slice(&rel.to_le_bytes());
        }
        let space = space_with(&bytes, 0x2000, true);
        // 最坏情况：段内每个 4 字节边界都"是指令起点"
        let any_start = |a: u64| (0x2000..0x2200).contains(&a) && (a - 0x2000).is_multiple_of(4);

        // movq 0x…(%rip), %rax —— 从数据槽取函数指针（没有索引！）
        //
        // disp 要按 RIP 相对算：地址 = 指令地址 + 指令长度 + disp。
        // `insn` 里 len 固定 4，所以 disp = 0x2000 - (0x1000 + 4)。
        //
        // 操作数形态用 `PcRelative`，与**真实解码器**的产出一致。
        // 早先这里手写成"带 RIP 基址的 Mem"，那种形态解码器现在已经
        // 不再产出了 —— 用不存在的形态做测试，测的就不是真实路径。
        let load_base = insn(
            0x1000,
            Flow::Fallthrough,
            None,
            vec![
                Operand::Reg(RegId(0)),
                Operand::PcRelative(0x2000 - (0x1000 + 4)),
            ],
            &[],
            &[0],
        );
        let test = insn(
            0x1006,
            Flow::Fallthrough,
            None,
            vec![Operand::Reg(RegId(0)), Operand::Reg(RegId(0))],
            &[0],
            &[],
        );
        let indirect = insn(
            0x1010,
            Flow::Branch { conditional: false },
            None,
            vec![Operand::Reg(RegId(0))],
            &[0],
            &[],
        );

        let insns = vec![load_base, test, indirect];
        // 基址寄存器活着（被 test 读了），但**从未被索引寻址**。
        assert!(
            register_is_live_until(&insns, 0, 2, RegId(0)),
            "前提取址指令的寄存器确实活到了跳转"
        );
        assert!(
            !register_is_indexed_into(&insns, 0, 2, RegId(0)),
            "没有 [base+index*scale] 形态 —— 这是尾调用而不是跳转表，\
             必须被拒绝"
        );

        // 端到端：即使每个字节边界都"像指令起点"，也不该识别出表。
        //
        // 这条断言是必需的：只测辅助函数的话，"辅助函数对但没接上"
        // 会让真实二进制上重新出现几百项的假表（实测 ntdll.dll 从 2 张
        // 变回 6 张，其中一张 u8/432 项）。
        let scan = scan_jump_tables(&space, &insns, any_start);
        assert!(
            scan.tables.is_empty(),
            "尾调用不得被识别成跳转表，但识别出了 {} 张：{:?}",
            scan.tables.len(),
            scan.tables
                .iter()
                .map(|t| format!("{:#x}/{}项", t.base, t.count))
                .collect::<Vec<_>>()
        );
    }

    /// 真正的跳转表形态必须通过索引寻址判定。
    #[test]
    fn indexed_table_load_is_recognized() {
        // 表放在 0x2000，基址指令取到 0x2000，索引读 scale=4，跳转经 rax。
        //
        // 这里走**完整的** `scan_jump_tables`，而不是只测辅助函数 ——
        // 否则"辅助函数对但没接上"这种错误不会被发现。
        // 段覆盖 0x2000..0x2000+0x200，表在头部、代码在后面。
        let mut bytes = vec![0u8; 0x200];
        // 表在 0x2000 起：16 个 4 字节项，相对基址指向 0x2100 起的代码
        for i in 0..16u64 {
            let target = 0x2100 + i * 4;
            let rel = (target as i64 - 0x2000) as i32;
            bytes[i as usize * 4..i as usize * 4 + 4].copy_from_slice(&rel.to_le_bytes());
        }
        // 表与代码放在**同一个可执行段**里：跳转目标必须在可执行段中，
        // 这是验证的必要条件（数据段里的地址不是跳转目标）。
        let space = space_with(&bytes, 0x2000, true);

        // 表基址用 `lea`-等价的形态给出：mov rax, 0x2000
        let load_base = insn(
            0x1000,
            Flow::Fallthrough,
            None,
            vec![Operand::Reg(RegId(1)), Operand::Imm(0x2000)],
            &[],
            &[1],
        );
        // `movslq (%rcx,%rax,4), %rax`：rcx=1 是基址，rax=0 是索引
        let indexed_read = insn(
            0x1006,
            Flow::Fallthrough,
            None,
            vec![
                Operand::Reg(RegId(0)),
                Operand::Mem(MemRef {
                    base: Some(RegId(1)),
                    index: Some(RegId(0)),
                    scale: 4,
                    disp: 0,
                    size: 4,
                    write: false,
                }),
            ],
            &[1, 0],
            &[0],
        );
        let indirect = insn(
            0x1010,
            Flow::Branch { conditional: false },
            None,
            vec![Operand::Reg(RegId(0))],
            &[0],
            &[],
        );

        let insns = vec![load_base, indexed_read, indirect];
        assert!(register_is_indexed_into(&insns, 0, 2, RegId(1)));
        // 宽度由 scale 推出：scale=4 → u32
        assert_eq!(
            table_entry_width(&insns, 2, 0),
            Some(EntryWidth::U32),
            "scale 就是表项宽度，应当直接给出 u32"
        );

        // 端到端：目标都是指令起点时，应当识别出一张 16 项的表。
        let starts: std::collections::BTreeSet<u64> = (0..16u64).map(|i| 0x2100 + i * 4).collect();
        let scan = scan_jump_tables(&space, &insns, |a| starts.contains(&a));
        assert_eq!(
            scan.tables.len(),
            1,
            "应当识别出唯一一张表；notes = {:?}",
            scan.notes
        );
        let t = &scan.tables[0];
        assert_eq!(t.base, 0x2000);
        assert_eq!(t.width, EntryWidth::U32, "宽度必须来自 scale");
        assert_eq!(t.count, 16);
    }

    /// 推断不出来时返回 `None`（调用方退回全试），**不瞎猜一个默认值**。
    #[test]
    fn table_entry_width_is_none_when_nothing_is_indexed() {
        let plain = insn(
            0x1000,
            Flow::Fallthrough,
            Some(0x3000),
            vec![Operand::Reg(RegId(0)), Operand::Imm(0x3000)],
            &[],
            &[0],
        );
        let indirect = insn(
            0x1010,
            Flow::Branch { conditional: false },
            None,
            vec![Operand::Reg(RegId(0))],
            &[0],
            &[],
        );
        let insns = vec![plain, indirect];
        assert_eq!(
            table_entry_width(&insns, 1, 0),
            None,
            "没有索引读就推不出宽度；返回默认值会让不该通过的表通过验证"
        );
    }
}
