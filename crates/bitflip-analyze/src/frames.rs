//! 栈帧与局部变量视图（M6 交付项 6）。
//!
//! # 结论从哪来：两个来源，互相核对
//!
//! "这个函数的栈帧多大、保存了哪些寄存器"有两个可用的来源，可靠性差很多：
//!
//! 1. **展开信息（PE 的 `UNWIND_INFO`）** —— 编译器生成的权威数据，
//!    描述"如何撤销这个函数的前导"。它直接给出帧大小、保存的寄存器、
//!    帧指针。这是**首选**来源。
//! 2. **前导扫描** —— 从函数入口顺着指令走，识别 `push` / `sub rsp, imm`
//!    这类建帧指令并累加。不需要任何元数据，但会被优化打断。
//!
//! 两个来源**同时存在时做交叉核对**：一致就敢说是帧大小；不一致就
//! 把两个值都摆出来并说明分歧，而不是悄悄挑一个（CLAUDE.md §7）。
//!
//! # 为什么不能只做前导扫描
//!
//! 前导扫描看着简单，其实很容易给出**看起来合理但错误**的数字：
//!
//! * 优化过的函数会把 `sub rsp` 拆成多条、或夹进无关指令；
//! * 前导里出现 `call`（栈探测 `__chkstk`）时，扫描必须停下；
//! * 叶函数没有前导 —— 此时"帧大小 0"是对的，但"扫描失败"和
//!   "确实没有前导"必须区分开。
//!
//! 所以：**有展开信息就信展开信息**，前导扫描用来补它的空白和做核对。
//!
//! # 边界：只给能确定的
//!
//! * 帧大小给不出来就是 `None` + `notes`，不用 0 冒充。
//! * 局部变量**只报栈上的保存位置**，不猜类型、不猜名字 —— 没有调试
//!   信息时那些是编出来的（CLAUDE.md §7）。
//! * 前导扫描停下来时记录**停在哪条指令**，让用户能自己核对。
//!
//! # 助记符名为什么必须问后端
//!
//! `DecodedInsn::mnemonic` 是 capstone 的编号，数值跨版本会变。把
//! `"push"` 之类的判断写成编号常量表，版本一升就**静默错位** ——
//! 帧大小算错却不报错。所以名字一律走
//! [`CapstoneDecoder::mnemonic_name`]，并在本模块按编号缓存
//! （前导只有几条指令，但函数有几千个，逐个走 FFI 会明显变慢）。

use std::cell::RefCell;
use std::collections::BTreeMap;

use bitflip_arch::{AbiSpec, CapstoneDecoder, DecodedInsn, Flow, Operand, RegId};
use bitflip_loader::object::{PeUnwindInfo, UnwindEntry};

use crate::args::InsnRange;

/// 前导扫描最多看多少条指令。
///
/// 前导通常不超过十几条指令。上限存在的意义是**兜底**：遇到畸形输入
/// 或异常指令流时保证停下来，不会顺着一整个函数扫下去。
pub const MAX_PROLOGUE_INSNS: usize = 24;

/// 前导扫描最多覆盖多少字节。
pub const MAX_PROLOGUE_BYTES: u64 = 256;

/// 帧大小的来源。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FrameSource {
    /// 只有展开信息给出了帧大小。
    Unwind,
    /// 只有前导扫描给出了帧大小。
    Prologue,
    /// 两个来源都给出，且**一致**。
    Agreed,
    /// 两个来源都给出，但**不一致**（分歧会写进 notes）。
    Disagreed,
    /// 两个来源都没能给出帧大小。
    Unknown,
}

impl FrameSource {
    /// 面向用户的中文标签。
    #[must_use]
    pub const fn label_zh(self) -> &'static str {
        match self {
            Self::Unwind => "展开信息",
            Self::Prologue => "前导扫描",
            Self::Agreed => "展开信息与前导扫描一致",
            Self::Disagreed => "展开信息与前导扫描不一致",
            Self::Unknown => "未能确定",
        }
    }
}

/// 单个函数的栈帧推断。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FrameInference {
    /// 函数入口。
    pub entry: u64,
    /// 前导扫描覆盖的字节数；`None` = 没扫出前导。
    pub prologue_len: Option<u64>,
    /// 前导扫描算出的帧大小。
    pub prologue_frame_size: Option<u64>,
    /// 展开信息给出的帧大小。
    pub unwind_frame_size: Option<u64>,
    /// **采纳**的帧大小。有展开信息时用展开信息（权威），否则用前导扫描。
    pub frame_size: Option<u64>,
    /// 帧大小来自哪里、两个来源是否一致。
    pub source: FrameSource,
    /// 保存的非易失寄存器（按前导顺序）。
    pub saved_registers: Vec<String>,
    /// 帧指针寄存器名（`"rbp"` / `"x29"`）。
    pub frame_pointer: Option<String>,
    /// 前导扫描停在哪个地址（未识别的第一条指令）。
    pub stopped_at: Option<u64>,
    /// 这个函数的降级说明。
    pub notes: Vec<String>,
}

impl FrameInference {
    /// 是否拿到了可用的帧信息（帧大小或保存寄存器至少有一个）。
    #[must_use]
    pub fn has_data(&self) -> bool {
        self.frame_size.is_some() || !self.saved_registers.is_empty()
    }

    /// 两个来源是否都给了帧大小且相等。
    #[must_use]
    pub fn sources_agree(&self) -> Option<bool> {
        match (self.unwind_frame_size, self.prologue_frame_size) {
            (Some(a), Some(b)) => Some(a == b),
            _ => None,
        }
    }
}

/// 一批函数的栈帧扫描结果。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FrameScan {
    /// 每个函数的推断。
    pub functions: Vec<FrameInference>,
    /// 本次扫描用的调用约定名；`None` = 该架构没有可用的调用约定。
    pub abi_name: Option<String>,
    /// 整体说明（能力是否适用、展开信息是否可用等）。
    pub notes: Vec<String>,
}

/// 扫描一批函数的栈帧。
///
/// `unwind` 是加载器给的展开表（PE 有 `.pdata`；ELF 的 `.eh_frame`
/// 目前只有函数边界、没有解码出的展开细节，因此 `decoded` 全是 `None`）。
/// `abi` 提供栈指针与帧指针的**名字**。
#[must_use]
pub fn scan_frames(
    insns: &[DecodedInsn],
    functions: &[InsnRange],
    unwind: &[UnwindEntry],
    abi: &AbiSpec,
) -> FrameScan {
    let mut notes = Vec::new();

    // 展开表按入口地址建索引。线性查找在 5000 个函数 × 5000 条展开信息
    // 上是 2500 万次比较，不能接受。
    let mut unwind_index: Vec<(u64, &PeUnwindInfo)> = unwind
        .iter()
        .filter_map(|e| e.decoded.as_ref().map(|d| (e.begin, d)))
        .collect();
    unwind_index.sort_by_key(|(begin, _)| *begin);

    let decoded_entries = unwind_index.len();
    if unwind.is_empty() {
        notes.push(
            "这个目标没有展开表（PE 的 .pdata / ELF 的 .eh_frame），帧大小只能靠前导扫描"
                .to_string(),
        );
    } else if decoded_entries == 0 {
        notes.push(format!(
            "有 {} 条展开信息，但都没有解码出帧细节（ELF 的 .eh_frame 目前只给函数边界），\
             帧大小只能靠前导扫描",
            unwind.len()
        ));
    } else if decoded_entries < unwind.len() {
        notes.push(format!(
            "展开表共 {} 条，其中 {decoded_entries} 条解码出帧细节",
            unwind.len()
        ));
    }

    // 名字解析需要一个真实后端：帧指针、链接寄存器这些名字在 ABI 表里
    // 不一定都有（例如 AArch64 的 x30）。拿不到解码器就退回只用 ABI 表。
    let decoder = match CapstoneDecoder::new(abi.spec) {
        Ok(d) => Some(d),
        Err(error) => {
            notes.push(format!(
                "没有可用的解码后端（{error}），助记符与表外寄存器名拿不到，\
                 前导扫描会很快停下"
            ));
            None
        }
    };
    let resolver = NameResolver::new(abi, decoder);

    let mut sorted: Vec<InsnRange> = functions.to_vec();
    sorted.sort_by_key(|f| f.start);

    let mut out: Vec<FrameInference> = Vec::with_capacity(sorted.len());
    let mut idx = 0usize;

    for (n, f) in sorted.iter().enumerate() {
        while idx < insns.len() && insns[idx].addr < f.start {
            idx += 1;
        }
        let begin = idx;
        // 与参数推断同样的边界规则：没有显式 end 时不越过下一个函数入口，
        // 否则会把别人的前导算进来。
        let limit = f
            .end
            .or_else(|| sorted.get(n + 1).map(|next| next.start))
            .unwrap_or(u64::MAX);
        while idx < insns.len() && insns[idx].addr < limit {
            idx += 1;
        }

        let body = &insns[begin..idx];
        let unwind_info = lookup_unwind(&unwind_index, f.start);
        out.push(infer_frame(f.start, body, unwind_info, &resolver));
    }

    FrameScan {
        functions: out,
        abi_name: Some(abi.name_zh.to_string()),
        notes,
    }
}

/// 在按入口排序的展开索引里查一个函数。
fn lookup_unwind<'a>(index: &[(u64, &'a PeUnwindInfo)], entry: u64) -> Option<&'a PeUnwindInfo> {
    let pos = index
        .binary_search_by_key(&entry, |(begin, _)| *begin)
        .ok()?;
    Some(index[pos].1)
}

/// 寄存器名 / 助记符名解析：先问 ABI 表，再问真实后端。
struct NameResolver<'a> {
    abi: &'a AbiSpec,
    decoder: Option<CapstoneDecoder>,
    /// `MnemonicId` → 名字。
    ///
    /// 前导扫描每条指令都要判助记符，而函数有几千个。逐个走 FFI 会
    /// 明显变慢；编号在同一个解码器（= 同一个架构规格）内稳定，所以
    /// 按编号缓存。键里**不需要**再混架构：一个 `NameResolver` 只服务
    /// 一个 `AbiSpec`，缓存的生命周期与它一致。
    mnemonic_cache: RefCell<BTreeMap<u32, Option<String>>>,
}

impl<'a> NameResolver<'a> {
    fn new(abi: &'a AbiSpec, decoder: Option<CapstoneDecoder>) -> Self {
        Self {
            abi,
            decoder,
            mnemonic_cache: RefCell::new(BTreeMap::new()),
        }
    }

    /// 助记符名（带缓存）。
    fn mnemonic(&self, insn: &DecodedInsn) -> Option<String> {
        let key = insn.mnemonic.0;
        if let Some(hit) = self.mnemonic_cache.borrow().get(&key) {
            return hit.clone();
        }
        let resolved = self.decoder.as_ref().and_then(|d| d.mnemonic_name(insn));
        self.mnemonic_cache
            .borrow_mut()
            .insert(key, resolved.clone());
        resolved
    }

    /// 寄存器名。
    fn name(&self, reg: RegId) -> Option<String> {
        // 先查 ABI 表：这些名字是契约的一部分，且不需要 FFI。
        if self.abi.reg_id(self.abi.stack_pointer_name) == Some(reg) {
            return Some(self.abi.stack_pointer_name.to_string());
        }
        if let Some(fp) = self.abi.frame_pointer_name {
            if self.abi.reg_id(fp) == Some(reg) {
                return Some(fp.to_string());
            }
        }
        if self.abi.reg_id(self.abi.ret_reg_name) == Some(reg) {
            return Some(self.abi.ret_reg_name.to_string());
        }
        for n in self.abi.arg_reg_names {
            if self.abi.reg_id(n) == Some(reg) {
                return Some((*n).to_string());
            }
        }
        for n in self.abi.callee_saved_names {
            if self.abi.reg_id(n) == Some(reg) {
                return Some((*n).to_string());
            }
        }
        // 表外寄存器：向真实后端问（例如 AArch64 的 x30 链接寄存器）。
        self.decoder.as_ref().and_then(|d| d.register_name(reg))
    }
}

/// 前导扫描的中间结果。
#[derive(Debug, Default)]
struct PrologueScan {
    len: u64,
    frame_size: u64,
    saved: Vec<String>,
    frame_pointer: Option<String>,
    stopped_at: Option<u64>,
    notes: Vec<String>,
    /// 是否识别出了至少一条建帧指令。
    recognized_any: bool,
}

impl PrologueScan {
    /// 只有**识别出建帧指令**时才算"有结论"。
    ///
    /// 一条都没识别出来时返回 `None`，而不是 0 —— "没扫到"和"确实没有
    /// 前导"是两件事，用 0 冒充会把前者说成后者（CLAUDE.md §7）。
    fn frame_size(&self) -> Option<u64> {
        self.recognized_any.then_some(self.frame_size)
    }
}

/// 推断单个函数：前导扫描 + 展开信息核对。
fn infer_frame(
    entry: u64,
    body: &[DecodedInsn],
    unwind: Option<&PeUnwindInfo>,
    resolver: &NameResolver<'_>,
) -> FrameInference {
    let mut notes = Vec::new();

    let prologue = scan_prologue(body, resolver);
    let prologue_frame_size = prologue.frame_size();

    let unwind_frame_size = unwind.and_then(PeUnwindInfo::frame_size);
    let mut saved_registers: Vec<String> = unwind
        .map(|d| {
            d.saved_registers()
                .into_iter()
                .map(str::to_string)
                .collect()
        })
        .unwrap_or_default();
    let frame_pointer = unwind
        .and_then(|d| d.frame_register.clone())
        .or_else(|| prologue.frame_pointer.clone());

    if let Some(d) = unwind {
        for n in &d.notes {
            notes.push(format!("展开信息：{n}"));
        }
    }

    // 两个来源都给出帧大小时核对
    let (frame_size, source) = match (unwind_frame_size, prologue_frame_size) {
        (Some(u), Some(p)) if u == p => (Some(u), FrameSource::Agreed),
        (Some(u), Some(p)) => {
            notes.push(format!(
                "帧大小有分歧：展开信息说 {u} 字节（{u:#x}），前导扫描说 {p} 字节（{p:#x}）；\
                 采纳展开信息（编译器生成的权威数据）"
            ));
            (Some(u), FrameSource::Disagreed)
        }
        (Some(u), None) => (Some(u), FrameSource::Unwind),
        (None, Some(p)) => (Some(p), FrameSource::Prologue),
        (None, None) => (None, FrameSource::Unknown),
    };

    // 保存寄存器：展开信息优先，缺了用前导扫描补，两边都有且不同就说明
    if saved_registers.is_empty() && !prologue.saved.is_empty() {
        saved_registers.clone_from(&prologue.saved);
        notes.push(format!(
            "保存寄存器来自前导扫描（展开信息没给出）：{}",
            prologue.saved.join(", ")
        ));
    } else if !saved_registers.is_empty()
        && !prologue.saved.is_empty()
        && saved_registers != prologue.saved
    {
        notes.push(format!(
            "保存寄存器两侧不一致：展开信息 {saved_registers:?}，前导扫描 {:?}；\
             以展开信息为准，前导扫描结果供核对",
            prologue.saved
        ));
    }

    if let Some(at) = prologue.stopped_at {
        if prologue.recognized_any {
            notes.push(format!("前导扫描在 {at:#x} 停下（未识别的指令）"));
        }
    }
    notes.extend(prologue.notes);

    if frame_size.is_none() && unwind.is_none() && !prologue.recognized_any {
        notes.push(
            "没有展开信息，前导里也没识别出建帧指令（可能是叶函数，也可能是分析不全）".to_string(),
        );
    }

    FrameInference {
        entry,
        prologue_len: prologue.recognized_any.then_some(prologue.len),
        prologue_frame_size,
        unwind_frame_size,
        frame_size,
        source,
        saved_registers,
        frame_pointer,
        stopped_at: prologue.stopped_at,
        notes,
    }
}

/// 顺着函数入口扫描前导，累加栈分配与保存的寄存器。
fn scan_prologue(body: &[DecodedInsn], resolver: &NameResolver<'_>) -> PrologueScan {
    let mut scan = PrologueScan::default();

    let sp = resolver.abi.reg_id(resolver.abi.stack_pointer_name);
    let fp = resolver
        .abi
        .frame_pointer_name
        .and_then(|n| resolver.abi.reg_id(n));

    // 一个寄存器压栈占几个字节。这是架构的事实，属于 ABI 层 ——
    // 在这里按 `arch` 分支会违反分层（架构差异必须收敛在 bitflip-arch），
    // 新架构出现时这里也会漏改。
    let slot = resolver.abi.stack_slot_size();

    for (n, insn) in body.iter().enumerate() {
        if n >= MAX_PROLOGUE_INSNS || scan.len >= MAX_PROLOGUE_BYTES {
            scan.notes.push(format!(
                "前导扫描达到上限（{MAX_PROLOGUE_INSNS} 条指令 / {MAX_PROLOGUE_BYTES} 字节）"
            ));
            scan.stopped_at = Some(insn.addr);
            break;
        }
        // 控制流指令意味着前导结束了。`call` 尤其不能跨过 —— 前导里的
        // call 通常是栈探测（__chkstk），跨过去会把被调函数的前导算进来。
        if matches!(
            insn.flow,
            Flow::Call | Flow::Branch { .. } | Flow::Return | Flow::Trap
        ) {
            scan.stopped_at = Some(insn.addr);
            break;
        }

        let Some(mnem) = resolver.mnemonic(insn) else {
            // 助记符名拿不到就没法判断，停下并说明（不猜）。
            scan.notes.push(format!(
                "{:#x} 的助记符名拿不到，前导扫描停下（该指令之后不再统计）",
                insn.addr
            ));
            scan.stopped_at = Some(insn.addr);
            break;
        };

        let step = match mnem.as_str() {
            // 压栈 / 存栈建帧：
            //   x86   `push rbx`
            //   ARM   `push {r4, lr}`
            //   A64   `stp x29, x30, [sp, #-16]!`
            "push" | "stp" | "str" | "stmdb" | "stm" | "vpush" => {
                match stack_store_setup(insn, sp, slot, resolver) {
                    Some((regs, size)) => {
                        scan.saved.extend(regs);
                        scan.frame_size += size;
                        true
                    }
                    None => false,
                }
            }
            // `sub rsp, imm` / `sub sp, sp, #imm`：栈分配
            "sub" => match sub_stack_pointer_amount(insn, sp) {
                Some(size) => {
                    scan.frame_size += size;
                    true
                }
                None => false,
            },
            // `mov rbp, rsp` / `lea rbp, [rsp+off]` / `mov x29, sp` /
            // `add x29, sp, #off`：建立帧指针
            "mov" | "lea" | "add" => match frame_pointer_setup(insn, fp, sp) {
                Some(reg) => {
                    if let Some(name) = resolver.name(reg) {
                        scan.frame_pointer = Some(name);
                    }
                    true
                }
                None => false,
            },
            // `and rsp, -16`：对齐。不改变"分配了多少"的语义，但要说明。
            "and" => match single_reg_operand(insn) {
                Some(reg) if Some(reg) == sp => {
                    scan.notes.push(format!(
                        "{:#x} 用 and 对齐栈指针，帧大小只统计到对齐前",
                        insn.addr
                    ));
                    true
                }
                _ => false,
            },
            _ => false,
        };

        if !step {
            scan.stopped_at = Some(insn.addr);
            break;
        }
        scan.recognized_any = true;
        scan.len += u64::from(insn.len);
    }

    scan
}

/// 指令的单一寄存器操作数（`push rbx`）。
fn single_reg_operand(insn: &DecodedInsn) -> Option<RegId> {
    let mut found = None;
    for op in &insn.operands {
        match op {
            Operand::Reg(r) => {
                if found.is_some() {
                    return None;
                }
                found = Some(*r);
            }
            // 其余操作数类型都不算"单一寄存器操作数"
            _ => return None,
        }
    }
    found
}

/// `sub <sp>, imm` 的分配字节数。
fn sub_stack_pointer_amount(insn: &DecodedInsn, sp: Option<RegId>) -> Option<u64> {
    let sp = sp?;
    let mut ops = insn.operands.iter();
    match (ops.next(), ops.next(), ops.next()) {
        // `sub rsp, 0x28`
        (Some(Operand::Reg(dst)), Some(Operand::Imm(amount)), None)
            if *dst == sp && *amount > 0 =>
        {
            Some(*amount as u64)
        }
        // `sub sp, sp, #0x20`（AArch64）
        (Some(Operand::Reg(dst)), Some(Operand::Reg(src)), Some(Operand::Imm(amount)))
            if *dst == sp && *src == sp && *amount > 0 =>
        {
            Some(*amount as u64)
        }
        _ => None,
    }
}

/// 是否在建立帧指针；返回帧寄存器编号。
fn frame_pointer_setup(insn: &DecodedInsn, fp: Option<RegId>, sp: Option<RegId>) -> Option<RegId> {
    let fp = fp?;
    let sp = sp?;
    let mut ops = insn.operands.iter();
    match (ops.next(), ops.next(), ops.next()) {
        // `mov rbp, rsp` / `mov x29, sp`
        (Some(Operand::Reg(dst)), Some(Operand::Reg(src)), None) if *dst == fp && *src == sp => {
            Some(fp)
        }
        // `add x29, sp, #0x20`
        (Some(Operand::Reg(dst)), Some(Operand::Reg(src)), Some(Operand::Imm(_)))
            if *dst == fp && *src == sp =>
        {
            Some(fp)
        }
        // `lea rbp, [rsp+off]`
        (Some(Operand::Reg(dst)), Some(Operand::Mem(m)), None)
            if *dst == fp && m.base == Some(sp) && m.index.is_none() =>
        {
            Some(fp)
        }
        _ => None,
    }
}

/// 存栈建帧：返回（保存的寄存器名，栈增长字节数）。
///
/// # 怎么判断是"写回"的存栈
///
/// `stp x29, x30, [sp, #-16]!` 的 `!` 表示**前索引写回**，栈指针会变；
/// 而 `str x30, [sp, #16]` 不写回，栈指针不变。两者在操作数列表里
/// 长得一样（都是一个 `Mem{base: sp, disp: -16}`），单看操作数分不出来。
///
/// 区别在于**栈指针有没有被写**：写回时 `writes` 里含 `sp`。
/// 所以这里要求 `writes` 含 `sp` 才算建帧 —— 否则会把"往栈上存东西"
/// 当成"分配了栈"，帧大小凭空变大。
fn stack_store_setup(
    insn: &DecodedInsn,
    sp: Option<RegId>,
    slot: u64,
    resolver: &NameResolver<'_>,
) -> Option<(Vec<String>, u64)> {
    let sp = sp?;
    if !insn.writes.contains(sp) {
        return None;
    }
    let mut regs = Vec::new();
    let mut mem_size = 0u64;
    for op in &insn.operands {
        match op {
            Operand::Reg(r) => {
                if let Some(name) = resolver.name(*r) {
                    regs.push(name);
                }
            }
            Operand::Mem(m) if m.base == Some(sp) && m.disp < 0 => {
                mem_size = mem_size.max(m.disp.unsigned_abs());
            }
            _ => {}
        }
    }
    // 有显式负偏移就用它（AArch64 的 stp/str）；否则按寄存器个数 × 槽宽
    // （x86 的 push / ARM 的 push 列表）。
    let size = if mem_size > 0 {
        mem_size
    } else {
        slot * regs.len() as u64
    };
    if size == 0 || regs.is_empty() {
        return None;
    }
    Some((regs, size))
}

/// 汇总一批帧推断，生成面向用户的说明。
#[must_use]
pub fn summarize_frames(inferences: &[FrameInference], abi: Option<&AbiSpec>) -> FrameScan {
    let Some(abi) = abi else {
        return FrameScan {
            functions: Vec::new(),
            abi_name: None,
            notes: vec!["该架构没有可用的调用约定，栈帧视图不适用".to_string()],
        };
    };

    let mut notes = Vec::new();
    let with_size = inferences.iter().filter(|f| f.frame_size.is_some()).count();
    let with_unwind = inferences
        .iter()
        .filter(|f| f.unwind_frame_size.is_some())
        .count();
    let with_prologue = inferences
        .iter()
        .filter(|f| f.prologue_frame_size.is_some())
        .count();
    let disagreed = inferences
        .iter()
        .filter(|f| f.source == FrameSource::Disagreed)
        .count();
    let with_saved = inferences
        .iter()
        .filter(|f| !f.saved_registers.is_empty())
        .count();

    notes.push(format!(
        "共 {} 个函数：{with_size} 个拿到帧大小，{with_unwind} 个有展开信息，\
         {with_prologue} 个从前导扫描得到帧大小，{with_saved} 个有保存寄存器",
        inferences.len()
    ));
    if disagreed > 0 {
        notes.push(format!(
            "有 {disagreed} 个函数的两个来源不一致，已在各自的说明里列出两个值"
        ));
    }
    if with_unwind == 0 && with_prologue == 0 {
        notes
            .push("没有任何函数能确定帧大小：既没有展开信息，前导里也没识别出建帧指令".to_string());
    }

    FrameScan {
        functions: inferences.to_vec(),
        abi_name: Some(abi.name_zh.to_string()),
        notes,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use bitflip_arch::{abi_for_spec, decoder_for, Arch, ArchSpec, Endian, Mode};
    use bitflip_loader::object::PeUnwindOp;

    fn x64() -> ArchSpec {
        ArchSpec::from_arch(Arch::X86_64, Mode::M64, Endian::Little)
    }

    fn a64() -> ArchSpec {
        ArchSpec::from_arch(Arch::Aarch64, Mode::M64, Endian::Little)
    }

    /// 按顺序解码一段机器码（测试用真实解码器，不造假的 `DecodedInsn`）。
    fn decode(spec: ArchSpec, bytes: &[u8], base: u64) -> Vec<DecodedInsn> {
        let dec = decoder_for(spec);
        let mut out = Vec::new();
        let mut off = 0usize;
        while off < bytes.len() {
            let Ok(insn) = dec.decode_one(&bytes[off..], base + off as u64) else {
                break;
            };
            let len = usize::from(insn.len);
            if len == 0 {
                break;
            }
            out.push(insn);
            off += len;
        }
        out
    }

    /// 一个函数范围（覆盖全部指令）。
    fn whole(insns: &[DecodedInsn]) -> Vec<InsnRange> {
        let first = insns.first().map(|i| i.addr).unwrap_or(0);
        let last = insns.last().map(|i| i.addr).unwrap_or(0);
        vec![InsnRange {
            start: first,
            end: Some(last + 1),
        }]
    }

    /// 造一条展开信息：帧大小 + 保存寄存器。
    fn unwind_with(frame_size: u64, saved: &[&str]) -> PeUnwindInfo {
        let mut ops = Vec::new();
        for r in saved {
            ops.push(PeUnwindOp::PushNonVolatile {
                reg: (*r).to_string(),
                slot_from_top: 0,
            });
        }
        let pushes = 8 * saved.len() as u64;
        if frame_size > pushes {
            ops.push(PeUnwindOp::Alloc {
                size: (frame_size - pushes) as u32,
            });
        }
        PeUnwindInfo {
            version: 1,
            flags: 0,
            prologue_size: 0,
            frame_register: None,
            frame_offset: 0,
            ops,
            notes: Vec::new(),
        }
    }

    fn entry(begin: u64, decoded: Option<PeUnwindInfo>) -> UnwindEntry {
        UnwindEntry {
            begin,
            end: begin + 0x100,
            unwind_info: 0,
            decoded,
        }
    }

    // ── 前导扫描 ──

    /// `push rbx; push rbp; sub rsp, 0x28` → 帧 0x38，保存 rbx/rbp。
    #[test]
    fn x64_push_push_sub_gives_frame_and_saved() {
        // 53           push rbx
        // 55           push rbp
        // 48 83 EC 28  sub rsp, 0x28
        // C3           ret
        let insns = decode(x64(), &[0x53, 0x55, 0x48, 0x83, 0xEC, 0x28, 0xC3], 0x1000);
        assert_eq!(insns.len(), 4, "应当解出 4 条指令");

        let abi = abi_for_spec(x64(), true).expect("Windows x64 调用约定");
        let scan = scan_frames(&insns, &whole(&insns), &[], &abi);
        assert_eq!(scan.functions.len(), 1);
        let f = &scan.functions[0];

        assert_eq!(f.frame_size, Some(0x38), "8+8+0x28 = 0x38");
        assert_eq!(f.prologue_frame_size, Some(0x38));
        assert_eq!(f.unwind_frame_size, None);
        assert_eq!(f.source, FrameSource::Prologue);
        assert_eq!(f.saved_registers, vec!["rbx", "rbp"]);
        // ret 是控制流指令，扫描在这里停
        assert_eq!(f.stopped_at, Some(0x1006));
    }

    /// 只有 `sub rsp, 0x28` → 帧 0x28，没有保存寄存器。
    #[test]
    fn x64_sub_only_has_no_saved_registers() {
        let insns = decode(x64(), &[0x48, 0x83, 0xEC, 0x28, 0xC3], 0x2000);
        let abi = abi_for_spec(x64(), true).expect("调用约定");
        let scan = scan_frames(&insns, &whole(&insns), &[], &abi);
        let f = &scan.functions[0];
        assert_eq!(f.frame_size, Some(0x28));
        assert!(f.saved_registers.is_empty(), "实际 {:?}", f.saved_registers);
    }

    /// `mov rbp, rsp` 要识别成帧指针。
    #[test]
    fn x64_frame_pointer_is_recognized() {
        // 55           push rbp
        // 48 89 E5     mov rbp, rsp
        // 48 83 EC 20  sub rsp, 0x20
        let insns = decode(
            x64(),
            &[0x55, 0x48, 0x89, 0xE5, 0x48, 0x83, 0xEC, 0x20, 0xC3],
            0x3000,
        );
        let abi = abi_for_spec(x64(), true).expect("调用约定");
        let scan = scan_frames(&insns, &whole(&insns), &[], &abi);
        let f = &scan.functions[0];
        assert_eq!(f.frame_pointer.as_deref(), Some("rbp"));
        assert_eq!(f.frame_size, Some(0x28), "8 + 0x20");
    }

    /// 叶函数：前导里没有建帧指令 —— 不能报成"帧大小 0"。
    ///
    /// 这是"没扫到"和"确实没有前导"的区别，用 0 冒充就是把后者说成前者。
    #[test]
    fn leaf_function_does_not_claim_a_zero_frame() {
        // B8 01 00 00 00  mov eax, 1
        // C3              ret
        let insns = decode(x64(), &[0xB8, 0x01, 0x00, 0x00, 0x00, 0xC3], 0x4000);
        let abi = abi_for_spec(x64(), true).expect("调用约定");
        let scan = scan_frames(&insns, &whole(&insns), &[], &abi);
        let f = &scan.functions[0];

        assert_eq!(f.frame_size, None, "没识别出建帧指令就不能报帧大小");
        assert_eq!(f.prologue_frame_size, None);
        assert_eq!(f.source, FrameSource::Unknown);
        assert!(!f.has_data());
        assert!(
            f.notes.iter().any(|n| n.contains("叶函数")),
            "必须说明可能是叶函数：{:?}",
            f.notes
        );
    }

    /// 前导里出现 `call`（栈探测）时必须停下，不能把被调函数的前导算进来。
    #[test]
    fn a_call_in_the_prologue_stops_the_scan() {
        // 48 83 EC 28   sub rsp, 0x28
        // E8 00 00 00 00 call +0
        // 53            push rbx   ← 绝不能被算进前导
        let insns = decode(
            x64(),
            &[0x48, 0x83, 0xEC, 0x28, 0xE8, 0x00, 0x00, 0x00, 0x00, 0x53],
            0x5000,
        );
        let abi = abi_for_spec(x64(), true).expect("调用约定");
        let scan = scan_frames(&insns, &whole(&insns), &[], &abi);
        let f = &scan.functions[0];

        assert_eq!(f.frame_size, Some(0x28), "只统计到 call 之前");
        assert!(
            f.saved_registers.is_empty(),
            "call 之后的 push 不算前导：{:?}",
            f.saved_registers
        );
        assert_eq!(f.stopped_at, Some(0x5004), "停在 call 上");
    }

    /// AArch64：`stp x29,x30,[sp,#-16]!` + `mov x29,sp` + `sub sp,sp,#0x20`。
    #[test]
    fn a64_stp_mov_sub_gives_frame_and_saved() {
        // FD 7B BF A9   stp x29, x30, [sp, #-16]!
        // FD 03 00 91   mov x29, sp
        // FF 83 00 D1   sub sp, sp, #0x20
        // C0 03 5F D6   ret
        //
        // 字节序踩过一次：AArch64 指令是 4 字节小端，`stp` 的指令字是
        // 0xFD7BBFA9，所以内存里的字节是 fd 7b bf a9。写成 a9 bf 7b fd
        // 会解码成完全不同的指令（实测是 ldr），而且**不报错**。
        let bytes = [
            0xFD, 0x7B, 0xBF, 0xA9, 0xFD, 0x03, 0x00, 0x91, 0xFF, 0x83, 0x00, 0xD1, 0xC0, 0x03,
            0x5F, 0xD6,
        ];
        let insns = decode(a64(), &bytes, 0x6000);
        assert!(insns.len() >= 3, "至少解出前 3 条，实际 {}", insns.len());

        let abi = abi_for_spec(a64(), false).expect("AAPCS64 调用约定");
        let scan = scan_frames(&insns, &whole(&insns), &[], &abi);
        let f = &scan.functions[0];

        assert_eq!(f.frame_size, Some(0x30), "16 + 0x20 = 0x30");
        assert_eq!(f.frame_pointer.as_deref(), Some("x29"));
        assert!(
            f.saved_registers.contains(&"x29".to_string())
                && f.saved_registers.contains(&"x30".to_string()),
            "必须保存 x29 与 x30（x30 不在 ABI 表的 callee_saved 里，靠后端查名）：{:?}",
            f.saved_registers
        );
    }

    /// 不写回的存栈（`str x30, [sp, #16]`）不能当成栈分配。
    ///
    /// 这条防的是"往栈上存东西"被误判成"分配了栈"，会让帧大小凭空变大。
    #[test]
    fn a_non_writeback_store_does_not_grow_the_frame() {
        // F9 5F 00 F9   ldr x25, [sp, #...] 之类先跳过，直接测 str 不写回
        // FE 0B 00 F9   str x30, [sp, #16]
        // C0 03 5F D6   ret
        let bytes = [0xFE, 0x0B, 0x00, 0xF9, 0xC0, 0x03, 0x5F, 0xD6];
        let insns = decode(a64(), &bytes, 0x7000);
        assert!(!insns.is_empty());

        let abi = abi_for_spec(a64(), false).expect("调用约定");
        let scan = scan_frames(&insns, &whole(&insns), &[], &abi);
        let f = &scan.functions[0];
        assert_eq!(
            f.frame_size, None,
            "str 不写回栈指针，不能算栈分配：{:?}",
            f.notes
        );
    }

    // ── 展开信息与前导扫描的核对 ──

    /// 两边一致 → `Agreed`，采纳该值。
    #[test]
    fn agreeing_sources_are_reported_as_agreed() {
        let insns = decode(x64(), &[0x53, 0x48, 0x83, 0xEC, 0x28, 0xC3], 0x8000);
        let abi = abi_for_spec(x64(), true).expect("调用约定");
        // push rbx(8) + 0x28 = 0x30
        let unw = vec![entry(0x8000, Some(unwind_with(0x30, &["rbx"])))];
        let scan = scan_frames(&insns, &whole(&insns), &unw, &abi);
        let f = &scan.functions[0];

        assert_eq!(f.prologue_frame_size, Some(0x30));
        assert_eq!(f.unwind_frame_size, Some(0x30));
        assert_eq!(f.source, FrameSource::Agreed);
        assert_eq!(f.sources_agree(), Some(true));
        assert_eq!(f.frame_size, Some(0x30));
    }

    /// 两边不一致 → `Disagreed`，两个值都摆出来，采纳展开信息。
    #[test]
    fn disagreeing_sources_keep_both_values_and_prefer_unwind() {
        let insns = decode(x64(), &[0x53, 0x48, 0x83, 0xEC, 0x28, 0xC3], 0x9000);
        let abi = abi_for_spec(x64(), true).expect("调用约定");
        // 展开信息说 0x60，前导扫描会说 0x30 —— 故意不一致
        let unw = vec![entry(0x9000, Some(unwind_with(0x60, &["rbx"])))];
        let scan = scan_frames(&insns, &whole(&insns), &unw, &abi);
        let f = &scan.functions[0];

        assert_eq!(f.prologue_frame_size, Some(0x30));
        assert_eq!(f.unwind_frame_size, Some(0x60));
        assert_eq!(f.source, FrameSource::Disagreed);
        assert_eq!(f.sources_agree(), Some(false));
        assert_eq!(f.frame_size, Some(0x60), "不一致时采纳展开信息");

        let joined = f.notes.join("\n");
        assert!(
            joined.contains("分歧") && joined.contains("0x30") && joined.contains("0x60"),
            "分歧必须两个值都写明：{:?}",
            f.notes
        );
    }

    /// 只有展开信息 → `Unwind`。
    #[test]
    fn unwind_only_is_used_when_the_prologue_has_nothing() {
        let insns = decode(x64(), &[0xB8, 0x01, 0x00, 0x00, 0x00, 0xC3], 0xA000);
        let abi = abi_for_spec(x64(), true).expect("调用约定");
        let unw = vec![entry(0xA000, Some(unwind_with(0x48, &["rbx", "rsi"])))];
        let scan = scan_frames(&insns, &whole(&insns), &unw, &abi);
        let f = &scan.functions[0];

        assert_eq!(f.source, FrameSource::Unwind);
        assert_eq!(f.frame_size, Some(0x48));
        assert_eq!(f.saved_registers, vec!["rbx", "rsi"]);
    }

    /// 展开信息没给保存寄存器时，用前导扫描补上并说明。
    #[test]
    fn saved_registers_fall_back_to_the_prologue() {
        let insns = decode(x64(), &[0x53, 0x55, 0x48, 0x83, 0xEC, 0x28, 0xC3], 0xB000);
        let abi = abi_for_spec(x64(), true).expect("调用约定");
        // 展开信息只给帧大小、不给保存寄存器
        let unw = vec![entry(0xB000, Some(unwind_with(0x38, &[])))];
        let scan = scan_frames(&insns, &whole(&insns), &unw, &abi);
        let f = &scan.functions[0];

        assert_eq!(f.saved_registers, vec!["rbx", "rbp"]);
        assert!(
            f.notes.iter().any(|n| n.contains("来自前导扫描")),
            "补齐来源必须说明：{:?}",
            f.notes
        );
    }

    /// 没有展开表时要在整体说明里讲清楚。
    #[test]
    fn missing_unwind_table_is_explained() {
        let insns = decode(x64(), &[0x53, 0xC3], 0xC000);
        let abi = abi_for_spec(x64(), true).expect("调用约定");
        let scan = scan_frames(&insns, &whole(&insns), &[], &abi);
        assert!(
            scan.notes.iter().any(|n| n.contains("没有展开表")),
            "notes = {:?}",
            scan.notes
        );
        assert_eq!(scan.abi_name.as_deref(), Some("Windows x64"));
    }

    /// 没有调用约定的架构：如实说"不适用"，不给一堆空结论。
    #[test]
    fn arch_without_abi_reports_not_applicable() {
        let scan = summarize_frames(&[], None);
        assert!(scan.functions.is_empty());
        assert!(scan.abi_name.is_none());
        assert!(
            scan.notes.iter().any(|n| n.contains("不适用")),
            "notes = {:?}",
            scan.notes
        );
    }

    /// 汇总要给出各类计数。
    #[test]
    fn summary_counts_each_source() {
        let insns = decode(x64(), &[0x53, 0x48, 0x83, 0xEC, 0x28, 0xC3], 0xD000);
        let abi = abi_for_spec(x64(), true).expect("调用约定");
        let unw = vec![entry(0xD000, Some(unwind_with(0x30, &["rbx"])))];
        let scan = scan_frames(&insns, &whole(&insns), &unw, &abi);
        let summary = summarize_frames(&scan.functions, Some(&abi));
        let joined = summary.notes.join("\n");
        assert!(
            joined.contains("共 1 个函数"),
            "notes = {:?}",
            summary.notes
        );
        assert!(
            joined.contains("1 个拿到帧大小"),
            "notes = {:?}",
            summary.notes
        );
        assert!(
            joined.contains("1 个有展开信息"),
            "notes = {:?}",
            summary.notes
        );
    }

    /// 函数边界按下一个入口截断，不把下一个函数的前导算进来。
    #[test]
    fn scan_stops_at_the_next_function_entry() {
        // 0xE000: sub rsp, 0x20        ← 第 1 个函数
        // 0xE004: push rbx             ← 第 2 个函数的前导
        // 0xE005: ret
        let insns = decode(x64(), &[0x48, 0x83, 0xEC, 0x20, 0x53, 0xC3], 0xE000);
        let abi = abi_for_spec(x64(), true).expect("调用约定");
        // 第 1 个函数没有显式 end，必须靠下一个入口 0xE004 截断
        let ranges = vec![
            InsnRange {
                start: 0xE000,
                end: None,
            },
            InsnRange {
                start: 0xE004,
                end: None,
            },
        ];
        let scan = scan_frames(&insns, &ranges, &[], &abi);
        assert_eq!(scan.functions.len(), 2);
        assert_eq!(scan.functions[0].frame_size, Some(0x20));
        assert!(
            scan.functions[0].saved_registers.is_empty(),
            "第 1 个函数不能把第 2 个函数的 push rbx 算进来：{:?}",
            scan.functions[0].saved_registers
        );
        assert_eq!(scan.functions[1].frame_size, Some(8));
    }
}
