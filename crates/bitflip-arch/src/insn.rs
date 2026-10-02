//! 结构化指令表示与寄存器集合。

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
