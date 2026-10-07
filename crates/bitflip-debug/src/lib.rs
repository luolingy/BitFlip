//! BitFlip 的调试信息来源（M8 交付物 1）：DWARF / PDB 里的函数名、源文件与行号。
//!
//! 单独一个 crate，而不是塞进 `bitflip-symbols`：解析格式与决定"谁的名字算数"
//! 是两件事。这里只做前者 —— 读出来、如实标注怎么读到的、读不到就说读不到；
//! 优先级与冲突合并由 `bitflip-core` 按符号来源决定。
//! 加一种格式（PDB、CodeView、dSYM）只动这里，不动分析层。
//!
//! 分层：`core → debug → loader`，与 `symbols` / `signature` 同级。
//!
//! # 为什么值得单独一层
//!
//! 符号表能给的是名字，调试信息能给的是**名字 + 源文件 + 行号**，而且在符号表被
//! 剥掉之后仍然在（事实上 `-g` 加 `strip --strip-all` 不会动 `.debug_*` 之外，
//! 用 `objcopy --keep-section` 甚至能只留调试信息）。这正是 M8 验收标准 2 要的东西：
//! 界面上（反汇编、交叉引用、调用图）能看到"这一行来自哪个源文件的哪一行"。
//!
//! # 边界
//!
//! * 只读，不改写任何字节。
//! * 不做类型系统（M8 明确把类型后置）：结构体布局、变量位置一律不读。
//! * 不因为调试信息缺失而失败：返回空的 [`DebugInfo`] 加一条 `notes` 说明。

mod dwarf;

pub use dwarf::{read_dwarf, DebugFunction, DebugInfo, DebugLine, DebugSkip, DebugUnit};

use bitflip_loader::object::Object;

/// 读目标里的调试信息。
///
/// 这是分析层唯一需要调用的入口：它负责在多种调试格式之间选择，并把"没有"
/// 这件事如实写进 `notes`，让上层不必知道 DWARF 与 PDB 的区别。
#[must_use]
pub fn read(object: &Object, bytes: &[u8]) -> DebugInfo {
    read_dwarf(object, bytes)
}
