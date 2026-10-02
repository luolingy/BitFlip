//! 符号来源、优先级与候选合并。
//!
//! 一个地址上的名字可能来自多个来源：用户手写、签名库匹配、调试信息、导出表、
//! 符号表、unwind 表、调用目标推断……BitFlip 的做法是**保留全部候选**，
//! 按来源优先级与置信度选一个用于展示，同时把"为什么叫这个名字"暴露给 UI。
//!
//! 这与参照实现的做法相反：那里用 `func_xxx` / `loc_xxx` 自动生成的假名
//! 填满符号表，把"没分析出来"伪装成"分析出来了"。
//!
//! M0 只固定契约（M3 起接入真实符号来源）。

use thiserror::Error;

/// 符号来源。数字越小优先级越高。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum SymbolSource {
    /// 用户手工命名/注释（永远最高优先级）。
    User,
    /// 签名库匹配（FLIRT 风格，M8）。
    Signature,
    /// 调试信息：DWARF / PDB（M8）。
    DebugInfo,
    /// 导出表（PE Export Table / ELF `.dynsym` 的全局定义）。
    Export,
    /// 符号表：ELF `.symtab` / COFF 符号表。
    SymbolTable,
    /// 异常/展开表：PE `.pdata`、ELF `.eh_frame` FDE。
    Unwind,
    /// 导入 thunk（IAT/PLT 桩）。
    ImportThunk,
    /// 分析推断出来的函数入口（调用目标 / prologue 模式）。
    Discovery,
    /// 兜底启发式（对齐填充里发现的代码等），置信度最低。
    Heuristic,
}

impl SymbolSource {
    /// 稳定的短名。
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::User => "user",
            Self::Signature => "signature",
            Self::DebugInfo => "debug-info",
            Self::Export => "export",
            Self::SymbolTable => "symbol-table",
            Self::Unwind => "unwind",
            Self::ImportThunk => "import-thunk",
            Self::Discovery => "discovery",
            Self::Heuristic => "heuristic",
        }
    }

    /// 面向界面的中文名。
    #[must_use]
    pub const fn label_zh(self) -> &'static str {
        match self {
            Self::User => "用户命名",
            Self::Signature => "签名库",
            Self::DebugInfo => "调试信息",
            Self::Export => "导出表",
            Self::SymbolTable => "符号表",
            Self::Unwind => "展开表",
            Self::ImportThunk => "导入桩",
            Self::Discovery => "分析推断",
            Self::Heuristic => "启发式",
        }
    }

    /// 优先级权重（越小越优先）。
    #[must_use]
    pub const fn priority(self) -> u8 {
        match self {
            Self::User => 0,
            Self::Signature => 10,
            Self::DebugInfo => 20,
            Self::Export => 30,
            Self::SymbolTable => 40,
            Self::Unwind => 50,
            Self::ImportThunk => 60,
            Self::Discovery => 70,
            Self::Heuristic => 90,
        }
    }
}

/// 一个符号候选。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SymbolCandidate {
    /// 地址。
    pub addr: u64,
    /// 名字。
    pub name: String,
    /// 来源。
    pub source: SymbolSource,
    /// 置信度（0–100）。同来源之间的比较依据。
    pub confidence: u8,
}

/// 符号层错误。
#[derive(Debug, Error)]
pub enum SymbolError {
    /// 候选结构非法（空名）。
    #[error("非法符号候选：地址 {addr:#x} 的名字为空")]
    EmptyName {
        /// 涉及的地址。
        addr: u64,
    },
}

/// 在候选集合里选出用于展示的那个：先比来源优先级，再比置信度。
///
/// 返回的引用可被 UI 用来解释来源；其余候选不会被丢弃（M3 起随工程库持久化）。
#[must_use]
pub fn preferred(candidates: &[SymbolCandidate]) -> Option<&SymbolCandidate> {
    candidates
        .iter()
        .min_by_key(|c| (c.source.priority(), 255 - c.confidence))
}

/// 校验候选合法性。
pub fn validate(candidate: &SymbolCandidate) -> Result<(), SymbolError> {
    if candidate.name.trim().is_empty() {
        return Err(SymbolError::EmptyName {
            addr: candidate.addr,
        });
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn cand(addr: u64, name: &str, source: SymbolSource, confidence: u8) -> SymbolCandidate {
        SymbolCandidate {
            addr,
            name: name.to_string(),
            source,
            confidence,
        }
    }

    #[test]
    fn user_name_wins_over_everything() {
        let candidates = vec![
            cand(0x1000, "sub_1000", SymbolSource::Discovery, 90),
            cand(0x1000, "memcpy", SymbolSource::Signature, 99),
            cand(0x1000, "my_copy", SymbolSource::User, 10),
        ];
        let best = preferred(&candidates).expect("应有候选");
        assert_eq!(best.name, "my_copy");
        assert_eq!(best.source, SymbolSource::User);
    }

    #[test]
    fn same_source_uses_confidence() {
        let candidates = vec![
            cand(0x2000, "weak", SymbolSource::SymbolTable, 40),
            cand(0x2000, "strong", SymbolSource::SymbolTable, 95),
        ];
        assert_eq!(preferred(&candidates).expect("候选").name, "strong");
    }

    #[test]
    fn empty_candidates_yield_none_and_validation_rejects_blank_names() {
        assert!(preferred(&[]).is_none());
        let blank = cand(0x3000, "   ", SymbolSource::Export, 100);
        assert!(matches!(
            validate(&blank),
            Err(SymbolError::EmptyName { addr: 0x3000 })
        ));
    }

    #[test]
    fn priorities_are_ordered_as_documented() {
        assert!(SymbolSource::User.priority() < SymbolSource::Signature.priority());
        assert!(SymbolSource::DebugInfo.priority() < SymbolSource::Export.priority());
        assert!(SymbolSource::Export.priority() < SymbolSource::SymbolTable.priority());
        assert!(SymbolSource::SymbolTable.priority() < SymbolSource::Unwind.priority());
        assert!(SymbolSource::Unwind.priority() < SymbolSource::Discovery.priority());
        assert!(SymbolSource::Discovery.priority() < SymbolSource::Heuristic.priority());
        assert_eq!(SymbolSource::Unwind.as_str(), "unwind");
        assert_eq!(SymbolSource::Export.label_zh(), "导出表");
    }
}
