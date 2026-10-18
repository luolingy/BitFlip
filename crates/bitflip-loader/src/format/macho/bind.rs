//! dyld 绑定操作码（`LC_DYLD_INFO(_ONLY)` 的 `bind_off` / `lazy_bind_off` 两段流）。
//!
//! # 这是什么
//!
//! Mach-O 的导入表和 PE 的 IAT 不是一回事：文件里没有"导入表"结构，只有**一段指令
//! 流**，dyld 在加载时逐条执行它，把"符号 → 库里的地址"写进指定的指针槽
//! （`__DATA,__got`、`__DATA,__objc_classrefs`、`__DATA,__la_symbol_ptr` 等）。
//! 所以"这个二进制导入了什么"必须靠**执行这串操作码**才能得到 —— 只读符号表只能
//! 看到 `N_UNDF` 的名字，看不到它绑定到哪个库、写在哪个地址。
//!
//! # 操作码表（出处：Apple `dyld` 的 `src/dyld.h` / `bind.h` 里的 `enum BindOpcode`）
//!
//! ```text
//! 每条操作码 = 1 字节：高 4 位是操作码，低 4 位是立即数（BIND_OPCODE_MASK = 0xF0、
//! BIND_IMMEDIATE_MASK = 0x0F）。带 uleb/sleb 的操作数紧跟在字节之后。
//!
//! 0x00 DONE                               结束（lazy 流里表示"这一条结束，继续下一条"）
//! 0x10 SET_DYLIB_ORDINAL_IMM              imm = 库序号（0 = self）
//! 0x20 SET_DYLIB_ORDINAL_ULEB             操作数 = 库序号
//! 0x30 SET_DYLIB_SPECIAL_IMM              低 4 位与 0xF0 相或后按 8 位补码解释：
//!                                         0=self、0x3F(=0xFF)=-1 main-executable、
//!                                         0x3E(=0xFE)=-2 flat、0x3D(=0xFD)=-3 weak
//! 0x40 SET_SYMBOL_TRAILING_FLAGS_IMM      imm = flags，后跟 NUL 结尾的符号名
//! 0x50 SET_TYPE_IMM                       imm = 绑定类型（1=pointer、2=text_abs32、3=text_pcrel32）
//! 0x60 SET_ADDEND_SLEB                    操作数 = 有符号加数
//! 0x70 SET_SEGMENT_AND_OFFSET_ULEB        imm = 段序号，操作数 = 段内偏移
//! 0x80 ADD_ADDR_ULEB                      段内偏移 += 操作数（不绑定）
//! 0x90 DO_BIND                            把当前符号绑定到当前槽位，然后槽位前移一个指针
//! 0xA0 DO_BIND_ADD_ADDR_ULEB              先 DO_BIND，再 偏移 += 操作数 + 指针大小
//! 0xB0 DO_BIND_ADD_ADDR_IMM_SCALED        先 DO_BIND，再 偏移 += imm × 指针大小 + 指针大小
//! 0xC0 DO_BIND_ULEB_TIMES_SKIPPING_ULEB   重复 count 次：DO_BIND 后 偏移 += skip + 指针大小（skip 是字节数）
//!
//! 偏移的加法一律**回绕**（`wrapping_add`）：ld64 的绑定表按（库, 符号）排序后会往回跳，
//! 回跳量被编成 10 字节的 ULEB128 二补数（真实样本里见过 `-0x220`）；dyld 的 `offset`
//! 是 `uint64_t`，`offset += read_uleb128()` 本身就是回绕加法。用 checked_add 会把
//! 这类合法文件判成坏文件。
//! 0xD0 THREADED                           arm64e 的线程化绑定（子操作码见下），本片不解
//! ```
//!
//! # 关于 0x80–0xC0 这三档的取值
//!
//! 任务书里给的是一张 `DO_BIND 0x80 / DO_BIND_ADDEND_ULEB 0x90 /
//! DO_BIND_ADDEND_SLEB 0xA0 / DO_BIND_ULEB_TIMES_SKIPPING_ULEB 0xB0` 的表，并且
//! 把 0x80 记成"ADD_ADDR_ULEB"的位置留空了。**那张表与 dyld 的 `bind.h` 不一致**：
//! dyld 里根本没有叫 `DO_BIND_ADDEND_*` 的操作码（加数只有 `SET_ADDEND_SLEB` 一个来源，
//! 它在 DO_BIND 之前设好、由 DO_BIND 一并写进槽位），而 0x80 是 `ADD_ADDR_ULEB`。
//!
//! 证据不是记忆，是**在真实二进制上对出来的**（`temp/net.kdt.pojavlauncher…ipa` 的主
//! 二进制，1 176 816 字节、`LC_DYLD_INFO_ONLY`）：
//!
//! * 用本文件的表解出的导入条数 = 1 547（regular 1 382 + lazy 165），
//!   与 `llvm-objdump --macho --bind/--lazy-bind` 逐行数出来的
//!   **1 382 / 165 完全相同**，地址与库名也逐条相同；
//! * 若按任务书那张表解（0x80 当 DO_BIND、0x90 当 DO_BIND_ADDEND_ULEB），第一条
//!   0x80 就会在没有 `SET_SYMBOL` 的状态下"绑定"，紧接着的操作数字节会被当成下一条
//!   操作码 —— 实测会立刻报"0x?? 不是已知操作码"。
//!
//! 所以这里按 dyld 的真实表实现，并把差异写进提交说明与文档（任务书的表是错的）。
//!
//! # 恶性输入
//!
//! 流里的每个操作数都先做边界检查；ULEB128 复用父模块那份实现（截断/超长都报错）。
//! 段序号越界、库序号越界、`DO_BIND` 时还没有符号名，都是**文件损坏** → `ParseError`。
//! `THREADED` 是"规范里有、本片不解" → 记 `notes` 后停止这条流（已解出的照常返回），
//! 不静默给短表。

use crate::reader::ParseError;

use super::MachOSegment;

/// 操作码掩码（高 4 位）。
pub const BIND_OPCODE_MASK: u8 = 0xf0;
/// 立即数掩码（低 4 位）。
pub const BIND_IMMEDIATE_MASK: u8 = 0x0f;

/// `BIND_OPCODE_DONE`。
pub const BIND_OPCODE_DONE: u8 = 0x00;
/// `BIND_OPCODE_SET_DYLIB_ORDINAL_IMM`。
pub const BIND_OPCODE_SET_DYLIB_ORDINAL_IMM: u8 = 0x10;
/// `BIND_OPCODE_SET_DYLIB_ORDINAL_ULEB`。
pub const BIND_OPCODE_SET_DYLIB_ORDINAL_ULEB: u8 = 0x20;
/// `BIND_OPCODE_SET_DYLIB_SPECIAL_IMM`。
pub const BIND_OPCODE_SET_DYLIB_SPECIAL_IMM: u8 = 0x30;
/// `BIND_OPCODE_SET_SYMBOL_TRAILING_FLAGS_IMM`。
pub const BIND_OPCODE_SET_SYMBOL_TRAILING_FLAGS_IMM: u8 = 0x40;
/// `BIND_OPCODE_SET_TYPE_IMM`。
pub const BIND_OPCODE_SET_TYPE_IMM: u8 = 0x50;
/// `BIND_OPCODE_SET_ADDEND_SLEB`。
pub const BIND_OPCODE_SET_ADDEND_SLEB: u8 = 0x60;
/// `BIND_OPCODE_SET_SEGMENT_AND_OFFSET_ULEB`。
pub const BIND_OPCODE_SET_SEGMENT_AND_OFFSET_ULEB: u8 = 0x70;
/// `BIND_OPCODE_ADD_ADDR_ULEB`。
pub const BIND_OPCODE_ADD_ADDR_ULEB: u8 = 0x80;
/// `BIND_OPCODE_DO_BIND`。
pub const BIND_OPCODE_DO_BIND: u8 = 0x90;
/// `BIND_OPCODE_DO_BIND_ADD_ADDR_ULEB`。
pub const BIND_OPCODE_DO_BIND_ADD_ADDR_ULEB: u8 = 0xa0;
/// `BIND_OPCODE_DO_BIND_ADD_ADDR_IMM_SCALED`。
pub const BIND_OPCODE_DO_BIND_ADD_ADDR_IMM_SCALED: u8 = 0xb0;
/// `BIND_OPCODE_DO_BIND_ULEB_TIMES_SKIPPING_ULEB`。
pub const BIND_OPCODE_DO_BIND_ULEB_TIMES_SKIPPING_ULEB: u8 = 0xc0;
/// `BIND_OPCODE_THREADED`（arm64e 线程化绑定）。
pub const BIND_OPCODE_THREADED: u8 = 0xd0;

/// `BIND_SPECIAL_DYLIB_SELF`（立即数 0）。
pub const BIND_SPECIAL_DYLIB_SELF: i64 = 0;
/// `BIND_SPECIAL_DYLIB_MAIN_EXECUTABLE`（立即数按补码是 -1）。
pub const BIND_SPECIAL_DYLIB_MAIN_EXECUTABLE: i64 = -1;
/// `BIND_SPECIAL_DYLIB_FLAT_LOOKUP`（-2）。
pub const BIND_SPECIAL_DYLIB_FLAT_LOOKUP: i64 = -2;
/// `BIND_SPECIAL_DYLIB_WEAK_LOOKUP`（-3）。
pub const BIND_SPECIAL_DYLIB_WEAK_LOOKUP: i64 = -3;

/// `BIND_TYPE_POINTER`（默认）。
pub const BIND_TYPE_POINTER: u8 = 1;

/// 一条绑定流的来处。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BindKind {
    /// `bind_off` / `bind_size`：普通绑定，加载时一次性做完。
    Regular,
    /// `lazy_bind_off` / `lazy_bind_size`：惰性绑定，**每条以 `DONE` 结尾**，
    /// 第一次调用时才执行到那一条 —— 规范语言相同，只是每段的状态各自从头开始。
    Lazy,
}

impl BindKind {
    /// 稳定的短名（进 `notes` 与错误信息）。
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Regular => "bind",
            Self::Lazy => "lazy_bind",
        }
    }

    /// 中文说明。
    #[must_use]
    pub const fn label_zh(self) -> &'static str {
        match self {
            Self::Regular => "普通绑定",
            Self::Lazy => "惰性绑定",
        }
    }
}

/// 一条绑定出来的导入（结构层事实）。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BindImport {
    /// 符号名。
    pub name: String,
    /// `SET_SYMBOL_TRAILING_FLAGS_IMM` 的立即数（`0x1` = weak import，`0x8` = non-weak def）。
    pub trailing_flags: u8,
    /// 目标库序号：正数是 `LC_LOAD_DYLIB` 的 1 基序号，0 / 负数是特殊序号。
    pub dylib_ordinal: i64,
    /// 目标库**名字**（按 `LC_LOAD_DYLIB` 的顺序解析出来的完整路径）。
    ///
    /// 特殊序号没有名字，这里是可读的占位标签（`<self>` / `<main-executable>` /
    /// `<flat-lookup>` / `<weak-lookup>`），见 [`resolve_dylib`]。
    /// **不**把裸序号留给上层去猜：序号 → 库名这一步必须在这里做完。
    pub dylib: String,
    /// 段序号（`SET_SEGMENT_AND_OFFSET_ULEB` 的立即数）。
    pub segment_index: u8,
    /// 段内偏移。
    pub segment_offset: u64,
    /// 被写入的槽位虚拟地址 = 段 `vmaddr` + 段内偏移。
    pub address: u64,
    /// 绑定类型（`BIND_TYPE_*`）。
    pub bind_type: u8,
    /// 加数（`SET_ADDEND_SLEB`，默认 0）。
    pub addend: i64,
    /// 这条来自哪条流。
    pub kind: BindKind,
}

/// 库序号 → 库名。
///
/// * 正数 `n`：`LC_LOAD_DYLIB` 列表里第 `n` 条（**1 基**，按加载命令顺序）。
///   越界就是坏文件（dyld 在这里也会报错），返回 `ParseError` —— 不把越界序号
///   原样透传，那样上层只能显示一个 `#7` 却不知道是谁。
/// * `0` / `-1` / `-2` / `-3`：`BIND_SPECIAL_DYLIB_SELF` / `MAIN_EXECUTABLE` /
///   `FLAT_LOOKUP` / `WEAK_LOOKUP`，没有库名，用尖括号标签。
/// * 其余负值：规范里没有定义，返回 `ParseError`。
fn resolve_dylib(
    ordinal: i64,
    dylibs: &[String],
    kind: BindKind,
    symbol: &str,
) -> Result<String, ParseError> {
    match ordinal {
        BIND_SPECIAL_DYLIB_SELF => Ok("<self>".to_string()),
        BIND_SPECIAL_DYLIB_MAIN_EXECUTABLE => Ok("<main-executable>".to_string()),
        BIND_SPECIAL_DYLIB_FLAT_LOOKUP => Ok("<flat-lookup>".to_string()),
        BIND_SPECIAL_DYLIB_WEAK_LOOKUP => Ok("<weak-lookup>".to_string()),
        n if n > 0 => {
            let index = usize::try_from(n - 1).unwrap_or(usize::MAX);
            dylibs.get(index).cloned().ok_or_else(|| {
                ParseError::Inconsistent(format!(
                    "{}：符号 {symbol:?} 的库序号是 {n}，但这个镜像的 LC_LOAD_DYLIB 只有 {} 条\
                     （序号是 1 基的）：绑定流与加载命令自相矛盾",
                    kind.as_str(),
                    dylibs.len()
                ))
            })
        }
        other => Err(ParseError::Inconsistent(format!(
            "{}：符号 {symbol:?} 的库序号是 {other}，不在 dyld 的特殊序号表里\
             （0=self、-1=main-executable、-2=flat-lookup、-3=weak-lookup）：文件被构造过",
            kind.as_str()
        ))),
    }
}

/// 绑定流的**执行状态**（dyld 的 `bind()` 里那几个局部变量）。
#[derive(Debug, Clone)]
struct State {
    ordinal: i64,
    symbol: Option<String>,
    trailing_flags: u8,
    bind_type: u8,
    addend: i64,
    segment: Option<u8>,
    offset: u64,
}

impl Default for State {
    fn default() -> Self {
        Self {
            ordinal: BIND_SPECIAL_DYLIB_SELF,
            symbol: None,
            trailing_flags: 0,
            bind_type: BIND_TYPE_POINTER,
            addend: 0,
            segment: None,
            offset: 0,
        }
    }
}

/// 单条流最多解出多少条绑定（挡住"重复 N 次"的放大输入）。
pub const MAX_BIND_SITES: u64 = 500_000;

/// 解一条绑定流。
///
/// `segments` 用来把（段序号, 段内偏移）换算成绝对地址 —— 序号越界就是坏文件，
/// 返回 `ParseError`（不猜段，也不悄悄跳过这条导入）。`dylibs` 是 `LC_LOAD_DYLIB`
/// 的库名表（按命令顺序），用来把库序号解析成库名。`pointer_size` 是文件位宽
/// 决定的槽位宽度（32 位 = 4、64 位 = 8）。
///
/// # Errors
///
/// 段序号越界、库序号越界或不在特殊序号表里、`DO_BIND` 时缺少符号名或段、
/// ULEB128 截断/超长、未知操作码、槽位落在段的虚拟范围之外 —— 都是 `ParseError`。
/// `THREADED` 不是错误：记 `notes` 后停止，已解出的照常返回。
pub fn parse(
    stream: &[u8],
    segments: &[MachOSegment],
    dylibs: &[String],
    pointer_size: u64,
    kind: BindKind,
    notes: &mut Vec<String>,
) -> Result<Vec<BindImport>, ParseError> {
    let mut out: Vec<BindImport> = Vec::new();
    if stream.is_empty() {
        return Ok(out);
    }

    let mut cursor = 0usize;
    let mut state = State::default();

    loop {
        if cursor >= stream.len() {
            break;
        }
        let byte = stream[cursor];
        cursor += 1;
        let opcode = byte & BIND_OPCODE_MASK;
        let imm = byte & BIND_IMMEDIATE_MASK;

        match opcode {
            BIND_OPCODE_DONE => {
                if kind == BindKind::Lazy {
                    // 惰性绑定的每条 entry 都以 DONE 结尾，并且**状态各自从头开始**
                    // （dyld 的 `eachLazyBind` 每条 entry 调一次 `bind()`，状态是局部变量）。
                    state = State::default();
                    continue;
                }
                break;
            }
            BIND_OPCODE_SET_DYLIB_ORDINAL_IMM => {
                state.ordinal = i64::from(imm);
            }
            BIND_OPCODE_SET_DYLIB_ORDINAL_ULEB => {
                let ordinal = read_uleb(stream, &mut cursor, kind, "SET_DYLIB_ORDINAL_ULEB")?;
                state.ordinal = i64::try_from(ordinal).map_err(|_| {
                    ParseError::Inconsistent(format!(
                        "{}：SET_DYLIB_ORDINAL_ULEB 的序号 {ordinal} 超出 i64",
                        kind.as_str()
                    ))
                })?;
            }
            BIND_OPCODE_SET_DYLIB_SPECIAL_IMM => {
                // dyld 原话：`libraryOrdinal = (int8_t)(BIND_OPCODE_MASK | immediate)`。
                // 立即数只有 **4 位**，符号扩展是"把高 4 位补成 0xF0 再按 8 位补码读"
                // —— 0x30|0x0F = 0x3F 代表 0xFF = -1（main-executable），
                // 0x3E 代表 0xFE = -2（flat lookup）、0x3D = 0xFD = -3（weak lookup）。
                // 直接对 4 位取补会得到 +15，那是错的。
                state.ordinal = if imm == 0 {
                    BIND_SPECIAL_DYLIB_SELF
                } else {
                    i64::from(i8::from_ne_bytes([BIND_OPCODE_MASK | imm]))
                };
            }
            BIND_OPCODE_SET_SYMBOL_TRAILING_FLAGS_IMM => {
                state.trailing_flags = imm;
                state.symbol = Some(read_cstring(stream, &mut cursor, kind)?);
            }
            BIND_OPCODE_SET_TYPE_IMM => {
                state.bind_type = imm;
            }
            BIND_OPCODE_SET_ADDEND_SLEB => {
                state.addend = read_sleb(stream, &mut cursor, kind)?;
            }
            BIND_OPCODE_SET_SEGMENT_AND_OFFSET_ULEB => {
                let index = usize::from(imm);
                if index >= segments.len() {
                    return Err(ParseError::Inconsistent(format!(
                        "{}：SET_SEGMENT_AND_OFFSET_ULEB 指向段 #{index}，但这个镜像只有 {} 个段\
                         （0..{}）：段的编号是文件里的事实，越界就是坏文件",
                        kind.as_str(),
                        segments.len(),
                        segments.len().saturating_sub(1)
                    )));
                }
                state.segment = Some(imm);
                state.offset = read_uleb(stream, &mut cursor, kind, "SET_SEGMENT_AND_OFFSET_ULEB")?;
            }
            BIND_OPCODE_ADD_ADDR_ULEB => {
                let delta = read_uleb(stream, &mut cursor, kind, "ADD_ADDR_ULEB")?;
                // **必须用回绕加法**：ld64 的绑定表按（库, 符号）排序后会**往回跳**，
                // 往回跳的增量是以 10 字节 ULEB128 编成的二补数（实测 PojavLauncher 的
                // 首个回跳是 `80 e0 fb ff ff ff ff ff ff ff 01` = -0x220）。dyld 里
                // `offset` 是 `uint64_t`，`offset += read_uleb128()` 就是回绕加法，
                // llvm-objdump 的地址列也与回绕后的值一致（0x1000B1460）。
                // 用 checked_add 会把这类真实文件判成坏文件，白丢 1300+ 条导入。
                state.offset = state.offset.wrapping_add(delta);
            }
            BIND_OPCODE_DO_BIND => {
                do_bind(&mut out, &state, segments, dylibs, kind, pointer_size)?;
                state.offset = state.offset.wrapping_add(pointer_size);
            }
            BIND_OPCODE_DO_BIND_ADD_ADDR_ULEB => {
                do_bind(&mut out, &state, segments, dylibs, kind, pointer_size)?;
                let delta = read_uleb(stream, &mut cursor, kind, "DO_BIND_ADD_ADDR_ULEB")?;
                // dyld：`offset += sizeof(intptr_t) + read_uleb128()` —— 除了操作数，
                // 槽位自己还要往前走一个指针（这一步很容易漏，漏了后面全错位）。
                state.offset = state.offset.wrapping_add(delta).wrapping_add(pointer_size);
            }
            BIND_OPCODE_DO_BIND_ADD_ADDR_IMM_SCALED => {
                do_bind(&mut out, &state, segments, dylibs, kind, pointer_size)?;
                // dyld：`offset += immediate*sizeof(intptr_t) + sizeof(intptr_t)`。
                let delta = u64::from(imm) * pointer_size + pointer_size;
                state.offset = state.offset.wrapping_add(delta);
            }
            BIND_OPCODE_DO_BIND_ULEB_TIMES_SKIPPING_ULEB => {
                let count = read_uleb(
                    stream,
                    &mut cursor,
                    kind,
                    "DO_BIND_ULEB_TIMES_SKIPPING_ULEB 的次数",
                )?;
                let skip = read_uleb(
                    stream,
                    &mut cursor,
                    kind,
                    "DO_BIND_ULEB_TIMES_SKIPPING_ULEB 的跳过量",
                )?;
                if count > MAX_BIND_SITES {
                    return Err(ParseError::Inconsistent(format!(
                        "{}：DO_BIND_ULEB_TIMES_SKIPPING_ULEB 声称要绑定 {count} 次，\
                         超过上限 {MAX_BIND_SITES}：这份流被人为构造过",
                        kind.as_str()
                    )));
                }
                // dyld 的每次迭代：`offset += skip + sizeof(intptr_t)`，其中 **skip 的
                // 单位是字节**（不是指针个数）—— 用 llvm-objdump 的地址列对照过：
                // 真实样本里 `DO_BIND_ULEB_TIMES_SKIPPING_ULEB{2, 0x48}` 的两次槽位相差
                // 0x50 字节，正是 0x48 + 8。
                let step = skip.checked_add(pointer_size).ok_or_else(|| {
                    ParseError::Overflow(format!("{}：跳过量 + 指针大小", kind.as_str()))
                })?;
                for _ in 0..count {
                    do_bind(&mut out, &state, segments, dylibs, kind, pointer_size)?;
                    state.offset = state.offset.wrapping_add(step);
                }
            }
            BIND_OPCODE_THREADED => {
                // arm64e 的线程化绑定：APPLY 分支要用线程化指针表与 rebase 信息，
                // 本片没有解那两张表，硬解会给出错地址。停下来并说明丢了多少字节。
                notes.push(format!(
                    "{} 流在 +{:#x} 处遇到 BIND_OPCODE_THREADED（arm64e 线程化绑定，\
                     子操作码 {imm:#x}）：本片**没有**解析线程化绑定的 APPLY 分支，\
                     这条流已解出 {} 条导入，其后还有 {} 字节未处理",
                    kind.as_str(),
                    cursor - 1,
                    out.len(),
                    stream.len() - cursor
                ));
                break;
            }
            other => {
                return Err(ParseError::Inconsistent(format!(
                    "{} 流在 +{:#x} 处的操作码 {other:#04x} 不在 dyld 的 bind 操作码表里：\
                     这条流的解码在这一点之前就已经错了（文件损坏或被人为构造）",
                    kind.as_str(),
                    cursor - 1
                )));
            }
        }

        if out.len() as u64 >= MAX_BIND_SITES {
            notes.push(format!(
                "{} 流解出的导入条数达到上限 {MAX_BIND_SITES}：只保留前 {MAX_BIND_SITES} 条，\
                 这条流还有 {} 字节未处理",
                kind.as_str(),
                stream.len() - cursor
            ));
            break;
        }
    }

    Ok(out)
}

/// 执行一条 `DO_BIND`：把当前（符号, 库序号）记到当前槽位。
fn do_bind(
    out: &mut Vec<BindImport>,
    state: &State,
    segments: &[MachOSegment],
    dylibs: &[String],
    kind: BindKind,
    pointer_size: u64,
) -> Result<(), ParseError> {
    let Some(symbol) = state.symbol.as_deref() else {
        return Err(ParseError::Inconsistent(format!(
            "{}：DO_BIND 之前没有 SET_SYMBOL_TRAILING_FLAGS_IMM —— dyld 会在这里报错，\
             没有符号名的绑定无法记录",
            kind.as_str()
        )));
    };
    let Some(index) = state.segment else {
        return Err(ParseError::Inconsistent(format!(
            "{}：DO_BIND 之前没有 SET_SEGMENT_AND_OFFSET_ULEB（符号 {symbol:?}）——\
             绑定槽位没有着落点",
            kind.as_str()
        )));
    };
    let segment = &segments[usize::from(index)];
    // 槽位必须落在段的虚拟范围内：越界说明这条流与段表不自洽（坏文件）。
    if state.offset >= segment.vmsize {
        return Err(ParseError::Inconsistent(format!(
            "{}：符号 {symbol:?} 的绑定偏移 {:#x} 超出段 {} 的虚拟大小 {:#x}：\
             绑定流与段表自相矛盾",
            kind.as_str(),
            state.offset,
            segment.name,
            segment.vmsize
        )));
    }
    let address = segment
        .vmaddr
        .checked_add(state.offset)
        .ok_or_else(|| ParseError::Overflow(format!("{}：段基址 + 偏移", kind.as_str())))?;
    // 槽位本身（address .. address + pointer_size）也要落在段里。
    if state.offset.saturating_add(pointer_size) > segment.vmsize {
        return Err(ParseError::Inconsistent(format!(
            "{}：符号 {symbol:?} 的 {pointer_size} 字节槽位（段 {} +{:#x}）越过段尾 {:#x}：\
             绑定流与段表自相矛盾",
            kind.as_str(),
            segment.name,
            state.offset,
            segment.vmsize
        )));
    }

    out.push(BindImport {
        name: symbol.to_string(),
        trailing_flags: state.trailing_flags,
        dylib_ordinal: state.ordinal,
        dylib: resolve_dylib(state.ordinal, dylibs, kind, symbol)?,
        segment_index: index,
        segment_offset: state.offset,
        address,
        bind_type: state.bind_type,
        addend: state.addend,
        kind,
    });
    Ok(())
}

/// 读一个 NUL 结尾的符号名并推进游标。
fn read_cstring(stream: &[u8], cursor: &mut usize, kind: BindKind) -> Result<String, ParseError> {
    let start = *cursor;
    if start >= stream.len() {
        return Err(ParseError::Inconsistent(format!(
            "{} 流在 +{start:#x} 处读符号名时数据就结束了",
            kind.as_str()
        )));
    }
    let nul = stream[start..]
        .iter()
        .position(|&byte| byte == 0)
        .ok_or_else(|| {
            ParseError::Inconsistent(format!(
                "{} 流在 +{start:#x} 处起的符号名到流尾都没有 NUL 终止符：这条流被裁剪",
                kind.as_str()
            ))
        })?;
    *cursor = start + nul + 1;
    Ok(String::from_utf8_lossy(&stream[start..start + nul]).into_owned())
}

/// 从 `stream[*cursor..]` 解一个 ULEB128 并推进游标（复用父模块那份解码器）。
fn read_uleb(
    stream: &[u8],
    cursor: &mut usize,
    kind: BindKind,
    what: &str,
) -> Result<u64, ParseError> {
    if *cursor >= stream.len() {
        return Err(ParseError::Inconsistent(format!(
            "{} 流在 +{:#x} 处读操作数（{what}）时数据就结束了",
            kind.as_str(),
            *cursor
        )));
    }
    match super::uleb128_at(stream, *cursor) {
        super::Uleb::Value(value, used) => {
            *cursor += used;
            Ok(value)
        }
        super::Uleb::Truncated => Err(ParseError::Inconsistent(format!(
            "{} 流在 +{:#x} 处读操作数（{what}）时 ULEB128 被截断（最后一个字节的续位仍是 1，\
             后面没有字节了）",
            kind.as_str(),
            *cursor
        ))),
        super::Uleb::Overflow => Err(ParseError::Inconsistent(format!(
            "{} 流在 +{:#x} 处读操作数（{what}）时 ULEB128 超过 64 位（合法编码最多 10 字节）：\
             这条流被人为构造过",
            kind.as_str(),
            *cursor
        ))),
    }
}

/// 从 `stream[*cursor..]` 解一个 SLEB128（有符号）并推进游标。
///
/// SLEB128 与 ULEB128 的区别只在高位的符号扩展：最后一个字节的最高有效位是符号位，
/// 且续位为 0。编码超过 64 位就是坏数据（本文件不接受"读到哪算哪"）。
fn read_sleb(stream: &[u8], cursor: &mut usize, kind: BindKind) -> Result<i64, ParseError> {
    let start = *cursor;
    let mut value: i64 = 0;
    let mut shift: u32 = 0;
    let mut index = start;
    loop {
        let Some(&byte) = stream.get(index) else {
            return Err(ParseError::Inconsistent(format!(
                "{} 流在 +{start:#x} 处读 SLEB128 时被截断（最后一个字节的续位仍是 1，\
                 后面没有字节了）",
                kind.as_str()
            )));
        };
        index += 1;
        let low = i64::from(byte & 0x7f);
        if shift >= 64 {
            return Err(ParseError::Inconsistent(format!(
                "{} 流在 +{start:#x} 处的 SLEB128 超过 64 位（合法编码最多 10 字节）：\
                 这条流被人为构造过",
                kind.as_str()
            )));
        }
        value |= low << shift;
        shift += 7;
        if byte & 0x80 == 0 {
            // 符号扩展：最后一个字节的 bit6 是符号位。
            if shift < 64 && byte & 0x40 != 0 {
                value |= -1i64 << shift;
            }
            *cursor = index;
            return Ok(value);
        }
    }
}
