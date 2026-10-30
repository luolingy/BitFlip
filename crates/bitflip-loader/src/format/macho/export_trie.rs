//! 导出 trie：`LC_DYLD_INFO(_ONLY).export_off` / `LC_DYLD_EXPORTS_TRIE` 指向的那张表。
//!
//! # 为什么要有它
//!
//! `LC_SYMTAB` 在 App Store 的二进制里经常被剥光（或者只留下少数符号），真正对外的
//! 导出集写在**导出 trie** 里 —— dyld 解析的就是它。只看符号表会把"这个库导出了
//! 什么"答错，而且答错的方式是**少给**，界面上看不出来（CLAUDE.md §7）。
//!
//! # 编码（出处）
//!
//! 规范出自 dyld 的 `ExportInfo`（`dyld` 的 `ImageLoaderMachO.h`）与 ld64 的
//! `ExportFile`（写这一侧），要点如下 —— 本文件**只按这段描述拼/解**：
//!
//! ```text
//! trie 的每个节点（从根节点 +0 开始）:
//!   uleb128  terminal_size          // 为 0 表示本节点没有导出
//!   [terminal_size 字节的 terminal] // 非 0 时紧跟
//!   uint8    child_count
//!   child_count × {
//!     c-string edge_label           // 边标签（NUL 结尾，不含 NUL）
//!     uleb128  child_node_offset    // 相对整张 trie 起点的偏移
//!   }
//!
//! terminal（terminal_size 那一段，字段顺序是 ld64 写出来的顺序）:
//!   uleb128  flags
//!   若 flags & EXPORT_SYMBOL_FLAGS_REEXPORT (0x08):
//!       uleb128  ordinal          // 目标库的 LC_LOAD_DYLIB 序号（1 基）
//!       c-string original_name    // 空串 = 与导出名同名
//!   否则:
//!       uleb128  address          // 相对镜像基址（__TEXT.vmaddr）的偏移
//!       若 flags & EXPORT_SYMBOL_FLAGS_STUB_AND_RESOLVER (0x10):
//!           uleb128  other        // 第二个地址（dyld 的 ExportInfo.other）
//! ```
//!
//! **flags 必须先读**：它是决定"后面的字节是序号+名字还是地址"的开关 —— 顺序反过来
//! 就无法解释了。`EXPORT_SYMBOL_FLAGS_KIND_MASK = 0x03` 区分 regular(0) /
//! thread_local(1) / absolute(2)，三者都**没有**额外字段，所以本文件只记原始 flags。
//!
//! # 名字怎么拼
//!
//! 一个符号的完整名字 = 从根走到它的路径上所有**边标签**依次拼接。节点自己不带名字。
//! 所以遍历必须带着前缀（本文件用 `String` 前缀 + 显式栈，不用递归 —— 恶意 trie
//! 可以把"深度"做成几万层，递归会先把调用栈打爆）。
//!
//! # 恶意/损坏输入（硬要求：不许挂死、不许静默给短表）
//!
//! | 情形 | 处理 |
//! |------|------|
//! | 同一个节点偏移被访问第二次（环 / 共享子树） | `ParseError::Inconsistent`，报偏移与路径 |
//! | 深度 > [`MAX_TRIE_DEPTH`]、名字长 > [`MAX_NAME_LEN`] | `ParseError::Inconsistent` |
//! | 节点数 > [`MAX_TRIE_NODES`]、导出数 > [`MAX_TRIE_EXPORTS`] | `ParseError::Inconsistent` |
//! | ULEB128 在数据中间结束 / 超过 10 字节 | `ParseError::Inconsistent`（点名是哪个字段） |
//! | 子节点偏移越界、terminal 越过 payload | `ParseError::Inconsistent` |
//!
//! 这些一律是**错误**而不是"尽量读"：坏 trie 里继续走只会给出错名字或错地址，
//! 那比拒绝更糟（§7）。
//!
//! **不在此表的一类**：**空边标签**。节点可以带一个空标签子节点作为"跳板"（这一步不追加
//! 名字字符，直接走到子节点，是路径压缩的边界情形）。ld64 一般不写，但其他链接器/后处理会
//! 生成；它不产生名字、名字前缀原样传下去，不会掩盖环或超深，所以**合法、如实继续走**。

use crate::reader::ParseError;

/// `EXPORT_SYMBOL_FLAGS_KIND_MASK`（`mach-o/loader.h`）：低两位是符号类别。
pub const EXPORT_SYMBOL_FLAGS_KIND_MASK: u64 = 0x03;
/// `EXPORT_SYMBOL_FLAGS_WEAK_DEFINITION`。
pub const EXPORT_SYMBOL_FLAGS_WEAK_DEFINITION: u64 = 0x04;
/// `EXPORT_SYMBOL_FLAGS_REEXPORT`：本条导出是"转发到另一个库里的符号"。
pub const EXPORT_SYMBOL_FLAGS_REEXPORT: u64 = 0x08;
/// `EXPORT_SYMBOL_FLAGS_STUB_AND_RESOLVER`：本条导出带第二个地址（stub / resolver）。
pub const EXPORT_SYMBOL_FLAGS_STUB_AND_RESOLVER: u64 = 0x10;

/// trie 的最大深度（边数）。真实导出名最长也就几百字节，128 层已经极其宽裕。
pub const MAX_TRIE_DEPTH: u32 = 128;
/// 单个导出名的最大字节数。
pub const MAX_NAME_LEN: usize = 4096;
/// 遍历的最大节点数（挡住"节点很多但大部分没有导出"的放大输入）。
pub const MAX_TRIE_NODES: u64 = 1_000_000;
/// 最大导出条数。
pub const MAX_TRIE_EXPORTS: u64 = 500_000;

/// 一条从 trie 里解出来的导出（结构层事实，地址已按镜像基址换算成绝对虚拟地址）。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MachOExport {
    /// 完整符号名（根到节点的边标签拼接）。
    pub name: String,
    /// 原始 `flags`（本文件不解释 `KIND_*`，只如实保留）。
    pub flags: u64,
    /// 绝对虚拟地址 = 镜像基址 + trie 里的偏移。
    ///
    /// `REEXPORT` 的 terminal 里**没有**地址字段，所以那时是 `None` ——
    /// 这里的 `None` 是"文件里没写"，不是"地址是 0"。
    pub address: Option<u64>,
    /// `STUB_AND_RESOLVER` 的第二个地址（dyld 的 `ExportInfo.other`，同样是相对基址的偏移）。
    ///
    /// 规范里这两个字段就叫 `address` 与 `other`，**没有**说明哪个是 stub、哪个是
    /// resolver，所以本结构不替它下结论（不发明字段名）。
    pub other: Option<u64>,
    /// `REEXPORT` 的目标库序号（`LC_LOAD_DYLIB` 的 1 基序号；解析成库名在 `mod.rs`）。
    pub reexport_ordinal: Option<u64>,
    /// `REEXPORT` 的目标库**名字**（按 `LC_LOAD_DYLIB` 顺序解析；解析失败是错误，
    /// 不会留一个裸序号给上层猜）。
    pub reexport_library: Option<String>,
    /// `REEXPORT` 的原始名字；空串表示"与导出名同名"（这是规范给的省略形式，不是缺字段）。
    pub reexport_name: Option<String>,
}

impl MachOExport {
    /// 是否是 re-export（转发到别的库，本镜像里没有代码）。
    #[must_use]
    pub const fn is_reexport(&self) -> bool {
        self.flags & EXPORT_SYMBOL_FLAGS_REEXPORT != 0
    }

    /// 是否是 `STUB_AND_RESOLVER`（带第二个地址）。
    #[must_use]
    pub const fn is_stub_and_resolver(&self) -> bool {
        self.flags & EXPORT_SYMBOL_FLAGS_STUB_AND_RESOLVER != 0
    }
}

/// 解一张导出 trie。
///
/// `payload` 是 trie 的字节（调用方已按 `export_off`/`export_size` 切好并校验过范围），
/// `base` 是镜像基址（`__TEXT.vmaddr`）—— 地址字段是相对它的偏移。`dylibs` 是
/// `LC_LOAD_DYLIB` 的库名表，用来把 re-export 的库序号解析成库名。
///
/// 返回的导出按**trie 里边出现的顺序**（子节点按编码顺序压栈，弹出顺序就是原顺序）。
/// ld64 写出来时它正好是字典序，但这里**不额外排序** —— 再排一次会把
/// "trie 没按规范解出来"这种问题盖住。
///
/// # Errors
///
/// 见模块文档的表：环、超深、超长名字、截断/超长 ULEB128、越界偏移都是错误；
/// re-export 的库序号为 0 或超出 `LC_LOAD_DYLIB` 的条数也是错误（坏文件）。
pub fn parse(payload: &[u8], base: u64, dylibs: &[String]) -> Result<Vec<MachOExport>, ParseError> {
    if payload.is_empty() {
        return Ok(Vec::new());
    }

    let mut out: Vec<MachOExport> = Vec::new();
    // 显式栈：(节点偏移, 名字前缀, 深度)。逆序压子节点就能按原顺序弹出。
    let mut stack: Vec<(usize, String, u32)> = vec![(0, String::new(), 0)];
    let mut visited: Vec<usize> = Vec::new();
    let mut nodes: u64 = 0;

    while let Some((offset, prefix, depth)) = stack.pop() {
        if depth > MAX_TRIE_DEPTH {
            return Err(ParseError::Inconsistent(format!(
                "导出 trie 的深度超过上限 {MAX_TRIE_DEPTH}（走到 +{offset:#x}、名字前缀 \
                 {prefix:?} 时）：环或人为构造的超深 trie，停止解析"
            )));
        }
        if visited.contains(&offset) {
            return Err(ParseError::Inconsistent(format!(
                "导出 trie 的节点 +{offset:#x} 被第二次访问（名字前缀 {prefix:?}）：\
                 规范要求它是树，出现环或共享子树会让遍历无限下去 —— 拒绝这张表"
            )));
        }
        visited.push(offset);
        nodes += 1;
        if nodes > MAX_TRIE_NODES {
            return Err(ParseError::Inconsistent(format!(
                "导出 trie 的节点数超过上限 {MAX_TRIE_NODES}：文件可能被构造（拒绝继续走）"
            )));
        }

        let mut cursor = offset;
        let terminal_size = read_uleb(payload, &mut cursor, "terminal_size", offset)?;

        if terminal_size > 0 {
            let size = usize::try_from(terminal_size).map_err(|_| {
                ParseError::Inconsistent(format!(
                    "导出 trie 的节点 +{offset:#x} 声明 terminal_size = {terminal_size}，超出 usize"
                ))
            })?;
            let end = cursor.checked_add(size).ok_or_else(|| {
                ParseError::Overflow(format!(
                    "导出 trie 的节点 +{offset:#x} 的 terminal 结束偏移"
                ))
            })?;
            if end > payload.len() {
                return Err(ParseError::Inconsistent(format!(
                    "导出 trie 的节点 +{offset:#x} 的 terminal（{cursor:#x}..{end:#x}）超出表尾 \
                     {:#x}：表被裁剪",
                    payload.len()
                )));
            }
            out.push(parse_terminal(
                &payload[cursor..end],
                offset,
                &prefix,
                base,
                dylibs,
            )?);
            if out.len() as u64 > MAX_TRIE_EXPORTS {
                return Err(ParseError::Inconsistent(format!(
                    "导出 trie 的导出条数超过上限 {MAX_TRIE_EXPORTS}：文件可能被构造"
                )));
            }
            cursor = end;
        }

        // terminal 之后是 child_count 与子节点表。
        let child_count = *payload.get(cursor).ok_or_else(|| {
            ParseError::Inconsistent(format!(
                "导出 trie 的节点 +{offset:#x} 在 +{cursor:#x} 处缺 child_count 字节：表被裁剪"
            ))
        })?;
        cursor += 1;

        let mut children: Vec<(usize, &str)> = Vec::with_capacity(usize::from(child_count));
        for _ in 0..child_count {
            let label_start = cursor;
            let nul = payload[label_start..]
                .iter()
                .position(|&byte| byte == 0)
                .map(|index| label_start + index)
                .ok_or_else(|| {
                    ParseError::Inconsistent(format!(
                        "导出 trie 的节点 +{offset:#x} 的边标签（起于 +{label_start:#x}）\
                         到表尾都没有 NUL 终止符：表被裁剪"
                    ))
                })?;
            let label = std::str::from_utf8(&payload[label_start..nul]).map_err(|_| {
                ParseError::Inconsistent(format!(
                    "导出 trie 的节点 +{offset:#x} 的边标签（+{label_start:#x}）不是合法 UTF-8"
                ))
            })?;
            // 空边标签是**合法**的：节点可以带一个空标签子节点作为"跳板"——这一步不追加
            // 任何名字字符，直接走到子节点（路径压缩的边界情形）。ld64 一般不写，但其他
            // 链接器/后处理（strip、壳、LTO、自研链接器）会生成。空标签不产生名字、名字前缀
            // 原样传给子节点，不会掩盖环或超深（那些由 visited / MAX_TRIE_DEPTH / 节点数上限
            // 独立检测），所以这里**不报错**，如实继续走。
            cursor = nul + 1;
            let child = read_uleb(payload, &mut cursor, "child_node_offset", offset)?;
            let child = usize::try_from(child).map_err(|_| {
                ParseError::Inconsistent(format!(
                    "导出 trie 的节点 +{offset:#x} 的子节点偏移 {child} 超出 usize"
                ))
            })?;
            if child >= payload.len() {
                return Err(ParseError::Inconsistent(format!(
                    "导出 trie 的节点 +{offset:#x} 的子节点偏移 +{child:#x} 超出表大小 {:#x}",
                    payload.len()
                )));
            }
            children.push((child, label));
        }

        // 逆序压栈：弹出顺序与 trie 里边的书写顺序一致。
        for (child, label) in children.into_iter().rev() {
            let mut name = String::with_capacity(prefix.len() + label.len());
            name.push_str(&prefix);
            name.push_str(label);
            if name.len() > MAX_NAME_LEN {
                return Err(ParseError::Inconsistent(format!(
                    "导出 trie 里有个名字超过 {MAX_NAME_LEN} 字节（到 +{child:#x} 时已经是 \
                     {} 字节）：文件被构造",
                    name.len()
                )));
            }
            stack.push((child, name, depth + 1));
        }
    }

    Ok(out)
}

/// 解一段 terminal（长度由节点自己写的 `terminal_size` 决定）。
fn parse_terminal(
    terminal: &[u8],
    node_offset: usize,
    name: &str,
    base: u64,
    dylibs: &[String],
) -> Result<MachOExport, ParseError> {
    let mut cursor = 0usize;
    let flags = read_uleb(terminal, &mut cursor, "flags", node_offset)?;

    let mut entry = MachOExport {
        name: name.to_string(),
        flags,
        address: None,
        other: None,
        reexport_ordinal: None,
        reexport_library: None,
        reexport_name: None,
    };

    if flags & EXPORT_SYMBOL_FLAGS_REEXPORT != 0 {
        let ordinal = read_uleb(terminal, &mut cursor, "reexport ordinal", node_offset)?;
        // 序号是 1 基的。0 或越界都说明 terminal 与加载命令自相矛盾 —— 报错，
        // 不把裸序号透传出去让上层去猜。
        let library = ordinal
            .checked_sub(1)
            .and_then(|zero_based| usize::try_from(zero_based).ok())
            .and_then(|zero_based| dylibs.get(zero_based))
            .cloned()
            .ok_or_else(|| {
                ParseError::Inconsistent(format!(
                    "导出 {name:?} 的 re-export 库序号是 {ordinal}，但这个镜像的 \
                     LC_LOAD_DYLIB 只有 {} 条（序号是 1 基的）：trie 与加载命令自相矛盾",
                    dylibs.len()
                ))
            })?;
        let tail = &terminal[cursor..];
        let nul = tail.iter().position(|&byte| byte == 0).ok_or_else(|| {
            ParseError::Inconsistent(format!(
                "导出 {name:?} 的 re-export 原始名字（terminal 内偏移 +{cursor:#x}）没有 NUL \
                 终止符：terminal_size 与内容对不上"
            ))
        })?;
        let original = String::from_utf8_lossy(&tail[..nul]).into_owned();
        // 规范允许省略：空串 = 与导出名同名。原样保留空串，不在这里替换成 name
        // —— "文件里写的是空串"和"文件里写了同名"是两件事，替换掉就看不出来了。
        entry.reexport_ordinal = Some(ordinal);
        entry.reexport_library = Some(library);
        entry.reexport_name = Some(original);
        let rest = &tail[nul + 1..];
        if rest.iter().any(|&byte| byte != 0) {
            return Err(ParseError::Inconsistent(format!(
                "导出 {name:?} 的 re-export terminal 在原始名字之后还有 {} 字节非零数据：\
                 terminal_size 与内容对不上",
                rest.len()
            )));
        }
        return Ok(entry);
    }

    let address = read_uleb(terminal, &mut cursor, "address", node_offset)?;
    entry.address = Some(base.checked_add(address).ok_or_else(|| {
        ParseError::Overflow(format!(
            "导出 {name:?} 的地址：镜像基址 {base:#x} + 偏移 {address:#x}"
        ))
    })?);

    if flags & EXPORT_SYMBOL_FLAGS_STUB_AND_RESOLVER != 0 {
        let other = read_uleb(
            terminal,
            &mut cursor,
            "stub/resolver（第二个地址）",
            node_offset,
        )?;
        entry.other = Some(base.checked_add(other).ok_or_else(|| {
            ParseError::Overflow(format!(
                "导出 {name:?} 的第二个地址：镜像基址 {base:#x} + 偏移 {other:#x}"
            ))
        })?);
    }

    if terminal[cursor..].iter().any(|&byte| byte != 0) {
        return Err(ParseError::Inconsistent(format!(
            "导出 {name:?} 的 terminal 解析完 flags/address 之后还有 {} 字节非零数据：\
             terminal_size 与内容对不上",
            terminal.len() - cursor
        )));
    }

    Ok(entry)
}

/// 从 `bytes[*cursor..]` 解一个 ULEB128 并推进游标。
///
/// 复用父模块那份实现（`LC_FUNCTION_STARTS` 用的是同一个解码器）：ULEB128 的规则
/// 只该有一份，两份迟早会在"超过 10 字节算不算合法"上分叉。这里只负责把三种结局
/// （值 / 截断 / 溢出）翻成带上下文的错误。
fn read_uleb(
    bytes: &[u8],
    cursor: &mut usize,
    what: &str,
    node_offset: usize,
) -> Result<u64, ParseError> {
    if *cursor >= bytes.len() {
        return Err(ParseError::Inconsistent(format!(
            "导出 trie 在 +{node_offset:#x} 处读{what}时数据就结束了（trie 被裁剪）"
        )));
    }
    match super::uleb128_at(bytes, *cursor) {
        super::Uleb::Value(value, used) => {
            *cursor += used;
            Ok(value)
        }
        super::Uleb::Truncated => Err(ParseError::Inconsistent(format!(
            "导出 trie 在 +{node_offset:#x} 处读{what}时 ULEB128 被截断（最后一个字节的续位仍是 1，\
             后面没有字节了）"
        ))),
        super::Uleb::Overflow => Err(ParseError::Inconsistent(format!(
            "导出 trie 在 +{node_offset:#x} 处读{what}时 ULEB128 超过 64 位（合法编码最多 10 字节）：\
             这份 trie 被人为构造过"
        ))),
    }
}
