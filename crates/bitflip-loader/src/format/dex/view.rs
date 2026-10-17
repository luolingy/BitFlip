//! DEX-specific method view: columnar instructions, text rendering, and CFG projection.
//!
//! This deliberately does not reuse machine-code `Disasm`: DEX addresses are method-local
//! 16-bit code-unit offsets and its control-flow model is distinct (ADR-0020).

use std::collections::{BTreeMap, BTreeSet};
use std::fmt::Write as _;

use droidsaw_dex::decode::{parse_code_item, CodeItem, PayloadData, PoolIndex};

/// A method's Dalvik instructions in structure-of-arrays form.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DexInstructions {
    /// Method-relative address in 16-bit code units.
    pub addresses: Vec<u32>,
    /// Dalvik opcode values.
    pub opcodes: Vec<u8>,
    /// Encoded instruction widths, in code units.
    pub widths: Vec<u8>,
    /// Optional destination register per instruction.
    pub destinations: Vec<Option<u16>>,
    /// CSR-style source register table, with `source_offsets.len() == len + 1`.
    pub source_offsets: Vec<usize>,
    /// Flattened source register IDs.
    pub source_registers: Vec<u16>,
    /// Signed or unsigned literal operand as decoded by droidsaw-dex.
    pub literals: Vec<i64>,
    /// Optional method-relative branch/payload target in code units.
    pub targets: Vec<Option<u32>>,
    /// Pool reference as a kind tag and index pair; proto is separate for polymorphic calls.
    pub pool_kinds: Vec<Option<DexPoolKind>>,
    pub pool_indices: Vec<Option<u32>>,
    pub pool_proto_indices: Vec<Option<u32>>,
}

/// Pool-index category carried by a Dalvik instruction.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum DexPoolKind {
    String = 1,
    Type = 2,
    Field = 3,
    Method = 4,
    CallSite = 5,
}

/// 一次符号解析的结果。**没有"写了个占位符"这一档**。
///
/// 这里刻意不给 `bool`：`false` 会把"这一类引用我们还没做"和"索引越界/库解析失败"
/// 混成同一件事，而调用方需要区别对待 —— 前者是已知缺口，后者是异常，必须被计数
/// 并报出来。库自己的 smali 渲染器正是在这里写 `?` / `<invalid>`，CLAUDE.md §7 禁止。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DexSymbolOutcome {
    /// 真实符号文本已写入。
    Written,
    /// 这一类引用我们**还没实现**（当前的 call-site）：已知缺口，不算异常。
    NotSupported,
    /// 索引越界或库拒绝解析：**异常**，调用方应当计数并报出来。
    Unavailable,
}

/// 池索引 → 符号文本。视图自身不带字符串（CLAUDE.md §4），所以解析器由调用方传入。
pub trait DexSymbolResolver {
    /// 写入字符串字面量（含引号与转义）。
    fn write_string(&self, index: u32, output: &mut String) -> DexSymbolOutcome;
    /// 写入类型描述符（`I` / `Ljava/lang/String;`）。
    fn write_type(&self, index: u32, output: &mut String) -> DexSymbolOutcome;
    /// 写入字段引用（`Lcom/Foo;->bar:I`）。
    fn write_field(&self, index: u32, output: &mut String) -> DexSymbolOutcome;
    /// 写入方法引用（`Lcom/Foo;->bar(I)V`）；`proto` 只在库里另给了原型索引时存在。
    fn write_method(&self, index: u32, proto: Option<u32>, output: &mut String)
        -> DexSymbolOutcome;
}

/// 渲染一次之后的账：**写了几条、有几处是已知缺口、有几处是异常**。
///
/// 返回它而不是 `()`，是因为"没解析出来"必须能被看见（CLAUDE.md §7）：
/// 只返回成功/失败的话，调用方可以轻易把一次大面积失败当成"没什么可显示的"。
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct DexRenderReport {
    /// 渲染出的指令条数。
    pub instructions: usize,
    /// 已知未实现的操作数处数（例如 call-site）。
    pub unsupported_operands: usize,
    /// 异常：索引越界或库拒绝解析的操作数处数。
    pub unavailable_operands: usize,
}

impl DexRenderReport {
    /// 是否每一处操作数都写成了真实符号文本。
    #[must_use]
    pub const fn is_fully_resolved(&self) -> bool {
        self.unsupported_operands == 0 && self.unavailable_operands == 0
    }
}

impl DexInstructions {
    /// Number of decoded instructions.
    #[must_use]
    pub fn len(&self) -> usize {
        self.addresses.len()
    }

    /// Whether this method has no decoded instructions.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.addresses.is_empty()
    }

    /// Render one instruction without allocating a per-instruction string.
    ///
    /// Register and pool references are shown as stable indices; callers with a DEX context
    /// may resolve those indices through their string/type/field/method pools.
    pub fn render_instruction(
        &self,
        index: usize,
        output: &mut String,
    ) -> Result<(), DexViewError> {
        self.render_instruction_with_symbols(index, None, output)
            .map(|_| ())
    }

    /// 渲染一条指令，可选地把池索引解析成符号文本。
    ///
    /// 返回这条指令里**没写成符号**的操作数结果（`None` = 本来就没有池引用）。
    /// 解析失败时**不写占位符**：保留可数的 `kind@index` 形式，把失败如实交回调用方。
    pub fn render_instruction_with_symbols(
        &self,
        index: usize,
        symbols: Option<&dyn DexSymbolResolver>,
        output: &mut String,
    ) -> Result<Option<DexSymbolOutcome>, DexViewError> {
        let opcode = *self
            .opcodes
            .get(index)
            .ok_or(DexViewError::InstructionIndex(index))?;
        let mnemonic = droidsaw_dex::opcodes::Opcode::from_u8(opcode)
            .map(|op| op.mnemonic())
            .unwrap_or("<unknown-opcode>");
        let address = *self
            .addresses
            .get(index)
            .ok_or(DexViewError::InstructionIndex(index))?;
        write!(output, "{address:04x}: {mnemonic}").map_err(|_| DexViewError::Formatting)?;
        let mut has_operand = false;
        if let Some(dst) = self.destinations.get(index).copied().flatten() {
            write_operand_separator(output, &mut has_operand);
            write!(output, "v{dst}").map_err(|_| DexViewError::Formatting)?;
        }
        if let (Some(&begin), Some(&end)) = (
            self.source_offsets.get(index),
            self.source_offsets.get(index + 1),
        ) {
            for reg in self
                .source_registers
                .get(begin..end)
                .ok_or(DexViewError::InvalidColumns)?
            {
                write_operand_separator(output, &mut has_operand);
                write!(output, "v{reg}").map_err(|_| DexViewError::Formatting)?;
            }
        }
        if let Some(Some(target)) = self.targets.get(index) {
            write_operand_separator(output, &mut has_operand);
            write!(output, ":{target:04x}").map_err(|_| DexViewError::Formatting)?;
        }
        let mut symbol_outcome = None;
        if let Some(Some(kind)) = self.pool_kinds.get(index) {
            let pool_idx = self
                .pool_indices
                .get(index)
                .copied()
                .flatten()
                .ok_or(DexViewError::InvalidColumns)?;
            let proto = self.pool_proto_indices.get(index).copied().flatten();
            write_operand_separator(output, &mut has_operand);
            // 先按符号解析；`Written` 就不要再写数值形式了 —— 两种形式并列会让人
            // 以为有两个操作数。
            let outcome = match (symbols, kind) {
                (Some(resolver), DexPoolKind::String) => resolver.write_string(pool_idx, output),
                (Some(resolver), DexPoolKind::Type) => resolver.write_type(pool_idx, output),
                (Some(resolver), DexPoolKind::Field) => resolver.write_field(pool_idx, output),
                (Some(resolver), DexPoolKind::Method) => {
                    resolver.write_method(pool_idx, proto, output)
                }
                (Some(_), DexPoolKind::CallSite) => DexSymbolOutcome::NotSupported,
                (None, _) => DexSymbolOutcome::NotSupported,
            };
            if outcome != DexSymbolOutcome::Written {
                // 没解析出来：保留可数的数值形式（这是事实，不是占位符）。
                write!(output, "{}@{pool_idx}", pool_kind_name(*kind))
                    .map_err(|_| DexViewError::Formatting)?;
                if let Some(proto) = proto {
                    write!(output, "/proto@{proto}").map_err(|_| DexViewError::Formatting)?;
                }
            }
            symbol_outcome = Some(match (outcome, symbols.is_some()) {
                // 没有解析器时"数值形式"就是预期行为，不是缺口。
                (_, false) => DexSymbolOutcome::Written,
                (outcome, true) => outcome,
            });
        }
        if let Some(&literal) = self.literals.get(index) {
            if has_literal_operand(mnemonic) {
                write_operand_separator(output, &mut has_operand);
                write!(output, "#{literal}").map_err(|_| DexViewError::Formatting)?;
            }
        }
        Ok(symbol_outcome)
    }
}

/// Payload table, kept separate from instruction rows.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DexPayloads {
    /// Payload start address in code units.
    pub addresses: Vec<u32>,
    /// Payload variant tags: 1=packed switch, 2=sparse switch, 3=array data.
    pub kinds: Vec<u8>,
    /// Packed/sparse switch keys aligned with `targets`.
    pub keys: Vec<i32>,
    /// CSR-style switch-target list offsets, length = addresses.len()+1.
    pub target_offsets: Vec<usize>,
    /// CSR-style switch-key list offsets, length = addresses.len()+1.
    pub key_offsets: Vec<usize>,
    /// CSR-style fill-array-data byte offsets, length = addresses.len()+1.
    pub array_offsets: Vec<usize>,
    /// Method-relative switch target addresses.
    pub targets: Vec<u32>,
    /// Fill-array element widths; zero for switch payloads.
    pub element_widths: Vec<u16>,
    /// Concatenated fill-array bytes; only present for array payloads.
    pub array_data: Vec<u8>,
    /// Try/catch table columns associated with payload/method view.
    pub exception_handlers: Vec<DexHandlerEntry>,
}

/// One typed/catch-all handler entry, kept in columns on the method view.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DexHandlerEntry {
    pub exception_type_index: Option<u32>,
    pub handler_address: u32,
}

/// Projected CFG as flat block and edge columns.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DexCfgView {
    pub block_ids: Vec<u32>,
    pub block_starts: Vec<u32>,
    pub block_instruction_offsets: Vec<usize>,
    pub block_instruction_addresses: Vec<u32>,
    pub edge_offsets: Vec<usize>,
    pub edge_targets: Vec<u32>,
    pub edge_kinds: Vec<DexEdgeKind>,
    /// Switch key for switch-case edges; `None` for other kinds.
    pub edge_switch_keys: Vec<Option<i32>>,
    /// Exception type index for typed-handler edges; `None` otherwise.
    pub edge_exception_type_indices: Vec<Option<u32>>,
    pub predecessor_offsets: Vec<usize>,
    pub predecessors: Vec<u32>,
    pub exception_regions: Vec<DexExceptionRegion>,
    /// 目标地址不是任何指令起点的边：**没有连边**，逐条记在这里。
    ///
    /// 不连边是刻意的（连到"最近的块"就是在编造控制流），但**不能悄悄丢** ——
    /// 否则读的人会以为这份 CFG 覆盖了全部跳转。CLAUDE.md §7。
    pub unresolved_edge_targets: Vec<UnresolvedEdgeTarget>,
    pub entry_block: Option<u32>,
}

/// 一条没连上的边：源块、原始目标地址、边的类别。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct UnresolvedEdgeTarget {
    /// 出边的块号。
    pub from_block: u32,
    /// 原始目标地址（方法内码元偏移）——不是任何指令的起点。
    pub target: u32,
    /// 这条边本来是什么类别。
    pub kind: DexEdgeKind,
}

/// CFG edge category with switch keys or typed-exception indices in a separate scalar.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DexEdgeKind {
    FallThrough,
    Branch,
    SwitchCase,
    SwitchDefault,
    ExceptionHandler,
    ExceptionCatchAll,
}

/// Try-range to handler-block projection.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DexExceptionRegion {
    pub start_addr: u32,
    pub end_addr: u32,
    pub handler_addresses: Vec<u32>,
    /// handler 地址所在的块号；`None` 表示该地址不是任何指令的起点（**不补 0**）。
    pub handler_blocks: Vec<Option<u32>>,
    pub handler_kinds: Vec<DexEdgeKind>,
    pub exception_type_indices: Vec<Option<u32>>,
}

/// Complete DEX-specific method view.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DexMethodView {
    pub instructions: DexInstructions,
    pub payloads: DexPayloads,
    pub cfg: DexCfgView,
    pub registers_size: u16,
    pub ins_size: u16,
    pub outs_size: u16,
}

/// Errors produced while constructing or rendering a method view.
#[derive(Debug, thiserror::Error)]
pub enum DexViewError {
    #[error("DEX code item parse failed at {code_off:#x}: {source}")]
    Parse {
        code_off: u32,
        #[source]
        source: droidsaw_dex::DexError,
    },
    /// `code_off == 0`：规范里这个方法**没有字节码**（抽象 / `native`）。
    ///
    /// 与 [`super::check_code_item_layout`] 的同名判断保持一致：偏移 0 在真实 DEX 里
    /// 是文件头的 `magic`，把它当 `code_item` 解析只会得到一堆假行。
    #[error("code_off = 0：这个方法没有字节码（抽象 / native）")]
    NoCode,
    #[error("instruction index {0} is out of range")]
    InstructionIndex(usize),
    #[error("inconsistent DEX column lengths")]
    InvalidColumns,
    #[error("try_item.handler_idx {handler_index} 越界（handler 数 {handler_count}）")]
    HandlerIndexOutOfRange {
        /// `try_item.handler_idx`。
        handler_index: usize,
        /// `catch_handlers` 的长度。
        handler_count: usize,
    },
    #[error("formatting failed")]
    Formatting,
}

/// Decode and project one `code_item` into DEX-specific SoA and CFG columns.
///
/// `code_off == 0` 是规范里的"没有字节码"哨兵值（抽象 / `native` 方法），
/// 返回 [`DexViewError::NoCode`]，与 [`super::check_code_item_layout`] 一致。
pub fn project_method(bytes: &[u8], code_off: u32) -> Result<DexMethodView, DexViewError> {
    if code_off == 0 {
        return Err(DexViewError::NoCode);
    }
    let code = parse_code_item(bytes, code_off)
        .map_err(|source| DexViewError::Parse { code_off, source })?;
    project_code_item(&code)
}

/// Project an already decoded code item.
pub fn project_code_item(code: &CodeItem) -> Result<DexMethodView, DexViewError> {
    let mut instructions = DexInstructions {
        addresses: Vec::with_capacity(code.instructions.len()),
        opcodes: Vec::with_capacity(code.instructions.len()),
        widths: Vec::with_capacity(code.instructions.len()),
        destinations: Vec::with_capacity(code.instructions.len()),
        source_offsets: Vec::with_capacity(code.instructions.len() + 1),
        source_registers: Vec::new(),
        literals: Vec::with_capacity(code.instructions.len()),
        targets: Vec::with_capacity(code.instructions.len()),
        pool_kinds: Vec::with_capacity(code.instructions.len()),
        pool_indices: Vec::with_capacity(code.instructions.len()),
        pool_proto_indices: Vec::with_capacity(code.instructions.len()),
    };
    instructions.source_offsets.push(0);
    for insn in &code.instructions {
        instructions.addresses.push(insn.addr);
        instructions.opcodes.push(insn.op.to_u8());
        instructions.widths.push(insn.size);
        instructions.destinations.push(insn.dst);
        instructions
            .source_registers
            .extend_from_slice(insn.src.as_slice());
        instructions
            .source_offsets
            .push(instructions.source_registers.len());
        instructions.literals.push(insn.literal);
        instructions.targets.push(insn.target);
        let (kind, index, proto) = pool_columns(insn.pool_idx);
        instructions.pool_kinds.push(kind);
        instructions.pool_indices.push(index);
        instructions.pool_proto_indices.push(proto);
    }

    let mut payloads = project_payloads(&code.payloads);
    payloads.exception_handlers = code
        .catch_handlers
        .iter()
        .flat_map(|handler| {
            handler
                .catches
                .iter()
                .map(|catch| DexHandlerEntry {
                    exception_type_index: Some(catch.exception_type.0),
                    handler_address: catch.handler_addr,
                })
                .chain(handler.catch_all_addr.map(|addr| DexHandlerEntry {
                    exception_type_index: None,
                    handler_address: addr,
                }))
        })
        .collect();
    let cfg = build_cfg(code)?;
    Ok(DexMethodView {
        instructions,
        payloads,
        cfg,
        registers_size: code.registers_size,
        ins_size: code.ins_size,
        outs_size: code.outs_size,
    })
}

/// 取出 CFG 并列数组里第 `index` 段的范围。
///
/// 这三列（块内指令、出边、前驱）与 [`DexInstructions::source_offsets`] 用**同一个**
/// 约定：开头先压一个 `0`，其后每个块压一个**结束位置** —— 所以第 `index` 段是
/// `offsets[index]..offsets[index + 1]`，列长比块数多 1。
pub fn column_range(
    offsets: &[usize],
    index: usize,
    total: usize,
) -> Option<std::ops::Range<usize>> {
    let start = *offsets.get(index)?;
    let end = *offsets.get(index + 1)?;
    (start <= end && end <= total).then_some(start..end)
}

/// 边类别 → 给人看的标签。
pub fn edge_label(
    kind: DexEdgeKind,
    switch_key: Option<i32>,
    exception_type: Option<u32>,
) -> String {
    match kind {
        DexEdgeKind::FallThrough => "落空".to_owned(),
        DexEdgeKind::Branch => "分支".to_owned(),
        DexEdgeKind::SwitchCase => match switch_key {
            Some(key) => format!("switch 分支（键={key}）"),
            // 不是占位符：这是在说"这一列本应有值却没有"，而不是替一个未知值编一个。
            None => "switch 分支（键缺失）".to_owned(),
        },
        DexEdgeKind::SwitchDefault => "switch 默认".to_owned(),
        DexEdgeKind::ExceptionHandler => match exception_type {
            Some(index) => format!("异常处理（类型池下标={index}）"),
            None => "异常处理（类型池下标缺失）".to_owned(),
        },
        DexEdgeKind::ExceptionCatchAll => "异常 catch-all".to_owned(),
    }
}

/// 把 CFG 渲染成文本：块（起址、指令数、前驱）、出边、以及**没连上的目标**。
///
/// 文本而不是图 —— M2b 第一版先把事实摆出来（用户 2026-10-16 的决定）。
/// 目标地址不是指令起点的边不连边，但一定会出现在末尾那段"未连上的目标"里，
/// 并且开头的汇总行也会把它计数出来（含 0）—— 降级必须看得见（CLAUDE.md §7）。
pub fn render_cfg_text(view: &DexMethodView, output: &mut String) {
    let cfg = &view.cfg;
    let blocks = cfg.block_ids.len();
    let edges = cfg.edge_kinds.len();
    let unresolved = cfg.unresolved_edge_targets.len();
    let entry = cfg
        .entry_block
        .map_or_else(|| "无".to_owned(), |block| block.to_string());
    let _ = writeln!(
        output,
        "CFG：{blocks} 个块、{edges} 条边、{unresolved} 个未连上的目标（入口块 {entry}）"
    );

    for index in 0..blocks {
        let id = cfg.block_ids.get(index).copied().unwrap_or(u32::MAX);
        let start = cfg.block_starts.get(index).copied().unwrap_or(0);
        let instruction_count = column_range(
            &cfg.block_instruction_offsets,
            index,
            cfg.block_instruction_addresses.len(),
        )
        .map_or(0, |range| range.len());
        let predecessors = column_range(&cfg.predecessor_offsets, index, cfg.predecessors.len())
            .map(|range| {
                cfg.predecessors[range]
                    .iter()
                    .map(|block| format!("块{block}"))
                    .collect::<Vec<_>>()
            })
            .unwrap_or_default();
        let predecessors = if predecessors.is_empty() {
            "无".to_owned()
        } else {
            predecessors.join("、")
        };
        let _ = writeln!(
            output,
            "块 {id} @{start:04x}（{instruction_count} 条指令）  前驱：{predecessors}"
        );

        let Some(range) = column_range(&cfg.edge_offsets, index, cfg.edge_kinds.len()) else {
            continue;
        };
        if range.is_empty() {
            let _ = writeln!(output, "    没有出边");
            continue;
        }
        for edge in range {
            let label = edge_label(
                cfg.edge_kinds
                    .get(edge)
                    .copied()
                    .unwrap_or(DexEdgeKind::FallThrough),
                cfg.edge_switch_keys.get(edge).copied().flatten(),
                cfg.edge_exception_type_indices.get(edge).copied().flatten(),
            );
            let target = cfg.edge_targets.get(edge).copied().unwrap_or(u32::MAX);
            let _ = writeln!(output, "    → 块{target} {label}");
        }
    }

    if unresolved > 0 {
        let _ = writeln!(output, "未连上的目标（{unresolved} 个，都没有连边）：");
        for entry in &cfg.unresolved_edge_targets {
            let label = edge_label(entry.kind, None, None);
            let _ = writeln!(
                output,
                "    块{} → {:#06x}（{label}；目标不是任何指令的起点）",
                entry.from_block, entry.target
            );
        }
    }
}

/// Render all instruction rows into a reusable output buffer.
pub fn render_instructions(
    instructions: &DexInstructions,
    output: &mut String,
) -> Result<(), DexViewError> {
    for index in 0..instructions.len() {
        instructions.render_instruction(index, output)?;
        output.push('\n');
    }
    Ok(())
}

/// 渲染全部指令，并把池索引解析成符号文本；返回一份"账"。
///
/// 解析不出来的操作数**不会**变成占位符：它保留可数的 `kind@index` 形式，
/// 同时被计入 [`DexRenderReport`]，由调用方决定怎么呈现（§7：降级要写在界面上）。
pub fn render_instructions_with_symbols(
    instructions: &DexInstructions,
    symbols: &dyn DexSymbolResolver,
    output: &mut String,
) -> Result<DexRenderReport, DexViewError> {
    let mut report = DexRenderReport::default();
    for index in 0..instructions.len() {
        report.instructions += 1;
        match instructions.render_instruction_with_symbols(index, Some(symbols), output)? {
            Some(DexSymbolOutcome::NotSupported) => report.unsupported_operands += 1,
            Some(DexSymbolOutcome::Unavailable) => report.unavailable_operands += 1,
            Some(DexSymbolOutcome::Written) | None => {}
        }
        output.push('\n');
    }
    Ok(report)
}

/// 基于已解析 `droidsaw-dex` 池的符号解析器。
///
/// 字段是库类型但**不出现**在任何公开签名里：调用方通过
/// `DexStructure::symbols()` 拿到它，于是换库时改动面仍在适配层内
/// （`tests/dex_library_boundary.rs` 那条"库只许被适配层引用"的守卫）。
pub struct DexSymbols<'a> {
    file: &'a droidsaw_dex::DexFile,
}

impl<'a> DexSymbols<'a> {
    pub(crate) const fn new(file: &'a droidsaw_dex::DexFile) -> Self {
        Self { file }
    }

    fn type_descriptor(&self, index: u32) -> Option<&str> {
        self.file
            .get_type_descriptor(droidsaw_dex::ids::TypeIdx(index))
            .ok()
    }

    /// 取原型的方法参数与返回值，用来拼 `(Args)Ret`。
    ///
    /// `parameters_off == 0` 是规范里的"无参数"（`type_lists` 里没有这一项），
    /// 不是"取不到" —— 两者必须分开，否则无参方法会被当成解析失败。
    fn write_proto(&self, proto_index: u32, output: &mut String) -> bool {
        let Ok(proto_index) = usize::try_from(proto_index) else {
            return false;
        };
        let Some(proto) = self.file.protos.get(proto_index) else {
            return false;
        };
        output.push('(');
        if proto.parameters_off != 0 {
            let Some(parameters) = self.file.type_lists.get(&proto.parameters_off) else {
                return false;
            };
            for parameter in parameters {
                match self.type_descriptor(parameter.0) {
                    Some(descriptor) => output.push_str(descriptor),
                    None => return false,
                }
            }
        }
        output.push(')');
        match self.type_descriptor(proto.return_type_idx.0) {
            Some(descriptor) => {
                output.push_str(descriptor);
                true
            }
            None => false,
        }
    }
}

impl DexSymbolResolver for DexSymbols<'_> {
    fn write_string(&self, index: u32, output: &mut String) -> DexSymbolOutcome {
        match self.file.get_string(droidsaw_dex::ids::StringIdx(index)) {
            Ok(text) => {
                write_str_operand(output, text);
                DexSymbolOutcome::Written
            }
            Err(_) => DexSymbolOutcome::Unavailable,
        }
    }

    fn write_type(&self, index: u32, output: &mut String) -> DexSymbolOutcome {
        match self.type_descriptor(index) {
            Some(descriptor) => {
                output.push_str(descriptor);
                DexSymbolOutcome::Written
            }
            None => DexSymbolOutcome::Unavailable,
        }
    }

    fn write_field(&self, index: u32, output: &mut String) -> DexSymbolOutcome {
        let Some(field) = usize::try_from(index)
            .ok()
            .and_then(|index| self.file.fields.get(index))
        else {
            return DexSymbolOutcome::Unavailable;
        };
        let Ok(name) = self.file.get_string(field.name_idx) else {
            return DexSymbolOutcome::Unavailable;
        };
        let (Some(class), Some(kind)) = (
            self.type_descriptor(field.class_idx.0),
            self.type_descriptor(field.type_idx.0),
        ) else {
            return DexSymbolOutcome::Unavailable;
        };
        if write!(output, "{class}->{name}:{kind}").is_err() {
            return DexSymbolOutcome::Unavailable;
        }
        DexSymbolOutcome::Written
    }

    fn write_method(
        &self,
        index: u32,
        proto: Option<u32>,
        output: &mut String,
    ) -> DexSymbolOutcome {
        let Some(method) = usize::try_from(index)
            .ok()
            .and_then(|index| self.file.methods.get(index))
        else {
            return DexSymbolOutcome::Unavailable;
        };
        let Ok(name) = self.file.get_string(method.name_idx) else {
            return DexSymbolOutcome::Unavailable;
        };
        let Some(class) = self.type_descriptor(method.class_idx.0) else {
            return DexSymbolOutcome::Unavailable;
        };
        // 指令自带的原型索引优先；否则用 method_id 自己的 proto_idx（事实，不是猜的）。
        let proto_index: u32 = match proto {
            Some(proto) => proto,
            None => method.proto_idx.0,
        };
        let mut prototype = String::new();
        if !self.write_proto(proto_index, &mut prototype) {
            return DexSymbolOutcome::Unavailable;
        }
        if write!(output, "{class}->{name}{prototype}").is_err() {
            return DexSymbolOutcome::Unavailable;
        }
        DexSymbolOutcome::Written
    }
}

/// 写字符串字面量。转义按 smali/Dalvik 的常见写法，但不借用库的渲染器
/// （见 ADR-0020 的 2026-10-15 更正）。
fn write_str_operand(output: &mut String, text: &str) {
    output.push('"');
    for ch in text.chars() {
        match ch {
            '"' => output.push_str("\\\""),
            '\\' => output.push_str("\\\\"),
            '\n' => output.push_str("\\n"),
            '\r' => output.push_str("\\r"),
            '\t' => output.push_str("\\t"),
            control if control.is_control() => {
                let _ = write!(output, "\\u{:04x}", control as u32);
            }
            other => output.push(other),
        }
    }
    output.push('"');
}

impl DexInstructions {
    /// 逐列核对长度与 CSR 边界。**空 = 列对齐**。
    ///
    /// SoA 的代价是"列之间靠约定对齐"，而约定不会自己成立：漏 `push` 一次就会让
    /// 所有后续行错位，而且**照样渲染得出来**（只是内容是错的）。所以这里显式对账，
    /// 调用方（测试 / 真实样本审计）负责断言它是空的。
    #[must_use]
    pub fn consistency_problems(&self) -> Vec<String> {
        let mut problems = Vec::new();
        let n = self.addresses.len();
        for (name, len) in [
            ("opcodes", self.opcodes.len()),
            ("widths", self.widths.len()),
            ("destinations", self.destinations.len()),
            ("literals", self.literals.len()),
            ("targets", self.targets.len()),
            ("pool_kinds", self.pool_kinds.len()),
            ("pool_indices", self.pool_indices.len()),
            ("pool_proto_indices", self.pool_proto_indices.len()),
        ] {
            if len != n {
                problems.push(format!("指令列 {name} 长度 {len}，地址列长度 {n}"));
            }
        }
        if self.source_offsets.len() != n + 1 {
            problems.push(format!(
                "source_offsets 长度 {}，应为 {n}+1",
                self.source_offsets.len()
            ));
        } else if self.source_offsets.first() != Some(&0) {
            problems.push("source_offsets 第一项不是 0".to_string());
        } else if self.source_offsets.last().copied() != Some(self.source_registers.len()) {
            problems.push(format!(
                "source_offsets 末项 {:?} 不等于 source_registers 长度 {}",
                self.source_offsets.last(),
                self.source_registers.len()
            ));
        } else {
            for pair in self.source_offsets.windows(2) {
                if let [begin, end] = pair {
                    if begin > end || *end > self.source_registers.len() {
                        problems.push(format!(
                            "source_offsets 出现逆序或越界区间 {begin}..{end}（寄存器数 {}）",
                            self.source_registers.len()
                        ));
                        break;
                    }
                }
            }
        }
        problems
    }
}

impl DexPayloads {
    /// 逐列核对长度与 CSR 边界。**空 = 列对齐**。
    #[must_use]
    pub fn consistency_problems(&self) -> Vec<String> {
        let mut problems = Vec::new();
        let n = self.addresses.len();
        for (name, len) in [
            ("kinds", self.kinds.len()),
            ("element_widths", self.element_widths.len()),
        ] {
            if len != n {
                problems.push(format!("载荷列 {name} 长度 {len}，地址列长度 {n}"));
            }
        }
        for (name, offsets, total, what) in [
            (
                "target_offsets",
                &self.target_offsets,
                self.targets.len(),
                "targets",
            ),
            ("key_offsets", &self.key_offsets, self.keys.len(), "keys"),
            (
                "array_offsets",
                &self.array_offsets,
                self.array_data.len(),
                "array_data",
            ),
        ] {
            if offsets.len() != n + 1 {
                problems.push(format!("{name} 长度 {}，应为 {n}+1", offsets.len()));
            } else if offsets.first() != Some(&0) {
                problems.push(format!("{name} 第一项不是 0"));
            } else if offsets.last().copied() != Some(total) {
                problems.push(format!(
                    "{name} 末项 {:?} 不等于 {what} 长度 {total}",
                    offsets.last()
                ));
            } else {
                for pair in offsets.windows(2) {
                    if let [begin, end] = pair {
                        if begin > end || *end > total {
                            problems.push(format!("{name} 出现逆序或越界区间 {begin}..{end}"));
                            break;
                        }
                    }
                }
            }
        }
        // 每个 payload 区间对应一行：switch（1/2）应当有 key，fill-array（3）不该有。
        for index in 0..self.addresses.len() {
            let (Some(&target_begin), Some(&target_end)) = (
                self.target_offsets.get(index),
                self.target_offsets.get(index + 1),
            ) else {
                break;
            };
            let (Some(&key_begin), Some(&key_end)) =
                (self.key_offsets.get(index), self.key_offsets.get(index + 1))
            else {
                break;
            };
            let target_count = target_end.saturating_sub(target_begin);
            let key_count = key_end.saturating_sub(key_begin);
            match self.kinds.get(index) {
                Some(1 | 2) if key_count != target_count => problems.push(format!(
                    "payload @{:?} 是 switch，但有 {key_count} 个 key、{target_count} 个 target",
                    self.addresses.get(index)
                )),
                Some(3) if key_count != 0 => problems.push(format!(
                    "payload @{:?} 是 fill-array，却带了 {key_count} 个 key",
                    self.addresses.get(index)
                )),
                Some(1..=3) => {}
                other => problems.push(format!(
                    "payload @{:?} 的类型标记 {other:?} 不是 1/2/3",
                    self.addresses.get(index)
                )),
            }
        }
        problems
    }
}

impl DexCfgView {
    /// 逐列核对长度与 CSR 边界。**空 = 列对齐**。
    #[must_use]
    pub fn consistency_problems(&self) -> Vec<String> {
        let mut problems = Vec::new();
        let n = self.block_ids.len();
        if self.block_starts.len() != n {
            problems.push(format!(
                "block_starts 长度 {}，应等于 block_ids 长度 {n}",
                self.block_starts.len()
            ));
        }
        for (name, offsets, total, what) in [
            (
                "block_instruction_offsets",
                &self.block_instruction_offsets,
                self.block_instruction_addresses.len(),
                "block_instruction_addresses",
            ),
            (
                "edge_offsets",
                &self.edge_offsets,
                self.edge_targets.len(),
                "edge_targets",
            ),
            (
                "predecessor_offsets",
                &self.predecessor_offsets,
                self.predecessors.len(),
                "predecessors",
            ),
        ] {
            if offsets.len() != n + 1 {
                problems.push(format!("{name} 长度 {}，应为 {n}+1", offsets.len()));
            } else if offsets.first() != Some(&0) {
                problems.push(format!("{name} 第一项不是 0"));
            } else if offsets.last().copied() != Some(total) {
                problems.push(format!(
                    "{name} 末项 {:?} 不等于 {what} 长度 {total}",
                    offsets.last()
                ));
            } else {
                for pair in offsets.windows(2) {
                    if let [begin, end] = pair {
                        if begin > end || *end > total {
                            problems.push(format!("{name} 出现逆序或越界区间 {begin}..{end}"));
                            break;
                        }
                    }
                }
            }
        }
        for (name, len) in [
            ("edge_kinds", self.edge_kinds.len()),
            ("edge_switch_keys", self.edge_switch_keys.len()),
            (
                "edge_exception_type_indices",
                self.edge_exception_type_indices.len(),
            ),
        ] {
            if len != self.edge_targets.len() {
                problems.push(format!(
                    "边列 {name} 长度 {len}，目标列长度 {}",
                    self.edge_targets.len()
                ));
            }
        }
        // 边的两个附加列必须只在自己的类别上带值。
        for (index, (kind, key, ty)) in self
            .edge_kinds
            .iter()
            .zip(self.edge_switch_keys.iter())
            .zip(self.edge_exception_type_indices.iter())
            .enumerate()
            .map(|(i, ((k, key), ty))| (i, (*k, *key, *ty)))
        {
            match kind {
                DexEdgeKind::SwitchCase => {
                    if key.is_none() {
                        problems.push(format!("第 {index} 条 switch 边没有 key"));
                    }
                }
                DexEdgeKind::ExceptionHandler => {
                    if ty.is_none() {
                        problems.push(format!("第 {index} 条 typed handler 边没有异常类型"));
                    }
                }
                _ => {
                    if key.is_some() || ty.is_some() {
                        problems.push(format!("第 {index} 条非附加边带有多余的 key/类型"));
                    }
                }
            }
        }
        for (index, region) in self.exception_regions.iter().enumerate() {
            let len = region.handler_blocks.len();
            for (name, other) in [
                ("handler_addresses", region.handler_addresses.len()),
                ("handler_kinds", region.handler_kinds.len()),
                (
                    "exception_type_indices",
                    region.exception_type_indices.len(),
                ),
            ] {
                if other != len {
                    problems.push(format!(
                        "异常区间 {index} 的 {name} 长度 {other}，handler_blocks 长度 {len}"
                    ));
                }
            }
        }
        // block_instruction_addresses 里的地址必须落在它所属块的范围内。
        for (index, block_id) in self.block_ids.iter().enumerate() {
            let (Some(begin), Some(end)) = (
                self.block_instruction_offsets.get(index).copied(),
                self.block_instruction_offsets.get(index + 1).copied(),
            ) else {
                break;
            };
            let Some(block_start) = self.block_starts.get(index).copied() else {
                break;
            };
            for address in self
                .block_instruction_addresses
                .get(begin..end)
                .unwrap_or_default()
            {
                if *address < block_start {
                    problems.push(format!(
                        "块 {block_id}（起点 {block_start}）里的指令地址 {address} 早于块起点"
                    ));
                    break;
                }
            }
        }
        problems
    }
}

impl DexMethodView {
    /// 汇总三张表的对账结果。**空 = 视图内部一致**。
    #[must_use]
    pub fn consistency_problems(&self) -> Vec<String> {
        let mut problems = self.instructions.consistency_problems();
        problems.extend(self.payloads.consistency_problems());
        problems.extend(self.cfg.consistency_problems());
        problems
    }

    /// 跨表对账：指令列与 CFG 是否**互相印证**。**空 = 两张表讲同一件事**。
    ///
    /// `consistency_problems` 只能查每张表自己的列对齐；它查不出"CFG 少了半个方法"
    /// 这种错 —— 那种错在列长度上完全合法。这里的规则跨表：
    ///
    /// 1. 块里的指令地址**恰好**等于指令列，顺序相同、不重不漏；
    /// 2. 每个块内部地址连续（`addr[i+1] == addr[i] + width[i]`）；
    /// 3. 每个块的首地址等于它自己的 `block_starts`；
    /// 4. 边目标、前驱、异常 handler 块号都落在块数范围内。
    ///
    /// 第 1 条是关键：指令列来自库的解码，而指令列本身又被
    /// `layout::check_code_item_layout` 用**另一条独立实现**（我们从原始字节按规范走）
    /// 对拍过。于是这条检查把"我们的 CFG"和"原始字节"间接连了起来 —— 中间任何一环
    /// 漏掉一条指令，这里就会响。
    #[must_use]
    pub fn cross_check_problems(&self) -> Vec<String> {
        let mut problems = Vec::new();
        let instructions = &self.instructions;
        let cfg = &self.cfg;

        if cfg.block_instruction_addresses != instructions.addresses {
            problems.push(format!(
                "块里的指令地址（{} 条）与指令列（{} 条）不一致",
                cfg.block_instruction_addresses.len(),
                instructions.addresses.len()
            ));
        }

        // 地址 → 宽度；用于"块内是否连续"。
        let width_of: BTreeMap<u32, u8> = instructions
            .addresses
            .iter()
            .copied()
            .zip(instructions.widths.iter().copied())
            .collect();

        for (index, block_id) in cfg.block_ids.iter().enumerate() {
            let Some(begin) = cfg.block_instruction_offsets.get(index).copied() else {
                break;
            };
            let Some(end) = cfg.block_instruction_offsets.get(index + 1).copied() else {
                break;
            };
            let Some(addresses) = cfg.block_instruction_addresses.get(begin..end) else {
                break;
            };
            let Some(&start) = cfg.block_starts.get(index) else {
                break;
            };
            if addresses.first() != Some(&start) {
                problems.push(format!("块 {block_id} 的首指令不是它的起点 {start}"));
            }
            for pair in addresses.windows(2) {
                let [previous, next] = pair else { continue };
                match width_of
                    .get(previous)
                    .copied()
                    .and_then(|width| previous.checked_add(u32::from(width)))
                {
                    Some(expected) if expected == *next => {}
                    Some(expected) => problems.push(format!(
                        "块 {block_id} 内 {previous} → {next} 不连续（按宽度应为 {expected}）"
                    )),
                    None => problems.push(format!("块 {block_id} 内地址 {previous} 没有对应宽度")),
                }
            }
        }

        let block_count = cfg.block_ids.len();
        for (index, target) in cfg.edge_targets.iter().enumerate() {
            if usize::try_from(*target).map_or(true, |target| target >= block_count) {
                problems.push(format!("第 {index} 条边的目标块 {target} 越界"));
            }
        }
        for predecessor in &cfg.predecessors {
            if usize::try_from(*predecessor).map_or(true, |from| from >= block_count) {
                problems.push(format!("前驱列里有越界的块号 {predecessor}"));
            }
        }
        for (index, region) in cfg.exception_regions.iter().enumerate() {
            for block in region.handler_blocks.iter().flatten() {
                if usize::try_from(*block).map_or(true, |block| block >= block_count) {
                    problems.push(format!("异常区间 {index} 的 handler 块号 {block} 越界"));
                }
            }
        }
        // 前驱列必须是边列的反向：每条边都要出现在目标块的前驱里。
        for (edge_index, target) in cfg.edge_targets.iter().enumerate() {
            let Ok(target) = usize::try_from(*target) else {
                continue;
            };
            if target >= block_count {
                continue;
            }
            let from = cfg
                .edge_offsets
                .partition_point(|&end| end <= edge_index)
                .saturating_sub(1);
            let Ok(from) = u32::try_from(from) else {
                continue;
            };
            let (Some(&begin), Some(&end)) = (
                cfg.predecessor_offsets.get(target),
                cfg.predecessor_offsets.get(target + 1),
            ) else {
                break;
            };
            let Some(range) = cfg.predecessors.get(begin..end) else {
                break;
            };
            if !range.contains(&from) {
                problems.push(format!(
                    "第 {edge_index} 条边（块 {from} → 块 {target}）没有出现在前驱列"
                ));
            }
        }
        problems
    }
}

fn write_operand_separator(output: &mut String, has_operand: &mut bool) {
    output.push_str(if *has_operand { ", " } else { " " });
    *has_operand = true;
}

fn has_literal_operand(mnemonic: &str) -> bool {
    mnemonic.starts_with("const")
        || mnemonic.starts_with("add-int/lit")
        || mnemonic.starts_with("rsub-int")
        || mnemonic.starts_with("mul-int/lit")
        || mnemonic.starts_with("div-int/lit")
        || mnemonic.starts_with("rem-int/lit")
        || mnemonic.starts_with("and-int/lit")
        || mnemonic.starts_with("or-int/lit")
        || mnemonic.starts_with("xor-int/lit")
        || mnemonic.starts_with("shl-int/lit")
        || mnemonic.starts_with("shr-int/lit")
        || mnemonic.starts_with("ushr-int/lit")
}

fn pool_kind_name(kind: DexPoolKind) -> &'static str {
    match kind {
        DexPoolKind::String => "string",
        DexPoolKind::Type => "type",
        DexPoolKind::Field => "field",
        DexPoolKind::Method => "method",
        DexPoolKind::CallSite => "call-site",
    }
}

fn pool_columns(pool: Option<PoolIndex>) -> (Option<DexPoolKind>, Option<u32>, Option<u32>) {
    match pool {
        Some(PoolIndex::String(v)) => (Some(DexPoolKind::String), Some(v.0), None),
        Some(PoolIndex::Type(v)) => (Some(DexPoolKind::Type), Some(v.0), None),
        Some(PoolIndex::Field(v)) => (Some(DexPoolKind::Field), Some(v.0), None),
        Some(PoolIndex::Method(v)) => (Some(DexPoolKind::Method), Some(v.0), None),
        Some(PoolIndex::MethodAndProto(m, p)) => (Some(DexPoolKind::Method), Some(m.0), Some(p.0)),
        Some(PoolIndex::CallSite(v)) => (Some(DexPoolKind::CallSite), Some(v.0), None),
        None => (None, None, None),
    }
}

fn project_payloads(payloads: &BTreeMap<u32, PayloadData>) -> DexPayloads {
    let mut out = DexPayloads {
        addresses: Vec::with_capacity(payloads.len()),
        kinds: Vec::with_capacity(payloads.len()),
        target_offsets: Vec::with_capacity(payloads.len() + 1),
        targets: Vec::new(),
        keys: Vec::new(),
        element_widths: Vec::with_capacity(payloads.len()),
        key_offsets: Vec::with_capacity(payloads.len() + 1),
        array_offsets: Vec::with_capacity(payloads.len() + 1),
        array_data: Vec::new(),
        exception_handlers: Vec::new(),
    };
    out.target_offsets.push(0);
    out.key_offsets.push(0);
    out.array_offsets.push(0);
    for (&address, payload) in payloads {
        out.addresses.push(address);
        match payload {
            PayloadData::PackedSwitch { first_key, targets } => {
                out.kinds.push(1);
                out.keys.extend(
                    (0..targets.len()).filter_map(|n| {
                        i32::try_from(n).ok().and_then(|n| first_key.checked_add(n))
                    }),
                );
                out.targets.extend_from_slice(targets);
                out.element_widths.push(0);
            }
            PayloadData::SparseSwitch { keys, targets } => {
                out.kinds.push(2);
                out.keys.extend_from_slice(keys);
                out.targets.extend_from_slice(targets);
                out.element_widths.push(0);
            }
            PayloadData::FillArrayData {
                element_width,
                data,
            } => {
                out.kinds.push(3);
                out.element_widths.push(*element_width);
                out.array_data.extend_from_slice(data);
            }
        }
        out.target_offsets.push(out.targets.len());
        out.key_offsets.push(out.keys.len());
        out.array_offsets.push(out.array_data.len());
    }
    out
}

/// 我们自己构建 CFG，**不用库的 `cfg` 模块**。
///
/// `dex_library_boundary` 那条守卫把库的 `cfg` 模块列为禁用：控制流是**二级结论**
/// （"这段代码会跳到哪"是我们推出来的，不是文件里写着的字节），CLAUDE.md §7 要求它必须由
/// 我们自己构建、并且每一步都说得清依据。这里只用库的**事实**：`Instruction.addr/size/op/
/// target`（解码结果）与 `CodeItem.tries/catch_handlers/payloads`（文件里写着的表）。
///
/// 构建规则（每一条都对应规范里的一个事实）：
///
/// 1. **块首**：第一条指令、任何分支的目标、switch 的每个 case 目标、分支/switch/返回/抛出
///    之后的下一条、每个 `try` 区间的起止、以及每个 catch handler 的地址。
/// 2. **只认指令起点**：目标地址必须真的是某条指令的起点（`index_of` 里有），否则**不连边**，
///    并记进 [`DexCfgView::unresolved_edge_targets`]。31t 的 `target` 指向 payload（不是指令
///    起点），所以它天然不会被当成跳转目标 —— 这正是需要显式写下来的理由。
/// 3. **边**：条件分支 = 分支 + 落空；`goto*` = 只分支；`return*`/`throw` = 无边；
///    `packed-switch`/`sparse-switch` = 默认落空 + payload 里每个 case；其余 = 落空。
/// 4. **异常边**：`try` 区间与块的范围相交时，连到该 `try` 的 typed catch / catch-all 块。
fn build_cfg(code: &CodeItem) -> Result<DexCfgView, DexViewError> {
    let empty = |unresolved: Vec<UnresolvedEdgeTarget>| DexCfgView {
        block_ids: Vec::new(),
        block_starts: Vec::new(),
        block_instruction_offsets: vec![0],
        block_instruction_addresses: Vec::new(),
        edge_offsets: vec![0],
        edge_targets: Vec::new(),
        edge_kinds: Vec::new(),
        edge_switch_keys: Vec::new(),
        edge_exception_type_indices: Vec::new(),
        predecessor_offsets: vec![0],
        predecessors: Vec::new(),
        exception_regions: Vec::new(),
        unresolved_edge_targets: unresolved,
        entry_block: None,
    };

    if code.instructions.is_empty() {
        return Ok(empty(Vec::new()));
    }

    let index_of: BTreeMap<u32, usize> = code
        .instructions
        .iter()
        .enumerate()
        .map(|(i, insn)| (insn.addr, i))
        .collect();

    // ── 1. 块首 ───────────────────────────────────────────────────────────
    let mut leaders: BTreeSet<u32> = BTreeSet::new();
    leaders.insert(code.instructions[0].addr);

    let note_leader = |addr: u32, leaders: &mut BTreeSet<u32>| {
        if index_of.contains_key(&addr) {
            leaders.insert(addr);
        }
    };

    // 上一条指令的结束地址，用来发现指令列里的断口（见循环里的说明）。
    let mut previous_end: Option<u32> = None;

    for insn in &code.instructions {
        let next = insn.addr.checked_add(u32::from(insn.size));
        let mnemonic = insn.op.mnemonic();
        // **断点后的一条必然另起一块。** 指令列里并不是处处连续：payload（switch /
        // fill-array-data）夹在指令之间，它们在 `instructions` 里没有对应项。若不在
        // 断口处另起一块，"载荷之后那一段"就没有任何块覆盖 —— 真跑起来会静默丢掉
        // 整段指令（`cross_check_problems` 就是为此加的，真实 APK 上抓到过一例）。
        if let Some(previous_end) = previous_end {
            if previous_end != insn.addr {
                leaders.insert(insn.addr);
            }
        }
        previous_end = next;
        match mnemonic {
            "packed-switch" | "sparse-switch" => {
                if let Some(target) = insn.target {
                    match code.payloads.get(&target) {
                        Some(PayloadData::PackedSwitch { targets, .. })
                        | Some(PayloadData::SparseSwitch { targets, .. }) => {
                            for case in targets {
                                note_leader(*case, &mut leaders);
                            }
                        }
                        // 31t 指向的不是匹配的 payload：如实记进未解析目标，
                        // 不猜它的 case 目标（那会是编造出来的控制流）。
                        _ => {}
                    }
                }
            }
            _ => {
                if let Some(target) = insn.target {
                    note_leader(target, &mut leaders);
                }
            }
        }
        // 分支 / switch / 终结指令之后的一条必须另起一块（它只能从别处到达）。
        let ends_block = is_branch_or_switch(mnemonic) || is_terminal(mnemonic);
        if ends_block {
            if let Some(next) = next {
                note_leader(next, &mut leaders);
            }
        }
    }

    // try 区间的起止与每个 handler 地址都是块首。
    for try_item in &code.tries {
        note_leader(try_item.start_addr, &mut leaders);
        note_leader(
            try_item
                .start_addr
                .saturating_add(u32::from(try_item.insn_count)),
            &mut leaders,
        );
    }
    for handler in &code.catch_handlers {
        for catch in &handler.catches {
            note_leader(catch.handler_addr, &mut leaders);
        }
        if let Some(addr) = handler.catch_all_addr {
            note_leader(addr, &mut leaders);
        }
    }

    // ── 2. 切块 ───────────────────────────────────────────────────────────
    let leaders: Vec<u32> = leaders.into_iter().collect();
    let mut blocks: Vec<BlockDraft> = Vec::with_capacity(leaders.len());
    let mut addr_to_block: BTreeMap<u32, u32> = BTreeMap::new();
    for &start in &leaders {
        let Some(&start_index) = index_of.get(&start) else {
            continue;
        };
        let mut addresses = Vec::new();
        let mut cursor = start_index;
        while let Some(insn) = code.instructions.get(cursor) {
            addresses.push(insn.addr);
            let Some(next) = insn.addr.checked_add(u32::from(insn.size)) else {
                break;
            };
            // 游标**必须真前进**。宽度为 0 的"指令"不是规范里的东西（每条指令至少占
            // 1 个码元），但 `project_code_item` 收的是调用方给的 `CodeItem`：那种输入下
            // `index_of[next]` 会指回游标自己，地址表无限增长 —— 公开 API 挂死/OOM 是
            // 不可接受的。到这儿收块，覆盖不到的部分交给跨表对账去报，不静默。
            if next <= insn.addr {
                break;
            }
            if leaders.binary_search(&next).is_ok() {
                break;
            }
            match index_of.get(&next) {
                // 地址表是调用方给的，顺序不保证递增；只允许往前走。
                Some(&next_index) if next_index > cursor => cursor = next_index,
                _ => break,
            }
        }
        let block_id = u32::try_from(blocks.len()).unwrap_or(u32::MAX);
        for address in &addresses {
            addr_to_block.insert(*address, block_id);
        }
        blocks.push(BlockDraft {
            start,
            instructions: addresses,
            edges: Vec::new(),
        });
    }

    // 块的结束地址（最后一条指令之后），用于判断 try 区间是否与块相交。
    let block_ends: Vec<u32> = blocks
        .iter()
        .map(|block| {
            block
                .instructions
                .last()
                .and_then(|address| index_of.get(address))
                .and_then(|&index| code.instructions.get(index))
                .and_then(|insn| insn.addr.checked_add(u32::from(insn.size)))
                .unwrap_or(block.start)
        })
        .collect();

    // ── 3. 边 ─────────────────────────────────────────────────────────────
    for block in blocks.iter_mut() {
        let Some(&last_address) = block.instructions.last() else {
            continue;
        };
        let Some(&last_index) = index_of.get(&last_address) else {
            continue;
        };
        let Some(last) = code.instructions.get(last_index) else {
            continue;
        };
        let mnemonic = last.op.mnemonic();
        let next = last.addr.checked_add(u32::from(last.size));

        if is_terminal(mnemonic) {
            continue;
        }
        if mnemonic.starts_with("goto") {
            push_branch_edge(block, last.target, DexEdgeKind::Branch, None, None);
            continue;
        }
        if mnemonic.starts_with("if-") {
            push_branch_edge(block, last.target, DexEdgeKind::Branch, None, None);
            push_branch_edge(block, next, DexEdgeKind::FallThrough, None, None);
            continue;
        }
        if matches!(mnemonic, "packed-switch" | "sparse-switch") {
            push_branch_edge(block, next, DexEdgeKind::SwitchDefault, None, None);
            if let Some(target) = last.target {
                push_switch_case_edges(block, &code.payloads, target);
            }
            continue;
        }
        // 其余（含 fill-array-data、move-exception 与普通语义指令）落空。
        push_branch_edge(block, next, DexEdgeKind::FallThrough, None, None);
    }

    // ── 4. 异常边 ─────────────────────────────────────────────────────────
    for try_item in &code.tries {
        let Some(handler) = code.catch_handlers.get(try_item.handler_idx) else {
            continue;
        };
        let try_start = try_item.start_addr;
        let try_end = try_item
            .start_addr
            .saturating_add(u32::from(try_item.insn_count));
        for (block_index, block) in blocks.iter_mut().enumerate() {
            let block_end = block_ends.get(block_index).copied().unwrap_or(block.start);
            if block.start >= try_end || block_end <= try_start {
                continue;
            }
            for catch in &handler.catches {
                block.edges.push(PendingEdge {
                    kind: DexEdgeKind::ExceptionHandler,
                    target: catch.handler_addr,
                    switch_key: None,
                    exception_type: Some(catch.exception_type.0),
                });
            }
            if let Some(addr) = handler.catch_all_addr {
                block.edges.push(PendingEdge {
                    kind: DexEdgeKind::ExceptionCatchAll,
                    target: addr,
                    switch_key: None,
                    exception_type: None,
                });
            }
        }
    }

    // ── 5. 落成列 ─────────────────────────────────────────────────────────
    let mut out = empty(Vec::new());
    out.block_ids.reserve(blocks.len());
    out.block_starts.reserve(blocks.len());
    for (block_index, block) in blocks.iter().enumerate() {
        out.block_ids
            .push(u32::try_from(block_index).unwrap_or(u32::MAX));
        out.block_starts.push(block.start);
        out.block_instruction_addresses
            .extend_from_slice(&block.instructions);
        out.block_instruction_offsets
            .push(out.block_instruction_addresses.len());
        for edge in &block.edges {
            // 目标不是指令起点：**不连边**，如实记账（§7：不许悄悄丢）。
            match addr_to_block.get(&edge.target) {
                Some(&target_block) => {
                    out.edge_targets.push(target_block);
                    out.edge_kinds.push(edge.kind);
                    out.edge_switch_keys.push(edge.switch_key);
                    out.edge_exception_type_indices.push(edge.exception_type);
                }
                None => {
                    out.unresolved_edge_targets.push(UnresolvedEdgeTarget {
                        from_block: u32::try_from(block_index).unwrap_or(u32::MAX),
                        target: edge.target,
                        kind: edge.kind,
                    });
                }
            }
        }
        out.edge_offsets.push(out.edge_targets.len());
    }

    // ── 6. 前驱 ───────────────────────────────────────────────────────────
    let mut predecessors: Vec<BTreeSet<u32>> = vec![BTreeSet::new(); out.block_ids.len()];
    for (index, target) in out.edge_targets.iter().enumerate() {
        let Some(from) = block_of_edge(&out.edge_offsets, index) else {
            continue;
        };
        let Ok(target_index) = usize::try_from(*target) else {
            continue;
        };
        if let Some(set) = predecessors.get_mut(target_index) {
            set.insert(from);
        }
    }
    for set in predecessors {
        out.predecessors.extend(set);
        out.predecessor_offsets.push(out.predecessors.len());
    }

    // ── 7. 异常区间（try 区间 → 它自己的 handler 块）─────────────────────
    for try_item in &code.tries {
        let Some(handler) = code.catch_handlers.get(try_item.handler_idx) else {
            // `handler_idx` 越界：库的 `parse_code_item` 已经拒绝过这种文件，
            // 走到这里说明上游换了实现 —— 如实报错，不静默少一列。
            return Err(DexViewError::HandlerIndexOutOfRange {
                handler_index: try_item.handler_idx,
                handler_count: code.catch_handlers.len(),
            });
        };
        let mut addresses = Vec::new();
        let mut blocks_column = Vec::new();
        let mut kinds = Vec::new();
        let mut types = Vec::new();
        for catch in &handler.catches {
            addresses.push(catch.handler_addr);
            blocks_column.push(block_for_address(&addr_to_block, catch.handler_addr));
            kinds.push(DexEdgeKind::ExceptionHandler);
            types.push(Some(catch.exception_type.0));
        }
        if let Some(addr) = handler.catch_all_addr {
            addresses.push(addr);
            blocks_column.push(block_for_address(&addr_to_block, addr));
            kinds.push(DexEdgeKind::ExceptionCatchAll);
            types.push(None);
        }
        out.exception_regions.push(DexExceptionRegion {
            start_addr: try_item.start_addr,
            end_addr: try_item
                .start_addr
                .saturating_add(u32::from(try_item.insn_count)),
            handler_addresses: addresses,
            handler_blocks: blocks_column,
            handler_kinds: kinds,
            exception_type_indices: types,
        });
    }

    out.entry_block = (!out.block_ids.is_empty()).then_some(0);
    Ok(out)
}

/// handler 地址落在哪个块。找不到时给 `None` —— **不补 0**（0 是合法块号，补 0 是伪造）。
fn block_for_address(addr_to_block: &BTreeMap<u32, u32>, address: u32) -> Option<u32> {
    addr_to_block.get(&address).copied()
}

/// 由 CSR 边偏移反查边属于哪个块。
fn block_of_edge(edge_offsets: &[usize], edge_index: usize) -> Option<u32> {
    // edge_offsets 形如 [0, a, b, ...]；edge_index 落在 [edge_offsets[i], edge_offsets[i+1])。
    // partition_point 给出第一个"结束位置 > edge_index"的桶，减一即所属块。
    let bucket = edge_offsets.partition_point(|&end| end <= edge_index);
    u32::try_from(bucket.checked_sub(1)?).ok()
}

/// 一条待落列的边（目标是**地址**，落列时才解析成块号）。
struct PendingEdge {
    kind: DexEdgeKind,
    target: u32,
    switch_key: Option<i32>,
    exception_type: Option<u32>,
}

struct BlockDraft {
    start: u32,
    instructions: Vec<u32>,
    edges: Vec<PendingEdge>,
}

/// 把一条边推进块里；目标是 `None` 时**什么都不做**（没有目标就没有边，不是"连到 0"）。
///
/// 目标是否是合法块起点**不在这里判断**：落列时统一解析，解析不出来的进
/// `unresolved_edge_targets`（那里才知道边属于哪个块）。
fn push_branch_edge(
    block: &mut BlockDraft,
    target: Option<u32>,
    kind: DexEdgeKind,
    switch_key: Option<i32>,
    exception_type: Option<u32>,
) {
    let Some(target) = target else {
        return;
    };
    block.edges.push(PendingEdge {
        kind,
        target,
        switch_key,
        exception_type,
    });
}

/// switch 的每个 case 各一条边（key 取自 payload，不是我们编的）。
fn push_switch_case_edges(
    block: &mut BlockDraft,
    payloads: &BTreeMap<u32, PayloadData>,
    payload_addr: u32,
) {
    match payloads.get(&payload_addr) {
        Some(PayloadData::PackedSwitch { first_key, targets }) => {
            for (offset, target) in targets.iter().enumerate() {
                let key = i32::try_from(offset)
                    .ok()
                    .and_then(|offset| first_key.checked_add(offset));
                block.edges.push(PendingEdge {
                    kind: DexEdgeKind::SwitchCase,
                    target: *target,
                    switch_key: key,
                    exception_type: None,
                });
            }
        }
        Some(PayloadData::SparseSwitch { keys, targets }) => {
            for (key, target) in keys.iter().zip(targets.iter()) {
                block.edges.push(PendingEdge {
                    kind: DexEdgeKind::SwitchCase,
                    target: *target,
                    switch_key: Some(*key),
                    exception_type: None,
                });
            }
        }
        _ => {}
    }
}

/// 终结指令：`return*` 与 `throw`（其后没有后继）。
fn is_terminal(mnemonic: &str) -> bool {
    mnemonic.starts_with("return") || mnemonic == "throw"
}

/// 会断开落空的控制转移：分支与 switch。
fn is_branch_or_switch(mnemonic: &str) -> bool {
    mnemonic.starts_with("if-")
        || mnemonic.starts_with("goto")
        || matches!(mnemonic, "packed-switch" | "sparse-switch")
}
