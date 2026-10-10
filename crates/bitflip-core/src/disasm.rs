//! 反汇编视图：把地址空间 + 解码扫描接到 wire 上。
//!
//! ## 为什么这里是"会话级"状态
//!
//! 地址空间与指令索引是**按目标**建立的，建立一次就要反复查询（滚动列表、
//! 跳转、交叉引用）。因此它们挂在 `Session` 上，而不是每次请求重建 ——
//! 那会把 100MB 目标的首扫成本乘上用户滚动次数。
//!
//! ## 分页而不是全量
//!
//! `GET .../insns?from=&count=` 只返回一页指令。这不是 UI 的临时妥协，
//! 而是**架构约束**：把 100 万条指令序列化成 JSON 是几百 MB 的响应，
//! 浏览器和内存都撑不住。指令文本在服务端按需渲染（`bitflip-arch::render`）。

use std::sync::Arc;

use bitflip_analyze::{
    scan_linear, scan_recursive, AddrSpace, InsnIndex, ScanCoverage, ScanOptions, ScanStats,
};
use bitflip_arch::{format_insn_with, CapstoneDecoder, Decoder, Flow};
use bitflip_loader::object::Object;
use serde::{Deserialize, Serialize};

/// 反汇编页的 wire 格式版本。
pub const DISASM_FORMAT_VERSION: u32 = 1;

/// 单页最多返回的指令条数。
///
/// 上限存在的意义是防止一个 `?count=10000000` 把内存打满 ——
/// 服务端不信任客户端给的数字。
pub const MAX_PAGE_SIZE: usize = 4096;

/// 默认页大小。
pub const DEFAULT_PAGE_SIZE: usize = 512;

/// 一条指令的 wire 表示（列式）。
///
/// 列式而不是对象数组：同样的数据 JSON 体积小得多，且前端解析更快。
/// 但这里的字段数量还不多，真正的列式收益要等 M5 的函数/基本块视图。
/// 现在保持"一行一条"的可读结构，同时**每字段都不含冗余文本**。
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct InsnWire {
    /// 定长 16 位小写十六进制地址。
    pub address: String,
    /// 编码长度（字节）。
    pub length: u8,
    /// 机器码（小写十六进制，无分隔）。
    pub bytes: String,
    /// 渲染后的指令文本。
    pub text: String,
    /// 流程类型（`flow` / `call` / `jump` / `cond-jump` / `ret` / `trap` / `unknown`）。
    pub flow: String,
    /// 流程的中文标签。
    pub flow_label: String,
    /// 直接控制流目标（定长十六进制）；间接跳转/调用为 `null`。
    pub target: Option<String>,
    /// 是否被递归下降证明可达。
    ///
    /// **这个字段是诚实性的关键**：线性扫描会把数据误当指令。
    /// 前端据此把"仅线性扫到"的指令标灰，而不是假装同样可信。
    pub reachable: bool,
    /// 源文件（来自调试信息）；没有调试信息就是 `null`，不拿别的东西顶替。
    pub file: Option<String>,
    /// 源码行号（来自调试信息）；没有就是 `null`。
    ///
    /// 地址落在两行之间（行表是稀疏的）时为 `null` —— 不返回"最近的那一行"，
    /// 那会把别的代码的行号安到这条指令上。
    pub line: Option<u32>,
}

/// 一页反汇编。
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InsnPage {
    /// wire 格式版本。
    pub format_version: u32,
    /// 本页起始地址（定长十六进制）。
    pub from: String,
    /// 请求的条数上限。
    pub requested: usize,
    /// 实际返回的条数。
    pub returned: usize,
    /// 下一页的游标；`null` 表示后面没有更多已索引指令。
    pub next: Option<String>,
    /// 上一页存在时可用（服务端不维护历史，由前端传入）。
    pub has_more: bool,
    /// 指令列。
    pub instructions: Vec<InsnWire>,
}

/// 反汇编统计（用于 UI 显示覆盖率而不是"分析完成"这种空话）。
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DisasmStats {
    /// 已索引指令数。
    pub indexed: u64,
    /// 递归下降可达的条数。
    pub reachable: u64,
    /// 仅线性扫描覆盖的条数（可信度较低）。
    pub linear_only: u64,
    /// 解码失败的字节数。
    pub decode_failures: u64,
    /// 扫描到的可执行段数。
    pub executable_segments: usize,
    /// 因达到上限而截断的次数。
    pub truncated: u64,
    /// 地址空间字节总量。
    pub mapped_bytes: u64,
    /// 索引常驻内存估算（字节）。
    pub index_bytes: u64,
}

/// 解码扫描的结果，挂在会话上复用。
///
/// 手写 `Debug` 而不是派生：`dyn Decoder` 不实现 `Debug`，
/// 而解码器本身也没有值得打印的状态。
pub struct Disasm {
    /// 地址空间。
    pub space: AddrSpace,
    /// 稀疏指令索引。
    pub index: Arc<InsnIndex>,
    /// 覆盖来源。
    pub coverage: ScanCoverage,
    /// 统计。
    pub stats: ScanStats,
    /// 由哪个解码器扫的（渲染指令文本时要用）。
    ///
    /// 存具体类型而不是 `dyn Decoder`：渲染需要 capstone 的助记符表，
    /// 那是 `CapstoneDecoder` 独有的能力。`Option` 表达"没有可渲染的后端"
    /// （例如 wasm32 只有占位解码器），此时文本退化为助记符编号 ——
    /// 而不是编一段看起来像汇编的字符串。
    pub decoder: Arc<dyn Decoder>,
    /// 可选的渲染后端。
    pub renderer: Option<Arc<CapstoneDecoder>>,
    /// 建库与扫描过程中的降级说明（合成地址、截断、无法解码的字节数…）。
    ///
    /// 这些必须能浮到 UI：分析质量的"折扣"要写在界面上，而不是埋在日志里。
    pub notes: Vec<String>,
    /// 调试信息（地址 → 源位置）。
    ///
    /// 放在反汇编这一层而不是分析层：行号是"这条指令来自哪一行"，属于反汇编
    /// 视图本身；而且反汇编列表、交叉引用、调用图三处都要查同一份映射 ——
    /// 各查各的会漂移（同一地址在两处显示不同的行号是没法解释的）。
    /// `None` 表示目标没有调试信息，此时所有位置字段如实为空。
    pub debug: Option<Arc<bitflip_debug::DebugInfo>>,

    /// 渲染指令文本用的语法风格。
    ///
    /// 放在**这里**而不是让每个调用方自己渲染：导出 AT&T 的第一版把它做成了
    /// "导出层另调一次 `format_insn_with`"，结果忘了把风格接进来，导出的
    /// 仍是 Intel 文本 —— 而那一版**看起来**完全正常（有地址、有指令、
    /// 有字节），只有拿 `%`/`$` 去断言才会露馅。风格是反汇编视图的属性，
    /// 就放在视图上，只有一条渲染路径。
    ///
    /// 改它不影响索引：`index` 只有地址与长度，与文本无关。
    pub text_style: bitflip_arch::TextStyle,
}

impl std::fmt::Debug for Disasm {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Disasm")
            .field("segments", &self.space.segment_count())
            .field("indexed", &self.index.len())
            .field("mapped_bytes", &self.space.total_vsize())
            .field("renderable", &self.renderer.is_some())
            .finish_non_exhaustive()
    }
}

impl Disasm {
    /// 建立反汇编：构造地址空间并跑线性 + 递归下降扫描。
    ///
    /// 种子来自对象里一切可用的入口信息：入口点、导出地址、函数符号。
    /// **没有种子时不猜** —— 只做线性扫描，并在统计里如实反映可达数为 0。
    pub fn build(object: &Object, bytes: Arc<[u8]>, options: ScanOptions) -> Self {
        let mut notes = Vec::new();

        let spec = object.arch;
        // capstone 后端存在时用它（能渲染文本）；不存在时退回占位解码器，
        // 它会对任何字节明确报 Unsupported。**不猜架构**。
        let renderer = CapstoneDecoder::new(spec).ok().map(Arc::new);
        let decoder: Arc<dyn Decoder> = match &renderer {
            Some(cs) => Arc::clone(cs) as Arc<dyn Decoder>,
            None => Arc::from(bitflip_arch::decoder_for(spec)),
        };

        let space = if object.segments.is_empty() {
            // 可重定位目标文件（`.o` / `.obj`）没有程序头，只有节表 ——
            // 这时必须从节表构造，否则地址空间为空、反汇编完全做不了。
            // 合成地址这件事会写进 notes，不静默处理。
            match AddrSpace::from_sections("<目标>", Arc::clone(&bytes), &object.sections) {
                Ok((space, synthetic)) => {
                    if synthetic {
                        notes.push(format!(
                            "这是可重定位目标文件（无程序头），节地址在链接前并未确定：\
                             反汇编里的地址是本次分析合成的（基址 {:#x}），\
                             不是目标文件里真实存在的地址",
                            bitflip_analyze::SYNTHETIC_BASE
                        ));
                    }
                    space
                }
                Err(error) => {
                    notes.push(format!("地址空间构造失败：{error}"));
                    AddrSpace::empty("<目标>")
                }
            }
        } else {
            match AddrSpace::new("<目标>", Arc::clone(&bytes), &object.segments) {
                Ok(space) => space,
                Err(error) => {
                    // 段信息不可用时不编造：返回空地址空间并说明原因
                    notes.push(format!("地址空间构造失败：{error}"));
                    AddrSpace::empty("<目标>")
                }
            }
        };

        let mut coverage = ScanCoverage::new();
        let linear = scan_linear(&space, decoder.as_ref(), options, &mut coverage);

        let seeds = collect_seeds(object);
        if seeds.is_empty() {
            notes.push(
                "没有可用的控制流种子（无入口点/导出/函数符号），只做了线性扫描：\
                 所有指令都标记为“仅线性覆盖”，可信度低于递归下降的可达指令"
                    .to_string(),
            );
        }
        let recursive = if options.recursive && !seeds.is_empty() {
            let mut recursive_coverage = ScanCoverage::new();
            let result = scan_recursive(
                &space,
                decoder.as_ref(),
                &seeds,
                options,
                &mut recursive_coverage,
            );
            coverage.merge(&recursive_coverage);
            coverage.normalize();
            result
        } else {
            (InsnIndex::new(), ScanStats::default())
        };

        let (index, stats) = bitflip_analyze::combine(linear, recursive);
        let index = Arc::new(index);

        // 把最终索引**同步回地址空间**。
        //
        // 不同步会造成一个很隐蔽的数据丢失：`disasm.index` 是正确的，
        // 但 `disasm.space.index()` 永远是空表（`Arc` 也不是同一个）。
        // 任何通过 `space.index()` 取指令的代码都会读到"这里没有指令"，
        // 于是静默地什么也不做 —— 不报错、不降级，只是结论为空。
        //
        // 实测后果：跳转表识别用 `space.index()` 取候选指令，在
        // switch fixture（87 条指令）上一条都取不到；而同一份 Disasm 的
        // `index` 里 87 条都在。两者必须指向同一份数据。
        let mut space = space;
        space.set_index_arc(Arc::clone(&index));

        if stats.truncated > 0 {
            notes.push(format!(
                "扫描达到上限并被截断 {} 次：结果不完整，调大上限或缩小目标范围后重试",
                stats.truncated
            ));
        }
        if stats.decode_failures > 0 {
            notes.push(format!(
                "有 {} 处字节无法解码为指令（数据混在代码段里是常态，不一定是错误）",
                stats.decode_failures
            ));
        }

        Self {
            space,
            index,
            coverage,
            stats,
            decoder,
            renderer,
            notes,
            // 调试信息由 `attach_debug` 挂上：扫描阶段不需要它，`build` 也不该
            // 依赖调用方手上有没有调试信息（没有照常反汇编）。
            debug: None,
            // 默认 Intel：界面上与既有 golden 快照都用它。要 AT&T 由导出层
            // 显式设置（见 `set_text_style`）。
            text_style: bitflip_arch::TextStyle::Intel,
        }
    }

    /// 设置渲染语法风格（原地）。
    ///
    /// 只影响**文本**，不影响索引与覆盖标记 —— 所以切换风格不需要重扫，
    /// 也不会让同一份 `Disasm` 的两条路径看到不同的指令集合。
    pub fn set_text_style(&mut self, style: bitflip_arch::TextStyle) {
        self.text_style = style;
    }

    /// 换一个渲染语法风格，返回新的视图（索引仍是同一个 `Arc`，不重扫）。
    ///
    /// 给"手上是 `&Disasm`、但要换风格输出"的场景用（导出 AT&T）。
    /// 选择 clone 而不是把索引也复制一份：索引是只读的大头，
    /// `Arc` 共享它意味着换风格几乎不花代价。
    #[must_use]
    pub fn with_text_style(&self, style: bitflip_arch::TextStyle) -> Self {
        Self {
            space: self.space.clone(),
            index: Arc::clone(&self.index),
            coverage: self.coverage.clone(),
            stats: self.stats,
            decoder: Arc::clone(&self.decoder),
            renderer: self.renderer.clone(),
            notes: self.notes.clone(),
            debug: self.debug.clone(),
            text_style: style,
        }
    }

    /// 统计。
    #[must_use]
    pub fn wire_stats(&self) -> DisasmStats {
        DisasmStats {
            indexed: self.index.len() as u64,
            reachable: self.coverage.reachable_len() as u64,
            linear_only: self.coverage.linear_only_len() as u64,
            decode_failures: self.stats.decode_failures as u64,
            executable_segments: self.space.executable_segments().len(),
            truncated: self.stats.truncated as u64,
            mapped_bytes: self.space.total_vsize(),
            index_bytes: self.index.estimated_bytes() as u64,
        }
    }

    /// 从 `from` 起顺序遍历已索引指令的地址。
    ///
    /// 这是**导出与分页共用的唯一走位实现**。分开写两份的代价是实测过的：
    /// 那种重复不会编译失败，只会让两条路径在边界上慢慢漂移，
    /// 而漂移的表现是"导出的指令数和界面显示的不一样" —— 用户没有
    /// 办法判断哪个是对的。
    ///
    /// `from` 落在指令中间时从**包含**它的那条指令开始（与 [`Disasm::page`] 一致）。
    #[must_use]
    pub fn cursor(&self, from: u64) -> Cursor<'_> {
        let start = self.index.containing(from).map_or(from, |(addr, _)| addr);
        Cursor {
            disasm: self,
            inner: Box::new(self.index.range(start, u64::MAX)),
        }
    }

    /// 取一页指令。
    ///
    /// `from` 是起始地址；返回**不小于**该地址的第一条已索引指令起的一页。
    /// 这样前端把上一条指令的 `next` 直接传回来就能顺序翻页，
    /// 而不会因为地址落在"指令中间"而拿到空页。
    #[must_use]
    pub fn page(&self, from: u64, count: usize) -> InsnPage {
        let count = count.clamp(1, MAX_PAGE_SIZE);

        let Some((start, _)) = self.index.containing(from) else {
            // 后面没有已索引指令了：返回空页并明确 next = None
            return InsnPage {
                format_version: DISASM_FORMAT_VERSION,
                from: hex16(from),
                requested: count,
                returned: 0,
                next: None,
                has_more: false,
                instructions: Vec::new(),
            };
        };

        let mut instructions = Vec::with_capacity(count);
        for (addr, len) in self.cursor(start).take(count) {
            instructions.push(self.render(addr, len));
        }

        // 下一页游标：本页最后一条的下一条
        let next = instructions.last().and_then(|last| {
            let last_addr = u64::from_str_radix(&last.address, 16).ok()?;
            let after = last_addr + u64::from(last.length);
            self.index.next_at_or_after(after).map(|(a, _)| hex16(a))
        });

        InsnPage {
            format_version: DISASM_FORMAT_VERSION,
            from: hex16(start),
            requested: count,
            returned: instructions.len(),
            has_more: next.is_some(),
            next,
            instructions,
        }
    }

    /// 渲染单条指令。
    ///
    /// 解码失败或字节读不到时**不编造**内容：文本为 `<无法解码>`，
    /// flow 为 `unknown`。这样 UI 上不会出现"看起来像指令其实是垃圾"的行。
    fn render(&self, addr: u64, len: u8) -> InsnWire {
        let bytes = self.space.read(addr, usize::from(len)).unwrap_or_default();
        // 行号查同一份行表；查不到就是"没有"（落在行与行之间也算没有）。
        let location = self.debug.as_ref().and_then(|info| info.location_at(addr));

        let decoded = if bytes.is_empty() {
            None
        } else {
            self.decoder.decode_one(&bytes, addr).ok()
        };

        let (text, flow, target) = match &decoded {
            Some(insn) => {
                // 只有 capstone 后端能把结构化指令渲染成文本。
                // 没有它就退化为助记符编号 —— 不编造"看起来像汇编"的字符串。
                let text = match &self.renderer {
                    Some(cs) => format_insn_with(cs, insn, self.text_style),
                    None => format!("<insn:{}>", insn.mnemonic.get()),
                };
                (text, insn.flow, insn.target)
            }
            None => ("<无法解码>".to_string(), Flow::Unknown, None),
        };

        InsnWire {
            address: hex16(addr),
            length: len,
            bytes: bytes.iter().map(|b| format!("{b:02x}")).collect(),
            text,
            flow: flow_tag(flow).to_string(),
            flow_label: bitflip_arch::flow_label(flow).to_string(),
            target: target.map(hex16),
            reachable: self.coverage.is_reachable(addr),
            file: location.as_ref().and_then(|row| row.file.clone()),
            line: location.as_ref().map(|row| row.line),
        }
    }

    /// 挂上调试信息（行号）。返回是否**有**行表可查。
    ///
    /// 只有说明、没有行表时返回 `false`：调用方据此知道"行号这条路是空的"，
    /// 而不是以为挂上就有行号（说明本身仍然留在 `DebugInfo::notes` 里，
    /// 由 session 汇总给用户看）。
    pub fn attach_debug(&mut self, debug: Option<Arc<bitflip_debug::DebugInfo>>) -> bool {
        let usable = debug
            .as_ref()
            .is_some_and(|info| !info.lines.is_empty() || !info.functions.is_empty());
        self.debug = debug;
        usable
    }
}

/// [`Disasm::cursor`] 返回的指令游标。
///
/// 产出 `(地址, 编码长度)`，**不**在这里渲染 —— 渲染一次要解码 + 查行表，
/// 导出大目标时把渲染结果全攒下来会白占内存，而调用方往往边渲染边写出。
pub struct Cursor<'a> {
    disasm: &'a Disasm,
    inner: Box<dyn Iterator<Item = (u64, u8)> + 'a>,
}

impl Cursor<'_> {
    /// 对应反汇编（渲染单条指令时要它）。
    #[must_use]
    pub const fn disasm(&self) -> &Disasm {
        self.disasm
    }

    /// 渲染下一条指令。
    pub fn render_next(&mut self) -> Option<InsnWire> {
        let (addr, len) = self.inner.next()?;
        Some(self.disasm.render(addr, len))
    }

    /// 剩余指令条数的提示（稀疏索引的 `size_hint` 下界）。
    #[must_use]
    pub fn remaining_hint(&self) -> usize {
        self.inner.size_hint().0
    }
}

impl Iterator for Cursor<'_> {
    type Item = (u64, u8);

    fn next(&mut self) -> Option<Self::Item> {
        self.inner.next()
    }
}

/// 收集控制流种子。
///
/// 来源按可信度排序：入口点 > 导出 > 函数符号。**只收真实存在的**，
/// 不用启发式猜出来的地址（那会让"可达"这个标记失去意义）。
fn collect_seeds(object: &Object) -> Vec<u64> {
    let mut seeds = Vec::new();

    if let Some(entry) = object.entry {
        seeds.push(entry);
    }
    for export in &object.exports {
        seeds.push(export.address);
    }
    for symbol in &object.symbols {
        if symbol.is_function && symbol.defined {
            seeds.push(symbol.value);
        }
    }
    // 展开表（PE .pdata / ELF .eh_frame）给出的函数入口。
    //
    // 这条对**剥离符号**的目标是关键：符号表没了、导出表也可能是空的，
    // 此时展开表是唯一还知道"函数从哪开始"的来源。不把它并入种子，
    // 递归下降就无从进入这些函数 —— 分析结果会是一大片空白，而
    // `.eh_frame` 明明就在文件里躺着。
    //
    // 注意 `m3_acceptance` 的覆盖率测试正依赖这条路径：那里的样本
    // strip 过，148/154 的边界来自 .eh_frame。
    for entry in &object.unwind {
        seeds.push(entry.begin);
    }

    seeds.sort_unstable();
    seeds.dedup();
    seeds
}

/// 流程类型的稳定短名。
fn flow_tag(flow: Flow) -> &'static str {
    match flow {
        Flow::Fallthrough => "flow",
        Flow::Branch { conditional: true } => "cond-jump",
        Flow::Branch { conditional: false } => "jump",
        Flow::Call => "call",
        Flow::Return => "ret",
        Flow::Trap => "trap",
        Flow::Unknown => "unknown",
    }
}

/// 定长 16 位小写十六进制（wire 契约）。
#[must_use]
pub fn hex16(value: u64) -> String {
    format!("{value:016x}")
}

/// 解析用户给的地址：接受 `0x` 前缀或裸十六进制。
#[must_use]
pub fn parse_address(text: &str) -> Option<u64> {
    let trimmed = text.trim();
    let body = trimmed
        .strip_prefix("0x")
        .or_else(|| trimmed.strip_prefix("0X"))
        .unwrap_or(trimmed);
    if body.is_empty() {
        return None;
    }
    u64::from_str_radix(body, 16).ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hex16_is_fixed_width_lowercase() {
        assert_eq!(hex16(0), "0000000000000000");
        assert_eq!(hex16(0x401000), "0000000000401000");
        assert_eq!(hex16(u64::MAX), "ffffffffffffffff");
        assert_eq!(hex16(0xdeadbeef).len(), 16);
    }

    #[test]
    fn parse_address_accepts_prefixed_and_bare() {
        assert_eq!(parse_address("0x401000"), Some(0x401000));
        assert_eq!(parse_address("0X401000"), Some(0x401000));
        assert_eq!(parse_address("401000"), Some(0x401000));
        assert_eq!(parse_address("  0x401000  "), Some(0x401000));
        assert_eq!(parse_address("ffffffffffffffff"), Some(u64::MAX));
    }

    #[test]
    fn parse_address_rejects_garbage() {
        assert_eq!(parse_address(""), None);
        assert_eq!(parse_address("0x"), None);
        assert_eq!(parse_address("zzz"), None);
        assert_eq!(parse_address("0x10000000000000000"), None); // 溢出
        assert_eq!(parse_address("-1"), None);
    }

    #[test]
    fn flow_tags_are_stable() {
        assert_eq!(flow_tag(Flow::Fallthrough), "flow");
        assert_eq!(flow_tag(Flow::Call), "call");
        assert_eq!(flow_tag(Flow::Return), "ret");
        assert_eq!(flow_tag(Flow::Branch { conditional: true }), "cond-jump");
        assert_eq!(flow_tag(Flow::Branch { conditional: false }), "jump");
        assert_eq!(flow_tag(Flow::Trap), "trap");
        assert_eq!(flow_tag(Flow::Unknown), "unknown");
    }

    #[test]
    fn page_size_is_clamped_to_a_maximum() {
        // 服务端不信任客户端给的 count
        let disasm = empty_disasm();
        let page = disasm.page(0, usize::MAX);
        assert_eq!(page.requested, MAX_PAGE_SIZE);
        assert_eq!(page.format_version, DISASM_FORMAT_VERSION);

        let page0 = disasm.page(0, 0);
        assert_eq!(page0.requested, 1, "count=0 应被提升为 1");
    }

    #[test]
    fn empty_index_yields_empty_page_with_no_cursor() {
        let disasm = empty_disasm();
        let page = disasm.page(0x1000, 16);
        assert_eq!(page.returned, 0);
        assert!(page.instructions.is_empty());
        assert_eq!(page.next, None);
        assert!(!page.has_more);
        assert_eq!(page.from, hex16(0x1000), "from 应回显请求地址");
    }

    #[test]
    fn text_style_moves_between_intel_and_att_without_rescanning() {
        // 这条测试锚的是一次真实的回归：导出 AT&T 曾经完全没生效，因为
        // 渲染风格没接到导出路径上，导出的仍是 Intel 文本 —— 而那份输出
        // **看起来**完全正常（有地址、有字节、有指令），只有拿 % / $ 去
        // 断言才会露馅。
        let mut disasm = empty_disasm();
        let renderer = Arc::clone(&disasm.renderer.clone().expect("x86_64 后端应可用"));
        let insn = renderer
            .decode_one(&[0x48, 0x8b, 0x45, 0xf8], 0x1000)
            .expect("解码 mov rax, [rbp-8]");

        let intel = format_insn_with(renderer.as_ref(), &insn, bitflip_arch::TextStyle::Intel);
        let att = format_insn_with(renderer.as_ref(), &insn, bitflip_arch::TextStyle::Att);
        assert!(intel.contains("ptr"), "Intel 应当有 ptr：{intel}");
        assert!(
            att.contains('%') && !att.contains("ptr"),
            "AT&T 应当有 % 且没有 ptr：{att}"
        );

        // 风格是"怎么看"，不是"看什么"：切换后索引（Arc）必须原封不动，
        // 否则会出现"换了语法风格就得重扫"的隐性代价。
        let index_before = Arc::as_ptr(&disasm.index);
        disasm.set_text_style(bitflip_arch::TextStyle::Att);
        assert_eq!(disasm.text_style, bitflip_arch::TextStyle::Att);
        assert_eq!(Arc::as_ptr(&disasm.index), index_before);
    }

    fn empty_disasm() -> Disasm {
        use bitflip_arch::{Arch, ArchSpec, Endian, Mode};
        let spec = ArchSpec::from_arch(Arch::X86_64, Mode::M64, Endian::Little);
        let renderer = Arc::new(CapstoneDecoder::new(spec).expect("x86_64 后端应可用"));
        Disasm {
            space: AddrSpace::empty("t"),
            index: Arc::new(InsnIndex::new()),
            coverage: ScanCoverage::new(),
            stats: ScanStats::default(),
            decoder: Arc::clone(&renderer) as Arc<dyn Decoder>,
            renderer: Some(renderer),
            notes: Vec::new(),
            debug: None,
            text_style: bitflip_arch::TextStyle::Intel,
        }
    }

    #[test]
    fn backends_are_dispatched_by_arch_not_guessed() {
        use bitflip_arch::{Arch, ArchSpec, Endian, Mode};
        // wasm32 没有 capstone 后端：必须拿到 UnsupportedDecoder，
        // 而不是被当成 x86 去解码
        let spec = ArchSpec::from_arch(Arch::Wasm32, Mode::M32, Endian::Little);
        let dec = bitflip_arch::decoder_for(spec);
        assert!(matches!(
            dec.decode_one(&[0x00; 4], 0),
            Err(bitflip_arch::DecodeError::Unsupported { .. })
        ));
    }

    #[test]
    fn wire_stats_fill_all_fields() {
        let disasm = empty_disasm();
        let stats = disasm.wire_stats();
        assert_eq!(stats.indexed, 0);
        assert_eq!(stats.reachable, 0);
        assert_eq!(stats.executable_segments, 0);
        assert_eq!(stats.mapped_bytes, 0);
    }
}
