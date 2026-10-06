//! 脚本的读 API：把目标与分析结论暴露给脚本。
//!
//! # 形状来自 core 的 wire 契约，不另造一套
//!
//! 脚本看到的 `FunctionWire` / `XrefWire` / `InsnWire` 与 HTTP `/api/*`
//! 返回的是**同一批结构**（都是 `bitflip-core` 里的 `Serialize` 类型）。
//! 这样做的收益不只是省代码：用户只需要理解一种数据形状，前端的
//! `web/src/api.ts` 类型定义同时也就是脚本的参考手册。
//!
//! # 分页不是可选项
//!
//! ntdll.dll 一个目标就有 66778 条 xref。提供 `xrefs.all()` 等于给脚本
//! 递上一颗定时炸弹：一次调用物化 6 万多个 JS 对象，超时上限一到就白跑。
//! 所以这里统一给 `count() / page(offset, count) / at(...)`，
//! 而 `search()` 返回的页对象里**同时**带 `total` 与 `truncated` ——
//! 只给"本页几条"，用户没法判断"是被过滤掉了还是本来就没有"（core 的
//! `XrefPage` 已经因为这个问题返工过一次）。
//!
//! # 可省略参数必须写 `Opt<T>`，不能写 `Option<T>`
//!
//! rquickjs 对实参个数是**严格校验**的：`Option<T>` 的 `ParamRequirement`
//! 是 `single()`（必填），只有 `rquickjs::prelude::Opt<T>` 才是 `optional()`。
//! 写成 `Option<T>` 时类型看起来完全正确，但脚本按文档写 `page()` 会得到
//! "Error calling function with 0 argument(s) while 2 where expected" ——
//! 一个只在用户侧才炸的坑。文档里承诺了默认值的参数，这里必须有对应的
//! `Opt` 与测试。

use std::sync::Arc;

use bitflip_core::{
    Disasm, FunctionWire, InsnPage, InsnWire, Session, StringWire, TargetAnalysis, XrefFilter,
    XrefWire, DEFAULT_PAGE_SIZE, MAX_PAGE_SIZE,
};
use rquickjs::prelude::Opt;
use rquickjs::{Ctx, Exception, Function, Object, Value};

use crate::host::{parse_address, Shared};
use crate::js::Wire;

/// `readBytes` 一次最多读多少字节。
///
/// 不是性能考虑而是**诚实**考虑：脚本要 4 GiB 时，与其返回一个被静默截断的
/// 短数组（用户会以为那段内存就这么多），不如报错说清楚上限。
const MAX_READ_BYTES: usize = 1 << 20;

/// 安装读 API。
///
/// 显式绑定同一个 `'js`：`bitflip` 对象与 `ctx` 必须属于同一个上下文，
/// 写成两个独立的匿名生命周期会被借用检查器判为"`'1` 未必比 `'2` 活得久"。
pub(crate) fn install<'js>(
    ctx: &Ctx<'js>,
    state: &Shared,
    bitflip: &Object<'js>,
) -> rquickjs::Result<()> {
    install_target(ctx, state, bitflip)?;
    install_notes(ctx, state, bitflip)?;
    install_counts(ctx, state, bitflip)?;
    install_read_bytes(ctx, state, bitflip)?;
    install_functions(ctx, state, bitflip)?;
    install_xrefs(ctx, state, bitflip)?;
    install_strings(ctx, state, bitflip)?;
    install_insns(ctx, state, bitflip)?;
    Ok(())
}

// ---------------------------------------------------------------------------
// 能力解析
// ---------------------------------------------------------------------------

fn session_of(state: &Shared) -> Option<Arc<Session>> {
    state.lock().session.clone()
}

/// 取分析结论。
///
/// `Session` 内部用 `OnceLock` 缓存，所以这里反复调用只有第一次付代价，
/// 而且拿到的是与服务层**同一个** `Arc`。
fn analysis(ctx: &Ctx<'_>, state: &Shared) -> rquickjs::Result<Arc<TargetAnalysis>> {
    let Some(session) = session_of(state) else {
        return Err(Exception::throw_message(
            ctx,
            "本次会话没有打开目标，读不了分析结论",
        ));
    };
    session
        .analysis(&session.detached_job())
        .map_err(|err| Exception::throw_message(ctx, &format!("无法构建分析结论：{err}")))
}

/// 取反汇编结果（由调用方注入的提供者负责缓存）。
fn disasm(ctx: &Ctx<'_>, state: &Shared) -> rquickjs::Result<Arc<Disasm>> {
    let provider = state.lock().disasm.clone();
    let Some(provider) = provider else {
        return Err(Exception::throw_message(
            ctx,
            "本次会话没有反汇编结果；bitflip.insns.* 不可用",
        ));
    };
    provider().map_err(|err| Exception::throw_message(ctx, err.as_str()))
}

// ---------------------------------------------------------------------------
// 通用分页
// ---------------------------------------------------------------------------

/// 切一页并组装页对象。
///
/// `requested` 与 `returned` 都带上：`count` 被 `MAX_PAGE_SIZE` 收敛时，
/// 只看 `returned` 会以为"后面的数据没了"，看到 `requested` 才知道是自己
/// 要多了。
fn slice_page<T: serde::Serialize>(all: &[T], offset: usize, count: usize) -> serde_json::Value {
    let skip = offset.min(all.len());
    let take = count.min(MAX_PAGE_SIZE);
    let end = skip.saturating_add(take).min(all.len());
    let items = &all[skip..end];
    serde_json::json!({
        "total": all.len(),
        "requested": count,
        "skipped": skip,
        "returned": items.len(),
        "truncated": all.len() - end,
        "items": items,
    })
}

/// 建一个子对象并挂到父对象上。
fn sub<'js>(ctx: &Ctx<'js>, parent: &Object<'js>, name: &str) -> rquickjs::Result<Object<'js>> {
    let object = Object::new(ctx.clone())?;
    parent.set(name, object.clone())?;
    Ok(object)
}

// ---------------------------------------------------------------------------
// 各段安装
// ---------------------------------------------------------------------------

/// `bitflip.target`：目标识别结论。
///
/// 这里是**值**不是函数：目标信息在会话打开时就确定了，没有惰性可言。
/// 没有会话时为 `null`（而不是空对象 —— 空对象会被 `Object.keys(...).length`
/// 之类当成"有目标但字段缺失"）。
fn install_target<'js>(
    ctx: &Ctx<'js>,
    state: &Shared,
    bitflip: &Object<'js>,
) -> rquickjs::Result<()> {
    let value = match session_of(state) {
        Some(session) => serde_json::to_value(session.target_info())
            .map_err(|err| Exception::throw_message(ctx, &format!("目标信息无法序列化：{err}")))?,
        None => serde_json::Value::Null,
    };
    bitflip.set("target", Wire(value))?;
    Ok(())
}

/// `bitflip.notes()`：分析过程的降级说明。
///
/// **必须暴露**：分析器拿不到某些信息时会写一条 note（"ELF 无 .eh_frame，
/// 函数边界靠线性扫描"之类）。脚本如果读不到这些，就会把一份降级结果
/// 当成完整事实导出成清单 —— 那正是 CLAUDE.md §7 禁止的。
fn install_notes<'js>(
    ctx: &Ctx<'js>,
    state: &Shared,
    bitflip: &Object<'js>,
) -> rquickjs::Result<()> {
    let state = state.clone();
    bitflip.set(
        "notes",
        Function::new(
            ctx.clone(),
            move |ctx: Ctx<'_>| -> rquickjs::Result<Wire<Vec<String>>> {
                let analysis = analysis(&ctx, &state)?;
                Ok(Wire(analysis.notes().to_vec()))
            },
        )?,
    )?;
    Ok(())
}

/// `bitflip.counts()`：各类条数汇总。
fn install_counts<'js>(
    ctx: &Ctx<'js>,
    state: &Shared,
    bitflip: &Object<'js>,
) -> rquickjs::Result<()> {
    let state = state.clone();
    bitflip.set(
        "counts",
        Function::new(
            ctx.clone(),
            move |ctx: Ctx<'_>| -> rquickjs::Result<Wire<serde_json::Value>> {
                let analysis = analysis(&ctx, &state)?;
                Ok(Wire(serde_json::json!({
                    "functions": analysis.function_count(),
                    "blocks": analysis.basic_block_count(),
                    "xrefs": analysis.xref_count(),
                    "strings": analysis.strings().len(),
                    "cfgs": analysis.cfg_count(),
                })))
            },
        )?,
    )?;
    Ok(())
}

/// `bitflip.readBytes(addr, length)`：读原始字节，返回小写十六进制串。
fn install_read_bytes<'js>(
    ctx: &Ctx<'js>,
    state: &Shared,
    bitflip: &Object<'js>,
) -> rquickjs::Result<()> {
    let state = state.clone();
    bitflip.set(
        "readBytes",
        Function::new(
            ctx.clone(),
            move |ctx: Ctx<'_>,
                  address: Value<'_>,
                  length: usize|
                  -> rquickjs::Result<Wire<String>> {
                if length > MAX_READ_BYTES {
                    return Err(Exception::throw_message(
                        &ctx,
                        &format!("一次最多读 {MAX_READ_BYTES} 字节（收到 {length}）"),
                    ));
                }
                let address = parse_address(&ctx, &address)?;
                let Some(session) = session_of(&state) else {
                    return Err(Exception::throw_message(
                        &ctx,
                        "本次会话没有打开目标，读不了字节",
                    ));
                };
                let bytes = session.read_virtual(address, length).map_err(|err| {
                    Exception::throw_message(&ctx, &format!("读取 {address:#x} 失败：{err}"))
                })?;
                Ok(Wire(hex_encode(&bytes)))
            },
        )?,
    )?;
    Ok(())
}

fn install_functions<'js>(
    ctx: &Ctx<'js>,
    state: &Shared,
    bitflip: &Object<'js>,
) -> rquickjs::Result<()> {
    let functions = sub(ctx, bitflip, "functions")?;

    {
        let state = state.clone();
        functions.set(
            "count",
            Function::new(
                ctx.clone(),
                move |ctx: Ctx<'_>| -> rquickjs::Result<usize> {
                    Ok(analysis(&ctx, &state)?.function_count())
                },
            )?,
        )?;
    }
    {
        let state = state.clone();
        functions.set(
            "page",
            Function::new(
                ctx.clone(),
                move |ctx: Ctx<'_>,
                      offset: Opt<usize>,
                      count: Opt<usize>|
                      -> rquickjs::Result<Wire<serde_json::Value>> {
                    let analysis = analysis(&ctx, &state)?;
                    Ok(Wire(slice_page(
                        analysis.functions(),
                        offset.0.unwrap_or(0),
                        count.0.unwrap_or(DEFAULT_PAGE_SIZE),
                    )))
                },
            )?,
        )?;
    }
    {
        let state = state.clone();
        functions.set(
            "at",
            Function::new(
                ctx.clone(),
                move |ctx: Ctx<'_>,
                      address: Value<'_>|
                      -> rquickjs::Result<Wire<Option<FunctionWire>>> {
                    let address = parse_address(&ctx, &address)?;
                    let analysis = analysis(&ctx, &state)?;
                    let exact = analysis
                        .function_containing(address)
                        .filter(|f| f.start == bitflip_core::hex16(address))
                        .cloned();
                    Ok(Wire(exact))
                },
            )?,
        )?;
    }
    {
        let state = state.clone();
        functions.set(
            "containing",
            Function::new(
                ctx.clone(),
                move |ctx: Ctx<'_>,
                      address: Value<'_>|
                      -> rquickjs::Result<Wire<Option<FunctionWire>>> {
                    let address = parse_address(&ctx, &address)?;
                    let analysis = analysis(&ctx, &state)?;
                    Ok(Wire(analysis.function_containing(address).cloned()))
                },
            )?,
        )?;
    }
    Ok(())
}

fn install_xrefs<'js>(
    ctx: &Ctx<'js>,
    state: &Shared,
    bitflip: &Object<'js>,
) -> rquickjs::Result<()> {
    let xrefs = sub(ctx, bitflip, "xrefs")?;

    {
        let state = state.clone();
        xrefs.set(
            "count",
            Function::new(
                ctx.clone(),
                move |ctx: Ctx<'_>| -> rquickjs::Result<usize> {
                    Ok(analysis(&ctx, &state)?.xref_count())
                },
            )?,
        )?;
    }
    {
        let state = state.clone();
        xrefs.set(
            "page",
            Function::new(
                ctx.clone(),
                move |ctx: Ctx<'_>,
                      offset: Opt<usize>,
                      count: Opt<usize>|
                      -> rquickjs::Result<Wire<serde_json::Value>> {
                    let analysis = analysis(&ctx, &state)?;
                    Ok(Wire(slice_page(
                        analysis.xrefs(),
                        offset.0.unwrap_or(0),
                        count.0.unwrap_or(DEFAULT_PAGE_SIZE),
                    )))
                },
            )?,
        )?;
    }
    {
        // 按**下标**取一条。存在的意义是让"遍历全部"不必一次物化：
        // 脚本可以 `for (let i = 0; i < n; i++)` 一条一条看。
        let state = state.clone();
        xrefs.set(
            "at",
            Function::new(
                ctx.clone(),
                move |ctx: Ctx<'_>, index: usize| -> rquickjs::Result<Wire<Option<XrefWire>>> {
                    let analysis = analysis(&ctx, &state)?;
                    Ok(Wire(analysis.xrefs().get(index).cloned()))
                },
            )?,
        )?;
    }
    {
        let state = state.clone();
        xrefs.set(
            "from",
            Function::new(
                ctx.clone(),
                move |ctx: Ctx<'_>, address: Value<'_>| -> rquickjs::Result<Wire<Vec<XrefWire>>> {
                    let address = parse_address(&ctx, &address)?;
                    let analysis = analysis(&ctx, &state)?;
                    Ok(Wire(
                        analysis.xrefs_from(address).into_iter().cloned().collect(),
                    ))
                },
            )?,
        )?;
    }
    {
        let state = state.clone();
        xrefs.set(
            "to",
            Function::new(
                ctx.clone(),
                move |ctx: Ctx<'_>, address: Value<'_>| -> rquickjs::Result<Wire<Vec<XrefWire>>> {
                    let address = parse_address(&ctx, &address)?;
                    let analysis = analysis(&ctx, &state)?;
                    Ok(Wire(
                        analysis.xrefs_to(address).into_iter().cloned().collect(),
                    ))
                },
            )?,
        )?;
    }
    {
        let state = state.clone();
        xrefs.set(
            "search",
            Function::new(
                ctx.clone(),
                move |ctx: Ctx<'_>,
                      filter: Opt<Value<'_>>|
                      -> rquickjs::Result<Wire<serde_json::Value>> {
                    let (filter, offset, count) = parse_filter(&ctx, filter.0.as_ref())?;
                    let analysis = analysis(&ctx, &state)?;
                    let page = analysis.search_xrefs(&filter, offset, count.min(MAX_PAGE_SIZE));
                    Ok(Wire(serde_json::json!({
                        "total": page.total,
                        "requested": count,
                        "skipped": page.skipped,
                        "returned": page.returned(),
                        // core 强调过：这个数必须能算出来并显示，
                        // 否则用户会以为数据丢了。
                        "truncated": page.truncated(),
                        "items": page.items,
                    })))
                },
            )?,
        )?;
    }
    Ok(())
}

fn install_strings<'js>(
    ctx: &Ctx<'js>,
    state: &Shared,
    bitflip: &Object<'js>,
) -> rquickjs::Result<()> {
    let strings = sub(ctx, bitflip, "strings")?;

    {
        let state = state.clone();
        strings.set(
            "count",
            Function::new(
                ctx.clone(),
                move |ctx: Ctx<'_>| -> rquickjs::Result<usize> {
                    Ok(analysis(&ctx, &state)?.strings().len())
                },
            )?,
        )?;
    }
    {
        let state = state.clone();
        strings.set(
            "page",
            Function::new(
                ctx.clone(),
                move |ctx: Ctx<'_>,
                      offset: Opt<usize>,
                      count: Opt<usize>|
                      -> rquickjs::Result<Wire<serde_json::Value>> {
                    let analysis = analysis(&ctx, &state)?;
                    Ok(Wire(slice_page(
                        analysis.strings(),
                        offset.0.unwrap_or(0),
                        count.0.unwrap_or(DEFAULT_PAGE_SIZE),
                    )))
                },
            )?,
        )?;
    }
    {
        let state = state.clone();
        strings.set(
            "at",
            Function::new(
                ctx.clone(),
                move |ctx: Ctx<'_>,
                      address: Value<'_>|
                      -> rquickjs::Result<Wire<Option<StringWire>>> {
                    let address = parse_address(&ctx, &address)?;
                    let analysis = analysis(&ctx, &state)?;
                    let wanted = bitflip_core::hex16(address);
                    Ok(Wire(
                        analysis
                            .strings()
                            .iter()
                            .find(|s| s.address == wanted)
                            .cloned(),
                    ))
                },
            )?,
        )?;
    }
    Ok(())
}

fn install_insns<'js>(
    ctx: &Ctx<'js>,
    state: &Shared,
    bitflip: &Object<'js>,
) -> rquickjs::Result<()> {
    let insns = sub(ctx, bitflip, "insns")?;

    {
        let state = state.clone();
        insns.set(
            "page",
            Function::new(
                ctx.clone(),
                move |ctx: Ctx<'_>,
                      from: Value<'_>,
                      count: Opt<usize>|
                      -> rquickjs::Result<Wire<InsnPage>> {
                    let from = parse_address(&ctx, &from)?;
                    let disasm = disasm(&ctx, &state)?;
                    Ok(Wire(
                        disasm.page(from, count.0.unwrap_or(DEFAULT_PAGE_SIZE)),
                    ))
                },
            )?,
        )?;
    }
    {
        // 严格取"起始地址正好是它"的那条；`page()` 是游标语义（返回 >= from
        // 的第一条），差距很大 —— 用游标冒充精确查找会让脚本在处理
        // "这个地址有指令吗"时拿到下一条指令，静默算错。
        let state = state.clone();
        insns.set(
            "at",
            Function::new(
                ctx.clone(),
                move |ctx: Ctx<'_>,
                      address: Value<'_>|
                      -> rquickjs::Result<Wire<Option<InsnWire>>> {
                    let address = parse_address(&ctx, &address)?;
                    let disasm = disasm(&ctx, &state)?;
                    let wanted = bitflip_core::hex16(address);
                    let page = disasm.page(address, 1);
                    Ok(Wire(
                        page.instructions
                            .into_iter()
                            .find(|insn| insn.address == wanted),
                    ))
                },
            )?,
        )?;
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// 过滤器解析
// ---------------------------------------------------------------------------

/// 解析 `xrefs.search` 的参数对象。
///
/// `value` 为 `None` 表示调用时没给参数（`search()`），与给了 `{}` 等价 ——
/// rquickjs 对实参个数是严格校验的，所以"可省略"必须写成 [`Opt`]，
/// 用 `Option<T>` 只会得到一个"实参个数不符"的错误。
fn parse_filter(
    ctx: &Ctx<'_>,
    value: Option<&Value<'_>>,
) -> rquickjs::Result<(XrefFilter, usize, usize)> {
    let mut filter = XrefFilter::default();
    let mut offset = 0usize;
    let mut count = DEFAULT_PAGE_SIZE;

    let Some(value) = value else {
        return Ok((filter, offset, count));
    };
    if value.is_undefined() || value.is_null() {
        return Ok((filter, offset, count));
    }
    let Some(object) = value.as_object() else {
        return Err(Exception::throw_message(
            ctx,
            "xrefs.search 的参数必须是对象，例如 { kinds: ['call'] }",
        ));
    };

    // 注意 `kinds: []` 与不给 `kinds` 是**两件事**：前者是"一个类型都不要"
    // （匹配 0 条），后者是"不按类型过滤"。这个区别在 core 的
    // `XrefFilter` 文档里专门写过，这里必须原样保留。
    if let Some(kinds) = object.get::<_, Option<Vec<String>>>("kinds")? {
        filter.kinds = Some(kinds.into_iter().collect());
    }
    if let Some(sources) = object.get::<_, Option<Vec<String>>>("sources")? {
        filter.sources = Some(sources.into_iter().collect());
    }
    if let Some(range) = object.get::<_, Option<Vec<Value<'_>>>>("fromRange")? {
        filter.from_range = Some(parse_range(ctx, "fromRange", &range)?);
    }
    if let Some(range) = object.get::<_, Option<Vec<Value<'_>>>>("toRange")? {
        filter.to_range = Some(parse_range(ctx, "toRange", &range)?);
    }
    if let Some(value) = object.get::<_, Option<usize>>("offset")? {
        offset = value;
    }
    if let Some(value) = object.get::<_, Option<usize>>("count")? {
        count = value;
    }

    Ok((filter, offset, count))
}

/// 解析 `[起始, 结束)` 地址对。
fn parse_range(ctx: &Ctx<'_>, name: &str, range: &[Value<'_>]) -> rquickjs::Result<(u64, u64)> {
    if range.len() != 2 {
        return Err(Exception::throw_message(
            ctx,
            &format!("{name} 必须是 [起始地址, 结束地址] 两个元素（左闭右开）"),
        ));
    }
    let start = parse_address(ctx, &range[0])?;
    let end = parse_address(ctx, &range[1])?;
    Ok((start, end))
}

/// 字节转小写十六进制（无分隔）。
fn hex_encode(bytes: &[u8]) -> String {
    use std::fmt::Write as _;
    let mut out = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        // 写进 String 不会失败；显式忽略返回值以免触发 must_use。
        let _ = write!(out, "{byte:02x}");
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hex_encoding_is_lowercase_and_unpadded_at_the_byte_level() {
        assert_eq!(hex_encode(&[0x00, 0x0f, 0xff]), "000fff");
        assert_eq!(hex_encode(&[]), "");
    }

    #[test]
    fn a_page_reports_both_what_was_asked_and_what_came_back() {
        let all: Vec<u32> = (0..10).collect();
        let page = slice_page(&all, 2, 3);
        assert_eq!(page["total"], 10);
        assert_eq!(page["requested"], 3);
        assert_eq!(page["skipped"], 2);
        assert_eq!(page["returned"], 3);
        assert_eq!(page["truncated"], 5);
    }

    #[test]
    fn an_offset_past_the_end_yields_an_empty_page_not_a_panic() {
        let all: Vec<u32> = (0..3).collect();
        let page = slice_page(&all, 99, 10);
        assert_eq!(page["skipped"], 3, "越界的 offset 收敛到总数");
        assert_eq!(page["returned"], 0);
        assert_eq!(page["truncated"], 0);
    }

    #[test]
    fn a_count_beyond_the_page_cap_is_clamped_and_visibly_so() {
        let all: Vec<u32> = (0..(MAX_PAGE_SIZE as u32 + 100)).collect();
        let page = slice_page(&all, 0, usize::MAX);
        assert_eq!(
            page["returned"], MAX_PAGE_SIZE,
            "超过上限的 count 必须收敛到 MAX_PAGE_SIZE"
        );
        assert_eq!(
            page["requested"],
            usize::MAX,
            "但要把用户原本要的数量如实回报，否则看不出是自己要多了"
        );
        assert_eq!(page["truncated"], 100);
    }
}
