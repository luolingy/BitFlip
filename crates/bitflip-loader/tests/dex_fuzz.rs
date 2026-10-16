//! DEX 视图 / CFG 的系统化模糊测试（M2a 遗留的"完整异常输入审计"）。
//!
//! 三条靶子：
//! 1. **结构化随机 `CodeItem`**：直接在库的解析结果表示上造"合理"输入（地址递增、
//!    载荷挂在 31t 上、try/handler 自洽），打投影 / CFG / 渲染；
//! 2. **字节级变异**：从按规范拼出的合法 `code_item` 出发随机改字节、截断；
//! 3. **纯随机字节**：任意长度的垃圾，直接喂给字节入口。
//!
//! 三条不许破的底线（CLAUDE.md §7）：
//! * **不 panic**：畸形输入只能变成 `Err`；这里用 `catch_unwind` 兜住，好把
//!   复现所需的种子与输入一起报出来；
//! * **不编造**：连不上的分支目标必须进 `unresolved_edge_targets`，且它**不能**
//!   是指令起点（是起点就该连上）；
//! * **不静默**：投影成功时列对账、跨表对账、载荷对账都必须为空。
//!
//! 随机数用自带的确定性 PRNG（不新增依赖，许可闸门无需变动）；失败信息里带种子，
//! 所以这些用例是**可复现**的，不是"偶尔红一次"。

use std::collections::{BTreeMap, BTreeSet};
use std::fmt::Write as _;
use std::panic::{catch_unwind, AssertUnwindSafe};

use bitflip_loader::{
    check_code_item_layout, project_dex_code_item, project_dex_method, render_dex_instructions,
    render_dex_instructions_with_symbols, DexMethodView, DexSymbolOutcome, DexSymbolResolver,
};
use droidsaw_dex::decode::{
    parse_code_item, CatchHandler, CodeItem, Instruction, PayloadData, PoolIndex, RegList, TryItem,
    TypedCatch,
};
use droidsaw_dex::ids::{CallSiteIdx, FieldIdx, MethodIdx, StringIdx, TypeIdx};
use droidsaw_dex::opcodes::Opcode;

// ── 确定性 PRNG（xorshift64*）────────────────────────────────────────────────

/// 不引入 `rand`：模糊测试要的是"可复现"，固定种子的自写 PRNG 就够，
/// 而且省掉一次新增依赖的许可检查。
struct Rng(u64);

impl Rng {
    const fn new(seed: u64) -> Self {
        // 0 会让 xorshift 停在 0，兜一个非零值。
        Self(if seed == 0 {
            0x9E37_79B9_7F4A_7C15
        } else {
            seed
        })
    }

    fn next_u64(&mut self) -> u64 {
        let mut x = self.0;
        x ^= x >> 12;
        x ^= x << 25;
        x ^= x >> 27;
        self.0 = x;
        x.wrapping_mul(0x2545_F491_4F6C_DD1D)
    }

    /// `0..n`（`n == 0` 时返回 0，免得调用点到处判空）。
    fn below(&mut self, n: u32) -> u32 {
        if n == 0 {
            return 0;
        }
        u32::try_from(self.next_u64() % u64::from(n)).unwrap_or(0)
    }

    fn chance(&mut self, percent: u32) -> bool {
        self.below(100) < percent
    }

    fn byte(&mut self) -> u8 {
        u8::try_from(self.next_u64() & 0xFF).unwrap_or(0)
    }

    /// `0..len` 的下标。
    fn index(&mut self, len: usize) -> usize {
        usize::try_from(self.below(u32::try_from(len).unwrap_or(u32::MAX))).unwrap_or(0)
    }
}

fn hex(bytes: &[u8]) -> String {
    let mut out = String::new();
    for byte in bytes.iter().take(96) {
        let _ = write!(out, "{byte:02x}");
    }
    if bytes.len() > 96 {
        let _ = write!(out, "…（共 {} 字节）", bytes.len());
    }
    out
}

/// 兜住被测代码的 panic，把复现所需的种子与输入附在失败信息里。
fn guarded<T>(
    what: &str,
    iteration: usize,
    seed: u64,
    input: &str,
    f: impl FnOnce() -> T,
) -> Result<T, String> {
    match catch_unwind(AssertUnwindSafe(f)) {
        Ok(value) => Ok(value),
        Err(payload) => {
            let detail = payload
                .downcast_ref::<&str>()
                .map(|text| (*text).to_owned())
                .or_else(|| payload.downcast_ref::<String>().cloned())
                .unwrap_or_else(|| "<非字符串 panic 载荷>".to_owned());
            Err(format!(
                "{what} panic（iteration={iteration}, seed={seed:#x}）：{detail}\n  输入：{input}"
            ))
        }
    }
}

// ── 渲染用替身：只关心"不许失败、条数要对" ──────────────────────────────────

struct CountingSymbols;

impl DexSymbolResolver for CountingSymbols {
    fn write_string(&self, index: u32, output: &mut String) -> DexSymbolOutcome {
        let _ = write!(output, "s{index}");
        DexSymbolOutcome::Written
    }

    fn write_type(&self, index: u32, output: &mut String) -> DexSymbolOutcome {
        let _ = write!(output, "Lt{index};");
        DexSymbolOutcome::Written
    }

    fn write_field(&self, index: u32, output: &mut String) -> DexSymbolOutcome {
        let _ = write!(output, "Lc;->f{index}:I");
        DexSymbolOutcome::Written
    }

    fn write_method(
        &self,
        index: u32,
        _proto: Option<u32>,
        output: &mut String,
    ) -> DexSymbolOutcome {
        let _ = write!(output, "Lc;->m{index}()V");
        DexSymbolOutcome::Written
    }
}

// ── 成功投影后的不变量 ──────────────────────────────────────────────────────

fn view_problems(view: &DexMethodView) -> Vec<String> {
    let mut problems = Vec::new();
    problems.extend(view.consistency_problems());
    problems.extend(view.cross_check_problems());
    problems.extend(view.payloads.consistency_problems());

    // 不许编造：能被连上的目标（指令起点）不该出现在"连不上"的账本里。
    let starts: BTreeSet<u32> = view.instructions.addresses.iter().copied().collect();
    for unresolved in &view.cfg.unresolved_edge_targets {
        if starts.contains(&unresolved.target) {
            problems.push(format!(
                "目标 {:#x} 是指令起点，却被记成「连不上」",
                unresolved.target
            ));
        }
    }

    match view.cfg.entry_block {
        Some(0) => {}
        _ if view.instructions.is_empty() => {}
        other => problems.push(format!("非空方法的入口块应当是 0，实际 {other:?}")),
    }

    let mut text = String::new();
    if render_dex_instructions(&view.instructions, &mut text).is_err() {
        problems.push("无论次文本渲染返回了错误".to_owned());
    }
    text.clear();
    match render_dex_instructions_with_symbols(&view.instructions, &CountingSymbols, &mut text) {
        Ok(report) => {
            if report.instructions != view.instructions.len() {
                problems.push(format!(
                    "符号渲染报了 {} 条，指令列有 {} 条",
                    report.instructions,
                    view.instructions.len()
                ));
            }
            if report.unavailable_operands != 0 {
                problems.push(format!(
                    "替身解析器不该有 {} 处解析异常",
                    report.unavailable_operands
                ));
            }
        }
        Err(_) => problems.push("符号渲染返回了错误".to_owned()),
    }
    problems
}

// ── 靶子 1：结构化随机 CodeItem ─────────────────────────────────────────────

fn random_start(rng: &mut Rng, starts: &[u32]) -> u32 {
    if starts.is_empty() {
        return 0;
    }
    starts[rng.index(starts.len())]
}

fn plausible_code_item(rng: &mut Rng) -> CodeItem {
    let mut instructions: Vec<Instruction> = Vec::new();
    let mut payload_slots: Vec<usize> = Vec::new();
    // 起点偶尔不从 0 开始：真实方法从 0 起，但非 0 也应当被如实处理。
    let mut addr: u32 = if rng.chance(20) { rng.below(8) } else { 0 };
    let count = 1 + rng.below(10);

    for _ in 0..count {
        let (op, size) = match rng.below(10) {
            0 => (Opcode::Nop, 1),
            1 => (Opcode::Const4, 1),
            2 => (Opcode::ReturnVoid, 1),
            3 => (Opcode::Throw, 1),
            4 | 5 => (Opcode::Goto, 1),
            6 | 7 => (Opcode::IfEqz, 2),
            8 => (Opcode::PackedSwitch, 3),
            _ => (Opcode::SparseSwitch, 3),
        };
        let dst = if rng.chance(60) {
            Some(u16::try_from(rng.below(8)).unwrap_or(0))
        } else {
            None
        };
        let source: Vec<u16> = (0..rng.below(3))
            .map(|_| u16::try_from(rng.below(8)).unwrap_or(0))
            .collect();
        let pool = match rng.below(6) {
            0 => Some(PoolIndex::String(StringIdx(rng.below(50)))),
            1 => Some(PoolIndex::Type(TypeIdx(rng.below(50)))),
            2 => Some(PoolIndex::Field(FieldIdx(rng.below(50)))),
            3 => Some(PoolIndex::Method(MethodIdx(rng.below(50)))),
            4 => Some(PoolIndex::CallSite(CallSiteIdx(rng.below(50)))),
            _ => None,
        };
        let index = instructions.len();
        instructions.push(Instruction {
            addr,
            op,
            size,
            dst,
            src: RegList::from_slice(&source),
            literal: i64::from(rng.below(200)) - 100,
            target: None,
            pool_idx: pool,
        });
        // 只有 31t（switch / fill-array）才带载荷指针；给它挂载荷，
        // 别把普通指令的 `target` 也占了（那会盖掉上面设的分支目标）。
        if matches!(
            op,
            Opcode::PackedSwitch | Opcode::SparseSwitch | Opcode::FillArrayData
        ) {
            payload_slots.push(index);
        }
        addr = addr.saturating_add(u32::from(size));
    }

    let starts: Vec<u32> = instructions.iter().map(|insn| insn.addr).collect();

    // 分支目标：多数落在真指令上，少数故意落在末尾之后 / 指令中间 / 远处。
    let code_end = addr;
    for insn in &mut instructions {
        let mnemonic = insn.op.mnemonic();
        if mnemonic.starts_with("goto") || mnemonic.starts_with("if-") {
            insn.target = Some(match rng.below(10) {
                0..=6 => random_start(rng, &starts),
                7 => code_end,
                8 => insn.addr.wrapping_add(1),
                _ => rng.below(64),
            });
        }
    }

    // 载荷：挂到 31t 上，目标同样多数合法、少数故意连不上。
    let mut payloads: BTreeMap<u32, PayloadData> = BTreeMap::new();
    for slot in payload_slots {
        if !rng.chance(75) {
            continue;
        }
        let cases = 1 + rng.below(4);
        let targets: Vec<u32> = (0..cases)
            .map(|_| {
                if rng.chance(80) {
                    random_start(rng, &starts)
                } else {
                    rng.below(64)
                }
            })
            .collect();
        let payload_addr = addr;
        let units = match instructions[slot].op {
            Opcode::PackedSwitch => {
                payloads.insert(
                    payload_addr,
                    PayloadData::PackedSwitch {
                        first_key: i32::try_from(rng.below(40)).unwrap_or(0) - 20,
                        targets,
                    },
                );
                2 + 2 * cases
            }
            Opcode::SparseSwitch => {
                let keys: Vec<i32> = (0..cases)
                    .map(|_| i32::try_from(rng.below(200)).unwrap_or(0) - 100)
                    .collect();
                payloads.insert(payload_addr, PayloadData::SparseSwitch { keys, targets });
                2 + 4 * cases
            }
            _ => {
                payloads.insert(
                    payload_addr,
                    PayloadData::FillArrayData {
                        element_width: u16::try_from(1 + rng.below(8)).unwrap_or(1),
                        data: (0..cases).map(|_| rng.byte()).collect(),
                    },
                );
                2 + 2 * cases
            }
        };
        instructions[slot].target = Some(payload_addr);
        addr = addr.saturating_add(units);
    }

    // try / handler：只在同时给了 handler 时才加 try（否则是"合理输入"里的
    // 悬空 handler_idx，属于另一条已经单独覆盖的路径）。
    let mut tries = Vec::new();
    let mut catch_handlers = Vec::new();
    if rng.chance(50) {
        let start = random_start(rng, &starts);
        let handler_addr = if rng.chance(80) {
            random_start(rng, &starts)
        } else {
            rng.below(64)
        };
        tries.push(TryItem {
            start_addr: start,
            insn_count: u16::try_from(1 + rng.below(4)).unwrap_or(1),
            handler_idx: 0,
        });
        let catches: Vec<TypedCatch> = (0..rng.below(3))
            .map(|_| TypedCatch {
                exception_type: TypeIdx(rng.below(40)),
                handler_addr,
            })
            .collect();
        catch_handlers.push(CatchHandler {
            catches,
            catch_all_addr: if rng.chance(50) {
                Some(handler_addr)
            } else {
                None
            },
        });
    }

    CodeItem {
        registers_size: u16::try_from(rng.below(16)).unwrap_or(0),
        ins_size: u16::try_from(rng.below(4)).unwrap_or(0),
        outs_size: u16::try_from(rng.below(4)).unwrap_or(0),
        debug_info_off: 0,
        instructions,
        tries,
        catch_handlers,
        payloads,
        invariant_violations: Vec::new(),
    }
}

#[test]
fn random_plausible_code_items_project_without_lying() {
    const SEED: u64 = 0x5EED_0001;
    const ITERATIONS: usize = 4000;
    let mut rng = Rng::new(SEED);
    let mut failures: Vec<String> = Vec::new();

    for iteration in 0..ITERATIONS {
        let item = plausible_code_item(&mut rng);
        let rendered = match project_dex_code_item(&item) {
            Ok(view) => {
                let problems = view_problems(&view);
                if problems.is_empty() {
                    None
                } else {
                    Some(problems)
                }
            }
            Err(error) => Some(vec![format!("合理输入却投影失败：{error}")]),
        };
        if let Some(problems) = rendered {
            failures.push(format!(
                "iteration={iteration}\n  {}\n  指令：{:?}\n  载荷地址：{:?}",
                problems.join("\n  "),
                item.instructions
                    .iter()
                    .map(|insn| (insn.addr, insn.op.mnemonic(), insn.size, insn.target))
                    .collect::<Vec<_>>(),
                item.payloads.keys().collect::<Vec<_>>()
            ));
            if failures.len() >= 5 {
                break;
            }
        }
    }

    assert!(
        failures.is_empty(),
        "seed={SEED:#x}：{} 例结构化随机输入破了不变量（最多列 5 例）：\n{}",
        failures.len(),
        failures.join("\n")
    );
}

// ── 靶子 2：字节级变异 ──────────────────────────────────────────────────────

/// 按规范 §4.5.12 拼一个合法 `code_item`。
///
/// 编码出处（规范 §4.5.12 / §4.5.14 / §4.5.16 / §F.2.1）：
/// * 头 16 字节：`registers_size` / `ins_size` / `outs_size` / `tries_size`（各 u16），
///   然后 `debug_info_off` / `insns_size`（各 u32）；
/// * `10x` 格式的 `return-void` 是 `0x000e`（高位字节 0）—— 与 `dex_structure.rs`
///   里那条同一个出处；
/// * `11n` 格式的 `const/4 vA, #+B` = `(B << 12) | (A << 8) | 0x12`；
/// * `try_item` = `start_addr`(u32) + `insn_count`(u16) + `handler_off`(u16)，
///   `handler_off` 的基准是 `encoded_catch_handler_list` 的起点；
/// * `encoded_catch_handler_list` = uleb128 `size` + `size` 个 `encoded_catch_handler`；
/// * `encoded_catch_handler` = sleb128 `size` + `size` 个 (uleb128 `type_idx`,
///   uleb128 `addr`)；`size <= 0` 时后面再跟一个 uleb128 `catch_all_addr`。
///
/// `insns_size = 2`（偶数）且 `tries_size = 1`，所以 `try_item` 前**没有**填充。
fn spec_code_item() -> Vec<u8> {
    let mut out = Vec::new();
    let push_u16 = |out: &mut Vec<u8>, value: u16| out.extend_from_slice(&value.to_le_bytes());
    let push_u32 = |out: &mut Vec<u8>, value: u32| out.extend_from_slice(&value.to_le_bytes());

    push_u16(&mut out, 1); // registers_size
    push_u16(&mut out, 0); // ins_size
    push_u16(&mut out, 0); // outs_size
    push_u16(&mut out, 1); // tries_size
    push_u32(&mut out, 0); // debug_info_off
    push_u32(&mut out, 2); // insns_size（码元数）
    push_u16(&mut out, 0x1012); // const/4 v0, #1
    push_u16(&mut out, 0x000e); // return-void

    push_u32(&mut out, 0); // try_item.start_addr
    push_u16(&mut out, 1); // try_item.insn_count
    push_u16(&mut out, 1); // try_item.handler_off（列表起点之后 1 字节）

    out.push(0x01); // encoded_catch_handler_list.size
    out.push(0x01); // encoded_catch_handler.size（正数 = 类型化 catch 的条数）
    out.push(0x00); // type_idx
    out.push(0x00); // addr
    out
}

#[test]
fn the_byte_fuzz_seed_is_a_valid_code_item() {
    // 这条用例的作用是**不让种子本身就是错的**：如果上面的编码写错，
    // 库会解析出别的东西（或直接报错），模糊测试就会在一个假前提上跑。
    let bytes = spec_buffer();
    let code = parse_code_item(&bytes, CODE_OFF).expect("按规范拼出的 code_item 必须能被库解析");

    assert_eq!(code.instructions.len(), 2, "两条指令");
    assert_eq!(code.instructions[0].op, Opcode::Const4);
    assert_eq!(
        (code.instructions[0].addr, code.instructions[0].size),
        (0, 1)
    );
    assert_eq!(code.instructions[0].dst, Some(0));
    assert_eq!(code.instructions[0].literal, 1);
    assert_eq!(code.instructions[1].op, Opcode::ReturnVoid);
    assert_eq!(
        (code.instructions[1].addr, code.instructions[1].size),
        (1, 1)
    );
    assert_eq!(code.tries.len(), 1);
    assert_eq!(code.tries[0].handler_idx, 0);
    assert_eq!(code.catch_handlers.len(), 1);
    assert_eq!(code.catch_handlers[0].catches.len(), 1);
    assert_eq!(code.catch_handlers[0].catches[0].exception_type, TypeIdx(0));
    assert_eq!(code.catch_handlers[0].catches[0].handler_addr, 0);
    assert_eq!(code.catch_handlers[0].catch_all_addr, None);
}

/// `spec_buffer()` 里 `code_item` 所在的偏移。
///
/// 为什么不能是 0：偏移 0 是"这个方法没有字节码"的哨兵值（也是真实 DEX 头部
/// `magic` 的位置），两条入口都该在它上面报 `NoCode`。把 `code_item` 放在 0
/// 会让整个字节级模糊测试一直在打错误分支，等于没测解析路径。
const CODE_OFF: u32 = 0x20;

/// 前缀只是给 `code_item` 找个非零的家；内容无关紧要（`parse_code_item`
/// 只从 `code_off` 读），所以填 0。
fn spec_buffer() -> Vec<u8> {
    let mut out = vec![0u8; usize::try_from(CODE_OFF).unwrap_or(0x20)];
    out.extend(spec_code_item());
    out
}

/// 字节级一轮的结果：问题清单 + "这条路径真的被走到了吗"的计数。
///
/// 计数是防**空转绿灯**用的：如果变异后的字节永远解析失败，"投影成功就不许说谎"
/// 那条断言就一次都没执行过，用例会绿得毫无意义（CLAUDE.md §7）。
#[derive(Default)]
struct ByteFuzzOutcome {
    problems: Vec<String>,
    projected_ok: bool,
    layout_ok: bool,
}

fn check_bytes(what: &str, iteration: usize, seed: u64, bytes: &[u8]) -> ByteFuzzOutcome {
    let input = hex(bytes);
    let mut problems = Vec::new();

    // `code_off = 0` 是"没有字节码"的哨兵值：必须**明确**报 `NoCode`，
    // 而不是去把文件头解析成 `code_item`（那会得到一堆假行）。
    match guarded(what, iteration, seed, &input, || {
        project_dex_method(bytes, 0)
    }) {
        Ok(Ok(_)) => problems.push("code_off=0（抽象/native）竟然投影成功了".to_owned()),
        Ok(Err(error)) if !matches!(error, bitflip_loader::DexViewError::NoCode) => {
            problems.push(format!("code_off=0 应当报 NoCode，实际报的是：{error}"));
        }
        Ok(Err(_)) => {}
        Err(report) => problems.push(report),
    }

    // 越界偏移：错误路径，不 panic。
    match guarded(what, iteration, seed, &input, || {
        project_dex_method(bytes, u32::MAX)
    }) {
        Ok(Ok(_)) => problems.push("code_off=u32::MAX 竟然投影成功了".to_owned()),
        Ok(Err(_)) => {}
        Err(report) => problems.push(report),
    }

    let layout = guarded(what, iteration, seed, &input, || {
        check_code_item_layout(bytes, CODE_OFF)
    });
    let projected = guarded(what, iteration, seed, &input, || {
        project_dex_method(bytes, CODE_OFF)
    });

    // 外层 `Err` = 被测代码 panic 了（`guarded` 兜住的）；两层都要报。
    if let Err(report) = &layout {
        problems.push(report.clone());
    }
    if let Err(report) = &projected {
        problems.push(report.clone());
    }

    // 任一路径成功，就必须满足同一组不变量（两边都成功时也要互相印证）。
    if let Ok(Ok(view)) = &projected {
        problems.extend(view_problems(view));
    }
    if let Ok(Ok(check)) = &layout {
        if let Ok(Ok(view)) = &projected {
            if view.instructions.len() != check.instructions
                || view.payloads.addresses.len() != check.payloads
            {
                problems.push(format!(
                    "布局校验（{} 条指令 / {} 个载荷）与投影（{} 条 / {} 个）不一致",
                    check.instructions,
                    check.payloads,
                    view.instructions.len(),
                    view.payloads.addresses.len()
                ));
            }
        }
    }
    ByteFuzzOutcome {
        problems,
        projected_ok: matches!(projected, Ok(Ok(_))),
        layout_ok: matches!(layout, Ok(Ok(_))),
    }
}

#[test]
fn mutated_code_item_bytes_never_panic_and_never_lie() {
    const SEED: u64 = 0x5EED_0002;
    const ITERATIONS: usize = 3000;
    let seed_bytes = spec_buffer();
    let mut rng = Rng::new(SEED);
    let mut failures: Vec<String> = Vec::new();
    let mut projected_ok = 0usize;
    let mut layout_ok = 0usize;

    for iteration in 0..ITERATIONS {
        let mut bytes = seed_bytes.clone();
        for _ in 0..1 + rng.below(6) {
            // 变异位置偏向 `code_item` 本体（前缀只是为了让偏移非 0）。
            let at = if rng.chance(80) {
                let start = usize::try_from(CODE_OFF).unwrap_or(0);
                start + rng.index(bytes.len() - start)
            } else {
                rng.index(bytes.len())
            };
            bytes[at] = match rng.below(4) {
                0 => 0x00,
                1 => 0xFF,
                2 => 0x80,
                _ => rng.byte(),
            };
        }
        // 偶尔截断，专门打"读不全"的路径。
        if rng.chance(20) {
            let keep = rng.index(bytes.len());
            bytes.truncate(keep);
        }

        let outcome = check_bytes("变异字节", iteration, SEED, &bytes);
        if outcome.projected_ok {
            projected_ok += 1;
        }
        if outcome.layout_ok {
            layout_ok += 1;
        }
        if !outcome.problems.is_empty() {
            failures.push(format!(
                "iteration={iteration}\n  {}",
                outcome.problems.join("\n  ")
            ));
            if failures.len() >= 5 {
                break;
            }
        }
    }

    assert!(
        failures.is_empty(),
        "seed={SEED:#x}：{} 例变异输入破了不变量（最多列 5 例）：\n{}",
        failures.len(),
        failures.join("\n")
    );
    // 防空转：解析/布局真的成功过，"成功就不许说谎"那条断言才不是废话。
    println!(
        "  变异字节：{ITERATIONS} 轮，投影成功 {projected_ok} 次、布局校验成功 {layout_ok} 次"
    );
    assert!(
        projected_ok >= ITERATIONS / 10,
        "只有 {projected_ok} 轮真的走到了投影成功分支 —— 断言等于没执行（种子或变异方式有问题）"
    );
    assert!(
        layout_ok >= ITERATIONS / 10,
        "只有 {layout_ok} 轮真的走到了布局校验成功分支 —— 断言等于没执行"
    );
}

#[test]
fn purely_random_bytes_never_panic() {
    const SEED: u64 = 0x5EED_0003;
    const ITERATIONS: usize = 2000;
    let mut rng = Rng::new(SEED);
    let mut failures: Vec<String> = Vec::new();
    let mut accepted = 0usize;

    for iteration in 0..ITERATIONS {
        // 长度特意包含 0：空缓冲区也必须走错误路径。
        let length = rng.below(128);
        let bytes: Vec<u8> = (0..length).map(|_| rng.byte()).collect();

        let outcome = check_bytes("随机字节", iteration, SEED, &bytes);
        if outcome.projected_ok || outcome.layout_ok {
            accepted += 1;
        }
        if !outcome.problems.is_empty() {
            failures.push(format!(
                "iteration={iteration}\n  {}",
                outcome.problems.join("\n  ")
            ));
            if failures.len() >= 5 {
                break;
            }
        }
    }

    assert!(
        failures.is_empty(),
        "seed={SEED:#x}：{} 例随机字节破了不变量（最多列 5 例）：\n{}",
        failures.len(),
        failures.join("\n")
    );
    println!("  随机字节：{ITERATIONS} 轮，其中 {accepted} 轮被任一条路径接受");
    // 反向的防空转：随机字节绝大多数必须被**拒掉**。如果这里几乎全 "接受"，
    // 说明入口在拿垃圾当有效输入（那才是真正的谎）。
    assert!(
        accepted <= ITERATIONS / 10,
        "随机字节有 {accepted}/{ITERATIONS} 轮被接受，太多了"
    );
}

// ── 回归：切块游标必须真前进 ────────────────────────────────────────────────

/// 零宽度的"指令"不是规范里的东西（每条指令至少占 1 个码元），
/// 但 `project_dex_code_item` 收的是**调用方给的** `CodeItem`：留了宽度 0 的口子，
/// 切块时 `index_of[next]` 会指回游标自己，地址表无限增长（挂死/OOM）。
///
/// 修法是"到这儿收块"：宽度 0 的那条**留在它所在的块里**（它是调用方给的指令，
/// 如实投影，不悄悄丢掉），只是不再从它往前走。结果是每条指令仍被恰好覆盖一次，
/// 所以跨表对账是空的 —— 这是对的，覆盖确实完整。
#[test]
fn a_zero_width_instruction_stops_the_block_instead_of_spinning_forever() {
    let narrow = |addr: u32, op: Opcode, size: u8| Instruction {
        addr,
        op,
        size,
        dst: None,
        src: RegList::from_slice(&[]),
        literal: 0,
        target: None,
        pool_idx: None,
    };
    let item = CodeItem {
        registers_size: 1,
        ins_size: 0,
        outs_size: 0,
        debug_info_off: 0,
        instructions: vec![
            narrow(0, Opcode::Const4, 1),
            // 宽度 0：它不是块首（地址与上一条连续），所以会走到"游标不前进"的分支。
            narrow(1, Opcode::Nop, 0),
            narrow(2, Opcode::ReturnVoid, 1),
        ],
        tries: Vec::new(),
        catch_handlers: Vec::new(),
        payloads: BTreeMap::new(),
        invariant_violations: Vec::new(),
    };

    // 关键断言：**会返回**。修之前这里会原地打转、地址表无限增长。
    let view = project_dex_code_item(&item).expect("零宽度输入也必须返回结果，而不是挂死");

    let mut covered: Vec<u32> = view.cfg.block_instruction_addresses.clone();
    covered.sort_unstable();
    assert_eq!(
        covered,
        vec![0, 1, 2],
        "每条指令都该被恰好覆盖一次（宽度 0 的那条留在块里、不被悄悄丢掉）"
    );
    assert_eq!(
        view.cfg.block_starts,
        vec![0, 2],
        "宽度 0 之后不再往前走，所以地址 2 只能是新块的起点"
    );
    assert!(view.consistency_problems().is_empty());
    assert!(
        view.cross_check_problems().is_empty(),
        "覆盖是完整的，跨表对账不该报问题：{:?}",
        view.cross_check_problems()
    );
    // 宽度 0 如实留在列里（我们没有偷偷把它改成 1）。
    assert_eq!(view.instructions.widths, vec![1, 0, 1]);
}

/// 地址重复（调用方给的顺序里两条指令同址）：`index_of` 只留最后一个，
/// 前一条必然覆盖不到 —— 那也要**报出来**，不能悄悄当成两条都覆盖了。
#[test]
fn duplicate_addresses_are_reported_rather_than_silently_merged() {
    let instruction_at = |addr: u32, op: Opcode| Instruction {
        addr,
        op,
        size: 1,
        dst: None,
        src: RegList::from_slice(&[]),
        literal: 0,
        target: None,
        pool_idx: None,
    };
    let item = CodeItem {
        registers_size: 1,
        ins_size: 0,
        outs_size: 0,
        debug_info_off: 0,
        instructions: vec![
            instruction_at(0, Opcode::Const4),
            instruction_at(0, Opcode::Nop),
            instruction_at(1, Opcode::ReturnVoid),
        ],
        tries: Vec::new(),
        catch_handlers: Vec::new(),
        payloads: BTreeMap::new(),
        invariant_violations: Vec::new(),
    };

    let view = project_dex_code_item(&item).expect("重复地址也必须返回结果");
    let problems = view.cross_check_problems();
    assert!(
        !problems.is_empty(),
        "同址的两条指令必然少覆盖一条，跨表对账必须说话（实际：{:?}）",
        view.cfg.block_instruction_addresses
    );
}
