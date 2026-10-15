//! `code_item` 的**布局校验**：指令与载荷必须**恰好铺满** `[0, insns_size)`。
//!
//! 这是设计文档 M1 验收里被推迟的三条中的第一条（另两条要 CFG，见 M2a 后续），
//! 也是**唯一一条能独立于库去验证库的宽度表**的检查：
//! 宽度表里错一个码元，后面所有指令的地址就全错位 —— 不是撞车就是留缝。
//!
//! # 这里刻意"不信"库的长度，只借它的地址
//!
//! 按设计文档的要求，`insns_size` 与**载荷长度**都按规范从**原始字节**重算，
//! 不读库报的长度字段：
//!
//! * `insns_size`：自己从 `code_off + 12` 读（规范 §4.5.12）；
//! * 载荷长度：从载荷自己的 `ident` 与其后的 `size` 字段按规范算（§F.3）；
//! * **只向库要两样东西**：每条指令的 `addr` 与 `size`，以及载荷的起始地址。
//!
//! 于是这条检查真的能抓到东西：库的宽度表若某处算错，我们从原始字节走出来的
//! 地图就会与它给的地址对不上 —— 而不是"用它的长度去验证它的长度"式的自证其说。
//!
//! # 为什么必须做（而不是"库应该处理了"）
//!
//! 库极新，而且发布的 crate 把 `tests/` 排除了（ADR-0019 记录的实测），
//! 所以"库应该处理了"**不是证据**。真实样本上跑一遍才算证据。

use std::collections::BTreeMap;

use droidsaw_dex::decode::parse_code_item;

use super::DexParseError;

/// 规范 §4.5.12：`code_item` 头长度（`insns` 紧随其后）。
const CODE_ITEM_HEADER_SIZE: usize = 16;
/// 规范 §4.5.12 各字段在头里的偏移。
const OFF_REGISTERS_SIZE: usize = 0;
const OFF_INS_SIZE: usize = 2;
const OFF_OUTS_SIZE: usize = 4;
const OFF_TRIES_SIZE: usize = 6;
const OFF_INSNS_SIZE: usize = 12;

/// 规范 §F.3 的三种载荷标识（写在载荷第一个码元里）。
const IDENT_PACKED_SWITCH: u16 = 0x0100;
const IDENT_SPARSE_SWITCH: u16 = 0x0200;
const IDENT_FILL_ARRAY_DATA: u16 = 0x0300;

/// `code_item` 头里那些**由我们从原始字节读出来**的事实。
///
/// 与库报的字段分开存在：这一份是校验的基准，不参与"用库验证库"。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CodeHeaderFacts {
    /// `registers_size`。
    pub registers_size: u16,
    /// `ins_size`。
    pub ins_size: u16,
    /// `outs_size`。
    pub outs_size: u16,
    /// `tries_size`。
    pub tries_size: u16,
    /// `insns_size`，单位是 16 位码元。
    pub insns_size: u32,
}

impl CodeHeaderFacts {
    /// 试图从原始字节读一份头。读不全就返回 `None`（**不补 0**）。
    #[must_use]
    fn read(bytes: &[u8], code_base: usize) -> Option<Self> {
        Some(Self {
            registers_size: read_u16(bytes, code_base.checked_add(OFF_REGISTERS_SIZE)?)?,
            ins_size: read_u16(bytes, code_base.checked_add(OFF_INS_SIZE)?)?,
            outs_size: read_u16(bytes, code_base.checked_add(OFF_OUTS_SIZE)?)?,
            tries_size: read_u16(bytes, code_base.checked_add(OFF_TRIES_SIZE)?)?,
            insns_size: read_u32(bytes, code_base.checked_add(OFF_INSNS_SIZE)?)?,
        })
    }
}

/// 布局校验发现的问题类别。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LayoutProblemKind {
    /// 某个码元处既没有指令也没有载荷：地图有洞。
    Gap,
    /// 一项的结束越过 `insns_size`，或者长度自相矛盾（含长度为 0）。
    Overrun,
    /// 载荷的原始长度读不出来（字节不够，或 `ident` 不是三种之一）。
    PayloadUnreadable,
    /// 库给的某个载荷地址与它自己的指令地址撞在同一码元上。
    PayloadCollidesWithInstruction,
    /// 31t 分支目标不是匹配类型的 payload 起始码元，或与库解码的目标不一致。
    InvalidPayloadTarget,
    /// 一个载荷没有任何 31t 指令指向它。
    OrphanPayload,
    /// try_item 的 handler_off 未落在原始 encoded_catch_handler 起点。
    InvalidHandlerOffset,
}

impl LayoutProblemKind {
    /// 稳定的短名（CLI / JSON / 测试断言用）。
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Gap => "gap",
            Self::Overrun => "overrun",
            Self::PayloadUnreadable => "payload-unreadable",
            Self::PayloadCollidesWithInstruction => "payload-collides-with-instruction",
            Self::InvalidPayloadTarget => "invalid-payload-target",
            Self::OrphanPayload => "orphan-payload",
            Self::InvalidHandlerOffset => "invalid-handler-offset",
        }
    }
}

/// 一条布局问题。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LayoutProblem {
    /// 出问题的码元地址（方法内偏移，单位 16 位码元）。
    pub at: u32,
    /// 类别。
    pub kind: LayoutProblemKind,
    /// 人可读的说明，**带实际数字**（方便与别的工具逐条对拍）。
    pub detail: String,
}

/// 布局校验的结论。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LayoutCheck {
    /// 从原始字节读出的头事实。
    pub header: CodeHeaderFacts,
    /// 库给的指令条数。
    pub instructions: usize,
    /// 库给的载荷个数。
    pub payloads: usize,
    /// 实际走到的位置（应当等于 `insns_size`）。
    pub walked_units: u32,
    /// 走完 `[0, insns_size)` 时消费掉的指令条数与载荷个数。
    pub walked_instructions: usize,
    /// 消费掉的载荷个数。
    pub walked_payloads: usize,
    /// 发现的问题。**空 = 恰好铺满**。
    pub problems: Vec<LayoutProblem>,
}

impl LayoutCheck {
    /// 布局是否恰好铺满：无洞、无重叠、无越界。
    #[must_use]
    pub fn is_exact(&self) -> bool {
        self.problems.is_empty()
    }
}

fn read_u16(bytes: &[u8], off: usize) -> Option<u16> {
    let raw: [u8; 2] = bytes.get(off..off.checked_add(2)?)?.try_into().ok()?;
    Some(u16::from_le_bytes(raw))
}

fn read_u32(bytes: &[u8], off: usize) -> Option<u32> {
    let raw: [u8; 4] = bytes.get(off..off.checked_add(4)?)?.try_into().ok()?;
    Some(u32::from_le_bytes(raw))
}

fn read_i32(bytes: &[u8], off: usize) -> Option<i32> {
    let raw: [u8; 4] = bytes.get(off..off.checked_add(4)?)?.try_into().ok()?;
    Some(i32::from_le_bytes(raw))
}

fn try_and_handlers_offsets(
    code_base: usize,
    insns_size: u32,
    tries_size: u16,
) -> Option<(usize, usize)> {
    let insns_bytes = usize::try_from(insns_size).ok()?.checked_mul(2)?;
    let mut tries_base = code_base
        .checked_add(CODE_ITEM_HEADER_SIZE)?
        .checked_add(insns_bytes)?;
    if insns_size % 2 == 1 {
        tries_base = tries_base.checked_add(2)?;
    }
    let handlers_base = tries_base.checked_add(usize::from(tries_size).checked_mul(8)?)?;
    Some((tries_base, handlers_base))
}

fn read_uleb128(bytes: &[u8], mut pos: usize) -> Option<(u32, usize)> {
    let start = pos;
    let mut value = 0u32;
    for shift in (0..35).step_by(7) {
        let byte = *bytes.get(pos)?;
        pos = pos.checked_add(1)?;
        value |= u32::from(byte & 0x7f).checked_shl(shift)?;
        if byte & 0x80 == 0 {
            return Some((value, pos.checked_sub(start)?));
        }
    }
    None
}

fn read_sleb128(bytes: &[u8], mut pos: usize) -> Option<(i32, usize)> {
    let start = pos;
    let mut value = 0i64;
    let mut shift = 0u32;
    loop {
        let byte = *bytes.get(pos)?;
        pos = pos.checked_add(1)?;
        value |= i64::from(byte & 0x7f).checked_shl(shift)?;
        shift = shift.checked_add(7)?;
        if byte & 0x80 == 0 {
            if shift < 64 && byte & 0x40 != 0 {
                value |= (!0i64) << shift;
            }
            return Some((i32::try_from(value).ok()?, pos.checked_sub(start)?));
        }
        if shift >= 35 {
            return None;
        }
    }
}

/// 返回每个 encoded_catch_handler 起点相对 list 起点的字节偏移。
fn encoded_handler_starts(bytes: &[u8], list_base: usize) -> Option<BTreeMap<usize, usize>> {
    let (count, count_len) = read_uleb128(bytes, list_base)?;
    let mut pos = list_base.checked_add(count_len)?;
    let mut starts = BTreeMap::new();
    for index in 0..usize::try_from(count).ok()? {
        starts.insert(pos.checked_sub(list_base)?, index);
        let (size, size_len) = read_sleb128(bytes, pos)?;
        pos = pos.checked_add(size_len)?;
        let typed_count = usize::try_from(size.unsigned_abs()).ok()?;
        for _ in 0..typed_count {
            let (_, type_len) = read_uleb128(bytes, pos)?;
            pos = pos.checked_add(type_len)?;
            let (_, addr_len) = read_uleb128(bytes, pos)?;
            pos = pos.checked_add(addr_len)?;
        }
        if size <= 0 {
            let (_, catch_all_len) = read_uleb128(bytes, pos)?;
            pos = pos.checked_add(catch_all_len)?;
        }
    }
    Some(starts)
}

/// 码元地址 → 字节偏移。**只有这一处做这个换算**（两处换算必然漂移）。
fn byte_off(insns_base: usize, pc: u32) -> Option<usize> {
    insns_base.checked_add(usize::try_from(pc).ok()?.checked_mul(2)?)
}

/// 按规范 §F.3 从**原始字节**算一个载荷占多少个码元。
///
/// `payload_byte_off` 是载荷第一个码元的**字节**偏移（不是码元下标：
/// 混用这两种单位是这个格式里最容易犯的错）。
///
/// 返回 `None` 表示读不出来（越界，或 `ident` 不是规范里的三种）。
/// 调用方必须把"读不出来"与"长度是 0"分开报 —— 那两件事不一样。
#[must_use]
pub fn payload_width_units(bytes: &[u8], payload_byte_off: usize) -> Option<u16> {
    let ident = read_u16(bytes, payload_byte_off)?;
    match ident {
        // §F.3.1 packed-switch-payload：ident + size + first_key(i32) + targets[size](i32)
        // 码元数 = 1 + 1 + 2 + 2*size
        IDENT_PACKED_SWITCH => {
            let size = read_u16(bytes, payload_byte_off.checked_add(2)?)?;
            4u16.checked_add(size.checked_mul(2)?)
        }
        // §F.3.2 sparse-switch-payload：ident + size + keys[size](i32) + targets[size](i32)
        // 码元数 = 1 + 1 + 2*size + 2*size
        IDENT_SPARSE_SWITCH => {
            let size = read_u16(bytes, payload_byte_off.checked_add(2)?)?;
            2u16.checked_add(size.checked_mul(4)?)
        }
        // §F.3.3 fill-array-data-payload：ident + element_width + size(u32) + data
        // 数据长度按**字节**给并补到偶数，所以是 div_ceil(2)
        IDENT_FILL_ARRAY_DATA => {
            let element_width = read_u16(bytes, payload_byte_off.checked_add(2)?)?;
            let size = read_u32(bytes, payload_byte_off.checked_add(4)?)?;
            let data_bytes = size.checked_mul(u32::from(element_width))?;
            4u16.checked_add(u16::try_from(data_bytes.div_ceil(2)).ok()?)
        }
        _ => None,
    }
}

/// 校验一个 `code_item` 的布局。
///
/// `bytes` 是**完整的 DEX 字节**（不是某一段），`code_off` 取
/// [`super::DexMethod::code_off`]。
///
/// # Errors
///
/// * `code_off == 0`（抽象 / native 方法没有字节码）→ [`DexParseError::NoCode`]；
/// * `code_off` 超出本机可寻址范围 → [`DexParseError::CodeOff`]；
/// * 16 字节头读不全 → [`DexParseError::Header`]（**不补 0 假装读到了**）；
/// * 库解析 `code_item` 失败 → [`DexParseError::CodeItem`]。
pub fn check_code_item_layout(bytes: &[u8], code_off: u32) -> Result<LayoutCheck, DexParseError> {
    if code_off == 0 {
        return Err(DexParseError::NoCode);
    }
    let Ok(code_base) = usize::try_from(code_off) else {
        return Err(DexParseError::CodeOff { off: code_off });
    };
    let Some(header) = CodeHeaderFacts::read(bytes, code_base) else {
        return Err(DexParseError::Header { off: code_off });
    };
    let insns_base = code_base
        .checked_add(CODE_ITEM_HEADER_SIZE)
        .ok_or(DexParseError::CodeOff { off: code_off })?;

    let code = parse_code_item(bytes, code_off).map_err(|source| DexParseError::CodeItem {
        off: code_off,
        source,
    })?;

    let mut problems = Vec::new();

    // 规范 §4.5.12：有 try_item 时，insns_size 为奇数则在 try_item 数组前补 2 字节，
    // 使 try_item 起点保持 4 字节对齐。然后每个 try_item 为 8 字节，后接
    // encoded_catch_handler_list。handler_off 是相对 list 起点的字节偏移。
    if header.tries_size > 0 {
        if let Some((try_items_base, handlers_base)) =
            try_and_handlers_offsets(code_base, header.insns_size, header.tries_size)
        {
            let handler_starts = encoded_handler_starts(bytes, handlers_base);
            match handler_starts {
                Some(starts) => {
                    for i in 0..usize::from(header.tries_size) {
                        let Some(item_off) =
                            i.checked_mul(8).and_then(|n| try_items_base.checked_add(n))
                        else {
                            problems.push(LayoutProblem {
                                at: 0,
                                kind: LayoutProblemKind::InvalidHandlerOffset,
                                detail: "try_item 偏移计算溢出".to_string(),
                            });
                            break;
                        };
                        let Some(handler_off) =
                            item_off.checked_add(6).and_then(|off| read_u16(bytes, off))
                        else {
                            problems.push(LayoutProblem {
                                at: 0,
                                kind: LayoutProblemKind::InvalidHandlerOffset,
                                detail: format!("第 {i} 个 try_item 的 handler_off 读不全"),
                            });
                            continue;
                        };
                        let offset = usize::from(handler_off);
                        if let Some(&expected_index) = starts.get(&offset) {
                            match code.tries.get(i) {
                                Some(lib_try) if lib_try.handler_idx == expected_index => {}
                                Some(lib_try) => problems.push(LayoutProblem {
                                    at: lib_try.start_addr,
                                    kind: LayoutProblemKind::InvalidHandlerOffset,
                                    detail: format!(
                                        "原始 handler_off={offset} 对应 index={expected_index}，库给出 index={}",
                                        lib_try.handler_idx
                                    ),
                                }),
                                None => problems.push(LayoutProblem {
                                    at: 0,
                                    kind: LayoutProblemKind::InvalidHandlerOffset,
                                    detail: format!("第 {i} 个原始 try_item 在库解析结果中缺失"),
                                }),
                            }
                        } else {
                            problems.push(LayoutProblem {
                                at: 0,
                                kind: LayoutProblemKind::InvalidHandlerOffset,
                                detail: format!(
                                    "第 {i} 个 try_item 的 handler_off={offset} 未落在任何 encoded_catch_handler 起点"
                                ),
                            });
                        }
                    }
                }
                None => problems.push(LayoutProblem {
                    at: 0,
                    kind: LayoutProblemKind::InvalidHandlerOffset,
                    detail: "encoded_catch_handler_list 无法按规范完整遍历".to_string(),
                }),
            }
        } else {
            problems.push(LayoutProblem {
                at: 0,
                kind: LayoutProblemKind::InvalidHandlerOffset,
                detail: "try_item / handler list 偏移计算溢出".to_string(),
            });
        }
    }

    // 库给的起点地图：码元 → 指令长度。
    let mut insn_at: BTreeMap<u32, u8> = BTreeMap::new();
    for insn in &code.instructions {
        if insn_at.insert(insn.addr, insn.size).is_some() {
            problems.push(LayoutProblem {
                at: insn.addr,
                kind: LayoutProblemKind::Overrun,
                detail: "库报了两条从同一码元开始的指令".to_string(),
            });
        }
    }

    // 从 0 走到 insns_size：每一步都必须**恰好**有一样东西接着。
    let mut pc: u32 = 0;
    let mut walked_instructions = 0usize;
    let mut walked_payloads = 0usize;
    while pc < header.insns_size {
        if code.payloads.contains_key(&pc) {
            if let Some(size) = insn_at.get(&pc) {
                problems.push(LayoutProblem {
                    at: pc,
                    kind: LayoutProblemKind::PayloadCollidesWithInstruction,
                    detail: format!("同一码元既是指令（长度 {size}）又是载荷起点"),
                });
                break;
            }
            let width = byte_off(insns_base, pc).and_then(|o| payload_width_units(bytes, o));
            match width {
                Some(0) => {
                    problems.push(LayoutProblem {
                        at: pc,
                        kind: LayoutProblemKind::Overrun,
                        detail: "按规范算出的载荷长度为 0".to_string(),
                    });
                    break;
                }
                Some(w) => {
                    walked_payloads += 1;
                    pc = pc.saturating_add(u32::from(w));
                }
                None => {
                    problems.push(LayoutProblem {
                        at: pc,
                        kind: LayoutProblemKind::PayloadUnreadable,
                        detail: format!(
                            "库报了载荷（{:#x} 处的 ident 不是三种之一，或字节不够）",
                            insns_base + usize::try_from(pc).map_or(0, |v| v * 2)
                        ),
                    });
                    break;
                }
            }
            continue;
        }

        match insn_at.get(&pc) {
            Some(0) => {
                problems.push(LayoutProblem {
                    at: pc,
                    kind: LayoutProblemKind::Overrun,
                    detail: "库报了一条长度为 0 的指令".to_string(),
                });
                break;
            }
            Some(size) => {
                walked_instructions += 1;
                pc = pc.saturating_add(u32::from(*size));
            }
            None => {
                problems.push(LayoutProblem {
                    at: pc,
                    kind: LayoutProblemKind::Gap,
                    detail: format!(
                        "码元 {pc} 处既没有指令也没有载荷，而 insns_size={}",
                        header.insns_size
                    ),
                });
                break;
            }
        }
    }

    if pc > header.insns_size {
        problems.push(LayoutProblem {
            at: header.insns_size,
            kind: LayoutProblemKind::Overrun,
            detail: format!(
                "最后一项越过了 insns_size（走到 {pc}，上限 {}）",
                header.insns_size
            ),
        });
    }

    // 31t 的目标独立从原始字节手算：opcode + signed i32 相对码元偏移。
    // 规格 §10.2：fill-array-data=0x26、packed-switch=0x2b、sparse-switch=0x2c。
    let mut targeted_payloads = std::collections::BTreeSet::new();
    for insn in &code.instructions {
        let Some(raw_off) = byte_off(insns_base, insn.addr) else {
            continue;
        };
        let Some(opcode) = read_u16(bytes, raw_off).map(|word| word & 0x00ff) else {
            continue;
        };
        let expected_ident = match opcode {
            0x26 => IDENT_FILL_ARRAY_DATA,
            0x2b => IDENT_PACKED_SWITCH,
            0x2c => IDENT_SPARSE_SWITCH,
            _ => continue,
        };
        let Some(relative) = raw_off.checked_add(2).and_then(|off| read_i32(bytes, off)) else {
            problems.push(LayoutProblem {
                at: insn.addr,
                kind: LayoutProblemKind::InvalidPayloadTarget,
                detail: "31t 指令的 32 位相对目标读不全".to_string(),
            });
            continue;
        };
        let target_i64 = i64::from(insn.addr) + i64::from(relative);
        let Ok(target) = u32::try_from(target_i64) else {
            problems.push(LayoutProblem {
                at: insn.addr,
                kind: LayoutProblemKind::InvalidPayloadTarget,
                detail: format!("31t 目标 {target_i64} 超出 u32 码元地址范围"),
            });
            continue;
        };
        let target_off = byte_off(insns_base, target);
        let ident_matches = target_off
            .and_then(|off| read_u16(bytes, off))
            .is_some_and(|ident| ident == expected_ident);
        if !code.payloads.contains_key(&target) || !ident_matches {
            problems.push(LayoutProblem {
                at: insn.addr,
                kind: LayoutProblemKind::InvalidPayloadTarget,
                detail: format!(
                    "31t opcode {opcode:#04x} 的目标码元 {target} 不是匹配 ident {expected_ident:#06x} 的 payload 起点"
                ),
            });
        }
        if insn.target != Some(target) {
            problems.push(LayoutProblem {
                at: insn.addr,
                kind: LayoutProblemKind::InvalidPayloadTarget,
                detail: format!(
                    "原始字节算出的 31t 目标是 {target}，库给出的 target 是 {:?}",
                    insn.target
                ),
            });
        }
        targeted_payloads.insert(target);
    }
    for payload_addr in code.payloads.keys() {
        if !targeted_payloads.contains(payload_addr) {
            problems.push(LayoutProblem {
                at: *payload_addr,
                kind: LayoutProblemKind::OrphanPayload,
                detail: "没有任何 31t 指令指向这个 payload".to_string(),
            });
        }
    }

    // 库报了、地图里却走不到的项：说明它给的地址与长度互相矛盾。
    if walked_instructions != code.instructions.len() {
        problems.push(LayoutProblem {
            at: 0,
            kind: LayoutProblemKind::Overrun,
            detail: format!(
                "库给了 {} 条指令，地图只走到 {walked_instructions} 条（地址与长度互相矛盾）",
                code.instructions.len()
            ),
        });
    }
    if walked_payloads != code.payloads.len() {
        problems.push(LayoutProblem {
            at: 0,
            kind: LayoutProblemKind::Overrun,
            detail: format!(
                "库给了 {} 个载荷，地图只走到 {walked_payloads} 个",
                code.payloads.len()
            ),
        });
    }

    Ok(LayoutCheck {
        header,
        instructions: code.instructions.len(),
        payloads: code.payloads.len(),
        walked_units: pc.min(header.insns_size),
        walked_instructions,
        walked_payloads,
        problems,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    /// 按 §F.3.1 拼一个 packed-switch-payload（`size` 是 targets 个数）。
    fn packed_switch(size: u16) -> Vec<u8> {
        let mut out = vec![0x00, 0x01]; // ident = 0x0100，小端
        out.extend_from_slice(&size.to_le_bytes());
        out.extend_from_slice(&0i32.to_le_bytes()); // first_key
        for i in 0..size {
            out.extend_from_slice(&i32::from(i).to_le_bytes());
        }
        out
    }

    /// 按 §F.3.2 拼一个 sparse-switch-payload。
    fn sparse_switch(size: u16) -> Vec<u8> {
        let mut out = vec![0x00, 0x02];
        out.extend_from_slice(&size.to_le_bytes());
        for i in 0..size {
            out.extend_from_slice(&i32::from(i).to_le_bytes()); // keys
        }
        for i in 0..size {
            out.extend_from_slice(&i32::from(i).to_le_bytes()); // targets
        }
        out
    }

    /// 按 §F.3.3 拼一个 fill-array-data-payload（数据补到偶数字节）。
    fn fill_array(element_width: u16, count: u32) -> Vec<u8> {
        let mut out = vec![0x00, 0x03];
        out.extend_from_slice(&element_width.to_le_bytes());
        out.extend_from_slice(&count.to_le_bytes());
        let mut data =
            vec![0u8; usize::try_from(count).map_or(0, |c| c) * usize::from(element_width)];
        if data.len() % 2 != 0 {
            data.push(0);
        }
        out.extend_from_slice(&data);
        out
    }

    #[test]
    fn encoded_handler_offsets_are_relative_to_the_list_and_match_real_starts() {
        // count=2；handler 0 从 list+1 开始，size=1 + (type=1, addr=2)；
        // handler 1 从 list+4 开始，size=0 表示 catch-all，addr=3。
        let bytes = [2, 1, 1, 2, 0, 3];
        let starts = encoded_handler_starts(&bytes, 0).expect("完整 handler list");
        assert_eq!(starts.get(&1), Some(&0));
        assert_eq!(starts.get(&4), Some(&1));
        assert!(!starts.contains_key(&2)); // 不能把 handler 内容里的字节误当起点
    }

    #[test]
    fn a_truncated_encoded_handler_list_is_not_accepted() {
        // count=1，handler 声明一个 typed catch，但 type/address 都缺失。
        assert_eq!(encoded_handler_starts(&[1, 1], 0), None);
    }

    #[test]
    fn payload_widths_follow_the_spec_tables() {
        // §F.3.1：4 + size*2
        assert_eq!(payload_width_units(&packed_switch(0), 0), Some(4));
        assert_eq!(payload_width_units(&packed_switch(3), 0), Some(10));
        // §F.3.2：2 + size*4
        assert_eq!(payload_width_units(&sparse_switch(0), 0), Some(2));
        assert_eq!(payload_width_units(&sparse_switch(3), 0), Some(14));
        // §F.3.3：4 + div_ceil(bytes, 2)
        assert_eq!(payload_width_units(&fill_array(1, 4), 0), Some(6));
        assert_eq!(payload_width_units(&fill_array(4, 1), 0), Some(6));
        assert_eq!(payload_width_units(&fill_array(1, 5), 0), Some(7)); // 5 字节补到 6
        assert_eq!(payload_width_units(&fill_array(8, 3), 0), Some(4 + 12));
    }

    #[test]
    fn an_unknown_ident_is_not_guessed() {
        // 0x0400 不是规范里的载荷标识：返回 None，不猜长度。
        assert_eq!(payload_width_units(&[0x00, 0x04, 0, 0], 0), None);
        // 真 NOP（ident 0x0000）也不是载荷。
        assert_eq!(payload_width_units(&[0x00, 0x00], 0), None);
    }

    #[test]
    fn a_payload_reports_its_declared_width_even_when_its_bytes_are_missing() {
        // 一个声明 size=100 的 sparse-switch，实际只有 4 字节头。
        // 宽度**只从头里的 size 算**（2 + 100*4 = 402），不去读键表 —— 这是刻意的：
        // 宽度算得出来，才说得出"它声明的比实际有的多"，而那一条由布局遍历报成
        // Overrun（比在这里返回 None 信息量大得多）。
        let truncated = [0x00u8, 0x02, 100, 0];
        assert_eq!(payload_width_units(&truncated, 0), Some(402));
        // 连 size 字段都读不到时才是 None（这里只给了 ident 两个字节）。
        assert_eq!(payload_width_units(&[0x00u8, 0x02], 0), None);
    }

    #[test]
    fn a_payload_is_measured_at_its_byte_offset_not_a_unit_index() {
        // 前面垫 6 字节后，同一个载荷的字节偏移是 6；若把"码元下标"当字节偏移用，
        // 会读到错位的 ident 并返回 None。这条测试就是钉死这个单位。
        let mut buf = vec![0xAAu8; 6];
        buf.extend_from_slice(&packed_switch(3));
        assert_eq!(payload_width_units(&buf, 0), None);
        assert_eq!(payload_width_units(&buf, 6), Some(10));
    }

    #[test]
    fn no_code_is_an_error_not_an_empty_layout() {
        assert!(matches!(
            check_code_item_layout(&[], 0),
            Err(DexParseError::NoCode)
        ));
    }

    #[test]
    fn an_unreadable_header_is_an_error_not_a_zeroed_header() {
        // code_off 非 0（否则先撞上 NoCode），但缓冲区只有 8 字节，读不出 insns_size。
        // 必须报 Header 错误，不能返回一个 insns_size=0 的"空布局"。
        assert!(matches!(
            check_code_item_layout(&[0u8; 8], 0x10),
            Err(DexParseError::Header { .. })
        ));
    }
}
