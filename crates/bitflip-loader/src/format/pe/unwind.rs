//! PE 展开信息：`.pdata` 的 `RUNTIME_FUNCTION` 与 x64 `UNWIND_INFO`。
//!
//! 这是"栈帧多大 + 保存了哪些寄存器"的**权威来源**：它由编译器生成，描述
//! "如何撤销这个函数的栈操作"。栈帧视图（M6）拿它和反汇编的前导扫描**交叉
//! 核对**，两边一致才敢下结论。
//!
//! # 只解码能确定的
//!
//! 版本、标志位、前导大小、帧寄存器、保存/分配操作都直接取自 `UNWIND_INFO`。
//! XMM 保存记录在案但**不计入帧大小**（它们也占栈，但字节数取决于浮点寄存器
//! 宽度，先不猜）；看不懂的操作码原样记下，让上层如实显示"有未识别的展开
//! 操作"，而不是丢掉它当作没发生。
//!
//! 解码结果 [`PeUnwindInfo`] 是**格式特有**的细节。通用层（栈帧推导）不读它，
//! 只读 `crate::object::UnwindEntry` 上那组格式无关访问器 —— 这样以后解码
//! ELF 的 CFI 指令时，分析层一个字都不用改。

use super::*;

/// 解析 `.pdata`（`RUNTIME_FUNCTION`：BeginAddress / EndAddress / UnwindInfoAddress）。
pub(super) fn parse_pdata(
    reader: &Reader<'_>,
    object: &Object,
    dir: DataDir,
) -> Result<Vec<UnwindEntry>, ParseError> {
    // RUNTIME_FUNCTION 在 PE32+ 里恒为 12 字节（三个 4 字节 RVA）
    const ENTRY_SIZE: u64 = 12;
    let count = u64::from(dir.size) / ENTRY_SIZE;
    if count == 0 {
        return Ok(Vec::new());
    }
    if count > MAX_TABLE_ENTRIES {
        return Err(ParseError::Overflow(format!(
            ".pdata 声称有 {count} 条记录，超过上限"
        )));
    }
    let offset = rva_to_offset(object, dir.rva).ok_or_else(|| {
        ParseError::Inconsistent(format!(
            ".pdata RVA {:#x} 不在任何有文件后备的节里",
            dir.rva
        ))
    })?;

    let entries: Vec<(u32, u32, u32)> =
        reader.for_each_entry(offset, ENTRY_SIZE, count, ".pdata", |_i, view| {
            Ok((
                view.u32(0, Endianness::Little, "BeginAddress")?,
                view.u32(4, Endianness::Little, "EndAddress")?,
                view.u32(8, Endianness::Little, "UnwindInfoAddress")?,
            ))
        })?;

    Ok(entries
        .into_iter()
        .map(|(begin, end, info)| {
            let begin = rva_to_va(object, begin);
            let end = rva_to_va(object, end);
            let info_va = rva_to_va(object, info);
            UnwindEntry {
                begin,
                end,
                unwind_info: info_va,
                // **推迟**解码 UNWIND_INFO，理由见 `UnwindEntry::deferred`。
                //
                // 早先在这里直接 `parse_unwind_info(...)`，于是打开目标时就要把
                // 每一条都解开。实测 owo-terminal.exe（201 MiB）有 417,629 条，
                // 光这一步 1.2 秒 —— 而 `info` 与 `functions` 的路径一个字段都用不到。
                // 真正的消费者是 `bitflip-analyze::frames::scan_frames`，它按需解。
                decoded: None,
                deferred: true,
            }
        })
        .collect())
}

/// 解码 x64 的 `UNWIND_INFO`（`.pdata` 条目指向的展开数据）。
///
/// # 结构（Microsoft PE/COFF 规范）
///
/// ```text
/// byte 0: Version(3) | Flags(3) | 保留(2)      // x64 现行版本 = 1
/// byte 1: SizeOfProlog
/// byte 2: CountOfCodes
/// byte 3: FrameRegister(4) | FrameOffset(4)   // FrameOffset 缩放 16
/// 之后: CountOfCodes × UNWIND_CODE（每槽 2 字节），4 字节对齐
/// ```
///
/// `UNWIND_CODE` 每槽 2 字节：`CodeOffset`(前导偏移) + `UnwindOp(4)` + `OpInfo(4)`。
/// 部分操作（ALLOC_LARGE / *_FAR / SAVE_NONVOL）**额外消耗后续槽位**，
/// 而 `CountOfCodes` 把附加槽也数进去了 —— 遍历时必须跟着跳过，
/// 否则会把附加数据当成独立操作码。
pub(crate) fn parse_unwind_info(
    reader: &Reader<'_>,
    object: &Object,
    unwind_info_va: u64,
) -> Option<PeUnwindInfo> {
    let mut notes = Vec::new();

    // VA → 文件偏移。定位不到就返回 None（调用方如实显示"无展开信息"）。
    let rva = unwind_info_va.checked_sub(object.image_base)? as u32;
    let offset = rva_to_offset(object, rva)?;

    let header = reader.slice(offset, 4, "UNWIND_INFO 头").ok()?;
    let version = header[0] & 0x07;
    let flags = (header[0] >> 3) & 0x07;
    let prologue_size = header[1];
    let count_of_codes = u64::from(header[2]);
    let frame_reg_raw = header[3] & 0x0F;
    let frame_offset_scaled = (header[3] >> 4) & 0x0F;

    // 版本 1 = x64（PE/COFF 规范："Version: currently 1"）。
    // 其他版本（如 ARM64 用的 2）操作码语义不同，只记录头字段。
    //
    // 这里最初写成了"版本 0 才是 x64"，在真实 MinGW PE 上立刻暴露：
    // 127 条展开信息**全部**报版本 1，于是全部退化成"只记录头字段"，
    // 一条操作码都没解出来。规范里 0 是历史值，现行 x64 就是 1。
    if version != 1 {
        notes.push(format!(
            "展开信息版本 {version} 不是 x64 现行版本（1），仅记录头字段，不解码展开操作"
        ));
        return Some(PeUnwindInfo {
            version,
            flags,
            prologue_size,
            frame_register: None,
            frame_offset: 0,
            ops: Vec::new(),
            notes,
        });
    }

    let frame_register = (frame_reg_raw != 0)
        .then(|| x64_reg_name(frame_reg_raw))
        .flatten()
        .map(str::to_string);
    let frame_offset = u32::from(frame_offset_scaled) * 16;

    // ── 遍历 UNWIND_CODE 槽位 ──
    // 第一遍：解析操作序列并累计"栈分配"（帧大小）。第二遍用帧大小
    // 给 push 槽位定位（push 的槽位要等总帧大小定了才知道相对最终 RSP
    // 的位置）。
    let codes_base = offset + 4;
    struct RawOp {
        opcode: u8,
        info: u8,
        prolog_off: u8,
        /// 附加数据（如 ALLOC_LARGE 的大小、SAVE 的偏移）。
        extra: Option<u32>,
    }

    let mut raw: Vec<RawOp> = Vec::new();
    let mut slot: usize = 0;
    let mut truncated = false;
    while slot < count_of_codes as usize {
        let base = codes_base + (slot as u64) * 2;
        let (Ok(prolog_off), Ok(b1)) = (
            reader.u8(base, "UNWIND_CODE CodeOffset"),
            reader.u8(base + 1, "UNWIND_CODE 操作"),
        ) else {
            notes.push(format!("展开码在槽位 {slot} 越界，截断"));
            truncated = true;
            break;
        };
        let opcode = b1 & 0x0F;
        let info = (b1 >> 4) & 0x0F;

        // 该操作消耗的槽位数（含自身）。CountOfCodes 把附加槽也数进去了，
        // 遍历时必须跟着跳过，否则会把附加数据当成独立操作码。
        // 默认 1（push/setfpreg/alloc_small/machineframe 等不占附加槽）。
        let mut slots = 1usize;
        let mut extra = None;
        // 附加数据读取：从后续槽位读（2 字节 / 4 字节）。
        let next_slot = base + 2;
        match opcode {
            // ALLOC_LARGE：OpInfo=0 → 下 1 槽、以 8 字节为单位的大小；
            // OpInfo=1 → 下 2 槽、未缩放的 32 位字节数。
            1 => {
                slots = if info == 1 { 3 } else { 2 };
                let size = if info == 1 {
                    // OpInfo=1：后两个槽组成未缩放的 32 位字节数。
                    reader.u32(next_slot, Endianness::Little, "ALLOC_LARGE 大小")
                } else {
                    // OpInfo=0：下一个槽是以 8 字节为单位的缩放值。
                    reader
                        .u16(next_slot, Endianness::Little, "ALLOC_LARGE 大小")
                        .map(|scaled| u32::from(scaled) * 8)
                };
                match size {
                    Ok(s) => extra = Some(s),
                    Err(_) => {
                        notes.push("ALLOC_LARGE 的大小越界，该项按 0 处理".to_string());
                        extra = Some(0);
                    }
                }
            }
            // SAVE_NONVOL：下 1 槽 = 缩放偏移（×8）
            4 => {
                slots = 2;
                extra = reader
                    .u16(next_slot, Endianness::Little, "SAVE_NONVOL 偏移")
                    .ok()
                    .map(u32::from);
            }
            // SAVE_NONVOL_FAR：下 2 槽 = 32 位偏移
            5 => {
                slots = 3;
                extra = reader
                    .u32(next_slot, Endianness::Little, "SAVE_NONVOL_FAR 偏移")
                    .ok();
            }
            // SAVE_XMM128：下 1 槽 = 缩放偏移（×16，128 位对齐）
            //
            // # 操作码编号为什么是 8 而不是 6
            //
            // 微软 PE/COFF 规范的真实定义：0=PUSH_NONVOL、1=ALLOC_LARGE、
            // 2=ALLOC_SMALL、3=SET_FPREG、4=SAVE_NONVOL、5=SAVE_NONVOL_FAR、
            // **6/7 = 保留（x64 上非法）**、8=SAVE_XMM128、9=SAVE_XMM128_FAR、
            // 0xA=PUSH_MACHFRAME。
            //
            // 第一版把 6/7 当 XMM、8 当 MACHFRAME —— 表错了一位，单独的
            // MinGW fixture 上 push/alloc 仍然全对（它们只用 0–5），测试
            // 全绿；上 ntdll 一跑，几十个函数的 XMM 保存被解成 MACHFRAME
            // 或"未识别 0xa"，帧大小与保存列表整体失真。教训：操作码表
            // 的冷门分支必须有一个真实系统二进制当参照。
            8 => {
                slots = 2;
                extra = reader
                    .u16(next_slot, Endianness::Little, "SAVE_XMM128 偏移")
                    .ok()
                    .map(|scaled| u32::from(scaled) * 16);
            }
            // SAVE_XMM128_FAR：下 2 槽 = 32 位偏移
            9 => {
                slots = 3;
                extra = reader
                    .u32(next_slot, Endianness::Little, "SAVE_XMM128_FAR 偏移")
                    .ok();
            }
            _ => {}
        }

        raw.push(RawOp {
            opcode,
            info,
            prolog_off,
            extra,
        });
        slot += slots;
        if slot > count_of_codes as usize {
            notes.push("展开码消耗槽位越过 CountOfCodes，截断".to_string());
            truncated = true;
            break;
        }
    }
    if truncated && raw.is_empty() {
        // 一条都没解出来：返回带说明的骨架，而不是空着
        return Some(PeUnwindInfo {
            version,
            flags,
            prologue_size,
            frame_register,
            frame_offset,
            ops: Vec::new(),
            notes,
        });
    }

    // ── 按前导顺序重排 ──
    //
    // PE/COFF 规定展开码在数组里按**前导偏移递减**排列（最后一条前导
    // 指令排在最前）。这不是笔误，是规范：规范说 "the unwind codes are
    // ordered in the array in descending order of prolog offset"。
    //
    // 后果很实际：直接按数组顺序处理，保存寄存器列表会是反的，而且
    // **push 的栈槽位置会全部算错**（槽位依赖"这个 push 在序列中的
    // 位置"）。真实 MinGW PE 上第一版就是这样：8 个 push 解出来的
    // 顺序恰好与反汇编相反。
    //
    // 排序而不是 `reverse()`：规范保证的是递减，但排序对"顺序本来
    // 就乱"的畸形输入也成立，且结果可预测。
    raw.sort_by_key(|r| r.prolog_off);

    // 帧大小（只累计确定占栈的：push / alloc / machineframe）
    let frame_size: u64 = raw
        .iter()
        .map(|r| match r.opcode {
            0 => 8,                                // PUSH_NONVOL
            1 => u64::from(r.extra.unwrap_or(0)),  // ALLOC_LARGE
            2 => u64::from(r.info as u32 + 1) * 8, // ALLOC_SMALL
            8 => {
                // PUSH_MACHFRAME：x64 机器帧 0x28/帧
                u64::from(r.info as u32 + 1) * 0x28
            }
            _ => 0,
        })
        .sum();

    // 第二遍：按序组装操作，push 的槽位用"总帧大小 − 该点已累计"定位
    let mut ops = Vec::new();
    let mut accum: u64 = 0;
    for r in &raw {
        match r.opcode {
            0 => {
                // PUSH_NONVOL
                let reg = x64_reg_name(r.info)
                    .map(str::to_string)
                    .unwrap_or_else(|| format!("reg{}", r.info));
                // 该 push 之后累计 = accum + 8；槽位距最终 RSP = T − (accum+8)
                let after = accum + 8;
                let slot_from_top = frame_size.saturating_sub(after);
                ops.push(PeUnwindOp::PushNonVolatile { reg, slot_from_top });
                accum = after;
            }
            1 => {
                // ALLOC_LARGE
                if let Some(size) = r.extra {
                    ops.push(PeUnwindOp::Alloc { size });
                    accum += u64::from(size);
                }
            }
            2 => {
                // ALLOC_SMALL
                let size = u32::from(r.info) + 1;
                ops.push(PeUnwindOp::Alloc { size: size * 8 });
                accum += u64::from(size) * 8;
            }
            3 => {
                // SET_FPREG（FrameRegister 字段已给出）
                let reg = x64_reg_name(r.info).map(str::to_string);
                if let Some(reg) = reg {
                    ops.push(PeUnwindOp::SetFramePointer { reg });
                }
            }
            4 => {
                // SAVE_NONVOL
                let reg = x64_reg_name(r.info).map(str::to_string);
                if let (Some(reg), Some(scaled)) = (reg, r.extra) {
                    ops.push(PeUnwindOp::SaveNonVolatile {
                        reg,
                        scaled_offset: scaled,
                    });
                }
            }
            5 => {
                // SAVE_NONVOL_FAR
                let reg = x64_reg_name(r.info).map(str::to_string);
                if let (Some(reg), Some(offset)) = (reg, r.extra) {
                    ops.push(PeUnwindOp::SaveNonVolatileFar { reg, offset });
                }
            }
            8 | 9 => {
                // SAVE_XMM128[_FAR]：记录但不计入帧大小
                //
                // 这里的编号是 **XMM** 寄存器编号，不是 GP 寄存器编号。
                // 拿 GP 表（rax..r15）翻译会把 xmm0 写成 "rax"、xmm6 写成
                // "rsi"。操作码编号见上面槽位循环里的说明（8/9，不是 6/7）。
                let reg = format!("xmm{}", r.info);
                let offset = r.extra.unwrap_or(0);
                ops.push(PeUnwindOp::SaveXmm { reg, offset });
            }
            0xA => {
                // PUSH_MACHFRAME：info=0 → 0x28（机器帧），info=1 → 再加
                // 8 字节错误码。规范里 info 只有这两种取值。
                let size = u32::from(r.info) + 1;
                ops.push(PeUnwindOp::PushMachineFrame { size: size * 0x28 });
                accum += u64::from(size) * 0x28;
            }
            6 | 7 => {
                // x64 上保留的操作码：按规范不该出现。如实记为未识别，
                // 不猜语义 —— 见 CLAUDE.md §7。
                ops.push(PeUnwindOp::Unknown {
                    opcode: r.opcode,
                    info: r.info,
                    prolog_offset: r.prolog_off,
                });
                notes.push(format!(
                    "展开码 {}（保留值，x64 上非法；info={:#x}，前导偏移 {:#x}）未识别",
                    r.opcode, r.info, r.prolog_off
                ));
            }
            other => {
                ops.push(PeUnwindOp::Unknown {
                    opcode: other,
                    info: r.info,
                    prolog_offset: r.prolog_off,
                });
                notes.push(format!(
                    "展开码 {other:#x}（info={:#x}，前导偏移 {:#x}）未识别",
                    r.info, r.prolog_off
                ));
            }
        }
    }

    if ops.iter().any(|o| matches!(o, PeUnwindOp::SaveXmm { .. })) {
        notes.push("存在 XMM 保存，其栈占用未计入帧大小（浮点寄存器宽度未做假设）".to_string());
    }

    Some(PeUnwindInfo {
        version,
        flags,
        prologue_size,
        frame_register,
        frame_offset,
        ops,
        notes,
    })
}

/// x64 展开码里寄存器编号 → 名字（0-15）。
fn x64_reg_name(n: u8) -> Option<&'static str> {
    match n {
        0 => Some("rax"),
        1 => Some("rcx"),
        2 => Some("rdx"),
        3 => Some("rbx"),
        4 => Some("rsp"),
        5 => Some("rbp"),
        6 => Some("rsi"),
        7 => Some("rdi"),
        8 => Some("r8"),
        9 => Some("r9"),
        10 => Some("r10"),
        11 => Some("r11"),
        12 => Some("r12"),
        13 => Some("r13"),
        14 => Some("r14"),
        15 => Some("r15"),
        _ => None,
    }
}
