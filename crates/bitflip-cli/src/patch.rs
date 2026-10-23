//! `patch`：预览补丁计划（只读）或写出 `.patched` 副本（需显式 `--apply`）。
//!
//! 安全语义与 `bitflip-patch` 一致：**默认只读**，`--apply` 是那次"显式解锁"。
//! 即使 `--apply`，也只写 `xxx.patched` 副本，原文件在磁盘上始终不动。

use std::path::Path;

use anyhow::{bail, Context};
use bitflip_patch::{PatchError, PatchPlan, PatchTarget};

use crate::cli::PatchArgs;

/// 一条解析好的改动：`(虚拟地址, 新字节)`。
type Edit = (u64, Vec<u8>);

pub fn run_patch(args: &PatchArgs) -> anyhow::Result<()> {
    // `--raw` 覆盖（架构/基址）对打补丁没有意义：这里拿到的是**真实文件的结构**，
    // 不是从固件里猜出来的裸二进制。给了就直接说清楚，免得用户以为它生效了。
    if args.raw.arch.is_some() || args.raw.base.is_some() || args.raw.mode.is_some() {
        bail!("`patch` 不接受 `--arch/--base/--mode`：打补丁依据目标自身的段/偏移，不猜架构");
    }
    if args.edit.is_empty() {
        bail!("没有改动：用 `--edit 地址=十六进制字节` 至少给一处（例如 `--edit 0x401000=9090`）");
    }

    let edits = parse_edits(&args.edit)?;
    let target =
        PatchTarget::open(&args.target).map_err(|error| open_error(&args.target, &error))?;

    // 生成计划（零副作用）。被拒的改动在 `plan` 里就返回错误，不会走到写盘。
    let plan = target
        .plan(&edits)
        .map_err(|error| plan_error(&args.target, &error))?;

    if args.json {
        return print_json(&target, &plan, args.apply);
    }

    // 人类可读：先打印计划 diff。
    print_plan(&target, &plan);

    if !args.apply {
        println!();
        println!("（只读预览：未写盘。确认无误后加 `--apply` 写出副本。）");
        return Ok(());
    }

    // `--apply` 就是那次显式解锁。
    let mut target = target;
    target.unlock();
    let report = target.apply(&plan).map_err(|error| apply_error(&error))?;
    println!();
    println!("已写出副本  {}", report.copy_path.display());
    println!(
        "改动        {} 字节 · 段 {}",
        report.changed_bytes,
        if report.segments.is_empty() {
            "（无）".to_string()
        } else {
            report.segments.join("、")
        }
    );
    println!(
        "大小        {} → {} 字节（{}）",
        report.size_before,
        report.size_after,
        if report.size_before == report.size_after {
            "等长替换，未变"
        } else {
            "变了！"
        }
    );
    println!("原文件      {}（未改动）", args.target.display());
    Ok(())
}

/// 把 `地址=十六进制` 解析成 `(u64, Vec<u8>)`。地址可带 `0x`；十六进制须偶数位。
fn parse_edits(raw: &[String]) -> anyhow::Result<Vec<Edit>> {
    let mut edits = Vec::with_capacity(raw.len());
    for (index, text) in raw.iter().enumerate() {
        let (addr_text, hex_text) = text.split_once('=').with_context(|| {
            format!(
                "第 {} 处改动 {text:?} 格式不对：应为 `地址=十六进制字节`",
                index + 1
            )
        })?;
        let addr_text = addr_text.trim();
        let addr_clean = addr_text
            .strip_prefix("0x")
            .or_else(|| addr_text.strip_prefix("0X"))
            .unwrap_or(addr_text);
        let vaddr = u64::from_str_radix(addr_clean, 16).with_context(|| {
            format!(
                "第 {} 处改动的地址 {addr_text:?} 不是合法十六进制",
                index + 1
            )
        })?;
        let bytes = parse_hex_bytes(hex_text.trim()).with_context(|| {
            format!(
                "第 {} 处改动的字节 {hex_text:?} 不是合法十六进制",
                index + 1
            )
        })?;
        if bytes.is_empty() {
            bail!("第 {} 处改动 {text:?} 的新字节为空", index + 1);
        }
        edits.push((vaddr, bytes));
    }
    Ok(edits)
}

/// `"9090"` → `[0x90, 0x90]`。要求偶数位、只含十六进制字符。
fn parse_hex_bytes(text: &str) -> anyhow::Result<Vec<u8>> {
    let digits: Vec<char> = text.chars().filter(|c| !c.is_whitespace()).collect();
    if digits.is_empty() {
        bail!("字节为空");
    }
    if !digits.len().is_multiple_of(2) {
        bail!(
            "十六进制字节必须是偶数位（每个字节两位），实际 {} 位",
            digits.len()
        );
    }
    let mut out = Vec::with_capacity(digits.len() / 2);
    let mut i = 0;
    while i < digits.len() {
        let pair: String = [digits[i], digits[i + 1]].iter().collect();
        let byte =
            u8::from_str_radix(&pair, 16).with_context(|| format!("不是合法十六进制：{pair:?}"))?;
        out.push(byte);
        i += 2;
    }
    Ok(out)
}

fn hex_bytes(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        out.push_str(&format!("{byte:02x}"));
    }
    out
}

fn print_plan(target: &PatchTarget, plan: &PatchPlan) {
    println!("目标        {}", target.path().display());
    println!(
        "格式        {}{}",
        target.kind().as_str(),
        if target.is_unlocked() {
            "（已解锁）"
        } else {
            ""
        },
    );
    println!("副本        {}", plan.copy_path.display());
    println!(
        "改动        {} 处 · {} 字节 · 段 {}",
        plan.sites.len(),
        plan.changed_bytes(),
        if plan.touched_segments().is_empty() {
            "（无）".to_string()
        } else {
            plan.touched_segments().join("、")
        }
    );
    println!();
    println!(
        "  {:<20} {:<12} {:<6} {:<10} {:<10} 段",
        "虚拟地址", "文件偏移", "长度", "原字节", "新字节"
    );
    for site in &plan.sites {
        println!(
            "  0x{:<18x} 0x{:<10x} {:<6} {:<10} {:<10} {}",
            site.vaddr,
            site.file_offset,
            site.new.len(),
            hex_bytes(&site.original),
            hex_bytes(&site.new),
            site.segment.as_deref().unwrap_or("（段外）"),
        );
    }
}

fn print_json(target: &PatchTarget, plan: &PatchPlan, apply: bool) -> anyhow::Result<()> {
    let sites: Vec<serde_json::Value> = plan
        .sites
        .iter()
        .map(|site| {
            serde_json::json!({
                "vaddr": format!("{:#018x}", site.vaddr),
                "file_offset": site.file_offset,
                "original": hex_bytes(&site.original),
                "new": hex_bytes(&site.new),
                "segment": site.segment,
            })
        })
        .collect();
    let payload = serde_json::json!({
        "target": target.path().to_string_lossy(),
        "kind": target.kind().as_str(),
        "copy_path": plan.copy_path.to_string_lossy(),
        "changed_bytes": plan.changed_bytes(),
        "segments": plan.touched_segments(),
        "sites": sites,
        // 只读预览时明确写"没有写盘"；`--apply` 的实际写在人类模式里给，这里只要契约。
        "apply_requested": apply,
        "written": false,
    });
    let text = serde_json::to_string_pretty(&payload).context("序列化补丁计划失败")?;
    println!("{text}");
    Ok(())
}

fn open_error(path: &Path, error: &PatchError) -> anyhow::Error {
    anyhow::anyhow!("打开目标 {} 失败：{error}", path.display())
}

fn plan_error(path: &Path, error: &PatchError) -> anyhow::Error {
    anyhow::anyhow!("为 {} 生成补丁计划被拒：{error}", path.display())
}

fn apply_error(error: &PatchError) -> anyhow::Error {
    anyhow::anyhow!("写补丁副本失败：{error}")
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cli::RawOverrideArgs;
    use std::path::PathBuf;

    #[test]
    fn parse_hex_bytes_accepts_even_digits() {
        assert_eq!(parse_hex_bytes("9090").unwrap(), vec![0x90, 0x90]);
        assert_eq!(parse_hex_bytes("90 90").unwrap(), vec![0x90, 0x90]);
        assert_eq!(parse_hex_bytes("c3").unwrap(), vec![0xc3]);
    }

    #[test]
    fn parse_hex_bytes_rejects_odd_and_bad() {
        assert!(parse_hex_bytes("909").is_err(), "奇数位应被拒");
        assert!(parse_hex_bytes("zz").is_err(), "非十六进制应被拒");
        assert!(parse_hex_bytes("").is_err(), "空应被拒");
    }

    #[test]
    fn parse_edits_parses_addr_and_hex() {
        let edits = parse_edits(&["0x401000=9090".to_string(), "0X401002=c3".to_string()]).unwrap();
        assert_eq!(edits.len(), 2);
        assert_eq!(edits[0], (0x401000, vec![0x90, 0x90]));
        assert_eq!(edits[1], (0x401002, vec![0xc3]));
    }

    #[test]
    fn parse_edits_rejects_missing_separator_and_empty_bytes() {
        assert!(parse_edits(&["401000=90".to_string()]).is_ok());
        assert!(parse_edits(&["nope".to_string()]).is_err(), "缺 `=` 应被拒");
        assert!(
            parse_edits(&["0x401000=".to_string()]).is_err(),
            "空字节应被拒"
        );
        assert!(
            parse_edits(&["0xZZ=90".to_string()]).is_err(),
            "非法地址应被拒"
        );
    }

    /// 手拼一个最小 ELF64 可执行文件（一个 PT_LOAD，文件 0x1000 起 0x100 字节填 0xAA）。
    /// 字段照 ELF 规范拼（§6.11）；与 patch crate 测试里的样本同构。
    fn minimal_elf64_exec() -> Vec<u8> {
        let mut bytes = vec![0u8; 0x1100];
        bytes[0..4].copy_from_slice(b"\x7fELF");
        bytes[4] = 2;
        bytes[5] = 1;
        bytes[6] = 1;
        bytes[16..18].copy_from_slice(&2u16.to_le_bytes()); // ET_EXEC
        bytes[18..20].copy_from_slice(&62u16.to_le_bytes()); // x86_64
        bytes[20..24].copy_from_slice(&1u32.to_le_bytes());
        bytes[24..32].copy_from_slice(&0x401000u64.to_le_bytes()); // entry
        bytes[32..40].copy_from_slice(&0x40u64.to_le_bytes()); // phoff
        bytes[52..54].copy_from_slice(&64u16.to_le_bytes());
        bytes[54..56].copy_from_slice(&56u16.to_le_bytes());
        bytes[56..58].copy_from_slice(&1u16.to_le_bytes()); // phnum
        let ph = 0x40;
        bytes[ph..ph + 4].copy_from_slice(&1u32.to_le_bytes()); // PT_LOAD
        bytes[ph + 4..ph + 8].copy_from_slice(&5u32.to_le_bytes()); // R|X
        bytes[ph + 8..ph + 16].copy_from_slice(&0x1000u64.to_le_bytes()); // offset
        bytes[ph + 16..ph + 24].copy_from_slice(&0x401000u64.to_le_bytes()); // vaddr
        bytes[ph + 24..ph + 32].copy_from_slice(&0x401000u64.to_le_bytes()); // paddr
        bytes[ph + 32..ph + 40].copy_from_slice(&0x100u64.to_le_bytes()); // filesz
        bytes[ph + 40..ph + 48].copy_from_slice(&0x100u64.to_le_bytes()); // memsz
        bytes[ph + 48..ph + 56].copy_from_slice(&0x1000u64.to_le_bytes()); // align
        for byte in &mut bytes[0x1000..0x1100] {
            *byte = 0xAA;
        }
        bytes
    }

    fn write_elf(dir: &Path) -> PathBuf {
        let path = dir.join("sample.elf");
        std::fs::write(&path, minimal_elf64_exec()).expect("写入样本");
        path
    }

    fn args_for(target: PathBuf, edits: Vec<&str>, apply: bool, json: bool) -> PatchArgs {
        PatchArgs {
            target,
            edit: edits.into_iter().map(str::to_string).collect(),
            apply,
            json,
            raw: RawOverrideArgs::default(),
        }
    }

    #[test]
    fn plan_then_apply_writes_copy_and_leaves_original() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = write_elf(dir.path());
        let before = std::fs::read(&path).expect("读原文件");

        // 只读预览：不写盘。
        run_patch(&args_for(path.clone(), vec!["0x401000=9090"], false, false)).expect("预览");
        assert!(
            !dir.path().join("sample.elf.patched").exists(),
            "预览不该写副本"
        );

        // --apply：写出副本，原文件不变。
        run_patch(&args_for(path.clone(), vec!["0x401000=9090"], true, false)).expect("apply");
        let copy = dir.path().join("sample.elf.patched");
        assert!(copy.exists(), "--apply 应当写出副本");

        let after = std::fs::read(&path).expect("再读原文件");
        assert_eq!(before, after, "原文件必须不变");

        let patched = std::fs::read(&copy).expect("读副本");
        assert_eq!(&patched[0x1000..0x1002], &[0x90, 0x90], "副本应被改");
        assert_eq!(&patched[0x1002..0x1100], &before[0x1002..0x1100]);
    }

    #[test]
    fn out_of_range_edit_is_rejected_before_writing() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = write_elf(dir.path());
        // 0x402000 不在任何段里。
        let err = run_patch(&args_for(path.clone(), vec!["0x402000=90"], true, false))
            .expect_err("越界应被拒");
        assert!(err.to_string().contains("被拒"), "{err}");
        assert!(
            !dir.path().join("sample.elf.patched").exists(),
            "被拒时不该写副本"
        );
    }

    #[test]
    fn json_mode_outputs_contract() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = write_elf(dir.path());
        // 只要不 panic 就算过（输出到 stdout，内容由集成层验证稳定性）。
        run_patch(&args_for(path, vec!["0x401000=9090"], false, true)).expect("json");
    }

    #[test]
    fn empty_edit_list_is_rejected() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = write_elf(dir.path());
        let err = run_patch(&args_for(path, vec![], false, false)).expect_err("无改动应报错");
        assert!(err.to_string().contains("没有改动"), "{err}");
    }
}
