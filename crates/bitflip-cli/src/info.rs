//! `info`：只做识别与结构解析，不启动服务。

use std::path::Path;

use anyhow::Context;
use bitflip_core::{ObjectInfo, OpenOptions, Session, TargetInfo};

/// 打印目标识别结论。`json` 时输出稳定的 wire 契约（供脚本消费）。
pub fn run_info(target: &Path, json: bool, verbose: bool) -> anyhow::Result<()> {
    crate::tracing_setup::init(verbose);

    let session = Session::open(target, OpenOptions::default())?;

    if json {
        // JSON 模式输出完整解析结果（含 format_version），供脚本消费
        let payload = serde_json::json!({
            "format_version": session.info().format_version,
            "target": session.info(),
            "parsed": session.parsed(),
        });
        let text = serde_json::to_string_pretty(&payload).context("序列化识别结论失败")?;
        println!("{text}");
        return Ok(());
    }

    print_human(session.info(), &session);

    if session.info().object == "raw" {
        println!();
        println!("提示  未识别出容器/对象格式。原始二进制的基址与架构需要手工指定（计划：M2）。");
    }

    Ok(())
}

fn print_human(info: &TargetInfo, session: &Session) {
    println!("{}", info.summary);
    println!();
    println!("路径      {}", info.path);
    println!("大小      {} 字节", info.file_size);
    println!("容器      {} ({})", info.container_label, info.container);
    println!("对象      {} ({})", info.object_label, info.object);
    if let Some(kind) = &info.member_kind {
        println!("成员格式  {kind}");
    }
    println!("架构      {}", info.arch.as_deref().unwrap_or("未识别"));
    println!(
        "位宽      {}",
        if info.bits == 0 {
            "未识别".to_string()
        } else {
            format!("{} 位", info.bits)
        }
    );
    println!("端序      {}", info.endian.as_deref().unwrap_or("未识别"));
    println!("入口      {}", info.entry.as_deref().unwrap_or("-"));
    println!("镜像基址  {}", info.image_base.as_deref().unwrap_or("-"));
    println!(
        "节数      {}",
        info.sections.map_or("-".to_string(), |s| s.to_string())
    );
    if info.member_count > 0 {
        println!(
            "成员数    {}{}",
            info.member_count,
            if info.members_truncated {
                "+（已截断）"
            } else {
                ""
            }
        );
    }

    // ── 解析结果 ──
    if let Some(parsed) = session.parsed() {
        print_parsed(parsed);
    } else {
        println!();
        println!("解析      未产生结构结果（原因见下方说明）");
    }

    if !info.notes.is_empty() {
        println!();
        println!("说明");
        for note in &info.notes {
            println!("  · {note}");
        }
    }

    let members = session.guess().members.as_slice();
    if !members.is_empty() {
        println!();
        println!("归档成员（最多显示 20 个）");
        for member in members.iter().take(20) {
            println!(
                "  {:>10} 字节  偏移 {:#010x}  {}{}",
                member.size,
                member.offset,
                member.name,
                if member.truncated {
                    "（超出嗅探窗口）"
                } else {
                    ""
                }
            );
        }
        if members.len() > 20 {
            println!("  … 其余 {} 个未显示", members.len() - 20);
        }
    }
}

/// 打印解析结果：段、节、各表的计数与降级说明。
fn print_parsed(parsed: &ObjectInfo) {
    if let Some(kind) = &parsed.format_type {
        println!("格式      {kind}");
    }
    if let Some(abi) = &parsed.os_abi {
        println!("目标      {abi}");
    }
    if let Some(subsystem) = &parsed.subsystem {
        println!("子系统    {subsystem}");
    }

    // 段（内存视角）—— 分析走地址空间，这是权威视图
    if !parsed.segments.is_empty() {
        println!();
        println!("段（内存视角，共 {} 个）", parsed.segments.len());
        println!(
            "  {:<20} {:<18} {:<12} {:<6} 类别",
            "名称", "虚拟地址", "大小", "权限"
        );
        for segment in parsed.segments.iter().take(40) {
            println!(
                "  {:<20} 0x{:<16} 0x{:<10x} {:<6} {}",
                truncate(&segment.name, 20),
                segment.vaddr,
                segment.vsize,
                segment.perms,
                segment.kind_label
            );
        }
        if parsed.segments.len() > 40 {
            println!("  … 其余 {} 个未显示", parsed.segments.len() - 40);
        }
    }

    // 节（文件视角）
    if !parsed.sections.is_empty() {
        println!();
        println!("节（文件视角，共 {} 个）", parsed.sections.len());
        println!(
            "  {:<20} {:<18} {:<12} {:<10} {:<6} 类别",
            "名称", "虚拟地址", "文件偏移", "大小", "权限"
        );
        for section in parsed.sections.iter().take(40) {
            println!(
                "  {:<20} 0x{:<16} 0x{:<10x} 0x{:<8x} {:<6} {}",
                truncate(&section.name, 20),
                section.vaddr,
                section.file_offset,
                section.file_size,
                section.perms,
                section.kind_label
            );
        }
        if parsed.sections.len() > 40 {
            println!("  … 其余 {} 个未显示", parsed.sections.len() - 40);
        }
    }

    // 各表计数
    let mut stats: Vec<String> = Vec::new();
    if !parsed.imports.is_empty() {
        stats.push(format!("导入 {}", parsed.imports.len()));
    }
    if !parsed.exports.is_empty() {
        stats.push(format!("导出 {}", parsed.exports.len()));
    }
    if !parsed.symbols.is_empty() {
        stats.push(format!("符号 {}", parsed.symbols.len()));
    }
    if !parsed.relocations.is_empty() {
        stats.push(format!("重定位 {}", parsed.relocations.len()));
    }
    if !stats.is_empty() {
        println!();
        println!("表        {}", stats.join("，"));
    }

    // 依赖模块（去重）
    if !parsed.imports.is_empty() {
        let mut modules: Vec<&str> = parsed.imports.iter().map(|i| i.module.as_str()).collect();
        modules.sort_unstable();
        modules.dedup();
        println!();
        println!("依赖模块（{} 个）", modules.len());
        for module in modules.iter().take(30) {
            let count = parsed
                .imports
                .iter()
                .filter(|import| import.module == *module)
                .count();
            if count > 1 {
                println!("  {module}（{count} 个符号）");
            } else {
                println!("  {module}");
            }
        }
        if modules.len() > 30 {
            println!("  … 其余 {} 个未显示", modules.len() - 30);
        }
    }

    // 导出
    if !parsed.exports.is_empty() {
        println!();
        println!("导出（最多显示 30 个）");
        for export in parsed.exports.iter().take(30) {
            let suffix = export
                .forwarder
                .as_ref()
                .map_or_else(String::new, |forwarder| format!(" -> {forwarder}"));
            println!("  0x{}  {}{}", export.address, export.name, suffix);
        }
        if parsed.exports.len() > 30 {
            println!("  … 其余 {} 个未显示", parsed.exports.len() - 30);
        }
    }

    // 解析器自己的降级说明
    if !parsed.notes.is_empty() {
        println!();
        println!("结构说明");
        for note in &parsed.notes {
            println!("  · {note}");
        }
    }
}

/// 按显示宽度截断（非 ASCII 按 2 宽度估算，避免中英混排时表格错位）。
fn truncate(text: &str, max: usize) -> String {
    let mut width = 0;
    let mut out = String::new();
    for ch in text.chars() {
        let char_width = if ch.is_ascii() { 1 } else { 2 };
        if width + char_width > max {
            out.push('…');
            return out;
        }
        width += char_width;
        out.push(ch);
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    fn write_elf(dir: &Path) -> PathBuf {
        let mut bytes = vec![0u8; 64];
        bytes[..4].copy_from_slice(b"\x7fELF");
        bytes[4] = 2;
        bytes[5] = 1;
        bytes[6] = 1;
        bytes[16..18].copy_from_slice(&2u16.to_le_bytes());
        bytes[18..20].copy_from_slice(&62u16.to_le_bytes());
        bytes[24..32].copy_from_slice(&0x401000u64.to_le_bytes());
        bytes[60..62].copy_from_slice(&5u16.to_le_bytes());
        let path = dir.join("sample.elf");
        std::fs::write(&path, bytes).expect("写入样本");
        path
    }

    #[test]
    fn json_and_human_modes_both_succeed() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = write_elf(dir.path());

        run_info(&path, true, false).expect("json 模式");
        run_info(&path, false, false).expect("人类可读模式");
    }

    #[test]
    fn info_on_missing_file_reports_load_error() {
        let error = run_info(Path::new("nope.dll"), false, false).expect_err("应失败");
        assert!(error.to_string().contains("读取目标失败"));
    }
}
