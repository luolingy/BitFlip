//! `info`：只做识别，不启动服务。

use std::path::Path;

use anyhow::Context;
use bitflip_core::{OpenOptions, Session, TargetInfo};

/// 打印目标识别结论。`json` 时输出稳定的 wire 契约（供脚本消费）。
pub fn run_info(target: &Path, json: bool, verbose: bool) -> anyhow::Result<()> {
    crate::tracing_setup::init(verbose);

    let session = Session::open(target, OpenOptions::default())?;

    if json {
        let text = serde_json::to_string_pretty(session.info()).context("序列化识别结论失败")?;
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
