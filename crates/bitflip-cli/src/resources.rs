//! `bitflip-cli resources`：看 APK 资源表（M3 第二、三片）。
//!
//! 与 `manifest` 同一族：子命令按**主题**命名（资源表），不按容器命名。
//! 三个出口共用**同一次解析**：摘要（默认）、稳定的 wire JSON（`--json`）、
//! 单条值查询（`--lookup ID`，第三片）。
//!
//! # 结构与值的边界
//!
//! 默认与 `--json` 出口只报**结构**（包/类型/配置/条目计数）——`@7f0d0001`
//! 对应的具体字符串/颜色在这里**不出现**，摘要末尾写明这一点。要查值用
//! `--lookup`：那是专门的出口，返回名字 + 值（库已解成可读文本）。

use anyhow::Result;

use crate::cli::ResourcesArgs;

/// 跑 `resources` 子命令：解析一次，按开关打印摘要 / JSON / 单条查询。
///
/// # Errors
///
/// 打开目标失败、目标里没有资源表、资源表解析不了、或 `--lookup` 的 id
/// 写得不是资源 id —— 都带着**具体原因**返回。
pub fn run_resources(args: &ResourcesArgs) -> Result<()> {
    let session = bitflip_core::Session::open(&args.target, args.raw.to_open_options()?)?;

    // 单条查询走**带值层**的表；整表快照不需要它（快照本来就不含值）。
    // 两个出口互斥：一个是"整张表长什么样"，一个是"这一条是什么"，混在
    // 一个输出里两者都会失真。
    if let Some(wanted) = args.lookup.as_deref() {
        let report =
            bitflip_core::resources::lookup_resource(&session, args.member.as_deref(), wanted)?;
        let text = serde_json::to_string_pretty(&report)?;
        print!("{text}");
        if !text.ends_with('\n') {
            println!();
        }
        return Ok(());
    }

    let report = bitflip_core::resources::read_resources(&session, args.member.as_deref())?;

    let text = if args.json {
        json(&report)
    } else {
        summary(&report)
    };
    print!("{text}");
    if !text.ends_with('\n') {
        println!();
    }
    Ok(())
}

/// 给人看的摘要。
fn summary(report: &bitflip_core::resources::ResourcesReport) -> String {
    let mut out = String::new();
    out.push_str(&format!(
        "资源表：{}（{} 字节）\n",
        report.member.as_deref().unwrap_or("（单文件目标）"),
        report.size
    ));
    out.push_str(&report.headline());
    out.push('\n');
    for package in &report.structure.packages {
        out.push_str(&format!(
            "包 {:#04x} {}：类型字符串 {} 条 / 键字符串 {} 条 / {} 种配置\n",
            package.package_id,
            package.name,
            package.type_strings,
            package.key_strings,
            package.config_count
        ));
        // 类型名按 type_id 去重后列出（同一类型会在多种配置里重复出现；
        // 摘要只关心"这个包里有哪些资源种类"）。解不出名字的类型如实写
        // `类型#id`，不编名字。
        let mut seen: Vec<(u8, Option<String>)> = Vec::new();
        for config in &package.configs {
            for ty in &config.types {
                if !seen.iter().any(|(id, _)| *id == ty.type_id) {
                    seen.push((ty.type_id, ty.type_name.clone()));
                }
            }
        }
        seen.sort_by_key(|(id, _)| *id);
        let names: Vec<String> = seen
            .iter()
            .map(|(id, name)| match name {
                Some(text) => text.clone(),
                None => format!("类型#{id}（池里解不出）"),
            })
            .collect();
        out.push_str(&format!(
            "  类型（{} 种）：{}\n",
            names.len(),
            names.join("、")
        ));
    }
    out.push_str(
        "说明：这是结构快照 —— 不含资源值；查某一条资源用 `resources <TARGET> --lookup 0x7f...`\n",
    );
    out
}

/// 稳定的 wire JSON（键名与字段顺序固定，前端与脚本按它写）。
fn json(report: &bitflip_core::resources::ResourcesReport) -> String {
    let payload = serde_json::json!({
        "format_version": 1,
        "member": report.member,
        "size": report.size,
        "structure": report.structure,
    });
    serde_json::to_string_pretty(&payload).unwrap_or_else(|_| "{}".to_string())
}
