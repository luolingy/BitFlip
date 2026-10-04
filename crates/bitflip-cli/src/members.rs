//! M5 归档成员与符号定位的三个无头子命令。
//!
//! 这三个命令存在的理由是同一条：**归档容器本身不可分析**。
//! `bitflip libfoo.a` 只能告诉你"这是个有 N 个成员的归档"，
//! 真正想看的函数在成员里。所以 M5 要求"成员选择与符号定位在 CLI 与 UI
//! 里都能用"—— 这里就是 CLI 那一半。
//!
//! 三个命令的分工：
//!
//! * `members`  —— 列出成员（名字、大小、偏移、格式）；
//! * `functions` —— 列出函数，可用 `--member` 缩到单个成员；
//! * `symbol`   —— 反向：给一个名字或地址，告诉你在**哪个成员**里。
//!
//! `symbol` 是"符号定位"的关键：跨成员重名是常态（每个 `.o` 都可能有个
//! `init`），所以答案必须带上成员名，否则用户拿着地址也不知道去哪看。

use anyhow::Context;
use bitflip_core::{ArchiveMember, OpenOptions, Session};
use serde_json::json;

use crate::cli::{FunctionsArgs, MembersArgs, SymbolArgs};

/// `members`：列出归档成员。
pub fn run_members(args: &MembersArgs) -> anyhow::Result<()> {
    crate::tracing_setup::init(args.verbose);

    // `members` 不需要架构/基址覆盖：归档自己带着成员格式，
    // 而"列成员"这一步不涉及解码。多给一组参数只会让人以为它们有用。
    let session = Session::open(&args.target, OpenOptions::default())?;
    let members = session.members();

    if args.json {
        let list: Vec<_> = members
            .iter()
            .map(|m| {
                json!({
                    "name": m.name,
                    "offset": m.offset,
                    "size": m.size,
                    // 逐成员的"内容未读全"标记。这是降级信息，
                    // 必须出现在输出里（CLAUDE.md §7）。
                    "truncated": m.truncated,
                })
            })
            .collect();
        let payload = json!({
            "format_version": session.info().format_version,
            "target": session.info().path,
            "container": session.info().container,
            "is_archive": session.info().is_archive(),
            "member_count": members.len(),
            "members_truncated": session.info().members_truncated,
            "members": list,
        });
        println!(
            "{}",
            serde_json::to_string_pretty(&payload).context("序列化成员列表失败")?
        );
        return Ok(());
    }

    if !session.info().is_archive() {
        // 不是归档时明确说清，而不是打印空列表 ——
        // "没有成员"和"这不是归档"对用户是两件事。
        println!(
            "{} 不是归档（容器 {}）：没有成员可列。",
            session.info().path,
            session.info().container_label
        );
        return Ok(());
    }

    println!(
        "{} —— {} 个成员{}",
        session.info().path,
        members.len(),
        if session.info().members_truncated {
            "（列表已截断）"
        } else {
            ""
        }
    );
    println!();
    println!("{:>10}  {:>12}  名字", "大小", "偏移");
    for member in members {
        println!(
            "{:>10}  {:#012x}  {}{}",
            member.size,
            member.offset,
            member.name,
            if member.truncated {
                "  （超出嗅探窗口，内容未完整读取）"
            } else {
                ""
            }
        );
    }

    if !session.info().notes.is_empty() {
        println!();
        println!("说明");
        for note in &session.info().notes {
            println!("  · {note}");
        }
    }
    Ok(())
}

/// `functions`：列出函数（可限定到单个成员）。
pub fn run_functions(args: &FunctionsArgs) -> anyhow::Result<()> {
    crate::tracing_setup::init(args.verbose);

    let opened = Session::open(&args.target, args.raw.to_open_options()?)?;

    // 归档必须指定成员：容器没有函数。这里**不**自动遍历所有成员 ——
    // 那会把几万个函数混在一起，而"这个函数来自哪个成员"这个信息
    // 一旦合并就丢了。宁可让用户挑一个。
    let (session, member_name) = match args.member.as_deref() {
        Some(name) => {
            let (member_session, member) = opened.member_session(name)?;
            (member_session, Some(member.name))
        }
        None => {
            if opened.info().is_archive() {
                anyhow::bail!(
                    "{} 是归档（{} 个成员）：容器本身没有函数。\
                     用 `--member <名字>` 指定成员，先用 `members` 子命令看有哪些成员。",
                    opened.info().path,
                    opened.members().len()
                );
            }
            (opened, None)
        }
    };

    let analysis = session
        .analysis(&session.detached_job())
        .context("建立目标分析")?;

    let from = match args.from.as_deref() {
        None => 0u64,
        Some(text) => bitflip_core::parse_address(text)
            .ok_or_else(|| anyhow::anyhow!("地址无法解析：{text:?}（十六进制，可带 0x 前缀）"))?,
    };

    let all: Vec<_> = analysis
        .functions()
        .iter()
        .filter(|f| bitflip_core::parse_address(&f.start).is_some_and(|addr| addr >= from))
        .collect();
    let total = all.len();

    if args.json {
        let list: Vec<_> = all
            .iter()
            .take(args.count)
            .map(|f| {
                json!({
                    "start": f.start,
                    "end": f.end,
                    "size": f.size,
                    "name": f.name,
                    // `named=false` 是**诚实的未知**：不是"函数叫这个名字"，
                    // 而是"我们知道这里有个函数，但不知道它叫什么"。
                    "named": f.named,
                    "source": f.source,
                })
            })
            .collect();
        let payload = json!({
            "format_version": bitflip_core::ANALYSIS_FORMAT_VERSION,
            "target": session.info().path,
            "member": member_name,
            "total": total,
            "returned": list.len(),
            "functions": list,
            "notes": analysis.notes(),
        });
        println!(
            "{}",
            serde_json::to_string_pretty(&payload).context("序列化函数列表失败")?
        );
        return Ok(());
    }

    if let Some(name) = &member_name {
        println!("成员    {name}");
    }
    println!("函数    {total} 个（显示前 {} 个）", args.count.min(total));
    println!();
    for f in all.iter().take(args.count) {
        // 未命名的函数如实显示为未命名 —— 绝不生成 `func_xxx` 占位名
        // （CLAUDE.md §7，也是参照实现的教训）。
        let label = if f.named {
            f.name.as_str()
        } else {
            "（未命名）"
        };
        // 大小未知时如实显示为未知 —— 不用 0 冒充
        // （`FunctionWire::size` 是 `Option`，正是为了这个）。
        let size = f
            .size
            .map_or_else(|| "大小未知".to_string(), |s| format!("{s:>6} 字节"));
        println!("  {}  {}  {}  [{}]", f.start, size, label, f.source);
    }
    if total > args.count {
        println!(
            "  … 其余 {} 个未显示（用 --count 调整）",
            total - args.count
        );
    }

    if !analysis.notes().is_empty() {
        println!();
        println!("说明");
        for note in analysis.notes() {
            println!("  · {note}");
        }
    }
    Ok(())
}

/// `symbol`：定位一个符号（名字或地址），报告它在哪个成员里。
pub fn run_symbol(args: &SymbolArgs) -> anyhow::Result<()> {
    crate::tracing_setup::init(args.verbose);

    let opened = Session::open(&args.target, args.raw.to_open_options()?)?;

    // 查询既可能是名字，也可能是地址。地址用 16 进制判定：
    // 纯十六进制字符且能解析成 u64（`parse_address` 已处理 0x 前缀）。
    let as_address = bitflip_core::parse_address(&args.query);
    let is_name_query = as_address.is_none();

    // 归档：先只按成员名查（用户可能直接问"这个成员在不在"）。
    // 若带 --member 就缩到那个成员。
    if opened.info().is_archive() {
        let candidates: Vec<ArchiveMember> = match args.member.as_deref() {
            Some(name) => vec![opened.member_session(name)?.1],
            None => opened.members().to_vec(),
        };

        // 没有 --member 时，先把"查询恰好是个成员名"这一情况处理掉 ——
        // 否则用户问 `-- member foo.o` 里的 foo.o，会被当成符号名去搜，
        // 得到一个"找不到"的答案，而成员其实就在那儿。
        if args.member.is_none() {
            let hits = opened.member_match_count(&args.query);
            if hits == 1 {
                let member = opened
                    .find_member(&args.query)
                    .expect("match_count 说唯一命中，find_member 必成功");
                return report_member_hit(&opened, member, &args.query, args.json);
            }
        }

        let mut found = Vec::new();
        let mut examined = 0usize;
        let mut failures = Vec::new();

        for member in &candidates {
            // 不是可分析对象的成员（长名表、符号索引）在这里**跳过**，
            // 但要记下原因 —— 静默跳过会让"找不到"变得不可信。
            let Ok((member_session, _)) = opened.member_session(&member.name) else {
                failures.push(format!("{}（不是可分析的对象）", member.name));
                continue;
            };
            let Ok(analysis) = member_session.analysis(&member_session.detached_job()) else {
                failures.push(format!("{}（分析失败）", member.name));
                continue;
            };
            examined += 1;

            if let Some(addr) = as_address {
                if let Some(f) = analysis
                    .functions()
                    .iter()
                    .find(|f| bitflip_core::parse_address(&f.start) == Some(addr))
                {
                    found.push((
                        member.name.clone(),
                        f.start.clone(),
                        f.name.clone(),
                        f.named,
                    ));
                }
            } else {
                for f in analysis.functions() {
                    if f.named && f.name == args.query {
                        found.push((member.name.clone(), f.start.clone(), f.name.clone(), true));
                    }
                }
            }
        }

        return report_archive_symbol(&opened, &args.query, &found, examined, &failures, args.json);
    }

    // 非归档：直接在唯一对象里找。
    let analysis = opened
        .analysis(&opened.detached_job())
        .context("建立目标分析")?;

    let hit = if let Some(addr) = as_address {
        analysis
            .functions()
            .iter()
            .find(|f| bitflip_core::parse_address(&f.start) == Some(addr))
    } else {
        analysis
            .functions()
            .iter()
            .find(|f| f.named && f.name == args.query)
    };

    if args.json {
        let payload = json!({
            "format_version": bitflip_core::ANALYSIS_FORMAT_VERSION,
            "target": opened.info().path,
            "query": args.query,
            "query_is_address": !is_name_query,
            "found": hit.is_some(),
            "matches": hit.map(|f| vec![json!({
                "member": serde_json::Value::Null,
                "start": f.start,
                "name": f.name,
                "named": f.named,
            })]).unwrap_or_default(),
        });
        println!(
            "{}",
            serde_json::to_string_pretty(&payload).context("序列化符号定位失败")?
        );
        return Ok(());
    }

    match hit {
        Some(f) => {
            println!("找到    {}", f.name);
            println!("地址    {}", f.start);
            match f.size {
                Some(size) => println!("大小    {size} 字节"),
                // 大小拿不到就说拿不到：不写 "0 字节"，
                // 那会读成"这个函数是空的"。
                None => println!("大小    未知（符号表没有给出区间，且未推断出结束地址）"),
            }
            println!("来源    {}", f.source);
        }
        None => {
            println!("没找到   {}", args.query);
            println!();
            println!(
                "在 {} 个函数里没有匹配的{}。",
                analysis.functions().len(),
                if is_name_query {
                    "函数名"
                } else {
                    "函数入口"
                }
            );
            if is_name_query {
                println!("提示    用 `functions` 子命令看实际识别出的函数名。");
            }
        }
    }
    Ok(())
}

/// 查询恰好命中一个成员名时的输出。
fn report_member_hit(
    session: &Session,
    member: &ArchiveMember,
    query: &str,
    json_output: bool,
) -> anyhow::Result<()> {
    if json_output {
        let payload = json!({
            "format_version": session.info().format_version,
            "target": session.info().path,
            "query": query,
            "query_is_address": false,
            "kind": "member",
            "found": true,
            "member": {
                "name": member.name,
                "offset": member.offset,
                "size": member.size,
                "truncated": member.truncated,
            },
        });
        println!(
            "{}",
            serde_json::to_string_pretty(&payload).context("序列化成员定位失败")?
        );
        return Ok(());
    }
    println!("找到    归档成员 {}", member.name);
    println!("偏移    {:#x}", member.offset);
    println!("大小    {} 字节", member.size);
    println!(
        "用法    bitflip-cli functions {} --member {}",
        session.info().path,
        member.name
    );
    Ok(())
}

/// 归档里跨成员搜索的结果。
fn report_archive_symbol(
    session: &Session,
    query: &str,
    found: &[(String, String, String, bool)],
    examined: usize,
    failures: &[String],
    json_output: bool,
) -> anyhow::Result<()> {
    if json_output {
        let matches: Vec<_> = found
            .iter()
            .map(|(member, start, name, named)| {
                json!({ "member": member, "start": start, "name": name, "named": named })
            })
            .collect();
        let payload = json!({
            "format_version": bitflip_core::ANALYSIS_FORMAT_VERSION,
            "target": session.info().path,
            "query": query,
            "found": !found.is_empty(),
            "examined_members": examined,
            "skipped_members": failures,
            "matches": matches,
        });
        println!(
            "{}",
            serde_json::to_string_pretty(&payload).context("序列化符号定位失败")?
        );
        return Ok(());
    }

    if found.is_empty() {
        println!("没找到   {query}");
        println!();
        println!("在 {examined} 个成员里没有匹配。");
        if !failures.is_empty() {
            println!();
            println!("已跳过 {} 个不可分析成员：", failures.len());
            for f in failures {
                println!("  · {f}");
            }
        }
        return Ok(());
    }

    // 多个成员里同名是常态（每个 .o 都可能有 `init`），所以把成员名
    // 放在每一行 —— 一条没有归属的地址对用户没有用。
    println!("找到 {} 处", found.len());
    println!();
    println!("{:>8}  {:>18}  成员", "来源", "地址");
    for (member, start, name, named) in found {
        let label = if *named {
            name.as_str()
        } else {
            "（未命名）"
        };
        println!("  {label}  {start}  {member}");
    }
    Ok(())
}
