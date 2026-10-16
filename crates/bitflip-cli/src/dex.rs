//! `dex` 子命令：DEX 视图的独立入口（M2b）。
//!
//! # 为什么不是 `functions --member classes.dex`
//!
//! 那条路要过 `Session::member_session`，它要求成员能被 `parse_object` 解析成对象；
//! DEX 没有对象解析器（ADR-0020），所以必然被拒。DEX 需要自己的入口，也需要自己的
//! 输出形状：它没有架构、没有线性地址，指令是寄存器机的码元序列（code unit）。
//!
//! # 怎么选
//!
//! * 目标可以是 **APK**（枚举其中的 `*.dex` 成员），也可以是**单个 `.dex` 文件**；
//! * 类用 smali 描述符 `Lcom/Foo;` 选，方法用完整 smali 标识 `Lcom/Foo;->bar(I)V` 选；
//! * **只做精确匹配**：短名、子串、参数通配都不做 —— 命中多个就说不清是哪一个
//!   （与 `find_class_by_descriptor` 同一立场）。
//!
//! # 降级要看得见
//!
//! 符号解析默认开启；解析不了的操作数分两类，**都写进报告**：
//! `unsupported`（我们已知的缺口，例如 call-site）与 `unavailable`（异常：本该有却没有）。
//! `--no-symbols` 时报告会明说"符号解析已关闭，下面是原始池下标"，
//! 而不是悄悄换成另一种格式让人以为解析成功了（CLAUDE.md §7）。

use std::fmt::Write as _;
use std::path::Path;
use std::sync::Arc;

use anyhow::{bail, Context};
use bitflip_core::dex::{
    self, DexInstructions, DexRenderReport, DexStructure, DexSymbolResolver, DexViewError,
};
use bitflip_core::{OpenOptions, Session};
use serde_json::json;

use crate::cli::DexArgs;

/// 一个待处理的 DEX 输入：APK 里的成员，或单文件目标本身。
struct DexInput {
    /// 显示名：APK 成员名，或单文件目标的文件名。
    name: String,
    /// APK 角色标签（`[主 dex]` 等）；单文件目标为空串。
    role: String,
    bytes: Arc<[u8]>,
}

/// 一条渲染好的指令行。
struct InstructionRow {
    /// 方法内码元偏移（不是字节地址 —— DEX 没有线性地址空间）。
    address: u32,
    /// 渲染好的整行（含 `{:04x}:` 前缀）。
    text: String,
}

/// `dex` 子命令入口。
pub fn run_dex(args: &DexArgs) -> anyhow::Result<()> {
    crate::tracing_setup::init(args.verbose);
    let text = if args.json {
        build_json(args)?
    } else {
        build_text(args)?
    };
    println!("{text}");
    Ok(())
}

/// 组装文本报告（纯函数：`run_dex` 只负责打印，测试直接断言这里）。
pub fn build_text(args: &DexArgs) -> anyhow::Result<String> {
    let parsed = load_all(args)?;

    let mut out = String::new();
    let _ = writeln!(out, "目标：{}", args.target.display());
    match (args.class.as_deref(), args.method.as_deref()) {
        (Some(class), Some(method)) => {
            bail!("`--class {class}` 与 `--method {method}` 只能给一个：前者列一个类的方法，后者看一个方法的指令")
        }
        (None, Some(signature)) => report_method(&mut out, &parsed, signature, args)?,
        (Some(descriptor), None) => report_class(&mut out, &parsed, descriptor, args)?,
        (None, None) => report_summary(&mut out, &parsed, args),
    }
    Ok(out)
}

/// 组装 JSON 报告（稳定的 wire 契约；每份都带 `format_version`）。
pub fn build_json(args: &DexArgs) -> anyhow::Result<String> {
    let parsed = load_all(args)?;
    let inputs: Vec<_> = parsed
        .iter()
        .map(|(input, structure)| {
            json!({
                "name": &input.name,
                "role": &input.role,
                "size": input.bytes.len(),
                "class_count": structure.class_count(),
                "method_count": structure.method_count(),
                "method_count_with_code": structure.method_count_with_code(),
                // 逐 DEX 的降级说明（解析器给的 notes）。必须在输出里。
                "notes": &structure.notes,
            })
        })
        .collect();

    let mut payload = json!({
        "format_version": dex::DEX_FORMAT_VERSION,
        "target": args.target.display().to_string(),
        "symbols": !args.no_symbols,
        "cfg": !args.no_cfg,
        "dex_inputs": inputs,
    });

    if let Some(signature) = args.method.as_deref() {
        payload["method"] = method_json(&parsed, signature, args)?;
    } else if let Some(descriptor) = args.class.as_deref() {
        payload["class"] = class_json(&parsed, descriptor, args)?;
    }
    serde_json::to_string_pretty(&payload).context("序列化 DEX 报告失败")
}

/// 打开目标，整理出所有 DEX 输入并逐个解析。
fn load_all(args: &DexArgs) -> anyhow::Result<Vec<(DexInput, DexStructure)>> {
    let inputs = collect_inputs(&args.target, args.member.as_deref())?;
    let mut parsed = Vec::with_capacity(inputs.len());
    for input in inputs {
        let structure = dex::parse(&input.bytes)
            .with_context(|| format!("把 {} 当 DEX 解析失败", input.name))?;
        parsed.push((input, structure));
    }
    Ok(parsed)
}

/// 整理 DEX 输入：归档（APK）取 `*.dex` 成员，其余当作单个 `.dex` 文件。
///
/// 先按归档试、失败再按单文件读：单个 `.dex` 文件不该为了"走进归档那条分支"
/// 而被拒绝，而嗅探不出容器的文件本来就走不通归档那条路。
fn collect_inputs(target: &Path, only: Option<&str>) -> anyhow::Result<Vec<DexInput>> {
    if let Ok(session) = Session::open(target, OpenOptions::default()) {
        if session.info().is_archive() {
            return archive_inputs(&session, only);
        }
    }

    if let Some(name) = only {
        bail!(
            "{name:?}：目标 {} 不是归档，没有成员可选（--member 只对 APK/ZIP 有意义）",
            target.display()
        );
    }
    let bytes =
        std::fs::read(target).with_context(|| format!("读取目标 {} 失败", target.display()))?;
    Ok(vec![DexInput {
        name: file_name(target),
        role: String::new(),
        bytes: Arc::from(bytes),
    }])
}

/// 从归档会话里取出 DEX 成员（`--member` 给了就只取它）。
fn archive_inputs(session: &Session, only: Option<&str>) -> anyhow::Result<Vec<DexInput>> {
    let available: Vec<&str> = session
        .members()
        .iter()
        .filter(|member| dex::is_dex_member_name(&member.name))
        .map(|member| member.name.as_str())
        .collect();

    if let Some(name) = only {
        // 明确指定了成员：不在这里替它做"是不是 DEX 名字"的判断 ——
        // 内容判据在 `dex::read_member` 里（名字可以骗人，内容不会）。
        let bytes = dex::read_member(session, name)?;
        return Ok(vec![DexInput {
            name: name.to_owned(),
            role: role_label(name),
            bytes,
        }]);
    }

    if available.is_empty() {
        bail!(
            "{} 里没有 DEX 成员（归档 {} 个成员，用 `members` 子命令看全部）",
            session.info().path,
            session.members().len()
        );
    }

    let mut inputs = Vec::with_capacity(available.len());
    for name in available {
        let bytes = dex::read_member(session, name)?;
        inputs.push(DexInput {
            name: name.to_owned(),
            role: role_label(name),
            bytes,
        });
    }
    Ok(inputs)
}

/// APK 角色标签（`[主 dex]` / `[dex 序号 N]`）；不符合约定的名字为空串。
fn role_label(name: &str) -> String {
    crate::members::apk_role_hint(true, name).trim().to_owned()
}

/// 单文件目标的显示名（拿不到就退回整个路径，不编名字）。
fn file_name(target: &Path) -> String {
    target.file_name().map_or_else(
        || target.display().to_string(),
        |name| name.to_string_lossy().into_owned(),
    )
}

/// 渲染整条指令列：数值形式（`symbols` 为 `None`）或符号形式。
fn instruction_rows(
    instructions: &DexInstructions,
    symbols: Option<&dyn DexSymbolResolver>,
) -> Result<(Vec<InstructionRow>, DexRenderReport), DexViewError> {
    let mut rows = Vec::with_capacity(instructions.len());
    let mut report = DexRenderReport::default();
    for index in 0..instructions.len() {
        let mut text = String::new();
        let outcome = instructions.render_instruction_with_symbols(index, symbols, &mut text)?;
        report.instructions += 1;
        match outcome {
            Some(dex::DexSymbolOutcome::NotSupported) => report.unsupported_operands += 1,
            Some(dex::DexSymbolOutcome::Unavailable) => report.unavailable_operands += 1,
            Some(dex::DexSymbolOutcome::Written) | None => {}
        }
        rows.push(InstructionRow {
            address: instructions
                .addresses
                .get(index)
                .copied()
                .unwrap_or_default(),
            text,
        });
    }
    Ok((rows, report))
}

/// 不给选择时的概览：有哪几个 DEX、各有多少类与方法，以及怎么用。
fn report_summary(out: &mut String, parsed: &[(DexInput, DexStructure)], args: &DexArgs) {
    let names: Vec<&str> = parsed
        .iter()
        .map(|(input, _)| input.name.as_str())
        .collect();
    let _ = writeln!(out, "DEX 输入：{} 个（{}）", parsed.len(), names.join("、"));

    let limit = if args.limit == 0 {
        usize::MAX
    } else {
        args.limit
    };
    for (input, structure) in parsed.iter().take(limit) {
        let role = if input.role.is_empty() {
            String::new()
        } else {
            format!(" {}", input.role)
        };
        let _ = writeln!(
            out,
            "  {}{}  {} 类 / {} 方法（{} 有字节码）",
            input.name,
            role,
            structure.class_count(),
            structure.method_count(),
            structure.method_count_with_code()
        );
        for note in &structure.notes {
            let _ = writeln!(out, "      降级说明：{note}");
        }
    }
    if parsed.len() > limit {
        let _ = writeln!(
            out,
            "  …还有 {} 个未列出（`--limit 0` 可全部列出）",
            parsed.len() - limit
        );
    }
    let _ = writeln!(
        out,
        "说明：用 `--class Lcom/Foo;` 列类的方法；用 `--method 'Lcom/Foo;->bar(I)V'` 看指令与文本 CFG。"
    );
}

/// 一个类的全部匹配（可能在多个 DEX 里都有）。
fn class_matches<'a>(
    parsed: &'a [(DexInput, DexStructure)],
    descriptor: &str,
) -> Vec<(&'a DexInput, &'a DexStructure, usize)> {
    let mut matches = Vec::new();
    for (input, structure) in parsed {
        if let Some(class) = structure.find_class_by_descriptor(descriptor) {
            matches.push((input, structure, class));
        }
    }
    matches
}

/// 一个方法的全部匹配（可能在多个 DEX 里都有）。
fn method_matches<'a>(
    parsed: &'a [(DexInput, DexStructure)],
    signature: &str,
) -> Vec<(&'a DexInput, &'a DexStructure, usize)> {
    let mut matches = Vec::new();
    for (input, structure) in parsed {
        if let Some(method) = structure.find_method_by_signature(signature) {
            matches.push((input, structure, method));
        }
    }
    matches
}

/// `--class`：列这个类的方法。
fn report_class(
    out: &mut String,
    parsed: &[(DexInput, DexStructure)],
    descriptor: &str,
    args: &DexArgs,
) -> anyhow::Result<()> {
    let matches = class_matches(parsed, descriptor);
    if matches.is_empty() {
        let hint = if looks_like_class_descriptor(descriptor) {
            ""
        } else {
            "（本命令只做精确匹配：类要写成 smali 描述符，如 `Lcom/Foo;`）"
        };
        bail!("在 {} 个 DEX 里都找不到类 {descriptor}{hint}", parsed.len());
    }

    let limit = if args.limit == 0 {
        usize::MAX
    } else {
        args.limit
    };
    for (input, structure, class) in matches {
        let methods = structure.class_methods(class);
        let with_code = methods
            .iter()
            .filter(|index| structure.methods.get(**index).is_some_and(|m| m.has_code()))
            .count();
        let _ = writeln!(out, "类：{descriptor}（{}）", input.name);
        if let Some(superclass) = structure.superclass_descriptor(class) {
            let _ = writeln!(out, "  父类：{superclass}");
        }
        let _ = writeln!(
            out,
            "  方法 {} 个（{with_code} 有字节码 / {} 没有）",
            methods.len(),
            methods.len() - with_code
        );
        for index in methods.iter().take(limit) {
            let signature = structure
                .method_signature(*index)
                .unwrap_or_else(|| format!("<方法 {index} 的标识取不到>"));
            let code_off = structure
                .methods
                .get(*index)
                .map_or(0, |method| method.code_off);
            if code_off == 0 {
                let _ = writeln!(out, "    {index:>5}  {signature}  [无字节码]");
            } else {
                let _ = writeln!(out, "    {index:>5}  {signature}  code_off={code_off:#x}");
            }
        }
        if methods.len() > limit {
            let _ = writeln!(
                out,
                "    …还有 {} 个未列出（`--limit 0` 可全部列出）",
                methods.len() - limit
            );
        }
    }
    Ok(())
}

/// `--method`：打印这个方法的指令与文本 CFG。
fn report_method(
    out: &mut String,
    parsed: &[(DexInput, DexStructure)],
    signature: &str,
    args: &DexArgs,
) -> anyhow::Result<()> {
    let matches = method_matches(parsed, signature);
    if matches.is_empty() {
        let hint = if looks_like_method_signature(signature) {
            ""
        } else {
            "（本命令只做精确匹配：方法要写成 smali 标识，如 `Lcom/Foo;->bar(I)V`）"
        };
        bail!(
            "在 {} 个 DEX 里都找不到方法 {signature}{hint}",
            parsed.len()
        );
    }
    if matches.len() > 1 {
        let names: Vec<&str> = matches
            .iter()
            .map(|(input, _, _)| input.name.as_str())
            .collect();
        bail!(
            "方法 {signature} 在多个 DEX 里都有（{}）：用 `--member <名字>` 指定一个",
            names.join("、")
        );
    }

    let (input, structure, index) = matches[0];
    let code_off = structure
        .methods
        .get(index)
        .map_or(0, |method| method.code_off);
    let _ = writeln!(out, "方法：{signature}");
    let role = if input.role.is_empty() {
        String::new()
    } else {
        format!(" {}", input.role)
    };
    let _ = writeln!(out, "来源：{}{}  code_off={code_off:#x}", input.name, role);

    if code_off == 0 {
        // 合法结论，不是错误：抽象/native 方法本来就没有 code_item。
        let _ = writeln!(
            out,
            "这个方法没有字节码（code_off = 0）：抽象方法或 native 方法，没有指令与 CFG。"
        );
        return Ok(());
    }

    let view = dex::project_method(&input.bytes, code_off)
        .with_context(|| format!("投影方法 {signature}（code_off={code_off:#x}）失败"))?;
    let _ = writeln!(
        out,
        "寄存器 {} / 入参 {} / 出参 {}",
        view.registers_size, view.ins_size, view.outs_size
    );

    // 关掉符号解析时那份"账"没有意义（根本没尝试解析），所以只保留指令行；
    // 报告里会明说"已关闭"，不让人误以为"解析过、全都成功了"。
    let rows = if args.no_symbols {
        let (rows, _) = instruction_rows(&view.instructions, None)
            .with_context(|| format!("渲染方法 {signature} 的指令失败"))?;
        let _ = writeln!(
            out,
            "符号解析：已关闭（--no-symbols）：池索引按原始形式输出，如 `string@12`。"
        );
        rows
    } else {
        let symbols = structure.symbols();
        let (rows, report) = instruction_rows(&view.instructions, Some(&symbols))
            .with_context(|| format!("渲染方法 {signature} 的指令失败"))?;
        let _ = writeln!(out, "{}", symbol_line(&report));
        rows
    };

    let _ = writeln!(out, "指令（{} 条）：", rows.len());
    for row in &rows {
        let _ = writeln!(out, "  {}", row.text);
    }

    if !args.no_cfg {
        let mut cfg = String::new();
        dex::render_cfg_text(&view, &mut cfg);
        out.push_str(&cfg);
    }
    Ok(())
}

/// 符号解析的"账"：把缺口与异常都写出来。
fn symbol_line(report: &DexRenderReport) -> String {
    if report.unsupported_operands == 0 && report.unavailable_operands == 0 {
        return format!(
            "符号解析：开启（{} 条指令的操作数都解析成了符号文本）",
            report.instructions
        );
    }
    format!(
        "符号解析：开启（已知缺口 {} 处（call-site 等尚未支持）；解析异常 {} 处（本该解析出来却没有））",
        report.unsupported_operands, report.unavailable_operands
    )
}

/// `--method --json` 的那一段。
fn method_json(
    parsed: &[(DexInput, DexStructure)],
    signature: &str,
    args: &DexArgs,
) -> anyhow::Result<serde_json::Value> {
    let matches = method_matches(parsed, signature);
    if matches.is_empty() {
        bail!("在 {} 个 DEX 里都找不到方法 {signature}", parsed.len());
    }
    if matches.len() > 1 {
        let names: Vec<&str> = matches
            .iter()
            .map(|(input, _, _)| input.name.as_str())
            .collect();
        bail!(
            "方法 {signature} 在多个 DEX 里都有（{}）：用 `--member <名字>` 指定一个",
            names.join("、")
        );
    }

    let (input, structure, index) = matches[0];
    let code_off = structure
        .methods
        .get(index)
        .map_or(0, |method| method.code_off);
    if code_off == 0 {
        return Ok(json!({
            "signature": signature,
            "member": input.name,
            "code_off": hex16(code_off),
            "has_code": false,
            "note": "抽象方法或 native 方法：没有 code_item，因此没有指令与 CFG",
        }));
    }

    let view = dex::project_method(&input.bytes, code_off)
        .with_context(|| format!("投影方法 {signature}（code_off={code_off:#x}）失败"))?;
    let (rows, report) = if args.no_symbols {
        instruction_rows(&view.instructions, None)
            .with_context(|| format!("渲染方法 {signature} 的指令失败"))?
    } else {
        let symbols = structure.symbols();
        instruction_rows(&view.instructions, Some(&symbols))
            .with_context(|| format!("渲染方法 {signature} 的指令失败"))?
    };

    let instructions: Vec<_> = rows
        .iter()
        .map(|row| {
            json!({
                // 定长小写 16 位十六进制（跨进程地址约定）；这是**码元偏移**，
                // 不是字节地址 —— DEX 没有线性地址空间。
                "code_unit": hex16(row.address),
                "text": row.text,
            })
        })
        .collect();

    let cfg = if args.no_cfg {
        None
    } else {
        let mut text = String::new();
        dex::render_cfg_text(&view, &mut text);
        Some(text)
    };

    Ok(json!({
        "signature": signature,
        "member": input.name,
        "code_off": hex16(code_off),
        "has_code": true,
        "registers_size": view.registers_size,
        "ins_size": view.ins_size,
        "outs_size": view.outs_size,
        "symbols": !args.no_symbols,
        "instruction_count": report.instructions,
        "unsupported_operands": report.unsupported_operands,
        "unavailable_operands": report.unavailable_operands,
        "instructions": instructions,
        "cfg_text": cfg,
        "unresolved_edge_targets": view.cfg.unresolved_edge_targets.len(),
    }))
}

/// `--class --json` 的那一段。
fn class_json(
    parsed: &[(DexInput, DexStructure)],
    descriptor: &str,
    args: &DexArgs,
) -> anyhow::Result<serde_json::Value> {
    let matches = class_matches(parsed, descriptor);
    if matches.is_empty() {
        bail!("在 {} 个 DEX 里都找不到类 {descriptor}", parsed.len());
    }
    let limit = if args.limit == 0 {
        usize::MAX
    } else {
        args.limit
    };
    let entries: Vec<_> = matches
        .iter()
        .map(|(input, structure, class)| {
            let methods: Vec<_> = structure
                .class_methods(*class)
                .into_iter()
                .take(limit)
                .map(|index| {
                    let code_off = structure.methods.get(index).map_or(0, |m| m.code_off);
                    json!({
                        "index": index,
                        "signature": structure.method_signature(index),
                        "has_code": code_off != 0,
                        "code_off": hex16(code_off),
                    })
                })
                .collect();
            json!({
                "member": input.name,
                "superclass": structure.superclass_descriptor(*class),
                "source_file": structure.source_file(*class),
                "methods": methods,
            })
        })
        .collect();
    Ok(json!({ "descriptor": descriptor, "occurrences": entries }))
}

/// 定长小写 16 位十六进制（跨进程 wire 的统一形式）。
fn hex16(value: u32) -> String {
    format!("{value:016x}")
}

/// 像不像一个 smali 类描述符（只用来决定"要不要给格式提示"，不参与匹配）。
fn looks_like_class_descriptor(text: &str) -> bool {
    text.starts_with('L') && text.ends_with(';') && text.len() > 2
}

/// 像不像一个 smali 方法标识（同上，只影响提示）。
fn looks_like_method_signature(text: &str) -> bool {
    text.contains("->") && text.contains('(') && text.contains(')')
}
