//! DEX 结构模型的黄金测试。
//!
//! 两条独立的路：
//!
//! 1. **合成样本**（[`fixture`]）：逐字段照 Dalvik 规范拼一份最小但完全合规的
//!    DEX，能在任何机器上跑，用来钉住偏移、编码与投影结果（CLAUDE.md §6.11：
//!    fixture 照规格拼，不照自己的解析代码拼）。
//! 2. **真实 APK**：需要本机样本，所以是 `#[ignore]` 的独立测试
//!    （CLAUDE.md §7：跳过与通过必须在报告里分得开）。
//!
//! 合成样本证明"我们按规范读"，真实样本证明"规范之外还有现实"——两者缺一不可。

use bitflip_loader::{
    project_dex_method, render_dex_instructions_with_symbols, DexStructure, ObjectKind,
};

// ── 合成样本 ────────────────────────────────────────────────────────────────

/// 按 Dalvik Executable 规范拼一份最小但完全合规的 DEX。
///
/// 规范出处逐项写在代码里（`§3.1` 指 "Dalvik Executable format" 文档的章节号）。
///
/// 实现搬到了 `common/dex_fixture.rs`：**CLI 的 `dex` 子命令测试也要用同一份样本**
/// （用 `#[path]` 引入），样本只有一份才不会两个 crate 各养一份、然后慢慢分叉。
#[path = "common/dex_fixture.rs"]
mod fixture;

/// 合成样本：逐项核对投影结果。
#[test]
fn a_minimal_but_conformant_dex_projects_classes_fields_and_methods() {
    let bytes = fixture::build();
    let dex: DexStructure =
        bitflip_loader::parse_dex_structure(&bytes).expect("合成样本必须能解析");

    // ── 头
    assert_eq!(dex.header.version, "035");
    assert_eq!(dex.header.file_size as usize, bytes.len());
    assert_eq!(dex.header.header_size, fixture::HEADER_SIZE);
    assert!(
        dex.header.sha1_matches_stored,
        "样本的 SHA-1 是按规范算出来的，必须判为一致"
    );

    // 六个池：声明多少就该解析出多少
    assert_eq!(
        dex.counts.declared.class_defs,
        fixture::hand_read_class_defs_size(&bytes),
        "我们读到的声明值必须等于从头里手读的值"
    );
    assert_eq!(dex.counts.declared.strings, fixture::STRINGS.len() as u32);
    assert!(
        dex.counts.mismatches.is_empty(),
        "合规样本不该有计数不符：{:?}",
        dex.counts.mismatches
    );

    // ── 类
    assert_eq!(dex.class_count(), 1);
    assert_eq!(dex.class_descriptor(0), Some("Lcom/example/Foo;"));
    assert_eq!(dex.class_short_name(0), Some("Foo"));
    assert_eq!(dex.superclass_descriptor(0), Some("Ljava/lang/Object;"));
    assert_eq!(dex.source_file(0), Some("Foo.java"));
    assert_eq!(dex.classes[0].access_flags, fixture::ACC_PUBLIC);

    // ── 字段：静态在前（规范 §4.5.11 的顺序），名字/类型回到池里取
    assert_eq!(dex.field_count(), 2);
    assert_eq!(dex.class_fields(0), vec![0, 1]);
    assert!(dex.fields[0].is_static, "静态字段排在前");
    assert!(!dex.fields[1].is_static, "实例字段排在后");
    assert_eq!(dex.field_name(0), Some("x"));
    assert_eq!(dex.field_type_descriptor(0), Some("I"));
    assert_eq!(dex.field_name(1), Some("s"));
    assert_eq!(dex.field_type_descriptor(1), Some("Ljava/lang/String;"));
    assert_eq!(dex.field_declaring_class(0), Some("Lcom/example/Foo;"));

    // ── 方法：直接方法在前；参数表来自 proto 的 type_list
    assert_eq!(dex.method_count(), 2);
    assert_eq!(dex.class_methods(0), vec![0, 1]);
    assert!(dex.methods[0].is_direct);
    assert_eq!(dex.method_name(0), Some("<init>"));
    assert_eq!(dex.method_return_descriptor(0), Some("V"));
    assert_eq!(dex.method_parameters(0), Vec::<&str>::new());
    assert!(!dex.methods[1].is_direct);
    assert_eq!(dex.method_name(1), Some("bar"));
    assert_eq!(dex.method_return_descriptor(1), Some("V"));
    assert_eq!(dex.method_parameters(1), vec!["I"]);

    // 两个方法都带字节码（样本里各给了一个 code_item）
    assert_eq!(dex.method_count_with_code(), 2);
    assert!(dex.methods.iter().all(|m| m.has_code()));
    assert_eq!(dex.method_class_index(0), Some(0));
    assert_eq!(dex.method_class_index(1), Some(0));

    // ── 结构性交叉校验：class_data 里数出来的符号数 == 两张表的条数之和
    assert_eq!(
        dex.symbols_declared_in_class_data(),
        (dex.field_count() + dex.method_count()) as u64,
        "四个 class_data 计数之和必须等于字段数 + 方法数（否则遍历时漏了某一类符号）"
    );

    // ── 按描述符精确查找
    assert_eq!(dex.find_class_by_descriptor("Lcom/example/Foo;"), Some(0));
    assert_eq!(dex.find_class_by_descriptor("Foo"), None, "不做模糊匹配");
    assert_eq!(dex.find_class_by_descriptor("Ljava/lang/Object;"), None);

    // ── smali 风格标识：`类->方法(参数)返回`
    assert_eq!(
        dex.method_signature(0).as_deref(),
        Some("Lcom/example/Foo;-><init>()V"),
        "无参方法（parameters_off == 0）出空括号"
    );
    assert_eq!(
        dex.method_signature(1).as_deref(),
        Some("Lcom/example/Foo;->bar(I)V")
    );
    assert_eq!(dex.method_signature(2), None, "下标越界给 None，不给空串");

    // 按标识反查（精确匹配，重名方法靠原型区分）
    assert_eq!(
        dex.find_method_by_signature("Lcom/example/Foo;->bar(I)V"),
        Some(1)
    );
    assert_eq!(
        dex.find_method_by_signature("Lcom/example/Foo;-><init>()V"),
        Some(0)
    );
    assert_eq!(
        dex.find_method_by_signature("Lcom/example/Foo;->bar()V"),
        None,
        "原型不同就是不同方法，不许模糊命中"
    );
    assert_eq!(dex.find_method_by_signature("Lcom/example/Foo;->bar"), None);
    assert_eq!(
        dex.find_method_by_signature("Lcom/other/Bar;->bar(I)V"),
        None
    );

    // ── 完全合规的文件不该有任何降级说明
    assert!(
        dex.notes.is_empty(),
        "合规样本不该有 notes（有的话说明我们或规范理解有偏差）：{:?}",
        dex.notes
    );
}

/// 合成的**不合规**样本：SHA-1 对不上时必须说出来，而不是照常报"分析完成"。
#[test]
fn a_dex_whose_stored_sha1_does_not_match_is_reported_not_hidden() {
    let bytes = fixture::build_with_a_wrong_signature();
    let dex = bitflip_loader::parse_dex_structure(&bytes).expect("checksum 是对的，仍应能解析");

    assert!(
        !dex.header.sha1_matches_stored,
        "这个变体就是要把 SHA-1 改坏"
    );
    assert!(
        dex.notes.iter().any(|n| n.contains("SHA-1")),
        "SHA-1 对不上必须出现在 notes 里（CLAUDE.md §7 的「降级要写在界面上」）：{:?}",
        dex.notes
    );
    // 但结构本身照常解析出来：容忍不等于丢弃
    assert_eq!(dex.class_count(), 1);
    assert_eq!(dex.method_count(), 2);
}

/// 输入被截断/不是 DEX 时必须是错误，不是"空但看起来完成"的结构。
#[test]
fn a_broken_input_is_an_error_not_an_empty_structure() {
    let full = fixture::build();
    // 掐掉尾部：class_data / code_item 都读不到了。
    let truncated = &full[..0x100];
    assert!(
        bitflip_loader::parse_dex_structure(truncated).is_err(),
        "截断的 DEX 必须报错，不能返回一个空结构"
    );
    assert!(bitflip_loader::parse_dex_structure(b"not a dex").is_err());
    assert!(bitflip_loader::parse_dex_structure(&[]).is_err());
}

/// 嗅探层认得出 DEX，且**不**给它编一个机器架构。
#[test]
fn sniffing_a_dex_yields_dex_marks_without_an_arch() {
    let bytes = fixture::build();
    let guess = bitflip_loader::sniff_bytes(&bytes);
    assert_eq!(guess.object, ObjectKind::Dex);
    assert_eq!(
        guess.arch, None,
        "DEX 没有机器架构：不能用占位值冒充（CLAUDE.md §7）"
    );
    assert_eq!(guess.container, bitflip_loader::ContainerKind::Plain);
}

// ── 真实样本 ────────────────────────────────────────────────────────────────

/// 本机真实 APK 的位置：优先 `BITFLIP_TEST_APK`，否则退回本机已知的那一份。
///
/// 环境变量优先是为了让别的机器也能跑这条测试 —— 把路径写死等于把测试
/// 绑在一台机器上，而"换台机器就跳过"正是 §7 说的会让绿灯说谎的做法。
fn sample_apk() -> std::path::PathBuf {
    if let Ok(from_env) = std::env::var("BITFLIP_TEST_APK") {
        return std::path::PathBuf::from(from_env);
    }
    std::path::PathBuf::from(r"C:\Users\Administrator\Downloads\ah-app-release.apk")
}

/// 真实 APK 里的三个 DEX：与头里**手读**的值逐一对齐。
///
/// 需要 32MB 的本机样本，所以默认 `#[ignore]`（CLAUDE.md §7：跳过与通过必须
/// 在报告里分得开）。
///
/// # 怎么手动跑
///
/// `scripts/cargo.ps1` 会吞掉裸 `--`（PS 5.1 的解析器先吃了一遍，脚本只在
/// 见到 `-D` / `--deny` 时才补回来），而 `cargo test --ignored` 又必须写成
/// `-- --ignored`。所以这条测试**直接跑测试可执行文件**：
///
/// ```text
/// & .\scripts\cargo.ps1 build --offline -p bitflip-loader --tests
/// $exe = Get-ChildItem .cargo-target\debug\deps\dex_structure-*.exe |
///        Sort-Object LastWriteTime -Descending | Select-Object -First 1
/// & $exe.FullName --ignored --nocapture
/// ```
///
/// # 耗时（实测，2026-10-14）
///
/// 本测试在 **debug** 下约 **5 分钟**（三个 dex 合计 25 MB）—— 时间几乎全在
/// 依赖库的解析里：同机 release 下 `classes.dex`（8.8 MB / 7643 类）只要
/// **1.2 s**，其中我们自己的 class_data 循环只占 **29 ms**。也就是说这是
/// **debug 构建的开销**，不是算法问题，也不是我们的代码慢。
///
/// 样本不在就**失败**（不是悄悄跳过）：既然有人显式要跑这条测试，
/// "样本没找到"就是它必须报告的那个事实。
#[ignore = "需要本机真实 APK（32MB）；用 --ignored 手动跑"]
#[test]
fn the_real_apk_dex_files_agree_with_their_headers() {
    let apk = sample_apk();
    let bytes = std::fs::read(&apk).unwrap_or_else(|e| {
        panic!(
            "读不到真实样本 {}: {e}\n（设 BITFLIP_TEST_APK 指向任意一个含 classes*.dex 的 APK）",
            apk.display()
        )
    });

    let listing = bitflip_loader::list_zip_members(&bytes).expect("列出 APK 成员");
    let mut dex_members: Vec<_> = listing
        .members
        .iter()
        .filter(|m| m.name.ends_with(".dex"))
        .collect();
    dex_members.sort_by(|a, b| a.name.cmp(&b.name));
    assert_eq!(
        dex_members.len(),
        3,
        "样本 APK 里有三个 dex，实际列出：{:?}",
        dex_members.iter().map(|m| &m.name).collect::<Vec<_>>()
    );

    let mut total_classes = 0usize;
    let mut total_methods = 0usize;
    let mut total_with_code = 0usize;
    let mut tolerance_notes: Vec<String> = Vec::new();

    for member in &dex_members {
        let raw = bitflip_loader::read_zip_member(&bytes, member.index)
            .unwrap_or_else(|e| panic!("取出 {} 失败: {e}", member.name));
        let dex = bitflip_loader::parse_dex_structure(&raw)
            .unwrap_or_else(|e| panic!("解析 {} 失败: {e}", member.name));

        // ① 类数 == **头里手读**的 class_defs_size（不是我们自己的声明值抄一遍）
        let hand_read = fixture::hand_read_class_defs_size(&raw);
        assert_eq!(
            dex.class_count(),
            hand_read as usize,
            "{}: 类数与头里手读的 class_defs_size 不符",
            member.name
        );

        // ② 六个池：声明 == 实际
        assert!(
            dex.counts.mismatches.is_empty(),
            "{}: 计数不符 {:?}",
            member.name,
            dex.counts.mismatches
        );

        // ③ 符号总数 == class_data 四个计数之和
        assert_eq!(
            dex.symbols_declared_in_class_data(),
            (dex.field_count() + dex.method_count()) as u64,
            "{}: 符号数与 class_data 计数之和不符 —— 说明有类被漏掉了",
            member.name
        );

        // ④ 每个类都能取到描述符，且字段/方法区间落在表内
        for (i, class) in dex.classes.iter().enumerate() {
            assert!(
                dex.class_descriptor(i).is_some(),
                "{}: 第 {i} 个类的描述符取不到",
                member.name
            );
            assert!(
                class.field_range().end <= dex.field_count(),
                "{}: 类的字段区间越界",
                member.name
            );
            assert!(
                class.method_range().end <= dex.method_count(),
                "{}: 类的方法区间越界",
                member.name
            );
        }

        // ⑤ 方法的总区间必须**恰好**铺满方法表（既不重叠也不留缝）
        let mut next = 0usize;
        for class in &dex.classes {
            assert_eq!(
                class.method_range().start,
                next,
                "{}: 方法区间有缝或重叠",
                member.name
            );
            next = class.method_range().end;
        }
        assert_eq!(
            next,
            dex.method_count(),
            "{}: 方法表没有被铺满",
            member.name
        );

        total_classes += dex.class_count();
        total_methods += dex.method_count();
        total_with_code += dex.method_count_with_code();
        for note in &dex.notes {
            tolerance_notes.push(format!("{}: {note}", member.name));
        }

        // 数据层输出：不只看绿灯，也看数（§7）
        println!(
            "  {} : {} 字节，类 {}，字段 {}，方法 {}（其中带字节码 {}），字符串池声明 {}",
            member.name,
            raw.len(),
            dex.class_count(),
            dex.field_count(),
            dex.method_count(),
            dex.method_count_with_code(),
            dex.counts.declared.strings
        );
    }

    println!("  合计：类 {total_classes}，方法 {total_methods}（带字节码 {total_with_code}）");

    // 三个 dex 的类数之和（M0 阶段手读过的值，写在这里当独立对照）。
    assert_eq!(
        total_classes,
        7643 + 8833 + 6462,
        "三个 dex 的类数之和与手读值不符"
    );

    // 真实世界里规范会被违反，而**容忍不等于没发生**：样本里就有一条
    // string_ids 乱序。这里钉住它，避免哪天"没人报告"被误当成"文件合规"。
    assert!(
        tolerance_notes.iter().any(|n| n.contains("StringIds")),
        "样本的 string_ids 乱序应当被如实记进 notes，实际：{tolerance_notes:?}"
    );
    for note in &tolerance_notes {
        println!("  note: {note}");
    }
}

/// M1 验收里被推迟的**第一条**：指令 ∪ 载荷必须**恰好铺满** `[0, insns_size)`。
///
/// 为什么这条非跑真实字节码不可：它是唯一一条**能独立于库验证库的宽度表**的检查 ——
/// 只借库给的地址，长度一律按规范从原始字节重算。宽度表里错一个码元，
/// 后面所有指令的地址就全错位，这里就会报洞或越界；而用库的长度去验证库的长度，
/// 无论库错得多离谱都会"通过"。
///
/// 代价：三个 dex 上共约 14 万个带字节码的方法，每个都要解析一次 `code_item`。
/// debug 下要跑几分钟（M1 记过：析构 `DexFile::parse` 才是大头，这条更贵）。
///
/// 样本不在就**失败**（不是悄悄跳过）：既然有人显式要跑这条测试，
/// "样本没找到"就是它必须报告的那个事实。
#[ignore = "需要本机真实 APK（32MB）；用 --ignored 手动跑"]
#[test]
fn every_real_methods_code_units_are_exactly_tiled_by_instructions_and_payloads() {
    let path = sample_apk();
    let bytes =
        std::fs::read(&path).unwrap_or_else(|e| panic!("读不到真实样本 {}: {e}", path.display()));
    let listing = bitflip_loader::list_zip_members(&bytes).expect("列出 APK 成员");

    let mut dex_members: Vec<_> = listing
        .members
        .iter()
        .filter(|m| m.name.ends_with(".dex"))
        .collect();
    dex_members.sort_by(|a, b| a.name.cmp(&b.name));

    let mut checked_methods = 0usize;
    let mut checked_payloads = 0usize;
    let mut without_code = 0usize;
    let mut problems: Vec<String> = Vec::new();
    let mut rendered_instructions = 0usize;
    let mut unsupported_operands = 0usize;
    let mut unavailable_operands = 0usize;
    let mut sample_text: Option<String> = None;

    for member in &dex_members {
        let raw = bitflip_loader::read_zip_member(&bytes, member.index)
            .unwrap_or_else(|e| panic!("取出 {} 失败: {e}", member.name));
        let dex = bitflip_loader::parse_dex_structure(&raw)
            .unwrap_or_else(|e| panic!("解析 {} 失败: {e}", member.name));

        for method in &dex.methods {
            if !method.has_code() {
                // 抽象 / native 方法本来就没有字节码：如实计数，不算跳过失败。
                without_code += 1;
                continue;
            }
            let check = bitflip_loader::check_code_item_layout(&raw, method.code_off)
                .unwrap_or_else(|e| {
                    panic!(
                        "{}: class_idx={} method_idx={} code_off={:#x} 布局校验失败: {e}",
                        member.name, method.class_index, method.method_idx, method.code_off
                    )
                });
            let view = project_dex_method(&raw, method.code_off).unwrap_or_else(|e| {
                panic!(
                    "{}: class_idx={} method_idx={} code_off={:#x} DEX view projection failed: {e}",
                    member.name, method.class_index, method.method_idx, method.code_off
                )
            });
            assert_eq!(view.instructions.len(), check.instructions);
            assert_eq!(view.payloads.addresses.len(), check.payloads);
            let view_problems = view.consistency_problems();
            assert!(
                view_problems.is_empty(),
                "{}: class_idx={} method_idx={} code_off={:#x} 视图列不对齐（最多列 5 条）：{:?}",
                member.name,
                method.class_index,
                method.method_idx,
                method.code_off,
                view_problems.iter().take(5).collect::<Vec<_>>()
            );
            let cross_problems = view.cross_check_problems();
            assert!(
                cross_problems.is_empty(),
                "{}: class_idx={} method_idx={} code_off={:#x} 指令列与 CFG 不互相印证（最多列 5 条）：{:?}",
                member.name,
                method.class_index,
                method.method_idx,
                method.code_off,
                cross_problems.iter().take(5).collect::<Vec<_>>()
            );
            checked_methods += 1;
            checked_payloads += check.payloads;

            // 符号解析：真实池上跑一遍渲染，异常（索引越界/库拒绝解析）必须是 0。
            // call-site 等已知缺口如实计数，不当成失败 —— 但也绝不静默。
            let mut text = String::new();
            let report =
                render_dex_instructions_with_symbols(&view.instructions, &dex.symbols(), &mut text)
                    .unwrap_or_else(|e| {
                        panic!(
                            "{}: class_idx={} method_idx={} code_off={:#x} 符号渲染失败: {e}",
                            member.name, method.class_index, method.method_idx, method.code_off
                        )
                    });
            rendered_instructions += report.instructions;
            unsupported_operands += report.unsupported_operands;
            unavailable_operands += report.unavailable_operands;
            assert_eq!(
                report.unavailable_operands,
                0,
                "{}: class_idx={} method_idx={} code_off={:#x} 有 {} 处符号解析异常；\
                 输出片段（最多 200 字符）：{}",
                member.name,
                method.class_index,
                method.method_idx,
                method.code_off,
                report.unavailable_operands,
                text.chars().take(200).collect::<String>()
            );
            if sample_text.is_none() && text.contains("->") {
                sample_text = Some(text.clone());
            }

            if !check.is_exact() {
                for p in &check.problems {
                    problems.push(format!(
                        "{}: class_idx={} method_idx={} code_off={:#x} 码元 {} [{}] {}",
                        member.name,
                        method.class_index,
                        method.method_idx,
                        method.code_off,
                        p.at,
                        p.kind.as_str(),
                        p.detail
                    ));
                }
            }
        }
    }

    println!(
        "  检查了 {checked_methods} 个方法的码元布局（含 {checked_payloads} 个载荷）；\
         {without_code} 个方法没有字节码（抽象/native，如实计数不计入检查）"
    );
    println!(
        "  符号渲染：{rendered_instructions} 条指令；已知缺口（如 call-site）\
         {unsupported_operands} 处；解析异常 {unavailable_operands} 处"
    );
    if let Some(text) = &sample_text {
        let sample: String = text.lines().take(8).collect::<Vec<_>>().join("\n    ");
        println!("  首个含符号引用的方法（前 8 行）：\n    {sample}");
    }

    // 设计文档写的验收门槛是"在 3000 个真实方法上 0 不吻合"。真实样本上我们
    // 检查的是全部带字节码的方法（远多于 3000），所以先钉住"确实检查到了量"。
    assert!(
        checked_methods >= 3000,
        "只检查到 {checked_methods} 个方法，样本不对或过滤条件错了"
    );
    assert!(
        problems.is_empty(),
        "{} 个方法的布局不吻合（最多列 10 条）：\n{}",
        problems.len(),
        problems
            .iter()
            .take(10)
            .cloned()
            .collect::<Vec<_>>()
            .join("\n")
    );
}
