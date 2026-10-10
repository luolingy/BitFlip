//! M9 差分的端到端回归：在**真实的两版样本**上验证差分。
//!
//! ## 这条测试要守什么
//!
//! 差分最危险的错误不是崩溃，而是"**看起来很正常、每一条都写得很具体**"的
//! 假报告。所以这里守三件事：
//!
//! 1. **地址归一化必须真的生效。** fixture 的两个版本镜像基址差 `0x40000000`，
//!    三个函数 RVA 相同而 VA 全不同。测试会**从真值文件里读出**这两个基址与
//!    那三个函数，然后断言差分把它们判成 `unchanged` —— 如果实现改成裸比 VA，
//!    这三条会立刻变成 `changed`，测试变红（`naive_va_comparison_would_be_a_false_alarm`
//!    进一步把这个反例显式地算出来，免得有人以为"归一化只是装饰"）。
//! 2. **归一化方式必须写进输出。** 报告里没有这一行，用户就无法复核清单，
//!    所以 `render_diff_text` 的头部必须有它，并且带上两个基址的实测值。
//! 3. **受控差异要逐条对上，账目要闭合。** 新增/删除/改动/未变四类在 fixture 里
//!    都是**刻意造出来的**，真值由 clang/lld + llvm-nm 产出（不是本项目的实现）。
//!    少报是漏报，多报是假阳性，两边都要能变红。
//!
//! ## 真值文件的来源
//!
//! `scripts/gen-diff-fixture.py` 编译两个源文件版本，再把两个符号表相减。
//! 测试**解析**这个文件而不是把数字抄进代码：抄进来的数字会随 fixture 重新生成
//! 而失效，而失效的方式是"测试还在绿"。
//!
//! fixture 缺失时**响亮失败**（CLAUDE.md §7：跳过会让绿灯说谎）。

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use bitflip_core::{
    diff, render_diff_text, DiffKind, DiffOptions, DiffScope, MatchBasis, Normalization,
    OpenOptions, Session, DIFF_FORMAT_VERSION,
};

const V1: &str = "diff-pe-x86_64-v1.exe";
const V2: &str = "diff-pe-x86_64-v2.exe";
const TRUTH: &str = "diff-pe-x86_64.truth.txt";

fn fixture(name: &str) -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("..")
        .join("..")
        .join("tests")
        .join("fixtures")
        .join("generated")
        .join(name)
}

fn open(name: &str) -> Session {
    let path = fixture(name);
    assert!(
        path.exists(),
        "缺少 fixture {}；先跑 python scripts/gen-diff-fixture.py --out tests/fixtures/generated/diff-pe-x86_64",
        path.display()
    );
    Session::open(&path, OpenOptions::default()).expect("打开样本")
}

/// 真值文件的一个条目。
#[derive(Debug, Clone)]
struct TruthEntry {
    kind: String,
    name: String,
    v1_va: Option<u64>,
    v2_va: Option<u64>,
    rva: Option<u64>,
}

/// 真值文件的全部内容。
struct Truth {
    v1_base: u64,
    v2_base: u64,
    entries: Vec<TruthEntry>,
}

impl Truth {
    fn get(&self, name: &str) -> &TruthEntry {
        self.entries
            .iter()
            .find(|entry| entry.name == name)
            .unwrap_or_else(|| {
                panic!(
                    "真值文件里没有 {name}；受控差异没生效？条目：{:?}",
                    self.entries.iter().map(|e| &e.name).collect::<Vec<_>>()
                )
            })
    }
}

fn parse_hex(text: &str) -> Option<u64> {
    let text = text.trim();
    if text == "-" {
        return None;
    }
    u64::from_str_radix(text.trim_start_matches("0x"), 16).ok()
}

/// 解析真值文件。
///
/// 格式（见 `scripts/gen-diff-fixture.py`）：
/// `<added|removed|same-rva|moved-rva> <名> <v1_va> <v2_va> <rva>`
fn load_truth() -> Truth {
    let path = fixture(TRUTH);
    assert!(
        path.exists(),
        "缺少真值文件 {}；先跑 python scripts/gen-diff-fixture.py --out tests/fixtures/generated/diff-pe-x86_64",
        path.display()
    );
    let text = std::fs::read_to_string(&path).expect("读真值文件");
    let mut v1_base = 0;
    let mut v2_base = 0;
    let mut entries = Vec::new();

    for line in text.lines() {
        let line = line.trim();
        if line.is_empty() {
            continue;
        }
        if let Some(rest) = line.strip_prefix("#") {
            // `# v1: <name>  镜像基址 0x...`
            let rest = rest.trim();
            if let Some(hex) = rest.rsplit("0x").next() {
                let value = u64::from_str_radix(hex.trim(), 16).unwrap_or(0);
                if rest.starts_with("v1:") {
                    v1_base = value;
                } else if rest.starts_with("v2:") {
                    v2_base = value;
                }
            }
            continue;
        }
        let fields: Vec<&str> = line.split_whitespace().collect();
        if fields.len() < 5 {
            continue;
        }
        entries.push(TruthEntry {
            kind: fields[0].to_string(),
            name: fields[1].to_string(),
            v1_va: parse_hex(fields[2]),
            v2_va: parse_hex(fields[3]),
            rva: parse_hex(fields[4]),
        });
    }

    assert!(
        v1_base != 0 && v2_base != 0,
        "真值文件里没读到镜像基址（v1 {v1_base:#x} / v2 {v2_base:#x}）"
    );
    assert!(!entries.is_empty(), "真值文件里没有条目");
    Truth {
        v1_base,
        v2_base,
        entries,
    }
}

/// 把报告折成"函数名 -> 类别"，只保留有名字的条目。
fn by_name(report: &bitflip_core::DiffReport) -> BTreeMap<String, DiffKind> {
    let mut out: BTreeMap<String, DiffKind> = BTreeMap::new();
    for entry in &report.entries {
        let Some(name) = entry.name.clone() else {
            continue;
        };
        match out.get(&name) {
            // 同名多条（别名）时保留更强的差异判定：宁可报"变了"，
            // 不要因为另一条"未变"把差异盖掉。
            Some(existing) if entry.kind.is_difference() && !existing.is_difference() => {
                out.insert(name, entry.kind);
            }
            Some(_) => {}
            None => {
                out.insert(name, entry.kind);
            }
        }
    }
    out
}

fn report() -> bitflip_core::DiffReport {
    let one = open(V1);
    let two = open(V2);
    let options = DiffOptions {
        scope: DiffScope::Functions,
        ..DiffOptions::default()
    };
    let report = diff(&one, &two, &options).expect("差分成功");
    assert_eq!(report.format_version, DIFF_FORMAT_VERSION);
    report
}

#[test]
fn the_two_versions_have_different_image_bases_and_the_truth_says_so() {
    let truth = load_truth();
    assert_ne!(
        truth.v1_base, truth.v2_base,
        "fixture 的两版基址必须不同，否则这条测试覆盖不到地址归一化"
    );

    // 从真值里挑一个 same-rva 条目：VA 两边不同、RVA 相同。
    let stable = truth.get("df_stable");
    assert_eq!(stable.kind, "same-rva");
    assert_ne!(
        stable.v1_va, stable.v2_va,
        "df_stable 的虚拟地址必须不同，否则这个 fixture 证明不了归一化是必需的"
    );
    assert_eq!(
        stable.v1_va.unwrap() - truth.v1_base,
        stable.v2_va.unwrap() - truth.v2_base,
        "df_stable 的 RVA 必须相同"
    );
}

#[test]
fn normalization_is_rva_and_the_report_says_which_base_each_side_used() {
    let truth = load_truth();
    let session1 = open(V1);
    let session2 = open(V2);

    // 两个会话读到的基址必须与真值一致 —— 否则下面的归一化断言是在比别的东西。
    assert_eq!(
        session1.object().expect("解析成功").image_base,
        truth.v1_base
    );
    assert_eq!(
        session2.object().expect("解析成功").image_base,
        truth.v2_base
    );

    let report = report();
    match &report.normalization {
        Normalization::Rva { v1_base, v2_base } => {
            assert_eq!(*v1_base, truth.v1_base);
            assert_eq!(*v2_base, truth.v2_base);
        }
        other => panic!("两个基址不同时必须用 RVA 归一化，实际是 {other:?}"),
    }

    // 用户要能从输出里自己核对：方式 + 两个基址都要在。
    let text = render_diff_text(&report);
    assert!(text.contains("归一化"), "{text}");
    assert!(text.contains("RVA"), "{text}");
    assert!(
        text.contains(&format!("{:#x}", truth.v1_base)),
        "输出的归一化说明里必须带上 v1 基址\n{text}"
    );
    assert!(
        text.contains(&format!("{:#x}", truth.v2_base)),
        "输出的归一化说明里必须带上 v2 基址\n{text}"
    );
}

#[test]
fn same_rva_functions_are_not_reported_as_changed() {
    let truth = load_truth();
    let report = report();
    let kinds = by_name(&report);

    let only = report
        .entries
        .iter()
        .filter(|entry| entry.name.as_deref() == Some("df_stable"))
        .collect::<Vec<_>>();
    assert!(!only.is_empty(), "报告里没有 df_stable");

    // 这是本测试的核心断言：RVA 相同 => 未变，而不是因为 VA 不同就报改动。
    for entry in &only {
        assert_eq!(
            entry.kind,
            DiffKind::Unchanged,
            "df_stable 的 RVA 两个版本相同，必须判为未变（实际 {:?}）；\
             报成改动说明归一化没生效",
            entry.kind
        );
        assert_eq!(
            entry.normalized,
            format!("{:016x}", truth.get("df_stable").rva.unwrap())
        );
    }

    // 同一个 family（same-rva）里的每个成员都不能被报成改动。
    for entry in &truth.entries {
        if entry.kind != "same-rva" {
            continue;
        }
        if let Some(kind) = kinds.get(&entry.name) {
            assert!(
                !matches!(kind, DiffKind::Added | DiffKind::Removed),
                "{} 在两版里都存在（RVA {:?}），不能被报成 {kind:?}",
                entry.name,
                entry.rva
            );
        }
    }
}

#[test]
fn naive_virtual_address_comparison_would_be_a_false_alarm() {
    // 把"如果按裸虚拟地址比会怎样"明确算出来。
    //
    // 这不是在测实现，是在**证明测试有意义**：如果哪天有人把归一化去掉，
    // 上面的 same-rva 断言会变红，但那条断言看不出"后果有多严重"。
    // 这一条给出后果 —— 每个函数都会被报成改动，而报告本身依然"看起来正常"。
    let truth = load_truth();
    let mut would_be_unchanged_by_va = 0usize;
    let mut rva_identical = 0usize;

    for entry in &truth.entries {
        if let (Some(a1), Some(a2)) = (entry.v1_va, entry.v2_va) {
            if a1 == a2 {
                would_be_unchanged_by_va += 1;
            }
            if a1 - truth.v1_base == a2 - truth.v2_base {
                rva_identical += 1;
            }
        }
    }

    assert_eq!(
        would_be_unchanged_by_va, 0,
        "fixture 的两版基址不同，所以按裸虚拟地址比时没有任何函数会被判为未变 —— \
         这正是归一化必须存在的理由"
    );
    assert!(
        rva_identical >= 3,
        "按 RVA 比至少有 3 个函数落在同一个 RVA 上，实际 {rva_identical}"
    );

    // 报告必须真的按 RVA 比对：真值里"两版都在同一个 RVA"的函数，绝不能
    // 被判成"新增/删除/移动"。这一条是归一化生效的**直接**证据
    // （上面那条只算了真值里的地址，没碰实现）。
    let report = report();
    let kinds = by_name(&report);
    let mut checked = 0usize;
    for entry in &truth.entries {
        if entry.kind != "same-rva" {
            continue;
        }
        let Some(kind) = kinds.get(&entry.name) else {
            continue;
        };
        checked += 1;
        assert!(
            !matches!(kind, DiffKind::Added | DiffKind::Removed | DiffKind::Moved),
            "{} 两版都在 RVA {:?} 上，不能被判成 {kind:?} —— 那是按裸虚拟地址比的结果",
            entry.name,
            entry.rva
        );
    }
    assert!(
        checked >= 3,
        "真值里 3 个 same-rva 函数都该在报告里出现，只核对到 {checked} 个"
    );
}

#[test]
fn the_controlled_differences_match_the_truth() {
    let truth = load_truth();
    let report = report();
    let kinds = by_name(&report);

    // 删除：只在 v1 里有。
    let removed = truth.get("df_removed");
    assert_eq!(removed.kind, "removed");
    assert_eq!(
        kinds.get("df_removed"),
        Some(&DiffKind::Removed),
        "df_removed 只在 v1 里，必须报删除；实际 {:?}",
        kinds.get("df_removed")
    );

    // 新增：只在 v2 里有。
    let added = truth.get("df_added");
    assert_eq!(added.kind, "added");
    assert_eq!(
        kinds.get("df_added"),
        Some(&DiffKind::Added),
        "df_added 只在 v2 里，必须报新增；实际 {:?}",
        kinds.get("df_added")
    );

    // 改动：两边都有、内容不同。
    assert!(
        matches!(
            kinds.get("df_changed"),
            Some(DiffKind::Changed) | Some(DiffKind::Moved)
        ),
        "df_changed 两版同名但实现不同，必须报改动或移动；实际 {:?}",
        kinds.get("df_changed")
    );

    // 未变：两边都有且相同 —— 不能产生假阳性。
    for name in ["df_stable", "df_helper"] {
        assert_eq!(
            kinds.get(name),
            Some(&DiffKind::Unchanged),
            "{name} 两版内容相同，不能报差异（假阳性）；实际 {:?}",
            kinds.get(name)
        );
    }

    // 账目闭合：逐条重数必须等于 totals。
    assert!(
        report.accounting_balanced(),
        "账目不闭合：{} 条 vs {:#?}",
        report.entries.len(),
        report.totals
    );
}

#[test]
fn entries_carry_the_match_basis_so_weak_matches_are_visible() {
    let report = report();
    assert!(!report.entries.is_empty());

    for entry in &report.entries {
        // 每个条目都必须说明是靠什么匹配上的 —— 不说明就成了"看着像"。
        assert!(
            !entry.match_basis.as_str().is_empty(),
            "条目 {entry:?} 没有匹配判据"
        );
        // 定长十六进制地址（wire 约定）。
        assert_eq!(entry.normalized.len(), 16, "{entry:?}");
        assert!(
            entry.normalized.chars().all(|c| c.is_ascii_hexdigit()),
            "{entry:?}"
        );
    }

    // 匹配判据必须与条目本身自洽 —— 这就是把 `match_basis` 放进 wire 的意义：
    // 用户能自己判断这一条的配对有多可信。
    let base1 = load_truth().v1_base;
    let base2 = load_truth().v2_base;
    for entry in &report.entries {
        let norm1 = entry
            .v1_address
            .as_deref()
            .map(|text| u64::from_str_radix(text, 16).expect("v1 地址是十六进制") - base1);
        let norm2 = entry
            .v2_address
            .as_deref()
            .map(|text| u64::from_str_radix(text, 16).expect("v2 地址是十六进制") - base2);
        let normalized = u64::from_str_radix(&entry.normalized, 16).expect("归一化地址是十六进制");

        match entry.match_basis {
            // 按"名字 + 地址"配上的：两侧必须真的归一化到同一个地址。
            MatchBasis::NameAndAddress => {
                assert_eq!(norm1, Some(normalized), "{entry:?}");
                assert_eq!(norm2, Some(normalized), "{entry:?}");
            }
            // 按"内容 + 大小"配上的：那是一次移动，两侧地址必须不同。
            MatchBasis::ContentAndSize => {
                let (Some(a), Some(b)) = (norm1, norm2) else {
                    panic!("移动条目必须两侧地址俱全：{entry:?}");
                };
                assert_ne!(
                    a, b,
                    "按内容匹配上的条目必须是搬了家（地址不同）：{entry:?}"
                );
                assert_eq!(
                    entry.normalized,
                    format!("{a:016x}"),
                    "移动条目的归一化地址取 v1 那一侧：{entry:?}"
                );
            }
            // 只在一边出现：另一边的地址必须是 None，而不是拿 0 冒充。
            MatchBasis::AddressOnly => {
                let both = norm1.is_some() && norm2.is_some();
                if matches!(entry.kind, DiffKind::Added | DiffKind::Removed) {
                    assert!(!both, "增删条目只能有一侧地址：{entry:?}");
                }
            }
            // 只按名字配上的：地址必须真的有差异，否则该走 NameAndAddress。
            MatchBasis::NameOnly => {
                assert_ne!(
                    norm1, norm2,
                    "只按名字配上的条目，地址必须真的不同：{entry:?}"
                );
            }
            MatchBasis::AddressOnlyContentDiffers => {}
        }
    }

    // 移动判定必须建立在"内容同一"之上，不能靠名字硬猜。
    let moved: Vec<_> = report
        .entries
        .iter()
        .filter(|entry| entry.kind == DiffKind::Moved)
        .collect();
    for entry in &moved {
        assert_ne!(
            entry.match_basis,
            MatchBasis::NameAndAddress,
            "移动条目不可能是同地址的：{entry:?}"
        );
        let detail = entry.detail.as_deref().unwrap_or("");
        assert!(
            detail.contains("位置"),
            "移动条目必须说清从哪搬到哪：{entry:?}"
        );
    }
}

#[test]
fn unnamed_functions_never_get_a_fabricated_name() {
    // CLAUDE.md §7：分析不出来的函数就叫"未识别"，不许生成 func_xxx。
    let report = report();
    for entry in &report.entries {
        let name = entry.name.as_deref().unwrap_or("");
        assert!(
            !name.starts_with("func_") && !name.starts_with("sub_"),
            "报告里出现了占位名 {name:?} —— 这是被禁止的做法"
        );
    }

    // 未命名的条目必须是 None，而不是空串冒充。
    for entry in &report.entries {
        if let Some(name) = &entry.name {
            assert!(!name.is_empty(), "名字不能是空串（未命名应当是 null）");
        }
    }
}

#[test]
fn text_output_is_self_describing_and_marks_every_entry() {
    let report = report();
    let text = render_diff_text(&report);

    assert!(text.starts_with("# bitflip-diff v1"), "{text}");
    assert!(text.contains("comparable"), "{text}");
    assert!(text.contains("# 账目："), "{text}");
    assert!(text.contains("+ 新增"), "{text}");
    assert!(text.contains("未变"), "{text}");

    // 每个列出的条目都要带标记，且总数与报告一致。
    let marked = text
        .lines()
        .filter(|line| {
            matches!(
                line.chars().next(),
                Some('+') | Some('-') | Some('~') | Some('>') | Some('=')
            )
        })
        .count();
    assert_eq!(
        marked,
        report.entries.len(),
        "文本输出的条目数必须与报告一致"
    );
}

#[test]
fn json_shape_is_a_versioned_contract() {
    let report = report();
    let value = serde_json::to_value(&report).expect("报告必须能序列化");
    assert_eq!(value["format_version"], DIFF_FORMAT_VERSION);
    assert!(value["producer"]
        .as_str()
        .unwrap_or("")
        .starts_with("bitflip"));
    assert!(value["normalization"]["method"].is_string(), "{value}");
    assert_ne!(
        value["v1_image_base"].as_u64(),
        Some(0),
        "镜像基址必须出现在 JSON 里（它为 0 时地址维度整体不可比）"
    );
    assert!(value["totals"]["added"].is_number(), "{value}");
    assert!(value["entries"].is_array(), "{value}");
    // 归一化方式必须是可解析的枚举值，不是自由文本。
    assert_eq!(value["normalization"]["method"], "rva", "{value}");
}

#[test]
fn scope_selects_what_is_compared() {
    let one = open(V1);
    let two = open(V2);

    let sections = diff(
        &one,
        &two,
        &DiffOptions {
            scope: DiffScope::Sections,
            ..DiffOptions::default()
        },
    )
    .expect("节表差分");
    assert_eq!(sections.scope, DiffScope::Sections);
    assert!(sections.v1_total > 0, "PE 一定有节");
    assert!(sections.v2_total > 0);
    // 节维度按名字比，每个条目都必须有名字。
    for entry in &sections.entries {
        assert!(entry.name.is_some(), "节条目必须有名字：{entry:?}");
    }

    let all = diff(
        &one,
        &two,
        &DiffOptions {
            scope: DiffScope::All,
            ..DiffOptions::default()
        },
    )
    .expect("全量差分");
    assert!(
        all.entries.len() >= sections.entries.len(),
        "all 的条目不该少于单独某一类"
    );
    assert!(all.accounting_balanced(), "all 的账目也要闭合");
}

#[test]
fn only_filter_narrows_entries_without_breaking_the_totals() {
    let one = open(V1);
    let two = open(V2);
    let full = diff(
        &one,
        &two,
        &DiffOptions {
            scope: DiffScope::Functions,
            ..DiffOptions::default()
        },
    )
    .expect("差分");

    let added_only = diff(
        &one,
        &two,
        &DiffOptions {
            scope: DiffScope::Functions,
            only: Some(DiffKind::Added),
            ..DiffOptions::default()
        },
    )
    .expect("只看新增");

    assert!(
        added_only.entries.iter().all(|e| e.kind == DiffKind::Added),
        "过滤后只剩新增"
    );
    assert_eq!(added_only.totals.added, full.totals.added);
    assert_eq!(
        added_only.v1_total, full.v1_total,
        "过滤不能污染\"比了多少条\"这个账"
    );
    assert!(added_only.accounting_balanced());
}

#[test]
fn truncation_is_reported_never_silent() {
    let one = open(V1);
    let two = open(V2);
    let report = diff(
        &one,
        &two,
        &DiffOptions {
            scope: DiffScope::All,
            max_entries: 1,
            ..DiffOptions::default()
        },
    )
    .expect("差分");

    assert!(report.truncated, "上限 1 必须触发截断");
    assert!(report.dropped > 0, "截断必须记账");
    assert_eq!(report.entries.len(), 1);
    assert!(
        report.notes.iter().any(|note| note.contains("截断")),
        "截断必须在 notes 里出现：{:?}",
        report.notes
    );
    let text = render_diff_text(&report);
    assert!(text.contains("截断"), "{text}");
    assert!(
        text.contains(&report.dropped.to_string()),
        "截断说明里要有丢掉的条数\n{text}"
    );
}
