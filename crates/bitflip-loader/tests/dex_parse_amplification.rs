//! DEX 的放大攻击面：计数被编大时必须**先报错、不分配**。
//!
//! 这件事以前在 `parse` 的文档里记的是"已知缺口：恶意构造的 DEX 可以靠超大计数
//! 把内存顶上去"。实测那句话**后半不成立** —— 库在每个 `Vec::with_capacity`
//! 之前都用 `droidsaw_common::guard::bound_count` 把"声明了多少项"与"这份输入
//! 按最小记录宽度最多装得下多少项"相除比对，超出就先报错。
//!
//! 但那是**库的行为**，不是我们的：库升级、开关一改就可能没了，而症状会是线上
//! 内存被打满 —— 离改这一行代码的那个 PR 已经很远。所以这里把每个计数字段
//! 逐个钉住：红在这条测试上，而不是红在内存里。
//!
//! # 样本怎么造
//!
//! 从合成样本出发，改**一个**头部计数字段，然后 `fixture::resign` 重算
//! SHA-1 + Adler-32。不重新签名的话，解析器在读到计数**之前**就因为校验和
//! 不对而拒绝 —— 测试看着是绿的（确实报错了），但验证的是校验和，不是计数守卫。
//!
//! 另一处坑：六个 id 区段之间还有"互不重叠"检查，而一个 `0xFFFF_FFFF` 的计数
//! 会把后面所有区段都罩住，于是先报 `SectionOverlap`。要钉计数守卫，样本里
//! **只留一个区段**（其余计数清零），不然轮不到 `bound_count`。

#[path = "common/dex_fixture.rs"]
#[allow(dead_code)]
mod fixture;

use std::time::{Duration, Instant};

use bitflip_loader::{parse_dex_structure, project_dex_method, DexParseError, DexStructure};

/// 头里六个计数字段的偏移（规范 §3.1：`string_ids_size` 在 `0x38`，
/// 每个 `*_size` 后面紧跟 `*_off`，所以整组步长 8 字节）。
const COUNT_FIELDS: [(&str, usize); 6] = [
    ("string_ids_size", 0x38),
    ("type_ids_size", 0x40),
    ("proto_ids_size", 0x48),
    ("field_ids_size", 0x50),
    ("method_ids_size", 0x58),
    ("class_defs_size", 0x60),
];

/// `string_ids_size` 的偏移与 `string_id_item` 的字节宽度（规范 §4.1）。
const STRING_IDS_SIZE: usize = 0x38;
const STRING_ID_ITEM_SIZE: usize = 4;

/// 一份"只有一个池的计数被改成 `value`、别的池都空着"的样本。
fn only_pool_count(off: usize, value: u32) -> Vec<u8> {
    let mut bytes = fixture::build();
    for (_, other) in COUNT_FIELDS {
        fixture::patch_u32(&mut bytes, other, 0);
    }
    fixture::patch_u32(&mut bytes, off, value);
    fixture::resign(&mut bytes);
    bytes
}

/// 解析一次并计时；畸形输入**不许 panic**（那是把"文件坏"变成"进程没了"）。
fn parse_timed(bytes: &[u8]) -> (Result<DexStructure, DexParseError>, Duration) {
    let started = Instant::now();
    let outcome = std::panic::catch_unwind(|| parse_dex_structure(bytes));
    let elapsed = started.elapsed();
    let result = outcome.unwrap_or_else(|_| panic!("解析畸形输入时 panic 了"));
    (result, elapsed)
}

fn expect_error(result: Result<DexStructure, DexParseError>, label: &str) -> DexParseError {
    match result {
        Ok(_) => panic!("{label}: 这份样本应该被拒绝，却解析成功了"),
        Err(error) => error,
    }
}

#[test]
fn every_pool_count_rejects_a_claim_the_input_cannot_hold() {
    for (label, off) in COUNT_FIELDS {
        let bytes = only_pool_count(off, u32::MAX);
        let (result, elapsed) = parse_timed(&bytes);
        let error = expect_error(result, label);
        match error {
            DexParseError::CountExceeded { item, got, max } => {
                assert_eq!(
                    got,
                    u64::from(u32::MAX),
                    "{label}: 报出来的应该是头里那个数"
                );
                assert!(
                    max <= bytes.len(),
                    "{label}: 物理上限 {max} 不该超过文件字节数 {}",
                    bytes.len()
                );
                assert!(!item.is_empty(), "{label}: 得说清是哪一段");
            }
            other => panic!("{label}: 期望 CountExceeded（计数守卫），得到 {other:?}"),
        }
        assert!(
            elapsed < Duration::from_secs(1),
            "{label}: 拒绝用了 {elapsed:?} —— 看起来是先分配了再报错"
        );
    }
}

#[test]
fn the_count_guard_is_a_boundary_not_a_magic_number() {
    // 只留 string_ids 一段、计数清零，先量出这份样本能装下多少项。
    let probe = only_pool_count(STRING_IDS_SIZE, 0);
    let max = probe.len() / STRING_ID_ITEM_SIZE;

    // 边界值：恰好装得下 → **计数守卫放行**。样本里没有真的 145 个 string_id_item，
    // 所以它随后会因为读到越界的字符串偏移而失败 —— 那是另一条校验，不是这条。
    // 这条断言只管一件事：守卫的阈值是 `文件字节数 / 4`，不是某个拍出来的数。
    let fits = only_pool_count(STRING_IDS_SIZE, u32::try_from(max).expect("样本很小"));
    let (result, elapsed) = parse_timed(&fits);
    if let Err(error) = &result {
        assert!(
            !matches!(error, DexParseError::CountExceeded { .. }),
            "计数 {max} 恰好装得下，计数守卫不该拦：{error:?}"
        );
    }
    assert!(
        elapsed < Duration::from_secs(1),
        "解析合成样本用了 {elapsed:?}"
    );

    // 多一项就必须在**分配之前**被拦下，且报出的上限正是 max。
    let one_more = only_pool_count(STRING_IDS_SIZE, u32::try_from(max + 1).expect("样本很小"));
    let error = expect_error(parse_timed(&one_more).0, "max+1");
    match error {
        DexParseError::CountExceeded {
            got, max: reported, ..
        } => {
            assert_eq!(got, (max + 1) as u64);
            assert_eq!(
                reported, max,
                "上限应当是 文件字节数 / 4 = {max}，报的是 {reported}"
            );
        }
        other => panic!("期望 CountExceeded，得到 {other:?}"),
    }
}

#[test]
fn a_count_that_swallows_the_other_sections_is_rejected_too() {
    // 只改一个字段、不动区段偏移（最省事的伪造手法）：`string_ids` 的区间会罩住
    // 后面所有区段。这条由"互不重叠"守卫拦下 —— 同样要在分配之前。
    let mut bytes = fixture::build();
    fixture::patch_u32(&mut bytes, STRING_IDS_SIZE, u32::MAX);
    fixture::resign(&mut bytes);
    let (result, elapsed) = parse_timed(&bytes);
    let _ = expect_error(result, "overlap");
    assert!(
        elapsed < Duration::from_secs(1),
        "互不重叠检查用了 {elapsed:?}"
    );
}

#[test]
fn an_instruction_count_that_cannot_fit_does_not_allocate() {
    let bytes = fixture::build();
    let structure = parse_dex_structure(&bytes).expect("合成样本必须能解析");
    let code_off = structure
        .methods
        .iter()
        .find(|method| method.code_off != 0)
        .map(|method| method.code_off)
        .expect("合成样本里应当有带字节码的方法");

    // `insns_size` 在 `code_item` 的 +12（规范 §4.5.12）。
    let mut patched = bytes.clone();
    let insns_size_off = usize::try_from(code_off).expect("样本很小") + 12;
    fixture::patch_u32(&mut patched, insns_size_off, u32::MAX);
    fixture::resign(&mut patched);

    let started = Instant::now();
    let outcome = std::panic::catch_unwind(|| project_dex_method(&patched, code_off));
    let elapsed = started.elapsed();
    let result = outcome.unwrap_or_else(|_| panic!("解码畸形 code_item 时 panic 了"));
    let error = match result {
        Ok(_) => panic!("insns_size 编成 0xFFFFFFFF 却解码成功了"),
        Err(error) => error,
    };
    assert!(
        matches!(&error, bitflip_loader::DexViewError::Parse { code_off: reported, .. } if *reported == code_off),
        "期望 DexViewError::Parse（code_off={code_off:#x}），得到 {error:?}"
    );
    assert!(
        elapsed < Duration::from_secs(1),
        "解码拒绝用了 {elapsed:?} —— 看起来是按 insns_size 预分配了"
    );
}
