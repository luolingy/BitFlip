//! 诊断：展开表候选的名字是否把边界标记泄漏成了"函数名"。
//!
//! 背景：`unwind_candidates` 把结束地址编码进 `name` 字段（约定 `"<name>\t<end>"`），
//! `merge_candidates` 用 `rsplit_once('\t')` 解析边界。如果解析之后没有把标记
//! 从 `name` 里去掉，UI 上就会看到 `"\t91a6"` 这种"名字"当函数名显示 ——
//! 这正是 CLAUDE.md §7 禁止的"用看似识别的结果掩盖实际没识别出来"。

use bitflip_analyze::unwind_candidates;
use bitflip_loader::object::UnwindEntry;

#[test]
fn unwind_marker_must_not_leak_into_the_name() {
    let entries = vec![UnwindEntry {
        begin: 0x140001000,
        end: 0x140001050,
        unwind_info: 0,
    }];

    let cands = unwind_candidates(&entries);
    assert_eq!(cands.len(), 1);
    println!("候选 name = {:?}", cands[0].name);

    let f = bitflip_analyze::merge_candidates(0x140001000, cands.clone());
    println!("合并后 name = {:?}, end = {:?}", f.name, f.end);

    // 边界必须被解析出来
    assert_eq!(f.end, Some(0x140001050), "展开表的边界必须被解析");

    // 而名字必须是空的 —— 展开表不提供名字，不能把 end 标记留在名字里
    assert!(
        f.name.is_empty(),
        "展开表候选的名字应被清空，实际是 {:?}（边界标记泄漏成了函数名）",
        f.name
    );
    assert!(
        !f.name.contains('\t'),
        "函数名里不该出现制表符：{:?}",
        f.name
    );
}
