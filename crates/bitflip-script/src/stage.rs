//! 脚本的写入暂存区。
//!
//! # 为什么脚本不能直接写工程库
//!
//! PLAN §M7 验收 2 要求"死循环脚本可被中断，不影响主进程"。真正危险的不是
//! 死循环本身，而是**死循环发生在一个批处理写到一半的时候**：如果脚本已经
//! 改掉了前 300 个函数的名字然后被掐断，用户看到的是一个**看起来完成了的
//! 半成品** —— 这正是 CLAUDE.md §7 明令禁止的失效模式。
//!
//! 所以脚本的写入先落在内存里，等脚本**正常结束**了才提交。要么全写，要么
//! 一条都不写。代价是脚本不能"边跑边看到结果"，收益是任何中断都不会留下
//! 半成品 —— 对批处理脚本来说后者重要得多。

use std::collections::BTreeMap;

use bitflip_core::{Annotation, AnnotationKind};

/// 一次脚本运行期间的写入缓冲。
///
/// 按 `(地址, 类别)` 去重，与工程库 `UNIQUE(address, kind)` 的约束一致：
/// 这样"暂存 12 条"与"落库 12 条"是同一个数，不会因为脚本重复写而虚高。
#[derive(Debug, Default)]
pub struct StagedWrites {
    items: BTreeMap<(u64, String), Annotation>,
}

impl StagedWrites {
    /// 空缓冲。
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// 暂存一条写入。同 `(地址, 类别)` 后写胜出 —— 与脚本里连续两次赋值
    /// 的直觉一致，也与工程库的 upsert 语义一致。
    pub fn stage(&mut self, annotation: Annotation) {
        let key = (annotation.address, annotation.kind.as_str().to_string());
        self.items.insert(key, annotation);
    }

    /// 暂存条数（去重后）。
    #[must_use]
    pub fn len(&self) -> usize {
        self.items.len()
    }

    /// 是否为空。
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.items.is_empty()
    }

    /// 查询暂存内容。
    ///
    /// 脚本读自己刚写的东西必须走这里：否则"先看有没有名字、没有才命名"这类
    /// 脚本会看不到自己的写入，于是重复劳动或做出错误判断。
    #[must_use]
    pub fn get(&self, address: u64, kind: AnnotationKind) -> Option<&Annotation> {
        self.items.get(&(address, kind.as_str().to_string()))
    }

    /// 按地址列出暂存内容（跨类别）。
    #[must_use]
    pub fn at(&self, address: u64) -> Vec<&Annotation> {
        self.items
            .values()
            .filter(|a| a.address == address)
            .collect()
    }

    /// 遍历（地址升序，类别按短名字典序 —— 顺序稳定，便于测试与展示）。
    pub fn iter(&self) -> impl Iterator<Item = &Annotation> {
        self.items.values()
    }

    /// 取出全部暂存并清空。
    ///
    /// 提交时用这个而不是 `iter()`：先原子的把内容搬出来，再逐个写库，
    /// 这样"写库途中失败"不会让缓冲处于半清空状态 —— 失败路径要么报出
    /// 已写多少，要么整体丢弃，不会留下一个说不清的中间态。
    pub fn take_all(&mut self) -> Vec<Annotation> {
        std::mem::take(&mut self.items).into_values().collect()
    }

    /// 清空（中断/失败时丢弃全部暂存）。
    pub fn clear(&mut self) {
        self.items.clear();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn comment(addr: u64, text: &str) -> Annotation {
        Annotation::text(addr, AnnotationKind::Comment, text)
    }

    #[test]
    fn staging_the_same_slot_twice_keeps_only_the_last_write() {
        let mut s = StagedWrites::new();
        s.stage(comment(0x1000, "第一次"));
        s.stage(comment(0x1000, "第二次"));
        assert_eq!(s.len(), 1, "同 (地址, 类别) 必须去重，否则暂存数会虚高");
        assert_eq!(
            s.get(0x1000, AnnotationKind::Comment)
                .unwrap()
                .text
                .as_deref(),
            Some("第二次")
        );
    }

    #[test]
    fn different_kinds_at_the_same_address_are_separate_slots() {
        let mut s = StagedWrites::new();
        s.stage(comment(0x1000, "注释"));
        s.stage(Annotation::text(0x1000, AnnotationKind::Name, "名字"));
        assert_eq!(s.len(), 2, "同一地址的注释与名字是两个槽位");
        assert_eq!(s.at(0x1000).len(), 2);
    }

    #[test]
    fn a_staged_write_is_visible_to_the_script_that_made_it() {
        let mut s = StagedWrites::new();
        s.stage(comment(0x2000, "刚写的"));
        assert!(
            s.get(0x2000, AnnotationKind::Comment).is_some(),
            "读自己的写入必须命中暂存区，否则'没有才命名'的脚本会重复劳动"
        );
        assert!(s.get(0x2001, AnnotationKind::Comment).is_none());
    }

    #[test]
    fn clearing_drops_everything() {
        let mut s = StagedWrites::new();
        s.stage(comment(1, "a"));
        s.stage(comment(2, "b"));
        s.clear();
        assert!(s.is_empty());
        assert_eq!(s.len(), 0);
    }
}
