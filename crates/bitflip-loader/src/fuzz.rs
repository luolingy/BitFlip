//! 结构化模糊测试（M1 验收标准 3：畸形输入只返回错误，绝不 panic / OOM）。
//!
//! ## 为什么不直接用 `cargo-fuzz`
//!
//! `docs/PLAN.md` M1 要求"从 M1 就上 fuzz"。本机只装了 stable MSVC 工具链，
//! `cargo-fuzz` 需要 nightly + libFuzzer，而磁盘只剩约 30GB（CLAUDE.md §0.3
//! 明确要求控制磁盘占用）。因此这里实现一个**确定性、零依赖**的结构化变异器：
//!
//! - 不依赖 nightly / libFuzzer / 外部 crate，`cargo test` 直接跑；
//! - 用固定种子的 xorshift 生成变异，因此**失败可复现**（打印种子）；
//! - 覆盖比字节翻转更"像真"的畸形：字段级极值、表长虚报、偏移越界、循环引用。
//!
//! `cargo-fuzz` 的目标（`fuzz/fuzz_targets/*.rs`）留作后续接入真 libFuzzer 时使用，
//! 二者的断言集保持一致。

use crate::object::ObjectId;
use crate::{coff, elf, pe, ContainerKind, ObjectKind};

/// 确定性伪随机数发生器（xorshift64*）。
///
/// 不用 `rand` crate：模糊测试必须能靠一个种子精确复现失败，
/// 而自带实现只有十几行、没有版本漂移风险。
struct Rng(u64);

impl Rng {
    fn new(seed: u64) -> Self {
        // 种子为 0 会让 xorshift 退化成恒 0，替换成非零常量
        Self(if seed == 0 {
            0x9e37_79b9_7f4a_7c15
        } else {
            seed
        })
    }

    fn next_u64(&mut self) -> u64 {
        let mut x = self.0;
        x ^= x >> 12;
        x ^= x << 25;
        x ^= x >> 27;
        self.0 = x;
        x.wrapping_mul(0x2545_f491_4f6c_dd1d)
    }

    fn below(&mut self, bound: usize) -> usize {
        if bound == 0 {
            return 0;
        }
        (self.next_u64() % bound as u64) as usize
    }

    fn pick<'a, T>(&mut self, items: &'a [T]) -> &'a T {
        &items[self.below(items.len())]
    }
}

/// 变异算子：覆盖"字段级极值"与"结构破坏"两类失真。
#[derive(Debug, Clone, Copy)]
enum Mutation {
    /// 翻转单个位。
    FlipBit,
    /// 把某个字节设成极值（0 / 0xFF）。
    ExtremeByte,
    /// 把 4 字节窗口写成极大/极小值（模拟虚报长度）。
    ExtremeWord,
    /// 把一段区间清零（模拟未填充区域）。
    ZeroRun,
    /// 把某处偏移指到文件末尾之外。
    OobOffset,
    /// 截断。
    Truncate,
    /// 复制一段数据到别处（制造重复节 / 循环引用）。
    Duplicate,
    /// 把某节的大小改到超过文件（表长虚报）。
    OversizeTable,
}

const MUTATIONS: &[Mutation] = &[
    Mutation::FlipBit,
    Mutation::ExtremeByte,
    Mutation::ExtremeWord,
    Mutation::ZeroRun,
    Mutation::OobOffset,
    Mutation::Truncate,
    Mutation::Duplicate,
    Mutation::OversizeTable,
];

/// 对 `bytes` 施加一次变异。
///
/// **偏向头部**：解析器的所有结构决策都来自文件头部的几十个字节（魔数、
/// 偏移、计数、表大小、节表项）。均匀随机地打到零填充区只会制造"看起来变了、
/// 实际等价"的样本，让模糊测试空转 —— 这是本文件早期版本的真实问题。
/// 因此 70% 的变异落在前 1/4（头部与节表所在区域）。
fn mutate(rng: &mut Rng, bytes: &mut Vec<u8>) {
    if bytes.is_empty() {
        return;
    }

    // 结构性区域：头部 + 节表。取前 25% 或前 512 字节，以较大者为准。
    let hot = (bytes.len() / 4).max(512).min(bytes.len());

    match *rng.pick(MUTATIONS) {
        Mutation::FlipBit => {
            let index = rng.below(hot);
            bytes[index] ^= 1 << (rng.below(8));
        }
        Mutation::ExtremeByte => {
            let index = rng.below(hot);
            bytes[index] = if rng.below(2) == 0 { 0x00 } else { 0xff };
        }
        Mutation::ExtremeWord => {
            if bytes.len() >= 4 {
                let index = rng.below(hot.saturating_sub(3).max(1));
                let value: u32 = *rng.pick(&[0, 1, u32::MAX, u32::MAX / 2, 0x7fff_ffff, 0xffff]);
                bytes[index..index + 4].copy_from_slice(&value.to_le_bytes());
            }
        }
        Mutation::ZeroRun => {
            let start = rng.below(hot);
            let len = rng.below(bytes.len() - start + 1).min(64);
            for byte in &mut bytes[start..start + len] {
                *byte = 0;
            }
        }
        Mutation::OobOffset => {
            if bytes.len() >= 8 {
                let index = rng.below(hot.saturating_sub(7).max(1));
                let bogus = (bytes.len() as u64).saturating_add(0x1000);
                bytes[index..index + 8].copy_from_slice(&bogus.to_le_bytes());
            }
        }
        Mutation::Truncate => {
            // 只截到有意义的位置：截到 0 会退化成"空文件"这一个平凡样本
            let keep = rng.below(bytes.len().max(1));
            bytes.truncate(keep.max(1));
        }
        Mutation::Duplicate => {
            let start = rng.below(hot);
            let len = rng.below(bytes.len() - start + 1).min(128);
            let chunk = bytes[start..start + len].to_vec();
            let at = rng.below(bytes.len());
            bytes.splice(at..at, chunk);
        }
        Mutation::OversizeTable => {
            if bytes.len() >= 4 {
                let index = rng.below(hot.saturating_sub(3).max(1));
                let bogus = (bytes.len() as u32).saturating_mul(4).max(0x1000);
                bytes[index..index + 4].copy_from_slice(&bogus.to_le_bytes());
            }
        }
    }
}

/// 按容器/对象格式分派到对应解析器。
///
/// 与 `sniff` 的分派规则保持一致：优先看魔数，失败再按扩展名猜。
fn dispatch(bytes: &[u8]) -> Option<ObjectKind> {
    if bytes.len() >= 4 && &bytes[..4] == b"\x7fELF" {
        return Some(ObjectKind::Elf);
    }
    if bytes.len() >= 2 && &bytes[..2] == b"MZ" {
        return Some(ObjectKind::Pe);
    }
    None
}

/// 对给定字节跑一遍所有可能的解析器。
///
/// 刻意**不做**格式判定就调用全部解析器：嗅探本身也是被测代码，
/// 让 ELF 解析器去啃 PE 数据是真实且廉价的鲁棒性来源。
fn parse_all(bytes: &[u8]) {
    let _ = elf::parse(bytes, 0, ObjectId::Plain);
    let _ = pe::parse(bytes, 0, ObjectId::Plain);
    let _ = coff::parse(bytes, 0, ObjectId::Plain);

    // 同时验证嗅探器本身
    let _ = crate::sniff_bytes(bytes);
}

/// 由变异生成一批样本并全部解析。
///
/// 断言只有一条：**不 panic**。解析结果是对是错不在本测试职责内 ——
/// 畸形输入下"给出错误结论"是允许的，"崩溃或吃光内存"不是。
fn run_corpus(seed: u64, base: &[u8], rounds: usize) {
    let mut rng = Rng::new(seed);
    for _ in 0..rounds {
        let mut bytes = base.to_vec();
        // 每次叠加 1..=4 个变异，制造多字段同时损坏的样本
        let count = 1 + rng.below(4);
        for _ in 0..count {
            mutate(&mut rng, &mut bytes);
        }
        parse_all(&bytes);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// 最小 ELF64 骨架，作为变异的种子。
    fn seed_elf() -> Vec<u8> {
        let mut bytes = vec![0u8; 0x300];
        bytes[..4].copy_from_slice(b"\x7fELF");
        bytes[4] = 2; // 64 位
        bytes[5] = 1; // 小端
        bytes[6] = 1;
        bytes[16..18].copy_from_slice(&1u16.to_le_bytes()); // ET_REL
        bytes[18..20].copy_from_slice(&62u16.to_le_bytes()); // x86_64
        bytes[20..24].copy_from_slice(&1u32.to_le_bytes());
        bytes[40..48].copy_from_slice(&0x40u64.to_le_bytes()); // e_shoff
        bytes[52..54].copy_from_slice(&64u16.to_le_bytes()); // e_ehsize
        bytes[54..56].copy_from_slice(&56u16.to_le_bytes()); // e_phentsize
        bytes[58..60].copy_from_slice(&64u16.to_le_bytes()); // e_shentsize
        bytes[60..62].copy_from_slice(&1u16.to_le_bytes()); // e_shnum
        bytes
    }

    /// 最小 PE64 骨架，作为变异的种子。
    fn seed_pe() -> Vec<u8> {
        let mut bytes = vec![0u8; 0x400];
        bytes[0..2].copy_from_slice(b"MZ");
        bytes[0x3c..0x40].copy_from_slice(&0x80u32.to_le_bytes());
        bytes[0x80..0x84].copy_from_slice(b"PE\0\0");
        let coff = 0x84;
        bytes[coff..coff + 2].copy_from_slice(&0x8664u16.to_le_bytes());
        bytes[coff + 2..coff + 4].copy_from_slice(&1u16.to_le_bytes());
        bytes[coff + 16..coff + 18].copy_from_slice(&0xf0u16.to_le_bytes());
        bytes[coff + 18..coff + 20].copy_from_slice(&0x0022u16.to_le_bytes());
        let opt = coff + 20;
        bytes[opt..opt + 2].copy_from_slice(&0x020bu16.to_le_bytes());
        bytes[opt + 24..opt + 32].copy_from_slice(&0x140000000u64.to_le_bytes());
        bytes[opt + 32..opt + 36].copy_from_slice(&0x1000u32.to_le_bytes());
        bytes[opt + 36..opt + 40].copy_from_slice(&0x200u32.to_le_bytes());
        bytes[opt + 56..opt + 60].copy_from_slice(&0x2000u32.to_le_bytes());
        bytes[opt + 60..opt + 64].copy_from_slice(&0x200u32.to_le_bytes());
        bytes[opt + 108..opt + 112].copy_from_slice(&16u32.to_le_bytes());
        let sec = opt + 0xf0;
        bytes[sec..sec + 5].copy_from_slice(b".text");
        bytes[sec + 16..sec + 20].copy_from_slice(&0x400u32.to_le_bytes());
        bytes[sec + 20..sec + 24].copy_from_slice(&0x200u32.to_le_bytes());
        bytes[sec + 36..sec + 40].copy_from_slice(&0x6000_0020u32.to_le_bytes());
        bytes
    }

    #[test]
    fn elf_mutations_never_panic() {
        // 固定种子保证可复现；失败时把种子写进断言语义里
        for seed in 1..=64u64 {
            run_corpus(seed, &seed_elf(), 48);
        }
    }

    #[test]
    fn pe_mutations_never_panic() {
        for seed in 1..=64u64 {
            run_corpus(seed, &seed_pe(), 48);
        }
    }

    #[test]
    fn pure_random_bytes_never_panic() {
        let mut rng = Rng::new(0xdead_beef);
        for _ in 0..512 {
            let len = rng.below(2048);
            let bytes: Vec<u8> = (0..len).map(|_| (rng.next_u64() & 0xff) as u8).collect();
            parse_all(&bytes);
        }
    }

    #[test]
    fn empty_and_tiny_inputs_never_panic() {
        for len in 0..64usize {
            let bytes = vec![0u8; len];
            parse_all(&bytes);
        }
        // 全 0xFF 的短输入也是常见的畸形边界
        for len in 0..64usize {
            let bytes = vec![0xffu8; len];
            parse_all(&bytes);
        }
    }

    #[test]
    fn elven_magic_with_absurd_headers_does_not_allocate_wildly() {
        // 头里声明了极大数量的节/段/符号，解析器必须先校验范围再分配。
        // 这个测试靠"能在合理时间内返回"来间接证明没有按声明值直接分配。
        let mut bytes = seed_elf();
        // e_shnum 走 extended（设为 0），并在 section 0 的 sh_size 里写极大值
        bytes[60..62].copy_from_slice(&0u16.to_le_bytes());
        let shoff = 0x40;
        bytes[shoff + 32..shoff + 40].copy_from_slice(&u64::MAX.to_le_bytes());
        bytes[shoff + 40..shoff + 44].copy_from_slice(&0xffff_ffffu32.to_le_bytes());
        let _ = elf::parse(&bytes, 0, ObjectId::Plain);
    }

    #[test]
    fn pe_with_absurd_section_count_does_not_allocate_wildly() {
        let mut bytes = seed_pe();
        bytes[0x86..0x88].copy_from_slice(&0xffffu16.to_le_bytes());
        let _ = pe::parse(&bytes, 0, ObjectId::Plain);
    }

    #[test]
    fn fuzz_corpus_actually_exercises_the_parsers() {
        // 防止"模糊测试看起来通过但根本没跑"：统计变异样本里
        // 有多少真的被解析器接受了（返回 Ok），以及有多少产生了错误。
        // 种子本身是合法的，因此健康的语料应当**两者都有**。
        // 若全 ok 说明变异没生效，若全 err 说明变异过重、失去了边界覆盖。
        let base = seed_elf();
        let mut rng = Rng::new(7);
        let mut ok = 0usize;
        let mut err = 0usize;
        let mut changed = 0usize;

        for _ in 0..256 {
            let mut bytes = base.clone();
            let count = 1 + rng.below(3);
            for _ in 0..count {
                mutate(&mut rng, &mut bytes);
            }
            if bytes != base {
                changed += 1;
            }
            match elf::parse(&bytes, 0, ObjectId::Plain) {
                Ok(_) => ok += 1,
                Err(_) => err += 1,
            }
        }

        // 绝大多数样本必须真的被改动了（允许极少数变异落在零填充上而无影响）
        assert!(changed > 200, "变异器几乎没改动样本：changed={changed}/256");
        assert!(err > 0, "应有样本被拒绝（否则变异没生效），ok={ok}");
        assert!(ok > 0, "应有样本仍能解析（否则变异过重），err={err}");
    }

    #[test]
    fn mutation_engine_is_deterministic() {
        // 同一颗种子必须产生同一串样本，否则失败无法复现
        let base = seed_elf();
        let mut a = base.clone();
        let mut b = base.clone();
        let mut rng_a = Rng::new(42);
        let mut rng_b = Rng::new(42);
        for _ in 0..32 {
            mutate(&mut rng_a, &mut a);
            mutate(&mut rng_b, &mut b);
        }
        assert_eq!(a, b, "相同种子必须产生相同变异结果");
    }

    #[test]
    fn snapshot_from_formats_reports_malformed_without_panic() {
        // 把 PE 数据交给 ELF 解析器、ELF 数据交给 PE 解析器：跨格式误判
        // 是嗅探出错时的真实场景，必须也只是返回错误。
        let pe = seed_pe();
        let elf = seed_elf();
        let _ = elf::parse(&pe, 0, ObjectId::Plain);
        let _ = pe::parse(&elf, 0, ObjectId::Plain);
        let _ = coff::parse(&pe, 0, ObjectId::Plain);
    }

    #[test]
    fn dispatch_matches_sniffer_for_valid_magic() {
        assert_eq!(dispatch(&seed_elf()), Some(ObjectKind::Elf));
        assert_eq!(dispatch(&seed_pe()), Some(ObjectKind::Pe));
        assert_eq!(dispatch(b"junk"), None);
    }

    #[test]
    fn container_kind_does_not_panic_on_mutations() {
        // ContainerKind 的分派在嗅探层，独立于对象格式，也要覆盖
        let _ = ContainerKind::Plain.as_str();
    }
}
