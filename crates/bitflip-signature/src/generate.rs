//! 从静态库/目标文件生成签名。
//!
//! # 一条签名是怎么来的
//!
//! 1. 找到**定义了名字的函数符号**（`defined` + `is_function` + 有名字 + 在可执行节里）；
//! 2. 按符号位置取出它的字节（长度优先用符号表给的大小，拿不到就用"到下一个符号的距离" ——
//!    COFF 的符号大小恒为 0，不这样算就一个函数都取不出来）；
//! 3. 把**同一节里、落在这段范围内**的重定位覆盖的字节标成通配：链接器会改写它们，
//!    库里看到的值在目标里是不成立的；
//! 4. 前缀模式 + 尾部无通配窗口的 CRC。
//!
//! # 长度这件事必须写清楚
//!
//! "函数有多长"在目标文件里常常是**推出来的**，不是读出来的。COFF 压根不存大小，
//! ELF 也允许为 0。所以本模块用的是"到下一个同节函数符号的距离"，并在拿不到时
//! 退回节尾 —— 这两种都是**上界**（中间可能有对齐填充），因此长度只用来定位尾部窗口，
//! 不用来断言"目标里的函数必须正好这么长"。匹配时不要求长度相等，正是这个原因。

use std::collections::{BTreeMap, BTreeSet};

use bitflip_arch::ArchSpec;
use bitflip_loader::object::{Object, ObjectId, RawSymbol, Reloc, RelocKind};
use bitflip_loader::{sniff_bytes, ContainerKind, ObjectKind};

use crate::pattern::{crc16_ccitt, Pattern, PatternByte};
use crate::signature::{
    DropReason, FunctionSignature, GenerationStats, SignatureArch, SignatureSet, TailCheck,
};

/// 前缀模式覆盖的字节数。
///
/// 24 是折中：太短则短函数互相混淆，太长则"开头一段有重定位"的函数被整段屏蔽。
/// 尾部 CRC 补的正是"只看开头"漏掉的那部分证据。
pub const PREFIX_BYTES: usize = 24;

/// 尾部窗口最多取多少字节。
pub const TAIL_WINDOW: usize = 16;

/// 尾部窗口至少要有多长才值得做校验。
pub const TAIL_MIN_BYTES: usize = 8;

/// 尾部校验最多允许放在离函数起点这么远的地方。
///
/// 尾部校验的价值是"在共享前缀的函数之间分开"；代价是**每比对一次目标函数就要
/// 读这么多字节**。符号表里的大小若被写坏（或某个函数真的巨大），一个几 MB 的尾部
/// 会让匹配器的内存与耗时失控 —— 而前缀通常已经够区分了，所以超过这个距离就只留前缀。
///
/// 这不影响 `length_exact`：结束位置本身仍然可信，只是我们选择不做远端校验。
pub const TAIL_MAX_EXTENT: u64 = 1024;

/// 连续多少个**完全相同的字节**就不再算作函数指纹。
///
/// 真实代码里八字节连成一片的情况极少，而对齐填充（函数之间）与尾部填充（节末尾）
/// 必然如此 —— 填什么值取决于目标与工具链（x86 常见 `90`/`cc`，其它目标常见 `00`
/// 或定长 nop），所以这里**只看"一样不一样"，不看是什么值**，也就不引入架构假设。
///
/// 阈值取 8 与 [`MIN_EXACT_NO_TAIL`] 一致：这样活下来的签名，其确定字节里必定不含
/// 八字节同值串，也就是"看起来像填充的部分不参与指纹"。
pub const PADDING_RUN_MIN: usize = 8;

/// 前缀里可以留下的长度：在第一次出现长同值串的地方截断。
///
/// 为什么必须截断：`ret` 后面跟着 15 个填充字节若被当成指纹，那么在目标里**任何**
/// "ret + 对齐填充"的位置都会命中 —— 实测就把 `__gcc_deregister_frame` 认成了
/// `__clear_cache`。填充是这个函数之外的字节，不能替它作证。
///
/// 通配**不**计入同值串：连续的通配是一段被屏蔽的重定位区（例如 8 字节立即数），
/// 那是有意的"不知道"，不是填充。
#[must_use]
fn padding_free_prefix(pattern: &[PatternByte]) -> usize {
    let mut run_start = 0;
    let mut run_len = 0usize;
    let mut previous: Option<PatternByte> = None;
    for (index, byte) in pattern.iter().enumerate() {
        if *byte == PatternByte::Wildcard {
            previous = None;
            run_start = index;
            run_len = 1;
            continue;
        }
        if Some(*byte) == previous {
            run_len += 1;
        } else {
            run_start = index;
            run_len = 1;
        }
        previous = Some(*byte);
        if run_len >= PADDING_RUN_MIN {
            return run_start;
        }
    }
    pattern.len()
}

/// 索引键的字节数（前缀开头必须有这么多连续确定字节）。
pub const INDEX_BYTES: usize = 4;

/// 前缀里至少要有的确定字节数。
///
/// 确定字节数 E 决定"随机撞上"的概率：目标里尝试的位置有十万量级（10^4），
/// 因此 E=6 时的偶然命中率约 10^4 / 2^48，可以忽略。真正需要防的不是偶然，
/// 而是**结构性雷同**（两个 TU 里同样的 `return a+b;`），那由"同形不同名一律丢弃"
/// 来管，不是靠抬高这个阈值。
pub const MIN_EXACT_BYTES: usize = 6;

/// 没有尾部校验时的确定字节数门槛（比有尾部校验时更高）。
///
/// 尾部 CRC 是"函数另一端"的独立证据；没有它时只剩前缀一处证据，
/// 所以要求更多的确定字节，而不是默许"证据只有一半也算数"。
pub const MIN_EXACT_NO_TAIL: usize = 8;

/// 少于这么多字节的函数不值得签名（取不出任何有意义的模式）。
pub const MIN_FUNCTION_BYTES: usize = 4;

/// 一个输入（静态库、归档或单个目标文件）。
#[derive(Debug, Clone)]
pub struct ArchiveInput<'a> {
    /// 显示名（用于报告；通常是路径）。
    pub name: String,
    /// 文件内容。
    pub bytes: &'a [u8],
}

/// 单个输入的产出报告。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SourceReport {
    /// 显示名。
    pub name: String,
    /// 容器短名（`ar` / `msvc-lib` / `plain`）。
    pub container: &'static str,
    /// 该输入里的对象个数。
    pub objects: u64,
    /// 该输入产出的签名条数。
    pub signatures: u64,
}

/// 生成结果。
#[derive(Debug, Clone)]
pub struct Generated {
    /// 签名集（含生成账）。
    pub set: SignatureSet,
    /// 逐输入的产出。
    pub sources: Vec<SourceReport>,
}

/// 由目标形态折算签名形态。
#[must_use]
pub fn signature_arch(spec: &ArchSpec) -> SignatureArch {
    SignatureArch::new(
        u16::from(spec.ptr_size) * 8,
        spec.endian.as_str(),
        spec.arch.as_str(),
    )
}

/// 生成签名。
///
/// 解析失败的对象**计入统计而不是中断**：一个用户目录里混着几个坏文件，
/// 不该让另外几十个库什么都产出不了。
#[must_use]
pub fn generate(inputs: &[ArchiveInput<'_>]) -> Generated {
    let mut signatures = Vec::new();
    let mut stats = GenerationStats::default();
    let mut sources = Vec::new();

    for input in inputs {
        let guess = sniff_bytes(input.bytes);
        let container = guess.container;
        let mut produced = 0u64;
        let mut objects = 0u64;

        match container {
            ContainerKind::Ar | ContainerKind::MsvcLib => {
                let member_kind = guess.member_kind.unwrap_or(ObjectKind::Raw);
                for member in &guess.members {
                    // 符号索引 / 长名表这类元数据成员不是对象：它们本来就不是
                    // 生成签名的候选，单独计数（免得报告里看起来像"解析失败"）。
                    if !member.payload {
                        stats.metadata_members += 1;
                        continue;
                    }
                    if member.truncated {
                        // 内容没读全的成员不能拿来生成签名：读到的字节是残缺的，
                        // 生成的模式会"看起来正常"但在目标里永远匹配不上。
                        stats.truncated_members += 1;
                        continue;
                    }
                    let Some(slice) = slice_member(input.bytes, member.offset, member.size) else {
                        stats.unparsable_objects += 1;
                        continue;
                    };
                    objects += 1;
                    let id = ObjectId::ArchiveMember(member.name.clone());
                    match parse_object(member_kind, slice, id) {
                        Some(object) => {
                            produced += collect_object(&object, slice, &mut signatures, &mut stats);
                        }
                        None => stats.unparsable_objects += 1,
                    }
                }
            }
            _ => {
                objects += 1;
                match parse_object(guess.object, input.bytes, ObjectId::Plain) {
                    Some(object) => {
                        produced +=
                            collect_object(&object, input.bytes, &mut signatures, &mut stats);
                    }
                    None => stats.unparsable_objects += 1,
                }
            }
        }

        stats.objects += objects;
        sources.push(SourceReport {
            name: input.name.clone(),
            container: container.as_str(),
            objects,
            signatures: produced,
        });
    }

    // 同形不同名 → 谁也留不下；完全重复 → 留一条。两件事都记账。
    signatures = resolve_collisions(signatures, &mut stats);
    signatures.sort_by(|left, right| {
        left.name
            .cmp(&right.name)
            .then_with(|| left.arch.cmp(&right.arch))
            .then_with(|| left.prefix.to_hex().cmp(&right.prefix.to_hex()))
            .then_with(|| left.tail.cmp(&right.tail))
    });
    stats.emitted = signatures.len() as u64;

    Generated {
        set: SignatureSet::new(signatures, stats),
        sources,
    }
}

/// 取归档成员的字节切片。
fn slice_member(bytes: &[u8], offset: u64, size: u64) -> Option<&[u8]> {
    let start = usize::try_from(offset).ok()?;
    let len = usize::try_from(size).ok()?;
    bytes.get(start..start.checked_add(len)?)
}

/// 按格式解析一个对象。
fn parse_object(kind: ObjectKind, bytes: &[u8], id: ObjectId) -> Option<Object> {
    match kind {
        ObjectKind::Coff => bitflip_loader::coff::parse(bytes, 0, id).ok(),
        ObjectKind::Elf => bitflip_loader::elf::parse(bytes, 0, id).ok(),
        ObjectKind::Pe => bitflip_loader::pe::parse(bytes, 0, id).ok(),
        ObjectKind::MachO | ObjectKind::Raw => None,
    }
}

/// 从一个对象里收集签名，返回产出条数。
fn collect_object(
    object: &Object,
    bytes: &[u8],
    out: &mut Vec<FunctionSignature>,
    stats: &mut GenerationStats,
) -> u64 {
    // 已链接的映像不生成签名：符号值究竟是"节内偏移"还是"虚拟地址"取决于链接器
    // （同一份 PE 规范，mingw 写节内偏移、MSVC 写 RVA），只凭文件内容无法可靠区分。
    // 猜错的后果是**静默读错字节**，所以这里选择不做，而不是做一个看起来能跑的实现。
    if !is_relocatable(object) {
        let count = object
            .symbols
            .iter()
            .filter(|symbol| symbol.is_function)
            .count() as u64;
        stats.functions_seen += count;
        stats.drop_many(DropReason::NotRelocatable, count);
        return 0;
    }

    let arch = signature_arch(&object.arch);
    let pointer_size = usize::from(object.arch.ptr_size.max(1));
    let mut produced = 0u64;

    // 同节内的函数符号按下标排序，供"到下一个符号的距离"使用。
    let mut by_section: BTreeMap<&str, Vec<&RawSymbol>> = BTreeMap::new();
    for symbol in &object.symbols {
        if !symbol.is_function || !symbol.defined || symbol.name.is_empty() {
            continue;
        }
        if let Some(section) = symbol.section.as_deref() {
            by_section.entry(section).or_default().push(symbol);
        }
    }
    for symbols in by_section.values_mut() {
        symbols.sort_by_key(|symbol| symbol.value);
    }

    for symbol in object.symbols.iter().filter(|s| s.is_function) {
        stats.functions_seen += 1;
        if !symbol.defined {
            stats.drop_one(DropReason::Undefined);
            continue;
        }
        if symbol.name.is_empty() {
            stats.drop_one(DropReason::EmptyName);
            continue;
        }
        let Some(section_name) = symbol.section.as_deref() else {
            stats.drop_one(DropReason::NoSection);
            continue;
        };
        let Some(section) = object.section_by_name(section_name) else {
            stats.drop_one(DropReason::NoSection);
            continue;
        };
        // 可执行节之外的"函数符号"多半是误标（数据符号被标成函数），不收。
        if !section.perms.execute {
            stats.drop_one(DropReason::NotExecutable);
            continue;
        }

        // 长度：符号表的大小优先，其次"到下一个同节函数符号的距离"（COFF 的大小恒为
        // 0，不这样算一个函数都取不出来），再退回节尾。都只是**上界**。
        let peers = by_section.get(section_name).map_or(&[][..], Vec::as_slice);
        let Some(length) = function_length(symbol, peers, section.file.size) else {
            stats.drop_one(DropReason::TooShort);
            continue;
        };
        if length.bytes < MIN_FUNCTION_BYTES as u64 {
            stats.drop_one(DropReason::TooShort);
            continue;
        }

        // 取字节：起点是节内偏移 + 节的文件偏移。
        let Some(start) = section.file.offset.checked_add(symbol.value) else {
            stats.drop_one(DropReason::NoBytes);
            continue;
        };
        // 取多少字节：最长只取到 [`TAIL_MAX_EXTENT`] —— 尾部校验不会比这更远，
        // 而"函数长度"的上界可能大到几十 KB（实测出现过 33KB），按它取字节会白读。
        //
        // 这里**不**按前缀长度截断：上界本身就不会越过下一个函数符号
        // （上界就是"到下一个符号的距离"），所以按上界取字节是安全的；
        // 而按 24 字节草率地"补足"前缀，会让只有 4 字节的函数被拼上邻居的字节
        // 认出来（实测 `bf_add` 就这么"复活"过）。
        let want = length.bytes.min(TAIL_MAX_EXTENT);
        let usable = want.min(section.file.size.saturating_sub(symbol.value));
        let Some(start) = usize::try_from(start).ok() else {
            stats.drop_one(DropReason::NoBytes);
            continue;
        };
        let Some(usable) = usize::try_from(usable).ok() else {
            stats.drop_one(DropReason::NoBytes);
            continue;
        };
        let Some(window) = bytes.get(start..start.saturating_add(usable)) else {
            stats.drop_one(DropReason::NoBytes);
            continue;
        };
        if window.len() < MIN_FUNCTION_BYTES {
            stats.drop_one(DropReason::TooShort);
            continue;
        }

        // 通配：同一节、落在这段范围里的重定位。
        let (mut wildcards, widened) = wildcard_offsets(
            &object.relocations,
            section_name,
            symbol.value,
            window.len(),
            pointer_size,
        );
        if widened {
            stats.widened_wildcards += 1;
        }
        wildcards.sort_unstable();
        wildcards.dedup();

        let prefix_len = window.len().min(PREFIX_BYTES);
        let mut pattern = Vec::with_capacity(prefix_len);
        for (index, byte) in window.iter().take(prefix_len).enumerate() {
            pattern.push(if wildcards.binary_search(&index).is_ok() {
                PatternByte::Wildcard
            } else {
                PatternByte::Exact(*byte)
            });
        }
        // 尾部被对齐填充占满时截短：填充不是这个函数的指纹（见 [`padding_free_prefix`]）。
        let informative = padding_free_prefix(&pattern);
        if informative < pattern.len() {
            pattern.truncate(informative);
            stats.padding_trimmed += 1;
        }
        let prefix = Pattern::new(pattern);

        // 尾部校验的落点：只有**符号表给了确切大小**时才做（`length.exact`）。
        //
        // 为什么不用"到下一个符号的距离"代替 —— 那个距离只是上界，实测过一次就够：
        // 拿它当结尾（4 个 mingw 静态库 → `m3-mingw-static.exe`），召回从 65 掉到 55、
        // 还多出 1 个错名。原因很直白：库里"下一个符号"的位置与链接后函数真正结束的
        // 位置经常对不上（中间夹着对齐填充或没有符号记录的局部代码），证据落在函数
        // 之外就不是证据，只会让签名变脆。
        //
        // 代价是 COFF 的签名只有前缀（COFF 函数符号通常没有大小）。这不亏：
        // [`MIN_EXACT_NO_TAIL`] 把门槛抬到 8 个确定字节，实测召回 65/65、错名 0。
        //
        // 窗口末尾若是**一长串同样的字节**，那是函数之间的对齐填充，不属于这个函数；
        // 去掉它，剩下的末尾才是函数真正的结尾（只影响"确切大小"的那一类）。
        let tail = if length.exact && usable as u64 == length.bytes {
            let padding = trailing_padding(window);
            let body = window.get(..window.len() - padding).unwrap_or(window);
            // 尾部扫描从前缀**原本**的长度开始：尾部要取的是"函数结尾那几个字节"，
            // 前缀被截短只影响它自己记录了多少证据，不改变结尾在哪。
            tail_check(body, &wildcards, prefix_len)
        } else {
            None
        };

        if prefix.leading_exact() < INDEX_BYTES {
            stats.drop_one(DropReason::PrefixWildcard);
            continue;
        }
        let exact_bytes = prefix.exact_count();
        if exact_bytes < MIN_EXACT_BYTES || (tail.is_none() && exact_bytes < MIN_EXACT_NO_TAIL) {
            stats.drop_one(DropReason::TooFewExact);
            continue;
        }

        out.push(FunctionSignature {
            name: symbol.name.clone(),
            arch: arch.clone(),
            length: u32::try_from(length.bytes).unwrap_or(u32::MAX),
            length_exact: length.exact,
            prefix,
            tail,
            exact_bytes: u16::try_from(exact_bytes).unwrap_or(u16::MAX),
        });
        produced += 1;
    }

    produced
}

/// 这个对象是**可重定位**的吗（各节还没有被放到最终地址上）？
///
/// 生成签名要求"符号值 = 节内偏移"。可重定位对象（`.o`/`.obj`）的各节虚拟地址
/// 都是 0，这个等式成立；已链接映像把节放到了最终地址上，而符号值遵循哪种约定
/// **取决于链接器**：mingw/ld 写节内偏移，MSVC 写 RVA，同一份 PE 规范里两种都存在。
/// 仅凭文件内容无法可靠区分，所以已链接映像一律不生成签名（见 [`collect_object`]）。
#[must_use]
fn is_relocatable(object: &Object) -> bool {
    object.sections.iter().all(|section| section.vaddr == 0)
}

/// 函数长度：符号表的大小优先，其次"到下一个同节函数符号的距离"，再退回节尾。
///
/// `peers` 必须是**同一节内、按 `value` 升序**的函数符号。用二分而不是每次遍历
/// 整张符号表：一个静态库成员里几千个符号是常态，平方复杂度会让生成过程变得很慢。
///
/// 三种来源都只是**上界**，只有第一种是确切大小：
///
/// * **符号表给出的大小**（ELF 的 `st_size`、带辅助记录的 COFF）—— 确切；
/// * **到下一个函数符号的距离** —— 上界：中间可以夹着没有符号记录的局部代码
///   （汇编写的 CRT 常见：只 `.globl` 几个入口，其余都是 `.L` 标签），
///   实测出现过 33KB 的间距；
/// * **到节尾** —— 那是"节里剩下的字节"，与函数大小无关。
///
/// 要注意 COFF 的函数符号**通常没有大小**（cli 与 GNU as 都写 0），
/// 所以 mingw 静态库那边基本只能靠"到下一个符号的距离"。
fn function_length(symbol: &RawSymbol, peers: &[&RawSymbol], section_size: u64) -> Option<Length> {
    if symbol.size > 0 {
        return Some(Length {
            bytes: symbol.size,
            exact: true,
        });
    }
    // 按 `value` 升序切分：第一个**严格大于**本符号的同类符号就是它的上界。
    // 同址并列（别名、`.L` 标签）会被一起跳过，这正是想要的 —— 别名不是下一个函数。
    let index = peers.partition_point(|peer| peer.value <= symbol.value);
    match peers.get(index) {
        Some(peer) => peer.value.checked_sub(symbol.value).map(|bytes| Length {
            bytes,
            exact: false,
        }),
        None => section_size.checked_sub(symbol.value).map(|bytes| Length {
            bytes,
            exact: false,
        }),
    }
}

/// [`function_length`] 的结果：长度上界，以及这个长度是不是确切大小。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct Length {
    /// 从函数起点算起的字节数上界。
    bytes: u64,
    /// `bytes` 是否就是函数的真实大小（只有符号表给了大小才为真）。
    exact: bool,
}

/// 窗口末尾那串"完全相同的字节"有多长（不足 [`PADDING_RUN_MIN`] 就是 0）。
///
/// 与 [`padding_free_prefix`] 是同一套判据（只看一样不一样，不看是什么值），
/// 用途反过来：前缀里出现它说明指纹混进了填充，要截掉；**末尾**出现它说明函数
/// 就在这里结束 —— 对齐填充只会跟在函数后面，所以末尾那串填充之前就是函数结尾。
#[must_use]
fn trailing_padding(window: &[u8]) -> usize {
    let Some(first) = window.last() else {
        return 0;
    };
    let run = window
        .iter()
        .rev()
        .take_while(|byte| *byte == first)
        .count();
    if run >= PADDING_RUN_MIN {
        run
    } else {
        0
    }
}

/// 一次屏蔽宽度：这条重定位改写了几个字节。
///
/// 只有两种宽度，因为这正是重定位在中性模型里能区分的两种：
///
/// * **数据槽位**（绝对地址、指针表）宽度等于指针宽度 —— 加载器会往整个槽位写地址；
/// * **代码里的相对寻址**是 4 字节位移：定长指令集里它是 4 字节指令槽的一部分，
///   变长指令集里它是 `rel32`。两种情况都只覆盖 4 字节。
///
/// 类型不认识时**取两者中更宽的那个**：多屏蔽几个字节只会让签名弱一点，
/// 少屏蔽则会让"库里成立的字节串"在目标里对不上而根本匹配不到 —— 后者更糟，
/// 因为它是静默的。这种情况会被计数（[`GenerationStats::widened_wildcards`]）。
#[must_use]
pub fn wildcard_width(kind: RelocKind, pointer_size: usize) -> usize {
    match kind {
        RelocKind::Absolute | RelocKind::RelocPointer => pointer_size.max(1),
        RelocKind::Relative | RelocKind::ImportLookup => 4,
        RelocKind::Other => pointer_size.max(4),
    }
}

/// 返回（函数内通配偏移集合，是否有被加宽的项）。
fn wildcard_offsets(
    relocations: &[Reloc],
    section_name: &str,
    symbol_value: u64,
    window_len: usize,
    pointer_size: usize,
) -> (Vec<usize>, bool) {
    let mut offsets = Vec::new();
    let mut widened = false;
    let end = symbol_value.saturating_add(window_len as u64);
    for reloc in relocations {
        if reloc.section.as_deref() != Some(section_name) {
            continue;
        }
        if reloc.address < symbol_value || reloc.address >= end {
            continue;
        }
        let Some(relative) = usize::try_from(reloc.address - symbol_value).ok() else {
            continue;
        };
        let width = wildcard_width(reloc.kind, pointer_size);
        if reloc.kind == RelocKind::Other && width > 4 {
            widened = true;
        }
        for index in relative..relative.saturating_add(width).min(window_len) {
            offsets.push(index);
        }
    }
    (offsets, widened)
}

/// 尾部校验：在 `[prefix_len, end)` 里取**最长的连续无通配窗口**，优先靠后的。
fn tail_check(window: &[u8], wildcards: &[usize], prefix_len: usize) -> Option<TailCheck> {
    if window.len() <= prefix_len {
        return None;
    }
    let mut best: Option<(usize, usize)> = None; // (start, len)
    let mut run_start: Option<usize> = None;
    for index in prefix_len..=window.len() {
        let covered = index < window.len() && wildcards.binary_search(&index).is_ok();
        if covered || index == window.len() {
            if let Some(start) = run_start {
                let run_len = index - start;
                let better = match best {
                    None => true,
                    Some((_, best_len)) => run_len >= best_len,
                };
                if better && run_len > 0 {
                    best = Some((start, run_len));
                }
                run_start = None;
            }
        } else if run_start.is_none() {
            run_start = Some(index);
        }
    }
    let (start, run_len) = best?;
    if run_len < TAIL_MIN_BYTES {
        return None;
    }
    // 取这个连续段的**末尾** TAIL_WINDOW 字节：靠近函数结尾的字节更能区分不同的函数。
    let take = run_len.min(TAIL_WINDOW);
    let offset = start + run_len - take;
    let slice = window.get(offset..offset + take)?;
    Some(TailCheck {
        offset: u32::try_from(offset).ok()?,
        bytes: u16::try_from(take).ok()?,
        crc16: crc16_ccitt(slice),
    })
}

/// 处理同形签名：不同名字的整组丢弃，完全重复的只留一条。
fn resolve_collisions(
    signatures: Vec<FunctionSignature>,
    stats: &mut GenerationStats,
) -> Vec<FunctionSignature> {
    let mut groups: BTreeMap<(SignatureArch, String, Option<TailCheck>), Vec<usize>> =
        BTreeMap::new();
    for (index, signature) in signatures.iter().enumerate() {
        groups
            .entry((
                signature.arch.clone(),
                signature.prefix.to_hex(),
                signature.tail,
            ))
            .or_default()
            .push(index);
    }

    let mut keep = vec![true; signatures.len()];
    for members in groups.values() {
        if members.len() < 2 {
            continue;
        }
        let names: BTreeSet<&str> = members
            .iter()
            .map(|index| signatures[*index].name.as_str())
            .collect();
        if names.len() > 1 {
            // 长得一模一样却要求不同的名字：匹配时无法在它们之间做选择。
            // 给它一个名字等于一半概率写错，不如不要。
            for index in members {
                keep[*index] = false;
                stats.drop_one(DropReason::Ambiguous);
            }
        } else {
            for index in members.iter().skip(1) {
                keep[*index] = false;
                stats.drop_one(DropReason::Duplicate);
            }
        }
    }

    signatures
        .into_iter()
        .zip(keep)
        .filter_map(|(signature, keep)| keep.then_some(signature))
        .collect()
}
