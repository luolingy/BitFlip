//! ZIP 容器（APK / JAR / XAPK 外壳）：从中央目录枚举成员、按需取出成员内容。
//!
//! # 为什么这一层在 `format/` 下
//!
//! 中央目录的字节布局、压缩方法号、data descriptor 都是 **ZIP 格式知识**。
//! 按 `format/mod.rs` 定下的边界，它只能待在这里：通用层（`lib.rs` / `sniff`）
//! 只知道"有个 [`crate::ContainerKind::Zip`] 和一堆 [`ArchiveMember`]"，
//! 不该出现 ZIP 的结构名。
//!
//! # 为什么解析交给 `zip` crate，而"找目录"自己来
//!
//! 中央目录、extra field、data descriptor、解压**全部**交给 `zip` crate ——
//! 那是成熟实现，自己再写一份只会多一处出错的地方（`docs/APK-DEX-DESIGN.md`
//! §1 的选型结论）。
//!
//! 唯一自己写的是 [`find_eocd`]，而且它**不参与解析**：它存在的唯一目的是把
//! 两种完全不同的情形分开报（见 [`ParseError::DirectoryNotInRange`]）——
//!
//! * "**我只看了文件的一部分**"：APK 的中央目录在文件末尾，而嗅探只读前 8 MiB
//!   给解析器一段前缀，成员可能好好地躺在后面；
//! * "**文件坏了**"。
//!
//! `zip` crate 对这两种情形都会返回一个"无效归档"类的错误。不先分这一刀，
//! 用户会去修一个根本没坏的文件 —— CLAUDE.md §7 要求这两者必须分得开。

use std::io::{Cursor, Read};

use crate::reader::ParseError;
use crate::{ArchiveMember, MemberStorage};

/// 成员枚举上限。
///
/// 与 ar 的 `MAX_ARCHIVE_MEMBERS`（4096）取值不同，因为**保护的东西不同**：
/// ar 那个上限保护的是"线性扫描多久"（成员头要一个个走过去，坏文件能让它
/// 走很远）；ZIP 的成员数直接写在中央目录结束记录里，我们只是把**已经列好**
/// 的清单读出来，所以取格式自身的上限 65535（非 ZIP64 的条目数上限）。
///
/// # 这个上限实际只在 ZIP64 下会触发
///
/// 非 ZIP64 的结束记录里成员数字段是 16 位，最多 65535，**永远够不到**这条线。
/// 真正需要它兜住的是 ZIP64：那里的成员数是 `u64`，一个坏文件可以声称有
/// 2^63 个成员。没有这条线，我们会照着那个数字一直循环下去。
///
/// 反过来说，**非 ZIP64 却超出 65535 个成员**的文件不会走到这里 ——
/// 它的成员数是**回绕**的（65538 → 2），那由
/// [`count_central_records`] 的核对负责报出来。
const MAX_ZIP_MEMBERS: usize = 65535;

/// 成员数上限的决策：返回（实际枚举数，是否被截断）。
///
/// # 为什么单独抽出来
///
/// 为的是能**直接测**。触发截断需要 ZIP64（非 ZIP64 的成员数字段是 16 位，
/// 永远够不到上限），而手工拼一份 ZIP64 fixture 的成本远高于这条算术的价值。
/// 抽成纯函数后，算术本身仍然是被验证过的 —— 而不是"因为构造不出来所以不测"。
const fn member_budget(total: usize) -> (usize, bool) {
    if total > MAX_ZIP_MEMBERS {
        (MAX_ZIP_MEMBERS, true)
    } else {
        (total, false)
    }
}

/// 单个成员**解压后**的大小上限（256 MiB）。
///
/// 解压是唯一一处"输入大小不决定输出大小"的地方：几 KB 的 deflate 流可以
/// 解出 GB 级数据（zip bomb）。这里是显式设限，而不是依赖 crate 的默认行为
/// ——上限一旦被触发要**报错**，不能让调用方拿到一段被悄悄截断的字节（§7）。
const MAX_MEMBER_BYTES: u64 = 256 * 1024 * 1024;

/// 中央目录结束记录（EOCD）固定部分长度（APPNOTE §4.3.16）。
const EOCD_LEN: usize = 22;
/// EOCD 注释长度是 2 字节（最大 65535），往回答 EOCD 只需回看这么多。
const EOCD_SEARCH: usize = EOCD_LEN + 0xFFFF;
/// EOCD 签名。
const EOCD_MAGIC: [u8; 4] = *b"PK\x05\x06";
/// 本地文件头（local file header）固定部分长度（APPNOTE §4.3.7）。
const LOCAL_HEADER_LEN: usize = 30;
/// 本地文件头签名。
const LOCAL_MAGIC: [u8; 4] = *b"PK\x03\x04";
/// APK Signing Block 的尾部魔数（APK Signature Scheme v2/v3，紧邻中央目录）。
const APK_SIG_BLOCK_MAGIC: &[u8; 16] = b"APK Sig Block 42";

/// APK Signing Block 里 `size` 字段的长度（8 字节，小端 `u64`）。
const APK_SIG_BLOCK_SIZE_LEN: usize = 8;

/// 中央目录记录（`PK\x01\x02`）的签名，用于核对成员数是否可信。
const CENTRAL_MAGIC: [u8; 4] = *b"PK\x01\x02";
/// 中央目录记录的**固定**部分长度（APPNOTE §4.3.12）。
const CENTRAL_HEADER_LEN: usize = 46;

/// 成员名在 **APK** 里的角色。
///
/// # 这是"按名字猜"，而且**只**按名字 —— 说清楚它的边界
///
/// APK 的条目名由 Android 构建工具固定下来（`classes*.dex`、
/// `lib/<abi>/*.so`、`AndroidManifest.xml`、`resources.arsc`），所以看名字
/// 就能分类，**不需要解压**。这是本类型唯一依据，也是它唯一的适用前提。
///
/// 两条**不能**从它推出的结论：
///
/// 1. **它不表示"这个归档是 APK"**。名字长这样是必要条件，不是充分条件；
///    判断"是不是 APK"要另找依据（清单能不能解出 `package` 等）。
///    所以名字对不上时返回 [`Self::Other`]，而 `Other` **不等于**"不是 APK"。
/// 2. **它不表示成员内容是什么格式**。`classes.dex` 里装的到底是不是合法 DEX、
///    `lib/*.so` 里是不是合法 ELF，都要**真去解析**才知道 ——
///    命名约定管不了内容。`bitflip-core` 的成员会话正是这么做的：
///    它不看名字，拿解压出来的字节去 [`crate::sniff_bytes`]。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ApkRole<'a> {
    /// `classes.dex`（序号 `None`）或 `classes<N>.dex`（序号 `Some(N)`，N ≥ 2）。
    ///
    /// 序号如实取自文件名，**不按枚举顺序重编**：文件名里的号码是构建产物
    /// 的一部分，重编过一遍就与真实工具链对不上了。
    Dex(Option<u32>),
    /// `lib/<abi>/<名字>.so` —— 原生库，值是 **ABI 目录名**（如 `arm64-v8a`）。
    NativeLib(&'a str),
    /// `AndroidManifest.xml`（二进制 XML）。
    Manifest,
    /// `resources.arsc`（资源表）。
    ResourceTable,
    /// `META-INF/` 下的签名文件（`*.SF` / `*.RSA` / `*.DSA` / `*.EC`）。
    Signature,
    /// 名字不符合上面任何一条。
    ///
    /// **不是**"这个成员没用" —— 绝大多数成员都会落到这里（图片、字体、
    /// 配置文件……），它们只是不属于 APK 的那几个固定位置。
    Other,
}

impl<'a> ApkRole<'a> {
    /// 按成员名判定角色。**纯字符串判断**，不读字节。
    #[must_use]
    pub fn of(name: &'a str) -> Self {
        // 顺序有讲究的只有 `classes*.dex`：先判精确名，再判带序号的。
        if name == "AndroidManifest.xml" {
            return Self::Manifest;
        }
        if name == "resources.arsc" {
            return Self::ResourceTable;
        }
        if let Some(rest) = name.strip_prefix("lib/") {
            // `lib/<abi>/<file>`：ABI 是第一段，文件是第二段，且**只能**两段。
            //
            // "文件段里不能再有 `/`" 这条是 APK 约定的一部分（原生库就放在
            // `lib/<abi>/` 正下方），不是多余的严格。少了它，`lib/a/b/c.so`
            // 会被判成"ABI 是 a 的原生库"—— 一个真实 APK 里不存在的位置，
            // 却被标成原生库，等于无中生有。
            if let Some((abi, file)) = rest.split_once('/') {
                if !abi.is_empty() && !file.contains('/') && file.ends_with(".so") {
                    return Self::NativeLib(abi);
                }
            }
        }
        if let Some(ordinal) = dex_ordinal(name) {
            return Self::Dex(ordinal);
        }
        if let Some(rest) = name.strip_prefix("META-INF/") {
            // 大小写不敏感：真实的 APK 实测都是大写，但签名文件名的规范
            // 只要求扩展名按惯例，没必要因为大小写不给分类。
            let upper = rest.to_ascii_uppercase();
            if !upper.contains('/')
                && [".SF", ".RSA", ".DSA", ".EC"]
                    .iter()
                    .any(|ext| upper.ends_with(ext))
            {
                return Self::Signature;
            }
        }
        Self::Other
    }

    /// 稳定的短名（JSON / CLI）。
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Dex(_) => "dex",
            Self::NativeLib(_) => "native-lib",
            Self::Manifest => "manifest",
            Self::ResourceTable => "resource-table",
            Self::Signature => "signature",
            Self::Other => "other",
        }
    }
}

/// `classes.dex` → `Some(None)`；`classes<N>.dex`（N ≥ 2）→ `Some(Some(N))`；
/// 其他 → `None`。
///
/// 返回 `Option<Option<u32>>` 看着绕，但两种"没有"是不同的事：
/// 外层 `None` = "这名字不是 dex"，内层 `None` = "是 dex 但没有序号"。
/// 压成一个 `Option<u32>` 就没法区分 `classes.dex` 与"不是 dex"了。
fn dex_ordinal(name: &str) -> Option<Option<u32>> {
    if name == "classes.dex" {
        return Some(None);
    }
    let digits = name.strip_prefix("classes")?.strip_suffix(".dex")?;
    // 空串会在下面被 `parse` 拒掉；这里显式排除是为了读起来更直白。
    if digits.is_empty() {
        return None;
    }
    let n: u32 = digits.parse().ok()?;
    // `classes1.dex` 不是构建工具的产物（第一个没有序号），但真出现时
    // **如实报出号码**比归进"不是 dex"有用。
    Some(Some(n))
}
/// 成员枚举结果。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ZipListing {
    /// 成员清单，按中央目录顺序。
    pub members: Vec<ArchiveMember>,
    /// 是否因上限而截断了成员清单。
    pub truncated: bool,
    /// 枚举过程中的说明（截断原因、个别成员的问题等）。
    pub notes: Vec<String>,
    /// 签名块的**存在性**结论（不是校验结论，见 [`SignaturePresence`]）。
    pub signature: SignaturePresence,
}

/// 签名块的**存在性**。
///
/// # 这个类型刻意不叫 `Signature`
///
/// 它回答的只有"**有没有**那一块"，**没有**回答"签名对不对"。
/// 假名成 `Signature` 会让下游把"存在"当成"已验证"，
/// 而"存在 v2 签名块"与"v2 签名有效"是两件事（前者扫 16 字节魔数就有结论，
/// 后者要跑完整的签名校验）。
///
/// 所以字段名一律带 `present` / `scheme`，且**不含**任何形如 `valid` /
/// `verified` 的字段 —— 让"想误用"这件事在类型上就无处落脚。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct SignaturePresence {
    /// 是否存在 v1（JAR signing）的痕迹：中央目录里有 `META-INF/*.SF`。
    pub v1_present: bool,
    /// 是否存在 v2/v3 的 APK Signing Block（紧邻中央目录的那 16 字节魔数）。
    pub apk_signing_block_present: bool,
}

/// 成员枚举 + 签名存在性检测。
///
/// `bytes` 必须是**完整文件**。只给一部分前缀会得到
/// [`ParseError::DirectoryNotInRange`]（而不是"没有成员"）——
/// 这个区分是刻意的，见模块文档。
///
/// # Errors
///
/// 中央目录不在给定范围内；或中央目录在、但结构无法解析。
pub fn list_members(bytes: &[u8]) -> Result<ZipListing, ParseError> {
    let eocd = read_eocd(bytes).ok_or(ParseError::DirectoryNotInRange {
        what: "ZIP 中央目录结束记录",
        actual: bytes.len() as u64,
    })?;

    // 中央目录之后有一块可选的"APK 签名块"，它的尾部魔数紧贴中央目录起点。
    // 这里**只判断存在性**：魔数对上就说明有那么一块，不代表签名有效。
    let signature = SignaturePresence {
        v1_present: false, // 由下面的成员名扫描填
        apk_signing_block_present: apk_signing_block_present(bytes, eocd.cd_offset),
    };

    let archive = zip::ZipArchive::new(Cursor::new(bytes)).map_err(map_zip_error)?;
    let meta = archive.metadata();
    let total = meta.len();

    let mut notes = Vec::new();

    // 先核对"结束记录声明的成员数"是否可信。
    //
    // 非 ZIP64 的结束记录里成员数是 `u16`：一个真有 65538 个成员的文件，这个
    // 字段会**回绕**成 2。照单全收的后果是**只列出 2 个成员、且不报截断** ——
    // 界面完全看不出少了东西，正是 §7 禁止的"静默少给"。
    //
    // 所以自己走一遍中央目录数实际条数。**不能**拿实际条数去多枚举几个：
    // 读取接口是照着结束记录的成员数定位的，超出部分本来就取不出来
    // （见 `read_member`）。与其编一个取不到的数字，不如把"这里少给了"说清楚。
    if let Some(actual) = count_central_records(bytes, eocd.cd_offset, eocd.cd_size) {
        if actual as u64 != eocd.entries {
            notes.push(format!(
                "中央目录结束记录声明 {} 个成员，但中央目录里实际有 {actual} 条记录：\
                 下面的成员清单**不完整**（非 ZIP64 的记录里成员数字段只有 16 位，\
                 很可能已回绕；这样的文件按规范应当使用 ZIP64 扩展）",
                eocd.entries
            ));
        }
    }

    let (count, truncated) = member_budget(total);
    if truncated {
        notes.push(format!(
            "成员数为 {total}，超过上限 {MAX_ZIP_MEMBERS}：只列出前 {MAX_ZIP_MEMBERS} 个，\
             后续未枚举"
        ));
    }

    let mut members = Vec::with_capacity(count);
    let mut v1_present = false;
    for index in 0..count {
        let entry = meta.entry(index).map_err(map_zip_error)?;
        let member = to_member(bytes, index, &entry);
        if member.name.starts_with("META-INF/") && member.name.ends_with(".SF") {
            v1_present = true;
        }
        members.push(member);
    }

    Ok(ZipListing {
        members,
        truncated,
        notes,
        signature: SignaturePresence {
            v1_present,
            ..signature
        },
    })
}

/// 取出第 `index` 个成员的**内容**（已解压）。
///
/// `index` 是 [`ArchiveMember::index`]，即中央目录下标。
///
/// # 它不依赖 [`ArchiveMember::offset`]，但**确实**依赖本地头
///
/// 两条容易混起来的事，分开说清：
///
/// * 这个函数**不用**调用方传偏移 —— 它拿着中央目录条目自己定位，所以调用方
///   不必（也不能）拿 `offset` 去切片；
/// * 但底层读取**照样要解析本地头**，并且会校验它（实测：本地头魔数被改坏或
///   被指错位置时，返回的是 `Invalid local file header`）。
///
/// 第二点是实测出来的，不是推断：我原本以为"走中央目录就不必看本地头"，
/// 于是写了两个"本地头坏了也能取到内容"的用例，结果都失败了。所以这里的
/// 结论是：**本地头坏掉的成员是取不出内容的**，只能报错。
///
/// 那 [`ArchiveMember::offset`] 为 `None` 还有什么意义？有：它表示"我们**自己**
/// 没能算出数据起点"，用来避免把一个**合法却错误**的偏移（比如 0）交给调用方。
/// 而取内容的正确途径始终是这里 —— 让容器自己去解析、自己去校验。
///
/// # Errors
///
/// 中央目录不在范围内、下标越界、压缩方法不支持、本地头不合法、
/// 解压失败、或解压后超过 [`MAX_MEMBER_BYTES`]。
pub fn read_member(bytes: &[u8], index: usize) -> Result<Vec<u8>, ParseError> {
    // 同样要先分"没看全"与"坏了"两种情形。
    if read_eocd(bytes).is_none() {
        return Err(ParseError::DirectoryNotInRange {
            what: "ZIP 中央目录结束记录",
            actual: bytes.len() as u64,
        });
    }

    let mut archive = zip::ZipArchive::new(Cursor::new(bytes)).map_err(map_zip_error)?;
    if index >= archive.len() {
        return Err(ParseError::Inconsistent(format!(
            "成员下标 {index} 越界（该容器共 {} 个成员）",
            archive.len()
        )));
    }

    let mut entry = archive.by_index(index).map_err(map_zip_error)?;
    let declared = entry.size();

    // 上限检查放在**读之前**：`size()` 来自中央目录，是可信的声明值。
    // 声明本身超标就直接拒绝，不先解压出 4 GB 再判断。
    if declared > MAX_MEMBER_BYTES {
        return Err(ParseError::NotSupported {
            what: "ZIP 成员",
            detail: format!(
                "成员声明解压后为 {declared} 字节，超过上限 {MAX_MEMBER_BYTES} 字节：\
                 不解压（避免解压炸弹），请先确认该成员是否可信"
            ),
        });
    }

    // 再兜一层：`size()` 是**声明值**，可能说谎。用 `take` 把实际读取量也卡住。
    let mut out = Vec::new();
    let mut limited = (&mut entry).take(MAX_MEMBER_BYTES + 1);
    limited
        .read_to_end(&mut out)
        .map_err(|error| ParseError::Inconsistent(format!("成员 {index} 解压失败：{error}")))?;

    if out.len() as u64 > MAX_MEMBER_BYTES {
        return Err(ParseError::NotSupported {
            what: "ZIP 成员",
            detail: format!(
                "成员 {index} 的解压结果超过上限 {MAX_MEMBER_BYTES} 字节\
                 （声明值是 {declared}，实际更多）：已中止，返回值不可用"
            ),
        });
    }
    Ok(out)
}

// ── 中央目录定位 ────────────────────────────────────────────────────────────

/// 从 EOCD 里读出来、我们真正会用到的字段。
struct Eocd {
    /// 中央目录的文件偏移。
    cd_offset: u64,
    /// 中央目录声明的字节长度。
    cd_size: u64,
    /// 结束记录声明的成员数（注意：非 ZIP64 时字段是 `u16`，可能**回绕**）。
    entries: u64,
}

/// 从**末尾**往前找中央目录结束记录。
///
/// # 为什么要自己找
///
/// 不是为了解析（解析在 `zip` crate 里）。是为了把"给的字节里没有 EOCD"
/// 与"有 EOCD 但解析失败"分开，见模块文档。
///
/// 判据不只是"看到 `PK\x05\x06`"：文件内容里完全可能**恰好**出现这四个字节。
/// 合法的 EOCD 还必须满足 `偏移 + 22 + 注释长度 == 文件长度`（APPNOTE §4.3.16）。
/// 加上这一条，误命中就基本消掉了。
fn read_eocd(bytes: &[u8]) -> Option<Eocd> {
    if bytes.len() < EOCD_LEN {
        return None;
    }
    // 注释最长 65535，所以 EOCD 起点不可能在更靠前的位置。
    let lowest = bytes.len().saturating_sub(EOCD_SEARCH);
    // 从后往前扫：真的 EOCD 通常就在最后，反向找命中更快。
    for i in (lowest..=bytes.len() - EOCD_LEN).rev() {
        if bytes[i..i + 4] != EOCD_MAGIC {
            continue;
        }
        let comment_len = u64::from(le_u16(bytes, i + 20)?);
        if i as u64 + EOCD_LEN as u64 + comment_len != bytes.len() as u64 {
            continue;
        }
        // APPNOTE §4.3.16：+10 总条目数、+12 中央目录大小、+16 中央目录偏移。
        let entries = u64::from(le_u16(bytes, i + 10)?);
        let cd_size = u64::from(le_u32(bytes, i + 12)?);
        let cd_offset = u64::from(le_u32(bytes, i + 16)?);
        return Some(Eocd {
            cd_offset,
            cd_size,
            entries,
        });
    }
    None
}

/// 中央目录起点之前是否紧邻着一个 **APK Signing Block**。
///
/// # 为什么不能只对 16 字节魔数
///
/// 第一版就只比对了结尾那 16 字节的 `APK Sig Block 42`。问题是最后那个成员的
/// **数据**正好以这 16 字节结尾时，中央目录也紧跟在它后面 —— 于是"成员数据的
/// 末 16 字节"与"签名块魔数"在字节上完全一致，判断必然为真。这不是理论担心：
/// 单元测试里随手构造一个内容就是这串魔数的成员就复现了。
///
/// 所以这里按 APK Signature Scheme v2 的实际结构验证（size 字段是 `u64` 小端）：
///
/// ```text
/// size（不含自身这 8 字节）     ← 块首
/// 若干 ID-value 对
/// size（与块首**相同**）        ← 魔数之前
/// "APK Sig Block 42"（16 字节）
/// ```
///
/// 于是"块首的 size"与"魔数前的 size"必须相等，且 `size + 8` 要正好回退到块首。
/// 巧合要同时凑齐这三件事就没那么容易了。
///
/// # 仍然只是"存在性"
///
/// 通过这个检查**不**代表签名有效 —— 我们只核对了外壳的尺寸自洽，
/// 没有做任何摘要/证书校验。类型名与字段名都刻意避开 `valid` / `verified`。
fn apk_signing_block_present(bytes: &[u8], cd_offset: u64) -> bool {
    let Ok(cd) = usize::try_from(cd_offset) else {
        return false;
    };
    // 块最小长度 = size(8) + size(8) + magic(16) = 32 字节。
    let min_block = APK_SIG_BLOCK_SIZE_LEN * 2 + APK_SIG_BLOCK_MAGIC.len();
    if cd < min_block || cd > bytes.len() {
        return false;
    }
    if &bytes[cd - APK_SIG_BLOCK_MAGIC.len()..cd] != APK_SIG_BLOCK_MAGIC {
        return false;
    }

    let some = le_u64(
        bytes,
        cd - APK_SIG_BLOCK_MAGIC.len() - APK_SIG_BLOCK_SIZE_LEN,
    );
    let Some(trailing_size) = some else {
        return false;
    };

    // 块总长 = size + 自身那 8 字节；太大说明这个 size 是别的东西的巧合。
    let Some(total) = trailing_size.checked_add(APK_SIG_BLOCK_SIZE_LEN as u64) else {
        return false;
    };
    let Ok(total) = usize::try_from(total) else {
        return false;
    };
    if total > cd {
        return false;
    }
    let start = cd - total;

    // 块首必须记着**同一个** size。
    le_u64(bytes, start) == Some(trailing_size)
}

/// 走一遍中央目录，数出**实际**有多少条记录。
///
/// # 为什么需要这个数
///
/// 成员数来自中央目录结束记录里的 `u16` 字段。一个**没有** ZIP64 扩展、
/// 却有 65536 个以上成员的文件，这个字段会**回绕**（65538 → 2）。
/// 于是我们会开开心心地只列出 2 个成员，而 `truncated` 还是 `false` ——
/// 界面看不出少了东西。这正是 CLAUDE.md §7 禁止的"静默少给"。
///
/// 返回 `None` 表示"中央目录本身没走通"：那时我们**说不出**实际有多少，
/// 就不说 —— 不猜一个数字出来。
fn count_central_records(bytes: &[u8], cd_offset: u64, cd_size: u64) -> Option<usize> {
    let start = usize::try_from(cd_offset).ok()?;
    let end = start
        .checked_add(usize::try_from(cd_size).ok()?)?
        .min(bytes.len());

    let mut pos = start;
    let mut count = 0usize;
    while pos + CENTRAL_HEADER_LEN <= end {
        if bytes[pos..pos + 4] != CENTRAL_MAGIC {
            // 走到非记录位置：目录结构没走通，别猜。
            return None;
        }
        // APPNOTE §4.3.12：+28 文件名长度、+30 extra 长度、+32 注释长度。
        let name_len = le_u16(bytes, pos + 28)? as usize;
        let extra_len = le_u16(bytes, pos + 30)? as usize;
        let comment_len = le_u16(bytes, pos + 32)? as usize;
        pos = pos.checked_add(CENTRAL_HEADER_LEN + name_len + extra_len + comment_len)?;
        count += 1;
    }
    // 必须**正好**停在目录末尾；差一点就说明长度字段有假。
    (pos == end).then_some(count)
}

// ── 成员转换 ────────────────────────────────────────────────────────────────

/// 取 ZIP 压缩方法号（APPNOTE §4.4.5 的原始号码）。
///
/// # 为什么这里留着唯一一处 `allow(deprecated)`
///
/// `CompressionMethod::to_u16` 被标了 `deprecated`，但它的说明是
/// "**要匹配**其他压缩方法就用常量比较" —— 它不想让人拿号码**做分支**。
///
/// 我们恰恰相反：**就是要那个号码**，而且不做任何分支、原样存进
/// [`MemberStorage::Container::method`] 展示给用户。这样遇到没见过的号码
/// 能如实报出来，而不是被归进"其他"（§7）。
///
/// 备选方案是给 `MemberStorage` 再定义一个自己的枚举，但那样等于把
/// "ZIP 有哪些压缩方法"这份知识抄一遍，抄漏一个就又是一个坑。
/// 所以保留原号码，并在这里显式说明为什么不是漏改。
#[allow(deprecated)]
fn method_code(method: zip::CompressionMethod) -> u16 {
    method.to_u16()
}

/// 把一个中央目录条目转成 [`ArchiveMember`]。
fn to_member(bytes: &[u8], index: usize, entry: &zip::read::ZipFileEntry<'_>) -> ArchiveMember {
    let name = String::from_utf8_lossy(entry.name_raw()).into_owned();
    let method = method_code(entry.compression());
    let compressed_size = entry.compressed_size();
    let uncompressed_size = entry.size();

    // 目录条目（以 `/` 结尾）在 ZIP 里是**真实存在的条目**，但它不装载内容。
    // 这跟 ar 的元数据成员（`/` 符号索引、`//` 长名表）是同一类东西：
    // 它确实是成员，但不是"可分析的对象"。
    let is_dir = entry.is_dir();

    ArchiveMember {
        index,
        name,
        // 数据起点要从**本地头**算（中央目录只记本地头位置）。
        // 算不出来就留 `None`，不拿 0 冒充（见 `ArchiveMember::offset` 的说明）。
        offset: local_data_offset(bytes, entry.header_start()),
        size: compressed_size,
        // 内容是否完整在手上：中央目录声明的那段字节是否真的落在文件内。
        truncated: entry
            .header_start()
            .checked_add(compressed_size)
            .is_none_or(|end| end > bytes.len() as u64),
        // ZIP 成员一律走容器读取接口：数据在哪、要不要解压，都由容器目录说了算。
        storage: MemberStorage::Container {
            method,
            uncompressed_size,
        },
        // 目录条目不是可分析对象；其余成员先按"装载内容"记，
        // 真正的格式由上层拿内容去嗅探决定。
        payload: !is_dir,
        // 中央目录里没有架构字段，而且 ZIP 成员的格式本来就各不相同
        // （APK 里同时有 dex / `.so` / 清单 / 资源）。要知道架构得先解析成员内容，
        // 所以这里如实给 `None`。
        arch: None,
    }
}

/// 解析本地文件头，算出成员**数据**的起始偏移。
///
/// 布局见 APPNOTE §4.3.7：固定 30 字节，随后是文件名与 extra field
/// （长度分别记在固定部分的 +26 / +28）。
///
/// 返回 `None` 的两种情形都**不是**猜测能补救的，所以不猜：
/// 本地头不在文件内，或签名对不上（说明中央目录指的本地头位置是错的）。
fn local_data_offset(bytes: &[u8], header_start: u64) -> Option<u64> {
    let start = usize::try_from(header_start).ok()?;
    let head = bytes.get(start..start.checked_add(LOCAL_HEADER_LEN)?)?;
    if head[0..4] != LOCAL_MAGIC {
        return None;
    }
    let name_len = u64::from(le_u16(head, 26)?);
    let extra_len = u64::from(le_u16(head, 28)?);
    let data = header_start
        .checked_add(LOCAL_HEADER_LEN as u64)?
        .checked_add(name_len)?
        .checked_add(extra_len)?;
    // 数据起点必须落在文件内（可以正好等于文件长度：零字节成员）。
    (data <= bytes.len() as u64).then_some(data)
}

// ── 小工具 ──────────────────────────────────────────────────────────────────

fn le_u16(bytes: &[u8], off: usize) -> Option<u16> {
    let slice = bytes.get(off..off.checked_add(2)?)?;
    Some(u16::from_le_bytes([slice[0], slice[1]]))
}

fn le_u32(bytes: &[u8], off: usize) -> Option<u32> {
    let slice = bytes.get(off..off.checked_add(4)?)?;
    Some(u32::from_le_bytes([slice[0], slice[1], slice[2], slice[3]]))
}

fn le_u64(bytes: &[u8], off: usize) -> Option<u64> {
    let slice = bytes.get(off..off.checked_add(8)?)?;
    Some(u64::from_le_bytes([
        slice[0], slice[1], slice[2], slice[3], slice[4], slice[5], slice[6], slice[7],
    ]))
}

/// 把 `zip` crate 的错误映射成我们的 [`ParseError`]。
///
/// 映射时保持一条原则：**错误信息里出现的每个值都必须是文件里真实存在的**，
/// 不为了凑字段编一个编号出来（§7）。
///
/// 所以 `UnsupportedArchive` / `InvalidPassword` 走 [`ParseError::NotSupported`]
/// （没有哪个字段的取值能代表"整个用法还不支持"），而不是硬塞进
/// [`ParseError::Unsupported`] 那个形状（它要一个 `what` + `value`）。
fn map_zip_error(error: zip::result::ZipError) -> ParseError {
    use zip::result::ZipError;

    match error {
        ZipError::InvalidArchive(detail) => {
            ParseError::Inconsistent(format!("ZIP 中央目录结构不合法：{detail}"))
        }
        ZipError::UnsupportedArchive(detail) => ParseError::NotSupported {
            what: "ZIP 容器特性",
            detail: format!("{detail}（该用法尚未实现）"),
        },
        ZipError::FileNotFound => ParseError::Inconsistent("中央目录里没有这个成员".to_string()),
        ZipError::InvalidPassword => ParseError::NotSupported {
            what: "ZIP 容器特性",
            detail: "这个条目是加密的，需要口令才能读（当前不支持加密 ZIP）".to_string(),
        },
        ZipError::CompressionMethodNotSupported(method) => ParseError::NotSupported {
            what: "ZIP 压缩方法",
            detail: format!("方法号 {method} 不在支持列表里（APK 实测只用 0=stored 与 8=deflate）"),
        },
        // 走到这里说明是读一段**内存**切片出的错，正常不可能发生；
        // 如实报出来而不是吞掉。
        ZipError::Io(error) => ParseError::Inconsistent(format!("读取 ZIP 结构时出错：{error}")),
        // `ZipError` 是非穷尽枚举，保留兜底臂。
        other => ParseError::Inconsistent(format!("ZIP 解析失败：{other}")),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // ── 按规格拼 fixture，**不照解析代码拼**（CLAUDE.md §6.11）──────────────
    //
    // 下面每个字节偏移都对着 APPNOTE.TXT 的章节写出来。理由就是 §6.11 记的那次
    // 教训：`IMAGE_DEBUG_DIRECTORY.Type` 读错了位置，而单测是绿的 —— 因为合成
    // 镜像按同一个错误假设拼的。所以这里**刻意不用 `zip` crate 的写入器**：
    // 用它拼出来的"正确样例"只能证明"crate 能读自己写的"，证明不了我们读的是
    // 规格里那个位置。

    const LOCAL_SIG: u32 = 0x0403_4b50;
    const CENTRAL_SIG: u32 = 0x0201_4b50;
    const EOCD_SIG: u32 = 0x0605_4b50;
    /// 解压后的长度，用于验证 `read_member` 真的解压了。
    const DEFLATE_PAYLOAD: &[u8] = b"BitFlip deflate member: hello hello hello hello hello!";
    /// 由 CPython `zlib` 独立生成的 raw deflate 流（`compressobj(9, DEFLATED, -15)`），
    /// 并且**已由 zlib 自己解回原文核对过**。不是我们自己算出来的字节。
    const DEFLATE_STREAM: &[u8] = &[
        0x73, 0xca, 0x2c, 0x71, 0xcb, 0xc9, 0x2c, 0x50, 0x48, 0x49, 0x4d, 0xcb, 0x49, 0x2c, 0x49,
        0x55, 0xc8, 0x4d, 0xcd, 0x4d, 0x4a, 0x2d, 0xb2, 0x52, 0xc8, 0x48, 0xcd, 0xc9, 0xc9, 0xc7,
        0x45, 0x2a, 0x02, 0x00,
    ];
    /// 同一份 payload 的 CRC-32（zlib 算的）。
    const DEFLATE_CRC: u32 = 0x40d7_70af;

    /// 一个待写入的成员。
    struct Entry {
        name: Vec<u8>,
        method: u16,
        /// 真正写进文件的字节（压缩后）。
        stored: Vec<u8>,
        /// 中央目录里声明的**解压后**长度。
        uncompressed: u32,
        crc: u32,
        ext_attrs: u32,
        /// 把本地头的魔数改坏：用于验证"数据起点算不出来"时留 `None` 而不是 0。
        corrupt_local_magic: bool,
        /// 把中央目录里的本地头偏移改指别处。
        bend_local_offset: bool,
        /// 覆盖**中央目录**里声明的压缩后大小。
        ///
        /// 必须改中央目录那一份（而不是本地头）：`compressed_size()` 读的是
        /// 中央目录，而我们的 `truncated` 判据用的就是这个值。第一版改了本地头，
        /// 测试于是"通过不了但也没测到东西"——改错了地方。
        bend_compressed_size: Option<u32>,
    }

    /// 按规格拼一个 ZIP：本地头们 → 中央目录 → EOCD。
    #[derive(Default)]
    struct Zip {
        body: Vec<u8>,
        central: Vec<u8>,
        entries: Vec<Entry>,
        /// 插在中央目录**之前**的额外字节（模拟 APK Signing Block）。
        before_central: Vec<u8>,
        comment: Vec<u8>,
    }

    impl Zip {
        fn push(&mut self, mut e: Entry) -> &mut Self {
            let local_off = self.body.len() as u64;
            // APPNOTE §4.3.7 本地文件头：固定 30 字节 + 文件名 + extra。
            let sig = if e.corrupt_local_magic {
                LOCAL_SIG ^ 0xFFFF_FFFF
            } else {
                LOCAL_SIG
            };
            self.body.extend_from_slice(&sig.to_le_bytes()); // +0  签名
            self.body.extend_from_slice(&20u16.to_le_bytes()); // +4  所需版本
            self.body.extend_from_slice(&0u16.to_le_bytes()); // +6  通用标志位
            self.body.extend_from_slice(&e.method.to_le_bytes()); // +8  压缩方法
            self.body.extend_from_slice(&0u16.to_le_bytes()); // +10 修改时间
            self.body.extend_from_slice(&0u16.to_le_bytes()); // +12 修改日期
            self.body.extend_from_slice(&e.crc.to_le_bytes()); // +14 CRC-32
            self.body
                .extend_from_slice(&(e.stored.len() as u32).to_le_bytes()); // +18 压缩后大小
            self.body.extend_from_slice(&e.uncompressed.to_le_bytes()); // +22 解压后大小
            self.body
                .extend_from_slice(&(e.name.len() as u16).to_le_bytes()); // +26 文件名长度
            self.body.extend_from_slice(&0u16.to_le_bytes()); // +28 extra 长度
            self.body.extend_from_slice(&e.name); // +30 文件名
                                                  // 无 extra field
            self.body.extend_from_slice(&e.stored); // 数据

            // APPNOTE §4.3.12 中央目录记录：固定 46 字节 + 文件名 + extra + 注释。
            let pointed = if e.bend_local_offset {
                local_off + 7 // 一个**存在但不对**的位置：魔数肯定不是 PK\x03\x04
            } else {
                local_off
            };
            let c = &mut self.central;
            c.extend_from_slice(&CENTRAL_SIG.to_le_bytes()); // +0  签名
            c.extend_from_slice(&20u16.to_le_bytes()); // +4  创建版本
            c.extend_from_slice(&20u16.to_le_bytes()); // +6  所需版本
            c.extend_from_slice(&0u16.to_le_bytes()); // +8  通用标志位
            c.extend_from_slice(&e.method.to_le_bytes()); // +10 压缩方法
            c.extend_from_slice(&0u16.to_le_bytes()); // +12 修改时间
            c.extend_from_slice(&0u16.to_le_bytes()); // +14 修改日期
            c.extend_from_slice(&e.crc.to_le_bytes()); // +16 CRC-32
            c.extend_from_slice(
                &e.bend_compressed_size
                    .unwrap_or(e.stored.len() as u32)
                    .to_le_bytes(),
            ); // +20 压缩后大小
            c.extend_from_slice(&e.uncompressed.to_le_bytes()); // +24 解压后大小
            c.extend_from_slice(&(e.name.len() as u16).to_le_bytes()); // +28 文件名长度
            c.extend_from_slice(&0u16.to_le_bytes()); // +30 extra 长度
            c.extend_from_slice(&0u16.to_le_bytes()); // +32 注释长度
            c.extend_from_slice(&0u16.to_le_bytes()); // +34 起始磁盘号
            c.extend_from_slice(&0u16.to_le_bytes()); // +36 内部属性
            c.extend_from_slice(&e.ext_attrs.to_le_bytes()); // +38 外部属性
            c.extend_from_slice(&(pointed as u32).to_le_bytes()); // +42 本地头偏移
            c.extend_from_slice(&e.name); // +46 文件名

            e.name.clear();
            self.entries.push(e);
            self
        }

        /// 一个 stored（method 0）成员：数据原样写入。
        fn stored(&mut self, name: &str, data: &[u8]) -> &mut Self {
            let crc = crc32(data);
            self.push(Entry {
                name: name.as_bytes().to_vec(),
                method: 0,
                stored: data.to_vec(),
                uncompressed: data.len() as u32,
                crc,
                ext_attrs: 0,
                corrupt_local_magic: false,
                bend_local_offset: false,
                bend_compressed_size: None,
            })
        }

        /// 一个目录成员：APPNOTE §4.3.12 的外部属性低字节 bit 4 = DOS 目录位。
        fn dir(&mut self, name: &str) -> &mut Self {
            self.push(Entry {
                name: name.as_bytes().to_vec(),
                method: 0,
                stored: Vec::new(),
                uncompressed: 0,
                crc: 0,
                ext_attrs: 0x10,
                corrupt_local_magic: false,
                bend_local_offset: false,
                bend_compressed_size: None,
            })
        }

        /// 一个 deflate 成员：文件里是 `stored`，目录里声明解压后长度 `unc`。
        fn deflate(&mut self, name: &str, stored: &[u8], unc: u32, crc: u32) -> &mut Self {
            self.push(Entry {
                name: name.as_bytes().to_vec(),
                method: 8,
                stored: stored.to_vec(),
                uncompressed: unc,
                crc,
                ext_attrs: 0,
                corrupt_local_magic: false,
                bend_local_offset: false,
                bend_compressed_size: None,
            })
        }

        fn finish(&self) -> Vec<u8> {
            let mut out = self.body.clone();
            out.extend_from_slice(&self.before_central);
            let cd_off = out.len() as u32;
            out.extend_from_slice(&self.central);
            let cd_size = self.central.len() as u32;

            // APPNOTE §4.3.16 中央目录结束记录（22 字节 + 注释）。
            out.extend_from_slice(&EOCD_SIG.to_le_bytes()); // +0  签名
            out.extend_from_slice(&0u16.to_le_bytes()); // +4  本磁盘号
            out.extend_from_slice(&0u16.to_le_bytes()); // +6  中央目录起始磁盘号
            out.extend_from_slice(&(self.entries.len() as u16).to_le_bytes()); // +8  本盘条目数
            out.extend_from_slice(&(self.entries.len() as u16).to_le_bytes()); // +10 总条目数
            out.extend_from_slice(&cd_size.to_le_bytes()); // +12 中央目录大小
            out.extend_from_slice(&cd_off.to_le_bytes()); // +16 中央目录偏移
            out.extend_from_slice(&(self.comment.len() as u16).to_le_bytes()); // +20 注释长度
            out.extend_from_slice(&self.comment); // +22 注释
            out
        }
    }

    /// 测试用例自己算 CRC-32（与 `zip` crate 无关，见 APPNOTE §4.4.7）。
    fn crc32(data: &[u8]) -> u32 {
        let mut crc = 0xFFFF_FFFFu32;
        for &byte in data {
            crc ^= u32::from(byte);
            for _ in 0..8 {
                crc = if crc & 1 != 0 {
                    (crc >> 1) ^ 0xEDB8_8320
                } else {
                    crc >> 1
                };
            }
        }
        !crc
    }

    // ── 用例 ────────────────────────────────────────────────────────────────

    /// 空 ZIP（只有 EOCD）→ 0 个成员，**不是**错误。
    ///
    /// 这条把"目录在、成员为零"与"目录不在"分开：前者要正常返回空列表。
    #[test]
    fn empty_zip_lists_zero_members() {
        let bytes = Zip::default().finish();
        let listing = list_members(&bytes).expect("空 ZIP 应当能列出成员");
        assert!(listing.members.is_empty(), "{:?}", listing.members);
        assert!(!listing.truncated);
    }

    /// stored 成员：名字、大小、偏移、方法号都要对得上，且能取回原字节。
    #[test]
    fn stored_member_is_listed_and_readable() {
        let payload = b"hello stored member";
        let bytes = Zip::default().stored("payload.bin", payload).finish();

        let listing = list_members(&bytes).expect("列出成员");
        assert_eq!(listing.members.len(), 1);
        let m = &listing.members[0];
        assert_eq!(m.name, "payload.bin");
        assert_eq!(m.size, payload.len() as u64);
        assert!(m.payload);
        assert!(!m.truncated);
        assert_eq!(
            m.storage,
            MemberStorage::Container {
                method: 0,
                uncompressed_size: payload.len() as u64
            }
        );
        assert!(!m.storage.is_inline(), "ZIP 成员一律走容器取出");

        // 偏移必须正好指向数据（本地头 30 + 名字长度 + extra 0）。
        assert_eq!(m.offset, Some(30 + "payload.bin".len() as u64));

        assert_eq!(read_member(&bytes, m.index).expect("取成员"), payload);
    }

    /// deflate 成员：`read_member` 必须**解压**，而不是把压缩流当内容返回。
    #[test]
    fn deflate_member_is_decompressed_on_read() {
        assert_eq!(crc32(DEFLATE_PAYLOAD), DEFLATE_CRC, "fixture 的 CRC 自检");
        let bytes = Zip::default()
            .deflate(
                "libs/arm64-v8a/libx.so",
                DEFLATE_STREAM,
                DEFLATE_PAYLOAD.len() as u32,
                DEFLATE_CRC,
            )
            .finish();

        let listing = list_members(&bytes).expect("列出成员");
        let m = &listing.members[0];
        assert_eq!(
            m.storage,
            MemberStorage::Container {
                method: 8,
                uncompressed_size: DEFLATE_PAYLOAD.len() as u64
            }
        );
        // `size` 是**压缩后**大小：这就是不能让消费方拿它当 file_size 的原因。
        assert_eq!(m.size, DEFLATE_STREAM.len() as u64);
        assert_ne!(m.size, DEFLATE_PAYLOAD.len() as u64);

        assert_eq!(
            read_member(&bytes, m.index).expect("取成员"),
            DEFLATE_PAYLOAD,
            "取出的必须是解压后的字节；若这里是压缩流，说明根本没解压"
        );
    }

    /// 目录成员在列表里看得见，但不算"装载内容的成员"。
    #[test]
    fn directory_entry_is_listed_but_not_a_payload() {
        let bytes = Zip::default()
            .dir("lib/")
            .stored("lib/a.so", b"xyz")
            .finish();
        let listing = list_members(&bytes).expect("列出成员");
        assert_eq!(listing.members.len(), 2);
        assert_eq!(listing.members[0].name, "lib/");
        assert!(!listing.members[0].payload, "目录不是可分析对象");
        assert!(listing.members[1].payload);
    }

    /// **没有 EOCD 时必须报"目录不在范围内"，不能报"没有成员"。**
    ///
    /// 这是整个模块最要紧的一条（§7）：嗅探只给前缀时，文件本身可能完好，
    /// 只是中央目录在没读到的那一段里。报"没有成员"会让用户去修一个没坏的文件。
    #[test]
    fn missing_eocd_is_reported_as_not_in_range() {
        let full = Zip::default().stored("a.bin", b"data").finish();
        // 只给前 40 字节：连本地头都没给全，更别说末尾的中央目录。
        let error = list_members(&full[..40]).expect_err("前缀里没有中央目录，必须报错");
        match error {
            ParseError::DirectoryNotInRange { what, actual } => {
                assert!(what.contains("中央目录"), "{what}");
                assert_eq!(actual, 40);
            }
            other => panic!("应当报 DirectoryNotInRange，实际是 {other:?}"),
        }

        // 同样地，取成员也要报这一条（而不是"越界"或"结构不合法"）。
        let error = read_member(&full[..40], 0).expect_err("前缀取成员也必须报错");
        assert!(
            matches!(error, ParseError::DirectoryNotInRange { .. }),
            "实际是 {error:?}"
        );
    }

    /// 完全不是 ZIP 的字节：报"目录不在范围内"。
    #[test]
    fn non_zip_bytes_are_not_in_range() {
        let error = list_members(b"\x7fELF\x02\x01\x01\x00 not a zip at all")
            .expect_err("不是 ZIP 就该报错");
        assert!(
            matches!(error, ParseError::DirectoryNotInRange { .. }),
            "实际是 {error:?}"
        );
    }

    /// EOCD 后面带注释时仍然要找得到。
    ///
    /// 注释会让 EOCD **不**在文件最后 22 字节处结束，所以"只看末尾 22 字节"
    /// 的实现会在这里失败。
    #[test]
    fn eocd_with_trailing_comment_is_found() {
        let mut zip = Zip::default();
        zip.stored("a.bin", b"data");
        zip.comment = b"this is a zip comment, 34+ bytes long................".to_vec();
        let bytes = zip.finish();

        let listing = list_members(&bytes).expect("带注释的 ZIP 应当能列出成员");
        assert_eq!(listing.members.len(), 1);
        assert_eq!(listing.members[0].name, "a.bin");
    }

    /// 文件内容里**恰好**出现 `PK\x05\x06` 不能骗过定位。
    ///
    /// 判据不止是魔数：还要满足"偏移 + 22 + 注释长度 == 文件长度"。
    #[test]
    fn stray_eocd_magic_inside_member_data_does_not_confuse_the_search() {
        // 成员数据里塞一个假的 EOCD（注释长度故意写成 0xFFFF，必不成立）。
        let mut fake = Vec::new();
        fake.extend_from_slice(&EOCD_SIG.to_le_bytes());
        fake.extend_from_slice(&[0u8; 16]);
        fake.extend_from_slice(&0xFFFFu16.to_le_bytes());

        let mut zip = Zip::default();
        zip.stored("trap.bin", &fake);
        zip.stored("real.bin", b"real data");
        let bytes = zip.finish();

        let listing = list_members(&bytes).expect("假魔数不该影响定位");
        assert_eq!(listing.members.len(), 2);
        assert_eq!(listing.members[1].name, "real.bin");
    }

    /// 本地头魔数被改坏：偏移留 `None`，**不拿 0 冒充**；取内容则**必须报错**。
    ///
    /// # 这条用例纠正了一个想当然的推断
    ///
    /// 最初写的是"本地头坏了也照样能按 index 取到内容"，理由是"取内容走中央目录，
    /// 不看本地头"。跑下来直接失败：底层读取**会**校验本地头。
    ///
    /// 所以这里断言的是**真实**行为：这类成员取不出内容，只能明确报错。
    /// 保留这条用例的价值就在于它是那次的记录 —— 免得以后又有人照着同样的
    /// 想当然去改设计。
    #[test]
    fn broken_local_header_leaves_offset_unknown_and_read_fails_honestly() {
        let payload = b"content does not survive a broken local header";
        let mut zip = Zip::default();
        zip.push(Entry {
            name: b"broken.bin".to_vec(),
            method: 0,
            stored: payload.to_vec(),
            uncompressed: payload.len() as u32,
            crc: crc32(payload),
            ext_attrs: 0,
            corrupt_local_magic: true,
            bend_local_offset: false,
            bend_compressed_size: None,
        });
        let bytes = zip.finish();

        let listing = list_members(&bytes).expect("列成员");
        let m = &listing.members[0];
        assert_eq!(
            m.offset, None,
            "本地头魔数不对时偏移必须留 None，不能用 0 冒充"
        );

        // 取内容必须失败，且理由要指向本地头 —— 不能静默返回一段错的数据。
        let error = read_member(&bytes, m.index).expect_err("本地头坏了就取不出内容");
        let text = error.to_string();
        assert!(
            text.contains("本地头") || text.to_lowercase().contains("local file header"),
            "错误信息应指向本地头：{text}"
        );
    }

    /// 中央目录把本地头偏移指到别处：偏移留 `None`，取内容报错。
    ///
    /// 与上一条的区别在**成因**：上一条是本地头本身坏了，这条是目录里的指针
    /// 指错了。两者都导致"数据起点不可信"，而对外表现必须一致：偏移未知 + 取不出。
    #[test]
    fn bent_local_offset_leaves_offset_unknown() {
        let payload = b"bent";
        let mut zip = Zip::default();
        zip.push(Entry {
            name: b"bent.bin".to_vec(),
            method: 0,
            stored: payload.to_vec(),
            uncompressed: payload.len() as u32,
            crc: crc32(payload),
            ext_attrs: 0,
            corrupt_local_magic: false,
            bend_local_offset: true,
            bend_compressed_size: None,
        });
        let bytes = zip.finish();

        let listing = list_members(&bytes).expect("列成员");
        assert_eq!(listing.members[0].offset, None);
        assert!(
            read_member(&bytes, listing.members[0].index).is_err(),
            "指针指错位置时取内容必须报错，不能给出别处的字节"
        );
    }

    /// 按 APK Signature Scheme v2 的结构拼一个签名块。
    ///
    /// ```text
    /// size（不含自身这 8 字节）   ← 块首
    /// 若干 ID-value 对（本函数由 `pairs` 给出）
    /// size（与块首相同）          ← 魔数之前
    /// "APK Sig Block 42"（16 字节）
    /// ```
    ///
    /// 所以 `size = pairs + 8（尾部 size） + 16（魔数）`。
    fn apk_signing_block(pairs: &[u8]) -> Vec<u8> {
        let size =
            pairs.len() as u64 + APK_SIG_BLOCK_SIZE_LEN as u64 + APK_SIG_BLOCK_MAGIC.len() as u64;
        let mut out = Vec::new();
        out.extend_from_slice(&size.to_le_bytes());
        out.extend_from_slice(pairs);
        out.extend_from_slice(&size.to_le_bytes());
        out.extend_from_slice(APK_SIG_BLOCK_MAGIC);
        out
    }

    /// 签名**存在性**：v1 看 `META-INF/*.SF`，v2/v3 看中央目录前的整块结构。
    ///
    /// 只验证"存在性"这个结论本身；**不**断言任何签名有效 ——
    /// `SignaturePresence` 里压根没有 `valid` / `verified` 这类字段。
    #[test]
    fn signature_presence_is_detected_without_claiming_validity() {
        // 没有任何签名痕迹
        let plain = Zip::default().stored("a.bin", b"d").finish();
        let sig = list_members(&plain).expect("列成员").signature;
        assert!(!sig.v1_present);
        assert!(!sig.apk_signing_block_present);

        // v1：有 META-INF/CERT.SF
        let mut v1 = Zip::default();
        v1.stored("META-INF/CERT.SF", b"Signature-Version: 1.0");
        v1.stored("a.bin", b"d");
        let sig = list_members(&v1.finish()).expect("列成员").signature;
        assert!(sig.v1_present);
        assert!(!sig.apk_signing_block_present);

        // v2/v3：中央目录之前是一个**结构自洽**的签名块
        let mut v2 = Zip::default();
        v2.stored("a.bin", b"d");
        v2.before_central = apk_signing_block(&[]);
        let sig = list_members(&v2.finish()).expect("列成员").signature;
        assert!(sig.apk_signing_block_present);
        assert!(!sig.v1_present);

        // 带 id-value 对的块也要认得（对里塞几个字节模拟一项签名）
        let mut v2b = Zip::default();
        v2b.stored("a.bin", b"d");
        v2b.before_central = apk_signing_block(&[0x71, 0x02, 0, 0, 0x04, 0, 0, 0, 1, 2, 3, 4]);
        let sig = list_members(&v2b.finish()).expect("列成员").signature;
        assert!(sig.apk_signing_block_present);
    }

    /// **只有** 16 字节魔数、没有自洽尺寸结构的，不算签名块。
    ///
    /// 这条用例是被第一版实现逼出来的：那时判据只是"中央目录前 16 字节 == 魔数"，
    /// 于是"最后一个成员的数据正好以这 16 字节结尾"的文件会被误判成有签名块。
    /// 这不是假想的巧合 —— 下面这个 fixture 就是随手构造的，第一版必然为真。
    #[test]
    fn bare_magic_without_a_consistent_size_is_not_a_signing_block() {
        // 成员数据恰好就是那 16 字节魔数 → 中央目录紧跟在它后面
        let mut coincidental = Zip::default();
        coincidental.stored("coincidence.bin", APK_SIG_BLOCK_MAGIC);
        let sig = list_members(&coincidental.finish())
            .expect("列成员")
            .signature;
        assert!(
            !sig.apk_signing_block_present,
            "只有 16 字节魔数、尺寸字段对不上，不应当算作签名块"
        );
    }

    /// 成员数上限的算术（逻辑单测）。
    ///
    /// 触发真实截断需要 ZIP64 —— 非 ZIP64 的成员数字段是 16 位，永远够不到
    /// 65535 这条线。手工拼 ZIP64 fixture 的成本远高于这段算术的价值，
    /// 所以把算术抽成纯函数直接测，而不是"构造不出来就不测"。
    #[test]
    fn member_budget_caps_and_flags() {
        assert_eq!(member_budget(0), (0, false));
        assert_eq!(member_budget(1), (1, false));
        assert_eq!(member_budget(MAX_ZIP_MEMBERS), (MAX_ZIP_MEMBERS, false));
        assert_eq!(
            member_budget(MAX_ZIP_MEMBERS + 1),
            (MAX_ZIP_MEMBERS, true),
            "刚好超过一个就要截断并置位"
        );
        assert_eq!(member_budget(usize::MAX), (MAX_ZIP_MEMBERS, true));
    }

    /// APK 成员名 → 角色。**纯名字判定**，所以这些用例都是字符串。
    ///
    /// 同时钉住三条边界：不误报（普通成员必须是 `Other`）、不吞号码
    /// （`classes2.dex` 的序号要如实给出）、不越界（`lib/a/b/c.so` 里
    /// ABI 只取第一段）。
    #[test]
    fn apk_roles_come_from_names_only() {
        // 真实 APK 里实测出现过的名字
        assert_eq!(ApkRole::of("classes.dex"), ApkRole::Dex(None));
        assert_eq!(ApkRole::of("classes2.dex"), ApkRole::Dex(Some(2)));
        assert_eq!(ApkRole::of("classes3.dex"), ApkRole::Dex(Some(3)));
        assert_eq!(
            ApkRole::of("lib/arm64-v8a/libBugly_Native.so"),
            ApkRole::NativeLib("arm64-v8a")
        );
        assert_eq!(
            ApkRole::of("lib/x86_64/libmsc.so"),
            ApkRole::NativeLib("x86_64")
        );
        assert_eq!(ApkRole::of("AndroidManifest.xml"), ApkRole::Manifest);
        assert_eq!(ApkRole::of("resources.arsc"), ApkRole::ResourceTable);
        assert_eq!(ApkRole::of("META-INF/CERT.SF"), ApkRole::Signature);
        assert_eq!(ApkRole::of("META-INF/CERT.RSA"), ApkRole::Signature);
        assert_eq!(
            ApkRole::of("META-INF/com/android/build/gradle/app-metadata.properties"),
            ApkRole::Other
        );

        // 「长得像但不是」的那几类必须落在 Other，不许硬凑
        //
        // `classes.dex` 的**前缀**匹配：`classesX.dex` 里 X 必须是数字，
        // 否则不是 dex 序号（`classes.dex` 已单独判过）。
        assert_eq!(ApkRole::of("classesX.dex"), ApkRole::Other);
        assert_eq!(ApkRole::of("sub/classes.dex"), ApkRole::Other);
        assert_eq!(ApkRole::of("classes2.dex.bak"), ApkRole::Other);
        assert_eq!(ApkRole::of("classes.dex.jar"), ApkRole::Other);
        // 目录不是 .so
        assert_eq!(ApkRole::of("lib/arm64-v8a/"), ApkRole::Other);
        // `lib/<abi>/` 下面还套目录：`.so` 判断直接否掉
        assert_eq!(ApkRole::of("lib/a/b/c.so"), ApkRole::Other);
        // 只有 ABI 一段、没有文件
        assert_eq!(ApkRole::of("lib/arm64-v8a"), ApkRole::Other);
        // 不在 lib/ 下的同名文件不算
        assert_eq!(ApkRole::of("assets/lib/x86/libfoo.so"), ApkRole::Other);
        // 签名文件必须直接在 META-INF/ 下
        assert_eq!(ApkRole::of("META-INF/sub/CERT.SF"), ApkRole::Other);
        // 普通成员
        assert_eq!(ApkRole::of("res/drawable/icon.png"), ApkRole::Other);
        assert_eq!(ApkRole::of(""), ApkRole::Other);

        // 短名稳定（JSON 契约）
        assert_eq!(ApkRole::of("classes2.dex").as_str(), "dex");
        assert_eq!(ApkRole::of("lib/x86/liba.so").as_str(), "native-lib");
        assert_eq!(ApkRole::of("AndroidManifest.xml").as_str(), "manifest");
        assert_eq!(ApkRole::of("resources.arsc").as_str(), "resource-table");
        assert_eq!(ApkRole::of("META-INF/A.SF").as_str(), "signature");
        assert_eq!(ApkRole::of("res/a.png").as_str(), "other");
    }

    /// `count_central_records` 的两条路径：走得通给实际条数，走不通给 `None`。
    ///
    /// `None` 那一支很要紧：它代表"我们说**不出**实际有多少条"。那时**不猜**，
    /// 也就不产生任何"成员数对不上"的结论 —— 宁可不说，不可说错。
    #[test]
    fn central_record_count_is_exact_or_none() {
        let bytes = Zip::default()
            .dir("d/")
            .stored("a.bin", b"a")
            .stored("b.bin", b"bb")
            .finish();

        // 从结束记录里取出真实的目录范围，再自己数一遍。
        let eocd = read_eocd(&bytes).expect("应能定位结束记录");
        assert_eq!(
            count_central_records(&bytes, eocd.cd_offset, eocd.cd_size),
            Some(3),
            "中央目录里实际是 3 条记录"
        );

        // 目录范围指向文件开头 → 那里是本地头（PK\\x03\\x04），不是中央目录记录。
        assert_eq!(
            count_central_records(&bytes, 0, eocd.cd_size),
            None,
            "从非记录处开始走不通，必须给 None 而不是编一个数"
        );

        // 长度少给 1 字节 → 走不到目录末尾，"正好停住"这条不成立。
        assert_eq!(
            count_central_records(&bytes, eocd.cd_offset, eocd.cd_size - 1),
            None
        );
    }

    /// 非 ZIP64 的成员数字段回绕时，必须**报出来**，不能静默少给。
    ///
    /// 65538 个成员会让 `u16` 的成员数字段回绕成 2。若照单全收，界面会显示
    /// "2 个成员"、`truncated` 还是 `false` —— 用户完全看不出少了 65536 个。
    #[test]
    fn wrapped_member_count_is_reported_not_silently_truncated() {
        let mut zip = Zip::default();
        // 数量取 65538：回绕后 u16 字段 = 2，与真实条数明显不符。
        for _ in 0..65_538 {
            zip.stored("f.bin", b"x");
        }
        let bytes = zip.finish();

        let listing = list_members(&bytes).expect("列成员");

        // 关键：必须留下"清单不完整"的说明，而不是悄悄只给 2 个。
        assert!(
            listing
                .notes
                .iter()
                .any(|n| n.contains("不完整") && n.contains("65538")),
            "回绕必须被报出来：notes = {:?}，members = {}",
            listing.notes,
            listing.members.len()
        );
    }

    /// 中央目录声明的大小越过文件末尾的成员要被标成 truncated。
    ///
    /// # 得改**中央目录**那一份，不是本地头那一份
    ///
    /// 第一版改的是本地头里的"压缩后大小"，测试没测到东西：`compressed_size()`
    /// 读的是**中央目录**的值，我们的 `truncated` 判据用的正是它。
    /// 改错了位置，等于什么都没验证（§6.11 的同类错误：fixture 没对着被测的那份数据）。
    #[test]
    fn member_extending_past_eof_is_flagged_truncated() {
        let mut zip = Zip::default();
        zip.push(Entry {
            name: b"liar.bin".to_vec(),
            method: 0,
            stored: b"short".to_vec(),
            uncompressed: 4096,
            crc: 0,
            ext_attrs: 0,
            corrupt_local_magic: false,
            bend_local_offset: false,
            // 中央目录声称压缩后有 4096 字节，实际只写了 5 字节。
            bend_compressed_size: Some(4096),
        });
        let bytes = zip.finish();

        let listing = list_members(&bytes).expect("列成员");
        let m = &listing.members[0];
        assert_eq!(m.size, 4096, "读到的应是中央目录里声明的那个大小");
        assert!(m.truncated, "声明长度越过文件末尾必须标记 truncated：{m:?}");
    }

    /// 不认识的压缩方法要**报出号码**，而不是归成"未知压缩"或静默失败。
    #[test]
    fn unsupported_method_is_reported_with_its_number() {
        let mut zip = Zip::default();
        zip.push(Entry {
            name: b"weird.bin".to_vec(),
            method: 99,
            stored: b"\x00\x01\x02".to_vec(),
            uncompressed: 3,
            crc: 0,
            ext_attrs: 0,
            corrupt_local_magic: false,
            bend_local_offset: false,
            bend_compressed_size: None,
        });
        let bytes = zip.finish();

        // 列成员本身不该失败：方法号是**如实报告**的内容，不是错误。
        let listing = list_members(&bytes).expect("列成员不应因方法号而失败");
        assert_eq!(listing.members[0].storage.method(), Some(99));
        assert!(
            listing.members[0].storage.label_zh().contains("99"),
            "说明里必须出现原始号码：{}",
            listing.members[0].storage.label_zh()
        );

        // 取内容则必须明确失败，且说清是什么原因。
        let error = read_member(&bytes, 0).expect_err("不认识的方法取内容必须报错");
        let text = match &error {
            ParseError::NotSupported { detail, .. } => detail.clone(),
            other => panic!("应当报 NotSupported，实际是 {other:?}"),
        };
        assert!(text.contains("99"), "错误里必须出现原始号码：{text}");
    }

    /// 成员的 `index` 必须是中央目录下标 —— `read_member` 靠它定位。
    ///
    /// 若实现把 index 记成"过滤后的序号"，跳过一个非 payload 成员之后
    /// 所有 index 都会错位，而这种错位在列表上看不出来。
    #[test]
    fn member_index_follows_central_directory_order() {
        let bytes = Zip::default()
            .dir("dir/")
            .stored("real.bin", b"real payload")
            .finish();
        let listing = list_members(&bytes).expect("列成员");

        assert_eq!(listing.members[0].index, 0);
        assert_eq!(listing.members[1].index, 1);
        assert_eq!(listing.members[0].name, "dir/");
        assert_eq!(listing.members[1].name, "real.bin");
        assert_eq!(
            read_member(&bytes, listing.members[1].index).expect("取成员"),
            b"real payload"
        );
    }
}
