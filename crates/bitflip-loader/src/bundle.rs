//! 从 `.app` / IPA 的成员表里认出**主二进制**，并且把"凭什么认出它"一起带出来。
//!
//! # 为什么要单独一个模块
//!
//! 这段判断原先只活在 `tests/macho_real_sample.rs` 里。测试里能跑，但界面上
//! 用不到 —— 于是用户看到"主二进制是 X"时，无法知道这是文件里写着的事实，
//! 还是我们按约定推出来的猜测。§7 的底线是"降级要写在界面上"，而推测比降级更
//! 需要自报家门：一个猜出来的答案如果长得和事实一模一样，那它就是**错的**答案。
//!
//! # 三种依据，优先级写在类型里
//!
//! 1. [`MainBinarySource::FromPlist`]：`Info.plist` 的 `CFBundleExecutable` 指向哪个
//!    文件 —— 这是**文件里写着的事实**，所以优先。
//! 2. [`MainBinarySource::NameMatch`]：`.app` 目录名与可执行名一致（IPA 里是
//!    `Payload/<Name>.app/<Name>`；目录容器里是根层 `<Name>` 或
//!    `Contents/MacOS/<Name>`）。这是**约定**，不是规范；加固/改名工具会破坏它。
//! 3. [`MainBinarySource::Guessed`]：前两条都落空时，取 bundle 层里第一个头
//!    4 字节是 Mach-O 魔数的成员。这条是**推断**，界面必须标明。
//!
//! 事实无法拿到时（`Info.plist` 缺失、损坏，或它声明的名字不在归档里），降级过程本身
//! 会作为 `MainBinary::notes` 跟着结论一起出来 —— 不吭声地退回约定/推断，等于把
//! "读不到"伪装成"没有"（CLAUDE.md §7）。
//!
//! # 两种容器布局
//!
//! 同一个判断要同时服务 [`BundleLayout::Ipa`]（ZIP 里的 `Payload/*.app/`）与
//! [`BundleLayout::Directory`]（`bitflip-cli` 直接打开 `.app` 目录，iOS 根层或
//! macOS 的 `Contents/` 结构）。目录容器还顺带承担"枚举成员 / 按名读盘"
//! （[`enumerate_app_directory`] / [`read_app_member`]）。

use std::path::Path;

use crate::plist;
use crate::{ArchiveMember, LoaderError, MemberStorage};

/// 两种容器布局。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BundleLayout {
    /// IPA / ZIP：成员名带 `Payload/<X>.app/` 前缀。
    Ipa,
    /// 目录容器：打开的目录**就是** `.app`（iOS 根层 `Info.plist` + 根层可执行，
    /// 或 macOS 的 `Contents/Info.plist` + `Contents/MacOS/<name>`）。
    Directory,
}

impl BundleLayout {
    /// 名字拆成"（bundle 段, 层内文件）"。
    ///
    /// * IPA：`Payload/X.app/Y` → `("X.app", "Y")`；再深一层（`Y/Z`）是资源。
    /// * 目录：根层文件 `Y` → `("", "Y")`；`Contents/Info.plist` →
    ///   `("Contents", "Info.plist")`；`Contents/MacOS/Foo` → `("MacOS", "Foo")`。
    ///   比这两层更深（`Contents/Resources/...`）是资源。
    fn layer(self, name: &str) -> Option<(&str, &str)> {
        match self {
            Self::Ipa => {
                let rest = name.strip_prefix("Payload/")?;
                let mut parts = rest.split('/');
                let (bundle, file) = (parts.next()?, parts.next()?);
                if parts.next().is_some() {
                    return None;
                }
                bundle.ends_with(".app").then_some((bundle, file))
            }
            Self::Directory => {
                if !name.contains('/') {
                    return Some(("", name));
                }
                let rest = name.strip_prefix("Contents/")?;
                let mut parts = rest.split('/');
                let first = parts.next()?;
                let Some(second) = parts.next() else {
                    // `Contents/<file>`（如 Contents/Info.plist）：Contents 是
                    // 唯一子层，把它当成"bundle 段"。
                    return Some(("Contents", first));
                };
                if parts.next().is_some() {
                    return None;
                }
                Some((first, second))
            }
        }
    }

    /// 这个文件是不是 `Info.plist`（事实来源所在）。
    fn is_plist(self, bundle: &str, file: &str) -> bool {
        match self {
            Self::Ipa => file == "Info.plist",
            Self::Directory => matches!(
                (bundle, file),
                ("", "Info.plist") | ("Contents", "Info.plist")
            ),
        }
    }

    /// 同名约定：`file` 是不是"目录名去掉 `.app`"那个名字。
    ///
    /// IPA 布局里每个成员自带 bundle 段（`Payload/<X>.app/<file>`），约定就是
    /// `file == X`，不需要 `bundle_name`；目录布局才用 `bundle_name`
    /// （目录名去掉 `.app`，在根层或 `MacOS` 层找同名文件）。
    fn is_name_match(self, bundle_name: Option<&str>, bundle: &str, file: &str) -> bool {
        match self {
            Self::Ipa => file == bundle.trim_end_matches(".app"),
            Self::Directory => {
                let Some(short) = bundle_name else {
                    return false;
                };
                match bundle {
                    "" => file == short,
                    "MacOS" => file == short,
                    _ => false,
                }
            }
        }
    }

    /// plist 声明 `CFBundleExecutable` 之后，主二进制成员的**完整名字**。
    fn plist_wanted(self, bundle: &str, executable: &str) -> String {
        match self {
            Self::Ipa => format!("Payload/{bundle}/{executable}"),
            Self::Directory => match bundle {
                "" => executable.to_string(),
                _ => format!("Contents/MacOS/{executable}"),
            },
        }
    }
}

/// 认出主二进制用的是哪条依据。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MainBinarySource {
    /// `Info.plist` 的 `CFBundleExecutable`：文件里写着的事实。
    FromPlist,
    /// `.app` 目录名与可执行名一致：按同名约定匹配上的。
    NameMatch,
    /// 前两条落空后的推断：bundle 层里第一个头 4 字节是 Mach-O 魔数的成员。
    Guessed,
}

impl MainBinarySource {
    /// 给人看的依据说明（中文）。
    #[must_use]
    pub fn label_zh(self) -> &'static str {
        match self {
            Self::FromPlist => "按 Info.plist 的 CFBundleExecutable 定位（文件里写着的事实）",
            Self::NameMatch => "按 `.app` 同名约定匹配",
            Self::Guessed => "推断（同名匹配落空，取 bundle 层里第一个 Mach-O 头）",
        }
    }

    /// 这是不是**猜**出来的。
    ///
    /// 调用方据此决定要不要在界面上加重语气 —— 事实与推测不能长得一样。
    #[must_use]
    pub fn is_guess(self) -> bool {
        matches!(self, Self::Guessed)
    }
}

/// 认出来的主二进制。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MainBinary {
    /// 成员下标（`ArchiveMember` 在成员表里的位置）。
    pub index: usize,
    /// 成员名，原样（`Payload/X.app/X`）。
    pub name: String,
    /// 依据。
    pub source: MainBinarySource,
    /// 认的过程中发生的降级（`Info.plist` 缺失/损坏/与归档不符）。
    ///
    /// 这些必须跟着结论一起进 `notes`：结论是对的，但"为什么不是事实来源"同样是
    /// 用户该知道的信息（§7：降级要写在界面上）。
    pub notes: Vec<String>,
}

impl MainBinary {
    /// 一句话结论，直接进 `notes` / 界面。
    ///
    /// **推测那一档必须带出"这是推断"**，否则用户会把猜出来的答案当成文件里的事实。
    #[must_use]
    pub fn note_zh(&self) -> String {
        if self.source.is_guess() {
            format!(
                "主二进制：{}（{}）—— 这是**推断**，不是文件里写着的事实",
                self.name,
                self.source.label_zh()
            )
        } else {
            format!("主二进制：{}（{}）", self.name, self.source.label_zh())
        }
    }
}

/// `bytes` 的头 4 字节看起来是不是 Mach-O（含 fat / universal）。
#[must_use]
pub fn looks_like_macho_header(bytes: &[u8]) -> bool {
    matches!(
        bytes.get(0..4),
        Some([0xce, 0xfa, 0xed, 0xfe])   // MH_MAGIC（大端字节序的 u32 0xfeedface）
            | Some([0xcf, 0xfa, 0xed, 0xfe]) // MH_MAGIC_64
            | Some([0xfe, 0xed, 0xfa, 0xce]) // MH_CIGAM
            | Some([0xfe, 0xed, 0xfa, 0xcf]) // MH_CIGAM_64
            | Some([0xca, 0xfe, 0xba, 0xbe]) // FAT_MAGIC
            | Some([0xca, 0xfe, 0xba, 0xbf]) // FAT_MAGIC_64
    )
}

/// 在成员表里找 `.app` 的主二进制。
///
/// `layout` 决定名字怎么拆（IPA 的 `Payload/` 前缀，还是目录的相对路径）；
/// `bundle_name` 是目录容器的目录名（去掉 `.app`），同名约定用它；IPA 布局传
/// `None`（每个成员自带 bundle 段）。`names` 是成员名（顺序即成员表顺序），
/// `read` 按**下标**取该成员的字节。只有两条路会读内容：读 `Info.plist`
/// （每个 `.app` 一份），以及最后一档的魔数检查。同名约定这一条不读任何字节。
///
/// 返回 `None` 表示"这份成员表看起来不是 .app，或者里面没有任何一层的
/// Mach-O" —— 那是**结论**，不是错误：调用方照旧列出成员，只是没有主二进制可说。
#[must_use]
pub fn find_main_binary(
    layout: BundleLayout,
    bundle_name: Option<&str>,
    names: &[&str],
    mut read: impl FnMut(usize) -> Option<Vec<u8>>,
) -> Option<MainBinary> {
    let mut notes: Vec<String> = Vec::new();

    // 第一层：Info.plist 的 CFBundleExecutable —— 文件里写着的事实。
    //
    // 只在成员表里**真有** Info.plist 时才读它，所以没有 plist 的归档还是零读取。
    // 读不到 / 解不开 / 声明的名字不在归档里，都不吞掉：写进 notes 再降级。
    for (index, name) in names.iter().enumerate() {
        let Some((bundle, file)) = layout.layer(name) else {
            continue;
        };
        if !layout.is_plist(bundle, file) {
            continue;
        }
        let Some(bytes) = read(index) else {
            notes.push(format!(
                "{name} 读不出来（成员损坏或超出读取上限），主二进制只能按约定或推断"
            ));
            continue;
        };
        match plist::bundle_executable(&bytes) {
            Ok(Some(executable)) => {
                let wanted = layout.plist_wanted(bundle, &executable);
                if let Some(found) = names.iter().position(|candidate| *candidate == wanted) {
                    return Some(MainBinary {
                        index: found,
                        name: wanted,
                        source: MainBinarySource::FromPlist,
                        notes,
                    });
                }
                // plist 说了名字，归档里却没有这个成员：这可能是加固/重排，也可能是
                // 我们认错了这一层。降级继续找，但把这句留下。
                notes.push(format!(
                    "{name} 声明 CFBundleExecutable = {executable}，但归档里没有 {wanted}"
                ));
            }
            Ok(None) => notes.push(format!("{name} 里没有 CFBundleExecutable 这个键")),
            Err(error) => notes.push(format!("{name} 解析失败（{error}）")),
        }
    }

    // 第二层：同名约定。
    let mut candidates: Vec<usize> = Vec::new();
    for (index, name) in names.iter().enumerate() {
        let Some((bundle, file)) = layout.layer(name) else {
            continue;
        };
        if layout.is_name_match(bundle_name, bundle, file) {
            return Some(MainBinary {
                index,
                name: (*name).to_string(),
                source: MainBinarySource::NameMatch,
                notes,
            });
        }
        candidates.push(index);
    }

    // 第三层：只有真正读了字节才知道是不是 Mach-O。读不到（成员损坏 / 超上限）
    // 就跳过它 —— 不因为"读不到"就断言"整份不是 .app"。
    for index in candidates {
        let Some(bytes) = read(index) else {
            continue;
        };
        if looks_like_macho_header(&bytes) {
            return Some(MainBinary {
                index,
                name: names[index].to_string(),
                source: MainBinarySource::Guessed,
                notes,
            });
        }
    }

    None
}

/// 成员表里有没有"像 .app 的一层"（不管找没找到主二进制）。
///
/// 用来区分两种 `None`：不是 .app，与是 .app 但主二进制认不出来。两者的
/// 界面措辞完全不同，不该混成一句。IPA 布局用这条；目录容器在嗅探阶段就
/// 已经确认过是 `.app`（[`looks_like_app_directory`]），不需要它。
#[must_use]
pub fn looks_like_app_bundle(members: &[ArchiveMember]) -> bool {
    members
        .iter()
        .any(|member| BundleLayout::Ipa.layer(&member.name).is_some())
}

// ── 目录容器（`.app` bundle 目录）──────────────────────────────────────────

/// 目录枚举的最大深度（`Contents/MacOS/X` 是三层；六层足够覆盖 PlugIns 等）。
const MAX_DIR_DEPTH: usize = 6;

/// 目录容器的成员上限（防止把整个磁盘列进界面）。
pub const MAX_BUNDLE_MEMBERS: usize = 4096;

/// 单个目录成员允许读取的最大字节数。
///
/// 与 `bitflip-core` 的 `MAX_FULL_PARSE_BYTES`（512 MiB）对齐：解析器需要的
/// 字节不会超过那个上限，更大的文件只能做识别，读了也解析不了。
/// ZIP 的解压上限（256 MiB）是另一条线，别混用。
pub const MAX_APP_MEMBER_BYTES: u64 = 512 * 1024 * 1024;

/// 打开的目录像不像 `.app` bundle。
///
/// 判据：根层有 `Info.plist`（iOS 解包目录），或 `Contents/Info.plist`
/// （macOS `.app`）。两者都没有就不是 bundle —— 那就不是本工具的目标。
#[must_use]
pub fn looks_like_app_directory(root: &Path) -> bool {
    root.join("Info.plist").is_file() || root.join("Contents").join("Info.plist").is_file()
}

/// 枚举 `.app` 目录容器的成员（只列普通文件）。
///
/// 名字用 `/` 分隔的相对路径；存储是 [`MemberStorage::File`] —— 内容要按名字
/// 从磁盘读（[`read_app_member`]），不是切片。符号链接**不跟随**：目录容器
/// 的成员名只代表 bundle 内部的文件，链接可能指向 bundle 之外。
///
/// 深度超过 [`MAX_DIR_DEPTH`]、成员达到 [`MAX_BUNDLE_MEMBERS`] 都会如实写进
/// `notes`；中途撞上读不到的目录返回 [`LoaderError::Io`]（目录打不开是打开失败，
/// 不静默）。
pub fn enumerate_app_directory(
    root: &Path,
) -> Result<(Vec<ArchiveMember>, Vec<String>), LoaderError> {
    let mut members = Vec::new();
    let mut notes = Vec::new();
    walk_directory(root, root, 0, &mut members, &mut notes)?;
    if members.len() >= MAX_BUNDLE_MEMBERS {
        notes.push(format!(
            "成员数达到上限 {MAX_BUNDLE_MEMBERS}，只枚举了前 {} 个",
            members.len()
        ));
    }
    Ok((members, notes))
}

fn walk_directory(
    root: &Path,
    dir: &Path,
    depth: usize,
    members: &mut Vec<ArchiveMember>,
    notes: &mut Vec<String>,
) -> Result<(), LoaderError> {
    if depth >= MAX_DIR_DEPTH {
        notes.push(format!("目录层级超过 {MAX_DIR_DEPTH} 层，更深的成员未枚举"));
        return Ok(());
    }
    let entries = match std::fs::read_dir(dir) {
        Ok(entries) => entries,
        Err(source) => {
            return Err(LoaderError::Io {
                path: dir.display().to_string(),
                source,
            })
        }
    };
    for entry in entries {
        if members.len() >= MAX_BUNDLE_MEMBERS {
            break;
        }
        let entry = match entry {
            Ok(entry) => entry,
            Err(source) => {
                notes.push(format!("读取目录项失败：{source}"));
                continue;
            }
        };
        let file_type = match entry.file_type() {
            Ok(file_type) => file_type,
            Err(source) => {
                notes.push(format!(
                    "读取 {} 的类型失败：{source}",
                    entry.path().display()
                ));
                continue;
            }
        };
        let path = entry.path();
        if file_type.is_dir() {
            walk_directory(root, &path, depth + 1, members, notes)?;
            continue;
        }
        if !file_type.is_file() {
            // 符号链接与其它（设备等）：不跟随。
            continue;
        }
        let relative = path.strip_prefix(root).unwrap_or(&path);
        let name = to_forward_slashes(relative);
        if name.is_empty() {
            continue;
        }
        let size = entry.metadata().map_or(0, |meta| meta.len());
        members.push(ArchiveMember {
            index: members.len(),
            name,
            offset: None,
            size,
            truncated: false,
            storage: MemberStorage::File,
            arch: None,
            payload: true,
        });
    }
    Ok(())
}

fn to_forward_slashes(path: &Path) -> String {
    let mut s = path.to_string_lossy().into_owned();
    if std::path::MAIN_SEPARATOR == '\\' {
        s = s.replace('\\', "/");
    }
    s
}

/// 从目录容器里读一个成员（按相对路径）。
///
/// 名字带 `..` / 绝对路径 / 空段一律拒绝（返回 `None`）—— 成员名来自我们自己的
/// 枚举，不该出现这些，但公共函数要挡住恶意调用。文件不存在、不是普通文件、
/// 超过 [`MAX_APP_MEMBER_BYTES`] 也返回 `None`（读取上限与解析上限对齐，见
/// 常量的注释）。
pub fn read_app_member(root: &Path, name: &str) -> Option<Vec<u8>> {
    if !safe_member_name(name) {
        return None;
    }
    let path = root.join(name);
    let meta = std::fs::metadata(&path).ok()?;
    if !meta.is_file() {
        return None;
    }
    if meta.len() > MAX_APP_MEMBER_BYTES {
        return None;
    }
    std::fs::read(&path).ok()
}

fn safe_member_name(name: &str) -> bool {
    if name.is_empty() || name.starts_with('/') {
        return false;
    }
    name.split('/')
        .all(|part| !part.is_empty() && part != "." && part != "..")
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::plist::support::{ascii, build, dict, info_plist};

    fn names(list: &[&'static str]) -> Vec<&'static str> {
        list.to_vec()
    }

    /// LiveContainer.ipa 的真实形状：可执行名与 `.app` 名不同。
    const RENAMED: &str = "Payload/LiveContainer.app/LiveContainer_PleaseDoNotShortenTheExecutableNameBecauseItIsUsedToReserveSpaceForOverwritingThankYou";
    /// 同一长名在**目录布局**里的写法（去掉 `Payload/` 前缀）。
    const RENAMED_IO: &str = "LiveContainer_PleaseDoNotShortenTheExecutableNameBecauseItIsUsedToReserveSpaceForOverwritingThankYou";

    /// IPA 布局的统一入口：`layout = Ipa, bundle_name = None`。
    fn find_ipa(names: &[&str], read: impl FnMut(usize) -> Option<Vec<u8>>) -> Option<MainBinary> {
        find_main_binary(BundleLayout::Ipa, None, names, read)
    }

    /// 目录布局的统一入口：`bundle_name` 是目录名去掉 `.app`。
    fn find_dir(
        bundle_name: &str,
        names: &[&str],
        read: impl FnMut(usize) -> Option<Vec<u8>>,
    ) -> Option<MainBinary> {
        find_main_binary(BundleLayout::Directory, Some(bundle_name), names, read)
    }

    #[test]
    fn the_plist_names_the_executable_even_when_the_bundle_was_renamed() {
        // 改名 + 约定失效，但 Info.plist 里写着可执行名 —— 这是事实，不是推断。
        let list = names(&["Payload/LiveContainer.app/Info.plist", RENAMED]);
        let found = find_ipa(&list, |index| match index {
            0 => Some(info_plist("LiveContainer_PleaseDoNotShortenTheExecutableNameBecauseItIsUsedToReserveSpaceForOverwritingThankYou")),
            _ => None,
        })
        .expect("Info.plist 应当给出答案");
        assert_eq!(found.index, 1);
        assert_eq!(found.name, RENAMED);
        assert_eq!(found.source, MainBinarySource::FromPlist);
        assert!(!found.source.is_guess(), "文件里写着的事实不该被算成猜测");
        let note = found.note_zh();
        assert!(note.contains("Info.plist"), "要说清依据：{note}");
        assert!(!note.contains("推断"), "事实不该自称推断：{note}");
        assert!(
            found.notes.is_empty(),
            "没降级就不该有降级说明：{:?}",
            found.notes
        );
    }

    #[test]
    fn the_dot_app_same_name_convention_wins_and_reads_nothing() {
        // 没有 Info.plist 的时候，同名约定一个字节都不该读。
        let list = names(&["Payload/SideStore.app/SideStore"]);
        let found =
            find_ipa(&list, |_| panic!("这条依据不该读成员字节")).expect("同名约定应当命中");
        assert_eq!(found.index, 0);
        assert_eq!(found.name, "Payload/SideStore.app/SideStore");
        assert_eq!(found.source, MainBinarySource::NameMatch);
        assert!(!found.source.is_guess());
        assert!(!found.note_zh().contains("推断"), "事实不该自称推断");
    }

    #[test]
    fn a_plist_naming_a_missing_member_falls_back_and_says_why() {
        // plist 说可执行名是 Gone，但归档里没有这个成员。退回同名约定，并把
        // "为什么不是事实来源"写进 notes —— 不能悄悄降级（§7）。
        let list = names(&["Payload/X.app/Info.plist", "Payload/X.app/X"]);
        let found = find_ipa(&list, |index| match index {
            0 => Some(info_plist("Gone")),
            _ => panic!("降级到同名约定之后不该再读字节"),
        })
        .expect("同名约定应当命中");
        assert_eq!(found.source, MainBinarySource::NameMatch);
        assert!(
            found
                .notes
                .iter()
                .any(|note| note.contains("Gone") && note.contains("没有")),
            "降级原因必须留下：{:?}",
            found.notes
        );
    }

    #[test]
    fn an_unparseable_plist_is_reported_and_not_swallowed() {
        let list = names(&["Payload/X.app/Info.plist", "Payload/X.app/X"]);
        let found = find_ipa(&list, |index| match index {
            0 => Some(b"bplist00".to_vec()), // 只有魔数：必然解析失败
            _ => panic!("降级到同名约定之后不该再读字节"),
        })
        .expect("同名约定应当命中");
        assert_eq!(found.source, MainBinarySource::NameMatch);
        assert!(
            found.notes.iter().any(|note| note.contains("解析失败")),
            "解析失败必须留下：{:?}",
            found.notes
        );
    }

    #[test]
    fn a_plist_without_the_key_falls_back_to_the_magic_and_says_it_is_a_guess() {
        // plist 能解析，但没有 CFBundleExecutable；同名约定也不成立 —— 只能推断。
        let list = names(&["Payload/LiveContainer.app/Info.plist", RENAMED]);
        let found = find_ipa(&list, |index| match index {
            0 => Some(build(
                &[dict(&[1], &[2]), ascii("CFBundleIdentifier"), ascii("x")],
                0,
            )),
            _ => Some(vec![0xcf, 0xfa, 0xed, 0xfe, 0, 0, 0, 0]),
        })
        .expect("第三层依据应当命中");
        assert_eq!(found.index, 1);
        assert_eq!(found.source, MainBinarySource::Guessed);
        assert!(found.source.is_guess());
        let note = found.note_zh();
        assert!(note.contains("推断"), "推测必须自报家门：{note}");
        assert!(note.contains("Mach-O 头"), "要说清依据：{note}");
        assert!(
            found
                .notes
                .iter()
                .any(|item| item.contains("CFBundleExecutable")),
            "缺键这件事要说出来：{:?}",
            found.notes
        );
    }

    #[test]
    fn a_non_app_archive_has_no_main_binary_and_that_is_not_an_error() {
        let list = names(&["AndroidManifest.xml", "classes.dex"]);
        assert!(find_ipa(&list, |_| Some(vec![0xcf, 0xfa, 0xed, 0xfe])).is_none());
    }

    #[test]
    fn a_deeper_path_is_a_resource_not_the_executable() {
        // `Payload/X.app/Frameworks/Y.framework/Y` 也是 Mach-O，但它不是主二进制。
        let list = names(&["Payload/X.app/Frameworks/Y.framework/Y", "Payload/X.app/X"]);
        let found = find_ipa(&list, |_| {
            panic!("同名约定在成员 1 上就该命中，不该有第二次读")
        })
        .expect("应当命中成员 1");
        assert_eq!(found.index, 1);
        assert_eq!(found.source, MainBinarySource::NameMatch);
    }

    #[test]
    fn an_unreadable_member_does_not_turn_into_a_verdict() {
        let list = names(&["Payload/X.app/A", "Payload/X.app/B"]);
        // 全读不到：结论是"认不出来"，而不是"这不是 .app"。
        assert!(find_ipa(&list, |_| None).is_none());
    }

    // ── 目录布局 ──────────────────────────────────────────────────────────

    #[test]
    fn a_directory_with_root_plist_names_the_executable() {
        // iOS 解包目录：Info.plist 在根层，可执行名与 .app 目录名不同。
        let list = names(&["Info.plist", RENAMED_IO]);
        let found = find_dir("LiveContainer", &list, |index| match index {
            0 => Some(info_plist("LiveContainer_PleaseDoNotShortenTheExecutableNameBecauseItIsUsedToReserveSpaceForOverwritingThankYou")),
            _ => None,
        })
        .expect("根层 Info.plist 应当给出答案");
        assert_eq!(found.index, 1);
        assert_eq!(found.name, RENAMED_IO);
        assert_eq!(found.source, MainBinarySource::FromPlist);
    }

    #[test]
    fn a_directory_with_contents_plist_names_the_macos_executable() {
        // macOS .app：Contents/Info.plist + Contents/MacOS/<可执行名>。
        let list = names(&[
            "Contents/Info.plist",
            "Contents/Resources/icon.png",
            "Contents/MacOS/SideStore",
        ]);
        let found = find_dir("SideStore", &list, |index| match index {
            0 => Some(info_plist("SideStore")),
            _ => None,
        })
        .expect("Contents/Info.plist 应当给出答案");
        assert_eq!(found.index, 2);
        assert_eq!(found.name, "Contents/MacOS/SideStore");
        assert_eq!(found.source, MainBinarySource::FromPlist);
    }

    #[test]
    fn a_directory_without_plist_uses_the_name_convention() {
        // 没有 Info.plist：同名约定（根层，目录名去掉 .app）。
        let list = names(&["Frameworks", "SideStore", "Resources/icon.png"]);
        let found = find_dir("SideStore", &list, |_| panic!("同名约定不该读成员字节"))
            .expect("同名约定应当命中");
        assert_eq!(found.name, "SideStore");
        assert_eq!(found.source, MainBinarySource::NameMatch);
    }

    #[test]
    fn a_directory_without_plist_matches_the_macos_layout_too() {
        let list = names(&["Contents/Info.plist", "Contents/MacOS/App", "Contents/App"]);
        // plist 在但读不到（返回 None）；同名约定也不成立（目录名是 SideStore，
        // 这里没有 SideStore 文件）。于是只能推断：第一个 Mach-O 是 Contents/MacOS/App。
        let found = find_dir("SideStore", &list, |index| match index {
            0 => None, // plist 读不到
            _ => Some(vec![0xcf, 0xfa, 0xed, 0xfe, 0, 0, 0, 0]),
        })
        .expect("推断应当命中");
        assert_eq!(found.source, MainBinarySource::Guessed);
        assert!(found.source.is_guess());
    }

    #[test]
    fn read_app_member_rejects_traversal_and_absolutes() {
        // 公共函数的防御：`..` / 绝对路径 / 空段一律拒绝，不能读到 bundle 外。
        let root = Path::new("C:/some/app.app");
        assert!(read_app_member(root, "../secret").is_none());
        assert!(read_app_member(root, "a/../../secret").is_none());
        assert!(read_app_member(root, "/etc/passwd").is_none());
        assert!(read_app_member(root, "a//b").is_none());
        assert!(read_app_member(root, "").is_none());
    }

    #[test]
    fn enumerate_and_read_roundtrip_on_a_temp_directory() {
        // 用真实目录验证枚举与按名读盘：这才是目录容器的主干。
        let dir = std::env::temp_dir().join(format!("bitflip-bundle-test-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(dir.join("Contents").join("MacOS")).unwrap();
        std::fs::create_dir_all(dir.join("Contents").join("Resources")).unwrap();
        std::fs::write(
            dir.join("Info.plist"),
            b"<?xml version=\"1.0\"?><plist><dict/></plist>",
        )
        .unwrap();
        std::fs::write(
            dir.join("Contents").join("MacOS").join("Foo"),
            b"\xcf\xfa\xed\xfe\x00\x00\x00\x00",
        )
        .unwrap();
        std::fs::write(
            dir.join("Contents").join("Resources").join("icon.png"),
            b"png",
        )
        .unwrap();

        let (members, notes) = enumerate_app_directory(&dir).expect("枚举应当成功");
        let names_set: Vec<&str> = members.iter().map(|m| m.name.as_str()).collect();
        assert!(
            names_set.contains(&"Info.plist"),
            "根层 plist 应在成员表里：{names_set:?}"
        );
        assert!(
            names_set.contains(&"Contents/MacOS/Foo"),
            "MacOS 可执行应在成员表里：{names_set:?}"
        );
        assert!(
            names_set.contains(&"Contents/Resources/icon.png"),
            "资源应在成员表里：{names_set:?}"
        );
        assert!(notes.is_empty(), "正常枚举不该有说明：{notes:?}");
        assert!(members.iter().all(|m| m.storage == MemberStorage::File));

        // 按名读盘要能读回我们写的字节。
        let bytes = read_app_member(&dir, "Contents/MacOS/Foo").expect("应当读回");
        assert_eq!(bytes, b"\xcf\xfa\xed\xfe\x00\x00\x00\x00");
        // 名字不合法就读不到。
        assert!(read_app_member(&dir, "../escape").is_none());
        let _ = std::fs::remove_dir_all(&dir);
    }
}
