//! 从 `.app` / IPA 的成员表里认出**主二进制**，并且把"凭什么认出它"一起带出来。
//!
//! # 为什么要单独一个模块
//!
//! 这段判断原先只活在 `tests/macho_real_sample.rs` 里。测试里能跑，但界面上
//! 用不到 —— 于是用户看到"主二进制是 X"时，无法知道这是文件里写着的事实，
//! 还是我们按约定推出来的猜测。§7 的底线是"降级要写在界面上"，而推测比降级更
//! 需要自报家门：一个猜出来的答案如果长得和事实一模一样，那它就是**错的**答案。
//!
//! # 三条依据，优先级写在类型里
//!
//! 1. [`MainBinarySource::FromPlist`]：`Info.plist` 的 `CFBundleExecutable` 指向哪个
//!    文件 —— 这是**文件里写着的事实**，所以优先。
//! 2. [`MainBinarySource::NameMatch`]：`Payload/<Name>.app/<Name>` —— iOS 打包约定
//!    （`.app` 目录名与可执行名一致）。这是**约定**，不是规范；加固/改名工具会破坏它。
//! 3. [`MainBinarySource::Guessed`]：前两条都落空时，取 `Payload/*.app/` 第一层里
//!    第一个头 4 字节是 Mach-O 魔数的成员。这条是**推断**，界面必须标明。
//!
//! 事实无法拿到时（`Info.plist` 缺失、损坏，或它声明的名字不在归档里），降级过程本身
//! 会作为 `MainBinary::notes` 跟着结论一起出来 —— 不吭声地退回约定/推断，等于把
//! "读不到"伪装成"没有"（CLAUDE.md §7）。

use crate::plist;
use crate::ArchiveMember;

/// 认出主二进制用的是哪条依据。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MainBinarySource {
    /// `Info.plist` 的 `CFBundleExecutable`：文件里写着的事实。
    FromPlist,
    /// `Payload/<Name>.app/<Name>`：按 `.app` 同名约定匹配上的。
    NameMatch,
    /// 前两条落空后的推断：第一层里第一个头 4 字节是 Mach-O 魔数的成员。
    Guessed,
}

impl MainBinarySource {
    /// 给人看的依据说明（中文）。
    #[must_use]
    pub fn label_zh(self) -> &'static str {
        match self {
            Self::FromPlist => "按 Info.plist 的 CFBundleExecutable 定位（文件里写着的事实）",
            Self::NameMatch => "按 `.app` 同名约定匹配",
            Self::Guessed => "推断（同名匹配落空，取第一层里第一个 Mach-O 头）",
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

/// `Payload/<bundle>.app/<file>` 这一层的两个部分。
fn payload_layer(name: &str) -> Option<(&str, &str)> {
    let rest = name.strip_prefix("Payload/")?;
    let mut parts = rest.split('/');
    let (bundle, file) = (parts.next()?, parts.next()?);
    // 再深一层就是资源，不是主二进制。
    if parts.next().is_some() {
        return None;
    }
    if !bundle.ends_with(".app") {
        return None;
    }
    Some((bundle, file))
}

/// 在成员表里找 `.app` 的主二进制。
///
/// `names` 是成员名（顺序即成员表顺序），`read` 按**下标**取该成员的字节。
/// 只有两条路会读内容：读 `Info.plist`（每个 `.app` 一份），以及最后一档的魔数
/// 检查。同名约定这一条不读任何字节。
///
/// 返回 `None` 表示"这份归档看起来不是 .app / IPA，或者里面没有任何一层的
/// Mach-O" —— 那是**结论**，不是错误：调用方照旧列出成员，只是没有主二进制可说。
#[must_use]
pub fn find_main_binary(
    names: &[&str],
    mut read: impl FnMut(usize) -> Option<Vec<u8>>,
) -> Option<MainBinary> {
    let mut notes: Vec<String> = Vec::new();

    // 第一层：Info.plist 的 CFBundleExecutable —— 文件里写着的事实。
    //
    // 只在成员表里**真有** Info.plist 时才读它，所以没有 plist 的归档还是零读取。
    // 读不到 / 解不开 / 声明的名字不在归档里，都不吞掉：写进 notes 再降级。
    for (index, name) in names.iter().enumerate() {
        let Some((bundle, file)) = payload_layer(name) else {
            continue;
        };
        if file != "Info.plist" {
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
                let wanted = format!("Payload/{bundle}/{executable}");
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
        let Some((bundle, file)) = payload_layer(name) else {
            continue;
        };
        if file == bundle.trim_end_matches(".app") {
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
/// 界面措辞完全不同，不该混成一句。
#[must_use]
pub fn looks_like_app_bundle(members: &[ArchiveMember]) -> bool {
    members
        .iter()
        .any(|member| payload_layer(&member.name).is_some())
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

    #[test]
    fn the_plist_names_the_executable_even_when_the_bundle_was_renamed() {
        // 改名 + 约定失效，但 Info.plist 里写着可执行名 —— 这是事实，不是推断。
        let list = names(&["Payload/LiveContainer.app/Info.plist", RENAMED]);
        let found = find_main_binary(&list, |index| match index {
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
        let found = find_main_binary(&list, |_| panic!("这条依据不该读成员字节"))
            .expect("同名约定应当命中");
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
        let found = find_main_binary(&list, |index| match index {
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
        let found = find_main_binary(&list, |index| match index {
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
        let found = find_main_binary(&list, |index| match index {
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
        assert!(find_main_binary(&list, |_| Some(vec![0xcf, 0xfa, 0xed, 0xfe])).is_none());
    }

    #[test]
    fn a_deeper_path_is_a_resource_not_the_executable() {
        // `Payload/X.app/Frameworks/Y.framework/Y` 也是 Mach-O，但它不是主二进制。
        let list = names(&["Payload/X.app/Frameworks/Y.framework/Y", "Payload/X.app/X"]);
        let found = find_main_binary(&list, |_| {
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
        assert!(find_main_binary(&list, |_| None).is_none());
    }
}
