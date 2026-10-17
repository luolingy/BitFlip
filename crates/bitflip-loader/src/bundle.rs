//! 从 `.app` / IPA 的成员表里认出**主二进制**，并且把"凭什么认出它"一起带出来。
//!
//! # 为什么要单独一个模块
//!
//! 这段判断原先只活在 `tests/macho_real_sample.rs` 里。测试里能跑，但界面上
//! 用不到 —— 于是用户看到"主二进制是 X"时，无法知道这是文件里写着的事实，
//! 还是我们按约定推出来的猜测。§7 的底线是"降级要写在界面上"，而推测比降级更
//! 需要自报家门：一个猜出来的答案如果长得和事实一模一样，那它就是**错的**答案。
//!
//! # 两条依据，优先级写在类型里
//!
//! 1. [`MainBinarySource::NameMatch`]：`Payload/<Name>.app/<Name>` —— iOS 打包约定
//!    （`.app` 目录名与可执行名一致）。这是**约定**，不是规范；加固/改名工具会破坏它。
//! 2. [`MainBinarySource::Guessed`]：同名匹配落空时，取 `Payload/*.app/` 第一层里
//!    第一个头 4 字节是 Mach-O 魔数的成员。这条是**推断**，界面必须标明。
//!
//! 目前**没有**第三条"读 `Info.plist` 的 `CFBundleExecutable`"的依据 —— 二进制
//! plist 还没解（见 `docs/PLAN.md` 的 M12 排期）。所以这里只有两个来源，
//! 不预留一个永远走不到的 `FromPlist`（§7：不摆做不到的选项）。

use crate::ArchiveMember;

/// 认出主二进制用的是哪条依据。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MainBinarySource {
    /// `Payload/<Name>.app/<Name>`：按 `.app` 同名约定匹配上的。
    NameMatch,
    /// 同名匹配落空后的推断：第一层里第一个头 4 字节是 Mach-O 魔数的成员。
    Guessed,
}

impl MainBinarySource {
    /// 给人看的依据说明（中文）。
    #[must_use]
    pub fn label_zh(self) -> &'static str {
        match self {
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
/// `names` 是成员名（顺序即成员表顺序），`read` 按**下标**取该成员的字节 ——
/// 只在需要看魔数时才调用，所以同名匹配这一条路不会去读任何内容。
///
/// 返回 `None` 表示"这份归档看起来不是 .app / IPA，或者里面没有任何一层的
/// Mach-O" —— 那是**结论**，不是错误：调用方照旧列出成员，只是没有主二进制可说。
#[must_use]
pub fn find_main_binary(
    names: &[&str],
    mut read: impl FnMut(usize) -> Option<Vec<u8>>,
) -> Option<MainBinary> {
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
            });
        }
        candidates.push(index);
    }

    // 第二层：只有真正读了字节才知道是不是 Mach-O。读不到（成员损坏 / 超上限）
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

    fn names(list: &[&'static str]) -> Vec<&'static str> {
        list.to_vec()
    }

    #[test]
    fn the_dot_app_same_name_convention_wins_and_reads_nothing() {
        let list = names(&[
            "Payload/SideStore.app/SideStore",
            "Payload/SideStore.app/Info.plist",
        ]);
        // 一个字节都不该读：同名匹配不需要看内容。
        let found = find_main_binary(&list, |_| panic!("这条依据不该读成员字节"))
            .expect("同名约定应当命中");
        assert_eq!(found.index, 0);
        assert_eq!(found.name, "Payload/SideStore.app/SideStore");
        assert_eq!(found.source, MainBinarySource::NameMatch);
        assert!(!found.source.is_guess());
        assert!(!found.note_zh().contains("推断"), "事实不该自称推断");
    }

    #[test]
    fn a_renamed_executable_falls_back_to_the_magic_and_says_it_is_a_guess() {
        // LiveContainer.ipa 的真实形状：可执行名与 .app 名不同。
        let list = names(&[
            "Payload/LiveContainer.app/Info.plist",
            "Payload/LiveContainer.app/LiveContainer_PleaseDoNotShortenTheExecutableNameBecauseItIsUsedToReserveSpaceForOverwritingThankYou",
        ]);
        let found = find_main_binary(&list, |index| match index {
            0 => Some(b"bplist00".to_vec()),
            _ => Some(vec![0xcf, 0xfa, 0xed, 0xfe, 0, 0, 0, 0]),
        })
        .expect("第二层依据应当命中");
        assert_eq!(found.index, 1);
        assert_eq!(found.source, MainBinarySource::Guessed);
        assert!(found.source.is_guess());
        let note = found.note_zh();
        assert!(note.contains("推断"), "推测必须自报家门：{note}");
        assert!(note.contains("Mach-O 头"), "要说清依据：{note}");
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
