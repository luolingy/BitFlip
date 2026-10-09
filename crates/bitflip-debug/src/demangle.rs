//! 名字反修饰（M8 遗留项之一）。
//!
//! MSVC 的 C++ 符号长这样：?bar@Widget@@QEAAHXZ —— 机器能对齐，人读不了。
//! 这里把**可读形式**算出来，但**不覆盖原始名字**：原始名是身份（签名库、脚本、
//! 地址表都按它匹配），可读名只是给人看的那一副面孔。调用方拿到可读名后，
//! 应当把原始名作为别名保留下来。
//!
//! 只做 MSVC 那一种修饰（以 ? 开头）。Itanium（_Z3fooi）与 Rust（_ZN…17h…E）
//! 这里**不猜**：不认得的形状返回 None，让调用方原样显示（§7：不认识就说不认识，
//! 不要给一个看着像样的名字）。

/// 反修饰后的可读名；不是认得的修饰形式（或本来就可读）时返回 None。
///
/// 返回 None 的三种情况都应当当"照原样显示"，不是失败：
/// 名字本来就可读、不是 MSVC 修饰、或修饰形式我们不认。
#[must_use]
pub fn readable_name(name: &str) -> Option<String> {
    if !name.starts_with('?') {
        return None;
    }
    // LLVM 风格输出（不额外加 oid 之类），与 undname.exe/llvm-undname 打印的形式一致
    // —— 测试里的真值就是这么取的。
    let flags = msvc_demangler::DemangleFlags::llvm();
    match msvc_demangler::demangle(name, flags) {
        Ok(readable) if !readable.is_empty() && readable != name => Some(readable),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// 真值来自 undname.exe（随 MSVC 一起装的那个），不是我自己写的期望值。
    #[test]
    fn msvc_names_become_readable() {
        assert_eq!(
            readable_name("?foo@@YAHH@Z").as_deref(),
            Some("int __cdecl foo(int)")
        );
        assert_eq!(
            readable_name("?bar@Widget@@QEAAHXZ").as_deref(),
            Some("public: int __cdecl Widget::bar(void)")
        );
        assert_eq!(
            readable_name("?method@Thing@@UEBAXPEBD@Z").as_deref(),
            Some("public: virtual void __cdecl Thing::method(char const *) const")
        );
    }

    #[test]
    fn names_we_do_not_recognise_are_left_alone() {
        // 本来就可读、Itanium 修饰、Rust 修饰、空串：一律 None（照原样显示）。
        assert!(readable_name("main").is_none());
        assert!(readable_name("_fpreset").is_none());
        assert!(readable_name("_Z3fooi").is_none());
        assert!(readable_name("").is_none());
        assert!(readable_name("?").is_none());
    }
}
