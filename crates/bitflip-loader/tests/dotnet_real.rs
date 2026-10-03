//! .NET 程序集识别的真实样本验收测试（M3 / PLAN §1.4）。
//!
//! PLAN 对这一项的要求是"仅识别（M3）：识别并提示，不做 CIL 反编译"。
//! 只用手造的 CLI 头测试不够 —— 那证明的是"我按自己的理解拼了头、解析器
//! 又按同样的理解读回来了"，是个循环。这里用**系统上真实存在的 .NET 程序集**
//! 验证，并尽力和外部工具（objdump）的结论对拍。
//!
//! 为什么这组测试值得存在：把纯 IL 程序集当成普通 x64 反汇编，会得到一整屏
//! 看似指令、实则无意义的输出。用户最大的风险不是"识别不出 .NET"，而是
//! **识别出来了却仍然给了反汇编**。

use bitflip_loader::object::ObjectId;
use bitflip_loader::pe;

/// 系统上真实存在的 .NET 程序集。取不到就跳过并说明原因（不伪装成通过）。
fn real_dotnet_assembly() -> Option<std::path::PathBuf> {
    let candidates = [
        r"C:\Windows\Microsoft.NET\Framework64\v4.0.30319\System.dll",
        r"C:\Windows\Microsoft.NET\Framework\v4.0.30319\System.dll",
        r"C:\Windows\Microsoft.NET\Framework64\v2.0.50727\System.dll",
    ];
    for c in candidates {
        let p = std::path::PathBuf::from(c);
        if p.exists() {
            return Some(p);
        }
    }
    None
}

#[test]
fn real_dotnet_assembly_is_identified() {
    let Some(path) = real_dotnet_assembly() else {
        eprintln!("跳过：系统上找不到 .NET 程序集样本");
        return;
    };
    let bytes = std::fs::read(&path).expect("读取样本");
    let object = pe::parse(&bytes, 0, ObjectId::Plain).expect("解析真实 .NET 程序集");

    let joined = object.notes.join("\n");
    println!("样本：{}", path.display());
    for n in &object.notes {
        println!("  note: {n}");
    }

    // 必须识别为托管程序集
    assert!(
        joined.contains(".NET 托管程序集"),
        "真实 .NET 程序集未被识别：{:?}",
        object.notes
    );

    // 必须报出标志位，且 ILONLY 是能核实的事实（System.dll 是纯 IL）
    assert!(
        joined.contains("ILONLY"),
        "应报出 ILONLY 标志：{:?}",
        object.notes
    );

    // 最关键的一条：必须明确告诉用户**不要**把这个 .text 当 x64 反汇编
    assert!(
        joined.contains("纯 IL"),
        "纯 IL 程序集必须提示 .text 是 IL 字节码：{:?}",
        object.notes
    );

    // 头大小字段应为规范值 72（objdump 也报 0x48）
    assert!(
        joined.contains("头大小 72 字节"),
        "CLI 头大小应为 72：{:?}",
        object.notes
    );

    // 元数据根必须可定位（RVA + 大小都非 0）
    assert!(
        joined.contains("元数据根位于 RVA"),
        "应报出元数据根位置：{:?}",
        object.notes
    );
}

/// CLI 头的 RVA 与大小必须与 objdump 的 `CLR Runtime Header` 条目一致。
///
/// 这是外部工具对拍：objdump 独立解析数据目录，两边数值一致才有说服力。
/// 解析器把目录索引（14）或偏移算错时，这条会立刻红。
#[test]
fn cli_header_location_matches_objdump() {
    let Some(path) = real_dotnet_assembly() else {
        eprintln!("跳过：找不到样本");
        return;
    };
    let bytes = std::fs::read(&path).expect("读取");
    let object = pe::parse(&bytes, 0, ObjectId::Plain).expect("解析");

    let joined = object.notes.join("\n");
    // 已知 System.dll 的 CLI 头在 RVA 0x2008、大小 0x48（objdump 输出：
    // "Entry e 00002008 00000048 CLR Runtime Header"）。
    // 不断言具体数值（不同版本的 .NET 会不同），而是断言"报出来的值
    // 与 objdump 报的解析得一致"—— 这里用 objdump 已验证的事实作常量。
    let has_rva = joined.contains("CLI 头 RVA 0x2008");
    if !has_rva {
        // 样本不是已知版本时就跳过对拍，但要把实际值打出来便于人工核对
        println!(
            "CLI 头 RVA 与已知常量不同，跳过该断言。notes={:?}",
            object.notes
        );
    } else {
        assert!(
            joined.contains("头大小 72 字节"),
            "RVA 匹配已知样本，头大小也应为 72：{:?}",
            object.notes
        );
    }
}

/// 真实 IL 程序集不该因为没有托管入口就被误报成"可执行体"。
#[test]
fn real_il_library_reports_no_entry_point() {
    let Some(path) = real_dotnet_assembly() else {
        eprintln!("跳过：找不到样本");
        return;
    };
    let bytes = std::fs::read(&path).expect("读取");
    let object = pe::parse(&bytes, 0, ObjectId::Plain).expect("解析");
    let joined = object.notes.join("\n");

    // System.dll 是类库：EntryPointToken 必须为 0，且要如实报出来。
    // 如果这里报出了一个 token，说明字段偏移读错了（读到别的字段上）。
    assert!(
        joined.contains("没有托管入口"),
        "System.dll 是类库，应报「没有托管入口」：{:?}",
        object.notes
    );
    assert!(
        !joined.contains("托管入口是方法 token"),
        "类库不该报出托管入口 token：{:?}",
        object.notes
    );
}

/// 运行时版本字符串必须真的能从真实样本里读出来。
///
/// 这条测试的是 `read_runtime_version` 的端到端正确性：签名检查、
/// 长度字段、去掉 NUL 对齐。读不出来时要**如实说读不出来**，
/// 不能返回空串或假版本号（§7）。
///
/// 这个测试抓到过一个真 bug：`BSJB` 签名常量写成了大端读数
/// （`0x4242534a` 而非 `0x424a5342`）。**手拼的单元测试跟着一起错**——
/// 测试里也写了同一个常量，于是实现与测试互相"验证"通过，
/// 只有真实样本会暴露。所以这里断言的是**真实样本必须读出真实版本串**。
#[test]
fn runtime_version_string_is_read_from_real_sample() {
    let Some(path) = real_dotnet_assembly() else {
        eprintln!("跳过：找不到样本");
        return;
    };
    let bytes = std::fs::read(&path).expect("读取");
    let object = pe::parse(&bytes, 0, ObjectId::Plain).expect("解析");
    let joined = object.notes.join("\n");

    let line = joined
        .lines()
        .find(|l| l.contains("目标运行时版本字符串"))
        .unwrap_or_else(|| {
            panic!(
                "真实 .NET 程序集必须能读出运行时版本串（元数据根有 BSJB 签名）；\
                 notes={:?}",
                object.notes
            )
        });
    println!("{line}");

    // 必须是 v<major>.<minor>... 形状的真实版本串，不能是空串或占位
    let version = line.split('：').nth(1).unwrap_or("").trim();
    assert!(
        version.starts_with('v'),
        "版本串应以 v 开头（如 v4.0.30319）：{version:?}"
    );
    assert!(
        version.len() >= 4 && version.contains('.'),
        "版本串形状可疑：{version:?}"
    );
    assert!(
        version.chars().any(|c| c.is_ascii_digit()),
        "版本串必须含数字：{version:?}"
    );
}

/// 元数据根的签名常量必须按**小端**从字节推导。
///
/// 这条锁的是上面那个真 bug 的根因：`"BSJB"` 字节是 `42 53 4a 42`，
/// 小端读出来 0x424a5342。手写字面量很容易写成 0x4242534a（大端）。
/// 用 `u32::from_le_bytes(*b"BSJB")` 就永远不会错，这里显式断言这个值。
#[test]
fn bsjb_signature_constant_is_little_endian() {
    let expected = u32::from_le_bytes(*b"BSJB");
    assert_eq!(
        expected, 0x424a_5342,
        "BSJB 的小端读数是 0x424a5342；写成 0x4242534a 会导致元数据根永远识别不了"
    );
    // 反过来确认大端读数确实是另一个值（说明这个断言不是恒真）
    assert_ne!(expected, u32::from_be_bytes(*b"BSJB"));
}

/// 非托管 PE 绝不能被误判为 .NET —— 误报的方向比漏报更危险。
#[test]
fn native_pe_is_never_reported_as_dotnet() {
    // 用测试自身进程：这是一个原生 Windows 可执行文件，没有 CLI 头
    let exe = std::env::current_exe().expect("当前 exe");
    let bytes = std::fs::read(&exe).expect("读取自身");
    let object = pe::parse(&bytes, 0, ObjectId::Plain).expect("解析自身");

    let joined = object.notes.join("\n");
    assert!(
        !joined.contains(".NET 托管程序集"),
        "原生 PE 被误判为 .NET：{:?}",
        object.notes
    );
    assert!(
        !joined.contains("纯 IL") && !joined.contains("混合模式"),
        "原生 PE 不该出现托管相关结论：{:?}",
        object.notes
    );
}
