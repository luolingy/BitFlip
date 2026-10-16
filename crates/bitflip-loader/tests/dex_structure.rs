//! DEX 结构模型的黄金测试。
//!
//! 两条独立的路：
//!
//! 1. **合成样本**（[`fixture`]）：逐字段照 Dalvik 规范拼一份最小但完全合规的
//!    DEX，能在任何机器上跑，用来钉住偏移、编码与投影结果（CLAUDE.md §6.11：
//!    fixture 照规格拼，不照自己的解析代码拼）。
//! 2. **真实 APK**：需要本机样本，所以是 `#[ignore]` 的独立测试
//!    （CLAUDE.md §7：跳过与通过必须在报告里分得开）。
//!
//! 合成样本证明"我们按规范读"，真实样本证明"规范之外还有现实"——两者缺一不可。

use bitflip_loader::{
    project_dex_method, render_dex_instructions_with_symbols, DexStructure, ObjectKind,
};

// ── 合成样本 ────────────────────────────────────────────────────────────────

/// 按 Dalvik Executable 规范拼一份最小但完全合规的 DEX。
///
/// 规范出处逐项写在代码里（`§3.1` 指 "Dalvik Executable format" 文档的章节号）。
mod fixture {
    /// 魔数：`dex\n` + 版本 `035` + NUL（规范 §3.1）。
    pub const MAGIC: &[u8; 8] = b"dex\n035\0";
    /// 头长度，规范固定 `0x70`（§3.1）。
    pub const HEADER_SIZE: u32 = 0x70;
    /// 字节序标记，规范固定 `0x12345678`（§3.1）。
    pub const ENDIAN_CONSTANT: u32 = 0x1234_5678;

    /// `string_ids` 的内容。规范要求按字符串内容（UTF-16 码元序）升序。
    pub const STRINGS: [&str; 11] = [
        "<init>",
        "Foo.java",
        "I",
        "Lcom/example/Foo;",
        "Ljava/lang/Object;",
        "Ljava/lang/String;",
        "V",
        "VI",
        "bar",
        "s",
        "x",
    ];

    /// `type_ids` 的内容（值是 [`STRINGS`] 的下标）。规范要求按描述符升序。
    pub const TYPES: [usize; 5] = [2, 3, 4, 5, 6];

    /// `field_ids`：(class, type, name)，都是 [`TYPES`] / [`STRINGS`] 的下标。
    /// 规范要求按 (类, 名字, 类型) 升序。
    /// 下标 0 = 实例字段 `s`（`Ljava/lang/String;`），下标 1 = 静态字段 `x`（`I`）。
    pub const FIELDS: [(u16, u16, usize); 2] = [(1, 3, 9), (1, 0, 10)];

    /// `method_ids`：(class, proto, name)。规范要求按 (类, 名字, proto) 升序。
    /// 下标 0 = `<init>`（proto 0，()V），下标 1 = `bar`（proto 1，(I)V）。
    pub const METHODS: [(u16, u16, usize); 2] = [(1, 0, 0), (1, 1, 8)];

    /// `SourceFile` 属性在 [`STRINGS`] 里的下标。
    pub const SOURCE_FILE_STR: usize = 1;
    /// 类在 `type_ids` 里的下标。
    pub const CLASS_TYPE: u32 = 1;

    /// `access_flags`（规范 §4.4 的 ACC_* 位）。
    pub const ACC_PUBLIC: u32 = 0x0001;
    pub const ACC_PRIVATE: u32 = 0x0002;
    pub const ACC_STATIC: u32 = 0x0008;
    pub const ACC_CONSTRUCTOR: u32 = 0x0001_0000;

    fn push_uleb(out: &mut Vec<u8>, mut value: u32) {
        // 规范 §3.2（LEB128）：低位在前，最高位是"还有下一个字节"。
        loop {
            let mut byte = (value & 0x7f) as u8;
            value >>= 7;
            if value != 0 {
                byte |= 0x80;
            }
            out.push(byte);
            if value == 0 {
                break;
            }
        }
    }

    fn push_u16(out: &mut Vec<u8>, value: u16) {
        out.extend_from_slice(&value.to_le_bytes());
    }

    fn push_u32(out: &mut Vec<u8>, value: u32) {
        out.extend_from_slice(&value.to_le_bytes());
    }

    fn put_u32(buf: &mut [u8], off: usize, value: u32) {
        buf[off..off + 4].copy_from_slice(&value.to_le_bytes());
    }

    /// 规范要求这些项 4 字节对齐（type_list §4.5.8、code_item §4.5.12、
    /// map_list §4.6）。数据段起点是 4 对齐的（下面有断言），所以对齐
    /// 段内长度就够了。
    fn align4(out: &mut Vec<u8>) {
        while !out.len().is_multiple_of(4) {
            out.push(0);
        }
    }

    /// `string_data_item` 里的 `utf16_size`（规范 §4.5.7）：**UTF-16 码元数**，
    /// 不是字节数。样本全 ASCII，两者相等，但这里仍按码元算 —— 换成含代理对的
    /// 字符串时不会悄悄错。
    fn utf16_len(s: &str) -> u32 {
        s.chars().map(|c| c.len_utf16() as u32).sum::<u32>()
    }

    /// RFC 1950 §9 的 Adler-32（`header.checksum` 的定义，规范 §3.1）。
    ///
    /// 自己按规范写而不是找个依赖：这是**被校验的**那个值，用别人的实现
    /// 就等于把"我们的样本对不对"交给了另一个不透明的假设。
    pub fn adler32(data: &[u8]) -> u32 {
        const MOD_ADLER: u32 = 65521;
        let mut a: u32 = 1;
        let mut b: u32 = 0;
        for byte in data {
            a = (a + u32::from(*byte)) % MOD_ADLER;
            b = (b + a) % MOD_ADLER;
        }
        (b << 16) | a
    }

    /// `SHA-1(out[32..])`。用 `sha1`（`droidsaw-dex` 的传递依赖，版本一致）
    /// 而不是自己写 —— 这里要的是**同一份**哈希定义，不是"另一个实现"。
    fn sha1(data: &[u8]) -> [u8; 20] {
        use sha1::{Digest, Sha1};
        let mut hasher = Sha1::new();
        hasher.update(data);
        hasher.finalize().into()
    }

    /// `code_item`（规范 §4.5.12）：一个 `return-void`。
    fn push_code_item(out: &mut Vec<u8>) {
        push_u16(out, 1); // registers_size
        push_u16(out, 0); // ins_size（无参数）
        push_u16(out, 0); // outs_size（不调用别的方法）
        push_u16(out, 0); // tries_size
        push_u32(out, 0); // debug_info_off
        push_u32(out, 1); // insns_size，单位是 16 位码元
        push_u16(out, 0x000e); // return-void（规范 §F.2.1 的 10x 格式）
    }

    /// `class_data_item`（规范 §4.5.11）：静态字段 `x`、实例字段 `s`、
    /// 直接方法 `<init>`、虚方法 `bar`。
    ///
    /// `code_offs` 是两个方法的 `code_off`；**非抽象非 native 的方法必须有
    /// 字节码**（规范 §4.5.10 对 `code_off` 的要求），所以这里都填真值 ——
    /// 用 0 省事会让样本本身违反规范，那样测试就是在验证一个不存在的文件。
    fn push_class_data(out: &mut Vec<u8>, code_offs: [u32; 2]) {
        push_uleb(out, 1); // static_fields_size
        push_uleb(out, 1); // instance_fields_size
        push_uleb(out, 1); // direct_methods_size
        push_uleb(out, 1); // virtual_methods_size

        // 静态字段 x：field_ids 下标 1，diff 从 0 起算
        push_uleb(out, 1);
        push_uleb(out, ACC_STATIC);
        // 实例字段 s：field_ids 下标 0（实例字段的 diff 从 0 **重新**起算）
        push_uleb(out, 0);
        push_uleb(out, ACC_PRIVATE);
        // 直接方法 <init>：method_ids 下标 0
        push_uleb(out, 0);
        push_uleb(out, ACC_PUBLIC | ACC_CONSTRUCTOR);
        push_uleb(out, code_offs[0]);
        // 虚方法 bar：method_ids 下标 1（diff 是相对上一个方法，所以是 1）
        push_uleb(out, 1);
        push_uleb(out, ACC_PUBLIC);
        push_uleb(out, code_offs[1]);
    }

    /// 拼出完整的 DEX 字节。
    pub fn build() -> Vec<u8> {
        // ── id 段：长度固定，偏移直接算得出来（头 0x70 之后的每一项都是 4 对齐的）
        let string_ids_off = HEADER_SIZE;
        let type_ids_off = string_ids_off + (STRINGS.len() as u32) * 4;
        let proto_ids_off = type_ids_off + (TYPES.len() as u32) * 4;
        let field_ids_off = proto_ids_off + 2 * 12; // 两个 proto
        let method_ids_off = field_ids_off + (FIELDS.len() as u32) * 8;
        let class_defs_off = method_ids_off + (METHODS.len() as u32) * 8;
        let data_off = class_defs_off + 32; // 一个 class_def

        assert!(data_off.is_multiple_of(4), "数据段起点必须 4 对齐");

        // ── 数据段：边拼边记偏移
        let mut data: Vec<u8> = Vec::new();

        let mut string_offs = Vec::new();
        for s in STRINGS {
            string_offs.push(data_off + data.len() as u32);
            push_uleb(&mut data, utf16_len(s));
            data.extend_from_slice(s.as_bytes()); // 样本全 ASCII，MUTF-8 就是它本身
            data.push(0); // 规范 §4.5.7 要求 NUL 结尾
        }

        align4(&mut data);
        let type_list_i_off = data_off + data.len() as u32;
        push_u32(&mut data, 1); // size
        push_u16(&mut data, 0); // 参数是 `I` —— 这里填的是 **type_ids 的下标**，不是字符串下标

        align4(&mut data);
        let code_off_init = data_off + data.len() as u32;
        push_code_item(&mut data);
        align4(&mut data);
        let code_off_bar = data_off + data.len() as u32;
        push_code_item(&mut data);

        align4(&mut data);
        let class_data_off = data_off + data.len() as u32;
        push_class_data(&mut data, [code_off_init, code_off_bar]);

        align4(&mut data);
        let map_off = data_off + data.len() as u32;

        let file_size = {
            // map_list 自己也要占位置，先按条目数算出来，再写进去
            let map_len = 4 + 12 * 12;
            data_off + data.len() as u32 + map_len
        };
        // 规范 §4.4：按 type 升序，每种 type 只出现一次。
        let mut map: Vec<(u16, u32, u32)> = vec![
            (0x0000, 1, 0),                                 // header_item
            (0x0001, STRINGS.len() as u32, string_ids_off), // string_id_item
            (0x0002, TYPES.len() as u32, type_ids_off),     // type_id_item
            (0x0003, 2, proto_ids_off),                     // proto_id_item
            (0x0004, FIELDS.len() as u32, field_ids_off),   // field_id_item
            (0x0005, METHODS.len() as u32, method_ids_off), // method_id_item
            (0x0006, 1, class_defs_off),                    // class_def_item
            (0x1000, 1, map_off),                           // map_list
            (0x1001, 1, type_list_i_off),                   // type_list_item
            (0x2000, 1, class_data_off),                    // class_data_item
            (0x2001, 2, code_off_init),                     // code_item（两个连在一起）
            (0x2002, STRINGS.len() as u32, string_offs[0]), // string_data_item
        ];
        map.sort_by_key(|entry| entry.0);
        push_u32(&mut data, map.len() as u32);
        for (ty, size, off) in &map {
            push_u16(&mut data, *ty);
            push_u16(&mut data, 0); // unused，规范要求 0
            push_u32(&mut data, *size);
            push_u32(&mut data, *off);
        }
        assert_eq!(data_off + data.len() as u32, file_size, "file_size 算错了");

        // ── 装起来：`out` 先按"头 + 全部 id 段"开好，池的内容才有地方写
        let mut out = vec![0u8; data_off as usize];
        out[..8].copy_from_slice(MAGIC);
        // 偏移 8 的 checksum 与偏移 12 的 signature 最后再写（它们覆盖下面的内容）
        put_u32(&mut out, 32, file_size);
        put_u32(&mut out, 36, HEADER_SIZE);
        put_u32(&mut out, 40, ENDIAN_CONSTANT);
        put_u32(&mut out, 44, 0); // link_size
        put_u32(&mut out, 48, 0); // link_off
        put_u32(&mut out, 52, map_off);
        put_u32(&mut out, 56, STRINGS.len() as u32);
        put_u32(&mut out, 60, string_ids_off);
        put_u32(&mut out, 64, TYPES.len() as u32);
        put_u32(&mut out, 68, type_ids_off);
        put_u32(&mut out, 72, 2);
        put_u32(&mut out, 76, proto_ids_off);
        put_u32(&mut out, 80, FIELDS.len() as u32);
        put_u32(&mut out, 84, field_ids_off);
        put_u32(&mut out, 88, METHODS.len() as u32);
        put_u32(&mut out, 92, method_ids_off);
        put_u32(&mut out, 96, 1);
        put_u32(&mut out, 100, class_defs_off);
        put_u32(&mut out, 104, file_size - data_off);
        put_u32(&mut out, 108, data_off);

        // string_ids：每项 4 字节，指向 string_data_item
        for (i, off) in string_offs.iter().enumerate() {
            put_u32(&mut out, (string_ids_off as usize) + i * 4, *off);
        }
        // type_ids：每项 4 字节，指向 string_ids
        for (i, s) in TYPES.iter().enumerate() {
            put_u32(&mut out, (type_ids_off as usize) + i * 4, *s as u32);
        }
        // proto_ids：每项 12 字节（shorty_idx, return_type_idx, parameters_off）
        let protos: [(u32, u32, u32); 2] = [
            (6, 4, 0),               // "V" / V / 无参数
            (7, 4, type_list_i_off), // "VI" / V / [I]
        ];
        for (i, (shorty, ret, params)) in protos.iter().enumerate() {
            let base = (proto_ids_off as usize) + i * 12;
            put_u32(&mut out, base, *shorty);
            put_u32(&mut out, base + 4, *ret);
            put_u32(&mut out, base + 8, *params);
        }
        // field_ids：每项 8 字节（u16 class, u16 type, u32 name）
        for (i, (class, ty, name)) in FIELDS.iter().enumerate() {
            let base = (field_ids_off as usize) + i * 8;
            out[base..base + 2].copy_from_slice(&class.to_le_bytes());
            out[base + 2..base + 4].copy_from_slice(&ty.to_le_bytes());
            put_u32(&mut out, base + 4, *name as u32);
        }
        // method_ids：每项 8 字节（u16 class, u16 proto, u32 name）
        for (i, (class, proto, name)) in METHODS.iter().enumerate() {
            let base = (method_ids_off as usize) + i * 8;
            out[base..base + 2].copy_from_slice(&class.to_le_bytes());
            out[base + 2..base + 4].copy_from_slice(&proto.to_le_bytes());
            put_u32(&mut out, base + 4, *name as u32);
        }
        // class_defs：一项 32 字节
        let cd = class_defs_off as usize;
        put_u32(&mut out, cd, CLASS_TYPE);
        put_u32(&mut out, cd + 4, ACC_PUBLIC);
        put_u32(&mut out, cd + 8, 2); // superclass_idx = Ljava/lang/Object;
        put_u32(&mut out, cd + 12, 0); // interfaces_off
        put_u32(&mut out, cd + 16, SOURCE_FILE_STR as u32);
        put_u32(&mut out, cd + 20, 0); // annotations_off
        put_u32(&mut out, cd + 24, class_data_off);
        put_u32(&mut out, cd + 28, 0); // static_values_off

        out.extend_from_slice(&data);

        // signature 先算：它的输入是 [32..file_size)，**不含** checksum 字段；
        // 而 checksum 的输入是 [12..file_size)，**含** signature 字段。
        // 顺序反了 checksum 就会算错（库会直接拒绝）。
        let signature = sha1(&out[32..]);
        out[12..32].copy_from_slice(&signature);
        let checksum = adler32(&out[12..]);
        put_u32(&mut out, 8, checksum);

        out
    }

    /// 把 signature 改坏、但把 checksum **重算对**的变体。
    ///
    /// 于是文件仍然能解析（Adler-32 是对的），只是头里的 SHA-1 对不上 ——
    /// 这正是真实世界里"被改过或重组过的 DEX"的样子，用来验证
    /// "降级必须说出来"（CLAUDE.md §7）这条路径。
    pub fn build_with_a_wrong_signature() -> Vec<u8> {
        let mut bytes = build();
        bytes[12] ^= 0xff;
        let checksum = adler32(&bytes[12..]);
        put_u32(&mut bytes, 8, checksum);
        bytes
    }

    /// 从**原始字节**里手读 `class_defs_size`（头偏移 `0x60`，规范 §3.1）。
    ///
    /// 刻意不走我们自己的解析：这是"库说有多少类"与"头里到底写了多少"的
    /// 独立对照，两边都出自同一份解析就失去意义了。
    pub fn hand_read_class_defs_size(bytes: &[u8]) -> u32 {
        u32::from_le_bytes(bytes[0x60..0x64].try_into().expect("4 字节"))
    }
}

/// 合成样本：逐项核对投影结果。
#[test]
fn a_minimal_but_conformant_dex_projects_classes_fields_and_methods() {
    let bytes = fixture::build();
    let dex: DexStructure =
        bitflip_loader::parse_dex_structure(&bytes).expect("合成样本必须能解析");

    // ── 头
    assert_eq!(dex.header.version, "035");
    assert_eq!(dex.header.file_size as usize, bytes.len());
    assert_eq!(dex.header.header_size, fixture::HEADER_SIZE);
    assert!(
        dex.header.sha1_matches_stored,
        "样本的 SHA-1 是按规范算出来的，必须判为一致"
    );

    // 六个池：声明多少就该解析出多少
    assert_eq!(
        dex.counts.declared.class_defs,
        fixture::hand_read_class_defs_size(&bytes),
        "我们读到的声明值必须等于从头里手读的值"
    );
    assert_eq!(dex.counts.declared.strings, fixture::STRINGS.len() as u32);
    assert!(
        dex.counts.mismatches.is_empty(),
        "合规样本不该有计数不符：{:?}",
        dex.counts.mismatches
    );

    // ── 类
    assert_eq!(dex.class_count(), 1);
    assert_eq!(dex.class_descriptor(0), Some("Lcom/example/Foo;"));
    assert_eq!(dex.class_short_name(0), Some("Foo"));
    assert_eq!(dex.superclass_descriptor(0), Some("Ljava/lang/Object;"));
    assert_eq!(dex.source_file(0), Some("Foo.java"));
    assert_eq!(dex.classes[0].access_flags, fixture::ACC_PUBLIC);

    // ── 字段：静态在前（规范 §4.5.11 的顺序），名字/类型回到池里取
    assert_eq!(dex.field_count(), 2);
    assert_eq!(dex.class_fields(0), vec![0, 1]);
    assert!(dex.fields[0].is_static, "静态字段排在前");
    assert!(!dex.fields[1].is_static, "实例字段排在后");
    assert_eq!(dex.field_name(0), Some("x"));
    assert_eq!(dex.field_type_descriptor(0), Some("I"));
    assert_eq!(dex.field_name(1), Some("s"));
    assert_eq!(dex.field_type_descriptor(1), Some("Ljava/lang/String;"));
    assert_eq!(dex.field_declaring_class(0), Some("Lcom/example/Foo;"));

    // ── 方法：直接方法在前；参数表来自 proto 的 type_list
    assert_eq!(dex.method_count(), 2);
    assert_eq!(dex.class_methods(0), vec![0, 1]);
    assert!(dex.methods[0].is_direct);
    assert_eq!(dex.method_name(0), Some("<init>"));
    assert_eq!(dex.method_return_descriptor(0), Some("V"));
    assert_eq!(dex.method_parameters(0), Vec::<&str>::new());
    assert!(!dex.methods[1].is_direct);
    assert_eq!(dex.method_name(1), Some("bar"));
    assert_eq!(dex.method_return_descriptor(1), Some("V"));
    assert_eq!(dex.method_parameters(1), vec!["I"]);

    // 两个方法都带字节码（样本里各给了一个 code_item）
    assert_eq!(dex.method_count_with_code(), 2);
    assert!(dex.methods.iter().all(|m| m.has_code()));
    assert_eq!(dex.method_class_index(0), Some(0));
    assert_eq!(dex.method_class_index(1), Some(0));

    // ── 结构性交叉校验：class_data 里数出来的符号数 == 两张表的条数之和
    assert_eq!(
        dex.symbols_declared_in_class_data(),
        (dex.field_count() + dex.method_count()) as u64,
        "四个 class_data 计数之和必须等于字段数 + 方法数（否则遍历时漏了某一类符号）"
    );

    // ── 按描述符精确查找
    assert_eq!(dex.find_class_by_descriptor("Lcom/example/Foo;"), Some(0));
    assert_eq!(dex.find_class_by_descriptor("Foo"), None, "不做模糊匹配");
    assert_eq!(dex.find_class_by_descriptor("Ljava/lang/Object;"), None);

    // ── 完全合规的文件不该有任何降级说明
    assert!(
        dex.notes.is_empty(),
        "合规样本不该有 notes（有的话说明我们或规范理解有偏差）：{:?}",
        dex.notes
    );
}

/// 合成的**不合规**样本：SHA-1 对不上时必须说出来，而不是照常报"分析完成"。
#[test]
fn a_dex_whose_stored_sha1_does_not_match_is_reported_not_hidden() {
    let bytes = fixture::build_with_a_wrong_signature();
    let dex = bitflip_loader::parse_dex_structure(&bytes).expect("checksum 是对的，仍应能解析");

    assert!(
        !dex.header.sha1_matches_stored,
        "这个变体就是要把 SHA-1 改坏"
    );
    assert!(
        dex.notes.iter().any(|n| n.contains("SHA-1")),
        "SHA-1 对不上必须出现在 notes 里（CLAUDE.md §7 的「降级要写在界面上」）：{:?}",
        dex.notes
    );
    // 但结构本身照常解析出来：容忍不等于丢弃
    assert_eq!(dex.class_count(), 1);
    assert_eq!(dex.method_count(), 2);
}

/// 输入被截断/不是 DEX 时必须是错误，不是"空但看起来完成"的结构。
#[test]
fn a_broken_input_is_an_error_not_an_empty_structure() {
    let full = fixture::build();
    // 掐掉尾部：class_data / code_item 都读不到了。
    let truncated = &full[..0x100];
    assert!(
        bitflip_loader::parse_dex_structure(truncated).is_err(),
        "截断的 DEX 必须报错，不能返回一个空结构"
    );
    assert!(bitflip_loader::parse_dex_structure(b"not a dex").is_err());
    assert!(bitflip_loader::parse_dex_structure(&[]).is_err());
}

/// 嗅探层认得出 DEX，且**不**给它编一个机器架构。
#[test]
fn sniffing_a_dex_yields_dex_marks_without_an_arch() {
    let bytes = fixture::build();
    let guess = bitflip_loader::sniff_bytes(&bytes);
    assert_eq!(guess.object, ObjectKind::Dex);
    assert_eq!(
        guess.arch, None,
        "DEX 没有机器架构：不能用占位值冒充（CLAUDE.md §7）"
    );
    assert_eq!(guess.container, bitflip_loader::ContainerKind::Plain);
}

// ── 真实样本 ────────────────────────────────────────────────────────────────

/// 本机真实 APK 的位置：优先 `BITFLIP_TEST_APK`，否则退回本机已知的那一份。
///
/// 环境变量优先是为了让别的机器也能跑这条测试 —— 把路径写死等于把测试
/// 绑在一台机器上，而"换台机器就跳过"正是 §7 说的会让绿灯说谎的做法。
fn sample_apk() -> std::path::PathBuf {
    if let Ok(from_env) = std::env::var("BITFLIP_TEST_APK") {
        return std::path::PathBuf::from(from_env);
    }
    std::path::PathBuf::from(r"C:\Users\Administrator\Downloads\ah-app-release.apk")
}

/// 真实 APK 里的三个 DEX：与头里**手读**的值逐一对齐。
///
/// 需要 32MB 的本机样本，所以默认 `#[ignore]`（CLAUDE.md §7：跳过与通过必须
/// 在报告里分得开）。
///
/// # 怎么手动跑
///
/// `scripts/cargo.ps1` 会吞掉裸 `--`（PS 5.1 的解析器先吃了一遍，脚本只在
/// 见到 `-D` / `--deny` 时才补回来），而 `cargo test --ignored` 又必须写成
/// `-- --ignored`。所以这条测试**直接跑测试可执行文件**：
///
/// ```text
/// & .\scripts\cargo.ps1 build --offline -p bitflip-loader --tests
/// $exe = Get-ChildItem .cargo-target\debug\deps\dex_structure-*.exe |
///        Sort-Object LastWriteTime -Descending | Select-Object -First 1
/// & $exe.FullName --ignored --nocapture
/// ```
///
/// # 耗时（实测，2026-10-14）
///
/// 本测试在 **debug** 下约 **5 分钟**（三个 dex 合计 25 MB）—— 时间几乎全在
/// 依赖库的解析里：同机 release 下 `classes.dex`（8.8 MB / 7643 类）只要
/// **1.2 s**，其中我们自己的 class_data 循环只占 **29 ms**。也就是说这是
/// **debug 构建的开销**，不是算法问题，也不是我们的代码慢。
///
/// 样本不在就**失败**（不是悄悄跳过）：既然有人显式要跑这条测试，
/// "样本没找到"就是它必须报告的那个事实。
#[ignore = "需要本机真实 APK（32MB）；用 --ignored 手动跑"]
#[test]
fn the_real_apk_dex_files_agree_with_their_headers() {
    let apk = sample_apk();
    let bytes = std::fs::read(&apk).unwrap_or_else(|e| {
        panic!(
            "读不到真实样本 {}: {e}\n（设 BITFLIP_TEST_APK 指向任意一个含 classes*.dex 的 APK）",
            apk.display()
        )
    });

    let listing = bitflip_loader::list_zip_members(&bytes).expect("列出 APK 成员");
    let mut dex_members: Vec<_> = listing
        .members
        .iter()
        .filter(|m| m.name.ends_with(".dex"))
        .collect();
    dex_members.sort_by(|a, b| a.name.cmp(&b.name));
    assert_eq!(
        dex_members.len(),
        3,
        "样本 APK 里有三个 dex，实际列出：{:?}",
        dex_members.iter().map(|m| &m.name).collect::<Vec<_>>()
    );

    let mut total_classes = 0usize;
    let mut total_methods = 0usize;
    let mut total_with_code = 0usize;
    let mut tolerance_notes: Vec<String> = Vec::new();

    for member in &dex_members {
        let raw = bitflip_loader::read_zip_member(&bytes, member.index)
            .unwrap_or_else(|e| panic!("取出 {} 失败: {e}", member.name));
        let dex = bitflip_loader::parse_dex_structure(&raw)
            .unwrap_or_else(|e| panic!("解析 {} 失败: {e}", member.name));

        // ① 类数 == **头里手读**的 class_defs_size（不是我们自己的声明值抄一遍）
        let hand_read = fixture::hand_read_class_defs_size(&raw);
        assert_eq!(
            dex.class_count(),
            hand_read as usize,
            "{}: 类数与头里手读的 class_defs_size 不符",
            member.name
        );

        // ② 六个池：声明 == 实际
        assert!(
            dex.counts.mismatches.is_empty(),
            "{}: 计数不符 {:?}",
            member.name,
            dex.counts.mismatches
        );

        // ③ 符号总数 == class_data 四个计数之和
        assert_eq!(
            dex.symbols_declared_in_class_data(),
            (dex.field_count() + dex.method_count()) as u64,
            "{}: 符号数与 class_data 计数之和不符 —— 说明有类被漏掉了",
            member.name
        );

        // ④ 每个类都能取到描述符，且字段/方法区间落在表内
        for (i, class) in dex.classes.iter().enumerate() {
            assert!(
                dex.class_descriptor(i).is_some(),
                "{}: 第 {i} 个类的描述符取不到",
                member.name
            );
            assert!(
                class.field_range().end <= dex.field_count(),
                "{}: 类的字段区间越界",
                member.name
            );
            assert!(
                class.method_range().end <= dex.method_count(),
                "{}: 类的方法区间越界",
                member.name
            );
        }

        // ⑤ 方法的总区间必须**恰好**铺满方法表（既不重叠也不留缝）
        let mut next = 0usize;
        for class in &dex.classes {
            assert_eq!(
                class.method_range().start,
                next,
                "{}: 方法区间有缝或重叠",
                member.name
            );
            next = class.method_range().end;
        }
        assert_eq!(
            next,
            dex.method_count(),
            "{}: 方法表没有被铺满",
            member.name
        );

        total_classes += dex.class_count();
        total_methods += dex.method_count();
        total_with_code += dex.method_count_with_code();
        for note in &dex.notes {
            tolerance_notes.push(format!("{}: {note}", member.name));
        }

        // 数据层输出：不只看绿灯，也看数（§7）
        println!(
            "  {} : {} 字节，类 {}，字段 {}，方法 {}（其中带字节码 {}），字符串池声明 {}",
            member.name,
            raw.len(),
            dex.class_count(),
            dex.field_count(),
            dex.method_count(),
            dex.method_count_with_code(),
            dex.counts.declared.strings
        );
    }

    println!("  合计：类 {total_classes}，方法 {total_methods}（带字节码 {total_with_code}）");

    // 三个 dex 的类数之和（M0 阶段手读过的值，写在这里当独立对照）。
    assert_eq!(
        total_classes,
        7643 + 8833 + 6462,
        "三个 dex 的类数之和与手读值不符"
    );

    // 真实世界里规范会被违反，而**容忍不等于没发生**：样本里就有一条
    // string_ids 乱序。这里钉住它，避免哪天"没人报告"被误当成"文件合规"。
    assert!(
        tolerance_notes.iter().any(|n| n.contains("StringIds")),
        "样本的 string_ids 乱序应当被如实记进 notes，实际：{tolerance_notes:?}"
    );
    for note in &tolerance_notes {
        println!("  note: {note}");
    }
}

/// M1 验收里被推迟的**第一条**：指令 ∪ 载荷必须**恰好铺满** `[0, insns_size)`。
///
/// 为什么这条非跑真实字节码不可：它是唯一一条**能独立于库验证库的宽度表**的检查 ——
/// 只借库给的地址，长度一律按规范从原始字节重算。宽度表里错一个码元，
/// 后面所有指令的地址就全错位，这里就会报洞或越界；而用库的长度去验证库的长度，
/// 无论库错得多离谱都会"通过"。
///
/// 代价：三个 dex 上共约 14 万个带字节码的方法，每个都要解析一次 `code_item`。
/// debug 下要跑几分钟（M1 记过：析构 `DexFile::parse` 才是大头，这条更贵）。
///
/// 样本不在就**失败**（不是悄悄跳过）：既然有人显式要跑这条测试，
/// "样本没找到"就是它必须报告的那个事实。
#[ignore = "需要本机真实 APK（32MB）；用 --ignored 手动跑"]
#[test]
fn every_real_methods_code_units_are_exactly_tiled_by_instructions_and_payloads() {
    let path = sample_apk();
    let bytes =
        std::fs::read(&path).unwrap_or_else(|e| panic!("读不到真实样本 {}: {e}", path.display()));
    let listing = bitflip_loader::list_zip_members(&bytes).expect("列出 APK 成员");

    let mut dex_members: Vec<_> = listing
        .members
        .iter()
        .filter(|m| m.name.ends_with(".dex"))
        .collect();
    dex_members.sort_by(|a, b| a.name.cmp(&b.name));

    let mut checked_methods = 0usize;
    let mut checked_payloads = 0usize;
    let mut without_code = 0usize;
    let mut problems: Vec<String> = Vec::new();
    let mut rendered_instructions = 0usize;
    let mut unsupported_operands = 0usize;
    let mut unavailable_operands = 0usize;
    let mut sample_text: Option<String> = None;

    for member in &dex_members {
        let raw = bitflip_loader::read_zip_member(&bytes, member.index)
            .unwrap_or_else(|e| panic!("取出 {} 失败: {e}", member.name));
        let dex = bitflip_loader::parse_dex_structure(&raw)
            .unwrap_or_else(|e| panic!("解析 {} 失败: {e}", member.name));

        for method in &dex.methods {
            if !method.has_code() {
                // 抽象 / native 方法本来就没有字节码：如实计数，不算跳过失败。
                without_code += 1;
                continue;
            }
            let check = bitflip_loader::check_code_item_layout(&raw, method.code_off)
                .unwrap_or_else(|e| {
                    panic!(
                        "{}: class_idx={} method_idx={} code_off={:#x} 布局校验失败: {e}",
                        member.name, method.class_index, method.method_idx, method.code_off
                    )
                });
            let view = project_dex_method(&raw, method.code_off).unwrap_or_else(|e| {
                panic!(
                    "{}: class_idx={} method_idx={} code_off={:#x} DEX view projection failed: {e}",
                    member.name, method.class_index, method.method_idx, method.code_off
                )
            });
            assert_eq!(view.instructions.len(), check.instructions);
            assert_eq!(view.payloads.addresses.len(), check.payloads);
            let view_problems = view.consistency_problems();
            assert!(
                view_problems.is_empty(),
                "{}: class_idx={} method_idx={} code_off={:#x} 视图列不对齐（最多列 5 条）：{:?}",
                member.name,
                method.class_index,
                method.method_idx,
                method.code_off,
                view_problems.iter().take(5).collect::<Vec<_>>()
            );
            let cross_problems = view.cross_check_problems();
            assert!(
                cross_problems.is_empty(),
                "{}: class_idx={} method_idx={} code_off={:#x} 指令列与 CFG 不互相印证（最多列 5 条）：{:?}",
                member.name,
                method.class_index,
                method.method_idx,
                method.code_off,
                cross_problems.iter().take(5).collect::<Vec<_>>()
            );
            checked_methods += 1;
            checked_payloads += check.payloads;

            // 符号解析：真实池上跑一遍渲染，异常（索引越界/库拒绝解析）必须是 0。
            // call-site 等已知缺口如实计数，不当成失败 —— 但也绝不静默。
            let mut text = String::new();
            let report =
                render_dex_instructions_with_symbols(&view.instructions, &dex.symbols(), &mut text)
                    .unwrap_or_else(|e| {
                        panic!(
                            "{}: class_idx={} method_idx={} code_off={:#x} 符号渲染失败: {e}",
                            member.name, method.class_index, method.method_idx, method.code_off
                        )
                    });
            rendered_instructions += report.instructions;
            unsupported_operands += report.unsupported_operands;
            unavailable_operands += report.unavailable_operands;
            assert_eq!(
                report.unavailable_operands,
                0,
                "{}: class_idx={} method_idx={} code_off={:#x} 有 {} 处符号解析异常；\
                 输出片段（最多 200 字符）：{}",
                member.name,
                method.class_index,
                method.method_idx,
                method.code_off,
                report.unavailable_operands,
                text.chars().take(200).collect::<String>()
            );
            if sample_text.is_none() && text.contains("->") {
                sample_text = Some(text.clone());
            }

            if !check.is_exact() {
                for p in &check.problems {
                    problems.push(format!(
                        "{}: class_idx={} method_idx={} code_off={:#x} 码元 {} [{}] {}",
                        member.name,
                        method.class_index,
                        method.method_idx,
                        method.code_off,
                        p.at,
                        p.kind.as_str(),
                        p.detail
                    ));
                }
            }
        }
    }

    println!(
        "  检查了 {checked_methods} 个方法的码元布局（含 {checked_payloads} 个载荷）；\
         {without_code} 个方法没有字节码（抽象/native，如实计数不计入检查）"
    );
    println!(
        "  符号渲染：{rendered_instructions} 条指令；已知缺口（如 call-site）\
         {unsupported_operands} 处；解析异常 {unavailable_operands} 处"
    );
    if let Some(text) = &sample_text {
        let sample: String = text.lines().take(8).collect::<Vec<_>>().join("\n    ");
        println!("  首个含符号引用的方法（前 8 行）：\n    {sample}");
    }

    // 设计文档写的验收门槛是"在 3000 个真实方法上 0 不吻合"。真实样本上我们
    // 检查的是全部带字节码的方法（远多于 3000），所以先钉住"确实检查到了量"。
    assert!(
        checked_methods >= 3000,
        "只检查到 {checked_methods} 个方法，样本不对或过滤条件错了"
    );
    assert!(
        problems.is_empty(),
        "{} 个方法的布局不吻合（最多列 10 条）：\n{}",
        problems.len(),
        problems
            .iter()
            .take(10)
            .cloned()
            .collect::<Vec<_>>()
            .join("\n")
    );
}
