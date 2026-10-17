//! 按 Dalvik Executable 规范拼一份最小但完全合规的 DEX（合成样本）。
//!
//! 规范出处逐项写在代码里（`§3.1` 指 "Dalvik Executable format" 文档的章节号）。
//!
//! 单列在 `tests/common/` 是为了**两个测试共用同一份样本**：loader 的结构黄金测试，
//! 和 CLI 的 `dex` 子命令测试（后者用 `#[path]` 引入）。样本只有一份，
//! 就没有"两个 crate 各养一份、然后慢慢分叉"的机会。
//!
//! 偏移与编码都对应规范原文（CLAUDE.md §6.11 要求 fixture 照规格拼，不许照自己的
//! 解析代码拼）；loader 侧另有一条真实 APK 测试兜底"规范之外还有现实"。

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

/// 把某个 u32 字段改成指定值（偏移按规范 §3.1 的头布局写）。
///
/// 只是原地改字节 —— 改完必须调 [`resign`]，否则库会先报校验和对不上。
///
/// `allow(dead_code)`：只有"造畸形样本"的那几个测试目标用得到它，而这份 fixture
/// 被多个测试用 `#[path]` 引入，用不到的目标不该因此报错。
#[allow(dead_code)]
pub fn patch_u32(bytes: &mut [u8], off: usize, value: u32) {
    put_u32(bytes, off, value);
}

/// 改过字节之后**重新签名**（`SHA-1` + Adler-32，按规范 §3.1 的两个区间）。
///
/// 为什么必须有这一步：造"头里的计数被改坏了、其余一切合规"的样本时，若不重算
/// 签名，解析器在读计数**之前**就因为 Adler-32 不对而拒绝 —— 那条测试看着是绿的
/// （确实报错了），但验证的是校验和，不是放大攻击守卫。踩过这个坑。
#[allow(dead_code)]
pub fn resign(bytes: &mut [u8]) {
    let signature = sha1(&bytes[32..]);
    bytes[12..32].copy_from_slice(&signature);
    let checksum = adler32(&bytes[12..]);
    put_u32(bytes, 8, checksum);
}
