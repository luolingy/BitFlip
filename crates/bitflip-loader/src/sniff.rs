//! 格式嗅探：只读文件头与容器结构，给出可验证的识别结论。
//!
//! 原则：**拿不到就说拿不到**。识别不出来时字段留 `None`，并在 `notes` 里写清
//! 判定依据与限制（例如"仅识别 Mach-O，解析推迟到 M10"），绝不用 0 或空值冒充。

use std::io::Read;
use std::path::Path;

use bitflip_arch::{Arch, ArchSpec, Endian, Mode};

use crate::{ArchiveMember, ContainerKind, Guess, LoaderError, ObjectKind};

/// 单次嗅探读取的字节上限（8 MiB）：足够覆盖任何正常文件头与常见归档目录，
/// 又不至于为了一次识别把 GB 级固件读进内存。
pub const SNIFF_WINDOW: usize = 8 * 1024 * 1024;

/// 归档成员枚举上限。
const MAX_ARCHIVE_MEMBERS: usize = 4096;

/// 递归嗅探的最大深度（归档成员里再套归档）。
const MAX_DEPTH: u8 = 2;

// ── 读取辅助 ────────────────────────────────────────────────────────────────

fn read_u16(bytes: &[u8], off: usize, endian: Endian) -> Option<u16> {
    let end = off.checked_add(2)?;
    let raw: [u8; 2] = bytes.get(off..end)?.try_into().ok()?;
    Some(match endian {
        Endian::Little => u16::from_le_bytes(raw),
        Endian::Big => u16::from_be_bytes(raw),
    })
}

fn read_u32(bytes: &[u8], off: usize, endian: Endian) -> Option<u32> {
    let end = off.checked_add(4)?;
    let raw: [u8; 4] = bytes.get(off..end)?.try_into().ok()?;
    Some(match endian {
        Endian::Little => u32::from_le_bytes(raw),
        Endian::Big => u32::from_be_bytes(raw),
    })
}

fn read_u64(bytes: &[u8], off: usize, endian: Endian) -> Option<u64> {
    let end = off.checked_add(8)?;
    let raw: [u8; 8] = bytes.get(off..end)?.try_into().ok()?;
    Some(match endian {
        Endian::Little => u64::from_le_bytes(raw),
        Endian::Big => u64::from_be_bytes(raw),
    })
}

/// 去掉首尾空白与 NUL（归档头字段用空格填充）。
fn trim_field(field: &[u8]) -> &[u8] {
    let start = field
        .iter()
        .position(|b| !b.is_ascii_whitespace() && *b != 0)
        .unwrap_or(field.len());
    let end = field
        .iter()
        .rposition(|b| !b.is_ascii_whitespace() && *b != 0)
        .map_or(start, |i| i + 1);
    &field[start..end]
}

/// 解析 ASCII 十进制字段（归档的大小字段）。
fn parse_decimal(field: &[u8]) -> Option<usize> {
    let s = std::str::from_utf8(trim_field(field)).ok()?;
    if s.is_empty() {
        return None;
    }
    s.parse::<usize>().ok()
}

// ── 入口 ────────────────────────────────────────────────────────────────────

/// 嗅探一个文件（只读前 [`SNIFF_WINDOW`] 字节）。
pub fn sniff_file(path: impl AsRef<Path>) -> Result<Guess, LoaderError> {
    let path = path.as_ref();
    let meta = std::fs::metadata(path).map_err(|source| LoaderError::Io {
        path: path.display().to_string(),
        source,
    })?;

    if meta.is_dir() {
        return Err(LoaderError::IsDirectory(path.display().to_string()));
    }
    if !meta.is_file() {
        return Err(LoaderError::NotRegularFile(path.display().to_string()));
    }

    let file = std::fs::File::open(path).map_err(|source| LoaderError::Io {
        path: path.display().to_string(),
        source,
    })?;
    let mut buf = Vec::new();
    file.take(SNIFF_WINDOW as u64)
        .read_to_end(&mut buf)
        .map_err(|source| LoaderError::Io {
            path: path.display().to_string(),
            source,
        })?;

    let mut guess = sniff_inner(&buf, 0);
    guess.sniffed_bytes = buf.len();
    guess.file_truncated = meta.len() > buf.len() as u64;
    if guess.file_truncated {
        let total = meta.len();
        guess
            .notes
            .push(format!("文件 {total} 字节，仅嗅探了前 {} 字节", buf.len()));
    }
    Ok(guess)
}

/// 嗅探内存中的字节。
#[must_use]
pub fn sniff_bytes(bytes: &[u8]) -> Guess {
    let mut guess = sniff_inner(bytes, 0);
    guess.sniffed_bytes = bytes.len();
    guess
}

fn sniff_inner(bytes: &[u8], depth: u8) -> Guess {
    let mut g = Guess::new(bytes.len());

    if bytes.is_empty() {
        g.notes.push("文件为空".to_string());
        return g;
    }

    if bytes.starts_with(b"\x7fELF") {
        sniff_elf(bytes, &mut g);
    } else if bytes.starts_with(b"!<arch>\n") {
        sniff_ar(bytes, &mut g, depth);
    } else if is_fat_container(bytes) {
        sniff_fat(bytes, &mut g);
    } else if bytes.len() >= 2 && bytes[0] == b'M' && bytes[1] == b'Z' {
        sniff_mz(bytes, &mut g);
    } else if is_thin_macho(bytes) {
        sniff_macho(bytes, &mut g);
    } else if looks_like_coff(bytes) {
        sniff_coff(bytes, &mut g);
    } else {
        g.object = ObjectKind::Raw;
        g.notes.push(
            "未匹配已知容器/对象格式，按原始二进制处理：需要手工指定架构（`--arch`），\
             基址也通常需要（`--base`）"
                .to_string(),
        );
    }

    g
}

// ── ELF ─────────────────────────────────────────────────────────────────────

const ELF_E_TYPE_OFF: usize = 16;
const ELF_E_MACHINE_OFF: usize = 18;
const ELF_E_ENTRY_OFF: usize = 24;
const ELF32_E_SHNUM_OFF: usize = 0x30;
const ELF64_E_SHNUM_OFF: usize = 0x3c;

fn sniff_elf(bytes: &[u8], g: &mut Guess) {
    g.container = ContainerKind::Plain;
    g.object = ObjectKind::Elf;

    if bytes.len() < 20 {
        g.notes.push("ELF 头被截断（不足 20 字节）".to_string());
        return;
    }

    let class = bytes[4];
    let endian = if bytes[5] == 2 {
        Endian::Big
    } else {
        Endian::Little
    };
    let is_64 = class == 2;
    g.endian = Some(endian);
    g.bits = if is_64 { 64 } else { 32 };
    if class != 1 && class != 2 {
        g.notes
            .push(format!("ELF Class 字段异常（{class}），按 32 位处理"));
    }

    let machine = read_u16(bytes, ELF_E_MACHINE_OFF, endian);
    g.arch = machine.and_then(|m| {
        Arch::from_elf_machine(m, is_64).map(|arch| {
            ArchSpec::from_arch(arch, if is_64 { Mode::M64 } else { Mode::M32 }, endian)
        })
    });
    if g.arch.is_none() {
        g.notes.push(match machine {
            Some(m) => format!("未识别的 ELF 架构（e_machine = {m} / {m:#x}）"),
            None => "无法读取 e_machine".to_string(),
        });
    }

    let e_type = read_u16(bytes, ELF_E_TYPE_OFF, endian);
    let kind = match e_type {
        Some(1) => "可重定位目标文件 (.o)",
        Some(2) => "可执行文件",
        Some(3) => "共享对象 (.so / PIE 可执行)",
        Some(4) => "core dump",
        _ => "未知 e_type",
    };
    g.notes.push(format!("ELF {kind}"));

    g.entry = if is_64 {
        read_u64(bytes, ELF_E_ENTRY_OFF, endian)
    } else {
        read_u32(bytes, ELF_E_ENTRY_OFF, endian).map(u64::from)
    };

    let shnum_off = if is_64 {
        ELF64_E_SHNUM_OFF
    } else {
        ELF32_E_SHNUM_OFF
    };
    g.sections = read_u16(bytes, shnum_off, endian);
    if g.sections == Some(0) {
        g.sections = None;
        g.notes.push(
            "节数为 0：真实数量在 section 0 的 sh_size 里（extended shnum），M1 处理".to_string(),
        );
    }
}

// ── PE / COFF ───────────────────────────────────────────────────────────────

const DOS_LFANEW_OFF: usize = 0x3c;
const COFF_HEADER_SIZE: usize = 24;
const PE_MAGIC_OFF: usize = 0;
const PE_ENTRY_RVA_OFF: usize = 16;
const PE32_IMAGE_BASE_OFF: usize = 28;
const PE32PLUS_IMAGE_BASE_OFF: usize = 24;
const PE32_NUM_DDIR_OFF: usize = 92;
const PE32PLUS_NUM_DDIR_OFF: usize = 108;
const PE32_DATA_DIR_OFF: usize = 96;
const PE32PLUS_DATA_DIR_OFF: usize = 112;
const DD_ENTRY_SIZE: usize = 8;
/// 数据目录 14 号是 CLI header（.NET 程序集）。
const DD_INDEX_CLI_HEADER: usize = 14;
/// `IMAGE_FILE_DLL`
const IMAGE_FILE_DLL: u16 = 0x2000;

fn sniff_mz(bytes: &[u8], g: &mut Guess) {
    let Some(lfanew) = read_u32(bytes, DOS_LFANEW_OFF, Endian::Little) else {
        g.notes.push("MZ 头被截断，无法读取 e_lfanew".to_string());
        return;
    };
    let Some(pe_off) = usize::try_from(lfanew).ok() else {
        g.notes.push(format!("e_lfanew 超出范围（{lfanew:#x}）"));
        return;
    };

    let Some(sig_end) = pe_off.checked_add(4) else {
        g.notes.push("e_lfanew 溢出".to_string());
        return;
    };
    if bytes.get(pe_off..sig_end) != Some(b"PE\0\0".as_slice()) {
        g.object = ObjectKind::Raw;
        g.notes
            .push("MZ 头但没有 PE 签名：DOS 可执行或文件已损坏，按原始二进制处理".to_string());
        return;
    }

    g.container = ContainerKind::Plain;
    g.object = ObjectKind::Pe;
    g.endian = Some(Endian::Little);

    let machine = read_u16(bytes, pe_off + 4, Endian::Little);
    g.arch = machine
        .and_then(Arch::from_pe_machine)
        .map(|(arch, mode)| ArchSpec::from_arch(arch, mode, Endian::Little));
    if g.arch.is_none() {
        g.notes.push(match machine {
            Some(m) => format!("未识别的 PE Machine（{m:#06x}）"),
            None => "PE 头被截断，无法读取 Machine".to_string(),
        });
    }

    g.sections = read_u16(bytes, pe_off + 6, Endian::Little);

    let characteristics = read_u16(bytes, pe_off + 18, Endian::Little);
    if characteristics.is_some_and(|c| c & IMAGE_FILE_DLL != 0) {
        g.notes.push("PE 标志位含 DLL，属动态库".to_string());
    }

    let optional_off = pe_off + COFF_HEADER_SIZE;
    let magic = read_u16(bytes, optional_off + PE_MAGIC_OFF, Endian::Little);
    let is_plus = match magic {
        Some(0x20b) => true,
        Some(0x10b) => false,
        Some(other) => {
            g.notes
                .push(format!("可选头 Magic 异常（{other:#06x}），按 PE32 处理"));
            false
        }
        None => {
            g.notes
                .push("缺少可选头（`IMAGE_FILE_*` 上的 .obj 走 COFF 路径）".to_string());
            return;
        }
    };
    g.bits = if is_plus { 64 } else { 32 };

    let entry_rva = read_u32(bytes, optional_off + PE_ENTRY_RVA_OFF, Endian::Little);
    g.image_base = if is_plus {
        read_u64(
            bytes,
            optional_off + PE32PLUS_IMAGE_BASE_OFF,
            Endian::Little,
        )
    } else {
        read_u32(bytes, optional_off + PE32_IMAGE_BASE_OFF, Endian::Little).map(u64::from)
    };

    g.entry = match (g.image_base, entry_rva) {
        (Some(base), Some(rva)) if rva != 0 => Some(base.wrapping_add(u64::from(rva))),
        _ => None,
    };
    if entry_rva == Some(0) {
        g.notes
            .push("AddressOfEntryPoint 为 0（DLL 常见）".to_string());
    }

    sniff_pe_data_directories(bytes, g, optional_off, is_plus);
}

fn sniff_pe_data_directories(bytes: &[u8], g: &mut Guess, optional_off: usize, is_plus: bool) {
    let (num_off, dir_off) = if is_plus {
        (PE32PLUS_NUM_DDIR_OFF, PE32PLUS_DATA_DIR_OFF)
    } else {
        (PE32_NUM_DDIR_OFF, PE32_DATA_DIR_OFF)
    };
    let Some(count) = read_u32(bytes, optional_off + num_off, Endian::Little) else {
        return;
    };
    if usize::try_from(count).unwrap_or(0) <= DD_INDEX_CLI_HEADER {
        return;
    }
    let cli_off = optional_off + dir_off + DD_INDEX_CLI_HEADER * DD_ENTRY_SIZE;
    let cli_rva = read_u32(bytes, cli_off, Endian::Little).unwrap_or(0);
    let cli_size = read_u32(bytes, cli_off + 4, Endian::Little).unwrap_or(0);
    if cli_rva != 0 && cli_size != 0 {
        g.notes.push(
            "检测到 CLI header：这是托管程序集（.NET），CIL 反编译不在 BitFlip 范围内".to_string(),
        );
    }
}

/// 无 `MZ` 前缀的 COFF 目标文件（`.obj`）。
fn looks_like_coff(bytes: &[u8]) -> bool {
    if bytes.len() < 20 {
        return false;
    }
    let machine = read_u16(bytes, 0, Endian::Little);
    let sections = read_u16(bytes, 2, Endian::Little);
    match (machine, sections) {
        (Some(m), Some(s)) => Arch::from_pe_machine(m).is_some() && (1..=4096).contains(&s),
        _ => false,
    }
}

fn sniff_coff(bytes: &[u8], g: &mut Guess) {
    g.container = ContainerKind::Plain;
    g.object = ObjectKind::Coff;
    g.endian = Some(Endian::Little);

    let machine = read_u16(bytes, 0, Endian::Little);
    g.arch = machine
        .and_then(Arch::from_pe_machine)
        .map(|(arch, mode)| ArchSpec::from_arch(arch, mode, Endian::Little));
    g.bits = g.arch.map_or(0, |a| a.ptr_size * 8);
    g.sections = read_u16(bytes, 2, Endian::Little);
    g.notes
        .push("COFF 目标文件：语义分析与段/符号解析在 M1/M5".to_string());
}

// ── Mach-O（M0 只识别） ─────────────────────────────────────────────────────

fn is_thin_macho(bytes: &[u8]) -> bool {
    bytes.len() >= 4 && macho_thin_kind(bytes).is_some()
}

fn is_fat_container(bytes: &[u8]) -> bool {
    bytes.len() >= 8
        && (bytes[0..4] == [0xca, 0xfe, 0xba, 0xbe] || bytes[0..4] == [0xca, 0xfe, 0xba, 0xbf])
}

/// 识别 thin Mach-O：返回（是否 64 位，文件端序）。
fn macho_thin_kind(bytes: &[u8]) -> Option<(bool, Endian)> {
    let magic = read_u32(bytes, 0, Endian::Little)?;
    Some(match magic {
        0xfeed_face => (false, Endian::Little),
        0xfeed_facf => (true, Endian::Little),
        0xcefa_edfe => (false, Endian::Big),
        0xcffa_edfe => (true, Endian::Big),
        _ => return None,
    })
}

fn sniff_macho(bytes: &[u8], g: &mut Guess) {
    let Some((is_64, endian)) = macho_thin_kind(bytes) else {
        return;
    };
    g.container = ContainerKind::Plain;
    g.object = ObjectKind::MachO;
    g.endian = Some(endian);
    g.bits = if is_64 { 64 } else { 32 };

    let cputype = read_u32(bytes, 4, endian);
    g.arch = cputype
        .and_then(Arch::from_macho_cputype)
        .map(|(arch, mode)| ArchSpec::from_arch(arch, mode, endian));

    let filetype = read_u32(bytes, 12, endian);
    let kind = match filetype {
        Some(1) => "object (.o)",
        Some(2) => "可执行文件（.app bundle 里通常是它）",
        Some(6) => "动态库 (.dylib)",
        Some(8) => "bundle",
        _ => "未知 filetype",
    };
    g.notes.push(format!(
        "识别为 Mach-O {kind}；完整解析（含 .app bundle 与 fat 容器）排期在 M10（见 docs/PLAN.md）"
    ));
}

fn sniff_fat(bytes: &[u8], g: &mut Guess) {
    let Some(nfat) = read_u32(bytes, 4, Endian::Big) else {
        return;
    };
    let first_cputype = read_u32(bytes, 8, Endian::Big);
    let plausible = first_cputype.and_then(Arch::from_macho_cputype).is_some();

    // 经典歧义：Java class 文件同样以 CAFEBABE 开头。用"切片数合理 + 首个
    // cputype 是已知 Mach-O CPU"两个条件把两者分开。
    if !plausible || !(1..=64).contains(&nfat) {
        g.object = ObjectKind::Raw;
        g.notes.push(
            "以 CAFEBABE 开头但不符合 fat Mach-O 结构（切片数或 cputype 不合理），按原始二进制处理"
                .to_string(),
        );
        return;
    }

    g.container = ContainerKind::Fat;
    g.object = ObjectKind::Raw;
    g.notes.push(format!(
        "Mach-O universal (fat) 容器，{nfat} 个切片；切片枚举与分析排期在 M10"
    ));
}

// ── ar / MSVC .lib ─────────────────────────────────────────────────────────

const AR_MAGIC_LEN: usize = 8;
const AR_MEMBER_HEADER_LEN: usize = 60;

fn sniff_ar(bytes: &[u8], g: &mut Guess, depth: u8) {
    g.container = ContainerKind::Ar;

    let mut pos = AR_MAGIC_LEN;
    let mut long_names: Option<Vec<u8>> = None;
    let mut msvc_style_names = false;
    let mut has_symbol_index = false;
    let mut first_member_data: Option<(usize, usize, String)> = None;

    while g.members.len() < MAX_ARCHIVE_MEMBERS {
        let Some(header_end) = pos.checked_add(AR_MEMBER_HEADER_LEN) else {
            break;
        };
        if header_end > bytes.len() {
            if pos < bytes.len() {
                g.members_truncated = true;
                g.notes
                    .push("归档在成员头处被截断（超出嗅探窗口）".to_string());
            }
            break;
        }
        let header = &bytes[pos..header_end];
        if &header[58..60] != b"`\n" {
            g.notes.push(format!(
                "归档成员头校验失败（偏移 {pos} 处缺少 `` `\\n ``），停止解析"
            ));
            break;
        }

        let raw_name = trim_field(&header[0..16]);
        let Some(size) = parse_decimal(&header[48..58]) else {
            g.notes
                .push(format!("归档成员大小字段无法解析（偏移 {pos}）"));
            break;
        };

        let mut data_off = header_end;
        let mut data_size = size;
        // 修剪 NUL 与空白：GNU 归档用 "/" 结束长名，BSD 用 NUL 填充内联名。
        let mut name = String::from_utf8_lossy(trim_field(raw_name)).into_owned();
        let mut is_payload_member = true;

        // ar 的名字字段有四种形态，先分类再处理 —— 顺序错了会互相误伤
        // （历史 bug：把 "/" 当空偏移的长名引用 → 符号索引名字为空；
        //   把 "/0" 当普通名字 → 长名表解析不出来）。
        //
        //   "name/"    普通短名，结尾 "/" 是 GNU 的终止符，不属于名字
        //   "//"       长名表（特例，终止符不适用）
        //   "/"        符号索引
        //   "/123"     长名表偏移引用（GNU；MSVC 里是 "/123" 或 "/name"）
        enum NameForm {
            Plain,
            LongNameTable,
            SymbolIndex,
            LongNameRef,
            Inline,
        }

        let form = if name.is_empty() {
            NameForm::Plain
        } else if name == "//" {
            NameForm::LongNameTable
        } else if name == "/" {
            NameForm::SymbolIndex
        } else if let Some(rest) = name.strip_prefix("#1/") {
            let _ = rest;
            NameForm::Inline
        } else if name.starts_with("/#1/") {
            NameForm::Inline
        } else if let Some(rest) = name.strip_prefix('/') {
            // 只有全部是数字（允许尾部一个 '/'）才是偏移引用；否则按普通名字处理，
            // 免得把 MSVC 的 "/name" 形式误判成数字解析失败。
            let digits = rest.strip_suffix('/').unwrap_or(rest);
            if !digits.is_empty() && digits.bytes().all(|b| b.is_ascii_digit()) {
                NameForm::LongNameRef
            } else {
                NameForm::Plain
            }
        } else {
            NameForm::Plain
        };

        // 普通短名剥掉 GNU 终止符。
        if matches!(form, NameForm::Plain) && name.len() > 1 && name.ends_with('/') {
            name.pop();
        }

        match form {
            NameForm::Plain => {
                if name.is_empty() {
                    name = "<无名成员>".to_string();
                    is_payload_member = false;
                }
            }
            NameForm::Inline => {
                // BSD 风格：名字内联在数据开头，内联段本身不算载荷。
                // 名字形如 "#1/<len>"；有些实现写成 "/#1/<len>"，两种都要认。
                is_payload_member = false;
                let len_str = name
                    .trim_start_matches('/')
                    .trim_start_matches("#1/")
                    .trim_end_matches('/');
                match len_str.parse::<usize>() {
                    Ok(inline_len) if inline_len <= data_size => {
                        if let Some(inline) = bytes.get(data_off..data_off + inline_len) {
                            let inline_name = trim_field(inline);
                            if !inline_name.is_empty() {
                                name = String::from_utf8_lossy(inline_name).into_owned();
                            }
                            data_off += inline_len;
                            data_size -= inline_len;
                            is_payload_member = data_size > 0;
                        }
                    }
                    _ => {
                        g.notes
                            .push(format!("BSD 内联名长度非法（{len_str}），该成员无法解析"));
                    }
                }
            }
            NameForm::LongNameTable => {
                is_payload_member = false;
                if let Some(table) = bytes.get(data_off..data_off + data_size) {
                    msvc_style_names = table.contains(&0);
                    long_names = Some(table.to_vec());
                }
                g.notes.push(if msvc_style_names {
                    "长名表为 NUL 分隔，按 MSVC `.lib` 处理".to_string()
                } else {
                    "长名表为 GNU `/\\n` 分隔".to_string()
                });
            }
            NameForm::SymbolIndex => {
                is_payload_member = false;
                has_symbol_index = true;
                name = "/ (符号索引)".to_string();
            }
            NameForm::LongNameRef => {
                let offset_str = name
                    .strip_prefix('/')
                    .unwrap_or("")
                    .trim_end_matches('/')
                    .to_string();
                match offset_str.parse::<usize>() {
                    Ok(offset) => {
                        let resolved = long_names
                            .as_ref()
                            .map(|table| resolve_long_name(table, offset, msvc_style_names));
                        match resolved {
                            Some(resolved_name) if !resolved_name.is_empty() => {
                                name = resolved_name;
                            }
                            _ => {
                                name = format!("/{offset}（长名表未命中）");
                                is_payload_member = false;
                            }
                        }
                    }
                    Err(_) => {
                        g.notes
                            .push(format!("成员名 {name} 不是合法的长名引用，保留原名"));
                    }
                }
            }
        }

        if is_payload_member && first_member_data.is_none() && data_size > 0 {
            first_member_data = Some((data_off, data_size, name.clone()));
        }

        let end = data_off.saturating_add(data_size);
        g.members.push(ArchiveMember {
            name,
            offset: data_off as u64,
            size: data_size as u64,
            truncated: end > bytes.len(),
        });

        // 成员数据按偶数对齐。
        let advance = AR_MEMBER_HEADER_LEN + data_size + (data_size & 1);
        pos = match pos.checked_add(advance) {
            Some(next) if next > pos => next,
            _ => break,
        };
        if pos > bytes.len() {
            g.members_truncated = true;
            break;
        }
    }

    if g.members.len() >= MAX_ARCHIVE_MEMBERS {
        g.members_truncated = true;
        g.notes
            .push(format!("成员数达到上限 {MAX_ARCHIVE_MEMBERS}，后续未枚举"));
    }

    if has_symbol_index && msvc_style_names {
        g.container = ContainerKind::MsvcLib;
    }

    // 成员格式：取第一个**有载荷**的成员做一次递归嗅探（深度受限，避免套娃）。
    // 归档里的长名表、"//" 与符号索引 "/" 都是元数据成员，不是目标对象：
    // 拿它们当"首个成员"会得出"这个归档不是 ELF"这种错误结论。
    if depth < MAX_DEPTH {
        if let Some((off, size, member_name)) = first_member_data {
            if let Some(slice) = bytes.get(off..off.saturating_add(size)) {
                let inner = sniff_inner(slice, depth + 1);
                if inner.object == ObjectKind::Raw {
                    g.notes.push(format!(
                        "无法识别成员 {member_name} 的对象格式（按原始二进制处理）"
                    ));
                } else {
                    g.member_kind = Some(inner.object);
                    if g.arch.is_none() {
                        g.arch = inner.arch;
                        g.bits = inner.bits;
                        g.endian = inner.endian;
                    }
                    g.notes.push(format!(
                        "成员格式（取自 {member_name}）：{}",
                        inner.object.label_zh()
                    ));
                }
            }
        }
    }
}

/// 解析归档长名表里的名字。GNU 以 `/` 或换行结束，MSVC 以 NUL 结束。
fn resolve_long_name(table: &[u8], offset: usize, nul_terminated: bool) -> String {
    let Some(rest) = table.get(offset..) else {
        return format!("/{offset}（偏移越界）");
    };
    let end = if nul_terminated {
        rest.iter().position(|b| *b == 0)
    } else {
        rest.iter().position(|b| *b == b'/' || *b == b'\n')
    };
    let slice = &rest[..end.unwrap_or(rest.len())];
    String::from_utf8_lossy(slice).to_string()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn elf64_header(machine: u16) -> Vec<u8> {
        let mut v = vec![0u8; 64];
        v[..4].copy_from_slice(b"\x7fELF");
        v[4] = 2; // 64 位
        v[5] = 1; // 小端
        v[6] = 1; // EV_CURRENT
        v[ELF_E_TYPE_OFF..ELF_E_TYPE_OFF + 2].copy_from_slice(&2u16.to_le_bytes()); // ET_EXEC
        v[ELF_E_MACHINE_OFF..ELF_E_MACHINE_OFF + 2].copy_from_slice(&machine.to_le_bytes());
        v[ELF_E_ENTRY_OFF..ELF_E_ENTRY_OFF + 8].copy_from_slice(&0x401000u64.to_le_bytes());
        v[ELF64_E_SHNUM_OFF..ELF64_E_SHNUM_OFF + 2].copy_from_slice(&5u16.to_le_bytes());
        v
    }

    fn pe64() -> Vec<u8> {
        let mut v = vec![0u8; 0x200];
        v[0] = b'M';
        v[1] = b'Z';
        v[DOS_LFANEW_OFF..DOS_LFANEW_OFF + 4].copy_from_slice(&0x80u32.to_le_bytes());
        let pe = 0x80usize;
        v[pe..pe + 4].copy_from_slice(b"PE\0\0");
        v[pe + 4..pe + 6].copy_from_slice(&0x8664u16.to_le_bytes());
        v[pe + 6..pe + 8].copy_from_slice(&3u16.to_le_bytes());
        v[pe + 18..pe + 20].copy_from_slice(&0x2022u16.to_le_bytes()); // EXECUTABLE_IMAGE | LARGE_ADDRESS_AWARE
        let opt = pe + COFF_HEADER_SIZE;
        v[opt..opt + 2].copy_from_slice(&0x20bu16.to_le_bytes()); // PE32+
        v[opt + PE_ENTRY_RVA_OFF..opt + PE_ENTRY_RVA_OFF + 4]
            .copy_from_slice(&0x1000u32.to_le_bytes());
        v[opt + PE32PLUS_IMAGE_BASE_OFF..opt + PE32PLUS_IMAGE_BASE_OFF + 8]
            .copy_from_slice(&0x1_4000_0000u64.to_le_bytes());
        v[opt + PE32PLUS_NUM_DDIR_OFF..opt + PE32PLUS_NUM_DDIR_OFF + 4]
            .copy_from_slice(&16u32.to_le_bytes());
        v
    }

    fn ar_member(name: &str, data: &[u8]) -> Vec<u8> {
        let mut header = vec![b' '; AR_MEMBER_HEADER_LEN];
        let name_bytes = name.as_bytes();
        let n = name_bytes.len().min(16);
        header[..n].copy_from_slice(&name_bytes[..n]);
        let size_field = format!("{:<10}", data.len());
        header[48..58].copy_from_slice(size_field.as_bytes());
        header[58..60].copy_from_slice(b"`\n");
        let mut out = header;
        out.extend_from_slice(data);
        if data.len() % 2 == 1 {
            out.push(b'\n');
        }
        out
    }

    #[test]
    fn elf_macho_and_pe_identify() {
        let elf = sniff_bytes(&elf64_header(62));
        assert_eq!(elf.object, ObjectKind::Elf);
        assert_eq!(elf.container, ContainerKind::Plain);
        assert_eq!(elf.arch, Some(ArchSpec::x86_64()));
        assert_eq!(elf.entry, Some(0x401000));
        assert_eq!(elf.sections, Some(5));

        let aarch64 = sniff_bytes(&elf64_header(183));
        assert_eq!(aarch64.arch, Some(ArchSpec::aarch64()));

        let unknown = sniff_bytes(&elf64_header(0x9999));
        assert!(unknown.arch.is_none());
        assert!(unknown
            .notes
            .iter()
            .any(|n| n.contains("未识别的 ELF 架构")));

        let pe = sniff_bytes(&pe64());
        assert_eq!(pe.object, ObjectKind::Pe);
        assert_eq!(pe.arch, Some(ArchSpec::x86_64()));
        assert_eq!(pe.image_base, Some(0x1_4000_0000));
        assert_eq!(pe.entry, Some(0x1_4000_1000));
        assert_eq!(pe.sections, Some(3));
        assert!(!pe.notes.iter().any(|n| n.contains("CLI header")));
    }

    #[test]
    fn truncated_and_garbage_are_handled_without_panic() {
        for len in 0..64usize {
            let mut bytes = vec![0u8; len];
            if len >= 4 {
                bytes[0] = b'M';
                bytes[1] = b'Z';
            }
            let g = sniff_bytes(&bytes);
            // MZ 但无 PE 签名 → raw；关键是不 panic。
            assert_eq!(g.object, ObjectKind::Raw);
        }

        let random = sniff_bytes(&[0xde, 0xad, 0xbe, 0xef, 0x00, 0x01]);
        assert_eq!(random.object, ObjectKind::Raw);
        assert!(random.has_notes());

        assert!(sniff_bytes(&[]).has_notes());
    }

    #[test]
    fn ar_members_and_long_names_resolve() {
        let mut archive = Vec::new();
        archive.extend_from_slice(b"!<arch>\n");

        // GNU 长名表：偏移 0 处是 "very_long_object_name.o/\n"
        let long_name = b"very_long_object_name.o/\n";
        archive.extend_from_slice(&ar_member("//", long_name));
        // 成员头名字 "/0" 指向长名表偏移 0；数据是 64 位 ELF 头
        archive.extend_from_slice(&ar_member("/0", &elf64_header(62)));
        archive.extend_from_slice(&ar_member("short.o", b"\x7fELF\x01\x01\x01"));

        let g = sniff_bytes(&archive);
        assert_eq!(g.container, ContainerKind::Ar);
        assert_eq!(g.members.len(), 3);
        assert_eq!(g.members[1].name, "very_long_object_name.o");
        // 成员格式取自**第一个有数据的成员**，而成员 0 是长名表本身。
        // 这里断言语义而不是实现顺序：成员格式必须是 ELF（长名表指向的对象就是 ELF）。
        assert_eq!(g.members[0].name, "//");
        assert_eq!(g.member_kind, Some(ObjectKind::Elf));
        assert_eq!(g.arch, Some(ArchSpec::x86_64()));
        assert!(!g.members_truncated);

        // 成员偏移必须能在原文件里精确定位到成员数据
        for m in &g.members {
            assert!(m.offset + m.size <= archive.len() as u64, "{m:?}");
        }
    }

    #[test]
    fn msvc_lib_detected_by_nul_terminated_name_table() {
        let mut archive = Vec::new();
        archive.extend_from_slice(b"!<arch>\n");
        archive.extend_from_slice(&ar_member("/", &[0u8; 8]));
        archive.extend_from_slice(&ar_member("//", b"a_very_long_msvc_name\0\x00\x00\x00"));
        archive.extend_from_slice(&ar_member("/1", b"\x64\x86\x02\x00"));

        let g = sniff_bytes(&archive);
        assert_eq!(g.container, ContainerKind::MsvcLib);
        assert!(g.notes.iter().any(|n| n.contains("MSVC")));
    }

    #[test]
    fn macho_thin_and_fat_are_distinguished_from_java_class() {
        let mut thin = vec![0u8; 32];
        thin[0..4].copy_from_slice(&0xfeed_facfu32.to_le_bytes()); // 64 位 LE Mach-O
        thin[4..8].copy_from_slice(&0x0100_0007u32.to_le_bytes()); // x86_64
        thin[12..16].copy_from_slice(&2u32.to_le_bytes()); // filetype = executable
        let g = sniff_bytes(&thin);
        assert_eq!(g.object, ObjectKind::MachO);
        assert_eq!(g.arch, Some(ArchSpec::x86_64()));
        assert!(g.notes.iter().any(|n| n.contains("M10")));

        let mut fat = vec![0u8; 32];
        fat[0..4].copy_from_slice(&[0xca, 0xfe, 0xba, 0xbe]);
        fat[4..8].copy_from_slice(&2u32.to_be_bytes());
        fat[8..12].copy_from_slice(&7u32.to_be_bytes()); // CPU_TYPE_X86
        assert_eq!(sniff_bytes(&fat).container, ContainerKind::Fat);

        // Java class：major version 52 → 前 8 字节像 nfat=52，必须被拒。
        let mut java = vec![0u8; 32];
        java[0..4].copy_from_slice(&[0xca, 0xfe, 0xba, 0xbe]);
        java[6..8].copy_from_slice(&52u16.to_be_bytes());
        let j = sniff_bytes(&java);
        assert_ne!(j.container, ContainerKind::Fat);
        assert_eq!(j.object, ObjectKind::Raw);
    }

    #[test]
    fn coff_object_identified() {
        let mut obj = vec![0u8; 40];
        obj[0..2].copy_from_slice(&0x8664u16.to_le_bytes());
        obj[2..4].copy_from_slice(&2u16.to_le_bytes());
        let g = sniff_bytes(&obj);
        assert_eq!(g.object, ObjectKind::Coff);
        assert_eq!(g.arch, Some(ArchSpec::x86_64()));
        assert_eq!(g.sections, Some(2));
    }

    #[test]
    fn sniff_file_reports_directories_and_missing_files() {
        let dir = tempfile::tempdir().expect("tempdir");
        let err = sniff_file(dir.path()).expect_err("目录必须报错");
        assert!(matches!(err, LoaderError::IsDirectory(_)));
        assert!(err.to_string().contains("M10"));

        let missing = dir.path().join("nope.bin");
        let err = sniff_file(&missing).expect_err("不存在的文件必须报错");
        assert!(matches!(err, LoaderError::Io { .. }));
    }

    #[test]
    fn ar_symbol_index_member_is_named_and_not_treated_as_payload() {
        // 真实 GNU 归档的成员 1 名字就是 "/"（符号索引），成员 0（长名表之前）
        // 是它的数据。曾经这里把 "/" 当成"空偏移的长名引用"，导致名字留空、
        // 且把符号索引当成"首个载荷成员"，从而得出"这不是 ELF"。
        let mut archive = Vec::new();
        archive.extend_from_slice(b"!<arch>\n");
        archive.extend_from_slice(&ar_member("/", &[0u8; 16]));
        archive.extend_from_slice(&ar_member("real.o/", &elf64_header(62)));

        let g = sniff_bytes(&archive);
        assert_eq!(g.members.len(), 2);
        assert!(
            g.members[0].name.contains("符号索引"),
            "符号索引成员必须有可读名字，实际 {:?}",
            g.members[0].name
        );
        assert_eq!(g.members[1].name, "real.o");
        assert_eq!(
            g.member_kind,
            Some(ObjectKind::Elf),
            "成员格式必须跳过符号索引后取到真实对象"
        );
        assert_eq!(g.arch, Some(ArchSpec::x86_64()));
    }

    #[test]
    fn ar_member_names_are_trimmed_of_gnu_slash_suffix() {
        let mut archive = Vec::new();
        archive.extend_from_slice(b"!<arch>\n");
        archive.extend_from_slice(&ar_member("mod.o/", &elf64_header(62)));
        let g = sniff_bytes(&archive);
        assert_eq!(g.members[0].name, "mod.o");
    }

    #[test]
    fn bsd_style_inline_name_is_extracted_from_member_data() {
        let payload = elf64_header(62);
        let name = b"bsd_named.o";
        let mut data = name.to_vec();
        data.extend_from_slice(&payload);
        let mut archive = Vec::new();
        archive.extend_from_slice(b"!<arch>\n");
        archive.extend_from_slice(&ar_member(&format!("#1/{}", name.len()), &data));

        let g = sniff_bytes(&archive);
        assert_eq!(g.members.len(), 1);
        assert_eq!(
            g.members[0].name, "bsd_named.o",
            "BSD 内联名必须从载荷里取出，而不是显示成 #1/11"
        );
        // 内联名不计入载荷长度：剩下的才是真正的对象数据
        assert_eq!(g.members[0].size, payload.len() as u64);
        assert_eq!(g.member_kind, Some(ObjectKind::Elf));
    }

    #[test]
    fn sniff_file_reads_and_flags_truncation() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("tiny.elf");
        std::fs::write(&path, elf64_header(62)).expect("write");
        let g = sniff_file(&path).expect("sniff");
        assert_eq!(g.object, ObjectKind::Elf);
        assert_eq!(g.sniffed_bytes, 64);
        assert!(!g.file_truncated);
    }
}
