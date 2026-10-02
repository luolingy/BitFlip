//! 架构、模式与端序的基础类型，以及各目标格式 machine 编号到架构的映射表。

use core::fmt;

/// 指令集架构。
///
/// `#[non_exhaustive]`：新增架构不属于破坏性变更，但下游 `match` 必须留兜底分支。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
#[non_exhaustive]
pub enum Arch {
    /// Intel 8086/80386 系列（16/32 位模式）。
    X86,
    /// AMD64 / Intel 64。
    X86_64,
    /// AArch64 (ARMv8-A 64 位)。
    Aarch64,
    /// AArch32：ARM 状态与 Thumb 状态共用，由 [`Mode`] 区分。
    Arm,
    /// RISC-V RV32。
    Riscv32,
    /// RISC-V RV64。
    Riscv64,
    /// MIPS32。
    Mips,
    /// MIPS64。
    Mips64,
    /// WebAssembly（M10 目标）。
    Wasm32,
}

impl Arch {
    /// 稳定的短名，用于 CLI / JSON / UI。
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::X86 => "x86",
            Self::X86_64 => "x86_64",
            Self::Aarch64 => "aarch64",
            Self::Arm => "arm",
            Self::Riscv32 => "riscv32",
            Self::Riscv64 => "riscv64",
            Self::Mips => "mips",
            Self::Mips64 => "mips64",
            Self::Wasm32 => "wasm32",
        }
    }

    /// 该架构在给定模式下的默认指针宽度（字节）。
    pub const fn ptr_size(self, mode: Mode) -> u8 {
        match self {
            Self::X86 => {
                if let Mode::M16 = mode {
                    2
                } else {
                    4
                }
            }
            Self::X86_64 | Self::Aarch64 | Self::Riscv64 | Self::Mips64 | Self::Wasm32 => 8,
            _ => 4,
        }
    }

    /// ELF `e_machine` → 架构。`is_64` 用于区分 RV32/RV64、MIPS32/64 这类共用编号的架构。
    pub const fn from_elf_machine(machine: u16, is_64: bool) -> Option<Self> {
        Some(match machine {
            3 => Self::X86, // EM_386
            8 => {
                if is_64 {
                    Self::Mips64
                } else {
                    Self::Mips
                }
            }
            40 => Self::Arm,      // EM_ARM
            62 => Self::X86_64,   // EM_X86_64
            183 => Self::Aarch64, // EM_AARCH64
            243 => {
                if is_64 {
                    Self::Riscv64
                } else {
                    Self::Riscv32
                } // EM_RISCV
            }
            415 => Self::Wasm32, // EM_WEBASSEMBLY
            _ => return None,
        })
    }

    /// PE/COFF `Machine` → 架构与解码模式。
    pub const fn from_pe_machine(machine: u16) -> Option<(Self, Mode)> {
        Some(match machine {
            0x014c => (Self::X86, Mode::M32),     // IMAGE_FILE_MACHINE_I386
            0x8664 => (Self::X86_64, Mode::M64),  // IMAGE_FILE_MACHINE_AMD64
            0x01c0 => (Self::Arm, Mode::M32),     // IMAGE_FILE_MACHINE_ARM
            0x01c4 => (Self::Arm, Mode::Thumb),   // IMAGE_FILE_MACHINE_ARMNT
            0xaa64 => (Self::Aarch64, Mode::M64), // IMAGE_FILE_MACHINE_ARM64
            0x5032 => (Self::Riscv32, Mode::M32), // IMAGE_FILE_MACHINE_RISCV32
            0x5064 => (Self::Riscv64, Mode::M64), // IMAGE_FILE_MACHINE_RISCV64
            _ => return None,
        })
    }

    /// Mach-O `cputype` → 架构与模式（仅识别用，Mach-O 解析推迟到 M10）。
    pub const fn from_macho_cputype(cputype: u32) -> Option<(Self, Mode)> {
        Some(match cputype {
            7 => (Self::X86, Mode::M32),               // CPU_TYPE_X86
            0x0100_0007 => (Self::X86_64, Mode::M64),  // CPU_TYPE_X86_64
            12 => (Self::Arm, Mode::M32),              // CPU_TYPE_ARM
            0x0100_000c => (Self::Aarch64, Mode::M64), // CPU_TYPE_ARM64
            _ => return None,
        })
    }
}

impl fmt::Display for Arch {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// 解码模式。同一架构可有多种模式（x86 的 16/32/64 位、ARM 的 ARM/Thumb 状态）。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Mode {
    /// 16 位模式（实模式 / 16 位代码段）。
    M16,
    /// 32 位模式（含 AArch32 的 ARM 状态、RV32）。
    M32,
    /// 64 位模式（含 AArch64、RV64）。
    M64,
    /// Thumb 状态（AArch32）。
    Thumb,
}

impl Mode {
    /// 稳定的短名。
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::M16 => "16",
            Self::M32 => "32",
            Self::M64 => "64",
            Self::Thumb => "thumb",
        }
    }
}

impl fmt::Display for Mode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// 字节序。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Endian {
    /// 小端。
    Little,
    /// 大端。
    Big,
}

impl Endian {
    /// 稳定的短名（`le` / `be`）。
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Little => "le",
            Self::Big => "be",
        }
    }
}

impl fmt::Display for Endian {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// 架构规格：架构 + 模式 + 端序 + 指针宽度。
///
/// 这是跨 crate 传递的"架构身份"，不允许用 `(String, u8)` 之类的松散元组代替。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct ArchSpec {
    /// 指令集架构。
    pub arch: Arch,
    /// 解码模式。
    pub mode: Mode,
    /// 字节序。
    pub endian: Endian,
    /// 指针宽度（字节）。
    pub ptr_size: u8,
}

impl ArchSpec {
    /// 由架构与模式推导指针宽度。
    #[must_use]
    pub const fn from_arch(arch: Arch, mode: Mode, endian: Endian) -> Self {
        Self {
            arch,
            mode,
            endian,
            ptr_size: arch.ptr_size(mode),
        }
    }

    /// x86_64 System V / Windows 通用规格。
    #[must_use]
    pub const fn x86_64() -> Self {
        Self::from_arch(Arch::X86_64, Mode::M64, Endian::Little)
    }

    /// AArch64 规格。
    #[must_use]
    pub const fn aarch64() -> Self {
        Self::from_arch(Arch::Aarch64, Mode::M64, Endian::Little)
    }

    /// 指针是否为 64 位。
    #[must_use]
    pub const fn is_64bit(&self) -> bool {
        self.ptr_size == 8
    }
}

impl fmt::Display for ArchSpec {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{}/{}/{}",
            self.arch.as_str(),
            self.mode.as_str(),
            self.endian.as_str()
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn elf_machine_maps_to_arch() {
        assert_eq!(Arch::from_elf_machine(62, true), Some(Arch::X86_64));
        assert_eq!(Arch::from_elf_machine(3, false), Some(Arch::X86));
        assert_eq!(Arch::from_elf_machine(183, true), Some(Arch::Aarch64));
        assert_eq!(Arch::from_elf_machine(243, true), Some(Arch::Riscv64));
        assert_eq!(Arch::from_elf_machine(243, false), Some(Arch::Riscv32));
        assert_eq!(Arch::from_elf_machine(0xffff, true), None);
    }

    #[test]
    fn pe_machine_maps_to_arch_and_mode() {
        assert_eq!(
            Arch::from_pe_machine(0x8664),
            Some((Arch::X86_64, Mode::M64))
        );
        assert_eq!(Arch::from_pe_machine(0x014c), Some((Arch::X86, Mode::M32)));
        assert_eq!(
            Arch::from_pe_machine(0xaa64),
            Some((Arch::Aarch64, Mode::M64))
        );
        assert_eq!(Arch::from_pe_machine(0x1234), None);
    }

    #[test]
    fn ptr_size_follows_mode() {
        let spec = ArchSpec::from_arch(Arch::X86, Mode::M16, Endian::Little);
        assert_eq!(spec.ptr_size, 2);
        assert!(!spec.is_64bit());
        assert_eq!(ArchSpec::x86_64().to_string(), "x86_64/64/le");
        assert_eq!(ArchSpec::aarch64().to_string(), "aarch64/64/le");
    }
}
