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

    /// 该架构最常用的解码模式。
    ///
    /// 只在**用户手工指定架构、却没指定模式**时用作兜底：`ArchSpec` 要求
    /// 模式必填（Thumb 与 ARM 是同一个架构的两套编码，没有模式就选不出
    /// 解码器）。这里的取值是"该架构最常见的那一种"，不是"唯一正确的"，
    /// 所以调用方把它用进猜测时应当说明这是默认值。
    ///
    /// ARM 取 ARM 状态而不是 Thumb：`Arch::Arm` 这个枚举值字面上就是
    /// ARM 状态；Thumb 需要用户显式说 `Mode::Thumb`。
    pub const fn default_mode(self) -> Mode {
        match self {
            Self::X86 => Mode::M32,
            Self::X86_64 | Self::Aarch64 | Self::Riscv64 | Self::Mips64 => Mode::M64,
            Self::Arm | Self::Riscv32 | Self::Mips | Self::Wasm32 => Mode::M32,
        }
    }

    /// 该架构**惯用**的字节序。
    ///
    /// 只有同时支持两种端序的架构（MIPS、ARM、RISC-V）才有真正的选择余地；
    /// 这里给的始终是**该架构最常见的那一种**，不是"唯一正确的"。
    /// 只在"用户手工指定了架构却没说端序"时用作兜底 ——
    /// 要按少见的那种解，必须由用户显式说 `--endian`。
    ///
    /// 这个函数存在的理由不只是方便：它是 M5 分层闸门
    /// （`scripts/check-arch-layering.ps1`）要求的那道边界。
    /// 端序判断属于架构知识，`bitflip-core` 这类架构无关的代码不该自己写
    /// `Endian::Little` —— 否则"哪个架构是小端"这件事就散落到全仓库了。
    ///
    /// 目前所有已支持架构的工具链默认都是小端，所以这里还没有分支；
    /// 真要区分时（例如把 MIPS 大端固件作为一等场景），改的应该是**这一个**
    /// 函数，而不是去调用方找散落的 `Endian::Little`。
    #[must_use]
    pub const fn preferred_endian(self) -> Endian {
        Endian::Little
    }

    /// 用户只给了架构、没给模式与端序时用的完整规格。
    ///
    /// 这是"给一个架构就能开始解码"的唯一入口：模式取
    /// [`Arch::default_mode`]，端序取 [`Arch::preferred_endian`]。
    #[must_use]
    pub const fn default_spec(self) -> ArchSpec {
        ArchSpec::from_arch(self, self.default_mode(), self.preferred_endian())
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

    /// 是否小端。
    ///
    /// 给"把目标端序翻译成别的库的端序枚举"这类消费方用：下游拿到的应当是
    /// 一个**值**，而不是自己去 `match` 端序变体 —— 那样端序知识会散到各层，
    /// 与架构知识被门禁挡住的理由完全一样（见 scripts/check-arch-layering.ps1）。
    pub const fn is_little(self) -> bool {
        matches!(self, Self::Little)
    }

    /// 是否大端。
    pub const fn is_big(self) -> bool {
        matches!(self, Self::Big)
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

    /// `default_spec` 是"只给一个架构就能开始解码"的唯一入口。
    ///
    /// 它存在的意义是分层：M5 闸门禁止 `bitflip-core` 自己写
    /// `Endian::Little` 或 `Mode::M64`，那些判断必须落在这里。
    #[test]
    fn default_spec_picks_a_usable_mode_and_endian() {
        assert_eq!(Arch::X86_64.default_spec().to_string(), "x86_64/64/le");
        assert_eq!(Arch::Aarch64.default_spec().to_string(), "aarch64/64/le");
        assert_eq!(Arch::X86.default_spec().to_string(), "x86/32/le");
        assert_eq!(Arch::Riscv32.default_spec().to_string(), "riscv32/32/le");
        assert_eq!(Arch::Mips64.default_spec().to_string(), "mips64/64/le");
    }

    /// ARM 的默认模式必须是 **ARM 状态**而不是 Thumb。
    ///
    /// 这是一个容易搞错的点：Cortex-M 固件大多是 Thumb，但
    /// `Arch::Arm` 这个枚举值字面上就是 ARM 状态。替用户"猜到 Thumb"
    /// 会解出一堆错指令；要 Thumb 必须显式说 `--mode thumb`。
    #[test]
    fn arm_defaults_to_arm_state_not_thumb() {
        assert_eq!(Arch::Arm.default_mode(), Mode::M32);
        assert_eq!(Arch::Arm.default_spec().to_string(), "arm/32/le");
    }

    /// 指针宽度跟着模式走：同一个架构在不同模式下宽度不同。
    #[test]
    fn default_spec_ptr_size_is_consistent_with_mode() {
        for arch in [Arch::X86_64, Arch::Aarch64, Arch::Riscv64, Arch::Mips64] {
            let spec = arch.default_spec();
            assert_eq!(spec.ptr_size, 8, "{arch} 应是 64 位");
            assert!(spec.is_64bit());
        }
        for arch in [Arch::X86, Arch::Arm, Arch::Riscv32, Arch::Mips] {
            let spec = arch.default_spec();
            assert_eq!(spec.ptr_size, 4, "{arch} 应是 32 位");
            assert!(!spec.is_64bit());
        }
    }
}
