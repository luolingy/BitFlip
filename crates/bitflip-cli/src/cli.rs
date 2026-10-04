//! 命令行界面定义（clap）。
//!
//! 两个入口共用同一套实现：
//!
//! - `bitflip <target>`（`bitflip-app`）—— 面向交互使用，起服务 + 开浏览器；
//! - `bitflip-cli <info|serve|version>` —— 面向脚本与 CI。

use std::path::PathBuf;

use clap::{Args, Parser, Subcommand};

/// `bitflip` 的交互式入口参数。
#[derive(Debug, Parser)]
#[command(
    name = "bitflip",
    version,
    about = "BitFlip · 比特翻转 —— 静态二进制逆向分析平台（本地 Web UI）",
    long_about = "打开一个可执行文件/动态库/静态库，在本地起 Web 服务并打开浏览器进行静态分析。\n\
                  只绑定回环地址；每次启动生成访问令牌，URL 里会带上。"
)]
pub struct OpenCli {
    /// 目标文件：可执行文件、动态库或静态库/归档
    #[arg(value_name = "TARGET")]
    pub target: PathBuf,

    /// 监听端口（0 = 由系统分配；被占用时自动顺延）
    #[arg(long, default_value_t = 8790, value_name = "PORT")]
    pub port: u16,

    /// 监听地址（默认只绑回环；改成非回环会把分析结果暴露到网络上）
    #[arg(long, default_value = "127.0.0.1", value_name = "ADDR")]
    pub host: String,

    /// 不自动打开浏览器
    #[arg(long)]
    pub no_open: bool,

    /// 固定访问令牌（默认每次启动随机生成）
    #[arg(long, env = "BITFLIP_TOKEN", value_name = "TOKEN")]
    pub token: Option<String>,

    /// 追加允许的 Origin（例如 Vite 开发服务器 http://127.0.0.1:5173）
    #[arg(long = "allow-origin", value_name = "ORIGIN")]
    pub allow_origin: Vec<String>,

    /// 只打印识别结论，不启动服务
    #[arg(long)]
    pub info_only: bool,

    /// 打开调试日志
    #[arg(short, long)]
    pub verbose: bool,

    /// 架构 / 基址覆盖（原始二进制需要）
    #[command(flatten)]
    pub raw: RawOverrideArgs,
}

/// `bitflip-cli` 的无头入口参数。
#[derive(Debug, Parser)]
#[command(
    name = "bitflip-cli",
    version,
    about = "BitFlip 无头命令行（脚本与 CI 用）"
)]
pub struct Cli {
    /// 子命令
    #[command(subcommand)]
    pub command: Command,
}

/// 无头子命令。
#[derive(Debug, Subcommand)]
pub enum Command {
    /// 识别目标格式与架构（不启动服务）
    Info(InfoArgs),
    /// 列出归档成员（静态库 / ar 归档）
    Members(MembersArgs),
    /// 列出识别出的函数
    Functions(FunctionsArgs),
    /// 在目标里定位一个符号（函数名或地址）
    Symbol(SymbolArgs),
    /// 启动本地 Web 服务
    Serve(ServeArgs),
    /// 打印版本与 API 版本
    Version,
}

/// 原始二进制的架构/基址覆盖参数。
///
/// 单独成一个结构体是因为**每个接受目标文件的命令都需要它**：
/// 固件里没有头可读，不给架构就没法反汇编。用 `#[command(flatten)]`
/// 摊平进各个参数结构，命令行上就是每个命令都直接支持 `--arch` / `--base`。
#[derive(Debug, Args, Clone, Default)]
pub struct RawOverrideArgs {
    /// 手工指定架构（原始二进制必须；也用于覆盖嗅探结论）
    #[arg(long, value_name = "ARCH")]
    pub arch: Option<String>,

    /// 手工指定解码模式（arm 上的 thumb、x86 的 16/32/64）
    #[arg(long, value_name = "MODE")]
    pub mode: Option<String>,

    /// 手工指定字节序（little / big）
    #[arg(long, value_name = "ENDIAN")]
    pub endian: Option<String>,

    /// 原始二进制的基址（十六进制，可带 0x）
    #[arg(long, value_name = "ADDR")]
    pub base: Option<String>,

    /// 视作原始二进制：忽略嗅探出的容器与对象格式
    #[arg(long)]
    pub force_raw: bool,
}

impl RawOverrideArgs {
    /// 转成核心层的打开选项。
    ///
    /// 解析失败时**报错**而不是忽略：用户明确敲了 `--arch arm6`，
    /// 悄悄跳过会让工具用错的架构去解码，输出看起来成功但是垃圾。
    pub fn to_open_options(&self) -> anyhow::Result<bitflip_core::OpenOptions> {
        let mut opts = bitflip_core::OpenOptions {
            force_raw: self.force_raw,
            ..Default::default()
        };

        if let Some(text) = &self.arch {
            let arch = parse_arch(text).ok_or_else(|| {
                anyhow::anyhow!(
                    "架构无法识别：{text:?}。可用值：x86、x86_64、aarch64、arm、riscv32、\
                     riscv64、mips、mips64、wasm32"
                )
            })?;
            opts.arch = Some(arch);
        }

        if let Some(text) = &self.mode {
            let mode = parse_mode(text).ok_or_else(|| {
                anyhow::anyhow!("模式无法识别：{text:?}。可用值：16、32、64、thumb")
            })?;
            opts.mode = Some(mode);
        }

        if let Some(text) = &self.endian {
            let endian = match text.to_ascii_lowercase().as_str() {
                "little" | "le" | "l" => bitflip_core::Endian::Little,
                "big" | "be" | "b" => bitflip_core::Endian::Big,
                other => {
                    anyhow::bail!("字节序无法识别：{other:?}。可用值：little、big");
                }
            };
            opts.endian = Some(endian);
        }

        if let Some(text) = &self.base {
            let base = bitflip_core::parse_address(text).ok_or_else(|| {
                anyhow::anyhow!("基址无法解析：{text:?}（十六进制，可带 0x 前缀）")
            })?;
            opts.base_address = Some(base);
        }

        Ok(opts)
    }
}

/// 架构短名 → `Arch`。与 `Arch::as_str` 一一对应。
fn parse_arch(text: &str) -> Option<bitflip_core::Arch> {
    use bitflip_core::Arch;
    Some(match text.to_ascii_lowercase().as_str() {
        "x86" | "i386" | "ia32" => Arch::X86,
        "x86_64" | "x64" | "amd64" => Arch::X86_64,
        "aarch64" | "arm64" => Arch::Aarch64,
        "arm" | "arm32" | "aarch32" => Arch::Arm,
        "riscv32" | "rv32" => Arch::Riscv32,
        "riscv64" | "rv64" => Arch::Riscv64,
        "mips" | "mips32" => Arch::Mips,
        "mips64" => Arch::Mips64,
        "wasm32" | "wasm" => Arch::Wasm32,
        _ => return None,
    })
}

/// 模式短名 → `Mode`。
fn parse_mode(text: &str) -> Option<bitflip_core::Mode> {
    use bitflip_core::Mode;
    Some(match text.to_ascii_lowercase().as_str() {
        "16" | "m16" => Mode::M16,
        "32" | "m32" => Mode::M32,
        "64" | "m64" => Mode::M64,
        "thumb" | "t" => Mode::Thumb,
        _ => return None,
    })
}

/// `members` 参数。
#[derive(Debug, Args)]
pub struct MembersArgs {
    /// 目标文件（归档 / 静态库）
    #[arg(value_name = "TARGET")]
    pub target: PathBuf,
    /// 输出 JSON（稳定的 wire 契约）
    #[arg(long)]
    pub json: bool,
    /// 打开调试日志
    #[arg(short, long)]
    pub verbose: bool,
}

/// `functions` 参数。
#[derive(Debug, Args)]
pub struct FunctionsArgs {
    /// 目标文件；归档可用 `--member` 指定成员
    #[arg(value_name = "TARGET")]
    pub target: PathBuf,
    /// 归档成员名（只分析该成员）
    #[arg(long, value_name = "NAME")]
    pub member: Option<String>,
    /// 只看地址 >= 该值的函数（十六进制，可带 0x）
    #[arg(long, value_name = "ADDR")]
    pub from: Option<String>,
    /// 最多输出多少条
    #[arg(long, default_value_t = 50, value_name = "N")]
    pub count: usize,
    /// 输出 JSON（稳定的 wire 契约）
    #[arg(long)]
    pub json: bool,
    /// 打开调试日志
    #[arg(short, long)]
    pub verbose: bool,
    /// 架构 / 基址覆盖（原始二进制需要）
    #[command(flatten)]
    pub raw: RawOverrideArgs,
}

/// `symbol` 参数。
#[derive(Debug, Args)]
pub struct SymbolArgs {
    /// 目标文件；归档可用 `--member` 指定成员
    #[arg(value_name = "TARGET")]
    pub target: PathBuf,
    /// 要定位的符号：函数名，或十六进制地址
    #[arg(value_name = "QUERY")]
    pub query: String,
    /// 归档成员名（只在该成员里找）
    #[arg(long, value_name = "NAME")]
    pub member: Option<String>,
    /// 输出 JSON（稳定的 wire 契约）
    #[arg(long)]
    pub json: bool,
    /// 打开调试日志
    #[arg(short, long)]
    pub verbose: bool,
    /// 架构 / 基址覆盖（原始二进制需要）
    #[command(flatten)]
    pub raw: RawOverrideArgs,
}

/// `info` 参数。
#[derive(Debug, Args)]
pub struct InfoArgs {
    /// 目标文件
    #[arg(value_name = "TARGET")]
    pub target: PathBuf,
    /// 输出 JSON（稳定的 wire 契约）
    #[arg(long)]
    pub json: bool,
    /// 打开调试日志
    #[arg(short, long)]
    pub verbose: bool,
    /// 架构 / 基址覆盖（原始二进制需要）
    #[command(flatten)]
    pub raw: RawOverrideArgs,
}

/// `serve` 参数。
#[derive(Debug, Args)]
pub struct ServeArgs {
    /// 目标文件
    #[arg(value_name = "TARGET")]
    pub target: PathBuf,
    /// 监听端口
    #[arg(long, default_value_t = 8790, value_name = "PORT")]
    pub port: u16,
    /// 监听地址
    #[arg(long, default_value = "127.0.0.1", value_name = "ADDR")]
    pub host: String,
    /// 不自动打开浏览器
    #[arg(long)]
    pub no_open: bool,
    /// 固定访问令牌
    #[arg(long, env = "BITFLIP_TOKEN", value_name = "TOKEN")]
    pub token: Option<String>,
    /// 追加允许的 Origin
    #[arg(long = "allow-origin", value_name = "ORIGIN")]
    pub allow_origin: Vec<String>,
    /// 打开调试日志
    #[arg(short, long)]
    pub verbose: bool,
    /// 架构 / 基址覆盖（原始二进制需要）
    #[command(flatten)]
    pub raw: RawOverrideArgs,
}

#[cfg(test)]
mod tests {
    use super::*;
    use clap::CommandFactory;

    #[test]
    fn cli_definitions_are_valid() {
        OpenCli::command().debug_assert();
        Cli::command().debug_assert();
    }

    #[test]
    fn gui_defaults_are_loopback_and_ephemeral_friendly() {
        let cli = OpenCli::try_parse_from(["bitflip", "sample.exe"]).expect("解析");
        assert_eq!(cli.host, "127.0.0.1");
        assert_eq!(cli.port, 8790);
        assert!(!cli.no_open);
        assert!(!cli.info_only);
        assert!(cli.token.is_none());
    }

    #[test]
    fn subcommands_parse() {
        let cli = Cli::try_parse_from(["bitflip-cli", "info", "a.dll", "--json"]).expect("解析");
        match cli.command {
            Command::Info(args) => {
                assert!(args.json);
                assert_eq!(args.target.to_string_lossy(), "a.dll");
            }
            other => panic!("期望 info，得到 {other:?}"),
        }

        let cli = Cli::try_parse_from([
            "bitflip-cli",
            "serve",
            "libfoo.a",
            "--port",
            "0",
            "--allow-origin",
            "http://127.0.0.1:5173",
        ])
        .expect("解析");
        match cli.command {
            Command::Serve(args) => {
                assert_eq!(args.port, 0);
                assert_eq!(args.allow_origin, vec!["http://127.0.0.1:5173"]);
            }
            other => panic!("期望 serve，得到 {other:?}"),
        }
    }

    /// M5 的三个成员/符号子命令必须能解析，且默认值不吓人。
    #[test]
    fn member_commands_parse() {
        let cli =
            Cli::try_parse_from(["bitflip-cli", "members", "libfoo.a"]).expect("解析 members");
        match cli.command {
            Command::Members(args) => {
                assert_eq!(args.target.to_string_lossy(), "libfoo.a");
                assert!(!args.json);
            }
            other => panic!("期望 members，得到 {other:?}"),
        }

        let cli = Cli::try_parse_from([
            "bitflip-cli",
            "functions",
            "libfoo.a",
            "--member",
            "foo.o",
            "--count",
            "5",
        ])
        .expect("解析 functions");
        match cli.command {
            Command::Functions(args) => {
                assert_eq!(args.member.as_deref(), Some("foo.o"));
                assert_eq!(args.count, 5);
                // 不指定 --from 时不该过滤掉任何地址
                assert!(args.from.is_none());
            }
            other => panic!("期望 functions，得到 {other:?}"),
        }

        // `symbol` 的查询是位置参数（既可能是名字也可能是地址）
        let cli = Cli::try_parse_from(["bitflip-cli", "symbol", "libfoo.a", "bf_add"])
            .expect("解析 symbol");
        match cli.command {
            Command::Symbol(args) => {
                assert_eq!(args.query, "bf_add");
                assert!(args.member.is_none());
            }
            other => panic!("期望 symbol，得到 {other:?}"),
        }
    }

    /// 缺少必需参数时必须报错，而不是静默用默认值。
    #[test]
    fn symbol_requires_a_query() {
        let result = Cli::try_parse_from(["bitflip-cli", "symbol", "libfoo.a"]);
        assert!(
            result.is_err(),
            "symbol 缺少 QUERY 应当解析失败，而不是拿空字符串去搜"
        );
    }
}
