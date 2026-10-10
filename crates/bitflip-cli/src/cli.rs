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
    /// 签名库：从静态库生成签名文件、查看签名文件
    Signature(SignatureArgs),
    /// 导出分析结论（反汇编 / 函数清单 / 符号表 / 交叉引用 / CFG）
    Export(ExportArgs),
    /// 启动本地 Web 服务
    Serve(ServeArgs),
    /// 打印版本与 API 版本
    Version,
}

/// 打开目标时的通用输入参数。
///
/// 单独成一个结构体是因为**每个接受目标文件的命令都需要它**：
/// 固件里没有头可读，不给架构就没法反汇编；剥离过的目标不给签名库就没有名字。
/// 用 `#[command(flatten)]` 摊平进各个参数结构，命令行上就是每个命令都直接支持
/// `--arch` / `--base` / `--signatures`。
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

    /// 签名库文件（`signature build` 的产物）：给剥离过的目标找回函数名
    ///
    /// 只做字节比对，不认识架构、不联网。文件读不出或版本不符会**直接报错**，
    /// 不会静默跳过 —— 否则"给了签名库却什么都没认出来"会被误解成库不够全。
    #[arg(long, value_name = "FILE")]
    pub signatures: Option<PathBuf>,
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

        if let Some(path) = &self.signatures {
            opts.signatures = Some(path.clone());
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

/// `signature` 参数。
#[derive(Debug, Args)]
pub struct SignatureArgs {
    /// 子命令
    #[command(subcommand)]
    pub command: SignatureCommand,
}

/// `signature` 的子命令。
#[derive(Debug, Subcommand)]
pub enum SignatureCommand {
    /// 从静态库 / 目标文件生成签名文件
    Build(SignatureBuildArgs),
    /// 查看签名文件的内容与来源
    Info(SignatureInfoArgs),
}

/// `signature build` 参数。
#[derive(Debug, Args)]
pub struct SignatureBuildArgs {
    /// 输入：静态库（`.a` / `.lib`）或可重定位目标文件，可给多个
    #[arg(value_name = "INPUT", required = true)]
    pub inputs: Vec<PathBuf>,
    /// 输出签名文件路径
    #[arg(long, value_name = "FILE")]
    pub out: PathBuf,
    /// 覆盖已存在的签名文件
    ///
    /// 默认拒绝覆盖：签名文件是用户自己攒的资产，被一次手滑的命令清掉
    /// 没有任何地方能恢复。要覆盖就明说。
    #[arg(long)]
    pub force: bool,
    /// 输出 JSON（稳定的 wire 契约）
    #[arg(long)]
    pub json: bool,
}

/// `signature info` 参数。
#[derive(Debug, Args)]
pub struct SignatureInfoArgs {
    /// 签名文件
    #[arg(value_name = "FILE")]
    pub file: PathBuf,
    /// 最多列出多少个名字（0 = 不列）
    #[arg(long, default_value_t = 20, value_name = "N")]
    pub count: usize,
    /// 输出 JSON（稳定的 wire 契约）
    #[arg(long)]
    pub json: bool,
}

/// `export` 参数。
///
/// 这一层只做参数解析与 IO；格式与内容全在 `bitflip_core::export` 里，
/// 服务端同一路径。**不要让 CLI 自己拼文本** —— 那早晚会和界面漂移。
#[derive(Debug, Args)]
pub struct ExportArgs {
    /// 目标文件；归档可用 `--member` 指定成员
    #[arg(value_name = "TARGET")]
    pub target: PathBuf,
    /// 导出格式：asm-intel、asm-att、json-functions、json-symbols、json-xrefs、dot-cfg
    #[arg(long, value_name = "FORMAT", default_value = "asm-intel")]
    pub format: String,
    /// 输出文件；缺省写标准输出
    #[arg(long, value_name = "FILE")]
    pub out: Option<PathBuf>,
    /// 起始地址（含；十六进制，可带 0x）
    #[arg(long, value_name = "ADDR")]
    pub from: Option<String>,
    /// 结束地址（不含；十六进制，可带 0x）
    #[arg(long, value_name = "ADDR")]
    pub to: Option<String>,
    /// 只导出这一个函数（入口地址；十六进制，可带 0x）
    ///
    /// 与 `--from/--to` 互斥：两者都要就没有"哪个更具体"的合理答案。
    #[arg(long, value_name = "ADDR")]
    pub function: Option<String>,
    /// 反汇编文本不带机器码列
    #[arg(long)]
    pub no_bytes: bool,
    /// 反汇编文本不带源位置列
    #[arg(long)]
    pub no_source: bool,
    /// DOT 最多画多少个函数的 CFG
    #[arg(long, default_value_t = 512, value_name = "N")]
    pub max_functions: usize,
    /// 字节上限（0 = 不限制）
    ///
    /// 默认 32 MiB 是为了"别把内存吃光"，不是为了限制导出能力：
    /// 要全量就调大它，或按地址段分批（截断时报告里会这么说）。
    #[arg(long, value_name = "BYTES")]
    pub limit_bytes: Option<u64>,
    /// 覆盖已存在的输出文件
    ///
    /// 默认拒绝覆盖：导出文件可能是别人拿去继续加工的资料，
    /// 被一次手滑的命令清掉没有地方能恢复。要覆盖就明说。
    #[arg(long)]
    pub force: bool,
    /// 只打印摘要（写了多少、是否截断），不打印正文
    #[arg(long)]
    pub summary: bool,
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

    /// `signature` 的两个子命令必须能解析；`--out` 是必需的。
    #[test]
    fn signature_commands_parse() {
        let cli = Cli::try_parse_from([
            "bitflip-cli",
            "signature",
            "build",
            "libgcc.a",
            "libmingw32.a",
            "--out",
            "mingw.sig.json",
        ])
        .expect("解析 signature build");
        match cli.command {
            Command::Signature(args) => match args.command {
                SignatureCommand::Build(build) => {
                    assert_eq!(build.inputs.len(), 2);
                    assert_eq!(build.out.to_string_lossy(), "mingw.sig.json");
                    // 默认拒绝覆盖：用户攒的签名文件不该被一次手滑清掉。
                    assert!(!build.force);
                    assert!(!build.json);
                }
                other => panic!("期望 build，得到 {other:?}"),
            },
            other => panic!("期望 signature，得到 {other:?}"),
        }

        let cli = Cli::try_parse_from([
            "bitflip-cli",
            "signature",
            "info",
            "mingw.sig.json",
            "--count",
            "5",
        ])
        .expect("解析 signature info");
        match cli.command {
            Command::Signature(args) => match args.command {
                SignatureCommand::Info(info) => {
                    assert_eq!(info.file.to_string_lossy(), "mingw.sig.json");
                    assert_eq!(info.count, 5);
                }
                other => panic!("期望 info，得到 {other:?}"),
            },
            other => panic!("期望 signature，得到 {other:?}"),
        }
    }

    /// 没给 `--out` 时不能"随便找个地方写"。
    #[test]
    fn signature_build_requires_an_output_path() {
        let result = Cli::try_parse_from(["bitflip-cli", "signature", "build", "libgcc.a"]);
        assert!(
            result.is_err(),
            "signature build 缺少 --out 应当解析失败，而不是默认写到当前目录"
        );
        let result = Cli::try_parse_from(["bitflip-cli", "signature", "build", "--out", "x.json"]);
        assert!(
            result.is_err(),
            "signature build 缺少输入应当解析失败，而不是产出空文件"
        );
    }

    /// M9：`export` 必须能解析，且默认值是**有界**的。
    #[test]
    fn export_command_parses_with_bounded_defaults() {
        let cli =
            Cli::try_parse_from(["bitflip-cli", "export", "target.exe"]).expect("解析 export");
        match cli.command {
            Command::Export(args) => {
                assert_eq!(args.target.to_string_lossy(), "target.exe");
                // 默认格式是反汇编：导出最常用的就是它。
                assert_eq!(args.format, "asm-intel");
                // 缺省写标准输出（管道里好用），不偷偷写文件。
                assert!(args.out.is_none());
                // 缺省不覆盖任何东西（没有 --out 也就无从覆盖）。
                assert!(!args.force);
                // 预算缺省交由核心层决定（有界），CLI 不重复写一个数字。
                assert!(args.limit_bytes.is_none());
                assert!(!args.no_bytes);
                assert_eq!(args.max_functions, 512);
                assert!(args.from.is_none() && args.to.is_none() && args.function.is_none());
            }
            other => panic!("期望 export，得到 {other:?}"),
        }

        let cli = Cli::try_parse_from([
            "bitflip-cli",
            "export",
            "target.exe",
            "--format",
            "dot-cfg",
            "--out",
            "cfg.dot",
            "--from",
            "0x401000",
            "--to",
            "0x402000",
            "--limit-bytes",
            "1048576",
            "--no-bytes",
            "--no-source",
            "--max-functions",
            "8",
            "--summary",
            "--force",
        ])
        .expect("解析 export 全参数");
        match cli.command {
            Command::Export(args) => {
                assert_eq!(args.format, "dot-cfg");
                assert_eq!(args.out.as_ref().expect("out").to_string_lossy(), "cfg.dot");
                assert_eq!(args.from.as_deref(), Some("0x401000"));
                assert_eq!(args.to.as_deref(), Some("0x402000"));
                assert_eq!(args.limit_bytes, Some(1_048_576));
                assert!(args.no_bytes && args.no_source);
                assert_eq!(args.max_functions, 8);
                assert!(args.summary && args.force);
            }
            other => panic!("期望 export，得到 {other:?}"),
        }
    }

    /// `export` 缺 TARGET 必须解析失败，而不是拿空路径去开文件。
    #[test]
    fn export_requires_a_target() {
        assert!(
            Cli::try_parse_from(["bitflip-cli", "export"]).is_err(),
            "export 缺少 TARGET 应当解析失败"
        );
    }
}
