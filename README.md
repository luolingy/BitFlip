# BitFlip · 比特翻转

> 本地优先、跨平台的静态二进制逆向分析平台 —— 单文件可执行 + 本地 Web UI。

BitFlip 面向可执行文件、动态库与静态库的静态逆向分析：PE（exe/dll/sys/obj/lib）、
ELF（exec/so/o/a）、raw 固件镜像，以及 x86/x64/ARM64/ARM/RISC-V/MIPS 等架构的指令解码。
打开方式是 `bitflip <target>`，它在 `127.0.0.1` 上启动本地 HTTP 服务并用浏览器打开 UI ——
UI 走 Web 是为了跨平台，不需要为每个平台维护原生 GUI 外壳。

**状态：M0 已完成（骨架可用）。** 现在能做的事：

- 打开目标、识别容器/对象格式/架构/入口点（PE、COFF、ELF、ar 与 MSVC `.lib`、raw；Mach-O 仅识别）；
- 起来一个本地服务，浏览器里能看到目标信息与三栏界面骨架；
- 其余能力（解码、函数识别、交叉引用、注释持久化……）按里程碑推进，**界面上未实现的入口一律置灰并标注里程碑**。

## 快速开始

```bash
cargo build --release -p bitflip-app

# 起服务并打开浏览器（默认 127.0.0.1:8790，端口占用自动顺延）
./target/release/bitflip path/to/sample.exe

# 只想看识别结论
./target/release/bitflip --info-only path/to/sample.exe
./target/release/bitflip-cli info path/to/libfoo.a --json
```

前端资源是可选的：仓库里保留了 `web/dist/.gitkeep`，所以**没构建过前端也能编译并运行**，
此时页面是一份说明如何构建前端的占位页。要看到真正的界面：

```bash
cd web && npm install --cache .npm-cache && npm run build && cd ..
cargo build --release -p bitflip-app
```

本机（Windows 沙箱）特有的两条约束：所有 cargo 命令走 `./scripts/cargo.ps1`（它把 `CARGO_HOME`
指向仓库内），npm 必须带 `--cache .npm-cache`（C: 盘空间不足）。原因见 `docs/DECISIONS.md` ADR-0008/0009。

## 安全模型

BitFlip 是本地工具，不是网络服务：只绑回环地址；每次启动生成 32 字节随机令牌
（终端打印的 URL 里带 `#token=…`，前端取到后立刻从地址栏擦掉）；
API 同时校验令牌与 `Origin`，挡住"恶意网页在用户浏览器里偷打本机 API"这类请求。
`--host 0.0.0.0` 能做，但会有明确警告。

## 文档

| 文档 | 内容 |
|------|------|
| [docs/PLAN.md](docs/PLAN.md) | 长期计划：里程碑 M0–M10、验收标准、性能预算、风险登记 |
| [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md) | 架构：crate 布局、数据模型、HTTP/WS 协议、存储设计 |
| [docs/DECISIONS.md](docs/DECISIONS.md) | 已定决策（ADR）与待决决策门 |
| [CLAUDE.md](CLAUDE.md) | 仓库规则：硬约束、语言、构建、提交前自检 |
| [web/README.md](web/README.md) | 前端构建与开发模式 |

## 目录结构

```
crates/
  bitflip-core/     引擎门面 —— 唯一对外稳定 API（可被其他项目作为子模块/依赖嵌入）
  bitflip-loader/   容器与对象格式：PE/COFF、ELF、ar/.lib、raw
  bitflip-arch/     指令解码与架构描述（ABI、寄存器、调用约定）
  bitflip-analyze/  分析流水线：作业、进度、取消、阶段 S1–S9
  bitflip-symbols/  符号来源与优先级（符号表、导出、unwind、DWARF/PDB、签名库）
  bitflip-project/  工程库（可写）：用户标注为主数据，分析结果为可重建派生物
  bitflip-server/   本地 HTTP/WS 服务 + 内嵌 SPA
  bitflip-cli/      CLI 实现（`bitflip` 与 `bitflip-cli` 共用）
  bitflip-app/      单二进制入口
web/                SPA：TypeScript + React + Vite
scripts/            构建/代理/样本生成/预检脚本
tests/fixtures/     样本生成脚本（样本不入库，按需生成）
```

## 开发

```powershell
& .\scripts\preflight.ps1     # fmt + clippy -D warnings + test + temp/ 守卫
& .\scripts\gen-fixtures.ps1  # 生成本地样本（不入库）
```

提交前自检清单见 `CLAUDE.md` §5。

## 免责声明

BitFlip 是静态分析工具，不执行目标代码。仅用于你拥有或已获授权分析的二进制。

## License

MIT OR Apache-2.0 双许可（见 `LICENSE-MIT`、`LICENSE-APACHE` 与 `docs/DECISIONS.md` ADR-0007）。
