# BitFlip · 比特翻转

> 本地优先、跨平台的静态二进制逆向分析平台 —— 单文件可执行 + 本地 Web UI。

BitFlip 面向可执行文件、动态库与静态库的静态逆向分析：PE（exe/dll/sys/obj/lib）、
ELF（exec/so/o/a）、raw 固件镜像，以及 x86/x64/ARM64/ARM/RISC-V/MIPS 等架构的指令解码。
打开方式是 `bitflip <target>`，它在 `127.0.0.1` 上启动本地 HTTP 服务并用浏览器打开 UI ——
UI 走 Web 是为了跨平台，不需要为每个平台维护原生 GUI 外壳。

**状态：M2 已完成（能反汇编并诚实地标注可信度）。** 现在能做的事：

- 打开目标、识别容器/对象格式/架构/入口点（PE、COFF、ELF、ar 与 MSVC `.lib`、raw；Mach-O 仅识别）；
- **完整解析 ELF32/64 与 PE32/PE32+**：段表、节表、导入表、导出表、符号表、重定位、`.pdata`、
  `.NET` CLI 头（仅识别）、架构相关标志位；
- **`bitflip info <目标>`**：人类可读的段/节/导入/导出清单，或 `--json` 拿到带版本号的稳定 schema；
- **浏览器里的段/节结构视图**：段（内存视角）与节（文件视角）分页签，含虚拟地址、文件偏移、
  权限、内容类别、是否映射，并高亮入口点所在的节；
- 解析失败**不会**让目标打不开：识别结论照常显示，失败原因写在说明里；
- **DEX 视图（CLI `bitflip-cli dex <APK|.dex>`、网页 `DEX` 视图；APK/DEX 里程碑的 M2b）**：
  按 smali 标识列类的方法（`--class 'Lcom/example/Foo;'`）、打印一个方法的指令与文本 CFG
  （`--method 'Lcom/example/Foo;->bar(I)V'`）；`--list-classes` / `--search <子串>`
  列出并**子串**查找类（大小写不敏感，`--search` 隐含列表 —— 混淆过的
  `L_COROUTINE/…;` 没法手打），输出给出"扫描 / 匹配 / 列出"三个数，搜不到是合法答案。
  符号解析默认开启；`--no-symbols` 输出原始池下标并把"已关闭"写进报告；`--json` 给带
  版本号的稳定契约。APK 里有多个 DEX 时按成员名区分（`classes.dex` / `classes2.dex` …）。
  **网页端同能力**：左侧导航的 `DEX` 视图对每个 `classes*.dex` 开一个标签页（按文件名），
  类列表可搜索分页，钻到类详情（字段 / 方法）与方法详情（指令表 + 整个方法的文本 CFG）；
  每个标签页下只挂它自己的解析说明（降级跟着来源走），"没有字节码"（抽象 / `native`
  方法）会写清是合法结论。**选中的标签页 / 类 / 方法 / 搜索词保存在 URL 的 hash 里**，
  刷新不丢、链接可分享（`#dex=1&member=classes.dex&class=…&method=…`）。
  DEX 也进 `export`（M2c）：`--format dex-json` / `dex-smali` / `dex-dot-cfg`，
  选择器 `--member` / `--class` / `--search` / `--method`，用机器码格式名导 DEX
  会**报错**（DEX 没有线性地址空间，详见 `docs/APK-DEX-DESIGN.md` §M2c、ADR-0021）。
  其余能力（解码、函数识别、交叉引用、注释持久化……）按里程碑推进，
  **界面上未实现的入口一律置灰并标注里程碑**。

- **反汇编视图**：x86 / x86-64 / AArch64 / ARM / RISC-V / MIPS 的真实解码，
  虚拟滚动的指令列表，`j`/`k`/`g`/`G`/`Enter` 键盘导航，点击地址跟随跳转，
  机器码与流程类型分列；
- **反汇编的可信度是分层的**：线性扫描覆盖全部字节（会把数据误当指令），
  递归下降只覆盖从入口点/导出/函数符号可达的部分。两条路径的结果分别统计，
  界面上把"仅线性覆盖"的行调暗 —— 不假装它们同样可信；

解析结果的正确性由 `scripts/verify-elf.ps1` 对照 `llvm-readobj` 逐项校验，
并由结构化模糊测试保证畸形输入只返回错误、绝不 panic。
反汇编链路另有 13 个跑在真实 fixture（ELF `.o`/`.exe`/`.so`、PE `.exe`、AArch64）上的端到端测试。

## 快速开始

```bash
cargo build --release -p bitflip-app

# 起服务并打开浏览器（默认 127.0.0.1:8790，端口占用自动顺延）
./target/release/bitflip path/to/sample.exe

# 只想看识别结论
./target/release/bitflip --info-only path/to/sample.exe
./target/release/bitflip-cli info path/to/libfoo.a --json

# 归档（.a / .lib）：列成员、按成员分析
./target/release/bitflip-cli members path/to/libfoo.a
./target/release/bitflip-cli functions path/to/libfoo.a --member foo.o
./target/release/bitflip-cli symbol path/to/libfoo.a bf_add --member foo.o

# 原始二进制（固件/裸镜像）：没有头可读，架构必须手工指定
./target/release/bitflip-cli info firmware.bin --arch arm --mode thumb --base 0x08000000
./target/release/bitflip    firmware.bin --arch arm --base 0x08000000

# APK 里的 DEX：列类的方法、看方法的指令与文本 CFG（多个 DEX 按成员名区分）
./target/release/bitflip-cli dex path/to/app.apk
./target/release/bitflip-cli dex path/to/app.apk --class 'Lcom/example/Foo;'
./target/release/bitflip-cli dex path/to/app.apk --member classes2.dex --method 'Lcom/example/Foo;->bar(I)V'

# 混淆过的 APK：先列类、再按子串找（--search 隐含 --list-classes）
./target/release/bitflip-cli dex path/to/app.apk --member classes.dex --list-classes --limit 20
./target/release/bitflip-cli dex path/to/app.apk --search Activity

# 导出：机器码与 DEX 共用一个 export 子命令，视图由 --format 决定
./target/release/bitflip-cli export sample.exe --format asm-intel --out disasm.txt
./target/release/bitflip-cli export app.apk --format dex-json --member classes.dex \
    --class 'Lcom/example/Foo;' --out foo.json
./target/release/bitflip-cli export app.apk --format dex-smali --member classes.dex \
    --method 'Lcom/example/Foo;->bar(I)V' --out bar.smali
# 选择器与视图不匹配会报错（不静默忽略）：DEX 没有线性地址空间
./target/release/bitflip-cli export app.apk --format dex-json --function 0x401000   # 报错
```

`--arch` / `--mode` / `--endian` / `--base` 是**公共覆盖参数**，`info`、`functions`、
`symbol`、`serve` 与 `bitflip <目标>` 都支持：

| 参数 | 取值 | 说明 |
| --- | --- | --- |
| `--arch` | `x86` `x86_64` `aarch64` `arm` `riscv32` `riscv64` `mips` `mips64` `wasm32` | 原始二进制**必须**给；有头的目标给了会覆盖嗅探结论 |
| `--mode` | `16` `32` `64` `thumb` | 不给则按架构取惯用模式；ARM 的两套编码靠它区分 |
| `--endian` | `little` `big` | 不给则按架构取惯用端序 |
| `--base` | 十六进制，可带 `0x` | 原始二进制的基址；不给则从 0 起 |
| `--force-raw` | 开关 | 忽略已识别的容器与格式，整体按裸字节处理（头损坏/加密但代码可用时） |

覆盖会如实写进结论的"说明"里（例如"用户指定按原始二进制处理（已忽略嗅探出的
对象格式：ELF）"），不会伪装成是工具自己识别出来的。

前端资源是可选的：仓库里保留了 `web/dist/.gitkeep`，所以**没构建过前端也能编译并运行**，
此时页面是一份说明如何构建前端的占位页。要看到真正的界面：

```bash
cd web && npm install --cache .npm-cache && npm run build && cd ..
cargo build --release -p bitflip-app
```

本机（Windows 沙箱）特有的三条约束：所有 cargo 命令走 `./scripts/cargo.ps1`（它把 `CARGO_HOME`
指向仓库内），npm 必须带 `--cache .npm-cache`（C: 盘空间不足），而 `vite build` 在受限沙箱里
**必然失败**（vite 加载配置时会 `execFile` 子进程，沙箱一律 `EPERM`）。原因见
`docs/DECISIONS.md` ADR-0008/0009。沙箱里请改用等价且已验证的构建路径：

```bash
node scripts/build-web.mjs     # rolldown 直出，不依赖子进程
```

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
  bitflip-patch/    可执行文件打补丁（默认只读；显式解锁后写 .patched 副本，不原地覆写）
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
