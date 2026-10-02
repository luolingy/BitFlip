# BitFlip · 比特翻转

> 本地优先、跨平台的静态二进制逆向分析平台 —— 单文件可执行 + 本地 Web UI。

BitFlip 面向可执行文件、动态库与静态库的静态逆向分析：PE（exe/dll/sys/obj/lib）、
ELF（exec/so/o/a）、raw 固件镜像，以及 x86/x64/ARM64/ARM 等架构的指令解码。
打开方式是 `bitflip <target>`，它在 `127.0.0.1` 上启动本地 HTTP 服务并用浏览器打开 UI ——
UI 走 Web 是为了跨平台，不需要为每个平台维护原生 GUI 外壳。

**状态：规划中（M0 尚未开工）。** 当前仓库只有长期计划与架构文档。

## 文档

| 文档 | 内容 |
|------|------|
| [docs/PLAN.md](docs/PLAN.md) | 长期计划：里程碑 M0–M10、验收标准、风险登记 |
| [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md) | 架构：crate 布局、数据模型、HTTP/WS 协议、存储设计 |
| [docs/DECISIONS.md](docs/DECISIONS.md) | 已定决策（ADR）与待决决策门 |

## 目标目录结构

```
crates/
  bitflip-core/     引擎门面 —— 唯一对外稳定 API（可被其他项目作为子模块/依赖嵌入）
  bitflip-loader/   容器与对象格式：PE/COFF、ELF、ar/.lib、raw
  bitflip-arch/     指令解码与架构描述（ABI、寄存器、调用约定）
  bitflip-analyze/  反汇编、函数发现、CFG、交叉引用、数据/代码判定
  bitflip-symbols/  符号来源：符号表、导出表、unwind、DWARF、PDB、签名库
  bitflip-project/  工程库（可写）：用户注释 + 可重建的分析派生物
  bitflip-server/   本地 HTTP/WS 服务 + 内嵌 SPA
  bitflip-cli/      无头 CLI
  bitflip-app/      单二进制入口
web/                SPA：TypeScript + React + Vite
tests/fixtures/     样本生成脚本与黄金快照（样本不入库，按需生成）
```

## 免责声明

BitFlip 是静态分析工具，不执行目标代码。仅用于你拥有或已获授权分析的二进制。

## License

待定（M0 决定）。
