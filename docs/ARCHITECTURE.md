# BitFlip 架构设计

> 本文件描述**目标架构**（M0–M8 演进后应有的样子），是实现的依据。
> 里程碑划分见 [PLAN.md](PLAN.md)，决策论证见 [DECISIONS.md](DECISIONS.md)。

---

## 1. 进程与分层

```
┌──────────────────────────── bitflip-app ────────────────────────────┐
│ 参数解析 → 打开目标 → 起服务 → 打开浏览器 → 信号/退出管理            │
└───────────────┬──────────────────────────────┬──────────────────────┘
                │                              │
        ┌───────▼────────┐            ┌────────▼─────────┐
        │ bitflip-cli    │            │ bitflip-server   │
        │ 无头命令       │            │ axum: REST + WS  │
        └───────┬────────┘            │ rust-embed: SPA  │
                │                     └────────┬─────────┘
                └───────────┬──────────────────┘
                     ┌──────▼───────┐
                     │ bitflip-core │  ← 对外稳定 API（可被嵌入）
                     └──────┬───────┘
      ┌──────────┬──────────┼──────────┬───────────┐
      ▼          ▼          ▼          ▼           ▼
 bitflip-    bitflip-   bitflip-   bitflip-   bitflip-
 loader       arch       analyze    symbols    project
```

约束：
- 依赖方向单向，下层永不 `use` 上层。
- `bitflip-core` 不依赖 `axum`/`tokio`（服务层才有 async），也不依赖 SPA 类型。
- `bitflip-core` 的公开类型不用 `#[non_exhaustive]` 之外的手段做兼容，破坏性变更走版本号 + CHANGELOG。

## 2. 数据流

```
文件 ──loader──▶ Image（容器+对象+段/节） ──arch──▶ 解码器
         │                                        │
         ├──symbols──▶ 符号/unwind/DWARF/PDB ─────┤
         │                                        ▼
         └──────────────────────────────▶ analyze 流水线
                                                  │
                        ┌─────────────────────────┼───────────────────┐
                        ▼                         ▼                   ▼
                 AddrSpace(指令索引)         Function/CFG/Xref    派生统计
                        │                         │                   │
                        └───────────┬─────────────┴───────────────────┘
                                    ▼
                            project（派生物落库）
                                    ▲
                    用户标注（names/comments/types/patches）─┘  ← 主数据，永不丢
                                    ▼
                        core 查询 API ──▶ server(列式+游标) ──▶ SPA
```

关键区别：**用户标注是主数据，分析结果是可重建的派生物**。重新分析只重建派生物，
标注通过地址映射回填（地址失效时进入"孤儿标注"区，UI 可见，不静默丢弃）。

## 3. `bitflip-loader`：容器与对象

三层抽象，刻意区分"容器"与"对象"：

```rust
/// 容器：一个文件里可能装着多个对象。
pub enum Container {
    Plain,                    // exe/dll/.so/.o：一个对象
    Archive(Archive),         // ar / MSVC .lib：多成员
    Fat(Vec<Slice>),          // universal（M10 预留，M0-M9 不实现解析）
}

/// 对象：可分析的基本单位。
pub struct Object {
    pub id: ObjectId,                // 容器内定位（归档成员名 / slice 序号）
    pub kind: ObjectKind,            // Pe | Coff | Elf | Raw
    pub arch: ArchSpec,              // 架构 + 位宽 + 端序
    pub format: FormatInfo,          // 头字段、子系统、OS/ABI
    pub image_base: u64,
    pub entry: Option<u64>,
    pub segments: Vec<Segment>,      // 内存视角（PT_LOAD / PE 节 / 归档成员）
    pub sections: Vec<Section>,      // 节视角（含未映射节）
    pub imports: Vec<Import>,        // 名称 + thunk 地址 + IAT 槽
    pub exports: Vec<Export>,
    pub symbols: Vec<RawSymbol>,     // 原始符号（未去重、未优选）
    pub relocations: Vec<Reloc>,
    pub unwind: Vec<UnwindEntry>,    // .pdata RUNTIME_FUNCTION / .eh_frame FDE
    pub bytes: ByteSource,           // mmap 或 owned，段通过 FileRange 引用
}
```

设计要点：
- **段（内存视角）优先于节**：分析基于地址空间，节只用于命名与边界提示。
- `ByteSource` 支持 mmap（大文件不复制）与 owned `Vec<u8>`（归档成员、解压内容）。
- 解析必须**惰性**：`sections` 全量解析很便宜；符号、重定位、`.pdata` 按需加载并缓存。
- 所有解析器对越界字段返回错误，不 panic（`checked_add` / `get(..)` 纪律）。
- 归档成员是独立 `Object`，`Container` 只是分发器 —— 这让"静态库里的每个 .o 独立分析"天然成立。

## 4. `bitflip-arch`：解码与 ABI

```rust
/// 架构描述：把架构差异收敛在一处。
pub struct ArchSpec {
    pub arch: Arch,          // X86 / X86_64 / Aarch64 / Arm / Riscv64 / ...
    pub mode: Mode,          // 16/32/64 / Thumb / ARM
    pub endian: Endian,
    pub ptr_size: u8,
}

pub trait Decoder: Send + Sync {
    /// 解码一条指令；`addr` 用于 rip-relative 与重定位计算。
    fn decode_one(&self, code: &[u8], addr: u64) -> Result<DecodedInsn, DecodeError>;
    /// 批量解码（分块，避免整段重复解码导致二次复杂度）。
    fn decode_many(&self, code: &[u8], addr: u64, max: usize) -> Vec<DecodedInsn>;
    fn abi(&self) -> &'static dyn Abi;
}

pub trait Abi: Send + Sync {
    fn arg_regs(&self) -> &'static [RegId];
    fn ret_reg(&self) -> RegId;
    fn frame_reg(&self) -> RegId;
    fn stack_reg(&self) -> RegId;
    fn is_volatile(&self, reg: RegId) -> bool;
    fn calling_conventions(&self) -> &'static [CallConv];
}
```

`DecodedInsn` 必须携带**语义**而不只是文本：

```rust
pub struct DecodedInsn {
    pub addr: u64,
    pub len: u8,
    pub mnemonic: MnemonicId,          // interned
    pub ops: SmallVec<[Operand; 3]>,
    pub flow: Flow,                    // Fallthrough | Branch{cond} | Call | Return | Trap | Indirect
    pub target: Option<FlowTarget>,     // Direct(u64) | Table{..} | Register/Memory 表达
    pub reads: RegSet,
    pub writes: RegSet,
    pub mem: SmallVec<[MemRef; 2]>,     // 内存操作数（基址/索引/比例/位移/宽度/读写）
    pub flags_written: bool,
    pub privileged: bool,
}
```

规则：
- 上层能力（数据流、跳转表、调用约定、签名匹配、CFG）**只能**消费结构化字段，禁止 `parse(op_str)`。
- 指令文本（Intel/AT&T）是**渲染层**的事，由 `bitflip-arch` 提供格式化器，UI 不自己拼。
- 未知指令显式表示（`mnemonic = ?`，`flow = Fallthrough`，标记 `unknown`），不允许静默跳过字节。

## 5. `bitflip-analyze`：流水线

分阶段、可单独重跑、每阶段可观测：

```
S1 段与映射        loader 结果归一化为 AddrSpace
S2 种子收集        入口、导出、符号、unwind FDE/RUNTIME_FUNCTION、导入 thunk、用户指定
S3 解码扫描        递归下降（种子驱动）+ 线性扫描（代码段补齐）；分块解码、访问集去重
S4 函数识别        候选合并 + 置信度 + 边界扩展（返回/填充/对齐/prologue）
S5 CFG 构建        basic block 切分、后继（含跳转表）、不可达块标记
S6 引用解析        call/jmp 目标、rip-relative/绝对数据引用、表指针
S7 数据/代码判定   引用驱动 + 无效指令检测 + 用户覆写
S8 语义增强        调用约定/参数、字符串聚合、常量与数组、栈帧
S9 符号增强        签名库匹配、库函数识别、名称优选
```

流水线属性：
- 每阶段输出可序列化的中间产物，便于"只重跑 S4–S5"（改名/注释绝不触发重跑）。
- 阶段内用 `rayon` 并行（按函数/按段分片），跨阶段用数据依赖串行。
- 每个识别结果带 `Source`（符号/unwind/调用/prologue/签名/用户）与 `Confidence`，
  UI 可解释"为什么这里被当成函数"。
- 长阶段可取消（协作式检查点），取消后保留已完成部分。

## 6. `bitflip-project`：可写工程库（决策门 D2）

要求（无论选 SQLite 还是自研日志）：

- **主数据**：`names`、`comments`、`types`、`bookmarks`、`patches`、`user_functions`（手工指定边界）、
  `analysis_config`。这些是权威来源，永不因重新分析丢失。
- **派生物**：`functions`、`basic_blocks`、`xrefs`、`insn_index`、`strings`、`signatures_matched`。
  带 `analysis_run_id`，可整体丢弃重建。
- **元数据**：`schema_version`、`target_hash`（内容 sha256，不只是 size+mtime —— adi 的 size+mtime 
  判定在"同名不同内容"时会给出错误命中）、`tool_version`、`analysis_runs`。
- 写路径：单写者（专用线程）串行提交，WAL/事务保证崩溃后一致；
  批量分析结果分块提交（避免一次事务巨大）。
- 读路径：内存索引（地址 → 记录）按需构建，支持多读者并发。
- 迁移：`schema_version` 不匹配时执行迁移或明确拒绝并提示重建派生物（主数据必须能迁走）。

## 7. `bitflip-core`：对外 API（稳定契约）

```rust
pub struct Session { /* 一个打开的目标 */ }

impl Session {
    pub fn open(path: &Path, opts: OpenOptions) -> Result<Self>;
    pub fn analyze(&self, job: &JobHandle, opts: AnalyzeOptions) -> Result<AnalysisSummary>;
    pub fn image(&self) -> &Image;
    pub fn objects(&self) -> &[ObjectInfo];

    // 查询（只读，无锁或细粒度锁）
    pub fn insn_at(&self, addr: u64) -> Option<InsnView<'_>>;
    pub fn insns_from(&self, addr: u64, count: usize, out: &mut InsnSink);
    pub fn functions(&self, filter: &FunctionFilter) -> Vec<FunctionRef>;
    pub fn function_containing(&self, addr: u64) -> Option<FunctionRef>;
    pub fn xrefs_to(&self, addr: u64) -> &[Xref];
    pub fn xrefs_from(&self, addr: u64) -> &[Xref];
    pub fn name_at(&self, addr: u64) -> NameView<'_>;

    // 标注（写，落库）
    pub fn set_name(&self, addr: u64, name: &str) -> Result<()>;
    pub fn set_comment(&self, addr: u64, kind: CommentKind, text: &str) -> Result<()>;
    pub fn set_code_data(&self, addr: u64, kind: CodeData) -> Result<()>;

    // 补丁与导出
    pub fn set_patch(&self, addr: u64, bytes: &[u8]) -> Result<()>;
    pub fn export(&self, fmt: ExportFormat, sink: &mut dyn Write) -> Result<()>;
    pub fn apply_patches(&self, out: &Path, policy: PatchPolicy) -> Result<PatchReport>;
}
```

约定：
- `JobHandle` 承载进度/取消，`bitflip-core` 不知道 HTTP/WS 的存在（服务层订阅事件再转发）。
- 查询返回**视图**（`InsnView`/`NameView`）而不是拷贝所有权类型，避免大对象复制。
- 所有地址参数/返回值都是 `u64`；字符串化只发生在渲染层。

## 8. `bitflip-server`：HTTP/WS 协议

绑定 `127.0.0.1` 随机或指定端口；启动生成 32 字节随机 token，注入 UI 的 URL fragment，
所有 `/api/*` 请求校验 `X-BitFlip-Token` 或 query token；同时校验 `Origin`（拒绝跨站）。

| Method | Path | 用途 |
|--------|------|------|
| `GET` | `/api/health` | 版本、构建信息、核心状态 |
| `GET` | `/api/sessions` | 最近打开列表 |
| `POST` | `/api/sessions` | 打开目标（`{path}`）或上传（multipart，超大文件上限可配） |
| `DELETE` | `/api/sessions/:id` | 关闭会话 |
| `GET` | `/api/sessions/:id/image` | 容器/对象/段/节/导入/导出/入口 |
| `GET` | `/api/sessions/:id/functions` | 函数列表（分页 + 过滤 + 置信度/来源） |
| `GET` | `/api/sessions/:id/insns` | 列式指令页：`from` / `count` / `object` |
| `GET` | `/api/sessions/:id/hex` | 原始字节窗口（`addr` + `len`） |
| `GET` | `/api/sessions/:id/xrefs` | 指定地址的引用（双向、可过滤） |
| `GET` | `/api/sessions/:id/strings` | 字符串表（分页 + 过滤 + 最小长度） |
| `GET` | `/api/sessions/:id/callgraph` | 调用图分片（按根/深度） |
| `PUT` | `/api/sessions/:id/names` | 命名 |
| `PUT` | `/api/sessions/:id/comments` | 注释 |
| `PUT` | `/api/sessions/:id/code-data` | 代码/数据覆写 |
| `PUT` | `/api/sessions/:id/patches` | 字节补丁 |
| `POST` | `/api/sessions/:id/analyze` | 触发/重跑分析（可带阶段范围） |
| `POST` | `/api/sessions/:id/jobs/:job/cancel` | 取消作业 |
| `GET` | `/api/sessions/:id/export` | 导出（asm/json/symbols/dot） |
| `WS` | `/api/sessions/:id/events` | 进度、阶段、日志、标注冲突、作业状态 |

Wire 规则（借鉴 adi web 的正确部分并修正其问题）：
- 指令页列式：`{ total, from, count, a:[addr], b:[bytesHex], m:[mnemonic], o:[operands], f:[flags], t:[target] }`。
- 地址一律 16 位定长小写 hex（`Option` 用 `null`，不用空字符串）。
- 分页由**服务端游标**（`from` 地址）驱动；浏览器只保留窗口附近数据，不整份下载。
- 所有响应带 `format_version`；前端遇到未知版本给出明确提示而不是崩溃。

## 9. SPA（`web/`）

- 栈：TypeScript + React + Vite；无状态服务，全部状态来自 API + 本地 UI store。
- 布局：左侧树（段/函数/符号/字符串）、中间标签页（反汇编 / 图形 CFG / hex / 脚本控制台）、
  右侧上下文（详情、xref、注释、原型）。
- 渲染：虚拟滚动（窗口化）+ 行级 diff 高亮（补丁/改名后局部刷新，不重拉整页）。
- 交互：键盘优先；命令面板（`Ctrl+P`）统一入口；导航历史（`b`/前进）；地址跳转接受
  `0x401000` / `401000` / 符号名 / 函数名。
- i18n：文案集中（`web/src/i18n/zh.ts` 为默认），禁止组件内硬编码中文。
- 测试：`npm run typecheck` + 组件测试 + 端到端（Playwright）主链路。

## 10. 并发与资源模型

- 分析：`rayon` 线程池，规模 = `min(物理核, 8)` 可配；一次只跑一个分析作业，避免内存叠加。
- 服务：`tokio` 多线程运行时**只**做 IO、作业调度与事件转发；分析在 `spawn_blocking` / 专用池中执行。
- 内存：`AddrSpace` 尽量 mmap；指令索引按分片分配；给解码缓存设上限（LRU），超限丢弃可重建数据。
- 全局内存上限可配（默认 4GB 或物理内存 60%），触顶时降级为"仅按需解码 + 丢弃派生物缓存"。

## 11. 与 `temp/adi` 的对应关系（借鉴清单）

| 借鉴 | 位置 | 说明 |
|------|------|------|
| 列式指令传输 | adi web `server/types.ts` | 直接采纳并加上服务端游标 |
| worker 隔离分析 | adi `web/server/analyze-worker.mjs` | 我们改成"分析池 + 作业"，隔离粒度更粗 |
| 内嵌 SPA + 单二进制 | adi `scripts/build-bundle.mjs` | 我们改用 `rust-embed`，去掉 pkg 打补丁那套脆弱流程 |
| 格式/解码选型 | adi `node-binding/Cargo.toml` | goblin + capstone 保留，FlatBuffers 降级为"导出格式" |
| 地址字符串规范 | adi CLAUDE.md | 采纳"16 位定长 hex"于 wire 层；内部统一 `u64` |

**不借鉴**：全量物化指令、只扫 `.text`、size+mtime 缓存判定、同步阻塞分析、假名兜底（`func_xxx`）。
