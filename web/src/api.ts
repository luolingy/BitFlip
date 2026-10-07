/**
 * 与本地 BitFlip 服务通信。
 *
 * 令牌来源（按优先级）：URL 片段 `#token=` → 查询串 `?token=` → sessionStorage。
 * 取到后立刻把 URL 里的令牌擦掉，避免它出现在截图、浏览历史或 Referer 里。
 */

const TOKEN_STORAGE_KEY = "bitflip.token";

/** 服务返回的目标识别结论。字段与 `bitflip-core::TargetInfo` 一一对应。 */
export interface TargetInfo {
  /** wire 契约版本号；字段含义变化时递增。 */
  format_version?: number;
  path: string;
  file_size: number;
  container: string;
  container_label: string;
  object: string;
  object_label: string;
  member_kind: string | null;
  arch: string | null;
  arch_family: string | null;
  bits: number;
  endian: string | null;
  entry: string | null;
  image_base: string | null;
  sections: number | null;
  member_count: number;
  members_truncated: boolean;
  summary: string;
  notes: string[];
  sniffed_bytes: number;
  file_truncated: boolean;
}

/** 一个节（文件视角）。对应 `bitflip-core::SectionInfo`。 */
export interface SectionInfo {
  name: string;
  /** 定长 16 位小写十六进制。 */
  vaddr: string;
  file_offset: number;
  file_size: number;
  /** `rwx` 形式，例如 `r-x`。 */
  perms: string;
  kind: string;
  kind_label: string;
  loaded: boolean;
}

/** 一个段（内存视角）。对应 `bitflip-core::SegmentInfo`。 */
export interface SegmentInfo {
  name: string;
  vaddr: string;
  vsize: number;
  file_offset: number | null;
  file_size: number | null;
  perms: string;
  kind: string;
  kind_label: string;
}

/** 一个符号。对应 `bitflip-core::SymbolInfo`。 */
export interface SymbolInfo {
  name: string;
  value: string;
  size: number;
  defined: boolean;
  is_function: boolean;
  is_weak: boolean;
  section: string | null;
  source: string;
}

/** 一个导入项。对应 `bitflip-core::ImportInfo`。 */
export interface ImportInfo {
  module: string;
  name: string | null;
  ordinal: number | null;
  iat_slot: string | null;
}

/** 一个导出项。对应 `bitflip-core::ExportInfo`。 */
export interface ExportInfo {
  name: string;
  ordinal: number | null;
  address: string;
  forwarder: string | null;
}

/** 一条重定位。对应 `bitflip-core::RelocInfo`。 */
export interface RelocInfo {
  address: string;
  kind: string;
  raw_kind: number;
  symbol: string | null;
}

/** 完整解析结果。对应 `bitflip-core::ObjectInfo`。 */
export interface ObjectInfo {
  id: string;
  format_type: string | null;
  os_abi: string | null;
  subsystem: string | null;
  is_dynamic_library: boolean;
  is_executable: boolean;
  is_relocatable: boolean;
  is_stripped: boolean;
  segments: SegmentInfo[];
  sections: SectionInfo[];
  imports: ImportInfo[];
  exports: ExportInfo[];
  symbols: SymbolInfo[];
  relocations: RelocInfo[];
  notes: string[];
}

/** `/api/sections` 响应：识别结论 + 解析结果。 */
export interface SectionsResponse {
  format_version: number;
  target: TargetInfo;
  /** `null` 表示解析失败，原因在 `target.notes` 与 `target` 的识别结论里。 */
  parsed: ObjectInfo | null;
}

/** 一条指令（列式 wire 表示）。对应 `bitflip-core::InsnWire`。 */
export interface InsnWire {
  /** 定长 16 位小写十六进制地址。 */
  address: string;
  /** 编码长度（字节）。 */
  length: number;
  /** 机器码（小写十六进制，无分隔）。 */
  bytes: string;
  /** 渲染后的指令文本。 */
  text: string;
  /** 稳定短名：`flow` / `call` / `jump` / `cond-jump` / `ret` / `trap` / `unknown`。 */
  flow: string;
  /** 流程的中文标签。 */
  flow_label: string;
  /** 直接控制流目标；间接跳转/调用为 `null`。 */
  target: string | null;
  /**
   * 是否被递归下降证明可达。
   *
   * 这是**可信度**信号：线性扫描会把数据误当指令，因此
   * `reachable === false` 的行必须被显著地区分显示，而不是与可达指令同样对待。
   */
  reachable: boolean;
}

/** 一页反汇编。对应 `bitflip-core::InsnPage`。 */
export interface InsnPage {
  format_version: number;
  /** 本页起始地址（定长十六进制）。 */
  from: string;
  /** 请求的条数上限。 */
  requested: number;
  /** 实际返回的条数。 */
  returned: number;
  /** 下一页游标；`null` 表示后面没有更多已索引指令。 */
  next: string | null;
  has_more: boolean;
  instructions: InsnWire[];
}

/** 扫描统计。对应 `bitflip-core::DisasmStats`。 */
export interface DisasmStats {
  indexed: number;
  /** 递归下降可达的条数。 */
  reachable: number;
  /** 仅线性扫描覆盖的条数（可信度较低）。 */
  linear_only: number;
  decode_failures: number;
  executable_segments: number;
  truncated: number;
  mapped_bytes: number;
  /** 索引常驻内存估算（字节）。 */
  index_bytes: number;
}

/** `/api/insns` 响应。 */
export interface InsnsResponse {
  format_version: number;
  page: InsnPage;
  stats: DisasmStats;
  /** 分析期产生的降级说明（合成地址、截断、无法解码的字节数…）。 */
  notes: string[];
}

/** `/api/health` 响应。 */
export interface HealthResponse {
  ok: boolean;
  name: string;
  name_zh: string;
  version: string;
  server_api_version: number;
  core_api_version: number;
  uptime_ms: number;
  ui_embedded: boolean;
  target: TargetInfo | null;
}

/** 服务端返回的错误（响应体是 `{ error, status }`）。 */
export class ApiError extends Error {
  readonly status: number;

  constructor(status: number, message: string) {
    super(message);
    this.name = "ApiError";
    this.status = status;
  }
}

function readTokenFromHash(): string | null {
  const raw = window.location.hash.replace(/^#/, "");
  if (!raw) {
    return null;
  }
  return new URLSearchParams(raw).get("token");
}

function readTokenFromQuery(): string | null {
  return new URLSearchParams(window.location.search).get("token");
}

/** 取令牌并清理 URL。 */
export function resolveToken(): string | null {
  const token = readTokenFromHash() ?? readTokenFromQuery();
  if (token) {
    try {
      window.sessionStorage.setItem(TOKEN_STORAGE_KEY, token);
    } catch {
      // 隐私模式下 sessionStorage 可能不可用：令牌只存在于内存里的返回值中。
    }
    window.history.replaceState(null, "", window.location.pathname);
    return token;
  }
  try {
    return window.sessionStorage.getItem(TOKEN_STORAGE_KEY);
  } catch {
    return null;
  }
}

async function request<T>(path: string, token: string | null): Promise<T> {
  const headers: Record<string, string> = {};
  if (token) {
    headers["x-bitflip-token"] = token;
  }

  const response = await fetch(path, { headers });
  if (!response.ok) {
    let message = `请求失败（HTTP ${response.status}）`;
    try {
      const body: unknown = await response.json();
      if (body && typeof body === "object" && "error" in body) {
        const raw = (body as { error: unknown }).error;
        if (typeof raw === "string") {
          message = raw;
        }
      }
    } catch {
      // 响应体不是 JSON：保留默认信息。
    }
    throw new ApiError(response.status, message);
  }

  return (await response.json()) as T;
}

/** 健康检查（需要令牌）。 */
export function fetchHealth(token: string | null): Promise<HealthResponse> {
  return request<HealthResponse>("/api/health", token);
}

/** 当前会话目标；服务端在无目标时返回 404，这里转成 `null`。 */
export async function fetchTarget(token: string | null): Promise<TargetInfo | null> {
  try {
    return await request<TargetInfo>("/api/target", token);
  } catch (error) {
    if (error instanceof ApiError && error.status === 404) {
      return null;
    }
    throw error;
  }
}

/** 段/节结构视图；无目标时返回 `null`。 */
export async function fetchSections(token: string | null): Promise<SectionsResponse | null> {
  try {
    return await request<SectionsResponse>("/api/sections", token);
  } catch (error) {
    if (error instanceof ApiError && error.status === 404) {
      return null;
    }
    throw error;
  }
}

/** 把定长十六进制地址渲染成带 `0x` 前缀的形式。 */
export function formatAddress(address: string | null | undefined): string {
  if (!address) {
    return "-";
  }
  // 去掉前导 0，但至少保留一位
  const trimmed = address.replace(/^0+/, "") || "0";
  return `0x${trimmed}`;
}

/**
 * 取一页反汇编。
 *
 * `from` 传定长十六进制地址或其前缀；传 `null` 表示从头开始。
 * 地址落在某条指令中间时，服务端会吸附到**包含**该地址的那条指令
 * （见 `InsnIndex::containing`），因此这里不需要客户端的额外处理。
 */
export function fetchInsns(
  token: string | null,
  from: string | null,
  count: number,
): Promise<InsnsResponse> {
  const params = new URLSearchParams();
  if (from) {
    params.set("from", from);
  }
  params.set("count", String(count));
  return request<InsnsResponse>(`/api/insns?${params.toString()}`, token);
}

/** 把字节数渲染成人类可读形式。 */
export function formatSize(bytes: number): string {
  if (bytes < 1024) {
    return `${bytes} B`;
  }
  const units = ["KiB", "MiB", "GiB", "TiB"];
  let value = bytes / 1024;
  let unitIndex = 0;
  while (value >= 1024 && unitIndex < units.length - 1) {
    value /= 1024;
    unitIndex += 1;
  }
  return `${value.toFixed(value < 10 ? 1 : 0)} ${units[unitIndex]}`;
}

// ── M3：目标级分析 ──────────────────────────────────────────────────────────

/** 一个函数。对应 `bitflip-core::FunctionWire`。 */
export interface FunctionWire {
  /** 入口地址（定长 16 位十六进制）。 */
  start: string;
  /**
   * 结束地址（不含）；未知时为 `null`。
   *
   * **不要**把 `null` 当成 0 或当成"到段尾"：它表示边界真的没识别出来，
   * UI 必须显示"未知"而不是编一个范围（CLAUDE.md §7）。
   */
  end: string | null;
  /** 函数名；未命名时为空串（配合 `named === false`）。 */
  name: string;
  /** 是否有名字（来自符号/导出/用户标注）。 */
  named: boolean;
  /** 名字来源短名：`symbol-table` / `export` / `unwind` / `discovery` / … */
  source: string;
  /** 来源的中文标签。 */
  source_label: string;
  /** 置信度（0–100）。 */
  confidence: number;
  /** 大小；`end` 未知时为 `null`。 */
  size: number | null;
}

/** 归档里的一个成员。对应 `bitflip-server` 的 `MemberWire`。 */
export interface MemberWire {
  /** 成员名（已尽量解析长名表）。 */
  name: string;
  /** 成员数据在容器里的文件偏移。 */
  offset: number;
  /** 成员数据长度。 */
  size: number;
  /** 成员数据是否超出嗅探窗口。 */
  truncated: boolean;
  /**
   * 成员是否**可以**被当作独立对象分析。
   *
   * 这是后端真的建过一次成员会话得出的结论，不是按名字猜的 ——
   * 所以可以直接拿来决定按钮是否可点，不需要前端再判一次。
   */
  analyzable: boolean;
}

/** 归档成员列表。对应 `GET /api/members`。 */
export interface MembersResponse {
  format_version: number;
  /**
   * 目标是不是归档。
   *
   * **"不是归档"与"归档没有成员"是两件事**，文案完全不同，
   * 所以后端显式给出这一位而不是靠数组为空判断。
   */
  is_archive: boolean;
  /** 容器类别（`ar` / `msvc-lib` / 其他）。 */
  container: string;
  /** 成员列表是否被截断。 */
  truncated: boolean;
  members: MemberWire[];
}

/** 一条交叉引用。对应 `bitflip-core::XrefWire`。 */
export interface XrefWire {
  /** 引用发出的地址。 */
  from: string;
  /** 被引用的地址。 */
  to: string;
  /** 类型短名：`call` / `jump` / `data`。 */
  kind: string;
  /**
   * 引用来源短名：`direct`（指令编码里写明的目标）或
   * `jump-table`（间接跳转经跳转表识别推导出的目标）。
   *
   * 两者的可信度不同：后者是分析器读表推导的，验证失败的模式
   * 也不同 —— UI 必须能区分，不能当成同一种事实展示。
   */
  source: string;
  /**
   * 发起指令是否被递归下降证明可达。
   *
   * `false` 不代表引用是错的，而是"发起指令本身可能只是线性扫描
   * 把数据误认成了指令"。低可信度的行要显著区分显示。
   */
  reachable: boolean;
}

/** 引用来源短名 → 中文标签。 */
export const XREF_SOURCE_LABELS: Record<string, string> = {
  direct: "直接",
  "jump-table": "跳转表推导",
};

/** 引用类型短名 → 中文标签。 */
export const XREF_KIND_LABELS: Record<string, string> = {
  call: "调用",
  jump: "跳转",
  data: "数据",
};

/** 一条字符串。对应 `bitflip-core::StringWire`。 */
export interface StringWire {
  address: string;
  /** 字节长度。 */
  size: number;
  /** 编码短名：`ascii` / `utf-16le`。 */
  encoding: string;
  text: string;
}

/** 编码短名 → 中文标签。 */
export const STRING_ENCODING_LABELS: Record<string, string> = {
  ascii: "ASCII",
  "utf-16le": "UTF-16LE",
};

/** `/api/functions` 响应。 */
export interface FunctionsResponse {
  format_version: number;
  total: number;
  functions: FunctionWire[];
  notes: string[];
}

/** `/api/xrefs` 响应。 */
export interface XrefsResponse {
  format_version: number;
  address: string;
  from: XrefWire[];
  to: XrefWire[];
  /** 包含该地址的函数；`null` 表示没有已知函数覆盖它（真实情形，不是错误）。 */
  function: FunctionWire | null;
}

/** `/api/strings` 响应。 */
export interface StringsResponse {
  format_version: number;
  total: number;
  strings: StringWire[];
}

/** `/api/xref-search` 响应（M6 交付物 7）。 */
export interface XrefSearchResponse {
  format_version: number;
  /** 满足条件的总条数（不受分页影响）。 */
  total: number;
  /** 本页返回条数。 */
  returned: number;
  /** 因分页跳过的条数。 */
  skipped: number;
  /** 因分页未返回的条数。`skipped + returned + truncated == total`。 */
  truncated: number;
  xrefs: XrefWire[];
  notes: string[];
}

/** xref 搜索的过滤条件。 */
export interface XrefSearchFilters {
  kind?: string[];
  source?: string[];
  // 显式写出 `| undefined`：项目开了 exactOptionalPropertyTypes，
  // 只写 `fromStart?: string` 时不允许显式传 undefined。
  fromStart?: string | undefined;
  fromEnd?: string | undefined;
  toStart?: string | undefined;
  toEnd?: string | undefined;
  count?: number | undefined;
  offset?: number | undefined;
}

/** 一个可达函数。对应 `bitflip-core::ReachableFunctionWire`。 */
export interface ReachableFunctionWire {
  entry: string;
  /** 距起点的跳数。 */
  depth: number;
  /** 函数名；`null` 表示未命名（不是编出来的占位名）。 */
  name: string | null;
}

/** 可达性结论。对应 `bitflip-core::ReachabilityWire`。 */
export interface ReachabilityWire {
  /** 起点；`null` 表示从全部根出发的全局可达性。 */
  entry: string | null;
  total_functions: number;
  reachable: number;
  unreachable: number;
  max_depth: number;
  /** `depth_histogram[i]` = 距起点 i 跳的函数数。 */
  depth_histogram: number[];
  functions: ReachableFunctionWire[];
  /** 明细被截断的条数。 */
  truncated: number;
  /**
   * 本次 BFS 没有走通的间接调用数。
   *
   * 这个数 > 0 时"不可达"**不等于**死代码：只被 `call rax` 调用的
   * 函数在这里也会显示成不可达。界面必须把它和不可达数一起显示。
   */
  unresolved_indirect: number;
  notes: string[];
}

/** `/api/reachability` 响应。 */
export interface ReachabilityResponse {
  format_version: number;
  result: ReachabilityWire;
}

/** 十六进制视图的一行。 */
export interface HexRow {
  address: string;
  hex: string;
  ascii: string;
}

/** `/api/hex` 响应。 */
export interface HexResponse {
  address: string;
  row_bytes: number;
  rows: HexRow[];
  /**
   * 实际读到的字节数。
   *
   * 可能**小于**请求值（到段尾或文件尾）。UI 必须据此提示"已到段尾"，
   * 否则用户会以为后面还有内容。
   */
  bytes_read: number;
}

/** 调用图汇总。对应 `bitflip-core::CallGraphSummaryWire`。 */
export interface CallGraphSummary {
  nodes: number;
  edges: number;
  /**
   * 未解析的间接调用数。
   *
   * 必须显示给用户：解析它们需要数据流分析（M6 未实现），
   * 所以这张图**本来就不完整**。藏起来等于假装完整。
   */
  unresolved_indirect: number;
  outside_targets: number;
  roots: number;
  components: number;
  /** >1 表示存在递归环。 */
  largest_component: number;
}

/** 一条调用边。 */
export interface CallEdge {
  caller: string;
  callee: string;
  /** 尾调用：跳过去就不回来了。 */
  tail: boolean;
}

/** 一个未解析的调用点。 */
export interface UnresolvedCall {
  caller: string;
  insn: string;
}

/** `/api/call-graph` 响应。 */
export interface CallGraphResponse {
  format_version: number;
  summary: CallGraphSummary;
  edges: CallEdge[];
  unresolved: UnresolvedCall[];
  /** 本次响应涉及的节点地址集合。 */
  nodes: string[];
  /** 邻域模式下的聚焦函数；全图模式为 `null`。 */
  focus: string | null;
  /** 邻域跳数；全图模式为 0。 */
  depth: number;
  /**
   * 实际返回的边数（= `edges.length`）。
   *
   * 大目标上 `summary.edges` 是图上真实的边数，而 `edges` 只装得下
   * 前 2 万条。两个数字不一致时**必须**告诉用户，否则界面会显示
   * "共 23660 条边"却只列出 20000 行，看起来像丢了数据。
   */
  returned_edges: number;
  /** 因上限未返回的边数；0 表示没截断。 */
  truncated_edges: number;
  notes: string[];
}

/** 数据/代码判定统计。对应 `bitflip-core::CodeMapStats`。 */
export interface CodeMapStats {
  code: number;
  data: number;
  unknown: number;
  /** 给出明确结论的比例（0–1）。低不是坏事：说明系统没硬凑结论。 */
  decided_ratio: number;
}

/** 一条代表性判定。 */
export interface CodeMapSample {
  /**
   * 判定地址（定长 16 位小写十六进制）。
   *
   * 字段名是 `addr`，与服务端 `CodeMapSample` 一致 —— 不要"顺手"
   * 改成 `address`：名字对不上会让这一列静默变成 `undefined`，
   * 而 TypeScript 不会因此报错（后端 JSON 是 `any`）。
   */
  addr: string;
  kind: string;
  kind_label: string;
  confidence: number;
  well_supported: boolean;
  reason: string;
}

/** `/api/code-map` 响应。 */
export interface CodeMapResponse {
  format_version: number;
  stats: CodeMapStats;
  samples: CodeMapSample[];
  notes: string[];
}

/** 一条跳转表。对应服务端的 `JumpTableWire`。 */
export interface JumpTable {
  /** 发起间接跳转的指令地址。 */
  insn_addr: string;
  /** 表基址。 */
  base: string;
  /** 表项字节宽度（1/2/4/8）。 */
  width: number;
  kind: string;
  kind_zh: string;
  /** 表项数。 */
  count: number;
  /** 目标地址列表。 */
  targets: string[];
}

/** `/api/jump-tables` 响应。 */
export interface JumpTablesResponse {
  format_version: number;
  tables: JumpTable[];
  notes: string[];
}

/** `/api/const-scan` 响应。 */
export interface ConstScanResponse {
  format_version: number;
  strings: StringUsage[];
  strides: StringStride[];
  immediates: Immediate[];
  immediate_total: number;
  immediate_distinct: number;
  notes: string[];
}

/** 一条被指令引用的字符串。 */
export interface StringUsage {
  /** 定长 16 位小写十六进制。 */
  address: string;
  /** 引用它的函数入口（可能为空：引用点落在已知函数之外）。 */
  functions: string[];
  /** 引用点（指令地址）。 */
  sites: string[];
}

/** 一个基址寄存器上的访问位移观测。 */
export interface StringStride {
  /** 基址寄存器编号（capstone 的 `RegId`）。 */
  base: number;
  /** 访问宽度（字节）。 */
  width: number;
  /** 推断出的步长；`null` 表示推不出来 —— **不是 0**。 */
  stride: number | null;
  /** 观测到的位移（升序）。 */
  offsets: number[];
}

/** 一个高频立即数。 */
export interface Immediate {
  /**
   * 立即数值，**十进制字符串**。
   *
   * 用字符串而不是 `number`：JSON 里超过 2^53 的整数会在 JS 侧被
   * 静默截断，而目标里完全可能出现这样的立即数。
   */
  value: string;
  count: number;
}

/** `/api/arg-scan` 响应。 */
export interface ArgScanResponse {
  format_version: number;
  /** 调用约定中文名；`null` 表示该架构没有寄存器级约定（如 wasm32）。 */
  abi_name: string | null;
  /** 参数寄存器名（按调用顺序）。 */
  arg_reg_names: string[];
  functions: ArgInference[];
  notes: string[];
}

/** 单个函数的参数推断结果。 */
export interface ArgInference {
  /** 函数入口，定长 16 位小写十六进制。 */
  entry: string;
  /** 推断所依据的指令条数。 */
  insn_count: number;
  /** 确定用到的参数寄存器序号（ABI 序号，不重编号）。 */
  used: number[];
  /** 上述序号对应的寄存器名，便于直接显示。 */
  used_names: string[];
  /**
   * 参数个数的**下界**（最大已用序号 + 1）。
   *
   * 不是参数个数：没有调试信息时，参数寄存器没被读到不等于没有这个
   * 参数（可能只被透传，或者一进函数就存到栈上）。UI 上必须显示成
   * "至少 N 个"，不能显示成"有 N 个"。
   */
  lower_bound: number;
  /** 第一个未观测到读取的参数寄存器序号；`null` 表示全都用到了。 */
  unobserved_from: number | null;
  /** ABI 规定的寄存器参数容量。 */
  register_slots: number;
  /** 是否观测到从栈上读参数。 */
  reads_stack_args: boolean;
}

/** 一条用户标注。对应 `bitflip-project::Annotation`。 */export interface Annotation {
  /** 定长 16 位小写十六进制。 */
  address: string;
  /** 类别短名：`name` / `comment` / `type` / `bookmark` / `patch` / … */
  kind: string;
  text: string | null;
  patch_hex: string | null;
}

/** `/api/annotations` 响应。 */
export interface AnnotationsResponse {
  format_version: number;
  target_sha256: string;
  annotations: Annotation[];
  /** 分析时间；`null` 表示还没跑过分析（或只改过标注）。 */
  analyzed_at_unix: number | null;
}

/** 标注类别短名 → 中文标签。 */
export const ANNOTATION_KIND_LABELS: Record<string, string> = {
  name: "名称",
  comment: "注释",
  type: "类型",
  bookmark: "书签",
  patch: "补丁",
  "function-boundary": "函数边界",
  "code-data": "代码/数据",
};

/** 取函数列表；无目标或不可分析时返回 `null`（服务端 400 带原因）。 */export async function fetchFunctions(
  token: string | null,
  from: string | null,
  count: number,
): Promise<FunctionsResponse | null> {
  const params = new URLSearchParams();
  if (from) {
    params.set("from", from);
  }
  params.set("count", String(count));
  return requestOrNull<FunctionsResponse>(`/api/functions?${params.toString()}`, token);
}

/** 取归档成员列表。 */
export async function fetchMembers(
  token: string | null,
): Promise<MembersResponse | null> {
  return requestOrNull<MembersResponse>("/api/members", token);
}

/** 取某个归档成员里的函数列表。 */
export async function fetchMemberFunctions(
  token: string | null,
  member: string,
  count: number,
): Promise<FunctionsResponse | null> {
  const params = new URLSearchParams({ member, count: String(count) });
  return requestOrNull<FunctionsResponse>(
    `/api/members/functions?${params.toString()}`,
    token,
  );
}

/** 取调用图。
 *
 * 不传 `entry` 取全图（大目标会被服务端截断并说明）；传 `entry`
 * 取该函数的邻域 —— 这是主路径，1 万函数里用户总是先定位一个
 * 函数再看它的邻居。 */
export async function fetchCallGraph(
  token: string | null,
  entry?: string | null,
  depth = 1,
): Promise<CallGraphResponse | null> {
  const params = new URLSearchParams();
  if (entry) {
    params.set("entry", entry);
    params.set("depth", String(depth));
  }
  const qs = params.toString();
  return requestOrNull<CallGraphResponse>(
    `/api/call-graph${qs ? `?${qs}` : ""}`,
    token,
  );
}

/** 取数据/代码判定的统计与样本。 */
export async function fetchCodeMap(
  token: string | null,
): Promise<CodeMapResponse | null> {
  return requestOrNull<CodeMapResponse>("/api/code-map", token);
}

/** 取识别出的跳转表。 */
export async function fetchJumpTables(
  token: string | null,
): Promise<JumpTablesResponse | null> {
  return requestOrNull<JumpTablesResponse>("/api/jump-tables", token);
}

/** 取常量/结构体初步推断。 */
export async function fetchConstScan(
  token: string | null,
): Promise<ConstScanResponse | null> {
  return requestOrNull<ConstScanResponse>("/api/const-scan", token);
}

/** 取调用约定与参数推断。 */
export async function fetchArgScan(
  token: string | null,
): Promise<ArgScanResponse | null> {
  return requestOrNull<ArgScanResponse>("/api/arg-scan", token);
}

/** `/api/frames` 响应。 */
export interface FrameScanResponse {
  format_version: number;
  abi_name: string | null;
  functions: FrameInference[];
  notes: string[];
}

/** 单个函数的栈帧与局部变量视图。 */
export interface FrameInference {
  entry: string;
  frame_size: number | null;
  source: string;
  unwind_frame_size: number | null;
  prologue_frame_size: number | null;
  prologue_len: number | null;
  saved_registers: string[];
  frame_pointer: string | null;
  stopped_at: string | null;
  notes: string[];
}

/** 取栈帧与局部变量视图。 */
export async function fetchFrames(
  token: string | null,
): Promise<FrameScanResponse | null> {
  return requestOrNull<FrameScanResponse>("/api/frames", token);
}


/** 取某地址的交叉引用，可按类型与来源过滤。 */export async function fetchXrefs(
  token: string | null,
  address: string,
  filters?: { kind?: string[]; source?: string[] },
): Promise<XrefsResponse | null> {
  const params = new URLSearchParams({ address });
  if (filters?.kind?.length) {
    params.set("kind", filters.kind.join(","));
  }
  if (filters?.source?.length) {
    params.set("source", filters.source.join(","));
  }
  return requestOrNull<XrefsResponse>(`/api/xrefs?${params.toString()}`, token);
}

/** 按条件搜索交叉引用（全表过滤 + 分页）。 */
export async function fetchXrefSearch(
  token: string | null,
  filters: XrefSearchFilters,
): Promise<XrefSearchResponse | null> {
  const params = new URLSearchParams();
  if (filters.kind?.length) {
    params.set("kind", filters.kind.join(","));
  }
  if (filters.source?.length) {
    params.set("source", filters.source.join(","));
  }
  if (filters.fromStart) {
    params.set("from_start", filters.fromStart);
  }
  if (filters.fromEnd) {
    params.set("from_end", filters.fromEnd);
  }
  if (filters.toStart) {
    params.set("to_start", filters.toStart);
  }
  if (filters.toEnd) {
    params.set("to_end", filters.toEnd);
  }
  if (filters.count !== undefined) {
    params.set("count", String(filters.count));
  }
  if (filters.offset !== undefined) {
    params.set("offset", String(filters.offset));
  }
  return requestOrNull<XrefSearchResponse>(
    `/api/xref-search?${params.toString()}`,
    token,
  );
}

/** 取可达性结论。`entry` 省略时为全局可达性。 */
export async function fetchReachability(
  token: string | null,
  entry?: string | null,
  limit?: number,
): Promise<ReachabilityResponse | null> {
  const params = new URLSearchParams();
  if (entry) {
    params.set("entry", entry);
  }
  if (limit !== undefined) {
    params.set("limit", String(limit));
  }
  const qs = params.toString();
  return requestOrNull<ReachabilityResponse>(
    `/api/reachability${qs ? `?${qs}` : ""}`,
    token,
  );
}

/** 取字符串列表（可按子串过滤）。 */
export async function fetchStrings(
  token: string | null,
  contains: string,
  count: number,
): Promise<StringsResponse | null> {
  const params = new URLSearchParams();
  if (contains) {
    params.set("contains", contains);
  }
  params.set("count", String(count));
  return requestOrNull<StringsResponse>(`/api/strings?${params.toString()}`, token);
}

/** 取十六进制视图。 */
export async function fetchHex(
  token: string | null,
  address: string,
  length: number,
): Promise<HexResponse | null> {
  const params = new URLSearchParams({ address, length: String(length) });
  return requestOrNull<HexResponse>(`/api/hex?${params.toString()}`, token);
}

/** 取地址范围内的标注。 */
export async function fetchAnnotations(
  token: string | null,
  from: string,
  to: string,
): Promise<AnnotationsResponse | null> {
  const params = new URLSearchParams({ from, to });
  return requestOrNull<AnnotationsResponse>(`/api/annotations?${params.toString()}`, token);
}

/**
 * 写一条标注。
 *
 * 服务端**不会**因此重新分析（响应里 `reanalyzed: false`）—— 改名是
 * 主数据写入，不是分析。UI 不该在改名后重新拉取整个反汇编。
 */
export async function putAnnotation(
  token: string | null,
  address: string,
  kind: string,
  text: string,
): Promise<void> {
  await requestJson("PUT", "/api/annotations", token, { address, kind, text });
}

/** 删除一条标注（幂等）。 */
export async function deleteAnnotation(
  token: string | null,
  address: string,
  kind: string,
): Promise<void> {
  const params = new URLSearchParams({ address, kind });
  await requestJson("DELETE", `/api/annotations?${params.toString()}`, token, null);
}

/**
 * 请求一个"不可用时返回 `null`"的端点。
 *
 * 与 `request` 的区别：分析端点在没有目标/目标不可分析时返回 400，
 * 那是**预期**情形而非异常 —— 面板应当显示原因，而不是抛异常炸掉整页。
 */
async function requestOrNull<T>(path: string, token: string | null): Promise<T | null> {
  try {
    return await request<T>(path, token);
  } catch (error) {
    if (error instanceof ApiError && error.status >= 400 && error.status < 500) {
      return null;
    }
    throw error;
  }
}

async function requestJson(
  method: string,
  path: string,
  token: string | null,
  body: unknown,
): Promise<void> {
  const headers: Record<string, string> = {};
  if (token) {
    headers["x-bitflip-token"] = token;
  }
  const init: RequestInit = { method, headers };
  if (body !== null) {
    headers["content-type"] = "application/json";
    init.body = JSON.stringify(body);
  }

  const response = await fetch(path, init);
  if (!response.ok) {
    let message = `请求失败（HTTP ${response.status}）`;
    try {
      const parsed: unknown = await response.json();
      if (parsed && typeof parsed === "object" && "error" in parsed) {
        const raw = (parsed as { error: unknown }).error;
        if (typeof raw === "string") {
          message = raw;
        }
      }
    } catch {
      // 响应体不是 JSON：保留默认信息。
    }
    throw new ApiError(response.status, message);
  }
}

/**
 * 把用户输入的地址规范成定长 16 位小写十六进制。
 *
 * 返回 `null` 表示输入不是合法地址 —— **不要**回退到 0：
 * 那会让用户以为自己跳转成功了，其实只是回到了文件开头。
 */
export function normalizeAddress(input: string): string | null {
  const trimmed = input.trim().replace(/^0x/i, "");
  if (!/^[0-9a-fA-F]{1,16}$/.test(trimmed)) {
    return null;
  }
  return trimmed.toLowerCase().padStart(16, "0");
}

// ── M7：脚本 ────────────────────────────────────────────────────────────────

/** 一行脚本日志。 */
export interface ScriptLogWire {
  /** `info` / `warn` / `error`。 */
  level: string;
  message: string;
}

/** 脚本上报的进度。 */
export interface ScriptProgressWire {
  /** 已完成。 */
  done: number;
  /**
   * 总数；脚本没说时为 `null`。
   *
   * 界面必须把 `null` 显示成"进行中"而不是 `0%`：进度条停在 0%
   * 与"正在进行但总量未知"是两种完全不同的状态。
   */
  total: number | null;
  /** 当前在做什么。 */
  label: string | null;
}

/**
 * 脚本失败的分类。
 *
 * 用带标签的联合而不是一个 `{ message }`：界面对"被取消"、"超时"、
 * "提交写了一半"要给完全不同的呈现，并让用户知道**该做什么**。
 */
export type ScriptErrorWire =
  | { kind: "cancelled" }
  | { kind: "timeout"; limit_ms: number }
  | { kind: "syntax"; message: string; line: number | null }
  | { kind: "runtime"; message: string; line: number | null; stack: string | null }
  | { kind: "host"; message: string }
  | { kind: "panic"; message: string }
  | { kind: "commit"; committed: number; total: number; reason: string }
  | { kind: "engine"; message: string };

/**
 * 列的类型。
 *
 * 它是**脚本声明的**，不是界面猜的。在加它之前，界面靠"定长十六进制"
 * 猜哪一列是地址 —— 猜错了就是把不是地址的东西当地址渲染，
 * 而用户以为是脚本声明的。
 */
export type ScriptColumnKind = "text" | "number" | "address" | "bool";

/** 一列。 */
export interface ScriptColumnWire {
  name: string;
  kind: ScriptColumnKind;
}

/**
 * 一张脚本表的摘要（随 `status` 回来）。
 *
 * 摘要里**没有数据行**：界面每几百毫秒轮询一次状态，把整张表塞进去
 * 会让轮询响应变成几百 KB。数据行走 [`fetchScriptTable`]。
 */
export interface ScriptTableSummaryWire {
  name: string;
  description: string | null;
  columns: ScriptColumnWire[];
  row_count: number;
}

/**
 * 一个单元格的 wire 值。
 *
 * 地址在 wire 上就是**定长十六进制字符串**（本项目唯一的地址格式），
 * 所以这里不需要"哪一列是地址"的推断 —— 列声明已经说了。
 */
export type ScriptCellWire = null | boolean | number | string;

/** 一页表数据。 */
export interface ScriptTableWire {
  name: string;
  description: string | null;
  columns: ScriptColumnWire[];
  /** 总行数；可能大于 `rows.length`（分页）。 */
  total: number;
  offset: number;
  rows: ScriptCellWire[][];
}

/** 运行状态。 */
export interface ScriptStatusWire {
  /** `idle` | `warming` | `running` | `done`。 */
  state: string;
  run_id: number | null;
  elapsed_ms: number;
  logs: ScriptLogWire[];
  progress: ScriptProgressWire | null;
  /** 目前暂存的写入条数。 */
  staged: number;
  /** 已提交条数（未结束时为 `null`）。 */
  committed: number | null;
  /** 本次尝试提交的条数（未结束时为 `null`）。 */
  staged_total: number | null;
  /** 本次运行产出的表（只给形状与行数）。 */
  tables: ScriptTableSummaryWire[];
  error: ScriptErrorWire | null;
  /**
   * 现在点"停止"是否有用。
   *
   * 单独给这个字段而不是让界面从 `state` 推断：预热阶段（构建分析结论）
   * 看起来也是"在跑"，但取消无效 —— 分析不在脚本引擎里跑。
   */
  can_cancel: boolean;
  /** 脚本 API 版本。 */
  api_version: number;
}

/** 一份内置脚本。 */
export interface BuiltinScriptWire {
  id: string;
  name: string;
  description: string;
  api_version: number;
  source: string;
}

/** 脚本库。 */
export interface ScriptLibraryWire {
  api_version: number;
  scripts: BuiltinScriptWire[];
}

/**
 * 发起一次脚本运行。
 *
 * 服务端**立刻**返回（202），不等脚本跑完 —— 否则界面看不到进度、
 * 也没有一个可被取消的运行对象。结果要靠 `fetchScriptStatus` 轮询。
 */
export function runScript(
  token: string | null,
  source: string,
): Promise<ScriptStatusWire> {
  return requestJsonResult<ScriptStatusWire>("POST", "/api/script/run", token, {
    source,
  });
}

/** 查询当前（或最近一次）运行的状态。 */
export function fetchScriptStatus(token: string | null): Promise<ScriptStatusWire> {
  return request<ScriptStatusWire>("/api/script/status", token);
}

/**
 * 请求取消当前运行。
 *
 * 被拒（没有在跑 / 还在预热 / 已经结束）时**不抛异常**，而是把原因带回来：
 * 那些都是有意义的回答，界面要显示它们，而不是弹一个红框。
 */
export async function cancelScript(
  token: string | null,
): Promise<{ ok: boolean; message: string }> {
  const headers: Record<string, string> = {};
  if (token) {
    headers["x-bitflip-token"] = token;
  }
  const response = await fetch("/api/script/cancel", { method: "POST", headers });
  const body: unknown = await response.json().catch(() => null);
  if (body && typeof body === "object" && "ok" in body) {
    const record = body as { ok: unknown; message: unknown };
    return {
      ok: record.ok === true,
      message: typeof record.message === "string" ? record.message : "",
    };
  }
  return {
    ok: false,
    message: `取消失败（HTTP ${response.status}）`,
  };
}

/** 内置示例脚本集。 */
export function fetchScriptLibrary(token: string | null): Promise<ScriptLibraryWire> {
  return request<ScriptLibraryWire>("/api/script/library", token);
}

/**
 * 取一页表数据。
 *
 * 分页而不是"全部给我"：一张表可以有上万行，而界面一屏只画得下几百行。
 * `total` 会一起回来，界面据此说清"还有多少没显示"。
 */
export function fetchScriptTable(
  token: string | null,
  name: string,
  offset = 0,
  count = 2000,
): Promise<ScriptTableWire> {
  const query = new URLSearchParams({
    name,
    offset: String(offset),
    count: String(count),
  });
  return request<ScriptTableWire>(`/api/script/table?${query.toString()}`, token);
}

/**
 * 带响应体的 `fetch`。
 *
 * 与 [`requestJson`] 的区别是它需要把响应解析回来，并且错误体里
 * 除了 `error` 还认 `message`（取消端点用的是后者）。
 */
async function requestJsonResult<T>(
  method: string,
  path: string,
  token: string | null,
  body: unknown,
): Promise<T> {
  const headers: Record<string, string> = {};
  if (token) {
    headers["x-bitflip-token"] = token;
  }
  const init: RequestInit = { method, headers };
  if (body !== null) {
    headers["content-type"] = "application/json";
    init.body = JSON.stringify(body);
  }

  const response = await fetch(path, init);
  const text = await response.text();
  if (!response.ok) {
    let message = `请求失败（HTTP ${response.status}）`;
    try {
      const parsed: unknown = JSON.parse(text);
      if (parsed && typeof parsed === "object") {
        const record = parsed as { error?: unknown; message?: unknown };
        const raw = record.error ?? record.message;
        if (typeof raw === "string" && raw.length > 0) {
          message = raw;
        }
      }
    } catch {
      // 响应体不是 JSON：保留默认信息。
    }
    throw new ApiError(response.status, message);
  }

  return JSON.parse(text) as T;
}
