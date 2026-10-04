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
export interface XrefWire {  /** 引用发出的地址。 */
  from: string;
  /** 被引用的地址。 */
  to: string;
  /** 类型短名：`call` / `jump` / `data`。 */
  kind: string;
}

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

/** 一条用户标注。对应 `bitflip-project::Annotation`。 */
export interface Annotation {
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

/** 取函数列表；无目标或不可分析时返回 `null`（服务端 400 带原因）。 */
export async function fetchFunctions(
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

/** 取某地址的交叉引用。 */
export async function fetchXrefs(
  token: string | null,
  address: string,
): Promise<XrefsResponse | null> {
  const params = new URLSearchParams({ address });
  return requestOrNull<XrefsResponse>(`/api/xrefs?${params.toString()}`, token);
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
