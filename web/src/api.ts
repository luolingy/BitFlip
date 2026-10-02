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
