/**
 * 与本地 BitFlip 服务通信。
 *
 * 令牌来源（按优先级）：URL 片段 `#token=` → 查询串 `?token=` → sessionStorage。
 * 取到后立刻把 URL 里的令牌擦掉，避免它出现在截图、浏览历史或 Referer 里。
 */

const TOKEN_STORAGE_KEY = "bitflip.token";

/** 服务返回的目标识别结论。字段与 `bitflip-core::TargetInfo` 一一对应。 */
export interface TargetInfo {
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
