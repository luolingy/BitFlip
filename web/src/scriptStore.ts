/**
 * 用户脚本的本地持久化（M7 脚本库的"保存/复用"那一半）。
 *
 * # 为什么不放服务端
 *
 * 服务端是**每次分析一个目标**的一次性进程：`bitflip target.exe` 起来、
 * 服务、退出。把用户脚本存在它旁边，用户关掉窗口脚本就没了 ——
 * 那比不提供保存更糟，因为用户会以为存住了。
 *
 * `localStorage` 按**来源**（scheme + host + port）隔离，而 BitFlip 每次启动
 * 端口都可能不同，所以换一次启动就换一个存储空间。这是本方案最实在的
 * 局限，界面必须把它说出来 —— 不要把"存在浏览器里"说成"存起来了"。
 *
 * # 版本号
 *
 * 键名带 `v1`：脚本对象的结构将来会变，读到不认识的形状时**当作没有**
 * 而不是硬解 —— 一份解析失败就整块清空的实现会让用户丢掉全部脚本。
 */

const SCRIPTS_KEY = "bitflip.script.library.v1";
const DRAFT_KEY = "bitflip.script.draft.v1";

/** 一份用户脚本。 */
export interface UserScript {
  /** 本地生成的标识。 */
  id: string;
  /** 用户起的名字。 */
  name: string;
  /** 源码。 */
  source: string;
  /** 保存时刻（毫秒时间戳）。 */
  saved_at: number;
}

/** 存储不可用（隐私模式、配额满、被策略禁用）。 */
export class ScriptStorageError extends Error {}

function storage(): Storage {
  try {
    const store = window.localStorage;
    if (!store) {
      throw new ScriptStorageError("这个浏览器没有可用的本地存储");
    }
    return store;
  } catch (error) {
    // 访问 `localStorage` 本身就可能抛（隐私模式/被策略禁用），
    // 这里必须自己转成一句话，否则界面只能显示一个空白的错误。
    throw new ScriptStorageError(
      error instanceof Error
        ? `本地存储不可用：${error.message}`
        : "本地存储不可用",
    );
  }
}

function isUserScript(value: unknown): value is UserScript {
  if (!value || typeof value !== "object") {
    return false;
  }
  const record = value as Record<string, unknown>;
  return (
    typeof record.id === "string" &&
    typeof record.name === "string" &&
    typeof record.source === "string" &&
    typeof record.saved_at === "number"
  );
}

/**
 * 读取用户脚本。
 *
 * 单条损坏只丢那一条 —— 一份脚本的 JSON 形状不对，不该让用户失去全部脚本。
 */
export function loadUserScripts(): UserScript[] {
  const raw = storage().getItem(SCRIPTS_KEY);
  if (raw === null) {
    return [];
  }
  let parsed: unknown;
  try {
    parsed = JSON.parse(raw);
  } catch {
    // 整块读不出来：不静默清空（那会毁掉用户唯一的一份），而是报错，
    // 由界面决定要不要覆盖。
    throw new ScriptStorageError("脚本库的内容已损坏，无法解析");
  }
  if (!Array.isArray(parsed)) {
    return [];
  }
  return parsed.filter(isUserScript);
}

function persist(scripts: UserScript[]): void {
  try {
    storage().setItem(SCRIPTS_KEY, JSON.stringify(scripts));
  } catch (error) {
    throw new ScriptStorageError(
      error instanceof Error
        ? `写入本地存储失败：${error.message}`
        : "写入本地存储失败",
    );
  }
}

/** 新建或按名字覆盖一份脚本（同名视为同一份，避免攒出一堆同名副本）。 */
export function saveUserScript(
  scripts: UserScript[],
  name: string,
  source: string,
): UserScript[] {
  const trimmed = name.trim();
  if (trimmed.length === 0) {
    throw new ScriptStorageError("脚本名不能为空");
  }
  const existing = scripts.find((script) => script.name === trimmed);
  const entry: UserScript = {
    id: existing?.id ?? `local-${Date.now().toString(36)}-${Math.floor(Math.random() * 1e6).toString(36)}`,
    name: trimmed,
    source,
    saved_at: Date.now(),
  };
  const next = existing
    ? scripts.map((script) => (script.id === existing.id ? entry : script))
    : [...scripts, entry];
  persist(next);
  return next;
}

/** 删除一份脚本。 */
export function deleteUserScript(scripts: UserScript[], id: string): UserScript[] {
  const next = scripts.filter((script) => script.id !== id);
  persist(next);
  return next;
}

/** 读取编辑器草稿（关掉页面也不会丢）。 */
export function loadDraft(): string | null {
  try {
    return storage().getItem(DRAFT_KEY);
  } catch {
    // 草稿读不出来不该拦住整个控制台 —— 它只是一份便利。
    return null;
  }
}

/** 写编辑器草稿。失败是静默的：每敲一个字都可能触发，弹窗会淹掉界面。 */
export function saveDraft(source: string): void {
  try {
    storage().setItem(DRAFT_KEY, source);
  } catch {
    // 有意忽略：草稿不是用户资产，脚本本身由"保存"按钮负责。
  }
}
