/**
 * DEX 视图的 URL 状态（放在 hash 里）。
 *
 * # 为什么放在 hash 而不是 query
 *
 * 服务端只按路径提供静态资源与 `/api/*`，没有前端路由；hash 不会发给服务端，
 * 所以类描述符这类"目标文件里的内容"不会出现在服务端的访问日志里。启动时
 * `resolveToken()` 会**只清掉令牌**、保留 hash 里的其他参数（改动见 `api.ts`），
 * 因此刷新之后这一份状态还在。
 *
 * # 有哪些状态、为什么是这几个
 *
 * - `dex=1`：**这一条 hash 是 DEX 视图的状态**。没有这个标记就分不清
 *   "用户想打开 DEX 视图"与"hash 里恰好有个同名参数"；有了它，分享出去的链接
 *   能直接落在 DEX 视图上。
 * - `member`：看哪个 `classes*.dex`（**文件名**，与标签页一一对应）。
 * - `class`：选中的类（smali 描述符）。
 * - `method`：选中的方法（smali 标识）。
 * - `search`：类列表的过滤词（分享链接要能还原"我看到的那个列表"）。
 *
 * 指令分页的页码**不进 URL**：它是"看到第几页"的临时位置，不是"在看哪个方法"，
 * 进 URL 只会让链接又长又脆（而且类详情与方法是按标识取的，与列表翻到第几页无关）。
 *
 * # 为什么用 `replaceState` 而不是 `pushState`
 *
 * 点 20 个类就会压 20 条历史，用户按 20 次"返回"才退得出这个视图 —— 那是把
 * 历史记录当状态存储用。这里要的是**可刷新、可分享**，不是"每次点击都能后退"。
 * 外部改动 hash（粘贴一条链接）仍然会被 `subscribeDexHash` 接住并应用。
 */

/** DEX 视图的 URL 状态。 */
export interface DexUrlState {
  /** 这条 hash 是否在说"打开 DEX 视图"。 */
  active: boolean;
  /** 看哪个 DEX（成员名 / 文件名）。 */
  member: string | null;
  /** 选中的类（smali 描述符）。 */
  descriptor: string | null;
  /** 选中的方法（smali 标识）。 */
  method: string | null;
  /** 类列表的过滤词。 */
  search: string | null;
}

/** URL 参数名（集中在一处，免得写入与读取各写一遍字符串）。 */
const KEY_MARKER = "dex";
const KEY_MEMBER = "member";
const KEY_CLASS = "class";
const KEY_METHOD = "method";
const KEY_SEARCH = "search";

function currentParams(): URLSearchParams {
  return new URLSearchParams(window.location.hash.replace(/^#/, ""));
}

/** 把参数还原成 hash（空参数表就是空串，不留一个孤零零的 `#`）。 */
function hashOf(params: URLSearchParams): string {
  const rest = params.toString();
  return rest ? `#${rest}` : "";
}

/** 读一小段值：空串与缺失都算"没有"（`search=` 不该被当成"搜空串"）。 */
function pick(params: URLSearchParams, key: string): string | null {
  const value = params.get(key);
  return value === null || value === "" ? null : value;
}

function setOrDelete(params: URLSearchParams, key: string, value: string | null): void {
  if (value === null || value === "") {
    params.delete(key);
  } else {
    params.set(key, value);
  }
}

/** 读当前 URL 里的 DEX 状态（视图挂载时与 hash 被外部改动时各读一次）。 */
export function readDexUrl(): DexUrlState {
  const params = currentParams();
  return {
    active: params.get(KEY_MARKER) === "1",
    member: pick(params, KEY_MEMBER),
    descriptor: pick(params, KEY_CLASS),
    method: pick(params, KEY_METHOD),
    search: pick(params, KEY_SEARCH),
  };
}

/**
 * 把 DEX 状态写回 URL。
 *
 * **保留其它参数**（例如启动时 hash 里可能还留着 `token`）：这个视图只拥有自己
 * 那几个键，把别人的参数删掉会让"令牌只剩内存里那一份"这类既有行为悄悄变掉。
 */
export function writeDexUrl(state: {
  member: string | null;
  descriptor: string | null;
  method: string | null;
  search: string | null;
}): void {
  const params = currentParams();
  params.set(KEY_MARKER, "1");
  setOrDelete(params, KEY_MEMBER, state.member);
  setOrDelete(params, KEY_CLASS, state.descriptor);
  setOrDelete(params, KEY_METHOD, state.method);
  setOrDelete(params, KEY_SEARCH, state.search);

  const next = hashOf(params);
  // 只在真的变了才动 URL：每次渲染都 replaceState 会把浏览器的 URL 编辑
  // 与前进/后退记录搅乱（也是无谓的 history 操作）。
  if (next !== window.location.hash) {
    window.history.replaceState(null, "", window.location.pathname + next);
  }
}

/**
 * 订阅 hash 的外部改动（粘贴链接、手改地址栏）。
 *
 * `replaceState` **不会**触发 `hashchange`，所以这里不会和 `writeDexUrl` 形成回环。
 * 返回取消订阅的函数。
 */
export function subscribeDexHash(listener: () => void): () => void {
  window.addEventListener("hashchange", listener);
  return () => window.removeEventListener("hashchange", listener);
}
