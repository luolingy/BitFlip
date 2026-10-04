/**
 * M6 分析视图：调用图、数据/代码判定、跳转表。
 *
 * 这三个视图的共同点：它们展示的都是**结论 + 依据**，而不是原始数据。
 * 所以每个视图都必须回答用户的同一个问题：「你凭什么这么说？」
 *
 * 具体到这一层（沿用 M3 视图确立的原则，CLAUDE.md §7）：
 *
 * - 调用图必须显示**未解析的间接调用数** —— 这张图本来就不完整，
 *   藏起来等于假装完整；
 * - 数据/代码判定必须显示**未判定的比例**与**判定理由** ——
 *   "未判定"多不是坏事，说明系统没硬凑结论；
 * - 跳转表必须显示**表项语义**（相对基址还是绝对）—— 不给这个，
 *   用户没法核对算出来的目标对不对。
 */

import { useCallback, useEffect, useState } from "react";

import {
  fetchCallGraph,
  fetchCodeMap,
  fetchFunctions,
  fetchJumpTables,
  formatAddress,
  normalizeAddress,
  type CallGraphResponse,
  type CodeMapResponse,
  type FunctionWire,
  type JumpTablesResponse,
} from "./api";

/** 一页的加载状态。 */
type Loaded<T> =
  | { kind: "loading" }
  | { kind: "ready"; data: T | null }
  | { kind: "error"; message: string };

/** 复用的加载钩子：处理取消与错误，避免每个视图各写一遍。 */
function useLoaded<T>(
  load: () => Promise<T | null>,
  deps: unknown[],
): Loaded<T> {
  const [state, setState] = useState<Loaded<T>>({ kind: "loading" });
  useEffect(() => {
    let cancelled = false;
    setState({ kind: "loading" });
    void load().then(
      (data) => {
        if (!cancelled) {
          setState({ kind: "ready", data });
        }
      },
      (error: unknown) => {
        if (!cancelled) {
          setState({
            kind: "error",
            message: error instanceof Error ? error.message : String(error),
          });
        }
      },
    );
    return () => {
      cancelled = true;
    };
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, deps);
  return state;
}

/**
 * 调用图视图。
 *
 * # 为什么默认不是"全图"
 *
 * 验收标准要的是 1 万函数规模可交互。1 万个节点画出来是一团糊 ——
 * 真实使用永远是**先定位一个函数，再看它的邻居**。所以这里：
 *
 * 1. 先给全图**汇总**（节点/边/未解析数/递归情况），让用户看到形状；
 * 2. 选中一个函数后才拉它的邻域（深度可选），渲染成两张列表；
 * 3. 未解析的间接调用单独列出，并说明为什么没有目标。
 *
 * 用列表而不是力导向图：1 万节点的力导向布局既慢又不可读，
 * 而"谁调用我 / 我调用谁"这两问用列表回答得最准确。图形化留给
 * 后续里程碑。
 */
export function CallGraphView({
  token,
  onNavigate,
}: {
  token: string | null;
  onNavigate: (address: string) => void;
}) {
  // 全图汇总
  const overview = useLoaded<CallGraphResponse>(
    () => fetchCallGraph(token, null, 1),
    [token],
  );

  // 可选：从函数列表里挑一个来展开邻域
  const functions = useLoaded<{ functions: FunctionWire[] }>(
    () => fetchFunctions(token, null, 200),
    [token],
  );

  const [focus, setFocus] = useState<string | null>(null);
  const [depth, setDepth] = useState(1);
  const [neighbourhood, setNeighbourhood] = useState<Loaded<CallGraphResponse>>({
    kind: "loading",
  });

  const loadNeighbourhood = useCallback(
    (entry: string, d: number) => {
      setNeighbourhood({ kind: "loading" });
      void fetchCallGraph(token, entry, d).then(
        (data) => setNeighbourhood({ kind: "ready", data }),
        (error: unknown) =>
          setNeighbourhood({
            kind: "error",
            message: error instanceof Error ? error.message : String(error),
          }),
      );
    },
    [token],
  );

  const pick = useCallback(
    (entry: string, d: number) => {
      setFocus(entry);
      setDepth(d);
      loadNeighbourhood(entry, d);
    },
    [loadNeighbourhood],
  );

  if (overview.kind === "loading") {
    return <div className="banner">正在构建调用图…（大目标需要十几秒）</div>;
  }
  if (overview.kind === "error") {
    return <div className="banner banner-error">{overview.message}</div>;
  }
  if (!overview.data) {
    return <div className="banner">本次会话没有可分析的目标。</div>;
  }

  const { summary, notes, returned_edges, truncated_edges } = overview.data;
  const fnList = functions.kind === "ready" && functions.data ? functions.data.functions : [];

  return (
    <div className="analysis-view">
      <div className="view-toolbar">
        <span className="hint">
          调用图：<strong>{summary.nodes}</strong> 个函数节点，
          <strong>{summary.edges}</strong> 条调用边
          {truncated_edges > 0 && (
            <>
              （本次只返回 <strong>{returned_edges}</strong> 条，
              另 {truncated_edges} 条未返回）
            </>
          )}
        </span>
      </div>

      {/* 截断必须紧挨着结论说，不能只在 notes 里提一句 ——
          否则上面那行数字与下面的列表对不上，看起来像丢了数据 */}
      {truncated_edges > 0 && (
        <div className="banner banner-warn">
          边数超过单次返回上限，已截断为前 {returned_edges} 条，
          另有 <strong>{truncated_edges}</strong> 条未返回。
          请用下面的函数列表展开单个函数的邻域来查看完整关系。
        </div>
      )}

      {/* 图的不完整性必须显示在最显眼的位置 */}
      {summary.unresolved_indirect > 0 && (
        <div className="banner banner-warn">
          有 <strong>{summary.unresolved_indirect}</strong> 处间接调用
          （寄存器/内存寻址）解析不了目标。解析它们需要数据流分析，
          M6 未实现 —— 所以这张图**是不完整的**：这些调用点在图上是断开的，
          被它们调用的函数会显示成"没人调用"。
        </div>
      )}

      <div className="summary-grid">
        <div className="summary-card">
          <span className="summary-label">没有调用者的函数</span>
          <span className="summary-value mono">{summary.roots}</span>
          <span className="summary-hint">
            不等于死代码 —— 被间接调用的函数也会落在这里
          </span>
        </div>
        <div className="summary-card">
          <span className="summary-label">强连通分量</span>
          <span className="summary-value mono">{summary.components}</span>
          <span className="summary-hint">
            最大分量 {summary.largest_component}
            {summary.largest_component > 1 ? "（存在互相调用/递归）" : ""}
          </span>
        </div>
        <div className="summary-card">
          <span className="summary-label">目标落在已知函数外</span>
          <span className="summary-value mono">{summary.outside_targets}</span>
          <span className="summary-hint">
            跳转表目标、thunk、编译器辅助块等，未被当成函数
          </span>
        </div>
      </div>

      {notes.length > 0 && (
        <ul className="notes notes-inline">
          {notes.map((note) => (
            <li key={note}>{note}</li>
          ))}
        </ul>
      )}

      <h3 className="section-title">查看某个函数的调用关系</h3>
      <div className="view-toolbar">
        <label className="hint">
          邻域深度{" "}
          <select
            className="input input-small"
            value={depth}
            onChange={(event) => {
              const d = Number(event.target.value);
              setDepth(d);
              if (focus) {
                loadNeighbourhood(focus, d);
              }
            }}
          >
            <option value={1}>1 跳</option>
            <option value={2}>2 跳</option>
            <option value={3}>3 跳</option>
          </select>
        </label>
        {focus && (
          <span className="hint mono">
            当前聚焦 {formatAddress(focus)}
          </span>
        )}
      </div>

      {fnList.length === 0 ? (
        <p className="hint">没有函数可展开。</p>
      ) : (
        <div className="table-wrap table-wrap-short">
          <table className="data-table">
            <thead>
              <tr>
                <th>函数</th>
                <th>名称</th>
                <th>操作</th>
              </tr>
            </thead>
            <tbody>
              {fnList.map((fn) => (
                <tr key={fn.start} className={focus === fn.start ? "row-active" : ""}>
                  <td className="mono">{formatAddress(fn.start)}</td>
                  <td>
                    {fn.named ? (
                      fn.name
                    ) : (
                      <span className="unknown">未命名</span>
                    )}
                  </td>
                  <td>
                    <button className="link-button" onClick={() => pick(fn.start, depth)}>
                      展开邻域
                    </button>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}

      {focus && <NeighbourhoodPanel state={neighbourhood} onNavigate={onNavigate} />}
    </div>
  );
}

function NeighbourhoodPanel({
  state,
  onNavigate,
}: {
  state: Loaded<CallGraphResponse>;
  onNavigate: (address: string) => void;
}) {
  if (state.kind === "loading") {
    return <div className="banner">正在取邻域…</div>;
  }
  if (state.kind === "error") {
    return <div className="banner banner-error">{state.message}</div>;
  }
  if (!state.data) {
    return <div className="banner">该地址没有调用图数据。</div>;
  }

  const { edges, focus, unresolved } = state.data;
  const callers = edges.filter((e) => e.callee === focus);
  const callees = edges.filter((e) => e.caller === focus);

  return (
    <div className="neighbourhood">
      <h3 className="section-title">
        调用关系（{state.data.depth} 跳，{state.data.nodes.length} 个节点）
      </h3>

      <div className="neighbour-grid">
        <div>
          <h4 className="sub-title">谁调用了它（{callers.length}）</h4>
          {callers.length === 0 ? (
            <p className="hint">
              没有记录到调用者。可能是从外部进入（入口点/导出），
              也可能是被间接调用 —— 那种情况解析不了。
            </p>
          ) : (
            <ul className="ref-list">
              {callers.map((e) => (
                <li key={`in-${e.caller}-${e.callee}`}>
                  <button className="link-button mono" onClick={() => onNavigate(e.caller)}>
                    {formatAddress(e.caller)}
                  </button>
                </li>
              ))}
            </ul>
          )}
        </div>

        <div>
          <h4 className="sub-title">它调用了谁（{callees.length}）</h4>
          {callees.length === 0 ? (
            <p className="hint">没有记录到被调用者。</p>
          ) : (
            <ul className="ref-list">
              {callees.map((e) => (
                <li key={`out-${e.caller}-${e.callee}`}>
                  <button className="link-button mono" onClick={() => onNavigate(e.callee)}>
                    {formatAddress(e.callee)}
                  </button>
                  {e.tail && <span className="chip chip-small">尾调用</span>}
                </li>
              ))}
            </ul>
          )}
        </div>
      </div>

      {unresolved.length > 0 && (
        <div className="banner banner-warn">
          该函数有 <strong>{unresolved.length}</strong> 处间接调用没有目标，
          未计入上面的列表。调用点：
          <span className="mono">
            {unresolved.map((u) => formatAddress(u.insn)).join("、")}
          </span>
        </div>
      )}
    </div>
  );
}

/**
 * 数据/代码判定视图。
 *
 * 核心是让用户看到「系统在哪儿不确定」。`decided_ratio` 低不是缺陷 ——
 * 硬凑结论才是。所以这里把"未判定"和"已判定"摆在一起显示，
 * 并把判定的**理由**逐条列出来。
 */
export function CodeMapView({ token }: { token: string | null }) {
  const state = useLoaded<CodeMapResponse>(() => fetchCodeMap(token), [token]);

  if (state.kind === "loading") {
    return <div className="banner">正在判定数据与代码…</div>;
  }
  if (state.kind === "error") {
    return <div className="banner banner-error">{state.message}</div>;
  }
  if (!state.data) {
    return <div className="banner">本次会话没有可分析的目标。</div>;
  }

  const { stats, samples, notes } = state.data;
  const total = stats.code + stats.data + stats.unknown;
  const pct = (n: number) => (total === 0 ? 0 : Math.round((n / total) * 100));

  return (
    <div className="analysis-view">
      <div className="view-toolbar">
        <span className="hint">
          抽样判定 <strong>{total}</strong> 个地址（段头 + 函数入口），
          不是全量统计
        </span>
      </div>

      <div className="summary-grid">
        <div className="summary-card">
          <span className="summary-label">代码</span>
          <span className="summary-value mono">{stats.code}</span>
          <span className="summary-hint">{pct(stats.code)}%</span>
        </div>
        <div className="summary-card">
          <span className="summary-label">数据</span>
          <span className="summary-value mono">{stats.data}</span>
          <span className="summary-hint">{pct(stats.data)}%</span>
        </div>
        <div className="summary-card">
          <span className="summary-label">未判定</span>
          <span className="summary-value mono">{stats.unknown}</span>
          <span className="summary-hint">
            {pct(stats.unknown)}% —— 判不出来就说判不出来，不硬凑结论
          </span>
        </div>
      </div>

      {notes.length > 0 && (
        <ul className="notes notes-inline">
          {notes.map((note) => (
            <li key={note}>{note}</li>
          ))}
        </ul>
      )}

      <h3 className="section-title">判定样本与依据</h3>
      <div className="table-wrap">
        <table className="data-table">
          <thead>
            <tr>
              <th>地址</th>
              <th>结论</th>
              <th>置信度</th>
              <th>依据</th>
            </tr>
          </thead>
          <tbody>
            {samples.map((s) => (
              <tr key={s.addr}>
                <td className="mono">{formatAddress(s.addr)}</td>
                <td>
                  <span className={`chip chip-small chip-${s.kind}`}>
                    {s.kind_label}
                  </span>
                  {/* 没有硬证据支撑的结论要标出来，别让它看起来一样可信 */}
                  {!s.well_supported && s.kind !== "unknown" && (
                    <span className="unknown" title="没有高可信证据支撑这个结论">
                      {" "}
                      证据不足
                    </span>
                  )}
                </td>
                <td className="mono">{s.confidence}</td>
                <td className="reason-cell">{s.reason}</td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </div>
  );
}

/**
 * 跳转表视图。
 *
 * 每个表都要显示**表项语义**（相对基址 / 相对指令 / 绝对）与宽度。
 * 不给这两样，用户看到一个目标列表没法核对 —— 而算错语义正是
 * 实现过程中真出现过的 bug（符号扩展、RIP 相对）。
 */
export function JumpTablesView({
  token,
  onNavigate,
}: {
  token: string | null;
  onNavigate: (address: string) => void;
}) {
  const state = useLoaded<JumpTablesResponse>(() => fetchJumpTables(token), [token]);

  if (state.kind === "loading") {
    return <div className="banner">正在识别跳转表…</div>;
  }
  if (state.kind === "error") {
    return <div className="banner banner-error">{state.message}</div>;
  }
  if (!state.data) {
    return <div className="banner">本次会话没有可分析的目标。</div>;
  }

  const { tables, notes } = state.data;

  return (
    <div className="analysis-view">
      <div className="view-toolbar">
        <span className="hint">
          识别出 <strong>{tables.length}</strong> 张跳转表
        </span>
      </div>

      {tables.length === 0 ? (
        <p className="hint">
          没有识别出跳转表。这可能是目标里确实没有 `switch` 密集分派，
          也可能是分派被编译成了比较链或二叉树。
        </p>
      ) : (
        tables.map((table) => (
          <div className="jump-table" key={`${table.insn_addr}-${table.base}`}>
            <div className="jump-table-header">
              <span className="mono">
                间接跳转 <strong>{formatAddress(table.insn_addr)}</strong>
              </span>
              <span className="chip chip-small">基址 {formatAddress(table.base)}</span>
              <span className="chip chip-small">{table.width} 字节/项</span>
              <span className="chip chip-small">{table.kind_zh}</span>
              <span className="chip chip-small">{table.count} 项</span>
            </div>
            <div className="target-list">
              {table.targets.map((t) => (
                <button
                  key={t}
                  className="link-button mono target"
                  onClick={() => onNavigate(t)}
                >
                  {formatAddress(t)}
                </button>
              ))}
            </div>
          </div>
        ))
      )}

      {notes.length > 0 && (
        <ul className="notes notes-inline">
          {notes.map((note) => (
            <li key={note}>{note}</li>
          ))}
        </ul>
      )}
    </div>
  );
}

/** 地址跳转框（与 M3 视图同形，供调用图里快速回跳用）。 */
export function AddressJump({ onJump }: { onJump: (address: string) => void }) {
  const [text, setText] = useState("");
  const [invalid, setInvalid] = useState(false);

  const submit = () => {
    const normalized = normalizeAddress(text);
    if (!normalized) {
      // 非法输入不做任何事并标记：悄悄回退到 0 会让人以为跳成功了。
      setInvalid(true);
      return;
    }
    setInvalid(false);
    onJump(normalized);
  };

  return (
    <div className="jump-box">
      <input
        className={invalid ? "input input-invalid" : "input"}
        placeholder="跳转到地址（十六进制）"
        value={text}
        onChange={(event) => setText(event.target.value)}
        onKeyDown={(event) => {
          if (event.key === "Enter") {
            submit();
          }
        }}
      />
      <button onClick={submit}>跳转</button>
      {invalid && <span className="unknown"> 地址格式不认识</span>}
    </div>
  );
}
