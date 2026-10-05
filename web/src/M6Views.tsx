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
  fetchArgScan,
  fetchCallGraph,
  fetchCodeMap,
  fetchConstScan,
  fetchFunctions,
  fetchFrames,
  fetchJumpTables,
  formatAddress,
  normalizeAddress,
  type ArgScanResponse,
  type CallGraphResponse,
  type CodeMapResponse,
  type ConstScanResponse,
  type FunctionWire,
  type FrameScanResponse,
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

/** 地址跳转框（与 M3 视图同形，供调用图里快速回跳用）。 */export function AddressJump({ onJump }: { onJump: (address: string) => void }) {
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

/**
 * 常量 / 结构体初步推断。
 *
 * # 界面上必须让人看出"这是观测事实，不是结构体定义"
 *
 * 后端只给三样东西：哪些字符串被谁引用、某个基址上看到过哪些位移、
 * 哪些立即数出现得多。**没有字段名，也没有字段类型** —— 没有调试信息
 * 就没有名字，编一个 `struct_1` 是禁止的。这里照实呈现，并在显眼处
 * 说明这一点，免得用户以为没显示名字是因为界面太窄。
 */
export function ConstScanView({ token }: { token: string | null }) {
  const loaded = useLoaded<ConstScanResponse>(
    () => fetchConstScan(token),
    [token],
  );

  if (loaded.kind === "loading") {
    return <p className="hint">正在加载常量分析…</p>;
  }
  if (loaded.kind === "error") {
    return <p className="error">加载失败：{loaded.message}</p>;
  }
  if (loaded.data === null) {
    return <p className="hint">尚未打开目标。</p>;
  }

  const scan = loaded.data;

  return (
    <div className="m6-view">
      <p className="banner-note">
        以下是**从指令里观测到的事实**：哪些字符串被引用、某个基址上
        出现过哪些位移、哪些立即数出现得多。这里**没有字段名和字段类型**
        —— 没有调试信息就没有名字，编一个 <code>struct_1</code> 属于造假，
        所以不编。
      </p>

      <section>
        <h3 className="section-title">
          字符串引用（{scan.strings.length} 条）
        </h3>
        {scan.strings.length === 0 ? (
          <p className="hint">
            没有观测到指令直接引用字符串。可能是间接传递（经寄存器、
            经跳转表），本版不做数据流分析。
          </p>
        ) : (
          <div className="table-wrap-short">
            <table>
              <thead>
                <tr>
                  <th>字符串地址</th>
                  <th>引用函数</th>
                  <th>引用点</th>
                </tr>
              </thead>
              <tbody>
                {scan.strings.map((s) => (
                  <tr key={s.address}>
                    <td className="mono">{s.address}</td>
                    <td>
                      {s.functions.length === 0 ? (
                        // 引用点可能落在所有已知函数之外 —— 如实说，
                        // 不要归到某个"最近的函数"上
                        <span className="unknown">不在已知函数内</span>
                      ) : (
                        <span className="ref-list">
                          {s.functions.map((f) => (
                            <button
                              key={f}
                              className="link-button mono"
                              title={f}
                            >
                              {f.slice(-6)}
                            </button>
                          ))}
                        </span>
                      )}
                    </td>
                    <td className="mono num">{s.sites.length}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </section>

      <section>
        <h3 className="section-title">内存访问位移（{scan.strides.length} 组）</h3>
        {scan.strides.length === 0 ? (
          <p className="hint">没有观测到带固定基址寄存器的内存访问。</p>
        ) : (
          <div className="table-wrap-short">
            <table>
              <thead>
                <tr>
                  <th>基址寄存器</th>
                  <th>宽度</th>
                  <th>步长</th>
                  <th>观测到的位移</th>
                </tr>
              </thead>
              <tbody>
                {scan.strides.map((s) => (
                  <tr key={`${s.base}-${s.width}`}>
                    <td className="mono">reg#{s.base}</td>
                    <td className="num">{s.width}</td>
                    <td className="num">
                      {s.stride === null ? (
                        // 推不出来时显示"不确定"，**不显示 0** ——
                        // 0 是个看起来合理的值，会让人以为步长就是 0
                        <span className="unknown" title="位移间隔不一致，推不出步长">
                          不确定
                        </span>
                      ) : (
                        s.stride
                      )}
                    </td>
                    <td className="mono">
                      {s.offsets
                        .slice(0, 12)
                        .map((o) => `+${o.toString(16)}`)
                        .join(" ")}
                      {s.offsets.length > 12 && ` …共 ${s.offsets.length} 个`}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </section>

      <section>
        <h3 className="section-title">
          高频立即数（{scan.immediates.length} / {scan.immediate_distinct} 种）
        </h3>
        <p className="hint">
          合计观测到 {scan.immediate_total} 个立即数，去重后{" "}
          {scan.immediate_distinct} 种。
        </p>
        {scan.immediates.length === 0 ? (
          <p className="hint">没有观测到立即数。</p>
        ) : (
          <div className="table-wrap-short">
            <table>
              <thead>
                <tr>
                  <th>值（十进制 / 十六进制）</th>
                  <th>出现次数</th>
                </tr>
              </thead>
              <tbody>
                {scan.immediates.map((i) => (
                  <tr key={i.value}>
                    <td className="mono">
                      {i.value}
                      <span className="unknown"> / {immediateHex(i.value)}</span>
                    </td>
                    <td className="num">{i.count}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </section>

      <Notes notes={scan.notes} />
    </div>
  );
}

/**
 * 把十进制的立即数显示成十六进制。
 *
 * 后端给的是**十进制字符串**（避免 JSON 大整数在 JS 侧被截断），
 * 而反汇编里的人习惯看十六进制 —— 两种都给。用 `BigInt` 而不是
 * `Number`：目标里的立即数可能超过 2^53，`Number` 会静默变形。
 */
function immediateHex(value: string): string {
  try {
    const n = BigInt(value);
    return n < 0n ? `-0x${(-n).toString(16)}` : `0x${n.toString(16)}`;
  } catch {
    // 解析不了就如实说，不要硬凑一个数
    return "无法解析";
  }
}

export function FrameScanView({ token }: { token: string | null }) {
  const loaded = useLoaded<FrameScanResponse>(() => fetchFrames(token), [token]);
  const [filter, setFilter] = useState("");

  if (loaded.kind === "loading") return <p className="hint">正在加载栈帧视图…</p>;
  if (loaded.kind === "error") return <p className="error">加载失败：{loaded.message}</p>;
  if (loaded.data === null) return <p className="hint">尚未打开目标。</p>;

  const scan = loaded.data;
  if (scan.abi_name === null) {
    return (
      <div className="m6-view">
        <p className="banner-warn">该架构没有可用的调用约定，因此栈帧视图不适用。</p>
        <Notes notes={scan.notes} />
      </div>
    );
  }

  const functions = scan.functions.filter((f) =>
    filter.length === 0 ? true : f.entry.includes(filter.toLowerCase()),
  );
  const withFrame = scan.functions.filter((f) => f.frame_size !== null).length;
  const withUnwind = scan.functions.filter((f) => f.unwind_frame_size !== null).length;
  const agreed = scan.functions.filter((f) => f.source.includes("一致") && !f.source.includes("不一致")).length;

  return (
    <div className="m6-view">
      <div className="summary-grid">
        <div className="summary-card">
          <div className="summary-label">调用约定</div>
          <div className="summary-value">{scan.abi_name}</div>
          <div className="summary-hint">帧大小来自展开信息与前导扫描</div>
        </div>
        <div className="summary-card">
          <div className="summary-label">帧大小</div>
          <div className="summary-value">{withFrame} / {scan.functions.length}</div>
          <div className="summary-hint">有确定结论的函数</div>
        </div>
        <div className="summary-card">
          <div className="summary-label">交叉核对</div>
          <div className="summary-value">{agreed}</div>
          <div className="summary-hint">两个来源一致</div>
        </div>
      </div>

      <p className="banner-note">
        展开信息是编译器生成的权威数据；前导扫描用于补充与核对。两个来源不一致时，
        表中同时保留两个值，不能把分歧隐藏成一个数字。
      </p>
      <p className="summary-hint">有展开信息细节：{withUnwind} 个函数</p>
      <input
        className="input input-small"
        placeholder="按函数入口地址筛选"
        value={filter}
        onChange={(event) => setFilter(event.target.value)}
      />

      <div className="table-wrap-short">
        <table>
          <thead>
            <tr>
              <th>入口</th>
              <th>帧大小</th>
              <th>来源</th>
              <th>保存寄存器</th>
              <th>帧指针</th>
              <th>前导长度</th>
            </tr>
          </thead>
          <tbody>
            {functions.map((f) => (
              <tr key={f.entry}>
                <td className="mono">{f.entry}</td>
                <td className="num">
                  {f.frame_size === null ? <span className="unknown">未知</span> : `${f.frame_size} B`}
                  {(f.unwind_frame_size !== f.prologue_frame_size) && (
                    <div className="subvalue">展开 {f.unwind_frame_size ?? "未知"} / 前导 {f.prologue_frame_size ?? "未知"}</div>
                  )}
                </td>
                <td>{f.source}</td>
                <td>
                  {f.saved_registers.length === 0 ? (
                    <span className="unknown">无</span>
                  ) : (
                    <span className="ref-list">
                      {f.saved_registers.map((reg) => <span className="chip-code" key={reg}>{reg}</span>)}
                    </span>
                  )}
                </td>
                <td>{f.frame_pointer ?? <span className="unknown">无</span>}</td>
                <td className="num">{f.prologue_len === null ? <span className="unknown">未知</span> : `${f.prologue_len} B`}</td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
      {functions.length === 0 && <p className="hint">没有匹配的函数。</p>}
      <Notes notes={scan.notes} />
    </div>
  );
}

/**
 * 调用约定与参数推断。
 *
 * 后端给的是"至少有几个参数"，不是"有几个参数"。没有调试信息时，
 * 参数寄存器没被读到**不等于**没有这个参数（可能只被透传、或者一进
 * 函数就存到栈上）。所以这里一律显示成"≥ N"，并在表头写明理由 ——
 * 直接显示 N 会让人当成确切个数。
 */
export function ArgScanView({ token }: { token: string | null }) {
  const loaded = useLoaded<ArgScanResponse>(() => fetchArgScan(token), [token]);
  const [filter, setFilter] = useState("");

  if (loaded.kind === "loading") {
    return <p className="hint">正在加载参数推断…</p>;
  }
  if (loaded.kind === "error") {
    return <p className="error">加载失败：{loaded.message}</p>;
  }
  if (loaded.data === null) {
    return <p className="hint">尚未打开目标。</p>;
  }

  const scan = loaded.data;

  if (scan.abi_name === null) {
    // 该架构没有寄存器级约定（如 wasm32）。说清是"不适用"，
    // 而不是让用户以为"这些函数都没有参数"。
    return (
      <div className="m6-view">
        <p className="banner-warn">
          该架构没有寄存器级调用约定（例如 WebAssembly 用栈式传参），
          因此不提供参数推断 —— 这是**这项能力不适用**，不是
          "这些函数没有参数"。
        </p>
        <Notes notes={scan.notes} />
      </div>
    );
  }

  const functions = scan.functions.filter((f) =>
    filter.length === 0 ? true : f.entry.includes(filter.toLowerCase()),
  );

  // 下界分布：一眼看出整体是否合理（全都 0 或全都满都说明判据有问题）
  const histogram = new Map<number, number>();
  for (const f of scan.functions) {
    histogram.set(f.lower_bound, (histogram.get(f.lower_bound) ?? 0) + 1);
  }
  const buckets = [...histogram.entries()].sort((a, b) => a[0] - b[0]);

  return (
    <div className="m6-view">
      <div className="summary-grid">
        <div className="summary-card">
          <div className="summary-label">调用约定</div>
          <div className="summary-value">{scan.abi_name}</div>
          <div className="summary-hint">
            参数寄存器：{scan.arg_reg_names.join("、")}
          </div>
        </div>
        <div className="summary-card">
          <div className="summary-label">函数</div>
          <div className="summary-value">{scan.functions.length}</div>
          <div className="summary-hint">
            从栈取参：
            {scan.functions.filter((f) => f.reads_stack_args).length} 个
          </div>
        </div>
        <div className="summary-card">
          <div className="summary-label">参数下界分布</div>
          <div className="summary-value">{buckets.length} 种</div>
          <div className="summary-hint">
            {buckets.map(([k, v]) => `${k}:${v}`).join("  ")}
          </div>
        </div>
      </div>

      <p className="banner-note">
        表中的数字是**参数个数的下界**（至少这么多），不是确切个数。
        没有调试信息时，参数寄存器没被读到不等于没有这个参数 ——
        它可能只被透传给别的调用，或者一进函数就存到栈上后再也没读。
      </p>

      <input
        className="input input-small"
        placeholder="按函数入口地址筛选"
        value={filter}
        onChange={(event) => setFilter(event.target.value)}
      />

      <div className="table-wrap-short">
        <table>
          <thead>
            <tr>
              <th>入口</th>
              <th>至少</th>
              <th>用到的参数寄存器</th>
              <th>指令数</th>
              <th>栈参数</th>
            </tr>
          </thead>
          <tbody>
            {functions.map((f) => (
              <tr key={f.entry}>
                <td className="mono">{f.entry}</td>
                <td className="num">≥ {f.lower_bound}</td>
                <td>
                  {f.used_names.length === 0 ? (
                    <span className="unknown">未观测到</span>
                  ) : (
                    <span className="ref-list">
                      {f.used.map((slot, i) => (
                        <span
                          key={slot}
                          className="chip-code"
                          title={`第 ${slot + 1} 个参数`}
                        >
                          {f.used_names[i]}
                        </span>
                      ))}
                    </span>
                  )}
                  {f.unobserved_from !== null && (
                    <span className="unknown">
                      {" "}
                      第 {f.unobserved_from + 1} 个起未观测到
                    </span>
                  )}
                </td>
                <td className="num">{f.insn_count}</td>
                <td className="num">
                  {f.reads_stack_args ? (
                    <span title="寄存器传参不够用，参数也走了栈">是</span>
                  ) : (
                    <span className="unknown">无</span>
                  )}
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
      {functions.length === 0 && (
        <p className="hint">没有匹配的函数。</p>
      )}

      <Notes notes={scan.notes} />
    </div>
  );
}

/** 降级/说明列表。没有说明时什么都不渲染，不留空标题。 */
function Notes({ notes }: { notes: string[] }) {
  if (notes.length === 0) {
    return null;
  }
  return (
    <section>
      <h3 className="section-title">说明</h3>
      <ul className="notes">
        {notes.map((n) => (
          <li key={n}>{n}</li>
        ))}
      </ul>
    </section>
  );
}
