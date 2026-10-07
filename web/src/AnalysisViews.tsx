/**
 * M3 分析视图：函数、交叉引用、字符串、十六进制。
 *
 * 贯穿这四个视图的一条原则（CLAUDE.md §7）：
 * **不确定的东西要显示成不确定**，而不是填一个看起来合理的值。
 *
 * - 函数边界未知 → 显示「未知」，不显示 0 或猜一个范围；
 * - 函数没名字 → 显示「未命名」，不生成 `func_xxx`；
 * - 地址不在任何已知函数里 → 明说，不挑一个最近的函数塞进去；
 * - 读到段尾 → 显示「已到段尾」并给出实际字节数，不用零填充凑满。
 */

import { useCallback, useEffect, useState } from "react";

import {
  ANNOTATION_KIND_LABELS,
  STRING_ENCODING_LABELS,
  XREF_KIND_LABELS,
  XREF_SOURCE_LABELS,
  deleteAnnotation,
  fetchAnnotations,
  fetchFunctions,
  fetchHex,
  fetchStrings,
  fetchXrefs,
  formatAddress,
  formatSourcePosition,
  formatSize,
  normalizeAddress,
  putAnnotation,
  type Annotation,
  type FunctionWire,
  type HexResponse,
  type StringsResponse,
  type XrefsResponse,
} from "./api";

const PAGE_SIZE = 200;

/** 一页的加载状态。 */
type Loaded<T> =
  | { kind: "loading" }
  | { kind: "ready"; data: T | null }
  | { kind: "error"; message: string };

/** 把任意地址输入解析成定长十六进制；失败时返回 `null`。 */
function useAddressJump(onJump: (address: string) => void) {
  const [text, setText] = useState("");
  const [invalid, setInvalid] = useState(false);

  const submit = useCallback(() => {
    const normalized = normalizeAddress(text);
    if (!normalized) {
      // 输入非法就**什么都不做**并标记：悄悄回退到 0 会让用户
      // 以为自己跳转成功了，其实只是回到了文件开头。
      setInvalid(true);
      return;
    }
    setInvalid(false);
    onJump(normalized);
  }, [text, onJump]);

  return { text, setText, invalid, submit };
}

function AddressJumpBox({
  label,
  onJump,
}: {
  label: string;
  onJump: (address: string) => void;
}) {
  const { text, setText, invalid, submit } = useAddressJump(onJump);
  return (
    <div className="jump-box">
      <input
        className={invalid ? "input input-invalid" : "input"}
        placeholder={label}
        value={text}
        onChange={(event) => setText(event.target.value)}
        onKeyDown={(event) => {
          if (event.key === "Enter") {
            submit();
          }
        }}
        aria-invalid={invalid}
      />
      <button type="button" onClick={submit}>
        跳转
      </button>
      {invalid && <span className="error-inline">地址无效（需要 16 进制）</span>}
    </div>
  );
}

/** 函数名显示：未命名就叫未命名，不造占位名。 */
function FunctionName({ fn }: { fn: FunctionWire }) {
  if (!fn.named) {
    return <span className="unnamed">未命名</span>;
  }
  return <span className="mono symbol-name">{fn.name}</span>;
}

/**
 * 函数视图。
 *
 * 每个函数都显示**来源与置信度**：用户需要能回答"为什么这里被当成函数"，
 * 否则一个错误识别的函数和一个确信的函数看起来一模一样。
 */
export function FunctionsView({
  token,
  onNavigate,
}: {
  token: string | null;
  onNavigate: (address: string) => void;
}) {
  const [state, setState] = useState<Loaded<Awaited<ReturnType<typeof fetchFunctions>>>>({
    kind: "loading",
  });

  useEffect(() => {
    let cancelled = false;
    setState({ kind: "loading" });
    void fetchFunctions(token, null, PAGE_SIZE).then(
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
  }, [token]);

  if (state.kind === "loading") {
    return <div className="banner">正在识别函数…</div>;
  }
  if (state.kind === "error") {
    return <div className="banner banner-error">{state.message}</div>;
  }
  if (!state.data) {
    return <div className="banner">本次会话没有可分析的目标。</div>;
  }

  const { functions, total, notes } = state.data;

  return (
    <div className="analysis-view">
      <div className="view-toolbar">
        <span className="hint">
          共 <strong>{total}</strong> 个函数，本页显示 {functions.length} 个
        </span>
      </div>

      {notes.length > 0 && (
        <ul className="notes notes-inline">
          {notes.map((note) => (
            <li key={note}>{note}</li>
          ))}
        </ul>
      )}

      {functions.length === 0 ? (
        <p className="hint">
          没有识别出任何函数。这可能是因为目标没有可执行代码，或符号信息已被剥离。
        </p>
      ) : (
        <div className="table-wrap">
          <table className="data-table">
            <thead>
              <tr>
                <th>地址</th>
                <th>名称</th>
                <th>来源</th>
                <th>置信度</th>
                <th>大小</th>
                <th>源位置</th>
              </tr>
            </thead>
            <tbody>
              {functions.map((fn) => (
                <tr key={fn.start} className="row-clickable" onClick={() => onNavigate(fn.start)}>
                  <td className="mono">{formatAddress(fn.start)}</td>
                  <td>
                    <FunctionName fn={fn} />
                  </td>
                  <td>
                    <span className="chip chip-small">{fn.source_label}</span>
                  </td>
                  <td>
                    <ConfidenceBar value={fn.confidence} />
                  </td>
                  <td className="mono">
                    {/* end 未知时说未知 —— 不写 0，也不写"到段尾" */}
                    {fn.size === null ? (
                      <span className="unknown" title="结束地址未识别出来">
                        未知
                      </span>
                    ) : (
                      `${fn.size} B`
                    )}
                  </td>
                  {/*
                    源位置：函数名回答"这是谁"，源文件:行号回答"它在哪"。
                    没有调试信息时显示"无"并说明原因 —— 空着会让人以为是界面漏了。
                  */}
                  <td className="mono src-pos" title={fn.file ?? undefined}>
                    {formatSourcePosition(fn.file, fn.line) ?? (
                      <span className="unknown" title="目标里没有这个函数的调试信息">
                        无
                      </span>
                    )}
                  </td>

                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
    </div>
  );
}

/** 置信度条：数值 + 可视化，让"低置信度"一眼可见。 */
function ConfidenceBar({ value }: { value: number }) {
  const level = value >= 80 ? "high" : value >= 50 ? "mid" : "low";
  return (
    <span className="confidence" title={`置信度 ${value}/100`}>
      <span className={`confidence-fill confidence-${level}`} style={{ width: `${value}%` }} />
      <span className="confidence-text mono">{value}</span>
    </span>
  );
}

/**
 * 交叉引用视图。
 *
 * 同时给出"我引用了谁"和"谁引用了我" —— 逆向时这两问几乎总是一起出现，
 * 分成两个面板只会让用户来回切。
 */
export function XrefsView({
  token,
  initialAddress,
  onNavigate,
}: {
  token: string | null;
  initialAddress: string | null;
  onNavigate: (address: string) => void;
}) {
  const [address, setAddress] = useState<string | null>(initialAddress);
  const [state, setState] = useState<Loaded<XrefsResponse>>({ kind: "loading" });
  const [annotation, setAnnotation] = useState<Annotation | null>(null);
  /**
   * 类型与来源过滤（M6 交付物 7）。
   *
   * 空数组 = 不过滤。过滤在服务端做，"谁引用了我 / 我引用了谁"的
   * 计数天然反映过滤后的结果。
   */
  const [kindFilter, setKindFilter] = useState<string[]>([]);
  const [sourceFilter, setSourceFilter] = useState<string[]>([]);

  useEffect(() => {
    setAddress(initialAddress);
  }, [initialAddress]);

  useEffect(() => {
    if (!address) {
      setState({ kind: "ready", data: null });
      return;
    }
    let cancelled = false;
    setState({ kind: "loading" });
    void fetchXrefs(token, address, { kind: kindFilter, source: sourceFilter }).then(
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
  }, [token, address, kindFilter, sourceFilter]);

  // 顺带取该地址的名称标注：用户改名后回到这里应当看到自己的名字。
  useEffect(() => {
    if (!address) {
      setAnnotation(null);
      return;
    }
    let cancelled = false;
    void fetchAnnotations(token, address, address).then((data) => {
      if (cancelled || !data) {
        return;
      }
      const named = data.annotations.find((a) => a.kind === "name") ?? null;
      setAnnotation(named);
    });
    return () => {
      cancelled = true;
    };
  }, [token, address]);

  const reloadAnnotations = useCallback(async () => {
    if (!address) {
      return;
    }
    const data = await fetchAnnotations(token, address, address);
    setAnnotation(data?.annotations.find((a) => a.kind === "name") ?? null);
  }, [token, address]);

  return (
    <div className="analysis-view">
      <div className="view-toolbar">
        <AddressJumpBox label="输入地址（16 进制）" onJump={setAddress} />
        {address && <span className="mono current-address">{formatAddress(address)}</span>}
      </div>

      {address && (
        <div className="view-toolbar xref-filters">
          <span className="hint">类型：</span>
          {(["call", "jump", "data"] as const).map((k) => {
            const on = kindFilter.includes(k);
            return (
              <label key={k} className="filter-chip">
                <input
                  type="checkbox"
                  checked={on}
                  onChange={() =>
                    setKindFilter((cur) =>
                      on ? cur.filter((v) => v !== k) : [...cur, k],
                    )
                  }
                />
                {XREF_KIND_LABELS[k] ?? k}
              </label>
            );
          })}
          <span className="hint">来源：</span>
          {(["direct", "jump-table"] as const).map((s) => {
            const on = sourceFilter.includes(s);
            return (
              <label key={s} className="filter-chip">
                <input
                  type="checkbox"
                  checked={on}
                  onChange={() =>
                    setSourceFilter((cur) =>
                      on ? cur.filter((v) => v !== s) : [...cur, s],
                    )
                  }
                />
                {XREF_SOURCE_LABELS[s] ?? s}
              </label>
            );
          })}
          {(kindFilter.length > 0 || sourceFilter.length > 0) && (
            <button
              type="button"
              className="button-small"
              onClick={() => {
                setKindFilter([]);
                setSourceFilter([]);
              }}
            >
              清除过滤
            </button>
          )}
        </div>
      )}

      {!address ? (
        <p className="hint">输入一个地址查看它的交叉引用。</p>
      ) : state.kind === "loading" ? (
        <div className="banner">正在查询…</div>
      ) : state.kind === "error" ? (
        <div className="banner banner-error">{state.message}</div>
      ) : !state.data ? (
        <div className="banner">该地址无法查询（目标不可分析）。</div>
      ) : (
        <>
          {state.data.function ? (
            <div className="xref-summary">
              <span className="hint">所属函数：</span>
              <FunctionName fn={state.data.function} />
              <span className="chip chip-small">{state.data.function.source_label}</span>
            </div>
          ) : (
            <div className="xref-summary">
              {/*
                地址不在任何已知函数里是**真实结论**（数据段、填充、还没识别的代码）。
                明说，而不是挑一个最近的函数填进来 —— 后者会让用户误判。
              */}
              <span className="hint">该地址不在任何已知函数内。</span>
            </div>
          )}

          <AnnotationEditor
            token={token}
            address={address}
            existing={annotation}
            onChanged={() => void reloadAnnotations()}
          />

          <XrefList title="谁引用了我" rows={state.data.to} onNavigate={onNavigate} />
          <XrefList title="我引用了谁" rows={state.data.from} onNavigate={onNavigate} />
        </>
      )}
    </div>
  );
}

function XrefList({
  title,
  rows,
  onNavigate,
}: {
  title: string;
  rows: XrefsResponse["to"];
  onNavigate: (address: string) => void;
}) {
  return (
    <>
      <h3 className="section-heading">
        {title} <span className="count">{rows.length}</span>
      </h3>
      {rows.length === 0 ? (
        <p className="hint">无（若设置了过滤，可能只是被过滤掉了 —— 清除过滤再看）。</p>
      ) : (
        <div className="table-wrap">
          <table className="data-table">
            <thead>
              <tr>
                <th>来源</th>
                <th>目标</th>
                <th>类型</th>
                <th>引用途径</th>
                <th>可信度</th>
              </tr>
            </thead>
            <tbody>
              {rows.map((xref) => (
                <tr key={`${xref.from}-${xref.to}-${xref.kind}-${xref.source}`}>
                  <td
                    className="mono row-clickable"
                    onClick={() => onNavigate(xref.from)}
                    title="点击查看该地址"
                  >
                    {formatAddress(xref.from)}
                    {/*
                      发起指令的源码行：用户问"谁调用了它"时，真正想知道的是
                      "在哪一行调用的"。没有调试信息就不显示这一行。
                    */}
                    {formatSourcePosition(xref.from_file, xref.from_line) && (
                      <span className="src-pos" title={xref.from_file ?? undefined}>
                        {formatSourcePosition(xref.from_file, xref.from_line)}
                      </span>
                    )}
                  </td>
                  <td
                    className="mono row-clickable"
                    onClick={() => onNavigate(xref.to)}
                    title="点击查看该地址"
                  >
                    {formatAddress(xref.to)}
                  </td>
                  <td>{XREF_KIND_LABELS[xref.kind] ?? xref.kind}</td>
                  <td>
                    {xref.source === "direct" ? (
                      <span>直接</span>
                    ) : (
                      <span
                        className="chip chip-small"
                        title="间接跳转经跳转表识别推导出的目标 —— 分析器读表算出来的，不是指令里写明的"
                      >
                        跳转表推导
                      </span>
                    )}
                  </td>
                  <td>
                    {xref.reachable ? (
                      <span>可达</span>
                    ) : (
                      <span
                        className="unknown"
                        title="发起指令未被递归下降证明可达：它可能只是线性扫描把数据误认成了指令，这条引用可能是伪影"
                      >
                        低（发起指令不可达）
                      </span>
                    )}
                  </td>

                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
    </>
  );
}

/**
 * 名称标注编辑器。
 *
 * 写标注**不触发重新分析** —— 所以在 100MB 目标上改名是即时完成的，
 * UI 也不会因此重新拉整个反汇编。
 */
function AnnotationEditor({
  token,
  address,
  existing,
  onChanged,
}: {
  token: string | null;
  address: string;
  existing: Annotation | null;
  onChanged: () => void;
}) {
  const [text, setText] = useState("");
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    setText(existing?.text ?? "");
    setError(null);
  }, [existing, address]);

  const save = useCallback(
    async (kind: string, value: string) => {
      if (!value.trim()) {
        setError("内容为空：空标注会被服务端拒绝。");
        return;
      }
      setBusy(true);
      setError(null);
      try {
        await putAnnotation(token, address, kind, value);
        onChanged();
      } catch (err: unknown) {
        setError(err instanceof Error ? err.message : String(err));
      } finally {
        setBusy(false);
      }
    },
    [token, address, onChanged],
  );

  const remove = useCallback(async () => {
    setBusy(true);
    setError(null);
    try {
      await deleteAnnotation(token, address, "name");
      setText("");
      onChanged();
    } catch (err: unknown) {
      setError(err instanceof Error ? err.message : String(err));
    } finally {
      setBusy(false);
    }
  }, [token, address, onChanged]);

  return (
    <div className="annotation-editor">
      <label className="compact-label" htmlFor="annotation-name">
        {ANNOTATION_KIND_LABELS.name}
      </label>
      <input
        id="annotation-name"
        className="input"
        value={text}
        placeholder="给这个地址起个名字"
        disabled={busy}
        onChange={(event) => setText(event.target.value)}
        onKeyDown={(event) => {
          if (event.key === "Enter") {
            void save("name", text);
          }
        }}
      />
      <button type="button" disabled={busy} onClick={() => void save("name", text)}>
        保存
      </button>
      <button type="button" disabled={busy || !existing} onClick={() => void remove()}>
        清除
      </button>
      <span className="hint">改名不会触发重新分析</span>
      {error && <span className="error-inline">{error}</span>}
    </div>
  );
}

/** 字符串视图：可过滤，点击地址跳转。 */
export function StringsView({
  token,
  onNavigate,
}: {
  token: string | null;
  onNavigate: (address: string) => void;
}) {
  const [filter, setFilter] = useState("");
  const [state, setState] = useState<Loaded<StringsResponse>>({ kind: "loading" });

  useEffect(() => {
    let cancelled = false;
    setState({ kind: "loading" });
    void fetchStrings(token, filter, PAGE_SIZE).then(
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
  }, [token, filter]);

  return (
    <div className="analysis-view">
      <div className="view-toolbar">
        <input
          className="input"
          placeholder="过滤字符串…"
          value={filter}
          onChange={(event) => setFilter(event.target.value)}
        />
        {state.kind === "ready" && state.data && (
          <span className="hint">
            匹配 <strong>{state.data.total}</strong> 条，本页 {state.data.strings.length} 条
          </span>
        )}
      </div>

      {state.kind === "loading" ? (
        <div className="banner">正在提取字符串…</div>
      ) : state.kind === "error" ? (
        <div className="banner banner-error">{state.message}</div>
      ) : !state.data ? (
        <div className="banner">本次会话没有可分析的目标。</div>
      ) : state.data.strings.length === 0 ? (
        <p className="hint">没有匹配的字符串。</p>
      ) : (
        <div className="table-wrap">
          <table className="data-table">
            <thead>
              <tr>
                <th>地址</th>
                <th>编码</th>
                <th>长度</th>
                <th>内容</th>
              </tr>
            </thead>
            <tbody>
              {state.data.strings.map((s) => (
                <tr key={s.address} className="row-clickable" onClick={() => onNavigate(s.address)}>
                  <td className="mono">{formatAddress(s.address)}</td>
                  <td>{STRING_ENCODING_LABELS[s.encoding] ?? s.encoding}</td>
                  <td className="mono">{s.size}</td>
                  <td className="string-cell" title={s.text}>
                    {s.text}
                  </td>

                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
    </div>
  );
}

/**
 * 十六进制视图。
 *
 * 显示 `bytes_read` 与请求长度的差别：读到段尾时明说，不用零填充冒充
 * 文件内容（那会让用户以为那段内存真是零）。
 */
export function HexView({
  token,
  initialAddress,
}: {
  token: string | null;
  initialAddress: string | null;
}) {
  const [address, setAddress] = useState<string | null>(initialAddress ?? "0000000000000000");
  const [state, setState] = useState<Loaded<HexResponse>>({ kind: "loading" });
  const requested = 512;

  useEffect(() => {
    if (!address) {
      return;
    }
    let cancelled = false;
    setState({ kind: "loading" });
    void fetchHex(token, address, requested).then(
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
  }, [token, address]);

  return (
    <div className="analysis-view">
      <div className="view-toolbar">
        <AddressJumpBox label="输入地址（16 进制）" onJump={setAddress} />
        {state.kind === "ready" && state.data && (
          <span className="hint">
            读到 <strong>{state.data.bytes_read}</strong> 字节
            {state.data.bytes_read < requested && (
              <span className="truncation-note">（请求 {requested} 字节，已到段尾）</span>
            )}
          </span>
        )}
      </div>

      {state.kind === "loading" ? (
        <div className="banner">正在读取…</div>
      ) : state.kind === "error" ? (
        <div className="banner banner-error">{state.message}</div>
      ) : !state.data ? (
        <div className="banner">该地址无法读取（不在任何已映射区间内）。</div>
      ) : (
        <pre className="hex-dump">
          {state.data.rows.map((row) => (
            <div key={row.address} className="hex-row">
              <span className="hex-address mono">{formatAddress(row.address)}</span>
              <span className="hex-bytes mono">{row.hex.padEnd(47, " ")}</span>
              <span className="hex-ascii mono">{row.ascii}</span>
            </div>
          ))}
        </pre>
      )}
    </div>
  );
}

/** 供 App 复用的空态提示。 */
export function NoTargetHint() {
  return <div className="banner">本次会话没有打开目标。</div>;
}

/** 目标大小的人类可读形式（导出给 App 复用）。 */
export { formatSize as formatTargetSize };
