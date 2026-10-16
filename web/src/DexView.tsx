/**
 * DEX 视图（M2b）：APK 里的 `classes*.dex`，按文件名分标签页。
 *
 * 三层钻取，每层都只在需要时才请求：
 *
 * 1. **输入**：这个目标里有哪几个 DEX（标签页），各自多少类 / 方法、解析时跳过了什么；
 * 2. **类**：搜索 + 分页的类列表，选中一个 → 它的字段与方法；
 * 3. **方法**：指令表（分页）与**整个方法**的文本 CFG。
 *
 * 四条诚实性要求（CLAUDE.md §7）：
 *
 * - **多个 DEX 必须分得开**。标签页用文件名，且每个端点的请求都显式带
 *   `member`：合并三个 DEX 的类列表之后，界面上就分不清第 5000 个类是哪个
 *   文件里的了（用户 2026-10-16 的决定）。
 * - **降级跟着它的来源走**。某个 DEX 的容错记录显示在那个标签页下，而不是
 *   合成一条总说明 —— 否则用户判断不了是哪份 dex 的结论要打折。
 * - **"没有字节码"是合法结论**，不是错误：抽象 / native 方法要写清楚为什么
 *   没有指令，而不是显示一张空表。
 * - **解析不出来要说出来**：符号解析的已知缺口与异常、CFG 里连不上的边
 *   都要显示出来，`unresolved_edge_targets > 0` 时高亮。
 * - **状态在 URL 里**（用户 2026-10-16 的决定）：标签页、选中的类与方法、搜索词
 *   写进 hash，所以刷新不丢、链接可分享（`web/src/dexUrl.ts`）。
 *   指令分页的页码**不**进 URL —— 那是"看到第几页"，不是"在看哪个方法"。
 */

import { useCallback, useEffect, useState } from "react";

import {
  fetchDexClass,
  fetchDexClasses,
  fetchDexInputs,
  fetchDexMethod,
  formatSize,
  type DexClassResponse,
  type DexClassesResponse,
  type DexInputWire,
  type DexInputsResponse,
  type DexMethodResponse,
} from "./api";
import { readDexUrl, subscribeDexHash, writeDexUrl } from "./dexUrl";

/** 类列表每页条数（后端上限 1000）。 */
const CLASS_PAGE = 200;

/** 指令每页条数（后端上限 5000）。 */
const INSN_PAGE = 500;

/** 加载状态。 */
type Loaded<T> =
  | { kind: "loading" }
  | { kind: "ready"; data: T }
  | { kind: "error"; message: string };

/** 把任意异常转成可读消息。 */
function messageOf(error: unknown): string {
  return error instanceof Error ? error.message : String(error);
}

/** DEX 视图：标签页 + 类浏览器。 */
export function DexView({ token }: { token: string | null }) {
  const [state, setState] = useState<Loaded<DexInputsResponse>>({ kind: "loading" });
  // 这三个（加 `member`）是**唯一**进 URL 的选中状态，所以放在这里由本组件拥有：
  // 分散在子组件里就没法写到 URL 上，也没法从 URL 里恢复。
  const initial = readDexUrl();
  /** 当前选中的 DEX（用**成员名**：它是稳定的，下标不是）。 */
  const [member, setMember] = useState<string | null>(initial.member);
  /** 选中的类与方法（smali 描述符 / smali 标识）。 */
  const [descriptor, setDescriptor] = useState<string | null>(initial.descriptor);
  const [method, setMethod] = useState<string | null>(initial.method);
  /** 类列表的过滤词（已提交的那个，不是输入框里的草稿）。 */
  const [search, setSearch] = useState<string>(initial.search ?? "");

  useEffect(() => {
    let cancelled = false;
    setState({ kind: "loading" });
    void fetchDexInputs(token).then(
      (data) => {
        if (cancelled) {
          return;
        }
        setState({ kind: "ready", data });
        // 默认选中第一个：不选就等于让用户先看一屏空白。
        setMember((current) => current ?? data.inputs[0]?.name ?? null);
      },
      (error: unknown) => {
        if (!cancelled) {
          setState({ kind: "error", message: messageOf(error) });
        }
      },
    );
    return () => {
      cancelled = true;
    };
  }, [token]);

  // 外部改动 hash（粘贴一条链接）时应用它。`replaceState` 不触发 `hashchange`，
  // 所以与下面那个写入 effect 不会互相触发。
  useEffect(
    () =>
      subscribeDexHash(() => {
        const url = readDexUrl();
        setMember(url.member);
        setDescriptor(url.descriptor);
        setMethod(url.method);
        setSearch(url.search ?? "");
      }),
    [],
  );

  // URL 同步必须在**所有** return 之前调用（hooks 的规则），所以这里先按
  // "输入还没加载完"的情况推导出要写进 URL 的 member，再在下面就绪时用同一个值。
  const currentName =
    state.kind === "ready"
      ? (state.data.inputs.find((input) => input.name === member) ??
          state.data.inputs[0])?.name ?? null
      : member;
  useDexUrlSync({
    member: currentName,
    descriptor,
    method,
    search: search === "" ? null : search,
  });

  if (state.kind === "loading") {
    return <div className="banner">正在读取 DEX 输入…</div>;
  }
  if (state.kind === "error") {
    // 后端在这里给的是能读的中文（"本次会话没有打开目标" /
    // "目标里没有以 .dex 结尾的成员"），照原样显示 —— 换成"暂无数据"就把
    // "没有 DEX" 与 "我们没做" 混成一件了。
    return (
      <div className="analysis-view">
        <div className="banner banner-error">{state.message}</div>
        <p className="hint">
          这个视图用于 APK（或单独的 <code>.dex</code> 文件）：列出
          <code>classes*.dex</code> 里的类与方法，并给出方法与文本 CFG。
        </p>
      </div>
    );
  }

  const { inputs } = state.data;
  const current = inputs.find((input) => input.name === member) ?? inputs[0] ?? null;
  // URL 里的 member 不在本次目标里（例如链接来自另一份 APK）：**明说**再换，
  // 不然用户会以为"链接里的那个 dex 就是这样"，而我们其实给的是另一个文件。
  const missingMember =
    member !== null && inputs.length > 0 && !inputs.some((input) => input.name === member)
      ? member
      : null;

  return (
    <div className="analysis-view">
      {missingMember !== null && current && (
        <ul className="notes notes-inline">
          <li>
            链接里的 <span className="mono">member={missingMember}</span>{" "}
            不在本次目标里，已切到{" "}
            <span className="mono">{current.name}</span>。
          </li>
        </ul>
      )}

      {inputs.length > 1 ? (
        <div className="tabs dex-tabs">
          {inputs.map((input) => (
            <button
              key={input.name}
              type="button"
              className={`tab${input.name === current?.name ? " tab-active" : ""}`}
              onClick={() => {
                setMember(input.name);
                // 换 DEX 之后原来的类/方法多半不在这个文件里：一起清掉，
                // 免得留下一个"看着还在选中、其实属于另一个文件"的状态。
                setDescriptor(null);
                setMethod(null);
              }}
              title={`${input.name}：${input.class_count} 类 / ${input.method_count} 方法`}
            >
              {input.name}
              <span className="tab-count">{input.class_count}</span>
            </button>
          ))}
        </div>
      ) : (
        <div className="view-toolbar">
          <span className="hint">
            目标里只有 1 个 DEX：<span className="mono">{current?.name ?? "?"}</span>
          </span>
        </div>
      )}

      {current && <DexFacts input={current} multiple={inputs.length > 1} />}
      {current && (
        <ClassBrowser
          key={current.name}
          token={token}
          member={current.name}
          search={search}
          onSearch={(next) => {
            setSearch(next);
            setDescriptor(null);
            setMethod(null);
          }}
          selected={descriptor}
          onSelect={(next) => {
            setDescriptor(next);
            setMethod(null);
          }}
          method={method}
          onSelectMethod={setMethod}
        />
      )}
    </div>
  );
}

/** 把 URL 状态同步到 hash（在状态变化后跑）。 */
function useDexUrlSync(state: {
  member: string | null;
  descriptor: string | null;
  method: string | null;
  search: string | null;
}): void {
  const { member, descriptor, method, search } = state;
  useEffect(() => {
    writeDexUrl({ member, descriptor, method, search });
  }, [member, descriptor, method, search]);
}

/** 当前 DEX 的计数与**它自己的**容错记录。 */
function DexFacts({ input, multiple }: { input: DexInputWire; multiple: boolean }) {
  return (
    <>
      <div className="view-toolbar">
        <span className="hint">
          {multiple && (
            <>
              <span className="mono">{input.name}</span>
              {input.role ? ` · ${input.role}` : ""} ·{" "}
            </>
          )}
          共 <strong>{input.class_count}</strong> 个类 ·{" "}
          <strong>{input.method_count}</strong> 个方法（
          {input.method_count_with_code} 个有字节码）
          {!multiple && input.role ? ` · ${input.role}` : ""} · {formatSize(input.size)}
        </span>
      </div>

      {input.notes.length > 0 && (
        <ul className="notes notes-inline">
          {input.notes.map((note) => (
            <li key={note}>
              <span className="mono">{input.name}</span> 的解析说明：{note}
            </li>
          ))}
        </ul>
      )}
    </>
  );
}

/** 类列表：搜索 + 分页，选中后加载类详情。 */
function ClassBrowser({
  token,
  member,
  search,
  onSearch,
  selected,
  onSelect,
  method,
  onSelectMethod,
}: {
  token: string | null;
  member: string;
  /** 已提交的过滤词（属于 URL 状态，所以由父组件拥有）。 */
  search: string;
  onSearch: (next: string) => void;
  selected: string | null;
  onSelect: (next: string) => void;
  method: string | null;
  onSelectMethod: (next: string | null) => void;
}) {
  /** 输入框里的草稿：没提交之前不影响请求，也不进 URL。 */
  const [draft, setDraft] = useState(search);
  const [offset, setOffset] = useState(0);
  const [state, setState] = useState<Loaded<DexClassesResponse>>({ kind: "loading" });

  // 过滤词或 DEX 变了就回到第一页（否则会停在一个"上一页已经不属于这个过滤词"的位置）；
  // 输入框也要跟着外部状态走，否则粘贴一条带 search 的链接时框里是空的。
  useEffect(() => {
    setOffset(0);
  }, [search, member]);
  useEffect(() => {
    setDraft(search);
  }, [search]);

  const load = useCallback(() => {
    setState({ kind: "loading" });
    void fetchDexClasses(token, member, {
      offset,
      limit: CLASS_PAGE,
      search,
    }).then(
      (data) => setState({ kind: "ready", data }),
      (error: unknown) => setState({ kind: "error", message: messageOf(error) }),
    );
  }, [token, member, offset, search]);

  useEffect(load, [load]);

  return (
    <div className="dex-class-browser">
      <form
        className="view-toolbar dex-search"
        onSubmit={(event) => {
          event.preventDefault();
          onSearch(draft);
        }}
      >
        <label className="compact-label" htmlFor="dex-class-search">
          找类（按描述符子串，大小写不敏感）
        </label>
        <input
          id="dex-class-search"
          type="text"
          className="input mono"
          value={draft}
          placeholder="例如 Activity / Lcom/example/"
          onChange={(event) => setDraft(event.target.value)}
        />
        <button type="submit" className="tab">
          搜索
        </button>
        {search !== "" && (
          <button
            type="button"
            className="tab"
            onClick={() => {
              setDraft("");
              onSearch("");
            }}
          >
            清除
          </button>
        )}
      </form>

      {state.kind === "loading" && <div className="banner">正在读取类列表…</div>}
      {state.kind === "error" && (
        <div className="banner banner-error">{state.message}</div>
      )}
      {state.kind === "ready" && (
        <>
          <p className="hint">
            {search === "" ? (
              <>
                共 <strong>{state.data.total}</strong> 个类
              </>
            ) : (
              <>
                「<span className="mono">{search}</span>」匹配{" "}
                <strong>{state.data.total}</strong> 个类
              </>
            )}
            {state.data.classes.length > 0 &&
              `，本页显示第 ${state.data.offset}–${state.data.offset + state.data.classes.length} 个`}
          </p>

          {state.data.notes.length > 0 && (
            <ul className="notes notes-inline">
              {state.data.notes.map((note) => (
                <li key={note}>{note}</li>
              ))}
            </ul>
          )}

          {state.data.total === 0 ? (
            <p className="hint">
              没有类匹配。这个 DEX 一共有 {state.data.total} 个匹配项 ——
              换个子串试试，或者清掉过滤条件看全部。
            </p>
          ) : (
            <div className="table-wrap">
              <table className="data-table">
                <thead>
                  <tr>
                    <th>类</th>
                    <th>短名</th>
                    <th>方法</th>
                  </tr>
                </thead>
                <tbody>
                  {state.data.classes.map((item) => (
                    <tr
                      key={item.descriptor}
                      className={
                        item.descriptor === selected ? "row-clickable member-active" : "row-clickable"
                      }
                      onClick={() => onSelect(item.descriptor)}
                      title={`查看 ${item.descriptor} 的字段与方法`}
                    >
                      <td className="mono">{item.descriptor}</td>
                      <td className="mono">{item.short_name ?? "—"}</td>
                      <td className="mono">
                        {item.method_count}
                        {item.methods_with_code < item.method_count && (
                          <span className="chip chip-small">
                            无字节码 {item.method_count - item.methods_with_code}
                          </span>
                        )}
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}

          <div className="dex-pager">
            <button
              type="button"
              className="tab"
              disabled={state.data.offset === 0}
              onClick={() => setOffset(Math.max(0, state.data.offset - CLASS_PAGE))}
            >
              ← 上一页
            </button>
            <button
              type="button"
              className="tab"
              disabled={state.data.offset + state.data.classes.length >= state.data.total}
              onClick={() => setOffset(state.data.offset + CLASS_PAGE)}
            >
              下一页 →
            </button>
          </div>
        </>
      )}

      {selected && (
        <ClassDetail
          key={`${member}:${selected}`}
          token={token}
          member={member}
          descriptor={selected}
          method={method}
          onSelectMethod={onSelectMethod}
        />
      )}
    </div>
  );
}

/** 类详情：字段 + 方法，选中方法后加载指令与 CFG。 */
function ClassDetail({
  token,
  member,
  descriptor,
  method,
  onSelectMethod,
}: {
  token: string | null;
  member: string;
  descriptor: string;
  /** 选中的方法（属于 URL 状态，所以由 `DexView` 拥有）。 */
  method: string | null;
  onSelectMethod: (next: string | null) => void;
}) {
  const [state, setState] = useState<Loaded<DexClassResponse>>({ kind: "loading" });

  useEffect(() => {
    let cancelled = false;
    setState({ kind: "loading" });
    void fetchDexClass(token, member, descriptor).then(
      (data) => {
        if (!cancelled) {
          setState({ kind: "ready", data });
        }
      },
      (error: unknown) => {
        if (!cancelled) {
          setState({ kind: "error", message: messageOf(error) });
        }
      },
    );
    return () => {
      cancelled = true;
    };
  }, [token, member, descriptor]);

  if (state.kind === "loading") {
    return <div className="banner">正在读取 {descriptor} …</div>;
  }
  if (state.kind === "error") {
    return <div className="banner banner-error">{state.message}</div>;
  }

  const data = state.data;
  return (
    <div className="member-detail dex-class-detail">
      <div className="view-toolbar">
        <span className="hint">
          <span className="mono">{data.descriptor}</span>
          {data.superclass && (
            <>
              {" "}
              · 继承 <span className="mono">{data.superclass}</span>
            </>
          )}
          {data.source_file && ` · 源码 ${data.source_file}`}
        </span>
      </div>

      {data.notes.length > 0 && (
        <ul className="notes notes-inline">
          {data.notes.map((note) => (
            <li key={note}>{note}</li>
          ))}
        </ul>
      )}

      <h3 className="dex-subtitle">字段（{data.fields.length}）</h3>
      {data.fields.length === 0 ? (
        <p className="hint">这个类没有字段。</p>
      ) : (
        <div className="table-wrap">
          <table className="data-table">
            <thead>
              <tr>
                <th>字段</th>
                <th>类型</th>
                <th>标志</th>
              </tr>
            </thead>
            <tbody>
              {data.fields.map((field) => (
                <tr key={field.name}>
                  <td className="mono">{field.name}</td>
                  <td className="mono">{field.type_descriptor ?? "—"}</td>
                  <td>
                    {field.is_static ? (
                      <span className="chip chip-small">static</span>
                    ) : (
                      <span className="chip chip-small">instance</span>
                    )}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}

      <h3 className="dex-subtitle">方法（{data.methods.length}）</h3>
      {data.methods.length === 0 ? (
        <p className="hint">这个类没有方法。</p>
      ) : (
        <div className="table-wrap">
          <table className="data-table">
            <thead>
              <tr>
                <th>标识</th>
                <th>code_off</th>
                <th>种类</th>
                <th>字节码</th>
              </tr>
            </thead>
            <tbody>
              {data.methods.map((item) => (
                <tr
                  key={item.signature}
                  className={
                    item.has_code
                      ? item.signature === method
                        ? "row-clickable member-active"
                        : "row-clickable"
                      : ""
                  }
                  onClick={item.has_code ? () => onSelectMethod(item.signature) : undefined}
                  title={
                    item.has_code
                      ? `查看 ${item.signature} 的指令与 CFG`
                      : "没有字节码（抽象或 native 方法）：没有指令可看"
                  }
                >
                  <td className="mono">{item.signature}</td>
                  <td className="mono">
                    {item.code_off ? `0x${item.code_off}` : <span className="hint">无</span>}
                  </td>
                  <td>{item.is_direct ? "直接" : "虚"}</td>
                  <td>
                    {item.has_code ? (
                      "有"
                    ) : (
                      <span className="chip chip-small">无字节码</span>
                    )}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}

      {/*
        点开一个**没有字节码**的方法时也要有反应：行的点击被禁用了，
        但用户仍然需要知道原因。这里在表后统一说明一次，避免"点了没反应"。
      */}
      <p className="hint">
        「无字节码」的方法（抽象 / <code>native</code>）没有指令与 CFG ——
        这是文件里确凿的结论，不是解析失败。
      </p>

      {method && (
        <MethodDetail
          key={`${member}:${method}`}
          token={token}
          member={member}
          signature={method}
        />
      )}
    </div>
  );
}

/** 方法详情：指令（分页）+ 整个方法的文本 CFG。 */
function MethodDetail({
  token,
  member,
  signature,
}: {
  token: string | null;
  member: string;
  signature: string;
}) {
  const [offset, setOffset] = useState(0);
  const [state, setState] = useState<Loaded<DexMethodResponse>>({ kind: "loading" });

  const load = useCallback(() => {
    setState({ kind: "loading" });
    void fetchDexMethod(token, member, signature, { offset, limit: INSN_PAGE }).then(
      (data) => setState({ kind: "ready", data }),
      (error: unknown) => setState({ kind: "error", message: messageOf(error) }),
    );
  }, [token, member, signature, offset]);

  useEffect(load, [load]);

  if (state.kind === "loading") {
    return <div className="banner">正在读取 {signature} …</div>;
  }
  if (state.kind === "error") {
    return <div className="banner banner-error">{state.message}</div>;
  }

  const data = state.data;
  return (
    <div className="dex-method-detail">
      <div className="view-toolbar">
        <span className="hint mono">{data.signature}</span>
      </div>

      <dl className="facts">
        <div>
          <dt>来源</dt>
          <dd className="mono">
            {data.member}
            {data.code_off ? ` @ 0x${data.code_off}` : ""}
          </dd>
        </div>
        <div>
          <dt>寄存器</dt>
          <dd className="mono">
            {data.registers_size ?? "—"} / 入参 {data.ins_size ?? "—"} / 出参{" "}
            {data.outs_size ?? "—"}
          </dd>
        </div>
        <div>
          <dt>指令</dt>
          <dd className="mono">{data.instruction_count}</dd>
        </div>
        <div>
          <dt>CFG</dt>
          <dd className="mono">
            {data.block_count} 块 / {data.edge_count} 边
          </dd>
        </div>
      </dl>

      {!data.has_code ? (
        <p className="hint">
          这个方法没有字节码（<code>code_off</code> 为空）：抽象方法或{" "}
          <code>native</code> 方法，没有指令与 CFG。
        </p>
      ) : (
        <>
          <p className="hint">
            符号解析：{data.symbols ? "开启" : "关闭"} · 已知缺口{" "}
            <strong>{data.unsupported_operands}</strong> · 异常{" "}
            <strong>{data.unavailable_operands}</strong> · CFG 未连上的目标{" "}
            <strong
              className={data.unresolved_edge_targets > 0 ? "dex-warn" : undefined}
            >
              {data.unresolved_edge_targets}
            </strong>
          </p>

          {data.notes.length > 0 && (
            <ul className="notes notes-inline">
              {data.notes.map((note) => (
                <li key={note}>{note}</li>
              ))}
            </ul>
          )}

          {data.instructions.length === 0 ? (
            <p className="hint">
              本页没有指令（偏移 {data.offset}，共 {data.instruction_count} 条）。
            </p>
          ) : (
            <div className="table-wrap dex-insn-table">
              <table className="data-table">
                <thead>
                  <tr>
                    <th>地址</th>
                    <th>opcode</th>
                    <th>指令</th>
                  </tr>
                </thead>
                <tbody>
                  {data.instructions.map((insn) => (
                    <tr key={`${insn.address}:${insn.opcode}`}>
                      <td className="mono">{insn.address}</td>
                      <td className="mono">{`0x${insn.opcode.toString(16).padStart(2, "0")}`}</td>
                      <td className="mono">{insn.text}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}

          <div className="dex-pager">
            <button
              type="button"
              className="tab"
              disabled={data.offset === 0}
              onClick={() => setOffset(Math.max(0, data.offset - INSN_PAGE))}
            >
              ← 上一页
            </button>
            <button
              type="button"
              className="tab"
              disabled={data.offset + data.instructions.length >= data.instruction_count}
              onClick={() => setOffset(data.offset + INSN_PAGE)}
            >
              下一页 →
            </button>
          </div>

          <h3 className="dex-subtitle">控制流图（文本）</h3>
          {data.cfg_text === "" ? (
            <p className="hint">后端没有给出 CFG 文本。</p>
          ) : (
            <pre className="mono dex-cfg">{data.cfg_text}</pre>
          )}
        </>
      )}
    </div>
  );
}
