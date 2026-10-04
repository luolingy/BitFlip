/**
 * M5 归档视图：静态库 / 归档的成员树，以及按成员进入分析。
 *
 * 这个视图解决的是 `.a` / `.lib` 最实际的问题：**一个归档里有几十上百个
 * 成员，直接对整体做分析只会得到一堆混在一起的结论**。必须能先看到
 * "里面有谁"，再钻进某一个。
 *
 * 两条诚实性要求（CLAUDE.md §7）：
 *
 * - **"不是归档"与"归档没有成员"是两件事**，文案完全不同。后端显式给出
 *   `is_archive`，这里据此分流，而不是靠 `members.length === 0` 猜。
 * - **成员能不能分析，由后端说**。`analyzable` 是后端真的建过一次成员
 *   会话得出的结论，不是按名字猜"以 `/` 开头的就是元数据"。前端直接
 *   拿它决定按钮是否可点 —— 点了才报错是很差的体验，而这里不用猜。
 */

import { useCallback, useEffect, useState } from "react";

import {
  fetchMemberFunctions,
  fetchMembers,
  formatAddress,
  formatSize,
  type MembersResponse,
  type MemberWire,
} from "./api";

const MEMBER_FN_LIMIT = 200;

/** 加载状态。 */
type Loaded<T> =
  | { kind: "loading" }
  | { kind: "ready"; data: T | null }
  | { kind: "error"; message: string };

/** 成员列表 + 成员选择。 */
export function MembersView({
  token,
  onNavigate,
}: {
  token: string | null;
  onNavigate: (address: string) => void;
}) {
  const [state, setState] = useState<Loaded<MembersResponse>>({ kind: "loading" });
  /**
   * 当前选中的成员名。
   *
   * 用**名字**而不是下标：列表可能被截断（`truncated`），下标在重取
   * 之后不保证指向同一个成员，名字才是稳定的标识。
   */
  const [selected, setSelected] = useState<string | null>(null);

  useEffect(() => {
    let cancelled = false;
    setState({ kind: "loading" });
    void fetchMembers(token).then(
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
    return <div className="banner">正在读取归档成员…</div>;
  }
  if (state.kind === "error") {
    return <div className="banner banner-error">{state.message}</div>;
  }
  if (!state.data) {
    return <div className="banner">本次会话没有可分析的目标。</div>;
  }

  const { is_archive, container, truncated, members } = state.data;

  // 不是归档：明说，并告诉用户这个视图是干什么的 ——
  // 而不是显示一个空表格让人以为是数据缺失。
  if (!is_archive) {
    return (
      <div className="analysis-view">
        <p className="hint">
          当前目标不是归档（容器：{container}），没有成员列表。
        </p>
        <p className="hint">
          这个视图用于静态库与归档：<code>.a</code>、<code>.lib</code>。
          归档里的每个成员都可以独立分析，从左侧列表选一个即可。
        </p>
      </div>
    );
  }

  return (
    <div className="analysis-view">
      <div className="view-toolbar">
        <span className="hint">
          共 <strong>{members.length}</strong> 个成员 · 容器 {container}
        </span>
      </div>

      {truncated && (
        <ul className="notes notes-inline">
          <li>
            成员列表已被截断：还有成员没有列出。归档成员过多时只列前一部分。
          </li>
        </ul>
      )}

      {members.length === 0 ? (
        <p className="hint">
          这是一个归档，但没有解析出任何成员。归档可能是空的，或成员头全部损坏。
        </p>
      ) : (
        <div className="table-wrap">
          <table className="data-table">
            <thead>
              <tr>
                <th>成员</th>
                <th>偏移</th>
                <th>大小</th>
                <th>状态</th>
              </tr>
            </thead>
            <tbody>
              {members.map((m) => (
                <MemberRow
                  key={`${m.name}@${m.offset}`}
                  member={m}
                  active={m.name === selected}
                  onSelect={setSelected}
                />
              ))}
            </tbody>
          </table>
        </div>
      )}

      {selected && (
        <MemberFunctions
          token={token}
          member={selected}
          onNavigate={onNavigate}
        />
      )}
    </div>
  );
}

/** 成员列表的一行。不可分析的成员做成不可点的行，而不是点了报错。 */
function MemberRow({
  member,
  active,
  onSelect,
}: {
  member: MemberWire;
  active: boolean;
  onSelect: (name: string) => void;
}) {
  // 元数据成员（如 `/ (符号索引)`）后端会标 analyzable=false。
  // 它们**照常显示** —— 用户需要知道归档里有这块数据 —— 但不可点。
  //
  // 可点的行复用已有的 `.row-clickable`：整个界面里"这一行能点"的
  // 视觉语言必须一致，多一套样式只会让人多猜一次。
  const className = [
    active ? "member-active" : "",
    member.analyzable ? "row-clickable" : "",
  ]
    .filter(Boolean)
    .join(" ");

  return (
    <tr
      className={className}
      onClick={member.analyzable ? () => onSelect(member.name) : undefined}
      title={
        member.analyzable
          ? `分析成员 ${member.name}`
          : `${member.name} 不是可分析对象（例如符号索引这类元数据）`
      }
    >
      <td className="mono">{member.name}</td>
      <td className="mono">{`0x${member.offset.toString(16)}`}</td>
      <td className="mono">{formatSize(member.size)}</td>
      <td>
        {member.truncated && <span className="chip chip-small">已截断</span>}
        {!member.analyzable && <span className="chip chip-small">元数据</span>}
      </td>
    </tr>
  );
}

/** 选中成员后，按需加载它的函数列表。 */
function MemberFunctions({
  token,
  member,
  onNavigate,
}: {
  token: string | null;
  member: string;
  onNavigate: (address: string) => void;
}) {
  const [state, setState] = useState<
    | { kind: "loading" }
    | { kind: "ready"; total: number; items: { start: string; name: string; source_label: string }[] }
    | { kind: "error"; message: string }
  >({ kind: "loading" });

  const load = useCallback(() => {
    setState({ kind: "loading" });
    void fetchMemberFunctions(token, member, MEMBER_FN_LIMIT).then(
      (data) => {
        if (!data) {
          setState({ kind: "error", message: "服务没有返回该成员的分析结果。" });
          return;
        }
        setState({
          kind: "ready",
          total: data.total,
          items: data.functions.map((f) => ({
            start: f.start,
            name: f.name,
            source_label: f.source_label,
          })),
        });
      },
      (error: unknown) => {
        setState({
          kind: "error",
          message: error instanceof Error ? error.message : String(error),
        });
      },
    );
  }, [token, member]);

  useEffect(load, [load]);

  return (
    <div className="member-detail">
      <div className="view-toolbar">
        <span className="hint">
          成员 <span className="mono">{member}</span>
        </span>
        <button type="button" className="back-button" onClick={load}>
          重新分析
        </button>
      </div>

      {state.kind === "loading" && <div className="banner">正在分析成员…</div>}
      {state.kind === "error" && (
        <div className="banner banner-error">{state.message}</div>
      )}
      {state.kind === "ready" && (
        <>
          <p className="hint">
            该成员里有 <strong>{state.total}</strong> 个函数
            {state.items.length < state.total &&
              `，本页显示 ${state.items.length} 个`}
          </p>
          {state.items.length === 0 ? (
            <p className="hint">
              这个成员里没有识别出函数。它可能是纯数据成员（如导入库的
              符号索引），或代码符号已被剥离。
            </p>
          ) : (
            <div className="table-wrap">
              <table className="data-table">
                <thead>
                  <tr>
                    <th>地址</th>
                    <th>名称</th>
                    <th>来源</th>
                  </tr>
                </thead>
                <tbody>
                  {state.items.map((f) => (
                    <tr
                      key={f.start}
                      className="row-clickable"
                      onClick={() => onNavigate(f.start)}
                      title={`在反汇编中查看 ${f.start}`}
                    >
                      <td className="mono">{formatAddress(f.start)}</td>
                      <td className="mono">
                        {f.name || <span className="hint">未命名</span>}
                      </td>
                      <td>{f.source_label}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}
        </>
      )}
    </div>
  );
}
