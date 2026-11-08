/**
 * 差分视图（M9）：两个同族二进制（例如 DLL 版本升级）的符号/函数/节级差异。
 *
 * 报告的**第一行永远是地址归一化方式**：两个版本的镜像基址几乎总不同，
 * 拿裸虚拟地址比会得到"每个函数都变了"——条理清楚、字段齐全、全错。
 * 所以界面把"按什么比"放在最上面，用户不必先理解归一化再判断。
 *
 * 未命名函数照旧**不造假名**；只在一边出现的条目，另一侧地址显示为"—"。
 */

import { useCallback, useState } from "react";

import {
  DIFF_KIND_LABELS,
  DIFF_SCOPES,
  MATCH_BASIS_LABELS,
  describeNormalization,
  fetchDiff,
  formatAddress,
  formatSize,
  type DiffEntryWire,
  type DiffKindWire,
  type DiffReportWire,
} from "./api";

type State =
  | { kind: "idle" }
  | { kind: "loading" }
  | { kind: "ready"; report: DiffReportWire }
  | { kind: "error"; message: string };

export function DiffView({ token }: { token: string | null }) {
  const [against, setAgainst] = useState("");
  const [scope, setScope] = useState("functions");
  const [only, setOnly] = useState<DiffKindWire | "">("");
  const [state, setState] = useState<State>({ kind: "idle" });

  const run = useCallback(async () => {
    if (!against.trim()) {
      setState({ kind: "error", message: "请填写要比对的另一个文件路径（v2）。" });
      return;
    }
    setState({ kind: "loading" });
    try {
      const report = await fetchDiff(token, against.trim(), {
        scope,
        only: only === "" ? undefined : only,
      });
      setState({ kind: "ready", report });
    } catch (error) {
      setState({
        kind: "error",
        message: error instanceof Error ? error.message : String(error),
      });
    }
  }, [token, against, scope, only]);

  return (
    <div className="analysis-view">
      <p className="hint">
        当前目标是 <strong>v1</strong>（旧），填写的路径是 <strong>v2</strong>（新）。
        服务端只读另一个文件、从不写回，且只接受已存在的常规文件。
      </p>

      <div className="view-toolbar">
        <input
          className="input-small mono"
          style={{ width: "28em" }}
          placeholder="v2 文件路径（另一版本）"
          value={against}
          onChange={(event) => setAgainst(event.target.value)}
        />
        <label className="hint">
          范围：{" "}
          <select
            className="input-small"
            value={scope}
            onChange={(event) => setScope(event.target.value)}
          >
            {DIFF_SCOPES.map((option) => (
              <option key={option.value} value={option.value}>
                {option.label}
              </option>
            ))}
          </select>
        </label>
        <label className="hint">
          只看：{" "}
          <select
            className="input-small"
            value={only}
            onChange={(event) => setOnly(event.target.value as DiffKindWire | "")}
          >
            <option value="">全部</option>
            {(Object.keys(DIFF_KIND_LABELS) as DiffKindWire[]).map((kind) => (
              <option key={kind} value={kind}>
                {DIFF_KIND_LABELS[kind]}
              </option>
            ))}
          </select>
        </label>
        <button
          className="button-small"
          type="button"
          disabled={state.kind === "loading"}
          onClick={() => void run()}
        >
          开始差分
        </button>
      </div>

      {state.kind === "loading" && <div className="banner">正在比对…</div>}
      {state.kind === "error" && (
        <div className="banner banner-error">{state.message}</div>
      )}
      {state.kind === "ready" && <ReportPanel report={state.report} />}
    </div>
  );
}

function ReportPanel({ report }: { report: DiffReportWire }) {
  const total = report.totals;
  return (
    <div>
      <p className="hint">
        <strong>地址归一化：</strong>
        {describeNormalization(report.normalization)}
      </p>
      <p className="hint">
        v1 <span className="mono">{report.v1_path}</span>（{report.v1_total} 条）· v2{" "}
        <span className="mono">{report.v2_path}</span>（{report.v2_total} 条）
      </p>
      <p className="hint">
        新增 {total.added} · 删除 {total.removed} · 改动 {total.changed} · 移动{" "}
        {total.moved} · 未变 {total.unchanged} · 共 {report.entries.length} 条
      </p>

      {report.truncated && (
        <div className="banner banner-warn">
          <div className="banner-title">条目已截断</div>
          <p>还有 {report.dropped} 条未列出。可缩小 only 过滤或用 CLI 取全量。</p>
        </div>
      )}

      {report.notes.length > 0 && (
        <div className="banner banner-note">
          <div className="banner-title">说明（{report.notes.length}）</div>
          <ul>
            {report.notes.map((note, index) => (
              <li key={index}>{note}</li>
            ))}
          </ul>
        </div>
      )}

      <div className="table-wrap">
        <table className="data-table">
          <thead>
            <tr>
              <th>类别</th>
              <th>名字</th>
              <th>归一化地址</th>
              <th>v1 地址</th>
              <th>v2 地址</th>
              <th>大小</th>
              <th>判据</th>
              <th>说明</th>
            </tr>
          </thead>
          <tbody>
            {report.entries.map((entry, index) => (
              <Row key={`${entry.normalized}-${entry.kind}-${index}`} entry={entry} />
            ))}
          </tbody>
        </table>
      </div>
    </div>
  );
}

function Row({ entry }: { entry: DiffEntryWire }) {
  const size =
    entry.v1_size === null && entry.v2_size === null
      ? "—"
      : `${entry.v1_size === null ? "—" : formatSize(entry.v1_size)} → ${
          entry.v2_size === null ? "—" : formatSize(entry.v2_size)
        }`;
  return (
    <>
      <tr>
        <td>
          <span className={`diff-kind diff-kind-${entry.kind}`}>
            {DIFF_KIND_LABELS[entry.kind]}
          </span>
        </td>
        <td>{entry.name ?? <span className="hint">（未命名）</span>}</td>
        <td className="mono">
          {entry.normalized === "0000000000000000" ? "—" : formatAddress(entry.normalized)}
        </td>
        <td className="mono">
          {entry.v1_address ? formatAddress(entry.v1_address) : "—"}
        </td>
        <td className="mono">
          {entry.v2_address ? formatAddress(entry.v2_address) : "—"}
        </td>
        <td className="num">{size}</td>
        <td>{MATCH_BASIS_LABELS[entry.match_basis] ?? entry.match_basis}</td>
        <td>{entry.detail ?? ""}</td>
      </tr>
    </>
  );
}
