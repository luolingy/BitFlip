/**
 * 导出视图（M9）：把分析结果带出工具。
 *
 * 正文与 `bitflip-cli export` **完全一致**（核心层只有一条写文本的路径），
 * 元信息（格式、条数、是否截断、降级说明）走响应头。界面必须把这些账目
 * 如实显示 —— 一份"看起来完整、其实少写了几百条"的导出比没有更糟（§7）。
 *
 * 只做**只读导出**：不写盘、不改目标。要落盘就点"在新标签打开/下载"，
 * 由浏览器决定存哪。
 */

import { useCallback, useState } from "react";

import {
  EXPORT_FORMATS,
  fetchExport,
  type ExportResult,
} from "./api";

type State =
  | { kind: "idle" }
  | { kind: "loading" }
  | { kind: "ready"; result: ExportResult }
  | { kind: "error"; message: string };

export function ExportView({ token }: { token: string | null }) {
  const [format, setFormat] = useState<string>("asm-intel");
  const [functionAddr, setFunctionAddr] = useState("");
  const [from, setFrom] = useState("");
  const [to, setTo] = useState("");
  const [member, setMember] = useState("");
  const [className, setClassName] = useState("");
  const [method, setMethod] = useState("");
  const [state, setState] = useState<State>({ kind: "idle" });

  const selected = EXPORT_FORMATS.find((f) => f.value === format);
  const isDex = selected?.dex ?? false;

  const run = useCallback(async () => {
    setState({ kind: "loading" });
    try {
      const result = await fetchExport(token, {
        format,
        function: !isDex && functionAddr.trim() ? functionAddr.trim() : undefined,
        from: !isDex && from.trim() ? from.trim() : undefined,
        to: !isDex && to.trim() ? to.trim() : undefined,
        member: isDex && member.trim() ? member.trim() : undefined,
        class: isDex && className.trim() ? className.trim() : undefined,
        method: isDex && method.trim() ? method.trim() : undefined,
      });
      setState({ kind: "ready", result });
    } catch (error) {
      setState({
        kind: "error",
        message: error instanceof Error ? error.message : String(error),
      });
    }
  }, [token, format, isDex, functionAddr, from, to, member, className, method]);

  return (
    <div className="analysis-view">
      <p className="hint">
        导出的内容与 <span className="mono">bitflip-cli export</span> 同源（核心层只有一条
        写文本的路径），区别只是走 HTTP。截断与降级会显示在下方横幅里 ——
        不会出现"看起来完整、其实少写了几百条"。
      </p>

      <div className="view-toolbar">
        <label className="hint">
          格式：{" "}
          <select
            className="input-small"
            value={format}
            onChange={(event) => setFormat(event.target.value)}
          >
            {EXPORT_FORMATS.map((option) => (
              <option key={option.value} value={option.value}>
                {option.label}
              </option>
            ))}
          </select>
        </label>

        {isDex ? (
          <>
            <input
              className="input-small mono"
              placeholder="member：classes.dex"
              value={member}
              onChange={(event) => setMember(event.target.value)}
            />
            <input
              className="input-small mono"
              placeholder="class：Lcom/Foo;（可选）"
              value={className}
              onChange={(event) => setClassName(event.target.value)}
            />
            <input
              className="input-small mono"
              placeholder="method：Lcom/Foo;->bar()V（可选）"
              value={method}
              onChange={(event) => setMethod(event.target.value)}
            />
          </>
        ) : (
          <>
            <input
              className="input-small mono"
              placeholder="function 入口（可选）"
              value={functionAddr}
              onChange={(event) => setFunctionAddr(event.target.value)}
            />
            <input
              className="input-small mono"
              placeholder="from（可选）"
              value={from}
              onChange={(event) => setFrom(event.target.value)}
            />
            <input
              className="input-small mono"
              placeholder="to（可选）"
              value={to}
              onChange={(event) => setTo(event.target.value)}
            />
          </>
        )}

        <button
          className="button-small"
          type="button"
          disabled={state.kind === "loading"}
          onClick={() => void run()}
        >
          生成导出
        </button>
      </div>

      {isDex && (
        <p className="hint">
          DEX 格式必须给 <span className="mono">member</span>；机器码格式给了 DEX
          选择器会报错（不静默忽略）。
        </p>
      )}

      {state.kind === "loading" && <div className="banner">正在生成导出…</div>}
      {state.kind === "error" && (
        <div className="banner banner-error">{state.message}</div>
      )}
      {state.kind === "ready" && <ResultPanel result={state.result} />}
    </div>
  );
}

function ResultPanel({ result }: { result: ExportResult }) {
  const openInTab = useCallback(() => {
    const blob = new Blob([result.body], {
      type: result.contentType ?? "text/plain;charset=utf-8",
    });
    const url = URL.createObjectURL(blob);
    window.open(url, "_blank");
    // 交给浏览器后延迟回收；立即 revoke 会让新标签拿到空内容。
    window.setTimeout(() => URL.revokeObjectURL(url), 60_000);
  }, [result]);

  const download = useCallback(() => {
    const blob = new Blob([result.body], {
      type: result.contentType ?? "text/plain;charset=utf-8",
    });
    const url = URL.createObjectURL(blob);
    const anchor = document.createElement("a");
    anchor.href = url;
    anchor.download = `bitflip-export.${result.format ?? "txt"}`;
    anchor.click();
    window.setTimeout(() => URL.revokeObjectURL(url), 60_000);
  }, [result]);

  const preview = result.body.length > 200_000
    ? `${result.body.slice(0, 200_000)}\n…（预览截断，完整内容请下载）`
    : result.body;

  return (
    <div>
      <p className="hint">
        格式 <span className="mono">{result.format ?? "?"}</span>
        {result.items !== null && ` · ${result.items} 条`} ·{" "}
        {result.truncated ? "⚠ 已截断" : "未截断"} · {result.body.length} 字符
      </p>

      {result.truncated && (
        <div className="banner banner-warn">
          <div className="banner-title">导出被截断</div>
          <p>完整内容请改用 CLI（<span className="mono">bitflip-cli export</span>）或提高 limit。</p>
        </div>
      )}

      {result.warnings.length > 0 && (
        <div className="banner banner-note">
          <div className="banner-title">降级 / 说明（{result.warnings.length}）</div>
          <ul>
            {result.warnings.map((warning, index) => (
              <li key={index}>{warning}</li>
            ))}
          </ul>
        </div>
      )}

      <div className="view-toolbar">
        <button className="button-small" type="button" onClick={download}>
          下载
        </button>
        <button className="button-small" type="button" onClick={openInTab}>
          在新标签打开
        </button>
      </div>

      <pre className="dex-cfg">{preview}</pre>
    </div>
  );
}
