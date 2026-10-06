/**
 * M7 脚本控制台：编辑器 + 运行/停止 + 日志 + 结果表格 + 脚本库。
 *
 * # 三件必须在界面上说清楚的事
 *
 * 1. **每次运行都是全新的上下文。** 脚本在宿主进程内执行，但每次运行都新建
 *    一个 JS 上下文 —— 上一次的变量不留下。所以这不是一个"能攒状态"的 REPL，
 *    把上一次的运行结果当变量用会直接报 `undefined`。界面必须明说，
 *    否则用户会以为引擎坏了。
 * 2. **停止在预热阶段无效。** 第一次读函数列表要先把分析结论建起来
 *    （ntdll.dll 上 10.6 秒），那一步不在脚本引擎里跑，中断回调管不着。
 *    服务端给了 `can_cancel`，界面据此把按钮置灰并说明原因 ——
 *    而不是让用户对着一个无效的按钮猛点。
 * 3. **脚本层不是沙箱。** 只承诺"你自己的脚本不会因为死循环或抛异常而拖垮宿主"，
 *    不承诺可以安全执行来路不明的脚本。
 *
 * # 结果表格从哪来
 *
 * 没有"查询结果集"这种东西：脚本的输出就是日志。所以制表符分隔的日志行会被
 * 摘出来渲染成表格 —— 内置的 `export-functions` 与 `library-patterns` 正是
 * 这么输出的。数据全部来自脚本自己，界面不加工、不推断列的含义。
 */

import { useCallback, useEffect, useMemo, useRef, useState } from "react";

import {
  cancelScript,
  fetchScriptLibrary,
  fetchScriptStatus,
  formatAddress,
  runScript,
  type BuiltinScriptWire,
  type ScriptErrorWire,
  type ScriptLogWire,
  type ScriptStatusWire,
} from "./api";
import {
  ScriptStorageError,
  deleteUserScript,
  loadDraft,
  loadUserScripts,
  saveDraft,
  saveUserScript,
  type UserScript,
} from "./scriptStore";

/** 轮询间隔。脚本都是毫秒级的，250ms 足够跟手，也不至于把服务打满。 */
const POLL_MS = 250;

/** 表格最多渲染多少行。再多就该导出到文件，而不是塞进 DOM。 */
const MAX_TABLE_ROWS = 2000;

const STARTER = `// 直接写 JavaScript。每次运行都是全新的上下文：上一次的变量不会留下。
bitflip.log('函数总数：' + bitflip.functions.count());
bitflip.log('交叉引用：' + bitflip.xrefs.count());
for (const note of bitflip.notes()) {
  bitflip.warn('降级说明：' + note);
}
`;

/** 运行阶段的中文说明。 */
const STATE_LABELS: Record<string, string> = {
  idle: "空闲",
  warming: "正在分析（预热）",
  running: "运行中",
  done: "已结束",
};

export function ScriptConsole({ token }: { token: string | null }) {
  const [source, setSource] = useState(STARTER);
  const [status, setStatus] = useState<ScriptStatusWire | null>(null);
  const [library, setLibrary] = useState<BuiltinScriptWire[]>([]);
  const [libraryError, setLibraryError] = useState<string | null>(null);
  const [selectedId, setSelectedId] = useState<string | null>(null);
  /** 本地提示（发起请求失败、取消被拒等），与脚本自己的日志分开。 */
  const [notice, setNotice] = useState<string | null>(null);
  const [submitting, setSubmitting] = useState(false);
  /** 用户自己的脚本（浏览器本地）。 */
  const [ownScripts, setOwnScripts] = useState<UserScript[]>([]);
  const [storageError, setStorageError] = useState<string | null>(null);
  const [saveName, setSaveName] = useState("");

  const state = status?.state ?? "idle";
  const active = state === "warming" || state === "running";

  // 恢复草稿与用户脚本。放在一个 effect 里：`localStorage` 在 SSR/受限环境
  // 下不存在，写在 useState 的初始化函数里会直接把组件炸掉。
  useEffect(() => {
    const draft = loadDraft();
    if (draft !== null && draft.length > 0) {
      setSource(draft);
    }
    try {
      setOwnScripts(loadUserScripts());
      setStorageError(null);
    } catch (error) {
      setStorageError(
        error instanceof ScriptStorageError
          ? error.message
          : String(error),
      );
    }
  }, []);

  // ── 首屏取一次状态 ──
  // 不只是为了显示 API 版本：另一个标签页可能正在跑脚本，
  // 这一次查询让我们接上它的进度，而不是显示"空闲"骗自己。
  useEffect(() => {
    let cancelled = false;
    void fetchScriptStatus(token).then(
      (data) => {
        if (!cancelled) {
          setStatus(data);
        }
      },
      () => {
        // 首次状态读不到不是致命问题：工具栏显示 "v?"，运行一次就知道了。
      },
    );
    return () => {
      cancelled = true;
    };
  }, [token]);

  // ── 脚本库 ──
  useEffect(() => {
    let cancelled = false;
    void fetchScriptLibrary(token).then(
      (data) => {
        if (!cancelled) {
          setLibrary(data.scripts);
          setLibraryError(null);
        }
      },
      (error: unknown) => {
        if (!cancelled) {
          setLibraryError(error instanceof Error ? error.message : String(error));
        }
      },
    );
    return () => {
      cancelled = true;
    };
  }, [token]);

  // ── 轮询 ──
  // 依赖是 `active` 这个布尔值而不是整个 status：后者每次轮询都会变，
  // 会让定时器每 250ms 重建一次。
  useEffect(() => {
    if (!active) {
      return;
    }
    let cancelled = false;
    const tick = async () => {
      try {
        const next = await fetchScriptStatus(token);
        if (!cancelled) {
          setStatus(next);
        }
      } catch (error) {
        if (!cancelled) {
          setNotice(error instanceof Error ? error.message : String(error));
        }
      }
    };
    const timer = window.setInterval(() => void tick(), POLL_MS);
    void tick();
    return () => {
      cancelled = true;
      window.clearInterval(timer);
    };
  }, [active, token]);

  const onRun = useCallback(async () => {
    setNotice(null);
    setSubmitting(true);
    try {
      // 立刻拿到的只是"已开始"，随后靠轮询看它怎么结束。
      setStatus(await runScript(token, source));
    } catch (error) {
      setNotice(error instanceof Error ? error.message : String(error));
    } finally {
      setSubmitting(false);
    }
  }, [token, source]);

  const onCancel = useCallback(async () => {
    try {
      const result = await cancelScript(token);
      // 被拒也是有意义的回答（还在预热 / 已经结束），如实显示。
      setNotice(result.ok ? null : result.message);
    } catch (error) {
      setNotice(error instanceof Error ? error.message : String(error));
    }
  }, [token]);

  const onPick = useCallback(
    (script: BuiltinScriptWire) => {
      setSelectedId(script.id);
      setSource(script.source);
      saveDraft(script.source);
      setNotice(null);
    },
    [],
  );

  const onEdit = useCallback((next: string) => {
    setSource(next);
    // 每敲一个字都存一次草稿：切到别的视图、刷新页面都不会丢。
    saveDraft(next);
  }, []);

  const onPickOwn = useCallback((script: UserScript) => {
    setSelectedId(script.id);
    setSource(script.source);
    saveDraft(script.source);
    setNotice(null);
  }, []);

  const onSave = useCallback(() => {
    try {
      setOwnScripts(saveUserScript(ownScripts, saveName, source));
      setStorageError(null);
      setNotice(`已保存「${saveName.trim()}」。`);
      setSaveName("");
    } catch (error) {
      // 存储不可用/配额满必须说出来：静默失败会让用户以为存住了。
      setStorageError(error instanceof Error ? error.message : String(error));
    }
  }, [ownScripts, saveName, source]);

  const onDelete = useCallback(
    (id: string) => {
      try {
        setOwnScripts(deleteUserScript(ownScripts, id));
        setStorageError(null);
      } catch (error) {
        setStorageError(error instanceof Error ? error.message : String(error));
      }
    },
    [ownScripts],
  );

  const logs = useMemo(() => splitLogs(status?.logs ?? []), [status]);

  return (
    <div className="analysis-view script-console">
      <div className="view-toolbar">
        <span className="hint">
          脚本 API <strong>v{status?.api_version ?? "?"}</strong>
        </span>
        <button
          type="button"
          className="button-small"
          onClick={() => void onRun()}
          disabled={active || submitting || source.trim().length === 0}
          title={active ? "已有脚本在运行" : "运行这段脚本"}
        >
          运行
        </button>
        <button
          type="button"
          className="button-small"
          onClick={() => void onCancel()}
          disabled={!status?.can_cancel}
          title={
            active
              ? status?.can_cancel
                ? "请求停止当前脚本"
                : "预热阶段不可中止：正在构建分析结论（结果会被缓存，下次直接复用）"
              : "当前没有正在运行的脚本"
          }
        >
          停止
        </button>
        {active && (
          <span className="hint">
            {STATE_LABELS[state] ?? state} · {formatDuration(status?.elapsed_ms ?? 0)}
            {status && status.staged > 0 && ` · 已暂存 ${status.staged} 条写入`}
          </span>
        )}
      </div>

      {notice && <div className="banner banner-warn">{notice}</div>}

      <div className="script-columns">
        <div className="script-editor-pane">
          <label className="compact-label" htmlFor="script-source">
            脚本源码
          </label>
          <textarea
            id="script-source"
            className="script-editor"
            value={source}
            spellCheck={false}
            wrap="off"
            onChange={(event) => onEdit(event.target.value)}
          />
          <div className="script-save-row">
            <input
              className="input-small"
              type="text"
              placeholder="脚本名"
              value={saveName}
              onChange={(event) => setSaveName(event.target.value)}
              aria-label="脚本名"
            />
            <button
              type="button"
              className="button-small"
              onClick={onSave}
              disabled={saveName.trim().length === 0}
              title="把当前编辑器里的脚本存进脚本库（同名覆盖）"
            >
              保存到我的脚本
            </button>
          </div>
          {storageError && (
            <p className="hint script-storage-error">
              本地存储不可用（{storageError}）—— 这一栏能写，但保存不了：
              本机浏览器禁止了页面存储。
            </p>
          )}
          <p className="hint">
            每次运行都是全新的 JS 上下文，上一次的变量不会留下 ——
            这不是一个能攒状态的 REPL。脚本在宿主进程内执行：
            超时与"停止"能掐断死循环，但脚本层**不是**沙箱，
            不要用来跑来路不明的脚本。
          </p>
        </div>

        <div className="script-library-pane">
          <label className="compact-label">脚本库</label>
          {libraryError && (
            <div className="banner banner-error">内置脚本读取失败：{libraryError}</div>
          )}
          {library.length === 0 && !libraryError && (
            <p className="hint">正在读取脚本库…</p>
          )}
          <ul className="script-library">
            {library.map((script) => (
              <li key={script.id}>
                <button
                  type="button"
                  className={
                    script.id === selectedId
                      ? "script-library-item script-library-active"
                      : "script-library-item"
                  }
                  onClick={() => onPick(script)}
                  title="把这份脚本载入编辑器（当前编辑内容会被替换）"
                >
                  <span className="script-library-name">{script.name}</span>
                  <span className="script-library-desc">{script.description}</span>
                </button>
              </li>
            ))}
          </ul>

          <label className="compact-label">我的脚本（{ownScripts.length}）</label>
          {ownScripts.length === 0 ? (
            <p className="hint">
              还没有保存过脚本。写完上面那份，起个名字点"保存到我的脚本"。
            </p>
          ) : (
            <ul className="script-library">
              {ownScripts.map((script) => (
                <li key={script.id} className="script-own-row">
                  <button
                    type="button"
                    className={
                      script.id === selectedId
                        ? "script-library-item script-library-active"
                        : "script-library-item"
                    }
                    onClick={() => onPickOwn(script)}
                    title="载入这份脚本"
                  >
                    <span className="script-library-name">{script.name}</span>
                    <span className="script-library-desc">
                      保存于 {new Date(script.saved_at).toLocaleString()}
                    </span>
                  </button>
                  <button
                    type="button"
                    className="link-button"
                    onClick={() => onDelete(script.id)}
                    title={`删除「${script.name}」`}
                  >
                    删除
                  </button>
                </li>
              ))}
            </ul>
          )}

          <p className="hint">
            内置示例编译在二进制里随服务下发，与脚本 API 版本一起演进，
            每一份都被测试真的执行过。"我的脚本"只存在**本机浏览器**里，
            换端口打开就是另一个存储空间 —— 需要长期保存请复制出去。
          </p>
        </div>
      </div>

      <RunSummary status={status} />

      {status && <ProgressBar progress={status.progress} />}

      <ErrorBanner error={status?.error ?? null} />

      {logs.rows.length > 0 && <ResultTable rows={logs.rows} />}

      <div className="script-log-pane">
        <label className="compact-label">
          日志{logs.narrative.length > 0 && `（${logs.narrative.length} 条）`}
        </label>
        {logs.narrative.length === 0 ? (
          <p className="hint">还没有输出。运行一段脚本，或用脚本库里的示例。</p>
        ) : (
          <LogList logs={logs.narrative} />
        )}
      </div>
    </div>
  );
}

/** 运行结果的汇总条。 */
function RunSummary({ status }: { status: ScriptStatusWire | null }) {
  if (!status || status.state === "idle") {
    return null;
  }
  return (
    <div className="script-summary">
      <span className="hint">
        状态：<strong>{STATE_LABELS[status.state] ?? status.state}</strong>
      </span>
      <span className="hint">耗时 {formatDuration(status.elapsed_ms)}</span>
      <span className="hint">暂存写入 {status.staged} 条</span>
      {status.committed !== null && (
        <span className="hint">
          已提交 <strong>{status.committed}</strong>
          {status.staged_total !== null &&
            status.staged_total !== status.committed &&
            ` / 尝试写入 ${status.staged_total}`}
        </span>
      )}
      {status.run_id !== null && (
        <span className="hint">第 {status.run_id} 次运行</span>
      )}
    </div>
  );
}

/** 进度条。 */
function ProgressBar({ progress }: { progress: ScriptStatusWire["progress"] }) {
  if (!progress) {
    return null;
  }
  // 总数未知时不画百分比：画一根停在 0% 的条等于谎报"还没开始"。
  const percent =
    progress.total !== null && progress.total > 0
      ? Math.min(100, Math.round((progress.done / progress.total) * 100))
      : null;

  return (
    <div className="script-progress">
      <div className="script-progress-track">
        {percent === null ? (
          <div className="script-progress-indeterminate" />
        ) : (
          <div className="script-progress-fill" style={{ width: `${percent}%` }} />
        )}
      </div>
      <span className="hint">
        {progress.label ?? "进行中"} · {progress.done}
        {progress.total === null ? "（总数未知）" : ` / ${progress.total}`}
        {percent === null ? "" : ` · ${percent}%`}
      </span>
    </div>
  );
}

/** 失败信息。分类不同，用户该做的事就不同。 */
function ErrorBanner({ error }: { error: ScriptErrorWire | null }) {
  if (!error) {
    return null;
  }
  const { title, detail, tone } = describeError(error);
  return (
    <div className={tone === "warn" ? "banner banner-warn" : "banner banner-error"}>
      <div className="banner-title">{title}</div>
      <p>{detail}</p>
      {error.kind === "runtime" && error.stack && (
        <pre className="script-stack">{error.stack}</pre>
      )}
    </div>
  );
}

function describeError(error: ScriptErrorWire): {
  title: string;
  detail: string;
  tone: "error" | "warn";
} {
  switch (error.kind) {
    case "cancelled":
      return {
        title: "已取消",
        detail: "你按了停止。本次运行暂存的写入已全部丢弃，没有留下半成品。",
        tone: "warn",
      };
    case "timeout":
      return {
        title: "脚本超时",
        detail: `超过 ${formatDuration(error.limit_ms)} 的墙钟上限，已被中断。脚本太慢，需要优化 —— 或者把一次性遍历改成按需查询。`,
        tone: "error",
      };
    case "syntax":
      return {
        title: "语法错误",
        detail:
          error.line === null
            ? error.message
            : `第 ${error.line} 行：${error.message}`,
        tone: "error",
      };
    case "runtime":
      return {
        title: "脚本抛出了异常",
        detail:
          error.line === null
            ? error.message
            : `第 ${error.line} 行：${error.message}`,
        tone: "error",
      };
    case "host":
      return {
        title: "调用脚本 API 的方式不对",
        detail: error.message,
        tone: "error",
      };
    case "panic":
      return {
        title: "宿主内部错误",
        detail: `${error.message}（这是 BitFlip 的问题，不是脚本的问题）`,
        tone: "error",
      };
    case "commit":
      return {
        // 提交是唯一可以部分成功的结局：两个数都必须显示出来，
        // 含糊其辞会让用户以为要么全成要么全不成。
        title: "写入只完成了一部分",
        detail: `已写入 ${error.committed} / ${error.total} 条，其余未写入。原因：${error.reason}`,
        tone: "error",
      };
    case "engine":
      return {
        title: "脚本引擎故障",
        detail: error.message,
        tone: "error",
      };
  }
}

/** 日志列表。 */
function LogList({ logs }: { logs: ScriptLogWire[] }) {
  const endRef = useRef<HTMLDivElement | null>(null);
  // 自动滚到底：批处理脚本的输出是边跑边来的，不跟到底就得一直手动拖。
  useEffect(() => {
    endRef.current?.scrollIntoView({ block: "end" });
  }, [logs.length]);

  return (
    <div className="script-log">
      {logs.map((log, index) => (
        <div key={index} className={`script-log-row log-${log.level}`}>
          <span className="script-log-level">{levelLabel(log.level)}</span>
          <span className="script-log-text mono">{log.message}</span>
        </div>
      ))}
      <div ref={endRef} />
    </div>
  );
}

function levelLabel(level: string): string {
  switch (level) {
    case "warn":
      return "警告";
    case "error":
      return "错误";
    default:
      return "信息";
  }
}

/** 结果表格（来自制表符分隔的日志行）。 */
function ResultTable({ rows }: { rows: string[][] }) {
  // 首行以 `#` 开头时当表头：内置脚本就是这么标表头的。
  const first = rows[0];
  const hasHeader = first !== undefined && first.length > 0 && first[0]?.startsWith("#") === true;
  const header = hasHeader ? first.map(cleanCell) : null;
  const body = hasHeader ? rows.slice(1) : rows;
  const shown = body.slice(0, MAX_TABLE_ROWS);

  return (
    <div className="script-table-pane">
      <label className="compact-label">
        结果表格（{body.length} 行，来自脚本输出的制表符分隔行）
      </label>
      <div className="table-wrap table-wrap-short">
        <table className="data-table">
          {header && (
            <thead>
              <tr>
                {header.map((cell, index) => (
                  <th key={index}>{cell}</th>
                ))}
              </tr>
            </thead>
          )}
          <tbody>
            {shown.map((row, rowIndex) => (
              <tr key={rowIndex}>
                {row.map((cell, cellIndex) => (
                  <td key={cellIndex} className="mono">
                    {/* 地址列跟着界面语言走：定长十六进制在这里也当地址渲染。 */}
                    {/^0[0-9a-f]{15}$/.test(cell) ? formatAddress(cell) : cell}
                  </td>
                ))}
              </tr>
            ))}
          </tbody>
        </table>
      </div>
      {body.length > shown.length && (
        <p className="hint">
          表格只渲染了前 {MAX_TABLE_ROWS} 行（共 {body.length} 行）。
          完整内容在脚本输出里，日志区给了全部行。
        </p>
      )}
    </div>
  );
}

function cleanCell(cell: string): string {
  return cell.replace(/^#\s*/, "").trim();
}

/**
 * 把日志拆成"叙述"与"表格"两路。
 *
 * 一条日志可能有多行（导出类脚本会把 200 行打包成一条），所以按行拆。
 * 带制表符的行进表格，其余留在日志里 —— 这样 `export-functions` 那种
 * "一大段制表符分隔文本"在界面上是可读的，而不是一坨。
 */
function splitLogs(logs: ScriptLogWire[]): {
  narrative: ScriptLogWire[];
  rows: string[][];
} {
  const narrative: ScriptLogWire[] = [];
  const rows: string[][] = [];

  for (const log of logs) {
    const lines = log.message.split("\n");
    let kept: string[] = [];
    for (const line of lines) {
      if (line.includes("\t")) {
        rows.push(line.split("\t"));
      } else {
        kept.push(line);
      }
    }
    if (kept.length > 0) {
      narrative.push({ level: log.level, message: kept.join("\n") });
    }
  }

  return { narrative, rows };
}

/** 毫秒 → 人看的时长。 */
function formatDuration(ms: number): string {
  if (ms < 1000) {
    return `${ms} ms`;
  }
  const seconds = ms / 1000;
  if (seconds < 60) {
    return `${seconds.toFixed(1)} s`;
  }
  const minutes = Math.floor(seconds / 60);
  return `${minutes} 分 ${Math.round(seconds - minutes * 60)} 秒`;
}
