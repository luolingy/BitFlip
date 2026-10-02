import { useCallback, useEffect, useMemo, useState, type ReactNode } from "react";

import {
  ApiError,
  fetchHealth,
  fetchTarget,
  formatSize,
  resolveToken,
  type HealthResponse,
  type TargetInfo,
} from "./api";

type LoadState =
  | { kind: "loading" }
  | { kind: "ready"; health: HealthResponse; target: TargetInfo | null }
  | { kind: "error"; message: string; forbidden: boolean };

/** 左侧导航：每项都标注真实可用里程碑，不做"看起来能用其实没实现"的假入口。 */
const NAV_SECTIONS: readonly { title: string; milestone: string; hint: string }[] = [
  { title: "函数", milestone: "M5", hint: "函数识别 + 置信度合并" },
  { title: "符号", milestone: "M3", hint: "符号来源与优先级" },
  { title: "段与节", milestone: "M5", hint: "地址空间与段映射" },
  { title: "交叉引用", milestone: "M6", hint: "谁引用了我 / 我引用了谁" },
  { title: "字符串", milestone: "M7", hint: "字符串提取与引用定位" },
  { title: "签名匹配", milestone: "M8", hint: "库函数签名识别" },
];

export function App() {
  const token = useMemo(resolveToken, []);
  const [state, setState] = useState<LoadState>({ kind: "loading" });

  const load = useCallback(async () => {
    setState({ kind: "loading" });
    try {
      const health = await fetchHealth(token);
      const target = health.target ?? (await fetchTarget(token));
      setState({ kind: "ready", health, target });
    } catch (error) {
      if (error instanceof ApiError) {
        setState({ kind: "error", message: error.message, forbidden: error.status === 403 });
      } else {
        setState({
          kind: "error",
          message: error instanceof Error ? error.message : String(error),
          forbidden: false,
        });
      }
    }
  }, [token]);

  useEffect(() => {
    void load();
  }, [load]);

  if (state.kind === "loading") {
    return (
      <Shell>
        <div className="banner">正在连接本地服务…</div>
      </Shell>
    );
  }

  if (state.kind === "error") {
    return (
      <Shell>
        <div className="banner banner-error">
          <div className="banner-title">
            {state.forbidden ? "访问令牌校验未通过" : "无法连接本地服务"}
          </div>
          <p>{state.message}</p>
          {state.forbidden && (
            <p className="hint">
              令牌在启动 BitFlip 时生成，只出现在终端打印的那个 URL 里（片段 <code>#token=…</code>）。
              重新运行一次 <code>bitflip &lt;目标&gt;</code>，用新打印的 URL 打开即可。
            </p>
          )}
          <button type="button" onClick={() => void load()}>
            重试
          </button>
        </div>
      </Shell>
    );
  }

  const { health, target } = state;

  return (
    <Shell>
      <header className="app-header">
        <div className="brand">
          <span className="brand-mark">BitFlip</span>
          <span className="brand-zh">比特翻转</span>
        </div>
        <div className="header-target" title={target?.path ?? ""}>
          {target ? (
            <>
              <span className="mono">{target.path}</span>
              <span className="chip">{target.summary}</span>
            </>
          ) : (
            <span className="hint">未打开目标（服务以无目标模式运行）</span>
          )}
        </div>
        <div className="header-status">
          <span className="dot" aria-hidden="true" />
          <span>
            v{health.version} · core API v{health.core_api_version}
          </span>
        </div>
      </header>

      <div className="app-body">
        <aside className="pane pane-left">
          <PaneTitle title="导航" />
          <ul className="nav-list">
            {NAV_SECTIONS.map((section) => (
              <li key={section.title} className="nav-item nav-disabled">
                <span className="nav-name">{section.title}</span>
                <span className="nav-milestone">{section.milestone}</span>
                <span className="nav-hint">{section.hint}</span>
              </li>
            ))}
          </ul>
          <p className="pane-note">
            这些入口在对应里程碑落地前一律置灰：宁可不显示，也不给一个点了没反应的按钮。
          </p>
        </aside>

        <main className="pane pane-center">
          <PaneTitle title="反汇编视图" />
          <div className="toolbar">
            <input
              className="address-input"
              placeholder="跳转到地址（例如 0000000000401000）"
              disabled
              title="地址跳转在 M2 接入解码器后可用"
            />
            <button type="button" disabled title="M2 起可用">
              跳转
            </button>
            <span className="hint">M2</span>
          </div>

          <div className="disasm">
            <div className="disasm-head">
              <span>地址</span>
              <span>机器码</span>
              <span>指令</span>
              <span>注释 / 符号</span>
            </div>
            <div className="disasm-body">
              <p className="placeholder">
                解码器（capstone / iced-x86）与分页指令索引在 <strong>M2</strong> 接入。
                届时这里显示的是<strong>结构化指令</strong>（流程、读写寄存器、内存操作数），
                不是被物化成字符串的指令流 —— 后者在 100MB 级目标上会直接把内存吃光。
              </p>
              {target?.entry && (
                <p className="placeholder mono">
                  入口点已识别：{target.entry}
                  {target.image_base ? `（镜像基址 ${target.image_base}）` : ""}
                </p>
              )}
            </div>
          </div>
        </main>

        <aside className="pane pane-right">
          <PaneTitle title="目标信息" />
          {target ? (
            <TargetFacts target={target} />
          ) : (
            <p className="hint">本次会话没有打开目标。</p>
          )}

          {target && target.notes.length > 0 && (
            <>
              <PaneTitle title="判定依据与限制" />
              <ul className="notes">
                {target.notes.map((note) => (
                  <li key={note}>{note}</li>
                ))}
              </ul>
            </>
          )}

          <PaneTitle title="本次运行" />
          <dl className="facts">
            <Fact label="服务版本" value={`v${health.version}`} />
            <Fact label="core API" value={`v${health.core_api_version}`} />
            <Fact label="server API" value={`v${health.server_api_version}`} />
            <Fact
              label="前端资源"
              value={health.ui_embedded ? "已内嵌进二进制" : "占位页（未构建）"}
            />
            <Fact label="已运行" value={`${Math.round(health.uptime_ms / 1000)} 秒`} />
          </dl>
        </aside>
      </div>

      <footer className="app-footer">
        <span>
          仅监听回环地址 · 令牌与 Origin 双重校验 · 服务在终端按 Ctrl+C 退出
        </span>
        <span className="mono">
          {target ? `嗅探 ${formatSize(target.sniffed_bytes)} / 文件 ${formatSize(target.file_size)}` : "无目标"}
        </span>
      </footer>
    </Shell>
  );
}

function Shell({ children }: { children: ReactNode }) {
  return <div className="app">{children}</div>;
}

function PaneTitle({ title }: { title: string }) {
  return <h2 className="pane-title">{title}</h2>;
}

function Fact({ label, value }: { label: string; value: string }) {
  return (
    <>
      <dt>{label}</dt>
      <dd className="mono">{value}</dd>
    </>
  );
}

function TargetFacts({ target }: { target: TargetInfo }) {
  return (
    <dl className="facts">
      <Fact label="格式" value={`${target.object_label}（${target.object}）`} />
      <Fact label="容器" value={`${target.container_label}（${target.container}）`} />
      {target.member_kind && <Fact label="成员格式" value={target.member_kind} />}
      <Fact label="架构" value={target.arch ?? "未识别"} />
      <Fact label="位宽" value={target.bits === 0 ? "未识别" : `${target.bits} 位`} />
      <Fact label="端序" value={target.endian ?? "未识别"} />
      <Fact label="入口点" value={target.entry ?? "-"} />
      <Fact label="镜像基址" value={target.image_base ?? "-"} />
      <Fact label="节数" value={target.sections === null ? "-" : String(target.sections)} />
      {target.member_count > 0 && (
        <Fact
          label="归档成员"
          value={`${target.member_count}${target.members_truncated ? "+（已截断）" : ""}`}
        />
      )}
      <Fact label="文件大小" value={formatSize(target.file_size)} />
    </dl>
  );
}
