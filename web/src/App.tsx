import { useCallback, useEffect, useMemo, useState, type ReactNode } from "react";

import {
  ApiError,
  fetchHealth,
  fetchSections,
  fetchTarget,
  formatAddress,
  formatSize,
  resolveToken,
  type HealthResponse,
  type ObjectInfo,
  type SectionInfo,
  type SegmentInfo,
  type SectionsResponse,
  type TargetInfo,
} from "./api";
import { DisassemblyView } from "./DisassemblyView";
import { FunctionsView, HexView, StringsView, XrefsView } from "./AnalysisViews";
import { MembersView } from "./MembersView";
import {
  ArgScanView,
  CallGraphView,
  CodeMapView,
  ConstScanView,
  FrameScanView,
  JumpTablesView,
  ReachabilityView,
  XrefSearchView,
} from "./M6Views";

type LoadState =
  | { kind: "loading" }
  | {
      kind: "ready";
      health: HealthResponse;
      target: TargetInfo | null;
      structure: SectionsResponse | null;
    }
  | { kind: "error"; message: string; forbidden: boolean };

/**
 * 左侧导航。
 *
 * `ready: true` 的项在本里程碑真实可用；其余一律标注里程碑并置灰。
 * 不做"点了没反应"的假入口（CLAUDE.md §7）。
 */
type ViewId =
  | "structure"
  | "disasm"
  | "functions"
  | "xrefs"
  | "strings"
  | "hex"
  | "members"
  | "call-graph"
  | "code-map"
  | "jump-tables"
  | "const-scan"
  | "arg-scan"
  | "frames"
  | "xref-search"
  | "reachability";

const NAV_SECTIONS: readonly {
  /** 只有 `ready: true` 的项才是真实可切换的视图。 */
  id: ViewId | null;
  title: string;
  milestone: string;
  hint: string;
  ready: boolean;
}[] = [
  { id: "structure", title: "段与节", milestone: "M1", hint: "地址空间、节表、入口点", ready: true },
  { id: "disasm", title: "反汇编", milestone: "M2", hint: "线性 + 递归下降双策略扫描", ready: true },
  // M3 交付了函数识别、交叉引用与字符串提取，这三项不再是"计划中"。
  { id: "functions", title: "函数", milestone: "M3", hint: "函数识别 + 来源与置信度", ready: true },
  { id: "xrefs", title: "交叉引用", milestone: "M3", hint: "谁引用了我 / 我引用了谁", ready: true },
  { id: "strings", title: "字符串", milestone: "M3", hint: "字符串提取与地址定位", ready: true },
  { id: "hex", title: "十六进制", milestone: "M3", hint: "原始字节视图", ready: true },
  // M5：归档成员树。静态库/动态库是 M5 的目标，成员列表是进入它们的入口。
  { id: "members", title: "归档成员", milestone: "M5", hint: "静态库/归档的成员与按成员分析", ready: true },
  // M6：函数间的关系与"这段字节是什么"。
  { id: "call-graph", title: "调用图", milestone: "M6", hint: "谁调用了谁，含未解析的间接调用", ready: true },
  { id: "code-map", title: "数据/代码", milestone: "M6", hint: "判定结论、置信度与依据", ready: true },
  { id: "jump-tables", title: "跳转表", milestone: "M6", hint: "switch 分派表与目标集合", ready: true },
  { id: "const-scan", title: "常量/结构体", milestone: "M6", hint: "字符串引用、访问位移、高频立即数", ready: true },
  { id: "arg-scan", title: "参数推断", milestone: "M6", hint: "调用约定与参数下界", ready: true },
  { id: "frames", title: "栈帧 / 局部变量", milestone: "M6", hint: "展开信息与前导扫描", ready: true },
  // 交付物 7：过滤与可达性。搜索是"先知道范围再找引用"的入口，
  // 可达性回答"这一片代码是不是活的"（但必须连着未解析数一起读）。
  { id: "xref-search", title: "交叉引用搜索", milestone: "M6", hint: "按类型/来源/范围过滤全表", ready: true },
  { id: "reachability", title: "可达性", milestone: "M6", hint: "从入口沿调用边的可达集（下界）", ready: true },
  // 下面这些确实还没做（M8 签名库匹配），保持置灰 —— 不给点了没反应的按钮。
  { id: null, title: "签名匹配", milestone: "M8", hint: "库函数签名识别", ready: false },
];

/** 视图标题（与导航项一一对应）。 */
const VIEW_TITLES: Record<ViewId, string> = {
  structure: "段与节",
  disasm: "反汇编",
  functions: "函数",
  xrefs: "交叉引用",
  strings: "字符串",
  hex: "十六进制",
  members: "归档成员",
  "call-graph": "调用图",
  "code-map": "数据/代码判定",
  "jump-tables": "跳转表",
  "const-scan": "常量 / 结构体初步",
  "arg-scan": "调用约定与参数推断",
  frames: "栈帧 / 局部变量",
  "xref-search": "交叉引用搜索",
  reachability: "可达性",
};


export function App() {
  const token = useMemo(resolveToken, []);
  const [state, setState] = useState<LoadState>({ kind: "loading" });
  const [view, setView] = useState<ViewId>("structure");
  /**
   * 当前聚焦的地址。
   *
   * 跨视图共享：从函数列表点一个函数，跳到反汇编的那个地址；再切到
   * 交叉引用看"谁调用了它"。逆向时的动作串就是这样 —— 地址是这条
   * 动线上的位置，视图只是看它的角度。
   */
  const [focus, setFocus] = useState<string | null>(null);
  /**
   * 导航历史（地址栈）。
   *
   * 逆向是反复跳转的过程，没有"返回"就只能靠手抄地址回去 —— 这也是
   * 为什么它必须有，而不是"以后再加"的便利功能。
   */
  const [history, setHistory] = useState<string[]>([]);

  const navigate = useCallback(
    (address: string) => {
      setFocus((current) => {
        if (current) {
          setHistory((past) => [...past, current]);
        }
        return address;
      });
    },
    [],
  );

  const goBack = useCallback(() => {
    setHistory((past) => {
      // 用 at(-1) 而不是 [length-1]：索引访问在 noUncheckedIndexedAccess 下
      // 是 `string | undefined`，空数组的情形必须显式处理。
      const previous = past.at(-1);
      if (previous === undefined) {
        return past;
      }
      setFocus(previous);
      return past.slice(0, -1);
    });
  }, []);

  const load = useCallback(async () => {
    setState({ kind: "loading" });
    try {
      const health = await fetchHealth(token);
      const target = health.target ?? (await fetchTarget(token));
      // 结构视图与识别结论分开取：解析可能失败，但识别结论仍然要能显示。
      const structure = target ? await fetchSections(token) : null;
      setState({ kind: "ready", health, target, structure });
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

  const { health, target, structure } = state;
  const parsed = structure?.parsed ?? null;

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
              <li key={section.id ?? section.title}>
                <button
                  type="button"
                  className={
                    section.ready
                      ? section.id === view
                        ? "nav-item nav-active nav-clickable"
                        : "nav-item nav-clickable"
                      : "nav-item nav-disabled"
                  }
                  onClick={section.id ? () => setView(section.id as ViewId) : undefined}
                  disabled={!section.ready}
                  aria-current={section.id === view ? "page" : undefined}
                >
                  <span className="nav-name">{section.title}</span>
                  <span className="nav-milestone">{section.milestone}</span>
                  <span className="nav-hint">{section.hint}</span>
                </button>
              </li>
            ))}
          </ul>
          <p className="pane-note">
            未落地的入口一律置灰：宁可不显示，也不给一个点了没反应的按钮。
          </p>
        </aside>

        <main className="pane pane-center">
          <div className="view-header">
            <button
              type="button"
              className="back-button"
              onClick={goBack}
              disabled={history.length === 0}
              title="返回上一个地址"
            >
              ← 返回
            </button>
            <PaneTitle title={VIEW_TITLES[view]} />
            {focus && <span className="mono focus-address">{formatAddress(focus)}</span>}
          </div>
          {view === "disasm" ? (
            parsed ? (
              <DisassemblyView token={token} initialAddress={focus} />
            ) : (
              <ParseFailure target={target} />
            )
          ) : view === "functions" ? (
            <FunctionsView token={token} onNavigate={navigate} />
          ) : view === "xrefs" ? (
            <XrefsView token={token} initialAddress={focus} onNavigate={navigate} />
          ) : view === "strings" ? (
            <StringsView token={token} onNavigate={navigate} />
          ) : view === "hex" ? (
            <HexView token={token} initialAddress={focus} />
          ) : view === "members" ? (
            <MembersView token={token} onNavigate={navigate} />
          ) : view === "call-graph" ? (
            <CallGraphView token={token} onNavigate={navigate} />
          ) : view === "code-map" ? (
            <CodeMapView token={token} />
          ) : view === "jump-tables" ? (
            <JumpTablesView token={token} onNavigate={navigate} />
          ) : view === "const-scan" ? (
            <ConstScanView token={token} />
          ) : view === "arg-scan" ? (
            <ArgScanView token={token} />
          ) : view === "frames" ? (
            <FrameScanView token={token} />
          ) : view === "xref-search" ? (
            <XrefSearchView token={token} onNavigate={navigate} />
          ) : view === "reachability" ? (
            <ReachabilityView token={token} onNavigate={navigate} />
          ) : parsed ? (
            <StructureView parsed={parsed} target={target} />
          ) : (
            <ParseFailure target={target} />
          )}
        </main>

        <aside className="pane pane-right">
          <PaneTitle title="目标信息" />
          {target ? (
            <TargetFacts target={target} parsed={parsed} />
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

          {parsed && parsed.notes.length > 0 && (
            <>
              <PaneTitle title="解析说明" />
              <ul className="notes">
                {parsed.notes.map((note) => (
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
              label="info 格式"
              value={structure ? `v${structure.format_version}` : "-"}
            />
            <Fact
              label="前端资源"
              value={health.ui_embedded ? "已内嵌进二进制" : "占位页（未构建）"}
            />
            <Fact label="已运行" value={`${Math.round(health.uptime_ms / 1000)} 秒`} />
          </dl>
        </aside>
      </div>

      <footer className="app-footer">
        <span>仅监听回环地址 · 令牌与 Origin 双重校验 · 服务在终端按 Ctrl+C 退出</span>
        <span className="mono">
          {target
            ? `嗅探 ${formatSize(target.sniffed_bytes)} / 文件 ${formatSize(target.file_size)}`
            : "无目标"}
        </span>
      </footer>
    </Shell>
  );
}

/** 解析失败：明确说明"没有结构结果"以及原因，不留空白。 */
function ParseFailure({ target }: { target: TargetInfo | null }) {
  return (
    <div className="placeholder-block">
      <p className="placeholder">
        <strong>未能得到结构结果。</strong>
        识别结论仍然可用（见右侧），但段/节表没有解析出来。
      </p>
      {target && target.notes.length > 0 && (
        <ul className="notes">
          {target.notes.map((note) => (
            <li key={note}>{note}</li>
          ))}
        </ul>
      )}
    </div>
  );
}

/** 段/节结构视图：内存视角（段）与文件视角（节）分开呈现。 */
function StructureView({ parsed, target }: { parsed: ObjectInfo; target: TargetInfo | null }) {
  const [tab, setTab] = useState<"sections" | "segments">("sections");
  // 入口点落在哪个节里 —— 这是"节表解析对不对"最直观的验证
  const entrySection = useMemo(() => {
    if (!target?.entry) {
      return null;
    }
    const entry = BigInt(`0x${target.entry}`);
    for (const section of parsed.sections) {
      if (!section.loaded) {
        continue;
      }
      const start = BigInt(`0x${section.vaddr}`);
      const end = start + BigInt(section.file_size);
      if (entry >= start && entry < end) {
        return section.name;
      }
    }
    return null;
  }, [parsed.sections, target?.entry]);

  return (
    <>
      <div className="toolbar">
        <div className="tabs">
          <button
            type="button"
            className={tab === "sections" ? "tab tab-active" : "tab"}
            onClick={() => setTab("sections")}
          >
            节（文件视角） {parsed.sections.length}
          </button>
          <button
            type="button"
            className={tab === "segments" ? "tab tab-active" : "tab"}
            onClick={() => setTab("segments")}
          >
            段（内存视角） {parsed.segments.length}
          </button>
        </div>
        <span className="hint">
          {entrySection ? `入口点位于 ${entrySection}` : "入口点不在任何已加载节内"}
        </span>
      </div>

      <div className="table-wrap">
        {tab === "sections" ? (
          parsed.sections.length > 0 ? (
            <table className="data-table">
              <thead>
                <tr>
                  <th>名称</th>
                  <th>虚拟地址</th>
                  <th>文件偏移</th>
                  <th className="num">大小</th>
                  <th>权限</th>
                  <th>类别</th>
                  <th>已映射</th>
                </tr>
              </thead>
              <tbody>
                {parsed.sections.map((section, index) => (
                  <SectionRow
                    key={`${section.name}-${index}`}
                    section={section}
                    isEntry={section.name === entrySection}
                  />
                ))}
              </tbody>
            </table>
          ) : (
            <p className="placeholder">该对象没有节表（可能已被剥离）。</p>
          )
        ) : parsed.segments.length > 0 ? (
          <table className="data-table">
            <thead>
              <tr>
                <th>名称</th>
                <th>虚拟地址</th>
                <th className="num">内存大小</th>
                <th>文件范围</th>
                <th>权限</th>
                <th>类别</th>
              </tr>
            </thead>
            <tbody>
              {parsed.segments.map((segment, index) => (
                <SegmentRow key={`${segment.name}-${index}`} segment={segment} />
              ))}
            </tbody>
          </table>
        ) : (
          <p className="placeholder">该对象没有段表（常见于可重定位目标文件）。</p>
        )}
      </div>

      <div className="struct-footer">
        <span>
          段是<strong>内存视角</strong>（分析走地址空间），节是<strong>文件视角</strong>（链接器与调试信息）。
          两者都列出是因为它们回答不同的问题。
        </span>
      </div>
    </>
  );
}

function SectionRow({ section, isEntry }: { section: SectionInfo; isEntry: boolean }) {
  return (
    <tr className={isEntry ? "row-entry" : undefined}>
      <td className="mono">
        {section.name || <span className="hint">（无名）</span>}
        {isEntry && <span className="badge badge-entry">入口</span>}
      </td>
      <td className="mono">{formatAddress(section.vaddr)}</td>
      <td className="mono">{`0x${section.file_offset.toString(16)}`}</td>
      <td className="mono num">{`0x${section.file_size.toString(16)}`}</td>
      <td className="mono perms">{section.perms}</td>
      <td>{section.kind_label}</td>
      <td>{section.loaded ? "是" : "否"}</td>
    </tr>
  );
}

function SegmentRow({ segment }: { segment: SegmentInfo }) {
  const fileRange =
    segment.file_offset === null || segment.file_size === null
      ? "不占文件空间"
      : `0x${segment.file_offset.toString(16)} + 0x${segment.file_size.toString(16)}`;
  return (
    <tr>
      <td className="mono">{segment.name || <span className="hint">（无名）</span>}</td>
      <td className="mono">{formatAddress(segment.vaddr)}</td>
      <td className="mono num">{`0x${segment.vsize.toString(16)}`}</td>
      <td className="mono">{fileRange}</td>
      <td className="mono perms">{segment.perms}</td>
      <td>{segment.kind_label}</td>
    </tr>
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

function TargetFacts({ target, parsed }: { target: TargetInfo; parsed: ObjectInfo | null }) {
  return (
    <dl className="facts">
      <Fact label="格式" value={`${target.object_label}（${target.object}）`} />
      <Fact label="容器" value={`${target.container_label}（${target.container}）`} />
      {target.member_kind && <Fact label="成员格式" value={target.member_kind} />}
      <Fact label="架构" value={target.arch ?? "未识别"} />
      <Fact label="位宽" value={target.bits === 0 ? "未识别" : `${target.bits} 位`} />
      <Fact label="端序" value={target.endian ?? "未识别"} />
      <Fact label="入口点" value={formatAddress(target.entry)} />
      <Fact label="镜像基址" value={formatAddress(target.image_base)} />
      <Fact label="节数" value={target.sections === null ? "-" : String(target.sections)} />
      {parsed && <Fact label="段数" value={String(parsed.segments.length)} />}
      {parsed?.format_type && <Fact label="类型" value={parsed.format_type} />}
      {parsed?.os_abi && <Fact label="目标 ABI" value={parsed.os_abi} />}
      {parsed?.subsystem && <Fact label="子系统" value={parsed.subsystem} />}
      {parsed && (
        <Fact
          label="符号可见性"
          value={parsed.is_stripped ? "已剥离符号表" : "含符号表"}
        />
      )}
      {parsed && <Fact label="导入" value={String(parsed.imports.length)} />}
      {parsed && <Fact label="导出" value={String(parsed.exports.length)} />}
      {parsed && <Fact label="符号" value={String(parsed.symbols.length)} />}
      {parsed && <Fact label="重定位" value={String(parsed.relocations.length)} />}
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
