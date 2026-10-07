import { useCallback, useEffect, useMemo, useRef, useState } from "react";

import {
  fetchInsns,
  formatAddress,
  formatSourcePosition,
  type DisasmStats,
  type InsnWire,
  type InsnsResponse,
} from "./api";

/** 每页请求的指令条数。 */
const PAGE_SIZE = 512;

/**
 * 虚拟滚动窗口：同时挂载的行数上限。
 *
 * ## 为什么必须虚拟化（这不是"优化"，而是前提）
 *
 * 一个中等规模的目标就有几十万条指令。把它们全部渲染成 DOM 节点会：
 *   1. 直接卡死主线程（几十万个元素的布局/样式计算）；
 *   2. 吃掉几百 MB 内存。
 *
 * 所以这里只渲染视口内的行 + 上下各一屏的缓冲。滚动时改的是
 * `translateY` 与行内容，行数始终是常数级。
 *
 * `OVERSCAN` 取 1 屏：太小会在快速滚动时露白，太大就失去虚拟化的意义。
 */
const OVERSCAN_SCREENS = 1;

/** 行高（像素）。必须与 CSS 里的 `.disasm-row` 高度一致。 */
const ROW_HEIGHT = 22;

/** 一页数据在客户端的状态。 */
interface Cursor {
  /** 当前页起始地址（`null` 表示从地址空间开头）。 */
  readonly from: string | null;
  /** 已加载的指令。 */
  readonly instructions: readonly InsnWire[];
  readonly stats: DisasmStats | null;
  readonly notes: readonly string[];
  /** 是否还有下一页（服务端给的游标非空）。 */
  readonly hasMore: boolean;
}

const EMPTY_CURSOR: Cursor = {
  from: null,
  instructions: [],
  stats: null,
  notes: [],
  hasMore: false,
};

/**
 * 反汇编视图。
 *
 * ## 分页与虚拟化是两件事，都在这里
 *
 * - **分页**（服务端）：一次只取一页指令，避免几百 MB 的响应。
 * - **虚拟化**（客户端）：只把视口内的行挂成 DOM。
 *
 * 两者解决的是不同瓶颈：分页管网络与内存，虚拟化管渲染。只做其中一件
 * 都不够 —— 只分页的话一页 512 行还好，但用户按 `G` 跳到末尾、
 * 连续翻几十页后累积的 DOM 依然会拖垮页面。
 */
export function DisassemblyView({
  token,
  initialAddress,
}: {
  token: string | null;
  /**
   * 从其他视图跳进来的目标地址。
   *
   * 变化时重新加载：这样"函数列表 → 反汇编 → 交叉引用"这条动线
   * 不需要用户手动再输一次地址。地址落在某条指令中间时服务端会吸附到
   * 包含它的那条指令，因此这里不需要额外对齐。
   */
  initialAddress?: string | null;
}) {
  const [cursor, setCursor] = useState<Cursor>(EMPTY_CURSOR);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [selected, setSelected] = useState(0);
  const [scrollTop, setScrollTop] = useState(0);
  const [viewportHeight, setViewportHeight] = useState(480);

  const scrollerRef = useRef<HTMLDivElement | null>(null);
  const loadToken = useRef(0);

  const load = useCallback(
    async (from: string | null) => {
      const myToken = ++loadToken.current;
      setLoading(true);
      setError(null);
      try {
        const response: InsnsResponse = await fetchInsns(token, from, PAGE_SIZE);
        // 竞态保护：用户可能连续翻页，只有最后一次请求的结果作数。
        // 没有这个检查的话，慢的旧响应会覆盖新页的数据。
        if (myToken !== loadToken.current) {
          return;
        }
        setCursor({
          from,
          instructions: response.page.instructions,
          stats: response.stats,
          notes: response.notes,
          hasMore: response.page.has_more,
        });
        setSelected(0);
        // 换页后回到顶部：否则滚动位置会落在新页的中间，看起来像跳页
        if (scrollerRef.current) {
          scrollerRef.current.scrollTop = 0;
        }
      } catch (caught) {
        if (myToken !== loadToken.current) {
          return;
        }
        setError(caught instanceof Error ? caught.message : String(caught));
      } finally {
        if (myToken === loadToken.current) {
          setLoading(false);
        }
      }
    },
    [token],
  );

  useEffect(() => {
    void load(null);
    // 只在挂载时定位到地址空间开头；之后由 initialAddress 的 effect 接管。
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [load]);

  // 外部跳转（来自函数/交叉引用/字符串视图）。
  const externalJump = useRef<string | null>(null);
  useEffect(() => {
    if (!initialAddress) {
      return;
    }
    // 同一个地址重复请求时不重载：否则用户点两次同一个函数会白扫两遍。
    if (externalJump.current === initialAddress) {
      return;
    }
    externalJump.current = initialAddress;
    void load(initialAddress);
  }, [initialAddress, load]);

  // 视口高度变化要重新计算虚拟窗口
  useEffect(() => {
    const element = scrollerRef.current;
    if (!element) {
      return;
    }
    const update = () => setViewportHeight(element.clientHeight || 480);
    update();
    if (typeof ResizeObserver === "undefined") {
      return;
    }
    const observer = new ResizeObserver(update);
    observer.observe(element);
    return () => observer.disconnect();
  }, []);

  const total = cursor.instructions.length;
  const visibleCount = Math.max(Math.ceil(viewportHeight / ROW_HEIGHT), 1);
  const overscan = visibleCount * OVERSCAN_SCREENS;

  const windowRange = useMemo(() => {
    const first = Math.max(Math.floor(scrollTop / ROW_HEIGHT) - overscan, 0);
    const last = Math.min(first + visibleCount + overscan * 2, total);
    return { first, last };
  }, [scrollTop, visibleCount, overscan, total]);

  const visible = cursor.instructions.slice(windowRange.first, windowRange.last);

  /** 跳到指定序号并让它可见。 */
  const goTo = useCallback(
    (index: number) => {
      const clamped = Math.max(0, Math.min(index, total - 1));
      setSelected(clamped);
      const element = scrollerRef.current;
      if (element) {
        // 让目标行落在视口中部，而不是贴着边缘
        const target = clamped * ROW_HEIGHT - element.clientHeight / 2 + ROW_HEIGHT;
        element.scrollTop = Math.max(target, 0);
      }
    },
    [total],
  );

  const onKeyDown = useCallback(
    (event: React.KeyboardEvent<HTMLDivElement>) => {
      // 只处理我们认识的键，其余一律放行 —— 拦掉 Tab 之类的键会毁掉可访问性
      switch (event.key) {
        case "j":
        case "ArrowDown":
          event.preventDefault();
          goTo(selected + 1);
          break;
        case "k":
        case "ArrowUp":
          event.preventDefault();
          goTo(selected - 1);
          break;
        case "g":
          event.preventDefault();
          goTo(0);
          break;
        case "G":
          event.preventDefault();
          goTo(total - 1);
          break;
        case "b":
          event.preventDefault();
          globalThis.history.back();
          break;
        case "Enter": {
          // 跟随跳转：直接跳到本行指令的控制流目标。
          // 目标可能不在本页 —— 那正是服务端 containing() 的用武之地：
          // 它会吸附到包含该地址的指令。
          event.preventDefault();
          const current = cursor.instructions[selected];
          if (current?.target) {
            void load(current.target);
          }
          break;
        }
        default:
          break;
      }
    },
    [cursor.instructions, goTo, load, selected, total],
  );

  const stats = cursor.stats;

  return (
    <div className="disasm">
      <div className="disasm-toolbar">
        <span className="disasm-hint">
          按 <kbd>j</kbd>/<kbd>k</kbd> 移动 · <kbd>g</kbd>/<kbd>G</kbd> 首尾 ·
          <kbd>Enter</kbd> 跟随跳转 · 单击地址跳转
        </span>
        <span className="disasm-pager">
          <button type="button" onClick={() => void load(null)} disabled={loading}>
            首
          </button>
          <button
            type="button"
            onClick={() => void load(cursor.instructions.at(-1)?.address ?? null)}
            disabled={loading || !cursor.hasMore}
            title="加载下一页"
          >
            下一页
          </button>
          <span className="mono">
            {cursor.instructions.length > 0
              ? `${formatAddress(cursor.instructions[0]?.address ?? null)} … ${formatAddress(
                  cursor.instructions.at(-1)?.address ?? null,
                )}`
              : "（无指令）"}
          </span>
        </span>
      </div>

      {/*
        覆盖率说明：不做笼统的"分析完成"。
        线性扫描会把数据误当指令，因此必须把"可达"与"仅线性"分开报告，
        并告诉用户灰色行的可信度更低。
      */}
      {stats && (
        <div className="disasm-stats">
          <Chip label="已索引" value={stats.indexed} />
          <Chip label="递归可达" value={stats.reachable} tone="ok" />
          <Chip label="仅线性" value={stats.linear_only} tone="warn" />
          <Chip label="无法解码" value={stats.decode_failures} tone="dim" />
          <Chip label="可执行段" value={stats.executable_segments} />
          <Chip label="映射字节" value={stats.mapped_bytes} />
          <Chip label="索引估算" value={`${stats.index_bytes} B`} />
          {stats.truncated > 0 && <Chip label="截断" value={stats.truncated} tone="warn" />}
        </div>
      )}

      {cursor.notes.length > 0 && (
        <ul className="disasm-notes">
          {cursor.notes.map((note) => (
            <li key={note}>{note}</li>
          ))}
        </ul>
      )}

      {error && <div className="banner banner-error">{error}</div>}

      {loading && <div className="banner">正在扫描并解码…（大文件首次扫描需要更久）</div>}

      {!loading && total === 0 && !error && (
        <div className="placeholder-block">
          <p className="placeholder">本页没有已索引的指令。</p>
          <p className="hint">
            可能原因：目标没有可执行区域，或当前地址之后没有可解码的字节。
            用「首」回到开头重试。
          </p>
        </div>
      )}

      {total > 0 && (
        <div
          className="disasm-body"
          ref={scrollerRef}
          tabIndex={0}
          role="grid"
          aria-label="反汇编"
          onKeyDown={onKeyDown}
          onScroll={(event) => setScrollTop(event.currentTarget.scrollTop)}
        >
          {/* 撑开总高度，让滚动条反映真实行数 */}
          <div style={{ height: total * ROW_HEIGHT, position: "relative" }}>
            <div style={{ transform: `translateY(${windowRange.first * ROW_HEIGHT}px)` }}>
              {visible.map((insn, offset) => {
                const index = windowRange.first + offset;
                return (
                  <InsnRow
                    key={insn.address}
                    insn={insn}
                    index={index}
                    selected={index === selected}
                    onSelect={() => setSelected(index)}
                    onFollow={
                      insn.target
                        ? () => {
                            void load(insn.target);
                          }
                        : undefined
                    }
                  />
                );
              })}
            </div>
          </div>
        </div>
      )}
    </div>
  );
}

/** 一行指令。 */
function InsnRow({
  insn,
  index,
  selected,
  onSelect,
  onFollow,
}: {
  insn: InsnWire;
  index: number;
  selected: boolean;
  onSelect: () => void;
  /** `undefined` 表示这条指令没有可跟随的直接目标。 */
  onFollow?: (() => void) | undefined;
}) {
  const classes = ["disasm-row"];
  if (selected) {
    classes.push("disasm-row-selected");
  }
  if (!insn.reachable) {
    // 仅线性扫到的行降低亮度：它们可能是数据被误当成指令。
    classes.push("disasm-row-linear");
  }

  // 源位置（调试信息）。没有调试信息时是 null —— 不显示，也不写"未知"。
  const source = formatSourcePosition(insn.file, insn.line);

  return (
    <div
      className={classes.join(" ")}
      style={{ height: ROW_HEIGHT }}
      onClick={onSelect}
      role="row"
      aria-rowindex={index + 1}
    >
      <span className="disasm-addr mono" onClick={onFollow} title={onFollow ? "跳转到该目标" : undefined}>
        {formatAddress(insn.address)}
      </span>
      <span className="disasm-bytes mono">{insn.bytes}</span>
      <span className="disasm-text mono">{insn.text}</span>
      <span className={`disasm-flow flow-${insn.flow}`}>{insn.flow_label}</span>
      {insn.target && (
        <span className="disasm-target mono">{formatAddress(insn.target)}</span>
      )}
      {/*
        源位置靠右显示（`margin-left: auto`）：它不像地址/目标那样属于控制流，
        但又是"这条指令在源码哪一行"的唯一答案。没有调试信息时整列不出现，
        而不是每行都挂一个"未知"。
      */}
      {source && (
        <span className="disasm-src mono" title={insn.file ?? undefined}>
          {source}
        </span>
      )}
    </div>
  );
}

function Chip({
  label,
  value,
  tone,
}: {
  label: string;
  value: number | string;
  tone?: "ok" | "warn" | "dim";
}) {
  const classes = ["stat-chip"];
  if (tone) {
    classes.push(`stat-chip-${tone}`);
  }
  return (
    <span className={classes.join(" ")}>
      <span className="stat-chip-label">{label}</span>
      <span className="stat-chip-value mono">{value}</span>
    </span>
  );
}
