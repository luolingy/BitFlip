/**
 * 打补丁视图：默认只读预览补丁计划；"解锁并写出副本"是一个**显式点击**的按钮。
 *
 * 安全语义与 `bitflip-patch` / 服务端一致：
 *
 * - 输入地址与字节后先看**只读计划**（`/api/patch/plan`），一行不写盘；
 * - 只有点了「解锁并写出副本」，前端才带 `confirm_unlock: true` 调 `/api/patch/apply`，
 *   而且服务端只写 `xxx.patched` 副本，原文件在磁盘上始终不动。
 *
 * 这里**不做**乐观假设：计划里的每处改动、拒绝原因都照后端原样显示（§7）。
 */

import { useCallback, useState } from "react";

import {
  applyPatch,
  fetchPatchPlan,
  type PatchApplyResponse,
  type PatchEditWire,
  type PatchPlanResponse,
} from "./api";

type PlanState =
  | { kind: "idle" }
  | { kind: "loading" }
  | { kind: "ready"; plan: PatchPlanResponse }
  | { kind: "error"; message: string };

type ApplyState =
  | { kind: "idle" }
  | { kind: "loading" }
  | { kind: "done"; report: PatchApplyResponse }
  | { kind: "error"; message: string };

/** 一行编辑输入（受控）。 */
interface EditRow {
  key: number;
  vaddr: string;
  hex: string;
}

let nextRowKey = 1;

function emptyRow(): EditRow {
  return { key: nextRowKey++, vaddr: "", hex: "" };
}

export function PatchView({ token }: { token: string | null }) {
  const [rows, setRows] = useState<EditRow[]>([emptyRow()]);
  const [plan, setPlan] = useState<PlanState>({ kind: "idle" });
  const [apply, setApply] = useState<ApplyState>({ kind: "idle" });

  const edits: PatchEditWire[] = rows
    .filter((row) => row.vaddr.trim() !== "" && row.hex.trim() !== "")
    .map((row) => ({ vaddr: row.vaddr.trim(), new_hex: row.hex.trim() }));

  const canPreview = edits.length > 0;

  const updateRow = useCallback(
    (key: number, patch: Partial<EditRow>) => {
      setRows((current) =>
        current.map((row) => (row.key === key ? { ...row, ...patch } : row)),
      );
      // 输入一变，旧的计划/结果就过期了，清掉免得看错。
      setPlan({ kind: "idle" });
      setApply({ kind: "idle" });
    },
    [],
  );

  const addRow = useCallback(() => {
    setRows((current) => [...current, emptyRow()]);
  }, []);

  const removeRow = useCallback((key: number) => {
    setRows((current) => {
      const next = current.filter((row) => row.key !== key);
      return next.length === 0 ? [emptyRow()] : next;
    });
    setPlan({ kind: "idle" });
    setApply({ kind: "idle" });
  }, []);

  const preview = useCallback(async () => {
    setPlan({ kind: "loading" });
    setApply({ kind: "idle" });
    try {
      const result = await fetchPatchPlan(token, edits);
      setPlan({ kind: "ready", plan: result });
    } catch (error) {
      setPlan({
        kind: "error",
        message: error instanceof Error ? error.message : String(error),
      });
    }
  }, [token, edits]);

  const unlockAndApply = useCallback(async () => {
    setApply({ kind: "loading" });
    try {
      const report = await applyPatch(token, edits);
      setApply({ kind: "done", report });
    } catch (error) {
      setApply({
        kind: "error",
        message: error instanceof Error ? error.message : String(error),
      });
    }
  }, [token, edits]);

  return (
    <div className="analysis-view">
      <p className="hint">
        默认<strong>只读</strong>：先「预览计划」看每处改动（虚拟地址 / 文件偏移 / 原字节 /
        新字节 / 所属段），一行都不写盘。确认无误后点「解锁并写出副本」——
        只写 <span className="mono">xxx.patched</span> 副本，原文件在磁盘上始终不动。
        落在代码签名区、越界、跨段的改动会被直接拒绝并说明原因。
      </p>

      <div className="view-toolbar">
        <table className="data-table">
          <thead>
            <tr>
              <th>虚拟地址</th>
              <th>新字节（十六进制）</th>
              <th />
            </tr>
          </thead>
          <tbody>
            {rows.map((row) => (
              <tr key={row.key}>
                <td>
                  <input
                    className="input-small mono"
                    placeholder="0x401000"
                    value={row.vaddr}
                    onChange={(event) => updateRow(row.key, { vaddr: event.target.value })}
                  />
                </td>
                <td>
                  <input
                    className="input-small mono"
                    placeholder="9090"
                    value={row.hex}
                    onChange={(event) => updateRow(row.key, { hex: event.target.value })}
                  />
                </td>
                <td>
                  <button
                    className="button-small"
                    type="button"
                    onClick={() => removeRow(row.key)}
                  >
                    删除
                  </button>
                </td>
              </tr>
            ))}
          </tbody>
        </table>
        <div>
          <button className="button-small" type="button" onClick={addRow}>
            + 加一处
          </button>
          <button
            className="button-small"
            type="button"
            disabled={!canPreview || plan.kind === "loading"}
            onClick={() => void preview()}
          >
            预览计划（只读）
          </button>
        </div>
      </div>

      {plan.kind === "loading" && <div className="banner">正在生成计划…</div>}
      {plan.kind === "error" && (
        <div className="banner banner-error">{plan.message}</div>
      )}
      {plan.kind === "ready" && (
        <PlanPanel
          plan={plan.plan}
          applyState={apply}
          onApply={() => void unlockAndApply()}
          canApply={canPreview}
        />
      )}
    </div>
  );
}

function PlanPanel({
  plan,
  applyState,
  onApply,
  canApply,
}: {
  plan: PatchPlanResponse;
  applyState: ApplyState;
  onApply: () => void;
  canApply: boolean;
}) {
  return (
    <div>
      <p className="hint">
        目标 <span className="mono">{plan.target}</span>（{plan.kind}）· 副本{" "}
        <span className="mono">{plan.copy_path}</span> · 改动 {plan.changed_bytes} 字节 ·
        段 {plan.segments.length > 0 ? plan.segments.join("、") : "（无）"} · 节{" "}
        {plan.sections.length > 0 ? plan.sections.join("、") : "（无）"}
      </p>
      <table className="data-table">
        <thead>
          <tr>
            <th>虚拟地址</th>
            <th>文件偏移</th>
            <th>长度</th>
            <th>原字节</th>
            <th>新字节</th>
            <th>段</th>
            <th>节</th>
          </tr>
        </thead>
        <tbody>
          {plan.sites.map((site, index) => (
            <tr key={`${site.vaddr}-${index}`}>
              <td className="mono">{site.vaddr}</td>
              <td className="num mono">0x{site.file_offset.toString(16)}</td>
              <td className="num">{site.new.length / 2}</td>
              <td className="mono">{site.original}</td>
              <td className="mono">{site.new}</td>
              <td>{site.segment ?? "（段外）"}</td>
              <td>{site.section ?? "（无节信息）"}</td>
            </tr>
          ))}
        </tbody>
      </table>

      <div className="view-toolbar">
        <button
          className="button-small"
          type="button"
          disabled={!canApply || applyState.kind === "loading"}
          onClick={onApply}
        >
          解锁并写出副本
        </button>
        <span className="hint">这一步会写盘（只写副本，原文件不动）。</span>
      </div>

      {applyState.kind === "loading" && <div className="banner">正在写副本…</div>}
      {applyState.kind === "error" && (
        <div className="banner banner-error">{applyState.message}</div>
      )}
      {applyState.kind === "done" && (
        <div className="banner">
          已写出副本 <span className="mono">{applyState.report.copy_path}</span> ·{" "}
          {applyState.report.changed_bytes} 字节 · 段{" "}
          {applyState.report.segments.length > 0
            ? applyState.report.segments.join("、")
            : "（无）"}{" "}
          · 节{" "}
          {applyState.report.sections.length > 0
            ? applyState.report.sections.join("、")
            : "（无）"}{" "}
          · 大小 {applyState.report.size_before} → {applyState.report.size_after} 字节 ·{" "}
          原文件 <span className="mono">{applyState.report.original_path}</span>{" "}
          {applyState.report.original_untouched ? "未改动" : "（状态异常！）"}
        </div>
      )}
    </div>
  );
}
