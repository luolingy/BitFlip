/**
 * APK 清单与资源表视图（M3）。
 *
 * 与 DEX（`/api/dex/*`）同族：清单与资源表是 **APK 容器层**的东西，不是
 * "某个地址段的对象"，所以是独立的视图与端点族。
 *
 * 诚实边界：
 * - 清单里解不出的资源引用（`@7f0d0001`）原样保留并计数，不编造值；
 * - 资源表只报**结构**（包/类型/配置/条目计数），值要按 id 查
 *   （`/api/apk/resource`），查不到就明说查不到。
 */

import { useCallback, useEffect, useState } from "react";

import {
  fetchManifest,
  fetchResource,
  fetchResources,
  formatSize,
  type ArscPackageSnapshot,
  type ArscStructure,
  type ManifestFactsWire,
  type ManifestResponse,
  type ResourceLookupResponse,
  type ResourcesResponse,
} from "./api";

type Load<T> =
  | { kind: "loading" }
  | { kind: "ready"; value: T }
  | { kind: "missing" }
  | { kind: "error"; message: string };

export function ApkView({ token }: { token: string | null }) {
  const [manifest, setManifest] = useState<Load<ManifestResponse>>({ kind: "loading" });
  const [resources, setResources] = useState<Load<ResourcesResponse>>({ kind: "loading" });

  useEffect(() => {
    let cancelled = false;
    void (async () => {
      try {
        const value = await fetchManifest(token);
        if (!cancelled) {
          setManifest(value ? { kind: "ready", value } : { kind: "missing" });
        }
      } catch (error) {
        if (!cancelled) {
          setManifest({
            kind: "error",
            message: error instanceof Error ? error.message : String(error),
          });
        }
      }
    })();
    void (async () => {
      try {
        const value = await fetchResources(token);
        if (!cancelled) {
          setResources(value ? { kind: "ready", value } : { kind: "missing" });
        }
      } catch (error) {
        if (!cancelled) {
          setResources({
            kind: "error",
            message: error instanceof Error ? error.message : String(error),
          });
        }
      }
    })();
    return () => {
      cancelled = true;
    };
  }, [token]);

  return (
    <div className="analysis-view">
      <section>
        <h3>AndroidManifest.xml</h3>
        {manifest.kind === "loading" && <div className="banner">正在读取清单…</div>}
        {manifest.kind === "missing" && (
          <p className="hint">本次目标没有可解码的 AndroidManifest.xml（不是 APK，或清单读不出）。</p>
        )}
        {manifest.kind === "error" && (
          <div className="banner banner-error">{manifest.message}</div>
        )}
        {manifest.kind === "ready" && <ManifestPanel data={manifest.value} />}
      </section>

      <section>
        <h3>resources.arsc</h3>
        {resources.kind === "loading" && <div className="banner">正在读取资源表…</div>}
        {resources.kind === "missing" && (
          <p className="hint">本次目标没有可解码的 resources.arsc。</p>
        )}
        {resources.kind === "error" && (
          <div className="banner banner-error">{resources.message}</div>
        )}
        {resources.kind === "ready" && (
          <ResourcesPanel token={token} data={resources.value} />
        )}
      </section>
    </div>
  );
}

function ManifestPanel({ data }: { data: ManifestResponse }) {
  const facts: ManifestFactsWire = data.facts;
  const row = (label: string, value: string | number | null) => (
    <tr>
      <th>{label}</th>
      <td className="mono">{value === null ? "—" : String(value)}</td>
    </tr>
  );
  return (
    <div>
      <p className="hint">
        {data.headline} · 成员 <span className="mono">{data.member}</span> ·{" "}
        {formatSize(data.size)}
      </p>
      <div className="table-wrap table-wrap-short">
        <table className="data-table">
          <tbody>
            {row("根元素", facts.root)}
            {row("包名", facts.package)}
            {row("versionCode", facts.version_code)}
            {row("versionName", facts.version_name)}
            {row("minSdk", facts.min_sdk)}
            {row("targetSdk", facts.target_sdk)}
            {row("activity", facts.activities)}
            {row("service", facts.services)}
            {row("receiver", facts.receivers)}
            {row("provider", facts.providers)}
            {row("权限", facts.permissions.length)}
            {row("解不出的资源引用", facts.unresolved_references)}
          </tbody>
        </table>
      </div>

      {facts.main_activities.length > 0 && (
        <p className="hint">
          入口 activity：<span className="mono">{facts.main_activities.join("、")}</span>
        </p>
      )}
      {facts.permissions.length > 0 && (
        <p className="hint">
          权限：<span className="mono">{facts.permissions.join("、")}</span>
        </p>
      )}
      {facts.unresolved_references > 0 && (
        <p className="hint">
          有 {facts.unresolved_references} 处资源引用（形如{" "}
          <span className="mono">@7f0d0001</span>）原样保留、未解值 —— 不是解析失败。
        </p>
      )}
      {facts.notes.length > 0 && (
        <div className="banner banner-note">
          <div className="banner-title">说明（{facts.notes.length}）</div>
          <ul>
            {facts.notes.map((note, index) => (
              <li key={index}>{note}</li>
            ))}
          </ul>
        </div>
      )}
    </div>
  );
}

function ResourcesPanel({
  token,
  data,
}: {
  token: string | null;
  data: ResourcesResponse;
}) {
  const structure: ArscStructure = data.structure;
  return (
    <div>
      <p className="hint">
        成员 <span className="mono">{data.member}</span> · {formatSize(data.size)} ·{" "}
        {structure.packages.length} 个包 · 共 {structure.entry_count} 条目（含{" "}
        {structure.no_entry_count} 个空位）
      </p>

      <ResourceLookup token={token} member={data.member} />

      {structure.packages.map((pkg) => (
        <PackagePanel key={pkg.package_id} pkg={pkg} />
      ))}
    </div>
  );
}

function PackagePanel({ pkg }: { pkg: ArscPackageSnapshot }) {
  const [expanded, setExpanded] = useState(false);
  return (
    <div>
      <p className="hint">
        <button
          className="button-small"
          type="button"
          onClick={() => setExpanded((v) => !v)}
        >
          {expanded ? "收起" : "展开"}
        </button>{" "}
        包 <span className="mono">0x{pkg.package_id.toString(16)}</span>{" "}
        <span className="mono">{pkg.name}</span> · 类型字符串 {pkg.type_strings} · 键字符串{" "}
        {pkg.key_strings} · {pkg.config_count} 个配置 · {pkg.entry_count} 条目
      </p>
      {expanded && (
        <div className="table-wrap">
          <table className="data-table">
            <thead>
              <tr>
                <th>配置（判定字段）</th>
                <th>类型数</th>
                <th>条目数</th>
              </tr>
            </thead>
            <tbody>
              {pkg.configs.map((config, index) => {
                const types = config.types.reduce((sum, t) => sum + t.entry_count, 0);
                const label =
                  Object.entries(config.config)
                    .filter(([, v]) => v !== null)
                    .map(([k, v]) => `${k}=${String(v)}`)
                    .join(" ") || "（默认配置）";
                return (
                  <tr key={index}>
                    <td className="mono">{label}</td>
                    <td className="num">{config.types.length}</td>
                    <td className="num">{types}</td>
                  </tr>
                );
              })}
            </tbody>
          </table>
        </div>
      )}
    </div>
  );
}

function ResourceLookup({
  token,
  member,
}: {
  token: string | null;
  member: string;
}) {
  const [id, setId] = useState("");
  const [state, setState] = useState<Load<ResourceLookupResponse>>({ kind: "loading" });

  const lookup = useCallback(async () => {
    if (!id.trim()) return;
    setState({ kind: "loading" });
    try {
      const value = await fetchResource(token, id.trim(), member);
      setState(value ? { kind: "ready", value } : { kind: "missing" });
    } catch (error) {
      setState({
        kind: "error",
        message: error instanceof Error ? error.message : String(error),
      });
    }
  }, [token, id, member]);

  return (
    <div className="view-toolbar">
      <input
        className="input-small mono"
        placeholder="资源 id：0x7f010000"
        value={id}
        onChange={(event) => setId(event.target.value)}
      />
      <button className="button-small" type="button" onClick={() => void lookup()}>
        按 id 查值
      </button>
      {state.kind === "ready" && (
        <span className="hint">
          <span className="mono">{state.value.id}</span> · 名字{" "}
          <span className="mono">{state.value.name ?? "（查不到）"}</span> · 值{" "}
          <span className="mono">{state.value.value ?? "（查不到）"}</span>
        </span>
      )}
      {state.kind === "missing" && (
        <span className="hint">该 id 在资源表里查不到（不是错误，是这个 id 不存在）。</span>
      )}
      {state.kind === "error" && (
        <span className="banner-error">{state.message}</span>
      )}
    </div>
  );
}
