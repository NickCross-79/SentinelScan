import { useEffect, useMemo, useState } from "react";
import { api } from "../api/client";
import { Card, SeverityBadge, Spinner } from "../components/ui";
import { useActiveScan } from "../lib/scanContext";
import type { Severity, VulnerabilityView } from "../lib/types";

const SEVERITIES: Severity[] = ["critical", "high", "medium", "low"];

export default function Vulnerabilities() {
  const { activeScanId } = useActiveScan();
  const [vulns, setVulns] = useState<VulnerabilityView[]>([]);
  const [filter, setFilter] = useState<Severity | "all">("all");
  const [expanded, setExpanded] = useState<string | null>(null);
  const [loading, setLoading] = useState(true);

  function load() {
    if (!activeScanId) {
      setLoading(false);
      return;
    }
    api.listVulnerabilities(activeScanId).then((v) => {
      setVulns(v);
      setLoading(false);
    });
  }
  useEffect(load, [activeScanId]);

  const counts = useMemo(() => {
    const c: Record<string, number> = { critical: 0, high: 0, medium: 0, low: 0 };
    vulns.forEach((v) => (c[v.severity] += 1));
    return c;
  }, [vulns]);

  async function markFalsePositive(id: string) {
    await api.updateVulnerability(id, { false_positive: true });
    load();
  }
  async function resolve(id: string) {
    await api.updateVulnerability(id, { status: "resolved" });
    load();
  }

  if (!activeScanId) return <Card title="Vulnerabilities"><p className="text-slate-500">No active scan.</p></Card>;
  if (loading) return <Spinner label="Loading vulnerabilities…" />;

  const shown = filter === "all" ? vulns : vulns.filter((v) => v.severity === filter);

  return (
    <div className="space-y-6">
      <h1 className="text-2xl font-bold text-slate-100">Vulnerabilities</h1>

      <div className="flex flex-wrap gap-2">
        <button
          onClick={() => setFilter("all")}
          className={`rounded-lg px-3 py-1 text-sm ${filter === "all" ? "bg-emerald-500 text-slate-900" : "bg-slate-800 text-slate-300"}`}
        >
          All ({vulns.length})
        </button>
        {SEVERITIES.map((s) => (
          <button
            key={s}
            onClick={() => setFilter(s)}
            className={`rounded-lg px-3 py-1 text-sm capitalize ${filter === s ? "bg-emerald-500 text-slate-900" : "bg-slate-800 text-slate-300"}`}
          >
            {s} ({counts[s]})
          </button>
        ))}
      </div>

      <Card>
        {shown.length === 0 ? (
          <p className="text-sm text-slate-500">No vulnerabilities match this filter.</p>
        ) : (
          <div className="divide-y divide-slate-800">
            {shown.map((v) => (
              <div key={v.id} className="py-3">
                <div
                  className="flex cursor-pointer items-center justify-between gap-3"
                  onClick={() => setExpanded(expanded === v.id ? null : v.id)}
                >
                  <div className="flex items-center gap-3">
                    <SeverityBadge severity={v.severity} />
                    <span className="font-mono text-slate-200">{v.cve_id}</span>
                    <span className="text-sm text-slate-500">
                      {v.device_ip}:{v.port} · {v.product} {v.version}
                    </span>
                  </div>
                  <span className="text-sm text-slate-400">CVSS {v.cvss_v3}</span>
                </div>

                {expanded === v.id && (
                  <div className="mt-3 space-y-2 rounded-lg bg-slate-950 p-3 text-sm">
                    <p className="text-slate-300">{v.description}</p>
                    {v.recommendation && (
                      <p className="text-emerald-300">
                        <span className="font-semibold">Fix:</span> {v.recommendation}
                      </p>
                    )}
                    <p className="text-slate-500">
                      Match confidence {(v.match_confidence * 100).toFixed(0)}% · status {v.status}
                    </p>
                    {v.references.length > 0 && (
                      <ul className="text-xs text-slate-500">
                        {v.references.map((r) => (
                          <li key={r}>
                            <a href={r} target="_blank" rel="noreferrer" className="underline">
                              {r}
                            </a>
                          </li>
                        ))}
                      </ul>
                    )}
                    <div className="flex gap-2 pt-1">
                      <button
                        onClick={() => resolve(v.id)}
                        className="rounded bg-slate-800 px-2 py-1 text-xs text-slate-300 hover:bg-slate-700"
                      >
                        Mark resolved
                      </button>
                      <button
                        onClick={() => markFalsePositive(v.id)}
                        className="rounded bg-slate-800 px-2 py-1 text-xs text-slate-300 hover:bg-slate-700"
                      >
                        False positive
                      </button>
                    </div>
                  </div>
                )}
              </div>
            ))}
          </div>
        )}
      </Card>
    </div>
  );
}
