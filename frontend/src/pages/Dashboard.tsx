import { useEffect, useState } from "react";
import { Link } from "react-router-dom";
import { api } from "../api/client";
import { Card, ScoreGauge, SeverityBadge, Spinner, StatTile } from "../components/ui";
import { useActiveScan } from "../lib/scanContext";
import type { RecommendationView, ScanSummary, VulnerabilityView } from "../lib/types";

export default function Dashboard() {
  const { activeScanId, setActiveScanId } = useActiveScan();
  const [scans, setScans] = useState<ScanSummary[]>([]);
  const [scan, setScan] = useState<ScanSummary | null>(null);
  const [vulns, setVulns] = useState<VulnerabilityView[]>([]);
  const [recs, setRecs] = useState<RecommendationView[]>([]);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    api.listScans().then((s) => {
      setScans(s);
      if (!activeScanId && s.length) setActiveScanId(s[0].id);
      setLoading(false);
    });
  }, []); // eslint-disable-line react-hooks/exhaustive-deps

  useEffect(() => {
    if (!activeScanId) return;
    api.getScan(activeScanId).then(setScan);
    api.listVulnerabilities(activeScanId).then(setVulns);
    api.listRecommendations(activeScanId).then(setRecs);
  }, [activeScanId]);

  if (loading) return <Spinner label="Loading dashboard…" />;

  if (!scans.length) {
    return (
      <Card title="Welcome to SentinelScan">
        <p className="text-slate-400">
          No scans yet. Head to the{" "}
          <Link to="/scan" className="text-emerald-300 underline">
            Scan page
          </Link>{" "}
          to run your first network assessment.
        </p>
      </Card>
    );
  }

  return (
    <div className="space-y-6">
      <div className="flex items-center justify-between">
        <h1 className="text-2xl font-bold text-slate-100">Dashboard</h1>
        <Link to="/scan" className="rounded-lg bg-emerald-500 px-4 py-2 text-sm font-semibold text-slate-900">
          New Scan
        </Link>
      </div>

      <div className="grid gap-6 lg:grid-cols-3">
        <Card title="Security Score">
          <div className="flex flex-col items-center">
            {scan?.score != null ? (
              <ScoreGauge score={scan.score} grade={scan.grade ?? "?"} />
            ) : (
              <Spinner label={scan?.status ?? "pending"} />
            )}
            <div className="mt-2 font-mono text-sm text-slate-500">{scan?.target}</div>
          </div>
        </Card>

        <div className="grid grid-cols-2 gap-4 lg:col-span-2">
          <StatTile label="Devices" value={scan?.device_count ?? 0} />
          <StatTile
            label="Critical findings"
            value={scan?.critical_count ?? 0}
            accent="text-red-300"
          />
          <StatTile label="Total vulnerabilities" value={scan?.vuln_count ?? 0} />
          <StatTile label="Status" value={scan?.status ?? "—"} accent="text-emerald-300" />
        </div>
      </div>

      <div className="grid gap-6 lg:grid-cols-2">
        <Card title="Critical & High Findings">
          {vulns.filter((v) => v.severity === "critical" || v.severity === "high").length === 0 ? (
            <p className="text-sm text-slate-500">No high-severity findings 🎉</p>
          ) : (
            <ul className="space-y-2">
              {vulns
                .filter((v) => v.severity === "critical" || v.severity === "high")
                .slice(0, 6)
                .map((v) => (
                  <li key={v.id} className="flex items-center justify-between gap-2 text-sm">
                    <div className="min-w-0">
                      <div className="flex items-center gap-2">
                        <SeverityBadge severity={v.severity} />
                        <span className="font-mono text-slate-200">{v.cve_id}</span>
                      </div>
                      <div className="truncate text-slate-500">
                        {v.device_ip}:{v.port} · {v.product} {v.version}
                      </div>
                    </div>
                    <span className="shrink-0 text-slate-400">CVSS {v.cvss_v3}</span>
                  </li>
                ))}
            </ul>
          )}
          <Link to="/vulnerabilities" className="mt-3 inline-block text-sm text-emerald-300 underline">
            View all vulnerabilities →
          </Link>
        </Card>

        <Card title="Top Recommendations">
          {recs.length === 0 ? (
            <p className="text-sm text-slate-500">No recommendations.</p>
          ) : (
            <ol className="space-y-2">
              {recs.slice(0, 6).map((r) => (
                <li key={r.id} className="text-sm">
                  <div className="flex items-center gap-2">
                    <SeverityBadge severity={r.severity} />
                    <span className="text-slate-200">{r.title}</span>
                  </div>
                  {r.action && <div className="text-slate-500">{r.action}</div>}
                </li>
              ))}
            </ol>
          )}
        </Card>
      </div>

      <Card title="Recent Scans">
        <table className="w-full text-sm">
          <thead className="text-left text-slate-500">
            <tr>
              <th className="py-2">Target</th>
              <th>Profile</th>
              <th>Status</th>
              <th>Score</th>
              <th>Devices</th>
              <th></th>
            </tr>
          </thead>
          <tbody>
            {scans.map((s) => (
              <tr key={s.id} className="border-t border-slate-800">
                <td className="py-2 font-mono text-slate-300">{s.target}</td>
                <td className="text-slate-400">{s.profile}</td>
                <td className="text-slate-400">{s.status}</td>
                <td className="text-slate-200">{s.score ?? "—"}</td>
                <td className="text-slate-400">{s.device_count}</td>
                <td className="text-right">
                  <button
                    className="text-emerald-300 underline"
                    onClick={() => setActiveScanId(s.id)}
                  >
                    select
                  </button>
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </Card>
    </div>
  );
}
