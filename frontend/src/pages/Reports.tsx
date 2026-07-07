import { useEffect, useState } from "react";
import { api } from "../api/client";
import { Card } from "../components/ui";
import { useActiveScan } from "../lib/scanContext";
import type { ReportView, ScanSummary } from "../lib/types";

const FORMATS = ["html", "json", "csv"];

export default function Reports() {
  const { activeScanId } = useActiveScan();
  const [scan, setScan] = useState<ScanSummary | null>(null);
  const [format, setFormat] = useState("html");
  const [report, setReport] = useState<ReportView | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);

  useEffect(() => {
    if (activeScanId) api.getScan(activeScanId).then(setScan);
  }, [activeScanId]);

  async function generate() {
    if (!activeScanId) return;
    setBusy(true);
    setError(null);
    setReport(null);
    try {
      const r = await api.createReport(activeScanId, format);
      setReport(r);
    } catch (e) {
      setError((e as Error).message);
    } finally {
      setBusy(false);
    }
  }

  if (!activeScanId) return <Card title="Reports"><p className="text-slate-500">No active scan.</p></Card>;

  return (
    <div className="space-y-6">
      <h1 className="text-2xl font-bold text-slate-100">Reports</h1>

      <Card title="Generate Report">
        <div className="space-y-4">
          <div className="text-sm text-slate-400">
            Scan <span className="font-mono text-slate-300">{scan?.target}</span> · status{" "}
            <span className="text-slate-300">{scan?.status}</span>
          </div>

          <div className="flex items-center gap-3">
            <select
              value={format}
              onChange={(e) => setFormat(e.target.value)}
              className="rounded-lg border border-slate-700 bg-slate-900 px-3 py-2 text-sm"
            >
              {FORMATS.map((f) => (
                <option key={f} value={f}>
                  {f.toUpperCase()}
                </option>
              ))}
            </select>
            <button
              onClick={generate}
              disabled={busy || scan?.status !== "completed"}
              className="rounded-lg bg-emerald-500 px-4 py-2 text-sm font-semibold text-slate-900 disabled:opacity-50"
            >
              {busy ? "Generating…" : "Generate"}
            </button>
          </div>

          {scan?.status !== "completed" && (
            <p className="text-sm text-amber-300">Reports can only be generated for completed scans.</p>
          )}
          {error && <p className="text-sm text-red-300">{error}</p>}

          {report && (
            <div className="rounded-lg border border-emerald-500/30 bg-emerald-500/10 p-3 text-sm">
              <p className="text-emerald-200">Report ready.</p>
              <a
                href={report.download_url}
                target="_blank"
                rel="noreferrer"
                className="mt-1 inline-block text-emerald-300 underline"
              >
                Download {report.format.toUpperCase()} →
              </a>
            </div>
          )}

          <p className="text-xs text-slate-500">
            Reports contain sensitive reconnaissance data. Store and share them with care.
          </p>
        </div>
      </Card>
    </div>
  );
}
