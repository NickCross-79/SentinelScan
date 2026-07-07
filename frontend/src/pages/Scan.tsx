import { useEffect, useRef, useState } from "react";
import { useNavigate } from "react-router-dom";
import { api, openScanStream } from "../api/client";
import { Card } from "../components/ui";
import { useActiveScan } from "../lib/scanContext";
import type { ProgressEvent } from "../lib/types";

const STAGES = ["discovery", "ports", "services", "done"];

export default function Scan() {
  const { setActiveScanId } = useActiveScan();
  const navigate = useNavigate();

  const [target, setTarget] = useState("127.0.0.1");
  const [profile, setProfile] = useState("quick");
  const [customPorts, setCustomPorts] = useState("22,80,443,8080");
  const [authorized, setAuthorized] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const [running, setRunning] = useState(false);
  const [progress, setProgress] = useState(0);
  const [stage, setStage] = useState<string>("");
  const [log, setLog] = useState<string[]>([]);
  const [finished, setFinished] = useState<null | { score?: number; grade?: string }>(null);
  const wsRef = useRef<WebSocket | null>(null);

  useEffect(() => () => wsRef.current?.close(), []);

  async function start() {
    setError(null);
    if (!authorized) {
      setError("You must confirm authorization to scan this target.");
      return;
    }
    const options: Record<string, unknown> = {};
    if (profile === "custom") {
      options.ports = customPorts
        .split(",")
        .map((p) => parseInt(p.trim(), 10))
        .filter((n) => !Number.isNaN(n));
    }
    try {
      const { scan_id } = await api.startScan({ target, profile, authorized, options });
      setActiveScanId(scan_id);
      setRunning(true);
      setFinished(null);
      setProgress(0);
      setLog([]);
      const ws = openScanStream(scan_id, (raw) => {
        const ev = raw as ProgressEvent;
        if (ev.type === "progress") {
          setProgress(ev.percent ?? 0);
          setStage(ev.stage ?? "");
          if (ev.message) setLog((l) => [...l.slice(-40), ev.message!]);
        } else if (ev.type === "completed") {
          setProgress(100);
          setRunning(false);
          setFinished({ score: ev.score, grade: ev.grade });
          ws.close();
        } else if (ev.type === "failed") {
          setRunning(false);
          setError(ev.error ?? "scan failed");
          ws.close();
        }
      });
      wsRef.current = ws;
    } catch (e) {
      setError((e as Error).message);
    }
  }

  return (
    <div className="space-y-6">
      <h1 className="text-2xl font-bold text-slate-100">New Scan</h1>

      <div className="grid gap-6 lg:grid-cols-2">
        <Card title="Configuration">
          <div className="space-y-4">
            <label className="block">
              <span className="text-sm text-slate-400">Target (IP, hostname, or CIDR)</span>
              <input
                value={target}
                onChange={(e) => setTarget(e.target.value)}
                className="mt-1 w-full rounded-lg border border-slate-700 bg-slate-900 px-3 py-2 font-mono text-sm"
                placeholder="192.168.1.0/24"
              />
            </label>

            <label className="block">
              <span className="text-sm text-slate-400">Profile</span>
              <select
                value={profile}
                onChange={(e) => setProfile(e.target.value)}
                className="mt-1 w-full rounded-lg border border-slate-700 bg-slate-900 px-3 py-2 text-sm"
              >
                <option value="quick">Quick (top ~100 ports)</option>
                <option value="full">Full (top ~1000 ports)</option>
                <option value="custom">Custom ports</option>
              </select>
            </label>

            {profile === "custom" && (
              <label className="block">
                <span className="text-sm text-slate-400">Ports (comma-separated)</span>
                <input
                  value={customPorts}
                  onChange={(e) => setCustomPorts(e.target.value)}
                  className="mt-1 w-full rounded-lg border border-slate-700 bg-slate-900 px-3 py-2 font-mono text-sm"
                />
              </label>
            )}

            <label className="flex items-start gap-2 rounded-lg border border-amber-500/30 bg-amber-500/10 p-3">
              <input
                type="checkbox"
                checked={authorized}
                onChange={(e) => setAuthorized(e.target.checked)}
                className="mt-1"
              />
              <span className="text-sm text-amber-200">
                I confirm I own this network or am explicitly authorized to scan it. Scanning
                systems without permission may be illegal.
              </span>
            </label>

            {error && <div className="rounded-lg bg-red-500/15 px-3 py-2 text-sm text-red-300">{error}</div>}

            <button
              onClick={start}
              disabled={running}
              className="w-full rounded-lg bg-emerald-500 px-4 py-2 font-semibold text-slate-900 hover:bg-emerald-400 disabled:opacity-50"
            >
              {running ? "Scanning…" : "Start Scan"}
            </button>
          </div>
        </Card>

        <Card title="Live Progress">
          {!running && !finished && (
            <p className="text-sm text-slate-500">Progress appears here once a scan starts.</p>
          )}

          {(running || finished) && (
            <div className="space-y-4">
              <div className="flex items-center justify-between text-xs text-slate-400">
                {STAGES.map((s) => (
                  <div
                    key={s}
                    className={`flex-1 text-center ${
                      stage === s || (finished && s === "done") ? "text-emerald-300" : ""
                    }`}
                  >
                    {s}
                  </div>
                ))}
              </div>
              <div className="h-2 w-full overflow-hidden rounded-full bg-slate-800">
                <div
                  className="h-full rounded-full bg-emerald-500 transition-all"
                  style={{ width: `${progress}%` }}
                />
              </div>

              {finished && (
                <div className="rounded-lg border border-emerald-500/30 bg-emerald-500/10 p-3 text-sm text-emerald-200">
                  Scan complete — score {finished.score} (grade {finished.grade}).{" "}
                  <button className="underline" onClick={() => navigate("/")}>
                    View dashboard →
                  </button>
                </div>
              )}

              <div className="h-48 overflow-auto rounded-lg bg-slate-950 p-3 font-mono text-xs text-slate-400">
                {log.map((line, i) => (
                  <div key={i}>{line}</div>
                ))}
              </div>
            </div>
          )}
        </Card>
      </div>
    </div>
  );
}
