import { useEffect, useState } from "react";
import { api } from "../api/client";
import { Card, Spinner } from "../components/ui";
import { useActiveScan } from "../lib/scanContext";
import type { DeviceDetail, DeviceSummary } from "../lib/types";

function riskColor(score: number | null): string {
  if (score == null) return "text-slate-400";
  if (score >= 80) return "text-emerald-300";
  if (score >= 60) return "text-yellow-300";
  return "text-red-300";
}

export default function Devices() {
  const { activeScanId } = useActiveScan();
  const [devices, setDevices] = useState<DeviceSummary[]>([]);
  const [selected, setSelected] = useState<DeviceDetail | null>(null);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    if (!activeScanId) {
      setLoading(false);
      return;
    }
    api.listDevices(activeScanId).then((d) => {
      setDevices(d);
      setLoading(false);
    });
  }, [activeScanId]);

  function open(id: string) {
    api.getDevice(id).then(setSelected);
  }

  if (!activeScanId) return <Card title="Devices"><p className="text-slate-500">No active scan.</p></Card>;
  if (loading) return <Spinner label="Loading devices…" />;

  return (
    <div className="space-y-6">
      <h1 className="text-2xl font-bold text-slate-100">Devices</h1>
      <div className="grid gap-6 lg:grid-cols-2">
        <Card title={`Hosts (${devices.length})`}>
          {devices.length === 0 ? (
            <p className="text-sm text-slate-500">No live hosts found.</p>
          ) : (
            <table className="w-full text-sm">
              <thead className="text-left text-slate-500">
                <tr>
                  <th className="py-2">IP</th>
                  <th>Hostname</th>
                  <th>OS</th>
                  <th>Ports</th>
                  <th>Risk</th>
                </tr>
              </thead>
              <tbody>
                {devices.map((d) => (
                  <tr
                    key={d.id}
                    className="cursor-pointer border-t border-slate-800 hover:bg-slate-800/50"
                    onClick={() => open(d.id)}
                  >
                    <td className="py-2 font-mono text-slate-300">{d.ip}</td>
                    <td className="text-slate-400">{d.hostname ?? "—"}</td>
                    <td className="text-slate-400">{d.os_family ?? "—"}</td>
                    <td className="text-slate-400">{d.open_ports}</td>
                    <td className={`font-semibold ${riskColor(d.risk_score)}`}>
                      {d.risk_score ?? "—"} {d.grade ? `(${d.grade})` : ""}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          )}
        </Card>

        <Card title={selected ? `Device ${selected.ip}` : "Device Detail"}>
          {!selected ? (
            <p className="text-sm text-slate-500">Select a host to see open ports and services.</p>
          ) : (
            <div className="space-y-4">
              <div className="grid grid-cols-2 gap-2 text-sm">
                <div><span className="text-slate-500">Hostname:</span> {selected.hostname ?? "—"}</div>
                <div><span className="text-slate-500">OS:</span> {selected.os_family ?? "—"}</div>
                <div><span className="text-slate-500">Risk:</span> {selected.risk_score} ({selected.grade})</div>
                <div><span className="text-slate-500">MAC:</span> {selected.mac ?? "—"}</div>
              </div>

              <div>
                <h4 className="mb-1 text-sm font-semibold text-slate-300">Open Ports</h4>
                <table className="w-full text-sm">
                  <thead className="text-left text-slate-500">
                    <tr><th className="py-1">Port</th><th>Service</th><th>Product</th><th>Version</th></tr>
                  </thead>
                  <tbody>
                    {selected.ports.map((p) => (
                      <tr key={p.number} className="border-t border-slate-800">
                        <td className="py-1 font-mono text-slate-300">{p.number}/{p.protocol}</td>
                        <td className="text-slate-400">{p.service?.name ?? "—"}</td>
                        <td className="text-slate-400">{p.service?.product ?? "—"}</td>
                        <td className="font-mono text-slate-400">{p.service?.version ?? "—"}</td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>

              {selected.score_factors.length > 0 && (
                <div>
                  <h4 className="mb-1 text-sm font-semibold text-slate-300">Why this score</h4>
                  <ul className="space-y-1 text-sm text-slate-400">
                    {selected.score_factors.map((f, i) => (
                      <li key={i}>
                        <span className="text-red-300">−{f.weight}</span> {f.factor}: {f.evidence}
                      </li>
                    ))}
                  </ul>
                </div>
              )}
            </div>
          )}
        </Card>
      </div>
    </div>
  );
}
