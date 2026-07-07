import { NavLink, Outlet } from "react-router-dom";
import { useActiveScan } from "../lib/scanContext";

const NAV = [
  { to: "/", label: "Dashboard", end: true },
  { to: "/scan", label: "Scan" },
  { to: "/devices", label: "Devices" },
  { to: "/vulnerabilities", label: "Vulnerabilities" },
  { to: "/reports", label: "Reports" },
];

export default function Layout() {
  const { activeScanId } = useActiveScan();
  return (
    <div className="min-h-screen">
      <div className="flex">
        <aside className="hidden w-56 shrink-0 border-r border-slate-800 bg-panel/60 p-4 md:block">
          <div className="mb-6 flex items-center gap-2">
            <span className="grid h-9 w-9 place-items-center rounded-lg bg-emerald-500/20 text-emerald-300">🛡️</span>
            <div>
              <div className="font-bold text-slate-100">SentinelScan</div>
              <div className="text-xs text-slate-500">local-first scanner</div>
            </div>
          </div>
          <nav className="space-y-1">
            {NAV.map((n) => (
              <NavLink
                key={n.to}
                to={n.to}
                end={n.end}
                className={({ isActive }) =>
                  `block rounded-lg px-3 py-2 text-sm ${
                    isActive
                      ? "bg-emerald-500/15 text-emerald-200"
                      : "text-slate-400 hover:bg-slate-800 hover:text-slate-200"
                  }`
                }
              >
                {n.label}
              </NavLink>
            ))}
          </nav>
          <div className="mt-8 rounded-lg border border-slate-800 p-3 text-xs text-slate-500">
            {activeScanId ? (
              <>
                <div className="text-slate-400">Active scan</div>
                <div className="mt-1 font-mono text-slate-300">{activeScanId.slice(0, 8)}</div>
              </>
            ) : (
              "No active scan — start one on the Scan page."
            )}
          </div>
        </aside>

        <main className="min-h-screen flex-1">
          <header className="border-b border-slate-800 bg-panel/40 px-6 py-3 md:hidden">
            <span className="font-bold text-slate-100">🛡️ SentinelScan</span>
          </header>
          <div className="mx-auto max-w-6xl p-6">
            <Outlet />
          </div>
        </main>
      </div>
    </div>
  );
}
