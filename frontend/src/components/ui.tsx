import type { ReactNode } from "react";
import type { Severity } from "../lib/types";

const SEVERITY_STYLES: Record<Severity, string> = {
  critical: "bg-red-500/15 text-red-300 border-red-500/40",
  high: "bg-orange-500/15 text-orange-300 border-orange-500/40",
  medium: "bg-yellow-500/15 text-yellow-300 border-yellow-500/40",
  low: "bg-emerald-500/15 text-emerald-300 border-emerald-500/40",
};

export function SeverityBadge({ severity }: { severity: Severity }) {
  return (
    <span
      className={`inline-block rounded-md border px-2 py-0.5 text-xs font-semibold uppercase tracking-wide ${SEVERITY_STYLES[severity]}`}
    >
      {severity}
    </span>
  );
}

export function StatTile({
  label,
  value,
  accent,
}: {
  label: string;
  value: ReactNode;
  accent?: string;
}) {
  return (
    <div className="rounded-xl border border-slate-800 bg-panel p-4">
      <div className="text-sm text-slate-400">{label}</div>
      <div className={`mt-1 text-2xl font-bold ${accent ?? "text-slate-100"}`}>{value}</div>
    </div>
  );
}

export function Card({
  title,
  children,
  actions,
}: {
  title?: string;
  children: ReactNode;
  actions?: ReactNode;
}) {
  return (
    <div className="rounded-xl border border-slate-800 bg-panel">
      {(title || actions) && (
        <div className="flex items-center justify-between border-b border-slate-800 px-4 py-3">
          {title && <h3 className="font-semibold text-slate-200">{title}</h3>}
          {actions}
        </div>
      )}
      <div className="p-4">{children}</div>
    </div>
  );
}

function gradeColor(score: number): string {
  if (score >= 90) return "#34d399";
  if (score >= 80) return "#a3e635";
  if (score >= 70) return "#facc15";
  if (score >= 60) return "#fb923c";
  return "#f87171";
}

export function ScoreGauge({
  score,
  grade,
  size = 180,
}: {
  score: number;
  grade: string;
  size?: number;
}) {
  const stroke = 14;
  const r = (size - stroke) / 2;
  const c = 2 * Math.PI * r;
  const pct = Math.max(0, Math.min(100, score)) / 100;
  const color = gradeColor(score);
  return (
    <svg width={size} height={size} viewBox={`0 0 ${size} ${size}`} role="img" aria-label={`Security score ${score} of 100`}>
      <circle cx={size / 2} cy={size / 2} r={r} fill="none" stroke="#1e293b" strokeWidth={stroke} />
      <circle
        cx={size / 2}
        cy={size / 2}
        r={r}
        fill="none"
        stroke={color}
        strokeWidth={stroke}
        strokeLinecap="round"
        strokeDasharray={c}
        strokeDashoffset={c * (1 - pct)}
        transform={`rotate(-90 ${size / 2} ${size / 2})`}
        style={{ transition: "stroke-dashoffset 0.6s ease" }}
      />
      <text x="50%" y="46%" textAnchor="middle" fontSize={size * 0.26} fontWeight={700} fill="#f1f5f9">
        {score}
      </text>
      <text x="50%" y="64%" textAnchor="middle" fontSize={size * 0.12} fill={color} fontWeight={700}>
        Grade {grade}
      </text>
    </svg>
  );
}

export function Spinner({ label }: { label?: string }) {
  return (
    <div className="flex items-center gap-2 text-slate-400">
      <span className="h-4 w-4 animate-spin rounded-full border-2 border-slate-600 border-t-slate-200" />
      {label && <span className="text-sm">{label}</span>}
    </div>
  );
}
