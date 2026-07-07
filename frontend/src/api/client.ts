import type {
  DeviceDetail,
  DeviceSummary,
  RecommendationView,
  ReportView,
  ScanSummary,
  VulnerabilityView,
} from "../lib/types";

async function req<T>(path: string, init?: RequestInit): Promise<T> {
  const res = await fetch(path, {
    headers: { "Content-Type": "application/json" },
    ...init,
  });
  if (!res.ok) {
    let detail = res.statusText;
    try {
      detail = (await res.json()).detail ?? detail;
    } catch {
      /* ignore */
    }
    throw new Error(detail);
  }
  return res.status === 204 ? (undefined as T) : ((await res.json()) as T);
}

export const api = {
  health: () => req<{ status: string }>("/api/health"),

  startScan: (body: {
    target: string;
    profile: string;
    authorized: boolean;
    options?: Record<string, unknown>;
  }) =>
    req<{ scan_id: string; status: string }>("/api/scans/start", {
      method: "POST",
      body: JSON.stringify(body),
    }),

  listScans: () => req<ScanSummary[]>("/api/scans"),
  getScan: (id: string) => req<ScanSummary>(`/api/scans/${id}`),
  cancelScan: (id: string) =>
    req<ScanSummary>(`/api/scans/${id}/cancel`, { method: "POST" }),

  listDevices: (scanId: string) =>
    req<DeviceSummary[]>(`/api/devices?scan_id=${scanId}`),
  getDevice: (id: string) => req<DeviceDetail>(`/api/devices/${id}`),

  listVulnerabilities: (scanId: string, params?: { severity?: string; status?: string }) => {
    const q = new URLSearchParams({ scan_id: scanId });
    if (params?.severity) q.set("severity", params.severity);
    if (params?.status) q.set("status", params.status);
    return req<VulnerabilityView[]>(`/api/vulnerabilities?${q.toString()}`);
  },
  updateVulnerability: (id: string, body: { false_positive?: boolean; status?: string }) =>
    req<VulnerabilityView>(`/api/vulnerabilities/${id}`, {
      method: "PATCH",
      body: JSON.stringify(body),
    }),

  listRecommendations: (scanId: string) =>
    req<RecommendationView[]>(`/api/recommendations?scan_id=${scanId}`),

  createReport: (scanId: string, format: string) =>
    req<ReportView>("/api/reports", {
      method: "POST",
      body: JSON.stringify({ scan_id: scanId, format }),
    }),
};

/** Open a WebSocket to a scan's live progress stream. */
export function openScanStream(
  scanId: string,
  onEvent: (data: unknown) => void,
): WebSocket {
  const proto = location.protocol === "https:" ? "wss" : "ws";
  const ws = new WebSocket(`${proto}://${location.host}/api/scans/${scanId}/stream`);
  ws.onmessage = (e) => {
    try {
      onEvent(JSON.parse(e.data));
    } catch {
      /* ignore malformed frames */
    }
  };
  return ws;
}
