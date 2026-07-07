export type Severity = "critical" | "high" | "medium" | "low";

export interface JobView {
  status: string;
  progress: number;
  current_stage: string | null;
  error: string | null;
}

export interface ScanSummary {
  id: string;
  target: string;
  profile: string;
  status: string;
  score: number | null;
  grade: string | null;
  device_count: number;
  vuln_count: number;
  critical_count: number;
  started_at: string | null;
  finished_at: string | null;
  created_at: string;
  job: JobView | null;
}

export interface ServiceView {
  name: string;
  product: string | null;
  version: string | null;
  cpe: string | null;
  banner: string | null;
}

export interface PortView {
  number: number;
  protocol: string;
  state: string;
  service: ServiceView | null;
}

export interface DeviceSummary {
  id: string;
  ip: string;
  hostname: string | null;
  vendor: string | null;
  os_family: string | null;
  risk_score: number | null;
  grade: string | null;
  open_ports: number;
}

export interface ScoreFactor {
  factor: string;
  weight: number;
  evidence: string;
}

export interface DeviceDetail extends DeviceSummary {
  mac: string | null;
  os_accuracy: number | null;
  score_factors: ScoreFactor[];
  ports: PortView[];
}

export interface VulnerabilityView {
  id: string;
  cve_id: string;
  severity: Severity;
  cvss_v3: number | null;
  description: string;
  device_ip: string | null;
  port: number | null;
  product: string | null;
  version: string | null;
  match_confidence: number;
  false_positive: boolean;
  status: string;
  recommendation: string | null;
  references: string[];
}

export interface RecommendationView {
  id: string;
  category: string;
  severity: Severity;
  title: string;
  description: string | null;
  action: string | null;
  priority: number;
  device_ip: string | null;
}

export interface ReportView {
  id: string;
  scan_id: string;
  format: string;
  created_at: string;
  summary: Record<string, unknown>;
  download_url: string;
}

export interface ProgressEvent {
  type: "progress" | "completed" | "failed" | "ping";
  scan_id: string;
  stage?: string;
  percent?: number;
  message?: string;
  host?: string | null;
  score?: number;
  grade?: string;
  error?: string;
}
