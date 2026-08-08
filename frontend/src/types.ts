export interface AssessRequest {
  name: string;
  jurisdiction: string;
  entity_type: string;
  processes_card_payments: boolean;
  eu_nexus: boolean;
  employee_count: number;
  hipaa_covered_entity: boolean;
}

export interface RegulationControl {
  title: string;
  status: string;
  findings: string[];
}

export interface RegulationReport {
  regulation_id: string;
  regulation_name: string;
  institution_name: string;
  assessed_at: string;
  overall_status: string;
  risk_score: number;
  applicable: boolean;
  recommendations: string[];
  controls: Record<string, RegulationControl>;
}

export type AssessResponse = Record<string, RegulationReport>;

export interface AuditStatus {
  [key: string]: unknown;
}

export interface AuditChain {
  entries: Array<Record<string, unknown>>;
  error?: string;
}

export interface KeyCheckResult {
  ok: boolean;
  findings: string[];
  key_algorithm: string | null;
  key_age_days: number | null;
  round_trip_passed: boolean | null;
}

export interface KeyReplaceResult {
  ok: boolean;
  algorithm: string;
  public_key: string;
}

export interface RotationManifest {
  rotated_at: string;
  new_algorithm: string;
  old_algorithm: string;
  chain_of_custody_signed: boolean;
  action: string;
  [key: string]: unknown;
}

export type SarFormat = "pdf" | "xml" | "json";
export type SarFilingType = "INITIAL" | "CORRECT" | "JOINT";

export interface MonitorJob {
  job_id: string;
  regulation_id: string;
  cron: string;
  profile: AssessRequest;
  last_run: string | null;
  last_status: string | null;
}

export interface CreateMonitorRequest {
  regulation: string;
  schedule: string;
  name: string;
  jurisdiction: string;
  entity_type: string;
  processes_card_payments: boolean;
  eu_nexus: boolean;
  employee_count: number;
  hipaa_covered_entity: boolean;
}

export interface SanctionsStatus {
  sanctions_cache_status: string;
  ofac_configured: boolean;
  unsc_configured: boolean;
  uk_configured: boolean;
  fincen_api_key_configured: boolean;
}

export interface ComplianceRow {
  section: string;
  description: string;
  module: string;
  configured: boolean;
}

export interface ValidateRulesResult {
  valid: boolean;
  rule_count: number;
  errors: string[];
}

export interface BenchmarkResult {
  /** What the caller asked for. */
  requested_algorithm?: string;
  /** What actually ran — QuantumSafeSigner falls back to RSA-4096 without liboqs. */
  effective_algorithm?: string;
  /** True when a post-quantum algorithm was requested but RSA-4096 ran instead. */
  fallback_active?: boolean;
  key_generation: { avg_ms: number; samples: number };
  signing: { avg_ms: number; samples: number };
}

export interface TrainModelResult {
  metrics: Record<string, number>;
  model_path: string;
}
