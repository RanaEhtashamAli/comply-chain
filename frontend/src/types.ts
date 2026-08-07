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
