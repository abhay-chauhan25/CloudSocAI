// TypeScript mirrors of the API's response models (backend/app/api/schemas.py).
// If the backend changes a response shape, these must change with it.

export type Severity = "informational" | "low" | "medium" | "high" | "critical";
export type FindingStatus = "open" | "acknowledged" | "resolved" | "false_positive";
export type IncidentStatus = "open" | "investigating" | "resolved" | "false_positive";
export type SortOrder = "newest" | "risk";

export const SEVERITIES: Severity[] = ["critical", "high", "medium", "low", "informational"];
export const FINDING_STATUSES: FindingStatus[] = [
  "open",
  "acknowledged",
  "resolved",
  "false_positive",
];
export const INCIDENT_STATUSES: IncidentStatus[] = [
  "open",
  "investigating",
  "resolved",
  "false_positive",
];

export interface Page<T> {
  items: T[];
  total: number;
  limit: number;
  offset: number;
}

export interface Health {
  status: string;
  database: string;
}

export interface RiskFactor {
  name: string;
  points: number;
  explanation: string;
}

export interface RiskAssessment {
  score: number;
  factors: RiskFactor[];
}

export interface EventSummary {
  event_id: string;
  timestamp: string;
  service: string;
  event_name: string;
  region: string;
  principal_type: string;
  principal: string | null;
  source_address: string | null;
  success: boolean;
  error_code: string | null;
}

export interface FindingSummary {
  finding_id: string;
  detector_id: string;
  title: string;
  severity: Severity;
  risk_score: number;
  status: FindingStatus;
  first_seen: string;
  last_seen: string;
  principal: string | null;
  resource: string | null;
  event_count: number;
}

export interface DetectorInfo {
  detector_id: string;
  name: string;
  description: string;
  rationale: string;
  mitre_techniques: string[];
}

export interface FindingDetail {
  finding_id: string;
  detector_id: string;
  title: string;
  severity: Severity;
  reason: string;
  status: FindingStatus;
  first_seen: string;
  last_seen: string;
  created_at: string;
  account_id: string | null;
  principal: string | null;
  principal_arn: string | null;
  resource: string | null;
  risk: RiskAssessment;
  detector: DetectorInfo | null;
  evidence: EventSummary[];
}

export interface IncidentSummary {
  incident_id: string;
  pattern_id: string;
  title: string;
  severity: Severity;
  risk_score: number;
  status: IncidentStatus;
  first_seen: string;
  last_seen: string;
  principal: string | null;
  finding_count: number;
}

export interface TimelineItem {
  event: EventSummary;
  flagged: boolean;
  detector_ids: string[];
}

export interface IncidentDetail {
  incident_id: string;
  pattern_id: string;
  title: string;
  summary: string;
  severity: Severity;
  status: IncidentStatus;
  first_seen: string;
  last_seen: string;
  created_at: string;
  updated_at: string;
  account_id: string | null;
  principal: string | null;
  principal_arn: string | null;
  risk: RiskAssessment;
  findings: FindingSummary[];
  timeline: TimelineItem[];
}
