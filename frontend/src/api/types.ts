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

/** "rule": a detection rule judged activity. "posture": a posture check judged configuration. */
export type FindingKind = "rule" | "posture";

export interface FindingSummary {
  finding_id: string;
  detector_id: string;
  kind: FindingKind;
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

export interface TacticInfo {
  tactic_id: string;
  name: string;
  url: string;
}

export interface TechniqueInfo {
  technique_id: string;
  name: string;
  tactics: TacticInfo[];
  url: string;
}

/** A curated mapping: a technique plus why the rule maps to it. */
export interface MitreMapping extends TechniqueInfo {
  rationale: string;
}

export interface DetectorInfo {
  detector_id: string;
  name: string;
  description: string;
  rationale: string;
  severity: Severity;
  mitre: MitreMapping[];
}

/** A posture check: tests configuration state, so it has no ATT&CK mapping. */
export interface PostureCheckInfo {
  check_id: string;
  name: string;
  service: string;
  description: string;
  rationale: string;
  remediation: string;
  reference: string;
  severity: Severity;
}

export interface DetectorCatalog {
  attack_version: string;
  tactics: TacticInfo[];
  detectors: DetectorInfo[];
  posture_checks: PostureCheckInfo[];
}

export interface IncidentTechnique extends TechniqueInfo {
  detector_ids: string[];
}

export interface FindingDetail {
  finding_id: string;
  detector_id: string;
  kind: FindingKind;
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
  posture_check: PostureCheckInfo | null;
  /** Empty for posture findings: their evidence is the configuration in `reason`. */
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
  mitre: IncidentTechnique[];
  timeline: TimelineItem[];
}

export interface NarrativeStep {
  description: string;
  event_ids: string[];
}

export interface AnalysisResult {
  summary: string;
  attack_narrative: NarrativeStep[];
  likely_objective: string;
  objective_confidence: "low" | "medium" | "high";
  investigation_steps: string[];
  containment_suggestions: string[];
  benign_explanations: string[];
  techniques_referenced: string[];
}

export interface Analysis {
  incident_id: string;
  provider: string;
  model: string;
  created_at: string;
  is_current: boolean;
  cached: boolean;
  input_tokens: number | null;
  output_tokens: number | null;
  result: AnalysisResult;
}
