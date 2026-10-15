import type { FindingStatus, IncidentStatus, Severity } from "../api/types";
import { formatLabel } from "../format";

export function SeverityBadge({ severity }: { severity: Severity }) {
  return <span className={`badge severity-${severity}`}>{formatLabel(severity)}</span>;
}

export function StatusBadge({ status }: { status: FindingStatus | IncidentStatus }) {
  return <span className={`badge status-${status}`}>{formatLabel(status)}</span>;
}

/** A risk score with a bar, coloured by band: 0-39 low, 40-69 elevated, 70+ high. */
export function RiskScore({ score }: { score: number }) {
  const band = score >= 70 ? "high" : score >= 40 ? "elevated" : "low";
  return (
    <span className={`risk risk-${band}`} title={`Risk ${score} of 100`}>
      <span className="risk-value">{score}</span>
      <span className="risk-bar" aria-hidden="true">
        <span style={{ width: `${Math.max(0, Math.min(100, score))}%` }} />
      </span>
    </span>
  );
}
