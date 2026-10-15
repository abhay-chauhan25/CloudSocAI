import { Link, useParams } from "react-router";

import { api } from "../api/client";
import { RiskScore, SeverityBadge, StatusBadge } from "../components/Badges";
import { RiskBreakdown } from "../components/RiskBreakdown";
import { ErrorMessage, Loading } from "../components/States";
import { Timeline } from "../components/Timeline";
import { formatTime } from "../format";
import { useApi } from "../hooks/useApi";

export function IncidentDetailPage() {
  const { incidentId = "" } = useParams();
  const state = useApi((signal) => api.getIncident(incidentId, signal), [incidentId]);

  if (state.status === "loading") return <Loading what="incident" />;
  if (state.status === "error") {
    if (state.error.status === 404) {
      return <ErrorMessage message="Incident not found." />;
    }
    return <ErrorMessage message={state.error.message} onRetry={state.reload} />;
  }
  const incident = state.data;

  return (
    <>
      <p>
        <Link to="/incidents">← Incidents</Link>
      </p>
      <header className="detail-header">
        <h1>{incident.title}</h1>
        <div className="detail-meta">
          <SeverityBadge severity={incident.severity} />
          <StatusBadge status={incident.status} />
          <RiskScore score={incident.risk.score} />
        </div>
      </header>
      <p>{incident.summary}</p>

      <div className="columns">
        <section>
          <RiskBreakdown risk={incident.risk} />
        </section>
        <section>
          <dl className="facts">
            <dt>Actor</dt>
            <dd>{incident.principal ?? "—"}</dd>
            <dt>ARN</dt>
            <dd className="mono">{incident.principal_arn ?? "—"}</dd>
            <dt>Account</dt>
            <dd className="mono">{incident.account_id ?? "—"}</dd>
            <dt>First seen</dt>
            <dd>{formatTime(incident.first_seen)}</dd>
            <dt>Last seen</dt>
            <dd>{formatTime(incident.last_seen)}</dd>
            <dt>Updated</dt>
            <dd>{formatTime(incident.updated_at)}</dd>
          </dl>
        </section>
      </div>

      <h2>Findings ({incident.findings.length})</h2>
      <table>
        <thead>
          <tr>
            <th>Risk</th>
            <th>Finding</th>
            <th>Severity</th>
            <th>First seen</th>
          </tr>
        </thead>
        <tbody>
          {incident.findings.map((finding) => (
            <tr key={finding.finding_id}>
              <td>
                <RiskScore score={finding.risk_score} />
              </td>
              <td>
                <Link to={`/findings/${encodeURIComponent(finding.finding_id)}`}>
                  {finding.title}
                </Link>
                {finding.resource && <div className="muted">{finding.resource}</div>}
              </td>
              <td>
                <SeverityBadge severity={finding.severity} />
              </td>
              <td>{formatTime(finding.first_seen)}</td>
            </tr>
          ))}
        </tbody>
      </table>

      <h2>Timeline</h2>
      <p className="muted">
        Everything this actor did around the incident. Highlighted events were flagged by a rule;
        the others are context.
      </p>
      <Timeline items={incident.timeline} />
    </>
  );
}
