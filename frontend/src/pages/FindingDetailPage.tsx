import { Link, useParams } from "react-router";

import { api } from "../api/client";
import type { FindingDetail } from "../api/types";
import { RiskScore, SeverityBadge, StatusBadge } from "../components/Badges";
import { TacticList, TechniqueLink } from "../components/Mitre";
import { RiskBreakdown } from "../components/RiskBreakdown";
import { ErrorMessage, Loading } from "../components/States";
import { formatTime } from "../format";
import { useApi } from "../hooks/useApi";

export function FindingDetailPage() {
  const { findingId = "" } = useParams();
  const state = useApi((signal) => api.getFinding(findingId, signal), [findingId]);

  if (state.status === "loading") return <Loading what="finding" />;
  if (state.status === "error") {
    if (state.error.status === 404) return <ErrorMessage message="Finding not found." />;
    return <ErrorMessage message={state.error.message} onRetry={state.reload} />;
  }
  const finding = state.data;

  return (
    <>
      <p>
        <Link to="/findings">← Findings</Link>
      </p>
      <header className="detail-header">
        <h1>{finding.title}</h1>
        <div className="detail-meta">
          <SeverityBadge severity={finding.severity} />
          <StatusBadge status={finding.status} />
          <RiskScore score={finding.risk.score} />
        </div>
      </header>
      <p className="reason">{finding.reason}</p>

      <div className="columns">
        <section>
          <RiskBreakdown risk={finding.risk} />
        </section>
        <section>
          {finding.kind === "posture" ? (
            <dl className="facts">
              <dt>Resource</dt>
              <dd className="mono">{finding.resource ?? "—"}</dd>
              <dt>Account</dt>
              <dd className="mono">{finding.account_id ?? "—"}</dd>
              <dt>Observed</dt>
              <dd>{formatTime(finding.first_seen)}</dd>
            </dl>
          ) : (
            <dl className="facts">
              <dt>Actor</dt>
              <dd>{finding.principal ?? "—"}</dd>
              <dt>ARN</dt>
              <dd className="mono">{finding.principal_arn ?? "—"}</dd>
              <dt>Resource</dt>
              <dd>{finding.resource ?? "—"}</dd>
              <dt>First seen</dt>
              <dd>{formatTime(finding.first_seen)}</dd>
              <dt>Last seen</dt>
              <dd>{formatTime(finding.last_seen)}</dd>
            </dl>
          )}
        </section>
      </div>

      {finding.kind === "posture" ? (
        <PostureCheckSection finding={finding} />
      ) : (
        <RuleSection finding={finding} />
      )}
    </>
  );
}

function PostureCheckSection({ finding }: { finding: FindingDetail }) {
  const check = finding.posture_check;
  return (
    <>
      <h2>Posture check</h2>
      {check ? (
        <dl className="facts">
          <dt>Check</dt>
          <dd>
            {check.name} <span className="mono muted">({check.check_id})</span>
          </dd>
          <dt>Fails when</dt>
          <dd>{check.description}</dd>
          <dt>Why it matters</dt>
          <dd>{check.rationale}</dd>
          <dt>How to fix</dt>
          <dd>{check.remediation}</dd>
          <dt>Reference</dt>
          <dd>{check.reference}</dd>
        </dl>
      ) : (
        <p className="muted">
          The check <span className="mono">{finding.detector_id}</span> no longer exists.
        </p>
      )}
      <h2>Evidence</h2>
      <p className="muted">
        This finding describes configuration, not activity: no events are involved. The values
        observed in the configuration snapshot are quoted in the explanation above.
      </p>
    </>
  );
}

function RuleSection({ finding }: { finding: FindingDetail }) {
  return (
    <>
      <h2>Detection rule</h2>
      {finding.detector ? (
        <dl className="facts">
          <dt>Rule</dt>
          <dd>
            {finding.detector.name} <span className="mono muted">({finding.detector.detector_id})</span>
          </dd>
          <dt>Fires when</dt>
          <dd>{finding.detector.description}</dd>
          <dt>Why it matters</dt>
          <dd>{finding.detector.rationale}</dd>
          <dt>MITRE ATT&amp;CK</dt>
          <dd>
            {finding.detector.mitre.length === 0 ? (
              <span className="muted">
                Not mapped: this rule's evidence does not justify one specific technique.
              </span>
            ) : (
              finding.detector.mitre.map((mapping) => (
                <div key={mapping.technique_id} className="mapping">
                  <TechniqueLink technique={mapping} /> <TacticList technique={mapping} />
                  <div className="muted">{mapping.rationale}</div>
                </div>
              ))
            )}
          </dd>
        </dl>
      ) : (
        <p className="muted">
          The rule <span className="mono">{finding.detector_id}</span> no longer exists.
        </p>
      )}

      <h2>Evidence ({finding.evidence.length})</h2>
      <table>
        <thead>
          <tr>
            <th>Time</th>
            <th>Event</th>
            <th>Actor</th>
            <th>Source</th>
            <th>Outcome</th>
          </tr>
        </thead>
        <tbody>
          {finding.evidence.map((event) => (
            <tr key={event.event_id}>
              <td>{formatTime(event.timestamp)}</td>
              <td>
                {event.event_name} <span className="muted">({event.service})</span>
                <div className="mono muted">{event.event_id}</div>
              </td>
              <td>{event.principal ?? "—"}</td>
              <td>{event.source_address ?? "—"}</td>
              <td>{event.success ? "Succeeded" : `Failed: ${event.error_code ?? "error"}`}</td>
            </tr>
          ))}
        </tbody>
      </table>
    </>
  );
}
