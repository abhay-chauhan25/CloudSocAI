import { Link } from "react-router";

import { api } from "../api/client";
import { SEVERITIES } from "../api/types";
import { RiskScore, SeverityBadge, StatusBadge } from "../components/Badges";
import { Empty, ErrorMessage, Loading } from "../components/States";
import { formatTime } from "../format";
import { useApi } from "../hooks/useApi";

async function loadDashboard(signal: AbortSignal) {
  // Counts come from each list's `total`, asking for a single item. That is
  // several small requests instead of a dedicated summary endpoint, which is
  // fine at this scale.
  const [health, openIncidents, topIncidents, events, ...bySeverity] = await Promise.all([
    api.health(signal),
    api.listIncidents({ status: "open", limit: 1 }, signal),
    api.listIncidents({ sort: "risk", limit: 5 }, signal),
    api.listEvents({ limit: 1 }, signal),
    ...SEVERITIES.map((severity) => api.listFindings({ severity, limit: 1 }, signal)),
  ]);
  return {
    health,
    openIncidentCount: openIncidents.total,
    topIncidents: topIncidents.items,
    eventCount: events.total,
    findingCounts: SEVERITIES.map((severity, i) => ({ severity, total: bySeverity[i]?.total ?? 0 })),
  };
}

export function DashboardPage() {
  const state = useApi(loadDashboard, []);

  if (state.status === "loading") return <Loading what="dashboard" />;
  if (state.status === "error") return <ErrorMessage message={state.error.message} onRetry={state.reload} />;
  const { health, openIncidentCount, topIncidents, eventCount, findingCounts } = state.data;

  return (
    <>
      <h1>Overview</h1>
      <p className="muted">
        API {health.status} · database {health.database}
      </p>

      <section className="cards">
        <Link to="/incidents?status=open" className="card">
          <span className="card-value">{openIncidentCount}</span>
          <span>Open incidents</span>
        </Link>
        {findingCounts.map(({ severity, total }) => (
          <Link key={severity} to={`/findings?severity=${severity}`} className="card">
            <span className="card-value">{total}</span>
            <span>
              <SeverityBadge severity={severity} /> findings
            </span>
          </Link>
        ))}
        <div className="card">
          <span className="card-value">{eventCount}</span>
          <span>Events analysed</span>
        </div>
      </section>

      <h2>Highest-risk incidents</h2>
      {topIncidents.length === 0 ? (
        <Empty>No incidents yet. Ingest logs and run detection to create some.</Empty>
      ) : (
        <table>
          <thead>
            <tr>
              <th>Risk</th>
              <th>Incident</th>
              <th>Severity</th>
              <th>Status</th>
              <th>Last activity</th>
            </tr>
          </thead>
          <tbody>
            {topIncidents.map((incident) => (
              <tr key={incident.incident_id}>
                <td>
                  <RiskScore score={incident.risk_score} />
                </td>
                <td>
                  <Link to={`/incidents/${encodeURIComponent(incident.incident_id)}`}>
                    {incident.title}
                  </Link>
                  <div className="muted">{incident.finding_count} finding(s)</div>
                </td>
                <td>
                  <SeverityBadge severity={incident.severity} />
                </td>
                <td>
                  <StatusBadge status={incident.status} />
                </td>
                <td>{formatTime(incident.last_seen)}</td>
              </tr>
            ))}
          </tbody>
        </table>
      )}
    </>
  );
}
