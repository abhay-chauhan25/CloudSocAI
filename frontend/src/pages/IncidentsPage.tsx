import { Link } from "react-router";

import { api } from "../api/client";
import { INCIDENT_STATUSES, SEVERITIES } from "../api/types";
import { RiskScore, SeverityBadge, StatusBadge } from "../components/Badges";
import { Pagination } from "../components/Pagination";
import { Empty, ErrorMessage, Loading } from "../components/States";
import { formatLabel, formatTime } from "../format";
import { useApi } from "../hooks/useApi";
import { PAGE_SIZE, oneOf, useListParams } from "./listParams";

const FILTERS = ["status", "severity"] as const;

export function IncidentsPage() {
  const { offset, sort, filters, update } = useListParams(FILTERS);
  const status = oneOf(INCIDENT_STATUSES, filters.status);
  const severity = oneOf(SEVERITIES, filters.severity);

  const state = useApi(
    (signal) =>
      api.listIncidents({ status, severity, sort, limit: PAGE_SIZE, offset }, signal),
    [status, severity, sort, offset],
  );

  return (
    <>
      <h1>Incidents</h1>
      <p className="muted">Related findings grouped into investigations.</p>

      <div className="filters">
        <label>
          Status
          <select value={status ?? ""} onChange={(e) => update({ status: e.target.value })}>
            <option value="">All</option>
            {INCIDENT_STATUSES.map((s) => (
              <option key={s} value={s}>
                {formatLabel(s)}
              </option>
            ))}
          </select>
        </label>
        <label>
          Severity
          <select value={severity ?? ""} onChange={(e) => update({ severity: e.target.value })}>
            <option value="">All</option>
            {SEVERITIES.map((s) => (
              <option key={s} value={s}>
                {formatLabel(s)}
              </option>
            ))}
          </select>
        </label>
        <label>
          Sort
          <select value={sort} onChange={(e) => update({ sort: e.target.value })}>
            <option value="newest">Latest activity</option>
            <option value="risk">Highest risk</option>
          </select>
        </label>
      </div>

      {state.status === "loading" && <Loading what="incidents" />}
      {state.status === "error" && <ErrorMessage message={state.error.message} onRetry={state.reload} />}
      {state.status === "success" &&
        (state.data.items.length === 0 ? (
          <Empty>No incidents match these filters.</Empty>
        ) : (
          <>
            <table>
              <thead>
                <tr>
                  <th>Risk</th>
                  <th>Incident</th>
                  <th>Severity</th>
                  <th>Status</th>
                  <th>Findings</th>
                  <th>Last activity</th>
                </tr>
              </thead>
              <tbody>
                {state.data.items.map((incident) => (
                  <tr key={incident.incident_id}>
                    <td>
                      <RiskScore score={incident.risk_score} />
                    </td>
                    <td>
                      <Link to={`/incidents/${encodeURIComponent(incident.incident_id)}`}>
                        {incident.title}
                      </Link>
                    </td>
                    <td>
                      <SeverityBadge severity={incident.severity} />
                    </td>
                    <td>
                      <StatusBadge status={incident.status} />
                    </td>
                    <td>{incident.finding_count}</td>
                    <td>{formatTime(incident.last_seen)}</td>
                  </tr>
                ))}
              </tbody>
            </table>
            <Pagination
              total={state.data.total}
              limit={state.data.limit}
              offset={state.data.offset}
              onChange={(next) => update({ offset: String(next) })}
            />
          </>
        ))}
    </>
  );
}
