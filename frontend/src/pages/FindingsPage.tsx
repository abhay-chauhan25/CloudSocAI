import { Link } from "react-router";

import { api } from "../api/client";
import { FINDING_STATUSES, SEVERITIES } from "../api/types";
import { RiskScore, SeverityBadge, StatusBadge } from "../components/Badges";
import { Pagination } from "../components/Pagination";
import { Empty, ErrorMessage, Loading } from "../components/States";
import { formatLabel, formatTime } from "../format";
import { useApi } from "../hooks/useApi";
import { PAGE_SIZE, oneOf, useListParams } from "./listParams";

const FILTERS = ["severity", "status"] as const;

export function FindingsPage() {
  const { offset, sort, filters, update } = useListParams(FILTERS);
  const severity = oneOf(SEVERITIES, filters.severity);
  const status = oneOf(FINDING_STATUSES, filters.status);

  const state = useApi(
    (signal) => api.listFindings({ severity, status, sort, limit: PAGE_SIZE, offset }, signal),
    [severity, status, sort, offset],
  );

  return (
    <>
      <h1>Findings</h1>
      <p className="muted">What the detection rules flagged, with an explainable risk score.</p>

      <div className="filters">
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
          Status
          <select value={status ?? ""} onChange={(e) => update({ status: e.target.value })}>
            <option value="">All</option>
            {FINDING_STATUSES.map((s) => (
              <option key={s} value={s}>
                {formatLabel(s)}
              </option>
            ))}
          </select>
        </label>
        <label>
          Sort
          <select value={sort} onChange={(e) => update({ sort: e.target.value })}>
            <option value="newest">Newest</option>
            <option value="risk">Highest risk</option>
          </select>
        </label>
      </div>

      {state.status === "loading" && <Loading what="findings" />}
      {state.status === "error" && <ErrorMessage message={state.error.message} onRetry={state.reload} />}
      {state.status === "success" &&
        (state.data.items.length === 0 ? (
          <Empty>No findings match these filters.</Empty>
        ) : (
          <>
            <table>
              <thead>
                <tr>
                  <th>Risk</th>
                  <th>Finding</th>
                  <th>Severity</th>
                  <th>Status</th>
                  <th>Actor</th>
                  <th>First seen</th>
                </tr>
              </thead>
              <tbody>
                {state.data.items.map((finding) => (
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
                    <td>
                      <StatusBadge status={finding.status} />
                    </td>
                    <td>{finding.principal ?? "—"}</td>
                    <td>{formatTime(finding.first_seen)}</td>
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
