import { api } from "../api/client";
import { SeverityBadge } from "../components/Badges";
import { TacticList, TechniqueLink } from "../components/Mitre";
import { ErrorMessage, Loading } from "../components/States";
import { useApi } from "../hooks/useApi";

/** The detection rules, which ATT&CK tactics they cover (gaps included), and the posture checks. */
export function RulesPage() {
  const state = useApi((signal) => api.listDetectors(signal), []);

  if (state.status === "loading") return <Loading what="rules" />;
  if (state.status === "error") {
    return <ErrorMessage message={state.error.message} onRetry={state.reload} />;
  }
  const { attack_version, tactics, detectors, posture_checks } = state.data;
  const covered = new Set(
    detectors.flatMap((d) => d.mitre.flatMap((m) => m.tactics.map((t) => t.tactic_id))),
  );

  return (
    <>
      <h1>Detection rules</h1>
      <p className="muted">
        {detectors.length} rules, mapped to MITRE ATT&amp;CK v{attack_version}. Mappings are
        curated by hand, each with a written rationale.
      </p>

      <h2>Tactic coverage</h2>
      <ul className="coverage" aria-label="Tactic coverage">
        {tactics.map((tactic) => (
          <li key={tactic.tactic_id} className={covered.has(tactic.tactic_id) ? "covered" : "gap"}>
            <a href={tactic.url} target="_blank" rel="noopener noreferrer">
              {tactic.name}
            </a>
          </li>
        ))}
      </ul>
      <p className="muted">
        {covered.size} of {tactics.length} tactics covered. Gaps are expected for a CloudTrail-only
        prototype: most need other telemetry (endpoint, network, data events).
      </p>

      <h2>Rules</h2>
      <table>
        <thead>
          <tr>
            <th>Rule</th>
            <th>Severity</th>
            <th>ATT&amp;CK</th>
          </tr>
        </thead>
        <tbody>
          {detectors.map((detector) => (
            <tr key={detector.detector_id}>
              <td>
                <strong>{detector.name}</strong>{" "}
                <span className="mono muted">({detector.detector_id})</span>
                <div className="muted">{detector.description}</div>
              </td>
              <td>
                <SeverityBadge severity={detector.severity} />
              </td>
              <td>
                {detector.mitre.length === 0 ? (
                  <span className="muted">Not mapped</span>
                ) : (
                  detector.mitre.map((mapping) => (
                    <div key={mapping.technique_id} className="mapping">
                      <TechniqueLink technique={mapping} />
                      <div>
                        <TacticList technique={mapping} />
                      </div>
                    </div>
                  ))
                )}
              </td>
            </tr>
          ))}
        </tbody>
      </table>

      <h2>Posture checks</h2>
      <p className="muted">
        {posture_checks.length} checks of AWS configuration, run against a snapshot rather than
        activity. They describe weaknesses, not adversary behaviour, so they are not mapped to
        ATT&amp;CK.
      </p>
      <table aria-label="Posture checks">
        <thead>
          <tr>
            <th>Check</th>
            <th>Service</th>
            <th>Severity</th>
            <th>Reference</th>
          </tr>
        </thead>
        <tbody>
          {posture_checks.map((check) => (
            <tr key={check.check_id}>
              <td>
                <strong>{check.name}</strong>{" "}
                <span className="mono muted">({check.check_id})</span>
                <div className="muted">{check.description}</div>
              </td>
              <td className="mono nowrap">{check.service}</td>
              <td>
                <SeverityBadge severity={check.severity} />
              </td>
              <td>{check.reference}</td>
            </tr>
          ))}
        </tbody>
      </table>
    </>
  );
}
