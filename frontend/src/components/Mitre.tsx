import type { TechniqueInfo } from "../api/types";

/**
 * A link to a technique on attack.mitre.org. External links open in a new tab
 * with rel="noopener noreferrer", so the other site cannot control this page
 * or learn which incident the analyst was viewing.
 */
export function TechniqueLink({ technique }: { technique: TechniqueInfo }) {
  return (
    <a href={technique.url} target="_blank" rel="noopener noreferrer" className="technique">
      <span className="mono">{technique.technique_id}</span> {technique.name}
    </a>
  );
}

export function TacticList({ technique }: { technique: TechniqueInfo }) {
  return (
    <span className="chips">
      {technique.tactics.map((tactic) => (
        <span key={tactic.tactic_id} className="chip" title={tactic.tactic_id}>
          {tactic.name}
        </span>
      ))}
    </span>
  );
}
