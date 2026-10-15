import type { RiskAssessment } from "../api/types";
import { formatPoints } from "../format";

/**
 * Show how a risk score was built, line by line, so it can be checked by hand.
 * The score itself comes from the API; this component only explains it.
 */
export function RiskBreakdown({ risk }: { risk: RiskAssessment }) {
  return (
    <table className="risk-breakdown">
      <caption>Risk breakdown</caption>
      <tbody>
        {risk.factors.map((factor, index) => (
          <tr key={index}>
            <td className="points">{formatPoints(factor.points)}</td>
            <td>
              <strong>{factor.name}</strong>
              <div className="muted">{factor.explanation}</div>
            </td>
          </tr>
        ))}
      </tbody>
      <tfoot>
        <tr>
          <td className="points">{risk.score}</td>
          <td>
            <strong>Total</strong>{" "}
            <span className="muted">(sum of the factors, capped to 0–100)</span>
          </td>
        </tr>
      </tfoot>
    </table>
  );
}
