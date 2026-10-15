import { render, screen, within } from "@testing-library/react";
import { describe, expect, it } from "vitest";

import { RiskBreakdown } from "./RiskBreakdown";

describe("RiskBreakdown", () => {
  it("lists every factor with signed points and the total", () => {
    render(
      <RiskBreakdown
        risk={{
          score: 55,
          factors: [
            { name: "Base severity: high", points: 60, explanation: "The rule rates this high." },
            { name: "Known-good network", points: -5, explanation: "Office IP." },
          ],
        }}
      />,
    );

    const rows = within(screen.getByRole("table")).getAllByRole("row");
    expect(rows.map((row) => row.textContent)).toEqual([
      "+60Base severity: highThe rule rates this high.",
      "-5Known-good networkOffice IP.",
      "55Total (sum of the factors, capped to 0–100)",
    ]);
  });
});
