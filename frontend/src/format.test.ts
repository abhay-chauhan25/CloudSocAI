import { describe, expect, it } from "vitest";

import { formatLabel, formatPoints, formatTime } from "./format";

describe("format", () => {
  it("turns identifiers into readable labels", () => {
    expect(formatLabel("false_positive")).toBe("False positive");
    expect(formatLabel("audit-logging-tampered")).toBe("Audit logging tampered");
  });

  it("shows times in UTC, as CloudTrail records them", () => {
    expect(formatTime("2026-10-06T03:05:31Z")).toBe("2026-10-06 03:05:31 UTC");
    expect(formatTime("not a time")).toBe("not a time");
  });

  it("signs risk points", () => {
    expect([formatPoints(15), formatPoints(0), formatPoints(-5)]).toEqual(["+15", "+0", "-5"]);
  });
});
