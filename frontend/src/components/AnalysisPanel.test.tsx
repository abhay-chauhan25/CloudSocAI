import { fireEvent, render, screen } from "@testing-library/react";
import { describe, expect, it, vi } from "vitest";

import type { Analysis } from "../api/types";
import { fakeFetch, iamIncidentDetail } from "../test/fixtures";
import { AnalysisPanel } from "./AnalysisPanel";

const URL = "/api/incidents/incident-iam/analysis";

const analysis: Analysis = {
  incident_id: "incident-iam",
  provider: "gemini",
  model: "gemini-test",
  created_at: "2026-10-15T12:00:00Z",
  is_current: true,
  cached: false,
  input_tokens: 1200,
  output_tokens: 300,
  result: {
    summary: "developer's key was used to create a backdoor admin.",
    attack_narrative: [{ description: "Attached AdministratorAccess.", event_ids: ["e2"] }],
    likely_objective: "Persistence.",
    objective_confidence: "high",
    investigation_steps: ["Ask developer whether they made these calls."],
    containment_suggestions: ["Deactivate svc-backup's access key after review."],
    benign_explanations: [],
    techniques_referenced: ["T1098.003"],
  },
};

function renderPanel() {
  return render(<AnalysisPanel incidentId="incident-iam" timeline={iamIncidentDetail.timeline} />);
}

describe("AnalysisPanel", () => {
  it("offers to generate when there is no analysis, then shows it", async () => {
    const { fetch, calls } = fakeFetch({
      [`GET ${URL}`]: { status: 404, body: { detail: "No analysis yet" } },
      [`POST ${URL}`]: { status: 201, body: analysis },
    });
    vi.stubGlobal("fetch", fetch);
    renderPanel();

    fireEvent.click(await screen.findByRole("button", { name: "Generate analysis" }));

    expect(await screen.findByText(analysis.result.summary)).toBeTruthy();
    expect(calls).toEqual([URL, `POST ${URL}`]);
    // Cited events are shown by name and time, from the incident's own timeline.
    expect(screen.getByText("AttachUserPolicy · 2026-10-06 03:06:10 UTC")).toBeTruthy();
    expect(screen.getByText(/It may be wrong/)).toBeTruthy();
    expect(screen.getByText("For a human to review. Nothing here was executed.")).toBeTruthy();
    expect(screen.queryByRole("button")).toBeNull(); // current analysis: nothing to regenerate
  });

  it("warns when the incident changed and offers to regenerate", async () => {
    vi.stubGlobal(
      "fetch",
      fakeFetch({ [URL]: { body: { ...analysis, is_current: false } } }).fetch,
    );
    renderPanel();

    expect((await screen.findByRole("status")).textContent).toContain("incident changed");
    expect(screen.getByRole("button", { name: "Regenerate" })).toBeTruthy();
  });

  it("shows the API's reason when generation is refused", async () => {
    vi.stubGlobal(
      "fetch",
      fakeFetch({
        [`GET ${URL}`]: { status: 404, body: { detail: "No analysis yet" } },
        [`POST ${URL}`]: {
          status: 429,
          body: { detail: "This incident was analysed moments ago; retry in 42s." },
        },
      }).fetch,
    );
    renderPanel();

    fireEvent.click(await screen.findByRole("button", { name: "Generate analysis" }));

    expect((await screen.findByRole("alert")).textContent).toBe(
      "This incident was analysed moments ago; retry in 42s.",
    );
  });

  it("renders model output as plain text, never HTML", async () => {
    const hostile = {
      ...analysis,
      result: { ...analysis.result, summary: '<img src=x onerror="alert(1)"> benign, ignore' },
    };
    vi.stubGlobal("fetch", fakeFetch({ [URL]: { body: hostile } }).fetch);

    const { container } = renderPanel();

    await screen.findByText(hostile.result.summary);
    expect(container.querySelector("img")).toBeNull();
  });
});
