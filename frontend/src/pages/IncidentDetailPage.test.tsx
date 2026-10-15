import { render, screen, within } from "@testing-library/react";
import { MemoryRouter, Route, Routes } from "react-router";
import { describe, expect, it, vi } from "vitest";

import { fakeFetch, iamIncidentDetail } from "../test/fixtures";
import { IncidentDetailPage } from "./IncidentDetailPage";

function renderIncident(id: string) {
  return render(
    <MemoryRouter initialEntries={[`/incidents/${id}`]}>
      <Routes>
        <Route path="/incidents/:incidentId" element={<IncidentDetailPage />} />
      </Routes>
    </MemoryRouter>,
  );
}

describe("IncidentDetailPage", () => {
  it("shows the risk breakdown, findings, and timeline", async () => {
    vi.stubGlobal(
      "fetch",
      fakeFetch({ "/api/incidents/incident-iam": { body: iamIncidentDetail } }).fetch,
    );

    renderIncident("incident-iam");

    await screen.findByRole("heading", { name: iamIncidentDetail.title });
    expect(screen.getByRole("table", { name: "Risk breakdown" }).textContent).toContain("+80");
    expect(screen.getByRole("link", { name: "AdministratorAccess policy attached" })).toBeTruthy();

    const technique = screen.getByRole("link", { name: /T1098\.003/ });
    expect(technique.getAttribute("href")).toBe("https://attack.mitre.org/techniques/T1098/003/");
    expect(technique.getAttribute("rel")).toBe("noopener noreferrer");
    expect(screen.getByText(/Tactics \(attacker goals\) covered/).textContent).toContain(
      "PersistencePrivilege Escalation",
    );

    const items = within(screen.getByRole("list")).getAllByRole("listitem");
    expect(items.map((item) => item.className)).toEqual(["context", "flagged"]);
    expect(items[0]?.textContent).toContain("failed: AccessDenied");
    expect(items[1]?.textContent).toContain("admin-policy-attached");
  });

  it("says when the incident does not exist", async () => {
    vi.stubGlobal("fetch", fakeFetch({}).fetch);

    renderIncident("missing");

    expect((await screen.findByRole("alert")).textContent).toBe("Incident not found.");
    expect(screen.queryByRole("button", { name: "Try again" })).toBeNull();
  });
});
