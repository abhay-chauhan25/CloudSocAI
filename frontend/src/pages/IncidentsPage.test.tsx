import { render, screen } from "@testing-library/react";
import { MemoryRouter } from "react-router";
import { describe, expect, it, vi } from "vitest";

import { fakeFetch, iamIncident, page } from "../test/fixtures";
import { IncidentsPage } from "./IncidentsPage";

function renderAt(url: string) {
  return render(
    <MemoryRouter initialEntries={[url]}>
      <IncidentsPage />
    </MemoryRouter>,
  );
}

describe("IncidentsPage", () => {
  it("shows loading, then the incidents with links", async () => {
    vi.stubGlobal("fetch", fakeFetch({ "/api/incidents": { body: page([iamIncident]) } }).fetch);

    renderAt("/incidents");

    expect(screen.getByRole("status").textContent).toBe("Loading incidents…");
    const link = await screen.findByRole("link", { name: iamIncident.title });
    expect(link.getAttribute("href")).toBe("/incidents/incident-iam");
    expect(screen.getByText("90")).toBeTruthy();
  });

  it("passes filters from the URL to the API and ignores invalid ones", async () => {
    const { fetch, calls } = fakeFetch({ "/api/incidents": { body: page([]) } });
    vi.stubGlobal("fetch", fetch);

    renderAt("/incidents?status=open&severity=nonsense&sort=risk&offset=-5");

    await screen.findByText("No incidents match these filters.");
    expect(calls).toEqual(["/api/incidents?status=open&sort=risk&limit=20&offset=0"]);
  });

  it("shows an error with a retry button when the API fails", async () => {
    vi.stubGlobal("fetch", fakeFetch({ "/api/incidents": { status: 503 } }).fetch);

    renderAt("/incidents");

    const alert = await screen.findByRole("alert");
    expect(alert.textContent).toContain("The database is unavailable");
    expect(screen.getByRole("button", { name: "Try again" })).toBeTruthy();
  });

  it("renders attacker-controlled text as plain text, never as HTML", async () => {
    const hostile = { ...iamIncident, title: '<img src=x onerror="alert(1)">' };
    vi.stubGlobal("fetch", fakeFetch({ "/api/incidents": { body: page([hostile]) } }).fetch);

    const { container } = renderAt("/incidents");

    await screen.findByRole("link", { name: hostile.title });
    expect(container.querySelector("img")).toBeNull();
  });
});
