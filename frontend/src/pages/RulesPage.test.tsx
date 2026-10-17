import { render, screen, within } from "@testing-library/react";
import { MemoryRouter } from "react-router";
import { describe, expect, it, vi } from "vitest";

import type { DetectorCatalog } from "../api/types";
import { fakeFetch } from "../test/fixtures";
import { RulesPage } from "./RulesPage";

const tactic = (tactic_id: string, name: string) => ({
  tactic_id,
  name,
  url: `https://attack.mitre.org/tactics/${tactic_id}/`,
});
const persistence = tactic("TA0003", "Persistence");

const catalog: DetectorCatalog = {
  attack_version: "20.0",
  tactics: [tactic("TA0001", "Initial Access"), persistence, tactic("TA0040", "Impact")],
  detectors: [
    {
      detector_id: "iam-user-created",
      name: "IAM user created",
      description: "A new IAM user was created.",
      rationale: "Persistence backdoor.",
      severity: "low",
      mitre: [
        {
          technique_id: "T1136.003",
          name: "Create Account: Cloud Account",
          tactics: [persistence],
          url: "https://attack.mitre.org/techniques/T1136/003/",
          rationale: "Creates a cloud account.",
        },
      ],
    },
    {
      detector_id: "failed-call-burst",
      name: "Burst of failed API calls",
      description: "Many denials.",
      rationale: "Probing.",
      severity: "medium",
      mitre: [],
    },
  ],
  posture_checks: [
    {
      check_id: "s3-bucket-public",
      name: "S3 bucket is public",
      service: "s3",
      description: "The bucket policy is public.",
      rationale: "Data leak.",
      remediation: "Remove the public statement.",
      reference: "CIS AWS Foundations Benchmark: S3 Block Public Access enabled",
      severity: "critical",
    },
  ],
};

describe("RulesPage", () => {
  it("shows rules, their mappings, and which tactics are covered or gaps", async () => {
    vi.stubGlobal("fetch", fakeFetch({ "/api/detectors": { body: catalog } }).fetch);

    render(
      <MemoryRouter>
        <RulesPage />
      </MemoryRouter>,
    );

    const coverage = await screen.findByRole("list", { name: "Tactic coverage" });
    const tiles = within(coverage).getAllByRole("listitem");
    expect(tiles.map((t) => [t.textContent, t.className])).toEqual([
      ["Initial Access", "gap"],
      ["Persistence", "covered"],
      ["Impact", "gap"],
    ]);
    expect(screen.getByText(/1 of 3 tactics covered/)).toBeTruthy();
    expect(screen.getByRole("link", { name: /T1136\.003/ })).toBeTruthy();
    expect(screen.getByText("Not mapped")).toBeTruthy();
    const posture = screen.getByRole("table", { name: "Posture checks" });
    expect(within(posture).getByText("S3 bucket is public")).toBeTruthy();
    expect(within(posture).getByText(/S3 Block Public Access enabled/)).toBeTruthy();
  });
});
