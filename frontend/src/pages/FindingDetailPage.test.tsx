import { render, screen } from "@testing-library/react";
import { MemoryRouter, Route, Routes } from "react-router";
import { describe, expect, it, vi } from "vitest";

import type { FindingDetail } from "../api/types";
import { fakeFetch } from "../test/fixtures";
import { FindingDetailPage } from "./FindingDetailPage";

const postureFinding: FindingDetail = {
  finding_id: "finding-bucket",
  detector_id: "s3-bucket-public",
  kind: "posture",
  title: "S3 bucket is public",
  severity: "critical",
  reason: "Bucket 'cloudsoc-public-reports': the bucket policy is public.",
  status: "open",
  first_seen: "2026-10-08T09:00:00Z",
  last_seen: "2026-10-08T09:00:00Z",
  created_at: "2026-10-08T09:05:00Z",
  account_id: "123456789012",
  principal: null,
  principal_arn: null,
  resource: "arn:aws:s3:::cloudsoc-public-reports",
  risk: {
    score: 80,
    factors: [{ name: "Base severity: critical", points: 80, explanation: "Critical." }],
  },
  detector: null,
  posture_check: {
    check_id: "s3-bucket-public",
    name: "S3 bucket is public",
    service: "s3",
    description: "The bucket policy is public.",
    rationale: "Anyone can read the objects.",
    remediation: "Remove the public statement from the bucket policy.",
    reference: "CIS AWS Foundations Benchmark: S3 Block Public Access enabled",
    severity: "critical",
  },
  evidence: [],
};

function renderFinding(id: string) {
  return render(
    <MemoryRouter initialEntries={[`/findings/${id}`]}>
      <Routes>
        <Route path="/findings/:findingId" element={<FindingDetailPage />} />
      </Routes>
    </MemoryRouter>,
  );
}

describe("FindingDetailPage", () => {
  it("explains a posture finding by its check, resource, and fix instead of events", async () => {
    vi.stubGlobal(
      "fetch",
      fakeFetch({ "/api/findings/finding-bucket": { body: postureFinding } }).fetch,
    );

    renderFinding("finding-bucket");

    await screen.findByRole("heading", { name: "Posture check" });
    expect(screen.getByText("arn:aws:s3:::cloudsoc-public-reports")).toBeTruthy();
    expect(screen.getByText(/Remove the public statement/)).toBeTruthy();
    expect(screen.getByText(/describes configuration, not activity/)).toBeTruthy();
    expect(screen.queryByRole("heading", { name: "Detection rule" })).toBeNull();
    expect(screen.queryByText("Actor")).toBeNull();
  });
});
