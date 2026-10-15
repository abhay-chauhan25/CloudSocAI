// Response bodies shaped like the real API's, based on the synthetic scenarios.

import type { FindingSummary, IncidentDetail, IncidentSummary, Page } from "../api/types";

export function page<T>(items: T[], total = items.length): Page<T> {
  return { items, total, limit: 20, offset: 0 };
}

export const iamIncident: IncidentSummary = {
  incident_id: "incident-iam",
  pattern_id: "iam-persistence",
  title: "Possible IAM persistence: developer",
  severity: "high",
  risk_score: 90,
  status: "open",
  first_seen: "2026-10-06T03:05:31Z",
  last_seen: "2026-10-06T03:06:10Z",
  principal: "developer",
  finding_count: 3,
};

export const adminFinding: FindingSummary = {
  finding_id: "finding-admin",
  detector_id: "admin-policy-attached",
  title: "AdministratorAccess policy attached",
  severity: "high",
  risk_score: 80,
  status: "open",
  first_seen: "2026-10-06T03:06:10Z",
  last_seen: "2026-10-06T03:06:10Z",
  principal: "developer",
  resource: "user 'svc-backup'",
  event_count: 1,
};

function event(event_id: string, event_name: string, timestamp: string, success = true) {
  return {
    event_id,
    timestamp,
    service: "iam",
    event_name,
    region: "us-east-1",
    principal_type: "IAMUser",
    principal: "developer",
    source_address: "203.0.113.50",
    success,
    error_code: success ? null : "AccessDenied",
  };
}

export const iamIncidentDetail: IncidentDetail = {
  ...iamIncident,
  summary: "3 finding(s) for 'developer'.",
  created_at: "2026-10-11T22:00:00Z",
  updated_at: "2026-10-11T22:00:00Z",
  account_id: "123456789012",
  principal_arn: "arn:aws:iam::123456789012:user/developer",
  risk: {
    score: 90,
    factors: [
      { name: "Highest finding risk", points: 80, explanation: "admin-policy-attached scored 80." },
      { name: "Corroborating rule: access-key-created", points: 5, explanation: "1 finding." },
      { name: "Corroborating rule: iam-user-created", points: 5, explanation: "1 finding." },
    ],
  },
  findings: [adminFinding],
  timeline: [
    {
      event: event("e1", "ListSecrets", "2026-10-06T03:05:02Z", false),
      flagged: false,
      detector_ids: [],
    },
    {
      event: event("e2", "AttachUserPolicy", "2026-10-06T03:06:10Z"),
      flagged: true,
      detector_ids: ["admin-policy-attached"],
    },
  ],
};

type Route = { status?: number; body?: unknown; networkError?: boolean };

/** A fake fetch that answers by URL path, and records every URL requested. */
export function fakeFetch(routes: Record<string, Route>) {
  const calls: string[] = [];
  const fetch = async (input: RequestInfo | URL) => {
    const url = String(input);
    calls.push(url);
    const path = url.split("?")[0] ?? url;
    const route = routes[path];
    if (!route) return new Response("{}", { status: 404 });
    if (route.networkError) throw new TypeError("Failed to fetch");
    return new Response(JSON.stringify(route.body ?? {}), {
      status: route.status ?? 200,
      headers: { "Content-Type": "application/json" },
    });
  };
  return { fetch, calls };
}
