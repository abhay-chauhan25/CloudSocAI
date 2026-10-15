import { describe, expect, it, vi } from "vitest";

import { fakeFetch } from "../test/fixtures";
import { ApiError, api, buildUrl } from "./client";

describe("buildUrl", () => {
  it("adds only the parameters that have a value", () => {
    expect(buildUrl("/findings", { severity: "high", status: undefined, sort: "", limit: 20 })).toBe(
      "/api/findings?severity=high&limit=20",
    );
  });

  it("returns the bare path when there are no parameters", () => {
    expect(buildUrl("/health")).toBe("/api/health");
  });
});

describe("api", () => {
  it("encodes IDs so they cannot change the request path", async () => {
    const { fetch, calls } = fakeFetch({});
    vi.stubGlobal("fetch", fetch);

    await expect(api.getIncident("../events?x=1")).rejects.toBeInstanceOf(ApiError);
    expect(calls).toEqual(["/api/incidents/..%2Fevents%3Fx%3D1"]);
  });

  it.each([
    [404, "Not found."],
    [503, "The database is unavailable. Is PostgreSQL running?"],
    [500, "The API returned an error (HTTP 500)."],
  ])("turns HTTP %i into a readable ApiError", async (status, message) => {
    vi.stubGlobal("fetch", fakeFetch({ "/api/health": { status, body: { detail: "x" } } }).fetch);

    const error = await api.health().catch((e: unknown) => e);

    expect(error).toBeInstanceOf(ApiError);
    expect((error as ApiError).status).toBe(status);
    expect((error as ApiError).message).toBe(message);
  });

  it("reports an unreachable backend as status 0", async () => {
    vi.stubGlobal("fetch", fakeFetch({ "/api/health": { networkError: true } }).fetch);

    const error = (await api.health().catch((e: unknown) => e)) as ApiError;

    expect(error.status).toBe(0);
    expect(error.message).toContain("Is the backend running?");
  });
});
