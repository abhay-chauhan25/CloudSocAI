// The only module that talks to the backend. Pages call these functions and
// never build URLs or call fetch() themselves.

import type {
  Analysis,
  DetectorCatalog,
  EventSummary,
  FindingDetail,
  FindingStatus,
  FindingSummary,
  Health,
  IncidentDetail,
  IncidentStatus,
  IncidentSummary,
  Page,
  Severity,
  SortOrder,
} from "./types";

// Same-origin path; the Vite dev server (or a production reverse proxy)
// forwards it to FastAPI.
export const API_BASE = "/api";

/** A failed API call, with a message that is safe and useful to show users. */
export class ApiError extends Error {
  readonly status: number;

  constructor(status: number, message: string) {
    super(message);
    this.name = "ApiError";
    this.status = status; // 0 means the API could not be reached at all
  }
}

type QueryValue = string | number | undefined | null;

export function buildUrl(path: string, params: Record<string, QueryValue> = {}): string {
  const query = new URLSearchParams();
  for (const [key, value] of Object.entries(params)) {
    if (value !== undefined && value !== null && value !== "") {
      query.set(key, String(value));
    }
  }
  const qs = query.toString();
  return `${API_BASE}${path}${qs ? `?${qs}` : ""}`;
}

function messageFor(status: number): string {
  switch (status) {
    case 404:
      return "Not found.";
    case 422:
      return "The request was invalid.";
    case 503:
      return "The database is unavailable. Is PostgreSQL running?";
    default:
      return `The API returned an error (HTTP ${status}).`;
  }
}

interface RequestOptions {
  method?: "GET" | "POST";
  signal?: AbortSignal;
  /** Show the API's own `detail` message on failure (only for endpoints that
   * deliberately return user-facing messages, such as the AI analysis). */
  serverMessages?: boolean;
}

async function request<T>(
  path: string,
  params: Record<string, QueryValue> = {},
  signalOrOptions?: AbortSignal | RequestOptions,
): Promise<T> {
  const options: RequestOptions =
    signalOrOptions instanceof AbortSignal ? { signal: signalOrOptions } : (signalOrOptions ?? {});
  let response: Response;
  try {
    response = await fetch(buildUrl(path, params), {
      method: options.method ?? "GET",
      headers: { Accept: "application/json" },
      signal: options.signal,
    });
  } catch (error) {
    if (options.signal?.aborted) throw error; // the page was left; not a real failure
    throw new ApiError(0, "Cannot reach the CloudSOC API. Is the backend running?");
  }
  if (!response.ok) {
    // By default response bodies are not shown: they are for developers.
    let message = messageFor(response.status);
    if (options.serverMessages) {
      const body: unknown = await response.json().catch(() => null);
      const detail = (body as { detail?: unknown } | null)?.detail;
      if (typeof detail === "string" && detail.length > 0) message = detail.slice(0, 300);
    }
    throw new ApiError(response.status, message);
  }
  return (await response.json()) as T;
}

/** Path segments from data (IDs) are encoded so they cannot change the URL's meaning. */
const segment = (value: string) => encodeURIComponent(value);

export interface PageParams {
  limit?: number;
  offset?: number;
}

export const api = {
  health: (signal?: AbortSignal) => request<Health>("/health", {}, signal),

  listEvents: (params: PageParams = {}, signal?: AbortSignal) =>
    request<Page<EventSummary>>("/events", { ...params }, signal),

  listFindings: (
    params: PageParams & {
      severity?: Severity;
      status?: FindingStatus;
      sort?: SortOrder;
      principal?: string;
    } = {},
    signal?: AbortSignal,
  ) => request<Page<FindingSummary>>("/findings", { ...params }, signal),

  getFinding: (findingId: string, signal?: AbortSignal) =>
    request<FindingDetail>(`/findings/${segment(findingId)}`, {}, signal),

  listIncidents: (
    params: PageParams & { status?: IncidentStatus; severity?: Severity; sort?: SortOrder } = {},
    signal?: AbortSignal,
  ) => request<Page<IncidentSummary>>("/incidents", { ...params }, signal),

  getIncident: (incidentId: string, signal?: AbortSignal) =>
    request<IncidentDetail>(`/incidents/${segment(incidentId)}`, {}, signal),

  listDetectors: (signal?: AbortSignal) => request<DetectorCatalog>("/detectors", {}, signal),

  getAnalysis: (incidentId: string, signal?: AbortSignal) =>
    request<Analysis>(`/incidents/${segment(incidentId)}/analysis`, {}, {
      signal,
      serverMessages: true,
    }),

  /** May call an external AI provider; the API caches, rate-limits, and records it. */
  createAnalysis: (incidentId: string) =>
    request<Analysis>(`/incidents/${segment(incidentId)}/analysis`, {}, {
      method: "POST",
      serverMessages: true,
    }),
};
