// The only module that talks to the backend. Pages call these functions and
// never build URLs or call fetch() themselves.

import type {
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

async function request<T>(
  path: string,
  params: Record<string, QueryValue> = {},
  signal?: AbortSignal,
): Promise<T> {
  let response: Response;
  try {
    response = await fetch(buildUrl(path, params), {
      headers: { Accept: "application/json" },
      signal,
    });
  } catch (error) {
    if (signal?.aborted) throw error; // the page was left; not a real failure
    throw new ApiError(0, "Cannot reach the CloudSOC API. Is the backend running?");
  }
  if (!response.ok) {
    // Response bodies are not shown: they are for developers, not users.
    throw new ApiError(response.status, messageFor(response.status));
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
};
