import { useSearchParams } from "react-router";

import type { SortOrder } from "../api/types";

export const PAGE_SIZE = 20;

/**
 * List filters and the page offset live in the URL query string, so a
 * filtered view can be bookmarked or shared and the back button works.
 * Values from the URL are untrusted: anything unexpected falls back to a default.
 */
export function useListParams<F extends string>(filterNames: readonly F[]) {
  const [params, setParams] = useSearchParams();

  const offsetValue = Number(params.get("offset") ?? 0);
  const offset = Number.isInteger(offsetValue) && offsetValue > 0 ? offsetValue : 0;
  const sort: SortOrder = params.get("sort") === "risk" ? "risk" : "newest";
  const filters = Object.fromEntries(
    filterNames.map((name) => [name, params.get(name) ?? ""]),
  ) as Record<F, string>;

  function update(changes: Partial<Record<F | "sort" | "offset", string>>) {
    const next = new URLSearchParams(params);
    for (const [key, value] of Object.entries(changes)) {
      if (value) next.set(key, value as string);
      else next.delete(key);
    }
    // Changing a filter or the sort order starts again from the first page.
    if (!("offset" in changes)) next.delete("offset");
    setParams(next);
  }

  return { offset, sort, filters, update };
}

/** Return ``value`` only if it is one of ``allowed``; otherwise undefined. */
export function oneOf<T extends string>(allowed: readonly T[], value: string): T | undefined {
  return (allowed as readonly string[]).includes(value) ? (value as T) : undefined;
}
