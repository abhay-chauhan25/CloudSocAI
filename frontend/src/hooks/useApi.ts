import { useCallback, useEffect, useState } from "react";

import { ApiError } from "../api/client";

export type ApiState<T> =
  | { status: "loading" }
  | { status: "error"; error: ApiError }
  | { status: "success"; data: T };

/**
 * Load data when the component appears or ``deps`` change.
 *
 * Each load gets an AbortSignal; leaving the page (or changing a filter)
 * cancels the previous request, so a slow old response can never overwrite
 * newer data.
 */
export function useApi<T>(
  load: (signal: AbortSignal) => Promise<T>,
  deps: readonly unknown[],
): ApiState<T> & { reload: () => void } {
  const [state, setState] = useState<ApiState<T>>({ status: "loading" });
  const [attempt, setAttempt] = useState(0);
  const reload = useCallback(() => setAttempt((n) => n + 1), []);

  useEffect(() => {
    const controller = new AbortController();
    setState({ status: "loading" });
    load(controller.signal).then(
      (data) => {
        if (!controller.signal.aborted) setState({ status: "success", data });
      },
      (error: unknown) => {
        if (controller.signal.aborted) return;
        const apiError =
          error instanceof ApiError ? error : new ApiError(0, "Something went wrong.");
        setState({ status: "error", error: apiError });
      },
    );
    return () => controller.abort();
    // `load` is a new function on every render; `deps` says when to reload.
  }, [...deps, attempt]);

  return { ...state, reload };
}
