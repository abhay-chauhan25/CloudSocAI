import react from "@vitejs/plugin-react";
import { loadEnv } from "vite";
import { defineConfig } from "vitest/config";

// The backend's address during development (uvicorn's default).
const API_TARGET = "http://127.0.0.1:8000";
// The repository root, where the shared .env lives (npm scripts run in frontend/).
const ENV_DIR = "..";

export default defineConfig(({ mode }) => {
  // Read API_KEY for the proxy below. The "" prefix loads every variable into
  // this Node process only; the browser bundle still receives just VITE_*
  // variables from frontend/, so the key never reaches the page.
  const apiKey = loadEnv(mode, ENV_DIR, "").API_KEY ?? "";

  return {
    plugins: [react()],
    server: {
      // Listen on localhost only: the dashboard shows security data, and the
      // proxy below authenticates every request it forwards.
      host: "127.0.0.1",
      port: 5173,
      strictPort: true,
      // The browser calls /api/... on the dashboard's own origin and Vite
      // forwards it to FastAPI. Same origin means the backend needs no CORS.
      proxy: {
        "/api": {
          target: API_TARGET,
          rewrite: (path) => path.replace(/^\/api/, ""),
          // Added server-side, like nginx does in the container; a key sent
          // by the browser is overwritten.
          headers: { "X-API-Key": apiKey },
        },
      },
    },
    test: {
      environment: "jsdom",
      setupFiles: ["src/test/setup.ts"],
    },
  };
});
