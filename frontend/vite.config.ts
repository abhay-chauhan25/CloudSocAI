import react from "@vitejs/plugin-react";
import { defineConfig } from "vitest/config";

// The backend's address during development (uvicorn's default).
const API_TARGET = "http://127.0.0.1:8000";

export default defineConfig({
  plugins: [react()],
  server: {
    // Listen on localhost only: the dashboard shows security data and the API
    // behind it has no authentication yet.
    host: "127.0.0.1",
    port: 5173,
    strictPort: true,
    // The browser calls /api/... on the dashboard's own origin and Vite
    // forwards it to FastAPI. Same origin means the backend needs no CORS.
    proxy: {
      "/api": {
        target: API_TARGET,
        rewrite: (path) => path.replace(/^\/api/, ""),
      },
    },
  },
  test: {
    environment: "jsdom",
    setupFiles: ["src/test/setup.ts"],
  },
});
