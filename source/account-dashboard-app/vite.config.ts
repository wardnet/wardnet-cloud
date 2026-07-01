/// <reference types="vitest/config" />
import { resolve } from "node:path";
import { defineConfig } from "vitest/config";
import react from "@vitejs/plugin-react";

// Singletons that must have exactly one copy across the app and the linked
// design system (which ships its own node_modules). Aliasing them to the app's
// copies prevents dueling-React / invalid-hook errors.
const app = (p: string) => resolve(import.meta.dirname, "node_modules", p);
const dedupedSingletons = {
  react: app("react"),
  "react-dom": app("react-dom"),
  "lucide-react": app("lucide-react"),
  "radix-ui": app("radix-ui"),
  cmdk: app("cmdk"),
};

// The backend the dev proxy targets. Override with VITE_API_PROXY when running
// the SPA against a locally-run wardnet-cloud backend.
const API_PROXY = process.env.VITE_API_PROXY ?? "http://localhost:8080";

// https://vite.dev/config/
export default defineConfig({
  plugins: [react()],
  // The linked @wardnet/* packages carry their own React copy; force a single
  // instance so DS-bundled Radix shares the app's React (avoids invalid-hook).
  resolve: {
    dedupe: ["react", "react-dom"],
    alias: dedupedSingletons,
  },
  // The linked @wardnet/* packages live outside the project root; allow Vite's
  // dev server to serve their files.
  server: {
    fs: { allow: [".."] },
    // Same-origin `/v1` → backend so the httpOnly session cookie works in dev
    // (mirrors nginx in prod). Only used when MSW is disabled.
    proxy: {
      "/v1": {
        target: API_PROXY,
        changeOrigin: true,
        secure: false,
      },
    },
  },
  // Pre-bundle the linked DS so its ESM resolves cleanly in dev.
  optimizeDeps: {
    include: ["@wardnet/ui"],
  },
  test: {
    globals: true,
    environment: "jsdom",
    setupFiles: ["./src/test/setup.ts"],
    css: false,
    restoreMocks: true,
    // Inline the linked DS so its externalised `react`/`radix-ui` imports
    // resolve through the app's deduped React rather than the DS's own copy.
    server: {
      deps: {
        inline: [/wardnet-design-system/],
      },
    },
  },
});
