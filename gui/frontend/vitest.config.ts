import { defineConfig } from "vitest/config";

// Dedicated config so vitest doesn't pull in the Svelte plugin's HMR setup
// from vite.config.ts (which targets the production build, not test runs).
// Tests cover plain TS modules (e.g. logs.ts), so no Svelte preprocessing is
// needed; if/when Svelte component tests are added, switch to vitest's
// browser mode or @testing-library/svelte and load the svelte plugin here.
export default defineConfig({
  test: {
    include: ["src/**/*.test.ts"],
    environment: "node",
  },
});
