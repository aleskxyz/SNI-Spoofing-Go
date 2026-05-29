import { writeFileSync } from "node:fs";
import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { defineConfig, type PluginOption } from "vite";
import { svelte } from "@sveltejs/vite-plugin-svelte";

const here = dirname(fileURLToPath(import.meta.url));

// Vite empties `dist/` at the start of every build, which removes the
// .gitkeep committed to git. Without that placeholder, `go build` (and CI's
// `go vet`) fails on a fresh checkout because `//go:embed all:frontend/dist`
// needs at least one file. This plugin re-creates the placeholder after the
// bundle is written so the working tree stays consistent with the index.
const ensureDistGitkeep = (): PluginOption => ({
  name: "ensure-dist-gitkeep",
  apply: "build",
  writeBundle() {
    writeFileSync(resolve(here, "dist", ".gitkeep"), "");
  },
});

export default defineConfig({
  plugins: [svelte(), ensureDistGitkeep()],
});
