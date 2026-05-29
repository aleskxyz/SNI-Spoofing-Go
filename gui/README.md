# SNI-Spoofing GUI

Cross-platform desktop frontend for the SNI-Spoofing proxy, built with [Wails v2](https://wails.io) and Svelte 5. Ships with English and Persian (RTL) translations using the Vazirmatn font.

This is a separate Go module (`gui/go.mod`) so the CLI build path in the repo root doesn't pull in Wails or its transitive deps. It imports the shared proxy core from `sni-spoofing-go/proxy` via a local `replace` directive — see [`go.mod`](go.mod). When the parent module is eventually tagged and published, drop the replace and pin a real version.

## Prerequisites

- Go 1.25+ (the gui module declares `go 1.25.0` in [`go.mod`](go.mod))
- Node.js 20.19+ (required by Vite 7 — older Node versions will fail at `npm install`) and npm 10+
- Wails CLI: `go install github.com/wailsapp/wails/v2/cmd/wails@v2.12.0`
- Platform-specific Wails dependencies — see [wails.io/docs/gettingstarted/installation](https://wails.io/docs/gettingstarted/installation) (WebView2 on Windows, `libgtk-3-dev` + `libwebkit2gtk-4.1-dev` on Linux, Xcode CLT on macOS).

## Build

```bash
cd gui
wails build
# binary lands in gui/build/bin/sni-spoofing-gui[.exe]
```

The build runs `npm install` and `vite build` in `gui/frontend`, generates TypeScript bindings into `gui/frontend/wailsjs/` (gitignored), and embeds the resulting `gui/frontend/dist/` into the binary via `//go:embed`.

A placeholder `gui/frontend/dist/.gitkeep` is committed so `go build` succeeds on a fresh checkout even before `wails build` populates the real assets — without it, the embed directive would fail because the directory would not exist.

## Dev mode (hot reload)

```bash
cd gui
wails dev
```

On Windows, the bundled manifest (`build/windows/wails.exe.manifest`) sets `requestedExecutionLevel level="requireAdministrator"`, so running `wails dev` from a non-elevated PowerShell aborts with `fork/exec: requires elevation` before the dev server can come up. Either launch the terminal as Administrator before invoking `wails dev`, or temporarily comment out the `<trustInfo>` block in `build/windows/wails.exe.manifest` while iterating on the UI locally — just remember to restore it before committing, since the production binary needs the elevation prompt to drive WinDivert.

## Privileges

The GUI needs the same elevated privileges as the CLI — Administrator on Windows, root on Linux/macOS — because it drives the same packet-injection backend (WinDivert / nfqueue / BPF). Launch with `sudo` or "Run as administrator."

## Status

The GUI is fully wired to the proxy core in `sni-spoofing-go/proxy`. Clicking **Start** launches the proxy in a goroutine and streams its log output into the UI panel via a Wails `log` event. **Stop** cancels the context and waits for the goroutine to drain. **Run test matrix** drives `proxy.RunMethodMatrix` and returns structured per-case results that the UI renders as a table. Validation (`validateConfig` in `app.go`) covers scalar/enum constraints; address parsing, hostname resolution, and uTLS preset validation run through the same `config.ConnectFromCLI` + `packet.ParseClientHelloID` paths the CLI uses.

## Layout

- `main.go` — Wails app entry, embeds `frontend/dist`.
- `app.go` — Go ↔ JS bindings (`Start`, `Stop`, `RunTest`, `GetDefaultConfig`, etc.) and config validation.
- `wails.json` — Wails build manifest.
- `frontend/` — Svelte 5 + Vite 7 + TypeScript app.
  - `src/App.svelte` — single-page UI.
  - `src/i18n.ts` — svelte-i18n setup; toggles `<html dir>` between `ltr` and `rtl` and persists locale to `localStorage`.
  - `src/locales/{en,fa}.json` — translation tables.
- `build/` — Wails platform manifests (Windows icon, macOS Info.plist) and output binary under `build/bin/`.
