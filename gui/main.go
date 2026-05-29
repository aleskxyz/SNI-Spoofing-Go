package main

import (
	"embed"
	"errors"
	"fmt"
	"io/fs"
	"log"
	"os"
	"path/filepath"

	"github.com/wailsapp/wails/v2"
	"github.com/wailsapp/wails/v2/pkg/options"
	"github.com/wailsapp/wails/v2/pkg/options/assetserver"
)

//go:embed all:frontend/dist
var assets embed.FS

// errFrontendNotBuilt is reported when the embedded frontend/dist directory
// contains only the .gitkeep placeholder we commit so `go build` works on a
// fresh checkout. Without this guard, `go build .` would silently produce a
// binary that launches a blank window, which is the worst kind of failure to
// diagnose for a new contributor.
var errFrontendNotBuilt = errors.New("frontend/dist only contains the placeholder .gitkeep — run `wails build` (or `wails dev`) so the embedded assets exist before launching the binary directly")

func main() {
	if err := verifyEmbeddedFrontend(); err != nil {
		logStartupFailure(err)
		// Also write to stderr so `go run .` shows it even though Windows GUI
		// builds may detach the console; the logfile is the durable channel.
		fmt.Fprintln(os.Stderr, "startup error:", err)
		os.Exit(1)
	}

	app := NewApp()

	err := wails.Run(&options.App{
		Title:     "SNI Spoofing",
		Width:     1100,
		Height:    760,
		MinWidth:  900,
		MinHeight: 600,
		AssetServer: &assetserver.Options{
			Assets: assets,
		},
		BackgroundColour: &options.RGBA{R: 18, G: 22, B: 31, A: 1},
		OnStartup:        app.startup,
		OnShutdown:       app.shutdown,
		Bind:             []interface{}{app},
	})

	if err != nil {
		// Windows GUI builds detach stderr, so plain println vanishes. Persist
		// the failure where a confused user (or maintainer) can find it.
		logStartupFailure(err)
	}
}

// verifyEmbeddedFrontend rejects a binary whose embedded frontend/dist
// directory is missing index.html — the entrypoint vite emits on a real
// build. That state is the symptom of `go build` without a prior
// `wails build`; the resulting window opens completely blank with no log
// line that explains why, which is hostile to anyone trying the project
// for the first time.
//
// Checking specifically for index.html (rather than "anything that isn't
// .gitkeep") guards against accidentally-committed noise like .DS_Store or
// Thumbs.db masking the missing-build state.
func verifyEmbeddedFrontend() error {
	return verifyFrontend(assets)
}

func verifyFrontend(fsys fs.FS) error {
	if _, err := fs.Stat(fsys, "frontend/dist/index.html"); err != nil {
		return errFrontendNotBuilt
	}
	return nil
}

func logStartupFailure(err error) {
	msg := fmt.Sprintf("wails.Run failed: %v", err)

	// Best effort: <user-cache>/sni-spoofing-gui/startup.log, falling back to
	// the binary directory and finally stderr. Any single failure short-circuits
	// to the next location, never the panic-on-error path.
	if dir, e := os.UserCacheDir(); e == nil {
		path := filepath.Join(dir, "sni-spoofing-gui", "startup.log")
		if writeLogLine(path, msg) {
			return
		}
	}
	if exe, e := os.Executable(); e == nil {
		path := filepath.Join(filepath.Dir(exe), "sni-spoofing-gui-startup.log")
		if writeLogLine(path, msg) {
			return
		}
	}
	log.Println(msg)
}

func writeLogLine(path, msg string) bool {
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return false
	}
	f, err := os.OpenFile(path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o644)
	if err != nil {
		return false
	}
	defer f.Close()
	logger := log.New(f, "", log.LstdFlags)
	logger.Println(msg)
	return true
}
