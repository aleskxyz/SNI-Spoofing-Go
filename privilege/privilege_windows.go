//go:build windows

// Package privilege exposes a tiny cross-platform check for whether the
// current process can drive the packet injector. Linux/macOS need root
// (euid 0); Windows needs an elevated process token.
package privilege

import "golang.org/x/sys/windows"

// IsElevated reports whether the current Windows process token has been
// raised by UAC (i.e. the user accepted the prompt or launched the .exe
// via "Run as administrator"). Without elevation, WinDivert can't open.
func IsElevated() (bool, error) {
	token, err := windows.OpenCurrentProcessToken()
	if err != nil {
		return false, err
	}
	defer token.Close()
	return token.IsElevated(), nil
}

// Hint returns a short, user-facing string suggesting how to obtain those
// privileges on the current platform.
func Hint() string {
	return "run as Administrator"
}

// Platform returns the stable platform key the frontend uses to pick a localized hint (vs the English Hint() string which Persian users currently see leaking through).
func Platform() string { return "windows" }
