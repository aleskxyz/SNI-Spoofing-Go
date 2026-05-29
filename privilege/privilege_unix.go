//go:build linux || darwin

// Package privilege exposes a tiny cross-platform check for whether the
// current process can drive the packet injector. Linux/macOS need root
// (euid 0); Windows needs an elevated process token.
package privilege

import "os"

// IsElevated reports whether the current process has the OS-level privileges
// required to open WinDivert / nfqueue / BPF. The bool is always meaningful
// (false on errors); the error is informational for the caller.
func IsElevated() (bool, error) {
	return os.Geteuid() == 0, nil
}

// Hint returns a short, user-facing string suggesting how to obtain those
// privileges on the current platform.
func Hint() string {
	return "run as root"
}

// Platform returns the stable platform key the frontend uses to pick a localized hint (vs the English Hint() string which Persian users currently see leaking through).
func Platform() string { return "unix" }
