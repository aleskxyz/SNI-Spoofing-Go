//go:build !darwin

package proxy

import "sni-spoofing-go/injection"

// DefaultInjectorMode is the per-platform default for the injector backend.
// Linux and Windows default to active (nfqueue / WinDivert reinject);
// macOS overrides this to passive in injector_mode_default_darwin.go.
func DefaultInjectorMode() injection.InjectorMode {
	return injection.InjectorModeActive
}
