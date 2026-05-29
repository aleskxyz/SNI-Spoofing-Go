//go:build darwin

package proxy

import "sni-spoofing-go/injection"

// DefaultInjectorMode on macOS is passive — the active path relies on
// nfqueue/WinDivert which aren't available, so the BPF tap is the only
// supported backend.
func DefaultInjectorMode() injection.InjectorMode {
	return injection.InjectorModePassive
}
