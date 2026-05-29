package proxy

import (
	"fmt"
	"strings"

	"sni-spoofing-go/injection"
)

// ParseInjectorMode normalizes the user-supplied -injector flag (or its GUI
// equivalent) into the typed enum the injection package expects. An empty
// string maps to InjectorModeActive for backward compatibility with the CLI's
// pre-flag default.
func ParseInjectorMode(s string) (injection.InjectorMode, error) {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "", string(injection.InjectorModeActive):
		return injection.InjectorModeActive, nil
	case string(injection.InjectorModePassive):
		return injection.InjectorModePassive, nil
	default:
		return "", fmt.Errorf("invalid -injector %q (want active or passive)", s)
	}
}
