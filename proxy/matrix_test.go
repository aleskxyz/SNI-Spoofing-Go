package proxy

import (
	"testing"
	"time"

	"sni-spoofing-go/injection"
)

func TestParseCloudflareTraceIP(t *testing.T) {
	got, err := parseCloudflareTraceIP("colo=FRA\nip=94.101.178.10\n")
	if err != nil {
		t.Fatal(err)
	}
	if got != "94.101.178.10" {
		t.Fatalf("ip = %q", got)
	}
	if _, err := parseCloudflareTraceIP("colo=FRA\n"); err == nil {
		t.Fatal("expected missing ip error")
	}
}

func TestParseArvanTraceIP(t *testing.T) {
	got, err := parseArvanTraceIP("<html>Your IP: 94.101.178.10</html>")
	if err != nil {
		t.Fatal(err)
	}
	if got != "94.101.178.10" {
		t.Fatalf("ip = %q", got)
	}
	if _, err := parseArvanTraceIP("<html>no ip</html>"); err == nil {
		t.Fatal("expected missing ip error")
	}
}

func TestLoopbackListenAddr(t *testing.T) {
	for _, tc := range []struct {
		in   string
		want string
	}{
		{"0.0.0.0:40443", "127.0.0.1:40443"},
		{":40443", "127.0.0.1:40443"},
		{"127.0.0.1:40443", "127.0.0.1:40443"},
	} {
		if got := loopbackListenAddr(tc.in); got != tc.want {
			t.Fatalf("loopbackListenAddr(%q) = %q, want %q", tc.in, got, tc.want)
		}
	}
}

func TestMethodMatrixCases(t *testing.T) {
	if MethodMatrixCaseDelay <= 0 {
		t.Fatal("method matrix case delay must be positive")
	}
	cases := MatrixCases()
	expected := len([]string{"none", "firefox", "chrome", "safari", "ios", "edge"}) * 2 * 2
	if len(cases) != expected {
		t.Fatalf("case count = %d, want %d", len(cases), expected)
	}

	seen := make(map[string]bool)
	for _, tc := range cases {
		opts := tc.options(injection.InjectorModeActive)
		if opts.AckTimeout != 3*time.Second || opts.FakeDelay != 10*time.Millisecond ||
			opts.FragmentDelay != 10*time.Millisecond || opts.SNIChunk != 3 {
			t.Fatalf("wrong constants for %s: %+v", tc.String(), opts)
		}
		if !opts.Quiet {
			t.Fatalf("matrix options must be quiet for %s", tc.String())
		}
		if opts.Logger == nil {
			t.Fatalf("matrix options must carry a non-nil logger for %s", tc.String())
		}
		seen[tc.String()] = true
	}
	for _, want := range []string{
		"utls=none repeat=1 fragment=off",
		"utls=firefox repeat=2 fragment=on",
		"utls=edge repeat=2 fragment=on",
	} {
		if !seen[want] {
			t.Fatalf("missing matrix case %q", want)
		}
	}
}

func TestParseInjectorMode(t *testing.T) {
	for _, tc := range []struct {
		in      string
		want    injection.InjectorMode
		wantErr bool
	}{
		{"", injection.InjectorModeActive, false},
		{"active", injection.InjectorModeActive, false},
		{"PASSIVE", injection.InjectorModePassive, false},
		{"  passive  ", injection.InjectorModePassive, false},
		{"nfqueue", "", true},
	} {
		got, err := ParseInjectorMode(tc.in)
		if (err != nil) != tc.wantErr {
			t.Fatalf("ParseInjectorMode(%q) err = %v, wantErr=%v", tc.in, err, tc.wantErr)
		}
		if !tc.wantErr && got != tc.want {
			t.Fatalf("ParseInjectorMode(%q) = %q, want %q", tc.in, got, tc.want)
		}
	}
}
