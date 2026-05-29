package main

import (
	"strings"
	"testing"
)

func validConfig() ProxyConfig {
	return ProxyConfig{
		Listen:          "127.0.0.1:40443",
		Connect:         "example.com:443",
		FakeSNI:         "hcaptcha.com",
		UTLS:            "firefox",
		Injector:        "active",
		FakeRepeat:      1,
		FakeDelayMs:     2,
		AckTimeoutMs:    2000,
		EnableFragment:  false,
		FragmentDelayMs: 500,
		SNIChunk:        3,
	}
}

func TestValidateConfig_AcceptsDefault(t *testing.T) {
	if err := validateConfig(validConfig()); err != nil {
		t.Fatalf("expected default config to pass, got: %v", err)
	}
}

func TestValidateConfig_Rejects(t *testing.T) {
	cases := []struct {
		name      string
		mutate    func(c *ProxyConfig)
		wantInMsg string
	}{
		{"blank listen", func(c *ProxyConfig) { c.Listen = "   " }, "listen"},
		{"blank connect", func(c *ProxyConfig) { c.Connect = "" }, "connect"},
		{"fake-repeat zero", func(c *ProxyConfig) { c.FakeRepeat = 0 }, "fake-repeat"},
		{"fake-repeat negative", func(c *ProxyConfig) { c.FakeRepeat = -1 }, "fake-repeat"},
		{"fake-repeat too large", func(c *ProxyConfig) { c.FakeRepeat = maxFakeRepeat + 1 }, "fake-repeat"},
		{"sni-chunk negative", func(c *ProxyConfig) { c.SNIChunk = -1 }, "sni-chunk"},
		{"sni-chunk too large", func(c *ProxyConfig) { c.SNIChunk = maxSNIChunk + 1 }, "sni-chunk"},
		{"ack-timeout zero", func(c *ProxyConfig) { c.AckTimeoutMs = 0 }, "ack-timeout"},
		{"ack-timeout negative", func(c *ProxyConfig) { c.AckTimeoutMs = -1 }, "ack-timeout"},
		{"ack-timeout too large", func(c *ProxyConfig) { c.AckTimeoutMs = maxAckTimeoutMs + 1 }, "ack-timeout"},
		{"fake-delay negative", func(c *ProxyConfig) { c.FakeDelayMs = -1 }, "fake-delay"},
		{"fake-delay too large", func(c *ProxyConfig) { c.FakeDelayMs = maxFakeDelayMs + 1 }, "fake-delay"},
		{"fragment-delay negative", func(c *ProxyConfig) { c.FragmentDelayMs = -1 }, "fragment-delay"},
		{"fragment-delay too large", func(c *ProxyConfig) { c.FragmentDelayMs = maxFragmentDelayMs + 1 }, "fragment-delay"},
		{"injector blank", func(c *ProxyConfig) { c.Injector = "" }, "injector"},
		{"injector unknown", func(c *ProxyConfig) { c.Injector = "nfqueue" }, "injector"},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			cfg := validConfig()
			tc.mutate(&cfg)
			err := validateConfig(cfg)
			if err == nil {
				t.Fatalf("validateConfig accepted invalid config %+v", cfg)
			}
			if !strings.Contains(err.Error(), tc.wantInMsg) {
				t.Errorf("error %q does not mention %q", err.Error(), tc.wantInMsg)
			}
		})
	}
}

func TestValidateConfig_AcceptsBoundaryValues(t *testing.T) {
	// SNIChunk == 0 is meaningful in the CLI ("0 = whole hostname in one
	// write") and must be accepted, as must active/passive injector and
	// zero-millisecond fake/fragment delays.
	cases := []struct {
		name   string
		mutate func(c *ProxyConfig)
	}{
		{"sni-chunk 0", func(c *ProxyConfig) { c.SNIChunk = 0 }},
		{"sni-chunk at max", func(c *ProxyConfig) { c.SNIChunk = maxSNIChunk }},
		{"fake-delay 0", func(c *ProxyConfig) { c.FakeDelayMs = 0 }},
		{"fake-delay at max", func(c *ProxyConfig) { c.FakeDelayMs = maxFakeDelayMs }},
		{"fragment-delay 0", func(c *ProxyConfig) { c.FragmentDelayMs = 0 }},
		{"fragment-delay at max", func(c *ProxyConfig) { c.FragmentDelayMs = maxFragmentDelayMs }},
		{"fake-repeat 1", func(c *ProxyConfig) { c.FakeRepeat = 1 }},
		{"fake-repeat at max", func(c *ProxyConfig) { c.FakeRepeat = maxFakeRepeat }},
		{"ack-timeout 1", func(c *ProxyConfig) { c.AckTimeoutMs = 1 }},
		{"ack-timeout at max", func(c *ProxyConfig) { c.AckTimeoutMs = maxAckTimeoutMs }},
		{"injector passive", func(c *ProxyConfig) { c.Injector = "passive" }},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			cfg := validConfig()
			tc.mutate(&cfg)
			if err := validateConfig(cfg); err != nil {
				t.Fatalf("expected boundary value to pass, got: %v", err)
			}
		})
	}
}

// buildProxyArgs is the next layer of validation past validateConfig — it
// runs the same config.ConnectFromCLI + packet.ParseClientHelloID +
// network.IsIPv4 paths the CLI uses. These tests cover the rejection paths
// that validateConfig doesn't see (bad uTLS preset, non-IPv4 listen host,
// IPv6 connect target, malformed addresses).
func TestBuildProxyArgs_RejectsBadInput(t *testing.T) {
	cases := []struct {
		name      string
		mutate    func(c *ProxyConfig)
		wantInMsg string
	}{
		{
			name:      "unknown uTLS preset",
			mutate:    func(c *ProxyConfig) { c.UTLS = "netscape_navigator" },
			wantInMsg: "utls",
		},
		{
			name:      "IPv6 listen host",
			mutate:    func(c *ProxyConfig) { c.Listen = "[::1]:40443" },
			wantInMsg: "listen",
		},
		{
			name:      "connect missing port",
			mutate:    func(c *ProxyConfig) { c.Connect = "example.com" },
			wantInMsg: "configuration",
		},
		{
			name:      "listen missing port",
			mutate:    func(c *ProxyConfig) { c.Listen = "127.0.0.1" },
			wantInMsg: "configuration",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			cfg := validConfig()
			tc.mutate(&cfg)
			_, _, err := buildProxyArgs(cfg, false)
			if err == nil {
				t.Fatalf("buildProxyArgs accepted invalid config %+v", cfg)
			}
			if !strings.Contains(strings.ToLower(err.Error()), tc.wantInMsg) {
				t.Errorf("error %q does not mention %q", err.Error(), tc.wantInMsg)
			}
		})
	}
}

func TestBuildProxyArgs_AcceptsLegacyUTLSAndPortZero(t *testing.T) {
	// "none" disables the uTLS preset path and uses the legacy template;
	// allowPortZero=true accepts a :0 listen for the matrix runner.
	cfg := validConfig()
	cfg.UTLS = "none"
	cfg.Listen = "127.0.0.1:0"
	pc, opts, err := buildProxyArgs(cfg, true)
	if err != nil {
		t.Fatalf("expected legacy uTLS + port:0 to pass, got: %v", err)
	}
	if pc == nil {
		t.Fatal("buildProxyArgs returned nil config without error")
	}
	if opts.Injector == "" {
		t.Fatal("Options.Injector not populated")
	}
}

// TestStop_NoopWhenIdle is a tiny state-machine check — Stop on a fresh App
// must not panic, must not flip flags, and must return nil. The richer
// concurrent-stop scenarios need a real proxy and live elsewhere.
func TestStop_NoopWhenIdle(t *testing.T) {
	a := NewApp()
	if err := a.Stop(); err != nil {
		t.Fatalf("Stop on idle App returned: %v", err)
	}
	st := a.Status()
	if st.Running || st.Testing {
		t.Fatalf("Status after idle Stop = %+v, want all-false", st)
	}
}
