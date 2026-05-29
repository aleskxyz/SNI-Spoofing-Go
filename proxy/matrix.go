package proxy

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"time"

	"sni-spoofing-go/config"
	"sni-spoofing-go/injection"
	"sni-spoofing-go/packet"
)

const MethodMatrixCaseDelay = 2 * time.Second

// MatrixCase is one row of the e2e test matrix.
type MatrixCase struct {
	UTLS           string `json:"utls"`
	FakeRepeat     int    `json:"fakeRepeat"`
	EnableFragment bool   `json:"enableFragment"`
}

func (c MatrixCase) String() string {
	return fmt.Sprintf("utls=%s repeat=%d fragment=%s", c.UTLS, c.FakeRepeat, FragmentLabel(c.EnableFragment))
}

func (c MatrixCase) options(injector injection.InjectorMode) Options {
	return Options{
		FakeRepeat:     c.FakeRepeat,
		FakeDelay:      10 * time.Millisecond,
		EnableFragment: c.EnableFragment,
		FragmentDelay:  10 * time.Millisecond,
		SNIChunk:       3,
		AckTimeout:     3 * time.Second,
		Quiet:          true,
		Injector:       injector,
		Logger:         log.New(io.Discard, "", 0),
	}
}

// MatrixResult is one row of output: which case ran and whether it passed.
// Err carries the failure reason on a fail; it's nil on pass.
type MatrixResult struct {
	Case MatrixCase
	Pass bool
	Err  error
}

// MatrixCases returns every test case the matrix will exercise — a cross
// product of {none, firefox, chrome, safari, ios, edge} × {1, 2} × {off, on}.
func MatrixCases() []MatrixCase {
	utlsNames := []string{"none", "firefox", "chrome", "safari", "ios", "edge"}
	repeats := []int{1, 2}
	fragments := []bool{false, true}

	out := make([]MatrixCase, 0, len(utlsNames)*len(repeats)*len(fragments))
	for _, utlsName := range utlsNames {
		for _, repeat := range repeats {
			for _, enableFragment := range fragments {
				out = append(out, MatrixCase{
					UTLS:           utlsName,
					FakeRepeat:     repeat,
					EnableFragment: enableFragment,
				})
			}
		}
	}
	return out
}

// Preflight is the result of the IP-match preflight check that runs before
// the matrix. The CLI prints a banner; the GUI surfaces it as a status line.
type Preflight struct {
	ExternalIP string
	InternalIP string
	Matched    bool
	LookupErr  error // external probe (cdn-cgi/trace) failed
	MatchErr   error // IPs differ, method won't bypass
}

// CheckMethodPreconditions performs the cdn-cgi/trace + arvancloud probe used
// to validate that the chosen (connectIP, fakeSNI) actually traverses the
// expected path before we run the full matrix.
func CheckMethodPreconditions(connectIP, fakeSNI string) Preflight {
	out := Preflight{}
	traceIP, err := fetchFakeSNITraceIP(connectIP, fakeSNI)
	if err != nil {
		out.LookupErr = fmt.Errorf("method test: fake-SNI trace failed: %w; method won't work", err)
		return out
	}
	out.ExternalIP = traceIP

	internalIP, err := fetchArvanTraceIP()
	if err != nil {
		// internal IP lookup is non-fatal; matrix still runs.
		return out
	}
	out.InternalIP = internalIP
	if traceIP == internalIP {
		out.Matched = true
	} else {
		out.MatchErr = fmt.Errorf("method test: IPs differ (%s != %s); method won't work", traceIP, internalIP)
	}
	return out
}

// RunMethodMatrix runs every case against the given config and reports a
// MatrixResult per case. If progress is non-nil it's invoked synchronously
// once per case, so the CLI can print rows as they complete. If ctx is
// cancelled the function returns early with the cases completed so far.
func RunMethodMatrix(
	ctx context.Context,
	cfg *config.Config,
	injector injection.InjectorMode,
	progress func(MatrixResult),
) ([]MatrixResult, error) {
	cases := MatrixCases()
	results := make([]MatrixResult, 0, len(cases))

	for i, tc := range cases {
		if ctx.Err() != nil {
			return results, ctx.Err()
		}
		if i > 0 {
			select {
			case <-ctx.Done():
				return results, ctx.Err()
			case <-time.After(MethodMatrixCaseDelay):
			}
		}
		caseCfg := *cfg
		caseCfg.UTLSClientHello = tc.UTLS
		if !packet.IsLegacyUTLS(caseCfg.UTLSClientHello) {
			if _, err := packet.ParseClientHelloID(caseCfg.UTLSClientHello); err != nil {
				return results, fmt.Errorf("method matrix: invalid uTLS %q: %w", caseCfg.UTLSClientHello, err)
			}
		}

		r := MatrixResult{Case: tc}
		if err := runMethodE2E(ctx, &caseCfg, tc.options(injector)); err != nil {
			r.Err = err
		} else {
			r.Pass = true
		}
		results = append(results, r)
		if progress != nil {
			progress(r)
		}
	}
	return results, nil
}

func runMethodE2E(parent context.Context, cfg *config.Config, opts Options) error {
	ctx, cancel := context.WithCancel(parent)
	defer cancel()

	ready := make(chan Ready, 1)
	proxyErr := make(chan error, 1)
	go func() {
		proxyErr <- Run(ctx, cfg, opts, ready)
	}()

	var listenAddr string
	select {
	case r := <-ready:
		if r.Err != nil {
			return fmt.Errorf("method test: tunnel start failed: %w", r.Err)
		}
		listenAddr = loopbackListenAddr(r.ListenAddr)
	case err := <-proxyErr:
		return fmt.Errorf("method test: tunnel stopped before ready: %w", err)
	case <-parent.Done():
		return parent.Err()
	case <-time.After(StartReadyTimeout):
		return fmt.Errorf("method test: tunnel start timeout")
	}

	if err := fetchE2EDNSJSON(ctx, listenAddr); err != nil {
		return fmt.Errorf("e2e request failed: %w", err)
	}
	cancel()
	<-proxyErr
	return nil
}

// FragmentLabel renders the EnableFragment flag for table output.
func FragmentLabel(enabled bool) string {
	if enabled {
		return "on"
	}
	return "off"
}

// DefaultTestListenAddr is the loopback any-port listener used during -test
// so the CLI doesn't fight the user's normal listen port.
func DefaultTestListenAddr() string {
	return "127.0.0.1:0"
}

func loopbackListenAddr(listenAddr string) string {
	host, port, err := net.SplitHostPort(listenAddr)
	if err != nil {
		return listenAddr
	}
	if host == "" || host == "0.0.0.0" || host == "::" {
		host = "127.0.0.1"
	}
	return net.JoinHostPort(host, port)
}

func fetchFakeSNITraceIP(connectIP, fakeSNI string) (string, error) {
	host := strings.TrimSpace(fakeSNI)
	if host == "" {
		return "", fmt.Errorf("empty fake SNI")
	}
	if strings.Contains(host, "://") || strings.ContainsAny(host, "/?#") {
		return "", fmt.Errorf("fake SNI must be a hostname, got %q", fakeSNI)
	}

	dialer := &net.Dialer{Timeout: 10 * time.Second, KeepAlive: 30 * time.Second}
	transport := &http.Transport{
		DialContext: func(ctx context.Context, networkName, addr string) (net.Conn, error) {
			return dialer.DialContext(ctx, "tcp4", net.JoinHostPort(connectIP, "443"))
		},
		TLSClientConfig:       testTLSConfig(host),
		TLSHandshakeTimeout:   10 * time.Second,
		ResponseHeaderTimeout: 10 * time.Second,
		ForceAttemptHTTP2:     false,
	}
	defer transport.CloseIdleConnections()

	client := &http.Client{Transport: transport, Timeout: 20 * time.Second}
	req, err := http.NewRequest(http.MethodGet, "https://"+host+"/cdn-cgi/trace", nil)
	if err != nil {
		return "", err
	}
	resp, err := client.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return "", fmt.Errorf("unexpected HTTP status %s", resp.Status)
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return "", err
	}
	return parseCloudflareTraceIP(string(body))
}

func fetchArvanTraceIP() (string, error) {
	dialer := &net.Dialer{Timeout: 10 * time.Second, KeepAlive: 30 * time.Second}
	transport := &http.Transport{
		DialContext: func(ctx context.Context, networkName, addr string) (net.Conn, error) {
			return dialer.DialContext(ctx, "tcp4", addr)
		},
		TLSClientConfig:       testTLSConfig("arvancloud.ir"),
		TLSHandshakeTimeout:   10 * time.Second,
		ResponseHeaderTimeout: 10 * time.Second,
		ForceAttemptHTTP2:     false,
	}
	defer transport.CloseIdleConnections()

	client := &http.Client{Transport: transport, Timeout: 20 * time.Second}
	req, err := http.NewRequest(http.MethodGet, "https://arvancloud.ir", nil)
	if err != nil {
		return "", err
	}
	// ArvanCloud's edge replies with a "Your IP: …" debug page when the Host
	// header doesn't match a real customer site — we use that as a free
	// "what does my outbound IP look like to a domestic CDN" probe. The
	// SNI on the TLS handshake remains arvancloud.ir (set via testTLSConfig
	// above); only the HTTP Host header is intentionally invalid.
	req.Host = "invalid"

	resp, err := client.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return "", err
	}
	return parseArvanTraceIP(string(body))
}

var arvanIPPattern = regexp.MustCompile(`Your IP:\s*([0-9.]+)`)

func parseArvanTraceIP(body string) (string, error) {
	m := arvanIPPattern.FindStringSubmatch(body)
	if len(m) != 2 {
		return "", fmt.Errorf("response has no internal IP")
	}
	ip := m[1]
	if net.ParseIP(ip).To4() == nil {
		return "", fmt.Errorf("invalid internal IP %q", ip)
	}
	return ip, nil
}

func parseCloudflareTraceIP(body string) (string, error) {
	for _, line := range strings.Split(body, "\n") {
		key, val, ok := strings.Cut(strings.TrimSpace(line), "=")
		if ok && key == "ip" {
			ip := strings.TrimSpace(val)
			if net.ParseIP(ip).To4() == nil {
				return "", fmt.Errorf("invalid trace IP %q", ip)
			}
			return ip, nil
		}
	}
	return "", fmt.Errorf("trace response has no ip field")
}

func fetchE2EDNSJSON(ctx context.Context, listenAddr string) error {
	dialer := &net.Dialer{Timeout: 10 * time.Second, KeepAlive: 30 * time.Second}
	transport := &http.Transport{
		DialContext: func(ctx context.Context, networkName, addr string) (net.Conn, error) {
			return dialer.DialContext(ctx, "tcp4", listenAddr)
		},
		TLSClientConfig:       testTLSConfig("one.one.one.one"),
		TLSHandshakeTimeout:   10 * time.Second,
		ResponseHeaderTimeout: 15 * time.Second,
		ForceAttemptHTTP2:     false,
	}
	defer transport.CloseIdleConnections()

	client := &http.Client{Transport: transport, Timeout: 30 * time.Second}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, "https://one.one.one.one/dns-query?name=one.one.one.one&type=A", nil)
	if err != nil {
		return err
	}
	req.Header.Set("accept", "application/dns-json")
	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return err
	}
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("unexpected HTTP status %s", resp.Status)
	}
	var payload any
	if err := json.Unmarshal(body, &payload); err != nil {
		return fmt.Errorf("invalid JSON payload: %w", err)
	}
	return nil
}

var (
	testRootCAsOnce sync.Once
	testRootCAs     *x509.CertPool
)

func testTLSConfig(serverName string) *tls.Config {
	return &tls.Config{
		ServerName: serverName,
		RootCAs:    methodTestRootCAs(),
	}
}

func methodTestRootCAs() *x509.CertPool {
	testRootCAsOnce.Do(func() {
		pool, err := x509.SystemCertPool()
		systemOK := err == nil && pool != nil
		if !systemOK {
			pool = x509.NewCertPool()
		}

		appended := appendCertFiles(pool, caBundleCandidates())
		appended = appendCertDirs(pool, caDirCandidates()) || appended
		if systemOK || appended {
			testRootCAs = pool
		}
	})
	return testRootCAs
}

func caBundleCandidates() []string {
	return []string{
		os.Getenv("SSL_CERT_FILE"),
		"/data/data/com.termux/files/usr/etc/tls/cert.pem",
		"/data/data/com.termux/files/usr/etc/ssl/cert.pem",
		"/etc/ssl/certs/ca-certificates.crt",
		"/etc/pki/tls/certs/ca-bundle.crt",
		"/etc/ssl/ca-bundle.pem",
		"/etc/pki/tls/cacert.pem",
		"/etc/pki/ca-trust/extracted/pem/tls-ca-bundle.pem",
	}
}

func caDirCandidates() []string {
	return []string{
		os.Getenv("SSL_CERT_DIR"),
		"/data/data/com.termux/files/usr/etc/tls/certs",
		"/data/data/com.termux/files/usr/etc/ssl/certs",
		"/etc/ssl/certs",
		"/system/etc/security/cacerts",
	}
}

func appendCertFiles(pool *x509.CertPool, paths []string) bool {
	appended := false
	for _, path := range paths {
		if appendCertFile(pool, path) {
			appended = true
		}
	}
	return appended
}

func appendCertDirs(pool *x509.CertPool, dirs []string) bool {
	appended := false
	for _, dir := range dirs {
		if strings.TrimSpace(dir) == "" {
			continue
		}
		entries, err := os.ReadDir(dir)
		if err != nil {
			continue
		}
		for _, entry := range entries {
			if entry.IsDir() {
				continue
			}
			if appendCertFile(pool, filepath.Join(dir, entry.Name())) {
				appended = true
			}
		}
	}
	return appended
}

func appendCertFile(pool *x509.CertPool, path string) bool {
	if strings.TrimSpace(path) == "" {
		return false
	}
	pem, err := os.ReadFile(path)
	if err != nil {
		return false
	}
	return pool.AppendCertsFromPEM(pem)
}
