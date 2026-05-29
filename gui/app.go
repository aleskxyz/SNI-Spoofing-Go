package main

import (
	"context"
	"errors"
	"fmt"
	"log"
	"strings"
	"sync"
	"time"

	"github.com/wailsapp/wails/v2/pkg/runtime"

	"sni-spoofing-go/config"
	"sni-spoofing-go/network"
	"sni-spoofing-go/packet"
	"sni-spoofing-go/privilege"
	"sni-spoofing-go/proxy"
)

// Upper bounds enforced by validateConfig. The CLI doesn't impose these (it
// trusts the operator), but a GUI lets users type "999999999" and end up with
// 11-day timeouts that look like hangs. Caps are generous — pick them so any
// realistic configuration fits comfortably below the limit.
const (
	maxFakeRepeat      = 20
	maxFakeDelayMs     = 10_000 // 10s
	maxAckTimeoutMs    = 60_000 // 60s
	maxFragmentDelayMs = 60_000 // 60s
	maxSNIChunk        = 256
)

// App is the Wails-bound application object. ctx is written exactly once by
// startup() before any binding is invoked (Wails guarantees startup runs before
// any frontend → backend call), and read by goroutines spawned from bindings;
// therefore reads are safe without a lock provided no binding spawns work that
// touches ctx before startup() returns. Treat ctx as effectively final after
// startup; if that invariant ever needs to relax, move reads under a.mu.
type App struct {
	ctx context.Context

	mu           sync.Mutex
	running      bool
	cancelFn     context.CancelFunc
	listenAddr   string
	doneCh       chan struct{}
	testing      bool
	testCancelFn context.CancelFunc
	testDoneCh   chan struct{}
}

type ProxyConfig struct {
	Listen          string `json:"listen"`
	Connect         string `json:"connect"`
	FakeSNI         string `json:"fakeSni"`
	UTLS            string `json:"utls"`
	Injector        string `json:"injector"`
	FakeRepeat      int    `json:"fakeRepeat"`
	FakeDelayMs     int    `json:"fakeDelayMs"`
	AckTimeoutMs    int    `json:"ackTimeoutMs"`
	EnableFragment  bool   `json:"enableFragment"`
	FragmentDelayMs int    `json:"fragmentDelayMs"`
	SNIChunk        int    `json:"sniChunk"`
}

type ProxyStatus struct {
	Running    bool   `json:"running"`
	Testing    bool   `json:"testing"`
	ListenAddr string `json:"listenAddr"`
}

type LogEvent struct {
	Level   string `json:"level"`
	Message string `json:"message"`
}

type TestResult struct {
	UTLS           string `json:"utls"`
	FakeRepeat     int    `json:"fakeRepeat"`
	EnableFragment bool   `json:"enableFragment"`
	Pass           bool   `json:"pass"`
	Error          string `json:"error,omitempty"`
}

type TestSummary struct {
	Preflight TestPreflight `json:"preflight"`
	Results   []TestResult  `json:"results"`
	Passed    int           `json:"passed"`
	Failed    int           `json:"failed"`
}

// TestPreflight reports what CheckMethodPreconditions discovered. Warning is
// set when the matrix can still run but with degraded confidence (e.g. internal
// IP lookup failed). The frontend renders Warning in the warn color.
type TestPreflight struct {
	ExternalIP string `json:"externalIp"`
	InternalIP string `json:"internalIp"`
	Matched    bool   `json:"matched"`
	Warning    string `json:"warning,omitempty"`
}

func NewApp() *App {
	return &App{}
}

func (a *App) startup(ctx context.Context) {
	a.ctx = ctx
}

func (a *App) shutdown(ctx context.Context) {
	a.mu.Lock()
	cancels := []context.CancelFunc{a.cancelFn, a.testCancelFn}
	a.cancelFn = nil
	a.testCancelFn = nil
	a.mu.Unlock()
	for _, c := range cancels {
		if c != nil {
			c()
		}
	}
}

// GetDefaultConfig fills the form with a known-good "open and run" config
// matching the README's quick-start example. Unlike the CLI (which requires
// the user to specify -connect / -fake-sni so they think about their target),
// the GUI is aimed at users who may not know what those fields should hold,
// so we pre-populate them with the same values the README walks through and
// let the user override.
func (a *App) GetDefaultConfig() ProxyConfig {
	return ProxyConfig{
		Listen:          "127.0.0.1:40443",
		Connect:         "104.19.229.21:443",
		FakeSNI:         "hcaptcha.com",
		UTLS:            "firefox",
		Injector:        string(proxy.DefaultInjectorMode()),
		FakeRepeat:      1,
		FakeDelayMs:     2,
		AckTimeoutMs:    2000,
		EnableFragment:  false,
		FragmentDelayMs: 500,
		SNIChunk:        3,
	}
}

func (a *App) UTLSPresets() []string {
	return []string{
		"none", "firefox", "chrome", "edge", "safari", "ios", "qq", "360browser",
	}
}

func (a *App) InjectorModes() []string {
	return []string{"active", "passive"}
}

func (a *App) Status() ProxyStatus {
	a.mu.Lock()
	defer a.mu.Unlock()
	return ProxyStatus{
		Running:    a.running,
		Testing:    a.testing,
		ListenAddr: a.listenAddr,
	}
}

// PrivilegeStatus tells the frontend whether the current process has the OS
// privileges to drive the injector, and what the user should do if not. The
// UI surfaces this as a banner so the user isn't surprised when Start fails.
type PrivilegeStatus struct {
	Elevated bool   `json:"elevated"`
	Hint     string `json:"hint"`
	Platform string `json:"platform"`
}

func (a *App) Privileged() PrivilegeStatus {
	ok, _ := privilege.IsElevated()
	return PrivilegeStatus{Elevated: ok, Hint: privilege.Hint(), Platform: privilege.Platform()}
}

// requirePrivilege rejects bindings that would call into the packet injector
// when the process isn't elevated. Returning a clean error keeps the UI
// honest: the user sees "needs Administrator" instead of an opaque WinDivert
// error 5 (ERROR_ACCESS_DENIED) hundreds of ms later.
func requirePrivilege() error {
	ok, err := privilege.IsElevated()
	if err != nil {
		return fmt.Errorf("privilege check failed: %w", err)
	}
	if !ok {
		return fmt.Errorf("this action needs elevated privileges; please %s", privilege.Hint())
	}
	return nil
}

// validateConfig covers the scalar/enum constraints that don't depend on the
// proxy core: lower bounds (no zero/negative timeouts, blank addresses) and
// upper bounds (a GUI lets users type absurd values that look like hangs).
// Address parsing, IPv4 enforcement, hostname resolution, and uTLS preset
// validation happen later via config.ConnectFromCLI and packet.ParseClientHelloID
// so the GUI rejects exactly what the CLI rejects. Errors are returned to
// the caller, not logged here — the frontend surfaces them once via the
// rejected promise.
func validateConfig(cfg ProxyConfig) error {
	if strings.TrimSpace(cfg.Listen) == "" {
		return errors.New("listen address is required")
	}
	if strings.TrimSpace(cfg.Connect) == "" {
		return errors.New("connect address is required")
	}
	if cfg.FakeRepeat < 1 {
		return errors.New("fake-repeat must be at least 1")
	}
	if cfg.FakeRepeat > maxFakeRepeat {
		return fmt.Errorf("fake-repeat must be <= %d", maxFakeRepeat)
	}
	if cfg.SNIChunk < 0 {
		return errors.New("sni-chunk must be >= 0 (0 = whole hostname in one write)")
	}
	if cfg.SNIChunk > maxSNIChunk {
		return fmt.Errorf("sni-chunk must be <= %d bytes", maxSNIChunk)
	}
	if cfg.AckTimeoutMs <= 0 {
		return fmt.Errorf("ack-timeout must be positive (got %dms)", cfg.AckTimeoutMs)
	}
	if cfg.AckTimeoutMs > maxAckTimeoutMs {
		return fmt.Errorf("ack-timeout must be <= %dms", maxAckTimeoutMs)
	}
	if cfg.FakeDelayMs < 0 {
		return errors.New("fake-delay must be >= 0")
	}
	if cfg.FakeDelayMs > maxFakeDelayMs {
		return fmt.Errorf("fake-delay must be <= %dms", maxFakeDelayMs)
	}
	if cfg.FragmentDelayMs < 0 {
		return errors.New("fragment-delay must be >= 0")
	}
	if cfg.FragmentDelayMs > maxFragmentDelayMs {
		return fmt.Errorf("fragment-delay must be <= %dms", maxFragmentDelayMs)
	}
	switch cfg.Injector {
	case "active", "passive":
	default:
		return fmt.Errorf("injector must be 'active' or 'passive', got %q", cfg.Injector)
	}
	return nil
}

// buildProxyArgs runs validation + address parsing + uTLS preset validation
// using the same code paths the CLI exercises. allowPortZero is true for the
// test matrix (which needs a loopback any-port listener) and false for Start
// (which requires the user-specified port).
func buildProxyArgs(cfg ProxyConfig, allowPortZero bool) (*config.Config, proxy.Options, error) {
	if err := validateConfig(cfg); err != nil {
		return nil, proxy.Options{}, err
	}
	injector, err := proxy.ParseInjectorMode(cfg.Injector)
	if err != nil {
		return nil, proxy.Options{}, err
	}
	fakeSNI := strings.TrimSpace(cfg.FakeSNI)
	var pc *config.Config
	if allowPortZero {
		pc, err = config.ConnectFromCLIAllowListenPortZero(cfg.Listen, cfg.Connect, fakeSNI)
	} else {
		pc, err = config.ConnectFromCLI(cfg.Listen, cfg.Connect, fakeSNI)
	}
	if err != nil {
		return nil, proxy.Options{}, fmt.Errorf("invalid configuration: %w", err)
	}
	if strings.TrimSpace(cfg.UTLS) != "" {
		pc.UTLSClientHello = cfg.UTLS
	}
	if !packet.IsLegacyUTLS(pc.UTLSClientHello) {
		if _, err := packet.ParseClientHelloID(pc.UTLSClientHello); err != nil {
			return nil, proxy.Options{}, fmt.Errorf("invalid -utls: %w", err)
		}
	}
	if !network.IsIPv4(pc.ConnectIP) {
		return nil, proxy.Options{}, fmt.Errorf("upstream must resolve to IPv4 (IPv6 is not supported): %q", pc.ConnectIP)
	}
	if len(pc.ConnectIPv4s) == 0 {
		return nil, proxy.Options{}, errors.New("internal error: no ConnectIPv4s after resolve")
	}
	if pc.ListenHost != "" && !network.IsIPv4(pc.ListenHost) {
		return nil, proxy.Options{}, fmt.Errorf("listen host must be IPv4 or empty: %q", pc.ListenHost)
	}
	opts := proxy.Options{
		FakeRepeat:     cfg.FakeRepeat,
		FakeDelay:      time.Duration(cfg.FakeDelayMs) * time.Millisecond,
		EnableFragment: cfg.EnableFragment,
		FragmentDelay:  time.Duration(cfg.FragmentDelayMs) * time.Millisecond,
		SNIChunk:       cfg.SNIChunk,
		AckTimeout:     time.Duration(cfg.AckTimeoutMs) * time.Millisecond,
		Injector:       injector,
	}
	return pc, opts, nil
}

// Start launches the proxy. The mutex check rejects double-start AND
// start-while-testing — a second proxy contending for the same injector
// would fail in confusing ways.
func (a *App) Start(cfg ProxyConfig) error {
	if err := requirePrivilege(); err != nil {
		return err
	}
	pc, opts, err := buildProxyArgs(cfg, false)
	if err != nil {
		return err
	}
	opts.Logger = a.newGuiLogger()

	a.mu.Lock()
	if a.running {
		a.mu.Unlock()
		return errors.New("proxy is already running")
	}
	if a.testing {
		a.mu.Unlock()
		return errors.New("cannot start the proxy while the test matrix is running")
	}
	ctx, cancel := context.WithCancel(a.ctx)
	a.cancelFn = cancel
	a.running = true
	doneCh := make(chan struct{})
	a.doneCh = doneCh
	selfCancel := doneCh // identity token; channels are comparable.
	a.mu.Unlock()

	ready := make(chan proxy.Ready, 1)
	go func() {
		err := proxy.Run(ctx, pc, opts, ready)

		a.mu.Lock()
		// Only clobber live state if no second Start has installed a new
		// doneCh in the meantime — otherwise we'd race the new run.
		if a.doneCh == selfCancel {
			a.running = false
			a.cancelFn = nil
			a.listenAddr = ""
		}
		a.mu.Unlock()
		close(doneCh)

		if err != nil && !errors.Is(err, context.Canceled) {
			a.emitLog("error", fmt.Sprintf("proxy exited: %v", err))
		} else {
			a.emitLog("info", "proxy stopped")
		}
		a.emitStatus(a.Status())
	}()

	startTimer := time.NewTimer(proxy.StartReadyTimeout)
	defer startTimer.Stop()
	// waitGoroutine cancels the run and waits (bounded) for the goroutine
	// to release its injector/listener handle before returning. The
	// matching-selfCancel check in the goroutine means we don't need to
	// also reset a.running here — the goroutine's cleanup will. But we DO
	// need to wait so a second Start doesn't race the still-held
	// WinDivert/nfqueue/BPF handle.
	waitGoroutine := func() {
		cancel()
		t := time.NewTimer(2 * time.Second)
		select {
		case <-doneCh:
		case <-t.C:
		}
		t.Stop()
	}
	select {
	case r := <-ready:
		if r.Err != nil {
			waitGoroutine()
			return fmt.Errorf("proxy start failed: %w", r.Err)
		}
		a.mu.Lock()
		a.listenAddr = r.ListenAddr
		a.mu.Unlock()
		a.emitLog("info", "listening on "+r.ListenAddr)
		a.emitStatus(a.Status())
		return nil
	case <-startTimer.C:
		waitGoroutine()
		return fmt.Errorf("proxy start timed out after %s", proxy.StartReadyTimeout)
	case <-a.ctx.Done():
		waitGoroutine()
		return a.ctx.Err()
	}
}

// Stop cancels whichever long-running operation is in flight — proxy or test
// matrix. Idempotent: silent (debug-level log) when neither is active.
// Stop waits (with a short bounded timeout) for the active goroutine to drain
// so that a back-to-back Stop+Start doesn't race against the still-running
// proxy goroutine's cleanup.
func (a *App) Stop() error {
	a.mu.Lock()
	if !a.running && !a.testing {
		a.mu.Unlock()
		a.emitLog("debug", "stop ignored: nothing is running")
		return nil
	}
	proxyCancel := a.cancelFn
	testCancel := a.testCancelFn
	proxyDone := a.doneCh
	testDone := a.testDoneCh
	a.cancelFn = nil
	a.testCancelFn = nil
	a.mu.Unlock()

	if proxyCancel != nil {
		proxyCancel()
	}
	if testCancel != nil {
		testCancel()
	}
	// Await whichever goroutine was active so the next Start sees clean
	// state. Bound the wait so a slow shutdown can't freeze the UI.
	if proxyDone != nil {
		proxyTimer := time.NewTimer(2 * time.Second)
		select {
		case <-proxyDone:
		case <-proxyTimer.C:
			a.emitLog("warn", "proxy goroutine slow to exit; proceeding")
		}
		proxyTimer.Stop()
	}
	if testDone != nil {
		testTimer := time.NewTimer(2 * time.Second)
		select {
		case <-testDone:
		case <-testTimer.C:
			a.emitLog("warn", "test goroutine slow to exit; proceeding")
		}
		testTimer.Stop()
	}
	// The proxy goroutine flips running=false; the RunTest defer flips
	// testing=false. Both emit their own status events so the UI sees a
	// single source of truth without duplication here.
	return nil
}

// RunTest runs proxy.CheckMethodPreconditions + proxy.RunMethodMatrix against
// the supplied config. The matrix can be cancelled mid-flight via Stop.
func (a *App) RunTest(cfg ProxyConfig) (TestSummary, error) {
	if err := requirePrivilege(); err != nil {
		return TestSummary{}, err
	}
	// Test matrix needs ListenPort=0 (auto-pick); user's chosen port may be
	// unavailable or already in use.
	testCfg := cfg
	testCfg.Listen = proxy.DefaultTestListenAddr()

	pc, opts, err := buildProxyArgs(testCfg, true)
	if err != nil {
		return TestSummary{}, err
	}

	a.mu.Lock()
	if a.running {
		a.mu.Unlock()
		return TestSummary{}, errors.New("stop the proxy before running the test matrix")
	}
	if a.testing {
		a.mu.Unlock()
		return TestSummary{}, errors.New("a test matrix is already running")
	}
	testCtx, cancel := context.WithCancel(a.ctx)
	a.testing = true
	a.testCancelFn = cancel
	a.testDoneCh = make(chan struct{})
	testDone := a.testDoneCh
	a.mu.Unlock()

	a.emitStatus(a.Status())
	defer func() {
		a.mu.Lock()
		a.testing = false
		a.testCancelFn = nil
		a.mu.Unlock()
		cancel()
		a.emitStatus(a.Status())
		close(testDone)
	}()

	a.emitLog("info", "running preflight…")
	pre := proxy.CheckMethodPreconditions(pc.ConnectIP, pc.FakeSNI)
	summary := TestSummary{
		Preflight: TestPreflight{
			ExternalIP: pre.ExternalIP,
			InternalIP: pre.InternalIP,
			Matched:    pre.Matched,
		},
	}
	if pre.LookupErr != nil {
		return summary, pre.LookupErr
	}
	if pre.InternalIP == "" {
		summary.Preflight.Warning = "internal IP unavailable; running matrix anyway"
		a.emitLog("warn", summary.Preflight.Warning)
	} else if !pre.Matched {
		return summary, pre.MatchErr
	} else {
		a.emitLog("info", fmt.Sprintf("preflight ok (external=%s internal=%s)", pre.ExternalIP, pre.InternalIP))
	}

	progress := func(r proxy.MatrixResult) {
		row := TestResult{
			UTLS:           r.Case.UTLS,
			FakeRepeat:     r.Case.FakeRepeat,
			EnableFragment: r.Case.EnableFragment,
			Pass:           r.Pass,
		}
		if r.Err != nil {
			row.Error = r.Err.Error()
		}
		summary.Results = append(summary.Results, row)
		a.emitTestResult(row)
		if r.Pass {
			summary.Passed++
			a.emitLog("info", fmt.Sprintf("  PASS  utls=%s repeat=%d fragment=%s", r.Case.UTLS, r.Case.FakeRepeat, proxy.FragmentLabel(r.Case.EnableFragment)))
		} else {
			summary.Failed++
			msg := ""
			if r.Err != nil {
				msg = ": " + r.Err.Error()
			}
			a.emitLog("warn", fmt.Sprintf("  FAIL  utls=%s repeat=%d fragment=%s%s", r.Case.UTLS, r.Case.FakeRepeat, proxy.FragmentLabel(r.Case.EnableFragment), msg))
		}
	}

	if _, err := proxy.RunMethodMatrix(testCtx, pc, opts.Injector, progress); err != nil {
		if errors.Is(err, context.Canceled) {
			a.emitLog("warn", "test matrix cancelled")
			return summary, err
		}
		return summary, err
	}
	a.emitLog("info", fmt.Sprintf("matrix done: %d passed / %d failed", summary.Passed, summary.Failed))
	return summary, nil
}

func (a *App) emitLog(level, message string) {
	if a.ctx == nil {
		return
	}
	runtime.EventsEmit(a.ctx, "log", LogEvent{Level: level, Message: message})
}

func (a *App) emitStatus(s ProxyStatus) {
	if a.ctx == nil {
		return
	}
	runtime.EventsEmit(a.ctx, "status", s)
}

func (a *App) emitTestResult(r TestResult) {
	if a.ctx == nil {
		return
	}
	runtime.EventsEmit(a.ctx, "test_result", r)
}

// newGuiLogger returns a *log.Logger that fans each line out as a Wails
// "log" event so the proxy's existing logger.Printf calls flow straight
// into the UI's log panel without changing the proxy code.
func (a *App) newGuiLogger() *log.Logger {
	return log.New(&guiLogWriter{app: a}, "", 0)
}

type guiLogWriter struct {
	app *App
}

func (w *guiLogWriter) Write(p []byte) (int, error) {
	// log.Logger always calls Write once per line and includes a trailing
	// newline; trim it so the UI doesn't render a blank row.
	msg := strings.TrimRight(string(p), "\r\n")
	if msg == "" {
		return len(p), nil
	}
	level := "info"
	for _, p := range []struct{ token, lvl string }{
		{"error: ", "error"},
		{"warn: ", "warn"},
		{"debug: ", "debug"},
	} {
		if strings.HasPrefix(msg, p.token) {
			level = p.lvl
			msg = strings.TrimPrefix(msg, p.token)
			break
		}
	}
	w.app.emitLog(level, msg)
	return len(p), nil
}
