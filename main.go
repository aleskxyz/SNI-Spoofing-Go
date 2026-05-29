// TLS proxy: fake ClientHello injection (wrong-seq) + optional real CH fragmentation. IPv4 only; needs admin/root.
package main

import (
	"bufio"
	"context"
	"flag"
	"fmt"
	"log"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"sni-spoofing-go/config"
	"sni-spoofing-go/injection"
	"sni-spoofing-go/network"
	"sni-spoofing-go/packet"
	"sni-spoofing-go/privilege"
	"sni-spoofing-go/proxy"
)

func defaultTestListenAddr() string {
	return proxy.DefaultTestListenAddr()
}

func effectiveListenAddr(listen string, testMethod bool) string {
	if testMethod {
		return defaultTestListenAddr()
	}
	return listen
}

func usage() {
	exe := os.Args[0]
	w := os.Stderr
	fmt.Fprintf(w, "SNI-Spoofing — fake TLS ClientHello (SNI) injection proxy. IPv4 only; run as Administrator / root.\n\n")
	fmt.Fprintf(w, "Usage:\n")
	fmt.Fprintf(w, "  %s -listen <addr> -connect <addr> [options]\n\n", exe)
	fmt.Fprintf(w, "Required:\n")
	fmt.Fprintf(w, "  -listen <host:port>   listen address (host optional, e.g. :8080)\n")
	fmt.Fprintf(w, "  -connect <host:port>  upstream; hostname (SNI from host) or IPv4 (needs -fake-sni)\n\n")
	fmt.Fprintf(w, "Optional:\n")
	fmt.Fprintf(w, "  -config <path>       INI config file (default: ./config.ini if it exists)\n")
	fmt.Fprintf(w, "  -test              run e2e method test matrix for the selected -connect/-fake-sni pair, then exit\n")
	fmt.Fprintf(w, "  -fake-sni <hostname>  SNI in the injected ClientHello (overrides -connect hostname)\n")
	fmt.Fprintf(w, "  -fake-repeat <n>      fake ClientHello injections before real traffic (default 1)\n")
	fmt.Fprintf(w, "  -fake-delay          delay after fake injection (default 2ms)\n")
	fmt.Fprintf(w, "  -ack-timeout         max wait for server ACK after fake injection (default 2s)\n")
	fmt.Fprintf(w, "  -utls <name>         TLS fingerprint (default: firefox); use \"none\" for legacy template; list below\n")
	fmt.Fprintf(w, "  -enable-fragment     fragment real ClientHello (prefix / SNI chunks / suffix); default false\n")
	fmt.Fprintf(w, "  -fragment-delay      delay between TCP segments when ClientHello is split (default 500ms)\n")
	fmt.Fprintf(w, "  -sni-chunk            SNI bytes per TCP write after prefix (default 3; 0 = whole name in one write)\n")
	fmt.Fprintf(w, "\n")
	fmt.Fprintf(w, "Examples:\n")
	fmt.Fprintf(w, "  %s -listen 127.0.0.1:8080 -connect example.com:443\n", exe)
	fmt.Fprintf(w, "  %s -listen 127.0.0.1:8080 -connect 198.51.100.2:443 -fake-sni allowed.example.com\n\n", exe)
	fmt.Fprintf(w, "Valid -utls names:\n\n")
	fmt.Fprintf(w, "%s", packet.UTLSHelpGroupedCSV())
	fmt.Fprintf(w, "\nDefault when -utls is omitted: %s. Use -utls none for the legacy fixed ClientHello.\n\n", packet.DefaultUTLSSummary())
	fmt.Fprintf(w, "Options:\n")
	flag.PrintDefaults()
}

func main() {
	fileOpts, configPath, err := loadInitialFileOptions(os.Args[1:])
	if err != nil {
		log.Fatal("Invalid config file: ", err)
	}

	flag.Usage = usage
	var optListen, optConnect, optFakeSNI, optUTLS string
	var enableFragment bool
	var injectorMode string
	var fragmentDelay time.Duration
	var sniChunk int
	var fakeRepeat int
	var ackTimeout time.Duration
	var fakeDelay time.Duration
	var testMode bool
	applyOptionDefaults(fileOpts, &optListen, &optConnect, &optFakeSNI, &optUTLS, &injectorMode, &fakeRepeat, &fakeDelay, &ackTimeout, &enableFragment, &fragmentDelay, &sniChunk)

	flag.StringVar(&configPath, "config", configPath, "INI config file (default: ./config.ini if available)")
	flag.BoolVar(&testMode, "test", false, "run e2e method test matrix for the selected upstream/decoy SNI pair, then exit")
	flag.StringVar(&injectorMode, "injector", string(proxy.DefaultInjectorMode()), "packet injector backend: active or passive")
	flag.StringVar(&optListen, "listen", optListen, "listen address host:port (required)")
	flag.StringVar(&optConnect, "connect", optConnect, "upstream host:port (required)")
	flag.StringVar(&optFakeSNI, "fake-sni", optFakeSNI, "injected ClientHello SNI (optional if -connect uses a hostname)")
	flag.IntVar(&fakeRepeat, "fake-repeat", fakeRepeat, "number of wrong-seq fake ClientHello injections before real traffic")
	flag.DurationVar(&fakeDelay, "fake-delay", fakeDelay, "delay after fake injection (0 = none)")
	flag.StringVar(&optUTLS, "utls", optUTLS, "TLS fingerprint preset (see usage above; e.g. chrome_120, firefox, none)")
	flag.BoolVar(&enableFragment, "enable-fragment", enableFragment, "after fake SNI, read real ClientHello: send prefix, then SNI chunks, then suffix")
	flag.DurationVar(&fragmentDelay, "fragment-delay", fragmentDelay, "delay between TCP segments when fake or real ClientHello is split (MSS / chunking)")
	flag.IntVar(&sniChunk, "sni-chunk", sniChunk, "SNI hostname bytes per TCP write (0 = entire hostname in one write)")
	flag.DurationVar(&ackTimeout, "ack-timeout", ackTimeout, "timeout waiting for server ACK after fake injection")
	flag.Parse()

	fakeSNIArg := strings.TrimSpace(optFakeSNI)

	args := flag.Args()
	if len(args) > 0 {
		fmt.Fprintf(os.Stderr, "error: unexpected arguments: %q\n", args)
		fmt.Fprintln(os.Stderr)
		usage()
		os.Exit(2)
	}
	requirePrivilegedOrExit()
	if testMode {
		optListen = effectiveListenAddr(optListen, true)
	}
	if strings.TrimSpace(optListen) == "" || strings.TrimSpace(optConnect) == "" {
		log.Fatal("required config: -listen and -connect (or listen/connect in config.ini)")
	}
	if fakeRepeat < 1 {
		log.Fatal("-fake-repeat must be at least 1")
	}
	if sniChunk < 0 {
		log.Fatal("-sni-chunk must be >= 0 (0 = whole hostname in one write)")
	}
	if ackTimeout <= 0 {
		log.Fatal("-ack-timeout must be positive (e.g. 2s, 5s, 1m)")
	}
	if fakeDelay < 0 {
		log.Fatal("-fake-delay must be >= 0")
	}
	if fragmentDelay < 0 {
		log.Fatal("-fragment-delay must be >= 0")
	}
	injector, err := proxy.ParseInjectorMode(injectorMode)
	if err != nil {
		log.Fatal(err)
	}
	var cfg *config.Config
	if testMode {
		cfg, err = config.ConnectFromCLIAllowListenPortZero(optListen, optConnect, fakeSNIArg)
	} else {
		cfg, err = config.ConnectFromCLI(optListen, optConnect, fakeSNIArg)
	}
	if err != nil {
		log.Fatal("Invalid configuration: ", err)
	}

	if strings.TrimSpace(optUTLS) != "" {
		cfg.UTLSClientHello = optUTLS
	}
	if !testMode && !packet.IsLegacyUTLS(cfg.UTLSClientHello) {
		if _, err := packet.ParseClientHelloID(cfg.UTLSClientHello); err != nil {
			log.Fatal("Invalid -utls: ", err)
		}
	}

	if !network.IsIPv4(cfg.ConnectIP) {
		log.Fatalf("upstream must resolve to IPv4 (IPv6 is not supported): %q", cfg.ConnectIP)
	}
	if len(cfg.ConnectIPv4s) == 0 {
		log.Fatal("internal error: no ConnectIPv4s after resolve")
	}
	if cfg.ListenHost != "" && !network.IsIPv4(cfg.ListenHost) {
		log.Fatalf("LISTEN host must be IPv4 or empty (IPv6 is not supported): %q", cfg.ListenHost)
	}

	opts := proxy.Options{
		FakeRepeat:     fakeRepeat,
		FakeDelay:      fakeDelay,
		EnableFragment: enableFragment,
		FragmentDelay:  fragmentDelay,
		SNIChunk:       sniChunk,
		AckTimeout:     ackTimeout,
		Injector:       injector,
	}
	if testMode {
		if err := runMethodMatrixCLI(cfg, injector); err != nil {
			fmt.Fprintln(os.Stderr, err)
			waitForExitKey()
			os.Exit(1)
		}
		waitForExitKey()
		return
	}

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()
	go func() {
		<-ctx.Done()
		log.Print("shutdown")
	}()
	if err := proxy.Run(ctx, cfg, opts, nil); err != nil {
		log.Fatal(err)
	}
}

// runMethodMatrixCLI prints the same preflight banner + table the pre-refactor
// CLI used, while delegating execution to proxy.RunMethodMatrix.
func runMethodMatrixCLI(cfg *config.Config, injector injection.InjectorMode) error {
	fmt.Println("Preflight")
	pre := proxy.CheckMethodPreconditions(cfg.ConnectIP, cfg.FakeSNI)
	if pre.LookupErr != nil {
		return pre.LookupErr
	}
	fmt.Printf("  external IP: %s\n", pre.ExternalIP)
	if pre.InternalIP == "" {
		fmt.Println("  internal IP: unavailable")
		fmt.Println("  warning: internal IP unavailable; running e2e matrix anyway")
	} else {
		fmt.Printf("  internal IP: %s\n", pre.InternalIP)
		if pre.Matched {
			fmt.Println("  result: IPs match; running e2e matrix")
		} else {
			return pre.MatchErr
		}
	}
	fmt.Println()
	fmt.Println("Matrix")
	fmt.Printf("%-8s %-11s %-8s %-6s\n", "UTLS", "Fake-Repeat", "Fragment", "Result")

	progress := func(r proxy.MatrixResult) {
		label := "PASS"
		if !r.Pass {
			label = "FAIL"
		}
		fmt.Printf("%-8s %-11d %-8s %-6s\n", r.Case.UTLS, r.Case.FakeRepeat, proxy.FragmentLabel(r.Case.EnableFragment), label)
	}

	results, err := proxy.RunMethodMatrix(context.Background(), cfg, injector, progress)
	if err != nil {
		return err
	}
	failed := 0
	for _, r := range results {
		if !r.Pass {
			failed++
		}
	}
	if failed > 0 {
		return fmt.Errorf("method matrix: %d/%d failed", failed, len(results))
	}
	fmt.Printf("\nAll %d cases passed.\n", len(results))
	return nil
}

func waitForExitKey() {
	fmt.Fprint(os.Stderr, "\nPress Enter to exit...")
	_, _ = bufio.NewReader(os.Stdin).ReadBytes('\n')
	fmt.Fprintln(os.Stderr)
}

func requirePrivilegedOrExit() {
	ok, err := privilege.IsElevated()
	if err == nil && ok {
		return
	}
	if err != nil {
		fmt.Fprintf(os.Stderr, "Privilege check failed: %v\n", err)
	}
	fmt.Fprintf(os.Stderr, "This program needs elevated privileges; please %s.\n", privilege.Hint())
	waitForExitKey()
	os.Exit(1)
}

func loadInitialFileOptions(args []string) (config.FileOptions, string, error) {
	path, provided, err := configPathFromArgs(args)
	if err != nil {
		return config.FileOptions{}, "", err
	}
	if provided {
		opts, err := config.LoadFileOptions(path)
		return opts, path, err
	}
	const defaultPath = "config.ini"
	if _, err := os.Stat(defaultPath); err == nil {
		opts, err := config.LoadFileOptions(defaultPath)
		return opts, defaultPath, err
	} else if !os.IsNotExist(err) {
		return config.FileOptions{}, "", err
	}
	return config.FileOptions{}, "", nil
}

func configPathFromArgs(args []string) (path string, provided bool, err error) {
	for i := 0; i < len(args); i++ {
		arg := args[i]
		if arg == "-config" || arg == "--config" {
			if i+1 >= len(args) {
				return "", true, fmt.Errorf("-config requires a path")
			}
			return args[i+1], true, nil
		}
		if strings.HasPrefix(arg, "-config=") {
			return strings.TrimPrefix(arg, "-config="), true, nil
		}
		if strings.HasPrefix(arg, "--config=") {
			return strings.TrimPrefix(arg, "--config="), true, nil
		}
	}
	return "", false, nil
}

func applyOptionDefaults(
	fileOpts config.FileOptions,
	optListen, optConnect, optFakeSNI, optUTLS, injectorMode *string,
	fakeRepeat *int,
	fakeDelay, ackTimeout *time.Duration,
	enableFragment *bool,
	fragmentDelay *time.Duration,
	sniChunk *int,
) {
	*fakeRepeat = 1
	*fakeDelay = 2 * time.Millisecond
	*ackTimeout = 2 * time.Second
	*fragmentDelay = 500 * time.Millisecond
	*sniChunk = packet.DefaultSNIChunkBytes

	if fileOpts.Has("listen") {
		*optListen = fileOpts.Listen
	}
	if fileOpts.Has("connect") {
		*optConnect = fileOpts.Connect
	}
	if fileOpts.Has("fake-sni") {
		*optFakeSNI = fileOpts.FakeSNI
	}
	if fileOpts.Has("fake-repeat") {
		*fakeRepeat = fileOpts.FakeRepeat
	}
	if fileOpts.Has("fake-delay") {
		*fakeDelay = fileOpts.FakeDelay
	}
	if fileOpts.Has("ack-timeout") {
		*ackTimeout = fileOpts.AckTimeout
	}
	if fileOpts.Has("injector") {
		*injectorMode = fileOpts.Injector
	}
	if fileOpts.Has("utls") {
		*optUTLS = fileOpts.UTLS
	}
	if fileOpts.Has("enable-fragment") {
		*enableFragment = fileOpts.EnableFragment
	}
	if fileOpts.Has("fragment-delay") {
		*fragmentDelay = fileOpts.FragmentDelay
	}
	if fileOpts.Has("sni-chunk") {
		*sniChunk = fileOpts.SNIChunk
	}
}
