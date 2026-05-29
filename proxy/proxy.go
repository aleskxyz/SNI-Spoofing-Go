// Package proxy is the SNI-spoofing TCP proxy core, shared between the CLI
// (root main package) and the Wails GUI (gui/). It owns the accept loop,
// per-connection handling, fake ClientHello injection, and fragmentation
// logic; callers pass in a Config + Options and an optional *log.Logger
// for output capture.
package proxy

import (
	"context"
	"fmt"
	"io"
	"log"
	"net"
	"strconv"
	"time"

	"sni-spoofing-go/config"
	"sni-spoofing-go/injection"
	"sni-spoofing-go/network"
	"sni-spoofing-go/packet"
)

const firstClientHelloTimeout = 10 * time.Second

const StartReadyTimeout = 15 * time.Second

// Options controls one proxy run. Zero values are fine for booleans; the
// caller must pick sensible defaults for durations and counts (see the CLI's
// applyOptionDefaults for the source of truth).
type Options struct {
	FakeRepeat     int
	FakeDelay      time.Duration
	EnableFragment bool
	FragmentDelay  time.Duration
	SNIChunk       int
	AckTimeout     time.Duration
	Quiet          bool
	Injector       injection.InjectorMode

	// Logger receives info/error lines. Nil falls back to log.Default(),
	// which the CLI relies on. The GUI passes a logger backed by a writer
	// that fans each line out as a Wails event.
	Logger *log.Logger
}

func (o *Options) logger() *log.Logger {
	if o.Logger != nil {
		return o.Logger
	}
	return log.Default()
}

// Ready is sent on the ready channel exactly once when the listener is up,
// or with err set when start-up failed. The CLI ignores it; the method matrix
// uses it to know when to start firing test requests.
type Ready struct {
	ListenAddr string
	Err        error
}

// Run is the proxy's accept loop. It blocks until ctx is cancelled or a
// fatal injector error occurs. ready (if non-nil) receives one Ready message
// once the listener is bound (or immediately on a start-up error).
func Run(ctx context.Context, cfg *config.Config, opts Options, ready chan<- Ready) error {
	logger := opts.logger()

	interfaceIPv4 := network.GetDefaultInterfaceIPv4(cfg.ConnectIP)
	if interfaceIPv4 == "" {
		err := fmt.Errorf("failed to detect local interface IPv4 address")
		if ready != nil {
			ready <- Ready{Err: err}
		}
		return err
	}
	if !opts.Quiet {
		logger.Printf("iface: %s", interfaceIPv4)
	}

	fakeInjector, err := injection.NewFakeTcpInjector(interfaceIPv4, cfg.ConnectIPv4s, uint16(cfg.ConnectPort), opts.Injector)
	if err != nil {
		wrapped := fmt.Errorf("failed to create injector: %w", err)
		if ready != nil {
			ready <- Ready{Err: wrapped}
		}
		return wrapped
	}
	defer fakeInjector.Close()

	injectorErr := make(chan error, 1)
	go func() {
		if err := fakeInjector.Start(); err != nil {
			injectorErr <- err
		}
	}()
	if err := fakeInjector.WaitInjectorReady(); err != nil {
		if ready != nil {
			ready <- Ready{Err: err}
		}
		return fmt.Errorf("injector: %w", err)
	}

	listenAddr := net.JoinHostPort(cfg.ListenHost, strconv.Itoa(cfg.ListenPort))
	listener, err := net.Listen("tcp4", listenAddr)
	if err != nil {
		if ready != nil {
			ready <- Ready{Err: err}
		}
		return fmt.Errorf("failed to listen: %w", err)
	}
	defer listener.Close()
	go func() {
		<-ctx.Done()
		_ = listener.Close()
		fakeInjector.Close()
	}()

	if !opts.Quiet {
		logger.Printf("listen: %s", listener.Addr().String())
	}
	if ready != nil {
		ready <- Ready{ListenAddr: listener.Addr().String()}
	}

	for {
		incomingSock, err := listener.Accept()
		if err != nil {
			if ctx.Err() != nil {
				return nil
			}
			select {
			case err := <-injectorErr:
				return fmt.Errorf("injector: %w", err)
			default:
			}
			if !opts.Quiet {
				logger.Printf("error: accept error: %v", err)
			}
			continue
		}

		if tc, ok := incomingSock.(*net.TCPConn); ok {
			tc.SetKeepAlive(true)
			tc.SetKeepAlivePeriod(11 * time.Second)
		}

		go handleConnection(incomingSock, cfg, interfaceIPv4, cfg.FakeSNI, fakeInjector, opts)
	}
}

func handleConnection(
	incomingSock net.Conn,
	cfg *config.Config,
	interfaceIPv4 string,
	fakeSNI string,
	fakeInjector injection.TCPInjector,
	opts Options,
) {
	logger := opts.logger()
	defer func() {
		if r := recover(); r != nil {
			if !opts.Quiet {
				logger.Printf("error: panic in handle: %v", r)
			}
		}
	}()

	fakeData, err := buildFakeClientHello(fakeSNI, cfg.UTLSClientHello)
	if err != nil {
		if !opts.Quiet {
			logger.Printf("error: ClientHello build: %v", err)
		}
		incomingSock.Close()
		return
	}

	outgoingSock, conn, _, err := dialOutgoing(
		interfaceIPv4, cfg.ConnectIP, cfg.ConnectPort,
		fakeData, "wrong_seq", opts.FakeRepeat, opts.FakeDelay, opts.FragmentDelay, incomingSock, fakeInjector,
	)
	if err != nil {
		if !opts.Quiet {
			logger.Printf("error: failed to connect to %s:%d: %v", cfg.ConnectIP, cfg.ConnectPort, err)
		}
		incomingSock.Close()
		return
	}

	conn.Mu.Lock()
	conn.Sock = outgoingSock
	conn.Mu.Unlock()

	if tc, ok := outgoingSock.(*net.TCPConn); ok {
		tc.SetKeepAlive(true)
		tc.SetKeepAlivePeriod(11 * time.Second)
	}

	timer := time.NewTimer(opts.AckTimeout)
	defer timer.Stop()
	select {
	case msg := <-conn.T2aChan:
		if msg == "unexpected_close" {
			if !opts.Quiet {
				logger.Printf("warn: proxy: injector aborted handshake")
			}
			stopMonitoring(fakeInjector, conn)
			closePair(outgoingSock, incomingSock)
			return
		}
		if msg != "fake_data_ack_recv" {
			if !opts.Quiet {
				logger.Printf("warn: unexpected t2a msg: %q", msg)
			}
			stopMonitoring(fakeInjector, conn)
			closePair(outgoingSock, incomingSock)
			return
		}
	case <-timer.C:
		if !opts.Quiet {
			logger.Printf("warn: proxy: ACK timeout after %v", opts.AckTimeout)
		}
		stopMonitoring(fakeInjector, conn)
		closePair(outgoingSock, incomingSock)
		return
	}

	stopMonitoring(fakeInjector, conn)

	if opts.FakeDelay > 0 {
		time.Sleep(opts.FakeDelay)
	}

	if opts.EnableFragment {
		if err := forwardFragmentedClientHello(incomingSock, outgoingSock, opts.FragmentDelay, opts.SNIChunk, false, !opts.Quiet, logger); err != nil {
			if !opts.Quiet {
				logger.Printf("error: ClientHello fragment: %v", err)
			}
			closePair(outgoingSock, incomingSock)
			return
		}
	}

	done := make(chan struct{}, 2)
	go func() {
		defer func() { done <- struct{}{} }()
		relay(outgoingSock, incomingSock)
	}()
	go func() {
		defer func() { done <- struct{}{} }()
		relay(incomingSock, outgoingSock)
	}()

	<-done
	closePair(outgoingSock, incomingSock)
	<-done
}

func buildFakeClientHello(fakeSNI, utlsName string) ([]byte, error) {
	if packet.IsLegacyUTLS(utlsName) {
		return packet.BuildLegacyClientHelloRecord(fakeSNI)
	}
	clientHelloID, err := packet.ParseClientHelloID(utlsName)
	if err != nil {
		return nil, err
	}
	return packet.BuildClientHelloRecord(fakeSNI, clientHelloID)
}

func forwardFragmentedClientHello(incoming, outgoing net.Conn, delay time.Duration, sniChunkBytes int, logEachFragment, logSummary bool, logger *log.Logger) error {
	if err := incoming.SetReadDeadline(time.Now().Add(firstClientHelloTimeout)); err != nil {
		return err
	}
	rec, err := packet.ReadFirstTLSRecord(incoming)
	_ = incoming.SetReadDeadline(time.Time{})
	if err != nil {
		return err
	}
	frags := packet.SplitClientHelloRecord(rec, sniChunkBytes)
	if logSummary {
		logger.Printf("fragment: %d write(s), sni-chunk=%d, delay=%v", nonEmptyFragments(frags), sniChunkBytes, delay)
	}
	var tcpFrag *net.TCPConn
	if tc, ok := outgoing.(*net.TCPConn); ok {
		tcpFrag = tc
	}
	return packet.WriteClientHelloFragments(outgoing, frags, delay, tcpFrag, logEachFragment)
}

func nonEmptyFragments(frags [][]byte) int {
	n := 0
	for _, frag := range frags {
		if len(frag) > 0 {
			n++
		}
	}
	return n
}

func relay(dst, src net.Conn) {
	const bufSize = 65575
	buf := make([]byte, bufSize)
	_, _ = io.CopyBuffer(dst, src, buf)
}

func stopMonitoring(fakeInjector injection.TCPInjector, conn *injection.FakeInjectiveConnection) {
	conn.Mu.Lock()
	conn.Monitor = false
	conn.Mu.Unlock()
	fakeInjector.UnregisterConn(conn)
}

func closePair(a, b net.Conn) {
	a.Close()
	b.Close()
}
