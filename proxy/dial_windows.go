//go:build windows

package proxy

import (
	"fmt"
	"net"
	"os"
	"syscall"
	"time"

	"sni-spoofing-go/injection"
)

// dialOutgoing opens the upstream TCP connection without net.Dialer.Control.
// Using Control + syscall.Bind inside the standard dial path still produced
// "bind: An invalid argument was supplied" on some Windows setups; binding via
// the same syscalls outside Dial avoids that interaction.
func dialOutgoing(
	interfaceIPv4, connectIP string, connectPort int,
	fakeData []byte, bypassMethod string,
	fakeRepeat int,
	fakeDelay, fragmentDelay time.Duration,
	incomingSock net.Conn,
	fakeInjector injection.TCPInjector,
) (outgoingSock net.Conn, conn *injection.FakeInjectiveConnection, srcPort uint16, err error) {

	if net.ParseIP(interfaceIPv4).To4() == nil {
		return nil, nil, 0, fmt.Errorf("local interface IP is not IPv4: %q", interfaceIPv4)
	}
	rIP := net.ParseIP(connectIP).To4()
	if rIP == nil {
		return nil, nil, 0, fmt.Errorf("connect IP is not IPv4: %q", connectIP)
	}

	fd, e := syscall.Socket(syscall.AF_INET, syscall.SOCK_STREAM, syscall.IPPROTO_TCP)
	if e != nil {
		return nil, nil, 0, e
	}
	h := syscall.Handle(fd)

	closeSock := func() { _ = syscall.Closesocket(h) }

	if e = syscall.SetsockoptInt(h, syscall.SOL_SOCKET, syscall.SO_KEEPALIVE, 1); e != nil {
		closeSock()
		return nil, nil, 0, e
	}

	bindAddr := &syscall.SockaddrInet4{Port: 0, Addr: [4]byte{0, 0, 0, 0}}
	if e = syscall.Bind(h, bindAddr); e != nil {
		closeSock()
		return nil, nil, 0, e
	}

	lsa, e := syscall.Getsockname(h)
	if e != nil {
		closeSock()
		return nil, nil, 0, e
	}
	switch la := lsa.(type) {
	case *syscall.SockaddrInet4:
		srcPort = uint16(la.Port)
	default:
		closeSock()
		return nil, nil, 0, fmt.Errorf("getsockname: unexpected address type %T", lsa)
	}

	conn = injection.NewFakeInjectiveConnection(
		nil, interfaceIPv4, connectIP, srcPort, uint16(connectPort),
		fakeData, bypassMethod, incomingSock, fakeRepeat, fakeDelay, fragmentDelay,
	)
	fakeInjector.RegisterConn(conn)

	raddr := &syscall.SockaddrInet4{
		Port: connectPort,
	}
	copy(raddr.Addr[:], rIP)

	if e = syscall.Connect(h, raddr); e != nil {
		conn.Mu.Lock()
		conn.Monitor = false
		conn.Mu.Unlock()
		fakeInjector.UnregisterConn(conn)
		closeSock()
		return nil, nil, 0, e
	}

	f := os.NewFile(uintptr(h), "")
	if f == nil {
		conn.Mu.Lock()
		conn.Monitor = false
		conn.Mu.Unlock()
		fakeInjector.UnregisterConn(conn)
		closeSock()
		return nil, nil, 0, fmt.Errorf("os.NewFile: nil file")
	}
	defer f.Close()

	outgoingSock, e = net.FileConn(f)
	if e != nil {
		conn.Mu.Lock()
		conn.Monitor = false
		conn.Mu.Unlock()
		fakeInjector.UnregisterConn(conn)
		return nil, nil, 0, e
	}

	return outgoingSock, conn, srcPort, nil
}
