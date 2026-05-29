//go:build linux

package proxy

import (
	"fmt"
	"net"
	"syscall"
	"time"

	"sni-spoofing-go/injection"
)

func dialOutgoing(
	interfaceIPv4, connectIP string, connectPort int,
	fakeData []byte, bypassMethod string,
	fakeRepeat int,
	fakeDelay, fragmentDelay time.Duration,
	incomingSock net.Conn,
	fakeInjector injection.TCPInjector,
) (outgoingSock net.Conn, conn *injection.FakeInjectiveConnection, srcPort uint16, err error) {
	targetAddr := net.JoinHostPort(connectIP, fmt.Sprintf("%d", connectPort))

	var registered bool

	dialer := net.Dialer{
		Timeout:   10 * time.Second,
		KeepAlive: 11 * time.Second,
		Control: func(netw, addr string, c syscall.RawConn) error {
			var bindErr error
			c.Control(func(fd uintptr) {
				syscall.SetsockoptInt(int(fd), syscall.SOL_SOCKET, syscall.SO_REUSEADDR, 1)
				syscall.SetsockoptInt(int(fd), syscall.SOL_SOCKET, syscall.SO_KEEPALIVE, 1)

				sa := &syscall.SockaddrInet4{Port: 0}
				ip4 := net.ParseIP(interfaceIPv4).To4()
				if ip4 == nil {
					bindErr = fmt.Errorf("local address is not IPv4: %q", interfaceIPv4)
					return
				}
				copy(sa.Addr[:], ip4)
				bindErr = syscall.Bind(int(fd), sa)
				if bindErr != nil {
					return
				}

				localSA, gsErr := syscall.Getsockname(int(fd))
				if gsErr != nil {
					bindErr = gsErr
					return
				}
				switch la := localSA.(type) {
				case *syscall.SockaddrInet4:
					srcPort = uint16(la.Port)
				default:
					bindErr = fmt.Errorf("getsockname: unexpected address type %T", localSA)
				}
			})
			if bindErr != nil {
				return bindErr
			}

			conn = injection.NewFakeInjectiveConnection(
				nil, interfaceIPv4, connectIP, srcPort, uint16(connectPort),
				fakeData, bypassMethod, incomingSock, fakeRepeat, fakeDelay, fragmentDelay,
			)
			fakeInjector.RegisterConn(conn)
			registered = true
			return nil
		},
	}

	outgoingSock, err = dialer.Dial("tcp4", targetAddr)
	if err != nil {
		if registered && conn != nil {
			conn.Mu.Lock()
			conn.Monitor = false
			conn.Mu.Unlock()
			fakeInjector.UnregisterConn(conn)
		}
		return nil, nil, 0, err
	}

	return outgoingSock, conn, srcPort, nil
}
