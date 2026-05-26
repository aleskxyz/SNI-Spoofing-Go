//go:build darwin

package injection

import (
	"context"
	"fmt"
	"log"
	"net"
	"sync"
	"time"

	"golang.org/x/sys/unix"

	"sni-spoofing-go/connection"
	"sni-spoofing-go/packet"
)

// FakeTcpInjector observes a flow's TCP handshake through a passive BPF tap to learn the
// kernel's sequence numbers, then writes the wrong-seq fake ClientHello back out the same
// /dev/bpf handle as a link-layer frame. The TCP state machine mirrors injector_linux.go; the
// tap is passive so there are no packet verdicts.
type FakeTcpInjector struct {
	bpfFd   int
	dlt     int
	linkLen int
	localIP string

	// linkHdr is the link-layer header observed on an outbound packet of the flow, reused
	// verbatim for injection so the source/destination MACs are correct.
	linkHdr   []byte
	linkHdrMu sync.RWMutex

	Connections sync.Map // connection.ConnID -> *FakeInjectiveConnection
	byLocalPort sync.Map // uint16 -> *FakeInjectiveConnection
	connectIP   string
	connectPort uint16
	nicMTU      int
	bufLen      int

	ctx    context.Context
	cancel context.CancelFunc

	injectorReady   chan struct{}
	injectorOpenErr error
	closeOnce       sync.Once
	sendMu          sync.Mutex
}

func NewFakeTcpInjector(interfaceIP string, connectIPv4s []string, connectPort uint16) (*FakeTcpInjector, error) {
	if len(connectIPv4s) == 0 {
		return nil, fmt.Errorf("no upstream IPv4 addresses")
	}
	connectIP := connectIPv4s[0]

	ifaceName, err := interfaceNameForIPv4(interfaceIP)
	if err != nil {
		return nil, err
	}

	ctx, cancel := context.WithCancel(context.Background())

	fd, bufLen, dlt, err := openBPF(ifaceName)
	if err != nil {
		cancel()
		return nil, err
	}
	linkLen, err := linkHeaderLen(dlt)
	if err != nil {
		unix.Close(fd)
		cancel()
		return nil, err
	}
	if err := setBPFFilter(fd, linkLen, connectIP); err != nil {
		log.Printf("bpf: filter not installed (%v); filtering in userspace", err)
	}

	mtu := nicMTUForLocalIPv4(interfaceIP)
	if mtu == 0 {
		log.Printf("injector: fallback MSS %d", fallbackTCPPayloadMax)
	}
	log.Printf("bpf: iface=%s dlt=%d linkLen=%d mtu=%d", ifaceName, dlt, linkLen, mtu)

	return &FakeTcpInjector{
		bpfFd:         fd,
		dlt:           dlt,
		linkLen:       linkLen,
		localIP:       interfaceIP,
		connectIP:     connectIP,
		connectPort:   connectPort,
		nicMTU:        mtu,
		bufLen:        bufLen,
		ctx:           ctx,
		cancel:        cancel,
		injectorReady: make(chan struct{}),
	}, nil
}

// Start runs the BPF read loop until the injector is closed. It is invoked on its own goroutine.
func (f *FakeTcpInjector) Start() error {
	close(f.injectorReady)
	buf := make([]byte, f.bufLen)
	for {
		if f.ctx.Err() != nil {
			return nil
		}
		n, err := unix.Read(f.bpfFd, buf)
		if err != nil {
			if err == unix.EINTR || err == unix.EAGAIN {
				continue
			}
			if f.ctx.Err() != nil {
				return nil
			}
			log.Printf("bpf read: %v", err)
			return nil
		}
		if n <= 0 {
			continue
		}
		iterBPFBuffer(buf[:n], f.onFrame)
	}
}

func (f *FakeTcpInjector) WaitInjectorReady() error {
	<-f.injectorReady
	return f.injectorOpenErr
}

func (f *FakeTcpInjector) Close() {
	f.closeOnce.Do(func() {
		f.cancel()
		if f.bpfFd >= 0 {
			unix.Close(f.bpfFd)
			f.bpfFd = -1
		}
	})
}

func (f *FakeTcpInjector) RegisterConn(conn *FakeInjectiveConnection) {
	f.Connections.Store(conn.ID, conn)
	f.byLocalPort.Store(conn.SrcPort, conn)
}

func (f *FakeTcpInjector) UnregisterConn(conn *FakeInjectiveConnection) {
	f.Connections.Delete(conn.ID)
	f.byLocalPort.Delete(conn.SrcPort)
}

// onFrame parses one captured link-layer frame, records the link header for injection, and
// dispatches the IP packet to the TCP state machine.
func (f *FakeTcpInjector) onFrame(frame []byte) {
	if len(frame) < f.linkLen {
		return
	}
	ipPkt := frame[f.linkLen:]
	if len(ipPkt) < 40 || packet.IPVersion(ipPkt) != 4 {
		return
	}

	src := packet.IPv4SrcAddr(ipPkt)
	if src == nil {
		return
	}
	srcIP := src.String()
	dstIP := packet.IPv4DstAddr(ipPkt).String()
	srcPort := packet.TCPSrcPort(ipPkt)
	dstPort := packet.TCPDstPort(ipPkt)

	if f.linkLen > 0 && ipv4Equal(srcIP, f.localIP) {
		f.captureLinkHeader(frame)
	}

	conn, outbound, ok := f.lookupConnQuad(srcIP, srcPort, dstIP, dstPort)
	if !ok {
		return
	}
	conn.Mu.Lock()
	defer conn.Mu.Unlock()
	if !conn.Monitor {
		return
	}
	if outbound {
		f.onOutboundPacket(ipPkt, conn)
	} else {
		f.onInboundPacket(ipPkt, conn)
	}
}

func (f *FakeTcpInjector) captureLinkHeader(frame []byte) {
	f.linkHdrMu.RLock()
	have := f.linkHdr != nil
	f.linkHdrMu.RUnlock()
	if have {
		return
	}
	hdr := make([]byte, f.linkLen)
	copy(hdr, frame[:f.linkLen])
	f.linkHdrMu.Lock()
	if f.linkHdr == nil {
		f.linkHdr = hdr
	}
	f.linkHdrMu.Unlock()
}

func (f *FakeTcpInjector) lookupConnQuad(srcIP string, srcPort uint16, dstIP string, dstPort uint16) (conn *FakeInjectiveConnection, outbound bool, ok bool) {
	idOut := connection.ConnID{SrcIP: srcIP, SrcPort: srcPort, DstIP: dstIP, DstPort: dstPort}
	if v, ok := f.Connections.Load(idOut); ok {
		return v.(*FakeInjectiveConnection), true, true
	}
	idIn := connection.ConnID{SrcIP: dstIP, SrcPort: dstPort, DstIP: srcIP, DstPort: srcPort}
	if v, ok := f.Connections.Load(idIn); ok {
		return v.(*FakeInjectiveConnection), false, true
	}
	if v, ok := f.byLocalPort.Load(srcPort); ok {
		c := v.(*FakeInjectiveConnection)
		if ipv4Equal(dstIP, c.DstIP) && dstPort == c.DstPort {
			return c, true, true
		}
	}
	if v, ok := f.byLocalPort.Load(dstPort); ok {
		c := v.(*FakeInjectiveConnection)
		if ipv4Equal(srcIP, c.DstIP) && srcPort == c.DstPort {
			return c, false, true
		}
	}
	return nil, false, false
}

func (f *FakeTcpInjector) onUnexpectedPacket(raw []byte, conn *FakeInjectiveConnection, info string) {
	log.Printf("injector: %s %s", info, packet.PacketSummary(raw))
	if conn.Sock != nil {
		conn.Sock.Close()
	}
	if conn.PeerSock != nil {
		conn.PeerSock.Close()
	}
	conn.Monitor = false
	select {
	case conn.T2aChan <- "unexpected_close":
	default:
	}
}

func (f *FakeTcpInjector) onInboundPacket(raw []byte, conn *FakeInjectiveConnection) {
	if conn.SynSeq == -1 {
		f.onUnexpectedPacket(raw, conn, "unexpected inbound packet, no syn sent!")
		return
	}

	flags := packet.GetTCPFlags(raw)
	payloadLen := packet.TCPPayloadLen(raw)
	seqNum := packet.TCPSeqNum(raw)
	ackNum := packet.TCPAckNum(raw)

	if flags.ACK && flags.SYN && !flags.RST && !flags.FIN && payloadLen == 0 {
		if conn.SynAckSeq != -1 && conn.SynAckSeq != int64(seqNum) {
			f.onUnexpectedPacket(raw, conn,
				fmt.Sprintf("unexpected inbound syn-ack, seq change! %d %d", seqNum, conn.SynAckSeq))
			return
		}
		expectedAck := uint32((uint32(conn.SynSeq) + 1) & 0xffffffff)
		if ackNum != expectedAck {
			f.onUnexpectedPacket(raw, conn,
				fmt.Sprintf("unexpected inbound syn-ack, ack not matched! %d %d", ackNum, conn.SynSeq))
			return
		}
		conn.SynAckSeq = int64(seqNum)
		return
	}

	if flags.ACK && !flags.SYN && !flags.RST && conn.FakeInjectInProgress.Load() && !conn.FakeSent.Load() {
		conn.PostFakeAckObserved.Store(true)
		return
	}

	// CDNs differ on seq/ack fields after the wrong-seq fake; accept a strict match or a peer ACK.
	if flags.ACK && !flags.SYN && !flags.RST && conn.FakeSent.Load() && conn.SynAckSeq != -1 {
		strict := postFakeInboundStrictOK(seqNum, ackNum, conn)
		if !strict && !postFakeInboundPermissiveOK(flags) {
			f.onUnexpectedPacket(raw, conn,
				fmt.Sprintf("unexpected inbound after fake seq=%d ack=%d synAck=%d syn=%d strict=%v", seqNum, ackNum, conn.SynAckSeq, conn.SynSeq, strict))
			return
		}
		conn.Monitor = false
		select {
		case conn.T2aChan <- "fake_data_ack_recv":
		default:
		}
		return
	}

	f.onUnexpectedPacket(raw, conn, "unexpected inbound packet")
}

func (f *FakeTcpInjector) onOutboundPacket(raw []byte, conn *FakeInjectiveConnection) {
	if conn.FakeSent.Load() || conn.FakeInjectInProgress.Load() {
		return
	}

	flags := packet.GetTCPFlags(raw)
	payloadLen := packet.TCPPayloadLen(raw)
	seqNum := packet.TCPSeqNum(raw)
	ackNum := packet.TCPAckNum(raw)

	if flags.SYN && !flags.ACK && !flags.RST && !flags.FIN && payloadLen == 0 {
		if ackNum != 0 {
			f.onUnexpectedPacket(raw, conn, "unexpected outbound syn, ack_num is not zero!")
			return
		}
		if conn.SynSeq != -1 && conn.SynSeq != int64(seqNum) {
			f.onUnexpectedPacket(raw, conn,
				fmt.Sprintf("unexpected outbound syn, seq not matched! %d %d", seqNum, conn.SynSeq))
			return
		}
		conn.SynSeq = int64(seqNum)
		return
	}

	if flags.ACK && !flags.SYN && !flags.RST && !flags.FIN && payloadLen == 0 {
		expectedSeq := uint32((uint32(conn.SynSeq) + 1) & 0xffffffff)
		if conn.SynSeq == -1 || expectedSeq != seqNum {
			f.onUnexpectedPacket(raw, conn,
				fmt.Sprintf("unexpected outbound ack, seq not matched! %d %d", seqNum, conn.SynSeq))
			return
		}
		expectedAck := uint32((uint32(conn.SynAckSeq) + 1) & 0xffffffff)
		if conn.SynAckSeq == -1 || ackNum != expectedAck {
			f.onUnexpectedPacket(raw, conn,
				fmt.Sprintf("unexpected outbound ack, ack not matched! %d %d", ackNum, conn.SynAckSeq))
			return
		}
		rawCopy := make([]byte, len(raw))
		copy(rawCopy, raw)
		conn.FakeInjectInProgress.Store(true)
		go f.runFakeInjection(rawCopy, conn)
		return
	}

	f.onUnexpectedPacket(raw, conn, "unexpected outbound packet")
}

// runFakeInjection sends the wrong-seq fake ClientHello off the read-loop goroutine. It does not
// hold conn.Mu during inject/sleep so the loop can still observe the post-fake inbound ACK.
func (f *FakeTcpInjector) runFakeInjection(rawCopy []byte, conn *FakeInjectiveConnection) {
	defer conn.FakeInjectInProgress.Store(false)

	time.Sleep(1 * time.Millisecond)

	conn.Mu.Lock()
	if !conn.Monitor {
		conn.Mu.Unlock()
		return
	}
	if conn.BypassMethod != "wrong_seq" {
		log.Printf("not implemented bypass method: %s", conn.BypassMethod)
		conn.AbortUnexpectedCloseLocked()
		conn.Mu.Unlock()
		return
	}
	conn.Mu.Unlock()

	repeat := conn.FakeRepeat
	if repeat < 1 {
		repeat = 1
	}
	total := len(conn.FakeData)
	mss := segmentMSS(f.nicMTU, rawCopy)
	segPerInject := (total + mss - 1) / mss
	if segPerInject < 1 {
		segPerInject = 1
	}
	for i := 0; i < repeat; i++ {
		if !conn.IsMonitoring() {
			return
		}
		if err := injectWrongSeqClientHello(f.nicMTU, rawCopy, conn, conn.IsMonitoring, f.sendRawPacket); err != nil {
			if err == errInjectionCanceled {
				return
			}
			log.Printf("inject fake ClientHello: %v", err)
			conn.Mu.Lock()
			conn.AbortUnexpectedCloseLocked()
			conn.Mu.Unlock()
			return
		}
		log.Printf("injector: fake ClientHello sent (%d/%d, %d bytes, %d segment(s))",
			i+1, repeat, total, segPerInject)
		if i+1 < repeat && conn.FakeDelay > 0 && !sleepWhileContinue(conn.FakeDelay, conn.IsMonitoring) {
			return
		}
	}
	conn.FakeSent.Store(true)
	if conn.PostFakeAckObserved.Load() {
		conn.Mu.Lock()
		if conn.Monitor {
			conn.Monitor = false
			select {
			case conn.T2aChan <- "fake_data_ack_recv":
			default:
			}
		}
		conn.Mu.Unlock()
	}
}

// sendRawPacket writes a crafted IP packet to the wire as a link-layer frame, reusing the
// observed link header. It is the send callback for injectWrongSeqClientHello.
func (f *FakeTcpInjector) sendRawPacket(rawIP []byte) error {
	f.linkHdrMu.RLock()
	hdr := f.linkHdr
	f.linkHdrMu.RUnlock()
	if f.linkLen > 0 && len(hdr) < f.linkLen {
		return fmt.Errorf("no observed link header yet for injection")
	}
	frame := buildFrame(hdr, rawIP)
	f.sendMu.Lock()
	defer f.sendMu.Unlock()
	_, err := unix.Write(f.bpfFd, frame)
	return err
}

// interfaceNameForIPv4 returns the name of the interface that owns localIPv4.
func interfaceNameForIPv4(localIPv4 string) (string, error) {
	ip := net.ParseIP(localIPv4)
	if ip == nil {
		return "", fmt.Errorf("invalid local IPv4 %q", localIPv4)
	}
	ip4 := ip.To4()
	if ip4 == nil {
		return "", fmt.Errorf("local address is not IPv4: %q", localIPv4)
	}
	ifaces, err := net.Interfaces()
	if err != nil {
		return "", err
	}
	for _, iface := range ifaces {
		addrs, err := iface.Addrs()
		if err != nil {
			continue
		}
		for _, a := range addrs {
			var cand net.IP
			switch v := a.(type) {
			case *net.IPNet:
				cand = v.IP
			case *net.IPAddr:
				cand = v.IP
			default:
				continue
			}
			if c4 := cand.To4(); c4 != nil && c4.Equal(ip4) {
				return iface.Name, nil
			}
		}
	}
	return "", fmt.Errorf("no interface found for local IPv4 %q", localIPv4)
}
