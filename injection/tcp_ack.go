//go:build linux || windows || darwin

package injection

import (
	"net"

	"sni-spoofing-go/packet"
)

// ipv4Equal compares host strings for IPv4 equality (canonical forms may differ).
func ipv4Equal(a, b string) bool {
	pa, pb := net.ParseIP(a), net.ParseIP(b)
	if pa == nil || pb == nil {
		return a == b
	}
	return pa.Equal(pb)
}

// postFakeInboundStrictOK matches the historical Linux/nfqueue expectations for the first server segment.
func postFakeInboundStrictOK(seqNum, ackNum uint32, conn *FakeInjectiveConnection) bool {
	if conn.SynAckSeq == -1 {
		return false
	}
	expectedSeq := uint32((uint32(conn.SynAckSeq) + 1) & 0xffffffff)
	if expectedSeq != seqNum {
		return false
	}
	return ackAcceptsPostFakeInbound(ackNum, conn.SynSeq, len(conn.FakeData))
}

// postFakeInboundPermissiveOK accepts any ACK-class reply from the peer after the fake (tuple already matched).
func postFakeInboundPermissiveOK(f packet.TCPFlags) bool {
	return f.ACK && !f.SYN && !f.RST
}

// ackAcceptsPostFakeInbound returns true if the server's ack field is consistent with having
// seen our wrong-seq fake: duplicate ACK (ack == SynSeq+1) or an ack advanced into the fake
// window [SynSeq+1, SynSeq+1+len(fake)].
func ackAcceptsPostFakeInbound(ackNum uint32, synSeq int64, fakeLen int) bool {
	minAck := uint32((uint32(synSeq) + 1) & 0xffffffff)
	if fakeLen <= 0 {
		return ackNum == minAck
	}
	maxAck := uint32(uint64(uint32(synSeq)) + 1 + uint64(fakeLen))
	return tcpSeqInRingIntervalInclusive(ackNum, minAck, maxAck)
}

func tcpSeqInRingIntervalInclusive(x, a, b uint32) bool {
	if a <= b {
		return x >= a && x <= b
	}
	return x >= a || x <= b
}
