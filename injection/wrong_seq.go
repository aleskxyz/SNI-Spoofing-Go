//go:build linux || windows || darwin

package injection

import (
	"errors"
	"fmt"
	"time"

	"sni-spoofing-go/packet"
)

var errInjectionCanceled = errors.New("injection canceled")

// injectWrongSeqClientHello sends one or more TCP segments for conn.FakeData using wrong-seq semantics.
// Large TLS ClientHellos are split so each IP packet fits the MTU. Checksums are applied before each send.
func injectWrongSeqClientHello(nicMTU int, template []byte, conn *FakeInjectiveConnection, shouldContinue func() bool, send func([]byte) error) error {
	payload := conn.FakeData
	total := len(payload)
	if total == 0 {
		return fmt.Errorf("empty FakeData")
	}

	baseWrongSeq := (uint32(conn.SynSeq) + 1 - uint32(total)) & 0xffffffff
	baseIdent := uint16(0)
	if packet.IPVersion(template) == 4 {
		baseIdent = packet.IPv4Ident(template)
	}

	mss := segmentMSS(nicMTU, template)
	chunkIdx := 0
	for off := 0; off < total; off += mss {
		if shouldContinue != nil && !shouldContinue() {
			return errInjectionCanceled
		}
		end := off + mss
		if end > total {
			end = total
		}
		chunk := payload[off:end]
		isLast := end == total

		pkt := packet.SetTCPPayload(template, chunk)
		if pkt == nil {
			return fmt.Errorf("SetTCPPayload: invalid TCP/IP packet")
		}
		packet.SetTCPSeqNum(pkt, baseWrongSeq+uint32(off))
		if isLast {
			packet.SetTCPFlag(pkt, "psh", true)
		} else {
			packet.SetTCPFlag(pkt, "psh", false)
		}
		if packet.IPVersion(pkt) == 4 {
			packet.SetIPv4Ident(pkt, (baseIdent+1+uint16(chunkIdx))&0xffff)
			packet.ClearIPv4DontFragment(pkt)
		}
		chunkIdx++

		packet.RecalculateIPv4AndTCPChecksums(pkt)
		if err := send(pkt); err != nil {
			return err
		}
		if !isLast && conn.FragmentDelay > 0 && !sleepWhileContinue(conn.FragmentDelay, shouldContinue) {
			return errInjectionCanceled
		}
	}
	return nil
}

func sleepWhileContinue(delay time.Duration, shouldContinue func() bool) bool {
	const maxStep = 25 * time.Millisecond
	remaining := delay
	for remaining > 0 {
		if shouldContinue != nil && !shouldContinue() {
			return false
		}
		step := remaining
		if step > maxStep {
			step = maxStep
		}
		time.Sleep(step)
		remaining -= step
	}
	return shouldContinue == nil || shouldContinue()
}
