//go:build linux || windows || darwin

package injection

import (
	"net"

	"sni-spoofing-go/packet"
)

const fallbackTCPPayloadMax = 1000

// nicMTUForLocalIPv4 returns the MTU of the interface that owns localIPv4, or 0.
func nicMTUForLocalIPv4(localIPv4 string) int {
	ip := net.ParseIP(localIPv4)
	if ip == nil {
		return 0
	}
	ip4 := ip.To4()
	if ip4 == nil {
		return 0
	}
	ifaces, err := net.Interfaces()
	if err != nil {
		return 0
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
			cand = cand.To4()
			if cand == nil || !cand.Equal(ip4) {
				continue
			}
			return iface.MTU
		}
	}
	return 0
}

// segmentMSS returns max TCP payload bytes per injected packet from NIC MTU and template IPv4/TCP headers.
func segmentMSS(nicMTU int, template []byte) int {
	if nicMTU <= 0 || packet.IPVersion(template) != 4 {
		return fallbackTCPPayloadMax
	}
	ipLen := packet.IPHeaderLen(template)
	tcpLen := packet.TCPDataOffset(template)
	if ipLen < 20 || tcpLen < 20 {
		return fallbackTCPPayloadMax
	}
	overhead := ipLen + tcpLen
	if nicMTU <= overhead {
		return fallbackTCPPayloadMax
	}
	mss := nicMTU - overhead
	if mss < 128 {
		return fallbackTCPPayloadMax
	}
	return mss
}
