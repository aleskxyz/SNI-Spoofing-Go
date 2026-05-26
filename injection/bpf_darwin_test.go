//go:build darwin

package injection

import (
	"encoding/binary"
	"testing"

	"golang.org/x/net/bpf"
	"golang.org/x/sys/unix"
)

func TestLinkHeaderLen(t *testing.T) {
	cases := []struct {
		dlt     int
		want    int
		wantErr bool
	}{
		{unix.DLT_EN10MB, 14, false},
		{unix.DLT_NULL, 4, false},
		{dltRaw, 0, false},
		{0x999, 0, true},
	}
	for _, c := range cases {
		got, err := linkHeaderLen(c.dlt)
		if c.wantErr {
			if err == nil {
				t.Errorf("linkHeaderLen(%#x): expected error", c.dlt)
			}
			continue
		}
		if err != nil || got != c.want {
			t.Errorf("linkHeaderLen(%#x) = %d, %v; want %d, nil", c.dlt, got, err, c.want)
		}
	}
}

func TestBpfWordAlign(t *testing.T) {
	cases := map[int]int{0: 0, 1: 4, 4: 4, 5: 8, 18: 20, 38: 40}
	for in, want := range cases {
		if got := bpfWordAlign(in); got != want {
			t.Errorf("bpfWordAlign(%d) = %d; want %d", in, got, want)
		}
	}
}

func TestBuildFrame(t *testing.T) {
	if got := buildFrame(nil, []byte{1, 2, 3}); string(got) != string([]byte{1, 2, 3}) {
		t.Errorf("buildFrame(nil) should return ip unchanged, got %v", got)
	}
	got := buildFrame([]byte{0xaa, 0xbb}, []byte{1, 2})
	if want := []byte{0xaa, 0xbb, 1, 2}; string(got) != string(want) {
		t.Errorf("buildFrame = %v; want %v", got, want)
	}
}

// appendBPFRecord writes one bpf_hdr-prefixed record (hdrlen=18) and pads to 4-byte alignment.
func appendBPFRecord(buf, data []byte) []byte {
	var hdr [18]byte
	binary.NativeEndian.PutUint32(hdr[8:], uint32(len(data)))  // Caplen
	binary.NativeEndian.PutUint32(hdr[12:], uint32(len(data))) // Datalen
	binary.NativeEndian.PutUint16(hdr[16:], 18)                // Hdrlen
	buf = append(buf, hdr[:]...)
	buf = append(buf, data...)
	for len(buf)%4 != 0 {
		buf = append(buf, 0)
	}
	return buf
}

func TestIterBPFBuffer(t *testing.T) {
	frames := [][]byte{
		{0x01, 0x02, 0x03},             // 3 bytes -> aligned advance
		{0x10, 0x11, 0x12, 0x13, 0x14}, // 5 bytes
	}
	var buf []byte
	for _, f := range frames {
		buf = appendBPFRecord(buf, f)
	}

	var got [][]byte
	iterBPFBuffer(buf, func(frame []byte) {
		cp := make([]byte, len(frame))
		copy(cp, frame)
		got = append(got, cp)
	})

	if len(got) != len(frames) {
		t.Fatalf("iterBPFBuffer yielded %d frames; want %d", len(got), len(frames))
	}
	for i := range frames {
		if string(got[i]) != string(frames[i]) {
			t.Errorf("frame %d = %v; want %v", i, got[i], frames[i])
		}
	}
}

func TestIterBPFBufferTruncated(t *testing.T) {
	// A trailing partial header must not panic and must stop cleanly.
	buf := appendBPFRecord(nil, []byte{1, 2, 3})
	buf = append(buf, 0x00, 0x01) // dangling bytes shorter than a header
	count := 0
	iterBPFBuffer(buf, func([]byte) { count++ })
	if count != 1 {
		t.Errorf("got %d frames; want 1", count)
	}
}

func ethIPv4TCP(linkLen int, etherType uint16, proto byte, src, dst [4]byte) []byte {
	pkt := make([]byte, linkLen+20+20)
	if linkLen == 14 {
		binary.BigEndian.PutUint16(pkt[12:], etherType)
	}
	pkt[linkLen] = 0x45 // IPv4, IHL=5
	pkt[linkLen+9] = proto
	copy(pkt[linkLen+12:], src[:])
	copy(pkt[linkLen+16:], dst[:])
	return pkt
}

func runFilter(t *testing.T, linkLen int, host [4]byte, pkt []byte) int {
	t.Helper()
	vm, err := bpf.NewVM(buildTCPHostFilter(linkLen, host))
	if err != nil {
		t.Fatalf("NewVM: %v", err)
	}
	out, err := vm.Run(pkt)
	if err != nil {
		t.Fatalf("vm.Run: %v", err)
	}
	return out
}

func TestBuildTCPHostFilterEthernet(t *testing.T) {
	host := [4]byte{104, 19, 229, 21}
	other := [4]byte{1, 1, 1, 1}
	const tcp, udp = 6, 17
	const ipv4, ipv6 = 0x0800, 0x86dd

	if runFilter(t, 14, host, ethIPv4TCP(14, ipv4, tcp, other, host)) == 0 {
		t.Error("dst==host TCP should be accepted")
	}
	if runFilter(t, 14, host, ethIPv4TCP(14, ipv4, tcp, host, other)) == 0 {
		t.Error("src==host TCP should be accepted")
	}
	if runFilter(t, 14, host, ethIPv4TCP(14, ipv4, tcp, other, other)) != 0 {
		t.Error("unrelated host should be dropped")
	}
	if runFilter(t, 14, host, ethIPv4TCP(14, ipv4, udp, other, host)) != 0 {
		t.Error("non-TCP should be dropped")
	}
	if runFilter(t, 14, host, ethIPv4TCP(14, ipv6, tcp, other, host)) != 0 {
		t.Error("non-IPv4 EtherType should be dropped")
	}
}

func TestBuildTCPHostFilterNull(t *testing.T) {
	host := [4]byte{104, 19, 229, 21}
	other := [4]byte{8, 8, 8, 8}
	if runFilter(t, 4, host, ethIPv4TCP(4, 0, 6, host, other)) == 0 {
		t.Error("DLT_NULL src==host TCP should be accepted")
	}
	if runFilter(t, 4, host, ethIPv4TCP(4, 0, 17, host, other)) != 0 {
		t.Error("DLT_NULL non-TCP should be dropped")
	}
}
