//go:build darwin

package injection

import (
	"encoding/binary"
	"fmt"
	"net"
	"os"
	"syscall"
	"unsafe"

	"golang.org/x/net/bpf"
	"golang.org/x/sys/unix"
)

// BPF on darwin is a passive tap: we read the connection's own handshake to learn the
// kernel's TCP sequence numbers, and write the wrong-seq fake ClientHello back out as a
// link-layer frame. One /dev/bpf handle serves both directions. CGO stays disabled.

const bpfReadTimeoutUsec = 100_000 // 100ms: lets the read loop poll ctx between reads

// ifreq is the prefix of struct ifreq used by BIOCSETIF (kernel reads ifr_name only).
type ifreq struct {
	name [unix.IFNAMSIZ]byte
	pad  [16]byte
}

// openBPF opens a free /dev/bpf* device bound to ifaceName and returns the fd, the read
// buffer length the kernel chose, and the link type (DLT_*).
func openBPF(ifaceName string) (fd, bufLen, dlt int, err error) {
	fd = -1
	for i := 0; i < 256; i++ {
		f, e := unix.Open(fmt.Sprintf("/dev/bpf%d", i), unix.O_RDWR, 0)
		if e == nil {
			fd = f
			break
		}
		if e == unix.EBUSY {
			continue
		}
		if e == unix.EACCES {
			return -1, 0, 0, fmt.Errorf("open /dev/bpf%d: permission denied (run with sudo)", i)
		}
		if os.IsNotExist(e) {
			break
		}
	}
	if fd < 0 {
		return -1, 0, 0, fmt.Errorf("no free /dev/bpf device available")
	}

	cleanup := func(e error) (int, int, int, error) {
		unix.Close(fd)
		return -1, 0, 0, e
	}

	// A larger buffer reduces read syscalls under load; the kernel clamps to its max.
	_ = unix.IoctlSetPointerInt(fd, unix.BIOCSBLEN, 1<<20)

	var ifr ifreq
	copy(ifr.name[:], ifaceName)
	if e := ioctlStruct(fd, unix.BIOCSETIF, unsafe.Pointer(&ifr)); e != nil {
		return cleanup(fmt.Errorf("BIOCSETIF %q: %w", ifaceName, e))
	}

	bufLen, e := unix.IoctlGetInt(fd, unix.BIOCGBLEN)
	if e != nil {
		return cleanup(fmt.Errorf("BIOCGBLEN: %w", e))
	}
	dlt, e = unix.IoctlGetInt(fd, unix.BIOCGDLT)
	if e != nil {
		return cleanup(fmt.Errorf("BIOCGDLT: %w", e))
	}

	if e := unix.IoctlSetPointerInt(fd, unix.BIOCIMMEDIATE, 1); e != nil {
		return cleanup(fmt.Errorf("BIOCIMMEDIATE: %w", e))
	}
	// See locally-sourced packets so we observe our own SYN/ACK and ignore our own injection.
	_ = unix.IoctlSetPointerInt(fd, unix.BIOCSSEESENT, 1)
	// We supply complete link headers on write; do not let the kernel fill in the source MAC.
	_ = unix.IoctlSetPointerInt(fd, unix.BIOCSHDRCMPLT, 1)
	// Periodic read wakeups so the read loop can notice ctx cancellation.
	tv := unix.Timeval{Sec: 0, Usec: bpfReadTimeoutUsec}
	_ = ioctlStruct(fd, unix.BIOCSRTIMEOUT, unsafe.Pointer(&tv))

	return fd, bufLen, dlt, nil
}

// setBPFFilter installs a coarse capture filter (best-effort). Exact 4-tuple matching is done
// in userspace, so correctness never depends on this filter.
func setBPFFilter(fd, linkLen int, connectIP string) error {
	ip := net.ParseIP(connectIP).To4()
	if ip == nil {
		return fmt.Errorf("connect IP is not IPv4: %q", connectIP)
	}
	var host [4]byte
	copy(host[:], ip)

	insns, err := bpf.Assemble(buildTCPHostFilter(linkLen, host))
	if err != nil {
		return err
	}
	prog := make([]unix.BpfInsn, len(insns))
	for i, in := range insns {
		prog[i] = unix.BpfInsn{Code: in.Op, Jt: in.Jt, Jf: in.Jf, K: in.K}
	}
	p := unix.BpfProgram{Len: uint32(len(prog)), Insns: &prog[0]}
	return ioctlStruct(fd, unix.BIOCSETF, unsafe.Pointer(&p))
}

// buildTCPHostFilter matches IPv4 TCP segments whose source or destination is host. linkLen is
// the link-layer header size; an EtherType guard is added only for Ethernet (linkLen == 14).
func buildTCPHostFilter(linkLen int, host [4]byte) []bpf.Instruction {
	k := binary.BigEndian.Uint32(host[:])
	const accept, drop = 0x40000, 0
	var ins []bpf.Instruction
	if linkLen == 14 {
		ins = append(ins,
			bpf.LoadAbsolute{Off: 12, Size: 2},
			bpf.JumpIf{Cond: bpf.JumpEqual, Val: 0x0800, SkipFalse: 7}, // not IPv4 -> drop
		)
	}
	ins = append(ins,
		bpf.LoadAbsolute{Off: uint32(linkLen + 9), Size: 1},
		bpf.JumpIf{Cond: bpf.JumpEqual, Val: 6, SkipFalse: 5}, // not TCP -> drop
		bpf.LoadAbsolute{Off: uint32(linkLen + 12), Size: 4},  // src IP
		bpf.JumpIf{Cond: bpf.JumpEqual, Val: k, SkipTrue: 2},  // src == host -> accept
		bpf.LoadAbsolute{Off: uint32(linkLen + 16), Size: 4},  // dst IP
		bpf.JumpIf{Cond: bpf.JumpEqual, Val: k, SkipFalse: 1}, // dst != host -> drop
		bpf.RetConstant{Val: accept},
		bpf.RetConstant{Val: drop},
	)
	return ins
}

// linkHeaderLen returns the link-layer header size for a BPF data-link type.
func linkHeaderLen(dlt int) (int, error) {
	switch dlt {
	case unix.DLT_EN10MB:
		return 14, nil // Ethernet / Wi-Fi (presented as Ethernet)
	case unix.DLT_NULL:
		return 4, nil // loopback / utun: 4-byte address-family header
	case dltRaw:
		return 0, nil // raw IP, no link header
	default:
		return 0, fmt.Errorf("unsupported BPF link type DLT=%d (need Ethernet, NULL, or RAW)", dlt)
	}
}

// dltRaw is DLT_RAW; not exported by x/sys/unix on darwin in all versions.
const dltRaw = 12

const bpfHdrMinLen = 18 // Timeval32(8) + Caplen(4) + Datalen(4) + Hdrlen(2)

// iterBPFBuffer walks the bpf_hdr-prefixed records in a BPF read buffer, calling fn with each
// captured frame (link header + packet). Records are 4-byte (BPF_ALIGNMENT) aligned.
func iterBPFBuffer(buf []byte, fn func(frame []byte)) {
	for off := 0; off+bpfHdrMinLen <= len(buf); {
		caplen := int(binary.NativeEndian.Uint32(buf[off+8:]))
		hdrlen := int(binary.NativeEndian.Uint16(buf[off+16:]))
		if hdrlen < bpfHdrMinLen || caplen <= 0 {
			return
		}
		start := off + hdrlen
		end := start + caplen
		if end > len(buf) {
			return
		}
		fn(buf[start:end])
		next := off + bpfWordAlign(hdrlen+caplen)
		if next <= off {
			return
		}
		off = next
	}
}

func bpfWordAlign(x int) int {
	const align = 4 // BPF_ALIGNMENT on darwin (sizeof(int32_t))
	return (x + (align - 1)) &^ (align - 1)
}

// buildFrame prepends the observed link header to an IP packet for BPF write. For DLT_RAW
// (empty link header) the IP packet is written directly.
func buildFrame(linkHdr, ip []byte) []byte {
	if len(linkHdr) == 0 {
		return ip
	}
	frame := make([]byte, len(linkHdr)+len(ip))
	copy(frame, linkHdr)
	copy(frame[len(linkHdr):], ip)
	return frame
}

func ioctlStruct(fd int, req uint, arg unsafe.Pointer) error {
	_, _, errno := syscall.Syscall(syscall.SYS_IOCTL, uintptr(fd), uintptr(req), uintptr(arg))
	if errno != 0 {
		return errno
	}
	return nil
}
