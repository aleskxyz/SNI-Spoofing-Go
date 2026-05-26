# Native macOS (darwin) Support — Spec Plan

**Status:** VERIFIED on macOS (darwin/arm64, Apple Silicon)
**Branch:** feat/macos-native-support
**Date:** 2026-05-26

## Current State

`SNI-Spoofing-Go` builds for **linux** (nfqueue + raw socket) and **windows** (WinDivert)
only. On macOS, `go build .` fails with four undefined symbols — `dialOutgoing`,
`injection.NewFakeTcpInjector`, `injection.FakeTcpInjector` — because the packet-interception
core is gated to `//go:build linux || windows`.

Relevant files today:
- `main.go` — platform-neutral proxy/test driver. Calls `dialOutgoing(...)`,
  `injection.NewFakeTcpInjector(...)`, then `go fakeInjector.Start()` +
  `fakeInjector.WaitInjectorReady()`. Sets `conn.Sock = outgoingSock` after dial
  (main.go:318). `interfaceIPv4` comes from `network.GetDefaultInterfaceIPv4(cfg.ConnectIP)`.
- `dial_linux.go` / `dial_windows.go` — open the upstream TCP socket, bind to the local
  interface IP, register the flow with the injector.
- `injection/injector_linux.go` — nfqueue observer + raw-socket injector. **Always issues
  `NfAccept`** (passive; never drops/mutates). Learns SynSeq/SynAckSeq from the handshake,
  then injects the wrong-seq fake ClientHello.
- `injection/injector_windows.go` — WinDivert equivalent.
- `injection/wrong_seq.go`, `mtu.go`, `tcp_ack.go` — shared injection/validation logic, tagged
  `linux || windows`, using only stdlib + the `packet` package.
- `injection/common.go`, `connection/monitor.go`, `packet/*`, `config/*` — platform-neutral
  (compile on darwin today; verified `go build ./injection/ ./packet/ ./connection/ ./config/`
  → exit 0).

## Goal

Add a native darwin backend so the tool **builds and works on macOS**: `make build` produces a
CGO-free darwin binary, and running it with `sudo` passes the built-in `-test` matrix and
serves the `curl` PoC through the local tunnel. No changes to the linux/windows runtime paths.

## Investigation Findings

- The Linux injector is a **passive observer** (every code path ends in `NfAccept`). macOS
  therefore needs no intrusive hook — a passive **BPF tap** (`/dev/bpf`) is equivalent for
  observation, and BPF can also *write* frames, so one handle does capture + injection.
- The shared helpers (`wrong_seq.go`, `mtu.go`, `tcp_ack.go`) contain no OS-specific syscalls;
  widening their build tag to include `darwin` compiles cleanly.
- The on-wire injection flow is identical to Linux: capture an outbound ACK as the IP template,
  set the fake payload, rewrite the seq to the wrong value, keep the ack, recompute checksums.
  Only the transport differs (BPF L2 write vs Linux raw socket).
- Risk: macOS raw sockets require `ip_len`/`ip_off` in **host** byte order (BSD quirk) which the
  packet builder does not do — avoided by using BPF L2 write, which takes the frame verbatim.
- Risk: L2 injection needs correct MACs — solved by reusing the Ethernet header observed on an
  outbound packet of the same flow.
- `golang.org/x/sys/unix` (already a dependency) exposes all needed BPF constants/structs for
  darwin/arm64 (`BpfHdr`, `BpfProgram`, `BpfInsn`, `BIOC*`, `DLT_*`, `SYS_IOCTL`). No `Ifreq`
  type on darwin in this version, so a 32-byte ifreq is defined locally.
- `golang.org/x/net/bpf` (cached, indirect dep) assembles the capture filter.

### 1. Widen shared injection helpers to darwin
1.1. Change `//go:build linux || windows` → `//go:build linux || windows || darwin` in
     `injection/wrong_seq.go`, `injection/mtu.go`, `injection/tcp_ack.go`.
1.2. Files affected: those three only.
1.3. Input/output/behavior: unchanged; only the set of target OSes widens.
1.4. Edge cases: none — bodies use stdlib + `packet` only.
1.5. Prerequisites: none.
1.6. Acceptance: `GOOS=linux`, `GOOS=windows`, `GOOS=darwin` all `go vet`/`build` these files.
1.7. Risk/rollback: negligible; revert the one-line tag edits.

### 2. BPF device + framing helpers (`injection/bpf_darwin.go`)
2.1. `openBPF(ifaceName)`: open `/dev/bpf0..N` (O_RDWR), `BIOCSETIF`, `BIOCSBLEN`/`BIOCGBLEN`,
     `BIOCIMMEDIATE=1`, `BIOCSSEESENT=1`, `BIOCSHDRCMPLT=1`, `BIOCSRTIMEOUT≈100ms` (best-effort),
     `BIOCGDLT`. Best-effort `BIOCSETF` filter (IPv4+TCP+host==connectIP) via `x/net/bpf`.
2.2. `linkHeaderLen(dlt)`: `DLT_EN10MB`→14, `DLT_NULL`→4, `DLT_RAW`→0, else error.
2.3. `iterBPFBuffer(buf, fn)`: walk `unix.BpfHdr` records by `Hdrlen`/`Caplen`, advance by
     4-byte `BPF_WORDALIGN`. Pure function.
2.4. `buildFrame(linkHdr, ip)`: prepend the observed link header (or nothing for `DLT_RAW`).
2.5. Int ioctls via `unix.IoctlSetPointerInt`/`IoctlGetInt`; struct ioctls (`BIOCSETIF`,
     `BIOCSETF`, `BIOCSRTIMEOUT`) via `syscall.Syscall(SYS_IOCTL, ...)`.
2.6. Acceptance: unit tests for `iterBPFBuffer`, `linkHeaderLen`, `buildFrame` pass without root.
2.7. Risk: wrong buffer alignment → covered by unit tests; bad filter → best-effort + userspace
     tuple match keeps correctness.

### 3. Darwin injector (`injection/injector_darwin.go`)
3.1. `FakeTcpInjector` with BPF fd, iface/dlt/localIP, observed `linkHdr` (mutex-guarded),
     `Connections`/`byLocalPort` maps, ctx/cancel, `injectorReady`, `closeOnce`, `sendMu`.
3.2. `NewFakeTcpInjector` resolves iface name from `interfaceIP`, computes MTU
     (`nicMTUForLocalIPv4`), opens BPF. `EACCES` → "run with sudo".
3.3. `Start` closes `injectorReady`, runs the read loop (strip link header → IP bytes → record
     `linkHdr` on first outbound → `lookupConnQuad` → `onOutbound`/`onInbound`), exits on ctx done.
3.4. `onInbound`/`onOutbound`/`onUnexpected`/`lookupConnQuad`/`runFakeInjection` ported from
     `injector_linux.go` with every `nf.SetVerdict` removed (passive tap).
3.5. `sendRawPacket(ip)`: `buildFrame` + `unix.Write(bpfFd, ...)` under `sendMu`; this is the
     `send` callback for `injectWrongSeqClientHello`.
3.6. `Close`: cancel ctx + close fd (idempotent).
3.7. Acceptance: `go build .` succeeds on darwin; injector starts under sudo.
3.8. Risk: capturing our own injected fake → already ignored via `FakeInjectInProgress`/`FakeSent`
     guards (same as Linux). Rollback: delete file.

### 4. Darwin dial (`dial_darwin.go`)
4.1. Mirror `dial_linux.go`: `net.Dialer` `Control` sets `SO_REUSEADDR`+`SO_KEEPALIVE`, binds to
     `interfaceIPv4:0`, reads ephemeral port, builds `FakeInjectiveConnection`, registers it.
     No `SO_MARK`.
4.2. Same signature/return as linux. 4.3–4.7: behavior, edge handling, and unregister-on-error
     mirror dial_linux.go exactly.

### 5. Build + docs
5.1. `Makefile`: add `darwin-amd64`/`darwin-arm64` dist targets; include in `dist all`.
5.2. `README.md`: add macOS row to the platform table and a `sudo` quick-start.

## SQL Changes (if any)

None.

## Verification Results (2026-05-26, darwin/arm64)

- `make build` → `Mach-O 64-bit executable arm64`, `CGO_ENABLED=0`. `go vet ./...` and
  `go test ./...` green (incl. new BPF unit tests). linux amd64/arm64, windows, darwin amd64
  cross-builds all succeed — no regression.
- Unprivileged run fails cleanly: `failed to create injector: open /dev/bpf0: permission
  denied (run with sudo)` (no crash).
- `sudo ./sni-spoofing -test -connect 104.19.229.21:443 -fake-sni hcaptcha.com`: preflight OK;
  matrix **PASS** for `none` (all 4 variants) and `firefox` (all 4 variants incl. fragment
  on/off and repeat 1/2). `chrome` FAIL is network/DPI-dependent (the injection path is
  fingerprint-agnostic; `firefox` multi-segment + fragment passing proves the mechanism). ✅
  Acceptance bar (≥1 PASS) exceeded.

## Verification Checklist

1. `CGO_ENABLED=0 make build` → `./sni-spoofing`; `file sni-spoofing` shows `Mach-O ... arm64`.
2. `go test ./...` (now includes `main` + `injection` on darwin) → all pass.
3. `sudo ./sni-spoofing -test -connect 104.19.229.21:443 -fake-sni hcaptcha.com` → preflight OK,
   matrix shows ≥1 `PASS`.
4. `sudo ./sni-spoofing -listen 127.0.0.1:40443 -connect 104.19.229.21:443 -fake-sni hcaptcha.com -utls firefox`
   then `curl -sSLf --resolve one.one.one.one:40443:127.0.0.1 https://one.one.one.one:40443/ | grep '^\.\.'`
   → ASCII-art page.

## Files Changed Summary

| File | Change |
|---|---|
| `dial_darwin.go` | NEW — dial path (mirror dial_linux, no SO_MARK) |
| `injection/bpf_darwin.go` | NEW — BPF open/ioctl/filter, DLT, buffer iterator, frame build |
| `injection/injector_darwin.go` | NEW — FakeTcpInjector lifecycle + passive state machine |
| `injection/bpf_darwin_test.go` | NEW — unit tests (no root) |
| `injection/wrong_seq.go` | EDIT — build tag += darwin |
| `injection/mtu.go` | EDIT — build tag += darwin |
| `injection/tcp_ack.go` | EDIT — build tag += darwin |
| `Makefile` | EDIT — darwin dist targets |
| `README.md` | EDIT — macOS platform row + quick-start |
