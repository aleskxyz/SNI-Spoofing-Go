# SNI-Spoofing-Go

A Go implementation of the [SNI-Spoofing](https://github.com/patterniha/SNI-Spoofing) DPI bypass technique.

This repository provides a local TCP proxy that injects a fake TLS ClientHello with a spoofed SNI during the TCP handshake. The real TLS connection is then relayed, allowing DPI devices to see a decoy SNI while the client continues to talk to the intended target.

## Quick Usage Guide

### Run

At minimum, provide `-listen` and `-connect`. Use `-fake-sni` when `-connect` is an IP address.

```bash
./sni-spoofing -listen 127.0.0.1:40443 -connect 104.19.229.21:443 -fake-sni hcaptcha.com -utls firefox
```

Platform-specific notes:

- **Linux/OpenWrt:** run as `root` or with `sudo`.
- **macOS:** run with `sudo`; BPF requires root privileges.
- **Windows:** run as Administrator.

### Listen / Connect

- `-listen` sets the local proxy address, e.g. `127.0.0.1:40443`.
- `-connect` sets the upstream server IP and port, e.g. `104.19.229.21:443`.

If `-connect` is a hostname, the tool resolves it automatically. If it is an IP address, then `-fake-sni` must be provided.

### Fake SNI and TLS fingerprint

- `-fake-sni` specifies the decoy hostname that DPI should see.
- `-utls` selects the ClientHello fingerprint preset.

Common presets:

- `firefox`
- `chrome`
- `edge`
- `safari`
- `ios`
- `qq`
- `360browser`
- `none`

Run `-h` for a full list of supported `-utls` names.

## Configuration

You can use CLI flags or a config file. If `-config` is not specified, the app loads `./config.ini` automatically when present. CLI flags override config values.

Example `config.ini`:

```ini
listen = 127.0.0.1:40443
connect = 104.19.229.21:443
fake-sni = hcaptcha.com
utls = firefox
fake-repeat = 1
fake-delay = 2ms
ack-timeout = 2s
injector = active
enable-fragment = false
fragment-delay = 500ms
sni-chunk = 3
```

## Common Flags

| Flag | Default | Description |
|------|---------|-------------|
| `-config` | `./config.ini` if available | Load INI config file |
| `-listen` | none | Local address to accept client connections |
| `-connect` | none | Upstream IP:port to connect through |
| `-fake-sni` | hostname from `-connect` | Decoy SNI used in the fake ClientHello |
| `-injector` | `active` (`passive` on macOS) | Injector backend |
| `-fake-repeat` | `1` | Number of fake ClientHello packets |
| `-fake-delay` | `2ms` | Delay before forwarding real traffic |
| `-ack-timeout` | `2s` | Max wait for server response after fake injection |
| `-utls` | `firefox` | TLS fingerprint preset |
| `-enable-fragment` | `false` | Split the real ClientHello into fragments |
| `-fragment-delay` | `500ms` | Delay between fragmented writes |
| `-sni-chunk` | `3` | Bytes per write when fragmentation is enabled |
| `-test` | disabled | Run built-in method test matrix |

## Injector Modes

`-injector` controls the packet injection backend.

- `active`: default on Linux/Windows.
- `passive`: use a passive observer/injector backend where available. In many cases, passive mode may also offer better performance.

Platform behavior:

- **Linux:** `active` uses nfqueue + raw socket, `passive` uses AF_PACKET and link-layer writes.
- **Windows:** `active` uses WinDivert reinjection, `passive` uses WinDivert sniff/send.
- **macOS:** only `passive` is supported by BPF tap and link-layer writes.

## Example Commands

Run the proxy on Linux:

```bash
sudo ./sni-spoofing-linux-amd64 \
  -listen 127.0.0.1:40443 \
  -connect 104.19.229.21:443 \
  -fake-sni hcaptcha.com \
  -utls firefox
```

Run the proxy on Windows:

```powershell
.\sni-spoofing.exe -listen 127.0.0.1:40443 -connect 104.19.229.21:443 -fake-sni hcaptcha.com -utls firefox
```

Run with passive injector mode:

```bash
sudo ./sni-spoofing-linux-amd64 -listen 127.0.0.1:40443 -connect 104.19.229.21:443 -fake-sni hcaptcha.com -injector passive
```

## Docker Usage

Run the official Docker image with host networking and required capabilities:

```bash
docker run --rm -it \
  --network host \
  --cap-add NET_ADMIN --cap-add NET_RAW \
  ghcr.io/aleskxyz/sni-spoofing-go:latest \
  -listen 127.0.0.1:40443 \
  -connect 104.19.229.21:443 \
  -fake-sni hcaptcha.com \
  -utls firefox
```

If Docker is unavailable, Podman can be used alternatively.

## Testing and Validation

Use `-test` to validate the selected upstream IP and fake SNI before normal operation.

```bash
./sni-spoofing-linux-amd64 -test -connect 104.19.229.21:443 -fake-sni hcaptcha.com
```

The test mode performs a preflight check and then runs a small matrix of endpoint combinations. If it reports failures, try a different upstream IP, a different fake SNI, or another `-utls` preset.

Example `-test` output:

```text
Preflight
  external IP: 198.51.100.1
  internal IP: 198.51.100.1
  result: IPs match; running e2e matrix

Matrix
UTLS     Fake-Repeat Fragment Result
none     1           off      PASS
none     1           on       PASS
none     2           off      PASS
none     2           on       PASS
firefox  1           off      PASS
firefox  1           on       PASS
firefox  2           off      PASS
firefox  2           on       PASS
chrome   1           off      PASS
chrome   1           on       PASS
chrome   2           off      PASS
chrome   2           on       PASS
safari   1           off      PASS
safari   1           on       PASS
safari   2           off      PASS
safari   2           on       PASS
ios      1           off      PASS
ios      1           on       PASS
ios      2           off      PASS
ios      2           on       PASS
edge     1           off      PASS
edge     1           on       PASS
edge     2           off      PASS
edge     2           on       PASS

All 24 cases passed.

Press Enter to exit...
```

## Practical Usage Tips

- This is a plain TCP proxy, not an HTTP or SOCKS proxy.
- Use `curl --resolve` to test HTTPS through the local listener while preserving the client hostname.
- The real target hostname comes from the client request, while `-fake-sni` is the decoy seen by DPI.
- If `-connect` is an IP address, supply `-fake-sni` explicitly.

Example test command:

```bash
curl -sSLf --resolve one.one.one.one:40443:127.0.0.1 https://one.one.one.one:40443/ | grep '^\.\.'
```

Expected output:

```text
............................................................
.........1............1............1............1...........
........11...........11...........11...........11...........
.......111..........111..........111..........111...........
......1111.........1111.........1111.........1111...........
........11...........11...........11...........11...........
........11...........11...........11...........11...........
........11...........11...........11...........11...........
........11....ooo....11....ooo....11....ooo....11...........
......111111..ooo..111111..ooo..111111..ooo..111111.........
............................................................
```

## Platforms

| Platform | Notes |
|----------|-------|
| Linux/OpenWrt | Requires root. Uses nfqueue + raw socket by default. |
| macOS | Requires sudo. Uses BPF tap and passive injection. |
| Windows | Requires Administrator. Uses WinDivert. |

### OpenWrt setup for active injector mode

On OpenWrt, install the required nfqueue packages before running in active injector mode:

```bash
apk update
apk install iptables-mod-nfqueue kmod-nfnetlink-queue
```

## GUI (experimental)

A cross-platform desktop GUI built with [Wails v2](https://wails.io) + Svelte lives in [gui/](gui/). It runs on Windows, Linux, and macOS, and ships with English and Persian translations using the Vazirmatn font.

Prerequisites: Go 1.25+ (matches [gui/go.mod](gui/go.mod)), Node.js 20.19+ (Vite 7 requirement), and the Wails CLI:

```bash
go install github.com/wailsapp/wails/v2/cmd/wails@v2.12.0
```

Build the GUI:

```bash
cd gui
wails build
# binary lands in gui/build/bin/
```

Run the GUI in dev mode (hot reload):

```bash
cd gui
wails dev
```

The GUI needs the same elevated privileges as the CLI (Administrator on Windows, root on Linux/macOS). Start/Stop/RunTest are wired to the shared `sni-spoofing-go/proxy` package, which is the same code path the CLI exercises.

## Build release targets

Build all release targets:

```bash
make dist
```

## License

This project is licensed under the **GNU General Public License v3.0**.

See [LICENSE](LICENSE) for details.

## Original Project

Based on [https://github.com/patterniha/SNI-Spoofing](https://github.com/patterniha/SNI-Spoofing) by [@patterniha](https://github.com/patterniha).
