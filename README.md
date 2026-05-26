# SNI-Spoofing-Go

A **Go implementation** of the [SNI-Spoofing](https://github.com/patterniha/SNI-Spoofing) DPI bypass tool, originally written in Python by [@patterniha](https://github.com/patterniha).

Cross-platform: **Windows** with WinDivert, **Linux/OpenWrt** with nfqueue plus a raw socket, and **macOS** with a passive BPF tap plus link-layer injection.

## Credits & Acknowledgments

This project is a complete port of the original **[SNI-Spoofing](https://github.com/patterniha/SNI-Spoofing)** by **[@patterniha](https://github.com/patterniha)**. All credit for the original concept, algorithm, and DPI bypass technique goes to them.

This Go version follows the original wrong-sequence fake ClientHello technique while adding:

- Native concurrency with goroutines
- Cross-compilation for Windows and Linux targets
- Single static binary; no Python interpreter or pip dependencies
- Linux/OpenWrt support via nfqueue (the original is Windows-only)

## How it works

This tool acts as a local TCP proxy that:

1. **Listens** on a local port for incoming connections
2. **Connects** to the target server (e.g., a Cloudflare IP on port 443)
3. **Intercepts** the TCP handshake using kernel-level packet capture
4. **Injects** a fake TLS ClientHello with a spoofed SNI using a deliberately **wrong TCP sequence number** — DPI reads the fake SNI while the real server ignores the invalid packet
5. **Relays** traffic bidirectionally after the injection

## Platform Support

| Platform          | Packet Interception   | Fake Injection      | Requirements                                |
| ----------------- | --------------------- | ------------------- | ------------------------------------------- |
| **Windows**       | WinDivert driver      | WinDivert send      | Run as Administrator; driver is embedded    |
| **Linux/OpenWrt** | nfqueue (netfilter)   | Raw socket          | `iptables`, `nfnetlink_queue` kernel module |
| **macOS**         | BPF tap (`/dev/bpf`)  | BPF link-layer write | Run with `sudo`; Ethernet/Wi-Fi or utun interface |

## Quick Start

### Build

```bash
go mod download

# all targets -> dist/
make dist

# or build one target:
make linux-amd64
make linux-arm64
make windows
make darwin-arm64   # macOS Apple Silicon
make darwin-amd64   # macOS Intel

# or just build for the machine you are on:
make build
```

The macOS build is pure Go (`CGO_ENABLED=0`); it uses a passive BPF tap and link-layer
injection, so no libpcap or kernel extension is required.

The Windows binary embeds the WinDivert driver through the local `godivert` module. You do not need to ship `WinDivert.dll` or `WinDivert64.sys` beside `sni-spoofing.exe`.

### Run

Configuration can come from CLI flags or an INI file. If `-config` is not provided, the app loads `./config.ini` when it exists. CLI flags override file values. `listen` and `connect` are required from either source; `fake-sni` is optional when `connect` uses a hostname, otherwise it is required because the connect target is only an IP address.

```bash
# Windows (as Administrator)
.\sni-spoofing.exe -listen 127.0.0.1:40443 -connect 104.19.229.21:443 -fake-sni hcaptcha.com -utls firefox

# Linux/OpenWrt (as root)
sudo ./sni-spoofing-linux-amd64 -listen 127.0.0.1:40443 -connect 104.19.229.21:443 -fake-sni hcaptcha.com -utls firefox

# macOS (with sudo; BPF requires root)
sudo ./sni-spoofing -listen 127.0.0.1:40443 -connect 104.19.229.21:443 -fake-sni hcaptcha.com -utls firefox
```

Useful options:

| Flag | Default | Meaning |
| ---- | ------- | ------- |
| `-config` | `./config.ini` if it exists | INI config file; CLI flags override file values |
| `-test` | disabled | Run the built-in e2e test matrix for the selected `-connect`/`-fake-sni` pair, then exit |
| `-fake-sni` | hostname from `-connect` | Decoy SNI used in the injected fake ClientHello |
| `-fake-repeat` | `1` | Number of fake ClientHello injections |
| `-fake-delay` | `2ms` | Delay after fake injection before forwarding real traffic |
| `-ack-timeout` | `2s` | Max wait for the server response after fake injection |
| `-utls` | `firefox` | TLS fingerprint preset; use `none` for the legacy fixed ClientHello template; run with `-h` to list all presets |
| `-enable-fragment` | disabled | Split the real ClientHello after fake injection |
| `-fragment-delay` | `500ms` | Delay between split real ClientHello writes |
| `-sni-chunk` | `3` | SNI bytes per write when `-enable-fragment` is set; `0` means the whole hostname; for `hcaptcha.com`, `3` writes `hca`, `ptc`, `ha.`, `com` |

Example config:

```ini
listen = 127.0.0.1:40443
connect = 104.19.229.21:443
fake-sni = hcaptcha.com
utls = firefox
fake-repeat = 1
fake-delay = 2ms
ack-timeout = 2s
enable-fragment = false
fragment-delay = 500ms
sni-chunk = 3
```

The repository includes `config.example.ini`; copy it to `config.ini` to use the automatic default config loading.

Method test:

```bash
./sni-spoofing-linux-amd64 -test -connect 104.19.229.21:443 -fake-sni hcaptcha.com
```

`-test` first runs a preflight check for the selected upstream IP and fake SNI. The preflight confirms that the upstream path is reachable and compares the network-visible IPs used by the test; if the upstream path is unreachable or the known IPs differ, the method is not expected to work for that pair.

After preflight, it runs an e2e matrix through the local tunnel. The matrix tries the supported TLS fingerprints with one or two fake injections, both with and without real ClientHello fragmentation. `PASS` means the local tunnel completed a real HTTPS request; `FAIL` means that combination did not work in the current network conditions. If every case fails, try a different upstream IP or fake SNI. If only some cases pass, use one of the passing combinations for normal runs.

### Docker (prebuilt image)

Prebuilt images are published to GitHub Container Registry:

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

#### For Iranian users

If pulling from `ghcr.io` is slow/blocked, use a **local Docker registry mirror** (example below). The image name/tag is the same; only the registry host changes.

Also, if you don’t have Docker installed, you can use **Podman**, which is available in most Linux distributions’ package repositories.

```bash
# Debian/Ubuntu
sudo apt update && sudo apt install -y podman

# RHEL/CentOS/Fedora
sudo yum install -y podman

# Run from a local registry mirror (example):
podman run --rm -it \
  --network host \
  --cap-add NET_ADMIN --cap-add NET_RAW \
  ghcr.hamdocker.ir/aleskxyz/sni-spoofing-go:latest \
  -listen 127.0.0.1:40443 \
  -connect 104.19.229.21:443 \
  -fake-sni hcaptcha.com \
  -utls firefox
```

### Test (Cloudflare example)

This is a plain TCP proxy. It is not a SOCKS or HTTP proxy.

To make this method work in practice you usually need:

- A **working upstream IP** you can reach on `:443` (set via `-connect IP:443`). In general this should be an IP that actually serves TLS for the hostname you are testing, but depending on the network/DPI you may need to experiment.
- A **working decoy SNI** (set via `-fake-sni`) that your DPI allows. This depends on your network/DPI and may require experimentation.

Remember: the **real target SNI** comes from the client request (`Host`/URL), while `-fake-sni` is the **decoy SNI** that the DPI is intended to see.

Use `curl` with `--resolve` so the TLS SNI/host stays the hostname you’re testing while connecting to your local listener.

Example (ASCII-art PoC via `one.one.one.one`; decoy SNI = `hcaptcha.com`):

```bash
sudo ./sni-spoofing-linux-amd64 \
  -listen 127.0.0.1:40443 \
  -connect 104.19.229.21:443 \
  -fake-sni hcaptcha.com \
  -utls firefox

# PoC: fetch a real page through the local listener while keeping SNI/Host correct.
curl -sSLf --resolve one.one.one.one:40443:127.0.0.1 https://one.one.one.one:40443/ | grep '^\.\.'

# Expected output:
# ............................................................
# .........1............1............1............1...........
# ........11...........11...........11...........11...........
# .......111..........111..........111..........111...........
# ......1111.........1111.........1111.........1111...........
# ........11...........11...........11...........11...........
# ........11...........11...........11...........11...........
# ........11...........11...........11...........11...........
# ........11....ooo....11....ooo....11....ooo....11...........
# ......111111..ooo..111111..ooo..111111..ooo..111111.........
# ............................................................
```

## License

This project is licensed under the **GNU General Public License v3.0** — the same license as the [original SNI-Spoofing project](https://github.com/patterniha/SNI-Spoofing).

See [LICENSE](LICENSE) for details.

## Original Project

- **Repository:** [https://github.com/patterniha/SNI-Spoofing](https://github.com/patterniha/SNI-Spoofing)
- **Author:** [@patterniha](https://github.com/patterniha)
- **Language:** Python
- **License:** GPL-3.0
