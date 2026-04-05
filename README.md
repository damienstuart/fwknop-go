# fwknop-go

A Go implementation of [fwknop](https://www.cipherdyne.org/fwknop/) (FireWall KNock OPerator) — Single Packet Authorization (SPA) for strong service concealment. Compatible with the legacy C fwknop implementation (protocol version 3.0.0).

## Overview

This project provides three components:

- **fkospa** — A Go library implementing the fwknop SPA protocol (encryption, encoding, HMAC, decoding)
- **fwknop** — A CLI client for sending SPA requests
- **fwknopd** — A server daemon that receives and processes SPA packets

## Installation

### Library

```
go get github.com/damienstuart/fwknop-go/fkospa
```

### Binaries

```
go install github.com/damienstuart/fwknop-go/cmd/fwknop@latest
go install github.com/damienstuart/fwknop-go/cmd/fwknopd@latest
```

## Project Layout

```
fwknop-go/
├── fkospa/              # SPA protocol library
│   ├── spa.go           #   Message struct, New(), options
│   ├── spa_encode.go    #   Encode + Encrypt
│   ├── spa_decode.go    #   Decrypt + Decode
│   ├── encrypt.go       #   Encryption interfaces and mode dispatch
│   ├── aes_cbc.go       #   AES-CBC + legacy IV implementation
│   ├── kdf.go           #   Key derivation (EVP_BytesToKey)
│   ├── digest.go        #   Hash algorithms (MD5–SHA3-512)
│   ├── hmac.go          #   HMAC algorithms
│   ├── base64.go        #   SPA-style base64
│   └── testdata/        #   Golden test vectors from C library
├── cmd/
│   ├── fwknop/          # SPA client
│   │   ├── main.go      #   Entry point, SPA message assembly
│   │   ├── config.go    #   CLI flags, env vars, config loading
│   │   ├── rcfile.go    #   .fwknoprc parsing (legacy + YAML)
│   │   ├── resolve.go   #   External IP resolution via HTTPS
│   │   └── send.go      #   UDP packet sending
│   └── fwknopd/         # SPA server daemon
│       ├── main.go      #   Entry point, daemon management
│       ├── config.go    #   CLI flags, YAML config loading
│       ├── access.go    #   Access stanza parsing and matching
│       ├── server.go    #   UDP listener, SPA processing
│       ├── replay.go    #   In-memory replay cache with TTL
│       └── log.go       #   File + syslog logging
├── test/interop/        # Cross-validation configs for C server
├── docs/
├── go.mod
└── README.md
```

## Quick Start

### Generate keys

```bash
fwknop --key-gen
```
```
KEY_BASE64: <base64-rijndael-key>
HMAC_KEY_BASE64: <base64-hmac-key>
```

### Send an SPA request

```bash
fwknop -D server.example.com -A tcp/22 -R \
    --key-base64-rijndael '<key>' \
    --key-base64-hmac '<hmac-key>'
```

### Start the server

```bash
fwknopd -c /etc/fwknop/server.yaml -a /etc/fwknop/access.yaml
```

Or in foreground with verbose output for testing:

```bash
fwknopd -c server.yaml -a access.yaml -f -t -v
```

---

## Client (`fwknop`)

The client creates and sends SPA packets via UDP. It supports all 7 SPA message types, HMAC authentication, and multiple digest algorithms.

### Usage

```
fwknop [options]
```

### Key Options

| Flag | Description |
|------|-------------|
| `-D, --destination` | Hostname or IP of the fwknop server (required) |
| `-A, --access` | Ports/protocols to open, e.g. `tcp/22` (required) |
| `-a, --allow-ip` | Source IP to allow in the SPA packet |
| `-R, --resolve-ip` | Auto-resolve external IP via HTTPS |
| `-s, --source-ip` | Use `0.0.0.0` (allow any source) |
| `--key-base64-rijndael` | Base64-encoded encryption key |
| `--key-base64-hmac` | Base64-encoded HMAC key |
| `-n, --named-config` | Use a named stanza from `.fwknoprc` |
| `-N, --nat-access` | NAT access specification (IP,port) |
| `-C, --server-cmd` | Command for the server to execute |
| `-f, --fw-timeout` | Firewall rule timeout in seconds |
| `-T, --test` | Build the packet but don't send it |
| `-k, --key-gen` | Generate random encryption + HMAC keys |
| `-v, --verbose` | Verbose output (repeatable) |

Run `fwknop --help` for the full list.

### Configuration

The client loads configuration from three sources (highest priority wins):

1. **CLI flags** — `--destination`, `--access`, etc.
2. **Environment variables** — prefixed with `FWKNOP_` (e.g. `FWKNOP_DESTINATION`)
3. **RC file** — `~/.fwknoprc` (lowest priority)

#### RC file formats

The client supports two `.fwknoprc` formats, auto-detected on load:

**Legacy format** (compatible with the C client):

```ini
[default]
SPA_SERVER          192.168.1.100
ACCESS              tcp/22
KEY_BASE64          <base64-key>
HMAC_KEY_BASE64     <base64-hmac-key>

[production]
SPA_SERVER          prod.example.com
ACCESS              tcp/22,tcp/443
```

**YAML format:**

```yaml
default:
  destination: 192.168.1.100
  access: tcp/22
  key_base64_rijndael: <base64-key>
  key_base64_hmac: <base64-hmac-key>

production:
  destination: prod.example.com
  access: tcp/22,tcp/443
```

Select a named stanza with `-n`:

```bash
fwknop -n production -R
```

---

## Server (`fwknopd`)

The server listens for SPA packets on a UDP port, decrypts and validates them against access rules, and logs the results. Firewall integration is planned for a future release.

### Usage

```
fwknopd [options]
```

### Key Options

| Flag | Description |
|------|-------------|
| `-c, --config-file` | Server config YAML (default: `/etc/fwknop/server.yaml`) |
| `-a, --access-file` | Access rules YAML (default: `/etc/fwknop/access.yaml`) |
| `-f, --foreground` | Run in foreground (don't daemonize) |
| `-t, --test` | Test mode — parse packets and log, no actions |
| `-D, --dump-config` | Print resolved config and exit |
| `-K, --kill` | Kill a running fwknopd |
| `-R, --restart` | Restart a running fwknopd |
| `-S, --status` | Check if fwknopd is running |
| `-v, --verbose` | Verbose output |

### Server Configuration (`server.yaml`)

```yaml
udp_port: 62201
bind_address: "0.0.0.0"

log_file: /var/log/fwknop/fwknopd.log
syslog_identity: fwknopd
syslog_facility: daemon
verbose: false

pid_file: /var/run/fwknop/fwknopd.pid
run_dir: /var/run/fwknop

max_spa_packet_age: 120   # seconds
```

Configuration can also be set via environment variables prefixed with `FWKNOPD_` (e.g. `FWKNOPD_UDP_PORT=62201`).

### Access Rules (`access.yaml`)

Each entry defines who can send SPA requests and with what credentials:

```yaml
- source: "192.168.1.0/24"
  open_ports:
    - tcp/22
  key_base64: "<base64-rijndael-key>"
  hmac_key_base64: "<base64-hmac-key>"
  hmac_digest_type: sha256
  fw_access_timeout: 30
  require_source_address: true

- source: "ANY"
  open_ports:
    - tcp/22
    - tcp/443
  key_base64: "<base64-rijndael-key>"
  hmac_key_base64: "<base64-hmac-key>"
```

#### Access stanza fields

| Field | Description |
|-------|-------------|
| `source` | Source IP, CIDR, or `ANY` (required) |
| `open_ports` | List of `proto/port` strings |
| `key_base64` / `key` | Encryption key (base64 or plaintext) |
| `hmac_key_base64` / `hmac_key` | HMAC key (base64 or plaintext) |
| `hmac_digest_type` | HMAC algorithm (default: `sha256`) |
| `encryption_mode` | `cbc` (default) or `legacy` |
| `fw_access_timeout` | Firewall rule timeout in seconds |
| `require_username` | Require a specific username |
| `require_source_address` | Source IP in packet must match sender |
| `enable_cmd_exec` | Allow command execution |
| `cmd_exec_user` | User to run commands as |

---

## Library (`fkospa`)

The `fkospa` package provides the SPA protocol implementation as a Go library.

### Creating and sending an SPA message

```go
import "github.com/damienstuart/fwknop-go/fkospa"

m, err := fkospa.NewWithOptions(
    fkospa.WithAccessMsg("192.168.1.1,tcp/22"),
)
if err != nil {
    log.Fatal(err)
}

spaData, err := m.Encrypt([]byte("enc_key"), []byte("hmac_key"))
// spaData is the wire-format string to send via UDP.
```

### Decrypting a received SPA packet

```go
msg, err := fkospa.Decrypt(spaData, []byte("enc_key"), []byte("hmac_key"))
if err != nil {
    log.Fatal(err)
}
fmt.Printf("User: %s, Access: %s\n", msg.Username, msg.AccessMsg)
```

### Supported algorithms

| Category | Algorithms |
|----------|-----------|
| Encryption | AES-256-CBC (default), Legacy CBC IV |
| Digest | MD5, SHA1, SHA256 (default), SHA384, SHA512, SHA3-256, SHA3-512 |
| HMAC | MD5, SHA1, SHA256 (default), SHA384, SHA512, SHA3-256, SHA3-512 |

See `go doc github.com/damienstuart/fwknop-go/fkospa` for the full API reference.

---

## Compatibility

This implementation is cross-validated against the legacy C fwknop:

- **Encoding** — Go produces byte-identical encoded SPA messages to the C library
- **Cross-decryption** — Go client packets are accepted by the C fwknopd server
- **Round-trip** — Go client → Go server works end-to-end
- **Replay detection** — Duplicate packets are rejected

Tested with: SHA256, MD5, SHA384, SHA512, SHA3-256, SHA3-512 digests; AES-CBC and legacy IV modes; with and without HMAC; all 7 message types.

## License

GNU General Public License v2.0 — see [LICENSE](LICENSE) for details.
