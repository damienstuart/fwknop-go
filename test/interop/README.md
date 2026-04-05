# Go Client ↔ C Server Interop Test

## Setup

Shared test keys (already in config files):
```
KEY_BASE64:      bcPRKXdUB6gQblanFrvjggk6YlcTzgBe3peIInFai/c=
HMAC_KEY_BASE64: ii0oj8m74w0d9+JJrqv5I0z7lxDPb5ECLfQjvJPgGEc=
```

## Running

### Terminal 1: Start the C fwknopd server

```bash
cd /Users/dstuart/projects/fwknop
sudo server/.libs/fwknopd \
    -c fwknop-go/test/interop/fwknopd.conf \
    -a fwknop-go/test/interop/access.conf \
    -f -t -v
```

Note: `sudo` may be needed for binding to the UDP port. Use `-f` (foreground)
and `-t` (test mode, no firewall changes).

### Terminal 2: Send from Go client

```bash
cd /Users/dstuart/projects/fwknop/fwknop-go
go run ./cmd/fwknop \
    -D 127.0.0.1 \
    -A tcp/22 \
    -a 127.0.0.1 \
    --key-base64 'bcPRKXdUB6gQblanFrvjggk6YlcTzgBe3peIInFai/c=' \
    --key-base64-hmac 'ii0oj8m74w0d9+JJrqv5I0z7lxDPb5ECLfQjvJPgGEc=' \
    -v
```

## What to look for

**Success** — the C server output will show:
- "SPA Packet from IP: 127.0.0.1" 
- Successful HMAC verification
- Successful decryption
- Parsed fields (username, access request, timestamp, etc.)

**Failure** — look for error messages about:
- HMAC verification failed → key mismatch or wire format issue
- Decryption failed → encryption key or format issue  
- Digest verification failed → encoding format mismatch
