# fkospa Developer Guide

The fkospa Go library for Single Packet Authorization (SPA).

**Version**: Protocol 3.0.0 | Compatible with C fwknop

---

## Table of Contents

1. [Introduction](#introduction)
2. [Getting Started](#getting-started)
3. [SPA Data Format](#spa-data-format)
4. [SPA Parameter Types](#spa-parameter-types)
5. [Creating SPA Messages](#creating-spa-messages)
6. [Encrypting SPA Messages](#encrypting-spa-messages)
7. [Decrypting and Parsing SPA Messages](#decrypting-and-parsing-spa-messages)
8. [Advanced Topics](#advanced-topics)
9. [Error Handling](#error-handling)
10. [API Reference Summary](#api-reference-summary)
11. [Compatibility with C fwknop](#compatibility-with-c-fwknop)

---

## Introduction

The `fkospa` package implements the fwknop Single Packet Authorization (SPA) protocol in Go. It provides the functionality needed to create, encrypt, decrypt, and parse SPA messages compatible with the legacy C [fwknop](https://www.cipherdyne.org/fwknop/) implementation.

**SPA** (Single Packet Authorization) is an authorization scheme for strong service concealment. SPA requires only a single packet which is encrypted, non-replayable, and authenticated via an HMAC in order to communicate desired access to a service that is hidden behind a firewall in a default-drop filtering stance. The main application of SPA is to use a firewall to drop all attempts to connect to services such as SSH, making the exploitation of vulnerabilities (both 0-day and unpatched code) more difficult. Because there are no open ports, any service concealed by SPA cannot be scanned for with Nmap.

The `fkospa` package is not an implementation of an fwknop client or server. It simply provides the functions for managing the SPA data used by those programs. The `fwknop` client and `fwknopd` server programs in this project use `fkospa` for their SPA handling.

### Features

- **Complete SPA protocol implementation** -- create, encrypt, decrypt, decode, and verify SPA messages
- **Seven hash algorithms** -- MD5, SHA1, SHA256, SHA384, SHA512, SHA3-256, SHA3-512 for both digests and HMAC
- **AES-256-CBC encryption** -- with EVP_BytesToKey key derivation for C compatibility
- **Legacy IV mode** -- backward compatibility with older fwknop clients
- **All seven message types** -- access, NAT access, local NAT, command, and timeout variants
- **HMAC authentication** -- encrypt-then-authenticate model
- **Wire-format compatible** -- produces messages accepted by the C fwknopd server
- **Idiomatic Go API** -- functional options, exported struct fields, standard error handling

---

## Getting Started

### Installation

```
go get github.com/damienstuart/fwknop-go/fkospa
```

### Import

```go
import "github.com/damienstuart/fwknop-go/fkospa"
```

### Quick Example

```go
package main

import (
    "fmt"
    "log"

    "github.com/damienstuart/fwknop-go/fkospa"
)

func main() {
    // Create a message requesting SSH access.
    msg, err := fkospa.NewWithOptions(
        fkospa.WithAccessMsg("192.168.1.50,tcp/22"),
    )
    if err != nil {
        log.Fatal(err)
    }

    // Encrypt with shared keys.
    spaData, err := msg.Encrypt([]byte("encryption_key"), []byte("hmac_key"))
    if err != nil {
        log.Fatal(err)
    }

    // spaData is the wire-format string to send via UDP.
    fmt.Println("SPA data length:", len(spaData))
}
```

### Compatibility Note

This package produces SPA messages using protocol version 3.0.0, which is accepted by the legacy C fwknopd server. See [Compatibility with C fwknop](#compatibility-with-c-fwknop) for details on cross-validation and known differences.

---

## SPA Data Format

The SPA plaintext is a colon-delimited string of fields, some of which are base64-encoded. The complete format (before encryption) is:

```
RAND_VAL : B64(USERNAME) : TIMESTAMP : VERSION : MSG_TYPE : B64(MESSAGE) [: B64(NAT_ACCESS)] [: B64(SERVER_AUTH)] [: CLIENT_TIMEOUT] : DIGEST
```

### Field Descriptions

| Field | Default | Description |
|-------|---------|-------------|
| `RandVal` | Random (auto-generated) | A 16-character decimal numeric string used as a nonce to prevent replay attacks. |
| `Username` | Current OS user | The username associated with this SPA request. Base64-encoded in the wire format. |
| `Timestamp` | Current time | Unix timestamp value. Used by the server to check packet freshness. |
| `Version` | `3.0.0` | The SPA protocol version. Not user-settable. |
| `MessageType` | `AccessMsg` (1) | The SPA message type value. Determines the format and purpose of the message. |
| `AccessMsg` | *(must be set)* | The SPA message content -- an access request or command string. Base64-encoded. |
| `NATAccess` | *(empty)* | Optional NAT access request. Required for NAT message types. Base64-encoded. |
| `ServerAuth` | *(empty)* | Optional server authentication string. Base64-encoded. |
| `ClientTimeout` | 0 | Optional timeout value (seconds) the client requests for the access rule. |
| `DigestType` | `DigestSHA256` | The hash algorithm used for the message integrity digest. |
| `EncryptionMode` | `EncryptionModeCBC` | The AES block cipher mode. |
| `HMACType` | `HMACSHA256` | The HMAC algorithm for message authentication. |

### Example Plaintext

With all fields populated, an unencrypted SPA message looks like:

```
8307540982176539:anVzZXI:1230665172:3.0.0:1:MTkyLjE2OC4xLjEsdGNwLzIy:MTAuMC4wLjEsMjI:Y3J5cHQsbXlwdw:120:xswj8V0zMR7/7MV9pQRarSKWG1l9Zfjv+kbXaKrJ+RA
```

In this example: random value, base64("juser"), timestamp, version 3.0.0, message type 1 (access), base64("192.168.1.1,tcp/22"), base64 NAT access, base64 server auth, timeout 120, and SHA256 digest.

For most fields, you need not be concerned about the format as fkospa handles encoding and validation automatically. The exceptions are `AccessMsg`, `NATAccess`, and `ServerAuth`, whose content formats are described under [Message Types](#message-types).

---

## SPA Parameter Types

### Digest Types

The SPA data includes a message digest hash as one of the fields, used to verify the data's integrity after decryption. The digest is base64-encoded before being appended.

| Constant | Value | Algorithm |
|----------|-------|-----------|
| `DigestMD5` | 1 | MD5 |
| `DigestSHA1` | 2 | SHA-1 |
| `DigestSHA256` | 3 | SHA-256 **(default)** |
| `DigestSHA384` | 4 | SHA-384 |
| `DigestSHA512` | 5 | SHA-512 |
| `DigestSHA3_256` | 6 | SHA3-256 |
| `DigestSHA3_512` | 7 | SHA3-512 |

SHA256 is the default. You only need to set the digest type explicitly if you want a different algorithm.

### Message Types

The message type determines the format and purpose of the `AccessMsg` field. Seven types are supported:

| Constant | Value | Description | AccessMsg Format |
|----------|-------|-------------|-----------------|
| `CommandMsg` | 0 | Execute a command on the server | `<IP>,<command text>` |
| `AccessMsg` | 1 | Basic access request **(default)** | `<IP>,<proto>/<port>` |
| `NATAccessMsg` | 2 | Access with NAT forwarding | `<IP>,<proto>/<port>` + NATAccess field |
| `ClientTimeoutAccessMsg` | 3 | Access with client-specified timeout | Same as AccessMsg |
| `ClientTimeoutNATAccessMsg` | 4 | NAT access with client timeout | Same as NATAccessMsg |
| `LocalNATAccessMsg` | 5 | NAT to a local service (127.0.0.1) | `<IP>,<proto>/<port>` + NATAccess field |
| `ClientTimeoutLocalNATAccessMsg` | 6 | Local NAT with client timeout | Same as LocalNATAccessMsg |

**AccessMsg format examples:**

```
"192.168.1.2,tcp/22"          -- access request for SSH
"192.168.1.2,tcp/22,udp/5005" -- multiple protocol/port entries
```

**CommandMsg format:**

```
"192.168.1.2,uname -a"        -- command to execute
```

**NATAccess format (separate field):**

```
"10.10.1.2,9922"              -- internal IP and port
```

The timeout message types (`ClientTimeoutAccessMsg`, etc.) are typically not set directly. Instead, set `ClientTimeout > 0` and fkospa will automatically adjust the message type. See [Client Timeout](#client-timeout-and-message-type-auto-adjustment).

### Encryption Modes

| Constant | Value | Status | Description |
|----------|-------|--------|-------------|
| `EncryptionModeECB` | 1 | Stub | Not implemented |
| `EncryptionModeCBC` | 2 | **Default** | AES-256-CBC with EVP_BytesToKey |
| `EncryptionModeCFB` | 3 | Stub | Not implemented |
| `EncryptionModePCBC` | 4 | Stub | Not implemented |
| `EncryptionModeOFB` | 5 | Stub | Not implemented |
| `EncryptionModeCTR` | 6 | Stub | Not implemented |
| `EncryptionModeCBCLegacy` | 8 | Implemented | CBC with legacy IV passphrase padding |

**AES-256-CBC** (`EncryptionModeCBC`) is the default and recommended mode. The encryption key is derived from a passphrase using the OpenSSL-compatible `EVP_BytesToKey` algorithm with MD5, producing a 256-bit key and 128-bit IV.

**Legacy IV mode** (`EncryptionModeCBCLegacy`) pads short passphrases (< 16 bytes) with `'0'` characters before key derivation. This exists for backward compatibility with older fwknop clients.

Mode 7 is intentionally skipped to match the C fwknop enum values. Stub modes return `ErrUnsupportedEncryptionMode`.

### HMAC Types

The HMAC provides message authentication using the encrypt-then-authenticate model. The HMAC is computed over the base64-encoded ciphertext and appended to the wire-format string.

| Constant | Value | Algorithm |
|----------|-------|-----------|
| `HMACMD5` | 1 | HMAC-MD5 |
| `HMACSHA1` | 2 | HMAC-SHA1 |
| `HMACSHA256` | 3 | HMAC-SHA256 **(default)** |
| `HMACSHA384` | 4 | HMAC-SHA384 |
| `HMACSHA512` | 5 | HMAC-SHA512 |
| `HMACSHA3_256` | 6 | HMAC-SHA3-256 |
| `HMACSHA3_512` | 7 | HMAC-SHA3-512 |

HMAC types mirror the digest types by design -- both use the same underlying hash algorithms. The HMAC key is separate from the encryption key and should be generated independently.

---

## Creating SPA Messages

### The Message Struct

The `Message` struct represents a single SPA message:

```go
type Message struct {
    RandVal        string         // 16-digit random nonce
    Username       string         // Username (from OS by default)
    Timestamp      time.Time      // Message timestamp
    MessageType    MessageType    // SPA message type
    AccessMsg      string         // Access request or command
    NATAccess      string         // Optional NAT access string
    ServerAuth     string         // Optional server auth
    ClientTimeout  uint32         // Optional timeout (seconds)
    DigestType     DigestType     // Hash algorithm for digest
    EncryptionMode EncryptionMode // AES block cipher mode
    HMACType       HMACType       // HMAC algorithm
}
```

Unlike the C library which uses an opaque context with getter/setter functions, fkospa uses exported struct fields. You can read and modify fields directly. Validation occurs at encode/encrypt time, not when setting fields.

### Creating with Defaults

Use `New()` to create a message with all defaults populated:

```go
msg, err := fkospa.New()
if err != nil {
    log.Fatal(err)
}
// msg now has: random nonce, OS username, current timestamp,
// AccessMsg type, SHA256 digest, CBC encryption, SHA256 HMAC.
// You must still set AccessMsg before encrypting.
msg.AccessMsg = "192.168.1.50,tcp/22"
```

### Creating with Options

Use `NewWithOptions()` with functional options for a more declarative approach:

```go
msg, err := fkospa.NewWithOptions(
    fkospa.WithUsername("alice"),
    fkospa.WithAccessMsg("192.168.1.50,tcp/22"),
    fkospa.WithDigestType(fkospa.DigestSHA512),
    fkospa.WithHMACType(fkospa.HMACSHA512),
)
```

### Available Options

| Option | Description |
|--------|-------------|
| `WithRandVal(val)` | Set the random value (must be exactly 16 decimal digits) |
| `WithUsername(u)` | Set the username |
| `WithTimestamp(t)` | Set an explicit timestamp |
| `WithTimestampOffset(d)` | Set timestamp to `time.Now().Add(d)` |
| `WithMessageType(mt)` | Set the message type |
| `WithAccessMsg(msg)` | Set the access message or command string |
| `WithNATAccess(nat)` | Set the NAT access string |
| `WithServerAuth(auth)` | Set the server authentication string |
| `WithClientTimeout(secs)` | Set the client timeout (adjusts message type automatically) |
| `WithDigestType(dt)` | Set the digest hash algorithm |
| `WithEncryptionMode(mode)` | Set the AES encryption mode |
| `WithHMACType(ht)` | Set the HMAC algorithm |

Options validate their input and return an error if invalid (e.g., an unrecognized digest type).

### Required Fields

Before encryption, the following must be set (either by defaults or explicitly):

- **RandVal** -- auto-generated by `New()`/`NewWithOptions()`
- **Username** -- auto-detected from OS by default
- **Timestamp** -- set to `time.Now()` by default
- **AccessMsg** -- **must be explicitly set** (no default)

For NAT message types, `NATAccess` must also be set.

---

## Encrypting SPA Messages

### Basic Encryption

Once a message is created, call `Encrypt()` to produce the wire-format string:

```go
encKey := []byte("my_encryption_passphrase")
hmacKey := []byte("my_hmac_key")

spaData, err := msg.Encrypt(encKey, hmacKey)
if err != nil {
    log.Fatal(err)
}
// spaData is the string to send via UDP to the fwknop server.
```

### Parameters

- **encKey** (required): The encryption passphrase. Used as input to EVP_BytesToKey to derive the AES-256 key and IV.
- **hmacKey** (optional): The HMAC key. If nil or empty, HMAC is skipped. **Using HMAC is strongly recommended.**

### What Encrypt Does

1. **Encode** -- Builds the colon-delimited plaintext from the message fields, computes the digest, and appends it.
2. **Encrypt** -- Encrypts the plaintext using AES-256-CBC (or the configured mode) with a random salt. Produces output in OpenSSL's `"Salted__" + salt + ciphertext` format.
3. **Base64 encode** -- Encodes the ciphertext as base64.
4. **Strip prefix** -- Removes the first 10 characters (`U2FsdGVkX1`, the base64 of `"Salted__"`) from the output. This is a protocol detail: the prefix is constant and omitted from the wire format to save space.
5. **Compute HMAC** -- If an HMAC key is provided, computes the HMAC over the **full** base64 string (including the stripped prefix) and appends it.

The final wire format is: `stripped_ciphertext + hmac_base64` (no separator).

### Key Generation

Use `GenerateKey()` and `GenerateHMACKey()` to create cryptographically random keys:

```go
encKey, err := fkospa.GenerateKey(32)    // 32-byte (256-bit) key, returned as base64
hmacKey, err := fkospa.GenerateHMACKey(32)
```

Both functions return standard base64-encoded strings suitable for use in configuration files. When using these keys with `Encrypt()`, decode them from base64 first:

```go
keyBytes, _ := base64.StdEncoding.DecodeString(encKey)
hmacBytes, _ := base64.StdEncoding.DecodeString(hmacKey)
spaData, err := msg.Encrypt(keyBytes, hmacBytes)
```

### The Encode Function

For debugging or testing, you can call `Encode()` directly to get the plaintext (before encryption):

```go
plaintext, err := msg.Encode()
// plaintext is the colon-delimited string with digest appended.
```

This is the intermediate representation that would be encrypted. It is not useful for transmission -- always use `Encrypt()` for actual SPA messages.

---

## Decrypting and Parsing SPA Messages

### Basic Decryption

Use the `Decrypt()` function to verify, decrypt, decode, and parse an incoming SPA message:

```go
msg, err := fkospa.Decrypt(spaData, encKey, hmacKey)
if err != nil {
    log.Fatal(err) // HMAC failure, decryption failure, or invalid data
}

fmt.Println("Username:", msg.Username)
fmt.Println("Access:", msg.AccessMsg)
fmt.Println("Type:", msg.MessageType)
fmt.Println("Timestamp:", msg.Timestamp)
```

### Parameters

- **spaData**: The wire-format SPA string (as received via UDP).
- **encKey**: The encryption passphrase (must match the sender's key).
- **hmacKey**: The HMAC key. If nil or empty, HMAC verification is skipped. **If the sender used HMAC, the receiver must verify it.**
- **opts**: Optional `DecryptOption` values to configure decryption behavior.

### Decrypt Options

| Option | Description |
|--------|-------------|
| `WithDecryptMode(mode)` | Set the encryption mode (default: `EncryptionModeCBC`) |
| `WithDecryptHMACType(ht)` | Set the expected HMAC type (default: `HMACSHA256`) |

Example with non-default options:

```go
msg, err := fkospa.Decrypt(spaData, encKey, hmacKey,
    fkospa.WithDecryptMode(fkospa.EncryptionModeCBCLegacy),
    fkospa.WithDecryptHMACType(fkospa.HMACSHA512),
)
```

### What Decrypt Does

1. **Restore prefix** -- Re-adds the `B64SaltPrefix` (`"U2FsdGVkX1"`) that was stripped during encryption.
2. **Verify HMAC** -- If an HMAC key is provided, splits the HMAC from the ciphertext (based on the expected HMAC length for the algorithm), recomputes, and compares using constant-time comparison.
3. **Base64 decode** -- Decodes the ciphertext.
4. **Decrypt** -- Decrypts using the configured mode and passphrase-derived key.
5. **Parse** -- Splits the plaintext on colons, decodes base64 fields, and populates the `Message` struct.
6. **Verify digest** -- Computes the digest of the encoded fields and compares it to the digest in the message. If SHA256 fails, automatically tries SHA3-256 (and similarly SHA512/SHA3-512) since they produce the same base64 length.

### Accessing Parsed Fields

After successful decryption, all fields are available on the returned `Message` struct:

```go
msg.RandVal        // "8307540982176539"
msg.Username       // "alice"
msg.Timestamp      // time.Time
msg.MessageType    // fkospa.AccessMsg
msg.AccessMsg      // "192.168.1.50,tcp/22"
msg.NATAccess      // "" (empty if not a NAT message)
msg.ServerAuth     // "" (empty if not set)
msg.ClientTimeout  // 0 (zero if not set)
msg.DigestType     // fkospa.DigestSHA256 (detected from the message)
```

---

## Advanced Topics

### NAT Access Messages

NAT access messages tell the fwknop server to create a NAT/forwarding rule in addition to the access rule. Use `NATAccessMsg` or `LocalNATAccessMsg` (for forwarding to 127.0.0.1):

```go
msg, err := fkospa.NewWithOptions(
    fkospa.WithMessageType(fkospa.NATAccessMsg),
    fkospa.WithAccessMsg("203.0.113.50,tcp/22"),
    fkospa.WithNATAccess("10.0.1.100,22"),
)
```

The `NATAccess` field format is `"<internal_IP>,<port>"`.

For local NAT (forwarding to a service on the server itself):

```go
fkospa.WithMessageType(fkospa.LocalNATAccessMsg)
fkospa.WithNATAccess("127.0.0.1,8080")
```

### Command Messages

Command messages request the server to execute an arbitrary command instead of managing firewall rules:

```go
msg, err := fkospa.NewWithOptions(
    fkospa.WithMessageType(fkospa.CommandMsg),
    fkospa.WithAccessMsg("uname -a"),
)
```

The server must have `enable_cmd_exec: true` in its access stanza to honor command messages.

### Client Timeout and Message Type Auto-Adjustment

When `ClientTimeout` is set to a value greater than zero, the message type is automatically adjusted during encoding:

- `AccessMsg` becomes `ClientTimeoutAccessMsg`
- `NATAccessMsg` becomes `ClientTimeoutNATAccessMsg`
- `LocalNATAccessMsg` becomes `ClientTimeoutLocalNATAccessMsg`
- `CommandMsg` is not adjusted (timeouts don't apply to commands)

You can set the timeout without manually changing the message type:

```go
msg, err := fkospa.NewWithOptions(
    fkospa.WithAccessMsg("10.0.0.1,tcp/22"),
    fkospa.WithClientTimeout(60), // 60-second timeout
)
// msg.MessageType is still AccessMsg, but will be encoded as
// ClientTimeoutAccessMsg (3) in the wire format.
```

### Server Auth Field

The optional server auth field provides an additional authentication mechanism:

```go
fkospa.WithServerAuth("my_server_token")
```

This field is rarely used in practice but is preserved for protocol completeness.

### Legacy IV Encryption Mode

For backward compatibility with older fwknop clients that use shorter passphrases:

```go
msg, err := fkospa.NewWithOptions(
    fkospa.WithAccessMsg("10.0.0.1,tcp/22"),
    fkospa.WithEncryptionMode(fkospa.EncryptionModeCBCLegacy),
)

// Decrypt must also specify legacy mode:
decoded, err := fkospa.Decrypt(spaData, key, hmacKey,
    fkospa.WithDecryptMode(fkospa.EncryptionModeCBCLegacy),
)
```

In legacy mode, passphrases shorter than 16 bytes are right-padded with `'0'` characters before key derivation.

### Custom Key Derivation

The `KeyDeriver` interface allows custom key derivation algorithms:

```go
type KeyDeriver interface {
    DeriveKeyAndIV(passphrase []byte, salt []byte, keyLen int, ivLen int) (key []byte, iv []byte, err error)
}
```

The default implementation is `EVPBytesToKey`, which uses the OpenSSL-compatible MD5-based PBKDF1 algorithm. This must be used for compatibility with the C fwknop implementation.

### Custom Encryption

The `Encrypter` and `Decrypter` interfaces allow custom encryption implementations:

```go
type Encrypter interface {
    Encrypt(plaintext []byte, key []byte) ([]byte, error)
}

type Decrypter interface {
    Decrypt(ciphertext []byte, key []byte) ([]byte, error)
}

type EncryptDecrypter interface {
    Encrypter
    Decrypter
}
```

These interfaces are used internally by the encryption mode dispatch system. Custom implementations would need to produce output in the `"Salted__" + salt + ciphertext` format for wire compatibility.

---

## Error Handling

All fkospa functions that can fail return a Go `error`. The package defines sentinel errors that can be checked with `errors.Is()`:

| Error | Description |
|-------|-------------|
| `ErrInvalidData` | Input data is malformed or out of range |
| `ErrMessageTooLarge` | Encoded SPA message exceeds the 1500-byte size limit |
| `ErrMissingField` | A required SPA field is empty or unset |
| `ErrDigestVerificationFailed` | The decoded message digest does not match (data corruption or wrong key) |
| `ErrHMACVerificationFailed` | The HMAC on encrypted data does not match (wrong HMAC key or tampering) |
| `ErrDecryptionFailed` | Decryption produced invalid plaintext (wrong encryption key) |
| `ErrUnsupportedEncryptionMode` | The requested encryption mode is not implemented (stub modes) |
| `ErrInvalidKeyLen` | The encryption or HMAC key length is invalid |
| `ErrUnsupportedDigestType` | Unknown or invalid digest algorithm |
| `ErrUnsupportedHMACType` | Unknown or invalid HMAC algorithm |

### Example Error Handling

```go
msg, err := fkospa.Decrypt(spaData, encKey, hmacKey)
if err != nil {
    if errors.Is(err, fkospa.ErrHMACVerificationFailed) {
        log.Println("HMAC mismatch -- wrong key or tampered data")
    } else if errors.Is(err, fkospa.ErrDecryptionFailed) {
        log.Println("Decryption failed -- wrong encryption key")
    } else if errors.Is(err, fkospa.ErrDigestVerificationFailed) {
        log.Println("Digest mismatch -- data corruption")
    } else {
        log.Printf("SPA processing error: %v", err)
    }
    return
}
```

---

## API Reference Summary

### Types

| Type | Description |
|------|-------------|
| `Message` | Represents a single SPA message with all fields |
| `Option` | Functional option for configuring a Message (`func(*Message) error`) |
| `DecryptOption` | Functional option for configuring decryption behavior |
| `MessageType` | Enum for SPA message types (0-6) |
| `DigestType` | Enum for hash algorithms (1-7) |
| `HMACType` | Enum for HMAC algorithms (1-7) |
| `EncryptionMode` | Enum for AES block cipher modes |
| `Encrypter` | Interface for encryption implementations |
| `Decrypter` | Interface for decryption implementations |
| `EncryptDecrypter` | Combined Encrypter + Decrypter interface |
| `KeyDeriver` | Interface for key derivation algorithms |
| `EVPBytesToKey` | OpenSSL-compatible key derivation implementation |

### Functions

| Function | Description |
|----------|-------------|
| `New()` | Create a Message with defaults |
| `NewWithOptions(opts...)` | Create a Message with functional options |
| `Decrypt(spaData, encKey, hmacKey, opts...)` | Verify, decrypt, decode, and parse SPA data |
| `Digest(dt, data)` | Compute a raw hash digest |
| `DigestBase64(dt, data)` | Compute a hash digest as SPA-style base64 |
| `ComputeHMAC(ht, data, key)` | Compute a raw HMAC |
| `ComputeHMACBase64(ht, data, key)` | Compute an HMAC as SPA-style base64 |
| `VerifyHMAC(ht, data, key, expected)` | Verify an HMAC (constant-time comparison) |
| `GenerateKey(keyLen)` | Generate a random encryption key (base64 string) |
| `GenerateHMACKey(keyLen)` | Generate a random HMAC key (base64 string) |
| `B64Encode(data)` | Encode bytes as SPA-style base64 (trailing `=` stripped) |
| `B64Decode(s)` | Decode SPA-style base64 (restores padding) |

### Methods on Message

| Method | Description |
|--------|-------------|
| `Encode()` | Build the plaintext wire format with digest (before encryption) |
| `Encrypt(encKey, hmacKey)` | Encode, encrypt, and optionally HMAC -- returns the wire-format string |

### Constants

| Constant | Value | Description |
|----------|-------|-------------|
| `ProtocolVersion` | `"3.0.0"` | The SPA protocol version |
| `B64SaltPrefix` | `"U2FsdGVkX1"` | Base64 of `"Salted__"`, stripped from wire format |

---

## Compatibility with C fwknop

### Wire Format Compatibility

The fkospa package produces SPA messages that are fully compatible with the C fwknop implementation (protocol version 3.0.0). This has been verified through:

- **Encoding compatibility** -- Go's `Encode()` produces byte-identical output to C's `fko_encode_spa_data()` for the same inputs.
- **Cross-decryption** -- SPA packets encrypted by the C library are successfully decrypted by Go, and vice versa.
- **Interoperability testing** -- Go client packets are accepted by the C fwknopd server in live testing.

### Golden Test Vectors

The package includes 8 golden test vectors generated by the C library (`fkospa/testdata/golden_vectors.txt`) covering:

- SHA256, MD5, SHA512, SHA1 digests
- AES-CBC and legacy IV encryption modes
- With and without HMAC
- NAT access, client timeout, and server auth fields

### Known Differences

**SHA1 on macOS**: The C fwknop SHA1 implementation (`lib/sha1.c`) has a byte-order detection bug on macOS that produces non-standard SHA1 hashes. The Go implementation uses standard SHA1. The SHA1 golden test is skipped on platforms where this bug is present.

**PKCS7 padding tolerance**: The C implementation silently accepts invalid PKCS7 padding during decryption. The Go implementation matches this behavior for compatibility, meaning decryption with a wrong key may produce garbage data rather than an immediate error. The digest verification step catches this case.

**Wire format prefix stripping**: The C function `fko_get_spa_data()` strips the first 10 characters (`"U2FsdGVkX1"`, the base64 of `"Salted__"`) from the encrypted data before returning it. The HMAC is computed on the full data (with prefix), but the wire format omits it. The Go implementation matches this behavior exactly.

---

*This guide is for fkospa protocol version 3.0.0. For the complete API documentation, see `go doc github.com/damienstuart/fwknop-go/fkospa`.*
