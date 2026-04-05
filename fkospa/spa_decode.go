package fkospa

import (
	"crypto/subtle"
	"fmt"
	"strconv"
	"strings"
	"time"
)

// Known base64 digest lengths (without trailing '=') for each algorithm.
const (
	md5B64Len     = 22
	sha1B64Len    = 27
	sha256B64Len  = 43 // also SHA3-256
	sha384B64Len  = 64
	sha512B64Len  = 86 // also SHA3-512
)

// DecryptOption configures decryption behavior.
type DecryptOption func(*decryptConfig)

type decryptConfig struct {
	encMode  EncryptionMode
	hmacType HMACType
}

func WithDecryptMode(mode EncryptionMode) DecryptOption {
	return func(c *decryptConfig) { c.encMode = mode }
}

func WithDecryptHMACType(ht HMACType) DecryptOption {
	return func(c *decryptConfig) { c.hmacType = ht }
}

// Decrypt takes base64-encoded SPA data, optionally verifies the HMAC,
// decrypts, decodes, and returns a populated Message.
//
//   - spaData: the wire-format SPA string
//   - encKey: encryption passphrase
//   - hmacKey: HMAC key (if nil or empty, HMAC verification is skipped)
//   - opts: optional configuration (encryption mode, HMAC type)
func Decrypt(spaData string, encKey []byte, hmacKey []byte, opts ...DecryptOption) (*Message, error) {
	cfg := &decryptConfig{
		encMode:  EncModeCBC,
		hmacType: HMACSHA256,
	}
	for _, o := range opts {
		o(cfg)
	}

	// The wire format has the "U2FsdGVkX1" prefix stripped. Re-add it for
	// HMAC verification and decryption. See fko_get_spa_data() in C code.
	b64WithPrefix := B64RijndaelSalt + spaData

	// If HMAC key is provided, the HMAC was computed on the full b64
	// ciphertext (with prefix), and is appended after the stripped ciphertext.
	// So the wire format is: stripped_ciphertext + hmac.
	// We need to split the HMAC from spaData, re-add prefix to the ciphertext
	// portion, then verify HMAC.
	if len(hmacKey) > 0 {
		hmacLen := hmacB64Len(cfg.hmacType)
		if hmacLen == 0 {
			return nil, fmt.Errorf("%w: %d", ErrUnsupportedHMACType, cfg.hmacType)
		}
		if len(spaData) <= hmacLen {
			return nil, fmt.Errorf("%w: SPA data too short for HMAC", ErrHMACVerificationFailed)
		}

		// Split: stripped_ciphertext | hmac
		strippedCiphertext := spaData[:len(spaData)-hmacLen]
		hmacFromData := spaData[len(spaData)-hmacLen:]

		// HMAC was computed on full b64 (with prefix).
		fullB64 := B64RijndaelSalt + strippedCiphertext
		computedHMAC, err := ComputeHMACBase64(cfg.hmacType, []byte(fullB64), hmacKey)
		if err != nil {
			return nil, err
		}
		if subtle.ConstantTimeCompare([]byte(hmacFromData), []byte(computedHMAC)) != 1 {
			return nil, ErrHMACVerificationFailed
		}

		b64WithPrefix = fullB64
	}

	// Base64-decode the ciphertext (with prefix restored).
	ciphertext, err := B64Decode(b64WithPrefix)
	if err != nil {
		return nil, fmt.Errorf("%w: base64 decode failed: %v", ErrDecryptionFailed, err)
	}

	// Decrypt.
	enc, err := encrypterFor(cfg.encMode)
	if err != nil {
		return nil, err
	}

	plaintext, err := enc.Decrypt(ciphertext, encKey)
	if err != nil {
		return nil, err
	}

	// Parse the decrypted plaintext into a Message.
	return decodePlaintext(string(plaintext))
}

// hmacB64Len returns the base64 length (without padding) for each HMAC type.
func hmacB64Len(ht HMACType) int {
	switch ht {
	case HMACMD5:
		return md5B64Len
	case HMACSHA1:
		return sha1B64Len
	case HMACSHA256:
		return sha256B64Len
	case HMACSHA384:
		return sha384B64Len
	case HMACSHA512:
		return sha512B64Len
	case HMACSHA3256:
		return sha256B64Len // same length as SHA256
	case HMACSHA3512:
		return sha512B64Len // same length as SHA512
	default:
		return 0
	}
}

// decodePlaintext parses the decrypted plaintext into a Message.
// Format: RAND_VAL:B64(USER):TIMESTAMP:VERSION:MSGTYPE:B64(MSG)[:B64(NAT)][:B64(AUTH)][:TIMEOUT]:DIGEST
func decodePlaintext(plaintext string) (*Message, error) {
	// The digest is the last field. First, determine the number of colons
	// to find the last field boundary.
	lastColon := strings.LastIndex(plaintext, ":")
	if lastColon < 0 {
		return nil, fmt.Errorf("%w: no fields found", ErrInvalidData)
	}

	digest := plaintext[lastColon+1:]
	encodedMsg := plaintext[:lastColon]

	// Detect digest type from length and verify it.
	digestType, err := detectDigestType(len(digest))
	if err != nil {
		return nil, err
	}

	if err := verifyDigest(encodedMsg, digest, digestType); err != nil {
		return nil, err
	}

	// Parse the encoded fields.
	fields := strings.Split(encodedMsg, ":")
	numFields := len(fields)

	if numFields < minSPAFields || numFields > maxSPAFields {
		return nil, fmt.Errorf("%w: expected %d-%d fields, got %d",
			ErrInvalidData, minSPAFields, maxSPAFields, numFields)
	}

	m := &Message{
		DigestType: digestType,
	}

	// Field 0: rand_val
	m.RandVal = fields[0]

	// Field 1: base64-encoded username
	userBytes, err := B64Decode(fields[1])
	if err != nil {
		return nil, fmt.Errorf("%w: decoding username: %v", ErrInvalidData, err)
	}
	m.Username = string(userBytes)

	// Field 2: timestamp
	ts, err := strconv.ParseInt(fields[2], 10, 64)
	if err != nil {
		return nil, fmt.Errorf("%w: invalid timestamp: %v", ErrInvalidData, err)
	}
	m.Timestamp = time.Unix(ts, 0)

	// Field 3: version (we validate but don't store separately)
	// The version is part of the wire format but not a settable field.

	// Field 4: message type
	mt, err := strconv.Atoi(fields[4])
	if err != nil {
		return nil, fmt.Errorf("%w: invalid message type: %v", ErrInvalidData, err)
	}
	m.MessageType = MessageType(mt)

	// Field 5: base64-encoded message
	msgBytes, err := B64Decode(fields[5])
	if err != nil {
		return nil, fmt.Errorf("%w: decoding message: %v", ErrInvalidData, err)
	}
	m.AccessMsg = string(msgBytes)

	// Remaining fields depend on message type and count.
	idx := 6
	if idx < numFields && m.MessageType.requiresNATAccess() {
		natBytes, err := B64Decode(fields[idx])
		if err != nil {
			return nil, fmt.Errorf("%w: decoding NAT access: %v", ErrInvalidData, err)
		}
		m.NATAccess = string(natBytes)
		idx++
	}

	// Server auth (if present and remaining fields suggest it).
	// Client timeout would be numeric, server auth would be base64.
	if idx < numFields {
		// Try to parse as timeout first; if it fails, it's server auth.
		if timeout, err := strconv.ParseUint(fields[idx], 10, 32); err == nil {
			m.ClientTimeout = uint32(timeout)
			idx++
		} else {
			// It's server auth (base64 encoded).
			authBytes, err := B64Decode(fields[idx])
			if err != nil {
				return nil, fmt.Errorf("%w: decoding server auth: %v", ErrInvalidData, err)
			}
			m.ServerAuth = string(authBytes)
			idx++

			// Check for timeout after server auth.
			if idx < numFields {
				timeout, err := strconv.ParseUint(fields[idx], 10, 32)
				if err != nil {
					return nil, fmt.Errorf("%w: invalid client timeout: %v", ErrInvalidData, err)
				}
				m.ClientTimeout = uint32(timeout)
			}
		}
	}

	return m, nil
}

// detectDigestType determines the digest algorithm from the base64 length.
func detectDigestType(b64Len int) (DigestType, error) {
	switch b64Len {
	case md5B64Len:
		return DigestMD5, nil
	case sha1B64Len:
		return DigestSHA1, nil
	case sha256B64Len:
		return DigestSHA256, nil // may be SHA3-256, verified later
	case sha384B64Len:
		return DigestSHA384, nil
	case sha512B64Len:
		return DigestSHA512, nil // may be SHA3-512, verified later
	default:
		return 0, fmt.Errorf("%w: unrecognized digest length %d", ErrUnsupportedDigestType, b64Len)
	}
}

// verifyDigest computes the digest of encodedMsg and compares it to the
// expected digest. If SHA256/SHA512 fail, falls back to SHA3 variants
// (matching the C implementation behavior).
func verifyDigest(encodedMsg string, expectedDigest string, digestType DigestType) error {
	computed, err := DigestBase64(digestType, []byte(encodedMsg))
	if err != nil {
		return fmt.Errorf("computing digest: %w", err)
	}

	if subtle.ConstantTimeCompare([]byte(computed), []byte(expectedDigest)) == 1 {
		return nil
	}

	// Try SHA3 fallback for ambiguous lengths.
	switch digestType {
	case DigestSHA256:
		computed, err = DigestBase64(DigestSHA3256, []byte(encodedMsg))
		if err != nil {
			return err
		}
		if subtle.ConstantTimeCompare([]byte(computed), []byte(expectedDigest)) == 1 {
			return nil
		}
	case DigestSHA512:
		computed, err = DigestBase64(DigestSHA3512, []byte(encodedMsg))
		if err != nil {
			return err
		}
		if subtle.ConstantTimeCompare([]byte(computed), []byte(expectedDigest)) == 1 {
			return nil
		}
	}

	return ErrDigestVerificationFailed
}
