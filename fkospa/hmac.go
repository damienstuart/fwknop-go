package fkospa

import (
	"crypto/hmac"
	"crypto/subtle"
	"fmt"
)

// HMACType identifies the HMAC algorithm used for SPA message authentication.
type HMACType int

const (
	HMACMD5     HMACType = 1
	HMACSHA1    HMACType = 2
	HMACSHA256  HMACType = 3 // default
	HMACSHA384  HMACType = 4
	HMACSHA512  HMACType = 5
	HMACSHA3256 HMACType = 6
	HMACSHA3512 HMACType = 7
)

// String returns a human-readable name for the HMAC type.
func (ht HMACType) String() string {
	switch ht {
	case HMACMD5:
		return "HMAC-MD5"
	case HMACSHA1:
		return "HMAC-SHA1"
	case HMACSHA256:
		return "HMAC-SHA256"
	case HMACSHA384:
		return "HMAC-SHA384"
	case HMACSHA512:
		return "HMAC-SHA512"
	case HMACSHA3256:
		return "HMAC-SHA3-256"
	case HMACSHA3512:
		return "HMAC-SHA3-512"
	default:
		return fmt.Sprintf("Unknown(%d)", int(ht))
	}
}

func (ht HMACType) isValid() bool {
	return ht >= HMACMD5 && ht <= HMACSHA3512
}

// digestType returns the corresponding DigestType for this HMAC type.
// The HMAC and Digest type values are aligned by design.
func (ht HMACType) digestType() DigestType {
	return DigestType(ht)
}

// ComputeHMAC computes an HMAC over data using the given key and algorithm.
func ComputeHMAC(ht HMACType, data []byte, key []byte) ([]byte, error) {
	hashFunc := ht.digestType().newHashFunc()
	if hashFunc == nil {
		return nil, fmt.Errorf("%w: %d", ErrUnsupportedHMACType, ht)
	}
	mac := hmac.New(hashFunc, key)
	mac.Write(data)
	return mac.Sum(nil), nil
}

// ComputeHMACBase64 computes an HMAC and returns it as SPA-style base64.
func ComputeHMACBase64(ht HMACType, data []byte, key []byte) (string, error) {
	raw, err := ComputeHMAC(ht, data, key)
	if err != nil {
		return "", err
	}
	return B64Encode(raw), nil
}

// VerifyHMAC checks that the HMAC over data matches expected.
// Uses constant-time comparison to prevent timing attacks.
func VerifyHMAC(ht HMACType, data []byte, key []byte, expected []byte) error {
	computed, err := ComputeHMAC(ht, data, key)
	if err != nil {
		return err
	}
	if subtle.ConstantTimeCompare(computed, expected) != 1 {
		return ErrHMACVerificationFailed
	}
	return nil
}
