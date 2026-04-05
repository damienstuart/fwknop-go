package fkospa

import (
	"crypto/md5"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/sha512"
	"fmt"
	"hash"

	"golang.org/x/crypto/sha3"
)

// DigestType identifies the hash algorithm used for the SPA message digest.
type DigestType int

const (
	DigestMD5     DigestType = 1
	DigestSHA1    DigestType = 2
	DigestSHA256  DigestType = 3 // default
	DigestSHA384  DigestType = 4
	DigestSHA512  DigestType = 5
	DigestSHA3_256 DigestType = 6
	DigestSHA3_512 DigestType = 7
)

// String returns a human-readable name for the digest type.
func (dt DigestType) String() string {
	switch dt {
	case DigestMD5:
		return "MD5"
	case DigestSHA1:
		return "SHA1"
	case DigestSHA256:
		return "SHA256"
	case DigestSHA384:
		return "SHA384"
	case DigestSHA512:
		return "SHA512"
	case DigestSHA3_256:
		return "SHA3-256"
	case DigestSHA3_512:
		return "SHA3-512"
	default:
		return fmt.Sprintf("Unknown(%d)", int(dt))
	}
}

func (dt DigestType) isValid() bool {
	return dt >= DigestMD5 && dt <= DigestSHA3_512
}

// newHash returns a new hash.Hash for the given digest type.
func (dt DigestType) newHash() (hash.Hash, error) {
	fn := dt.newHashFunc()
	if fn == nil {
		return nil, fmt.Errorf("%w: %d", ErrUnsupportedDigestType, dt)
	}
	return fn(), nil
}

// newHashFunc returns a constructor function for the hash algorithm.
// Returns nil for unsupported types. Used by both Digest and HMAC.
func (dt DigestType) newHashFunc() func() hash.Hash {
	switch dt {
	case DigestMD5:
		return md5.New
	case DigestSHA1:
		return sha1.New
	case DigestSHA256:
		return sha256.New
	case DigestSHA384:
		return sha512.New384
	case DigestSHA512:
		return sha512.New
	case DigestSHA3_256:
		return sha3.New256
	case DigestSHA3_512:
		return sha3.New512
	default:
		return nil
	}
}

// Digest computes the raw hash of data using the specified algorithm.
func Digest(dt DigestType, data []byte) ([]byte, error) {
	h, err := dt.newHash()
	if err != nil {
		return nil, err
	}
	h.Write(data)
	return h.Sum(nil), nil
}

// DigestBase64 computes a hash and returns it as SPA-style base64
// (standard base64 with trailing '=' stripped).
func DigestBase64(dt DigestType, data []byte) (string, error) {
	raw, err := Digest(dt, data)
	if err != nil {
		return "", err
	}
	return B64Encode(raw), nil
}
