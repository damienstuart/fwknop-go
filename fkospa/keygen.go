package fkospa

import (
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"io"
)

// GenerateKey generates a random encryption key of keyLen bytes
// and returns it as standard base64.
func GenerateKey(keyLen int) (string, error) {
	if keyLen < 1 {
		return "", fmt.Errorf("%w: key length must be positive", ErrInvalidKeyLen)
	}
	key := make([]byte, keyLen)
	if _, err := io.ReadFull(rand.Reader, key); err != nil {
		return "", fmt.Errorf("generating random key: %w", err)
	}
	return base64.StdEncoding.EncodeToString(key), nil
}

// GenerateHMACKey generates a random HMAC key of keyLen bytes
// and returns it as standard base64.
func GenerateHMACKey(keyLen int) (string, error) {
	if keyLen < 1 {
		return "", fmt.Errorf("%w: HMAC key length must be positive", ErrInvalidKeyLen)
	}
	key := make([]byte, keyLen)
	if _, err := io.ReadFull(rand.Reader, key); err != nil {
		return "", fmt.Errorf("generating random HMAC key: %w", err)
	}
	return base64.StdEncoding.EncodeToString(key), nil
}
