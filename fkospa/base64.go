package fkospa

import (
	"encoding/base64"
	"strings"
)

// B64Encode encodes data using standard base64 and strips trailing '='
// padding characters, matching the fwknop C library behavior.
func B64Encode(data []byte) string {
	encoded := base64.StdEncoding.EncodeToString(data)
	return strings.TrimRight(encoded, "=")
}

// B64Decode decodes an SPA-style base64 string. It handles input with
// or without trailing '=' padding by re-adding padding as needed.
func B64Decode(s string) ([]byte, error) {
	// Re-add padding to make length a multiple of 4.
	if m := len(s) % 4; m != 0 {
		s += strings.Repeat("=", 4-m)
	}
	return base64.StdEncoding.DecodeString(s)
}
