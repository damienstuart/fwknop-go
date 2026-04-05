package fkospa

import (
	"bytes"
	"testing"
)

// Test vectors from the C implementation's unit tests (base64.c).
func TestB64EncodeVectors(t *testing.T) {
	tests := []struct {
		input    string
		expected string // with padding, as the C b64_encode produces
	}{
		{"", ""},
		{"f", "Zg=="},
		{"fo", "Zm8="},
		{"foo", "Zm9v"},
		{"foob", "Zm9vYg=="},
		{"fooba", "Zm9vYmE="},
		{"foobar", "Zm9vYmFy"},
	}

	for _, tc := range tests {
		// B64Encode strips trailing '=', so strip from expected too.
		want := tc.expected
		for len(want) > 0 && want[len(want)-1] == '=' {
			want = want[:len(want)-1]
		}
		got := B64Encode([]byte(tc.input))
		if got != want {
			t.Errorf("B64Encode(%q) = %q, want %q", tc.input, got, want)
		}
	}
}

func TestB64DecodeVectors(t *testing.T) {
	tests := []struct {
		input    string
		expected string
	}{
		{"", ""},
		{"Zg==", "f"},
		{"Zm8=", "fo"},
		{"Zm9v", "foo"},
		{"Zm9vYg==", "foob"},
		{"Zm9vYmE=", "fooba"},
		{"Zm9vYmFy", "foobar"},
	}

	for _, tc := range tests {
		got, err := B64Decode(tc.input)
		if err != nil {
			t.Errorf("B64Decode(%q) error: %v", tc.input, err)
			continue
		}
		if !bytes.Equal(got, []byte(tc.expected)) {
			t.Errorf("B64Decode(%q) = %q, want %q", tc.input, got, tc.expected)
		}
	}
}

// Verify round-trip: encode then decode recovers original data.
func TestB64RoundTrip(t *testing.T) {
	inputs := []string{"", "a", "ab", "abc", "abcd", "Hello, World!", "SPA test data 123"}
	for _, input := range inputs {
		encoded := B64Encode([]byte(input))
		decoded, err := B64Decode(encoded)
		if err != nil {
			t.Errorf("round-trip decode error for %q: %v", input, err)
			continue
		}
		if !bytes.Equal(decoded, []byte(input)) {
			t.Errorf("round-trip failed for %q: got %q", input, decoded)
		}
	}
}

// Verify decoding works with and without padding (C library accepts both).
func TestB64DecodeWithoutPadding(t *testing.T) {
	tests := []struct {
		input    string
		expected string
	}{
		{"Zg", "f"},
		{"Zm8", "fo"},
		{"Zm9vYg", "foob"},
		{"Zm9vYmE", "fooba"},
	}

	for _, tc := range tests {
		got, err := B64Decode(tc.input)
		if err != nil {
			t.Errorf("B64Decode(%q) error: %v", tc.input, err)
			continue
		}
		if !bytes.Equal(got, []byte(tc.expected)) {
			t.Errorf("B64Decode(%q) = %q, want %q", tc.input, got, tc.expected)
		}
	}
}
