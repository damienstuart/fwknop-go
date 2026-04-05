package main

import (
	"testing"
	"time"

	"github.com/damienstuart/fwknop-go/fkospa"
)

func TestResolveDigestType(t *testing.T) {
	tests := []struct {
		input    string
		expected fkospa.DigestType
		wantErr  bool
	}{
		{"md5", fkospa.DigestMD5, false},
		{"sha1", fkospa.DigestSHA1, false},
		{"sha256", fkospa.DigestSHA256, false},
		{"sha384", fkospa.DigestSHA384, false},
		{"sha512", fkospa.DigestSHA512, false},
		{"sha3_256", fkospa.DigestSHA3256, false},
		{"sha3-256", fkospa.DigestSHA3256, false},
		{"sha3_512", fkospa.DigestSHA3512, false},
		{"sha3-512", fkospa.DigestSHA3512, false},
		{"SHA256", fkospa.DigestSHA256, false},  // case insensitive
		{"Sha512", fkospa.DigestSHA512, false},  // case insensitive
		{"bogus", 0, true},
		{"", 0, true},
	}

	for _, tc := range tests {
		t.Run(tc.input, func(t *testing.T) {
			got, err := resolveDigestType(tc.input)
			if tc.wantErr {
				if err == nil {
					t.Error("expected error, got nil")
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if got != tc.expected {
				t.Errorf("got %v, want %v", got, tc.expected)
			}
		})
	}
}

func TestResolveHMACType(t *testing.T) {
	tests := []struct {
		input    string
		expected fkospa.HMACType
		wantErr  bool
	}{
		{"md5", fkospa.HMACMD5, false},
		{"sha1", fkospa.HMACSHA1, false},
		{"sha256", fkospa.HMACSHA256, false},
		{"sha384", fkospa.HMACSHA384, false},
		{"sha512", fkospa.HMACSHA512, false},
		{"sha3_256", fkospa.HMACSHA3256, false},
		{"sha3_512", fkospa.HMACSHA3512, false},
		{"SHA256", fkospa.HMACSHA256, false},
		{"invalid", 0, true},
	}

	for _, tc := range tests {
		t.Run(tc.input, func(t *testing.T) {
			got, err := resolveHMACType(tc.input)
			if tc.wantErr {
				if err == nil {
					t.Error("expected error, got nil")
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if got != tc.expected {
				t.Errorf("got %v, want %v", got, tc.expected)
			}
		})
	}
}

func TestResolveEncMode(t *testing.T) {
	tests := []struct {
		input    string
		expected fkospa.EncryptionMode
		wantErr  bool
	}{
		{"cbc", fkospa.EncModeCBC, false},
		{"CBC", fkospa.EncModeCBC, false},
		{"legacy", fkospa.EncModeCBCLegacyIV, false},
		{"LEGACY", fkospa.EncModeCBCLegacyIV, false},
		{"ecb", 0, true},
		{"", 0, true},
	}

	for _, tc := range tests {
		t.Run(tc.input, func(t *testing.T) {
			got, err := resolveEncMode(tc.input)
			if tc.wantErr {
				if err == nil {
					t.Error("expected error, got nil")
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if got != tc.expected {
				t.Errorf("got %v, want %v", got, tc.expected)
			}
		})
	}
}

func TestResolveEncKey(t *testing.T) {
	tests := []struct {
		name    string
		cfg     clientConfig
		wantLen int
		wantErr bool
	}{
		{
			name:    "base64 key",
			cfg:     clientConfig{KeyBase64Rijn: "dGVzdGtleQ=="},
			wantLen: 7, // "testkey"
		},
		{
			name:    "plaintext key",
			cfg:     clientConfig{KeyRijndael: "mypassword"},
			wantLen: 10,
		},
		{
			name:    "base64 takes precedence",
			cfg:     clientConfig{KeyBase64Rijn: "dGVzdGtleQ==", KeyRijndael: "other"},
			wantLen: 7,
		},
		{
			name:    "no key",
			cfg:     clientConfig{},
			wantErr: true,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			key, err := tc.cfg.resolveEncKey()
			if tc.wantErr {
				if err == nil {
					t.Error("expected error, got nil")
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if len(key) != tc.wantLen {
				t.Errorf("key length = %d, want %d", len(key), tc.wantLen)
			}
		})
	}
}

func TestResolveHMACKey(t *testing.T) {
	tests := []struct {
		name    string
		cfg     clientConfig
		wantNil bool
		wantLen int
		wantErr bool
	}{
		{
			name:    "hmac disabled",
			cfg:     clientConfig{UseHMAC: false},
			wantNil: true,
		},
		{
			name:    "base64 hmac key",
			cfg:     clientConfig{UseHMAC: true, KeyBase64HMAC: "aG1hY2tleQ=="},
			wantLen: 7,
		},
		{
			name:    "plaintext hmac key",
			cfg:     clientConfig{UseHMAC: true, KeyHMAC: "hmackey"},
			wantLen: 7,
		},
		{
			name:    "hmac enabled but no key",
			cfg:     clientConfig{UseHMAC: true},
			wantErr: true,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			key, err := tc.cfg.resolveHMACKey()
			if tc.wantErr {
				if err == nil {
					t.Error("expected error, got nil")
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if tc.wantNil {
				if key != nil {
					t.Errorf("expected nil key, got %v", key)
				}
				return
			}
			if len(key) != tc.wantLen {
				t.Errorf("key length = %d, want %d", len(key), tc.wantLen)
			}
		})
	}
}

func TestParseTimeOffset(t *testing.T) {
	tests := []struct {
		input    string
		expected time.Duration
		wantErr  bool
	}{
		{"", 0, false},
		{"30", 30 * time.Second, false},
		{"120", 120 * time.Second, false},
		{"2m", 2 * time.Minute, false},
		{"1h", 1 * time.Hour, false},
		{"1h30m", 90 * time.Minute, false},
		{"500ms", 500 * time.Millisecond, false},
		{"abc", 0, true},
	}

	for _, tc := range tests {
		t.Run(tc.input, func(t *testing.T) {
			got, err := parseTimeOffset(tc.input)
			if tc.wantErr {
				if err == nil {
					t.Error("expected error, got nil")
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if got != tc.expected {
				t.Errorf("got %v, want %v", got, tc.expected)
			}
		})
	}
}
