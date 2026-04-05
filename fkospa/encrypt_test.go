package fkospa

import (
	"bytes"
	"testing"
)

func TestAESCBCRoundTrip(t *testing.T) {
	enc := &aesCBC{kdf: EVPBytesToKey{}}
	passphrase := []byte("test encryption key")
	plaintext := []byte("Hello, SPA world! This is a test message.")

	ciphertext, err := enc.Encrypt(plaintext, passphrase)
	if err != nil {
		t.Fatalf("Encrypt error: %v", err)
	}

	// Verify "Salted__" prefix.
	if string(ciphertext[:8]) != "Salted__" {
		t.Error("ciphertext missing Salted__ prefix")
	}

	decrypted, err := enc.Decrypt(ciphertext, passphrase)
	if err != nil {
		t.Fatalf("Decrypt error: %v", err)
	}

	if !bytes.Equal(decrypted, plaintext) {
		t.Errorf("round-trip failed: got %q, want %q", decrypted, plaintext)
	}
}

func TestAESCBCLegacyIVRoundTrip(t *testing.T) {
	enc := &aesCBCLegacyIV{kdf: EVPBytesToKey{}}
	passphrase := []byte("short") // shorter than 16 bytes — will be padded
	plaintext := []byte("Legacy IV test data")

	ciphertext, err := enc.Encrypt(plaintext, passphrase)
	if err != nil {
		t.Fatalf("Encrypt error: %v", err)
	}

	decrypted, err := enc.Decrypt(ciphertext, passphrase)
	if err != nil {
		t.Fatalf("Decrypt error: %v", err)
	}

	if !bytes.Equal(decrypted, plaintext) {
		t.Errorf("round-trip failed: got %q, want %q", decrypted, plaintext)
	}
}

func TestAESCBCWrongKey(t *testing.T) {
	enc := &aesCBC{kdf: EVPBytesToKey{}}
	plaintext := []byte("secret message")

	ciphertext, err := enc.Encrypt(plaintext, []byte("correct key"))
	if err != nil {
		t.Fatalf("Encrypt error: %v", err)
	}

	// Decryption with wrong key should either error or produce garbage
	// (the C implementation doesn't always error on wrong key —
	// it may produce garbage that fails digest verification later).
	decrypted, err := enc.Decrypt(ciphertext, []byte("wrong key"))
	if err == nil && bytes.Equal(decrypted, plaintext) {
		t.Error("decryption with wrong key produced correct plaintext")
	}
}

func TestAESCBCDeterministicWithFixedSalt(t *testing.T) {
	enc := &aesCBC{kdf: EVPBytesToKey{}}
	passphrase := []byte("testkey")
	plaintext := []byte("deterministic test")
	salt := []byte{0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08}

	ct1, err := enc.encryptWithSalt(plaintext, passphrase, salt)
	if err != nil {
		t.Fatalf("Encrypt error: %v", err)
	}

	ct2, err := enc.encryptWithSalt(plaintext, passphrase, salt)
	if err != nil {
		t.Fatalf("Encrypt error: %v", err)
	}

	if !bytes.Equal(ct1, ct2) {
		t.Error("same inputs with same salt should produce identical ciphertext")
	}
}

func TestLegacyPadPassphrase(t *testing.T) {
	tests := []struct {
		input    string
		expected string
	}{
		{"abc", "abc0000000000000"},           // 3 → padded to 16 with '0'
		{"1234567890123456", "1234567890123456"}, // 16 → unchanged
		{"longpassphrase!!", "longpassphrase!!"}, // 16 → unchanged
		{"verylongpassphrase", "verylongpassphrase"}, // 18 → unchanged (>= 16)
	}

	for _, tc := range tests {
		got := legacyPadPassphrase([]byte(tc.input))
		if string(got) != tc.expected {
			t.Errorf("legacyPadPassphrase(%q) = %q, want %q", tc.input, got, tc.expected)
		}
	}
}

func TestPKCS7Padding(t *testing.T) {
	// Test padding round-trip for various lengths.
	for dataLen := 0; dataLen <= 32; dataLen++ {
		data := make([]byte, dataLen)
		for i := range data {
			data[i] = byte(i)
		}

		padded := pkcs7Pad(data, 16)
		if len(padded)%16 != 0 {
			t.Errorf("padded length %d not multiple of 16 for input len %d", len(padded), dataLen)
		}

		unpadded, err := pkcs7Unpad(padded, 16)
		if err != nil {
			t.Errorf("unpad error for input len %d: %v", dataLen, err)
			continue
		}

		if !bytes.Equal(unpadded, data) {
			t.Errorf("PKCS7 round-trip failed for input len %d", dataLen)
		}
	}
}

func TestAESStubReturnsError(t *testing.T) {
	stub := &aesStub{mode: EncryptionModeECB}

	_, err := stub.Encrypt([]byte("test"), []byte("key"))
	if err == nil {
		t.Error("stub Encrypt should return error")
	}

	_, err = stub.Decrypt([]byte("test"), []byte("key"))
	if err == nil {
		t.Error("stub Decrypt should return error")
	}
}

func TestEncrypterForModes(t *testing.T) {
	// CBC and Legacy IV should return working encrypters.
	for _, mode := range []EncryptionMode{EncryptionModeCBC, EncryptionModeCBCLegacy} {
		enc, err := encrypterFor(mode)
		if err != nil {
			t.Errorf("encrypterFor(%v) error: %v", mode, err)
			continue
		}
		ct, err := enc.Encrypt([]byte("test data here!!"), []byte("key"))
		if err != nil {
			t.Errorf("Encrypt with mode %v error: %v", mode, err)
			continue
		}
		pt, err := enc.Decrypt(ct, []byte("key"))
		if err != nil {
			t.Errorf("Decrypt with mode %v error: %v", mode, err)
			continue
		}
		if string(pt) != "test data here!!" {
			t.Errorf("round-trip with mode %v: got %q", mode, pt)
		}
	}

	// Stubbed modes should return stubs.
	for _, mode := range []EncryptionMode{EncryptionModeECB, EncryptionModeCFB, EncryptionModePCBC, EncryptionModeOFB, EncryptionModeCTR} {
		enc, err := encrypterFor(mode)
		if err != nil {
			t.Errorf("encrypterFor(%v) error: %v", mode, err)
			continue
		}
		_, err = enc.Encrypt([]byte("test"), []byte("key"))
		if err == nil {
			t.Errorf("stubbed mode %v should error on Encrypt", mode)
		}
	}
}
