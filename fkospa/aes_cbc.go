package fkospa

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"fmt"
	"io"
)

// aesCBC implements AES-256-CBC encryption compatible with the C fwknop
// implementation and OpenSSL's "Salted__" format.
type aesCBC struct {
	kdf KeyDeriver
}

// Encrypt encrypts plaintext using AES-256-CBC with PKCS7 padding.
// Output format: "Salted__" (8 bytes) + salt (8 bytes) + ciphertext.
func (a *aesCBC) Encrypt(plaintext []byte, passphrase []byte) ([]byte, error) {
	// Generate random 8-byte salt.
	salt := make([]byte, saltLen)
	if _, err := io.ReadFull(rand.Reader, salt); err != nil {
		return nil, fmt.Errorf("generating salt: %w", err)
	}

	return a.encryptWithSalt(plaintext, passphrase, salt)
}

func (a *aesCBC) encryptWithSalt(plaintext []byte, passphrase []byte, salt []byte) ([]byte, error) {
	// Derive key and IV.
	key, iv, err := a.kdf.DeriveKeyAndIV(passphrase, salt, aesKeySize, aesBlockSize)
	if err != nil {
		return nil, fmt.Errorf("key derivation: %w", err)
	}

	// Apply PKCS7 padding.
	padded := pkcs7Pad(plaintext, aesBlockSize)

	// Encrypt.
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("creating AES cipher: %w", err)
	}

	ciphertext := make([]byte, len(padded))
	cbc := cipher.NewCBCEncrypter(block, iv)
	cbc.CryptBlocks(ciphertext, padded)

	// Assemble output: "Salted__" + salt + ciphertext.
	out := make([]byte, 0, saltLen+saltLen+len(ciphertext))
	out = append(out, "Salted__"...)
	out = append(out, salt...)
	out = append(out, ciphertext...)

	return out, nil
}

// Decrypt decrypts data produced by Encrypt.
// Expects input format: "Salted__" (8 bytes) + salt (8 bytes) + ciphertext.
func (a *aesCBC) Decrypt(data []byte, passphrase []byte) ([]byte, error) {
	// Minimum size: 16 (salt header) + 16 (at least one block).
	if len(data) < saltLen+saltLen+aesBlockSize {
		return nil, fmt.Errorf("%w: ciphertext too short", ErrDecryptionFailed)
	}

	// Verify and extract salt.
	if string(data[:saltLen]) != "Salted__" {
		return nil, fmt.Errorf("%w: missing Salted__ prefix", ErrDecryptionFailed)
	}
	salt := data[saltLen : saltLen+saltLen]
	ciphertext := data[saltLen+saltLen:]

	if len(ciphertext)%aesBlockSize != 0 {
		return nil, fmt.Errorf("%w: ciphertext not block-aligned", ErrDecryptionFailed)
	}

	// Derive key and IV.
	key, iv, err := a.kdf.DeriveKeyAndIV(passphrase, salt, aesKeySize, aesBlockSize)
	if err != nil {
		return nil, fmt.Errorf("key derivation: %w", err)
	}

	// Decrypt.
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("creating AES cipher: %w", err)
	}

	plaintext := make([]byte, len(ciphertext))
	cbc := cipher.NewCBCDecrypter(block, iv)
	cbc.CryptBlocks(plaintext, ciphertext)

	// Remove PKCS7 padding.
	plaintext, err = pkcs7Unpad(plaintext, aesBlockSize)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrDecryptionFailed, err)
	}

	return plaintext, nil
}

// aesCBCLegacyIV implements the legacy IV mode where short passphrases
// are right-padded with '0' characters to 16 bytes before key derivation.
type aesCBCLegacyIV struct {
	kdf KeyDeriver
}

func (a *aesCBCLegacyIV) Encrypt(plaintext []byte, passphrase []byte) ([]byte, error) {
	padded := legacyPadPassphrase(passphrase)
	inner := &aesCBC{kdf: a.kdf}
	return inner.Encrypt(plaintext, padded)
}

func (a *aesCBCLegacyIV) Decrypt(data []byte, passphrase []byte) ([]byte, error) {
	padded := legacyPadPassphrase(passphrase)
	inner := &aesCBC{kdf: a.kdf}
	return inner.Decrypt(data, padded)
}

// legacyPadPassphrase pads a passphrase shorter than 16 bytes with '0'
// characters, matching the legacy C behavior.
func legacyPadPassphrase(passphrase []byte) []byte {
	if len(passphrase) >= aesMinKeySize {
		return passphrase
	}
	padded := make([]byte, aesMinKeySize)
	copy(padded, passphrase)
	for i := len(passphrase); i < aesMinKeySize; i++ {
		padded[i] = '0'
	}
	return padded
}

// pkcs7Pad appends PKCS7 padding to data.
func pkcs7Pad(data []byte, blockSize int) []byte {
	padLen := blockSize - (len(data) % blockSize)
	padding := make([]byte, padLen)
	for i := range padding {
		padding[i] = byte(padLen)
	}
	return append(data, padding...)
}

// pkcs7Unpad removes PKCS7 padding, matching the C implementation's
// tolerance for invalid padding (returns data as-is if padding is invalid).
func pkcs7Unpad(data []byte, blockSize int) ([]byte, error) {
	if len(data) == 0 {
		return data, nil
	}

	padVal := int(data[len(data)-1])
	if padVal < 1 || padVal > blockSize {
		// C implementation silently ignores invalid padding.
		return data, nil
	}

	padStart := len(data) - padVal
	for i := padStart; i < len(data); i++ {
		if data[i] != byte(padVal) {
			// Padding bytes don't match — C ignores this too.
			return data, nil
		}
	}

	return data[:padStart], nil
}
