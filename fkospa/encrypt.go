package fkospa

import "fmt"

// EncryptionMode identifies the AES block cipher mode.
type EncryptionMode int

const (
	EncryptionModeECB         EncryptionMode = 1 // stubbed
	EncryptionModeCBC         EncryptionMode = 2 // default, fully implemented
	EncryptionModeCFB         EncryptionMode = 3 // stubbed
	EncryptionModePCBC        EncryptionMode = 4 // stubbed
	EncryptionModeOFB         EncryptionMode = 5 // stubbed
	EncryptionModeCTR         EncryptionMode = 6 // stubbed
	// Mode 7 is intentionally skipped to match the C fwknop enum values.
	EncryptionModeCBCLegacy   EncryptionMode = 8 // fully implemented
)

// String returns a human-readable name for the encryption mode.
func (em EncryptionMode) String() string {
	switch em {
	case EncryptionModeECB:
		return "ECB"
	case EncryptionModeCBC:
		return "CBC"
	case EncryptionModeCFB:
		return "CFB"
	case EncryptionModePCBC:
		return "PCBC"
	case EncryptionModeOFB:
		return "OFB"
	case EncryptionModeCTR:
		return "CTR"
	case EncryptionModeCBCLegacy:
		return "CBC-LegacyIV"
	default:
		return fmt.Sprintf("Unknown(%d)", int(em))
	}
}

func (em EncryptionMode) isValid() bool {
	switch em {
	case EncryptionModeECB, EncryptionModeCBC, EncryptionModeCFB, EncryptionModePCBC,
		EncryptionModeOFB, EncryptionModeCTR, EncryptionModeCBCLegacy:
		return true
	default:
		return false
	}
}

// Encrypter encrypts plaintext with a passphrase and returns ciphertext.
type Encrypter interface {
	Encrypt(plaintext []byte, key []byte) ([]byte, error)
}

// Decrypter decrypts ciphertext with a passphrase and returns plaintext.
type Decrypter interface {
	Decrypt(ciphertext []byte, key []byte) ([]byte, error)
}

// EncryptDecrypter combines both encryption and decryption capabilities.
type EncryptDecrypter interface {
	Encrypter
	Decrypter
}

// encrypterFor returns the EncryptDecrypter for the given mode.
func encrypterFor(mode EncryptionMode) (EncryptDecrypter, error) {
	switch mode {
	case EncryptionModeCBC:
		return &aesCBC{kdf: EVPBytesToKey{}}, nil
	case EncryptionModeCBCLegacy:
		return &aesCBCLegacyIV{kdf: EVPBytesToKey{}}, nil
	case EncryptionModeECB, EncryptionModeCFB, EncryptionModePCBC, EncryptionModeOFB, EncryptionModeCTR:
		return &aesStub{mode: mode}, nil
	default:
		return nil, fmt.Errorf("%w: %d", ErrUnsupportedEncryptionMode, mode)
	}
}
