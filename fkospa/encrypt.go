package fkospa

import "fmt"

// EncryptionMode identifies the AES block cipher mode.
type EncryptionMode int

const (
	EncModeECB         EncryptionMode = 1 // stubbed
	EncModeCBC         EncryptionMode = 2 // default, fully implemented
	EncModeCFB         EncryptionMode = 3 // stubbed
	EncModePCBC        EncryptionMode = 4 // stubbed
	EncModeOFB         EncryptionMode = 5 // stubbed
	EncModeCTR         EncryptionMode = 6 // stubbed
	EncModeCBCLegacyIV EncryptionMode = 8 // fully implemented
)

// String returns a human-readable name for the encryption mode.
func (em EncryptionMode) String() string {
	switch em {
	case EncModeECB:
		return "ECB"
	case EncModeCBC:
		return "CBC"
	case EncModeCFB:
		return "CFB"
	case EncModePCBC:
		return "PCBC"
	case EncModeOFB:
		return "OFB"
	case EncModeCTR:
		return "CTR"
	case EncModeCBCLegacyIV:
		return "CBC-LegacyIV"
	default:
		return fmt.Sprintf("Unknown(%d)", int(em))
	}
}

func (em EncryptionMode) isValid() bool {
	switch em {
	case EncModeECB, EncModeCBC, EncModeCFB, EncModePCBC,
		EncModeOFB, EncModeCTR, EncModeCBCLegacyIV:
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
	case EncModeCBC:
		return &aesCBC{kdf: EVPBytesToKey{}}, nil
	case EncModeCBCLegacyIV:
		return &aesCBCLegacyIV{kdf: EVPBytesToKey{}}, nil
	case EncModeECB, EncModeCFB, EncModePCBC, EncModeOFB, EncModeCTR:
		return &aesStub{mode: mode}, nil
	default:
		return nil, fmt.Errorf("%w: %d", ErrUnsupportedEncryptionMode, mode)
	}
}
