package fkospa

import "fmt"

// aesStub is a placeholder for unimplemented AES modes.
type aesStub struct {
	mode EncryptionMode
}

func (s *aesStub) Encrypt(plaintext []byte, key []byte) ([]byte, error) {
	return nil, fmt.Errorf("%w (mode %v)", ErrUnsupportedEncryptionMode, s.mode)
}

func (s *aesStub) Decrypt(ciphertext []byte, key []byte) ([]byte, error) {
	return nil, fmt.Errorf("%w (mode %v)", ErrUnsupportedEncryptionMode, s.mode)
}
