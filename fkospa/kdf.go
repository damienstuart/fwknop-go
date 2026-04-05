package fkospa

import "crypto/md5"

const (
	rijndaelKeySize   = 32 // AES-256
	rijndaelBlockSize = 16
	rijndaelMinKey    = 16 // AES-128 minimum for legacy padding
	saltLen           = 8
)

// KeyDeriver derives an encryption key and IV from a passphrase and salt.
type KeyDeriver interface {
	DeriveKeyAndIV(passphrase []byte, salt []byte, keyLen int, ivLen int) (key []byte, iv []byte, err error)
}

// EVPBytesToKey implements the OpenSSL EVP_BytesToKey algorithm using MD5.
// This is the algorithm used by the C fwknop implementation and must produce
// byte-identical output for legacy compatibility.
type EVPBytesToKey struct{}

// DeriveKeyAndIV derives key and IV material by iteratively hashing
// (previous_md5 || passphrase || salt) with MD5 until enough bytes are
// produced to fill both the key and IV.
func (e EVPBytesToKey) DeriveKeyAndIV(passphrase []byte, salt []byte, keyLen int, ivLen int) ([]byte, []byte, error) {
	needed := keyLen + ivLen
	var kiv []byte
	var prev []byte

	for len(kiv) < needed {
		h := md5.New()
		if len(prev) > 0 {
			h.Write(prev)
		}
		h.Write(passphrase)
		h.Write(salt)
		prev = h.Sum(nil)
		kiv = append(kiv, prev...)
	}

	return kiv[:keyLen], kiv[keyLen : keyLen+ivLen], nil
}
