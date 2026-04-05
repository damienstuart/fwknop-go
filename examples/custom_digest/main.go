// Example custom_digest demonstrates using different digest and HMAC
// algorithms for SPA message creation and verification.
package main

import (
	"fmt"
	"log"

	"github.com/damienstuart/fwknop-go/fkospa"
)

func main() {
	encKey := []byte("my_encryption_key")
	hmacKey := []byte("my_hmac_key")

	// Available digest types: DigestMD5, DigestSHA1, DigestSHA256 (default),
	// DigestSHA384, DigestSHA512, DigestSHA3_256, DigestSHA3_512.
	//
	// HMAC types mirror the digest types: HMACMD5, HMACSHA1, HMACSHA256,
	// HMACSHA384, HMACSHA512, HMACSHA3_256, HMACSHA3_512.

	configs := []struct {
		name   string
		digest fkospa.DigestType
		hmac   fkospa.HMACType
	}{
		{"SHA-512", fkospa.DigestSHA512, fkospa.HMACSHA512},
		{"SHA3-256", fkospa.DigestSHA3_256, fkospa.HMACSHA3_256},
		{"MD5 (not recommended)", fkospa.DigestMD5, fkospa.HMACMD5},
	}

	for _, cfg := range configs {
		msg, err := fkospa.NewWithOptions(
			fkospa.WithUsername("alice"),
			fkospa.WithAccessMsg("10.0.0.1,tcp/22"),
			fkospa.WithDigestType(cfg.digest),
			fkospa.WithHMACType(cfg.hmac),
		)
		if err != nil {
			log.Fatal(err)
		}

		spaData, err := msg.Encrypt(encKey, hmacKey)
		if err != nil {
			log.Fatal(err)
		}

		// The server must use matching HMAC type for decryption.
		decoded, err := fkospa.Decrypt(spaData, encKey, hmacKey,
			fkospa.WithDecryptHMACType(cfg.hmac),
		)
		if err != nil {
			log.Fatalf("%s: decrypt failed: %v", cfg.name, err)
		}

		fmt.Printf("%-25s  digest=%s  hmac=%s  SPA length=%d\n",
			cfg.name, decoded.DigestType, cfg.hmac, len(spaData))
	}
}
