// Example basic_spa demonstrates creating, encrypting, and decrypting
// an SPA message using the fkospa library.
package main

import (
	"fmt"
	"log"

	"github.com/damienstuart/fwknop-go/fkospa"
)

func main() {
	// Shared keys (in production, use base64-encoded keys from fwknop --key-gen).
	encKey := []byte("my_encryption_key")
	hmacKey := []byte("my_hmac_key")

	// --- Client side: create and encrypt ---

	msg, err := fkospa.NewWithOptions(
		fkospa.WithUsername("alice"),
		fkospa.WithAccessMsg("192.168.1.50,tcp/22"),
	)
	if err != nil {
		log.Fatal(err)
	}

	spaData, err := msg.Encrypt(encKey, hmacKey)
	if err != nil {
		log.Fatal(err)
	}

	fmt.Println("Encrypted SPA data:")
	fmt.Println(spaData)
	fmt.Printf("Length: %d bytes\n\n", len(spaData))

	// --- Server side: decrypt and parse ---

	decoded, err := fkospa.Decrypt(spaData, encKey, hmacKey)
	if err != nil {
		log.Fatal(err)
	}

	fmt.Println("Decrypted SPA message:")
	fmt.Printf("  Username:     %s\n", decoded.Username)
	fmt.Printf("  Access:       %s\n", decoded.AccessMsg)
	fmt.Printf("  Message Type: %s\n", decoded.MessageType)
	fmt.Printf("  Timestamp:    %s\n", decoded.Timestamp)
	fmt.Printf("  Digest:       %s\n", decoded.DigestType)
}
