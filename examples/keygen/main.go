// Example keygen demonstrates generating random encryption and HMAC keys
// suitable for use with fwknop.
package main

import (
	"fmt"
	"log"

	"github.com/damienstuart/fwknop-go/fkospa"
)

func main() {
	// Generate a 32-byte (256-bit) encryption key.
	encKey, err := fkospa.GenerateKey(32)
	if err != nil {
		log.Fatal(err)
	}

	// Generate a 32-byte HMAC key.
	hmacKey, err := fkospa.GenerateHMACKey(32)
	if err != nil {
		log.Fatal(err)
	}

	fmt.Println("Add these to your client .fwknoprc and server access.yaml:")
	fmt.Println()
	fmt.Printf("KEY_BASE64:      %s\n", encKey)
	fmt.Printf("HMAC_KEY_BASE64: %s\n", hmacKey)
}
