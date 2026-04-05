// Example nat_access demonstrates creating an SPA message that requests
// NAT access, where the server forwards a connection to an internal host.
package main

import (
	"fmt"
	"log"

	"github.com/damienstuart/fwknop-go/fkospa"
)

func main() {
	encKey := []byte("my_encryption_key")
	hmacKey := []byte("my_hmac_key")

	// Create a NAT access request.
	// This tells the server: allow 192.168.1.50 to connect via tcp/22,
	// and forward the connection to internal host 10.0.0.100 port 22.
	msg, err := fkospa.NewWithOptions(
		fkospa.WithUsername("alice"),
		fkospa.WithMessageType(fkospa.NATAccessMsg),
		fkospa.WithAccessMsg("192.168.1.50,tcp/22"),
		fkospa.WithNATAccess("10.0.0.100,22"),
	)
	if err != nil {
		log.Fatal(err)
	}

	spaData, err := msg.Encrypt(encKey, hmacKey)
	if err != nil {
		log.Fatal(err)
	}

	// Decrypt and verify.
	decoded, err := fkospa.Decrypt(spaData, encKey, hmacKey)
	if err != nil {
		log.Fatal(err)
	}

	fmt.Printf("Message Type: %s\n", decoded.MessageType)
	fmt.Printf("Access:       %s\n", decoded.AccessMsg)
	fmt.Printf("NAT Access:   %s\n", decoded.NATAccess)
}
