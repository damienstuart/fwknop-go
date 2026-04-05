package fkospa_test

import (
	"fmt"
	"log"
	"time"

	"github.com/damienstuart/fwknop-go/fkospa"
)

func ExampleNew() {
	// Create a message with default settings.
	// Defaults: AccessMsg type, SHA256 digest, AES-CBC, HMAC-SHA256.
	m, err := fkospa.New()
	if err != nil {
		log.Fatal(err)
	}

	// Set the access request — required before encryption.
	m.AccessMsg = "192.168.1.1,tcp/22"

	fmt.Println("Type:", m.MessageType)
	fmt.Println("Digest:", m.DigestType)
	fmt.Println("Encryption:", m.EncryptionMode)
	// Output:
	// Type: Access
	// Digest: SHA256
	// Encryption: CBC
}

func ExampleNewWithOptions() {
	m, err := fkospa.NewWithOptions(
		fkospa.WithUsername("alice"),
		fkospa.WithAccessMsg("10.0.0.1,tcp/22"),
		fkospa.WithDigestType(fkospa.DigestSHA512),
		fkospa.WithHMACType(fkospa.HMACSHA512),
	)
	if err != nil {
		log.Fatal(err)
	}

	fmt.Println("User:", m.Username)
	fmt.Println("Access:", m.AccessMsg)
	fmt.Println("Digest:", m.DigestType)
	// Output:
	// User: alice
	// Access: 10.0.0.1,tcp/22
	// Digest: SHA512
}

func ExampleMessage_Encrypt() {
	m, err := fkospa.NewWithOptions(
		fkospa.WithUsername("alice"),
		fkospa.WithAccessMsg("192.168.1.1,tcp/22"),
	)
	if err != nil {
		log.Fatal(err)
	}

	encKey := []byte("my_encryption_key")
	hmacKey := []byte("my_hmac_key")

	spaData, err := m.Encrypt(encKey, hmacKey)
	if err != nil {
		log.Fatal(err)
	}

	// spaData is the wire-format string to send to the fwknop server.
	fmt.Println("SPA data length:", len(spaData))
}

func ExampleDecrypt() {
	// First, create and encrypt a message.
	m, err := fkospa.NewWithOptions(
		fkospa.WithRandVal("1234567890123456"),
		fkospa.WithUsername("bob"),
		fkospa.WithTimestamp(time.Unix(1700000000, 0)),
		fkospa.WithAccessMsg("10.0.0.1,tcp/22"),
	)
	if err != nil {
		log.Fatal(err)
	}

	encKey := []byte("shared_secret")
	hmacKey := []byte("hmac_secret")

	spaData, err := m.Encrypt(encKey, hmacKey)
	if err != nil {
		log.Fatal(err)
	}

	// Now decrypt and parse the SPA data (server side).
	decoded, err := fkospa.Decrypt(spaData, encKey, hmacKey)
	if err != nil {
		log.Fatal(err)
	}

	fmt.Println("User:", decoded.Username)
	fmt.Println("Access:", decoded.AccessMsg)
	fmt.Println("Type:", decoded.MessageType)
	// Output:
	// User: bob
	// Access: 10.0.0.1,tcp/22
	// Type: Access
}

func ExampleMessage_Encode() {
	// Encode produces the plaintext wire format (before encryption).
	// Useful for debugging or testing.
	m := &fkospa.Message{
		RandVal:        "1234567890123456",
		Username:       "alice",
		Timestamp:      time.Unix(1700000000, 0),
		MessageType:    fkospa.AccessMsg,
		AccessMsg:      "192.168.1.1,tcp/22",
		DigestType:     fkospa.DigestSHA256,
		EncryptionMode: fkospa.EncModeCBC,
		HMACType:       fkospa.HMACSHA256,
	}

	encoded, err := m.Encode()
	if err != nil {
		log.Fatal(err)
	}

	fmt.Println(encoded)
	// Output:
	// 1234567890123456:YWxpY2U:1700000000:3.0.0:1:MTkyLjE2OC4xLjEsdGNwLzIy:InhdiYP3+F4uF1ShX9rkUs/lL8N86cJPn4VWjmXpU1w
}

func ExampleGenerateKey() {
	// Generate a random 32-byte encryption key.
	key, err := fkospa.GenerateKey(32)
	if err != nil {
		log.Fatal(err)
	}
	fmt.Println("Key length (base64):", len(key))
	// Output:
	// Key length (base64): 44
}

func ExampleMessage_Encrypt_withNAT() {
	m, err := fkospa.NewWithOptions(
		fkospa.WithUsername("alice"),
		fkospa.WithMessageType(fkospa.NATAccessMsg),
		fkospa.WithAccessMsg("192.168.1.1,tcp/22"),
		fkospa.WithNATAccess("10.0.0.100,22"),
	)
	if err != nil {
		log.Fatal(err)
	}

	spaData, err := m.Encrypt([]byte("key"), []byte("hmac"))
	if err != nil {
		log.Fatal(err)
	}

	// Decrypt and verify NAT access is preserved.
	decoded, err := fkospa.Decrypt(spaData, []byte("key"), []byte("hmac"))
	if err != nil {
		log.Fatal(err)
	}

	fmt.Println("Type:", decoded.MessageType)
	fmt.Println("NAT:", decoded.NATAccess)
	// Output:
	// Type: NATAccess
	// NAT: 10.0.0.100,22
}

func ExampleMessage_Encrypt_withTimeout() {
	m, err := fkospa.NewWithOptions(
		fkospa.WithUsername("alice"),
		fkospa.WithAccessMsg("10.0.0.1,tcp/22"),
		fkospa.WithClientTimeout(30),
	)
	if err != nil {
		log.Fatal(err)
	}

	spaData, err := m.Encrypt([]byte("key"), []byte("hmac"))
	if err != nil {
		log.Fatal(err)
	}

	decoded, err := fkospa.Decrypt(spaData, []byte("key"), []byte("hmac"))
	if err != nil {
		log.Fatal(err)
	}

	// MessageType is auto-adjusted to include timeout.
	fmt.Println("Type:", decoded.MessageType)
	fmt.Println("Timeout:", decoded.ClientTimeout)
	// Output:
	// Type: ClientTimeoutAccess
	// Timeout: 30
}
