// Package fkospa implements the fwknop Single Packet Authorization (SPA)
// protocol in Go. It provides functionality for creating, encrypting,
// decrypting, and parsing SPA messages compatible with the legacy C fwknop
// implementation (https://www.cipherdyne.org/fwknop/).
//
// SPA allows a client to send a single encrypted, non-replayable,
// HMAC-authenticated packet to a server in order to request access to a
// service hidden behind a firewall in a default-drop stance.
//
// # Creating and Sending SPA Messages
//
// Use [New] or [NewWithOptions] to create a message, then [Message.Encrypt]
// to produce the wire-format data:
//
//	m, err := fkospa.NewWithOptions(
//	    fkospa.WithUsername("alice"),
//	    fkospa.WithAccessMsg("192.168.1.1,tcp/22"),
//	)
//	if err != nil {
//	    log.Fatal(err)
//	}
//
//	spaData, err := m.Encrypt([]byte("encryption_key"), []byte("hmac_key"))
//	if err != nil {
//	    log.Fatal(err)
//	}
//	// Send spaData over UDP to the fwknop server.
//
// # Receiving and Decoding SPA Messages
//
// Use [Decrypt] to verify, decrypt, and parse incoming SPA data:
//
//	msg, err := fkospa.Decrypt(spaData, []byte("encryption_key"), []byte("hmac_key"))
//	if err != nil {
//	    log.Fatal(err)
//	}
//	fmt.Println(msg.Username, msg.AccessMsg)
//
// # Wire Format
//
// The SPA plaintext is a colon-delimited string of fields:
//
//	RAND_VAL : B64(USERNAME) : TIMESTAMP : VERSION : MSG_TYPE : B64(MESSAGE) [: B64(NAT_ACCESS)] [: B64(SERVER_AUTH)] [: CLIENT_TIMEOUT] : DIGEST
//
// This plaintext (including digest) is encrypted with AES-256-CBC using a key
// derived via the OpenSSL-compatible EVP_BytesToKey algorithm. An HMAC is
// computed over the base64-encoded ciphertext and appended to produce the
// final wire-format string.
//
// # Encryption
//
// The default and recommended encryption is AES-256-CBC ([EncModeCBC]). A
// legacy CBC IV mode ([EncModeCBCLegacyIV]) is also supported for backward
// compatibility. Other AES modes are defined as constants but not yet
// implemented — they return [ErrUnsupportedEncryptionMode].
//
// The encryption subsystem is extensible via the [Encrypter] and [Decrypter]
// interfaces. Key derivation is extensible via the [KeyDeriver] interface,
// with [EVPBytesToKey] as the default implementation.
//
// # Digest and HMAC
//
// Seven hash algorithms are supported for both message digests and HMAC:
// MD5, SHA1, SHA256 (default), SHA384, SHA512, SHA3-256, and SHA3-512.
//
// # Compatibility
//
// This package produces SPA messages that are accepted by the legacy C
// fwknopd server (protocol version 3.0.0). Cross-validation testing confirms
// byte-identical encoding and successful cross-decryption for all supported
// configurations.
package fkospa
