package fkospa

import (
	"fmt"
	"strings"
)

// Encode builds the colon-delimited plaintext SPA message with the digest
// appended. This is the intermediate representation before encryption.
//
// Wire format:
//
//	RAND_VAL:B64(USERNAME):TIMESTAMP:VERSION:MSG_TYPE:B64(MESSAGE)[:B64(NAT)][:B64(AUTH)][:TIMEOUT]:DIGEST
//
// The plaintext fed to encryption is: encoded_fields + ":" + digest
func (m *Message) Encode() (string, error) {
	if err := m.validate(); err != nil {
		return "", err
	}

	var b strings.Builder

	// 1. Random value (16 decimal digits).
	b.WriteString(m.RandVal)

	// 2. Base64-encoded username.
	b.WriteByte(':')
	b.WriteString(B64Encode([]byte(m.Username)))

	// 3. Timestamp as unsigned integer.
	b.WriteByte(':')
	fmt.Fprintf(&b, "%d", m.Timestamp.Unix())

	// 4. Colon + version string.
	b.WriteByte(':')
	b.WriteString(ProtocolVersion)

	// 5. Message type (adjusted for client_timeout if needed).
	msgType := m.effectiveMessageType()
	b.WriteByte(':')
	fmt.Fprintf(&b, "%d", int(msgType))

	// 6. Base64-encoded message.
	b.WriteByte(':')
	b.WriteString(B64Encode([]byte(m.AccessMsg)))

	// 7. Optional: base64-encoded NAT access.
	if m.NATAccess != "" {
		b.WriteByte(':')
		b.WriteString(B64Encode([]byte(m.NATAccess)))
	}

	// 8. Optional: base64-encoded server auth.
	if m.ServerAuth != "" {
		b.WriteByte(':')
		b.WriteString(B64Encode([]byte(m.ServerAuth)))
	}

	// 9. Optional: client timeout (only if > 0 and not a command message).
	if m.ClientTimeout > 0 && msgType != CommandMsg {
		fmt.Fprintf(&b, ":%d", m.ClientTimeout)
	}

	encodedMsg := b.String()

	// Validate encoded message length.
	if len(encodedMsg) < minSPAEncodedMsgSize || len(encodedMsg) > maxSPAEncodedMsgSize {
		return "", fmt.Errorf("%w: encoded message length %d out of range [%d, %d]",
			ErrMessageTooLarge, len(encodedMsg), minSPAEncodedMsgSize, maxSPAEncodedMsgSize)
	}

	// 10. Compute digest of the encoded fields.
	digest, err := DigestBase64(m.DigestType, []byte(encodedMsg))
	if err != nil {
		return "", fmt.Errorf("computing digest: %w", err)
	}

	// The full plaintext is: encoded_fields + ":" + digest
	return encodedMsg + ":" + digest, nil
}

// Encrypt encodes the message, encrypts it, and optionally appends an HMAC.
// Returns the final SPA data string ready for transmission.
//
//   - encKey: encryption passphrase (required)
//   - hmacKey: HMAC key (if nil or empty, HMAC is skipped)
func (m *Message) Encrypt(encKey []byte, hmacKey []byte) (string, error) {
	// Encode the plaintext (fields + digest).
	plaintext, err := m.Encode()
	if err != nil {
		return "", err
	}

	// Get the encrypter for this mode.
	enc, err := encrypterFor(m.EncryptionMode)
	if err != nil {
		return "", err
	}

	// Encrypt the plaintext.
	ciphertext, err := enc.Encrypt([]byte(plaintext), encKey)
	if err != nil {
		return "", fmt.Errorf("encrypting: %w", err)
	}

	// Base64-encode the ciphertext (includes "Salted__" prefix → "U2FsdGVkX1").
	b64Ciphertext := B64Encode(ciphertext)

	// The wire format strips the first 10 chars ("U2FsdGVkX1") since they
	// are a constant prefix for AES encryption. The HMAC, however,
	// is computed on the FULL base64 string including the prefix.
	// See fko_get_spa_data() in the C code.
	strippedCiphertext := b64Ciphertext[len(B64SaltPrefix):]

	if len(hmacKey) == 0 {
		return strippedCiphertext, nil
	}

	// Compute HMAC over the FULL base64-encoded ciphertext (with prefix).
	hmacB64, err := ComputeHMACBase64(m.HMACType, []byte(b64Ciphertext), hmacKey)
	if err != nil {
		return "", fmt.Errorf("computing HMAC: %w", err)
	}

	// Final wire format: stripped_ciphertext + hmac_base64 (no separator).
	return strippedCiphertext + hmacB64, nil
}

// validate checks that all required fields are present and valid.
func (m *Message) validate() error {
	if err := validRandVal(m.RandVal); err != nil {
		return err
	}
	if err := validUsername(m.Username); err != nil {
		return err
	}
	if !m.MessageType.isValid() {
		return fmt.Errorf("%w: invalid message type %d", ErrInvalidData, m.MessageType)
	}

	// Validate the message content based on type.
	if m.MessageType == CommandMsg {
		if err := validCmdMsg(m.AccessMsg); err != nil {
			return err
		}
	} else {
		if err := validAccessMsg(m.AccessMsg); err != nil {
			return err
		}
	}

	// NAT access required for NAT message types.
	if m.MessageType.requiresNATAccess() {
		if err := validNATAccess(m.NATAccess); err != nil {
			return err
		}
	}

	return nil
}

// effectiveMessageType adjusts the message type based on client_timeout,
// matching the C implementation's logic in fko_encode_spa_data.
func (m *Message) effectiveMessageType() MessageType {
	if m.ClientTimeout == 0 || m.MessageType == CommandMsg {
		return m.MessageType
	}

	switch m.MessageType {
	case AccessMsg:
		return ClientTimeoutAccessMsg
	case NATAccessMsg:
		return ClientTimeoutNATAccessMsg
	case LocalNATAccessMsg:
		return ClientTimeoutLocalNATAccessMsg
	default:
		return m.MessageType
	}
}
