package fkospa

import "errors"

var (
	// ErrInvalidData indicates that input data is malformed or out of range.
	ErrInvalidData = errors.New("invalid data")

	// ErrMessageTooLarge indicates that the encoded SPA message exceeds size limits.
	ErrMessageTooLarge = errors.New("message too large")

	// ErrMissingField indicates a required SPA field is empty or unset.
	ErrMissingField = errors.New("missing required field")

	// ErrDigestVerificationFailed indicates the decoded message digest does not match.
	ErrDigestVerificationFailed = errors.New("digest verification failed")

	// ErrHMACVerificationFailed indicates the HMAC on encrypted data does not match.
	ErrHMACVerificationFailed = errors.New("HMAC verification failed")

	// ErrDecryptionFailed indicates that decryption produced invalid plaintext.
	ErrDecryptionFailed = errors.New("decryption failed")

	// ErrUnsupportedEncryptionMode indicates the requested encryption mode is not implemented.
	ErrUnsupportedEncryptionMode = errors.New("unsupported encryption mode")

	// ErrInvalidKeyLen indicates the encryption or HMAC key length is invalid.
	ErrInvalidKeyLen = errors.New("invalid key length")

	// ErrUnsupportedDigestType indicates an unknown or invalid digest algorithm.
	ErrUnsupportedDigestType = errors.New("unsupported digest type")

	// ErrUnsupportedHMACType indicates an unknown or invalid HMAC algorithm.
	ErrUnsupportedHMACType = errors.New("unsupported HMAC type")
)
