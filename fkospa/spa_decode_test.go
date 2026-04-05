package fkospa

import (
	"testing"
	"time"
)

func TestDecryptRoundTrip(t *testing.T) {
	ts := time.Unix(1705312800, 0)
	original := &Message{
		RandVal:        "1234567890123456",
		Username:       "testuser",
		Timestamp:      ts,
		MessageType:    AccessMsg,
		AccessMsg:      "192.168.1.1,tcp/22",
		DigestType:     DigestSHA256,
		EncryptionMode: EncModeCBC,
		HMACType:       HMACSHA256,
	}

	encKey := []byte("my_secret_key")
	hmacKey := []byte("my_hmac_key")

	spaData, err := original.Encrypt(encKey, hmacKey)
	if err != nil {
		t.Fatalf("Encrypt error: %v", err)
	}

	decoded, err := Decrypt(spaData, encKey, hmacKey)
	if err != nil {
		t.Fatalf("Decrypt error: %v", err)
	}

	if decoded.RandVal != original.RandVal {
		t.Errorf("RandVal = %q, want %q", decoded.RandVal, original.RandVal)
	}
	if decoded.Username != original.Username {
		t.Errorf("Username = %q, want %q", decoded.Username, original.Username)
	}
	if decoded.Timestamp.Unix() != original.Timestamp.Unix() {
		t.Errorf("Timestamp = %v, want %v", decoded.Timestamp, original.Timestamp)
	}
	if decoded.AccessMsg != original.AccessMsg {
		t.Errorf("AccessMsg = %q, want %q", decoded.AccessMsg, original.AccessMsg)
	}
	// Message type will be AccessMsg (1) since ClientTimeout is 0.
	if decoded.MessageType != AccessMsg {
		t.Errorf("MessageType = %v, want AccessMsg", decoded.MessageType)
	}
}

func TestDecryptRoundTripWithNAT(t *testing.T) {
	original := &Message{
		RandVal:        "9876543210123456",
		Username:       "admin",
		Timestamp:      time.Unix(1700000000, 0),
		MessageType:    NATAccessMsg,
		AccessMsg:      "10.0.0.1,tcp/443",
		NATAccess:      "192.168.1.100,443",
		DigestType:     DigestSHA256,
		EncryptionMode: EncModeCBC,
		HMACType:       HMACSHA256,
	}

	encKey := []byte("nat_test_key")
	hmacKey := []byte("nat_hmac_key")

	spaData, err := original.Encrypt(encKey, hmacKey)
	if err != nil {
		t.Fatalf("Encrypt error: %v", err)
	}

	decoded, err := Decrypt(spaData, encKey, hmacKey)
	if err != nil {
		t.Fatalf("Decrypt error: %v", err)
	}

	if decoded.NATAccess != original.NATAccess {
		t.Errorf("NATAccess = %q, want %q", decoded.NATAccess, original.NATAccess)
	}
	if decoded.MessageType != NATAccessMsg {
		t.Errorf("MessageType = %v, want NATAccessMsg", decoded.MessageType)
	}
}

func TestDecryptRoundTripWithTimeout(t *testing.T) {
	original := &Message{
		RandVal:        "5555555555555555",
		Username:       "timeoutuser",
		Timestamp:      time.Unix(1700000000, 0),
		MessageType:    AccessMsg,
		AccessMsg:      "10.0.0.1,tcp/22",
		ClientTimeout:  60,
		DigestType:     DigestSHA256,
		EncryptionMode: EncModeCBC,
		HMACType:       HMACSHA256,
	}

	encKey := []byte("timeout_key")
	hmacKey := []byte("timeout_hmac")

	spaData, err := original.Encrypt(encKey, hmacKey)
	if err != nil {
		t.Fatalf("Encrypt error: %v", err)
	}

	decoded, err := Decrypt(spaData, encKey, hmacKey)
	if err != nil {
		t.Fatalf("Decrypt error: %v", err)
	}

	// Should be decoded as ClientTimeoutAccessMsg (3).
	if decoded.MessageType != ClientTimeoutAccessMsg {
		t.Errorf("MessageType = %v, want ClientTimeoutAccessMsg", decoded.MessageType)
	}
	if decoded.ClientTimeout != original.ClientTimeout {
		t.Errorf("ClientTimeout = %d, want %d", decoded.ClientTimeout, original.ClientTimeout)
	}
}

func TestDecryptWithoutHMAC(t *testing.T) {
	original := &Message{
		RandVal:        "1234567890123456",
		Username:       "nohmac",
		Timestamp:      time.Unix(1705312800, 0),
		MessageType:    AccessMsg,
		AccessMsg:      "192.168.1.1,tcp/22",
		DigestType:     DigestSHA256,
		EncryptionMode: EncModeCBC,
		HMACType:       HMACSHA256,
	}

	encKey := []byte("encryption_only")

	spaData, err := original.Encrypt(encKey, nil)
	if err != nil {
		t.Fatalf("Encrypt error: %v", err)
	}

	decoded, err := Decrypt(spaData, encKey, nil)
	if err != nil {
		t.Fatalf("Decrypt error: %v", err)
	}

	if decoded.Username != original.Username {
		t.Errorf("Username = %q, want %q", decoded.Username, original.Username)
	}
}

func TestDecryptWrongEncKey(t *testing.T) {
	original := &Message{
		RandVal:        "1234567890123456",
		Username:       "testuser",
		Timestamp:      time.Unix(1705312800, 0),
		MessageType:    AccessMsg,
		AccessMsg:      "192.168.1.1,tcp/22",
		DigestType:     DigestSHA256,
		EncryptionMode: EncModeCBC,
		HMACType:       HMACSHA256,
	}

	spaData, _ := original.Encrypt([]byte("correct_key"), nil)

	_, err := Decrypt(spaData, []byte("wrong_key"), nil)
	if err == nil {
		t.Error("expected error decrypting with wrong key")
	}
}

func TestDecryptWrongHMACKey(t *testing.T) {
	original := &Message{
		RandVal:        "1234567890123456",
		Username:       "testuser",
		Timestamp:      time.Unix(1705312800, 0),
		MessageType:    AccessMsg,
		AccessMsg:      "192.168.1.1,tcp/22",
		DigestType:     DigestSHA256,
		EncryptionMode: EncModeCBC,
		HMACType:       HMACSHA256,
	}

	spaData, _ := original.Encrypt([]byte("enc_key"), []byte("correct_hmac"))

	_, err := Decrypt(spaData, []byte("enc_key"), []byte("wrong_hmac"))
	if err == nil {
		t.Error("expected HMAC verification error")
	}
}

func TestDecryptAllDigestTypes(t *testing.T) {
	digestTypes := []DigestType{
		DigestMD5, DigestSHA1, DigestSHA256, DigestSHA384,
		DigestSHA512, DigestSHA3256, DigestSHA3512,
	}

	for _, dt := range digestTypes {
		t.Run(dt.String(), func(t *testing.T) {
			m := &Message{
				RandVal:        "1234567890123456",
				Username:       "user",
				Timestamp:      time.Unix(1705312800, 0),
				MessageType:    AccessMsg,
				AccessMsg:      "10.0.0.1,tcp/22",
				DigestType:     dt,
				EncryptionMode: EncModeCBC,
				HMACType:       HMACSHA256,
			}

			spaData, err := m.Encrypt([]byte("key"), []byte("hmac"))
			if err != nil {
				t.Fatalf("Encrypt error: %v", err)
			}

			decoded, err := Decrypt(spaData, []byte("key"), []byte("hmac"))
			if err != nil {
				t.Fatalf("Decrypt error: %v", err)
			}

			if decoded.AccessMsg != m.AccessMsg {
				t.Errorf("AccessMsg = %q, want %q", decoded.AccessMsg, m.AccessMsg)
			}
		})
	}
}

func TestDecryptLegacyIVMode(t *testing.T) {
	m := &Message{
		RandVal:        "1234567890123456",
		Username:       "legacyuser",
		Timestamp:      time.Unix(1705312800, 0),
		MessageType:    AccessMsg,
		AccessMsg:      "10.0.0.1,tcp/22",
		DigestType:     DigestSHA256,
		EncryptionMode: EncModeCBCLegacyIV,
		HMACType:       HMACSHA256,
	}

	spaData, err := m.Encrypt([]byte("short"), []byte("hmac"))
	if err != nil {
		t.Fatalf("Encrypt error: %v", err)
	}

	decoded, err := Decrypt(spaData, []byte("short"), []byte("hmac"),
		WithDecryptMode(EncModeCBCLegacyIV))
	if err != nil {
		t.Fatalf("Decrypt error: %v", err)
	}

	if decoded.Username != "legacyuser" {
		t.Errorf("Username = %q, want %q", decoded.Username, "legacyuser")
	}
}
