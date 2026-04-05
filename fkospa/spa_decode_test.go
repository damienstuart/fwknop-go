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
		EncryptionMode: EncryptionModeCBC,
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
		EncryptionMode: EncryptionModeCBC,
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
		EncryptionMode: EncryptionModeCBC,
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
		EncryptionMode: EncryptionModeCBC,
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
		EncryptionMode: EncryptionModeCBC,
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
		EncryptionMode: EncryptionModeCBC,
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
		DigestSHA512, DigestSHA3_256, DigestSHA3_512,
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
				EncryptionMode: EncryptionModeCBC,
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

func TestDecryptServerAuthRoundTrip(t *testing.T) {
	m := &Message{
		RandVal:        "1234567890123456",
		Username:       "authuser",
		Timestamp:      time.Unix(1705312800, 0),
		MessageType:    AccessMsg,
		AccessMsg:      "10.0.0.1,tcp/22",
		ServerAuth:     "my_server_auth_token",
		DigestType:     DigestSHA256,
		EncryptionMode: EncryptionModeCBC,
		HMACType:       HMACSHA256,
	}

	encKey := []byte("server_auth_key!")
	hmacKey := []byte("server_auth_hmac")

	spaData, err := m.Encrypt(encKey, hmacKey)
	if err != nil {
		t.Fatalf("Encrypt error: %v", err)
	}

	decoded, err := Decrypt(spaData, encKey, hmacKey)
	if err != nil {
		t.Fatalf("Decrypt error: %v", err)
	}

	if decoded.ServerAuth != m.ServerAuth {
		t.Errorf("ServerAuth = %q, want %q", decoded.ServerAuth, m.ServerAuth)
	}
	if decoded.Username != m.Username {
		t.Errorf("Username = %q, want %q", decoded.Username, m.Username)
	}
}

func TestDecryptAllHMACTypes(t *testing.T) {
	hmacTypes := []HMACType{
		HMACMD5, HMACSHA1, HMACSHA256, HMACSHA384,
		HMACSHA512, HMACSHA3_256, HMACSHA3_512,
	}

	for _, ht := range hmacTypes {
		t.Run(ht.String(), func(t *testing.T) {
			m := &Message{
				RandVal:        "1234567890123456",
				Username:       "user",
				Timestamp:      time.Unix(1705312800, 0),
				MessageType:    AccessMsg,
				AccessMsg:      "10.0.0.1,tcp/22",
				DigestType:     DigestSHA256,
				EncryptionMode: EncryptionModeCBC,
				HMACType:       ht,
			}

			spaData, err := m.Encrypt([]byte("key"), []byte("hmac"))
			if err != nil {
				t.Fatalf("Encrypt error: %v", err)
			}

			decoded, err := Decrypt(spaData, []byte("key"), []byte("hmac"),
				WithDecryptHMACType(ht))
			if err != nil {
				t.Fatalf("Decrypt error: %v", err)
			}

			if decoded.AccessMsg != m.AccessMsg {
				t.Errorf("AccessMsg = %q, want %q", decoded.AccessMsg, m.AccessMsg)
			}
		})
	}
}

func TestDecryptNATAccessRoundTrip(t *testing.T) {
	m := &Message{
		RandVal:        "1234567890123456",
		Username:       "natuser",
		Timestamp:      time.Unix(1705312800, 0),
		MessageType:    LocalNATAccessMsg,
		AccessMsg:      "10.0.0.1,tcp/22",
		NATAccess:      "192.168.1.100,22",
		DigestType:     DigestSHA256,
		EncryptionMode: EncryptionModeCBC,
		HMACType:       HMACSHA256,
	}

	spaData, err := m.Encrypt([]byte("nat_key"), []byte("nat_hmac"))
	if err != nil {
		t.Fatalf("Encrypt error: %v", err)
	}

	decoded, err := Decrypt(spaData, []byte("nat_key"), []byte("nat_hmac"))
	if err != nil {
		t.Fatalf("Decrypt error: %v", err)
	}

	if decoded.MessageType != LocalNATAccessMsg {
		t.Errorf("MessageType = %v, want LocalNATAccessMsg", decoded.MessageType)
	}
	if decoded.NATAccess != m.NATAccess {
		t.Errorf("NATAccess = %q, want %q", decoded.NATAccess, m.NATAccess)
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
		EncryptionMode: EncryptionModeCBCLegacy,
		HMACType:       HMACSHA256,
	}

	spaData, err := m.Encrypt([]byte("short"), []byte("hmac"))
	if err != nil {
		t.Fatalf("Encrypt error: %v", err)
	}

	decoded, err := Decrypt(spaData, []byte("short"), []byte("hmac"),
		WithDecryptMode(EncryptionModeCBCLegacy))
	if err != nil {
		t.Fatalf("Decrypt error: %v", err)
	}

	if decoded.Username != "legacyuser" {
		t.Errorf("Username = %q, want %q", decoded.Username, "legacyuser")
	}
}
