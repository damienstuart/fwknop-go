package fkospa

import (
	"strings"
	"testing"
	"time"
)

func TestNewDefaults(t *testing.T) {
	m, err := New()
	if err != nil {
		t.Fatalf("New() error: %v", err)
	}

	if len(m.RandVal) != fkoRandValSize {
		t.Errorf("RandVal length = %d, want %d", len(m.RandVal), fkoRandValSize)
	}
	if m.Username == "" {
		t.Error("Username should be auto-detected")
	}
	if m.MessageType != AccessMsg {
		t.Errorf("MessageType = %v, want AccessMsg", m.MessageType)
	}
	if m.DigestType != DigestSHA256 {
		t.Errorf("DigestType = %v, want DigestSHA256", m.DigestType)
	}
	if m.EncryptionMode != EncModeCBC {
		t.Errorf("EncryptionMode = %v, want EncModeCBC", m.EncryptionMode)
	}
	if m.HMACType != HMACSHA256 {
		t.Errorf("HMACType = %v, want HMACSHA256", m.HMACType)
	}
}

func TestNewWithOptions(t *testing.T) {
	ts := time.Date(2024, 1, 15, 12, 0, 0, 0, time.UTC)
	m, err := NewWithOptions(
		WithRandVal("1234567890123456"),
		WithUsername("testuser"),
		WithTimestamp(ts),
		WithAccessMsg("192.168.1.1,tcp/22"),
	)
	if err != nil {
		t.Fatalf("NewWithOptions error: %v", err)
	}

	if m.RandVal != "1234567890123456" {
		t.Errorf("RandVal = %q, want %q", m.RandVal, "1234567890123456")
	}
	if m.Username != "testuser" {
		t.Errorf("Username = %q, want %q", m.Username, "testuser")
	}
	if !m.Timestamp.Equal(ts) {
		t.Errorf("Timestamp = %v, want %v", m.Timestamp, ts)
	}
}

func TestEncodeWireFormat(t *testing.T) {
	ts := time.Unix(1705312800, 0)
	m := &Message{
		RandVal:        "1234567890123456",
		Username:       "testuser",
		Timestamp:      ts,
		MessageType:    AccessMsg,
		AccessMsg:      "192.168.1.1,tcp/22",
		DigestType:     DigestSHA256,
		EncryptionMode: EncModeCBC,
		HMACType:       HMACSHA256,
	}

	encoded, err := m.Encode()
	if err != nil {
		t.Fatalf("Encode error: %v", err)
	}

	// The encoded format should be:
	// RAND_VAL:B64(USERNAME):TIMESTAMP:VERSION:MSG_TYPE:B64(MESSAGE):DIGEST
	parts := strings.Split(encoded, ":")
	if len(parts) < minSPAFields+1 { // +1 for digest
		t.Fatalf("expected at least %d fields, got %d", minSPAFields+1, len(parts))
	}

	// Verify individual fields.
	if parts[0] != "1234567890123456" {
		t.Errorf("field 0 (rand_val) = %q", parts[0])
	}

	// Username should be base64 of "testuser".
	usernameDecoded, err := B64Decode(parts[1])
	if err != nil {
		t.Fatalf("decoding username: %v", err)
	}
	if string(usernameDecoded) != "testuser" {
		t.Errorf("decoded username = %q, want %q", usernameDecoded, "testuser")
	}

	// Timestamp.
	if parts[2] != "1705312800" {
		t.Errorf("field 2 (timestamp) = %q, want %q", parts[2], "1705312800")
	}

	// Version.
	if parts[3] != ProtocolVersion {
		t.Errorf("field 3 (version) = %q, want %q", parts[3], ProtocolVersion)
	}

	// Message type.
	if parts[4] != "1" { // AccessMsg = 1
		t.Errorf("field 4 (msg_type) = %q, want %q", parts[4], "1")
	}

	// Message should be base64 of "192.168.1.1,tcp/22".
	msgDecoded, err := B64Decode(parts[5])
	if err != nil {
		t.Fatalf("decoding message: %v", err)
	}
	if string(msgDecoded) != "192.168.1.1,tcp/22" {
		t.Errorf("decoded message = %q, want %q", msgDecoded, "192.168.1.1,tcp/22")
	}

	// Last field should be the SHA256 digest (43 chars in SPA base64).
	digest := parts[len(parts)-1]
	if len(digest) != 43 {
		t.Errorf("digest length = %d, want 43 (SHA256 base64)", len(digest))
	}
}

func TestEncodeWithNATAccess(t *testing.T) {
	m := &Message{
		RandVal:        "1234567890123456",
		Username:       "testuser",
		Timestamp:      time.Unix(1705312800, 0),
		MessageType:    NATAccessMsg,
		AccessMsg:      "192.168.1.1,tcp/22",
		NATAccess:      "10.0.0.1,22",
		DigestType:     DigestSHA256,
		EncryptionMode: EncModeCBC,
		HMACType:       HMACSHA256,
	}

	encoded, err := m.Encode()
	if err != nil {
		t.Fatalf("Encode error: %v", err)
	}

	// Should have 8 parts (7 fields + digest) with NAT access included.
	parts := strings.Split(encoded, ":")
	if len(parts) != 8 {
		t.Errorf("expected 8 parts, got %d: %v", len(parts), parts)
	}
}

func TestEncodeWithClientTimeout(t *testing.T) {
	m := &Message{
		RandVal:        "1234567890123456",
		Username:       "testuser",
		Timestamp:      time.Unix(1705312800, 0),
		MessageType:    AccessMsg,
		AccessMsg:      "192.168.1.1,tcp/22",
		ClientTimeout:  30,
		DigestType:     DigestSHA256,
		EncryptionMode: EncModeCBC,
		HMACType:       HMACSHA256,
	}

	encoded, err := m.Encode()
	if err != nil {
		t.Fatalf("Encode error: %v", err)
	}

	// Message type should be auto-adjusted to ClientTimeoutAccessMsg (3).
	parts := strings.Split(encoded, ":")
	if parts[4] != "3" {
		t.Errorf("message type = %q, want %q (ClientTimeoutAccessMsg)", parts[4], "3")
	}
}

func TestEncryptRoundTrip(t *testing.T) {
	m := &Message{
		RandVal:        "1234567890123456",
		Username:       "testuser",
		Timestamp:      time.Unix(1705312800, 0),
		MessageType:    AccessMsg,
		AccessMsg:      "192.168.1.1,tcp/22",
		DigestType:     DigestSHA256,
		EncryptionMode: EncModeCBC,
		HMACType:       HMACSHA256,
	}

	encKey := []byte("my_encryption_key")
	hmacKey := []byte("my_hmac_key")

	spaData, err := m.Encrypt(encKey, hmacKey)
	if err != nil {
		t.Fatalf("Encrypt error: %v", err)
	}

	if spaData == "" {
		t.Fatal("Encrypt returned empty string")
	}

	// The SPA data should NOT start with the Rijndael salt prefix
	// (it's stripped from the wire format per the C protocol).
	if strings.HasPrefix(spaData, B64RijndaelSalt) {
		t.Errorf("SPA data should not start with %q (should be stripped)", B64RijndaelSalt)
	}

	t.Logf("SPA data length: %d", len(spaData))
	t.Logf("SPA data: %s", spaData)
}

func TestEncryptWithoutHMAC(t *testing.T) {
	m := &Message{
		RandVal:        "1234567890123456",
		Username:       "testuser",
		Timestamp:      time.Unix(1705312800, 0),
		MessageType:    AccessMsg,
		AccessMsg:      "192.168.1.1,tcp/22",
		DigestType:     DigestSHA256,
		EncryptionMode: EncModeCBC,
		HMACType:       HMACSHA256,
	}

	spaData, err := m.Encrypt([]byte("key"), nil)
	if err != nil {
		t.Fatalf("Encrypt error: %v", err)
	}

	// Without HMAC, should be the stripped base64 ciphertext.
	if spaData == "" {
		t.Error("SPA data should not be empty")
	}
}

func TestValidationErrors(t *testing.T) {
	tests := []struct {
		name string
		msg  Message
	}{
		{
			name: "empty username",
			msg: Message{
				RandVal: "1234567890123456", Username: "",
				Timestamp: time.Now(), MessageType: AccessMsg,
				AccessMsg: "1.2.3.4,tcp/22", DigestType: DigestSHA256,
			},
		},
		{
			name: "empty access message",
			msg: Message{
				RandVal: "1234567890123456", Username: "user",
				Timestamp: time.Now(), MessageType: AccessMsg,
				AccessMsg: "", DigestType: DigestSHA256,
			},
		},
		{
			name: "invalid access message format",
			msg: Message{
				RandVal: "1234567890123456", Username: "user",
				Timestamp: time.Now(), MessageType: AccessMsg,
				AccessMsg: "not_valid", DigestType: DigestSHA256,
			},
		},
		{
			name: "NAT type without NAT access",
			msg: Message{
				RandVal: "1234567890123456", Username: "user",
				Timestamp: time.Now(), MessageType: NATAccessMsg,
				AccessMsg: "1.2.3.4,tcp/22", NATAccess: "",
				DigestType: DigestSHA256,
			},
		},
		{
			name: "bad rand_val length",
			msg: Message{
				RandVal: "123", Username: "user",
				Timestamp: time.Now(), MessageType: AccessMsg,
				AccessMsg: "1.2.3.4,tcp/22", DigestType: DigestSHA256,
			},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			_, err := tc.msg.Encode()
			if err == nil {
				t.Error("expected validation error, got nil")
			}
		})
	}
}

func TestEffectiveMessageType(t *testing.T) {
	tests := []struct {
		msgType  MessageType
		timeout  uint32
		expected MessageType
	}{
		{AccessMsg, 0, AccessMsg},
		{AccessMsg, 30, ClientTimeoutAccessMsg},
		{NATAccessMsg, 30, ClientTimeoutNATAccessMsg},
		{LocalNATAccessMsg, 30, ClientTimeoutLocalNATAccessMsg},
		{CommandMsg, 30, CommandMsg}, // command ignores timeout
		{ClientTimeoutAccessMsg, 30, ClientTimeoutAccessMsg}, // already timeout type
	}

	for _, tc := range tests {
		m := &Message{MessageType: tc.msgType, ClientTimeout: tc.timeout}
		got := m.effectiveMessageType()
		if got != tc.expected {
			t.Errorf("effectiveMessageType(%v, timeout=%d) = %v, want %v",
				tc.msgType, tc.timeout, got, tc.expected)
		}
	}
}
