package main

import (
	"log"
	"net"
	"os"
	"testing"
	"time"

	"github.com/damienstuart/fwknop-go/fkospa"
)

// testLogger returns a spaLogger that writes to stderr for test visibility.
func testLogger() *spaLogger {
	return &spaLogger{
		fileLogger: log.New(os.Stderr, "[test] ", log.LstdFlags),
		verbose:    true,
	}
}

// makeTestSPA creates an encrypted SPA packet with the given parameters.
func makeTestSPA(t *testing.T, encKey, hmacKey []byte, accessMsg string) string {
	t.Helper()
	m, err := fkospa.NewWithOptions(
		fkospa.WithAccessMsg(accessMsg),
	)
	if err != nil {
		t.Fatalf("creating SPA message: %v", err)
	}

	spaData, err := m.Encrypt(encKey, hmacKey)
	if err != nil {
		t.Fatalf("encrypting SPA message: %v", err)
	}
	return spaData
}

func TestProcessSPAPacketSuccess(t *testing.T) {
	encKey := []byte("test_enc_key_123")
	hmacKey := []byte("test_hmac_key_456")

	stanza := accessStanza{
		Source:        "ANY",
		KeyBase64:     "",
		HMACKeyBase64: "",
	}
	stanza.encKey = encKey
	stanza.hmacKey = hmacKey
	stanza.hmacType = fkospa.HMACSHA256
	stanza.encMode = fkospa.EncModeCBC
	stanza.sourceNets = []*net.IPNet{{IP: net.IPv4(0, 0, 0, 0), Mask: net.CIDRMask(0, 32)}}
	stanza.Source = "ANY"
	stanza.FWAccessTimeout = 30

	cfg := &serverConfig{MaxSPAPacketAge: 120, Test: true}
	replay := newReplayCache(2 * time.Minute)
	logger := testLogger()

	spaData := makeTestSPA(t, encKey, hmacKey, "127.0.0.1,tcp/22")
	srcIP := net.ParseIP("127.0.0.1")

	// Should process without panicking or logging errors.
	processSPAPacket(cfg, []accessStanza{stanza}, replay, logger, spaData, srcIP)
}

func TestProcessSPAPacketNoMatchingStanza(t *testing.T) {
	encKey := []byte("test_enc_key_123")
	hmacKey := []byte("test_hmac_key_456")

	// Stanza only matches 192.168.1.0/24.
	stanza := accessStanza{Source: "192.168.1.0/24"}
	stanza.encKey = encKey
	stanza.hmacKey = hmacKey
	stanza.hmacType = fkospa.HMACSHA256
	stanza.encMode = fkospa.EncModeCBC
	_, ipNet, _ := net.ParseCIDR("192.168.1.0/24")
	stanza.sourceNets = []*net.IPNet{ipNet}
	stanza.FWAccessTimeout = 30

	cfg := &serverConfig{MaxSPAPacketAge: 120, Test: true}
	replay := newReplayCache(2 * time.Minute)
	logger := testLogger()

	spaData := makeTestSPA(t, encKey, hmacKey, "10.0.0.1,tcp/22")
	srcIP := net.ParseIP("10.0.0.1") // Does NOT match 192.168.1.0/24

	// Should not panic — will log "no matching stanza".
	processSPAPacket(cfg, []accessStanza{stanza}, replay, logger, spaData, srcIP)
}

func TestProcessSPAPacketWrongKey(t *testing.T) {
	encKey := []byte("correct_key_1234")
	hmacKey := []byte("correct_hmac_key")
	wrongKey := []byte("wrong_key_000000")

	stanza := accessStanza{Source: "ANY"}
	stanza.encKey = wrongKey // wrong key
	stanza.hmacKey = hmacKey
	stanza.hmacType = fkospa.HMACSHA256
	stanza.encMode = fkospa.EncModeCBC
	stanza.sourceNets = []*net.IPNet{{IP: net.IPv4(0, 0, 0, 0), Mask: net.CIDRMask(0, 32)}}
	stanza.FWAccessTimeout = 30

	cfg := &serverConfig{MaxSPAPacketAge: 120, Test: true}
	replay := newReplayCache(2 * time.Minute)
	logger := testLogger()

	spaData := makeTestSPA(t, encKey, hmacKey, "127.0.0.1,tcp/22")
	srcIP := net.ParseIP("127.0.0.1")

	// Should fail decryption — will log "no matching stanza" since the only one fails.
	processSPAPacket(cfg, []accessStanza{stanza}, replay, logger, spaData, srcIP)
}

func TestProcessSPAPacketReplayRejected(t *testing.T) {
	encKey := []byte("replay_test_key!")
	hmacKey := []byte("replay_hmac_key!")

	stanza := accessStanza{Source: "ANY"}
	stanza.encKey = encKey
	stanza.hmacKey = hmacKey
	stanza.hmacType = fkospa.HMACSHA256
	stanza.encMode = fkospa.EncModeCBC
	stanza.sourceNets = []*net.IPNet{{IP: net.IPv4(0, 0, 0, 0), Mask: net.CIDRMask(0, 32)}}
	stanza.FWAccessTimeout = 30

	cfg := &serverConfig{MaxSPAPacketAge: 120, Test: true}
	replay := newReplayCache(2 * time.Minute)
	logger := testLogger()

	spaData := makeTestSPA(t, encKey, hmacKey, "127.0.0.1,tcp/22")
	srcIP := net.ParseIP("127.0.0.1")

	// First time — should succeed.
	processSPAPacket(cfg, []accessStanza{stanza}, replay, logger, spaData, srcIP)

	// Second time with same data — replay should be detected.
	processSPAPacket(cfg, []accessStanza{stanza}, replay, logger, spaData, srcIP)
	// The replay detection is logged but doesn't panic. We verify the replay
	// cache directly.
	digest, _ := fkospa.DigestBase64(fkospa.DigestSHA256, []byte(spaData))
	if !replay.isDuplicate(digest) {
		t.Error("digest should be in replay cache after first processing")
	}
}

func TestProcessSPAPacketTriesMultipleStanzas(t *testing.T) {
	correctKey := []byte("correct_enc_key!")
	hmacKey := []byte("shared_hmac_key!")
	wrongKey := []byte("wrong_enc_key!!!")

	// First stanza has wrong encryption key but matching source.
	stanza1 := accessStanza{Source: "ANY"}
	stanza1.encKey = wrongKey
	stanza1.hmacKey = hmacKey
	stanza1.hmacType = fkospa.HMACSHA256
	stanza1.encMode = fkospa.EncModeCBC
	stanza1.sourceNets = []*net.IPNet{{IP: net.IPv4(0, 0, 0, 0), Mask: net.CIDRMask(0, 32)}}
	stanza1.FWAccessTimeout = 30

	// Second stanza has correct key.
	stanza2 := accessStanza{Source: "ANY"}
	stanza2.encKey = correctKey
	stanza2.hmacKey = hmacKey
	stanza2.hmacType = fkospa.HMACSHA256
	stanza2.encMode = fkospa.EncModeCBC
	stanza2.sourceNets = []*net.IPNet{{IP: net.IPv4(0, 0, 0, 0), Mask: net.CIDRMask(0, 32)}}
	stanza2.FWAccessTimeout = 30

	cfg := &serverConfig{MaxSPAPacketAge: 120, Test: true}
	replay := newReplayCache(2 * time.Minute)
	logger := testLogger()

	spaData := makeTestSPA(t, correctKey, hmacKey, "127.0.0.1,tcp/22")
	srcIP := net.ParseIP("127.0.0.1")

	// Should fail stanza1, succeed on stanza2.
	processSPAPacket(cfg, []accessStanza{stanza1, stanza2}, replay, logger, spaData, srcIP)

	// Verify it was processed (should be in replay cache).
	digest, _ := fkospa.DigestBase64(fkospa.DigestSHA256, []byte(spaData))
	if !replay.isDuplicate(digest) {
		t.Error("packet should have been processed via stanza2")
	}
}
