package main

import (
	"os"
	"path/filepath"
	"testing"
)

func TestConvertServerBasic(t *testing.T) {
	data := []byte(`UDPSERV_PORT    62201;
VERBOSE         1;
MAX_SPA_PACKET_AGE    120;
SYSLOG_IDENTITY       fwknopd;
`)

	config, warnings := parseServerConfig(data)

	if len(warnings) != 0 {
		t.Errorf("unexpected warnings: %v", warnings)
	}
	if got := config["udp_port"]; got != "62201" {
		t.Errorf("udp_port = %v, want %q", got, "62201")
	}
	if got := config["verbose"]; got != "1" {
		t.Errorf("verbose = %v, want %q", got, "1")
	}
	if got := config["max_spa_packet_age"]; got != "120" {
		t.Errorf("max_spa_packet_age = %v, want %q", got, "120")
	}
	if got := config["syslog_identity"]; got != "fwknopd" {
		t.Errorf("syslog_identity = %v, want %q", got, "fwknopd")
	}
}

func TestConvertServerSemicolonStripping(t *testing.T) {
	data := []byte(`UDPSERV_PORT    62201;
VERBOSE         1;
`)

	config, _ := parseServerConfig(data)

	// Values should have semicolons stripped.
	if got := config["udp_port"]; got != "62201" {
		t.Errorf("udp_port = %v (semicolon not stripped?)", got)
	}
}

func TestConvertServerUnsupportedKeys(t *testing.T) {
	data := []byte(`UDPSERV_PORT    62201;
PCAP_INTF       eth0;
PCAP_FILTER     udp port 62201;
IPT_INPUT_ACCESS    ACCEPT;
ENABLE_IPT_FORWARDING    N;
`)

	_, warnings := parseServerConfig(data)

	// Should have warnings for unsupported keys.
	if len(warnings) < 3 {
		t.Errorf("expected at least 3 warnings, got %d: %v", len(warnings), warnings)
	}
}

func TestConvertServerIPTDetection(t *testing.T) {
	data := []byte(`UDPSERV_PORT    62201;
IPT_INPUT_ACCESS    ACCEPT;
`)

	_, warnings := parseServerConfig(data)

	// Should suggest iptables action template.
	found := false
	for _, w := range warnings {
		if contains(w, "iptables.yaml") {
			found = true
			break
		}
	}
	if !found {
		t.Error("expected warning suggesting iptables.yaml action template")
	}
}

func contains(s, substr string) bool {
	return len(s) >= len(substr) && searchString(s, substr)
}

func searchString(s, substr string) bool {
	for i := 0; i <= len(s)-len(substr); i++ {
		if s[i:i+len(substr)] == substr {
			return true
		}
	}
	return false
}

func TestConvertServerComments(t *testing.T) {
	data := []byte(`# This is a comment
UDPSERV_PORT    62201;
# Another comment
VERBOSE         1;
`)

	config, _ := parseServerConfig(data)

	if got := config["udp_port"]; got != "62201" {
		t.Errorf("udp_port = %v", got)
	}
	if got := config["verbose"]; got != "1" {
		t.Errorf("verbose = %v", got)
	}
}

func TestConvertServerBooleans(t *testing.T) {
	data := []byte(`ENABLE_SPA_PACKET_AGING    Y;
ENABLE_DIGEST_PERSISTENCE  N;
`)

	config, _ := parseServerConfig(data)

	if got := config["enable_spa_packet_aging"]; got != true {
		t.Errorf("enable_spa_packet_aging = %v, want true", got)
	}
	if got := config["enable_digest_persistence"]; got != false {
		t.Errorf("enable_digest_persistence = %v, want false", got)
	}
}

func TestConvertServerEndToEnd(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "fwknopd.conf")
	os.WriteFile(path, []byte(`UDPSERV_PORT    62201;
VERBOSE         1;
`), 0600)

	err := convertServer(path)
	if err != nil {
		t.Fatalf("convertServer error: %v", err)
	}
}

func TestConvertServerMissingFile(t *testing.T) {
	err := convertServer("/nonexistent/fwknopd.conf")
	if err == nil {
		t.Error("expected error for missing file")
	}
}
