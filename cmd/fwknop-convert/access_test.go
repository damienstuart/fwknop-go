package main

import (
	"os"
	"path/filepath"
	"testing"
)

func TestConvertAccessBasic(t *testing.T) {
	data := []byte(`SOURCE                      ANY;
OPEN_PORTS                  tcp/22;
KEY_BASE64                  dGVzdGtleQ==;
HMAC_KEY_BASE64             dGVzdGhtYWM=;
FW_ACCESS_TIMEOUT           30;
`)

	stanzas, warnings := parseAccessConfig(data)

	if len(warnings) != 0 {
		t.Errorf("unexpected warnings: %v", warnings)
	}
	if len(stanzas) != 1 {
		t.Fatalf("expected 1 stanza, got %d", len(stanzas))
	}

	s := stanzas[0]
	if got := s["source"]; got != "ANY" {
		t.Errorf("source = %v, want %q", got, "ANY")
	}
	if got := s["key_base64"]; got != "dGVzdGtleQ==" {
		t.Errorf("key_base64 = %v, want %q", got, "dGVzdGtleQ==")
	}
	if got := s["access_timeout"]; got != "30" {
		t.Errorf("access_timeout = %v, want %q", got, "30")
	}
}

func TestConvertAccessMultipleStanzas(t *testing.T) {
	data := []byte(`SOURCE                      192.168.1.0/24;
OPEN_PORTS                  tcp/22;
KEY_BASE64                  key1;
FW_ACCESS_TIMEOUT           60;

SOURCE                      ANY;
OPEN_PORTS                  tcp/22,tcp/443;
KEY_BASE64                  key2;
`)

	stanzas, _ := parseAccessConfig(data)

	if len(stanzas) != 2 {
		t.Fatalf("expected 2 stanzas, got %d", len(stanzas))
	}
	if got := stanzas[0]["source"]; got != "192.168.1.0/24" {
		t.Errorf("stanza 0 source = %v", got)
	}
	if got := stanzas[1]["source"]; got != "ANY" {
		t.Errorf("stanza 1 source = %v", got)
	}
}

func TestConvertAccessOpenPortsList(t *testing.T) {
	data := []byte(`SOURCE    ANY;
OPEN_PORTS    tcp/22, tcp/443, udp/53;
KEY_BASE64    key;
`)

	stanzas, _ := parseAccessConfig(data)

	ports, ok := stanzas[0]["open_ports"].([]string)
	if !ok {
		t.Fatalf("open_ports is not []string: %T", stanzas[0]["open_ports"])
	}
	if len(ports) != 3 {
		t.Fatalf("expected 3 ports, got %d: %v", len(ports), ports)
	}
	if ports[0] != "tcp/22" || ports[1] != "tcp/443" || ports[2] != "udp/53" {
		t.Errorf("ports = %v", ports)
	}
}

func TestConvertAccessBooleanValues(t *testing.T) {
	data := []byte(`SOURCE    ANY;
KEY_BASE64    key;
REQUIRE_SOURCE_ADDRESS    Y;
ENABLE_CMD_EXEC           N;
`)

	stanzas, _ := parseAccessConfig(data)

	if got := stanzas[0]["require_source_address"]; got != true {
		t.Errorf("require_source_address = %v, want true", got)
	}
	if got := stanzas[0]["enable_cmd_exec"]; got != false {
		t.Errorf("enable_cmd_exec = %v, want false", got)
	}
}

func TestConvertAccessTimeoutMapping(t *testing.T) {
	data := []byte(`SOURCE    ANY;
KEY_BASE64    key;
FW_ACCESS_TIMEOUT    60;
MAX_FW_TIMEOUT       300;
`)

	stanzas, _ := parseAccessConfig(data)

	if got := stanzas[0]["access_timeout"]; got != "60" {
		t.Errorf("access_timeout = %v, want %q", got, "60")
	}
	if got := stanzas[0]["max_access_timeout"]; got != "300" {
		t.Errorf("max_access_timeout = %v, want %q", got, "300")
	}
}

func TestConvertAccessIncludeWarning(t *testing.T) {
	data := []byte(`%include /etc/fwknop/keys.conf
SOURCE    ANY;
KEY_BASE64    key;
`)

	_, warnings := parseAccessConfig(data)

	if len(warnings) == 0 {
		t.Error("expected warning for %include directive")
	}
}

func TestConvertAccessGPGWarning(t *testing.T) {
	data := []byte(`SOURCE    ANY;
KEY_BASE64    key;
GPG_DECRYPT_ID    ABCD1234;
GPG_REMOTE_ID     EFGH5678;
`)

	_, warnings := parseAccessConfig(data)

	if len(warnings) < 2 {
		t.Errorf("expected at least 2 warnings for GPG keys, got %d", len(warnings))
	}
}

func TestConvertAccessSemicolonStripping(t *testing.T) {
	data := []byte(`SOURCE    ANY;
KEY_BASE64    dGVzdGtleQ==;
`)

	stanzas, _ := parseAccessConfig(data)

	if got := stanzas[0]["key_base64"]; got != "dGVzdGtleQ==" {
		t.Errorf("key_base64 = %v (semicolon not stripped?)", got)
	}
}

func TestConvertAccessEndToEnd(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "access.conf")
	os.WriteFile(path, []byte(`SOURCE    ANY;
KEY_BASE64    dGVzdGtleQ==;
`), 0600)

	err := convertAccess(path)
	if err != nil {
		t.Fatalf("convertAccess error: %v", err)
	}
}

func TestConvertAccessMissingFile(t *testing.T) {
	err := convertAccess("/nonexistent/access.conf")
	if err == nil {
		t.Error("expected error for missing file")
	}
}
