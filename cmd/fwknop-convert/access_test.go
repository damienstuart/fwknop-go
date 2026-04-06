package main

import (
	"os"
	"path/filepath"
	"strings"
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
	if got := s["hmac_key_base64"]; got != "dGVzdGhtYWM=" {
		t.Errorf("hmac_key_base64 = %v, want %q", got, "dGVzdGhtYWM=")
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

func TestConvertAccessRestrictPorts(t *testing.T) {
	data := []byte(`SOURCE    ANY;
KEY_BASE64    key;
RESTRICT_PORTS    tcp/23, tcp/25;
`)

	stanzas, _ := parseAccessConfig(data)

	ports, ok := stanzas[0]["restrict_ports"].([]string)
	if !ok {
		t.Fatalf("restrict_ports is not []string: %T", stanzas[0]["restrict_ports"])
	}
	if len(ports) != 2 {
		t.Errorf("expected 2 ports, got %d", len(ports))
	}
}

func TestConvertAccessBooleanValues(t *testing.T) {
	data := []byte(`SOURCE    ANY;
KEY_BASE64    key;
REQUIRE_SOURCE_ADDRESS    Y;
ENABLE_CMD_EXEC           N;
FORCE_NAT                 Y;
FORCE_SNAT                N;
FORCE_MASQUERADE          Y;
DISABLE_DNAT              N;
FORWARD_ALL               Y;
ENABLE_CMD_SUDO_EXEC      N;
`)

	stanzas, warnings := parseAccessConfig(data)

	if len(warnings) != 0 {
		t.Errorf("unexpected warnings: %v", warnings)
	}

	s := stanzas[0]
	if got := s["require_source_address"]; got != true {
		t.Errorf("require_source_address = %v, want true", got)
	}
	if got := s["enable_cmd_exec"]; got != false {
		t.Errorf("enable_cmd_exec = %v, want false", got)
	}
	if got := s["force_nat"]; got != true {
		t.Errorf("force_nat = %v, want true", got)
	}
	if got := s["force_snat"]; got != false {
		t.Errorf("force_snat = %v, want false", got)
	}
	if got := s["force_masquerade"]; got != true {
		t.Errorf("force_masquerade = %v, want true", got)
	}
	if got := s["disable_dnat"]; got != false {
		t.Errorf("disable_dnat = %v, want false", got)
	}
	if got := s["forward_all"]; got != true {
		t.Errorf("forward_all = %v, want true", got)
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

func TestConvertAccessSynonym(t *testing.T) {
	data := []byte(`SOURCE    ANY;
KEY_BASE64    key;
REQUIRE_SOURCE    Y;
`)

	stanzas, _ := parseAccessConfig(data)

	if got := stanzas[0]["require_source_address"]; got != true {
		t.Errorf("REQUIRE_SOURCE should map to require_source_address=true, got %v", got)
	}
}

func TestConvertAccessNATKeys(t *testing.T) {
	data := []byte(`SOURCE    ANY;
KEY_BASE64    key;
FORCE_NAT     Y;
FORCE_SNAT    Y;
DISABLE_DNAT  Y;
FORWARD_ALL   Y;
`)

	stanzas, warnings := parseAccessConfig(data)

	if len(warnings) != 0 {
		t.Errorf("unexpected warnings: %v", warnings)
	}
	s := stanzas[0]
	if got := s["force_nat"]; got != true {
		t.Errorf("force_nat = %v", got)
	}
	if got := s["forward_all"]; got != true {
		t.Errorf("forward_all = %v", got)
	}
}

func TestConvertAccessExpireKeys(t *testing.T) {
	data := []byte(`SOURCE    ANY;
KEY_BASE64    key;
ACCESS_EXPIRE       2025-12-31;
ACCESS_EXPIRE_EPOCH 1767225600;
`)

	stanzas, warnings := parseAccessConfig(data)

	if len(warnings) != 0 {
		t.Errorf("unexpected warnings: %v", warnings)
	}
	if got := stanzas[0]["access_expire"]; got != "2025-12-31" {
		t.Errorf("access_expire = %v", got)
	}
	if got := stanzas[0]["access_expire_epoch"]; got != "1767225600" {
		t.Errorf("access_expire_epoch = %v", got)
	}
}

func TestConvertAccessCmdCycleKeys(t *testing.T) {
	data := []byte(`SOURCE    ANY;
KEY_BASE64    key;
CMD_CYCLE_OPEN   /usr/bin/open_cmd;
CMD_CYCLE_CLOSE  /usr/bin/close_cmd;
CMD_CYCLE_TIMER  30;
`)

	stanzas, warnings := parseAccessConfig(data)

	if len(warnings) != 0 {
		t.Errorf("unexpected warnings: %v", warnings)
	}
	if got := stanzas[0]["cmd_cycle_open"]; got != "/usr/bin/open_cmd" {
		t.Errorf("cmd_cycle_open = %v", got)
	}
	if got := stanzas[0]["cmd_cycle_close"]; got != "/usr/bin/close_cmd" {
		t.Errorf("cmd_cycle_close = %v", got)
	}
}

func TestConvertAccessDestination(t *testing.T) {
	data := []byte(`SOURCE    ANY;
KEY_BASE64    key;
DESTINATION   10.0.0.0/8;
`)

	stanzas, warnings := parseAccessConfig(data)

	if len(warnings) != 0 {
		t.Errorf("unexpected warnings: %v", warnings)
	}
	if got := stanzas[0]["destination"]; got != "10.0.0.0/8" {
		t.Errorf("destination = %v", got)
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
GPG_DECRYPT_PW    mypassword;
GPG_REMOTE_ID     EFGH5678;
GPG_REQUIRE_SIG   Y;
GPG_HOME_DIR      /root/.gnupg;
`)

	_, warnings := parseAccessConfig(data)

	if len(warnings) != 5 {
		t.Errorf("expected 5 GPG warnings, got %d: %v", len(warnings), warnings)
	}
	for _, w := range warnings {
		if !strings.Contains(w, "GPG") {
			t.Errorf("expected GPG-related warning, got: %s", w)
		}
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

func TestConvertAccessAllValidKeys(t *testing.T) {
	data := []byte(`SOURCE                  192.168.1.0/24;
DESTINATION             10.0.0.0/8;
OPEN_PORTS              tcp/22, tcp/443;
RESTRICT_PORTS          tcp/23;
KEY_BASE64              dGVzdGtleQ==;
HMAC_KEY_BASE64         aG1hY2tleQ==;
HMAC_DIGEST_TYPE        SHA256;
ENCRYPTION_MODE         CBC;
FW_ACCESS_TIMEOUT       60;
MAX_FW_TIMEOUT          300;
REQUIRE_USERNAME        admin;
REQUIRE_SOURCE_ADDRESS  Y;
ENABLE_CMD_EXEC         Y;
CMD_EXEC_USER           nobody;
CMD_EXEC_GROUP          nogroup;
ENABLE_CMD_SUDO_EXEC    N;
CMD_SUDO_EXEC_USER      root;
CMD_SUDO_EXEC_GROUP     wheel;
ACCESS_EXPIRE           2025-12-31;
ACCESS_EXPIRE_EPOCH     1767225600;
FORCE_NAT               N;
FORCE_SNAT              N;
FORCE_MASQUERADE        N;
DISABLE_DNAT            N;
FORWARD_ALL             N;
CMD_CYCLE_OPEN          /usr/bin/open;
CMD_CYCLE_CLOSE         /usr/bin/close;
CMD_CYCLE_TIMER         30;
`)

	stanzas, warnings := parseAccessConfig(data)

	if len(warnings) != 0 {
		t.Errorf("unexpected warnings for valid keys: %v", warnings)
	}
	if len(stanzas) != 1 {
		t.Fatalf("expected 1 stanza, got %d", len(stanzas))
	}
	// Should have all keys mapped.
	s := stanzas[0]
	expectedKeys := []string{
		"source", "destination", "open_ports", "restrict_ports",
		"key_base64", "hmac_key_base64", "hmac_digest_type", "encryption_mode",
		"access_timeout", "max_access_timeout", "require_username",
		"require_source_address", "enable_cmd_exec", "cmd_exec_user",
		"cmd_exec_group", "enable_cmd_sudo_exec", "cmd_sudo_exec_user",
		"cmd_sudo_exec_group", "access_expire", "access_expire_epoch",
		"force_nat", "force_snat", "force_masquerade", "disable_dnat",
		"forward_all", "cmd_cycle_open", "cmd_cycle_close", "cmd_cycle_timer",
	}
	for _, k := range expectedKeys {
		if _, ok := s[k]; !ok {
			t.Errorf("missing key %q in converted output", k)
		}
	}
}

func TestConvertAccessEndToEnd(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "access.conf")
	os.WriteFile(path, []byte(`SOURCE    ANY;
KEY_BASE64    dGVzdGtleQ==;
HMAC_KEY_BASE64    aG1hY2tleQ==;
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
