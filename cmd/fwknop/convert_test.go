package main

import (
	"os"
	"path/filepath"
	"testing"

	"gopkg.in/yaml.v3"
)

func TestConvertLegacyRC(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, ".fwknoprc")
	os.WriteFile(path, []byte(`[default]
SPA_SERVER    192.168.1.100
ACCESS        tcp/22
KEY_BASE64    dGVzdGtleQ==
HMAC_KEY_BASE64    dGVzdGhtYWM=
`), 0600)

	out, err := convertLegacyRC(path)
	if err != nil {
		t.Fatalf("convertLegacyRC error: %v", err)
	}

	var stanzas map[string]map[string]interface{}
	if err := yaml.Unmarshal(out, &stanzas); err != nil {
		t.Fatalf("YAML unmarshal error: %v", err)
	}

	defaults, ok := stanzas["default"]
	if !ok {
		t.Fatal("missing 'default' stanza in output")
	}
	if got := defaults["destination"]; got != "192.168.1.100" {
		t.Errorf("destination = %v, want %q", got, "192.168.1.100")
	}
	if got := defaults["access"]; got != "tcp/22" {
		t.Errorf("access = %v, want %q", got, "tcp/22")
	}
	if got := defaults["key_base64"]; got != "dGVzdGtleQ==" {
		t.Errorf("key_base64 = %v, want %q", got, "dGVzdGtleQ==")
	}
}

func TestConvertLegacyRCMultipleStanzas(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, ".fwknoprc")
	os.WriteFile(path, []byte(`[default]
SPA_SERVER    192.168.1.100
ACCESS        tcp/22
FW_TIMEOUT    30

[staging]
SPA_SERVER    staging.example.com

[production]
SPA_SERVER    prod.example.com
ACCESS        tcp/22,tcp/443
`), 0600)

	out, err := convertLegacyRC(path)
	if err != nil {
		t.Fatalf("convertLegacyRC error: %v", err)
	}

	var stanzas map[string]map[string]interface{}
	if err := yaml.Unmarshal(out, &stanzas); err != nil {
		t.Fatalf("YAML unmarshal error: %v", err)
	}

	// Verify all stanzas exist.
	if _, ok := stanzas["default"]; !ok {
		t.Error("missing 'default' stanza")
	}
	if _, ok := stanzas["staging"]; !ok {
		t.Error("missing 'staging' stanza")
	}
	if _, ok := stanzas["production"]; !ok {
		t.Error("missing 'production' stanza")
	}

	// Staging should only have its own key (not flattened defaults).
	staging := stanzas["staging"]
	if got := staging["destination"]; got != "staging.example.com" {
		t.Errorf("staging destination = %v, want %q", got, "staging.example.com")
	}
	if _, ok := staging["access"]; ok {
		t.Error("staging should not have 'access' (not flattened from default)")
	}

	// Production should have its own overrides.
	prod := stanzas["production"]
	if got := prod["destination"]; got != "prod.example.com" {
		t.Errorf("production destination = %v, want %q", got, "prod.example.com")
	}
	if got := prod["access"]; got != "tcp/22,tcp/443" {
		t.Errorf("production access = %v, want %q", got, "tcp/22,tcp/443")
	}
}

func TestConvertLegacyRCUnknownKeys(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, ".fwknoprc")
	os.WriteFile(path, []byte(`[default]
SPA_SERVER    192.168.1.100
GPG_RECIPIENT someone
UNKNOWN_KEY   some_value
`), 0600)

	out, err := convertLegacyRC(path)
	if err != nil {
		t.Fatalf("convertLegacyRC error: %v", err)
	}

	var stanzas map[string]map[string]interface{}
	if err := yaml.Unmarshal(out, &stanzas); err != nil {
		t.Fatalf("YAML unmarshal error: %v", err)
	}

	defaults := stanzas["default"]
	if got := defaults["destination"]; got != "192.168.1.100" {
		t.Errorf("destination = %v, want %q", got, "192.168.1.100")
	}
	// Unknown keys should not appear in output.
	for key := range defaults {
		if key == "gpg_recipient" || key == "unknown_key" {
			t.Errorf("unexpected key %q in output", key)
		}
	}
}

func TestConvertLegacyRCMissingFile(t *testing.T) {
	_, err := convertLegacyRC("/nonexistent/path/.fwknoprc")
	if err == nil {
		t.Error("expected error for missing file, got nil")
	}
}

func TestMapLegacyKey(t *testing.T) {
	tests := []struct {
		legacyKey string
		configKey string
	}{
		{"SPA_SERVER", "destination"},
		{"SPA_SERVER_PORT", "server_port"},
		{"SPA_SERVER_PROTO", ""},
		{"ACCESS", "access"},
		{"ALLOW_IP", "allow_ip"},
		{"KEY", "key"},
		{"KEY_BASE64", "key_base64"},
		{"HMAC_KEY", "key_hmac"},
		{"HMAC_KEY_BASE64", "key_base64_hmac"},
		{"DIGEST_TYPE", "digest_type"},
		{"HMAC_DIGEST_TYPE", "hmac_digest_type"},
		{"ENCRYPTION_MODE", "encryption_mode"},
		{"FW_TIMEOUT", "fw_timeout"},
		{"SPOOF_USER", "spoof_user"},
		{"NAT_ACCESS", "nat_access"},
		{"RESOLVE_URL", "resolve_url"},
		{"RESOLVE_IP_HTTPS", "resolve_ip"},
		{"VERBOSE", "verbose"},
		{"UNKNOWN", ""},
	}

	for _, tc := range tests {
		t.Run(tc.legacyKey, func(t *testing.T) {
			got := mapLegacyKey(tc.legacyKey)
			if got != tc.configKey {
				t.Errorf("mapLegacyKey(%q) = %q, want %q", tc.legacyKey, got, tc.configKey)
			}
		})
	}
}

func TestParseLegacyStanzas(t *testing.T) {
	data := []byte(`# Comment line
; Another comment

[default]

SPA_SERVER    192.168.1.100
# Comment in stanza
ACCESS	tcp/22

[production]
SPA_SERVER    prod.example.com
`)

	stanzas, warnings := parseLegacyStanzas(data)

	if len(warnings) != 0 {
		t.Errorf("unexpected warnings: %v", warnings)
	}

	defaults := stanzas["default"]
	if got := defaults["destination"]; got != "192.168.1.100" {
		t.Errorf("default destination = %v, want %q", got, "192.168.1.100")
	}
	if got := defaults["access"]; got != "tcp/22" {
		t.Errorf("default access = %v, want %q", got, "tcp/22")
	}

	prod := stanzas["production"]
	if got := prod["destination"]; got != "prod.example.com" {
		t.Errorf("production destination = %v, want %q", got, "prod.example.com")
	}
}
