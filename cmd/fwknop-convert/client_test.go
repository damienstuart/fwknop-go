package main

import (
	"os"
	"path/filepath"
	"testing"

	"gopkg.in/yaml.v3"
)

func TestConvertClient(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, ".fwknoprc")
	os.WriteFile(path, []byte(`[default]
SPA_SERVER    192.168.1.100
ACCESS        tcp/22
KEY_BASE64    dGVzdGtleQ==
HMAC_KEY_BASE64    dGVzdGhtYWM=
`), 0600)

	// Capture the conversion by calling parseClientStanzas directly.
	data, _ := os.ReadFile(path)
	stanzas, warnings := parseClientStanzas(data)

	if len(warnings) != 0 {
		t.Errorf("unexpected warnings: %v", warnings)
	}

	defaults, ok := stanzas["default"]
	if !ok {
		t.Fatal("missing 'default' stanza")
	}
	if got := defaults["destination"]; got != "192.168.1.100" {
		t.Errorf("destination = %v, want %q", got, "192.168.1.100")
	}
	if got := defaults["key_base64"]; got != "dGVzdGtleQ==" {
		t.Errorf("key_base64 = %v, want %q", got, "dGVzdGtleQ==")
	}
}

func TestConvertClientMultipleStanzas(t *testing.T) {
	data := []byte(`[default]
SPA_SERVER    192.168.1.100
ACCESS        tcp/22

[staging]
SPA_SERVER    staging.example.com

[production]
SPA_SERVER    prod.example.com
ACCESS        tcp/22,tcp/443
`)

	stanzas, _ := parseClientStanzas(data)

	if _, ok := stanzas["default"]; !ok {
		t.Error("missing 'default' stanza")
	}
	if _, ok := stanzas["staging"]; !ok {
		t.Error("missing 'staging' stanza")
	}
	if _, ok := stanzas["production"]; !ok {
		t.Error("missing 'production' stanza")
	}

	// Staging should only have its own key (not flattened).
	if _, ok := stanzas["staging"]["access"]; ok {
		t.Error("staging should not have 'access' (not flattened from default)")
	}
}

func TestConvertClientUnknownKeys(t *testing.T) {
	data := []byte(`[default]
SPA_SERVER    192.168.1.100
GPG_RECIPIENT someone
UNKNOWN_KEY   some_value
`)

	stanzas, warnings := parseClientStanzas(data)

	if len(warnings) != 2 {
		t.Errorf("expected 2 warnings, got %d", len(warnings))
	}

	defaults := stanzas["default"]
	if got := defaults["destination"]; got != "192.168.1.100" {
		t.Errorf("destination = %v, want %q", got, "192.168.1.100")
	}
}

func TestMapClientKey(t *testing.T) {
	tests := []struct {
		legacyKey string
		configKey string
	}{
		{"SPA_SERVER", "destination"},
		{"SPA_SERVER_PORT", "server_port"},
		{"SPA_SERVER_PROTO", ""},
		{"ACCESS", "access"},
		{"KEY", "key"},
		{"KEY_BASE64", "key_base64"},
		{"HMAC_KEY", "key_hmac"},
		{"HMAC_KEY_BASE64", "key_base64_hmac"},
		{"FW_TIMEOUT", "fw_timeout"},
		{"RESOLVE_IP_HTTPS", "resolve_ip"},
		{"UNKNOWN", ""},
	}

	for _, tc := range tests {
		t.Run(tc.legacyKey, func(t *testing.T) {
			got := mapClientKey(tc.legacyKey)
			if got != tc.configKey {
				t.Errorf("mapClientKey(%q) = %q, want %q", tc.legacyKey, got, tc.configKey)
			}
		})
	}
}

func TestConvertClientEndToEnd(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, ".fwknoprc")
	os.WriteFile(path, []byte(`[default]
SPA_SERVER    192.168.1.100
ACCESS        tcp/22
`), 0600)

	// Run the full conversion.
	err := convertClient(path)
	if err != nil {
		t.Fatalf("convertClient error: %v", err)
	}
}

func TestConvertClientMissingFile(t *testing.T) {
	err := convertClient("/nonexistent/.fwknoprc")
	if err == nil {
		t.Error("expected error for missing file")
	}
}

func TestMapToYAMLNode(t *testing.T) {
	m := map[string]interface{}{"b": "2", "a": "1", "c": "3"}
	node := mapToYAMLNode(m)

	if len(node.Content) != 6 { // 3 key-value pairs = 6 nodes
		t.Fatalf("expected 6 content nodes, got %d", len(node.Content))
	}
	// Keys should be sorted.
	if node.Content[0].Value != "a" {
		t.Errorf("first key = %q, want %q", node.Content[0].Value, "a")
	}

	// Verify it marshals cleanly.
	_, err := yaml.Marshal(node)
	if err != nil {
		t.Fatalf("yaml.Marshal error: %v", err)
	}
}
