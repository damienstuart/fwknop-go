package main

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/knadh/koanf/v2"
)

func TestLoadRCLegacyDefaultStanza(t *testing.T) {
	data := []byte(`[default]
SPA_SERVER    192.168.1.100
ACCESS        tcp/22
KEY_BASE64    dGVzdGtleQ==
HMAC_KEY_BASE64    dGVzdGhtYWM=
`)
	k := koanf.New(".")
	if err := loadRCLegacy(k, data, ""); err != nil {
		t.Fatalf("loadRCLegacy error: %v", err)
	}

	if got := k.String("destination"); got != "192.168.1.100" {
		t.Errorf("destination = %q, want %q", got, "192.168.1.100")
	}
	if got := k.String("access"); got != "tcp/22" {
		t.Errorf("access = %q, want %q", got, "tcp/22")
	}
	if got := k.String("key_base64_rijndael"); got != "dGVzdGtleQ==" {
		t.Errorf("key_base64_rijndael = %q, want %q", got, "dGVzdGtleQ==")
	}
}

func TestLoadRCLegacyNamedStanza(t *testing.T) {
	data := []byte(`[default]
SPA_SERVER    192.168.1.100
ACCESS        tcp/22

[production]
SPA_SERVER    prod.example.com
ACCESS        tcp/22,tcp/443
`)
	k := koanf.New(".")
	if err := loadRCLegacy(k, data, "production"); err != nil {
		t.Fatalf("loadRCLegacy error: %v", err)
	}

	// Named stanza should override default.
	if got := k.String("destination"); got != "prod.example.com" {
		t.Errorf("destination = %q, want %q", got, "prod.example.com")
	}
	if got := k.String("access"); got != "tcp/22,tcp/443" {
		t.Errorf("access = %q, want %q", got, "tcp/22,tcp/443")
	}
}

func TestLoadRCLegacyDefaultInherited(t *testing.T) {
	data := []byte(`[default]
SPA_SERVER    192.168.1.100
ACCESS        tcp/22
FW_TIMEOUT    30

[staging]
SPA_SERVER    staging.example.com
`)
	k := koanf.New(".")
	if err := loadRCLegacy(k, data, "staging"); err != nil {
		t.Fatalf("loadRCLegacy error: %v", err)
	}

	// Staging overrides destination but inherits access and timeout from default.
	if got := k.String("destination"); got != "staging.example.com" {
		t.Errorf("destination = %q, want %q", got, "staging.example.com")
	}
	if got := k.String("access"); got != "tcp/22" {
		t.Errorf("access = %q, want %q", got, "tcp/22")
	}
	if got := k.String("fw_timeout"); got != "30" {
		t.Errorf("fw_timeout = %q, want %q", got, "30")
	}
}

func TestLoadRCLegacyMissingStanza(t *testing.T) {
	data := []byte(`[default]
SPA_SERVER    192.168.1.100
`)
	k := koanf.New(".")
	err := loadRCLegacy(k, data, "nonexistent")
	if err == nil {
		t.Error("expected error for missing stanza, got nil")
	}
}

func TestLoadRCLegacyCommentsAndBlanks(t *testing.T) {
	data := []byte(`# This is a comment
; Another comment

[default]

SPA_SERVER    192.168.1.100
# Comment in stanza
ACCESS        tcp/22
`)
	k := koanf.New(".")
	if err := loadRCLegacy(k, data, ""); err != nil {
		t.Fatalf("loadRCLegacy error: %v", err)
	}
	if got := k.String("destination"); got != "192.168.1.100" {
		t.Errorf("destination = %q, want %q", got, "192.168.1.100")
	}
}

func TestLoadRCLegacyKeyMapping(t *testing.T) {
	tests := []struct {
		legacyKey string
		configKey string
		value     string
	}{
		{"SPA_SERVER", "destination", "10.0.0.1"},
		{"SPA_SERVER_PORT", "server_port", "12345"},
		{"ACCESS", "access", "tcp/22"},
		{"ALLOW_IP", "allow_ip", "1.2.3.4"},
		{"KEY", "key_rijndael", "mykey"},
		{"KEY_BASE64", "key_base64_rijndael", "bXlrZXk="},
		{"HMAC_KEY", "key_hmac", "hmackey"},
		{"HMAC_KEY_BASE64", "key_base64_hmac", "aG1hY2tleQ=="},
		{"DIGEST_TYPE", "digest_type", "sha512"},
		{"HMAC_DIGEST_TYPE", "hmac_digest_type", "sha384"},
		{"ENCRYPTION_MODE", "encryption_mode", "legacy"},
		{"FW_TIMEOUT", "fw_timeout", "60"},
		{"SPOOF_USER", "spoof_user", "alice"},
		{"NAT_ACCESS", "nat_access", "10.0.0.1,22"},
		{"RESOLVE_URL", "resolve_url", "https://example.com/ip"},
	}

	for _, tc := range tests {
		t.Run(tc.legacyKey, func(t *testing.T) {
			data := []byte("[default]\n" + tc.legacyKey + "    " + tc.value + "\n")
			k := koanf.New(".")
			if err := loadRCLegacy(k, data, ""); err != nil {
				t.Fatalf("loadRCLegacy error: %v", err)
			}
			if got := k.String(tc.configKey); got != tc.value {
				t.Errorf("%s: got %q, want %q", tc.configKey, got, tc.value)
			}
		})
	}
}

func TestLoadRCLegacyUnknownKeysIgnored(t *testing.T) {
	data := []byte(`[default]
SPA_SERVER    192.168.1.100
UNKNOWN_KEY   some_value
GPG_RECIPIENT someone
`)
	k := koanf.New(".")
	if err := loadRCLegacy(k, data, ""); err != nil {
		t.Fatalf("loadRCLegacy error: %v", err)
	}
	if got := k.String("destination"); got != "192.168.1.100" {
		t.Errorf("destination = %q, want %q", got, "192.168.1.100")
	}
	// Unknown keys should not appear.
	if k.Exists("unknown_key") {
		t.Error("unknown key should not be loaded")
	}
}

func TestLoadRCYAMLDefaultStanza(t *testing.T) {
	data := []byte(`default:
  destination: 192.168.1.100
  access: tcp/22
  key_base64_rijndael: dGVzdGtleQ==
`)
	k := koanf.New(".")
	if err := loadRCYAML(k, data, ""); err != nil {
		t.Fatalf("loadRCYAML error: %v", err)
	}

	if got := k.String("destination"); got != "192.168.1.100" {
		t.Errorf("destination = %q, want %q", got, "192.168.1.100")
	}
	if got := k.String("access"); got != "tcp/22" {
		t.Errorf("access = %q, want %q", got, "tcp/22")
	}
}

func TestLoadRCYAMLNamedStanza(t *testing.T) {
	data := []byte(`default:
  destination: 192.168.1.100
  access: tcp/22
production:
  destination: prod.example.com
  access: tcp/443
`)
	k := koanf.New(".")
	if err := loadRCYAML(k, data, "production"); err != nil {
		t.Fatalf("loadRCYAML error: %v", err)
	}

	if got := k.String("destination"); got != "prod.example.com" {
		t.Errorf("destination = %q, want %q", got, "prod.example.com")
	}
}

func TestLoadRCYAMLMissingStanza(t *testing.T) {
	data := []byte(`default:
  destination: 192.168.1.100
`)
	k := koanf.New(".")
	err := loadRCYAML(k, data, "nonexistent")
	if err == nil {
		t.Error("expected error for missing stanza, got nil")
	}
}

func TestIsYAMLFile(t *testing.T) {
	tests := []struct {
		path     string
		content  string
		expected bool
	}{
		{"config.yaml", "", true},
		{"config.yml", "", true},
		{"config.YAML", "", true},
		{".fwknoprc", "---\ndefault:\n", true},
		{".fwknoprc", "default:\n  server: foo\n", true},
		{".fwknoprc", "# yaml\ndefault:\n", true},
		{".fwknoprc", "[default]\nSPA_SERVER  foo\n", false},
		{".fwknoprc", "# comment\n[default]\n", false},
	}

	for _, tc := range tests {
		got := isYAMLFile(tc.path, []byte(tc.content))
		if got != tc.expected {
			t.Errorf("isYAMLFile(%q, %q) = %v, want %v", tc.path, tc.content, got, tc.expected)
		}
	}
}

func TestLoadRCFileAutoDetect(t *testing.T) {
	dir := t.TempDir()

	// Write a legacy format file.
	legacyPath := filepath.Join(dir, ".fwknoprc")
	os.WriteFile(legacyPath, []byte("[default]\nSPA_SERVER    10.0.0.1\n"), 0600)

	k := koanf.New(".")
	if err := loadRCFile(k, legacyPath, ""); err != nil {
		t.Fatalf("loadRCFile (legacy) error: %v", err)
	}
	if got := k.String("destination"); got != "10.0.0.1" {
		t.Errorf("destination = %q, want %q", got, "10.0.0.1")
	}

	// Write a YAML format file.
	yamlPath := filepath.Join(dir, "config.yaml")
	os.WriteFile(yamlPath, []byte("default:\n  destination: 10.0.0.2\n"), 0600)

	k2 := koanf.New(".")
	if err := loadRCFile(k2, yamlPath, ""); err != nil {
		t.Fatalf("loadRCFile (yaml) error: %v", err)
	}
	if got := k2.String("destination"); got != "10.0.0.2" {
		t.Errorf("destination = %q, want %q", got, "10.0.0.2")
	}
}

func TestLoadRCFileMissing(t *testing.T) {
	k := koanf.New(".")
	err := loadRCFile(k, "/nonexistent/path/.fwknoprc", "")
	if err == nil {
		t.Error("expected error for missing file, got nil")
	}
}
