package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/knadh/koanf/v2"
)

func TestLoadRCYAMLDefaultStanza(t *testing.T) {
	data := []byte(`default:
  destination: 192.168.1.100
  access: tcp/22
  key_base64: dGVzdGtleQ==
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

func TestLoadRCFileYAML(t *testing.T) {
	dir := t.TempDir()

	yamlPath := filepath.Join(dir, "config.yaml")
	os.WriteFile(yamlPath, []byte("default:\n  destination: 10.0.0.2\n"), 0600)

	k := koanf.New(".")
	if err := loadRCFile(k, yamlPath, ""); err != nil {
		t.Fatalf("loadRCFile error: %v", err)
	}
	if got := k.String("destination"); got != "10.0.0.2" {
		t.Errorf("destination = %q, want %q", got, "10.0.0.2")
	}
}

func TestLoadRCFileLegacyFormatError(t *testing.T) {
	dir := t.TempDir()

	legacyPath := filepath.Join(dir, ".fwknoprc")
	os.WriteFile(legacyPath, []byte("[default]\nSPA_SERVER    10.0.0.1\n"), 0600)

	k := koanf.New(".")
	err := loadRCFile(k, legacyPath, "")
	if err == nil {
		t.Fatal("expected error for legacy format, got nil")
	}
	if !strings.Contains(err.Error(), "no longer supported") {
		t.Errorf("expected 'no longer supported' message, got: %v", err)
	}
	if !strings.Contains(err.Error(), "--convert-rc") {
		t.Errorf("expected '--convert-rc' hint in error, got: %v", err)
	}
}

func TestLoadRCFileMissing(t *testing.T) {
	k := koanf.New(".")
	err := loadRCFile(k, "/nonexistent/path/.fwknoprc", "")
	if err == nil {
		t.Error("expected error for missing file, got nil")
	}
}

func TestLooksLikeLegacy(t *testing.T) {
	tests := []struct {
		content  string
		expected bool
	}{
		{"[default]\nSPA_SERVER  foo\n", true},
		{"# comment\n[default]\n", true},
		{"default:\n  destination: foo\n", false},
		{"---\ndefault:\n", false},
		{"", false},
	}
	for _, tc := range tests {
		got := looksLikeLegacy([]byte(tc.content))
		if got != tc.expected {
			t.Errorf("looksLikeLegacy(%q) = %v, want %v", tc.content, got, tc.expected)
		}
	}
}

func TestListStanzasYAML(t *testing.T) {
	dir := t.TempDir()
	yamlPath := filepath.Join(dir, "config.yaml")
	os.WriteFile(yamlPath, []byte("default:\n  destination: foo\nproduction:\n  destination: bar\n"), 0600)

	err := listStanzas(yamlPath)
	if err != nil {
		t.Fatalf("listStanzas error: %v", err)
	}
}

func TestListStanzasLegacyError(t *testing.T) {
	dir := t.TempDir()
	legacyPath := filepath.Join(dir, ".fwknoprc")
	os.WriteFile(legacyPath, []byte("[default]\nSPA_SERVER    10.0.0.1\n"), 0600)

	err := listStanzas(legacyPath)
	if err == nil {
		t.Fatal("expected error for legacy format, got nil")
	}
	if !strings.Contains(err.Error(), "no longer supported") {
		t.Errorf("expected 'no longer supported' message, got: %v", err)
	}
}
