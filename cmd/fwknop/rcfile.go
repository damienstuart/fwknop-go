package main

import (
	"bufio"
	"fmt"
	"os"
	"strings"

	"github.com/knadh/koanf/v2"
	"gopkg.in/yaml.v3"
)

// loadRCFile loads configuration from an .fwknoprc file into Koanf.
// It auto-detects the format: YAML if the file has a .yaml/.yml extension
// or starts with YAML markers, otherwise legacy stanza format.
func loadRCFile(k *koanf.Koanf, path string, stanza string) error {
	data, err := os.ReadFile(path)
	if err != nil {
		return err
	}

	if isYAMLFile(path, data) {
		return loadRCYAML(k, data, stanza)
	}
	return loadRCLegacy(k, data, stanza)
}

// isYAMLFile checks if a file should be treated as YAML.
func isYAMLFile(path string, data []byte) bool {
	lower := strings.ToLower(path)
	if strings.HasSuffix(lower, ".yaml") || strings.HasSuffix(lower, ".yml") {
		return true
	}
	s := strings.TrimSpace(string(data))
	return strings.HasPrefix(s, "---") || strings.HasPrefix(s, "default:") || strings.HasPrefix(s, "# yaml")
}

// loadRCYAML parses a YAML-format .fwknoprc file.
// Format:
//
//	default:
//	  spa_server: 192.168.1.100
//	  access: tcp/22
//	production:
//	  spa_server: prod.example.com
func loadRCYAML(k *koanf.Koanf, data []byte, stanza string) error {
	var stanzas map[string]map[string]interface{}
	if err := yaml.Unmarshal(data, &stanzas); err != nil {
		return fmt.Errorf("parsing YAML rc file: %w", err)
	}

	// Load "default" stanza first, then overlay the named stanza.
	if defaults, ok := stanzas["default"]; ok {
		if err := loadMapIntoKoanf(k, defaults); err != nil {
			return err
		}
	}

	if stanza != "" && stanza != "default" {
		named, ok := stanzas[stanza]
		if !ok {
			return fmt.Errorf("stanza %q not found in rc file", stanza)
		}
		if err := loadMapIntoKoanf(k, named); err != nil {
			return err
		}
	}

	return nil
}

// loadRCLegacy parses the legacy stanza format .fwknoprc file.
// Format:
//
//	[default]
//	SPA_SERVER    192.168.1.100
//	ACCESS        tcp/22
//
//	[production]
//	SPA_SERVER    prod.example.com
func loadRCLegacy(k *koanf.Koanf, data []byte, stanza string) error {
	stanzas := parseLegacyStanzas(data)

	// Load "default" stanza first.
	if defaults, ok := stanzas["default"]; ok {
		if err := loadMapIntoKoanf(k, defaults); err != nil {
			return err
		}
	}

	if stanza != "" && stanza != "default" {
		named, ok := stanzas[stanza]
		if !ok {
			return fmt.Errorf("stanza %q not found in rc file", stanza)
		}
		if err := loadMapIntoKoanf(k, named); err != nil {
			return err
		}
	}

	return nil
}

// parseLegacyStanzas parses the legacy KEY VALUE stanza format.
func parseLegacyStanzas(data []byte) map[string]map[string]interface{} {
	stanzas := make(map[string]map[string]interface{})
	currentStanza := "default"
	stanzas[currentStanza] = make(map[string]interface{})

	scanner := bufio.NewScanner(strings.NewReader(string(data)))
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())

		// Skip empty lines and comments.
		if line == "" || strings.HasPrefix(line, "#") || strings.HasPrefix(line, ";") {
			continue
		}

		// Stanza header: [name]
		if strings.HasPrefix(line, "[") && strings.HasSuffix(line, "]") {
			currentStanza = strings.TrimSpace(line[1 : len(line)-1])
			if _, ok := stanzas[currentStanza]; !ok {
				stanzas[currentStanza] = make(map[string]interface{})
			}
			continue
		}

		// KEY VALUE pair — split on first whitespace.
		parts := strings.SplitN(line, " ", 2)
		if len(parts) < 2 {
			// Try tab separator.
			parts = strings.SplitN(line, "\t", 2)
		}
		if len(parts) < 2 {
			continue
		}

		key := strings.TrimSpace(parts[0])
		value := strings.TrimSpace(parts[1])

		// Map legacy C-style keys to our config keys.
		mappedKey := mapLegacyKey(key)
		if mappedKey != "" {
			stanzas[currentStanza][mappedKey] = value
		}
	}

	return stanzas
}

// mapLegacyKey converts C-style .fwknoprc keys to our config key names.
func mapLegacyKey(key string) string {
	switch strings.ToUpper(key) {
	case "SPA_SERVER":
		return "destination"
	case "SPA_SERVER_PORT":
		return "server_port"
	case "SPA_SERVER_PROTO":
		return "" // UDP only, ignore
	case "ACCESS":
		return "access"
	case "ALLOW_IP":
		return "allow_ip"
	case "DIGEST_TYPE":
		return "digest_type"
	case "HMAC_DIGEST_TYPE":
		return "hmac_digest_type"
	case "ENCRYPTION_MODE":
		return "encryption_mode"
	case "KEY":
		return "key_rijndael"
	case "KEY_BASE64":
		return "key_base64_rijndael"
	case "HMAC_KEY":
		return "key_hmac"
	case "HMAC_KEY_BASE64":
		return "key_base64_hmac"
	case "USE_HMAC":
		return "use_hmac"
	case "FW_TIMEOUT":
		return "fw_timeout"
	case "SPOOF_USER":
		return "spoof_user"
	case "NAT_ACCESS":
		return "nat_access"
	case "NAT_LOCAL":
		return "nat_local"
	case "NAT_PORT":
		return "nat_port"
	case "RESOLVE_IP_HTTPS", "RESOLVE_IP_HTTP":
		return "resolve_ip"
	case "RESOLVE_URL":
		return "resolve_url"
	case "VERBOSE":
		return "verbose"
	default:
		return "" // Unknown key, skip
	}
}

// loadMapIntoKoanf loads a string→interface map into koanf.
func loadMapIntoKoanf(k *koanf.Koanf, m map[string]interface{}) error {
	for key, val := range m {
		k.Set(key, val)
	}
	return nil
}

// listStanzas reads the rc file and prints available stanza names.
func listStanzas(path string) error {
	data, err := os.ReadFile(path)
	if err != nil {
		return err
	}

	if isYAMLFile(path, data) {
		var stanzas map[string]interface{}
		if err := yaml.Unmarshal(data, &stanzas); err != nil {
			return err
		}
		for name := range stanzas {
			fmt.Println(name)
		}
		return nil
	}

	// Legacy format — scan for [stanza] headers.
	scanner := bufio.NewScanner(strings.NewReader(string(data)))
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if strings.HasPrefix(line, "[") && strings.HasSuffix(line, "]") {
			fmt.Println(strings.TrimSpace(line[1 : len(line)-1]))
		}
	}
	return nil
}
