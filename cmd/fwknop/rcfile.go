package main

import (
	"fmt"
	"os"
	"strings"

	"github.com/knadh/koanf/v2"
	"gopkg.in/yaml.v3"
)

// loadRCFile loads configuration from a YAML .fwknoprc file into Koanf.
func loadRCFile(k *koanf.Koanf, path string, stanza string) error {
	data, err := os.ReadFile(path)
	if err != nil {
		return err
	}

	if err := loadRCYAML(k, data, stanza); err != nil {
		if looksLikeLegacy(data) {
			return fmt.Errorf("legacy .fwknoprc format is no longer supported; "+
				"convert with: fwknop-convert --type client --input %s", path)
		}
		return err
	}
	return nil
}

// looksLikeLegacy checks if the data appears to be a legacy INI-format rc file.
func looksLikeLegacy(data []byte) bool {
	for _, line := range strings.Split(string(data), "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") || strings.HasPrefix(line, ";") {
			continue
		}
		return strings.HasPrefix(line, "[")
	}
	return false
}

// loadRCYAML parses a YAML-format .fwknoprc file.
// Format:
//
//	default:
//	  destination: 192.168.1.100
//	  access: tcp/22
//	production:
//	  destination: prod.example.com
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

// loadMapIntoKoanf loads a string→interface map into koanf.
func loadMapIntoKoanf(k *koanf.Koanf, m map[string]interface{}) error {
	for key, val := range m {
		k.Set(key, val)
	}
	return nil
}

// listStanzas reads the YAML rc file and prints available stanza names.
func listStanzas(path string) error {
	data, err := os.ReadFile(path)
	if err != nil {
		return err
	}

	if looksLikeLegacy(data) {
		return fmt.Errorf("legacy .fwknoprc format is no longer supported; "+
			"convert with: fwknop-convert --type client --input %s", path)
	}

	var stanzas map[string]interface{}
	if err := yaml.Unmarshal(data, &stanzas); err != nil {
		return err
	}
	for name := range stanzas {
		fmt.Println(name)
	}
	return nil
}
