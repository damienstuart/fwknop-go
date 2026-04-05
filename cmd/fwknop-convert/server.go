package main

import (
	"bufio"
	"fmt"
	"os"
	"strings"

	"gopkg.in/yaml.v3"
)

// convertServer reads a legacy C fwknopd.conf and prints YAML to stdout.
func convertServer(path string) error {
	data, err := os.ReadFile(path)
	if err != nil {
		return fmt.Errorf("reading server config: %w", err)
	}

	config, warnings := parseServerConfig(data)

	for _, w := range warnings {
		fmt.Fprintf(os.Stderr, "warning: %s\n", w)
	}

	out, err := yaml.Marshal(config)
	if err != nil {
		return fmt.Errorf("marshalling YAML: %w", err)
	}

	fmt.Print(string(out))
	return nil
}

// parseServerConfig parses a C fwknopd.conf into a map for YAML output.
func parseServerConfig(data []byte) (map[string]interface{}, []string) {
	config := make(map[string]interface{})
	var warnings []string
	hasIPTKeys := false

	scanner := bufio.NewScanner(strings.NewReader(string(data)))
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())

		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}

		// KEY VALUE pair — split on first whitespace.
		parts := strings.SplitN(line, " ", 2)
		if len(parts) < 2 {
			parts = strings.SplitN(line, "\t", 2)
		}
		if len(parts) < 2 {
			continue
		}

		key := strings.TrimSpace(parts[0])
		value := strings.TrimSpace(parts[1])
		// Strip trailing semicolons.
		value = strings.TrimRight(value, ";")
		value = strings.TrimSpace(value)

		// Track iptables-specific keys for suggesting action template.
		if strings.HasPrefix(strings.ToUpper(key), "IPT_") ||
			strings.HasPrefix(strings.ToUpper(key), "ENABLE_IPT_") {
			hasIPTKeys = true
		}

		mappedKey := mapServerKey(key)
		switch {
		case mappedKey == "":
			warnings = append(warnings, fmt.Sprintf("skipping unsupported key %s (use action templates instead)", key))
		case mappedKey == "_bool":
			config[mapServerKeyName(key)] = parseBool(value)
		default:
			config[mappedKey] = value
		}
	}

	if hasIPTKeys {
		warnings = append(warnings, "iptables-specific keys detected; consider using: action_template: iptables.yaml")
	}

	return config, warnings
}

// mapServerKey returns the Go config key, "" for unsupported, or "_bool" for boolean keys.
func mapServerKey(key string) string {
	switch strings.ToUpper(key) {
	case "UDPSERV_PORT":
		return "udp_port"
	case "VERBOSE":
		return "verbose"
	case "MAX_SPA_PACKET_AGE":
		return "max_spa_packet_age"
	case "SYSLOG_IDENTITY":
		return "syslog_identity"
	case "SYSLOG_FACILITY":
		return "syslog_facility"
	case "FWKNOP_RUN_DIR":
		return "run_dir"
	case "FWKNOP_PID_FILE":
		return "pid_file"
	case "ENABLE_SPA_PACKET_AGING":
		return "_bool"
	case "ENABLE_DIGEST_PERSISTENCE":
		return "_bool"
	default:
		return ""
	}
}

// mapServerKeyName returns the Go config key name for boolean keys.
func mapServerKeyName(key string) string {
	switch strings.ToUpper(key) {
	case "ENABLE_SPA_PACKET_AGING":
		return "enable_spa_packet_aging"
	case "ENABLE_DIGEST_PERSISTENCE":
		return "enable_digest_persistence"
	default:
		return strings.ToLower(key)
	}
}

func parseBool(s string) bool {
	s = strings.ToUpper(strings.TrimSpace(s))
	return s == "Y" || s == "YES" || s == "1" || s == "TRUE"
}
