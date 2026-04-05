package main

import (
	"bufio"
	"fmt"
	"os"
	"strings"

	"gopkg.in/yaml.v3"
)

// convertAccess reads a legacy C access.conf and prints YAML to stdout.
func convertAccess(path string) error {
	data, err := os.ReadFile(path)
	if err != nil {
		return fmt.Errorf("reading access config: %w", err)
	}

	stanzas, warnings := parseAccessConfig(data)

	for _, w := range warnings {
		fmt.Fprintf(os.Stderr, "warning: %s\n", w)
	}

	if len(stanzas) == 0 {
		return fmt.Errorf("no access stanzas found in %s", path)
	}

	out, err := yaml.Marshal(stanzas)
	if err != nil {
		return fmt.Errorf("marshalling YAML: %w", err)
	}

	fmt.Print(string(out))
	return nil
}

// parseAccessConfig parses a C access.conf into a list of stanza maps.
// A new SOURCE line starts a new stanza.
func parseAccessConfig(data []byte) ([]map[string]interface{}, []string) {
	var stanzas []map[string]interface{}
	var warnings []string
	var current map[string]interface{}

	scanner := bufio.NewScanner(strings.NewReader(string(data)))
	lineNum := 0
	for scanner.Scan() {
		lineNum++
		line := strings.TrimSpace(scanner.Text())

		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}

		// Handle %include directives.
		if strings.HasPrefix(line, "%include") {
			warnings = append(warnings, fmt.Sprintf("line %d: %s directive not resolved; manually merge the included file", lineNum, strings.SplitN(line, " ", 2)[0]))
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

		// A new SOURCE line starts a new stanza.
		if strings.ToUpper(key) == "SOURCE" {
			if current != nil {
				stanzas = append(stanzas, current)
			}
			current = make(map[string]interface{})
			current["source"] = value
			continue
		}

		if current == nil {
			current = make(map[string]interface{})
		}

		mappedKey := mapAccessKey(key)
		if mappedKey == "" {
			warnings = append(warnings, fmt.Sprintf("skipping unsupported key %s", key))
			continue
		}

		// Handle special value conversions.
		switch mappedKey {
		case "open_ports":
			current[mappedKey] = parsePortList(value)
		case "require_source_address", "enable_cmd_exec":
			current[mappedKey] = parseBool(value)
		default:
			current[mappedKey] = value
		}
	}

	// Don't forget the last stanza.
	if current != nil {
		stanzas = append(stanzas, current)
	}

	return stanzas, warnings
}

// mapAccessKey converts C-style access.conf keys to Go config key names.
func mapAccessKey(key string) string {
	switch strings.ToUpper(key) {
	case "SOURCE":
		return "source"
	case "OPEN_PORTS":
		return "open_ports"
	case "RESTRICT_PORTS":
		return "" // warn
	case "KEY":
		return "key"
	case "KEY_BASE64":
		return "key_base64"
	case "HMAC_KEY":
		return "hmac_key"
	case "HMAC_KEY_BASE64":
		return "hmac_key_base64"
	case "HMAC_DIGEST_TYPE":
		return "hmac_digest_type"
	case "ENCRYPTION_MODE":
		return "encryption_mode"
	case "FW_ACCESS_TIMEOUT":
		return "access_timeout"
	case "MAX_FW_TIMEOUT":
		return "max_access_timeout"
	case "REQUIRE_USERNAME":
		return "require_username"
	case "REQUIRE_SOURCE_ADDRESS":
		return "require_source_address"
	case "ENABLE_CMD_EXEC":
		return "enable_cmd_exec"
	case "CMD_EXEC_USER":
		return "cmd_exec_user"
	case "DESTINATION":
		return "" // not used in Go version
	default:
		// GPG and other unsupported keys.
		if strings.HasPrefix(strings.ToUpper(key), "GPG_") {
			return ""
		}
		return ""
	}
}

// parsePortList splits a comma-separated port list into a string slice.
func parsePortList(s string) []string {
	var ports []string
	for _, p := range strings.Split(s, ",") {
		p = strings.TrimSpace(p)
		if p != "" {
			ports = append(ports, p)
		}
	}
	return ports
}
