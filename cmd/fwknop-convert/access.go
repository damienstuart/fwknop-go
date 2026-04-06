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
			directive := strings.SplitN(line, " ", 2)[0]
			warnings = append(warnings, fmt.Sprintf("line %d: %s directive not resolved; manually merge the included file", lineNum, directive))
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

		upper := strings.ToUpper(key)
		action := classifyAccessKey(upper)

		switch action.category {
		case catConvert:
			current[action.goKey] = value
		case catConvertBool:
			current[action.goKey] = parseBool(value)
		case catConvertList:
			current[action.goKey] = parsePortList(value)
		case catIgnore:
			// silently drop
		case catWarn:
			warnings = append(warnings, fmt.Sprintf("%s: key %s skipped", action.reason, key))
		default:
			warnings = append(warnings, fmt.Sprintf("unrecognized key %s", key))
		}
	}

	// Don't forget the last stanza.
	if current != nil {
		stanzas = append(stanzas, current)
	}

	return stanzas, warnings
}

const catConvertList keyCategory = 10 // maps to string list (comma-separated → YAML list)

func classifyAccessKey(upper string) keyAction {
	switch upper {
	// --- Convert: direct mapping ---
	case "SOURCE":
		return keyAction{catConvert, "source", ""}
	case "DESTINATION":
		return keyAction{catConvert, "destination", ""}
	case "KEY":
		return keyAction{catConvert, "key", ""}
	case "KEY_BASE64":
		return keyAction{catConvert, "key_base64", ""}
	case "HMAC_KEY":
		return keyAction{catConvert, "hmac_key", ""}
	case "HMAC_KEY_BASE64":
		return keyAction{catConvert, "hmac_key_base64", ""}
	case "HMAC_DIGEST_TYPE":
		return keyAction{catConvert, "hmac_digest_type", ""}
	case "ENCRYPTION_MODE":
		return keyAction{catConvert, "encryption_mode", ""}
	case "FW_ACCESS_TIMEOUT":
		return keyAction{catConvert, "access_timeout", ""}
	case "MAX_FW_TIMEOUT":
		return keyAction{catConvert, "max_access_timeout", ""}
	case "REQUIRE_USERNAME":
		return keyAction{catConvert, "require_username", ""}
	case "CMD_EXEC_USER":
		return keyAction{catConvert, "cmd_exec_user", ""}
	case "CMD_EXEC_GROUP":
		return keyAction{catConvert, "cmd_exec_group", ""}
	case "CMD_SUDO_EXEC_USER":
		return keyAction{catConvert, "cmd_sudo_exec_user", ""}
	case "CMD_SUDO_EXEC_GROUP":
		return keyAction{catConvert, "cmd_sudo_exec_group", ""}
	case "ACCESS_EXPIRE":
		return keyAction{catConvert, "access_expire", ""}
	case "ACCESS_EXPIRE_EPOCH":
		return keyAction{catConvert, "access_expire_epoch", ""}
	case "CMD_CYCLE_OPEN":
		return keyAction{catConvert, "cmd_cycle_open", ""}
	case "CMD_CYCLE_CLOSE":
		return keyAction{catConvert, "cmd_cycle_close", ""}
	case "CMD_CYCLE_TIMER":
		return keyAction{catConvert, "cmd_cycle_timer", ""}

	// --- Convert: boolean ---
	case "REQUIRE_SOURCE_ADDRESS", "REQUIRE_SOURCE":
		return keyAction{catConvertBool, "require_source_address", ""}
	case "ENABLE_CMD_EXEC":
		return keyAction{catConvertBool, "enable_cmd_exec", ""}
	case "ENABLE_CMD_SUDO_EXEC":
		return keyAction{catConvertBool, "enable_cmd_sudo_exec", ""}
	case "FORCE_NAT":
		return keyAction{catConvertBool, "force_nat", ""}
	case "FORCE_SNAT":
		return keyAction{catConvertBool, "force_snat", ""}
	case "FORCE_MASQUERADE":
		return keyAction{catConvertBool, "force_masquerade", ""}
	case "DISABLE_DNAT":
		return keyAction{catConvertBool, "disable_dnat", ""}
	case "FORWARD_ALL":
		return keyAction{catConvertBool, "forward_all", ""}

	// --- Convert: comma-separated lists ---
	case "OPEN_PORTS":
		return keyAction{catConvertList, "open_ports", ""}
	case "RESTRICT_PORTS":
		return keyAction{catConvertList, "restrict_ports", ""}

	// --- Warn: GPG ---
	case "GPG_HOME_DIR", "GPG_EXE", "GPG_DECRYPT_ID", "GPG_DECRYPT_PW",
		"GPG_REQUIRE_SIG", "GPG_DISABLE_SIG", "GPG_IGNORE_SIG_VERIFY_ERROR",
		"GPG_REMOTE_ID", "GPG_FINGERPRINT_ID", "GPG_ALLOW_NO_PW":
		return keyAction{catWarn, "", "GPG support not available in Go fwknop"}

	default:
		return keyAction{catUnknown, "", ""}
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
