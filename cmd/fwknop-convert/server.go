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

	config, warnings, fwDetected := parseServerConfig(data)

	for _, w := range warnings {
		fmt.Fprintf(os.Stderr, "warning: %s\n", w)
	}

	// Emit action_template if a firewall backend was detected.
	if fwDetected != "" {
		config["action_template"] = fwDetected + ".yaml"
	}

	out, err := yaml.Marshal(config)
	if err != nil {
		return fmt.Errorf("marshalling YAML: %w", err)
	}

	// Add header comment for detected firewall.
	if fwDetected != "" {
		fmt.Fprintf(os.Stdout, "# Detected %s firewall configuration from legacy config.\n", fwDetected)
	}

	fmt.Print(string(out))
	return nil
}

// parseServerConfig parses a C fwknopd.conf into a map for YAML output.
// Returns the config map, warnings, and the detected firewall backend (if any).
func parseServerConfig(data []byte) (map[string]interface{}, []string, string) {
	config := make(map[string]interface{})
	var warnings []string
	var fwKeys []string
	fwBackend := ""

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
		value = strings.TrimRight(value, ";")
		value = strings.TrimSpace(value)

		upper := strings.ToUpper(key)

		// Detect firewall backend from key prefixes.
		switch {
		case strings.HasPrefix(upper, "IPT_") ||
			strings.HasPrefix(upper, "ENABLE_IPT_") ||
			strings.HasPrefix(upper, "FLUSH_IPT_"):
			if fwBackend == "" {
				fwBackend = "iptables"
			}
			fwKeys = append(fwKeys, key)
			continue

		case strings.HasPrefix(upper, "FIREWD_") ||
			strings.HasPrefix(upper, "ENABLE_FIREWD_") ||
			strings.HasPrefix(upper, "FLUSH_FIREWD_"):
			if fwBackend == "" || fwBackend == "iptables" {
				fwBackend = "firewalld"
			}
			fwKeys = append(fwKeys, key)
			continue

		case strings.HasPrefix(upper, "IPFW_") ||
			strings.HasPrefix(upper, "FLUSH_IPFW_"):
			fwBackend = "ipfw"
			fwKeys = append(fwKeys, key)
			continue

		case strings.HasPrefix(upper, "PF_"):
			fwBackend = "pf"
			fwKeys = append(fwKeys, key)
			continue

		case strings.HasPrefix(upper, "NFQ_") ||
			strings.HasPrefix(upper, "ENABLE_NFQ_"):
			warnings = append(warnings, fmt.Sprintf("NFQ capture not supported; key %s skipped (use UDP server mode)", key))
			continue
		}

		action := classifyServerKey(upper)

		switch action.category {
		case catConvert:
			config[action.goKey] = value
		case catConvertBool:
			config[action.goKey] = parseBool(value)
		case catIgnore:
			// silently drop
		case catWarn:
			warnings = append(warnings, fmt.Sprintf("%s: key %s skipped", action.reason, key))
		default:
			warnings = append(warnings, fmt.Sprintf("unrecognized key %s", key))
		}
	}

	return config, warnings, fwBackend
}

type keyCategory int

const (
	catConvert     keyCategory = iota // direct mapping to Go config key
	catConvertBool                    // maps to bool
	catIgnore                         // silently drop
	catWarn                           // warn with reason
	catUnknown                        // unrecognized
)

type keyAction struct {
	category keyCategory
	goKey    string // target YAML key (for convert/convertBool)
	reason   string // explanation (for warn)
}

func classifyServerKey(upper string) keyAction {
	switch upper {
	// --- Convert: direct mapping ---
	case "UDPSERV_PORT":
		return keyAction{catConvert, "udp_port", ""}
	case "VERBOSE":
		return keyAction{catConvert, "verbose", ""}
	case "MAX_SPA_PACKET_AGE":
		return keyAction{catConvert, "max_spa_packet_age", ""}
	case "SYSLOG_IDENTITY":
		return keyAction{catConvert, "syslog_identity", ""}
	case "SYSLOG_FACILITY":
		return keyAction{catConvert, "syslog_facility", ""}
	case "FWKNOP_RUN_DIR":
		return keyAction{catConvert, "run_dir", ""}
	case "FWKNOP_PID_FILE":
		return keyAction{catConvert, "pid_file", ""}
	case "ACCESS_FILE":
		return keyAction{catConvert, "access_file", ""}

	// --- Convert: boolean ---
	case "ENABLE_SPA_PACKET_AGING":
		return keyAction{catConvertBool, "enable_spa_packet_aging", ""}
	case "ENABLE_DIGEST_PERSISTENCE":
		return keyAction{catConvertBool, "enable_digest_persistence", ""}

	// --- Ignore: pcap-specific (Go uses UDP server mode) ---
	case "PCAP_INTF", "PCAP_FILTER", "PCAP_DISPATCH_COUNT", "PCAP_LOOP_SLEEP",
		"MAX_SNIFF_BYTES", "ENABLE_PCAP_PROMISC", "ENABLE_PCAP_ANY_DIRECTION",
		"EXIT_AT_INTF_DOWN":
		return keyAction{catIgnore, "", ""}

	// --- Ignore: always-on or not applicable ---
	case "ENABLE_UDP_SERVER", "UDPSERV_SELECT_TIMEOUT",
		"FWKNOP_CONF_DIR", "ACCESS_FOLDER",
		"DIGEST_FILE", "DIGEST_DB_FILE",
		"RULES_CHECK_THRESHOLD", "CMD_EXEC_TIMEOUT":
		return keyAction{catIgnore, "", ""}

	// --- Ignore: firewall rule behavior (handled by action templates) ---
	case "ENABLE_RULE_PREPEND", "ENABLE_DESTINATION_RULE", "ENABLE_NAT_DNS",
		"FIREWALL_EXE", "SNAT_TRANSLATE_IP",
		"ENABLE_FIREWD_COMMENT_CHECK", "ENABLE_IPT_COMMENT_CHECK":
		return keyAction{catIgnore, "", ""}

	// --- Warn: GPG ---
	case "GPG_HOME_DIR", "GPG_EXE":
		return keyAction{catWarn, "", "GPG encryption not supported in Go version"}

	// --- Warn: HTTP SPA ---
	case "ENABLE_SPA_OVER_HTTP", "ALLOW_ANY_USER_AGENT", "ENABLE_X_FORWARDED_FOR":
		return keyAction{catWarn, "", "HTTP SPA mode not supported"}

	// --- Warn: TCP server ---
	case "ENABLE_TCP_SERVER", "TCPSERV_PORT":
		return keyAction{catWarn, "", "TCP server mode not supported; use UDP"}

	// --- Warn: external commands ---
	case "ENABLE_EXTERNAL_CMDS", "EXTERNAL_CMD_OPEN", "EXTERNAL_CMD_CLOSE",
		"EXTERNAL_CMD_ALARM", "ENABLE_EXT_CMD_PREFIX", "EXT_CMD_PREFIX":
		return keyAction{catWarn, "", "use action templates instead of external commands"}

	// --- Warn: pcap file replay ---
	case "PCAP_FILE":
		return keyAction{catWarn, "", "pcap file replay not supported"}

	// --- Warn: locale ---
	case "LOCALE":
		return keyAction{catWarn, "", "locale override not applicable"}

	default:
		return keyAction{catUnknown, "", ""}
	}
}
