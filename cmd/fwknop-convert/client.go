package main

import (
	"bufio"
	"fmt"
	"os"
	"sort"
	"strings"

	"gopkg.in/yaml.v3"
)

// convertClient reads a legacy .fwknoprc file and prints YAML to stdout.
func convertClient(path string) error {
	data, err := os.ReadFile(path)
	if err != nil {
		return fmt.Errorf("reading rc file: %w", err)
	}

	stanzas, warnings := parseClientStanzas(data)

	for _, w := range warnings {
		fmt.Fprintf(os.Stderr, "warning: %s\n", w)
	}

	if len(stanzas) == 0 {
		return fmt.Errorf("no stanzas found in %s", path)
	}

	// Build ordered output: "default" first, then remaining sorted.
	ordered := &yaml.Node{Kind: yaml.MappingNode}

	if defaults, ok := stanzas["default"]; ok {
		ordered.Content = append(ordered.Content,
			&yaml.Node{Kind: yaml.ScalarNode, Value: "default"},
			mapToYAMLNode(defaults),
		)
	}

	var names []string
	for name := range stanzas {
		if name != "default" {
			names = append(names, name)
		}
	}
	sort.Strings(names)

	for _, name := range names {
		ordered.Content = append(ordered.Content,
			&yaml.Node{Kind: yaml.ScalarNode, Value: name},
			mapToYAMLNode(stanzas[name]),
		)
	}

	doc := &yaml.Node{Kind: yaml.DocumentNode, Content: []*yaml.Node{ordered}}
	out, err := yaml.Marshal(doc)
	if err != nil {
		return fmt.Errorf("marshalling YAML: %w", err)
	}

	fmt.Print(string(out))
	return nil
}

// parseClientStanzas parses the legacy KEY VALUE stanza format.
func parseClientStanzas(data []byte) (map[string]map[string]interface{}, []string) {
	stanzas := make(map[string]map[string]interface{})
	var warnings []string
	currentStanza := "default"
	stanzas[currentStanza] = make(map[string]interface{})

	scanner := bufio.NewScanner(strings.NewReader(string(data)))
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())

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
			parts = strings.SplitN(line, "\t", 2)
		}
		if len(parts) < 2 {
			continue
		}

		key := strings.TrimSpace(parts[0])
		value := strings.TrimSpace(parts[1])

		mappedKey := mapClientKey(key)
		if mappedKey == "" {
			warnings = append(warnings, fmt.Sprintf("skipping unsupported key %s in stanza [%s]", key, currentStanza))
			continue
		}
		stanzas[currentStanza][mappedKey] = value
	}

	return stanzas, warnings
}

// mapClientKey converts C-style .fwknoprc keys to Go config key names.
func mapClientKey(key string) string {
	switch strings.ToUpper(key) {
	case "SPA_SERVER":
		return "destination"
	case "SPA_SERVER_PORT":
		return "server_port"
	case "SPA_SERVER_PROTO":
		return "" // UDP only, ignored
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
		return "key"
	case "KEY_BASE64":
		return "key_base64"
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
		return ""
	}
}
