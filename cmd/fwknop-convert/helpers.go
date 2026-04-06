package main

import (
	"fmt"
	"sort"
	"strings"

	"gopkg.in/yaml.v3"
)

// parseBool converts Y/N/YES/NO/1/0/TRUE/FALSE strings to bool.
func parseBool(s string) bool {
	s = strings.ToUpper(strings.TrimSpace(s))
	return s == "Y" || s == "YES" || s == "1" || s == "TRUE"
}

// mapToYAMLNode converts a map to a yaml.Node with sorted keys.
func mapToYAMLNode(m map[string]interface{}) *yaml.Node {
	node := &yaml.Node{Kind: yaml.MappingNode}
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		node.Content = append(node.Content,
			&yaml.Node{Kind: yaml.ScalarNode, Value: k},
			&yaml.Node{Kind: yaml.ScalarNode, Value: fmt.Sprintf("%v", m[k])},
		)
	}
	return node
}
