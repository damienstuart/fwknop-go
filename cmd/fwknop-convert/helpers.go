package main

import (
	"fmt"
	"sort"

	"gopkg.in/yaml.v3"
)

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
