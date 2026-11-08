// Copyright 2026 Uddeshya Kumar
// SPDX-License-Identifier: Apache-2.0

package pack

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"strings"

	"gopkg.in/yaml.v3"
)

// Load parses and lints a pack. Malformed YAML returns an error and does not panic.
func Load(path string, data []byte) (p *Pack, err error) {
	defer func() {
		if r := recover(); r != nil {
			p = nil
			err = fmt.Errorf("pack: rejected unsafe YAML: %v", r)
		}
	}()
	if len(data) == 0 {
		return nil, fmt.Errorf("pack: empty document")
	}
	if len(data) > MaxBytes {
		return nil, fmt.Errorf("pack: document exceeds %d bytes", MaxBytes)
	}
	if err := rejectDangerousYAML(data); err != nil {
		return nil, err
	}
	dec := yaml.NewDecoder(bytes.NewReader(data))
	dec.KnownFields(true)
	var out Pack
	if err := dec.Decode(&out); err != nil {
		return nil, fmt.Errorf("pack: %w", err)
	}
	var extra yaml.Node
	if err := dec.Decode(&extra); err != io.EOF {
		if err == nil {
			return nil, fmt.Errorf("pack: multiple YAML documents are rejected")
		}
		return nil, fmt.Errorf("pack: %w", err)
	}
	sum := sha256.Sum256(data)
	out.SHA256 = hex.EncodeToString(sum[:])
	out.FilePath = path
	if err := Lint(&out); err != nil {
		return nil, err
	}
	return &out, nil
}

func rejectDangerousYAML(data []byte) error {
	dec := yaml.NewDecoder(bytes.NewReader(data))
	var doc yaml.Node
	if err := dec.Decode(&doc); err != nil {
		return fmt.Errorf("pack: %w", err)
	}
	nodes := 0
	if err := walkNode(&doc, 0, &nodes); err != nil {
		return err
	}
	return nil
}

func walkNode(n *yaml.Node, depth int, nodes *int) error {
	if n == nil {
		return nil
	}
	*nodes++
	if *nodes > 10000 {
		return fmt.Errorf("pack: YAML node limit exceeded")
	}
	if depth > 40 {
		return fmt.Errorf("pack: YAML nesting limit exceeded")
	}
	if n.Alias != nil || n.Kind == yaml.AliasNode || n.Anchor != "" {
		return fmt.Errorf("pack: YAML aliases and anchors are rejected")
	}
	if n.Kind == yaml.MappingNode {
		seen := map[string]struct{}{}
		if len(n.Content)%2 != 0 {
			return fmt.Errorf("pack: malformed YAML mapping")
		}
		for i := 0; i < len(n.Content); i += 2 {
			k := n.Content[i]
			if k.Kind != yaml.ScalarNode {
				return fmt.Errorf("pack: YAML mapping keys must be scalars")
			}
			if _, ok := seen[k.Value]; ok {
				return fmt.Errorf("pack: duplicate YAML key %q", k.Value)
			}
			seen[k.Value] = struct{}{}
			if err := walkNode(n.Content[i+1], depth+1, nodes); err != nil {
				return err
			}
		}
		return nil
	}
	for _, c := range n.Content {
		if err := walkNode(c, depth+1, nodes); err != nil {
			return err
		}
	}
	return nil
}

// UnmarshalYAML decodes a condition node that has exactly one key.
func (c *Condition) UnmarshalYAML(node *yaml.Node) error {
	if node.Kind != yaml.MappingNode || len(node.Content) != 2 {
		return fmt.Errorf("condition must be a mapping with exactly one of ref, not, all_of, any_of")
	}
	key, val := node.Content[0], node.Content[1]
	if key.Kind != yaml.ScalarNode {
		return fmt.Errorf("condition key must be a string")
	}
	switch key.Value {
	case "ref":
		if val.Kind != yaml.ScalarNode || strings.TrimSpace(val.Value) == "" {
			return fmt.Errorf("ref must be a non-empty string")
		}
		c.Ref = val.Value
	case "not":
		var child Condition
		if err := val.Decode(&child); err != nil {
			return fmt.Errorf("not: %w", err)
		}
		c.Not = &child
	case "all_of":
		kids, err := decodeGroup("all_of", val)
		if err != nil {
			return err
		}
		c.AllOf = kids
	case "any_of":
		kids, err := decodeGroup("any_of", val)
		if err != nil {
			return err
		}
		c.AnyOf = kids
	default:
		return fmt.Errorf("unknown condition key %q", key.Value)
	}
	return nil
}

func decodeGroup(name string, val *yaml.Node) ([]Condition, error) {
	if val.Kind != yaml.SequenceNode {
		return nil, fmt.Errorf("%s must be a sequence", name)
	}
	var kids []Condition
	if err := val.Decode(&kids); err != nil {
		return nil, fmt.Errorf("%s: %w", name, err)
	}
	if len(kids) == 0 {
		return nil, fmt.Errorf("%s must not be empty", name)
	}
	return kids, nil
}
