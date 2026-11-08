// Copyright 2026 Uddeshya Kumar
// SPDX-License-Identifier: Apache-2.0

// Package purl parses the subset of Package URLs the engine matches on.
package purl

import (
	"fmt"
	"strings"
)

// PURL is a package identifier.
type PURL struct {
	Type      string
	Namespace string
	Name      string
	Version   string
	Raw       string
}

// Parse splits a package URL. Qualifiers and subpaths are ignored for matching
// and rejected if this is used as a pattern; versions may be present.
func Parse(raw string) (PURL, error) {
	if !strings.HasPrefix(raw, "pkg:") {
		return PURL{}, fmt.Errorf("purl: %q does not start with pkg:", raw)
	}
	s := strings.TrimPrefix(raw, "pkg:")
	if i := strings.IndexAny(s, "?#"); i >= 0 {
		s = s[:i]
	}
	typ, rest, ok := strings.Cut(s, "/")
	if !ok || typ == "" || rest == "" {
		return PURL{}, fmt.Errorf("purl: malformed %q", raw)
	}
	version := ""
	if i := strings.LastIndex(rest, "@"); i >= 0 {
		version = rest[i+1:]
		rest = rest[:i]
		if version == "" || rest == "" {
			return PURL{}, fmt.Errorf("purl: malformed %q", raw)
		}
	}
	parts := strings.Split(rest, "/")
	name := parts[len(parts)-1]
	if name == "" {
		return PURL{}, fmt.Errorf("purl: malformed %q", raw)
	}
	ns := strings.Join(parts[:len(parts)-1], "/")
	return PURL{Type: typ, Namespace: ns, Name: name, Version: version, Raw: raw}, nil
}

// Match reports whether p matches a versionless pattern.
// An empty pattern namespace matches any namespace.
func Match(pattern string, p PURL) bool {
	pat, err := Parse(pattern)
	if err != nil {
		return false
	}
	if pat.Type != p.Type || pat.Name != p.Name {
		return false
	}
	if pat.Namespace == "" {
		return true
	}
	return pat.Namespace == p.Namespace
}

// DistroType reports whether version sorting must not be used.
func DistroType(typ string) bool {
	switch typ {
	case "deb", "rpm", "apk":
		return true
	default:
		return false
	}
}
