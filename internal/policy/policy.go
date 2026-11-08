// Copyright 2026 Uddeshya Kumar
// SPDX-License-Identifier: Apache-2.0

// Package policy loads a site zone policy.
// Zone names are the operator's vocabulary. Packs do not carry them.
package policy

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"strings"
)

// Policy classifies exposure zones for every pack on a site.
// A zone in neither list is unknown and is treated as exposed.
type Policy struct {
	UntrustedZones []string `json:"untrusted_zones"`
	TrustedZones   []string `json:"trusted_zones"`

	SHA256 string `json:"-"`
}

// Load decodes a policy and rejects unknown fields.
// SHA256 is the hash of the file bytes the caller passed in.
func Load(data []byte) (*Policy, error) {
	if len(data) == 0 {
		return nil, fmt.Errorf("policy: empty document")
	}
	if len(data) > 64*1024 {
		return nil, fmt.Errorf("policy: document exceeds 64KiB")
	}
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.DisallowUnknownFields()
	var p Policy
	if err := dec.Decode(&p); err != nil {
		return nil, fmt.Errorf("policy: %w", err)
	}
	if dec.More() {
		return nil, fmt.Errorf("policy: trailing JSON")
	}
	if err := validate(&p); err != nil {
		return nil, err
	}
	sum := sha256.Sum256(data)
	p.SHA256 = hex.EncodeToString(sum[:])
	return &p, nil
}

func validate(p *Policy) error {
	if len(p.UntrustedZones) == 0 {
		return fmt.Errorf("policy: untrusted_zones must not be empty")
	}
	if len(p.TrustedZones) == 0 {
		return fmt.Errorf("policy: trusted_zones must not be empty")
	}
	seen := map[string]string{}
	if err := addZones("untrusted_zones", p.UntrustedZones, seen); err != nil {
		return err
	}
	if err := addZones("trusted_zones", p.TrustedZones, seen); err != nil {
		return err
	}
	return nil
}

func addZones(name string, zones []string, seen map[string]string) error {
	local := map[string]struct{}{}
	for _, z := range zones {
		key := strings.ToLower(z)
		if z == "" || key == "unknown" || strings.TrimSpace(z) != z {
			return fmt.Errorf("policy: %s zone %q is not a concrete zone", name, z)
		}
		if _, ok := local[key]; ok {
			return fmt.Errorf("policy: %s has duplicate zone %q", name, z)
		}
		local[key] = struct{}{}
		if prev, ok := seen[key]; ok {
			return fmt.Errorf("policy: zone %q is in both %s and %s", z, prev, name)
		}
		seen[key] = name
	}
	return nil
}
