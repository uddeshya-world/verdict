// Copyright 2026 Uddeshya Kumar
// SPDX-License-Identifier: Apache-2.0

// Package snapshot loads a caller-asserted inventory document.
package snapshot

import (
	"bytes"
	"encoding/json"
	"fmt"
	"regexp"
	"time"

	"github.com/uddeshya-world/verdict/internal/purl"
)

// DefaultMaxBytes is the largest snapshot Load accepts. Commands that read
// snapshot files take --max-snapshot-bytes and call LoadMax instead.
const DefaultMaxBytes int64 = 256 * 1024 * 1024

var idRE = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$`)

// Snapshot is the explicit input to a drill besides the pack.
type Snapshot struct {
	KBVersion      string  `json:"kb_version"`
	EvaluationTime string  `json:"evaluation_time"`
	EvidenceTrust  string  `json:"evidence_trust"`
	Assets         []Asset `json:"assets"`
}

// Asset is one host, image, or similar subject.
type Asset struct {
	ID          string     `json:"id"`
	Name        string     `json:"name"`
	Kind        string     `json:"kind"`
	Zones       []string   `json:"zones"`
	PrimaryPURL string     `json:"primary_purl,omitempty"`
	Inventory   Inventory  `json:"inventory"`
	Facts       []Fact     `json:"facts"`
	Exposure    []Exposure `json:"exposure"`
}

// Inventory is the package list and the quality of that observation.
type Inventory struct {
	Complete   bool      `json:"complete"`
	ObservedAt string    `json:"observed_at"`
	Basis      string    `json:"basis"`
	Confidence string    `json:"confidence"`
	EvidenceID string    `json:"evidence_id"`
	Packages   []Package `json:"packages"`
}

// Package is one installed coordinate.
type Package struct {
	PURL    string `json:"purl"`
	Version string `json:"version"`
}

// Fact is one observed, attested, or inferred key.
// PURL, when set, limits the fact to that inventory package. An advisory
// fact without PURL does not apply to every package on the asset.
type Fact struct {
	Key        string `json:"key"`
	PURL       string `json:"purl,omitempty"`
	Value      string `json:"value"`
	Basis      string `json:"basis"`
	Confidence string `json:"confidence"`
	ObservedAt string `json:"observed_at"`
	ExpiresAt  string `json:"expires_at,omitempty"`
	EvidenceID string `json:"evidence_id"`
	Source     string `json:"source"`
}

// Exposure is one reachability observation. Asset zones are not a substitute.
type Exposure struct {
	Port          int      `json:"port"`
	Proto         string   `json:"proto"`
	ReachableFrom []string `json:"reachable_from"`
	Basis         string   `json:"basis"`
	Confidence    string   `json:"confidence"`
	ObservedAt    string   `json:"observed_at"`
	ExpiresAt     string   `json:"expires_at,omitempty"`
	EvidenceID    string   `json:"evidence_id"`
	Source        string   `json:"source"`
}

// Load decodes a snapshot of at most DefaultMaxBytes and rejects unknown fields.
func Load(data []byte) (*Snapshot, error) {
	return LoadMax(data, DefaultMaxBytes)
}

// LoadMax is Load with a caller-chosen size cap in bytes.
func LoadMax(data []byte, maxBytes int64) (*Snapshot, error) {
	if len(data) == 0 {
		return nil, fmt.Errorf("snapshot: empty document")
	}
	if maxBytes < 1 {
		return nil, fmt.Errorf("snapshot: size cap must be positive")
	}
	if int64(len(data)) > maxBytes {
		return nil, fmt.Errorf("snapshot: document is %d bytes, over the %d-byte cap; raise it with --max-snapshot-bytes", len(data), maxBytes)
	}
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.DisallowUnknownFields()
	var s Snapshot
	if err := dec.Decode(&s); err != nil {
		return nil, fmt.Errorf("snapshot: %w", err)
	}
	if dec.More() {
		return nil, fmt.Errorf("snapshot: trailing JSON")
	}
	if err := validate(&s); err != nil {
		return nil, err
	}
	return &s, nil
}

func validate(s *Snapshot) error {
	if s.EvidenceTrust != "caller_asserted" {
		return fmt.Errorf("snapshot: evidence_trust must be \"caller_asserted\" (got %q). The engine does not accept a claim that evidence is verified", s.EvidenceTrust)
	}
	if s.KBVersion == "" {
		return fmt.Errorf("snapshot: kb_version is required")
	}
	if _, err := time.Parse(time.RFC3339, s.EvaluationTime); err != nil {
		return fmt.Errorf("snapshot: evaluation_time: %w", err)
	}
	if len(s.Assets) == 0 {
		return fmt.Errorf("snapshot: at least one asset is required")
	}
	seen := map[string]struct{}{}
	for i := range s.Assets {
		a := &s.Assets[i]
		if !idRE.MatchString(a.ID) {
			return fmt.Errorf("snapshot: asset id %q is invalid", a.ID)
		}
		if _, ok := seen[a.ID]; ok {
			return fmt.Errorf("snapshot: duplicate asset %q", a.ID)
		}
		seen[a.ID] = struct{}{}
		switch a.Kind {
		case "host", "container", "pod", "image", "appliance", "app", "k8s_workload":
		default:
			return fmt.Errorf("snapshot: asset %s kind %q is invalid", a.ID, a.Kind)
		}
		if a.Name == "" {
			return fmt.Errorf("snapshot: asset %s name is required", a.ID)
		}
		if err := validateQuality(a.ID+" inventory", a.Inventory.Basis, a.Inventory.Confidence, a.Inventory.ObservedAt, "", a.Inventory.EvidenceID); err != nil {
			return err
		}
		purls := map[string]struct{}{}
		for _, pkg := range a.Inventory.Packages {
			if pkg.PURL == "" || pkg.Version == "" {
				return fmt.Errorf("snapshot: asset %s has a package without purl and version", a.ID)
			}
			if _, ok := purls[pkg.PURL]; ok {
				return fmt.Errorf("snapshot: asset %s duplicate purl %s", a.ID, pkg.PURL)
			}
			purls[pkg.PURL] = struct{}{}
		}
		keys := map[string]struct{}{}
		for _, f := range a.Facts {
			id := f.Key + "\x00" + f.PURL
			if _, ok := keys[id]; ok {
				return fmt.Errorf("snapshot: asset %s duplicate fact %q for purl %q", a.ID, f.Key, f.PURL)
			}
			keys[id] = struct{}{}
			if f.Key == "" || f.Source == "" {
				return fmt.Errorf("snapshot: asset %s fact is missing key or source", a.ID)
			}
			if f.PURL != "" {
				if _, err := purl.Parse(f.PURL); err != nil {
					return fmt.Errorf("snapshot: asset %s fact %q: %w", a.ID, f.Key, err)
				}
			}
			if err := validateQuality(a.ID+" fact "+f.Key, f.Basis, f.Confidence, f.ObservedAt, f.ExpiresAt, f.EvidenceID); err != nil {
				return err
			}
		}
		for _, e := range a.Exposure {
			if e.Port < 1 || e.Port > 65535 || (e.Proto != "tcp" && e.Proto != "udp") {
				return fmt.Errorf("snapshot: asset %s exposure port/proto is invalid", a.ID)
			}
			if e.Source == "" {
				return fmt.Errorf("snapshot: asset %s exposure is missing source", a.ID)
			}
			if err := validateQuality(a.ID+" exposure", e.Basis, e.Confidence, e.ObservedAt, e.ExpiresAt, e.EvidenceID); err != nil {
				return err
			}
		}
	}
	return nil
}

func validateQuality(where, basis, confidence, observedAt, expiresAt, evidenceID string) error {
	switch basis {
	case "observed", "attested", "inferred":
	default:
		return fmt.Errorf("snapshot: %s basis %q is invalid", where, basis)
	}
	switch confidence {
	case "low", "medium", "high", "confirmed":
	default:
		return fmt.Errorf("snapshot: %s confidence %q is invalid", where, confidence)
	}
	if _, err := time.Parse(time.RFC3339, observedAt); err != nil {
		return fmt.Errorf("snapshot: %s observed_at: %w", where, err)
	}
	if expiresAt != "" {
		if _, err := time.Parse(time.RFC3339, expiresAt); err != nil {
			return fmt.Errorf("snapshot: %s expires_at: %w", where, err)
		}
	}
	if !idRE.MatchString(evidenceID) {
		return fmt.Errorf("snapshot: %s evidence_id %q is invalid", where, evidenceID)
	}
	return nil
}
