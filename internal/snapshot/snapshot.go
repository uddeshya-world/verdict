// Copyright 2026 Uddeshya Kumar
// SPDX-License-Identifier: Apache-2.0

// Package snapshot loads a caller-asserted inventory document.
package snapshot

import (
	"bytes"
	"encoding/json"
	"fmt"
	"regexp"
	"strings"
	"time"

	"github.com/uddeshya-world/verdict/internal/purl"
)

// DefaultMaxBytes is the largest snapshot Load accepts. Commands that read
// snapshot files take --max-snapshot-bytes and call LoadMax instead.
const DefaultMaxBytes int64 = 256 * 1024 * 1024

// MaxCapBytes is the largest --max-snapshot-bytes accepted (1 TiB). It keeps
// cap+1 from overflowing and rejects values no real snapshot approaches.
const MaxCapBytes int64 = 1 << 40

// ValidateCap rejects a size cap outside [1, MaxCapBytes].
func ValidateCap(maxBytes int64) error {
	if maxBytes < 1 || maxBytes > MaxCapBytes {
		return fmt.Errorf("--max-snapshot-bytes must be between 1 and %d (got %d)", MaxCapBytes, maxBytes)
	}
	return nil
}

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
	// Edits is the audit trail of operator edits (snapshot set-fact,
	// set-exposure, apply). Importers never write it.
	Edits []EditRecord `json:"edits,omitempty"`
}

// EditRecord is one operator edit of an asset's facts or exposure. It records
// what was there before and what the operator put there, so a report can say
// which evidence is operator-entered. It is caller-asserted like the rest of
// the snapshot.
type EditRecord struct {
	Op         string   `json:"op"`
	Key        string   `json:"key,omitempty"`
	PURL       string   `json:"purl,omitempty"`
	Port       int      `json:"port,omitempty"`
	Proto      string   `json:"proto,omitempty"`
	OldValue   string   `json:"old_value,omitempty"`
	NewValue   string   `json:"new_value,omitempty"`
	OldZones   []string `json:"old_zones,omitempty"`
	NewZones   []string `json:"new_zones,omitempty"`
	OldBasis   string   `json:"old_basis,omitempty"`
	NewBasis   string   `json:"new_basis"`
	Replaced   bool     `json:"replaced"`
	At         string   `json:"at"`
	Source     string   `json:"source"`
	EvidenceID string   `json:"evidence_id,omitempty"`
	// ActorKind is human or agent. Records written before actor kinds
	// existed omit it and are read as human. The engine never treats a
	// fact or exposure entry whose latest edit is an agent's as observed.
	ActorKind string `json:"actor_kind,omitempty"`
}

// IsAgent reports whether the record names an agent as the actor.
func (e EditRecord) IsAgent() bool { return e.ActorKind == ActorAgent }

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
//
// Confidence, when set, is this package's own confidence. It can only lower
// the inventory's: the engine uses the lower of the two for any check that
// matches this package. The host importer sets it to "medium" on a version
// read from a binary's banner (Source "binary_version"), so that entry can
// make a check true but can never meet the not_affected bar. Empty means the
// inventory confidence applies, which is every package-database entry.
// Basis and freshness are always the inventory's.
type Package struct {
	PURL       string `json:"purl"`
	Version    string `json:"version"`
	Confidence string `json:"confidence,omitempty"`
	Source     string `json:"source,omitempty"`
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
	if err := ValidateCap(maxBytes); err != nil {
		return nil, fmt.Errorf("snapshot: %w", err)
	}
	if len(data) == 0 {
		return nil, fmt.Errorf("snapshot: empty document")
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
			switch pkg.Confidence {
			case "", "low", "medium", "high", "confirmed":
			default:
				return fmt.Errorf("snapshot: asset %s package %s confidence %q is invalid", a.ID, pkg.PURL, pkg.Confidence)
			}
			if len(pkg.Source) > 64 || strings.ContainsAny(pkg.Source, "\x00\r\n") {
				return fmt.Errorf("snapshot: asset %s package %s source must be one line of at most 64 bytes", a.ID, pkg.PURL)
			}
			purls[pkg.PURL] = struct{}{}
		}
		// A byte-identical key and purl twice is a malformed document and is
		// rejected. Different spellings of one package URL (escapes, qualifier
		// order, name case) are accepted: merged advisory sources produce them.
		// The engine reads every spelling of a package's advisory together and
		// any disagreement is unknown, so neither order nor spelling can pick
		// the value. Rejecting here instead would fail a whole fleet's drill
		// over one asset's conflict and hide which sources disagree.
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
		for i, er := range a.Edits {
			if err := validateEditRecord(a.ID, i, er); err != nil {
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

func validateEditRecord(asset string, i int, e EditRecord) error {
	bad := func(format string, args ...any) error {
		return fmt.Errorf("snapshot: asset %s edits[%d]: %s", asset, i, fmt.Sprintf(format, args...))
	}
	line := func(name, v string, max int) error {
		if len(v) > max || strings.ContainsAny(v, "\x00\r\n") {
			return bad("%s must be one line of at most %d bytes", name, max)
		}
		return nil
	}
	for _, f := range []struct {
		n, v string
		max  int
	}{{"old_value", e.OldValue, 1024}, {"new_value", e.NewValue, 1024}, {"source", e.Source, 512}} {
		if err := line(f.n, f.v, f.max); err != nil {
			return err
		}
	}
	if e.Source == "" {
		return bad("source is required")
	}
	if _, err := time.Parse(time.RFC3339, e.At); err != nil {
		return bad("at: %v", err)
	}
	switch e.NewBasis {
	case "observed", "attested":
	default:
		return bad("new_basis %q is invalid", e.NewBasis)
	}
	switch e.OldBasis {
	case "", "observed", "attested", "inferred":
	default:
		return bad("old_basis %q is invalid", e.OldBasis)
	}
	if e.EvidenceID != "" && !idRE.MatchString(e.EvidenceID) {
		return bad("evidence_id %q is invalid", e.EvidenceID)
	}
	switch e.ActorKind {
	case "", ActorHuman, ActorAgent:
	default:
		return bad("actor_kind %q is invalid", e.ActorKind)
	}
	if e.Replaced && e.OldBasis == "" {
		return bad("a replaced edit needs old_basis")
	}
	switch e.Op {
	case OpSetFact:
		if !idRE.MatchString(e.Key) {
			return bad("key %q is invalid", e.Key)
		}
		if e.NewValue == "" {
			return bad("set_fact needs new_value")
		}
		if e.PURL != "" {
			if _, err := purl.Parse(e.PURL); err != nil {
				return bad("purl: %v", err)
			}
		}
		if e.Port != 0 || e.Proto != "" || len(e.OldZones) > 0 || len(e.NewZones) > 0 {
			return bad("set_fact carries exposure fields")
		}
	case OpSetExposure:
		if e.Port < 1 || e.Port > 65535 || (e.Proto != "tcp" && e.Proto != "udp") {
			return bad("port/proto is invalid")
		}
		if len(e.NewZones) == 0 {
			return bad("set_exposure needs new_zones")
		}
		for _, z := range append(append([]string{}, e.OldZones...), e.NewZones...) {
			if z == "" || len(z) > 128 || strings.ContainsAny(z, "\x00\r\n") {
				return bad("zone %q is invalid", z)
			}
		}
		if e.Key != "" || e.PURL != "" || e.OldValue != "" || e.NewValue != "" {
			return bad("set_exposure carries fact fields")
		}
	default:
		return bad("op %q is not %s or %s", e.Op, OpSetFact, OpSetExposure)
	}
	return nil
}
