// Copyright 2026 Uddeshya Kumar
// SPDX-License-Identifier: Apache-2.0

package snapshot

import (
	"encoding/json"
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/uddeshya-world/verdict/internal/purl"
)

// Edit operations.
const (
	OpSetFact     = "set_fact"
	OpSetExposure = "set_exposure"
)

// EvidenceIDPrefix starts an evidence id derived from the bytes of an
// evidence file.
const EvidenceIDPrefix = "sha256:"

// Edit is one operator-entered change to one asset. It never touches
// inventory.complete, evidence_trust, or any other asset.
type Edit struct {
	Op            string   `json:"op"`
	Asset         string   `json:"asset"`
	Key           string   `json:"key,omitempty"`
	Value         string   `json:"value,omitempty"`
	PURL          string   `json:"purl,omitempty"`
	Port          int      `json:"port,omitempty"`
	Proto         string   `json:"proto,omitempty"`
	ReachableFrom []string `json:"reachable_from,omitempty"`
	Basis         string   `json:"basis,omitempty"`      // attested (default) or observed
	Confidence    string   `json:"confidence,omitempty"` // low, medium (default), or high
	ObservedAt    string   `json:"observed_at,omitempty"`
	ExpiresAt     string   `json:"expires_at,omitempty"`
	EvidenceID    string   `json:"-"` // sha256:<hex> of the evidence file; set by the caller
	HasEvidence   bool     `json:"-"` // an evidence file was supplied
	Source        string   `json:"source,omitempty"`
	Replace       bool     `json:"replace,omitempty"`
}

// HostFactChecker reports whether key is one the host collector writes and
// whether value is acceptable for it. It is injected to keep this package
// free of an importer dependency.
type HostFactChecker func(key, value string) (known bool, err error)

// Apply returns a copy of s with every edit applied in order. It is all or
// nothing: the first failing edit returns an error and no result. The result
// is re-validated with LoadMax at maxBytes.
func Apply(s *Snapshot, edits []Edit, check HostFactChecker, maxBytes int64) (*Snapshot, error) {
	if len(edits) == 0 {
		return nil, fmt.Errorf("snapshot edit: no edits")
	}
	raw, err := json.Marshal(s)
	if err != nil {
		return nil, err
	}
	work, err := LoadMax(raw, int64(len(raw)))
	if err != nil {
		return nil, err
	}
	evalAt, _ := time.Parse(time.RFC3339, work.EvaluationTime)
	for i, e := range edits {
		var aerr error
		switch e.Op {
		case OpSetFact:
			aerr = setFact(work, e, evalAt, check)
		case OpSetExposure:
			aerr = setExposure(work, e, evalAt)
		default:
			aerr = fmt.Errorf("op %q is not %s or %s", e.Op, OpSetFact, OpSetExposure)
		}
		if aerr != nil {
			return nil, fmt.Errorf("edit %d: %w", i+1, aerr)
		}
	}
	out, err := json.Marshal(work)
	if err != nil {
		return nil, err
	}
	return LoadMax(out, maxBytes)
}

func findAsset(s *Snapshot, id string) (*Asset, error) {
	for i := range s.Assets {
		if s.Assets[i].ID == id {
			return &s.Assets[i], nil
		}
	}
	return nil, fmt.Errorf("asset %q is not in the snapshot", id)
}

// quality applies the basis, confidence, and evidence rules shared by facts
// and exposure, and returns the stored values.
func quality(e Edit, evalAt time.Time) (basis, conf, observedAt, expiresAt, evidenceID string, err error) {
	basis, conf = e.Basis, e.Confidence
	if basis == "" {
		basis = "attested"
	}
	if conf == "" {
		conf = "medium"
	}
	if basis != "attested" && basis != "observed" {
		return "", "", "", "", "", fmt.Errorf("basis must be attested or observed (got %q)", basis)
	}
	switch conf {
	case "low", "medium", "high":
	default:
		return "", "", "", "", "", fmt.Errorf("confidence must be low, medium, or high (got %q)", conf)
	}
	if conf == "high" && basis != "observed" {
		return "", "", "", "", "", fmt.Errorf("confidence high requires basis observed: an attested entry can never reach the not_affected bar")
	}
	if basis == "observed" {
		if !e.HasEvidence || !strings.HasPrefix(e.EvidenceID, EvidenceIDPrefix) {
			return "", "", "", "", "", fmt.Errorf("basis observed requires an evidence file; verdict hashes it into the evidence id. Without evidence the entry can only be attested")
		}
		if e.ObservedAt == "" {
			return "", "", "", "", "", fmt.Errorf("basis observed requires observed_at")
		}
	}
	observedAt = e.ObservedAt
	if observedAt == "" {
		// The clock is never read: an attested entry is dated at the
		// snapshot's own evaluation time.
		observedAt = evalAt.UTC().Format(time.RFC3339)
	}
	obs, perr := time.Parse(time.RFC3339, observedAt)
	if perr != nil {
		return "", "", "", "", "", fmt.Errorf("observed_at: %w", perr)
	}
	if obs.After(evalAt) {
		return "", "", "", "", "", fmt.Errorf("observed_at %s is after the snapshot evaluation_time; the engine would treat it as unusable", observedAt)
	}
	expiresAt = e.ExpiresAt
	if expiresAt != "" {
		exp, perr := time.Parse(time.RFC3339, expiresAt)
		if perr != nil {
			return "", "", "", "", "", fmt.Errorf("expires_at: %w", perr)
		}
		if !exp.After(obs) {
			return "", "", "", "", "", fmt.Errorf("expires_at must be after observed_at")
		}
	}
	evidenceID = e.EvidenceID
	if evidenceID == "" {
		evidenceID = "attested:operator-entry"
	}
	return basis, conf, observedAt, expiresAt, evidenceID, nil
}

func sourceOrDefault(s string) (string, error) {
	if s == "" {
		return "operator entry (verdict snapshot)", nil
	}
	if len(s) > 512 || strings.ContainsAny(s, "\x00\r\n") {
		return "", fmt.Errorf("source must be one line of at most 512 bytes")
	}
	return s, nil
}

func setFact(s *Snapshot, e Edit, evalAt time.Time, check HostFactChecker) error {
	a, err := findAsset(s, e.Asset)
	if err != nil {
		return err
	}
	if !idRE.MatchString(e.Key) {
		return fmt.Errorf("fact key %q is invalid (letters, digits, . _ : -, at most 128 characters)", e.Key)
	}
	if e.Value == "" || len(e.Value) > 1024 || strings.ContainsAny(e.Value, "\x00\r\n") {
		return fmt.Errorf("fact %q value must be one non-empty line of at most 1024 bytes", e.Key)
	}
	if check != nil {
		if known, err := check(e.Key, e.Value); known && err != nil {
			return fmt.Errorf("fact %q: %w", e.Key, err)
		}
	}
	factPURL := ""
	if e.PURL != "" {
		if _, err := purl.Parse(e.PURL); err != nil {
			return fmt.Errorf("purl: %w", err)
		}
		for _, p := range a.Inventory.Packages {
			if purl.Same(p.PURL, e.PURL) {
				factPURL = p.PURL
				break
			}
		}
		if factPURL == "" {
			return fmt.Errorf("purl %s is not an inventory package of asset %s", e.PURL, a.ID)
		}
	}
	basis, conf, obs, exp, ev, err := quality(e, evalAt)
	if err != nil {
		return err
	}
	src, err := sourceOrDefault(e.Source)
	if err != nil {
		return err
	}
	f := Fact{Key: e.Key, PURL: factPURL, Value: e.Value, Basis: basis, Confidence: conf,
		ObservedAt: obs, ExpiresAt: exp, EvidenceID: ev, Source: src}
	for i := range a.Facts {
		old := a.Facts[i]
		if old.Key != e.Key || !samePURLOrBothEmpty(old.PURL, factPURL) {
			continue
		}
		if !e.Replace {
			return fmt.Errorf("asset %s already has fact %q (value %q, %s/%s); pass replace to overwrite it", a.ID, e.Key, old.Value, old.Basis, old.Confidence)
		}
		a.Facts[i] = f
		return nil
	}
	a.Facts = append(a.Facts, f)
	return nil
}

func samePURLOrBothEmpty(a, b string) bool {
	if a == "" || b == "" {
		return a == b
	}
	return purl.Same(a, b)
}

func setExposure(s *Snapshot, e Edit, evalAt time.Time) error {
	a, err := findAsset(s, e.Asset)
	if err != nil {
		return err
	}
	if e.Port < 1 || e.Port > 65535 || (e.Proto != "tcp" && e.Proto != "udp") {
		return fmt.Errorf("exposure needs port 1-65535 and proto tcp or udp")
	}
	zones := dedupe(e.ReachableFrom)
	if len(zones) == 0 {
		return fmt.Errorf("exposure needs at least one reachable_from zone")
	}
	for _, z := range zones {
		if z == "" || len(z) > 128 || strings.ContainsAny(z, "\x00\r\n") {
			return fmt.Errorf("zone %q is invalid", z)
		}
	}
	basis, conf, obs, exp, ev, err := quality(e, evalAt)
	if err != nil {
		return err
	}
	src, err := sourceOrDefault(e.Source)
	if err != nil {
		return err
	}
	x := Exposure{Port: e.Port, Proto: e.Proto, ReachableFrom: zones, Basis: basis, Confidence: conf,
		ObservedAt: obs, ExpiresAt: exp, EvidenceID: ev, Source: src}
	var keep []Exposure
	have := map[string]bool{}
	found := false
	for _, old := range a.Exposure {
		if old.Port == e.Port && old.Proto == e.Proto {
			found = true
			for _, z := range old.ReachableFrom {
				have[z] = true
			}
			continue
		}
		keep = append(keep, old)
	}
	if found && !e.Replace {
		given := map[string]bool{}
		for _, z := range zones {
			given[z] = true
		}
		var dropped []string
		for z := range have {
			if !given[z] {
				dropped = append(dropped, z)
			}
		}
		if len(dropped) > 0 {
			sort.Strings(dropped)
			return fmt.Errorf("asset %s %d/%s already lists zones %v that this edit would drop; list them too to widen, or pass replace to narrow", a.ID, e.Port, e.Proto, dropped)
		}
	}
	a.Exposure = append(keep, x)
	return nil
}

func dedupe(in []string) []string {
	seen := map[string]bool{}
	var out []string
	for _, v := range in {
		v = strings.TrimSpace(v)
		if !seen[v] {
			seen[v] = true
			out = append(out, v)
		}
	}
	return out
}
