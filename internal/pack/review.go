// Copyright 2026 Uddeshya Kumar
// SPDX-License-Identifier: Apache-2.0

package pack

import (
	"bytes"
	"encoding/json"
	"fmt"
	"sort"
	"strings"
	"time"
)

// ReviewAttestation is one human's statement about one pack file.
// The name is whoever the operator records. This package does not
// check that the person exists.
type ReviewAttestation struct {
	Name       string `json:"name"`
	ReviewedAt string `json:"reviewed_at"`
	Statement  string `json:"statement"`
}

// ReviewRecord binds reviewer statements to the exact pack bytes.
type ReviewRecord struct {
	PackID     string              `json:"pack_id"`
	PackSHA256 string              `json:"pack_sha256"`
	Reviewers  []ReviewAttestation `json:"reviewers"`
}

// ParseReviewRecord decodes a review file. Unknown fields are rejected.
func ParseReviewRecord(data []byte) (*ReviewRecord, error) {
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.DisallowUnknownFields()
	var rec ReviewRecord
	if err := dec.Decode(&rec); err != nil {
		return nil, fmt.Errorf("pack review: %w", err)
	}
	if dec.More() {
		return nil, fmt.Errorf("pack review: trailing JSON")
	}
	return &rec, nil
}

// CheckReview reports whether rec is enough to mark p reviewed.
// It does not edit p. Fixture names are accepted only on synthetic packs.
func CheckReview(p *Pack, rec *ReviewRecord) error {
	if p == nil || rec == nil {
		return fmt.Errorf("pack review: pack and record are required")
	}
	if rec.PackID != p.Metadata.ID {
		return fmt.Errorf("pack review: record pack_id %q does not match %q", rec.PackID, p.Metadata.ID)
	}
	if rec.PackSHA256 == "" || rec.PackSHA256 != p.SHA256 {
		return fmt.Errorf("pack review: record pack_sha256 does not match these pack bytes")
	}
	if len(rec.Reviewers) < 2 {
		return fmt.Errorf("pack review: two distinct reviewers are required")
	}
	seen := map[string]struct{}{}
	for _, r := range rec.Reviewers {
		name := strings.TrimSpace(r.Name)
		if name == "" {
			return fmt.Errorf("pack review: reviewer name is empty")
		}
		if strings.TrimSpace(r.Statement) == "" {
			return fmt.Errorf("pack review: %s has an empty statement", name)
		}
		if _, err := time.Parse(time.RFC3339, r.ReviewedAt); err != nil {
			return fmt.Errorf("pack review: %s reviewed_at: %w", name, err)
		}
		key := strings.ToLower(name)
		if _, ok := seen[key]; ok {
			return fmt.Errorf("pack review: duplicate reviewer %q", name)
		}
		seen[key] = struct{}{}
		fixture := strings.HasPrefix(key, "synthetic-reviewer-")
		if p.Metadata.Synthetic && !fixture {
			return fmt.Errorf("pack review: synthetic pack reviewer %q must use a synthetic-reviewer-* name", name)
		}
		if !p.Metadata.Synthetic && fixture {
			return fmt.Errorf("pack review: synthetic-reviewer-* cannot sign a real CVE pack")
		}
	}
	return nil
}

// ReviewerNames returns the record's names in order.
func ReviewerNames(rec *ReviewRecord) []string {
	out := make([]string, 0, len(rec.Reviewers))
	for _, r := range rec.Reviewers {
		out = append(out, strings.TrimSpace(r.Name))
	}
	return out
}

// SameReviewers reports whether the pack YAML lists the same people as the record.
func SameReviewers(p *Pack, rec *ReviewRecord) bool {
	a := map[string]struct{}{}
	for _, r := range p.Metadata.Reviewers {
		a[strings.ToLower(strings.TrimSpace(r.Name))] = struct{}{}
	}
	b := map[string]struct{}{}
	for _, name := range ReviewerNames(rec) {
		b[strings.ToLower(name)] = struct{}{}
	}
	if len(a) != len(b) {
		return false
	}
	for k := range a {
		if _, ok := b[k]; !ok {
			return false
		}
	}
	return true
}

// SortedNames is a stable display of reviewer names.
func SortedNames(names []string) []string {
	out := append([]string{}, names...)
	sort.Strings(out)
	return out
}
