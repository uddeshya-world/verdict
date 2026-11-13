// Copyright 2026 Uddeshya Kumar
// SPDX-License-Identifier: Apache-2.0

// Package diff compares two drill reports for the same pack and CVE, asset
// by asset. It never re-decides a verdict: it reads the state each report
// already carries and classifies the move between them. It does not read the
// clock, the filesystem, or the network.
package diff

import (
	"fmt"
	"sort"

	"github.com/uddeshya-world/verdict/internal/engine"
)

// States, as the report schema spells them.
const (
	StateExploitable = "exploitable"
	StateNotExposed  = "vulnerable_not_exposed"
	StateNotAffected = "not_affected"
	StateNeedsReview = "needs_review"
)

// Change kinds.
const (
	KindAdded   = "added"
	KindRemoved = "removed"
	KindChanged = "changed"
)

// Change classes.
const (
	ClassRegression  = "regression"
	ClassImprovement = "improvement"
	ClassNeutral     = "neutral"
)

// Fail-on policies for Result.Matches.
const (
	FailOnRegression        = "regression"
	FailOnAnyAffectedChange = "any-affected-change"
	FailOnAny               = "any"
	DefaultFailOn           = FailOnRegression
	// FailOnValues is the policy list for error messages.
	FailOnValues = "regression, any-affected-change, or any"
)

// ValidFailOn reports whether s is a known --fail-on policy.
func ValidFailOn(s string) bool {
	return s == FailOnRegression || s == FailOnAnyAffectedChange || s == FailOnAny
}

// AssetState is the part of a verdict the diff compares. Reasons keep the
// report's order; they are compared as a set.
type AssetState struct {
	State               string   `json:"state"`
	VEXStatus           string   `json:"vex_status"`
	Justification       string   `json:"justification,omitempty"`
	Confidence          string   `json:"confidence"`
	ExposureUncertainty bool     `json:"exposure_uncertainty"`
	Reasons             []string `json:"reasons"`
}

// Change is one asset that was added, removed, or changed.
type Change struct {
	AssetID string      `json:"asset_id"`
	Kind    string      `json:"change"`
	Class   string      `json:"class"`
	Before  *AssetState `json:"before"`
	After   *AssetState `json:"after"`
	// Fields lists the compared fields that differ, in a fixed order. For an
	// added or removed asset it is empty.
	Fields         []string `json:"fields"`
	ReasonsAdded   []string `json:"reasons_added"`
	ReasonsRemoved []string `json:"reasons_removed"`
}

// ContextChange is a report-level field that differs. It is noted, not
// refused: the comparison is still per asset, but the reader should know the
// pack, policy, knowledge version, or evaluation time moved too.
type ContextChange struct {
	Field  string `json:"field"`
	Before string `json:"before"`
	After  string `json:"after"`
}

// Counts summarises a Result.
type Counts struct {
	Added       int `json:"added"`
	Removed     int `json:"removed"`
	Changed     int `json:"changed"`
	Unchanged   int `json:"unchanged"`
	Regression  int `json:"regression"`
	Improvement int `json:"improvement"`
	Neutral     int `json:"neutral"`
}

// Result is the comparison of two reports.
type Result struct {
	PackID         string          `json:"pack_id"`
	CVE            string          `json:"cve"`
	ContextChanges []ContextChange `json:"context_changes"`
	BeforeSummary  engine.Summary  `json:"before_summary"`
	AfterSummary   engine.Summary  `json:"after_summary"`
	Counts         Counts          `json:"counts"`
	Changes        []Change        `json:"changes"`
}

// MismatchError is a refusal to compare reports for different packs or CVEs.
type MismatchError struct {
	Field, Before, After string
}

func (e *MismatchError) Error() string {
	return fmt.Sprintf("diff: %s differs (before %q, after %q); reports for different packs or CVEs are not comparable", e.Field, e.Before, e.After)
}

// Compare diffs before against after. It refuses reports whose pack_id or
// cve differ, and reports with a duplicate asset_id (the pairing would be
// ambiguous). Changes are ordered by asset_id.
func Compare(before, after *engine.Report) (*Result, error) {
	if before == nil || after == nil {
		return nil, fmt.Errorf("diff: two reports are required")
	}
	if before.PackID != after.PackID {
		return nil, &MismatchError{Field: "pack_id", Before: before.PackID, After: after.PackID}
	}
	if before.CVE != after.CVE {
		return nil, &MismatchError{Field: "cve", Before: before.CVE, After: after.CVE}
	}
	bm, err := index(before, "before")
	if err != nil {
		return nil, err
	}
	am, err := index(after, "after")
	if err != nil {
		return nil, err
	}
	res := &Result{
		PackID:         before.PackID,
		CVE:            before.CVE,
		ContextChanges: contextChanges(before, after),
		BeforeSummary:  before.Summary,
		AfterSummary:   after.Summary,
		Changes:        []Change{},
	}
	ids := make([]string, 0, len(bm)+len(am))
	for id := range bm {
		ids = append(ids, id)
	}
	for id := range am {
		if _, ok := bm[id]; !ok {
			ids = append(ids, id)
		}
	}
	sort.Strings(ids)
	for _, id := range ids {
		b, inB := bm[id]
		a, inA := am[id]
		var c Change
		switch {
		case !inB:
			s := stateOf(a)
			c = Change{AssetID: id, Kind: KindAdded, After: &s, Fields: []string{}, ReasonsAdded: sortedCopy(s.Reasons), ReasonsRemoved: []string{}}
			res.Counts.Added++
		case !inA:
			s := stateOf(b)
			c = Change{AssetID: id, Kind: KindRemoved, Before: &s, Fields: []string{}, ReasonsAdded: []string{}, ReasonsRemoved: sortedCopy(s.Reasons)}
			res.Counts.Removed++
		default:
			bs, as := stateOf(b), stateOf(a)
			fields := changedFields(bs, as)
			if len(fields) == 0 {
				res.Counts.Unchanged++
				continue
			}
			added, removed := setDiff(bs.Reasons, as.Reasons)
			c = Change{AssetID: id, Kind: KindChanged, Before: &bs, After: &as, Fields: fields, ReasonsAdded: added, ReasonsRemoved: removed}
			res.Counts.Changed++
		}
		c.Class = Classify(c.Before, c.After)
		switch c.Class {
		case ClassRegression:
			res.Counts.Regression++
		case ClassImprovement:
			res.Counts.Improvement++
		default:
			res.Counts.Neutral++
		}
		res.Changes = append(res.Changes, c)
	}
	return res, nil
}

// Classify returns the class of a move from before to after. A nil side is an
// added (before nil) or removed (after nil) asset.
//
//   - regression: after is exploitable and before was not (including an added
//     exploitable asset), or before was not_affected and after is anything
//     else that is still present.
//   - improvement: before was exploitable and after is a different state, or
//     after is not_affected and before was something else. Both sides must be
//     present: an added asset is never an improvement, and a removed asset is
//     never one either, because a report that omits an asset proves nothing
//     about it.
//   - neutral: everything else, including a removed asset (use --fail-on any
//     to gate on removals) and a change that leaves the state alone.
func Classify(before, after *AssetState) string {
	switch {
	case before == nil && after == nil:
		return ClassNeutral
	case before == nil:
		if after.State == StateExploitable {
			return ClassRegression
		}
		return ClassNeutral
	case after == nil:
		return ClassNeutral
	}
	if after.State == StateExploitable && before.State != StateExploitable {
		return ClassRegression
	}
	if before.State == StateNotAffected && after.State != StateNotAffected {
		return ClassRegression
	}
	if before.State == StateExploitable && after.State != StateExploitable {
		return ClassImprovement
	}
	if after.State == StateNotAffected && before.State != StateNotAffected {
		return ClassImprovement
	}
	return ClassNeutral
}

// Matches returns the changes the policy matches.
//
//   - regression: changes classed regression.
//   - any-affected-change: regressions, plus any added, removed, or changed
//     asset whose before or after state is exploitable or
//     vulnerable_not_exposed (OpenVEX affected).
//   - any: every added, removed, or changed asset. Context changes alone do
//     not match.
func (r *Result) Matches(policy string) []Change {
	var out []Change
	for _, c := range r.Changes {
		var m bool
		switch policy {
		case FailOnRegression:
			m = c.Class == ClassRegression
		case FailOnAnyAffectedChange:
			m = c.Class == ClassRegression || affected(c.Before) || affected(c.After)
		case FailOnAny:
			m = true
		}
		if m {
			out = append(out, c)
		}
	}
	return out
}

func affected(s *AssetState) bool {
	return s != nil && (s.State == StateExploitable || s.State == StateNotExposed)
}

func index(r *engine.Report, side string) (map[string]*engine.Verdict, error) {
	m := make(map[string]*engine.Verdict, len(r.Verdicts))
	for i := range r.Verdicts {
		v := &r.Verdicts[i]
		if _, dup := m[v.AssetID]; dup {
			return nil, fmt.Errorf("diff: %s report has asset_id %q more than once", side, v.AssetID)
		}
		m[v.AssetID] = v
	}
	return m, nil
}

func stateOf(v *engine.Verdict) AssetState {
	return AssetState{
		State:               v.State,
		VEXStatus:           v.VEXStatus,
		Justification:       v.Justification,
		Confidence:          v.Confidence,
		ExposureUncertainty: v.ExposureUncertainty,
		Reasons:             append([]string{}, v.Reasons...),
	}
}

func changedFields(b, a AssetState) []string {
	var f []string
	if b.State != a.State {
		f = append(f, "state")
	}
	if b.VEXStatus != a.VEXStatus {
		f = append(f, "vex_status")
	}
	if b.Justification != a.Justification {
		f = append(f, "justification")
	}
	if b.Confidence != a.Confidence {
		f = append(f, "confidence")
	}
	if b.ExposureUncertainty != a.ExposureUncertainty {
		f = append(f, "exposure_uncertainty")
	}
	if added, removed := setDiff(b.Reasons, a.Reasons); len(added)+len(removed) > 0 {
		f = append(f, "reasons")
	}
	return f
}

func contextChanges(b, a *engine.Report) []ContextChange {
	out := []ContextChange{}
	for _, p := range []struct{ field, b, a string }{
		{"pack_sha256", b.PackSHA256, a.PackSHA256},
		{"pack_status", b.PackStatus, a.PackStatus},
		{"policy_sha256", b.PolicySHA256, a.PolicySHA256},
		{"kb_version", b.KBVersion, a.KBVersion},
		{"evaluation_time", b.EvaluationTime, a.EvaluationTime},
		{"tool", b.Tool, a.Tool},
	} {
		if p.b != p.a {
			out = append(out, ContextChange{Field: p.field, Before: p.b, After: p.a})
		}
	}
	return out
}

// setDiff returns the sorted, de-duplicated members of a not in b (added)
// and of b not in a (removed), reading b as before and a as after.
func setDiff(before, after []string) (added, removed []string) {
	bs, as := map[string]bool{}, map[string]bool{}
	for _, s := range before {
		bs[s] = true
	}
	for _, s := range after {
		as[s] = true
	}
	added, removed = []string{}, []string{}
	for s := range as {
		if !bs[s] {
			added = append(added, s)
		}
	}
	for s := range bs {
		if !as[s] {
			removed = append(removed, s)
		}
	}
	sort.Strings(added)
	sort.Strings(removed)
	return added, removed
}

func sortedCopy(s []string) []string {
	out := append([]string{}, s...)
	sort.Strings(out)
	return out
}
