// Copyright 2026 Uddeshya Kumar
// SPDX-License-Identifier: Apache-2.0

package diff

import (
	"errors"
	"reflect"
	"testing"

	"github.com/uddeshya-world/verdict/internal/engine"
)

var allStates = []string{StateExploitable, StateNotExposed, StateNotAffected, StateNeedsReview}

func st(s string) *AssetState { return &AssetState{State: s} }

// TestClassifyTable pins every transition, including added and removed.
func TestClassifyTable(t *testing.T) {
	want := map[[2]string]string{
		// from exploitable
		{StateExploitable, StateExploitable}: ClassNeutral,
		{StateExploitable, StateNotExposed}:  ClassImprovement,
		{StateExploitable, StateNotAffected}: ClassImprovement,
		{StateExploitable, StateNeedsReview}: ClassImprovement,
		// from vulnerable_not_exposed
		{StateNotExposed, StateExploitable}: ClassRegression,
		{StateNotExposed, StateNotExposed}:  ClassNeutral,
		{StateNotExposed, StateNotAffected}: ClassImprovement,
		{StateNotExposed, StateNeedsReview}: ClassNeutral,
		// from not_affected: leaving it is always a regression
		{StateNotAffected, StateExploitable}: ClassRegression,
		{StateNotAffected, StateNotExposed}:  ClassRegression,
		{StateNotAffected, StateNotAffected}: ClassNeutral,
		{StateNotAffected, StateNeedsReview}: ClassRegression,
		// from needs_review
		{StateNeedsReview, StateExploitable}: ClassRegression,
		{StateNeedsReview, StateNotExposed}:  ClassNeutral,
		{StateNeedsReview, StateNotAffected}: ClassImprovement,
		{StateNeedsReview, StateNeedsReview}: ClassNeutral,
		// added (before absent)
		{"", StateExploitable}: ClassRegression,
		{"", StateNotExposed}:  ClassNeutral,
		{"", StateNotAffected}: ClassNeutral,
		{"", StateNeedsReview}: ClassNeutral,
		// removed (after absent): never an improvement, never a regression
		{StateExploitable, ""}: ClassNeutral,
		{StateNotExposed, ""}:  ClassNeutral,
		{StateNotAffected, ""}: ClassNeutral,
		{StateNeedsReview, ""}: ClassNeutral,
	}
	if len(want) != 4*4+4+4 {
		t.Fatalf("table has %d rows", len(want))
	}
	seen := map[string]bool{}
	for k, w := range want {
		var b, a *AssetState
		if k[0] != "" {
			b = st(k[0])
		}
		if k[1] != "" {
			a = st(k[1])
		}
		if got := Classify(b, a); got != w {
			t.Errorf("%q -> %q: got %s, want %s", k[0], k[1], got, w)
		}
		seen[w] = true
	}
	for _, c := range []string{ClassRegression, ClassImprovement, ClassNeutral} {
		if !seen[c] {
			t.Errorf("class %s not covered", c)
		}
	}
}

func verdict(id, state string, reasons ...string) engine.Verdict {
	vex := map[string]string{
		StateExploitable: "affected", StateNotExposed: "affected",
		StateNotAffected: "not_affected", StateNeedsReview: "under_investigation",
	}[state]
	v := engine.Verdict{AssetID: id, State: state, VEXStatus: vex, Confidence: "high", Reasons: reasons}
	if state == StateNotAffected {
		v.Justification = "vulnerable_code_not_present"
	}
	return v
}

func report(vs ...engine.Verdict) *engine.Report {
	return &engine.Report{
		PackID: "ECP-X", CVE: "CVE-2099-0001", PackSHA256: "aa", PolicySHA256: "bb",
		KBVersion: "kb1", EvaluationTime: "2026-01-01T00:00:00Z", PackStatus: "reviewed", Tool: "t",
		Verdicts: vs,
	}
}

func TestCompareRefusesDifferentPackOrCVE(t *testing.T) {
	b := report(verdict("a", StateExploitable))
	for _, mut := range []struct {
		field string
		f     func(*engine.Report)
	}{
		{"pack_id", func(r *engine.Report) { r.PackID = "ECP-Y" }},
		{"cve", func(r *engine.Report) { r.CVE = "CVE-2099-0002" }},
	} {
		a := report(verdict("a", StateExploitable))
		mut.f(a)
		_, err := Compare(b, a)
		var me *MismatchError
		if !errors.As(err, &me) || me.Field != mut.field {
			t.Fatalf("%s: want MismatchError, got %v", mut.field, err)
		}
	}
	if _, err := Compare(report(verdict("a", StateExploitable), verdict("a", StateNeedsReview)), b); err == nil {
		t.Fatal("duplicate asset_id must be refused")
	}
	if _, err := Compare(nil, b); err == nil {
		t.Fatal("nil report must be refused")
	}
}

func TestContextChangesNotedNotRefused(t *testing.T) {
	b := report(verdict("a", StateExploitable))
	a := report(verdict("a", StateExploitable))
	a.PackSHA256, a.PolicySHA256, a.KBVersion, a.EvaluationTime = "cc", "dd", "kb2", "2026-02-01T00:00:00Z"
	res, err := Compare(b, a)
	if err != nil {
		t.Fatal(err)
	}
	var fields []string
	for _, c := range res.ContextChanges {
		fields = append(fields, c.Field)
	}
	if want := []string{"pack_sha256", "policy_sha256", "kb_version", "evaluation_time"}; !reflect.DeepEqual(fields, want) {
		t.Fatalf("context changes %v, want %v", fields, want)
	}
	if len(res.Changes) != 0 || res.Counts.Unchanged != 1 {
		t.Fatalf("no asset changed: %+v", res)
	}
	for _, p := range []string{FailOnRegression, FailOnAnyAffectedChange, FailOnAny} {
		if m := res.Matches(p); len(m) != 0 {
			t.Fatalf("%s: context changes alone must not match", p)
		}
	}
}

func TestCompareFieldsAndReasons(t *testing.T) {
	b := report(
		verdict("same", StateNeedsReview, "insufficient_proof", "tree_unknown"),
		verdict("reorder", StateNeedsReview, "insufficient_proof", "tree_unknown"),
		verdict("reasons", StateNeedsReview, "insufficient_proof", "tree_unknown"),
		verdict("unc", StateExploitable),
		verdict("gone", StateNotAffected),
	)
	unc := verdict("unc", StateExploitable, "exposure_unknown_treated_as_exposed")
	unc.ExposureUncertainty = true
	a := report(
		unc,
		verdict("new", StateNeedsReview),
		verdict("reasons", StateNeedsReview, "insufficient_proof", "tree_false_without_sufficient_proof"),
		verdict("reorder", StateNeedsReview, "tree_unknown", "insufficient_proof"),
		verdict("same", StateNeedsReview, "insufficient_proof", "tree_unknown"),
	)
	res, err := Compare(b, a)
	if err != nil {
		t.Fatal(err)
	}
	var ids []string
	for _, c := range res.Changes {
		ids = append(ids, c.AssetID+":"+c.Kind+":"+c.Class)
	}
	want := []string{"gone:removed:neutral", "new:added:neutral", "reasons:changed:neutral", "unc:changed:neutral"}
	if !reflect.DeepEqual(ids, want) {
		t.Fatalf("changes %v, want %v", ids, want)
	}
	r := res.Changes[2]
	if !reflect.DeepEqual(r.Fields, []string{"reasons"}) || !reflect.DeepEqual(r.ReasonsAdded, []string{"tree_false_without_sufficient_proof"}) || !reflect.DeepEqual(r.ReasonsRemoved, []string{"tree_unknown"}) {
		t.Fatalf("reasons change: %+v", r)
	}
	if u := res.Changes[3]; !reflect.DeepEqual(u.Fields, []string{"exposure_uncertainty", "reasons"}) {
		t.Fatalf("uncertainty change fields %v", u.Fields)
	}
	if res.Counts != (Counts{Added: 1, Removed: 1, Changed: 2, Unchanged: 2, Neutral: 4}) {
		t.Fatalf("counts %+v", res.Counts)
	}
	// The removed not_affected asset is not a regression, but any catches it.
	if len(res.Matches(FailOnRegression)) != 0 || len(res.Matches(FailOnAny)) != 4 {
		t.Fatal("fail-on policies")
	}
	// unc is exploitable on both sides, so any-affected-change matches it.
	if m := res.Matches(FailOnAnyAffectedChange); len(m) != 1 || m[0].AssetID != "unc" {
		t.Fatalf("any-affected-change: %+v", m)
	}
}

func TestMatchesPolicies(t *testing.T) {
	b := report(verdict("x", StateNeedsReview), verdict("y", StateExploitable), verdict("z", StateNotExposed))
	a := report(verdict("x", StateExploitable), verdict("z", StateNeedsReview))
	res, err := Compare(b, a)
	if err != nil {
		t.Fatal(err)
	}
	count := map[string]int{}
	for _, p := range []string{FailOnRegression, FailOnAnyAffectedChange, FailOnAny} {
		count[p] = len(res.Matches(p))
	}
	// x regression; y removed (affected); z changed out of affected.
	if count[FailOnRegression] != 1 || count[FailOnAnyAffectedChange] != 3 || count[FailOnAny] != 3 {
		t.Fatalf("matches %v", count)
	}
	if len(res.Matches("bogus")) != 0 || ValidFailOn("bogus") || !ValidFailOn(DefaultFailOn) {
		t.Fatal("unknown policy")
	}
}

// TestDeterministic: verdict order in either report does not change the result.
func TestDeterministic(t *testing.T) {
	vs := []engine.Verdict{
		verdict("c", StateNotAffected), verdict("a", StateExploitable),
		verdict("b", StateNeedsReview, "tree_unknown", "insufficient_proof"), verdict("d", StateNotExposed),
	}
	ws := []engine.Verdict{
		verdict("e", StateExploitable), verdict("b", StateNeedsReview, "insufficient_proof"),
		verdict("c", StateExploitable), verdict("a", StateNeedsReview),
	}
	first, err := Compare(report(vs...), report(ws...))
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 20; i++ {
		rv := append([]engine.Verdict{}, vs...)
		rw := append([]engine.Verdict{}, ws...)
		for j := range rv {
			k := (j*7 + i) % len(rv)
			rv[j], rv[k] = rv[k], rv[j]
		}
		for j := range rw {
			k := (j*5 + i) % len(rw)
			rw[j], rw[k] = rw[k], rw[j]
		}
		got, err := Compare(report(rv...), report(rw...))
		if err != nil {
			t.Fatal(err)
		}
		if !reflect.DeepEqual(got.Changes, first.Changes) || got.Counts != first.Counts {
			t.Fatalf("order-dependent result on permutation %d", i)
		}
	}
	for i := 1; i < len(first.Changes); i++ {
		if first.Changes[i-1].AssetID >= first.Changes[i].AssetID {
			t.Fatal("changes not sorted by asset_id")
		}
	}
}
