// Copyright 2026 Uddeshya Kumar
// SPDX-License-Identifier: Apache-2.0

package engine

import (
	"math/rand"
	"testing"

	"github.com/uddeshya-world/verdict/internal/logic"
)

func TestDecideSafetyProperty(t *testing.T) {
	rng := rand.New(rand.NewSource(20261108))
	statuses := []string{"draft", "reviewed", "deprecated", "nope"}
	kinds := []string{"untrusted", "trusted_only", "unknown", ""}
	for i := 0; i < 400; i++ {
		res := logic.Result{Value: logic.Value(rng.Intn(3)), TrueConf: logic.Confidence(rng.Intn(5))}
		if rng.Intn(2) == 0 {
			nJust := 1
			js := []string{"vulnerable_code_not_present"}
			uniform := true
			if rng.Intn(3) == 0 {
				nJust = 2
				js = []string{"component_not_present", "vulnerable_code_not_present"}
				uniform = false
			}
			_ = nJust
			res.StrictFalse = &logic.StrictFalse{
				Confidence:     logic.Confidence(rng.Intn(5)),
				Justifications: js,
				Uniform:        uniform,
				CheckIDs:       []string{"a"},
				EvidenceIDs:    []string{"e"},
			}
		}
		meta := Meta{
			Status:    statuses[rng.Intn(len(statuses))],
			Reviewers: rng.Intn(4),
			Ceiling:   logic.Confidence(rng.Intn(5)),
		}
		if meta.Status == "deprecated" {
			meta.Deprecated = true
		}
		exp := ExposureClass{Kind: kinds[rng.Intn(len(kinds))]}
		d := Decide(res, meta, exp)
		if d.State == stateNotAffected {
			if res.Value != logic.False || res.StrictFalse == nil || !res.StrictFalse.Uniform || len(res.StrictFalse.Justifications) != 1 {
				t.Fatalf("not_affected without a uniform false proof: %+v", d)
			}
			if !meta.allowsNotAffected() {
				t.Fatalf("not_affected from ineligible pack: %+v meta=%+v", d, meta)
			}
			if capConf(res.StrictFalse.Confidence, meta.Ceiling) < logic.ConfHigh {
				t.Fatalf("not_affected below high: %+v", d)
			}
			if d.VEX != vexNotAffected || d.Justification == "" || d.Uncertainty {
				t.Fatalf("not_affected shape: %+v", d)
			}
		} else if d.Justification != "" {
			t.Fatalf("justification set on %s", d.State)
		}
		if d.State == stateExploitable || d.State == stateNotExposed {
			if res.Value != logic.True || d.VEX != vexAffected {
				t.Fatalf("affected shape: %+v value %s", d, res.Value)
			}
		}
		if d.State == stateNotExposed && exp.Kind != "trusted_only" {
			t.Fatalf("not exposed without trusted exposure: %+v", d)
		}
		if res.Value == logic.True && exp.Kind != "trusted_only" && exp.Kind != "untrusted" {
			if d.State != stateExploitable || !d.Uncertainty {
				t.Fatalf("unknown exposure must be uncertain exploitable: %+v", d)
			}
			found := false
			for _, r := range d.Reasons {
				if r == "exposure_unknown_treated_as_exposed" {
					found = true
				}
			}
			if !found {
				t.Fatal("missing exposure reason")
			}
		}
		if d.State == stateNeedsReview && d.VEX != vexInvestigating {
			t.Fatalf("needs_review vex: %s", d.VEX)
		}
		if res.Value != logic.True && (d.State == stateExploitable || d.State == stateNotExposed) {
			t.Fatal("non-true tree produced an affected state")
		}
	}
}

func TestExposureIgnoresAssetZones(t *testing.T) {
	asset := assetWithZonesOnly()
	got := classifyExposure(labPol(t), spec22(), asset, mustTime(t), mustAge())
	if got.Kind != "unknown" || !got.Uncertain {
		t.Fatalf("zones alone are not exposure: %+v", got)
	}
}
