// Copyright 2026 Uddeshya Kumar
// SPDX-License-Identifier: Apache-2.0

package engine

import (
	"sort"

	"github.com/uddeshya-world/verdict/internal/logic"
)

const (
	stateExploitable = "exploitable"
	stateNotExposed  = "vulnerable_not_exposed"
	stateNotAffected = "not_affected"
	stateNeedsReview = "needs_review"
	vexAffected      = "affected"
	vexNotAffected   = "not_affected"
	vexInvestigating = "under_investigation"
)

// Meta is the pack review state the not_affected rule consults.
type Meta struct {
	Status     string
	Reviewers  int
	Ceiling    logic.Confidence
	Deprecated bool
}

// ExposureClass is the reachability classification for a true tree.
// Kind is "untrusted", "trusted_only", or "unknown".
type ExposureClass struct {
	Kind        string
	Uncertain   bool
	Reason      string
	EvidenceIDs []string
}

// Decision is the operator-facing result before rendering.
type Decision struct {
	State         string
	VEX           string
	Justification string
	Confidence    logic.Confidence
	Uncertainty   bool
	Reasons       []string
	Tree          string
}

func (m Meta) allowsNotAffected() bool {
	if m.Deprecated || m.Status == "deprecated" {
		return false
	}
	return m.Status == "reviewed" && m.Reviewers >= 2 && m.Ceiling >= logic.ConfHigh
}

func (m Meta) blockReasons() []string {
	var reasons []string
	if m.Deprecated || m.Status == "deprecated" {
		reasons = append(reasons, ReasonPackDeprecated)
	}
	if m.Status != "reviewed" && m.Status != "deprecated" {
		reasons = append(reasons, ReasonPackNotReviewed)
	}
	if m.Status == "reviewed" && m.Reviewers < 2 {
		reasons = append(reasons, ReasonReviewerQuorumNotMet)
	}
	if m.Ceiling < logic.ConfHigh {
		reasons = append(reasons, ReasonConfidenceCeilingBlocks)
	}
	return reasons
}

func capConf(c, ceiling logic.Confidence) logic.Confidence {
	if c > ceiling {
		return ceiling
	}
	return c
}

// Decide applies the not_affected bar and the exposure split.
// Exposure is ignored unless the tree is true.
func Decide(res logic.Result, meta Meta, exp ExposureClass) Decision {
	d := Decision{Tree: res.Value.String(), Reasons: []string{}}
	if res.Value == logic.True {
		d.Confidence = capConf(res.TrueConf, meta.Ceiling)
		switch exp.Kind {
		case "trusted_only":
			d.State = stateNotExposed
			d.VEX = vexAffected
		case "untrusted":
			d.State = stateExploitable
			d.VEX = vexAffected
			d.Uncertainty = exp.Uncertain
		default:
			d.State = stateExploitable
			d.VEX = vexAffected
			d.Uncertainty = true
			d.Reasons = append(d.Reasons, ReasonExposureUnknownTreatedExposed)
			if exp.Reason != "" {
				d.Reasons = append(d.Reasons, exp.Reason)
			}
			sort.Strings(d.Reasons)
		}
		return d
	}

	d.State = stateNeedsReview
	d.VEX = vexInvestigating
	// A strict proof is only meaningful when the Kleene value is false.
	// An inconsistent Result must not become not_affected.
	if res.Value != logic.False || res.StrictFalse == nil {
		d.Confidence = logic.ConfNone
		d.Reasons = append(d.Reasons, ReasonInsufficientProof)
		if res.Value == logic.Unknown {
			d.Reasons = append(d.Reasons, ReasonTreeUnknown)
		} else {
			d.Reasons = append(d.Reasons, ReasonTreeFalseWithoutSufficient)
		}
		sort.Strings(d.Reasons)
		return d
	}

	conf := capConf(res.StrictFalse.Confidence, meta.Ceiling)
	d.Confidence = conf
	if !res.StrictFalse.Uniform {
		d.Reasons = append(d.Reasons, ReasonMixedJustification)
	}
	d.Reasons = append(d.Reasons, meta.blockReasons()...)
	if conf < logic.ConfHigh {
		d.Reasons = append(d.Reasons, ReasonConfidenceBelowNotAffectedBar)
	}
	if res.StrictFalse.Uniform && meta.allowsNotAffected() && conf >= logic.ConfHigh && len(res.StrictFalse.Justifications) == 1 {
		d.State = stateNotAffected
		d.VEX = vexNotAffected
		d.Justification = res.StrictFalse.Justifications[0]
		d.Reasons = []string{}
		return d
	}
	sort.Strings(d.Reasons)
	return d
}
