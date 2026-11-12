// Copyright 2026 Uddeshya Kumar
// SPDX-License-Identifier: Apache-2.0

package engine

import (
	"sort"
	"time"

	"github.com/uddeshya-world/verdict/internal/logic"
	"github.com/uddeshya-world/verdict/internal/pack"
	"github.com/uddeshya-world/verdict/internal/purl"
	"github.com/uddeshya-world/verdict/internal/snapshot"
	"github.com/uddeshya-world/verdict/internal/vercmp"
)

type observation struct {
	Basis      string
	Confidence string
	ObservedAt string
	ExpiresAt  string
}

type leafEval struct {
	ID     string
	Leaf   logic.Leaf
	Reason string
	Detail string
	Stale  bool
}

func assess(o observation, eval time.Time, maxAge time.Duration) (usable, observed bool, conf logic.Confidence, reason string) {
	ts, err := time.Parse(time.RFC3339, o.ObservedAt)
	if err != nil {
		return false, false, logic.ConfNone, "unreadable_time"
	}
	if ts.After(eval) {
		return false, false, logic.ConfNone, "evidence_time_after_evaluation"
	}
	if eval.Sub(ts) > maxAge {
		return false, false, logic.ConfNone, "stale_evidence"
	}
	if o.ExpiresAt != "" {
		exp, err := time.Parse(time.RFC3339, o.ExpiresAt)
		if err != nil {
			return false, false, logic.ConfNone, "unreadable_time"
		}
		if !exp.After(eval) {
			return false, false, logic.ConfNone, "expired_evidence"
		}
	}
	conf, ok := logic.ParseConfidence(o.Confidence)
	if !ok {
		return false, false, logic.ConfNone, "unreadable_confidence"
	}
	switch o.Basis {
	case "inferred":
		return false, false, logic.ConfNone, "inferred_evidence_discarded"
	case "attested":
		return true, false, conf, ""
	case "observed":
		return true, true, conf, ""
	default:
		return false, false, logic.ConfNone, "basis_not_usable"
	}
}

func findFact(asset snapshot.Asset, key string) *snapshot.Fact {
	for i := range asset.Facts {
		if asset.Facts[i].Key == key && asset.Facts[i].PURL == "" {
			return &asset.Facts[i]
		}
	}
	return nil
}

// findAdvisories returns every advisory fact for key whose purl is the
// package's purl. exact facts have the same canonical form; variants differ
// only by case, white space, or separators in the name (FoldKey). Every
// match is returned so the caller can be independent of fact order.
func findAdvisories(asset snapshot.Asset, key, packagePURL string) (exact, variants []*snapshot.Fact) {
	if key == "" || packagePURL == "" {
		return nil, nil
	}
	for i := range asset.Facts {
		f := &asset.Facts[i]
		if f.Key != key || f.PURL == "" {
			continue
		}
		switch {
		case purl.Same(f.PURL, packagePURL):
			exact = append(exact, f)
		case purl.SameFolded(f.PURL, packagePURL):
			variants = append(variants, f)
		}
	}
	return exact, variants
}

// advisoryNamesPackage reports whether any purl-scoped advisory fact for key
// names this inventory package, under any spelling.
func advisoryNamesPackage(asset snapshot.Asset, key, packagePURL string) bool {
	exact, variants := findAdvisories(asset, key, packagePURL)
	return len(exact)+len(variants) > 0
}

// orphanAdvisory returns a purl-scoped advisory fact for key that names no
// inventory package. With a complete inventory that is a contradiction, so
// it blocks the absence proof.
func orphanAdvisory(asset snapshot.Asset, key string) *snapshot.Fact {
	if key == "" {
		return nil
	}
	for i := range asset.Facts {
		f := &asset.Facts[i]
		if f.Key != key || f.PURL == "" {
			continue
		}
		named := false
		for _, pkg := range asset.Inventory.Packages {
			if purl.SameFolded(f.PURL, pkg.PURL) {
				named = true
				break
			}
		}
		if !named {
			return f
		}
	}
	return nil
}

// classify sorts one inventory package against the pack patterns.
// exact: canonical type, namespace, and name match a pattern.
// related: anything purl.Related says could be the component.
func classify(parsed purl.PURL, patterns []string) (exact, related bool) {
	for _, pattern := range patterns {
		if purl.Match(pattern, parsed) {
			return true, false
		}
	}
	for _, pattern := range patterns {
		if purl.Related(pattern, parsed) {
			return false, true
		}
	}
	return false, false
}

func unknownLeaf(id, reason, detail string, evidence []string) leafEval {
	return leafEval{
		ID: id,
		Leaf: logic.Leaf{
			Value:       logic.Unknown,
			EvidenceIDs: nonEmpty(evidence),
		},
		Reason: reason,
		Detail: detail,
		Stale:  reason == "stale_evidence" || reason == "expired_evidence",
	}
}

func valueLeaf(id string, value logic.Value, conf logic.Confidence, observed bool, justification string, evidence []string, reason, detail string) leafEval {
	return leafEval{
		ID: id,
		Leaf: logic.Leaf{
			Value:         value,
			Confidence:    conf,
			Observed:      observed,
			Justification: justification,
			EvidenceIDs:   nonEmpty(evidence),
		},
		Reason: reason,
		Detail: detail,
	}
}

func evalChecks(p *pack.Pack, asset snapshot.Asset, eval time.Time) []leafEval {
	ids := sortedCheckIDs(p)
	out := make([]leafEval, 0, len(ids))
	for _, id := range ids {
		out = append(out, evalCheck(id, p.Checks[id], p.Component.Purls, asset, eval, p.MaxAge))
	}
	return out
}

func evalCheck(id string, ch pack.Check, component []string, asset snapshot.Asset, eval time.Time, maxAge time.Duration) leafEval {
	switch ch.Type {
	case "package_version":
		return evalPackage(id, ch, component, asset, eval, maxAge)
	case "process_listening":
		return evalBoolFact(id, ch, "process.listening."+ch.Process, asset, eval, maxAge)
	case "process_running":
		return evalBoolFact(id, ch, "process.running."+ch.Process, asset, eval, maxAge)
	case "file_exists":
		return evalBoolFact(id, ch, "file.exists."+ch.Path, asset, eval, maxAge)
	case "manual_attestation":
		return evalEquals(id, ch, ch.Key, true, asset, eval, maxAge)
	default:
		return evalEquals(id, ch, ch.Key, false, asset, eval, maxAge)
	}
}

func evalBoolFact(id string, ch pack.Check, key string, asset snapshot.Asset, eval time.Time, maxAge time.Duration) leafEval {
	fact := findFact(asset, key)
	if fact == nil {
		return unknownLeaf(id, "missing_fact", key, nil)
	}
	usable, observed, conf, reason := assess(observation{fact.Basis, fact.Confidence, fact.ObservedAt, fact.ExpiresAt}, eval, maxAge)
	if !usable {
		return unknownLeaf(id, reason, key, []string{fact.EvidenceID})
	}
	switch fact.Value {
	case "true", "false":
	default:
		return unknownLeaf(id, "unexpected_fact_value", key, []string{fact.EvidenceID})
	}
	value := logic.False
	if fact.Value == "true" {
		value = logic.True
	}
	weak := ""
	if !observed {
		weak = "evidence_not_observed"
	} else if value == logic.False && conf < logic.ConfHigh {
		weak = "confidence_below_not_affected_bar"
	}
	return valueLeaf(id, value, conf, observed, ch.NegationJustification, []string{fact.EvidenceID}, weak, key)
}

func evalEquals(id string, ch pack.Check, key string, requireExpiry bool, asset snapshot.Asset, eval time.Time, maxAge time.Duration) leafEval {
	if ch.WhenPackage != nil {
		gate, gerr := evalWhen(*ch.WhenPackage, asset, eval, maxAge)
		if gerr.Reason != "" {
			gerr.ID = id
			return gerr
		}
		if !gate.applicable {
			weak := "when_package_not_applicable"
			if !gate.observed {
				weak = "evidence_not_observed"
			} else if gate.conf < logic.ConfHigh {
				weak = "confidence_below_not_affected_bar"
			}
			return valueLeaf(id, logic.False, gate.conf, gate.observed, ch.NegationJustification, gate.evidence, weak, key)
		}
	}
	fact := findFact(asset, key)
	if fact == nil {
		return unknownLeaf(id, "missing_fact", key, nil)
	}
	if requireExpiry && fact.ExpiresAt == "" {
		return unknownLeaf(id, "attestation_missing_expiry", key, []string{fact.EvidenceID})
	}
	usable, observed, conf, reason := assess(observation{fact.Basis, fact.Confidence, fact.ObservedAt, fact.ExpiresAt}, eval, maxAge)
	if !usable {
		return unknownLeaf(id, reason, key, []string{fact.EvidenceID})
	}
	value := logic.False
	if fact.Value == ch.Equals {
		value = logic.True
	}
	weak := ""
	if !observed {
		weak = "evidence_not_observed"
	} else if value == logic.False && conf < logic.ConfHigh {
		weak = "confidence_below_not_affected_bar"
	}
	return valueLeaf(id, value, conf, observed, ch.NegationJustification, []string{fact.EvidenceID}, weak, key)
}

type whenResult struct {
	applicable bool
	observed   bool
	conf       logic.Confidence
	evidence   []string
}

func evalWhen(w pack.WhenPackage, asset snapshot.Asset, eval time.Time, maxAge time.Duration) (whenResult, leafEval) {
	usable, observed, conf, reason := assess(observation{
		asset.Inventory.Basis, asset.Inventory.Confidence, asset.Inventory.ObservedAt, "",
	}, eval, maxAge)
	var matched []snapshot.Package
	var extras []snapshot.Package
	for _, pkg := range asset.Inventory.Packages {
		canon, err := purl.Canonical(pkg.PURL)
		if err != nil {
			return whenResult{}, unknownLeaf("", "malformed_purl", pkg.PURL, nil)
		}
		parsed, err := purl.Parse(canon)
		if err != nil {
			return whenResult{}, unknownLeaf("", "malformed_purl", pkg.PURL, nil)
		}
		if parsed.Version != "" && parsed.Version != pkg.Version {
			return whenResult{}, unknownLeaf("", "version_purl_mismatch", pkg.PURL, nil)
		}
		exact, related := classify(parsed, w.PurlPatterns)
		switch {
		case exact:
			matched = append(matched, pkg)
		case related:
			extras = append(extras, pkg)
		}
	}
	ev := []string{asset.Inventory.EvidenceID}
	if len(matched) == 0 && len(extras) > 0 {
		return whenResult{}, unknownLeaf("", "distro_advisory_required", extras[0].PURL, ev)
	}
	if !usable {
		return whenResult{}, unknownLeaf("", "when_package_unresolved", reason, ev)
	}
	if len(matched) == 0 {
		if !asset.Inventory.Complete || !observed {
			return whenResult{}, unknownLeaf("", "when_package_unresolved", "inventory", ev)
		}
		return whenResult{applicable: false, observed: true, conf: conf, evidence: ev}, leafEval{}
	}
	inRange := false
	for _, pkg := range matched {
		if purl.DistroType(mustType(pkg.PURL)) {
			return whenResult{}, unknownLeaf("", "distro_advisory_required", pkg.PURL, ev)
		}
		in, unknown := versionInRanges(w.VersionScheme, pkg.Version, w.AffectedRanges)
		if unknown {
			return whenResult{}, unknownLeaf("", "unsupported_version", pkg.Version, ev)
		}
		if in {
			inRange = true
		}
	}
	return whenResult{applicable: inRange, observed: observed, conf: conf, evidence: ev}, leafEval{}
}

func evalPackage(id string, ch pack.Check, component []string, asset snapshot.Asset, eval time.Time, maxAge time.Duration) leafEval {
	patterns := ch.PurlPatterns
	if len(patterns) == 0 {
		patterns = component
	}
	usable, observed, conf, reason := assess(observation{
		asset.Inventory.Basis, asset.Inventory.Confidence, asset.Inventory.ObservedAt, "",
	}, eval, maxAge)
	var matched []snapshot.Package
	var extras []snapshot.Package
	for _, pkg := range asset.Inventory.Packages {
		canon, err := purl.Canonical(pkg.PURL)
		if err != nil {
			return unknownLeaf(id, "malformed_purl", pkg.PURL, []string{asset.Inventory.EvidenceID})
		}
		parsed, err := purl.Parse(canon)
		if err != nil {
			return unknownLeaf(id, "malformed_purl", pkg.PURL, []string{asset.Inventory.EvidenceID})
		}
		if parsed.Version != "" && parsed.Version != pkg.Version {
			return unknownLeaf(id, "version_purl_mismatch", pkg.PURL, []string{asset.Inventory.EvidenceID})
		}
		exact, related := classify(parsed, patterns)
		switch {
		case exact:
			matched = append(matched, pkg)
		case related, advisoryNamesPackage(asset, ch.AdvisoryFact, pkg.PURL):
			// A case, white-space, or separator variant of the component
			// name, the same name under another type or namespace, a
			// free-form alias, or a package an advisory for this CVE names.
			// Absence is not proven, and the version is never sorted.
			extras = append(extras, pkg)
		}
	}
	var fact *snapshot.Fact
	if ch.AdvisoryFact != "" {
		fact = findFact(asset, ch.AdvisoryFact)
	}
	ev := []string{asset.Inventory.EvidenceID}
	if len(matched) == 0 && len(extras) == 0 {
		if fact != nil {
			return applyAdvisory(id, ch, fact, nil, usable, observed, conf, reason, asset, eval, maxAge)
		}
		if orphan := orphanAdvisory(asset, ch.AdvisoryFact); orphan != nil {
			return unknownLeaf(id, "advisory_without_package", ch.AdvisoryFact, append(ev, orphan.EvidenceID))
		}
		if !asset.Inventory.Complete {
			return unknownLeaf(id, "inventory_incomplete", "", ev)
		}
		if !usable || !observed {
			why := reason
			if why == "" {
				why = "inventory_not_observed"
			}
			return unknownLeaf(id, why, "", ev)
		}
		weak := ""
		if conf < logic.ConfHigh {
			weak = "confidence_below_not_affected_bar"
		}
		return valueLeaf(id, logic.False, conf, true, ch.AbsenceJustification, ev, weak, "")
	}
	if !usable {
		return unknownLeaf(id, reason, "", ev)
	}
	var upstream []snapshot.Package
	var distro []snapshot.Package
	for _, pkg := range matched {
		if purl.DistroType(mustType(pkg.PURL)) {
			distro = append(distro, pkg)
			continue
		}
		upstream = append(upstream, pkg)
	}
	sawUnknown := false
	for _, pkg := range upstream {
		in, unknown := versionInRanges(ch.VersionScheme, pkg.Version, ch.AffectedRanges)
		if unknown {
			sawUnknown = true
			continue
		}
		if in {
			// An in-range non-distro package is vulnerable on its own.
			// A fixed advisory for a distro build on the same asset does not clear it.
			weak := ""
			if !observed {
				weak = "evidence_not_observed"
			}
			return valueLeaf(id, logic.True, conf, observed, ch.NegationJustification, ev, weak, "")
		}
	}
	needsAdvisory := len(distro) > 0 || len(extras) > 0
	if needsAdvisory {
		return resolveDistroAdvisories(id, ch, distro, extras, sawUnknown, usable, observed, conf, reason, asset, eval, maxAge)
	}
	if sawUnknown {
		return unknownLeaf(id, "unsupported_version", "", ev)
	}
	weak := ""
	if !observed {
		weak = "evidence_not_observed"
	} else if conf < logic.ConfHigh {
		weak = "confidence_below_not_affected_bar"
	}
	return valueLeaf(id, logic.False, conf, observed, ch.NegationJustification, ev, weak, "")
}

func resolveDistroAdvisories(id string, ch pack.Check, distro, extras []snapshot.Package, sawUnknown, invUsable, invObserved bool, invConf logic.Confidence, invReason string, asset snapshot.Asset, eval time.Time, maxAge time.Duration) leafEval {
	subjects := append(append([]snapshot.Package{}, distro...), extras...)
	ev := []string{asset.Inventory.EvidenceID}
	if !invUsable {
		return unknownLeaf(id, invReason, ch.AdvisoryFact, ev)
	}
	anyTrue := false
	allFalse := true
	useConf := invConf
	allObserved := invObserved
	unknownReason, unknownDetail := "", ""
	note := func(reason, detail string) {
		allFalse = false
		if unknownReason == "" {
			unknownReason = reason
			unknownDetail = detail
		}
	}
	for _, pkg := range subjects {
		exact, variants := findAdvisories(asset, ch.AdvisoryFact, pkg.PURL)
		if len(exact) == 0 && len(variants) == 0 {
			if bare := findFact(asset, ch.AdvisoryFact); bare != nil {
				note("advisory_purl_required", ch.AdvisoryFact)
			} else {
				note("distro_advisory_required", pkg.PURL)
			}
			continue
		}
		all := append(append([]*snapshot.Fact{}, exact...), variants...)
		for _, f := range all {
			ev = append(ev, f.EvidenceID)
		}
		// Every spelling of this package URL is considered, so the result
		// does not depend on fact order. Disagreement is unknown.
		conflict := false
		for _, f := range all[1:] {
			if f.Value != all[0].Value {
				conflict = true
				break
			}
		}
		if conflict {
			note("conflicting_advisory", pkg.PURL)
			continue
		}
		if len(exact) == 0 {
			note("advisory_purl_variant", pkg.PURL)
			continue
		}
		bad := false
		for _, f := range exact {
			usable, observed, conf, reason := assess(observation{f.Basis, f.Confidence, f.ObservedAt, f.ExpiresAt}, eval, maxAge)
			if !usable || !observed {
				why := reason
				if why == "" {
					why = "advisory_not_observed"
				}
				note(why, pkg.PURL)
				bad = true
				break
			}
			if conf < useConf {
				useConf = conf
			}
		}
		if bad {
			continue
		}
		switch exact[0].Value {
		case "affected":
			anyTrue = true
		case "fixed", "not_affected":
		default:
			note("unexpected_advisory_value", ch.AdvisoryFact)
		}
	}
	ev = uniq(ev)
	if anyTrue {
		weak := ""
		if !allObserved {
			weak = "evidence_not_observed"
		}
		return valueLeaf(id, logic.True, useConf, allObserved, ch.NegationJustification, ev, weak, ch.AdvisoryFact)
	}
	if sawUnknown {
		return unknownLeaf(id, "unsupported_version", "", ev)
	}
	if !allFalse {
		return unknownLeaf(id, unknownReason, unknownDetail, ev)
	}
	weak := ""
	if !allObserved {
		weak = "evidence_not_observed"
	} else if useConf < logic.ConfHigh {
		weak = "confidence_below_not_affected_bar"
	}
	return valueLeaf(id, logic.False, useConf, allObserved, ch.NegationJustification, ev, weak, ch.AdvisoryFact)
}

func applyAdvisory(id string, ch pack.Check, fact *snapshot.Fact, matched []snapshot.Package, invUsable, invObserved bool, invConf logic.Confidence, invReason string, asset snapshot.Asset, eval time.Time, maxAge time.Duration) leafEval {
	usable, observed, conf, reason := assess(observation{fact.Basis, fact.Confidence, fact.ObservedAt, fact.ExpiresAt}, eval, maxAge)
	ev := []string{fact.EvidenceID, asset.Inventory.EvidenceID}
	if !usable || !observed {
		why := reason
		if why == "" {
			why = "advisory_not_observed"
		}
		return unknownLeaf(id, why, ch.AdvisoryFact, ev)
	}
	if len(matched) == 0 {
		return unknownLeaf(id, "advisory_without_package", ch.AdvisoryFact, ev)
	}
	if !invUsable {
		return unknownLeaf(id, invReason, ch.AdvisoryFact, ev)
	}
	useConf := conf
	if invConf < useConf {
		useConf = invConf
	}
	switch fact.Value {
	case "affected":
		weak := ""
		if !invObserved {
			weak = "evidence_not_observed"
		}
		return valueLeaf(id, logic.True, useConf, invObserved && observed, ch.NegationJustification, ev, weak, ch.AdvisoryFact)
	case "fixed", "not_affected":
		weak := ""
		if !invObserved {
			weak = "evidence_not_observed"
		} else if useConf < logic.ConfHigh {
			weak = "confidence_below_not_affected_bar"
		}
		return valueLeaf(id, logic.False, useConf, invObserved && observed, ch.NegationJustification, ev, weak, ch.AdvisoryFact)
	default:
		return unknownLeaf(id, "unexpected_advisory_value", ch.AdvisoryFact, ev)
	}
}

func versionInRanges(scheme, version string, ranges []string) (in bool, unknown bool) {
	for _, r := range ranges {
		ok, err := vercmp.InRange(scheme, version, r)
		if err != nil {
			return false, true
		}
		if ok {
			return true, false
		}
	}
	return false, false
}

func mustType(raw string) string {
	p, err := purl.Parse(raw)
	if err != nil {
		return ""
	}
	return p.Type
}

func nonEmpty(s []string) []string {
	if s == nil {
		return []string{}
	}
	return s
}

func sortedCheckIDs(p *pack.Pack) []string {
	ids := make([]string, 0, len(p.Checks))
	for id := range p.Checks {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	return ids
}

func uniq(in []string) []string {
	if len(in) == 0 {
		return []string{}
	}
	cp := append([]string{}, in...)
	sort.Strings(cp)
	out := []string{cp[0]}
	for _, s := range cp[1:] {
		if s != out[len(out)-1] {
			out = append(out, s)
		}
	}
	return out
}
