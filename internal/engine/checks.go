// Copyright 2026 Uddeshya Kumar
// SPDX-License-Identifier: Apache-2.0

package engine

import (
	"sort"
	"strings"
	"time"

	"github.com/uddeshya-world/verdict/internal/factkeys"
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
		return false, false, logic.ConfNone, ReasonUnreadableTime
	}
	if ts.After(eval) {
		return false, false, logic.ConfNone, ReasonEvidenceTimeAfterEvaluation
	}
	if eval.Sub(ts) > maxAge {
		return false, false, logic.ConfNone, ReasonStaleEvidence
	}
	if o.ExpiresAt != "" {
		exp, err := time.Parse(time.RFC3339, o.ExpiresAt)
		if err != nil {
			return false, false, logic.ConfNone, ReasonUnreadableTime
		}
		if !exp.After(eval) {
			return false, false, logic.ConfNone, ReasonExpiredEvidence
		}
	}
	conf, ok := logic.ParseConfidence(o.Confidence)
	if !ok {
		return false, false, logic.ConfNone, ReasonUnreadableConfidence
	}
	switch o.Basis {
	case "inferred":
		return false, false, logic.ConfNone, ReasonInferredEvidenceDiscarded
	case "attested":
		return true, false, conf, ""
	case "observed":
		return true, true, conf, ""
	default:
		return false, false, logic.ConfNone, ReasonBasisNotUsable
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

func foldKey(k string) string { return strings.ToLower(strings.TrimSpace(k)) }

// foldedKeyFact returns a fact whose key differs from key only by case or
// surrounding white space. Such a fact is not the fact the pack asked for, and
// the leaf must be unknown rather than missing or falsified.
func foldedKeyFact(asset snapshot.Asset, key string) *snapshot.Fact {
	fk := foldKey(key)
	for i := range asset.Facts {
		f := &asset.Facts[i]
		if f.PURL == "" && f.Key != key && foldKey(f.Key) == fk {
			return f
		}
	}
	return nil
}

// findAdvisories returns every advisory fact for key whose purl is the
// package's purl. exact facts have the same canonical form; variants differ
// only by case, white space, or separators in the name (FoldKey). Every
// match is returned so the caller can be independent of fact order.
func findAdvisories(ac *assetCtx, key, packagePURL string) (exact, variants []*snapshot.Fact) {
	if key == "" || packagePURL == "" {
		return nil, nil
	}
	return ac.findAdvisories(key, ac.ec.info(packagePURL))
}

// advisoryNamesPackage reports whether any purl-scoped advisory fact for key
// names this inventory package, under any spelling.
func advisoryNamesPackage(ac *assetCtx, key, packagePURL string) bool {
	exact, variants := findAdvisories(ac, key, packagePURL)
	return len(exact)+len(variants) > 0
}

// orphanAdvisory returns a purl-scoped advisory fact for key that names no
// inventory package. With a complete inventory that is a contradiction, so
// it blocks the absence proof.
func orphanAdvisory(ac *assetCtx, key string) *snapshot.Fact {
	if key == "" {
		return nil
	}
	ix := ac.advIndex(key)
	if len(ix.facts) == 0 {
		return nil
	}
	if ac.named == nil {
		ac.named = map[string]struct{}{}
		for _, pkg := range ac.packages() {
			ac.named[pkg.info.fold] = struct{}{}
		}
	}
	for i, f := range ix.facts {
		if _, named := ac.named[ix.infos[i].fold]; !named {
			return f
		}
	}
	return nil
}

// classify sorts one inventory package against the pack patterns.
// exact: canonical type, namespace, and name match a pattern.
// related: anything purl.Related says could be the component.
func classify(subj *purl.Subject, patterns []*purl.Pattern) (exact, related bool) {
	for _, pattern := range patterns {
		if pattern.Match(subj.P) {
			return true, false
		}
	}
	if len(patterns) > 0 && subj.NonASCII() {
		// A name with a rune the skeleton table does not map could be a
		// disguised spelling of anything. It is never absent.
		return false, true
	}
	for _, pattern := range patterns {
		if pattern.Related(subj) {
			return false, true
		}
	}
	return false, false
}

// aliasHit reports whether a package that is not an exact component match
// is the pack's declared alias, by exact match or by purl.Related. It can
// only move a package into the unknown set; it never matches a component.
func aliasHit(subj *purl.Subject, aliases []*purl.Pattern) bool {
	for _, a := range aliases {
		if a.Match(subj.P) || a.Related(subj) {
			return true
		}
	}
	return false
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
		Stale:  reason == ReasonStaleEvidence || reason == ReasonExpiredEvidence,
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

func evalChecks(p *pack.Pack, ac *assetCtx, eval time.Time) []leafEval {
	ids := sortedCheckIDs(p)
	out := make([]leafEval, 0, len(ids))
	for _, id := range ids {
		out = append(out, evalCheck(id, p.Checks[id], p.Component.Purls, ac, eval, p.MaxAge))
	}
	return out
}

func evalCheck(id string, ch pack.Check, component []string, ac *assetCtx, eval time.Time, maxAge time.Duration) leafEval {
	asset := ac.asset
	switch ch.Type {
	case "package_version":
		return evalPackageCtx(id, ch, component, ac, eval, maxAge)
	case "process_listening":
		return evalBoolFact(id, ch, "process.listening."+ch.Process, asset, eval, maxAge)
	case "process_running":
		return evalBoolFact(id, ch, "process.running."+ch.Process, asset, eval, maxAge)
	case "file_exists":
		return evalBoolFact(id, ch, "file.exists."+ch.Path, asset, eval, maxAge)
	case "manual_attestation":
		return evalEquals(id, ch, ch.Key, true, ac, eval, maxAge)
	default:
		return evalEquals(id, ch, ch.Key, false, ac, eval, maxAge)
	}
}

func evalBoolFact(id string, ch pack.Check, key string, asset snapshot.Asset, eval time.Time, maxAge time.Duration) leafEval {
	fact := findFact(asset, key)
	if fact == nil {
		if v := foldedKeyFact(asset, key); v != nil {
			return unknownLeaf(id, ReasonFactKeyNotCanonical, key, []string{v.EvidenceID})
		}
		return unknownLeaf(id, ReasonMissingFact, key, nil)
	}
	usable, observed, conf, reason := assess(observation{fact.Basis, fact.Confidence, fact.ObservedAt, fact.ExpiresAt}, eval, maxAge)
	if !usable {
		return unknownLeaf(id, reason, key, []string{fact.EvidenceID})
	}
	switch fact.Value {
	case "true", "false":
	default:
		return unknownLeaf(id, ReasonUnexpectedFactValue, key, []string{fact.EvidenceID})
	}
	value := logic.False
	if fact.Value == "true" {
		value = logic.True
	}
	weak := ""
	if !observed {
		weak = ReasonEvidenceNotObserved
	} else if value == logic.False && conf < logic.ConfHigh {
		weak = ReasonConfidenceBelowNotAffectedBar
	}
	return valueLeaf(id, value, conf, observed, ch.NegationJustification, []string{fact.EvidenceID}, weak, key)
}

func evalEquals(id string, ch pack.Check, key string, requireExpiry bool, ac *assetCtx, eval time.Time, maxAge time.Duration) leafEval {
	asset := ac.asset
	if ch.WhenPackage != nil {
		gate, gerr := evalWhen(*ch.WhenPackage, ac, eval, maxAge)
		if gerr.Reason != "" {
			gerr.ID = id
			return gerr
		}
		if !gate.applicable {
			weak := ReasonWhenPackageNotApplicable
			if !gate.observed {
				weak = ReasonEvidenceNotObserved
			} else if gate.conf < logic.ConfHigh {
				weak = ReasonConfidenceBelowNotAffectedBar
			}
			return valueLeaf(id, logic.False, gate.conf, gate.observed, ch.NegationJustification, gate.evidence, weak, key)
		}
	}
	fact := findFact(asset, key)
	if fact == nil {
		if v := foldedKeyFact(asset, key); v != nil {
			return unknownLeaf(id, ReasonFactKeyNotCanonical, key, []string{v.EvidenceID})
		}
		return unknownLeaf(id, ReasonMissingFact, key, nil)
	}
	if requireExpiry && fact.ExpiresAt == "" {
		return unknownLeaf(id, ReasonAttestationMissingExpiry, key, []string{fact.EvidenceID})
	}
	usable, observed, conf, reason := assess(observation{fact.Basis, fact.Confidence, fact.ObservedAt, fact.ExpiresAt}, eval, maxAge)
	if !usable {
		return unknownLeaf(id, reason, key, []string{fact.EvidenceID})
	}
	value := logic.False
	if fact.Value == ch.Equals {
		value = logic.True
	} else {
		a, e := fact.Value, ch.Equals
		switch {
		case strings.EqualFold(strings.TrimSpace(a), strings.TrimSpace(e)):
			return unknownLeaf(id, ReasonFactValueNotCanonical, key, []string{fact.EvidenceID})
		case (e == "true" || e == "false") && a != "true" && a != "false":
			return unknownLeaf(id, ReasonFactValueNotBoolean, key, []string{fact.EvidenceID})
		}
		if ok, known := factkeys.InDomain(key, a); known && !ok {
			return unknownLeaf(id, ReasonFactValueOutOfDomain, key, []string{fact.EvidenceID})
		}
	}
	weak := ""
	if !observed {
		weak = ReasonEvidenceNotObserved
	} else if value == logic.False && conf < logic.ConfHigh {
		weak = ReasonConfidenceBelowNotAffectedBar
	}
	return valueLeaf(id, value, conf, observed, ch.NegationJustification, []string{fact.EvidenceID}, weak, key)
}

type whenResult struct {
	applicable bool
	observed   bool
	conf       logic.Confidence
	evidence   []string
}

func evalWhen(w pack.WhenPackage, ac *assetCtx, eval time.Time, maxAge time.Duration) (whenResult, leafEval) {
	asset := ac.asset
	patterns := ac.ec.patterns(w.PurlPatterns)
	usable, observed, conf, reason := assess(observation{
		asset.Inventory.Basis, asset.Inventory.Confidence, asset.Inventory.ObservedAt, "",
	}, eval, maxAge)
	var matched []snapshot.Package
	var extras []snapshot.Package
	for _, pkg := range ac.packages() {
		pi := pkg.info
		if pi.canonErr || pi.parseErr {
			return whenResult{}, unknownLeaf("", ReasonMalformedPURL, pkg.PURL, nil)
		}
		if pi.parsed.Version != "" && pi.parsed.Version != pkg.Version {
			return whenResult{}, unknownLeaf("", ReasonVersionPURLMismatch, pkg.PURL, nil)
		}
		exact, related := classify(&pi.subj, patterns)
		switch {
		case exact:
			matched = append(matched, pkg.Package)
		case related:
			extras = append(extras, pkg.Package)
		}
	}
	for _, pkg := range matched {
		conf = pkgConf(conf, pkg)
	}
	ev := []string{asset.Inventory.EvidenceID}
	if len(matched) == 0 && len(extras) > 0 {
		return whenResult{}, unknownLeaf("", ReasonDistroAdvisoryRequired, extras[0].PURL, ev)
	}
	if !usable {
		return whenResult{}, unknownLeaf("", ReasonWhenPackageUnresolved, reason, ev)
	}
	if len(matched) == 0 {
		if !asset.Inventory.Complete || !observed {
			return whenResult{}, unknownLeaf("", ReasonWhenPackageUnresolved, "inventory", ev)
		}
		return whenResult{applicable: false, observed: true, conf: conf, evidence: ev}, leafEval{}
	}
	inRange := false
	for _, pkg := range matched {
		if ac.ec.info(pkg.PURL).rawIsDist {
			return whenResult{}, unknownLeaf("", ReasonDistroAdvisoryRequired, pkg.PURL, ev)
		}
		in, unknown := versionInRanges(w.VersionScheme, pkg.Version, w.AffectedRanges)
		if unknown {
			return whenResult{}, unknownLeaf("", ReasonUnsupportedVersion, pkg.Version, ev)
		}
		if in {
			inRange = true
		}
	}
	return whenResult{applicable: inRange, observed: observed, conf: conf, evidence: ev}, leafEval{}
}

func evalPackage(id string, ch pack.Check, component []string, asset snapshot.Asset, eval time.Time, maxAge time.Duration) leafEval {
	return evalPackageCtx(id, ch, component, newAssetCtx(newEvalCtx(), asset), eval, maxAge)
}

func evalPackageCtx(id string, ch pack.Check, component []string, ac *assetCtx, eval time.Time, maxAge time.Duration) leafEval {
	asset := ac.asset
	patternList := ch.PurlPatterns
	if len(patternList) == 0 {
		patternList = component
	}
	patterns := ac.ec.patterns(patternList)
	aliases := ac.ec.patterns(ch.Aliases)
	usable, observed, conf, reason := assess(observation{
		asset.Inventory.Basis, asset.Inventory.Confidence, asset.Inventory.ObservedAt, "",
	}, eval, maxAge)
	var matched []snapshot.Package
	var extras []snapshot.Package
	for _, pkg := range ac.packages() {
		pi := pkg.info
		if pi.canonErr || pi.parseErr {
			return unknownLeaf(id, ReasonMalformedPURL, pkg.PURL, []string{asset.Inventory.EvidenceID})
		}
		if pi.parsed.Version != "" && pi.parsed.Version != pkg.Version {
			return unknownLeaf(id, ReasonVersionPURLMismatch, pkg.PURL, []string{asset.Inventory.EvidenceID})
		}
		exact, related := classify(&pi.subj, patterns)
		switch {
		case exact:
			matched = append(matched, pkg.Package)
		case related, aliasHit(&pi.subj, aliases), advisoryNamesPackage(ac, ch.AdvisoryFact, pkg.PURL):
			// A case, white-space, or separator variant of the component
			// name, the same name under another type or namespace, a
			// free-form alias, or a package an advisory for this CVE names.
			// Absence is not proven, and the version is never sorted.
			extras = append(extras, pkg.Package)
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
		if orphan := orphanAdvisory(ac, ch.AdvisoryFact); orphan != nil {
			return unknownLeaf(id, ReasonAdvisoryWithoutPackage, ch.AdvisoryFact, append(ev, orphan.EvidenceID))
		}
		if !asset.Inventory.Complete {
			return unknownLeaf(id, ReasonInventoryIncomplete, "", ev)
		}
		if !usable || !observed {
			why := reason
			if why == "" {
				why = ReasonInventoryNotObserved
			}
			return unknownLeaf(id, why, "", ev)
		}
		for _, key := range ch.AbsenceContradictedBy {
			for i := range asset.Facts {
				f := &asset.Facts[i]
				// Any spelling of the key, scoped or not, on any basis or age,
				// with any value other than exactly "false" says the component
				// may run here. Contradiction is fail-safe.
				if f.Key != key && foldKey(f.Key) != foldKey(key) {
					continue
				}
				if f.Value == "false" {
					// Only the canonical value clears; " False " or "FALSE"
					// is not a value the collector writes, so it blocks.
					continue
				}
				return unknownLeaf(id, ReasonComponentAbsentButInUse, key, append(ev, f.EvidenceID))
			}
		}
		weak := ""
		if conf < logic.ConfHigh {
			weak = ReasonConfidenceBelowNotAffectedBar
		}
		return valueLeaf(id, logic.False, conf, true, ch.AbsenceJustification, ev, weak, "")
	}
	if !usable {
		return unknownLeaf(id, reason, "", ev)
	}
	// From here a package is present. A per-package confidence (a version
	// read from a binary banner) lowers every result but an in-range true,
	// which uses that package's own confidence.
	setConf := conf
	for _, pkg := range matched {
		setConf = pkgConf(setConf, pkg)
	}
	for _, pkg := range extras {
		setConf = pkgConf(setConf, pkg)
	}
	var upstream []snapshot.Package
	var distro []snapshot.Package
	for _, pkg := range matched {
		if ac.ec.info(pkg.PURL).rawIsDist {
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
				weak = ReasonEvidenceNotObserved
			}
			return valueLeaf(id, logic.True, pkgConf(conf, pkg), observed, ch.NegationJustification, ev, weak, "")
		}
	}
	needsAdvisory := len(distro) > 0 || len(extras) > 0
	if needsAdvisory {
		return resolveDistroAdvisories(id, ch, distro, extras, sawUnknown, usable, observed, setConf, reason, ac, eval, maxAge)
	}
	if sawUnknown {
		return unknownLeaf(id, ReasonUnsupportedVersion, "", ev)
	}
	weak := ""
	if !observed {
		weak = ReasonEvidenceNotObserved
	} else if setConf < logic.ConfHigh {
		weak = ReasonConfidenceBelowNotAffectedBar
	}
	return valueLeaf(id, logic.False, setConf, observed, ch.NegationJustification, ev, weak, "")
}

// pkgConf is the lower of c and the package's own confidence. An empty
// package confidence leaves c; an unreadable one is none, never higher.
func pkgConf(c logic.Confidence, p snapshot.Package) logic.Confidence {
	if p.Confidence == "" {
		return c
	}
	pc, ok := logic.ParseConfidence(p.Confidence)
	if !ok {
		return logic.ConfNone
	}
	return logic.Min(c, pc)
}

func resolveDistroAdvisories(id string, ch pack.Check, distro, extras []snapshot.Package, sawUnknown, invUsable, invObserved bool, invConf logic.Confidence, invReason string, ac *assetCtx, eval time.Time, maxAge time.Duration) leafEval {
	asset := ac.asset
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
		exact, variants := findAdvisories(ac, ch.AdvisoryFact, pkg.PURL)
		if len(exact) == 0 && len(variants) == 0 {
			if bare := findFact(asset, ch.AdvisoryFact); bare != nil {
				note(ReasonAdvisoryPURLRequired, ch.AdvisoryFact)
			} else {
				note(ReasonDistroAdvisoryRequired, pkg.PURL)
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
			note(ReasonConflictingAdvisory, pkg.PURL)
			continue
		}
		if len(exact) == 0 {
			note(ReasonAdvisoryPURLVariant, pkg.PURL)
			continue
		}
		bad := false
		for _, f := range exact {
			usable, observed, conf, reason := assess(observation{f.Basis, f.Confidence, f.ObservedAt, f.ExpiresAt}, eval, maxAge)
			if !usable || !observed {
				why := reason
				if why == "" {
					why = ReasonAdvisoryNotObserved
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
			note(ReasonUnexpectedAdvisoryValue, ch.AdvisoryFact)
		}
	}
	ev = uniq(ev)
	if anyTrue {
		weak := ""
		if !allObserved {
			weak = ReasonEvidenceNotObserved
		}
		return valueLeaf(id, logic.True, useConf, allObserved, ch.NegationJustification, ev, weak, ch.AdvisoryFact)
	}
	if sawUnknown {
		return unknownLeaf(id, ReasonUnsupportedVersion, "", ev)
	}
	if !allFalse {
		return unknownLeaf(id, unknownReason, unknownDetail, ev)
	}
	weak := ""
	if !allObserved {
		weak = ReasonEvidenceNotObserved
	} else if useConf < logic.ConfHigh {
		weak = ReasonConfidenceBelowNotAffectedBar
	}
	return valueLeaf(id, logic.False, useConf, allObserved, ch.NegationJustification, ev, weak, ch.AdvisoryFact)
}

func applyAdvisory(id string, ch pack.Check, fact *snapshot.Fact, matched []snapshot.Package, invUsable, invObserved bool, invConf logic.Confidence, invReason string, asset snapshot.Asset, eval time.Time, maxAge time.Duration) leafEval {
	usable, observed, conf, reason := assess(observation{fact.Basis, fact.Confidence, fact.ObservedAt, fact.ExpiresAt}, eval, maxAge)
	ev := []string{fact.EvidenceID, asset.Inventory.EvidenceID}
	if !usable || !observed {
		why := reason
		if why == "" {
			why = ReasonAdvisoryNotObserved
		}
		return unknownLeaf(id, why, ch.AdvisoryFact, ev)
	}
	if len(matched) == 0 {
		return unknownLeaf(id, ReasonAdvisoryWithoutPackage, ch.AdvisoryFact, ev)
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
			weak = ReasonEvidenceNotObserved
		}
		return valueLeaf(id, logic.True, useConf, invObserved && observed, ch.NegationJustification, ev, weak, ch.AdvisoryFact)
	case "fixed", "not_affected":
		weak := ""
		if !invObserved {
			weak = ReasonEvidenceNotObserved
		} else if useConf < logic.ConfHigh {
			weak = ReasonConfidenceBelowNotAffectedBar
		}
		return valueLeaf(id, logic.False, useConf, invObserved && observed, ch.NegationJustification, ev, weak, ch.AdvisoryFact)
	default:
		return unknownLeaf(id, ReasonUnexpectedAdvisoryValue, ch.AdvisoryFact, ev)
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
