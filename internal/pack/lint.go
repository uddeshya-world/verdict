// Copyright 2026 Uddeshya Kumar
// SPDX-License-Identifier: Apache-2.0

package pack

import (
	"fmt"
	"net/url"
	"regexp"
	"sort"
	"strings"
	"time"

	"github.com/uddeshya-world/verdict/internal/vercmp"
)

var (
	idRE      = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$`)
	checkIDRE = regexp.MustCompile(`^[A-Za-z][A-Za-z0-9_]{0,63}$`)
	cveRE     = regexp.MustCompile(`^CVE-[0-9]{4}-[0-9]{4,}$`)
	procRE    = regexp.MustCompile(`^[a-z][a-z0-9_-]{0,31}$`)
	factKeyRE = regexp.MustCompile(`^[A-Za-z0-9_./:-]{1,200}$`)
)

// Lint checks structural and semantic rules. It does not fetch source URLs.
func Lint(p *Pack) error {
	var errs []string
	add := func(f string, args ...any) {
		errs = append(errs, fmt.Sprintf(f, args...))
	}
	if p.APIVersion != "verdict.dev/v1" {
		add("apiVersion must be verdict.dev/v1")
	}
	if p.Kind != "ConditionPack" {
		add("kind must be ConditionPack")
	}
	lintMeta(p, add)
	if len(p.Component.Purls) == 0 {
		add("component.purls must not be empty")
	}
	for _, pattern := range p.Component.Purls {
		if err := lintPurlPattern(pattern); err != nil {
			add("component purl %q: %v", pattern, err)
		}
	}
	if len(p.Checks) == 0 {
		add("checks must not be empty")
	}
	if len(p.Checks) > 64 {
		add("checks exceed 64")
	}
	ids := make([]string, 0, len(p.Checks))
	for id, ch := range p.Checks {
		ids = append(ids, id)
		if !checkIDRE.MatchString(id) {
			add("check id %q is not a safe identifier", id)
		}
		if err := lintCheck(id, ch, p.Component.Purls); err != nil {
			add("%v", err)
		}
	}
	sort.Strings(ids)
	nodes := 0
	if err := lintCond(p.Conditions, 1, &nodes, p.Checks); err != nil {
		add("%v", err)
	}
	if nodes > 64 {
		add("condition tree exceeds 64 nodes")
	}
	if err := lintNegation(p.Conditions, 0, p.Checks); err != nil {
		add("%v", err)
	}
	if p.Exposure.Port < 1 || p.Exposure.Port > 65535 {
		add("exposure.port must be 1-65535")
	}
	if p.Exposure.Proto != "tcp" && p.Exposure.Proto != "udp" {
		add("exposure.proto must be tcp or udp")
	}
	if len(p.Exposure.UntrustedZones) == 0 {
		add("exposure.untrusted_zones must not be empty")
	}
	if len(p.Exposure.TrustedZones) == 0 {
		add("exposure.trusted_zones must not be empty")
	}
	lintZoneList("untrusted_zones", p.Exposure.UntrustedZones, add)
	lintZoneList("trusted_zones", p.Exposure.TrustedZones, add)
	seenZone := map[string]string{}
	for _, z := range p.Exposure.UntrustedZones {
		seenZone[strings.ToLower(z)] = "untrusted_zones"
	}
	for _, z := range p.Exposure.TrustedZones {
		key := strings.ToLower(z)
		if prev, ok := seenZone[key]; ok && prev != "trusted_zones" {
			add("exposure zone %q is listed as both trusted and untrusted", z)
		}
	}
	if strings.TrimSpace(p.Remediation.Fix) == "" {
		add("remediation.fix must not be empty")
	}
	for _, tc := range p.Tests {
		if tc.Name == "" || tc.Snapshot == "" || tc.Asset == "" || tc.ExpectState == "" || tc.ExpectVEX == "" {
			add("test %q is missing name, snapshot, asset, expect_state, or expect_vex", tc.Name)
		}
		switch tc.ExpectState {
		case "exploitable", "vulnerable_not_exposed", "not_affected", "needs_review":
		default:
			add("test %q has unknown expect_state %q", tc.Name, tc.ExpectState)
		}
		switch tc.ExpectVEX {
		case "affected", "not_affected", "under_investigation":
		default:
			add("test %q has unknown expect_vex %q", tc.Name, tc.ExpectVEX)
		}
		if tc.ExpectState == "not_affected" && tc.ExpectJustification == "" {
			add("test %q expects not_affected without expect_justification", tc.Name)
		}
	}
	if p.Metadata.Status == "reviewed" && len(p.Tests) == 0 {
		add("reviewed packs must declare tests")
	}
	if len(errs) > 0 {
		return fmt.Errorf("pack lint:\n- %s", strings.Join(errs, "\n- "))
	}
	d, err := time.ParseDuration(p.Metadata.EvidenceMaxAge)
	if err != nil || d <= 0 {
		return fmt.Errorf("pack lint: evidence_max_age must be a positive duration")
	}
	p.MaxAge = d
	return nil
}

func lintMeta(p *Pack, add func(string, ...any)) {
	m := p.Metadata
	if !idRE.MatchString(m.ID) {
		add("metadata.id %q is invalid", m.ID)
	}
	if len(m.CVE) != 1 || !cveRE.MatchString(m.CVE[0]) {
		add("metadata.cve must contain exactly one CVE id")
	}
	if strings.TrimSpace(m.Title) == "" || strings.TrimSpace(m.Description) == "" {
		add("title and description are required")
	}
	switch m.Status {
	case "draft", "reviewed", "deprecated":
	default:
		add("status must be draft, reviewed, or deprecated")
	}
	switch m.ConfidenceCeiling {
	case "low", "medium", "high", "confirmed":
	default:
		add("confidence_ceiling must be low, medium, high, or confirmed")
	}
	if len(m.Authors) == 0 || strings.TrimSpace(m.Authors[0].Name) == "" {
		add("at least one author name is required")
	}
	if len(m.Limitations) == 0 {
		add("limitations must state at least one caveat")
	}
	if strings.TrimSpace(m.KBMinVersion) == "" {
		add("kb_min_version is required")
	}
	if _, err := time.ParseDuration(m.EvidenceMaxAge); err != nil {
		add("evidence_max_age: %v", err)
	}
	if m.Synthetic {
		if len(m.CVE) != 1 || !strings.HasPrefix(m.CVE[0], "CVE-2099-") {
			add("synthetic packs must use a CVE-2099-* id")
		}
	}
	if m.Status != "reviewed" && len(m.Reviewers) > 0 {
		add("reviewers must be empty unless status is reviewed")
	}
	seen := map[string]struct{}{}
	for _, r := range m.Reviewers {
		name := strings.TrimSpace(r.Name)
		if name == "" {
			add("reviewer name is empty")
			continue
		}
		key := strings.ToLower(name)
		if _, ok := seen[key]; ok {
			add("duplicate reviewer %q", name)
		}
		seen[key] = struct{}{}
		reserved := strings.HasPrefix(key, "synthetic-reviewer-")
		if m.Synthetic && !reserved {
			add("synthetic reviewed packs must use synthetic-reviewer-* names, got %q", name)
		}
		if !m.Synthetic && reserved {
			add("synthetic-reviewer-* names are reserved for synthetic packs")
		}
	}
	if m.Status == "reviewed" && len(seen) < 2 {
		add("reviewed packs need two distinct reviewers")
	}
	if len(m.Sources) == 0 {
		add("at least one source is required")
	}
	for _, s := range m.Sources {
		u, err := url.Parse(s.URL)
		if err != nil || u.Host == "" || (u.Scheme != "https" && u.Scheme != "http") {
			add("source url %q must be an http(s) URL", s.URL)
		}
	}
}

func lintCheck(id string, c Check, component []string) error {
	var errs []string
	add := func(f string, args ...any) {
		errs = append(errs, fmt.Sprintf(f, args...))
	}
	if _, ok := CheckTypes[c.Type]; !ok {
		add("check %s: unknown type %q", id, c.Type)
	}
	if _, ok := Justifications[c.NegationJustification]; !ok {
		add("check %s: negation_justification %q is not an OpenVEX label", id, c.NegationJustification)
	}
	if len(c.ResolutionHint) > 500 {
		add("check %s: resolution_hint is too long", id)
	}
	switch c.Type {
	case "package_version":
		if !vercmp.Known(c.VersionScheme) {
			add("check %s: version_scheme %q is not implemented", id, c.VersionScheme)
		}
		if len(c.AffectedRanges) == 0 {
			add("check %s: affected_ranges required", id)
		}
		for _, r := range c.AffectedRanges {
			if err := vercmp.ValidateRange(c.VersionScheme, r); err != nil {
				add("check %s: %v", id, err)
			}
		}
		if _, ok := Justifications[c.AbsenceJustification]; !ok {
			add("check %s: absence_justification required", id)
		}
		patterns := c.PurlPatterns
		if len(patterns) == 0 {
			patterns = component
		}
		if len(patterns) == 0 {
			add("check %s: purl patterns required", id)
		}
		for _, pattern := range patterns {
			if err := lintPurlPattern(pattern); err != nil {
				add("check %s: %v", id, err)
			}
		}
		if c.Key != "" || c.Equals != "" || c.Process != "" || c.Path != "" || c.WhenPackage != nil {
			add("check %s: package_version has fields it does not use", id)
		}
		if c.AdvisoryFact != "" && !factKeyRE.MatchString(c.AdvisoryFact) {
			add("check %s: advisory_fact key is invalid", id)
		}
	case "host_fact", "config_value", "env_var", "manual_attestation":
		if !factKeyRE.MatchString(c.Key) || c.Equals == "" {
			add("check %s: key and equals are required", id)
		}
		if c.VersionScheme != "" || len(c.AffectedRanges) != 0 || c.AdvisoryFact != "" || len(c.PurlPatterns) != 0 || c.Process != "" || c.Path != "" || c.AbsenceJustification != "" {
			add("check %s: inapplicable fields are set", id)
		}
		if c.Type == "manual_attestation" && c.WhenPackage != nil {
			add("check %s: manual_attestation cannot use when_package", id)
		}
		if err := lintWhen(id, c.WhenPackage); err != nil {
			add("%v", err)
		}
	case "process_listening", "process_running":
		if !procRE.MatchString(c.Process) {
			add("check %s: process name %q is invalid", id, c.Process)
		}
		if c.Key != "" || c.Equals != "" || c.Path != "" || c.VersionScheme != "" || len(c.AffectedRanges) != 0 || c.AdvisoryFact != "" || len(c.PurlPatterns) != 0 || c.AbsenceJustification != "" || c.WhenPackage != nil {
			add("check %s: inapplicable fields are set", id)
		}
	case "file_exists":
		if c.Path == "" || !strings.HasPrefix(c.Path, "/") || strings.ContainsAny(c.Path, "\n\r\t") {
			add("check %s: path must be an absolute path without whitespace", id)
		}
		if c.Key != "" || c.Equals != "" || c.Process != "" || c.VersionScheme != "" || len(c.AffectedRanges) != 0 || len(c.PurlPatterns) != 0 || c.AbsenceJustification != "" || c.WhenPackage != nil || c.AdvisoryFact != "" {
			add("check %s: inapplicable fields are set", id)
		}
	}
	if len(errs) > 0 {
		return fmt.Errorf("%s", strings.Join(errs, "; "))
	}
	return nil
}

func lintWhen(id string, w *WhenPackage) error {
	if w == nil {
		return nil
	}
	if !vercmp.Known(w.VersionScheme) {
		return fmt.Errorf("check %s: when_package scheme %q is not implemented", id, w.VersionScheme)
	}
	if len(w.PurlPatterns) == 0 || len(w.AffectedRanges) == 0 {
		return fmt.Errorf("check %s: when_package needs purl patterns and ranges", id)
	}
	for _, pattern := range w.PurlPatterns {
		if err := lintPurlPattern(pattern); err != nil {
			return fmt.Errorf("check %s: %w", id, err)
		}
	}
	for _, r := range w.AffectedRanges {
		if err := vercmp.ValidateRange(w.VersionScheme, r); err != nil {
			return fmt.Errorf("check %s: %w", id, err)
		}
	}
	return nil
}

func lintPurlPattern(pattern string) error {
	if strings.Contains(pattern, "@") || strings.Contains(pattern, "?") || strings.Contains(pattern, "#") {
		return fmt.Errorf("purl pattern %q must not include a version, qualifier, or subpath", pattern)
	}
	if !strings.HasPrefix(pattern, "pkg:") {
		return fmt.Errorf("purl pattern %q must start with pkg:", pattern)
	}
	rest := strings.TrimPrefix(pattern, "pkg:")
	typ, path, ok := strings.Cut(rest, "/")
	if !ok || typ == "" || path == "" || strings.Contains(path, " ") {
		return fmt.Errorf("purl pattern %q is malformed", pattern)
	}
	return nil
}

func lintCond(c Condition, depth int, nodes *int, checks map[string]Check) error {
	*nodes++
	if depth > 8 {
		return fmt.Errorf("condition nesting exceeds 8")
	}
	arms := 0
	if c.Ref != "" {
		arms++
	}
	if c.Not != nil {
		arms++
	}
	if len(c.AllOf) > 0 {
		arms++
	}
	if len(c.AnyOf) > 0 {
		arms++
	}
	if arms != 1 {
		return fmt.Errorf("condition node must set exactly one of ref, not, all_of, any_of")
	}
	if c.Ref != "" {
		if _, ok := checks[c.Ref]; !ok {
			return fmt.Errorf("condition ref %q does not match a check", c.Ref)
		}
		return nil
	}
	if c.Not != nil {
		return lintCond(*c.Not, depth+1, nodes, checks)
	}
	kids := c.AllOf
	if len(c.AnyOf) > 0 {
		kids = c.AnyOf
	}
	for _, k := range kids {
		if err := lintCond(k, depth+1, nodes, checks); err != nil {
			return err
		}
	}
	return nil
}

func lintNegation(c Condition, neg int, checks map[string]Check) error {
	if c.Ref != "" {
		ch := checks[c.Ref]
		if ch.WhenPackage != nil && neg%2 == 0 {
			return fmt.Errorf("check %s uses when_package and must appear under a not, so an inapplicable predicate cannot falsify the tree", c.Ref)
		}
		return nil
	}
	if c.Not != nil {
		return lintNegation(*c.Not, neg+1, checks)
	}
	kids := c.AllOf
	if len(c.AnyOf) > 0 {
		kids = c.AnyOf
	}
	for _, k := range kids {
		if err := lintNegation(k, neg, checks); err != nil {
			return err
		}
	}
	return nil
}

// DistinctReviewers counts reviewer names case-insensitively.
func lintZoneList(name string, zones []string, add func(string, ...any)) {
	seen := map[string]struct{}{}
	for _, z := range zones {
		key := strings.ToLower(z)
		if z == "" || key == "unknown" || strings.TrimSpace(z) != z {
			add("exposure.%s zone %q is not a concrete zone", name, z)
		}
		if _, ok := seen[key]; ok {
			add("exposure.%s has duplicate zone %q", name, z)
		}
		seen[key] = struct{}{}
	}
}

func DistinctReviewers(p *Pack) int {
	seen := map[string]struct{}{}
	for _, r := range p.Metadata.Reviewers {
		n := strings.ToLower(strings.TrimSpace(r.Name))
		if n == "" {
			continue
		}
		seen[n] = struct{}{}
	}
	return len(seen)
}
