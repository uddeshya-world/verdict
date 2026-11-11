// Copyright 2026 Uddeshya Kumar
// SPDX-License-Identifier: Apache-2.0

// Package osv turns local OSV records into a version-only fallback pack.
//
// The fallback answers "which assets carry a package version OSV lists as
// affected" when no condition pack exists for a CVE. It is always a draft
// with a low confidence ceiling, so the engine cannot emit not_affected from
// it. An out-of-range or absent package is needs_review, never a clear.
// Nothing here reads the network; the records are files the operator carried in.
package osv

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"regexp"
	"sort"
	"strings"

	"github.com/uddeshya-world/verdict/internal/pack"
	"github.com/uddeshya-world/verdict/internal/purl"
	"github.com/uddeshya-world/verdict/internal/vercmp"
)

// MaxBytes is the largest OSV document accepted.
const MaxBytes = 4 * 1024 * 1024

var cveRE = regexp.MustCompile(`^CVE-[0-9]{4}-[0-9]{4,}$`)

// Record is the subset of the OSV schema the fallback reads.
type Record struct {
	ID        string     `json:"id"`
	Aliases   []string   `json:"aliases"`
	Summary   string     `json:"summary"`
	Details   string     `json:"details"`
	Withdrawn string     `json:"withdrawn"`
	Affected  []Affected `json:"affected"`
}

// Affected is one package entry.
type Affected struct {
	Package  Package  `json:"package"`
	Ranges   []Range  `json:"ranges"`
	Versions []string `json:"versions"`
}

// Package names an ecosystem package.
type Package struct {
	Ecosystem string `json:"ecosystem"`
	Name      string `json:"name"`
	PURL      string `json:"purl"`
}

// Range is an OSV range with ordered events.
type Range struct {
	Type   string  `json:"type"`
	Events []Event `json:"events"`
}

// Event is one introduced, fixed, last_affected, or limit marker.
type Event struct {
	Introduced   string `json:"introduced"`
	Fixed        string `json:"fixed"`
	LastAffected string `json:"last_affected"`
	Limit        string `json:"limit"`
}

// Parse reads one OSV record or a JSON array of records.
func Parse(data []byte) ([]Record, error) {
	if len(data) == 0 {
		return nil, fmt.Errorf("osv: empty document")
	}
	if len(data) > MaxBytes {
		return nil, fmt.Errorf("osv: document exceeds %d bytes", MaxBytes)
	}
	trimmed := bytes.TrimSpace(data)
	var recs []Record
	if len(trimmed) > 0 && trimmed[0] == '[' {
		if err := json.Unmarshal(trimmed, &recs); err != nil {
			return nil, fmt.Errorf("osv: %w", err)
		}
	} else {
		var r Record
		if err := json.Unmarshal(trimmed, &r); err != nil {
			return nil, fmt.Errorf("osv: %w", err)
		}
		recs = []Record{r}
	}
	for _, r := range recs {
		if r.ID == "" {
			return nil, fmt.Errorf("osv: record without id")
		}
	}
	return recs, nil
}

// Names reports whether the record is about the CVE (id or alias).
func Names(r Record, cve string) bool {
	if r.ID == cve {
		return true
	}
	for _, a := range r.Aliases {
		if a == cve {
			return true
		}
	}
	return false
}

// CVEOf returns the single CVE the records name, or an error if it is ambiguous.
func CVEOf(recs []Record) (string, error) {
	seen := map[string]struct{}{}
	for _, r := range recs {
		for _, id := range append([]string{r.ID}, r.Aliases...) {
			if cveRE.MatchString(id) {
				seen[id] = struct{}{}
			}
		}
	}
	if len(seen) != 1 {
		ids := make([]string, 0, len(seen))
		for id := range seen {
			ids = append(ids, id)
		}
		sort.Strings(ids)
		return "", fmt.Errorf("osv: records name %d CVE ids %v; pass --cve", len(seen), ids)
	}
	for id := range seen {
		return id, nil
	}
	return "", nil
}

// ecosystem maps an OSV ecosystem to a purl type and version scheme.
// Ecosystems without an implemented comparator are reported as skipped.
type ecosystem struct {
	purlType string
	scheme   string
	goPrefix bool
}

var ecosystems = map[string]ecosystem{
	"Maven":     {purlType: "maven", scheme: vercmp.SchemeMaven},
	"npm":       {purlType: "npm", scheme: vercmp.SchemeSemver},
	"crates.io": {purlType: "cargo", scheme: vercmp.SchemeSemver},
	"Go":        {purlType: "golang", scheme: vercmp.SchemeGo, goPrefix: true},
}

// Build is the result of turning records into a fallback pack.
type Build struct {
	Pack    *pack.Pack
	Skipped []string
}

// BuildPack builds a draft, low-ceiling pack for cve from recs.
// Port and proto describe the service exposure to check; the default is
// a port no service uses, so exposure is unknown and fails closed.
func BuildPack(recs []Record, cve string, raw [][]byte, port int, proto string) (*Build, error) {
	if !cveRE.MatchString(cve) {
		return nil, fmt.Errorf("osv: %q is not a CVE id", cve)
	}
	type pkgKey struct{ purl, scheme string }
	ranges := map[pkgKey][]string{}
	var skipped []string
	var ids, titles []string
	fixed := map[string][]string{}
	for _, r := range recs {
		if !Names(r, cve) {
			continue
		}
		if r.Withdrawn != "" {
			skipped = append(skipped, fmt.Sprintf("%s: withdrawn %s", r.ID, r.Withdrawn))
			continue
		}
		ids = append(ids, r.ID)
		if s := strings.TrimSpace(r.Summary); s != "" {
			titles = append(titles, s)
		}
		for _, a := range r.Affected {
			eco, ok := lookupEcosystem(a.Package.Ecosystem)
			if !ok {
				skipped = append(skipped, fmt.Sprintf("%s %s/%s: ecosystem has no version comparator in Verdict; distro builds need an advisory fact", r.ID, a.Package.Ecosystem, a.Package.Name))
				continue
			}
			pattern, err := patternFor(eco, a.Package.Name)
			if err != nil {
				skipped = append(skipped, fmt.Sprintf("%s %s/%s: %v", r.ID, a.Package.Ecosystem, a.Package.Name, err))
				continue
			}
			exprs, fixes, err := rangesFor(eco, a)
			if err != nil || len(exprs) == 0 {
				why := "no comparable ranges or versions"
				if err != nil {
					why = err.Error()
				}
				// A package whose ranges cannot all be read is dropped whole,
				// so a partial range can never make an affected build look fixed.
				skipped = append(skipped, fmt.Sprintf("%s %s/%s: %s", r.ID, a.Package.Ecosystem, a.Package.Name, why))
				continue
			}
			k := pkgKey{pattern, eco.scheme}
			ranges[k] = append(ranges[k], exprs...)
			fixed[pattern] = append(fixed[pattern], fixes...)
		}
	}
	if len(ids) == 0 {
		return nil, fmt.Errorf("osv: no record names %s", cve)
	}
	if len(ranges) == 0 {
		return nil, fmt.Errorf("osv: %s has no affected package Verdict can version-compare (%d skipped)", cve, len(skipped))
	}
	keys := make([]pkgKey, 0, len(ranges))
	for k := range ranges {
		keys = append(keys, k)
	}
	sort.Slice(keys, func(i, j int) bool {
		if keys[i].purl != keys[j].purl {
			return keys[i].purl < keys[j].purl
		}
		return keys[i].scheme < keys[j].scheme
	})
	if len(keys) > 64 {
		return nil, fmt.Errorf("osv: %s lists %d packages; the fallback evaluates at most 64", cve, len(keys))
	}
	advisoryKey := "advisory." + strings.ToLower(strings.ReplaceAll(cve, "-", "_")) + ".status"
	checks := map[string]pack.Check{}
	var arms []pack.Condition
	var components []string
	for i, k := range keys {
		id := fmt.Sprintf("V%02d_version", i+1)
		checks[id] = pack.Check{
			Type:                  "package_version",
			VersionScheme:         k.scheme,
			AffectedRanges:        uniqSorted(ranges[k]),
			AdvisoryFact:          advisoryKey,
			PurlPatterns:          []string{k.purl},
			NegationJustification: "vulnerable_code_not_present",
			AbsenceJustification:  "component_not_present",
			ResolutionHint:        "Version-only fallback from OSV. Provide the package URL from an SBOM, or for a distro build an " + advisoryKey + " fact scoped to that package URL.",
		}
		arms = append(arms, pack.Condition{Ref: id})
		components = append(components, k.purl)
	}
	var cond pack.Condition
	if len(arms) == 1 {
		cond = arms[0]
	} else {
		cond = pack.Condition{AnyOf: arms}
	}
	sort.Strings(ids)
	title := cve + " version-only fallback"
	if len(titles) > 0 {
		title += ": " + truncate(titles[0], 120)
	}
	var fixText []string
	for _, c := range uniqSorted(components) {
		if f := uniqSorted(fixed[c]); len(f) > 0 {
			fixText = append(fixText, c+" fixed in "+strings.Join(f, ", "))
		}
	}
	fix := "Upgrade to a version outside the OSV affected ranges."
	if len(fixText) > 0 {
		fix = "Upgrade: " + truncate(strings.Join(fixText, "; "), 900)
	}
	sources := make([]pack.Source, 0, len(ids))
	for _, id := range ids {
		sources = append(sources, pack.Source{URL: "https://osv.dev/vulnerability/" + id, Note: "Local OSV record carried in by the operator."})
	}
	limitations := []string{
		"Version-only fallback. No exploit preconditions, configuration, or reachability checks exist for this CVE yet.",
		"Draft with a low confidence ceiling: an absent or out-of-range package is needs_review, never not_affected.",
		"Exposure has no service port unless one was passed, so reachability is unknown and fails closed.",
	}
	for _, s := range skipped {
		limitations = append(limitations, "Skipped: "+truncate(s, 300))
	}
	p := &pack.Pack{
		APIVersion: "verdict.dev/v1",
		Kind:       "ConditionPack",
		Metadata: pack.Metadata{
			ID:                "FALLBACK-" + cve + "-osv",
			CVE:               []string{cve},
			Title:             title,
			Description:       "Generated in memory from OSV records " + strings.Join(ids, ", ") + ". Not a condition pack.",
			Status:            "draft",
			ConfidenceCeiling: "low",
			Authors:           []pack.Person{{Name: "verdict osv fallback", Role: "generator"}},
			Sources:           sources,
			KBMinVersion:      "osv-fallback",
			EvidenceMaxAge:    "24h",
			Limitations:       limitations,
		},
		Component:   pack.Component{Purls: uniqSorted(components)},
		Checks:      checks,
		Conditions:  cond,
		Exposure:    pack.ExposureSpec{Port: port, Proto: proto},
		Remediation: pack.Remediation{Fix: fix},
	}
	sum := sha256.New()
	for _, b := range raw {
		s := sha256.Sum256(b)
		sum.Write(s[:])
	}
	p.SHA256 = hex.EncodeToString(sum.Sum(nil))
	p.FilePath = "osv:" + strings.Join(ids, ",")
	if err := pack.Lint(p); err != nil {
		return nil, fmt.Errorf("osv: generated pack failed lint: %w", err)
	}
	if p.Metadata.Status != "draft" || p.Metadata.ConfidenceCeiling != "low" {
		return nil, fmt.Errorf("osv: fallback must stay draft and low")
	}
	sort.Strings(skipped)
	return &Build{Pack: p, Skipped: skipped}, nil
}

func lookupEcosystem(name string) (ecosystem, bool) {
	e, ok := ecosystems[name]
	return e, ok
}

func patternFor(eco ecosystem, name string) (string, error) {
	if name == "" || strings.ContainsAny(name, "?#% ") || strings.Contains(strings.TrimPrefix(name, "@"), "@") {
		return "", fmt.Errorf("package name %q", name)
	}
	if strings.HasPrefix(name, "@") && eco.purlType != "npm" {
		return "", fmt.Errorf("package name %q", name)
	}
	var raw string
	switch eco.purlType {
	case "maven":
		g, a, ok := strings.Cut(name, ":")
		if !ok || g == "" || a == "" || strings.Contains(a, ":") {
			return "", fmt.Errorf("maven name %q is not group:artifact", name)
		}
		raw = "pkg:maven/" + g + "/" + a
	case "npm":
		if strings.HasPrefix(name, "@") {
			scope, n, ok := strings.Cut(name, "/")
			if !ok || n == "" {
				return "", fmt.Errorf("npm name %q", name)
			}
			raw = "pkg:npm/%40" + strings.TrimPrefix(scope, "@") + "/" + n
		} else {
			raw = "pkg:npm/" + name
		}
	case "golang":
		if name == "stdlib" || name == "toolchain" {
			return "", fmt.Errorf("Go %s is not a module in an SBOM inventory", name)
		}
		raw = "pkg:golang/" + name
	case "cargo":
		raw = "pkg:cargo/" + name
	default:
		return "", fmt.Errorf("unsupported purl type %q", eco.purlType)
	}
	canon, err := purl.Canonical(raw)
	if err != nil {
		return "", err
	}
	return canon, nil
}

func rangesFor(eco ecosystem, a Affected) ([]string, []string, error) {
	norm := func(v string) string {
		if eco.goPrefix && v != "" && !strings.HasPrefix(v, "v") {
			return "v" + v
		}
		return v
	}
	var out, fixes []string
	add := func(expr string) error {
		if err := vercmp.ValidateRange(eco.scheme, expr); err != nil {
			return err
		}
		out = append(out, expr)
		return nil
	}
	for _, r := range a.Ranges {
		switch r.Type {
		case "ECOSYSTEM", "SEMVER":
		case "GIT":
			continue
		default:
			return nil, nil, fmt.Errorf("range type %q", r.Type)
		}
		lower := ""
		open := false
		for _, ev := range r.Events {
			switch {
			case ev.Introduced != "":
				lower = ""
				if ev.Introduced != "0" {
					lower = ">=" + norm(ev.Introduced)
				}
				open = true
			case ev.Fixed != "":
				if !open {
					return nil, nil, fmt.Errorf("fixed %q without introduced", ev.Fixed)
				}
				if err := add(strings.TrimSpace(lower + " <" + norm(ev.Fixed))); err != nil {
					return nil, nil, err
				}
				fixes = append(fixes, ev.Fixed)
				open = false
			case ev.LastAffected != "":
				if !open {
					return nil, nil, fmt.Errorf("last_affected %q without introduced", ev.LastAffected)
				}
				if err := add(strings.TrimSpace(lower + " <=" + norm(ev.LastAffected))); err != nil {
					return nil, nil, err
				}
				open = false
			case ev.Limit != "":
				return nil, nil, fmt.Errorf("limit events are not supported")
			}
		}
		if open {
			expr := lower
			if expr == "" {
				// Every version is affected and no fix is listed.
				expr = ">=" + norm(zeroFor(eco.scheme))
			}
			if err := add(expr); err != nil {
				return nil, nil, err
			}
		}
	}
	if len(a.Ranges) == 0 {
		for _, v := range a.Versions {
			if err := add("=" + norm(v)); err != nil {
				return nil, nil, err
			}
		}
	}
	return out, fixes, nil
}

func zeroFor(scheme string) string {
	if scheme == vercmp.SchemeMaven {
		return "0"
	}
	return "0.0.0"
}

func uniqSorted(in []string) []string {
	seen := map[string]struct{}{}
	out := make([]string, 0, len(in))
	for _, s := range in {
		if _, ok := seen[s]; ok {
			continue
		}
		seen[s] = struct{}{}
		out = append(out, s)
	}
	sort.Strings(out)
	return out
}

func truncate(s string, n int) string {
	s = strings.Join(strings.Fields(s), " ")
	if len(s) <= n {
		return s
	}
	return s[:n] + "..."
}
