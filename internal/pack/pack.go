// Copyright 2026 Uddeshya Kumar
// SPDX-License-Identifier: Apache-2.0

// Package pack loads and lints Exploitability Condition Packs.
// Packs are data. Unknown fields, aliases, and unknown check kinds are rejected.
package pack

import "time"

// MaxBytes is the largest pack document accepted.
const MaxBytes = 256 * 1024

// Pack is a decoded condition pack plus load metadata.
type Pack struct {
	APIVersion  string           `yaml:"apiVersion"`
	Kind        string           `yaml:"kind"`
	Metadata    Metadata         `yaml:"metadata"`
	Component   Component        `yaml:"component"`
	Checks      map[string]Check `yaml:"checks"`
	Conditions  Condition        `yaml:"conditions"`
	Exposure    ExposureSpec     `yaml:"exposure"`
	Remediation Remediation      `yaml:"remediation"`
	Tests       []DeclaredTest   `yaml:"tests"`

	FilePath string        `yaml:"-"`
	SHA256   string        `yaml:"-"`
	MaxAge   time.Duration `yaml:"-"`
}

// Metadata identifies the pack and its review state.
type Metadata struct {
	ID                string   `yaml:"id"`
	CVE               []string `yaml:"cve"`
	Title             string   `yaml:"title"`
	Description       string   `yaml:"description"`
	Status            string   `yaml:"status"`
	Synthetic         bool     `yaml:"synthetic"`
	ConfidenceCeiling string   `yaml:"confidence_ceiling"`
	Authors           []Person `yaml:"authors"`
	Reviewers         []Person `yaml:"reviewers"`
	Sources           []Source `yaml:"sources"`
	KBMinVersion      string   `yaml:"kb_min_version"`
	EvidenceMaxAge    string   `yaml:"evidence_max_age"`
	Limitations       []string `yaml:"limitations"`
}

// Person is an author or reviewer name supplied in the pack.
// A name is not authenticated.
type Person struct {
	Name string `yaml:"name"`
	Role string `yaml:"role"`
}

// Source cites an advisory the pack was written from.
type Source struct {
	URL  string `yaml:"url"`
	Note string `yaml:"note"`
}

// Component names the packages the pack is about.
type Component struct {
	Purls []string `yaml:"purls"`
}

// Check is one typed predicate.
type Check struct {
	Type                  string `yaml:"type"`
	NegationJustification string `yaml:"negation_justification"`
	AbsenceJustification  string `yaml:"absence_justification"`
	// AbsenceContradictedBy lists fact keys (process.listening.sshd) that,
	// when true on the asset, mean the component runs here and "no matching
	// package" cannot be a proof of absence.
	AbsenceContradictedBy []string `yaml:"absence_contradicted_by"`
	// Aliases are purl patterns for other names under which the same
	// component ships (a name that shares no token with the component
	// patterns). An inventory package that matches one is never absent and
	// never version-sorted. An alias only widens what blocks an absence
	// proof; it never makes a check true or false. omitempty keeps the
	// content hash of a pack without aliases unchanged.
	Aliases        []string     `yaml:"aliases" json:"Aliases,omitempty"`
	ResolutionHint string       `yaml:"resolution_hint"`
	Tradeoff       string       `yaml:"tradeoff"`
	VersionScheme  string       `yaml:"version_scheme"`
	AffectedRanges []string     `yaml:"affected_ranges"`
	AdvisoryFact   string       `yaml:"advisory_fact"`
	PurlPatterns   []string     `yaml:"purl_patterns"`
	Key            string       `yaml:"key"`
	Equals         string       `yaml:"equals"`
	Process        string       `yaml:"process"`
	Path           string       `yaml:"path"`
	WhenPackage    *WhenPackage `yaml:"when_package"`
}

// WhenPackage restricts a check to packages inside a range.
type WhenPackage struct {
	VersionScheme  string   `yaml:"version_scheme"`
	PurlPatterns   []string `yaml:"purl_patterns"`
	AffectedRanges []string `yaml:"affected_ranges"`
}

// Condition is a ref, not, all_of, or any_of node.
type Condition struct {
	Ref   string
	Not   *Condition
	AllOf []Condition
	AnyOf []Condition
}

// ExposureSpec names the port and protocol a true tree is about.
// It never selects not_affected. Zone names live in the site policy.
// Exactly one of Port and PortFact is set. PortFact names a host fact
// (factkeys.PortLists) whose canonical value is the port list the service
// listens on; there is no fallback to a fixed port when that fact is
// missing or malformed, exposure is unknown. omitempty keeps the content
// hash of packs without port_fact unchanged.
type ExposureSpec struct {
	Port     int    `yaml:"port"`
	Proto    string `yaml:"proto"`
	PortFact string `yaml:"port_fact" json:"PortFact,omitempty"`
}

// Remediation text is copied into OpenVEX action statements.
type Remediation struct {
	Fix     string `yaml:"fix"`
	Interim string `yaml:"interim"`
}

// DeclaredTest is an in-process fixture, not a container build.
type DeclaredTest struct {
	Name                      string `yaml:"name"`
	Snapshot                  string `yaml:"snapshot"`
	Policy                    string `yaml:"policy"`
	Asset                     string `yaml:"asset"`
	ExpectState               string `yaml:"expect_state"`
	ExpectVEX                 string `yaml:"expect_vex"`
	ExpectJustification       string `yaml:"expect_justification"`
	ExpectExposureUncertainty *bool  `yaml:"expect_exposure_uncertainty"`
}

// Justifications are the OpenVEX not_affected labels.
var Justifications = map[string]struct{}{
	"component_not_present":                             {},
	"vulnerable_code_not_present":                       {},
	"vulnerable_code_not_in_execute_path":               {},
	"vulnerable_code_cannot_be_controlled_by_adversary": {},
	"inline_mitigations_already_exist":                  {},
}

// CheckTypes is the closed set implemented by the engine.
var CheckTypes = map[string]struct{}{
	"package_version":    {},
	"host_fact":          {},
	"config_value":       {},
	"env_var":            {},
	"process_listening":  {},
	"process_running":    {},
	"file_exists":        {},
	"manual_attestation": {},
}
