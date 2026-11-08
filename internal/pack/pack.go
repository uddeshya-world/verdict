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
	Type                  string       `yaml:"type"`
	NegationJustification string       `yaml:"negation_justification"`
	AbsenceJustification  string       `yaml:"absence_justification"`
	ResolutionHint        string       `yaml:"resolution_hint"`
	VersionScheme         string       `yaml:"version_scheme"`
	AffectedRanges        []string     `yaml:"affected_ranges"`
	AdvisoryFact          string       `yaml:"advisory_fact"`
	PurlPatterns          []string     `yaml:"purl_patterns"`
	Key                   string       `yaml:"key"`
	Equals                string       `yaml:"equals"`
	Process               string       `yaml:"process"`
	Path                  string       `yaml:"path"`
	WhenPackage           *WhenPackage `yaml:"when_package"`
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

// ExposureSpec classifies a true tree. It never selects not_affected.
type ExposureSpec struct {
	Port           int      `yaml:"port"`
	Proto          string   `yaml:"proto"`
	UntrustedZones []string `yaml:"untrusted_zones"`
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
