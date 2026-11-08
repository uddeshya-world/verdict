// Copyright 2026 Uddeshya Kumar
// SPDX-License-Identifier: Apache-2.0

// Package importer turns local SBOM files into snapshots.
// It does not read vulnerability verdicts out of those files and it does
// not contact a registry or an advisory feed.
package importer

import (
	"bytes"
	"encoding/json"
	"fmt"
	"sort"
	"strings"

	"github.com/uddeshya-world/verdict/internal/purl"
	"github.com/uddeshya-world/verdict/internal/snapshot"
)

// InventoryOptions is how an imported package list is labeled.
// The defaults are attested and medium so the import alone cannot support
// not_affected. Raising them is the operator's claim, not a verification.
type InventoryOptions struct {
	AssetID    string
	AssetName  string
	AssetKind  string
	Zones      []string
	Complete   bool
	Basis      string
	Confidence string
	ObservedAt string
	EvidenceID string
	KBVersion  string
	Evaluation string
}

// Result is a snapshot plus packages that were skipped.
type Result struct {
	Snapshot *snapshot.Snapshot
	Skipped  []string
}

// CycloneDX reads one CycloneDX JSON BOM into one asset.
// Components without a purl are skipped. Fields this parser does not
// understand, including any vulnerability list, are ignored.
func CycloneDX(data []byte, opt InventoryOptions) (*Result, error) {
	var doc struct {
		BOMFormat  string `json:"bomFormat"`
		Components []struct {
			Name    string `json:"name"`
			Version string `json:"version"`
			PURL    string `json:"purl"`
		} `json:"components"`
	}
	if err := json.Unmarshal(data, &doc); err != nil {
		return nil, fmt.Errorf("import cyclonedx: %w", err)
	}
	if doc.BOMFormat != "CycloneDX" {
		return nil, fmt.Errorf("import cyclonedx: bomFormat must be CycloneDX")
	}
	var rows []row
	var skipped []string
	for _, c := range doc.Components {
		if c.PURL == "" {
			name := c.Name
			if name == "" {
				name = "(unnamed)"
			}
			skipped = append(skipped, name+": no purl")
			continue
		}
		rows = append(rows, row{raw: c.PURL, version: c.Version, name: c.Name})
	}
	return finish(rows, skipped, opt, "cyclonedx")
}

// Trivy reads one Trivy JSON report into one asset.
// Only Results[].Packages[].Identifier.PURL is imported.
// Vulnerabilities are not copied. Trivy's affected/fixed decision is not an advisory fact.
func Trivy(data []byte, opt InventoryOptions) (*Result, error) {
	var doc struct {
		Results []struct {
			Packages []struct {
				Name       string `json:"Name"`
				Version    string `json:"Version"`
				Identifier struct {
					PURL string `json:"PURL"`
				} `json:"Identifier"`
			} `json:"Packages"`
		} `json:"Results"`
	}
	if err := json.Unmarshal(data, &doc); err != nil {
		return nil, fmt.Errorf("import trivy: %w", err)
	}
	if doc.Results == nil {
		return nil, fmt.Errorf("import trivy: Results is missing")
	}
	var rows []row
	var skipped []string
	for _, r := range doc.Results {
		for _, p := range r.Packages {
			if p.Identifier.PURL == "" {
				name := p.Name
				if name == "" {
					name = "(unnamed)"
				}
				skipped = append(skipped, name+": no purl")
				continue
			}
			rows = append(rows, row{raw: p.Identifier.PURL, version: p.Version, name: p.Name})
		}
	}
	return finish(rows, skipped, opt, "trivy")
}

type row struct {
	raw     string
	version string
	name    string
}

func finish(rows []row, skipped []string, opt InventoryOptions, kind string) (*Result, error) {
	if err := normalize(&opt); err != nil {
		return nil, err
	}
	pkgs := make([]snapshot.Package, 0, len(rows))
	seen := map[string]struct{}{}
	for _, r := range rows {
		pkg, err := packageFromPURL(r.raw, r.version)
		if err != nil {
			label := r.name
			if label == "" {
				label = r.raw
			}
			skipped = append(skipped, label+": "+err.Error())
			continue
		}
		if _, ok := seen[pkg.PURL]; ok {
			skipped = append(skipped, pkg.PURL+": duplicate purl")
			continue
		}
		seen[pkg.PURL] = struct{}{}
		pkgs = append(pkgs, pkg)
	}
	sort.Slice(pkgs, func(i, j int) bool { return pkgs[i].PURL < pkgs[j].PURL })
	if opt.Complete && len(skipped) > 0 {
		return nil, fmt.Errorf("import %s: inventory cannot be complete: %d components skipped (%s)", kind, len(skipped), strings.Join(skipped, "; "))
	}
	if len(pkgs) == 0 {
		return nil, fmt.Errorf("import %s: no packages with a usable purl", kind)
	}
	if opt.Zones == nil {
		opt.Zones = []string{}
	}
	snap := &snapshot.Snapshot{
		KBVersion:      opt.KBVersion,
		EvaluationTime: opt.Evaluation,
		EvidenceTrust:  "caller_asserted",
		Assets: []snapshot.Asset{{
			ID:    opt.AssetID,
			Name:  opt.AssetName,
			Kind:  opt.AssetKind,
			Zones: opt.Zones,
			Inventory: snapshot.Inventory{
				Complete:   opt.Complete,
				ObservedAt: opt.ObservedAt,
				Basis:      opt.Basis,
				Confidence: opt.Confidence,
				EvidenceID: opt.EvidenceID,
				Packages:   pkgs,
			},
			Facts:    []snapshot.Fact{},
			Exposure: []snapshot.Exposure{},
		}},
	}
	// Re-parse so the importer cannot emit a snapshot the engine would reject.
	raw, err := json.Marshal(snap)
	if err != nil {
		return nil, err
	}
	checked, err := snapshot.Load(raw)
	if err != nil {
		return nil, fmt.Errorf("import %s: %w", kind, err)
	}
	return &Result{Snapshot: checked, Skipped: skipped}, nil
}

func packageFromPURL(raw, versionField string) (snapshot.Package, error) {
	parsed, err := purl.Parse(raw)
	if err != nil {
		return snapshot.Package{}, err
	}
	ver := parsed.Version
	if ver == "" {
		ver = versionField
	} else if versionField != "" && versionField != ver {
		return snapshot.Package{}, fmt.Errorf("purl version %q disagrees with version %q", ver, versionField)
	}
	if ver == "" {
		return snapshot.Package{}, fmt.Errorf("purl %q has no version", raw)
	}
	return snapshot.Package{PURL: raw, Version: ver}, nil
}

func normalize(opt *InventoryOptions) error {
	if opt.AssetID == "" || opt.AssetName == "" {
		return fmt.Errorf("import: asset id and name are required")
	}
	if opt.AssetKind == "" {
		opt.AssetKind = "host"
	}
	if opt.Basis == "" {
		opt.Basis = "attested"
	}
	if opt.Confidence == "" {
		opt.Confidence = "medium"
	}
	if opt.KBVersion == "" || opt.Evaluation == "" || opt.ObservedAt == "" || opt.EvidenceID == "" {
		return fmt.Errorf("import: kb version, evaluation time, observed time, and evidence id are required")
	}
	return nil
}

// Advisory is one caller-supplied advisory row. It is not fetched.
type Advisory struct {
	AssetID    string `json:"asset_id"`
	Key        string `json:"key"`
	PURL       string `json:"purl"`
	Value      string `json:"value"`
	Basis      string `json:"basis"`
	Confidence string `json:"confidence"`
	ObservedAt string `json:"observed_at"`
	ExpiresAt  string `json:"expires_at,omitempty"`
	EvidenceID string `json:"evidence_id"`
	Source     string `json:"source"`
}

// AdvisoryDocument is a local file of advisory rows.
type AdvisoryDocument struct {
	Facts []Advisory `json:"facts"`
}

// ParseAdvisories decodes an advisory overlay. Unknown fields are rejected.
func ParseAdvisories(data []byte) (*AdvisoryDocument, error) {
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.DisallowUnknownFields()
	var doc AdvisoryDocument
	if err := dec.Decode(&doc); err != nil {
		return nil, fmt.Errorf("import advisories: %w", err)
	}
	if dec.More() {
		return nil, fmt.Errorf("import advisories: trailing JSON")
	}
	if len(doc.Facts) == 0 {
		return nil, fmt.Errorf("import advisories: facts is empty")
	}
	for _, f := range doc.Facts {
		switch f.Value {
		case "affected", "fixed", "not_affected":
		default:
			return nil, fmt.Errorf("import advisories: %s value %q must be affected, fixed, or not_affected", f.Key, f.Value)
		}
		if f.AssetID == "" || f.Key == "" || f.PURL == "" || f.Source == "" || f.EvidenceID == "" {
			return nil, fmt.Errorf("import advisories: each fact needs asset_id, key, purl, source, and evidence_id")
		}
	}
	return &doc, nil
}

// ApplyAdvisories adds advisory facts onto a snapshot.
// It does not invent a status for a package that is not listed.
func ApplyAdvisories(s *snapshot.Snapshot, doc *AdvisoryDocument) (*snapshot.Snapshot, []string, error) {
	if s == nil || doc == nil {
		return nil, nil, fmt.Errorf("import advisories: snapshot and document are required")
	}
	next := *s
	next.Assets = append([]snapshot.Asset{}, s.Assets...)
	index := map[string]int{}
	for i := range next.Assets {
		index[next.Assets[i].ID] = i
	}
	var warnings []string
	for _, f := range doc.Facts {
		i, ok := index[f.AssetID]
		if !ok {
			return nil, nil, fmt.Errorf("import advisories: asset %q is not in the snapshot", f.AssetID)
		}
		asset := next.Assets[i]
		if !inventoryHasPURL(asset, f.PURL) {
			warnings = append(warnings, fmt.Sprintf("advisory purl not in asset inventory: asset %s purl %s", f.AssetID, f.PURL))
		}
		asset.Facts = append(append([]snapshot.Fact{}, asset.Facts...), snapshot.Fact{
			Key: f.Key, PURL: f.PURL, Value: f.Value, Basis: f.Basis, Confidence: f.Confidence,
			ObservedAt: f.ObservedAt, ExpiresAt: f.ExpiresAt, EvidenceID: f.EvidenceID, Source: f.Source,
		})
		next.Assets[i] = asset
	}
	raw, err := json.Marshal(&next)
	if err != nil {
		return nil, nil, err
	}
	checked, err := snapshot.Load(raw)
	if err != nil {
		return nil, nil, fmt.Errorf("import advisories: %w", err)
	}
	return checked, warnings, nil
}

func inventoryHasPURL(asset snapshot.Asset, raw string) bool {
	for _, pkg := range asset.Inventory.Packages {
		if pkg.PURL == raw {
			return true
		}
	}
	return false
}
