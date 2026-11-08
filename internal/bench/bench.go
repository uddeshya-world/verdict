// Copyright 2026 Uddeshya Kumar
// SPDX-License-Identifier: Apache-2.0

// Package bench scores packs against labeled fixtures.
// A draft pack is evaluated again with the reviewed decision bar applied
// only in memory. That does not mark the pack reviewed and does not invent
// a human reviewer. The gate fails when that simulation says not_affected
// and the fixture's ground truth is anything else.
package bench

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/uddeshya-world/verdict/internal/engine"
	"github.com/uddeshya-world/verdict/internal/importer"
	"github.com/uddeshya-world/verdict/internal/pack"
	"github.com/uddeshya-world/verdict/internal/policy"
	"github.com/uddeshya-world/verdict/internal/snapshot"
)

// Case is one labeled fixture. Paths are relative to the module root.
type Case struct {
	ID              string `json:"id"`
	Kind            string `json:"kind,omitempty"`
	Pack            string `json:"pack"`
	Policy          string `json:"policy"`
	Snapshot        string `json:"snapshot,omitempty"`
	Asset           string `json:"asset,omitempty"`
	GroundTruth     string `json:"ground_truth"`
	ExpectState     string `json:"expect_state,omitempty"`
	RequireTradeoff bool   `json:"require_mitigation_dependent,omitempty"`
	ImportFormat    string `json:"import_format,omitempty"`
	ImportInput     string `json:"import_input,omitempty"`
	ImportComplete  bool   `json:"import_complete,omitempty"`
	Note            string `json:"note,omitempty"`
}

// Row is the result of one case.
type Row struct {
	ID                  string `json:"id"`
	GroundTruth         string `json:"ground_truth"`
	State               string `json:"state"`
	VEXStatus           string `json:"vex_status"`
	Justification       string `json:"justification,omitempty"`
	MitigationDependent bool   `json:"mitigation_dependent,omitempty"`
	FalseNotAffected    bool   `json:"false_not_affected"`
	StateMismatch       bool   `json:"state_mismatch,omitempty"`
	TradeoffMissing     bool   `json:"tradeoff_missing,omitempty"`
	Detail              string `json:"detail,omitempty"`
	Note                string `json:"note,omitempty"`
}

// Report is the scoreboard. ReviewedSimulation means draft packs were
// scored as if they had two fixture reviewers. The pack files are unchanged.
type Report struct {
	ReviewedSimulation bool   `json:"reviewed_simulation"`
	ReviewerNote       string `json:"reviewer_note"`
	Cases              int    `json:"cases"`
	FalseNotAffected   int    `json:"false_not_affected"`
	StateMismatches    int    `json:"state_mismatches"`
	Rows               []Row  `json:"rows"`
}

// FalseNotAffected reports a not_affected claim the label does not allow.
func FalseNotAffected(state, vex, ground string) bool {
	if ground == "not_affected" {
		return false
	}
	return state == "not_affected" || vex == "not_affected"
}

// LoadCorpus reads a JSON array of cases. Unknown fields are rejected.
func LoadCorpus(data []byte) ([]Case, error) {
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.DisallowUnknownFields()
	var cases []Case
	if err := dec.Decode(&cases); err != nil {
		return nil, fmt.Errorf("bench: %w", err)
	}
	if len(cases) == 0 {
		return nil, fmt.Errorf("bench: corpus is empty")
	}
	seen := map[string]struct{}{}
	for _, c := range cases {
		if c.ID == "" || c.Pack == "" || c.Policy == "" {
			return nil, fmt.Errorf("bench: case %q needs id, pack, and policy", c.ID)
		}
		switch c.GroundTruth {
		case "affected", "not_affected", "unknown":
		default:
			return nil, fmt.Errorf("bench: %s ground_truth %q", c.ID, c.GroundTruth)
		}
		if _, ok := seen[c.ID]; ok {
			return nil, fmt.Errorf("bench: duplicate case %s", c.ID)
		}
		seen[c.ID] = struct{}{}
		kind := c.Kind
		if kind == "" {
			kind = "drill"
		}
		switch kind {
		case "drill":
			if c.Snapshot == "" || c.Asset == "" {
				return nil, fmt.Errorf("bench: %s needs snapshot and asset", c.ID)
			}
		case "import":
			if c.ImportInput == "" || (c.ImportFormat != "cyclonedx" && c.ImportFormat != "trivy") {
				return nil, fmt.Errorf("bench: %s needs import_input and import_format cyclonedx or trivy", c.ID)
			}
			if c.ExpectState == "" {
				return nil, fmt.Errorf("bench: %s is an import case and needs expect_state", c.ID)
			}
		default:
			return nil, fmt.Errorf("bench: %s kind %q", c.ID, c.Kind)
		}
	}
	return cases, nil
}

// Run scores every case. root is the module root.
// UncoveredPacks lists repository packs that have no corpus case.
func UncoveredPacks(root string, cases []Case) ([]string, error) {
	covered := map[string]struct{}{}
	for _, c := range cases {
		covered[filepath.ToSlash(c.Pack)] = struct{}{}
	}
	var missing []string
	for _, dir := range []string{"packs/draft", "packs/synthetic"} {
		ents, err := os.ReadDir(filepath.Join(root, dir))
		if err != nil {
			return nil, err
		}
		for _, ent := range ents {
			if ent.IsDir() || !strings.HasSuffix(ent.Name(), ".yaml") {
				continue
			}
			rel := dir + "/" + ent.Name()
			if _, ok := covered[rel]; !ok {
				missing = append(missing, rel)
			}
		}
	}
	sort.Strings(missing)
	return missing, nil
}

func Run(root string, cases []Case) (*Report, error) {
	missing, err := UncoveredPacks(root, cases)
	if err != nil {
		return nil, err
	}
	if len(missing) > 0 {
		return nil, fmt.Errorf("bench: packs with no corpus case: %s", strings.Join(missing, ", "))
	}
	rep := &Report{
		ReviewedSimulation: true,
		ReviewerNote:       "Draft packs are scored with two synthetic-reviewer-* names in memory. Those names are not a review of a real CVE and are not written back to the pack.",
		Rows:               []Row{},
	}
	ordered := append([]Case{}, cases...)
	sort.Slice(ordered, func(i, j int) bool { return ordered[i].ID < ordered[j].ID })
	for _, c := range ordered {
		row, err := runCase(root, c)
		if err != nil {
			return nil, err
		}
		if row.FalseNotAffected {
			rep.FalseNotAffected++
		}
		if row.StateMismatch || row.TradeoffMissing {
			rep.StateMismatches++
		}
		rep.Rows = append(rep.Rows, row)
	}
	rep.Cases = len(rep.Rows)
	return rep, nil
}

func runCase(root string, c Case) (Row, error) {
	row := Row{ID: c.ID, GroundTruth: c.GroundTruth, Note: c.Note}
	p, err := loadPack(root, c.Pack)
	if err != nil {
		return row, fmt.Errorf("bench %s: %w", c.ID, err)
	}
	simulateReviewed(p)
	pol, err := loadPolicy(root, c.Policy)
	if err != nil {
		return row, fmt.Errorf("bench %s: %w", c.ID, err)
	}
	kind := c.Kind
	if kind == "" {
		kind = "drill"
	}
	if kind == "import" {
		return runImport(root, c, row, p, pol)
	}
	snap, err := loadSnapshot(root, c.Snapshot)
	if err != nil {
		return row, fmt.Errorf("bench %s: %w", c.ID, err)
	}
	verdict, err := drillAsset(p, pol, snap, c.Asset)
	if err != nil {
		return row, fmt.Errorf("bench %s: %w", c.ID, err)
	}
	fill(&row, c, verdict)
	return row, nil
}

func runImport(root string, c Case, row Row, p *pack.Pack, pol *policy.Policy) (Row, error) {
	data, err := os.ReadFile(filepath.Join(root, c.ImportInput))
	if err != nil {
		return row, fmt.Errorf("bench %s: %w", c.ID, err)
	}
	opt := importer.InventoryOptions{
		AssetID: "imported", AssetName: "imported",
		Complete: c.ImportComplete, Basis: "observed", Confidence: "high",
		ObservedAt: "2026-11-08T11:00:00Z", EvidenceID: "e-bench-import",
		KBVersion: "demo-2026.11.08", Evaluation: "2026-11-08T12:00:00Z",
	}
	var got *importer.Result
	switch c.ImportFormat {
	case "cyclonedx":
		got, err = importer.CycloneDX(data, opt)
	case "trivy":
		got, err = importer.Trivy(data, opt)
	default:
		err = fmt.Errorf("import format %q", c.ImportFormat)
	}
	if err != nil {
		row.State = "import_rejected"
		row.Detail = err.Error()
		if c.ExpectState != "" && c.ExpectState != "import_rejected" {
			row.StateMismatch = true
			row.Detail = "import rejected; expected " + c.ExpectState
		}
		return row, nil
	}
	verdict, err := drillAsset(p, pol, got.Snapshot, "imported")
	if err != nil {
		return row, fmt.Errorf("bench %s: %w", c.ID, err)
	}
	fill(&row, c, verdict)
	if row.FalseNotAffected {
		row.Detail = "import accepted a skipped component and the drill said not_affected. " + row.Detail
	}
	return row, nil
}

func fill(row *Row, c Case, v *engine.Verdict) {
	row.State = v.State
	row.VEXStatus = v.VEXStatus
	row.Justification = v.Justification
	row.MitigationDependent = v.MitigationDependent
	row.FalseNotAffected = FalseNotAffected(v.State, v.VEXStatus, c.GroundTruth)
	if c.ExpectState != "" && v.State != c.ExpectState {
		row.StateMismatch = true
	}
	if c.RequireTradeoff && v.State == "not_affected" && !v.MitigationDependent {
		row.TradeoffMissing = true
	}
	if row.FalseNotAffected {
		row.Detail = fmt.Sprintf("ground truth %s but verdict %s/%s justification %s", c.GroundTruth, v.State, v.VEXStatus, v.Justification)
	}
}

func drillAsset(p *pack.Pack, pol *policy.Policy, snap *snapshot.Snapshot, assetID string) (*engine.Verdict, error) {
	var found bool
	var one snapshot.Asset
	for _, a := range snap.Assets {
		if a.ID == assetID {
			one = a
			found = true
			break
		}
	}
	if !found {
		return nil, fmt.Errorf("asset %q is not in the snapshot", assetID)
	}
	only := *snap
	only.Assets = []snapshot.Asset{one}
	eval, err := time.Parse(time.RFC3339, snap.EvaluationTime)
	if err != nil {
		return nil, err
	}
	rep, err := engine.Evaluate(engine.Input{
		Pack: p, Policy: pol, Snapshot: &only,
		EvaluationTime: eval, KBVersion: snap.KBVersion,
	})
	if err != nil {
		return nil, err
	}
	if len(rep.Verdicts) != 1 {
		return nil, fmt.Errorf("expected one verdict, got %d", len(rep.Verdicts))
	}
	return &rep.Verdicts[0], nil
}

func loadPack(root, rel string) (*pack.Pack, error) {
	path := filepath.Join(root, rel)
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	return pack.Load(path, data)
}

func loadPolicy(root, rel string) (*policy.Policy, error) {
	data, err := os.ReadFile(filepath.Join(root, rel))
	if err != nil {
		return nil, err
	}
	return policy.Load(data)
}

func loadSnapshot(root, rel string) (*snapshot.Snapshot, error) {
	data, err := os.ReadFile(filepath.Join(root, rel))
	if err != nil {
		return nil, err
	}
	return snapshot.Load(data)
}

func simulateReviewed(p *pack.Pack) {
	if p.Metadata.Status == "reviewed" && pack.DistinctReviewers(p) >= 2 {
		return
	}
	p.Metadata.Status = "reviewed"
	p.Metadata.Reviewers = []pack.Person{
		{Name: "synthetic-reviewer-alpha"},
		{Name: "synthetic-reviewer-beta"},
	}
}
