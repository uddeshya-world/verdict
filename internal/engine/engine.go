// Copyright 2026 Uddeshya Kumar
// SPDX-License-Identifier: Apache-2.0

// Package engine derives verdicts from a pack and a snapshot.
// It does not read the clock, the filesystem, or the network.
package engine

import (
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/uddeshya-world/verdict/internal/buildinfo"
	"github.com/uddeshya-world/verdict/internal/logic"
	"github.com/uddeshya-world/verdict/internal/pack"
	"github.com/uddeshya-world/verdict/internal/policy"
	"github.com/uddeshya-world/verdict/internal/snapshot"
)

// Report is the canonical drill result.
type Report struct {
	ReportVersion  string    `json:"report_version"`
	Tool           string    `json:"tool"`
	KBVersion      string    `json:"kb_version"`
	EvaluationTime string    `json:"evaluation_time"`
	PackID         string    `json:"pack_id"`
	PackSHA256     string    `json:"pack_sha256"`
	PolicySHA256   string    `json:"policy_sha256"`
	PackStatus     string    `json:"pack_status"`
	CVE            string    `json:"cve"`
	EvidenceTrust  string    `json:"evidence_trust"`
	Verdicts       []Verdict `json:"verdicts"`
	Summary        Summary   `json:"summary"`
}

// Summary is the funnel count for the report. It is derived from Verdicts.
type Summary struct {
	Assets               int `json:"assets"`
	Exploitable          int `json:"exploitable"`
	VulnerableNotExposed int `json:"vulnerable_not_exposed"`
	NotAffected          int `json:"not_affected"`
	NeedsReview          int `json:"needs_review"`
}

// Verdict is one asset.
type Verdict struct {
	AssetID             string     `json:"asset_id"`
	AssetName           string     `json:"asset_name"`
	AssetKind           string     `json:"asset_kind"`
	Zones               []string   `json:"zones"`
	PrimaryPURL         string     `json:"primary_purl,omitempty"`
	State               string     `json:"state"`
	VEXStatus           string     `json:"vex_status"`
	Justification       string     `json:"justification,omitempty"`
	Confidence          string     `json:"confidence"`
	ExposureUncertainty bool       `json:"exposure_uncertainty"`
	ExposureEvidenceIDs []string   `json:"exposure_evidence_ids"`
	TreeValue           string     `json:"tree_value"`
	Reasons             []string   `json:"reasons"`
	Hints               []Hint     `json:"hints"`
	Proof               *ProofView `json:"proof,omitempty"`
	Leaves              []LeafView `json:"leaves"`
	ActionStatement     string     `json:"action_statement,omitempty"`
}

// Hint tells an operator what is missing.
type Hint struct {
	CheckID string `json:"check_id,omitempty"`
	Reason  string `json:"reason"`
	Hint    string `json:"hint"`
}

// ProofView is the sufficient false proof, whether or not it was allowed
// to become not_affected.
type ProofView struct {
	Sufficient           bool     `json:"sufficient"`
	Suppressed           bool     `json:"suppressed"`
	SuppressReasons      []string `json:"suppress_reasons"`
	Confidence           string   `json:"confidence"`
	Justification        string   `json:"justification,omitempty"`
	Justifications       []string `json:"justifications"`
	UniformJustification bool     `json:"uniform_justification"`
	CheckIDs             []string `json:"check_ids"`
	EvidenceIDs          []string `json:"evidence_ids"`
}

// LeafView is one check after evidence rules, before the tree.
type LeafView struct {
	CheckID       string   `json:"check_id"`
	Value         string   `json:"value"`
	Confidence    string   `json:"confidence"`
	Observed      bool     `json:"observed"`
	Stale         bool     `json:"stale"`
	Reason        string   `json:"reason,omitempty"`
	EvidenceIDs   []string `json:"evidence_ids"`
	Justification string   `json:"justification,omitempty"`
}

// Input is the entire explicit evaluation request.
type Input struct {
	Pack           *pack.Pack
	Policy         *policy.Policy
	Snapshot       *snapshot.Snapshot
	EvaluationTime time.Time
	KBVersion      string
}

// Evaluate returns a deterministic report.
func Evaluate(in Input) (*Report, error) {
	if in.Pack == nil || in.Snapshot == nil {
		return nil, fmt.Errorf("engine: pack and snapshot are required")
	}
	if in.EvaluationTime.IsZero() {
		return nil, fmt.Errorf("engine: evaluation time is required and is not read from the clock")
	}
	if in.KBVersion == "" {
		return nil, fmt.Errorf("engine: kb_version is required")
	}
	if len(in.Pack.Metadata.CVE) != 1 {
		return nil, fmt.Errorf("engine: pack must name one CVE")
	}
	meta := Meta{
		Status:     in.Pack.Metadata.Status,
		Reviewers:  pack.DistinctReviewers(in.Pack),
		Deprecated: in.Pack.Metadata.Status == "deprecated",
	}
	if c, ok := logic.ParseConfidence(in.Pack.Metadata.ConfidenceCeiling); ok {
		meta.Ceiling = c
	}
	report := &Report{
		ReportVersion:  "0.1.0",
		Tool:           buildinfo.ModulePath + " " + buildinfo.Version,
		KBVersion:      in.KBVersion,
		EvaluationTime: in.EvaluationTime.UTC().Format("2006-01-02T15:04:05.000000000Z"),
		PackID:         in.Pack.Metadata.ID,
		PackSHA256:     in.Pack.SHA256,
		PolicySHA256:   policyHash(in.Policy),
		PackStatus:     in.Pack.Metadata.Status,
		CVE:            in.Pack.Metadata.CVE[0],
		EvidenceTrust:  "caller_asserted_unverified",
		Verdicts:       []Verdict{},
	}
	node := toNode(in.Pack.Conditions)
	for _, asset := range in.Snapshot.Assets {
		report.Verdicts = append(report.Verdicts, evalAsset(in.Pack, in.Policy, asset, node, meta, in.EvaluationTime))
	}
	sort.Slice(report.Verdicts, func(i, j int) bool {
		return report.Verdicts[i].AssetID < report.Verdicts[j].AssetID
	})
	report.Summary = summarize(report.Verdicts)
	return report, nil
}

func summarize(vs []Verdict) Summary {
	s := Summary{Assets: len(vs)}
	for _, v := range vs {
		switch v.State {
		case stateExploitable:
			s.Exploitable++
		case stateNotExposed:
			s.VulnerableNotExposed++
		case stateNotAffected:
			s.NotAffected++
		case stateNeedsReview:
			s.NeedsReview++
		}
	}
	return s
}

func policyHash(p *policy.Policy) string {
	if p == nil {
		return ""
	}
	return p.SHA256
}

func evalAsset(p *pack.Pack, pol *policy.Policy, asset snapshot.Asset, node logic.Node, meta Meta, eval time.Time) Verdict {
	leaves := evalChecks(p, asset, eval)
	leafMap := map[string]logic.Leaf{}
	for _, l := range leaves {
		leafMap[l.ID] = l.Leaf
	}
	res, err := logic.Evaluate(node, leafMap)
	if err != nil {
		return errorVerdict(asset, err)
	}
	exp := classifyExposure(pol, p.Exposure, asset, eval, p.MaxAge)
	d := Decide(res, meta, exp)
	v := Verdict{
		AssetID:             asset.ID,
		AssetName:           asset.Name,
		AssetKind:           asset.Kind,
		Zones:               append([]string{}, asset.Zones...),
		PrimaryPURL:         primaryPURL(asset),
		State:               d.State,
		VEXStatus:           d.VEX,
		Justification:       d.Justification,
		Confidence:          d.Confidence.String(),
		ExposureUncertainty: d.Uncertainty,
		ExposureEvidenceIDs: nonEmpty(exp.EvidenceIDs),
		TreeValue:           d.Tree,
		Reasons:             append([]string{}, d.Reasons...),
		Hints:               []Hint{},
		Leaves:              make([]LeafView, 0, len(leaves)),
	}
	if v.Zones == nil {
		v.Zones = []string{}
	}
	if v.Reasons == nil {
		v.Reasons = []string{}
	}
	for _, l := range leaves {
		view := LeafView{
			CheckID:       l.ID,
			Value:         l.Leaf.Value.String(),
			Confidence:    l.Leaf.Confidence.String(),
			Observed:      l.Leaf.Observed,
			Stale:         l.Stale,
			Reason:        l.Reason,
			EvidenceIDs:   uniq(l.Leaf.EvidenceIDs),
			Justification: l.Leaf.Justification,
		}
		if l.Leaf.Value == logic.Unknown {
			view.Justification = ""
		}
		v.Leaves = append(v.Leaves, view)
		if l.Reason != "" {
			v.Hints = append(v.Hints, Hint{
				CheckID: l.ID,
				Reason:  l.Reason,
				Hint:    leafHint(l.Reason, l.ID, l.Detail, p.Checks[l.ID].ResolutionHint),
			})
		}
	}
	for _, reason := range d.Reasons {
		v.Hints = append(v.Hints, Hint{Reason: reason, Hint: decisionHint(reason)})
	}
	sort.Slice(v.Hints, func(i, j int) bool {
		if v.Hints[i].CheckID == v.Hints[j].CheckID {
			return v.Hints[i].Reason < v.Hints[j].Reason
		}
		return v.Hints[i].CheckID < v.Hints[j].CheckID
	})
	if res.StrictFalse != nil {
		js := append([]string{}, res.StrictFalse.Justifications...)
		suppress := d.State != stateNotAffected
		reasons := []string{}
		if suppress {
			reasons = append(reasons, d.Reasons...)
		}
		just := ""
		if len(js) == 1 {
			just = js[0]
		}
		v.Proof = &ProofView{
			Sufficient:           true,
			Suppressed:           suppress,
			SuppressReasons:      reasons,
			Confidence:           res.StrictFalse.Confidence.String(),
			Justification:        just,
			Justifications:       js,
			UniformJustification: res.StrictFalse.Uniform,
			CheckIDs:             append([]string{}, res.StrictFalse.CheckIDs...),
			EvidenceIDs:          append([]string{}, res.StrictFalse.EvidenceIDs...),
		}
	}
	if d.VEX == vexAffected {
		v.ActionStatement = actionStatement(p, d.State)
	}
	return v
}

func errorVerdict(asset snapshot.Asset, err error) Verdict {
	return Verdict{
		AssetID:             asset.ID,
		AssetName:           asset.Name,
		AssetKind:           asset.Kind,
		Zones:               []string{},
		State:               stateNeedsReview,
		VEXStatus:           vexInvestigating,
		Confidence:          "none",
		ExposureEvidenceIDs: []string{},
		TreeValue:           "unknown",
		Reasons:             []string{"evaluation_error"},
		Hints:               []Hint{{Reason: "evaluation_error", Hint: err.Error()}},
		Leaves:              []LeafView{},
	}
}

func actionStatement(p *pack.Pack, state string) string {
	msg := strings.TrimSpace(p.Remediation.Fix)
	if interim := strings.TrimSpace(p.Remediation.Interim); interim != "" {
		msg += " Interim: " + interim
	}
	return msg + " Internal verdict state: " + state + ". Generated by verdict from caller-asserted facts. This is not a human attestation and it is not a claim that the asset is safe."
}

func primaryPURL(asset snapshot.Asset) string {
	if asset.PrimaryPURL != "" {
		return asset.PrimaryPURL
	}
	if len(asset.Inventory.Packages) > 0 {
		return asset.Inventory.Packages[0].PURL
	}
	return ""
}

func toNode(c pack.Condition) logic.Node {
	if c.Ref != "" {
		return logic.Node{Kind: logic.KindRef, Ref: c.Ref}
	}
	if c.Not != nil {
		return logic.Node{Kind: logic.KindNot, Kids: []logic.Node{toNode(*c.Not)}}
	}
	if len(c.AllOf) > 0 {
		kids := make([]logic.Node, len(c.AllOf))
		for i := range c.AllOf {
			kids[i] = toNode(c.AllOf[i])
		}
		return logic.Node{Kind: logic.KindAll, Kids: kids}
	}
	kids := make([]logic.Node, len(c.AnyOf))
	for i := range c.AnyOf {
		kids[i] = toNode(c.AnyOf[i])
	}
	return logic.Node{Kind: logic.KindAny, Kids: kids}
}
