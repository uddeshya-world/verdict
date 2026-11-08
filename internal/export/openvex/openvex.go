// Copyright 2026 Uddeshya Kumar
// SPDX-License-Identifier: Apache-2.0

// Package openvex builds an OpenVEX 0.2 document from a verdict report.
package openvex

import (
	"fmt"
	"strings"

	"github.com/uddeshya-world/verdict/internal/canonjson"
	"github.com/uddeshya-world/verdict/internal/engine"
)

const contextV02 = "https://openvex.dev/ns/v0.2.0"

// Document is an OpenVEX 0.2 document. Field order is the encoded order.
type Document struct {
	Context    string      `json:"@context"`
	ID         string      `json:"@id"`
	Author     string      `json:"author"`
	Role       string      `json:"role"`
	Timestamp  string      `json:"timestamp"`
	Version    int         `json:"version"`
	Tooling    string      `json:"tooling"`
	Statements []Statement `json:"statements"`
}

// Statement is one product/vulnerability assertion.
type Statement struct {
	ID                       string    `json:"@id"`
	Vulnerability            Vuln      `json:"vulnerability"`
	Timestamp                string    `json:"timestamp"`
	Products                 []Product `json:"products"`
	Status                   string    `json:"status"`
	StatusNotes              string    `json:"status_notes,omitempty"`
	Justification            string    `json:"justification,omitempty"`
	ImpactStatement          string    `json:"impact_statement,omitempty"`
	ActionStatement          string    `json:"action_statement,omitempty"`
	ActionStatementTimestamp string    `json:"action_statement_timestamp,omitempty"`
}

// Vuln names the CVE without pointing at a catalog URL.
type Vuln struct {
	ID   string `json:"@id"`
	Name string `json:"name"`
}

// Product identifies the asset.
type Product struct {
	ID          string       `json:"@id"`
	Identifiers *Identifiers `json:"identifiers,omitempty"`
}

// Identifiers carries a package URL when the snapshot has one.
type Identifiers struct {
	PURL string `json:"purl"`
}

// FromReport builds a document. author is an operator-supplied label, not an authenticated identity.
func FromReport(rep *engine.Report, author string) (*Document, error) {
	if rep == nil {
		return nil, fmt.Errorf("openvex: nil report")
	}
	if strings.TrimSpace(author) == "" {
		return nil, fmt.Errorf("openvex: author is required and is not authenticated")
	}
	if len(rep.Verdicts) == 0 {
		return nil, fmt.Errorf("openvex: no statements to export")
	}
	doc := &Document{
		Context:   contextV02,
		ID:        documentID(rep),
		Author:    author,
		Role:      "tool-assisted document creator; evidence was not authenticated",
		Timestamp: rep.EvaluationTime,
		Version:   1,
		Tooling:   rep.Tool,
	}
	for _, v := range rep.Verdicts {
		st, err := statement(rep, v)
		if err != nil {
			return nil, err
		}
		doc.Statements = append(doc.Statements, st)
	}
	return doc, nil
}

// Marshal encodes the document canonically.
func Marshal(doc *Document) ([]byte, error) {
	return canonjson.Marshal(doc)
}

func statement(rep *engine.Report, v engine.Verdict) (Statement, error) {
	prod := Product{ID: "urn:verdict:asset:" + v.AssetID}
	if v.PrimaryPURL != "" {
		prod.Identifiers = &Identifiers{PURL: v.PrimaryPURL}
	}
	st := Statement{
		ID: "urn:verdict:statement:" + v.AssetID + ":" + rep.CVE,
		Vulnerability: Vuln{
			ID:   "urn:cve:" + rep.CVE,
			Name: rep.CVE,
		},
		Timestamp:       rep.EvaluationTime,
		Products:        []Product{prod},
		Status:          v.VEXStatus,
		StatusNotes:     notes(rep, v),
		ImpactStatement: v.ImpactStatement,
	}
	switch v.VEXStatus {
	case "not_affected":
		if v.Justification == "" {
			return Statement{}, fmt.Errorf("openvex: not_affected verdict %s has no justification", v.AssetID)
		}
		st.Justification = v.Justification
	case "affected":
		if v.ActionStatement == "" {
			return Statement{}, fmt.Errorf("openvex: affected verdict %s has no action statement", v.AssetID)
		}
		st.ActionStatement = v.ActionStatement
		st.ActionStatementTimestamp = rep.EvaluationTime
	case "under_investigation":
	default:
		return Statement{}, fmt.Errorf("openvex: verdict %s has status %q", v.AssetID, v.VEXStatus)
	}
	return st, nil
}

func notes(rep *engine.Report, v engine.Verdict) string {
	b := fmt.Sprintf(
		"verdict_state=%s; confidence=%s; evidence_trust=%s; tree=%s; exposure_uncertainty=%t; pack=%s; pack_status=%s; kb_version=%s",
		v.State, v.Confidence, rep.EvidenceTrust, v.TreeValue, v.ExposureUncertainty, rep.PackID, rep.PackStatus, rep.KBVersion,
	)
	if len(v.Reasons) > 0 {
		b += "; reasons=" + strings.Join(v.Reasons, ",")
	}
	if v.MitigationDependent {
		b += "; mitigation_dependent=true"
	}
	b += ". not_affected is withheld unless a reviewed pack has a sufficient observed proof. Unknown exposure on an affected asset is exploitable with uncertainty. This note is not a claim that the asset is safe."
	return b
}

func documentID(rep *engine.Report) string {
	ts := strings.NewReplacer("-", "", ":", "", ".", "").Replace(rep.EvaluationTime)
	pol := rep.PolicySHA256
	if pol == "" {
		pol = "none"
	}
	return "urn:verdict:openvex:" + sanitize(rep.PackSHA256) + ":" + sanitize(rep.KBVersion) + ":" + sanitize(ts) + ":" + sanitize(pol)
}

func sanitize(s string) string {
	var b strings.Builder
	for _, r := range s {
		switch {
		case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z', r >= '0' && r <= '9', r == '.', r == '_', r == '-':
			b.WriteRune(r)
		default:
			b.WriteByte('_')
		}
	}
	if b.Len() == 0 {
		return "none"
	}
	return b.String()
}
