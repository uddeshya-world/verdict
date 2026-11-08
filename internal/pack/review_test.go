// Copyright 2026 Uddeshya Kumar
// SPDX-License-Identifier: Apache-2.0

package pack

import (
	"os"
	"strings"
	"testing"

	"github.com/uddeshya-world/verdict/internal/rootpath"
)

func TestReviewRecordRequiresTwoHumansAndMatchingBytes(t *testing.T) {
	root, err := rootpath.Find()
	if err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(root + "/packs/synthetic/ecp-synthetic-polarity.yaml")
	if err != nil {
		t.Fatal(err)
	}
	p, err := Load("ecp-synthetic-polarity.yaml", data)
	if err != nil {
		t.Fatal(err)
	}
	rec := &ReviewRecord{
		PackID: p.Metadata.ID, PackSHA256: p.SHA256,
		Reviewers: []ReviewAttestation{
			{Name: "synthetic-reviewer-alpha", ReviewedAt: "2026-11-08T12:00:00Z", Statement: "Fixture review of these bytes."},
			{Name: "synthetic-reviewer-beta", ReviewedAt: "2026-11-08T12:00:00Z", Statement: "Fixture review of these bytes."},
		},
	}
	if err := CheckReview(p, rec); err != nil {
		t.Fatal(err)
	}
	if !SameReviewers(p, rec) {
		t.Fatal("synthetic pack names should match the fixture record")
	}
	rec.PackSHA256 = strings.Repeat("ab", 32)
	if err := CheckReview(p, rec); err == nil {
		t.Fatal("sha mismatch must fail")
	}
	rec.PackSHA256 = p.SHA256
	rec.Reviewers = rec.Reviewers[:1]
	if err := CheckReview(p, rec); err == nil {
		t.Fatal("one reviewer must fail")
	}
}

func TestRealCVEPackRejectsFixtureReviewers(t *testing.T) {
	root, err := rootpath.Find()
	if err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(root + "/packs/draft/ecp-cve-2024-6387-openssh.yaml")
	if err != nil {
		t.Fatal(err)
	}
	p, err := Load("ecp-cve-2024-6387-openssh.yaml", data)
	if err != nil {
		t.Fatal(err)
	}
	if p.Metadata.Status != "draft" || len(p.Metadata.Reviewers) != 0 {
		t.Fatalf("regreSSHion must stay draft, got %s reviewers=%d", p.Metadata.Status, len(p.Metadata.Reviewers))
	}
	rec := &ReviewRecord{
		PackID: p.Metadata.ID, PackSHA256: p.SHA256,
		Reviewers: []ReviewAttestation{
			{Name: "synthetic-reviewer-alpha", ReviewedAt: "2026-11-08T12:00:00Z", Statement: "not a person"},
			{Name: "synthetic-reviewer-beta", ReviewedAt: "2026-11-08T12:00:00Z", Statement: "not a person"},
		},
	}
	if err := CheckReview(p, rec); err == nil {
		t.Fatal("fixture names must not sign regreSSHion")
	}
}
