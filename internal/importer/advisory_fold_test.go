// Copyright 2026 Uddeshya Kumar
// SPDX-License-Identifier: Apache-2.0

package importer

import (
	"strings"
	"testing"
)

func advRows(t *testing.T, rows ...[2]string) *AdvisoryDocument {
	t.Helper()
	var b strings.Builder
	b.WriteString(`{"facts":[`)
	for i, r := range rows {
		if i > 0 {
			b.WriteString(",")
		}
		b.WriteString(`{"asset_id":"bastion-01","key":"advisory.cve_2024_6387.status","purl":"` + r[0] + `","value":"` + r[1] + `","basis":"observed","confidence":"high","observed_at":"2026-11-08T11:00:00Z","evidence_id":"e","source":"USN"}`)
	}
	b.WriteString(`]}`)
	doc, err := ParseAdvisories([]byte(b.String()))
	if err != nil {
		t.Fatal(err)
	}
	return doc
}

const (
	exactRow   = "pkg:deb/ubuntu/openssh-server@1:8.9p1-3ubuntu0.10?distro=ubuntu-22.04"
	caseRow    = "pkg:deb/ubuntu/OpenSSH-Server@1:8.9p1-3ubuntu0.10?distro=ubuntu-22.04"
	homoRow    = "pkg:deb/ubuntu/%D0%BEpenssh-server@1:8.9p1-3ubuntu0.10?distro=ubuntu-22.04"
	wrongDist  = "pkg:deb/ubuntu/openssh-server@1:8.9p1-3ubuntu0.10?distro=ubuntu-24.04"
	otherNames = "pkg:deb/ubuntu/openssh-sftp-server@1:8.9p1-3ubuntu0.10"
)

// N3: an affected row that is a case variant of an inventory package is never
// dropped, so its fixed sibling cannot clear the host.
func TestFoldedVariantRowIsNeverDropped(t *testing.T) {
	snap := syftUbuntu(t, "ubuntu-22.04")
	for _, order := range [][][2]string{
		{{exactRow, "fixed"}, {caseRow, "affected"}},
		{{caseRow, "affected"}, {exactRow, "fixed"}},
		{{caseRow, "affected"}},
		{{homoRow, "affected"}},
	} {
		for _, allow := range []bool{false, true} {
			_, _, err := ApplyAdvisories(snap, advRows(t, order...), AdvisoryOptions{AllowUnmatched: allow})
			if err == nil {
				t.Fatalf("allow=%v rows=%v: variant row must be an error", allow, order)
			}
		}
	}
	_, _, err := ApplyAdvisories(snap, advRows(t, [2]string{caseRow, "affected"}), AdvisoryOptions{AllowUnmatched: true})
	if err == nil || !strings.Contains(err.Error(), "OpenSSH-Server") || !strings.Contains(err.Error(), "openssh-server") {
		t.Fatalf("error must name both purls: %v", err)
	}
}

// Rows that are genuinely about another package or distro stay droppable.
func TestUnrelatedUnmatchedRowStillDroppable(t *testing.T) {
	snap := syftUbuntu(t, "ubuntu-22.04")
	for _, row := range []string{wrongDist, otherNames} {
		out, rep, err := ApplyAdvisories(snap, advRows(t, [2]string{row, "fixed"}), AdvisoryOptions{AllowUnmatched: true})
		if err != nil || len(rep.Unmatched) != 1 || len(out.Assets[0].Facts) != 0 {
			t.Fatalf("%s: %v %+v", row, err, rep)
		}
	}
}

// Two rows that fold to one package and disagree conflict even when neither
// names an inventory package.
func TestFoldedRowsThatDisagreeConflict(t *testing.T) {
	snap := syftUbuntu(t, "ubuntu-22.04")
	a := "pkg:deb/ubuntu/openssh-server@9:9?distro=ubuntu-22.04"
	b := "pkg:deb/ubuntu/OpenSSH-Server@9:9?distro=ubuntu-22.04"
	_, _, err := ApplyAdvisories(snap, advRows(t, [2]string{a, "fixed"}, [2]string{b, "affected"}), AdvisoryOptions{AllowUnmatched: true})
	if err == nil || !strings.Contains(err.Error(), "disagree") {
		t.Fatalf("disagreeing folded rows: %v", err)
	}
	if _, _, err := ApplyAdvisories(snap, advRows(t, [2]string{a, "fixed"}, [2]string{b, "fixed"}), AdvisoryOptions{AllowUnmatched: true}); err != nil {
		t.Fatalf("agreeing unmatched rows are droppable: %v", err)
	}
}
