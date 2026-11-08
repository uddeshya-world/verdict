// Copyright 2026 Uddeshya Kumar
// SPDX-License-Identifier: Apache-2.0

package bench

import (
	"os"
	"strings"
	"testing"

	"github.com/uddeshya-world/verdict/internal/rootpath"
)

func TestCorpusHasNoFalseNotAffected(t *testing.T) {
	root, err := rootpath.Find()
	if err != nil {
		t.Fatal(err)
	}
	raw, err := os.ReadFile(root + "/bench/corpus.json")
	if err != nil {
		t.Fatal(err)
	}
	cases, err := LoadCorpus(raw)
	if err != nil {
		t.Fatal(err)
	}
	need := []string{
		"regresshion/lab-socket-activated",
		"regresshion/import-complete-skips-openssh",
		"regresshion/wrong-advisory-version",
		"xz/lab-xz-sshd-down",
	}
	have := map[string]Case{}
	for _, c := range cases {
		have[c.ID] = c
	}
	for _, id := range need {
		if _, ok := have[id]; !ok {
			t.Fatalf("corpus dropped adversarial case %s", id)
		}
	}
	if have["xz/lab-xz-sshd-down"].GroundTruth != "affected" {
		t.Fatal("xz sshd-down must be labeled affected")
	}
	if have["regresshion/lab-socket-activated"].ExpectState != "exploitable" {
		t.Fatal("socket activation must stay exploitable")
	}
	flag := have["log4shell/lab-log4j-property-set"]
	if flag.GroundTruth != "affected" || flag.ExpectState != "exploitable" {
		t.Fatal("formatMsgNoLookups must not be labeled not_affected")
	}
	if _, err := UncoveredPacks(root, nil); err != nil {
		t.Fatal(err)
	} else if missing, _ := UncoveredPacks(root, nil); len(missing) == 0 {
		t.Fatal("a corpus with no cases must report every pack")
	}
	rep, err := Run(root, cases)
	if err != nil {
		t.Fatal(err)
	}
	if rep.FalseNotAffected != 0 || rep.StateMismatches != 0 {
		var b strings.Builder
		for _, row := range rep.Rows {
			if row.FalseNotAffected || row.StateMismatch || row.TradeoffMissing {
				b.WriteString(row.ID + " state=" + row.State + " vex=" + row.VEXStatus + " " + row.Detail + "\n")
			}
		}
		t.Fatalf("bench gate failed\n%s", b.String())
	}
	if rep.Cases != len(cases) {
		t.Fatalf("cases %d rows %d", len(cases), rep.Cases)
	}
}

func TestFalseNotAffectedPredicate(t *testing.T) {
	if !FalseNotAffected("not_affected", "not_affected", "affected") {
		t.Fatal("affected asset claimed clear")
	}
	if !FalseNotAffected("needs_review", "not_affected", "unknown") {
		t.Fatal("vex not_affected on an unknown asset")
	}
	if FalseNotAffected("not_affected", "not_affected", "not_affected") {
		t.Fatal("a labeled clear is not a false clear")
	}
	if FalseNotAffected("needs_review", "under_investigation", "affected") {
		t.Fatal("withholding not_affected is not a false clear")
	}
}
