// Copyright 2026 Uddeshya Kumar
// SPDX-License-Identifier: Apache-2.0

package engine

import (
	"strings"
	"testing"
)

func TestParseLeafHintRoundTrip(t *testing.T) {
	details := []string{"sshd.login_grace_time", `odd "key" with spaces`, ""}
	packHints := []string{"", "Run sshd -T and record LoginGraceTime.", "Pack hint: nested"}
	parsed := 0
	for _, code := range ReasonCodes() {
		info := Reasons[code]
		for _, d := range details {
			for _, ph := range packHints {
				hint := leafHint(code, "chk_one", d, ph)
				gotD, hasD, gotPH, ok := ParseLeafHint(code, "chk_one", hint)
				reliable := info.Kind == KindLeaf && !strings.Contains(info.Hint, "{detail}")
				if ok != reliable {
					t.Fatalf("%s: ok=%v, want %v", code, ok, reliable)
				}
				if !ok {
					continue
				}
				parsed++
				if hasD != strings.Contains(info.Hint, "{detail_q}") {
					t.Fatalf("%s: hasDetail=%v", code, hasD)
				}
				if hasD && gotD != d {
					t.Fatalf("%s: detail %q, want %q", code, gotD, d)
				}
				if gotPH != ph {
					t.Fatalf("%s: pack hint %q, want %q", code, gotPH, ph)
				}
			}
		}
	}
	if parsed == 0 {
		t.Fatal("no leaf hint parsed")
	}
	if _, _, _, ok := ParseLeafHint(ReasonMissingFact, "chk_one", "Check chk_one needs something else"); ok {
		t.Fatal("parsed a hint that is not the catalog text")
	}
	if _, _, _, ok := ParseLeafHint(ReasonPackNotReviewed, "", decisionHint(ReasonPackNotReviewed)); ok {
		t.Fatal("parsed a decision hint as a leaf hint")
	}
}
