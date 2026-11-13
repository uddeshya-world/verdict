// Copyright 2026 Uddeshya Kumar
// SPDX-License-Identifier: Apache-2.0

package engine

import (
	"testing"

	"github.com/uddeshya-world/verdict/internal/logic"
	"github.com/uddeshya-world/verdict/internal/pack"
	"github.com/uddeshya-world/verdict/internal/snapshot"
)

// A package-level confidence (a version read from a binary banner) can make a
// check true but never false at the not_affected bar, on every path.
func TestPackageConfidenceOnlyLowers(t *testing.T) {
	eval := mustTime(t)
	ch := opensshCheck()
	bin := func(v string) snapshot.Package {
		return snapshot.Package{PURL: "pkg:generic/openssh@" + v, Version: v, Confidence: "medium", Source: "binary_version"}
	}
	deb := snapshot.Package{PURL: "pkg:deb/debian/openssh-server@1:9.2p1-2+deb12u3", Version: "1:9.2p1-2+deb12u3"}

	t.Run("in range is true at medium", func(t *testing.T) {
		got := evalPackage("C1", ch, nil, freshInventory(bin("9.6p1")), eval, mustAge())
		if got.Leaf.Value != logic.True || !got.Leaf.Observed || got.Leaf.Confidence != logic.ConfMedium {
			t.Fatalf("%+v", got)
		}
	})
	t.Run("out of range is false below the bar", func(t *testing.T) {
		got := evalPackage("C1", ch, nil, freshInventory(bin("9.8p1")), eval, mustAge())
		if got.Leaf.Value != logic.False || got.Leaf.Confidence >= logic.ConfHigh || got.Reason != "confidence_below_not_affected_bar" {
			t.Fatalf("%+v", got)
		}
	})
	t.Run("fixed distro advisory plus banner stays below the bar", func(t *testing.T) {
		a := freshInventory(bin("9.8p1"), deb)
		a.Facts = []snapshot.Fact{advisoryFact("fixed", "observed", "high", "2026-11-08T11:00:00Z", deb.PURL)}
		got := evalPackage("C1", ch, nil, a, eval, mustAge())
		if got.Leaf.Value != logic.False || got.Leaf.Confidence >= logic.ConfHigh {
			t.Fatalf("%+v", got)
		}
	})
	t.Run("in-range banner beside a fixed distro package is true", func(t *testing.T) {
		a := freshInventory(bin("9.6p1"), deb)
		a.Facts = []snapshot.Fact{advisoryFact("fixed", "observed", "high", "2026-11-08T11:00:00Z", deb.PURL)}
		got := evalPackage("C1", ch, nil, a, eval, mustAge())
		if got.Leaf.Value != logic.True {
			t.Fatalf("%+v", got)
		}
	})
	t.Run("high package confidence does not raise a medium inventory", func(t *testing.T) {
		p := bin("9.8p1")
		p.Confidence = "confirmed"
		a := freshInventory(p)
		a.Inventory.Confidence = "medium"
		got := evalPackage("C1", ch, nil, a, eval, mustAge())
		if got.Leaf.Confidence >= logic.ConfHigh {
			t.Fatalf("%+v", got)
		}
	})
	t.Run("empty package confidence keeps the inventory", func(t *testing.T) {
		got := evalPackage("C1", ch, nil, freshInventory(snapshot.Package{PURL: "pkg:generic/openssh@9.8p1", Version: "9.8p1"}), eval, mustAge())
		if got.Leaf.Value != logic.False || got.Leaf.Confidence != logic.ConfHigh {
			t.Fatalf("%+v", got)
		}
	})
}

func TestPackageConfidenceLowersWhenGate(t *testing.T) {
	eval := mustTime(t)
	ch := pack.Check{
		Type: "config_value", Key: "config.sshd.LoginGraceTime", Equals: "0",
		NegationJustification: "inline_mitigations_already_exist",
		WhenPackage: &pack.WhenPackage{
			VersionScheme: "openssh_upstream", PurlPatterns: []string{"pkg:generic/openssh"},
			AffectedRanges: []string{">=8.5p1 <9.8p1"},
		},
	}
	for _, c := range []struct {
		conf string
		want logic.Confidence
	}{{"medium", logic.ConfMedium}, {"", logic.ConfHigh}} {
		a := freshInventory(snapshot.Package{PURL: "pkg:generic/openssh@9.8p1", Version: "9.8p1", Confidence: c.conf})
		got := evalEquals("M1", ch, ch.Key, false, newAssetCtx(newEvalCtx(), a), eval, mustAge())
		if got.Leaf.Value != logic.False || got.Leaf.Confidence != c.want {
			t.Fatalf("package confidence %q: %+v", c.conf, got)
		}
	}
}

func TestPkgConfUnreadableIsNone(t *testing.T) {
	if c := pkgConf(logic.ConfHigh, snapshot.Package{Confidence: "certain"}); c != logic.ConfNone {
		t.Fatalf("got %v", c)
	}
}
