// Copyright 2026 Uddeshya Kumar
// SPDX-License-Identifier: Apache-2.0

package engine

import (
	"math/rand"
	"testing"

	"github.com/uddeshya-world/verdict/internal/logic"
	"github.com/uddeshya-world/verdict/internal/pack"
	"github.com/uddeshya-world/verdict/internal/snapshot"
	"github.com/uddeshya-world/verdict/internal/vercmp"
)

func opensshCheck() pack.Check {
	return pack.Check{
		Type:                  "package_version",
		VersionScheme:         "openssh_upstream",
		AffectedRanges:        []string{">=8.5p1 <9.8p1", "<4.4p1"},
		AdvisoryFact:          "advisory.cve_2024_6387.status",
		PurlPatterns:          []string{"pkg:generic/openssh", "pkg:deb/openssh-server", "pkg:rpm/openssh-server", "pkg:apk/openssh-server"},
		NegationJustification: "vulnerable_code_not_present",
		AbsenceJustification:  "component_not_present",
	}
}

func freshInventory(pkgs ...snapshot.Package) snapshot.Asset {
	return snapshot.Asset{
		ID: "a", Name: "a", Kind: "host",
		Inventory: snapshot.Inventory{
			Complete: true, Basis: "observed", Confidence: "high",
			ObservedAt: "2026-11-08T11:00:00Z", EvidenceID: "e-inv",
			Packages: pkgs,
		},
	}
}

func advisoryFact(value, basis, confidence, observedAt string) snapshot.Fact {
	return snapshot.Fact{
		Key: "advisory.cve_2024_6387.status", Value: value,
		Basis: basis, Confidence: confidence, ObservedAt: observedAt,
		EvidenceID: "e-adv", Source: "caller",
	}
}

func TestFixedAdvisoryDoesNotClearInRangeUpstream(t *testing.T) {
	eval := mustTime(t)
	ch := opensshCheck()
	generic := snapshot.Package{PURL: "pkg:generic/openssh@9.0p1", Version: "9.0p1"}
	deb := snapshot.Package{PURL: "pkg:deb/ubuntu/openssh-server@1:9.6p1-3ubuntu13.4", Version: "1:9.6p1-3ubuntu13.4"}

	t.Run("generic and deb", func(t *testing.T) {
		a := freshInventory(generic, deb)
		a.Facts = []snapshot.Fact{advisoryFact("fixed", "observed", "high", "2026-11-08T11:00:00Z")}
		got := evalPackage("C1", ch, nil, a, eval, mustAge())
		if got.Leaf.Value != logic.True || !got.Leaf.Observed || got.Leaf.Confidence < logic.ConfHigh {
			t.Fatalf("in-range generic must stay true: %+v", got)
		}
	})
	t.Run("generic only", func(t *testing.T) {
		a := freshInventory(generic)
		a.Facts = []snapshot.Fact{advisoryFact("fixed", "observed", "high", "2026-11-08T11:00:00Z")}
		got := evalPackage("C1", ch, nil, a, eval, mustAge())
		if got.Leaf.Value != logic.True {
			t.Fatalf("stray fixed advisory cleared upstream: %+v", got)
		}
	})
	t.Run("upstream out of range and deb fixed", func(t *testing.T) {
		a := freshInventory(
			snapshot.Package{PURL: "pkg:generic/openssh@9.8p1", Version: "9.8p1"},
			deb,
		)
		a.Facts = []snapshot.Fact{advisoryFact("fixed", "observed", "high", "2026-11-08T11:00:00Z")}
		got := evalPackage("C1", ch, nil, a, eval, mustAge())
		if got.Leaf.Value != logic.False || !got.Leaf.Observed {
			t.Fatalf("patched upstream plus fixed distro should be false: %+v", got)
		}
	})
	t.Run("deb only fixed", func(t *testing.T) {
		a := freshInventory(deb)
		a.Facts = []snapshot.Fact{advisoryFact("fixed", "observed", "high", "2026-11-08T11:00:00Z")}
		got := evalPackage("C1", ch, nil, a, eval, mustAge())
		if got.Leaf.Value != logic.False || !got.Leaf.Observed || got.Leaf.Confidence < logic.ConfHigh {
			t.Fatalf("distro advisory fixed: %+v", got)
		}
	})
	t.Run("deb only without advisory", func(t *testing.T) {
		got := evalPackage("C1", ch, nil, freshInventory(deb), eval, mustAge())
		if got.Leaf.Value != logic.Unknown || got.Reason != "distro_advisory_required" {
			t.Fatalf("%+v", got)
		}
	})
	t.Run("deb affected", func(t *testing.T) {
		a := freshInventory(deb)
		a.Facts = []snapshot.Fact{advisoryFact("affected", "observed", "high", "2026-11-08T11:00:00Z")}
		got := evalPackage("C1", ch, nil, a, eval, mustAge())
		if got.Leaf.Value != logic.True {
			t.Fatalf("%+v", got)
		}
	})
	t.Run("out of range generic ignores affected advisory", func(t *testing.T) {
		a := freshInventory(snapshot.Package{PURL: "pkg:generic/openssh@9.8p1", Version: "9.8p1"})
		a.Facts = []snapshot.Fact{advisoryFact("affected", "observed", "high", "2026-11-08T11:00:00Z")}
		got := evalPackage("C1", ch, nil, a, eval, mustAge())
		if got.Leaf.Value != logic.False {
			t.Fatalf("advisory must not mark a non-distro package affected: %+v", got)
		}
	})
	t.Run("unparsed upstream blocks fixed advisory", func(t *testing.T) {
		a := freshInventory(
			snapshot.Package{PURL: "pkg:generic/openssh@1:9.6p1-3ubuntu13.4", Version: "1:9.6p1-3ubuntu13.4"},
			deb,
		)
		a.Facts = []snapshot.Fact{advisoryFact("fixed", "observed", "high", "2026-11-08T11:00:00Z")}
		got := evalPackage("C1", ch, nil, a, eval, mustAge())
		if got.Leaf.Value != logic.Unknown || got.Reason != "unsupported_version" {
			t.Fatalf("%+v", got)
		}
	})
	t.Run("stale advisory does not fall through to sorting", func(t *testing.T) {
		a := freshInventory(deb)
		a.Facts = []snapshot.Fact{advisoryFact("fixed", "observed", "high", "2026-11-01T11:00:00Z")}
		got := evalPackage("C1", ch, nil, a, eval, mustAge())
		if got.Leaf.Value != logic.Unknown || got.Reason != "stale_evidence" {
			t.Fatalf("%+v", got)
		}
	})
}

func TestReviewedPackAdvisoryCannotClearInRangeGeneric(t *testing.T) {
	eval := mustTime(t)
	p := &pack.Pack{
		Metadata: pack.Metadata{
			ID: "ECP-SYNTHETIC-ADVISORY", CVE: []string{"CVE-2099-6387"},
			Status: "reviewed", ConfidenceCeiling: "high", Synthetic: true,
			Reviewers: []pack.Person{{Name: "synthetic-reviewer-alpha"}, {Name: "synthetic-reviewer-beta"}},
		},
		MaxAge: mustAge(),
		Checks: map[string]pack.Check{
			"C1": opensshCheck(),
			"C2": {Type: "host_fact", Key: "libc.family", Equals: "glibc", NegationJustification: "vulnerable_code_not_present"},
			"C3": {Type: "process_listening", Process: "sshd", NegationJustification: "vulnerable_code_not_in_execute_path"},
			"M1": {Type: "config_value", Key: "config.sshd.LoginGraceTime", Equals: "0", NegationJustification: "inline_mitigations_already_exist"},
		},
		Conditions: pack.Condition{AllOf: []pack.Condition{
			{Ref: "C1"},
			{Ref: "C2"},
			{Ref: "C3"},
			{Not: &pack.Condition{Ref: "M1"}},
		}},
		Exposure: spec22(),
	}
	baseFacts := []snapshot.Fact{
		{Key: "libc.family", Value: "glibc", Basis: "observed", Confidence: "high", ObservedAt: "2026-11-08T11:00:00Z", EvidenceID: "e-libc", Source: "caller"},
		{Key: "process.listening.sshd", Value: "true", Basis: "observed", Confidence: "high", ObservedAt: "2026-11-08T11:00:00Z", EvidenceID: "e-sshd", Source: "caller"},
		{Key: "config.sshd.LoginGraceTime", Value: "120", Basis: "observed", Confidence: "high", ObservedAt: "2026-11-08T11:00:00Z", EvidenceID: "e-lgt", Source: "caller"},
		advisoryFact("fixed", "observed", "high", "2026-11-08T11:00:00Z"),
	}
	exposure := []snapshot.Exposure{{
		Port: 22, Proto: "tcp", ReachableFrom: []string{"internet"},
		Basis: "observed", Confidence: "high", ObservedAt: "2026-11-08T11:00:00Z",
		EvidenceID: "e-exp", Source: "caller",
	}}
	mixed := freshInventory(
		snapshot.Package{PURL: "pkg:generic/openssh@9.0p1", Version: "9.0p1"},
		snapshot.Package{PURL: "pkg:deb/ubuntu/openssh-server@1:9.6p1-3ubuntu13.4", Version: "1:9.6p1-3ubuntu13.4"},
	)
	mixed.Facts = baseFacts
	mixed.Exposure = exposure
	debOnly := freshInventory(snapshot.Package{PURL: "pkg:deb/ubuntu/openssh-server@1:9.6p1-3ubuntu13.4", Version: "1:9.6p1-3ubuntu13.4"})
	debOnly.ID = "deb"
	debOnly.Facts = baseFacts
	debOnly.Exposure = exposure
	snap := &snapshot.Snapshot{
		KBVersion: "demo-2026.11.08", EvaluationTime: "2026-11-08T12:00:00Z",
		EvidenceTrust: "caller_asserted", Assets: []snapshot.Asset{mixed, debOnly},
	}
	rep, err := Evaluate(Input{Pack: p, Snapshot: snap, EvaluationTime: eval, KBVersion: snap.KBVersion})
	if err != nil {
		t.Fatal(err)
	}
	byID := map[string]Verdict{}
	for _, v := range rep.Verdicts {
		byID[v.AssetID] = v
	}
	if byID["a"].State != stateExploitable || byID["a"].VEXStatus != vexAffected || byID["a"].Justification != "" {
		t.Fatalf("mixed asset: %+v", byID["a"])
	}
	if byID["deb"].State != stateNotAffected || byID["deb"].Justification != "vulnerable_code_not_present" {
		t.Fatalf("deb-only fixed advisory: %+v", byID["deb"])
	}
}

func TestAdvisoryFactDoesNotClearUpstreamProperty(t *testing.T) {
	rng := rand.New(rand.NewSource(20261108))
	eval := mustTime(t)
	ch := opensshCheck()
	versions := []string{"9.0p1", "8.5p1", "9.8p1", "4.0p1", "nope", "1:9.6p1-3ubuntu13.4"}
	advisories := []string{"absent", "fixed", "affected", "stale-fixed", "attested-fixed", "low-fixed"}
	for i := 0; i < 400; i++ {
		var pkgs []snapshot.Package
		var inRange bool
		if rng.Intn(5) != 0 {
			ver := versions[rng.Intn(len(versions))]
			pkgs = append(pkgs, snapshot.Package{PURL: "pkg:generic/openssh@" + ver, Version: ver})
			for _, r := range ch.AffectedRanges {
				ok, err := vercmp.InRange(ch.VersionScheme, ver, r)
				if err == nil && ok {
					inRange = true
				}
			}
		}
		if rng.Intn(2) == 0 {
			pkgs = append(pkgs, snapshot.Package{PURL: "pkg:deb/ubuntu/openssh-server@1:9.6p1-3ubuntu13.4", Version: "1:9.6p1-3ubuntu13.4"})
		}
		if rng.Intn(4) == 0 {
			pkgs = append(pkgs, snapshot.Package{PURL: "pkg:rpm/opensuse/openssh-server@9.6p1-1.1", Version: "9.6p1-1.1"})
		}
		asset := freshInventory(pkgs...)
		kind := advisories[rng.Intn(len(advisories))]
		switch kind {
		case "fixed":
			asset.Facts = []snapshot.Fact{advisoryFact("fixed", "observed", "high", "2026-11-08T11:00:00Z")}
		case "affected":
			asset.Facts = []snapshot.Fact{advisoryFact("affected", "observed", "high", "2026-11-08T11:00:00Z")}
		case "stale-fixed":
			asset.Facts = []snapshot.Fact{advisoryFact("fixed", "observed", "high", "2026-11-01T11:00:00Z")}
		case "attested-fixed":
			asset.Facts = []snapshot.Fact{advisoryFact("fixed", "attested", "high", "2026-11-08T11:00:00Z")}
		case "low-fixed":
			asset.Facts = []snapshot.Fact{advisoryFact("fixed", "observed", "low", "2026-11-08T11:00:00Z")}
		}
		got := evalPackage("C1", ch, nil, asset, eval, mustAge())
		if inRange && got.Leaf.Value == logic.False {
			t.Fatalf("iter %d advisory %s cleared in-range upstream: %+v packages %+v", i, kind, got, pkgs)
		}
		if inRange && got.Leaf.Value != logic.True {
			t.Fatalf("iter %d advisory %s in-range upstream was %s (%s)", i, kind, got.Leaf.Value, got.Reason)
		}
		if got.Leaf.Value == logic.False && inRange {
			t.Fatalf("iter %d strict false with in-range generic", i)
		}
	}
}

func TestZoneCaseDoesNotDowngradeExploitable(t *testing.T) {
	eval := mustTime(t)
	p := &pack.Pack{
		Metadata: pack.Metadata{
			ID: "ECP-SYNTHETIC-ZONE", CVE: []string{"CVE-2099-0001"},
			Status: "reviewed", ConfidenceCeiling: "high", Synthetic: true,
			Reviewers: []pack.Person{{Name: "synthetic-reviewer-alpha"}, {Name: "synthetic-reviewer-beta"}},
		},
		MaxAge: mustAge(),
		Checks: map[string]pack.Check{
			"C": {Type: "host_fact", Key: "synth.flag", Equals: "true", NegationJustification: "vulnerable_code_not_present"},
		},
		Conditions: pack.Condition{Ref: "C"},
		Exposure:   spec22(),
	}
	asset := snapshot.Asset{
		ID: "z", Name: "z", Kind: "host", Zones: []string{"internal"},
		Inventory: snapshot.Inventory{
			Complete: true, Basis: "observed", Confidence: "high",
			ObservedAt: "2026-11-08T11:00:00Z", EvidenceID: "e-inv",
		},
		Facts: []snapshot.Fact{{
			Key: "synth.flag", Value: "true", Basis: "observed", Confidence: "high",
			ObservedAt: "2026-11-08T11:00:00Z", EvidenceID: "e-f", Source: "caller",
		}},
		Exposure: []snapshot.Exposure{{
			Port: 22, Proto: "tcp", ReachableFrom: []string{"Internet"},
			Basis: "observed", Confidence: "high", ObservedAt: "2026-11-08T11:00:00Z",
			EvidenceID: "e-exp", Source: "caller",
		}},
	}
	rep, err := Evaluate(Input{
		Pack: p,
		Snapshot: &snapshot.Snapshot{
			KBVersion: "demo", EvaluationTime: "2026-11-08T12:00:00Z",
			EvidenceTrust: "caller_asserted", Assets: []snapshot.Asset{asset},
		},
		EvaluationTime: eval,
		KBVersion:      "demo",
	})
	if err != nil {
		t.Fatal(err)
	}
	got := rep.Verdicts[0]
	if got.State != stateExploitable || got.ExposureUncertainty {
		t.Fatalf("Internet must match untrusted zone internet: %+v", got)
	}
	asset.Exposure[0].ReachableFrom = []string{"dmz"}
	rep, err = Evaluate(Input{
		Pack: p,
		Snapshot: &snapshot.Snapshot{
			KBVersion: "demo", EvaluationTime: "2026-11-08T12:00:00Z",
			EvidenceTrust: "caller_asserted", Assets: []snapshot.Asset{asset},
		},
		EvaluationTime: eval, KBVersion: "demo",
	})
	if err != nil {
		t.Fatal(err)
	}
	got = rep.Verdicts[0]
	if got.State != stateExploitable || !got.ExposureUncertainty {
		t.Fatalf("unlisted zone: %+v", got)
	}
}
