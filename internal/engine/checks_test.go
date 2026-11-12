// Copyright 2026 Uddeshya Kumar
// SPDX-License-Identifier: Apache-2.0

package engine

import (
	"math/rand"
	"strings"
	"testing"

	"github.com/uddeshya-world/verdict/internal/logic"
	"github.com/uddeshya-world/verdict/internal/pack"
	"github.com/uddeshya-world/verdict/internal/purl"
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

func advisoryFact(value, basis, confidence, observedAt, packagePURL string) snapshot.Fact {
	return snapshot.Fact{
		Key: "advisory.cve_2024_6387.status", PURL: packagePURL, Value: value,
		Basis: basis, Confidence: confidence, ObservedAt: observedAt,
		EvidenceID: "e-adv", Source: "caller",
	}
}

func TestCanonicalPURLAdvisoryMatches(t *testing.T) {
	eval := mustTime(t)
	ch := opensshCheck()
	a := freshInventory(snapshot.Package{
		PURL:    "pkg:deb/ubuntu/openssh-server@1%3A8.9p1-3ubuntu0.10?distro=ubuntu-22.04&arch=amd64",
		Version: "1:8.9p1-3ubuntu0.10",
	})
	a.Facts = []snapshot.Fact{advisoryFact("fixed", "observed", "high", "2026-11-08T11:00:00Z", "pkg:deb/ubuntu/openssh-server@1:8.9p1-3ubuntu0.10?arch=amd64&distro=ubuntu-22.04")}
	got := evalPackage("C1", ch, nil, a, eval, mustAge())
	if got.Leaf.Value != logic.False || got.Leaf.Justification != "vulnerable_code_not_present" {
		t.Fatalf("canonical advisory should cover the encoded package URL: %+v", got)
	}
	a.Facts[0].PURL = "pkg:deb/ubuntu/openssh-server@1:8.9p1-3ubuntu0.10"
	got = evalPackage("C1", ch, nil, a, eval, mustAge())
	if got.Leaf.Value == logic.False {
		t.Fatalf("an advisory without the qualifiers must not clear the package: %+v", got)
	}
}

func TestFixedAdvisoryDoesNotClearInRangeUpstream(t *testing.T) {
	eval := mustTime(t)
	ch := opensshCheck()
	generic := snapshot.Package{PURL: "pkg:generic/openssh@9.0p1", Version: "9.0p1"}
	deb := snapshot.Package{PURL: "pkg:deb/ubuntu/openssh-server@1:9.6p1-3ubuntu13.4", Version: "1:9.6p1-3ubuntu13.4"}

	t.Run("generic and deb", func(t *testing.T) {
		a := freshInventory(generic, deb)
		a.Facts = []snapshot.Fact{advisoryFact("fixed", "observed", "high", "2026-11-08T11:00:00Z", deb.PURL)}
		got := evalPackage("C1", ch, nil, a, eval, mustAge())
		if got.Leaf.Value != logic.True || !got.Leaf.Observed || got.Leaf.Confidence < logic.ConfHigh {
			t.Fatalf("in-range generic must stay true: %+v", got)
		}
	})
	t.Run("generic only", func(t *testing.T) {
		a := freshInventory(generic)
		a.Facts = []snapshot.Fact{advisoryFact("fixed", "observed", "high", "2026-11-08T11:00:00Z", generic.PURL)}
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
		a.Facts = []snapshot.Fact{advisoryFact("fixed", "observed", "high", "2026-11-08T11:00:00Z", deb.PURL)}
		got := evalPackage("C1", ch, nil, a, eval, mustAge())
		if got.Leaf.Value != logic.False || !got.Leaf.Observed {
			t.Fatalf("patched upstream plus fixed distro should be false: %+v", got)
		}
	})
	t.Run("deb only fixed", func(t *testing.T) {
		a := freshInventory(deb)
		a.Facts = []snapshot.Fact{advisoryFact("fixed", "observed", "high", "2026-11-08T11:00:00Z", deb.PURL)}
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
		a.Facts = []snapshot.Fact{advisoryFact("affected", "observed", "high", "2026-11-08T11:00:00Z", deb.PURL)}
		got := evalPackage("C1", ch, nil, a, eval, mustAge())
		if got.Leaf.Value != logic.True {
			t.Fatalf("%+v", got)
		}
	})
	t.Run("out of range generic ignores affected advisory", func(t *testing.T) {
		a := freshInventory(snapshot.Package{PURL: "pkg:generic/openssh@9.8p1", Version: "9.8p1"})
		a.Facts = []snapshot.Fact{advisoryFact("affected", "observed", "high", "2026-11-08T11:00:00Z", "pkg:generic/openssh@9.8p1")}
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
		a.Facts = []snapshot.Fact{advisoryFact("fixed", "observed", "high", "2026-11-08T11:00:00Z", deb.PURL)}
		got := evalPackage("C1", ch, nil, a, eval, mustAge())
		if got.Leaf.Value != logic.Unknown || got.Reason != "unsupported_version" {
			t.Fatalf("%+v", got)
		}
	})
	t.Run("stale advisory does not fall through to sorting", func(t *testing.T) {
		a := freshInventory(deb)
		a.Facts = []snapshot.Fact{advisoryFact("fixed", "observed", "high", "2026-11-01T11:00:00Z", deb.PURL)}
		got := evalPackage("C1", ch, nil, a, eval, mustAge())
		if got.Leaf.Value != logic.Unknown || got.Reason != "stale_evidence" {
			t.Fatalf("%+v", got)
		}
	})
	t.Run("not_affected is distinct from fixed and is scoped", func(t *testing.T) {
		rhel := snapshot.Package{PURL: "pkg:rpm/redhat/openssh-server@8.0p1-10.el8", Version: "8.0p1-10.el8"}
		a := freshInventory(rhel)
		a.Facts = []snapshot.Fact{advisoryFact("not_affected", "observed", "high", "2026-11-08T11:00:00Z", rhel.PURL)}
		got := evalPackage("C1", ch, nil, a, eval, mustAge())
		if got.Leaf.Value != logic.False || !got.Leaf.Observed || got.Leaf.Confidence < logic.ConfHigh {
			t.Fatalf("never-vulnerable advisory: %+v", got)
		}
		a.Facts[0].PURL = ""
		got = evalPackage("C1", ch, nil, a, eval, mustAge())
		if got.Leaf.Value != logic.Unknown || got.Reason != "advisory_purl_required" {
			t.Fatalf("bare advisory: %+v", got)
		}
		a.Facts[0].PURL = "pkg:rpm/redhat/openssh-server@8.0p1-9.el8"
		got = evalPackage("C1", ch, nil, a, eval, mustAge())
		if got.Leaf.Value != logic.Unknown || got.Reason != "distro_advisory_required" {
			t.Fatalf("other purl: %+v", got)
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
		advisoryFact("fixed", "observed", "high", "2026-11-08T11:00:00Z", "pkg:deb/ubuntu/openssh-server@1:9.6p1-3ubuntu13.4"),
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
	rep, err := Evaluate(Input{Pack: p, Policy: labPol(t), Snapshot: snap, EvaluationTime: eval, KBVersion: snap.KBVersion})
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
	advisories := []string{"absent", "fixed", "affected", "not-affected", "stale-fixed", "attested-fixed", "low-fixed"}
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
		target := ""
		for _, pkg := range pkgs {
			if strings.HasPrefix(pkg.PURL, "pkg:deb/") || strings.HasPrefix(pkg.PURL, "pkg:rpm/") {
				target = pkg.PURL
				break
			}
		}
		if target == "" && len(pkgs) > 0 && rng.Intn(2) == 0 {
			target = pkgs[0].PURL
		}
		kind := advisories[rng.Intn(len(advisories))]
		switch kind {
		case "fixed":
			asset.Facts = []snapshot.Fact{advisoryFact("fixed", "observed", "high", "2026-11-08T11:00:00Z", target)}
		case "affected":
			asset.Facts = []snapshot.Fact{advisoryFact("affected", "observed", "high", "2026-11-08T11:00:00Z", target)}
		case "stale-fixed":
			asset.Facts = []snapshot.Fact{advisoryFact("fixed", "observed", "high", "2026-11-01T11:00:00Z", target)}
		case "attested-fixed":
			asset.Facts = []snapshot.Fact{advisoryFact("fixed", "attested", "high", "2026-11-08T11:00:00Z", target)}
		case "low-fixed":
			asset.Facts = []snapshot.Fact{advisoryFact("fixed", "observed", "low", "2026-11-08T11:00:00Z", target)}
		case "not-affected":
			asset.Facts = []snapshot.Fact{advisoryFact("not_affected", "observed", "high", "2026-11-08T11:00:00Z", target)}
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
		Pack: p, Policy: labPol(t),
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
	asset.Exposure[0].ReachableFrom = []string{"corp"}
	rep, err = Evaluate(Input{
		Pack: p, Policy: labPol(t),
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

// F1: a name or type variant of the component, an alias, or a package an
// advisory names is never proof of absence.
func TestPackageVariantsAreNotAbsence(t *testing.T) {
	eval := mustTime(t)
	ch := opensshCheck()
	for _, raw := range []string{
		"pkg:generic/OpenSSH@9.6p1",
		"pkg:generic/openssh%20@9.6p1",
		"pkg:generic/openssh-portable@9.6p1",
		"pkg:generic/Open_SSH@9.6p1",
		"pkg:deb/ubuntu/OpenSSH-Server@1:8.9p1-3",
		"pkg:apk/alpine/openssh-server-pam@9.6_p1-r0",
	} {
		p, err := purl.Parse(raw)
		if err != nil {
			t.Fatal(err)
		}
		got := evalPackage("C1", ch, nil, freshInventory(snapshot.Package{PURL: raw, Version: p.Version}), eval, mustAge())
		if got.Leaf.Value != logic.Unknown || got.Reason != "distro_advisory_required" {
			t.Errorf("%s: variant must be unknown, got %+v", raw, got)
		}
	}
}

func TestVariantWithAdvisoryUsesThatAdvisory(t *testing.T) {
	eval := mustTime(t)
	ch := opensshCheck()
	raw := "pkg:deb/ubuntu/OpenSSH-Server@1:8.9p1-3"
	a := freshInventory(snapshot.Package{PURL: raw, Version: "1:8.9p1-3"})
	a.Facts = []snapshot.Fact{advisoryFact("affected", "observed", "high", "2026-11-08T11:00:00Z", raw)}
	if got := evalPackage("C1", ch, nil, a, eval, mustAge()); got.Leaf.Value != logic.True {
		t.Fatalf("affected advisory on the variant must hold: %+v", got)
	}
	// An advisory written on a spelling variant of the package is not applied.
	a.Facts[0] = advisoryFact("fixed", "observed", "high", "2026-11-08T11:00:00Z", "pkg:deb/ubuntu/openssh-server@1:8.9p1-3")
	if got := evalPackage("C1", ch, nil, a, eval, mustAge()); got.Leaf.Value != logic.Unknown || got.Reason != "advisory_purl_variant" {
		t.Fatalf("fixed on a different spelling must not clear: %+v", got)
	}
}

func TestAdvisoryKeepsUnrelatedPackageInScope(t *testing.T) {
	eval := mustTime(t)
	ch := opensshCheck()
	raw := "pkg:generic/sshd-bundle@9.6p1"
	a := freshInventory(snapshot.Package{PURL: raw, Version: "9.6p1"})
	a.Facts = []snapshot.Fact{advisoryFact("affected", "observed", "high", "2026-11-08T11:00:00Z", raw)}
	if got := evalPackage("C1", ch, nil, a, eval, mustAge()); got.Leaf.Value != logic.True {
		t.Fatalf("a package an advisory names stays in scope: %+v", got)
	}
	a.Facts[0].PURL = "pkg:generic/openssh@9.6p1"
	if got := evalPackage("C1", ch, nil, a, eval, mustAge()); got.Leaf.Value != logic.Unknown || got.Reason != "advisory_without_package" {
		t.Fatalf("an advisory for a package missing from a complete inventory blocks absence: %+v", got)
	}
}

func TestUnrelatedPackageIsStillAbsence(t *testing.T) {
	eval := mustTime(t)
	ch := opensshCheck()
	a := freshInventory(snapshot.Package{PURL: "pkg:deb/ubuntu/openssh-client@1:8.9p1-3", Version: "1:8.9p1-3"})
	got := evalPackage("C1", ch, nil, a, eval, mustAge())
	if got.Leaf.Value != logic.False || got.Leaf.Justification != "component_not_present" {
		t.Fatalf("openssh-client alone is not sshd: %+v", got)
	}
}

// F2: every spelling of an advisory purl is considered; disagreement is
// unknown in either order.
func TestConflictingAdvisoriesAreOrderIndependent(t *testing.T) {
	eval := mustTime(t)
	ch := opensshCheck()
	pkg := "pkg:deb/ubuntu/openssh-server@1:8.9p1-3?arch=amd64&distro=ubuntu-22.04"
	spellings := []string{
		"pkg:deb/ubuntu/openssh-server@1%3A8.9p1-3?arch=amd64&distro=ubuntu-22.04",
		"pkg:deb/ubuntu/openssh-server@1:8.9p1-3?distro=ubuntu-22.04&arch=amd64",
		"pkg:deb/ubuntu/OpenSSH-Server@1:8.9p1-3?arch=amd64&distro=ubuntu-22.04",
	}
	for _, other := range spellings {
		fixed := advisoryFact("fixed", "observed", "high", "2026-11-08T11:00:00Z", other)
		affected := advisoryFact("affected", "observed", "high", "2026-11-08T11:00:00Z", pkg)
		for _, facts := range [][]snapshot.Fact{{fixed, affected}, {affected, fixed}} {
			a := freshInventory(snapshot.Package{PURL: pkg, Version: "1:8.9p1-3"})
			a.Facts = facts
			got := evalPackage("C1", ch, nil, a, eval, mustAge())
			if got.Leaf.Value != logic.Unknown || got.Reason != "conflicting_advisory" {
				t.Fatalf("%s order %s first: %+v", other, facts[0].Value, got)
			}
		}
	}
	// Agreeing spellings use the weakest quality.
	a := freshInventory(snapshot.Package{PURL: pkg, Version: "1:8.9p1-3"})
	a.Facts = []snapshot.Fact{
		advisoryFact("fixed", "observed", "high", "2026-11-08T11:00:00Z", spellings[0]),
		advisoryFact("fixed", "observed", "medium", "2026-11-08T11:00:00Z", spellings[1]),
	}
	got := evalPackage("C1", ch, nil, a, eval, mustAge())
	if got.Leaf.Value != logic.False || got.Leaf.Confidence != logic.ConfMedium {
		t.Fatalf("agreeing advisories must take the weakest confidence: %+v", got)
	}
}

// F6: the OpenVEX product is the matched component, never an unrelated package.
func TestPrimaryPURLIsMatchedComponent(t *testing.T) {
	p := &pack.Pack{Checks: map[string]pack.Check{"C1": opensshCheck()}}
	p.Component.Purls = []string{"pkg:generic/openssh"}
	base := snapshot.Package{PURL: "pkg:apk/alpine/alpine-baselayout-data@3.6.5-r0", Version: "3.6.5-r0"}
	ssh := snapshot.Package{PURL: "pkg:apk/alpine/openssh-server@9.6_p1-r0", Version: "9.6_p1-r0"}
	if got := primaryPURL(p, newAssetCtx(newEvalCtx(), freshInventory(base))); got != "" {
		t.Fatalf("no component: want empty, got %s", got)
	}
	if got := primaryPURL(p, newAssetCtx(newEvalCtx(), freshInventory(base, ssh))); got != ssh.PURL {
		t.Fatalf("want matched component, got %s", got)
	}
	two := freshInventory(base, ssh, snapshot.Package{PURL: "pkg:generic/openssh@9.6p1", Version: "9.6p1"})
	if got := primaryPURL(p, newAssetCtx(newEvalCtx(), two)); got != "" {
		t.Fatalf("ambiguous: want empty, got %s", got)
	}
	asset := freshInventory(base)
	asset.PrimaryPURL = "pkg:oci/app@sha256%3Aabc"
	if got := primaryPURL(p, newAssetCtx(newEvalCtx(), asset)); got != asset.PrimaryPURL {
		t.Fatalf("caller primary_purl wins: %s", got)
	}
}

// N1: a name that is a homoglyph or compat spelling of the component, or holds
// a rune the skeleton does not map, is never absent.
func TestHomoglyphNamesAreNotAbsence(t *testing.T) {
	eval := mustTime(t)
	ch := opensshCheck()
	for _, raw := range []string{
		"pkg:generic/%D0%BEpenssh@9.6p1",
		"pkg:generic/\u043epenssh@9.6p1",
		"pkg:generic/\uff4f\uff50\uff45\uff4e\uff53\uff53\uff48@9.6p1",
		"pkg:generic/open\u017f\u017fh@9.6p1",
		"pkg:generic/opensshd@9.6p1",
		"pkg:generic/openssh9@9.6p1",
		"pkg:npm/zlib\u200b@1.0.0", // unmapped non-ASCII: unknown for every pattern
	} {
		p, err := purl.Parse(raw)
		if err != nil {
			t.Fatal(err)
		}
		got := evalPackage("C1", ch, nil, freshInventory(snapshot.Package{PURL: raw, Version: p.Version}), eval, mustAge())
		if got.Leaf.Value != logic.Unknown {
			t.Errorf("%s: must be unknown, got %+v", raw, got)
		}
	}
}

func TestAbsenceContradictedByRunningFact(t *testing.T) {
	eval := mustTime(t)
	ch := opensshCheck()
	ch.AbsenceContradictedBy = []string{"process.listening.sshd", "service.socket_activation.sshd"}
	inv := func(key, value, basis string) snapshot.Asset {
		a := freshInventory(snapshot.Package{PURL: "pkg:generic/sshd@9.6p1", Version: "9.6p1"})
		if key != "" {
			a.Facts = []snapshot.Fact{{Key: key, Value: value, Basis: basis, Confidence: "high", ObservedAt: "2026-11-08T11:00:00Z", EvidenceID: "e-run", Source: "t"}}
		}
		return a
	}
	for _, c := range []struct{ key, value, basis string }{
		{"process.listening.sshd", "true", "observed"},
		{"service.socket_activation.sshd", "true", "attested"},
		{"process.listening.sshd", "true", "inferred"},
	} {
		got := evalPackage("C1", ch, nil, inv(c.key, c.value, c.basis), eval, mustAge())
		if got.Leaf.Value != logic.Unknown || got.Reason != "component_absent_but_in_use" {
			t.Errorf("%+v: %+v", c, got)
		}
		found := false
		for _, id := range got.Leaf.EvidenceIDs {
			found = found || id == "e-run"
		}
		if !found {
			t.Errorf("%+v: evidence id of the fact missing: %v", c, got.Leaf.EvidenceIDs)
		}
	}
	// Unrelated package name so the inventory really has no match.
	plain := freshInventory(snapshot.Package{PURL: "pkg:generic/zlib@1.3", Version: "1.3"})
	plain.Facts = []snapshot.Fact{{Key: "process.listening.sshd", Value: "true", Basis: "observed", Confidence: "high", ObservedAt: "2026-11-08T11:00:00Z", EvidenceID: "e-run", Source: "t"}}
	if got := evalPackage("C1", ch, nil, plain, eval, mustAge()); got.Reason != "component_absent_but_in_use" || got.Leaf.Value != logic.Unknown {
		t.Fatalf("sshd listening with no openssh package: %+v", got)
	}
	// A false fact, a missing fact, or no listed key still proves absence.
	plain.Facts[0].Value = "false"
	if got := evalPackage("C1", ch, nil, plain, eval, mustAge()); got.Leaf.Value != logic.False {
		t.Fatalf("false fact must not block: %+v", got)
	}
	plain.Facts = nil
	if got := evalPackage("C1", ch, nil, plain, eval, mustAge()); got.Leaf.Value != logic.False {
		t.Fatalf("no fact must not block: %+v", got)
	}
	plain.Facts = []snapshot.Fact{{Key: "process.listening.sshd", Value: "true", Basis: "observed", Confidence: "high", ObservedAt: "2026-11-08T11:00:00Z", EvidenceID: "e-run", Source: "t"}}
	if got := evalPackage("C1", opensshCheck(), nil, plain, eval, mustAge()); got.Leaf.Value != logic.False {
		t.Fatalf("a pack that lists no key is unchanged: %+v", got)
	}
}

func hostFact(key, value, purlStr string) snapshot.Fact {
	return snapshot.Fact{Key: key, PURL: purlStr, Value: value, Basis: "observed", Confidence: "high", ObservedAt: "2026-11-08T11:00:00Z", EvidenceID: "e-v", Source: "t"}
}

// Run 4 H1/H2/M1: any spelling of a listed key, scoped or not, with any
// value other than false contradicts absence.
func TestAbsenceContradictedByAnyNonFalseValue(t *testing.T) {
	eval := mustTime(t)
	ch := opensshCheck()
	ch.AbsenceContradictedBy = []string{"process.listening.sshd"}
	plain := func(f snapshot.Fact) snapshot.Asset {
		a := freshInventory(snapshot.Package{PURL: "pkg:generic/zlib@1.3", Version: "1.3"})
		a.Facts = []snapshot.Fact{f}
		return a
	}
	k := "process.listening.sshd"
	for _, f := range []snapshot.Fact{
		hostFact(k, "True", ""), hostFact(k, "yes", ""), hostFact(k, "1", ""), hostFact(k, "on", ""),
		hostFact(k, "running", ""), hostFact(k, " true", ""), hostFact(k, "true ", ""), hostFact(k, "TRUE", ""),
		hostFact(k, "", ""), hostFact(k, "true", "pkg:generic/openssh@9.6p1"),
		hostFact("Process.Listening.sshd", "true", ""), hostFact(" process.listening.sshd", "true", ""),
	} {
		if got := evalPackage("C1", ch, nil, plain(f), eval, mustAge()); got.Leaf.Value != logic.Unknown || got.Reason != "component_absent_but_in_use" {
			t.Errorf("%+v must block absence: %+v", f, got)
		}
	}
	if got := evalPackage("C1", ch, nil, plain(hostFact(k, "false", "")), eval, mustAge()); got.Leaf.Value != logic.False {
		t.Errorf("canonical false must not block: %+v", got)
	}
	for _, v := range []string{" False ", "FALSE", "false "} {
		if got := evalPackage("C1", ch, nil, plain(hostFact(k, v, "")), eval, mustAge()); got.Leaf.Value == logic.False {
			t.Errorf("non-canonical %q must block absence: %+v", v, got)
		}
	}
	// Unrelated keys (residual M1: sshd2) are not matched.
	if got := evalPackage("C1", ch, nil, plain(hostFact("process.listening.sshd2", "true", "")), eval, mustAge()); got.Leaf.Value != logic.False {
		t.Errorf("sshd2 residual: %+v", got)
	}
}

// Run 4 H3: a non-canonical or out-of-domain fact value never falsifies an
// equals leaf, and a folded key never reads as missing or false.
func TestEqualsLeafNormalisedValues(t *testing.T) {
	eval := mustTime(t)
	asset := func(f snapshot.Fact) snapshot.Asset {
		a := freshInventory()
		a.Facts = []snapshot.Fact{f}
		return a
	}
	cases := []struct {
		key, equals string
		fact        snapshot.Fact
		want        string
	}{
		{"service.socket_activation.sshd", "false", hostFact("service.socket_activation.sshd", "True", ""), "fact_value_not_boolean"},
		{"service.socket_activation.sshd", "true", hostFact("service.socket_activation.sshd", "yes", ""), "fact_value_not_boolean"},
		{"service.socket_activation.sshd", "false", hostFact("service.socket_activation.sshd", "1", ""), "fact_value_not_boolean"},
		{"service.socket_activation.sshd", "false", hostFact("service.socket_activation.sshd", "on", ""), "fact_value_not_boolean"},
		{"service.socket_activation.sshd", "false", hostFact("service.socket_activation.sshd", "running", ""), "fact_value_not_boolean"},
		{"service.socket_activation.sshd", "true", hostFact("service.socket_activation.sshd", " true", ""), "fact_value_not_canonical"},
		{"libc.family", "musl", hostFact("libc.family", "Musl", ""), "fact_value_not_canonical"},
		{"libc.family", "musl", hostFact("libc.family", "Glibc", ""), "fact_value_out_of_domain"},
		{"libc.family", "musl", hostFact("libc.family", "uclibc", ""), "fact_value_out_of_domain"},
		{"service.socket_activation.sshd", "false", hostFact("Service.Socket_Activation.sshd", "true", ""), "fact_key_not_canonical"},
		{"process.listening.sshd", "false", hostFact("Process.Listening.sshd", "true", ""), "fact_key_not_canonical"},
	}
	for _, c := range cases {
		ch := pack.Check{Type: "host_fact", Key: c.key, Equals: c.equals}
		got := evalCheck("C1", ch, nil, newAssetCtx(newEvalCtx(), asset(c.fact)), eval, mustAge())
		if got.Leaf.Value != logic.Unknown || got.Reason != c.want {
			t.Errorf("%s=%q vs %q: want unknown %s, got %+v", c.fact.Key, c.fact.Value, c.equals, c.want, got)
		}
	}
	// Process leaves: a purl-scoped fact is not the process fact; a folded key is unknown.
	for _, typ := range []string{"process_listening", "process_running"} {
		ch := pack.Check{Type: typ, Process: "sshd"}
		for _, f := range []snapshot.Fact{
			hostFact("Process.Listening.sshd", "false", ""), hostFact("Process.Running.sshd", "false", ""),
			hostFact("process.listening.sshd", "yes", ""), hostFact("process.running.sshd", "True", ""),
		} {
			if got := evalCheck("C1", ch, nil, newAssetCtx(newEvalCtx(), asset(f)), eval, mustAge()); got.Leaf.Value == logic.False {
				t.Errorf("%s with %+v must not be false: %+v", typ, f, got)
			}
		}
	}
	// Controls: canonical values still evaluate.
	ch := pack.Check{Type: "host_fact", Key: "libc.family", Equals: "musl"}
	if got := evalCheck("C1", ch, nil, newAssetCtx(newEvalCtx(), asset(hostFact("libc.family", "glibc", ""))), eval, mustAge()); got.Leaf.Value != logic.False {
		t.Errorf("glibc vs musl must stay false: %+v", got)
	}
	if got := evalCheck("C1", ch, nil, newAssetCtx(newEvalCtx(), asset(hostFact("libc.family", "musl", ""))), eval, mustAge()); got.Leaf.Value != logic.True {
		t.Errorf("musl vs musl must stay true: %+v", got)
	}
}
