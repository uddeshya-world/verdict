// Copyright 2026 Uddeshya Kumar
// SPDX-License-Identifier: Apache-2.0

package engine

import (
	"testing"

	"github.com/uddeshya-world/verdict/internal/logic"
	"github.com/uddeshya-world/verdict/internal/pack"
	"github.com/uddeshya-world/verdict/internal/snapshot"
)

func specPortFact() pack.ExposureSpec {
	return pack.ExposureSpec{Proto: "tcp", PortFact: "config.sshd.Port"}
}

func portFact(v string) snapshot.Fact {
	return snapshot.Fact{
		Key: "config.sshd.Port", Value: v, Basis: "observed", Confidence: "high",
		ObservedAt: "2026-11-08T11:00:00Z", EvidenceID: "e-port", Source: "t",
	}
}

func expo(port int, zones ...string) snapshot.Exposure {
	return snapshot.Exposure{
		Port: port, Proto: "tcp", ReachableFrom: zones,
		Basis: "observed", Confidence: "high", ObservedAt: "2026-11-08T11:00:00Z",
		EvidenceID: "e-exp", Source: "t",
	}
}

// Packet Q5: sshd on 2222, an internal-only observation on 22. A fixed port
// 22 gives trusted_only and so vulnerable_not_exposed; the port fact must
// make it unknown, which is exploitable.
func TestPortFactSSHDOn2222WithInternal22IsNotTrustedOnly(t *testing.T) {
	a := assetWithZonesOnly()
	a.Facts = []snapshot.Fact{portFact("2222")}
	a.Exposure = []snapshot.Exposure{expo(22, "internal")}
	got := classifyExposure(labPol(t), specPortFact(), a, mustTime(t), mustAge())
	if got.Kind != "unknown" || !got.Uncertain {
		t.Fatalf("sshd on 2222 must not be trusted_only from a 22 observation: %+v", got)
	}
	d := Decide(logic.Result{Value: logic.True, TrueConf: logic.ConfHigh}, Meta{Status: "reviewed", Reviewers: 2, Ceiling: logic.ConfHigh}, got)
	if d.State != stateExploitable || !d.Uncertainty {
		t.Fatalf("decision: %+v", d)
	}
	a.Exposure = append(a.Exposure, expo(2222, "internet"))
	if got := classifyExposure(labPol(t), specPortFact(), a, mustTime(t), mustAge()); got.Kind != "untrusted" {
		t.Fatalf("2222 from internet: %+v", got)
	}
}

func TestPortFactAbsentIsUnobserved(t *testing.T) {
	a := assetWithZonesOnly()
	a.Exposure = []snapshot.Exposure{expo(22, "internal")}
	got := classifyExposure(labPol(t), specPortFact(), a, mustTime(t), mustAge())
	if got.Kind != "unknown" || !got.Uncertain || got.Reason != "exposure_port_unobserved" {
		t.Fatalf("absent port fact must not fall back to 22: %+v", got)
	}
	d := Decide(logic.Result{Value: logic.True, TrueConf: logic.ConfHigh}, Meta{}, got)
	if d.State != stateExploitable || !d.Uncertainty || !contains(d.Reasons, "exposure_port_unobserved") || !contains(d.Reasons, "exposure_unknown_treated_as_exposed") {
		t.Fatalf("decision: %+v", d)
	}
	if h := decisionHint("exposure_port_unobserved"); h == "exposure_port_unobserved" {
		t.Fatal("no hint text for exposure_port_unobserved")
	}
}

func TestPortFactNonCanonicalIsUnknown(t *testing.T) {
	for _, v := range []string{"", "0", "65536", "022", "22 ", " 22", "22, 2222", "2222,22", "22,22", "22,", "ssh", "22;2222", "-1", "1e3"} {
		a := assetWithZonesOnly()
		a.Facts = []snapshot.Fact{portFact(v)}
		a.Exposure = []snapshot.Exposure{expo(22, "internal")}
		got := classifyExposure(labPol(t), specPortFact(), a, mustTime(t), mustAge())
		if got.Kind != "unknown" || !got.Uncertain || got.Reason != "exposure_port_not_canonical" {
			t.Errorf("%q: %+v", v, got)
		}
	}
}

func TestPortFactKeyVariantsAreNotCanonical(t *testing.T) {
	cases := map[string][]snapshot.Fact{
		"case variant":  {func() snapshot.Fact { f := portFact("22"); f.Key = "config.sshd.port"; return f }()},
		"space variant": {func() snapshot.Fact { f := portFact("22"); f.Key = "config.sshd.Port "; return f }()},
		"purl scoped":   {func() snapshot.Fact { f := portFact("22"); f.PURL = "pkg:generic/openssh@9.6p1"; return f }()},
		"exact plus variant": {portFact("22"), func() snapshot.Fact {
			f := portFact("2222")
			f.Key = "Config.sshd.Port"
			return f
		}()},
	}
	for name, facts := range cases {
		a := assetWithZonesOnly()
		a.Facts = facts
		a.Exposure = []snapshot.Exposure{expo(22, "internal")}
		got := classifyExposure(labPol(t), specPortFact(), a, mustTime(t), mustAge())
		if got.Kind != "unknown" || got.Reason != "exposure_port_not_canonical" {
			t.Errorf("%s: %+v", name, got)
		}
	}
}

func TestPortFactEvidenceBar(t *testing.T) {
	cases := map[string]func(*snapshot.Fact){
		"attested":  func(f *snapshot.Fact) { f.Basis = "attested" },
		"inferred":  func(f *snapshot.Fact) { f.Basis = "inferred" },
		"medium":    func(f *snapshot.Fact) { f.Confidence = "medium" },
		"low":       func(f *snapshot.Fact) { f.Confidence = "low" },
		"stale":     func(f *snapshot.Fact) { f.ObservedAt = "2026-11-01T11:00:00Z" },
		"future":    func(f *snapshot.Fact) { f.ObservedAt = "2026-11-09T11:00:00Z" },
		"expired":   func(f *snapshot.Fact) { f.ExpiresAt = "2026-11-08T11:30:00Z" },
		"bad time":  func(f *snapshot.Fact) { f.ObservedAt = "yesterday" },
		"bad basis": func(f *snapshot.Fact) { f.Basis = "Observed" },
	}
	for name, mut := range cases {
		a := assetWithZonesOnly()
		f := portFact("22")
		mut(&f)
		a.Facts = []snapshot.Fact{f}
		a.Exposure = []snapshot.Exposure{expo(22, "internal")}
		got := classifyExposure(labPol(t), specPortFact(), a, mustTime(t), mustAge())
		if got.Kind != "unknown" || got.Reason != "exposure_port_evidence_insufficient" {
			t.Errorf("%s: %+v", name, got)
		}
	}
}

func TestPortFactMultiplePortsAnyExposed(t *testing.T) {
	cases := []struct {
		name string
		exp  []snapshot.Exposure
		kind string
	}{
		{"both trusted", []snapshot.Exposure{expo(22, "internal"), expo(2222, "pci")}, "trusted_only"},
		{"one untrusted", []snapshot.Exposure{expo(22, "internal"), expo(2222, "internet")}, "untrusted"},
		{"one unobserved", []snapshot.Exposure{expo(22, "internal")}, "unknown"},
		{"one unlisted zone", []snapshot.Exposure{expo(22, "internal"), expo(2222, "guest")}, "unknown"},
		{"only other ports", []snapshot.Exposure{expo(443, "internal")}, "unknown"},
	}
	for _, tc := range cases {
		a := assetWithZonesOnly()
		a.Facts = []snapshot.Fact{portFact("22,2222")}
		a.Exposure = tc.exp
		got := classifyExposure(labPol(t), specPortFact(), a, mustTime(t), mustAge())
		if got.Kind != tc.kind {
			t.Errorf("%s: %+v want %s", tc.name, got, tc.kind)
		}
		if got.Kind == "trusted_only" && !contains(got.EvidenceIDs, "e-port") {
			t.Errorf("%s: port fact evidence not cited: %+v", tc.name, got)
		}
	}
}

func TestPortFactSingleTrustedIsTrustedOnly(t *testing.T) {
	a := assetWithZonesOnly()
	a.Facts = []snapshot.Fact{portFact("22")}
	a.Exposure = []snapshot.Exposure{expo(22, "internal")}
	got := classifyExposure(labPol(t), specPortFact(), a, mustTime(t), mustAge())
	if got.Kind != "trusted_only" || got.Uncertain {
		t.Fatalf("%+v", got)
	}
}

func contains(list []string, s string) bool {
	for _, v := range list {
		if v == s {
			return true
		}
	}
	return false
}
