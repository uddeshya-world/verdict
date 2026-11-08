// Copyright 2026 Uddeshya Kumar
// SPDX-License-Identifier: Apache-2.0

package engine

import (
	"testing"
	"time"

	"github.com/uddeshya-world/verdict/internal/pack"
	"github.com/uddeshya-world/verdict/internal/policy"
	"github.com/uddeshya-world/verdict/internal/snapshot"
)

func spec22() pack.ExposureSpec {
	return pack.ExposureSpec{Port: 22, Proto: "tcp"}
}

func labPol(t *testing.T) *policy.Policy {
	t.Helper()
	p, err := policy.Load([]byte(`{"untrusted_zones":["internet","partner","user_lan","dmz"],"trusted_zones":["internal","pci"]}`))
	if err != nil {
		t.Fatal(err)
	}
	return p
}

func mustTime(t *testing.T) time.Time {
	t.Helper()
	ts, err := time.Parse(time.RFC3339, "2026-11-08T12:00:00Z")
	if err != nil {
		t.Fatal(err)
	}
	return ts
}

func mustAge() time.Duration { return 24 * time.Hour }

func assetWithZonesOnly() snapshot.Asset {
	return snapshot.Asset{
		ID: "z", Name: "z", Kind: "host", Zones: []string{"internal"},
		Exposure: nil,
	}
}

func TestTrustedObservedIsNotExposedClass(t *testing.T) {
	a := assetWithZonesOnly()
	a.Zones = []string{"internet"} // must not force untrusted
	a.Exposure = []snapshot.Exposure{{
		Port: 22, Proto: "tcp", ReachableFrom: []string{"internal"},
		Basis: "observed", Confidence: "high", ObservedAt: "2026-11-08T11:00:00Z",
		EvidenceID: "e", Source: "t",
	}}
	got := classifyExposure(labPol(t), spec22(), a, mustTime(t), mustAge())
	if got.Kind != "trusted_only" || got.Uncertain {
		t.Fatalf("%+v", got)
	}
}

func TestInferredInternalIsUnknown(t *testing.T) {
	a := assetWithZonesOnly()
	a.Exposure = []snapshot.Exposure{{
		Port: 22, Proto: "tcp", ReachableFrom: []string{"internal"},
		Basis: "inferred", Confidence: "high", ObservedAt: "2026-11-08T11:00:00Z",
		EvidenceID: "e", Source: "t",
	}}
	got := classifyExposure(labPol(t), spec22(), a, mustTime(t), mustAge())
	if got.Kind != "unknown" {
		t.Fatalf("inferred internal must not clear exposure: %+v", got)
	}
}

func TestUnlistedAndMismatchedZonesAreUnknown(t *testing.T) {
	eval := mustTime(t)
	cases := []struct {
		name string
		zone string
		kind string
	}{
		{"canonical untrusted", "internet", "untrusted"},
		{"case variant of untrusted", "Internet", "untrusted"},
		{"canonical trusted", "internal", "trusted_only"},
		{"case variant of trusted", "Internal", "trusted_only"},
		{"unlisted", "corp", "unknown"},
		{"typo", "internel", "unknown"},
		{"wan", "wan", "unknown"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			a := assetWithZonesOnly()
			a.Exposure = []snapshot.Exposure{{
				Port: 22, Proto: "tcp", ReachableFrom: []string{tc.zone},
				Basis: "observed", Confidence: "high", ObservedAt: "2026-11-08T11:00:00Z",
				EvidenceID: "e", Source: "t",
			}}
			got := classifyExposure(labPol(t), spec22(), a, eval, mustAge())
			if got.Kind != tc.kind {
				t.Fatalf("zone %q: got %+v want %s", tc.zone, got, tc.kind)
			}
			if tc.kind == "unknown" && !got.Uncertain {
				t.Fatalf("zone %q must be uncertain: %+v", tc.zone, got)
			}
			if tc.kind != "unknown" && got.Uncertain {
				t.Fatalf("zone %q must not be uncertain: %+v", tc.zone, got)
			}
		})
	}
}

func TestMixedTrustedAndUnlistedIsUnknown(t *testing.T) {
	a := assetWithZonesOnly()
	a.Exposure = []snapshot.Exposure{{
		Port: 22, Proto: "tcp", ReachableFrom: []string{"internal", "guest-wifi"},
		Basis: "observed", Confidence: "high", ObservedAt: "2026-11-08T11:00:00Z",
		EvidenceID: "e", Source: "t",
	}}
	got := classifyExposure(labPol(t), spec22(), a, mustTime(t), mustAge())
	if got.Kind != "unknown" || !got.Uncertain {
		t.Fatalf("%+v", got)
	}
}

func TestStaleExposureIsUnknown(t *testing.T) {
	a := assetWithZonesOnly()
	a.Exposure = []snapshot.Exposure{{
		Port: 22, Proto: "tcp", ReachableFrom: []string{"internal"},
		Basis: "observed", Confidence: "high", ObservedAt: "2026-11-01T11:00:00Z",
		EvidenceID: "e", Source: "t",
	}}
	got := classifyExposure(labPol(t), spec22(), a, mustTime(t), mustAge())
	if got.Kind != "unknown" {
		t.Fatalf("stale exposure: %+v", got)
	}
}
