// Copyright 2026 Uddeshya Kumar
// SPDX-License-Identifier: Apache-2.0

package engine

import (
	"testing"
	"time"

	"github.com/uddeshya-world/verdict/internal/pack"
	"github.com/uddeshya-world/verdict/internal/snapshot"
)

func spec22() pack.ExposureSpec {
	return pack.ExposureSpec{Port: 22, Proto: "tcp", UntrustedZones: []string{"internet"}}
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
	got := classifyExposure(spec22(), a, mustTime(t), mustAge())
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
	got := classifyExposure(spec22(), a, mustTime(t), mustAge())
	if got.Kind != "unknown" {
		t.Fatalf("inferred internal must not clear exposure: %+v", got)
	}
}

func TestStaleExposureIsUnknown(t *testing.T) {
	a := assetWithZonesOnly()
	a.Exposure = []snapshot.Exposure{{
		Port: 22, Proto: "tcp", ReachableFrom: []string{"internal"},
		Basis: "observed", Confidence: "high", ObservedAt: "2026-11-01T11:00:00Z",
		EvidenceID: "e", Source: "t",
	}}
	got := classifyExposure(spec22(), a, mustTime(t), mustAge())
	if got.Kind != "unknown" {
		t.Fatalf("stale exposure: %+v", got)
	}
}
