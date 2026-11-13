// Copyright 2026 Uddeshya Kumar
// SPDX-License-Identifier: Apache-2.0

package engine

import (
	"testing"

	"github.com/uddeshya-world/verdict/internal/snapshot"
)

func TestAgentDowngrade(t *testing.T) {
	asset := snapshot.Asset{
		ID: "a",
		Facts: []snapshot.Fact{
			{Key: "libc.family", Value: "musl", Basis: "observed", EvidenceID: "sha256:aa"},
			{Key: "other", Value: "x", Basis: "observed", EvidenceID: "sha256:bb"},
			{Key: "legacy", Value: "y", Basis: "observed", EvidenceID: "sha256:cc"},
		},
		Exposure: []snapshot.Exposure{
			{Port: 22, Proto: "tcp", Basis: "observed", ReachableFrom: []string{"internal"}},
			{Port: 443, Proto: "tcp", Basis: "observed", ReachableFrom: []string{"internal"}},
		},
		Edits: []snapshot.EditRecord{
			{Op: snapshot.OpSetFact, Key: "libc.family", ActorKind: snapshot.ActorAgent},
			{Op: snapshot.OpSetFact, Key: "other", ActorKind: snapshot.ActorAgent},
			{Op: snapshot.OpSetFact, Key: "other", ActorKind: snapshot.ActorHuman},
			{Op: snapshot.OpSetFact, Key: "legacy"}, // pre-actor record: human
			{Op: snapshot.OpSetExposure, Port: 22, Proto: "tcp", ActorKind: snapshot.ActorAgent},
		},
	}
	got, ev := agentDowngrade(asset)
	if got.Facts[0].Basis != "attested" || !ev["sha256:aa"] {
		t.Fatalf("agent fact not downgraded: %+v %v", got.Facts[0], ev)
	}
	if got.Facts[1].Basis != "observed" || got.Facts[2].Basis != "observed" || ev["sha256:bb"] || ev["sha256:cc"] {
		t.Fatalf("human-latest fact downgraded: %+v", got.Facts)
	}
	if got.Exposure[0].Basis != "attested" || got.Exposure[1].Basis != "observed" {
		t.Fatalf("exposure: %+v", got.Exposure)
	}
	if asset.Facts[0].Basis != "observed" || asset.Exposure[0].Basis != "observed" {
		t.Fatal("caller's asset was modified")
	}
	// An agent-downgraded exposure entry is not usable exposure evidence.
	plain, _ := agentDowngrade(snapshot.Asset{Facts: asset.Facts})
	if plain.Facts[0].Basis != "observed" {
		t.Fatal("asset without edits changed")
	}
}
