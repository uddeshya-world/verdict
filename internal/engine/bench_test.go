// Copyright 2026 Uddeshya Kumar
// SPDX-License-Identifier: Apache-2.0

package engine

import (
	"fmt"
	"os"
	"testing"
	"time"

	"github.com/uddeshya-world/verdict/internal/pack"
	"github.com/uddeshya-world/verdict/internal/policy"
	"github.com/uddeshya-world/verdict/internal/snapshot"
)

// benchSnapshot builds n assets of 13 packages each: one openssh-family
// package (varying spelling and type), a few distro packages, and unrelated
// dependencies, plus advisory and property facts.
func benchSnapshot(n int) *snapshot.Snapshot {
	const ts = "2026-11-08T11:00:00Z"
	opensshPkgs := []snapshot.Package{
		{PURL: "pkg:generic/openssh@9.7p1", Version: "9.7p1"},
		{PURL: "pkg:generic/openssh@9.8p1", Version: "9.8p1"},
		{PURL: "pkg:deb/debian/openssh-server@1:9.2p1-2", Version: "1:9.2p1-2"},
		{PURL: "pkg:generic/OpenSSH@8.9p1", Version: "8.9p1"},
	}
	s := &snapshot.Snapshot{KBVersion: "bench", EvaluationTime: "2026-11-08T12:00:00Z", EvidenceTrust: "caller_asserted"}
	for i := 0; i < n; i++ {
		pkgs := []snapshot.Package{opensshPkgs[i%len(opensshPkgs)]}
		for j := 0; j < 12; j++ {
			v := fmt.Sprintf("3.%d.1", j)
			pkgs = append(pkgs, snapshot.Package{PURL: fmt.Sprintf("pkg:maven/com.example/dep%d@%s", j, v), Version: v})
		}
		a := snapshot.Asset{
			ID: fmt.Sprintf("a%06d", i), Name: "asset", Kind: "host", Zones: []string{"internal"},
			Inventory: snapshot.Inventory{Complete: true, ObservedAt: ts, Basis: "observed", Confidence: "high", EvidenceID: fmt.Sprintf("inv%d", i), Packages: pkgs},
		}
		for k := 0; k < 4; k++ {
			a.Facts = append(a.Facts, snapshot.Fact{Key: fmt.Sprintf("misc.%d", k), Value: "true", Basis: "observed", Confidence: "high", ObservedAt: ts, EvidenceID: fmt.Sprintf("f%d-%d", i, k), Source: "gen"})
		}
		if i%3 == 0 {
			a.Facts = append(a.Facts, snapshot.Fact{Key: "advisory.cve_2024_6387.status", PURL: pkgs[0].PURL, Value: "fixed", Basis: "observed", Confidence: "high", ObservedAt: ts, EvidenceID: fmt.Sprintf("adv%d", i), Source: "gen"})
		}
		s.Assets = append(s.Assets, a)
	}
	return s
}

func benchEvaluate(b *testing.B, n int) {
	data, err := os.ReadFile("../../packs/draft/ecp-cve-2024-6387-openssh.yaml")
	if err != nil {
		b.Fatal(err)
	}
	p, err := pack.Load("ecp-cve-2024-6387-openssh.yaml", data)
	if err != nil {
		b.Fatal(err)
	}
	snap := benchSnapshot(n)
	eval := time.Date(2026, 11, 8, 12, 0, 0, 0, time.UTC)
	in := Input{Pack: p, Policy: &policy.Policy{}, Snapshot: snap, EvaluationTime: eval, KBVersion: "bench"}
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if _, err := Evaluate(in); err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkEvaluate1k(b *testing.B)  { benchEvaluate(b, 1000) }
func BenchmarkEvaluate10k(b *testing.B) { benchEvaluate(b, 10000) }
