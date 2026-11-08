// Copyright 2026 Uddeshya Kumar
// SPDX-License-Identifier: Apache-2.0

package engine

import (
	"os"
	"testing"

	"github.com/uddeshya-world/verdict/internal/pack"
	"github.com/uddeshya-world/verdict/internal/rootpath"
	"github.com/uddeshya-world/verdict/internal/snapshot"
)

// promoteReviewed simulates a reviewed pack in memory. It does not write
// reviewer names into the pack file.
func promoteReviewed(t *testing.T, path string) *pack.Pack {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	p, err := pack.Load(path, data)
	if err != nil {
		t.Fatal(err)
	}
	p.Metadata.Status = "reviewed"
	p.Metadata.Reviewers = []pack.Person{{Name: "synthetic-reviewer-alpha"}, {Name: "synthetic-reviewer-beta"}}
	return p
}

func fact(key, value string) snapshot.Fact {
	return snapshot.Fact{
		Key: key, Value: value, Basis: "observed", Confidence: "high",
		ObservedAt: "2026-11-08T11:00:00Z", EvidenceID: "e-" + key, Source: "caller",
	}
}

func evalOne(t *testing.T, p *pack.Pack, asset snapshot.Asset) Verdict {
	t.Helper()
	asset.Kind = "host"
	if asset.Name == "" {
		asset.Name = asset.ID
	}
	snap := &snapshot.Snapshot{
		KBVersion: "demo-2026.11.08", EvaluationTime: "2026-11-08T12:00:00Z",
		EvidenceTrust: "caller_asserted", Assets: []snapshot.Asset{asset},
	}
	rep, err := Evaluate(Input{Pack: p, Policy: labPol(t), Snapshot: snap, EvaluationTime: mustTime(t), KBVersion: snap.KBVersion})
	if err != nil {
		t.Fatal(err)
	}
	if len(rep.Verdicts) != 1 {
		t.Fatalf("verdicts: %+v", rep.Verdicts)
	}
	return rep.Verdicts[0]
}

func TestReviewedXZDoesNotClearWhenSSHDIsDown(t *testing.T) {
	root, err := rootpath.Find()
	if err != nil {
		t.Fatal(err)
	}
	p := promoteReviewed(t, root+"/packs/draft/ecp-cve-2024-3094-xz.yaml")
	asset := freshInventory(snapshot.Package{PURL: "pkg:generic/xz@5.6.1", Version: "5.6.1"})
	asset.ID = "xz-down"
	asset.Facts = []snapshot.Fact{
		fact("process.sshd.links_liblzma", "false"),
		fact("process.listening.sshd", "false"),
	}
	asset.Exposure = []snapshot.Exposure{{
		Port: 22, Proto: "tcp", ReachableFrom: []string{"internet"},
		Basis: "observed", Confidence: "high", ObservedAt: "2026-11-08T11:00:00Z",
		EvidenceID: "e-exp", Source: "caller",
	}}
	got := evalOne(t, p, asset)
	if got.State != stateExploitable || got.VEXStatus != vexAffected || got.Justification != "" {
		t.Fatalf("backdoored xz with sshd down: %+v", got)
	}
}

func TestReviewedRegreSSHionSocketActivationDoesNotClear(t *testing.T) {
	root, err := rootpath.Find()
	if err != nil {
		t.Fatal(err)
	}
	p := promoteReviewed(t, root+"/packs/draft/ecp-cve-2024-6387-openssh.yaml")
	base := freshInventory(snapshot.Package{PURL: "pkg:generic/openssh@9.6p1", Version: "9.6p1"})
	base.Exposure = []snapshot.Exposure{{
		Port: 22, Proto: "tcp", ReachableFrom: []string{"internet"},
		Basis: "observed", Confidence: "high", ObservedAt: "2026-11-08T11:00:00Z",
		EvidenceID: "e-exp", Source: "caller",
	}}
	with := func(id string, facts ...snapshot.Fact) snapshot.Asset {
		a := base
		a.ID = id
		a.Facts = append([]snapshot.Fact{
			fact("libc.family", "glibc"),
			fact("config.sshd.LoginGraceTime", "120"),
		}, facts...)
		return a
	}
	socket := evalOne(t, p, with("socket", fact("process.listening.sshd", "false"), fact("service.socket_activation.sshd", "true")))
	if socket.State != stateExploitable || socket.Justification != "" {
		t.Fatalf("socket activation: %+v", socket)
	}
	missing := evalOne(t, p, with("missing", fact("process.listening.sshd", "false")))
	if missing.State == stateNotAffected || missing.VEXStatus == vexNotAffected {
		t.Fatalf("missing socket fact cleared the host: %+v", missing)
	}
	if missing.State != stateNeedsReview {
		t.Fatalf("missing socket fact: %+v", missing)
	}
	bothDown := evalOne(t, p, with("both-down", fact("process.listening.sshd", "false"), fact("service.socket_activation.sshd", "false")))
	if bothDown.State != stateNotAffected || bothDown.Justification != "vulnerable_code_not_in_execute_path" {
		t.Fatalf("both reachability facts false: %+v", bothDown)
	}
}
