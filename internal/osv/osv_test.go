// Copyright 2026 Uddeshya Kumar
// SPDX-License-Identifier: Apache-2.0

package osv

import (
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/uddeshya-world/verdict/internal/engine"
	"github.com/uddeshya-world/verdict/internal/policy"
	"github.com/uddeshya-world/verdict/internal/snapshot"
)

func root(t *testing.T) string {
	t.Helper()
	_, file, _, _ := runtime.Caller(0)
	return filepath.Join(filepath.Dir(file), "..", "..")
}

const eval = "2026-11-08T12:00:00Z"

func rec(eco, name string, ranges string) string {
	return `{"id":"GHSA-test-0001","aliases":["CVE-2099-0001"],"summary":"test","affected":[{"package":{"ecosystem":"` + eco + `","name":"` + name + `"},"ranges":` + ranges + `}]}`
}

func build(t *testing.T, doc string) *Build {
	t.Helper()
	recs, err := Parse([]byte(doc))
	if err != nil {
		t.Fatal(err)
	}
	b, err := BuildPack(recs, "CVE-2099-0001", [][]byte{[]byte(doc)}, 1, "tcp")
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func asset(id, purlStr, version string, complete bool) snapshot.Asset {
	pkgs := []snapshot.Package{}
	if purlStr != "" {
		pkgs = append(pkgs, snapshot.Package{PURL: purlStr, Version: version})
	}
	return snapshot.Asset{
		ID: id, Name: id, Kind: "host", Zones: []string{"internet"},
		Inventory: snapshot.Inventory{
			Complete: complete, ObservedAt: "2026-11-08T11:00:00Z", Basis: "observed",
			Confidence: "high", EvidenceID: "e-inv-" + id, Packages: pkgs,
		},
		Facts: []snapshot.Fact{},
		Exposure: []snapshot.Exposure{{
			Port: 1, Proto: "tcp", ReachableFrom: []string{"internet"}, Basis: "observed",
			Confidence: "high", ObservedAt: "2026-11-08T11:00:00Z", EvidenceID: "e-exp", Source: "test",
		}},
	}
}

func drill(t *testing.T, b *Build, assets ...snapshot.Asset) map[string]engine.Verdict {
	t.Helper()
	pol, err := policy.Load([]byte(`{"untrusted_zones":["internet"],"trusted_zones":["internal"]}`))
	if err != nil {
		t.Fatal(err)
	}
	at, _ := time.Parse(time.RFC3339, eval)
	rep, err := engine.Evaluate(engine.Input{
		Pack: b.Pack, Policy: pol, EvaluationTime: at, KBVersion: "test",
		Snapshot: &snapshot.Snapshot{KBVersion: "test", EvaluationTime: eval, EvidenceTrust: "caller_asserted", Assets: assets},
	})
	if err != nil {
		t.Fatal(err)
	}
	out := map[string]engine.Verdict{}
	for _, v := range rep.Verdicts {
		out[v.AssetID] = v
	}
	return out
}

func TestFallbackIsDraftLowAndNeverClears(t *testing.T) {
	b := build(t, rec("Maven", "org.example:lib", `[{"type":"ECOSYSTEM","events":[{"introduced":"1.0"},{"fixed":"1.5"}]}]`))
	if b.Pack.Metadata.Status != "draft" || b.Pack.Metadata.ConfidenceCeiling != "low" {
		t.Fatalf("status=%s ceiling=%s", b.Pack.Metadata.Status, b.Pack.Metadata.ConfidenceCeiling)
	}
	got := drill(t, b,
		asset("in", "pkg:maven/org.example/lib@1.2", "1.2", true),
		asset("fixed", "pkg:maven/org.example/lib@1.5", "1.5", true),
		asset("absent", "pkg:maven/org.other/thing@9.9", "9.9", true),
		asset("empty", "", "", true),
		asset("incomplete", "", "", false),
	)
	if got["in"].State != "exploitable" || got["in"].VEXStatus != "affected" {
		t.Fatalf("in-range: %+v", got["in"])
	}
	for _, id := range []string{"fixed", "absent", "empty", "incomplete"} {
		if got[id].State != "needs_review" || got[id].VEXStatus != "under_investigation" {
			t.Fatalf("%s: state=%s vex=%s", id, got[id].State, got[id].VEXStatus)
		}
	}
}

func TestFallbackNeverNotAffectedOnExampleSnapshots(t *testing.T) {
	r := root(t)
	doc, err := os.ReadFile(filepath.Join(r, "examples/osv/GHSA-jfh8-c2jp-5v3q.json"))
	if err != nil {
		t.Fatal(err)
	}
	recs, err := Parse(doc)
	if err != nil {
		t.Fatal(err)
	}
	b, err := BuildPack(recs, "CVE-2021-44228", [][]byte{doc}, 8080, "tcp")
	if err != nil {
		t.Fatal(err)
	}
	snaps, _ := filepath.Glob(filepath.Join(r, "examples/snapshots/*.json"))
	if len(snaps) == 0 {
		t.Fatal("no example snapshots")
	}
	polRaw, err := os.ReadFile(filepath.Join(r, "examples/policy/lab-zones.json"))
	if err != nil {
		t.Fatal(err)
	}
	pol, err := policy.Load(polRaw)
	if err != nil {
		t.Fatal(err)
	}
	for _, path := range snaps {
		raw, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		s, err := snapshot.Load(raw)
		if err != nil {
			t.Fatal(err)
		}
		at, _ := time.Parse(time.RFC3339, s.EvaluationTime)
		rep, err := engine.Evaluate(engine.Input{Pack: b.Pack, Policy: pol, Snapshot: s, EvaluationTime: at, KBVersion: s.KBVersion})
		if err != nil {
			t.Fatal(err)
		}
		for _, v := range rep.Verdicts {
			if v.State == "not_affected" || v.VEXStatus == "not_affected" {
				t.Fatalf("%s %s: fallback produced not_affected", filepath.Base(path), v.AssetID)
			}
		}
	}
}

func TestUnreadableRangeDropsWholePackage(t *testing.T) {
	doc := `{"id":"GHSA-test-0002","aliases":["CVE-2099-0001"],"affected":[
	 {"package":{"ecosystem":"npm","name":"good"},"ranges":[{"type":"SEMVER","events":[{"introduced":"0"},{"fixed":"1.2.3"}]}]},
	 {"package":{"ecosystem":"npm","name":"partial"},"ranges":[
	   {"type":"SEMVER","events":[{"introduced":"1.0.0"},{"fixed":"1.1.0"}]},
	   {"type":"SEMVER","events":[{"introduced":"2.0"},{"fixed":"2.1"}]}]}]}`
	b := build(t, doc)
	for _, c := range b.Pack.Checks {
		for _, p := range c.PurlPatterns {
			if strings.Contains(p, "partial") {
				t.Fatalf("partially readable package kept: %v", c.AffectedRanges)
			}
		}
	}
	if len(b.Skipped) != 1 || !strings.Contains(b.Skipped[0], "partial") {
		t.Fatalf("skipped=%v", b.Skipped)
	}
}

func TestEcosystemMapping(t *testing.T) {
	cases := []struct {
		eco, name, ranges, purlStr, version, want string
	}{
		{"npm", "@scope/pkg", `[{"type":"SEMVER","events":[{"introduced":"0"},{"fixed":"2.0.0"}]}]`, "pkg:npm/%40scope/pkg@1.9.9", "1.9.9", "exploitable"},
		{"Go", "github.com/example/mod", `[{"type":"SEMVER","events":[{"introduced":"0"},{"fixed":"1.4.0"}]}]`, "pkg:golang/github.com/example/mod@v1.3.0", "v1.3.0", "exploitable"},
		{"Go", "github.com/example/mod", `[{"type":"SEMVER","events":[{"introduced":"0"},{"fixed":"1.4.0"}]}]`, "pkg:golang/github.com/example/mod@v1.4.0", "v1.4.0", "needs_review"},
		{"crates.io", "hyper", `[{"type":"SEMVER","events":[{"introduced":"0.14.0"},{"last_affected":"0.14.9"}]}]`, "pkg:cargo/hyper@0.14.9", "0.14.9", "exploitable"},
		{"Maven", "g.example:art", `[{"type":"ECOSYSTEM","events":[{"introduced":"0"}]}]`, "pkg:maven/g.example/art@3.0", "3.0", "exploitable"},
	}
	for _, c := range cases {
		b := build(t, rec(c.eco, c.name, c.ranges))
		got := drill(t, b, asset("a", c.purlStr, c.version, true))
		if got["a"].State != c.want {
			t.Fatalf("%s %s %s: state=%s want %s (%v)", c.eco, c.name, c.version, got["a"].State, c.want, got["a"].Reasons)
		}
	}
}

func TestDistroBuildNeedsAdvisory(t *testing.T) {
	b := build(t, rec("Maven", "org.apache.logging.log4j:log4j-core", `[{"type":"ECOSYSTEM","events":[{"introduced":"2.0"},{"fixed":"2.15.0"}]}]`))
	got := drill(t, b, asset("rpm", "pkg:rpm/redhat/log4j-core@2.14.1-1.el8", "2.14.1-1.el8", true))
	if got["rpm"].State != "needs_review" {
		t.Fatalf("rpm build: %+v", got["rpm"])
	}
}

func TestRejects(t *testing.T) {
	bad := map[string]string{
		"no record for cve": `{"id":"GHSA-x","aliases":["CVE-2099-0002"],"affected":[]}`,
		"only distro":       rec("Debian:12", "openssh", `[{"type":"ECOSYSTEM","events":[{"introduced":"0"},{"fixed":"1:9.2p1-2+deb12u3"}]}]`),
		"only withdrawn":    `{"id":"GHSA-x","aliases":["CVE-2099-0001"],"withdrawn":"2026-01-01T00:00:00Z","affected":[{"package":{"ecosystem":"npm","name":"a"},"ranges":[{"type":"SEMVER","events":[{"introduced":"0"}]}]}]}`,
		"limit event":       rec("npm", "a", `[{"type":"SEMVER","events":[{"introduced":"0"},{"limit":"2.0.0"}]}]`),
	}
	for name, doc := range bad {
		recs, err := Parse([]byte(doc))
		if err != nil {
			continue
		}
		if _, err := BuildPack(recs, "CVE-2099-0001", [][]byte{[]byte(doc)}, 1, "tcp"); err == nil {
			t.Fatalf("%s: expected an error", name)
		}
	}
	if _, err := BuildPack(nil, "not-a-cve", nil, 1, "tcp"); err == nil {
		t.Fatal("bad cve accepted")
	}
}

func TestCVEOf(t *testing.T) {
	recs, _ := Parse([]byte(`[{"id":"GHSA-a","aliases":["CVE-2021-44228"]},{"id":"CVE-2021-44228"}]`))
	if got, err := CVEOf(recs); err != nil || got != "CVE-2021-44228" {
		t.Fatalf("%q %v", got, err)
	}
	recs, _ = Parse([]byte(`{"id":"GHSA-a","aliases":["CVE-2021-44228","CVE-2021-45046"]}`))
	if _, err := CVEOf(recs); err == nil {
		t.Fatal("ambiguous CVE accepted")
	}
}
