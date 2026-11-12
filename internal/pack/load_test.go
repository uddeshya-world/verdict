// Copyright 2026 Uddeshya Kumar
// SPDX-License-Identifier: Apache-2.0

package pack

import (
	"encoding/json"
	"os"
	"strings"
	"testing"

	"github.com/uddeshya-world/verdict/internal/rootpath"
)

func TestRepositoryPackPolicy(t *testing.T) {
	root, err := rootpath.Find()
	if err != nil {
		t.Fatal(err)
	}
	drafts, err := os.ReadDir(root + "/packs/draft")
	if err != nil {
		t.Fatal(err)
	}
	if len(drafts) == 0 {
		t.Fatal("expected draft packs")
	}
	for _, ent := range drafts {
		data, err := os.ReadFile(root + "/packs/draft/" + ent.Name())
		if err != nil {
			t.Fatal(err)
		}
		p, err := Load(ent.Name(), data)
		if err != nil {
			t.Fatalf("%s: %v", ent.Name(), err)
		}
		if p.Metadata.Status != "draft" || p.Metadata.Synthetic || len(p.Metadata.Reviewers) != 0 {
			t.Fatalf("%s must stay an unreviewed draft", ent.Name())
		}
		if !strings.HasPrefix(p.Metadata.CVE[0], "CVE-") || strings.HasPrefix(p.Metadata.CVE[0], "CVE-2099-") {
			t.Fatalf("%s CVE id", p.Metadata.CVE)
		}
	}
	syn, err := os.ReadDir(root + "/packs/synthetic")
	if err != nil {
		t.Fatal(err)
	}
	for _, ent := range syn {
		data, err := os.ReadFile(root + "/packs/synthetic/" + ent.Name())
		if err != nil {
			t.Fatal(err)
		}
		p, err := Load(ent.Name(), data)
		if err != nil {
			t.Fatalf("%s: %v", ent.Name(), err)
		}
		if !p.Metadata.Synthetic || !strings.HasPrefix(p.Metadata.CVE[0], "CVE-2099-") {
			t.Fatalf("%s must be a CVE-2099 synthetic fixture", ent.Name())
		}
		for _, r := range p.Metadata.Reviewers {
			if !strings.HasPrefix(strings.ToLower(r.Name), "synthetic-reviewer-") {
				t.Fatalf("non-fixture reviewer %q", r.Name)
			}
		}
	}
}

func TestRejectsUnsafePacks(t *testing.T) {
	base, err := os.ReadFile(mustRoot(t) + "/packs/synthetic/ecp-synthetic-mixed.yaml")
	if err != nil {
		t.Fatal(err)
	}
	cases := map[string]string{
		"alias":         "a: &a [1]\nb: [*a, *a]\n",
		"unknown field": string(base) + "\nexec: /bin/sh\n",
		"unknown check": strings.Replace(string(base), "type: host_fact", "type: code_reachable", 1),
		"dangling":      strings.Replace(string(base), "ref: J2", "ref: NOPE", 1),
	}
	for name, body := range cases {
		t.Run(name, func(t *testing.T) {
			if _, err := Load("bad.yaml", []byte(body)); err == nil {
				t.Fatal("expected error")
			}
		})
	}
	dup := "apiVersion: verdict.dev/v1\napiVersion: other\n"
	if _, err := Load("dup.yaml", []byte(dup)); err == nil {
		t.Fatal("duplicate key accepted")
	}
}

func TestFuzzCorpusLoads(t *testing.T) {
	data, err := os.ReadFile(mustRoot(t) + "/packs/draft/ecp-cve-2024-6387-openssh.yaml")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := Load("p.yaml", data); err != nil {
		t.Fatal(err)
	}
}

func mustRoot(t *testing.T) string {
	t.Helper()
	root, err := rootpath.Find()
	if err != nil {
		t.Fatal(err)
	}
	return root
}

func TestAbsenceContradictedByLint(t *testing.T) {
	base, err := os.ReadFile(mustRoot(t) + "/packs/draft/ecp-cve-2024-6387-openssh.yaml")
	if err != nil {
		t.Fatal(err)
	}
	src := string(base)
	if !strings.Contains(src, "      - process.listening.sshd\n") {
		t.Fatal("openssh pack must list process.listening.sshd in absence_contradicted_by")
	}
	if _, err := Load("ok.yaml", base); err != nil {
		t.Fatal(err)
	}
	for name, body := range map[string]string{
		"bad key":          strings.Replace(src, "      - process.listening.sshd\n", "      - \"process listening\"\n", 1),
		"duplicate":        strings.Replace(src, "      - process.listening.sshd\n", "      - process.listening.sshd\n      - process.listening.sshd\n", 1),
		"wrong check type": strings.Replace(src, "    key: libc.family\n", "    key: libc.family\n    absence_contradicted_by:\n      - process.listening.sshd\n", 1),
	} {
		if _, err := Load("bad.yaml", []byte(body)); err == nil {
			t.Errorf("%s: expected lint error", name)
		}
	}
}

func TestAliasesLintAndHash(t *testing.T) {
	base, err := os.ReadFile(mustRoot(t) + "/packs/draft/ecp-cve-2024-6387-openssh.yaml")
	if err != nil {
		t.Fatal(err)
	}
	src := string(base)
	if _, err := Load("ok.yaml", base); err != nil {
		t.Fatal(err)
	}
	anchor := "      - pkg:generic/sshd\n"
	if !strings.Contains(src, anchor) {
		t.Fatal("openssh pack must list pkg:generic/sshd as an alias")
	}
	var many strings.Builder
	for i := 0; i < 33; i++ {
		many.WriteString("      - pkg:generic/alias" + strings.Repeat("x", i) + "\n")
	}
	for name, body := range map[string]string{
		"duplicate":            strings.Replace(src, anchor, anchor+anchor, 1),
		"duplicate other case": strings.Replace(src, anchor, anchor+"      - pkg:GENERIC/SSHD\n", 1),
		"equals component":     strings.Replace(src, anchor, anchor+"      - pkg:generic/openssh\n", 1),
		"equals check pattern": strings.Replace(src, anchor, anchor+"      - pkg:deb/openssh-server\n", 1),
		"malformed":            strings.Replace(src, anchor, anchor+"      - generic/nope\n", 1),
		"with version":         strings.Replace(src, anchor, anchor+"      - pkg:generic/nope@1\n", 1),
		"over cap":             strings.Replace(src, anchor, many.String(), 1),
		"wrong check type":     strings.Replace(src, "    key: libc.family\n", "    key: libc.family\n    aliases:\n      - pkg:generic/sshd\n", 1),
	} {
		if _, err := Load("bad.yaml", []byte(body)); err == nil {
			t.Errorf("%s: expected lint error", name)
		}
	}
	// The content hash covers aliases, and a pack without aliases hashes as
	// it did before the field existed (omitempty).
	p1, _ := Load("a.yaml", base)
	p2, err := Load("b.yaml", []byte(strings.Replace(src, anchor, anchor+"      - pkg:generic/ssh-extra\n", 1)))
	if err != nil {
		t.Fatal(err)
	}
	h1, _ := ContentSHA256(p1)
	h2, _ := ContentSHA256(p2)
	if h1 == h2 {
		t.Fatal("content hash must change when aliases change")
	}
	p3 := *p1
	c := p3.Checks["C1_vulnerable_build"]
	c.Aliases = nil
	p3.Checks = map[string]Check{}
	for k, v := range p1.Checks {
		p3.Checks[k] = v
	}
	p3.Checks["C1_vulnerable_build"] = c
	raw, _ := json.Marshal(&p3)
	if strings.Contains(string(raw), "Aliases") && strings.Count(string(raw), "Aliases") != 0 {
		t.Fatalf("empty aliases must be omitted from the hashed JSON")
	}
}
