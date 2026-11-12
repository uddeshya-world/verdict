// Copyright 2026 Uddeshya Kumar
// SPDX-License-Identifier: Apache-2.0

package pack

import (
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
