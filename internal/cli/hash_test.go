// Copyright 2026 Uddeshya Kumar
// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"bytes"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"

	"github.com/uddeshya-world/verdict/internal/pack"
)

var hashLine = regexp.MustCompile(`^pack_sha256=([0-9a-f]{64}) pack=(\S+) file=(.+)$`)

// runHash runs `pack hash` on one file and returns the parsed hex and id.
func runHash(t *testing.T, path string) (string, string) {
	t.Helper()
	var stdout, stderr bytes.Buffer
	if err := Execute([]string{"pack", "hash", path}, &stdout, &stderr); err != nil {
		t.Fatalf("pack hash %s: %v (stderr %q)", path, err, stderr.String())
	}
	out := strings.TrimSuffix(stdout.String(), "\n")
	m := hashLine.FindStringSubmatch(out)
	if m == nil || strings.Contains(out, "\n") {
		t.Fatalf("unexpected pack hash output %q", stdout.String())
	}
	if m[3] != path {
		t.Fatalf("file=%q, want %q", m[3], path)
	}
	return m[1], m[2]
}

func writeRecord(t *testing.T, dir, id, sum string, names ...string) string {
	t.Helper()
	rec := pack.ReviewRecord{PackID: id, PackSHA256: sum}
	for _, n := range names {
		rec.Reviewers = append(rec.Reviewers, pack.ReviewAttestation{Name: n, ReviewedAt: "2026-11-13T10:00:00Z", Statement: "Checked the tree against the advisory."})
	}
	raw, err := json.Marshal(rec)
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, "record.json")
	if err := os.WriteFile(path, raw, 0o644); err != nil {
		t.Fatal(err)
	}
	return path
}

func runReview(packPath, recPath string) error {
	var stdout, stderr bytes.Buffer
	return Execute([]string{"pack", "review", "--pack", packPath, "--record", recPath}, &stdout, &stderr)
}

func TestPackHashMatchesContentSHA256(t *testing.T) {
	root := moduleRoot(t)
	for _, rel := range []string{
		"packs/draft/ecp-cve-2024-6387-openssh.yaml",
		"packs/synthetic/ecp-synthetic-polarity.yaml",
	} {
		path := filepath.Join(root, rel)
		data, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		p, err := pack.Load(path, data)
		if err != nil {
			t.Fatal(err)
		}
		want, err := pack.ContentSHA256(p)
		if err != nil {
			t.Fatal(err)
		}
		got, id := runHash(t, path)
		if got != want || id != p.Metadata.ID {
			t.Fatalf("%s: got %s %s, want %s %s", rel, got, id, want, p.Metadata.ID)
		}
	}
}

func TestPackHashRoundTripsThroughReview(t *testing.T) {
	root := moduleRoot(t)
	dir := t.TempDir()
	// Real CVE pack, real-looking names.
	ssh := filepath.Join(root, "packs/draft/ecp-cve-2024-6387-openssh.yaml")
	sum, id := runHash(t, ssh)
	rec := writeRecord(t, dir, id, sum, "Reviewer One", "Reviewer Two")
	if err := runReview(ssh, rec); err != nil {
		t.Fatalf("record built from pack hash output rejected: %v", err)
	}
	// One flipped hex digit must be rejected.
	bad := []byte(sum)
	if bad[0] == '0' {
		bad[0] = '1'
	} else {
		bad[0] = '0'
	}
	rec = writeRecord(t, dir, id, string(bad), "Reviewer One", "Reviewer Two")
	if err := runReview(ssh, rec); err == nil {
		t.Fatal("altered hash accepted")
	}
}

func TestPackHashIgnoresOnlyStatusAndReviewers(t *testing.T) {
	root := moduleRoot(t)
	src, err := os.ReadFile(filepath.Join(root, "packs/synthetic/ecp-synthetic-polarity-draft.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	base := filepath.Join(dir, "base.yaml")
	if err := os.WriteFile(base, src, 0o644); err != nil {
		t.Fatal(err)
	}
	baseSum, id := runHash(t, base)
	rec := writeRecord(t, dir, id, baseSum, "synthetic-reviewer-alpha", "synthetic-reviewer-beta")
	if err := runReview(base, rec); err != nil {
		t.Fatal(err)
	}

	edit := func(name string, pairs ...string) string {
		t.Helper()
		s := string(src)
		for i := 0; i+1 < len(pairs); i += 2 {
			if strings.Count(s, pairs[i]) != 1 {
				t.Fatalf("%s: %q occurs %d times", name, pairs[i], strings.Count(s, pairs[i]))
			}
			s = strings.Replace(s, pairs[i], pairs[i+1], 1)
		}
		path := filepath.Join(dir, name+".yaml")
		if err := os.WriteFile(path, []byte(s), 0o644); err != nil {
			t.Fatal(err)
		}
		return path
	}

	// Promotion writes status and reviewers together (lint requires both).
	reviewers := "reviewers:\n    - name: synthetic-reviewer-alpha\n      role: synthetic-fixture-reviewer\n    - name: synthetic-reviewer-beta\n      role: synthetic-fixture-reviewer"
	same := map[string][]string{
		"promoted": {"status: draft", "status: reviewed", "reviewers: []", reviewers},
		"comment":  {"status: draft", "status: draft # a YAML comment"},
	}
	for name, pairs := range same {
		path := edit(name, pairs...)
		if got, _ := runHash(t, path); got != baseSum {
			t.Fatalf("%s: hash changed (%s != %s)", name, got, baseSum)
		}
		if err := runReview(path, rec); err != nil {
			t.Fatalf("%s: record no longer accepted: %v", name, err)
		}
	}

	changed := map[string][2]string{
		"title":     {`title: "Synthetic polarity fixture (draft)"`, `title: "Synthetic polarity fixture (draft) edited"`},
		"ceiling":   {"confidence_ceiling: high", "confidence_ceiling: medium"},
		"max_age":   {"evidence_max_age: 24h", "evidence_max_age: 48h"},
		"synthetic": {"synthetic: true", "synthetic: false"},
		"check":     {"key: synth.pre_a", "key: synth.pre_z"},
		"kb_min":    {"kb_min_version: demo-2026.11.08", "kb_min_version: demo-2026.11.09"},
	}
	for name, e := range changed {
		path := edit(name, e[0], e[1])
		got, _ := runHash(t, path)
		if got == baseSum {
			t.Fatalf("%s: hash unchanged after a content edit", name)
		}
		if err := runReview(path, rec); err == nil {
			t.Fatalf("%s: stale record accepted after a content edit", name)
		}
	}
}

func TestPackHashFailsOnLoadError(t *testing.T) {
	dir := t.TempDir()
	bad := filepath.Join(dir, "bad.yaml")
	if err := os.WriteFile(bad, []byte("apiVersion: verdict.dev/v1\nkind: ConditionPack\nsurprise: 1\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	for _, args := range [][]string{
		{"pack", "hash", bad},
		{"pack", "hash", filepath.Join(dir, "missing.yaml")},
		{"pack", "hash"},
	} {
		var stdout, stderr bytes.Buffer
		err := Execute(args, &stdout, &stderr)
		if err == nil {
			t.Fatalf("%v: want error", args)
		}
		if stdout.Len() != 0 {
			t.Fatalf("%v: printed %q on failure", args, stdout.String())
		}
	}
	var ee *ExitError
	var stdout, stderr bytes.Buffer
	err := Execute([]string{"pack", "hash", bad}, &stdout, &stderr)
	if !errors.As(err, &ee) || ee.Code != 2 {
		t.Fatalf("want exit 2, got %v", err)
	}
}
