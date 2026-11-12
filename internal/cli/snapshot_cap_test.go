// Copyright 2026 Uddeshya Kumar
// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/uddeshya-world/verdict/internal/snapshot"
)

// bigSnapshot writes a snapshot of n copies of the log4shell lab's first
// asset, with ids prefixed by tag.
func bigSnapshot(t *testing.T, dir, tag string, n int) string {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join(moduleRoot(t), "examples/snapshots/log4shell-lab.json"))
	if err != nil {
		t.Fatal(err)
	}
	s, err := snapshot.Load(raw)
	if err != nil {
		t.Fatal(err)
	}
	proto := s.Assets[0]
	s.Assets = nil
	for i := 0; i < n; i++ {
		a := proto
		a.ID = fmt.Sprintf("%s-%05d", tag, i)
		a.Name = a.ID
		s.Assets = append(s.Assets, a)
	}
	body, err := json.Marshal(s)
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, tag+".json")
	if err := os.WriteFile(path, body, 0o644); err != nil {
		t.Fatal(err)
	}
	return path
}

func TestMaxSnapshotBytes(t *testing.T) {
	root := moduleRoot(t)
	dir := t.TempDir()
	run := func(args ...string) (string, error) {
		var stdout, stderr bytes.Buffer
		err := Execute(args, &stdout, &stderr)
		return stdout.String() + stderr.String(), err
	}
	// Two parts of about 1.5 MiB each: the old fixed 2 MiB cap refused the merge.
	a, b := bigSnapshot(t, dir, "a", 2500), bigSnapshot(t, dir, "b", 2500)
	if fi, _ := os.Stat(a); fi.Size() < 1<<20 {
		t.Fatalf("part is only %d bytes", fi.Size())
	}
	merged := filepath.Join(dir, "merged.json")
	if out, err := run("snapshot", "merge", a, b, "--out", merged); err != nil {
		t.Fatalf("merge under default cap: %v\n%s", err, out)
	}
	if fi, _ := os.Stat(merged); fi.Size() <= 2<<20 {
		t.Fatalf("merged is only %d bytes; test does not cross 2 MiB", fi.Size())
	}
	pk := filepath.Join(root, "packs/draft/ecp-cve-2021-44228-log4j.yaml")
	if out, err := run("drill", "--pack", pk, "--snapshot", merged, "--out", filepath.Join(dir, "r.json")); err != nil {
		t.Fatalf("drill under default cap: %v\n%s", err, out)
	}
	// A lower cap is enforced, and the error says how to raise it.
	_, err := run("drill", "--pack", pk, "--snapshot", merged, "--max-snapshot-bytes", "1048576", "--out", filepath.Join(dir, "r2.json"))
	if err == nil || !strings.Contains(err.Error(), "--max-snapshot-bytes") {
		t.Fatalf("drill over cap: %v", err)
	}
	// Merge refuses to write what the same cap could not read back.
	small := bigSnapshot(t, dir, "c", 10)
	small2 := bigSnapshot(t, dir, "d", 10)
	fi, _ := os.Stat(small)
	capFlag := fmt.Sprint(fi.Size() + 100)
	if _, err := run("snapshot", "merge", small, small2, "--out", filepath.Join(dir, "m2.json"), "--max-snapshot-bytes", capFlag); err == nil || !strings.Contains(err.Error(), "--max-snapshot-bytes") {
		t.Fatalf("merge output over cap: %v", err)
	}
	for _, args := range [][]string{
		{"import", "advisories", "--snapshot", merged, "--advisories", merged, "--out", filepath.Join(dir, "x.json"), "--max-snapshot-bytes", "1024"},
		{"drill", "--pack", pk, "--snapshot", small, "--max-snapshot-bytes", "0"},
	} {
		if _, err := run(args...); err == nil || !strings.Contains(err.Error(), "max-snapshot-bytes") {
			t.Errorf("%v: %v", args, err)
		}
	}
}
