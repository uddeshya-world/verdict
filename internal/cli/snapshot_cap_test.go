// Copyright 2026 Uddeshya Kumar
// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
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

// Every command that writes a snapshot takes --max-snapshot-bytes, refuses
// output over it, and rejects an out-of-range cap with a clear error.
func TestImportCommandsMaxSnapshotBytes(t *testing.T) {
	root := moduleRoot(t)
	dir := t.TempDir()
	jar := filepath.Join(dir, "log4j.jar")
	writeLog4jJar(t, jar, true)
	common := []string{"--kb-version", "kb1", "--evaluation-time", "2026-11-08T12:00:00Z"}
	sbom := []string{"--asset-id", "a1", "--asset-name", "a1", "--input", filepath.Join(root, "examples/import/cyclonedx-openssh.json")}
	cmds := map[string][]string{
		"cyclonedx": sbom,
		"trivy":     sbom, // refused on cap (or parse) before anything is written; see below
		"jar":       {"--asset-id", "a1", "--asset-name", "a1", "--input", jar},
		"host":      {"--asset-id", "a1", "--input", filepath.Join(root, "examples/collect/lab-ubuntu-sshd.json")},
		"k8s":       {"--cluster", "lab", "--input", filepath.Join(root, "examples/k8s/cluster.json")},
	}
	run := func(sub string, extra ...string) (string, error) {
		args := append([]string{"import", sub, "--out", filepath.Join(dir, sub+".json")}, cmds[sub]...)
		args = append(args, common...)
		args = append(args, extra...)
		var o, e bytes.Buffer
		err := Execute(args, &o, &e)
		return o.String() + e.String(), err
	}
	for sub := range cmds {
		for _, bad := range []string{"0", "-5", "9223372036854775807", "1099511627777"} {
			if _, err := run(sub, "--max-snapshot-bytes", bad); err == nil || !strings.Contains(err.Error(), "--max-snapshot-bytes must be between 1 and 1099511627776") {
				t.Errorf("import %s cap %s: %v", sub, bad, err)
			}
		}
		if sub == "trivy" {
			continue
		}
		_ = os.Remove(filepath.Join(dir, sub+".json"))
		if out, err := run(sub, "--max-snapshot-bytes", "64"); err == nil || !strings.Contains(err.Error(), "over the 64-byte cap") {
			t.Errorf("import %s over cap: %v\n%s", sub, err, out)
		}
		if _, err := os.Stat(filepath.Join(dir, sub+".json")); err == nil {
			t.Errorf("import %s wrote output over the cap", sub)
		}
		if out, err := run(sub); err != nil {
			t.Errorf("import %s default cap: %v\n%s", sub, err, out)
		}
	}
}

// A cap of MaxInt64 used to wrap cap+1 and surface as "empty document".
func TestSnapshotCapRange(t *testing.T) {
	dir := t.TempDir()
	path := bigSnapshot(t, dir, "s", 1)
	for _, c := range []int64{0, -1, 1<<40 + 1, 1<<63 - 1} {
		if _, err := loadSnapshotFile(path, c); err == nil || !strings.Contains(err.Error(), "must be between 1 and") {
			t.Errorf("cap %d: %v", c, err)
		}
	}
	if _, err := loadSnapshotFile(path, 1<<40); err != nil {
		t.Errorf("cap 1 TiB refused: %v", err)
	}
}

// A file over the cap is refused from its size, before it is read.
func TestLoadSnapshotFileOversizeNotRead(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "big.json")
	f, err := os.Create(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := f.Truncate(64 << 20); err != nil { // sparse: reading it would allocate 64 MiB
		t.Fatal(err)
	}
	f.Close()
	var before, after runtime.MemStats
	runtime.ReadMemStats(&before)
	_, err = loadSnapshotFile(path, 1<<20)
	runtime.ReadMemStats(&after)
	if err == nil || !strings.Contains(err.Error(), "over the 1048576-byte cap") {
		t.Fatalf("%v", err)
	}
	if grown := after.TotalAlloc - before.TotalAlloc; grown > 8<<20 {
		t.Fatalf("refusal allocated %d bytes", grown)
	}
	// A non-regular source is bounded by the reader instead.
	if _, err := loadSnapshotFile("/dev/zero", 1<<20); err == nil || !strings.Contains(err.Error(), "over the 1048576-byte cap") {
		t.Fatalf("/dev/zero: %v", err)
	}
}
