// Copyright 2026 Uddeshya Kumar
// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestDrillOSVFallback(t *testing.T) {
	root := moduleRoot(t)
	dir := t.TempDir()
	out := filepath.Join(dir, "report.json")
	vex := filepath.Join(dir, "vex.json")
	var stdout, stderr bytes.Buffer
	err := Execute([]string{
		"drill",
		"--osv", filepath.Join(root, "examples/osv/GHSA-jfh8-c2jp-5v3q.json"),
		"--snapshot", filepath.Join(root, "examples/snapshots/log4shell-lab.json"),
		"--policy", filepath.Join(root, "examples/policy/lab-zones.json"),
		"--out", out, "--openvex", vex, "--author", "test",
	}, &stdout, &stderr)
	if err != nil {
		t.Fatalf("%v\n%s", err, stderr.String())
	}
	if !strings.Contains(stderr.String(), "cannot say not_affected") || !strings.Contains(stderr.String(), "fallback skipped") {
		t.Fatalf("stderr: %s", stderr.String())
	}
	raw, err := os.ReadFile(out)
	if err != nil {
		t.Fatal(err)
	}
	rep, err := DecodeReport(raw)
	if err != nil {
		t.Fatal(err)
	}
	if rep.PackStatus != "draft" || rep.Summary.NotAffected != 0 || rep.Summary.Exploitable == 0 {
		t.Fatalf("status=%s summary=%+v", rep.PackStatus, rep.Summary)
	}
	stdout.Reset()
	if err := Execute([]string{"openvex", "validate", vex}, &stdout, &stderr); err != nil {
		t.Fatal(err)
	}
}

func TestDrillNeedsExactlyOneOfPackOrOSV(t *testing.T) {
	root := moduleRoot(t)
	var stdout, stderr bytes.Buffer
	snap := filepath.Join(root, "examples/snapshots/log4shell-lab.json")
	for _, args := range [][]string{
		{"drill", "--snapshot", snap},
		{"drill", "--snapshot", snap, "--pack", filepath.Join(root, "packs/draft/ecp-cve-2021-44228-log4j.yaml"), "--osv", filepath.Join(root, "examples/osv/GHSA-jfh8-c2jp-5v3q.json")},
	} {
		if err := Execute(args, &stdout, &stderr); err == nil {
			t.Fatalf("accepted %v", args)
		}
	}
}
