// Copyright 2026 Uddeshya Kumar
// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/uddeshya-world/verdict/internal/snapshot"
)

func TestImportCycloneDXThenAdvisories(t *testing.T) {
	root := moduleRoot(t)
	dir := t.TempDir()
	snapPath := filepath.Join(dir, "snap.json")
	merged := filepath.Join(dir, "merged.json")
	var stdout, stderr bytes.Buffer
	err := Execute([]string{
		"import", "cyclonedx",
		"--input", filepath.Join(root, "examples/import/cyclonedx-openssh.json"),
		"--out", snapPath,
		"--asset-id", "bastion-01",
		"--asset-name", "bastion",
		"--kb-version", "demo-2026.11.08",
		"--evaluation-time", "2026-11-08T12:00:00Z",
	}, &stdout, &stderr)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(stderr.String(), "unidentified-library") {
		t.Fatalf("stderr: %s", stderr.String())
	}
	raw, err := os.ReadFile(snapPath)
	if err != nil {
		t.Fatal(err)
	}
	snap, err := snapshot.Load(raw)
	if err != nil {
		t.Fatal(err)
	}
	if snap.Assets[0].Inventory.Basis != "attested" || len(snap.Assets[0].Facts) != 0 {
		t.Fatalf("%+v", snap.Assets[0])
	}
	stderr.Reset()
	if err := Execute([]string{
		"import", "advisories",
		"--snapshot", snapPath,
		"--advisories", filepath.Join(root, "examples/import/advisories-openssh.json"),
		"--out", merged,
	}, &stdout, &stderr); err != nil {
		t.Fatal(err)
	}
	raw, err = os.ReadFile(merged)
	if err != nil {
		t.Fatal(err)
	}
	snap, err = snapshot.Load(raw)
	if err != nil {
		t.Fatal(err)
	}
	if len(snap.Assets[0].Facts) != 1 || snap.Assets[0].Facts[0].Value != "affected" {
		t.Fatalf("%+v", snap.Assets[0].Facts)
	}
}

func TestImportCompleteRefusesSkippedPackages(t *testing.T) {
	dir := t.TempDir()
	in := filepath.Join(dir, "bom.json")
	out := filepath.Join(dir, "snap.json")
	body := []byte(`{"bomFormat":"CycloneDX","components":[
	  {"name":"openssh-server","version":"1:8.9p1-3ubuntu0.6"},
	  {"name":"bash","version":"5.1-6ubuntu1","purl":"pkg:deb/ubuntu/bash@5.1-6ubuntu1"}
	]}`)
	if err := os.WriteFile(in, body, 0o644); err != nil {
		t.Fatal(err)
	}
	var stdout, stderr bytes.Buffer
	err := Execute([]string{
		"import", "cyclonedx",
		"--input", in, "--out", out,
		"--asset-id", "bastion-x", "--asset-name", "bastion",
		"--kb-version", "demo-2026.11.08",
		"--evaluation-time", "2026-11-08T12:00:00Z",
		"--complete", "--basis", "observed", "--confidence", "high",
	}, &stdout, &stderr)
	if err == nil || !strings.Contains(err.Error(), "inventory cannot be complete") {
		t.Fatal(err)
	}
	if _, statErr := os.Stat(out); !os.IsNotExist(statErr) {
		t.Fatalf("complete import wrote a snapshot after skipping openssh: %v", statErr)
	}
}
