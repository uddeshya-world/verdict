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
