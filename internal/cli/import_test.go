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

func TestImportAdvisoriesUnmatchedRowExitsNonZero(t *testing.T) {
	dir := t.TempDir()
	in := filepath.Join(dir, "bom.json")
	snapPath := filepath.Join(dir, "snap.json")
	adv := filepath.Join(dir, "adv.json")
	out := filepath.Join(dir, "out.json")
	bom := []byte(`{"bomFormat":"CycloneDX","components":[
	  {"type":"operating-system","name":"ubuntu","version":"24.04"},
	  {"name":"openssh-server","version":"1:9.6p1-3ubuntu13.5","purl":"pkg:deb/ubuntu/openssh-server@1:9.6p1-3ubuntu13.5?arch=arm64&distro=ubuntu-24.04&upstream=openssh"},
	  {"name":"lib","version":"1"}
	]}`)
	if err := os.WriteFile(in, bom, 0o644); err != nil {
		t.Fatal(err)
	}
	var stdout, stderr bytes.Buffer
	if err := Execute([]string{
		"import", "cyclonedx", "--input", in, "--out", snapPath,
		"--asset-id", "u24", "--asset-name", "u24",
		"--kb-version", "demo-2026.11.08", "--evaluation-time", "2026-11-08T12:00:00Z",
	}, &stdout, &stderr); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(stdout.String(), "skipped=1 (lib)") || !strings.Contains(stderr.String(), "note: ignored operating-system component ubuntu") {
		t.Fatalf("stdout=%q stderr=%q", stdout.String(), stderr.String())
	}
	row := func(p string) []byte {
		return []byte(`{"facts":[{"asset_id":"u24","key":"advisory.cve_2024_6387.status","purl":"` + p + `","value":"fixed","basis":"observed","confidence":"high","observed_at":"2026-11-08T11:00:00Z","evidence_id":"e","source":"USN"}]}`)
	}
	args := []string{"import", "advisories", "--snapshot", snapPath, "--advisories", adv, "--out", out}
	// A 22.04 row never lands on a 24.04 package.
	if err := os.WriteFile(adv, row("pkg:deb/ubuntu/openssh-server@1:9.6p1-3ubuntu13.5?distro=ubuntu-22.04"), 0o644); err != nil {
		t.Fatal(err)
	}
	err := Execute(args, &stdout, &stderr)
	if code, ok := err.(*ExitError); !ok || code.Code != 2 {
		t.Fatalf("unmatched row must exit 2: %v", err)
	}
	if _, statErr := os.Stat(out); !os.IsNotExist(statErr) {
		t.Fatalf("unmatched import wrote %s", out)
	}
	if err := Execute(append(args, "--allow-unmatched"), &stdout, &stderr); err != nil {
		t.Fatal(err)
	}
	// A row written the way a USN reads, without qualifiers, matches.
	if err := os.WriteFile(adv, row("pkg:deb/ubuntu/openssh-server@1:9.6p1-3ubuntu13.5"), 0o644); err != nil {
		t.Fatal(err)
	}
	stderr.Reset()
	if err := Execute(args, &stdout, &stderr); err != nil {
		t.Fatal(err)
	}
	raw, err := os.ReadFile(out)
	if err != nil {
		t.Fatal(err)
	}
	snap, err := snapshot.Load(raw)
	if err != nil {
		t.Fatal(err)
	}
	f := snap.Assets[0].Facts
	if len(f) != 1 || f[0].PURL != "pkg:deb/ubuntu/openssh-server@1:9.6p1-3ubuntu13.5?arch=arm64&distro=ubuntu-24.04&upstream=openssh" {
		t.Fatalf("%+v", f)
	}
	if !strings.Contains(stderr.String(), "matched=1 unmatched=0 facts=1") {
		t.Fatalf("stderr: %s", stderr.String())
	}
}
