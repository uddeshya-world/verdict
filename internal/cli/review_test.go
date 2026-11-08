// Copyright 2026 Uddeshya Kumar
// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/uddeshya-world/verdict/internal/pack"
)

func TestPackReviewAcceptsSyntheticRecordOnly(t *testing.T) {
	root := moduleRoot(t)
	synPath := filepath.Join(root, "packs/synthetic/ecp-synthetic-polarity.yaml")
	data, err := os.ReadFile(synPath)
	if err != nil {
		t.Fatal(err)
	}
	p, err := pack.Load(synPath, data)
	if err != nil {
		t.Fatal(err)
	}
	sum, err := pack.ContentSHA256(p)
	if err != nil {
		t.Fatal(err)
	}
	rec := pack.ReviewRecord{
		PackID: p.Metadata.ID, PackSHA256: sum,
		Reviewers: []pack.ReviewAttestation{
			{Name: "synthetic-reviewer-alpha", ReviewedAt: "2026-11-08T12:00:00Z", Statement: "Fixture."},
			{Name: "synthetic-reviewer-beta", ReviewedAt: "2026-11-08T12:00:00Z", Statement: "Fixture."},
		},
	}
	dir := t.TempDir()
	path := filepath.Join(dir, "record.json")
	raw, err := json.Marshal(rec)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, raw, 0o644); err != nil {
		t.Fatal(err)
	}
	var stdout, stderr bytes.Buffer
	if err := Execute([]string{"pack", "review", "--pack", synPath, "--record", path}, &stdout, &stderr); err != nil {
		t.Fatal(err)
	}
	ssh := filepath.Join(root, "packs/draft/ecp-cve-2024-6387-openssh.yaml")
	if err := Execute([]string{"pack", "review", "--pack", ssh, "--record", path}, &stdout, &stderr); err == nil {
		t.Fatal("a synthetic record must not sign regreSSHion")
	}
}
