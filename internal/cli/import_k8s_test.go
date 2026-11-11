// Copyright 2026 Uddeshya Kumar
// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestImportK8sThenDrillIngressNginx(t *testing.T) {
	root := moduleRoot(t)
	dir := t.TempDir()
	snapPath := filepath.Join(dir, "snap.json")
	var stdout, stderr bytes.Buffer
	args := []string{
		"import", "k8s",
		"--input", filepath.Join(root, "examples/k8s/cluster.json"),
		"--out", snapPath,
		"--cluster", "lab",
		"--kb-version", "demo-2026.11.08",
		"--evaluation-time", "2026-11-08T12:00:00Z",
		"--observed-at", "2026-11-08T11:00:00Z",
		"--untrusted-zone-for-loadbalancer", "internet",
		"--untrusted-zone-for-ingress", "internet",
	}
	if err := Execute(args, &stdout, &stderr); err != nil {
		t.Fatalf("%v\n%s", err, stderr.String())
	}
	if !strings.Contains(stderr.String(), "NetworkPolicy is not used to narrow exposure") {
		t.Fatalf("stderr: %s", stderr.String())
	}
	first, err := os.ReadFile(snapPath)
	if err != nil {
		t.Fatal(err)
	}
	// Deterministic: a second run writes the same bytes.
	if err := Execute(args, &stdout, &stderr); err != nil {
		t.Fatal(err)
	}
	second, _ := os.ReadFile(snapPath)
	if !bytes.Equal(first, second) {
		t.Fatal("import output is not deterministic")
	}

	controller := "lab:ingress-nginx:deployment:ingress-nginx-controller"
	strict := filepath.Join(dir, "strict-policy.json")
	if err := os.WriteFile(strict, []byte(`{"untrusted_zones":["internet","cluster-internal"],"trusted_zones":["internal"]}`), 0o644); err != nil {
		t.Fatal(err)
	}
	lenient := filepath.Join(dir, "lenient-policy.json")
	if err := os.WriteFile(lenient, []byte(`{"untrusted_zones":["internet"],"trusted_zones":["cluster-internal"]}`), 0o644); err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		policy, want string
	}{
		{filepath.Join(root, "examples/policy/lab-zones.json"), "exploitable"},
		{strict, "exploitable"},
		{lenient, "vulnerable_not_exposed"},
	} {
		reportPath := filepath.Join(dir, "report.json")
		stderr.Reset()
		if err := Execute([]string{
			"drill",
			"--pack", filepath.Join(root, "packs/draft/ecp-cve-2025-1974-ingress-nginx.yaml"),
			"--snapshot", snapPath,
			"--policy", tc.policy,
			"--out", reportPath,
		}, &stdout, &stderr); err != nil {
			t.Fatalf("%v\n%s", err, stderr.String())
		}
		raw, err := os.ReadFile(reportPath)
		if err != nil {
			t.Fatal(err)
		}
		var rep struct {
			Verdicts []struct {
				AssetID string `json:"asset_id"`
				State   string `json:"state"`
			} `json:"verdicts"`
		}
		if err := json.Unmarshal(raw, &rep); err != nil {
			t.Fatal(err)
		}
		found := false
		for _, v := range rep.Verdicts {
			if v.State == "not_affected" {
				t.Fatalf("%s: %s is not_affected", tc.policy, v.AssetID)
			}
			if v.AssetID == controller {
				found = true
				if v.State != tc.want {
					t.Fatalf("%s: controller state %s, want %s", tc.policy, v.State, tc.want)
				}
			}
		}
		if !found {
			t.Fatalf("controller not in report: %s", raw)
		}
	}
}

func TestImportK8sRequiresFlags(t *testing.T) {
	var stdout, stderr bytes.Buffer
	err := Execute([]string{"import", "k8s", "--out", filepath.Join(t.TempDir(), "x.json")}, &stdout, &stderr)
	if err == nil || !strings.Contains(err.Error(), "--input") {
		t.Fatalf("err %v", err)
	}
}
