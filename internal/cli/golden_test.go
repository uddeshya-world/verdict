// Copyright 2026 Uddeshya Kumar
// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/uddeshya-world/verdict/internal/canonjson"
	"github.com/uddeshya-world/verdict/internal/engine"
	"github.com/uddeshya-world/verdict/internal/export/openvex"
	"github.com/uddeshya-world/verdict/internal/pack"
	"github.com/uddeshya-world/verdict/internal/policy"
	"github.com/uddeshya-world/verdict/internal/rootpath"
	"github.com/uddeshya-world/verdict/internal/snapshot"
)

func TestGoldenDrills(t *testing.T) {
	root := moduleRoot(t)
	schema := filepath.Join(root, "schemas", "openvex.schema.json")
	cases := []struct {
		name  string
		pack  string
		snap  string
		draft bool
	}{
		{"regresshion", "packs/draft/ecp-cve-2024-6387-openssh.yaml", "examples/snapshots/regresshion-lab.json", true},
		{"log4shell", "packs/draft/ecp-cve-2021-44228-log4j.yaml", "examples/snapshots/log4shell-lab.json", true},
		{"synthetic-polarity", "packs/synthetic/ecp-synthetic-polarity.yaml", "examples/snapshots/synthetic-polarity.json", false},
		{"synthetic-mixed", "packs/synthetic/ecp-synthetic-mixed.yaml", "examples/snapshots/synthetic-mixed.json", false},
		{"spring4shell", "packs/draft/ecp-cve-2022-22965-spring.yaml", "examples/snapshots/spring4shell-lab.json", true},
		{"xz", "packs/draft/ecp-cve-2024-3094-xz.yaml", "examples/snapshots/xz-lab.json", true},
		{"ingress-nginx", "packs/draft/ecp-cve-2025-1974-ingress-nginx.yaml", "examples/snapshots/ingress-nginx-lab.json", true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			rep, vex := drill(t, root, tc.pack, tc.snap)
			if tc.draft {
				for _, v := range rep.Verdicts {
					if v.State == "not_affected" || v.VEXStatus == "not_affected" || v.Justification != "" {
						t.Fatalf("draft pack produced not_affected-shaped output for %s: %+v", v.AssetID, v.State)
					}
					if v.AssetID == "lab-log4j-rpm" {
						if v.Proof != nil {
							for _, j := range v.Proof.Justifications {
								if j == "component_not_present" {
									t.Fatal("rpm log4j-core must not be treated as component_not_present")
								}
							}
						}
					}
				}
			}
			body, err := canonjson.Marshal(rep)
			if err != nil {
				t.Fatal(err)
			}
			again, err := canonjson.Marshal(rep)
			if err != nil {
				t.Fatal(err)
			}
			if !bytes.Equal(body, again) {
				t.Fatal("report marshal not stable")
			}
			raw, err := openvex.Marshal(vex)
			if err != nil {
				t.Fatal(err)
			}
			if err := openvex.Validate(schema, raw); err != nil {
				t.Fatal(err)
			}
			if err := openvex.Validate("", raw); err != nil {
				t.Fatal(err)
			}
			sum := rep.Summary
			got := sum.Exploitable + sum.VulnerableNotExposed + sum.NotAffected + sum.NeedsReview
			if sum.Assets != len(rep.Verdicts) || got != sum.Assets {
				t.Fatalf("summary %+v does not cover %d verdicts", sum, len(rep.Verdicts))
			}
			compareGolden(t, filepath.Join(root, "testdata", "golden", tc.name+"-report.json"), body)
			compareGolden(t, filepath.Join(root, "testdata", "golden", tc.name+".openvex.json"), raw)
		})
	}
}

func TestReversedAssetsMatch(t *testing.T) {
	root := moduleRoot(t)
	p := loadPack(t, filepath.Join(root, "packs/synthetic/ecp-synthetic-polarity.yaml"))
	raw := mustRead(t, filepath.Join(root, "examples/snapshots/synthetic-polarity.json"))
	snap, err := snapshot.Load(raw)
	if err != nil {
		t.Fatal(err)
	}
	evalAt, err := time.Parse(time.RFC3339, snap.EvaluationTime)
	if err != nil {
		t.Fatal(err)
	}
	pol := loadLabPolicy(t, root)
	a, err := engine.Evaluate(engine.Input{Pack: p, Policy: pol, Snapshot: snap, EvaluationTime: evalAt, KBVersion: snap.KBVersion})
	if err != nil {
		t.Fatal(err)
	}
	rev := *snap
	rev.Assets = append([]snapshot.Asset{}, snap.Assets...)
	for i, j := 0, len(rev.Assets)-1; i < j; i, j = i+1, j-1 {
		rev.Assets[i], rev.Assets[j] = rev.Assets[j], rev.Assets[i]
	}
	b, err := engine.Evaluate(engine.Input{Pack: p, Policy: pol, Snapshot: &rev, EvaluationTime: evalAt, KBVersion: snap.KBVersion})
	if err != nil {
		t.Fatal(err)
	}
	ab, _ := canonjson.Marshal(a)
	bb, _ := canonjson.Marshal(b)
	if !bytes.Equal(ab, bb) {
		t.Fatal("asset order changed the report")
	}
}

func TestSummaryAndValidateOutsideRepo(t *testing.T) {
	root := moduleRoot(t)
	dir := t.TempDir()
	vexPath := filepath.Join(dir, "out.openvex.json")
	var stdout, stderr bytes.Buffer
	err := Execute([]string{
		"drill",
		"--pack", filepath.Join(root, "packs/draft/ecp-cve-2024-6387-openssh.yaml"),
		"--snapshot", filepath.Join(root, "examples/snapshots/regresshion-lab.json"),
		"--policy", filepath.Join(root, "examples/policy/lab-zones.json"),
		"--author", "Uddeshya Kumar",
		"--openvex", vexPath,
	}, &stdout, &stderr)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(stderr.String(), "summary exploitable=") || !strings.Contains(stderr.String(), "assets=") {
		t.Fatalf("missing summary line:\n%s", stderr.String())
	}
	rep, err := DecodeReport(stdout.Bytes())
	if err != nil {
		t.Fatal(err)
	}
	if rep.Summary.Assets != len(rep.Verdicts) || rep.Summary.Assets == 0 {
		t.Fatalf("%+v", rep.Summary)
	}
	wd, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chdir(wd) })
	if err := os.Chdir(dir); err != nil {
		t.Fatal(err)
	}
	var out2, err2 bytes.Buffer
	if err := Execute([]string{"openvex", "validate", vexPath}, &out2, &err2); err != nil {
		t.Fatalf("embedded schema: %v %s", err, err2.String())
	}
	if !strings.Contains(out2.String(), "openvex: valid") {
		t.Fatal(out2.String())
	}
}

func TestPackTestCommand(t *testing.T) {
	root := moduleRoot(t)
	var stdout, stderr bytes.Buffer
	err := Execute([]string{
		"pack", "test",
		filepath.Join(root, "packs/draft/ecp-cve-2024-6387-openssh.yaml"),
		filepath.Join(root, "packs/draft/ecp-cve-2021-44228-log4j.yaml"),
		filepath.Join(root, "packs/draft/ecp-cve-2022-22965-spring.yaml"),
		filepath.Join(root, "packs/draft/ecp-cve-2024-3094-xz.yaml"),
		filepath.Join(root, "packs/draft/ecp-cve-2025-1974-ingress-nginx.yaml"),
		filepath.Join(root, "packs/synthetic/ecp-synthetic-polarity.yaml"),
		filepath.Join(root, "packs/synthetic/ecp-synthetic-polarity-draft.yaml"),
		filepath.Join(root, "packs/synthetic/ecp-synthetic-mixed.yaml"),
	}, &stdout, &stderr)
	if err != nil {
		t.Fatalf("pack test: %v\n%s\n%s", err, stdout.String(), stderr.String())
	}
}

func drill(t *testing.T, root, packPath, snapPath string) (*engine.Report, *openvex.Document) {
	t.Helper()
	p := loadPack(t, filepath.Join(root, packPath))
	raw := mustRead(t, filepath.Join(root, snapPath))
	snap, err := snapshot.Load(raw)
	if err != nil {
		t.Fatal(err)
	}
	evalAt, err := time.Parse(time.RFC3339, snap.EvaluationTime)
	if err != nil {
		t.Fatal(err)
	}
	rep, err := engine.Evaluate(engine.Input{Pack: p, Policy: loadLabPolicy(t, root), Snapshot: snap, EvaluationTime: evalAt, KBVersion: snap.KBVersion})
	if err != nil {
		t.Fatal(err)
	}
	doc, err := openvex.FromReport(rep, "Uddeshya Kumar")
	if err != nil {
		t.Fatal(err)
	}
	return rep, doc
}

func loadLabPolicy(t *testing.T, root string) *policy.Policy {
	t.Helper()
	p, err := policy.Load(mustRead(t, filepath.Join(root, "examples/policy/lab-zones.json")))
	if err != nil {
		t.Fatal(err)
	}
	return p
}

func loadPack(t *testing.T, path string) *pack.Pack {
	t.Helper()
	data := mustRead(t, path)
	p, err := pack.Load(path, data)
	if err != nil {
		t.Fatal(err)
	}
	return p
}

func mustRead(t *testing.T, path string) []byte {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	return data
}

func compareGolden(t *testing.T, path string, got []byte) {
	t.Helper()
	if os.Getenv("UPDATE_GOLDEN") == "1" {
		if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, got, 0o644); err != nil {
			t.Fatal(err)
		}
		return
	}
	want, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("missing golden %s (%v). Re-run with UPDATE_GOLDEN=1 after review", path, err)
	}
	if !bytes.Equal(want, got) {
		t.Fatalf("golden mismatch %s\n--- got ---\n%s", path, got)
	}
}

func moduleRoot(t *testing.T) string {
	t.Helper()
	root, err := rootpath.Find()
	if err != nil {
		t.Fatal(err)
	}
	return root
}
