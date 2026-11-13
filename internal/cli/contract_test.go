// Copyright 2026 Uddeshya Kumar
// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"bytes"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/uddeshya-world/verdict/internal/engine"
)

func run(t *testing.T, args ...string) (string, string, int) {
	t.Helper()
	var out, errb bytes.Buffer
	err := Execute(args, &out, &errb)
	code := 0
	if err != nil {
		var ee *ExitError
		if errors.As(err, &ee) {
			code = ee.Code
		} else {
			code = 1
		}
	}
	return out.String(), errb.String(), code
}

func decodeObj(t *testing.T, s string) map[string]any {
	t.Helper()
	var m map[string]any
	dec := json.NewDecoder(strings.NewReader(s))
	if err := dec.Decode(&m); err != nil {
		t.Fatalf("not JSON: %v\n%s", err, s)
	}
	if dec.More() {
		t.Fatalf("more than one JSON value:\n%s", s)
	}
	return m
}

func TestExplain(t *testing.T) {
	out, _, code := run(t, "explain", "--all")
	if code != 0 {
		t.Fatalf("exit %d", code)
	}
	var res explainResult
	if err := json.Unmarshal([]byte(out), &res); err != nil {
		t.Fatal(err)
	}
	if len(res.Reasons) != len(engine.Reasons) || !res.OK || res.Command != "explain" {
		t.Fatalf("explain --all: %d entries, want %d", len(res.Reasons), len(engine.Reasons))
	}
	for _, r := range res.Reasons {
		if r.Hint == "" || r.NextAction == "" || r.Kind == "" || r.Actor == "" {
			t.Fatalf("incomplete entry %+v", r)
		}
	}
	out, _, code = run(t, "explain", "zone_policy_missing", "pack_not_reviewed")
	if code != 0 || !strings.Contains(out, `"code": "zone_policy_missing"`) || !strings.Contains(out, `"next_action"`) {
		t.Fatalf("explain codes: %d\n%s", code, out)
	}
	if out, _, code = run(t, "explain", "no_such_reason"); code != 2 || out != "" {
		t.Fatalf("unknown code: exit %d, stdout %q", code, out)
	}
	if _, _, code = run(t, "explain"); code != 2 {
		t.Fatalf("no args: exit %d", code)
	}
	if _, _, code = run(t, "explain", "--all", "missing_fact"); code != 2 {
		t.Fatalf("--all with codes: exit %d", code)
	}
}

func TestReportValidate(t *testing.T) {
	root := moduleRoot(t)
	golden, err := filepath.Glob(filepath.Join(root, "testdata", "golden", "*-report.json"))
	if err != nil || len(golden) == 0 {
		t.Fatal("no goldens")
	}
	args := append([]string{"report", "validate"}, golden...)
	out, errOut, code := run(t, args...)
	if code != 0 || strings.Count(out, ": valid\n") != len(golden) {
		t.Fatalf("exit %d\n%s\n%s", code, out, errOut)
	}
	bad := filepath.Join(t.TempDir(), "bad.json")
	data := mustRead(t, golden[0])
	if err := os.WriteFile(bad, bytes.Replace(data, []byte(`"evidence_trust": "caller_asserted_unverified"`), []byte(`"evidence_trust": "verified"`), 1), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, errOut, code = run(t, "report", "validate", bad); code != 2 || !strings.Contains(errOut, "bad.json") {
		t.Fatalf("bad report: exit %d %s", code, errOut)
	}
	out, _, code = run(t, "report", "validate", "--json", golden[0], bad)
	if code != 2 {
		t.Fatalf("--json bad: exit %d", code)
	}
	m := decodeObj(t, out)
	files := m["files"].([]any)
	if m["ok"] != false || len(files) != 2 || files[0].(map[string]any)["ok"] != true || files[1].(map[string]any)["error"] == "" {
		t.Fatalf("--json shape: %s", out)
	}
}

func TestDrillFailOn(t *testing.T) {
	root := moduleRoot(t)
	base := []string{
		"drill",
		"--pack", filepath.Join(root, "packs/synthetic/ecp-synthetic-polarity.yaml"),
		"--snapshot", filepath.Join(root, "examples/snapshots/synthetic-polarity.json"),
		"--policy", filepath.Join(root, "examples/policy/lab-zones.json"),
	}
	with := func(extra ...string) []string { return append(append([]string{}, base...), extra...) }

	// Default: exit 0 even with exploitable verdicts.
	plain, _, code := run(t, with()...)
	if code != 0 {
		t.Fatalf("default exit %d", code)
	}
	for _, tc := range []struct {
		asset, policy string
		want          int
	}{
		{"", "exploitable", 3},
		{"", "affected", 3},
		{"", "needs_review", 3},
		{"", "not_cleared", 3},
		{"syn-affected-internal", "exploitable", 0},
		{"syn-affected-internal", "affected", 3},
		{"syn-mitigated", "not_cleared", 0},
		{"syn-mitigated", "needs_review", 0},
		{"syn-stale-false", "needs_review", 3},
		{"syn-stale-false", "affected", 0},
	} {
		dir := t.TempDir()
		outPath := filepath.Join(dir, "r.json")
		vexPath := filepath.Join(dir, "r.vex.json")
		args := with("--fail-on", tc.policy, "--out", outPath, "--openvex", vexPath, "--author", "test")
		if tc.asset != "" {
			args = append(args, "--asset", tc.asset)
		}
		_, errOut, code := run(t, args...)
		if code != tc.want {
			t.Fatalf("%s %s: exit %d, want %d\n%s", tc.asset, tc.policy, code, tc.want, errOut)
		}
		// Outputs are written before the policy exit.
		for _, p := range []string{outPath, vexPath} {
			if _, err := os.Stat(p); err != nil {
				t.Fatalf("%s %s: %s not written", tc.asset, tc.policy, filepath.Base(p))
			}
		}
		if tc.asset == "" {
			if got := string(mustRead(t, outPath)); got != plain {
				t.Fatal("--fail-on changed the report")
			}
		}
	}
	if _, _, code := run(t, with("--fail-on", "safe")...); code != 2 {
		t.Fatalf("bad --fail-on: exit %d", code)
	}
}

func TestJSONFlags(t *testing.T) {
	root := moduleRoot(t)
	packPath := filepath.Join(root, "packs/synthetic/ecp-synthetic-polarity.yaml")
	vex := filepath.Join(t.TempDir(), "v.json")
	if _, errOut, code := run(t, "drill", "--pack", packPath,
		"--snapshot", filepath.Join(root, "examples/snapshots/synthetic-polarity.json"),
		"--openvex", vex, "--author", "test", "--out", filepath.Join(t.TempDir(), "r.json")); code != 0 {
		t.Fatal(errOut)
	}
	for _, tc := range []struct {
		args    []string
		command string
		code    int
	}{
		{[]string{"version", "--json"}, "version", 0},
		{[]string{"pack", "lint", "--json", packPath}, "pack lint", 0},
		{[]string{"pack", "lint", "--json", packPath, filepath.Join(root, "README.md")}, "pack lint", 2},
		{[]string{"pack", "hash", "--json", packPath}, "pack hash", 0},
		{[]string{"pack", "test", "--json", packPath}, "pack test", 0},
		{[]string{"openvex", "validate", "--json", vex}, "openvex validate", 0},
		{[]string{"openvex", "validate", "--json", packPath}, "openvex validate", 2},
	} {
		out, errOut, code := run(t, tc.args...)
		if code != tc.code {
			t.Fatalf("%v: exit %d, want %d\n%s", tc.args, code, tc.code, errOut)
		}
		m := decodeObj(t, out)
		if m["command"] != tc.command || m["ok"] != (tc.code == 0) {
			t.Fatalf("%v: %s", tc.args, out)
		}
	}
	out, _, _ := run(t, "version", "--json")
	if m := decodeObj(t, out); m["report_version"] != engine.ReportVersion {
		t.Fatal(out)
	}
	out, _, _ = run(t, "pack", "hash", "--json", packPath)
	text, _, _ := run(t, "pack", "hash", packPath)
	f := decodeObj(t, out)["files"].([]any)[0].(map[string]any)
	if !strings.Contains(text, "pack_sha256="+f["pack_sha256"].(string)) {
		t.Fatalf("json hash %v disagrees with text %s", f["pack_sha256"], text)
	}
}

func TestBenchJSON(t *testing.T) {
	root := moduleRoot(t)
	wd, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chdir(wd) })
	if err := os.Chdir(root); err != nil {
		t.Fatal(err)
	}
	out, errOut, code := run(t, "bench", "--json")
	if code != 0 {
		t.Fatalf("exit %d %s", code, errOut)
	}
	m := decodeObj(t, out)
	if m["false_not_affected"] != float64(0) {
		t.Fatalf("scoreboard: %v", m["false_not_affected"])
	}
}

func TestImportAndSnapshotJSON(t *testing.T) {
	root := moduleRoot(t)
	dir := t.TempDir()
	snapPath := filepath.Join(dir, "s.json")
	common := []string{
		"--input", filepath.Join(root, "examples/import/cyclonedx-openssh.json"),
		"--asset-id", "bastion-01", "--asset-name", "bastion",
		"--kb-version", "demo-2026.11.08", "--evaluation-time", "2026-11-08T12:00:00Z",
	}
	text, _, code := run(t, append([]string{"import", "cyclonedx", "--out", snapPath}, common...)...)
	if code != 0 || !strings.HasPrefix(text, "import cyclonedx: asset=bastion-01 packages=") {
		t.Fatalf("text: %d %q", code, text)
	}
	out, _, code := run(t, append([]string{"import", "cyclonedx", "--json", "--out", snapPath}, common...)...)
	m := decodeObj(t, out)
	if code != 0 || m["command"] != "import cyclonedx" || m["asset_id"] != "bastion-01" || m["out"] != snapPath {
		t.Fatalf("json: %d %s", code, out)
	}
	merged := filepath.Join(dir, "m.json")
	out, _, code = run(t, "import", "advisories", "--json", "--snapshot", snapPath,
		"--advisories", filepath.Join(root, "examples/import/advisories-openssh.json"), "--out", merged)
	if m = decodeObj(t, out); code != 0 || m["command"] != "import advisories" {
		t.Fatalf("advisories: %d %s", code, out)
	}
	second := filepath.Join(dir, "s2.json")
	other := append([]string{}, common...)
	other[3] = "bastion-02"
	if _, errOut, code := run(t, append([]string{"import", "cyclonedx", "--out", second}, other...)...); code != 0 {
		t.Fatal(errOut)
	}
	out, errOut, code := run(t, "snapshot", "merge", "--json", "--out", filepath.Join(dir, "mm.json"), snapPath, second)
	if m = decodeObj(t, out); code != 0 || m["command"] != "snapshot merge" || m["assets"] != float64(2) {
		t.Fatalf("merge: %d %s %s", code, out, errOut)
	}
}
