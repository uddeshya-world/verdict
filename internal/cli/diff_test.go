// Copyright 2026 Uddeshya Kumar
// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"sort"
	"strings"
	"testing"
)

// The fixtures in testdata/diff are real verdict objects from the
// synthetic-polarity golden. before.json is that golden. Each after-*.json
// swaps some assets' verdict objects for another asset's (asset_id renamed),
// drops or adds assets, or edits report-level fields, and recomputes the
// summary, so every fixture passes report validate.

func diffFixture(t *testing.T, name string) string {
	t.Helper()
	return filepath.Join(moduleRoot(t), "testdata", "diff", name)
}

func TestDiffFixtures(t *testing.T) {
	before := diffFixture(t, "before.json")
	for _, tc := range []struct {
		after, failOn string
		code          int
		classes       map[string]string // asset_id -> class
	}{
		{"before.json", "", 0, map[string]string{}},
		{"before.json", "any", 0, map[string]string{}},
		{"after-regression.json", "", 3, map[string]string{
			"syn-affected-internal":   "regression",  // vulnerable_not_exposed -> exploitable
			"syn-affected-internet":   "improvement", // exploitable -> not_affected
			"syn-attested-mitigation": "neutral",     // reasons only
			"syn-disjunction-unknown": "neutral",     // removed
			"syn-mitigated":           "regression",  // not_affected -> needs_review
			"syn-new-exploitable":     "regression",  // added exploitable
			"syn-pre-a-false":         "regression",  // not_affected -> exploitable
			"syn-unknown-zone":        "neutral",     // exposure_uncertainty only
		}},
		{"after-improvement.json", "", 0, map[string]string{
			"syn-affected-internal": "neutral",     // vulnerable_not_exposed -> needs_review
			"syn-new-review":        "neutral",     // added needs_review
			"syn-stale-false":       "improvement", // needs_review -> not_affected
			"syn-zones-only":        "improvement", // exploitable -> needs_review
		}},
		{"after-improvement.json", "any-affected-change", 3, nil},
		{"after-improvement.json", "any", 3, nil},
		{"after-removed.json", "", 0, map[string]string{"syn-affected-internet": "neutral"}},
		{"after-removed.json", "regression", 0, nil},
		{"after-removed.json", "any-affected-change", 3, nil},
		{"after-removed.json", "any", 3, nil},
	} {
		args := []string{"diff", "--json", before, diffFixture(t, tc.after)}
		if tc.failOn != "" {
			args = append(args, "--fail-on", tc.failOn)
		}
		out, errOut, code := run(t, args...)
		if code != tc.code {
			t.Fatalf("%s --fail-on %q: exit %d, want %d\n%s", tc.after, tc.failOn, code, tc.code, errOut)
		}
		m := decodeObj(t, out)
		if m["ok"] != (code == 0) {
			t.Fatalf("%s: ok=%v with exit %d", tc.after, m["ok"], code)
		}
		if tc.classes == nil {
			continue
		}
		got := map[string]string{}
		for _, c := range m["changes"].([]any) {
			c := c.(map[string]any)
			got[c["asset_id"].(string)] = c["class"].(string)
		}
		if !reflect.DeepEqual(got, tc.classes) {
			t.Fatalf("%s classes:\n got %v\nwant %v", tc.after, got, tc.classes)
		}
	}
}

func TestDiffExitCodes(t *testing.T) {
	before := diffFixture(t, "before.json")
	// Same report: 0, and the text summary passes.
	out, _, code := run(t, "diff", before, before)
	if code != 0 || !strings.HasPrefix(out, "summary ") || !strings.Contains(out, "result=pass") {
		t.Fatalf("same report: exit %d\n%s", code, out)
	}
	// Regression: 3, one text line per changed asset plus the summary.
	out, _, code = run(t, "diff", before, diffFixture(t, "after-regression.json"))
	if code != 3 {
		t.Fatalf("regression: exit %d", code)
	}
	var sink bytes.Buffer
	if err := Execute([]string{"diff", before, diffFixture(t, "after-regression.json")}, &sink, &sink); err == nil || !strings.Contains(err.Error(), "--fail-on regression: 4 of 8") {
		t.Fatalf("regression error: %v", err)
	}
	lines := strings.Split(strings.TrimSuffix(out, "\n"), "\n")
	if len(lines) != 9 || !strings.HasPrefix(lines[8], "summary ") || !strings.Contains(lines[8], "result=fail") {
		t.Fatalf("text output:\n%s", out)
	}
	if !strings.Contains(out, "asset=syn-pre-a-false before=not_affected after=exploitable class=regression change=changed") ||
		!strings.Contains(out, "asset=syn-new-exploitable before=absent after=exploitable class=regression change=added") {
		t.Fatalf("text lines:\n%s", out)
	}

	// Context changes are printed, not refused.
	out, _, code = run(t, "diff", before, diffFixture(t, "after-removed.json"))
	if code != 0 || !strings.Contains(out, "context kb_version before=demo-2026.11.08 after=demo-2026.11.09\n") {
		t.Fatalf("context: exit %d\n%s", code, out)
	}

	// Input errors: 2 with nothing on stdout.
	other := filepath.Join(moduleRoot(t), "testdata", "golden", "xz-report.json")
	bad := filepath.Join(t.TempDir(), "bad.json")
	if err := os.WriteFile(bad, bytes.Replace(mustRead(t, before), []byte(`"state": "exploitable"`), []byte(`"state": "safe"`), 1), 0o644); err != nil {
		t.Fatal(err)
	}
	unknownReason := filepath.Join(t.TempDir(), "reason.json")
	if err := os.WriteFile(unknownReason, bytes.Replace(mustRead(t, before), []byte(`"tree_unknown"`), []byte(`"tree_made_up"`), 1), 0o644); err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		name string
		args []string
		msg  string
	}{
		{"other pack", []string{before, other}, "pack_id differs"},
		{"other cve", []string{before, diffFixture(t, "after-other-cve.json")}, "cve differs"},
		{"schema", []string{bad, before}, "report.schema.json"},
		{"catalog", []string{before, unknownReason}, "reason catalog"},
		{"missing", []string{before, filepath.Join(t.TempDir(), "nope.json")}, "nope.json"},
		{"one arg", []string{before}, "arg"},
		{"fail-on", []string{before, before, "--fail-on", "exploitable"}, "--fail-on must be"},
	} {
		for _, asJSON := range []bool{false, true} {
			args := append([]string{"diff"}, tc.args...)
			if asJSON {
				args = append(args, "--json")
			}
			out, _, code := run(t, args...)
			if code != 2 || out != "" {
				t.Fatalf("%s json=%t: exit %d stdout %q", tc.name, asJSON, code, out)
			}
			var b bytes.Buffer
			err := Execute(args, &b, &b)
			if err == nil || !strings.Contains(err.Error(), tc.msg) {
				t.Fatalf("%s: error %v, want %q", tc.name, err, tc.msg)
			}
		}
	}
}

// TestDiffJSONShape pins the top-level and per-change keys (docs/agents.md).
func TestDiffJSONShape(t *testing.T) {
	out, _, code := run(t, "diff", "--json", diffFixture(t, "before.json"), diffFixture(t, "after-regression.json"))
	if code != 3 {
		t.Fatalf("exit %d", code)
	}
	m := decodeObj(t, out)
	keysOf := func(m map[string]any) []string {
		var k []string
		for key := range m {
			k = append(k, key)
		}
		sort.Strings(k)
		return k
	}
	if got, want := keysOf(m), []string{"after", "after_summary", "before", "before_summary", "changes", "command", "context_changes", "counts", "cve", "fail_on", "matched", "ok", "pack_id"}; !reflect.DeepEqual(got, want) {
		t.Fatalf("top-level keys %v\nwant %v", got, want)
	}
	if m["command"] != "diff" || m["ok"] != false || m["fail_on"] != "regression" || m["matched"] != float64(4) || m["pack_id"] != "ECP-SYNTHETIC-POLARITY" {
		t.Fatalf("fields: %s", out)
	}
	if got, want := keysOf(m["counts"].(map[string]any)), []string{"added", "changed", "improvement", "neutral", "regression", "removed", "unchanged"}; !reflect.DeepEqual(got, want) {
		t.Fatalf("counts keys %v", got)
	}
	changes := m["changes"].([]any)
	byKind := map[string]map[string]any{}
	for _, c := range changes {
		c := c.(map[string]any)
		if got, want := keysOf(c), []string{"after", "asset_id", "before", "change", "class", "fields", "reasons_added", "reasons_removed"}; !reflect.DeepEqual(got, want) {
			t.Fatalf("change keys %v", got)
		}
		byKind[c["change"].(string)] = c
	}
	if byKind["added"]["before"] != nil || byKind["removed"]["after"] != nil {
		t.Fatal("added has before null, removed has after null")
	}
	side := byKind["changed"]["after"].(map[string]any)
	for _, k := range []string{"state", "vex_status", "confidence", "exposure_uncertainty", "reasons"} {
		if _, ok := side[k]; !ok {
			t.Fatalf("asset state lacks %s: %v", k, side)
		}
	}
	// Context changes are always an array.
	out, _, _ = run(t, "diff", "--json", diffFixture(t, "before.json"), diffFixture(t, "before.json"))
	if cc, ok := decodeObj(t, out)["context_changes"].([]any); !ok || len(cc) != 0 {
		t.Fatalf("context_changes: %s", out)
	}
}

// TestDiffDeterministic: same inputs, same bytes; a report with its verdicts
// in another order gives the same result.
func TestDiffDeterministic(t *testing.T) {
	before, after := diffFixture(t, "before.json"), diffFixture(t, "after-regression.json")
	first, _, _ := run(t, "diff", "--json", before, after)
	for i := 0; i < 5; i++ {
		again, _, _ := run(t, "diff", "--json", before, after)
		if again != first {
			t.Fatal("diff --json output is not byte-stable")
		}
	}
	// Reverse the verdict array of the after report. Files differ, so only
	// the before/after path fields may differ in the output.
	rev := filepath.Join(t.TempDir(), "rev.json")
	if err := os.WriteFile(rev, reverseVerdicts(t, mustRead(t, after)), 0o644); err != nil {
		t.Fatal(err)
	}
	got, _, _ := run(t, "diff", "--json", before, rev)
	if strings.Replace(got, rev, after, 1) != first {
		t.Fatalf("verdict order changed the diff:\n%s", got)
	}
}

func reverseVerdicts(t *testing.T, data []byte) []byte {
	t.Helper()
	var m map[string]any
	if err := json.Unmarshal(data, &m); err != nil {
		t.Fatal(err)
	}
	vs := m["verdicts"].([]any)
	for i, j := 0, len(vs)-1; i < j; i, j = i+1, j-1 {
		vs[i], vs[j] = vs[j], vs[i]
	}
	out, err := json.Marshal(m)
	if err != nil {
		t.Fatal(err)
	}
	return out
}
