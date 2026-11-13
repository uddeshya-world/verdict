// Copyright 2026 Uddeshya Kumar
// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestDrillInvokedBy(t *testing.T) {
	root := moduleRoot(t)
	dir := t.TempDir()
	out := filepath.Join(dir, "rep.json")
	base := []string{"drill", "--pack", filepath.Join(root, "packs/draft/ecp-cve-2024-6387-openssh.yaml"),
		"--snapshot", filepath.Join(root, "examples/snapshots/regresshion-lab.json"), "--out", out}
	if o, err := runCLI(append(base, "--invoked-by", "verdict-mcp/claude-code 2.1")...); err != nil {
		t.Fatalf("%v\n%s", err, o)
	}
	raw, _ := os.ReadFile(out)
	var rep map[string]any
	if err := json.Unmarshal(raw, &rep); err != nil || rep["invoked_by"] != "verdict-mcp/claude-code 2.1" {
		t.Fatalf("invoked_by=%v err=%v", rep["invoked_by"], err)
	}
	if o, err := runCLI("report", "validate", out); err != nil {
		t.Fatalf("%v\n%s", err, o)
	}
	// Unset: the field is absent, so reports without it are unchanged.
	if o, err := runCLI(base...); err != nil {
		t.Fatalf("%v\n%s", err, o)
	}
	raw, _ = os.ReadFile(out)
	if strings.Contains(string(raw), "invoked_by") {
		t.Fatal("invoked_by written when unset")
	}
	for _, bad := range []string{"line\nbreak", "tab\there", "café", "bidi‮", strings.Repeat("a", 129), "nul\x00"} {
		wantExit2(t, "--invoked-by", append(base, "--invoked-by", bad)...)
	}
	if o, err := runCLI(append(base, "--invoked-by", strings.Repeat("a", 128))...); err != nil {
		t.Fatalf("128 characters refused: %v\n%s", err, o)
	}
	// The schema refuses a hand-edited non-ASCII invoked_by.
	rep["invoked_by"] = "agent‮"
	body, _ := json.Marshal(rep)
	os.WriteFile(out, body, 0o644)
	if _, err := runCLI("report", "validate", out); err == nil {
		t.Fatal("schema accepted a non-ASCII invoked_by")
	}
}
