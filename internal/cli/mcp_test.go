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
)

func runMCP(t *testing.T, stdin string, args ...string) (string, error) {
	t.Helper()
	var out, errb bytes.Buffer
	root := newRoot(&out, &errb)
	root.SetArgs(append([]string{"mcp"}, args...))
	root.SetIn(strings.NewReader(stdin))
	root.SetOut(&out)
	root.SetErr(&errb)
	err := root.Execute()
	return out.String(), err
}

func TestMCPCommand(t *testing.T) {
	dir := t.TempDir()
	logPath := filepath.Join(dir, "mcp.jsonl")
	in := `{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-06-18","clientInfo":{"name":"t"}}}` + "\n" +
		`{"jsonrpc":"2.0","method":"notifications/initialized"}` + "\n" +
		`{"jsonrpc":"2.0","id":2,"method":"tools/list"}` + "\n"
	out, err := runMCP(t, in, "--root", dir, "--log", logPath)
	if err != nil {
		t.Fatalf("clean EOF should exit 0: %v", err)
	}
	if n := strings.Count(out, "\n"); n != 2 {
		t.Fatalf("%d responses on stdout: %s", n, out)
	}
	for _, l := range strings.Split(strings.TrimSpace(out), "\n") {
		if !json.Valid([]byte(l)) {
			t.Fatalf("stdout carries a non-JSON line: %q", l)
		}
	}
	fi, err := os.Stat(logPath)
	if err != nil {
		t.Fatal(err)
	}
	if fi.Mode().Perm() != 0o600 {
		t.Fatalf("log mode %v", fi.Mode().Perm())
	}
	log, _ := os.ReadFile(logPath)
	lines := strings.Split(strings.TrimSpace(string(log)), "\n")
	if len(lines) != 5 {
		t.Fatalf("%d log lines", len(lines))
	}
	for i, l := range lines {
		var e struct {
			Seq int `json:"seq"`
		}
		if err := json.Unmarshal([]byte(l), &e); err != nil || e.Seq != i+1 {
			t.Fatalf("log line %d: seq %d err %v", i, e.Seq, err)
		}
	}
	// A second run truncates the log: seq restarts at 1 in a fresh file.
	if _, err := runMCP(t, "", "--root", dir, "--log", logPath); err != nil {
		t.Fatal(err)
	}
	if log, _ := os.ReadFile(logPath); len(log) != 0 {
		t.Fatalf("log not truncated: %s", log)
	}

	var ee *ExitError
	if _, err := runMCP(t, "", "--root", filepath.Join(dir, "missing")); !errors.As(err, &ee) || ee.Code != exitInput {
		t.Fatalf("missing root: %v", err)
	}
	if _, err := runMCP(t, "", "--root", logPath); !errors.As(err, &ee) || ee.Code != exitInput {
		t.Fatalf("file as root: %v", err)
	}
	if _, err := runMCP(t, "", "--root", dir, "--max-snapshot-bytes", "0"); !errors.As(err, &ee) || ee.Code != exitInput {
		t.Fatalf("bad cap: %v", err)
	}
}
