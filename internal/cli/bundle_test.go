// Copyright 2026 Uddeshya Kumar
// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestBundleBuildInstallDrill(t *testing.T) {
	root := moduleRoot(t)
	dir := t.TempDir()
	src := filepath.Join(dir, "src")
	os.MkdirAll(filepath.Join(src, "packs"), 0o755)
	os.MkdirAll(filepath.Join(src, "osv"), 0o755)
	copyFile := func(from, to string) {
		data, err := os.ReadFile(from)
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(to, data, 0o644); err != nil {
			t.Fatal(err)
		}
	}
	copyFile(filepath.Join(root, "packs/draft/ecp-cve-2024-6387-openssh.yaml"), filepath.Join(src, "packs/regresshion.yaml"))
	copyFile(filepath.Join(root, "examples/osv/GHSA-jfh8-c2jp-5v3q.json"), filepath.Join(src, "osv/log4shell.json"))
	priv, pub := filepath.Join(dir, "priv.pem"), filepath.Join(dir, "pub.pem")
	tarball, kb := filepath.Join(dir, "kb.tar"), filepath.Join(dir, "kb")
	run := func(args ...string) (string, error) {
		var stdout, stderr bytes.Buffer
		err := Execute(args, &stdout, &stderr)
		return stdout.String() + stderr.String(), err
	}
	steps := [][]string{
		{"bundle", "keygen", "--private-key", priv, "--public-key", pub},
		{"bundle", "build", "--dir", src, "--kb-version", "t1", "--created-at", "2026-11-09T06:00:00Z", "--key", priv, "--out", tarball},
		{"bundle", "verify", "--bundle", tarball, "--pubkey", pub},
		{"bundle", "install", "--bundle", tarball, "--pubkey", pub, "--dir", kb},
	}
	for _, s := range steps {
		if out, err := run(s...); err != nil {
			t.Fatalf("%v: %v\n%s", s, err, out)
		}
	}
	if out, err := run("bundle", "keygen", "--private-key", priv, "--public-key", pub); err == nil {
		t.Fatalf("keygen overwrote a key: %s", out)
	}
	installed := filepath.Join(kb, "t1")
	out, err := run("drill", "--kb", installed, "--pubkey", pub, "--cve", "CVE-2024-6387",
		"--snapshot", filepath.Join(root, "examples/snapshots/regresshion-lab.json"),
		"--policy", filepath.Join(root, "examples/policy/lab-zones.json"), "--out", filepath.Join(dir, "r1.json"))
	if err != nil || !strings.Contains(out, "pack ECP-CVE-2024-6387-openssh") {
		t.Fatalf("pack path: %v\n%s", err, out)
	}
	out, err = run("drill", "--kb", installed, "--pubkey", pub, "--cve", "CVE-2021-44228",
		"--snapshot", filepath.Join(root, "examples/snapshots/log4shell-lab.json"),
		"--policy", filepath.Join(root, "examples/policy/lab-zones.json"), "--out", filepath.Join(dir, "r2.json"))
	if err != nil || !strings.Contains(out, "version-only OSV fallback") || !strings.Contains(out, "not_affected=0") {
		t.Fatalf("fallback path: %v\n%s", err, out)
	}
	if _, err := run("drill", "--kb", installed, "--pubkey", pub, "--cve", "CVE-2099-9999",
		"--snapshot", filepath.Join(root, "examples/snapshots/log4shell-lab.json"), "--out", filepath.Join(dir, "r3.json")); err == nil {
		t.Fatal("unknown CVE accepted")
	}
	// Tampering with the stored bundle stops every later drill.
	stored := filepath.Join(installed, "bundle.tar")
	raw, _ := os.ReadFile(stored)
	i := bytes.Index(raw, []byte("LoginGraceTime"))
	if i < 0 {
		t.Fatal("marker not found")
	}
	raw[i] ^= 0x20
	os.WriteFile(stored, raw, 0o644)
	if out, err := run("drill", "--kb", installed, "--pubkey", pub, "--cve", "CVE-2024-6387",
		"--snapshot", filepath.Join(root, "examples/snapshots/regresshion-lab.json"), "--out", filepath.Join(dir, "r4.json")); err == nil {
		t.Fatalf("tampered bundle accepted: %s", out)
	}
}
