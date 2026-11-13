// Copyright 2026 Uddeshya Kumar
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"bytes"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"testing"

	"github.com/uddeshya-world/verdict/internal/buildinfo"
)

// build links ./cmd/verdict the way scripts/release-build.sh does, with
// extra ldflags appended, and returns the binary path.
func build(t *testing.T, dir, extra string) string {
	t.Helper()
	exe := filepath.Join(dir, "verdict")
	if runtime.GOOS == "windows" {
		exe += ".exe"
	}
	gobin := filepath.Join(runtime.GOROOT(), "bin", "go")
	ldflags := "-s -w -buildid="
	if extra != "" {
		ldflags += " " + extra
	}
	cmd := exec.Command(gobin, "build", "-trimpath", "-buildvcs=false", "-ldflags", ldflags, "-o", exe, ".")
	cmd.Env = append(os.Environ(), "CGO_ENABLED=0")
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("go build: %v\n%s", err, out)
	}
	return exe
}

func runVersion(t *testing.T, exe string) string {
	t.Helper()
	out, err := exec.Command(exe, "version").Output()
	if err != nil {
		t.Fatalf("%s version: %v", exe, err)
	}
	return string(out)
}

func TestVersionLdflagOverride(t *testing.T) {
	if testing.Short() {
		t.Skip("builds the binary")
	}
	flag := "-X " + buildinfo.ModulePath + "/internal/buildinfo.Version=9.8.7-test"

	a := build(t, t.TempDir(), flag)
	if got, want := runVersion(t, a), buildinfo.ModulePath+" 9.8.7-test\n"; got != want {
		t.Fatalf("with ldflag: got %q, want %q", got, want)
	}
	// Same inputs, same bytes: the version stamp must not break reproducibility.
	b := build(t, t.TempDir(), flag)
	ab, err := os.ReadFile(a)
	if err != nil {
		t.Fatal(err)
	}
	bb, err := os.ReadFile(b)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(ab, bb) {
		t.Fatal("two builds with the same version ldflag differ")
	}

	plain := build(t, t.TempDir(), "")
	if got, want := runVersion(t, plain), buildinfo.ModulePath+" "+buildinfo.DefaultVersion+"\n"; got != want {
		t.Fatalf("without ldflag: got %q, want %q", got, want)
	}
}
