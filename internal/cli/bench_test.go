// Copyright 2026 Uddeshya Kumar
// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"bytes"
	"os"
	"testing"
)

func TestBenchCommandPassesCorpus(t *testing.T) {
	root := moduleRoot(t)
	wd, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chdir(wd) })
	if err := os.Chdir(root); err != nil {
		t.Fatal(err)
	}
	var stdout, stderr bytes.Buffer
	if err := Execute([]string{"bench", "--corpus", "bench/corpus.json"}, &stdout, &stderr); err != nil {
		t.Fatalf("%v\n%s", err, stderr.String())
	}
	if !bytes.Contains(stdout.Bytes(), []byte("false_not_affected=0")) {
		t.Fatalf("stdout: %s", stdout.String())
	}
}
