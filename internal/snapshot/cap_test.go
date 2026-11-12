// Copyright 2026 Uddeshya Kumar
// SPDX-License-Identifier: Apache-2.0

package snapshot

import (
	"encoding/json"
	"strings"
	"testing"
)

func TestLoadMaxCap(t *testing.T) {
	raw, err := json.Marshal(snap("a"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := LoadMax(raw, int64(len(raw))); err != nil {
		t.Fatalf("at the cap: %v", err)
	}
	_, err = LoadMax(raw, int64(len(raw))-1)
	if err == nil || !strings.Contains(err.Error(), "--max-snapshot-bytes") {
		t.Fatalf("over the cap: %v", err)
	}
	if _, err := LoadMax(raw, 0); err == nil {
		t.Fatal("zero cap accepted")
	}
	if DefaultMaxBytes < 256*1024*1024 {
		t.Fatalf("default cap %d is below 256 MiB", DefaultMaxBytes)
	}
}

// Merge re-validates the combined document at its own size, so parts that
// each fit the caller's cap are not refused by a fixed internal limit.
func TestMergeNotCappedByDefault(t *testing.T) {
	a, b := snap("a"), snap("b")
	pad := strings.Repeat("x", 120)
	for i := 0; i < 3; i++ {
		a.Assets[0].Name += pad
		b.Assets[0].Name += pad
	}
	if _, err := Merge(a, b); err != nil {
		t.Fatal(err)
	}
}
