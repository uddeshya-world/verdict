// Copyright 2026 Uddeshya Kumar
// SPDX-License-Identifier: Apache-2.0

package bundle

import (
	"os"
	"path/filepath"
	"testing"
)

func TestUpdateLatestIsMonotonic(t *testing.T) {
	dir := t.TempDir()
	if l, err := ReadLatest(dir); err != nil || l != nil {
		t.Fatalf("empty root: %+v %v", l, err)
	}
	steps := []struct {
		ver, at, want string
	}{
		{"b", "2026-11-08T00:00:00Z", "b"},
		{"a", "2026-11-01T00:00:00Z", "b"},  // older: floor stays
		{"c", "2026-11-09T00:00:00Z", "c"},  // newer: floor moves
		{"bb", "2026-11-09T00:00:00Z", "c"}, // same time, lower name: stays
		{"d", "2026-11-09T00:00:00Z", "d"},  // same time, higher name: moves
	}
	for _, s := range steps {
		got, err := UpdateLatest(dir, Manifest{KBVersion: s.ver, CreatedAt: s.at})
		if err != nil || got.KBVersion != s.want {
			t.Fatalf("install %s: %+v %v, want %s", s.ver, got, err, s.want)
		}
		onDisk, err := ReadLatest(dir)
		if err != nil || onDisk.KBVersion != s.want {
			t.Fatalf("on disk after %s: %+v %v", s.ver, onDisk, err)
		}
	}
	l, _ := ReadLatest(dir)
	if older, _ := l.Older("2026-11-08T23:59:59Z"); !older {
		t.Fatal("earlier created_at not older")
	}
	if older, _ := l.Older("2026-11-09T00:00:00Z"); older {
		t.Fatal("equal created_at counted as older")
	}
	for _, bad := range []string{"", "{}", `{"kb_version":"x","created_at":"nope"}`, `{"kb_version":"x","created_at":"2026-11-09T00:00:00Z","extra":1}`} {
		os.WriteFile(filepath.Join(dir, LatestName), []byte(bad), 0o644)
		if _, err := ReadLatest(dir); err == nil {
			t.Errorf("malformed LATEST %q accepted", bad)
		}
	}
}
