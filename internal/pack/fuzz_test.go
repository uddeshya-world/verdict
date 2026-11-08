// Copyright 2026 Uddeshya Kumar
// SPDX-License-Identifier: Apache-2.0

package pack

import (
	"os"
	"testing"

	"github.com/uddeshya-world/verdict/internal/rootpath"
)

func FuzzLoad(f *testing.F) {
	f.Add([]byte("apiVersion: verdict.dev/v1\nkind: ConditionPack\n"))
	f.Add([]byte("&\n"))
	f.Add([]byte("a: &a [1, *a]\n"))
	f.Add([]byte("{]\n"))
	if root, err := rootpath.Find(); err == nil {
		if data, err := os.ReadFile(root + "/packs/synthetic/ecp-synthetic-mixed.yaml"); err == nil {
			f.Add(data)
		}
	}
	f.Fuzz(func(t *testing.T, data []byte) {
		if len(data) > MaxBytes {
			return
		}
		_, _ = Load("fuzz.yaml", data)
	})
}
