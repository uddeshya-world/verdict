// Copyright 2026 Uddeshya Kumar
// SPDX-License-Identifier: Apache-2.0

package engine

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/uddeshya-world/verdict/internal/rootpath"
)

func TestProductionSourcesStayOffline(t *testing.T) {
	root, err := rootpath.Find()
	if err != nil {
		t.Fatal(err)
	}
	bannedImport := []string{
		`"net"`,
		`"net/http"`,
		`"os/exec"`,
	}
	err = filepath.Walk(root, func(path string, info os.FileInfo, err error) error {
		if err != nil || info.IsDir() {
			return err
		}
		if !strings.HasSuffix(path, ".go") || strings.HasSuffix(path, "_test.go") {
			return nil
		}
		rel, _ := filepath.Rel(root, path)
		if strings.HasPrefix(rel, "internal/netpolicy/") {
			return nil
		}
		body, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		text := string(body)
		if strings.Contains(text, "time.Now") {
			t.Errorf("%s calls time.Now", rel)
		}
		for _, b := range bannedImport {
			if strings.Contains(text, b) {
				t.Errorf("%s imports %s", rel, b)
			}
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
}
