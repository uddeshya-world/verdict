// Copyright 2026 Uddeshya Kumar
// SPDX-License-Identifier: Apache-2.0

package bundle

import (
	"crypto/ed25519"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"time"
)

// MaxScanVersions caps how many installed versions ScanFloor verifies.
const MaxScanVersions = 256

// Floor is the newest signed bundle found in a knowledge-base root.
type Floor struct {
	KBVersion string
	CreatedAt string
}

// FloorScan is the result of verifying every installed bundle in a root.
type FloorScan struct {
	// Newest is the verified bundle with the greatest signed created_at
	// (ties broken by kb_version), or nil when none verified.
	Newest *Floor
	// Verified lists the kb_versions that verified, sorted.
	Verified []string
	// Created maps each verified kb_version to its signed created_at.
	Created map[string]string
	// Notes names each version that was skipped and why.
	Notes []string
}

// Has reports whether version verified in the scan.
func (s *FloorScan) Has(version string) bool {
	for _, v := range s.Verified {
		if v == version {
			return true
		}
	}
	return false
}

// ScanFloor verifies every root/<dir>/bundle.tar against pub and returns the
// newest signed created_at. A bundle that fails verification, or whose signed
// kb_version differs from its directory name, is skipped and noted, never
// counted. Nothing here reads LATEST: the result derives from signed data
// only. Hidden directories are ignored.
func ScanFloor(root string, pub ed25519.PublicKey) (*FloorScan, error) {
	ents, err := os.ReadDir(root)
	if err != nil {
		return nil, err
	}
	scan := &FloorScan{Created: map[string]string{}}
	seen := 0
	for _, e := range ents {
		name := e.Name()
		if !e.IsDir() || name == "" || name[0] == '.' {
			continue
		}
		tarPath := filepath.Join(root, name, "bundle.tar")
		if _, err := os.Lstat(tarPath); err != nil {
			continue
		}
		seen++
		if seen > MaxScanVersions {
			scan.Notes = append(scan.Notes, fmt.Sprintf("floor scan: more than %d installed versions; the rest were not checked", MaxScanVersions))
			break
		}
		m, err := verifyFile(tarPath, pub)
		if err != nil {
			scan.Notes = append(scan.Notes, fmt.Sprintf("floor scan: %s not counted: %v", name, err))
			continue
		}
		if m.KBVersion != name {
			scan.Notes = append(scan.Notes, fmt.Sprintf("floor scan: %s not counted: signed as kb_version %s", name, m.KBVersion))
			continue
		}
		scan.Verified = append(scan.Verified, name)
		scan.Created[name] = m.CreatedAt
		if scan.Newest == nil || newer(m.CreatedAt, m.KBVersion, scan.Newest) {
			scan.Newest = &Floor{KBVersion: m.KBVersion, CreatedAt: m.CreatedAt}
		}
	}
	sort.Strings(scan.Verified)
	return scan, nil
}

func newer(createdAt, version string, than *Floor) bool {
	a, err1 := time.Parse(time.RFC3339, createdAt)
	b, err2 := time.Parse(time.RFC3339, than.CreatedAt)
	if err1 != nil || err2 != nil {
		return false
	}
	return a.After(b) || (a.Equal(b) && version > than.KBVersion)
}

func verifyFile(path string, pub ed25519.PublicKey) (*Manifest, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	v, err := Verify(f, pub)
	if err != nil {
		return nil, err
	}
	return &v.Manifest, nil
}
