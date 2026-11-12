// Copyright 2026 Uddeshya Kumar
// SPDX-License-Identifier: Apache-2.0

package bundle

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"time"
)

// LatestName is the file in a knowledge-base root that names the newest
// installed version. It is a cache and a hint: install only moves it forward
// (by signed created_at). It is not signed, so drill --kb does not trust it
// to lower the floor. The floor is the newest created_at among the bundles
// that ScanFloor verifies; LATEST can only raise it.
const LatestName = "LATEST"

// Latest is the content of LATEST.
type Latest struct {
	KBVersion string `json:"kb_version"`
	CreatedAt string `json:"created_at"`
}

// ReadLatest returns the floor recorded in root, or nil when there is none.
func ReadLatest(root string) (*Latest, error) {
	raw, err := os.ReadFile(filepath.Join(root, LatestName))
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	if len(raw) > 4096 {
		return nil, fmt.Errorf("bundle: %s is too large", LatestName)
	}
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()
	var l Latest
	if err := dec.Decode(&l); err != nil {
		return nil, fmt.Errorf("bundle: %s: %w", LatestName, err)
	}
	if l.KBVersion == "" {
		return nil, fmt.Errorf("bundle: %s has no kb_version", LatestName)
	}
	if _, err := time.Parse(time.RFC3339, l.CreatedAt); err != nil {
		return nil, fmt.Errorf("bundle: %s created_at: %w", LatestName, err)
	}
	return &l, nil
}

// Older reports whether a bundle created at createdAt is older than the floor.
func (l *Latest) Older(createdAt string) (bool, error) {
	floor, err := time.Parse(time.RFC3339, l.CreatedAt)
	if err != nil {
		return false, err
	}
	at, err := time.Parse(time.RFC3339, createdAt)
	if err != nil {
		return false, err
	}
	return at.Before(floor), nil
}

// Before reports whether the floor is strictly earlier than createdAt.
func (l *Latest) Before(createdAt string) (bool, error) {
	floor, err := time.Parse(time.RFC3339, l.CreatedAt)
	if err != nil {
		return false, err
	}
	at, err := time.Parse(time.RFC3339, createdAt)
	if err != nil {
		return false, err
	}
	return floor.Before(at), nil
}

// UpdateLatest moves the floor in root to m when m is newer by created_at
// (ties broken by kb_version), and returns the floor now in effect.
func UpdateLatest(root string, m Manifest) (*Latest, error) {
	cur, err := ReadLatest(root)
	if err != nil {
		return nil, err
	}
	next := &Latest{KBVersion: m.KBVersion, CreatedAt: m.CreatedAt}
	if cur != nil {
		older, err := cur.Older(m.CreatedAt)
		if err != nil {
			return nil, err
		}
		if older || (cur.CreatedAt == m.CreatedAt && m.KBVersion <= cur.KBVersion) {
			return cur, nil
		}
	}
	body, err := json.Marshal(next)
	if err != nil {
		return nil, err
	}
	tmp, err := os.CreateTemp(root, ".latest-")
	if err != nil {
		return nil, err
	}
	defer os.Remove(tmp.Name())
	if _, err := tmp.Write(append(body, '\n')); err != nil {
		tmp.Close()
		return nil, err
	}
	if err := tmp.Close(); err != nil {
		return nil, err
	}
	if err := os.Chmod(tmp.Name(), 0o644); err != nil {
		return nil, err
	}
	if err := os.Rename(tmp.Name(), filepath.Join(root, LatestName)); err != nil {
		return nil, err
	}
	return next, nil
}
