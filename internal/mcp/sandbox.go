// Copyright 2026 Uddeshya Kumar
// SPDX-License-Identifier: Apache-2.0

package mcp

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

// OutDirName is the only directory the server writes under, inside the root.
const OutDirName = ".verdict-out"

// errEscape is a path that leaves the root.
var errEscape = errors.New("path is outside the server root")

func resolveRoot(dir string) (real, lexical string, err error) {
	if dir == "" {
		dir = "."
	}
	lexical, err = filepath.Abs(dir)
	if err != nil {
		return "", "", err
	}
	real, err = filepath.EvalSymlinks(lexical)
	if err != nil {
		return "", "", fmt.Errorf("--root: %w", err)
	}
	fi, err := os.Stat(real)
	if err != nil {
		return "", "", fmt.Errorf("--root: %w", err)
	}
	if !fi.IsDir() {
		return "", "", fmt.Errorf("--root %s is not a directory", dir)
	}
	return real, filepath.Clean(lexical), nil
}

func joinOut(root string) string { return filepath.Join(root, OutDirName) }

// within reports whether p is root or below it. Both must be clean and
// absolute.
func within(root, p string) bool {
	rel, err := filepath.Rel(root, p)
	if err != nil || filepath.IsAbs(rel) {
		return false
	}
	return rel != ".." && !strings.HasPrefix(rel, ".."+string(filepath.Separator))
}

// resolve maps a client-supplied path to a real path inside the root. A
// relative path is joined to the root; an absolute path must already name
// something inside it. The cleaned path must be inside the root before
// symlinks are followed, and the EvalSymlinks'd path must be inside the
// EvalSymlinks'd root after. The file must exist.
func (s *Server) resolve(p string) (string, error) {
	if p == "" {
		return "", errors.New("empty path")
	}
	if strings.ContainsRune(p, 0) {
		return "", errors.New("path contains a NUL byte")
	}
	var cand string
	if filepath.IsAbs(p) {
		cand = filepath.Clean(p)
		if !within(s.root, cand) && !within(s.rootLexical, cand) {
			return "", errEscape
		}
	} else {
		cand = filepath.Join(s.root, p) // Join cleans
		if !within(s.root, cand) {
			return "", errEscape
		}
	}
	real, err := filepath.EvalSymlinks(cand)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return "", errors.New("no such file under the server root")
		}
		return "", errors.New("cannot resolve path under the server root")
	}
	if !within(s.root, real) {
		return "", errEscape
	}
	return real, nil
}

// rel returns p relative to the root with forward slashes, for output.
func (s *Server) rel(p string) string {
	if r, err := filepath.Rel(s.root, p); err == nil && within(s.root, p) {
		return filepath.ToSlash(r)
	}
	return p
}

// ensureOutDir creates Root/.verdict-out (0o750) or checks that it is a real
// directory, not a symlink planted to redirect writes.
func (s *Server) ensureOutDir() error {
	fi, err := os.Lstat(s.outDir)
	if errors.Is(err, os.ErrNotExist) {
		if err := os.Mkdir(s.outDir, 0o750); err != nil && !errors.Is(err, os.ErrExist) {
			return err
		}
		fi, err = os.Lstat(s.outDir)
	}
	if err != nil {
		return err
	}
	if fi.Mode()&os.ModeSymlink != 0 || !fi.IsDir() {
		return fmt.Errorf("%s exists and is not a plain directory; refusing to write through it", OutDirName)
	}
	return nil
}

// writeOut writes body to Root/.verdict-out/name. name is chosen by the
// server, never by the client. The file is written under a fresh temporary
// name and renamed into place, so an existing symlink at name is replaced,
// not followed. It returns the root-relative path.
func (s *Server) writeOut(name string, body []byte) (string, error) {
	if name == "" || strings.ContainsAny(name, `/\`) || name[0] == '.' {
		return "", fmt.Errorf("invalid output name %q", name)
	}
	if err := s.ensureOutDir(); err != nil {
		return "", err
	}
	f, err := os.CreateTemp(s.outDir, ".tmp-*")
	if err != nil {
		return "", err
	}
	tmp := f.Name()
	_, werr := f.Write(body)
	cerr := f.Close()
	if werr == nil {
		werr = cerr
	}
	if werr == nil {
		werr = os.Chmod(tmp, 0o640)
	}
	if werr == nil {
		werr = os.Rename(tmp, filepath.Join(s.outDir, name))
	}
	if werr != nil {
		_ = os.Remove(tmp)
		return "", werr
	}
	return OutDirName + "/" + name, nil
}
