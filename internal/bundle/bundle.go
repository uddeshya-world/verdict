// Copyright 2026 Uddeshya Kumar
// SPDX-License-Identifier: Apache-2.0

// Package bundle builds, signs, verifies, and unpacks offline knowledge bundles.
//
// A bundle is a tar file with three kinds of member:
//
//	manifest.json      canonical JSON: kb_version, created_at, and every file with its SHA-256
//	manifest.sig       raw Ed25519 signature over the exact manifest.json bytes
//	files/<path>       packs (*.yaml) and OSV records (*.json)
//
// Verification is closed: every member must be listed in the manifest, every
// listed file must be present exactly once with a matching hash, paths must be
// clean and relative, and only regular files are accepted. A bundle that fails
// any rule is rejected whole. The package reads no network and no clock; the
// creation time is an explicit input.
package bundle

import (
	"archive/tar"
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"os"
	"path"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"time"
)

const (
	// FormatVersion is the manifest format.
	FormatVersion = "verdict-kb-bundle/1"
	// MaxFileBytes caps one member.
	MaxFileBytes = 4 * 1024 * 1024
	// MaxBundleBytes caps the sum of all members.
	MaxBundleBytes = 256 * 1024 * 1024
	// MaxFiles caps the number of members.
	MaxFiles = 20000

	manifestName = "manifest.json"
	sigName      = "manifest.sig"
	filesPrefix  = "files/"
)

var (
	kbRE   = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$`)
	pathRE = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._/-]{0,255}$`)
)

// Manifest is the signed table of contents.
type Manifest struct {
	Format    string  `json:"format"`
	KBVersion string  `json:"kb_version"`
	CreatedAt string  `json:"created_at"`
	KeyID     string  `json:"key_id"`
	Files     []Entry `json:"files"`
}

// Entry is one file in the bundle.
type Entry struct {
	Path   string `json:"path"`
	SHA256 string `json:"sha256"`
	Size   int64  `json:"size"`
}

// Verified is a bundle whose signature and contents were checked.
type Verified struct {
	Manifest Manifest
	Files    map[string][]byte
}

// KeyID is the hex SHA-256 of the public key, truncated to 16 bytes.
func KeyID(pub ed25519.PublicKey) string {
	sum := sha256.Sum256(pub)
	return hex.EncodeToString(sum[:16])
}

// GenerateKey returns PEM-encoded private (PKCS#8) and public (PKIX) keys.
func GenerateKey() (privPEM, pubPEM []byte, err error) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, nil, err
	}
	der, err := x509.MarshalPKCS8PrivateKey(priv)
	if err != nil {
		return nil, nil, err
	}
	pubDER, err := x509.MarshalPKIXPublicKey(pub)
	if err != nil {
		return nil, nil, err
	}
	return pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der}),
		pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: pubDER}), nil
}

// ParsePrivateKey reads a PKCS#8 Ed25519 private key.
func ParsePrivateKey(data []byte) (ed25519.PrivateKey, error) {
	block, _ := pem.Decode(data)
	if block == nil || block.Type != "PRIVATE KEY" {
		return nil, errors.New("bundle: private key is not a PEM PRIVATE KEY")
	}
	k, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("bundle: private key: %w", err)
	}
	priv, ok := k.(ed25519.PrivateKey)
	if !ok {
		return nil, errors.New("bundle: private key is not Ed25519")
	}
	return priv, nil
}

// ParsePublicKey reads a PKIX Ed25519 public key.
func ParsePublicKey(data []byte) (ed25519.PublicKey, error) {
	block, _ := pem.Decode(data)
	if block == nil || block.Type != "PUBLIC KEY" {
		return nil, errors.New("bundle: public key is not a PEM PUBLIC KEY")
	}
	k, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("bundle: public key: %w", err)
	}
	pub, ok := k.(ed25519.PublicKey)
	if !ok {
		return nil, errors.New("bundle: public key is not Ed25519")
	}
	return pub, nil
}

// CleanPath validates a bundle-relative file path.
func CleanPath(p string) error {
	if !pathRE.MatchString(p) || path.Clean(p) != p || strings.HasPrefix(p, "/") {
		return fmt.Errorf("bundle: unsafe path %q", p)
	}
	for _, seg := range strings.Split(p, "/") {
		if seg == "" || seg == "." || seg == ".." || strings.HasPrefix(seg, ".") {
			return fmt.Errorf("bundle: unsafe path %q", p)
		}
	}
	ext := path.Ext(p)
	if ext != ".yaml" && ext != ".json" {
		return fmt.Errorf("bundle: %q is not a .yaml pack or .json OSV record", p)
	}
	return nil
}

// Build signs files into a bundle. files maps bundle path to contents.
func Build(files map[string][]byte, kbVersion string, createdAt time.Time, priv ed25519.PrivateKey) ([]byte, error) {
	if !kbRE.MatchString(kbVersion) {
		return nil, fmt.Errorf("bundle: kb_version %q is invalid", kbVersion)
	}
	if createdAt.IsZero() {
		return nil, errors.New("bundle: created_at is required and is not read from the clock")
	}
	if len(files) == 0 {
		return nil, errors.New("bundle: no files")
	}
	if len(files) > MaxFiles {
		return nil, fmt.Errorf("bundle: more than %d files", MaxFiles)
	}
	pub, ok := priv.Public().(ed25519.PublicKey)
	if !ok {
		return nil, errors.New("bundle: bad private key")
	}
	m := Manifest{
		Format:    FormatVersion,
		KBVersion: kbVersion,
		CreatedAt: createdAt.UTC().Format(time.RFC3339),
		KeyID:     KeyID(pub),
	}
	paths := make([]string, 0, len(files))
	var total int64
	for p, data := range files {
		if err := CleanPath(p); err != nil {
			return nil, err
		}
		if len(data) > MaxFileBytes {
			return nil, fmt.Errorf("bundle: %s exceeds %d bytes", p, MaxFileBytes)
		}
		total += int64(len(data))
		paths = append(paths, p)
	}
	if total > MaxBundleBytes {
		return nil, fmt.Errorf("bundle: contents exceed %d bytes", MaxBundleBytes)
	}
	sort.Strings(paths)
	for _, p := range paths {
		sum := sha256.Sum256(files[p])
		m.Files = append(m.Files, Entry{Path: p, SHA256: hex.EncodeToString(sum[:]), Size: int64(len(files[p]))})
	}
	manifest, err := json.MarshalIndent(m, "", "  ")
	if err != nil {
		return nil, err
	}
	manifest = append(manifest, '\n')
	sig := ed25519.Sign(priv, manifest)

	var buf bytes.Buffer
	tw := tar.NewWriter(&buf)
	mtime := createdAt.UTC()
	write := func(name string, data []byte) error {
		hdr := &tar.Header{Name: name, Mode: 0o644, Size: int64(len(data)), ModTime: mtime, Typeflag: tar.TypeReg, Format: tar.FormatPAX}
		if err := tw.WriteHeader(hdr); err != nil {
			return err
		}
		_, err := tw.Write(data)
		return err
	}
	if err := write(manifestName, manifest); err != nil {
		return nil, err
	}
	if err := write(sigName, sig); err != nil {
		return nil, err
	}
	for _, p := range paths {
		if err := write(filesPrefix+p, files[p]); err != nil {
			return nil, err
		}
	}
	if err := tw.Close(); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

// Verify checks a bundle against one trusted public key.
func Verify(r io.Reader, pub ed25519.PublicKey) (*Verified, error) {
	tr := tar.NewReader(io.LimitReader(r, MaxBundleBytes+64*1024*1024))
	var manifest, sig []byte
	members := map[string][]byte{}
	var total int64
	count := 0
	for {
		hdr, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			return nil, fmt.Errorf("bundle: %w", err)
		}
		count++
		if count > MaxFiles+2 {
			return nil, fmt.Errorf("bundle: more than %d members", MaxFiles)
		}
		if hdr.Typeflag != tar.TypeReg {
			return nil, fmt.Errorf("bundle: member %q is not a regular file", hdr.Name)
		}
		if hdr.Size < 0 || hdr.Size > MaxFileBytes {
			return nil, fmt.Errorf("bundle: member %q has size %d", hdr.Name, hdr.Size)
		}
		total += hdr.Size
		if total > MaxBundleBytes {
			return nil, fmt.Errorf("bundle: contents exceed %d bytes", MaxBundleBytes)
		}
		data, err := io.ReadAll(io.LimitReader(tr, hdr.Size+1))
		if err != nil {
			return nil, fmt.Errorf("bundle: %w", err)
		}
		if int64(len(data)) != hdr.Size {
			return nil, fmt.Errorf("bundle: member %q is truncated", hdr.Name)
		}
		switch {
		case hdr.Name == manifestName:
			if manifest != nil {
				return nil, errors.New("bundle: duplicate manifest")
			}
			manifest = data
		case hdr.Name == sigName:
			if sig != nil {
				return nil, errors.New("bundle: duplicate signature")
			}
			sig = data
		case strings.HasPrefix(hdr.Name, filesPrefix):
			p := strings.TrimPrefix(hdr.Name, filesPrefix)
			if err := CleanPath(p); err != nil {
				return nil, err
			}
			if _, dup := members[p]; dup {
				return nil, fmt.Errorf("bundle: duplicate member %q", p)
			}
			members[p] = data
		default:
			return nil, fmt.Errorf("bundle: unexpected member %q", hdr.Name)
		}
	}
	if manifest == nil || sig == nil {
		return nil, errors.New("bundle: manifest or signature is missing")
	}
	if len(sig) != ed25519.SignatureSize || !ed25519.Verify(pub, manifest, sig) {
		return nil, errors.New("bundle: signature does not verify with the trusted key")
	}
	dec := json.NewDecoder(bytes.NewReader(manifest))
	dec.DisallowUnknownFields()
	var m Manifest
	if err := dec.Decode(&m); err != nil {
		return nil, fmt.Errorf("bundle: manifest: %w", err)
	}
	if m.Format != FormatVersion {
		return nil, fmt.Errorf("bundle: format %q", m.Format)
	}
	if !kbRE.MatchString(m.KBVersion) {
		return nil, fmt.Errorf("bundle: kb_version %q is invalid", m.KBVersion)
	}
	if _, err := time.Parse(time.RFC3339, m.CreatedAt); err != nil {
		return nil, fmt.Errorf("bundle: created_at: %w", err)
	}
	if m.KeyID != KeyID(pub) {
		return nil, errors.New("bundle: manifest key_id does not match the trusted key")
	}
	listed := map[string]struct{}{}
	for _, e := range m.Files {
		if err := CleanPath(e.Path); err != nil {
			return nil, err
		}
		if _, dup := listed[e.Path]; dup {
			return nil, fmt.Errorf("bundle: manifest lists %q twice", e.Path)
		}
		listed[e.Path] = struct{}{}
		data, ok := members[e.Path]
		if !ok {
			return nil, fmt.Errorf("bundle: %q is listed but missing", e.Path)
		}
		sum := sha256.Sum256(data)
		if hex.EncodeToString(sum[:]) != e.SHA256 || int64(len(data)) != e.Size {
			return nil, fmt.Errorf("bundle: %q does not match its manifest hash", e.Path)
		}
	}
	for p := range members {
		if _, ok := listed[p]; !ok {
			return nil, fmt.Errorf("bundle: %q is not in the signed manifest", p)
		}
	}
	return &Verified{Manifest: m, Files: members}, nil
}

// Install writes a verified bundle into dir/<kb_version>/. It refuses to
// overwrite an existing version directory, so an installed knowledge base
// is never silently replaced. The manifest and signature are kept beside
// the files so the install can be re-verified later.
func Install(v *Verified, raw []byte, dir string) (string, error) {
	if v == nil {
		return "", errors.New("bundle: nothing to install")
	}
	target := filepath.Join(dir, v.Manifest.KBVersion)
	if _, err := os.Lstat(target); err == nil {
		return "", fmt.Errorf("bundle: %s already exists; knowledge versions are immutable", target)
	}
	tmp, err := os.MkdirTemp(dir, ".install-")
	if err != nil {
		return "", err
	}
	defer os.RemoveAll(tmp)
	for p, data := range v.Files {
		dst := filepath.Join(tmp, "files", filepath.FromSlash(p))
		if !strings.HasPrefix(dst, filepath.Join(tmp, "files")+string(os.PathSeparator)) {
			return "", fmt.Errorf("bundle: unsafe path %q", p)
		}
		if err := os.MkdirAll(filepath.Dir(dst), 0o755); err != nil {
			return "", err
		}
		if err := os.WriteFile(dst, data, 0o644); err != nil {
			return "", err
		}
	}
	if err := os.WriteFile(filepath.Join(tmp, "bundle.tar"), raw, 0o644); err != nil {
		return "", err
	}
	if err := os.Rename(tmp, target); err != nil {
		return "", err
	}
	return target, nil
}

// PackPaths returns the pack file paths. The caller loads and lints each one.
func (v *Verified) PackPaths() []string {
	var out []string
	for p := range v.Files {
		if strings.HasSuffix(p, ".yaml") {
			out = append(out, p)
		}
	}
	sort.Strings(out)
	return out
}

// OSVPaths returns the OSV record paths.
func (v *Verified) OSVPaths() []string {
	var out []string
	for p := range v.Files {
		if strings.HasSuffix(p, ".json") {
			out = append(out, p)
		}
	}
	sort.Strings(out)
	return out
}
