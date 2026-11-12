// Copyright 2026 Uddeshya Kumar
// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"bytes"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/spf13/cobra"
	"github.com/uddeshya-world/verdict/internal/bundle"
	"github.com/uddeshya-world/verdict/internal/osv"
	"github.com/uddeshya-world/verdict/internal/pack"
)

func newBundle(stdout, stderr io.Writer) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "bundle",
		Short: "Build, sign, verify, and install offline knowledge bundles",
		Long: `A knowledge bundle carries condition packs and OSV records across an air gap.
It is a tar with a manifest of SHA-256 hashes signed with Ed25519. The
engine side only ever needs the public key. Keep the private key on the
connected build machine.`,
	}

	var privOut, pubOut string
	keygen := &cobra.Command{
		Use:   "keygen",
		Short: "Create an Ed25519 signing key pair",
		RunE: func(*cobra.Command, []string) error {
			if privOut == "" || pubOut == "" {
				return &ExitError{Code: 2, Err: fmt.Errorf("--private-key and --public-key are required")}
			}
			for _, p := range []string{privOut, pubOut} {
				if _, err := os.Lstat(p); err == nil {
					return &ExitError{Code: 2, Err: fmt.Errorf("%s exists; refusing to overwrite a key", p)}
				}
			}
			priv, pub, err := bundle.GenerateKey()
			if err != nil {
				return err
			}
			if err := os.WriteFile(privOut, priv, 0o600); err != nil {
				return err
			}
			if err := os.WriteFile(pubOut, pub, 0o644); err != nil {
				return err
			}
			pk, _ := bundle.ParsePublicKey(pub)
			fmt.Fprintf(stdout, "key_id=%s private=%s (mode 0600, keep it off the air-gapped side) public=%s\n", bundle.KeyID(pk), privOut, pubOut)
			return nil
		},
	}
	keygen.Flags().StringVar(&privOut, "private-key", "", "where to write the PEM private key")
	keygen.Flags().StringVar(&pubOut, "public-key", "", "where to write the PEM public key")

	var srcDir, kbVersion, createdAt, keyPath, out string
	build := &cobra.Command{
		Use:   "build",
		Short: "Sign every .yaml pack and .json OSV record under --dir into a bundle",
		RunE: func(*cobra.Command, []string) error {
			if srcDir == "" || kbVersion == "" || createdAt == "" || keyPath == "" || out == "" {
				return &ExitError{Code: 2, Err: fmt.Errorf("--dir, --kb-version, --created-at, --key, and --out are required")}
			}
			at, err := time.Parse(time.RFC3339, createdAt)
			if err != nil {
				return &ExitError{Code: 2, Err: fmt.Errorf("--created-at: %w", err)}
			}
			raw, err := os.ReadFile(keyPath)
			if err != nil {
				return &ExitError{Code: 2, Err: err}
			}
			priv, err := bundle.ParsePrivateKey(raw)
			if err != nil {
				return &ExitError{Code: 2, Err: err}
			}
			files, err := collect(srcDir)
			if err != nil {
				return &ExitError{Code: 2, Err: err}
			}
			for p, data := range files {
				if strings.HasSuffix(p, ".yaml") {
					if _, err := pack.Load(p, data); err != nil {
						return &ExitError{Code: 2, Err: fmt.Errorf("%s: %w", p, err)}
					}
				} else if _, err := osv.Parse(data); err != nil {
					return &ExitError{Code: 2, Err: fmt.Errorf("%s: %w", p, err)}
				}
			}
			tarball, err := bundle.Build(files, kbVersion, at, priv)
			if err != nil {
				return &ExitError{Code: 2, Err: err}
			}
			if err := os.WriteFile(out, tarball, 0o644); err != nil {
				return err
			}
			fmt.Fprintf(stdout, "bundle kb_version=%s files=%d out=%s\n", kbVersion, len(files), out)
			return nil
		},
	}
	build.Flags().StringVar(&srcDir, "dir", "", "directory of packs (*.yaml) and OSV records (*.json)")
	build.Flags().StringVar(&kbVersion, "kb-version", "", "knowledge version name, e.g. 2026.11.09")
	build.Flags().StringVar(&createdAt, "created-at", "", "creation time (RFC3339); not read from the clock")
	build.Flags().StringVar(&keyPath, "key", "", "PEM Ed25519 private key")
	build.Flags().StringVar(&out, "out", "", "bundle tar to write")

	var bundlePath, pubPath, installDir string
	verify := &cobra.Command{
		Use:   "verify",
		Short: "Verify a bundle's signature and every file hash",
		RunE: func(*cobra.Command, []string) error {
			v, _, err := openBundle(bundlePath, pubPath)
			if err != nil {
				return &ExitError{Code: 2, Err: err}
			}
			fmt.Fprintf(stdout, "bundle ok kb_version=%s created_at=%s key_id=%s files=%d\n",
				v.Manifest.KBVersion, v.Manifest.CreatedAt, v.Manifest.KeyID, len(v.Manifest.Files))
			return nil
		},
	}
	verify.Flags().StringVar(&bundlePath, "bundle", "", "bundle tar")
	verify.Flags().StringVar(&pubPath, "pubkey", "", "trusted PEM Ed25519 public key")

	install := &cobra.Command{
		Use:   "install",
		Short: "Verify a bundle and unpack it into --dir/<kb_version>",
		RunE: func(*cobra.Command, []string) error {
			if installDir == "" {
				return &ExitError{Code: 2, Err: fmt.Errorf("--dir is required")}
			}
			v, raw, err := openBundle(bundlePath, pubPath)
			if err != nil {
				return &ExitError{Code: 2, Err: err}
			}
			if err := os.MkdirAll(installDir, 0o755); err != nil {
				return err
			}
			target, err := bundle.Install(v, raw, installDir)
			if err != nil {
				return &ExitError{Code: 2, Err: err}
			}
			latest, err := bundle.UpdateLatest(installDir, v.Manifest)
			if err != nil {
				return &ExitError{Code: 2, Err: fmt.Errorf("installed at %s but %s not updated: %w", target, bundle.LatestName, err)}
			}
			fmt.Fprintf(stdout, "installed kb_version=%s at %s latest=%s\n", v.Manifest.KBVersion, target, latest.KBVersion)
			return nil
		},
	}
	install.Flags().StringVar(&bundlePath, "bundle", "", "bundle tar")
	install.Flags().StringVar(&pubPath, "pubkey", "", "trusted PEM Ed25519 public key")
	install.Flags().StringVar(&installDir, "dir", "", "knowledge base directory")

	cmd.AddCommand(keygen, build, verify, install)
	_ = stderr
	return cmd
}

func openBundle(bundlePath, pubPath string) (*bundle.Verified, []byte, error) {
	if bundlePath == "" || pubPath == "" {
		return nil, nil, fmt.Errorf("--bundle and --pubkey are required")
	}
	pubRaw, err := os.ReadFile(pubPath)
	if err != nil {
		return nil, nil, err
	}
	pub, err := bundle.ParsePublicKey(pubRaw)
	if err != nil {
		return nil, nil, err
	}
	raw, err := os.ReadFile(bundlePath)
	if err != nil {
		return nil, nil, err
	}
	v, err := bundle.Verify(bytes.NewReader(raw), pub)
	if err != nil {
		return nil, nil, err
	}
	return v, raw, nil
}

func collect(dir string) (map[string][]byte, error) {
	files := map[string][]byte{}
	err := filepath.WalkDir(dir, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			if p != dir && strings.HasPrefix(d.Name(), ".") {
				return filepath.SkipDir
			}
			return nil
		}
		if !d.Type().IsRegular() {
			return fmt.Errorf("%s is not a regular file", p)
		}
		ext := filepath.Ext(p)
		if ext != ".yaml" && ext != ".json" {
			return nil
		}
		rel, err := filepath.Rel(dir, p)
		if err != nil {
			return err
		}
		data, err := os.ReadFile(p)
		if err != nil {
			return err
		}
		files[filepath.ToSlash(rel)] = data
		return nil
	})
	return files, err
}

// kbResolution is what a drill against an installed knowledge base used.
type kbResolution struct {
	Pack      *pack.Pack
	KBVersion string
	KeyID     string
	CreatedAt string
	Notes     []string
}

// resolveFromKB re-verifies an installed bundle and picks the pack for cve,
// falling back to its OSV records when no pack names the CVE.
func resolveFromKB(kbDir, pubPath, cve string, port int, proto string, allowOlder, requireFloor bool) (*kbResolution, error) {
	if cve == "" {
		return nil, fmt.Errorf("--cve is required with --kb")
	}
	v, _, err := openBundle(filepath.Join(kbDir, "bundle.tar"), pubPath)
	if err != nil {
		return nil, fmt.Errorf("--kb %s: %w", kbDir, err)
	}
	if base := filepath.Base(filepath.Clean(kbDir)); base != v.Manifest.KBVersion {
		// install writes kb/<kb_version>/. A different signed bundle copied
		// into that directory (for example an older one) is a rollback.
		return nil, fmt.Errorf("--kb %s holds a bundle signed as kb_version %s; refusing a mismatched or rolled-back install", kbDir, v.Manifest.KBVersion)
	}
	res := &kbResolution{KBVersion: v.Manifest.KBVersion, KeyID: v.Manifest.KeyID, CreatedAt: v.Manifest.CreatedAt}
	// Monotonic floor, derived from signed data: verify every installed
	// bundle under the root and take the newest signed created_at. LATEST is
	// a cache and a hint that can only raise the floor.
	root := filepath.Dir(filepath.Clean(kbDir))
	pubRaw, err := os.ReadFile(pubPath)
	if err != nil {
		return nil, err
	}
	pub, err := bundle.ParsePublicKey(pubRaw)
	if err != nil {
		return nil, err
	}
	scan, err := bundle.ScanFloor(root, pub)
	if err != nil {
		return nil, fmt.Errorf("--kb %s: %w", kbDir, err)
	}
	res.Notes = append(res.Notes, scan.Notes...)
	latest, err := bundle.ReadLatest(root)
	if err != nil {
		return nil, fmt.Errorf("--kb %s: %w", kbDir, err)
	}
	floor := &bundle.Latest{KBVersion: res.KBVersion, CreatedAt: res.CreatedAt}
	if scan.Newest != nil {
		floor = &bundle.Latest{KBVersion: scan.Newest.KBVersion, CreatedAt: scan.Newest.CreatedAt}
	}
	switch {
	case latest == nil:
		res.Notes = append(res.Notes, fmt.Sprintf("kb %s: no %s in %s; floor %s computed from signed bundles", res.KBVersion, bundle.LatestName, root, floor.KBVersion))
	default:
		claim := *latest
		if signed, ok := scan.Created[latest.KBVersion]; ok {
			claim.CreatedAt = signed // the signed time wins over the cache
		}
		if higher, err := floor.Before(claim.CreatedAt); err != nil {
			return nil, fmt.Errorf("--kb %s: %w", kbDir, err)
		} else if higher {
			if _, ok := scan.Created[latest.KBVersion]; !ok {
				res.Notes = append(res.Notes, fmt.Sprintf("kb %s: %s names %s, which is not a verified install; honoring it as a floor", res.KBVersion, bundle.LatestName, latest.KBVersion))
			}
			floor = &claim
		} else if claim.KBVersion != floor.KBVersion {
			res.Notes = append(res.Notes, fmt.Sprintf("kb %s: %s names %s, below the signed floor %s; using the computed floor", res.KBVersion, bundle.LatestName, latest.KBVersion, floor.KBVersion))
		}
	}
	if requireFloor {
		others := 0
		for _, v := range scan.Verified {
			if v != res.KBVersion {
				others++
			}
		}
		if others == 0 {
			return nil, fmt.Errorf("--kb %s: --require-floor needs at least one other verified bundle under %s; none found", kbDir, root)
		}
	}
	older, err := floor.Older(res.CreatedAt)
	if err != nil {
		return nil, fmt.Errorf("--kb %s: %w", kbDir, err)
	}
	if older && !allowOlder {
		return nil, fmt.Errorf("--kb %s is kb_version %s (created %s), older than the signed floor %s (created %s); pass --allow-older-kb to use it anyway", kbDir, res.KBVersion, res.CreatedAt, floor.KBVersion, floor.CreatedAt)
	}
	if older {
		res.Notes = append(res.Notes, fmt.Sprintf("kb %s: older than the floor %s; used because --allow-older-kb was given", res.KBVersion, floor.KBVersion))
	}
	var matches []*pack.Pack
	for _, p := range v.PackPaths() {
		pk, err := pack.Load("kb:"+p, v.Files[p])
		if err != nil {
			return nil, fmt.Errorf("kb pack %s: %w", p, err)
		}
		if pk.Metadata.CVE[0] == cve && pk.Metadata.Status != "deprecated" {
			matches = append(matches, pk)
		}
	}
	if len(matches) > 1 {
		ids := make([]string, 0, len(matches))
		for _, m := range matches {
			ids = append(ids, m.Metadata.ID)
		}
		sort.Strings(ids)
		return nil, fmt.Errorf("kb %s has %d packs for %s (%s); pass --pack to choose", res.KBVersion, len(matches), cve, strings.Join(ids, ", "))
	}
	if len(matches) == 1 {
		res.Pack = matches[0]
		res.Notes = append(res.Notes, fmt.Sprintf("kb %s: pack %s (%s)", res.KBVersion, res.Pack.Metadata.ID, res.Pack.Metadata.Status))
		return res, nil
	}
	var recs []osv.Record
	var raws [][]byte
	for _, p := range v.OSVPaths() {
		rs, err := osv.Parse(v.Files[p])
		if err != nil {
			return nil, fmt.Errorf("kb osv %s: %w", p, err)
		}
		// Every record in a file counts, as with drill --osv: a narrow
		// record listed first must not hide a wider one after it.
		matched := false
		for _, r := range rs {
			if osv.Names(r, cve) {
				recs = append(recs, r)
				matched = true
			}
		}
		if matched {
			raws = append(raws, v.Files[p])
		}
	}
	if len(recs) == 0 {
		return nil, fmt.Errorf("kb %s has no pack and no OSV record for %s", res.KBVersion, cve)
	}
	fb, err := osv.BuildPack(recs, cve, raws, port, proto)
	if err != nil {
		return nil, err
	}
	res.Pack = fb.Pack
	res.Notes = append(res.Notes, fmt.Sprintf("kb %s: no pack for %s; version-only OSV fallback %s, draft, confidence ceiling low. It cannot say not_affected.", res.KBVersion, cve, fb.Pack.Metadata.ID))
	for _, s := range fb.Skipped {
		res.Notes = append(res.Notes, "fallback skipped: "+s)
	}
	return res, nil
}
