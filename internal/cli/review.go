// Copyright 2026 Uddeshya Kumar
// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"crypto/ed25519"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"

	"github.com/spf13/cobra"
	"github.com/uddeshya-world/verdict/internal/bundle"
	"github.com/uddeshya-world/verdict/internal/pack"
)

// maxKeyFileBytes bounds one reviewer public key file.
const maxKeyFileBytes = 16 << 10

// maxReviewFileBytes bounds one review record.
const maxReviewFileBytes = 1 << 20

var reviewKeyIDRE = regexp.MustCompile(`^[0-9a-f]{32}$`)

// dirKeys looks up DIR/<key_id>.pub, a PEM Ed25519 public key in the
// internal/bundle format. Only regular files are read.
func dirKeys(dir string) pack.KeyLookup {
	if dir == "" {
		return nil
	}
	return func(id string) (ed25519.PublicKey, error) {
		if !reviewKeyIDRE.MatchString(id) {
			return nil, fmt.Errorf("key id %q is invalid", id)
		}
		path := filepath.Join(dir, id+".pub")
		fi, err := os.Lstat(path)
		if err != nil {
			return nil, fmt.Errorf("no trusted key %s in %s", id, dir)
		}
		if !fi.Mode().IsRegular() || fi.Size() > maxKeyFileBytes {
			return nil, fmt.Errorf("%s is not a regular key file", path)
		}
		data, err := os.ReadFile(path)
		if err != nil {
			return nil, err
		}
		return bundle.ParsePublicKey(data)
	}
}

func readBounded(path string, max int64) ([]byte, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	data, err := io.ReadAll(io.LimitReader(f, max+1))
	if err != nil {
		return nil, err
	}
	if int64(len(data)) > max {
		return nil, fmt.Errorf("%s is over %d bytes", path, max)
	}
	return data, nil
}

func newPackReview(stdout, stderr interface{ Write([]byte) (int, error) }) *cobra.Command {
	var packPath, recordPath, keysDir string
	var asJSON, requireSigs bool
	cmd := &cobra.Command{
		Use:   "review",
		Short: "Check a review record against a pack file",
		Long: `review checks that a record names two reviewers and the pack content.
The hash ignores metadata.status and metadata.reviewers, so setting
status to reviewed does not invalidate a record made against the draft.
It does not edit the pack and it does not decide that a name belongs to a real person.
synthetic-reviewer-* names cannot sign a real CVE.

With --reviewer-keys DIR, every reviewer entry that carries key_id and
signature is verified against DIR/<key_id>.pub (Ed25519, the bundle key
format) over "verdict-pack-review/v1\n<pack_id>\n<pack_sha256>\n<name>\n".
A bad signature, an unknown key, or one key for two reviewers exits 2.
--require-signatures also refuses any unsigned reviewer. Reviewers make their
entry with verdict pack sign-review, on their own machine, with their own key.`,
		RunE: func(*cobra.Command, []string) error {
			if packPath == "" || recordPath == "" {
				return &ExitError{Code: 2, Err: fmt.Errorf("--pack and --record are required")}
			}
			if requireSigs && keysDir == "" {
				return &ExitError{Code: 2, Err: fmt.Errorf("--require-signatures needs --reviewer-keys")}
			}
			data, err := os.ReadFile(packPath)
			if err != nil {
				return &ExitError{Code: 2, Err: err}
			}
			p, err := pack.Load(packPath, data)
			if err != nil {
				return &ExitError{Code: 2, Err: err}
			}
			raw, err := os.ReadFile(recordPath)
			if err != nil {
				return &ExitError{Code: 2, Err: err}
			}
			rec, err := pack.ParseReviewRecord(raw)
			if err != nil {
				return &ExitError{Code: 2, Err: err}
			}
			if err := pack.CheckReview(p, rec); err != nil {
				return &ExitError{Code: 2, Err: err}
			}
			if p.Metadata.Status == "reviewed" && !pack.SameReviewers(p, rec) {
				return &ExitError{Code: 2, Err: fmt.Errorf("reviewed pack reviewers do not match the record")}
			}
			signed := 0
			if keysDir != "" {
				if signed, err = pack.VerifyReviewSignatures(rec, dirKeys(keysDir), requireSigs); err != nil {
					return &ExitError{Code: 2, Err: err}
				}
			} else {
				for _, r := range rec.Reviewers {
					if r.Signature != "" || r.KeyID != "" {
						fmt.Fprintf(stderr, "note: %s is signed; pass --reviewer-keys to verify it. Signatures were not checked.\n", strings.TrimSpace(r.Name))
						break
					}
				}
			}
			names := pack.SortedNames(pack.ReviewerNames(rec))
			if asJSON {
				if err := writeJSON(stdout, reviewResult{
					Command: "pack review", OK: true, PackID: p.Metadata.ID,
					PackStatus: p.Metadata.Status, Reviewers: append([]string{}, names...),
					SignaturesVerified: signed,
				}); err != nil {
					return err
				}
			} else {
				fmt.Fprintf(stdout, "review record ok pack=%s reviewers=%s signatures_verified=%d\n", p.Metadata.ID, strings.Join(names, ","), signed)
			}
			if p.Metadata.Status != "reviewed" {
				fmt.Fprintf(stderr, "pack status is %s. This command does not change it.\n", p.Metadata.Status)
			}
			return nil
		},
	}
	cmd.Flags().StringVar(&packPath, "pack", "", "pack file")
	cmd.Flags().StringVar(&recordPath, "record", "", "review record JSON")
	cmd.Flags().StringVar(&keysDir, "reviewer-keys", "", "directory of trusted reviewer public keys named <key_id>.pub")
	cmd.Flags().BoolVar(&requireSigs, "require-signatures", false, "refuse any reviewer without a verified signature (needs --reviewer-keys)")
	addJSONFlag(cmd, &asJSON)
	return cmd
}

// newPackSignReview prints one signed reviewer entry. It is for a human
// reviewer to run with their own private key; agents must never run it.
func newPackSignReview(stdout io.Writer) *cobra.Command {
	var packPath, keyPath, name, statement, reviewedAt string
	cmd := &cobra.Command{
		Use:   "sign-review",
		Short: "Sign your own review of a pack and print the reviewer entry (humans only)",
		Long: `sign-review is for a human reviewer, run on their own machine with their own
Ed25519 private key (verdict bundle keygen makes one). It prints one reviewer
entry for a review record: name, reviewed_at, statement, key_id, and a
signature over "verdict-pack-review/v1\n<pack_id>\n<pack_sha256>\n<name>\n".
Put the public key in the trusted key directory as <key_id>.pub.

Signing says you reviewed the pack content it hashes. Coding agents must never
run this command, and nobody should run it for someone else. It does not
edit the pack or the record, and it does not read the clock: pass
--reviewed-at.`,
		Args: cobra.NoArgs,
		RunE: func(*cobra.Command, []string) error {
			if packPath == "" || keyPath == "" || name == "" || statement == "" || reviewedAt == "" {
				return &ExitError{Code: 2, Err: fmt.Errorf("--pack, --key, --reviewer, --statement, and --reviewed-at are required")}
			}
			data, err := os.ReadFile(packPath)
			if err != nil {
				return &ExitError{Code: 2, Err: err}
			}
			p, err := pack.Load(packPath, data)
			if err != nil {
				return &ExitError{Code: 2, Err: err}
			}
			raw, err := readBounded(keyPath, maxKeyFileBytes)
			if err != nil {
				return &ExitError{Code: 2, Err: err}
			}
			priv, err := bundle.ParsePrivateKey(raw)
			if err != nil {
				return &ExitError{Code: 2, Err: err}
			}
			att, err := pack.SignReview(p, priv, name, reviewedAt, statement)
			if err != nil {
				return &ExitError{Code: 2, Err: err}
			}
			return writeJSON(stdout, att)
		},
	}
	cmd.Flags().StringVar(&packPath, "pack", "", "pack file you reviewed")
	cmd.Flags().StringVar(&keyPath, "key", "", "your PEM Ed25519 private key")
	cmd.Flags().StringVar(&name, "reviewer", "", "your name as it will appear in the record and the pack")
	cmd.Flags().StringVar(&statement, "statement", "", "what you reviewed and concluded")
	cmd.Flags().StringVar(&reviewedAt, "reviewed-at", "", "RFC3339 time of your review")
	return cmd
}

// checkReviewsResult is the pack check-reviews --json shape.
type checkReviewsResult struct {
	Command  string   `json:"command"`
	OK       bool     `json:"ok"`
	Packs    int      `json:"packs"`
	Reviewed []string `json:"reviewed"`
	Errors   []string `json:"errors"`
}

// checkReviewedPacks walks packsDir for *.yaml packs. Every non-synthetic pack
// with status reviewed needs at least one record in reviewsDir/<pack_id>/*.json
// that passes CheckReview, names the same reviewers as the pack, and has a
// verified signature for every reviewer against keysDir. Synthetic packs use
// fixture reviewers and are exempt. The reviews directory is skipped by the
// walk. It returns the packs seen, the reviewed packs that passed, and one
// error line per failing pack.
func checkReviewedPacks(packsDir, reviewsDir, keysDir string) (int, []string, []string, error) {
	var paths []string
	absReviews, _ := filepath.Abs(reviewsDir)
	err := filepath.WalkDir(packsDir, func(path string, d os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			if abs, _ := filepath.Abs(path); abs == absReviews && path != packsDir {
				return filepath.SkipDir
			}
			return nil
		}
		if strings.HasSuffix(path, ".yaml") && d.Type().IsRegular() {
			paths = append(paths, path)
		}
		return nil
	})
	if err != nil {
		return 0, nil, nil, err
	}
	sort.Strings(paths)
	var ok, bad []string
	for _, path := range paths {
		data, err := os.ReadFile(path)
		if err != nil {
			return 0, nil, nil, err
		}
		p, err := pack.Load(path, data)
		if err != nil {
			bad = append(bad, fmt.Sprintf("%s: %v", path, err))
			continue
		}
		if p.Metadata.Synthetic || p.Metadata.Status != "reviewed" {
			continue
		}
		recs, _ := filepath.Glob(filepath.Join(reviewsDir, p.Metadata.ID, "*.json"))
		sort.Strings(recs)
		var why []string
		passed := false
		for _, rp := range recs {
			if err := checkSignedRecord(p, rp, keysDir); err != nil {
				why = append(why, fmt.Sprintf("%s: %v", rp, err))
				continue
			}
			passed = true
			break
		}
		switch {
		case passed:
			ok = append(ok, p.Metadata.ID)
		case len(recs) == 0:
			bad = append(bad, fmt.Sprintf("%s: status reviewed but no review record in %s", path, filepath.Join(reviewsDir, p.Metadata.ID)))
		default:
			bad = append(bad, fmt.Sprintf("%s: no signed review record verifies: %s", path, strings.Join(why, "; ")))
		}
	}
	return len(paths), ok, bad, nil
}

func checkSignedRecord(p *pack.Pack, recPath, keysDir string) error {
	raw, err := readBounded(recPath, maxReviewFileBytes)
	if err != nil {
		return err
	}
	rec, err := pack.ParseReviewRecord(raw)
	if err != nil {
		return err
	}
	if err := pack.CheckReview(p, rec); err != nil {
		return err
	}
	if !pack.SameReviewers(p, rec) {
		return fmt.Errorf("pack reviewers do not match the record")
	}
	_, err = pack.VerifyReviewSignatures(rec, dirKeys(keysDir), true)
	return err
}

func newPackCheckReviews(stdout, stderr io.Writer) *cobra.Command {
	var packsDir, reviewsDir, keysDir string
	var asJSON bool
	cmd := &cobra.Command{
		Use:   "check-reviews",
		Short: "CI gate: every reviewed real pack needs a signed review record",
		Long: `check-reviews loads every .yaml pack under --packs. Each pack that is not
synthetic and has status reviewed must have a record in
<reviews>/<pack_id>/*.json that pack review accepts, that names the pack's
reviewers, and in which every reviewer's signature verifies against
<reviewer-keys>/<key_id>.pub. Otherwise it exits 2. Synthetic CVE-2099 packs use
fixture reviewers and are not checked.`,
		Args: cobra.NoArgs,
		RunE: func(*cobra.Command, []string) error {
			n, ok, bad, err := checkReviewedPacks(packsDir, reviewsDir, keysDir)
			if err != nil {
				return &ExitError{Code: 2, Err: err}
			}
			if asJSON {
				res := checkReviewsResult{Command: "pack check-reviews", OK: len(bad) == 0, Packs: n,
					Reviewed: append([]string{}, ok...), Errors: append([]string{}, bad...)}
				if err := writeJSON(stdout, res); err != nil {
					return err
				}
			} else {
				for _, b := range bad {
					fmt.Fprintln(stderr, b)
				}
				fmt.Fprintf(stdout, "check-reviews packs=%d reviewed_signed=%d failed=%d\n", n, len(ok), len(bad))
			}
			if len(bad) > 0 {
				return &ExitError{Code: 2, Err: fmt.Errorf("pack check-reviews: %d pack(s) failed", len(bad))}
			}
			return nil
		},
	}
	cmd.Flags().StringVar(&packsDir, "packs", "packs", "directory of pack YAML files (walked recursively)")
	cmd.Flags().StringVar(&reviewsDir, "reviews", filepath.Join("packs", "reviews"), "directory of review records, one subdirectory per pack id")
	cmd.Flags().StringVar(&keysDir, "reviewer-keys", filepath.Join("packs", "reviewer-keys"), "directory of trusted reviewer public keys named <key_id>.pub")
	addJSONFlag(cmd, &asJSON)
	return cmd
}

// reviewResult is the pack review --json shape. It is written only when the
// record checks out; a failed check exits 2 with the error on stderr.
type reviewResult struct {
	Command    string   `json:"command"`
	OK         bool     `json:"ok"`
	PackID     string   `json:"pack_id"`
	PackStatus string   `json:"pack_status"`
	Reviewers  []string `json:"reviewers"`
	// SignaturesVerified counts reviewers whose signature verified
	// (only with --reviewer-keys).
	SignaturesVerified int `json:"signatures_verified"`
}

// newPackHash prints the content hash that pack review compares against.
// Output is one line per file: "pack_sha256=<hex> pack=<id> file=<path>".
func newPackHash(stdout, stderr interface{ Write([]byte) (int, error) }) *cobra.Command {
	var asJSON bool
	cmd := &cobra.Command{
		Use:   "hash FILE...",
		Short: "Print the review content hash (pack_sha256) of pack files",
		Long: `hash loads each pack with the same strict loader as lint and review
and prints the pack_sha256 that a review record must carry:

  pack_sha256=<64 hex> pack=<metadata.id> file=<path>

The hash is of the decoded pack with metadata.status and
metadata.reviewers cleared. YAML comments and formatting do not change it;
any other field does. It is not the pack_sha256 in a drill report, which
hashes the file bytes. A file that fails to load prints nothing and the
command exits 2.`,
		Args: cobra.MinimumNArgs(1),
		RunE: func(_ *cobra.Command, args []string) error {
			res := filesResult{Command: "pack hash", OK: true, Files: []fileResult{}}
			fail := func(path string, err error, text bool) error {
				if !asJSON {
					if text {
						fmt.Fprintf(stderr, "%s: %v\n", path, err)
						return &ExitError{Code: 2, Err: fmt.Errorf("pack hash failed")}
					}
					return &ExitError{Code: 2, Err: err}
				}
				res.OK = false
				res.Files = append(res.Files, fileResult{File: path, Error: err.Error()})
				if werr := writeJSON(stdout, res); werr != nil {
					return werr
				}
				return &ExitError{Code: 2, Err: fmt.Errorf("pack hash failed")}
			}
			for _, path := range args {
				data, err := os.ReadFile(path)
				if err != nil {
					return fail(path, err, false)
				}
				p, err := pack.Load(path, data)
				if err != nil {
					return fail(path, err, true)
				}
				sum, err := pack.ContentSHA256(p)
				if err != nil {
					return fail(path, err, false)
				}
				if asJSON {
					res.Files = append(res.Files, fileResult{File: path, OK: true, PackID: p.Metadata.ID, PackSHA256: sum})
					continue
				}
				fmt.Fprintf(stdout, "pack_sha256=%s pack=%s file=%s\n", sum, p.Metadata.ID, path)
			}
			if asJSON {
				return writeJSON(stdout, res)
			}
			return nil
		},
	}
	addJSONFlag(cmd, &asJSON)
	return cmd
}
